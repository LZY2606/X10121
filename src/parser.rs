//! 帧解析器：把每个字节映射到解析树；严格区分 incomplete 与 violation。
use crate::model::{ErrorInfo, ParseNode, ParseReport, Status, Warning};
use crate::spec::{
    Algo, ArrayItem, Endian, Field, FieldKind, LengthSpec, Spec, StructDef,
};

#[derive(Debug, Clone, Copy)]
enum EvalStatus {
    Ok,
    Incomplete,
    Violation,
}

struct Scope {
    /// 字段名 -> 整数取值
    ints: Vec<(String, i64)>,
    /// 字段名 -> 字节覆盖区间（起，止）
    spans: Vec<(String, (usize, usize))>,
}

impl Scope {
    fn new() -> Scope {
        Scope { ints: Vec::new(), spans: Vec::new() }
    }
    fn put_int(&mut self, name: &str, v: i64) {
        self.ints.push((name.to_string(), v));
    }
    fn put_span(&mut self, name: &str, s: usize, e: usize) {
        self.spans.push((name.to_string(), (s, e)));
    }
}

pub struct Parser<'a> {
    spec: &'a Spec,
    data: &'a [u8],
    scopes: Vec<Scope>,
    fatal: Option<ErrorInfo>,
    warnings: Vec<Warning>,
    /// 所有 incomplete 检查中，最远的绝对字节位置；用于“仍需字节数下界”。
    need_end: usize,
}

pub fn parse(spec: &Spec, data: &[u8]) -> ParseReport {
    let root_name = spec.root.clone();
    let mut p = Parser {
        spec,
        data,
        scopes: vec![Scope::new()],
        fatal: None,
        warnings: Vec::new(),
        need_end: 0,
    };
    let mut node = ParseNode {
        name: root_name.clone(),
        path: format!("${}", root_name),
        kind: "struct",
        dtype: root_name.clone(),
        ..Default::default()
    };
    let status = p.run_struct(spec.get(&root_name).unwrap(), &mut node, 0, None, 1);
    let mut report = ParseReport {
        status: match status {
            EvalStatus::Ok | EvalStatus::Incomplete => Status::Incomplete,
            EvalStatus::Violation => Status::Violation,
        },
        tree: Some(node),
        error: None,
        warnings: p.warnings,
        input_len: data.len(),
        consumed: 0,
    };
    match p.fatal {
        Some(mut e) => {
            if e.kind == "incomplete" {
                report.status = Status::Incomplete;
                e.need = Some(p.need_end.saturating_sub(data.len()).max(1));
            } else {
                report.status = Status::Violation;
            }
            report.error = Some(e);
        }
        None => {
            let t = report.tree.as_ref().unwrap();
            if t.end > data.len() {
                report.status = Status::Incomplete;
                p.need_end = p.need_end.max(t.end);
                report.error = Some(ErrorInfo {
                    code: "incomplete".into(),
                    kind: "incomplete",
                    message: format!("根结构至少需要 {} 字节，目前只有 {} 字节", t.end, data.len()),
                    path: t.path.clone(),
                    offset: data.len(),
                    need: Some(p.need_end - data.len()),
                });
            } else if t.end < data.len() {
                report.status = Status::Ok;
                let extra = data.len() - t.end;
                report.warnings.push(Warning {
                    path: t.path.clone(),
                    code: "trailing_bytes".into(),
                    message: format!("根结构之后还有 {extra} 个未消费字节"),
                    offset: Some(t.end),
                });
            } else {
                report.status = Status::Ok;
            }
        }
    }
    report.consumed = report.tree.as_ref().map(|t| t.end.min(data.len())).unwrap_or(0);
    // 把节点上的内联告警合并到报告级警告（路径已知）
    collect_warnings(report.tree.as_ref().unwrap(), &mut report.warnings);
    report
}

fn collect_warnings(node: &ParseNode, out: &mut Vec<Warning>) {
    for w in &node.warnings {
        out.push(Warning {
            path: node.path.clone(),
            code: w.clone(),
            message: warning_text(w),
            offset: Some(node.start),
        });
    }
    for c in &node.children {
        collect_warnings(c, out);
    }
}

fn warning_text(code: &str) -> String {
    match code {
        "enum_unknown" => "取值不在声明的枚举集合内".to_string(),
        "const_mismatch_warn" => "常量字段取值异常".to_string(),
        other => {
            if let Some(name) = other.strip_prefix("checksum_unresolved:") {
                format!("校验和字段 {name} 的覆盖标记无法解析，未执行校验")
            } else {
                other.to_string()
            }
        }
    }
}

impl<'a> Parser<'a> {
    fn fail(&mut self, code: &str, kind: &'static str, msg: String, path: String, offset: usize) {
        if self.fatal.is_some() {
            return;
        }
        self.fatal = Some(ErrorInfo {
            code: code.to_string(),
            kind,
            message: msg,
            path,
            offset,
            need: None,
        });
    }

    fn lookup_int(&self, name: &str) -> Option<i64> {
        for sc in self.scopes.iter().rev() {
            for (k, v) in sc.ints.iter().rev() {
                if k == name {
                    return Some(*v);
                }
            }
        }
        None
    }

    fn lookup_span(&self, name: &str) -> Option<(usize, usize)> {
        for sc in self.scopes.iter().rev() {
            for (k, v) in sc.spans.iter().rev() {
                if k == name {
                    return Some(*v);
                }
            }
        }
        None
    }

    /// 长度/计数字段只允许引用“当前结构”中先前解析的字段。
    fn resolve_len_local(&self, ls: &LengthSpec) -> Result<i64, ()> {
        match ls {
            LengthSpec::Fixed(n) => Ok(*n),
            LengthSpec::Field { name, offset } => self
                .scopes
                .last()
                .and_then(|sc| sc.ints.iter().rev().find(|(k, _)| k == name).map(|(_, v)| *v + *offset))
                .ok_or(()),
        }
    }

    /// 尝试把结构的 length_ref 解析为绝对硬边界；None 表示引用字段尚未可见。
    /// 解析出非法值（负数/越过父边界）时直接登记 fatal 并返回 Some 占位。
    fn try_resolve_struct_end(
        &mut self,
        sd: &StructDef,
        start: usize,
        lr: &LengthSpec,
        parent_end: Option<usize>,
        path: &str,
    ) -> Option<usize> {
        let v = self.resolve_len_local(lr).ok()?;
        let offset = match lr {
            LengthSpec::Field { offset, .. } => *offset,
            LengthSpec::Fixed(_) => 0,
        };
        let he = start as i64 + v + offset;
        if he < start as i64 {
            self.fail(
                "length_negative",
                "violation",
                format!("结构 {} 的长度引用推导出越界边界 {}", sd.name, he),
                path.to_string(),
                start,
            );
            return Some(start);
        }
        let he = he as usize;
        if let Some(pe) = parent_end {
            if he > pe {
                // 报告到“长度引用”字段：找到提供该值的字段区间
                let off = match lr {
                    LengthSpec::Field { name, .. } => self
                        .lookup_span(name)
                        .map(|(s, _)| s)
                        .unwrap_or(start),
                    LengthSpec::Fixed(_) => start,
                };
                self.fail(
                    "length_out_of_bounds",
                    "violation",
                    format!(
                        "长度字段把结构 {} 带出父结构边界：硬边界 {he} > 父边界 {pe}",
                        sd.name
                    ),
                    path.to_string(),
                    off,
                );
            }
        }
        Some(he)
    }
}

impl<'a> Parser<'a> {
    /// 解析一个（可能带硬边界的）结构。返回 Ok 表示结构内字段全部走完，
    /// Incomplete/Violation 表示中途已停止。
    fn run_struct(
        &mut self,
        sd: &StructDef,
        node: &mut ParseNode,
        start: usize,
        parent_end: Option<usize>,
        depth: usize,
    ) -> EvalStatus {
        node.start = start;
        node.kind = "struct";
        node.dtype = sd.name.clone();
        self.scopes.push(Scope::new());

        let mut cursor = start;
        let mut hard_end: Option<usize> = None;
        let mut st = EvalStatus::Ok;

        for field in &sd.fields {
            if let FieldKind::Struct { when: Some(w), .. } = &field.kind {
                match self.lookup_int(&w.field) {
                    Some(v) if v == w.eq => {}
                    Some(_) => continue,
                    None => continue,
                }
            }

            // 若本结构长度引用的字段已经可见（同结构先前字段或祖先字段），
            // 在解析当前字段前确定硬边界，保证任何越界都被父边界拦下。
                if hard_end.is_none() {
                    if let Some(lr) = &sd.length_ref {
                        if let Some(he) = self.try_resolve_struct_end(sd, start, lr, parent_end, &node.path) {
                        hard_end = Some(he);
                        if self.fatal.is_some() {
                            break;
                        }
                    }
                }
            }

            let child_path = format!("{}.{}", node.path, field.name);
            let mut child = ParseNode {
                name: field.name.clone(),
                path: child_path,
                ..Default::default()
            };

            // 字段读取的有效边界：本结构声明了硬边界就用它，否则受父结构边界约束。
            let field_bound = hard_end.or(parent_end);
            let fst = self.run_field(field, &mut child, cursor, field_bound, depth + 1);
            if matches!(fst, EvalStatus::Violation) {
                node.children.push(child);
                st = EvalStatus::Violation;
                break;
            }

            cursor = child.end.max(cursor);
            self.scopes
                .last_mut()
                .unwrap()
                .put_span(&field.name, child.start, child.end);
            node.children.push(child);

            if matches!(fst, EvalStatus::Incomplete) {
                st = EvalStatus::Incomplete;
                break;
            }
        }

        // 收尾
        if matches!(st, EvalStatus::Ok) {
            if let Some(he) = hard_end {
                if cursor < he {
                    if he > self.data.len() {
                        self.need_end = self.need_end.max(he);
                        self.fail(
                            "incomplete",
                            "incomplete",
                            format!("结构 {} 声明长度需要到 {} 字节，输入不足", sd.name, he),
                            node.path.clone(),
                            self.data.len(),
                        );
                        st = EvalStatus::Incomplete;
                    } else {
                        self.fail(
                            "struct_short",
                            "violation",
                            format!("结构 {} 在边界 {} 之前结束（{}），字段未填满", sd.name, he, cursor),
                            node.path.clone(),
                            cursor,
                        );
                        st = EvalStatus::Violation;
                    }
                } else if cursor > he {
                    self.fail(
                        "struct_overflow",
                        "violation",
                        format!("字段越过结构 {} 的边界（{} > {}）", sd.name, cursor, he),
                        node.path.clone(),
                        he,
                    );
                    st = EvalStatus::Violation;
                } else {
                    node.end = he;
                }
            } else {
                node.end = cursor;
            }
        } else {
            node.end = hard_end.unwrap_or(cursor);
        }

        // 校验和（结构字段全部走完后）
        if !matches!(st, EvalStatus::Violation) {
            self.eval_checksums(sd, node, hard_end);
            if self.fatal.as_ref().map(|e| e.kind == "violation").unwrap_or(false) {
                st = EvalStatus::Violation;
            }
        }

        self.scopes.pop();
        st
    }
}

impl<'a> Parser<'a> {
    fn run_field(
        &mut self,
        field: &Field,
        node: &mut ParseNode,
        cursor: usize,
        hard_end: Option<usize>,
        depth: usize,
    ) -> EvalStatus {
        node.start = cursor;
        match &field.kind {
            FieldKind::Int {
                width,
                signed,
                endian,
                expect_const,
                enum_vals,
                checksum,
            } => {
                node.kind = "int";
                node.dtype = type_name(*width, *signed);
                let end = cursor + *width;
                if let Some(he) = hard_end {
                    if end > he {
                        self.fail(
                            "field_out_of_bounds",
                            "violation",
                            format!("整数字段 {} 越过结构边界（{} > {}）", field.name, end, he),
                            node.path.clone(),
                            he,
                        );
                        node.end = end;
                        return EvalStatus::Violation;
                    }
                }
                if end > self.data.len() {
                    self.need_end = self.need_end.max(end);
                    self.fail(
                        "incomplete",
                        "incomplete",
                        format!("整数字段 {} 需要 {width} 字节，输入不足", field.name),
                        node.path.clone(),
                        self.data.len(),
                    );
                    node.end = end;
                    return EvalStatus::Incomplete;
                }
                let raw = &self.data[cursor..end];
                let v = read_int(raw, *endian, *signed);
                node.end = end;
                node.value = Some(v.to_string());
                self.scopes.last_mut().unwrap().put_int(&field.name, v);

                if let Some(c) = expect_const {
                    if v != *c {
                        self.fail(
                            "const_mismatch",
                            "violation",
                            format!("常量字段 {} 应为 {c}，实际为 {v}", field.name),
                            node.path.clone(),
                            cursor,
                        );
                        return EvalStatus::Violation;
                    }
                }
                if !enum_vals.is_empty() && !enum_vals.iter().any(|e| e.value == v) {
                    node.warnings.push("enum_unknown".into());
                }
                // checksum 延后到 run_struct 收尾时统一评估，这里只记录覆盖依赖
                let _ = checksum;
                EvalStatus::Ok
            }
            FieldKind::Bytes { length } => {
                node.kind = "bytes";
                node.dtype = "bytes".to_string();
                let n = match self.resolve_len_local(length) {
                    Ok(n) if n >= 0 => n as usize,
                    Ok(_) => {
                        self.fail(
                            "length_negative",
                            "violation",
                            format!("字节字段 {} 的长度为负", field.name),
                            node.path.clone(),
                            cursor,
                        );
                        return EvalStatus::Violation;
                    }
                    Err(()) => {
                        self.fail(
                            "length_unresolved",
                            "violation",
                            format!("字节字段 {} 引用的长度字段尚不可用", field.name),
                            node.path.clone(),
                            cursor,
                        );
                        return EvalStatus::Violation;
                    }
                };
                let end = cursor + n;
                if let Some(he) = hard_end {
                    if end > he {
                        self.fail(
                            "length_out_of_bounds",
                            "violation",
                            format!(
                                "字节字段 {} 的长度 {n} 越过结构边界（{end} > {he}）",
                                field.name
                            ),
                            node.path.clone(),
                            // 最深失败位置：边界处（但不超过实际输入长度）
                            he.min(self.data.len()),
                        );
                        node.end = end;
                        return EvalStatus::Violation;
                    }
                }
                if end > self.data.len() {
                    self.need_end = self.need_end.max(end);
                    self.fail(
                        "incomplete",
                        "incomplete",
                        format!("字节字段 {} 需要 {n} 字节，输入不足", field.name),
                        node.path.clone(),
                        self.data.len(),
                    );
                    node.end = end;
                    return EvalStatus::Incomplete;
                }
                node.end = end;
                node.value = Some(crate::hexutil::encode_hex(&self.data[cursor..end]));
                EvalStatus::Ok
            }
            FieldKind::Struct { struct_name, .. } => {
                if depth > self.spec.max_depth {
                    self.fail(
                        "max_depth",
                        "violation",
                        format!(
                            "嵌套结构深度达到 {} 层，超过配置上限 {}（字段 {}）",
                            depth, self.spec.max_depth, field.name
                        ),
                        node.path.clone(),
                        cursor,
                    );
                    return EvalStatus::Violation;
                }
                let sd = self.spec.get(struct_name).expect("validated");
                self.run_struct(sd, node, cursor, hard_end, depth)
            }
            FieldKind::Array { count, item } => {
                node.kind = "array";
                node.dtype = match item {
                    ArrayItem::Int { width, signed, .. } => type_name(*width, *signed),
                    ArrayItem::Bytes { .. } => "bytes".to_string(),
                    ArrayItem::Struct { struct_name } => struct_name.clone(),
                };
                let cnt = match self.resolve_len_local(count) {
                    Ok(n) if n >= 0 => n as usize,
                    Ok(_) => {
                        self.fail(
                            "length_negative",
                            "violation",
                            format!("数组 {} 的数量为负", field.name),
                            node.path.clone(),
                            cursor,
                        );
                        return EvalStatus::Violation;
                    }
                    Err(()) => {
                        self.fail(
                            "count_unresolved",
                            "violation",
                            format!("数组 {} 引用的计数字段尚不可用", field.name),
                            node.path.clone(),
                            cursor,
                        );
                        return EvalStatus::Violation;
                    }
                };
                self.run_array_items(field, node, cursor, hard_end, depth, cnt, item)
            }
        }
    }
}

fn read_int(raw: &[u8], endian: Endian, signed: bool) -> i64 {
    let mut v: i64 = 0;
    let bytes: Vec<u8> = match endian {
        Endian::Be => raw.to_vec(),
        Endian::Le => raw.iter().rev().copied().collect(),
    };
    for b in &bytes {
        v = (v << 8) | (*b as i64);
    }
    if signed && !bytes.is_empty() && bytes[0] & 0x80 != 0 {
        let bits = bytes.len() * 8;
        if bits >= 64 {
            v
        } else {
            v - (1i64 << bits)
        }
    } else {
        v
    }
}

fn type_name(width: usize, signed: bool) -> String {
    let prefix = if signed { "i" } else { "u" };
    format!("{prefix}{}", width * 8)
}

impl<'a> Parser<'a> {
    fn run_array_items(
        &mut self,
        _field: &Field,
        node: &mut ParseNode,
        mut cursor: usize,
        hard_end: Option<usize>,
        depth: usize,
        count: usize,
        item: &ArrayItem,
    ) -> EvalStatus {
        for i in 0..count {
            if self.fatal.is_some() {
                break;
            }
            let mut item_node = ParseNode {
                name: format!("[{i}]"),
                path: format!("{}[{i}]", node.path),
                ..Default::default()
            };
            let st = match item {
                ArrayItem::Int { width, signed, endian } => {
                    let pseudo = Field {
                        name: format!("[{i}]"),
                        kind: FieldKind::Int {
                            width: *width,
                            signed: *signed,
                            endian: *endian,
                            expect_const: None,
                            enum_vals: Vec::new(),
                            checksum: None,
                        },
                    };
                    let s = self.run_field(&pseudo, &mut item_node, cursor, hard_end, depth);
                    if matches!(s, EvalStatus::Ok) {
                        let v = item_node.value.as_ref().and_then(|x| x.parse::<i64>().ok());
                        if let Some(v) = v {
                            self.scopes.last_mut().unwrap().put_int(&format!("[{i}]"), v);
                        }
                    }
                    s
                }
                ArrayItem::Bytes { length } => {
                    let pseudo = Field {
                        name: format!("[{i}]"),
                        kind: FieldKind::Bytes { length: length.clone() },
                    };
                    self.run_field(&pseudo, &mut item_node, cursor, hard_end, depth)
                }
                ArrayItem::Struct { struct_name } => {
                    let sd = self.spec.get(struct_name).expect("validated");
                    self.run_struct(sd, &mut item_node, cursor, hard_end, depth)
                }
            };
            cursor = item_node.end.max(cursor);
            node.children.push(item_node);
            if matches!(st, EvalStatus::Violation) {
                node.end = cursor;
                return EvalStatus::Violation;
            }
            if matches!(st, EvalStatus::Incomplete) {
                node.end = cursor;
                return EvalStatus::Incomplete;
            }
        }
        node.start = node.children.first().map(|c| c.start).unwrap_or(cursor);
        node.end = cursor;
        EvalStatus::Ok
    }

    /// 在某个结构字段全部解析后评估其中的校验和字段。
    fn eval_checksums(&mut self, sd: &StructDef, snode: &mut ParseNode, hard_end: Option<usize>) {
        for f in &sd.fields {
            let FieldKind::Int { checksum: Some(cs), .. } = &f.kind else {
                continue;
            };
            let Some(fnode) = snode.children.iter().find(|c| c.name == f.name) else {
                continue; // 条件字段未出现
            };
            let Some(actual) = fnode.value.as_ref().and_then(|s| s.parse::<i64>().ok()) else {
                continue;
            };
            // 解析覆盖标记
            let mut marks: Vec<usize> = Vec::new();
            let mut unresolved = false;
            for mark in &cs.covers {
                let pos = if mark == "@start" {
                    Some(snode.start)
                } else if mark == "@end" {
                    hard_end.or(Some(snode.end))
                } else {
                    self.lookup_span(mark).map(|(s, _e)| s)
                };
                match pos {
                    Some(p) => marks.push(p),
                    None => {
                        unresolved = true;
                        break;
                    }
                }
            }
            if unresolved {
                snode
                    .warnings
                    .push(format!("checksum_unresolved:{}", f.name));
                continue;
            }
            let mut lo = marks[0];
            let mut hi = marks[0];
            for p in marks {
                lo = lo.min(p);
                hi = hi.max(p);
            }
            // 覆盖区间：从最小标记到最大标记；自排除时挖掉校验字段自身。
            let mut sum: i64 = 0;
            let mut xor: u8 = 0;
            let end = hi.min(self.data.len());
            let mut i = lo;
            while i < end {
                let in_self = cs.skip_self && i >= fnode.start && i < fnode.end;
                if !in_self {
                    sum = (sum + self.data[i] as i64) & 0xFF;
                    xor ^= self.data[i];
                }
                i += 1;
            }
            let want = match cs.algo {
                Algo::Sum8 => sum,
                Algo::Xor8 => xor as i64,
            };
            if hi > self.data.len() {
                self.need_end = self.need_end.max(hi);
                self.fail(
                    "incomplete",
                    "incomplete",
                    format!("校验和 {} 的覆盖区间需要到 {hi} 字节，输入不足", f.name),
                    fnode.path.clone(),
                    self.data.len(),
                );
                return;
            }
            if want & 0xFF != actual & 0xFF {
                self.fail(
                    "checksum_mismatch",
                    "violation",
                    format!(
                        "校验和 {} 不匹配：按覆盖区间计算为 {want:#04x}，字段值为 {:#04x}",
                        f.name, actual
                    ),
                    fnode.path.clone(),
                    fnode.start,
                );
                return;
            }
        }
    }
}
