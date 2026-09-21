// 帧解析器：把字节流映射为带字节覆盖区间的解析树。
//
// 两种“没走完”的语义严格区分：
// - Incomplete：当前输入还不足以完成解析，need_total 给出至少还需要多长（总长下界）。
// - Violation：输入已经违反协议（长度越界父结构、深度超限、枚举/校验和错误等），
//              给出到达的最深字段路径 path 与字节偏移 offset。

use crate::model::{ChecksumAlgo, Endian, Expr, Field, FieldKind, Protocol};
use crate::json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeStatus {
    Ok,
    Warning,
    Error,
    Absent,
}

impl NodeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            NodeStatus::Ok => "ok",
            NodeStatus::Warning => "warning",
            NodeStatus::Error => "error",
            NodeStatus::Absent => "absent",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FailKind {
    Incomplete,
    Violation,
}

#[derive(Debug, Clone)]
pub struct ParseFailure {
    pub kind: FailKind,
    pub message: String,
    pub path: Vec<String>,
    pub offset: usize,
    /// 仅 Incomplete：要完成解析至少需要的总字节数
    pub need_total: Option<usize>,
}

#[derive(Debug, Clone)]
pub struct Node {
    pub path: Vec<String>,
    pub name: String,
    pub kind: String,
    pub start: usize,
    pub end: usize,
    pub status: NodeStatus,
    pub value: Option<Value>,
    pub display: String,
    pub diagnostics: Vec<String>,
    pub children: Vec<Node>,
}

#[derive(Debug, Clone)]
pub struct ParseResult {
    pub status: NodeStatus,
    pub tree: Option<Node>,
    pub warnings: Vec<String>,
    pub error: Option<ParseFailure>,
    pub consumed: usize,
    pub input_len: usize,
    pub digest: String,
}

fn join_path(path: &[String], name: &str) -> Vec<String> {
    let mut p = path.to_vec();
    p.push(name.to_string());
    p
}

pub fn read_int(data: &[u8], signed: bool, endian: Endian) -> i128 {
    let mut raw: u64 = 0;
    match endian {
        Endian::Big => {
            for &b in data {
                raw = (raw << 8) | b as u64;
            }
        }
        Endian::Little => {
            for (i, &b) in data.iter().enumerate() {
                raw |= (b as u64) << (i * 8);
            }
        }
    }
    if signed {
        let bits = data.len() * 8;
        let sign = 1u64 << (bits - 1);
        if raw & sign != 0 {
            let ext = u64::MAX << bits;
            (raw | ext) as i64 as i128
        } else {
            raw as i128
        }
    } else {
        raw as i128
    }
}

fn fail_incomplete(
    message: impl Into<String>,
    path: Vec<String>,
    offset: usize,
    need_total: usize,
) -> ParseFailure {
    ParseFailure {
        kind: FailKind::Incomplete,
        message: message.into(),
        path,
        offset,
        need_total: Some(need_total),
    }
}

fn fail_violation(message: impl Into<String>, path: Vec<String>, offset: usize) -> ParseFailure {
    ParseFailure {
        kind: FailKind::Violation,
        message: message.into(),
        path,
        offset,
        need_total: None,
    }
}

struct Frame<'a> {
    data: &'a [u8],
    proto: &'a Protocol,
}

pub fn parse(proto: &Protocol, data: &[u8]) -> ParseResult {
    let fr = Frame { data, proto };
    let root_path = vec![proto.root.clone()];
    let mut warnings = Vec::new();
    let result = fr.parse_struct(
        &proto.root,
        root_path,
        0,
        proto.max_frame,
        1,
        &mut warnings,
    );
    let mut status = NodeStatus::Ok;
    let mut tree = None;
    let mut error = None;
    let mut consumed = 0;
    match result {
        Ok(node) => {
            consumed = node.end;
            if node.status == NodeStatus::Error {
                status = NodeStatus::Error;
            }
            tree = Some(node);
            if consumed < data.len() {
                warnings.push(format!(
                    "trailing-bytes: 结构在偏移 {} 结束，剩余 {} 字节未被任何字段覆盖",
                    consumed,
                    data.len() - consumed
                ));
            }
        }
        Err((node_opt, failure)) => {
            error = Some(failure.clone());
            status = NodeStatus::Error;
            if let Some(n) = node_opt {
                consumed = n.end;
                tree = Some(n);
            }
        }
    }
    let has_warning = !warnings.is_empty()
        || tree
            .as_ref()
            .map(|t| t.status == NodeStatus::Warning)
            .unwrap_or(false);
    if status == NodeStatus::Ok && has_warning {
        status = NodeStatus::Warning;
    }
    let digest = crate::tree::tree_digest(tree.as_ref());
    ParseResult {
        status,
        tree,
        warnings,
        error,
        consumed,
        input_len: data.len(),
        digest,
    }
}

impl<'a> Frame<'a> {
    fn endian_for(&self, field_e: Option<Endian>) -> Endian {
        field_e.unwrap_or(self.proto.endian)
    }

    #[allow(clippy::too_many_arguments)]
    fn parse_struct(
        &self,
        sname: &str,
        path: Vec<String>,
        start: usize,
        parent_end: usize,
        depth: usize,
        warnings: &mut Vec<String>,
    ) -> Result<Node, (Option<Node>, ParseFailure)> {
        if depth > self.proto.max_depth {
            return Err((
                None,
                fail_violation(
                    format!(
                        "depth-limit: 结构 {:?} 嵌套深度 {} 超过协议上限 {}",
                        sname, depth, self.proto.max_depth
                    ),
                    path.clone(),
                    start,
                ),
            ));
        }

        let fields = &self.proto.structs[sname];
        let mut nodes: Vec<Node> = Vec::new();
        let mut local: Vec<(String, i128)> = Vec::new();
        let mut checksum_fields: Vec<(usize, ChecksumAlgo, Vec<String>, Vec<String>)> =
            Vec::new();
        let mut cur = start;
        let struct_path = path.clone();

        'fields: for field in fields.iter() {
            let fpath = join_path(&struct_path, &field.name);

            // 条件字段
            if let Some(wf) = &field.when_field {
                let dep = local.iter().rev().find(|(n, _)| n == wf).map(|(_, v)| *v);
                let present = dep == Some(field.when_equals as i128);
                if !present {
                    let mut absent = Node {
                        path: fpath.clone(),
                        name: field.name.clone(),
                        kind: kind_label(field).to_string(),
                        start: cur,
                        end: cur,
                        status: NodeStatus::Absent,
                        value: None,
                        display: format!(
                            "absent（条件 ${} == {} 不成立）",
                            wf, field.when_equals
                        ),
                        diagnostics: Vec::new(),
                        children: Vec::new(),
                    };
                    // 数组/结构体缺席时也给一个空容器，保持树形态
                    if matches!(field.kind, FieldKind::Struct(_) | FieldKind::Array { .. }) {
                        absent.display = format!("{}（条件不成立，未出现）", absent.display);
                    }
                    nodes.push(absent);
                    continue 'fields;
                }
            }

            match &field.kind {
                FieldKind::Int {
                    bytes,
                    signed,
                    endian,
                    default: _,
                    enum_map,
                    checksum,
                } => {
                    let end = cur + bytes;
                    if end > parent_end {
                        return Err((
                            Some(self.assemble(
                                sname, struct_path, start, cur, nodes,
                            )),
                            fail_violation(
                                format!(
                                    "bounds: int 字段 {:?} 需要越过父结构边界（{} > {}）",
                                    field.name, end, parent_end
                                ),
                                fpath,
                                cur,
                            ),
                        ));
                    }
                    if end > self.data.len() {
                        return Err((
                            Some(self.assemble(sname, struct_path, start, cur, nodes)),
                            fail_incomplete(
                                format!(
                                    "incomplete: int 字段 {:?} 需要 {} 字节，输入在偏移 {} 结束",
                                    field.name, bytes, self.data.len()
                                ),
                                fpath,
                                cur,
                                end,
                            ),
                        ));
                    }
                    let raw = &self.data[cur..end];
                    let val = read_int(raw, *signed, self.endian_for(*endian));
                    let mut diags = Vec::new();
                    let mut status = NodeStatus::Ok;
                    let mut label = None;
                    if !enum_map.is_empty() {
                        match enum_map.iter().find(|(_, v)| *v as i128 == val) {
                            Some((lname, _)) => label = Some(lname.clone()),
                            None => {
                                status = NodeStatus::Warning;
                                let msg = format!("enum: 值 {} 不在声明的枚举集合内", val);
                                diags.push(msg.clone());
                                warnings.push(format!(
                                    "{}: {}",
                                    fpath.join("/"),
                                    msg
                                ));
                            }
                        }
                    }
                    let display = match &label {
                        Some(l) => format!("{} = {} ({})", field.name, val, l),
                        None => format!("{} = {}", field.name, val),
                    };
                    if let Some(cs) = checksum {
                        let cover = cs.cover.clone().unwrap_or_default();
                        checksum_fields.push((
                            nodes.len(),
                            cs.algo,
                            cover,
                            cs.skip.clone(),
                        ));
                    }
                    local.push((field.name.clone(), val));
                    nodes.push(Node {
                        path: fpath,
                        name: field.name.clone(),
                        kind: "int".to_string(),
                        start: cur,
                        end,
                        status,
                        value: Some(Value::Int(val)),
                        display,
                        diagnostics: diags,
                        children: Vec::new(),
                    });
                    cur = end;
                }
                FieldKind::Bytes { length, remaining } => {
                    let (len, lref) = if *remaining {
                        (parent_end.min(self.data.len()).saturating_sub(cur), None)
                    } else {
                        let e = length.as_ref().unwrap();
                        let (val, refname) = self.eval_len(e, &local, &fpath, cur)?;
                        let val = val.max(0) as usize;
                        (val, refname)
                    };
                    let end = match (cur as u64).checked_add(len as u64) {
                        Some(e) if e <= parent_end as u64 => e as usize,
                        _ => {
                            return Err((
                                Some(self.assemble(sname, struct_path.clone(), start, cur, nodes)),
                                fail_violation(
                                    format!(
                                        "malicious-length: bytes 字段 {:?} 长度 {} 会越过父结构边界（当前偏移 {}，边界 {}）",
                                        field.name, len, cur, parent_end
                                    ),
                                    fpath,
                                    lref.unwrap_or(cur),
                                ),
                            ));
                        }
                    };
                    if end > self.data.len() {
                        return Err((
                            Some(self.assemble(sname, struct_path.clone(), start, cur, nodes)),
                            fail_incomplete(
                                format!(
                                    "incomplete: bytes 字段 {:?} 声明长度 {}，输入在偏移 {} 结束",
                                    field.name, len, self.data.len()
                                ),
                                fpath,
                                cur,
                                end,
                            ),
                        ));
                    }
                    let slice = &self.data[cur..end];
                    let display = format!(
                        "{}: {} 字节{}",
                        field.name,
                        len,
                        if *remaining { "（剩余全部）" } else { "" }
                    );
                    local.push((field.name.clone(), len as i128));
                    nodes.push(Node {
                        path: fpath,
                        name: field.name.clone(),
                        kind: "bytes".to_string(),
                        start: cur,
                        end,
                        status: NodeStatus::Ok,
                        value: Some(Value::Str(crate::hash::hex(slice))),
                        display,
                        diagnostics: Vec::new(),
                        children: Vec::new(),
                    });
                    cur = end;
                }
                FieldKind::Struct(child_name) => {
                    let child_path = fpath.clone();
                    match self.parse_struct(
                        child_name,
                        child_path,
                        cur,
                        parent_end,
                        depth + 1,
                        warnings,
                    ) {
                        Ok(node) => {
                            cur = node.end;
                            local.push((field.name.clone(), node.end as i128 - node.start as i128));
                            nodes.push(node);
                        }
                        Err((inner, failure)) => {
                            let mut partial =
                                self.assemble(sname, struct_path.clone(), start, cur, nodes);
                            if let Some(inner_node) = inner {
                                partial.children.push(inner_node);
                            }
                            return Err((Some(partial), failure));
                        }
                    }
                }
                FieldKind::Array { struct_name, count } => {
                    let (count_val, cref) =
                        self.eval_len(count, &local, &fpath, cur)?;
                    if count_val < 0 {
                        return Err((
                            Some(self.assemble(sname, struct_path.clone(), start, cur, nodes)),
                            fail_violation(
                                format!("malicious-length: array {:?} 计数为负数 {}", field.name, count_val),
                                fpath,
                                cref.unwrap_or(cur),
                            ),
                        ));
                    }
                    let count_val = count_val as usize;
                    let mut arr_node = Node {
                        path: fpath.clone(),
                        name: field.name.clone(),
                        kind: "array".to_string(),
                        start: cur,
                        end: cur,
                        status: NodeStatus::Ok,
                        value: Some(Value::Int(count_val as i128)),
                        display: format!("{}: {} 项", field.name, count_val),
                        diagnostics: Vec::new(),
                        children: Vec::new(),
                    };
                    for item in 0..count_val {
                        let ipath = join_path(&fpath, &format!("[{}]", item));
                        match self.parse_struct(
                            struct_name,
                            ipath,
                            cur,
                            parent_end,
                            depth + 1,
                            warnings,
                        ) {
                            Ok(node) => {
                                cur = node.end;
                                arr_node.children.push(node);
                            }
                            Err((inner, failure)) => {
                                if let Some(n) = inner {
                                    arr_node.children.push(n);
                                }
                                arr_node.end = cur;
                                let mut partial = self.assemble(
                                    sname,
                                    struct_path.clone(),
                                    start,
                                    cur,
                                    nodes,
                                );
                                partial.children.push(arr_node);
                                return Err((Some(partial), failure));
                            }
                        }
                    }
                    arr_node.end = cur;
                    local.push((field.name.clone(), count_val as i128));
                    nodes.push(arr_node);
                }
            }
        }

        let mut node = self.assemble(sname, struct_path, start, cur, nodes);

        // 校验和验证（覆盖区间允许通过 skip 跳过自身字段）
        for (node_idx, algo, cover, skip) in checksum_fields {
            let (cs_start, cs_end, cs_name, cs_path, actual) = {
                let cs_node = &node.children[node_idx];
                (
                    cs_node.start,
                    cs_node.end,
                    cs_node.name.clone(),
                    cs_node.path.clone(),
                    cs_node.value.as_ref().and_then(|v| v.as_i128()).unwrap_or(0),
                )
            };

            let covered: Vec<(usize, usize, String, Vec<String>)> = if cover.is_empty() {
                node.children
                    .iter()
                    .filter(|n| n.end <= cs_start && n.status != NodeStatus::Absent)
                    .map(|n| (n.start, n.end, n.name.clone(), n.path.clone()))
                    .collect()
            } else {
                cover
                    .iter()
                    .filter_map(|name| node.children.iter().find(|n| &n.name == name))
                    .filter(|n| n.status != NodeStatus::Absent)
                    .map(|n| (n.start, n.end, n.name.clone(), n.path.clone()))
                    .collect()
            };

            let mut ranges: Vec<(usize, usize)> = Vec::new();
            for (s, e, name, node_path) in covered {
                if skip.iter().any(|x| x == &name) {
                    continue;
                }
                // 跳过自身字段：cover 若显式包含同名段，这里也会排除
                if s == cs_start && e == cs_end && name == cs_name {
                    continue;
                }
                if s < e {
                    let _ = node_path;
                    ranges.push((s, e));
                }
            }
            let mut acc8: u16 = 0;
            let mut acc16: u32 = 0;
            let mut xor: u8 = 0;
            for (a, b) in &ranges {
                let slice = &self.data[*a..*b];
                match algo {
                    ChecksumAlgo::Sum8 => {
                        for &x in slice {
                            acc8 = acc8.wrapping_add(x as u16);
                        }
                    }
                    ChecksumAlgo::Xor8 => {
                        for &x in slice {
                            xor ^= x;
                        }
                    }
                    ChecksumAlgo::Sum16 => {
                        if (b - a) % 2 != 0 {
                            warnings.push(format!(
                                "{}: checksum: 覆盖区间 {}..{} 为奇数长度，sum16 按末尾补 0 处理",
                                cs_path.join("/"),
                                a,
                                b
                            ));
                        }
                        for chunk in slice.chunks(2) {
                            let hi = chunk[0] as u32;
                            let lo = *chunk.get(1).unwrap_or(&0) as u32;
                            acc16 = acc16.wrapping_add((hi << 8) | lo);
                        }
                    }
                }
            }
            let expected: i128 = match algo {
                ChecksumAlgo::Sum8 => (acc8 & 0xff) as i128,
                ChecksumAlgo::Xor8 => xor as i128,
                ChecksumAlgo::Sum16 => {
                    let mut s = acc16;
                    while (s >> 16) != 0 {
                        s = (s & 0xffff) + (s >> 16);
                    }
                    (s & 0xffff) as i128
                }
            };
            if actual != expected {
                let msg = format!(
                    "checksum-mismatch: {} 字段值 {} 与覆盖区间计算值 {} 不一致（{} 个区间，已按 skip 排除自身）",
                    cs_name,
                    actual,
                    expected,
                    ranges.len()
                );
                node.status = NodeStatus::Error;
                node.diagnostics.push(msg.clone());
                node.children[node_idx].status = NodeStatus::Error;
                node.children[node_idx].diagnostics.push(msg.clone());
                return Err((
                    Some(node),
                    fail_violation(msg, cs_path, cs_start),
                ));
            } else {
                let extra = format!(
                    "checksum-ok: {} = {}（覆盖 {} 个区间）",
                    cs_name,
                    expected,
                    ranges.len()
                );
                node.children[node_idx].diagnostics.push(extra);
            }
        }

        Ok(node)
    }

    fn assemble(
        &self,
        sname: &str,
        path: Vec<String>,
        start: usize,
        end: usize,
        children: Vec<Node>,
    ) -> Node {
        let status = if children.iter().any(|c| c.status == NodeStatus::Error) {
            NodeStatus::Error
        } else if children.iter().any(|c| c.status == NodeStatus::Warning) {
            NodeStatus::Warning
        } else {
            NodeStatus::Ok
        };
        Node {
            display: format!("struct {} ({} 字节)", sname, end - start),
            path,
            name: sname.to_string(),
            kind: "struct".to_string(),
            start,
            end,
            status,
            value: None,
            diagnostics: Vec::new(),
            children,
        }
    }

    fn eval_len(
        &self,
        e: &Expr,
        local: &[(String, i128)],
        fpath: &[String],
        offset: usize,
    ) -> Result<(i64, Option<usize>), (Option<Node>, ParseFailure)> {
        match e {
            Expr::Const(c) => Ok((*c, None)),
            Expr::Ref(name) => match local.iter().rev().find(|(n, _)| n == name) {
                Some((_, v)) => Ok((i64::try_from(*v).unwrap_or(i64::MAX), Some(offset))),
                None => Err((
                    None,
                    fail_violation(
                        format!("引用字段 {:?} 尚未求值", name),
                        fpath.to_vec(),
                        offset,
                    ),
                )),
            },
            Expr::RefMinus(name, k) => match local.iter().rev().find(|(n, _)| n == name) {
                Some((_, v)) => {
                    let val = (*v).saturating_sub(*k as i128);
                    Ok((i64::try_from(val).unwrap_or(i64::MAX), Some(offset)))
                }
                None => Err((
                    None,
                    fail_violation(
                        format!("引用字段 {:?} 尚未求值", name),
                        fpath.to_vec(),
                        offset,
                    ),
                )),
            },
        }
    }
}

fn kind_label(f: &Field) -> &'static str {
    match f.kind {
        FieldKind::Int { .. } => "int",
        FieldKind::Bytes { .. } => "bytes",
        FieldKind::Struct(_) => "struct",
        FieldKind::Array { .. } => "array",
    }
}
