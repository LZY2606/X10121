//! 帧解析器。
//!
//! 三态结果：
//! - `complete`：输入满足协议（可能伴随校验和等告警）；
//! - `incomplete`：输入尚未完整，给出仍需字节数下界；
//! - `violation`：输入已违反协议，给出最深字段路径与字节偏移。

use crate::model::*;


#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeStatus {
    Ok,
    Incomplete,
    Violation,
}

/// 解析树节点，每个节点都携带字节覆盖区间。
#[derive(Clone, Debug, PartialEq)]
pub struct Node {
    pub name: String,
    pub kind: String,
    pub start: u64,
    pub end: u64,
    pub status: NodeStatus,
    pub value_int: Option<i64>,
    pub value_hex: Option<String>,
    pub detail: Option<String>,
    pub children: Vec<Node>,
}

impl Node {
    fn new(name: &str, kind: &str, start: u64, end: u64, status: NodeStatus) -> Self {
        Node {
            name: name.to_string(),
            kind: kind.to_string(),
            start,
            end,
            status,
            value_int: None,
            value_hex: None,
            detail: None,
            children: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Diagnostic {
    pub level: String,
    pub message: String,
    pub path: String,
    pub offset: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Complete,
    Incomplete,
    Violation,
}

/// 一次解析的完整报告。
#[derive(Clone, Debug, PartialEq)]
pub struct ParseReport {
    pub outcome: Outcome,
    /// incomplete 时仍需字节数的下界。
    pub need_bytes: u64,
    pub tree: Option<Node>,
    pub warnings: Vec<Diagnostic>,
    /// 违规位置：最深字段路径与字节偏移。
    pub error_path: Option<String>,
    pub error_offset: Option<u64>,
    pub error_message: Option<String>,
}

#[derive(Debug)]
struct Fail {
    kind: NodeStatus,
    path: String,
    offset: u64,
    message: String,
}

#[derive(Clone, Debug)]
struct FieldInfo {
    start: u64,
    end: u64,
    value_int: Option<i64>,
}

/// 字段作用域：本层已解析字段的区间与整数值。
#[derive(Default)]
struct Scope {
    fields: Vec<(String, FieldInfo)>,
}

impl Scope {
    fn put(&mut self, name: &str, info: FieldInfo) {
        self.fields.push((name.to_string(), info));
    }
    fn lookup(&self, name: &str) -> Option<&FieldInfo> {
        self.fields.iter().rev().find(|(n, _)| n == name).map(|(_, i)| i)
    }
}

fn lookup_ref<'s>(
    local: &'s Scope,
    ancestors: &'s [&Scope],
    name: &str,
) -> Option<&'s FieldInfo> {
    local
        .lookup(name)
        .or_else(|| ancestors.iter().rev().find_map(|s| s.lookup(name)))
}

/// 待结构体解析完成后验证的校验和。
struct PendingChecksum {
    child_idx: usize,
    algo: ChecksumAlgo,
    width: u32,
    cover_start: u64,
    cover_end: u64,
    own_start: u64,
    own_end: u64,
    expected: u64,
    path: String,
}

struct StructResult {
    node: Node,
    end: u64,
}

pub struct Parser<'a> {
    spec: &'a ProtocolSpec,
    input: &'a [u8],
    need_end: u64,
    warnings: Vec<Diagnostic>,
}

fn join(base: &str, seg: &str) -> String {
    if base.is_empty() {
        seg.to_string()
    } else {
        format!("{}.{}", base, seg)
    }
}

/// 入口：按协议解析字节流。
pub fn parse(spec: &ProtocolSpec, input: &[u8]) -> ParseReport {
    let mut p = Parser {
        spec,
        input,
        need_end: input.len() as u64,
        warnings: Vec::new(),
    };
    let len = input.len() as u64;
    let root_path = spec.root.clone();
    let empty: [&Scope; 0] = [];
    // 根结构没有外部声明边界：读不到字节即 incomplete；
    // “长度带出父边界”由所有定界/嵌套结构的 hard_end 强制。
    match p.parse_struct(&spec.root, &root_path, 0, u64::MAX, 0, &empty) {
        Err(f) => {
            let incomplete = f.kind == NodeStatus::Incomplete;
            ParseReport {
                outcome: if incomplete {
                    Outcome::Incomplete
                } else {
                    Outcome::Violation
                },
                need_bytes: if incomplete {
                    p.need_end.saturating_sub(len).max(1)
                } else {
                    0
                },
                tree: None,
                warnings: Vec::new(),
                error_path: if !incomplete { Some(f.path) } else { None },
                error_offset: if !incomplete { Some(f.offset) } else { None },
                error_message: if !incomplete { Some(f.message) } else { None },
            }
        }
        Ok(result) => {
            if result.end < len {
                p.warnings.push(Diagnostic {
                    level: "warning".into(),
                    message: format!("根结构体后仍有 {} 字节未消费", len - result.end),
                    path: root_path,
                    offset: result.end,
                });
            }
            ParseReport {
                outcome: Outcome::Complete,
                need_bytes: 0,
                tree: Some(result.node),
                warnings: p.warnings,
                error_path: None,
                error_offset: None,
                error_message: None,
            }
        }
    }
}

impl<'a> Parser<'a> {
    fn incomplete(&self, path: String, offset: u64, need_end: u64) -> Fail {
        Fail {
            kind: NodeStatus::Incomplete,
            path,
            offset,
            message: format!("输入尚未完整：至少需要解析到偏移 {}", need_end),
        }
    }

    fn violation(&self, path: String, offset: u64, message: String) -> Fail {
        Fail {
            kind: NodeStatus::Violation,
            path,
            offset,
            message,
        }
    }

    /// 读取 n 字节：越过父边界为违规，输入长度不足为未完成。
    fn read(
        &mut self,
        path: &str,
        start: u64,
        n: u64,
        hard_end: u64,
        len_field_start: Option<u64>,
    ) -> Result<&'a [u8], Fail> {
        let end = start.saturating_add(n);
        if n != 0 && end < start {
            return Err(self.violation(path.into(), start, "长度溢出".into()));
        }
        if end > hard_end {
            return Err(self.violation(
                path.into(),
                len_field_start.unwrap_or(start),
                format!("字段需要到偏移 {}，但父结构边界在 {}", end, hard_end),
            ));
        }
        if end > self.input.len() as u64 {
            self.need_end = self.need_end.max(end);
            return Err(self.incomplete(path.into(), start, end));
        }
        Ok(&self.input[start as usize..end as usize])
    }

    fn parse_struct(
        &mut self,
        ty: &str,
        path: &str,
        start: u64,
        hard_end: u64,
        depth: u32,
        ancestors: &[&Scope],
    ) -> Result<StructResult, Fail> {
        if depth > self.spec.max_depth {
            return Err(self.violation(
                path.into(),
                start,
                format!("递归深度超过上限 {}", self.spec.max_depth),
            ));
        }
        let sdef = self
            .spec
            .structs
            .get(ty)
            .ok_or_else(|| self.violation(path.into(), start, format!("未知结构体 `{}`", ty)))?;
        let mut node = Node::new(ty, "struct", start, start, NodeStatus::Ok);
        let mut scope = Scope::default();
        let mut pos = start;
        let mut pending: Vec<PendingChecksum> = Vec::new();

        for fdef in &sdef.fields {
            let child_path = join(path, fdef.name());
            let (advanced, info) = self.parse_field(
                fdef,
                &child_path,
                pos,
                hard_end,
                depth,
                start,
                &scope,
                ancestors,
                &mut node.children,
                &mut pending,
            )?;
            scope.put(fdef.name(), info);
            pos = advanced;
        }
        node.end = pos;
        self.finish_checksums(start, pos, &mut node, &pending)?;
        Ok(StructResult { node, end: pos })
    }

    /// 解析单个字段。返回（新解析位置, 供本作用域注册的字段信息）。
    #[allow(clippy::too_many_arguments)]
    fn parse_field(
        &mut self,
        fdef: &FieldDef,
        path: &str,
        pos: u64,
        hard_end: u64,
        depth: u32,
        struct_start: u64,
        local: &Scope,
        ancestors: &[&Scope],
        children: &mut Vec<Node>,
        pending: &mut Vec<PendingChecksum>,
    ) -> Result<(u64, FieldInfo), Fail> {
        match fdef {
            FieldDef::Int {
                name,
                width,
                endian,
                signed,
                expect,
            } => {
                let end = pos + *width as u64;
                let bytes = self.read(path, pos, *width as u64, hard_end, None)?;
                let raw = read_uint(bytes, *endian);
                let value = if *signed {
                    sign_extend(raw, *width)
                } else {
                    raw as i64
                };
                if let Some(want) = expect {
                    if value != *want {
                        return Err(self.violation(
                            path.into(),
                            pos,
                            format!("常量字段期望 {}，实际 {}", want, value),
                        ));
                    }
                }
                let mut n = Node::new(name, "int", pos, end, NodeStatus::Ok);
                n.value_int = Some(value);
                n.detail = Some(format!("{} 字节 {:?}", width, endian));
                children.push(n);
                Ok((
                    end,
                    FieldInfo {
                        start: pos,
                        end,
                        value_int: Some(value),
                    },
                ))
            }

            FieldDef::Bytes { name, length } => {
                let (nlen, len_start) = self.resolve(length, local, ancestors, pos)?;
                let end = pos.saturating_add(nlen);
                let bytes = self.read(path, pos, nlen, hard_end, len_start)?;
                let mut n = Node::new(name, "bytes", pos, end, NodeStatus::Ok);
                n.value_hex = Some(hex_of(bytes));
                n.detail = Some(format!("{} 字节", nlen));
                children.push(n);
                Ok((end, FieldInfo { start: pos, end, value_int: None }))
            }

            FieldDef::Payload { name, length_field } => {
                let info = lookup_ref(local, ancestors, length_field).ok_or_else(|| {
                    self.violation(
                        path.into(),
                        pos,
                        format!("payload 长度字段 `{}` 不存在", length_field),
                    )
                })?;
                let nlen = match info.value_int {
                    Some(v) if v >= 0 => v as u64,
                    _ => {
                        return Err(self.violation(
                            path.into(),
                            info.start,
                            format!("payload 长度字段 `{}` 不是非负整数", length_field),
                        ))
                    }
                };
                let end = pos.saturating_add(nlen);
                let bytes = self.read(path, pos, nlen, hard_end, Some(info.start))?;
                let mut n = Node::new(name, "payload", pos, end, NodeStatus::Ok);
                n.value_hex = Some(hex_of(bytes));
                n.detail = Some(format!("payload {} 字节，长度字段 {}", nlen, length_field));
                children.push(n);
                Ok((end, FieldInfo { start: pos, end, value_int: None }))
            }

            FieldDef::Checksum {
                name,
                width,
                algorithm,
                endian,
                start,
                end,
            } => {
                let end_off = pos + *width as u64;
                let bytes = self.read(path, pos, *width as u64, hard_end, None)?;
                let expected = read_uint(bytes, *endian);
                let cover_start = struct_start + start.unwrap_or(0);
                let cover_end = match end {
                    None | Some(EndRef::StructEnd) => hard_end,
                    Some(EndRef::Field(field)) => match lookup_ref(local, ancestors, field) {
                        Some(info) => info.end,
                        None => {
                            return Err(self.violation(
                                path.into(),
                                pos,
                                format!("覆盖终点字段 `{}` 不存在", field),
                            ))
                        }
                    },
                };
                let mut n = Node::new(name, "checksum", pos, end_off, NodeStatus::Ok);
                n.value_int = Some(expected as i64);
                n.detail = Some(format!(
                    "{:?}，覆盖 [{},{})，跳过自身",
                    algorithm, cover_start, cover_end
                ));
                children.push(n);
                let child_idx = children.len() - 1;
                pending.push(PendingChecksum {
                    child_idx,
                    algo: *algorithm,
                    width: *width,
                    cover_start,
                    cover_end,
                    own_start: pos,
                    own_end: end_off,
                    expected,
                    path: path.to_string(),
                });
                Ok((
                    end_off,
                    FieldInfo {
                        start: pos,
                        end: end_off,
                        value_int: Some(expected as i64),
                    },
                ))
            }

            complex => self.parse_complex(complex, path, pos, hard_end, depth, local, ancestors, children),
        }
    }

    fn resolve(
        &self,
        expr: &LengthExpr,
        local: &Scope,
        ancestors: &[&Scope],
        pos: u64,
    ) -> Result<(u64, Option<u64>), Fail> {
        match expr {
            LengthExpr::Fixed(v) => Ok((*v, None)),
            LengthExpr::Field(ln) => {
                let info = lookup_ref(local, ancestors, ln).ok_or_else(|| {
                    self.violation(
                        ln.into(),
                        pos,
                        format!("引用的长度字段 `{}` 不存在", ln),
                    )
                })?;
                match info.value_int {
                    Some(v) if v >= 0 => Ok((v as u64, Some(info.start))),
                    _ => Err(self.violation(
                        ln.into(),
                        info.start,
                        format!("长度字段 `{}` 不是非负整数", ln),
                    )),
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn parse_complex(
        &mut self,
        fdef: &FieldDef,
        path: &str,
        pos: u64,
        hard_end: u64,
        depth: u32,
        local: &Scope,
        ancestors: &[&Scope],
        children: &mut Vec<Node>,
    ) -> Result<(u64, FieldInfo), Fail> {
        match fdef {
            FieldDef::Struct { name, ty, length } => {
                let bound = match length {
                    None => hard_end,
                    Some(expr) => {
                        let (n, _) = self.resolve(expr, local, ancestors, pos)?;
                        let b = pos.saturating_add(n);
                        if b > hard_end {
                            return Err(self.violation(
                                path.into(),
                                pos,
                                format!("定界子结构到偏移 {} 越过父边界 {}", b, hard_end),
                            ));
                        }
                        b
                    }
                };
                // 子结构体有自己的字段作用域：不继承父结构体内的字段，
                // 但仍受父硬边界（bound/hard_end）约束。
                let no_ancestors: [&Scope; 0] = [];
                let mut res = self.parse_struct(ty, path, pos, bound, depth + 1, &no_ancestors)?;
                res.node.name = name.clone();
                if length.is_some() && res.end < bound {
                    self.warnings.push(Diagnostic {
                        level: "warning".into(),
                        message: format!("定界子结构剩余 {} 字节未消费", bound - res.end),
                        path: path.into(),
                        offset: res.end,
                    });
                }
                children.push(res.node);
                Ok((bound, FieldInfo { start: pos, end: bound, value_int: None }))
            }

            FieldDef::Vector {
                name,
                count,
                bounded,
                element,
            } => {
                let mut node = Node::new(name, "vector", pos, pos, NodeStatus::Ok);
                let nested = chain_ancestors(local, ancestors);
                let mut end = pos;
                match (count, bounded) {
                    (Some(expr), _) => {
                        let (n, _) = self.resolve(expr, local, ancestors, pos)?;
                        for i in 0..n {
                            let ep = join(path, &format!("[{}]", i));
                            end = self.parse_element(
                                element, &ep, end, hard_end, depth, &nested, &mut node.children,
                            )?;
                        }
                    }
                    (None, Some(expr)) => {
                        let (n, _) = self.resolve(expr, local, ancestors, pos)?;
                        let bound = pos.saturating_add(n);
                        if bound > hard_end {
                            return Err(self.violation(
                                path.into(),
                                pos,
                                format!("vector 区间到偏移 {} 越过父边界 {}", bound, hard_end),
                            ));
                        }
                        let mut i = 0u64;
                        while end < bound {
                            let ep = join(path, &format!("[{}]", i));
                            let advanced = self.parse_element(
                                element, &ep, end, bound, depth, &nested, &mut node.children,
                            )?;
                            if advanced <= end {
                                return Err(self.violation(ep, end, "vector 元素未推进解析".into()));
                            }
                            end = advanced;
                            i += 1;
                        }
                    }
                    (None, None) => {
                        return Err(self.violation(path.into(), pos, "vector 缺少 count/bounded".into()))
                    }
                }
                node.end = end;
                children.push(node);
                Ok((end, FieldInfo { start: pos, end, value_int: None }))
            }

            FieldDef::Switch {
                name,
                on,
                cases,
                fallback,
            } => {
                let selector_info = lookup_ref(local, ancestors, on).ok_or_else(|| {
                    self.violation(path.into(), pos, format!("判据字段 `{}` 不存在", on))
                })?;
                let selector = selector_info.value_int.ok_or_else(|| {
                    self.violation(path.into(), selector_info.start, "判据不是整数".into())
                })?;
                let case_fields: Option<&Vec<FieldDef>> = cases
                    .get(&selector.to_string())
                    .map(|c| &c.fields)
                    .or_else(|| fallback.as_ref().map(|c| &c.fields));
                let fields = match case_fields {
                    Some(f) => f,
                    None => {
                        return Err(self.violation(
                            path.into(),
                            selector_info.start,
                            format!("switch 没有匹配 {} 的分支", selector),
                        ))
                    }
                };
                let mut node = Node::new(name, "switch", pos, pos, NodeStatus::Ok);
                node.detail = Some(format!("{} = {}", on, selector));
                let mut sub = Scope::default();
                let outer = chain_ancestors(local, ancestors);
                let mut end = pos;
                for cf in fields {
                    let cp = join(path, cf.name());
                    let (adv, info) = self.parse_field(
                        cf,
                        &cp,
                        end,
                        hard_end,
                        depth,
                        pos,
                        &sub,
                        &outer,
                        &mut node.children,
                        &mut Vec::new(),
                    )?;
                    sub.put(cf.name(), info);
                    end = adv;
                }
                node.end = end;
                children.push(node);
                Ok((end, FieldInfo { start: pos, end, value_int: None }))
            }

            _ => Err(self.violation(path.into(), pos, "不支持的字段".into())),
        }
    }

    fn parse_element(
        &mut self,
        elem: &FieldDef,
        path: &str,
        pos: u64,
        hard_end: u64,
        depth: u32,
        ancestors: &[&Scope],
        out: &mut Vec<Node>,
    ) -> Result<u64, Fail> {
        match elem {
            FieldDef::Struct { ty, .. } => {
                let none: [&Scope; 0] = [];
                let res = self.parse_struct(ty, path, pos, hard_end, depth + 1, &none)?;
                out.push(res.node);
                Ok(res.end)
            }
            other => {
                let empty = Scope::default();
                let (adv, _) = self.parse_field(
                    other,
                    path,
                    pos,
                    hard_end,
                    depth,
                    pos,
                    &empty,
                    ancestors,
                    out,
                    &mut Vec::new(),
                )?;
                Ok(adv)
            }
        }
    }

    fn finish_checksums(
        &mut self,
        struct_start: u64,
        struct_end: u64,
        node: &mut Node,
        pending: &[PendingChecksum],
    ) -> Result<(), Fail> {
        for pc in pending {
            let cs_start = pc.cover_start.max(struct_start);
            let mut cs_end = pc.cover_end.min(struct_end);
            if cs_end < cs_start {
                cs_end = cs_start;
            }
            if cs_end > self.input.len() as u64 {
                self.need_end = self.need_end.max(cs_end);
                return Err(self.incomplete(pc.path.clone(), pc.own_start, cs_end));
            }
            let got = self.compute_checksum(
                pc.algo, cs_start, cs_end, pc.own_start, pc.own_end,
            );
            let mask = if pc.width == 8 {
                u64::MAX
            } else {
                (1u64 << (pc.width * 8)) - 1
            };
            let got = got & mask;
            if got != pc.expected {
                let width = (pc.width as usize) * 2;
                let child = &mut node.children[pc.child_idx];
                child.status = NodeStatus::Violation;
                child.detail = Some(format!(
                    "校验失败：期望 0x{:0w$x}，实际 0x{:0w$x}（已跳过自身字段）",
                    pc.expected, got, w = width
                ));
                self.warnings.push(Diagnostic {
                    level: "warning".into(),
                    message: format!(
                        "校验和不匹配：期望 0x{:0w$x}，实际 0x{:0w$x}",
                        pc.expected, got, w = width
                    ),
                    path: pc.path.clone(),
                    offset: pc.own_start,
                });
            }
        }
        Ok(())
    }

    /// 在 [cs_start, cs_end) 上计算校验和，跳过校验和自身字段区间。
    fn compute_checksum(
        &self,
        algo: ChecksumAlgo,
        cs_start: u64,
        cs_end: u64,
        own_start: u64,
        own_end: u64,
    ) -> u64 {
        let mut sum = 0u64;
        let mut crc = 0xFFFF_FFFFu32;
        let mut pos = cs_start;
        while pos < cs_end {
            if pos >= own_start && pos < own_end {
                pos += 1;
                continue;
            }
            let b = self.input[pos as usize];
            match algo {
                ChecksumAlgo::Sum8 | ChecksumAlgo::Sum16 => sum += b as u64,
                ChecksumAlgo::Xor8 => sum ^= b as u64,
                ChecksumAlgo::Crc32 => crc = crc32_update(crc, b),
            }
            pos += 1;
        }
        match algo {
            ChecksumAlgo::Sum8 => sum & 0xff,
            ChecksumAlgo::Xor8 => sum & 0xff,
            ChecksumAlgo::Sum16 => sum & 0xffff,
            ChecksumAlgo::Crc32 => (crc ^ 0xFFFF_FFFF) as u64,
        }
    }
}

/// 组合 [本层作用域, 祖先作用域...]，作为嵌套结构的祖先链。
fn chain_ancestors<'s>(local: &'s Scope, ancestors: &'s [&'s Scope]) -> Vec<&'s Scope> {
    let mut v = Vec::with_capacity(ancestors.len() + 1);
    v.push(local);
    v.extend_from_slice(ancestors);
    v
}

fn read_uint(bytes: &[u8], endian: Endian) -> u64 {
    let mut v = 0u64;
    match endian {
        Endian::Be => {
            for b in bytes {
                v = (v << 8) | *b as u64;
            }
        }
        Endian::Le => {
            for b in bytes.iter().rev() {
                v = (v << 8) | *b as u64;
            }
        }
    }
    v
}

fn sign_extend(raw: u64, width: u32) -> i64 {
    let bits = width * 8;
    if bits < 64 && (raw >> (bits - 1)) & 1 == 1 {
        (raw as i64) | !(((1u64 << bits) - 1) as i64)
    } else {
        raw as i64
    }
}

fn hex_of(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn crc32_update(mut crc: u32, byte: u8) -> u32 {
    crc ^= byte as u32;
    for _ in 0..8 {
        let mask = (crc & 1).wrapping_neg();
        crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
    }
    crc
}

/// CRC-32（IEEE/zlib）。
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for b in data {
        crc = crc32_update(crc, *b);
    }
    crc ^ 0xFFFF_FFFF
}

/// 编码器侧使用：在一段字节上计算校验值。
pub fn checksum_of(algo: ChecksumAlgo, data: &[u8]) -> u64 {
    let mut sum = 0u64;
    let mut crc = 0xFFFF_FFFFu32;
    for b in data {
        match algo {
            ChecksumAlgo::Sum8 | ChecksumAlgo::Sum16 => sum += *b as u64,
            ChecksumAlgo::Xor8 => sum ^= *b as u64,
            ChecksumAlgo::Crc32 => crc = crc32_update(crc, *b),
        }
    }
    match algo {
        ChecksumAlgo::Sum8 => sum & 0xff,
        ChecksumAlgo::Xor8 => sum & 0xff,
        ChecksumAlgo::Sum16 => sum & 0xffff,
        ChecksumAlgo::Crc32 => (crc ^ 0xFFFF_FFFF) as u64,
    }
}

// ---- JSON 序列化（无第三方依赖）----

use crate::json::{obj as jobj, Json};

fn js_str(s: &str) -> Json {
    Json::string(s)
}
fn js_opt_str(s: &Option<String>) -> Json {
    match s {
        Some(v) => Json::string(v),
        None => Json::Null,
    }
}

impl NodeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            NodeStatus::Ok => "ok",
            NodeStatus::Incomplete => "incomplete",
            NodeStatus::Violation => "violation",
        }
    }
}

impl Node {
    pub fn to_json(&self) -> Json {
        let mut pairs = vec![
            ("name", js_str(&self.name)),
            ("kind", js_str(&self.kind)),
            ("start", Json::from_u64(self.start)),
            ("end", Json::from_u64(self.end)),
            ("status", js_str(self.status.as_str())),
        ];
        match self.value_int {
            Some(v) => pairs.push(("value_int", Json::from_i64(v))),
            None => pairs.push(("value_int", Json::Null)),
        }
        match &self.value_hex {
            Some(v) => pairs.push(("value_hex", js_str(v))),
            None => pairs.push(("value_hex", Json::Null)),
        }
        pairs.push(("detail", js_opt_str(&self.detail)));
        pairs.push((
            "children",
            Json::Arr(self.children.iter().map(|c| c.to_json()).collect()),
        ));
        jobj(pairs)
    }

    pub fn from_json(j: &Json) -> Result<Node, String> {
        let name = j.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let kind = j.get("kind").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let start = j.get("start").and_then(|v| v.as_u64()).unwrap_or(0);
        let end = j.get("end").and_then(|v| v.as_u64()).unwrap_or(0);
        let status = match j.get("status").and_then(|v| v.as_str()) {
            Some("incomplete") => NodeStatus::Incomplete,
            Some("violation") => NodeStatus::Violation,
            _ => NodeStatus::Ok,
        };
        let value_int = j.get("value_int").and_then(|v| v.as_i64());
        let value_hex = j.get("value_hex").and_then(|v| v.as_str()).map(String::from);
        let detail = j.get("detail").and_then(|v| v.as_str()).map(String::from);
        let mut children = Vec::new();
        if let Some(arr) = j.get("children").and_then(|v| v.as_array()) {
            for c in arr {
                children.push(Node::from_json(c)?);
            }
        }
        Ok(Node {
            name,
            kind,
            start,
            end,
            status,
            value_int,
            value_hex,
            detail,
            children,
        })
    }
}

impl Diagnostic {
    pub fn to_json(&self) -> Json {
        jobj(vec![
            ("level", js_str(&self.level)),
            ("message", js_str(&self.message)),
            ("path", js_str(&self.path)),
            ("offset", Json::from_u64(self.offset)),
        ])
    }
    pub fn from_json(j: &Json) -> Result<Diagnostic, String> {
        Ok(Diagnostic {
            level: j.get("level").and_then(|v| v.as_str()).unwrap_or("warning").into(),
            message: j.get("message").and_then(|v| v.as_str()).unwrap_or("").into(),
            path: j.get("path").and_then(|v| v.as_str()).unwrap_or("").into(),
            offset: j.get("offset").and_then(|v| v.as_u64()).unwrap_or(0),
        })
    }
}

impl Outcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Outcome::Complete => "complete",
            Outcome::Incomplete => "incomplete",
            Outcome::Violation => "violation",
        }
    }
    fn parse(s: &str) -> Outcome {
        match s {
            "incomplete" => Outcome::Incomplete,
            "violation" => Outcome::Violation,
            _ => Outcome::Complete,
        }
    }
}

impl ParseReport {
    pub fn to_json(&self) -> Json {
        jobj(vec![
            ("outcome", js_str(self.outcome.as_str())),
            ("need_bytes", Json::from_u64(self.need_bytes)),
            (
                "tree",
                match &self.tree {
                    Some(n) => n.to_json(),
                    None => Json::Null,
                },
            ),
            (
                "warnings",
                Json::Arr(self.warnings.iter().map(|w| w.to_json()).collect()),
            ),
            ("error_path", js_opt_str(&self.error_path)),
            (
                "error_offset",
                self.error_offset.map(Json::from_u64).unwrap_or(Json::Null),
            ),
            ("error_message", js_opt_str(&self.error_message)),
        ])
    }

    pub fn from_json(j: &Json) -> Result<ParseReport, String> {
        let outcome = Outcome::parse(j.get("outcome").and_then(|v| v.as_str()).unwrap_or("complete"));
        let need_bytes = j.get("need_bytes").and_then(|v| v.as_u64()).unwrap_or(0);
        let tree = match j.get("tree") {
            Some(Json::Null) | None => None,
            Some(t) => Some(Node::from_json(t)?),
        };
        let mut warnings = Vec::new();
        if let Some(arr) = j.get("warnings").and_then(|v| v.as_array()) {
            for w in arr {
                warnings.push(Diagnostic::from_json(w)?);
            }
        }
        Ok(ParseReport {
            outcome,
            need_bytes,
            tree,
            warnings,
            error_path: j.get("error_path").and_then(|v| v.as_str()).map(String::from),
            error_offset: j.get("error_offset").and_then(|v| v.as_u64()),
            error_message: j.get("error_message").and_then(|v| v.as_str()).map(String::from),
        })
    }
}
