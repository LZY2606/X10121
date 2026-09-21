//! 解析引擎：把字节流映射为解析树，区分“输入不完整”与“违反协议”。
use crate::protocol::{Cover, Endian, Node, Protocol};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TreeNode {
    pub name: String,
    pub path: String,
    pub kind: String,
    pub start: usize,
    /// 半开区间终点
    pub end: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<serde_json::Value>,
    pub status: String, // "ok" | "warn"
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub children: Vec<TreeNode>,
    /// 字节改动后重新解析时被重新计算的节点（仅内存/响应中使用）
    #[serde(default)]
    pub recomputed: bool,
}

impl TreeNode {
    fn new(name: &str, path: &str, kind: &str, start: usize, end: usize) -> Self {
        TreeNode {
            name: name.to_string(),
            path: path.to_string(),
            kind: kind.to_string(),
            start,
            end,
            value: None,
            status: "ok".to_string(),
            message: None,
            children: Vec::new(),
            recomputed: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ParseOutcome {
    /// 解析成功；可能附带警告（如尾部多余字节）
    Ok { tree: TreeNode, warnings: Vec<String> },
    /// 输入尚未完整：给出最深层字段路径与仍需字节的下界
    Incomplete { path: String, needed_at_least: usize },
    /// 输入已违反协议：给出最深层字段路径与字节偏移
    Violation { path: String, offset: usize, message: String },
}

#[derive(Debug, Clone)]
enum ParseError {
    Incomplete { path: String, needed_at_least: usize },
    Violation { path: String, offset: usize, message: String },
}

impl ParseError {
    fn violation(path: &str, offset: usize, message: impl Into<String>) -> Self {
        ParseError::Violation { path: path.to_string(), offset, message: message.into() }
    }
}

pub fn parse(protocol: &Protocol, input: &[u8]) -> ParseOutcome {
    let mut p = Parser { input, max_depth: protocol.max_depth, warnings: Vec::new() };
    let root_path = protocol.root.name().to_string();
    match p.parse_node(&protocol.root, 0, input.len(), 1, &root_path, &[]) {
        Ok((tree, cursor)) => {
            if cursor < input.len() {
                p.warnings.push(format!(
                    "{} trailing byte(s) after frame at offset {}",
                    input.len() - cursor,
                    cursor
                ));
            }
            ParseOutcome::Ok { tree, warnings: p.warnings }
        }
        Err(ParseError::Incomplete { path, needed_at_least }) => {
            ParseOutcome::Incomplete { path, needed_at_least }
        }
        Err(ParseError::Violation { path, offset, message }) => {
            ParseOutcome::Violation { path, offset, message }
        }
    }
}

struct Parser<'a> {
    input: &'a [u8],
    max_depth: usize,
    warnings: Vec<String>,
}

impl<'a> Parser<'a> {
    /// 边界检查：需要 [cursor, cursor+len) 落在父窗口内。
    /// 父窗口即整个输入 → 视为“输入不完整”；否则视为“越出父结构边界”的违约。
    fn need(&self, path: &str, cursor: usize, len: usize, window_end: usize) -> Result<(), ParseError> {
        let required_end = cursor.checked_add(len).ok_or_else(|| {
            ParseError::violation(path, cursor, "declared length overflows address space")
        })?;
        if required_end <= window_end {
            return Ok(());
        }
        if window_end == self.input.len() {
            Err(ParseError::Incomplete {
                path: path.to_string(),
                needed_at_least: required_end - self.input.len(),
            })
        } else {
            Err(ParseError::violation(
                path,
                cursor,
                format!(
                    "field needs {} byte(s) but only {} remain within parent bounds",
                    len,
                    window_end.saturating_sub(cursor)
                ),
            ))
        }
    }

    fn parse_node(
        &mut self,
        node: &Node,
        cursor: usize,
        window_end: usize,
        depth: usize,
        path: &str,
        siblings: &[TreeNode],
    ) -> Result<(TreeNode, usize), ParseError> {
        match node {
            Node::Uint { name, size, endian } => {
                self.check_int_size(path, cursor, *size)?;
                self.need(path, cursor, *size, window_end)?;
                let value = read_uint(self.input, cursor, *size, *endian);
                let mut n = TreeNode::new(name, path, "uint", cursor, cursor + size);
                n.value = Some(serde_json::Value::from(value));
                Ok((n, cursor + size))
            }
            Node::Bytes { name, size } => {
                self.need(path, cursor, *size, window_end)?;
                let mut n = TreeNode::new(name, path, "bytes", cursor, cursor + size);
                n.value = Some(serde_json::Value::from(hex_encode(&self.input[cursor..cursor + size])));
                Ok((n, cursor + size))
            }
            Node::VarBytes { name, len_from, max } => {
                let len = lookup_u64(siblings, len_from).ok_or_else(|| {
                    ParseError::violation(path, cursor, format!("unknown length field '{len_from}'"))
                })?;
                let len = usize::try_from(len).map_err(|_| {
                    ParseError::violation(path, cursor, "declared length does not fit in memory")
                })?;
                if let Some(m) = max {
                    if len > *m {
                        return Err(ParseError::violation(
                            path,
                            cursor,
                            format!("declared length {len} exceeds maximum {m}"),
                        ));
                    }
                }
                self.need(path, cursor, len, window_end)?;
                let mut n = TreeNode::new(name, path, "var_bytes", cursor, cursor + len);
                n.value = Some(serde_json::Value::from(hex_encode(&self.input[cursor..cursor + len])));
                Ok((n, cursor + len))
            }
            Node::Seq { name, len_from, children } => {
                if depth > self.max_depth {
                    return Err(ParseError::violation(
                        path,
                        cursor,
                        format!("recursion depth limit exceeded (max_depth = {})", self.max_depth),
                    ));
                }
                let (end, bounded) = match len_from {
                    Some(lf) => {
                        let l = lookup_u64(siblings, lf).ok_or_else(|| {
                            ParseError::violation(path, cursor, format!("unknown length field '{lf}'"))
                        })?;
                        let l = usize::try_from(l).map_err(|_| {
                            ParseError::violation(path, cursor, "declared length does not fit in memory")
                        })?;
                        self.need(path, cursor, l, window_end)?;
                        (cursor + l, true)
                    }
                    None => (window_end, false),
                };
                let mut child_cursor = cursor;
                let mut child_nodes: Vec<TreeNode> = Vec::new();
                for child in children {
                    let child_path = format!("{path}/{}", child.name());
                    let (n, nc) =
                        self.parse_node(child, child_cursor, end, depth + 1, &child_path, &child_nodes)?;
                    child_cursor = nc;
                    child_nodes.push(n);
                }
                let mut node = TreeNode::new(name, path, "seq", cursor, if bounded { end } else { child_cursor });
                if bounded && child_cursor < end {
                    node.status = "warn".to_string();
                    node.message = Some(format!("{} unparsed byte(s) within declared bounds", end - child_cursor));
                }
                node.children = child_nodes;
                Ok((node, if bounded { end } else { child_cursor }))
            }
            Node::If { name, cond, then } => {
                let actual = lookup_u64(siblings, &cond.field).ok_or_else(|| {
                    ParseError::violation(path, cursor, format!("unknown condition field '{}'", cond.field))
                })?;
                if cond.op.apply(actual, cond.value) {
                    let child_path = format!("{path}/{}", then.name());
                    let (child, nc) = self.parse_node(then, cursor, window_end, depth + 1, &child_path, siblings)?;
                    let mut node = TreeNode::new(name, path, "if", cursor, nc);
                    node.children = vec![child];
                    Ok((node, nc))
                } else {
                    let mut node = TreeNode::new(name, path, "if", cursor, cursor);
                    node.message = Some("condition false; skipped".to_string());
                    Ok((node, cursor))
                }
            }
            Node::Checksum { name, size, endian, algo, cover, skip_self } => {
                self.check_int_size(path, cursor, *size)?;
                self.need(path, cursor, *size, window_end)?;
                let actual = read_uint(self.input, cursor, *size, *endian);
                let (from_start, to_end) =
                    self.resolve_cover(path, cursor, window_end, cover.as_ref(), siblings)?;
                let mut data = Vec::with_capacity(to_end.saturating_sub(from_start));
                for i in from_start..to_end {
                    if *skip_self && i >= cursor && i < cursor + size {
                        continue; // 校验和区间跳过自身字段
                    }
                    data.push(self.input[i]);
                }
                let expected = algo.compute(&data);
                if expected == actual {
                    let mut n = TreeNode::new(name, path, "checksum", cursor, cursor + size);
                    n.value = Some(serde_json::Value::from(actual));
                    Ok((n, cursor + size))
                } else {
                    Err(ParseError::violation(
                        path,
                        cursor,
                        format!("checksum mismatch: expected {expected:#06x}, got {actual:#06x}"),
                    ))
                }
            }
        }
    }

    fn check_int_size(&self, path: &str, cursor: usize, size: usize) -> Result<(), ParseError> {
        if size == 0 || size > 8 {
            return Err(ParseError::violation(
                path,
                cursor,
                format!("unsupported integer size {size} (allowed 1..=8)"),
            ));
        }
        Ok(())
    }

    fn resolve_cover(
        &self,
        path: &str,
        cursor: usize,
        window_end: usize,
        cover: Option<&Cover>,
        siblings: &[TreeNode],
    ) -> Result<(usize, usize), ParseError> {
        let from_start = match cover.and_then(|c| c.from.as_deref()) {
            Some(name) => siblings
                .iter()
                .find(|s| s.name == name)
                .map(|s| s.start)
                .ok_or_else(|| ParseError::violation(path, cursor, format!("unknown cover field '{name}'")))?,
            None => siblings.first().map(|s| s.start).unwrap_or(cursor),
        };
        let to_end = match cover.and_then(|c| c.to.as_deref()) {
            Some("@self") => cursor,
            Some("@end") => window_end,
            Some(name) => siblings
                .iter()
                .find(|s| s.name == name)
                .map(|s| s.end)
                .ok_or_else(|| ParseError::violation(path, cursor, format!("unknown cover field '{name}'")))?,
            None => cursor,
        };
        if from_start > to_end || to_end > self.input.len() {
            return Err(ParseError::violation(path, cursor, "invalid checksum cover range"));
        }
        Ok((from_start, to_end))
    }
}

fn lookup_u64(siblings: &[TreeNode], name: &str) -> Option<u64> {
    siblings
        .iter()
        .find(|s| s.name == name)
        .and_then(|s| s.value.as_ref())
        .and_then(|v| v.as_u64())
}

fn read_uint(input: &[u8], cursor: usize, size: usize, endian: Endian) -> u64 {
    let mut v: u64 = 0;
    match endian {
        Endian::Big => {
            for i in 0..size {
                v = (v << 8) | input[cursor + i] as u64;
            }
        }
        Endian::Little => {
            for i in 0..size {
                v |= (input[cursor + i] as u64) << (8 * i);
            }
        }
    }
    v
}

/// 字节改动后重新解析：按“同名同序”匹配旧树，标记被重新计算的节点。
pub fn mark_recomputed(new: &mut TreeNode, old: Option<&TreeNode>) {
    let changed = match old {
        None => true,
        Some(o) => {
            o.name != new.name
                || o.start != new.start
                || o.end != new.end
                || o.value != new.value
                || o.status != new.status
                || o.message != new.message
        }
    };
    new.recomputed = changed;
    let mut idx = 0;
    while idx < new.children.len() {
        let ordinal = new.children[..idx]
            .iter()
            .filter(|c| c.name == new.children[idx].name)
            .count();
        let old_child = old.and_then(|o| {
            o.children
                .iter()
                .filter(|c| c.name == new.children[idx].name)
                .nth(ordinal)
        });
        mark_recomputed(&mut new.children[idx], old_child);
        idx += 1;
    }
}

/// 解析树摘要：对规范化（不含 recomputed 标记）的树做 SHA-256。
pub fn tree_digest(tree: &TreeNode) -> String {
    let mut s = String::new();
    canonical_tree(tree, &mut s);
    sha256_hex(s.as_bytes())
}

fn canonical_tree(n: &TreeNode, out: &mut String) {
    out.push_str(&n.name);
    out.push('|');
    out.push_str(&n.kind);
    out.push('|');
    out.push_str(&n.start.to_string());
    out.push('|');
    out.push_str(&n.end.to_string());
    out.push('|');
    out.push_str(&n.status);
    out.push('|');
    if let Some(v) = &n.value {
        out.push_str(&v.to_string());
    }
    out.push('|');
    if let Some(m) = &n.message {
        out.push_str(m);
    }
    out.push_str("{\n");
    for c in &n.children {
        canonical_tree(c, out);
    }
    out.push_str("}\n");
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex_encode(&Sha256::digest(data))
}

pub fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0xf) as usize] as char);
    }
    s
}

pub fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    let cleaned: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if cleaned.len() % 2 != 0 {
        return Err("hex string has odd length".to_string());
    }
    let mut out = Vec::with_capacity(cleaned.len() / 2);
    for pair in cleaned.chunks(2) {
        let hi = (pair[0] as char).to_digit(16).ok_or("invalid hex digit")?;
        let lo = (pair[1] as char).to_digit(16).ok_or("invalid hex digit")?;
        out.push(((hi << 4) | lo) as u8);
    }
    Ok(out)
}
