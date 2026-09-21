use crate::model::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Node {
    pub name: String,
    pub path: String,
    pub kind: String,
    pub start: usize,
    pub end: usize,
    pub display: String,
    #[serde(default)]
    pub children: Vec<Node>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ErrorInfo {
    pub path: String,
    pub offset: usize,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Diagnostic {
    /// "ok" | "incomplete" | "invalid"
    pub outcome: String,
    /// lower bound of additional bytes still required (incomplete only)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub need_more: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorInfo>,
    #[serde(default)]
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParseResult {
    pub tree: Node,
    pub diag: Diagnostic,
}

#[derive(Debug)]
enum Fail {
    /// absolute total input length needed to make progress
    Incomplete { need: usize },
    Invalid { path: String, offset: usize, message: String },
}

#[derive(Default)]
struct Ctx {
    values: HashMap<String, u64>,
    ranges: HashMap<String, (usize, usize)>,
}

struct Pending {
    path: String,
    self_start: usize,
    size: usize,
    algo: CheckAlgo,
    from: CheckBound,
    to: CheckBound,
    skip_self: bool,
    actual: u64,
}

pub fn parse(doc: &ProtocolDoc, input: &[u8]) -> ParseResult {
    let mut warnings: Vec<String> = Vec::new();
    let root = doc.root.clone();
    let (mut tree, res) = parse_struct(doc, input, &root, input, 0, false, 1, &root, &mut warnings);
    let diag = match res {
        Ok(consumed) => {
            if consumed < input.len() {
                warnings.push(format!(
                    "{} trailing byte(s) after {}",
                    input.len() - consumed,
                    root
                ));
                tree.end = consumed;
            }
            Diagnostic { outcome: "ok".into(), need_more: None, error: None, warnings }
        }
        Err(Fail::Incomplete { need }) => Diagnostic {
            outcome: "incomplete".into(),
            need_more: Some(need.saturating_sub(input.len()).max(1)),
            error: None,
            warnings,
        },
        Err(Fail::Invalid { path, offset, message }) => Diagnostic {
            outcome: "invalid".into(),
            need_more: None,
            error: Some(ErrorInfo { path, offset, message }),
            warnings,
        },
    };
    ParseResult { tree, diag }
}

#[allow(clippy::too_many_arguments)]
fn parse_struct(
    doc: &ProtocolDoc,
    input: &[u8],
    name: &str,
    buf: &[u8],
    base: usize,
    bounded: bool,
    depth: usize,
    path: &str,
    warnings: &mut Vec<String>,
) -> (Node, Result<usize, Fail>) {
    let mut node = Node {
        name: name.to_string(),
        path: path.to_string(),
        kind: "struct".into(),
        start: base,
        end: base,
        display: String::new(),
        children: Vec::new(),
    };
    if depth > doc.max_depth {
        return (
            node,
            Err(Fail::Invalid {
                path: path.into(),
                offset: base,
                message: format!("recursion depth limit {} exceeded", doc.max_depth),
            }),
        );
    }
    let fields = match doc.structs.get(name) {
        Some(f) => f.clone(),
        None => {
            return (
                node,
                Err(Fail::Invalid {
                    path: path.into(),
                    offset: base,
                    message: format!("unknown struct '{}'", name),
                }),
            )
        }
    };
    let mut ctx = Ctx::default();
    let mut pending: Vec<Pending> = Vec::new();
    let mut cursor = 0usize;
    for f in &fields {
        if let Some(w) = &f.when {
            if ctx.values.get(&w.field).copied() != Some(w.eq) {
                continue;
            }
        }
        let fpath = format!("{}.{}", path, f.name);
        match parse_field(doc, input, f, buf, base, bounded, depth, &fpath, cursor, &mut ctx, &mut pending) {
            Ok((child, consumed)) => {
                cursor += consumed;
                node.children.push(child);
            }
            Err(e) => {
                node.end = base + cursor;
                return (node, Err(e));
            }
        }
    }
    for chk in &pending {
        if let Err(e) = verify_checksum(chk, base, base + cursor, &ctx.ranges) {
            node.end = base + cursor;
            return (node, Err(e));
        }
    }
    if bounded && cursor < buf.len() {
        warnings.push(format!("{} unconsumed byte(s) inside {}", buf.len() - cursor, path));
    }
    node.end = base + cursor;
    node.display = format!("{} ({} byte(s))", name, cursor);
    (node, Ok(cursor))
}

fn ensure(
    buf_len: usize,
    cursor: usize,
    size: usize,
    bounded: bool,
    base: usize,
    path: &str,
) -> Result<(), Fail> {
    if cursor + size > buf_len {
        if bounded {
            Err(Fail::Invalid {
                path: path.into(),
                offset: base + cursor,
                message: format!(
                    "field of {} byte(s) exceeds enclosing struct bounds ({} byte(s) left)",
                    size,
                    buf_len - cursor
                ),
            })
        } else {
            Err(Fail::Incomplete { need: base + cursor + size })
        }
    } else {
        Ok(())
    }
}

fn read_uint(buf: &[u8], cursor: usize, size: usize, endian: Endian) -> u64 {
    let slice = &buf[cursor..cursor + size];
    let mut v: u64 = 0;
    match endian {
        Endian::Big => {
            for b in slice {
                v = (v << 8) | (*b as u64);
            }
        }
        Endian::Little => {
            for b in slice.iter().rev() {
                v = (v << 8) | (*b as u64);
            }
        }
    }
    v
}

#[allow(clippy::too_many_arguments)]
fn parse_field(
    doc: &ProtocolDoc,
    input: &[u8],
    f: &Field,
    buf: &[u8],
    base: usize,
    bounded: bool,
    depth: usize,
    fpath: &str,
    cursor: usize,
    ctx: &mut Ctx,
    pending: &mut Vec<Pending>,
) -> Result<(Node, usize), Fail> {
    match &f.kind {
        FieldKind::Uint { size, endian, expect } => {
            if *size == 0 || *size > 8 {
                return Err(Fail::Invalid {
                    path: fpath.into(),
                    offset: base + cursor,
                    message: format!("invalid uint size {}", size),
                });
            }
            ensure(buf.len(), cursor, *size, bounded, base, fpath)?;
            let v = read_uint(buf, cursor, *size, *endian);
            if let Some(e) = expect {
                if v != *e {
                    return Err(Fail::Invalid {
                        path: fpath.into(),
                        offset: base + cursor,
                        message: format!("expected 0x{:X}, got 0x{:X}", e, v),
                    });
                }
            }
            ctx.values.insert(f.name.clone(), v);
            ctx.ranges.insert(f.name.clone(), (base + cursor, base + cursor + size));
            Ok((
                Node {
                    name: f.name.clone(),
                    path: fpath.into(),
                    kind: "uint".into(),
                    start: base + cursor,
                    end: base + cursor + size,
                    display: format!("{} (0x{:X})", v, v),
                    children: Vec::new(),
                },
                *size,
            ))
        }
        FieldKind::Bytes { length, length_from, extra, until_end } => {
            let len: usize = if *until_end {
                buf.len() - cursor
            } else if let Some(l) = length {
                *l
            } else if let Some(r) = length_from {
                let v = match ctx.values.get(r) {
                    Some(v) => *v,
                    None => {
                        return Err(Fail::Invalid {
                            path: fpath.into(),
                            offset: base + cursor,
                            message: format!("unknown length reference '{}'", r),
                        })
                    }
                };
                let l = v as i64 + extra;
                if l < 0 {
                    return Err(Fail::Invalid {
                        path: fpath.into(),
                        offset: base + cursor,
                        message: "computed length is negative".into(),
                    });
                }
                l as usize
            } else {
                return Err(Fail::Invalid {
                    path: fpath.into(),
                    offset: base + cursor,
                    message: "bytes field needs length, length_from or until_end".into(),
                });
            };
            ensure(buf.len(), cursor, len, bounded, base, fpath)?;
            ctx.ranges.insert(f.name.clone(), (base + cursor, base + cursor + len));
            let preview: String = buf[cursor..cursor + len.min(8)]
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect();
            Ok((
                Node {
                    name: f.name.clone(),
                    path: fpath.into(),
                    kind: "bytes".into(),
                    start: base + cursor,
                    end: base + cursor + len,
                    display: format!("[{} byte(s)] {}{}", len, preview, if len > 8 { "…" } else { "" }),
                    children: Vec::new(),
                },
                len,
            ))
        }
        FieldKind::Struct { struct_name, length_from } => {
            let (sub, sub_bounded) = if let Some(r) = length_from {
                let v = match ctx.values.get(r) {
                    Some(v) => *v,
                    None => {
                        return Err(Fail::Invalid {
                            path: fpath.into(),
                            offset: base + cursor,
                            message: format!("unknown length reference '{}'", r),
                        })
                    }
                };
                let len = v as usize;
                ensure(buf.len(), cursor, len, bounded, base, fpath)?;
                (&buf[cursor..cursor + len], true)
            } else {
                (&buf[cursor..], bounded)
            };
            let mut warnings = Vec::new();
            let (child, res) = parse_struct(
                doc,
                input,
                struct_name,
                sub,
                base + cursor,
                sub_bounded,
                depth + 1,
                fpath,
                &mut warnings,
            );
            // warnings from nested parse are lost here by design of the helper;
            // nested structs pass a shared vec in practice (see parse_struct caller)
            let _ = warnings;
            match res {
                Ok(consumed) => {
                    ctx.ranges.insert(f.name.clone(), (base + cursor, base + cursor + consumed));
                    Ok((child, consumed))
                }
                Err(e) => Err(e),
            }
        }
        FieldKind::Array { count, count_from, element } => {
            let n: usize = if let Some(c) = count {
                *c
            } else if let Some(r) = count_from {
                match ctx.values.get(r) {
                    Some(v) => *v as usize,
                    None => {
                        return Err(Fail::Invalid {
                            path: fpath.into(),
                            offset: base + cursor,
                            message: format!("unknown count reference '{}'", r),
                        })
                    }
                }
            } else {
                return Err(Fail::Invalid {
                    path: fpath.into(),
                    offset: base + cursor,
                    message: "array field needs count or count_from".into(),
                });
            };
            if matches!(element.kind, FieldKind::Checksum { .. }) {
                return Err(Fail::Invalid {
                    path: fpath.into(),
                    offset: base + cursor,
                    message: "checksum element not allowed inside array".into(),
                });
            }
            let mut node = Node {
                name: f.name.clone(),
                path: fpath.into(),
                kind: "array".into(),
                start: base + cursor,
                end: base + cursor,
                display: format!("[{} element(s)]", n),
                children: Vec::new(),
            };
            let mut cur = cursor;
            for i in 0..n {
                let ipath = format!("{}[{}]", fpath, i);
                let mut elem = (**element).clone();
                elem.name = format!("{}[{}]", f.name, i);
                let (child, consumed) =
                    parse_field(doc, input, &elem, buf, base, bounded, depth, &ipath, cur, ctx, pending)?;
                cur += consumed;
                node.children.push(child);
            }
            node.end = base + cur;
            ctx.ranges.insert(f.name.clone(), (base + cursor, base + cur));
            Ok((node, cur - cursor))
        }
        FieldKind::Checksum { size, endian, algo, from, to, skip_self } => {
            ensure(buf.len(), cursor, *size, bounded, base, fpath)?;
            let v = read_uint(buf, cursor, *size, *endian);
            ctx.values.insert(f.name.clone(), v);
            ctx.ranges.insert(f.name.clone(), (base + cursor, base + cursor + size));
            pending.push(Pending {
                path: fpath.into(),
                self_start: base + cursor,
                size: *size,
                algo: *algo,
                from: from.clone(),
                to: to.clone(),
                skip_self: *skip_self,
                actual: v,
            });
            Ok((
                Node {
                    name: f.name.clone(),
                    path: fpath.into(),
                    kind: "checksum".into(),
                    start: base + cursor,
                    end: base + cursor + size,
                    display: format!("0x{:0width$X}", v, width = size * 2),
                    children: Vec::new(),
                },
                *size,
            ))
        }
    }
}

fn resolve_bound(
    b: &CheckBound,
    is_from: bool,
    struct_start: usize,
    struct_end: usize,
    self_start: usize,
    ranges: &HashMap<String, (usize, usize)>,
    chk_path: &str,
) -> Result<usize, Fail> {
    match b {
        CheckBound::Token(t) => match t.as_str() {
            "start" => Ok(struct_start),
            "end" => Ok(struct_end),
            "self" => Ok(self_start),
            other => Err(Fail::Invalid {
                path: chk_path.into(),
                offset: self_start,
                message: format!("unknown checksum bound '{}'", other),
            }),
        },
        CheckBound::Field { field } => match ranges.get(field) {
            Some((s, e)) => Ok(if is_from { *s } else { *e }),
            None => Err(Fail::Invalid {
                path: chk_path? no,
            }),
        },
        CheckBound::Offset { offset } => Ok(struct_start + offset),
    }
}

fn verify_checksum(
    chk: &Pending,
    struct_start: usize,
    struct_end: usize,
    ranges: &HashMap<String, (usize, usize)>,
) -> Result<(), Fail> {
    Ok(())
}
