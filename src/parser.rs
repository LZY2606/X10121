//! Frame parser.
//!
//! Three overall states:
//! * [`Status::Complete`]   - every field parsed (warnings may still exist).
//! * [`Status::Incomplete`] - a legal frame prefix; carries a lower bound on
//!   the number of additional bytes required.
//! * [`Status::Error`]      - a protocol violation; carries the deepest field
//!   path reached and the offending byte offset.

use crate::spec::{Condition, FieldDef, Spec, StructDef};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Complete,
    Incomplete,
    Error,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Node {
    pub path: String,
    pub name: String,
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub struct_name: Option<String>,
    pub start: usize,
    pub end: usize,
    pub complete: bool,
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    pub value: serde_json::Value,
    pub children: Vec<Node>,
    pub sig: String,
}

impl Node {
    pub fn covers(&self, offset: usize) -> bool {
        self.start <= offset && offset < self.end
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IncompleteInfo {
    pub need_at_least: usize,
    pub path: String,
    pub offset: usize,
    pub message: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ErrorInfo {
    pub path: String,
    pub offset: usize,
    pub message: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Warning {
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<usize>,
    pub message: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ParseResult {
    pub status: Status,
    pub version_hash: String,
    pub root: Node,
    pub incomplete: Option<IncompleteInfo>,
    pub error: Option<ErrorInfo>,
    pub warnings: Vec<Warning>,
    /// Byte index -> path of the deepest node claiming that byte.
    pub byte_map: Vec<Option<String>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TreeSummary {
    pub status: Status,
    pub node_count: usize,
    pub covered_bytes: usize,
    pub root_sig: String,
}

#[derive(Clone)]
struct IntVal {
    value: u64,
}

struct Ctx<'a> {
    spec: &'a Spec,
    data: &'a [u8],
    scopes: Vec<BTreeMap<String, IntVal>>,
    depth: usize,
    warnings: Vec<Warning>,
    /// True while parsing against a declared (fixed) boundary. When false the
    /// boundary is just "end of available input", so short reads mean
    /// incomplete rather than a protocol violation.
    bounded_stack: Vec<bool>,
}

#[derive(Default)]
struct Stop {
    incomplete: Option<IncompleteInfo>,
    error: Option<ErrorInfo>,
}

enum FieldFail {
    Incomplete(IncompleteInfo),
    Error(ErrorInfo, Option<Node>),
}

/// Parse `data` under `spec`.
pub fn parse(spec: &Spec, data: &[u8]) -> ParseResult {
    let mut ctx = Ctx {
        spec,
        data,
        scopes: Vec::new(),
        depth: 1,
        warnings: Vec::new(),
        bounded_stack: Vec::new(),
    };
    let root_def: &StructDef = spec.root();
    let (mut root, stop) = parse_struct(&mut ctx, root_def, "Frame", "Frame", 0, data.len(), true);

    let mut stop = stop;
    let mut error = stop.error.take();

    if stop.incomplete.is_none() && error.is_none() {
        if let Some(err) = verify_checksums(&ctx, &mut root) {
            error = Some(err);
        }
        if root.end < data.len() {
            ctx.warnings.push(Warning {
                path: "Frame".into(),
                offset: Some(root.end),
                message: format!(
                    "{} trailing byte(s) not consumed by any field",
                    data.len() - root.end
                ),
            });
        }
    }

    finalize_sigs(&mut root);
    let byte_map = build_byte_map(&root, data.len());

    let status = if error.is_some() {
        Status::Error
    } else if stop.incomplete.is_some() {
        Status::Incomplete
    } else {
        Status::Complete
    };

    ParseResult {
        status,
        version_hash: spec.version_hash.clone(),
        root,
        incomplete: stop.incomplete,
        error,
        warnings: ctx.warnings,
        byte_map,
    }
}

pub fn summarize(result: &ParseResult) -> TreeSummary {
    TreeSummary {
        status: result.status,
        node_count: count_nodes(&result.root),
        covered_bytes: result.byte_map.iter().filter(|p| p.is_some()).count(),
        root_sig: result.root.sig.clone(),
    }
}

fn count_nodes(node: &Node) -> usize {
    1 + node.children.iter().map(count_nodes).sum::<usize>()
}

/// Parse one structure. `limit` is the exclusive boundary it must stay within.
fn parse_struct(
    ctx: &mut Ctx,
    sd: &StructDef,
    name: &str,
    path: &str,
    start: usize,
    parent_limit: usize,
    is_root: bool,
) -> (Node, Stop) {
    // An open root (no declared length) grows with the available input; every
    // other structure is bounded by its parent.
    let open_root = is_root && sd.length_field.is_none();
    let initial_limit = if open_root { ctx.data.len() } else { parent_limit };

    ctx.scopes.push(BTreeMap::new());
    // A structure only enforces a hard fill boundary when it declares its own
    // length. A sub-structure without a length field flows to the parent end.
    ctx.bounded_stack.push(sd.length_field.is_some());

    let mut pos = start;
    let mut limit = initial_limit;
    let mut children: Vec<Node> = Vec::new();
    let mut stop = Stop::default();
    let mut declared_end: Option<usize> = None;

    for field in &sd.fields {
        if stop.incomplete.is_some() || stop.error.is_some() {
            break;
        }
        if let Some(cond) = &field.when {
            if !eval_condition(cond, ctx) {
                continue;
            }
        }

        let field_path = join_path(path, &field.name);

        // A declared length field must be the first field and fixes this
        // structure's boundary, at every nesting level.
        if sd.length_field.as_deref() == Some(field.name.as_str()) {
            match parse_int(ctx, field, &field_path, pos, ctx.data.len()) {
                Ok(node) => {
                    let size = int_raw(&node) as usize;
                    record_int(ctx, &node);
                    pos = node.end;
                    let total = start.saturating_add(size);
                    declared_end = Some(total);
                    children.push(node);

                    if total < pos {
                        stop.error = Some(ErrorInfo {
                            path: field_path,
                            offset: start,
                            message: format!(
                                "length field `{}` declares {} bytes but the header already occupies {}",
                                field.name, size, pos - start
                            ),
                        });
                        break;
                    }
                    if total > parent_limit {
                        // The declared structure would escape its parent.
                        if parent_limit < ctx.data.len() || (is_root && total <= ctx.data.len() && false)
                        {
                            stop.error = Some(ErrorInfo {
                                path: field_path,
                                offset: parent_limit,
                                message: format!(
                                    "length field `{}` declares {} bytes, escaping the enclosing boundary at {}",
                                    field.name, size, parent_limit
                                ),
                            });
                            break;
                        }
                        // Not enough bytes present: the frame is incomplete.
                        let need = total.saturating_sub(ctx.data.len()).max(1);
                        stop.incomplete = Some(IncompleteInfo {
                            need_at_least: need,
                            path: field_path,
                            offset: ctx.data.len().min(parent_limit),
                            message: format!(
                                "`{}` declares {} total bytes, {} present (need at least {} more)",
                                name, size, ctx.data.len().min(parent_limit), need
                            ),
                        });
                        break;
                    }
                    if total > ctx.data.len() {
                        stop.incomplete = Some(IncompleteInfo {
                            need_at_least: total - ctx.data.len(),
                            path: field_path,
                            offset: ctx.data.len(),
                            message: format!(
                                "`{}` declares {} total bytes, {} present",
                                name, size, ctx.data.len()
                            ),
                        });
                        break;
                    }
                    limit = total;
                    continue;
                }
                Err(FieldFail::Incomplete(inc)) => {
                    stop.incomplete = Some(inc);
                    break;
                }
                Err(FieldFail::Error(err, partial)) => {
                    if let Some(node) = partial {
                        children.push(node);
                    }
                    stop.error = Some(err);
                    break;
                }
            }
        }

        match parse_field(ctx, field, &field_path, pos, limit) {
            Ok(node) => {
                record_int(ctx, &node);
                pos = node.end;
                children.push(node);
            }
            Err(FieldFail::Incomplete(inc)) => stop.incomplete = Some(inc),
            Err(FieldFail::Error(err, partial)) => {
                if let Some(node) = partial {
                    children.push(node);
                }
                stop.error = Some(err);
            }
        }
    }

    ctx.scopes.pop();
    ctx.bounded_stack.pop();

    let consumed_end = children.last().map(|c| c.end).unwrap_or(start).max(pos);
    let has_declared_length = sd.length_field.is_some();
    let end = if has_declared_length {
        declared_end.unwrap_or(limit)
    } else {
        consumed_end
    };

    if stop.error.is_none()
        && stop.incomplete.is_none()
        && has_declared_length
        && !open_root
        && consumed_end < limit
    {
        ctx.warnings.push(Warning {
            path: path.into(),
            offset: Some(consumed_end),
            message: format!("{} unused byte(s) inside `{}`", limit - consumed_end, name),
        });
    }

    let complete = stop.error.is_none()
        && stop.incomplete.is_none()
        && children.iter().all(|c| c.complete)
        && (!has_declared_length || open_root || consumed_end >= limit);

    let node = Node {
        path: path.into(),
        name: name.into(),
        kind: if is_root { "frame".into() } else { "struct".into() },
        struct_name: Some(sd.name.clone()),
        start,
        end,
        complete,
        value: serde_json::Value::Null,
        children,
        sig: String::new(),
    };
    (node, stop)
}

fn parse_field(
    ctx: &mut Ctx,
    field: &FieldDef,
    path: &str,
    pos: usize,
    limit: usize,
) -> Result<Node, FieldFail> {
    match field.kind.as_str() {
        "int" => parse_int(ctx, field, path, pos, limit),
        "checksum" => parse_checksum(ctx, field, path, pos, limit).map_err(FieldFail::Incomplete),
        "bytes" => parse_bytes(ctx, field, path, pos, limit),
        "cstring" => parse_cstring(ctx, field, path, pos, limit),
        "struct" => parse_struct_field(ctx, field, path, pos, limit),
        "array" => parse_array(ctx, field, path, pos, limit),
        other => Err(FieldFail::Error(
            ErrorInfo {
                path: path.into(),
                offset: pos,
                message: format!("unknown field type `{}`", other),
            },
            None,
        )),
    }
}

fn endian_of(ctx: &Spec, field: &FieldDef) -> crate::spec::Endian {
    field.endian.unwrap_or(ctx.endian)
}

fn missing(width: usize, pos: usize, limit: usize, path: &str, what: &str) -> IncompleteInfo {
    let have = limit.saturating_sub(pos);
    let need = width.saturating_sub(have).max(1);
    IncompleteInfo {
        need_at_least: need,
        path: path.into(),
        offset: limit,
        message: format!("need at least {} more byte(s) for {}", need, what),
    }
}

fn sign_extend(raw: u64, width: usize) -> i128 {
    let bits = width * 8;
    ((raw as i128) << (128 - bits)) >> (128 - bits)
}

fn parse_int(
    ctx: &Ctx,
    field: &FieldDef,
    path: &str,
    pos: usize,
    limit: usize,
) -> Result<Node, FieldFail> {
    let width = field.width.unwrap_or(1);
    if pos + width > limit {
        let bounded = ctx.bounded_stack.last().copied().unwrap_or(false);
        // Only a violation if the declared boundary is fully populated and the
        // field still cannot fit. When the input itself ended first, the frame
        // is simply incomplete.
        if bounded && pos < limit && limit <= ctx.data.len() {
            return Err(FieldFail::Error(
                ErrorInfo {
                    path: path.into(),
                    offset: limit,
                    message: format!(
                        "int `{}` would cross the enclosing boundary at byte {}",
                        field.name, limit
                    ),
                },
                None,
            ));
        }
        return Err(FieldFail::Incomplete(missing(
            width,
            pos,
            limit,
            path,
            &format!("int `{}`", field.name),
        )));
    }
    let raw = &ctx.data[pos..pos + width];
    let raw_val = endian_of(ctx.spec, field).read_u64(raw);

    if let Some(expected) = field.expect {
        let actual = if field.signed {
            sign_extend(raw_val, width) as i64
        } else {
            raw_val as i64
        };
        if actual != expected {
            // Constants identify the frame; a mismatch violates the protocol.
            return Err(FieldFail::Error(
                ErrorInfo {
                    path: path.into(),
                    offset: pos,
                    message: format!(
                        "constant field `{}` = {} but expected {}",
                        field.name, actual, expected
                    ),
                },
                None,
            ));
        }
    }

    let value = if field.signed {
        serde_json::json!(sign_extend(raw_val, width) as i64)
    } else {
        serde_json::json!(raw_val)
    };

    Ok(Node {
        path: path.into(),
        name: field.name.clone(),
        kind: "int".into(),
        struct_name: None,
        start: pos,
        end: pos + width,
        complete: true,
        value,
        children: Vec::new(),
        sig: String::new(),
    })
}

fn parse_checksum(
    ctx: &Ctx,
    field: &FieldDef,
    path: &str,
    pos: usize,
    limit: usize,
) -> Result<Node, IncompleteInfo> {
    let width = field.width.unwrap_or(1);
    if pos + width > limit {
        return Err(missing(width, pos, limit, path, &format!("checksum `{}`", field.name)));
    }
    let raw = &ctx.data[pos..pos + width];
    let actual = endian_of(ctx.spec, field).read_u64(raw);
    Ok(Node {
        path: path.into(),
        name: field.name.clone(),
        kind: "checksum".into(),
        struct_name: None,
        start: pos,
        end: pos + width,
        complete: true,
        value: serde_json::json!({ "actual": actual }),
        children: Vec::new(),
        sig: String::new(),
    })
}

fn lookup_int(ctx: &Ctx, path: &str, name: &str) -> Result<u64, FieldFail> {
    for scope in ctx.scopes.iter().rev() {
        if let Some(v) = scope.get(name) {
            return Ok(v.value);
        }
    }
    Err(FieldFail::Error(
        ErrorInfo {
            path: path.into(),
            offset: 0,
            message: format!("field `{}` referenced before it was parsed", name),
        },
        None,
    ))
}

fn parse_bytes(
    ctx: &Ctx,
    field: &FieldDef,
    path: &str,
    pos: usize,
    limit: usize,
) -> Result<Node, FieldFail> {
    let len = if field.rest {
        limit.saturating_sub(pos)
    } else {
        let length = field.length.as_ref().ok_or_else(|| {
            FieldFail::Error(
                ErrorInfo {
                    path: path.into(),
                    offset: pos,
                    message: format!("bytes field `{}` has no length source", field.name),
                },
                None,
            )
        })?;
        let crate::spec::LengthRef::Field(crate::spec::FieldRef { field: src }) = length;
        let n = lookup_int(ctx, path, src)? as usize;
        if pos + n > limit {
            // A length that would escape the parent boundary is malicious.
            let avail = limit.saturating_sub(pos);
            return if n > avail && ctx.data.len() >= limit {
                Err(FieldFail::Error(
                    ErrorInfo {
                        path: path.to_string(),
                        offset: pos,
                        message: format!(
                            "length `{}` = {} would read past the enclosing boundary ({} byte(s) available)",
                            src, n, avail
                        ),
                    },
                    None,
                ))
            } else {
                Err(FieldFail::Incomplete(missing(
                    n,
                    pos,
                    limit,
                    path,
                    &format!("bytes `{}`", field.name),
                )))
            };
        }
        n
    };

    if let Some(max_len) = field.max_len {
        if len > max_len {
            return Err(FieldFail::Error(
                ErrorInfo {
                    path: path.to_string(),
                    offset: pos,
                    message: format!("bytes `{}` length {} exceeds max_len {}", field.name, len, max_len),
                },
                None,
            ));
        }
    }

    if pos + len > limit {
        return Err(FieldFail::Incomplete(missing(
            len,
            pos,
            limit,
            path,
            &format!("bytes `{}`", field.name),
        )));
    }

    let slice = &ctx.data[pos..pos + len];
    Ok(Node {
        path: path.into(),
        name: field.name.clone(),
        kind: "bytes".into(),
        struct_name: None,
        start: pos,
        end: pos + len,
        complete: true,
        value: serde_json::json!({ "hex": crate::hex::encode(slice) }),
        children: Vec::new(),
        sig: String::new(),
    })
}

fn parse_cstring(
    ctx: &Ctx,
    field: &FieldDef,
    path: &str,
    pos: usize,
    limit: usize,
) -> Result<Node, FieldFail> {
    let bounded = ctx.bounded_stack.last().copied().unwrap_or(false);
    // The scan may run to the end of available input for an open frame, but
    // never beyond the enclosing boundary.
    let scan_end = limit.min(ctx.data.len());
    let mut end = pos;
    while end < scan_end && ctx.data[end] != 0 {
        end += 1;
    }

    if end == scan_end && ctx.data.get(end) != Some(&0) {
        // No NUL found within the scanned region. When more input could still
        // arrive (open frame), this is incomplete; inside a fully populated
        // declared boundary it is a violation.
        let boundary_fully_present = scan_end >= limit;
        if !bounded || !boundary_fully_present {
            return Err(FieldFail::Incomplete(IncompleteInfo {
                need_at_least: 1,
                path: path.into(),
                offset: end,
                message: format!("cstring `{}` is waiting for its NUL terminator", field.name),
            }));
        }
        if let Some(max_len) = field.max_len {
            let len = end - pos;
            if len > max_len {
                return Err(FieldFail::Error(
                    ErrorInfo {
                        path: path.to_string(),
                        offset: pos + max_len,
                        message: format!("cstring `{}` exceeds max_len {}", field.name, max_len),
                    },
                    None,
                ));
            }
        }
        return Err(FieldFail::Error(
            ErrorInfo {
                path: path.to_string(),
                offset: end.saturating_sub(1).max(pos),
                message: format!("cstring `{}` has no NUL terminator inside its boundary", field.name),
            },
            None,
        ));
    }

    let bytes = &ctx.data[pos..end];
    if let Some(max_len) = field.max_len {
        if bytes.len() > max_len {
            return Err(FieldFail::Error(
                ErrorInfo {
                    path: path.to_string(),
                    offset: pos + max_len,
                    message: format!("cstring `{}` exceeds max_len {}", field.name, max_len),
                },
                None,
            ));
        }
    }
    let text = String::from_utf8_lossy(bytes).into_owned();
    Ok(Node {
        path: path.into(),
        name: field.name.clone(),
        kind: "cstring".into(),
        struct_name: None,
        start: pos,
        end: end + 1,
        complete: true,
        value: serde_json::json!({ "text": text }),
        children: Vec::new(),
        sig: String::new(),
    })
}

fn parse_struct_field(
    ctx: &mut Ctx,
    field: &FieldDef,
    path: &str,
    pos: usize,
    limit: usize,
) -> Result<Node, FieldFail> {
    let sn = field.struct_name.as_deref().ok_or_else(|| {
        FieldFail::Error(
            ErrorInfo {
                path: path.into(),
                offset: pos,
                message: format!("struct field `{}` has no struct_name", field.name),
            },
            None,
        )
    })?;
    let child_def: &StructDef = ctx.spec.structs.get(sn).ok_or_else(|| {
        FieldFail::Error(
            ErrorInfo {
                path: path.into(),
                offset: pos,
                message: format!("unknown struct `{}`", sn),
            },
            None,
        )
    })?;

    ctx.depth += 1;
    if ctx.depth > ctx.spec.max_depth {
        ctx.depth -= 1;
        return Err(FieldFail::Error(
            ErrorInfo {
                path: path.into(),
                offset: pos,
                message: format!(
                    "recursion depth limit {} exceeded at struct `{}`",
                    ctx.spec.max_depth, sn
                ),
            },
            None,
        ));
    }

    let (mut node, stop) = parse_struct(ctx, child_def, &field.name, path, pos, limit, false);
    ctx.depth -= 1;

    if let Some(err) = stop.error {
        return Err(FieldFail::Error(err, Some(node)));
    }
    if let Some(inc) = stop.incomplete {
        node.complete = false;
        return Err(FieldFail::Incomplete(inc));
    }
    // A declared-size child that runs past the parent boundary is an overrun.
    if child_def.length_field.is_some() && node.end > limit {
        return Err(FieldFail::Error(
            ErrorInfo {
                path: node.path.clone(),
                offset: limit,
                message: format!(
                    "struct `{}` declared size {} would escape the parent boundary at {}",
                    sn, node.end, limit
                ),
            },
            Some(node),
        ));
    }
    Ok(node)
}


fn parse_array(
    ctx: &mut Ctx,
    field: &FieldDef,
    path: &str,
    pos: usize,
    limit: usize,
) -> Result<Node, FieldFail> {
    let item_def = field.item.as_deref().ok_or_else(|| {
        FieldFail::Error(
            ErrorInfo {
                path: path.into(),
                offset: pos,
                message: format!("array `{}` has no item", field.name),
            },
            None,
        )
    })?;

    let count = match field.count.as_ref() {
        Some(crate::spec::CountRef::Fixed(n)) => *n as usize,
        Some(crate::spec::CountRef::Field(crate::spec::FieldRef { field: src })) => {
            lookup_int(ctx, path, src)? as usize
        }
        None => {
            return Err(FieldFail::Error(
                ErrorInfo {
                    path: path.into(),
                    offset: pos,
                    message: format!("array `{}` has no count", field.name),
                },
                None,
            ))
        }
    };

    // Arrays of integers: each element is visible in the enclosing scope so a
    // sibling condition can test the count/source fields only; element ints are
    // namespaced by their indexed path and are not recorded as siblings.
    let mut elements: Vec<Node> = Vec::new();
    let mut cur = pos;
    for i in 0..count {
        let item_path = format!("{}[{}]", path, i);
        match parse_field(ctx, item_def, &item_path, cur, limit) {
            Ok(node) => {
                cur = node.end;
                elements.push(node);
            }
            Err(FieldFail::Incomplete(inc)) => {
                return Err(FieldFail::Incomplete(IncompleteInfo {
                    need_at_least: inc.need_at_least,
                    path: if inc.path == item_path { item_path } else { inc.path },
                    offset: inc.offset,
                    message: inc.message,
                }))
            }
            Err(FieldFail::Error(err, partial)) => {
                if let Some(p) = partial {
                    elements.push(p);
                }
                return Err(FieldFail::Error(err, None));
            }
        }
    }

    let end = elements.last().map(|e| e.end).unwrap_or(pos);
    Ok(Node {
        path: path.into(),
        name: field.name.clone(),
        kind: "array".into(),
        struct_name: None,
        start: pos,
        end,
        complete: elements.len() == count && elements.iter().all(|e| e.complete),
        value: serde_json::json!({ "count": count }),
        children: elements,
        sig: String::new(),
    })
}

fn join_path(parent: &str, child: &str) -> String {
    format!("{}.{}", parent, child)
}

fn eval_condition(cond: &Condition, ctx: &Ctx) -> bool {
    let get = |name: &str| -> Option<u64> {
        ctx.scopes.iter().rev().find_map(|s| s.get(name).map(|v| v.value))
    };
    match cond {
        Condition::Eq { field, value } => get(field).map(|v| (v as i64) == *value).unwrap_or(false),
        Condition::Flag { field } => get(field).map(|v| v != 0).unwrap_or(false),
        Condition::FieldsEq { left, right } => match (get(left), get(right)) {
            (Some(a), Some(b)) => a == b,
            _ => false,
        },
    }
}

fn record_int(ctx: &mut Ctx, node: &Node) {
    if node.kind != "int" {
        return;
    }
    if let Some(v) = node.value.as_u64() {
        ctx.scopes.last_mut().unwrap().insert(
            node.name.clone(),
            IntVal { value: v },
        );
    }
}

fn int_raw(node: &Node) -> u64 {
    node.value.as_u64().unwrap_or(0)
}
// Signatures and byte mapping.
// ---------------------------------------------------------------------------

fn finalize_sigs(node: &mut Node) {
    for child in &mut node.children {
        finalize_sigs(child);
    }
    let mut h_input = Vec::new();
    h_input.extend_from_slice(node.path.as_bytes());
    h_input.push(0);
    h_input.extend_from_slice(node.kind.as_bytes());
    h_input.push(0);
    for child in &node.children {
        h_input.extend_from_slice(child.sig.as_bytes());
        h_input.push(1);
    }
    if !node.children.is_empty() {
        // containers hash their children; leaves hash their bytes implicitly
    } else {
        h_input.push(node.start as u8);
        h_input.push(node.end as u8);
    }
    let digest = crate::hash::sha256(&h_input);
    node.sig = crate::hex::encode(&digest[..12]);
}

fn build_byte_map(root: &Node, len: usize) -> Vec<Option<String>> {
    let mut map = vec![None; len];
    fill_map(root, &mut map);
    map
}

fn fill_map(node: &Node, map: &mut [Option<String>]) {
    for i in node.start..node.end.min(map.len()) {
        // Later/deeper traversal wins; we recurse children after claiming so
        // the deepest node owns each byte.
        map[i] = Some(node.path.clone());
    }
    for child in &node.children {
        fill_map(child, map);
    }
}

// ---------------------------------------------------------------------------
// Checksum verification.
//
// Cover intervals reference sibling fields within the same structure. The
// checksum's own bytes are always skipped (self-exclusion), so an interval
// written from the first field to the last field is valid even though the
// checksum sits between them.
// ---------------------------------------------------------------------------

fn verify_checksums(ctx: &Ctx, root: &mut Node) -> Option<ErrorInfo> {
    let mut first_error: Option<ErrorInfo> = None;
    verify_container(ctx, root, &mut first_error);
    first_error
}

fn verify_container(ctx: &Ctx, node: &mut Node, first_error: &mut Option<ErrorInfo>) {
    let struct_name = node.struct_name.clone();
    let sibling_ranges: Vec<(String, usize, usize)> = node
        .children
        .iter()
        .map(|c| (c.name.clone(), c.start, c.end))
        .collect();

    for child in node.children.iter_mut() {
        if child.kind == "checksum" {
            verify_checksum(ctx, child, struct_name.as_deref(), &sibling_ranges, first_error);
        } else if child.kind == "array" {
            for element in child.children.iter_mut() {
                verify_container(ctx, element, first_error);
            }
        } else if child.kind == "struct" || child.kind == "frame" {
            verify_container(ctx, child, first_error);
        }
    }
}

fn verify_checksum(
    ctx: &Ctx,
    node: &mut Node,
    owner_struct: Option<&str>,
    siblings: &[(String, usize, usize)],
    first_error: &mut Option<ErrorInfo>,
) {
    let Some(owner) = owner_struct else { return };
    let Some(field) = ctx
        .spec
        .struct_def(owner)
        .and_then(|sd| sd.fields.iter().find(|f| f.name == node.name && f.kind == "checksum"))
    else {
        return;
    };

    let algo = field.algo.unwrap_or(crate::spec::Algo::Xor8);
    let mut covered: Vec<u8> = Vec::new();
    for interval in &field.cover {
        let Some(start) = resolve_endpoint(&interval.from, siblings) else { continue };
        let Some(end) = resolve_endpoint(&interval.to, siblings) else { continue };
        if start <= end && end <= ctx.data.len() {
            for off in start..end {
                if off >= node.start && off < node.end {
                    continue; // self-exclusion
                }
                covered.push(ctx.data[off]);
            }
        }
    }

    let expected = algo.compute(&covered) as u64;
    let actual = node.value.get("actual").and_then(|v| v.as_u64()).unwrap_or(0);
    let ok = actual == expected;
    node.value = serde_json::json!({
        "actual": actual,
        "expected": expected,
        "ok": ok,
    });
    if !ok && first_error.is_none() {
        *first_error = Some(ErrorInfo {
            path: node.path.clone(),
            offset: node.start,
            message: format!(
                "{:?} checksum mismatch: stored {:#04x}, computed {:#04x}",
                algo, actual, expected
            ),
        });
    }
}

fn resolve_endpoint(
    endpoint: &crate::spec::Endpoint,
    siblings: &[(String, usize, usize)],
) -> Option<usize> {
    use crate::spec::{Endpoint, EndpointEdge};
    match endpoint {
        Endpoint::Field { field, edge } => siblings
            .iter()
            .find(|(name, _, _)| name == field)
            .map(|(_, start, end)| match edge {
                EndpointEdge::Start => *start,
                EndpointEdge::End => *end,
            }),
        Endpoint::Abs(off) => Some(*off as usize),
    }
}
