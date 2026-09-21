use super::checksum::{compute_checksum, CoverSpan};
use super::{Diagnostic, Node, ParseResult, Span, Status};
use crate::json::Json;
use crate::spec::{
    ChecksumAlgo, CoverSpec, Endian, FieldDef, FieldKind, LenExpr, Protocol, StructDef, WhenCond,
};

/// Parser stop: either a hard protocol violation or an "need more bytes".
struct Halt {
    status: Status,
    message: String,
    /// Field path at the stop point (already qualified).
    path: String,
    byte: Option<usize>,
    need: usize,
}

type Rx<T> = Result<T, Halt>;

fn err<M: Into<String>>(message: M, path: &str, byte: Option<usize>) -> Halt {
    Halt {
        status: Status::Error,
        message: message.into(),
        path: path.to_string(),
        byte,
        need: 0,
    }
}

#[derive(Clone)]
struct Scope {
    /// Logical sibling slots in declaration order (when-inlined).
    slots: Vec<Slot>,
    /// Byte start of this scope's struct node.
    start: usize,
}

#[derive(Clone)]
struct Slot {
    name: String,
    path: String,
    value: Json,
    span: Option<Span>,
    cover: Option<CoverSpec>,
}

struct P<'a> {
    proto: &'a Protocol,
    data: &'a [u8],
    scopes: Vec<Scope>,
    ref_depth: usize,
}

impl<'a> P<'a> {
    fn cur(&self) -> usize {
        self.scopes.last().map(|s| s.start).unwrap_or(0)
    }

    /// Find a sibling value: exact suffix match nearest first, supporting
    /// dotted paths inside already-parsed composite values.
    fn lookup(&self, name: &str) -> Option<(Json, Option<Span>)> {
        for scope in self.scopes.iter().rev() {
            if let Some(found) = lookup_in_scope(scope, name) {
                return Some(found);
            }
        }
        None
    }

    fn eval_len(&self, le: &LenExpr, path: &str) -> Rx<usize> {
        match le {
            LenExpr::Const(n) => Ok(*n),
            LenExpr::Field { path: fp, scale, bias } => {
                let (v, _) = self.lookup(fp).ok_or_else(|| {
                    err(
                        format!("length/count field '{}' not found", fp),
                        path,
                        None,
                    )
                })?;
                let n = v.as_i64().ok_or_else(|| {
                    err(format!("field '{}' is not an integer", fp), path, None)
                })?;
                let computed = n
                    .checked_mul(*scale)
                    .and_then(|x| x.checked_add(*bias))
                    .ok_or_else(|| err("length expression overflow", path, None))?;
                if computed < 0 {
                    return Err(err(
                        format!("length expression evaluated to {} (< 0)", computed),
                        path,
                        None,
                    ));
                }
                Ok(computed as usize)
            }
        }
    }
}

fn lookup_in_scope(scope: &Scope, name: &str) -> Option<(Json, Option<Span>)> {
    // Direct match of a full logical path first.
    for s in &scope.slots {
        if s.path == name || s.name == name {
            return Some((s.value.clone(), s.span));
        }
    }
    // Dotted: first segment resolves to a composite slot, remainder descends.
    if let Some(dot) = name.find('.') {
        let (head, tail) = name.split_at(dot);
        let tail = &tail[1..];
        for s in &scope.slots {
            if s.name == head {
                if let Some(v) = descend(&s.value, tail) {
                    return Some((v, s.span));
                }
            }
        }
    }
    None
}

fn descend(v: &Json, path: &str) -> Option<Json> {
    if path.is_empty() {
        return Some(v.clone());
    }
    let (head, rest) = match path.find('.') {
        Some(i) => (&path[..i], Some(&path[i + 1..])),
        None => (path, None),
    };
    if let Json::Obj(m) = v {
        if let Some(child) = m.get(head) {
            return match rest {
                Some(r) => descend(child, r),
                None => Some(child.clone()),
            };
        }
    }
    None
}

fn read_uint(data: &[u8], off: usize, width: usize, endian: Endian) -> u64 {
    let mut value = 0u64;
    for i in 0..width {
        let idx = match endian {
            Endian::Big => off + i,
            Endian::Little => off + width - 1 - i,
        };
        value = (value << 8) | data[idx] as u64;
    }
    value
}

fn check_when(cond: &WhenCond, p: &P, path: &str) -> Rx<bool> {
    let (v, _) = p
        .lookup(&cond.path)
        .ok_or_else(|| err(format!("condition field '{}' not found", cond.path), path, None))?;
    let n = v
        .as_i64()
        .ok_or_else(|| err(format!("condition field '{}' is not an integer", cond.path), path, None))?;
    Ok(match cond.mask {
        Some(mask) => (n as u64 & mask) as i64 == cond.equals,
        None => n == cond.equals,
    })
}

fn join<S: AsRef<str>>(base: &str, name: S) -> String {
    let name = name.as_ref();
    if base.is_empty() {
        name.to_string()
    } else {
        format!("{}.{}", base, name)
    }
}

fn worse(a: Status, b: Status) -> Status {
    if a.rank() >= b.rank() { a } else { b }
}

/// Outcome of parsing one struct.
struct StructOut {
    node: Node,
    value: Json,
    end: usize,
}

/// Parse a struct within the hard bound `[start, end)`.
fn parse_struct(
    p: &mut P,
    sdef: &StructDef,
    base: &str,
    start: usize,
    end: usize,
    hard_end: usize,
    ref_depth: usize,
) -> Rx<StructOut> {
    if start > end {
        return Err(err("struct start beyond its boundary", base, Some(start)));
    }
    p.scopes.push(Scope {
        slots: Vec::new(),
        start,
    });
    let mut children: Vec<Node> = Vec::new();
    let mut cursor = start;
    let mut status = Status::Ok;
    let mut map = std::collections::BTreeMap::new();

    for field in &sdef.fields {
        let fpath = join(base, &field.name);
        let zero = field_has_zero_size(field, p, &fpath)?;
        if cursor >= end && !zero {
            // Struct expects another field but its declared bound is spent.
            if cursor < hard_end {
                // Declared-length sub-struct ended early: hard violation.
                return Err(err(
                    format!(
                        "struct '{}' ended before its declared length; missing field '{}'",
                        sdef.name, field.name
                    ),
                    &fpath,
                    Some(cursor),
                ));
            }
            if cursor < p.data.len() {
                // Bytes exist but the parent hard bound forbids growth.
                return Err(err(
                    format!(
                        "field '{}' cannot fit inside the parent boundary at {}",
                        field.name, cursor
                    ),
                    &fpath,
                    Some(cursor),
                ));
            }
            return Err(Halt {
                status: Status::Incomplete,
                message: format!(
                    "struct '{}' needs field '{}' at its boundary",
                    sdef.name, field.name
                ),
                path: fpath,
                byte: Some(cursor),
                need: 1,
            });
        }
        let fo = parse_field(p, field, base, &mut cursor, end, hard_end, ref_depth)?;
        for n in fo.nodes {
            status = worse(status, n.status);
            children.push(n);
        }
        if let Some(slot) = fo.slot {
            map.insert(slot.name.clone(), slot.value.clone());
            p.scopes.last_mut().unwrap().slots.push(slot);
        }
    }

    let span = if cursor > start || !children.is_empty() {
        Some(Span {
            start,
            len: cursor - start,
        })
    } else {
        None
    };

    let node = Node {
        kind: "struct".to_string(),
        name: sdef.name.clone(),
        path: base.to_string(),
        span,
        value: Json::from_map(map.clone()),
        children,
        status,
        cover: Vec::new(),
        cover_spec: None,
        algo_label: None,
    };

    p.scopes.pop();
    Ok(StructOut {
        node,
        value: Json::from_map(map),
        end: cursor,
    })
}

struct FieldOut {
    nodes: Vec<Node>,
    /// Value registered in the parent's logical field map / scope.
    slot: Option<Slot>,
}

#[allow(clippy::too_many_arguments)]
fn parse_field(
    p: &mut P,
    field: &FieldDef,
    base: &str,
    cursor: &mut usize,
    end: usize,
    hard_end: usize,
    ref_depth: usize,
) -> Rx<FieldOut> {
    let path = join(base, &field.name);
    match &field.kind {
        FieldKind::UInt {
            width,
            endian,
            constant,
        } => parse_uint(p, &path, cursor, end, hard_end, *width, *endian, *constant),
        FieldKind::Bytes { length } => parse_bytes(p, &path, cursor, end, hard_end, length),
        FieldKind::Struct {
            struct_name,
            length,
        } => parse_struct_field(
            p,
            field,
            &path,
            cursor,
            end,
            hard_end,
            struct_name,
            length.as_ref(),
            ref_depth,
        ),
        FieldKind::Array { count, item } => {
            parse_array(p, field, &path, cursor, end, hard_end, count, item, ref_depth)
        }
        FieldKind::When { cond, fields } => {
            parse_when(p, field, &path, cursor, end, hard_end, cond, fields, ref_depth)
        }
        FieldKind::Ref { target } => {
            parse_ref(p, &path, cursor, end, hard_end, target, ref_depth)
        }
        FieldKind::Checksum {
            width,
            endian,
            algo,
            cover,
        } => parse_checksum_field(p, &path, cursor, end, hard_end, *width, *endian, *algo, cover.clone()),
    }
}

/// Minimum fixed size of a field without consuming; used to decide whether a
/// boundary means "incomplete" or "violation". Best-effort.
fn field_has_zero_size(field: &FieldDef, p: &P, path: &str) -> Rx<bool> {
    Ok(match &field.kind {
        FieldKind::When { cond, fields } => {
            if !check_when(cond, p, path)? {
                true
            } else {
                for f in fields {
                    if !field_has_zero_size(f, p, &join(path, f.name.as_str()))? {
                        return Ok(false);
                    }
                }
                true
            }
        }
        FieldKind::UInt { .. } | FieldKind::Checksum { .. } => false,
        FieldKind::Bytes { length } => p.eval_len(length, path)? == 0,
        _ => false,
    })
}

fn need_incomplete(path: &str, need: usize, byte: usize, what: &str) -> Halt {
    Halt {
        status: Status::Incomplete,
        message: format!("{}: input incomplete, need at least {} more byte(s)", what, need),
        path: path.to_string(),
        byte: Some(byte),
        need,
    }
}

fn parse_uint(
    p: &P,
    path: &str,
    cursor: &mut usize,
    end: usize,
    hard_end: usize,
    width: usize,
    endian: Endian,
    constant: Option<u64>,
) -> Rx<FieldOut> {
    let _ = end;
    let start = *cursor;
    if start + width > hard_end {
        if start + width <= p.data.len() {
            return Err(err(
                format!("integer field ({} byte(s)) crosses parent boundary {}", width, hard_end),
                path,
                Some(start),
            ));
        }
        return Err(need_incomplete(
            path,
            start + width - p.data.len(),
            p.data.len(),
            "integer",
        ));
    }
    if start + width > p.data.len() {
        return Err(need_incomplete(
            path,
            start + width - p.data.len(),
            p.data.len(),
            "integer",
        ));
    }
    let value = read_uint(p.data, start, width, endian);
    if let Some(expected) = constant {
        if value != expected {
            return Err(err(
                format!(
                    "constant field mismatch: expected 0x{:x}, got 0x{:x}",
                    expected, value
                ),
                path,
                Some(start),
            ));
        }
    }
    let span = Span { start, len: width };
    *cursor += width;
    Ok(FieldOut {
        nodes: vec![Node {
            kind: "uint".to_string(),
            name: path.rsplit('.').next().unwrap_or(path).to_string(),
            path: path.to_string(),
            span: Some(span),
            value: Json::uint(value),
            children: Vec::new(),
            status: Status::Ok,
            cover: Vec::new(),
            cover_spec: None,
            algo_label: None,
        }],
        slot: Some(Slot {
            name: path.rsplit('.').next().unwrap_or(path).to_string(),
            path: path.to_string(),
            value: Json::uint(value),
            span: Some(span),
            cover: None,
        }),
    })
}

fn parse_bytes(
    p: &P,
    path: &str,
    cursor: &mut usize,
    end: usize,
    hard_end: usize,
    length: &LenExpr,
) -> Rx<FieldOut> {
    let _ = end;
    let start = *cursor;
    let len = p.eval_len(length, path)?;
    let target = start.checked_add(len).ok_or_else(|| err("length overflow", path, Some(start)))?;
    if target > hard_end {
        // Violation only if the stream actually contains the bytes that would
        // cross the boundary; otherwise it is merely incomplete.
        if target <= p.data.len() {
            return Err(err(
                format!(
                    "length field would read {} byte(s) past the parent boundary ({})",
                    len, hard_end
                ),
                path,
                Some(start),
            ));
        }
        return Err(need_incomplete(
            path,
            target - p.data.len(),
            p.data.len(),
            "byte field",
        ));
    }
    if target > p.data.len() {
        return Err(need_incomplete(
            path,
            target - p.data.len(),
            p.data.len(),
            "byte field",
        ));
    }
    let raw = &p.data[start..start + len];
    let span = Span { start, len };
    *cursor += len;
    let hex = crate::hash::hex_encode(raw);
    let mut arr = Vec::with_capacity(len);
    for b in raw {
        arr.push(Json::uint(*b as u64));
    }
    Ok(FieldOut {
        nodes: vec![Node {
            kind: "bytes".to_string(),
            name: path.rsplit('.').next().unwrap_or(path).to_string(),
            path: path.to_string(),
            span: Some(span),
            value: Json::str(hex),
            children: Vec::new(),
            status: Status::Ok,
            cover: Vec::new(),
            cover_spec: None,
            algo_label: None,
        }],
        slot: Some(Slot {
            name: path.rsplit('.').next().unwrap_or(path).to_string(),
            path: path.to_string(),
            value: Json::arr(arr),
            span: Some(span),
            cover: None,
        }),
    })
}

#[allow(clippy::too_many_arguments)]
fn parse_checksum_field(
    p: &P,
    path: &str,
    cursor: &mut usize,
    end: usize,
    hard_end: usize,
    width: usize,
    endian: Endian,
    algo: ChecksumAlgo,
    cover: CoverSpec,
) -> Rx<FieldOut> {
    let _ = end;
    let start = *cursor;
    if start + width > hard_end {
        if start + width <= p.data.len() {
            return Err(err("checksum crosses parent boundary", path, Some(start)));
        }
        return Err(need_incomplete(
            path,
            start + width - p.data.len(),
            start,
            "checksum",
        ));
    }
    if start + width > p.data.len() {
        let need = start + width - p.data.len();
        return Err(need_incomplete(path, need.max(1), start, "checksum"));
    }
    let value = read_uint(p.data, start, width, endian);
    let span = Span { start, len: width };
    *cursor += width;
    let short = path.rsplit('.').next().unwrap_or(path).to_string();
    let mut val = Json::obj();
    val.put("algo", Json::str(algo.label()));
    val.put("stored", Json::uint(value));
    Ok(FieldOut {
        nodes: vec![Node {
            kind: "checksum".to_string(),
            name: short.clone(),
            path: path.to_string(),
            span: Some(span),
            value: val,
            children: Vec::new(),
            status: Status::Ok,
            cover: Vec::new(),
            cover_spec: Some(cover.clone()),
            algo_label: Some(algo.label().to_string()),
        }],
        slot: Some(Slot {
            name: short,
            path: path.to_string(),
            value: Json::uint(value),
            span: Some(span),
            cover: Some(cover),
        }),
    })
}

#[allow(clippy::too_many_arguments)]
fn parse_struct_field(
    p: &mut P,
    field: &FieldDef,
    path: &str,
    cursor: &mut usize,
    end: usize,
    hard_end: usize,
    struct_name: &str,
    length: Option<&LenExpr>,
    ref_depth: usize,
) -> Rx<FieldOut> {
    let start = *cursor;
    let sdef = p
        .proto
        .structs
        .get(struct_name)
        .ok_or_else(|| err(format!("unknown struct '{}'", struct_name), path, Some(start)))?;

    // Declared length forms a hard sub-boundary; otherwise inherit parent end.
    let sub_end = match length {
        Some(le) => {
            let declared = p.eval_len(le, path)?;
            let candidate = start.checked_add(declared).ok_or_else(|| {
                err("declared struct length overflow", path, Some(start))
            })?;
            if candidate > hard_end {
                return Err(err(
                    format!(
                        "declared struct length {} reads past parent boundary ({})",
                        declared, hard_end
                    ),
                    path,
                    Some(start),
                ));
            }
            candidate
        }
        None => end,
    };
    let sub_hard = sub_end.min(hard_end);

    let out = parse_struct(p, sdef, path, start, sub_end, sub_hard, ref_depth)?;
    let mut node = out.node;

    let mut status = node.status;
    if let Some(le) = length {
        let declared = p.eval_len(le, path)?;
        if out.end < start + declared {
            // Stream cut inside a declared-length struct -> incomplete.
            if start + declared <= hard_end && start + declared > p.data.len() {
                return Err(need_incomplete(
                    path,
                    start + declared - p.data.len(),
                    p.data.len(),
                    "declared struct",
                ));
            }
            status = worse(status, Status::Warning);
            let _ = le;
        }
    }
    node.status = status;
    node.name = field.name.clone();
    let node_span = node.span;
    *cursor = out.end;

    Ok(FieldOut {
        nodes: vec![node],
        slot: Some(Slot {
            name: field.name.clone(),
            path: path.to_string(),
            value: out.value,
            span: node_span,
            cover: None,
        }),
    })
}

#[allow(clippy::too_many_arguments)]
fn parse_array(
    p: &mut P,
    field: &FieldDef,
    path: &str,
    cursor: &mut usize,
    end: usize,
    hard_end: usize,
    count: &LenExpr,
    item: &FieldDef,
    ref_depth: usize,
) -> Rx<FieldOut> {
    let _ = end;
    let start = *cursor;
    let n = p.eval_len(count, path)?;

    // Malicious count sanity: items are at least one byte each; if even the
    // first byte cannot fit inside the parent bound it is a hard violation.
    if n > 0 && start >= hard_end {
        return Err(err(
            format!(
                "array count {} exceeds the parent boundary ({} byte left)",
                n,
                hard_end.saturating_sub(start)
            ),
            path,
            Some(start),
        ));
    }

    let mut elements: Vec<Node> = Vec::new();
    let mut values: Vec<Json> = Vec::new();
    let mut status = Status::Ok;

    for idx in 0..n {
        let ipath = format!("{}[{}]", path, idx);
        let before = *cursor;
        let mut item_def = item.clone();
        item_def.name = format!("{}", idx);
        let fo = parse_field(p, &item_def, path, cursor, end, hard_end, ref_depth)?;
        if *cursor == before {
            return Err(err(
                "zero-width array element makes the array unbounded",
                &ipath,
                Some(*cursor),
            ));
        }
        for mut node in fo.nodes {
            node.name = format!("[{}]", idx);
            node.path = ipath.clone();
            status = worse(status, node.status);
            values.push(node.value.clone());
            elements.push(node);
        }
        if let Some(slot) = fo.slot {
            p.scopes.last_mut().unwrap().slots.push(Slot {
                name: format!("{}", idx),
                path: ipath,
                value: slot.value,
                span: slot.span,
                cover: slot.cover,
            });
        }
    }

    let last_end = elements.last().and_then(|e| e.span.map(|s| s.end()));
    let span = match last_end {
        Some(e) if e >= start => Some(Span {
            start,
            len: e - start,
        }),
        _ => None,
    };

    Ok(FieldOut {
        nodes: vec![Node {
            kind: "array".to_string(),
            name: field.name.clone(),
            path: path.to_string(),
            span,
            value: Json::arr(values),
            children: elements,
            status,
            cover: Vec::new(),
            cover_spec: None,
            algo_label: None,
        }],
        slot: None,
    })
}

#[allow(clippy::too_many_arguments)]
fn parse_when(
    p: &mut P,
    field: &FieldDef,
    path: &str,
    cursor: &mut usize,
    end: usize,
    hard_end: usize,
    cond: &WhenCond,
    fields: &[FieldDef],
    ref_depth: usize,
) -> Rx<FieldOut> {
    if !check_when(cond, p, path)? {
        // Branch absent: contributes no node, no bytes, but record a marker.
        return Ok(FieldOut {
            nodes: vec![Node {
                kind: "when-skip".to_string(),
                name: field.name.clone(),
                path: path.to_string(),
                span: None,
                value: Json::bool_(false),
                children: Vec::new(),
                status: Status::Ok,
                cover: Vec::new(),
            cover_spec: None,
            algo_label: None,
            }],
            slot: None,
        });
    }

    let start = *cursor;
    let mut nodes = Vec::new();
    let mut status = Status::Ok;
    for inner in fields {
        let fo = parse_field(p, inner, path, cursor, end, hard_end, ref_depth)?;
        for node in fo.nodes {
            status = worse(status, node.status);
            nodes.push(node);
        }
        if let Some(slot) = fo.slot {
            p.scopes.last_mut().unwrap().slots.push(slot);
        }
    }
    let last_end = nodes
        .iter()
        .filter_map(|n| n.span.map(|s| s.end()))
        .max();
    let span = last_end.map(|e| Span {
        start,
        len: e.saturating_sub(start),
    });

    Ok(FieldOut {
        nodes: vec![Node {
            kind: "when".to_string(),
            name: field.name.clone(),
            path: path.to_string(),
            span,
            value: Json::bool_(true),
            children: nodes,
            status,
            cover: Vec::new(),
            cover_spec: None,
            algo_label: None,
        }],
        slot: None,
    })
}

fn parse_ref(
    p: &mut P,
    path: &str,
    cursor: &mut usize,
    end: usize,
    hard_end: usize,
    target: &str,
    ref_depth: usize,
) -> Rx<FieldOut> {
    if ref_depth >= p.proto.max_depth {
        return Err(err(
            format!(
                "recursion depth limit {} reached while following '{}'",
                p.proto.max_depth, target
            ),
            path,
            Some(*cursor),
        ));
    }
    let sdef = p
        .proto
        .structs
        .get(target)
        .ok_or_else(|| err(format!("unknown ref target '{}'", target), path, Some(*cursor)))?;
    let _ = hard_end;
    let out = parse_struct(p, sdef, path, *cursor, end, hard_end, ref_depth + 1)?;
    let node_span = out.node.span;
    *cursor = out.end;
    Ok(FieldOut {
        nodes: vec![out.node],
        slot: Some(Slot {
            name: path.rsplit('.').next().unwrap_or(path).to_string(),
            path: path.to_string(),
            value: out.value,
            span: node_span,
            cover: None,
        }),
    })
}

/// Parse a whole frame against the protocol's root struct.
pub fn parse_frame(proto: &Protocol, data: &[u8]) -> ParseResult {
    let mut p = P {
        proto,
        data,
        scopes: Vec::new(),
        ref_depth: 0,
    };
    let root_def = proto
        .structs
        .get(&proto.root)
        .expect("root validated at compile time");

    let total = data.len();
    // The root has no enclosing declared boundary, so its hard bound is
    /// unbounded; `total` only limits what can currently be consumed.
    match parse_struct(&mut p, root_def, "", 0, total, usize::MAX, 0) {
        Ok(out) => {
            let mut root = out.node;
            let mut diagnostics = Vec::new();
            let mut status = root.status;

            // Trailing bytes are tolerated but reported as a warning so that a
            // frame is never silently shorter than the supplied stream.
            if out.end < total {
                status = worse(status, Status::Warning);
                diagnostics.push(Diagnostic {
                    level: Status::Warning,
                    message: format!("{} trailing byte(s) after root", total - out.end),
                    path: String::new(),
                    byte: Some(out.end),
                });
            }

            verify_checksums(&mut root, data, &mut diagnostics, &mut status);
            root.status = status;

            ParseResult {
                status,
                root: Some(root),
                diagnostics,
                need: 0,
                consumed: out.end,
            }
        }
        Err(h) => {
            // Even a halted parse leaves no root node; callers rely on the
            // deepest path/offset plus the lower bound of missing bytes.
            let level = h.status;
            ParseResult {
                status: level,
                root: None,
                diagnostics: vec![Diagnostic {
                    level,
                    message: h.message,
                    path: h.path,
                    byte: h.byte,
                }],
                need: h.need,
                consumed: h.byte.unwrap_or(0),
            }
        }
    }
}


// ---------------- Checksum post-pass ----------------

struct CheckInfo {
    path: String,
    span: Span,
    stored: u64,
    computed: u64,
    algo: ChecksumAlgo,
    cover_spans: Vec<Span>,
}

fn verify_checksums(
    root: &mut Node,
    data: &[u8],
    diagnostics: &mut Vec<Diagnostic>,
    status: &mut Status,
) {
    let mut infos: Vec<CheckInfo> = Vec::new();
    collect_checksums(root, data, &mut infos);

    for info in &infos {
        let computed = compute_checksum(data, &info.cover_spans, info.algo);
        if computed != info.stored {
            *status = worse(*status, Status::Error);
            diagnostics.push(Diagnostic {
                level: Status::Error,
                message: format!(
                    "{} checksum mismatch: stored 0x{:0w$x}, computed 0x{:0w$x}",
                    info.algo.label(),
                    info.stored,
                    computed,
                    w = info.algo.width() * 2
                ),
                path: info.path.clone(),
                byte: Some(info.span.start),
            });
        }
    }

    annotate_checksums(root, &infos);
}

/// Recursively gather checksum nodes and resolve their cover intervals from
/// the direct children of the enclosing struct.
fn collect_checksums(node: &Node, data: &[u8], out: &mut Vec<CheckInfo>) {
    if node.kind == "struct" {
        resolve_struct_checksums(node, data, out);
    }
    for child in &node.children {
        collect_checksums(child, data, out);
    }
}

fn resolve_struct_checksums(struct_node: &Node, data: &[u8], out: &mut Vec<CheckInfo>) {
    // Direct logical children (non when-skip wrappers at depth one).
    let direct: Vec<&Node> = struct_node.children.iter().collect();
    for child in &direct {
        if child.kind != "checksum" {
            continue;
        }
        let self_span = match child.span {
            Some(s) => s,
            None => continue,
        };
        let stored = child
            .value
            .get("stored")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let algo = child
            .algo_label
            .as_deref()
            .and_then(|l| ChecksumAlgo::parse(l).ok())
            .unwrap_or(ChecksumAlgo::Sum8);

        // Preceding direct children with a concrete span.
        let preceding: Vec<&Node> = struct_node
            .children
            .iter()
            .filter(|n| n.span.map(|s| s.start < self_span.start).unwrap_or(false))
            .collect();

        let mut cover_spans: Vec<Span> = Vec::new();
        let spec = match &child.cover_spec {
            Some(c) => c,
            None => continue,
        };

        if spec.ranges.is_empty() {
            for n in &preceding {
                if let Some(sp) = n.span {
                    cover_spans.push(sp);
                }
            }
        } else {
            for range in &spec.ranges {
                let mut include = false;
                for n in &preceding {
                    if n.name == range.start {
                        include = true;
                    }
                    if include {
                        if let Some(sp) = n.span {
                            cover_spans.push(sp);
                        }
                    }
                    if n.name == range.end {
                        include = false;
                    }
                }
            }
        }

        // Defensive: never include the checksum's own bytes.
        cover_spans.retain(|sp| sp.end() <= self_span.start || sp.start >= self_span.end());

        let computed = compute_checksum(data, &cover_spans, algo);
        out.push(CheckInfo {
            path: child.path.clone(),
            span: self_span,
            stored,
            computed,
            algo,
            cover_spans,
        });
    }

    // Recurse into composite direct children (arrays, when, nested structs).
    for child in &direct {
        if child.kind == "checksum" {
            continue;
        }
        resolve_nested(child, data, out);
    }
}

fn resolve_nested(node: &Node, data: &[u8], out: &mut Vec<CheckInfo>) {
    if node.kind == "struct" {
        resolve_struct_checksums(node, data, out);
        return;
    }
    for child in &node.children {
        resolve_nested(child, data, out);
    }
}

fn annotate_checksums(node: &mut Node, infos: &[CheckInfo]) {
    if node.kind == "checksum" {
        if let Some(info) = infos.iter().find(|i| i.path == node.path) {
            node.cover = info.cover_spans.clone();
            node.value.put("computed", Json::uint(info.computed));
            node.value
                .put("valid", Json::bool_(info.computed == info.stored));
        }
    }
    for child in &mut node.children {
        annotate_checksums(child, infos);
    }
}
