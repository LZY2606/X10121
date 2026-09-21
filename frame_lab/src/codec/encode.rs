// Deterministic encoder. Given a protocol and a JSON value tree it emits bytes
// for the root struct. Length/count fields are auto-derived from the fields
// they size when omitted; checksums are filled in a finalisation pass.

use super::checksum::compute_checksum;
use super::Span;
use crate::json::Json;
use crate::spec::{ChecksumAlgo, Endian, FieldDef, FieldKind, LenExpr, Protocol};
use std::collections::BTreeMap;

#[derive(Debug, Clone)]
struct PendingChecksum {
    start: usize,
    width: usize,
    endian: Endian,
    algo: ChecksumAlgo,
    cover_names: Vec<(String, String)>,
}

struct E<'a> {
    proto: &'a Protocol,
    out: Vec<u8>,
    pending: Vec<PendingChecksum>,
    /// Per-struct record of named child spans, keyed by struct path.
    spans: BTreeMap<String, Vec<(String, Span)>>,
}

pub fn encode(proto: &Protocol, value: &Json) -> Result<Vec<u8>, String> {
    let mut e = E {
        proto,
        out: Vec::new(),
        pending: Vec::new(),
        spans: BTreeMap::new(),
    };
    let root = proto
        .structs
        .get(&proto.root)
        .ok_or_else(|| format!("root struct '{}' missing", proto.root))?;
    encode_struct(&mut e, root, "", value)?;
    finalize(&mut e)?;
    Ok(e.out)
}

fn write_int(out: &mut Vec<u8>, value: u64, width: usize, endian: Endian) {
    let mut raw = vec![0u8; width];
    let mut v = value;
    for i in 0..width {
        raw[width - 1 - i] = (v & 0xff) as u8;
        v >>= 8;
    }
    match endian {
        Endian::Big => out.extend_from_slice(&raw),
        Endian::Little => {
            raw.reverse();
            out.extend_from_slice(&raw);
        }
    }
}

fn json_bytes(v: &Json) -> Result<Vec<u8>, String> {
    match v {
        Json::Str(s) => crate::hash::hex_decode(s),
        Json::Arr(a) => {
            let mut out = Vec::new();
            for item in a {
                out.push(item.as_u64().ok_or("byte array entry must be 0..=255")? as u8);
            }
            Ok(out)
        }
        _ => Err("byte field must be a hex string or byte array".to_string()),
    }
}

fn lookup_value<'a>(value: &'a Json, name: &str) -> Option<&'a Json> {
    match value {
        Json::Obj(m) => m.get(name),
        _ => None,
    }
}

fn eval_len(le: &LenExpr, value: &Json) -> Result<usize, String> {
    match le {
        LenExpr::Const(n) => Ok(*n),
        LenExpr::Field { path, scale, bias } => {
            let n = lookup_value(value, path)
                .and_then(|v| v.as_i64())
                .ok_or_else(|| format!("length field '{}' missing while encoding", path))?;
            let computed = n
                .checked_mul(*scale)
                .and_then(|x| x.checked_add(*bias))
                .ok_or_else(|| "length expression overflow".to_string())?;
            if computed < 0 {
                return Err("negative length while encoding".to_string());
            }
            Ok(computed as usize)
        }
    }
}

fn encode_struct(e: &mut E, sdef: &crate::spec::StructDef, path: &str, value: &Json) -> Result<(), String> {
    let start = e.out.len();
    let mut child_spans: Vec<(String, Span)> = Vec::new();

    for field in &sdef.fields {
        let fstart = e.out.len();
        encode_field(e, field, path, value)?;
        let fend = e.out.len();
        if fend > fstart {
            child_spans.push((
                field.name.clone(),
                Span {
                    start: fstart,
                    len: fend - fstart,
                },
            ));
        }
    }

    let span = Span {
        start,
        len: e.out.len() - start,
    };
    e.spans.insert(path.to_string(), child_spans);
    let _ = span;
    Ok(())
}

fn encode_field(e: &mut E, field: &FieldDef, parent_path: &str, value: &Json) -> Result<(), String> {
    let path = if parent_path.is_empty() {
        field.name.clone()
    } else {
        format!("{}.{}", parent_path, field.name)
    };
    let fv = lookup_value(value, &field.name);

    match &field.kind {
        FieldKind::UInt {
            width,
            endian,
            constant,
        } => {
            let n = match (fv, constant) {
                (Some(Json::Num(..)), _) => fv.unwrap().as_u64().ok_or("uint value out of range")?,
                (_, Some(c)) => *c,
                _ => return Err(format!("missing value for uint '{}'", field.name)),
            };
            if n >= 1u64.checked_shl((width * 8) as u32).unwrap_or(0) && *width < 8 {
                return Err(format!("value for '{}' does not fit in {} bytes", field.name, width));
            }
            write_int(&mut e.out, n, *width, *endian);
        }
        FieldKind::Bytes { length } => {
            let bytes = match fv {
                Some(v) => json_bytes(v)?,
                None => Vec::new(),
            };
            let want = eval_len(length, value)?;
            if bytes.len() != want {
                return Err(format!(
                    "bytes '{}' has {} bytes but length expression says {}",
                    field.name,
                    bytes.len(),
                    want
                ));
            }
            e.out.extend_from_slice(&bytes);
        }
        FieldKind::Struct {
            struct_name,
            length,
        } => {
            let sdef = e
                .proto
                .structs
                .get(struct_name)
                .ok_or_else(|| format!("unknown struct '{}'", struct_name))?;
            let fstart = e.out.len();
            let sub_value = fv.cloned().unwrap_or_else(Json::obj);
            encode_struct(e, sdef, &path, &sub_value)?;
            if let Some(le) = length {
                let want = eval_len(le, value)?;
                let got = e.out.len() - fstart;
                if got != want {
                    return Err(format!(
                        "struct '{}' encoded {} bytes, declared length {}",
                        field.name, got, want
                    ));
                }
            }
        }
        FieldKind::Array { count, item } => {
            let arr = fv.and_then(|v| v.as_array()).cloned().unwrap_or_default();
            let want = eval_len(count, value)?;
            if arr.len() != want {
                return Err(format!(
                    "array '{}' has {} items, count says {}",
                    field.name,
                    arr.len(),
                    want
                ));
            }
            for (idx, item_value) in arr.iter().enumerate() {
                let ipath = format!("{}[{}]", path, idx);
                let mut item_def = (**item).clone();
                item_def.name = format!("{}", idx);
                encode_array_item(e, &item_def, &ipath, item_value)?;
            }
        }
        FieldKind::When { cond, fields } => {
            let take = match lookup_value(value, &cond.path).and_then(|v| v.as_i64()) {
                Some(n) => match cond.mask {
                    Some(mask) => (n as u64 & mask) as i64 == cond.equals,
                    None => n == cond.equals,
                },
                None => false,
            };
            if take {
                for inner in fields {
                    encode_field(e, inner, &path, value)?;
                }
            }
        }
        FieldKind::Ref { target } => {
            let sdef = e
                .proto
                .structs
                .get(target)
                .ok_or_else(|| format!("unknown ref target '{}'", target))?;
            let sub = fv.cloned().unwrap_or_else(Json::obj);
            encode_struct(e, sdef, &path, &sub)?;
        }
        FieldKind::Checksum {
            width,
            endian,
            algo,
            cover,
        } => {
            let start = e.out.len();
            write_int(&mut e.out, 0, *width, *endian);
            e.pending.push(PendingChecksum {
                start,
                width: *width,
                endian: *endian,
                algo: *algo,
                cover_names: cover
                    .ranges
                    .iter()
                    .map(|r| (r.start.clone(), r.end.clone()))
                    .collect(),
            });
        }
    }
    Ok(())
}

fn encode_array_item(
    e: &mut E,
    item: &FieldDef,
    path: &str,
    value: &Json,
) -> Result<(), String> {
    match &item.kind {
        FieldKind::UInt {
            width,
            endian,
            constant,
        } => {
            let n = match (Some(value), constant) {
                (Some(Json::Num(..)), _) => value.as_u64().ok_or("uint item out of range")?,
                (_, Some(c)) => *c,
                _ => return Err(format!("missing uint item at {}", path)),
            };
            write_int(&mut e.out, n, *width, *endian);
            Ok(())
        }
        FieldKind::Bytes { .. } => {
            let bytes = json_bytes(value)?;
            e.out.extend_from_slice(&bytes);
            Ok(())
        }
        FieldKind::Struct { struct_name, .. } => {
            let sdef = e
                .proto
                .structs
                .get(struct_name)
                .ok_or_else(|| format!("unknown struct '{}'", struct_name))?;
            encode_struct(e, sdef, path, value)
        }
        FieldKind::Ref { target } => {
            let sdef = e
                .proto
                .structs
                .get(target)
                .ok_or_else(|| format!("unknown ref '{}'", target))?;
            encode_struct(e, sdef, path, value)
        }
        other => Err(format!("unsupported array item type: {:?}", other)),
    }
}

fn finalize(e: &mut E) -> Result<(), String> {
    // Pending checksums are stored in emission order; resolve each one against
    // the direct children of its enclosing struct using recorded spans.
    // Walk pending in reverse so that inner checksums are finalised first,
    // allowing outer checksums to include them if referenced.
    let pending = std::mem::take(&mut e.pending);
    for pc in pending.iter() {
        let parent = find_enclosing(e, pc.start);
        let mut spans: Vec<Span> = Vec::new();
        if let Some(parent_path) = parent {
            let children = e.spans.get(&parent_path).cloned().unwrap_or_default();
            let preceding: Vec<&(String, Span)> =
                children.iter().filter(|(_, sp)| sp.start < pc.start).collect();
            if pc.cover_names.is_empty() {
                for (_, sp) in &preceding {
                    spans.push(*sp);
                }
            } else {
                for (rs, re) in &pc.cover_names {
                    let mut include = false;
                    for (name, sp) in &preceding {
                        if name == rs {
                            include = true;
                        }
                        if include {
                            spans.push(*sp);
                        }
                        if name == re {
                            include = false;
                        }
                    }
                }
            }
        }
        spans.retain(|sp| sp.end() <= pc.start || sp.start >= pc.start + pc.width);
        let value = compute_checksum(&e.out, &spans, pc.algo);
        for i in 0..pc.width {
            let byte = ((value >> (8 * (pc.width - 1 - i))) & 0xff) as u8;
            let idx = match pc.endian {
                Endian::Big => pc.start + i,
                Endian::Little => pc.start + (pc.width - 1 - i),
            };
            e.out[idx] = byte;
        }
    }
    Ok(())
}

fn find_enclosing(e: &E, offset: usize) -> Option<String> {
    // The struct whose recorded child spans contain the nearest preceding
    // checksum start is the tightest enclosing scope. Approximate by choosing
    // the recorded struct path with the largest child-start <= offset.
    let mut best: Option<(usize, String)> = None;
    for (path, children) in &e.spans {
        if let Some((_, first)) = children.first() {
            if first.start <= offset {
                match &best {
                    Some((s, _)) if *s >= first.start => {}
                    _ => best = Some((first.start, path.clone())),
                }
            }
        }
    }
    best.map(|(_, p)| p)
}
