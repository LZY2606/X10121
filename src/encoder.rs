//! Frame encoder (parser inverse). Used by the generated-data tests to build
//! legal frames. Length fields, array counts and checksums are backpatched
//! automatically; callers provide only meaningful payload values.

use crate::spec::{Algo, Condition, CountRef, Endian, FieldDef, LengthRef, Spec, StructDef};
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Debug)]
pub struct EncodeError(pub String);

impl std::fmt::Display for EncodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Clone)]
struct IntInfo {
    start: usize,
    width: usize,
    endian: Endian,
    value: u64,
}

#[derive(Clone)]
struct Range {
    name: String,
    start: usize,
    end: usize,
}

struct ChecksumJob {
    at: usize,
    width: usize,
    endian: Endian,
    algo: Algo,
    siblings: Vec<Range>,
    intervals: Vec<crate::spec::Interval>,
}

struct Enc<'a> {
    spec: &'a Spec,
    out: Vec<u8>,
    scopes: Vec<BTreeMap<String, IntInfo>>,
    checksums: Vec<ChecksumJob>,
    depth: usize,
}

/// Encode the root struct from `values` (JSON object keyed by field names).
pub fn encode(spec: &Spec, values: &Value) -> Result<Vec<u8>, EncodeError> {
    let mut enc = Enc {
        spec,
        out: Vec::new(),
        scopes: vec![BTreeMap::new()],
        checksums: Vec::new(),
        depth: 1,
    };
    enc.encode_struct(spec.root(), values)?;

    // Checksums last so every covered byte is final.
    for job in enc.checksums.iter() {
        let mut covered = Vec::new();
        for interval in &job.intervals {
            let s = resolve_endpoint(&interval.from, &job.siblings);
            let e = resolve_endpoint(&interval.to, &job.siblings);
            if let (Some(s), Some(e)) = (s, e) {
                for off in s..e {
                    if off >= job.at && off < job.at + job.width {
                        continue; // self-exclusion
                    }
                    if let Some(byte) = enc.out.get(off).copied() {
                        covered.push(byte);
                    }
                }
            }
        }
        let checksum = job.algo.compute(&covered) as u64;
        job.endian
            .write(checksum, job.width, &mut enc.out[job.at..job.at + job.width]);
    }
    Ok(enc.out)
}

fn resolve_endpoint(ep: &crate::spec::Endpoint, siblings: &[Range]) -> Option<usize> {
    use crate::spec::{Endpoint, EndpointEdge};
    match ep {
        Endpoint::Field { field, edge } => siblings
            .iter()
            .find(|r| &r.name == field)
            .map(|r| match edge {
                EndpointEdge::Start => r.start,
                EndpointEdge::End => r.end,
            }),
        Endpoint::Abs(off) => Some(*off as usize),
    }
}

impl<'a> Enc<'a> {
    fn err<T>(msg: impl Into<String>) -> Result<T, EncodeError> {
        Err(EncodeError(msg.into()))
    }

    fn endian_of(&self, field: &FieldDef) -> Endian {
        field.endian.unwrap_or(self.spec.endian)
    }

    fn encode_struct(&mut self, sd: &StructDef, values: &Value) -> Result<(), EncodeError> {
        let start = self.out.len();
        self.scopes.push(BTreeMap::new());

        // Record sibling ranges for checksum jobs: fields append in order, but
        // length/count values are backpatched. Ranges are captured at close.
        let mut ranges: Vec<Range> = Vec::new();
        let mut length_target: Option<(String, usize, usize, Endian)> = None;

        for field in &sd.fields {
            if let Some(cond) = &field.when {
                if !self.eval(cond) {
                    continue;
                }
            }
            let fstart = self.out.len();

            if sd.length_field.as_deref() == Some(field.name.as_str()) {
                let endian = self.endian_of(field);
                let width = field.width.unwrap_or(1);
                let at = self.out.len();
                self.out.extend(std::iter::repeat(0u8).take(width));
                length_target = Some((field.name.clone(), at, width, endian));
                self.scopes.last_mut().unwrap().insert(
                    field.name.clone(),
                    IntInfo { start: at, width, endian, value: 0 },
                );
                ranges.push(Range { name: field.name.clone(), start: fstart, end: at + width });
                continue;
            }

            let value = values.get(&field.name);
            self.encode_field(field, value)?;
            ranges.push(Range {
                name: field.name.clone(),
                start: fstart,
                end: self.out.len(),
            });
        }

        let end = self.out.len();
        if let Some((_, at, width, endian)) = length_target {
            let total = (end - start) as u64;
            endian.write(total, width, &mut self.out[at..at + width]);
            for info in self.scopes.last_mut().unwrap().values_mut() {
                if info.start == at {
                    info.value = total;
                }
            }
        }

        // Register checksum jobs belonging to this structure.
        for field in &sd.fields {
            if field.kind == "checksum" {
                if let Some(range) = ranges.iter().find(|r| r.name == field.name) {
                    self.checksums.push(ChecksumJob {
                        at: range.start,
                        width: field.width.unwrap_or(1),
                        endian: self.endian_of(field),
                        algo: field.algo.unwrap_or(Algo::Xor8),
                        siblings: ranges.clone(),
                        intervals: field.cover.clone(),
                    });
                }
            }
        }

        self.scopes.pop();
        Ok(())
    }

    fn encode_field(&mut self, field: &FieldDef, value: Option<&Value>) -> Result<(), EncodeError> {
        match field.kind.as_str() {
            "int" => self.encode_int(field, value, false),
            "checksum" => self.encode_int(field, None, true),
            "bytes" => self.encode_bytes(field, value),
            "cstring" => self.encode_cstring(field, value),
            "struct" => self.encode_struct_field(field, value),
            "array" => self.encode_array(field, value),
            other => Self::err(format!("cannot encode unknown type `{}`", other)),
        }
    }

    fn encode_int(&mut self, field: &FieldDef, value: Option<&Value>, checksum: bool) -> Result<(), EncodeError> {
        let width = field.width.unwrap_or(if checksum { 1 } else { 1 });
        let endian = self.endian_of(field);
        let value = if checksum {
            0u64
        } else {
            match value {
                Some(Value::Number(n)) => n
                    .as_u64()
                    .or_else(|| n.as_i64().map(|v| v as u64))
                    .ok_or_else(|| EncodeError(format!("field `{}` needs an integer", field.name)))?,
                Some(Value::Bool(b)) => *b as u64,
                Some(_) if field.expect.is_some() => field.expect.unwrap() as u64,
                None => field
                    .expect
                    .map(|v| v as u64)
                    .ok_or_else(|| EncodeError(format!("missing value for int `{}`", field.name)))?,
                other => {
                    return Err(EncodeError(format!(
                        "field `{}` needs an integer, got {}",
                        field.name,
                        other.cloned().unwrap_or(Value::Null)
                    )))
                }
            }
        };
        let start = self.out.len();
        let mut slot = vec![0u8; width];
        endian.write(value, width, &mut slot);
        self.out.extend_from_slice(&slot);
        self.scopes
            .last_mut()
            .unwrap()
            .insert(field.name.clone(), IntInfo { start, width, endian, value });
        Ok(())
    }

    fn encode_bytes(&mut self, field: &FieldDef, value: Option<&Value>) -> Result<(), EncodeError> {
        let bytes: Vec<u8> = match value {
            Some(Value::String(s)) => crate::hex::decode(s).map_err(EncodeError)?,
            Some(Value::Array(items)) => items
                .iter()
                .map(|v| {
                    v.as_u64()
                        .map(|n| n as u8)
                        .ok_or_else(|| EncodeError("byte array must contain numbers".into()))
                })
                .collect::<Result<Vec<u8>, _>>()?,
            _ => return Self::err(format!("missing hex value for bytes `{}`", field.name)),
        };
        let start = self.out.len();
        self.out.extend_from_slice(&bytes);
        if let Some(LengthRef::Field(crate::spec::FieldRef { field: src })) = &field.length {
            self.backpatch_int(src, bytes.len() as u64)?;
        }
        let _ = start;
        Ok(())
    }

    fn encode_cstring(&mut self, field: &FieldDef, value: Option<&Value>) -> Result<(), EncodeError> {
        let text = value
            .and_then(|v| v.as_str())
            .ok_or_else(|| EncodeError(format!("missing text for cstring `{}`", field.name)))?;
        self.out.extend_from_slice(text.as_bytes());
        self.out.push(0);
        Ok(())
    }

    fn encode_struct_field(&mut self, field: &FieldDef, value: Option<&Value>) -> Result<(), EncodeError> {
        let sn = field
            .struct_name
            .as_deref()
            .ok_or_else(|| EncodeError(format!("struct field `{}` has no struct_name", field.name)))?;
        let child_def = self
            .spec
            .struct_def(sn)
            .ok_or_else(|| EncodeError(format!("unknown struct `{}`", sn)))?
            .clone();
        self.depth += 1;
        if self.depth > self.spec.max_depth {
            return Err(EncodeError(format!("recursion depth {} exceeded", self.spec.max_depth)));
        }
        let values = value.unwrap_or(&Value::Null);
        let result = self.encode_struct(&child_def, values);
        self.depth -= 1;
        result
    }

    fn backpatch_int(&mut self, name: &str, value: u64) -> Result<(), EncodeError> {
        for scope in self.scopes.iter_mut().rev() {
            if let Some(info) = scope.get_mut(name) {
                info.endian.write(value, info.width, &mut self.out[info.start..info.start + info.width]);
                info.value = value;
                return Ok(());
            }
        }
        Err(EncodeError(format!("cannot backpatch unknown int field `{}`", name)))
    }

    fn eval(&self, cond: &Condition) -> bool {
        let get = |name: &str| -> Option<u64> {
            self.scopes
                .iter()
                .rev()
                .find_map(|s| s.get(name).map(|i| i.value))
        };
        match cond {
            Condition::Eq { field, value } => get(field).map(|v| (v as i64) == *value).unwrap_or(false),
            Condition::Flag { field } => get(field).map(|v| v != 0).unwrap_or(false),
            Condition::FieldsEq { left, right } => {
                get(left).zip(get(right)).map(|(a, b)| a == b).unwrap_or(false)
            }
        }
    }
}

impl<'a> Enc<'a> {
    fn encode_array(&mut self, field: &FieldDef, value: Option<&Value>) -> Result<(), EncodeError> {
        let item = field
            .item
            .as_deref()
            .ok_or_else(|| EncodeError(format!("array `{}` has no item", field.name)))?;
        let items = match value {
            Some(Value::Array(a)) => a.clone(),
            Some(Value::Null) | None => Vec::new(),
            _ => return Self::err(format!("array `{}` needs a JSON array", field.name)),
        };

        // Resolve/count and backpatch the count field.
        match field.count.as_ref() {
            Some(CountRef::Fixed(n)) => {
                if *n as usize != items.len() {
                    return Err(EncodeError(format!(
                        "array `{}` fixed count {} but {} item(s) supplied",
                        field.name, n, items.len()
                    )));
                }
            }
            Some(crate::spec::CountRef::Field(crate::spec::FieldRef { field: src })) => {
                self.backpatch_int(src, items.len() as u64)?;
            }
            None => return Self::err(format!("array `{}` has no count", field.name)),
        }

        for element in &items {
            self.encode_field(item, Some(element))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec::*;

    fn demo_spec() -> Spec {
        let raw = serde_json::json!({
            "name": "demo",
            "root": "frame",
            "endian": "big",
            "structs": [{
                "name": "frame",
                "length_field": "total",
                "fields": [
                    {"name": "total", "type": "int", "width": 1},
                    {"name": "magic", "type": "int", "width": 2, "expect": 61377},
                    {"name": "n", "type": "int", "width": 1},
                    {"name": "payload", "type": "bytes",
                     "length": {"field": "n"}},
                    {"name": "crc", "type": "checksum", "algo": "xor8",
                     "cover": [{"from": {"field": "magic", "edge": "start"},
                                "to": {"field": "payload", "edge": "end"}}]}
                ]
            }]
        });
        let raw: RawSpec = serde_json::from_value(raw).unwrap();
        Spec::compile(raw).unwrap()
    }

    #[test]
    fn roundtrips_a_full_frame() {
        let spec = demo_spec();
        let frame = encode(
            &spec,
            &serde_json::json!({
                "magic": 61377,
                "total": 0,
                "n": 3,
                "payload": "010203",
                "crc": 0
            }),
        )
        .unwrap();
        let result = crate::parser::parse(&spec, &frame);
        assert_eq!(result.status, crate::parser::Status::Complete, "{:?} {:?}", result.error, frame);
    }
}
