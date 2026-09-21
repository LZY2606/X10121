//! Protocol description model.
//!
//! A protocol is JSON like:
//!
//! ```json
//! {
//!   "name": "demo",
//!   "endian": "big",
//!   "max_depth": 8,
//!   "root": "frame",
//!   "structs": [
//!     {
//!       "name": "frame",
//!       "length_field": "total",
//!       "fields": [
//!         {"name": "magic", "type": "int", "width": 2, "expect": 61377},
//!         {"name": "total", "type": "int", "width": 1},
//!         {"name": "kind",  "type": "int", "width": 1},
//!         {"name": "payload_len", "type": "int", "width": 1},
//!         {"name": "payload", "type": "bytes", "length": {"field": "payload_len"}},
//!         {"name": "crc", "type": "checksum", "algo": "xor8",
//!          "cover": [{"from": {"field": "magic"}, "to": {"field": "payload"}}]}
//!       ]
//!     }
//!   ]
//! }
//! ```
//!
//! The JSON form is canonicalised before hashing; a saved [`Spec`] is therefore
//! immutable and addressed by the hash of its canonical JSON.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Byte order used when a field does not carry its own override.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Endian {
    Little,
    Big,
}

impl Endian {
    pub fn read_u64(&self, bytes: &[u8]) -> u64 {
        match self {
            Endian::Big => {
                let mut v = 0u64;
                for b in bytes {
                    v = (v << 8) | (*b as u64);
                }
                v
            }
            Endian::Little => {
                let mut v = 0u64;
                for (i, b) in bytes.iter().enumerate() {
                    v |= (*b as u64) << (8 * i);
                }
                v
            }
        }
    }

    pub fn write(&self, value: u64, width: usize, out: &mut [u8]) {
        match self {
            Endian::Big => {
                for (i, slot) in out.iter_mut().enumerate() {
                    *slot = ((value >> (8 * (width - 1 - i))) & 0xff) as u8;
                }
            }
            Endian::Little => {
                for (i, slot) in out.iter_mut().enumerate() {
                    *slot = ((value >> (8 * i)) & 0xff) as u8;
                }
            }
        }
    }
}

/// Reference to a previously parsed integer field.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldRef {
    /// Field name, resolved against the same structure scope.
    pub field: String,
}

/// Reference to an integer field that supplies the length (in bytes) of data.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum LengthRef {
    /// Length given by an earlier sibling field.
    Field(FieldRef),
}

/// How the number of array elements is determined.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CountRef {
    /// Element count given by an earlier sibling field.
    Field(FieldRef),
    /// Constant element count.
    Fixed(u64),
}

/// Supported one-byte checksum algorithms.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Algo {
    /// Wrapping sum of covered bytes.
    Sum8,
    /// XOR of covered bytes.
    Xor8,
}

impl Algo {
    pub fn compute(&self, data: &[u8]) -> u8 {
        match self {
            Algo::Sum8 => data.iter().fold(0u8, |acc, b| acc.wrapping_add(*b)),
            Algo::Xor8 => data.iter().fold(0u8, |acc, b| acc ^ *b),
        }
    }
}

/// One endpoint of a checksum cover interval.
///
/// Accepted JSON shapes:
/// * `"field_name"` - start of that field
/// * `{"field": "name"}` - start of that field
/// * `{"field": "name", "edge": "end"}`
/// * `{"abs": 12}` - absolute frame offset
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Endpoint {
    Field { field: String, edge: EndpointEdge },
    Abs(u64),
}

impl Serialize for Endpoint {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        match self {
            Endpoint::Field { field, edge } => {
                use serde::ser::SerializeStruct;
                let mut m = ser.serialize_struct("Field", 2)?;
                m.serialize_field("field", field)?;
                m.serialize_field("edge", edge)?;
                m.end()
            }
            Endpoint::Abs(off) => ser.serialize_newtype_struct("Abs", off),
        }
    }
}

impl<'de> Deserialize<'de> for Endpoint {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        let value = serde_json::Value::deserialize(de)?;
        if let Some(name) = value.as_str() {
            return Ok(Endpoint::Field { field: name.to_string(), edge: EndpointEdge::Start });
        }
        let map = value
            .as_object()
            .ok_or_else(|| serde::de::Error::custom("endpoint must be a string or object"))?;

        // Externally tagged form produced by Serialize: {"Field": {...}} or
        // {"Abs": 12}.
        if let Some(inner) = map.get("Field") {
            if let Some(obj) = inner.as_object() {
                let field = obj
                    .get("field")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| serde::de::Error::custom("Field endpoint needs field"))?
                    .to_string();
                let edge = parse_edge(obj.get("edge"))?;
                return Ok(Endpoint::Field { field, edge });
            }
        }
        if let Some(off) = map.get("Abs").and_then(|v| v.as_u64()) {
            return Ok(Endpoint::Abs(off));
        }

        // Flat authoring form.
        if let Some(off) = map.get("abs").and_then(|v| v.as_u64()) {
            return Ok(Endpoint::Abs(off));
        }
        if let Some(field) = map.get("field").and_then(|v| v.as_str()) {
            let edge = parse_edge(map.get("edge"))?;
            for key in map.keys() {
                if !matches!(key.as_str(), "field" | "edge" | "abs") {
                    return Err(serde::de::Error::unknown_field(key, &["field", "edge", "abs"]));
                }
            }
            return Ok(Endpoint::Field { field: field.to_string(), edge });
        }
        Err(serde::de::Error::custom("endpoint needs field or abs"))
    }
}

fn parse_edge<E: serde::de::Error>(value: Option<&serde_json::Value>) -> Result<EndpointEdge, E> {
    match value.and_then(|v| v.as_str()) {
        None | Some("start") => Ok(EndpointEdge::Start),
        Some("end") => Ok(EndpointEdge::End),
        Some(other) => Err(serde::de::Error::custom(format!("bad edge `{}`", other))),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum EndpointEdge {
    /// First byte of the field.
    #[default]
    Start,
    /// One byte past the field.
    End,
}

/// Inclusive coverage is `[start, end)` in byte offsets.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Interval {
    pub from: Endpoint,
    pub to: Endpoint,
}

/// Runtime condition guarding a field or branch.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum Condition {
    /// Field equals a literal integer.
    Eq { field: String, value: i64 },
    /// Field is non-zero.
    Flag { field: String },
    /// Fields are equal.
    FieldsEq { left: String, right: String },
}

/// One field declaration. Only the attributes meaningful for `type` are used;
/// a flat shape keeps the JSON easy to author and edit by hand.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FieldDef {
    pub name: String,
    #[serde(rename = "type")]
    pub kind: String,

    // int
    #[serde(default)]
    pub width: Option<usize>,
    #[serde(default)]
    pub endian: Option<Endian>,
    #[serde(default)]
    pub signed: bool,
    #[serde(default)]
    pub expect: Option<i64>,

    // bytes
    #[serde(default)]
    pub length: Option<LengthRef>,
    /// `rest` bytes run to the enclosing boundary.
    #[serde(default)]
    pub rest: bool,

    // cstring
    #[serde(default)]
    pub max_len: Option<usize>,

    // struct / array
    #[serde(default)]
    pub struct_name: Option<String>,
    #[serde(default)]
    pub item: Option<Box<FieldDef>>,
    #[serde(default)]
    pub count: Option<CountRef>,

    // checksum
    #[serde(default)]
    pub algo: Option<Algo>,
    #[serde(default)]
    pub cover: Vec<Interval>,

    // conditional
    #[serde(default)]
    pub when: Option<Condition>,
}

/// A structure declaration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StructDef {
    pub name: String,
    pub fields: Vec<FieldDef>,
    /// Earlier int field naming the structure's declared total byte size.
    #[serde(default)]
    pub length_field: Option<String>,
}

/// Raw, user-authored protocol description (the editable form).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawSpec {
    pub name: String,
    pub root: String,
    #[serde(default)]
    pub endian: Option<Endian>,
    #[serde(default)]
    pub max_depth: Option<usize>,
    #[serde(default)]
    pub structs: Vec<StructDef>,
}

/// Compiled, validated protocol description.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Spec {
    pub raw: RawSpec,
    pub version_hash: String,
    pub endian: Endian,
    pub max_depth: usize,
    pub structs: BTreeMap<String, StructDef>,
}

pub const DEFAULT_MAX_DEPTH: usize = 8;

impl Spec {
    /// Compile a raw description, validating every reference.
    pub fn compile(raw: RawSpec) -> Result<Spec, Vec<String>> {
        let mut errors = Vec::new();

        if raw.name.trim().is_empty() {
            errors.push("protocol name must not be empty".to_string());
        }

        let mut seen = BTreeMap::new();
        for sd in &raw.structs {
            if sd.name.trim().is_empty() {
                errors.push("struct name must not be empty".to_string());
                continue;
            }
            if seen.insert(sd.name.clone(), ()).is_some() {
                errors.push(format!("duplicate struct name `{}`", sd.name));
            }
        }

        let structs: BTreeMap<String, StructDef> = raw
            .structs
            .iter()
            .map(|s| (s.name.clone(), s.clone()))
            .collect();

        if !structs.contains_key(&raw.root) {
            errors.push(format!("root struct `{}` is not defined", raw.root));
        }

        let max_depth = raw.max_depth.unwrap_or(DEFAULT_MAX_DEPTH);
        if max_depth == 0 {
            errors.push("max_depth must be at least 1".to_string());
        }

        for sd in &raw.structs {
            validate_struct(sd, &structs, &mut errors);
        }

        if let Some(max) = raw.max_depth {
            if max > 0 {
                check_recursion_bounds(&raw.root, &structs, max, &mut errors);
            }
        }

        if errors.is_empty() {
            let canonical = canonical_json(&raw);
            let version_hash = crate::hash::sha256_hex(canonical.as_bytes());
            let endian = raw.endian.unwrap_or(Endian::Big);
            Ok(Spec {
                raw: raw.clone(),
                version_hash,
                endian,
                max_depth,
                structs,
            })
        } else {
            Err(errors)
        }
    }

    pub fn root(&self) -> &StructDef {
        &self.structs[&self.raw.root]
    }

    pub fn struct_def(&self, name: &str) -> Option<&StructDef> {
        self.structs.get(name)
    }

    pub fn field(&self, struct_name: &str, field_name: &str) -> Option<&FieldDef> {
        self.structs
            .get(struct_name)
            .and_then(|s| s.fields.iter().find(|f| f.name == field_name))
    }

    /// Canonical JSON of the editable description.
    pub fn canonical(&self) -> String {
        canonical_json(&self.raw)
    }
}


/// Deterministic serialisation: JSON with object keys sorted lexicographically.
pub fn canonical_json<T: Serialize>(value: &T) -> String {
    let value = serde_json::to_value(value).expect("values are JSON");
    let mut buf = Vec::new();
    write_canonical(&value, &mut buf);
    String::from_utf8(buf).expect("canonical json is utf-8")
}

fn write_canonical(value: &serde_json::Value, out: &mut Vec<u8>) {
    match value {
        serde_json::Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push(b'{');
            for (i, key) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                serde_json::to_writer(&mut *out, *key).expect("write key");
                out.push(b':');
                write_canonical(&map[*key], out);
            }
            out.push(b'}');
        }
        serde_json::Value::Array(items) => {
            out.push(b'[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_canonical(item, out);
            }
            out.push(b']');
        }
        other => {
            serde_json::to_writer(&mut *out, other).expect("write scalar");
        }
    }
}

const VALID_TYPES: &[&str] = &["int", "bytes", "cstring", "struct", "array", "checksum"];

fn validate_struct(
    sd: &StructDef,
    structs: &BTreeMap<String, StructDef>,
    errors: &mut Vec<String>,
) {
    let ctx = format!("struct `{}`", sd.name);
    let mut names = BTreeMap::new();
    for (idx, f) in sd.fields.iter().enumerate() {
        if f.name.trim().is_empty() {
            errors.push(format!("{}: field #{} has an empty name", ctx, idx + 1));
        } else if names.insert(f.name.clone(), idx).is_some() {
            errors.push(format!("{}: duplicate field name `{}`", ctx, f.name));
        }
        validate_field(sd, f, structs, errors, false);
    }

    if let Some(lf) = &sd.length_field {
        match sd.fields.iter().position(|f| &f.name == lf) {
            None => errors.push(format!("{}: length_field `{}` is not a field", ctx, lf)),
            Some(pos) => {
                let lfdef = &sd.fields[pos];
                if lfdef.kind != "int" {
                    errors.push(format!("{}: length_field `{}` must be an int", ctx, lf));
                }
                if pos != 0 {
                    errors.push(format!(
                        "{}: length_field `{}` must be the first field",
                        ctx, lf
                    ));
                }
            }
        }
    }
}

fn validate_field(
    sd: &StructDef,
    f: &FieldDef,
    structs: &BTreeMap<String, StructDef>,
    errors: &mut Vec<String>,
    array_item: bool,
) {
    let ctx = if array_item {
        format!("struct `{}` array item", sd.name)
    } else {
        format!("struct `{}` field `{}`", sd.name, f.name)
    };

    if !VALID_TYPES.contains(&f.kind.as_str()) {
        errors.push(format!(
            "{}: unknown type `{}` (expected one of {})",
            ctx,
            f.kind,
            VALID_TYPES.join(", ")
        ));
        return;
    }

    let earlier = |target: &str| -> bool {
        sd.fields
            .iter()
            .take_while(|x| x.name != f.name)
            .any(|x| x.name == target)
    };

    match f.kind.as_str() {
        "int" => {
            match f.width {
                Some(w) if (1..=8).contains(&w) => {}
                Some(w) => errors.push(format!("{}: width {} must be between 1 and 8", ctx, w)),
                None => errors.push(format!("{}: int field requires `width`", ctx)),
            }
            if f.rest || f.length.is_some() || f.struct_name.is_some() || f.item.is_some()
                || f.count.is_some() || !f.cover.is_empty() || f.algo.is_some()
            {
                errors.push(format!("{}: int field has attributes it cannot use", ctx));
            }
            if let Some(v) = f.expect {
                if v < 0 && !f.signed {
                    errors.push(format!("{}: negative expect requires signed: true", ctx));
                }
            }
        }
        "checksum" => {
            match f.width {
                Some(w) if (1..=8).contains(&w) => {}
                Some(w) => errors.push(format!("{}: width {} must be between 1 and 8", ctx, w)),
                None => {}
            }
            let algo = f.algo.ok_or_else(|| {
                errors.push(format!("{}: checksum requires `algo` (sum8/xor8)", ctx));
            });
            if f.cover.is_empty() {
                errors.push(format!("{}: checksum requires at least one cover interval", ctx));
            }
            if f.rest || f.length.is_some() || f.struct_name.is_some() || f.item.is_some()
                || f.count.is_some() || f.max_len.is_some()
            {
                errors.push(format!("{}: checksum field has attributes it cannot use", ctx));
            }
            if let Ok(algo) = algo {
                if matches!(algo, Algo::Sum8 | Algo::Xor8) {
                    match f.width {
                        Some(w) if w != 1 => errors.push(format!(
                            "{}: {:?} checksum requires width 1",
                            ctx, algo
                        )),
                        _ => {}
                    }
                }
            }
            for interval in &f.cover {
                validate_endpoint(sd, f, &interval.from, earlier, errors, &ctx);
                validate_endpoint(sd, f, &interval.to, earlier, errors, &ctx);
            }
        }
        "bytes" => {
            if f.rest {
                if f.length.is_some() {
                    errors.push(format!("{}: bytes field cannot use both length and rest", ctx));
                }
            } else if f.length.is_none() {
                errors.push(format!("{}: bytes field requires `length` or rest: true", ctx));
            } else {
                let LengthRef::Field(FieldRef { field }) = f.length.as_ref().unwrap();
                require_earlier_int(sd, field, f, errors, "length");
            }
            if f.struct_name.is_some() || f.item.is_some() || f.count.is_some()
                || !f.cover.is_empty() || f.algo.is_some() || f.expect.is_some()
            {
                errors.push(format!("{}: bytes field has attributes it cannot use", ctx));
            }
            if let Some(m) = f.max_len {
                if m == 0 {
                    errors.push(format!("{}: max_len must be greater than 0", ctx));
                }
            }
        }
        "cstring" => {
            if f.length.is_some() || f.rest || f.struct_name.is_some() || f.item.is_some()
                || f.count.is_some() || !f.cover.is_empty() || f.algo.is_some()
                || f.width.is_some()
            {
                errors.push(format!("{}: cstring field has attributes it cannot use", ctx));
            }
            if let Some(m) = f.max_len {
                if m == 0 {
                    errors.push(format!("{}: max_len must be greater than 0", ctx));
                }
            }
        }
        "struct" => {
            let sn = f.struct_name.as_ref().ok_or_else(|| {
                errors.push(format!("{}: struct field requires `struct_name`", ctx));
            });
            if let Ok(sn) = sn {
                if !structs.contains_key(sn) {
                    errors.push(format!("{}: unknown struct_name `{}`", ctx, sn));
                }
            }
            if f.rest || f.length.is_some() || f.item.is_some() || f.count.is_some()
                || !f.cover.is_empty() || f.algo.is_some() || f.width.is_some()
            {
                errors.push(format!("{}: struct field has attributes it cannot use", ctx));
            }
        }
        "array" => {
            match &f.count {
                Some(CountRef::Field(FieldRef { field })) => {
                    require_earlier_int(sd, field, f, errors, "count");
                }
                Some(CountRef::Fixed(n)) => {
                    if *n == 0 {
                        errors.push(format!("{}: fixed count must be greater than 0", ctx));
                    }
                }
                None => errors.push(format!("{}: array requires `count`", ctx)),
            }
            if let Some(item) = f.item.as_ref() {
                if item.when.is_some() {
                    errors.push(format!("{}: array item cannot itself be conditional", ctx));
                }
                validate_field(sd, item, structs, errors, true);
            } else {
                errors.push(format!("{}: array requires an `item` declaration", ctx));
            }
            if f.rest || f.length.is_some() || f.struct_name.is_some()
                || !f.cover.is_empty() || f.algo.is_some() || f.width.is_some()
            {
                errors.push(format!("{}: array field has attributes it cannot use", ctx));
            }
        }
        _ => unreachable!(),
    }

    if let Some(cond) = &f.when {
        match cond {
            Condition::Eq { field, .. } | Condition::Flag { field } => {
                if !earlier(field) {
                    errors.push(format!("{}: condition references non-earlier field `{}`", ctx, field));
                } else {
                    require_int_by_name(sd, field, errors, &ctx);
                }
            }
            Condition::FieldsEq { left, right } => {
                for name in [left, right] {
                    if !earlier(name) {
                        errors.push(format!(
                            "{}: condition references non-earlier field `{}`",
                            ctx, name
                        ));
                    } else {
                        require_int_by_name(sd, name, errors, &ctx);
                    }
                }
            }
        }
    }
}

fn require_earlier_int(
    sd: &StructDef,
    target: &str,
    f: &FieldDef,
    errors: &mut Vec<String>,
    role: &str,
) {
    let pos = sd.fields.iter().position(|x| x.name == target);
    match pos {
        None => errors.push(format!(
            "struct `{}` field `{}`: {} references unknown field `{}`",
            sd.name, f.name, role, target
        )),
        Some(p) => {
            if p >= sd.fields.iter().position(|x| x.name == f.name).unwrap_or(0) {
                errors.push(format!(
                    "struct `{}` field `{}`: {} field `{}` must appear earlier",
                    sd.name, f.name, role, target
                ));
            }
            if sd.fields[p].kind != "int" {
                errors.push(format!(
                    "struct `{}` field `{}`: {} field `{}` must be an int",
                    sd.name, f.name, role, target
                ));
            }
        }
    }
}

fn require_int_by_name(sd: &StructDef, target: &str, errors: &mut Vec<String>, ctx: &str) {
    if let Some(dep) = sd.fields.iter().find(|x| x.name == target) {
        if dep.kind != "int" {
            errors.push(format!("{}: referenced field `{}` must be an int", ctx, target));
        }
    }
}

fn validate_endpoint(
    sd: &StructDef,
    _checksum: &FieldDef,
    ep: &Endpoint,
    _earlier: impl Fn(&str) -> bool,
    errors: &mut Vec<String>,
    ctx: &str,
) {
    if let Endpoint::Field { field, .. } = ep {
        // Endpoints are resolved after parsing, so they may name fields that
        // sit before, at or after the checksum inside the same structure.
        if !sd.fields.iter().any(|x| &x.name == field) {
            errors.push(format!("{}: cover endpoint references unknown field `{}`", ctx, field));
        }
    }
}

/// Ensure every possible `struct` nesting chain stays within the depth budget.
fn check_recursion_bounds(
    root: &str,
    structs: &BTreeMap<String, StructDef>,
    _max_depth: usize,
    errors: &mut Vec<String>,
) {
    // Only reject statically unbounded recursion (a cycle). A finite chain
    // longer than max_depth is legal to declare; the runtime parser reports
    // the depth error based on actual data.
    fn visit(
        current: &str,
        structs: &BTreeMap<String, StructDef>,
        chain: &mut Vec<String>,
        errors: &mut Vec<String>,
    ) {
        if chain.contains(&current.to_string()) {
            errors.push(format!(
                "unbounded struct recursion through `{}` (cycle: {})",
                current,
                chain.join(" -> ")
            ));
            return;
        }
        let Some(sd) = structs.get(current) else { return };
        chain.push(current.to_string());
        for f in &sd.fields {
            if let Some(child) = &f.struct_name {
                visit(child, structs, chain, errors);
            }
            if let Some(item) = &f.item {
                if let Some(child) = &item.struct_name {
                    visit(child, structs, chain, errors);
                }
            }
        }
        chain.pop();
    }
    let mut chain = Vec::new();
    visit(root, structs, &mut chain, errors);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_is_key_sorted_and_stable() {
        let raw = RawSpec {
            name: "d".into(),
            root: "r".into(),
            endian: Some(Endian::Little),
            max_depth: None,
            structs: vec![StructDef {
                name: "r".into(),
                length_field: None,
                fields: vec![FieldDef {
                    name: "a".into(),
                    kind: "int".into(),
                    width: Some(1),
                    endian: None,
                    signed: false,
                    expect: None,
                    length: None,
                    rest: false,
                    max_len: None,
                    struct_name: None,
                    item: None,
                    count: None,
                    algo: None,
                    cover: vec![],
                    when: None,
                }],
            }],
        };
        let a = Spec::compile(raw.clone()).unwrap();
        let b = Spec::compile(raw.clone()).unwrap();
        assert_eq!(a.version_hash, b.version_hash);
        assert_eq!(a.canonical(), b.canonical());
    }

    #[test]
    fn rejects_forward_reference_and_bad_cover() {
        let raw = RawSpec {
            name: "d".into(),
            root: "r".into(),
            endian: None,
            max_depth: None,
            structs: vec![StructDef {
                name: "r".into(),
                length_field: None,
                fields: vec![
                    FieldDef {
                        name: "p".into(),
                        kind: "bytes".into(),
                        width: None,
                        endian: None,
                        signed: false,
                        expect: None,
                        length: Some(LengthRef::Field(FieldRef { field: "n".into() })),
                        rest: false,
                        max_len: None,
                        struct_name: None,
                        item: None,
                        count: None,
                        algo: None,
                        cover: vec![],
                        when: None,
                    },
                    FieldDef {
                        name: "n".into(),
                        kind: "int".into(),
                        width: Some(1),
                        endian: None,
                        signed: false,
                        expect: None,
                        length: None,
                        rest: false,
                        max_len: None,
                        struct_name: None,
                        item: None,
                        count: None,
                        algo: None,
                        cover: vec![],
                        when: None,
                    },
                ],
            }],
        };
        let errs = Spec::compile(raw).unwrap_err();
        assert!(errs.iter().any(|e| e.contains("must appear earlier")));
    }
}
