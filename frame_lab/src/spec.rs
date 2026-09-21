// Compiled protocol description. A protocol is a set of named structs made
// of fields. Fields may be fixed/variable integers, sized byte runs, nested
// structs, arrays, conditional groups, recursive references and checksums.

use crate::json::Json;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endian {
    Big,
    Little,
}

impl Endian {
    fn parse(s: Option<&str>) -> Result<Endian, String> {
        match s.unwrap_or("big") {
            "big" | "be" => Ok(Endian::Big),
            "little" | "le" => Ok(Endian::Little),
            other => Err(format!("unknown endian '{}'", other)),
        }
    }
}

/// Length/count expression: constant or scale*field + bias.
#[derive(Debug, Clone)]
pub enum LenExpr {
    Const(usize),
    Field {
        path: String,
        scale: i64,
        bias: i64,
    },
}

impl LenExpr {
    fn from_json(j: &Json) -> Result<LenExpr, String> {
        match j {
            Json::Num(n, _) if *n >= 0 => Ok(LenExpr::Const(*n as usize)),
            Json::Obj(m) => {
                let path = m
                    .get("field")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| "length expression needs 'field'".to_string())?
                    .to_string();
                let scale = m.get("scale").and_then(|v| v.as_i64()).unwrap_or(1);
                let bias = m.get("bias").and_then(|v| v.as_i64()).unwrap_or(0);
                if scale <= 0 {
                    return Err("length scale must be positive".to_string());
                }
                Ok(LenExpr::Field {
                    path,
                    scale,
                    bias,
                })
            }
            _ => Err("length must be a non-negative integer or {field,...}".to_string()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct WhenCond {
    pub path: String,
    pub equals: i64,
    pub mask: Option<u64>,
}

impl WhenCond {
    fn from_json(j: &Json) -> Result<WhenCond, String> {
        let path = j
            .get("field")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "condition needs 'field'".to_string())?
            .to_string();
        let equals = j
            .get("equals")
            .and_then(|v| v.as_i64())
            .ok_or_else(|| "condition needs integer 'equals'".to_string())?;
        let mask = j.get("mask").and_then(|v| v.as_u64());
        Ok(WhenCond {
            path,
            equals,
            mask,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChecksumAlgo {
    Sum8,
    Sum16,
    Xor8,
    Xor16,
}

impl ChecksumAlgo {
    pub fn parse(s: &str) -> Result<ChecksumAlgo, String> {
        Ok(match s {
            "sum8" => ChecksumAlgo::Sum8,
            "sum16" => ChecksumAlgo::Sum16,
            "xor8" => ChecksumAlgo::Xor8,
            "xor16" => ChecksumAlgo::Xor16,
            other => return Err(format!("unknown checksum algo '{}'", other)),
        })
    }
    pub fn width(self) -> usize {
        match self {
            ChecksumAlgo::Sum8 | ChecksumAlgo::Xor8 => 1,
            ChecksumAlgo::Sum16 | ChecksumAlgo::Xor16 => 2,
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            ChecksumAlgo::Sum8 => "sum8",
            ChecksumAlgo::Sum16 => "sum16",
            ChecksumAlgo::Xor8 => "xor8",
            ChecksumAlgo::Xor16 => "xor16",
        }
    }
}

/// One inclusive range of sibling field names within the checksum's
/// enclosing struct. The checksum's own bytes are always excluded.
#[derive(Debug, Clone)]
pub struct CoverRange {
    pub start: String,
    pub end: String,
}

#[derive(Debug, Clone)]
pub struct CoverSpec {
    pub ranges: Vec<CoverRange>,
}

#[derive(Debug, Clone)]
pub enum FieldKind {
    UInt {
        width: usize,
        endian: Endian,
        constant: Option<u64>,
    },
    Bytes {
        length: LenExpr,
    },
    Struct {
        struct_name: String,
        /// Optional declared byte length; the struct must consume exactly it
        /// and it forms the hard boundary for all descendant fields.
        length: Option<LenExpr>,
    },
    Array {
        count: LenExpr,
        item: Box<FieldDef>,
    },
    When {
        cond: WhenCond,
        fields: Vec<FieldDef>,
    },
    Ref {
        target: String,
    },
    Checksum {
        width: usize,
        endian: Endian,
        algo: ChecksumAlgo,
        cover: CoverSpec,
    },
}

#[derive(Debug, Clone)]
pub struct FieldDef {
    pub name: String,
    pub kind: FieldKind,
}

#[derive(Debug, Clone)]
pub struct StructDef {
    pub name: String,
    pub fields: Vec<FieldDef>,
}

#[derive(Debug, Clone)]
pub struct Protocol {
    pub name: String,
    pub root: String,
    pub max_depth: usize,
    pub structs: BTreeMap<String, StructDef>,
    pub struct_order: Vec<String>,
}

impl Protocol {
    /// Compile from schema JSON. Fails on structural problems so that an
    /// invalid description can never become an immutable version.
    pub fn compile(schema: &Json) -> Result<Protocol, String> {
        let name = schema
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("protocol")
            .to_string();
        let root = schema
            .get("root")
            .and_then(|v| v.as_str())
            .unwrap_or("Frame")
            .to_string();
        let max_depth = schema
            .get("max_depth")
            .and_then(|v| v.as_u64())
            .unwrap_or(16) as usize;
        if max_depth == 0 {
            return Err("max_depth must be >= 1".to_string());
        }

        let structs_json = schema
            .get("structs")
            .and_then(|v| v.as_object())
            .ok_or_else(|| "schema needs a 'structs' object".to_string())?;

        let mut structs = BTreeMap::new();
        let mut struct_order = Vec::new();
        for (sname, fields_json) in structs_json {
            let arr = fields_json
                .as_array()
                .ok_or_else(|| format!("struct '{}' must be an array of fields", sname))?;
            let mut fields = Vec::new();
            for fj in arr {
                fields.push(compile_field(fj)?);
            }
            unique_names(&fields, &format!("struct '{}'", sname))?;
            struct_order.push(sname.clone());
            structs.insert(
                sname.clone(),
                StructDef {
                    name: sname.clone(),
                    fields,
                },
            );
        }

        if !structs.contains_key(&root) {
            return Err(format!("root struct '{}' not found", root));
        }

        let proto = Protocol {
            name,
            root,
            max_depth,
            structs,
            struct_order,
        };
        proto.validate_refs()?;
        Ok(proto)
    }

    fn validate_refs(&self) -> Result<(), String> {
        for sdef in self.structs.values() {
            for f in &sdef.fields {
                self.validate_field(f, &sdef.name, 0)?;
            }
        }
        Ok(())
    }

    fn validate_field(&self, f: &FieldDef, owner: &str, depth: usize) -> Result<(), String> {
        if depth > 64 {
            return Err("nested definitions too deep".to_string());
        }
        match &f.kind {
            FieldKind::UInt { width, .. } => {
                if *width == 0 || *width > 8 {
                    return Err(format!("{}.{}: uint width must be 1..=8", owner, f.name));
                }
            }
            FieldKind::Struct {
                struct_name, length, ..
            } => {
                if !self.structs.contains_key(struct_name) {
                    return Err(format!(
                        "{}.{}: unknown struct '{}'",
                        owner, f.name, struct_name
                    ));
                }
                let _ = length;
            }
            FieldKind::Array { item, .. } => {
                if item.name != "$item" {
                    return Err("internal: array item must be anonymous".to_string());
                }
                self.validate_field(item, owner, depth + 1)?;
            }
            FieldKind::When { fields, .. } => {
                unique_names(fields, &format!("{}.{} when-group", owner, f.name))?;
                for inner in fields {
                    self.validate_field(inner, owner, depth + 1)?;
                }
            }
            FieldKind::Ref { target } => {
                if !self.structs.contains_key(target) {
                    return Err(format!("{}.{}: unknown ref target '{}'", owner, f.name, target));
                }
            }
            FieldKind::Checksum { width, algo, .. } => {
                if *width != algo.width() {
                    return Err(format!(
                        "{}.{}: {} needs width {}",
                        owner,
                        f.name,
                        algo.label(),
                        algo.width()
                    ));
                }
            }
            FieldKind::Bytes { .. } => {}
        }
        Ok(())
    }
}

fn unique_names(fields: &[FieldDef], ctx: &str) -> Result<(), String> {
    let mut seen = std::collections::BTreeSet::new();
    for f in fields {
        if !seen.insert(f.name.clone()) {
            return Err(format!("{}: duplicate field name '{}'", ctx, f.name));
        }
    }
    Ok(())
}

fn compile_field(j: &Json) -> Result<FieldDef, String> {
    let name = j
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("$item")
        .to_string();
    let ty = j
        .get("type")
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("field '{}' needs a type", name))?;

    let kind = match ty {
        "uint" | "int" => {
            let width = j
                .get("width")
                .and_then(|v| v.as_u64())
                .ok_or_else(|| format!("field '{}' needs integer width", name))?
                as usize;
            let endian = Endian::parse(j.get("endian").and_then(|v| v.as_str()))?;
            let constant = j.get("const").and_then(|v| v.as_u64());
            FieldKind::UInt {
                width,
                endian,
                constant,
            }
        }
        "bytes" => {
            let length = j
                .get("length")
                .map(LenExpr::from_json)
                .transpose()?
                .unwrap_or(LenExpr::Const(0));
            FieldKind::Bytes { length }
        }
        "struct" => {
            let struct_name = j
                .get("ref")
                .and_then(|v| v.as_str())
                .ok_or_else(|| format!("struct field '{}' needs 'ref'", name))?
                .to_string();
            let length = j
                .get("length")
                .map(LenExpr::from_json)
                .transpose()?;
            FieldKind::Struct {
                struct_name,
                length,
            }
        }
        "array" => {
            let count = j
                .get("count")
                .map(LenExpr::from_json)
                .transpose()?
                .ok_or_else(|| format!("array '{}' needs 'count'", name))?;
            let item_json = j
                .get("item")
                .ok_or_else(|| format!("array '{}' needs 'item'", name))?;
            let mut item = compile_field(item_json)?;
            item.name = "$item".to_string();
            FieldKind::Array {
                count,
                item: Box::new(item),
            }
        }
        "when" => {
            let cond = WhenCond::from_json(j)?;
            let arr = j
                .get("fields")
                .and_then(|v| v.as_array())
                .ok_or_else(|| format!("when '{}' needs 'fields' array", name))?;
            let mut fields = Vec::new();
            for fj in arr {
                fields.push(compile_field(fj)?);
            }
            FieldKind::When { cond, fields }
        }
        "ref" => {
            let target = j
                .get("to")
                .and_then(|v| v.as_str())
                .ok_or_else(|| format!("ref field '{}' needs 'to'", name))?
                .to_string();
            FieldKind::Ref { target }
        }
        "checksum" => {
            let algo = j
                .get("algo")
                .and_then(|v| v.as_str())
                .map(ChecksumAlgo::parse)
                .transpose()?
                .unwrap_or(ChecksumAlgo::Sum8);
            let width = j
                .get("width")
                .and_then(|v| v.as_u64())
                .map(|w| w as usize)
                .unwrap_or_else(|| algo.width());
            let endian = Endian::parse(j.get("endian").and_then(|v| v.as_str()))?;
            let cover = compile_cover(j.get("cover"))?;
            FieldKind::Checksum {
                width,
                endian,
                algo,
                cover,
            }
        }
        other => return Err(format!("field '{}': unknown type '{}'", name, other)),
    };

    Ok(FieldDef { name, kind })
}

fn compile_cover(j: Option<&Json>) -> Result<CoverSpec, String> {
    let Some(j) = j else {
        return Ok(CoverSpec { ranges: Vec::new() });
    };
    let arr = j
        .as_array()
        .ok_or_else(|| "cover must be an array of ranges".to_string())?;
    let mut ranges = Vec::new();
    for r in arr {
        let (start, end) = if let Some(name) = r.as_str() {
            (name.to_string(), name.to_string())
        } else {
            let start = r
                .get("start")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "cover range needs 'start'".to_string())?
                .to_string();
            let end = r
                .get("end")
                .and_then(|v| v.as_str())
                .unwrap_or(&start)
                .to_string();
            (start, end)
        };
        ranges.push(CoverRange { start, end });
    }
    Ok(CoverSpec { ranges })
}
