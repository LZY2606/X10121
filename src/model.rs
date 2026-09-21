//! 协议描述的不可变数据模型。
//!
//! 协议以 JSON 声明，保存时计算规范化哈希作为不可变版本号。
//! 本模块自带与 [`crate::json`] 之间的确定性转换。

use crate::json::Json;
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq)]
pub struct ProtocolSpec {
    pub name: String,
    pub root: String,
    pub max_depth: u32,
    pub structs: BTreeMap<String, StructDef>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct StructDef {
    pub fields: Vec<FieldDef>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum FieldDef {
    Int {
        name: String,
        width: u32,
        endian: Endian,
        signed: bool,
        /// 若给出，解析值必须等于该常量（如 magic），否则违规。
        expect: Option<i64>,
    },
    Bytes {
        name: String,
        length: LengthExpr,
    },
    Payload {
        name: String,
        length_field: String,
    },
    Struct {
        name: String,
        ty: String,
        length: Option<LengthExpr>,
    },
    Vector {
        name: String,
        count: Option<LengthExpr>,
        bounded: Option<LengthExpr>,
        element: Box<FieldDef>,
    },
    Switch {
        name: String,
        on: String,
        cases: BTreeMap<String, SwitchCase>,
        fallback: Option<SwitchCase>,
    },
    Checksum {
        name: String,
        width: u32,
        algorithm: ChecksumAlgo,
        endian: Endian,
        start: Option<u64>,
        end: Option<EndRef>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Endian {
    Le,
    Be,
}

#[derive(Clone, Debug, PartialEq)]
pub enum LengthExpr {
    Fixed(u64),
    Field(String),
}

#[derive(Clone, Debug, PartialEq)]
pub struct SwitchCase {
    pub fields: Vec<FieldDef>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum EndRef {
    StructEnd,
    Field(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChecksumAlgo {
    Sum8,
    Xor8,
    Sum16,
    Crc32,
}

impl ChecksumAlgo {
    pub fn required_width(self) -> u32 {
        match self {
            ChecksumAlgo::Sum8 | ChecksumAlgo::Xor8 => 1,
            ChecksumAlgo::Sum16 => 2,
            ChecksumAlgo::Crc32 => 4,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            ChecksumAlgo::Sum8 => "sum8",
            ChecksumAlgo::Xor8 => "xor8",
            ChecksumAlgo::Sum16 => "sum16",
            ChecksumAlgo::Crc32 => "crc32",
        }
    }
    pub fn parse(s: &str) -> Option<ChecksumAlgo> {
        Some(match s {
            "sum8" => ChecksumAlgo::Sum8,
            "xor8" => ChecksumAlgo::Xor8,
            "sum16" => ChecksumAlgo::Sum16,
            "crc32" => ChecksumAlgo::Crc32,
            _ => return None,
        })
    }
}

impl Endian {
    fn as_str(self) -> &'static str {
        match self {
            Endian::Le => "le",
            Endian::Be => "be",
        }
    }
}

impl FieldDef {
    pub fn name(&self) -> &str {
        match self {
            FieldDef::Int { name, .. }
            | FieldDef::Bytes { name, .. }
            | FieldDef::Payload { name, .. }
            | FieldDef::Struct { name, .. }
            | FieldDef::Vector { name, .. }
            | FieldDef::Switch { name, .. }
            | FieldDef::Checksum { name, .. } => name,
        }
    }
    pub fn kind(&self) -> &'static str {
        match self {
            FieldDef::Int { .. } => "int",
            FieldDef::Bytes { .. } => "bytes",
            FieldDef::Payload { .. } => "payload",
            FieldDef::Struct { .. } => "struct",
            FieldDef::Vector { .. } => "vector",
            FieldDef::Switch { .. } => "switch",
            FieldDef::Checksum { .. } => "checksum",
        }
    }
}

fn jstr(j: &Json, key: &str) -> Result<String, String> {
    j.get(key)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| format!("缺少字符串字段 {}", key))
}
fn ju64(j: &Json, key: &str) -> Result<u64, String> {
    j.get(key)
        .and_then(|v| v.as_u64())
        .ok_or_else(|| format!("缺少非负整数字段 {}", key))
}
fn ju32(j: &Json, key: &str) -> Result<u32, String> {
    ju64(j, key).map(|v| v as u32)
}

fn parse_length(j: &Json) -> Result<LengthExpr, String> {
    match j {
        Json::Num(n) => Ok(LengthExpr::Fixed(*n as u64)),
        Json::Obj(_m) => {
            if let Some(name) = j.get("field").and_then(|v| v.as_str()) {
                Ok(LengthExpr::Field(name.to_string()))
            } else if let Some(v) = j
                .get("fixed")
                .or_else(|| j.get("value"))
                .and_then(|v| v.as_u64())
            {
                Ok(LengthExpr::Fixed(v))
            } else {
                Err("长度对象需要 field 或 fixed".into())
            }
        }
        _ => Err("长度表达式必须是数字或对象".into()),
    }
}

fn length_to_json(l: &LengthExpr) -> Json {
    match l {
        LengthExpr::Fixed(v) => Json::from_u64(*v),
        LengthExpr::Field(name) => {
            crate::json::obj(vec![("kind", Json::string("field")), ("field", Json::string(name))])
        }
    }
}

fn parse_case(j: &Json) -> Result<SwitchCase, String> {
    let arr = j
        .get("fields")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "分支需要 fields 数组".to_string())?;
    let mut fields = Vec::new();
    for f in arr {
        fields.push(parse_field(f)?);
    }
    Ok(SwitchCase { fields })
}

fn case_to_json(c: &SwitchCase) -> Json {
    crate::json::obj(vec![(
        "fields",
        Json::Arr(c.fields.iter().map(field_to_json).collect()),
    )])
}

pub fn parse_field(j: &Json) -> Result<FieldDef, String> {
    let kind = jstr(j, "kind")?;
    let name = jstr(j, "name")?;
    let endian = match j.get("endian").and_then(|v| v.as_str()) {
        None | Some("be") => Endian::Be,
        Some("le") => Endian::Le,
        Some(other) => return Err(format!("未知字节序 {}", other)),
    };
    let signed = j.get("signed").and_then(|v| v.as_bool()).unwrap_or(false);
    Ok(match kind.as_str() {
        "int" => FieldDef::Int {
            name,
            width: ju32(j, "width")?,
            endian,
            signed,
            expect: j.get("expect").and_then(|v| v.as_i64()),
        },
        "bytes" => FieldDef::Bytes {
            name,
            length: parse_length(j.get("length").ok_or("bytes 需要 length")?)?,
        },
        "payload" => FieldDef::Payload {
            name,
            length_field: jstr(j, "length_field")?,
        },
        "struct" => FieldDef::Struct {
            name,
            ty: jstr(j, "ty")?,
            length: match j.get("length") {
                Some(v) if !matches!(v, Json::Null) => Some(parse_length(v)?),
                _ => None,
            },
        },
        "vector" => {
            if j.get("count").is_some() && j.get("bounded").is_some() {
                return Err("vector 只能给出 count 或 bounded 之一".into());
            }
            let element = parse_field(j.get("element").ok_or("vector 需要 element")?)?;
            FieldDef::Vector {
                name,
                count: match j.get("count") {
                    Some(v) if !matches!(v, Json::Null) => Some(parse_length(v)?),
                    _ => None,
                },
                bounded: match j.get("bounded") {
                    Some(v) if !matches!(v, Json::Null) => Some(parse_length(v)?),
                    _ => None,
                },
                element: Box::new(element),
            }
        }
        "switch" => {
            let mut cases = BTreeMap::new();
            if let Some(Json::Obj(m)) = j.get("cases") {
                for (k, v) in m {
                    cases.insert(k.clone(), parse_case(v)?);
                }
            }
            FieldDef::Switch {
                name,
                on: jstr(j, "on")?,
                cases,
                fallback: match j.get("fallback") {
                    Some(v) if !matches!(v, Json::Null) => Some(parse_case(v)?),
                    _ => None,
                },
            }
        }
        "checksum" => FieldDef::Checksum {
            name,
            width: ju32(j, "width")?,
            algorithm: ChecksumAlgo::parse(&jstr(j, "algorithm")?)
                .ok_or_else(|| "未知校验算法".to_string())?,
            endian,
            start: j.get("start").and_then(|v| v.as_u64()),
            end: match j.get("end") {
                None | Some(Json::Null) => None,
                Some(Json::Str(s)) if s == "struct_end" => Some(EndRef::StructEnd),
                Some(Json::Obj(_)) => {
                    let field = jstr(j.get("end").unwrap(), "field")?;
                    Some(EndRef::Field(field))
                }
                Some(_) => return Err("非法 end".into()),
            },
        },
        other => return Err(format!("未知字段类型 {}", other)),
    })
}

pub fn field_to_json(f: &FieldDef) -> Json {
    let mut pairs: Vec<(&str, Json)> = vec![("kind", Json::string(f.kind()))];
    match f {
        FieldDef::Int {
            name,
            width,
            endian,
            signed,
            expect,
        } => {
            pairs.push(("name", Json::string(name)));
            pairs.push(("width", Json::from_u64(*width as u64)));
            pairs.push(("endian", Json::string(endian.as_str())));
            pairs.push(("signed", Json::Bool(*signed)));
            if let Some(e) = expect {
                pairs.push(("expect", Json::from_i64(*e)));
            }
        }
        FieldDef::Bytes { name, length } => {
            pairs.push(("name", Json::string(name)));
            pairs.push(("length", length_to_json(length)));
        }
        FieldDef::Payload { name, length_field } => {
            pairs.push(("name", Json::string(name)));
            pairs.push(("length_field", Json::string(length_field)));
        }
        FieldDef::Struct { name, ty, length } => {
            pairs.push(("name", Json::string(name)));
            pairs.push(("ty", Json::string(ty)));
            if let Some(l) = length {
                pairs.push(("length", length_to_json(l)));
            }
        }
        FieldDef::Vector {
            name,
            count,
            bounded,
            element,
        } => {
            pairs.push(("name", Json::string(name)));
            if let Some(c) = count {
                pairs.push(("count", length_to_json(c)));
            }
            if let Some(b) = bounded {
                pairs.push(("bounded", length_to_json(b)));
            }
            pairs.push(("element", field_to_json(element)));
        }
        FieldDef::Switch {
            name,
            on,
            cases,
            fallback,
        } => {
            pairs.push(("name", Json::string(name)));
            pairs.push(("on", Json::string(on)));
            let cm: BTreeMap<String, Json> = cases
                .iter()
                .map(|(k, c)| (k.clone(), case_to_json(c)))
                .collect();
            pairs.push(("cases", Json::Obj(cm)));
            if let Some(fb) = fallback {
                pairs.push(("fallback", case_to_json(fb)));
            }
        }
        FieldDef::Checksum {
            name,
            width,
            algorithm,
            endian,
            start,
            end,
        } => {
            pairs.push(("name", Json::string(name)));
            pairs.push(("width", Json::from_u64(*width as u64)));
            pairs.push(("algorithm", Json::string(algorithm.as_str())));
            pairs.push(("endian", Json::string(endian.as_str())));
            if let Some(s) = start {
                pairs.push(("start", Json::from_u64(*s)));
            }
            if let Some(e) = end {
                match e {
                    EndRef::StructEnd => pairs.push(("end", Json::string("struct_end"))),
                    EndRef::Field(name) => pairs.push((
                        "end",
                        crate::json::obj(vec![("field", Json::string(name))]),
                    )),
                }
            }
        }
    }
    crate::json::obj(pairs)
}

impl ProtocolSpec {
    pub fn from_json(j: &Json) -> Result<ProtocolSpec, String> {
        let name = jstr(j, "name")?;
        let root = jstr(j, "root")?;
        let max_depth = j.get("max_depth").and_then(|v| v.as_u64()).unwrap_or(16) as u32;
        let mut structs = BTreeMap::new();
        let sm = j
            .get("structs")
            .and_then(|v| v.as_object())
            .ok_or_else(|| "需要 structs 对象".to_string())?;
        for (sname, sval) in sm {
            let arr = sval
                .get("fields")
                .and_then(|v| v.as_array())
                .ok_or_else(|| format!("结构体 {} 需要 fields", sname))?;
            let mut fields = Vec::new();
            for f in arr {
                fields.push(parse_field(f)?);
            }
            structs.insert(sname.clone(), StructDef { fields });
        }
        Ok(ProtocolSpec {
            name,
            root,
            max_depth,
            structs,
        })
    }

    pub fn to_json(&self) -> Json {
        let mut sm = BTreeMap::new();
        for (name, sdef) in &self.structs {
            sm.insert(
                name.clone(),
                crate::json::obj(vec![(
                    "fields",
                    Json::Arr(sdef.fields.iter().map(field_to_json).collect()),
                )]),
            );
        }
        crate::json::obj(vec![
            ("name", Json::string(&self.name)),
            ("root", Json::string(&self.root)),
            ("max_depth", Json::from_u64(self.max_depth as u64)),
            ("structs", Json::Obj(sm)),
        ])
    }

    /// 规范化序列化：字段顺序固定、键排序。
    pub fn canonical(&self) -> String {
        self.to_json().to_string()
    }
}
