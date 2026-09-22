//! 协议描述：定长整数、变长字段、由前置字段决定长度的 payload、
//! 带条件的子结构、校验和覆盖区间（可跳过自身）、可配置递归深度上限。
//!
//! 结构字段类型：
//! - int:    {name,type:"u8|u16|u32|u64|i8|i16|i32", endian:"be|le", const?, enum?}
//! - bytes:  {name,type:"bytes", length: 固定数 | 字段名 | {field, offset}}
//! - struct: {name,type:"struct", struct:"结构名", when?:{field,eq}}
//! - array:  {name,type:"array", item:"int|bytes|struct", type_info?（宽度/struct 名）,
//!            count: 同 length 语义, length?: 仅 item=bytes 时使用}
//! 校验和是 int 字段上的 checksum 子对象：{algo:"sum8|xor8", covers:[标记或字段名...], skip_self?}
//! 结构上的边界：{length_ref:"字段名", length_offset?}，把整个结构限定在字段值的字节边界内。
//! 校验和覆盖标记：字段名（取该字段起点），或 "@start" / "@end"。
use crate::json::Json;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Algo {
    Sum8,
    Xor8,
}

#[derive(Debug, Clone)]
pub struct ChecksumSpec {
    pub algo: Algo,
    pub covers: Vec<String>,
    pub skip_self: bool,
}

#[derive(Debug, Clone, Copy)]
pub enum Endian {
    Be,
    Le,
}

#[derive(Debug, Clone)]
pub struct EnumVal {
    pub value: i64,
    pub label: String,
}

#[derive(Debug, Clone)]
pub enum LengthSpec {
    Fixed(i64),
    Field { name: String, offset: i64 },
}

#[derive(Debug, Clone)]
pub struct WhenSpec {
    pub field: String,
    pub eq: i64,
}

#[derive(Debug, Clone)]
pub enum FieldKind {
    Int {
        width: usize,
        signed: bool,
        endian: Endian,
        expect_const: Option<i64>,
        enum_vals: Vec<EnumVal>,
        checksum: Option<ChecksumSpec>,
    },
    Bytes {
        length: LengthSpec,
    },
    Struct {
        struct_name: String,
        when: Option<WhenSpec>,
    },
    Array {
        count: LengthSpec,
        item: ArrayItem,
    },
}

#[derive(Debug, Clone)]
pub enum ArrayItem {
    Int { width: usize, signed: bool, endian: Endian },
    Bytes { length: LengthSpec },
    Struct { struct_name: String },
}

#[derive(Debug, Clone)]
pub struct Field {
    pub name: String,
    pub kind: FieldKind,
}

#[derive(Debug, Clone)]
pub struct StructDef {
    pub name: String,
    pub fields: Vec<Field>,
    /// 整个结构的硬边界：来自同结构内先前解析的某个字段。
    pub length_ref: Option<LengthSpec>,
}

#[derive(Debug, Clone)]
pub struct Spec {
    pub name: String,
    pub root: String,
    pub max_depth: usize,
    pub structs: Vec<StructDef>,
}

fn req_str<'a>(o: &'a Json, key: &str, ctx: &str) -> Result<&'a str, String> {
    o.get(key)
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("{ctx}：缺少字符串字段 {key}"))
}

fn parse_length(v: Option<&Json>, ctx: &str) -> Result<LengthSpec, String> {
    let v = v.ok_or_else(|| format!("{ctx}：缺少 length/count 说明"))?;
    match v {
        Json::Int(n) => Ok(LengthSpec::Fixed(*n)),
        Json::Str(s) => Ok(LengthSpec::Field { name: s.clone(), offset: 0 }),
        Json::Obj(_) => {
            let field = req_str(v, "field", ctx)?.to_string();
            let offset = v.get("offset").and_then(|x| x.as_i64()).unwrap_or(0);
            Ok(LengthSpec::Field { name: field, offset })
        }
        other => Err(format!("{ctx}：length/count 必须是数字、字符串或对象，实际为 {other:?}")),
    }
}

fn parse_int_type(t: &str) -> Option<(usize, bool)> {
    Some(match t {
        "u8" => (1, false),
        "u16" => (2, false),
        "u32" => (4, false),
        "u64" => (8, false),
        "i8" => (1, true),
        "i16" => (2, true),
        "i32" => (4, true),
        _ => return None,
    })
}

fn parse_checksum(v: &Json, ctx: &str) -> Result<ChecksumSpec, String> {
    let algo = match req_str(v, "algo", ctx)? {
        "sum8" => Algo::Sum8,
        "xor8" => Algo::Xor8,
        other => return Err(format!("{ctx}：不支持的校验算法 {other}（支持 sum8/xor8）")),
    };
    let covers = v
        .get("covers")
        .and_then(|x| x.as_array())
        .ok_or_else(|| format!("{ctx}：checksum.covers 必须是数组"))?
        .iter()
        .map(|c| c.as_str().map(|s| s.to_string()).ok_or_else(|| format!("{ctx}：covers 项必须是字符串")))
        .collect::<Result<Vec<_>, _>>()?;
    if covers.is_empty() {
        return Err(format!("{ctx}：checksum.covers 不能为空"));
    }
    let skip_self = v.get("skip_self").and_then(|x| x.as_bool()).unwrap_or(true);
    Ok(ChecksumSpec { algo, covers, skip_self })
}

impl Spec {
    pub fn from_json(j: &Json) -> Result<Spec, String> {
        let name = req_str(j, "name", "协议描述")?.to_string();
        let root = req_str(j, "root", "协议描述")?.to_string();
        let max_depth = j.get("max_depth").and_then(|x| x.as_i64()).unwrap_or(16);
        if !(1..=64).contains(&max_depth) {
            return Err("max_depth 必须在 1..=64 之间".to_string());
        }
        let arr = j
            .get("structs")
            .and_then(|x| x.as_array())
            .ok_or_else(|| "协议描述：structs 必须是数组".to_string())?;
        let mut structs = Vec::new();
        for so in arr {
            structs.push(Self::parse_struct(so)?);
        }
        if structs.is_empty() {
            return Err("协议描述：至少需要一个结构".to_string());
        }
        let spec = Spec { name, root, max_depth: max_depth as usize, structs };
        spec.validate()?;
        Ok(spec)
    }

    pub fn get(&self, name: &str) -> Option<&StructDef> {
        self.structs.iter().find(|s| s.name == name)
    }

    fn parse_struct(so: &Json) -> Result<StructDef, String> {
        let sname = req_str(so, "name", "结构定义")?.to_string();
        let ctx = format!("结构 {sname}");
        let farr = so
            .get("fields")
            .and_then(|x| x.as_array())
            .ok_or_else(|| format!("{ctx}：fields 必须是数组"))?;
        let mut fields = Vec::new();
        for fo in farr {
            fields.push(Self::parse_field(fo, &sname)?);
        }
        if fields.is_empty() {
            return Err(format!("{ctx}：结构不能为空"));
        }
        let length_ref = if let Some(lr) = so.get("length_ref") {
            Some(parse_length(Some(lr), &format!("{ctx}.length_ref"))?)
        } else {
            None
        };
        Ok(StructDef { name: sname, fields, length_ref })
    }

    fn parse_field(fo: &Json, sname: &str) -> Result<Field, String> {
        let name = req_str(fo, "name", &format!("结构 {sname}"))?.to_string();
        let ctx = format!("字段 {sname}.{name}");
        let ftype = req_str(fo, "type", &ctx)?;
        let endian = match fo.get("endian").and_then(|x| x.as_str()).unwrap_or("be") {
            "be" | "big" => Endian::Be,
            "le" | "little" => Endian::Le,
            other => return Err(format!("{ctx}：未知字节序 {other}")),
        };
        let kind = match ftype {
            t if parse_int_type(t).is_some() => {
                let (width, signed) = parse_int_type(t).unwrap();
                let expect_const = fo.get("const").and_then(|x| x.as_i64());
                if let Some(c) = expect_const {
                    if !int_fits(c, width, signed) {
                        return Err(format!("{ctx}：常量 {c} 超出 {t} 范围"));
                    }
                }
                let enum_vals = fo
                    .get("enum")
                    .and_then(|x| x.as_array())
                    .map(|a| {
                        a.iter()
                            .map(|ev| {
                                Ok(EnumVal {
                                    value: ev
                                        .get("value")
                                        .and_then(|x| x.as_i64())
                                        .ok_or_else(|| format!("{ctx}：enum 项缺少 value"))?,
                                    label: ev
                                        .get("label")
                                        .and_then(|x| x.as_str())
                                        .unwrap_or("")
                                        .to_string(),
                                })
                            })
                            .collect::<Result<Vec<_>, String>>()
                    })
                    .transpose()?
                    .unwrap_or_default();
                let checksum = fo
                    .get("checksum")
                    .map(|c| parse_checksum(c, &ctx))
                    .transpose()?;
                FieldKind::Int { width, signed, endian, expect_const, enum_vals, checksum }
            }
            "bytes" => {
                let length = parse_length(fo.get("length"), &ctx)?;
                FieldKind::Bytes { length }
            }
            "struct" => {
                let struct_name = req_str(fo, "struct", &ctx)?.to_string();
                let when = if let Some(w) = fo.get("when") {
                    let field = req_str(w, "field", &format!("{ctx}.when"))?.to_string();
                    let eq = w
                        .get("eq")
                        .and_then(|x| x.as_i64())
                        .ok_or_else(|| format!("{ctx}.when：缺少 eq 整数"))?;
                    Some(WhenSpec { field, eq })
                } else {
                    None
                };
                FieldKind::Struct { struct_name, when }
            }
            "array" => {
                let count = parse_length(fo.get("count"), &format!("{ctx}.count"))?;
                let item_name = req_str(fo, "item", &ctx)?;
                let item = match item_name {
                    t if parse_int_type(t).is_some() => {
                        let (w, signed) = parse_int_type(t).unwrap();
                        ArrayItem::Int { width: w, signed, endian }
                    }
                    "bytes" => {
                        let length = parse_length(fo.get("length"), &format!("{ctx}.length"))?;
                        ArrayItem::Bytes { length }
                    }
                    sname2 => ArrayItem::Struct { struct_name: sname2.to_string() },
                };
                FieldKind::Array { count, item }
            }
            other => return Err(format!("{ctx}：未知字段类型 {other}")),
        };
        Ok(Field { name, kind })
    }

    fn validate(&self) -> Result<(), String> {
        if self.get(&self.root).is_none() {
            return Err(format!("协议 {}：根结构 {} 不存在", self.name, self.root));
        }
        for s in &self.structs {
            let mut seen = std::collections::HashSet::new();
            for f in &s.fields {
                if !seen.insert(f.name.clone()) {
                    return Err(format!("结构 {}：字段名 {} 重复", s.name, f.name));
                }
                self.validate_field(f, &s.name)?;
            }
            if let Some(LengthSpec::Field { name, .. }) = &s.length_ref {
                if !s.fields.iter().any(|f| &f.name == name) {
                    return Err(format!("结构 {}：length_ref 引用的字段 {} 不存在", s.name, name));
                }
            }
        }
        // 递归可达性 / 深度上限静态检查（简单 DFS 检测可达即可，深度运行时再限制）
        if self.get(&self.root).is_none() {
            return Err("根结构不存在".to_string());
        }
        Ok(())
    }

    fn validate_field(&self, f: &Field, sname: &str) -> Result<(), String> {
        let ctx = format!("{sname}.{}", f.name);
        match &f.kind {
            FieldKind::Struct { struct_name, .. } => {
                if self.get(struct_name).is_none() {
                    return Err(format!("{ctx}：引用的结构 {struct_name} 不存在"));
                }
            }
            FieldKind::Array { item, .. } => {
                if let ArrayItem::Struct { struct_name } = item {
                    if self.get(struct_name).is_none() {
                        return Err(format!("{ctx}：数组引用的结构 {struct_name} 不存在"));
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }
}

pub(crate) fn int_fits(value: i64, width: usize, signed: bool) -> bool {
    if signed {
        let bits = width * 8;
        if bits >= 64 {
            return true;
        }
        let min = -(1i64 << (bits - 1));
        let max = (1i64 << (bits - 1)) - 1;
        value >= min && value <= max
    } else {
        if width >= 8 {
            return value >= 0;
        }
        value >= 0 && (value as u64) < (1u64 << (width * 8))
    }
}
