use crate::error::{LabError, LabResult};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
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
                    v = (v << 8) | *b as u64;
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

    pub fn write_u64(&self, value: u64, width: usize) -> Vec<u8> {
        let mut out = vec![0u8; width];
        match self {
            Endian::Big => {
                for i in 0..width {
                    out[width - 1 - i] = ((value >> (8 * i)) & 0xff) as u8;
                }
            }
            Endian::Little => {
                for i in 0..width {
                    out[i] = ((value >> (8 * i)) & 0xff) as u8;
                }
            }
        }
        out
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CondOp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct When {
    /// 同结构体内的字段名（先于当前字段出现），或 "field.sub" 形式的路径。
    pub field: String,
    pub op: CondOp,
    /// 与字段值比较的常量；整数字段按数字比较，字节字段按十六进制字符串比较。
    pub value: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum LengthOf {
    /// 长度来自同结构体中先出现的整数字段。
    Field {
        field: String,
        /// 解析后回填时的算术调整：实际长度 = 字段值 + adjust。
        #[serde(default)]
        adjust: i64,
    },
    Fixed {
        len: usize,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChecksumAlgo {
    Sum8,
    Sum16Be,
    Xor8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Error,
    Warning,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Field {
    Int {
        name: String,
        width: usize,
        #[serde(default = "default_endian")]
        endian: Endian,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        expect: Option<serde_json::Value>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        when: Vec<When>,
    },
    Bytes {
        name: String,
        len: LengthOf,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        when: Vec<When>,
    },
    Payload {
        name: String,
        len: LengthOf,
        /// 有界负载内部按该结构体继续解析；为 None 时作为不透明字节。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        struct_ref: Option<String>,
    },
    Struct {
        name: String,
        struct_ref: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        when: Vec<When>,
    },
    Ref {
        name: String,
        struct_ref: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        when: Vec<When>,
    },
    Checksum {
        name: String,
        width: usize,
        algo: ChecksumAlgo,
        /// 覆盖的同结构体字段名；为空时覆盖整个父结构。
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        covers: Vec<String>,
        /// 是否从覆盖区间中跳过校验和自身字节。
        #[serde(default = "default_true")]
        skip_self: bool,
        #[serde(default = "default_warning")]
        mismatch: Severity,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        when: Vec<When>,
    },
}

fn default_endian() -> Endian {
    Endian::Big
}

fn default_true() -> bool {
    true
}

fn default_warning() -> Severity {
    Severity::Warning
}

impl Field {
    pub fn name(&self) -> &str {
        match self {
            Field::Int { name, .. }
            | Field::Bytes { name, .. }
            | Field::Payload { name, .. }
            | Field::Struct { name, .. }
            | Field::Ref { name, .. }
            | Field::Checksum { name, .. } => name,
        }
    }

    pub fn when(&self) -> &[When] {
        match self {
            Field::Int { when, .. }
            | Field::Bytes { when, .. }
            | Field::Struct { when, .. }
            | Field::Ref { when, .. }
            | Field::Checksum { when, .. } => when,
            Field::Payload { .. } => &[],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Protocol {
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub root: String,
    /// 递归（payload 有界展开 / 结构体引用）的最大深度，根结构深度为 0。
    #[serde(default = "default_max_depth")]
    pub max_depth: usize,
    #[serde(default)]
    pub structs: BTreeMap<String, Vec<Field>>,
}

fn default_max_depth() -> usize {
    8
}

impl Protocol {
    /// 校验协议描述：名称、宽度、引用与长度字段依赖必须合法。
    pub fn validate(&self) -> LabResult<()> {
        if self.name.trim().is_empty() {
            return Err(LabError::new("协议名称不能为空"));
        }
        if self.max_depth == 0 {
            return Err(LabError::new("max_depth 必须 >= 1"));
        }
        if !self.structs.contains_key(&self.root) {
            return Err(LabError::new(format!(
                "根结构 '{}' 不存在",
                self.root
            )));
        }
        if self.structs.is_empty() {
            return Err(LabError::new("协议至少要声明一个结构"));
        }
        for (sname, fields) in &self.structs {
            let mut seen = std::collections::BTreeSet::new();
            if fields.is_empty() {
                return Err(LabError::new(format!("结构 '{sname}' 不能为空")));
            }
            for f in fields {
                let fname = f.name();
                if fname.trim().is_empty() {
                    return Err(LabError::new(format!("结构 '{sname}' 存在空字段名")));
                }
                if !seen.insert(fname.to_string()) {
                    return Err(LabError::new(format!(
                        "结构 '{sname}' 中字段 '{fname}' 重名"
                    )));
                }
                self.validate_field(sname, f, fields)?;
            }
        }
        Ok(())
    }

    fn validate_field(
        &self,
        sname: &str,
        field: &Field,
        siblings: &[Field],
    ) -> LabResult<()> {
        let names: std::collections::BTreeSet<&str> =
            siblings.iter().map(|f| f.name()).collect();
        let earlier = |target: &str| -> LabResult<()> {
            if names.contains(target) {
                Ok(())
            } else {
                Err(LabError::new(format!(
                    "结构 '{sname}' 的字段 '{}' 引用了不存在的字段 '{target}'",
                    field.name()
                )))
            }
        };
        match field {
            Field::Int {
                width,
                expect,
                when,
                ..
            } => {
                if !(1..=8).contains(width) {
                    return Err(LabError::new(format!(
                        "字段 '{}.{}' 的 width 必须在 1..=8",
                        sname,
                        field.name()
                    )));
                }
                if let Some(v) = expect {
                    json_as_u64(v).ok_or_else(|| {
                        LabError::new(format!(
                            "字段 '{}.{}' 的 expect 必须是非负整数",
                            sname,
                            field.name()
                        ))
                    })?;
                }
                for w in when {
                    earlier(&w.field)?;
                }
            }
            Field::Bytes { len, when, .. } => {
                check_len(self, sname, field.name(), len, siblings)?;
                for w in when {
                    earlier(&w.field)?;
                }
            }
            Field::Payload {
                len,
                struct_ref,
                name: _,
            } => {
                check_len(self, sname, field.name(), len, siblings)?;
                if let Some(r) = struct_ref {
                    if !self.structs.contains_key(r) {
                        return Err(LabError::new(format!(
                            "payload '{}.{}' 引用了不存在的结构 '{r}'",
                            sname,
                            field.name()
                        )));
                    }
                }
            }
            Field::Struct {
                struct_ref, when, ..
            }
            | Field::Ref {
                struct_ref, when, ..
            } => {
                if !self.structs.contains_key(struct_ref) {
                    return Err(LabError::new(format!(
                        "字段 '{}.{}' 引用了不存在的结构 '{struct_ref}'",
                        sname,
                        field.name()
                    )));
                }
                for w in when {
                    earlier(&w.field)?;
                }
            }
            Field::Checksum {
                width,
                algo,
                covers,
                when,
                ..
            } => {
                let ok = match (width, algo) {
                    (1, ChecksumAlgo::Sum8)
                    | (1, ChecksumAlgo::Xor8)
                    | (2, ChecksumAlgo::Sum16Be) => true,
                    _ => false,
                };
                if !ok {
                    return Err(LabError::new(format!(
                        "校验和 '{}.{}' 的 width/algo 组合不支持",
                        sname,
                        field.name()
                    )));
                }
                for c in covers {
                    earlier(c)?;
                }
                for w in when {
                    earlier(&w.field)?;
                }
            }
        }
        Ok(())
    }
}

fn check_len(
    protocol: &Protocol,
    sname: &str,
    fname: &str,
    len: &LengthOf,
    siblings: &[Field],
) -> LabResult<()> {
    if let LengthOf::Field { field, .. } = len {
        let target = siblings
            .iter()
            .find(|f| f.name() == field)
            .ok_or_else(|| {
                LabError::new(format!(
                    "字段 '{sname}.{fname}' 的长度字段 '{field}' 不存在"
                ))
            })?;
        match target {
            Field::Int { .. } => {}
            _ => {
                return Err(LabError::new(format!(
                    "字段 '{sname}.{fname}' 的长度字段 '{field}' 必须是整数类型"
                )));
            }
        }
        let _ = protocol;
    }
    Ok(())
}

pub fn json_as_u64(v: &serde_json::Value) -> Option<u64> {
    v.as_u64()
        .or_else(|| v.as_i64().and_then(|n| u64::try_from(n).ok()))
}

/// 规范化序列化：键名排序，消除空白，保证同一语义协议哈希稳定。
pub fn canonical_bytes(protocol: &Protocol) -> LabResult<Vec<u8>> {
    let value = serde_json::to_value(protocol)?;
    let canonical = canonicalize_value(value);
    Ok(canonical.to_string().into_bytes())
}

fn canonicalize_value(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let sorted: BTreeMap<String, serde_json::Value> =
                map.into_iter().map(|(k, v)| (k, canonicalize_value(v))).collect();
            serde_json::Value::Object(sorted.into_iter().collect())
        }
        serde_json::Value::Array(items) => {
            serde_json::Value::Array(items.into_iter().map(canonicalize_value).collect())
        }
        other => other,
    }
}
