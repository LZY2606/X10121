use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

fn default_max_depth() -> usize {
    16
}
fn default_true() -> bool {
    true
}

/// A protocol description document. Versions are immutable: the version id is
/// a content hash of the canonical JSON of this document.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProtocolDoc {
    pub name: String,
    #[serde(default = "default_max_depth")]
    pub max_depth: usize,
    pub root: String,
    pub structs: BTreeMap<String, Vec<Field>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Field {
    pub name: String,
    #[serde(flatten)]
    pub kind: FieldKind,
    #[serde(default)]
    pub when: Option<Condition>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Condition {
    pub field: String,
    pub eq: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "lowercase")]
pub enum Endian {
    #[default]
    Big,
    Little,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum CheckAlgo {
    Sum8,
    Sum16,
    Xor8,
}

/// Boundary of a checksum coverage range, relative to the enclosing struct.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum CheckBound {
    /// "start" | "end" | "self" (self = the checksum field's own start)
    Token(String),
    Field { field: String },
    Offset { offset: usize },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FieldKind {
    Uint {
        size: usize,
        #[serde(default)]
        endian: Endian,
        #[serde(default)]
        expect: Option<u64>,
    },
    Bytes {
        #[serde(default)]
        length: Option<usize>,
        #[serde(default)]
        length_from: Option<String>,
        #[serde(default)]
        extra: i64,
        #[serde(default)]
        until_end: bool,
    },
    Struct {
        #[serde(rename = "struct")]
        struct_name: String,
        #[serde(default)]
        length_from: Option<String>,
    },
    Array {
        #[serde(default)]
        count: Option<usize>,
        #[serde(default)]
        count_from: Option<String>,
        element: Box<Field>,
    },
    Checksum {
        size: usize,
        #[serde(default)]
        endian: Endian,
        algo: CheckAlgo,
        from: CheckBound,
        to: CheckBound,
        #[serde(default = "default_true")]
        skip_self: bool,
    },
}

pub fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

pub fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if cleaned.len() % 2 != 0 {
        return Err("hex string has odd length".to_string());
    }
    let mut out = Vec::with_capacity(cleaned.len() / 2);
    let bytes = cleaned.as_bytes();
    for i in (0..bytes.len()).step_by(2) {
        let hi = (bytes[i] as char).to_digit(16).ok_or("invalid hex digit")?;
        let lo = (bytes[i + 1] as char).to_digit(16).ok_or("invalid hex digit")?;
        out.push(((hi << 4) | lo) as u8);
    }
    Ok(out)
}
