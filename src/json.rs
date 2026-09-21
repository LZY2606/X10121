//! 零依赖 JSON：Json 枚举、位置感知解析器、确定性序列化。

use std::collections::BTreeMap;
use std::fmt::Write as _;

#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    /// 词法上读出来的整数（无小数/指数）。
    Int(i64),
    Float(f64),
    Str(String),
    Array(Vec<Json>),
    /// BTreeMap 保证键有序，便于做确定性摘要。
    Object(BTreeMap<String, Json>),
}

#[derive(Debug)]
pub struct JsonError {
    pub message: String,
    pub pos: usize,
}

impl std::fmt::Display for JsonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "JSON 错误（字节 {}）：{}", self.pos, self.message)
    }
}

fn write_json_string(out: &mut String, s: &str) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn write_json_float(out: &mut String, f: f64) {
    if f.is_nan() || f.is_infinite() {
        out.push_str("null");
    } else if f.fract() == 0.0 && f.abs() < 1e16 {
        let _ = write!(out, "{:.1}", f);
    } else {
        let _ = write!(out, "{f}");
    }
}

pub fn parse(input: &str) -> JsonResult<Json> {
    let bytes = input.as_bytes();
    let mut p = Parser {
        bytes,
        pos: 0,
    };
    p.skip_ws();
    let value = p.parse_value()?;
    p.skip_ws();
    if p.pos != bytes.len() {
        return Err(p.err("值之后仍有多余字符"));
    }
    Ok(value)
}

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn err(&self, message: &str) -> JsonError {
        JsonError {
            message: message.to_string(),
            pos: self.pos,
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn bump(&mut self) -> Option<u8> {
        let b = self.peek()?;
        self.pos += 1;
        Some(b)
    }

    fn expect(&mut self, b: u8, what: &str) -> JsonResult<()> {
        if self.peek() == Some(b) {
            self.pos += 1;
            Ok(())
        } else {
            Err(self.err(&format!("缺少 {what}")))
        }
    }

    fn skip_ws(&mut self) {
        while let Some(b) = self.peek() {
            if matches!(b, b' ' | b'\t' | b'\n' | b'\r') {
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    fn parse_value(&mut self) -> JsonResult<Json> {
        self.skip_ws();
        match self.peek() {
            None => Err(self.err("意外结束，期望一个 JSON 值")),
            Some(b'{') => self.parse_object(),
            Some(b'[') => self.parse_array(),
            Some(b'"') => Ok(Json::Str(self.parse_string()?)),
            Some(b't') | Some(b'f') => self.parse_bool(),
            Some(b'n') => self.parse_null(),
            Some(b) if b == b'-' || b.is_ascii_digit() => self.parse_number(),
            Some(_) => Err(self.err("无法识别的 JSON 值")),
        }
    }

    fn parse_object(&mut self) -> JsonResult<Json> {
        self.bump();
        let mut map = BTreeMap::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.bump();
            return Ok(Json::Object(map));
        }
        loop {
            self.skip_ws();
            if self.peek() != Some(b'"') {
                return Err(self.err("对象键必须是字符串"));
            }
            let key = self.parse_string()?;
            self.skip_ws();
            self.expect(b':', "冒号")?;
            let value = self.parse_value()?;
            map.insert(key, value);
            self.skip_ws();
            match self.bump() {
                Some(b',') => continue,
                Some(b'}') => break,
                _ => return Err(self.err("对象里缺少逗号或右花括号")),
            }
        }
        Ok(Json::Object(map))
    }

    fn parse_array(&mut self) -> JsonResult<Json> {
        self.bump();
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.bump();
            return Ok(Json::Array(items));
        }
        loop {
            items.push(self.parse_value()?);
            self.skip_ws();
            match self.bump() {
                Some(b',') => continue,
                Some(b']') => break,
                _ => return Err(self.err("数组里缺少逗号或右方括号")),
            }
        }
        Ok(Json::Array(items))
    }

    fn parse_bool(&mut self) -> JsonResult<Json> {
        if self.bytes[self.pos..].starts_with(b"true") {
            self.pos += 4;
            Ok(Json::Bool(true))
        } else if self.bytes[self.pos..].starts_with(b"false") {
            self.pos += 5;
            Ok(Json::Bool(false))
        } else {
            Err(self.err("非法的布尔字面量"))
        }
    }

    fn parse_null(&mut self) -> JsonResult<Json> {
        if self.bytes[self.pos..].starts_with(b"null") {
            self.pos += 4;
            Ok(Json::Null)
        } else {
            Err(self.err("非法的 null 字面量"))
        }
    }

    fn parse_number(&mut self) -> JsonResult<Json> {
        let start = self.pos;
        let mut is_float = false;
        if self.peek() == Some(b'-') {
            self.bump();
        }
        while let Some(b) = self.peek() {
            match b {
                b'0'..=b'9' => {
                    self.bump();
                }
                b'.' | b'e' | b'E' | b'+' | b'-' => {
                    is_float = true;
                    self.bump();
                }
                _ => break,
            }
        }
        let text = std::str::from_utf8(&self.bytes[start..self.pos])
            .map_err(|_| self.err("数字不是合法 UTF-8"))?;
        if is_float {
            text.parse::<f64>()
                .map(Json::Float)
                .map_err(|_| self.err("非法数字"))
        } else {
            text.parse::<i64>()
                .map(Json::Int)
                .map_err(|_| self.err("整数超出 i64 范围"))
        }
    }

    fn parse_string(&mut self) -> JsonResult<String> {
        self.expect(b'"', "字符串起始引号")?;
        let mut out = String::new();
        loop {
            match self.bump() {
                None => return Err(self.err("字符串未闭合")),
                Some(b'"') => break,
                Some(b'\\') => {
                    let esc = self.bump().ok_or_else(|| self.err("转义未结束"))?;
                    match esc {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'b' => out.push('\u{08}'),
                        b'f' => out.push('\u{0c}'),
                        b'u' => {
                            let cp1 = self.parse_hex4()?;
                            let cp = if (0xD800..=0xDBFF).contains(&cp1) {
                                if self.bump() != Some(b'\\') || self.bump() != Some(b'u') {
                                    return Err(self.err("高代理项后缺少低代理项"));
                                }
                                let cp2 = self.parse_hex4()?;
                                if !(0xDC00..=0xDFFF).contains(&cp2) {
                                    return Err(self.err("非法的 UTF-16 低代理项"));
                                }
                                0x10000 + ((cp1 - 0xD800) << 10) + (cp2 - 0xDC00)
                            } else {
                                cp1
                            };
                            if let Some(ch) = char::from_u32(cp) {
                                out.push(ch);
                            } else {
                                return Err(self.err("非法的 Unicode 码点"));
                            }
                        }
                        _ => return Err(self.err("非法的字符串转义")),
                    }
                }
                Some(b) => {
                    if b < 0x80 {
                        out.push(b as char);
                    } else {
                        let begin = self.pos - 1;
                        while self.peek().is_some_and(|x| x >= 0x80) && self.peek() != Some(b'"') {
                            self.bump();
                        }
                        let chunk = std::str::from_utf8(&self.bytes[begin..self.pos])
                            .map_err(|_| self.err("非法 UTF-8 字节"))?;
                        out.push_str(chunk);
                    }
                }
            }
        }
        Ok(out)
    }

    fn parse_hex4(&mut self) -> JsonResult<u32> {
        let mut value = 0u32;
        for _ in 0..4 {
            let b = self.bump().ok_or_else(|| self.err("\\u 后需要 4 位十六进制"))?;
            let digit = match b {
                b'0'..=b'9' => (b - b'0') as u32,
                b'a'..=b'f' => (b - b'a' + 10) as u32,
                b'A'..=b'F' => (b - b'A' + 10) as u32,
                _ => return Err(self.err("非法十六进制位")),
            };
            value = value * 16 + digit;
        }
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_is_canonical() {
        let parsed = parse(r#"{"b":1,"a":[true,false,null,"x",3.0,-2]}"#).unwrap();
        assert_eq!(
            parsed.stringify(),
            r#"{"a":[true,false,null,"x",3.0,-2],"b":1}"#
        );
    }

    #[test]
    fn position_tracks_error() {
        let err = parse(r#"{"a": }"#).unwrap_err();
        assert!(err.pos >= 5);
    }

    #[test]
    fn unicode_surrogate_pair() {
        let parsed = parse(r#""\uD83D\uDE00""#).unwrap();
        assert_eq!(parsed.as_str(), Some("😀"));
    }
}

impl std::error::Error for JsonError {}

pub type JsonResult<T> = Result<T, JsonError>;

impl Json {
    pub fn obj() -> Self {
        Json::Object(BTreeMap::new())
    }

    pub fn from_str_value(s: impl Into<String>) -> Self {
        Json::Str(s.into())
    }

    pub fn is_null(&self) -> bool {
        matches!(self, Json::Null)
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Json::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Json::Int(n) => Some(*n),
            Json::Float(f) if f.fract() == 0.0 && f.is_finite() => Some(*f as i64),
            _ => None,
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        self.as_i64().and_then(|n| u64::try_from(n).ok())
    }

    pub fn as_usize(&self) -> Option<usize> {
        self.as_i64().and_then(|n| usize::try_from(n).ok())
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::Str(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&Vec<Json>> {
        match self {
            Json::Array(a) => Some(a),
            _ => None,
        }
    }

    pub fn as_object(&self) -> Option<&BTreeMap<String, Json>> {
        match self {
            Json::Object(o) => Some(o),
            _ => None,
        }
    }

    pub fn get(&self, key: &str) -> Option<&Json> {
        self.as_object().and_then(|o| o.get(key))
    }

    pub fn insert(&mut self, key: impl Into<String>, value: Json) {
        if let Json::Object(o) = self {
            o.insert(key.into(), value);
        } else {
            panic!("Json::insert 只能用于 Object");
        }
    }

    pub fn push(&mut self, value: Json) {
        if let Json::Array(a) = self {
            a.push(value);
        } else {
            panic!("Json::push 只能用于 Array");
        }
    }

    pub fn stringify(&self) -> String {
        let mut out = String::new();
        self.write(&mut out, "", "");
        out
    }

    pub fn stringify_pretty(&self) -> String {
        let mut out = String::new();
        self.write(&mut out, "", "  ");
        out
    }

    fn write(&self, out: &mut String, indent: &str, step: &str) {
        match self {
            Json::Null => out.push_str("null"),
            Json::Bool(true) => out.push_str("true"),
            Json::Bool(false) => out.push_str("false"),
            Json::Int(n) => {
                let _ = write!(out, "{n}");
            }
            Json::Float(f) => write_json_float(out, *f),
            Json::Str(s) => write_json_string(out, s),
            Json::Array(items) => {
                if items.is_empty() {
                    out.push_str("[]");
                } else if step.is_empty() {
                    out.push('[');
                    for (i, item) in items.iter().enumerate() {
                        if i > 0 {
                            out.push(',');
                        }
                        item.write(out, "", step);
                    }
                    out.push(']');
                } else {
                    let child = format!("{indent}{step}");
                    out.push_str("[\n");
                    for (i, item) in items.iter().enumerate() {
                        out.push_str(&child);
                        item.write(out, &child, step);
                        if i + 1 < items.len() {
                            out.push(',');
                        }
                        out.push('\n');
                    }
                    out.push_str(indent);
                    out.push(']');
                }
            }
            Json::Object(map) => {
                if map.is_empty() {
                    out.push_str("{}");
                } else if step.is_empty() {
                    out.push('{');
                    for (i, (key, value)) in map.iter().enumerate() {
                        if i > 0 {
                            out.push(',');
                        }
                        write_json_string(out, key);
                        out.push(':');
                        value.write(out, "", step);
                    }
                    out.push('}');
                } else {
                    let child = format!("{indent}{step}");
                    out.push_str("{\n");
                    for (i, (key, value)) in map.iter().enumerate() {
                        out.push_str(&child);
                        write_json_string(out, key);
                        out.push_str(": ");
                        value.write(out, &child, step);
                        if i + 1 < map.len() {
                            out.push(',');
                        }
                        out.push('\n');
                    }
                    out.push_str(indent);
                    out.push('}');
                }
            }
        }
    }
}
