//! 小型 JSON 解析/序列化（零依赖）。对象使用有序 Map，保证规范化输出确定。

use std::collections::BTreeMap;
use std::fmt::Write as _;

#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
    Arr(Vec<Json>),
    Obj(BTreeMap<String, Json>),
}

impl Json {
    pub fn obj() -> Json {
        Json::Obj(BTreeMap::new())
    }

    pub fn str<S: Into<String>>(s: S) -> Json {
        Json::Str(s.into())
    }

    pub fn put<K: Into<String>>(&mut self, k: K, v: Json) {
        if let Json::Obj(m) = self {
            m.insert(k.into(), v);
        } else {
            panic!("Json::put 只能用于对象");
        }
    }

    pub fn with<K: Into<String>>(mut self, k: K, v: Json) -> Json {
        self.put(k, v);
        self
    }

    pub fn get(&self, k: &str) -> Option<&Json> {
        match self {
            Json::Obj(m) => m.get(k),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::Str(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Json::Int(n) => Some(*n),
            Json::Float(f) if f.fract() == 0.0 => Some(*f as i64),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&Vec<Json>> {
        match self {
            Json::Arr(a) => Some(a),
            _ => None,
        }
    }

    pub fn as_object(&self) -> Option<&BTreeMap<String, Json>> {
        match self {
            Json::Obj(m) => Some(m),
            _ => None,
        }
    }

    /// 规范化序列化：键按字典序、无多余空白、整数不使用指数。
    pub fn canonical(&self) -> String {
        let mut out = String::new();
        self.write_canonical(&mut out);
        out
    }

    pub fn pretty(&self) -> String {
        let mut out = String::new();
        self.write_pretty(&mut out, 0);
        out.push('\n');
        out
    }

    fn write_canonical(&self, out: &mut String) {
        match self {
            Json::Null => out.push_str("null"),
            Json::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            Json::Int(n) => {
                let _ = write!(out, "{}", n);
            }
            Json::Float(f) => {
                if f.is_finite() {
                    let _ = write!(out, "{}", f);
                } else {
                    out.push_str("null");
                }
            }
            Json::Str(s) => write_json_string(s, out),
            Json::Arr(a) => {
                out.push('[');
                for (i, v) in a.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    v.write_canonical(out);
                }
                out.push(']');
            }
            Json::Obj(m) => {
                out.push('{');
                for (i, (k, v)) in m.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    write_json_string(k, out);
                    out.push(':');
                    v.write_canonical(out);
                }
                out.push('}');
            }
        }
    }

    fn write_pretty(&self, out: &mut String, indent: usize) {
        let pad = "  ".repeat(indent);
        let pad_in = "  ".repeat(indent + 1);
        match self {
            Json::Arr(a) if a.is_empty() => out.push_str("[]"),
            Json::Obj(m) if m.is_empty() => out.push_str("{}"),
            Json::Arr(a) => {
                out.push_str("[\n");
                for (i, v) in a.iter().enumerate() {
                    out.push_str(&pad_in);
                    v.write_pretty(out, indent + 1);
                    if i + 1 < a.len() {
                        out.push(',');
                    }
                    out.push('\n');
                }
                out.push_str(&pad);
                out.push(']');
            }
            Json::Obj(m) => {
                out.push_str("{\n");
                let n = m.len();
                for (i, (k, v)) in m.iter().enumerate() {
                    out.push_str(&pad_in);
                    write_json_string(k, out);
                    out.push_str(": ");
                    v.write_pretty(out, indent + 1);
                    if i + 1 < n {
                        out.push(',');
                    }
                    out.push('\n');
                }
                out.push_str(&pad);
                out.push('}');
            }
            other => other.write_canonical(out),
        }
    }
}

fn write_json_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
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

pub fn parse(input: &str) -> Result<Json, String> {
    let bytes = input.as_bytes();
    let mut p = Parser {
        bytes,
        pos: 0,
    };
    p.ws();
    let v = p.value()?;
    p.ws();
    if p.pos != bytes.len() {
        return Err(format!("JSON: 第 {} 字节后有多余内容", p.pos));
    }
    Ok(v)
}

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn ws(&mut self) {
        while self.pos < self.bytes.len() {
            match self.bytes[self.pos] {
                b' ' | b'\t' | b'\n' | b'\r' => self.pos += 1,
                _ => break,
            }
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn value(&mut self) -> Result<Json, String> {
        self.ws();
        match self.peek() {
            None => Err("JSON: 意外的输入结尾".to_string()),
            Some(b'{') => self.object(),
            Some(b'[') => self.array(),
            Some(b'"') => Ok(Json::Str(self.string()?)),
            Some(b't') | Some(b'f') => self.boolean(),
            Some(b'n') => self.null(),
            Some(c) if c == b'-' || c.is_ascii_digit() => self.number(),
            Some(c) => Err(format!("JSON: 位置 {} 处出现意外字符 {:?}", self.pos, c as char)),
        }
    }

    fn object(&mut self) -> Result<Json, String> {
        self.pos += 1;
        let mut m = BTreeMap::new();
        self.ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(Json::Obj(m));
        }
        loop {
            self.ws();
            if self.peek() != Some(b'"') {
                return Err(format!("JSON: 对象键必须是字符串（位置 {}）", self.pos));
            }
            let key = self.string()?;
            self.ws();
            if self.peek() != Some(b':') {
                return Err(format!("JSON: 对象键后缺少 ':'（位置 {}）", self.pos));
            }
            self.pos += 1;
            let val = self.value()?;
            m.insert(key, val);
            self.ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                }
                Some(b'}') => {
                    self.pos += 1;
                    break;
                }
                _ => return Err(format!("JSON: 对象中缺少 ',' 或 '}}'（位置 {}）", self.pos)),
            }
        }
        Ok(Json::Obj(m))
    }

    fn array(&mut self) -> Result<Json, String> {
        self.pos += 1;
        let mut a = Vec::new();
        self.ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(Json::Arr(a));
        }
        loop {
            a.push(self.value()?);
            self.ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                }
                Some(b']') => {
                    self.pos += 1;
                    break;
                }
                _ => return Err(format!("JSON: 数组中缺少 ',' 或 ']'（位置 {}）", self.pos)),
            }
        }
        Ok(Json::Arr(a))
    }

    fn string(&mut self) -> Result<String, String> {
        self.pos += 1;
        let mut out = String::new();
        loop {
            if self.pos >= self.bytes.len() {
                return Err("JSON: 字符串未闭合".to_string());
            }
            let c = self.bytes[self.pos];
            self.pos += 1;
            match c {
                b'"' => break,
                b'\\' => {
                    if self.pos >= self.bytes.len() {
                        return Err("JSON: 转义序列被截断".to_string());
                    }
                    let e = self.bytes[self.pos];
                    self.pos += 1;
                    match e {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'n' => out.push('\n'),
                        b't' => out.push('\t'),
                        b'r' => out.push('\r'),
                        b'b' => out.push('\u{08}'),
                        b'f' => out.push('\u{0c}'),
                        b'u' => {
                            let cp = self.hex4()?;
                            if (0xd800..=0xdbff).contains(&cp) {
                                if self.bytes.get(self.pos..self.pos + 2) == Some(&b"\\u"[..]) {
                                    self.pos += 2;
                                    let lo = self.hex4()?;
                                    if (0xdc00..=0xdfff).contains(&lo) {
                                        let c = 0x10000
                                            + (((cp - 0xd800) as u32) << 10)
                                            + (lo - 0xdc00) as u32;
                                        out.push(char::from_u32(c).ok_or("JSON: 非法代理对")?);
                                    } else {
                                        return Err("JSON: 非法的低代理项".to_string());
                                    }
                                } else {
                                    return Err("JSON: 高代理项后缺少低代理项".to_string());
                                }
                            } else if (0xdc00..=0xdfff).contains(&cp) {
                                return Err("JSON: 出现孤立的低代理项".to_string());
                            } else {
                                out.push(char::from_u32(cp as u32).ok_or("JSON: 非法码点")?);
                            }
                        }
                        _ => return Err(format!("JSON: 非法转义 \\{}", e as char)),
                    }
                }
                _ => {
                    if c < 0x80 {
                        out.push(c as char);
                    } else {
                        let start = self.pos - 1;
                        let width = if c >= 0xf0 {
                            4
                        } else if c >= 0xe0 {
                            3
                        } else {
                            2
                        };
                        if self.pos - 1 + width > self.bytes.len() {
                            return Err("JSON: UTF-8 被截断".to_string());
                        }
                        let slice = &self.bytes[start..start + width];
                        let s = std::str::from_utf8(slice).map_err(|_| "JSON: 非法 UTF-8")?;
                        out.push_str(s);
                        self.pos = start + width;
                    }
                }
            }
        }
        Ok(out)
    }

    fn hex4(&mut self) -> Result<u16, String> {
        if self.pos + 4 > self.bytes.len() {
            return Err("JSON: \\u 转义被截断".to_string());
        }
        let mut n = 0u16;
        for _ in 0..4 {
            let c = self.bytes[self.pos];
            let d = match c {
                b'0'..=b'9' => c - b'0',
                b'a'..=b'f' => c - b'a' + 10,
                b'A'..=b'F' => c - b'A' + 10,
                _ => return Err(format!("JSON: \\u 后非法十六进制字符 {:?}", c as char)),
            };
            n = n * 16 + d as u16;
            self.pos += 1;
        }
        Ok(n)
    }

    fn number(&mut self) -> Result<Json, String> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        let mut is_float = false;
        while self.pos < self.bytes.len() {
            match self.bytes[self.pos] {
                b'0'..=b'9' => self.pos += 1,
                b'.' | b'e' | b'E' | b'+' | b'-' => {
                    is_float = true;
                    self.pos += 1;
                }
                _ => break,
            }
        }
        let s = std::str::from_utf8(&self.bytes[start..self.pos]).map_err(|_| "JSON: 非法数字")?;
        if is_float {
            s.parse::<f64>()
                .map(Json::Float)
                .map_err(|_| format!("JSON: 无法解析数字 {}", s))
        } else {
            s.parse::<i64>()
                .map(Json::Int)
                .map_err(|_| format!("JSON: 无法解析整数 {}", s))
        }
    }

    fn boolean(&mut self) -> Result<Json, String> {
        if self.bytes[self.pos..].starts_with(b"true") {
            self.pos += 4;
            Ok(Json::Bool(true))
        } else if self.bytes[self.pos..].starts_with(b"false") {
            self.pos += 5;
            Ok(Json::Bool(false))
        } else {
            Err(format!("JSON: 位置 {} 处非法字面量", self.pos))
        }
    }

    fn null(&mut self) -> Result<Json, String> {
        if self.bytes[self.pos..].starts_with(b"null") {
            self.pos += 4;
            Ok(Json::Null)
        } else {
            Err(format!("JSON: 位置 {} 处非法字面量", self.pos))
        }
    }
}
