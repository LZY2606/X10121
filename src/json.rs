//! 极简 JSON：解析、DOM、确定性序列化。仅支持本项目所需子集。

use std::collections::BTreeMap;

#[derive(Clone, Debug)]
pub enum Json {
    Null,
    Bool(bool),
    /// 规范数字（按 i64/u64/f64 均可还原）。
    Num(f64),
    Str(String),
    Arr(Vec<Json>),
    /// BTreeMap 保证键序确定。
    Obj(BTreeMap<String, Json>),
}

impl Json {
    pub fn parse(s: &str) -> Result<Json, String> {
        let bytes = s.as_bytes();
        let mut i = 0;
        let p = Parser::new(bytes);
        let v = p.parse_value(&mut i)?;
        p.skip_ws(&mut i);
        if i != bytes.len() {
            return Err(format!("第 {} 字节后有多余内容", i));
        }
        Ok(v)
    }

    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Obj(m) => m.get(key),
            _ => None,
        }
    }
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::Str(s) => Some(s),
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
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Json::Num(n) if n.fract() == 0.0 => Some(*n as i64),
            _ => None,
        }
    }
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Json::Num(n) if *n >= 0.0 && n.fract() == 0.0 => Some(*n as u64),
            _ => None,
        }
    }
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Json::Bool(b) => Some(*b),
            _ => None,
        }
    }
    pub fn from_i64(v: i64) -> Json {
        Json::Num(v as f64)
    }
    pub fn from_u64(v: u64) -> Json {
        Json::Num(v as f64)
    }
    pub fn string(s: impl Into<String>) -> Json {
        Json::Str(s.into())
    }

    /// 确定性序列化（键排序）。
    pub fn to_string(&self) -> String {
        let mut out = String::new();
        self.write(&mut out);
        out
    }
    pub fn to_string_pretty(&self) -> String {
        let mut out = String::new();
        self.write_pretty(&mut out, 0);
        out.push('\n');
        out
    }

    fn write(&self, out: &mut String) {
        match self {
            Json::Null => out.push_str("null"),
            Json::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            Json::Num(n) => write_num(*n, out),
            Json::Str(s) => write_str(s, out),
            Json::Arr(a) => {
                out.push('[');
                for (i, v) in a.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    v.write(out);
                }
                out.push(']');
            }
            Json::Obj(m) => {
                out.push('{');
                for (i, (k, v)) in m.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    write_str(k, out);
                    out.push(':');
                    v.write(out);
                }
                out.push('}');
            }
        }
    }

    fn write_pretty(&self, out: &mut String, indent: usize) {
        match self {
            Json::Arr(a) if a.is_empty() => out.push_str("[]"),
            Json::Obj(m) if m.is_empty() => out.push_str("{}"),
            Json::Arr(a) => {
                out.push_str("[\n");
                for (i, v) in a.iter().enumerate() {
                    push_indent(out, indent + 1);
                    v.write_pretty(out, indent + 1);
                    if i + 1 < a.len() {
                        out.push(',');
                    }
                    out.push('\n');
                }
                push_indent(out, indent);
                out.push(']');
            }
            Json::Obj(m) => {
                out.push_str("{\n");
                for (i, (k, v)) in m.iter().enumerate() {
                    push_indent(out, indent + 1);
                    write_str(k, out);
                    out.push_str(": ");
                    v.write_pretty(out, indent + 1);
                    if i + 1 < m.len() {
                        out.push(',');
                    }
                    out.push('\n');
                }
                push_indent(out, indent);
                out.push('}');
            }
            other => other.write(out),
        }
    }
}

fn push_indent(out: &mut String, n: usize) {
    for _ in 0..n {
        out.push_str("  ");
    }
}

fn write_num(n: f64, out: &mut String) {
    if n.fract() == 0.0 && n.is_finite() && n.abs() < 9e15 {
        out.push_str(&(n as i64).to_string());
    } else {
        out.push_str(&n.to_string());
    }
}

fn write_str(s: &str, out: &mut String) {
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
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

pub fn obj(pairs: Vec<(&str, Json)>) -> Json {
    let mut m = BTreeMap::new();
    for (k, v) in pairs {
        m.insert(k.to_string(), v);
    }
    Json::Obj(m)
}

struct Parser<'a> {
    b: &'a [u8],
}

impl<'a> Parser<'a> {
    fn new(b: &'a [u8]) -> Self {
        Parser { b }
    }

    fn skip_ws(&self, i: &mut usize) {
        while *i < self.b.len() && self.b[*i].is_ascii_whitespace() {
            *i += 1;
        }
    }

    fn parse_value(&self, i: &mut usize) -> Result<Json, String> {
        self.skip_ws(i);
        if *i >= self.b.len() {
            return Err("意外结束".into());
        }
        match self.b[*i] {
            b'{' => self.parse_obj(i),
            b'[' => self.parse_arr(i),
            b'"' => Ok(Json::Str(self.parse_str(i)?)),
            b't' | b'f' => self.parse_bool(i),
            b'n' => self.parse_lit(i, "null", Json::Null),
            b'-' | b'0'..=b'9' => self.parse_num(i),
            c => Err(format!("第 {} 字节处意外字符 {}", i, c as char)),
        }
    }

    fn parse_lit(&self, i: &mut usize, lit: &str, v: Json) -> Result<Json, String> {
        if self.b[*i..].starts_with(lit.as_bytes()) {
            *i += lit.len();
            Ok(v)
        } else {
            Err(format!("第 {} 字节处应为 {}", i, lit))
        }
    }

    fn parse_bool(&self, i: &mut usize) -> Result<Json, String> {
        if self.b[*i..].starts_with(b"true") {
            *i += 4;
            Ok(Json::Bool(true))
        } else if self.b[*i..].starts_with(b"false") {
            *i += 5;
            Ok(Json::Bool(false))
        } else {
            Err(format!("第 {} 字节处应为布尔值", i))
        }
    }

    fn parse_num(&self, i: &mut usize) -> Result<Json, String> {
        let start = *i;
        if self.b[*i] == b'-' {
            *i += 1;
        }
        while *i < self.b.len() {
            match self.b[*i] {
                b'0'..=b'9' | b'.' | b'e' | b'E' | b'+' | b'-' => *i += 1,
                _ => break,
            }
        }
        let s = std::str::from_utf8(&self.b[start..*i]).map_err(|e| e.to_string())?;
        s.parse::<f64>()
            .map(Json::Num)
            .map_err(|e| format!("非法数字 {}: {}", s, e))
    }

    fn parse_str(&self, i: &mut usize) -> Result<String, String> {
        *i += 1;
        let mut out = String::new();
        while *i < self.b.len() {
            let c = self.b[*i];
            *i += 1;
            match c {
                b'"' => return Ok(out),
                b'\\' => {
                    if *i >= self.b.len() {
                        return Err("字符串转义未结束".into());
                    }
                    let e = self.b[*i];
                    *i += 1;
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
                            if *i + 4 > self.b.len() {
                                return Err("\\u 转义不完整".into());
                            }
                            let hex = std::str::from_utf8(&self.b[*i..*i + 4]).unwrap();
                            let code = u32::from_str_radix(hex, 16).map_err(|e| e.to_string())?;
                            *i += 4;
                            if let Some(ch) = char::from_u32(code) {
                                out.push(ch);
                            }
                        }
                        _ => return Err(format!("非法转义 \\{}", e as char)),
                    }
                }
                _ => {
                    // UTF-8 原样收集
                    let len = utf8_len(c);
                    if *i - 1 + len > self.b.len() {
                        return Err("UTF-8 被截断".into());
                    }
                    let slice = &self.b[*i - 1..*i - 1 + len];
                    out.push_str(std::str::from_utf8(slice).map_err(|e| e.to_string())?);
                    *i += len - 1;
                }
            }
        }
        Err("字符串未闭合".into())
    }

    fn parse_arr(&self, i: &mut usize) -> Result<Json, String> {
        *i += 1;
        let mut arr = Vec::new();
        self.skip_ws(i);
        if *i < self.b.len() && self.b[*i] == b']' {
            *i += 1;
            return Ok(Json::Arr(arr));
        }
        loop {
            arr.push(self.parse_value(i)?);
            self.skip_ws(i);
            if *i >= self.b.len() {
                return Err("数组未闭合".into());
            }
            match self.b[*i] {
                b',' => {
                    *i += 1;
                }
                b']' => {
                    *i += 1;
                    return Ok(Json::Arr(arr));
                }
                c => return Err(format!("数组中第 {} 字节处应为 , 或 ]，得到 {}", i, c as char)),
            }
        }
    }

    fn parse_obj(&self, i: &mut usize) -> Result<Json, String> {
        *i += 1;
        let mut map = BTreeMap::new();
        self.skip_ws(i);
        if *i < self.b.len() && self.b[*i] == b'}' {
            *i += 1;
            return Ok(Json::Obj(map));
        }
        loop {
            self.skip_ws(i);
            if *i >= self.b.len() || self.b[*i] != b'"' {
                return Err(format!("对象键应为字符串（第 {} 字节）", i));
            }
            let key = self.parse_str(i)?;
            self.skip_ws(i);
            if *i >= self.b.len() || self.b[*i] != b':' {
                return Err(format!("第 {} 字节处应为 :", i));
            }
            *i += 1;
            let val = self.parse_value(i)?;
            map.insert(key, val);
            self.skip_ws(i);
            if *i >= self.b.len() {
                return Err("对象未闭合".into());
            }
            match self.b[*i] {
                b',' => {
                    *i += 1;
                }
                b'}' => {
                    *i += 1;
                    return Ok(Json::Obj(map));
                }
                c => return Err(format!("对象中第 {} 字节处应为 , 或 }}，得到 {}", i, c as char)),
            }
        }
    }
}

fn utf8_len(b: u8) -> usize {
    if b < 0x80 {
        1
    } else if b >> 5 == 0b110 {
        2
    } else if b >> 4 == 0b1110 {
        3
    } else {
        4
    }
}
