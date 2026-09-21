// 手写 JSON：解析、序列化、规范化。零外部依赖。

use std::fmt::Write as _;

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    RawNum(String),
    Int(i128),
    Float(f64),
    Str(String),
    Obj(Vec<(String, Value)>),
    Arr(Vec<Value>),
}

impl Value {
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s),
            _ => None,
        }
    }
    pub fn as_array(&self) -> Option<&Vec<Value>> {
        match self {
            Value::Arr(a) => Some(a),
            _ => None,
        }
    }
    pub fn as_object(&self) -> Option<&Vec<(String, Value)>> {
        match self {
            Value::Obj(o) => Some(o),
            _ => None,
        }
    }
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Obj(o) => o.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }
    pub fn has(&self, key: &str) -> bool {
        self.get(key).is_some()
    }
    pub fn as_i128(&self) -> Option<i128> {
        match self {
            Value::Int(i) => Some(*i),
            Value::RawNum(s) => s.parse::<i128>().ok(),
            _ => None,
        }
    }
    pub fn as_usize(&self) -> Option<usize> {
        self.as_i128().and_then(|i| usize::try_from(i).ok())
    }
    pub fn as_number(&self) -> Option<f64> {
        match self {
            Value::Int(i) => Some(*i as f64),
            Value::Float(f) => Some(*f),
            Value::RawNum(s) => s.parse::<f64>().ok(),
            _ => None,
        }
    }
    pub fn type_name(&self) -> &'static str {
        match self {
            Value::Null => "null",
            Value::Bool(_) => "bool",
            Value::RawNum(_) | Value::Int(_) | Value::Float(_) => "number",
            Value::Str(_) => "string",
            Value::Obj(_) => "object",
            Value::Arr(_) => "array",
        }
    }
}

pub fn parse(input: &str) -> Result<Value, String> {
    let bytes = input.as_bytes();
    let mut p = Parser { b: bytes, i: 0 };
    p.skip_ws();
    let v = p.value()?;
    p.skip_ws();
    if p.i != bytes.len() {
        return Err(format!("json: 位置 {} 之后存在多余字符", p.i));
    }
    Ok(v)
}

struct Parser<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Parser<'a> {
    fn skip_ws(&mut self) {
        while self.i < self.b.len() && matches!(self.b[self.i], b' ' | b'\t' | b'\n' | b'\r') {
            self.i += 1;
        }
    }
    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }
    fn value(&mut self) -> Result<Value, String> {
        self.skip_ws();
        match self.peek() {
            Some(b'{') => self.object(),
            Some(b'[') => self.array(),
            Some(b'"') => self.string().map(Value::Str),
            Some(b't') | Some(b'f') => self.boolean(),
            Some(b'n') => self.null(),
            Some(c) if c == b'-' || c.is_ascii_digit() => self.number(),
            Some(c) => Err(format!("json: 位置 {} 出现意外字符 {:?}", self.i, c as char)),
            None => Err("json: 输入意外结束".to_string()),
        }
    }
    fn object(&mut self) -> Result<Value, String> {
        self.i += 1;
        let mut out = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.i += 1;
            return Ok(Value::Obj(out));
        }
        loop {
            self.skip_ws();
            if self.peek() != Some(b'"') {
                return Err(format!("json: 对象键必须是字符串（位置 {}）", self.i));
            }
            let key = self.string()?;
            self.skip_ws();
            if self.peek() != Some(b':') {
                return Err(format!("json: 对象键后缺少 ':'（位置 {}）", self.i));
            }
            self.i += 1;
            let val = self.value()?;
            out.push((key, val));
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.i += 1;
                }
                Some(b'}') => {
                    self.i += 1;
                    break;
                }
                _ => return Err(format!("json: 对象中缺少 ',' 或 '}}'（位置 {}）", self.i)),
            }
        }
        Ok(Value::Obj(out))
    }
    fn array(&mut self) -> Result<Value, String> {
        self.i += 1;
        let mut out = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.i += 1;
            return Ok(Value::Arr(out));
        }
        loop {
            let val = self.value()?;
            out.push(val);
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.i += 1;
                }
                Some(b']') => {
                    self.i += 1;
                    break;
                }
                _ => return Err(format!("json: 数组中缺少 ',' 或 ']'（位置 {}）", self.i)),
            }
        }
        Ok(Value::Arr(out))
    }
    fn string(&mut self) -> Result<String, String> {
        self.i += 1;
        let mut out = String::new();
        while self.i < self.b.len() {
            let c = self.b[self.i];
            self.i += 1;
            match c {
                b'"' => return Ok(out),
                b'\\' => {
                    let e = self.b.get(self.i).copied().ok_or("json: 转义被截断")?;
                    self.i += 1;
                    match e {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{0008}'),
                        b'f' => out.push('\u{000C}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            if self.i + 4 > self.b.len() {
                                return Err("json: \\u 转义被截断".to_string());
                            }
                            let hex = std::str::from_utf8(&self.b[self.i..self.i + 4])
                                .map_err(|_| "json: \\u 非 utf8".to_string())?;
                            let cp = u32::from_str_radix(hex, 16)
                                .map_err(|_| format!("json: 非法 \\u{} 转义", hex))?;
                            self.i += 4;
                            if (0xD800..=0xDBFF).contains(&cp) {
                                if self.b.get(self.i..self.i + 2) != Some(&b"\\u"[..]) {
                                    return Err("json: 高代理项后缺少低代理项".to_string());
                                }
                                self.i += 2;
                                let hex2 = std::str::from_utf8(&self.b[self.i..self.i + 4])
                                    .map_err(|_| "json: \\u 非 utf8".to_string())?;
                                let lo = u32::from_str_radix(hex2, 16)
                                    .map_err(|_| format!("json: 非法 \\u{} 转义", hex2))?;
                                self.i += 4;
                                if !(0xDC00..=0xDFFF).contains(&lo) {
                                    return Err("json: 低代理项无效".to_string());
                                }
                                let c = 0x10000
                                    + ((cp - 0xD800) << 10)
                                    + (lo - 0xDC00);
                                out.push(char::from_u32(c).ok_or("json: 代理对无效")?);
                            } else if (0xDC00..=0xDFFF).contains(&cp) {
                                return Err("json: 非法孤立低代理项".to_string());
                            } else {
                                out.push(char::from_u32(cp).ok_or("json: 码点无效")?);
                            }
                        }
                        _ => return Err(format!("json: 非法转义 \\{}", e as char)),
                    }
                }
                _ => {
                    // 累积一个 UTF-8 序列
                    let start = self.i - 1;
                    let len = if c < 0x80 {
                        1
                    } else if c >> 5 == 0b110 {
                        2
                    } else if c >> 4 == 0b1110 {
                        3
                    } else if c >> 3 == 0b11110 {
                        4
                    } else {
                        return Err("json: 非法 UTF-8 起始字节".to_string());
                    };
                    if self.i - 1 + len > self.b.len() {
                        return Err("json: UTF-8 序列被截断".to_string());
                    }
                    let chunk = &self.b[start..start + len];
                    self.i = start + len;
                    out.push_str(std::str::from_utf8(chunk).map_err(|_| "json: 非 utf8")?);
                }
            }
        }
        Err("json: 字符串缺少闭合引号".to_string())
    }
    fn boolean(&mut self) -> Result<Value, String> {
        if self.b[self.i..].starts_with(b"true") {
            self.i += 4;
            Ok(Value::Bool(true))
        } else if self.b[self.i..].starts_with(b"false") {
            self.i += 5;
            Ok(Value::Bool(false))
        } else {
            Err(format!("json: 位置 {} 非法字面量", self.i))
        }
    }
    fn null(&mut self) -> Result<Value, String> {
        if self.b[self.i..].starts_with(b"null") {
            self.i += 4;
            Ok(Value::Null)
        } else {
            Err(format!("json: 位置 {} 非法字面量", self.i))
        }
    }
    fn number(&mut self) -> Result<Value, String> {
        let start = self.i;
        if self.peek() == Some(b'-') {
            self.i += 1;
        }
        while self.i < self.b.len() {
            let c = self.b[self.i];
            if c.is_ascii_digit() || matches!(c, b'.' | b'e' | b'E' | b'+' | b'-') {
                self.i += 1;
            } else {
                break;
            }
        }
        let s = std::str::from_utf8(&self.b[start..self.i]).map_err(|_| "json: 数字非 utf8")?;
        if s == "-" || s.is_empty() {
            return Err("json: 非法数字".to_string());
        }
        Ok(Value::RawNum(s.to_string()))
    }
}

/// 紧凑序列化（保留对象键顺序）
pub fn stringify(v: &Value) -> String {
    let mut out = String::new();
    write_value(&mut out, v);
    out
}

/// 带缩进的序列化（两空格），便于在文本框里编辑
pub fn stringify_pretty(v: &Value) -> String {
    let mut out = String::new();
    write_pretty(&mut out, v, 0);
    out.push('\n');
    out
}

fn escape_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{0008}' => out.push_str("\\b"),
            '\u{000C}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn write_value(out: &mut String, v: &Value) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::RawNum(s) => out.push_str(s),
        Value::Int(i) => {
            let _ = write!(out, "{}", i);
        }
        Value::Float(f) => {
            if f.is_finite() {
                let _ = write!(out, "{}", f);
            } else {
                out.push_str("null");
            }
        }
        Value::Str(s) => escape_string(out, s),
        Value::Obj(o) => {
            out.push('{');
            for (i, (k, v)) in o.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                escape_string(out, k);
                out.push(':');
                write_value(out, v);
            }
            out.push('}');
        }
        Value::Arr(a) => {
            out.push('[');
            for (i, v) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(out, v);
            }
            out.push(']');
        }
    }
}

fn write_pretty(out: &mut String, v: &Value, indent: usize) {
    let pad = "  ".repeat(indent);
    let pad1 = "  ".repeat(indent + 1);
    match v {
        Value::Obj(o) if o.is_empty() => out.push_str("{}"),
        Value::Obj(o) => {
            out.push_str("{\n");
            for (i, (k, v)) in o.iter().enumerate() {
                out.push_str(&pad1);
                escape_string(out, k);
                out.push_str(": ");
                write_pretty(out, v, indent + 1);
                if i + 1 < o.len() {
                    out.push(',');
                }
                out.push('\n');
            }
            out.push_str(&pad);
            out.push('}');
        }
        Value::Arr(a) if a.is_empty() => out.push_str("[]"),
        Value::Arr(a) => {
            out.push_str("[\n");
            for (i, v) in a.iter().enumerate() {
                out.push_str(&pad1);
                write_pretty(out, v, indent + 1);
                if i + 1 < a.len() {
                    out.push(',');
                }
                out.push('\n');
            }
            out.push_str(&pad);
            out.push(']');
        }
        other => write_value(out, other),
    }
}

/// 规范化：对象键按 Unicode 字典序排序、数字规整。用于内容寻址与确定性摘要。
pub fn canonicalize(v: &Value) -> Value {
    match v {
        Value::Obj(o) => {
            let mut sorted: Vec<(String, Value)> =
                o.iter().map(|(k, v)| (k.clone(), canonicalize(v))).collect();
            sorted.sort_by(|a, b| a.0.cmp(&b.0));
            Value::Obj(sorted)
        }
        Value::Arr(a) => Value::Arr(a.iter().map(canonicalize).collect()),
        Value::RawNum(s) => normalize_number(s),
        other => other.clone(),
    }
}

fn normalize_number(s: &str) -> Value {
    if let Ok(i) = s.parse::<i128>() {
        return Value::Int(i);
    }
    match s.parse::<f64>() {
        Ok(f) if f.is_finite() => Value::Float(f),
        _ => Value::RawNum(s.to_string()),
    }
}
