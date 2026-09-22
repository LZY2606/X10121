//! 一个极小但完整的 JSON 值、解析器与序列化器（仅标准库）。
use std::collections::BTreeMap;
use std::fmt::Write as _;

#[derive(Debug, Clone)]
pub enum Json {
    Null,
    Bool(bool),
    /// 整数统一使用 i64；测试/协议范围内足够。
    Int(i64),
    Num(f64),
    Str(String),
    Arr(Vec<Json>),
    Obj(BTreeMap<String, Json>),
}

pub type JResult<T> = Result<T, String>;

impl Json {
    pub fn obj() -> Json {
        Json::Obj(BTreeMap::new())
    }
    pub fn put(&mut self, k: impl Into<String>, v: Json) {
        if let Json::Obj(m) = self {
            m.insert(k.into(), v);
        } else {
            panic!("put on non-object");
        }
    }
    pub fn with(mut self, k: impl Into<String>, v: Json) -> Json {
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
            Json::Num(x) => Some(*x as i64),
            _ => None,
        }
    }
    pub fn as_u64(&self) -> Option<u64> {
        self.as_i64().and_then(|n| u64::try_from(n).ok())
    }
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Json::Bool(b) => Some(*b),
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

    /// 紧凑、确定性输出：对象按 key 字典序（BTreeMap 已保证）。
    pub fn dump(&self) -> String {
        let mut out = String::new();
        self.write(&mut out, false);
        out
    }
    pub fn dump_pretty(&self) -> String {
        let mut out = String::new();
        self.write(&mut out, true);
        out.push('\n');
        out
    }

    fn write(&self, out: &mut String, pretty: bool) {
        match self {
            Json::Null => out.push_str("null"),
            Json::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            Json::Int(n) => {
                let _ = write!(out, "{n}");
            }
            Json::Num(n) => {
                if n.is_finite() {
                    let _ = write!(out, "{n}");
                } else {
                    out.push_str("null");
                }
            }
            Json::Str(s) => escape_into(s, out),
            Json::Arr(a) => {
                if a.is_empty() {
                    out.push_str("[]");
                    return;
                }
                out.push('[');
                for (i, v) in a.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    v.write(out, pretty);
                }
                out.push(']');
            }
            Json::Obj(m) => {
                if m.is_empty() {
                    out.push_str("{}");
                    return;
                }
                out.push('{');
                for (i, (k, v)) in m.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    escape_into(k, out);
                    out.push(':');
                    v.write(out, pretty);
                }
                out.push('}');
            }
        }
    }

    pub fn parse(input: &str) -> JResult<Json> {
        let bytes = input.as_bytes();
        let mut p = Parser { b: bytes, i: 0 };
        p.ws();
        let v = p.value()?;
        p.ws();
        if p.i != bytes.len() {
            return Err(p.err("尾部存在多余字符"));
        }
        Ok(v)
    }
}

fn escape_into(s: &str, out: &mut String) {
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

struct Parser<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Parser<'a> {
    fn err(&self, msg: &str) -> String {
        format!("JSON 解析错误（字节 {}）：{msg}", self.i)
    }
    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }
    fn ws(&mut self) {
        while let Some(c) = self.peek() {
            if c == b' ' || c == b'\t' || c == b'\n' || c == b'\r' {
                self.i += 1;
            } else {
                break;
            }
        }
    }
    fn eat(&mut self, c: u8) -> JResult<()> {
        if self.peek() == Some(c) {
            self.i += 1;
            Ok(())
        } else {
            Err(self.err(&format!("缺少字符 '{}'", c as char)))
        }
    }

    fn value(&mut self) -> JResult<Json> {
        self.ws();
        match self.peek() {
            None => Err(self.err("输入提前结束")),
            Some(b'{') => self.object(),
            Some(b'[') => self.array(),
            Some(b'"') => Ok(Json::Str(self.string()?)),
            Some(b't') | Some(b'f') => self.boolean(),
            Some(b'n') => self.null(),
            Some(c) if c == b'-' || c.is_ascii_digit() => self.number(),
            Some(c) => Err(self.err(&format!("意外字符 '{}'", c as char))),
        }
    }

    fn object(&mut self) -> JResult<Json> {
        self.eat(b'{')?;
        let mut m = BTreeMap::new();
        self.ws();
        if self.peek() == Some(b'}') {
            self.i += 1;
            return Ok(Json::Obj(m));
        }
        loop {
            self.ws();
            if self.peek() != Some(b'"') {
                return Err(self.err("对象键必须是字符串"));
            }
            let k = self.string()?;
            self.ws();
            self.eat(b':')?;
            let v = self.value()?;
            m.insert(k, v);
            self.ws();
            match self.peek() {
                Some(b',') => {
                    self.i += 1;
                }
                Some(b'}') => {
                    self.i += 1;
                    break;
                }
                _ => return Err(self.err("对象中应为 ',' 或 '}'")),
            }
        }
        Ok(Json::Obj(m))
    }

    fn array(&mut self) -> JResult<Json> {
        self.eat(b'[')?;
        let mut a = Vec::new();
        self.ws();
        if self.peek() == Some(b']') {
            self.i += 1;
            return Ok(Json::Arr(a));
        }
        loop {
            a.push(self.value()?);
            self.ws();
            match self.peek() {
                Some(b',') => {
                    self.i += 1;
                }
                Some(b']') => {
                    self.i += 1;
                    break;
                }
                _ => return Err(self.err("数组中应为 ',' 或 ']'")),
            }
        }
        Ok(Json::Arr(a))
    }

    fn string(&mut self) -> JResult<String> {
        self.eat(b'"')?;
        let mut s = String::new();
        loop {
            match self.peek() {
                None => return Err(self.err("字符串未闭合")),
                Some(b'"') => {
                    self.i += 1;
                    break;
                }
                Some(b'\\') => {
                    self.i += 1;
                    match self.peek() {
                        Some(b'"') => s.push('"'),
                        Some(b'\\') => s.push('\\'),
                        Some(b'/') => s.push('/'),
                        Some(b'n') => s.push('\n'),
                        Some(b't') => s.push('\t'),
                        Some(b'r') => s.push('\r'),
                        Some(b'b') => s.push('\u{08}'),
                        Some(b'f') => s.push('\u{0c}'),
                        Some(b'u') => {
                            self.i += 1;
                            let cp = self.hex4()?;
                            if (0xD800..=0xDBFF).contains(&cp) {
                                if self.peek() == Some(b'\\') {
                                    self.i += 1;
                                    if self.peek() == Some(b'u') {
                                        self.i += 1;
                                        let lo = self.hex4()?;
                                        if (0xDC00..=0xDFFF).contains(&lo) {
                                            let c = 0x10000
                                                + ((cp - 0xD800) << 10)
                                                + (lo - 0xDC00);
                                            if let Some(ch) = char::from_u32(c) {
                                                s.push(ch);
                                            } else {
                                                return Err(self.err("非法代理对"));
                                            }
                                            continue;
                                        }
                                    }
                                }
                                return Err(self.err("高代理后缺少低代理"));
                            }
                            if let Some(ch) = char::from_u32(cp) {
                                s.push(ch);
                            } else {
                                return Err(self.err("非法 \\u 码点"));
                            }
                            continue;
                        }
                        _ => return Err(self.err("非法转义")),
                    }
                    self.i += 1;
                }
                Some(c) => {
                    // 按 UTF-8 原样收集，逐字节推进到下一个 ASCII 边界/引号。
                    let start = self.i;
                    let len = if c < 0x80 {
                        1
                    } else {
                        2 + (c >= 0xE0) as usize + (c >= 0xF0) as usize
                    };
                    let end = (start + len).min(self.b.len());
                    match std::str::from_utf8(&self.b[start..end]) {
                        Ok(part) => s.push_str(part),
                        Err(_) => return Err(self.err("非法 UTF-8")),
                    }
                    self.i = end;
                }
            }
        }
        Ok(s)
    }

    fn hex4(&mut self) -> JResult<u32> {
        if self.i + 4 > self.b.len() {
            return Err(self.err("\\u 后需要 4 个十六进制位"));
        }
        let s = std::str::from_utf8(&self.b[self.i..self.i + 4]).unwrap();
        let n = u32::from_str_radix(s, 16)
            .map_err(|_| self.err("\\u 码点不是十六进制"))?;
        self.i += 4;
        Ok(n)
    }

    fn boolean(&mut self) -> JResult<Json> {
        if self.b[self.i..].starts_with(b"true") {
            self.i += 4;
            Ok(Json::Bool(true))
        } else if self.b[self.i..].starts_with(b"false") {
            self.i += 5;
            Ok(Json::Bool(false))
        } else {
            Err(self.err("无法识别的字面量"))
        }
    }

    fn null(&mut self) -> JResult<Json> {
        if self.b[self.i..].starts_with(b"null") {
            self.i += 4;
            Ok(Json::Null)
        } else {
            Err(self.err("无法识别的字面量"))
        }
    }

    fn number(&mut self) -> JResult<Json> {
        let start = self.i;
        if self.peek() == Some(b'-') {
            self.i += 1;
        }
        let mut is_float = false;
        while let Some(c) = self.peek() {
            match c {
                b'0'..=b'9' => self.i += 1,
                b'.' | b'e' | b'E' | b'+' | b'-' => {
                    is_float = true;
                    self.i += 1;
                }
                _ => break,
            }
        }
        let text = std::str::from_utf8(&self.b[start..self.i]).unwrap();
        if is_float {
            text.parse::<f64>()
                .map(Json::Num)
                .map_err(|_| self.err("非法数字"))
        } else {
            text.parse::<i64>()
                .map(Json::Int)
                .map_err(|_| self.err("非法整数"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_ordering() {
        let j = Json::parse(r#"{"b":1,"a":[true,false,null,"你好\n"]}"#).unwrap();
        let s = j.dump();
        // BTreeMap 保证键排序确定
        assert!(s.starts_with(r#"{"a":["#));
        let j2 = Json::parse(&s).unwrap();
        assert_eq!(j2.dump(), s);
    }

    #[test]
    fn rejects_trailing_garbage() {
        assert!(Json::parse("1 2").is_err());
        assert!(Json::parse("{").is_err());
    }
}
