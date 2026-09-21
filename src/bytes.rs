//! 十六进制字节流工具，以及测试用的轻量编码器。

/// 解析用户粘贴的十六进制：允许空白、逗号、冒号、换行、可选 0x 前缀。
pub fn parse_hex(input: &str) -> Result<Vec<u8>, String> {
    let cleaned: Vec<char> = input
        .chars()
        .filter(|c| !c.is_whitespace() && *c != ',' && *c != ':')
        .collect();
    let mut text: String = cleaned.into_iter().collect();
    if let Some(rest) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        text = rest.to_string();
    }
    if text.is_empty() {
        return Err("十六进制输入为空".to_string());
    }
    if text.len() % 2 != 0 {
        return Err(format!("十六进制字符数必须为偶数，当前 {} 个", text.len()));
    }
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let hi = hex_nibble(pair[0])
            .ok_or_else(|| format!("非法十六进制字符 {:?}", pair[0] as char))?;
        let lo = hex_nibble(pair[1])
            .ok_or_else(|| format!("非法十六进制字符 {:?}", pair[1] as char))?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

pub fn to_hex(bytes: &[u8]) -> String {
    crate::hash::hex_encode(bytes)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// 生成数据测试时使用的字节编码器，语法上保持与解析器对称。
#[derive(Debug, Default, Clone)]
pub struct ByteWriter {
    buf: Vec<u8>,
}

impl ByteWriter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn u8(&mut self, v: u8) -> &mut Self {
        self.buf.push(v);
        self
    }

    pub fn u16_be(&mut self, v: u16) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }

    pub fn u16_le(&mut self, v: u16) -> &mut Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }

    pub fn u24_be(&mut self, v: u32) -> &mut Self {
        self.buf.extend_from_slice(&[(v >> 16) as u8, (v >> 8) as u8, v as u8]);
        self
    }

    pub fn u32_be(&mut self, v: u32) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }

    pub fn bytes(&mut self, data: &[u8]) -> &mut Self {
        self.buf.extend_from_slice(data);
        self
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.buf
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }

    pub fn patch_u8(&mut self, index: usize, value: u8) {
        self.buf[index] = value;
    }

    pub fn patch_u16_be(&mut self, index: usize, value: u16) {
        self.buf[index..index + 2].copy_from_slice(&value.to_be_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_loose_hex() {
        assert_eq!(
            parse_hex("0x AB CD , 01\n02").unwrap(),
            vec![0xab, 0xcd, 0x01, 0x02]
        );
    }

    #[test]
    fn rejects_odd_length() {
        assert!(parse_hex("abc").is_err());
    }
}
