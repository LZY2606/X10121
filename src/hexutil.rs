//! 十六进制样本输入的规范化：允许空格/换行/0x 前缀，要求偶数个 nibble。
pub fn decode_hex(input: &str) -> Result<Vec<u8>, String> {
    let cleaned: String = input
        .chars()
        .filter(|c| !c.is_whitespace())
        .map(|c| if c == 'X' { 'x' } else { c })
        .collect();
    let s = cleaned.strip_prefix("0x").unwrap_or(&cleaned);
    if s.is_empty() {
        return Ok(Vec::new());
    }
    if s.len() % 2 != 0 {
        return Err("十六进制字符数必须为偶数".to_string());
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_val(bytes[i]).ok_or_else(|| format!("非法十六进制字符 '{}'", bytes[i] as char))?;
        let lo = hex_val(bytes[i + 1])
            .ok_or_else(|| format!("非法十六进制字符 '{}'", bytes[i + 1] as char))?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

pub fn encode_hex(data: &[u8]) -> String {
    crate::hash::hex_lower(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tolerant_decoding() {
        assert_eq!(decode_hex("0xAB cd").unwrap(), vec![0xAB, 0xCD]);
        assert!(decode_hex("abc").is_err());
        assert!(decode_hex("zz").is_err());
    }
}
