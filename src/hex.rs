pub fn encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

pub fn decode(input: &str) -> Result<Vec<u8>, String> {
    let cleaned: String = input.chars().filter(|c| !c.is_whitespace() && *c != '-').collect();
    if cleaned.len() % 2 != 0 {
        return Err("十六进制字符串长度必须为偶数".to_string());
    }
    let mut out = Vec::with_capacity(cleaned.len() / 2);
    let bytes = cleaned.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_digit(bytes[i])
            .ok_or_else(|| format!("非法的十六进制字符: {}", bytes[i] as char))?;
        let lo = hex_digit(bytes[i + 1])
            .ok_or_else(|| format!("非法的十六进制字符: {}", bytes[i + 1] as char))?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let data = vec![0x00, 0x01, 0xab, 0xff];
        assert_eq!(decode(&encode(&data)).unwrap(), data);
        assert_eq!(decode("01 02-ab").unwrap(), vec![1, 2, 0xab]);
        assert!(decode("abc").is_err());
        assert!(decode("zz").is_err());
    }
}
