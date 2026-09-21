//! 十六进制工具：容忍空白与 `0x` 前缀。

/// 将十六进制文本解码为字节。允许空白、冒号、`0x` 前缀。
pub fn decode(input: &str) -> Result<Vec<u8>, String> {
    let cleaned: Vec<char> = input
        .chars()
        .filter(|c| !c.is_whitespace() && *c != ':' && *c != '-')
        .collect();
    let s: String = cleaned.iter().collect();
    let s = s.strip_prefix("0x").unwrap_or(&s).to_string();
    if s.len() % 2 != 0 {
        return Err("十六进制字符串长度必须为偶数".to_string());
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_val(bytes[i])
            .ok_or_else(|| format!("非法十六进制字符 {:?}（位置 {}）", bytes[i] as char, i))?;
        let lo = hex_val(bytes[i + 1])
            .ok_or_else(|| format!("非法十六进制字符 {:?}（位置 {}）", bytes[i + 1] as char, i + 1))?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// 字节编码为小写十六进制。
pub fn encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(nibble(b >> 4));
        s.push(nibble(b & 0xf));
    }
    s
}

fn nibble(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        _ => (b'a' + n - 10) as char,
    }
}
