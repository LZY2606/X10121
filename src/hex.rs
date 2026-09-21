//! Hexadecimal helpers. Input tolerates spaces, tabs, newlines and an
//! optional `0x` prefix so users can paste streams freely.

pub fn encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

pub fn decode(input: &str) -> Result<Vec<u8>, String> {
    let cleaned: String = input
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .trim_start_matches("0x")
        .to_string();
    if cleaned.len() % 2 != 0 {
        return Err("hex input must contain an even number of digits".to_string());
    }
    let mut out = Vec::with_capacity(cleaned.len() / 2);
    let bytes = cleaned.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = nibble(bytes[i]).ok_or_else(|| format!("invalid hex digit: {}", bytes[i] as char))?;
        let lo = nibble(bytes[i + 1])
            .ok_or_else(|| format!("invalid hex digit: {}", bytes[i + 1] as char))?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

fn nibble(b: u8) -> Option<u8> {
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
    fn roundtrip_with_noise() {
        assert_eq!(decode("0x01 A2\n9f").unwrap(), vec![1, 0xa2, 0x9f]);
        assert_eq!(encode(&[0, 255, 15]), "00ff0f");
        assert!(decode("abc").is_err());
        assert!(decode("zz").is_err());
    }
}
