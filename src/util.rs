//! 稳定的哈希与十六进制工具（不依赖外部 crate，保证跨运行确定性）。

pub struct Fnv(u64);

impl Fnv {
    pub fn new() -> Self {
        Fnv(0xcbf29ce484222325)
    }
    pub fn write(&mut self, data: &[u8]) {
        for b in data {
            self.0 ^= *b as u64;
            self.0 = self.0.wrapping_mul(0x100000001b3);
        }
    }
    pub fn finish(&self) -> u64 {
        self.0
    }
}

pub fn fnv1a64(data: &[u8]) -> u64 {
    let mut h = Fnv::new();
    h.write(data);
    h.finish()
}

pub fn hex_encode(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len() * 2);
    for b in data {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

pub fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    let cleaned: String = s
        .chars()
        .filter(|c| !c.is_whitespace() && *c != ',')
        .collect();
    if cleaned.len() % 2 != 0 {
        return Err("hex string must have an even number of digits".into());
    }
    let mut out = Vec::with_capacity(cleaned.len() / 2);
    let bytes = cleaned.as_bytes();
    for i in (0..bytes.len()).step_by(2) {
        let pair = std::str::from_utf8(&bytes[i..i + 2]).map_err(|e| e.to_string())?;
        out.push(u8::from_str_radix(pair, 16).map_err(|_| format!("invalid hex byte '{pair}'"))?);
    }
    Ok(out)
}
