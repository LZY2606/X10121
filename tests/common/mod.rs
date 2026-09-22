//! 生成数据测试公共工具：确定性 LCG、协议夹具、手工帧构造器。
use frame_lab::json::Json;
use frame_lab::spec::Spec;

/// 确定性线性同余随机源（测试可复现）。
pub struct Rng(u64);
impl Rng {
    pub fn new(seed: u64) -> Rng {
        Rng(seed.max(1))
    }
    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        self.0
    }
    pub fn below(&mut self, n: u64) -> u64 {
        self.next_u64() % n
    }
    pub fn byte(&mut self) -> u8 {
        (self.next_u64() & 0xFF) as u8
    }
}

pub fn demo_spec() -> Spec {
    Spec::from_json(&frame_lab::demo::demo_spec_json()).unwrap()
}

pub fn parse_json(s: &str) -> Json {
    Json::parse(s).unwrap()
}

pub fn demo_frame() -> Vec<u8> {
    let spec = demo_spec();
    let values = parse_json(
        r#"{
          "soi": 170, "frame_len": 19, "kind": 2, "seq": 7,
          "body": {
            "clen": 12,
            "payload": "010203",
            "tail": { "marker": 205 },
            "node": {
              "ntype": 1, "nlen": 2, "nval": "abcd",
              "child": { "ntype": 9, "nlen": 0, "nval": "" }
            }
          }
        }"#,
    );
    frame_lab::encoder::encode(&spec, &values).unwrap()
}

/// 恶意长度测试协议：blen 决定 body 硬边界，plen 决定 payload 长度。
pub fn malicious_spec_json() -> Json {
    parse_json(
        r#"{
          "name": "恶意长度测试协议",
          "root": "frame",
          "max_depth": 4,
          "structs": [
            {
              "name": "frame",
              "length_ref": { "field": "frame_len" },
              "fields": [
                { "name": "soi", "type": "u8", "const": 170 },
                { "name": "frame_len", "type": "u8" },
                { "name": "body", "type": "struct", "struct": "body" },
                {
                  "name": "chk",
                  "type": "u8",
                  "checksum": { "algo": "sum8", "covers": ["soi", "@end"], "skip_self": true }
                }
              ]
            },
            {
              "name": "body",
              "length_ref": { "field": "blen", "offset": 0 },
              "fields": [
                { "name": "blen", "type": "u8" },
                { "name": "plen", "type": "u8" },
                { "name": "payload", "type": "bytes", "length": "plen" },
                { "name": "pad", "type": "u8" }
              ]
            }
          ]
        }"#,
    )
}

/// 递归深度协议：tag==1 时出现 child。
pub fn recursion_spec_json(max_depth: i64) -> Json {
    Json::parse(&format!(
        r#"{{
          "name": "递归协议",
          "root": "node",
          "max_depth": {max_depth},
          "structs": [
            {{
              "name": "node",
              "fields": [
                {{ "name": "tag", "type": "u8" }},
                {{ "name": "v", "type": "u8" }},
                {{
                  "name": "child",
                  "type": "struct",
                  "struct": "node",
                  "when": {{ "field": "tag", "eq": 1 }}
                }}
              ]
            }}
          ]
        }}"#
    ))
    .unwrap()
}

/// 校验和自排除协议：chk 覆盖 start..end 并跳过自身。
pub fn checksum_spec_json(algo: &str) -> Json {
    Json::parse(&format!(
        r#"{{
          "name": "校验和协议-{algo}",
          "root": "frame",
          "max_depth": 4,
          "structs": [
            {{
              "name": "frame",
              "fields": [
                {{ "name": "a", "type": "u8" }},
                {{ "name": "b", "type": "u8" }},
                {{
                  "name": "chk",
                  "type": "u8",
                  "checksum": {{ "algo": "{algo}", "covers": ["@start", "@end"], "skip_self": true }}
                }}
              ]
            }}
          ]
        }}"#
    ))
    .unwrap()
}

pub fn sum8(data: &[u8]) -> u8 {
    data.iter().fold(0u8, |acc, &b| acc.wrapping_add(b))
}
pub fn xor8(data: &[u8]) -> u8 {
    data.iter().fold(0u8, |acc, &b| acc ^ b)
}
