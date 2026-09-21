pub mod parser;
pub mod protocol;
pub mod server;
pub mod store;

/// 内置演示协议：magic(2) + kind(1) + len(1) + payload(len, max 64)
/// + 条件扩展字段(kind>=2 时 2 字节) + sum16 校验和（覆盖自 magic 起，跳过自身）。
pub const DEMO_PROTOCOL_JSON: &str = r#"{
  "name": "demo-frame",
  "max_depth": 8,
  "root": {
    "type": "seq",
    "name": "frame",
    "children": [
      { "type": "uint", "name": "magic", "size": 2, "endian": "big" },
      { "type": "uint", "name": "kind", "size": 1 },
      { "type": "uint", "name": "len", "size": 1 },
      { "type": "var_bytes", "name": "payload", "len_from": "len", "max": 64 },
      { "type": "if", "name": "ext",
        "cond": { "field": "kind", "op": "gte", "value": 2 },
        "then": { "type": "uint", "name": "ext_val", "size": 2, "endian": "big" } },
      { "type": "checksum", "name": "cksum", "size": 2, "endian": "big",
        "algo": "sum16", "cover": { "from": "magic" }, "skip_self": true }
    ]
  }
}"#;

/// 与演示协议匹配的一帧样例。
pub fn demo_frame() -> Vec<u8> {
    let mut f = vec![0xAB, 0xCD, 0x02, 0x04, 0xDE, 0xAD, 0xBE, 0xEF, 0x12, 0x34];
    let sum: u16 = f.iter().map(|b| *b as u16).sum();
    f.extend_from_slice(&sum.to_be_bytes());
    f
}
