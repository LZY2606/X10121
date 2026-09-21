//! 内置演示协议：递归 TLV 帧，覆盖定长整数、变长 payload、条件字段、
//! 有界递归子结构、数组与“跳过自身”的 sum8 校验和。

pub const DEMO_PROTOCOL: &str = r#"{
  "name": "递归TLV演示帧 v1",
  "description": "SOI/EOI 常量包裹的 TLV：tag=2 的 item 携带递归 children（受 body_len 约束），帧尾 sum8 覆盖除自身外全部字节。",
  "root": "frame",
  "structs": {
    "frame": {
      "fields": [
        {"name": "soi", "type": "int", "width": 1, "expect": 170},
        {"name": "frame_id", "type": "int", "width": 2, "endian": "big"},
        {"name": "body_len", "type": "int", "width": 2, "endian": "big"},
        {"name": "body", "type": "struct", "struct": "body", "length": {"field": "body_len"}},
        {"name": "eoi", "type": "int", "width": 1, "expect": 187},
        {"name": "checksum", "type": "checksum", "alg": "sum8", "from": "soi", "to": "eoi", "skip_self": true, "severity": "error"}
      ]
    },
    "body": {
      "fields": [
        {"name": "item_count", "type": "int", "width": 1},
        {"name": "items", "type": "array", "count": {"field": "item_count"}, "item": {
          "name": "item",
          "type": "struct",
          "struct": "item"
        }}
      ]
    },
    "item": {
      "fields": [
        {"name": "tag", "type": "int", "width": 1},
        {"name": "value_len", "type": "int", "width": 1},
        {"name": "value", "type": "bytes", "length": {"field": "value_len"}},
        {"name": "children_len", "type": "int", "width": 1},
        {"name": "children", "type": "struct", "struct": "body", "length": {"field": "children_len"}, "max_depth": 8, "when": {"field": "tag", "eq": 2}}
      ]
    }
  }
}"#;

/// 第二个演示协议：xor8、warn 级校验与条件结构，用于版本演进演示。
pub const DEMO_PROTOCOL_V2: &str = r#"{
  "name": "递归TLV演示帧 v2",
  "description": "在 v1 基础上把帧尾校验改为 xor8 且仅告警；其余字节布局保持兼容。",
  "root": "frame",
  "structs": {
    "frame": {
      "fields": [
        {"name": "soi", "type": "int", "width": 1, "expect": 170},
        {"name": "frame_id", "type": "int", "width": 2, "endian": "big"},
        {"name": "body_len", "type": "int", "width": 2, "endian": "big"},
        {"name": "body", "type": "struct", "struct": "body", "length": {"field": "body_len"}},
        {"name": "eoi", "type": "int", "width": 1, "expect": 187},
        {"name": "checksum", "type": "checksum", "alg": "xor8", "from": "soi", "to": "eoi", "skip_self": true, "severity": "warn"}
      ]
    },
    "body": {
      "fields": [
        {"name": "item_count", "type": "int", "width": 1},
        {"name": "items", "type": "array", "count": {"field": "item_count"}, "item": {
          "name": "item",
          "type": "struct",
          "struct": "item"
        }}
      ]
    },
    "item": {
      "fields": [
        {"name": "tag", "type": "int", "width": 1},
        {"name": "value_len", "type": "int", "width": 1},
        {"name": "value", "type": "bytes", "length": {"field": "value_len"}},
        {"name": "children_len", "type": "int", "width": 1},
        {"name": "children", "type": "struct", "struct": "body", "length": {"field": "children_len"}, "max_depth": 8, "when": {"field": "tag", "eq": 2}}
      ]
    }
  }
}"#;
