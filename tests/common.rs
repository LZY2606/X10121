// 公共测试辅助（integration test submodule 由 tests/*.rs 通过 mod common 引入）。
#![allow(dead_code)]

use frame_lab::json::{self, Value};
use frame_lab::model::{self, Protocol};
use frame_lab::parser;

pub fn load(spec: &str) -> Protocol {
    let v = json::parse(spec).expect("spec 应是合法 JSON");
    model::load_protocol(&v).expect("spec 应通过校验")
}

pub fn load_value(v: &Value) -> Protocol {
    model::load_protocol(v).expect("spec 应通过校验")
}

/// 演示协议：定长整数 + 变长 payload（长度字段 - 常数）+ sum8 自排除校验和 + 条件字段。
pub const DEMO_SPEC: &str = r#"
{
  "name": "demo",
  "endian": "big",
  "max_depth": 6,
  "max_frame": 4096,
  "root": "frame",
  "structs": {
    "frame": [
      {"name": "magic", "type": "int", "bytes": 1, "enum": {"SYNC": 161}},
      {"name": "type", "type": "int", "bytes": 1, "enum": {"DATA": 1, "ACK": 2}},
      {"name": "length", "type": "int", "bytes": 1},
      {"name": "payload", "type": "bytes", "length": "$length-1"},
      {"name": "crc", "type": "int", "bytes": 1,
       "checksum": {"algo": "sum8", "skip": ["crc"]}},
      {"name": "trailer", "type": "int", "bytes": 1, "default": 17,
       "when": {"field": "type", "equals": 2}}
    ],
    "part": [
      {"name": "tag", "type": "int", "bytes": 1},
      {"name": "len", "type": "int", "bytes": 1},
      {"name": "val", "type": "bytes", "length": "$len"}
    ]
  }
}
"#;

/// 直接按字段手工构造一帧（不用被测编码器），避免“编码器/解析器同错”。
pub fn demo_frame(payload: &[u8], frame_type: u8) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(0xa1);
    out.push(frame_type);
    out.push((payload.len() + 1) as u8);
    out.extend_from_slice(payload);
    let crc = out.iter().map(|&b| b as u16).sum::<u16>() as u8;
    out.push(crc);
    if frame_type == 2 {
        out.push(17);
    }
    out
}

pub fn root(r: &parser::ParseResult) -> &parser::Node {
    r.tree.as_ref().expect("应有部分解析树")
}

pub fn find_path<'a>(node: &'a parser::Node, path: &[String]) -> Option<&'a parser::Node> {
    if node.path == path {
        return Some(node);
    }
    for c in &node.children {
        if let Some(n) = find_path(c, path) {
            return Some(n);
        }
    }
    None
}

pub fn p(names: &[&str]) -> Vec<String> {
    let mut v = vec!["frame".to_string()];
    v.extend(names.iter().map(|s| s.to_string()));
    v
}
