mod common;

use common::*;
use frame_lab::parser::{FailKind, NodeStatus};

const MAL_SPEC: &str = r#"
{
  "name": "mal",
  "endian": "little",
  "max_depth": 3,
  "max_frame": 1024,
  "root": "frame",
  "structs": {
    "frame": [
      {"name": "kind", "type": "int", "bytes": 1},
      {"name": "plen", "type": "int", "bytes": 2},
      {"name": "payload", "type": "bytes", "length": "$plen"},
      {"name": "tail", "type": "int", "bytes": 1}
    ]
  }
}
"#;

#[test]
fn length_field_cannot_escape_parent_boundary() {
    let proto = load(MAL_SPEC);
    // 声称 payload 有 70000 字节，但帧只有 5 字节，属于“违反协议”而非“还没收全”
    let mut frame = vec![1u8];
    frame.extend_from_slice(&70000u32.to_le_bytes()[..2]);
    frame.extend_from_slice(b"ab");
    frame.push(0x00);
    let r = frame_lab::parser::parse(&proto, &frame);
    let e = r.error.as_ref().expect("应失败");
    assert_eq!(e.kind, FailKind::Violation);
    assert!(
        e.message.contains("malicious-length") || e.message.contains("bounds"),
        "{}", e.message
    );
    assert_eq!(e.path, p(&["payload"]));
    // 深度解析到的 payload 节点仍被保留
    let payload = find_path(root(&r), &p(&["payload"])).unwrap();
    assert_eq!(payload.start, 3);
}

#[test]
fn oversized_but_within_input_is_not_flagged() {
    let proto = load(MAL_SPEC);
    // plen=4，payload 4 字节，后面还有 tail：合法
    let mut frame = vec![1u8, 4u8, 0u8];
    frame.extend_from_slice(b"abcd");
    frame.push(0x7e);
    let r = frame_lab::parser::parse(&proto, &frame);
    assert_eq!(r.status, NodeStatus::Ok, "{:?}", r.error);
    assert_eq!(r.consumed, 8);
}

#[test]
fn honest_short_declaration_is_incomplete_not_violation() {
    let proto = load(MAL_SPEC);
    // plen=100，而输入只有 6 字节 —— 可能是输入没收全
    let mut frame = vec![1u8, 100u8, 0u8];
    frame.extend_from_slice(b"abc");
    let r = frame_lab::parser::parse(&proto, &frame);
    let e = r.error.as_ref().expect("应不完整");
    assert_eq!(e.kind, FailKind::Incomplete);
    assert!(e.need_total.unwrap() >= 3 + 100 + 1);
    assert_eq!(e.path, p(&["payload"]));
}

const REC_SPEC: &str = r#"
{
  "name": "rec",
  "endian": "big",
  "max_depth": 3,
  "root": "node",
  "structs": {
    "node": [
      {"name": "has_next", "type": "int", "bytes": 1},
      {"name": "code", "type": "int", "bytes": 1},
      {"name": "next", "type": "struct", "struct": "node",
       "when": {"field": "has_next", "equals": 1}}
    ]
  }
}
"#;

#[test]
fn recursive_struct_respects_depth_limit() {
    let proto = load(REC_SPEC);
    // 每层 2 字节；超过 max_depth=3 后第 4 层为 violation
    let frame = vec![1u8, 0, 1, 0, 1, 0, 1, 0, 0, 0];
    let r = frame_lab::parser::parse(&proto, &frame);
    let e = r.error.as_ref().expect("应触发深度上限");
    assert_eq!(e.kind, FailKind::Violation);
    assert!(e.message.contains("depth-limit"), "{}", e.message);
    // 最深路径恰好是第 4 层 node/next...
    let depth = e.path.iter().filter(|s| s.as_str() == "next").count();
    assert!(depth >= 2, "路径 {:?} 应指向深层 next", e.path);
    // 部分树仍然保留
    assert!(r.tree.is_some());
}

#[test]
fn recursion_within_limit_succeeds() {
    let proto = load(REC_SPEC);
    let frame = vec![1u8, 0, 1, 0, 0, 9];
    let r = frame_lab::parser::parse(&proto, &frame);
    assert_eq!(r.status, NodeStatus::Ok, "{:?}", r.error);
}

#[test]
fn nested_child_cannot_claim_beyond_parent_boundary() {
    // array 中每个元素的 payload 巨大：恶意长度不能带出 array/root
    let spec = r#"
    {
      "name": "arr", "endian": "big", "max_frame": 512, "root": "frame",
      "structs": {
        "frame": [
          {"name": "count", "type": "int", "bytes": 1},
          {"name": "items", "type": "array", "struct": "part", "count": "$count"}
        ],
        "part": [
          {"name": "plen", "type": "int", "bytes": 1},
          {"name": "data", "type": "bytes", "length": "$plen"}
        ]
      }
    }
    "#;
    let proto = load(spec);
    let frame = vec![2u8, 250u8, b'x', 200u8, b'y'];
    let r = frame_lab::parser::parse(&proto, &frame);
    let e = r.error.as_ref().unwrap();
    assert_eq!(e.kind, FailKind::Violation);
    assert!(e.message.contains("malicious-length") || e.message.contains("bounds"));
    assert!(e.path.join("/").contains("items"));
}
