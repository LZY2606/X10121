//! 内置演示协议与示例帧。

use crate::encoder::Encoder;
use crate::model::ProtocolSpec;
use crate::store::Store;

pub const DEMO_SPEC_JSON: &str = r#"
{
  "name": "演示帧 v1",
  "root": "frame",
  "max_depth": 8,
  "structs": {
    "frame": {
      "fields": [
        { "kind": "int", "name": "magic", "width": 2, "endian": "be", "expect": 48813 },
        { "kind": "int", "name": "type", "width": 1 },
        { "kind": "int", "name": "seq", "width": 2, "endian": "le" },
        { "kind": "int", "name": "len", "width": 2 },
        {
          "kind": "payload",
          "name": "body",
          "length_field": "len"
        },
        {
          "kind": "switch",
          "name": "tail",
          "on": "type",
          "fallback": { "fields": [] },
          "cases": {
            "1": {
              "fields": [
                { "kind": "int", "name": "code", "width": 1 },
                { "kind": "int", "name": "mask", "width": 1 }
              ]
            },
            "2": {
              "fields": [
                {
                  "kind": "struct",
                  "name": "meta",
                  "ty": "meta_t",
                  "length": { "fixed": 3 }
                }
              ]
            }
          }
        },
        {
          "kind": "checksum",
          "name": "crc",
          "width": 4,
          "algorithm": "crc32",
          "endian": "be"
        }
      ]
    },
    "meta_t": {
      "fields": [
        { "kind": "int", "name": "ver", "width": 1 },
        { "kind": "int", "name": "flags", "width": 1 },
        { "kind": "int", "name": "idx", "width": 1 }
      ]
    }
  }
}
"#;

pub const TLV_SPEC_JSON: &str = r#"
{
  "name": "递归 TLV 树",
  "root": "tlv",
  "max_depth": 4,
  "structs": {
    "tlv": {
      "fields": [
        { "kind": "int", "name": "tag", "width": 1 },
        { "kind": "int", "name": "len", "width": 1 },
        {
          "kind": "switch",
          "name": "content",
          "on": "tag",
          "fallback": {
            "fields": [
              { "kind": "payload", "name": "value", "length_field": "len" }
            ]
          },
          "cases": {
            "1": {
              "fields": [
                {
                  "kind": "vector",
                  "name": "children",
                  "bounded": { "field": "len" },
                  "element": {
                    "kind": "struct",
                    "name": "child",
                    "ty": "tlv"
                  }
                }
              ]
            }
          }
        }
      ]
    }
  }
}
"#;

pub fn demo_spec() -> ProtocolSpec {
    crate::json::Json::parse(DEMO_SPEC_JSON).and_then(|j| ProtocolSpec::from_json(&j)).expect("内置演示协议合法")
}

pub fn tlv_spec() -> ProtocolSpec {
    crate::json::Json::parse(TLV_SPEC_JSON).and_then(|j| ProtocolSpec::from_json(&j)).expect("内置 TLV 协议合法")
}

/// 生成一个合法演示帧（type=2，含定界子结构）。
pub fn demo_frame() -> Vec<u8> {
    let spec = demo_spec();
    let payload = b"hello-lab";
    use crate::json::{obj, Json};
    let value = obj(vec![
        ("magic", Json::from_u64(48813)),
        ("type", Json::from_u64(2)),
        ("seq", Json::from_u64(7)),
        ("len", Json::from_u64(payload.len() as u64)),
        ("body", Json::string(crate::encoder::encode_hex(payload))),
        (
            "tail",
            obj(vec![
                ("case", Json::from_u64(2)),
                (
                    "value",
                    obj(vec![(
                        "meta",
                        obj(vec![
                            ("ver", Json::from_u64(1)),
                            ("flags", Json::from_u64(0)),
                            ("idx", Json::from_u64(9)),
                        ]),
                    )]),
                ),
            ]),
        ),
    ]);
    Encoder::new(&spec)
        .encode(&value)
        .expect("内置演示帧可编码")
}

/// 首次启动时保存内置协议版本（已存在则幂等）。
pub fn seed_demo_protocol(store: &Store) -> Result<(), String> {
    store.save_protocol(&demo_spec())?;
    store.save_protocol(&tlv_spec())?;
    Ok(())
}
