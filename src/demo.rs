use crate::protocol::{
    ChecksumAlgo, CondOp, Endian, Field, LengthOf, Protocol, Severity, When,
};
use std::collections::BTreeMap;

/// 内置演示协议：含长度驱动 payload、条件子结构与自排除校验和。
pub fn protocol() -> Protocol {
    let frame = vec![
        Field::Int {
            name: "soh".to_string(),
            width: 1,
            endian: Endian::Big,
            expect: Some(serde_json::json!(0xa5)),
            when: vec![],
        },
        Field::Int {
            name: "type".to_string(),
            width: 1,
            endian: Endian::Big,
            expect: None,
            when: vec![],
        },
        Field::Int {
            name: "length".to_string(),
            width: 2,
            endian: Endian::Big,
            expect: None,
            when: vec![],
        },
        Field::Payload {
            name: "payload".to_string(),
            len: LengthOf::Field {
                field: "length".to_string(),
                adjust: 0,
            },
            struct_ref: Some("body".to_string()),
        },
        Field::Checksum {
            name: "crc".to_string(),
            width: 2,
            algo: ChecksumAlgo::Sum16Be,
            covers: vec![],
            skip_self: true,
            mismatch: Severity::Warning,
            when: vec![],
        },
    ];

    let body = vec![
        Field::Int {
            name: "channel".to_string(),
            width: 1,
            endian: Endian::Big,
            expect: None,
            when: vec![],
        },
        Field::Int {
            name: "flags".to_string(),
            width: 1,
            endian: Endian::Big,
            expect: None,
            when: vec![],
        },
        Field::Int {
            name: "dlen".to_string(),
            width: 1,
            endian: Endian::Big,
            expect: None,
            when: vec![When {
                field: "flags".to_string(),
                op: CondOp::Eq,
                value: serde_json::json!(1),
            }],
        },
        Field::Bytes {
            name: "data".to_string(),
            len: LengthOf::Field {
                field: "dlen".to_string(),
                adjust: 0,
            },
            when: vec![When {
                field: "flags".to_string(),
                op: CondOp::Eq,
                value: serde_json::json!(1),
            }],
        },
    ];

    let mut structs = BTreeMap::new();
    structs.insert("frame".to_string(), frame);
    structs.insert("body".to_string(), body);

    Protocol {
        name: "演示帧协议".to_string(),
        description: "soh + type + length + 有界 payload(body) + 自排除 CRC16".to_string(),
        root: "frame".to_string(),
        max_depth: 4,
        structs,
    }
}

/// 生成一个演示合法帧与对应编码输入。
pub fn sample_values() -> serde_json::Value {
    serde_json::json!({
        "type": 1,
        "payload": {
            "channel": 7,
            "flags": 1,
            "dlen": 3,
            "data": "010203",
        }
    })
}
