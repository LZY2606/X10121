#![allow(dead_code)]

use frame_lab::protocol::{
    ChecksumAlgo, CondOp, Endian, Field, LengthOf, Protocol, Severity, When,
};
use std::collections::BTreeMap;

/// 带长度驱动 payload + 自排除校验和的协议。
pub fn len_frame_protocol() -> Protocol {
    let frame = vec![
        Field::Int {
            name: "soh".to_string(),
            width: 1,
            endian: Endian::Big,
            expect: Some(serde_json::json!(0xa5)),
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
            width: 1,
            algo: ChecksumAlgo::Sum8,
            covers: vec!["soh".to_string(), "length".to_string(), "payload".to_string()],
            skip_self: true,
            mismatch: Severity::Error,
            when: vec![],
        },
    ];
    let body = vec![
        Field::Int {
            name: "kind".to_string(),
            width: 1,
            endian: Endian::Big,
            expect: None,
            when: vec![],
        },
        Field::Int {
            name: "n".to_string(),
            width: 1,
            endian: Endian::Big,
            expect: None,
            when: vec![],
        },
        Field::Bytes {
            name: "data".to_string(),
            len: LengthOf::Field {
                field: "n".to_string(),
                adjust: 0,
            },
            when: vec![],
        },
    ];
    let mut structs = BTreeMap::new();
    structs.insert("frame".to_string(), frame);
    structs.insert("body".to_string(), body);
    Protocol {
        name: "长度协议".to_string(),
        description: String::new(),
        root: "frame".to_string(),
        max_depth: 4,
        structs,
    }
}

/// 条件子结构协议：type==1 才有 ext。
pub fn conditional_protocol() -> Protocol {
    let frame = vec![
        Field::Int {
            name: "t".to_string(),
            width: 1,
            endian: Endian::Big,
            expect: None,
            when: vec![],
        },
        Field::Bytes {
            name: "ext".to_string(),
            len: LengthOf::Fixed { len: 2 },
            when: vec![When {
                field: "t".to_string(),
                op: CondOp::Eq,
                value: serde_json::json!(1),
            }],
        },
    ];
    let mut structs = BTreeMap::new();
    structs.insert("frame".to_string(), frame);
    Protocol {
        name: "条件协议".to_string(),
        description: String::new(),
        root: "frame".to_string(),
        max_depth: 4,
        structs,
    }
}

/// 递归 Ref 协议（链），用于深度上限测试。
pub fn recursive_protocol(max_depth: usize) -> Protocol {
    let node = vec![
        Field::Int {
            name: "tag".to_string(),
            width: 1,
            endian: Endian::Big,
            expect: None,
            when: vec![],
        },
        Field::Int {
            name: "more".to_string(),
            width: 1,
            endian: Endian::Big,
            expect: None,
            when: vec![],
        },
        Field::Ref {
            name: "next".to_string(),
            struct_ref: "node".to_string(),
            when: vec![When {
                field: "more".to_string(),
                op: CondOp::Eq,
                value: serde_json::json!(1),
            }],
        },
    ];
    let mut structs = BTreeMap::new();
    structs.insert("node".to_string(), node);
    Protocol {
        name: "递归协议".to_string(),
        description: String::new(),
        root: "node".to_string(),
        max_depth,
        structs,
    }
}

/// xor8 校验和协议：covers 为空（覆盖整个父结构，含校验和自身）。
pub fn xor_protocol(skip_self: bool) -> Protocol {
    let frame = vec![
        Field::Int {
            name: "a".to_string(),
            width: 1,
            endian: Endian::Big,
            expect: None,
            when: vec![],
        },
        Field::Int {
            name: "b".to_string(),
            width: 1,
            endian: Endian::Big,
            expect: None,
            when: vec![],
        },
        Field::Checksum {
            name: "xor".to_string(),
            width: 1,
            algo: ChecksumAlgo::Xor8,
            covers: vec![],
            skip_self,
            mismatch: Severity::Error,
            when: vec![],
        },
    ];
    let mut structs = BTreeMap::new();
    structs.insert("frame".to_string(), frame);
    Protocol {
        name: "异或协议".to_string(),
        description: String::new(),
        root: "frame".to_string(),
        max_depth: 4,
        structs,
    }
}

/// 简单确定性伪随机（xorshift），保证测试可复现。
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Rng(seed ^ 0x9e3779b97f4a7c15)
    }
    pub fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545f4914f6cdd1d)
    }
    pub fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    pub fn byte(&mut self) -> u8 {
        (self.next() & 0xff) as u8
    }
}

/// 找到解析树中指定名称（含路径前缀）的节点。
pub fn find_node<'a>(root: &'a frame_lab::parser::Node, path: &[&str]) -> Option<&'a frame_lab::parser::Node> {
    let mut cur = root;
    for name in path {
        cur = cur.children.iter().find(|c| c.name == *name)?;
    }
    Some(cur)
}
