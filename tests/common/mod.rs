//! Shared builders for generated-data tests.
#![allow(dead_code)]

use frame_lab::encoder::encode;
use frame_lab::parser::{self, Status};
use frame_lab::spec::{RawSpec, Spec};
use serde_json::{json, Value};

pub fn spec_from(value: Value) -> Spec {
    let raw: RawSpec = serde_json::from_value(value).unwrap();
    Spec::compile(raw).unwrap()
}

pub fn demo_spec() -> Spec {
    spec_from(json!({
        "name": "demo",
        "root": "frame",
        "endian": "big",
        "max_depth": 8,
        "structs": [{
            "name": "frame",
            "length_field": "total",
            "fields": [
                {"name": "total", "type": "int", "width": 1},
                {"name": "magic", "type": "int", "width": 2, "expect": 61377},
                {"name": "kind", "type": "int", "width": 1},
                {"name": "payload_len", "type": "int", "width": 1},
                {"name": "payload", "type": "bytes", "length": {"field": "payload_len"}},
                {
                    "name": "crc", "type": "checksum", "algo": "xor8",
                    "cover": [{"from": "magic", "to": {"field": "payload", "edge": "end"}}]
                }
            ]
        }]
    }))
}

pub fn legal_demo_frame(payload: &[u8], kind: u64) -> Vec<u8> {
    let spec = demo_spec();
    let payload_hex: String = payload.iter().map(|b| format!("{:02x}", b)).collect();
    encode(
        &spec,
        &json!({
            "total": 0,
            "magic": 61377,
            "kind": kind,
            "payload_len": payload.len(),
            "payload": payload_hex,
            "crc": 0
        }),
    )
    .unwrap()
}

pub fn assert_truncation_only_incomplete(spec: &Spec, data: &[u8]) {
    for n in 0..data.len() {
        let result = parser::parse(spec, &data[..n]);
        assert_ne!(result.status, Status::Error,
            "prefix of {} bytes produced an error: {:?}", n, result.error);
        assert_ne!(result.status, Status::Complete,
            "prefix of {} bytes reported complete", n);
        if n > 0 {
            let inc = result.incomplete.expect("non-empty prefix must be incomplete");
            assert!(inc.need_at_least >= 1);
            assert!(!inc.path.is_empty());
        }
    }
}
