//! Checksum cover intervals, including intervals that span the checksum field.

mod common;

use frame_lab::encoder::encode;
use frame_lab::parser::{parse, Status};
use frame_lab::spec::{RawSpec, Spec};
use serde_json::{json, Value};

fn build_spec(algo: &str, cover_from: Value, cover_to: Value) -> Spec {
    let doc = json!({
        "name": "crcproto",
        "root": "frame",
        "endian": "big",
        "max_depth": 8,
        "structs": [{
            "name": "frame",
            "length_field": "total",
            "fields": [
                {"name": "total", "type": "int", "width": 1},
                {"name": "a", "type": "int", "width": 1},
                {"name": "b", "type": "int", "width": 1},
                {"name": "crc", "type": "checksum", "algo": algo,
                 "cover": [{"from": cover_from, "to": cover_to}]},
                {"name": "tail", "type": "int", "width": 1}
            ]
        }]
    });
    let raw: RawSpec = serde_json::from_value(doc).unwrap();
    Spec::compile(raw).unwrap()
}

#[test]
fn cover_interval_skips_the_checksums_own_bytes() {
    // Cover the WHOLE frame from a through tail; the crc byte itself must be
    // excluded from the computation.
    let spec = build_spec("xor8", json!("a"), json!({"field": "tail", "edge": "end"}));
    let frame = encode(
        &spec,
        &json!({"total": 0, "a": 0x10, "b": 0x20, "crc": 0, "tail": 0x30}),
    )
    .unwrap();
    let result = parse(&spec, &frame);
    assert_eq!(result.status, Status::Complete, "{:?}", result.error);

    // Manually verify: xor of a, b, tail only (crc byte excluded).
    let expect = 0x10u8 ^ 0x20u8 ^ 0x30u8;
    assert_eq!(frame[3], expect, "encoder self-exclusion mismatch");

    // Corrupting the checksum byte itself is detected (it changes stored value
    // but not the covered computation).
    let mut broken = frame.clone();
    broken[3] ^= 0x7F;
    let r = parse(&spec, &broken);
    assert_eq!(r.status, Status::Error);
    assert_eq!(r.error.unwrap().path, "Frame.crc");
}

#[test]
fn sum8_self_exclusion() {
    let spec = build_spec("sum8", json!("a"), json!({"field": "tail", "edge": "end"}));
    let frame = encode(
        &spec,
        &json!({"total": 0, "a": 0xAB, "b": 0x05, "crc": 0, "tail": 0x10}),
    )
    .unwrap();
    let expect = 0xABu8.wrapping_add(0x05).wrapping_add(0x10);
    assert_eq!(frame[3], expect);
    let result = parse(&spec, &frame);
    assert_eq!(result.status, Status::Complete, "{:?}", result.error);
}

#[test]
fn payload_corruption_is_attributed_to_checksum() {
    // The demo protocol covers magic..payload; flipping a payload byte must
    // fail on the checksum node, never be silently accepted.
    let spec = common::demo_spec();
    let frame = common::legal_demo_frame(&[1, 2, 3, 4], 0);
    let mut broken = frame.clone();
    broken[6] ^= 0xFF;
    let result = parse(&spec, &broken);
    assert_eq!(result.status, Status::Error);
    assert_eq!(result.error.unwrap().path, "Frame.crc");
}
