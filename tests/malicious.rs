//! Length fields must never pull parsing outside the parent boundary.

mod common;

use frame_lab::parser::{parse, Status};
use frame_lab::spec::{RawSpec, Spec};
use serde_json::json;

fn bounded_spec() -> Spec {
    let raw: RawSpec = serde_json::from_value(json!({
        "name": "bounded",
        "root": "frame",
        "endian": "big",
        "max_depth": 8,
        "structs": [
        {
            "name": "frame",
            "length_field": "total",
            "fields": [
                {"name": "total", "type": "int", "width": 1},
                {"name": "inner", "type": "struct", "struct_name": "inner"}
            ]
        },
        {
            "name": "inner",
            "length_field": "len",
            "fields": [
                {"name": "len", "type": "int", "width": 1},
                {"name": "data_len", "type": "int", "width": 1},
                {"name": "data", "type": "bytes", "length": {"field": "data_len"}}
            ]
        }]
    }))
    .unwrap();
    Spec::compile(raw).unwrap()
}

#[test]
fn inner_length_cannot_escape_outer_boundary() {
    let spec = bounded_spec();
    // outer total = 4 (total + inner's 3 bytes); inner claims len=200.
    // Bytes: total=04, inner.len=200, inner.data_len=1, data=AA
    let malicious = vec![4u8, 200, 1, 0xAA];
    let result = parse(&spec, &malicious);
    assert_eq!(result.status, Status::Incomplete, "child must not read past buffer: {:?}", result.error);
    let inc = result.incomplete.unwrap();
    assert!(inc.need_at_least >= 190);
}

#[test]
fn payload_length_cannot_escape_declared_frame() {
    // Build a frame whose payload_len says 200 while the declared total says 5.
    let raw: RawSpec = serde_json::from_value(json!({
        "name": "evil",
        "root": "frame",
        "endian": "big",
        "max_depth": 8,
        "structs": [{
            "name": "frame",
            "length_field": "total",
            "fields": [
                {"name": "total", "type": "int", "width": 1},
                {"name": "payload_len", "type": "int", "width": 1},
                {"name": "payload", "type": "bytes", "length": {"field": "payload_len"}}
            ]
        }]
    }))
    .unwrap();
    let spec = Spec::compile(raw).unwrap();
    // total=5 => frame spans bytes 0..5; payload_len=200 must be an error,
    // because enough bytes are present to know the declared boundary is 5.
    let data = vec![5u8, 200, 0xAA, 0xBB, 0xCC];
    let result = parse(&spec, &data);
    assert_eq!(result.status, Status::Error);
    let err = result.error.unwrap();
    assert!(err.path.contains("payload"), "path: {}", err.path);
    assert!(err.message.contains("boundary") || err.message.contains("past"), "msg: {}", err.message);
}

#[test]
fn root_total_smaller_than_header_is_error() {
    let raw: RawSpec = serde_json::from_value(json!({
        "name": "small",
        "root": "frame",
        "endian": "big",
        "max_depth": 8,
        "structs": [{
            "name": "frame",
            "length_field": "total",
            "fields": [
                {"name": "total", "type": "int", "width": 1},
                {"name": "a", "type": "int", "width": 4}
            ]
        }]
    }))
    .unwrap();
    let spec = Spec::compile(raw).unwrap();
    // total=2 but the header alone needs 5 bytes.
    let data = vec![2u8, 0, 0, 0, 0];
    let result = parse(&spec, &data);
    assert_eq!(result.status, Status::Error);
    let msg = result.error.unwrap().message; assert!(msg.contains("boundary") || msg.contains("header already occupies"), "{}", msg);
}
