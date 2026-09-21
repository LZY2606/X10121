//! Every strict prefix of generated legal frames is only ever incomplete.

mod common;

use common::*;

#[test]
fn truncation_is_never_error_or_complete() {
    let spec = demo_spec();
    for len in 0..12usize {
        let payload: Vec<u8> = (0..len).map(|i| ((i as u8).wrapping_mul(31)).wrapping_add(7)).collect();
        let frame = legal_demo_frame(&payload, 2);
        assert_truncation_only_incomplete(&spec, &frame);
    }
}

#[test]
fn need_lower_bound_is_sound() {
    let spec = demo_spec();
    let frame = legal_demo_frame(&[1, 2, 3, 4, 5], 0);
    // Removing exactly `need_at_least` bytes from the end must still leave an
    // incomplete state, and adding them back must succeed.
    let result = parse_full(&spec, &frame);
    assert_eq!(result.status, frame_lab::parser::Status::Complete);
    let cut = &frame[..frame.len() - 1];
    let r = frame_lab::parser::parse(&spec, cut);
    assert_eq!(r.status, frame_lab::parser::Status::Incomplete);
    assert_eq!(r.incomplete.as_ref().unwrap().need_at_least, 1);
}

fn parse_full(spec: &frame_lab::Spec, data: &[u8]) -> frame_lab::parser::ParseResult {
    frame_lab::parser::parse(spec, data)
}

#[test]
fn cstring_within_declared_boundary_needs_terminator_or_errors() {
    use frame_lab::spec::{RawSpec, Spec};
    use frame_lab::parser::{parse, Status};
    // Declared frame: total=5 then a cstring expected to fit with a NUL.
    let raw: RawSpec = serde_json::from_value(serde_json::json!({
        "name": "strframe", "root": "frame", "endian": "big", "max_depth": 8,
        "structs": [{"name": "frame", "length_field": "total", "fields": [
            {"name": "total", "type": "int", "width": 1},
            {"name": "name", "type": "cstring"}
        ]}]
    }))
    .unwrap();
    let spec = Spec::compile(raw).unwrap();

    // Fully populated boundary (5 bytes) with no NUL anywhere -> error.
    let no_nul = vec![5u8, b'a', b'b', b'c', b'd'];
    let r = parse(&spec, &no_nul);
    assert_eq!(r.status, Status::Error);
    assert!(r.error.unwrap().path.ends_with("name"));

    // Prefix that ends before the declared boundary -> incomplete.
    let cut = vec![5u8, b'a', b'b'];
    let r2 = parse(&spec, &cut);
    assert_eq!(r2.status, Status::Incomplete);

    // Open-ended frame (no length field) prefix missing NUL -> incomplete,
    // but a terminated frame is complete.
    let raw_open: RawSpec = serde_json::from_value(serde_json::json!({
        "name": "stropen", "root": "frame", "endian": "big", "max_depth": 8,
        "structs": [{"name": "frame", "fields": [
            {"name": "name", "type": "cstring"}
        ]}]
    }))
    .unwrap();
    let open_spec = Spec::compile(raw_open).unwrap();
    assert_eq!(parse(&open_spec, b"abc").status, Status::Incomplete);
    assert_eq!(parse(&open_spec, b"abc\0").status, Status::Complete);
}
