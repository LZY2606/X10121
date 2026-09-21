//! Single-byte corruption must land on a stable, meaningful field path.

mod common;

use common::*;
use frame_lab::parser::{parse, Status};
use std::collections::HashMap;

#[test]
fn corrupting_one_byte_reports_deterministic_field_path() {
    let spec = demo_spec();
    let frame = legal_demo_frame(&[0x11, 0x22, 0x33, 0x44], 3);

    // Parse twice with identical corruption: results must be byte-identical.
    for index in 0..frame.len() {
        let mut a = frame.clone();
        a[index] ^= 0xA5;
        let ra = parse(&spec, &a);
        let rb = parse(&spec, &a);
        assert_eq!(
            serde_json::to_value(&ra).unwrap(),
            serde_json::to_value(&rb).unwrap(),
            "non-deterministic parse at byte {}",
            index
        );
    }

    // Each byte's corruption maps to the field that owns it (or a downstream
    // checksum), never to an empty path.
    let mut owners: HashMap<usize, String> = HashMap::new();
    for (index, _byte) in frame.iter().enumerate() {
        let mut broken = frame.clone();
        broken[index] ^= 0x01;
        let result = parse(&spec, &broken);
        let path = match result.status {
            Status::Error => result.error.unwrap().path,
            Status::Incomplete => result.incomplete.unwrap().path,
            Status::Complete => panic!(
                "flipping byte {} did not change the verdict at all",
                index
            ),
        };
        assert!(path.starts_with("Frame."), "path must start at root: {}", path);
        owners.insert(index, path);
    }

    // Magic bytes corrupt to a constant violation on Frame.magic.
    assert_eq!(owners[&1], "Frame.magic");
    assert_eq!(owners[&2], "Frame.magic");

    // Payload and header corruption that slips past the constant is caught by
    // the checksum (the deepest check in the frame).
    for payload_offset in 5..8 {
        assert_eq!(owners[&payload_offset], "Frame.crc");
    }
}

#[test]
fn corruption_locations_are_offsets_within_input() {
    let spec = demo_spec();
    let frame = legal_demo_frame(&[0x55, 0x66], 0);
    for index in 0..frame.len() {
        let mut broken = frame.clone();
        broken[index] ^= 0xFF;
        let result = parse(&spec, &broken);
        if let Some(err) = result.error {
            assert!(err.offset <= frame.len());
        }
    }
}
