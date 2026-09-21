//! Encoder-generated legal frames must parse to completion.

mod common;

use common::*;
use frame_lab::parser::{parse, Status};

#[test]
fn generated_legal_frames_parse() {
    let spec = demo_spec();
    for seed in 0u8..32 {
        let payload: Vec<u8> = (0..seed % 9).map(|i| i.wrapping_mul(7).wrapping_add(seed)).collect();
        let frame = legal_demo_frame(&payload, seed as u64 % 4);
        let result = parse(&spec, &frame);
        assert_eq!(
            result.status,
            Status::Complete,
            "seed {}: {:?} frame={:02x?}",
            seed,
            result.error,
            frame
        );
        assert!(result.error.is_none());
        assert_eq!(result.root.end, frame.len());
        assert!(result.byte_map.iter().all(Option::is_some), "every byte maps to a field");
    }
}

#[test]
fn byte_maps_cover_whole_frame() {
    let spec = demo_spec();
    let frame = legal_demo_frame(&[0x10, 0x20, 0x30, 0x40], 1);
    let result = parse(&spec, &frame);
    for (i, owner) in result.byte_map.iter().enumerate() {
        assert!(owner.is_some(), "byte {} unclaimed", i);
    }
    // Payload bytes must belong to the payload node specifically.
    let payload_node = result
        .root
        .children
        .iter()
        .find(|n| n.name == "payload")
        .unwrap();
    for i in payload_node.start..payload_node.end {
        assert_eq!(result.byte_map[i].as_deref(), Some("Frame.payload"));
    }
}
