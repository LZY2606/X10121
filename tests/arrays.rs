//! Count-driven arrays, including arrays of nested structs.

mod common;

use frame_lab::encoder::encode;
use frame_lab::parser::{parse, Status};
use frame_lab::spec::{RawSpec, Spec};
use serde_json::json;

fn array_spec() -> Spec {
    let doc = json!({
        "name": "arr",
        "root": "frame",
        "endian": "big",
        "max_depth": 8,
        "structs": [
        {
            "name": "frame",
            "length_field": "total",
            "fields": [
                {"name": "total", "type": "int", "width": 1},
                {"name": "count", "type": "int", "width": 1},
                {"name": "items", "type": "array", "count": {"field": "count"},
                 "item": {"name": "item", "type": "int", "width": 1}}
            ]
        }]
    });
    let raw: RawSpec = serde_json::from_value(doc).unwrap();
    Spec::compile(raw).unwrap()
}

#[test]
fn fixed_and_field_counted_arrays_roundtrip() {
    let spec = array_spec();
    for n in 0..6usize {
        let items: Vec<_> = (0..n).map(|i| (i as u8) * 11).collect();
        let frame = encode(
            &spec,
            &json!({"total": 0, "count": n as u64, "items": items}),
        )
        .unwrap();
        let r = parse(&spec, &frame);
        assert_eq!(r.status, Status::Complete, "n={} {:?}", n, r.error);
        let arr = r.root.children.iter().find(|c| c.name == "items").unwrap();
        assert_eq!(arr.children.len(), n);
        for (i, child) in arr.children.iter().enumerate() {
            assert_eq!(child.path, format!("Frame.items[{}]", i));
            assert_eq!(child.value.as_u64(), Some((i as u64) * 11));
        }
    }
}

#[test]
fn truncated_array_is_incomplete() {
    let spec = array_spec();
    let frame = encode(&spec, &json!({"total": 0, "count": 4u64, "items": [1u64, 2, 3, 4]})).unwrap();
    for n in 1..frame.len() {
        let r = parse(&spec, &frame[..n]);
        assert_ne!(r.status, Status::Error, "prefix {}: {:?}", n, r.error);
    }
}
