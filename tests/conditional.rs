//! Conditional fields and sub-structures driven by earlier fields.

mod common;

use frame_lab::encoder::encode;
use frame_lab::parser::{parse, Status};
use frame_lab::spec::{RawSpec, Spec};
use serde_json::json;

fn cond_spec() -> Spec {
    let doc = json!({
        "name": "cond",
        "root": "frame",
        "endian": "big",
        "max_depth": 8,
        "structs": [
        {
            "name": "frame",
            "length_field": "total",
            "fields": [
                {"name": "total", "type": "int", "width": 1},
                {"name": "kind", "type": "int", "width": 1},
                {"name": "extended", "type": "struct", "struct_name": "ext",
                 "when": {"kind": "eq", "field": "kind", "value": 1}},
                {"name": "tail", "type": "int", "width": 1}
            ]
        },
        {
            "name": "ext",
            "fields": [
                {"name": "ext_len", "type": "int", "width": 1},
                {"name": "ext_data", "type": "bytes", "length": {"field": "ext_len"}}
            ]
        }]
    });
    let raw: RawSpec = serde_json::from_value(doc).unwrap();
    Spec::compile(raw).unwrap()
}

#[test]
fn conditional_substructure_appears_and_disappears() {
    let spec = cond_spec();

    // kind=1 => ext present: total, kind, ext_len, data, tail
    let with_ext = encode(
        &spec,
        &json!({"total": 0, "kind": 1, "extended": {"ext_len": 2, "ext_data": "aabb"}, "tail": 0x77}),
    )
    .unwrap();
    let r = parse(&spec, &with_ext);
    assert_eq!(r.status, Status::Complete, "{:?}", r.error);
    let names: Vec<&str> = r.root.children.iter().map(|n| n.name.as_str()).collect();
    assert_eq!(names, vec!["total", "kind", "extended", "tail"]);
    assert_eq!(with_ext[0] as usize, with_ext.len());

    // kind=0 => ext skipped; frame is shorter.
    let without_ext = encode(&spec, &json!({"total": 0, "kind": 0, "tail": 0x88})).unwrap();
    let r2 = parse(&spec, &without_ext);
    assert_eq!(r2.status, Status::Complete, "{:?}", r2.error);
    let names: Vec<&str> = r2.root.children.iter().map(|n| n.name.as_str()).collect();
    assert_eq!(names, vec!["total", "kind", "tail"]);
    assert_eq!(without_ext.len(), 3);
}

#[test]
fn truncating_conditional_frame_is_incomplete_not_error() {
    let spec = cond_spec();
    let frame = encode(
        &spec,
        &json!({"total": 0, "kind": 1, "extended": {"ext_len": 3, "ext_data": "010203"}, "tail": 9}),
    )
    .unwrap();
    for n in 1..frame.len() {
        let r = parse(&spec, &frame[..n]);
        assert_ne!(r.status, Status::Error, "prefix {} errored: {:?}", n, r.error);
        assert_ne!(r.status, Status::Complete);
    }
    let full = parse(&spec, &frame);
    assert_eq!(full.status, Status::Complete);
}
