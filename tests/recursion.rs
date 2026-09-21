//! Configurable recursion depth limit for nested structures.

mod common;

use frame_lab::encoder::encode;
use frame_lab::parser::{parse, Status};
use frame_lab::spec::{RawSpec, Spec};
use serde_json::{json, Value};

fn nested_spec(max_depth: usize, levels: usize) -> (Spec, Value) {
    // chain0 -> chain1 -> ... a self-similar nesting.
    let mut structs = Vec::new();
    for i in 0..levels {
        let child = format!("chain{}", i + 1);
        let mut fields = vec![json!({"name": "v", "type": "int", "width": 1})];
        if i + 1 < levels {
            fields.push(json!({
                "name": "next", "type": "struct", "struct_name": child
            }));
        }
        structs.push(json!({
            "name": format!("chain{}", i),
            "fields": fields
        }));
    }
    let doc = json!({
        "name": "nested",
        "root": "chain0",
        "endian": "big",
        "max_depth": max_depth,
        "structs": structs
    });
    let raw: RawSpec = serde_json::from_value(doc).unwrap();
    let spec = Spec::compile(raw).expect("spec must compile within configured depth");

    let mut value = json!({"v": 0});
    // Build nested values innermost-out.
    for _ in 0..levels.saturating_sub(1) {
        value = json!({"v": 0, "next": value});
    }
    (spec, value)
}

#[test]
fn depth_within_limit_parses() {
    let (spec, value) = nested_spec(6, 4);
    let frame = encode(&spec, &value).unwrap();
    let result = parse(&spec, &frame);
    assert_eq!(result.status, Status::Complete, "{:?}", result.error);
}

#[test]
fn depth_beyond_limit_is_error_with_path_and_offset() {
    // max_depth 3 but the data nests 5 deep.
    let (spec, value) = nested_spec(8, 5);
    let frame = encode(&spec, &value).unwrap();
    // Recompile with a stricter limit (same structure).
    let strict_spec = {
        let mut raw = spec.raw.clone();
        raw.max_depth = Some(3);
        Spec::compile(raw).unwrap()
    };
    let result = parse(&strict_spec, &frame);
    assert_eq!(result.status, Status::Error);
    let err = result.error.unwrap();
    assert!(err.path.contains("next"), "path should name the nested struct: {}", err.path);
    assert!(err.message.contains("recursion depth limit"));
    assert!(err.offset <= frame.len());
}

#[test]
fn compile_rejects_protocol_that_cannot_fit_depth_budget() {
    // Direct self-recursion can never succeed at a finite depth.
    let doc = json!({
        "name": "selfrec",
        "root": "node",
        "endian": "big",
        "max_depth": 4,
        "structs": [{
            "name": "node",
            "fields": [
                {"name": "v", "type": "int", "width": 1},
                {"name": "child", "type": "struct", "struct_name": "node",
                 "when": {"kind": "flag", "field": "has_child"}},
                {"name": "has_child", "type": "int", "width": 1}
            ]
        }]
    });
    let raw: RawSpec = serde_json::from_value(doc).unwrap();
    let err = Spec::compile(raw).unwrap_err();
    assert!(err.iter().any(|e| e.contains("recursion") || e.contains("max_depth")));
}
