use frame_lab::bytes::ByteWriter;
use frame_lab::{parser, spec};

const SPEC: &str = r#"
{
  "name": "smoke",
  "root": "frame",
  "structs": {
    "frame": {
      "fields": [
        {"name": "soi", "type": "int", "width": 1, "expect": 170},
        {"name": "count", "type": "int", "width": 1},
        {"name": "payload", "type": "bytes", "length": {"field": "count"}},
        {"name": "checksum", "type": "checksum", "alg": "sum8", "from": "soi", "to": "eoi", "skip_self": true}
      ]
    }
  }
}
"#;

#[test]
fn valid_frame_parses_and_checksum_covers_self_exclusion() {
    let p = spec::compile(SPEC).unwrap();
    let payload = [1u8, 2, 3];
    let mut w = ByteWriter::new();
    w.u8(0xaa).u8(payload.len() as u8).bytes(&payload);
    let covered: Vec<u8> = w.as_slice().to_vec();
    w.u8(parser::checksum_fix_byte(
        frame_lab::spec::ChecksumAlg::Sum8,
        &covered,
    ));
    let result = parser::parse(&p, w.as_slice());
    if let Some(v) = &result.violation { eprintln!("VIOL: {} {} {}", v.code, v.path, v.message); }
    assert_eq!(result.outcome, parser::Outcome::Complete);
    assert!(result.violation.is_none());
}

#[test]
fn truncation_is_incomplete_with_lower_bound() {
    let p = spec::compile(SPEC).unwrap();
    let result = parser::parse(&p, &[0xaa, 0x05, 0x01]);
    assert_eq!(result.outcome, parser::Outcome::Incomplete);
    let inc = result.incomplete.unwrap();
    assert!(inc.need_at_least >= 3);
    assert_eq!(inc.path, "frame.payload");
}
