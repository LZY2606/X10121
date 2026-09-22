//! 校验和区间允许跳过自身字段。
#[allow(dead_code)]
mod common;

use common::*;
use frame_lab::model::Status;
use frame_lab::parser;
use frame_lab::spec::Spec;

#[test]
fn sum8_self_exclusion() {
    let spec = Spec::from_json(&checksum_spec_json("sum8")).unwrap();
    // chk = a + b（不含自身）
    let (a, b) = (0x12u8, 0x34u8);
    let chk = sum8(&[a, b]);
    let frame = [a, b, chk];
    let r = parser::parse(&spec, &frame);
    assert_eq!(r.status, Status::Ok, "{:?}", r.error.map(|e| e.message.clone()));

    // 若错误地把自身纳入，校验会失败——证明自排除语义
    let mut bad = frame;
    bad[2] = sum8(&[a, b, chk]); // 含自身的值
    let r2 = parser::parse(&spec, &bad);
    assert_eq!(r2.status, Status::Violation);
    assert_eq!(r2.error.unwrap().code, "checksum_mismatch");
}

#[test]
fn xor8_self_exclusion() {
    let spec = Spec::from_json(&checksum_spec_json("xor8")).unwrap();
    let (a, b) = (0x77u8, 0x9eu8);
    let chk = xor8(&[a, b]);
    let frame = [a, b, chk];
    let r = parser::parse(&spec, &frame);
    assert_eq!(r.status, Status::Ok, "{:?}", r.error.map(|e| e.message.clone()));

    let mut corrupt = frame;
    corrupt[1] ^= 0x01;
    let r2 = parser::parse(&spec, &corrupt);
    assert_eq!(r2.status, Status::Violation);
    let e = r2.error.unwrap();
    assert_eq!(e.path, "$frame.chk");
}

#[test]
fn checksum_field_change_alone_is_detected() {
    let spec = Spec::from_json(&checksum_spec_json("sum8")).unwrap();
    let frame = [0x01, 0x02, 0x03];
    assert_eq!(parser::parse(&spec, &frame).status, Status::Ok);
    for delta in 1u8..=255 {
        let mut bad = frame;
        bad[2] = bad[2].wrapping_add(delta);
        assert_eq!(parser::parse(&spec, &bad).status, Status::Violation);
    }
}

#[test]
fn truncated_checksum_input_is_incomplete() {
    // 覆盖区间需要完整输入；缺失 chk 字段时是 incomplete 而非 mismatch
    let spec = Spec::from_json(&checksum_spec_json("sum8")).unwrap();
    let r = parser::parse(&spec, &[0x01, 0x02]);
    assert_eq!(r.status, Status::Incomplete);
    assert_eq!(r.error.as_ref().unwrap().kind, "incomplete");
}
