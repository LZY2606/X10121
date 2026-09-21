mod common;
use common::*;

use frame_lab::bytes::ByteWriter;
use frame_lab::{parser, spec};

#[test]
fn malicious_body_length_cannot_escape_parent() {
    let p = spec::compile(frame_lab::demo::DEMO_PROTOCOL).unwrap();
    // body_len 声明巨大，但实际帧很短：属于违反协议，最深路径落在 body。
    let mut w = ByteWriter::new();
    w.u8(0xaa).u16_be(1).u16_be(0xffff).u8(0x01);
    let frame = w.into_vec();
    let result = parser::parse(&p, &frame);
    assert_eq!(result.outcome, parser::Outcome::Incomplete);
    let inc = result.incomplete.unwrap();
    assert!(inc.path.contains("frame.body"));

    // 声明长度越过父结构边界（带 eoi+checksum 但 body 声明超过剩余空间）：
    // body_len=0xff00，后面只给 3 字节，必须稳定报错而不是越界。
    let mut w = ByteWriter::new();
    w.u8(0xaa).u16_be(1).u16_be(0xff00).bytes(&[1, 2, 3]).u8(0xbb).u8(0x00);
    let result = parser::parse(&p, w.as_slice());
    assert!(matches!(result.outcome, parser::Outcome::Incomplete | parser::Outcome::Error));
    let path = result
        .violation
        .as_ref()
        .map(|v| v.path.clone())
        .or_else(|| result.incomplete.as_ref().map(|i| i.path.clone()))
        .unwrap();
    assert!(path.starts_with("frame.body"), "错误路径 {path} 未落到 body");
}

#[test]
fn value_length_cannot_escape_bounded_body() {
    let p = spec::compile(frame_lab::demo::DEMO_PROTOCOL).unwrap();
    // body 声明 3 字节：item_count=1, tag=1, value_len=200 —— 越界即 violation。
    let mut w = ByteWriter::new();
    w.u8(0xaa).u16_be(1).u16_be(3).bytes(&[0x01, 0x01, 0xc8]);
    w.u8(0xbb).u8(0x00);
    let result = parser::parse(&p, w.as_slice());
    assert_eq!(result.outcome, parser::Outcome::Error);
    let v = result.violation.unwrap();
    assert_eq!(v.code, "length_out_of_bounds");
    assert!(v.path.contains("items[0].value"), "实际路径 {}", v.path);
}

#[test]
fn recursion_depth_is_capped() {
    let p = spec::compile(frame_lab::demo::DEMO_PROTOCOL).unwrap();
    // max_depth=8：构造 12 层嵌套必然超限。
    let frame = deep_nesting_frame(12);
    let result = parser::parse(&p, &frame);
    assert_eq!(result.outcome, parser::Outcome::Error);
    let v = result.violation.expect("必须报告递归上限");
    assert_eq!(v.code, "recursion_limit");
    assert!(v.path.contains("children"), "路径 {}", v.path);

    // 同样输入重复解析路径稳定。
    let again = parser::parse(&p, &frame).violation.unwrap();
    assert_eq!(again.path, v.path);
    assert_eq!(again.offset, v.offset);
}

#[test]
fn checksum_self_exclusion_makes_legal_frame_validate() {
    let p = spec::compile(frame_lab::demo::DEMO_PROTOCOL).unwrap();
    let frame = sample_frame();
    let result = parser::parse(&p, &frame);
    assert_eq!(result.outcome, parser::Outcome::Complete);
    // 手工把 checksum 改成 0：应失败且定位到 checksum 字段。
    let mut broken = frame.clone();
    let last = broken.len() - 1;
    broken[last] = 0;
    let result = parser::parse(&p, &broken);
    assert_eq!(result.outcome, parser::Outcome::Error);
    let v = result.violation.unwrap();
    assert_eq!(v.code, "checksum_mismatch");
    assert_eq!(v.path, "frame.checksum");
    assert_eq!(v.offset, last);
}

#[test]
fn checksum_without_self_exclusion_has_distinct_semantics() {
    // 一个把 skip_self 关掉的简单协议：checksum 字节也参与裸 sum（校验值需自洽）。
    let spec_text = r#"{
      "name": "cs-inclusive",
      "root": "f",
      "structs": {
        "f": { "fields": [
          {"name": "a", "type": "int", "width": 1},
          {"name": "b", "type": "int", "width": 1},
          {"name": "cs", "type": "checksum", "alg": "sum8", "from": "soi", "to": "eoi", "skip_self": false}
        ]}
      }
    }"#;
    let p = spec::compile(spec_text).unwrap();
    // skip_self=false 时我们的约定是“补码”；要让整段含 cs 相加为 0，cs 同样是 -(a+b)。
    let frame = [0x01u8, 0x02u8, 0xfd];
    let result = parser::parse(&p, &frame);
    assert_eq!(result.outcome, parser::Outcome::Complete);
    // 若改为跳过自身则该字节布局不再自洽（对照：破坏后报错）。
    let broken = [0x01u8, 0x02u8, 0x00];
    let result = parser::parse(&p, &broken);
    assert_eq!(result.outcome, parser::Outcome::Error);
}

#[test]
fn expect_violation_pins_constant_field() {
    let p = spec::compile(frame_lab::demo::DEMO_PROTOCOL).unwrap();
    let mut frame = sample_frame();
    frame[0] = 0x00; // SOI
    let result = parser::parse(&p, &frame);
    assert_eq!(result.outcome, parser::Outcome::Error);
    let v = result.violation.unwrap();
    assert_eq!(v.code, "expect_mismatch");
    assert_eq!(v.path, "frame.soi");
    assert_eq!(v.offset, 0);
}
