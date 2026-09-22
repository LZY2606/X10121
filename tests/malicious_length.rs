//! 恶意长度字段：声称的长度不能把解析带出父结构边界。
#[allow(dead_code)]
mod common;

use common::*;
use frame_lab::model::Status;
use frame_lab::parser;
use frame_lab::spec::Spec;

fn build_legal() -> Vec<u8> {
    // body = blen(1)+plen(1)+payload(3)+pad(1) = 6；frame_len = 1+1+6+1 = 9
    let spec = Spec::from_json(&malicious_spec_json()).unwrap();
    let v = parse_json(
        r#"{
          "soi": 170, "frame_len": 9,
          "body": { "blen": 6, "plen": 3, "payload": "112233", "pad": 0 }
        }"#,
    );
    frame_lab::encoder::encode(&spec, &v).unwrap()
}

#[test]
fn legal_malicious_protocol_frame_is_ok() {
    let spec = Spec::from_json(&malicious_spec_json()).unwrap();
    let bytes = build_legal();
    let r = parser::parse(&spec, &bytes);
    assert_eq!(r.status, Status::Ok, "{:?}", r.error.map(|e| e.message));
}

#[test]
fn oversized_plen_is_violation_not_oob_read() {
    let spec = Spec::from_json(&malicious_spec_json()).unwrap();
    let mut bytes = build_legal();
    // 布局：0 soi, 1 frame_len, 2 blen, 3 plen, 4..7 payload, 7 pad, 8 chk
    // plen 在偏移 3：从 3 改成恶意的 250
    bytes[3] = 250;
    let r = parser::parse(&spec, &bytes);
    assert_eq!(r.status, Status::Violation);
    let e = r.error.unwrap();
    assert!(
        e.code == "length_out_of_bounds" || e.code == "field_out_of_bounds",
        "应被父边界拦截，实际 code={}",
        e.code
    );
    // payload 的声明长度直接顶破 body 的硬边界
    assert!(
        e.path.contains("payload"),
        "路径应指向越界的 payload：{}",
        e.path
    );
    // 偏移不得超出输入长度（解析器绝不能越界读）
    assert!(e.offset <= bytes.len());
}

#[test]
fn oversized_frame_len_is_incomplete_within_parent_input() {
    let spec = Spec::from_json(&malicious_spec_json()).unwrap();
    let mut bytes = build_legal();
    // frame_len 在偏移 1：9 -> 200；输入不足 => incomplete，而不是越界
    bytes[1] = 200;
    let r = parser::parse(&spec, &bytes);
    assert_eq!(r.status, Status::Incomplete);
    let e = r.error.unwrap();
    assert_eq!(e.kind, "incomplete");
    assert!(e.need.unwrap() >= 1);
}

#[test]
fn inner_length_never_exceeds_parent_hard_bound_on_generated_data() {
    // 生成数据：随机 plen 与 frame_len 的组合，解析器绝不 panic / 越界，
    // 且任何 violation 的 offset 都不超过输入长度。
    let spec = Spec::from_json(&malicious_spec_json()).unwrap();
    let base = build_legal();
    let mut rng = Rng::new(777);
    for _ in 0..200 {
        let mut b = base.clone();
        b[1] = rng.byte(); // frame_len
        b[2] = rng.byte(); // blen
        b[3] = rng.byte(); // plen
        let r = parser::parse(&spec, &b);
        if let Some(e) = &r.error {
            assert!(e.offset <= b.len(), "错误偏移越界：{:?}", e);
        }
        let tree = r.tree.as_ref().unwrap();
        // 根结构覆盖绝不能超过合理的声明上界（最多 255）
        assert!(tree.end <= 256, "解析被带出到 {} ", tree.end);
    }
}

#[test]
fn length_fields_only_reference_earlier_fields_in_same_struct() {
    // 无效描述：bytes 引用了不存在/不可见的长度字段 => 拒绝保存（Spec 校验/解析失败）
    let bad = parse_json(
        r#"{
          "name": "坏描述",
          "root": "f",
          "max_depth": 4,
          "structs": [
            { "name": "f", "fields": [
              { "name": "x", "type": "bytes", "length": "never" }
            ] }
          ]
        }"#,
    );
    let spec = Spec::from_json(&bad).unwrap(); // 结构合法但引用在运行时不可解析
    let r = parser::parse(&spec, &[0u8; 4]);
    assert_eq!(r.status, Status::Violation);
    assert_eq!(r.error.unwrap().code, "length_unresolved");
}
