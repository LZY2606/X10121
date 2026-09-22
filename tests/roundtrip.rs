//! 编码器生成的合法帧必须能被解析为成功；任意截断只产生 incomplete。
#[allow(dead_code)]
mod common;

use common::*;
use frame_lab::model::Status;
use frame_lab::parser;

#[test]
fn encoded_demo_frame_parses_ok() {
    let spec = demo_spec();
    let bytes = demo_frame();
    let report = parser::parse(&spec, &bytes);
    assert_eq!(report.status, Status::Ok, "应成功：{:?}", report.error.map(|e| e.message));
    assert_eq!(report.consumed, bytes.len());
    assert!(report.warnings.is_empty(), "不应有警告：{:?}", report.warnings);
    let tree = report.tree.as_ref().unwrap();
    // 每个字节都应落在某个字段覆盖内，且总覆盖 = 全长
    assert_eq!(tree.start, 0);
    assert_eq!(tree.end, bytes.len());
}

#[test]
fn every_proper_prefix_is_incomplete() {
    let spec = demo_spec();
    let bytes = demo_frame();
    for cut in 0..bytes.len() {
        let r = parser::parse(&spec, &bytes[..cut]);
        assert_eq!(
            r.status,
            Status::Incomplete,
            "截断到 {cut} 字节应 incomplete，实际 {:?}: {:?}",
            r.status,
            r.error.as_ref().map(|e| (&e.code, &e.path))
        );
        let e = r.error.as_ref().expect("incomplete 必须带错误信息");
        assert_eq!(e.kind, "incomplete");
        // 仍需字节数是一个正下界
        let need = e.need.expect("incomplete 必须给出仍需字节下界");
        assert!(need >= 1, "下界必须为正");
        assert_eq!(cut + need, e.offset + need);
        assert!(cut + need <= bytes.len() + 8, "下界不应远超目标长度");
        // 最深字段路径非空
        assert!(e.path.starts_with('$'));
    }
}

#[test]
fn generated_frames_roundtrip_with_random_payloads() {
    // 生成数据：随机 seq / 3 字节 payload / 二级递归节点值
    let mut rng = Rng::new(20260919);
    let spec = demo_spec();
    for _ in 0..40 {
        let seq = rng.below(0xFFFF) as i64;
        let p = [rng.byte(), rng.byte(), rng.byte()];
        let nv = [rng.byte(), rng.byte()];
        let values = parse_json(&format!(
            r#"{{
              "soi": 170, "frame_len": 19, "kind": 2, "seq": {seq},
              "body": {{
                "clen": 12,
                "payload": "{p0:02x}{p1:02x}{p2:02x}",
                "tail": {{ "marker": 205 }},
                "node": {{
                  "ntype": 1, "nlen": 2, "nval": "{n0:02x}{n1:02x}",
                  "child": {{ "ntype": 9, "nlen": 0, "nval": "" }}
                }}
              }}
            }}"#,
            p0 = p[0],
            p1 = p[1],
            p2 = p[2],
            n0 = nv[0],
            n1 = nv[1],
            seq = seq,
        ));
        let bytes = frame_lab::encoder::encode(&spec, &values).unwrap();
        let report = parser::parse(&spec, &bytes);
        assert_eq!(report.status, Status::Ok, "随机帧应成功：{:?}", report.error.map(|e| e.message));
        assert_eq!(report.consumed, 19);

        // 所有真前缀 incomplete
        for cut in 0..bytes.len() {
            assert_eq!(parser::parse(&spec, &bytes[..cut]).status, Status::Incomplete);
        }
    }
}

#[test]
fn no_violation_and_no_const_mismatch_on_legal_data() {
    let spec = demo_spec();
    let bytes = demo_frame();
    for cut in 0..=bytes.len() {
        let r = parser::parse(&spec, &bytes[..cut]);
        assert_ne!(r.status, Status::Violation, "合法数据的任何前缀都不能是 violation（cut={cut}）");
    }
}
