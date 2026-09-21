mod common;

use common::*;
use frame_lab::encoder;
use frame_lab::json::{self, Value};
use frame_lab::parser::{FailKind, NodeStatus};

#[test]
fn generated_valid_frame_parses_successfully() {
    let proto = load(DEMO_SPEC);
    let input = json::parse(
        r#"{"magic":161,"type":1,"payload":"68656c6c6f"}"#,
    )
    .unwrap();
    let frame = encoder::encode(&proto, &input).expect("编码应成功");
    let expected = demo_frame(b"hello", 1);
    assert_eq!(frame.bytes, expected, "编码器应自动派生 length 与 sum8");

    let r = frame_lab::parser::parse(&proto, &frame.bytes);
    assert_eq!(r.status, NodeStatus::Ok, "成功帧不应有警告/错误: {:?}", r.warnings);
    assert!(r.error.is_none());
    assert_eq!(r.consumed, frame.bytes.len());
    assert_eq!(r.tree.as_ref().unwrap().end, frame.bytes.len());

    let payload = find_path(root(&r), &p(&["payload"])).unwrap();
    assert_eq!(payload.value.as_ref().unwrap().as_str(), Some("68656c6c6f"));
    assert_eq!(payload.start, 3);
    assert_eq!(payload.end, 8);
    let crc = find_path(root(&r), &p(&["crc"])).unwrap();
    assert!(crc.diagnostics.iter().any(|d| d.starts_with("checksum-ok")));

    // 条件字段在 type=1 时缺席
    let trailer = find_path(root(&r), &p(&["trailer"])).unwrap();
    assert_eq!(trailer.status, NodeStatus::Absent);
}

#[test]
fn conditional_field_present_when_guard_matches() {
    let proto = load(DEMO_SPEC);
    let frame = demo_frame(b"ab", 2);
    let r = frame_lab::parser::parse(&proto, &frame);
    assert_eq!(r.status, NodeStatus::Ok, "{:?}", r.error);
    let trailer = find_path(root(&r), &p(&["trailer"])).unwrap();
    assert_eq!(trailer.status, NodeStatus::Ok);
    assert_eq!(trailer.value.as_ref().and_then(|v| v.as_i128()), Some(17));
}

#[test]
fn truncation_never_becomes_violation() {
    let proto = load(DEMO_SPEC);
    let full = demo_frame(&(0u8..40u8).collect::<Vec<_>>(), 1);
    for cut in 0..full.len() {
        let partial = &full[..cut];
        let r = frame_lab::parser::parse(&proto, partial);
        // 空输入以及任何截断都不可能“完整”：因为 magic 至少需要 1 字节。
        let err = r.error
            .as_ref()
            .unwrap_or_else(|| panic!("截断到 {} 字节应当不完整", cut));
        assert_eq!(
            err.kind,
            FailKind::Incomplete,
            "截断 cut={} 不应被判为违反协议: {}",
            cut,
            err.message
        );
        let need = err.need_total.expect("incomplete 必须给出总长下界");
        assert!(need >= full.len(), "下界 {} 至少应为完整长度 {}", need, full.len());
        assert_eq!(need - partial.len(), need.saturating_sub(partial.len()));
        assert!(need > partial.len(), "下界必须大于当前长度");
    }
}

#[test]
fn single_byte_corruption_is_stable_and_localized() {
    let proto = load(DEMO_SPEC);
    let full = demo_frame(b"hello", 1);
    let mut signatures = std::collections::HashSet::new();

    for i in 0..full.len() {
        for &delta in &[1u8, 0x80, 0xff] {
            let mut broken = full.clone();
            broken[i] ^= delta;
            if broken == full {
                continue;
            }
            let r1 = frame_lab::parser::parse(&proto, &broken);
            let r2 = frame_lab::parser::parse(&proto, &broken);
            let e1 = r1.error.as_ref().expect("破坏后必须给出明确结果（或校验和失败）");
            let e2 = r2.error.as_ref().expect("重复解析结果应相同");
            assert_eq!(e1.kind, FailKind::Violation, "破坏字节 {} 不能只是 incomplete", i);
            assert_eq!(e1.path, e2.path, "同一破坏重复解析必须落到相同字段路径");
            assert_eq!(e1.offset, e2.offset);
            assert!(!e1.path.is_empty(), "必须给出最深字段路径");
            // 路径上的叶子字段必须覆盖被破坏的偏移（校验和类错误落在 crc 字段）
            let leaf = e1.path.last().unwrap();
            let covers = find_path(root(&r1), &e1.path)
                .map(|n| i >= n.start && i < n.end)
                .unwrap_or(false);
            assert!(
                covers || leaf == "crc" || leaf == "magic" || leaf == "type",
                "破坏偏移 {} 的错误路径 {:?} 未定位到该字节: {}",
                i, e1.path, e1.message
            );
            signatures.insert((e1.path.join("/"), e1.offset));
        }
    }
    // 不同破坏应稳定分布在若干字段路径上（payload/crc/magic/type/length）
    assert!(signatures.len() >= 3, "破坏定位路径集合: {:?}", signatures);
}

#[test]
fn corrupt_payload_byte_is_reported_on_payload_or_checksum() {
    let proto = load(DEMO_SPEC);
    let full = demo_frame(b"hello", 1);
    let mut broken = full;
    broken[5] ^= 0x01;
    let r = frame_lab::parser::parse(&proto, &broken);
    let e = r.error.as_ref().unwrap();
    assert_eq!(e.kind, FailKind::Violation);
    let leaf = e.path.last().unwrap();
    assert!(
        leaf == "crc" || leaf == "payload",
        "payload 破坏应反映为 payload 或其校验和失败，实际 {:?}",
        e.path
    );
}
