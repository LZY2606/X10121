//! 单字节破坏：重复解析必须得到完全相同的结论（状态/错误码/最深路径/偏移）。
//! 同时验证不同位置的破坏会落到语义对应的字段路径。
#[allow(dead_code)]
mod common;

use common::*;
use frame_lab::model::Status;
use frame_lab::parser;
use frame_lab::parser as p2;

fn fingerprint(bytes: &[u8]) -> (String, String, String, usize) {
    let r = parser::parse(&demo_spec(), bytes);
    match &r.error {
        Some(e) => (
            r.status.as_str().to_string(),
            e.code.clone(),
            e.path.clone(),
            e.offset,
        ),
        None => (r.status.as_str().to_string(), "none".into(), String::new(), 0),
    }
}

#[test]
fn corruption_is_deterministic_across_repeated_parses() {
    let original = demo_frame();
    let mut rng = Rng::new(424242);
    for _ in 0..100 {
        let pos = rng.below(original.len() as u64) as usize;
        let delta = 1 + rng.below(255) as u8;
        let mut corrupted = original.clone();
        corrupted[pos] = corrupted[pos].wrapping_add(delta);

        let f1 = fingerprint(&corrupted);
        for _ in 0..5 {
            assert_eq!(f1, fingerprint(&corrupted), "位置 {pos} 的破坏重复解析结论不一致");
        }
    }
}

#[test]
fn checksum_byte_corruption_lands_on_checksum_field() {
    let original = demo_frame();
    let chk_pos = original.len() - 1;
    let mut bad = original.clone();
    bad[chk_pos] ^= 0x5A;
    let r = parser::parse(&demo_spec(), &bad);
    assert_eq!(r.status, Status::Violation);
    let e = r.error.unwrap();
    assert_eq!(e.code, "checksum_mismatch");
    assert_eq!(e.path, "$frame.chk");
    assert_eq!(e.offset, chk_pos);
}

#[test]
fn payload_byte_corruption_lands_on_checksum_field() {
    let original = demo_frame();
    // payload 三字节偏移 8..11；破坏后帧仍完整，但校验和不匹配
    for pos in 8..11 {
        let mut bad = original.clone();
        bad[pos] ^= 0xFF;
        let r = parser::parse(&demo_spec(), &bad);
        assert_eq!(r.status, Status::Violation, "位置 {pos} 破坏应违反协议");
        let e = r.error.unwrap();
        assert_eq!(e.code, "checksum_mismatch", "位置 {pos}");
        assert_eq!(e.path, "$frame.chk", "位置 {pos} 的最深字段路径");
    }
}

#[test]
fn soi_corruption_is_const_mismatch() {
    let mut bad = demo_frame();
    bad[0] = 0x00;
    let r = parser::parse(&demo_spec(), &bad);
    assert_eq!(r.status, Status::Violation);
    let e = r.error.unwrap();
    assert_eq!(e.code, "const_mismatch");
    assert_eq!(e.path, "$frame.soi");
    assert_eq!(e.offset, 0);
}

#[test]
fn node_nlen_corruption_has_stable_deep_path() {
    // node.nlen 位于偏移 13；把它从 2 增大到 4 => nval 吞掉 body 剩余字节，
    // 递归 child 被 body 硬边界拦截 => violation，且路径稳定在 node 子树内。
    let mut bad = demo_frame();
    bad[13] = 4;
    let r1 = parser::parse(&demo_spec(), &bad);
    let r2 = p2::parse(&demo_spec(), &bad);
    assert_eq!(r1.status, Status::Violation);
    let e = r1.error.unwrap();
    assert!(
        e.code == "length_out_of_bounds" || e.code == "field_out_of_bounds",
        "应被父边界拦截，实际 {}",
        e.code
    );
    assert!(e.path.contains("$frame.body.node"), "路径应在 node 子树内：{}", e.path);
    // 稳定性
    assert_eq!(e.path, r2.error.clone().unwrap().path);
    assert_eq!(e.offset, r2.error.unwrap().offset);
}

#[test]
fn frame_length_increase_is_incomplete_with_lower_bound() {
    // 增大 frame_len 而输入不变：声明的硬边界超出输入 => incomplete 且有正下界
    let mut bad = demo_frame();
    bad[2] = 0x40; // frame_len 变大（同时校验和也会不成立，但 incomplete 优先因为帧无法闭合）
    let r = parser::parse(&demo_spec(), &bad);
    assert_eq!(r.status, Status::Incomplete);
    let e = r.error.unwrap();
    assert!(e.need.unwrap() >= 1);
}

#[test]
fn every_corrupted_byte_either_violates_or_is_explicitly_incomplete() {
    // 对每个位置做 +1 破坏：结论必须是 violation 或 incomplete，绝不允许静默成功
    let original = demo_frame();
    let mut outcomes = std::collections::HashSet::new();
    for pos in 0..original.len() {
        let mut bad = original.clone();
        bad[pos] = bad[pos].wrapping_add(1);
        let r = parser::parse(&demo_spec(), &bad);
        assert_ne!(r.status, Status::Ok, "位置 {pos} 被破坏却报告成功");
        if let Some(e) = &r.error {
            assert!(!e.path.is_empty(), "位置 {pos} 的错误必须给出字段路径");
            outcomes.insert(e.code.clone());
        }
    }
    // 至少触发了校验和与常量两类不同错误
    assert!(outcomes.contains("checksum_mismatch"));
}
