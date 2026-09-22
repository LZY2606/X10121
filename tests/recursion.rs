//! 递归结构必须受可配置深度上限约束。
#[allow(dead_code)]
mod common;

use common::*;
use frame_lab::model::Status;
use frame_lab::parser;
use frame_lab::spec::Spec;

/// 构造 n 层递归节点：前 n-1 层 tag=1（继续），最后一层 tag=0（终止）。
fn chain(n: usize) -> Vec<u8> {
    let mut b = Vec::new();
    for i in 0..n {
        b.push(if i + 1 < n { 1 } else { 0 });
        b.push(0x10 + i as u8);
    }
    b
}

#[test]
fn chain_within_depth_limit_parses() {
    let spec = Spec::from_json(&recursion_spec_json(4)).unwrap();
    let bytes = chain(4);
    let r = parser::parse(&spec, &bytes);
    assert_eq!(r.status, Status::Ok, "{:?}", r.error.map(|e| e.message));
}

#[test]
fn chain_beyond_depth_limit_is_violation() {
    let spec = Spec::from_json(&recursion_spec_json(4)).unwrap();
    let bytes = chain(8);
    let r = parser::parse(&spec, &bytes);
    assert_eq!(r.status, Status::Violation);
    let e = r.error.unwrap();
    assert_eq!(e.code, "max_depth");
    assert!(e.path.contains("child"), "最深路径应为 child：{}", e.path);
}

#[test]
fn depth_limit_is_configurable_and_deterministic() {
    // 同一 6 层输入：上限 10 成功，上限 3 违规；两次解析结论一致
    let bytes = chain(6);
    let loose = Spec::from_json(&recursion_spec_json(10)).unwrap();
    let tight = Spec::from_json(&recursion_spec_json(3)).unwrap();

    let r1 = parser::parse(&loose, &bytes);
    let r2 = parser::parse(&loose, &bytes);
    assert_eq!(r1.status, Status::Ok);
    assert_eq!(r1.tree_digest(), r2.tree_digest());

    let t1 = parser::parse(&tight, &bytes);
    let t2 = parser::parse(&tight, &bytes);
    assert_eq!(t1.status, Status::Violation);
    assert_eq!(t1.error.as_ref().unwrap().path, t2.error.as_ref().unwrap().path);
    assert_eq!(t1.error.as_ref().unwrap().offset, t2.error.as_ref().unwrap().offset);
}

#[test]
fn non_recursive_tag_does_not_descend() {
    // tag=0 的节点不产生 child，不受深度影响
    let spec = Spec::from_json(&recursion_spec_json(1)).unwrap();
    let r = parser::parse(&spec, &[0u8, 5]);
    assert_eq!(r.status, Status::Ok, "{:?}", r.error.map(|e| e.message.clone()));
}
