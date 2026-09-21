mod common;

use common::*;
use frame_lab::{parser, spec};

fn demo_protocol() -> spec::Protocol {
    spec::compile(frame_lab::demo::DEMO_PROTOCOL).expect("内置演示协议必须能编译")
}

fn complete_frame() -> Vec<u8> {
    sample_frame()
}

#[test]
fn encoder_legal_frame_parses_completely() {
    let p = demo_protocol();
    let frame = complete_frame();
    let result = parser::parse(&p, &frame);
    assert_eq!(result.outcome, parser::Outcome::Complete, "{}",
        result.violation.as_ref().map(|v| v.message.clone()).unwrap_or_default());
    assert!(result.violation.is_none());
    assert_eq!(result.consumed, frame.len());
    let root = result.root.expect("根节点存在");
    assert_eq!(root.start, 0);
    assert_eq!(root.end, frame.len());
    // 每个字节至少属于一个字段：递归校验所有区间拼接覆盖整帧。
    let mut covered = vec![false; frame.len()];
    mark_leaves(root, &mut covered);
    assert!(covered.iter().all(|x| *x), "存在未映射到字段的字节");
}

fn mark_leaves(node: parser::FieldNode, covered: &mut [bool]) {
    if node.children.is_empty() {
        for i in node.start..node.end {
            covered[i] = true;
        }
    }
    for child in node.children {
        mark_leaves(child, covered);
    }
}

#[test]
fn every_truncation_is_incomplete_until_last_byte() {
    let p = demo_protocol();
    let frame = complete_frame();
    for cut in 0..frame.len() {
        let partial = &frame[..cut];
        let result = parser::parse(&p, partial);
        assert!(
            matches!(result.outcome, parser::Outcome::Incomplete),
            "截断到 {cut} 字节应为 incomplete，实际 {:?}：{}",
            result.outcome,
            result.violation.as_ref().map(|v| v.message.clone()).unwrap_or_default()
        );
        let inc = result.incomplete.expect("incomplete 诊断必须存在");
        assert!(inc.need_at_least >= 1, "need_at_least 是仍需字节数的正下界");
        assert!(inc.offset <= cut, "incomplete 偏移不能越过已输入末尾");
        assert!(!inc.path.is_empty());
    }
    // 完整帧必须从 incomplete 切换为 complete。
    assert_eq!(parser::parse(&p, &frame).outcome, parser::Outcome::Complete);
}

#[test]
fn single_byte_corruption_lands_on_stable_field_path() {
    let p = demo_protocol();
    let frame = complete_frame();
    let baseline = parser::parse(&p, &frame);
    assert_eq!(baseline.outcome, parser::Outcome::Complete);

    for index in 0..frame.len() {
        let mut corrupted = frame.clone();
        corrupted[index] ^= 0xFF;
        let first = parser::parse(&p, &corrupted);
        // 稳定性：同一破坏重复解析必须落到完全相同的路径与偏移。
        let second = parser::parse(&p, &corrupted);
        assert_ne!(first.outcome, parser::Outcome::Complete, "字节 {index} 翻转后不应成功");
        match (&first.violation, &second.violation) {
            (Some(a), Some(b)) => {
                assert_eq!(a.path, b.path, "字节 {index} 的失败路径不稳定");
                assert_eq!(a.offset, b.offset, "字节 {index} 的失败偏移不稳定");
                assert_eq!(a.code, b.code);
                // 失败位置必须定位到包含被破坏字节的字段，或其祖先边界。
                assert!(a.offset <= index, "失败偏移不应晚于破坏字节");
            }
            _ => panic!("单字节破坏必须产生违反协议诊断（非 incomplete），字节 {index}"),
        }
    }
}

#[test]
fn corruption_never_misclassified_as_incomplete() {
    let p = demo_protocol();
    let frame = complete_frame();
    for index in 0..frame.len() {
        let mut corrupted = frame.clone();
        corrupted[index] ^= 0xFF;
        let result = parser::parse(&p, &corrupted);
        assert_ne!(
            result.outcome,
            parser::Outcome::Incomplete,
            "长度完整的帧被破坏后不允许报告 incomplete（字节 {index}）"
        );
    }
}
