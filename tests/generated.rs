mod common;

use common::*;
use framelab::parser::{parse, Outcome};

/// 1) 编码器生成的合法帧必须能成功解析（演示协议 + 递归 TLV）。
#[test]
fn encoded_legal_frames_parse() {
    let demo = demo_spec();
    for seed in 0..200u64 {
        let frame = gen_demo_frame(seed.wrapping_add(1));
        let r = parse(&demo, &frame);
        assert_eq!(
            r.outcome,
            Outcome::Complete,
            "seed={} 应成功，错误={:?} 告警={:?}",
            seed,
            r.error_message,
            r.warnings
        );
        assert!(r.warnings.is_empty(), "seed={} 不应有告警: {:?}", seed, r.warnings);
        let tree = r.tree.unwrap();
        assert_eq!(tree.end as usize, frame.len());
    }

    let tlv = tlv_spec();
    for seed in 0..200u64 {
        let depth = 1 + seed % 3;
        let frame = gen_tlv_frame(seed.wrapping_add(1000), depth as u32);
        let r = parse(&tlv, &frame);
        assert_eq!(
            r.outcome,
            Outcome::Complete,
            "tlv seed={} depth={} 应成功: {:?}",
            seed,
            depth,
            r.error_message
        );
    }
}

/// 2) 任何截断都只能产生 incomplete，且给出正的下界，绝不产生 violation。
#[test]
fn truncation_only_incomplete() {
    let demo = demo_spec();
    for seed in [1u64, 7, 42, 99] {
        let frame = gen_demo_frame(seed);
        for cut in 1..frame.len() {
            let r = parse(&demo, &frame[..cut]);
            assert_eq!(
                r.outcome,
                Outcome::Incomplete,
                "seed={} cut={} 截断必须是 incomplete",
                seed,
                cut
            );
            assert!(r.need_bytes >= 1, "seed={} cut={} 需要下界>=1", seed, cut);
            assert!(r.error_path.is_none());
            // need_bytes + cut 不应超过原始帧长度之后太多
            assert!(cut as u64 + r.need_bytes <= frame.len() as u64 + 8);
        }
    }

    let tlv = tlv_spec();
    let frame = gen_tlv_frame(55, 3);
    for cut in 1..frame.len() {
        let r = parse(&tlv, &frame[..cut]);
        assert_eq!(r.outcome, Outcome::Incomplete, "tlv cut={}", cut);
    }
}

/// 3) 单字节破坏必须稳定落到确定的字段路径：
///    - 破坏 magic 固定落到 frame.magic（violation）；
///    - 破坏 payload 固定落到 crc 校验字段（checksum 告警路径稳定）。
#[test]
fn single_byte_corruption_stable_path() {
    let spec = demo_spec();
    for seed in 0..100u64 {
        let frame = gen_demo_frame(seed.wrap_add_1());
        // 破坏第一个字节（magic 高字节）
        let mut bad = frame.clone();
        bad[0] ^= 0xFF;
        let r = parse(&spec, &bad);
        assert_eq!(
            r.outcome,
            Outcome::Violation,
            "seed={} magic 破坏应违规",
            seed
        );
        assert_eq!(r.error_path.as_deref(), Some("frame.magic"));
    }

    // payload 区域任意单字节破坏 -> crc 不匹配，告警路径恒定为 frame.crc
    for seed in 0..60u64 {
        let frame = gen_demo_frame(seed.wrap_add_1());
        let body_start = 7usize; // magic2 type1 seq2 len2
        let body_len = u16::from_be_bytes([frame[5], frame[6]]) as usize;
        for off in body_start..body_start + body_len {
            let mut bad = frame.clone();
            bad[off] ^= 0x01;
            let r = parse(&spec, &bad);
            assert_eq!(r.outcome, Outcome::Complete);
            assert_eq!(r.warnings.len(), 1, "seed={} off={}", seed, off);
            assert_eq!(r.warnings[0].path, "frame.crc");
        }
    }
}

/// 4) 恶意长度字段：把 payload 长度改写为巨大值。
///    根层面未越输入 => incomplete；放进定界容器 => 必须 violation，且不能越过父边界。
#[test]
fn malicious_length_field() {
    let spec = demo_spec();
    let frame = gen_demo_frame(3);
    let mut evil = frame.clone();
    evil[5] = 0xFF;
    evil[6] = 0xFF;
    let r = parse(&spec, &evil);
    // 声称 65535 字节，输入不足：incomplete，而不是读到缓冲区外
    assert_eq!(r.outcome, Outcome::Incomplete);
    assert!(r.need_bytes > 0);

    // 定界 TLV 容器内，子节点长度超过容器区间必须是 violation
    let tlv = tlv_spec();
    // 容器 tag=1 len=3, 子节点声称 len=5（只放了 1 字节载荷）
    let bounded_evil = vec![1u8, 3, 2, 5, 0xAA];
    let r = parse(&tlv, &bounded_evil);
    assert_eq!(r.outcome, Outcome::Violation);
    assert_eq!(
        r.error_path.as_deref(),
        Some("tlv.content.children.[0].content.value")
    );
    let off = r.error_offset.unwrap();
    assert!(off < bounded_evil.len() as u64);
}

/// 5) 递归深度上限可配置；超过即 violation，并给出深路径。
#[test]
fn recursion_depth_limit() {
    let tlv = tlv_spec(); // max_depth = 4
    for depth in 0..=4u32 {
        let frame = gen_tlv_frame(depth as u64 + 7, depth);
        let r = parse(&tlv, &frame);
        assert_eq!(r.outcome, Outcome::Complete, "depth={}", depth);
    }
    // 手工构造 6 层容器嵌套
    let mut deep = vec![2u8, 1, 0x7A];
    for _ in 0..6 {
        let len = deep.len() as u8;
        let mut next = vec![1u8, len];
        next.extend_from_slice(&deep);
        deep = next;
    }
    let r = parse(&tlv, &deep);
    assert_eq!(r.outcome, Outcome::Violation);
    assert!(r.error_path.as_deref().unwrap().contains("children.[0]"));
    assert!(r.error_message.as_deref().unwrap().contains("递归深度"));
}

/// 6) 校验和自排除：把校验字段自身改成任意值，再用同样的覆盖规则重算应一致；
///    而覆盖自身时则会互相牵连。这里验证解析器对“跳过自身”的行为：
///    合法帧改 crc 字段，仅 crc 节点报 warning，其余字段全部 ok。
#[test]
fn checksum_self_exclusion() {
    let spec = demo_spec();
    let frame = gen_demo_frame(11);
    let crc_off = frame.len() - 4;
    let mut tampered = frame.clone();
    tampered[crc_off] ^= 0xA5;
    let r = parse(&spec, &tampered);
    assert_eq!(r.outcome, Outcome::Complete);
    assert_eq!(r.warnings.len(), 1);
    assert_eq!(r.warnings[0].path, "frame.crc");

    // 对合法帧：编码器算出的 crc 与输入一致 -> 无告警
    let r = parse(&spec, &frame);
    assert!(r.warnings.is_empty());

    // 直接验证自排除逻辑：在 [0, len) 上计算 crc 并跳过 crc 字段应等于帧中 crc
    let algo = framelab::model::ChecksumAlgo::Crc32;
    let mut span = frame[..crc_off].to_vec();
    span.extend_from_slice(&frame[crc_off + 4..]);
    let expected = u32::from_be_bytes([
        frame[crc_off],
        frame[crc_off + 1],
        frame[crc_off + 2],
        frame[crc_off + 3],
    ]);
    assert_eq!(framelab::parser::checksum_of(algo, &span) as u32, expected);
}

trait SeedExt {
    fn wrap_add_1(self) -> u64;
}
impl SeedExt for u64 {
    fn wrap_add_1(self) -> u64 {
        self.wrapping_add(1)
    }
}
