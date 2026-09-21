mod common;

use common::*;
use frame_lab::parser::{self, Status};
use serde_json::json;

// ---------- 1. 编码器生成的合法帧一定能被解析 ----------

#[test]
fn generated_valid_frames_parse_complete() {
    let proto = len_frame_protocol();
    let mut rng = Rng::new(20260921);
    for iter in 0..200 {
        let n = rng.below(20);
        let data: Vec<u8> = (0..n).map(|_| rng.byte()).collect();
        let values = json!({
            "payload": {
                "kind": rng.below(256),
                "n": n,
                "data": frame_lab::hex::encode(&data),
            }
        });
        let frame = frame_lab::encoder::encode(&proto, &values)
            .unwrap_or_else(|e| panic!("iter {iter} 编码失败: {e}"));
        let outcome = parser::parse(&proto, &frame)
            .unwrap_or_else(|e| panic!("iter {iter} 解析失败: {e}"));
        assert_eq!(
            outcome.status,
            Status::Complete,
            "iter {iter}: 合法帧必须解析成功，诊断 {:?}",
            outcome.diagnostics
        );
        let payload = find_node(&outcome.root, &["payload", "body", "data"]).unwrap();
        assert_eq!(payload.end - payload.start, n, "iter {iter} data 长度");
        assert_eq!(outcome.consumed, frame.len(), "iter {iter} 完全消费");
    }
}

#[test]
fn conditional_fields_roundtrip() {
    let proto = conditional_protocol();
    // t==1：ext 存在
    let f1 = frame_lab::encoder::encode(&proto, &json!({ "t": 1, "ext": "cafe" })).unwrap();
    let o1 = parser::parse(&proto, &f1).unwrap();
    assert_eq!(o1.status, Status::Complete);
    assert_eq!(o1.consumed, 3);
    // t==0：ext 缺失
    let f0 = frame_lab::encoder::encode(&proto, &json!({ "t": 0 })).unwrap();
    let o0 = parser::parse(&proto, &f0).unwrap();
    assert_eq!(o0.status, Status::Complete);
    let ext = o0.root.children.iter().find(|c| c.name == "ext").unwrap();
    assert!(!ext.present);
    assert_eq!(o0.consumed, 1);
}

// ---------- 2. 截断只产生 incomplete，且给出仍需字节下界 ----------

#[test]
fn truncation_only_incomplete_with_lower_bound() {
    let proto = len_frame_protocol();
    let frame = frame_lab::encoder::encode(
        &proto,
        &json!({ "payload": { "kind": 9, "n": 5, "data": "0011223344" } }),
    )
    .unwrap();
    for cut in 0..frame.len() {
        let truncated = &frame[..cut];
        let outcome = parser::parse(&proto, truncated).unwrap();
        assert_ne!(
            outcome.status,
            Status::Error,
            "截断到 {cut} 字节不能是 error"
        );
        if cut < frame.len() {
            assert_eq!(
                outcome.status,
                Status::Incomplete,
                "截断到 {cut}/{} 必须是 incomplete",
                frame.len()
            );
            let diag = outcome
                .diagnostics
                .iter()
                .find(|d| d.severity == "incomplete")
                .expect("必须有 incomplete 诊断");
            let need = diag.need_more.expect("必须给出仍需字节下界");
            assert!(need >= 1 && cut + need <= frame.len(), "cut={cut} need={need}");
        }
    }
    let full = parser::parse(&proto, &frame).unwrap();
    assert_eq!(full.status, Status::Complete);
}

// ---------- 3. 单字节破坏稳定落到相同字段路径 ----------

#[test]
fn single_byte_corruption_lands_stably_on_field_path() {
    let proto = len_frame_protocol();
    let frame = frame_lab::encoder::encode(
        &proto,
        &json!({ "payload": { "kind": 2, "n": 4, "data": "deadbeef" } }),
    )
    .unwrap();

    // 1) 每个偏移、每种破坏值：必须被检出（非 complete），且重放结果逐位一致。
    for offset in 0..frame.len() {
        for flip in [0x01u8, 0x80u8] {
            let mut bad = frame.clone();
            bad[offset] ^= flip;
            let first = parser::parse(&proto, &bad).unwrap();
            let second = parser::parse(&proto, &bad).unwrap();
            assert_ne!(
                first.status,
                Status::Complete,
                "偏移 {offset} 破坏 {flip:#x} 后不能静默通过"
            );
            assert_eq!(first.status, second.status, "offset {offset} 状态不稳定");
            assert_eq!(
                first.diagnostics, second.diagnostics,
                "offset {offset} 诊断不稳定"
            );
            assert_eq!(
                parser::tree_digest(&first.root),
                parser::tree_digest(&second.root),
                "offset {offset} 树摘要不稳定"
            );
        }
    }

    // 2) 代表性落点检查：soh 魔数、数据字节、长度低字节。
    let mut bad_soh = frame.clone();
    bad_soh[0] ^= 0x01;
    let o = parser::parse(&proto, &bad_soh).unwrap();
    let d = o.diagnostics.iter().find(|d| d.severity == "error").unwrap();
    assert_eq!(d.path, vec!["frame".to_string(), "soh".to_string()]);
    assert_eq!(d.offset, 0);

    let data_start = find_node(
        &parser::parse(&proto, &frame).unwrap().root,
        &["payload", "body", "data"],
    )
    .unwrap()
    .start;
    let mut bad_data = frame.clone();
    bad_data[data_start] ^= 0xff;
    let o = parser::parse(&proto, &bad_data).unwrap();
    let d = o
        .diagnostics
        .iter()
        .find(|d| d.code == "checksum_mismatch")
        .unwrap();
    let crc_start = o
        .root
        .children
        .iter()
        .find(|c| c.name == "crc")
        .unwrap()
        .start;
    assert_eq!(d.offset, crc_start);

    let mut bad_len = frame.clone();
    bad_len[2] = 0xff; // length 低字节 -> 巨大长度
    let o = parser::parse(&proto, &bad_len).unwrap();
    assert_eq!(o.status, Status::Incomplete);
    let d = o
        .diagnostics
        .iter()
        .find(|d| d.severity == "incomplete")
        .unwrap();
    assert!(d.need_more.unwrap() >= 1);
    assert_eq!(d.path.last().unwrap(), "payload");
}

#[test]
fn corruption_of_data_byte_reports_checksum_path_and_offset() {
    let proto = len_frame_protocol();
    let frame = frame_lab::encoder::encode(
        &proto,
        &json!({ "payload": { "kind": 2, "n": 4, "data": "deadbeef" } }),
    )
    .unwrap();
    let parsed_ok = parser::parse(&proto, &frame).unwrap();
    let data_node = find_node(
        &parsed_ok.root,
        &["payload", "body", "data"],
    )
    .unwrap();
    let mut bad = frame.clone();
    bad[data_node.start] ^= 0xff;
    let o = parser::parse(&proto, &bad).unwrap();
    let crc_diag = o
        .diagnostics
        .iter()
        .find(|d| d.code == "checksum_mismatch")
        .unwrap();
    let crc_node = o.root.children.iter().find(|c| c.name == "crc").unwrap();
    assert_eq!(crc_diag.offset, crc_node.start);
    assert_eq!(crc_diag.path, vec!["crc".to_string()]);
}

// ---------- 4. 恶意长度：不能带出父结构边界 ----------

#[test]
fn malicious_length_cannot_escape_parent() {
    let proto = len_frame_protocol();
    // 构造：length 声明巨大，但实际输入很短。
    let mut evil = vec![0xa5, 0xff, 0xff];
    evil.extend(std::iter::repeat_n(0x41u8, 10));
    let o = parser::parse(&proto, &evil).unwrap();
    // 输入总量不足以满足 payload：由于未越过任何有界父结构（根无硬边界），
    // 只能是 incomplete 而不是越界读取。
    assert_eq!(o.status, Status::Incomplete);

    // 嵌套：外层 payload 有界，内层 n 声明超出 payload 长度 -> error 且不越界。
    // soh(1) length(2) payload{kind, n=200, data...} crc(1)
    let mut nested = vec![0xa5, 0x00, 0x03, 0x01, 0xc8, 0xaa];
    nested.push(0x00); // crc 占位
    let o2 = parser::parse(&proto, &nested).unwrap();
    assert_eq!(o2.status, Status::Error);
    let diag = o2
        .diagnostics
        .iter()
        .find(|d| d.code == "length_exceeds_parent")
        .expect("必须报告越界父结构");
    assert!(diag.path.iter().any(|p| p == "data"));
}

// ---------- 5. 递归深度上限 ----------

#[test]
fn recursion_depth_is_capped() {
    let max_depth = 3;
    let proto = recursive_protocol(max_depth);
    // 构造链：每层 tag + more=1，共 6 层后 more=0 结束。
    let mut bytes = Vec::new();
    for _ in 0..6 {
        bytes.extend_from_slice(&[0x00, 0x01]);
    }
    bytes.extend_from_slice(&[0x00, 0x00]);
    let o = parser::parse(&proto, &bytes).unwrap();
    assert_eq!(o.status, Status::Error);
    let diag = o
        .diagnostics
        .iter()
        .find(|d| d.code == "depth_exceeded")
        .expect("必须报告深度超限");
    assert!(diag.path.iter().filter(|p| *p == "next").count() >= max_depth);
}

#[test]
fn recursion_within_cap_succeeds() {
    let proto = recursive_protocol(6);
    let mut bytes = Vec::new();
    for _ in 0..2 {
        bytes.extend_from_slice(&[0x00, 0x01]);
    }
    bytes.extend_from_slice(&[0x05, 0x00]);
    let values = json!({ "tag": 0, "more": 1, "next": {
        "tag": 0, "more": 1, "next": { "tag": 5, "more": 0 }
    }});
    let encoded = frame_lab::encoder::encode(&proto, &values).unwrap();
    assert_eq!(encoded, bytes);
    let o = parser::parse(&proto, &encoded).unwrap();
    assert_eq!(o.status, Status::Complete);
}

// ---------- 6. 校验和自排除 ----------

#[test]
fn checksum_skip_self_semantics() {
    // skip_self=true：校验值位置可以是正确的 xor(a,b)
    let proto_skip = xor_protocol(true);
    let frame = frame_lab::encoder::encode(&proto_skip, &json!({ "a": 0x12, "b": 0x34 })).unwrap();
    assert_eq!(frame, vec![0x12, 0x34, 0x12 ^ 0x34]);
    let o = parser::parse(&proto_skip, &frame).unwrap();
    assert_eq!(o.status, Status::Complete);

    // skip_self=false：校验值把自身也计入，因此 xor(a,b,0)=xor(a,b) 填进去后
    // 重算 xor(a,b,c)=0，与 c 不同 -> mismatch，证明区间确实包含自身。
    let proto_incl = xor_protocol(false);
    let mut inclusive = vec![0x12u8, 0x34, 0x12 ^ 0x34];
    // 找到使 xor(a,b,c)==c 的 c：xor(a,b,c)=c => xor(a,b)=0，a/b 不同所以无解；
    // 直接验证错误码即可。
    let o2 = parser::parse(&proto_incl, &inclusive).unwrap();
    assert!(o2.diagnostics.iter().any(|d| d.code == "checksum_mismatch"));

    // 而在 skip_self=false 协议里，手工放置 c=0 且 a==b 时通过。
    inclusive[0] = 0x77;
    inclusive[1] = 0x77;
    inclusive[2] = 0x00;
    let o3 = parser::parse(&proto_incl, &inclusive).unwrap();
    assert_eq!(o3.status, Status::Complete, "a=b,c=0 时整体 xor 为 0 == c");
}

// ---------- 7. 最深字段路径定位 ----------

#[test]
fn deepest_path_for_offset() {
    let proto = len_frame_protocol();
    let frame = frame_lab::encoder::encode(
        &proto,
        &json!({ "payload": { "kind": 1, "n": 3, "data": "aabbcc" } }),
    )
    .unwrap();
    let o = parser::parse(&proto, &frame).unwrap();
    let data = find_node(&o.root, &["payload", "body", "data"]).unwrap();
    let path = parser::deepest_path_at(&o.root, data.start + 1);
    assert_eq!(
        path,
        vec!["frame", "payload", "body", "data"]
            .into_iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
    );
}

// ---------- 8. 修改字节后重算节点差异 ----------

#[test]
fn diff_detects_recomputed_nodes() {
    let proto = len_frame_protocol();
    let frame = frame_lab::encoder::encode(
        &proto,
        &json!({ "payload": { "kind": 1, "n": 2, "data": "0102" } }),
    )
    .unwrap();
    let before = parser::parse(&proto, &frame).unwrap();
    let mut changed = frame.clone();
    let kind_offset = find_node(&before.root, &["payload", "body", "kind"]).unwrap().start;
    changed[kind_offset] = changed[kind_offset].wrapping_add(1);
    let after = parser::parse(&proto, &changed).unwrap();
    let diffs = parser::diff_paths(&before.root, &after.root);
    let diff_key: Vec<String> = diffs
        .iter()
        .map(|p| p.join("/"))
        .collect();
    assert!(diff_key.iter().any(|k| k.ends_with("kind")));
    assert!(diff_key.iter().any(|k| k.ends_with("crc")));
    // 未改动的 length 不应出现在差异中。
    assert!(!diff_key.iter().any(|k| k.ends_with("length")));
}
