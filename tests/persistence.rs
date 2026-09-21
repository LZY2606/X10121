mod common;

use common::*;
use framelab::model::{Endian, FieldDef, LengthExpr, ProtocolSpec, StructDef};
use framelab::parser::Outcome;
use std::collections::BTreeMap;

#[test]
fn blob_dedup_same_bytes_same_id() {
    let g = fresh_store("dedup");
    let bytes = gen_demo_frame(4);
    let id1 = g.store.put_blob(&bytes).unwrap();
    let id2 = g.store.put_blob(&bytes.clone()).unwrap();
    assert_eq!(id1, id2);

    let mut other = bytes.clone();
    other.push(0);
    let id3 = g.store.put_blob(&other).unwrap();
    assert_ne!(id1, id3);

    // 相同样本两次导入创建 blob 只有一个文件
    let count = std::fs::read_dir(g.dir.join("blobs")).unwrap().count();
    assert_eq!(count, 2);
}

#[test]
fn protocol_versions_are_immutable_and_content_addressed() {
    let g = fresh_store("imm");
    let spec = demo_spec();
    let v1 = g.store.save_protocol(&spec).unwrap();
    let v1_again = g.store.save_protocol(&spec).unwrap();
    assert_eq!(v1.version_id, v1_again.version_id);

    // 改一个字段 -> 新版本，旧版本仍在
    let mut spec2 = spec.clone();
    let mut frame = spec2.structs.remove("frame").unwrap();
    if let FieldDef::Int { width, .. } = &mut frame.fields[0] {
        *width = 4;
    }
    spec2.structs.insert("frame".into(), frame);
    let v2 = g.store.save_protocol(&spec2).unwrap();
    assert_ne!(v1.version_id, v2.version_id);

    // 旧版本内容原样可读
    let loaded = g.store.load_protocol(&v1.version_id).unwrap();
    assert_eq!(loaded.spec, spec);
    assert_eq!(g.store.list_protocols().unwrap().len(), 2);
}

#[test]
fn historical_session_replays_with_bound_version() {
    let g = fresh_store("replay");
    let spec = demo_spec();
    let pv = g.store.save_protocol(&spec).unwrap();
    let frame = gen_demo_frame(2);
    let blob = g.store.put_blob(&frame).unwrap();
    let session = g
        .store
        .create_session(&pv.version_id, &blob, "历史样本", "旧备注")
        .unwrap();
    assert_eq!(session.report.outcome, Outcome::Complete);

    // 保存一个不兼容的新版本（根结构改名），旧会话仍按旧版本重放且结论一致
    let mut spec2 = spec.clone();
    spec2.name = "演示帧 v2".into();
    spec2.root = "frame".into();
    let mut new_structs = BTreeMap::new();
    for (k, mut sdef) in spec2.structs.clone() {
        if k == "frame" {
            sdef.fields.remove(6); // 删除 crc
        }
        new_structs.insert(k, sdef);
    }
    spec2.structs = new_structs;
    let pv2 = g.store.save_protocol(&spec2).unwrap();
    assert_ne!(pv.version_id, pv2.version_id);

    let reloaded = g.store.load_session(&session.session_id).unwrap();
    assert_eq!(reloaded.version_id, pv.version_id);
    assert_eq!(reloaded.report, session.report);
    assert_eq!(reloaded.tree_digest, session.tree_digest);
    assert_eq!(reloaded.note, "旧备注");
}

#[test]
fn export_import_roundtrip_is_deterministic() {
    let g1 = fresh_store("exp1");
    let pv = g1.store.save_protocol(&demo_spec()).unwrap();
    let frame = gen_demo_frame(13);
    let blob = g1.store.put_blob(&frame).unwrap();
    let session = g1
        .store
        .create_session(&pv.version_id, &blob, "导出样本", "我的备注")
        .unwrap();
    let bundle = g1.store.export_session(&session.session_id).unwrap();

    // 序列化确定：两次导出字节一致
    let b1 = bundle.to_json().to_string();
    let bundle2 = g1.store.export_session(&session.session_id).unwrap();
    let b2 = bundle2.to_json().to_string();
    assert_eq!(b1, b2);

    // 导入到全新目录
    let g2 = fresh_store("imp2");
    let imported = g2.store.import_bundle(&bundle).unwrap();
    assert_ne!(imported.session_id, session.session_id, "导入生成独立会话");
    assert_eq!(imported.note, "我的备注", "备注随包独立保留");
    assert_eq!(imported.version_id, pv.version_id);
    assert_eq!(imported.blob_id, blob);
    assert_eq!(imported.report, session.report);
    assert_eq!(imported.tree_digest, session.tree_digest);

    // 再导入同一个包：协议与 blob 去重，会话再得新 id
    let imported2 = g2.store.import_bundle(&bundle).unwrap();
    assert_ne!(imported2.session_id, imported.session_id);
    assert_eq!(g2.store.list_protocols().unwrap().len(), 1);
    assert_eq!(
        std::fs::read_dir(g2.dir.join("blobs")).unwrap().count(),
        1
    );
    assert_eq!(g2.store.list_sessions().unwrap().len(), 2);

    // 导出导入后的再导出，版本/字节/诊断/树摘要保持一致
    let re_bundle = g2.store.export_session(&imported2.session_id).unwrap();
    assert_eq!(re_bundle.protocol.spec, bundle.protocol.spec);
    assert_eq!(re_bundle.blob_hex, bundle.blob_hex);
    assert_eq!(re_bundle.session.report, bundle.session.report);
    assert_eq!(re_bundle.session.tree_digest, bundle.session.tree_digest);
}

#[test]
fn import_rejects_tampered_bundle() {
    let g1 = fresh_store("tam1");
    let pv = g1.store.save_protocol(&demo_spec()).unwrap();
    let frame = gen_demo_frame(5);
    let blob = g1.store.put_blob(&frame).unwrap();
    let session = g1
        .store
        .create_session(&pv.version_id, &blob, "x", "y")
        .unwrap();
    let mut bundle = g1.store.export_session(&session.session_id).unwrap();

    // 篡改协议但保留旧版本号 -> 必须拒绝
    bundle.protocol.version_id = bundle.protocol.version_id.clone();
    bundle.protocol.spec.name = "伪造".into();
    let g2 = fresh_store("tam2");
    assert!(g2.store.import_bundle(&bundle).is_err());
}

#[test]
fn invalid_protocol_is_rejected() {
    let g = fresh_store("bad");
    // 引用不存在的结构体
    let bad = ProtocolSpec {
        name: "坏".into(),
        root: "nope".into(),
        max_depth: 4,
        structs: BTreeMap::new(),
    };
    assert!(g.store.save_protocol(&bad).is_err());

    // int 宽度非法
    let mut fields = BTreeMap::new();
    fields.insert(
        "r".into(),
        StructDef {
            fields: vec![FieldDef::Int {
                name: "x".into(),
                width: 9,
                endian: Endian::Be,
                signed: false,
                expect: None,
            }],
        },
    );
    let bad2 = ProtocolSpec {
        name: "坏2".into(),
        root: "r".into(),
        max_depth: 4,
        structs: fields,
    };
    assert!(g.store.save_protocol(&bad2).is_err());

    // payload 引用后置字段
    let mut fields = BTreeMap::new();
    fields.insert(
        "r".into(),
        StructDef {
            fields: vec![
                FieldDef::Payload {
                    name: "p".into(),
                    length_field: "later".into(),
                },
                FieldDef::Int {
                    name: "later".into(),
                    width: 1,
                    endian: Endian::Be,
                    signed: false,
                    expect: None,
                },
            ],
        },
    );
    let _ = LengthExpr::Fixed(0);
    let bad3 = ProtocolSpec {
        name: "坏3".into(),
        root: "r".into(),
        max_depth: 4,
        structs: fields,
    };
    assert!(g.store.save_protocol(&bad3).is_err());
}
