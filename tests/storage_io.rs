//! 相同样本指向已有 blob；会话/备注独立；导出包重导入后
//! 版本、字节、诊断与解析树摘要保持一致；历史会话始终按绑定版本重放。
#[allow(dead_code)]
mod common;

use common::*;
use frame_lab::model::Status;

use frame_lab::parser;
use frame_lab::storage::Store;
use frame_lab::json::Json;

fn temp_dir(tag: &str) -> std::path::PathBuf {
    let mut d = std::env::temp_dir();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    d.push(format!("frame_lab_test_{tag}_{nanos}_{}", std::process::id()));
    d
}

#[test]
fn identical_samples_share_blob_but_sessions_and_notes_are_independent() {
    let dir = temp_dir("blob");
    let store = Store::open(&dir).unwrap();
    let spec = demo_spec();
    let proto = store.create_protocol("p", &frame_lab::demo::demo_spec_json(), "").unwrap();
    let bytes = demo_frame();

    let h1 = store.put_blob(&bytes).unwrap();
    let h2 = store.put_blob(&bytes.clone()).unwrap();
    assert_eq!(h1, h2, "相同样本必须指向同一个 blob");
    let altered: Vec<u8> = bytes.iter().enumerate().map(|(i, &b)| if i == 4 { b ^ 1 } else { b }).collect();
    let h3 = store.put_blob(&altered).unwrap();
    assert_ne!(h1, h3, "不同内容必须是不同 blob");

    let r = parser::parse(&spec, &bytes);
    let s1 = store.create_session("会话 A", "备注 A", &proto.id, 1, &h1, bytes.len(), &r).unwrap();
    let s2 = store.create_session("会话 B", "备注 B", &proto.id, 1, &h1, bytes.len(), &r).unwrap();
    assert_ne!(s1.id, s2.id);

    // 备注独立修改
    let s1b = store.set_note(&s1.id, None, Some("改后的备注 A")).unwrap();
    let s2b = store.load_session(&s2.id).unwrap();
    assert_eq!(s1b.note, "改后的备注 A");
    assert_eq!(s2b.note, "备注 B", "另一会话备注不应被影响");

    // 两个会话仍指向同一 blob
    assert_eq!(s1b.current.blob, s2b.current.blob);

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn export_then_import_preserves_version_bytes_diagnostics_and_tree() {
    let dir1 = temp_dir("export");
    let dir2 = temp_dir("import");
    let src = Store::open(&dir1).unwrap();
    let dst = Store::open(&dir2).unwrap();

    let proto = src.create_protocol("导出协议", &frame_lab::demo::demo_spec_json(), "v1").unwrap();
    let bytes = demo_frame();
    let blob = src.put_blob(&bytes).unwrap();
    let spec = frame_lab::spec::Spec::from_json(&frame_lab::demo::demo_spec_json()).unwrap();
    let report = parser::parse(&spec, &bytes);
    let sess = src
        .create_session("要导出的会话", "原始备注", &proto.id, 1, &blob, bytes.len(), &report)
        .unwrap();
    let orig_tree_digest = report.tree_digest();
    let orig_report_digest = report.report_digest();

    let pkg = src.export_session(&sess.id).unwrap();
    // 导出包必须是确定性 JSON（两次导出字节一致）
    let pkg2 = src.export_session(&sess.id).unwrap();
    assert_eq!(pkg.dump(), pkg2.dump(), "导出包必须确定");

    let (imported, verify) = dst.import_package(&pkg).unwrap();
    assert_eq!(verify.get("match").and_then(|x| x.as_bool()), Some(true), "重放校验应全部通过：{}", verify.dump());

    // 字节一致
    let back = dst.get_blob(&imported.current.blob).unwrap();
    assert_eq!(back, bytes);

    // 用导入后绑定的协议版本重放，诊断/树摘要一致
    let ip = dst.load_protocol(&imported.current.protocol_id).unwrap();
    let ispec = &ip.revisions.iter().find(|r| r.version == imported.current.version).unwrap().spec;
    let replayed = parser::parse(ispec, &back);
    assert_eq!(replayed.status, Status::Ok);
    assert_eq!(replayed.tree_digest(), orig_tree_digest);
    assert_eq!(replayed.report_digest(), orig_report_digest);
    assert_eq!(imported.current.tree_digest, orig_tree_digest);
    assert_eq!(imported.current.report_digest, orig_report_digest);

    // 备注与标题保持
    assert_eq!(imported.note, "原始备注");
    assert_eq!(imported.title, "要导出的会话");

    std::fs::remove_dir_all(&dir1).ok();
    std::fs::remove_dir_all(&dir2).ok();
}

#[test]
fn import_is_idempotent_and_deduplicates_protocol_and_blobs() {
    let dir1 = temp_dir("dedup1");
    let dir2 = temp_dir("dedup2");
    let src = Store::open(&dir1).unwrap();
    let dst = Store::open(&dir2).unwrap();

    let proto = src.create_protocol("p", &frame_lab::demo::demo_spec_json(), "").unwrap();
    let bytes = demo_frame();
    let blob = src.put_blob(&bytes).unwrap();
    let spec = demo_spec();
    let report = parser::parse(&spec, &bytes);
    let sess = src.create_session("s", "", &proto.id, 1, &blob, bytes.len(), &report).unwrap();
    let pkg = src.export_session(&sess.id).unwrap();

    let (i1, _) = dst.import_package(&pkg).unwrap();
    let (i2, _) = dst.import_package(&pkg).unwrap();
    // 同一协议摘要只对应一份协议；blob 去重
    assert_eq!(i1.current.protocol_id, i2.current.protocol_id, "协议应去重");
    assert_eq!(i1.current.blob, i2.current.blob);
    assert_eq!(dst.list_protocols().unwrap().len(), 1);
    assert_eq!(
        std::fs::read_dir(dir2.join("blobs")).unwrap().count(),
        1,
        "blob 目录只应有一个内容文件"
    );

    std::fs::remove_dir_all(&dir1).ok();
    std::fs::remove_dir_all(&dir2).ok();
}

#[test]
fn new_protocol_version_does_not_change_historical_sessions() {
    let dir = temp_dir("versions");
    let store = Store::open(&dir).unwrap();

    // v1：soi 常量 170
    let v1_json = frame_lab::demo::demo_spec_json();
    let proto = store.create_protocol("会演进的协议", &v1_json, "v1").unwrap();
    let bytes = demo_frame();
    let blob = store.put_blob(&bytes).unwrap();
    let spec1 = frame_lab::spec::Spec::from_json(&v1_json).unwrap();
    let report1 = parser::parse(&spec1, &bytes);
    assert_eq!(report1.status, Status::Ok);
    let sess = store
        .create_session("历史会话", "", &proto.id, 1, &blob, bytes.len(), &report1)
        .unwrap();
    let saved_digest = sess.current.report_digest;

    // v2：把 soi 常量改成别的（同一批字节在 v2 下应违规）——但会话必须仍按 v1 重放
    let mut v2_json = v1_json.clone();
    if let Json::Obj(root) = &mut v2_json {
        if let Some(Json::Arr(structs)) = root.get_mut("structs") {
            if let Json::Obj(frame) = &mut structs[0] {
                if let Some(Json::Arr(fields)) = frame.get_mut("fields") {
                    if let Json::Obj(soi) = &mut fields[0] {
                        soi.insert("const".into(), Json::Int(1));
                    }
                }
            }
        }
    }
    let rev2 = store.save_version(&proto.id, &v2_json, "收紧 soi").unwrap();
    assert_eq!(rev2.version, 2);

    // 重新打开历史会话：仍绑定 v1，结论不变
    let reloaded = store.load_session(&sess.id).unwrap();
    assert_eq!(reloaded.current.version, 1, "历史会话必须仍绑定 v1");
    let p = store.load_protocol(&proto.id).unwrap();
    let spec_replay = &p.revisions.iter().find(|r| r.version == 1).unwrap().spec;
    let replay = parser::parse(spec_replay, &store.get_blob(&blob).unwrap());
    assert_eq!(replay.status, Status::Ok);
    assert_eq!(replay.report_digest(), saved_digest, "新版本不能改变旧结论");

    // 同样字节按 v2 解析确实不同（证明版本间确实有差异，而不是没生效）
    let spec2 = &p.revisions.iter().find(|r| r.version == 2).unwrap().spec;
    let under_v2 = parser::parse(spec2, &bytes);
    assert_eq!(under_v2.status, Status::Violation);

    // 不可变：再次保存 v1 的内容返回同一版本号，不产生 v3
    let again = store.save_version(&proto.id, &v1_json, "重复保存 v1").unwrap();
    assert_eq!(again.version, 1);
    assert_eq!(store.load_protocol(&proto.id).unwrap().latest, 2);

    std::fs::remove_dir_all(&dir).ok();
}
