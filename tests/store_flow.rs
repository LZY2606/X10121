mod common;

use common::{len_frame_protocol, Rng};
use frame_lab::store::Store;
use serde_json::json;

fn temp_dir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "frame-lab-test-{}-{}-{}",
        tag,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn valid_frame(seed: u64) -> (frame_lab::protocol::Protocol, Vec<u8>) {
    let proto = len_frame_protocol();
    let mut rng = Rng::new(seed);
    let n = 3 + rng.below(8);
    let data: Vec<u8> = (0..n).map(|_| rng.byte()).collect();
    let values = json!({
        "payload": { "kind": rng.below(256), "n": n, "data": frame_lab::hex::encode(&data) }
    });
    let frame = frame_lab::encoder::encode(&proto, &values).unwrap();
    (proto, frame)
}

#[test]
fn protocol_versions_are_immutable_and_deduped() {
    let dir = temp_dir("version");
    let store = Store::open(&dir).unwrap();
    let proto = len_frame_protocol();
    let v1 = store.save_version(&proto).unwrap();
    let v1_again = store.save_version(&proto).unwrap();
    assert_eq!(v1.version_id, v1_again.version_id, "相同规范必须复用版本");

    // 修改语义内容 -> 新版本；旧版本文件保持原样。
    let mut evolved = proto.clone();
    evolved.name = "长度协议-v2".to_string();
    let v2 = store.save_version(&evolved).unwrap();
    assert_ne!(v1.version_id, v2.version_id);

    let old = store.version_by_id(&v1.version_id).unwrap();
    assert_eq!(old.spec, proto, "历史版本不可变");

    // 仅 JSON 键顺序不同不应产生新版本（规范化哈希）。
    let reordered: frame_lab::protocol::Protocol =
        serde_json::from_str(&serde_json::to_string(&proto).unwrap()).unwrap();
    let v3 = store.save_version(&reordered).unwrap();
    assert_eq!(v3.version_id, v1.version_id);
}

#[test]
fn identical_samples_share_blob_but_sessions_and_notes_are_independent() {
    let dir = temp_dir("blob");
    let store = Store::open(&dir).unwrap();
    let (proto, frame) = valid_frame(7);
    let v = store.save_version(&proto).unwrap();

    let s1 = store.create_session(&v.version_id, &frame, "备注一").unwrap();
    let s2 = store.create_session(&v.version_id, &frame, "备注二").unwrap();
    assert_ne!(s1.rec.session_id, s2.rec.session_id, "会话互相独立");
    assert_eq!(s1.rec.blob_hash, s2.rec.blob_hash, "相同样本指向同一 blob");

    // 存储中 blob 文件只有一份。
    let mut blob_files = 0;
    for entry in walkdir(&dir.join("blobs")) {
        if entry.extension().is_some_and(|e| e == "bin") {
            blob_files += 1;
        }
    }
    assert_eq!(blob_files, 1, "相同内容必须去重为一个 blob 文件");

    store.set_note(&s1.rec.session_id, "修改后的备注一").unwrap();
    let again1 = store.get_session(&s1.rec.session_id).unwrap();
    let again2 = store.get_session(&s2.rec.session_id).unwrap();
    assert_eq!(again1.rec.note, "修改后的备注一");
    assert_eq!(again2.rec.note, "备注二", "另一会话备注不受影响");
}

fn walkdir(root: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(root) {
        for entry in rd.flatten() {
            let path = entry.path();
            if path.is_dir() {
                out.extend(walkdir(&path));
            } else {
                out.push(path);
            }
        }
    }
    out
}

#[test]
fn old_session_replays_with_bound_version_despite_new_version() {
    let dir = temp_dir("replay");
    let store = Store::open(&dir).unwrap();
    let (mut proto, frame) = valid_frame(11);
    let v1 = store.save_version(&proto).unwrap();
    let session = store
        .create_session(&v1.version_id, &frame, "历史会话")
        .unwrap();

    // 发布不兼容的新版本（校验和升级为 warning 语义变化的姊妹协议）。
    proto.name = "演进后的协议".to_string();
    let v2 = store.save_version(&proto).unwrap();
    assert_ne!(v1.version_id, v2.version_id);

    // 历史会话仍按 v1 重放，结论与快照一致。
    let replay = store.replay(&session.rec.session_id).unwrap();
    assert!(replay.consistent, "旧会话必须按绑定版本确定性重放");
    assert_eq!(replay.session.rec.version_id, v1.version_id);
    assert_eq!(replay.outcome.status, frame_lab::parser::Status::Complete);
}

#[test]
fn export_then_import_is_deterministic() {
    let dir_a = temp_dir("export-a");
    let dir_b = temp_dir("import-b");
    let store_a = Store::open(&dir_a).unwrap();
    let store_b = Store::open(&dir_b).unwrap();

    let (proto, frame) = valid_frame(99);
    let v = store_a.save_version(&proto).unwrap();
    let session = store_a
        .create_session(&v.version_id, &frame, "待导出")
        .unwrap();

    let bundle_value = serde_json::to_value(store_a.export_session(&session.rec.session_id).unwrap())
        .unwrap();
    let bundle: frame_lab::store::ImportBundle =
        serde_json::from_value(bundle_value).unwrap();
    let imported = store_b.import_bundle(&bundle).unwrap();

    // 版本一致、blob 一致、会话快照一致。
    assert_eq!(imported.rec.version_id, session.rec.version_id);
    assert_eq!(imported.rec.blob_hash, session.rec.blob_hash);
    assert_eq!(imported.rec.snapshot, session.rec.snapshot);

    // 再次导入：blob/版本去重，但得到独立新会话。
    let imported2 = store_b.import_bundle(&bundle).unwrap();
    assert_ne!(imported.rec.session_id, imported2.rec.session_id);
    assert_eq!(imported2.rec.blob_hash, imported.rec.blob_hash);

    // 重放导入会话仍然一致；字节逐位相同。
    let replay_b = store_b.replay(&imported.rec.session_id).unwrap();
    assert!(replay_b.consistent);
    let bytes_b = store_b.get_blob(&imported.rec.blob_hash).unwrap();
    assert_eq!(bytes_b, frame);
}

#[test]
fn import_rejects_tampered_bundle() {
    let dir_a = temp_dir("tamper-a");
    let dir_b = temp_dir("tamper-b");
    let store_a = Store::open(&dir_a).unwrap();
    let store_b = Store::open(&dir_b).unwrap();

    let (proto, frame) = valid_frame(5);
    let v = store_a.save_version(&proto).unwrap();
    let session = store_a
        .create_session(&v.version_id, &frame, "x")
        .unwrap();
    let mut bundle_value =
        serde_json::to_value(store_a.export_session(&session.rec.session_id).unwrap()).unwrap();

    // 篡改一个数据字节但保留原快照 -> 必须拒绝。
    let mut hex = bundle_value["blob_hex"].as_str().unwrap().to_string();
    let mut bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect();
    bytes[0] ^= 0x01;
    hex = frame_lab::hex::encode(&bytes);
    bundle_value["blob_hex"] = serde_json::Value::String(hex);
    let tampered: frame_lab::store::ImportBundle =
        serde_json::from_value(bundle_value).unwrap();
    assert!(store_b.import_bundle(&tampered).is_err());
}

#[test]
fn incomplete_and_error_sessions_persist_distinct_status() {
    let dir = temp_dir("statuses");
    let store = Store::open(&dir).unwrap();
    let (proto, frame) = valid_frame(3);
    let v = store.save_version(&proto).unwrap();

    let truncated = &frame[..frame.len() - 2];
    let inc = store
        .create_session(&v.version_id, truncated, "截断样本")
        .unwrap();
    assert_eq!(inc.rec.snapshot.status, "incomplete");
    assert!(inc.rec.snapshot.diagnostics.iter().any(|d| d.need_more.is_some()));

    let mut evil = frame.clone();
    evil[0] = 0x00; // 破坏 soh 魔数
    let bad = store.create_session(&v.version_id, &evil, "非法样本").unwrap();
    assert_eq!(bad.rec.snapshot.status, "error");
    let err_diag = bad
        .rec
        .snapshot
        .diagnostics
        .iter()
        .find(|d| d.severity == "error")
        .unwrap();
    assert_eq!(err_diag.offset, 0);

    let replay = store.replay(&inc.rec.session_id).unwrap();
    assert!(replay.consistent);
}
