//! JSON API：与库能力等价；字节修改后重新解析，摘要随之变化且版本绑定不变。
#[allow(dead_code)]
mod common;

use common::*;
use frame_lab::api::Api;
use frame_lab::json::Json;

use frame_lab::storage::Store;

fn temp_dir() -> std::path::PathBuf {
    let mut d = std::env::temp_dir();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    d.push(format!("frame_lab_api_{nanos}_{}", std::process::id()));
    d
}

fn data_get(j: &Json) -> &Json {
    j.get("data").unwrap()
}

#[test]
fn api_parse_roundtrip_and_status_fields() {
    let dir = temp_dir();
    let api = Api::new(Store::open(&dir).unwrap());
    let bytes = demo_frame();
    let hex = frame_lab::hexutil::encode_hex(&bytes);
    let body = Json::obj()
        .with("spec", frame_lab::demo::demo_spec_json())
        .with("hex", Json::Str(hex.clone()));
    let (code, resp) = api.dispatch("POST", "/api/parse", &body.dump());
    assert_eq!(code, 200);
    let d = data_get(&resp);
    assert_eq!(d.get("status").and_then(|x| x.as_str()), Some("ok"));
    assert!(d.get("tree").is_some());
    assert!(d.get("tree_digest").and_then(|x| x.as_str()).unwrap().len() == 64);

    // 截断：incomplete + need
    let short = hex[..hex.len() - 4].to_string();
    let body2 = Json::obj()
        .with("spec", frame_lab::demo::demo_spec_json())
        .with("hex", Json::Str(short));
    let (_, r2) = api.dispatch("POST", "/api/parse", &body2.dump());
    let d2 = data_get(&r2);
    assert_eq!(d2.get("status").and_then(|x| x.as_str()), Some("incomplete"));
    assert!(d2.get("error").unwrap().get("need").and_then(|x| x.as_i64()).unwrap() >= 1);

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn api_byte_edit_recomputes_and_reports_changed_nodes() {
    let dir = temp_dir();
    let api = Api::new(Store::open(&dir).unwrap());

    // 创建协议
    let (_, pc) = api.dispatch(
        "POST",
        "/api/protocols",
        &Json::obj()
            .with("name", Json::Str("API 协议".into()))
            .with("spec", frame_lab::demo::demo_spec_json())
            .dump(),
    );
    let pid = data_get(&pc).get("id").and_then(|x| x.as_str()).unwrap().to_string();

    // 创建会话
    let hex = frame_lab::hexutil::encode_hex(&demo_frame());
    let (_, sc) = api.dispatch(
        "POST",
        "/api/sessions",
        &Json::obj()
            .with("title", Json::Str("编辑会话".into()))
            .with("protocol_id", Json::Str(pid.clone()))
            .with("version", Json::Int(1))
            .with("hex", Json::Str(hex.clone()))
            .dump(),
    );
    let sid = data_get(&sc).get("id").and_then(|x| x.as_str()).unwrap().to_string();
    let d1 = data_get(&sc)
        .get("report")
        .unwrap()
        .get("tree_digest")
        .and_then(|x| x.as_str())
        .unwrap()
        .to_string();

    // 修改一个 payload 字节 -> 新修订，状态变 violation，摘要变化，仍绑定 v1
    let mut bad = demo_frame();
    bad[9] ^= 0xFF;
    let hex2 = frame_lab::hexutil::encode_hex(&bad);
    let (_, rc) = api.dispatch(
        "POST",
        &format!("/api/sessions/{sid}/revisions"),
        &Json::obj().with("hex", Json::Str(hex2)).dump(),
    );
    let d = data_get(&rc);
    assert_eq!(d.get("report").unwrap().get("status").and_then(|x| x.as_str()), Some("violation"));
    let d2 = d.get("report").unwrap().get("tree_digest").and_then(|x| x.as_str()).unwrap().to_string();
    assert_ne!(d1, d2, "改字节后解析树摘要必须变化");
    assert_eq!(d.get("current").unwrap().get("version").and_then(|x| x.as_i64()), Some(1));

    // 会话历史现在有 2 个修订
    let (_, gs) = api.dispatch("GET", &format!("/api/sessions/{sid}"), "");
    let gd = data_get(&gs);
    assert_eq!(gd.get("revisions").unwrap().as_array().unwrap().len(), 2);
    assert_eq!(gd.get("replay_match").and_then(|x| x.as_bool()), Some(true));

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn api_import_export_cycle_via_json() {
    let dir1 = temp_dir();
    let dir2 = temp_dir();
    let a = Api::new(Store::open(&dir1).unwrap());
    let b = Api::new(Store::open(&dir2).unwrap());

    let (_, pc) = a.dispatch(
        "POST",
        "/api/protocols",
        &Json::obj().with("spec", frame_lab::demo::demo_spec_json()).dump(),
    );
    let pid = data_get(&pc).get("id").and_then(|x| x.as_str()).unwrap().to_string();
    let hex = frame_lab::hexutil::encode_hex(&demo_frame());
    let (_, sc) = a.dispatch(
        "POST",
        "/api/sessions",
        &Json::obj()
            .with("protocol_id", Json::Str(pid))
            .with("version", Json::Int(1))
            .with("hex", Json::Str(hex.clone()))
            .dump(),
    );
    let sid = data_get(&sc).get("id").and_then(|x| x.as_str()).unwrap().to_string();

    let (_, pkg) = a.dispatch("POST", &format!("/api/sessions/{sid}/export"), "");
    let req = Json::obj().with("package_json", data_get(&pkg).clone());
    let (code, imp) = b.dispatch("POST", "/api/import", &req.dump());
    assert_eq!(code, 200);
    let verify = data_get(&imp).get("verify").unwrap();
    assert_eq!(verify.get("match").and_then(|x| x.as_bool()), Some(true), "{}", verify.dump());

    std::fs::remove_dir_all(&dir1).ok();
    std::fs::remove_dir_all(&dir2).ok();
}
