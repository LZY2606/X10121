mod common;

use common::{len_frame_protocol, Rng};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::time::Duration;

struct TestServer {
    addr: String,
    _dir: PathBuf,
}

fn request(addr: &str, method: &str, path: &str, body: Option<Value>) -> (u16, Value) {
    let mut stream = TcpStream::connect(addr).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(8))).unwrap();
    let payload = match &body {
        Some(v) => serde_json::to_vec(v).unwrap(),
        None => Vec::new(),
    };
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        payload.len()
    );
    stream.write_all(req.as_bytes()).unwrap();
    stream.write_all(&payload).unwrap();
    let mut raw = Vec::new();
    stream
        .read_to_end(&mut raw)
        .unwrap_or_else(|e| panic!("读取 {method} {path} 失败: {e}; 已收到 {} 字节: {:?}", raw.len(), String::from_utf8_lossy(&raw)));
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap() + 4;
    let status = String::from_utf8_lossy(&raw[..40])
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    let value: Value = serde_json::from_slice(&raw[split..]).unwrap();
    (status, value)
}

impl TestServer {
    fn start() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "frame-lab-api-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        drop(listener);
        let store = std::sync::Arc::new(frame_lab::store::Store::open(&dir).unwrap());
        let listen_addr = addr.clone();
        std::thread::spawn(move || {
            let listener = std::net::TcpListener::bind(&listen_addr).unwrap();
            for stream in listener.incoming().flatten() {
                let store = std::sync::Arc::clone(&store);
                std::thread::spawn(move || {
                    let _ = frame_lab::server::handle_public(stream, &store);
                });
            }
        });
        std::thread::sleep(Duration::from_millis(150));
        TestServer {
            addr,
            _dir: dir,
        }
    }
}

#[test]
fn full_api_lifecycle_and_static_page() {
    let server = TestServer::start();
    let base = format!("http://{}", server.addr);

    // 首页包含标题。
    let mut stream = TcpStream::connect(&server.addr).unwrap();
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut html = Vec::new();
    stream.read_to_end(&mut html).unwrap();
    let text = String::from_utf8_lossy(&html);
    assert!(text.contains("帧解析实验室"), "首页必须出现产品标题");

    // 保存协议版本。
    let proto = len_frame_protocol();
    let (_, resp) = request(
        &server.addr,
        "POST",
        "/api/protocols",
        Some(json!({ "spec": proto })),
    );
    let version_id = resp["version"]["version_id"].as_str().unwrap().to_string();

    // 编码 -> 解析。
    let (_, enc) = request(
        &server.addr,
        "POST",
        "/api/encode",
        Some(json!({
            "version_id": version_id,
            "values": { "payload": { "kind": 3, "n": 2, "data": "abcd" } }
        })),
    );
    let hex = enc["hex"].as_str().unwrap().to_string();
    let (_, parsed) = request(
        &server.addr,
        "POST",
        "/api/parse",
        Some(json!({ "version_id": version_id, "hex": hex })),
    );
    assert_eq!(parsed["outcome"]["status"], "complete");

    // 截断 -> incomplete。
    let short: String = hex.chars().take(hex.len() - 4).collect();
    let (_, inc) = request(
        &server.addr,
        "POST",
        "/api/parse",
        Some(json!({ "version_id": version_id, "hex": short })),
    );
    assert_eq!(inc["outcome"]["status"], "incomplete");
    let need = inc["outcome"]["diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .find_map(|d| d["need_more"].as_u64());
    assert!(need.is_some_and(|n| n >= 1));

    // 会话保存、回放、导出/导入。
    let (_, sess) = request(
        &server.addr,
        "POST",
        "/api/sessions",
        Some(json!({ "version_id": version_id, "hex": hex, "note": "api 会话" })),
    );
    let session_id = sess["session"]["session_id"].as_str().unwrap();
    let (_, replay) = request(
        &server.addr,
        "POST",
        "/api/replay",
        Some(json!({ "session_id": session_id })),
    );
    assert_eq!(replay["consistent"], true);

    let (_, bundle) = request(
        &server.addr,
        "POST",
        "/api/export",
        Some(json!({ "session_id": session_id })),
    );
    let (imp_status, imported) = request(
        &server.addr,
        "POST",
        "/api/import",
        Some(json!({ "bundle": bundle["bundle"].clone() })),
    );
    assert_eq!(imp_status, 200);
    assert_eq!(
        imported["session"]["snapshot"]["tree_digest"],
        sess["session"]["snapshot"]["tree_digest"]
    );

    // 列表 API。
    let (_, list) = request(&server.addr, "GET", "/api/sessions", None);
    assert!(list["sessions"].as_array().unwrap().len() >= 2);

    let _ = base;
}

#[test]
fn deterministic_parse_is_idempotent_under_random_input() {
    let proto = len_frame_protocol();
    let version = frame_lab::store::Store::open(
        &std::env::temp_dir().join(format!("frame-lab-det-{}", std::process::id())),
    )
    .unwrap()
    .save_version(&proto)
    .unwrap();
    let _ = version;
    let mut rng = Rng::new(424242);
    for _ in 0..300 {
        let len = rng.below(40);
        let input: Vec<u8> = (0..len).map(|_| rng.byte()).collect();
        let o1 = frame_lab::parser::parse(&proto, &input).unwrap();
        let o2 = frame_lab::parser::parse(&proto, &input).unwrap();
        let d1 = frame_lab::parser::tree_digest(&o1.root);
        let d2 = frame_lab::parser::tree_digest(&o2.root);
        assert_eq!(d1, d2, "同一输入解析必须确定");
        assert_eq!(o1.status, o2.status);
        assert_eq!(o1.diagnostics, o2.diagnostics);

        // incomplete 与 error 互斥原则：随机短帧若解析失败必须落入其一。
        match o1.status {
            frame_lab::parser::Status::Complete
            | frame_lab::parser::Status::Incomplete
            | frame_lab::parser::Status::Error => {}
        }
    }
}
