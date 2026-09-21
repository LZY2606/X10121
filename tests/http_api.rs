//! End-to-end JSON API checks against a real bound server on an ephemeral port.

use frame_lab::server::Server;
use serde_json::{json, Value};
use std::time::{SystemTime, UNIX_EPOCH};

struct TestServer {
    base: String,
}

fn spawn() -> TestServer {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let dir = std::env::temp_dir().join(format!("frame-lab-http-{}-{}", std::process::id(), nanos));
    let server = Server::bind("127.0.0.1:0", &dir).unwrap();
    let addr = server.local_addr().unwrap();
    std::thread::spawn(move || {
        let _ = server.run();
    });
    std::thread::sleep(std::time::Duration::from_millis(150));
    TestServer { base: format!("http://{}", addr) }
}

fn request(method: &str, url: &str, body: Option<Value>) -> (u16, Value) {
    ureq_like(method, url, body)
}

// Minimal HTTP/1.1 client over a TCP stream (no external dependency).
fn ureq_like(method: &str, url: &str, body: Option<Value>) -> (u16, Value) {
    use std::io::{Read, Write};
    use std::net::TcpStream;

    let addr = url.trim_start_matches("http://");
    let (host_port, path) = addr.split_once('/').map(|(h, p)| (h, format!("/{}", p))).unwrap_or((addr, "/".into()));
    let mut stream = TcpStream::connect(host_port).unwrap();
    let payload = match &body {
        Some(v) => serde_json::to_vec(v).unwrap(),
        None => Vec::new(),
    };
    write!(stream, "{} {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", method, path, host_port, payload.len()).unwrap();
    stream.write_all(&payload).unwrap();
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).unwrap();
    let header_end = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    let head = String::from_utf8_lossy(&raw[..header_end]).to_string();
    let status = head.lines().next().unwrap().split_whitespace().nth(1).unwrap().parse().unwrap();
    let body_text = String::from_utf8_lossy(&raw[header_end..]).to_string();
    let value = if body_text.trim().is_empty() {
        Value::Null
    } else {
        serde_json::from_str(&body_text).unwrap_or(Value::Null)
    };
    (status, value)
}

#[test]
fn serves_ui_and_full_api_flow() {
    let s = spawn();
    let (status, health) = request("GET", &format!("{}/api/health", s.base), None);
    assert_eq!(status, 200);
    assert_eq!(health["ok"], json!(true));

    // UI title is served at `/`.
    use std::io::{Read, Write};
    use std::net::TcpStream;
    let mut stream = TcpStream::connect(s.base.trim_start_matches("http://")).unwrap();
    write!(stream, "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").unwrap();
    let mut page = Vec::new();
    stream.read_to_end(&mut page).unwrap();
    let page = String::from_utf8_lossy(&page);
    assert!(page.contains("帧解析实验室"));

    // Create protocol + version.
    let spec = json!({
        "name": "httpdemo", "root": "frame", "endian": "big", "max_depth": 8,
        "structs": [{"name": "frame", "length_field": "total", "fields": [
            {"name": "total", "type": "int", "width": 1},
            {"name": "v", "type": "int", "width": 1}
        ]}]
    });
    assert_eq!(request("POST", &format!("{}/api/protocols", s.base), Some(json!({"name":"httpdemo"}))).0, 200);
    let (st, version) = request("POST", &format!("{}/api/versions", s.base),
        Some(json!({"protocol":"httpdemo","label":"v1","spec":spec})));
    assert_eq!(st, 200);
    let hash = version["version_hash"].as_str().unwrap().to_string();

    // Legal frame [total=2, v=7] is complete; one-byte prefix is incomplete.
    let (_, parsed) = request("POST", &format!("{}/api/parse", s.base),
        Some(json!({"version_hash":hash,"hex":"0207"})));
    assert_eq!(parsed["result"]["status"], json!("complete"));
    let (_, cut) = request("POST", &format!("{}/api/parse", s.base),
        Some(json!({"version_hash":hash,"hex":"02"})));
    assert_eq!(cut["result"]["status"], json!("incomplete"));
    assert!(cut["result"]["incomplete"]["need_at_least"].as_u64().unwrap() >= 1);
}
