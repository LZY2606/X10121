mod common;


use framelab::json::Json;
use framelab::store::Store;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

struct Server {
    addr: String,
}

fn start_server() -> Server {
    let dir = common::temp_dir("api");
    let store = Arc::new(Store::open(&dir).unwrap());
    framelab::samples::seed_demo_protocol(&store).unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let store2 = Arc::clone(&store);
    let a2 = addr.clone();
    std::thread::spawn(move || framelab::server::serve(listener, store2, &a2).unwrap());
    std::thread::sleep(std::time::Duration::from_millis(150));
    Server { addr }
}

fn request(s: &Server, method: &str, path: &str, body: Option<&str>) -> (u16, Json) {
    let mut stream = TcpStream::connect(&s.addr).unwrap();
    let mut req = format!(
        "{} {} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n",
        method, path
    );
    if let Some(b) = body {
        req.push_str(&format!("Content-Length: {}\r\nContent-Type: application/json\r\n", b.len()));
    }
    req.push_str("\r\n");
    if let Some(b) = body {
        req.push_str(b);
    }
    stream.write_all(req.as_bytes()).unwrap();
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).unwrap();
    let text = String::from_utf8_lossy(&raw);
    let status: u16 = text.split_whitespace().nth(1).unwrap().parse().unwrap();
    let body_start = text.find("\r\n\r\n").unwrap() + 4;
    let j = Json::parse(&text[body_start..]).unwrap_or(Json::Null);
    (status, j)
}

fn first_demo_version(j: &Json) -> String {
    j.as_array()
        .unwrap()
        .iter()
        .find(|v| v.get("name").and_then(|n| n.as_str()) == Some("演示帧 v1"))
        .unwrap()
        .get("version_id")
        .unwrap()
        .as_str()
        .unwrap()
        .to_string()
}

#[test]
fn full_api_flow_and_index() {
    let s = start_server();

    // 首页包含标题
    request(&s, "GET", "/", None);
    // 静态 JSON 无法解析 HTML，因此单独验证字节
    let mut stream = TcpStream::connect(&s.addr).unwrap();
    stream.write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").unwrap();
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).unwrap();
    let html = String::from_utf8_lossy(&raw);
    assert!(html.contains("帧解析实验室"));

    // 健康检查
    let (st, j) = request(&s, "GET", "/health", None);
    assert_eq!(st, 200);
    assert_eq!(j.get("ok").and_then(|v| v.as_bool()), Some(true));

    // 内置协议已播种
    let (st, versions) = request(&s, "GET", "/api/protocols", None);
    assert_eq!(st, 200);
    let version_id = first_demo_version(&versions);

    // 示例帧
    let (st, demo) = request(&s, "GET", "/api/demo-frame", None);
    assert_eq!(st, 200);
    let hex = demo.get("hex").unwrap().as_str().unwrap().to_string();

    // 解析成功
    let parse_body = format!(r#"{{"version_id":"{}","hex":"{}"}}"#, version_id, hex);
    let (st, report) = request(&s, "POST", "/api/parse", Some(&parse_body));
    assert_eq!(st, 200);
    assert_eq!(report.get("outcome").unwrap().as_str(), Some("complete"));
    assert!(report.get("tree").unwrap().get("children").unwrap().as_array().unwrap().len() >= 5);

    // 截断 -> incomplete 下界
    let cut = &hex[..hex.len() - 4];
    let body = format!(r#"{{"version_id":"{}","hex":"{}"}}"#, version_id, cut);
    let (st, r) = request(&s, "POST", "/api/parse", Some(&body));
    assert_eq!(st, 200);
    assert_eq!(r.get("outcome").unwrap().as_str(), Some("incomplete"));
    assert!(r.get("need_bytes").unwrap().as_u64().unwrap() >= 1);

    // blob 幂等
    let body = format!(r#"{{"hex":"{}"}}"#, hex);
    let (st, b1) = request(&s, "POST", "/api/blobs", Some(&body));
    assert_eq!(st, 201);
    let (st, b2) = request(&s, "POST", "/api/blobs", Some(&body));
    assert_eq!(st, 201);
    let id1 = b1.get("blob_id").unwrap().as_str().unwrap();
    assert_eq!(id1, b2.get("blob_id").unwrap().as_str().unwrap());

    // 建会话
    let body = format!(
        r#"{{"version_id":"{}","blob_id":"{}","title":"API 样本","note":"n1"}}"#,
        version_id, id1
    );
    let (st, sess) = request(&s, "POST", "/api/sessions", Some(&body));
    assert_eq!(st, 201);
    let sid = sess.get("session_id").unwrap().as_str().unwrap().to_string();
    assert_eq!(sess.get("report").unwrap().get("outcome").unwrap().as_str(), Some("complete"));

    // 导出 -> 再导入
    let (st, bundle) = request(&s, "GET", &format!("/api/sessions/{}/export", sid), None);
    assert_eq!(st, 200);
    let bundle_text = bundle.to_string();
    let (st, imported) = request(&s, "POST", "/api/sessions/import", Some(&bundle_text));
    assert_eq!(st, 201, "import: {}", imported.to_string());
    assert_ne!(
        imported.get("session_id").unwrap().as_str(),
        Some(sid.as_str())
    );

    // 备注独立修改
    let (st, _) = request(&s, "PATCH", &format!("/api/sessions/{}", sid), Some(r#"{"note":"新备注"}"#));
    assert_eq!(st, 200);
    let (_st, updated) = request(&s, "GET", &format!("/api/sessions/{}", sid), None);
    assert_eq!(updated.get("note").unwrap().as_str(), Some("新备注"));

    // 非法协议 400
    let (st, errj) = request(&s, "POST", "/api/protocols", Some(r#"{"name":"x","root":"nope","structs":{}}"#));
    assert_eq!(st, 400);
    assert!(errj.get("message").unwrap().as_str().unwrap().contains("根结构体"));

    // 404
    let (st, _) = request(&s, "GET", "/api/protocols/nonexistent", None);
    assert_eq!(st, 404);
}
