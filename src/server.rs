//! 等价 JSON API + 静态前端。仅依赖 std::net。

use crate::encoder::{decode_hex, encode_hex};
use crate::json::{obj as jobj, Json};
use crate::model::ProtocolSpec;
use crate::parser::parse;
use crate::store::{SessionBundle, Store};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;

struct Response {
    status: u16,
    content_type: String,
    body: Vec<u8>,
}

fn json_status(status: u16, payload: Json) -> Response {
    Response {
        status,
        content_type: "application/json; charset=utf-8".into(),
        body: payload.to_string_pretty().into_bytes(),
    }
}
fn json(payload: Json) -> Response {
    json_status(200, payload)
}
fn err(status: u16, code: &str, message: &str) -> Response {
    json_status(
        status,
        jobj(vec![
            ("error", Json::string(code)),
            ("message", Json::string(message)),
        ]),
    )
}

struct App {
    store: Arc<Store>,
}

pub fn run(addr: &str, store: Arc<Store>) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr)?;
    serve(listener, store, addr)
}

pub fn serve(listener: TcpListener, store: Arc<Store>, addr: &str) -> std::io::Result<()> {
    let app = Arc::new(App { store });
    eprintln!("帧解析实验室 已启动: http://{}", addr);
    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                let app = Arc::clone(&app);
                std::thread::spawn(move || {
                    let _ = handle_connection(app, s);
                });
            }
            Err(e) => eprintln!("accept 失败: {}", e),
        }
    }
    Ok(())
}

struct Request {
    method: String,
    path: String,
    body: Vec<u8>,
}

fn handle_connection(app: Arc<App>, mut stream: TcpStream) -> std::io::Result<()> {
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(10)));
    let req = match read_request(&mut stream) {
        Some(r) => r,
        None => return Ok(()),
    };
    let resp = route(&app, &req);
    write_response(&mut stream, &resp)
}

fn read_request(stream: &mut TcpStream) -> Option<Request> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    let mut header_end = None;
    loop {
        let n = stream.read(&mut tmp).ok()?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(idx) = find_header_end(&buf) {
            header_end = Some(idx);
            break;
        }
        if buf.len() > 16 * 1024 * 1024 {
            return None;
        }
    }
    let header_end = header_end?;
    let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let mut lines = head.split("\r\n");
    let request_line = lines.next()?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next()?.to_string();
    let path = parts.next()?.to_string();
    let mut content_length = 0usize;
    for line in lines {
        if let Some(rest) = line.to_ascii_lowercase().strip_prefix("content-length:") {
            content_length = rest.trim().parse().ok()?;
        }
    }
    let body_start = header_end + 4;
    while buf.len() < body_start + content_length {
        let n = stream.read(&mut tmp).ok()?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
    }
    let body = if content_length > 0 {
        buf[body_start..body_start + content_length].to_vec()
    } else {
        Vec::new()
    };
    Some(Request { method, path, body })
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn write_response(stream: &mut TcpStream, resp: &Response) -> std::io::Result<()> {
    let reason = match resp.status {
        200 => "OK",
        201 => "Created",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        500 => "Internal Server Error",
        _ => "OK",
    };
    let head = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        resp.status,
        reason,
        resp.content_type,
        resp.body.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(&resp.body)?;
    stream.flush()
}

fn protocols_json(vs: &[crate::store::ProtocolVersion]) -> Json {
    Json::Arr(vs.iter().map(|v| v.to_json()).collect())
}

fn sessions_json(vs: &[crate::store::Session]) -> Json {
    Json::Arr(vs.iter().map(|v| v.to_json()).collect())
}

fn route(app: &App, req: &Request) -> Response {
    let path = req.path.split('?').next().unwrap_or("/").to_string();
    let method = req.method.as_str();
    match (method, path.as_str()) {
        ("GET", "/") | ("GET", "/index.html") => {
            serve_static("index.html", "text/html; charset=utf-8")
        }
        ("GET", "/static/app.js") => {
            serve_static("app.js", "application/javascript; charset=utf-8")
        }
        ("GET", "/static/style.css") => serve_static("style.css", "text/css; charset=utf-8"),
        ("GET", "/health") => json(jobj(vec![("ok", Json::Bool(true))])),
        ("GET", "/api/demo-frame") => json(jobj(vec![(
            "hex",
            Json::string(encode_hex(&crate::samples::demo_frame())),
        )])),
        ("GET", "/api/protocols") => match app.store.list_protocols() {
            Ok(v) => json(protocols_json(&v)),
            Err(e) => err(500, "store", &e),
        },
        ("POST", "/api/protocols") => post_protocol(app, req),
        ("GET", p) if p.starts_with("/api/protocols/") => {
            let id = &p["/api/protocols/".len()..];
            match app.store.load_protocol(id) {
                Ok(v) => json(v.to_json()),
                Err(_) => err(404, "not_found", "协议版本不存在"),
            }
        }
        ("POST", "/api/parse") => post_parse(app, req),
        ("POST", "/api/blobs") => post_blob(app, req),
        ("GET", p) if p.starts_with("/api/blobs/") => {
            let id = &p["/api/blobs/".len()..];
            match app.store.get_blob(id) {
                Ok(b) => json(jobj(vec![
                    ("blob_id", Json::string(id)),
                    ("hex", Json::string(encode_hex(&b))),
                ])),
                Err(_) => err(404, "not_found", "blob 不存在"),
            }
        }
        ("GET", "/api/sessions") => match app.store.list_sessions() {
            Ok(v) => json(sessions_json(&v)),
            Err(e) => err(500, "store", &e),
        },
        ("POST", "/api/sessions") => post_session(app, req),
        ("POST", "/api/sessions/import") => post_import(app, req),
        ("GET", p) if p.starts_with("/api/sessions/") && p.ends_with("/export") => {
            let id = &p["/api/sessions/".len()..p.len() - "/export".len()];
            match app.store.export_session(id) {
                Ok(b) => json(b.to_json()),
                Err(e) => err(404, "export", &e),
            }
        }
        ("GET", p) if p.starts_with("/api/sessions/") => {
            let id = &p["/api/sessions/".len()..];
            match app.store.load_session(id) {
                Ok(v) => json(v.to_json()),
                Err(_) => err(404, "not_found", "会话不存在"),
            }
        }
        ("PATCH", p) if p.starts_with("/api/sessions/") => {
            let id = &p["/api/sessions/".len()..];
            patch_note(app, req, id)
        }
        _ => err(404, "not_found", "未知路径"),
    }
}

fn serve_static(name: &str, content_type: &str) -> Response {
    match crate::webassets::read(name) {
        Some(bytes) => Response {
            status: 200,
            content_type: content_type.to_string(),
            body: bytes,
        },
        None => err(404, "not_found", "静态资源缺失"),
    }
}

fn body_json(req: &Request) -> Result<Json, Response> {
    Json::parse(&String::from_utf8_lossy(&req.body)).map_err(|e| err(400, "bad_json", &e))
}

fn hex_from_body(v: &Json) -> Result<Vec<u8>, Response> {
    let h = v
        .get("hex")
        .and_then(|x| x.as_str())
        .ok_or_else(|| err(400, "bad_request", "需要 hex 字段"))?;
    decode_hex(h).map_err(|e| err(400, "bad_hex", &e))
}

fn post_protocol(app: &App, req: &Request) -> Response {
    let v = match body_json(req) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let spec = match ProtocolSpec::from_json(&v) {
        Ok(s) => s,
        Err(e) => return err(400, "bad_spec", &e),
    };
    match app.store.save_protocol(&spec) {
        Ok(pv) => json_status(201, pv.to_json()),
        Err(e) => err(400, "invalid_spec", &e),
    }
}

fn post_parse(app: &App, req: &Request) -> Response {
    let v = match body_json(req) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let bytes = match hex_from_body(&v) {
        Ok(b) => b,
        Err(r) => return r,
    };
    let spec = match parse_spec_param(app, &v) {
        Ok(s) => s,
        Err(r) => return r,
    };
    json(parse(&spec, &bytes).to_json())
}

fn parse_spec_param(app: &App, v: &Json) -> Result<ProtocolSpec, Response> {
    if let Some(inline) = v.get("spec") {
        return ProtocolSpec::from_json(inline).map_err(|e| err(400, "bad_spec", &e));
    }
    if let Some(id) = v.get("version_id").and_then(|x| x.as_str()) {
        return app
            .store
            .load_protocol(id)
            .map(|pv| pv.spec)
            .map_err(|_| err(404, "not_found", "协议版本不存在"));
    }
    Err(err(400, "bad_request", "需要 spec 或 version_id"))
}

fn post_blob(app: &App, req: &Request) -> Response {
    let v = match body_json(req) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let bytes = match hex_from_body(&v) {
        Ok(b) => b,
        Err(r) => return r,
    };
    match app.store.put_blob(&bytes) {
        Ok(id) => json_status(
            201,
            jobj(vec![
                ("blob_id", Json::string(id)),
                ("length", Json::from_u64(bytes.len() as u64)),
            ]),
        ),
        Err(e) => err(500, "store", &e),
    }
}

fn post_session(app: &App, req: &Request) -> Response {
    let v = match body_json(req) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let version_id = v.get("version_id").and_then(|x| x.as_str()).unwrap_or("");
    let blob_id = v.get("blob_id").and_then(|x| x.as_str()).unwrap_or("");
    let title = v.get("title").and_then(|x| x.as_str()).unwrap_or("未命名样本");
    let note = v.get("note").and_then(|x| x.as_str()).unwrap_or("");
    match app.store.create_session(version_id, blob_id, title, note) {
        Ok(s) => json_status(201, s.to_json()),
        Err(e) => err(400, "create_session", &e),
    }
}

fn patch_note(app: &App, req: &Request, id: &str) -> Response {
    let v = match body_json(req) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let note = v.get("note").and_then(|x| x.as_str()).unwrap_or("");
    match app.store.update_note(id, note) {
        Ok(s) => json(s.to_json()),
        Err(e) => err(404, "not_found", &e),
    }
}

fn post_import(app: &App, req: &Request) -> Response {
    let v = match body_json(req) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let bundle = match SessionBundle::from_json(&v) {
        Ok(b) => b,
        Err(e) => return err(400, "bad_bundle", &e),
    };
    match app.store.import_bundle(&bundle) {
        Ok(s) => json_status(201, s.to_json()),
        Err(e) => err(409, "import", &e),
    }
}
