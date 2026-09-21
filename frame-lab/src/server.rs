//! 最小 HTTP/1.1 服务器：静态前端 + JSON API。每连接一线程。

use crate::dsl_check::compile;
use crate::json::Json;
use crate::parser;
use crate::store::LabStore;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

use std::sync::Arc;
use std::time::Duration;

const INDEX_HTML: &str = include_str!("../static/index.html");
const APP_JS: &str = include_str!("../static/app.js");
const APP_CSS: &str = include_str!("../static/app.css");

pub struct Server {
    store: Arc<LabStore>,
}

pub fn serve(store: Arc<LabStore>, addr: &str) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr)?;
    eprintln!("帧解析实验室已启动：http://{}", addr);
    for stream in listener.incoming() {
        let stream = match stream {
            Ok(s) => s,
            Err(_) => continue,
        };
        let store = Arc::clone(&store);
        std::thread::spawn(move || {
            let _ = handle(stream, store);
        });
    }
    Ok(())
}

fn handle(mut stream: TcpStream, store: Arc<LabStore>) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(15)))?;
    stream.set_write_timeout(Some(Duration::from_secs(15)))?;

    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    let header_end;
    loop {
        if let Some(pos) = find_header_end(&buf) {
            header_end = Some(pos);
            break;
        }
        let n = stream.read(&mut tmp)?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.len() > 8 * 1024 * 1024 {
            return Ok(());
        }
    }
    let header_end = header_end.unwrap();
    let header_text = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let mut lines = header_text.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let target = parts.next().unwrap_or("/").to_string();

    let mut content_length = 0usize;
    for line in lines {
        if let Some(rest) = line
            .split_once(':')
            .map(|(k, v)| (k.trim().to_lowercase(), v.trim()))
        {
            if rest.0 == "content-length" {
                content_length = rest.1.parse().unwrap_or(0);
            }
        }
    }

    let body_start = header_end + 4;
    while buf.len() < body_start + content_length {
        let n = stream.read(&mut tmp)?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
    }
    let available = buf.len().saturating_sub(body_start);
    let take = content_length.min(available);
    let body = buf[body_start..body_start + take].to_vec();

    let srv = Server { store };
    let (status, ctype, payload) = srv.route(&method, &target, &body);
    write_response(&mut stream, status, ctype, &payload)
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn write_response(
    stream: &mut TcpStream,
    status: u16,
    ctype: &str,
    body: &[u8],
) -> std::io::Result<()> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        500 => "Internal Server Error",
        _ => "OK",
    };
    let head = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\nAccess-Control-Allow-Origin: *\r\n\r\n",
        status,
        reason,
        ctype,
        body.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(body)?;
    Ok(())
}

fn json_ok(j: Json) -> (u16, &'static str, Vec<u8>) {
    (200, "application/json; charset=utf-8", j.pretty().into_bytes())
}

fn json_error(status: u16, message: &str) -> (u16, &'static str, Vec<u8>) {
    let mut j = Json::obj();
    j.put("error", Json::str(message));
    (status, "application/json; charset=utf-8", j.pretty().into_bytes())
}

impl Server {
    fn route(&self, method: &str, target: &str, body: &[u8]) -> (u16, &'static str, Vec<u8>) {
        let path = target.split('?').next().unwrap_or("/");
        match (method, path) {
            ("GET", "/") => (200, "text/html; charset=utf-8", INDEX_HTML.as_bytes().to_vec()),
            ("GET", "/static/app.js") => (200, "application/javascript; charset=utf-8", APP_JS.as_bytes().to_vec()),
            ("GET", "/static/app.css") => (200, "text/css; charset=utf-8", APP_CSS.as_bytes().to_vec()),
            ("GET", "/api/health") => json_ok(Json::obj().with("ok", Json::Bool(true))),
            ("GET", "/api/protocols") => self.with_store(|s| {
                let arr = Json::Arr(s.list_protocols()?);
                Ok(json_ok(Json::obj().with("protocols", arr)))
            }),
            ("POST", "/api/protocols/versions") => {
                self.with_json(body, |j| {
                    let name = j.get("name").and_then(|v| v.as_str()).ok_or("缺少 name")?;
                    let source = j.get("source").and_then(|v| v.as_str()).ok_or("缺少 source")?;
                    let (pid, vid, reused) = self.store.save_version(name, source)
                        .map_err(|e| e.to_string())?;
                    let mut o = Json::obj();
                    o.put("protocol_id", Json::str(&pid));
                    o.put("version_id", Json::str(&vid));
                    o.put("reused", Json::Bool(reused));
                    Ok(json_ok(o))
                })
            }
            ("POST", "/api/compile") => self.with_json(body, |j| {
                let source = j.get("source").and_then(|v| v.as_str()).ok_or("缺少 source")?;
                compile(source).map_err(|e| e)?;
                Ok(json_ok(Json::obj().with("ok", Json::Bool(true))))
            }),
            ("POST", "/api/parse") => self.with_json(body, |j| {
                let source = j.get("source").and_then(|v| v.as_str());
                let parsed = self.run_parse(j, source)?;
                Ok(json_ok(parsed.to_json()))
            }),
            ("POST", "/api/blobs") => self.with_json(body, |j| {
                let bytes = self.body_bytes(j)?;
                let (id, reused) = self.store.put_blob(&bytes).map_err(|e| e.to_string())?;
                let mut o = Json::obj();
                o.put("blob_id", Json::str(&id));
                o.put("byte_length", Json::Int(bytes.len() as i64));
                o.put("reused", Json::Bool(reused));
                Ok(json_ok(o))
            }),
            ("GET", p) if p.starts_with("/api/blobs/") => {
                let id = p.trim_start_matches("/api/blobs/");
                match self.store.get_blob(id) {
                    Ok(Some(b)) => json_ok(Json::obj()
                        .with("blob_id", Json::str(id))
                        .with("hex", Json::str(&crate::hex::encode(&b)))),
                    Ok(None) => json_error(404, "blob 不存在"),
                    Err(e) => json_error(500, &e.to_string()),
                }
            }
            ("POST", "/api/sessions") => self.with_json(body, |j| {
                let pid = j.get("protocol_id").and_then(|v| v.as_str()).ok_or("缺少 protocol_id")?;
                let vid = j.get("version_id").and_then(|v| v.as_str()).ok_or("缺少 version_id")?;
                let note = j.get("note").and_then(|v| v.as_str()).unwrap_or("");
                let bytes = self.session_bytes(j)?;
                let (session, _) = self.store.create_session(pid, vid, &bytes, note)
                    .map_err(|e| e.to_string())?;
                Ok(json_ok(session))
            }),
            ("GET", "/api/sessions") => self.with_store(|s| {
                Ok(json_ok(Json::obj().with("sessions", Json::Arr(s.list_sessions()?))))
            }),
            ("GET", p) if p.starts_with("/api/sessions/") && p.ends_with("/replay") => {
                let id = p.trim_start_matches("/api/sessions/").trim_end_matches("/replay");
                match self.store.replay_session(id) {
                    Ok(Some(r)) => json_ok(r),
                    Ok(None) => json_error(404, "会话不存在"),
                    Err(e) => json_error(500, &e.to_string()),
                }
            }
            ("POST", p) if p.starts_with("/api/sessions/") && p.ends_with("/export") => {
                let id = p.trim_start_matches("/api/sessions/").trim_end_matches("/export");
                match self.store.export_package(id) {
                    Ok(pkg) => json_ok(pkg),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => json_error(404, &e.to_string()),
                    Err(e) => json_error(500, &e.to_string()),
                }
            }
            ("POST", "/api/sessions/import") => self.with_json(body, |j| {
                let report = self.store.import_package(j).map_err(|e| e.to_string())?;
                let mut o = Json::obj();
                o.put("protocol_id", Json::str(&report.protocol_id));
                o.put("version_id", Json::str(&report.version_id));
                o.put("blob_id", Json::str(&report.blob_id));
                o.put("session_id", Json::str(&report.session_id));
                o.put("reused_blob", Json::Bool(report.reused_blob));
                o.put("reused_version", Json::Bool(report.reused_version));
                o.put("reused_session", Json::Bool(report.reused_session));
                Ok(json_ok(o))
            }),
            _ => {
                if path.starts_with("/api/") {
                    json_error(404, "未知 API")
                } else {
                    (404, "text/plain; charset=utf-8", b"Not Found".to_vec())
                }
            }
        }
    }

    fn with_store<F>(&self, f: F) -> (u16, &'static str, Vec<u8>)
    where
        F: FnOnce(&LabStore) -> std::io::Result<(u16, &'static str, Vec<u8>)>,
    {
        let _g = self.store.lock.lock().unwrap_or_else(|p| p.into_inner());
        match f(&self.store) {
            Ok(v) => v,
            Err(e) => json_error(500, &e.to_string()),
        }
    }

    fn with_json<F>(&self, body: &[u8], f: F) -> (u16, &'static str, Vec<u8>)
    where
        F: FnOnce(&Json) -> Result<(u16, &'static str, Vec<u8>), String>,
    {
        let _g = self.store.lock.lock().unwrap_or_else(|p| p.into_inner());
        let text = std::str::from_utf8(body).unwrap_or("{}");
        let j = match crate::json::parse(text) {
            Ok(j) => j,
            Err(e) => return json_error(400, &format!("请求 JSON 解析失败：{}", e)),
        };
        match f(&j) {
            Ok(v) => v,
            Err(msg) => json_error(400, &msg),
        }
    }

    fn body_bytes(&self, j: &Json) -> Result<Vec<u8>, &'static str> {
        if let Some(hex) = j.get("hex").and_then(|v| v.as_str()) {
            return crate::hex::decode(hex).map_err(|_| "十六进制非法");
        }
        if let Some(blob_id) = j.get("blob_id").and_then(|v| v.as_str()) {
            return self
                .store
                .get_blob(blob_id)
                .map_err(|_| "读取 blob 失败")?
                .ok_or("blob 不存在");
        }
        Err("缺少 hex 或 blob_id")
    }

    fn session_bytes(&self, j: &Json) -> Result<Vec<u8>, &'static str> {
        if let Some(hex) = j.get("hex").and_then(|v| v.as_str()) {
            return crate::hex::decode(hex).map_err(|_| "十六进制非法");
        }
        if let Some(blob_id) = j.get("blob_id").and_then(|v| v.as_str()) {
            return self
                .store
                .get_blob(blob_id)
                .map_err(|_| "读取 blob 失败")?
                .ok_or("blob 不存在");
        }
        Err("缺少 hex 或 blob_id")
    }

    fn run_parse<'a>(
        &self,
        j: &'a Json,
        source_override: Option<&str>,
    ) -> Result<parser::ParseOut, &'static str> {
        let bytes = self.body_bytes(j)?;
        let protocol = if let Some(source) = source_override {
            compile(source).map_err(|_| "DSL 编译失败")?
        } else {
            let pid = j.get("protocol_id").and_then(|v| v.as_str()).ok_or("缺少 protocol_id")?;
            let vid = j.get("version_id").and_then(|v| v.as_str()).ok_or("缺少 version_id")?;
            let version = self
                .store
                .get_version(pid, vid)
                .map_err(|_| "读取版本失败")?
                .ok_or("版本不存在")?;
            let source = version.get("source").and_then(|v| v.as_str()).ok_or("版本缺 source")?;
            compile(source).map_err(|_| "DSL 编译失败")?
        };
        Ok(parser::parse(&protocol, &bytes))
    }
}
