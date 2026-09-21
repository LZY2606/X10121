//! Small standard-library HTTP server exposing a JSON API and the embedded
//! single-page UI. No external HTTP crate or system service is involved.

use crate::parser;
use crate::spec::{RawSpec, Spec};
use crate::store::Store;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::sync::Arc;
use std::thread;

pub const INDEX_HTML: &str = include_str!("../static/index.html");
pub const APP_JS: &str = include_str!("../static/app.js");
pub const STYLE_CSS: &str = include_str!("../static/style.css");

pub struct Server {
    store: Arc<Store>,
    listener: TcpListener,
}

impl Server {
    pub fn bind(addr: &str, data_dir: &Path) -> std::io::Result<Server> {
        let store = Store::open(data_dir).map_err(|e| std::io::Error::other(e.0))?;
        let listener = TcpListener::bind(addr)?;
        Ok(Server { store: Arc::new(store), listener })
    }

    pub fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.listener.local_addr()
    }

    pub fn run(self) -> std::io::Result<()> {
        let addr = self.listener.local_addr()?;
        println!("帧解析实验室 listening on http://{}", addr);
        println!("data directory: {}", self.store.root().display());
        for stream in self.listener.incoming() {
            match stream {
                Ok(stream) => {
                    let store = Arc::clone(&self.store);
                    thread::spawn(move || {
                        let _ = handle_connection(store, stream);
                    });
                }
                Err(_) => continue,
            }
        }
        Ok(())
    }
}

struct Request {
    method: String,
    path: String,
    body: Vec<u8>,
}

fn handle_connection(store: Arc<Store>, mut stream: TcpStream) -> std::io::Result<()> {
    stream.set_read_timeout(Some(std::time::Duration::from_secs(10)))?;
    let mut raw = Vec::new();
    let mut buf = [0u8; 4096];

    // Read headers.
    loop {
        let n = stream.read(&mut buf)?;
        if n == 0 {
            return Ok(());
        }
        raw.extend_from_slice(&buf[..n]);
        if raw.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if raw.len() > 1 << 20 {
            return Ok(());
        }
    }

    let header_end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + 4)
        .unwrap_or(raw.len());
    let headers = String::from_utf8_lossy(&raw[..header_end]).into_owned();
    let mut lines = headers.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let target = parts.next().unwrap_or("/").to_string();

    let mut content_length = 0usize;
    for line in lines {
        if let Some(rest) = line.to_ascii_lowercase().strip_prefix("content-length:") {
            content_length = rest.trim().parse().unwrap_or(0);
        }
    }
    if content_length > 16 * 1024 * 1024 {
        send_json(
            &mut stream,
            413,
            &serde_json::json!({"error": "request body too large"}),
        )?;
        return Ok(());
    }

    let mut body = raw[header_end..].to_vec();
    while body.len() < content_length {
        let n = stream.read(&mut buf)?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&buf[..n]);
    }
    body.truncate(content_length);

    let req = Request { method, path: target, body };
    let response = route(&store, &req);
    write_response(&mut stream, response)
}

struct Response {
    status: u16,
    content_type: String,
    body: Vec<u8>,
}

fn ok_json(value: &serde_json::Value) -> Response {
    Response {
        status: 200,
        content_type: "application/json; charset=utf-8".into(),
        body: serde_json::to_vec_pretty(value).unwrap_or_default(),
    }
}

fn error_json(status: u16, message: &str) -> Response {
    Response {
        status,
        content_type: "application/json; charset=utf-8".into(),
        body: serde_json::to_vec_pretty(&serde_json::json!({"error": message})).unwrap_or_default(),
    }
}

fn static_asset(kind: AssetKind) -> Response {
    let (content_type, body) = match kind {
        AssetKind::Index => ("text/html; charset=utf-8", INDEX_HTML.as_bytes()),
        AssetKind::Js => ("application/javascript; charset=utf-8", APP_JS.as_bytes()),
        AssetKind::Css => ("text/css; charset=utf-8", STYLE_CSS.as_bytes()),
    };
    Response { status: 200, content_type: content_type.into(), body: body.to_vec() }
}

enum AssetKind {
    Index,
    Js,
    Css,
}

fn write_response(stream: &mut TcpStream, resp: Response) -> std::io::Result<()> {
    let reason = match resp.status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        413 => "Payload Too Large",
        500 => "Internal Server Error",
        _ => "OK",
    };
    write!(
        stream,
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n",
        resp.status,
        reason,
        resp.content_type,
        resp.body.len()
    )?;
    stream.write_all(&resp.body)?;
    stream.flush()
}

fn send_json(stream: &mut TcpStream, status: u16, value: &serde_json::Value) -> std::io::Result<()> {
    write_response(stream, Response {
        status,
        content_type: "application/json; charset=utf-8".into(),
        body: serde_json::to_vec_pretty(value).unwrap_or_default(),
    })
}

fn route(store: &Store, req: &Request) -> Response {
    let path = req.path.split('?').next().unwrap_or("/");
    let is_api = path.starts_with("/api/");

    if !is_api {
        return match (req.method.as_str(), path) {
            ("GET", "/") | ("GET", "/index.html") => static_asset(AssetKind::Index),
            ("GET", "/app.js") => static_asset(AssetKind::Js),
            ("GET", "/style.css") => static_asset(AssetKind::Css),
            _ => error_json(404, "not found"),
        };
    }

    match (req.method.as_str(), path) {
        ("GET", "/api/health") => ok_json(&serde_json::json!({"ok": true, "service": "frame-lab"})),

        ("GET", "/api/protocols") => match store.list_protocols() {
            Ok(items) => ok_json(&serde_json::to_value(items).unwrap()),
            Err(e) => error_json(500, &e.0),
        },

        ("POST", "/api/protocols") => with_json(&req.body, |doc| {
            let name = doc
                .get("name")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "missing protocol name".to_string())?
                .to_string();
            store
                .put_protocol(&name)
                .map(|_| serde_json::json!({"name": name}))
                .map_err(|e| e.0)
        }),

        ("POST", "/api/validate") => with_json(&req.body, |doc| {
            let raw: RawSpec = serde_json::from_value(doc.clone())
                .map_err(|e| format!("invalid protocol JSON: {}", e))?;
            match Spec::compile(raw) {
                Ok(spec) => Ok(serde_json::json!({
                    "ok": true,
                    "version_hash": spec.version_hash,
                    "canonical": spec.canonical(),
                })),
                Err(errors) => Ok(serde_json::json!({"ok": false, "errors": errors})),
            }
        }),

        ("POST", "/api/versions") => with_json(&req.body, |doc| {
            let protocol = doc
                .get("protocol")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "missing protocol".to_string())?;
            let label = doc.get("label").and_then(|v| v.as_str()).unwrap_or("");
            let parent = doc
                .get("parent_hash")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let spec_doc = doc.get("spec").cloned().ok_or_else(|| "missing spec".to_string())?;
            let raw: RawSpec = serde_json::from_value(spec_doc)
                .map_err(|e| format!("invalid protocol JSON: {}", e))?;
            store
                .save_version(protocol, raw, label, parent)
                .map(|info| serde_json::to_value(info).unwrap())
                .map_err(|e| e.0)
        }),

        ("GET", p) if p.starts_with("/api/versions/") => {
            let rest = &p["/api/versions/".len()..];
            let hash = rest.split('/').next().unwrap_or("");
            if rest.ends_with("/raw") {
                let hash = hash.trim_end_matches("/raw");
                match store.raw_version(hash) {
                    Ok(raw) => ok_json(&serde_json::to_value(raw).unwrap()),
                    Err(e) => error_json(404, &e.0),
                }
            } else {
                match store.load_version(hash) {
                    Ok(spec) => ok_json(&serde_json::json!({
                        "version_hash": spec.version_hash,
                        "name": spec.raw.name,
                        "canonical": spec.canonical(),
                        "spec": spec.raw,
                    })),
                    Err(e) => error_json(404, &e.0),
                }
            }
        }

        ("GET", p) if p.starts_with("/api/protocols/") && p.ends_with("/versions") => {
            let name = &p["/api/protocols/".len()..p.len() - "/versions".len()];
            match store.list_versions(name) {
                Ok(items) => ok_json(&serde_json::to_value(items).unwrap()),
                Err(e) => error_json(404, &e.0),
            }
        }

        // Parse without persisting a version: either reference a version hash
        // or supply an ephemeral spec document for trial parsing.
        ("POST", "/api/parse") => with_json(&req.body, |doc| {
            let bytes = parse_hex_input(doc)?;
            let spec = resolve_spec(store, doc)?;
            let result = parser::parse(&spec, &bytes);
            Ok(serde_json::json!({
                "result": result,
                "summary": parser::summarize(&result),
                "input_length": bytes.len(),
            }))
        }),

        ("POST", "/api/blobs") => with_json(&req.body, |doc| {
            let bytes = parse_hex_input(doc)?;
            store
                .put_blob(&bytes)
                .map(|(hash, reused)| serde_json::json!({"blob_hash": hash, "reused": reused, "length": bytes.len()}))
                .map_err(|e| e.0)
        }),

        ("GET", p) if p.starts_with("/api/blobs/") => {
            let hash = &p["/api/blobs/".len()..];
            match store.get_blob(hash) {
                Ok(bytes) => ok_json(&serde_json::json!({
                    "blob_hash": hash,
                    "hex": crate::hex::encode(&bytes),
                    "length": bytes.len(),
                })),
                Err(e) => error_json(404, &e.0),
            }
        }

        ("POST", "/api/sessions") => with_json(&req.body, |doc| {
            let protocol = doc
                .get("protocol")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "missing protocol".to_string())?;
            let version_hash = doc
                .get("version_hash")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "missing version_hash".to_string())?;
            let note = doc.get("note").and_then(|v| v.as_str()).unwrap_or("");
            let bytes = parse_hex_input(doc)?;
            store
                .create_session(protocol, version_hash, &bytes, note)
                .map(|s| serde_json::to_value(&s).unwrap())
                .map_err(|e| e.0)
        }),

        ("GET", "/api/sessions") => match store.list_sessions() {
            Ok(items) => ok_json(&serde_json::to_value(items).unwrap()),
            Err(e) => error_json(500, &e.0),
        },

        ("GET", p) if p.starts_with("/api/sessions/") && p.ends_with("/replay") => {
            let id = &p["/api/sessions/".len()..p.len() - "/replay".len()];
            match store.replay_session(id) {
                Ok(report) => ok_json(&serde_json::to_value(report).unwrap()),
                Err(e) => error_json(404, &e.0),
            }
        }

        ("GET", p) if p.starts_with("/api/sessions/") && p.ends_with("/export") => {
            let id = &p["/api/sessions/".len()..p.len() - "/export".len()];
            match store.export_session(id) {
                Ok(bundle) => ok_json(&serde_json::to_value(bundle).unwrap()),
                Err(e) => error_json(404, &e.0),
            }
        }

        ("GET", p) if p.starts_with("/api/sessions/") => {
            let id = &p["/api/sessions/".len()..];
            match store.get_session(id) {
                Ok(session) => ok_json(&serde_json::to_value(&session).unwrap()),
                Err(e) => error_json(404, &e.0),
            }
        }

        ("PATCH", p) if p.starts_with("/api/sessions/") && p.ends_with("/note") => {
            let id = &p["/api/sessions/".len()..p.len() - "/note".len()];
            with_json(&req.body, |doc| {
                let note = doc.get("note").and_then(|v| v.as_str()).unwrap_or("");
                store
                    .update_note(id, note)
                    .map(|s| serde_json::to_value(&s).unwrap())
                    .map_err(|e| e.0)
            })
        }

        ("POST", "/api/import") => with_json(&req.body, |doc| {
            let bundle: crate::store::Bundle = serde_json::from_value(doc.clone())
                .map_err(|e| format!("invalid bundle: {}", e))?;
            store.import_bundle(bundle).map(|r| serde_json::to_value(r).unwrap()).map_err(|e| e.0)
        }),

        _ => error_json(404, &format!("no API route for {} {}", req.method, path)),
    }
}

fn with_json<F>(body: &[u8], handler: F) -> Response
where
    F: FnOnce(&serde_json::Value) -> Result<serde_json::Value, String>,
{
    let doc: serde_json::Value = match serde_json::from_slice(body) {
        Ok(doc) => doc,
        Err(e) => return error_json(400, &format!("invalid JSON body: {}", e)),
    };
    match handler(&doc) {
        Ok(value) => ok_json(&value),
        Err(message) => error_json(400, &message),
    }
}

fn parse_hex_input(doc: &serde_json::Value) -> Result<Vec<u8>, String> {
    if let Some(hex) = doc.get("hex").and_then(|v| v.as_str()) {
        return crate::hex::decode(hex).map_err(|e| e);
    }
    if let Some(bytes) = doc.get("bytes").and_then(|v| v.as_array()) {
        return bytes
            .iter()
            .map(|v| {
                v.as_u64()
                    .map(|n| n as u8)
                    .ok_or_else(|| "bytes must contain integers 0..=255".to_string())
            })
            .collect();
    }
    Err("request needs `hex` or `bytes`".to_string())
}

fn resolve_spec(store: &Store, doc: &serde_json::Value) -> Result<Spec, String> {
    if let Some(hash) = doc.get("version_hash").and_then(|v| v.as_str()) {
        return store.load_version(hash).map_err(|e| e.0);
    }
    if let Some(spec_doc) = doc.get("spec") {
        let raw: RawSpec = serde_json::from_value(spec_doc.clone())
            .map_err(|e| format!("invalid protocol JSON: {}", e))?;
        return Spec::compile(raw).map_err(|e| e.join("; "));
    }
    Err("request needs version_hash or an inline spec".to_string())
}
