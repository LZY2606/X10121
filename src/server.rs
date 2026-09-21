//! 极简 HTTP/1.1 服务：JSON API + 内嵌前端页面。无外部服务、无系统数据库。
use crate::parser;
use crate::store::{Session, Store};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};

const INDEX_HTML: &str = include_str!("../static/index.html");

pub fn run(listener: TcpListener, store: Arc<Mutex<Store>>) -> std::io::Result<()> {
    let addr = listener.local_addr()?;
    println!("帧解析实验室 listening on http://{addr}");
    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                let store = Arc::clone(&store);
                std::thread::spawn(move || {
                    let _ = handle(s, store);
                });
            }
            Err(e) => eprintln!("accept: {e}"),
        }
    }
    Ok(())
}

struct Request {
    method: String,
    path: String,
    body: Vec<u8>,
}

fn handle(mut stream: TcpStream, store: Arc<Mutex<Store>>) -> std::io::Result<()> {
    let req = match read_request(&mut stream)? {
        Some(r) => r,
        None => return Ok(()),
    };
    let (status, content_type, body) = route(&req, &store);
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(&body)?;
    Ok(())
}

fn read_request(stream: &mut TcpStream) -> std::io::Result<Option<Request>> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 8192];
    let header_end;
    loop {
        if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
            header_end = pos;
            break;
        }
        let n = stream.read(&mut tmp)?;
        if n == 0 {
            return Ok(None);
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.len() > 1 << 20 {
            return Ok(None);
        }
    }
    let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let mut lines = head.lines();
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let target = parts.next().unwrap_or("/").to_string();
    let mut content_length = 0usize;
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case("content-length") {
                content_length = v.trim().parse().unwrap_or(0);
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
    let body = buf[body_start..buf.len().min(body_start + content_length)].to_vec();
    let path = target.split('?').next().unwrap_or("/").to_string();
    Ok(Some(Request { method, path, body }))
}

fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

fn json_response(status: &str, value: Value) -> (String, String, Vec<u8>) {
    (
        status.to_string(),
        "application/json; charset=utf-8".to_string(),
        serde_json::to_vec_pretty(&value).unwrap_or_default(),
    )
}

fn ok_json(value: Value) -> (String, String, Vec<u8>) {
    json_response("200 OK", value)
}

fn err_json(status: &str, msg: impl Into<String>) -> (String, String, Vec<u8>) {
    json_response(status, json!({ "error": msg.into() }))
}

fn route(req: &Request, store: &Arc<Mutex<Store>>) -> (String, String, Vec<u8>) {
    let segs: Vec<&str> = req.path.split('/').filter(|s| !s.is_empty()).collect();
    let m = req.method.as_str();
    match (m, segs.as_slice()) {
        ("GET", []) => (
            "200 OK".to_string(),
            "text/html; charset=utf-8".to_string(),
            INDEX_HTML.as_bytes().to_vec(),
        ),
        ("GET", ["api", "state"]) => with_store(store, |st| {
            let protocols: Vec<Value> = st
                .protocols
                .values()
                .map(|p| json!({"id": p.id, "name": p.name, "version": p.version, "hash": p.hash, "created_at": p.created_at}))
                .collect();
            let blobs: Vec<Value> = st
                .blobs
                .values()
                .map(|b| json!({"id": b.id, "len": b.len, "created_at": b.created_at}))
                .collect();
            let sessions: Vec<Value> = st
                .sessions
                .values()
                .map(|s| {
                    json!({"id": s.id, "protocol_id": s.protocol_id, "blob_id": s.blob_id,
                           "created_at": s.created_at, "notes": s.notes.len(),
                           "status": session_status(s)})
                })
                .collect();
            Ok(json!({"protocols": protocols, "blobs": blobs, "sessions": sessions}))
        }),
        ("POST", ["api", "protocols"]) => with_json(req, |v| {
            let name = v.get("name").and_then(Value::as_str).unwrap_or("protocol").to_string();
            let content = v.get("content").cloned().ok_or("missing 'content'")?;
            with_store(store, |st| {
                let pv = st.add_protocol(&name, content)?;
                Ok(json!({"id": pv.id, "name": pv.name, "version": pv.version, "hash": pv.hash}))
            })
        }),
        ("GET", ["api", "protocols", id]) => with_store(store, |st| {
            let pv = st.protocols.get(*id).ok_or_else(|| "unknown protocol".to_string())?;
            Ok(serde_json::to_value(pv).unwrap())
        }),
        ("POST", ["api", "blobs"]) => with_json(req, |v| {
            let hex = v.get("hex").and_then(Value::as_str).ok_or("missing 'hex'")?;
            let bytes = parser::hex_decode(hex).map_err(|e| e.to_string())?;
            with_store(store, |st| {
                let (id, reused) = st.add_blob(&bytes);
                let len = st.blobs.get(&id).map(|b| b.len).unwrap_or(0);
                Ok(json!({"id": id, "reused": reused, "len": len}))
            })
        }),
        ("GET", ["api", "blobs", id, "hex"]) => with_store(store, |st| {
            let bytes = st.blob_bytes(id).ok_or_else(|| "unknown blob".to_string())?;
            Ok(json!({"id": id, "hex": parser::hex_encode(&bytes)}))
        }),
        ("POST", ["api", "sessions"]) => with_json(req, |v| {
            let pid = v.get("protocol_id").and_then(Value::as_str).ok_or("missing 'protocol_id'")?.to_string();
            let bid = v.get("blob_id").and_then(Value::as_str).ok_or("missing 'blob_id'")?.to_string();
            with_store(store, |st| {
                let s = st.create_session(&pid, &bid)?;
                Ok(session_detail(st, &s))
            })
        }),
        ("GET", ["api", "sessions", id]) => with_store(store, |st| {
            let s = st.sessions.get(*id).ok_or_else(|| "unknown session".to_string())?.clone();
            Ok(session_detail(st, &s))
        }),
        ("POST", ["api", "sessions", id, "bytes"]) => with_json(req, |v| {
            let hex = v.get("hex").and_then(Value::as_str).ok_or("missing 'hex'")?;
            let bytes = parser::hex_decode(hex).map_err(|e| e.to_string())?;
            let id = id.to_string();
            with_store(store, |st| {
                let s = st.update_session_bytes(&id, &bytes)?;
                Ok(session_detail(st, &s))
            })
        }),
        ("POST", ["api", "sessions", id, "notes"]) => with_json(req, |v| {
            let text = v.get("text").and_then(Value::as_str).ok_or("missing 'text'")?.to_string();
            let id = id.to_string();
            with_store(store, |st| {
                let note = st.add_note(&id, &text)?;
                Ok(serde_json::to_value(note).unwrap())
            })
        }),
        ("GET", ["api", "sessions", id, "export"]) => with_store(store, |st| {
            let pkg = st.export_session(id)?;
            Ok(serde_json::to_value(pkg).unwrap())
        }),
        ("POST", ["api", "sessions", "import"]) => with_json(req, |v| {
            let pkg: crate::store::ExportPackage =
                serde_json::from_value(v).map_err(|e| format!("bad export package: {e}"))?;
            with_store(store, |st| {
                let id = st.import_session(&pkg)?;
                Ok(json!({"session_id": id}))
            })
        }),
        _ => err_json("404 Not Found", "not found"),
    }
}

fn session_status(s: &Session) -> &'static str {
    match s.latest().map(|r| &r.outcome) {
        Some(crate::parser::ParseOutcome::Ok { .. }) => "ok",
        Some(crate::parser::ParseOutcome::Incomplete { .. }) => "incomplete",
        Some(crate::parser::ParseOutcome::Violation { .. }) => "violation",
        None => "empty",
    }
}

fn session_detail(st: &Store, s: &Session) -> Value {
    let blob_hex = st
        .blob_bytes(&s.blob_id)
        .map(|b| parser::hex_encode(&b))
        .unwrap_or_default();
    json!({
        "session": s,
        "blob_hex": blob_hex,
        "status": session_status(s),
    })
}

fn with_store<F>(store: &Arc<Mutex<Store>>, f: F) -> (String, String, Vec<u8>)
where
    F: FnOnce(&mut Store) -> Result<Value, String>,
{
    let mut st = match store.lock() {
        Ok(g) => g,
        Err(_) => return err_json("500 Internal Server Error", "store lock poisoned"),
    };
    match f(&mut st) {
        Ok(v) => ok_json(v),
        Err(e) => err_json("400 Bad Request", e),
    }
}

fn with_json<F>(req: &Request, f: F) -> (String, String, Vec<u8>)
where
    F: FnOnce(Value) -> (String, String, Vec<u8>),
{
    match serde_json::from_slice::<Value>(&req.body) {
        Ok(v) => f(v),
        Err(e) => err_json("400 Bad Request", format!("invalid JSON body: {e}")),
    }
}
