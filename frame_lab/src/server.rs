// Small std-only HTTP/1.1 server exposing the JSON API and the browser UI.

use crate::codec::{parse_frame, ParseResult};
use crate::hash::hex_encode;
use crate::json::{self, Json};
use crate::spec::Protocol;
use crate::storage::Store;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

pub struct Server {
    store: Store,
}

#[derive(Debug)]
struct Request {
    method: String,
    path: String,
    body: String,
}

pub fn run(addr: &str, data_dir: &Path) -> Result<(), String> {
    let store = Store::open(data_dir)?;
    seed_demo(&store);
    let server = Arc::new(Server { store });
    let listener = TcpListener::bind(addr).map_err(|e| format!("bind {addr}: {e}"))?;
    println!("帧解析实验室 listening on http://{}", addr);
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let server = Arc::clone(&server);
                thread::spawn(move || {
                    let _ = handle_connection(&server, stream);
                });
            }
            Err(_) => continue,
        }
    }
    Ok(())
}

fn handle_connection(server: &Server, mut stream: TcpStream) -> Result<(), String> {
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .ok();
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        match stream.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&tmp[..n]);
                if let Some(header_end) = find_header_end(&buf) {
                    if has_full_body(&buf, header_end) {
                        break;
                    }
                }
                if n < tmp.len() {
                    break;
                }
            }
            Err(_) => break,
        }
    }

    let raw = String::from_utf8_lossy(&buf).to_string();
    let request = match parse_request(&raw) {
        Some(r) => r,
        None => {
            respond(&mut stream, 400, "Bad Request", &Json::str("bad request"));
            return Ok(());
        }
    };
    route(server, &mut stream, &request);
    Ok(())
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + 4)
}

fn has_full_body(buf: &[u8], header_end: usize) -> bool {
    let headers = String::from_utf8_lossy(&buf[..header_end]);
    for line in headers.split("\r\n") {
        if line.to_ascii_lowercase().starts_with("content-length:") {
        }
    }
    true
}

fn parse_request(raw: &str) -> Option<Request> {
    let mut parts = raw.splitn(2, "\r\n\r\n");
    let head = parts.next()?;
    let body = parts.next().unwrap_or("").to_string();
    let mut lines = head.split("\r\n");
    let request_line = lines.next()?;
    let mut segs = request_line.split_whitespace();
    let method = segs.next()?.to_string();
    let path = segs.next()?.to_string();
    Some(Request { method, path, body })
}

fn route(server: &Server, stream: &mut TcpStream, req: &Request) {
    let path = req.path.split('?').next().unwrap_or("/");

    if req.method == "GET" && (path == "/" || path == "/index.html") {
        return serve_static(stream, "text/html; charset=utf-8", include_str!("../static/index.html"));
    }

    if req.method == "GET" && path == "/api/health" {
        let mut j = Json::obj();
        j.put("ok", Json::bool_(true));
        j.put("title", Json::str("帧解析实验室"));
        return respond(stream, 200, "OK", &j);
    }

    if req.method == "GET" && path == "/api/protocols" {
        return match server.store.list_protocols() {
            Ok(list) => {
                let arr: Vec<Json> = list
                    .iter()
                    .map(|m| {
                        let mut o = Json::obj();
                        o.put("id", Json::str(&m.id));
                        o.put("name", Json::str(&m.name));
                        o.put("created_at", Json::uint(m.created_at));
                        o
                    })
                    .collect();
                respond(stream, 200, "OK", &Json::arr(arr));
            }
            Err(e) => respond_err(stream, 500, &e),
        };
    }

    if req.method == "POST" && path == "/api/protocols" {
        return with_json(stream, &req.body, |schema| {
            // Echo canonical form so saving is reproducible.
            let canonical = schema.canonical();
            let reparsed = json::parse(&canonical).map_err(|e| (400, e))?;
            match server.store.save_protocol(&reparsed) {
                Ok((id, proto)) => {
                    let mut o = Json::obj();
                    o.put("id", Json::str(&id));
                    o.put("name", Json::str(&proto.name));
                    o.put("root", Json::str(&proto.root));
                    Ok((201, o))
                }
                Err(e) => Err((400, e)),
            }
        });
    }

    if let Some(rest) = path.strip_prefix("/api/protocols/") {
        if req.method == "GET" {
            let id = rest.trim_end_matches('/').to_string();
            return match server.store.load_protocol(&id) {
                Ok((schema, proto)) => {
                    let mut o = Json::obj();
                    o.put("id", Json::str(&id));
                    o.put("schema", schema);
                    o.put("name", Json::str(&proto.name));
                    o.put("root", Json::str(&proto.root));
                    o.put("max_depth", Json::uint(proto.max_depth as u64));
                    respond(stream, 200, "OK", &o);
                }
                Err(e) => respond_err(stream, 404, &e),
            };
        }
    }

    if req.method == "POST" && path == "/api/blobs" {
        return with_json(stream, &req.body, |body| {
            let hex = body
                .get("hex")
                .and_then(|v| v.as_str())
                .ok_or((400, "missing hex".to_string()))?;
            let data = crate::hash::hex_decode(hex).map_err(|e| (400, e))?;
            let id = server.store.put_blob(&data).map_err(|e| (500, e))?;
            let mut o = Json::obj();
            o.put("id", Json::str(&id));
            o.put("length", Json::uint(data.len() as u64));
            Ok((201, o))
        });
    }

    if req.method == "POST" && path == "/api/parse" {
        return with_json(stream, &req.body, |body| {
            let protocol_id = body
                .get("protocol_id")
                .and_then(|v| v.as_str())
                .ok_or((400, "missing protocol_id".to_string()))?;
            let hex = body
                .get("hex")
                .and_then(|v| v.as_str())
                .ok_or((400, "missing hex".to_string()))?;
            let data = crate::hash::hex_decode(hex).map_err(|e| (400, e))?;
            let (_schema, proto) = server
                .store
                .load_protocol(protocol_id)
                .map_err(|e| (404, e))?;
            let result = parse_frame(&proto, &data);
            Ok((200, parse_payload(&result)))
        });
    }

    if req.method == "POST" && path == "/api/sessions" {
        return with_json(stream, &req.body, |body| {
            let protocol_id = body
                .get("protocol_id")
                .and_then(|v| v.as_str())
                .ok_or((400, "missing protocol_id".to_string()))?;
            let hex = body
                .get("hex")
                .and_then(|v| v.as_str())
                .ok_or((400, "missing hex".to_string()))?;
            let title = body.get("title").and_then(|v| v.as_str()).unwrap_or("session");
            let data = crate::hash::hex_decode(hex).map_err(|e| (400, e))?;
            let blob_id = server.store.put_blob(&data).map_err(|e| (500, e))?;
            let session = server
                .store
                .create_session(protocol_id, &blob_id, title)
                .map_err(|e| (400, e))?;
            Ok((201, session_json_full(&session)))
        });
    }

    if req.method == "POST" && path == "/api/import" {
        return with_json(stream, &req.body, |body| {
            let pkg = body.get("package").unwrap_or(body);
            match server.store.import_session(pkg) {
                Ok(report) => {
                    let mut o = Json::obj();
                    o.put("session", session_json_full(&report.session));
                    o.put("protocol_id", Json::str(&report.protocol_id));
                    o.put("blob_id", Json::str(&report.blob_id));
                    o.put("replay", report.replay.to_json());
                    Ok((200, o))
                }
                Err(e) => Err((400, e)),
            }
        });
    }

    if req.method == "GET" && path == "/api/sessions" {
        return match server.store.list_sessions() {
            Ok(list) => respond(
                stream,
                200,
                "OK",
                &Json::arr(list.iter().map(session_json_meta).collect()),
            ),
            Err(e) => respond_err(stream, 500, &e),
        };
    }

    if let Some(rest) = path.strip_prefix("/api/sessions/") {
        return session_routes(server, stream, req, rest);
    }

    respond_err(stream, 404, "no such route")
}

fn parse_payload(result: &ParseResult) -> Json {
    result.to_json()
}

fn session_routes(server: &Server, stream: &mut TcpStream, req: &Request, rest: &str) {
    let mut parts = rest.split('/');
    let id = parts.next().unwrap_or("").to_string();
    let action = parts.next().unwrap_or("");

    if req.method == "GET" && action.is_empty() {
        return match server.store.get_session(&id) {
            Ok(session) => {
                let result = server
                    .store
                    .replay_work(&session)
                    .unwrap_or_else(|_| empty_error(&id));
                let mut o = session_json_full(&session);
                o.put("parse", result.to_json());
                o.put("blob_hex", Json::str(&session.work_hex));
                respond(stream, 200, "OK", &o);
            }
            Err(e) => respond_err(stream, 404, &e),
        };
    }

    if req.method == "PUT" && action == "work" {
        return with_json(stream, &req.body, |body| {
            let hex = body
                .get("hex")
                .and_then(|v| v.as_str())
                .ok_or((400, "missing hex".to_string()))?;
            let (session, result) = server
                .store
                .update_work(&id, hex)
                .map_err(|e| (400, e))?;
            let mut o = session_json_full(&session);
            o.put("parse", result.to_json());
            Ok((200, o))
        });
    }

    if req.method == "PUT" && action == "note" {
        return with_json(stream, &req.body, |body| {
            let note = body.get("note").and_then(|v| v.as_str()).unwrap_or("");
            let session = server.store.set_note(&id, note).map_err(|e| (400, e))?;
            Ok((200, session_json_meta(&session)))
        });
    }

    if req.method == "PUT" && action == "rename" {
        return with_json(stream, &req.body, |body| {
            let title = body
                .get("title")
                .and_then(|v| v.as_str())
                .unwrap_or("session");
            let session = server
                .store
                .rename_session(&id, title)
                .map_err(|e| (400, e))?;
            Ok((200, session_json_meta(&session)))
        });
    }

    if req.method == "POST" && action == "replay" {
        return match server.store.get_session(&id) {
            Ok(session) => match server.store.replay_work(&session) {
                Ok(result) => respond(stream, 200, "OK", &result.to_json()),
                Err(e) => respond_err(stream, 400, &e),
            },
            Err(e) => respond_err(stream, 404, &e),
        };
    }

    if req.method == "GET" && action == "export" {
        return match server.store.export_session(&id) {
            Ok(pkg) => respond(stream, 200, "OK", &pkg),
            Err(e) => respond_err(stream, 400, &e),
        };
    }

    respond_err(stream, 404, "no such session route")
}

fn empty_error(id: &str) -> ParseResult {
    ParseResult {
        status: crate::codec::Status::Error,
        root: None,
        diagnostics: vec![crate::codec::Diagnostic {
            level: crate::codec::Status::Error,
            message: format!("cannot replay session {}", id),
            path: String::new(),
            byte: None,
        }],
        need: 0,
        consumed: 0,
    }
}

fn session_json_meta(s: &crate::storage::Session) -> Json {
    let mut o = Json::obj();
    o.put("id", Json::str(&s.id));
    o.put("protocol_id", Json::str(&s.protocol_id));
    o.put("blob_id", Json::str(&s.blob_id));
    o.put("title", Json::str(&s.title));
    o.put("note", Json::str(&s.note));
    o.put("created_at", Json::uint(s.created_at));
    o.put("updated_at", Json::uint(s.updated_at));
    o.put("length", Json::uint(s.work_hex.len() as u64 / 2));
    if let Some(last) = s.history.last() {
        o.put("status", Json::str(&last.status));
        o.put("need", Json::uint(last.need as u64));
        o.put("digest", Json::str(&last.digest));
    }
    o
}

fn session_json_full(s: &crate::storage::Session) -> Json {
    let mut o = session_json_meta(s);
    o.put("work_hex", Json::str(&s.work_hex));
    o.put(
        "history",
        Json::arr(
            s.history
                .iter()
                .map(|h| {
                    let mut x = Json::obj();
                    x.put("at", Json::uint(h.at));
                    x.put("status", Json::str(&h.status));
                    x.put("need", Json::uint(h.need as u64));
                    x.put("digest", Json::str(&h.digest));
                    x.put("diagnostic", Json::str(&h.diagnostic));
                    x.put("path", Json::str(&h.path));
                    x.put("work_hex", Json::str(&h.work_hex));
                    match h.byte {
                        Some(b) => x.put("byte", Json::uint(b as u64)),
                        None => x.put("byte", Json::Null),
                    }
                    x
                })
                .collect(),
        ),
    );
    o
}

fn with_json<F>(stream: &mut TcpStream, body: &str, f: F)
where
    F: FnOnce(&Json) -> Result<(u16, Json), (u16, String)>,
{
    let parsed = match json::parse(body) {
        Ok(j) => j,
        Err(e) => return respond_err(stream, 400, &format!("invalid JSON: {e}")),
    };
    match f(&parsed) {
        Ok((code, value)) => respond(stream, code, reason(code), &value),
        Err((code, message)) => respond_err(stream, code, &message),
    }
}

fn reason(code: u16) -> &'static str {
    match code {
        200 => "OK",
        201 => "Created",
        400 => "Bad Request",
        404 => "Not Found",
        500 => "Internal Server Error",
        _ => "OK",
    }
}

fn respond_err(stream: &mut TcpStream, code: u16, message: &str) {
    let mut o = Json::obj();
    o.put("error", Json::str(message));
    respond(stream, code, reason(code), &o);
}

fn respond(stream: &mut TcpStream, code: u16, reason_text: &str, value: &Json) {
    let body = value.pretty();
    let head = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\nAccess-Control-Allow-Origin: *\r\n\r\n",
        code,
        reason_text,
        body.len()
    );
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(body.as_bytes());
    let _ = stream.flush();
}

fn serve_static(stream: &mut TcpStream, content_type: &str, body: &str) {
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        content_type,
        body.len()
    );
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(body.as_bytes());
    let _ = stream.flush();
}

// ---------------- Demo data ----------------

fn seed_demo(store: &Store) {
    // Idempotent: if any protocol exists, assume the lab has been initialised.
    if let Ok(existing) = store.list_protocols() {
        if !existing.is_empty() {
            return;
        }
    }

    let demo_schema = match json::parse(include_str!("../static/demo_protocol.json")) {
        Ok(j) => j,
        Err(_) => return,
    };
    let recursive_schema = match json::parse(include_str!("../static/recursive_protocol.json")) {
        Ok(j) => j,
        Err(_) => return,
    };

    if let Ok((pid, proto)) = store.save_protocol(&demo_schema) {
        let value = json::parse(
            r#"{
              "magic": 42245,
              "version": 1,
              "type": 1,
              "len": 7,
              "head": {"kind": 7, "seq": 200},
              "payload": "0a1b2c3d4e",
              "trailer": 21
            }"#,
        )
        .unwrap_or_else(|_| Json::obj());
        if let Ok(bytes) = crate::codec::encode(&proto, &value) {
            if let Ok(bid) = store.put_blob(&bytes) {
                let _ = store.create_session(&pid, &bid, "演示帧 · demo v1");
            }
        }
    }

    let _ = store.save_protocol(&recursive_schema);
}
