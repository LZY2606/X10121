//! 等价 JSON API 与静态页面托管：纯 `std::net` 的线程阻塞 HTTP 服务。

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::json::Json;
use crate::store::Store;

const INDEX_HTML: &str = include_str!("static/index.html");

pub struct AppState {
    pub store: Store,
}

impl AppState {
    pub fn open(data_dir: PathBuf) -> std::io::Result<Self> {
        let store = Store::open(data_dir)?;
        // 首次启动时播种内置演示协议；幂等：内容相同则复用既有不可变版本。
        if store.list_protocols().is_empty() {
            if let Err(e) = store.save_protocol(crate::demo::DEMO_PROTOCOL, now_unix()) {
                eprintln!("警告：内置演示协议播种失败：{e}");
            }
        }
        Ok(AppState { store })
    }
}

pub fn serve(addr: &str, state: Arc<AppState>) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr)?;
    eprintln!("帧解析实验室已启动：http://{addr}");
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let state = Arc::clone(&state);
                std::thread::spawn(move || {
                    if let Err(e) = handle_connection(stream, &state) {
                        eprintln!("连接处理失败：{e}");
                    }
                });
            }
            Err(e) => eprintln!("接受连接失败：{e}"),
        }
    }
    Ok(())
}

#[derive(Debug)]
struct Request {
    method: String,
    path: String,
    body: String,
}

fn read_request(stream: &mut TcpStream) -> std::io::Result<Request> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    let mut header_end = None;
    loop {
        let n = stream.read(&mut tmp)?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = find_header_end(&buf) {
            header_end = Some(pos);
            break;
        }
        if buf.len() > 16 * 1024 * 1024 {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "请求头过大"));
        }
    }
    let header_end = header_end.ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "请求不完整")
    })?;
    let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let mut lines = head.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "缺少请求行"))?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let raw_path = parts.next().unwrap_or("/").to_string();
    let (path, _query) = raw_path.split_once('?').unwrap_or((&raw_path, ""));
    let headers: Vec<(String, String)> = lines
        .filter_map(|line| line.split_once(':').map(|(k, v)| (k.trim().to_lowercase(), v.trim().to_string())))
        .collect();
    let content_length = headers
        .iter()
        .find(|(k, _)| k == "content-length")
        .and_then(|(_, v)| v.parse::<usize>().ok())
        .unwrap_or(0);
    let body_start = header_end + 4;
    let mut body = buf[body_start..].to_vec();
    while body.len() < content_length {
        let n = stream.read(&mut tmp)?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&tmp[..n]);
    }
    body.truncate(content_length);
    Ok(Request {
        method,
        path: path.to_string(),
        body: String::from_utf8_lossy(&body).to_string(),
    })
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn handle_connection(mut stream: TcpStream, state: &AppState) -> std::io::Result<()> {
    let request = read_request(&mut stream)?;
    let response = route(state, &request);
    stream.write_all(&response.as_bytes())?;
    stream.flush()
}

struct Response {
    status: u16,
    content_type: String,
    body: String,
}

impl Response {
    fn as_bytes(&self) -> Vec<u8> {
        let status_text = match self.status {
            200 => "OK",
            201 => "Created",
            400 => "Bad Request",
            404 => "Not Found",
            405 => "Method Not Allowed",
            409 => "Conflict",
            500 => "Internal Server Error",
            _ => "OK",
        };
        let mut head = format!(
            "HTTP/1.1 {} {status_text}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n",
            self.status,
            self.content_type,
            self.body.len()
        );
        let mut out = head.as_bytes().to_vec();
        out.extend_from_slice(self.body.as_bytes());
        let _ = &mut head;
        out
    }
}

fn json_response(status: u16, value: Json) -> Response {
    Response {
        status,
        content_type: "application/json; charset=utf-8".to_string(),
        body: value.stringify(),
    }
}

fn error_json(status: u16, code: &str, message: impl Into<String>) -> Response {
    let mut o = Json::obj();
    o.insert("ok", Json::Bool(false));
    o.insert("error", Json::from_str_value(code));
    o.insert("message", Json::from_str_value(message.into()));
    json_response(status, o)
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn route(state: &AppState, req: &Request) -> Response {
    match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/") => Response {
            status: 200,
            content_type: "text/html; charset=utf-8".to_string(),
            body: INDEX_HTML.to_string(),
        },
        ("GET", "/api/health") => {
            let mut o = Json::obj();
            o.insert("ok", Json::Bool(true));
            o.insert("service", Json::from_str_value("frame-lab"));
            json_response(200, o)
        }
        ("GET", "/api/protocols") => list_protocols(state),
        ("POST", "/api/protocols") => save_protocol(state, req),
        ("GET", "/api/samples") => list_samples(state),
        ("POST", "/api/samples") => put_sample(state, req),
        ("POST", "/api/parse") => parse_now(state, req),
        ("GET", "/api/sessions") => list_sessions(state),
        ("POST", "/api/sessions") => create_session(state, req),
        ("GET", path) if path.starts_with("/api/sessions/") => session_get(state, path),
        ("POST", path) if path.starts_with("/api/sessions/") => session_action(state, path, req),
        ("POST", "/api/export") => export_bundle(state, req),
        ("POST", "/api/import") => import_bundle(state, req),
        _ => error_json(404, "not_found", format!("未找到 {} {}", req.method, req.path)),
    }
}

fn parse_result_json(result: &crate::parser::ParseResult) -> Json {
    let mut o = Json::obj();
    let label = match result.outcome {
        crate::parser::Outcome::Complete => "complete",
        crate::parser::Outcome::Incomplete => "incomplete",
        crate::parser::Outcome::Error => "error",
    };
    o.insert("outcome", Json::from_str_value(label));
    o.insert("input_len", Json::Int(result.input_len as i64));
    o.insert("consumed", Json::Int(result.consumed as i64));
    o.insert(
        "root",
        result.root.as_ref().map(|n| n.to_json()).unwrap_or(Json::Null),
    );
    o.insert(
        "incomplete",
        match &result.incomplete {
            Some(i) => {
                let mut d = Json::obj();
                d.insert("path", Json::from_str_value(i.path.clone()));
                d.insert("offset", Json::Int(i.offset as i64));
                d.insert("need_at_least", Json::Int(i.need_at_least as i64));
                d.insert("reason", Json::from_str_value(i.reason.clone()));
                d
            }
            None => Json::Null,
        },
    );
    o.insert(
        "violation",
        match &result.violation {
            Some(v) => {
                let mut d = Json::obj();
                d.insert("code", Json::from_str_value(v.code.clone()));
                d.insert("path", Json::from_str_value(v.path.clone()));
                d.insert("offset", Json::Int(v.offset as i64));
                d.insert("message", Json::from_str_value(v.message.clone()));
                d
            }
            None => Json::Null,
        },
    );
    o.insert(
        "warnings",
        Json::Array(
            result
                .warnings
                .iter()
                .map(|w| {
                    let mut d = Json::obj();
                    d.insert("code", Json::from_str_value(w.code.clone()));
                    d.insert("path", Json::from_str_value(w.path.clone()));
                    d.insert("offset", Json::Int(w.offset as i64));
                    d.insert("message", Json::from_str_value(w.message.clone()));
                    d
                })
                .collect(),
        ),
    );
    o.insert("tree_digest", Json::from_str_value(result.tree_digest()));
    o
}

fn body_json(req: &Request) -> Result<Json, Response> {
    crate::json::parse(&req.body).map_err(|e| {
        error_json(
            400,
            "invalid_json",
            format!("请求体不是合法 JSON（字节 {}）：{}", e.pos, e.message),
        )
    })
}

fn require_hex(body: &Json, key: &str) -> Result<Vec<u8>, Response> {
    let text = body
        .get(key)
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_json(400, "missing_field", format!("缺少字符串字段 `{key}`")))?;
    crate::bytes::parse_hex(text).map_err(|e| error_json(400, "invalid_hex", e))
}

fn list_protocols(state: &AppState) -> Response {
    let arr = state
        .store
        .list_protocols()
        .into_iter()
        .map(|r| {
            let mut o = r.to_json();
            o.insert("spec", r.protocol.to_json());
            o
        })
        .collect::<Vec<_>>();
    json_response(200, Json::Array(arr))
}

fn save_protocol(state: &AppState, req: &Request) -> Response {
    let body = match body_json(req) {
        Ok(j) => j,
        Err(r) => return r,
    };
    let source = match body.get("source").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => {
            return error_json(400, "missing_field", "缺少 `source`（协议 JSON 文本）")
        }
    };
    match state.store.save_protocol(source, now_unix()) {
        Ok(record) => {
            let mut o = Json::obj();
            o.insert("ok", Json::Bool(true));
            let mut rj = record.to_json();
            rj.insert("spec", record.protocol.to_json());
            o.insert("version", rj);
            json_response(201, o)
        }
        Err(message) => error_json(400, "protocol_invalid", message),
    }
}

fn list_samples(state: &AppState) -> Response {
    // blob 本身不可枚举目录 API 也足够：从会话中聚合已见 blob。
    let mut seen = std::collections::BTreeMap::new();
    for session in state.store.list_sessions() {
        *seen.entry(session.blob_hash).or_insert(0usize) += 1;
    }
    let arr = seen
        .into_iter()
        .map(|(hash, uses)| {
            let bytes = state.store.get_blob(&hash);
            let mut o = Json::obj();
            o.insert("blob_hash", Json::from_str_value(hash));
            o.insert(
                "length",
                Json::Int(bytes.as_ref().map(|b| b.len()).unwrap_or(0) as i64),
            );
            o.insert("session_refs", Json::Int(uses as i64));
            o
        })
        .collect::<Vec<_>>();
    json_response(200, Json::Array(arr))
}

fn put_sample(state: &AppState, req: &Request) -> Response {
    let body = match body_json(req) {
        Ok(j) => j,
        Err(r) => return r,
    };
    let bytes = match require_hex(&body, "hex") {
        Ok(b) => b,
        Err(r) => return r,
    };
    match state.store.put_blob(&bytes) {
        Ok(hash) => {
            let mut o = Json::obj();
            o.insert("ok", Json::Bool(true));
            o.insert("blob_hash", Json::from_str_value(hash));
            o.insert("length", Json::Int(bytes.len() as i64));
            json_response(201, o)
        }
        Err(e) => error_json(500, "store_failed", e.to_string()),
    }
}

fn parse_payload(state: &AppState, req: &Request) -> Result<(crate::spec::Protocol, Vec<u8>, String), Response> {
    let body = body_json(req)?;
    let version_id = body
        .get("version_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| error_json(400, "missing_field", "缺少 `version_id`"))?
        .to_string();
    let record = state
        .store
        .get_protocol(&version_id)
        .ok_or_else(|| error_json(400, "unknown_version", format!("协议版本 `{version_id}` 不存在")))?;
    let bytes = if let Some(hex) = body.get("hex").and_then(|v| v.as_str()) {
        crate::bytes::parse_hex(hex).map_err(|e| error_json(400, "invalid_hex", e))?
    } else if let Some(hash) = body.get("blob_hash").and_then(|v| v.as_str()) {
        state
            .store
            .get_blob(hash)
            .ok_or_else(|| error_json(400, "unknown_blob", format!("blob `{hash}` 不存在")))?
    } else {
        return Err(error_json(400, "missing_field", "需要提供 `hex` 或 `blob_hash`"));
    };
    Ok((record.protocol, bytes, version_id))
}

fn parse_now(state: &AppState, req: &Request) -> Response {
    let (protocol, bytes, version_id) = match parse_payload(state, req) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let result = crate::parser::parse(&protocol, &bytes);
    let mut o = Json::obj();
    o.insert("ok", Json::Bool(true));
    o.insert("version_id", Json::from_str_value(version_id));
    o.insert("hex", Json::from_str_value(crate::bytes::to_hex(&bytes)));
    o.insert("result", parse_result_json(&result));
    json_response(200, o)
}

fn list_sessions(state: &AppState) -> Response {
    let arr = state
        .store
        .list_sessions()
        .into_iter()
        .map(|s| {
            let mut o = Json::obj();
            o.insert("id", Json::from_str_value(s.id));
            o.insert("title", Json::from_str_value(s.title));
            o.insert("version_id", Json::from_str_value(s.version_id));
            o.insert("blob_hash", Json::from_str_value(s.blob_hash));
            o.insert("note", Json::from_str_value(s.note));
            o.insert("working_hex", Json::from_str_value(s.working_hex));
            o.insert("created_at", Json::Int(s.created_at as i64));
            o.insert("updated_at", Json::Int(s.updated_at as i64));
            o.insert("event_count", Json::Int(s.events.len() as i64));
            o
        })
        .collect::<Vec<_>>();
    json_response(200, Json::Array(arr))
}

fn create_session(state: &AppState, req: &Request) -> Response {
    let body = match body_json(req) {
        Ok(j) => j,
        Err(r) => return r,
    };
    let version_id = match body.get("version_id").and_then(|v| v.as_str()) {
        Some(v) => v.to_string(),
        None => return error_json(400, "missing_field", "缺少 `version_id`"),
    };
    let title = body.get("title").and_then(|v| v.as_str()).unwrap_or("未命名会话");
    let note = body.get("note").and_then(|v| v.as_str()).unwrap_or("");
    let bytes = if let Some(hex) = body.get("hex").and_then(|v| v.as_str()) {
        match crate::bytes::parse_hex(hex) {
            Ok(b) => b,
            Err(e) => return error_json(400, "invalid_hex", e),
        }
    } else if let Some(hash) = body.get("blob_hash").and_then(|v| v.as_str()) {
        match state.store.get_blob(hash) {
            Some(b) => b,
            None => return error_json(400, "unknown_blob", format!("blob `{hash}` 不存在")),
        }
    } else {
        return error_json(400, "missing_field", "需要 `hex` 或 `blob_hash`");
    };
    let record = match state.store.get_protocol(&version_id) {
        Some(r) => r,
        None => return error_json(400, "unknown_version", format!("协议版本 `{version_id}` 不存在")),
    };
    let blob_hash = match state.store.put_blob(&bytes) {
        Ok(h) => h,
        Err(e) => return error_json(500, "store_failed", e.to_string()),
    };
    let working_hex = crate::bytes::to_hex(&bytes);
    let result = crate::parser::parse(&record.protocol, &bytes);
    match state.store.create_session(
        title,
        &version_id,
        &blob_hash,
        &working_hex,
        &result,
        note,
        now_unix(),
    ) {
        Ok(session) => {
            let mut o = Json::obj();
            o.insert("ok", Json::Bool(true));
            o.insert("session", session_json(&session));
            o.insert("blob_hash", Json::from_str_value(blob_hash));
            o.insert("result", parse_result_json(&result));
            json_response(201, o)
        }
        Err(e) => error_json(400, "session_failed", e),
    }
}

fn session_json(s: &crate::store::Session) -> Json {
    let mut o = Json::obj();
    o.insert("id", Json::from_str_value(s.id.clone()));
    o.insert("title", Json::from_str_value(s.title.clone()));
    o.insert("version_id", Json::from_str_value(s.version_id.clone()));
    o.insert("blob_hash", Json::from_str_value(s.blob_hash.clone()));
    o.insert("note", Json::from_str_value(s.note.clone()));
    o.insert("working_hex", Json::from_str_value(s.working_hex.clone()));
    o.insert("created_at", Json::Int(s.created_at as i64));
    o.insert("updated_at", Json::Int(s.updated_at as i64));
    o.insert(
        "events",
        Json::Array(s.events.iter().map(|e| e.to_json_public()).collect()),
    );
    o
}

fn session_get(state: &AppState, path: &str) -> Response {
    let rest = path.trim_start_matches("/api/sessions/");
    let (id, action) = rest.split_once('/').unwrap_or((rest, ""));
    if id.is_empty() {
        return error_json(404, "not_found", "缺少会话 id".to_string());
    }
    match action {
        "" => match state.store.get_session(id) {
            Some(session) => match state.store.replay_session(id) {
                Ok(replay) => {
                    let mut o = Json::obj();
                    o.insert("ok", Json::Bool(true));
                    o.insert("session", session_json(&session));
                    o.insert("result", parse_result_json(&replay.result));
                    let mut v = replay.record.to_json();
                    v.insert("spec", replay.record.protocol.to_json());
                    o.insert("version", v);
                    json_response(200, o)
                }
                Err(e) => error_json(500, "replay_failed", e),
            },
            None => error_json(404, "session_missing", format!("会话 `{id}` 不存在")),
        },
        _ => error_json(405, "method_not_allowed", "该子路径仅支持 POST".to_string()),
    }
}

fn session_action(state: &AppState, path: &str, req: &Request) -> Response {
    let rest = path.trim_start_matches("/api/sessions/");
    let (id, action) = rest.split_once('/').unwrap_or((rest, ""));
    let body = body_json(req).unwrap_or(Json::Null);
    match action {
        "edit" => edit_bytes(state, id, &body),
        "replay" => replay(state, id),
        "note" => update_note(state, id, &body),
        "delete" => delete_session(state, id),
        _ => error_json(404, "not_found", format!("未知会话操作 `{action}`")),
    }
}

fn replay(state: &AppState, id: &str) -> Response {
    match state.store.replay_session(id) {
        Ok(replay) => {
            let mut o = Json::obj();
            o.insert("ok", Json::Bool(true));
            o.insert("session", session_json(&replay.session));
            o.insert("result", parse_result_json(&replay.result));
            json_response(200, o)
        }
        Err(e) => error_json(404, "replay_failed", e),
    }
}

fn edit_bytes(state: &AppState, id: &str, body: &Json) -> Response {
    let hex = match body.get("hex").and_then(|v| v.as_str()) {
        Some(h) => h,
        None => return error_json(400, "missing_field", "缺少 `hex` 工作副本"),
    };
    let new_bytes = match crate::bytes::parse_hex(hex) {
        Ok(b) => b,
        Err(e) => return error_json(400, "invalid_hex", e),
    };
    let before = match state.store.replay_session(id) {
        Ok(r) => r,
        Err(e) => return error_json(404, "session_missing", e),
    };
    if new_bytes.len() != before.result.input_len {
        return error_json(
            400,
            "length_changed",
            format!(
                "字节编辑必须保持长度不变（原 {} 字节，现 {} 字节）；请用导入新样本创建新会话",
                before.result.input_len,
                new_bytes.len()
            ),
        );
    }
    let result = crate::parser::parse(&before.record.protocol, &new_bytes);
    let old_bytes = crate::bytes::parse_hex(&before.session.working_hex).unwrap_or_default();
    let changes = changed_offsets(&old_bytes, &new_bytes);
    let recomputed = diff_recomputed(
        before.result.root.as_ref(),
        result.root.as_ref(),
        &changes,
    );
    let normalized = crate::bytes::to_hex(&new_bytes);
    match state
        .store
        .record_byte_edit(id, &normalized, &result, &recomputed, now_unix())
    {
        Ok(session) => {
            let mut o = Json::obj();
            o.insert("ok", Json::Bool(true));
            o.insert("session", session_json(&session));
            o.insert("result", parse_result_json(&result));
            o.insert(
                "recomputed",
                Json::Array(
                    recomputed
                        .iter()
                        .map(|s| Json::from_str_value(s.clone()))
                        .collect(),
                ),
            );
            json_response(200, o)
        }
        Err(e) => error_json(400, "edit_failed", e),
    }
}

fn update_note(state: &AppState, id: &str, body: &Json) -> Response {
    let note = body.get("note").and_then(|v| v.as_str()).unwrap_or("");
    match state.store.update_note(id, note, now_unix()) {
        Ok(session) => {
            let _ = state.store.record_note_event(id, note, now_unix());
            let mut o = Json::obj();
            o.insert("ok", Json::Bool(true));
            o.insert("session", session_json(&session));
            json_response(200, o)
        }
        Err(e) => error_json(404, "session_missing", e),
    }
}

fn delete_session(state: &AppState, id: &str) -> Response {
    match state.store.delete_session(id) {
        Ok(()) => {
            let mut o = Json::obj();
            o.insert("ok", Json::Bool(true));
            json_response(200, o)
        }
        Err(e) => error_json(404, "session_missing", e),
    }
}

fn export_bundle(state: &AppState, req: &Request) -> Response {
    let body = match body_json(req) {
        Ok(j) => j,
        Err(r) => return r,
    };
    let id = match body.get("session_id").and_then(|v| v.as_str()) {
        Some(v) => v,
        None => return error_json(400, "missing_field", "缺少 `session_id`"),
    };
    match state.store.export_bundle(id) {
        Ok(text) => Response {
            status: 200,
            content_type: "application/json; charset=utf-8".to_string(),
            body: text,
        },
        Err(e) => error_json(400, "export_failed", e),
    }
}

fn import_bundle(state: &AppState, req: &Request) -> Response {
    match state.store.import_bundle(&req.body, now_unix()) {
        Ok(report) => {
            let mut o = Json::obj();
            o.insert("ok", Json::Bool(true));
            o.insert("session_id", Json::from_str_value(report.session_id));
            o.insert("reused_session", Json::Bool(report.reused_session));
            o.insert("version_id", Json::from_str_value(report.version_id));
            o.insert("blob_hash", Json::from_str_value(report.blob_hash));
            o.insert("tree_digest", Json::from_str_value(report.tree_digest));
            json_response(200, o)
        }
        Err(e) => error_json(400, "import_failed", e),
    }
}

/// 字节修改后重新解析：任何覆盖了变化字节、或值发生变化的节点都视为“被重新计算”。
fn diff_recomputed(
    old_root: Option<&crate::parser::FieldNode>,
    new_root: Option<&crate::parser::FieldNode>,
    changed_offsets: &[usize],
) -> Vec<String> {
    let mut out = std::collections::BTreeSet::new();
    let mut old_index = std::collections::BTreeMap::new();
    if let Some(root) = old_root {
        index_nodes(root, &mut old_index);
    }
    if let Some(root) = new_root {
        walk_recomputed(root, &old_index, changed_offsets, &mut out);
    }
    out.into_iter().collect()
}

fn index_nodes(node: &crate::parser::FieldNode, map: &mut std::collections::BTreeMap<String, (usize, usize, Json)>) {
    map.insert(node.id.clone(), (node.start, node.end, node.value.clone()));
    for child in &node.children {
        index_nodes(child, map);
    }
}

fn walk_recomputed(
    node: &crate::parser::FieldNode,
    old: &std::collections::BTreeMap<String, (usize, usize, Json)>,
    changed: &[usize],
    out: &mut std::collections::BTreeSet<String>,
) {
    let overlaps = changed.iter().any(|off| *off >= node.start && *off < node.end);
    let value_changed = old
        .get(&node.id)
        .map(|(s, e, v)| *s != node.start || *e != node.end || *v != node.value)
        .unwrap_or(true);
    if overlaps || value_changed {
        out.insert(node.id.clone());
    }
    for child in &node.children {
        walk_recomputed(child, old, changed, out);
    }
}

/// 找到内容发生变化的字节偏移。
fn changed_offsets(old: &[u8], new: &[u8]) -> Vec<usize> {
    old.iter()
        .zip(new.iter())
        .enumerate()
        .filter_map(|(i, (a, b))| if a != b { Some(i) } else { None })
        .collect()
}
