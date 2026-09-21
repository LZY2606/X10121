use crate::error::LabResult;
use crate::store::Store;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};

pub fn run(addr: &str, data_dir: &Path) -> LabResult<()> {
    let store = Arc::new(Store::open(data_dir)?);
    crate::server_seed::seed(&store)?;
    let listener = TcpListener::bind(addr)?;
    eprintln!("帧解析实验室已启动: http://{addr}");
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let store = Arc::clone(&store);
                std::thread::spawn(move || {
                    let _ = handle(stream, &store);
                });
            }
            Err(_) => continue,
        }
    }
    Ok(())
}

struct Request {
    method: String,
    path: String,
    body: Vec<u8>,
}

fn handle(mut stream: TcpStream, store: &Arc<Store>) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;

    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    let header_end;
    loop {
        let n = stream.read(&mut tmp)?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = find_subsequence(&buf, b"\r\n\r\n") {
            header_end = pos + 4;
            break;
        }
        if buf.len() > 16 * 1024 * 1024 {
            return Ok(());
        }
    }

    let header_text = String::from_utf8_lossy(&buf[..header_end]);
    let mut lines = header_text.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let raw_target = parts.next().unwrap_or("/");
    let (path, _query) = match raw_target.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (raw_target.to_string(), String::new()),
    };
    let content_length = header_text
        .lines()
        .find_map(|line| {
            let lower = line.to_ascii_lowercase();
            lower
                .strip_prefix("content-length:")
                .map(|v| v.trim().parse::<usize>().unwrap_or(0))
        })
        .unwrap_or(0);
    while buf.len() < header_end + content_length {
        let n = stream.read(&mut tmp)?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
    }
    let body = buf[header_end..header_end + content_length].to_vec();

    let request = Request { method, path, body };
    let response = route(request, store);
    write_response(&mut stream, response)
}

/// 供库内集成测试直接驱动一条连接。
pub fn handle_public(stream: TcpStream, store: &Arc<Store>) -> std::io::Result<()> {
    handle(stream, store)
}

struct Response {
    status: u16,
    content_type: String,
    body: Vec<u8>,
}

fn json_response(status: u16, value: &Value) -> Response {
    Response {
        status,
        content_type: "application/json; charset=utf-8".to_string(),
        body: serde_json::to_vec_pretty(value).unwrap_or_default(),
    }
}

fn err_response(status: u16, code: &str, message: &str) -> Response {
    json_response(
        status,
        &json!({ "error": { "code": code, "message": message } }),
    )
}

fn write_response(stream: &mut TcpStream, resp: Response) -> std::io::Result<()> {
    let reason = match resp.status {
        200 => "OK",
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

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|w| w == needle)
}

fn route(req: Request, store: &Arc<Store>) -> Response {
    match route_inner(req, store) {
        Ok(resp) => resp,
        Err(e) => err_response(400, "bad_request", &e.0),
    }
}

fn json_body(body: &[u8]) -> Result<Value, crate::error::LabError> {
    if body.is_empty() {
        return Ok(Value::Null);
    }
    Ok(serde_json::from_slice(body)?)
}

fn bytes_from_req(value: &Value) -> Result<Vec<u8>, crate::error::LabError> {
    if let Some(hex_str) = value.get("hex").and_then(|v| v.as_str()) {
        crate::hex::decode(hex_str)
            .map_err(|e| crate::error::LabError::new(format!("hex 解析失败: {e}")))
    } else if let Some(arr) = value.get("bytes").and_then(|v| v.as_array()) {
        arr.iter()
            .map(|v| {
                v.as_u64()
                    .and_then(|n| u8::try_from(n).ok())
                    .ok_or_else(|| crate::error::LabError::new("字节数组元素必须在 0..=255"))
            })
            .collect()
    } else {
        Err(crate::error::LabError::new("需要提供 hex 或 bytes 字段"))
    }
}

fn route_inner(req: Request, store: &Arc<Store>) -> Result<Response, crate::error::LabError> {
    let segments: Vec<&str> = req.path.split('/').filter(|s| !s.is_empty()).collect();

    // 静态页面
    if req.method == "GET" && (segments.is_empty() || segments == [""]) {
        return Ok(Response {
            status: 200,
            content_type: "text/html; charset=utf-8".to_string(),
            body: crate::web::INDEX_HTML.to_vec(),
        });
    }
    if req.method == "GET" && segments == ["app.js"] {
        return Ok(Response {
            status: 200,
            content_type: "application/javascript; charset=utf-8".to_string(),
            body: crate::web::APP_JS.to_vec(),
        });
    }

    let api: Vec<&str> = segments
        .iter()
        .copied()
        .skip_while(|s| *s != "api")
        .collect();
    if api.is_empty() || api[0] != "api" {
        return Ok(err_response(404, "not_found", "路径不存在"));
    }

    match (req.method.as_str(), api.get(1).copied()) {
        ("GET", Some("protocols")) => {
            let protocols = store.list_protocols()?;
            Ok(json_response(200, &json!({ "protocols": protocols })))
        }
        ("GET", Some("versions")) => {
            let id = api.get(2).ok_or_else(|| {
                crate::error::LabError::new("缺少版本 id")
            })?;
            let rec = store.version_by_id(id)?;
            Ok(json_response(200, &json!({ "version": rec })))
        }
        ("POST", Some("protocols")) => {
            let value = json_body(&req.body)?;
            let spec: crate::protocol::Protocol =
                serde_json::from_value(value.get("spec").cloned().unwrap_or(value))?;
            let rec = store.save_version(&spec)?;
            Ok(json_response(200, &json!({ "version": rec })))
        }
        ("POST", Some("parse")) => {
            let value = json_body(&req.body)?;
            let version_id = value
                .get("version_id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| crate::error::LabError::new("缺少 version_id"))?;
            let version = store.version_by_id(version_id)?;
            let data = bytes_from_req(&value)?;
            let outcome = crate::parser::parse(&version.spec, &data)?;
            Ok(json_response(200, &json!({ "outcome": outcome })))
        }
        ("POST", Some("encode")) => {
            let value = json_body(&req.body)?;
            let version_id = value
                .get("version_id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| crate::error::LabError::new("缺少 version_id"))?;
            let version = store.version_by_id(version_id)?;
            let values = value.get("values").cloned().unwrap_or(Value::Null);
            let bytes = crate::encoder::encode(&version.spec, &values)?;
            Ok(json_response(
                200,
                &json!({ "hex": crate::hex::encode(&bytes), "length": bytes.len() }),
            ))
        }
        ("POST", Some("blobs")) => {
            let value = json_body(&req.body)?;
            let data = bytes_from_req(&value)?;
            let hash = store.put_blob(&data)?;
            Ok(json_response(
                200,
                &json!({ "blob_hash": hash, "length": data.len() }),
            ))
        }
        ("GET", Some("blobs")) => {
            let hash = api.get(2).ok_or_else(|| {
                crate::error::LabError::new("缺少 blob hash")
            })?;
            let data = store.get_blob(hash)?;
            Ok(json_response(
                200,
                &json!({ "blob_hash": hash, "hex": crate::hex::encode(&data), "length": data.len() }),
            ))
        }
        ("GET", Some("sessions")) => {
            if let Some(id) = api.get(2) {
                let view = store.get_session(id)?;
                Ok(json_response(200, &json!({ "session": view })))
            } else {
                let views = store.list_sessions()?;
                Ok(json_response(200, &json!({ "sessions": views })))
            }
        }
        ("POST", Some("sessions")) => {
            let value = json_body(&req.body)?;
            let version_id = value
                .get("version_id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| crate::error::LabError::new("缺少 version_id"))?;
            let data = bytes_from_req(&value)?;
            let note = value.get("note").and_then(|v| v.as_str()).unwrap_or("");
            let view = store.create_session(version_id, &data, note)?;
            Ok(json_response(200, &json!({ "session": view })))
        }
        ("POST", Some("replay")) => {
            let value = json_body(&req.body)?;
            let id = value
                .get("session_id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| crate::error::LabError::new("缺少 session_id"))?;
            let replay = store.replay(id)?;
            Ok(json_response(
                200,
                &json!({ "session": replay.session, "outcome": replay.outcome, "consistent": replay.consistent }),
            ))
        }
        ("POST", Some("export")) => {
            let value = json_body(&req.body)?;
            let id = value
                .get("session_id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| crate::error::LabError::new("缺少 session_id"))?;
            let bundle = store.export_session(id)?;
            Ok(json_response(200, &json!({ "bundle": bundle })))
        }
        ("POST", Some("import")) => {
            let value = json_body(&req.body)?;
            let bundle: crate::store::ImportBundle =
                serde_json::from_value(value.get("bundle").cloned().unwrap_or(value))?;
            let view = store.import_bundle(&bundle)?;
            Ok(json_response(200, &json!({ "session": view })))
        }
        _ => {
            if let Some(id_pos) = api.iter().position(|s| *s == "sessions") {
                if req.method == "POST"
                    && api.get(id_pos + 2) == Some(&"note")
                {
                    let id = api[id_pos + 1];
                    let value = json_body(&req.body)?;
                    let note = value.get("note").and_then(|v| v.as_str()).unwrap_or("");
                    let view = store.set_note(id, note)?;
                    return Ok(json_response(200, &json!({ "session": view })));
                }
            }
            Ok(err_response(404, "not_found", "未知的 API 路径"))
        }
    }
}
