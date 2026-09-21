// 等价的 JSON API + 静态前端。仅用 std::net，线程内阻塞处理。

use crate::encoder;
use crate::hash::{hex, unhex};
use crate::json::{self, Value};
use crate::model;
use crate::store::Store;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;

const INDEX_HTML: &str = include_str!("../web/index.html");
const MAX_BODY: usize = 32 << 20;

pub fn serve(addr: SocketAddr, data_dir: &str) -> std::io::Result<()> {
    let store = Arc::new(Store::open(data_dir)?);
    let listener = TcpListener::bind(addr)?;
    eprintln!("帧解析实验室已启动: http://{}/  (状态目录: {})", addr, data_dir);
    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                let st = Arc::clone(&store);
                std::thread::spawn(move || {
                    let _ = handle(st, s);
                });
            }
            Err(e) => eprintln!("接受连接失败: {}", e),
        }
    }
    Ok(())
}

fn handle(store: Arc<Store>, mut stream: TcpStream) -> std::io::Result<()> {
    stream.set_read_timeout(Some(std::time::Duration::from_secs(15)))?;
    let mut all = Vec::new();
    let mut buf = [0u8; 8192];
    let (method, path, headers, header_len) = loop {
        let n = stream.read(&mut buf)?;
        if n == 0 {
            return Ok(());
        }
        all.extend_from_slice(&buf[..n]);
        if let Some(pos) = find_double_crlf(&all) {
            let head = String::from_utf8_lossy(&all[..pos]).to_string();
            let mut lines = head.split("\r\n");
            let request_line = lines.next().unwrap_or("");
            let mut parts = request_line.split_whitespace();
            let method = parts.next().unwrap_or("").to_string();
            let path = parts.next().unwrap_or("/").to_string();
            let mut headers = Vec::new();
            for line in lines {
                if let Some((k, v)) = line.split_once(':') {
                    headers.push((k.trim().to_ascii_lowercase(), v.trim().to_string()));
                }
            }
            break (method, path, headers, pos + 4);
        }
        if all.len() > 64 * 1024 {
            return Ok(());
        }
    };

    let body_len: usize = headers
        .iter()
        .find(|(k, _)| k == "content-length")
        .and_then(|(_, v)| v.parse().ok())
        .unwrap_or(0);
    if body_len > MAX_BODY {
        return write_json(&mut stream, 413, &err_body("请求体过大"));
    }
    while all.len() < header_len + body_len {
        let n = stream.read(&mut buf)?;
        if n == 0 {
            break;
        }
        all.extend_from_slice(&buf[..n]);
    }
    let body = &all[header_len..header_len + body_len.min(all.len().saturating_sub(header_len))];

    let response = route(&store, &method, &path, body);
    write_response(&mut stream, response)
}

fn find_double_crlf(b: &[u8]) -> Option<usize> {
    b.windows(4).position(|w| w == b"\r\n\r\n")
}

struct Response {
    status: u16,
    content_type: String,
    body: Vec<u8>,
}

fn write_response(stream: &mut TcpStream, r: Response) -> std::io::Result<()> {
    let reason = match r.status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Payload Too Large",
        500 => "Internal Server Error",
        _ => "OK",
    };
    let head = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\nAccess-Control-Allow-Origin: *\r\n\r\n",
        r.status, reason, r.content_type, r.body.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(&r.body)?;
    stream.flush()
}

fn write_json(stream: &mut TcpStream, status: u16, v: &Value) -> std::io::Result<()> {
    write_response(
        stream,
        Response {
            status,
            content_type: "application/json; charset=utf-8".to_string(),
            body: json::stringify_pretty(v).into_bytes(),
        },
    )
}

fn err_body(msg: &str) -> Value {
    Value::Obj(vec![("ok".to_string(), Value::Bool(false)), ("error".to_string(), Value::Str(msg.to_string()))])
}

fn ok_value(extra: Vec<(String, Value)>) -> Value {
    let mut v = vec![("ok".to_string(), Value::Bool(true))];
    v.extend(extra);
    Value::Obj(v)
}

fn route(store: &Arc<Store>, method: &str, path: &str, body: &[u8]) -> Response {
    let (route_path, query) = path.split_once('?').unwrap_or((path, ""));
    let _ = query;
    let json_ct = "application/json; charset=utf-8".to_string();

    if method == "GET" && (route_path == "/" || route_path == "/index.html") {
        return Response {
            status: 200,
            content_type: "text/html; charset=utf-8".to_string(),
            body: INDEX_HTML.as_bytes().to_vec(),
        };
    }
    if method == "GET" && route_path == "/healthz" {
        return json_response(200, &ok_value(vec![("service".to_string(), Value::Str("frame-lab".to_string()))]));
    }

    if method != "POST" {
        return Response {
            status: 405,
            content_type: json_ct,
            body: json::stringify(&err_body("只支持 GET / 与 POST /api/...")).into_bytes(),
        };
    }

    let parsed = std::str::from_utf8(body).ok().and_then(|s| json::parse(s).ok());
    let req = match (route_path.starts_with("/api/"), parsed) {
        (true, Some(v)) => v,
        (true, None) => {
            return Response {
                status: 400,
                content_type: json_ct,
                body: json::stringify(&err_body("请求体必须是合法 JSON")).into_bytes(),
            }
        }
        _ => {
            return Response {
                status: 404,
                content_type: json_ct,
                body: json::stringify(&err_body("未知路径")).into_bytes(),
            }
        }
    };

    let result = dispatch(store, route_path, &req);
    match result {
        Ok(v) => json_response(200, &v),
        Err((status, msg)) => Response {
            status,
            content_type: json_ct,
            body: json::stringify(&err_body(&msg)).into_bytes(),
        },
    }
}

fn json_response(status: u16, v: &Value) -> Response {
    Response {
        status,
        content_type: "application/json; charset=utf-8".to_string(),
        body: json::stringify_pretty(v).into_bytes(),
    }
}

fn api_err(msg: impl Into<String>) -> (u16, String) {
    (400, msg.into())
}

fn need_str<'a>(v: &'a Value, key: &str) -> Result<&'a str, (u16, String)> {
    v.get(key)
        .and_then(|x| x.as_str())
        .ok_or_else(|| api_err(format!("缺少字符串参数 {}", key)))
}

fn dispatch(store: &Arc<Store>, path: &str, req: &Value) -> Result<Value, (u16, String)> {
    match path {
        "/api/state" => {
            let protos = store.list_protocols().map_err(api_err)?;
            let blobs = store.list_blobs().map_err(api_err)?;
            let sessions = store.list_sessions().map_err(api_err)?;
            Ok(ok_value(vec![
                ("protocols".to_string(), Value::Arr(protos)),
                ("blobs".to_string(), Value::Arr(blobs)),
                ("sessions".to_string(), Value::Arr(sessions)),
            ]))
        }
        "/api/protocols/save" => {
            let spec = req
                .get("spec")
                .ok_or_else(|| api_err("缺少 spec（协议描述 JSON）"))?;
            let (vid, proto) = store.save_protocol(spec).map_err(api_err)?;
            let normalized = model::protocol_to_json(&proto);
            Ok(ok_value(vec![
                ("version_id".to_string(), Value::Str(vid)),
                ("spec".to_string(), normalized),
            ]))
        }
        "/api/protocols/validate" => {
            let spec = req.get("spec").ok_or_else(|| api_err("缺少 spec"))?;
            match model::load_protocol(spec) {
                Ok(proto) => Ok(ok_value(vec![
                    ("valid".to_string(), Value::Bool(true)),
                    ("name".to_string(), Value::Str(proto.name)),
                    ("root".to_string(), Value::Str(proto.root)),
                ])),
                Err(e) => Ok(ok_value(vec![
                    ("valid".to_string(), Value::Bool(false)),
                    ("error".to_string(), Value::Str(e)),
                ])),
            }
        }
        "/api/parse" => {
            let vid = need_str(req, "version_id")?;
            let data = extract_bytes(req)?;
            let result = store.parse_with(vid, &data).map_err(api_err)?;
            Ok(ok_value(vec![
                ("version_id".to_string(), Value::Str(vid.to_string())),
                ("input_len".to_string(), Value::Int(data.len() as i128)),
                ("result".to_string(), result),
            ]))
        }
        "/api/encode" => {
            let vid = need_str(req, "version_id")?;
            let (proto, _) = store.load_protocol_version(vid).map_err(api_err)?;
            let input = req
                .get("values")
                .cloned()
                .unwrap_or_else(|| Value::Obj(Vec::new()));
            let frame = encoder::encode(&proto, &input).map_err(api_err)?;
            let result = crate::parser::parse(&proto, &frame.bytes);
            Ok(ok_value(vec![
                ("bytes_hex".to_string(), Value::Str(hex(&frame.bytes))),
                ("used_defaults".to_string(), Value::Arr(
                    frame.used_defaults.into_iter().map(Value::Str).collect()
                )),
                ("parse".to_string(), crate::tree::result_to_value(&result)),
            ]))
        }
        "/api/blobs/put" => {
            let data = extract_bytes(req)?;
            let new_id = hex(&crate::hash::sha256(&data));
            let existed = store.get_blob(&new_id).is_ok();
            let id = store.put_blob(&data).map_err(api_err)?;
            Ok(ok_value(vec![
                ("blob_id".to_string(), Value::Str(id)),
                ("size".to_string(), Value::Int(data.len() as i128)),
                ("deduped".to_string(), Value::Bool(existed)),
            ]))
        }
        "/api/blobs/get" => {
            let id = need_str(req, "blob_id")?;
            let data = store.get_blob(id).map_err(api_err)?;
            Ok(ok_value(vec![
                ("blob_id".to_string(), Value::Str(id.to_string())),
                ("bytes_hex".to_string(), Value::Str(hex(&data))),
                ("size".to_string(), Value::Int(data.len() as i128)),
            ]))
        }
        "/api/sessions/create" => {
            let vid = need_str(req, "version_id")?;
            let name = req.get("name").and_then(|v| v.as_str()).unwrap_or("未命名会话");
            let note = req.get("note").and_then(|v| v.as_str()).unwrap_or("");
            let data = extract_bytes(req)?;
            let rec = store
                .create_session(name, note, vid, crate::store::BytesInput::Data(&data))
                .map_err(api_err)?;
            Ok(ok_value(vec![
                ("session".to_string(), session_summary_json(&rec)),
            ]))
        }
        "/api/sessions/update" => {
            let id = need_str(req, "session_id")?;
            let note = req.get("note").and_then(|v| v.as_str()).unwrap_or("");
            let name = req.get("name").and_then(|v| v.as_str());
            let rec = store.update_session_note(id, note, name).map_err(api_err)?;
            Ok(ok_value(vec![("session".to_string(), session_summary_json(&rec))]))
        }
        "/api/sessions/get" => {
            let id = need_str(req, "session_id")?;
            let rec = store.load_session(id).map_err(api_err)?;
            let data = store.get_blob(&rec.blob_id).map_err(api_err)?;
            Ok(ok_value(vec![
                ("session".to_string(), crate::store::session_public_json(&rec)),
                ("bytes_hex".to_string(), Value::Str(hex(&data))),
            ]))
        }
        "/api/sessions/replay" => {
            let id = need_str(req, "session_id")?;
            let v = store.replay_session(id).map_err(api_err)?;
            Ok(ok_value(vec![("replay".to_string(), v)]))
        }
        "/api/sessions/export" => {
            let id = need_str(req, "session_id")?;
            let pkg = store.export_session(id).map_err(api_err)?;
            Ok(ok_value(vec![("package".to_string(), pkg)]))
        }
        "/api/sessions/import" => {
            let pkg = req.get("package").cloned().unwrap_or_else(|| req.clone());
            let report = store.import_package(&pkg).map_err(api_err)?;
            Ok(ok_value(vec![("import".to_string(), report)]))
        }
        _ => Err((404, format!("未知 API 路径 {}", path))),
    }
}

fn session_summary_json(rec: &crate::store::SessionRecord) -> Value {
    Value::Obj(vec![
        ("session_id".to_string(), Value::Str(rec.id.clone())),
        ("name".to_string(), Value::Str(rec.name.clone())),
        ("note".to_string(), Value::Str(rec.note.clone())),
        ("version_id".to_string(), Value::Str(rec.version_id.clone())),
        ("blob_id".to_string(), Value::Str(rec.blob_id.clone())),
        ("status".to_string(), rec.result.get("status").cloned().unwrap_or(Value::Null)),
        ("tree_digest".to_string(), rec.result.get("tree_digest").cloned().unwrap_or(Value::Null)),
        ("created_at".to_string(), Value::Int(rec.created_at as i128)),
    ])
}

fn extract_bytes(req: &Value) -> Result<Vec<u8>, (u16, String)> {
    if let Some(h) = req.get("bytes_hex").and_then(|v| v.as_str()) {
        return unhex(h).ok_or_else(|| api_err("bytes_hex 不是合法十六进制"));
    }
    if let Some(arr) = req.get("bytes").and_then(|v| v.as_array()) {
        let mut out = Vec::with_capacity(arr.len());
        for item in arr {
            let n = item.as_i128().ok_or_else(|| api_err("bytes 数组元素必须是整数"))?;
            if !(0..=255).contains(&n) {
                return Err(api_err("bytes 数组元素必须在 0..=255"));
            }
            out.push(n as u8);
        }
        return Ok(out);
    }
    if let Some(id) = req.get("blob_id").and_then(|v| v.as_str()) {
        // blob_id 的读取在 store 内完成
        return Err(api_err(format!("请先通过 /api/blobs/get 读取 blob {} 再解析", id)));
    }
    Err(api_err("缺少 bytes_hex 或 bytes"))
}
