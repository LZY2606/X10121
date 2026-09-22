//! 零依赖 HTTP/1.1 服务：JSON API + 内嵌静态页面。
use crate::api::Api;
use crate::json::Json;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;

const INDEX_HTML: &str = include_str!("static/index.html");

pub fn serve(addr: &str, api: Arc<Api>) -> Result<(), String> {
    let listener = TcpListener::bind(addr).map_err(|e| format!("绑定 {addr} 失败：{e}"))?;
    println!("帧解析实验室已启动：http://{addr}");
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let api = api.clone();
                thread::spawn(move || {
                    let _ = handle_connection(stream, &api);
                });
            }
            Err(e) => eprintln!("接受连接失败：{e}"),
        }
    }
    Ok(())
}

fn handle_connection(mut stream: TcpStream, api: &Api) -> std::io::Result<()> {
    stream.set_read_timeout(Some(std::time::Duration::from_secs(10)))?;
    let mut buf = Vec::with_capacity(8192);
    let mut tmp = [0u8; 4096];
    // 读到头部结束
    let header_end = loop {
        let n = stream.read(&mut tmp)?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(p) = find_subslice(&buf, b"\r\n\r\n") {
            break p;
        }
        if buf.len() > 1024 * 1024 {
            return Ok(());
        }
    };

    let header_text = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let mut lines = header_text.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let raw_target = parts.next().unwrap_or("/").to_string();
    let (path, _query) = match raw_target.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (raw_target.clone(), String::new()),
    };

    let content_length: usize = header_text
        .lines()
        .find_map(|l| {
            let l = l.to_ascii_lowercase();
            l.strip_prefix("content-length:")
                .and_then(|v| v.trim().parse().ok())
        })
        .unwrap_or(0);
    if content_length > 16 * 1024 * 1024 {
        write_response(
            &mut stream,
            413,
            "application/json; charset=utf-8",
            Json::obj()
                .with("ok", Json::Bool(false))
                .with("error", Json::Str("请求体过大".into()))
                .dump()
                .as_bytes(),
        )?;
        return Ok(());
    }
    let mut body_buf = buf[header_end + 4..].to_vec();
    while body_buf.len() < content_length {
        let n = stream.read(&mut tmp)?;
        if n == 0 {
            break;
        }
        body_buf.extend_from_slice(&tmp[..n]);
    }
    body_buf.truncate(content_length);
    let body = String::from_utf8_lossy(&body_buf).to_string();

    if method == "GET" && (path == "/" || path == "/index.html") {
        write_response(&mut stream, 200, "text/html; charset=utf-8", INDEX_HTML.as_bytes())?;
        return Ok(());
    }
    if method == "GET" && path == "/static/app.js" {
        write_response(&mut stream, 200, "application/javascript; charset=utf-8", include_bytes!("static/app.js"))?;
        return Ok(());
    }
    if method == "GET" && path == "/favicon.ico" {
        write_response(&mut stream, 204, "image/x-icon", &[])?;
        return Ok(());
    }

    if path.starts_with("/api/") {
        let (status, j) = api.dispatch(&method, &path, &body);
        let code: u16 = status;
        write_response(&mut stream, code, "application/json; charset=utf-8", j.dump_pretty().as_bytes())?;
        return Ok(());
    }

    write_response(&mut stream, 404, "text/plain; charset=utf-8", "404 Not Found".as_bytes())
}

fn write_response(stream: &mut TcpStream, status: u16, content_type: &str, body: &[u8]) -> std::io::Result<()> {
    let reason = match status {
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        404 => "Not Found",
        413 => "Payload Too Large",
        _ => "OK",
    };
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\nAccess-Control-Allow-Origin: *\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}
