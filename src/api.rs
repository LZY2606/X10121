//! 等价的 JSON API：所有浏览器能力在此都有对应的无状态/有状态端点。
use crate::json::Json;
use crate::model::ParseReport;
use crate::parser;
use crate::spec::Spec;
use crate::storage::{Session, Store};

pub struct Api {
    pub store: Store,
}

fn err_json(code: &str, msg: &str) -> Json {
    Json::obj()
        .with("ok", Json::Bool(false))
        .with("error_code", Json::Str(code.to_string()))
        .with("error", Json::Str(msg.to_string()))
}

fn ok(data: Json) -> Json {
    Json::obj().with("ok", Json::Bool(true)).with("data", data)
}

impl Api {
    pub fn new(store: Store) -> Api {
        Api { store }
    }

    pub fn dispatch(&self, method: &str, path: &str, body: &str) -> (u16, Json) {
        let route = (method, path);
        let result = match route {
            ("GET", "/api/demo") => Ok(Json::obj()
                .with("name", Json::Str(crate::demo::DEMO_NAME.to_string()))
                .with("spec", crate::demo::demo_spec_json())
                .with("hex", Json::Str(crate::demo::demo_sample_hex()))),
            ("GET", "/api/protocols") => self.list_protocols(),
            ("POST", "/api/protocols") => with_body(body, |j| self.create_protocol(j)),
            ("GET", p) if p.starts_with("/api/protocols/") => {
                let pid = p.trim_start_matches("/api/protocols/");
                self.get_protocol(pid)
            }
            ("POST", p) if p.starts_with("/api/protocols/") && p.ends_with("/versions") => {
                let pid = p
                    .trim_start_matches("/api/protocols/")
                    .trim_end_matches("/versions");
                with_body(body, |j| self.save_version(pid, j))
            }
            ("POST", "/api/parse") => with_body(body, |j| self.parse(j)),
            ("POST", "/api/blobs") => with_body(body, |j| self.put_blob(j)),
            ("GET", p) if p.starts_with("/api/blobs/") => {
                let hash = p.trim_start_matches("/api/blobs/");
                self.get_blob(hash)
            }
            ("GET", "/api/sessions") => self.list_sessions(),
            ("POST", "/api/sessions") => with_body(body, |j| self.create_session(j)),
            ("GET", p) if p.starts_with("/api/sessions/") && !p.ends_with("/export") => {
                let sid = p.trim_start_matches("/api/sessions/");
                self.get_session(sid)
            }
            ("PATCH", p) if p.starts_with("/api/sessions/") => {
                let sid = p.trim_start_matches("/api/sessions/");
                with_body(body, |j| self.patch_session(sid, j))
            }
            ("POST", p) if p.starts_with("/api/sessions/") && p.ends_with("/revisions") => {
                let sid = p
                    .trim_start_matches("/api/sessions/")
                    .trim_end_matches("/revisions");
                with_body(body, |j| self.add_revision(sid, j))
            }
            ("POST", p) if p.starts_with("/api/sessions/") && p.ends_with("/export") => {
                let sid = p
                    .trim_start_matches("/api/sessions/")
                    .trim_end_matches("/export");
                self.export_session(sid)
            }
            ("POST", "/api/import") => with_body(body, |j| self.import_session(j)),
            _ => return (404, err_json("not_found", &format!("未知端点：{method} {path}"))),
        };
        match result {
            Ok(j) => (200, ok(j)),
            Err(msg) => (400, err_json("bad_request", &msg)),
        }
    }

    fn list_protocols(&self) -> Result<Json, String> {
        let arr = self
            .store
            .list_protocols()?
            .into_iter()
            .map(|p| Json::obj().with("id", Json::Str(p.id)).with("name", Json::Str(p.name)).with("latest", Json::Int(p.latest as i64)))
            .collect();
        Ok(Json::Arr(arr))
    }

    fn create_protocol(&self, j: &Json) -> Result<Json, String> {
        let name = j.get("name").and_then(|x| x.as_str()).unwrap_or("未命名协议");
        let spec = j.get("spec").ok_or("缺少 spec")?;
        let note = j.get("note").and_then(|x| x.as_str()).unwrap_or("");
        let p = self.store.create_protocol(name, spec, note)?;
        Ok(protocol_json(&p))
    }

    fn get_protocol(&self, pid: &str) -> Result<Json, String> {
        let p = self.store.load_protocol(pid)?;
        Ok(protocol_json(&p))
    }

    fn save_version(&self, pid: &str, j: &Json) -> Result<Json, String> {
        let spec = j.get("spec").ok_or("缺少 spec")?;
        let note = j.get("note").and_then(|x| x.as_str()).unwrap_or("");
        let r = self.store.save_version(pid, spec, note)?;
        Ok(Json::obj()
            .with("version", Json::Int(r.version as i64))
            .with("digest", Json::Str(r.digest))
            .with("created", Json::Bool(true)))
    }

    fn parse(&self, j: &Json) -> Result<Json, String> {
        let (spec, _pid, version) = parse_spec_arg(&self.store, j)?;
        let bytes = parse_bytes_arg(j)?;
        let report = parser::parse(&spec, &bytes);
        Ok(parse_response(&report, version))
    }

    fn put_blob(&self, j: &Json) -> Result<Json, String> {
        let bytes = parse_bytes_arg(j)?;
        let hash = self.store.put_blob(&bytes)?;
        Ok(Json::obj()
            .with("blob", Json::Str(hash.clone()))
            .with("byte_length", Json::Int(bytes.len() as i64))
            .with("reused", Json::Bool(self.store.blob_exists(&hash))))
    }

    fn get_blob(&self, hash: &str) -> Result<Json, String> {
        let bytes = self.store.get_blob(hash)?;
        Ok(Json::obj()
            .with("blob", Json::Str(hash.to_string()))
            .with("hex", Json::Str(crate::hexutil::encode_hex(&bytes)))
            .with("byte_length", Json::Int(bytes.len() as i64)))
    }

    fn list_sessions(&self) -> Result<Json, String> {
        Ok(Json::Arr(self.store.list_sessions()?))
    }

    fn create_session(&self, j: &Json) -> Result<Json, String> {
        let title = j.get("title").and_then(|x| x.as_str()).unwrap_or("未命名会话");
        let note = j.get("note").and_then(|x| x.as_str()).unwrap_or("");
        let pid = j.get("protocol_id").and_then(|x| x.as_str()).ok_or("缺少 protocol_id")?;
        let version = j.get("version").and_then(|x| x.as_i64()).ok_or("缺少 version")? as usize;
        let bytes = parse_bytes_arg(j)?;
        let blob = self.store.put_blob(&bytes)?;
        let proto = self.store.load_protocol(pid)?;
        let spec = proto
            .revisions
            .iter()
            .find(|r| r.version == version)
            .ok_or_else(|| format!("协议 {pid} 没有版本 {version}"))?;
        let report = parser::parse(&spec.spec, &bytes);
        let sess = self
            .store
            .create_session(title, note, pid, version, &blob, bytes.len(), &report)?;
        let mut out = session_json(&sess);
        out.put("report", report.to_json());
        Ok(out)
    }

    fn get_session(&self, sid: &str) -> Result<Json, String> {
        let sess = self.store.load_session(sid)?;
        let bytes = self.store.get_blob(&sess.current.blob)?;
        let proto = self.store.load_protocol(&sess.current.protocol_id)?;
        let spec = proto
            .revisions
            .iter()
            .find(|r| r.version == sess.current.version)
            .unwrap()
            .spec
            .clone();
        let report = parser::parse(&spec, &bytes);
        // 历史重放与保存摘要的一致性
        let replay_match = report.report_digest() == sess.current.report_digest;
        let mut out = session_json(&sess);
        out.put("hex", Json::Str(crate::hexutil::encode_hex(&bytes)));
        out.put("report", report.to_json());
        out.put("replay_match", Json::Bool(replay_match));
        Ok(out)
    }

    fn patch_session(&self, sid: &str, j: &Json) -> Result<Json, String> {
        let title = j.get("title").and_then(|x| x.as_str());
        let note = j.get("note").and_then(|x| x.as_str());
        let sess = self.store.set_note(sid, title, note)?;
        Ok(session_json(&sess))
    }

    fn add_revision(&self, sid: &str, j: &Json) -> Result<Json, String> {
        let bytes = parse_bytes_arg(j)?;
        let sess0 = self.store.load_session(sid)?;
        let blob = self.store.put_blob(&bytes)?;
        let proto = self.store.load_protocol(&sess0.current.protocol_id)?;
        let spec = proto
            .revisions
            .iter()
            .find(|r| r.version == sess0.current.version)
            .unwrap()
            .spec
            .clone();
        let report = parser::parse(&spec, &bytes);
        let sess = self.store.save_session_revision(sid, &blob, bytes.len(), &report)?;
        let mut out = session_json(&sess);
        out.put("report", report.to_json());
        Ok(out)
    }

    fn export_session(&self, sid: &str) -> Result<Json, String> {
        self.store.export_session(sid)
    }

    fn import_session(&self, j: &Json) -> Result<Json, String> {
        let pkg = j.get("package_json").cloned().unwrap_or_else(|| j.clone());
        let (sess, verify) = self.store.import_package(&pkg)?;
        Ok(Json::obj().with("session", session_json(&sess)).with("verify", verify))
    }
}

fn with_body<F: FnOnce(&Json) -> Result<Json, String>>(body: &str, f: F) -> Result<Json, String> {
    let j = Json::parse(body).map_err(|e| format!("请求体不是合法 JSON：{e}"))?;
    f(&j)
}

fn parse_bytes_arg(j: &Json) -> Result<Vec<u8>, String> {
    if let Some(hex) = j.get("hex").and_then(|x| x.as_str()) {
        crate::hexutil::decode_hex(hex)
    } else if let Some(arr) = j.get("bytes").and_then(|x| x.as_array()) {
        arr.iter()
            .map(|v| {
                v.as_i64()
                    .filter(|n| (0..=255).contains(n))
                    .map(|n| n as u8)
                    .ok_or_else(|| "bytes 数组项必须是 0..255 整数".to_string())
            })
            .collect()
    } else {
        Err("缺少 hex 或 bytes 输入".to_string())
    }
}

fn parse_spec_arg(store: &Store, j: &Json) -> Result<(Spec, String, usize), String> {
    if let Some(spec) = j.get("spec") {
        let s = Spec::from_json(spec)?;
        Ok((s, String::new(), 0))
    } else {
        let pid = j.get("protocol_id").and_then(|x| x.as_str()).ok_or("缺少 spec 或 protocol_id")?;
        let version = match j.get("version").and_then(|x| x.as_i64()) {
            Some(v) => v as usize,
            None => store.load_protocol(pid)?.latest,
        };
        let proto = store.load_protocol(pid)?;
        let rev = proto
            .revisions
            .iter()
            .find(|r| r.version == version)
            .ok_or_else(|| format!("协议 {pid} 没有版本 {version}"))?;
        Ok((rev.spec.clone(), pid.to_string(), version))
    }
}

fn parse_response(report: &ParseReport, version: usize) -> Json {
    let mut o = report.to_json();
    o.put("bound_version", Json::Int(version as i64));
    o
}

pub(crate) fn protocol_json(p: &crate::storage::Protocol) -> Json {
    Json::obj()
        .with("id", Json::Str(p.id.clone()))
        .with("name", Json::Str(p.name.clone()))
        .with("latest", Json::Int(p.latest as i64))
        .with(
            "revisions",
            Json::Arr(
                p.revisions
                    .iter()
                    .map(|r| {
                        Json::obj()
                            .with("version", Json::Int(r.version as i64))
                            .with("digest", Json::Str(r.digest.clone()))
                            .with("note", Json::Str(r.note.clone()))
                            .with("created_at", Json::Str(r.created_at.clone()))
                            .with("spec", r.spec_json.clone())
                    })
                    .collect(),
            ),
        )
            .with(
            "spec",
            p.revisions
                .iter()
                .find(|r| r.version == p.latest)
                .map(|r| r.spec_json.clone())
                .unwrap_or(Json::Null),
        )
}

pub(crate) fn session_json(s: &Session) -> Json {
    crate::storage::session_to_json(s)
}
