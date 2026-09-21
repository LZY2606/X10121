// 状态持久化：全部落在仓库目录下的 data 目录，纯文件 + JSON，无系统数据库。
//
//   <dir>/protocols/<vid>.json   协议版本（不可变）
//   <dir>/blobs/<blobid>         原始字节
//   <dir>/sessions/<sid>.json    会话（绑定协议版本与 blob，含备注/诊断/树摘要）
//   <dir>/meta.json              自增序号等元数据

use crate::hash::{hex, sha256, unhex};
use crate::json::{self, Value};
use crate::model::{self, Protocol};
use crate::parser::{self, NodeStatus};
use crate::tree;

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct Store {
    dir: PathBuf,
    seq: Mutex<u64>,
}

#[derive(Debug)]
pub struct SessionRecord {
    pub id: String,
    pub created_at: u64,
    pub updated_at: u64,
    pub name: String,
    pub note: String,
    pub version_id: String,
    pub blob_id: String,
    pub result: Value,
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

pub fn canonical_bytes(v: &Value) -> Vec<u8> {
    let c = json::canonicalize(v);
    json::stringify(&c).into_bytes()
}

pub fn content_id(canon: &[u8]) -> String {
    hex(&sha256(canon))
}

impl Store {
    pub fn open(dir: impl AsRef<Path>) -> std::io::Result<Store> {
        let dir = dir.as_ref().to_path_buf();
        fs::create_dir_all(dir.join("protocols"))?;
        fs::create_dir_all(dir.join("blobs"))?;
        fs::create_dir_all(dir.join("sessions"))?;
        let meta_path = dir.join("meta.json");
        let seq = if meta_path.exists() {
            let raw = fs::read_to_string(&meta_path)?;
            match json::parse(&raw).ok().and_then(|v| v.get("seq").and_then(|x| x.as_i128())) {
                Some(n) => n as u64,
                None => 0,
            }
        } else {
            0
        };
        Ok(Store {
            dir,
            seq: Mutex::new(seq),
        })
    }

    fn next_id(&self, prefix: &str) -> std::io::Result<String> {
        let mut s = self.seq.lock().unwrap();
        *s += 1;
        let nanos = now_millis();
        let id = format!("{}_{:016x}_{:06}", prefix, nanos, s);
        let meta = Value::Obj(vec![("seq".to_string(), Value::Int(*s as i128))]);
        fs::write(self.dir.join("meta.json"), json::stringify_pretty(&meta))?;
        Ok(id)
    }

    pub fn data_dir(&self) -> &Path {
        &self.dir
    }

    // ---------- 协议版本 ----------

    pub fn save_protocol(&self, spec: &Value) -> Result<(String, Protocol), String> {
        let proto = model::load_protocol(spec)?;
        let normalized = model::protocol_to_json(&proto);
        let canon = canonical_bytes(&normalized);
        let vid = content_id(&canon);
        let path = self.dir.join("protocols").join(format!("{}.json", vid));
        if !path.exists() {
            atomic_write_json(&path, &normalized)?;
        }
        Ok((vid, proto))
    }

    pub fn list_protocols(&self) -> Result<Vec<Value>, String> {
        let mut out = Vec::new();
        for ent in fs::read_dir(self.dir.join("protocols")).map_err(io_err)? {
            let ent = ent.map_err(io_err)?;
            let fname = ent.file_name().to_string_lossy().to_string();
            let Some(vid) = fname.strip_suffix(".json") else { continue };
            let raw = fs::read_to_string(ent.path()).map_err(io_err)?;
            let v = json::parse(&raw).map_err(|e| format!("版本 {} 损坏: {}", vid, e))?;
            let name = v.get("name").and_then(|x| x.as_str()).unwrap_or("");
            let created = ent
                .metadata()
                .and_then(|m| m.created())
                .ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_millis() as i128)
                .unwrap_or(0);
            out.push(Value::Obj(vec![
                ("version_id".to_string(), Value::Str(vid.to_string())),
                ("name".to_string(), Value::Str(name.to_string())),
                ("created_at".to_string(), Value::Int(created)),
                ("spec".to_string(), v),
            ]));
        }
        out.sort_by(|a, b| {
            a.get("version_id")
                .and_then(|v| v.as_str())
                .cmp(&b.get("version_id").and_then(|v| v.as_str()))
        });
        Ok(out)
    }

    pub fn load_protocol_version(&self, vid: &str) -> Result<(Protocol, Value), String> {
        let path = self.safe_protocol_path(vid)?;
        if !path.exists() {
            return Err(format!("协议版本 {} 不存在（历史版本不可变，不会被新版本替换）", vid));
        }
        let raw = fs::read_to_string(&path).map_err(io_err)?;
        let spec = json::parse(&raw).map_err(|e| format!("版本 JSON 损坏: {}", e))?;
        let proto = model::load_protocol(&spec)?;
        Ok((proto, spec))
    }

    fn safe_protocol_path(&self, vid: &str) -> Result<PathBuf, String> {
        if !is_hex_id(vid) {
            return Err("非法 version_id".to_string());
        }
        Ok(self.dir.join("protocols").join(format!("{}.json", vid)))
    }

    pub fn known_version(&self, vid: &str) -> bool {
        self.safe_protocol_path(vid).map(|p| p.exists()).unwrap_or(false)
    }

    // ---------- blob ----------

    pub fn put_blob(&self, data: &[u8]) -> Result<String, String> {
        let id = hex(&sha256(data));
        let path = self.dir.join("blobs").join(&id);
        if !path.exists() {
            atomic_write_bytes(&path, data)?;
        }
        Ok(id)
    }

    pub fn get_blob(&self, id: &str) -> Result<Vec<u8>, String> {
        if !is_hex_id(id) {
            return Err("非法 blob_id".to_string());
        }
        let path = self.dir.join("blobs").join(id);
        if !path.exists() {
            return Err(format!("blob {} 不存在", id));
        }
        fs::read(&path).map_err(io_err)
    }

    pub fn list_blobs(&self) -> Result<Vec<Value>, String> {
        let mut out = Vec::new();
        for ent in fs::read_dir(self.dir.join("blobs")).map_err(io_err)? {
            let ent = ent.map_err(io_err)?;
            let name = ent.file_name().to_string_lossy().to_string();
            if !is_hex_id(&name) {
                continue;
            }
            let len = ent.metadata().map(|m| m.len() as i128).unwrap_or(0);
            out.push(Value::Obj(vec![
                ("blob_id".to_string(), Value::Str(name)),
                ("size".to_string(), Value::Int(len)),
            ]));
        }
        out.sort_by(|a, b| {
            a.get("blob_id")
                .and_then(|v| v.as_str())
                .cmp(&b.get("blob_id").and_then(|v| v.as_str()))
        });
        Ok(out)
    }

    // ---------- 会话 ----------

    pub fn create_session(
        &self,
        name: &str,
        note: &str,
        version_id: &str,
        bytes_hex_or_data: BytesInput<'_>,
    ) -> Result<SessionRecord, String> {
        let (proto, _spec) = self.load_protocol_version(version_id)?;
        let data = bytes_hex_or_data.into_vec()?;
        let blob_id = self.put_blob(&data)?;
        let result = parser::parse(&proto, &data);
        let result_v = tree::result_to_value(&result);
        let now = now_millis();
        let id = self.next_id("sess").map_err(io_err)?;
        let rec = SessionRecord {
            id,
            created_at: now,
            updated_at: now,
            name: name.to_string(),
            note: note.to_string(),
            version_id: version_id.to_string(),
            blob_id,
            result: result_v,
        };
        self.write_session(&rec)?;
        Ok(rec)
    }

    pub fn update_session_note(&self, id: &str, note: &str, name: Option<&str>) -> Result<SessionRecord, String> {
        let mut rec = self.load_session(id)?;
        rec.note = note.to_string();
        if let Some(n) = name {
            rec.name = n.to_string();
        }
        rec.updated_at = now_millis();
        self.write_session(&rec)?;
        Ok(rec)
    }

    /// 用同一（版本, blob）重放会话：重算诊断与树摘要并比对，确认“旧结论不被新版本改变”。
    pub fn replay_session(&self, id: &str) -> Result<Value, String> {
        let rec = self.load_session(id)?;
        let (proto, _) = self.load_protocol_version(&rec.version_id)?;
        let data = self.get_blob(&rec.blob_id)?;
        let fresh = parser::parse(&proto, &data);
        let fresh_v = tree::result_to_value(&fresh);
        let consistent = fresh_v == rec.result;
        let mut out = vec![
            ("session_id".to_string(), Value::Str(rec.id.clone())),
            ("version_id".to_string(), Value::Str(rec.version_id.clone())),
            ("blob_id".to_string(), Value::Str(rec.blob_id.clone())),
            ("consistent".to_string(), Value::Bool(consistent)),
            ("replayed".to_string(), fresh_v),
            ("stored".to_string(), rec.result),
        ];
        if !consistent {
            out.push((
                "message".to_string(),
                Value::Str(
                    "重放结果与创建时不一致：会话绑定的版本内容可能被外部改动（正常情况下不可变）"
                        .to_string(),
                ),
            ));
        }
        Ok(Value::Obj(out))
    }

    fn write_session(&self, rec: &SessionRecord) -> Result<(), String> {
        let v = session_to_json(rec);
        let path = self.dir.join("sessions").join(format!("{}.json", rec.id));
        atomic_write_json(&path, &v)
    }

    pub fn load_session(&self, id: &str) -> Result<SessionRecord, String> {
        if id.contains('/') || id.contains("..") {
            return Err("非法 session id".to_string());
        }
        let path = self.dir.join("sessions").join(format!("{}.json", id));
        if !path.exists() {
            return Err(format!("会话 {} 不存在", id));
        }
        let raw = fs::read_to_string(&path).map_err(io_err)?;
        let v = json::parse(&raw).map_err(|e| format!("会话 JSON 损坏: {}", e))?;
        json_to_session(v)
    }

    pub fn list_sessions(&self) -> Result<Vec<Value>, String> {
        let mut out = Vec::new();
        for ent in fs::read_dir(self.dir.join("sessions")).map_err(io_err)? {
            let ent = ent.map_err(io_err)?;
            let fname = ent.file_name().to_string_lossy().to_string();
            let Some(id) = fname.strip_suffix(".json") else { continue };
            let rec = self.load_session(id)?;
            let status = rec
                .result
                .get("status")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let digest = rec
                .result
                .get("tree_digest")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            out.push(Value::Obj(vec![
                ("session_id".to_string(), Value::Str(rec.id)),
                ("name".to_string(), Value::Str(rec.name)),
                ("note".to_string(), Value::Str(rec.note)),
                ("created_at".to_string(), Value::Int(rec.created_at as i128)),
                ("updated_at".to_string(), Value::Int(rec.updated_at as i128)),
                ("version_id".to_string(), Value::Str(rec.version_id)),
                ("blob_id".to_string(), Value::Str(rec.blob_id)),
                ("status".to_string(), Value::Str(status.to_string())),
                ("tree_digest".to_string(), Value::Str(digest.to_string())),
            ]));
        }
        out.sort_by(|a, b| {
            b.get("created_at")
                .and_then(|v| v.as_i128())
                .cmp(&a.get("created_at").and_then(|v| v.as_i128()))
        });
        Ok(out)
    }

    // ---------- 导入 / 导出 ----------

    /// 导出会话包：协议版本 + blob 字节 + 会话记录全部内联，包体带 sha256 自校验。
    pub fn export_session(&self, id: &str) -> Result<Value, String> {
        let rec = self.load_session(id)?;
        let (_proto, spec) = self.load_protocol_version(&rec.version_id)?;
        let data = self.get_blob(&rec.blob_id)?;
        let payload = Value::Obj(vec![
            ("format".to_string(), Value::Str("frame-lab-session@1".to_string())),
            ("version_id".to_string(), Value::Str(rec.version_id.clone())),
            ("blob_id".to_string(), Value::Str(rec.blob_id.clone())),
            ("spec".to_string(), spec),
            ("bytes_hex".to_string(), Value::Str(hex(&data))),
            ("session".to_string(), session_to_json(&rec)),
        ]);
        let sha = content_id(&canonical_bytes(&payload));
        Ok(Value::Obj(vec![
            ("payload".to_string(), payload),
            ("sha256".to_string(), Value::Str(sha)),
        ]))
    }

    /// 导入会话包。版本/blob 已存在则指向已有对象（同一样本只存一份）；会话保留原 id 与备注。
    /// 重放并核对 version/blob/诊断/树摘要四者一致，否则整包拒绝。
    pub fn import_package(&self, pkg: &Value) -> Result<Value, String> {
        let payload = pkg
            .get("payload")
            .ok_or_else(|| "会话包缺少 payload".to_string())?;
        let claimed_sha = pkg
            .get("sha256")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "会话包缺少 sha256".to_string())?;
        let actual = content_id(&canonical_bytes(payload));
        if claimed_sha != actual {
            return Err(format!(
                "会话包校验失败：声明 {}，实际 {}（包可能已损坏或被篡改）",
                claimed_sha, actual
            ));
        }
        if payload.get("format").and_then(|v| v.as_str()) != Some("frame-lab-session@1") {
            return Err("不支持的会话包格式（需要 frame-lab-session@1）".to_string());
        }
        let version_id = req_str(payload, "version_id")?;
        let blob_id = req_str(payload, "blob_id")?;
        let spec = payload
            .get("spec")
            .ok_or_else(|| "会话包缺少 spec".to_string())?;
        let bytes_hex = req_str(payload, "bytes_hex")?;
        let session_v = payload
            .get("session")
            .ok_or_else(|| "会话包缺少 session".to_string())?;
        let data = unhex(bytes_hex).ok_or_else(|| "bytes_hex 不是合法十六进制".to_string())?;

        // 版本：重新规范化并核对内容 id；已存在则复用，不允许包内版本覆盖本地版本。
        let proto = model::load_protocol(spec)?;
        let normalized = model::protocol_to_json(&proto);
        let computed_vid = content_id(&canonical_bytes(&normalized));
        if computed_vid != version_id {
            return Err(format!(
                "版本不一致：包内声明 {}，按描述计算得到 {}（新版本不能冒充旧版本）",
                version_id, computed_vid
            ));
        }
        let version_existed = self.known_version(&version_id);
        if !version_existed {
            atomic_write_json(
                &self.dir.join("protocols").join(format!("{}.json", version_id)),
                &normalized,
            )?;
        }

        // blob：去重
        let computed_blob = hex(&sha256(&data));
        if computed_blob != blob_id {
            return Err(format!("字节不一致：声明 blob {}，实际 {}", blob_id, computed_blob));
        }
        let blob_existed = self.dir.join("blobs").join(&blob_id).exists();
        if !blob_existed {
            atomic_write_bytes(&self.dir.join("blobs").join(&blob_id), &data)?;
        }

        // 重放诊断与树摘要
        let fresh = parser::parse(&proto, &data);
        let fresh_v = tree::result_to_value(&fresh);
        let stored_session = json_to_session(session_v.clone())?;
        if stored_session.version_id != version_id || stored_session.blob_id != blob_id {
            return Err("会话记录与包内 version/blob 绑定不一致".to_string());
        }
        if fresh_v != stored_session.result {
            return Err(
                "重放诊断/解析树摘要与包内记录不一致，拒绝导入（保证历史会话可确定性重放）"
                    .to_string(),
            );
        }

        // 会话保留原 id；若同 id 已存在则整体拒绝（避免覆盖独立备注的会话）。
        let session_path = self
            .dir
            .join("sessions")
            .join(format!("{}.json", stored_session.id));
        let session_existed = session_path.exists();
        if !session_existed {
            atomic_write_json(&session_path, &session_to_json(&stored_session))?;
        } else {
            let existing = self.load_session(&stored_session.id)?;
            if existing.result != stored_session.result
                || existing.version_id != stored_session.version_id
                || existing.blob_id != stored_session.blob_id
            {
                return Err(format!(
                    "session id {} 已被内容不同的会话占用，拒绝覆盖",
                    stored_session.id
                ));
            }
        }

        Ok(Value::Obj(vec![
            ("session_id".to_string(), Value::Str(stored_session.id)),
            ("version_id".to_string(), Value::Str(version_id.to_string())),
            ("blob_id".to_string(), Value::Str(blob_id.to_string())),
            ("version_reused".to_string(), Value::Bool(version_existed)),
            ("blob_reused".to_string(), Value::Bool(blob_existed)),
            ("session_existed".to_string(), Value::Bool(session_existed)),
            ("status".to_string(), Value::Str(fresh.status.as_str().to_string())),
            ("tree_digest".to_string(), {
                let d = fresh_v.get("tree_digest").and_then(|v| v.as_str()).unwrap_or("");
                Value::Str(d.to_string())
            }),
        ]))
    }

    /// 仅解析（不落库），供编辑字节时实时重算。
    pub fn parse_with(&self, version_id: &str, data: &[u8]) -> Result<Value, String> {
        let (proto, _) = self.load_protocol_version(version_id)?;
        let result = parser::parse(&proto, data);
        Ok(tree::result_to_value(&result))
    }

    pub fn status_of(result: &Value) -> NodeStatus {
        match result.get("status").and_then(|v| v.as_str()) {
            Some("warning") => NodeStatus::Warning,
            Some("error") => NodeStatus::Error,
            _ => NodeStatus::Ok,
        }
    }
}

pub enum BytesInput<'a> {
    Hex(&'a str),
    Data(&'a [u8]),
}

impl<'a> BytesInput<'a> {
    fn into_vec(self) -> Result<Vec<u8>, String> {
        match self {
            BytesInput::Hex(h) => unhex(h).ok_or_else(|| "无法解析十六进制字节流".to_string()),
            BytesInput::Data(d) => Ok(d.to_vec()),
        }
    }
}

fn session_to_json(rec: &SessionRecord) -> Value {
    session_public_json(rec)
}

/// 会话的完整对外 JSON（含重放得到的诊断与解析树）。
pub fn session_public_json(rec: &SessionRecord) -> Value {
    Value::Obj(vec![
        ("id".to_string(), Value::Str(rec.id.clone())),
        ("created_at".to_string(), Value::Int(rec.created_at as i128)),
        ("updated_at".to_string(), Value::Int(rec.updated_at as i128)),
        ("name".to_string(), Value::Str(rec.name.clone())),
        ("note".to_string(), Value::Str(rec.note.clone())),
        ("version_id".to_string(), Value::Str(rec.version_id.clone())),
        ("blob_id".to_string(), Value::Str(rec.blob_id.clone())),
        ("result".to_string(), rec.result.clone()),
    ])
}

fn json_to_session(v: Value) -> Result<SessionRecord, String> {
    let req_s = |key: &str| -> Result<String, String> {
        v.get(key)
            .and_then(|x| x.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| format!("会话记录缺少 {}", key))
    };
    let req_n = |key: &str| -> Result<u64, String> {
        v.get(key)
            .and_then(|x| x.as_i128())
            .map(|n| n as u64)
            .ok_or_else(|| format!("会话记录缺少 {}", key))
    };
    Ok(SessionRecord {
        id: req_s("id")?,
        created_at: req_n("created_at")?,
        updated_at: req_n("updated_at")?,
        name: req_s("name")?,
        note: req_s("note")?,
        version_id: req_s("version_id")?,
        blob_id: req_s("blob_id")?,
        result: v
            .get("result")
            .cloned()
            .ok_or_else(|| "会话记录缺少 result".to_string())?,
    })
}

fn req_str<'a>(v: &'a Value, key: &str) -> Result<&'a str, String> {
    v.get(key)
        .and_then(|x| x.as_str())
        .ok_or_else(|| format!("缺少字段 {}", key))
}

fn is_hex_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f' | b'A'..=b'F'))
}

fn io_err(e: std::io::Error) -> String {
    format!("存储 IO 错误: {}", e)
}

fn atomic_write_json(path: &Path, v: &Value) -> Result<(), String> {
    let bytes = json::stringify_pretty(v).into_bytes();
    atomic_write_bytes(path, &bytes)
}

fn atomic_write_bytes(path: &Path, data: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(io_err)?;
    }
    let tmp = path.with_extra_extension();
    fs::write(&tmp, data).map_err(io_err)?;
    fs::rename(&tmp, path).map_err(io_err)?;
    Ok(())
}

trait ExtraExt {
    fn with_extra_extension(&self) -> PathBuf;
}

impl ExtraExt for Path {
    fn with_extra_extension(&self) -> PathBuf {
        let mut s = self.as_os_str().to_owned();
        s.push(".tmp");
        PathBuf::from(s)
    }
}
