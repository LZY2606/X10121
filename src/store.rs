//! 仓库目录持久化：不可变协议版本、内容寻址 blob、可回看会话。
//!
//! 目录布局：
//! - `data/protocols/<version_id>.json`（不可变，正文含版本元信息）
//! - `data/blobs/<sha256>.bin`（相同字节物理上只存一份）
//! - `data/sessions/<id>.json`（会话、备注与修订事件流）

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

use crate::json::Json;
use crate::parser::ParseResult;
use crate::spec::Protocol;

#[derive(Debug, Clone)]
pub struct ProtocolRecord {
    pub version_id: String,
    pub name: String,
    pub description: String,
    pub source: String,
    pub content_hash: String,
    pub created_at: u64,
    pub protocol: Protocol,
}

impl ProtocolRecord {
    pub fn to_json(&self) -> Json {
        let mut o = Json::obj();
        o.insert("version_id", Json::from_str_value(self.version_id.clone()));
        o.insert("name", Json::from_str_value(self.name.clone()));
        o.insert("description", Json::from_str_value(self.description.clone()));
        o.insert("content_hash", Json::from_str_value(self.content_hash.clone()));
        o.insert("created_at", Json::Int(self.created_at as i64));
        o.insert("spec", self.protocol.to_json());
        o
    }
}

#[derive(Debug, Clone)]
pub struct SessionEvent {
    pub seq: u32,
    pub at: u64,
    pub kind: String,
    /// 字节修改前的十六进制；解析类事件为 null。
    pub old_hex: Option<String>,
    pub new_hex: String,
    pub outcome: String,
    pub tree_digest: String,
    pub recomputed: Vec<String>,
    pub note: Option<String>,
}

impl SessionEvent {
    pub fn to_json_public(&self) -> Json {
        self.to_json()
    }

    fn to_json(&self) -> Json {
        let mut o = Json::obj();
        o.insert("seq", Json::Int(self.seq as i64));
        o.insert("at", Json::Int(self.at as i64));
        o.insert("kind", Json::from_str_value(self.kind.clone()));
        o.insert(
            "old_hex",
            self.old_hex
                .as_ref()
                .map(|s| Json::from_str_value(s.clone()))
                .unwrap_or(Json::Null),
        );
        o.insert("new_hex", Json::from_str_value(self.new_hex.clone()));
        o.insert("outcome", Json::from_str_value(self.outcome.clone()));
        o.insert("tree_digest", Json::from_str_value(self.tree_digest.clone()));
        o.insert(
            "recomputed",
            Json::Array(self.recomputed.iter().map(|s| Json::from_str_value(s.clone())).collect()),
        );
        o.insert(
            "note",
            self.note
                .as_ref()
                .map(|s| Json::from_str_value(s.clone()))
                .unwrap_or(Json::Null),
        );
        o
    }

    fn from_json(j: &Json) -> Option<SessionEvent> {
        Some(SessionEvent {
            seq: j.get("seq")?.as_u64()? as u32,
            at: j.get("at")?.as_u64()?,
            kind: j.get("kind")?.as_str()?.to_string(),
            old_hex: j.get("old_hex")?.as_str().map(|s| s.to_string()),
            new_hex: j.get("new_hex")?.as_str()?.to_string(),
            outcome: j.get("outcome")?.as_str()?.to_string(),
            tree_digest: j.get("tree_digest")?.as_str()?.to_string(),
            recomputed: j
                .get("recomputed")?
                .as_array()?
                .iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect(),
            note: j.get("note")?.as_str().map(|s| s.to_string()),
        })
    }
}

#[derive(Debug, Clone)]
pub struct Session {
    pub id: String,
    pub title: String,
    pub version_id: String,
    pub blob_hash: String,
    pub note: String,
    pub working_hex: String,
    pub created_at: u64,
    pub updated_at: u64,
    pub events: Vec<SessionEvent>,
}

impl Session {
    fn to_json(&self) -> Json {
        let mut o = Json::obj();
        o.insert("id", Json::from_str_value(self.id.clone()));
        o.insert("title", Json::from_str_value(self.title.clone()));
        o.insert("version_id", Json::from_str_value(self.version_id.clone()));
        o.insert("blob_hash", Json::from_str_value(self.blob_hash.clone()));
        o.insert("note", Json::from_str_value(self.note.clone()));
        o.insert("working_hex", Json::from_str_value(self.working_hex.clone()));
        o.insert("created_at", Json::Int(self.created_at as i64));
        o.insert("updated_at", Json::Int(self.updated_at as i64));
        o.insert(
            "events",
            Json::Array(self.events.iter().map(SessionEvent::to_json).collect()),
        );
        o
    }

    fn from_json(j: &Json) -> Option<Session> {
        Some(Session {
            id: j.get("id")?.as_str()?.to_string(),
            title: j.get("title")?.as_str()?.to_string(),
            version_id: j.get("version_id")?.as_str()?.to_string(),
            blob_hash: j.get("blob_hash")?.as_str()?.to_string(),
            note: j.get("note")?.as_str()?.to_string(),
            working_hex: j.get("working_hex")?.as_str()?.to_string(),
            created_at: j.get("created_at")?.as_u64()?,
            updated_at: j.get("updated_at")?.as_u64()?,
            events: j
                .get("events")?
                .as_array()?
                .iter()
                .filter_map(SessionEvent::from_json)
                .collect(),
        })
    }
}

pub struct Store {
    root: PathBuf,
    inner: Mutex<Inner>,
}

struct Inner {
    protocols: BTreeMap<String, ProtocolRecord>,
    blobs: BTreeMap<String, Vec<u8>>,
    sessions: BTreeMap<String, Session>,
    session_seq: u64,
}

impl Store {
    pub fn open(root: impl Into<PathBuf>) -> std::io::Result<Self> {
        let root = root.into();
        fs::create_dir_all(root.join("protocols"))?;
        fs::create_dir_all(root.join("blobs"))?;
        fs::create_dir_all(root.join("sessions"))?;
        let mut inner = Inner {
            protocols: BTreeMap::new(),
            blobs: BTreeMap::new(),
            sessions: BTreeMap::new(),
            session_seq: 0,
        };

        for entry in fs::read_dir(root.join("protocols"))? {
            let path = entry?.path();
            if path.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }
            let text = fs::read_to_string(&path)?;
            let json = crate::json::parse(&text)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
            if let Some(record) = record_from_json(&json, &text) {
                inner.protocols.insert(record.version_id.clone(), record);
            }
        }

        for entry in fs::read_dir(root.join("blobs"))? {
            let path = entry?.path();
            let hash = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or_default()
                .to_string();
            let bytes = fs::read(&path)?;
            inner.blobs.insert(hash, bytes);
        }

        for entry in fs::read_dir(root.join("sessions"))? {
            let path = entry?.path();
            if path.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }
            let text = fs::read_to_string(&path)?;
            let json = crate::json::parse(&text)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
            if let Some(session) = Session::from_json(&json) {
                let seq = session
                    .id
                    .trim_start_matches("s")
                    .parse::<u64>()
                    .unwrap_or(0);
                inner.session_seq = inner.session_seq.max(seq);
                inner.sessions.insert(session.id.clone(), session);
            }
        }

        Ok(Store { root, inner: Mutex::new(inner) })
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().expect("仓储锁中毒")
    }

    /// 保存协议描述；同内容返回既有不可变版本（幂等）。
    pub fn save_protocol(&self, source: &str, now: u64) -> Result<ProtocolRecord, String> {
        let protocol = crate::spec::compile(source).map_err(|errs| format_errors(&errs))?;
        let version_id = protocol.version_id();
        let mut inner = self.lock();
        if let Some(existing) = inner.protocols.get(&version_id) {
            return Ok(existing.clone());
        }
        let record = ProtocolRecord {
            version_id: version_id.clone(),
            name: protocol.name.clone(),
            description: protocol.description.clone(),
            source: source.trim().to_string(),
            content_hash: protocol.content_hash(),
            created_at: now,
            protocol,
        };
        let path = self.root.join("protocols").join(format!("{version_id}.json"));
        atomic_write_json(&path, &record.to_json()).map_err(|e| e.to_string())?;
        inner.protocols.insert(version_id, record.clone());
        Ok(record)
    }

    pub fn list_protocols(&self) -> Vec<ProtocolRecord> {
        self.lock()
            .protocols
            .values()
            .map(|r| {
                let mut r = r.clone();
                r.source = String::new();
                r
            })
            .collect()
    }

    pub fn get_protocol(&self, version_id: &str) -> Option<ProtocolRecord> {
        self.lock().protocols.get(version_id).cloned()
    }

    pub fn latest_protocol(&self) -> Option<ProtocolRecord> {
        self.lock()
            .protocols
            .values()
            .max_by_key(|r| r.created_at)
            .cloned()
    }

    /// 内容寻址写入：相同字节复用同一 blob，返回 sha256。
    pub fn put_blob(&self, data: &[u8]) -> Result<String, std::io::Error> {
        let hash = crate::hash::hex_encode(&crate::hash::sha256(data));
        let mut inner = self.lock();
        if !inner.blobs.contains_key(&hash) {
            let path = self.root.join("blobs").join(format!("{hash}.bin"));
            atomic_write_bytes(&path, data)?;
            inner.blobs.insert(hash.clone(), data.to_vec());
        }
        Ok(hash)
    }

    pub fn get_blob(&self, hash: &str) -> Option<Vec<u8>> {
        self.lock().blobs.get(hash).cloned()
    }

    pub fn blob_exists(&self, hash: &str) -> bool {
        self.lock().blobs.contains_key(hash)
    }

    pub fn create_session(
        &self,
        title: &str,
        version_id: &str,
        blob_hash: &str,
        working_hex: &str,
        first: &ParseResult,
        note: &str,
        now: u64,
    ) -> Result<Session, String> {
        let mut inner = self.lock();
        if !inner.protocols.contains_key(version_id) {
            return Err(format!("协议版本 `{version_id}` 不存在"));
        }
        if !inner.blobs.contains_key(blob_hash) {
            return Err(format!("blob `{blob_hash}` 尚未导入"));
        }
        inner.session_seq += 1;
        let id = format!("s{:04}", inner.session_seq);
        let session = Session {
            id: id.clone(),
            title: title.to_string(),
            version_id: version_id.to_string(),
            blob_hash: blob_hash.to_string(),
            note: note.to_string(),
            working_hex: working_hex.to_string(),
            created_at: now,
            updated_at: now,
            events: vec![SessionEvent {
                seq: 1,
                at: now,
                kind: "create".to_string(),
                old_hex: None,
                new_hex: working_hex.to_string(),
                outcome: outcome_label(first).to_string(),
                tree_digest: first.tree_digest(),
                recomputed: Vec::new(),
                note: None,
            }],
        };
        let path = self.root.join("sessions").join(format!("{id}.json"));
        atomic_write_json(&path, &session.to_json())
            .map_err(|e| format!("保存会话失败：{e}"))?;
        inner.sessions.insert(id, session.clone());
        Ok(session)
    }

    pub fn list_sessions(&self) -> Vec<Session> {
        self.lock().sessions.values().cloned().collect()
    }

    pub fn get_session(&self, id: &str) -> Option<Session> {
        self.lock().sessions.get(id).cloned()
    }

    pub fn update_note(&self, id: &str, note: &str, now: u64) -> Result<Session, String> {
        self.mutate_session(id, |s| {
            s.note = note.to_string();
            s.updated_at = now;
        })
    }

    /// 记录一次字节修订：工作副本改变，事件流中留下重算节点与新摘要。
    pub fn record_byte_edit(
        &self,
        id: &str,
        new_hex: &str,
        result: &ParseResult,
        recomputed: &[String],
        now: u64,
    ) -> Result<Session, String> {
        self.mutate_session(id, |s| {
            let seq = s.events.last().map(|e| e.seq + 1).unwrap_or(1);
            let old_hex = std::mem::take(&mut s.working_hex);
            s.working_hex = new_hex.to_string();
            s.updated_at = now;
            s.events.push(SessionEvent {
                seq,
                at: now,
                kind: "byte_edit".to_string(),
                old_hex: Some(old_hex),
                new_hex: new_hex.to_string(),
                outcome: outcome_label(result).to_string(),
                tree_digest: result.tree_digest(),
                recomputed: recomputed.to_vec(),
                note: None,
            });
        })
    }

    pub fn record_note_event(&self, id: &str, note: &str, now: u64) -> Result<Session, String> {
        self.mutate_session(id, |s| {
            let seq = s.events.last().map(|e| e.seq + 1).unwrap_or(1);
            let hex = s.working_hex.clone();
            s.note = note.to_string();
            s.updated_at = now;
            s.events.push(SessionEvent {
                seq,
                at: now,
                kind: "note".to_string(),
                old_hex: None,
                new_hex: hex,
                outcome: String::new(),
                tree_digest: String::new(),
                recomputed: Vec::new(),
                note: Some(note.to_string()),
            });
        })
    }

    pub fn delete_session(&self, id: &str) -> Result<(), String> {
        let mut inner = self.lock();
        if inner.sessions.remove(id).is_none() {
            return Err(format!("会话 `{id}` 不存在"));
        }
        let path = self.root.join("sessions").join(format!("{id}.json"));
        let _ = fs::remove_file(path);
        Ok(())
    }

    fn mutate_session<F: FnOnce(&mut Session)>(&self, id: &str, f: F) -> Result<Session, String> {
        let mut inner = self.lock();
        let session = inner
            .sessions
            .get_mut(id)
            .ok_or_else(|| format!("会话 `{id}` 不存在"))?;
        f(session);
        let path = self.root.join("sessions").join(format!("{id}.json"));
        atomic_write_json(&path, &session.to_json()).map_err(|e| format!("保存会话失败：{e}"))?;
        Ok(session.clone())
    }

    /// 用创建时绑定的版本重放工作副本：新版本永远不会改变旧结论。
    pub fn replay_session(&self, id: &str) -> Result<Replay, String> {
        let inner = self.lock();
        let session = inner
            .sessions
            .get(id)
            .cloned()
            .ok_or_else(|| format!("会话 `{id}` 不存在"))?;
        let record = inner
            .protocols
            .get(&session.version_id)
            .cloned()
            .ok_or_else(|| format!("会话绑定的版本 `{}` 已丢失", session.version_id))?;
        let bytes = crate::bytes::parse_hex(&session.working_hex)
            .map_err(|e| format!("会话工作副本不是合法十六进制：{e}"))?;
        let result = crate::parser::parse(&record.protocol, &bytes);
        Ok(Replay { session, record, result })
    }

    /// 导出确定性会话包：协议规范化文本 + blob 字节 + 会话记录 + 当前诊断摘要。
    pub fn export_bundle(&self, id: &str) -> Result<String, String> {
        let replay = self.replay_session(id)?;
        let bytes = self
            .get_blob(&replay.session.blob_hash)
            .ok_or_else(|| "原始 blob 已丢失".to_string())?;
        let mut bundle = Json::obj();
        bundle.insert("bundle_type", Json::from_str_value("frame-lab-session"));
        bundle.insert("bundle_version", Json::Int(1));
        bundle.insert("session", replay.session.to_json());
        bundle.insert(
            "protocol",
            protocol_export_json(&replay.record, &replay.record.protocol),
        );
        bundle.insert("blob_hex", Json::from_str_value(crate::bytes::to_hex(&bytes)));
        let mut snap = Json::obj();
        snap.insert("outcome", Json::from_str_value(outcome_label(&replay.result)));
        snap.insert("tree_digest", Json::from_str_value(replay.result.tree_digest()));
        snap.insert("consumed", Json::Int(replay.result.consumed as i64));
        snap.insert("input_len", Json::Int(replay.result.input_len as i64));
        bundle.insert("snapshot", snap);
        Ok(bundle.stringify())
    }

    pub fn import_bundle(&self, text: &str, now: u64) -> Result<ImportReport, String> {
        let json = crate::json::parse(text).map_err(|e| format!("会话包不是合法 JSON：{e}"))?;
        if json.get("bundle_type").and_then(|v| v.as_str()) != Some("frame-lab-session") {
            return Err("不是 frame-lab-session 会话包".to_string());
        }
        let session_json = json
            .get("session")
            .ok_or_else(|| "会话包缺少 session".to_string())?;
        let mut session =
            Session::from_json(session_json).ok_or_else(|| "session 内容损坏".to_string())?;
        let protocol_json = json
            .get("protocol")
            .and_then(|p| p.get("spec"))
            .ok_or_else(|| "会话包缺少 protocol.spec".to_string())?;
        let canonical = protocol_json.stringify();
        let protocol =
            crate::spec::compile(&canonical).map_err(|errs| format_errors(&errs))?;
        let blob_hex = json
            .get("blob_hex")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "会话包缺少 blob_hex".to_string())?;
        let blob = crate::bytes::parse_hex(blob_hex)?;

        let record = self.save_protocol(&canonical, now)?;
        if record.version_id != session.version_id {
            return Err(format!(
                "协议内容与版本标识不一致：包内声明 {}，实际编译为 {}",
                session.version_id, record.version_id
            ));
        }
        let blob_hash = self.put_blob(&blob).map_err(|e| format!("写入 blob 失败：{e}"))?;
        if blob_hash != session.blob_hash {
            return Err(format!(
                "blob 内容与摘要不一致：包内声明 {}，实际为 {blob_hash}",
                session.blob_hash
            ));
        }

        let working = crate::bytes::parse_hex(&session.working_hex)
            .map_err(|e| format!("工作副本十六进制损坏：{e}"))?;
        let result = crate::parser::parse(&protocol, &working);
        let digest = result.tree_digest();
        let expected = json
            .get("snapshot")
            .and_then(|s| s.get("tree_digest"))
            .and_then(|v| v.as_str())
            .unwrap_or(&digest);
        if expected != digest {
            return Err(format!(
                "导入后解析树摘要不一致：包内 {expected}，重放 {digest}"
            ));
        }

        {
            let inner = self.lock();
            if let Some(existing) = inner.sessions.get(&session.id) {
                if existing.to_json().stringify() != session.to_json().stringify() {
                    return Err(format!("会话 id `{}` 已被不同内容占用", session.id));
                }
                return Ok(ImportReport {
                    session_id: session.id,
                    reused_session: true,
                    version_id: record.version_id,
                    blob_hash,
                    tree_digest: digest,
                });
            }
        }

        if session.created_at == 0 {
            session.created_at = now;
        }
        session.updated_at = session.updated_at.max(now).max(session.created_at);
        let path = self.root.join("sessions").join(format!("{}.json", session.id));
        atomic_write_json(&path, &session.to_json()).map_err(|e| format!("写入会话失败：{e}"))?;
        let id = session.id.clone();
        let mut inner = self.lock();
        let seq = id.trim_start_matches('s').parse::<u64>().unwrap_or(0);
        inner.session_seq = inner.session_seq.max(seq);
        inner.sessions.insert(id.clone(), session);
        Ok(ImportReport {
            session_id: id,
            reused_session: false,
            version_id: record.version_id,
            blob_hash,
            tree_digest: digest,
        })
    }
}

#[derive(Debug)]
pub struct ImportReport {
    pub session_id: String,
    pub reused_session: bool,
    pub version_id: String,
    pub blob_hash: String,
    pub tree_digest: String,
}

fn protocol_export_json(record: &ProtocolRecord, protocol: &Protocol) -> Json {
    let mut o = Json::obj();
    o.insert("version_id", Json::from_str_value(record.version_id.clone()));
    o.insert("content_hash", Json::from_str_value(record.content_hash.clone()));
    o.insert("spec", protocol.to_json());
    o
}

fn format_errors(errs: &[crate::spec::CompileError]) -> String {
    errs.iter()
        .map(|e| format!("[{}] {}", e.path, e.message))
        .collect::<Vec<_>>()
        .join("；")
}

pub struct Replay {
    pub session: Session,
    pub record: ProtocolRecord,
    pub result: ParseResult,
}

fn outcome_label(result: &ParseResult) -> &'static str {
    match result.outcome {
        crate::parser::Outcome::Complete => "complete",
        crate::parser::Outcome::Incomplete => "incomplete",
        crate::parser::Outcome::Error => "error",
    }
}

fn record_from_json(json: &Json, source: &str) -> Option<ProtocolRecord> {
    let spec_json = json.get("spec")?;
    let protocol = crate::spec::compile(&spec_json.stringify()).ok()?;
    Some(ProtocolRecord {
        version_id: json.get("version_id")?.as_str()?.to_string(),
        name: json.get("name")?.as_str()?.to_string(),
        description: json.get("description")?.as_str()?.to_string(),
        source: source.to_string(),
        content_hash: json.get("content_hash")?.as_str()?.to_string(),
        created_at: json.get("created_at")?.as_u64()?,
        protocol,
    })
}

pub fn atomic_write_json(path: &Path, value: &Json) -> std::io::Result<()> {
    atomic_write_bytes(path, value.stringify_pretty().as_bytes())
}

pub fn atomic_write_bytes(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, bytes)?;
    fs::rename(&tmp, path)
}
