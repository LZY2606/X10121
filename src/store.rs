//! 持久化存储：协议不可变版本、内容寻址 blob、会话与备注、导出/导入包。
//! 全部状态以 JSON/二进制文件保存在仓库目录下的 `data/` 中，启动时载入。
use crate::parser::{self, ParseOutcome, TreeNode};
use crate::protocol::Protocol;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn hash16(data: &[u8]) -> String {
    parser::sha256_hex(data)[..16].to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProtocolVersion {
    /// 内容寻址 id：`pv_<sha256(content)[:16]>`，导出/导入后保持稳定。
    pub id: String,
    pub name: String,
    pub version: u32,
    pub content: serde_json::Value,
    pub hash: String,
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BlobMeta {
    /// 内容寻址 id：完整 sha256 hex。相同样本再次导入指向同一 blob。
    pub id: String,
    pub len: usize,
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Note {
    pub id: String,
    pub text: String,
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ParseRecord {
    pub blob_id: String,
    pub outcome: ParseOutcome,
    pub tree_digest: Option<String>,
    pub at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Session {
    pub id: String,
    /// 创建时绑定的协议版本 id；历史会话始终按该版本重放。
    pub protocol_id: String,
    pub blob_id: String,
    pub created_at: u64,
    #[serde(default)]
    pub notes: Vec<Note>,
    #[serde(default)]
    pub history: Vec<ParseRecord>,
}

impl Session {
    pub fn latest(&self) -> Option<&ParseRecord> {
        self.history.last()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportPackage {
    pub format: String,
    pub format_version: u32,
    pub protocol: ProtocolVersion,
    pub blob_hex: String,
    pub session: Session,
    pub tree_digest: Option<String>,
    /// 对上述全部字段规范化 JSON 的 sha256；导入时校验。
    pub digest: String,
}

pub const EXPORT_FORMAT: &str = "frame-lab-session";

pub struct Store {
    dir: PathBuf,
    pub protocols: BTreeMap<String, ProtocolVersion>,
    pub blobs: BTreeMap<String, BlobMeta>,
    pub sessions: BTreeMap<String, Session>,
}

impl Store {
    pub fn open(dir: &Path) -> io::Result<Store> {
        let mut store = Store {
            dir: dir.to_path_buf(),
            protocols: BTreeMap::new(),
            blobs: BTreeMap::new(),
            sessions: BTreeMap::new(),
        };
        for sub in ["blobs", "protocols", "sessions"] {
            fs::create_dir_all(dir.join(sub))?;
        }
        for entry in fs::read_dir(dir.join("protocols"))? {
            let path = entry?.path();
            if path.extension().and_then(|e| e.to_str()) == Some("json") {
                let pv: ProtocolVersion = serde_json::from_slice(&fs::read(&path)?)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                store.protocols.insert(pv.id.clone(), pv);
            }
        }
        for entry in fs::read_dir(dir.join("blobs"))? {
            let path = entry?.path();
            if path.extension().and_then(|e| e.to_str()) == Some("bin") {
                let bytes = fs::read(&path)?;
                let id = parser::sha256_hex(&bytes);
                store.blobs.insert(
                    id.clone(),
                    BlobMeta { id, len: bytes.len(), created_at: 0 },
                );
            }
        }
        for entry in fs::read_dir(dir.join("sessions"))? {
            let path = entry?.path();
            if path.extension().and_then(|e| e.to_str()) == Some("json") {
                let s: Session = serde_json::from_slice(&fs::read(&path)?)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                store.sessions.insert(s.id.clone(), s);
            }
        }
        Ok(store)
    }

    fn persist_protocol(&self, pv: &ProtocolVersion) -> Result<(), String> {
        write_json(&self.dir.join("protocols").join(format!("{}.json", pv.id)), pv)
    }

    fn persist_session(&self, s: &Session) -> Result<(), String> {
        write_json(&self.dir.join("sessions").join(format!("{}.json", s.id)), s)
    }

    fn persist_blob(&self, id: &str, bytes: &[u8]) -> Result<(), String> {
        fs::write(self.dir.join("blobs").join(format!("{id}.bin")), bytes)
            .map_err(|e| format!("write blob: {e}"))
    }

    /// 保存协议的一个新的不可变版本。已存在的版本永不修改。
    pub fn add_protocol(
        &mut self,
        name: &str,
        content: serde_json::Value,
    ) -> Result<ProtocolVersion, String> {
        let canonical = serde_json::to_vec(&content).map_err(|e| e.to_string())?;
        let hash = parser::sha256_hex(&canonical);
        // 内容必须能解析为合法协议描述
        let _: Protocol =
            serde_json::from_value(content.clone()).map_err(|e| format!("invalid protocol: {e}"))?;
        let id = format!("pv_{}", &hash[..16]);
        if let Some(existing) = self.protocols.get(&id) {
            return Ok(existing.clone()); // 内容寻址：同内容即同版本
        }
        let version = self
            .protocols
            .values()
            .filter(|p| p.name == name)
            .map(|p| p.version)
            .max()
            .unwrap_or(0)
            + 1;
        let pv = ProtocolVersion {
            id,
            name: name.to_string(),
            version,
            content,
            hash,
            created_at: now_millis(),
        };
        self.persist_protocol(&pv)?;
        self.protocols.insert(pv.id.clone(), pv.clone());
        Ok(pv)
    }

    /// 导入样本；相同字节流指向已有 blob。
    pub fn add_blob(&mut self, bytes: &[u8]) -> (String, bool) {
        let id = parser::sha256_hex(bytes);
        if self.blobs.contains_key(&id) {
            return (id, true);
        }
        let meta = BlobMeta { id: id.clone(), len: bytes.len(), created_at: now_millis() };
        let _ = self.persist_blob(&id, bytes);
        self.blobs.insert(id.clone(), meta);
        (id, false)
    }

    pub fn blob_bytes(&self, id: &str) -> Option<Vec<u8>> {
        fs::read(self.dir.join("blobs").join(format!("{id}.bin"))).ok()
    }

    pub fn protocol_def(&self, id: &str) -> Result<Protocol, String> {
        let pv = self
            .protocols
            .get(id)
            .ok_or_else(|| format!("unknown protocol version '{id}'"))?;
        serde_json::from_value(pv.content.clone()).map_err(|e| format!("bad protocol: {e}"))
    }

    fn run_parse(&self, protocol_id: &str, blob_id: &str) -> Result<ParseRecord, String> {
        let proto = self.protocol_def(protocol_id)?;
        let bytes = self
            .blob_bytes(blob_id)
            .ok_or_else(|| format!("unknown blob '{blob_id}'"))?;
        let outcome = parser::parse(&proto, &bytes);
        let tree_digest = match &outcome {
            ParseOutcome::Ok { tree, .. } => Some(parser::tree_digest(tree)),
            _ => None,
        };
        Ok(ParseRecord {
            blob_id: blob_id.to_string(),
            outcome,
            tree_digest,
            at: now_millis(),
        })
    }

    /// 创建会话：绑定创建时的协议版本，立即解析并存档。
    pub fn create_session(&mut self, protocol_id: &str, blob_id: &str) -> Result<Session, String> {
        let record = self.run_parse(protocol_id, blob_id)?;
        let id = format!(
            "se_{}",
            hash16(
                format!("{protocol_id}|{blob_id}|{}|{}", now_millis(), self.sessions.len()).as_bytes()
            )
        );
        let session = Session {
            id,
            protocol_id: protocol_id.to_string(),
            blob_id: blob_id.to_string(),
            created_at: now_millis(),
            notes: Vec::new(),
            history: vec![record],
        };
        self.persist_session(&session)?;
        self.sessions.insert(session.id.clone(), session.clone());
        Ok(session)
    }

    /// 改动字节后重新解析：新字节成为新 blob，标记被重新计算的树节点。
    pub fn update_session_bytes(&mut self, session_id: &str, bytes: &[u8]) -> Result<Session, String> {
        let (blob_id, _) = self.add_blob(bytes);
        let mut record = self.run_parse_for(session_id, &blob_id)?;
        let mut session = self
            .sessions
            .get(session_id)
            .cloned()
            .ok_or_else(|| format!("unknown session '{session_id}'"))?;
        // 与上一次成功解析的树对比，标记重新计算的节点
        let old_tree = session.latest().and_then(|r| match &r.outcome {
            ParseOutcome::Ok { tree, .. } => Some(tree.clone()),
            _ => None,
        });
        if let (ParseOutcome::Ok { tree: new_tree, .. }, Some(old_tree)) =
            (&mut record.outcome, old_tree)
        {
            parser::mark_recomputed(new_tree, Some(&old_tree));
        }
        session.blob_id = blob_id;
        session.history.push(record);
        self.persist_session(&session)?;
        self.sessions.insert(session.id.clone(), session.clone());
        Ok(session)
    }

    fn run_parse_for(&self, session_id: &str, blob_id: &str) -> Result<ParseRecord, String> {
        let session = self
            .sessions
            .get(session_id)
            .ok_or_else(|| format!("unknown session '{session_id}'"))?;
        // 始终按会话创建时绑定的版本重放
        self.run_parse(&session.protocol_id, blob_id)
    }

    pub fn add_note(&mut self, session_id: &str, text: &str) -> Result<Note, String> {
        let mut session = self
            .sessions
            .get(session_id)
            .cloned()
            .ok_or_else(|| format!("unknown session '{session_id}'"))?;
        let note = Note {
            id: format!("nt_{}", hash16(format!("{session_id}|{}|{text}", now_millis()).as_bytes())),
            text: text.to_string(),
            created_at: now_millis(),
        };
        session.notes.push(note.clone());
        self.persist_session(&session)?;
        self.sessions.insert(session.id.clone(), session);
        Ok(note)
    }

    pub fn export_session(&self, session_id: &str) -> Result<ExportPackage, String> {
        let session = self
            .sessions
            .get(session_id)
            .ok_or_else(|| format!("unknown session '{session_id}'"))?;
        let protocol = self
            .protocols
            .get(&session.protocol_id)
            .ok_or_else(|| "session references missing protocol".to_string())?;
        let bytes = self
            .blob_bytes(&session.blob_id)
            .ok_or_else(|| "session references missing blob".to_string())?;
        let tree_digest = session.latest().and_then(|r| r.tree_digest.clone());
        let mut pkg = ExportPackage {
            format: EXPORT_FORMAT.to_string(),
            format_version: 1,
            protocol: protocol.clone(),
            blob_hex: parser::hex_encode(&bytes),
            session: session.clone(),
            tree_digest,
            digest: String::new(),
        };
        pkg.digest = package_digest(&pkg);
        Ok(pkg)
    }

    /// 导入会话包：校验摘要，落地协议版本与 blob，按包内版本重新解析并核对诊断与树摘要。
    pub fn import_session(&mut self, pkg: &ExportPackage) -> Result<String, String> {
        if pkg.format != EXPORT_FORMAT {
            return Err(format!("unknown export format '{}'", pkg.format));
        }
        if pkg.digest != package_digest(pkg) {
            return Err("export package digest mismatch".to_string());
        }
        let bytes = parser::hex_decode(&pkg.blob_hex)?;
        if parser::sha256_hex(&bytes) != pkg.session.blob_id {
            return Err("blob bytes do not match session blob id".to_string());
        }
        // 协议版本：同 id 必须同内容（不可变性）
        match self.protocols.get(&pkg.protocol.id) {
            Some(existing) if existing.hash != pkg.protocol.hash => {
                return Err("protocol id collision with different content".to_string())
            }
            None => {
                self.persist_protocol(&pkg.protocol)?;
                self.protocols.insert(pkg.protocol.id.clone(), pkg.protocol.clone());
            }
            _ => {}
        }
        self.add_blob(&bytes);
        // 用包内绑定的版本重新解析，核对诊断与树摘要
        let record = self.run_parse(&pkg.protocol.id, &pkg.session.blob_id)?;
        let packaged = pkg
            .session
            .latest()
            .ok_or_else(|| "export package has empty history".to_string())?;
        if !same_diagnostic(&record.outcome, &packaged.outcome) {
            return Err("re-parse diagnostics differ from exported session".to_string());
        }
        if record.tree_digest != pkg.tree_digest {
            return Err("re-parse tree digest differs from exported session".to_string());
        }
        // 幂等：同 id 会话已存在且一致则直接复用
        if let Some(existing) = self.sessions.get(&pkg.session.id) {
            if existing.latest().and_then(|r| r.tree_digest.clone()) == pkg.tree_digest {
                return Ok(existing.id.clone());
            }
            return Err("session id collision with different content".to_string());
        }
        let mut session = pkg.session.clone();
        if let Some(last) = session.history.last_mut() {
            *last = record; // 以本机重放结果为准（内容一致，时间戳为本机）
        }
        self.persist_session(&session)?;
        self.sessions.insert(session.id.clone(), session.clone());
        Ok(session.id)
    }
}

fn same_diagnostic(a: &ParseOutcome, b: &ParseOutcome) -> bool {
    use ParseOutcome::*;
    match (a, b) {
        (Ok { .. }, Ok { .. }) => true,
        (
            Incomplete { path: p1, needed_at_least: n1 },
            Incomplete { path: p2, needed_at_least: n2 },
        ) => p1 == p2 && n1 == n2,
        (
            Violation { path: p1, offset: o1, message: m1 },
            Violation { path: p2, offset: o2, message: m2 },
        ) => p1 == p2 && o1 == o2 && m1 == m2,
        _ => false,
    }
}

fn package_digest(pkg: &ExportPackage) -> String {
    #[derive(Serialize)]
    struct Core<'a> {
        format: &'a str,
        format_version: u32,
        protocol: &'a ProtocolVersion,
        blob_hex: &'a str,
        session: &'a Session,
        tree_digest: &'a Option<String>,
    }
    let core = Core {
        format: &pkg.format,
        format_version: pkg.format_version,
        protocol: &pkg.protocol,
        blob_hex: &pkg.blob_hex,
        session: &pkg.session,
        tree_digest: &pkg.tree_digest,
    };
    parser::sha256_hex(&serde_json::to_vec(&core).expect("serialize export core"))
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    let data = serde_json::to_vec_pretty(value).map_err(|e| e.to_string())?;
    fs::write(path, data).map_err(|e| format!("write {}: {e}", path.display()))
}
