//! 仓库目录持久化：不可变协议版本、内容寻址 blob、可回看会话、导入导出。

use crate::json::{obj as jobj, Json};
use crate::model::ProtocolSpec;
use crate::parser::{parse, ParseReport};
use crate::sha256::sha256_hex;
use crate::validate::validate;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

#[derive(Clone, Debug, PartialEq)]
pub struct ProtocolVersion {
    pub version_id: String,
    pub name: String,
    pub created_at: u64,
    pub spec: ProtocolSpec,
}

impl ProtocolVersion {
    pub fn to_json(&self) -> Json {
        jobj(vec![
            ("version_id", Json::string(&self.version_id)),
            ("name", Json::string(&self.name)),
            ("created_at", Json::from_u64(self.created_at)),
            ("spec", self.spec.to_json()),
        ])
    }
    fn from_json(j: &Json) -> Result<Self, String> {
        Ok(ProtocolVersion {
            version_id: j.get("version_id").and_then(|v| v.as_str()).unwrap_or("").into(),
            name: j.get("name").and_then(|v| v.as_str()).unwrap_or("").into(),
            created_at: j.get("created_at").and_then(|v| v.as_u64()).unwrap_or(0),
            spec: ProtocolSpec::from_json(j.get("spec").ok_or("缺少 spec")?)?,
        })
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Session {
    pub session_id: String,
    pub title: String,
    pub note: String,
    pub version_id: String,
    pub blob_id: String,
    pub report: ParseReport,
    pub tree_digest: String,
    pub created_at: u64,
    pub updated_at: u64,
}

impl Session {
    pub fn to_json(&self) -> Json {
        jobj(vec![
            ("session_id", Json::string(&self.session_id)),
            ("title", Json::string(&self.title)),
            ("note", Json::string(&self.note)),
            ("version_id", Json::string(&self.version_id)),
            ("blob_id", Json::string(&self.blob_id)),
            ("report", self.report.to_json()),
            ("tree_digest", Json::string(&self.tree_digest)),
            ("created_at", Json::from_u64(self.created_at)),
            ("updated_at", Json::from_u64(self.updated_at)),
        ])
    }
    fn from_json(j: &Json) -> Result<Self, String> {
        Ok(Session {
            session_id: j.get("session_id").and_then(|v| v.as_str()).unwrap_or("").into(),
            title: j.get("title").and_then(|v| v.as_str()).unwrap_or("").into(),
            note: j.get("note").and_then(|v| v.as_str()).unwrap_or("").into(),
            version_id: j.get("version_id").and_then(|v| v.as_str()).unwrap_or("").into(),
            blob_id: j.get("blob_id").and_then(|v| v.as_str()).unwrap_or("").into(),
            report: ParseReport::from_json(j.get("report").ok_or("缺少 report")?)?,
            tree_digest: j.get("tree_digest").and_then(|v| v.as_str()).unwrap_or("").into(),
            created_at: j.get("created_at").and_then(|v| v.as_u64()).unwrap_or(0),
            updated_at: j.get("updated_at").and_then(|v| v.as_u64()).unwrap_or(0),
        })
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct SessionBundle {
    pub protocol: ProtocolVersion,
    pub blob_hex: String,
    pub session: Session,
}

impl SessionBundle {
    pub fn to_json(&self) -> Json {
        let pj = self.protocol.to_json();
        let sj = self.session.to_json();
        jobj(vec![
            ("format", Json::string("frame-lab-session/1")),
            ("protocol", pj),
            ("blob_hex", Json::string(&self.blob_hex)),
            ("session", sj),
        ])
    }
    pub fn from_json(j: &Json) -> Result<Self, String> {
        let format = j.get("format").and_then(|v| v.as_str()).unwrap_or("");
        if format != "frame-lab-session/1" {
            return Err(format!("不支持的会话包格式 {}", format));
        }
        Ok(SessionBundle {
            protocol: ProtocolVersion::from_json(j.get("protocol").ok_or("缺少 protocol")?)?,
            blob_hex: j.get("blob_hex").and_then(|v| v.as_str()).unwrap_or("").into(),
            session: Session::from_json(j.get("session").ok_or("缺少 session")?)?,
        })
    }
}

pub struct Store {
    root: PathBuf,
    now: Mutex<Box<dyn Fn() -> u64 + Send + Sync>>,
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl Store {
    pub fn open(root: impl AsRef<Path>) -> std::io::Result<Self> {
        let root = root.as_ref().to_path_buf();
        for d in ["protocols", "blobs", "sessions"] {
            fs::create_dir_all(root.join(d))?;
        }
        Ok(Store {
            root,
            now: Mutex::new(Box::new(now_unix)),
        })
    }

    pub fn set_clock(&self, f: impl Fn() -> u64 + Send + Sync + 'static) {
        *self.now.lock().unwrap() = Box::new(f);
    }

    fn clock(&self) -> u64 {
        (self.now.lock().unwrap())()
    }

    fn protocols_dir(&self) -> PathBuf {
        self.root.join("protocols")
    }
    fn blobs_dir(&self) -> PathBuf {
        self.root.join("blobs")
    }
    fn sessions_dir(&self) -> PathBuf {
        self.root.join("sessions")
    }

    pub fn version_id_of(spec: &ProtocolSpec) -> String {
        sha256_hex(spec.canonical().as_bytes())
    }

    pub fn blob_id_of(bytes: &[u8]) -> String {
        sha256_hex(bytes)
    }

    pub fn save_protocol(&self, spec: &ProtocolSpec) -> Result<ProtocolVersion, String> {
        let errs = validate(spec);
        if !errs.is_empty() {
            return Err(errs.join("; "));
        }
        let version_id = Self::version_id_of(spec);
        let path = self.protocols_dir().join(format!("{}.json", version_id));
        if path.exists() {
            return self.load_protocol(&version_id);
        }
        let v = ProtocolVersion {
            version_id: version_id.clone(),
            name: spec.name.clone(),
            created_at: self.clock(),
            spec: spec.clone(),
        };
        atomic_write_json(&path, &v.to_json())?;
        Ok(v)
    }

    pub fn load_protocol(&self, version_id: &str) -> Result<ProtocolVersion, String> {
        let path = self.protocols_dir().join(format!("{}.json", safe(version_id)?));
        let j = read_json(&path)?;
        ProtocolVersion::from_json(&j)
    }

    pub fn list_protocols(&self) -> Result<Vec<ProtocolVersion>, String> {
        let mut out = Vec::new();
        for e in fs::read_dir(self.protocols_dir()).map_err(io)? {
            let e = e.map_err(io)?;
            if e.path().extension().and_then(|s| s.to_str()) == Some("json") {
                if let Ok(j) = read_json(&e.path()) {
                    if let Ok(v) = ProtocolVersion::from_json(&j) {
                        out.push(v);
                    }
                }
            }
        }
        out.sort_by(|a, b| (a.created_at, &a.version_id).cmp(&(b.created_at, &b.version_id)));
        Ok(out)
    }

    pub fn put_blob(&self, bytes: &[u8]) -> Result<String, String> {
        let id = Self::blob_id_of(bytes);
        let path = self.blobs_dir().join(&id);
        if !path.exists() {
            atomic_write_bytes(&path, bytes)?;
        }
        Ok(id)
    }

    pub fn get_blob(&self, blob_id: &str) -> Result<Vec<u8>, String> {
        let path = self.blobs_dir().join(safe(blob_id)?);
        fs::read(&path).map_err(|e| format!("blob 不存在：{}", e))
    }

    pub fn create_session(
        &self,
        version_id: &str,
        blob_id: &str,
        title: &str,
        note: &str,
    ) -> Result<Session, String> {
        let pv = self.load_protocol(version_id)?;
        let bytes = self.get_blob(blob_id)?;
        let report = parse(&pv.spec, &bytes);
        let t = self.clock();
        let session = Session {
            session_id: new_id("ses"),
            title: title.to_string(),
            note: note.to_string(),
            version_id: version_id.to_string(),
            blob_id: blob_id.to_string(),
            tree_digest: tree_digest(&report),
            report,
            created_at: t,
            updated_at: t,
        };
        self.write_session(&session)?;
        Ok(session)
    }

    pub fn update_note(&self, session_id: &str, note: &str) -> Result<Session, String> {
        let mut s = self.load_session(session_id)?;
        s.note = note.to_string();
        s.updated_at = self.clock();
        self.write_session(&s)?;
        Ok(s)
    }

    fn write_session(&self, s: &Session) -> Result<(), String> {
        let path = self.sessions_dir().join(format!("{}.json", s.session_id));
        atomic_write_json(&path, &s.to_json())
    }

    pub fn load_session(&self, session_id: &str) -> Result<Session, String> {
        let path = self.sessions_dir().join(format!("{}.json", safe(session_id)?));
        let j = read_json(&path)?;
        Session::from_json(&j)
    }

    pub fn list_sessions(&self) -> Result<Vec<Session>, String> {
        let mut out = Vec::new();
        for e in fs::read_dir(self.sessions_dir()).map_err(io)? {
            let e = e.map_err(io)?;
            if e.path().extension().and_then(|s| s.to_str()) == Some("json") {
                if let Ok(j) = read_json(&e.path()) {
                    if let Ok(v) = Session::from_json(&j) {
                        out.push(v);
                    }
                }
            }
        }
        out.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        Ok(out)
    }

    pub fn export_session(&self, session_id: &str) -> Result<SessionBundle, String> {
        let session = self.load_session(session_id)?;
        let protocol = self.load_protocol(&session.version_id)?;
        let bytes = self.get_blob(&session.blob_id)?;
        Ok(SessionBundle {
            protocol,
            blob_hex: crate::encoder::encode_hex(&bytes),
            session,
        })
    }

    pub fn import_bundle(&self, bundle: &SessionBundle) -> Result<Session, String> {
        let canonical_id = Self::version_id_of(&bundle.protocol.spec);
        if canonical_id != bundle.protocol.version_id {
            return Err("协议版本号与描述内容不一致".into());
        }
        let bytes = crate::encoder::decode_hex(&bundle.blob_hex)?;
        if Self::blob_id_of(&bytes) != bundle.session.blob_id {
            return Err("blob 哈希不一致".into());
        }

        let saved_proto = self.save_protocol(&bundle.protocol.spec)?;
        let blob_id = self.put_blob(&bytes)?;

        let report = parse(&saved_proto.spec, &bytes);
        let digest = tree_digest(&report);
        if report != bundle.session.report || digest != bundle.session.tree_digest {
            return Err("重放结果与包内结论不一致".into());
        }

        let mut session = bundle.session.clone();
        session.session_id = new_id("ses");
        session.version_id = saved_proto.version_id.clone();
        session.blob_id = blob_id;
        let t = self.clock();
        session.created_at = t;
        session.updated_at = t;
        self.write_session(&session)?;
        Ok(session)
    }
}

pub fn tree_digest(report: &ParseReport) -> String {
    let mut lines: Vec<String> = Vec::new();
    if let Some(root) = &report.tree {
        walk_digest(root, &mut lines);
    }
    lines.push(format!("outcome={}", report.outcome.as_str()));
    for w in &report.warnings {
        lines.push(format!("warn@{}@{}:{}", w.path, w.offset, w.message));
    }
    if let Some(p) = &report.error_path {
        lines.push(format!(
            "err@{}@{}:{}",
            p,
            report.error_offset.unwrap_or(0),
            report.error_message.as_deref().unwrap_or("")
        ));
    }
    sha256_hex(lines.join("\n").as_bytes())
}

fn walk_digest(n: &crate::parser::Node, lines: &mut Vec<String>) {
    let vi = n.value_int.map(|v| v.to_string()).unwrap_or_default();
    let vh = n.value_hex.clone().unwrap_or_default();
    lines.push(format!(
        "{}#{}[{},{}){} int={} hex={}",
        n.kind,
        n.name,
        n.start,
        n.end,
        n.status.as_str(),
        vi,
        vh
    ));
    for c in &n.children {
        walk_digest(c, lines);
    }
}

fn new_id(prefix: &str) -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(1);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let mut input = Vec::new();
    input.extend_from_slice(&(nanos as u64).to_le_bytes());
    input.extend_from_slice(&seq.to_le_bytes());
    input.extend_from_slice(&std::process::id().to_le_bytes());
    format!("{}_{}", prefix, &sha256_hex(&input)[..16])
}

fn safe(id: &str) -> Result<String, String> {
    if id.len() > 128
        || id.is_empty()
        || !id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err("非法 id".into());
    }
    Ok(id.to_string())
}

fn io(e: std::io::Error) -> String {
    e.to_string()
}

fn read_json(path: &Path) -> Result<Json, String> {
    let s = fs::read_to_string(path).map_err(io)?;
    Json::parse(&s)
}

fn atomic_write_json(path: &Path, value: &Json) -> Result<(), String> {
    let s = value.to_string_pretty();
    atomic_write_bytes(path, s.as_bytes())
}

fn atomic_write_bytes(path: &Path, data: &[u8]) -> Result<(), String> {
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, data).map_err(io)?;
    fs::rename(&tmp, path).map_err(io)
}
