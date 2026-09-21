use crate::error::{LabError, LabResult};
use crate::hex;
use crate::parser::{self, Outcome};
use crate::protocol::{canonical_bytes, Protocol};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

const FORMAT_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionRec {
    pub version_id: String,
    pub protocol_id: String,
    pub created_at: String,
    pub spec: Protocol,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionRec {
    pub session_id: String,
    pub protocol_id: String,
    pub version_id: String,
    pub blob_hash: String,
    pub note: String,
    pub created_at: String,
    /// 创建时的结果快照（仅保存确定性内容）。
    pub snapshot: SavedOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SavedOutcome {
    pub status: String,
    pub consumed: usize,
    pub tree_digest: String,
    pub diagnostics: Vec<parser::Diagnostic>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SessionView {
    #[serde(flatten)]
    pub rec: SessionRec,
    pub length: usize,
}

#[derive(Debug, Serialize, Deserialize)]
struct VersionFile {
    version: VersionRec,
}

#[derive(Debug, Serialize, Deserialize)]
struct SessionFile {
    session: SessionRec,
}

#[derive(Debug, Serialize, Deserialize)]
struct Index {
    protocols: BTreeMap<String, Vec<String>>,
    sessions: BTreeMap<String, ()>,
}

#[derive(Serialize)]
pub struct ExportBundle {
    pub format: String,
    pub format_version: u32,
    pub exported_at: String,
    pub protocol: VersionRec,
    pub blob_hex: String,
    pub blob_hash: String,
    pub session: SessionRec,
}

#[derive(Deserialize)]
pub struct ImportBundle {
    pub format: String,
    pub format_version: u32,
    pub protocol: VersionRec,
    pub blob_hex: String,
    pub blob_hash: String,
    pub session: SessionRec,
}

pub struct Store {
    root: PathBuf,
    inner: Mutex<()>,
}

impl Store {
    pub fn open(root: impl AsRef<Path>) -> LabResult<Self> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(root.join("protocols"))?;
        fs::create_dir_all(root.join("versions"))?;
        fs::create_dir_all(root.join("blobs"))?;
        fs::create_dir_all(root.join("sessions"))?;
        if !root.join("index.json").exists() {
            let index = Index {
                protocols: BTreeMap::new(),
                sessions: BTreeMap::new(),
            };
            write_json(&root.join("index.json"), &index)?;
        }
        Ok(Store {
            root,
            inner: Mutex::new(()),
        })
    }

    fn lock(&self) -> MutexGuard<'_, ()> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn read_index(&self) -> LabResult<Index> {
        read_json(&self.root.join("index.json"))
    }

    fn write_index(&self, index: &Index) -> LabResult<()> {
        write_json(&self.root.join("index.json"), index)
    }

    /// 保存协议的一个不可变版本；相同规范哈希复用已有版本。
    pub fn save_version(&self, protocol: &Protocol) -> LabResult<VersionRec> {
        let _g = self.lock();
        self.save_version_locked(protocol)
    }

    fn save_version_locked(&self, protocol: &Protocol) -> LabResult<VersionRec> {
        protocol.validate()?;
        let canonical = canonical_bytes(protocol)?;
        let hash = hex::encode(&crate::sha256::digest(&canonical));
        let protocol_id = protocol_id_for(&protocol.name);
        let version_id = hash[..16].to_string();
        let path = self
            .root
            .join("versions")
            .join(format!("{version_id}.json"));
        let rec = if path.exists() {
            let file: VersionFile = read_json(&path)?;
            file.version
        } else {
            let rec = VersionRec {
                version_id: version_id.clone(),
                protocol_id: protocol_id.clone(),
                created_at: now_iso(),
                spec: protocol.clone(),
            };
            write_json(&path, &VersionFile { version: rec.clone() })?;
            let mut index = self.read_index()?;
            let versions = index
                .protocols
                .entry(protocol_id)
                .or_default();
            if !versions.contains(&version_id) {
                versions.push(version_id);
                versions.sort();
            }
            self.write_index(&index)?;
            rec
        };
        Ok(rec)
    }

    pub fn list_protocols(&self) -> LabResult<BTreeMap<String, Vec<VersionRec>>> {
        let _g = self.lock();
        let index = self.read_index()?;
        let mut out = BTreeMap::new();
        for (pid, version_ids) in index.protocols {
            let mut recs = Vec::new();
            for vid in version_ids {
                recs.push(self.version_by_id(&vid)?);
            }
            out.insert(pid, recs);
        }
        Ok(out)
    }

    pub fn version_by_id(&self, version_id: &str) -> LabResult<VersionRec> {
        let path = self
            .root
            .join("versions")
            .join(format!("{version_id}.json"));
        if !path.exists() {
            return Err(LabError::new(format!("版本 {version_id} 不存在")));
        }
        let file: VersionFile = read_json(&path)?;
        Ok(file.version)
    }

    /// 内容寻址：相同字节始终指向同一 blob。
    pub fn put_blob(&self, data: &[u8]) -> LabResult<String> {
        let _g = self.lock();
        self.put_blob_locked(data)
    }

    fn put_blob_locked(&self, data: &[u8]) -> LabResult<String> {
        let hash = blob_hash(data);
        let dir = self.root.join("blobs").join(&hash[0..2]);
        fs::create_dir_all(&dir)?;
        let path = dir.join(format!("{hash}.bin"));
        if !path.exists() {
            atomic_write(&path, data)?;
        }
        Ok(hash)
    }

    pub fn get_blob(&self, hash: &str) -> LabResult<Vec<u8>> {
        self.get_blob_locked(hash)
    }

    fn get_blob_locked(&self, hash: &str) -> LabResult<Vec<u8>> {
        let path = self
            .root
            .join("blobs")
            .join(&hash[0..2])
            .join(format!("{hash}.bin"));
        if !path.exists() {
            return Err(LabError::new(format!("blob {hash} 不存在")));
        }
        Ok(fs::read(path)?)
    }

    /// 创建会话：用指定版本解析 blob，并固化结果快照。
    pub fn create_session(
        &self,
        version_id: &str,
        data: &[u8],
        note: &str,
    ) -> LabResult<SessionView> {
        let _g = self.lock();
        let version = self.version_by_id(version_id)?;
        let blob = self.put_blob_locked(data)?;
        let outcome = parser::parse(&version.spec, data)?;
        let rec = SessionRec {
            session_id: new_id("sess"),
            protocol_id: version.protocol_id.clone(),
            version_id: version.version_id.clone(),
            blob_hash: blob,
            note: note.to_string(),
            created_at: now_iso(),
            snapshot: saved_outcome(&outcome),
        };
        self.write_session_locked(&rec)?;
        let mut index = self.read_index()?;
        index.sessions.insert(rec.session_id.clone(), ());
        self.write_index(&index)?;
        self.view_locked(rec)
    }

    fn write_session_locked(&self, rec: &SessionRec) -> LabResult<()> {
        let path = self
            .root
            .join("sessions")
            .join(format!("{}.json", rec.session_id));
        write_json(&path, &SessionFile { session: rec.clone() })
    }

    pub fn list_sessions(&self) -> LabResult<Vec<SessionView>> {
        let _g = self.lock();
        let index = self.read_index()?;
        let mut views = Vec::new();
        for sid in index.sessions.keys() {
            let file: SessionFile =
                read_json(&self.root.join("sessions").join(format!("{sid}.json")))?;
            views.push(self.view_locked(file.session)?);
        }
        views.sort_by(|a, b| b.rec.created_at.cmp(&a.rec.created_at));
        Ok(views)
    }

    pub fn get_session(&self, session_id: &str) -> LabResult<SessionView> {
        let _g = self.lock();
        let file: SessionFile =
            read_json(&self.root.join("sessions").join(format!("{session_id}.json")))?;
        self.view_locked(file.session)
    }

    pub fn set_note(&self, session_id: &str, note: &str) -> LabResult<SessionView> {
        let _g = self.lock();
        let path = self
            .root
            .join("sessions")
            .join(format!("{session_id}.json"));
        let mut file: SessionFile = read_json(&path)?;
        file.session.note = note.to_string();
        write_json(&path, &file)?;
        self.view_locked(file.session)
    }

    /// 按会话创建时绑定的版本重放，并与固化快照比对。
    pub fn replay(&self, session_id: &str) -> LabResult<Replay> {
        let _g = self.lock();
        let file: SessionFile =
            read_json(&self.root.join("sessions").join(format!("{session_id}.json")))?;
        let version = self.version_by_id(&file.session.version_id)?;
        let data = self.get_blob(&file.session.blob_hash)?;
        let outcome = parser::parse(&version.spec, &data)?;
        let fresh = saved_outcome(&outcome);
        let consistent = fresh == file.session.snapshot;
        Ok(Replay {
            session: self.view_locked(file.session)?,
            outcome,
            consistent,
        })
    }

    fn view_locked(&self, rec: SessionRec) -> LabResult<SessionView> {
        let length = self.get_blob_locked(&rec.blob_hash).map(|b| b.len()).unwrap_or(0);
        Ok(SessionView { rec, length })
    }

    pub fn export_session(&self, session_id: &str) -> LabResult<ExportBundle> {
        let _g = self.lock();
        let file: SessionFile =
            read_json(&self.root.join("sessions").join(format!("{session_id}.json")))?;
        let version = self.version_by_id(&file.session.version_id)?;
        let data = self.get_blob(&file.session.blob_hash)?;
        Ok(ExportBundle {
            format: "frame-lab-session".to_string(),
            format_version: FORMAT_VERSION,
            exported_at: now_iso(),
            protocol: version,
            blob_hex: hex::encode(&data),
            blob_hash: file.session.blob_hash.clone(),
            session: file.session,
        })
    }

    /// 导入会话包：校验版本/字节/诊断/树摘要一致后落盘；
    /// blob 与协议版本去重，会话生成新 id，备注独立保留。
    pub fn import_bundle(&self, bundle: &ImportBundle) -> LabResult<SessionView> {
        let _g = self.lock();
        if bundle.format != "frame-lab-session" {
            return Err(LabError::new("不是帧解析实验室会话包"));
        }
        if bundle.format_version != FORMAT_VERSION {
            return Err(LabError::new(format!(
                "不支持的会话包版本 {}",
                bundle.format_version
            )));
        }
        bundle.protocol.spec.validate()?;
        let canonical = canonical_bytes(&bundle.protocol.spec)?;
        let computed_version = hex::encode(&crate::sha256::digest(&canonical));
        let want_version = bundle.protocol.version_id.clone();
        if want_version.len() < 16 || !computed_version.starts_with(&want_version) {
            return Err(LabError::new("协议版本哈希与内容不一致"));
        }

        let data = hex::decode(&bundle.blob_hex)
            .map_err(|e| LabError::new(format!("blob 十六进制非法: {e}")))?;
        if blob_hash(&data) != bundle.blob_hash {
            return Err(LabError::new("blob 哈希与内容不一致"));
        }

        let outcome = parser::parse(&bundle.protocol.spec, &data)?;
        let fresh = saved_outcome(&outcome);
        if fresh != bundle.session.snapshot {
            return Err(LabError::new(
                "会话包快照与重放结果不一致（版本/字节/诊断/树摘要）",
            ));
        }

        let version = self.save_version_locked(&bundle.protocol.spec)?;
        let blob_hash = self.put_blob_locked(&data)?;
        let mut rec = bundle.session.clone();
        rec.session_id = new_id("sess");
        rec.protocol_id = version.protocol_id;
        rec.version_id = version.version_id;
        rec.blob_hash = blob_hash;
        rec.created_at = now_iso();
        self.write_session_locked(&rec)?;
        let mut index = self.read_index()?;
        index.sessions.insert(rec.session_id.clone(), ());
        self.write_index(&index)?;
        self.view_locked(rec)
    }
}

pub struct Replay {
    pub session: SessionView,
    pub outcome: Outcome,
    pub consistent: bool,
}

fn saved_outcome(outcome: &Outcome) -> SavedOutcome {
    SavedOutcome {
        status: match outcome.status {
            parser::Status::Complete => "complete",
            parser::Status::Incomplete => "incomplete",
            parser::Status::Error => "error",
        }
        .to_string(),
        consumed: outcome.consumed,
        tree_digest: parser::tree_digest(&outcome.root),
        diagnostics: outcome.diagnostics.clone(),
    }
}

fn blob_hash(data: &[u8]) -> String {
    hex::encode(&crate::sha256::digest(data))
}

fn protocol_id_for(name: &str) -> String {
    let slug: String = name
        .trim()
        .chars()
        .map(|c| {
            if c.is_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    let slug = slug.trim_matches('-').to_string();
    if slug.is_empty() {
        "protocol".to_string()
    } else {
        slug
    }
}

fn now_iso() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    format!("{millis}")
}

fn new_id(prefix: &str) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0) as u64;
    let mut x = nanos ^ 0x9e37_79b9_7f4a_7c15;
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^= x >> 31;
    let pid = std::process::id() as u64;
    format!(
        "{prefix}_{:012x}",
        (x ^ pid.wrapping_mul(0x100000001b3)) & 0xffffffffffff
    )
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> LabResult<()> {
    let bytes = serde_json::to_vec_pretty(value)?;
    atomic_write(path, &bytes)
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> LabResult<T> {
    let bytes = fs::read(path)?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn atomic_write(path: &Path, bytes: &[u8]) -> LabResult<()> {
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, bytes)?;
    fs::rename(&tmp, path)?;
    Ok(())
}
