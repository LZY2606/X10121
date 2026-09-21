//! Repository-directory persistence.
//!
//! Layout under `<data_dir>`:
//! ```text
//! protocols.json              # lineage metadata (editable heads)
//! versions/<hash>.json        # immutable canonical protocol versions
//! blobs/ab/cd/<sha256>        # content-addressed byte samples (deduplicated)
//! sessions/<id>.json          # saved sessions (note, bytes, version, snapshot)
//! ```
//! Everything is plain JSON written atomically, so no system database is used.

use crate::hash::sha256_hex;
use crate::parser::{self, ParseResult, TreeSummary};
use crate::spec::{canonical_json, RawSpec, Spec};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

#[derive(Debug)]
pub struct StoreError(pub String);

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<std::io::Error> for StoreError {
    fn from(e: std::io::Error) -> Self {
        StoreError(e.to_string())
    }
}

impl From<serde_json::Error> for StoreError {
    fn from(e: serde_json::Error) -> Self {
        StoreError(e.to_string())
    }
}

fn err<T>(msg: impl Into<String>) -> Result<T, StoreError> {
    Err(StoreError(msg.into()))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VersionInfo {
    pub version_hash: String,
    pub protocol: String,
    pub label: String,
    pub created_at: String,
    pub parent_hash: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ProtocolMeta {
    pub name: String,
    pub current_hash: Option<String>,
    pub versions: Vec<VersionInfo>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Session {
    pub id: String,
    pub created_at: String,
    pub updated_at: String,
    pub note: String,
    pub protocol: String,
    pub version_hash: String,
    pub blob_hash: String,
    pub length: usize,
    pub result: ParseResult,
    pub summary: TreeSummary,
}

/// A portable, deterministic session package.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Bundle {
    pub bundle_version: u32,
    pub exported_at: String,
    pub version_label: String,
    pub parent_hash: Option<String>,
    pub spec: RawSpec,
    pub version_hash: String,
    pub blob_hex: String,
    pub blob_hash: String,
    pub note: String,
    pub result: ParseResult,
    pub summary: TreeSummary,
}

#[derive(Clone, Debug, Serialize)]
pub struct ImportReport {
    pub session_id: String,
    pub version_hash: String,
    pub blob_hash: String,
    pub reused_blob: bool,
    pub version_present: bool,
    pub replay_consistent: bool,
}

#[derive(Default, Serialize, Deserialize)]
struct LineageFile {
    protocols: BTreeMap<String, ProtocolMeta>,
}

pub struct Store {
    root: PathBuf,
    write_lock: Mutex<()>,
}

impl Store {
    pub fn open(root: impl AsRef<Path>) -> Result<Store, StoreError> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(root.join("versions"))?;
        fs::create_dir_all(root.join("sessions"))?;
        fs::create_dir_all(root.join("blobs"))?;
        Ok(Store { root, write_lock: Mutex::new(()) })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn lineage_path(&self) -> PathBuf {
        self.root.join("protocols.json")
    }

    fn load_lineage(&self) -> Result<LineageFile, StoreError> {
        let path = self.lineage_path();
        if !path.exists() {
            return Ok(LineageFile::default());
        }
        let text = fs::read_to_string(path)?;
        Ok(serde_json::from_str(&text)?)
    }

    fn save_lineage(&self, lineage: &LineageFile) -> Result<(), StoreError> {
        let text = serde_json::to_string_pretty(lineage)?;
        atomic_write(&self.lineage_path(), text.as_bytes())
    }

    /// Create or replace a protocol lineage (editor initialization).
    pub fn put_protocol(&self, name: &str) -> Result<(), StoreError> {
        let _guard = self.write_lock.lock().unwrap();
        let mut lineage = self.load_lineage()?;
        lineage
            .protocols
            .entry(name.to_string())
            .or_insert_with(|| ProtocolMeta {
                name: name.to_string(),
                current_hash: None,
                versions: Vec::new(),
            });
        self.save_lineage(&lineage)
    }

    pub fn list_protocols(&self) -> Result<Vec<ProtocolMeta>, StoreError> {
        let lineage = self.load_lineage()?;
        Ok(lineage.protocols.values().cloned().collect())
    }

    /// Compile, validate and persist a new immutable protocol version.
    /// Saving identical content twice returns the existing hash.
    pub fn save_version(
        &self,
        protocol: &str,
        raw: RawSpec,
        label: &str,
        parent_hash: Option<String>,
    ) -> Result<VersionInfo, StoreError> {
        let _guard = self.write_lock.lock().unwrap();
        let spec = Spec::compile(raw).map_err(|e| StoreError(e.join("; ")))?;
        let hash = spec.version_hash.clone();

        let mut lineage = self.load_lineage()?;
        let meta = lineage
            .protocols
            .entry(protocol.to_string())
            .or_insert_with(|| ProtocolMeta {
                name: protocol.to_string(),
                current_hash: None,
                versions: Vec::new(),
            });

        if let Some(existing) = meta.versions.iter().find(|v| v.version_hash == hash) {
            return Ok(existing.clone());
        }

        let info = VersionInfo {
            version_hash: hash.clone(),
            protocol: protocol.to_string(),
            label: label.to_string(),
            created_at: now_ts(),
            parent_hash,
        };

        let version_path = self.root.join("versions").join(format!("{}.json", hash));
        let persisted = serde_json::json!({
            "info": info,
            "spec": spec.raw,
            "canonical": spec.canonical(),
        });
        atomic_write(&version_path, serde_json::to_string_pretty(&persisted)?.as_bytes())?;

        meta.versions.push(info.clone());
        meta.current_hash = Some(hash);
        self.save_lineage(&lineage)?;
        Ok(info)
    }

    pub fn list_versions(&self, protocol: &str) -> Result<Vec<VersionInfo>, StoreError> {
        let lineage = self.load_lineage()?;
        match lineage.protocols.get(protocol) {
            Some(meta) => Ok(meta.versions.clone()),
            None => err(format!("unknown protocol `{}`", protocol)),
        }
    }

    /// Load a compiled version by its immutable hash.
    pub fn load_version(&self, hash: &str) -> Result<Spec, StoreError> {
        let path = self.root.join("versions").join(format!("{}.json", hash));
        if !path.exists() {
            return err(format!("unknown version `{}`", hash));
        }
        let text = fs::read_to_string(path)?;
        let doc: serde_json::Value = serde_json::from_str(&text)?;
        let raw: RawSpec = serde_json::from_value(doc.get("spec").cloned().unwrap_or_default())?;
        let spec = Spec::compile(raw).map_err(|e| StoreError(e.join("; ")))?;
        if spec.version_hash != hash {
            return err("stored version failed its hash check".to_string());
        }
        Ok(spec)
    }

    pub fn raw_version(&self, hash: &str) -> Result<RawSpec, StoreError> {
        Ok(self.load_version(hash)?.raw)
    }
}

impl Store {
    /// Content-address a sample; identical bytes always map to the same blob.
    /// Returns the sha256 hash and whether an existing blob was reused.
    pub fn put_blob(&self, bytes: &[u8]) -> Result<(String, bool), StoreError> {
        let _guard = self.write_lock.lock().unwrap();
        self.put_blob_unlocked(bytes)
    }

    fn put_blob_unlocked(&self, bytes: &[u8]) -> Result<(String, bool), StoreError> {
        let hash = sha256_hex(bytes);
        let path = self.blob_path(&hash);
        if path.exists() {
            return Ok((hash, true));
        }
        fs::create_dir_all(path.parent().unwrap())?;
        atomic_write(&path, bytes)?;
        Ok((hash, false))
    }

    pub fn get_blob(&self, hash: &str) -> Result<Vec<u8>, StoreError> {
        let path = self.blob_path(hash);
        if !path.exists() {
            return err(format!("unknown blob `{}`", hash));
        }
        Ok(fs::read(path)?)
    }

    fn blob_path(&self, hash: &str) -> PathBuf {
        self.root
            .join("blobs")
            .join(&hash[0..2])
            .join(&hash[2..4])
            .join(hash)
    }

    /// Parse and persist a new, independent session.
    pub fn create_session(
        &self,
        protocol: &str,
        version_hash: &str,
        bytes: &[u8],
        note: &str,
    ) -> Result<Session, StoreError> {
        let spec = self.load_version(version_hash)?;
        let result = parser::parse(&spec, bytes);
        let summary = parser::summarize(&result);
        let (blob_hash, _) = self.put_blob(bytes)?;

        let now = now_ts();
        let session = Session {
            id: new_id("ses"),
            created_at: now.clone(),
            updated_at: now,
            note: note.to_string(),
            protocol: protocol.to_string(),
            version_hash: version_hash.to_string(),
            blob_hash,
            length: bytes.len(),
            result,
            summary,
        };
        self.write_session(&session)?;
        Ok(session)
    }

    pub fn list_sessions(&self) -> Result<Vec<SessionHeader>, StoreError> {
        let dir = self.root.join("sessions");
        let mut out = Vec::new();
        for entry in fs::read_dir(&dir)? {
            let path = entry?.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let text = fs::read_to_string(&path)?;
            let session: Session = serde_json::from_str(&text)?;
            out.push(SessionHeader {
                id: session.id,
                created_at: session.created_at,
                updated_at: session.updated_at,
                note: session.note,
                protocol: session.protocol,
                version_hash: session.version_hash,
                blob_hash: session.blob_hash,
                length: session.length,
                status: session.summary.status,
            });
        }
        out.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        Ok(out)
    }

    pub fn get_session(&self, id: &str) -> Result<Session, StoreError> {
        let path = self.session_path(id);
        if !path.exists() {
            return err(format!("unknown session `{}`", id));
        }
        let text = fs::read_to_string(path)?;
        Ok(serde_json::from_str(&text)?)
    }

    pub fn update_note(&self, id: &str, note: &str) -> Result<Session, StoreError> {
        let mut session = self.get_session(id)?;
        session.note = note.to_string();
        session.updated_at = now_ts();
        self.write_session(&session)?;
        Ok(session)
    }

    /// Re-parse the stored blob with the bound (immutable) version. Sessions
    /// never silently follow newer protocol versions.
    pub fn replay_session(&self, id: &str) -> Result<ReplayReport, StoreError> {
        let session = self.get_session(id)?;
        let spec = self.load_version(&session.version_hash)?;
        let bytes = self.get_blob(&session.blob_hash)?;
        let fresh = parser::parse(&spec, &bytes);
        let fresh_summary = parser::summarize(&fresh);

        let before = canonical_json(&session.result);
        let after = canonical_json(&fresh);
        Ok(ReplayReport {
            id: session.id.clone(),
            version_hash: session.version_hash.clone(),
            consistent: before == after && canonical_json(&session.summary) == canonical_json(&fresh_summary),
            stored_summary: session.summary.clone(),
            fresh_summary,
        })
    }

    pub fn export_session(&self, id: &str) -> Result<Bundle, StoreError> {
        let session = self.get_session(id)?;
        let spec = self.load_version(&session.version_hash)?;
        let bytes = self.get_blob(&session.blob_hash)?;
        let info = self
            .list_versions(&session.protocol)?
            .into_iter()
            .find(|v| v.version_hash == session.version_hash);
        Ok(Bundle {
            bundle_version: 1,
            exported_at: now_ts(),
            version_label: info.as_ref().map(|i| i.label.clone()).unwrap_or_default(),
            parent_hash: info.and_then(|i| i.parent_hash),
            spec: spec.raw.clone(),
            version_hash: session.version_hash.clone(),
            blob_hex: crate::hex::encode(&bytes),
            blob_hash: session.blob_hash.clone(),
            note: session.note.clone(),
            result: session.result.clone(),
            summary: session.summary.clone(),
        })
    }

    /// Import a bundle: version and blob are content-deduplicated, but the
    /// session and note remain independent. Replays before saving and refuses
    /// anything whose bytes/version/diagnostics do not reproduce.
    pub fn import_bundle(&self, bundle: Bundle) -> Result<ImportReport, StoreError> {
        let _guard = self.write_lock.lock().unwrap();

        let bytes = crate::hex::decode(&bundle.blob_hex)
            .map_err(|e| StoreError(format!("invalid blob hex: {}", e)))?;
        if sha256_hex(&bytes) != bundle.blob_hash {
            return err("bundle blob hash mismatch".to_string());
        }

        let spec = Spec::compile(bundle.spec.clone()).map_err(|e| StoreError(e.join("; ")))?;
        if spec.version_hash != bundle.version_hash {
            return err("bundle spec does not hash to its declared version".to_string());
        }

        let fresh = parser::parse(&spec, &bytes);
        if canonical_json(&fresh) != canonical_json(&bundle.result) {
            return err("bundle diagnostics are not reproducible under the bound version".to_string());
        }
        let fresh_summary = parser::summarize(&fresh);
        if canonical_json(&fresh_summary) != canonical_json(&bundle.summary) {
            return err("bundle tree summary is not reproducible".to_string());
        }

        let version_present = self
            .root
            .join("versions")
            .join(format!("{}.json", bundle.version_hash))
            .exists();
        if !version_present {
            let info = VersionInfo {
                version_hash: bundle.version_hash.clone(),
                protocol: spec.raw.name.clone(),
                label: bundle.version_label.clone(),
                created_at: now_ts(),
                parent_hash: bundle.parent_hash.clone(),
            };
            let persisted = serde_json::json!({
                "info": info,
                "spec": spec.raw,
                "canonical": spec.canonical(),
            });
            atomic_write(
                &self.root.join("versions").join(format!("{}.json", bundle.version_hash)),
                serde_json::to_string_pretty(&persisted)?.as_bytes(),
            )?;
            let mut lineage = self.load_lineage()?;
            let meta = lineage
                .protocols
                .entry(spec.raw.name.clone())
                .or_insert_with(|| ProtocolMeta {
                    name: spec.raw.name.clone(),
                    current_hash: None,
                    versions: Vec::new(),
                });
            if !meta.versions.iter().any(|v| v.version_hash == bundle.version_hash) {
                meta.versions.push(VersionInfo {
                    version_hash: bundle.version_hash.clone(),
                    protocol: spec.raw.name.clone(),
                    label: bundle.version_label.clone(),
                    created_at: now_ts(),
                    parent_hash: bundle.parent_hash.clone(),
                });
                meta.current_hash = Some(bundle.version_hash.clone());
            }
            self.save_lineage(&lineage)?;
        }

        let (blob_hash, reused_blob) = self.put_blob_unlocked(&bytes)?;
        let now = now_ts();
        let session = Session {
            id: new_id("ses"),
            created_at: now.clone(),
            updated_at: now,
            note: bundle.note.clone(),
            protocol: spec.raw.name.clone(),
            version_hash: bundle.version_hash.clone(),
            blob_hash,
            length: bytes.len(),
            result: fresh,
            summary: fresh_summary,
        };
        let session_id = session.id.clone();
        self.write_session(&session)?;

        Ok(ImportReport {
            session_id,
            version_hash: bundle.version_hash,
            blob_hash: bundle.blob_hash,
            reused_blob,
            version_present,
            replay_consistent: true,
        })
    }

    fn write_session(&self, session: &Session) -> Result<(), StoreError> {
        let path = self.session_path(&session.id);
        atomic_write(&path, serde_json::to_string_pretty(session)?.as_bytes())
    }

    fn session_path(&self, id: &str) -> PathBuf {
        self.root.join("sessions").join(format!("{}.json", id))
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct SessionHeader {
    pub id: String,
    pub created_at: String,
    pub updated_at: String,
    pub note: String,
    pub protocol: String,
    pub version_hash: String,
    pub blob_hash: String,
    pub length: usize,
    pub status: parser::Status,
}

#[derive(Clone, Debug, Serialize)]
pub struct ReplayReport {
    pub id: String,
    pub version_hash: String,
    pub consistent: bool,
    pub stored_summary: TreeSummary,
    pub fresh_summary: TreeSummary,
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), StoreError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, bytes)?;
    fs::rename(&tmp, path)?;
    Ok(())
}

fn now_ts() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    format!("{}", secs)
}

fn new_id(prefix: &str) -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let thread_hash = seq.rotate_left(17) ^ 0x517cc1b727220a95;
    let mut seed = (nanos as u64)
        ^ std::process::id() as u64
        ^ seq.wrapping_mul(0x9e3779b97f4a7c15)
        ^ thread_hash;
    // SplitMix64 finalizer.
    seed = (seed ^ (seed >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    seed = (seed ^ (seed >> 27)).wrapping_mul(0x94d049bb133111eb);
    seed ^= seed >> 31;
    format!("{}_{}_{:016x}", prefix, seq, seed)
}
