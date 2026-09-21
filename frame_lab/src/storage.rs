// On-disk persistence. No database: protocol versions and byte blobs are
// content-addressed and immutable; sessions and notes are independent files
// that bind to a specific version id, so history always replays exactly.

use crate::codec::{parse_frame, ParseResult, Status};
use crate::json::{self, Json};
use crate::spec::Protocol;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct Store {
    root: PathBuf,
    lock: Mutex<()>,
}

#[derive(Debug, Clone)]
pub struct VersionMeta {
    pub id: String,
    pub name: String,
    pub created_at: u64,
    pub canonical: String,
}

#[derive(Debug, Clone)]
pub struct Session {
    pub id: String,
    pub protocol_id: String,
    pub blob_id: String,
    pub title: String,
    pub note: String,
    pub work_hex: String,
    pub created_at: u64,
    pub updated_at: u64,
    pub history: Vec<HistoryEntry>,
}

#[derive(Debug, Clone)]
pub struct HistoryEntry {
    pub at: u64,
    pub work_hex: String,
    pub status: String,
    pub need: usize,
    pub digest: String,
    pub diagnostic: String,
    pub path: String,
    pub byte: Option<usize>,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl Store {
    pub fn open(root: impl AsRef<Path>) -> Result<Store, String> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(root.join("protocols"))
            .map_err(|e| format!("create protocols dir: {e}"))?;
        fs::create_dir_all(root.join("blobs")).map_err(|e| format!("create blobs dir: {e}"))?;
        fs::create_dir_all(root.join("sessions"))
            .map_err(|e| format!("create sessions dir: {e}"))?;
        fs::create_dir_all(root.join("index"))
            .map_err(|e| format!("create index dir: {e}"))?;
        Ok(Store {
            root,
            lock: Mutex::new(()),
        })
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

    // ---------- Protocol versions ----------

    /// Validate and persist an immutable protocol version. Identical content
    /// always returns the same id.
    pub fn save_protocol(&self, schema: &Json) -> Result<(String, Protocol), String> {
        let proto = Protocol::compile(schema)?;
        let canonical = schema.canonical();
        let id = crate::hash::content_id("proto", &canonical);
        let dir = self.protocols_dir().join(&id);
        if !dir.exists() {
            fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
            atomic_write(&dir.join("schema.json"), &schema.pretty())?;
            let mut meta = Json::obj();
            meta.put("id", Json::str(&id));
            meta.put("name", Json::str(&proto.name));
            meta.put("root", Json::str(&proto.root));
            meta.put("max_depth", Json::uint(proto.max_depth as u64));
            meta.put("created_at", Json::uint(now()));
            atomic_write(&dir.join("meta.json"), &meta.pretty())?;
        }
        Ok((id, proto))
    }

    pub fn list_protocols(&self) -> Result<Vec<VersionMeta>, String> {
        let mut out = Vec::new();
        for entry in fs::read_dir(self.protocols_dir()).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            let meta_path = entry.path().join("meta.json");
            let schema_path = entry.path().join("schema.json");
            if meta_path.exists() {
                let raw = fs::read_to_string(&meta_path).map_err(|e| e.to_string())?;
                let m = json::parse(&raw)?;
                let canonical = fs::read_to_string(&schema_path)
                    .ok()
                    .and_then(|t| json::parse(&t).ok())
                    .map(|j| j.canonical())
                    .unwrap_or_default();
                out.push(VersionMeta {
                    id: m.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                    name: m.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                    created_at: m.get("created_at").and_then(|v| v.as_u64()).unwrap_or(0),
                    canonical,
                });
            }
        }
        out.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        Ok(out)
    }

    pub fn load_protocol(&self, id: &str) -> Result<(Json, Protocol), String> {
        let path = self.protocols_dir().join(safe(id)).join("schema.json");
        let raw = fs::read_to_string(&path).map_err(|e| format!("protocol {id}: {e}"))?;
        let schema = json::parse(&raw)?;
        let proto = Protocol::compile(&schema)?;
        Ok((schema, proto))
    }

    pub fn protocol_exists(&self, id: &str) -> bool {
        self.protocols_dir().join(safe(id)).join("schema.json").exists()
    }

    // ---------- Blobs (content addressed) ----------

    /// Store bytes once. Re-importing the same sample returns the existing
    /// blob id; sessions that reference it stay independent.
    pub fn put_blob(&self, data: &[u8]) -> Result<String, String> {
        let id = format!(
            "blob_{}",
            &crate::hash::hex_encode(&crate::hash::sha256(data)[..16])
        );
        let path = self.blobs_dir().join(format!("{}.bin", id));
        if !path.exists() {
            atomic_write_bytes(&path, data)?;
        }
        Ok(id)
    }

    pub fn get_blob(&self, id: &str) -> Result<Vec<u8>, String> {
        let path = self.blobs_dir().join(format!("{}.bin", safe(id)));
        fs::read(&path).map_err(|e| format!("blob {id}: {e}"))
    }

    // ---------- Sessions ----------

    pub fn create_session(
        &self,
        protocol_id: &str,
        blob_id: &str,
        title: &str,
    ) -> Result<Session, String> {
        if !self.protocol_exists(protocol_id) {
            return Err("unknown protocol version".to_string());
        }
        let bytes = self.get_blob(blob_id)?;
        let (_schema, proto) = self.load_protocol(protocol_id)?;
        let result = parse_frame(&proto, &bytes);
        let work_hex = crate::hash::hex_encode(&bytes);
        let entry = history_entry(&work_hex, &result);
        let ts = now();
        let session = Session {
            id: new_id("sess"),
            protocol_id: protocol_id.to_string(),
            blob_id: blob_id.to_string(),
            title: title.to_string(),
            note: String::new(),
            work_hex: work_hex.clone(),
            created_at: ts,
            updated_at: ts,
            history: vec![entry],
        };
        self.write_session(&session)?;
        Ok(session)
    }

    pub fn list_sessions(&self) -> Result<Vec<Session>, String> {
        let mut out = Vec::new();
        for entry in fs::read_dir(self.sessions_dir()).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            if entry.path().extension().and_then(|x| x.to_str()) == Some("json") {
                let raw = fs::read_to_string(entry.path()).map_err(|e| e.to_string())?;
                if let Ok(s) = session_from_json(&json::parse(&raw)?) {
                    out.push(s);
                }
            }
        }
        out.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
        Ok(out)
    }

    pub fn get_session(&self, id: &str) -> Result<Session, String> {
        let raw = fs::read_to_string(self.session_path(id)).map_err(|e| e.to_string())?;
        session_from_json(&json::parse(&raw)?)
    }

    fn session_path(&self, id: &str) -> PathBuf {
        self.sessions_dir().join(format!("{}.json", safe(id)))
    }

    fn write_session(&self, session: &Session) -> Result<(), String> {
        atomic_write(&self.session_path(&session.id), &session_to_json(session).pretty())
    }

    /// Re-parse the working bytes under the bound protocol version and append
    /// a replay entry. Returns the fresh parse result.
    pub fn update_work(&self, id: &str, work_hex: &str) -> Result<(Session, ParseResult), String> {
        let _g = self.lock.lock().map_err(|e| e.to_string())?;
        let mut session = self.get_session(id)?;
        let bytes = crate::hash::hex_decode(work_hex)?;
        let (_schema, proto) = self.load_protocol(&session.protocol_id)?;
        let result = parse_frame(&proto, &bytes);
        let hex = crate::hash::hex_encode(&bytes);
        session.work_hex = hex;
        session.updated_at = now();
        session.history.push(history_entry(&session.work_hex, &result));
        if session.history.len() > 200 {
            let drop_n = session.history.len() - 200;
            session.history.drain(0..drop_n);
        }
        self.write_session(&session)?;
        Ok((session, result))
    }

    pub fn set_note(&self, id: &str, note: &str) -> Result<Session, String> {
        let _g = self.lock.lock().map_err(|e| e.to_string())?;
        let mut session = self.get_session(id)?;
        session.note = note.to_string();
        session.updated_at = now();
        self.write_session(&session)?;
        Ok(session)
    }

    pub fn rename_session(&self, id: &str, title: &str) -> Result<Session, String> {
        let _g = self.lock.lock().map_err(|e| e.to_string())?;
        let mut session = self.get_session(id)?;
        session.title = title.to_string();
        session.updated_at = now();
        self.write_session(&session)?;
        Ok(session)
    }

    /// Parse the immutable original blob (used when replaying an old session).
    pub fn replay_original(&self, session: &Session) -> Result<ParseResult, String> {
        let bytes = self.get_blob(&session.blob_id)?;
        let (_schema, proto) = self.load_protocol(&session.protocol_id)?;
        Ok(parse_frame(&proto, &bytes))
    }

    /// Re-parse the stored working bytes under the bound version. This is the
    /// deterministic replay used by export/import verification.
    pub fn replay_work(&self, session: &Session) -> Result<ParseResult, String> {
        let bytes = crate::hash::hex_decode(&session.work_hex)?;
        let (_schema, proto) = self.load_protocol(&session.protocol_id)?;
        Ok(parse_frame(&proto, &bytes))
    }

    // ---------- Export / Import ----------

    /// Build a self-contained, deterministic session package.
    pub fn export_session(&self, id: &str) -> Result<Json, String> {
        let session = self.get_session(id)?;
        let (schema, _proto) = self.load_protocol(&session.protocol_id)?;
        let bytes = self.get_blob(&session.blob_id)?;
        let replay = self.replay_work(&session)?;

        let mut pkg = Json::obj();
        pkg.put("format", Json::str("frame-lab-session/1"));
        let mut body = Json::obj();
        body.put("session", session_to_json(&session));
        body.put("protocol_id", Json::str(&session.protocol_id));
        body.put("schema", schema);
        body.put("blob_id", Json::str(&session.blob_id));
        body.put("blob_hex", Json::str(crate::hash::hex_encode(&bytes)));
        body.put("replay_status", Json::str(replay.status.as_str()));
        body.put("replay_digest", Json::str(replay.digest()));
        let digest = package_digest(&body);
        pkg.put("body", body);
        pkg.put("digest", Json::str(digest));
        Ok(pkg)
    }

    /// Import a package. Version and blob are de-duplicated; the session and
    /// its note remain independent from any existing session. Replay must
    /// reproduce the recorded version/bytes/diagnostics/tree digest.
    pub fn import_session(&self, pkg: &Json) -> Result<ImportReport, String> {
        if pkg.get("format").and_then(|v| v.as_str()) != Some("frame-lab-session/1") {
            return Err("unsupported package format".to_string());
        }
        let body = pkg.get("body").ok_or("package missing body")?;
        let recorded_digest = pkg
            .get("digest")
            .and_then(|v| v.as_str())
            .ok_or("package missing digest")?;
        if package_digest(body) != recorded_digest {
            return Err("package digest mismatch".to_string());
        }

        let schema = body.get("schema").ok_or("missing schema")?;
        let (protocol_id, proto) = self.save_protocol(schema)?;
        let declared_pid = body
            .get("protocol_id")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if protocol_id != declared_pid {
            return Err(format!(
                "version id mismatch: package {} vs content {}",
                declared_pid, protocol_id
            ));
        }

        let blob_hex = body
            .get("blob_hex")
            .and_then(|v| v.as_str())
            .ok_or("missing blob_hex")?;
        let bytes = crate::hash::hex_decode(blob_hex)?;
        let blob_id = self.put_blob(&bytes)?;
        let declared_bid = body
            .get("blob_id")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if blob_id != declared_bid {
            return Err(format!(
                "blob id mismatch: package {} vs content {}",
                declared_bid, blob_id
            ));
        }

        let session_json = body.get("session").ok_or("missing session")?;
        let mut session = session_from_json(session_json)?;
        if session.protocol_id != protocol_id || session.blob_id != blob_id {
            return Err("session references do not match package".to_string());
        }

        // Deterministic replay under the bound version.
        let replay = parse_frame(&proto, &crate::hash::hex_decode(&session.work_hex)?);
        let expected_status = body
            .get("replay_status")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let expected_digest = body
            .get("replay_digest")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if replay.status.as_str() != expected_status || replay.digest() != expected_digest {
            return Err(format!(
                "replay mismatch: expected {} / {}, got {} / {}",
                expected_status,
                expected_digest,
                replay.status.as_str(),
                replay.digest()
            ));
        }

        // Independent session: give it a fresh id even if content is identical.
        session.id = new_id("sess");
        self.write_session(&session)?;

        Ok(ImportReport {
            session,
            protocol_id,
            blob_id,
            replay,
        })
    }
}

pub struct ImportReport {
    pub session: Session,
    pub protocol_id: String,
    pub blob_id: String,
    pub replay: ParseResult,
}

fn package_digest(body: &Json) -> String {
    crate::hash::hex_encode(&crate::hash::sha256(body.canonical().as_bytes()))
}

fn history_entry(work_hex: &str, result: &ParseResult) -> HistoryEntry {
    let d = result.diagnostics.first();
    HistoryEntry {
        at: now(),
        work_hex: work_hex.to_string(),
        status: result.status.as_str().to_string(),
        need: result.need,
        digest: result.digest(),
        diagnostic: d.map(|x| x.message.clone()).unwrap_or_default(),
        path: d.map(|x| x.path.clone()).unwrap_or_default(),
        byte: d.and_then(|x| x.byte),
    }
}

fn session_to_json(s: &Session) -> Json {
    let mut o = Json::obj();
    o.put("id", Json::str(&s.id));
    o.put("protocol_id", Json::str(&s.protocol_id));
    o.put("blob_id", Json::str(&s.blob_id));
    o.put("title", Json::str(&s.title));
    o.put("note", Json::str(&s.note));
    o.put("work_hex", Json::str(&s.work_hex));
    o.put("created_at", Json::uint(s.created_at));
    o.put("updated_at", Json::uint(s.updated_at));
    o.put(
        "history",
        Json::arr(
            s.history
                .iter()
                .map(|h| {
                    let mut x = Json::obj();
                    x.put("at", Json::uint(h.at));
                    x.put("work_hex", Json::str(&h.work_hex));
                    x.put("status", Json::str(&h.status));
                    x.put("need", Json::uint(h.need as u64));
                    x.put("digest", Json::str(&h.digest));
                    x.put("diagnostic", Json::str(&h.diagnostic));
                    x.put("path", Json::str(&h.path));
                    match h.byte {
                        Some(b) => x.put("byte", Json::uint(b as u64)),
                        None => x.put("byte", Json::Null),
                    }
                    x
                })
                .collect(),
        ),
    );
    o
}

fn session_from_json(j: &Json) -> Result<Session, String> {
    let get = |k: &str| -> Result<&Json, String> {
        j.get(k).ok_or_else(|| format!("session missing {k}"))
    };
    let history = match get("history")?.as_array() {
        Some(arr) => arr
            .iter()
            .map(|h| HistoryEntry {
                at: h.get("at").and_then(|v| v.as_u64()).unwrap_or(0),
                work_hex: h
                    .get("work_hex")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                status: h
                    .get("status")
                    .and_then(|v| v.as_str())
                    .unwrap_or("ok")
                    .to_string(),
                need: h.get("need").and_then(|v| v.as_u64()).unwrap_or(0) as usize,
                digest: h
                    .get("digest")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                diagnostic: h
                    .get("diagnostic")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                path: h
                    .get("path")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                byte: h.get("byte").and_then(|v| v.as_u64()).map(|b| b as usize),
            })
            .collect(),
        None => Vec::new(),
    };
    Ok(Session {
        id: get("id")?.as_str().unwrap_or("").to_string(),
        protocol_id: get("protocol_id")?.as_str().unwrap_or("").to_string(),
        blob_id: get("blob_id")?.as_str().unwrap_or("").to_string(),
        title: get("title")?.as_str().unwrap_or("").to_string(),
        note: j.get("note").and_then(|v| v.as_str()).unwrap_or("").to_string(),
        work_hex: get("work_hex")?.as_str().unwrap_or("").to_string(),
        created_at: get("created_at")?.as_u64().unwrap_or(0),
        updated_at: get("updated_at")?.as_u64().unwrap_or(0),
        history,
    })
}

fn new_id(prefix: &str) -> String {
    let mut seed = [0u8; 16];
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let n = nanos.to_le_bytes();
    seed[..n.len().min(16)].copy_from_slice(&n[..n.len().min(16)]);
    let digest = crate::hash::sha256(&seed);
    format!("{}_{}", prefix, &crate::hash::hex_encode(&digest[..10]))
}

fn safe(id: &str) -> String {
    id.chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '_' || c == '-' { c } else { '_' })
        .collect()
}

fn atomic_write(path: &Path, content: &str) -> Result<(), String> {
    atomic_write_bytes(path, content.as_bytes())
}

fn atomic_write_bytes(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, bytes).map_err(|e| e.to_string())?;
    fs::rename(&tmp, path).map_err(|e| e.to_string())
}

// Silence unused warnings while keeping Status/BTreeMap imports available for
// future API surfaces.
#[allow(dead_code)]
fn _used(m: &BTreeMap<String, String>, s: Status) -> bool {
    m.is_empty() && s.rank() > 9
}
