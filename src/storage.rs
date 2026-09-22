//! 仓库目录持久化（不依赖系统数据库）：
//!   <data>/protocols/<pid>/meta.json, v<N>.json
//!   <data>/blobs/<sha256>
//!   <data>/sessions/<sid>.json
//! 协议版本不可变；历史会话始终绑定创建/修订时的协议版本。
use crate::json::Json;
use crate::spec::Spec;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

#[derive(Debug, Clone)]
pub struct Revision {
    pub version: usize,
    pub spec_json: Json,
    pub spec: Spec,
    pub digest: String,
    pub created_at: String,
    pub note: String,
}

#[derive(Debug, Clone)]
pub struct Protocol {
    pub id: String,
    pub name: String,
    pub latest: usize,
    pub revisions: Vec<Revision>,
}

#[derive(Debug, Clone)]
pub struct SessionRev {
    pub at: String,
    pub protocol_id: String,
    pub version: usize,
    pub blob: String,
    pub byte_length: usize,
    pub status: String,
    pub report_digest: String,
    pub tree_digest: String,
}

#[derive(Debug, Clone)]
pub struct Session {
    pub id: String,
    pub title: String,
    pub note: String,
    pub created_at: String,
    pub updated_at: String,
    pub current: SessionRev,
    pub revisions: Vec<SessionRev>,
}

pub struct Store {
    root: PathBuf,
    // 串行化所有写操作，保证文件状态一致
    write_lock: Mutex<()>,
}

fn now_ts() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("{secs}")
}

impl Store {
    pub fn open(root: impl AsRef<Path>) -> Result<Store, String> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(root.join("protocols")).map_err(|e| format!("创建 protocols 目录失败：{e}"))?;
        fs::create_dir_all(root.join("blobs")).map_err(|e| format!("创建 blobs 目录失败：{e}"))?;
        fs::create_dir_all(root.join("sessions")).map_err(|e| format!("创建 sessions 目录失败：{e}"))?;
        Ok(Store { root, write_lock: Mutex::new(()) })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    // ---------- blob：相同样本内容寻址 ----------
    pub fn put_blob(&self, data: &[u8]) -> Result<String, String> {
        let _g = self.write_lock.lock().unwrap();
        self.put_blob_locked(data)
    }

    fn put_blob_locked(&self, data: &[u8]) -> Result<String, String> {
        let hash = crate::hash::hex_lower(&crate::hash::sha256(data));
        let path = self.blob_path(&hash);
        if !path.exists() {
            atomic_write(&path, data)?;
        }
        Ok(hash)
    }

    pub fn get_blob(&self, hash: &str) -> Result<Vec<u8>, String> {
        if !is_hex_id(hash) {
            return Err("非法 blob id".to_string());
        }
        fs::read(self.blob_path(hash)).map_err(|e| format!("读取 blob {hash} 失败：{e}"))
    }

    pub fn blob_exists(&self, hash: &str) -> bool {
        self.blob_path(hash).exists()
    }

    fn blob_path(&self, hash: &str) -> PathBuf {
        self.root.join("blobs").join(hash)
    }

    // ---------- 协议与不可变版本 ----------
    pub fn create_protocol(&self, name: &str, spec_json: &Json, note: &str) -> Result<Protocol, String> {
        let _g = self.write_lock.lock().unwrap();
        self.create_protocol_locked(name, spec_json, note)
    }

    fn create_protocol_locked(&self, name: &str, spec_json: &Json, note: &str) -> Result<Protocol, String> {
        let spec = Spec::from_json(spec_json)?;
        let id = self.unique_id("p")?;
        let pdir = self.root.join("protocols").join(&id);
        fs::create_dir_all(&pdir).map_err(|e| e.to_string())?;
        let digest = spec_digest(spec_json);
        let rev = Revision {
            version: 1,
            spec_json: spec_json.clone(),
            spec,
            digest,
            created_at: now_ts(),
            note: note.to_string(),
        };
        fs::write(pdir.join("v1.json"), rev.spec_json.dump_pretty())
            .map_err(|e| e.to_string())?;
        let proto = Protocol {
            id,
            name: name.to_string(),
            latest: 1,
            revisions: vec![rev],
        };
        self.write_meta_locked(&proto)?;
        Ok(proto)
    }

    pub fn save_version(&self, pid: &str, spec_json: &Json, note: &str) -> Result<Revision, String> {
        let _g = self.write_lock.lock().unwrap();
        self.save_version_locked(pid, spec_json, note)
    }

    fn save_version_locked(&self, pid: &str, spec_json: &Json, note: &str) -> Result<Revision, String> {
        let spec = Spec::from_json(spec_json)?;
        let mut proto = self.load_protocol_locked(pid)?;
        let digest = spec_digest(spec_json);
        // 与最新版本完全相同：幂等返回已有版本（不制造新版本号）
        if let Some(existing) = proto.revisions.iter().find(|r| r.digest == digest) {
            return Ok(existing.clone());
        }
        let v = proto.latest + 1;
        let rev = Revision {
            version: v,
            spec_json: spec_json.clone(),
            spec,
            digest,
            created_at: now_ts(),
            note: note.to_string(),
        };
        let pdir = self.root.join("protocols").join(pid);
        fs::write(pdir.join(format!("v{v}.json")), rev.spec_json.dump_pretty())
            .map_err(|e| e.to_string())?;
        proto.latest = v;
        proto.revisions.push(rev.clone());
        self.write_meta_locked(&proto)?;
        Ok(rev)
    }

    pub fn list_protocols(&self) -> Result<Vec<ProtocolSummary>, String> {
        let mut out = Vec::new();
        let pdir = self.root.join("protocols");
        for entry in fs::read_dir(&pdir).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            if !entry.path().is_dir() {
                continue;
            }
            let id = entry.file_name().to_string_lossy().to_string();
            let meta = read_json(&entry.path().join("meta.json"))?;
            out.push(ProtocolSummary {
                id,
                name: meta.get("name").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                latest: meta.get("latest").and_then(|x| x.as_i64()).unwrap_or(1) as usize,
            });
        }
        out.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(out)
    }

    pub fn load_protocol(&self, pid: &str) -> Result<Protocol, String> {
        let _g = self.write_lock.lock().unwrap();
        self.load_protocol_locked(pid)
    }

    fn load_protocol_locked(&self, pid: &str) -> Result<Protocol, String> {
        if !is_simple_id(pid) {
            return Err("非法协议 id".to_string());
        }
        let pdir = self.root.join("protocols").join(pid);
        let meta = read_json(&pdir.join("meta.json"))?;
        let latest = meta.get("latest").and_then(|x| x.as_i64()).ok_or("meta 缺少 latest")? as usize;
        let mut revisions = Vec::new();
        for v in 1..=latest {
            let sj = read_json(&pdir.join(format!("v{v}.json")))?;
            let spec = Spec::from_json(&sj)?;
            let info = meta
                .get("revisions")
                .and_then(|x| x.as_array())
                .and_then(|a| a.iter().find(|r| r.get("version").and_then(|z| z.as_i64()) == Some(v as i64)));
            revisions.push(Revision {
                version: v,
                digest: spec_digest(&sj),
                created_at: info
                    .and_then(|r| r.get("created_at"))
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string(),
                note: info
                    .and_then(|r| r.get("note"))
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string(),
                spec_json: sj,
                spec,
            });
        }
        Ok(Protocol {
            id: pid.to_string(),
            name: meta.get("name").and_then(|x| x.as_str()).unwrap_or("").to_string(),
            latest,
            revisions,
        })
    }

    fn write_meta_locked(&self, proto: &Protocol) -> Result<(), String> {
        let mut revs = Vec::new();
        for r in &proto.revisions {
            revs.push(
                Json::obj()
                    .with("version", Json::Int(r.version as i64))
                    .with("digest", Json::Str(r.digest.clone()))
                    .with("created_at", Json::Str(r.created_at.clone()))
                    .with("note", Json::Str(r.note.clone())),
            );
        }
        let meta = Json::obj()
            .with("id", Json::Str(proto.id.clone()))
            .with("name", Json::Str(proto.name.clone()))
            .with("latest", Json::Int(proto.latest as i64))
            .with("revisions", Json::Arr(revs));
        atomic_write(
            &self.root.join("protocols").join(&proto.id).join("meta.json"),
            meta.dump_pretty().as_bytes(),
        )
    }
}

#[derive(Debug, Clone)]
pub struct ProtocolSummary {
    pub id: String,
    pub name: String,
    pub latest: usize,
}

pub fn spec_digest(j: &Json) -> String {
    crate::hash::hex_lower(&crate::hash::sha256(j.dump().as_bytes()))
}

pub fn read_json(path: &Path) -> Result<Json, String> {
    let text = fs::read_to_string(path).map_err(|e| format!("读取 {} 失败：{e}", path.display()))?;
    Json::parse(&text)
}

pub fn atomic_write(path: &Path, data: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, data).map_err(|e| e.to_string())?;
    fs::rename(&tmp, path).map_err(|e| e.to_string())
}

pub fn is_hex_id(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

pub fn is_simple_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 40
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

impl Store {
    fn unique_id(&self, prefix: &str) -> Result<String, String> {
        use std::time::{SystemTime, UNIX_EPOCH};
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let h = crate::hash::sha256(format!("{prefix}-{nanos}").as_bytes());
        let mut id = format!("{prefix}{}", &crate::hash::hex_lower(&h)[..16]);
        // 极小概率冲突时追加后缀
        let mut n = 1u32;
        let dir = if prefix == "p" { "protocols" } else { "sessions" };
        while self.root.join(dir).join(&id).exists() {
            id = format!("{prefix}{}-{n}", &crate::hash::hex_lower(&h)[..12]);
            n += 1;
        }
        Ok(id)
    }

    pub fn create_session(
        &self,
        title: &str,
        note: &str,
        protocol_id: &str,
        version: usize,
        blob: &str,
        byte_length: usize,
        report: &crate::model::ParseReport,
    ) -> Result<Session, String> {
        let _g = self.write_lock.lock().unwrap();
        self.create_session_locked(title, note, protocol_id, version, blob, byte_length, report)
    }

    pub(crate) fn create_session_locked(
        &self,
        title: &str,
        note: &str,
        protocol_id: &str,
        version: usize,
        blob: &str,
        byte_length: usize,
        report: &crate::model::ParseReport,
    ) -> Result<Session, String> {
        if !self.blob_exists(blob) {
            return Err("blob 不存在，请先导入样本".to_string());
        }
        // 确认协议版本存在（不可变）
        let proto = self.load_protocol_locked(protocol_id)?;
        if proto.revisions.iter().all(|r| r.version != version) {
            return Err(format!("协议 {protocol_id} 不存在版本 {version}"));
        }
        let id = self.unique_id("s")?;
        let ts = now_ts();
        let rev = SessionRev {
            at: ts.clone(),
            protocol_id: protocol_id.to_string(),
            version,
            blob: blob.to_string(),
            byte_length,
            status: report.status.as_str().to_string(),
            report_digest: report.report_digest(),
            tree_digest: report.tree_digest(),
        };
        let sess = Session {
            id: id.clone(),
            title: title.to_string(),
            note: note.to_string(),
            created_at: ts.clone(),
            updated_at: ts,
            current: rev.clone(),
            revisions: vec![rev],
        };
        self.write_session_locked(&sess)?;
        Ok(sess)
    }

    pub fn save_session_revision(
        &self,
        sid: &str,
        blob: &str,
        byte_length: usize,
        report: &crate::model::ParseReport,
    ) -> Result<Session, String> {
        let _g = self.write_lock.lock().unwrap();
        self.save_session_revision_locked(sid, blob, byte_length, report)
    }

    pub(crate) fn save_session_revision_locked(
        &self,
        sid: &str,
        blob: &str,
        byte_length: usize,
        report: &crate::model::ParseReport,
    ) -> Result<Session, String> {
        if !self.blob_exists(blob) {
            return Err("blob 不存在".to_string());
        }
        let mut sess = self.load_session_locked(sid)?;
        // 新字节修订：仍绑定同一个不可变协议版本
        let rev = SessionRev {
            at: now_ts(),
            protocol_id: sess.current.protocol_id.clone(),
            version: sess.current.version,
            blob: blob.to_string(),
            byte_length,
            status: report.status.as_str().to_string(),
            report_digest: report.report_digest(),
            tree_digest: report.tree_digest(),
        };
        sess.current = rev.clone();
        sess.revisions.push(rev);
        sess.updated_at = now_ts();
        self.write_session_locked(&sess)?;
        Ok(sess)
    }

    pub fn set_note(&self, sid: &str, title: Option<&str>, note: Option<&str>) -> Result<Session, String> {
        let _g = self.write_lock.lock().unwrap();
        let mut sess = self.load_session_locked(sid)?;
        if let Some(t) = title {
            sess.title = t.to_string();
        }
        if let Some(n) = note {
            sess.note = n.to_string();
        }
        sess.updated_at = now_ts();
        self.write_session_locked(&sess)?;
        Ok(sess)
    }

    pub fn list_sessions(&self) -> Result<Vec<Json>, String> {
        let mut out = Vec::new();
        let sdir = self.root.join("sessions");
        for entry in fs::read_dir(&sdir).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            if entry.path().extension().and_then(|x| x.to_str()) != Some("json") {
                continue;
            }
            let j = read_json(&entry.path())?;
            out.push(session_list_item(&j));
        }
        out.sort_by(|a, b| {
            b.get("updated_at")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .cmp(a.get("updated_at").and_then(|x| x.as_str()).unwrap_or(""))
        });
        Ok(out)
    }

    pub fn load_session(&self, sid: &str) -> Result<Session, String> {
        let _g = self.write_lock.lock().unwrap();
        self.load_session_locked(sid)
    }

    fn load_session_locked(&self, sid: &str) -> Result<Session, String> {
        if !is_simple_id(sid) || !sid.starts_with('s') {
            return Err("非法会话 id".to_string());
        }
        let j = read_json(&self.root.join("sessions").join(format!("{sid}.json")))?;
        session_from_json(&j)
    }

    fn write_session_locked(&self, sess: &Session) -> Result<(), String> {
        atomic_write(
            &self.root.join("sessions").join(format!("{}.json", sess.id)),
            session_to_json(sess).dump_pretty().as_bytes(),
        )
    }
}

fn rev_to_json(r: &SessionRev) -> Json {
    Json::obj()
        .with("at", Json::Str(r.at.clone()))
        .with("protocol_id", Json::Str(r.protocol_id.clone()))
        .with("version", Json::Int(r.version as i64))
        .with("blob", Json::Str(r.blob.clone()))
        .with("byte_length", Json::Int(r.byte_length as i64))
        .with("status", Json::Str(r.status.clone()))
        .with("report_digest", Json::Str(r.report_digest.clone()))
        .with("tree_digest", Json::Str(r.tree_digest.clone()))
}

fn rev_from_json(j: &Json) -> Result<SessionRev, String> {
    let g = |k: &str| j.get(k).ok_or_else(|| format!("会话修订缺少 {k}"));
    Ok(SessionRev {
        at: g("at")?.as_str().unwrap_or("").to_string(),
        protocol_id: g("protocol_id")?.as_str().unwrap_or("").to_string(),
        version: g("version")?.as_i64().ok_or("version 非整数")? as usize,
        blob: g("blob")?.as_str().ok_or("blob 非字符串")?.to_string(),
        byte_length: g("byte_length")?.as_i64().unwrap_or(0) as usize,
        status: g("status")?.as_str().unwrap_or("").to_string(),
        report_digest: g("report_digest")?.as_str().unwrap_or("").to_string(),
        tree_digest: g("tree_digest")?.as_str().unwrap_or("").to_string(),
    })
}

pub fn session_to_json(sess: &Session) -> Json {
    Json::obj()
        .with("id", Json::Str(sess.id.clone()))
        .with("title", Json::Str(sess.title.clone()))
        .with("note", Json::Str(sess.note.clone()))
        .with("created_at", Json::Str(sess.created_at.clone()))
        .with("updated_at", Json::Str(sess.updated_at.clone()))
        .with("current", rev_to_json(&sess.current))
        .with("revisions", Json::Arr(sess.revisions.iter().map(rev_to_json).collect()))
}

fn session_from_json(j: &Json) -> Result<Session, String> {
    let g = |k: &str| j.get(k).ok_or_else(|| format!("会话缺少 {k}"));
    let current = rev_from_json(g("current")?)?;
    let revisions = match g("revisions")?.as_array() {
        Some(a) => a.iter().map(rev_from_json).collect::<Result<Vec<_>, _>>()?,
        None => vec![current.clone()],
    };
    Ok(Session {
        id: g("id")?.as_str().unwrap_or("").to_string(),
        title: g("title")?.as_str().unwrap_or("").to_string(),
        note: g("note")?.as_str().unwrap_or("").to_string(),
        created_at: g("created_at")?.as_str().unwrap_or("").to_string(),
        updated_at: g("updated_at")?.as_str().unwrap_or("").to_string(),
        current,
        revisions,
    })
}

fn session_list_item(j: &Json) -> Json {
    let c = j.get("current").cloned().unwrap_or(Json::Null);
    Json::obj()
        .with("id", j.get("id").cloned().unwrap_or(Json::Null))
        .with("title", j.get("title").cloned().unwrap_or(Json::Null))
        .with("note", j.get("note").cloned().unwrap_or(Json::Null))
        .with("created_at", j.get("created_at").cloned().unwrap_or(Json::Null))
        .with("updated_at", j.get("updated_at").cloned().unwrap_or(Json::Null))
        .with("current", c)
        .with("revision_count", Json::Int(j.get("revisions").and_then(|x| x.as_array()).map(|a| a.len()).unwrap_or(0) as i64))
}

/// 导出包（确定性 JSON）。重新导入后版本、字节、诊断摘要、解析树摘要必须一致。
impl Store {
    pub fn export_session(&self, sid: &str) -> Result<Json, String> {
        let _g = self.write_lock.lock().unwrap();
        let sess = self.load_session_locked(sid)?;
        let proto = self.load_protocol_locked(&sess.current.protocol_id)?;
        let mut pkg_blobs: BTreeMap<String, String> = BTreeMap::new();
        for r in &sess.revisions {
            let bytes = self.get_blob(&r.blob)?;
            pkg_blobs.insert(r.blob.clone(), crate::hexutil::encode_hex(&bytes));
        }
        let mut pkg_revs = Vec::new();
        for r in &sess.revisions {
            pkg_revs.push(
                rev_to_json(r)
                    .with("hex", Json::Str(pkg_blobs.get(&r.blob).cloned().unwrap_or_default())),
            );
        }
        Ok(Json::obj()
            .with("package", Json::Str("frame-lab-session".to_string()))
            .with("format_version", Json::Int(1))
            .with(
                "session",
                Json::obj()
                    .with("id", Json::Str(sess.id.clone()))
                    .with("title", Json::Str(sess.title.clone()))
                    .with("note", Json::Str(sess.note.clone()))
                    .with("created_at", Json::Str(sess.created_at.clone()))
                    .with("updated_at", Json::Str(sess.updated_at.clone()))
                    .with("revisions", Json::Arr(pkg_revs)),
            )
            .with(
                "protocol",
                Json::obj()
                    .with("name", Json::Str(proto.name.clone()))
                    .with(
                        "revisions",
                        Json::Arr(
                            proto.revisions
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
                    ),
            ))
    }

    /// 导入。返回（导入后的会话，校验结果）。
    pub fn import_package(&self, pkg: &Json) -> Result<(Session, Json), String> {
        if pkg.get("package").and_then(|x| x.as_str()) != Some("frame-lab-session") {
            return Err("不是帧解析实验室导出的会话包".to_string());
        }
        let sess_j = pkg.get("session").ok_or("缺少 session")?;
        let proto_j = pkg.get("protocol").ok_or("缺少 protocol")?;
        let _g = self.write_lock.lock().unwrap();

        // 1) 协议：按版本摘要去重/对齐不可变版本
        let proto_name = proto_j.get("name").and_then(|x| x.as_str()).unwrap_or("导入的协议");
        let prevs = proto_j
            .get("revisions")
            .and_then(|x| x.as_array())
            .ok_or("protocol.revisions 必须是数组")?;
        let mut local_pid: Option<String> = None;
        let mut version_map: BTreeMap<usize, usize> = BTreeMap::new();
        for pr in prevs {
            let version = pr.get("version").and_then(|x| x.as_i64()).ok_or("协议版本缺少 version")? as usize;
            let spec = pr.get("spec").ok_or("协议版本缺少 spec")?;
            let note = pr.get("note").and_then(|x| x.as_str()).unwrap_or("");
            let digest = spec_digest(spec);
            // 在全部本地协议中寻找摘要一致的协议+版本
            let mut found: Option<(String, usize)> = None;
            for ps in self.list_protocols()? {
                let lp = self.load_protocol_locked(&ps.id)?;
                if let Some(r) = lp.revisions.iter().find(|r| r.digest == digest) {
                    found = Some((lp.id, r.version));
                    break;
                }
            }
            let (pid, local_v) = if let Some(f) = found {
                f
            } else if let Some(pid) = &local_pid {
                let r = self.save_version_locked(pid, spec, &format!("导入：{note}"))?;
                (pid.clone(), r.version)
            } else {
                let p = self.create_protocol_locked(proto_name, spec, &format!("导入：{note}"))?;
                (p.id.clone(), 1)
            };
            local_pid = Some(pid.clone());
            version_map.insert(version, local_v);
            let _ = pid;
        }

        // 2) blob 去重写入
        let mut blob_map: BTreeMap<String, String> = BTreeMap::new();
        for r in sess_j.get("revisions").and_then(|x| x.as_array()).ok_or("session.revisions 必须是数组")? {
            let old = r.get("blob").and_then(|x| x.as_str()).ok_or("修订缺少 blob")?;
            if !blob_map.contains_key(old) {
                let hex = r.get("hex").and_then(|x| x.as_str()).ok_or("修订缺少 hex 字节")?;
                let bytes = crate::hexutil::decode_hex(hex)?;
                let actual = crate::hash::hex_lower(&crate::hash::sha256(&bytes));
                if &actual != old {
                    return Err(format!("blob 内容与摘要不一致（{old}）"));
                }
                let new_hash = self.put_blob_locked(&bytes)?;
                blob_map.insert(old.to_string(), new_hash);
            }
        }

        // 3) 创建会话与全部修订（重放并校验摘要）
        let revs = sess_j.get("revisions").and_then(|x| x.as_array()).unwrap();
        let first = &revs[0];
        let first = strip_hex(first);
        let first = remap_revision(&first, &blob_map, local_pid.as_deref().unwrap_or(""), &version_map);
        let fr = rev_from_json(&first)?;
        let proto = self.load_protocol_locked(&fr.protocol_id)?;
        let spec = &proto.revisions.iter().find(|r| r.version == fr.version).unwrap().spec;
        let bytes = self.get_blob(&fr.blob)?;
        let report = crate::parser::parse(spec, &bytes);
        let mut checks = Vec::new();
        checks.push(verify_revision(&fr, &report));

        let title = sess_j.get("title").and_then(|x| x.as_str()).unwrap_or("导入的会话");
        let note = sess_j.get("note").and_then(|x| x.as_str()).unwrap_or("");
        let mut sess = self.create_session_locked(title, note, &fr.protocol_id, fr.version, &fr.blob, bytes.len(), &report)?;
        for r in &revs[1..] {
            let r = remap_revision(&strip_hex(r), &blob_map, &sess.current.protocol_id, &version_map);
            let rr = rev_from_json(&r)?;
            let spec = {
                let p = self.load_protocol_locked(&rr.protocol_id)?;
                p.revisions.iter().find(|x| x.version == rr.version).unwrap().spec.clone()
            };
            let bytes = self.get_blob(&rr.blob)?;
            let report = crate::parser::parse(&spec, &bytes);
            checks.push(verify_revision(&rr, &report));
            sess = self.save_session_revision_locked(&sess.id, &rr.blob, bytes.len(), &report)?;
        }

        let ok = checks.iter().all(|c| c.get("match").and_then(|x| x.as_bool()) == Some(true));
        let verify = Json::obj()
            .with("match", Json::Bool(ok))
            .with("revisions", Json::Arr(checks));
        Ok((sess, verify))
    }
}

fn strip_hex(r: &Json) -> Json {
    let mut j = r.clone();
    if let Json::Obj(m) = &mut j {
        m.remove("hex");
    }
    j
}

fn remap_revision(
    r: &Json,
    blob_map: &BTreeMap<String, String>,
    pid: &str,
    version_map: &BTreeMap<usize, usize>,
) -> Json {
    let mut j = r.clone();
    if let Json::Obj(m) = &mut j {
        if let Some(Json::Str(old)) = m.get("blob").cloned() {
            m.insert("blob".into(), Json::Str(blob_map.get(&old).cloned().unwrap_or(old)));
        }
        m.insert("protocol_id".into(), Json::Str(pid.to_string()));
        if let Some(Json::Int(v)) = m.get("version").cloned() {
            let nv = version_map.get(&(v as usize)).copied().unwrap_or(v as usize);
            m.insert("version".into(), Json::Int(nv as i64));
        }
    }
    j
}

fn verify_revision(stored: &SessionRev, report: &crate::model::ParseReport) -> Json {
    let status_ok = report.status.as_str() == stored.status;
    let report_ok = report.report_digest() == stored.report_digest;
    let tree_ok = report.tree_digest() == stored.tree_digest;
    Json::obj()
        .with("at", Json::Str(stored.at.clone()))
        .with("status", Json::Str(stored.status.clone()))
        .with(
            "match",
            Json::Bool(status_ok && report_ok && tree_ok),
        )
        .with("status_match", Json::Bool(status_ok))
        .with("report_digest_match", Json::Bool(report_ok))
        .with("tree_digest_match", Json::Bool(tree_ok))
        .with("replayed_report_digest", Json::Str(report.report_digest()))
        .with("replayed_tree_digest", Json::Str(report.tree_digest()))
}
