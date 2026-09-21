//! 仓库目录持久化：协议版本、内容寻址 blob、会话与导入导出包。

use crate::dsl_check::compile;
use crate::json::Json;
use crate::parser;
use crate::sha256;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

pub const PACKAGE_FORMAT: &str = "frame-lab-session-package/1";

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

fn short_hash(data: &[u8], prefix: &str, n: usize) -> String {
    let h = sha256::hex(data);
    format!("{}{}", prefix, &h[..n])
}

pub struct LabStore {
    root: PathBuf,
    pub lock: Mutex<()>,
}

#[derive(Debug)]
pub struct ImportReport {
    pub protocol_id: String,
    pub version_id: String,
    pub blob_id: String,
    pub session_id: String,
    pub reused_blob: bool,
    pub reused_session: bool,
    pub reused_version: bool,
}

impl LabStore {
    pub fn open(root: impl AsRef<Path>) -> std::io::Result<LabStore> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(root.join("protocols"))?;
        fs::create_dir_all(root.join("blobs"))?;
        fs::create_dir_all(root.join("sessions"))?;
        let store = LabStore {
            root,
            lock: Mutex::new(()),
        };
        store.seed_if_empty()?;
        Ok(store)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn seed_if_empty(&self) -> std::io::Result<()> {
        let protocols_dir = self.root.join("protocols");
        let any = fs::read_dir(&protocols_dir)?.next().is_some();
        if any {
            return Ok(());
        }
        for (_key, source) in crate::seeds::all() {
            if let Ok(protocol) = compile(source) {
                let _ = self.save_version(&protocol.name, source);
            }
        }
        Ok(())
    }
}

fn read_json(path: &Path) -> std::io::Result<Json> {
    let text = fs::read_to_string(path)?;
    crate::json::parse(&text)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

fn write_json(path: &Path, j: &Json) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, j.pretty())?;
    fs::rename(&tmp, path)
}

impl LabStore {
    // ---------- 协议与版本 ----------

    fn protocol_dir(&self, protocol_id: &str) -> PathBuf {
        self.root.join("protocols").join(protocol_id)
    }

    fn version_path(&self, protocol_id: &str, version_id: &str) -> PathBuf {
        self.protocol_dir(protocol_id)
            .join("versions")
            .join(format!("{}.json", version_id))
    }

    /// 保存一个新版本。相同名称 + 相同 DSL 内容复用同一不可变版本。
    pub fn save_version(&self, name: &str, source: &str) -> std::io::Result<(String, String, bool)> {
        compile(source).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
        let protocol_id = short_hash(name.as_bytes(), "p", 12);
        let pdir = self.protocol_dir(&protocol_id);
        fs::create_dir_all(pdir.join("versions"))?;
        let meta_path = pdir.join("protocol.json");
        let mut meta = if meta_path.exists() {
            read_json(&meta_path)?
        } else {
            let mut m = Json::obj();
            m.put("id", Json::str(&protocol_id));
            m.put("name", Json::str(name));
            m.put("created_at", Json::Int(now_ms() as i64));
            m
        };
        meta.put("name", Json::str(name));
        write_json(&meta_path, &meta)?;

        let mut canon = Json::obj();
        canon.put("name", Json::str(name));
        canon.put("source", Json::str(source));
        let version_id = short_hash(canon.canonical().as_bytes(), "v", 12);
        let vpath = self.version_path(&protocol_id, &version_id);
        let reused = vpath.exists();
        if !reused {
            let mut v = Json::obj();
            v.put("id", Json::str(&version_id));
            v.put("protocol_id", Json::str(&protocol_id));
            v.put("name", Json::str(name));
            v.put("source", Json::str(source));
            v.put("created_at", Json::Int(now_ms() as i64));
            v.put("immutable", Json::Bool(true));
            write_json(&vpath, &v)?;
        }
        Ok((protocol_id, version_id, reused))
    }

    pub fn list_protocols(&self) -> std::io::Result<Vec<Json>> {
        let mut out = Vec::new();
        for entry in fs::read_dir(self.root.join("protocols"))? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            let meta_path = entry.path().join("protocol.json");
            if meta_path.exists() {
                if let Ok(meta) = read_json(&meta_path) {
                    let versions = self.list_versions(
                        meta.get("id")
                            .and_then(|v| v.as_str())
                            .unwrap_or_default(),
                    )?;
                    let mut m = meta;
                    m.put("versions", Json::Arr(versions));
                    out.push(m);
                }
            }
        }
        out.sort_by(|a, b| {
            a.get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .cmp(b.get("name").and_then(|v| v.as_str()).unwrap_or(""))
        });
        Ok(out)
    }

    pub fn list_versions(&self, protocol_id: &str) -> std::io::Result<Vec<Json>> {
        let vdir = self.protocol_dir(protocol_id).join("versions");
        let mut out = Vec::new();
        if !vdir.exists() {
            return Ok(out);
        }
        for entry in fs::read_dir(&vdir)? {
            let entry = entry?;
            if let Ok(v) = read_json(&entry.path()) {
                out.push(v);
            }
        }
        out.sort_by_key(|v| v.get("created_at").and_then(|c| c.as_i64()).unwrap_or(0));
        Ok(out)
    }

    pub fn get_version(&self, protocol_id: &str, version_id: &str) -> std::io::Result<Option<Json>> {
        let p = self.version_path(protocol_id, version_id);
        if p.exists() {
            Ok(Some(read_json(&p)?))
        } else {
            Ok(None)
        }
    }
}

impl LabStore {
    // ---------- blob 内容寻址 ----------

    pub fn put_blob(&self, bytes: &[u8]) -> std::io::Result<(String, bool)> {
        let blob_id = short_hash(bytes, "b", 16);
        let path = self.root.join("blobs").join(&blob_id);
        let reused = path.exists();
        if !reused {
            let tmp = path.with_extension("tmp");
            fs::write(&tmp, bytes)?;
            fs::rename(&tmp, &path)?;
        }
        Ok((blob_id, reused))
    }

    pub fn get_blob(&self, blob_id: &str) -> std::io::Result<Option<Vec<u8>>> {
        let path = self.root.join("blobs").join(blob_id);
        if path.exists() {
            Ok(Some(fs::read(path)?))
        } else {
            Ok(None)
        }
    }

    // ---------- 会话 ----------

    fn session_path(&self, session_id: &str) -> PathBuf {
        self.root
            .join("sessions")
            .join(format!("{}.json", session_id))
    }

    /// 创建会话：编译绑定版本，解析 blob，固化状态/诊断/树摘要。
    /// 会话 ID 由（版本、blob、备注）内容确定，同一输入重复创建指向同一会话。
    pub fn create_session(
        &self,
        protocol_id: &str,
        version_id: &str,
        bytes: &[u8],
        note: &str,
    ) -> std::io::Result<(Json, bool)> {
        let version = self
            .get_version(protocol_id, version_id)?
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("协议版本 {}/{} 不存在", protocol_id, version_id),
                )
            })?;
        let source = version
            .get("source")
            .and_then(|v| v.as_str())
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "版本缺少 source"))?;
        let protocol = compile(source)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        let (blob_id, reused_blob) = self.put_blob(bytes)?;
        let parsed = parser::parse(&protocol, bytes);
        let result_json = parsed.to_json();
        let tree_summary = parsed.tree_summary();

        let mut session = Json::obj();
        session.put("protocol_id", Json::str(protocol_id));
        session.put("version_id", Json::str(version_id));
        session.put("protocol_name", Json::str(&protocol.name));
        session.put("blob_id", Json::str(&blob_id));
        session.put("byte_length", Json::Int(bytes.len() as i64));
        session.put("note", Json::str(note));
        session.put("status", Json::str(&parsed.status));
        session.put("result", result_json);
        session.put("tree_summary", Json::str(&tree_summary));
        session.put("package_format", Json::str(PACKAGE_FORMAT));
        session.put("created_at", Json::Int(now_ms() as i64));

        let session_id = short_hash(session.canonical().as_bytes(), "s", 16);
        session.put("id", Json::str(&session_id));

        let path = self.session_path(&session_id);
        let reused_session = path.exists();
        if !reused_session {
            write_json(&path, &session)?;
        }
        Ok((session, reused_blob || reused_session))
    }

    pub fn list_sessions(&self) -> std::io::Result<Vec<Json>> {
        let mut out = Vec::new();
        for entry in fs::read_dir(self.root.join("sessions"))? {
            let entry = entry?;
            if let Ok(s) = read_json(&entry.path()) {
                out.push(s);
            }
        }
        out.sort_by_key(|v| v.get("created_at").and_then(|c| c.as_i64()).unwrap_or(0));
        Ok(out)
    }

    pub fn get_session(&self, session_id: &str) -> std::io::Result<Option<Json>> {
        let p = self.session_path(session_id);
        if p.exists() {
            Ok(Some(read_json(&p)?))
        } else {
            Ok(None)
        }
    }

    /// 重放历史会话：始终用创建时绑定的版本重新解析其 blob，并与固化结论核对。
    pub fn replay_session(&self, session_id: &str) -> std::io::Result<Option<Json>> {
        let session = match self.get_session(session_id)? {
            Some(s) => s,
            None => return Ok(None),
        };
        let protocol_id = session.get("protocol_id").and_then(|v| v.as_str()).unwrap();
        let version_id = session.get("version_id").and_then(|v| v.as_str()).unwrap();
        let blob_id = session.get("blob_id").and_then(|v| v.as_str()).unwrap();
        let bound_summary = session
            .get("tree_summary")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let bound_status = session
            .get("status")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let version = self
            .get_version(protocol_id, version_id)?
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "绑定版本缺失"))?;
        let source = version.get("source").and_then(|v| v.as_str()).unwrap();
        let protocol = compile(source)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let bytes = self
            .get_blob(blob_id)?
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "绑定 blob 缺失"))?;
        let parsed = parser::parse(&protocol, &bytes);

        let mut report = Json::obj();
        report.put("bound_status", Json::str(&bound_status));
        report.put("replay_status", Json::str(&parsed.status));
        report.put("bound_tree_summary", Json::str(&bound_summary));
        report.put("replay_tree_summary", Json::str(&parsed.tree_summary()));
        report.put(
            "matches",
            Json::Bool(
                bound_status == parsed.status && bound_summary == parsed.tree_summary(),
            ),
        );
        report.put("replay", parsed.to_json());
        Ok(Some(report))
    }
}

impl LabStore {
    pub fn export_package(&self, session_id: &str) -> std::io::Result<Json> {
        let session = self
            .get_session(session_id)?
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "会话不存在"))?;
        let protocol_id = session
            .get("protocol_id")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let version_id = session
            .get("version_id")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let blob_id = session.get("blob_id").and_then(|v| v.as_str()).unwrap_or("");
        let version = self
            .get_version(protocol_id, version_id)?
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "版本缺失"))?;
        let bytes = self
            .get_blob(blob_id)?
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "blob 缺失"))?;

        let mut pkg = Json::obj();
        pkg.put("package_format", Json::str(PACKAGE_FORMAT));
        pkg.put("version", Json::obj().with("source", version.get("source").cloned().unwrap_or(Json::Null))
            .with("name", version.get("name").cloned().unwrap_or(Json::Null))
            .with("version_id", Json::str(version_id)));
        let mut hex_bytes = Json::obj();
        hex_bytes.put("hex", Json::str(&crate::hex::encode(&bytes)));
        hex_bytes.put("blob_id", Json::str(blob_id));
        pkg.put("bytes", hex_bytes);
        pkg.put("note", session.get("note").cloned().unwrap_or(Json::Str(String::new())));
        pkg.put("status", session.get("status").cloned().unwrap_or(Json::Null));
        pkg.put(
            "tree_summary",
            session.get("tree_summary").cloned().unwrap_or(Json::Null),
        );
        pkg.put(
            "result",
            session.get("result").cloned().unwrap_or(Json::Null),
        );
        Ok(pkg)
    }

    /// 导入会话包：重建/复用协议版本与 blob，重放后核对版本、字节、诊断与树摘要。
    pub fn import_package(&self, pkg: &Json) -> std::io::Result<ImportReport> {
        let format = pkg.get("package_format").and_then(|v| v.as_str());
        if format != Some(PACKAGE_FORMAT) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "不是帧解析实验室会话包",
            ));
        }
        let name = pkg
            .get("version")
            .and_then(|v| v.get("name"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "缺少版本名称"))?;
        let source = pkg
            .get("version")
            .and_then(|v| v.get("source"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "缺少 DSL source"))?;
        let hex = pkg
            .get("bytes")
            .and_then(|v| v.get("hex"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "缺少 hex 字节"))?;
        let bytes = crate::hex::decode(hex)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let note = pkg.get("note").and_then(|v| v.as_str()).unwrap_or("");
        let expected_summary = pkg
            .get("tree_summary")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let expected_status = pkg.get("status").and_then(|v| v.as_str()).unwrap_or("");

        let (protocol_id, version_id, reused_version) = self.save_version(name, source)?;
        let (blob_id, reused_blob) = self.put_blob(&bytes)?;
        let (session, reused_session) =
            self.create_session(&protocol_id, &version_id, &bytes, note)?;
        let session_id = session.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();

        let actual_status = session.get("status").and_then(|v| v.as_str()).unwrap_or("");
        let actual_summary = session
            .get("tree_summary")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if !expected_status.is_empty() && expected_status != actual_status {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "导入校验失败：status {} 与包内 {} 不一致",
                    actual_status, expected_status
                ),
            ));
        }
        if !expected_summary.is_empty() && expected_summary != actual_summary {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "导入校验失败：解析树摘要与包内不一致（版本被改动或字节损坏）",
            ));
        }

        // 诊断稳定性：警告数量/种类/路径/偏移一致
        if let (Some(expected_result), Some(actual_result)) =
            (pkg.get("result"), session.get("result"))
        {
            compare_diagnostics(expected_result, actual_result)?;
        }

        Ok(ImportReport {
            protocol_id,
            version_id,
            blob_id,
            session_id,
            reused_blob,
            reused_session,
            reused_version,
        })
    }
}

fn compare_diagnostics(expected: &Json, actual: &Json) -> std::io::Result<()> {
    let slim = |r: &Json| -> Json {
        let mut o = Json::obj();
        o.put("status", r.get("status").cloned().unwrap_or(Json::Null));
        if let Some(d) = r.get("diag") {
            let mut d2 = Json::obj();
            d2.put("kind", d.get("kind").cloned().unwrap_or(Json::Null));
            d2.put("path", d.get("path").cloned().unwrap_or(Json::Null));
            d2.put("offset", d.get("offset").cloned().unwrap_or(Json::Null));
            d2.put("need", d.get("need").cloned().unwrap_or(Json::Null));
            o.put("diag", d2);
        }
        let warns = r
            .get("warnings")
            .and_then(|w| w.as_array())
            .map(|ws| {
                ws.iter()
                    .map(|w| {
                        let mut d = Json::obj();
                        d.put("kind", w.get("kind").cloned().unwrap_or(Json::Null));
                        d.put("path", w.get("path").cloned().unwrap_or(Json::Null));
                        d.put("offset", w.get("offset").cloned().unwrap_or(Json::Null));
                        d
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        o.put("warnings", Json::Arr(warns));
        o
    };
    let a = slim(expected).canonical();
    let b = slim(actual).canonical();
    if a != b {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "导入校验失败：诊断（状态/路径/偏移/need）与包内不一致",
        ));
    }
    Ok(())
}
