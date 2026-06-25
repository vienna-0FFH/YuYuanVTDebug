//! AI 会话状态 (P87) — 取消, artifact store, 持久化
//!
//! 一个 GuardMeta 进程持有一个 `AiSessionStore`. 内部 map: session_id → AiSession.
//! 每次 `dbg_ai_run` 启动时, 前端给一个 session_id; 同 session_id 触发新轮就续上;
//! 用户点取消 → set cancel flag → 主循环每步检测后立即退出.
//!
//! Artifact: 大体积工具结果(ue_dump 全表 / find_globals top32 / read_memory > 2KB)
//! 不直接灌回 LLM, 只回 {id, summary, size}. LLM 想看具体内容调 read_artifact.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Default)]
pub struct AiSessionStore {
    sessions: Mutex<HashMap<String, Arc<AiSession>>>,
    artifact_seq: AtomicU64,
}

#[derive(Debug)]
pub struct AiSession {
    pub id: String,
    pub cancel: AtomicBool,
    pub artifacts: Mutex<HashMap<String, Artifact>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Artifact {
    pub id: String,
    pub kind: String,        // "ue_objects" / "globals" / "aob_hits" / "memory" ...
    pub summary: String,     // 一两句话给 LLM 看
    pub size: u64,           // 字节 / 元素数
    /// 完整内容. 这里直接放 Value, 不落盘. 重启就丢. P87.5 持久化时改 file.
    pub data: Value,
}

impl AiSessionStore {
    pub fn new() -> Self { Self::default() }

    pub fn get_or_create(&self, id: &str) -> Arc<AiSession> {
        let mut m = self.sessions.lock().unwrap();
        if let Some(s) = m.get(id) { return s.clone(); }
        let s = Arc::new(AiSession {
            id: id.to_string(),
            cancel: AtomicBool::new(false),
            artifacts: Mutex::new(HashMap::new()),
        });
        m.insert(id.to_string(), s.clone());
        s
    }

    pub fn get(&self, id: &str) -> Option<Arc<AiSession>> {
        self.sessions.lock().unwrap().get(id).cloned()
    }

    pub fn cancel(&self, id: &str) {
        if let Some(s) = self.get(id) {
            s.cancel.store(true, Ordering::SeqCst);
        }
    }

    /// 申请新 artifact id
    pub fn next_artifact_id(&self) -> String {
        let n = self.artifact_seq.fetch_add(1, Ordering::SeqCst);
        format!("art_{n:08x}")
    }
}

impl AiSession {
    pub fn store_artifact(&self, store: &AiSessionStore, kind: &str, summary: String, size: u64, data: Value) -> String {
        let id = store.next_artifact_id();
        let a = Artifact { id: id.clone(), kind: kind.to_string(), summary, size, data };
        self.artifacts.lock().unwrap().insert(id.clone(), a);
        id
    }

    pub fn get_artifact(&self, id: &str) -> Option<Artifact> {
        self.artifacts.lock().unwrap().get(id).cloned()
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancel.load(Ordering::SeqCst)
    }

    pub fn reset_cancel(&self) {
        self.cancel.store(false, Ordering::SeqCst);
    }
}

// ===== 持久化 (P87.5) =====
//
// 路径: %LOCALAPPDATA%\GuardMetaVSP\ai_sessions\{session_id}.jsonl
// 每行一条 JSON: { ts, kind: "user" | "assistant" | "tool_result" | "complete", payload }
// 启动列出文件, UI 可恢复; 加载时把 jsonl 还原成 history.

fn sessions_dir() -> std::io::Result<PathBuf> {
    let base = std::env::var_os("LOCALAPPDATA")
        .or_else(|| std::env::var_os("APPDATA"))
        .map(PathBuf::from)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "LOCALAPPDATA"))?;
    let dir = base.join("GuardMetaVSP").join("ai_sessions");
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

pub fn session_file(id: &str) -> std::io::Result<PathBuf> {
    Ok(sessions_dir()?.join(format!("{}.jsonl", sanitize(id))))
}

pub fn append_log(id: &str, line: &Value) -> std::io::Result<()> {
    use std::io::Write;
    let p = session_file(id)?;
    let mut f = std::fs::OpenOptions::new().append(true).create(true).open(&p)?;
    let mut s = serde_json::to_string(line).unwrap_or_default();
    s.push('\n');
    f.write_all(s.as_bytes())?;
    Ok(())
}

fn sanitize(s: &str) -> String {
    s.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_').collect()
}

#[derive(Debug, Serialize)]
pub struct SessionFileInfo {
    pub id: String,
    pub size_bytes: u64,
    pub modified: u64,        // unix seconds
    pub first_user: Option<String>,
}

pub fn list_sessions() -> std::io::Result<Vec<SessionFileInfo>> {
    let dir = sessions_dir()?;
    let mut out = Vec::new();
    for entry in std::fs::read_dir(&dir)? {
        let entry = entry?;
        let p = entry.path();
        if p.extension().map(|e| e == "jsonl").unwrap_or(false) {
            let meta = entry.metadata()?;
            let id = p.file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();
            let modified = meta.modified().ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0);
            // 抓第一条 user 作为预览
            let first_user = read_first_user(&p).ok().flatten();
            out.push(SessionFileInfo {
                id, size_bytes: meta.len(), modified, first_user,
            });
        }
    }
    out.sort_by_key(|s| std::cmp::Reverse(s.modified));
    Ok(out)
}

fn read_first_user(p: &std::path::Path) -> std::io::Result<Option<String>> {
    use std::io::BufRead;
    let f = std::fs::File::open(p)?;
    let reader = std::io::BufReader::new(f);
    for line in reader.lines().flatten() {
        if let Ok(v) = serde_json::from_str::<Value>(&line) {
            if v.get("kind").and_then(|k| k.as_str()) == Some("user") {
                let preview = v.pointer("/payload/content")
                    .and_then(|c| c.as_str())
                    .or_else(|| v.pointer("/payload/text").and_then(|c| c.as_str()))
                    .unwrap_or("");
                return Ok(Some(preview.chars().take(80).collect()));
            }
        }
    }
    Ok(None)
}

pub fn load_session(id: &str) -> std::io::Result<Vec<Value>> {
    use std::io::BufRead;
    let p = session_file(id)?;
    if !p.exists() { return Ok(Vec::new()); }
    let f = std::fs::File::open(&p)?;
    let reader = std::io::BufReader::new(f);
    let mut out = Vec::new();
    for line in reader.lines().flatten() {
        if let Ok(v) = serde_json::from_str::<Value>(&line) {
            if let Some(payload) = v.get("payload") {
                out.push(payload.clone());
            }
        }
    }
    Ok(out)
}

pub fn delete_session(id: &str) -> std::io::Result<()> {
    let p = session_file(id)?;
    if p.exists() { std::fs::remove_file(&p)?; }
    Ok(())
}
