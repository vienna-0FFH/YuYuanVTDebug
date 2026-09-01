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
use serde_json::{json, Value};

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
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        format!("art_{now:016x}_{n:08x}")
    }
}

impl AiSession {
    pub fn store_artifact(&self, store: &AiSessionStore, kind: &str, summary: String, size: u64, data: Value) -> String {
        let id = store.next_artifact_id();
        let artifact = Artifact { id: id.clone(), kind: kind.to_string(), summary, size, data };
        if let Ok(path) = artifact_file(&self.id, &id) {
            let _ = serde_json::to_vec(&artifact)
                .ok()
                .and_then(|bytes| std::fs::write(&path, bytes).ok());
        }
        self.artifacts.lock().unwrap().insert(id.clone(), artifact);
        id
    }

    pub fn get_artifact(&self, id: &str) -> Option<Artifact> {
        if let Some(artifact) = self.artifacts.lock().unwrap().get(id).cloned() {
            return Some(artifact);
        }
        let path = artifact_file(&self.id, id).ok()?;
        let bytes = std::fs::read(path).ok()?;
        serde_json::from_slice(&bytes).ok()
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
// 每行一条 JSON 事件. history_snapshot 建立无损基线, compaction_commit 原子替换活动上下文,
// 其余 user/assistant/tool_result 继续增量追加. started/failed/complete 不参与恢复.

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

fn artifact_file(session_id: &str, artifact_id: &str) -> std::io::Result<PathBuf> {
    let directory = sessions_dir()?.join("artifacts").join(sanitize(session_id));
    std::fs::create_dir_all(&directory)?;
    Ok(directory.join(format!("{}.json", sanitize(artifact_id))))
}

pub fn append_log(id: &str, line: &Value) -> std::io::Result<()> {
    append_log_inner(id, line, false)
}

pub fn append_log_durable(id: &str, line: &Value) -> std::io::Result<()> {
    append_log_inner(id, line, true)
}

pub fn ensure_history_snapshot(id: &str, active_messages: &[Value], history_messages: &[Value]) -> std::io::Result<bool> {
    let path = session_file(id)?;
    if path.exists() && path.metadata()?.len() > 0 {
        return Ok(false);
    }
    append_log_durable(id, &json!({
        "kind": "history_snapshot",
        "payload": {
            "active_messages": active_messages,
            "history_messages": history_messages,
        },
    }))?;
    Ok(true)
}

fn append_log_inner(id: &str, line: &Value, durable: bool) -> std::io::Result<()> {
    use std::io::Write;
    let p = session_file(id)?;
    let mut f = std::fs::OpenOptions::new().append(true).create(true).open(&p)?;
    let mut s = serde_json::to_string(line).unwrap_or_default();
    s.push('\n');
    f.write_all(s.as_bytes())?;
    if durable {
        f.sync_data()?;
    }
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
            if v.get("kind").and_then(|k| k.as_str()) == Some("history_snapshot") {
                let preview = v.pointer("/payload/active_messages")
                    .and_then(Value::as_array)
                    .and_then(|messages| messages.iter().find(|message| {
                        message.get("role").and_then(Value::as_str) == Some("user")
                    }))
                    .and_then(|message| message.get("content"))
                    .and_then(Value::as_str)
                    .unwrap_or("");
                if !preview.is_empty() {
                    return Ok(Some(preview.chars().take(80).collect()));
                }
            }
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
            apply_session_record(&mut out, &v);
        }
    }
    Ok(out)
}

pub fn load_session_history(id: &str) -> std::io::Result<Vec<Value>> {
    use std::io::BufRead;
    let p = session_file(id)?;
    if !p.exists() { return Ok(Vec::new()); }
    let f = std::fs::File::open(&p)?;
    let reader = std::io::BufReader::new(f);
    let mut out = Vec::new();
    for line in reader.lines().flatten() {
        let Ok(record) = serde_json::from_str::<Value>(&line) else { continue; };
        apply_history_record(&mut out, &record);
    }
    Ok(out)
}

fn apply_history_record(out: &mut Vec<Value>, record: &Value) {
    let kind = record.get("kind").and_then(Value::as_str).unwrap_or("");
    if kind == "history_snapshot" {
        if let Some(history) = record.pointer("/payload/history_messages").and_then(Value::as_array)
            .or_else(|| record.pointer("/payload/active_messages").and_then(Value::as_array))
        {
            *out = history.clone();
        }
        return;
    }
    if matches!(kind, "user" | "assistant" | "tool_result") {
        if let Some(payload) = record.get("payload") {
            if payload.get("role").and_then(Value::as_str).is_some() {
                out.push(payload.clone());
            }
        }
    }
}

fn apply_session_record(out: &mut Vec<Value>, record: &Value) {
    let kind = record.get("kind").and_then(Value::as_str).unwrap_or("");
    if matches!(kind, "history_snapshot" | "compaction_commit" | "tool_prune_commit") {
        if let Some(active) = record.pointer("/payload/active_messages").and_then(Value::as_array) {
            *out = active.clone();
        }
        return;
    }
    if !matches!(kind, "user" | "assistant" | "tool_result") {
        return;
    }
    if let Some(payload) = record.get("payload") {
        if payload.get("role").and_then(Value::as_str).is_some() {
            out.push(payload.clone());
        }
    }
}

pub fn delete_session(id: &str) -> std::io::Result<()> {
    let p = session_file(id)?;
    if p.exists() { std::fs::remove_file(&p)?; }
    let artifacts = sessions_dir()?.join("artifacts").join(sanitize(id));
    if artifacts.exists() { std::fs::remove_dir_all(artifacts)?; }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn latest_compaction_commit_replaces_prior_active_context() {
        let mut active = Vec::new();
        apply_session_record(&mut active, &json!({
            "kind": "history_snapshot",
            "payload": { "active_messages": [
                { "role": "user", "content": "old user" },
                { "role": "assistant", "content": "old assistant" }
            ] }
        }));
        apply_session_record(&mut active, &json!({
            "kind": "compaction_started",
            "payload": { "id": "compact-1" }
        }));
        assert_eq!(active.len(), 2);

        apply_session_record(&mut active, &json!({
            "kind": "compaction_commit",
            "payload": { "active_messages": [
                { "role": "system", "content": "summary", "_guardmeta": { "kind": "compaction" } },
                { "role": "user", "content": "recent" }
            ] }
        }));
        apply_session_record(&mut active, &json!({
            "kind": "assistant",
            "payload": { "role": "assistant", "content": "continued" }
        }));
        apply_session_record(&mut active, &json!({
            "kind": "complete",
            "payload": { "summary": "not a chat message" }
        }));

        assert_eq!(active.len(), 3);
        assert_eq!(active[0].get("content").and_then(Value::as_str), Some("summary"));
        assert_eq!(active[2].get("content").and_then(Value::as_str), Some("continued"));
    }

    #[test]
    fn artifact_survives_in_memory_session_eviction() {
        let store = AiSessionStore::new();
        let session_id = format!("artifact-test-{}", std::process::id());
        let session = store.get_or_create(&session_id);
        let artifact_id = session.store_artifact(
            &store,
            "test",
            "persisted test artifact".to_string(),
            11,
            json!({ "value": "hello world" }),
        );
        session.artifacts.lock().unwrap().clear();
        let restored = session.get_artifact(&artifact_id).expect("artifact on disk");
        assert_eq!(restored.kind, "test");
        assert_eq!(restored.data.pointer("/value").and_then(Value::as_str), Some("hello world"));
        delete_session(&session_id).expect("cleanup artifact test");
    }

    #[test]
    fn display_history_ignores_context_replacement_events() {
        let mut history = Vec::new();
        apply_history_record(&mut history, &json!({
            "kind": "history_snapshot",
            "payload": {
                "active_messages": [{ "role": "system", "content": "summary" }],
                "history_messages": [
                    { "role": "user", "content": "original user" },
                    { "role": "assistant", "content": "original answer" }
                ]
            }
        }));
        apply_history_record(&mut history, &json!({
            "kind": "tool_prune_commit",
            "payload": { "active_messages": [{ "role": "system", "content": "pruned" }] }
        }));
        apply_history_record(&mut history, &json!({
            "kind": "assistant",
            "payload": { "role": "assistant", "content": "continued answer" }
        }));
        assert_eq!(history.len(), 3);
        assert_eq!(history[0].get("content").and_then(Value::as_str), Some("original user"));
        assert_eq!(history[2].get("content").and_then(Value::as_str), Some("continued answer"));
    }
}
