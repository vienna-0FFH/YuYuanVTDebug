//! 项目级签名管理 (P99) — 把签名从硬编码 .ts 文件搬到运行时 store + .gmproj 持久化.
//!
//! 数据模型: HashMap<id, StoredSig>.
//! 持久化两份:
//!   - 全局库: %LOCALAPPDATA%\GuardMetaVSP\signatures.json (跨项目共享)
//!   - 当前项目: ProjectDoc.signatures (P88 持久化, 跟当前游戏绑)
//!
//! 来源 source:
//!   - "builtin": signatures.ts 硬编码 (默认显示, 不写入项目, 不可修改)
//!   - "user": 用户手动加
//!   - "ai": AI 工具发现的, 自动标 confirmed=false 等用户/sig_validate 验证

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::util::error::{AppError, AppResult};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredSig {
    pub id: String,
    pub name: String,
    /// 适用引擎. ["UE4", "UE5", "Unity"] etc. 空 = 通用
    #[serde(default)]
    pub engine: Vec<String>,
    /// CE 风格 AOB, "48 8B 05 ?? ?? ?? ??" — `?`/`??` 都算通配
    pub pattern: String,
    pub follow_rip: bool,
    /// "main_module" / "specific_module:<name>" / "all"
    pub scope: String,
    #[serde(default)]
    pub description: String,
    /// "builtin" / "user" / "ai"
    pub source: String,
    #[serde(default)]
    pub confirmed: bool,
    /// 上次扫描成功后的最终地址 (跟随 RIP 后) — 用于 sig_validate 快速比对
    pub last_addr: Option<u64>,
    /// 上次测试时间 (unix secs)
    pub last_tested_at: Option<u64>,
    /// 关联模块 — 用于在多游戏切换时记录"哪个游戏哪个 exe"
    pub target_exe: Option<String>,
}

#[derive(Debug, Default)]
pub struct SignatureStore {
    inner: Mutex<Inner>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Inner {
    pub sigs: HashMap<String, StoredSig>,
}

impl SignatureStore {
    pub fn new() -> Self { Self::default() }
    pub fn snapshot(&self) -> Inner { self.inner.lock().unwrap().clone() }
    pub fn replace(&self, data: Inner) { *self.inner.lock().unwrap() = data; }

    pub fn upsert(&self, sig: StoredSig) {
        self.inner.lock().unwrap().sigs.insert(sig.id.clone(), sig);
    }
    pub fn remove(&self, id: &str) -> bool {
        self.inner.lock().unwrap().sigs.remove(id).is_some()
    }
    pub fn get(&self, id: &str) -> Option<StoredSig> {
        self.inner.lock().unwrap().sigs.get(id).cloned()
    }
    pub fn list(&self) -> Vec<StoredSig> {
        let mut v: Vec<_> = self.inner.lock().unwrap().sigs.values().cloned().collect();
        v.sort_by(|a, b| a.name.cmp(&b.name));
        v
    }
}

// ===== 全局库持久化 (%LOCALAPPDATA%\GuardMetaVSP\signatures.json) =====

fn lib_path() -> AppResult<PathBuf> {
    let base = std::env::var_os("LOCALAPPDATA")
        .or_else(|| std::env::var_os("APPDATA"))
        .map(PathBuf::from)
        .ok_or_else(|| AppError::Internal("LOCALAPPDATA".into()))?;
    let dir = base.join("GuardMetaVSP");
    std::fs::create_dir_all(&dir).map_err(|e| AppError::Internal(format!("mkdir: {e}")))?;
    Ok(dir.join("signatures.json"))
}

pub fn load_library() -> Inner {
    let Ok(p) = lib_path() else { return Inner::default() };
    let Ok(raw) = std::fs::read_to_string(&p) else { return Inner::default() };
    serde_json::from_str(&raw).unwrap_or_default()
}

pub fn save_library(data: &Inner) {
    if let Ok(p) = lib_path() {
        if let Ok(s) = serde_json::to_string_pretty(data) {
            let _ = std::fs::write(&p, s);
        }
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ===== Tauri commands (前端 + AI 共用) =====

#[derive(Debug, Deserialize)]
pub struct SaveSigReq {
    pub id: Option<String>,
    pub name: String,
    #[serde(default)]
    pub engine: Vec<String>,
    pub pattern: String,
    pub follow_rip: bool,
    pub scope: String,
    #[serde(default)]
    pub description: String,
    /// 默认 "user", AI 调时传 "ai"
    pub source: Option<String>,
    pub target_exe: Option<String>,
}

fn gen_id(name: &str) -> String {
    let now = now_secs();
    let slug: String = name.trim().to_lowercase()
        .chars().filter(|c| c.is_ascii_alphanumeric() || *c == '_').take(40).collect();
    if slug.is_empty() {
        format!("sig_{:x}", now)
    } else {
        format!("{slug}_{:x}", now)
    }
}

#[tauri::command]
pub fn sig_list(store: tauri::State<'_, std::sync::Arc<SignatureStore>>) -> AppResult<Vec<StoredSig>> {
    Ok(store.list())
}

#[tauri::command]
pub fn sig_save(
    store: tauri::State<'_, std::sync::Arc<SignatureStore>>,
    req: SaveSigReq,
) -> AppResult<StoredSig> {
    if req.pattern.trim().is_empty() {
        return Err(AppError::Internal("pattern 不能为空".into()));
    }
    let id = req.id.unwrap_or_else(|| gen_id(&req.name));
    let existing = store.get(&id);
    let sig = StoredSig {
        id: id.clone(),
        name: req.name.trim().to_string(),
        engine: req.engine,
        pattern: req.pattern.trim().to_string(),
        follow_rip: req.follow_rip,
        scope: req.scope.trim().to_string(),
        description: req.description,
        source: req.source.unwrap_or_else(|| "user".into()),
        confirmed: existing.as_ref().map(|s| s.confirmed).unwrap_or(false),
        last_addr: existing.as_ref().and_then(|s| s.last_addr),
        last_tested_at: existing.as_ref().and_then(|s| s.last_tested_at),
        target_exe: req.target_exe.or_else(|| existing.as_ref().and_then(|s| s.target_exe.clone())),
    };
    store.upsert(sig.clone());
    // 同时落盘到全局库
    let mut lib = load_library();
    lib.sigs.insert(id.clone(), sig.clone());
    save_library(&lib);
    Ok(sig)
}

#[tauri::command]
pub fn sig_delete(
    store: tauri::State<'_, std::sync::Arc<SignatureStore>>,
    id: String,
) -> AppResult<bool> {
    let removed = store.remove(&id);
    if removed {
        let mut lib = load_library();
        lib.sigs.remove(&id);
        save_library(&lib);
    }
    Ok(removed)
}

#[tauri::command]
pub fn sig_snapshot(store: tauri::State<'_, std::sync::Arc<SignatureStore>>) -> AppResult<Inner> {
    Ok(store.snapshot())
}

#[tauri::command]
pub fn sig_replace(
    store: tauri::State<'_, std::sync::Arc<SignatureStore>>,
    data: Inner,
) -> AppResult<()> {
    store.replace(data);
    Ok(())
}

/// 用于 sig_test/validate 后回填状态
pub fn mark_tested(store: &SignatureStore, id: &str, last_addr: Option<u64>) {
    let mut i = store.inner.lock().unwrap();
    if let Some(s) = i.sigs.get_mut(id) {
        s.last_addr = last_addr;
        s.last_tested_at = Some(now_secs());
        s.confirmed = last_addr.is_some();
    }
}
