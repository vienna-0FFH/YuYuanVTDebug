//! 调试器项目保存/加载 (P88)
//!
//! 项目文件 (.gmproj, JSON):
//!   - target: { exe_name, module_name, last_pid (信息) }
//!   - watches: [{ address, type, description, frozen, frozen_bytes }]
//!   - bookmarks: [{ address, label, note }]
//!   - scanner_cuts: [{ value_type, op, value, result_count }]
//!   - notes: 全局备注 string
//!   - main_address: 当前光标地址
//!   - created_at, modified_at
//!
//! 最近列表存在 %LOCALAPPDATA%\GuardMetaVSP\recent_projects.json (最多 8 条).

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tauri::AppHandle;
use tauri_plugin_dialog::DialogExt;

use crate::util::error::{AppError, AppResult};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectTarget {
    pub exe_name: String,
    pub module_name: Option<String>,
    pub last_pid: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectWatch {
    pub address: String,           // 十六进制 (前端 BigInt → hex string)
    pub type_: String,
    pub description: String,
    pub frozen: bool,
    pub frozen_bytes: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectBookmark {
    pub address: String,
    pub label: String,
    pub note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProjectDoc {
    #[serde(default = "default_version")]
    pub version: u32,
    pub target: Option<ProjectTarget>,
    #[serde(default)]
    pub watches: Vec<ProjectWatch>,
    #[serde(default)]
    pub bookmarks: Vec<ProjectBookmark>,
    #[serde(default)]
    pub notes: String,
    pub main_address: Option<String>,
    pub created_at: Option<u64>,
    pub modified_at: Option<u64>,
    /// P93 注解 (labels/comments/functions). 存为整个 AnnotationStore::Inner.
    #[serde(default)]
    pub annotations: Option<crate::commands::annotations::Inner>,
    /// P99 签名 (user/ai 起源).
    #[serde(default)]
    pub signatures: Option<crate::commands::sig_store::Inner>,
}

fn default_version() -> u32 { 1 }

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn recent_path() -> AppResult<PathBuf> {
    let base = std::env::var_os("LOCALAPPDATA")
        .or_else(|| std::env::var_os("APPDATA"))
        .map(PathBuf::from)
        .ok_or_else(|| AppError::Internal("LOCALAPPDATA".into()))?;
    let dir = base.join("GuardMetaVSP");
    std::fs::create_dir_all(&dir).map_err(|e| AppError::Internal(format!("mkdir: {e}")))?;
    Ok(dir.join("recent_projects.json"))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecentEntry {
    pub path: String,
    pub name: String,
    pub modified: u64,
}

fn load_recent() -> Vec<RecentEntry> {
    let Ok(p) = recent_path() else { return Vec::new(); };
    let Ok(raw) = std::fs::read_to_string(&p) else { return Vec::new(); };
    serde_json::from_str(&raw).unwrap_or_default()
}

fn save_recent(list: &[RecentEntry]) {
    if let Ok(p) = recent_path() {
        let _ = std::fs::write(&p, serde_json::to_string_pretty(list).unwrap_or_default());
    }
}

fn push_recent(path_str: &str) {
    let mut list = load_recent();
    list.retain(|e| e.path != path_str);
    let name = Path::new(path_str)
        .file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_else(|| path_str.to_string());
    list.insert(0, RecentEntry { path: path_str.to_string(), name, modified: now_secs() });
    list.truncate(8);
    save_recent(&list);
}

#[tauri::command]
pub fn project_save(
    anno: tauri::State<'_, std::sync::Arc<crate::commands::annotations::AnnotationStore>>,
    sigs: tauri::State<'_, std::sync::Arc<crate::commands::sig_store::SignatureStore>>,
    path: String,
    mut doc: ProjectDoc,
) -> AppResult<()> {
    if doc.created_at.is_none() { doc.created_at = Some(now_secs()); }
    doc.modified_at = Some(now_secs());
    if doc.version == 0 { doc.version = 1; }
    doc.annotations = Some(anno.snapshot());
    doc.signatures = Some(sigs.snapshot());
    let s = serde_json::to_string_pretty(&doc)
        .map_err(|e| AppError::Internal(format!("encode: {e}")))?;
    std::fs::write(&path, s).map_err(|e| AppError::Internal(format!("写 {path}: {e}")))?;
    push_recent(&path);
    Ok(())
}

#[tauri::command]
pub fn project_load(
    anno: tauri::State<'_, std::sync::Arc<crate::commands::annotations::AnnotationStore>>,
    sigs: tauri::State<'_, std::sync::Arc<crate::commands::sig_store::SignatureStore>>,
    path: String,
) -> AppResult<ProjectDoc> {
    let raw = std::fs::read_to_string(&path)
        .map_err(|e| AppError::Internal(format!("读 {path}: {e}")))?;
    let doc: ProjectDoc = serde_json::from_str(&raw)
        .map_err(|e| AppError::Internal(format!("解析 {path}: {e}")))?;
    if let Some(a) = &doc.annotations {
        anno.replace(a.clone());
    } else {
        anno.replace(crate::commands::annotations::Inner::default());
    }
    if let Some(s) = &doc.signatures {
        sigs.replace(s.clone());
    }
    // 不重置 sigs — 让全局库的签名跟项目签名合并 (项目签名会覆盖同 id 的全局)
    push_recent(&path);
    Ok(doc)
}

#[tauri::command]
pub fn project_list_recent() -> AppResult<Vec<RecentEntry>> {
    // 过滤已被删除的文件
    let mut list = load_recent();
    list.retain(|e| Path::new(&e.path).exists());
    save_recent(&list);
    Ok(list)
}

/// 弹保存对话框 (主线程要 await), 返回选中路径或 None
#[tauri::command]
pub async fn project_pick_save(app: AppHandle, default_name: Option<String>) -> AppResult<Option<String>> {
    use tokio::sync::oneshot;
    let (tx, rx) = oneshot::channel();
    let name = default_name.unwrap_or_else(|| "未命名.gmproj".into());
    app.dialog().file()
        .add_filter("GuardMeta 项目", &["gmproj"])
        .set_file_name(&name)
        .save_file(move |p| { let _ = tx.send(p); });
    match rx.await {
        Ok(Some(fp)) => Ok(Some(fp.to_string())),
        _ => Ok(None),
    }
}

#[tauri::command]
pub async fn project_pick_open(app: AppHandle) -> AppResult<Option<String>> {
    use tokio::sync::oneshot;
    let (tx, rx) = oneshot::channel();
    app.dialog().file()
        .add_filter("GuardMeta 项目", &["gmproj"])
        .pick_file(move |p| { let _ = tx.send(p); });
    match rx.await {
        Ok(Some(fp)) => Ok(Some(fp.to_string())),
        _ => Ok(None),
    }
}
