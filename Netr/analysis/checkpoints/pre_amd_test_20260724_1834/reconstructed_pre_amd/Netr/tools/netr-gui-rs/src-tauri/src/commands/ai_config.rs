//! AI 配置磁盘持久化 (P85)
//!
//! 用户报告 localStorage 偶尔丢失. 改成 LocalAppData 下一个文件存,
//! 重启不丢. 前端在 LlmConfigDialog::onSave 同时写 localStorage + 这个 IPC,
//! loadLlmConfig 先读 localStorage, 没有再问后端.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::util::error::{AppError, AppResult};

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct StoredAiConfig {
    pub provider: String,
    pub base_url: String,
    pub api_key: String,
    pub model: String,
    pub temperature: Option<f32>,
}

fn config_path() -> AppResult<PathBuf> {
    // %LOCALAPPDATA%\GuardMetaVSP\ai_config.json
    let base = std::env::var_os("LOCALAPPDATA")
        .or_else(|| std::env::var_os("APPDATA"))
        .map(PathBuf::from)
        .ok_or_else(|| AppError::Internal("无法解析 LOCALAPPDATA".into()))?;
    let dir = base.join("GuardMetaVSP");
    std::fs::create_dir_all(&dir).map_err(|e| AppError::Internal(format!("mkdir: {e}")))?;
    Ok(dir.join("ai_config.json"))
}

#[tauri::command]
pub fn ai_config_load() -> AppResult<Option<StoredAiConfig>> {
    let p = config_path()?;
    if !p.exists() { return Ok(None); }
    let raw = std::fs::read_to_string(&p)
        .map_err(|e| AppError::Internal(format!("读 {p:?}: {e}")))?;
    let cfg: StoredAiConfig = serde_json::from_str(&raw)
        .map_err(|e| AppError::Internal(format!("解析 {p:?}: {e}")))?;
    Ok(Some(cfg))
}

#[tauri::command]
pub fn ai_config_save(config: StoredAiConfig) -> AppResult<()> {
    let p = config_path()?;
    let s = serde_json::to_string_pretty(&config)
        .map_err(|e| AppError::Internal(format!("encode: {e}")))?;
    std::fs::write(&p, s).map_err(|e| AppError::Internal(format!("写 {p:?}: {e}")))?;
    Ok(())
}

#[tauri::command]
pub fn ai_config_clear() -> AppResult<()> {
    let p = config_path()?;
    if p.exists() {
        std::fs::remove_file(&p).map_err(|e| AppError::Internal(format!("删 {p:?}: {e}")))?;
    }
    Ok(())
}
