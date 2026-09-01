//! 用 Windows Credential Manager 持久化登录凭证。
//!
//! 设计:
//! - 只存 `username + password`,不存 token。
//!   理由:token 跟会话强耦合(token 有签发时间、心跳关联),重启后用旧 token
//!         再发请求,部署端可能已踢下线,反而误导。统一方案:重启后用 user+pass
//!         re-verify_account 一次,拿新 token,流程统一。
//! - 凭证存进 Windows Credential Manager(用户级,加密存储),普通文件读取者拿不到。
//!
//! keyring v3 在 Windows 上后端是 WinAPI `CredRead/CredWrite`,显示在
//! 控制面板 → 凭据管理器 → Windows 凭据 → "通用凭据" 下。

use keyring::Entry;
use serde::{Deserialize, Serialize};

use crate::util::error::{AppError, AppResult};

const SERVICE: &str = "netr.control";
const KEY_ACCOUNT: &str = "yuyuan-account";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredAccount {
    pub username: String,
    pub password: String,
}

pub fn load_account() -> AppResult<Option<StoredAccount>> {
    let entry = Entry::new(SERVICE, KEY_ACCOUNT)?;
    match entry.get_password() {
        Ok(json) => Ok(serde_json::from_str(&json)?),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(AppError::Io(format!("keyring read: {e}"))),
    }
}

pub fn save_account(acc: &StoredAccount) -> AppResult<()> {
    let entry = Entry::new(SERVICE, KEY_ACCOUNT)?;
    let json = serde_json::to_string(acc)?;
    entry.set_password(&json)?;
    Ok(())
}

pub fn clear_account() -> AppResult<()> {
    let entry = Entry::new(SERVICE, KEY_ACCOUNT)?;
    match entry.delete_credential() {
        Ok(()) => Ok(()),
        Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(AppError::Io(format!("keyring clear: {e}"))),
    }
}
