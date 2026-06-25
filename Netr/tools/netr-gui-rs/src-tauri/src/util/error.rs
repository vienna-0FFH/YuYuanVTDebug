//! 统一错误类型。
//!
//! 设计要点:
//! - 所有 command 返回 `Result<T, AppError>`,Tauri 自动序列化 `AppError` 给前端。
//! - 字段 `kind` 用稳定字符串,前端按 kind 做条件提示(国际化 / 重试逻辑)。
//! - 字段 `message` 是给用户看的中文。
//! - 字段 `detail` 给开发者 / 日志。

use serde::Serialize;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("license: {0}")]
    License(String),

    #[error("network: {0}")]
    Network(String),

    #[error("auth invalid")]
    AuthInvalid,

    #[error("not authorized")]
    NotAuthorized,

    #[error("io: {0}")]
    Io(String),

    #[error("internal: {0}")]
    Internal(String),
}

impl AppError {
    pub fn kind(&self) -> &'static str {
        match self {
            AppError::License(_) => "license",
            AppError::Network(_) => "network",
            AppError::AuthInvalid => "auth_invalid",
            AppError::NotAuthorized => "not_authorized",
            AppError::Io(_) => "io",
            AppError::Internal(_) => "internal",
        }
    }
}

/// 前端能看到的扁平形态。
#[derive(Debug, Serialize)]
pub struct AppErrorWire {
    pub kind: &'static str,
    pub message: String,
}

impl Serialize for AppError {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        AppErrorWire {
            kind: self.kind(),
            message: self.to_string(),
        }
        .serialize(s)
    }
}

// 常见 from
impl From<yuyuan_client::ClientError> for AppError {
    fn from(e: yuyuan_client::ClientError) -> Self {
        use yuyuan_client::ClientError::*;
        match e {
            BadServerSignature | BadAuthSignature => AppError::AuthInvalid,
            Server { message, .. } => AppError::License(message),
            Http(err) => AppError::Network(err.to_string()),
            Json(err) => AppError::Network(format!("json: {err}")),
            NotAuthorized => AppError::NotAuthorized,
            NotConnected => AppError::Network("尚未握手".into()),
            other => AppError::License(other.to_string()),
        }
    }
}

impl From<keyring::Error> for AppError {
    fn from(e: keyring::Error) -> Self {
        AppError::Io(format!("keyring: {e}"))
    }
}

impl From<serde_json::Error> for AppError {
    fn from(e: serde_json::Error) -> Self {
        AppError::Internal(format!("json: {e}"))
    }
}

pub type AppResult<T> = Result<T, AppError>;
