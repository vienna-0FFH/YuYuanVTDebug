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

#[cfg(feature = "network-license")]
impl From<yuyuan_client::ClientError> for AppError {
    fn from(error: yuyuan_client::ClientError) -> Self {
        use yuyuan_client::ClientError::*;
        match error {
            BadServerSignature | BadAuthSignature => AppError::AuthInvalid,
            Server { message, .. } => AppError::License(message),
            Http(error) => AppError::Network(error.to_string()),
            Json(error) => AppError::Network(format!("json: {error}")),
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
