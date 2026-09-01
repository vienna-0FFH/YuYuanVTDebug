//! Global authorization state.
//!
//! The production path is `network-license`: it uses the private
//! yuyuan-client SDK and preserves the server-signed payload submitted to the
//! driver.  The repository can still be checked on a machine without that
//! SDK. With neither feature selected the current project workflow is open and
//! does not require a login. `dev-license-bypass` remains an explicit legacy
//! development path for compatibility.

use parking_lot::Mutex;
use serde::Serialize;

#[cfg(any(feature = "network-license", feature = "dev-license-bypass"))]
use crate::util::error::AppError;
use crate::util::error::AppResult;

#[cfg(feature = "network-license")]
use crate::license::hardcoded::{APP_KEY, DEPLOY_BASE_URL, DEPLOY_PUB_HEX};
#[cfg(feature = "network-license")]
use yuyuan_client::Client;

#[cfg(all(feature = "network-license", feature = "dev-license-bypass"))]
compile_error!("network-license and dev-license-bypass are mutually exclusive");

pub struct AuthState {
    inner: Mutex<Inner>,
}

#[cfg(feature = "network-license")]
struct Inner {
    client: Option<Client>,
}

#[cfg(all(not(feature = "network-license"), feature = "dev-license-bypass"))]
struct Inner {
    session: Option<AuthSession>,
}

#[cfg(all(
    not(feature = "network-license"),
    not(feature = "dev-license-bypass")
))]
struct Inner;

#[derive(Debug, Clone)]
pub struct AuthSession {
    pub token: String,
    pub subject_type: String,
    pub subject_id: i64,
    pub expires_at: i64,
    pub remaining_count: i64,
    pub notice: String,
    pub machine_code: String,
}

#[derive(Debug, Clone)]
pub struct LicensePayload {
    pub app_key: String,
    pub subject_type: String,
    pub subject_id: i64,
    pub machine_code: String,
    pub expires_at: i64,
    pub token: String,
    /// base64(64-byte Ed25519 signature) supplied by the deployment server.
    pub auth_sig_b64: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct TopupSummary {
    pub message: String,
    pub expires_at: i64,
    pub remaining_count: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct HeartbeatSummary {
    pub online: bool,
    pub expires_at: i64,
    pub remaining_count: i64,
    pub server_time: i64,
    pub message: String,
}

#[cfg(feature = "network-license")]
impl AuthState {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Inner { client: None }),
        }
    }

    pub fn login(&self, username: &str, password: &str) -> AppResult<AuthSession> {
        let mut client = Client::new(DEPLOY_BASE_URL, APP_KEY, DEPLOY_PUB_HEX)
            .map_err(|e| AppError::Internal(format!("client new: {e}")))?;
        let auth = client.verify_account(username, password)?;
        let session = AuthSession {
            token: auth.token.clone(),
            subject_type: auth.subject_type.clone(),
            subject_id: auth.subject_id,
            expires_at: auth.expires_at,
            remaining_count: auth.remaining_count,
            notice: auth.notice.clone(),
            machine_code: client.machine_code().to_string(),
        };
        self.inner.lock().client = Some(client);
        Ok(session)
    }

    pub fn register(
        &self,
        username: &str,
        password: &str,
        card_key: Option<&str>,
    ) -> AppResult<String> {
        let mut client = Client::new(DEPLOY_BASE_URL, APP_KEY, DEPLOY_PUB_HEX)
            .map_err(|e| AppError::Internal(format!("client new: {e}")))?;
        Ok(client.register(username, password, card_key)?)
    }

    pub fn change_password(&self, old: &str, new: &str) -> AppResult<String> {
        let mut inner = self.inner.lock();
        let client = inner.client.as_mut().ok_or(AppError::NotAuthorized)?;
        Ok(client.change_password(old, new)?)
    }

    pub fn topup_account(
        &self,
        username: &str,
        password: &str,
        card_key: &str,
    ) -> AppResult<TopupSummary> {
        let mut client = Client::new(DEPLOY_BASE_URL, APP_KEY, DEPLOY_PUB_HEX)
            .map_err(|e| AppError::Internal(format!("client new: {e}")))?;
        let response = client.topup_account(username, password, card_key)?;
        if !response.ok {
            return Err(AppError::Internal(response.message));
        }
        Ok(TopupSummary {
            message: response.message,
            expires_at: response.expires_at,
            remaining_count: response.remaining_count,
        })
    }

    pub fn logout(&self) -> AppResult<()> {
        let mut inner = self.inner.lock();
        if let Some(client) = inner.client.as_mut() {
            let _ = client.logout();
        }
        inner.client = None;
        Ok(())
    }

    pub fn heartbeat(&self) -> AppResult<HeartbeatSummary> {
        let mut inner = self.inner.lock();
        let client = inner.client.as_mut().ok_or(AppError::NotAuthorized)?;
        let response = client.heartbeat()?;
        if !response.online {
            inner.client = None;
        }
        Ok(HeartbeatSummary {
            online: response.online,
            expires_at: response.expires_at,
            remaining_count: response.remaining_count,
            server_time: response.server_time,
            message: response.message,
        })
    }

    pub fn is_authorized(&self) -> bool {
        self.inner
            .lock()
            .client
            .as_ref()
            .map(|client| client.is_authorized())
            .unwrap_or(false)
    }

    pub fn current_token(&self) -> Option<String> {
        self.inner
            .lock()
            .client
            .as_ref()
            .and_then(|client| client.token().map(String::from))
    }

    pub fn machine_code(&self) -> Option<String> {
        self.inner
            .lock()
            .client
            .as_ref()
            .map(|client| client.machine_code().to_string())
    }

    pub fn license_payload(&self) -> Option<LicensePayload> {
        let inner = self.inner.lock();
        let client = inner.client.as_ref()?;
        let auth = client.auth()?;
        Some(LicensePayload {
            app_key: APP_KEY.to_string(),
            subject_type: auth.subject_type.clone(),
            subject_id: auth.subject_id,
            machine_code: client.machine_code().to_string(),
            expires_at: auth.expires_at,
            token: auth.token.clone(),
            auth_sig_b64: auth.auth_sig.clone(),
        })
    }
}

#[cfg(all(not(feature = "network-license"), feature = "dev-license-bypass"))]
impl AuthState {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Inner { session: None }),
        }
    }

    pub fn login(&self, username: &str, password: &str) -> AppResult<AuthSession> {
        if username.trim().is_empty() || password.is_empty() {
            return Err(AppError::AuthInvalid);
        }
        let session = AuthSession {
            token: format!("dev-{username}-{}", now_unix()),
            subject_type: "dev".to_string(),
            subject_id: 1,
            expires_at: i64::MAX,
            remaining_count: -1,
            notice: "DEVELOPMENT LICENSE BYPASS ACTIVE".to_string(),
            machine_code: local_machine_code(),
        };
        self.inner.lock().session = Some(session.clone());
        Ok(session)
    }

    pub fn register(
        &self,
        username: &str,
        password: &str,
        _card_key: Option<&str>,
    ) -> AppResult<String> {
        if username.trim().is_empty() || password.is_empty() {
            return Err(AppError::AuthInvalid);
        }
        Ok("development bypass: registration not sent".to_string())
    }

    pub fn change_password(&self, _old: &str, _new: &str) -> AppResult<String> {
        if !self.is_authorized() {
            return Err(AppError::NotAuthorized);
        }
        Ok("development bypass: password not changed".to_string())
    }

    pub fn topup_account(
        &self,
        _username: &str,
        _password: &str,
        _card_key: &str,
    ) -> AppResult<TopupSummary> {
        Ok(TopupSummary {
            message: "development bypass: top-up not sent".to_string(),
            expires_at: i64::MAX,
            remaining_count: -1,
        })
    }

    pub fn logout(&self) -> AppResult<()> {
        self.inner.lock().session = None;
        Ok(())
    }

    pub fn heartbeat(&self) -> AppResult<HeartbeatSummary> {
        if !self.is_authorized() {
            return Err(AppError::NotAuthorized);
        }
        Ok(HeartbeatSummary {
            online: true,
            expires_at: i64::MAX,
            remaining_count: -1,
            server_time: now_unix(),
            message: "development bypass active".to_string(),
        })
    }

    pub fn is_authorized(&self) -> bool {
        self.inner.lock().session.is_some()
    }

    pub fn current_token(&self) -> Option<String> {
        self.inner
            .lock()
            .session
            .as_ref()
            .map(|session| session.token.clone())
    }

    pub fn machine_code(&self) -> Option<String> {
        self.inner
            .lock()
            .session
            .as_ref()
            .map(|session| session.machine_code.clone())
    }

    pub fn license_payload(&self) -> Option<LicensePayload> {
        let inner = self.inner.lock();
        let session = inner.session.as_ref()?;
        Some(LicensePayload {
            app_key: "dev-license-bypass".to_string(),
            subject_type: session.subject_type.clone(),
            subject_id: session.subject_id,
            machine_code: session.machine_code.clone(),
            expires_at: session.expires_at,
            token: session.token.clone(),
            auth_sig_b64: String::new(),
        })
    }
}

#[cfg(all(
    not(feature = "network-license"),
    not(feature = "dev-license-bypass")
))]
impl AuthState {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Inner),
        }
    }

    pub fn login(&self, username: &str, _password: &str) -> AppResult<AuthSession> {
        Ok(AuthSession {
            token: String::new(),
            subject_type: "open".to_string(),
            subject_id: 0,
            expires_at: i64::MAX,
            remaining_count: -1,
            notice: "authorization is not required".to_string(),
            machine_code: username.to_string(),
        })
    }

    pub fn register(
        &self,
        _username: &str,
        _password: &str,
        _card_key: Option<&str>,
    ) -> AppResult<String> {
        Ok("authorization is not required".to_string())
    }

    pub fn change_password(&self, _old: &str, _new: &str) -> AppResult<String> {
        Ok("authorization is not required".to_string())
    }

    pub fn topup_account(
        &self,
        _username: &str,
        _password: &str,
        _card_key: &str,
    ) -> AppResult<TopupSummary> {
        Ok(TopupSummary {
            message: "authorization is not required".to_string(),
            expires_at: i64::MAX,
            remaining_count: -1,
        })
    }

    pub fn logout(&self) -> AppResult<()> {
        Ok(())
    }

    pub fn heartbeat(&self) -> AppResult<HeartbeatSummary> {
        Ok(HeartbeatSummary {
            online: true,
            expires_at: i64::MAX,
            remaining_count: -1,
            server_time: 0,
            message: "authorization is not required".to_string(),
        })
    }

    pub fn is_authorized(&self) -> bool {
        true
    }

    pub fn current_token(&self) -> Option<String> {
        None
    }

    pub fn machine_code(&self) -> Option<String> {
        None
    }

    pub fn license_payload(&self) -> Option<LicensePayload> {
        None
    }
}

#[cfg(all(not(feature = "network-license"), feature = "dev-license-bypass"))]
fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(all(not(feature = "network-license"), feature = "dev-license-bypass"))]
fn local_machine_code() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "dev-machine".to_string())
}
