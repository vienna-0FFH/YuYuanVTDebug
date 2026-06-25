//! 全局 Auth state。Tauri command 通过 `tauri::State<AuthState>` 拿。
//!
//! 为什么用 parking_lot::Mutex 不用 tokio::Mutex:
//!   yuyuan-client 是同步阻塞 API,我们已经在 spawn_blocking 里调它。
//!   parking_lot 比 std::sync 快、不会 poison,适合简单临界区。

use parking_lot::Mutex;
use serde::Serialize;
use yuyuan_client::{Auth, Client};

use crate::license::hardcoded::{APP_KEY, DEPLOY_BASE_URL, DEPLOY_PUB_HEX};
use crate::util::error::{AppError, AppResult};

pub struct AuthState {
    inner: Mutex<Inner>,
}

struct Inner {
    /// 已握手 + 已登录 的 client。`verify_account` 失败前先创建,失败后 drop。
    /// None 表示未登录。
    client: Option<Client>,
}

impl AuthState {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Inner { client: None }),
        }
    }

    /// 用账号 + 密码登录。成功后 client 留在 state 里供后续心跳/登出。
    pub fn login(&self, username: &str, password: &str) -> AppResult<Auth> {
        let mut new_client = Client::new(DEPLOY_BASE_URL, APP_KEY, DEPLOY_PUB_HEX)
            .map_err(|e| AppError::Internal(format!("client new: {e}")))?;
        let auth = new_client.verify_account(username, password)?;

        let mut g = self.inner.lock();
        g.client = Some(new_client);
        Ok(auth)
    }

    /// 自助注册账号(可选附带卡密)。注册成功后**不**登录,后续调 login。
    /// 用一个临时 client 完成 RPC,握手后立即丢弃。
    pub fn register(
        &self,
        username: &str,
        password: &str,
        card_key: Option<&str>,
    ) -> AppResult<String> {
        let mut c = Client::new(DEPLOY_BASE_URL, APP_KEY, DEPLOY_PUB_HEX)
            .map_err(|e| AppError::Internal(format!("client new: {e}")))?;
        let msg = c.register(username, password, card_key)?;
        Ok(msg)
    }

    /// 已登录用户改密。
    pub fn change_password(&self, old: &str, new: &str) -> AppResult<String> {
        let mut g = self.inner.lock();
        let c = g.client.as_mut().ok_or(AppError::NotAuthorized)?;
        let msg = c.change_password(old, new)?;
        Ok(msg)
    }

    /// 卡密给账号充值(需要重新输入账号/密码以避免误操作)。
    pub fn topup_account(
        &self,
        username: &str,
        password: &str,
        card_key: &str,
    ) -> AppResult<TopupSummary> {
        // 临时 client 走 RPC,不污染已登录 state
        let mut c = Client::new(DEPLOY_BASE_URL, APP_KEY, DEPLOY_PUB_HEX)
            .map_err(|e| AppError::Internal(format!("client new: {e}")))?;
        let resp = c.topup_account(username, password, card_key)?;
        if !resp.ok {
            return Err(AppError::Internal(resp.message));
        }
        Ok(TopupSummary {
            message: resp.message,
            expires_at: resp.expires_at,
            remaining_count: resp.remaining_count,
        })
    }

    /// 主动注销。
    pub fn logout(&self) -> AppResult<()> {
        let mut g = self.inner.lock();
        if let Some(c) = g.client.as_mut() {
            // 部署端 logout 可能失败(网络/会话已过期),但本地无论如何都清。
            let _ = c.logout();
        }
        g.client = None;
        Ok(())
    }

    /// 心跳。返回是否仍在线;部署端判定下线时同时清本地。
    pub fn heartbeat(&self) -> AppResult<HeartbeatSummary> {
        let mut g = self.inner.lock();
        let c = g
            .client
            .as_mut()
            .ok_or(AppError::NotAuthorized)?;
        let r = c.heartbeat()?;
        if !r.online {
            g.client = None;
        }
        Ok(HeartbeatSummary {
            online: r.online,
            expires_at: r.expires_at,
            remaining_count: r.remaining_count,
            server_time: r.server_time,
            message: r.message,
        })
    }

    /// 当前是否已登录(快速判断,不联网)。
    pub fn is_authorized(&self) -> bool {
        self.inner
            .lock()
            .client
            .as_ref()
            .map(|c| c.is_authorized())
            .unwrap_or(false)
    }

    /// 当前 token(供 driver IOCTL_HV_SUBMIT_LICENSE 用)。
    pub fn current_token(&self) -> Option<String> {
        self.inner
            .lock()
            .client
            .as_ref()
            .and_then(|c| c.token().map(String::from))
    }

    /// 当前机器码。
    pub fn machine_code(&self) -> Option<String> {
        self.inner
            .lock()
            .client
            .as_ref()
            .map(|c| c.machine_code().to_string())
    }

    /// Phase 2: 拿到提交给 driver 的完整 license payload。
    /// 要求已登录过(否则返 None)。
    pub fn license_payload(&self) -> Option<LicensePayload> {
        let g = self.inner.lock();
        let c = g.client.as_ref()?;
        let auth = c.auth()?;
        Some(LicensePayload {
            app_key: APP_KEY.to_string(),
            subject_type: auth.subject_type.clone(),
            subject_id: auth.subject_id,
            machine_code: c.machine_code().to_string(),
            expires_at: auth.expires_at,
            token: auth.token.clone(),
            auth_sig_b64: auth.auth_sig.clone(),
        })
    }
}

/// 提交给 driver IOCTL_HV_SUBMIT_LICENSE 的载荷。
#[derive(Debug, Clone)]
pub struct LicensePayload {
    pub app_key: String,
    pub subject_type: String,
    pub subject_id: i64,
    pub machine_code: String,
    pub expires_at: i64,
    pub token: String,
    /// base64(64B Ed25519 签名),提交时解码为二进制 64B 填进 IOCTL struct
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
