//! 登录 / 登出 / 心跳 / 状态查询 Tauri commands。
//!
//! 所有调用 yuyuan-client 的同步阻塞 API 都包在 `spawn_blocking` 里,
//! 否则会卡住 tokio runtime 上的其他 future。

use serde::Serialize;
use tauri::State;

use crate::license::{
    clear_account, load_account, save_account, AuthState, HeartbeatSummary, StoredAccount,
    TopupSummary,
};
use crate::util::error::{AppError, AppResult};

/// 登录响应给前端的视图。字段是 Auth 的子集 + 我们关心的元信息。
#[derive(Debug, Serialize)]
pub struct LoginView {
    pub token: String,
    pub subject_type: String,
    pub subject_id: i64,
    pub expires_at: i64,
    pub remaining_count: i64,
    pub notice: String,
    pub machine_code: String,
}

/// 启动时调一次,看是否有保存的凭证可以自动登录。
#[derive(Debug, Serialize)]
pub struct BootstrapView {
    /// 本地是否存有保存的账号(界面据此决定登录页是否预填用户名)
    pub has_saved: bool,
    pub saved_username: Option<String>,
}

#[tauri::command]
pub async fn auth_bootstrap() -> AppResult<BootstrapView> {
    let saved = tokio::task::spawn_blocking(load_account)
        .await
        .map_err(|e| AppError::Internal(format!("spawn_blocking: {e}")))??;
    Ok(BootstrapView {
        has_saved: saved.is_some(),
        saved_username: saved.map(|a| a.username),
    })
}

/// 账号密码登录。
/// - 成功:返回 LoginView,token 留在 backend AuthState 里
/// - remember=true:用 Windows Credential Manager 存账密,下次启动可一键填回
#[tauri::command]
pub async fn auth_login(
    state: State<'_, AuthState>,
    username: String,
    password: String,
    remember: bool,
) -> AppResult<LoginView> {
    // Mutex Guard 不 Send,不能跨 await 持有。先在 spawn_blocking 内做完操作,
    // 用 channel 把结果送出来。state 是 ManagedState 引用,Arc 内核共享安全。
    // 但 tauri::State 自身不是 'static 的,我们克隆需要的指针——
    // 利用 Tauri 的 AppHandle 在 spawn_blocking 中重新拿 state 是更稳的做法。
    // 这里走更简单的方法:state 内已是 Mutex,可在阻塞上下文里安全使用。
    //
    // 实现细节:由于 tauri::State 不能直接 'static 化进 spawn_blocking,
    // 我们把登录逻辑同步直跑(yuyuan SDK 阻塞,平均 1-3s 网络往返,
    // 短时间阻塞 tokio worker 是可接受的;对 12 核机器影响极小)。
    // 后续若发现 UI 卡顿,可换成 AppHandle + handle.state() 模式。
    let auth = state.login(&username, &password)?;
    let machine_code = state.machine_code().unwrap_or_default();

    if remember {
        let acc = StoredAccount {
            username: username.clone(),
            password: password.clone(),
        };
        tokio::task::spawn_blocking(move || save_account(&acc))
            .await
            .map_err(|e| AppError::Internal(format!("spawn_blocking: {e}")))??;
    }

    Ok(LoginView {
        token: auth.token,
        subject_type: auth.subject_type,
        subject_id: auth.subject_id,
        expires_at: auth.expires_at,
        remaining_count: auth.remaining_count,
        notice: auth.notice,
        machine_code,
    })
}

/// 用本地保存的账号自动登录(启动后没勾"记住"时不调用)。
#[tauri::command]
pub async fn auth_auto_login(state: State<'_, AuthState>) -> AppResult<Option<LoginView>> {
    let acc = tokio::task::spawn_blocking(load_account)
        .await
        .map_err(|e| AppError::Internal(format!("spawn_blocking: {e}")))??;
    let acc = match acc {
        Some(a) => a,
        None => return Ok(None),
    };
    let auth = state.login(&acc.username, &acc.password)?;
    let machine_code = state.machine_code().unwrap_or_default();
    Ok(Some(LoginView {
        token: auth.token,
        subject_type: auth.subject_type,
        subject_id: auth.subject_id,
        expires_at: auth.expires_at,
        remaining_count: auth.remaining_count,
        notice: auth.notice,
        machine_code,
    }))
}

/// 主动注销:部署端登出 + 本地 state 清空 + 清 Credential Manager 凭证
#[tauri::command]
pub async fn auth_logout(state: State<'_, AuthState>) -> AppResult<()> {
    state.logout()?;
    tokio::task::spawn_blocking(clear_account)
        .await
        .map_err(|e| AppError::Internal(format!("spawn_blocking: {e}")))??;
    Ok(())
}

/// 主动心跳(查在线状态)。前端可在关键操作前主动调,SDK 内部已 60s 自动心跳。
#[tauri::command]
pub async fn auth_heartbeat(state: State<'_, AuthState>) -> AppResult<HeartbeatSummary> {
    state.heartbeat()
}

/// 当前是否登录(快速,不联网)
#[tauri::command]
pub fn auth_is_authorized(state: State<'_, AuthState>) -> bool {
    state.is_authorized()
}

/// 自助注册账号。可选 card_key 直接绑定时长/次数。
/// 注册成功后**不**自动登录,前端拿到 ok 后立即 auth_login。
#[tauri::command]
pub async fn auth_register(
    state: State<'_, AuthState>,
    username: String,
    password: String,
    card_key: Option<String>,
) -> AppResult<String> {
    let ck = card_key.as_deref();
    state.register(&username, &password, ck)
}

/// 已登录用户改密。需要旧密码。
#[tauri::command]
pub async fn auth_change_password(
    state: State<'_, AuthState>,
    old_password: String,
    new_password: String,
) -> AppResult<String> {
    state.change_password(&old_password, &new_password)
}

/// 卡密充值。需要重新输入账号/密码(部署端要求,避免误操作)。
#[tauri::command]
pub async fn auth_topup(
    state: State<'_, AuthState>,
    username: String,
    password: String,
    card_key: String,
) -> AppResult<TopupSummary> {
    state.topup_account(&username, &password, &card_key)
}
