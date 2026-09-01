use serde::Serialize;
use tauri::State;

use crate::license::{
    clear_account, load_account, save_account, AuthState, HeartbeatSummary, StoredAccount,
    TopupSummary,
};
use crate::util::error::{AppError, AppResult};

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

#[derive(Debug, Serialize)]
pub struct BootstrapView {
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

#[tauri::command]
pub async fn auth_login(
    state: State<'_, AuthState>,
    username: String,
    password: String,
    remember: bool,
) -> AppResult<LoginView> {
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

#[tauri::command]
pub async fn auth_auto_login(state: State<'_, AuthState>) -> AppResult<Option<LoginView>> {
    #[cfg(all(
        not(feature = "network-license"),
        not(feature = "dev-license-bypass")
    ))]
    {
        let auth = state.login("open", "")?;
        return Ok(Some(LoginView {
            token: auth.token,
            subject_type: auth.subject_type,
            subject_id: auth.subject_id,
            expires_at: auth.expires_at,
            remaining_count: auth.remaining_count,
            notice: auth.notice,
            machine_code: auth.machine_code,
        }));
    }

    #[cfg(any(feature = "network-license", feature = "dev-license-bypass"))]
    {
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
}

#[tauri::command]
pub async fn auth_logout(state: State<'_, AuthState>) -> AppResult<()> {
    state.logout()?;
    tokio::task::spawn_blocking(clear_account)
        .await
        .map_err(|e| AppError::Internal(format!("spawn_blocking: {e}")))??;
    Ok(())
}

#[tauri::command]
pub async fn auth_heartbeat(state: State<'_, AuthState>) -> AppResult<HeartbeatSummary> {
    state.heartbeat()
}

#[tauri::command]
pub fn auth_is_authorized(state: State<'_, AuthState>) -> bool {
    state.is_authorized()
}

#[tauri::command]
pub async fn auth_register(
    state: State<'_, AuthState>,
    username: String,
    password: String,
    card_key: Option<String>,
) -> AppResult<String> {
    state.register(&username, &password, card_key.as_deref())
}

#[tauri::command]
pub async fn auth_change_password(
    state: State<'_, AuthState>,
    old_password: String,
    new_password: String,
) -> AppResult<String> {
    state.change_password(&old_password, &new_password)
}

#[tauri::command]
pub async fn auth_topup(
    state: State<'_, AuthState>,
    username: String,
    password: String,
    card_key: String,
) -> AppResult<TopupSummary> {
    state.topup_account(&username, &password, &card_key)
}
