//! IOCTL_HV_SUBMIT_LICENSE 调用。
//!
//! 调用时机:
//!   - GUI 登录成功后,driver 已启动且 device 已打开 → 调本 command
//!   - 调用后 driver g_LicenseValid=TRUE,业务 IOCTL 解锁
//!
//! 前置:driver 必须在跑(否则 NetrDevice::open 失败)

use base64::Engine;
use tauri::State;

use crate::ioctl::codes::IOCTL_HV_SUBMIT_LICENSE;
use crate::ioctl::structs::{fill_cstr, HvLicenseReq};
use crate::ioctl::DeviceState;
use crate::license::AuthState;
use crate::util::error::{AppError, AppResult};

/// 内部实现:构造请求 + 通过 DeviceState 发送。
///
/// 调用方需保证 device 已 open。
pub fn license_submit_to_driver_internal(
    device: &DeviceState,
    auth: &AuthState,
) -> AppResult<()> {
    let payload = auth.license_payload().ok_or(AppError::NotAuthorized)?;
    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(payload.auth_sig_b64.as_bytes())
        .map_err(|e| AppError::License(format!("auth_sig base64 decode: {e}")))?;
    if sig_bytes.len() != 64 {
        return Err(AppError::License(format!(
            "auth_sig length {} != 64",
            sig_bytes.len()
        )));
    }

    let mut req = HvLicenseReq::zeroed();
    fill_cstr(&mut req.app_key, &payload.app_key);
    fill_cstr(&mut req.subject_type, &payload.subject_type);
    req.subject_id = payload.subject_id;
    fill_cstr(&mut req.machine_code, &payload.machine_code);
    req.expires_at = payload.expires_at;
    fill_cstr(&mut req.token, &payload.token);
    req.auth_sig.copy_from_slice(&sig_bytes);

    let in_buf = unsafe {
        std::slice::from_raw_parts(
            (&req as *const HvLicenseReq) as *const u8,
            std::mem::size_of::<HvLicenseReq>(),
        )
    };

    let mut out = [0u8; 16];
    let _ = device.ioctl(IOCTL_HV_SUBMIT_LICENSE, in_buf, &mut out)?;
    Ok(())
}

/// 把当前登录态的 license 提交给 driver。
#[tauri::command]
pub async fn license_submit_to_driver(
    device: State<'_, DeviceState>,
    auth: State<'_, AuthState>,
) -> AppResult<()> {
    // device 未 open 时,自动 open(driver 必须先启动)
    if !device.is_open() {
        device.open()?;
    }
    license_submit_to_driver_internal(&device, &auth)
}

// ============================================================
// 诊断:把当前 license payload 以可读形式 dump 出来,辅助排查
// driver 拒绝原因(canonical 字段值、签名 hex、当前 Unix 时间等)
// ============================================================
#[derive(Debug, serde::Serialize)]
pub struct LicenseDump {
    pub app_key: String,
    pub subject_type: String,
    pub subject_id: i64,
    pub machine_code: String,
    pub expires_at: i64,
    pub token: String,
    pub auth_sig_b64: String,
    pub auth_sig_hex: String,
    pub auth_sig_len: usize,
    pub canonical: String,
    pub now_unix: i64,
    pub deploy_pub_hex: String,
    /// 在 GUI 端用 ed25519-dalek(SDK 同一栈)验签 — 跟 driver 端验签结果对照
    pub local_verify_ok: bool,
    /// SHA-512(R || A || M) 头 16 字节(driver 也会打印同样的) — 比对 SHA-512 实现是否一致
    pub sha512_ram_first16_hex: String,
}

#[tauri::command]
pub fn license_dump(auth: State<'_, AuthState>) -> AppResult<LicenseDump> {
    use base64::Engine;
    use crate::license::hardcoded::DEPLOY_PUB_HEX;

    let p = auth.license_payload().ok_or(AppError::NotAuthorized)?;
    let sig = base64::engine::general_purpose::STANDARD
        .decode(p.auth_sig_b64.as_bytes())
        .unwrap_or_default();

    let canonical = format!(
        "YUYUAN-AUTH-v1|{}|{}|{}|{}|{}|{}",
        p.app_key, p.subject_type, p.subject_id, p.machine_code, p.expires_at, p.token
    );

    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    // 用 ed25519-dalek(SDK 同 crate)在 GUI 后端跑同样的 verify
    let local_verify_ok = (|| -> Option<bool> {
        let pub_bytes_vec = hex::decode(DEPLOY_PUB_HEX).ok()?;
        if pub_bytes_vec.len() != 32 || sig.len() != 64 {
            return Some(false);
        }
        let mut pub_arr = [0u8; 32];
        pub_arr.copy_from_slice(&pub_bytes_vec);
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig);
        Some(yuyuan_protocol::crypto::verify_with_server_pub(
            &pub_arr,
            canonical.as_bytes(),
            &sig_arr,
        ))
    })()
    .unwrap_or(false);

    // SHA-512(R || A || M) 头 16 字节 — 跟 driver [Ed25519] sha512(R||A||M)[0..16] 对比
    let sha512_ram_first16_hex = (|| -> Option<String> {
        use sha2::{Sha512, Digest};
        let pub_bytes_vec = hex::decode(DEPLOY_PUB_HEX).ok()?;
        if pub_bytes_vec.len() != 32 || sig.len() != 64 {
            return None;
        }
        let r_bytes = &sig[0..32];  // R 是签名前 32 字节
        let mut h = Sha512::new();
        h.update(r_bytes);
        h.update(&pub_bytes_vec);
        h.update(canonical.as_bytes());
        let out = h.finalize();
        Some(out[..16].iter().map(|b| format!("{:02x}", b)).collect())
    })()
    .unwrap_or_default();

    Ok(LicenseDump {
        app_key: p.app_key,
        subject_type: p.subject_type,
        subject_id: p.subject_id,
        machine_code: p.machine_code,
        expires_at: p.expires_at,
        token: p.token,
        auth_sig_b64: p.auth_sig_b64,
        auth_sig_hex: sig.iter().map(|b| format!("{:02x}", b)).collect::<String>(),
        auth_sig_len: sig.len(),
        canonical,
        now_unix,
        deploy_pub_hex: DEPLOY_PUB_HEX.to_string(),
        local_verify_ok,
        sha512_ram_first16_hex,
    })
}
