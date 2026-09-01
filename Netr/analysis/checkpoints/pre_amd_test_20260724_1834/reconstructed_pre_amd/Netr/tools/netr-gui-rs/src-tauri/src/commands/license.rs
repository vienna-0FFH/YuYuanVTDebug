//! Submit the deployment-server-signed authorization payload to the driver.

use base64::Engine;
use tauri::State;

#[cfg(feature = "network-license")]
use crate::ioctl::codes::IOCTL_HV_SUBMIT_LICENSE;
#[cfg(feature = "network-license")]
use crate::ioctl::structs::{fill_cstr, HvLicenseReq};
use crate::ioctl::DeviceState;
use crate::license::AuthState;
use crate::util::error::{AppError, AppResult};

pub fn license_submit_to_driver_internal(
    device: &DeviceState,
    auth: &AuthState,
) -> AppResult<()> {
    #[cfg(not(feature = "network-license"))]
    {
        let _ = (device, auth);
        return Ok(());
    }

    #[cfg(feature = "network-license")]
    {
        let payload = auth.license_payload().ok_or(AppError::NotAuthorized)?;
        let signature = base64::engine::general_purpose::STANDARD
            .decode(payload.auth_sig_b64.as_bytes())
            .map_err(|error| AppError::License(format!("auth_sig base64 decode: {error}")))?;
        if signature.len() != 64 {
            return Err(AppError::License(format!(
                "auth_sig length {} != 64",
                signature.len()
            )));
        }

        let mut request = HvLicenseReq::zeroed();
        fill_cstr(&mut request.app_key, &payload.app_key);
        fill_cstr(&mut request.subject_type, &payload.subject_type);
        request.subject_id = payload.subject_id;
        fill_cstr(&mut request.machine_code, &payload.machine_code);
        request.expires_at = payload.expires_at;
        fill_cstr(&mut request.token, &payload.token);
        request.auth_sig.copy_from_slice(&signature);

        let input = unsafe {
            std::slice::from_raw_parts(
                (&request as *const HvLicenseReq).cast::<u8>(),
                std::mem::size_of::<HvLicenseReq>(),
            )
        };

        let mut output = [0u8; 16];
        let _ = device.ioctl(IOCTL_HV_SUBMIT_LICENSE, input, &mut output)?;
        Ok(())
    }
}

#[tauri::command]
pub async fn license_submit_to_driver(
    device: State<'_, DeviceState>,
    auth: State<'_, AuthState>,
) -> AppResult<()> {
    #[cfg(not(feature = "network-license"))]
    {
        let _ = (device, auth);
        Ok(())
    }

    #[cfg(feature = "network-license")]
    {
        if !device.is_open() {
            device.open()?;
        }
        license_submit_to_driver_internal(&device, &auth)
    }
}

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
    pub local_verify_ok: bool,
    pub sha512_ram_first16_hex: String,
}

#[tauri::command]
pub fn license_dump(auth: State<'_, AuthState>) -> AppResult<LicenseDump> {
    use crate::license::hardcoded::DEPLOY_PUB_HEX;

    let payload = auth.license_payload().ok_or(AppError::NotAuthorized)?;
    let signature = base64::engine::general_purpose::STANDARD
        .decode(payload.auth_sig_b64.as_bytes())
        .unwrap_or_default();
    let canonical = format!(
        "YUYUAN-AUTH-v1|{}|{}|{}|{}|{}|{}",
        payload.app_key,
        payload.subject_type,
        payload.subject_id,
        payload.machine_code,
        payload.expires_at,
        payload.token
    );

    #[cfg(feature = "network-license")]
    let local_verify_ok = (|| -> Option<bool> {
        let public_key = hex::decode(DEPLOY_PUB_HEX).ok()?;
        if public_key.len() != 32 || signature.len() != 64 {
            return Some(false);
        }
        let mut public_key_array = [0u8; 32];
        public_key_array.copy_from_slice(&public_key);
        let mut signature_array = [0u8; 64];
        signature_array.copy_from_slice(&signature);
        Some(yuyuan_protocol::crypto::verify_with_server_pub(
            &public_key_array,
            canonical.as_bytes(),
            &signature_array,
        ))
    })()
    .unwrap_or(false);

    #[cfg(not(feature = "network-license"))]
    let local_verify_ok = false;

    let sha512_ram_first16_hex = (|| -> Option<String> {
        use sha2::{Digest, Sha512};

        let public_key = hex::decode(DEPLOY_PUB_HEX).ok()?;
        if public_key.len() != 32 || signature.len() != 64 {
            return None;
        }
        let mut hash = Sha512::new();
        hash.update(&signature[0..32]);
        hash.update(&public_key);
        hash.update(canonical.as_bytes());
        let output = hash.finalize();
        Some(output[..16].iter().map(|byte| format!("{byte:02x}")).collect())
    })()
    .unwrap_or_default();

    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0);

    Ok(LicenseDump {
        app_key: payload.app_key,
        subject_type: payload.subject_type,
        subject_id: payload.subject_id,
        machine_code: payload.machine_code,
        expires_at: payload.expires_at,
        token: payload.token,
        auth_sig_b64: payload.auth_sig_b64,
        auth_sig_hex: signature.iter().map(|byte| format!("{byte:02x}")).collect(),
        auth_sig_len: signature.len(),
        canonical,
        now_unix,
        deploy_pub_hex: DEPLOY_PUB_HEX.to_string(),
        local_verify_ok,
        sha512_ram_first16_hex,
    })
}
