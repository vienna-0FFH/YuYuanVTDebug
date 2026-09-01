use serde::Serialize;
use tauri::State;

use crate::ioctl::codes::*;
use crate::ioctl::DeviceState;
use crate::util::error::AppResult;

const DSE_STATUS_SIZE: usize = 13;

#[derive(Debug, Clone, Copy, Serialize)]
pub struct DseStatusView {
    pub disabled: bool,
}

#[tauri::command]
pub fn dse_status(device: State<'_, DeviceState>) -> AppResult<DseStatusView> {
    // Driver.c: pack(1) { BOOLEAN DseEnabled; ULONG CiOptionsValue;
    // UINT64 CiOptionsAddress; } => 13 bytes.
    let mut out = [0u8; DSE_STATUS_SIZE];
    let written = device.ioctl(IOCTL_HV_GET_DSE_STATUS, &[], &mut out)?;
    if written < DSE_STATUS_SIZE as u32 {
        return Err(crate::util::error::AppError::Internal(format!(
            "GET_DSE_STATUS returned {written} bytes"
        )));
    }
    Ok(DseStatusView {
        disabled: out[0] == 0,
    })
}

#[tauri::command]
pub fn dse_enable(device: State<'_, DeviceState>) -> AppResult<()> {
    let mut out = [0u8; 16];
    device.ioctl(IOCTL_HV_ENABLE_DSE, &[], &mut out)?;
    Ok(())
}

#[tauri::command]
pub fn dse_disable(device: State<'_, DeviceState>) -> AppResult<()> {
    let mut out = [0u8; 16];
    device.ioctl(IOCTL_HV_DISABLE_DSE, &[], &mut out)?;
    Ok(())
}
