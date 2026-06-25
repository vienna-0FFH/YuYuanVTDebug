use serde::Serialize;
use tauri::State;

use crate::ioctl::codes::*;
use crate::ioctl::DeviceState;
use crate::util::error::AppResult;

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct DseStatus {
    disabled: u32,
    ci_options_va: u64,
    original_value: u32,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct DseStatusView {
    pub disabled: bool,
}

#[tauri::command]
pub fn dse_status(device: State<'_, DeviceState>) -> AppResult<DseStatusView> {
    let mut out = vec![0u8; std::mem::size_of::<DseStatus>()];
    device.ioctl(IOCTL_HV_GET_DSE_STATUS, &[], &mut out)?;
    let v: DseStatus = unsafe { *(out.as_ptr() as *const DseStatus) };
    Ok(DseStatusView { disabled: { let d = v.disabled; d != 0 } })
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
