use serde::{Deserialize, Serialize};
use tauri::State;

use crate::ioctl::codes::{
    IOCTL_HV_DISABLE_ANTIANTIDEBUG, IOCTL_HV_ENABLE_ANTIANTIDEBUG,
    IOCTL_HV_GET_ANTIANTIDEBUG_STATUS,
    IOCTL_HV_SET_PRIVATE_DEBUG_OBJECT,
};
use crate::ioctl::DeviceState;
use crate::util::error::{AppError, AppResult};

const CONTROL_VERSION: u32 = 1;
const FEATURE_PROCESS_DEBUG_QUERY: u32 = 1 << 0;
const FEATURE_KERNEL_DEBUG_QUERY: u32 = 1 << 1;
const FEATURE_THREAD_HIDE: u32 = 1 << 2;
const FEATURE_INVALID_HANDLE: u32 = 1 << 3;
const FEATURE_DEBUG_OBJECT: u32 = 1 << 4;
const FEATURE_DEBUG_REGISTERS: u32 = 1 << 5;
const FEATURE_SYSTEM_DEBUG_CONTROL: u32 = 1 << 6;

#[derive(Debug, Clone, Deserialize)]
pub struct AntiVmpConfig {
    pub process_debug_query: bool,
    pub kernel_debug_query: bool,
    pub thread_hide: bool,
    pub invalid_handle: bool,
    pub debug_object: bool,
    pub debug_registers: bool,
    pub system_debug_control: bool,
}

impl AntiVmpConfig {
    fn feature_mask(&self) -> u32 {
        (self.process_debug_query as u32) * FEATURE_PROCESS_DEBUG_QUERY
            | (self.kernel_debug_query as u32) * FEATURE_KERNEL_DEBUG_QUERY
            | (self.thread_hide as u32) * FEATURE_THREAD_HIDE
            | (self.invalid_handle as u32) * FEATURE_INVALID_HANDLE
            | (self.debug_object as u32) * FEATURE_DEBUG_OBJECT
            | (self.debug_registers as u32) * FEATURE_DEBUG_REGISTERS
            | (self.system_debug_control as u32) * FEATURE_SYSTEM_DEBUG_CONTROL
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct AntiVmpStatus {
    pub version: u32,
    pub enabled: bool,
    pub target_pid: u32,
    pub configured_mask: u32,
    pub installed_mask: u32,
    pub bridge_auto_enabled: bool,
    pub protected_target_count: u32,
    pub private_debug_object_enabled: bool,
}

fn read_u32(buffer: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(buffer[offset..offset + 4].try_into().unwrap())
}

fn query_status(device: &DeviceState) -> AppResult<AntiVmpStatus> {
    let mut output = [0u8; 32];
    let bytes = device.ioctl(
        IOCTL_HV_GET_ANTIANTIDEBUG_STATUS,
        &[],
        &mut output,
    )?;
    if bytes < output.len() as u32 {
        return Err(AppError::Internal(format!(
            "AntiVMP status ABI mismatch: expected {}, got {bytes}",
            output.len()
        )));
    }

    let version = read_u32(&output, 0);
    if version != CONTROL_VERSION {
        return Err(AppError::Internal(format!(
            "AntiVMP control version mismatch: driver={version}, ui={CONTROL_VERSION}"
        )));
    }

    Ok(AntiVmpStatus {
        version,
        enabled: read_u32(&output, 4) != 0,
        target_pid: read_u32(&output, 8),
        configured_mask: read_u32(&output, 12),
        installed_mask: read_u32(&output, 16),
        bridge_auto_enabled: read_u32(&output, 20) != 0,
        protected_target_count: read_u32(&output, 24),
        private_debug_object_enabled: read_u32(&output, 28) != 0,
    })
}

pub(crate) fn private_debug_object_enabled(device: &DeviceState) -> AppResult<bool> {
    Ok(query_status(device)?.private_debug_object_enabled)
}

#[tauri::command]
pub fn antivmp_get_status(
    device: State<'_, DeviceState>,
) -> AppResult<AntiVmpStatus> {
    query_status(device.inner())
}

#[tauri::command]
pub fn antivmp_apply(
    device: State<'_, DeviceState>,
    enabled: bool,
    config: AntiVmpConfig,
) -> AppResult<AntiVmpStatus> {
    let feature_mask = config.feature_mask();
    if enabled && feature_mask == 0 {
        return Err(AppError::Internal(
            "AntiVMP requires at least one filter".into(),
        ));
    }

    let mut ignored = [0u8; 4];
    device.ioctl(IOCTL_HV_DISABLE_ANTIANTIDEBUG, &[], &mut ignored)?;

    if enabled {
        let mut input = [0u8; 16];
        input[0..4].copy_from_slice(&CONTROL_VERSION.to_le_bytes());
        input[4..8].copy_from_slice(&0u32.to_le_bytes());
        input[8..12].copy_from_slice(&feature_mask.to_le_bytes());
        device.ioctl(
            IOCTL_HV_ENABLE_ANTIANTIDEBUG,
            &input,
            &mut ignored,
        )?;
    }

    query_status(device.inner())
}

#[tauri::command]
pub fn antivmp_set_private_debug_object(
    device: State<'_, DeviceState>,
    enabled: bool,
) -> AppResult<AntiVmpStatus> {
    let mut input = [0u8; 8];
    input[0..4].copy_from_slice(&CONTROL_VERSION.to_le_bytes());
    input[4..8].copy_from_slice(&(enabled as u32).to_le_bytes());
    let mut output = [0u8; 16];
    device.ioctl(
        IOCTL_HV_SET_PRIVATE_DEBUG_OBJECT,
        &input,
        &mut output,
    )?;
    query_status(device.inner())
}
