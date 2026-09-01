//! Driver 管理 commands。

use tauri::State;
use std::sync::Arc;
use std::time::Duration;

use crate::commands::debugger_ui::{DebuggerHandles, FreezeStore};
use crate::ioctl::codes::IOCTL_HV_GET_STATUS;
use crate::ioctl::service::{self, ServiceInfo};
use crate::ioctl::DeviceState;
use crate::util::error::AppResult;
use crate::license::AuthState;

/// 安装 driver(传 .sys 文件路径)
#[tauri::command]
pub async fn driver_install(driver_path: String) -> AppResult<()> {
    tokio::task::spawn_blocking(move || service::install(&driver_path))
        .await
        .map_err(|e| crate::util::error::AppError::Internal(e.to_string()))??;
    Ok(())
}

#[tauri::command]
pub async fn driver_start() -> AppResult<()> {
    tokio::task::spawn_blocking(service::start)
        .await
        .map_err(|e| crate::util::error::AppError::Internal(e.to_string()))??;
    Ok(())
}

#[tauri::command]
pub async fn driver_stop(
    device: State<'_, DeviceState>,
    handles: State<'_, Arc<DebuggerHandles>>,
    freeze: State<'_, Arc<FreezeStore>>,
) -> AppResult<()> {
    // stop 前先关 device handle,否则 driver 卸载会被阻塞
    crate::commands::debugger_ui::cleanup_all_builtin_targets(
        handles.inner(),
        device.inner(),
        freeze.inner(),
    )?;
    device.close();
    let stop = tokio::task::spawn_blocking(service::stop);
    match tokio::time::timeout(Duration::from_secs(20), stop).await {
        Ok(joined) => {
            joined
                .map_err(|e| crate::util::error::AppError::Internal(e.to_string()))??;
        }
        Err(_) => {
            return Err(crate::util::error::AppError::Internal(
                "driver stop timed out after 20 s; kernel unload is still pending (check C:\\HvUnloadTrace.log)".into(),
            ));
        }
    }
    Ok(())
}

#[tauri::command]
pub async fn driver_uninstall(device: State<'_, DeviceState>) -> AppResult<()> {
    device.close();
    tokio::task::spawn_blocking(service::uninstall)
        .await
        .map_err(|e| crate::util::error::AppError::Internal(e.to_string()))??;
    Ok(())
}

#[tauri::command]
pub async fn driver_query() -> AppResult<ServiceInfo> {
    tokio::task::spawn_blocking(service::query)
        .await
        .map_err(|e| crate::util::error::AppError::Internal(e.to_string()))?
}

/// 打开 driver 设备 handle(在 driver 运行后调用)
/// 打开成功后自动尝试提交 license。
#[tauri::command]
pub async fn driver_open_device(
    device: State<'_, DeviceState>,
    auth: State<'_, AuthState>,
) -> AppResult<()> {
    device.open()?;
    // 尝试提交 license — 已登录就一并把驱动也解锁
    if auth.is_authorized() {
        // 复用 commands::license::license_submit_to_driver 的实现可能引发循环,
        // 这里直接调底层接口
        if let Some(_) = auth.license_payload() {
            // 异步调一次,失败也无所谓(用户可手动重试)
            let _ = crate::commands::license::license_submit_to_driver_internal(&device, &auth);
        }
    }
    Ok(())
}

#[tauri::command]
pub fn driver_close_device(device: State<'_, DeviceState>) {
    device.close();
}

#[tauri::command]
pub fn driver_device_open(device: State<'_, DeviceState>) -> bool {
    device.is_open()
}

/// 调 IOCTL_HV_GET_STATUS 拿 driver 内部状态
#[derive(Debug, serde::Serialize)]
pub struct DriverStatusView {
    pub hypervisor_active: bool,
    pub hook_initialized: bool,
    pub dse_disabled: bool,
    pub anti_anti_debug: bool,
    pub debuggers: u32,
    pub protected_processes: u32,
    pub cpu_vendor: u32,
    pub cpu_count: u32,
    pub vt_root_enabled: bool,
    pub debugger_proxy_enabled: bool,
    pub access_bypass_enabled: bool,
}

// 与 Driver.c 的 HV_STATUS_INFO **严格** 对应 — BOOLEAN 是 1 字节,ULONG 4 字节,
// 默认 8-byte 对齐。手动按 offset 解码,避免 repr(C) 在 BOOLEAN/ULONG 混杂下与 MSVC
// 的实际布局不一致的悲剧(2026-06-21 面板全字段错位的根因)。
//
// driver 端布局(见 Driver.c::HV_STATUS_INFO):
//   off  0   ULONG    Version
//   off  4   BOOLEAN  HypervisorActive
//   off  5   BOOLEAN  HookManagerInitialized
//   off  6   BOOLEAN  DseDisabled
//   off  7   BOOLEAN  AntiAntiDebugEnabled
//   off  8   ULONG    HiddenProcessCount
//   off 12   ULONG    HiddenDriverCount
//   off 16   ULONG    ProtectedDebuggerCount
//   off 20   ULONG    ProtectedProcessCount
//   off 24   ULONG    CpuVendor
//   off 28   ULONG    ProcessorCount
//   off 32   BOOLEAN  VtRootEnabled
//   off 33   BOOLEAN  DebuggerProxyEnabled
//   off 34   BOOLEAN  AccessBypassEnabled
//   size = 35,sizeof 对齐到 36(末尾 1 字节 pad)
const HV_STATUS_INFO_SIZE: usize = 36;

#[inline]
fn rd_u32(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(buf[off..off + 4].try_into().unwrap())
}

#[inline]
fn rd_bool(buf: &[u8], off: usize) -> bool {
    buf[off] != 0
}

#[tauri::command]
pub fn driver_get_status(device: State<'_, DeviceState>) -> AppResult<DriverStatusView> {
    let mut out = vec![0u8; HV_STATUS_INFO_SIZE];
    device.ioctl(IOCTL_HV_GET_STATUS, &[], &mut out)?;
    let raw_cpu_count = rd_u32(&out, 28);
    Ok(DriverStatusView {
        hypervisor_active: rd_bool(&out, 4),
        hook_initialized:  rd_bool(&out, 5),
        dse_disabled:      rd_bool(&out, 6),
        anti_anti_debug:   rd_bool(&out, 7),
        debuggers:                rd_u32(&out, 16),
        protected_processes:      rd_u32(&out, 20),
        cpu_vendor:               rd_u32(&out, 24),
        cpu_count:                normalize_cpu_count(raw_cpu_count),
        vt_root_enabled:          rd_bool(&out, 32),
        debugger_proxy_enabled:   rd_bool(&out, 33),
        access_bypass_enabled:    rd_bool(&out, 34),
    })
}

fn normalize_cpu_count(driver_value: u32) -> u32 {
    if driver_value != 0 {
        return driver_value;
    }

    std::thread::available_parallelism()
        .map(|n| n.get() as u32)
        .unwrap_or(0)
}
