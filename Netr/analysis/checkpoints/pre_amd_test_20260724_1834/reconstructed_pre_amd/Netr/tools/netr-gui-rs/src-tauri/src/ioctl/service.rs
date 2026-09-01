//! Windows SCM 操作:install / start / stop / uninstall / query。
//!
//! Driver 服务名约定:固定为 "Netr"(与旧 Python GUI 一致,driver 名 = 服务名)。
//! 启动类型:SERVICE_DEMAND_START(手动启动)
//! 类型:    SERVICE_KERNEL_DRIVER
//!
//! 路径策略:用户通过 GUI 选择 .sys 文件路径(或默认 ./Netr.sys 相对路径)。
//! SCM 内部用绝对路径转 NT 路径。我们 install 时传 \??\<绝对路径>。

use std::path::Path;
use serde::Serialize;
use windows::core::PCWSTR;
use windows::Win32::System::Services::{
    CloseServiceHandle, ControlService, CreateServiceW, DeleteService, OpenSCManagerW,
    OpenServiceW, QueryServiceStatusEx, StartServiceW, ENUM_SERVICE_TYPE, SC_HANDLE,
    SC_MANAGER_ALL_ACCESS, SC_STATUS_PROCESS_INFO, SERVICE_ALL_ACCESS, SERVICE_CONTROL_STOP,
    SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, SERVICE_KERNEL_DRIVER, SERVICE_STATUS,
    SERVICE_STATUS_PROCESS,
};

use crate::util::error::{AppError, AppResult};

pub const SERVICE_NAME: &str = "Netr";

/// 状态枚举,前端能用。
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ServiceState {
    NotInstalled,
    Stopped,
    StartPending,
    StopPending,
    Running,
    ContinuePending,
    PausePending,
    Paused,
    Unknown,
}

impl ServiceState {
    fn from_raw(v: u32) -> ServiceState {
        match v {
            1 => ServiceState::Stopped,
            2 => ServiceState::StartPending,
            3 => ServiceState::StopPending,
            4 => ServiceState::Running,
            5 => ServiceState::ContinuePending,
            6 => ServiceState::PausePending,
            7 => ServiceState::Paused,
            _ => ServiceState::Unknown,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ServiceInfo {
    pub state: ServiceState,
    pub process_id: u32,
    pub image_path: Option<String>,
}

struct ScmHandle(SC_HANDLE);
impl Drop for ScmHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                let _ = CloseServiceHandle(self.0);
            }
        }
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn open_scm() -> AppResult<ScmHandle> {
    let h = unsafe { OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_ALL_ACCESS) }
        .map_err(|e| AppError::Io(format!("OpenSCManager: {e}")))?;
    Ok(ScmHandle(h))
}

fn open_service(scm: &ScmHandle, access: u32) -> AppResult<ScmHandle> {
    let name = wide(SERVICE_NAME);
    let h = unsafe { OpenServiceW(scm.0, PCWSTR(name.as_ptr()), access) }
        .map_err(|e| AppError::Io(format!("OpenService {SERVICE_NAME}: {e}")))?;
    Ok(ScmHandle(h))
}

/// 安装 driver 服务(driver_path 是绝对路径)
pub fn install(driver_path: &str) -> AppResult<()> {
    let path = Path::new(driver_path);
    if !path.is_file() {
        return Err(AppError::Io(format!("driver file not found: {driver_path}")));
    }
    let abs = path
        .canonicalize()
        .map_err(|e| AppError::Io(format!("canonicalize: {e}")))?;
    // 去掉 \\?\ 前缀(Windows API 直接吃绝对路径)
    let abs_str = abs.to_string_lossy().trim_start_matches(r"\\?\").to_string();

    let scm = open_scm()?;
    let name = wide(SERVICE_NAME);
    let display = wide("Netr Hypervisor");
    let bin = wide(&abs_str);

    let h = unsafe {
        CreateServiceW(
            scm.0,
            PCWSTR(name.as_ptr()),
            PCWSTR(display.as_ptr()),
            SERVICE_ALL_ACCESS,
            ENUM_SERVICE_TYPE(SERVICE_KERNEL_DRIVER.0),
            SERVICE_DEMAND_START,
            SERVICE_ERROR_NORMAL,
            PCWSTR(bin.as_ptr()),
            PCWSTR::null(),
            None,
            PCWSTR::null(),
            PCWSTR::null(),
            PCWSTR::null(),
        )
    }
    .map_err(|e| AppError::Io(format!("CreateService: {e}")))?;
    unsafe { let _ = CloseServiceHandle(h); }
    Ok(())
}

pub fn start() -> AppResult<()> {
    let scm = open_scm()?;
    let svc = open_service(&scm, SERVICE_ALL_ACCESS)?;
    unsafe { StartServiceW(svc.0, None) }
        .map_err(|e| {
            // 已经在跑就忽略
            let code = e.code().0 as u32;
            const ERROR_SERVICE_ALREADY_RUNNING: u32 = 1056;
            if code == ERROR_SERVICE_ALREADY_RUNNING {
                AppError::Internal("already running".into()) // 后面 swallow
            } else {
                AppError::Io(format!("StartService: {e}"))
            }
        })
        .or_else(|e| match e {
            AppError::Internal(m) if m == "already running" => Ok(()),
            other => Err(other),
        })?;
    Ok(())
}

pub fn stop() -> AppResult<()> {
    let scm = open_scm()?;
    let svc = open_service(&scm, SERVICE_ALL_ACCESS)?;
    let mut status = SERVICE_STATUS::default();
    unsafe { ControlService(svc.0, SERVICE_CONTROL_STOP, &mut status) }
        .map_err(|e| {
            let code = e.code().0 as u32;
            const ERROR_SERVICE_NOT_ACTIVE: u32 = 1062;
            if code == ERROR_SERVICE_NOT_ACTIVE {
                AppError::Internal("not active".into())
            } else {
                AppError::Io(format!("ControlService(STOP): {e}"))
            }
        })
        .or_else(|e| match e {
            AppError::Internal(m) if m == "not active" => Ok(()),
            other => Err(other),
        })?;
    Ok(())
}

pub fn uninstall() -> AppResult<()> {
    let scm = open_scm()?;
    let svc = match open_service(&scm, SERVICE_ALL_ACCESS) {
        Ok(s) => s,
        Err(_) => return Ok(()), // 不存在视为成功
    };
    unsafe { DeleteService(svc.0) }
        .map_err(|e| AppError::Io(format!("DeleteService: {e}")))?;
    Ok(())
}

pub fn query() -> AppResult<ServiceInfo> {
    let scm = open_scm()?;
    let svc = match open_service(&scm, SERVICE_ALL_ACCESS) {
        Ok(s) => s,
        Err(_) => {
            return Ok(ServiceInfo {
                state: ServiceState::NotInstalled,
                process_id: 0,
                image_path: None,
            })
        }
    };

    let mut buf = [0u8; std::mem::size_of::<SERVICE_STATUS_PROCESS>()];
    let mut needed: u32 = 0;
    unsafe {
        QueryServiceStatusEx(
            svc.0,
            SC_STATUS_PROCESS_INFO,
            Some(&mut buf),
            &mut needed,
        )
    }
    .map_err(|e| AppError::Io(format!("QueryServiceStatusEx: {e}")))?;

    let status_ptr = buf.as_ptr() as *const SERVICE_STATUS_PROCESS;
    let status = unsafe { *status_ptr };

    Ok(ServiceInfo {
        state: ServiceState::from_raw(status.dwCurrentState.0),
        process_id: status.dwProcessId,
        image_path: None, // 可选:再调 QueryServiceConfigW 拿 binary path
    })
}
