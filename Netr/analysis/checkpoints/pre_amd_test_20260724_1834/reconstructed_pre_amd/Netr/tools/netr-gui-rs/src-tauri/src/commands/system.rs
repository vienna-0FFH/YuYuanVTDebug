//! 系统级辅助 commands:列进程 / 启动进程 / 浏览选 exe。
//!
//! 列进程:CreateToolhelp32Snapshot + Process32FirstW/Process32NextW(快),
//!         然后 QueryFullProcessImageNameW 拿到完整路径。
//! 启动进程:CreateProcessW(适合带参数)或 ShellExecuteW(走 Shell 关联)。
//! 这里用 CreateProcessW,suspended=false。
//!
//! 注意:list_processes 是同步 + 需要遍历整张快照,
//! 必须放 spawn_blocking 里,不然 tokio worker 会被阻塞。

use serde::{Deserialize, Serialize};
use std::os::windows::ffi::OsStrExt;
use std::path::PathBuf;
use windows::core::PWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE, MAX_PATH};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
    TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Threading::{
    CreateProcessW, OpenProcess, QueryFullProcessImageNameW, CREATE_NEW_CONSOLE,
    PROCESS_CREATION_FLAGS, PROCESS_INFORMATION, PROCESS_NAME_FORMAT, PROCESS_QUERY_LIMITED_INFORMATION,
    STARTUPINFOW,
};

use crate::util::error::{AppError, AppResult};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    /// 完整 exe 路径,失败为空串(常因权限不足/系统进程)
    pub path: String,
    /// 父进程 PID,失败为 0
    pub parent_pid: u32,
}

/// 枚举所有用户态进程(返回时 pid 升序)。
fn enumerate() -> AppResult<Vec<ProcessInfo>> {
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
            .map_err(|e| AppError::Internal(format!("CreateToolhelp32Snapshot: {e}")))?;

        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };

        let mut out = Vec::with_capacity(256);
        if Process32FirstW(snap, &mut entry).is_ok() {
            loop {
                let name = utf16_to_string(&entry.szExeFile);
                let path = query_image_path(entry.th32ProcessID).unwrap_or_default();
                out.push(ProcessInfo {
                    pid: entry.th32ProcessID,
                    name,
                    path,
                    parent_pid: entry.th32ParentProcessID,
                });
                if Process32NextW(snap, &mut entry).is_err() {
                    break;
                }
            }
        }

        let _ = CloseHandle(snap);
        out.sort_by_key(|p| p.pid);
        Ok(out)
    }
}

fn utf16_to_string(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}

fn query_image_path(pid: u32) -> Option<String> {
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
        if h.is_invalid() {
            return None;
        }
        let mut buf = [0u16; MAX_PATH as usize];
        let mut size = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(
            h,
            PROCESS_NAME_FORMAT(0),
            PWSTR(buf.as_mut_ptr()),
            &mut size,
        )
        .is_ok();
        let _ = CloseHandle(h);
        if ok {
            Some(String::from_utf16_lossy(&buf[..size as usize]))
        } else {
            None
        }
    }
}

#[tauri::command]
pub async fn system_list_processes() -> AppResult<Vec<ProcessInfo>> {
    tokio::task::spawn_blocking(enumerate)
        .await
        .map_err(|e| AppError::Internal(format!("spawn_blocking: {e}")))?
}

/// 启动一个进程,返回新 PID。
/// - exe_path 必须是绝对路径
/// - args 拼接到命令行
/// - working_dir 为空时用 exe 同目录
#[derive(Debug, Deserialize)]
pub struct LaunchRequest {
    pub exe_path: String,
    pub args: String,
    pub working_dir: Option<String>,
}

#[tauri::command]
pub async fn system_launch_process(req: LaunchRequest) -> AppResult<u32> {
    let exe = PathBuf::from(&req.exe_path);
    if !exe.exists() {
        return Err(AppError::Internal(format!("exe 不存在: {}", req.exe_path)));
    }
    let working_dir = match &req.working_dir {
        Some(s) if !s.is_empty() => PathBuf::from(s),
        _ => exe.parent().map(|p| p.to_path_buf()).unwrap_or_else(|| PathBuf::from(".")),
    };

    // 命令行:CreateProcessW 第二个参数是 mutable PWSTR,首项常规习惯是 "\"exe\" args"
    let cmdline_str = if req.args.is_empty() {
        format!("\"{}\"", exe.display())
    } else {
        format!("\"{}\" {}", exe.display(), req.args)
    };
    let mut cmdline_w: Vec<u16> = std::ffi::OsStr::new(&cmdline_str)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let working_w: Vec<u16> = std::ffi::OsStr::new(&working_dir)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let pid = tokio::task::spawn_blocking(move || -> AppResult<u32> {
        unsafe {
            let mut si = STARTUPINFOW {
                cb: std::mem::size_of::<STARTUPINFOW>() as u32,
                ..Default::default()
            };
            let mut pi = PROCESS_INFORMATION::default();

            let ok = CreateProcessW(
                None,
                PWSTR(cmdline_w.as_mut_ptr()),
                None,
                None,
                false,
                PROCESS_CREATION_FLAGS(CREATE_NEW_CONSOLE.0),
                None,
                PWSTR(working_w.as_ptr() as *mut u16),
                &si,
                &mut pi,
            );
            // silence "unused" — &mut for cb init
            let _ = &mut si;

            if ok.is_err() {
                return Err(AppError::Internal(format!(
                    "CreateProcessW failed: {:?}",
                    ok.err()
                )));
            }

            let pid = pi.dwProcessId;
            let _ = CloseHandle(pi.hThread);
            // 主进程 handle 暂不需要保留(我们靠 PID 后续 OpenProcess)
            let _ = CloseHandle(pi.hProcess);
            Ok(pid)
        }
    })
    .await
    .map_err(|e| AppError::Internal(format!("spawn_blocking: {e}")))??;

    Ok(pid)
}

/// 返回 GUI exe 同目录下 Netr.sys 的绝对路径,以及该文件是否存在。
#[derive(Debug, Clone, Serialize)]
pub struct DriverFile {
    pub path: String,
    pub exists: bool,
}

/// 检查当前进程是否以管理员/Elevated 身份运行(发 IOCTL 必需)。
#[tauri::command]
pub fn system_is_elevated() -> bool {
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return false;
        }
        let mut elev: TOKEN_ELEVATION = std::mem::zeroed();
        let mut sz = std::mem::size_of::<TOKEN_ELEVATION>() as u32;
        let r = GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elev as *mut _ as *mut _),
            sz,
            &mut sz,
        );
        let _ = windows::Win32::Foundation::CloseHandle(token);
        r.is_ok() && elev.TokenIsElevated != 0
    }
}

/// 以管理员身份重启自身(走 ShellExecuteW "runas" 触发 UAC)。
/// 成功 → 当前进程立刻退出,新实例由 Shell 启动。
#[tauri::command]
pub fn system_restart_as_admin() -> AppResult<()> {
    use windows::core::PCWSTR;
    use windows::Win32::UI::Shell::ShellExecuteW;
    use windows::Win32::UI::WindowsAndMessaging::SW_NORMAL;

    let exe = std::env::current_exe()
        .map_err(|e| AppError::Internal(format!("current_exe: {e}")))?;
    let exe_w: Vec<u16> = std::ffi::OsStr::new(&exe)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let verb_w: Vec<u16> = "runas\0".encode_utf16().collect();

    unsafe {
        let h = ShellExecuteW(
            None,
            PCWSTR(verb_w.as_ptr()),
            PCWSTR(exe_w.as_ptr()),
            PCWSTR::null(),
            PCWSTR::null(),
            SW_NORMAL,
        );
        // ShellExecuteW 返回 > 32 表示成功;<= 32 是错误码
        if (h.0 as isize) <= 32 {
            return Err(AppError::Internal(format!(
                "ShellExecuteW runas failed: {}",
                h.0 as isize
            )));
        }
    }

    // 给 Shell 一点时间真正 spawn 出新进程,然后我们退出
    std::thread::spawn(|| {
        std::thread::sleep(std::time::Duration::from_millis(300));
        std::process::exit(0);
    });
    Ok(())
}

#[tauri::command]
pub fn system_resolve_driver_path() -> AppResult<DriverFile> {
    let exe =
        std::env::current_exe().map_err(|e| AppError::Internal(format!("current_exe: {e}")))?;
    let dir = exe
        .parent()
        .ok_or_else(|| AppError::Internal("exe 无父目录".into()))?;
    let sys = dir.join("GuardMetaCore.sys");
    let exists = sys.is_file();
    Ok(DriverFile {
        path: sys.to_string_lossy().to_string(),
        exists,
    })
}

/// 检查进程是否仍存活。
#[tauri::command]
pub async fn system_process_alive(pid: u32) -> AppResult<bool> {
    let alive = tokio::task::spawn_blocking(move || unsafe {
        let h: Result<HANDLE, _> = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        match h {
            Ok(h) if !h.is_invalid() => {
                let _ = CloseHandle(h);
                true
            }
            _ => false,
        }
    })
    .await
    .map_err(|e| AppError::Internal(format!("spawn_blocking: {e}")))?;
    Ok(alive)
}
