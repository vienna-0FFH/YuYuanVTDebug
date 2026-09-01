use serde::{Deserialize, Serialize};
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};
use tauri::State;
use windows::core::PWSTR;
use windows::Win32::Foundation::{CloseHandle, BOOL, HANDLE, STILL_ACTIVE};
use windows::Win32::System::Threading::{
    CreateProcessW, GetExitCodeProcess, IsWow64Process, OpenProcess,
    TerminateProcess, WaitForInputIdle, CREATE_NEW_CONSOLE,
    PROCESS_CREATION_FLAGS, PROCESS_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION,
    STARTUPINFOW,
};

use crate::ioctl::DeviceState;
use crate::util::error::{AppError, AppResult};

use super::debugger::{debugger_add_impl, debugger_remove};

#[derive(Debug, Deserialize)]
pub struct DebuggerBridgeLaunchRequest {
    pub exe_path: String,
    pub args: String,
    pub working_dir: Option<String>,
    pub enable_privilege: bool,
    pub protect_from_terminate: bool,
    pub hide_from_list: bool,
}

#[derive(Debug, Deserialize)]
pub struct DebuggerBridgeInjectRequest {
    pub pid: u32,
    pub process_name: String,
    pub enable_privilege: bool,
    pub protect_from_terminate: bool,
    pub hide_from_list: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct DebuggerBridgeResult {
    pub pid: u32,
    pub architecture: String,
    pub bridge_path: String,
    pub injector_path: String,
}

struct BridgeArtifacts {
    architecture: &'static str,
    bridge: PathBuf,
    injector: PathBuf,
}

struct QueryProcessHandle(HANDLE);

impl Drop for QueryProcessHandle {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

fn wide(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(std::iter::once(0)).collect()
}

fn candidate_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Some(dir) = std::env::var_os("NETR_BRIDGE_DIR") {
        dirs.push(PathBuf::from(dir));
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            dirs.push(dir.to_path_buf());
            dirs.push(dir.join("DebuggerBridge"));
            dirs.push(dir.join("bridge"));
        }
    }

    // Development tree: src-tauri -> netr-gui-rs -> tools -> Netr.
    dirs.push(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("..")
            .join("DebuggerBridge")
            .join("bin"),
    );
    dirs
}

fn resolve_artifacts(wow64: bool) -> AppResult<BridgeArtifacts> {
    let suffix = if wow64 { "32" } else { "64" };
    let bridge_name = format!("NetrDebuggerBridge{suffix}.dll");
    let injector_name = format!("NetrBridgeInjector{suffix}.exe");

    for dir in candidate_dirs() {
        let bridge = dir.join(&bridge_name);
        let injector = dir.join(&injector_name);
        if bridge.is_file() && injector.is_file() {
            return Ok(BridgeArtifacts {
                architecture: if wow64 { "x86" } else { "x64" },
                bridge: bridge.canonicalize().unwrap_or(bridge),
                injector: injector.canonicalize().unwrap_or(injector),
            });
        }
    }

    Err(AppError::Internal(format!(
        "debugger bridge artifacts not found ({bridge_name}, {injector_name}); run Netr\\DebuggerBridge\\build.bat or set NETR_BRIDGE_DIR"
    )))
}

fn open_process_for_query(pid: u32) -> AppResult<QueryProcessHandle> {
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }
        .map_err(|e| AppError::Io(format!("OpenProcess({pid}) for architecture: {e}")))?;
    Ok(QueryProcessHandle(process))
}

fn target_is_wow64(process: HANDLE, pid: u32) -> AppResult<bool> {
    let mut wow64 = BOOL(0);
    let result = unsafe { IsWow64Process(process, &mut wow64) };
    result.map_err(|e| AppError::Io(format!("IsWow64Process({pid}): {e}")))?;
    Ok(wow64.as_bool())
}

fn ensure_process_active(process: HANDLE, pid: u32, phase: &str) -> AppResult<()> {
    let mut exit_code = 0u32;
    unsafe { GetExitCodeProcess(process, &mut exit_code) }
        .map_err(|e| AppError::Io(format!("GetExitCodeProcess({pid}) {phase}: {e}")))?;
    if exit_code != STILL_ACTIVE.0 as u32 {
        return Err(AppError::Internal(format!(
            "debugger PID {pid} exited {phase} (exit code 0x{exit_code:08X})"
        )));
    }
    Ok(())
}

fn wait_for_host_initialization(process: HANDLE, pid: u32) -> AppResult<()> {
    // Both reference launchers leave the debugger alone for at least one
    // second before injection.  The observed CLR plug-in failure happened at
    // process uptime ~= 1 s, so keep a full second beyond that boundary.
    // WaitForInputIdle still lets a slower GUI extend the grace naturally.
    const MINIMUM_GRACE: Duration = Duration::from_secs(2);
    const INPUT_IDLE_TIMEOUT_MS: u32 = 1_500;

    ensure_process_active(process, pid, "before host initialization grace")?;
    let started = Instant::now();
    let _ = unsafe { WaitForInputIdle(process, INPUT_IDLE_TIMEOUT_MS) };
    if let Some(remaining) = MINIMUM_GRACE.checked_sub(started.elapsed()) {
        std::thread::sleep(remaining);
    }
    ensure_process_active(process, pid, "during host initialization grace")
}

fn run_injector(pid: u32, artifacts: &BridgeArtifacts) -> AppResult<()> {
    let output = Command::new(&artifacts.injector)
        .arg("--deferred")
        .arg(pid.to_string())
        .arg(&artifacts.bridge)
        .output()
        .map_err(|e| {
            AppError::Io(format!(
                "start {}: {e}",
                artifacts.injector.display()
            ))
        })?;

    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let detail = if !stderr.is_empty() { stderr } else { stdout };
    Err(AppError::Internal(format!(
        "bridge injector failed (exit={}): {}",
        output.status.code().unwrap_or(-1),
        if detail.is_empty() { "no diagnostic output" } else { &detail }
    )))
}

fn run_bridge_control(
    pid: u32,
    artifacts: &BridgeArtifacts,
    action: &str,
) -> AppResult<()> {
    let output = Command::new(&artifacts.injector)
        .arg(action)
        .arg(pid.to_string())
        .output()
        .map_err(|e| {
            AppError::Io(format!(
                "start {} {action}: {e}",
                artifacts.injector.display()
            ))
        })?;

    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let detail = if !stderr.is_empty() { stderr } else { stdout };
    Err(AppError::Internal(format!(
        "bridge control {action} failed (exit={}): {}",
        output.status.code().unwrap_or(-1),
        if detail.is_empty() { "no diagnostic output" } else { &detail }
    )))
}

fn result_from(pid: u32, artifacts: BridgeArtifacts) -> DebuggerBridgeResult {
    DebuggerBridgeResult {
        pid,
        architecture: artifacts.architecture.to_string(),
        bridge_path: artifacts.bridge.to_string_lossy().to_string(),
        injector_path: artifacts.injector.to_string_lossy().to_string(),
    }
}

fn close_process_info(pi: &PROCESS_INFORMATION) {
    unsafe {
        let _ = CloseHandle(pi.hThread);
        let _ = CloseHandle(pi.hProcess);
    }
}

fn terminate_process(pi: &PROCESS_INFORMATION) -> AppResult<()> {
    let result = unsafe { TerminateProcess(pi.hProcess, 1) }
        .map_err(|e| AppError::Io(format!("TerminateProcess rollback failed: {e}")));
    close_process_info(pi);
    result
}

#[tauri::command]
pub fn debugger_bridge_launch(
    device: State<'_, DeviceState>,
    req: DebuggerBridgeLaunchRequest,
) -> AppResult<DebuggerBridgeResult> {
    let exe = PathBuf::from(&req.exe_path);
    if !exe.is_file() {
        return Err(AppError::Io(format!(
            "debugger executable not found: {}",
            exe.display()
        )));
    }
    let working_dir = match &req.working_dir {
        Some(value) if !value.is_empty() => PathBuf::from(value),
        _ => exe.parent().unwrap_or(Path::new(".")).to_path_buf(),
    };
    let process_name = exe
        .file_name()
        .and_then(OsStr::to_str)
        .unwrap_or("debugger")
        .to_string();

    let command_line = if req.args.is_empty() {
        format!("\"{}\"", exe.display())
    } else {
        format!("\"{}\" {}", exe.display(), req.args)
    };
    let mut command_line_w = wide(OsStr::new(&command_line));
    let working_dir_w = wide(working_dir.as_os_str());

    let mut startup = STARTUPINFOW {
        cb: std::mem::size_of::<STARTUPINFOW>() as u32,
        ..Default::default()
    };
    let mut process_info = PROCESS_INFORMATION::default();
    // Match the reference launch lifecycle: allow the debugger's normal
    // loader/plug-in startup to run, then inject only after the host grace.
    let flags = PROCESS_CREATION_FLAGS(CREATE_NEW_CONSOLE.0);
    unsafe {
        CreateProcessW(
            None,
            PWSTR(command_line_w.as_mut_ptr()),
            None,
            None,
            false,
            flags,
            None,
            PWSTR(working_dir_w.as_ptr() as *mut u16),
            &startup,
            &mut process_info,
        )
    }
    .map_err(|e| AppError::Io(format!("CreateProcessW: {e}")))?;
    let _ = &mut startup;

    let pid = process_info.dwProcessId;
    let operation = (|| -> AppResult<DebuggerBridgeResult> {
        let wow64 = target_is_wow64(process_info.hProcess, pid)?;
        let artifacts = resolve_artifacts(wow64)?;

        // Leave the host/plug-in loader a real initialization grace before
        // touching any module or arming debugger policy in the driver.
        wait_for_host_initialization(process_info.hProcess, pid)?;
        ensure_process_active(process_info.hProcess, pid, "before bridge injection")?;
        run_injector(pid, &artifacts)?;
        ensure_process_active(process_info.hProcess, pid, "after bridge injection")?;
        debugger_add_impl(
            device.inner(),
            pid,
            &process_name,
            req.enable_privilege,
            req.protect_from_terminate,
            req.hide_from_list,
            true,
        )?;
        run_bridge_control(pid, &artifacts, "--commit")?;
        Ok(result_from(pid, artifacts))
    })();

    match operation {
        Ok(result) => {
            close_process_info(&process_info);
            Ok(result)
        }
        Err(error) => {
            // We own a process created by this command.  Never leave a
            // partially injected or unprotected debugger running after any
            // launch-stage failure.
            let remove_result = debugger_remove(device, pid);
            let terminate_result = terminate_process(&process_info);
            let rollback = match (remove_result, terminate_result) {
                (Ok(()), Ok(())) => "driver state removed; process terminated".to_string(),
                (remove, terminate) => format!(
                    "driver_remove={}; terminate={}",
                    remove.map(|_| "ok".to_string()).unwrap_or_else(|e| e.to_string()),
                    terminate.map(|_| "ok".to_string()).unwrap_or_else(|e| e.to_string()),
                ),
            };
            Err(AppError::Internal(format!(
                "debugger PID {pid} launch failed: {error}; rollback: {rollback}"
            )))
        }
    }
}

#[tauri::command]
pub fn debugger_bridge_inject(
    device: State<'_, DeviceState>,
    req: DebuggerBridgeInjectRequest,
) -> AppResult<DebuggerBridgeResult> {
    if req.pid == 0 || req.pid == std::process::id() {
        return Err(AppError::Internal("invalid external debugger PID".into()));
    }

    let process = open_process_for_query(req.pid)?;
    ensure_process_active(process.0, req.pid, "before bridge injection")?;
    let wow64 = target_is_wow64(process.0, req.pid)?;
    let artifacts = resolve_artifacts(wow64)?;
    wait_for_host_initialization(process.0, req.pid)?;
    ensure_process_active(process.0, req.pid, "after host initialization grace")?;
    run_injector(req.pid, &artifacts)?;
    ensure_process_active(process.0, req.pid, "after bridge injection")?;
    if let Err(error) = debugger_add_impl(
        device.inner(),
        req.pid,
        &req.process_name,
        req.enable_privilege,
        req.protect_from_terminate,
        req.hide_from_list,
        true,
    ) {
        let abort = run_bridge_control(req.pid, &artifacts, "--abort")
            .map(|_| "bridge publication aborted".to_string())
            .unwrap_or_else(|abort_error| format!("bridge abort failed: {abort_error}"));
        return Err(AppError::Internal(format!(
            "debugger PID {} driver protection failed before hook commit: {}; {}; any pre-existing driver registration was left unchanged",
            req.pid,
            error,
            abort
        )));
    }
    if let Err(error) = run_bridge_control(req.pid, &artifacts, "--commit") {
        let abort = run_bridge_control(req.pid, &artifacts, "--abort")
            .map(|_| "bridge publication aborted".to_string())
            .unwrap_or_else(|abort_error| format!("bridge abort failed: {abort_error}"));
        return Err(AppError::Internal(format!(
            "debugger PID {} was registered in the driver, but Bridge hook commit failed: {}; {}; the driver identity/configuration was retained because this command cannot safely distinguish a new record from an update",
            req.pid,
            error,
            abort
        )));
    }
    Ok(result_from(req.pid, artifacts))
}
