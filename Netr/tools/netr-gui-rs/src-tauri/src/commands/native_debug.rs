//! Windows DebugObject sessions used by the built-in debugger's native mode.
//!
//! A dedicated OS thread owns each launch/attach and all of its debug events.
//! Keeping byte-breakpoint restoration, TF stepping, DR state and
//! `ContinueDebugEvent` on that one thread makes event ownership explicit and
//! prevents the UI from submitting one debug event more than once.

use parking_lot::{Condvar, Mutex};
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::ffi::{c_void, OsStr};
use std::fs::OpenOptions;
use std::io::Write;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tauri::{AppHandle, Emitter, Manager};
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{
    CloseHandle, GetLastError, BOOL, DBG_CONTINUE, DBG_EXCEPTION_NOT_HANDLED,
    ERROR_SEM_TIMEOUT, EXCEPTION_BREAKPOINT, EXCEPTION_SINGLE_STEP, HANDLE, NTSTATUS,
    WAIT_OBJECT_0,
};
use windows::Win32::System::Diagnostics::Debug::{
    ContinueDebugEvent, DebugActiveProcess, DebugActiveProcessStop, DebugSetProcessKillOnExit,
    FlushInstructionCache, GetThreadContext, ReadProcessMemory, SetThreadContext,
    WaitForDebugEventEx, Wow64GetThreadContext, Wow64SetThreadContext,
    WriteProcessMemory, CONTEXT, CONTEXT_CONTROL_AMD64, CONTEXT_DEBUG_REGISTERS_AMD64,
    CREATE_PROCESS_DEBUG_EVENT, CREATE_THREAD_DEBUG_EVENT, DEBUG_EVENT,
    EXCEPTION_DEBUG_EVENT, EXIT_PROCESS_DEBUG_EVENT, EXIT_THREAD_DEBUG_EVENT,
    LOAD_DLL_DEBUG_EVENT, WOW64_CONTEXT, WOW64_CONTEXT_CONTROL,
    WOW64_CONTEXT_DEBUG_REGISTERS,
};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
};
use windows::Win32::System::Memory::{
    VirtualProtectEx, PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS,
};
use windows::Win32::System::Threading::{
    CreateProcessW, GetProcessId, IsWow64Process, OpenProcess, OpenThread, ResumeThread,
    SuspendThread, TerminateProcess, WaitForSingleObject,
    CREATE_NEW_CONSOLE, DEBUG_ONLY_THIS_PROCESS, PROCESS_CREATION_FLAGS, PROCESS_INFORMATION,
    PROCESS_QUERY_INFORMATION, PROCESS_SYNCHRONIZE, PROCESS_TERMINATE, PROCESS_VM_OPERATION,
    PROCESS_VM_READ, PROCESS_VM_WRITE, STARTUPINFOW, THREAD_GET_CONTEXT, THREAD_SET_CONTEXT,
    THREAD_SUSPEND_RESUME, THREAD_SYNCHRONIZE,
};

use crate::util::error::{AppError, AppResult};
use crate::ioctl::codes::{
    IOCTL_HV_BRIDGE_BIND_TARGET, IOCTL_HV_BRIDGE_PENDING_HWBP,
    IOCTL_HV_BRIDGE_UNBIND_TARGET,
};
use crate::ioctl::DeviceState;

const STAGE_CREATE_EVENT_GATED: u32 = 0;
const STAGE_RUNNING_TO_ENTRY: u32 = 1;
const STAGE_ENTRY_PENDING: u32 = 2;
const STAGE_ENTRY_CONTINUED: u32 = 3;
const STAGE_ENDED: u32 = 4;
const STAGE_DETACH_RETRY: u32 = 5;
const STAGE_WAITING_INITIAL_SYSTEM_BREAKPOINT: u32 = 6;

const EVENT_POLL_MS: u32 = 50;
const LAUNCH_TIMEOUT: Duration = Duration::from_secs(15);
// TLS callbacks, packers and large game runtimes can legitimately take a long
// time before reaching the PE entry. The UI remains asynchronous and detach
// stays available through the control channel while this wait is outstanding.
const RUN_TO_ENTRY_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const CONTROL_TIMEOUT: Duration = Duration::from_secs(5);
const WORKER_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(15);
const FORCED_CLEANUP_TIMEOUT: Duration = Duration::from_secs(3);
const FORCED_DETACH_GRACE: Duration = Duration::from_millis(500);
const BRIDGE_PROTOCOL_VERSION: u32 = 6;
const BRIDGE_BIND_DEFAULT_FLAGS: u32 = 0x0000_0007;
const BRIDGE_BIND_EXPECT_WINDOWS_DEBUG_OBJECT: u32 = 0x0001_0000;
const BRIDGE_BIND_EXPECT_PRIVATE_DBGK: u32 = 0x0002_0000;
const BRIDGE_BIND_DEFER_PEB_CLOAK: u32 = 0x0004_0000;
const HRESULT_ERROR_DEBUGGER_INACTIVE: i32 = 0x8007_0504u32 as i32;
const STATUS_NOT_FOUND: i32 = 0xC000_0225u32 as i32;
const PENDING_HWBP_QUERY: u32 = 0;
const PENDING_HWBP_RETIRE: u32 = 1;

#[repr(C)]
struct PrivateTargetRequest {
    version: u32,
    target_pid: u32,
    flags: u32,
    reserved: u32,
}

#[repr(C)]
struct PrivateTargetResult {
    version: u32,
    status: i32,
    debugger_pid: u32,
    target_pid: u32,
    active_bindings: u32,
    flags: u32,
}

const _: [(); 16] = [(); std::mem::size_of::<PrivateTargetRequest>()];
const _: [(); 24] = [(); std::mem::size_of::<PrivateTargetResult>()];

#[repr(C)]
struct PendingHardwareBreakpointRequest {
    version: u32,
    target_pid: u32,
    thread_id: u32,
    operation: u32,
    generation: u64,
}

#[repr(C)]
struct PendingHardwareBreakpointResult {
    status: i32,
    reserved: u32,
    generation: u64,
    dr6_mask: u64,
}

#[derive(Debug, Clone, Copy)]
struct PendingHardwareHit {
    generation: u64,
    dr6_mask: u64,
}

const _: [(); 24] = [(); std::mem::size_of::<PendingHardwareBreakpointRequest>()];
const _: [(); 24] = [(); std::mem::size_of::<PendingHardwareBreakpointResult>()];

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtCreateDebugObject(
        debug_handle: *mut HANDLE,
        desired_access: u32,
        object_attributes: *const c_void,
        flags: u32,
    ) -> NTSTATUS;
    fn DbgUiSetThreadDebugObject(debug_handle: HANDLE);
}

fn create_private_debug_object() -> AppResult<HANDLE> {
    let mut handle = HANDLE::default();
    let status = unsafe {
        NtCreateDebugObject(
            &mut handle,
            0x001F_000Fu32,
            std::ptr::null(),
            0,
        )
    };
    if status.0 < 0 || handle.is_invalid() {
        return Err(AppError::Internal(format!(
            "NtCreateDebugObject(private) failed: 0x{:08X}",
            status.0 as u32
        )));
    }
    unsafe { DbgUiSetThreadDebugObject(handle) };
    Ok(handle)
}

struct PrivateDebugObjectGuard(HANDLE);

impl Drop for PrivateDebugObjectGuard {
    fn drop(&mut self) {
        unsafe { DbgUiSetThreadDebugObject(HANDLE::default()) };
        close_handle(self.0);
    }
}

fn private_target_operation(
    app: &AppHandle,
    pid: u32,
    code: u32,
    flags: u32,
) -> AppResult<()> {
    private_dbgk_entry_diag(
        pid,
        "bridge.target.begin",
        format!("ioctl=0x{code:X} flags=0x{flags:X}"),
    );
    let device = app.state::<DeviceState>();
    let request = PrivateTargetRequest {
        version: BRIDGE_PROTOCOL_VERSION,
        target_pid: pid,
        flags,
        reserved: 0,
    };
    let mut result = PrivateTargetResult {
        version: 0,
        status: 0,
        debugger_pid: 0,
        target_pid: 0,
        active_bindings: 0,
        flags: 0,
    };
    let written = match device.ioctl(
        code,
        unsafe {
            std::slice::from_raw_parts(
                (&request as *const PrivateTargetRequest).cast::<u8>(),
                std::mem::size_of::<PrivateTargetRequest>(),
            )
        },
        unsafe {
            std::slice::from_raw_parts_mut(
                (&mut result as *mut PrivateTargetResult).cast::<u8>(),
                std::mem::size_of::<PrivateTargetResult>(),
            )
        },
    ) {
        Ok(written) => written,
        Err(error) => {
            private_dbgk_entry_diag(
                pid,
                "bridge.target.error",
                format!("ioctl=0x{code:X} error={error}"),
            );
            return Err(error);
        }
    };
    private_dbgk_entry_diag(
        pid,
        "bridge.target.result",
        format!(
            "ioctl=0x{code:X} bytes={written} version={} status=0x{:08X} debugger_pid={} target_pid={} active_bindings={} flags=0x{:X}",
            result.version,
            result.status as u32,
            result.debugger_pid,
            result.target_pid,
            result.active_bindings,
            result.flags,
        ),
    );
    if written as usize != std::mem::size_of::<PrivateTargetResult>() ||
        result.version != BRIDGE_PROTOCOL_VERSION || result.status < 0 {
        return Err(AppError::Internal(format!(
            "private Dbgk target operation 0x{code:X} failed for PID {pid}: bytes={written}, status=0x{:08X}",
            result.status as u32
        )));
    }
    Ok(())
}

struct VtTargetBindingGuard {
    app: AppHandle,
    pid: u32,
}

impl Drop for VtTargetBindingGuard {
    fn drop(&mut self) {
        let _ = private_target_operation(
            &self.app,
            self.pid,
            IOCTL_HV_BRIDGE_UNBIND_TARGET,
            0,
        );
    }
}

fn bind_vt_target(
    app: &AppHandle,
    pid: u32,
    expected_control_plane: u32,
    extra_flags: u32,
) -> AppResult<VtTargetBindingGuard> {
    private_target_operation(
        app,
        pid,
        IOCTL_HV_BRIDGE_BIND_TARGET,
        BRIDGE_BIND_DEFAULT_FLAGS | expected_control_plane | extra_flags,
    )?;
    Ok(VtTargetBindingGuard {
        app: app.clone(),
        pid,
    })
}

const HIT_ENTRY: u32 = 1;
const HIT_SOFTWARE: u32 = 2;
const HIT_HARDWARE: u32 = 3;
const HIT_SINGLE_STEP: u32 = 4;
const HIT_STEP_OVER: u32 = 5;
const EFLAGS_TRAP: u32 = 1 << 8;
const EFLAGS_RESUME: u32 = 1 << 16;
const DR6_BREAKPOINT_MASK: u64 = 0x0f;
const DR6_SINGLE_STEP: u64 = 1 << 14;
const STATUS_WX86_SINGLE_STEP: NTSTATUS = NTSTATUS(0x4000_001E);
const STATUS_WX86_BREAKPOINT: NTSTATUS = NTSTATUS(0x4000_001F);

static SESSION_SEQUENCE: AtomicU64 = AtomicU64::new(1);
static HIT_SEQUENCE: AtomicU64 = AtomicU64::new(1);
static NATIVE_SESSIONS: OnceLock<Mutex<HashMap<u32, NativeSessionControl>>> =
    OnceLock::new();

// BEGIN TEMP_VT_DEBUG_DIAGNOSTICS: remove this diagnostic-only block before release.
// This was originally private-Dbgk-only. Keep the existing helper names for a
// small diagnostic-only change, but create a log for both VT control planes.
static PRIVATE_DBGK_ENTRY_DIAGNOSTICS: OnceLock<Mutex<HashMap<u32, PathBuf>>> =
    OnceLock::new();
static PRIVATE_DBGK_ENTRY_DIAGNOSTIC_WRITE: OnceLock<Mutex<()>> = OnceLock::new();

fn private_dbgk_entry_diagnostics() -> &'static Mutex<HashMap<u32, PathBuf>> {
    PRIVATE_DBGK_ENTRY_DIAGNOSTICS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn diagnostic_timestamp_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or_default()
}

fn append_private_dbgk_diagnostic(path: &Path, pid: u32, phase: &str, detail: &str) {
    let Ok(mut output) = OpenOptions::new().append(true).create(true).open(path) else {
        return;
    };
    let detail = detail.replace('\r', "\\r").replace('\n', "\\n");
    let _ = writeln!(
        output,
        "timestamp_unix_ms={} pid={} host_thread={:?} phase={} detail={}",
        diagnostic_timestamp_ms(),
        pid,
        std::thread::current().id(),
        phase,
        detail,
    );
}

pub(crate) fn begin_vt_debug_diagnostics(
    pid: u32,
    exe_path: &Path,
    primary_tid: u32,
    entry_rva: u32,
    size_of_image: u32,
    control_plane: &str,
) -> Option<PathBuf> {
    let file_name = format!(
        "GuardMeta-VtDebug-p{pid}-{}.log",
        diagnostic_timestamp_ms(),
    );
    let mut directories = Vec::new();
    if let Ok(executable) = std::env::current_exe() {
        if let Some(parent) = executable.parent() {
            directories.push(parent.to_path_buf());
        }
    }
    directories.push(std::env::temp_dir());

    for directory in directories {
        let path = directory.join(&file_name);
        let Ok(mut output) = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        else {
            continue;
        };
        let _ = writeln!(output, "TEMP_VT_DEBUG_DIAGNOSTICS=1");
        let _ = writeln!(output, "remove_before_production_release=true");
        let _ = writeln!(output, "timestamp_unix_ms={}", diagnostic_timestamp_ms());
        let _ = writeln!(output, "frontend_pid={}", std::process::id());
        let _ = writeln!(output, "target_pid={pid}");
        let _ = writeln!(output, "primary_tid={primary_tid}");
        let _ = writeln!(output, "control_plane={control_plane}");
        let _ = writeln!(output, "exe_path={}", exe_path.display());
        let _ = writeln!(output, "pe_entry_rva=0x{entry_rva:X}");
        let _ = writeln!(output, "pe_size_of_image=0x{size_of_image:X}");
        let _ = writeln!(output);
        drop(output);
        private_dbgk_entry_diagnostics()
            .lock()
            .insert(pid, path.clone());
        private_dbgk_entry_diag(
            pid,
            "diagnostic.begin",
            format!("VT launch control_plane={control_plane}"),
        );
        return Some(path);
    }
    None
}

pub(crate) fn private_dbgk_entry_diagnostic_path(pid: u32) -> Option<PathBuf> {
    private_dbgk_entry_diagnostics().lock().get(&pid).cloned()
}

pub(crate) fn private_dbgk_entry_diag(pid: u32, phase: &str, detail: impl AsRef<str>) {
    let Some(path) = private_dbgk_entry_diagnostic_path(pid) else {
        return;
    };
    let _write = PRIVATE_DBGK_ENTRY_DIAGNOSTIC_WRITE
        .get_or_init(|| Mutex::new(()))
        .lock();
    append_private_dbgk_diagnostic(&path, pid, phase, detail.as_ref());
}

pub(crate) fn private_dbgk_entry_diag_all(phase: &str, detail: impl AsRef<str>) {
    let paths: Vec<(u32, PathBuf)> = private_dbgk_entry_diagnostics()
        .lock()
        .iter()
        .map(|(pid, path)| (*pid, path.clone()))
        .collect();
    let _write = PRIVATE_DBGK_ENTRY_DIAGNOSTIC_WRITE
        .get_or_init(|| Mutex::new(()))
        .lock();
    for (pid, path) in paths {
        append_private_dbgk_diagnostic(&path, pid, phase, detail.as_ref());
    }
}

pub(crate) fn private_dbgk_session_snapshot(pid: u32) -> String {
    let sessions = sessions().lock();
    let Some(control) = sessions.get(&pid) else {
        return "session=absent".into();
    };
    format!(
        "session=present control_plane={} stage={} pending_tid={} primary_tid={} entry=0x{:X}",
        control.control_plane.name(),
        control.stage.load(Ordering::Acquire),
        control.pending_tid.load(Ordering::Acquire),
        control.primary_tid,
        control.entry_address,
    )
}
// END TEMP_VT_DEBUG_DIAGNOSTICS

fn sessions() -> &'static Mutex<HashMap<u32, NativeSessionControl>> {
    NATIVE_SESSIONS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn normalize_debug_exception_code(code: NTSTATUS, wow64: bool) -> NTSTATUS {
    if wow64 && code == STATUS_WX86_BREAKPOINT {
        EXCEPTION_BREAKPOINT
    } else if wow64 && code == STATUS_WX86_SINGLE_STEP {
        EXCEPTION_SINGLE_STEP
    } else {
        code
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct NativeLaunchInfo {
    pub pid: u32,
    pub primary_tid: u32,
    pub entry_address: u64,
    pub stopped_at_entry: bool,
}

#[derive(Debug, Clone, Serialize)]
struct NativeHit {
    sequence: u64,
    pid: u32,
    tid: u32,
    rip: u64,
    kind: u32,
    entry: bool,
    slot: Option<u32>,
    transient: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum AttachedControlPlane {
    Native,
    VtWindowsDebugObject {
        hold_initial_system_breakpoint: bool,
        defer_peb_cloak: bool,
    },
    VtPrivateDbgk {
        launch_gate: bool,
    },
}

impl AttachedControlPlane {
    fn uses_private_dbgk(self) -> bool {
        matches!(self, Self::VtPrivateDbgk { .. })
    }

    fn holds_initial_system_breakpoint(self) -> bool {
        matches!(
            self,
            Self::VtWindowsDebugObject {
                hold_initial_system_breakpoint: true,
                ..
            }
        )
    }

    fn holds_private_launch_gate(self) -> bool {
        matches!(
            self,
            Self::VtPrivateDbgk {
                launch_gate: true,
            }
        )
    }

    fn defers_peb_cloak(self) -> bool {
        matches!(
            self,
            Self::VtWindowsDebugObject {
                defer_peb_cloak: true,
                ..
            } | Self::VtPrivateDbgk { launch_gate: true }
        )
    }

    fn name(self) -> &'static str {
        match self {
            Self::Native => "native Windows DebugObject",
            Self::VtWindowsDebugObject { .. } => "VT Windows DebugObject",
            Self::VtPrivateDbgk { .. } => "VT private Dbgk",
        }
    }
}

struct AttachedControlPlaneGuards {
    _private_debug_object: Option<PrivateDebugObjectGuard>,
    _vt_target_binding: Option<VtTargetBindingGuard>,
}

fn prepare_attached_control_plane(
    app: &AppHandle,
    pid: u32,
    control_plane: AttachedControlPlane,
) -> AppResult<AttachedControlPlaneGuards> {
    match control_plane {
        AttachedControlPlane::Native => Ok(AttachedControlPlaneGuards {
            _private_debug_object: None,
            _vt_target_binding: None,
        }),
        AttachedControlPlane::VtWindowsDebugObject { .. } => {
            let binding = bind_vt_target(
                app,
                pid,
                BRIDGE_BIND_EXPECT_WINDOWS_DEBUG_OBJECT,
                if control_plane.defers_peb_cloak() {
                    BRIDGE_BIND_DEFER_PEB_CLOAK
                } else {
                    0
                },
            )?;
            Ok(AttachedControlPlaneGuards {
                _private_debug_object: None,
                _vt_target_binding: Some(binding),
            })
        }
        AttachedControlPlane::VtPrivateDbgk { .. } => {
            private_dbgk_entry_diag(pid, "control_plane.prepare", "create private DebugObject");
            let debug_object = match create_private_debug_object() {
                Ok(handle) => {
                    private_dbgk_entry_diag(
                        pid,
                        "control_plane.debug_object",
                        format!("created handle={:p}", handle.0),
                    );
                    PrivateDebugObjectGuard(handle)
                }
                Err(error) => {
                    private_dbgk_entry_diag(
                        pid,
                        "control_plane.debug_object.error",
                        error.to_string(),
                    );
                    return Err(error);
                }
            };
            let binding = match bind_vt_target(
                app,
                pid,
                BRIDGE_BIND_EXPECT_PRIVATE_DBGK,
                if control_plane.defers_peb_cloak() {
                    BRIDGE_BIND_DEFER_PEB_CLOAK
                } else {
                    0
                },
            ) {
                Ok(binding) => binding,
                Err(error) => {
                    private_dbgk_entry_diag(
                        pid,
                        "control_plane.bind.error",
                        error.to_string(),
                    );
                    return Err(error);
                }
            };
            private_dbgk_entry_diag(pid, "control_plane.prepare", "private Dbgk ready");
            Ok(AttachedControlPlaneGuards {
                _private_debug_object: Some(debug_object),
                _vt_target_binding: Some(binding),
            })
        }
    }
}

#[derive(Clone)]
struct NativeSessionControl {
    id: u64,
    tx: mpsc::Sender<LoopCommand>,
    stage: Arc<AtomicU32>,
    pending_tid: Arc<AtomicU32>,
    initial_system_breakpoint: Arc<InitialSystemBreakpointState>,
    private_vt_step_intents: Option<Arc<Mutex<HashSet<u32>>>>,
    control_plane: AttachedControlPlane,
    primary_tid: u32,
    entry_address: u64,
}

struct InitialSystemBreakpointState {
    pending_tid: AtomicU32,
    changed_lock: Mutex<()>,
    changed: Condvar,
}

impl InitialSystemBreakpointState {
    fn new() -> Self {
        Self {
            pending_tid: AtomicU32::new(0),
            changed_lock: Mutex::new(()),
            changed: Condvar::new(),
        }
    }

    fn publish(&self, tid: u32) {
        let _guard = self.changed_lock.lock();
        self.pending_tid.store(tid, Ordering::Release);
        self.changed.notify_all();
    }

    fn clear(&self) {
        let _guard = self.changed_lock.lock();
        self.pending_tid.store(0, Ordering::Release);
        self.changed.notify_all();
    }
}

enum LoopCommand {
    RunToEntry(mpsc::Sender<Result<NativeLaunchInfo, String>>),
    ActivateAttach(mpsc::Sender<Result<(), String>>),
    ContinueEntry {
        tid: u32,
        reply: mpsc::Sender<Result<(), String>>,
    },
    ContinueInitialSystemBreakpoint {
        tid: u32,
        reply: mpsc::Sender<Result<(), String>>,
    },
    StepInto {
        tid: u32,
        reply: mpsc::Sender<Result<bool, String>>,
    },
    StepIntoVt {
        tid: u32,
        reply: mpsc::Sender<Result<bool, String>>,
    },
    CancelVtStep {
        tid: u32,
        reply: mpsc::Sender<Result<(), String>>,
    },
    StepOver {
        tid: u32,
        reply: mpsc::Sender<Result<NativeStepOverResult, String>>,
    },
    StepOut {
        tid: u32,
        reply: mpsc::Sender<Result<u64, String>>,
    },
    CancelStepOver {
        tid: u32,
        reply: mpsc::Sender<Result<bool, String>>,
    },
    SetSoftware {
        address: u64,
        reply: mpsc::Sender<Result<NativeSoftwareBreakpoint, String>>,
    },
    ClearSoftware {
        address: u64,
        reply: mpsc::Sender<Result<(), String>>,
    },
    ListSoftware(mpsc::Sender<Vec<NativeSoftwareBreakpoint>>),
    SetHardware {
        breakpoint: NativeHardwareBreakpoint,
        reply: mpsc::Sender<Result<(), String>>,
    },
    ClearHardware {
        slot: u32,
        reply: mpsc::Sender<Result<(), String>>,
    },
    ListHardware(mpsc::Sender<Vec<NativeHardwareBreakpoint>>),
    Detach(mpsc::Sender<Result<(), String>>),
    /// Authoritative rollback for a launch that was never delivered to the
    /// frontend. Unlike Detach, this must not leave a retryable live session.
    Abandon(mpsc::Sender<Result<(), String>>),
}

#[derive(Debug, Clone, Serialize)]
pub struct NativeSoftwareBreakpoint {
    pub address: u64,
    pub original_byte: u8,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct NativeHardwareBreakpoint {
    pub slot: u32,
    pub address: u64,
    pub length: u8,
    pub bp_type: u8,
}

#[derive(Debug, Clone, Serialize)]
pub struct NativeStepOverResult {
    pub kind: &'static str,
    pub next_rip: u64,
    pub continued_event: bool,
}

struct ByteBreakpoint {
    address: u64,
    original_byte: u8,
    armed: bool,
}

#[derive(Debug, Clone, Copy)]
enum PendingKind {
    InitialSystemBreakpoint,
    Entry,
    Software { address: u64 },
    Hardware { slot: Option<u32>, generation: u64 },
    SingleStep,
    StepOver { address: u64 },
    TransientPass { address: u64 },
}

struct PendingEvent {
    pid: u32,
    tid: u32,
    ip_rewound: bool,
    continue_status: NTSTATUS,
    rip: u64,
    kind: PendingKind,
    resume_prepared: bool,
}

#[derive(Clone, Copy)]
struct DebugRegisterState {
    dr: [u64; 4],
    dr6: u64,
    dr7: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RearmKind {
    Software,
    Transient,
}

struct HeldSuspension {
    tid: u32,
    handle: HANDLE,
}

struct RearmStep {
    address: u64,
    stop_after: bool,
    kind: RearmKind,
    tf_armed: bool,
    suspended: Vec<HeldSuspension>,
}

fn wide(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(std::iter::once(0)).collect()
}

fn app_error(context: &str, error: impl std::fmt::Display) -> AppError {
    AppError::Internal(format!("{context}: {error}"))
}

fn string_error(context: &str, error: impl std::fmt::Display) -> String {
    format!("{context}: {error}")
}

fn valid_handle(handle: HANDLE) -> bool {
    !handle.is_invalid() && !handle.0.is_null()
}

fn close_handle(handle: HANDLE) {
    if valid_handle(handle) {
        unsafe {
            let _ = CloseHandle(handle);
        }
    }
}

fn read_remote_exact(process: HANDLE, address: u64, output: &mut [u8]) -> Result<(), String> {
    let mut read = 0usize;
    unsafe {
        ReadProcessMemory(
            process,
            address as *const c_void,
            output.as_mut_ptr().cast(),
            output.len(),
            Some(&mut read),
        )
    }
    .map_err(|error| string_error(&format!("ReadProcessMemory(0x{address:X})"), error))?;
    if read != output.len() {
        return Err(format!(
            "ReadProcessMemory(0x{address:X}) returned {read}/{} bytes",
            output.len()
        ));
    }
    Ok(())
}

fn remote_entry_address(process: HANDLE, image_base: u64) -> Result<u64, String> {
    let mut dos = [0u8; 0x40];
    read_remote_exact(process, image_base, &mut dos)?;
    if &dos[0..2] != b"MZ" {
        return Err(format!("main image at 0x{image_base:X} has no MZ header"));
    }
    let nt_offset = u32::from_le_bytes(dos[0x3c..0x40].try_into().unwrap()) as u64;
    if !(0x40..=0x0100_0000).contains(&nt_offset) {
        return Err(format!("invalid PE header offset 0x{nt_offset:X}"));
    }
    let nt_address = image_base
        .checked_add(nt_offset)
        .ok_or_else(|| "PE header address overflow".to_string())?;
    // Signature + file header + OptionalHeader fields through SizeOfImage.
    let mut nt = [0u8; 84];
    read_remote_exact(process, nt_address, &mut nt)?;
    if &nt[0..4] != b"PE\0\0" {
        return Err(format!("main image at 0x{image_base:X} has no PE signature"));
    }
    let optional_magic = u16::from_le_bytes(nt[24..26].try_into().unwrap());
    if optional_magic != 0x10b && optional_magic != 0x20b {
        return Err(format!("unsupported PE optional-header magic 0x{optional_magic:04X}"));
    }
    let entry_rva = u32::from_le_bytes(nt[40..44].try_into().unwrap()) as u64;
    if entry_rva == 0 {
        return Err("PE AddressOfEntryPoint is zero".into());
    }
    let image_size = u32::from_le_bytes(nt[80..84].try_into().unwrap()) as u64;
    if image_size == 0 || entry_rva >= image_size {
        return Err(format!(
            "PE entry RVA 0x{entry_rva:X} is outside SizeOfImage 0x{image_size:X}"
        ));
    }
    image_base
        .checked_add(entry_rva)
        .ok_or_else(|| "entry-point address overflow".to_string())
}

fn patch_byte(process: HANDLE, address: u64, value: u8) -> Result<(), String> {
    let mut old = PAGE_PROTECTION_FLAGS::default();
    unsafe {
        VirtualProtectEx(
            process,
            address as *const c_void,
            1,
            PAGE_EXECUTE_READWRITE,
            &mut old,
        )
    }
    .map_err(|error| string_error(&format!("VirtualProtectEx(0x{address:X})"), error))?;

    let mut written = 0usize;
    let write_result = unsafe {
        WriteProcessMemory(
            process,
            address as *const c_void,
            (&value as *const u8).cast(),
            1,
            Some(&mut written),
        )
    };
    let flush_result = if write_result.is_ok() && written == 1 {
        unsafe { FlushInstructionCache(process, Some(address as *const c_void), 1) }
    } else {
        Ok(())
    };
    let restore_result = unsafe {
        let mut ignored = PAGE_PROTECTION_FLAGS::default();
        VirtualProtectEx(process, address as *const c_void, 1, old, &mut ignored)
    };

    write_result
        .map_err(|error| string_error(&format!("WriteProcessMemory(0x{address:X})"), error))?;
    if written != 1 {
        return Err(format!(
            "WriteProcessMemory(0x{address:X}) returned {written}/1 bytes"
        ));
    }
    flush_result
        .map_err(|error| string_error(&format!("FlushInstructionCache(0x{address:X})"), error))?;
    restore_result
        .map_err(|error| string_error(&format!("restore protection at 0x{address:X}"), error))?;
    Ok(())
}

fn arm_byte_breakpoint(process: HANDLE, address: u64) -> Result<ByteBreakpoint, String> {
    let mut original = [0u8; 1];
    read_remote_exact(process, address, &mut original)?;
    if original[0] == 0xcc {
        return Err(format!(
            "PE entry 0x{address:X} already contains INT3; the one-shot native entry breakpoint cannot distinguish or restore it safely"
        ));
    }
    if let Err(error) = patch_byte(process, address, 0xcc) {
        // A write or cache flush may have succeeded before a later protection
        // restoration error. Best-effort rollback prevents leaking an INT3
        // into a process that the launch path is about to detach from.
        let _ = patch_byte(process, address, original[0]);
        return Err(error);
    }
    Ok(ByteBreakpoint {
        address,
        original_byte: original[0],
        armed: true,
    })
}

fn restore_byte_breakpoint(process: HANDLE, breakpoint: &mut ByteBreakpoint) -> Result<(), String> {
    if breakpoint.armed {
        patch_byte(process, breakpoint.address, breakpoint.original_byte)?;
        breakpoint.armed = false;
    }
    Ok(())
}

fn restore_byte_or_confirm_absent(
    process: HANDLE,
    breakpoint: &mut ByteBreakpoint,
) -> Result<(), String> {
    if !breakpoint.armed {
        return Ok(());
    }
    match restore_byte_breakpoint(process, breakpoint) {
        Ok(()) => Ok(()),
        Err(error) => {
            let mut current = [0u8; 1];
            if read_remote_exact(process, breakpoint.address, &mut current).is_err()
                || current[0] != 0xcc
            {
                breakpoint.armed = false;
                Ok(())
            } else {
                Err(error)
            }
        }
    }
}

fn rearm_byte_breakpoint(process: HANDLE, breakpoint: &mut ByteBreakpoint) -> Result<(), String> {
    if !breakpoint.armed {
        patch_byte(process, breakpoint.address, 0xcc)?;
        breakpoint.armed = true;
    }
    Ok(())
}

fn target_is_wow64(process: HANDLE) -> Result<bool, String> {
    let mut wow64 = BOOL(0);
    unsafe { IsWow64Process(process, &mut wow64) }
        .map_err(|error| string_error("IsWow64Process", error))?;
    Ok(wow64.as_bool())
}

fn rewind_instruction_pointer(
    thread: HANDLE,
    wow64: bool,
    entry_address: u64,
) -> Result<(), String> {
    unsafe {
        if wow64 {
            let entry = u32::try_from(entry_address)
                .map_err(|_| format!("WOW64 entry 0x{entry_address:X} exceeds 32-bit address space"))?;
            let mut context = WOW64_CONTEXT::default();
            context.ContextFlags = WOW64_CONTEXT_CONTROL;
            Wow64GetThreadContext(thread, &mut context)
                .map_err(|error| string_error("Wow64GetThreadContext", error))?;
            context.Eip = entry;
            Wow64SetThreadContext(thread, &context)
                .map_err(|error| string_error("Wow64SetThreadContext", error))?;
        } else {
            #[repr(align(16))]
            struct AlignedContext(CONTEXT);
            let mut context = AlignedContext(std::mem::zeroed());
            context.0.ContextFlags = CONTEXT_CONTROL_AMD64;
            GetThreadContext(thread, &mut context.0)
                .map_err(|error| string_error("GetThreadContext", error))?;
            context.0.Rip = entry_address;
            SetThreadContext(thread, &context.0)
                .map_err(|error| string_error("SetThreadContext", error))?;
        }
    }
    Ok(())
}

fn update_thread_control(
    thread: HANDLE,
    wow64: bool,
    operation: impl FnOnce(&mut u64, &mut u32),
) -> Result<(u64, u32), String> {
    unsafe {
        if wow64 {
            let mut context = WOW64_CONTEXT::default();
            context.ContextFlags = WOW64_CONTEXT_CONTROL;
            Wow64GetThreadContext(thread, &mut context)
                .map_err(|error| string_error("Wow64GetThreadContext", error))?;
            let mut ip = context.Eip as u64;
            operation(&mut ip, &mut context.EFlags);
            context.Eip = u32::try_from(ip)
                .map_err(|_| format!("WOW64 instruction pointer 0x{ip:X} exceeds 32 bits"))?;
            Wow64SetThreadContext(thread, &context)
                .map_err(|error| string_error("Wow64SetThreadContext", error))?;
            Ok((ip, context.EFlags))
        } else {
            #[repr(align(16))]
            struct AlignedContext(CONTEXT);
            let mut context = AlignedContext(std::mem::zeroed());
            context.0.ContextFlags = CONTEXT_CONTROL_AMD64;
            GetThreadContext(thread, &mut context.0)
                .map_err(|error| string_error("GetThreadContext", error))?;
            operation(&mut context.0.Rip, &mut context.0.EFlags);
            SetThreadContext(thread, &context.0)
                .map_err(|error| string_error("SetThreadContext", error))?;
            Ok((context.0.Rip, context.0.EFlags))
        }
    }
}

fn read_thread_control(thread: HANDLE, wow64: bool) -> Result<(u64, u32), String> {
    unsafe {
        if wow64 {
            let mut context = WOW64_CONTEXT::default();
            context.ContextFlags = WOW64_CONTEXT_CONTROL;
            Wow64GetThreadContext(thread, &mut context)
                .map_err(|error| string_error("Wow64GetThreadContext(control)", error))?;
            Ok((context.Eip as u64, context.EFlags))
        } else {
            #[repr(align(16))]
            struct AlignedContext(CONTEXT);
            let mut context = AlignedContext(std::mem::zeroed());
            context.0.ContextFlags = CONTEXT_CONTROL_AMD64;
            GetThreadContext(thread, &mut context.0)
                .map_err(|error| string_error("GetThreadContext(control)", error))?;
            Ok((context.0.Rip, context.0.EFlags))
        }
    }
}

fn set_trap_flag(thread: HANDLE, wow64: bool, enabled: bool) -> Result<u64, String> {
    let (written_ip, _) = update_thread_control(thread, wow64, |_, flags| {
        if enabled {
            *flags |= EFLAGS_TRAP;
        } else {
            *flags &= !EFLAGS_TRAP;
        }
    })?;
    let (verified_ip, verified_flags) = read_thread_control(thread, wow64)?;
    if (verified_flags & EFLAGS_TRAP != 0) != enabled {
        return Err(format!(
            "thread context rejected EFLAGS.TF={} at RIP 0x{verified_ip:X} (EFlags=0x{verified_flags:X})",
            enabled as u8,
        ));
    }
    if verified_ip != written_ip {
        return Err(format!(
            "thread RIP changed while committing EFLAGS.TF: 0x{written_ip:X} -> 0x{verified_ip:X}"
        ));
    }
    Ok(verified_ip)
}

fn read_instruction_pointer(thread: HANDLE, wow64: bool) -> Result<u64, String> {
    read_thread_control(thread, wow64).map(|(ip, _)| ip)
}

fn read_stack_pointer(thread: HANDLE, wow64: bool) -> Result<u64, String> {
    unsafe {
        if wow64 {
            let mut context = WOW64_CONTEXT::default();
            context.ContextFlags = WOW64_CONTEXT_CONTROL;
            Wow64GetThreadContext(thread, &mut context)
                .map_err(|error| string_error("Wow64GetThreadContext(stack)", error))?;
            Ok(context.Esp as u64)
        } else {
            #[repr(align(16))]
            struct AlignedContext(CONTEXT);
            let mut context = AlignedContext(std::mem::zeroed());
            context.0.ContextFlags = CONTEXT_CONTROL_AMD64;
            GetThreadContext(thread, &mut context.0)
                .map_err(|error| string_error("GetThreadContext(stack)", error))?;
            Ok(context.0.Rsp)
        }
    }
}

fn mark_hardware_resume(thread: HANDLE, wow64: bool) -> Result<u64, String> {
    update_thread_control(thread, wow64, |_, flags| *flags |= EFLAGS_RESUME)
        .map(|(ip, _)| ip)
}

fn with_event_thread<T>(
    primary_thread: HANDLE,
    primary_tid: u32,
    event_tid: u32,
    operation: impl FnOnce(HANDLE) -> Result<T, String>,
) -> Result<T, String> {
    if event_tid == primary_tid {
        return operation(primary_thread);
    }
    let thread = unsafe { OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, false, event_tid) }
        .map_err(|error| string_error(&format!("OpenThread({event_tid})"), error))?;
    let result = operation(thread);
    close_handle(thread);
    result
}

fn with_suspended_thread<T>(
    tid: u32,
    operation: impl FnOnce(HANDLE) -> Result<T, String>,
) -> Result<T, String> {
    let thread = unsafe {
        OpenThread(
            THREAD_GET_CONTEXT
                | THREAD_SET_CONTEXT
                | THREAD_SUSPEND_RESUME
                | THREAD_SYNCHRONIZE,
            false,
            tid,
        )
    }
    .map_err(|error| string_error(&format!("OpenThread({tid})"), error))?;
    let previous = unsafe { SuspendThread(thread) };
    if previous == u32::MAX {
        close_handle(thread);
        return Err(format!("SuspendThread({tid}) failed"));
    }
    let result = operation(thread);
    loop {
        let resumed = unsafe { ResumeThread(thread) };
        let exited = unsafe { WaitForSingleObject(thread, 0) } == WAIT_OBJECT_0;
        if resumed != u32::MAX || exited {
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    close_handle(thread);
    result
}

fn enumerate_process_threads(pid: u32) -> Result<Vec<u32>, String> {
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) }
        .map_err(|error| string_error("CreateToolhelp32Snapshot(threads)", error))?;
    let mut entry = THREADENTRY32 {
        dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
        ..Default::default()
    };
    let mut result = Vec::new();
    if unsafe { Thread32First(snapshot, &mut entry) }.is_ok() {
        loop {
            if entry.th32OwnerProcessID == pid {
                result.push(entry.th32ThreadID);
            }
            if unsafe { Thread32Next(snapshot, &mut entry) }.is_err() {
                break;
            }
        }
    }
    close_handle(snapshot);
    if result.is_empty() {
        return Err(format!("PID {pid} has no enumerable threads"));
    }
    Ok(result)
}

fn release_suspensions(suspended: &mut Vec<HeldSuspension>) -> Result<(), String> {
    let mut failures = Vec::new();
    let mut index = 0;
    while index < suspended.len() {
        let item = &suspended[index];
        let resumed = unsafe { ResumeThread(item.handle) };
        let exited = unsafe { WaitForSingleObject(item.handle, 0) } == WAIT_OBJECT_0;
        if resumed != u32::MAX || exited {
            let item = suspended.swap_remove(index);
            close_handle(item.handle);
        } else {
            failures.push(format!("ResumeThread({}) failed", item.tid));
            index += 1;
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; "))
    }
}

fn release_suspensions_confirmed(suspended: &mut Vec<HeldSuspension>) {
    while !suspended.is_empty() {
        let _ = release_suspensions(suspended);
        if !suspended.is_empty() {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}

fn suspend_other_threads(pid: u32, owner_tid: u32) -> Result<Vec<HeldSuspension>, String> {
    let mut suspended = Vec::new();
    for tid in enumerate_process_threads(pid)? {
        if tid == owner_tid {
            continue;
        }
        let handle = match unsafe {
            OpenThread(
                THREAD_SUSPEND_RESUME | THREAD_SYNCHRONIZE,
                false,
                tid,
            )
        } {
            Ok(handle) => handle,
            Err(error) => {
                release_suspensions_confirmed(&mut suspended);
                return Err(format!(
                    "OpenThread({tid}) while closing INT3 rearm window: {error}"
                ));
            }
        };
        let previous = unsafe { SuspendThread(handle) };
        if previous == u32::MAX {
            let exited = unsafe { WaitForSingleObject(handle, 0) } == WAIT_OBJECT_0;
            close_handle(handle);
            if exited {
                continue;
            }
            release_suspensions_confirmed(&mut suspended);
            return Err(format!(
                "SuspendThread({tid}) while closing INT3 rearm window failed"
            ));
        }
        suspended.push(HeldSuspension { tid, handle });
    }
    Ok(suspended)
}

fn read_debug_registers(thread: HANDLE, wow64: bool) -> Result<DebugRegisterState, String> {
    unsafe {
        if wow64 {
            let mut context = WOW64_CONTEXT::default();
            context.ContextFlags = WOW64_CONTEXT_DEBUG_REGISTERS;
            Wow64GetThreadContext(thread, &mut context)
                .map_err(|error| string_error("Wow64GetThreadContext(DR)", error))?;
            Ok(DebugRegisterState {
                dr: [
                    context.Dr0 as u64,
                    context.Dr1 as u64,
                    context.Dr2 as u64,
                    context.Dr3 as u64,
                ],
                dr6: context.Dr6 as u64,
                dr7: context.Dr7 as u64,
            })
        } else {
            #[repr(align(16))]
            struct AlignedContext(CONTEXT);
            let mut context = AlignedContext(std::mem::zeroed());
            context.0.ContextFlags = CONTEXT_DEBUG_REGISTERS_AMD64;
            GetThreadContext(thread, &mut context.0)
                .map_err(|error| string_error("GetThreadContext(DR)", error))?;
            Ok(DebugRegisterState {
                dr: [context.0.Dr0, context.0.Dr1, context.0.Dr2, context.0.Dr3],
                dr6: context.0.Dr6,
                dr7: context.0.Dr7,
            })
        }
    }
}

fn write_debug_registers(
    thread: HANDLE,
    wow64: bool,
    state: DebugRegisterState,
) -> Result<(), String> {
    unsafe {
        if wow64 {
            let mut context = WOW64_CONTEXT::default();
            context.ContextFlags = WOW64_CONTEXT_DEBUG_REGISTERS;
            Wow64GetThreadContext(thread, &mut context)
                .map_err(|error| string_error("Wow64GetThreadContext(DR)", error))?;
            context.Dr0 = u32::try_from(state.dr[0]).map_err(|_| "WOW64 DR0 overflow".to_string())?;
            context.Dr1 = u32::try_from(state.dr[1]).map_err(|_| "WOW64 DR1 overflow".to_string())?;
            context.Dr2 = u32::try_from(state.dr[2]).map_err(|_| "WOW64 DR2 overflow".to_string())?;
            context.Dr3 = u32::try_from(state.dr[3]).map_err(|_| "WOW64 DR3 overflow".to_string())?;
            context.Dr6 = state.dr6 as u32;
            context.Dr7 = state.dr7 as u32;
            Wow64SetThreadContext(thread, &context)
                .map_err(|error| string_error("Wow64SetThreadContext(DR)", error))
        } else {
            #[repr(align(16))]
            struct AlignedContext(CONTEXT);
            let mut context = AlignedContext(std::mem::zeroed());
            context.0.ContextFlags = CONTEXT_DEBUG_REGISTERS_AMD64;
            GetThreadContext(thread, &mut context.0)
                .map_err(|error| string_error("GetThreadContext(DR)", error))?;
            context.0.Dr0 = state.dr[0];
            context.0.Dr1 = state.dr[1];
            context.0.Dr2 = state.dr[2];
            context.0.Dr3 = state.dr[3];
            context.0.Dr6 = state.dr6;
            context.0.Dr7 = state.dr7;
            SetThreadContext(thread, &context.0)
                .map_err(|error| string_error("SetThreadContext(DR)", error))
        }
    }
}

fn validate_hardware_breakpoint(breakpoint: NativeHardwareBreakpoint, wow64: bool) -> Result<(), String> {
    if breakpoint.slot >= 4 {
        return Err(format!("hardware breakpoint slot {} is outside DR0-DR3", breakpoint.slot));
    }
    if breakpoint.address == 0 || (wow64 && breakpoint.address > u32::MAX as u64) {
        return Err(format!("invalid hardware breakpoint address 0x{:X}", breakpoint.address));
    }
    if !matches!(breakpoint.bp_type, 0 | 1 | 3) {
        return Err(format!("invalid hardware breakpoint type {}", breakpoint.bp_type));
    }
    if !matches!(breakpoint.length, 1 | 2 | 4 | 8)
        || (breakpoint.bp_type == 0 && breakpoint.length != 1)
        || (wow64 && breakpoint.length == 8)
    {
        return Err(format!(
            "invalid hardware breakpoint length {} for type {}",
            breakpoint.length, breakpoint.bp_type
        ));
    }
    if breakpoint.address & (breakpoint.length as u64 - 1) != 0 {
        return Err(format!(
            "hardware breakpoint address 0x{:X} is not {}-byte aligned",
            breakpoint.address, breakpoint.length
        ));
    }
    Ok(())
}

fn effective_debug_registers(
    original: DebugRegisterState,
    breakpoints: &[Option<NativeHardwareBreakpoint>; 4],
) -> DebugRegisterState {
    let mut state = original;
    state.dr6 &= !DR6_BREAKPOINT_MASK;
    for (slot, breakpoint) in breakpoints.iter().enumerate() {
        let enable_shift = slot * 2;
        let control_shift = 16 + slot * 4;
        state.dr7 &= !(3u64 << enable_shift);
        state.dr7 &= !(0x0fu64 << control_shift);
        if let Some(breakpoint) = breakpoint {
            state.dr[slot] = breakpoint.address;
            state.dr7 |= 1u64 << enable_shift;
            state.dr7 |= (breakpoint.bp_type as u64 & 3) << control_shift;
            let length = match breakpoint.length {
                1 => 0,
                2 => 1,
                8 => 2,
                4 => 3,
                _ => unreachable!(),
            };
            state.dr7 |= length << (control_shift + 2);
        }
    }
    state
}

struct NativeEngine {
    app: AppHandle,
    pid: u32,
    process: HANDLE,
    primary_thread: HANDLE,
    primary_tid: u32,
    wow64: bool,
    terminate_on_cleanup: bool,
    entry: Option<ByteBreakpoint>,
    software: HashMap<u64, ByteBreakpoint>,
    transient: HashMap<u64, ByteBreakpoint>,
    step_over_targets: HashMap<u64, u32>,
    hardware: [Option<NativeHardwareBreakpoint>; 4],
    original_dr: HashMap<u32, DebugRegisterState>,
    rearm_steps: HashMap<u32, RearmStep>,
    // TF-backed native steps and VT/MTF-backed steps have different cleanup:
    // only the former owns EFLAGS.TF in the target thread context.
    tf_steps: HashSet<u32>,
    vt_steps: HashSet<u32>,
    private_vt_step_intents: Option<Arc<Mutex<HashSet<u32>>>>,
}

impl NativeEngine {
    fn emit_hit(&self, tid: u32, rip: u64, kind: u32, slot: Option<u32>) {
        let _ = self.app.emit(
            "dbg-native-hit",
            NativeHit {
                sequence: HIT_SEQUENCE.fetch_add(1, Ordering::Relaxed),
                pid: self.pid,
                tid,
                rip,
                kind,
                entry: kind == HIT_ENTRY,
                slot,
                transient: kind == HIT_STEP_OVER,
            },
        );
    }

    fn emit_control_error(&self, tid: u32, operation: &str, error: &str) {
        eprintln!(
            "native debugger PID {} TID {tid} {operation}: {error}",
            self.pid
        );
        let _ = self.app.emit(
            "dbg-native-error",
            serde_json::json!({
                "pid": self.pid,
                "tid": tid,
                "operation": operation,
                "error": error,
            }),
        );
    }

    fn start_rearm_step(
        &mut self,
        tid: u32,
        address: u64,
        stop_after: bool,
        kind: RearmKind,
    ) -> Result<(), String> {
        if self.rearm_steps.contains_key(&tid) {
            return Err(format!("TID {tid} already owns an INT3 rearm window"));
        }
        let mut suspended = suspend_other_threads(self.pid, tid)?;
        let set_tf = with_event_thread(
            self.primary_thread,
            self.primary_tid,
            tid,
            |thread| set_trap_flag(thread, self.wow64, true).map(|_| ()),
        );
        if let Err(error) = set_tf {
            let release = release_suspensions(&mut suspended);
            if !suspended.is_empty() {
                self.rearm_steps.insert(
                    tid,
                    RearmStep {
                        address,
                        stop_after,
                        kind,
                        tf_armed: false,
                        suspended,
                    },
                );
            }
            return Err(match release {
                Ok(()) => error,
                Err(release_error) => format!("{error}; suspension rollback: {release_error}"),
            });
        }
        self.rearm_steps.insert(
            tid,
            RearmStep {
                address,
                stop_after,
                kind,
                tf_armed: true,
                suspended,
            },
        );
        Ok(())
    }

    fn retry_incomplete_rearm_start(&mut self, tid: u32) -> Result<(), String> {
        let incomplete = self
            .rearm_steps
            .get(&tid)
            .is_some_and(|step| !step.tf_armed);
        if !incomplete {
            return Ok(());
        }
        let release = {
            let step = self.rearm_steps.get_mut(&tid).unwrap();
            release_suspensions(&mut step.suspended)
        };
        release?;
        let step = self.rearm_steps.remove(&tid).unwrap();
        self.start_rearm_step(tid, step.address, step.stop_after, step.kind)
    }

    fn complete_rearm_step(&mut self, tid: u32, clear_tf: bool) -> Result<bool, String> {
        let Some(step) = self.rearm_steps.get(&tid) else {
            return Err(format!("TID {tid} has no INT3 rearm state"));
        };
        if !step.tf_armed {
            return Err(format!("TID {tid} INT3 rearm state never armed TF"));
        }
        let address = step.address;
        let kind = step.kind;
        let stop_after = step.stop_after;
        if clear_tf {
            with_event_thread(
                self.primary_thread,
                self.primary_tid,
                tid,
                |thread| set_trap_flag(thread, self.wow64, false).map(|_| ()),
            )?;
        }
        if address != 0 {
            match kind {
                RearmKind::Software => {
                    if let Some(breakpoint) = self.software.get_mut(&address) {
                        rearm_byte_breakpoint(self.process, breakpoint)?;
                    }
                }
                RearmKind::Transient => {
                    if self.step_over_targets.contains_key(&address) {
                        if let Some(breakpoint) = self.transient.get_mut(&address) {
                            rearm_byte_breakpoint(self.process, breakpoint)?;
                        }
                    }
                }
            }
        }
        {
            let step = self.rearm_steps.get_mut(&tid).unwrap();
            release_suspensions(&mut step.suspended)?;
        }
        self.rearm_steps.remove(&tid);
        Ok(stop_after)
    }

    fn clear_owned_debug_status(&self, tid: u32) -> Result<(), String> {
        with_event_thread(
            self.primary_thread,
            self.primary_tid,
            tid,
            |thread| {
                let mut state = read_debug_registers(thread, self.wow64)?;
                let configured_mask = self
                    .hardware
                    .iter()
                    .enumerate()
                    .fold(0u64, |mask, (slot, breakpoint)| {
                        if breakpoint.is_some() {
                            mask | (1u64 << slot)
                        } else {
                            mask
                        }
                    })
                    | super::hwbp::vt_hardware_mask(self.pid);
                state.dr6 &= !(configured_mask | DR6_SINGLE_STEP);
                write_debug_registers(thread, self.wow64, state)
            },
        )
    }

    fn cancel_step_over_for_thread(&mut self, tid: u32) -> Result<bool, String> {
        let addresses: Vec<u64> = self
            .step_over_targets
            .iter()
            .filter_map(|(address, owner)| (*owner == tid).then_some(*address))
            .collect();
        let cancelled = !addresses.is_empty();
        let mut failures = Vec::new();
        for address in addresses {
            if let Some(breakpoint) = self.transient.get_mut(&address) {
                if let Err(error) = restore_byte_or_confirm_absent(self.process, breakpoint) {
                    failures.push(format!("restore one-shot 0x{address:X}: {error}"));
                    continue;
                }
                self.transient.remove(&address);
            }
            self.step_over_targets.remove(&address);
        }
        if failures.is_empty() {
            Ok(cancelled)
        } else {
            Err(failures.join("; "))
        }
    }

    fn finish_rearm_for_exiting_thread(&mut self, tid: u32) -> Result<(), String> {
        let Some(step) = self.rearm_steps.get(&tid) else {
            return Ok(());
        };
        let address = step.address;
        let kind = step.kind;
        if address != 0 {
            let rearm = match kind {
                RearmKind::Software => self
                    .software
                    .get_mut(&address)
                    .map(|breakpoint| rearm_byte_breakpoint(self.process, breakpoint)),
                RearmKind::Transient => self
                    .transient
                    .get_mut(&address)
                    .map(|breakpoint| rearm_byte_breakpoint(self.process, breakpoint)),
            };
            if let Some(Err(error)) = rearm {
                match kind {
                    RearmKind::Software => {
                        self.software.remove(&address);
                    }
                    RearmKind::Transient => {
                        self.transient.remove(&address);
                        self.step_over_targets.remove(&address);
                    }
                }
                self.emit_control_error(
                    tid,
                    "thread-exit breakpoint rearm",
                    &format!("0x{address:X}: {error}; breakpoint revoked"),
                );
            }
        }
        {
            let step = self.rearm_steps.get_mut(&tid).unwrap();
            release_suspensions_confirmed(&mut step.suspended);
        }
        self.rearm_steps.remove(&tid);
        Ok(())
    }

    fn rollback_new_thread_holds(&mut self, owners: &[u32], tid: u32) -> Result<(), String> {
        let mut failures = Vec::new();
        for owner in owners {
            let Some(step) = self.rearm_steps.get_mut(owner) else {
                continue;
            };
            let Some(index) = step.suspended.iter().position(|item| item.tid == tid) else {
                continue;
            };
            let item = &step.suspended[index];
            let resumed = unsafe { ResumeThread(item.handle) };
            let exited = unsafe { WaitForSingleObject(item.handle, 0) } == WAIT_OBJECT_0;
            if resumed != u32::MAX || exited {
                let item = step.suspended.swap_remove(index);
                close_handle(item.handle);
            } else {
                failures.push(format!("ResumeThread({tid}) for owner TID {owner} failed"));
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(failures.join("; "))
        }
    }

    fn hold_new_thread_during_rearm(&mut self, tid: u32) -> Result<(), String> {
        let owners: Vec<u32> = self
            .rearm_steps
            .iter()
            .filter_map(|(owner, step)| (step.tf_armed && *owner != tid).then_some(*owner))
            .collect();
        let mut added = Vec::new();
        for owner in owners {
            let handle = unsafe {
                OpenThread(
                    THREAD_SUSPEND_RESUME | THREAD_SYNCHRONIZE,
                    false,
                    tid,
                )
            }
            .map_err(|error| format!("OpenThread({tid}) for INT3 rearm window: {error}"));
            let handle = match handle {
                Ok(handle) => handle,
                Err(error) => {
                    let rollback = self.rollback_new_thread_holds(&added, tid);
                    return Err(match rollback {
                        Ok(()) => error,
                        Err(rollback_error) => format!("{error}; rollback: {rollback_error}"),
                    });
                }
            };
            let previous = unsafe { SuspendThread(handle) };
            if previous == u32::MAX {
                close_handle(handle);
                let rollback = self.rollback_new_thread_holds(&added, tid);
                return Err(match rollback {
                    Ok(()) => format!("SuspendThread({tid}) for INT3 rearm window failed"),
                    Err(rollback_error) => format!(
                        "SuspendThread({tid}) for INT3 rearm window failed; rollback: {rollback_error}"
                    ),
                });
            }
            self.rearm_steps
                .get_mut(&owner)
                .unwrap()
                .suspended
                .push(HeldSuspension { tid, handle });
            added.push(owner);
        }
        Ok(())
    }

    fn revoke_hardware_after_new_thread_failure(
        &mut self,
        event_tid: u32,
        event_thread: HANDLE,
    ) -> Result<(), String> {
        let configured = self.hardware;
        let originals: Vec<_> = self
            .original_dr
            .iter()
            .map(|(tid, state)| (*tid, *state))
            .collect();
        let mut restored = Vec::new();
        let mut failures = Vec::new();
        for (tid, original) in originals {
            let result = if tid == event_tid {
                write_debug_registers(event_thread, self.wow64, original)
            } else {
                with_suspended_thread(tid, |thread| {
                    write_debug_registers(thread, self.wow64, original)
                })
            };
            match result {
                Ok(()) => restored.push(tid),
                Err(error) => failures.push(format!("restore DR on TID {tid}: {error}")),
            }
        }
        if failures.is_empty() {
            self.hardware = [None; 4];
            self.original_dr.clear();
            return Ok(());
        }
        for tid in restored {
            let rollback = if tid == event_tid {
                let original = self.original_dr.get(&tid).copied().unwrap();
                write_debug_registers(
                    event_thread,
                    self.wow64,
                    effective_debug_registers(original, &configured),
                )
            } else {
                self.apply_hardware_to_tid(tid, &configured)
            };
            if let Err(error) = rollback {
                failures.push(format!("rollback DR on TID {tid}: {error}"));
            }
        }
        Err(failures.join("; "))
    }

    fn software_list(&self) -> Vec<NativeSoftwareBreakpoint> {
        let mut result: Vec<_> = self
            .software
            .values()
            .map(|breakpoint| NativeSoftwareBreakpoint {
                address: breakpoint.address,
                original_byte: breakpoint.original_byte,
            })
            .collect();
        result.sort_unstable_by_key(|breakpoint| breakpoint.address);
        result
    }

    fn set_software(&mut self, address: u64) -> Result<NativeSoftwareBreakpoint, String> {
        if address == 0 || (self.wow64 && address > u32::MAX as u64) {
            return Err(format!("invalid native software-breakpoint address 0x{address:X}"));
        }
        if self.software.contains_key(&address) {
            return Err(format!("native software breakpoint already exists at 0x{address:X}"));
        }
        if self.transient.contains_key(&address)
            || self.entry.as_ref().is_some_and(|breakpoint| {
                breakpoint.armed && breakpoint.address == address
            })
        {
            return Err(format!("0x{address:X} is already owned by a one-shot breakpoint"));
        }
        let breakpoint = arm_byte_breakpoint(self.process, address)?;
        let result = NativeSoftwareBreakpoint {
            address,
            original_byte: breakpoint.original_byte,
        };
        self.software.insert(address, breakpoint);
        Ok(result)
    }

    fn clear_software(&mut self, address: u64) -> Result<(), String> {
        let Some(breakpoint) = self.software.get_mut(&address) else {
            return Err(format!("no native software breakpoint exists at 0x{address:X}"));
        };
        restore_byte_breakpoint(self.process, breakpoint)?;
        self.software.remove(&address);
        for step in self.rearm_steps.values_mut() {
            if step.address == address {
                step.address = 0;
            }
        }
        Ok(())
    }

    fn hardware_list(&self) -> Vec<NativeHardwareBreakpoint> {
        self.hardware.iter().flatten().copied().collect()
    }

    fn sanitized_new_thread_baseline(
        &self,
        mut state: DebugRegisterState,
    ) -> DebugRegisterState {
        for (slot, breakpoint) in self.hardware.iter().enumerate() {
            let Some(breakpoint) = breakpoint else { continue };
            let enabled = (state.dr7 >> (slot * 2)) & 3;
            if enabled != 0 && state.dr[slot] == breakpoint.address {
                state.dr[slot] = 0;
                state.dr7 &= !(3u64 << (slot * 2));
                state.dr7 &= !(0x0fu64 << (16 + slot * 4));
            }
        }
        state.dr6 &= !DR6_BREAKPOINT_MASK;
        state
    }

    fn apply_hardware_to_thread_handle(
        &mut self,
        tid: u32,
        thread: HANDLE,
        desired: &[Option<NativeHardwareBreakpoint>; 4],
        new_thread: bool,
    ) -> Result<(), String> {
        let original = match self.original_dr.get(&tid).copied() {
            Some(value) => value,
            None => {
                let captured = read_debug_registers(thread, self.wow64)?;
                let captured = if new_thread {
                    self.sanitized_new_thread_baseline(captured)
                } else {
                    captured
                };
                self.original_dr.insert(tid, captured);
                captured
            }
        };
        write_debug_registers(
            thread,
            self.wow64,
            effective_debug_registers(original, desired),
        )
    }

    fn apply_hardware_to_tid(
        &mut self,
        tid: u32,
        desired: &[Option<NativeHardwareBreakpoint>; 4],
    ) -> Result<(), String> {
        with_suspended_thread(tid, |thread| {
            self.apply_hardware_to_thread_handle(tid, thread, desired, false)
        })
    }

    fn set_hardware(&mut self, breakpoint: NativeHardwareBreakpoint) -> Result<(), String> {
        validate_hardware_breakpoint(breakpoint, self.wow64)?;
        let slot = breakpoint.slot as usize;
        if self.hardware[slot].is_some() {
            return Err(format!("native hardware breakpoint slot {} is already occupied", breakpoint.slot));
        }
        let previous = self.hardware;
        let mut desired = previous;
        desired[slot] = Some(breakpoint);
        let tids = enumerate_process_threads(self.pid)?;
        let mut applied = Vec::new();
        for tid in tids {
            match self.apply_hardware_to_tid(tid, &desired) {
                Ok(()) => applied.push(tid),
                Err(error) => {
                    for applied_tid in applied {
                        let _ = self.apply_hardware_to_tid(applied_tid, &previous);
                    }
                    return Err(format!("apply DR{} to TID {tid}: {error}", breakpoint.slot));
                }
            }
        }
        self.hardware = desired;
        Ok(())
    }

    fn clear_hardware(&mut self, slot: u32) -> Result<(), String> {
        if slot >= 4 {
            return Err(format!("hardware breakpoint slot {slot} is outside DR0-DR3"));
        }
        if self.hardware[slot as usize].is_none() {
            return Err(format!("native hardware breakpoint slot {slot} is not set"));
        }
        let previous = self.hardware;
        let mut desired = previous;
        desired[slot as usize] = None;
        let restore_exact = desired.iter().all(Option::is_none);
        let tids = enumerate_process_threads(self.pid)?;
        let mut applied = Vec::new();
        for tid in tids {
            let apply = if restore_exact {
                match self.original_dr.get(&tid).copied() {
                    Some(original) => with_suspended_thread(tid, |thread| {
                        write_debug_registers(thread, self.wow64, original)
                    }),
                    None => Ok(()),
                }
            } else {
                self.apply_hardware_to_tid(tid, &desired)
            };
            match apply {
                Ok(()) => applied.push(tid),
                Err(error) => {
                    for applied_tid in applied {
                        let _ = self.apply_hardware_to_tid(applied_tid, &previous);
                    }
                    return Err(format!("clear DR{slot} on TID {tid}: {error}"));
                }
            }
        }
        self.hardware = desired;
        if restore_exact {
            self.original_dr.clear();
        }
        Ok(())
    }

    fn apply_hardware_to_new_thread(&mut self, tid: u32, thread: HANDLE) -> Result<(), String> {
        if self.hardware.iter().all(Option::is_none) {
            return Ok(());
        }
        let desired = self.hardware;
        self.apply_hardware_to_thread_handle(tid, thread, &desired, true)
    }

    fn active_run_target(&self, tid: u32) -> Option<u64> {
        self.step_over_targets
            .iter()
            .find_map(|(address, owner)| (*owner == tid).then_some(*address))
    }

    fn ensure_no_active_run(&self, tid: u32) -> Result<(), String> {
        if let Some(address) = self.active_run_target(tid) {
            return Err(format!(
                "TID {tid} is still running to one-shot breakpoint 0x{address:X}"
            ));
        }
        Ok(())
    }

    fn arm_step_over(&mut self, tid: u32, address: u64) -> Result<(), String> {
        self.ensure_no_active_run(tid)?;
        if address == 0 || (self.wow64 && address > u32::MAX as u64) {
            return Err(format!("invalid native step-over address 0x{address:X}"));
        }
        if self.step_over_targets.contains_key(&address) {
            return Err(format!("native step-over target 0x{address:X} is already active"));
        }
        if !self.software.contains_key(&address) {
            if self.transient.contains_key(&address) {
                return Err(format!("one-shot breakpoint already exists at 0x{address:X}"));
            }
            let breakpoint = arm_byte_breakpoint(self.process, address)?;
            self.transient.insert(address, breakpoint);
        }
        self.step_over_targets.insert(address, tid);
        Ok(())
    }

    fn decode_step_over(
        &self,
        pending: &PendingEvent,
    ) -> Result<(ResumeAction, NativeStepOverResult), String> {
        use iced_x86::FlowControl;

        let mut bytes = [0u8; 16];
        read_remote_exact(self.process, pending.rip, &mut bytes)?;
        let bitness = if self.wow64 { 32 } else { 64 };
        let mut decoder = iced_x86::Decoder::with_ip(
            bitness,
            &bytes,
            pending.rip,
            iced_x86::DecoderOptions::NONE,
        );
        let instruction = decoder.decode();
        if instruction.is_invalid() || instruction.len() == 0 {
            return Err(format!("unable to decode instruction at 0x{:X}", pending.rip));
        }
        let next_rip = pending
            .rip
            .checked_add(instruction.len() as u64)
            .ok_or_else(|| "native step-over address overflow".to_string())?;
        if matches!(
            instruction.flow_control(),
            FlowControl::Call | FlowControl::IndirectCall | FlowControl::Interrupt
        ) {
            Ok((
                ResumeAction::StepOver(next_rip),
                NativeStepOverResult {
                    kind: "run-over",
                    next_rip,
                    continued_event: false,
                },
            ))
        } else {
            Ok((
                ResumeAction::StepInto,
                NativeStepOverResult {
                    kind: "step",
                    next_rip,
                    continued_event: false,
                },
            ))
        }
    }

    fn return_address(&self, tid: u32) -> Result<u64, String> {
        let stack_pointer = with_suspended_thread(tid, |thread| {
            read_stack_pointer(thread, self.wow64)
        })?;
        let pointer_size = if self.wow64 { 4 } else { 8 };
        let mut bytes = [0u8; 8];
        read_remote_exact(self.process, stack_pointer, &mut bytes[..pointer_size])?;
        let address = if self.wow64 {
            u32::from_le_bytes(bytes[..4].try_into().unwrap()) as u64
        } else {
            u64::from_le_bytes(bytes)
        };
        if address == 0 {
            return Err(format!("stack at 0x{stack_pointer:X} contains a null return address"));
        }
        Ok(address)
    }

    fn arm_external_step(&mut self, tid: u32) -> Result<(), String> {
        self.ensure_no_active_run(tid)?;
        if self.rearm_steps.contains_key(&tid)
            || self.tf_steps.contains(&tid)
            || self.vt_steps.contains(&tid)
        {
            return Err(format!("TID {tid} already has an active native single-step intent"));
        }
        with_suspended_thread(tid, |thread| {
            set_trap_flag(thread, self.wow64, true).map(|_| ())
        })?;
        self.tf_steps.insert(tid);
        Ok(())
    }

    fn arm_external_vt_step(&mut self, tid: u32) -> Result<(), String> {
        self.ensure_no_active_run(tid)?;
        if self.rearm_steps.contains_key(&tid)
            || self.tf_steps.contains(&tid)
            || self.vt_steps.contains(&tid)
        {
            return Err(format!("TID {tid} already has an active single-step intent"));
        }
        self.vt_steps.insert(tid);
        Ok(())
    }

    fn prepare_resume(
        &mut self,
        pending: &mut PendingEvent,
        action: ResumeAction,
    ) -> Result<(), String> {
        if pending.resume_prepared {
            return Ok(());
        }
        if !pending.ip_rewound {
            match pending.kind {
                PendingKind::Entry => {
                    if let Some(breakpoint) = self.entry.as_mut() {
                        restore_byte_breakpoint(self.process, breakpoint)?;
                    }
                }
                PendingKind::Software { address } => {
                    if let Some(breakpoint) = self.software.get_mut(&address) {
                        restore_byte_breakpoint(self.process, breakpoint)?;
                    }
                }
                PendingKind::StepOver { address } => {
                    if let Some(breakpoint) = self.transient.get_mut(&address) {
                        restore_byte_breakpoint(self.process, breakpoint)?;
                    }
                }
                PendingKind::TransientPass { address } => {
                    if let Some(breakpoint) = self.transient.get_mut(&address) {
                        restore_byte_breakpoint(self.process, breakpoint)?;
                    }
                }
                PendingKind::InitialSystemBreakpoint
                | PendingKind::Hardware { .. }
                | PendingKind::SingleStep => {}
            }
            with_event_thread(
                self.primary_thread,
                self.primary_tid,
                pending.tid,
                |thread| rewind_instruction_pointer(thread, self.wow64, pending.rip),
            )?;
            pending.ip_rewound = true;
        }
        if let PendingKind::StepOver { address } = pending.kind {
            self.transient.remove(&address);
            self.step_over_targets.remove(&address);
        }
        self.retry_incomplete_rearm_start(pending.tid)?;
        if matches!(pending.kind, PendingKind::SingleStep) {
            if self.rearm_steps.contains_key(&pending.tid) {
                self.clear_owned_debug_status(pending.tid)?;
                self.complete_rearm_step(pending.tid, true)?;
            } else if self.tf_steps.contains(&pending.tid) {
                self.clear_owned_debug_status(pending.tid)?;
                with_event_thread(
                    self.primary_thread,
                    self.primary_tid,
                    pending.tid,
                    |thread| set_trap_flag(thread, self.wow64, false).map(|_| ()),
                )?;
                self.tf_steps.remove(&pending.tid);
            } else if self.vt_steps.contains(&pending.tid) {
                // A VT step never owns EFLAGS.TF.  It may still reach this
                // recovery path if event classification failed after #DB.
                self.vt_steps.remove(&pending.tid);
            }
        }
        if let PendingKind::TransientPass { address } = pending.kind {
            if !self.rearm_steps.contains_key(&pending.tid) {
                self.start_rearm_step(
                    pending.tid,
                    address,
                    matches!(action, ResumeAction::StepInto),
                    RearmKind::Transient,
                )?;
            }
            pending.resume_prepared = true;
            return Ok(());
        }
        if let ResumeAction::StepOver(next_address) = action {
            self.arm_step_over(pending.tid, next_address)?;
        }
        let step_requested = matches!(action, ResumeAction::StepInto);
        let software_address = match pending.kind {
            PendingKind::Software { address } => Some(address),
            _ => None,
        };
        if let Some(address) = software_address.filter(|address| self.software.contains_key(address)) {
            if self.rearm_steps.contains_key(&pending.tid) {
                pending.resume_prepared = true;
                return Ok(());
            }
            self.start_rearm_step(
                pending.tid,
                address,
                step_requested,
                RearmKind::Software,
            )?;
        } else if step_requested {
            with_event_thread(
                self.primary_thread,
                self.primary_tid,
                pending.tid,
                |thread| set_trap_flag(thread, self.wow64, true).map(|_| ()),
            )?;
            self.tf_steps.insert(pending.tid);
        }
        pending.resume_prepared = true;
        Ok(())
    }

    fn restore_all_controls(&mut self) -> Result<(), String> {
        let mut failures = Vec::new();
        if let Some(entry) = self.entry.as_mut() {
            if let Err(error) = restore_byte_or_confirm_absent(self.process, entry) {
                failures.push(format!("entry byte: {error}"));
            }
        }
        for breakpoint in self.software.values_mut() {
            if let Err(error) = restore_byte_or_confirm_absent(self.process, breakpoint) {
                failures.push(format!("software byte 0x{:X}: {error}", breakpoint.address));
            }
        }
        for breakpoint in self.transient.values_mut() {
            if let Err(error) = restore_byte_or_confirm_absent(self.process, breakpoint) {
                failures.push(format!("one-shot byte 0x{:X}: {error}", breakpoint.address));
            }
        }

        let live: HashSet<u32> = enumerate_process_threads(self.pid)
            .unwrap_or_default()
            .into_iter()
            .collect();
        let originals: Vec<_> = self.original_dr.iter().map(|(tid, state)| (*tid, *state)).collect();
        for (tid, original) in originals {
            if !live.contains(&tid) {
                self.original_dr.remove(&tid);
                continue;
            }
            match with_suspended_thread(tid, |thread| {
                write_debug_registers(thread, self.wow64, original)
            }) {
                Ok(()) => {
                    self.original_dr.remove(&tid);
                }
                Err(error) => failures.push(format!("restore DR state on TID {tid}: {error}")),
            }
        }

        let rearm_tids: Vec<u32> = self.rearm_steps.keys().copied().collect();
        for tid in rearm_tids {
            let tf_armed = self
                .rearm_steps
                .get(&tid)
                .is_some_and(|step| step.tf_armed);
            let clear_tf = if tf_armed && live.contains(&tid) {
                with_suspended_thread(tid, |thread| {
                    set_trap_flag(thread, self.wow64, false).map(|_| ())
                })
            } else {
                Ok(())
            };
            let release = {
                let step = self.rearm_steps.get_mut(&tid).unwrap();
                release_suspensions(&mut step.suspended)
            };
            match (clear_tf, release) {
                (Ok(()), Ok(())) => {
                    self.rearm_steps.remove(&tid);
                }
                (clear, release) => {
                    if let Err(error) = clear {
                        failures.push(format!("clear TF on TID {tid}: {error}"));
                    }
                    if let Err(error) = release {
                        failures.push(format!("release INT3 window for TID {tid}: {error}"));
                    }
                }
            }
        }
        let user_tids: Vec<u32> = self.tf_steps.iter().copied().collect();
        for tid in user_tids {
            if !live.contains(&tid) {
                self.tf_steps.remove(&tid);
                continue;
            }
            match with_suspended_thread(tid, |thread| {
                set_trap_flag(thread, self.wow64, false).map(|_| ())
                }) {
                Ok(()) => {
                    self.tf_steps.remove(&tid);
                }
                Err(error) => failures.push(format!("clear TF on TID {tid}: {error}")),
            }
        }
        // MTF-backed steps do not modify thread context.  Driver-side gates
        // are retired by the VT target owner before the DebugObject detaches.
        self.vt_steps.clear();
        if let Some(intents) = self.private_vt_step_intents.as_ref() {
            intents.lock().clear();
        }
        if failures.is_empty() {
            self.hardware = [None; 4];
            self.step_over_targets.clear();
            Ok(())
        } else {
            Err(failures.join("; "))
        }
    }
}

#[derive(Clone, Copy)]
enum ResumeAction {
    Continue,
    StepInto,
    StepOver(u64),
}

fn continue_event(event: &DEBUG_EVENT, status: NTSTATUS) -> Result<(), String> {
    let result = unsafe { ContinueDebugEvent(event.dwProcessId, event.dwThreadId, status) }
        .map_err(|error| string_error("ContinueDebugEvent", error));
    private_dbgk_entry_diag(
        event.dwProcessId,
        "dbgk.continue",
        match &result {
            Ok(()) => format!(
                "tid={} event_code={} continue_status=0x{:08X} result=ok",
                event.dwThreadId,
                event.dwDebugEventCode.0,
                status.0 as u32,
            ),
            Err(error) => format!(
                "tid={} event_code={} continue_status=0x{:08X} result=error error={error}",
                event.dwThreadId,
                event.dwDebugEventCode.0,
                status.0 as u32,
            ),
        },
    );
    result
}

fn pending_hardware_hit_operation(
    app: &AppHandle,
    pid: u32,
    tid: u32,
    operation: u32,
    generation: u64,
) -> Result<Option<PendingHardwareHit>, String> {
    let operation_name = match operation {
        PENDING_HWBP_QUERY => "query",
        PENDING_HWBP_RETIRE => "retire",
        _ => return Err(format!("invalid pending HWBP operation {operation}")),
    };
    let request = PendingHardwareBreakpointRequest {
        version: BRIDGE_PROTOCOL_VERSION,
        target_pid: pid,
        thread_id: tid,
        operation,
        generation,
    };
    let mut result = PendingHardwareBreakpointResult {
        status: 0,
        reserved: 0,
        generation: 0,
        dr6_mask: 0,
    };
    let written = app
        .state::<DeviceState>()
        .ioctl(
            IOCTL_HV_BRIDGE_PENDING_HWBP,
            unsafe {
                std::slice::from_raw_parts(
                    (&request as *const PendingHardwareBreakpointRequest).cast::<u8>(),
                    std::mem::size_of::<PendingHardwareBreakpointRequest>(),
                )
            },
            unsafe {
                std::slice::from_raw_parts_mut(
                    (&mut result as *mut PendingHardwareBreakpointResult).cast::<u8>(),
                    std::mem::size_of::<PendingHardwareBreakpointResult>(),
                )
            },
        )
        .map_err(|error| format!("pending HWBP {operation_name} IOCTL: {error}"))?;
    private_dbgk_entry_diag(
        pid,
        &format!("hwbp.pending.{operation_name}"),
        format!(
            "tid={tid} bytes={written} status=0x{:08X} request_generation={generation} returned_generation={} dr6=0x{:X}",
            result.status as u32,
            result.generation,
            result.dr6_mask,
        ),
    );
    if written as usize != std::mem::size_of::<PendingHardwareBreakpointResult>() {
        return Err(format!(
            "pending HWBP {operation_name} returned {written} bytes, expected {}",
            std::mem::size_of::<PendingHardwareBreakpointResult>(),
        ));
    }
    if result.reserved != 0 {
        return Err(format!(
            "pending HWBP {operation_name} returned non-zero reserved field 0x{:08X}",
            result.reserved,
        ));
    }
    if result.status == STATUS_NOT_FOUND {
        return Ok(None);
    }
    if result.status < 0 {
        return Err(format!(
            "pending HWBP {operation_name} failed: NTSTATUS=0x{:08X}",
            result.status as u32,
        ));
    }
    let hit = PendingHardwareHit {
        generation: result.generation,
        dr6_mask: result.dr6_mask & DR6_BREAKPOINT_MASK,
    };
    if operation == PENDING_HWBP_QUERY && (hit.generation == 0 || hit.dr6_mask == 0) {
        return Err(format!(
            "pending HWBP query returned invalid hit generation={} dr6=0x{:X}",
            hit.generation, hit.dr6_mask,
        ));
    }
    Ok(Some(hit))
}

fn continue_pending_event(
    app: &AppHandle,
    event: &PendingEvent,
    status: NTSTATUS,
    operation: &str,
) -> Result<(), String> {
    let result = unsafe { ContinueDebugEvent(event.pid, event.tid, status) }
        .map_err(|error| string_error(operation, error));
    private_dbgk_entry_diag(
        event.pid,
        "dbgk.continue",
        match &result {
            Ok(()) => format!(
                "tid={} pending_kind={:?} continue_status=0x{:08X} result=ok",
                event.tid,
                event.kind,
                status.0 as u32,
            ),
            Err(error) => format!(
                "tid={} pending_kind={:?} continue_status=0x{:08X} result=error error={error}",
                event.tid,
                event.kind,
                status.0 as u32,
            ),
        },
    );
    if result.is_ok() {
        if let PendingKind::Hardware { generation, .. } = event.kind {
            if generation != 0 {
                match pending_hardware_hit_operation(
                    app,
                    event.pid,
                    event.tid,
                    PENDING_HWBP_RETIRE,
                    generation,
                ) {
                    Ok(_) => {}
                    Err(error) => private_dbgk_entry_diag(
                        event.pid,
                        "hwbp.pending.retire.error",
                        format!(
                            "tid={} generation={generation} event_already_continued=true error={error}",
                            event.tid,
                        ),
                    ),
                }
            }
        }
    }
    result
}

fn debug_event_diagnostic(event: &DEBUG_EVENT) -> String {
    let base = format!(
        "event_code={} pid={} tid={}",
        event.dwDebugEventCode.0,
        event.dwProcessId,
        event.dwThreadId,
    );
    unsafe {
        if event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT {
            let exception = event.u.Exception;
            format!(
                "{base} exception_code=0x{:08X} address=0x{:X} first_chance={}",
                exception.ExceptionRecord.ExceptionCode.0 as u32,
                exception.ExceptionRecord.ExceptionAddress as usize as u64,
                exception.dwFirstChance,
            )
        } else if event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT {
            format!("{base} exit_code=0x{:08X}", event.u.ExitProcess.dwExitCode)
        } else if event.dwDebugEventCode == EXIT_THREAD_DEBUG_EVENT {
            format!("{base} exit_code=0x{:08X}", event.u.ExitThread.dwExitCode)
        } else if event.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT {
            let info = event.u.CreateProcessInfo;
            format!(
                "{base} image_base=0x{:X} start=0x{:X} process_handle={:p} thread_handle={:p}",
                info.lpBaseOfImage as usize as u64,
                info.lpStartAddress.map_or(0, |address| address as usize as u64),
                info.hProcess.0,
                info.hThread.0,
            )
        } else {
            base
        }
    }
}

fn wait_debug_event(timeout_ms: u32) -> Result<Option<DEBUG_EVENT>, String> {
    let mut event = DEBUG_EVENT::default();
    match unsafe { WaitForDebugEventEx(&mut event, timeout_ms) } {
        Ok(()) => Ok(Some(event)),
        Err(error) => {
            let last = unsafe { GetLastError() };
            if last == ERROR_SEM_TIMEOUT || last.0 == 258 {
                Ok(None)
            } else {
                Err(string_error("WaitForDebugEventEx", error))
            }
        }
    }
}

fn close_debug_event_handle(event: &DEBUG_EVENT) {
    unsafe {
        if event.dwDebugEventCode == CREATE_THREAD_DEBUG_EVENT {
            close_handle(event.u.CreateThread.hThread);
        } else if event.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT {
            close_handle(event.u.LoadDll.hFile);
        }
    }
}

fn detach_debuggee(
    pid: u32,
    process: HANDLE,
    breakpoint: &mut ByteBreakpoint,
    pending: &mut Option<PendingEvent>,
    create_event: &mut Option<DEBUG_EVENT>,
) -> (bool, Result<(), String>) {
    if let Err(error) = restore_byte_breakpoint(process, breakpoint) {
        // Hard invariant: while our 0xCC may still be present, releasing the
        // event or DebugObject would let the target execute a leaked trap with
        // no debugger left to own it. Retain every event and the session so a
        // later detach can retry restoration.
        return (false, Err(format!("entry-byte restore: {error}")));
    }
    let mut failures = Vec::new();
    if let Some(event) = create_event.as_ref() {
        if let Err(error) = continue_event(event, DBG_CONTINUE) {
            failures.push(format!("create-event continue: {error}"));
        } else {
            // ContinueDebugEvent transfers ownership to Windows exactly once.
            // Clear it before attempting Stop so a Stop-only retry can never
            // submit the already-consumed event a second time.
            *create_event = None;
        }
    }
    if let Some(event) = pending.as_ref() {
        if let Err(error) = unsafe {
            ContinueDebugEvent(event.pid, event.tid, event.continue_status)
        } {
            failures.push(string_error("pending-event continue", error));
        } else {
            *pending = None;
        }
    }
    let detached = match unsafe { DebugActiveProcessStop(pid) } {
        Ok(()) => {
            // A successful authoritative detach releases any event even when
            // its explicit Continue reported an error.
            *create_event = None;
            *pending = None;
            true
        }
        Err(error) if error.code().0 == HRESULT_ERROR_DEBUGGER_INACTIVE => {
            // A private Dbgk session removes its synthetic DebugObject in the
            // hooked NtRemoveProcessDebug path.  Windows may surface that
            // completed transition as ERROR_DEBUGGER_INACTIVE rather than a
            // synchronous success.  No debugger still owns either event.
            *create_event = None;
            *pending = None;
            true
        }
        Err(error) => {
            failures.push(string_error(&format!("DebugActiveProcessStop({pid})"), error));
            false
        }
    };
    let result = if detached || failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; "))
    };
    (detached, result)
}

fn close_rollback_event_handles(
    event: &DEBUG_EVENT,
    process: HANDLE,
    primary_thread: HANDLE,
) {
    unsafe {
        if event.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT {
            let info = event.u.CreateProcessInfo;
            close_handle(info.hFile);
            if info.hProcess != process {
                close_handle(info.hProcess);
            }
            if info.hThread != primary_thread {
                close_handle(info.hThread);
            }
        } else {
            close_debug_event_handle(event);
        }
    }
}

fn clear_owned_rollback_state(
    process: HANDLE,
    primary_thread: HANDLE,
    pending: &mut Option<PendingEvent>,
    create_event: &mut Option<DEBUG_EVENT>,
) {
    if let Some(event) = create_event.take() {
        close_rollback_event_handles(&event, process, primary_thread);
    }
    *pending = None;
}

/// No caller remains to retry an unpublished/abandoned launch. Termination is
/// bounded: first request process termination and drain its debug events, then
/// hand final ownership to DebugObject kill-on-close. The worker exits only
/// after one of those two authoritative owners has accepted cleanup.
fn terminate_owned_until_confirmed(
    process: HANDLE,
    primary_thread: HANDLE,
    pending: &mut Option<PendingEvent>,
    create_event: &mut Option<DEBUG_EVENT>,
) -> Result<(), String> {
    let pid = unsafe { GetProcessId(process) };
    let kill_on_close = unsafe { DebugSetProcessKillOnExit(true) }
        .map_err(|error| string_error("DebugSetProcessKillOnExit(TRUE)", error));
    let deadline = Instant::now() + FORCED_CLEANUP_TIMEOUT;
    let mut last_terminate_error = None;

    while Instant::now() < deadline {
        if unsafe { WaitForSingleObject(process, 0) } == WAIT_OBJECT_0 {
            clear_owned_rollback_state(process, primary_thread, pending, create_event);
            return Ok(());
        }

        if let Err(error) = unsafe { TerminateProcess(process, 0xE000_0003) } {
            last_terminate_error = Some(string_error("TerminateProcess(forced cleanup)", error));
        }

        // Once termination has been requested, continuing an owned event
        // cannot execute the patched target. Consume each event at most once.
        if let Some(event) = create_event.as_ref() {
            if continue_event(event, DBG_CONTINUE).is_ok() {
                *create_event = None;
            }
        }
        if let Some(event) = pending.as_ref() {
            if unsafe { ContinueDebugEvent(event.pid, event.tid, event.continue_status) }.is_ok() {
                *pending = None;
            }
        }

        if create_event.is_none() && pending.is_none() {
            if let Ok(Some(event)) = wait_debug_event(EVENT_POLL_MS) {
                close_rollback_event_handles(&event, process, primary_thread);
                let status = if event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT {
                    DBG_EXCEPTION_NOT_HANDLED
                } else {
                    DBG_CONTINUE
                };
                if continue_event(&event, status).is_err() {
                    *pending = Some(PendingEvent {
                        pid: event.dwProcessId,
                        tid: event.dwThreadId,
                        ip_rewound: true,
                        continue_status: status,
                        rip: 0,
                        kind: PendingKind::SingleStep,
                        resume_prepared: false,
                    });
                }
            }
        }
        std::thread::sleep(Duration::from_millis(25));
    }

    if unsafe { WaitForSingleObject(process, 0) } == WAIT_OBJECT_0 {
        clear_owned_rollback_state(process, primary_thread, pending, create_event);
        return Ok(());
    }
    if kill_on_close.is_ok() {
        private_dbgk_entry_diag(
            pid,
            "cleanup.kill_on_close",
            "process did not signal within forced-cleanup window; DebugObject close owns termination",
        );
        clear_owned_rollback_state(process, primary_thread, pending, create_event);
        return Ok(());
    }

    Err(format!(
        "forced cleanup could not terminate PID {pid} and could not arm DebugObject kill-on-close: {}; last termination error: {}",
        kill_on_close.err().unwrap_or_else(|| "unknown".into()),
        last_terminate_error.unwrap_or_else(|| "none".into()),
    ))
}

fn abandon_debuggee(
    pid: u32,
    process: HANDLE,
    primary_thread: HANDLE,
    breakpoint: &mut ByteBreakpoint,
    pending: &mut Option<PendingEvent>,
    create_event: &mut Option<DEBUG_EVENT>,
) -> Result<(), String> {
    // A pending entry whose IP was not restored cannot be safely detached;
    // terminating the unpublished target is the only authoritative rollback.
    if pending.as_ref().is_some_and(|event| !event.ip_rewound) {
        return terminate_owned_until_confirmed(
            process,
            primary_thread,
            pending,
            create_event,
        );
    }

    let (detached, _) = detach_debuggee(
        pid,
        process,
        breakpoint,
        pending,
        create_event,
    );
    if detached {
        return Ok(());
    }

    terminate_owned_until_confirmed(process, primary_thread, pending, create_event)
}

fn detach_active_debuggee(
    engine: &mut NativeEngine,
    pending: &mut Option<PendingEvent>,
    create_event: &mut Option<DEBUG_EVENT>,
) -> (bool, Result<(), String>) {
    if let Err(error) = engine.restore_all_controls() {
        return (false, Err(format!("restore native debug controls: {error}")));
    }
    if let Some(event) = pending.as_mut() {
        if !event.ip_rewound {
            let rewind = with_event_thread(
                engine.primary_thread,
                engine.primary_tid,
                event.tid,
                |thread| rewind_instruction_pointer(thread, engine.wow64, event.rip),
            );
            if let Err(error) = rewind {
                return (false, Err(format!("restore pending instruction pointer: {error}")));
            }
            event.ip_rewound = true;
        }
    }

    let mut failures = Vec::new();
    if let Some(event) = create_event.as_ref() {
        if let Err(error) = continue_event(event, DBG_CONTINUE) {
            failures.push(format!("create-event continue: {error}"));
        } else {
            *create_event = None;
        }
    }
    if let Some(event) = pending.as_ref() {
        if let Err(error) = continue_pending_event(
            &engine.app,
            event,
            event.continue_status,
            "pending-event continue",
        ) {
            failures.push(error);
        } else {
            *pending = None;
        }
    }
    let detached = match unsafe { DebugActiveProcessStop(engine.pid) } {
        Ok(()) => {
            *create_event = None;
            *pending = None;
            true
        }
        Err(error) if error.code().0 == HRESULT_ERROR_DEBUGGER_INACTIVE => {
            *create_event = None;
            *pending = None;
            true
        }
        Err(error) => {
            failures.push(string_error(
                &format!("DebugActiveProcessStop({})", engine.pid),
                error,
            ));
            false
        }
    };
    let result = if detached || failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; "))
    };
    (detached, result)
}

fn finish_failed_detach(
    engine: &mut NativeEngine,
    pending: &mut Option<PendingEvent>,
    create_pending: &mut Option<DEBUG_EVENT>,
) -> Result<(), String> {
    if engine.terminate_on_cleanup {
        return terminate_owned_until_confirmed(
            engine.process,
            engine.primary_thread,
            pending,
            create_pending,
        );
    }

    let deadline = Instant::now() + FORCED_DETACH_GRACE;
    while Instant::now() < deadline {
        if unsafe { WaitForSingleObject(engine.process, 0) } == WAIT_OBJECT_0 {
            clear_owned_rollback_state(
                engine.process,
                engine.primary_thread,
                pending,
                create_pending,
            );
            return Ok(());
        }
        let (detached, _) = detach_active_debuggee(engine, pending, create_pending);
        if detached {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(25));
    }

    terminate_owned_until_confirmed(
        engine.process,
        engine.primary_thread,
        pending,
        create_pending,
    )
}

enum ActiveCommandResult {
    KeepRunning,
    Detached,
    Abandoned,
}

#[allow(clippy::too_many_arguments)]
fn handle_active_command(
    engine: &mut NativeEngine,
    command: LoopCommand,
    pending: &mut Option<PendingEvent>,
    create_pending: &mut Option<DEBUG_EVENT>,
    run_reply: &mut Option<mpsc::Sender<Result<NativeLaunchInfo, String>>>,
    stage: &Arc<AtomicU32>,
    pending_tid: &Arc<AtomicU32>,
    initial_system_breakpoint: Option<&InitialSystemBreakpointState>,
) -> ActiveCommandResult {
    match command {
        LoopCommand::RunToEntry(reply) => {
            if let Some(event) = pending.as_ref().filter(|event| matches!(event.kind, PendingKind::Entry)) {
                let _ = reply.send(Ok(NativeLaunchInfo {
                    pid: engine.pid,
                    primary_tid: engine.primary_tid,
                    entry_address: event.rip,
                    stopped_at_entry: true,
                }));
            } else if run_reply.is_some() {
                let _ = reply.send(Err("native target is already running to its entry point".into()));
            } else {
                let _ = reply.send(Err("native entry event has already been continued".into()));
            }
        }
        LoopCommand::ActivateAttach(reply) => {
            let _ = reply.send(Err("native attach session is already active".into()));
        }
        LoopCommand::ContinueEntry { tid, reply } => {
            let Some(event) = pending.as_mut() else {
                let _ = reply.send(Err(format!("there is no pending native event for TID {tid}")));
                return ActiveCommandResult::KeepRunning;
            };
            if event.tid != tid {
                let _ = reply.send(Err(format!(
                    "native event belongs to TID {}, not TID {tid}",
                    event.tid
                )));
                return ActiveCommandResult::KeepRunning;
            }
            let was_initial_system_breakpoint =
                matches!(event.kind, PendingKind::InitialSystemBreakpoint);
            let result = if was_initial_system_breakpoint {
                continue_pending_event(
                    &engine.app,
                    event,
                    DBG_CONTINUE,
                    "ContinueDebugEvent(initial system breakpoint)",
                )
            } else {
                engine.prepare_resume(event, ResumeAction::Continue).and_then(|_| {
                    continue_pending_event(
                        &engine.app,
                        event,
                        event.continue_status,
                        "ContinueDebugEvent(native)",
                    )
                })
            };
            if result.is_ok() {
                *pending = None;
                pending_tid.store(0, Ordering::Release);
                stage.store(STAGE_ENTRY_CONTINUED, Ordering::Release);
                if was_initial_system_breakpoint {
                    if let Some(state) = initial_system_breakpoint {
                        state.clear();
                    }
                }
            }
            let _ = reply.send(result);
        }
        LoopCommand::ContinueInitialSystemBreakpoint { tid, reply } => {
            let Some(event) = pending.as_ref() else {
                let _ = reply.send(Err(format!(
                    "there is no pending initial system breakpoint for TID {tid}"
                )));
                return ActiveCommandResult::KeepRunning;
            };
            if event.tid != tid {
                let _ = reply.send(Err(format!(
                    "initial system breakpoint belongs to TID {}, not TID {tid}",
                    event.tid
                )));
                return ActiveCommandResult::KeepRunning;
            }
            if !matches!(event.kind, PendingKind::InitialSystemBreakpoint) {
                let _ = reply.send(Err(format!(
                    "pending native event for TID {tid} is not the initial system breakpoint"
                )));
                return ActiveCommandResult::KeepRunning;
            }
            let result = continue_pending_event(
                &engine.app,
                event,
                DBG_CONTINUE,
                "ContinueDebugEvent(initial system breakpoint)",
            );
            if result.is_ok() {
                *pending = None;
                pending_tid.store(0, Ordering::Release);
                stage.store(STAGE_ENTRY_CONTINUED, Ordering::Release);
                if let Some(state) = initial_system_breakpoint {
                    state.clear();
                }
            }
            let _ = reply.send(result);
        }
        LoopCommand::StepInto { tid, reply } => {
            if let Err(error) = engine.ensure_no_active_run(tid) {
                let _ = reply.send(Err(error));
                return ActiveCommandResult::KeepRunning;
            }
            if let Some(event) = pending.as_mut() {
                if event.tid != tid {
                    let _ = reply.send(Err(format!(
                        "native event belongs to TID {}, not TID {tid}",
                        event.tid
                    )));
                    return ActiveCommandResult::KeepRunning;
                }
                if matches!(event.kind, PendingKind::InitialSystemBreakpoint) {
                    let _ = reply.send(Err(
                        "initial system breakpoint must be continued before native stepping"
                            .into(),
                    ));
                    return ActiveCommandResult::KeepRunning;
                }
                let result = engine.prepare_resume(event, ResumeAction::StepInto).and_then(|_| {
                    continue_pending_event(
                        &engine.app,
                        event,
                        event.continue_status,
                        "ContinueDebugEvent(step-into)",
                    )
                });
                if result.is_ok() {
                    *pending = None;
                    pending_tid.store(0, Ordering::Release);
                    stage.store(STAGE_ENTRY_CONTINUED, Ordering::Release);
                }
                let _ = reply.send(result.map(|_| true));
            } else {
                let _ = reply.send(engine.arm_external_step(tid).map(|_| false));
            }
        }
        LoopCommand::StepIntoVt { tid, reply } => {
            if let Err(error) = engine.ensure_no_active_run(tid) {
                let _ = reply.send(Err(error));
                return ActiveCommandResult::KeepRunning;
            }
            if let Some(event) = pending.as_mut() {
                if event.tid != tid {
                    let _ = reply.send(Err(format!(
                        "native event belongs to TID {}, not TID {tid}",
                        event.tid
                    )));
                    return ActiveCommandResult::KeepRunning;
                }
                if matches!(event.kind, PendingKind::InitialSystemBreakpoint) {
                    let _ = reply.send(Err(
                        "initial system breakpoint must be continued before VT stepping"
                            .into(),
                    ));
                    return ActiveCommandResult::KeepRunning;
                }
                let result = engine
                    .prepare_resume(event, ResumeAction::Continue)
                    .and_then(|_| engine.arm_external_vt_step(tid))
                    .and_then(|_| {
                        continue_pending_event(
                            &engine.app,
                            event,
                            event.continue_status,
                            "ContinueDebugEvent(VT step-into)",
                        )
                        .map_err(|error| {
                            engine.vt_steps.remove(&tid);
                            error
                        })
                    });
                if result.is_ok() {
                    *pending = None;
                    pending_tid.store(0, Ordering::Release);
                    stage.store(STAGE_ENTRY_CONTINUED, Ordering::Release);
                }
                let _ = reply.send(result.map(|_| true));
            } else {
                let _ = reply.send(engine.arm_external_vt_step(tid).map(|_| false));
            }
        }
        LoopCommand::CancelVtStep { tid, reply } => {
            if engine.rearm_steps.contains_key(&tid) {
                let _ = reply.send(Err(format!(
                    "TID {tid} is completing a native breakpoint rearm"
                )));
            } else {
                engine.vt_steps.remove(&tid);
                let _ = reply.send(Ok(()));
            }
        }
        LoopCommand::StepOver {
            tid,
            reply,
        } => {
            if let Err(error) = engine.ensure_no_active_run(tid) {
                let _ = reply.send(Err(error));
                return ActiveCommandResult::KeepRunning;
            }
            if let Some(event) = pending.as_mut() {
                if event.tid != tid {
                    let _ = reply.send(Err(format!(
                        "native event belongs to TID {}, not TID {tid}",
                        event.tid
                    )));
                    return ActiveCommandResult::KeepRunning;
                }
                if matches!(event.kind, PendingKind::InitialSystemBreakpoint) {
                    let _ = reply.send(Err(
                        "initial system breakpoint must be continued before native stepping"
                            .into(),
                    ));
                    return ActiveCommandResult::KeepRunning;
                }
                let decoded = engine.decode_step_over(event);
                let result = decoded.and_then(|(action, mut result)| {
                    engine.prepare_resume(event, action)?;
                    continue_pending_event(
                        &engine.app,
                        event,
                        event.continue_status,
                        "ContinueDebugEvent(step-over)",
                    )?;
                    result.continued_event = true;
                    Ok(result)
                });
                if result.is_ok() {
                    *pending = None;
                    pending_tid.store(0, Ordering::Release);
                    stage.store(STAGE_ENTRY_CONTINUED, Ordering::Release);
                }
                let _ = reply.send(result);
            } else {
                let rip = with_suspended_thread(tid, |thread| {
                    read_instruction_pointer(thread, engine.wow64)
                });
                let result = rip.and_then(|rip| {
                    let synthetic = PendingEvent {
                        pid: engine.pid,
                        tid,
                        ip_rewound: true,
                        continue_status: DBG_CONTINUE,
                        rip,
                        kind: PendingKind::SingleStep,
                        resume_prepared: false,
                    };
                    let (action, result) = engine.decode_step_over(&synthetic)?;
                    match action {
                        ResumeAction::StepInto => engine.arm_external_step(tid)?,
                        ResumeAction::StepOver(address) => engine.arm_step_over(tid, address)?,
                        ResumeAction::Continue => unreachable!(),
                    }
                    Ok(result)
                });
                let _ = reply.send(result);
            }
        }
        LoopCommand::StepOut { tid, reply } => {
            if let Err(error) = engine.ensure_no_active_run(tid) {
                let _ = reply.send(Err(error));
                return ActiveCommandResult::KeepRunning;
            }
            if pending.as_ref().is_some_and(|event| {
                matches!(event.kind, PendingKind::InitialSystemBreakpoint)
            }) {
                let _ = reply.send(Err(
                    "initial system breakpoint must be continued before native stepping".into(),
                ));
                return ActiveCommandResult::KeepRunning;
            }
            let result = engine.return_address(tid).and_then(|return_address| {
                if let Some(event) = pending.as_mut() {
                    if event.tid != tid {
                        return Err(format!(
                            "native event belongs to TID {}, not TID {tid}",
                            event.tid
                        ));
                    }
                    engine.prepare_resume(event, ResumeAction::StepOver(return_address))?;
                    continue_pending_event(
                        &engine.app,
                        event,
                        event.continue_status,
                        "ContinueDebugEvent(step-out)",
                    )?;
                    *pending = None;
                    pending_tid.store(0, Ordering::Release);
                    stage.store(STAGE_ENTRY_CONTINUED, Ordering::Release);
                } else {
                    engine.arm_step_over(tid, return_address)?;
                }
                Ok(return_address)
            });
            let _ = reply.send(result);
        }
        LoopCommand::CancelStepOver { tid, reply } => {
            let _ = reply.send(engine.cancel_step_over_for_thread(tid));
        }
        LoopCommand::SetSoftware { address, reply } => {
            let _ = reply.send(engine.set_software(address));
        }
        LoopCommand::ClearSoftware { address, reply } => {
            let _ = reply.send(engine.clear_software(address));
        }
        LoopCommand::ListSoftware(reply) => {
            let _ = reply.send(engine.software_list());
        }
        LoopCommand::SetHardware { breakpoint, reply } => {
            let _ = reply.send(engine.set_hardware(breakpoint));
        }
        LoopCommand::ClearHardware { slot, reply } => {
            let _ = reply.send(engine.clear_hardware(slot));
        }
        LoopCommand::ListHardware(reply) => {
            let _ = reply.send(engine.hardware_list());
        }
        LoopCommand::Detach(reply) => {
            stage.store(STAGE_DETACH_RETRY, Ordering::Release);
            if let Some(waiter) = run_reply.take() {
                let _ = waiter.send(Err("native run-to-entry was cancelled by detach".into()));
            }
            let (detached, result) = detach_active_debuggee(engine, pending, create_pending);
            if pending.is_none() {
                pending_tid.store(0, Ordering::Release);
            }
            let _ = reply.send(result);
            if detached {
                return ActiveCommandResult::Detached;
            }
        }
        LoopCommand::Abandon(reply) => {
            if let Some(waiter) = run_reply.take() {
                let _ = waiter.send(Err("native run-to-entry was abandoned".into()));
            }
            let (detached, _) = detach_active_debuggee(engine, pending, create_pending);
            let result = if detached {
                Ok(())
            } else {
                finish_failed_detach(engine, pending, create_pending)
            };
            if result.is_ok() {
                pending_tid.store(0, Ordering::Release);
            } else {
                stage.store(STAGE_DETACH_RETRY, Ordering::Release);
            }
            let completed = result.is_ok();
            let _ = reply.send(result);
            if completed {
                return ActiveCommandResult::Abandoned;
            }
        }
    }
    ActiveCommandResult::KeepRunning
}

fn make_pending(
    event: &DEBUG_EVENT,
    rip: u64,
    kind: PendingKind,
    ip_rewound: bool,
) -> PendingEvent {
    PendingEvent {
        pid: event.dwProcessId,
        tid: event.dwThreadId,
        ip_rewound,
        continue_status: DBG_CONTINUE,
        rip,
        kind,
        resume_prepared: false,
    }
}

fn handle_breakpoint_event(
    engine: &mut NativeEngine,
    event: &DEBUG_EVENT,
    address: u64,
    saw_system_breakpoint: &mut bool,
    run_reply: &mut Option<mpsc::Sender<Result<NativeLaunchInfo, String>>>,
    stage: &Arc<AtomicU32>,
    pending_tid: &Arc<AtomicU32>,
    initial_system_breakpoint: Option<&InitialSystemBreakpointState>,
) -> Result<Option<PendingEvent>, String> {
    if engine
        .entry
        .as_ref()
        .is_some_and(|breakpoint| breakpoint.armed && breakpoint.address == address)
    {
        let restore = restore_byte_breakpoint(engine.process, engine.entry.as_mut().unwrap());
        let rewind = restore.and_then(|_| {
            with_event_thread(
                engine.primary_thread,
                engine.primary_tid,
                event.dwThreadId,
                |thread| rewind_instruction_pointer(thread, engine.wow64, address),
            )
        });
        let rewound = rewind.is_ok();
        if let Err(error) = rewind {
            if let Some(reply) = run_reply.take() {
                let _ = reply.send(Err(format!(
                    "entry breakpoint hit but execution state could not be restored: {error}"
                )));
            }
        } else if let Some(reply) = run_reply.take() {
            let _ = reply.send(Ok(NativeLaunchInfo {
                pid: engine.pid,
                primary_tid: engine.primary_tid,
                entry_address: address,
                stopped_at_entry: true,
            }));
        }
        stage.store(STAGE_ENTRY_PENDING, Ordering::Release);
        pending_tid.store(event.dwThreadId, Ordering::Release);
        engine.emit_hit(event.dwThreadId, address, HIT_ENTRY, None);
        return Ok(Some(make_pending(event, address, PendingKind::Entry, rewound)));
    }

    if engine.software.contains_key(&address) {
        let restore = restore_byte_breakpoint(engine.process, engine.software.get_mut(&address).unwrap());
        let rewind = restore.and_then(|_| {
            with_event_thread(
                engine.primary_thread,
                engine.primary_tid,
                event.dwThreadId,
                |thread| rewind_instruction_pointer(thread, engine.wow64, address),
            )
        });
        let rewound = rewind.is_ok();
        let step_over = engine
            .step_over_targets
            .get(&address)
            .is_some_and(|owner| *owner == event.dwThreadId);
        if step_over {
            engine.step_over_targets.remove(&address);
        }
        let kind = if step_over { HIT_STEP_OVER } else { HIT_SOFTWARE };
        stage.store(STAGE_ENTRY_PENDING, Ordering::Release);
        pending_tid.store(event.dwThreadId, Ordering::Release);
        engine.emit_hit(event.dwThreadId, address, kind, None);
        return Ok(Some(make_pending(
            event,
            address,
            PendingKind::Software { address },
            rewound,
        )));
    }

    if engine.transient.contains_key(&address) {
        let owner_tid = engine.step_over_targets.get(&address).copied();
        let restore = restore_byte_breakpoint(engine.process, engine.transient.get_mut(&address).unwrap());
        let rewind = restore.and_then(|_| {
            with_event_thread(
                engine.primary_thread,
                engine.primary_tid,
                event.dwThreadId,
                |thread| rewind_instruction_pointer(thread, engine.wow64, address),
            )
        });
        let rewound = rewind.is_ok();
        if owner_tid.is_none() && rewound {
            engine.transient.remove(&address);
            return Ok(None);
        }
        if owner_tid.is_some_and(|owner| owner != event.dwThreadId) {
            if rewound {
                match engine.start_rearm_step(
                    event.dwThreadId,
                    address,
                    false,
                    RearmKind::Transient,
                ) {
                    Ok(()) => return Ok(None),
                    Err(error) => engine.emit_control_error(
                        event.dwThreadId,
                        "non-owner one-shot pass-through",
                        &error,
                    ),
                }
            }
            stage.store(STAGE_ENTRY_PENDING, Ordering::Release);
            pending_tid.store(event.dwThreadId, Ordering::Release);
            engine.emit_hit(event.dwThreadId, address, HIT_STEP_OVER, None);
            return Ok(Some(make_pending(
                event,
                address,
                PendingKind::TransientPass { address },
                rewound,
            )));
        }
        if rewound {
            engine.transient.remove(&address);
            engine.step_over_targets.remove(&address);
        }
        stage.store(STAGE_ENTRY_PENDING, Ordering::Release);
        pending_tid.store(event.dwThreadId, Ordering::Release);
        engine.emit_hit(event.dwThreadId, address, HIT_STEP_OVER, None);
        return Ok(Some(make_pending(
            event,
            address,
            PendingKind::StepOver { address },
            rewound,
        )));
    }

    if !*saw_system_breakpoint {
        *saw_system_breakpoint = true;
        if let Some(state) = initial_system_breakpoint {
            stage.store(STAGE_ENTRY_PENDING, Ordering::Release);
            pending_tid.store(event.dwThreadId, Ordering::Release);
            state.publish(event.dwThreadId);
            return Ok(Some(make_pending(
                event,
                address,
                PendingKind::InitialSystemBreakpoint,
                true,
            )));
        }
        return Ok(None);
    }
    Err("unowned-breakpoint".into())
}

fn handle_single_step_event(
    engine: &mut NativeEngine,
    event: &DEBUG_EVENT,
    stage: &Arc<AtomicU32>,
    pending_tid: &Arc<AtomicU32>,
) -> Result<Option<PendingEvent>, String> {
    let vt_hardware_mask = super::hwbp::vt_hardware_mask(engine.pid);
    let pending_vt_hit = if vt_hardware_mask != 0 {
        match pending_hardware_hit_operation(
            &engine.app,
            engine.pid,
            event.dwThreadId,
            PENDING_HWBP_QUERY,
            0,
        ) {
            Ok(hit) => hit,
            Err(error) => {
                private_dbgk_entry_diag(
                    engine.pid,
                    "hwbp.pending.query.error",
                    format!("tid={} error={error}", event.dwThreadId),
                );
                return Err(error);
            }
        }
    } else {
        None
    };

    if let Some(hit) = pending_vt_hit {
        let rip = with_event_thread(
            engine.primary_thread,
            engine.primary_tid,
            event.dwThreadId,
            |thread| read_instruction_pointer(thread, engine.wow64),
        )?;
        let slot = (0..4)
            .find(|slot| hit.dr6_mask & (1u64 << slot) != 0)
            .map(|slot| slot as u32);
        private_dbgk_entry_diag(
            engine.pid,
            "hwbp.pending.classify",
            format!(
                "tid={} rip=0x{rip:X} dr6=0x{:X} generation={} configured_vt=0x{vt_hardware_mask:X} slot={}",
                event.dwThreadId,
                hit.dr6_mask,
                hit.generation,
                slot.map_or_else(|| "none".into(), |value| value.to_string()),
            ),
        );
        stage.store(STAGE_ENTRY_PENDING, Ordering::Release);
        pending_tid.store(event.dwThreadId, Ordering::Release);
        engine.emit_hit(event.dwThreadId, rip, HIT_HARDWARE, slot);
        return Ok(Some(make_pending(
            event,
            rip,
            PendingKind::Hardware {
                slot,
                generation: hit.generation,
            },
            true,
        )));
    }

    let native_vt_step = engine.vt_steps.contains(&event.dwThreadId);
    let private_vt_step = engine
        .private_vt_step_intents
        .as_ref()
        .is_some_and(|intents| intents.lock().contains(&event.dwThreadId));

    // MTF supplies the completion cause for a VT step.  It does not own TF or
    // any guest debug register, so do not read, classify or write DR state on
    // this path.  In particular, stale DR6 bits must not turn a completed VT
    // step into a hardware-breakpoint event or a SetThreadContext recovery.
    if native_vt_step || private_vt_step {
        let rip = with_event_thread(
            engine.primary_thread,
            engine.primary_tid,
            event.dwThreadId,
            |thread| read_instruction_pointer(thread, engine.wow64),
        )?;
        if native_vt_step {
            engine.vt_steps.remove(&event.dwThreadId);
        }
        if private_vt_step {
            if let Some(intents) = engine.private_vt_step_intents.as_ref() {
                intents.lock().remove(&event.dwThreadId);
            }
            private_dbgk_entry_diag(
                engine.pid,
                "vt_step.receiver.hit",
                format!("tid={} rip=0x{rip:X}", event.dwThreadId),
            );
        }
        stage.store(STAGE_ENTRY_PENDING, Ordering::Release);
        pending_tid.store(event.dwThreadId, Ordering::Release);
        engine.emit_hit(event.dwThreadId, rip, HIT_SINGLE_STEP, None);
        return Ok(Some(make_pending(
            event,
            rip,
            PendingKind::SingleStep,
            true,
        )));
    }

    let (mut debug_state, rip) = with_event_thread(
        engine.primary_thread,
        engine.primary_tid,
        event.dwThreadId,
        |thread| {
            let debug = read_debug_registers(thread, engine.wow64)?;
            let rip = read_instruction_pointer(thread, engine.wow64)?;
            Ok((debug, rip))
        },
    )?;
    let configured_mask = engine
        .hardware
        .iter()
        .enumerate()
        .fold(0u64, |mask, (slot, breakpoint)| {
            if breakpoint.is_some() {
                mask | (1u64 << slot)
            } else {
                mask
            }
        });
    let hardware_mask = debug_state.dr6 & DR6_BREAKPOINT_MASK & configured_mask;
    let has_rearm = engine.rearm_steps.contains_key(&event.dwThreadId);
    let native_tf_step = engine.tf_steps.contains(&event.dwThreadId);
    let user_step = native_tf_step;
    let owns_single_step = has_rearm || user_step;
    if configured_mask != 0 {
        private_dbgk_entry_diag(
            engine.pid,
            "hwbp.single_step.classify",
            format!(
                "tid={} rip=0x{rip:X} dr6=0x{:X} configured_native=0x{configured_mask:X} hit=0x{hardware_mask:X}",
                event.dwThreadId,
                debug_state.dr6,
            ),
        );
    }

    let owns_native_dr6 = has_rearm || native_tf_step;
    if hardware_mask != 0 || owns_native_dr6 {
        let owned_dr6 = hardware_mask
            | if owns_native_dr6 {
                DR6_SINGLE_STEP
            } else {
                0
            };
        debug_state.dr6 &= !owned_dr6;
        with_event_thread(
            engine.primary_thread,
            engine.primary_tid,
            event.dwThreadId,
            |thread| write_debug_registers(thread, engine.wow64, debug_state),
        )?;
    }

    let slot = if hardware_mask != 0 {
        (0..4)
            .find(|slot| hardware_mask & (1u64 << slot) != 0)
            .map(|slot| slot as u32)
    } else {
        None
    };
    if let Some(slot) = slot {
        if engine.hardware[slot as usize].is_some_and(|breakpoint| breakpoint.bp_type == 0) {
            with_event_thread(
                engine.primary_thread,
                engine.primary_tid,
                event.dwThreadId,
                |thread| mark_hardware_resume(thread, engine.wow64).map(|_| ()),
            )?;
        }
    }

    let mut stop_after_rearm = false;
    if has_rearm {
        stop_after_rearm = engine.complete_rearm_step(event.dwThreadId, true)?;
    } else if user_step {
        if native_tf_step {
            with_event_thread(
                engine.primary_thread,
                engine.primary_tid,
                event.dwThreadId,
                |thread| set_trap_flag(thread, engine.wow64, false).map(|_| ()),
            )?;
            engine.tf_steps.remove(&event.dwThreadId);
        }
    }

    if hardware_mask != 0 {
        stage.store(STAGE_ENTRY_PENDING, Ordering::Release);
        pending_tid.store(event.dwThreadId, Ordering::Release);
        engine.emit_hit(event.dwThreadId, rip, HIT_HARDWARE, slot);
        return Ok(Some(make_pending(
            event,
            rip,
            PendingKind::Hardware {
                slot,
                generation: 0,
            },
            true,
        )));
    }
    if stop_after_rearm || user_step {
        stage.store(STAGE_ENTRY_PENDING, Ordering::Release);
        pending_tid.store(event.dwThreadId, Ordering::Release);
        engine.emit_hit(event.dwThreadId, rip, HIT_SINGLE_STEP, None);
        return Ok(Some(make_pending(
            event,
            rip,
            PendingKind::SingleStep,
            true,
        )));
    }
    if owns_single_step {
        return Ok(None);
    }
    Err("unowned-single-step".into())
}

#[allow(clippy::too_many_arguments)]
fn active_event_loop(
    mut engine: NativeEngine,
    commands: &mpsc::Receiver<LoopCommand>,
    mut pending: Option<PendingEvent>,
    mut create_pending: Option<DEBUG_EVENT>,
    mut run_reply: Option<mpsc::Sender<Result<NativeLaunchInfo, String>>>,
    stage: &Arc<AtomicU32>,
    pending_tid: &Arc<AtomicU32>,
    initial_system_breakpoint: Option<&InitialSystemBreakpointState>,
) {
    let mut saw_system_breakpoint =
        engine.entry.is_none() && initial_system_breakpoint.is_none();
    loop {
        if pending.is_some() {
            match commands.recv() {
                Ok(command) => match handle_active_command(
                    &mut engine,
                    command,
                    &mut pending,
                    &mut create_pending,
                    &mut run_reply,
                    stage,
                    pending_tid,
                    initial_system_breakpoint,
                ) {
                    ActiveCommandResult::KeepRunning => continue,
                    ActiveCommandResult::Detached | ActiveCommandResult::Abandoned => return,
                },
                Err(_) => {
                    let (detached, _) = detach_active_debuggee(
                        &mut engine,
                        &mut pending,
                        &mut create_pending,
                    );
                    if !detached {
                        if let Err(error) = finish_failed_detach(
                            &mut engine,
                            &mut pending,
                            &mut create_pending,
                        ) {
                            private_dbgk_entry_diag(
                                engine.pid,
                                "cleanup.force.error",
                                error,
                            );
                        }
                    }
                    return;
                }
            }
        }

        loop {
            match commands.try_recv() {
                Ok(command) => match handle_active_command(
                    &mut engine,
                    command,
                    &mut pending,
                    &mut create_pending,
                    &mut run_reply,
                    stage,
                    pending_tid,
                    initial_system_breakpoint,
                ) {
                    ActiveCommandResult::KeepRunning => {}
                    ActiveCommandResult::Detached | ActiveCommandResult::Abandoned => return,
                },
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => {
                    let (detached, _) = detach_active_debuggee(
                        &mut engine,
                        &mut pending,
                        &mut create_pending,
                    );
                    if !detached {
                        if let Err(error) = finish_failed_detach(
                            &mut engine,
                            &mut pending,
                            &mut create_pending,
                        ) {
                            private_dbgk_entry_diag(
                                engine.pid,
                                "cleanup.force.error",
                                error,
                            );
                        }
                    }
                    return;
                }
            }
            if pending.is_some() {
                break;
            }
        }
        if pending.is_some() {
            continue;
        }

        let event = match wait_debug_event(EVENT_POLL_MS) {
            Ok(Some(event)) => event,
            Ok(None) => continue,
            Err(error) => {
                private_dbgk_entry_diag(engine.pid, "dbgk.wait.error", &error);
                if let Some(reply) = run_reply.take() {
                    let _ = reply.send(Err(error));
                }
                break;
            }
        };
        private_dbgk_entry_diag(
            engine.pid,
            "dbgk.event",
            debug_event_diagnostic(&event),
        );

        if event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT {
            close_debug_event_handle(&event);
            let _ = continue_event(&event, DBG_CONTINUE);
            if let Some(reply) = run_reply.take() {
                let _ = reply.send(Err("target exited before reaching its PE entry point".into()));
            }
            engine.software.clear();
            engine.transient.clear();
            for step in engine.rearm_steps.values_mut() {
                release_suspensions_confirmed(&mut step.suspended);
            }
            engine.rearm_steps.clear();
            engine.tf_steps.clear();
            engine.vt_steps.clear();
            if let Some(intents) = engine.private_vt_step_intents.as_ref() {
                intents.lock().clear();
            }
            engine.step_over_targets.clear();
            engine.hardware = [None; 4];
            engine.original_dr.clear();
            return;
        }

        if event.dwDebugEventCode == CREATE_THREAD_DEBUG_EVENT {
            let info = unsafe { event.u.CreateThread };
            if let Err(error) = engine.hold_new_thread_during_rearm(event.dwThreadId) {
                engine.emit_control_error(
                    event.dwThreadId,
                    "CREATE_THREAD INT3 window inheritance",
                    &error,
                );
                let owners: Vec<u32> = engine.rearm_steps.keys().copied().collect();
                let mut abort_failures = Vec::new();
                for owner in owners {
                    if let Err(abort_error) = engine.complete_rearm_step(owner, true) {
                        abort_failures.push(format!("TID {owner}: {abort_error}"));
                    }
                }
                if !abort_failures.is_empty() {
                    let detail = format!(
                        "unable to close INT3 rearm window after new-thread suspension failure: {}",
                        abort_failures.join("; ")
                    );
                    engine.emit_control_error(event.dwThreadId, "CREATE_THREAD fail-closed", &detail);
                    close_debug_event_handle(&event);
                    pending = Some(make_pending(&event, 0, PendingKind::SingleStep, true));
                    break;
                }
            }
            let apply = engine.apply_hardware_to_new_thread(event.dwThreadId, info.hThread);
            if let Err(error) = apply {
                let revoke = engine.revoke_hardware_after_new_thread_failure(
                    event.dwThreadId,
                    info.hThread,
                );
                let detail = match revoke {
                    Ok(()) => format!("{error}; all native DR breakpoints were revoked"),
                    Err(revoke_error) => format!(
                        "{error}; DR revocation failed and the prior configuration remains active where possible: {revoke_error}"
                    ),
                };
                engine.emit_control_error(
                    event.dwThreadId,
                    "CREATE_THREAD DR synchronization",
                    &detail,
                );
                if let Some(reply) = run_reply.take() {
                    let _ = reply.send(Err(detail));
                }
            }
            close_debug_event_handle(&event);
            if continue_event(&event, DBG_CONTINUE).is_err() {
                pending = Some(make_pending(&event, 0, PendingKind::SingleStep, true));
                break;
            }
            continue;
        }

        if event.dwDebugEventCode == EXIT_THREAD_DEBUG_EVENT {
            if let Err(error) = engine.finish_rearm_for_exiting_thread(event.dwThreadId) {
                engine.emit_control_error(
                    event.dwThreadId,
                    "thread-exit INT3 window cleanup",
                    &error,
                );
            }
            if let Err(error) = engine.cancel_step_over_for_thread(event.dwThreadId) {
                engine.emit_control_error(
                    event.dwThreadId,
                    "thread-exit one-shot cleanup",
                    &error,
                );
            }
            engine.original_dr.remove(&event.dwThreadId);
            engine.tf_steps.remove(&event.dwThreadId);
            engine.vt_steps.remove(&event.dwThreadId);
            if let Some(intents) = engine.private_vt_step_intents.as_ref() {
                intents.lock().remove(&event.dwThreadId);
            }
            close_debug_event_handle(&event);
            if continue_event(&event, DBG_CONTINUE).is_err() {
                pending = Some(make_pending(&event, 0, PendingKind::SingleStep, true));
                break;
            }
            continue;
        }

        close_debug_event_handle(&event);
        let mut status = DBG_CONTINUE;
        if event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT {
            let exception = unsafe { event.u.Exception };
            let code = normalize_debug_exception_code(
                exception.ExceptionRecord.ExceptionCode,
                engine.wow64,
            );
            let address = exception.ExceptionRecord.ExceptionAddress as usize as u64;
            if code == EXCEPTION_BREAKPOINT {
                match handle_breakpoint_event(
                    &mut engine,
                    &event,
                    address,
                    &mut saw_system_breakpoint,
                    &mut run_reply,
                    stage,
                    pending_tid,
                    initial_system_breakpoint,
                ) {
                    Ok(Some(owned)) => pending = Some(owned),
                    Ok(None) => status = DBG_CONTINUE,
                    Err(error) if error == "unowned-breakpoint" => {
                        status = DBG_EXCEPTION_NOT_HANDLED
                    }
                    Err(_) => status = DBG_EXCEPTION_NOT_HANDLED,
                }
            } else if code == EXCEPTION_SINGLE_STEP {
                match handle_single_step_event(&mut engine, &event, stage, pending_tid) {
                    Ok(Some(owned)) => pending = Some(owned),
                    Ok(None) => status = DBG_CONTINUE,
                    Err(error) if error == "unowned-single-step" => {
                        status = DBG_EXCEPTION_NOT_HANDLED
                    }
                    Err(error) => {
                        if let Some(reply) = run_reply.take() {
                            let _ = reply.send(Err(error.clone()));
                        }
                        engine.emit_control_error(
                            event.dwThreadId,
                            "single-step completion",
                            &error,
                        );
                        stage.store(STAGE_ENTRY_PENDING, Ordering::Release);
                        pending_tid.store(event.dwThreadId, Ordering::Release);
                        engine.emit_hit(event.dwThreadId, address, HIT_SINGLE_STEP, None);
                        pending = Some(make_pending(
                            &event,
                            address,
                            PendingKind::SingleStep,
                            true,
                        ));
                    }
                }
            } else {
                status = DBG_EXCEPTION_NOT_HANDLED;
            }
        }

        if pending.is_none() {
            if continue_event(&event, status).is_err() {
                pending = Some(PendingEvent {
                    pid: event.dwProcessId,
                    tid: event.dwThreadId,
                    ip_rewound: true,
                    continue_status: status,
                    rip: 0,
                    kind: PendingKind::SingleStep,
                    resume_prepared: false,
                });
                break;
            }
        }
    }

    let (detached, _) = detach_active_debuggee(&mut engine, &mut pending, &mut create_pending);
    if !detached {
        if let Err(error) = finish_failed_detach(
            &mut engine,
            &mut pending,
            &mut create_pending,
        ) {
            private_dbgk_entry_diag(engine.pid, "cleanup.force.error", error);
        }
    }
}

fn worker(
    app: AppHandle,
    session_id: u64,
    exe_path: PathBuf,
    args: Option<String>,
    working_dir: PathBuf,
    initial_reply: mpsc::Sender<Result<NativeLaunchInfo, String>>,
    commands: mpsc::Receiver<LoopCommand>,
    stage: Arc<AtomicU32>,
    pending_tid: Arc<AtomicU32>,
) {
    let result = worker_inner(
        app,
        exe_path,
        args,
        working_dir,
        initial_reply,
        commands,
        stage.clone(),
        pending_tid.clone(),
    );
    pending_tid.store(0, Ordering::Release);

    // Do not erase a newer session if Windows has already reused this PID.
    if let Some(pid) = result.pid {
        let mut map = sessions().lock();
        if map.get(&pid).is_some_and(|entry| entry.id == session_id) {
            map.remove(&pid);
        }
    }
    // STAGE_ENDED is the authoritative completion fence: all engine resources
    // are gone and this generation is no longer published in the session map.
    stage.store(STAGE_ENDED, Ordering::Release);
}

struct WorkerResult {
    pid: Option<u32>,
}

#[allow(clippy::too_many_arguments)]
fn worker_inner(
    app: AppHandle,
    exe_path: PathBuf,
    args: Option<String>,
    working_dir: PathBuf,
    initial_reply: mpsc::Sender<Result<NativeLaunchInfo, String>>,
    commands: mpsc::Receiver<LoopCommand>,
    stage: Arc<AtomicU32>,
    pending_tid: Arc<AtomicU32>,
) -> WorkerResult {
    let command_line = match args.as_deref().map(str::trim).filter(|value| !value.is_empty()) {
        Some(arguments) => format!("\"{}\" {arguments}", exe_path.display()),
        None => format!("\"{}\"", exe_path.display()),
    };
    let executable_w = wide(exe_path.as_os_str());
    let mut command_line_w = wide(OsStr::new(&command_line));
    let working_dir_w = wide(working_dir.as_os_str());
    let startup = STARTUPINFOW {
        cb: std::mem::size_of::<STARTUPINFOW>() as u32,
        ..Default::default()
    };
    let mut process_info = PROCESS_INFORMATION::default();
    let creation_flags = PROCESS_CREATION_FLAGS(
        DEBUG_ONLY_THIS_PROCESS.0 | CREATE_NEW_CONSOLE.0,
    );

    let create_result = unsafe {
        CreateProcessW(
            PCWSTR(executable_w.as_ptr()),
            PWSTR(command_line_w.as_mut_ptr()),
            None,
            None,
            false,
            creation_flags,
            None,
            PCWSTR(working_dir_w.as_ptr()),
            &startup,
            &mut process_info,
        )
    };
    if let Err(error) = create_result {
        let _ = initial_reply.send(Err(string_error("CreateProcessW", error)));
        return WorkerResult { pid: None };
    }

    let pid = process_info.dwProcessId;
    let primary_tid = process_info.dwThreadId;
    if let Err(error) = unsafe { DebugSetProcessKillOnExit(false) } {
        let _ = initial_reply.send(Err(string_error("DebugSetProcessKillOnExit(FALSE)", error)));
        let mut pending = None;
        let mut create = None;
        let _ = terminate_owned_until_confirmed(
            process_info.hProcess,
            process_info.hThread,
            &mut pending,
            &mut create,
        );
        close_handle(process_info.hThread);
        close_handle(process_info.hProcess);
        return WorkerResult { pid: Some(pid) };
    }

    let create_event = match wait_debug_event(10_000) {
        Ok(Some(event)) if event.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT => event,
        Ok(Some(event)) => {
            let _ = initial_reply.send(Err(format!(
                "expected CREATE_PROCESS_DEBUG_EVENT, received {}",
                event.dwDebugEventCode.0
            )));
            close_rollback_event_handles(
                &event,
                process_info.hProcess,
                process_info.hThread,
            );
            let mut pending = Some(PendingEvent {
                pid: event.dwProcessId,
                tid: event.dwThreadId,
                ip_rewound: true,
                continue_status: DBG_CONTINUE,
                rip: 0,
                kind: PendingKind::SingleStep,
                resume_prepared: false,
            });
            let mut create = None;
            let _ = terminate_owned_until_confirmed(
                process_info.hProcess,
                process_info.hThread,
                &mut pending,
                &mut create,
            );
            close_handle(process_info.hThread);
            close_handle(process_info.hProcess);
            return WorkerResult { pid: Some(pid) };
        }
        Ok(None) => {
            let _ = initial_reply.send(Err("timed out waiting for CREATE_PROCESS_DEBUG_EVENT".into()));
            let mut pending = None;
            let mut create = None;
            let _ = terminate_owned_until_confirmed(
                process_info.hProcess,
                process_info.hThread,
                &mut pending,
                &mut create,
            );
            close_handle(process_info.hThread);
            close_handle(process_info.hProcess);
            return WorkerResult { pid: Some(pid) };
        }
        Err(error) => {
            let _ = initial_reply.send(Err(error));
            let mut pending = None;
            let mut create = None;
            let _ = terminate_owned_until_confirmed(
                process_info.hProcess,
                process_info.hThread,
                &mut pending,
                &mut create,
            );
            close_handle(process_info.hThread);
            close_handle(process_info.hProcess);
            return WorkerResult { pid: Some(pid) };
        }
    };

    let create_info = unsafe { create_event.u.CreateProcessInfo };
    close_handle(create_info.hFile);
    // PROCESS_INFORMATION already owns handles suitable for the entire loop.
    // Close duplicate debug-event handles only when they are genuinely distinct.
    if create_info.hThread != process_info.hThread {
        close_handle(create_info.hThread);
    }
    if create_info.hProcess != process_info.hProcess {
        close_handle(create_info.hProcess);
    }
    // From this point forward the CREATE_PROCESS event has a single explicit
    // local owner. Early rollback either consumes it after requesting
    // termination or retains it; it is never silently forgotten.
    let mut create_pending = Some(create_event);
    let mut no_pending_event = None;

    let image_base = create_info.lpBaseOfImage as usize as u64;
    let entry_address = match remote_entry_address(process_info.hProcess, image_base) {
        Ok(value) => value,
        Err(error) => {
            let _ = initial_reply.send(Err(error));
            let _ = terminate_owned_until_confirmed(
                process_info.hProcess,
                process_info.hThread,
                &mut no_pending_event,
                &mut create_pending,
            );
            close_handle(process_info.hThread);
            close_handle(process_info.hProcess);
            return WorkerResult { pid: Some(pid) };
        }
    };
    let mut breakpoint = match arm_byte_breakpoint(process_info.hProcess, entry_address) {
        Ok(value) => value,
        Err(error) => {
            let _ = initial_reply.send(Err(error));
            // arm_byte_breakpoint may have written 0xCC before a later
            // protection/cache step failed. The launch was never published,
            // so terminate and confirm instead of detaching an uncertain image.
            let _ = terminate_owned_until_confirmed(
                process_info.hProcess,
                process_info.hThread,
                &mut no_pending_event,
                &mut create_pending,
            );
            close_handle(process_info.hThread);
            close_handle(process_info.hProcess);
            return WorkerResult { pid: Some(pid) };
        }
    };
    let wow64 = match target_is_wow64(process_info.hProcess) {
        Ok(value) => value,
        Err(error) => {
            let _ = initial_reply.send(Err(error));
            // Try the ordinary fail-closed detach first. If restoration or
            // Stop fails, no caller owns this unpublished launch, so terminate
            // it and keep the worker until exit is confirmed.
            let (detached, _) = detach_debuggee(
                pid,
                process_info.hProcess,
                &mut breakpoint,
                &mut no_pending_event,
                &mut create_pending,
            );
            if !detached {
                let _ = terminate_owned_until_confirmed(
                    process_info.hProcess,
                    process_info.hThread,
                    &mut no_pending_event,
                    &mut create_pending,
                );
            }
            close_handle(process_info.hThread);
            close_handle(process_info.hProcess);
            return WorkerResult { pid: Some(pid) };
        }
    };

    let launch_info = NativeLaunchInfo {
        pid,
        primary_tid,
        entry_address,
        stopped_at_entry: false,
    };
    if initial_reply.send(Ok(launch_info.clone())).is_err() {
        let (detached, _) = detach_debuggee(
            pid,
            process_info.hProcess,
            &mut breakpoint,
            &mut no_pending_event,
            &mut create_pending,
        );
        if !detached {
            let _ = terminate_owned_until_confirmed(
                process_info.hProcess,
                process_info.hThread,
                &mut no_pending_event,
                &mut create_pending,
            );
        }
        close_handle(process_info.hThread);
        close_handle(process_info.hProcess);
        return WorkerResult { pid: Some(pid) };
    }

    // Start gate: no target instruction runs until the front-end has accepted
    // the launch result, populated its session PID, and explicitly asks to run.
    let run_reply = loop {
        match commands.recv() {
            Ok(LoopCommand::RunToEntry(reply)) => {
                let Some(event) = create_pending.as_ref() else {
                    let _ = reply.send(Err(
                        "native CREATE_PROCESS event was already consumed".into(),
                    ));
                    stage.store(STAGE_DETACH_RETRY, Ordering::Release);
                    break None;
                };
                if let Err(error) = continue_event(event, DBG_CONTINUE) {
                    let _ = reply.send(Err(error));
                    continue;
                }
                create_pending = None;
                stage.store(STAGE_RUNNING_TO_ENTRY, Ordering::Release);
                break Some(reply);
            }
            Ok(LoopCommand::ContinueEntry { reply, .. }) => {
                let _ = reply.send(Err("native target is still at the launch gate".into()));
            }
            Ok(LoopCommand::ContinueInitialSystemBreakpoint { reply, .. }) => {
                let _ = reply.send(Err("native launch has no pending attached-system breakpoint".into()));
            }
            Ok(LoopCommand::ActivateAttach(reply)) => {
                let _ = reply.send(Err("launch session cannot activate as an attached session".into()));
            }
            Ok(LoopCommand::StepInto { reply, .. }) => {
                let _ = reply.send(Err("native target is still at the launch gate".into()));
            }
            Ok(LoopCommand::StepIntoVt { reply, .. }) => {
                let _ = reply.send(Err("native target is still at the launch gate".into()));
            }
            Ok(LoopCommand::CancelVtStep { reply, .. }) => {
                let _ = reply.send(Ok(()));
            }
            Ok(LoopCommand::StepOver { reply, .. }) => {
                let _ = reply.send(Err("native target is still at the launch gate".into()));
            }
            Ok(LoopCommand::StepOut { reply, .. }) => {
                let _ = reply.send(Err("native target is still at the launch gate".into()));
            }
            Ok(LoopCommand::CancelStepOver { reply, .. }) => {
                let _ = reply.send(Ok(false));
            }
            Ok(LoopCommand::SetSoftware { reply, .. }) => {
                let _ = reply.send(Err("software breakpoints require the active native event loop".into()));
            }
            Ok(LoopCommand::ClearSoftware { reply, .. }) => {
                let _ = reply.send(Err("software breakpoints require the active native event loop".into()));
            }
            Ok(LoopCommand::ListSoftware(reply)) => {
                let _ = reply.send(Vec::new());
            }
            Ok(LoopCommand::SetHardware { reply, .. }) => {
                let _ = reply.send(Err("hardware breakpoints require the active native event loop".into()));
            }
            Ok(LoopCommand::ClearHardware { reply, .. }) => {
                let _ = reply.send(Err("hardware breakpoints require the active native event loop".into()));
            }
            Ok(LoopCommand::ListHardware(reply)) => {
                let _ = reply.send(Vec::new());
            }
            Ok(LoopCommand::Detach(reply)) => {
                let (detached, result) = detach_debuggee(
                    pid,
                    process_info.hProcess,
                    &mut breakpoint,
                    &mut no_pending_event,
                    &mut create_pending,
                );
                let _ = reply.send(result);
                if detached {
                    close_handle(process_info.hThread);
                    close_handle(process_info.hProcess);
                    return WorkerResult { pid: Some(pid) };
                }
                if create_pending.is_none() {
                    // The create event was successfully continued, so the
                    // process is live even though Stop failed. Leave the gate
                    // and keep pumping events; future detach retries are
                    // Stop-only (plus any still-needed byte restoration).
                    stage.store(STAGE_DETACH_RETRY, Ordering::Release);
                    break None;
                }
            }
            Ok(LoopCommand::Abandon(reply)) => {
                let result = abandon_debuggee(
                    pid,
                    process_info.hProcess,
                    process_info.hThread,
                    &mut breakpoint,
                    &mut no_pending_event,
                    &mut create_pending,
                );
                close_handle(process_info.hThread);
                close_handle(process_info.hProcess);
                let _ = reply.send(result);
                return WorkerResult { pid: Some(pid) };
            }
            Err(_) => {
                let (detached, _) = detach_debuggee(
                    pid,
                    process_info.hProcess,
                    &mut breakpoint,
                    &mut no_pending_event,
                    &mut create_pending,
                );
                if !detached {
                    let _ = terminate_owned_until_confirmed(
                        process_info.hProcess,
                        process_info.hThread,
                        &mut no_pending_event,
                        &mut create_pending,
                    );
                }
                close_handle(process_info.hThread);
                close_handle(process_info.hProcess);
                return WorkerResult { pid: Some(pid) };
            }
        }
    };

    #[cfg(any())]
    {
    let mut saw_system_breakpoint = false;
    let mut entry_pending: Option<PendingEvent> = None;
    loop {
        if entry_pending.is_some() {
            match commands.recv() {
                Ok(LoopCommand::ContinueEntry { tid, reply }) => {
                    let pending = entry_pending.as_mut().unwrap();
                    if tid != pending.tid {
                        let _ = reply.send(Err(format!(
                            "native entry event belongs to TID {}, not TID {tid}",
                            pending.tid
                        )));
                        continue;
                    }
                    if !pending.ip_rewound {
                        let rewind = restore_entry_breakpoint(
                            process_info.hProcess,
                            &mut breakpoint,
                        )
                        .and_then(|_| {
                            with_event_thread(
                                process_info.hThread,
                                primary_tid,
                                pending.tid,
                                |thread| rewind_instruction_pointer(thread, wow64, entry_address),
                            )
                        });
                        if let Err(error) = rewind {
                            let _ = reply.send(Err(format!(
                                "native entry context is not safe to continue: {error}"
                            )));
                            continue;
                        }
                        pending.ip_rewound = true;
                    }
                    let result = unsafe { ContinueDebugEvent(pending.pid, pending.tid, DBG_CONTINUE) }
                        .map_err(|error| string_error("ContinueDebugEvent(entry)", error));
                    if result.is_ok() {
                        entry_pending = None;
                        pending_tid.store(0, Ordering::Release);
                        stage.store(STAGE_ENTRY_CONTINUED, Ordering::Release);
                    }
                    let _ = reply.send(result);
                }
                Ok(LoopCommand::RunToEntry(reply)) => {
                    let _ = reply.send(Ok(NativeLaunchInfo {
                        pid,
                        primary_tid,
                        entry_address,
                        stopped_at_entry: true,
                    }));
                }
                Ok(LoopCommand::Detach(reply)) => {
                    if let Some(pending) = entry_pending.as_mut() {
                        if !pending.ip_rewound {
                            match with_event_thread(
                                process_info.hThread,
                                primary_tid,
                                pending.tid,
                                |thread| rewind_instruction_pointer(thread, wow64, entry_address),
                            ) {
                                Ok(()) => pending.ip_rewound = true,
                                Err(error) => {
                                    let _ = reply.send(Err(format!(
                                        "cannot safely detach at native entry: {error}"
                                    )));
                                    continue;
                                }
                            }
                        }
                    }
                    stage.store(STAGE_DETACH_RETRY, Ordering::Release);
                    let (detached, result) = detach_debuggee(
                        pid,
                        process_info.hProcess,
                        &mut breakpoint,
                        &mut entry_pending,
                        &mut create_pending,
                    );
                    if entry_pending.is_none() {
                        pending_tid.store(0, Ordering::Release);
                    }
                    let _ = reply.send(result);
                    if detached {
                        if let Some(waiter) = run_reply.take() {
                            let _ = waiter.send(Err(
                                "native run-to-entry was cancelled by detach".into(),
                            ));
                        }
                        close_handle(process_info.hThread);
                        close_handle(process_info.hProcess);
                        return WorkerResult { pid: Some(pid) };
                    }
                }
                Ok(LoopCommand::Abandon(reply)) => {
                    let result = abandon_debuggee(
                        pid,
                        process_info.hProcess,
                        process_info.hThread,
                        &mut breakpoint,
                        &mut entry_pending,
                        &mut create_pending,
                    );
                    pending_tid.store(0, Ordering::Release);
                    close_handle(process_info.hThread);
                    close_handle(process_info.hProcess);
                    let _ = reply.send(result);
                    return WorkerResult { pid: Some(pid) };
                }
                Err(_) => {
                    let (detached, _) = detach_debuggee(
                        pid,
                        process_info.hProcess,
                        &mut breakpoint,
                        &mut entry_pending,
                        &mut create_pending,
                    );
                    if !detached {
                        let _ = terminate_owned_until_confirmed(
                            process_info.hProcess,
                            process_info.hThread,
                            &mut entry_pending,
                            &mut create_pending,
                        );
                    }
                    close_handle(process_info.hThread);
                    close_handle(process_info.hProcess);
                    return WorkerResult { pid: Some(pid) };
                }
            }
            continue;
        }

        loop {
            let command = match commands.try_recv() {
                Ok(command) => command,
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => {
                    let (detached, _) = detach_debuggee(
                        pid,
                        process_info.hProcess,
                        &mut breakpoint,
                        &mut entry_pending,
                        &mut create_pending,
                    );
                    if !detached {
                        let _ = terminate_owned_until_confirmed(
                            process_info.hProcess,
                            process_info.hThread,
                            &mut entry_pending,
                            &mut create_pending,
                        );
                    }
                    close_handle(process_info.hThread);
                    close_handle(process_info.hProcess);
                    return WorkerResult { pid: Some(pid) };
                }
            };
            match command {
                LoopCommand::RunToEntry(reply) => {
                    if stage.load(Ordering::Acquire) == STAGE_RUNNING_TO_ENTRY {
                        let _ = reply.send(Err("native target is already running to its entry point".into()));
                    } else {
                        let _ = reply.send(Err("native entry event has already been continued".into()));
                    }
                }
                LoopCommand::ContinueEntry { reply, .. } => {
                    let _ = reply.send(Err("there is no pending native entry event".into()));
                }
                LoopCommand::Detach(reply) => {
                    stage.store(STAGE_DETACH_RETRY, Ordering::Release);
                    if let Some(waiter) = run_reply.take() {
                        let _ = waiter.send(Err(
                            "native run-to-entry was cancelled by detach".into(),
                        ));
                    }
                    let (detached, result) = detach_debuggee(
                        pid,
                        process_info.hProcess,
                        &mut breakpoint,
                        &mut entry_pending,
                        &mut create_pending,
                    );
                    let _ = reply.send(result);
                    if detached {
                        close_handle(process_info.hThread);
                        close_handle(process_info.hProcess);
                        return WorkerResult { pid: Some(pid) };
                    }
                }
                LoopCommand::Abandon(reply) => {
                    if let Some(waiter) = run_reply.take() {
                        let _ = waiter.send(Err(
                            "native run-to-entry was abandoned before delivery".into(),
                        ));
                    }
                    let result = abandon_debuggee(
                        pid,
                        process_info.hProcess,
                        process_info.hThread,
                        &mut breakpoint,
                        &mut entry_pending,
                        &mut create_pending,
                    );
                    pending_tid.store(0, Ordering::Release);
                    close_handle(process_info.hThread);
                    close_handle(process_info.hProcess);
                    let _ = reply.send(result);
                    return WorkerResult { pid: Some(pid) };
                }
            }
        }

        let event = match wait_debug_event(EVENT_POLL_MS) {
            Ok(Some(value)) => value,
            Ok(None) => continue,
            Err(error) => {
                if let Some(reply) = run_reply.take() {
                    let _ = reply.send(Err(error));
                }
                break;
            }
        };

        close_debug_event_handle(&event);
        if event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT {
            if continue_event(&event, DBG_CONTINUE).is_err() {
                entry_pending = Some(PendingEvent {
                    pid: event.dwProcessId,
                    tid: event.dwThreadId,
                    ip_rewound: true,
                    continue_status: DBG_CONTINUE,
                });
            }
            if let Some(reply) = run_reply.take() {
                let _ = reply.send(Err("target exited before reaching its PE entry point".into()));
            }
            break;
        }

        let mut status = DBG_CONTINUE;
        let mut hold_event = false;
        if event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT {
            let exception = unsafe { event.u.Exception };
            let code = exception.ExceptionRecord.ExceptionCode;
            let address = exception.ExceptionRecord.ExceptionAddress as usize as u64;
            if code == EXCEPTION_BREAKPOINT && address == entry_address {
                let restore = restore_entry_breakpoint(process_info.hProcess, &mut breakpoint);
                let rewind = restore.and_then(|_| {
                    with_event_thread(
                        process_info.hThread,
                        primary_tid,
                        event.dwThreadId,
                        |thread| rewind_instruction_pointer(thread, wow64, entry_address),
                    )
                });
                match rewind {
                    Ok(()) => {
                        pending_tid.store(event.dwThreadId, Ordering::Release);
                        stage.store(STAGE_ENTRY_PENDING, Ordering::Release);
                        entry_pending = Some(PendingEvent {
                            pid: event.dwProcessId,
                            tid: event.dwThreadId,
                            ip_rewound: true,
                            continue_status: DBG_CONTINUE,
                        });
                        let stopped = NativeLaunchInfo {
                            pid,
                            primary_tid,
                            entry_address,
                            stopped_at_entry: true,
                        };
                        if let Some(reply) = run_reply.take() {
                            let _ = reply.send(Ok(stopped));
                        }
                        let _ = app.emit(
                            "dbg-native-hit",
                            NativeHit {
                                sequence: HIT_SEQUENCE.fetch_add(1, Ordering::Relaxed),
                                pid,
                                tid: event.dwThreadId,
                                rip: entry_address,
                                kind: 1,
                            },
                        );
                        hold_event = true;
                    }
                    Err(error) => {
                        if let Some(reply) = run_reply.take() {
                            let _ = reply.send(Err(format!(
                                "entry breakpoint hit but could not restore execution state: {error}"
                            )));
                        }
                        // Fail closed: the exception remains pending. Detach can
                        // retry restoration instead of executing at entry+1.
                        entry_pending = Some(PendingEvent {
                            pid: event.dwProcessId,
                            tid: event.dwThreadId,
                            ip_rewound: false,
                            continue_status: DBG_CONTINUE,
                        });
                        pending_tid.store(event.dwThreadId, Ordering::Release);
                        stage.store(STAGE_ENTRY_PENDING, Ordering::Release);
                        hold_event = true;
                    }
                }
            } else if code == EXCEPTION_BREAKPOINT && !saw_system_breakpoint {
                // Windows' loader-generated initial breakpoint is debugger
                // bookkeeping, not an application exception.
                saw_system_breakpoint = true;
                status = DBG_CONTINUE;
            } else {
                // Never swallow application exceptions. Give both first- and
                // second-chance faults back to the target/OS.
                status = DBG_EXCEPTION_NOT_HANDLED;
            }
        }

        if !hold_event {
            if let Err(error) = continue_event(&event, status) {
                if let Some(reply) = run_reply.take() {
                    let _ = reply.send(Err(error));
                }
                entry_pending = Some(PendingEvent {
                    pid: event.dwProcessId,
                    tid: event.dwThreadId,
                    ip_rewound: true,
                    continue_status: status,
                });
                break;
            }
        }
    }

    // Every abnormal event-loop exit explicitly relinquishes the DebugObject.
    // DebugSetProcessKillOnExit(FALSE) prevents target termination, but it does
    // not replace restoring our byte or continuing an event that failed once.
    let (detached, _) = detach_debuggee(
        pid,
        process_info.hProcess,
        &mut breakpoint,
        &mut entry_pending,
        &mut create_pending,
    );
    if !detached {
        let _ = terminate_owned_until_confirmed(
            process_info.hProcess,
            process_info.hThread,
            &mut entry_pending,
            &mut create_pending,
        );
    }
    close_handle(process_info.hThread);
    close_handle(process_info.hProcess);
    WorkerResult { pid: Some(pid) }
    }

    let engine = NativeEngine {
        app,
        pid,
        process: process_info.hProcess,
        primary_thread: process_info.hThread,
        primary_tid,
        wow64,
        terminate_on_cleanup: true,
        entry: Some(breakpoint),
        software: HashMap::new(),
        transient: HashMap::new(),
        step_over_targets: HashMap::new(),
        hardware: [None; 4],
        original_dr: HashMap::new(),
        rearm_steps: HashMap::new(),
        tf_steps: HashSet::new(),
        vt_steps: HashSet::new(),
        private_vt_step_intents: None,
    };
    active_event_loop(
        engine,
        &commands,
        None,
        create_pending,
        run_reply,
        &stage,
        &pending_tid,
        None,
    );
    close_handle(process_info.hThread);
    close_handle(process_info.hProcess);
    WorkerResult { pid: Some(pid) }
}

fn attached_worker(
    app: AppHandle,
    session_id: u64,
    pid: u32,
    initial_reply: mpsc::Sender<Result<NativeLaunchInfo, String>>,
    commands: mpsc::Receiver<LoopCommand>,
    stage: Arc<AtomicU32>,
    pending_tid: Arc<AtomicU32>,
    control_plane: AttachedControlPlane,
    initial_system_breakpoint: Arc<InitialSystemBreakpointState>,
    private_vt_step_intents: Option<Arc<Mutex<HashSet<u32>>>>,
) {
    private_dbgk_entry_diag(
        pid,
        "attach.worker.begin",
        format!("session_id={session_id} control_plane={}", control_plane.name()),
    );
    attached_worker_inner(
        app,
        pid,
        initial_reply,
        commands,
        stage.clone(),
        pending_tid.clone(),
        control_plane,
        initial_system_breakpoint.clone(),
        private_vt_step_intents,
    );
    pending_tid.store(0, Ordering::Release);
    initial_system_breakpoint.clear();
    let mut map = sessions().lock();
    if map.get(&pid).is_some_and(|entry| entry.id == session_id) {
        map.remove(&pid);
    }
    drop(map);
    private_dbgk_entry_diag(pid, "attach.worker.end", format!("session_id={session_id}"));
    // The detach caller may start a replacement only after this store.  The
    // private DebugObject, target binding and process/thread handles were all
    // released before attached_worker_inner returned.
    stage.store(STAGE_ENDED, Ordering::Release);
}

fn attached_worker_inner(
    app: AppHandle,
    pid: u32,
    initial_reply: mpsc::Sender<Result<NativeLaunchInfo, String>>,
    commands: mpsc::Receiver<LoopCommand>,
    stage: Arc<AtomicU32>,
    pending_tid: Arc<AtomicU32>,
    control_plane: AttachedControlPlane,
    initial_system_breakpoint: Arc<InitialSystemBreakpointState>,
    private_vt_step_intents: Option<Arc<Mutex<HashSet<u32>>>>,
) {
    private_dbgk_entry_diag(
        pid,
        "attach.begin",
        format!("control_plane={}", control_plane.name()),
    );
    let _control_plane_guards = match prepare_attached_control_plane(
        &app,
        pid,
        control_plane,
    ) {
        Ok(guards) => {
            private_dbgk_entry_diag(pid, "attach.control_plane", "ready");
            guards
        }
        Err(error) => {
            private_dbgk_entry_diag(pid, "attach.control_plane.error", error.to_string());
            let _ = initial_reply.send(Err(error.to_string()));
            return;
        }
    };
    let hold_initial_system_breakpoint =
        control_plane.holds_initial_system_breakpoint();
    let access = PROCESS_QUERY_INFORMATION
        | PROCESS_SYNCHRONIZE
        | PROCESS_TERMINATE
        | PROCESS_VM_OPERATION
        | PROCESS_VM_READ
        | PROCESS_VM_WRITE;
    let process = match unsafe { OpenProcess(access, false, pid) } {
        Ok(handle) => {
            private_dbgk_entry_diag(
                pid,
                "attach.open_process",
                format!("handle={:p} access=0x{:X}", handle.0, access.0),
            );
            handle
        }
        Err(error) => {
            private_dbgk_entry_diag(pid, "attach.open_process.error", error.to_string());
            let _ = initial_reply.send(Err(string_error(&format!("OpenProcess({pid})"), error)));
            return;
        }
    };
    private_dbgk_entry_diag(pid, "attach.debug_active_process", "begin");
    if let Err(error) = unsafe { DebugActiveProcess(pid) } {
        private_dbgk_entry_diag(pid, "attach.debug_active_process.error", error.to_string());
        let _ = initial_reply.send(Err(string_error(&format!("DebugActiveProcess({pid})"), error)));
        close_handle(process);
        return;
    }
    private_dbgk_entry_diag(pid, "attach.debug_active_process", "ok");
    if let Err(error) = unsafe { DebugSetProcessKillOnExit(false) } {
        private_dbgk_entry_diag(pid, "attach.kill_on_exit.error", error.to_string());
        let _ = initial_reply.send(Err(string_error("DebugSetProcessKillOnExit(FALSE)", error)));
        let _ = unsafe { DebugActiveProcessStop(pid) };
        close_handle(process);
        return;
    }
    private_dbgk_entry_diag(pid, "attach.kill_on_exit", "disabled");

    let create_event = match wait_debug_event(10_000) {
        Ok(Some(event)) if event.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT => {
            private_dbgk_entry_diag(pid, "attach.create_event", debug_event_diagnostic(&event));
            event
        }
        Ok(Some(event)) => {
            private_dbgk_entry_diag(
                pid,
                "attach.create_event.unexpected",
                debug_event_diagnostic(&event),
            );
            let _ = initial_reply.send(Err(format!(
                "expected attached CREATE_PROCESS_DEBUG_EVENT, received {}",
                event.dwDebugEventCode.0
            )));
            close_debug_event_handle(&event);
            let _ = continue_event(&event, DBG_CONTINUE);
            let _ = unsafe { DebugActiveProcessStop(pid) };
            close_handle(process);
            return;
        }
        Ok(None) => {
            private_dbgk_entry_diag(pid, "attach.create_event.timeout", "timeout_ms=10000");
            let _ = initial_reply.send(Err("timed out waiting for attached CREATE_PROCESS event".into()));
            let _ = unsafe { DebugActiveProcessStop(pid) };
            close_handle(process);
            return;
        }
        Err(error) => {
            private_dbgk_entry_diag(pid, "attach.create_event.error", &error);
            let _ = initial_reply.send(Err(error));
            let _ = unsafe { DebugActiveProcessStop(pid) };
            close_handle(process);
            return;
        }
    };
    let create_info = unsafe { create_event.u.CreateProcessInfo };
    close_handle(create_info.hFile);
    if create_info.hProcess != process {
        close_handle(create_info.hProcess);
    }
    let primary_tid = create_event.dwThreadId;
    let primary_thread = match unsafe {
        OpenThread(
            THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME,
            false,
            primary_tid,
        )
    } {
        Ok(handle) => {
            private_dbgk_entry_diag(
                pid,
                "attach.open_primary_thread",
                format!("tid={primary_tid} handle={:p}", handle.0),
            );
            handle
        }
        Err(error) => {
            private_dbgk_entry_diag(
                pid,
                "attach.open_primary_thread.error",
                format!("tid={primary_tid} error={error}"),
            );
            close_handle(create_info.hThread);
            let _ = initial_reply.send(Err(string_error(
                &format!("OpenThread({primary_tid})"),
                error,
            )));
            let _ = continue_event(&create_event, DBG_CONTINUE);
            let _ = unsafe { DebugActiveProcessStop(pid) };
            close_handle(process);
            return;
        }
    };
    if create_info.hThread != primary_thread {
        close_handle(create_info.hThread);
    }

    let wow64 = match target_is_wow64(process) {
        Ok(value) => value,
        Err(error) => {
            let _ = initial_reply.send(Err(error));
            let _ = continue_event(&create_event, DBG_CONTINUE);
            let _ = unsafe { DebugActiveProcessStop(pid) };
            close_handle(primary_thread);
            close_handle(process);
            return;
        }
    };
    let image_base = create_info.lpBaseOfImage as usize as u64;
    let entry_address = remote_entry_address(process, image_base).unwrap_or(0);
    private_dbgk_entry_diag(
        pid,
        "attach.runtime_image",
        format!(
            "primary_tid={primary_tid} wow64={wow64} image_base=0x{image_base:X} entry=0x{entry_address:X}"
        ),
    );
    let launch = NativeLaunchInfo {
        pid,
        primary_tid,
        entry_address,
        stopped_at_entry: false,
    };
    if initial_reply.send(Ok(launch)).is_err() {
        let _ = continue_event(&create_event, DBG_CONTINUE);
        let _ = unsafe { DebugActiveProcessStop(pid) };
        close_handle(primary_thread);
        close_handle(process);
        return;
    }

    let mut create_pending = Some(create_event);
    loop {
        match commands.recv() {
            Ok(LoopCommand::ActivateAttach(reply)) => {
                private_dbgk_entry_diag(pid, "attach.activate", "continue CREATE_PROCESS event");
                let result = create_pending
                    .as_ref()
                    .ok_or_else(|| "attached CREATE_PROCESS event was already consumed".to_string())
                    .and_then(|event| continue_event(event, DBG_CONTINUE));
                if result.is_ok() {
                    create_pending = None;
                    stage.store(
                        if hold_initial_system_breakpoint {
                            STAGE_WAITING_INITIAL_SYSTEM_BREAKPOINT
                        } else {
                            STAGE_ENTRY_CONTINUED
                        },
                        Ordering::Release,
                    );
                }
                let ok = result.is_ok();
                private_dbgk_entry_diag(
                    pid,
                    "attach.activate.result",
                    match &result {
                        Ok(()) => format!(
                            "ok next_stage={}",
                            if hold_initial_system_breakpoint {
                                STAGE_WAITING_INITIAL_SYSTEM_BREAKPOINT
                            } else {
                                STAGE_ENTRY_CONTINUED
                            }
                        ),
                        Err(error) => format!("error={error}"),
                    },
                );
                let _ = reply.send(result);
                if ok {
                    break;
                }
            }
            Ok(LoopCommand::Detach(reply)) => {
                let mut engine = NativeEngine {
                    app: app.clone(),
                    pid,
                    process,
                    primary_thread,
                    primary_tid,
                    wow64,
                    terminate_on_cleanup: false,
                    entry: None,
                    software: HashMap::new(),
                    transient: HashMap::new(),
                    step_over_targets: HashMap::new(),
                    hardware: [None; 4],
                    original_dr: HashMap::new(),
                    rearm_steps: HashMap::new(),
                    tf_steps: HashSet::new(),
                    vt_steps: HashSet::new(),
                    private_vt_step_intents: private_vt_step_intents.clone(),
                };
                let mut no_pending = None;
                let (detached, result) = detach_active_debuggee(
                    &mut engine,
                    &mut no_pending,
                    &mut create_pending,
                );
                let _ = reply.send(result);
                if detached {
                    close_handle(primary_thread);
                    close_handle(process);
                    return;
                }
            }
            Ok(LoopCommand::Abandon(reply)) => {
                let mut engine = NativeEngine {
                    app: app.clone(),
                    pid,
                    process,
                    primary_thread,
                    primary_tid,
                    wow64,
                    terminate_on_cleanup: false,
                    entry: None,
                    software: HashMap::new(),
                    transient: HashMap::new(),
                    step_over_targets: HashMap::new(),
                    hardware: [None; 4],
                    original_dr: HashMap::new(),
                    rearm_steps: HashMap::new(),
                    tf_steps: HashSet::new(),
                    vt_steps: HashSet::new(),
                    private_vt_step_intents: private_vt_step_intents.clone(),
                };
                let mut no_pending = None;
                let (detached, _) = detach_active_debuggee(
                    &mut engine,
                    &mut no_pending,
                    &mut create_pending,
                );
                let result = if detached {
                    Ok(())
                } else {
                    finish_failed_detach(
                        &mut engine,
                        &mut no_pending,
                        &mut create_pending,
                    )
                };
                let completed = result.is_ok();
                let _ = reply.send(result);
                if completed {
                    close_handle(primary_thread);
                    close_handle(process);
                    return;
                }
            }
            Ok(LoopCommand::RunToEntry(reply)) => {
                let _ = reply.send(Err("run-to-entry is only available for a native launch".into()));
            }
            Ok(LoopCommand::ContinueEntry { reply, .. }) => {
                let _ = reply.send(Err("attached target is still at its activation gate".into()));
            }
            Ok(LoopCommand::ContinueInitialSystemBreakpoint { reply, .. }) => {
                let _ = reply.send(Err("attached target is still at its activation gate".into()));
            }
            Ok(LoopCommand::StepInto { reply, .. }) => {
                let _ = reply.send(Err("attached target is still at its activation gate".into()));
            }
            Ok(LoopCommand::StepIntoVt { reply, .. }) => {
                let _ = reply.send(Err("attached target is still at its activation gate".into()));
            }
            Ok(LoopCommand::CancelVtStep { reply, .. }) => {
                let _ = reply.send(Ok(()));
            }
            Ok(LoopCommand::StepOver { reply, .. }) => {
                let _ = reply.send(Err("attached target is still at its activation gate".into()));
            }
            Ok(LoopCommand::StepOut { reply, .. }) => {
                let _ = reply.send(Err("attached target is still at its activation gate".into()));
            }
            Ok(LoopCommand::CancelStepOver { reply, .. }) => {
                let _ = reply.send(Ok(false));
            }
            Ok(LoopCommand::SetSoftware { reply, .. }) => {
                let _ = reply.send(Err("attached target is still at its activation gate".into()));
            }
            Ok(LoopCommand::ClearSoftware { reply, .. }) => {
                let _ = reply.send(Err("attached target is still at its activation gate".into()));
            }
            Ok(LoopCommand::ListSoftware(reply)) => {
                let _ = reply.send(Vec::new());
            }
            Ok(LoopCommand::SetHardware { reply, .. }) => {
                let _ = reply.send(Err("attached target is still at its activation gate".into()));
            }
            Ok(LoopCommand::ClearHardware { reply, .. }) => {
                let _ = reply.send(Err("attached target is still at its activation gate".into()));
            }
            Ok(LoopCommand::ListHardware(reply)) => {
                let _ = reply.send(Vec::new());
            }
            Err(_) => {
                let _ = continue_event(create_pending.as_ref().unwrap(), DBG_CONTINUE);
                let _ = unsafe { DebugActiveProcessStop(pid) };
                close_handle(primary_thread);
                close_handle(process);
                return;
            }
        }
    }

    let engine = NativeEngine {
        app,
        pid,
        process,
        primary_thread,
        primary_tid,
        wow64,
        terminate_on_cleanup: false,
        entry: None,
        software: HashMap::new(),
        transient: HashMap::new(),
        step_over_targets: HashMap::new(),
        hardware: [None; 4],
        original_dr: HashMap::new(),
        rearm_steps: HashMap::new(),
        tf_steps: HashSet::new(),
        vt_steps: HashSet::new(),
        private_vt_step_intents,
    };
    private_dbgk_entry_diag(pid, "attach.event_loop", "begin");
    active_event_loop(
        engine,
        &commands,
        None,
        create_pending,
        None,
        &stage,
        &pending_tid,
        hold_initial_system_breakpoint.then_some(initial_system_breakpoint.as_ref()),
    );
    private_dbgk_entry_diag(pid, "attach.event_loop", "end");
    close_handle(primary_thread);
    close_handle(process);
}

/// Return whether a DebugObject worker already owns this PID. The worker is
/// mode-neutral and may serve either a native session or the Windows control
/// plane of a VT session.
pub fn is_session(pid: u32) -> bool {
    sessions().lock().contains_key(&pid)
}

pub fn is_private_dbgk_session(pid: u32) -> bool {
    sessions()
        .lock()
        .get(&pid)
        .is_some_and(|control| control.control_plane.uses_private_dbgk())
}

/// The VT attach worker establishes the Bridge binding before DebugActiveProcess
/// so the target cannot run between control-plane selection and protection.
/// Once published, that worker remains the sole binding owner until teardown.
pub fn owns_vt_target_binding(pid: u32) -> bool {
    sessions()
        .lock()
        .get(&pid)
        .is_some_and(|control| !matches!(control.control_plane, AttachedControlPlane::Native))
}

/// Return whether this worker currently owns the thread's suspended
/// `DEBUG_EVENT`. VT-private stops have no pending Windows event and therefore
/// return false even though the same worker remains attached to the process.
pub fn owns_pending_event(pid: u32, tid: u32) -> bool {
    sessions()
        .lock()
        .get(&pid)
        .is_some_and(|control| control.pending_tid.load(Ordering::Acquire) == tid)
}

fn initial_system_breakpoint_tid(control: &NativeSessionControl) -> Option<u32> {
    if !control.control_plane.holds_initial_system_breakpoint()
        || control.stage.load(Ordering::Acquire) != STAGE_ENTRY_PENDING
    {
        return None;
    }
    let tid = control
        .initial_system_breakpoint
        .pending_tid
        .load(Ordering::Acquire);
    (tid != 0 && control.pending_tid.load(Ordering::Acquire) == tid).then_some(tid)
}

/// Query the loader-generated breakpoint held as the VT launch synchronization
/// gate. `None` also means that this session was not attached in VT-launch mode.
pub fn pending_initial_system_breakpoint_tid(pid: u32) -> Option<u32> {
    sessions()
        .lock()
        .get(&pid)
        .and_then(initial_system_breakpoint_tid)
}

/// Wait until the attached process reaches its loader-generated initial
/// breakpoint. This wait never resumes the event or reads/writes thread state.
pub fn wait_for_initial_system_breakpoint(
    pid: u32,
    timeout: Duration,
) -> AppResult<u32> {
    let control = sessions()
        .lock()
        .get(&pid)
        .cloned()
        .ok_or_else(|| AppError::Internal(format!("no native debug session for PID {pid}")))?;
    if !control.control_plane.holds_initial_system_breakpoint() {
        return Err(AppError::Internal(format!(
            "native debug session for PID {pid} is not configured to hold its initial system breakpoint"
        )));
    }

    let deadline = Instant::now() + timeout;
    let mut changed_guard = control.initial_system_breakpoint.changed_lock.lock();
    loop {
        if let Some(tid) = initial_system_breakpoint_tid(&control) {
            return Ok(tid);
        }
        match control.stage.load(Ordering::Acquire) {
            STAGE_CREATE_EVENT_GATED | STAGE_WAITING_INITIAL_SYSTEM_BREAKPOINT => {}
            STAGE_ENTRY_PENDING => {}
            STAGE_ENTRY_CONTINUED => {
                return Err(AppError::Internal(format!(
                    "PID {pid} initial system breakpoint was already continued"
                )))
            }
            STAGE_DETACH_RETRY => {
                return Err(AppError::Internal(format!(
                    "PID {pid} is detaching before its initial system breakpoint"
                )))
            }
            STAGE_ENDED => {
                return Err(AppError::Internal(format!(
                    "PID {pid} ended before its initial system breakpoint"
                )))
            }
            stage => {
                return Err(AppError::Internal(format!(
                    "PID {pid} has invalid initial-system-breakpoint stage {stage}"
                )))
            }
        }

        let now = Instant::now();
        if now >= deadline {
            return Err(AppError::Internal(format!(
                "timed out waiting for PID {pid} initial system breakpoint"
            )));
        }
        let remaining = deadline.saturating_duration_since(now);
        control.initial_system_breakpoint.changed.wait_for(
            &mut changed_guard,
            remaining.min(Duration::from_millis(EVENT_POLL_MS as u64)),
        );
    }
}

/// Continue only the hidden loader-generated breakpoint held for a VT launch.
/// The worker uses `DBG_CONTINUE` directly and does not rewind or edit RIP.
pub fn continue_initial_system_breakpoint(pid: u32, tid: u32) -> AppResult<()> {
    let control = sessions()
        .lock()
        .get(&pid)
        .cloned()
        .ok_or_else(|| AppError::Internal(format!("no native debug session for PID {pid}")))?;
    if !control.control_plane.holds_initial_system_breakpoint() {
        return Err(AppError::Internal(format!(
            "native debug session for PID {pid} has no initial-system-breakpoint gate"
        )));
    }
    let (reply_tx, reply_rx) = mpsc::channel();
    control
        .tx
        .send(LoopCommand::ContinueInitialSystemBreakpoint {
            tid,
            reply: reply_tx,
        })
        .map_err(|error| app_error("continue initial system breakpoint", error))?;
    reply_rx
        .recv_timeout(CONTROL_TIMEOUT)
        .map_err(|error| app_error("wait for initial system breakpoint continue", error))?
        .map_err(AppError::Internal)
}

fn attach_process_inner(
    app: AppHandle,
    pid: u32,
    control_plane: AttachedControlPlane,
) -> AppResult<NativeLaunchInfo> {
    if let Some(control) = sessions().lock().get(&pid).cloned() {
        let current_stage = control.stage.load(Ordering::Acquire);
        if control.control_plane != control_plane {
            return Err(AppError::Internal(format!(
                "PID {pid} already uses {}; requested {}",
                control.control_plane.name(),
                control_plane.name(),
            )));
        }
        if control_plane.holds_initial_system_breakpoint()
            && !matches!(
                current_stage,
                STAGE_CREATE_EVENT_GATED
                    | STAGE_WAITING_INITIAL_SYSTEM_BREAKPOINT
                    | STAGE_ENTRY_PENDING
            )
        {
            return Err(AppError::Internal(format!(
                "Windows DebugObject session for PID {pid} passed its initial-system-breakpoint gate before attach"
            )));
        }
        if control_plane.holds_private_launch_gate()
            && current_stage != STAGE_CREATE_EVENT_GATED
        {
            return Err(AppError::Internal(format!(
                "private Dbgk launch session for PID {pid} passed its CREATE_PROCESS gate before launch setup"
            )));
        }
        return Ok(NativeLaunchInfo {
            pid,
            primary_tid: control.primary_tid,
            entry_address: control.entry_address,
            stopped_at_entry: current_stage == STAGE_ENTRY_PENDING,
        });
    }

    let id = SESSION_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let stage = Arc::new(AtomicU32::new(STAGE_CREATE_EVENT_GATED));
    let pending_tid = Arc::new(AtomicU32::new(0));
    let initial_system_breakpoint = Arc::new(InitialSystemBreakpointState::new());
    let (initial_tx, initial_rx) = mpsc::channel();
    let (command_tx, command_rx) = mpsc::channel();
    let worker_stage = stage.clone();
    let worker_pending_tid = pending_tid.clone();
    let worker_initial_system_breakpoint = initial_system_breakpoint.clone();
    let private_vt_step_intents = control_plane
        .uses_private_dbgk()
        .then(|| Arc::new(Mutex::new(HashSet::new())));
    let worker_private_vt_step_intents = private_vt_step_intents.clone();
    std::thread::Builder::new()
        .name(format!(
            "{}-attach-{id}",
            if control_plane.uses_private_dbgk() {
                "private-dbgk"
            } else {
                "native-debug"
            }
        ))
        .spawn(move || {
            attached_worker(
                app,
                id,
                pid,
                initial_tx,
                command_rx,
                worker_stage,
                worker_pending_tid,
                control_plane,
                worker_initial_system_breakpoint,
                worker_private_vt_step_intents,
            )
        })
        .map_err(|error| app_error("spawn native attach thread", error))?;

    let info = initial_rx
        .recv_timeout(LAUNCH_TIMEOUT)
        .map_err(|error| app_error("wait for attached CREATE_PROCESS event", error))?
        .map_err(AppError::Internal)?;
    let control = NativeSessionControl {
        id,
        tx: command_tx.clone(),
        stage,
        pending_tid,
        initial_system_breakpoint,
        private_vt_step_intents,
        control_plane,
        primary_tid: info.primary_tid,
        entry_address: info.entry_address,
    };
    {
        let mut map = sessions().lock();
        if map.contains_key(&pid) {
            drop(map);
            let (reply_tx, reply_rx) = mpsc::channel();
            let _ = command_tx.send(LoopCommand::Detach(reply_tx));
            let _ = reply_rx.recv_timeout(CONTROL_TIMEOUT);
            return Err(AppError::Internal(format!(
                "native debugger session for PID {pid} appeared during attach"
            )));
        }
        map.insert(pid, control.clone());
    }

    if control_plane.holds_private_launch_gate() {
        private_dbgk_entry_diag(
            pid,
            "attach.activation_deferred",
            "CREATE_PROCESS remains pending until the VT entry breakpoint is armed",
        );
        return Ok(info);
    }

    let (reply_tx, reply_rx) = mpsc::channel();
    if let Err(error) = command_tx.send(LoopCommand::ActivateAttach(reply_tx)) {
        sessions().lock().remove(&pid);
        return Err(app_error("activate native attach session", error));
    }
    if let Err(error) = reply_rx
        .recv_timeout(CONTROL_TIMEOUT)
        .map_err(|error| app_error("wait for native attach activation", error))?
        .map_err(AppError::Internal)
    {
        sessions().lock().remove(&pid);
        return Err(error);
    }
    Ok(info)
}

/// Attach a dedicated DebugObject worker without intercepting Windows' loader
/// breakpoint. Existing native debugger behavior uses this mode.
pub fn attach_process(app: AppHandle, pid: u32) -> AppResult<NativeLaunchInfo> {
    attach_process_inner(app, pid, AttachedControlPlane::Native)
}

pub fn attach_process_for_native_vt(
    app: AppHandle,
    pid: u32,
) -> AppResult<NativeLaunchInfo> {
    attach_process_inner(
        app,
        pid,
        AttachedControlPlane::VtWindowsDebugObject {
            hold_initial_system_breakpoint: false,
            defer_peb_cloak: false,
        },
    )
}

pub fn attach_process_for_private_vt(
    app: AppHandle,
    pid: u32,
) -> AppResult<NativeLaunchInfo> {
    attach_process_inner(
        app,
        pid,
        AttachedControlPlane::VtPrivateDbgk { launch_gate: false },
    )
}

pub fn attach_process_for_native_vt_launch(
    app: AppHandle,
    pid: u32,
) -> AppResult<NativeLaunchInfo> {
    attach_process_inner(
        app,
        pid,
        AttachedControlPlane::VtWindowsDebugObject {
            hold_initial_system_breakpoint: false,
            defer_peb_cloak: true,
        },
    )
}

pub fn attach_process_for_private_vt_launch(
    app: AppHandle,
    pid: u32,
) -> AppResult<NativeLaunchInfo> {
    attach_process_inner(
        app,
        pid,
        AttachedControlPlane::VtPrivateDbgk { launch_gate: true },
    )
}

pub fn activate_private_vt_launch(pid: u32) -> AppResult<()> {
    let control = sessions()
        .lock()
        .get(&pid)
        .cloned()
        .ok_or_else(|| AppError::Internal(format!("no native debug session for PID {pid}")))?;
    if !control.control_plane.holds_private_launch_gate() {
        return Err(AppError::Internal(format!(
            "native debug session for PID {pid} has no private launch gate"
        )));
    }
    match control.stage.load(Ordering::Acquire) {
        STAGE_CREATE_EVENT_GATED => {}
        STAGE_ENTRY_CONTINUED => return Ok(()),
        stage => {
            return Err(AppError::Internal(format!(
                "private Dbgk launch session for PID {pid} cannot activate from stage {stage}"
            )))
        }
    }

    private_dbgk_entry_diag(pid, "run_to_entry.launch_gate", "continue CREATE_PROCESS event");
    let (reply_tx, reply_rx) = mpsc::channel();
    control
        .tx
        .send(LoopCommand::ActivateAttach(reply_tx))
        .map_err(|error| app_error("activate private Dbgk launch", error))?;
    reply_rx
        .recv_timeout(CONTROL_TIMEOUT)
        .map_err(|error| app_error("wait for private Dbgk launch activation", error))?
        .map_err(AppError::Internal)?;
    private_dbgk_entry_diag(pid, "run_to_entry.launch_gate", "activated");
    Ok(())
}

pub fn launch_uses_initial_system_breakpoint(pid: u32) -> AppResult<bool> {
    sessions()
        .lock()
        .get(&pid)
        .map(|control| control.control_plane.holds_initial_system_breakpoint())
        .ok_or_else(|| AppError::Internal(format!("no native debug session for PID {pid}")))
}

/// Create the process under a native DebugObject, resolve and arm its PE entry
/// point, then leave the CREATE_PROCESS event pending.  The target cannot race
/// ahead of front-end session publication.  Call [`run_to_entry`] only after
/// the UI has accepted the returned PID.
pub fn launch_executable(
    app: AppHandle,
    exe_path: String,
    args: Option<String>,
    working_dir: Option<String>,
) -> AppResult<NativeLaunchInfo> {
    let exe = PathBuf::from(&exe_path);
    if !exe.is_file() {
        return Err(AppError::Internal(format!(
            "native debug executable not found: {}",
            exe.display()
        )));
    }
    let directory = working_dir
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| exe.parent().unwrap_or(Path::new(".")).to_path_buf());
    if !directory.is_dir() {
        return Err(AppError::Internal(format!(
            "native debug working directory not found: {}",
            directory.display()
        )));
    }

    let id = SESSION_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let stage = Arc::new(AtomicU32::new(STAGE_CREATE_EVENT_GATED));
    let pending_tid = Arc::new(AtomicU32::new(0));
    let (initial_tx, initial_rx) = mpsc::channel();
    let (command_tx, command_rx) = mpsc::channel();
    let worker_stage = stage.clone();
    let worker_pending_tid = pending_tid.clone();
    std::thread::Builder::new()
        .name(format!("native-debug-launch-{id}"))
        .spawn(move || {
            worker(
                app,
                id,
                exe,
                args,
                directory,
                initial_tx,
                command_rx,
                worker_stage,
                worker_pending_tid,
            )
        })
        .map_err(|error| app_error("spawn native debugger thread", error))?;

    let launch = initial_rx
        .recv_timeout(LAUNCH_TIMEOUT)
        .map_err(|error| app_error("wait for native CREATE_PROCESS event", error))?
        .map_err(|error| AppError::Internal(error))?;
    let control = NativeSessionControl {
        id,
        tx: command_tx.clone(),
        stage,
        pending_tid,
        initial_system_breakpoint: Arc::new(InitialSystemBreakpointState::new()),
        private_vt_step_intents: None,
        control_plane: AttachedControlPlane::Native,
        primary_tid: launch.primary_tid,
        entry_address: launch.entry_address,
    };
    let mut map = sessions().lock();
    if map.contains_key(&launch.pid) {
        drop(map);
        let (reply_tx, reply_rx) = mpsc::channel();
        command_tx
            .send(LoopCommand::Abandon(reply_tx))
            .map_err(|error| app_error("abandon duplicate native launch", error))?;
        reply_rx
            .recv_timeout(CONTROL_TIMEOUT)
            .map_err(|error| app_error("wait for duplicate native launch abandon", error))?
            .map_err(AppError::Internal)?;
        return Err(AppError::Internal(format!(
            "native debugger already owns PID {}",
            launch.pid
        )));
    }
    map.insert(launch.pid, control);
    Ok(launch)
}

/// Open the launch gate and run until the one-shot PE-entry breakpoint is
/// pending. The front-end must call this after storing the launch PID so the
/// emitted `dbg-native-hit` event has an authoritative session to land in.
pub fn run_to_entry(pid: u32) -> AppResult<NativeLaunchInfo> {
    let control = sessions()
        .lock()
        .get(&pid)
        .cloned()
        .ok_or_else(|| AppError::Internal(format!("no native debug session for PID {pid}")))?;
    match control.stage.load(Ordering::Acquire) {
        STAGE_ENTRY_PENDING => {
            return Ok(NativeLaunchInfo {
                pid,
                primary_tid: control.primary_tid,
                entry_address: control.entry_address,
                stopped_at_entry: true,
            })
        }
        STAGE_RUNNING_TO_ENTRY => {
            return Err(AppError::Internal(format!(
                "PID {pid} is already running to its entry point"
            )))
        }
        STAGE_ENTRY_CONTINUED | STAGE_ENDED => {
            return Err(AppError::Internal(format!(
                "PID {pid} has already passed or ended its native entry event"
            )))
        }
        STAGE_DETACH_RETRY => {
            return Err(AppError::Internal(format!(
                "PID {pid} is retrying native DebugObject detach"
            )))
        }
        STAGE_CREATE_EVENT_GATED => {}
        other => {
            return Err(AppError::Internal(format!(
                "PID {pid} has invalid native debugger stage {other}"
            )))
        }
    }
    let (reply_tx, reply_rx) = mpsc::channel();
    control
        .tx
        .send(LoopCommand::RunToEntry(reply_tx))
        .map_err(|error| app_error("start native run-to-entry", error))?;
    reply_rx
        .recv_timeout(RUN_TO_ENTRY_TIMEOUT)
        .map_err(|error| app_error("wait for native entry breakpoint", error))?
        .map_err(AppError::Internal)
}

/// Continue a pending native DebugObject event instead of calling
/// ResumeThread. Returns `Ok(None)` when the TID is not owned by this minimal
/// native event loop, allowing the caller to use its existing VT/R3 path.
pub fn continue_pending_tid(tid: u32) -> AppResult<Option<u32>> {
    let control = sessions()
        .lock()
        .values()
        .find(|entry| entry.pending_tid.load(Ordering::Acquire) == tid)
        .cloned();
    let Some(control) = control else {
        return Ok(None);
    };
    let (reply_tx, reply_rx) = mpsc::channel();
    control
        .tx
        .send(LoopCommand::ContinueEntry { tid, reply: reply_tx })
        .map_err(|error| app_error("continue native entry event", error))?;
    reply_rx
        .recv_timeout(CONTROL_TIMEOUT)
        .map_err(|error| app_error("wait for native entry continue", error))?
        .map_err(AppError::Internal)?;
    // A DebugObject event is a suspension owned by the debugger rather than a
    // SuspendThread count. `1` preserves the existing command's success shape.
    Ok(Some(1))
}

fn session_for_pid(pid: u32) -> AppResult<NativeSessionControl> {
    sessions()
        .lock()
        .get(&pid)
        .cloned()
        .ok_or_else(|| AppError::Internal(format!("no native DebugObject session for PID {pid}")))
}

pub fn session_pids() -> Vec<u32> {
    sessions().lock().keys().copied().collect()
}

/// Arm one TF step. Returns true when the worker consumed a pending native
/// debug event itself, or false when it only armed TF on a VT-suspended thread
/// and the caller must resume that VT event afterwards.
pub fn step_into(pid: u32, tid: u32) -> AppResult<bool> {
    let control = session_for_pid(pid)?;
    let (reply_tx, reply_rx) = mpsc::channel();
    control
        .tx
        .send(LoopCommand::StepInto { tid, reply: reply_tx })
        .map_err(|error| app_error("arm native step-into", error))?;
    reply_rx
        .recv_timeout(CONTROL_TIMEOUT)
        .map_err(|error| app_error("wait for native step-into", error))?
        .map_err(AppError::Internal)
}

pub fn step_into_vt(pid: u32, tid: u32) -> AppResult<bool> {
    let control = session_for_pid(pid)?;
    if control.control_plane.uses_private_dbgk() {
        let intents = control.private_vt_step_intents.as_ref().ok_or_else(|| {
            AppError::Internal(format!(
                "private Dbgk session for PID {pid} has no VT step receiver"
            ))
        })?;
        if !intents.lock().insert(tid) {
            return Err(AppError::Internal(format!(
                "TID {tid} already has an active private VT single-step intent"
            )));
        }
        private_dbgk_entry_diag(
            pid,
            "vt_step.receiver.register",
            format!("tid={tid} transport=shared-private-dbgk"),
        );
        return Ok(false);
    }
    let (reply_tx, reply_rx) = mpsc::channel();
    control
        .tx
        .send(LoopCommand::StepIntoVt { tid, reply: reply_tx })
        .map_err(|error| app_error("arm VT step-into receiver", error))?;
    reply_rx
        .recv_timeout(CONTROL_TIMEOUT)
        .map_err(|error| app_error("wait for VT step-into receiver", error))?
        .map_err(AppError::Internal)
}

pub fn cancel_vt_step(pid: u32, tid: u32) -> AppResult<()> {
    let control = session_for_pid(pid)?;
    if control.control_plane.uses_private_dbgk() {
        if let Some(intents) = control.private_vt_step_intents.as_ref() {
            intents.lock().remove(&tid);
        }
        private_dbgk_entry_diag(
            pid,
            "vt_step.receiver.cancel",
            format!("tid={tid} transport=shared-private-dbgk"),
        );
        return Ok(());
    }
    let (reply_tx, reply_rx) = mpsc::channel();
    control
        .tx
        .send(LoopCommand::CancelVtStep { tid, reply: reply_tx })
        .map_err(|error| app_error("cancel VT step receiver", error))?;
    reply_rx
        .recv_timeout(CONTROL_TIMEOUT)
        .map_err(|error| app_error("wait for VT step cancellation", error))?
        .map_err(AppError::Internal)
}

/// Decode the current instruction in the worker and either arm TF or a
/// one-shot fall-through breakpoint. The backend never trusts a UI-supplied
/// next RIP.
pub fn step_over(pid: u32, tid: u32) -> AppResult<NativeStepOverResult> {
    let control = session_for_pid(pid)?;
    let (reply_tx, reply_rx) = mpsc::channel();
    control
        .tx
        .send(LoopCommand::StepOver { tid, reply: reply_tx })
        .map_err(|error| app_error("arm native step-over", error))?;
    reply_rx
        .recv_timeout(CONTROL_TIMEOUT)
        .map_err(|error| app_error("wait for native step-over", error))?
        .map_err(AppError::Internal)
}

pub fn step_out(pid: u32, tid: u32) -> AppResult<u64> {
    let control = session_for_pid(pid)?;
    let (reply_tx, reply_rx) = mpsc::channel();
    control
        .tx
        .send(LoopCommand::StepOut { tid, reply: reply_tx })
        .map_err(|error| app_error("arm native step-out", error))?;
    reply_rx
        .recv_timeout(CONTROL_TIMEOUT)
        .map_err(|error| app_error("wait for native step-out", error))?
        .map_err(AppError::Internal)
}

pub fn cancel_step_over(pid: u32, tid: u32) -> AppResult<bool> {
    let control = session_for_pid(pid)?;
    let (reply_tx, reply_rx) = mpsc::channel();
    control
        .tx
        .send(LoopCommand::CancelStepOver { tid, reply: reply_tx })
        .map_err(|error| app_error("cancel native one-shot run", error))?;
    reply_rx
        .recv_timeout(CONTROL_TIMEOUT)
        .map_err(|error| app_error("wait for native one-shot cancellation", error))?
        .map_err(AppError::Internal)
}

pub fn set_software_breakpoint(
    pid: u32,
    address: u64,
) -> AppResult<NativeSoftwareBreakpoint> {
    let control = session_for_pid(pid)?;
    let (reply_tx, reply_rx) = mpsc::channel();
    control
        .tx
        .send(LoopCommand::SetSoftware { address, reply: reply_tx })
        .map_err(|error| app_error("set native software breakpoint", error))?;
    reply_rx
        .recv_timeout(CONTROL_TIMEOUT)
        .map_err(|error| app_error("wait for native software breakpoint set", error))?
        .map_err(AppError::Internal)
}

pub fn clear_software_breakpoint(pid: u32, address: u64) -> AppResult<()> {
    let control = session_for_pid(pid)?;
    let (reply_tx, reply_rx) = mpsc::channel();
    control
        .tx
        .send(LoopCommand::ClearSoftware { address, reply: reply_tx })
        .map_err(|error| app_error("clear native software breakpoint", error))?;
    reply_rx
        .recv_timeout(CONTROL_TIMEOUT)
        .map_err(|error| app_error("wait for native software breakpoint clear", error))?
        .map_err(AppError::Internal)
}

pub fn list_software_breakpoints(pid: u32) -> AppResult<Vec<NativeSoftwareBreakpoint>> {
    let control = session_for_pid(pid)?;
    let (reply_tx, reply_rx) = mpsc::channel();
    control
        .tx
        .send(LoopCommand::ListSoftware(reply_tx))
        .map_err(|error| app_error("list native software breakpoints", error))?;
    reply_rx
        .recv_timeout(CONTROL_TIMEOUT)
        .map_err(|error| app_error("wait for native software breakpoint list", error))
}

pub fn set_hardware_breakpoint(
    pid: u32,
    slot: u32,
    address: u64,
    length: u8,
    bp_type: u8,
) -> AppResult<()> {
    let control = session_for_pid(pid)?;
    let (reply_tx, reply_rx) = mpsc::channel();
    control
        .tx
        .send(LoopCommand::SetHardware {
            breakpoint: NativeHardwareBreakpoint {
                slot,
                address,
                length,
                bp_type,
            },
            reply: reply_tx,
        })
        .map_err(|error| app_error("set native hardware breakpoint", error))?;
    reply_rx
        .recv_timeout(CONTROL_TIMEOUT)
        .map_err(|error| app_error("wait for native hardware breakpoint set", error))?
        .map_err(AppError::Internal)
}

pub fn clear_hardware_breakpoint(pid: u32, slot: u32) -> AppResult<()> {
    let control = session_for_pid(pid)?;
    let (reply_tx, reply_rx) = mpsc::channel();
    control
        .tx
        .send(LoopCommand::ClearHardware { slot, reply: reply_tx })
        .map_err(|error| app_error("clear native hardware breakpoint", error))?;
    reply_rx
        .recv_timeout(CONTROL_TIMEOUT)
        .map_err(|error| app_error("wait for native hardware breakpoint clear", error))?
        .map_err(AppError::Internal)
}

pub fn list_hardware_breakpoints(pid: u32) -> AppResult<Vec<NativeHardwareBreakpoint>> {
    let control = session_for_pid(pid)?;
    let (reply_tx, reply_rx) = mpsc::channel();
    control
        .tx
        .send(LoopCommand::ListHardware(reply_tx))
        .map_err(|error| app_error("list native hardware breakpoints", error))?;
    reply_rx
        .recv_timeout(CONTROL_TIMEOUT)
        .map_err(|error| app_error("wait for native hardware breakpoint list", error))
}

fn wait_for_worker_shutdown(
    pid: u32,
    control: &NativeSessionControl,
    operation: &str,
) -> AppResult<()> {
    let deadline = Instant::now() + WORKER_SHUTDOWN_TIMEOUT;
    loop {
        let stage = control.stage.load(Ordering::Acquire);
        if stage == STAGE_ENDED {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(AppError::Internal(format!(
                "{operation} for PID {pid}: worker generation {} did not release resources (stage={stage})",
                control.id,
            )));
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// Restore an unhit entry breakpoint, release any pending debug event, and
/// relinquish the DebugObject without terminating the target.
pub fn detach(pid: u32) -> AppResult<bool> {
    let control = sessions().lock().get(&pid).cloned();
    let Some(control) = control else {
        return Ok(false);
    };
    let (reply_tx, reply_rx) = mpsc::channel();
    if let Err(error) = control.tx.send(LoopCommand::Detach(reply_tx)) {
        // The worker removes itself from `sessions` immediately before its
        // final STAGE_ENDED store.  A sender racing that small window observes
        // a closed channel even though teardown is already authoritative.
        wait_for_worker_shutdown(pid, &control, "native debugger detach")?;
        let _ = error;
        return Ok(true);
    }
    match reply_rx.recv_timeout(CONTROL_TIMEOUT) {
        Ok(result) => result.map_err(AppError::Internal)?,
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            // Private Dbgk can wake WaitForDebugEventEx with
            // ERROR_DEBUGGER_INACTIVE and finish before delivering the command
            // reply.  STAGE_ENDED, not channel ordering, is the completion
            // fence for DebugObject handles and the worker-owned VT binding.
            wait_for_worker_shutdown(pid, &control, "native debugger detach")?;
            return Ok(true);
        }
        Err(error @ mpsc::RecvTimeoutError::Timeout) => {
            if control.stage.load(Ordering::Acquire) == STAGE_ENDED {
                return Ok(true);
            }
            return Err(app_error("wait for native debugger detach", error));
        }
    }
    wait_for_worker_shutdown(pid, &control, "native debugger detach")?;
    Ok(true)
}

/// Authoritatively discard a launch that has not been delivered to the
/// frontend. This command waits until the worker has either safely detached or
/// terminated and confirmed exit of the process; it never leaves a retryable
/// DebugObject session behind the failed launch call.
pub fn abandon(pid: u32) -> AppResult<()> {
    let control = sessions().lock().get(&pid).cloned();
    let Some(control) = control else {
        return Ok(());
    };
    let (reply_tx, reply_rx) = mpsc::channel();
    if let Err(error) = control.tx.send(LoopCommand::Abandon(reply_tx)) {
        // A disconnected receiver means the worker is already completing its
        // own authoritative cleanup. Wait for its final state instead of
        // returning while ownership is ambiguous.
        wait_for_worker_shutdown(pid, &control, "authoritative native launch abandon")?;
        let _ = error;
        return Ok(());
    }

    let result = match reply_rx.recv_timeout(CONTROL_TIMEOUT) {
        Ok(result) => result.map_err(AppError::Internal),
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            wait_for_worker_shutdown(pid, &control, "authoritative native launch abandon")?;
            return Ok(());
        }
        Err(error @ mpsc::RecvTimeoutError::Timeout) => {
            if control.stage.load(Ordering::Acquire) == STAGE_ENDED {
                return Ok(());
            }
            Err(app_error("wait for authoritative native launch abandon", error))
        }
    };
    if result.is_ok() {
        wait_for_worker_shutdown(pid, &control, "authoritative native launch abandon")?;
    }
    result
}
