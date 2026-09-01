//! 调试器窗口相关 commands。
//!
//! P14 完整 R3 落地:
//!   - 多窗口、独立 session
//!   - 读 / 写 / 反汇编 内存
//!   - 模块 / 线程 / 内存 region 枚举
//!   - GetThreadContext / SetThreadContext / Suspend / Resume
//!   - int3 软断点 set/clear(备份原字节)
//!   - 内存扫描:首扫 + 再扫,类型 i8/i16/i32/i64/f32/f64,
//!     比较运算 exact / gt / lt / changed / unchanged
//!
//! 驱动 IOCTL 路径作为可选后置,在 P14-A 单独 PR 里替换 R3 实现。

use iced_x86::{Decoder, DecoderOptions, Formatter, Instruction, IntelFormatter};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::ffi::{c_void, OsString};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::ffi::OsStringExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use tauri::{AppHandle, Emitter, Manager, State, WebviewUrl, WebviewWindowBuilder};
use windows::core::{PCSTR, PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, FILETIME, HANDLE, STILL_ACTIVE, WAIT_OBJECT_0};
use windows::Win32::System::Diagnostics::Debug::{
    GetThreadContext, ReadProcessMemory, SetThreadContext, Wow64GetThreadContext,
    Wow64SetThreadContext, WriteProcessMemory, CONTEXT, CONTEXT_ALL_AMD64,
    CONTEXT_CONTROL_AMD64, CONTEXT_INTEGER_AMD64, WOW64_CONTEXT,
    WOW64_CONTEXT_CONTROL, WOW64_CONTEXT_FULL, SymCleanup, SymFromName,
    SymInitializeW, SymLoadModuleExW, SymSetOptions, SYMBOL_INFO_PACKAGE,
    SYMOPT_DEFERRED_LOADS, SYMOPT_FAIL_CRITICAL_ERRORS, SYMOPT_LOAD_LINES,
    SYMOPT_UNDNAME, SYM_LOAD_FLAGS,
};
use windows::Win32::System::ProcessStatus::{EnumDeviceDrivers, GetDeviceDriverFileNameW};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, Thread32First, Thread32Next,
    MODULEENTRY32W, TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32, TH32CS_SNAPTHREAD, THREADENTRY32,
};
use windows::Win32::System::Memory::{
    VirtualProtectEx, VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, PAGE_EXECUTE_READWRITE,
    PAGE_GUARD, PAGE_NOACCESS, PAGE_PROTECTION_FLAGS,
};
use windows::Win32::System::Threading::{
    CreateProcessW, GetCurrentProcess, GetExitCodeProcess, GetExitCodeThread, GetProcessId,
    GetProcessIdOfThread, GetProcessTimes, IsWow64Process, OpenProcess, OpenThread, ResumeThread,
    SuspendThread, TerminateProcess, WaitForSingleObject,
    CREATE_NEW_CONSOLE, CREATE_SUSPENDED, PROCESS_CREATION_FLAGS, PROCESS_INFORMATION,
    PROCESS_QUERY_INFORMATION, PROCESS_SYNCHRONIZE, PROCESS_TERMINATE, PROCESS_VM_OPERATION,
    PROCESS_VM_READ, PROCESS_VM_WRITE, STARTUPINFOW,
    THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_SET_CONTEXT,
    THREAD_SUSPEND_RESUME,
};

use crate::ioctl::codes::*;
use crate::ioctl::DeviceState;
use crate::util::error::{AppError, AppResult};
use super::debugger::{debugger_add_impl, debugger_remove_impl};

static SESSION_SEQ: AtomicU64 = AtomicU64::new(1);

const BRIDGE_PROTOCOL_VERSION: u32 = 6;
const BRIDGE_CAP_DEBUG_EVENTS: u32 = 0x0000_0001;
const BRIDGE_CAP_MEMORY_IO: u32 = 0x0000_0004;
const BRIDGE_CAP_THREAD_CONTEXT: u32 = 0x0000_0008;
const BRIDGE_CAP_PEB_SCRUB: u32 = 0x0000_0010;
const BRIDGE_CAP_PRIVATE_SWBP: u32 = 0x0000_0080;
const BRIDGE_CAP_VT_HWBP: u32 = 0x0000_0100;
const BRIDGE_CAP_VT_STEP: u32 = 0x0000_1000;
const BRIDGE_CAP_PRIVATE_DEBUG_OBJECT: u32 = 0x0000_2000;
const BRIDGE_STATE_PRIVATE_DEBUG_OBJECT: u32 = 0x1000_0000;
const BRIDGE_BIND_DEFAULT_FLAGS: u32 = 0x0000_0007;
const BRIDGE_BIND_EXPECT_WINDOWS_DEBUG_OBJECT: u32 = 0x0001_0000;
const BRIDGE_BIND_EXPECT_PRIVATE_DBGK: u32 = 0x0002_0000;
const BRIDGE_PEB_CLOAK_ACTIVATE: u32 = 0x0000_0001;
const BRIDGE_STATUS_SUCCESS: i32 = 0;
const BRIDGE_STATUS_NOT_FOUND: i32 = 4;
const NT_STATUS_NOT_FOUND: i32 = 0xC000_0225u32 as i32;
const DBG_CONTINUE_STATUS: u32 = 0x0001_0002;
const STEP_TRANSACTION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
const SYMBOL_CACHE_CANDIDATES: [&str; 3] = ["E:\\Symbols", "D:\\Symbols", "C:\\Symbols"];
static SYMBOL_CACHE_OVERRIDE: OnceLock<Mutex<Option<PathBuf>>> = OnceLock::new();
#[repr(C)]
#[derive(Clone, Copy)]
struct BridgeRegisterRequest {
    version: u32,
    capabilities: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct BridgeTargetRequest {
    version: u32,
    target_pid: u32,
    flags: u32,
    reserved: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct BridgeResult {
    version: u32,
    status: i32,
    debugger_pid: u32,
    target_pid: u32,
    active_bindings: u32,
    flags: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct PrivateDbgkSymbolsRequest {
    version: u32,
    reserved: u32,
    nt_create_debug_object: u64,
    nt_debug_active_process: u64,
    nt_set_information_debug_object: u64,
    nt_wait_for_debug_event: u64,
    nt_debug_continue: u64,
    nt_remove_process_debug: u64,
    dbgk_forward_exception: u64,
    dbgk_create_thread: u64,
    dbgk_exit_thread: u64,
    dbgk_exit_process: u64,
    dbgk_map_view_of_section: u64,
    dbgk_unmap_view_of_section: u64,
    ps_get_next_process_thread: u64,
    nt_set_context_thread: u64,
    nt_read_virtual_memory: u64,
    nt_write_virtual_memory: u64,
}

const _: [(); 136] = [(); std::mem::size_of::<PrivateDbgkSymbolsRequest>()];

#[repr(C)]
#[derive(Clone, Copy)]
struct PrivateWaitRequest {
    version: u32,
    timeout_ms: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct PrivateEventRaw {
    sequence: u64,
    thread_id: u32,
    process_id: u32,
    cr3: u64,
    rip: u64,
    rsp: u64,
    rflags: u64,
    gpr: [u64; 15],
    dr6: u64,
    hit_slot: u32,
    kind: u32,
    thread_token: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct PrivateWaitResult {
    status: i32,
    reserved: u32,
    event: PrivateEventRaw,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct PrivateContinueRequest {
    version: u32,
    continue_status: u32,
    sequence: u64,
    process_id: u32,
    thread_id: u32,
    thread_token: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct OperationResult {
    status: u32,
    reserved: u32,
    info: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct VtStepRequest {
    version: u32,
    target_pid: u32,
    thread_id: u32,
    reserved: u32,
    address: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ResolveThreadRequest {
    version: u32,
    process_id: u32,
    thread_id: u32,
    reserved: u32,
    thread_token: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct ResolveThreadResult {
    status: i32,
    thread_id: u32,
    thread_token: u64,
}

const _: [(); 8] = [(); std::mem::size_of::<BridgeRegisterRequest>()];
const _: [(); 16] = [(); std::mem::size_of::<BridgeTargetRequest>()];
const _: [(); 24] = [(); std::mem::size_of::<BridgeResult>()];
const _: [(); 8] = [(); std::mem::size_of::<PrivateWaitRequest>()];
const _: [(); 192] = [(); std::mem::size_of::<PrivateEventRaw>()];
const _: [(); 200] = [(); std::mem::size_of::<PrivateWaitResult>()];
const _: [(); 32] = [(); std::mem::size_of::<PrivateContinueRequest>()];
const _: [(); 16] = [(); std::mem::size_of::<OperationResult>()];
const _: [(); 24] = [(); std::mem::size_of::<VtStepRequest>()];
const _: [(); 24] = [(); std::mem::size_of::<ResolveThreadRequest>()];
const _: [(); 16] = [(); std::mem::size_of::<ResolveThreadResult>()];

// ============================================================
// Self PID — 给前端 "本程序注册受保护调试器" 用
// ============================================================

#[tauri::command]
pub fn dbg_self_pid() -> u32 {
    std::process::id()
}

/// 全局 flag:GUI 自身是否已成功注册到 driver 保护链。
/// 主窗口 driverStore 注册成功 → set true;driver_close_device → set false。
/// 任何窗口都可调 `dbg_self_protected` 查询当前值,无需通过 zustand。
static SELF_PROTECTED: AtomicBool = AtomicBool::new(false);

/// P60 扫描取消 flag — GUI 点取消时 set true,扫描循环每个 region 后检查,
/// region 内每 1MB chunk 也检查一次。扫描结束时清。
static SCAN_CANCEL: AtomicBool = AtomicBool::new(false);

#[tauri::command]
pub fn dbg_scan_cancel() {
    SCAN_CANCEL.store(true, Ordering::Relaxed);
}

#[tauri::command]
pub fn dbg_self_protected() -> bool {
    SELF_PROTECTED.load(Ordering::Relaxed)
}

#[tauri::command]
pub fn dbg_set_self_protected(value: bool) {
    SELF_PROTECTED.store(value, Ordering::Relaxed);
}

// ============================================================
// Freeze — 锁定地址定值,后台 10Hz 写回
// ============================================================

#[derive(Default)]
pub struct FreezeStore {
    inner: Mutex<std::collections::HashMap<(u32, u64), Vec<u8>>>,
}

#[tauri::command]
pub fn dbg_freeze_set(
    freeze: State<'_, Arc<FreezeStore>>,
    pid: u32,
    address: u64,
    bytes: Vec<u8>,
) -> AppResult<()> {
    freeze.inner.lock().insert((pid, address), bytes);
    Ok(())
}

#[tauri::command]
pub fn dbg_freeze_clear(
    freeze: State<'_, Arc<FreezeStore>>,
    pid: u32,
    address: u64,
) -> AppResult<()> {
    freeze.inner.lock().remove(&(pid, address));
    Ok(())
}

#[tauri::command]
pub fn dbg_freeze_list(freeze: State<'_, Arc<FreezeStore>>) -> AppResult<Vec<(u32, u64, Vec<u8>)>> {
    Ok(freeze
        .inner
        .lock()
        .iter()
        .map(|((p, a), v)| (*p, *a, v.clone()))
        .collect())
}

/// 启动后台 freeze writer,10Hz 把所有 freeze 项写回目标。
/// 在 lib.rs setup 里启动一次即可。
pub fn spawn_freeze_writer(
    app: AppHandle,
    handles: Arc<DebuggerHandles>,
    freeze: Arc<FreezeStore>,
) {
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(std::time::Duration::from_millis(100));
            let snapshot: Vec<((u32, u64), Vec<u8>)> = {
                let g = freeze.inner.lock();
                if g.is_empty() {
                    continue;
                }
                g.iter().map(|(k, v)| (*k, v.clone())).collect()
            };
            for ((pid, addr), bytes) in snapshot {
                match builtin_target_mode(&handles, pid) {
                    Some(BuiltinDebugMode::Vt) => {
                        let device = app.state::<DeviceState>();
                        if device.is_open() {
                            let _ = super::memory::memory_write_impl(
                                device.inner(),
                                pid,
                                addr,
                                bytes,
                            );
                        }
                    }
                    Some(BuiltinDebugMode::Native) => {
                        let h = match get_or_open(&handles, pid) {
                            Ok(h) => h,
                            Err(_) => continue,
                        };
                        unsafe {
                            let mut old: PAGE_PROTECTION_FLAGS = std::mem::zeroed();
                            let _ = VirtualProtectEx(
                                h,
                                addr as *const c_void,
                                bytes.len(),
                                PAGE_EXECUTE_READWRITE,
                                &mut old,
                            );
                            let mut wrote = 0;
                            let _ = WriteProcessMemory(
                                h,
                                addr as *const c_void,
                                bytes.as_ptr() as *const c_void,
                                bytes.len(),
                                Some(&mut wrote),
                            );
                            let mut restored: PAGE_PROTECTION_FLAGS = std::mem::zeroed();
                            let _ = VirtualProtectEx(
                                h,
                                addr as *const c_void,
                                bytes.len(),
                                old,
                                &mut restored,
                            );
                        }
                    }
                    None => {
                        freeze.inner.lock().remove(&(pid, addr));
                    }
                }
            }
        }
    });
}

fn resolve_private_event_thread(
    device: &DeviceState,
    event: &PrivateEventRaw,
) -> Option<u32> {
    if event.thread_id != 0 {
        return Some(event.thread_id);
    }
    if event.process_id == 0 || event.thread_token == 0 {
        return None;
    }

    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0).ok()?;
        let mut entry: THREADENTRY32 = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
        let mut resolved = None;
        if Thread32First(snapshot, &mut entry).is_ok() {
            loop {
                if entry.th32OwnerProcessID == event.process_id {
                    let request = ResolveThreadRequest {
                        version: BRIDGE_PROTOCOL_VERSION,
                        process_id: event.process_id,
                        thread_id: entry.th32ThreadID,
                        reserved: 0,
                        thread_token: event.thread_token,
                    };
                    let mut result = ResolveThreadResult::default();
                    if device
                        .ioctl(
                            IOCTL_HV_DBG_RESOLVE_THREAD,
                            pod_bytes(&request),
                            pod_bytes_mut(&mut result),
                        )
                        .ok()
                        == Some(std::mem::size_of::<ResolveThreadResult>() as u32)
                        && result.status >= 0
                        && result.thread_id == entry.th32ThreadID
                        && result.thread_token == event.thread_token
                    {
                        resolved = Some(entry.th32ThreadID);
                        break;
                    }
                }
                if Thread32Next(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snapshot);
        resolved
    }
}

pub fn spawn_private_event_poller(
    app: AppHandle,
    handles: Arc<DebuggerHandles>,
) {
    std::thread::spawn(move || loop {
        let should_poll = {
            let lifecycle = handles.lifecycle.lock();
            (lifecycle.granted_capabilities & BRIDGE_CAP_PRIVATE_SWBP) != 0
                && lifecycle
                    .target_refs
                    .values()
                    .any(|target| {
                        target.refs != 0
                            && target.mode == BuiltinDebugMode::Vt
                            && !target.driver_unbound
                    })
        };
        if !should_poll {
            std::thread::sleep(std::time::Duration::from_millis(25));
            continue;
        }

        let device = app.state::<DeviceState>();
        if !device.is_open() {
            std::thread::sleep(std::time::Duration::from_millis(25));
            continue;
        }
        let request = PrivateWaitRequest {
            version: BRIDGE_PROTOCOL_VERSION,
            timeout_ms: 25,
        };
        let mut result = PrivateWaitResult::default();
        let written = match device.ioctl(
            IOCTL_HV_DBG_WAIT_EVENT,
            pod_bytes(&request),
            pod_bytes_mut(&mut result),
        ) {
            Ok(written) => written,
            Err(error) => {
                super::native_debug::private_dbgk_entry_diag_all(
                    "private_swbp.wait.error",
                    error.to_string(),
                );
                std::thread::sleep(std::time::Duration::from_millis(25));
                continue;
            }
        };
        if written as usize != std::mem::size_of::<PrivateWaitResult>() {
            super::native_debug::private_dbgk_entry_diag_all(
                "private_swbp.wait.invalid_size",
                format!(
                    "bytes={written} expected={}",
                    std::mem::size_of::<PrivateWaitResult>()
                ),
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
            continue;
        }
        if result.status == BRIDGE_STATUS_NOT_FOUND {
            continue;
        }
        if result.status != BRIDGE_STATUS_SUCCESS
            || result.event.sequence == 0
            || result.event.process_id == 0
        {
            super::native_debug::private_dbgk_entry_diag_all(
                "private_swbp.wait.invalid_result",
                format!(
                    "status={} sequence={} pid={} tid={} rip=0x{:X} kind={}",
                    result.status,
                    result.event.sequence,
                    result.event.process_id,
                    result.event.thread_id,
                    result.event.rip,
                    result.event.kind,
                ),
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
            continue;
        }

        super::native_debug::private_dbgk_entry_diag(
            result.event.process_id,
            "private_swbp.event",
            format!(
                "sequence={} raw_tid={} thread_token=0x{:X} cr3=0x{:X} rip=0x{:X} rsp=0x{:X} kind={} hit_slot={} dr6=0x{:X}",
                result.event.sequence,
                result.event.thread_id,
                result.event.thread_token,
                result.event.cr3,
                result.event.rip,
                result.event.rsp,
                result.event.kind,
                result.event.hit_slot,
                result.event.dr6,
            ),
        );

        let Some(tid) = resolve_private_event_thread(device.inner(), &result.event) else {
            super::native_debug::private_dbgk_entry_diag(
                result.event.process_id,
                "private_swbp.resolve_thread.error",
                format!(
                    "sequence={} raw_tid={} thread_token=0x{:X}",
                    result.event.sequence,
                    result.event.thread_id,
                    result.event.thread_token,
                ),
            );
            let unresolved = PendingBuiltinPrivateEvent {
                sequence: result.event.sequence,
                process_id: result.event.process_id,
                thread_id: 0,
                thread_token: result.event.thread_token,
                rip: result.event.rip,
                kind: result.event.kind,
                thread_handle: 0,
                driver_continued: result.event.kind == 0,
                thread_resumed: false,
            };
            let _ = continue_private_event(device.inner(), &unresolved);
            continue;
        };
        super::native_debug::private_dbgk_entry_diag(
            result.event.process_id,
            "private_swbp.resolve_thread",
            format!("sequence={} resolved_tid={tid}", result.event.sequence),
        );
        let wrong_transient_only_thread = handles
            .transient_bps
            .lock()
            .get(&result.event.process_id)
            .and_then(|items| items.get(&result.event.rip))
            .is_some_and(|target| {
                target.owns_registration && target.owner_tid != tid
            });
        if wrong_transient_only_thread {
            super::native_debug::private_dbgk_entry_diag(
                result.event.process_id,
                "private_swbp.wrong_transient_thread",
                format!("sequence={} resolved_tid={tid}", result.event.sequence),
            );
            let skipped = PendingBuiltinPrivateEvent {
                sequence: result.event.sequence,
                process_id: result.event.process_id,
                thread_id: tid,
                thread_token: result.event.thread_token,
                rip: result.event.rip,
                kind: result.event.kind,
                thread_handle: 0,
                driver_continued: result.event.kind == 0,
                thread_resumed: false,
            };
            if continue_private_event(device.inner(), &skipped).is_ok() {
                continue;
            }
        }
        // Serialize the bound check, thread suspension, and pending-map insert
        // against detach.  Otherwise detach can drain the map and then race a
        // late poller insert, leaving the target thread suspended after UNBIND.
        let lifecycle_mutation = handles.lifecycle_mutation.lock();
        if !builtin_target_is_bound(&handles, result.event.process_id) {
            super::native_debug::private_dbgk_entry_diag(
                result.event.process_id,
                "private_swbp.discard_unbound",
                format!("sequence={} tid={tid}", result.event.sequence),
            );
            drop(lifecycle_mutation);
            let discarded = PendingBuiltinPrivateEvent {
                sequence: result.event.sequence,
                process_id: result.event.process_id,
                thread_id: tid,
                thread_token: result.event.thread_token,
                rip: result.event.rip,
                kind: result.event.kind,
                thread_handle: 0,
                driver_continued: result.event.kind == 0,
                thread_resumed: false,
            };
            let _ = continue_private_event(device.inner(), &discarded);
            continue;
        }

        let thread = unsafe {
            OpenThread(
                THREAD_SUSPEND_RESUME | THREAD_QUERY_LIMITED_INFORMATION,
                false,
                tid,
            )
        };
        let Ok(thread) = thread else {
            super::native_debug::private_dbgk_entry_diag(
                result.event.process_id,
                "private_swbp.open_thread.error",
                format!("sequence={} tid={tid}", result.event.sequence),
            );
            let discarded = PendingBuiltinPrivateEvent {
                sequence: result.event.sequence,
                process_id: result.event.process_id,
                thread_id: tid,
                thread_token: result.event.thread_token,
                rip: result.event.rip,
                kind: result.event.kind,
                thread_handle: 0,
                driver_continued: result.event.kind == 0,
                thread_resumed: false,
            };
            let _ = continue_private_event(device.inner(), &discarded);
            continue;
        };
        let previous = unsafe { SuspendThread(thread) };
        if previous == u32::MAX {
            super::native_debug::private_dbgk_entry_diag(
                result.event.process_id,
                "private_swbp.suspend_thread.error",
                format!("sequence={} tid={tid}", result.event.sequence),
            );
            unsafe {
                let _ = CloseHandle(thread);
            }
            let discarded = PendingBuiltinPrivateEvent {
                sequence: result.event.sequence,
                process_id: result.event.process_id,
                thread_id: tid,
                thread_token: result.event.thread_token,
                rip: result.event.rip,
                kind: result.event.kind,
                thread_handle: 0,
                driver_continued: result.event.kind == 0,
                thread_resumed: false,
            };
            let _ = continue_private_event(device.inner(), &discarded);
            continue;
        }
        super::native_debug::private_dbgk_entry_diag(
            result.event.process_id,
            "private_swbp.suspend_thread",
            format!(
                "sequence={} tid={tid} previous_suspend_count={previous}",
                result.event.sequence
            ),
        );

        let pending = PendingBuiltinPrivateEvent {
            sequence: result.event.sequence,
            process_id: result.event.process_id,
            thread_id: tid,
            thread_token: result.event.thread_token,
            rip: result.event.rip,
            kind: result.event.kind,
            thread_handle: thread.0 as isize,
            driver_continued: result.event.kind == 0,
            thread_resumed: false,
        };
        let inserted = {
            let mut pending_events = handles.pending_private.lock();
            if pending_events.contains_key(&tid) {
                false
            } else {
                pending_events.insert(tid, pending);
                true
            }
        };
        drop(lifecycle_mutation);
        if !inserted {
            super::native_debug::private_dbgk_entry_diag(
                result.event.process_id,
                "private_swbp.pending_collision",
                format!("sequence={} tid={tid}", result.event.sequence),
            );
            unsafe {
                let _ = ResumeThread(thread);
                let _ = CloseHandle(thread);
            }
            let discarded = PendingBuiltinPrivateEvent {
                sequence: result.event.sequence,
                process_id: result.event.process_id,
                thread_id: tid,
                thread_token: result.event.thread_token,
                rip: result.event.rip,
                kind: result.event.kind,
                thread_handle: 0,
                driver_continued: result.event.kind == 0,
                thread_resumed: false,
            };
            let _ = continue_private_event(device.inner(), &discarded);
            continue;
        }
        super::native_debug::private_dbgk_entry_diag(
            result.event.process_id,
            "private_swbp.pending_inserted",
            format!(
                "sequence={} tid={tid} rip=0x{:X} kind={}",
                result.event.sequence, result.event.rip, result.event.kind
            ),
        );

        let entry = handles
            .entry_bps
            .lock()
            .get(&result.event.process_id)
            .copied()
            == Some(result.event.rip);
        let transient = handles
            .transient_bps
            .lock()
            .get(&result.event.process_id)
            .and_then(|items| items.get(&result.event.rip))
            .is_some_and(|target| target.owner_tid == tid);
        let mut cleanup_failures = Vec::new();
        if entry {
            match remove_private_swbp(
                &handles,
                device.inner(),
                result.event.process_id,
                result.event.rip,
            ) {
                Ok(()) => {
                    handles.entry_bps.lock().remove(&result.event.process_id);
                    super::native_debug::private_dbgk_entry_diag(
                        result.event.process_id,
                        "private_swbp.entry_cleanup",
                        format!("sequence={} result=ok", result.event.sequence),
                    );
                }
                Err(error) => {
                    super::native_debug::private_dbgk_entry_diag(
                        result.event.process_id,
                        "private_swbp.entry_cleanup.error",
                        format!("sequence={} error={error}", result.event.sequence),
                    );
                    cleanup_failures.push(error.to_string());
                }
            }
        }
        if transient {
            if let Err(error) = consume_transient_private_swbp(
                &handles,
                device.inner(),
                result.event.process_id,
                result.event.rip,
            ) {
                cleanup_failures.push(error.to_string());
            }
        }
        let cleanup_error = (!cleanup_failures.is_empty())
            .then(|| cleanup_failures.join("; "));
        let payload = BuiltinPrivateHit {
            sequence: result.event.sequence,
            pid: result.event.process_id,
            tid,
            rip: result.event.rip,
            kind: result.event.kind,
            entry,
            transient,
            cleanup_error,
        };
        super::native_debug::private_dbgk_entry_diag(
            result.event.process_id,
            "private_swbp.publish",
            format!(
                "sequence={} tid={tid} entry={entry} transient={transient} cleanup_error={}",
                result.event.sequence,
                payload.cleanup_error.as_deref().unwrap_or("none"),
            ),
        );
        if app.emit("dbg-private-hit", payload).is_err() {
            super::native_debug::private_dbgk_entry_diag(
                result.event.process_id,
                "private_swbp.publish.error",
                format!("sequence={} tid={tid}", result.event.sequence),
            );
            if let Some(mut event) = handles.pending_private.lock().remove(&tid) {
                if continue_private_event(device.inner(), &event).is_ok() {
                    event.driver_continued = true;
                    unsafe {
                        let handle = HANDLE(event.thread_handle as _);
                        let _ = ResumeThread(handle);
                        let _ = CloseHandle(handle);
                    }
                } else {
                    handles.pending_private.lock().insert(tid, event);
                }
            }
        }
    });
}

// ============================================================
// Window
// ============================================================

#[tauri::command]
pub async fn dbg_open_window(app: AppHandle) -> AppResult<String> {
    let sid = SESSION_SEQ.fetch_add(1, Ordering::Relaxed);
    let label = format!("dbg-{sid}");

    let url = WebviewUrl::App(format!("debugger.html?sid={sid}").into());

    WebviewWindowBuilder::new(&app, &label, url)
        .title(format!("御元调试器 · GuardMeta Debugger #{sid}"))
        .inner_size(1600.0, 1000.0)
        .min_inner_size(1200.0, 800.0)
        .resizable(true)
        .decorations(false)
        .drag_and_drop(true)
        .build()
        .map_err(|e| AppError::Internal(format!("WebviewWindow build: {e}")))?;

    Ok(label)
}

#[tauri::command]
pub async fn dbg_close_window(app: AppHandle, label: String) -> AppResult<()> {
    if let Some(w) = app.get_webview_window(&label) {
        let _ = w.close();
    }
    Ok(())
}

/// P122: 打开 trace console 浮动窗口. 已存在则 focus.
#[tauri::command]
pub async fn trace_open_window(app: AppHandle) -> AppResult<()> {
    const LABEL: &str = "trace-console";
    if let Some(w) = app.get_webview_window(LABEL) {
        let _ = w.set_focus();
        return Ok(());
    }
    let url = WebviewUrl::App("trace.html".into());
    WebviewWindowBuilder::new(&app, LABEL, url)
        .title("驱动 Trace 控制台")
        .inner_size(1100.0, 700.0)
        .min_inner_size(900.0, 500.0)
        .resizable(true)
        .decorations(false)
        .build()
        .map_err(|e| AppError::Internal(format!("trace window build: {e}")))?;
    Ok(())
}

// ============================================================
// Process handle 缓存 (per pid)
// ============================================================

#[derive(Default)]
struct BuiltinDebuggerLifecycle {
    registered: bool,
    granted_capabilities: u32,
    restart_pins: u32,
    target_refs: std::collections::HashMap<u32, TargetAttachState>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BuiltinDebugMode {
    Native,
    Vt,
}

#[derive(Clone, Debug)]
struct BuiltinLaunchSpec {
    exe_path: String,
    args: Option<String>,
    working_dir: Option<String>,
    mode: BuiltinDebugMode,
}

#[derive(Clone, Copy, Debug)]
struct TargetAttachState {
    refs: u32,
    mode: BuiltinDebugMode,
    // VT DebugObject workers bind before DebugActiveProcess and retain that
    // sole ownership until their event loop and handles have fully stopped.
    binding_owned_by_worker: bool,
    // The driver binding is already authoritatively gone, but one or more
    // user-mode thread suspension handles still require retryable cleanup.
    driver_unbound: bool,
}

struct BuiltinRestartRegistrationPin<'a> {
    state: &'a Arc<DebuggerHandles>,
    device: &'a DeviceState,
    active: bool,
}

impl<'a> BuiltinRestartRegistrationPin<'a> {
    fn acquire(
        state: &'a Arc<DebuggerHandles>,
        device: &'a DeviceState,
        mode: BuiltinDebugMode,
    ) -> Self {
        let active = if mode == BuiltinDebugMode::Vt {
            let mut lifecycle = state.lifecycle.lock();
            if lifecycle.registered {
                lifecycle.restart_pins = lifecycle.restart_pins.saturating_add(1);
                true
            } else {
                false
            }
        } else {
            false
        };
        Self {
            state,
            device,
            active,
        }
    }
}

impl Drop for BuiltinRestartRegistrationPin<'_> {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        {
            let mut lifecycle = self.state.lifecycle.lock();
            lifecycle.restart_pins = lifecycle.restart_pins.saturating_sub(1);
        }
        let _ = unregister_builtin_if_idle(self.state, self.device);
    }
}

struct PendingBuiltinPrivateEvent {
    sequence: u64,
    process_id: u32,
    thread_id: u32,
    thread_token: u64,
    rip: u64,
    kind: u32,
    thread_handle: isize,
    driver_continued: bool,
    thread_resumed: bool,
}

#[derive(Clone, Copy)]
struct TransientPrivateBreakpoint {
    owner_tid: u32,
    owns_registration: bool,
}

struct PendingBuiltinLaunch {
    process_handle: isize,
    primary_thread_handle: isize,
    primary_tid: u32,
    entry_address: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct BuiltinAttachResult {
    pub pid: u32,
    pub mode: String,
    pub debugger_protected: bool,
    pub vt_memory: bool,
    pub private_swbp: bool,
    pub vt_hwbp: bool,
    pub vt_step: bool,
    pub dr_fallback: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct BuiltinLaunchResult {
    pub attach: BuiltinAttachResult,
    pub primary_tid: u32,
    pub entry_address: u64,
    pub stopped_at_entry: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct BuiltinRunToEntryResult {
    pub pid: u32,
    pub primary_tid: u32,
    pub entry_address: u64,
    pub stopped_at_entry: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct BuiltinRestartResult {
    pub old_pid: u32,
    pub new_pid: u32,
    pub process_name: String,
    pub attach: BuiltinAttachResult,
    pub primary_tid: u32,
    pub entry_address: u64,
    pub stopped_at_entry: bool,
}

#[derive(Debug, Clone, Serialize)]
struct BuiltinPrivateHit {
    sequence: u64,
    pid: u32,
    tid: u32,
    rip: u64,
    kind: u32,
    entry: bool,
    transient: bool,
    cleanup_error: Option<String>,
}

#[derive(Default)]
pub struct DebuggerHandles {
    // pid -> handle (PROCESS_ALL_ACCESS)
    procs: Mutex<std::collections::HashMap<u32, isize>>,
    // pid -> 上次成功的模块列表(失败时回退)
    module_cache: Mutex<std::collections::HashMap<u32, Vec<ModuleInfo>>>,
    // pid -> Vec<(addr, original_byte)>  软断点备份
    sw_bps: Mutex<std::collections::HashMap<u32, Vec<(u64, u8)>>>,
    // pid -> 上一轮扫描结果(原始字节序列 + 每个命中地址)
    scan_state: Mutex<std::collections::HashMap<u32, ScanState>>,
    // P56 临时断点(步过/步出装的 sw bp): 命中后自动清。
    // pid -> address -> owner/registration ownership
    transient_bps: Mutex<std::collections::HashMap<
        u32,
        std::collections::HashMap<u64, TransientPrivateBreakpoint>,
    >>,
    // pid -> runtime entry.  This is intentionally separate from step-over /
    // step-out transient breakpoints so the UI can report an entry stop.
    entry_bps: Mutex<std::collections::HashMap<u32, u64>>,
    // CREATE_SUSPENDED launches are held here until the frontend has installed
    // its session state and explicitly calls dbg_run_to_entry.
    pending_launches: Mutex<std::collections::HashMap<u32, PendingBuiltinLaunch>>,
    // Only debugger-created processes receive a restart specification.  Its
    // absence intentionally distinguishes attach-only sessions.
    launch_specs: Mutex<std::collections::HashMap<u32, BuiltinLaunchSpec>>,
    launch_mutation: tokio::sync::Mutex<()>,
    step_mutation: tokio::sync::Mutex<()>,
    lifecycle_mutation: Mutex<()>,
    lifecycle: Mutex<BuiltinDebuggerLifecycle>,
    pending_private: Mutex<std::collections::HashMap<u32, PendingBuiltinPrivateEvent>>,
    vt_step_gates: Mutex<std::collections::HashMap<u32, (u32, u64, bool)>>,
}

/// P116: 数值类型 hit 字节内联到栈 (8B union), Bytes/String 才 spill 到堆.
/// 把 100 万 hit 的 100 万次 malloc 降到 0 次, 加上 (addr, bytes) tuple 总 24B 紧凑.
type HitBytes = smallvec::SmallVec<[u8; 8]>;

struct ScanState {
    /// 上次的值类型
    value_type: ValueType,
    /// 命中地址 + 当时的原始 little-endian 字节
    hits: Vec<(u64, HitBytes)>,
}

fn pod_bytes<T>(value: &T) -> &[u8] {
    unsafe {
        std::slice::from_raw_parts(
            (value as *const T).cast::<u8>(),
            std::mem::size_of::<T>(),
        )
    }
}

fn pod_bytes_mut<T>(value: &mut T) -> &mut [u8] {
    unsafe {
        std::slice::from_raw_parts_mut(
            (value as *mut T).cast::<u8>(),
            std::mem::size_of::<T>(),
        )
    }
}

fn symbol_cache_override() -> &'static Mutex<Option<PathBuf>> {
    SYMBOL_CACHE_OVERRIDE.get_or_init(|| Mutex::new(None))
}

fn symbol_cache_directories() -> Vec<PathBuf> {
    let mut directories = Vec::new();
    if let Some(path) = symbol_cache_override().lock().clone() {
        directories.push(path);
    }
    for candidate in SYMBOL_CACHE_CANDIDATES {
        let path = PathBuf::from(candidate);
        let drive = format!("{}:\\", &candidate[..1]);
        if Path::new(&drive).is_dir() &&
            (std::fs::create_dir_all(&path).is_ok() || path.is_dir()) {
            if !directories.iter().any(|existing| {
                existing.to_string_lossy().eq_ignore_ascii_case(&path.to_string_lossy())
            }) {
                directories.push(path);
            }
        }
    }
    if directories.is_empty() {
        directories.push(PathBuf::from("C:\\Symbols"));
    }
    directories
}

fn symbol_search_path() -> (String, PathBuf) {
    let directories = symbol_cache_directories();
    let primary = directories[0].clone();
    let mut entries: Vec<String> = directories
        .iter()
        .map(|path| path.display().to_string())
        .collect();
    entries.push(format!(
        "srv*{}*https://msdl.microsoft.com/download/symbols",
        primary.display()
    ));
    if let Ok(extra) = std::env::var("_NT_SYMBOL_PATH") {
        if !extra.trim().is_empty() {
            entries.push(extra);
        }
    }
    (entries.join(";"), primary)
}

#[tauri::command]
pub fn dbg_symbol_cache_get() -> Option<String> {
    symbol_cache_override()
        .lock()
        .as_ref()
        .map(|path| path.display().to_string())
}

#[tauri::command]
pub fn dbg_symbol_cache_set(path: Option<String>) -> AppResult<Option<String>> {
    let selected = path
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .map(PathBuf::from);
    if let Some(directory) = &selected {
        if !directory.is_absolute() {
            return Err(AppError::Internal("symbol cache path must be absolute".into()));
        }
        std::fs::create_dir_all(directory).map_err(|error| {
            AppError::Internal(format!(
                "create symbol cache {}: {error}",
                directory.display()
            ))
        })?;
    }
    *symbol_cache_override().lock() = selected.clone();
    Ok(selected.map(|directory| directory.display().to_string()))
}

fn kernel_image_path() -> AppResult<(PathBuf, u64)> {
    let mut bases = [std::ptr::null_mut::<c_void>(); 1024];
    let mut needed = 0u32;
    unsafe {
        EnumDeviceDrivers(
            bases.as_mut_ptr(),
            std::mem::size_of_val(&bases) as u32,
            &mut needed,
        )
    }
    .map_err(|error| AppError::Internal(format!("EnumDeviceDrivers failed: {error}")))?;
    let base = bases[0];
    if base.is_null() {
        return Err(AppError::Internal("kernel driver base is null".into()));
    }
    let mut raw = [0u16; 512];
    let length = unsafe { GetDeviceDriverFileNameW(base, &mut raw) } as usize;
    if length == 0 || length >= raw.len() {
        return Err(AppError::Internal("GetDeviceDriverFileNameW failed".into()));
    }
    let mut path = OsString::from_wide(&raw[..length]).to_string_lossy().into_owned();
    if let Some(rest) = path.strip_prefix("\\SystemRoot\\") {
        let windows_dir = std::env::var("WINDIR").unwrap_or_else(|_| "C:\\Windows".into());
        path = format!("{windows_dir}\\{rest}");
    } else if let Some(rest) = path.strip_prefix("\\??\\") {
        path = rest.to_string();
    }
    Ok((PathBuf::from(path), base as usize as u64))
}

fn resolve_dbgk_symbol(process: HANDLE, name: &str) -> Option<u64> {
    let mut package = SYMBOL_INFO_PACKAGE::default();
    package.si.SizeOfStruct = std::mem::size_of::<windows::Win32::System::Diagnostics::Debug::SYMBOL_INFO>() as u32;
    package.si.MaxNameLen = 2000;
    let qualified = format!("nt!{name}\0");
    let plain = format!("{name}\0");
    unsafe {
        if SymFromName(process, PCSTR(qualified.as_ptr()), &mut package.si).is_ok() ||
            SymFromName(process, PCSTR(plain.as_ptr()), &mut package.si).is_ok() {
            return Some(package.si.Address);
        }
    }
    None
}

fn configure_private_dbgk_symbols(device: &DeviceState) -> AppResult<()> {
    let (kernel, base) = kernel_image_path()?;
    let (search, cache) = symbol_search_path();
    let search_wide: Vec<u16> = search.encode_utf16().chain(std::iter::once(0)).collect();
    let image_wide: Vec<u16> = kernel.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
    let module_wide: Vec<u16> = "nt\0".encode_utf16().collect();
    let process = unsafe { GetCurrentProcess() };
    unsafe {
        SymSetOptions(
            SYMOPT_DEFERRED_LOADS | SYMOPT_UNDNAME |
                SYMOPT_FAIL_CRITICAL_ERRORS | SYMOPT_LOAD_LINES,
        );
        SymInitializeW(process, PCWSTR(search_wide.as_ptr()), false)
            .map_err(|error| AppError::Internal(format!("SymInitializeW failed: {error}")))?;
    }
    let result = (|| {
        let loaded = unsafe {
            SymLoadModuleExW(
                process,
                HANDLE::default(),
                PCWSTR(image_wide.as_ptr()),
                PCWSTR(module_wide.as_ptr()),
                base,
                0,
                None,
                SYM_LOAD_FLAGS(0),
            )
        };
        if loaded == 0 {
            return Err(AppError::Internal(format!(
                "SymLoadModuleExW failed for {} using cache {}: {}",
                kernel.display(), cache.display(), windows::core::Error::from_win32()
            )));
        }
        let names = [
            "NtCreateDebugObject",
            "NtDebugActiveProcess",
            "NtSetInformationDebugObject",
            "NtWaitForDebugEvent",
            "NtDebugContinue",
            "NtRemoveProcessDebug",
            "DbgkForwardException",
            "DbgkCreateThread",
            "DbgkExitThread",
            "DbgkExitProcess",
            "DbgkMapViewOfSection",
            "DbgkUnMapViewOfSection",
            "PsGetNextProcessThread",
            "NtSetContextThread",
            "NtReadVirtualMemory",
            "NtWriteVirtualMemory",
        ];
        let mut addresses = [0u64; 16];
        for (slot, name) in addresses.iter_mut().zip(names) {
            *slot = resolve_dbgk_symbol(process, name)
                .ok_or_else(|| AppError::Internal(format!(
                    "missing kernel symbol {name}; kernel={}; search={search}",
                    kernel.display()
                )))?;
        }
        let request = PrivateDbgkSymbolsRequest {
            version: BRIDGE_PROTOCOL_VERSION,
            reserved: 0,
            nt_create_debug_object: addresses[0],
            nt_debug_active_process: addresses[1],
            nt_set_information_debug_object: addresses[2],
            nt_wait_for_debug_event: addresses[3],
            nt_debug_continue: addresses[4],
            nt_remove_process_debug: addresses[5],
            dbgk_forward_exception: addresses[6],
            dbgk_create_thread: addresses[7],
            dbgk_exit_thread: addresses[8],
            dbgk_exit_process: addresses[9],
            dbgk_map_view_of_section: addresses[10],
            dbgk_unmap_view_of_section: addresses[11],
            ps_get_next_process_thread: addresses[12],
            nt_set_context_thread: addresses[13],
            nt_read_virtual_memory: addresses[14],
            nt_write_virtual_memory: addresses[15],
        };
        let mut output = OperationResult::default();
        let written = device.ioctl(
            IOCTL_HV_BRIDGE_DBGK_SYMBOLS,
            pod_bytes(&request),
            pod_bytes_mut(&mut output),
        )?;
        if written as usize != std::mem::size_of::<OperationResult>()
            || output.status != BRIDGE_STATUS_SUCCESS as u32
        {
            return Err(AppError::Internal(format!(
                "private Dbgk hook configuration failed: bytes={written}, bridge={}, ntstatus=0x{:08X}",
                output.status,
                output.info as u32,
            )));
        }
        Ok(())
    })();
    unsafe { let _ = SymCleanup(process); }
    result
}

fn bridge_register_builtin(
    state: &Arc<DebuggerHandles>,
    device: &DeviceState,
) -> AppResult<u32> {
    let already_registered = state.lifecycle.lock().registered;

    if already_registered {
        let request = BridgeRegisterRequest {
            version: BRIDGE_PROTOCOL_VERSION,
            capabilities: BRIDGE_CAP_DEBUG_EVENTS
                | BRIDGE_CAP_MEMORY_IO
                | BRIDGE_CAP_THREAD_CONTEXT
                | BRIDGE_CAP_PEB_SCRUB
                | BRIDGE_CAP_PRIVATE_SWBP
                | BRIDGE_CAP_VT_HWBP
                | BRIDGE_CAP_VT_STEP
                | BRIDGE_CAP_PRIVATE_DEBUG_OBJECT,
        };
        let mut result = BridgeResult::default();
        let written = device.ioctl(
            IOCTL_HV_BRIDGE_REGISTER,
            pod_bytes(&request),
            pod_bytes_mut(&mut result),
        )?;
        let me = std::process::id();
        if written as usize != std::mem::size_of::<BridgeResult>()
            || result.version != BRIDGE_PROTOCOL_VERSION
            || result.debugger_pid != me
            || result.status < 0
        {
            return Err(AppError::Internal(format!(
                "built-in debugger state refresh failed: bytes={written}, version={}, debugger={}, status=0x{:08X}",
                result.version,
                result.debugger_pid,
                result.status as u32,
            )));
        }
        state.lifecycle.lock().granted_capabilities = result.flags;
        return Ok(result.flags);
    }

    let me = std::process::id();
    // The driver intentionally ignores the old passive GUI polling identity.
    // Use a distinct explicit identity only when the user opens the built-in
    // debugger and attaches a target.
    debugger_add_impl(
        device,
        me,
        "GuardMetaBuiltinDebugger",
        true,
        true,
        false,
        true,
    )?;

    let request = BridgeRegisterRequest {
        version: BRIDGE_PROTOCOL_VERSION,
        capabilities: BRIDGE_CAP_DEBUG_EVENTS
            | BRIDGE_CAP_MEMORY_IO
            | BRIDGE_CAP_THREAD_CONTEXT
            | BRIDGE_CAP_PEB_SCRUB
            | BRIDGE_CAP_PRIVATE_SWBP
            | BRIDGE_CAP_VT_HWBP
            | BRIDGE_CAP_VT_STEP
            | BRIDGE_CAP_PRIVATE_DEBUG_OBJECT,
    };
    let mut result = BridgeResult::default();
    let written = match device.ioctl(
        IOCTL_HV_BRIDGE_REGISTER,
        pod_bytes(&request),
        pod_bytes_mut(&mut result),
    ) {
        Ok(written) => written,
        Err(error) => {
            let _ = debugger_remove_impl(device, me);
            return Err(error);
        }
    };
    if written as usize != std::mem::size_of::<BridgeResult>()
        || result.version != BRIDGE_PROTOCOL_VERSION
        || result.debugger_pid != me
        || result.status < 0
    {
        let _ = debugger_remove_impl(device, me);
        return Err(AppError::Internal(format!(
            "built-in debugger registration failed: bytes={written}, version={}, debugger={}, status=0x{:08X}",
            result.version,
            result.debugger_pid,
            result.status as u32,
        )));
    }
    if (result.flags & BRIDGE_CAP_PRIVATE_DEBUG_OBJECT) != 0 {
        if let Err(error) = configure_private_dbgk_symbols(device) {
            let _ = debugger_remove_impl(device, me);
            return Err(error);
        }
    }
    if let Err(error) = debugger_add_impl(
        device,
        me,
        "GuardMetaBuiltinDebugger",
        true,
        true,
        false,
        false,
    ) {
        let _ = debugger_remove_impl(device, me);
        return Err(error);
    }

    {
        let mut lifecycle = state.lifecycle.lock();
        lifecycle.registered = true;
        lifecycle.granted_capabilities = result.flags;
    }
    SELF_PROTECTED.store(true, Ordering::Release);
    Ok(result.flags)
}

fn unregister_builtin_if_idle(state: &Arc<DebuggerHandles>, device: &DeviceState) -> AppResult<()> {
    let should_unregister = {
        let lifecycle = state.lifecycle.lock();
        lifecycle.registered
            && lifecycle.restart_pins == 0
            && !lifecycle
                .target_refs
                .values()
                .any(|target| target.refs != 0 && target.mode == BuiltinDebugMode::Vt)
    };
    if !should_unregister {
        return Ok(());
    }

    if !device.is_open() {
        return Err(AppError::Internal(
            "cannot unregister the built-in debugger while the driver device is closed".into(),
        ));
    }
    debugger_remove_impl(device, std::process::id())?;
    {
        let mut lifecycle = state.lifecycle.lock();
        lifecycle.registered = false;
        lifecycle.granted_capabilities = 0;
    }
    SELF_PROTECTED.store(false, Ordering::Release);
    Ok(())
}

fn bridge_target_operation(
    device: &DeviceState,
    code: u32,
    pid: u32,
    flags: u32,
) -> AppResult<BridgeResult> {
    super::native_debug::private_dbgk_entry_diag(
        pid,
        "builtin.bridge_target.begin",
        format!("ioctl=0x{code:X} flags=0x{flags:X}"),
    );
    let request = BridgeTargetRequest {
        version: BRIDGE_PROTOCOL_VERSION,
        target_pid: pid,
        flags,
        reserved: 0,
    };
    let mut result = BridgeResult::default();
    let written = match device.ioctl(code, pod_bytes(&request), pod_bytes_mut(&mut result)) {
        Ok(written) => written,
        Err(error) => {
            super::native_debug::private_dbgk_entry_diag(
                pid,
                "builtin.bridge_target.error",
                format!("ioctl=0x{code:X} error={error}"),
            );
            return Err(error);
        }
    };
    super::native_debug::private_dbgk_entry_diag(
        pid,
        "builtin.bridge_target.result",
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
    let idempotent_unbind = code == IOCTL_HV_BRIDGE_UNBIND_TARGET
        && result.status == NT_STATUS_NOT_FOUND;
    if written as usize != std::mem::size_of::<BridgeResult>()
        || result.version != BRIDGE_PROTOCOL_VERSION
        || result.target_pid != pid
        || (result.status < 0 && !idempotent_unbind)
    {
        return Err(AppError::Internal(format!(
            "built-in target operation 0x{code:X} failed for PID {pid}: bytes={written}, version={}, status=0x{:08X}",
            result.version,
            result.status as u32,
        )));
    }
    Ok(result)
}

fn builtin_target_is_bound(state: &Arc<DebuggerHandles>, pid: u32) -> bool {
    state
        .lifecycle
        .lock()
        .target_refs
        .get(&pid)
        .is_some_and(|entry| {
            entry.refs != 0
                && entry.mode == BuiltinDebugMode::Vt
                && !entry.driver_unbound
        })
}

fn builtin_capabilities(state: &Arc<DebuggerHandles>) -> u32 {
    state.lifecycle.lock().granted_capabilities
}

pub(crate) fn builtin_target_mode(
    state: &Arc<DebuggerHandles>,
    pid: u32,
) -> Option<BuiltinDebugMode> {
    state
        .lifecycle
        .lock()
        .target_refs
        .get(&pid)
        .map(|entry| entry.mode)
}

pub(crate) fn parse_builtin_mode(mode: &str) -> AppResult<BuiltinDebugMode> {
    match mode.to_ascii_lowercase().as_str() {
        "native" => Ok(BuiltinDebugMode::Native),
        "vt" => Ok(BuiltinDebugMode::Vt),
        other => Err(AppError::Internal(format!(
            "unknown built-in debugger mode '{other}'"
        ))),
    }
}

pub(crate) fn attach_builtin_target(
    state: &Arc<DebuggerHandles>,
    device: &DeviceState,
    pid: u32,
    requested_mode: BuiltinDebugMode,
) -> AppResult<BuiltinAttachResult> {
    if pid == 0 || pid == std::process::id() {
        return Err(AppError::Internal("invalid built-in debugger target PID".into()));
    }
    let _mutation = state.lifecycle_mutation.lock();
    if let Some(existing) = builtin_target_mode(state, pid) {
        if existing != requested_mode {
            return Err(AppError::Internal(format!(
                "PID {pid} is already attached in {} mode; detach every session before switching mode",
                if existing == BuiltinDebugMode::Vt { "VT" } else { "native" },
            )));
        }
    }

    let first_reference = {
        let lifecycle = state.lifecycle.lock();
        !lifecycle.target_refs.contains_key(&pid)
    };
    let binding_owned_by_worker = requested_mode == BuiltinDebugMode::Vt
        && super::native_debug::owns_vt_target_binding(pid);

    let caps = if requested_mode == BuiltinDebugMode::Vt {
        if !device.is_open() {
            return Err(AppError::Internal(
                "driver device is not open; VT mode cannot attach".into(),
            ));
        }
        let caps = bridge_register_builtin(state, device)?;
        if (caps & BRIDGE_CAP_MEMORY_IO) == 0 {
            let _ = unregister_builtin_if_idle(state, device);
            return Err(AppError::Internal(
                "driver did not grant the VT memory capability".into(),
            ));
        }
        if first_reference && !binding_owned_by_worker {
            let expected_control_plane =
                if (caps & BRIDGE_STATE_PRIVATE_DEBUG_OBJECT) != 0 {
                    BRIDGE_BIND_EXPECT_PRIVATE_DBGK
                } else {
                    BRIDGE_BIND_EXPECT_WINDOWS_DEBUG_OBJECT
                };
            if let Err(error) = bridge_target_operation(
                device,
                IOCTL_HV_BRIDGE_BIND_TARGET,
                pid,
                BRIDGE_BIND_DEFAULT_FLAGS | expected_control_plane,
            ) {
                let _ = unregister_builtin_if_idle(state, device);
                return Err(error);
            }
        }
        caps
    } else {
        0
    };

    if let Err(error) = get_or_open(state, pid) {
        if first_reference
            && requested_mode == BuiltinDebugMode::Vt
            && !binding_owned_by_worker
        {
            let _ = bridge_target_operation(
                device,
                IOCTL_HV_BRIDGE_UNBIND_TARGET,
                pid,
                0,
            );
            let _ = unregister_builtin_if_idle(state, device);
        }
        return Err(error);
    }
    if first_reference
        && requested_mode == BuiltinDebugMode::Vt
        && (caps & BRIDGE_CAP_PEB_SCRUB) != 0
    {
        let _ = bridge_target_operation(
            device,
            IOCTL_HV_BRIDGE_SCRUB_PEB,
            pid,
            0,
        );
    }

    {
        let mut lifecycle = state.lifecycle.lock();
        let entry = lifecycle.target_refs.entry(pid).or_insert(TargetAttachState {
            refs: 0,
            mode: requested_mode,
            binding_owned_by_worker,
            driver_unbound: false,
        });
        entry.refs = entry.refs.saturating_add(1);
    }

    Ok(BuiltinAttachResult {
        pid,
        mode: if requested_mode == BuiltinDebugMode::Vt {
            "vt".into()
        } else {
            "native".into()
        },
        debugger_protected: requested_mode == BuiltinDebugMode::Vt,
        vt_memory: requested_mode == BuiltinDebugMode::Vt
            && (caps & BRIDGE_CAP_MEMORY_IO) != 0,
        private_swbp: requested_mode == BuiltinDebugMode::Vt
            && (caps & BRIDGE_CAP_PRIVATE_SWBP) != 0,
        vt_hwbp: requested_mode == BuiltinDebugMode::Vt
            && (caps & BRIDGE_CAP_VT_HWBP) != 0,
        vt_step: requested_mode == BuiltinDebugMode::Vt
            && (caps & BRIDGE_CAP_VT_STEP) != 0,
        dr_fallback: requested_mode == BuiltinDebugMode::Native,
    })
}

#[tauri::command]
pub fn dbg_attach(
    app: AppHandle,
    state: State<'_, Arc<DebuggerHandles>>,
    device: State<'_, DeviceState>,
    pid: u32,
    mode: String,
) -> AppResult<BuiltinAttachResult> {
    let mode = parse_builtin_mode(&mode)?;
    let created_debug_session = !super::native_debug::is_session(pid);
    let attach = if mode == BuiltinDebugMode::Vt {
        let capabilities = bridge_register_builtin(state.inner(), device.inner())?;
        let private_debug_object =
            (capabilities & BRIDGE_STATE_PRIVATE_DEBUG_OBJECT) != 0;
        if private_debug_object {
            super::native_debug::attach_process_for_private_vt(app, pid)
        } else {
            super::native_debug::attach_process_for_native_vt(app, pid)
        }
    } else {
        super::native_debug::attach_process(app, pid)
    };
    if let Err(error) = attach {
        if mode == BuiltinDebugMode::Vt {
            let _ = unregister_builtin_if_idle(state.inner(), device.inner());
        }
        return Err(error);
    }
    let result = attach_builtin_target(
        state.inner(),
        device.inner(),
        pid,
        mode,
    );
    if result.is_err() && created_debug_session {
        let _ = super::native_debug::detach(pid);
        if mode == BuiltinDebugMode::Vt {
            let _ = unregister_builtin_if_idle(state.inner(), device.inner());
        }
    }
    result
}

struct PeLaunchMetadata {
    entry_rva: u32,
    size_of_image: u32,
}

fn read_u16_at(bytes: &[u8], offset: usize, label: &str) -> AppResult<u16> {
    let raw = bytes
        .get(offset..offset.saturating_add(2))
        .ok_or_else(|| AppError::Internal(format!("truncated PE while reading {label}")))?;
    Ok(u16::from_le_bytes(raw.try_into().unwrap()))
}

fn read_u32_at(bytes: &[u8], offset: usize, label: &str) -> AppResult<u32> {
    let raw = bytes
        .get(offset..offset.saturating_add(4))
        .ok_or_else(|| AppError::Internal(format!("truncated PE while reading {label}")))?;
    Ok(u32::from_le_bytes(raw.try_into().unwrap()))
}

fn parse_pe_launch_metadata(path: &Path) -> AppResult<PeLaunchMetadata> {
    let bytes = std::fs::read(path)
        .map_err(|error| AppError::Internal(format!("read {}: {error}", path.display())))?;
    if bytes.get(0..2) != Some(b"MZ") {
        return Err(AppError::Internal("selected file is not a PE image".into()));
    }
    let nt_offset = read_u32_at(&bytes, 0x3C, "e_lfanew")? as usize;
    if bytes.get(nt_offset..nt_offset.saturating_add(4)) != Some(b"PE\0\0") {
        return Err(AppError::Internal("selected file has no PE signature".into()));
    }
    let optional_size = read_u16_at(&bytes, nt_offset + 20, "optional-header size")? as usize;
    let optional = nt_offset
        .checked_add(24)
        .ok_or_else(|| AppError::Internal("PE optional-header offset overflow".into()))?;
    if optional_size < 60 || optional.saturating_add(optional_size) > bytes.len() {
        return Err(AppError::Internal("invalid PE optional header".into()));
    }
    match read_u16_at(&bytes, optional, "optional-header magic")? {
        0x10B | 0x20B => {}
        magic => {
            return Err(AppError::Internal(format!(
                "unsupported PE optional-header magic 0x{magic:04X}"
            )))
        }
    }
    let entry_rva = read_u32_at(&bytes, optional + 16, "AddressOfEntryPoint")?;
    let size_of_image = read_u32_at(&bytes, optional + 56, "SizeOfImage")?;
    if entry_rva == 0 || size_of_image == 0 || entry_rva >= size_of_image {
        return Err(AppError::Internal(format!(
            "invalid PE entry RVA 0x{entry_rva:X} for image size 0x{size_of_image:X}"
        )));
    }
    Ok(PeLaunchMetadata {
        entry_rva,
        size_of_image,
    })
}

fn create_suspended_process(
    exe: &Path,
    args: Option<&str>,
    working_dir: Option<&str>,
) -> AppResult<PROCESS_INFORMATION> {
    let directory = working_dir
        .filter(|value| !value.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| exe.parent().unwrap_or(Path::new(".")).to_path_buf());
    if !directory.is_dir() {
        return Err(AppError::Internal(format!(
            "debug working directory not found: {}",
            directory.display()
        )));
    }
    let arguments = args.unwrap_or_default().trim();
    let command_line = if arguments.is_empty() {
        format!("\"{}\"", exe.display())
    } else {
        format!("\"{}\" {arguments}", exe.display())
    };
    let mut command_line_w: Vec<u16> = std::ffi::OsStr::new(&command_line)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let directory_w: Vec<u16> = directory
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut startup = STARTUPINFOW {
        cb: std::mem::size_of::<STARTUPINFOW>() as u32,
        ..Default::default()
    };
    let mut process = PROCESS_INFORMATION::default();
    unsafe {
        CreateProcessW(
            None,
            PWSTR(command_line_w.as_mut_ptr()),
            None,
            None,
            false,
            PROCESS_CREATION_FLAGS(CREATE_NEW_CONSOLE.0 | CREATE_SUSPENDED.0),
            None,
            PWSTR(directory_w.as_ptr() as *mut u16),
            &startup,
            &mut process,
        )
    }
    .map_err(|error| AppError::Internal(format!("CreateProcessW(CREATE_SUSPENDED): {error}")))?;
    let _ = &mut startup;
    Ok(process)
}

fn launch_vt_executable(
    app: &AppHandle,
    state: &Arc<DebuggerHandles>,
    device: &DeviceState,
    freeze: &Arc<FreezeStore>,
    exe_path: String,
    args: Option<String>,
    working_dir: Option<String>,
) -> AppResult<BuiltinLaunchResult> {
    let exe = PathBuf::from(&exe_path);
    if !exe.is_file() {
        return Err(AppError::Internal(format!(
            "debug executable not found: {}",
            exe.display()
        )));
    }
    let pe = parse_pe_launch_metadata(&exe)?;
    let process = create_suspended_process(
        &exe,
        args.as_deref(),
        working_dir.as_deref(),
    )?;
    let pid = process.dwProcessId;
    let primary_tid = process.dwThreadId;
    // Transfer the creator handles into the retryable launch registry before
    // any attach/PE/VT operation can fail.  From this point onward `process`
    // is a non-owning view; rollback must go through abort_pending_launch.
    let previous_launch = state.pending_launches.lock().insert(
        pid,
        PendingBuiltinLaunch {
            process_handle: process.hProcess.0 as isize,
            primary_thread_handle: process.hThread.0 as isize,
            primary_tid,
            entry_address: 0,
        },
    );
    debug_assert!(
        previous_launch.is_none(),
        "a live creator handle prevents Windows from reusing its PID"
    );
    let operation = (|| -> AppResult<BuiltinLaunchResult> {
        let capabilities = bridge_register_builtin(state, device)?;
        let private_debug_object =
            (capabilities & BRIDGE_STATE_PRIVATE_DEBUG_OBJECT) != 0;
        {
            let control_plane = if private_debug_object {
                "VT private Dbgk"
            } else {
                "VT Windows DebugObject"
            };
            let diagnostic_path = super::native_debug::begin_vt_debug_diagnostics(
                pid,
                &exe,
                primary_tid,
                pe.entry_rva,
                pe.size_of_image,
                control_plane,
            );
            super::native_debug::private_dbgk_entry_diag(
                pid,
                "launch.created_suspended",
                format!(
                    "capabilities=0x{capabilities:X} process_handle={:p} thread_handle={:p} diagnostic_path={}",
                    process.hProcess.0,
                    process.hThread.0,
                    diagnostic_path
                        .as_deref()
                        .map(|path| path.display().to_string())
                        .unwrap_or_else(|| "unavailable".into()),
                ),
            );
        }
        let native_result = if private_debug_object {
            super::native_debug::attach_process_for_private_vt_launch(app.clone(), pid)
        } else {
            super::native_debug::attach_process_for_native_vt_launch(app.clone(), pid)
        };
        let native = match native_result {
            Ok(native) => {
                super::native_debug::private_dbgk_entry_diag(
                    pid,
                    "launch.debug_control_attached",
                    format!(
                        "reported_pid={} primary_tid={} runtime_entry=0x{:X} stopped_at_entry={}",
                        native.pid,
                        native.primary_tid,
                        native.entry_address,
                        native.stopped_at_entry,
                    ),
                );
                native
            }
            Err(error) => {
                super::native_debug::private_dbgk_entry_diag(
                    pid,
                    "launch.debug_control_attach.error",
                    error.to_string(),
                );
                return Err(error);
            }
        };
        let attach = match attach_builtin_target(state, device, pid, BuiltinDebugMode::Vt) {
            Ok(attach) => {
                super::native_debug::private_dbgk_entry_diag(
                    pid,
                    "launch.builtin_target_attached",
                    format!(
                        "private_swbp={} vt_hwbp={} vt_step={} vt_memory={}",
                        attach.private_swbp,
                        attach.vt_hwbp,
                        attach.vt_step,
                        attach.vt_memory,
                    ),
                );
                attach
            }
            Err(error) => {
                super::native_debug::private_dbgk_entry_diag(
                    pid,
                    "launch.builtin_target_attach.error",
                    error.to_string(),
                );
                return Err(error);
            }
        };
        if native.pid != pid || native.entry_address == 0 {
            super::native_debug::private_dbgk_entry_diag(
                pid,
                "launch.runtime_entry.error",
                format!(
                    "reported_pid={} runtime_entry=0x{:X}",
                    native.pid, native.entry_address
                ),
            );
            return Err(AppError::Internal(format!(
                "DebugObject did not resolve a runtime PE entry for PID {pid}"
            )));
        }
        let entry_address = native.entry_address;
        let image_base = entry_address
            .checked_sub(pe.entry_rva as u64)
            .ok_or_else(|| AppError::Internal("runtime entry precedes the PE image".into()))?;
        let image_end = image_base
            .checked_add(pe.size_of_image as u64)
            .ok_or_else(|| AppError::Internal("runtime image range overflow".into()))?;
        if image_base < 0x10000 || entry_address >= image_end {
            super::native_debug::private_dbgk_entry_diag(
                pid,
                "launch.runtime_entry.error",
                format!(
                    "entry=0x{entry_address:X} image_base=0x{image_base:X} image_end=0x{image_end:X}"
                ),
            );
            return Err(AppError::Internal("runtime entry lies outside the image".into()));
        }
        super::native_debug::private_dbgk_entry_diag(
            pid,
            "launch.runtime_entry",
            format!(
                "entry=0x{entry_address:X} image_base=0x{image_base:X} image_end=0x{image_end:X}"
            ),
        );

        let name = exe
            .file_name()
            .map(|value| value.to_string_lossy().into_owned())
            .unwrap_or_else(|| exe_path.clone());
        state.module_cache.lock().insert(
            pid,
            vec![ModuleInfo {
                base: image_base,
                size: pe.size_of_image as u64,
                name,
                path: exe_path.clone(),
            }],
        );
        let mut launches = state.pending_launches.lock();
        let launch = launches.get_mut(&pid).ok_or_else(|| {
            AppError::Internal("suspended launch ownership disappeared during setup".into())
        })?;
        launch.entry_address = entry_address;
        Ok(BuiltinLaunchResult {
            attach,
            primary_tid,
            entry_address,
            stopped_at_entry: false,
        })
    })();

    match operation {
        Ok(result) => Ok(result),
        Err(error) => {
            super::native_debug::private_dbgk_entry_diag(
                pid,
                "launch.setup.error",
                error.to_string(),
            );
            match detach_builtin_target(state, device, freeze, pid) {
                Ok(()) => {
                    super::native_debug::private_dbgk_entry_diag(
                        pid,
                        "launch.rollback",
                        "ok",
                    );
                    Err(error)
                }
                Err(rollback_error) => {
                    super::native_debug::private_dbgk_entry_diag(
                        pid,
                        "launch.rollback.error",
                        rollback_error.to_string(),
                    );
                    Err(AppError::Internal(format!(
                        "{error}; rollback retained suspended launch PID {pid} for retry: {rollback_error}"
                    )))
                }
            }
        }
    }
}

fn normalize_launch_spec(
    exe_path: String,
    args: Option<String>,
    working_dir: Option<String>,
    mode: BuiltinDebugMode,
) -> AppResult<BuiltinLaunchSpec> {
    let exe = std::fs::canonicalize(&exe_path).map_err(|error| {
        AppError::Internal(format!("debug executable not found: {exe_path}: {error}"))
    })?;
    if !exe.is_file() {
        return Err(AppError::Internal(format!(
            "debug executable is not a file: {}",
            exe.display()
        )));
    }
    let directory = match working_dir.as_deref().map(str::trim) {
        Some(value) if !value.is_empty() => std::fs::canonicalize(value).map_err(|error| {
            AppError::Internal(format!("debug working directory not found: {value}: {error}"))
        })?,
        _ => exe
            .parent()
            .unwrap_or(Path::new("."))
            .to_path_buf(),
    };
    if !directory.is_dir() {
        return Err(AppError::Internal(format!(
            "debug working directory is not a directory: {}",
            directory.display()
        )));
    }
    Ok(BuiltinLaunchSpec {
        exe_path: exe.to_string_lossy().into_owned(),
        args,
        working_dir: Some(directory.to_string_lossy().into_owned()),
        mode,
    })
}

async fn launch_executable_from_spec(
    app: AppHandle,
    state: &Arc<DebuggerHandles>,
    device: &DeviceState,
    freeze: &Arc<FreezeStore>,
    spec: &BuiltinLaunchSpec,
) -> AppResult<BuiltinLaunchResult> {
    let result = match spec.mode {
        BuiltinDebugMode::Vt => launch_vt_executable(
            &app,
            state,
            device,
            freeze,
            spec.exe_path.clone(),
            spec.args.clone(),
            spec.working_dir.clone(),
        ),
        BuiltinDebugMode::Native => {
            let exe_path = spec.exe_path.clone();
            let args = spec.args.clone();
            let working_dir = spec.working_dir.clone();
            let info = tokio::task::spawn_blocking(move || {
                super::native_debug::launch_executable(app, exe_path, args, working_dir)
            })
            .await
            .map_err(|error| AppError::Internal(format!("native launch task: {error}")))??;
            match attach_builtin_target(
                state,
                device,
                info.pid,
                BuiltinDebugMode::Native,
            ) {
                Ok(attach) => Ok(BuiltinLaunchResult {
                    attach,
                    primary_tid: info.primary_tid,
                    entry_address: info.entry_address,
                    stopped_at_entry: info.stopped_at_entry,
                }),
                Err(error) => {
                    let failed_pid = info.pid;
                    let abandon = tokio::task::spawn_blocking(move || {
                        super::native_debug::abandon(failed_pid)
                    })
                    .await
                    .map_err(|join_error| {
                        AppError::Internal(format!(
                            "{error}; native launch abandon task failed for PID {failed_pid}: {join_error}"
                        ))
                    })?;
                    match abandon {
                        Ok(()) => Err(error),
                        Err(abandon_error) => Err(AppError::Internal(format!(
                            "{error}; authoritative native launch abandon failed for PID {failed_pid}: {abandon_error}"
                        ))),
                    }
                }
            }
        }
    }?;
    state
        .launch_specs
        .lock()
        .insert(result.attach.pid, spec.clone());
    Ok(result)
}

#[tauri::command]
pub async fn dbg_launch_executable(
    app: AppHandle,
    state: State<'_, Arc<DebuggerHandles>>,
    device: State<'_, DeviceState>,
    freeze: State<'_, Arc<FreezeStore>>,
    exe_path: String,
    args: Option<String>,
    working_dir: Option<String>,
    mode: String,
) -> AppResult<BuiltinLaunchResult> {
    let spec = normalize_launch_spec(exe_path, args, working_dir, parse_builtin_mode(&mode)?)?;
    let _launch = state.launch_mutation.lock().await;
    launch_executable_from_spec(
        app,
        state.inner(),
        device.inner(),
        freeze.inner(),
        &spec,
    )
    .await
}

async fn run_to_entry_impl(
    state: &Arc<DebuggerHandles>,
    device: &DeviceState,
    freeze: &Arc<FreezeStore>,
    pid: u32,
) -> AppResult<BuiltinRunToEntryResult> {
    match builtin_target_mode(state, pid) {
        Some(BuiltinDebugMode::Native) => {
            let info = tokio::task::spawn_blocking(move || {
                super::native_debug::run_to_entry(pid)
            })
            .await
            .map_err(|error| AppError::Internal(format!("native run-to-entry task: {error}")))??;
            Ok(BuiltinRunToEntryResult {
                pid: info.pid,
                primary_tid: info.primary_tid,
                entry_address: info.entry_address,
                stopped_at_entry: info.stopped_at_entry,
            })
        }
        Some(BuiltinDebugMode::Vt) => {
            let (process_handle, thread_handle, primary_tid, entry_address) = {
                let launches = state.pending_launches.lock();
                let launch = launches.get(&pid).ok_or_else(|| AppError::Internal(format!(
                    "PID {pid} has no armed suspended VT launch"
                )))?;
                (
                    launch.process_handle,
                    launch.primary_thread_handle,
                    launch.primary_tid,
                    launch.entry_address,
                )
            };
            let private_dbgk_session = super::native_debug::is_private_dbgk_session(pid);
            let use_initial_system_breakpoint =
                super::native_debug::launch_uses_initial_system_breakpoint(pid)?;
            super::native_debug::private_dbgk_entry_diag(
                pid,
                "run_to_entry.begin",
                format!(
                    "private_dbgk={private_dbgk_session} primary_tid={primary_tid} entry=0x{entry_address:X} process_handle=0x{:X} thread_handle=0x{:X} initial_system_breakpoint={use_initial_system_breakpoint} {}",
                    process_handle as usize,
                    thread_handle as usize,
                    super::native_debug::private_dbgk_session_snapshot(pid),
                ),
            );

            state.entry_bps.lock().insert(pid, entry_address);
            super::native_debug::private_dbgk_entry_diag(
                pid,
                "run_to_entry.swbp_add",
                format!("begin address=0x{entry_address:X} scope_tid={primary_tid}"),
            );
            let entry_install = if private_dbgk_session {
                add_private_swbp_scoped(
                    state,
                    device,
                    pid,
                    entry_address,
                    primary_tid,
                )
            } else {
                add_private_swbp(state, device, pid, entry_address)
            };
            if let Err(error) = entry_install {
                super::native_debug::private_dbgk_entry_diag(
                    pid,
                    "run_to_entry.swbp_add.error",
                    error.to_string(),
                );
                state.entry_bps.lock().remove(&pid);
                let rollback = detach_builtin_target(
                    state,
                    device,
                    freeze,
                    pid,
                );
                return Err(match rollback {
                    Ok(()) => error,
                    Err(rollback_error) => AppError::Internal(format!(
                        "{error}; VT launch rollback failed: {rollback_error}"
                    )),
                });
            }
            super::native_debug::private_dbgk_entry_diag(
                pid,
                "run_to_entry.swbp_add",
                "ok",
            );

            if private_dbgk_session {
                if let Err(error) = super::native_debug::activate_private_vt_launch(pid) {
                    super::native_debug::private_dbgk_entry_diag(
                        pid,
                        "run_to_entry.launch_gate.error",
                        error.to_string(),
                    );
                    state.entry_bps.lock().remove(&pid);
                    let rollback = detach_builtin_target(state, device, freeze, pid);
                    return Err(match rollback {
                        Ok(()) => error,
                        Err(rollback_error) => AppError::Internal(format!(
                            "{error}; VT launch rollback failed: {rollback_error}"
                        )),
                    });
                }
            }

            let thread = HANDLE(thread_handle as _);
            let previous = unsafe { ResumeThread(thread) };
            if previous == u32::MAX {
                super::native_debug::private_dbgk_entry_diag(
                    pid,
                    "run_to_entry.resume_primary.error",
                    format!("tid={primary_tid}"),
                );
                let primary_error = AppError::Internal(format!(
                    "ResumeThread({primary_tid}) failed while running to entry"
                ));
                state.entry_bps.lock().remove(&pid);
                let rollback = detach_builtin_target(
                    state,
                    device,
                    freeze,
                    pid,
                );
                return Err(match rollback {
                    Ok(()) => primary_error,
                    Err(rollback_error) => AppError::Internal(format!(
                        "{primary_error}; VT launch rollback failed: {rollback_error}"
                    )),
                });
            }
            super::native_debug::private_dbgk_entry_diag(
                pid,
                "run_to_entry.resume_primary",
                format!("tid={primary_tid} previous_suspend_count={previous}"),
            );

            if use_initial_system_breakpoint {
                let initial_tid = match tokio::task::spawn_blocking(move || {
                    super::native_debug::wait_for_initial_system_breakpoint(
                        pid,
                        std::time::Duration::from_secs(30),
                    )
                })
                .await
                {
                    Ok(Ok(tid)) => tid,
                    Ok(Err(error)) => {
                        state.entry_bps.lock().remove(&pid);
                        let rollback = detach_builtin_target(state, device, freeze, pid);
                        return Err(match rollback {
                            Ok(()) => error,
                            Err(rollback_error) => AppError::Internal(format!(
                                "{error}; VT launch rollback failed: {rollback_error}"
                            )),
                        });
                    }
                    Err(error) => {
                        let primary_error = AppError::Internal(format!(
                            "wait for initial DebugObject breakpoint task failed: {error}"
                        ));
                        state.entry_bps.lock().remove(&pid);
                        let rollback = detach_builtin_target(state, device, freeze, pid);
                        return Err(match rollback {
                            Ok(()) => primary_error,
                            Err(rollback_error) => AppError::Internal(format!(
                                "{primary_error}; VT launch rollback failed: {rollback_error}"
                            )),
                        });
                    }
                };

                if let Err(error) =
                    super::native_debug::continue_initial_system_breakpoint(pid, initial_tid)
                {
                    super::native_debug::private_dbgk_entry_diag(
                        pid,
                        "run_to_entry.initial_breakpoint_continue.error",
                        error.to_string(),
                    );
                    state.entry_bps.lock().remove(&pid);
                    let rollback = detach_builtin_target(state, device, freeze, pid);
                    return Err(match rollback {
                        Ok(()) => error,
                        Err(rollback_error) => AppError::Internal(format!(
                            "{error}; VT launch rollback failed: {rollback_error}"
                        )),
                    });
                }
                super::native_debug::private_dbgk_entry_diag(
                    pid,
                    "run_to_entry.initial_breakpoint_continue",
                    format!("tid={initial_tid} ok"),
                );
            }

            let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
            let mut next_diagnostic = tokio::time::Instant::now();
            let mut detached = false;
            let mut target_exit_code = None;
            let stopped_at_entry = loop {
                let stopped = state.pending_private.lock().values().any(|event| {
                    event.process_id == pid && event.rip == entry_address && event.kind != 0
                });
                if stopped {
                    super::native_debug::private_dbgk_entry_diag(
                        pid,
                        "run_to_entry.hit_observed",
                        format!("entry=0x{entry_address:X}"),
                    );
                    break true;
                }
                let process = HANDLE(process_handle as _);
                if unsafe { WaitForSingleObject(process, 0) } == WAIT_OBJECT_0 {
                    let mut exit_code = 0u32;
                    let _ = unsafe { GetExitCodeProcess(process, &mut exit_code) };
                    target_exit_code = Some(exit_code);
                    super::native_debug::private_dbgk_entry_diag(
                        pid,
                        "run_to_entry.target_exit",
                        format!("exit_code=0x{exit_code:08X}"),
                    );
                    break false;
                }
                if builtin_target_mode(state, pid) != Some(BuiltinDebugMode::Vt) {
                    detached = true;
                    break false;
                }
                let now = tokio::time::Instant::now();
                if now >= next_diagnostic {
                    let pending = state
                        .pending_private
                        .lock()
                        .values()
                        .filter(|event| event.process_id == pid)
                        .map(|event| {
                            format!(
                                "seq={} tid={} rip=0x{:X} kind={} driver_continued={} thread_resumed={}",
                                event.sequence,
                                event.thread_id,
                                event.rip,
                                event.kind,
                                event.driver_continued,
                                event.thread_resumed,
                            )
                        })
                        .collect::<Vec<_>>();
                    let process = HANDLE(process_handle as _);
                    let wait = unsafe { WaitForSingleObject(process, 0) };
                    let mut exit_code = 0u32;
                    let exit_code_result = unsafe { GetExitCodeProcess(process, &mut exit_code) };
                    super::native_debug::private_dbgk_entry_diag(
                        pid,
                        "run_to_entry.progress",
                        format!(
                            "{} process_wait={} process_signaled={} exit_code={} exit_query={} pending_private_count={} pending_private=[{}]",
                            super::native_debug::private_dbgk_session_snapshot(pid),
                            wait.0,
                            wait == WAIT_OBJECT_0,
                            if exit_code_result.is_ok() {
                                format!("0x{exit_code:08X}")
                            } else {
                                "unavailable".into()
                            },
                            if exit_code_result.is_ok() { "ok" } else { "error" },
                            pending.len(),
                            pending.join(" | "),
                        ),
                    );
                    next_diagnostic = now + std::time::Duration::from_secs(1);
                }
                if now >= deadline {
                    break false;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            };
            if detached {
                super::native_debug::private_dbgk_entry_diag(
                    pid,
                    "run_to_entry.detached",
                    super::native_debug::private_dbgk_session_snapshot(pid),
                );
                return Err(AppError::Internal(format!(
                    "PID {pid} detached while running to its entry point"
                )));
            }
            if !stopped_at_entry {
                let failure = target_exit_code
                    .map(|exit_code| {
                        format!(
                            "PID {pid} exited with 0x{exit_code:08X} before VT entry breakpoint 0x{entry_address:X}"
                        )
                    })
                    .unwrap_or_else(|| {
                        format!(
                            "timed out waiting for PID {pid} VT entry breakpoint at 0x{entry_address:X}"
                        )
                    });
                super::native_debug::private_dbgk_entry_diag(
                    pid,
                    if target_exit_code.is_some() {
                        "run_to_entry.exit_before_entry"
                    } else {
                        "run_to_entry.timeout"
                    },
                    format!(
                        "entry=0x{entry_address:X} {}",
                        super::native_debug::private_dbgk_session_snapshot(pid),
                    ),
                );
                let diagnostic_suffix = if private_dbgk_session {
                    super::native_debug::private_dbgk_entry_diagnostic_path(pid)
                        .map(|path| format!("; diagnostic log: {}", path.display()))
                        .unwrap_or_else(|| "; diagnostic log unavailable".into())
                } else {
                    String::new()
                };
                let primary_error = AppError::Internal(format!(
                    "{failure}{diagnostic_suffix}"
                ));
                state.entry_bps.lock().remove(&pid);
                let rollback = detach_builtin_target(state, device, freeze, pid);
                return Err(match rollback {
                    Ok(()) => primary_error,
                    Err(rollback_error) => AppError::Internal(format!(
                        "{primary_error}; VT launch rollback failed: {rollback_error}"
                    )),
                });
            }
            if (builtin_capabilities(state) & BRIDGE_CAP_PEB_SCRUB) != 0 {
                if let Err(error) = bridge_target_operation(
                    device,
                    IOCTL_HV_BRIDGE_SCRUB_PEB,
                    pid,
                    BRIDGE_PEB_CLOAK_ACTIVATE,
                ) {
                    super::native_debug::private_dbgk_entry_diag(
                        pid,
                        "run_to_entry.peb_cloak_activate.error",
                        error.to_string(),
                    );
                    state.entry_bps.lock().remove(&pid);
                    let rollback = detach_builtin_target(state, device, freeze, pid);
                    return Err(match rollback {
                        Ok(()) => error,
                        Err(rollback_error) => AppError::Internal(format!(
                            "{error}; VT launch rollback failed: {rollback_error}"
                        )),
                    });
                }
                super::native_debug::private_dbgk_entry_diag(
                    pid,
                    "run_to_entry.peb_cloak_activate",
                    "ok",
                );
            }
            let launch = state
                .pending_launches
                .lock()
                .remove(&pid)
                .ok_or_else(|| AppError::Internal(format!(
                    "PID {pid} detached while closing its VT launch handles"
                )))?;
            close_pending_launch(launch)?;
            super::native_debug::private_dbgk_entry_diag(
                pid,
                "run_to_entry.success",
                format!("tid={primary_tid} entry=0x{entry_address:X}"),
            );
            Ok(BuiltinRunToEntryResult {
                pid,
                primary_tid,
                entry_address,
                stopped_at_entry,
            })
        }
        None => Err(AppError::Internal(format!(
            "PID {pid} is not attached to the built-in debugger"
        ))),
    }
}

#[tauri::command]
pub async fn dbg_run_to_entry(
    state: State<'_, Arc<DebuggerHandles>>,
    device: State<'_, DeviceState>,
    freeze: State<'_, Arc<FreezeStore>>,
    pid: u32,
) -> AppResult<BuiltinRunToEntryResult> {
    run_to_entry_impl(state.inner(), device.inner(), freeze.inner(), pid).await
}

fn get_or_open(state: &Arc<DebuggerHandles>, pid: u32) -> AppResult<HANDLE> {
    {
        let g = state.procs.lock();
        if let Some(h) = g.get(&pid).copied() {
            return Ok(HANDLE(h as _));
        }
    }
    // 不再用 PROCESS_ALL_ACCESS — 它对很多保护进程会返 NULL handle 但 Ok,
    // 后续 WriteProcessMemory 返 0x57 INVALID_PARAMETER. 只要必要权限:
    let h = unsafe {
        OpenProcess(
            PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION,
            false,
            pid,
        )
        .map_err(|e| AppError::Internal(format!("OpenProcess({pid}): {e}")))?
    };
    if h.is_invalid() || h.0.is_null() {
        return Err(AppError::Internal(format!(
            "OpenProcess({pid}) 返 NULL handle (进程可能受保护)"
        )));
    }
    state.procs.lock().insert(pid, h.0 as isize);
    Ok(h)
}

// 关闭 pid 对应的所有资源
fn close_pending_launch(launch: PendingBuiltinLaunch) -> AppResult<()> {
    let process = HANDLE(launch.process_handle as _);
    let thread = HANDLE(launch.primary_thread_handle as _);
    unsafe {
        if !thread.is_invalid() && !thread.0.is_null() {
            let _ = CloseHandle(thread);
        }
        if !process.is_invalid() && !process.0.is_null() {
            let _ = CloseHandle(process);
        }
    }
    Ok(())
}

fn abort_pending_launch(state: &Arc<DebuggerHandles>, pid: u32) -> AppResult<()> {
    let mut launches = state.pending_launches.lock();
    let Some(launch) = launches.get(&pid) else {
        return Ok(());
    };
    let process = HANDLE(launch.process_handle as _);
    if let Err(terminate_error) = unsafe { TerminateProcess(process, 0xE000_0001) } {
        let mut exit_code = STILL_ACTIVE.0 as u32;
        let query = unsafe { GetExitCodeProcess(process, &mut exit_code) };
        if query.is_err() || exit_code == STILL_ACTIVE.0 as u32 {
            return Err(AppError::Internal(format!(
                "TerminateProcess failed for suspended debug launch PID {pid}; ownership retained for retry: {terminate_error}"
            )));
        }
        // TerminateProcess commonly reports ACCESS_DENIED once a process has
        // already exited.  A non-STILL_ACTIVE exit code is authoritative, so
        // its creator handles can be retired without leaving a live orphan.
    }
    let launch = launches
        .remove(&pid)
        .expect("pending launch disappeared while its map lock was held");
    drop(launches);
    close_pending_launch(launch)
}

fn release_pid(state: &Arc<DebuggerHandles>, pid: u32) {
    let h = state.procs.lock().remove(&pid);
    if let Some(h) = h {
        unsafe {
            let _ = CloseHandle(HANDLE(h as _));
        }
    }
    state.sw_bps.lock().remove(&pid);
    state.scan_state.lock().remove(&pid);
    state.transient_bps.lock().remove(&pid);
    state.entry_bps.lock().remove(&pid);
    state
        .vt_step_gates
        .lock()
        .retain(|_, (gate_pid, _, _)| *gate_pid != pid);
    state.module_cache.lock().remove(&pid);
    state.launch_specs.lock().remove(&pid);
}

fn cleanup_vt_step_gates_for_pid(
    state: &Arc<DebuggerHandles>,
    device: &DeviceState,
    pid: u32,
) -> Vec<String> {
    let tids: Vec<u32> = state
        .vt_step_gates
        .lock()
        .iter()
        .filter_map(|(tid, (gate_pid, _, _))| (*gate_pid == pid).then_some(*tid))
        .collect();
    let mut failures = Vec::new();
    for tid in tids {
        if let Err(error) = cancel_vt_step_gate(state, device, pid, tid) {
            failures.push(format!("TID {tid}: {error}"));
        }
    }
    failures
}

fn continue_private_event(
    device: &DeviceState,
    pending: &PendingBuiltinPrivateEvent,
) -> AppResult<()> {
    // Private VT HWBP events are observational: the driver did not enter the
    // SWBP HitPending state, so there is no IOCTL continue transaction.
    if pending.kind == 0 {
        super::native_debug::private_dbgk_entry_diag(
            pending.process_id,
            "private_swbp.continue",
            format!("sequence={} kind=0 observational", pending.sequence),
        );
        return Ok(());
    }
    let request = PrivateContinueRequest {
        version: BRIDGE_PROTOCOL_VERSION,
        continue_status: DBG_CONTINUE_STATUS,
        sequence: pending.sequence,
        process_id: pending.process_id,
        thread_id: pending.thread_id,
        thread_token: pending.thread_token,
    };
    let mut result = OperationResult::default();
    let written = match device.ioctl(
        IOCTL_HV_DBG_CONTINUE,
        pod_bytes(&request),
        pod_bytes_mut(&mut result),
    ) {
        Ok(written) => written,
        Err(error) => {
            super::native_debug::private_dbgk_entry_diag(
                pending.process_id,
                "private_swbp.continue.error",
                format!(
                    "sequence={} tid={} ioctl_error={error}",
                    pending.sequence, pending.thread_id
                ),
            );
            return Err(error);
        }
    };
    super::native_debug::private_dbgk_entry_diag(
        pending.process_id,
        "private_swbp.continue.result",
        format!(
            "sequence={} tid={} bytes={written} status={} reserved={} info=0x{:X}",
            pending.sequence,
            pending.thread_id,
            result.status,
            result.reserved,
            result.info,
        ),
    );
    if written as usize != std::mem::size_of::<OperationResult>()
        || result.reserved != 0
        || result.status != BRIDGE_STATUS_SUCCESS as u32
    {
        return Err(AppError::Internal(format!(
            "private continue failed: bytes={written}, status={}, reserved={}",
            result.status, result.reserved,
        )));
    }
    Ok(())
}

fn drain_pending_private_events_for_pid(
    state: &Arc<DebuggerHandles>,
    pid: u32,
) -> Vec<PendingBuiltinPrivateEvent> {
    {
        let mut map = state.pending_private.lock();
        let tids: Vec<u32> = map
            .iter()
            .filter_map(|(tid, event)| (event.process_id == pid).then_some(*tid))
            .collect();
        tids.into_iter().filter_map(|tid| map.remove(&tid)).collect()
    }
}

fn resume_and_close_pending_private_events(
    pending: Vec<PendingBuiltinPrivateEvent>,
) -> (Vec<PendingBuiltinPrivateEvent>, Vec<String>) {
    let mut retry = Vec::new();
    let mut failures = Vec::new();
    for mut event in pending {
        let handle = HANDLE(event.thread_handle as _);
        if handle.is_invalid() || handle.0.is_null() {
            failures.push(format!(
                "TID {} has an invalid pending suspension handle",
                event.thread_id
            ));
            retry.push(event);
            continue;
        }

        if !event.thread_resumed {
            let previous = unsafe { ResumeThread(handle) };
            if previous != u32::MAX {
                event.thread_resumed = true;
            } else {
                let resume_error = unsafe { windows::Win32::Foundation::GetLastError() };
                let mut exit_code = STILL_ACTIVE.0 as u32;
                let exited = unsafe { GetExitCodeThread(handle, &mut exit_code) }.is_ok()
                    && exit_code != STILL_ACTIVE.0 as u32;
                if exited {
                    event.thread_resumed = true;
                } else {
                    failures.push(format!(
                        "ResumeThread({}) failed (GLE=0x{:X}); suspension ownership retained",
                        event.thread_id, resume_error.0
                    ));
                    retry.push(event);
                    continue;
                }
            }
        }

        if unsafe { CloseHandle(handle) }.is_err() {
            failures.push(format!(
                "CloseHandle for resumed/exited TID {} failed; handle ownership retained",
                event.thread_id
            ));
            retry.push(event);
        }
    }
    (retry, failures)
}

fn requeue_pending_private_events(
    state: &Arc<DebuggerHandles>,
    pending: Vec<PendingBuiltinPrivateEvent>,
) {
    let mut pending_map = state.pending_private.lock();
    for event in pending {
        let previous = pending_map.insert(event.thread_id, event);
        debug_assert!(
            previous.is_none(),
            "lifecycle_mutation must exclude a concurrent pending-event insert"
        );
    }
}

fn detach_last_target(
    state: &Arc<DebuggerHandles>,
    device: &DeviceState,
    freeze: &Arc<FreezeStore>,
    pid: u32,
    target: TargetAttachState,
) -> AppResult<()> {
    let mut failures = Vec::new();
    let mut pending = Vec::new();
    let mut hwbp_cleanup_error = None;
    let mut step_cleanup_errors = Vec::new();
    let mut driver_detached =
        target.mode != BuiltinDebugMode::Vt || target.driver_unbound;
    let mut native_detached = false;

    // Stop background writes before dismantling breakpoint and binding state.
    freeze
        .inner
        .lock()
        .retain(|(target_pid, _), _| *target_pid != pid);

    if let Err(error) = abort_pending_launch(state, pid) {
        return Err(AppError::Internal(format!(
            "built-in debugger detach PID {pid} is incomplete: pending launch cleanup: {error}"
        )));
    }

    if target.mode == BuiltinDebugMode::Vt {
        if target.driver_unbound {
            state
                .vt_step_gates
                .lock()
                .retain(|_, (gate_pid, _, _)| *gate_pid != pid);
        } else if device.is_open() {
            step_cleanup_errors = cleanup_vt_step_gates_for_pid(state, device, pid);
        } else if state
            .vt_step_gates
            .lock()
            .values()
            .any(|(gate_pid, _, _)| *gate_pid == pid)
        {
            step_cleanup_errors.push("driver device is closed while VT steps remain active".into());
        }
        pending = drain_pending_private_events_for_pid(state, pid);
    }
    if !(target.mode == BuiltinDebugMode::Vt && target.driver_unbound) {
        if let Err(error) = super::hwbp::hwbp_clear_all_for_target(device, pid) {
            hwbp_cleanup_error = Some(format!("HWBP cleanup: {error}"));
        }
    }

    if target.mode == BuiltinDebugMode::Vt && target.binding_owned_by_worker {
        match super::native_debug::detach(pid) {
            Ok(_) => native_detached = true,
            Err(error) => {
                requeue_pending_private_events(state, pending);
                return Err(AppError::Internal(format!(
                    "built-in debugger detach PID {pid} is incomplete: VT DebugObject worker detach: {error}"
                )));
            }
        }
    }

    if target.mode == BuiltinDebugMode::Vt && !target.driver_unbound {
        // Worker-owned bindings have already been released before reaching
        // this point.  Keep one sequential idempotent UNBIND as the
        // authoritative fallback if the worker's device call failed; never
        // race it against worker/DebugObject teardown.
        if device.is_open() {
            if let Err(error) = bridge_target_operation(
                device,
                IOCTL_HV_BRIDGE_UNBIND_TARGET,
                pid,
                0,
            ) {
                failures.push(format!("VT target unbind: {error}"));
            } else {
                driver_detached = true;
                if let Some(entry) = state.lifecycle.lock().target_refs.get_mut(&pid) {
                    entry.driver_unbound = true;
                }
            }
        } else {
            failures.push("VT target unbind: driver device is closed".into());
        }
    }

    if target.mode == BuiltinDebugMode::Vt && driver_detached {
        super::hwbp::hwbp_forget_target(pid);
    } else if let Some(error) = hwbp_cleanup_error.take() {
        failures.push(error);
    }

    if !driver_detached {
        // Keep the target reference so a second close/detach can retry the
        // authoritative UNBIND.  Dropping local ownership here would make the
        // UI believe cleanup succeeded while the driver still owns overlays.
        // UNBIND failed, so events with a driver transaction retain both their
        // sequence and suspended thread handle for retry. Observational events
        // without a driver-side continue transaction may release their local
        // suspension immediately.
        let mut continued = Vec::new();
        let mut still_driver_pending = Vec::new();
        for event in pending {
            if event.driver_continued {
                continued.push(event);
            } else {
                still_driver_pending.push(event);
            }
        }
        requeue_pending_private_events(state, still_driver_pending);
        failures.extend(step_cleanup_errors);
        let (resume_retry, resume_failures) =
            resume_and_close_pending_private_events(continued);
        requeue_pending_private_events(state, resume_retry);
        failures.extend(resume_failures);
        return Err(AppError::Internal(format!(
            "built-in debugger detach PID {pid} is incomplete: {}",
            failures.join("; ")
        )));
    }

    state
        .vt_step_gates
        .lock()
        .retain(|_, (gate_pid, _, _)| *gate_pid != pid);

    // An authoritative UNBIND has cleared every remaining driver sequence.
    // Local suspension-handle ownership is committed separately: a failed
    // ResumeThread must keep target_refs alive for a later cleanup retry.
    if target.mode == BuiltinDebugMode::Vt {
        for event in &mut pending {
            event.driver_continued = true;
        }
    }
    if !native_detached {
        match super::native_debug::detach(pid) {
            Ok(_) => native_detached = true,
            Err(error) => failures.push(format!("Windows DebugObject detach: {error}")),
        }
    }
    let (resume_retry, resume_failures) =
        resume_and_close_pending_private_events(pending);
    if !resume_retry.is_empty() {
        requeue_pending_private_events(state, resume_retry);
        if target.mode == BuiltinDebugMode::Vt {
            if let Some(entry) = state.lifecycle.lock().target_refs.get_mut(&pid) {
                entry.driver_unbound = true;
            }
        }
        failures.extend(resume_failures);
        return Err(AppError::Internal(format!(
            "built-in debugger detach PID {pid} is incomplete: {}",
            failures.join("; ")
        )));
    }
    failures.extend(resume_failures);

    if !native_detached {
        if target.mode == BuiltinDebugMode::Vt {
            if let Some(entry) = state.lifecycle.lock().target_refs.get_mut(&pid) {
                entry.driver_unbound = true;
            }
        }
        return Err(AppError::Internal(format!(
            "built-in debugger detach PID {pid} is incomplete: {}",
            failures.join("; ")
        )));
    }

    state.lifecycle.lock().target_refs.remove(&pid);
    release_pid(state, pid);

    if target.mode == BuiltinDebugMode::Vt {
        if let Err(error) = unregister_builtin_if_idle(state, device) {
            failures.push(format!("debugger unregister: {error}"));
        }
    }

    if failures.is_empty() {
        Ok(())
    } else {
        Err(AppError::Internal(format!(
            "built-in debugger detach PID {pid} completed with cleanup errors: {}",
            failures.join("; ")
        )))
    }
}

fn detach_builtin_target(
    state: &Arc<DebuggerHandles>,
    device: &DeviceState,
    freeze: &Arc<FreezeStore>,
    pid: u32,
) -> AppResult<()> {
    let _mutation = state.lifecycle_mutation.lock();
    let target = {
        let lifecycle = state.lifecycle.lock();
        lifecycle.target_refs.get(&pid).copied()
    };
    let Some(target) = target else {
        // A setup failure can own a suspended process before target_refs was
        // published. Retire both the creator handles and whichever immutable
        // DebugObject control plane owns the unpublished process.
        abort_pending_launch(state, pid)?;
        super::native_debug::abandon(pid)?;
        release_pid(state, pid);
        return unregister_builtin_if_idle(state, device);
    };
    if target.refs > 1 {
        if let Some(entry) = state.lifecycle.lock().target_refs.get_mut(&pid) {
            entry.refs -= 1;
        }
        return Ok(());
    }

    detach_last_target(state, device, freeze, pid, target)
}

fn detach_builtin_target_authoritative(
    state: &Arc<DebuggerHandles>,
    device: &DeviceState,
    freeze: &Arc<FreezeStore>,
    pid: u32,
) -> AppResult<()> {
    let _mutation = state.lifecycle_mutation.lock();
    let target = state.lifecycle.lock().target_refs.get(&pid).copied();
    let Some(target) = target else {
        abort_pending_launch(state, pid)?;
        super::native_debug::abandon(pid)?;
        release_pid(state, pid);
        return unregister_builtin_if_idle(state, device);
    };
    detach_last_target(state, device, freeze, pid, target)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RestartProcessIdentity {
    pid: u32,
    create_time: u64,
}

struct RestartProcess {
    handle: isize,
    identity: RestartProcessIdentity,
}

fn query_live_process_identity(
    process: HANDLE,
    requested_pid: u32,
) -> AppResult<Option<RestartProcessIdentity>> {
    // The ordinary memory handle intentionally does not require SYNCHRONIZE.
    // Querying its exit code works for both that cached handle and the
    // dedicated restart handle without treating WAIT_FAILED as "still live".
    let mut exit_code = STILL_ACTIVE.0 as u32;
    unsafe { GetExitCodeProcess(process, &mut exit_code) }.map_err(|error| {
        AppError::Internal(format!(
            "GetExitCodeProcess({requested_pid}) for restart identity: {error}"
        ))
    })?;
    if exit_code != STILL_ACTIVE.0 as u32 {
        return Ok(None);
    }
    let actual_pid = unsafe { GetProcessId(process) };
    if actual_pid == 0 || actual_pid != requested_pid {
        return Err(AppError::Internal(format!(
            "restart process identity mismatch: requested PID {requested_pid}, handle PID {actual_pid}"
        )));
    }

    let mut create_time = FILETIME::default();
    let mut exit_time = FILETIME::default();
    let mut kernel_time = FILETIME::default();
    let mut user_time = FILETIME::default();
    unsafe {
        GetProcessTimes(
            process,
            &mut create_time,
            &mut exit_time,
            &mut kernel_time,
            &mut user_time,
        )
    }
    .map_err(|error| {
        AppError::Internal(format!(
            "GetProcessTimes({requested_pid}) for restart identity: {error}"
        ))
    })?;
    let create_time = ((create_time.dwHighDateTime as u64) << 32)
        | create_time.dwLowDateTime as u64;
    if create_time == 0 {
        return Err(AppError::Internal(format!(
            "PID {requested_pid} has no stable process creation identity"
        )));
    }
    Ok(Some(RestartProcessIdentity {
        pid: actual_pid,
        create_time,
    }))
}

fn open_restart_process(
    state: &Arc<DebuggerHandles>,
    pid: u32,
) -> AppResult<Option<RestartProcess>> {
    let cached = state.procs.lock().get(&pid).copied().ok_or_else(|| {
        AppError::Internal(format!(
            "restart refused for PID {pid}: current debugger session has no cached process handle"
        ))
    })?;
    let Some(cached_identity) =
        query_live_process_identity(HANDLE(cached as _), pid)?
    else {
        return Ok(None);
    };

    let process = unsafe {
        OpenProcess(
            PROCESS_TERMINATE | PROCESS_SYNCHRONIZE | PROCESS_QUERY_INFORMATION,
            false,
            pid,
        )
    }
    .map_err(|error| {
        AppError::Internal(format!(
            "OpenProcess({pid}) for authoritative restart: {error}"
        ))
    })?;
    let opened_identity = match query_live_process_identity(process, pid) {
        Ok(Some(identity)) => identity,
        Ok(None) => {
            unsafe {
                let _ = CloseHandle(process);
            }
            return Ok(None);
        }
        Err(error) => {
            unsafe {
                let _ = CloseHandle(process);
            }
            return Err(error);
        }
    };
    if opened_identity != cached_identity {
        unsafe {
            let _ = CloseHandle(process);
        }
        return Err(AppError::Internal(format!(
            "restart refused for PID {pid}: PID was reused (cached create=0x{:X}, opened create=0x{:X})",
            cached_identity.create_time, opened_identity.create_time,
        )));
    }
    Ok(Some(RestartProcess {
        handle: process.0 as isize,
        identity: opened_identity,
    }))
}

fn terminate_restart_process(process: RestartProcess) -> AppResult<()> {
    let pid = process.identity.pid;
    let handle = HANDLE(process.handle as _);
    let result = (|| {
        let identity = query_live_process_identity(handle, pid)?;
        if identity.is_none() {
            return Ok(());
        }
        if identity != Some(process.identity) {
            return Err(AppError::Internal(format!(
                "restart termination refused for PID {pid}: process identity changed"
            )));
        }
        if let Err(error) = unsafe { TerminateProcess(handle, 0xE000_0004) } {
            let mut exit_code = STILL_ACTIVE.0 as u32;
            if unsafe { GetExitCodeProcess(handle, &mut exit_code) }.is_err()
                || exit_code == STILL_ACTIVE.0 as u32
            {
                return Err(AppError::Internal(format!(
                    "TerminateProcess({pid}) during restart: {error}"
                )));
            }
        }
        let wait = unsafe { WaitForSingleObject(handle, 10_000) };
        if wait != WAIT_OBJECT_0 {
            return Err(AppError::Internal(format!(
                "PID {pid} did not terminate during restart (wait=0x{:08X})",
                wait.0
            )));
        }
        Ok(())
    })();
    unsafe {
        let _ = CloseHandle(handle);
    }
    result
}

#[tauri::command]
pub async fn dbg_detach(
    state: State<'_, Arc<DebuggerHandles>>,
    device: State<'_, DeviceState>,
    freeze: State<'_, Arc<FreezeStore>>,
    pid: u32,
) -> AppResult<()> {
    let _step = state.step_mutation.lock().await;
    super::native_debug::private_dbgk_entry_diag(
        pid,
        "lifecycle.detach.begin",
        super::native_debug::private_dbgk_session_snapshot(pid),
    );
    let result = detach_builtin_target(state.inner(), device.inner(), freeze.inner(), pid);
    super::native_debug::private_dbgk_entry_diag(
        pid,
        "lifecycle.detach.result",
        match &result {
            Ok(()) => "ok".into(),
            Err(error) => format!("error={error}"),
        },
    );
    result
}

#[tauri::command]
pub async fn dbg_restart_process(
    app: AppHandle,
    state: State<'_, Arc<DebuggerHandles>>,
    device: State<'_, DeviceState>,
    freeze: State<'_, Arc<FreezeStore>>,
    pid: u32,
) -> AppResult<BuiltinRestartResult> {
    let _launch = state.launch_mutation.lock().await;
    let _step = state.step_mutation.lock().await;
    let spec = state.launch_specs.lock().get(&pid).cloned().ok_or_else(|| {
        AppError::Internal(format!(
            "PID {pid} is an attach-only session and cannot be restarted"
        ))
    })?;
    let target = state.lifecycle.lock().target_refs.get(&pid).copied();
    super::native_debug::private_dbgk_entry_diag(
        pid,
        "lifecycle.restart.begin",
        format!(
            "mode={:?} target_owned={} {}",
            spec.mode,
            target.is_some(),
            super::native_debug::private_dbgk_session_snapshot(pid),
        ),
    );
    if let Some(target) = target {
        if target.refs != 1 || target.mode != spec.mode {
            return Err(AppError::Internal(format!(
                "restart refused for PID {pid}: target ownership is not unique or its mode changed"
            )));
        }
    }
    // Replacing a target is one control-plane transaction.  Keep debugger
    // registration and the Dbgk hook set stable between old-session teardown
    // and publication of the replacement.
    let _registration_pin = BuiltinRestartRegistrationPin::acquire(
        state.inner(),
        device.inner(),
        spec.mode,
    );

    // A worker may already have retired after the target exited.  A live
    // lifecycle target must still have its identity handle; a restart
    // tombstone intentionally has neither target ownership nor a live handle.
    let old_process = if target.is_some() {
        open_restart_process(state.inner(), pid)?
    } else {
        None
    };
    if let Err(error) = detach_builtin_target_authoritative(
        state.inner(),
        device.inner(),
        freeze.inner(),
        pid,
    ) {
        if let Some(process) = old_process {
            unsafe {
                let _ = CloseHandle(HANDLE(process.handle as _));
            }
        }
        return Err(error);
    }
    // release_pid removes the old index during authoritative teardown.  Keep
    // one restart tombstone until the replacement is stopped at entry so a
    // failed launch can be retried from the frontend's still-current old PID.
    state.launch_specs.lock().insert(pid, spec.clone());
    super::native_debug::private_dbgk_entry_diag(
        pid,
        "lifecycle.restart.old_detached",
        "restart tombstone retained",
    );
    if let Some(process) = old_process {
        terminate_restart_process(process)?;
        super::native_debug::private_dbgk_entry_diag(
            pid,
            "lifecycle.restart.old_terminated",
            "ok",
        );
    }

    let launch = launch_executable_from_spec(
        app.clone(),
        state.inner(),
        device.inner(),
        freeze.inner(),
        &spec,
    )
    .await?;
    let new_pid = launch.attach.pid;
    super::native_debug::private_dbgk_entry_diag(
        new_pid,
        "lifecycle.restart.replacement_launched",
        format!("old_pid={pid}"),
    );
    let new_process = match open_restart_process(state.inner(), new_pid) {
        Ok(Some(process)) => process,
        Ok(None) => {
            let error = AppError::Internal(format!(
                "replacement PID {new_pid} exited before run-to-entry"
            ));
            let cleanup = detach_builtin_target_authoritative(
                state.inner(),
                device.inner(),
                freeze.inner(),
                new_pid,
            );
            return Err(match cleanup {
                Ok(()) => error,
                Err(cleanup_error) => AppError::Internal(format!(
                    "{error}; cleanup of replacement PID {new_pid} failed: {cleanup_error}"
                )),
            });
        }
        Err(error) => {
            let cleanup = detach_builtin_target_authoritative(
                state.inner(),
                device.inner(),
                freeze.inner(),
                new_pid,
            );
            return Err(match cleanup {
                Ok(()) => error,
                Err(cleanup_error) => AppError::Internal(format!(
                    "{error}; cleanup of replacement PID {new_pid} failed: {cleanup_error}"
                )),
            });
        }
    };

    let stopped = run_to_entry_impl(
        state.inner(),
        device.inner(),
        freeze.inner(),
        new_pid,
    )
    .await;
    let stopped = match stopped {
        Ok(stopped) if stopped.stopped_at_entry => stopped,
        Ok(_) => {
            let primary_error = AppError::Internal(format!(
                "replacement PID {new_pid} did not stop at its entry point"
            ));
            let cleanup = detach_builtin_target_authoritative(
                state.inner(),
                device.inner(),
                freeze.inner(),
                new_pid,
            );
            let termination = terminate_restart_process(new_process);
            return Err(match (cleanup, termination) {
                (Ok(()), Ok(())) => primary_error,
                (cleanup, termination) => AppError::Internal(format!(
                    "{primary_error}; replacement cleanup: {:?}; termination: {:?}",
                    cleanup.err(),
                    termination.err()
                )),
            });
        }
        Err(primary_error) => {
            let cleanup = detach_builtin_target_authoritative(
                state.inner(),
                device.inner(),
                freeze.inner(),
                new_pid,
            );
            let termination = terminate_restart_process(new_process);
            return Err(match (cleanup, termination) {
                (Ok(()), Ok(())) => primary_error,
                (cleanup, termination) => AppError::Internal(format!(
                    "{primary_error}; replacement cleanup: {:?}; termination: {:?}",
                    cleanup.err(),
                    termination.err()
                )),
            });
        }
    };
    unsafe {
        let _ = CloseHandle(HANDLE(new_process.handle as _));
    }

    let process_name = Path::new(&spec.exe_path)
        .file_name()
        .map(|value| value.to_string_lossy().into_owned())
        .unwrap_or_else(|| spec.exe_path.clone());
    let payload = BuiltinRestartResult {
        old_pid: pid,
        new_pid,
        process_name,
        attach: launch.attach,
        primary_tid: stopped.primary_tid,
        entry_address: stopped.entry_address,
        stopped_at_entry: true,
    };
    app.emit("dbg-debuggee-restarted", payload.clone())
        .map_err(|error| {
            AppError::Internal(format!(
                "replacement PID {new_pid} stopped at entry, but restart event emission failed: {error}"
            ))
        })?;
    if pid != new_pid {
        state.launch_specs.lock().remove(&pid);
    }
    super::native_debug::private_dbgk_entry_diag(
        new_pid,
        "lifecycle.restart.success",
        format!("old_pid={pid} entry=0x{:X}", stopped.entry_address),
    );
    Ok(payload)
}

fn force_cleanup_builtin_target(
    state: &Arc<DebuggerHandles>,
    device: &DeviceState,
    freeze: &Arc<FreezeStore>,
    pid: u32,
    fallback_target: TargetAttachState,
) -> AppResult<()> {
    let target = state
        .lifecycle
        .lock()
        .target_refs
        .get(&pid)
        .copied()
        .unwrap_or(fallback_target);

    freeze
        .inner
        .lock()
        .retain(|(target_pid, _), _| *target_pid != pid);
    if target.mode == BuiltinDebugMode::Vt && device.is_open() {
        let _ = cleanup_vt_step_gates_for_pid(state, device, pid);
    }
    abort_pending_launch(state, pid)?;

    // Abandon is the shutdown-only escalation: ordinary Detach preserves a
    // live target on failure, while Abandon may terminate it or arm
    // DebugObject kill-on-close so no patched process or worker survives.
    super::native_debug::abandon(pid)?;

    let mut pending = if target.mode == BuiltinDebugMode::Vt {
        drain_pending_private_events_for_pid(state, pid)
    } else {
        Vec::new()
    };
    if target.mode == BuiltinDebugMode::Vt && !target.driver_unbound {
        if !device.is_open() {
            requeue_pending_private_events(state, pending);
            return Err(AppError::Internal(format!(
                "forced cleanup PID {pid} cannot retire its VT binding after the driver device closed"
            )));
        }
        if let Err(error) =
            bridge_target_operation(device, IOCTL_HV_BRIDGE_UNBIND_TARGET, pid, 0)
        {
            requeue_pending_private_events(state, pending);
            return Err(error);
        }
    }

    state
        .vt_step_gates
        .lock()
        .retain(|_, (gate_pid, _, _)| *gate_pid != pid);
    super::hwbp::hwbp_forget_target(pid);
    for event in &mut pending {
        event.driver_continued = true;
    }
    let (retry, resume_failures) = resume_and_close_pending_private_events(pending);
    if !retry.is_empty() {
        requeue_pending_private_events(state, retry);
        return Err(AppError::Internal(format!(
            "forced cleanup PID {pid} retained private suspension ownership: {}",
            resume_failures.join("; ")
        )));
    }

    state.lifecycle.lock().target_refs.remove(&pid);
    release_pid(state, pid);
    if target.mode == BuiltinDebugMode::Vt {
        unregister_builtin_if_idle(state, device)?;
    }
    Ok(())
}

pub(crate) fn cleanup_all_builtin_targets(
    state: &Arc<DebuggerHandles>,
    device: &DeviceState,
    freeze: &Arc<FreezeStore>,
) -> AppResult<()> {
    let _mutation = state.lifecycle_mutation.lock();
    let targets: Vec<(u32, TargetAttachState)> = state
        .lifecycle
        .lock()
        .target_refs
        .iter()
        .map(|(pid, target)| (*pid, *target))
        .collect();
    let mut failures = Vec::new();
    for (pid, target) in targets {
        if let Err(error) = detach_last_target(state, device, freeze, pid, target) {
            if let Err(force_error) =
                force_cleanup_builtin_target(state, device, freeze, pid, target)
            {
                failures.push(format!(
                    "PID {pid} graceful cleanup failed: {error}; forced cleanup failed: {force_error}"
                ));
            }
        }
    }
    // A launch can fail before target_refs is published.  Those creator
    // handles still live in pending_launches and must participate in shutdown
    // retry instead of becoming an unreachable suspended process.
    let bound_pids: std::collections::HashSet<u32> = state
        .lifecycle
        .lock()
        .target_refs
        .keys()
        .copied()
        .collect();
    let orphan_launches: Vec<u32> = state
        .pending_launches
        .lock()
        .keys()
        .filter(|pid| !bound_pids.contains(pid))
        .copied()
        .collect();
    for pid in orphan_launches {
        match abort_pending_launch(state, pid)
            .and_then(|_| super::native_debug::abandon(pid))
        {
            Ok(()) => release_pid(state, pid),
            Err(error) => failures.push(format!(
                "orphan suspended launch PID {pid} cleanup retained for retry: {error}"
            )),
        }
    }

    // A worker can outlive a failed publication before either target_refs or
    // pending_launches receives ownership. Retire those otherwise unreachable
    // DebugObject sessions before allowing the driver device to close.
    let mut tracked_pids: std::collections::HashSet<u32> = state
        .lifecycle
        .lock()
        .target_refs
        .keys()
        .copied()
        .collect();
    tracked_pids.extend(state.pending_launches.lock().keys().copied());
    for pid in super::native_debug::session_pids() {
        if !tracked_pids.contains(&pid) {
            if let Err(error) = super::native_debug::abandon(pid) {
                failures.push(format!(
                    "untracked DebugObject worker PID {pid} cleanup retained for retry: {error}"
                ));
            }
        }
    }
    if let Err(error) = unregister_builtin_if_idle(state, device) {
        failures.push(format!("final debugger unregister: {error}"));
    }

    if failures.is_empty() {
        Ok(())
    } else {
        Err(AppError::Internal(format!(
            "built-in debugger shutdown cleanup errors: {}",
            failures.join("; ")
        )))
    }
}

// ============================================================
// 读 / 写 内存
// ============================================================

#[derive(Debug, Clone, Serialize)]
pub struct ReadResult {
    pub address: u64,
    pub bytes: Vec<u8>,
    pub truncated: bool,
}

#[tauri::command]
pub async fn dbg_read_memory(
    state: State<'_, Arc<DebuggerHandles>>,
    device: State<'_, DeviceState>,
    pid: u32,
    address: u64,
    size: u32,
) -> AppResult<ReadResult> {
    let state = state.inner().clone();
    let size = size.min(64 * 1024);
    match builtin_target_mode(&state, pid) {
        Some(BuiltinDebugMode::Vt) => {
            let bytes = super::memory::memory_read_impl(
                device.inner(), pid, address, size,
            )?;
            return Ok(ReadResult {
                address,
                truncated: bytes.len() != size as usize,
                bytes,
            });
        }
        Some(BuiltinDebugMode::Native) => {}
        None => {
            return Err(AppError::Internal(format!(
                "PID {pid} is not attached to the built-in debugger"
            )))
        }
    }
    let size = size as usize;
    tokio::task::spawn_blocking(move || -> AppResult<ReadResult> {
        let h = get_or_open(&state, pid)?;
        Ok(read_safe(h, address, size))
    })
    .await
    .map_err(|e| AppError::Internal(format!("spawn_blocking: {e}")))?
}

fn read_safe(h: HANDLE, address: u64, size: usize) -> ReadResult {
    unsafe {
        let mut out = vec![0u8; size];
        let mut truncated = false;

        let mut cursor: usize = 0;
        while cursor < size {
            let addr = address as usize + cursor;
            let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
            let q = VirtualQueryEx(
                h,
                Some(addr as *const c_void),
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            );
            if q == 0 {
                truncated = true;
                break;
            }
            let region_end = (mbi.BaseAddress as usize).saturating_add(mbi.RegionSize);
            let want = size - cursor;
            let avail = region_end - addr;
            let take = want.min(avail);

            let bad = mbi.State != MEM_COMMIT
                || (mbi.Protect.0 & PAGE_NOACCESS.0) != 0
                || (mbi.Protect.0 & PAGE_GUARD.0) != 0;
            if bad {
                truncated = true;
                cursor += take;
                continue;
            }

            let mut got: usize = 0;
            let ok = ReadProcessMemory(
                h,
                addr as *const c_void,
                out.as_mut_ptr().add(cursor) as *mut c_void,
                take,
                Some(&mut got),
            )
            .is_ok();
            if !ok || got == 0 {
                truncated = true;
                cursor += take;
                continue;
            }
            cursor += got;
            if got < take {
                truncated = true;
            }
        }
        ReadResult { address, bytes: out, truncated }
    }
}

#[tauri::command]
pub async fn dbg_write_memory(
    state: State<'_, Arc<DebuggerHandles>>,
    device: State<'_, DeviceState>,
    pid: u32,
    address: u64,
    bytes: Vec<u8>,
) -> AppResult<()> {
    let state = state.inner().clone();
    match builtin_target_mode(&state, pid) {
        Some(BuiltinDebugMode::Vt) => {
            return super::memory::memory_write_impl(
                device.inner(), pid, address, bytes,
            );
        }
        Some(BuiltinDebugMode::Native) => {}
        None => {
            return Err(AppError::Internal(format!(
                "PID {pid} is not attached to the built-in debugger"
            )))
        }
    }
    tokio::task::spawn_blocking(move || -> AppResult<()> {
        let h = get_or_open(&state, pid)?;
        unsafe {
            // 先暂时改 protect 到 RWX(避免写入只读 .text)
            let mut old: PAGE_PROTECTION_FLAGS = std::mem::zeroed();
            let _ = VirtualProtectEx(
                h,
                address as *const c_void,
                bytes.len(),
                PAGE_EXECUTE_READWRITE,
                &mut old,
            );
            let mut wrote: usize = 0;
            let ok = WriteProcessMemory(
                h,
                address as *const c_void,
                bytes.as_ptr() as *const c_void,
                bytes.len(),
                Some(&mut wrote),
            )
            .is_ok();
            // 还原 protect
            let mut _x: PAGE_PROTECTION_FLAGS = std::mem::zeroed();
            let _ = VirtualProtectEx(h, address as *const c_void, bytes.len(), old, &mut _x);
            if !ok || wrote != bytes.len() {
                return Err(AppError::Internal(format!(
                    "WriteProcessMemory partial {}/{}", wrote, bytes.len()
                )));
            }
            Ok(())
        }
    })
    .await
    .map_err(|e| AppError::Internal(format!("spawn_blocking: {e}")))?
}

// ============================================================
// 反汇编
// ============================================================

#[derive(Debug, Clone, Serialize)]
pub struct DisasmLine {
    pub address: u64,
    pub bytes_hex: String,
    pub text: String,
    pub len: u8,
}

fn decoder_anchor_score(bytes: &[u8], address: u64, start: usize, anchor: u64) -> Option<usize> {
    let mut decoder = Decoder::with_ip(
        64,
        &bytes[start..],
        address + start as u64,
        DecoderOptions::NONE,
    );
    let mut instruction = Instruction::default();
    let mut invalid = 0usize;
    while decoder.can_decode() && decoder.ip() <= anchor {
        let ip = decoder.ip();
        decoder.decode_out(&mut instruction);
        if ip == anchor {
            return Some(invalid);
        }
        if instruction.is_invalid() {
            invalid += 1;
        }
    }
    None
}

fn append_disassembly(
    output: &mut Vec<DisasmLine>,
    formatter: &mut IntelFormatter,
    bytes: &[u8],
    address: u64,
    start: usize,
    stop_before: Option<u64>,
) {
    let mut decoder = Decoder::with_ip(
        64,
        &bytes[start..],
        address + start as u64,
        DecoderOptions::NONE,
    );
    let mut instruction = Instruction::default();
    let mut text = String::with_capacity(64);
    while decoder.can_decode() {
        let ip = decoder.ip();
        if stop_before.is_some_and(|stop| ip >= stop) {
            break;
        }
        decoder.decode_out(&mut instruction);
        if stop_before.is_some_and(|stop| ip + instruction.len() as u64 > stop) {
            break;
        }
        let offset = (ip - address) as usize;
        let length = instruction.len();
        if offset + length > bytes.len() {
            break;
        }
        text.clear();
        formatter.format(&instruction, &mut text);
        let bytes_hex = bytes[offset..offset + length]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<_>>()
            .join(" ");
        output.push(DisasmLine {
            address: ip,
            bytes_hex,
            text: text.clone(),
            len: length as u8,
        });
    }
}

#[tauri::command]
pub async fn dbg_disasm(
    address: u64,
    bytes: Vec<u8>,
    anchor: Option<u64>,
) -> AppResult<Vec<DisasmLine>> {
    tokio::task::spawn_blocking(move || -> AppResult<Vec<DisasmLine>> {
        let mut formatter = IntelFormatter::new();
        formatter.options_mut().set_first_operand_char_index(8);
        formatter.options_mut().set_uppercase_hex(false);
        let mut output = Vec::with_capacity(bytes.len() / 4);

        let anchored = anchor.filter(|anchor| {
            *anchor >= address && *anchor < address.saturating_add(bytes.len() as u64)
        });
        if let Some(anchor) = anchored {
            let anchor_offset = (anchor - address) as usize;
            let max_candidate = anchor_offset.min(15).min(bytes.len().saturating_sub(1));
            let decode_start = (0..=max_candidate)
                .filter_map(|candidate| {
                    decoder_anchor_score(&bytes, address, candidate, anchor)
                        .map(|invalid| (invalid, candidate))
                })
                .min()
                .map(|(_, candidate)| candidate)
                .unwrap_or(0);
            append_disassembly(
                &mut output,
                &mut formatter,
                &bytes,
                address,
                decode_start,
                Some(anchor),
            );
            append_disassembly(
                &mut output,
                &mut formatter,
                &bytes,
                address,
                anchor_offset,
                None,
            );
        } else {
            append_disassembly(
                &mut output,
                &mut formatter,
                &bytes,
                address,
                0,
                None,
            );
        }
        Ok(output)
    })
    .await
    .map_err(|e| AppError::Internal(format!("spawn_blocking: {e}")))?
}

// ============================================================
// 模块 / 线程 / 内存 region
// ============================================================

#[derive(Debug, Clone, Serialize)]
pub struct ModuleInfo {
    pub base: u64,
    pub size: u64,
    pub name: String,
    pub path: String,
}

fn list_modules_for_pid(state: &Arc<DebuggerHandles>, pid: u32) -> Vec<ModuleInfo> {
    let result = unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        match snap {
            Ok(snap) => {
                let mut entry = MODULEENTRY32W {
                    dwSize: std::mem::size_of::<MODULEENTRY32W>() as u32,
                    ..Default::default()
                };
                let mut out = Vec::with_capacity(64);
                if Module32FirstW(snap, &mut entry).is_ok() {
                    loop {
                        out.push(ModuleInfo {
                            base: entry.modBaseAddr as u64,
                            size: entry.modBaseSize as u64,
                            name: utf16_to_string(&entry.szModule),
                            path: utf16_to_string(&entry.szExePath),
                        });
                        if Module32NextW(snap, &mut entry).is_err() {
                            break;
                        }
                    }
                }
                let _ = CloseHandle(snap);
                out.sort_by_key(|module| module.base);
                (!out.is_empty()).then_some(out)
            }
            Err(_) => None,
        }
    };

    match result {
        Some(modules) => {
            state.module_cache.lock().insert(pid, modules.clone());
            modules
        }
        None => state
            .module_cache
            .lock()
            .get(&pid)
            .cloned()
            .unwrap_or_default(),
    }
}

fn is_windows_system_module(path: &str) -> bool {
    let raw = path.replace('/', "\\").to_ascii_lowercase();
    let normalized = raw
        .strip_prefix("\\\\?\\")
        .or_else(|| raw.strip_prefix("\\??\\"))
        .unwrap_or(&raw);
    if normalized.is_empty() {
        return true;
    }
    if normalized.starts_with("\\systemroot\\") {
        return true;
    }
    let root = std::env::var("SystemRoot")
        .unwrap_or_else(|_| "C:\\Windows".into())
        .replace('/', "\\")
        .trim_end_matches('\\')
        .to_ascii_lowercase();
    normalized == root || normalized.starts_with(&(root + "\\"))
}

fn validate_private_swbp_address(
    state: &Arc<DebuggerHandles>,
    pid: u32,
    address: u64,
) -> AppResult<()> {
    if builtin_target_mode(state, pid) != Some(BuiltinDebugMode::Vt)
        || !builtin_target_is_bound(state, pid)
    {
        return Err(AppError::Internal(format!(
            "PID {pid} is not bound in built-in VT mode"
        )));
    }
    if (builtin_capabilities(state) & BRIDGE_CAP_PRIVATE_SWBP) == 0 {
        return Err(AppError::Internal(
            "driver did not grant private VT software breakpoints".into(),
        ));
    }
    if state.entry_bps.lock().get(&pid).copied() == Some(address) {
        return Ok(());
    }

    let modules = list_modules_for_pid(state, pid);
    if modules.is_empty() {
        return Err(AppError::Internal(
            "cannot classify breakpoint address because the target module list is unavailable"
                .into(),
        ));
    }
    let Some(module) = modules.iter().find(|module| {
        address >= module.base && address < module.base.saturating_add(module.size)
    }) else {
        return Err(AppError::Internal(format!(
            "private VT SWBP address 0x{address:X} is outside loaded user modules"
        )));
    };
    if is_windows_system_module(&module.path) {
        return Err(AppError::Internal(format!(
            "system-module breakpoint {}+0x{:X} requires a native debug-event loop; built-in VT mode rejected it",
            module.name,
            address.saturating_sub(module.base),
        )));
    }
    Ok(())
}

fn software_breakpoint_uses_native_transport(
    state: &Arc<DebuggerHandles>,
    pid: u32,
    address: u64,
) -> AppResult<bool> {
    match builtin_target_mode(state, pid) {
        Some(BuiltinDebugMode::Native) => return Ok(true),
        Some(BuiltinDebugMode::Vt) => {}
        None => {
            return Err(AppError::Internal(format!(
                "PID {pid} is not attached to the built-in debugger"
            )))
        }
    }

    let modules = list_modules_for_pid(state, pid);
    if modules.is_empty() {
        return Err(AppError::Internal(
            "cannot classify breakpoint address because the target module list is unavailable"
                .into(),
        ));
    }
    let module = modules
        .iter()
        .find(|module| {
            address >= module.base && address < module.base.saturating_add(module.size)
        })
        .ok_or_else(|| {
            AppError::Internal(format!(
                "software breakpoint address 0x{address:X} is outside loaded modules"
            ))
        })?;
    Ok(is_windows_system_module(&module.path))
}

#[tauri::command]
pub async fn dbg_list_modules(
    state: State<'_, Arc<DebuggerHandles>>,
    pid: u32,
) -> AppResult<Vec<ModuleInfo>> {
    let state = state.inner().clone();
    tokio::task::spawn_blocking(move || Ok(list_modules_for_pid(&state, pid)))
    .await
    .map_err(|e| AppError::Internal(format!("spawn_blocking: {e}")))?
}

#[derive(Debug, Clone, Serialize)]
pub struct ThreadBrief {
    pub tid: u32,
    pub owner_pid: u32,
}

#[tauri::command]
pub async fn dbg_list_threads(pid: u32) -> AppResult<Vec<ThreadBrief>> {
    tokio::task::spawn_blocking(move || -> AppResult<Vec<ThreadBrief>> {
        unsafe {
            let snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
                .map_err(|e| AppError::Internal(format!("snap threads: {e}")))?;
            let mut entry = THREADENTRY32 {
                dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
                ..Default::default()
            };
            let mut out = Vec::with_capacity(16);
            if Thread32First(snap, &mut entry).is_ok() {
                loop {
                    if entry.th32OwnerProcessID == pid {
                        out.push(ThreadBrief {
                            tid: entry.th32ThreadID,
                            owner_pid: entry.th32OwnerProcessID,
                        });
                    }
                    if Thread32Next(snap, &mut entry).is_err() {
                        break;
                    }
                }
            }
            let _ = CloseHandle(snap);
            Ok(out)
        }
    })
    .await
    .map_err(|e| AppError::Internal(format!("spawn_blocking: {e}")))?
}

#[derive(Debug, Clone, Serialize)]
pub struct RegionInfo {
    pub base: u64,
    pub size: u64,
    pub protect: u32,
    pub state: u32,
    pub type_: u32,
}

#[tauri::command]
pub async fn dbg_list_regions(
    state: State<'_, Arc<DebuggerHandles>>,
    pid: u32,
) -> AppResult<Vec<RegionInfo>> {
    let state = state.inner().clone();
    tokio::task::spawn_blocking(move || -> AppResult<Vec<RegionInfo>> {
        let h = get_or_open(&state, pid)?;
        let mut out = Vec::new();
        let mut addr: usize = 0;
        unsafe {
            loop {
                let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
                let q = VirtualQueryEx(
                    h,
                    Some(addr as *const c_void),
                    &mut mbi,
                    std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                );
                if q == 0 {
                    break;
                }
                let base = mbi.BaseAddress as usize;
                let size = mbi.RegionSize;
                if size == 0 {
                    break;
                }
                if mbi.State == MEM_COMMIT
                    && (mbi.Protect.0 & PAGE_NOACCESS.0) == 0
                    && (mbi.Protect.0 & PAGE_GUARD.0) == 0
                {
                    out.push(RegionInfo {
                        base: base as u64,
                        size: size as u64,
                        protect: mbi.Protect.0,
                        state: mbi.State.0,
                        type_: mbi.Type.0,
                    });
                }
                let next = base.saturating_add(size);
                if next == addr || next == 0 {
                    break;
                }
                addr = next;
                if addr > 0x7FFF_FFFF_FFFF {
                    break;
                }
            }
        }
        Ok(out)
    })
    .await
    .map_err(|e| AppError::Internal(format!("spawn_blocking: {e}")))?
}

// ============================================================
// Thread context (R3) + Suspend / Resume
// ============================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadContextView {
    pub tid: u32,
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub rsp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub rflags: u32,
    pub cs: u16,
    pub ss: u16,
}

/// 暂停线程并抓取上下文。返回 ThreadContextView。
/// 注意:为了能反复抓,这里抓完不 resume,前端调用 dbg_resume_thread 释放。
#[tauri::command]
pub async fn dbg_get_thread_context(tid: u32) -> AppResult<ThreadContextView> {
    tokio::task::spawn_blocking(move || -> AppResult<ThreadContextView> {
        let wow64 = thread_is_wow64(tid)?;
        unsafe {
            let h = OpenThread(
                THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME,
                false,
                tid,
            )
            .map_err(|e| AppError::Internal(format!("OpenThread({tid}): {e}")))?;

            let prev = SuspendThread(h);
            if prev == u32::MAX {
                let _ = CloseHandle(h);
                let err = windows::Win32::Foundation::GetLastError();
                return Err(AppError::Internal(format!("SuspendThread failed: GLE=0x{:x}", err.0)));
            }

            if wow64 {
                let mut ctx = std::mem::zeroed::<WOW64_CONTEXT>();
                ctx.ContextFlags = WOW64_CONTEXT_FULL;
                let ok = Wow64GetThreadContext(h, &mut ctx).is_ok();
                let _ = ResumeThread(h);
                let _ = CloseHandle(h);
                if !ok {
                    return Err(AppError::Internal("Wow64GetThreadContext failed".into()));
                }
                return Ok(ThreadContextView {
                    tid,
                    rax: ctx.Eax as u64,
                    rbx: ctx.Ebx as u64,
                    rcx: ctx.Ecx as u64,
                    rdx: ctx.Edx as u64,
                    rsi: ctx.Esi as u64,
                    rdi: ctx.Edi as u64,
                    rbp: ctx.Ebp as u64,
                    rsp: ctx.Esp as u64,
                    r8: 0,
                    r9: 0,
                    r10: 0,
                    r11: 0,
                    r12: 0,
                    r13: 0,
                    r14: 0,
                    r15: 0,
                    rip: ctx.Eip as u64,
                    rflags: ctx.EFlags,
                    cs: ctx.SegCs as u16,
                    ss: ctx.SegSs as u16,
                });
            }

            #[repr(align(16))]
            struct AlignedContext(CONTEXT);
            let mut ctx = AlignedContext(std::mem::zeroed::<CONTEXT>());
            ctx.0.ContextFlags = CONTEXT_ALL_AMD64;

            let ok = GetThreadContext(h, &mut ctx.0).is_ok();
            // 抓完立刻 resume,前端不应假定线程仍停
            let _ = ResumeThread(h);
            let _ = CloseHandle(h);
            if !ok {
                return Err(AppError::Internal("GetThreadContext failed".into()));
            }

            Ok(ThreadContextView {
                tid,
                rax: ctx.0.Rax,
                rbx: ctx.0.Rbx,
                rcx: ctx.0.Rcx,
                rdx: ctx.0.Rdx,
                rsi: ctx.0.Rsi,
                rdi: ctx.0.Rdi,
                rbp: ctx.0.Rbp,
                rsp: ctx.0.Rsp,
                r8: ctx.0.R8,
                r9: ctx.0.R9,
                r10: ctx.0.R10,
                r11: ctx.0.R11,
                r12: ctx.0.R12,
                r13: ctx.0.R13,
                r14: ctx.0.R14,
                r15: ctx.0.R15,
                rip: ctx.0.Rip,
                rflags: ctx.0.EFlags,
                cs: ctx.0.SegCs,
                ss: ctx.0.SegSs,
            })
        }
    })
    .await
    .map_err(|e| AppError::Internal(format!("spawn_blocking: {e}")))?
}

#[tauri::command]
pub async fn dbg_set_thread_context(ctx: ThreadContextView) -> AppResult<()> {
    let tid = ctx.tid;
    tokio::task::spawn_blocking(move || -> AppResult<()> {
        let wow64 = thread_is_wow64(tid)?;
        unsafe {
            let h = OpenThread(
                THREAD_SET_CONTEXT | THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME,
                false,
                tid,
            )
            .map_err(|e| AppError::Internal(format!("OpenThread({tid}): {e}")))?;
            let prev = SuspendThread(h);
            if prev == u32::MAX {
                let _ = CloseHandle(h);
                let err = windows::Win32::Foundation::GetLastError();
                return Err(AppError::Internal(format!("SuspendThread failed: GLE=0x{:x}", err.0)));
            }
            if wow64 {
                let mut existing = std::mem::zeroed::<WOW64_CONTEXT>();
                existing.ContextFlags = WOW64_CONTEXT_FULL;
                if Wow64GetThreadContext(h, &mut existing).is_err() {
                    let _ = ResumeThread(h);
                    let _ = CloseHandle(h);
                    return Err(AppError::Internal("Wow64GetThreadContext failed".into()));
                }
                let narrow = |name: &str, value: u64| {
                    u32::try_from(value).map_err(|_| {
                        AppError::Internal(format!(
                            "{name}=0x{value:X} does not fit a WOW64 register"
                        ))
                    })
                };
                let update = (|| -> AppResult<()> {
                    existing.Eax = narrow("EAX", ctx.rax)?;
                    existing.Ebx = narrow("EBX", ctx.rbx)?;
                    existing.Ecx = narrow("ECX", ctx.rcx)?;
                    existing.Edx = narrow("EDX", ctx.rdx)?;
                    existing.Esi = narrow("ESI", ctx.rsi)?;
                    existing.Edi = narrow("EDI", ctx.rdi)?;
                    existing.Ebp = narrow("EBP", ctx.rbp)?;
                    existing.Esp = narrow("ESP", ctx.rsp)?;
                    existing.Eip = narrow("EIP", ctx.rip)?;
                    existing.EFlags = ctx.rflags;
                    Ok(())
                })();
                if let Err(error) = update {
                    let _ = ResumeThread(h);
                    let _ = CloseHandle(h);
                    return Err(error);
                }
                existing.ContextFlags = WOW64_CONTEXT_FULL;
                let ok = Wow64SetThreadContext(h, &existing).is_ok();
                let _ = ResumeThread(h);
                let _ = CloseHandle(h);
                if !ok {
                    return Err(AppError::Internal("Wow64SetThreadContext failed".into()));
                }
                return Ok(());
            }
            #[repr(align(16))]
            struct AlignedContext(CONTEXT);
            let mut existing = AlignedContext(std::mem::zeroed::<CONTEXT>());
            existing.0.ContextFlags = CONTEXT_ALL_AMD64;
            let _ = GetThreadContext(h, &mut existing.0);

            // 只覆盖 INTEGER + CONTROL 部分
            existing.0.Rax = ctx.rax;
            existing.0.Rbx = ctx.rbx;
            existing.0.Rcx = ctx.rcx;
            existing.0.Rdx = ctx.rdx;
            existing.0.Rsi = ctx.rsi;
            existing.0.Rdi = ctx.rdi;
            existing.0.Rbp = ctx.rbp;
            existing.0.Rsp = ctx.rsp;
            existing.0.R8 = ctx.r8;
            existing.0.R9 = ctx.r9;
            existing.0.R10 = ctx.r10;
            existing.0.R11 = ctx.r11;
            existing.0.R12 = ctx.r12;
            existing.0.R13 = ctx.r13;
            existing.0.R14 = ctx.r14;
            existing.0.R15 = ctx.r15;
            existing.0.Rip = ctx.rip;
            existing.0.EFlags = ctx.rflags;
            existing.0.ContextFlags = CONTEXT_INTEGER_AMD64 | CONTEXT_CONTROL_AMD64;

            let ok = SetThreadContext(h, &existing.0).is_ok();
            let _ = ResumeThread(h);
            let _ = CloseHandle(h);
            if !ok {
                return Err(AppError::Internal("SetThreadContext failed".into()));
            }
            Ok(())
        }
    })
    .await
    .map_err(|e| AppError::Internal(format!("spawn_blocking: {e}")))?
}

#[tauri::command]
pub async fn dbg_suspend_thread(tid: u32) -> AppResult<u32> {
    tokio::task::spawn_blocking(move || -> AppResult<u32> {
        unsafe {
            // 试两种 access mask. 直接 THREAD_SUSPEND_RESUME 在受保护进程的线程上 OpenThread
            // 通了但 handle ACL 没 SUSPEND_RESUME, SuspendThread 返 -1, GLE=0x5.
            // 加 QUERY_INFORMATION 让 Ob 走完整权限协商.
            let h = OpenThread(
                windows::Win32::System::Threading::THREAD_ACCESS_RIGHTS(
                    THREAD_SUSPEND_RESUME.0
                    | windows::Win32::System::Threading::THREAD_QUERY_INFORMATION.0
                    | windows::Win32::System::Threading::THREAD_QUERY_LIMITED_INFORMATION.0,
                ),
                false,
                tid,
            )
            .or_else(|_| OpenThread(THREAD_SUSPEND_RESUME, false, tid))
            .map_err(|e| AppError::Internal(format!("OpenThread({tid}): {e}")))?;
            let prev = SuspendThread(h);
            let _ = CloseHandle(h);
            if prev == u32::MAX {
                let err = windows::Win32::Foundation::GetLastError();
                return Err(AppError::Internal(format!(
                    "SuspendThread failed: GLE=0x{:x} (handle ACL 限制 — 目标线程在受保护进程内)", err.0
                )));
            }
            Ok(prev)
        }
    })
    .await
    .map_err(|e| AppError::Internal(format!("spawn_blocking: {e}")))?
}

fn resume_pending_private_event(
    state: &Arc<DebuggerHandles>,
    device: &DeviceState,
    tid: u32,
) -> AppResult<Option<u32>> {
    let pending = state.pending_private.lock().remove(&tid);
    let Some(mut pending) = pending else {
        return Ok(None);
    };
    if !pending.driver_continued {
        if let Err(error) = continue_private_event(device, &pending) {
            state.pending_private.lock().insert(tid, pending);
            return Err(error);
        }
        pending.driver_continued = true;
    }
    let previous = unsafe { ResumeThread(HANDLE(pending.thread_handle as _)) };
    if previous == u32::MAX {
        state.pending_private.lock().insert(tid, pending);
        return Err(AppError::Internal(
            "ResumeThread failed for pending VT breakpoint".into(),
        ));
    }
    unsafe {
        let _ = CloseHandle(HANDLE(pending.thread_handle as _));
    }
    Ok(Some(previous))
}

fn continue_pending_private_event_for_step(
    state: &Arc<DebuggerHandles>,
    device: &DeviceState,
    pid: u32,
    tid: u32,
    rip: u64,
) -> AppResult<Option<u64>> {
    let mut pending_events = state.pending_private.lock();
    let Some(pending) = pending_events.get_mut(&tid) else {
        return Ok(None);
    };
    if pending.process_id != pid || pending.rip != rip {
        return Err(AppError::Internal(format!(
            "pending VT event mismatch for TID {tid}: event PID {} RIP 0x{:X}, requested PID {pid} RIP 0x{rip:X}",
            pending.process_id, pending.rip,
        )));
    }
    if pending.driver_continued {
        return Ok(Some(pending.sequence));
    }

    super::native_debug::private_dbgk_entry_diag(
        pid,
        "vt_step.pending_continue",
        format!("sequence={} tid={tid} rip=0x{rip:X}", pending.sequence),
    );
    continue_private_event(device, pending)?;
    pending.driver_continued = true;
    super::native_debug::private_dbgk_entry_diag(
        pid,
        "vt_step.pending_continue",
        format!("sequence={} result=ok thread_still_suspended=true", pending.sequence),
    );
    Ok(Some(pending.sequence))
}

#[tauri::command]
pub async fn dbg_resume_thread(
    state: State<'_, Arc<DebuggerHandles>>,
    device: State<'_, DeviceState>,
    tid: u32,
) -> AppResult<u32> {
    let _step = state.step_mutation.lock().await;
    if state.vt_step_gates.lock().contains_key(&tid) {
        let pid = state
            .vt_step_gates
            .lock()
            .get(&tid)
            .map(|(pid, _, _)| *pid)
            .unwrap_or_default();
        cancel_vt_step_gate(state.inner(), device.inner(), pid, tid)?;
    }
    let private_previous = resume_pending_private_event(
        state.inner(), device.inner(), tid,
    )?;
    let native_previous = super::native_debug::continue_pending_tid(tid)?;
    if let Some(previous) = private_previous.or(native_previous) {
        return Ok(previous);
    }

    tokio::task::spawn_blocking(move || -> AppResult<u32> {
        unsafe {
            let h = OpenThread(THREAD_SUSPEND_RESUME, false, tid)
                .map_err(|e| AppError::Internal(format!("OpenThread: {e}")))?;
            let prev = ResumeThread(h);
            let _ = CloseHandle(h);
            if prev == u32::MAX {
                return Err(AppError::Internal("ResumeThread failed".into()));
            }
            Ok(prev)
        }
    })
    .await
    .map_err(|e| AppError::Internal(format!("spawn_blocking: {e}")))?
}

fn thread_owner_pid(tid: u32) -> AppResult<u32> {
    unsafe {
        let thread = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, false, tid)
            .map_err(|error| AppError::Internal(format!("OpenThread({tid}): {error}")))?;
        let pid = GetProcessIdOfThread(thread);
        let _ = CloseHandle(thread);
        if pid == 0 {
            return Err(AppError::Internal(format!(
                "GetProcessIdOfThread({tid}) failed"
            )));
        }
        Ok(pid)
    }
}

pub(crate) async fn wait_for_builtin_thread_pause(
    state: &Arc<DebuggerHandles>,
    pid: u32,
    tid: u32,
    timeout: std::time::Duration,
    require_native_event: bool,
) -> AppResult<()> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if builtin_target_mode(state, pid).is_none() {
            return Err(AppError::Internal(format!(
                "PID {pid} detached while waiting for thread {tid} to pause"
            )));
        }
        let private_pending = state
            .pending_private
            .lock()
            .get(&tid)
            .is_some_and(|event| event.process_id == pid);
        let native_pending = super::native_debug::owns_pending_event(pid, tid);
        if native_pending || (!require_native_event && private_pending) {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(AppError::Internal(format!(
                "timed out waiting for PID {pid} thread {tid} to pause after stepping"
            )));
        }
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    }
}

fn suspend_thread_for_step_recovery(tid: u32) -> AppResult<()> {
    unsafe {
        let thread = OpenThread(THREAD_SUSPEND_RESUME, false, tid)
            .map_err(|error| AppError::Internal(format!("OpenThread({tid}): {error}")))?;
        let previous = SuspendThread(thread);
        let _ = CloseHandle(thread);
        if previous == u32::MAX {
            return Err(AppError::Internal(format!("SuspendThread({tid}) failed")));
        }
        Ok(())
    }
}

async fn finish_step_transaction(
    state: &Arc<DebuggerHandles>,
    device: &DeviceState,
    pid: u32,
    tid: u32,
    owns_vt_gate: bool,
    transient_address: Option<u64>,
) -> AppResult<()> {
    match wait_for_builtin_thread_pause(
        state,
        pid,
        tid,
        STEP_TRANSACTION_TIMEOUT,
        owns_vt_gate,
    )
    .await
    {
        Ok(()) => {
            if owns_vt_gate {
                clear_vt_step_gate(state, device, tid)?;
            }
            if let Some(address) = transient_address {
                consume_transient_private_swbp(state, device, pid, address)?;
            }
            Ok(())
        }
        Err(wait_error) => {
            let mut cleanup_failures = Vec::new();
            if let Err(error) = suspend_thread_for_step_recovery(tid) {
                cleanup_failures.push(format!("fail-safe suspend: {error}"));
            }
            if owns_vt_gate {
                if let Err(error) = cancel_vt_step_gate(state, device, pid, tid) {
                    cleanup_failures.push(format!("VT step cancel: {error}"));
                }
            }
            if let Some(address) = transient_address {
                if let Err(error) = consume_transient_private_swbp(state, device, pid, address) {
                    cleanup_failures.push(format!("transient breakpoint cleanup: {error}"));
                }
            }
            let cleanup = if cleanup_failures.is_empty() {
                "fail-safe thread suspension and step cleanup completed".to_string()
            } else {
                format!("fail-safe cleanup errors: {}", cleanup_failures.join("; "))
            };
            Err(AppError::Internal(format!("{wait_error}; {cleanup}")))
        }
    }
}

struct ThreadControlSnapshot {
    instruction_pointer: u64,
    stack_pointer: u64,
    wow64: bool,
}

fn thread_is_wow64(tid: u32) -> AppResult<bool> {
    let pid = thread_owner_pid(tid)?;
    unsafe {
        let process = OpenProcess(PROCESS_QUERY_INFORMATION, false, pid)
            .map_err(|error| AppError::Internal(format!("OpenProcess({pid}): {error}")))?;
        let mut wow64 = windows::Win32::Foundation::BOOL(0);
        let architecture_result = IsWow64Process(process, &mut wow64);
        let _ = CloseHandle(process);
        architecture_result
            .map_err(|error| AppError::Internal(format!("IsWow64Process({pid}): {error}")))?;
        Ok(wow64.as_bool())
    }
}

fn read_thread_control_snapshot(tid: u32) -> AppResult<ThreadControlSnapshot> {
    let wow64 = thread_is_wow64(tid)?;
    unsafe {
        let thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME, false, tid)
            .map_err(|error| AppError::Internal(format!("OpenThread({tid}): {error}")))?;
        let previous = SuspendThread(thread);
        if previous == u32::MAX {
            let _ = CloseHandle(thread);
            return Err(AppError::Internal(format!("SuspendThread({tid}) failed")));
        }
        let snapshot = if wow64 {
            let mut context = std::mem::zeroed::<WOW64_CONTEXT>();
            context.ContextFlags = WOW64_CONTEXT_CONTROL;
            Wow64GetThreadContext(thread, &mut context)
                .map(|_| ThreadControlSnapshot {
                    instruction_pointer: context.Eip as u64,
                    stack_pointer: context.Esp as u64,
                    wow64: true,
                })
                .map_err(|error| {
                    AppError::Internal(format!("Wow64GetThreadContext({tid}): {error}"))
                })
        } else {
            #[repr(align(16))]
            struct AlignedContext(CONTEXT);
            let mut context = AlignedContext(std::mem::zeroed::<CONTEXT>());
            context.0.ContextFlags = CONTEXT_CONTROL_AMD64 | CONTEXT_INTEGER_AMD64;
            GetThreadContext(thread, &mut context.0)
                .map(|_| ThreadControlSnapshot {
                    instruction_pointer: context.0.Rip,
                    stack_pointer: context.0.Rsp,
                    wow64: false,
                })
                .map_err(|error| {
                    AppError::Internal(format!("GetThreadContext({tid}): {error}"))
                })
        };
        let resumed = ResumeThread(thread);
        let _ = CloseHandle(thread);
        if resumed == u32::MAX {
            return Err(AppError::Internal(format!("ResumeThread({tid}) failed")));
        }
        snapshot
    }
}

async fn resume_after_private_breakpoint(
    state: &Arc<DebuggerHandles>,
    device: &DeviceState,
    tid: u32,
) -> AppResult<()> {
    let private_resumed = resume_pending_private_event(state, device, tid)?.is_some();
    let native_continued = super::native_debug::continue_pending_tid(tid)?.is_some();
    if private_resumed || native_continued {
        return Ok(());
    }
    tokio::task::spawn_blocking(move || -> AppResult<()> {
        unsafe {
            let thread = OpenThread(THREAD_SUSPEND_RESUME, false, tid)
                .map_err(|error| AppError::Internal(format!("OpenThread({tid}): {error}")))?;
            let previous = ResumeThread(thread);
            let _ = CloseHandle(thread);
            if previous == u32::MAX {
                return Err(AppError::Internal(format!(
                    "ResumeThread({tid}) failed"
                )));
            }
            Ok(())
        }
    })
    .await
    .map_err(|error| AppError::Internal(format!("spawn_blocking: {error}")))?
}

async fn start_vt_single_step(
    state: &Arc<DebuggerHandles>,
    device: &DeviceState,
    pid: u32,
    tid: u32,
    rip: u64,
) -> AppResult<()> {
    if (builtin_capabilities(state) & BRIDGE_CAP_VT_STEP) == 0 {
        return Err(AppError::Internal(
            "VT single-step capability is unavailable".into(),
        ));
    }
    if !builtin_target_is_bound(state, pid) {
        return Err(AppError::Internal(
            "VT single-step requires an active target binding".into(),
        ));
    }

    super::native_debug::private_dbgk_entry_diag(
        pid,
        "vt_step.begin",
        format!(
            "tid={tid} rip=0x{rip:X} {}",
            super::native_debug::private_dbgk_session_snapshot(pid),
        ),
    );
    if let Err(error) = clear_vt_step_gate(state, device, tid) {
        super::native_debug::private_dbgk_entry_diag(
            pid,
            "vt_step.clear.error",
            format!("tid={tid} error={error}"),
        );
        return Err(error);
    }
    let pending_private_sequence =
        match continue_pending_private_event_for_step(state, device, pid, tid, rip) {
            Ok(sequence) => sequence,
            Err(error) => {
                super::native_debug::private_dbgk_entry_diag(
                    pid,
                    "vt_step.pending_continue.error",
                    format!("tid={tid} rip=0x{rip:X} error={error}"),
                );
                return Err(error);
            }
        };
    let uses_swbp_gate =
        (builtin_capabilities(state) & BRIDGE_CAP_PRIVATE_SWBP) != 0;
    if uses_swbp_gate {
        super::native_debug::private_dbgk_entry_diag(
            pid,
            "vt_step.gate.begin",
            format!("tid={tid} address=0x{rip:X}"),
        );
        if let Err(error) = install_transient_private_swbp(state, device, pid, tid, rip) {
            super::native_debug::private_dbgk_entry_diag(
                pid,
                "vt_step.gate.error",
                format!("tid={tid} address=0x{rip:X} error={error}"),
            );
            return Err(error);
        }
        super::native_debug::private_dbgk_entry_diag(
            pid,
            "vt_step.gate.result",
            format!("tid={tid} address=0x{rip:X} result=ok"),
        );
    }
    super::native_debug::private_dbgk_entry_diag(
        pid,
        "vt_step.arm.begin",
        format!("tid={tid} address=0x{rip:X}"),
    );
    if let Err(error) = driver_vt_step_ioctl(
        device,
        crate::ioctl::codes::IOCTL_HV_DBG_STEP_ARM,
        pid,
        tid,
        rip,
    ) {
        if uses_swbp_gate {
            let _ = consume_transient_private_swbp(state, device, pid, rip);
        }
        super::native_debug::private_dbgk_entry_diag(
            pid,
            "vt_step.arm.error",
            format!("tid={tid} address=0x{rip:X} error={error}"),
        );
        return Err(error);
    }
    super::native_debug::private_dbgk_entry_diag(
        pid,
        "vt_step.arm.result",
        format!("tid={tid} address=0x{rip:X} result=ok"),
    );
    state
        .vt_step_gates
        .lock()
        .insert(tid, (pid, rip, uses_swbp_gate));

    super::native_debug::private_dbgk_entry_diag(
        pid,
        "vt_step.receiver.begin",
        format!("tid={tid}"),
    );
    let continued_event = match super::native_debug::step_into_vt(pid, tid) {
        Ok(value) => {
            super::native_debug::private_dbgk_entry_diag(
                pid,
                "vt_step.receiver.result",
                format!("tid={tid} continued_event={value}"),
            );
            value
        }
        Err(error) => {
            super::native_debug::private_dbgk_entry_diag(
                pid,
                "vt_step.receiver.error",
                format!("tid={tid} error={error}"),
            );
            state.vt_step_gates.lock().remove(&tid);
            let _ = driver_vt_step_ioctl(
                device,
                crate::ioctl::codes::IOCTL_HV_DBG_STEP_CLEAR,
                pid,
                tid,
                rip,
            );
            if uses_swbp_gate {
                let _ = consume_transient_private_swbp(state, device, pid, rip);
            }
            return Err(error);
        }
    };
    let private_event_resumed = if pending_private_sequence.is_some() {
        resume_pending_private_event(state, device, tid)?.is_some()
    } else {
        false
    };
    if !continued_event && !private_event_resumed {
        super::native_debug::private_dbgk_entry_diag(
            pid,
            "vt_step.resume.begin",
            format!("tid={tid}"),
        );
        if let Err(error) = resume_after_private_breakpoint(state, device, tid).await {
            super::native_debug::private_dbgk_entry_diag(
                pid,
                "vt_step.resume.error",
                format!("tid={tid} error={error}"),
            );
            let _ = super::native_debug::cancel_vt_step(pid, tid);
            state.vt_step_gates.lock().remove(&tid);
            let _ = driver_vt_step_ioctl(
                device,
                crate::ioctl::codes::IOCTL_HV_DBG_STEP_CLEAR,
                pid,
                tid,
                rip,
            );
            if uses_swbp_gate {
                let _ = consume_transient_private_swbp(state, device, pid, rip);
            }
            return Err(error);
        }
        super::native_debug::private_dbgk_entry_diag(
            pid,
            "vt_step.resume.result",
            format!("tid={tid} result=ok"),
        );
    }
    Ok(())
}

async fn run_real_tf_single_step(
    state: &Arc<DebuggerHandles>,
    device: &DeviceState,
    pid: u32,
    tid: u32,
) -> AppResult<()> {
    super::native_debug::private_dbgk_entry_diag(
        pid,
        "real_tf.begin",
        format!("tid={tid}"),
    );
    let continued_event = super::native_debug::step_into(pid, tid)?;
    if !continued_event {
        resume_after_private_breakpoint(state, device, tid).await?;
    }
    finish_step_transaction(state, device, pid, tid, false, None).await?;
    super::native_debug::private_dbgk_entry_diag(
        pid,
        "real_tf.complete",
        format!("tid={tid}"),
    );
    Ok(())
}

#[tauri::command]
pub async fn dbg_step_into(
    state: State<'_, Arc<DebuggerHandles>>,
    device: State<'_, DeviceState>,
    tid: u32,
    synthetic_mtf: Option<bool>,
) -> AppResult<()> {
    let state = state.inner().clone();
    let _step = state.step_mutation.lock().await;
    let pid = thread_owner_pid(tid)?;
    match builtin_target_mode(&state, pid) {
        Some(BuiltinDebugMode::Native) =>
            run_real_tf_single_step(&state, device.inner(), pid, tid).await,
        Some(BuiltinDebugMode::Vt) => {
            if !synthetic_mtf.unwrap_or(true) {
                return run_real_tf_single_step(&state, device.inner(), pid, tid).await;
            }
            let snapshot = read_thread_control_snapshot(tid)?;
            if software_breakpoint_uses_native_transport(
                &state,
                pid,
                snapshot.instruction_pointer,
            )? {
                return run_real_tf_single_step(&state, device.inner(), pid, tid).await;
            }
            start_vt_single_step(
                &state,
                device.inner(),
                pid,
                tid,
                snapshot.instruction_pointer,
            )
            .await?;
            finish_step_transaction(&state, device.inner(), pid, tid, true, None).await
        }
        None => Err(AppError::Internal(format!(
            "thread {tid} belongs to PID {pid}, which is not attached"
        ))),
    }
}

#[derive(Debug, Serialize)]
pub struct StepOverResult {
    pub kind: &'static str,
    pub next_rip: u64,
}

#[tauri::command]
pub async fn dbg_step_over(
    state: State<'_, Arc<DebuggerHandles>>,
    device: State<'_, DeviceState>,
    pid: u32,
    tid: u32,
    synthetic_mtf: Option<bool>,
) -> AppResult<StepOverResult> {
    use iced_x86::FlowControl;
    let state = state.inner().clone();
    let _step = state.step_mutation.lock().await;
    let mode = match builtin_target_mode(&state, pid) {
        Some(mode) => mode,
        None => {
            return Err(AppError::Internal(format!(
                "PID {pid} is not attached to the built-in debugger"
            )))
        }
    };
    let owner_pid = thread_owner_pid(tid)?;
    if owner_pid != pid {
        return Err(AppError::Internal(format!(
            "thread {tid} belongs to PID {owner_pid}, not requested PID {pid}"
        )));
    }

    if mode == BuiltinDebugMode::Native {
        let result = super::native_debug::step_over(pid, tid)?;
        if !result.continued_event {
            resume_after_private_breakpoint(&state, device.inner(), tid).await?;
        }
        finish_step_transaction(&state, device.inner(), pid, tid, false, None).await?;
        return Ok(StepOverResult {
            kind: result.kind,
            next_rip: result.next_rip,
        });
    }
    if !builtin_target_is_bound(&state, pid) {
        return Err(AppError::Internal(
            "VT step-over requires an active target binding".into(),
        ));
    }

    let snapshot = tokio::task::spawn_blocking(move || read_thread_control_snapshot(tid))
    .await
    .map_err(|error| AppError::Internal(format!("spawn_blocking: {error}")))??;
    let rip = snapshot.instruction_pointer;

    if software_breakpoint_uses_native_transport(&state, pid, rip)? {
        let result = super::native_debug::step_over(pid, tid)?;
        if !result.continued_event {
            resume_after_private_breakpoint(&state, device.inner(), tid).await?;
        }
        finish_step_transaction(&state, device.inner(), pid, tid, false, None).await?;
        return Ok(StepOverResult {
            kind: result.kind,
            next_rip: result.next_rip,
        });
    }

    let bytes = super::memory::memory_read_impl(device.inner(), pid, rip, 16)?;
    if bytes.is_empty() {
        return Err(AppError::Internal("unable to read RIP bytes through VT memory".into()));
    }
    let mut decoder = iced_x86::Decoder::with_ip(
        if snapshot.wow64 { 32 } else { 64 },
        &bytes,
        rip,
        iced_x86::DecoderOptions::NONE,
    );
    let instruction = decoder.decode();
    let flow = instruction.flow_control();
    if !matches!(
        flow,
        FlowControl::Call | FlowControl::IndirectCall | FlowControl::Interrupt
    ) {
        let synthetic_mtf = synthetic_mtf.unwrap_or(true);
        if synthetic_mtf {
            start_vt_single_step(&state, device.inner(), pid, tid, rip).await?;
            finish_step_transaction(&state, device.inner(), pid, tid, true, None).await?;
        } else {
            run_real_tf_single_step(&state, device.inner(), pid, tid).await?;
        }
        return Ok(StepOverResult {
            kind: if synthetic_mtf {
                "vt-single-step"
            } else {
                "real-tf-single-step"
            },
            next_rip: rip.saturating_add(instruction.len() as u64),
        });
    }
    if (builtin_capabilities(&state) & BRIDGE_CAP_PRIVATE_SWBP) == 0 {
        return Err(AppError::Internal(
            "VT call step-over requires private SWBP capability".into(),
        ));
    }
    let next = rip
        .checked_add(instruction.len() as u64)
        .ok_or_else(|| AppError::Internal("step-over address overflow".into()))?;
    install_transient_private_swbp(&state, device.inner(), pid, tid, next)?;
    if let Err(error) = resume_after_private_breakpoint(&state, device.inner(), tid).await {
        let _ = consume_transient_private_swbp(&state, device.inner(), pid, next);
        return Err(error);
    }
    finish_step_transaction(
        &state,
        device.inner(),
        pid,
        tid,
        false,
        Some(next),
    )
    .await?;
    Ok(StepOverResult {
        kind: "run-over",
        next_rip: next,
    })
}

/// P56 步出: walk 栈拿 return address (RSP+0),装临时 sw bp + resume
#[derive(Debug, Serialize)]
pub struct StepManyResult {
    pub kind: String,
    pub steps: u32,
    pub tid: u32,
    pub rip: u64,
}

#[tauri::command]
pub async fn dbg_step_many(
    app: AppHandle,
    pid: u32,
    tid: u32,
    kind: String,
    count: u32,
    synthetic_mtf: Option<bool>,
) -> AppResult<StepManyResult> {
    if !(1..=1000).contains(&count) {
        return Err(AppError::Internal(
            "step count must be an integer from 1 to 1000".into(),
        ));
    }
    if !matches!(kind.as_str(), "into" | "over") {
        return Err(AppError::Internal(format!(
            "unsupported multi-step kind '{kind}'"
        )));
    }

    let handles = app.state::<Arc<DebuggerHandles>>().inner().clone();
    if builtin_target_mode(&handles, pid).is_none() {
        return Err(AppError::Internal(format!(
            "PID {pid} is not attached to the built-in debugger"
        )));
    }
    let owner_pid = thread_owner_pid(tid)?;
    if owner_pid != pid {
        return Err(AppError::Internal(format!(
            "thread {tid} belongs to PID {owner_pid}, not requested PID {pid}"
        )));
    }

    for completed in 0..count {
        let step_result = match kind.as_str() {
            "into" => dbg_step_into(
                app.state::<Arc<DebuggerHandles>>(),
                app.state::<DeviceState>(),
                tid,
                synthetic_mtf,
            )
            .await,
            "over" => dbg_step_over(
                app.state::<Arc<DebuggerHandles>>(),
                app.state::<DeviceState>(),
                pid,
                tid,
                synthetic_mtf,
            )
            .await
            .map(|_| ()),
            _ => unreachable!(),
        };
        if let Err(error) = step_result {
            return Err(AppError::Internal(format!(
                "{kind} failed after {completed}/{count} completed steps: {error}"
            )));
        }
        if let Err(error) = wait_for_builtin_thread_pause(
            &handles,
            pid,
            tid,
            std::time::Duration::from_secs(30),
            false,
        )
        .await
        {
            return Err(AppError::Internal(format!(
                "{kind} wait failed after {}/{} completed steps: {error}",
                completed + 1,
                count
            )));
        }
    }

    let context = dbg_get_thread_context(tid).await.map_err(|error| {
        AppError::Internal(format!(
            "{count} {kind} steps completed but final context read failed: {error}"
        ))
    })?;
    Ok(StepManyResult {
        kind,
        steps: count,
        tid,
        rip: context.rip,
    })
}

#[tauri::command]
pub async fn dbg_step_out(
    state: State<'_, Arc<DebuggerHandles>>,
    device: State<'_, DeviceState>,
    pid: u32,
    tid: u32,
) -> AppResult<u64> {
    let state = state.inner().clone();
    let _step = state.step_mutation.lock().await;
    let mode = match builtin_target_mode(&state, pid) {
        Some(mode) => mode,
        None => {
            return Err(AppError::Internal(format!(
                "PID {pid} is not attached to the built-in debugger"
            )))
        }
    };
    let owner_pid = thread_owner_pid(tid)?;
    if owner_pid != pid {
        return Err(AppError::Internal(format!(
            "thread {tid} belongs to PID {owner_pid}, not requested PID {pid}"
        )));
    }

    let native_pending = super::native_debug::owns_pending_event(pid, tid);
    if mode == BuiltinDebugMode::Native || native_pending {
        let return_address = super::native_debug::step_out(pid, tid)?;
        if !native_pending {
            resume_after_private_breakpoint(&state, device.inner(), tid).await?;
        }
        finish_step_transaction(&state, device.inner(), pid, tid, false, None).await?;
        return Ok(return_address);
    }
    if !builtin_target_is_bound(&state, pid) {
        return Err(AppError::Internal(
            "VT step-out requires an active target binding".into(),
        ));
    }

    let snapshot = tokio::task::spawn_blocking(move || read_thread_control_snapshot(tid))
    .await
    .map_err(|error| AppError::Internal(format!("spawn_blocking: {error}")))??;
    let pointer_size: usize = if snapshot.wow64 { 4 } else { 8 };
    let stack = super::memory::memory_read_impl(
        device.inner(),
        pid,
        snapshot.stack_pointer,
        pointer_size as u32,
    )?;
    if stack.len() != pointer_size {
        return Err(AppError::Internal(
            "VT stack read did not return a complete return address".into(),
        ));
    }
    let ret_addr = if snapshot.wow64 {
        u32::from_le_bytes(stack[..4].try_into().unwrap()) as u64
    } else {
        u64::from_le_bytes(stack[..8].try_into().unwrap())
    };
    if software_breakpoint_uses_native_transport(&state, pid, ret_addr)? {
        let return_address = super::native_debug::step_out(pid, tid)?;
        resume_after_private_breakpoint(&state, device.inner(), tid).await?;
        finish_step_transaction(&state, device.inner(), pid, tid, false, None).await?;
        return Ok(return_address);
    }
    if (builtin_capabilities(&state) & BRIDGE_CAP_PRIVATE_SWBP) == 0 {
        return Err(AppError::Internal(
            "VT step-out to a user module requires private SWBP capability".into(),
        ));
    }
    install_transient_private_swbp(&state, device.inner(), pid, tid, ret_addr)?;
    if let Err(error) = resume_after_private_breakpoint(&state, device.inner(), tid).await {
        let _ = consume_transient_private_swbp(&state, device.inner(), pid, ret_addr);
        return Err(error);
    }
    finish_step_transaction(
        &state,
        device.inner(),
        pid,
        tid,
        false,
        Some(ret_addr),
    )
    .await?;
    Ok(ret_addr)
}

/// P56 命中临时 bp 后由前端调,自动清掉这个临时 bp
#[tauri::command]
pub async fn dbg_consume_transient_bp(
    state: State<'_, Arc<DebuggerHandles>>,
    device: State<'_, DeviceState>,
    pid: u32,
    address: u64,
) -> AppResult<bool> {
    consume_transient_private_swbp(state.inner(), device.inner(), pid, address)
}

// ============================================================
// 软断点 (int3) — set/clear,自动备份原字节
// ============================================================

#[derive(Debug, Clone, Serialize)]
pub struct SwBreakpoint {
    pub address: u64,
    pub original_byte: u8,
}

fn driver_sw_bp_ioctl(
    device: &DeviceState,
    code: u32,
    operation: &str,
    target_pid: u32,
    address: u64,
    scope_thread_id: Option<u32>,
) -> AppResult<()> {
    super::native_debug::private_dbgk_entry_diag(
        target_pid,
        "private_swbp.ioctl.begin",
        format!(
            "operation={operation} ioctl=0x{code:X} address=0x{address:X} scope_tid={}",
            scope_thread_id.unwrap_or(0)
        ),
    );
    if !device.is_open() {
        return Err(AppError::Internal(format!(
            "{operation} requires the driver-backed private breakpoint path"
        )));
    }
    // HV_BRIDGE_SWBP_REQUEST v6: Version, TargetPid, ScopeThreadId, Flags, Address.
    let mut request = [0u8; 24];
    request[0..4].copy_from_slice(&BRIDGE_PROTOCOL_VERSION.to_le_bytes());
    request[4..8].copy_from_slice(&target_pid.to_le_bytes());
    let scope_thread_id = scope_thread_id.unwrap_or(0);
    request[8..12].copy_from_slice(&scope_thread_id.to_le_bytes());
    request[12..16].copy_from_slice(
        &(if scope_thread_id != 0 { 1u32 } else { 0u32 }).to_le_bytes(),
    );
    request[16..24].copy_from_slice(&address.to_le_bytes());
    let mut out = [0u8; 16];
    let written = match device.ioctl(code, &request, &mut out) {
        Ok(written) => written,
        Err(error) => {
            super::native_debug::private_dbgk_entry_diag(
                target_pid,
                "private_swbp.ioctl.error",
                format!("operation={operation} error={error}"),
            );
            return Err(error);
        }
    };
    if written != 16 {
        return Err(AppError::Internal(format!(
            "{operation} returned {written} bytes, expected 16"
        )));
    }
    let status = u32::from_le_bytes(out[0..4].try_into().unwrap());
    let reserved = u32::from_le_bytes(out[4..8].try_into().unwrap());
    let info = u64::from_le_bytes(out[8..16].try_into().unwrap());
    super::native_debug::private_dbgk_entry_diag(
        target_pid,
        "private_swbp.ioctl.result",
        format!(
            "operation={operation} bytes={written} status={status} reserved={reserved} info=0x{info:X}"
        ),
    );
    if status != 0 || reserved != 0 {
        return Err(AppError::Internal(format!(
            "{operation} failed: driver status={status}, reserved={reserved}"
        )));
    }
    Ok(())
}

fn driver_register_sw_bp(
    device: &DeviceState,
    target_pid: u32,
    address: u64,
    scope_thread_id: Option<u32>,
) -> AppResult<()> {
    driver_sw_bp_ioctl(
        device,
        crate::ioctl::codes::IOCTL_HV_DBG_SW_BP_ADD,
        "private SWBP add",
        target_pid,
        address,
        scope_thread_id,
    )
}

fn driver_unregister_sw_bp(device: &DeviceState, target_pid: u32, address: u64) -> AppResult<()> {
    driver_sw_bp_ioctl(
        device,
        crate::ioctl::codes::IOCTL_HV_DBG_SW_BP_DEL,
        "private SWBP remove",
        target_pid,
        address,
        None,
    )
}

fn driver_vt_step_ioctl(
    device: &DeviceState,
    code: u32,
    pid: u32,
    tid: u32,
    address: u64,
) -> AppResult<()> {
    let request = VtStepRequest {
        version: BRIDGE_PROTOCOL_VERSION,
        target_pid: pid,
        thread_id: tid,
        reserved: 0,
        address,
    };
    let mut result = OperationResult::default();
    let written = device.ioctl(code, pod_bytes(&request), pod_bytes_mut(&mut result))?;
    let clear_not_found = code == crate::ioctl::codes::IOCTL_HV_DBG_STEP_CLEAR
        && result.status == BRIDGE_STATUS_NOT_FOUND as u32;
    if written as usize != std::mem::size_of::<OperationResult>()
        || result.reserved != 0
        || (result.status != BRIDGE_STATUS_SUCCESS as u32 && !clear_not_found)
    {
        return Err(AppError::Internal(format!(
            "VT step ioctl 0x{code:X} failed: bytes={written}, status={}, reserved={}",
            result.status, result.reserved,
        )));
    }
    Ok(())
}

fn clear_vt_step_gate(
    state: &Arc<DebuggerHandles>,
    device: &DeviceState,
    tid: u32,
) -> AppResult<()> {
    let gate = state.vt_step_gates.lock().remove(&tid);
    let Some((pid, address, owns_swbp_gate)) = gate else {
        return Ok(());
    };
    if let Err(error) = driver_vt_step_ioctl(
        device,
        crate::ioctl::codes::IOCTL_HV_DBG_STEP_CLEAR,
        pid,
        tid,
        address,
    ) {
        state
            .vt_step_gates
            .lock()
            .insert(tid, (pid, address, owns_swbp_gate));
        return Err(error);
    }
    if owns_swbp_gate {
        if let Err(error) = consume_transient_private_swbp(state, device, pid, address) {
            state
                .vt_step_gates
                .lock()
                .entry(tid)
                .or_insert((pid, address, owns_swbp_gate));
            return Err(error);
        }
    }
    Ok(())
}

fn cancel_vt_step_gate(
    state: &Arc<DebuggerHandles>,
    device: &DeviceState,
    pid: u32,
    tid: u32,
) -> AppResult<()> {
    let mut failures = Vec::new();
    if let Err(error) = super::native_debug::cancel_vt_step(pid, tid) {
        failures.push(format!("receiver cancel: {error}"));
    }
    if let Err(error) = clear_vt_step_gate(state, device, tid) {
        failures.push(format!("driver gate clear: {error}"));
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(AppError::Internal(failures.join("; ")))
    }
}

fn add_private_swbp(
    state: &Arc<DebuggerHandles>,
    device: &DeviceState,
    pid: u32,
    address: u64,
) -> AppResult<SwBreakpoint> {
    add_private_swbp_inner(state, device, pid, address, None)
}

fn add_private_swbp_scoped(
    state: &Arc<DebuggerHandles>,
    device: &DeviceState,
    pid: u32,
    address: u64,
    scope_thread_id: u32,
) -> AppResult<SwBreakpoint> {
    add_private_swbp_inner(
        state,
        device,
        pid,
        address,
        Some(scope_thread_id),
    )
}

fn add_private_swbp_inner(
    state: &Arc<DebuggerHandles>,
    device: &DeviceState,
    pid: u32,
    address: u64,
    scope_thread_id: Option<u32>,
) -> AppResult<SwBreakpoint> {
    validate_private_swbp_address(state, pid, address)?;
    if state
        .sw_bps
        .lock()
        .get(&pid)
        .is_some_and(|items| items.iter().any(|(item_address, _)| *item_address == address))
    {
        return Err(AppError::Internal(format!(
            "private VT SWBP already exists at 0x{address:X}"
        )));
    }

    let bytes = super::memory::memory_read_impl(device, pid, address, 1)?;
    let original_byte = *bytes
        .first()
        .ok_or_else(|| AppError::Internal("unable to read target breakpoint byte".into()))?;
    if original_byte == 0xCC {
        return Err(AppError::Internal(format!(
            "0x{address:X} already contains INT3; a one-shot private SWBP cannot distinguish the original trap (use an execute HWBP)"
        )));
    }
    driver_register_sw_bp(device, pid, address, scope_thread_id)?;
    state
        .sw_bps
        .lock()
        .entry(pid)
        .or_default()
        .push((address, original_byte));
    Ok(SwBreakpoint {
        address,
        original_byte,
    })
}

fn remove_private_swbp(
    state: &Arc<DebuggerHandles>,
    device: &DeviceState,
    pid: u32,
    address: u64,
) -> AppResult<()> {
    if builtin_target_mode(state, pid) != Some(BuiltinDebugMode::Vt) {
        return Err(AppError::Internal(
            "software breakpoints are disabled outside built-in VT mode".into(),
        ));
    }
    let exists = state.sw_bps.lock().get(&pid).is_some_and(|items| {
        items
            .iter()
            .any(|(item_address, _)| *item_address == address)
    });
    if !exists {
        return Err(AppError::Internal("no private breakpoint at this address".into()));
    }

    // Private/EPT SWBP never patches the guest byte. Removal is driver-only;
    // writing the stale original byte here would corrupt self-modifying code.
    driver_unregister_sw_bp(device, pid, address)?;
    if let Some(items) = state.sw_bps.lock().get_mut(&pid) {
        if let Some(index) = items
            .iter()
            .position(|(item_address, _)| *item_address == address)
        {
            items.swap_remove(index);
        }
    }
    Ok(())
}

fn install_transient_private_swbp(
    state: &Arc<DebuggerHandles>,
    device: &DeviceState,
    pid: u32,
    owner_tid: u32,
    address: u64,
) -> AppResult<()> {
    let owns_registration = !state
        .sw_bps
        .lock()
        .get(&pid)
        .is_some_and(|items| {
            items
                .iter()
                .any(|(item_address, _)| *item_address == address)
        });
    {
        let mut transient = state.transient_bps.lock();
        let items = transient.entry(pid).or_default();
        if items.contains_key(&address) {
            return Err(AppError::Internal(format!(
                "private VT transient breakpoint already exists at 0x{address:X}"
            )));
        }
        items.insert(
            address,
            TransientPrivateBreakpoint {
                owner_tid,
                owns_registration,
            },
        );
    }
    if owns_registration {
        let add_result = if super::native_debug::is_private_dbgk_session(pid) {
            add_private_swbp_scoped(state, device, pid, address, owner_tid)
        } else {
            add_private_swbp(state, device, pid, address)
        };
        if let Err(error) = add_result {
            let mut transient = state.transient_bps.lock();
            if let Some(items) = transient.get_mut(&pid) {
                items.remove(&address);
                if items.is_empty() {
                    transient.remove(&pid);
                }
            }
            return Err(error);
        }
    }
    Ok(())
}

fn consume_transient_private_swbp(
    state: &Arc<DebuggerHandles>,
    device: &DeviceState,
    pid: u32,
    address: u64,
) -> AppResult<bool> {
    let target = {
        let mut transient = state.transient_bps.lock();
        let target = transient
            .get_mut(&pid)
            .and_then(|items| items.remove(&address));
        if transient.get(&pid).is_some_and(|items| items.is_empty()) {
            transient.remove(&pid);
        }
        target
    };
    let Some(target) = target else {
        return Ok(false);
    };
    if target.owns_registration {
        if let Err(error) = remove_private_swbp(state, device, pid, address) {
            state
                .transient_bps
                .lock()
                .entry(pid)
                .or_default()
                .entry(address)
                .or_insert(target);
            return Err(error);
        }
    }
    Ok(true)
}

#[tauri::command]
pub async fn dbg_sw_bp_set(
    state: State<'_, Arc<DebuggerHandles>>,
    device: State<'_, DeviceState>,
    pid: u32,
    address: u64,
) -> AppResult<SwBreakpoint> {
    if software_breakpoint_uses_native_transport(state.inner(), pid, address)? {
        let breakpoint = super::native_debug::set_software_breakpoint(pid, address)?;
        return Ok(SwBreakpoint {
            address: breakpoint.address,
            original_byte: breakpoint.original_byte,
        });
    }
    add_private_swbp(state.inner(), device.inner(), pid, address)
}

#[tauri::command]
pub async fn dbg_sw_bp_clear(
    state: State<'_, Arc<DebuggerHandles>>,
    device: State<'_, DeviceState>,
    pid: u32,
    address: u64,
) -> AppResult<()> {
    if state
        .transient_bps
        .lock()
        .get(&pid)
        .is_some_and(|items| items.contains_key(&address))
    {
        return Err(AppError::Internal(format!(
            "breakpoint 0x{address:X} is currently owned by step-over/step-out"
        )));
    }
    let is_private = state
        .sw_bps
        .lock()
        .get(&pid)
        .is_some_and(|items| items.iter().any(|(item_address, _)| *item_address == address));
    if is_private {
        remove_private_swbp(state.inner(), device.inner(), pid, address)
    } else {
        super::native_debug::clear_software_breakpoint(pid, address)
    }
}

#[tauri::command]
pub fn dbg_sw_bp_list(
    state: State<'_, Arc<DebuggerHandles>>,
    pid: u32,
) -> AppResult<Vec<SwBreakpoint>> {
    let mut breakpoints: Vec<SwBreakpoint> = state
        .sw_bps
        .lock()
        .get(&pid)
        .map(|items| {
            items
                .iter()
                .map(|(address, original_byte)| SwBreakpoint {
                    address: *address,
                    original_byte: *original_byte,
                })
                .collect()
        })
        .unwrap_or_default();
    if super::native_debug::is_session(pid) {
        for breakpoint in super::native_debug::list_software_breakpoints(pid)? {
            if !breakpoints
                .iter()
                .any(|item| item.address == breakpoint.address)
            {
                breakpoints.push(SwBreakpoint {
                    address: breakpoint.address,
                    original_byte: breakpoint.original_byte,
                });
            }
        }
    }
    breakpoints.sort_by_key(|breakpoint| breakpoint.address);
    Ok(breakpoints)
}

// ============================================================
// 内存扫描器
// ============================================================

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ValueType {
    I8,
    I16,
    I32,
    I64,
    U8,
    U16,
    U32,
    U64,
    F32,
    F64,
    Bytes,
    String,
}

impl ValueType {
    fn size(self, value: &ScanValue) -> usize {
        match self {
            ValueType::I8 | ValueType::U8 => 1,
            ValueType::I16 | ValueType::U16 => 2,
            ValueType::I32 | ValueType::U32 | ValueType::F32 => 4,
            ValueType::I64 | ValueType::U64 | ValueType::F64 => 8,
            ValueType::Bytes => value.bytes.as_ref().map(|b| b.len()).unwrap_or(0),
            ValueType::String => value.string.as_ref().map(|s| s.len()).unwrap_or(0),
        }
    }

    fn encode(self, v: &ScanValue) -> Option<Vec<u8>> {
        Some(match self {
            ValueType::I8 => (v.number? as i8).to_le_bytes().to_vec(),
            ValueType::I16 => (v.number? as i16).to_le_bytes().to_vec(),
            ValueType::I32 => (v.number? as i32).to_le_bytes().to_vec(),
            ValueType::I64 => v.number?.to_le_bytes().to_vec(),
            ValueType::U8 => (v.number? as u8).to_le_bytes().to_vec(),
            ValueType::U16 => (v.number? as u16).to_le_bytes().to_vec(),
            ValueType::U32 => (v.number? as u32).to_le_bytes().to_vec(),
            ValueType::U64 => (v.number? as u64).to_le_bytes().to_vec(),
            ValueType::F32 => (v.float? as f32).to_le_bytes().to_vec(),
            ValueType::F64 => v.float?.to_le_bytes().to_vec(),
            ValueType::Bytes => v.bytes.clone()?,
            ValueType::String => v.string.clone()?.into_bytes(),
        })
    }

    fn decode_number(self, bytes: &[u8]) -> Option<i64> {
        match self {
            ValueType::I8 => Some(i8::from_le_bytes(bytes.get(..1)?.try_into().ok()?) as i64),
            ValueType::I16 => Some(i16::from_le_bytes(bytes.get(..2)?.try_into().ok()?) as i64),
            ValueType::I32 => Some(i32::from_le_bytes(bytes.get(..4)?.try_into().ok()?) as i64),
            ValueType::I64 => Some(i64::from_le_bytes(bytes.get(..8)?.try_into().ok()?)),
            ValueType::U8 => Some(u8::from_le_bytes(bytes.get(..1)?.try_into().ok()?) as i64),
            ValueType::U16 => Some(u16::from_le_bytes(bytes.get(..2)?.try_into().ok()?) as i64),
            ValueType::U32 => Some(u32::from_le_bytes(bytes.get(..4)?.try_into().ok()?) as i64),
            ValueType::U64 => {
                let v = u64::from_le_bytes(bytes.get(..8)?.try_into().ok()?);
                Some(v as i64)
            }
            _ => None,
        }
    }

    fn decode_float(self, bytes: &[u8]) -> Option<f64> {
        match self {
            ValueType::F32 => Some(f32::from_le_bytes(bytes.get(..4)?.try_into().ok()?) as f64),
            ValueType::F64 => Some(f64::from_le_bytes(bytes.get(..8)?.try_into().ok()?)),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanValue {
    pub number: Option<i64>,
    pub float: Option<f64>,
    pub bytes: Option<Vec<u8>>,
    pub string: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScanOp {
    Exact,
    Gt,
    Lt,
    Ge,
    Le,
    Ne,
    /// 再扫专用:跟上次不同
    Changed,
    /// 再扫专用:跟上次相同
    Unchanged,
    /// 再扫专用:比上次大
    IncreasedBy,
    /// 再扫专用:比上次小
    DecreasedBy,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ScanRequest {
    pub pid: u32,
    pub value_type: ValueType,
    pub op: ScanOp,
    /// Exact/Gt/Lt 等需要的值;Changed/Unchanged 可不填
    pub value: ScanValue,
    /// 起始/结束地址(0..u64::MAX = 全空间)
    pub addr_min: u64,
    pub addr_max: u64,
    /// P116: 对齐扫描. 默认 true (跟 CE 一致). 关掉退回字节滑动用于打包数据.
    /// 仅对 i16/u16/i32/u32/f32/i64/u64/f64 生效, byte/string 永远字节滑动.
    #[serde(default = "default_true")]
    pub aligned: bool,
}

fn default_true() -> bool { true }

#[derive(Debug, Clone, Serialize)]
pub struct ScanHit {
    pub address: u64,
    /// 当前值的可读形式(数字 / 浮点 / hex)
    pub display: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanResult {
    pub total: usize,
    /// 只返前 N 条给 UI;UI 想看更多翻页
    pub hits: Vec<ScanHit>,
    /// scan_next 诊断: prev 候选数 / RPM 失败数 / 实际比对数
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diag: Option<ScanDiag>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanDiag {
    pub prev_count: usize,
    pub read_failed: usize,
    pub compared: usize,
    pub matched: usize,
}

fn cmp_match(op: ScanOp, current_bytes: &[u8], wanted_bytes: &[u8], vt: ValueType) -> bool {
    match op {
        ScanOp::Exact => current_bytes.starts_with(wanted_bytes),
        ScanOp::Ne => !current_bytes.starts_with(wanted_bytes),
        ScanOp::Gt | ScanOp::Lt | ScanOp::Ge | ScanOp::Le => {
            // 浮点
            if let (Some(c), Some(w)) = (vt.decode_float(current_bytes), vt.decode_float(wanted_bytes)) {
                return match op {
                    ScanOp::Gt => c > w,
                    ScanOp::Lt => c < w,
                    ScanOp::Ge => c >= w,
                    ScanOp::Le => c <= w,
                    _ => false,
                };
            }
            if let (Some(c), Some(w)) = (vt.decode_number(current_bytes), vt.decode_number(wanted_bytes)) {
                return match op {
                    ScanOp::Gt => c > w,
                    ScanOp::Lt => c < w,
                    ScanOp::Ge => c >= w,
                    ScanOp::Le => c <= w,
                    _ => false,
                };
            }
            false
        }
        _ => false,
    }
}

fn format_value(vt: ValueType, bytes: &[u8]) -> String {
    if let Some(n) = vt.decode_number(bytes) {
        return n.to_string();
    }
    if let Some(f) = vt.decode_float(bytes) {
        return format!("{}", f);
    }
    bytes.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ")
}

const SCAN_MAX_HITS: usize = 1024;

#[tauri::command]
pub async fn dbg_scan_first(
    app: AppHandle,
    state: State<'_, Arc<DebuggerHandles>>,
    req: ScanRequest,
) -> AppResult<ScanResult> {
    let state = state.inner().clone();
    let mode = builtin_target_mode(&state, req.pid).ok_or_else(|| {
        AppError::Internal(format!(
            "PID {} is not attached to the built-in debugger",
            req.pid
        ))
    })?;
    SCAN_CANCEL.store(false, Ordering::Relaxed);
    tokio::task::spawn_blocking(move || -> AppResult<ScanResult> {
        let h = get_or_open(&state, req.pid)?;

        let wanted = req.value_type.encode(&req.value).ok_or_else(|| AppError::Internal("缺值".into()))?;
        let wsize = req.value_type.size(&req.value).max(1);

        // ---- Phase 1: 串行 VirtualQueryEx 收集所有可读 region (这步纯 syscall, 并行收益小) ----
        let mut regions: Vec<(usize, usize)> = Vec::new();   // (start, end), 已截到 [addr_min, addr_max]
        let mut addr: usize = req.addr_min as usize;
        let max_addr = (req.addr_max.min(0x7FFF_FFFF_FFFF)) as usize;
        unsafe {
            while addr < max_addr {
                let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
                let q = VirtualQueryEx(
                    h, Some(addr as *const c_void), &mut mbi,
                    std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                );
                if q == 0 { break; }
                let base = mbi.BaseAddress as usize;
                let size = mbi.RegionSize;
                let next = base.saturating_add(size);
                if size == 0 || next == addr { break; }

                let bad = mbi.State != MEM_COMMIT
                    || (mbi.Protect.0 & PAGE_NOACCESS.0) != 0
                    || (mbi.Protect.0 & PAGE_GUARD.0) != 0;
                if !bad {
                    let s = base.max(req.addr_min as usize);
                    let e = next.min(max_addr);
                    if e > s { regions.push((s, e)); }
                }
                addr = next;
            }
        }

        // 把进度信号源换成原子计数 (worker 累加扫过的字节数). 主线程 100ms 轮询发 emit.
        let total_bytes: u64 = regions.iter().map(|(s, e)| (e - s) as u64).sum();
        let scanned_bytes = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let hits_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));

        // 后台 emit 线程 — 不持锁
        let app_em = app.clone();
        let scanned_em = scanned_bytes.clone();
        let hits_em = hits_count.clone();
        let span = total_bytes.max(1);
        let stop_flag = Arc::new(AtomicBool::new(false));
        let stop_em = stop_flag.clone();
        let emit_handle = std::thread::spawn(move || {
            while !stop_em.load(Ordering::Relaxed) {
                std::thread::sleep(std::time::Duration::from_millis(100));
                let s = scanned_em.load(Ordering::Relaxed);
                let pct = (s as f64 / span as f64) * 100.0;
                let _ = app_em.emit("scan_progress", serde_json::json!({
                    "pct": pct.min(100.0),
                    "addr": s, // 用累计字节凑数, 反正只是进度条
                    "hits": hits_em.load(Ordering::Relaxed),
                    "cancelled": false,
                }));
            }
        });

        // ---- Phase 2: region 扫描 ----
        // Native 保留并行 RPM；VT 通过单一 device handle 做有界串行读取，
        // 避免把 rayon 并发放大成大量并发 IOCTL/VM-exit。
        let wanted_ref = wanted.as_slice();
        let vt = req.value_type;
        let op = req.op;
        let aligned = req.aligned && matches!(vt,
            ValueType::I16 | ValueType::U16
            | ValueType::I32 | ValueType::U32 | ValueType::F32
            | ValueType::I64 | ValueType::U64 | ValueType::F64);
        let scanned_w = scanned_bytes.clone();
        let hits_w = hits_count.clone();
        let mut hits: Vec<(u64, HitBytes)> = match mode {
            BuiltinDebugMode::Native => {
                use rayon::prelude::*;
                let raw_h = h.0 as usize; // HANDLE 不 Send, 用 raw 跨线程
                regions
                    .par_iter()
                    .map(|(s, e)| {
                        if SCAN_CANCEL.load(Ordering::Relaxed) {
                            return Vec::new();
                        }
                        let len = e - s;
                        let mut buf = vec![0u8; len];
                        let mut got: usize = 0;
                        let ok = unsafe {
                            ReadProcessMemory(
                                HANDLE(raw_h as _),
                                *s as *const c_void,
                                buf.as_mut_ptr() as *mut c_void,
                                len,
                                Some(&mut got),
                            )
                            .is_ok()
                        };
                        if !ok || got == 0 {
                            scanned_w.fetch_add(len as u64, Ordering::Relaxed);
                            return Vec::new();
                        }
                        let local_hits = scan_region(
                            &buf[..got],
                            *s as u64,
                            wsize,
                            aligned,
                            op,
                            vt,
                            wanted_ref,
                        );
                        hits_w.fetch_add(local_hits.len(), Ordering::Relaxed);
                        scanned_w.fetch_add(len as u64, Ordering::Relaxed);
                        local_hits
                    })
                    .reduce(Vec::new, |mut a, mut b| {
                        if a.len() + b.len() > 5_000_000 {
                            let remain = 5_000_000usize.saturating_sub(a.len());
                            b.truncate(remain);
                        }
                        a.append(&mut b);
                        a
                    })
            }
            BuiltinDebugMode::Vt => {
                const VT_SCAN_CHUNK: usize = 256 * 1024;
                let device = app.state::<DeviceState>();
                let mut out = Vec::new();
                'regions: for (start, end) in &regions {
                    let mut cursor = *start;
                    while cursor < *end {
                        if SCAN_CANCEL.load(Ordering::Relaxed) || out.len() >= 5_000_000 {
                            break 'regions;
                        }
                        let logical = (*end - cursor).min(VT_SCAN_CHUNK);
                        let overlap = wsize.saturating_sub(1);
                        let read_len = (*end - cursor).min(logical.saturating_add(overlap));
                        let bytes = match super::memory::memory_read_impl(
                            device.inner(),
                            req.pid,
                            cursor as u64,
                            read_len as u32,
                        ) {
                            Ok(bytes) => bytes,
                            Err(_) => {
                                scanned_w.fetch_add(logical as u64, Ordering::Relaxed);
                                cursor = cursor.saturating_add(logical);
                                continue;
                            }
                        };
                        let mut local = scan_region(
                            &bytes,
                            cursor as u64,
                            wsize,
                            aligned,
                            op,
                            vt,
                            wanted_ref,
                        );
                        let logical_end = (cursor + logical) as u64;
                        local.retain(|(address, _)| *address < logical_end);
                        if out.len() + local.len() > 5_000_000 {
                            local.truncate(5_000_000usize.saturating_sub(out.len()));
                        }
                        hits_w.fetch_add(local.len(), Ordering::Relaxed);
                        out.append(&mut local);
                        scanned_w.fetch_add(logical as u64, Ordering::Relaxed);
                        cursor = cursor.saturating_add(logical);
                    }
                }
                out
            }
        };

        // 停止 emit 线程
        stop_flag.store(true, Ordering::Relaxed);
        let _ = emit_handle.join();

        // par reduce 后地址顺序不固定 (region 之间的合并顺序), 排一下让 next_scan 的合并读受益
        hits.sort_unstable_by_key(|(a, _)| *a);

        let cancelled = SCAN_CANCEL.load(Ordering::Relaxed);
        let _ = app.emit("scan_progress", serde_json::json!({
            "pct": 100.0, "addr": max_addr as u64, "hits": hits.len(),
            "cancelled": cancelled, "done": true
        }));
        let total = hits.len();
        let preview: Vec<ScanHit> = hits
            .iter()
            .take(SCAN_MAX_HITS)
            .map(|(addr, bytes)| ScanHit {
                address: *addr,
                display: format_value(req.value_type, bytes),
            })
            .collect();

        state.scan_state.lock().insert(
            req.pid,
            ScanState { value_type: req.value_type, hits },
        );

        Ok(ScanResult { total, hits: preview, diag: None })
    })
    .await
    .map_err(|e| AppError::Internal(format!("spawn_blocking: {e}")))?
}

/// P116: 单 region 内热路径扫描. 编译器能向量化 chunks_exact 的 cmp.
///
/// `aligned`: true 时步进 = wsize, false 时 = 1.
/// 返回 Vec 而非 SmallVec 是因为 par reduce 要 append, 内部 hit 元素仍是 HitBytes (inline 8B).
fn scan_region(
    buf: &[u8],
    region_base: u64,
    wsize: usize,
    aligned: bool,
    op: ScanOp,
    vt: ValueType,
    wanted: &[u8],
) -> Vec<(u64, HitBytes)> {
    let mut out = Vec::new();
    if wsize == 0 || buf.len() < wsize { return out; }

    // Exact 的 wsize=1..8 路径用 typed 比较, 编译器/LLVM 用 SIMD 自动向量化
    if matches!(op, ScanOp::Exact) && aligned {
        match wsize {
            4 => {
                let w = u32::from_le_bytes(wanted[..4].try_into().unwrap());
                let mut i = 0;
                let end = buf.len();
                while i + 4 <= end {
                    let v = u32::from_le_bytes(buf[i..i+4].try_into().unwrap());
                    if v == w {
                        let mut sv = HitBytes::new();
                        sv.extend_from_slice(&buf[i..i+4]);
                        out.push((region_base + i as u64, sv));
                    }
                    i += 4;
                }
                return out;
            }
            8 => {
                let w = u64::from_le_bytes(wanted[..8].try_into().unwrap());
                let mut i = 0;
                let end = buf.len();
                while i + 8 <= end {
                    let v = u64::from_le_bytes(buf[i..i+8].try_into().unwrap());
                    if v == w {
                        let mut sv = HitBytes::new();
                        sv.extend_from_slice(&buf[i..i+8]);
                        out.push((region_base + i as u64, sv));
                    }
                    i += 8;
                }
                return out;
            }
            2 => {
                let w = u16::from_le_bytes(wanted[..2].try_into().unwrap());
                let mut i = 0;
                let end = buf.len();
                while i + 2 <= end {
                    let v = u16::from_le_bytes(buf[i..i+2].try_into().unwrap());
                    if v == w {
                        let mut sv = HitBytes::new();
                        sv.extend_from_slice(&buf[i..i+2]);
                        out.push((region_base + i as u64, sv));
                    }
                    i += 2;
                }
                return out;
            }
            _ => {}
        }
    }

    // 通用回退: aligned 步进 wsize, 非 aligned 步进 1
    let step = if aligned { wsize } else { 1 };
    let mut i = 0;
    while i + wsize <= buf.len() {
        if cmp_match(op, &buf[i..i+wsize], wanted, vt) {
            let mut sv = HitBytes::new();
            sv.extend_from_slice(&buf[i..i+wsize]);
            out.push((region_base + i as u64, sv));
        }
        i += step;
    }
    out
}

#[derive(Debug, Clone, Deserialize)]
pub struct ScanNextRequest {
    pub pid: u32,
    pub op: ScanOp,
    pub value: ScanValue,
}

#[tauri::command]
pub async fn dbg_scan_next(
    state: State<'_, Arc<DebuggerHandles>>,
    req: ScanNextRequest,
) -> AppResult<ScanResult> {
    let state = state.inner().clone();
    tokio::task::spawn_blocking(move || -> AppResult<ScanResult> {
        let h = get_or_open(&state, req.pid)?;

        let (vt, prev) = {
            let g = state.scan_state.lock();
            let st = g.get(&req.pid).ok_or_else(|| AppError::Internal("没有上一轮扫描结果".into()))?;
            (st.value_type, st.hits.clone())
        };

        let wsize = match vt {
            ValueType::I8 | ValueType::U8 => 1,
            ValueType::I16 | ValueType::U16 => 2,
            ValueType::I32 | ValueType::U32 | ValueType::F32 => 4,
            ValueType::I64 | ValueType::U64 | ValueType::F64 => 8,
            ValueType::Bytes => req.value.bytes.as_ref().map(|b| b.len()).unwrap_or(0),
            ValueType::String => req.value.string.as_ref().map(|s| s.len()).unwrap_or(0),
        };
        if wsize == 0 {
            return Err(AppError::Internal("wsize=0".into()));
        }

        let wanted_bytes = vt.encode(&req.value);

        // ---- P116: 把相邻 hit 合并成 batch, 一次 RPM 读连续区段, 内存内切片对比 ----
        //
        // prev 已按 addr 排序 (first_scan / next_scan 收尾都 sort). 用滑窗合并:
        // 当下一个 hit 的 addr <= 当前 batch end + JOIN_GAP 时, 把它纳入同一 batch.
        // JOIN_GAP 选 64KB 是经验值:跨页 syscall 开销 ~5-8us, RPM 读 64KB ~10-20us,
        // 合并门槛超过 64KB 收益就转负 (拷贝太多没用的字节)。
        const JOIN_GAP: u64 = 64 * 1024;
        const MAX_BATCH: u64 = 1 * 1024 * 1024;   // 单 batch 上限 1MB, 防 hit 散布到几 GB 范围被合成超大读

        // 第一遍: 划 batch
        struct Batch { start: u64, end: u64, idx_range: (usize, usize) }    // [start, end), prev[idx_lo..idx_hi]
        let mut batches: Vec<Batch> = Vec::new();
        let mut i = 0;
        while i < prev.len() {
            let s = prev[i].0;
            let mut e = s + wsize as u64;
            let lo = i;
            while i + 1 < prev.len() {
                let next_s = prev[i + 1].0;
                let candidate_end = (next_s + wsize as u64).max(e);
                if next_s <= e + JOIN_GAP && (candidate_end - s) <= MAX_BATCH {
                    e = candidate_end;
                    i += 1;
                } else {
                    break;
                }
            }
            batches.push(Batch { start: s, end: e, idx_range: (lo, i + 1) });
            i += 1;
        }

        // 第二遍: rayon 并行读各 batch, 内存内切片比对
        use rayon::prelude::*;
        let raw_h = h.0 as usize;
        let wanted_ref = wanted_bytes.as_deref();
        let op = req.op;

        // 累计统计 (read_failed / compared) — 用原子, 不要在 reduce 里加 tuple 字段
        let read_failed = std::sync::atomic::AtomicUsize::new(0);
        let compared = std::sync::atomic::AtomicUsize::new(0);

        let mut kept: Vec<(u64, HitBytes)> = batches.par_iter().flat_map_iter(|b| {
            let len = (b.end - b.start) as usize;
            let mut buf = vec![0u8; len];
            let mut got: usize = 0;
            let ok = unsafe {
                ReadProcessMemory(
                    HANDLE(raw_h as _),
                    b.start as *const c_void,
                    buf.as_mut_ptr() as *mut c_void,
                    len,
                    Some(&mut got),
                ).is_ok()
            };
            if !ok || got == 0 {
                // 整 batch RPM 失败 — 给每个 hit 计 1 次 read_failed
                read_failed.fetch_add(b.idx_range.1 - b.idx_range.0, Ordering::Relaxed);
                return Vec::new().into_iter();
            }

            let mut local: Vec<(u64, HitBytes)> = Vec::new();
            for (addr, prev_bytes) in &prev[b.idx_range.0 .. b.idx_range.1] {
                let off = (*addr - b.start) as usize;
                if off + wsize > got {
                    read_failed.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                let cur = &buf[off..off + wsize];
                compared.fetch_add(1, Ordering::Relaxed);

                let keep = match op {
                    ScanOp::Exact | ScanOp::Ne | ScanOp::Gt | ScanOp::Lt | ScanOp::Ge | ScanOp::Le => {
                        let w = wanted_ref.unwrap_or(prev_bytes.as_slice());
                        cmp_match(op, cur, w, vt)
                    }
                    ScanOp::Changed => cur != prev_bytes.as_slice(),
                    ScanOp::Unchanged => cur == prev_bytes.as_slice(),
                    ScanOp::IncreasedBy => {
                        if let (Some(c), Some(p)) = (vt.decode_number(cur), vt.decode_number(prev_bytes)) { c > p }
                        else if let (Some(c), Some(p)) = (vt.decode_float(cur), vt.decode_float(prev_bytes)) { c > p }
                        else { false }
                    }
                    ScanOp::DecreasedBy => {
                        if let (Some(c), Some(p)) = (vt.decode_number(cur), vt.decode_number(prev_bytes)) { c < p }
                        else if let (Some(c), Some(p)) = (vt.decode_float(cur), vt.decode_float(prev_bytes)) { c < p }
                        else { false }
                    }
                };

                if keep {
                    let mut sv = HitBytes::new();
                    sv.extend_from_slice(cur);
                    local.push((*addr, sv));
                }
            }
            local.into_iter()
        }).collect();

        // par 收尾后保证 addr 升序 (batch 间并行, 顺序不保证)
        kept.sort_unstable_by_key(|(a, _)| *a);

        let total = kept.len();
        let preview: Vec<ScanHit> = kept
            .iter()
            .take(SCAN_MAX_HITS)
            .map(|(addr, bytes)| ScanHit {
                address: *addr,
                display: format_value(vt, bytes),
            })
            .collect();

        let prev_count = prev.len();
        let read_failed = read_failed.load(Ordering::Relaxed);
        let compared = compared.load(Ordering::Relaxed);
        state.scan_state.lock().insert(req.pid, ScanState { value_type: vt, hits: kept });
        Ok(ScanResult {
            total,
            hits: preview,
            diag: Some(ScanDiag {
                prev_count,
                read_failed,
                compared,
                matched: total,
            }),
        })
    })
    .await
    .map_err(|e| AppError::Internal(format!("spawn_blocking: {e}")))?
}

#[tauri::command]
pub fn dbg_scan_reset(state: State<'_, Arc<DebuggerHandles>>, pid: u32) -> AppResult<()> {
    state.scan_state.lock().remove(&pid);
    Ok(())
}

// P110: 给前端实时刷新扫描结果用 — 读 N 个地址当前值, 返 display 字符串数组.
// 不动 scan_state, 不影响下一轮 scan_next.
#[derive(Debug, Clone, Deserialize)]
pub struct ScanRefreshReq {
    pub pid: u32,
    pub value_type: ValueType,
    /// 要刷的地址列表 — 一般是当前 UI 可见的几十条
    pub addresses: Vec<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanRefreshResult {
    /// 每个地址当前值的 display, RPM 失败 = "?"
    pub values: Vec<String>,
}

#[tauri::command]
pub async fn dbg_scan_refresh(
    state: State<'_, Arc<DebuggerHandles>>,
    req: ScanRefreshReq,
) -> AppResult<ScanRefreshResult> {
    let state = state.inner().clone();
    tokio::task::spawn_blocking(move || -> AppResult<ScanRefreshResult> {
        let h = get_or_open(&state, req.pid)?;
        let wsize = match req.value_type {
            ValueType::I8 | ValueType::U8 => 1,
            ValueType::I16 | ValueType::U16 => 2,
            ValueType::I32 | ValueType::U32 | ValueType::F32 => 4,
            ValueType::I64 | ValueType::U64 | ValueType::F64 => 8,
            ValueType::Bytes | ValueType::String => 16, // 取 16 字节预览
        };

        // P116: 同 next_scan, 用 batch 合并连续地址段, 一次 RPM 读一段
        // GUI 200ms 轮询时 5000 个 addr 默认 5000 次 syscall ~25ms, 合并后 ~10 次 ~1ms.
        // 这里给 addresses 临时排序但保留原顺序映射, 因为 GUI 期望按 req.addresses 顺序回值.
        let n = req.addresses.len();
        let mut sorted_idx: Vec<usize> = (0..n).collect();
        sorted_idx.sort_unstable_by_key(|&i| req.addresses[i]);

        const JOIN_GAP: u64 = 64 * 1024;
        const MAX_BATCH: u64 = 1 * 1024 * 1024;

        let mut out: Vec<String> = vec![String::new(); n];

        let mut i = 0;
        while i < n {
            let s_addr = req.addresses[sorted_idx[i]];
            let mut e_addr = s_addr + wsize as u64;
            let lo = i;
            while i + 1 < n {
                let next_a = req.addresses[sorted_idx[i + 1]];
                let cand_end = (next_a + wsize as u64).max(e_addr);
                if next_a <= e_addr + JOIN_GAP && (cand_end - s_addr) <= MAX_BATCH {
                    e_addr = cand_end;
                    i += 1;
                } else {
                    break;
                }
            }
            // 一次 RPM
            let len = (e_addr - s_addr) as usize;
            let mut buf = vec![0u8; len];
            let mut got = 0usize;
            let ok = unsafe {
                ReadProcessMemory(
                    h, s_addr as *const c_void,
                    buf.as_mut_ptr() as *mut c_void, len, Some(&mut got),
                ).is_ok()
            };
            for j in lo..=i {
                let orig = sorted_idx[j];
                let addr = req.addresses[orig];
                let off = (addr - s_addr) as usize;
                if ok && off + wsize <= got {
                    out[orig] = format_value(req.value_type, &buf[off..off + wsize]);
                } else {
                    out[orig] = "?".into();
                }
            }
            i += 1;
        }
        Ok(ScanRefreshResult { values: out })
    })
    .await
    .map_err(|e| AppError::Internal(format!("spawn_blocking: {e}")))?
}

// ============================================================
// utils
// ============================================================

fn utf16_to_string(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}
