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
use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tauri::{AppHandle, Emitter, Manager, State, WebviewUrl, WebviewWindowBuilder};
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Diagnostics::Debug::{
    GetThreadContext, ReadProcessMemory, SetThreadContext, WriteProcessMemory, CONTEXT,
    CONTEXT_ALL_AMD64, CONTEXT_CONTROL_AMD64, CONTEXT_INTEGER_AMD64,
};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, Thread32First, Thread32Next,
    MODULEENTRY32W, TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32, TH32CS_SNAPTHREAD, THREADENTRY32,
};
use windows::Win32::System::Memory::{
    VirtualProtectEx, VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, PAGE_EXECUTE_READWRITE,
    PAGE_GUARD, PAGE_NOACCESS, PAGE_PROTECTION_FLAGS,
};
use windows::Win32::System::Threading::{
    OpenProcess, OpenThread, ResumeThread, SuspendThread, PROCESS_ALL_ACCESS,
    PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE,
    THREAD_GET_CONTEXT, THREAD_SET_CONTEXT, THREAD_SUSPEND_RESUME,
};

use crate::ioctl::DeviceState;
use crate::util::error::{AppError, AppResult};

static SESSION_SEQ: AtomicU64 = AtomicU64::new(1);

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
pub fn spawn_freeze_writer(handles: Arc<DebuggerHandles>, freeze: Arc<FreezeStore>) {
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
                    let mut _wrote = 0;
                    let _ = WriteProcessMemory(
                        h,
                        addr as *const c_void,
                        bytes.as_ptr() as *const c_void,
                        bytes.len(),
                        Some(&mut _wrote),
                    );
                    let mut _x: PAGE_PROTECTION_FLAGS = std::mem::zeroed();
                    let _ = VirtualProtectEx(h, addr as *const c_void, bytes.len(), old, &mut _x);
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
pub struct DebuggerHandles {
    // pid -> handle (PROCESS_ALL_ACCESS)
    procs: Mutex<std::collections::HashMap<u32, isize>>,
    // pid -> 上次成功的模块列表(失败时回退)
    module_cache: Mutex<std::collections::HashMap<u32, Vec<ModuleInfo>>>,
    // pid -> Vec<(addr, original_byte)>  软断点备份
    sw_bps: Mutex<std::collections::HashMap<u32, Vec<(u64, u8)>>>,
    // pid -> 上一轮扫描结果(原始字节序列 + 每个命中地址)
    scan_state: Mutex<std::collections::HashMap<u32, ScanState>>,
    // P56 临时断点(步过/步出装的 sw bp): 命中后自动清。pid -> set of addresses
    transient_bps: Mutex<std::collections::HashMap<u32, std::collections::HashSet<u64>>>,
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
    state.module_cache.lock().remove(&pid);
}

#[tauri::command]
pub fn dbg_detach(state: State<'_, Arc<DebuggerHandles>>, pid: u32) -> AppResult<()> {
    release_pid(&state, pid);
    Ok(())
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
    pid: u32,
    address: u64,
    size: u32,
) -> AppResult<ReadResult> {
    let state = state.inner().clone();
    let size = size.min(64 * 1024) as usize;
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
    pid: u32,
    address: u64,
    bytes: Vec<u8>,
) -> AppResult<()> {
    let state = state.inner().clone();
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

#[tauri::command]
pub async fn dbg_disasm(address: u64, bytes: Vec<u8>) -> AppResult<Vec<DisasmLine>> {
    tokio::task::spawn_blocking(move || -> AppResult<Vec<DisasmLine>> {
        let mut decoder = Decoder::with_ip(64, &bytes, address, DecoderOptions::NONE);
        let mut formatter = IntelFormatter::new();
        formatter.options_mut().set_first_operand_char_index(8);
        formatter.options_mut().set_uppercase_hex(false);

        let mut out: Vec<DisasmLine> = Vec::with_capacity(bytes.len() / 4);
        let mut insn = Instruction::default();
        let mut text = String::with_capacity(64);
        while decoder.can_decode() {
            let ip = decoder.ip();
            decoder.decode_out(&mut insn);
            text.clear();
            formatter.format(&insn, &mut text);
            let off = (ip - address) as usize;
            let len = insn.len();
            let bh = bytes[off..off + len]
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<Vec<_>>()
                .join(" ");
            out.push(DisasmLine {
                address: ip,
                bytes_hex: bh,
                text: text.clone(),
                len: len as u8,
            });
        }
        Ok(out)
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

#[tauri::command]
pub async fn dbg_list_modules(
    state: State<'_, Arc<DebuggerHandles>>,
    pid: u32,
) -> AppResult<Vec<ModuleInfo>> {
    let state = state.inner().clone();
    tokio::task::spawn_blocking(move || -> AppResult<Vec<ModuleInfo>> {
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
                    out.sort_by_key(|m| m.base);
                    if out.is_empty() { None } else { Some(out) }
                }
                Err(_) => None,
            }
        };

        match result {
            Some(mods) => {
                state.module_cache.lock().insert(pid, mods.clone());
                Ok(mods)
            }
            None => {
                // 失败回退缓存,无缓存则返空 Vec (调用方按"模块未知"处理,不弹错)
                let cached = state.module_cache.lock().get(&pid).cloned().unwrap_or_default();
                Ok(cached)
            }
        }
    })
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

#[tauri::command]
pub async fn dbg_resume_thread(tid: u32) -> AppResult<u32> {
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

/// P51 单步: 拿 ctx → 置 EFLAGS.TF=1 → 通知 driver arm tid → resume
/// 下一条指令引发 #DB(BS), driver 命中后 post BREAK_HIT, R3 不需要再 suspend
/// (driver 当前实现是"上报但放行 guest",所以 R3 应当先 SuspendThread 再拿 ctx)
#[tauri::command]
pub async fn dbg_step_into(
    device: State<'_, DeviceState>,
    tid: u32,
) -> AppResult<()> {
    // 1. 同步通知 driver
    if device.is_open() {
        let buf = tid.to_le_bytes();
        let mut out = [0u8; 16];
        let _ = device.ioctl(crate::ioctl::codes::IOCTL_HV_DBG_STEP_ARM, &buf, &mut out);
    }
    // 2. R3 改 EFLAGS.TF + resume
    tokio::task::spawn_blocking(move || -> AppResult<()> {
        unsafe {
            let h = OpenThread(
                THREAD_SET_CONTEXT | THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME,
                false,
                tid,
            )
            .map_err(|e| AppError::Internal(format!("OpenThread({tid}): {e}")))?;
            // 必须先 suspend 才能拿 ctx
            let _ = SuspendThread(h);
            #[repr(align(16))]
            struct AlignedContext(CONTEXT);
            let mut ctx = AlignedContext(std::mem::zeroed::<CONTEXT>());
            ctx.0.ContextFlags = CONTEXT_CONTROL_AMD64 | CONTEXT_INTEGER_AMD64;
            let got_ok = GetThreadContext(h, &mut ctx.0).is_ok();
            if !got_ok {
                let _ = ResumeThread(h);
                let _ = CloseHandle(h);
                return Err(AppError::Internal("GetThreadContext failed".into()));
            }
            ctx.0.EFlags |= 0x100; // TF
            let set_ok = SetThreadContext(h, &ctx.0).is_ok();
            // resume (我们多 suspend 了一次,要 resume 两次让回到原 suspend count)
            let _ = ResumeThread(h);
            let _ = ResumeThread(h);
            let _ = CloseHandle(h);
            if !set_ok {
                return Err(AppError::Internal("SetThreadContext(TF=1) failed".into()));
            }
            Ok(())
        }
    })
    .await
    .map_err(|e| AppError::Internal(format!("spawn_blocking: {e}")))?
}

/// P56 真步过:
///   - 读 16 字节 from RIP
///   - iced 解码一条
///   - call / int / syscall / loop / rep 前缀: 在 RIP+len 装临时 sw bp,标 transient,resume
///   - 其它: 等同 step-into (EFLAGS.TF=1 + resume)
///
/// 返回 (kind, next_rip):
///   kind="step"      → 走的 TF 单步
///   kind="run-over"  → 装了临时 bp 在 next_rip,等命中
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
) -> AppResult<StepOverResult> {
    use iced_x86::FlowControl;
    let state_clone = state.inner().clone();

    // 1. 拿 RIP,反汇编一条
    let (rip, len, fc): (u64, u32, FlowControl) = tokio::task::spawn_blocking(move || -> AppResult<(u64, u32, FlowControl)> {
        unsafe {
            let h = OpenThread(
                THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME,
                false,
                tid,
            )
            .map_err(|e| AppError::Internal(format!("OpenThread({tid}): {e}")))?;
            let _ = SuspendThread(h);
            #[repr(align(16))]
            struct AlignedContext(CONTEXT);
            let mut ctx = AlignedContext(std::mem::zeroed::<CONTEXT>());
            ctx.0.ContextFlags = CONTEXT_CONTROL_AMD64 | CONTEXT_INTEGER_AMD64;
            let got = GetThreadContext(h, &mut ctx.0).is_ok();
            let rip = ctx.0.Rip;
            let _ = ResumeThread(h);
            let _ = CloseHandle(h);
            if !got {
                return Err(AppError::Internal("GetThreadContext failed".into()));
            }
            // 读 16 字节
            let ph = get_or_open(&state_clone, pid)?;
            let r = read_safe(ph, rip, 16);
            if r.bytes.is_empty() {
                return Err(AppError::Internal("无法读 RIP 字节".into()));
            }
            let mut decoder = iced_x86::Decoder::with_ip(64, &r.bytes, rip, iced_x86::DecoderOptions::NONE);
            let insn = decoder.decode();
            Ok((rip, insn.len() as u32, insn.flow_control()))
        }
    })
    .await
    .map_err(|e| AppError::Internal(format!("spawn_blocking: {e}")))??;

    let stepover = matches!(
        fc,
        FlowControl::Call
            | FlowControl::IndirectCall
            | FlowControl::Interrupt
    );
    // rep/loop 前缀: iced 用 Next 表示一般指令;rep 不在 FlowControl 里
    // 简化: 只识别 call/interrupt 这两种典型 "停留在当前栈层" 的指令

    if !stepover {
        // 等同 step-into
        if device.is_open() {
            let buf = tid.to_le_bytes();
            let mut out = [0u8; 16];
            let _ = device.ioctl(crate::ioctl::codes::IOCTL_HV_DBG_STEP_ARM, &buf, &mut out);
        }
        tokio::task::spawn_blocking(move || -> AppResult<()> {
            unsafe {
                let h = OpenThread(
                    THREAD_SET_CONTEXT | THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME,
                    false,
                    tid,
                )
                .map_err(|e| AppError::Internal(format!("OpenThread({tid}): {e}")))?;
                let _ = SuspendThread(h);
                #[repr(align(16))]
                struct AlignedContext(CONTEXT);
                let mut ctx = AlignedContext(std::mem::zeroed::<CONTEXT>());
                ctx.0.ContextFlags = CONTEXT_CONTROL_AMD64 | CONTEXT_INTEGER_AMD64;
                let got = GetThreadContext(h, &mut ctx.0).is_ok();
                if !got {
                    let _ = ResumeThread(h);
                    let _ = CloseHandle(h);
                    return Err(AppError::Internal("GetThreadContext failed".into()));
                }
                ctx.0.EFlags |= 0x100;
                let set = SetThreadContext(h, &ctx.0).is_ok();
                let _ = ResumeThread(h);
                let _ = ResumeThread(h);
                let _ = CloseHandle(h);
                if !set {
                    return Err(AppError::Internal("SetThreadContext(TF) failed".into()));
                }
                Ok(())
            }
        })
        .await
        .map_err(|e| AppError::Internal(format!("spawn_blocking: {e}")))??;
        return Ok(StepOverResult { kind: "step", next_rip: rip + len as u64 });
    }

    // step-over: 在 rip+len 装一个 sw bp,标 transient,resume
    let next = rip + len as u64;
    let state_clone2 = state.inner().clone();
    let pid_const = pid;
    tokio::task::spawn_blocking(move || -> AppResult<()> {
        unsafe {
            let h = get_or_open(&state_clone2, pid_const)?;
            let r = read_safe(h, next, 1);
            if r.bytes.is_empty() || r.truncated {
                return Err(AppError::Internal("无法读 next 字节".into()));
            }
            let orig = r.bytes[0];
            let mut old: PAGE_PROTECTION_FLAGS = std::mem::zeroed();
            let _ = VirtualProtectEx(h, next as *const c_void, 1, PAGE_EXECUTE_READWRITE, &mut old);
            let cc: u8 = 0xCC;
            let mut wrote = 0;
            let ok = WriteProcessMemory(
                h,
                next as *const c_void,
                &cc as *const u8 as *const c_void,
                1,
                Some(&mut wrote),
            )
            .is_ok();
            let mut _x: PAGE_PROTECTION_FLAGS = std::mem::zeroed();
            let _ = VirtualProtectEx(h, next as *const c_void, 1, old, &mut _x);
            if !ok || wrote != 1 {
                let err = windows::Win32::Foundation::GetLastError();
                return Err(AppError::Internal(format!("写 0xCC 失败: GLE=0x{:x}", err.0)));
            }
            // 记账:正式 sw_bps 列表里加 (next, orig);并加入 transient 集合
            state_clone2.sw_bps.lock().entry(pid_const).or_default().push((next, orig));
            state_clone2.transient_bps.lock().entry(pid_const).or_default().insert(next);
            Ok(())
        }
    })
    .await
    .map_err(|e| AppError::Internal(format!("spawn_blocking: {e}")))??;

    // driver 也注册 sw bp (跟 dbg_sw_bp_set 一样)
    driver_register_sw_bp(&device, pid, next);
    // resume
    tokio::task::spawn_blocking(move || -> AppResult<()> {
        unsafe {
            let h = OpenThread(THREAD_SUSPEND_RESUME, false, tid)
                .map_err(|e| AppError::Internal(format!("OpenThread: {e}")))?;
            let _ = ResumeThread(h);
            let _ = CloseHandle(h);
            Ok(())
        }
    })
    .await
    .map_err(|e| AppError::Internal(format!("spawn_blocking: {e}")))??;
    Ok(StepOverResult { kind: "run-over", next_rip: next })
}

/// P56 步出: walk 栈拿 return address (RSP+0),装临时 sw bp + resume
#[tauri::command]
pub async fn dbg_step_out(
    state: State<'_, Arc<DebuggerHandles>>,
    device: State<'_, DeviceState>,
    pid: u32,
    tid: u32,
) -> AppResult<u64> {
    let state_clone = state.inner().clone();
    let ret_addr: u64 = tokio::task::spawn_blocking(move || -> AppResult<u64> {
        unsafe {
            let h = OpenThread(THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME, false, tid)
                .map_err(|e| AppError::Internal(format!("OpenThread: {e}")))?;
            let _ = SuspendThread(h);
            #[repr(align(16))]
            struct AlignedContext(CONTEXT);
            let mut ctx = AlignedContext(std::mem::zeroed::<CONTEXT>());
            ctx.0.ContextFlags = CONTEXT_CONTROL_AMD64 | CONTEXT_INTEGER_AMD64;
            let got = GetThreadContext(h, &mut ctx.0).is_ok();
            let rsp = ctx.0.Rsp;
            let _ = ResumeThread(h);
            let _ = CloseHandle(h);
            if !got {
                return Err(AppError::Internal("GetThreadContext failed".into()));
            }
            let ph = get_or_open(&state_clone, pid)?;
            let r = read_safe(ph, rsp, 8);
            if r.bytes.len() < 8 {
                return Err(AppError::Internal("读 RSP 不够 8 字节".into()));
            }
            let v = u64::from_le_bytes(r.bytes[..8].try_into().unwrap());
            Ok(v)
        }
    })
    .await
    .map_err(|e| AppError::Internal(format!("spawn_blocking: {e}")))??;

    // 装 sw bp + transient
    let state_clone2 = state.inner().clone();
    tokio::task::spawn_blocking(move || -> AppResult<()> {
        unsafe {
            let h = get_or_open(&state_clone2, pid)?;
            let r = read_safe(h, ret_addr, 1);
            if r.bytes.is_empty() {
                return Err(AppError::Internal("ret addr 不可读".into()));
            }
            let orig = r.bytes[0];
            let mut old: PAGE_PROTECTION_FLAGS = std::mem::zeroed();
            let _ = VirtualProtectEx(h, ret_addr as *const c_void, 1, PAGE_EXECUTE_READWRITE, &mut old);
            let cc: u8 = 0xCC;
            let mut wrote = 0;
            let ok = WriteProcessMemory(h, ret_addr as *const c_void, &cc as *const u8 as *const c_void, 1, Some(&mut wrote)).is_ok();
            let mut _x: PAGE_PROTECTION_FLAGS = std::mem::zeroed();
            let _ = VirtualProtectEx(h, ret_addr as *const c_void, 1, old, &mut _x);
            if !ok || wrote != 1 {
                let err = windows::Win32::Foundation::GetLastError();
                return Err(AppError::Internal(format!("写 0xCC 失败: GLE=0x{:x}", err.0)));
            }
            state_clone2.sw_bps.lock().entry(pid).or_default().push((ret_addr, orig));
            state_clone2.transient_bps.lock().entry(pid).or_default().insert(ret_addr);
            Ok(())
        }
    })
    .await
    .map_err(|e| AppError::Internal(format!("spawn_blocking: {e}")))??;
    driver_register_sw_bp(&device, pid, ret_addr);
    // resume
    tokio::task::spawn_blocking(move || -> AppResult<()> {
        unsafe {
            let h = OpenThread(THREAD_SUSPEND_RESUME, false, tid)
                .map_err(|e| AppError::Internal(format!("OpenThread: {e}")))?;
            let _ = ResumeThread(h);
            let _ = CloseHandle(h);
            Ok(())
        }
    })
    .await
    .map_err(|e| AppError::Internal(format!("spawn_blocking: {e}")))??;
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
    let is_transient = {
        let mut g = state.transient_bps.lock();
        if let Some(set) = g.get_mut(&pid) {
            set.remove(&address)
        } else {
            false
        }
    };
    if !is_transient {
        return Ok(false);
    }
    // 清这个 sw bp (走标准路径还原字节 + driver unregister)
    let state_clone = state.inner().clone();
    tokio::task::spawn_blocking(move || -> AppResult<()> {
        let orig = {
            let mut g = state_clone.sw_bps.lock();
            let vec = g.get_mut(&pid).ok_or_else(|| AppError::Internal("无此 pid 的软断点".into()))?;
            let idx = vec.iter().position(|(a, _)| *a == address)
                .ok_or_else(|| AppError::Internal("无此地址的软断点".into()))?;
            vec.swap_remove(idx).1
        };
        unsafe {
            let h = get_or_open(&state_clone, pid)?;
            let mut old: PAGE_PROTECTION_FLAGS = std::mem::zeroed();
            let _ = VirtualProtectEx(h, address as *const c_void, 1, PAGE_EXECUTE_READWRITE, &mut old);
            let mut wrote = 0;
            let _ = WriteProcessMemory(
                h,
                address as *const c_void,
                &orig as *const u8 as *const c_void,
                1,
                Some(&mut wrote),
            );
            let mut _x: PAGE_PROTECTION_FLAGS = std::mem::zeroed();
            let _ = VirtualProtectEx(h, address as *const c_void, 1, old, &mut _x);
        }
        Ok(())
    })
    .await
    .map_err(|e| AppError::Internal(format!("spawn_blocking: {e}")))??;
    driver_unregister_sw_bp(&device, pid, address);
    Ok(true)
}

// ============================================================
// 软断点 (int3) — set/clear,自动备份原字节
// ============================================================

#[derive(Debug, Clone, Serialize)]
pub struct SwBreakpoint {
    pub address: u64,
    pub original_byte: u8,
}

/// 向 driver 注册软断点(R3 仍是 0xCC 字节,driver 仅登记 (pid, address) 用于 #BP 反查)。
/// driver 未加载 / IOCTL 失败时不阻断 — 当作 R3 only 断点继续(命中不会上报事件)。
fn driver_register_sw_bp(device: &DeviceState, target_pid: u32, address: u64) {
    if !device.is_open() {
        return;
    }
    #[repr(C, packed)]
    struct SwBpReq { target_pid: u32, _pad: u32, address: u64 }
    let req = SwBpReq { target_pid, _pad: 0, address };
    let buf = unsafe {
        std::slice::from_raw_parts(
            (&req as *const SwBpReq) as *const u8,
            std::mem::size_of::<SwBpReq>(),
        )
    };
    let mut out = [0u8; 16];
    let _ = device.ioctl(crate::ioctl::codes::IOCTL_HV_DBG_SW_BP_ADD, buf, &mut out);
}

fn driver_unregister_sw_bp(device: &DeviceState, target_pid: u32, address: u64) {
    if !device.is_open() {
        return;
    }
    #[repr(C, packed)]
    struct SwBpReq { target_pid: u32, _pad: u32, address: u64 }
    let req = SwBpReq { target_pid, _pad: 0, address };
    let buf = unsafe {
        std::slice::from_raw_parts(
            (&req as *const SwBpReq) as *const u8,
            std::mem::size_of::<SwBpReq>(),
        )
    };
    let mut out = [0u8; 16];
    let _ = device.ioctl(crate::ioctl::codes::IOCTL_HV_DBG_SW_BP_DEL, buf, &mut out);
}

#[tauri::command]
pub async fn dbg_sw_bp_set(
    state: State<'_, Arc<DebuggerHandles>>,
    device: State<'_, DeviceState>,
    pid: u32,
    address: u64,
) -> AppResult<SwBreakpoint> {
    let state = state.inner().clone();
    // 先把 driver 注册(同步, 几微秒) — 不能跨 spawn_blocking 因为 DeviceState 不 Clone
    driver_register_sw_bp(&device, pid, address);
    let bp = tokio::task::spawn_blocking(move || -> AppResult<SwBreakpoint> {
        let h = get_or_open(&state, pid)?;
        // 读 1 字节备份
        let r = read_safe(h, address, 1);
        if r.bytes.is_empty() || r.truncated {
            return Err(AppError::Internal("无法读目标字节".into()));
        }
        let orig = r.bytes[0];

        // 写 0xCC
        unsafe {
            let mut old: PAGE_PROTECTION_FLAGS = std::mem::zeroed();
            let _ = VirtualProtectEx(h, address as *const c_void, 1, PAGE_EXECUTE_READWRITE, &mut old);
            let mut wrote = 0;
            let cc: u8 = 0xCC;
            let ok = WriteProcessMemory(
                h,
                address as *const c_void,
                &cc as *const u8 as *const c_void,
                1,
                Some(&mut wrote),
            )
            .is_ok();
            let mut _x: PAGE_PROTECTION_FLAGS = std::mem::zeroed();
            let _ = VirtualProtectEx(h, address as *const c_void, 1, old, &mut _x);
            if !ok || wrote != 1 {
                let err = windows::Win32::Foundation::GetLastError();
                return Err(AppError::Internal(format!("写 0xCC 失败: GLE=0x{:x}", err.0)));
            }
        }

        state
            .sw_bps
            .lock()
            .entry(pid)
            .or_default()
            .push((address, orig));
        Ok(SwBreakpoint { address, original_byte: orig })
    })
    .await
    .map_err(|e| AppError::Internal(format!("spawn_blocking: {e}")))??;
    Ok(bp)
}

#[tauri::command]
pub async fn dbg_sw_bp_clear(
    state: State<'_, Arc<DebuggerHandles>>,
    device: State<'_, DeviceState>,
    pid: u32,
    address: u64,
) -> AppResult<()> {
    let state = state.inner().clone();
    driver_unregister_sw_bp(&device, pid, address);
    tokio::task::spawn_blocking(move || -> AppResult<()> {
        let orig = {
            let mut g = state.sw_bps.lock();
            let vec = g.get_mut(&pid).ok_or_else(|| AppError::Internal("无此 pid 的软断点".into()))?;
            let idx = vec.iter().position(|(a, _)| *a == address)
                .ok_or_else(|| AppError::Internal("无此地址的软断点".into()))?;
            vec.swap_remove(idx).1
        };

        let h = get_or_open(&state, pid)?;
        unsafe {
            let mut old: PAGE_PROTECTION_FLAGS = std::mem::zeroed();
            let _ = VirtualProtectEx(h, address as *const c_void, 1, PAGE_EXECUTE_READWRITE, &mut old);
            let mut wrote = 0;
            let ok = WriteProcessMemory(
                h,
                address as *const c_void,
                &orig as *const u8 as *const c_void,
                1,
                Some(&mut wrote),
            )
            .is_ok();
            let mut _x: PAGE_PROTECTION_FLAGS = std::mem::zeroed();
            let _ = VirtualProtectEx(h, address as *const c_void, 1, old, &mut _x);
            if !ok || wrote != 1 {
                return Err(AppError::Internal("还原原字节失败".into()));
            }
        }
        Ok(())
    })
    .await
    .map_err(|e| AppError::Internal(format!("spawn_blocking: {e}")))?
}

#[tauri::command]
pub fn dbg_sw_bp_list(
    state: State<'_, Arc<DebuggerHandles>>,
    pid: u32,
) -> AppResult<Vec<SwBreakpoint>> {
    let g = state.sw_bps.lock();
    Ok(g.get(&pid)
        .map(|v| v.iter().map(|(a, b)| SwBreakpoint { address: *a, original_byte: *b }).collect())
        .unwrap_or_default())
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

        // ---- Phase 2: rayon 并行 region 扫描 ----
        use rayon::prelude::*;
        let raw_h = h.0 as usize;   // HANDLE 不 Send, 用 raw 跨线程
        let wanted_ref = wanted.as_slice();
        let vt = req.value_type;
        let op = req.op;
        let aligned = req.aligned && matches!(vt,
            ValueType::I16 | ValueType::U16
            | ValueType::I32 | ValueType::U32 | ValueType::F32
            | ValueType::I64 | ValueType::U64 | ValueType::F64);
        let scanned_w = scanned_bytes.clone();
        let hits_w = hits_count.clone();

        let mut hits: Vec<(u64, HitBytes)> = regions.par_iter().map(|(s, e)| {
            if SCAN_CANCEL.load(Ordering::Relaxed) { return Vec::new(); }
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
                ).is_ok()
            };
            if !ok || got == 0 {
                scanned_w.fetch_add(len as u64, Ordering::Relaxed);
                return Vec::new();
            }
            let buf = &buf[..got];
            let local_hits = scan_region(buf, *s as u64, wsize, aligned, op, vt, wanted_ref);
            hits_w.fetch_add(local_hits.len(), Ordering::Relaxed);
            scanned_w.fetch_add(len as u64, Ordering::Relaxed);
            local_hits
        }).reduce(Vec::new, |mut a, mut b| {
            if a.len() + b.len() > 5_000_000 {
                // 超上限就丢弃尾部
                let remain = 5_000_000usize.saturating_sub(a.len());
                b.truncate(remain);
            }
            a.append(&mut b);
            a
        });

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
