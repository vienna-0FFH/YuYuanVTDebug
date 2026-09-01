//! 内置调试器 HWBP：VT 使用 EPT watchpoint，Native 使用 DR0..DR3。
//!
//! 流程:
//!   1) SET_HWBP 只请求 HV_BRIDGE_HWBP_ALLOW_VT。
//!   2) 严格校验 driver 返回的 16-byte HV_DBG_RESULT 和实际选择的 mode。
//!   3) VT mode 完全由 driver/Vwatch 管理，不改目标线程 DR0..3/DR7。
//!   4) Native 模式由 Windows debug-event loop 管理真实 DR 和 #DB。
//!   5) clear 使用创建时记录的 mode，并保留旧 DR 记录的清零能力用于升级清理。

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tauri::State;
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Diagnostics::Debug::{
    GetThreadContext, SetThreadContext, CONTEXT, CONTEXT_DEBUG_REGISTERS_AMD64,
};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
};
use windows::Win32::System::Threading::{
    OpenThread, ResumeThread, SuspendThread,
    THREAD_GET_CONTEXT, THREAD_SET_CONTEXT, THREAD_SUSPEND_RESUME,
};

use crate::ioctl::codes::*;
use crate::ioctl::DeviceState;
use crate::util::error::{AppError, AppResult};
use crate::commands::debugger_ui::{
    builtin_target_mode, BuiltinDebugMode, DebuggerHandles,
};
use crate::commands::native_debug::{self, NativeHardwareBreakpoint};

// ============================================================
// driver IOCTL 包结构
// ============================================================

// 与 Driver.c HV_HWBP_REQUEST 对应 (32 字节, repr(C) 自然对齐, address @+0x10)
#[repr(C)]
struct HwbpReq {
    debugger_pid: u32,
    target_pid: u32,
    slot_index: u32,
    reserved0: u32,
    address: u64,
    length: u8,
    bp_type: u8,
    reserved1: [u8; 6],
}

const HV_BRIDGE_HWBP_ALLOW_VT: u32 = 0x0000_0001;
const HV_BRIDGE_HWBP_MODE_VT: u64 = 1;
const HV_BRIDGE_HWBP_MODE_DR: u64 = 2;
const HV_STATUS_SUCCESS: u32 = 0;
const HV_DBG_RESULT_SIZE: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HwbpMode {
    Vt,
    Dr,
}

impl HwbpMode {
    fn from_driver(value: u64, operation: &str) -> AppResult<Self> {
        match value {
            HV_BRIDGE_HWBP_MODE_VT => Ok(Self::Vt),
            HV_BRIDGE_HWBP_MODE_DR => Ok(Self::Dr),
            _ => Err(AppError::Internal(format!(
                "{operation}: driver returned invalid HWBP mode {value}"
            ))),
        }
    }

    fn policy(self) -> u32 {
        match self {
            Self::Vt => HV_BRIDGE_HWBP_ALLOW_VT,
            // 仅用于清理由旧版本留下的 DR 记录。当前 set 永不创建 DR。
            Self::Dr => 0x0000_0002,
        }
    }

    fn driver_value(self) -> u64 {
        match self {
            Self::Vt => HV_BRIDGE_HWBP_MODE_VT,
            Self::Dr => HV_BRIDGE_HWBP_MODE_DR,
        }
    }
}

fn parse_hwbp_result(
    operation: &str,
    written: u32,
    out: &[u8; HV_DBG_RESULT_SIZE],
) -> AppResult<HwbpMode> {
    if written as usize != HV_DBG_RESULT_SIZE {
        return Err(AppError::Internal(format!(
            "{operation}: driver returned {written} bytes, expected {HV_DBG_RESULT_SIZE}"
        )));
    }

    let status = u32::from_le_bytes(out[0..4].try_into().unwrap());
    let reserved = u32::from_le_bytes(out[4..8].try_into().unwrap());
    let mode_value = u64::from_le_bytes(out[8..16].try_into().unwrap());
    if reserved != 0 {
        return Err(AppError::Internal(format!(
            "{operation}: driver returned non-zero reserved field 0x{reserved:08X}"
        )));
    }
    if status != HV_STATUS_SUCCESS {
        return Err(AppError::Internal(format!(
            "{operation}: driver status={status}, mode={mode_value}"
        )));
    }
    HwbpMode::from_driver(mode_value, operation)
}

fn driver_set_hwbp(
    device: &DeviceState,
    debugger_pid: u32,
    target_pid: u32,
    slot: u32,
    address: u64,
    length: u8,
    bp_type: u8,
) -> AppResult<HwbpMode> {
    let req = HwbpReq {
        debugger_pid,
        target_pid,
        slot_index: slot,
        reserved0: HV_BRIDGE_HWBP_ALLOW_VT,
        address,
        length,
        bp_type,
        reserved1: [0; 6],
    };
    let buf = unsafe {
        std::slice::from_raw_parts(
            (&req as *const HwbpReq) as *const u8,
            std::mem::size_of::<HwbpReq>(),
        )
    };
    let mut out = [0u8; HV_DBG_RESULT_SIZE];
    let written = device.ioctl(IOCTL_HV_DBG_SET_HWBP, buf, &mut out)?;
    let mode = parse_hwbp_result("SET_HWBP", written, &out)?;
    if mode != HwbpMode::Vt {
        return Err(AppError::Internal(format!(
            "SET_HWBP selected unsafe mode {}; built-in debugger requires VT",
            mode.driver_value()
        )));
    }
    Ok(mode)
}

fn driver_clear_hwbp(
    device: &DeviceState,
    target_pid: u32,
    slot: u32,
    expected_mode: HwbpMode,
) -> AppResult<()> {
    let req = HwbpReq {
        debugger_pid: std::process::id(),
        target_pid,
        slot_index: slot,
        reserved0: expected_mode.policy(),
        address: 0,
        length: 0,
        bp_type: 0,
        reserved1: [0; 6],
    };
    let buf = unsafe {
        std::slice::from_raw_parts(
            (&req as *const HwbpReq) as *const u8,
            std::mem::size_of::<HwbpReq>(),
        )
    };
    let mut out = [0u8; HV_DBG_RESULT_SIZE];
    let written = device.ioctl(IOCTL_HV_DBG_CLEAR_HWBP, buf, &mut out)?;
    let cleared_mode = parse_hwbp_result("CLEAR_HWBP", written, &out)?;
    if cleared_mode != expected_mode {
        return Err(AppError::Internal(format!(
            "CLEAR_HWBP: driver cleared mode {}, expected {}",
            cleared_mode.driver_value(),
            expected_mode.driver_value()
        )));
    }
    Ok(())
}

// ============================================================
// GUI 本地 slot 表 — 用于算 DR7 + SetThreadContext 时写全 4 个 DR
// ============================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Slot {
    address: u64,
    length: u8,    // 1/2/4/8
    bp_type: u8,   // 0=exec, 1=write, 3=rw
    mode: HwbpMode,
    driver_owned: bool,
}

#[derive(Default)]
struct HwbpStore {
    // pid -> 4 slot (Some = 启用)
    by_pid: Mutex<HashMap<u32, [Option<Slot>; 4]>>,
}

// 进程级单例 — Tauri State 不方便整 lazy, 直接 OnceLock
fn store() -> &'static HwbpStore {
    static S: std::sync::OnceLock<HwbpStore> = std::sync::OnceLock::new();
    S.get_or_init(HwbpStore::default)
}

pub(crate) fn vt_hardware_mask(pid: u32) -> u64 {
    store()
        .by_pid
        .lock()
        .unwrap()
        .get(&pid)
        .map(|slots| {
            slots
                .iter()
                .enumerate()
                .fold(0u64, |mask, (slot, breakpoint)| {
                    if breakpoint.is_some_and(|entry| entry.mode == HwbpMode::Vt) {
                        mask | (1u64 << slot)
                    } else {
                        mask
                    }
                })
        })
        .unwrap_or(0)
}

/// 根据 4 个槽位状态拼 DR7 — 同 driver HvDbgpComputeDr7
fn compute_dr7(slots: &[Option<Slot>; 4]) -> u64 {
    // bit10 保留位必须 1, 其余 enable / type / len 按 slot 拼
    let mut dr7: u64 = 1 << 10;
    for i in 0..4 {
        if let Some(s) = slots[i].filter(|s| s.mode == HwbpMode::Dr) {
            // L_i (local enable)
            dr7 |= 1u64 << (i * 2);
            // R/W field at bit 16+i*4..18+i*4 (2 bits)
            dr7 |= ((s.bp_type & 3) as u64) << (16 + i * 4);
            // LEN field at bit 18+i*4..20+i*4 — 00=1 / 01=2 / 10=8 / 11=4
            let len_bits: u64 = match s.length {
                1 => 0,
                2 => 1,
                8 => 2,
                4 => 3,
                _ => 0,
            };
            dr7 |= len_bits << (18 + i * 4);
        }
    }
    dr7
}

/// 枚举一个进程的所有线程 ID
fn enum_threads_of_pid(pid: u32) -> Vec<u32> {
    let mut out = Vec::new();
    unsafe {
        let snap = match CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) {
            Ok(h) => h,
            Err(_) => return out,
        };
        let mut te: THREADENTRY32 = std::mem::zeroed();
        te.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
        if Thread32First(snap, &mut te).is_ok() {
            loop {
                if te.th32OwnerProcessID == pid {
                    out.push(te.th32ThreadID);
                }
                if Thread32Next(snap, &mut te).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snap);
    }
    out
}

/// 给一个线程下发 DR0..3 + DR7. 失败的线程跳过, 返回成功计数.
fn apply_dr_to_thread(tid: u32, dr: [u64; 4], dr7: u64) -> bool {
    unsafe {
        let h = match OpenThread(
            THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME,
            false,
            tid,
        ) {
            Ok(h) if h.0 as usize != 0 => h,
            _ => return false,
        };

        // 必须 Suspend 才能改 DR. 已 suspend 的线程也支持. 失败 (-1) 时仍尝试.
        let prev = SuspendThread(h);

        let mut ctx: CONTEXT = std::mem::zeroed();
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS_AMD64;
        let got = GetThreadContext(h, &mut ctx).is_ok();
        let mut ok = false;
        if got {
            ctx.Dr0 = dr[0];
            ctx.Dr1 = dr[1];
            ctx.Dr2 = dr[2];
            ctx.Dr3 = dr[3];
            ctx.Dr7 = dr7;
            // Dr6 不动 — guest 触发后由 #DB handler 上报
            ok = SetThreadContext(h, &ctx).is_ok();
        }

        if prev != u32::MAX {
            ResumeThread(h);
        }
        let _ = CloseHandle(h);
        ok
    }
}

/// 把 pid 的当前 slots 同步到所有线程
fn sync_to_all_threads(pid: u32, slots: &[Option<Slot>; 4]) -> usize {
    let dr = [
        slots[0]
            .filter(|s| s.mode == HwbpMode::Dr)
            .map(|s| s.address)
            .unwrap_or(0),
        slots[1]
            .filter(|s| s.mode == HwbpMode::Dr)
            .map(|s| s.address)
            .unwrap_or(0),
        slots[2]
            .filter(|s| s.mode == HwbpMode::Dr)
            .map(|s| s.address)
            .unwrap_or(0),
        slots[3]
            .filter(|s| s.mode == HwbpMode::Dr)
            .map(|s| s.address)
            .unwrap_or(0),
    ];
    let dr7 = compute_dr7(slots);
    let tids = enum_threads_of_pid(pid);
    let mut ok_count = 0;
    for tid in tids {
        if apply_dr_to_thread(tid, dr, dr7) {
            ok_count += 1;
        }
    }
    ok_count
}

// ============================================================
// Tauri commands
// ============================================================

#[tauri::command]
pub fn hwbp_set(
    device: State<'_, DeviceState>,
    handles: State<'_, Arc<DebuggerHandles>>,
    debugger_pid: u32,
    target_pid: u32,
    slot: u32,
    address: u64,
    length: u32,
    bp_type: u8,
) -> AppResult<()> {
    let target_mode = builtin_target_mode(handles.inner(), target_pid)
        .ok_or_else(|| AppError::Internal(format!(
            "target PID {target_pid} is not attached to the built-in debugger"
        )))?;

    if slot >= 4 {
        return Err(AppError::Internal(format!("slot {slot} 超出 0..3")));
    }
    let len_u8 = u8::try_from(length).map_err(|_| {
        AppError::Internal(format!("length 必须 1/2/4/8, 收到 {length}"))
    })?;
    if !matches!(len_u8, 1 | 2 | 4 | 8) {
        return Err(AppError::Internal(format!(
            "length 必须 1/2/4/8, 收到 {length}"
        )));
    }
    if !matches!(bp_type, 0 | 1 | 3) {
        return Err(AppError::Internal(format!(
            "bp_type 必须 0=exec / 1=write / 3=rw, 收到 {bp_type}"
        )));
    }
    if target_mode == BuiltinDebugMode::Native {
        return native_debug::set_hardware_breakpoint(
            target_pid,
            slot,
            address,
            len_u8,
            bp_type,
        );
    }

    // Built-in VT mode never permits the driver's real-DR fallback.
    let selected_mode = driver_set_hwbp(
        device.inner(),
        debugger_pid,
        target_pid,
        slot,
        address,
        len_u8,
        bp_type,
    )?;

    {
        let mut g = store().by_pid.lock().unwrap();
        let entry = g.entry(target_pid).or_insert([None; 4]);
        entry[slot as usize] = Some(Slot {
            address,
            length: len_u8,
            bp_type,
            mode: selected_mode,
            driver_owned: true,
        });
    }

    debug_assert_eq!(selected_mode, HwbpMode::Vt);
    Ok(())
}

#[tauri::command]
pub fn hwbp_clear(
    device: State<'_, DeviceState>,
    handles: State<'_, Arc<DebuggerHandles>>,
    target_pid: u32,
    slot: u32,
) -> AppResult<()> {
    if slot >= 4 {
        return Err(AppError::Internal(format!("slot {slot} 超出 0..3")));
    }
    let target_mode = builtin_target_mode(handles.inner(), target_pid)
        .ok_or_else(|| AppError::Internal(format!(
            "target PID {target_pid} is not attached to the built-in debugger"
        )))?;
    if target_mode == BuiltinDebugMode::Native {
        return native_debug::clear_hardware_breakpoint(target_pid, slot);
    }

    let recorded = {
        let g = store().by_pid.lock().unwrap();
        g.get(&target_pid)
            .and_then(|entry| entry[slot as usize])
            .ok_or_else(|| {
                AppError::Internal(format!(
                    "HWBP target={target_pid} slot={slot} has no local mode record"
                ))
            })?
    };
    if recorded.driver_owned {
        driver_clear_hwbp(device.inner(), target_pid, slot, recorded.mode)?;
    }

    let slots_snapshot = {
        let mut g = store().by_pid.lock().unwrap();
        if let Some(entry) = g.get_mut(&target_pid) {
            entry[slot as usize] = None;
            let snap = *entry;
            // 若所有槽位都空, 把这个 pid 从表里删掉
            if entry.iter().all(|s| s.is_none()) {
                g.remove(&target_pid);
            }
            snap
        } else {
            [None; 4]
        }
    };
    if recorded.mode == HwbpMode::Dr {
        let _ = sync_to_all_threads(target_pid, &slots_snapshot);
    }
    Ok(())
}

#[tauri::command]
pub fn hwbp_list(
    handles: State<'_, Arc<DebuggerHandles>>,
    target_pid: u32,
) -> AppResult<Vec<NativeHardwareBreakpoint>> {
    let target_mode = builtin_target_mode(handles.inner(), target_pid)
        .ok_or_else(|| AppError::Internal(format!(
            "target PID {target_pid} is not attached to the built-in debugger"
        )))?;
    if target_mode == BuiltinDebugMode::Native {
        return native_debug::list_hardware_breakpoints(target_pid);
    }

    let guard = store().by_pid.lock().unwrap();
    let slots = guard.get(&target_pid).copied().unwrap_or([None; 4]);
    Ok(slots
        .into_iter()
        .enumerate()
        .filter_map(|(slot, record)| {
            record.map(|record| NativeHardwareBreakpoint {
                slot: slot as u32,
                address: record.address,
                length: record.length,
                bp_type: record.bp_type,
            })
        })
        .collect())
}

/// 清理一个 target 的全部内置调试器 HWBP。
///
/// 每个 slot 使用创建时记录的 mode 发送精确 clear。VT slot 从不触碰线程 DR；
/// 旧版本残留的 DR slot 会从目标线程上下文中强制撤掉。clear 失败的记录保留，
/// 供尚未完成 authoritative UNBIND 的 detach 生命周期重试。
pub(crate) fn hwbp_clear_all_for_target(
    device: &DeviceState,
    target_pid: u32,
) -> AppResult<()> {
    let snapshot = {
        let g = store().by_pid.lock().unwrap();
        g.get(&target_pid).copied().unwrap_or([None; 4])
    };
    if snapshot.iter().all(Option::is_none) {
        return Ok(());
    }

    let had_dr = snapshot
        .iter()
        .flatten()
        .any(|recorded| recorded.mode == HwbpMode::Dr);
    let mut failures = Vec::new();
    let mut cleared = [false; 4];
    for (index, item) in snapshot.iter().enumerate() {
        let Some(recorded) = item else { continue };
        let result = if recorded.driver_owned {
            driver_clear_hwbp(device, target_pid, index as u32, recorded.mode)
        } else {
            Ok(())
        };
        match result {
            Ok(()) => cleared[index] = true,
            Err(error) => failures.push(format!("slot {index}: {error}")),
        }
    }

    let remaining = {
        let mut g = store().by_pid.lock().unwrap();
        let mut remove_target = false;
        let remaining = if let Some(current) = g.get_mut(&target_pid) {
            for index in 0..current.len() {
                // A concurrent replacement owns a new driver transaction and
                // must not be erased by completion of the snapshotted clear.
                if cleared[index] && current[index] == snapshot[index] {
                    current[index] = None;
                }
            }
            remove_target = current.iter().all(Option::is_none);
            *current
        } else {
            [None; 4]
        };
        if remove_target {
            g.remove(&target_pid);
        }
        remaining
    };

    if had_dr {
        // Cleanup 必须优先保证目标线程不再携带真实 DR。即使某个 driver clear
        // 失败并保留本地记录供上层重试，也不让该 DR fallback 继续武装线程。
        let mut dr_cleanup_snapshot = remaining;
        for item in &mut dr_cleanup_snapshot {
            if item.is_some_and(|recorded| recorded.mode == HwbpMode::Dr) {
                *item = None;
            }
        }
        let _ = sync_to_all_threads(target_pid, &dr_cleanup_snapshot);
    }

    if failures.is_empty() {
        Ok(())
    } else {
        Err(AppError::Internal(format!(
            "failed to clear all HWBP for target {target_pid}: {}",
            failures.join("; ")
        )))
    }
}

pub(crate) fn hwbp_forget_target(target_pid: u32) {
    store().by_pid.lock().unwrap().remove(&target_pid);
}
