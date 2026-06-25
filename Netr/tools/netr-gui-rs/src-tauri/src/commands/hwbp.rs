//! P118: 简化 HWBP — 关掉 hypervisor 透明 DR 装载, 改成 GUI 直接 SetThreadContext
//!
//! 流程:
//!   1) IOCTL_HV_DBG_SET_HWBP — 告诉 driver "这个 (pid, slot) 关心 addr",
//!      driver 里只用于 #DB vmexit 时反查命中的 slot, 不再装载真硬件 DR
//!   2) 本地 slot 表维护当前每个 pid 的 4 个 slot 状态 + 计算 DR7
//!   3) 枚举目标进程所有 tid, SuspendThread + GetThreadContext +
//!      把 Dr0..3 + Dr7 写进 CONTEXT + SetThreadContext + ResumeThread
//!   4) Windows 调度器在线程上下文切换时自然 load DR0..3+DR7, 触发 #DB
//!   5) #DB 被 driver vmexit 拦截, 投递事件到 GUI ring
//!
//! 限制: hwbp_set 之后新建的线程不带 DR. 跟 CE 一样的限制. 用户可重新 hwbp_set
//!       触发一次全 tid 同步.

use std::collections::HashMap;
use std::ffi::c_void;
use std::sync::Mutex;

use tauri::State;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
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

// ============================================================
// GUI 本地 slot 表 — 用于算 DR7 + SetThreadContext 时写全 4 个 DR
// ============================================================

#[derive(Debug, Clone, Copy)]
struct Slot {
    address: u64,
    length: u8,    // 1/2/4/8
    bp_type: u8,   // 0=exec, 1=write, 3=rw
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

/// 根据 4 个槽位状态拼 DR7 — 同 driver HvDbgpComputeDr7
fn compute_dr7(slots: &[Option<Slot>; 4]) -> u64 {
    // bit10 保留位必须 1, 其余 enable / type / len 按 slot 拼
    let mut dr7: u64 = 1 << 10;
    for i in 0..4 {
        if let Some(s) = slots[i] {
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
        slots[0].map(|s| s.address).unwrap_or(0),
        slots[1].map(|s| s.address).unwrap_or(0),
        slots[2].map(|s| s.address).unwrap_or(0),
        slots[3].map(|s| s.address).unwrap_or(0),
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
    debugger_pid: u32,
    target_pid: u32,
    slot: u32,
    address: u64,
    length: u32,
    bp_type: u8,
) -> AppResult<()> {
    if slot >= 4 {
        return Err(AppError::Internal(format!("slot {slot} 超出 0..3")));
    }
    let len_u8 = length as u8;
    if !matches!(len_u8, 1 | 2 | 4 | 8) {
        return Err(AppError::Internal(format!("length 必须 1/2/4/8, 收到 {length}")));
    }
    if !matches!(bp_type, 0 | 1 | 3) {
        return Err(AppError::Internal(format!("bp_type 必须 0=exec / 1=write / 3=rw, 收到 {bp_type}")));
    }

    // 1) 告 driver (供 #DB 命中时反查)
    let req = HwbpReq {
        debugger_pid,
        target_pid,
        slot_index: slot,
        reserved0: 0,
        address,
        length: len_u8,
        bp_type,
        reserved1: [0; 6],
    };
    let buf = unsafe {
        std::slice::from_raw_parts(
            (&req as *const HwbpReq) as *const u8,
            std::mem::size_of::<HwbpReq>(),
        )
    };
    let mut out = [0u8; 32];
    device.ioctl(IOCTL_HV_DBG_SET_HWBP, buf, &mut out)?;

    // 2) 更新本地 slot 表 + 同步到所有线程
    let slots_snapshot = {
        let mut g = store().by_pid.lock().unwrap();
        let entry = g.entry(target_pid).or_insert([None; 4]);
        entry[slot as usize] = Some(Slot { address, length: len_u8, bp_type });
        *entry
    };
    let ok = sync_to_all_threads(target_pid, &slots_snapshot);
    if ok == 0 {
        // 没装上任何线程 — 给警告但不算失败 (有时进程刚 attach, 线程列表暂时拿不到)
        return Err(AppError::Internal(format!(
            "DR 写入 0 个线程 (target pid={target_pid}). 检查进程是否存在 + 权限"
        )));
    }
    Ok(())
}

#[tauri::command]
pub fn hwbp_clear(
    device: State<'_, DeviceState>,
    target_pid: u32,
    slot: u32,
) -> AppResult<()> {
    if slot >= 4 {
        return Err(AppError::Internal(format!("slot {slot} 超出 0..3")));
    }

    // 1) driver 清
    let req = HwbpReq {
        debugger_pid: 0,
        target_pid,
        slot_index: slot,
        reserved0: 0,
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
    let mut out = [0u8; 32];
    device.ioctl(IOCTL_HV_DBG_CLEAR_HWBP, buf, &mut out)?;

    // 2) 本地表清掉这个槽位, 同步到所有线程 (DR 那一位会被 compute_dr7 关掉)
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
    let _ = sync_to_all_threads(target_pid, &slots_snapshot);
    Ok(())
}
