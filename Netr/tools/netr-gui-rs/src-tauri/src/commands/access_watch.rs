//! P112: AI 用的 "找出谁访问/改写此地址" 工具.
//!
//! 流程 (同步):
//!   1. 拉一次 dbgevt 拿到当前 baseline seq
//!   2. 装 HWBP (slot 0, WRITE 或 RW, length 1/2/4/8) 到 driver
//!   3. sleep duration_ms (默认 3000), 期间 dbgevt ring 里会累积命中
//!   4. 清 HWBP
//!   5. 再拉 dbgevt, 取 baseline 后的 category=HWBP_HIT(7) + target_pid 匹配
//!   6. 按 RIP 聚合, 返排序的访问者列表
//!
//! AI 调用范式:
//!   先 attach 进程 + 让用户在游戏里改那个值 → 调 find_who_accesses
//!   → 拿 top RIP → resolve_symbol / disasm 查看代码

use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::commands::debugger_ui::DebuggerHandles;
use crate::ioctl::codes::{IOCTL_HV_DBG_SET_HWBP, IOCTL_HV_DBG_CLEAR_HWBP, IOCTL_HV_GET_DBGEVT};
use crate::ioctl::DeviceState;
use crate::util::error::{AppError, AppResult};

#[repr(C, packed)]
struct HwbpReq {
    debugger_pid: u32,
    target_pid: u32,
    slot_index: u32,
    address: u64,
    length: u32,
    bp_type: u8,
    _pad: [u8; 3],
}

#[repr(C, packed)]
struct PullReq {
    since_seq: u64,
    max_count: u32,
    _pad: u32,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct PullResHdr {
    count: u32,
    _pad: u32,
    next_seq: u64,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct DbgEvtRaw {
    sequence: u64,
    timestamp_qpc: u64,
    severity: u32,
    category: u32,
    status: i32,
    caller_pid: u32,
    target_pid: u32,
    _pad: u32,
    addr: u64,
    size: u64,
    detail: [u8; 96],
}

const CAT_HWBP_HIT: u32 = 7;
const PULL_MAX: u32 = 64;

#[derive(Debug, Deserialize)]
pub struct FindWhoAccessesReq {
    pub pid: u32,
    pub address: u64,
    /// "write" / "rw"
    pub mode: String,
    /// 1 / 2 / 4 / 8, 默认 4
    pub length: Option<u32>,
    /// 收集时间窗 ms, 默认 3000, 上限 30000
    pub duration_ms: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct AccessEntry {
    pub rip: u64,
    pub count: u32,
}

#[derive(Debug, Serialize)]
pub struct FindWhoAccessesResult {
    pub address: u64,
    pub mode: String,
    pub duration_ms: u32,
    pub hits_total: u32,
    /// 按 count 倒序, 最多 32
    pub by_rip: Vec<AccessEntry>,
    pub note: String,
}

fn pull_dbgevt(device: &DeviceState, since: u64) -> Result<(u64, Vec<DbgEvtRaw>), String> {
    let req = PullReq { since_seq: since, max_count: PULL_MAX, _pad: 0 };
    let in_buf = unsafe {
        std::slice::from_raw_parts(
            (&req as *const PullReq) as *const u8,
            std::mem::size_of::<PullReq>(),
        )
    };
    let mut out = vec![0u8; std::mem::size_of::<PullResHdr>() + PULL_MAX as usize * std::mem::size_of::<DbgEvtRaw>()];
    let written = device.ioctl(IOCTL_HV_GET_DBGEVT, in_buf, &mut out)
        .map_err(|e| format!("pull dbgevt: {e:?}"))?;
    if (written as usize) < std::mem::size_of::<PullResHdr>() {
        return Ok((since, vec![]));
    }
    let hdr: PullResHdr = unsafe { *(out.as_ptr() as *const PullResHdr) };
    let count = { let c = hdr.count; c };
    let next_seq = { let n = hdr.next_seq; n };
    let mut evts = Vec::with_capacity(count as usize);
    let items_off = std::mem::size_of::<PullResHdr>();
    for i in 0..(count as usize) {
        let p = unsafe {
            out.as_ptr().add(items_off + i * std::mem::size_of::<DbgEvtRaw>()) as *const DbgEvtRaw
        };
        evts.push(unsafe { *p });
    }
    Ok((next_seq, evts))
}

#[tauri::command]
pub async fn dbg_find_who_accesses(
    device: tauri::State<'_, DeviceState>,
    _handles: tauri::State<'_, Arc<DebuggerHandles>>,
    req: FindWhoAccessesReq,
) -> AppResult<FindWhoAccessesResult> {
    let pid = req.pid;
    let target_addr = req.address;
    let mode = req.mode.to_lowercase();
    let bp_type: u8 = match mode.as_str() {
        "write" => 1,
        "rw" => 3,
        other => return Err(AppError::Internal(format!(
            "mode 必须是 'write' 或 'rw' (拿到 '{other}')"
        ))),
    };
    let length = req.length.unwrap_or(4);
    if !matches!(length, 1 | 2 | 4 | 8) {
        return Err(AppError::Internal(format!("length 必须是 1/2/4/8 (拿到 {length})")));
    }
    let duration_ms = req.duration_ms.unwrap_or(3000).min(30_000);

    // 把 device 取出来 (它本身 Clone 廉价 — 内部 Arc)
    let device_cloned = device.inner().clone();
    drop(device);

    // 1) 拉光当前 ring, 拿 baseline next_seq
    let (baseline_seq, _) = pull_dbgevt(&device_cloned, 0)
        .map_err(AppError::Internal)?;

    // 2) 装 HWBP. debugger_pid 我们用 0 (driver 接受, 它从 device file handle 关联的 PID 拿)
    // driver IOCTL 期望 debugger_pid != 0; 用当前进程 PID
    let me = std::process::id();
    let hwbp_req = HwbpReq {
        debugger_pid: me,
        target_pid: pid,
        slot_index: 0,
        address: target_addr,
        length,
        bp_type,
        _pad: [0; 3],
    };
    let hwbp_buf = unsafe {
        std::slice::from_raw_parts(
            (&hwbp_req as *const HwbpReq) as *const u8,
            std::mem::size_of::<HwbpReq>(),
        )
    };
    let mut out = [0u8; 32];
    device_cloned.ioctl(IOCTL_HV_DBG_SET_HWBP, hwbp_buf, &mut out)
        .map_err(|e| AppError::Internal(format!("装 HWBP: {e:?}")))?;

    // 3) 收集时间窗内的 hit. 每 100ms 拉一次, 防 ring 满 (64 entry)
    let mut all_hits: Vec<DbgEvtRaw> = Vec::new();
    let mut seq = baseline_seq;
    let mut elapsed = 0u32;
    while elapsed < duration_ms {
        tokio::time::sleep(Duration::from_millis(100)).await;
        elapsed += 100;
        match pull_dbgevt(&device_cloned, seq) {
            Ok((next, evts)) => {
                seq = next;
                for e in evts {
                    let cat = { let c = e.category; c };
                    let tgt = { let t = e.target_pid; t };
                    if cat == CAT_HWBP_HIT && tgt == pid {
                        all_hits.push(e);
                    }
                }
            }
            Err(_) => break,
        }
    }

    // 4) 清 HWBP
    let clear_req = HwbpReq {
        debugger_pid: me,
        target_pid: pid,
        slot_index: 0,
        address: 0,
        length: 0,
        bp_type: 0,
        _pad: [0; 3],
    };
    let clear_buf = unsafe {
        std::slice::from_raw_parts(
            (&clear_req as *const HwbpReq) as *const u8,
            std::mem::size_of::<HwbpReq>(),
        )
    };
    let _ = device_cloned.ioctl(IOCTL_HV_DBG_CLEAR_HWBP, clear_buf, &mut out);

    // 5) 聚合 by RIP
    let mut agg: std::collections::HashMap<u64, u32> = std::collections::HashMap::new();
    for e in &all_hits {
        let rip = { let r = e.addr; r };
        *agg.entry(rip).or_insert(0) += 1;
    }
    let mut sorted: Vec<AccessEntry> = agg.into_iter()
        .map(|(rip, count)| AccessEntry { rip, count })
        .collect();
    sorted.sort_by_key(|e| std::cmp::Reverse(e.count));
    sorted.truncate(32);

    let total = all_hits.len() as u32;
    let note = if total == 0 {
        "0 命中 — 这段时间内此地址没被访问. 让目标值在游戏里发生变化再重试 (durartion_ms 加长 / 检查 address 对不对).".into()
    } else if sorted.len() == 1 {
        format!("只有 1 个 RIP, 命中 {} 次. 极大概率就是它.", total)
    } else {
        format!("{} 个不同 RIP, 共命中 {} 次. count 最多的是主要写入点.", sorted.len(), total)
    };

    Ok(FindWhoAccessesResult {
        address: target_addr,
        mode,
        duration_ms,
        hits_total: total,
        by_rip: sorted,
        note,
    })
}
