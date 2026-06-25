//! 1Hz 后台轮询 dbgevt ring,通过 Tauri event 推给前端。
//!
//! 事件结构与 driver HV_DBGEVT 严格对齐(96 字节 Detail)。

use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager};

use crate::ioctl::codes::IOCTL_HV_GET_DBGEVT;
use crate::ioctl::DeviceState;

// P122: 跟 driver HV_DBGEVT_DETAIL_MAX 严格对齐 (96 → 192)
const DETAIL_MAX: usize = 192;
// P122: ring 4096, driver 短期可能爆发, 5Hz × 512 = 2560/秒 覆盖
const PULL_MAX: u32 = 512;

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
struct DbgEvt {
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
    detail: [u8; DETAIL_MAX],
}

#[derive(Debug, Clone, Serialize)]
pub struct DbgEvtView {
    pub sequence: u64,
    pub severity: u32,
    pub category: u32,
    pub status: i32,
    pub caller_pid: u32,
    pub target_pid: u32,
    pub addr: u64,
    pub size: u64,
    pub detail: String,
}

/// 启动后台任务。每秒 IOCTL 一次,只在 device 已打开时调,emit "dbgevt" 事件。
/// 使用 tauri::async_runtime,因 setup 阶段没有 #[tokio::main] runtime。
pub fn spawn(app: AppHandle) {
    let last_seq = Arc::new(Mutex::new(0u64));

    tauri::async_runtime::spawn(async move {
        // P122: 5Hz 拉,配 driver ring 4096
        let mut interval = tokio::time::interval(Duration::from_millis(200));
        loop {
            interval.tick().await;

            let device = match app.try_state::<DeviceState>() {
                Some(d) => d,
                None => continue,
            };
            if !device.is_open() {
                continue;
            }

            let since = *last_seq.lock();
            let req = PullReq {
                since_seq: since,
                max_count: PULL_MAX,
                _pad: 0,
            };
            let in_buf = unsafe {
                std::slice::from_raw_parts(
                    (&req as *const PullReq) as *const u8,
                    std::mem::size_of::<PullReq>(),
                )
            };
            let mut out =
                vec![0u8; std::mem::size_of::<PullResHdr>() + PULL_MAX as usize * std::mem::size_of::<DbgEvt>()];

            let written = match device.ioctl(IOCTL_HV_GET_DBGEVT, in_buf, &mut out) {
                Ok(n) => n,
                Err(_) => continue, // driver 可能在卸载,跳过
            };
            if (written as usize) < std::mem::size_of::<PullResHdr>() {
                continue;
            }

            let hdr: PullResHdr = unsafe { *(out.as_ptr() as *const PullResHdr) };
            let count = { let c = hdr.count; c };
            let next_seq = { let n = hdr.next_seq; n };
            *last_seq.lock() = next_seq;

            if count == 0 {
                continue;
            }

            let mut events: Vec<DbgEvtView> = Vec::with_capacity(count as usize);
            let items_offset = std::mem::size_of::<PullResHdr>();
            for i in 0..(count as usize) {
                let p = unsafe {
                    out.as_ptr()
                        .add(items_offset + i * std::mem::size_of::<DbgEvt>())
                        as *const DbgEvt
                };
                let e: DbgEvt = unsafe { *p };
                let detail = parse_cstring(&e.detail);
                events.push(DbgEvtView {
                    sequence: { let s = e.sequence; s },
                    severity: { let s = e.severity; s },
                    category: { let c = e.category; c },
                    status: { let s = e.status; s },
                    caller_pid: { let v = e.caller_pid; v },
                    target_pid: { let v = e.target_pid; v },
                    addr: { let v = e.addr; v },
                    size: { let v = e.size; v },
                    detail,
                });
            }

            let _ = app.emit("dbgevt", events);
        }
    });
}

fn parse_cstring(buf: &[u8]) -> String {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).into_owned()
}
