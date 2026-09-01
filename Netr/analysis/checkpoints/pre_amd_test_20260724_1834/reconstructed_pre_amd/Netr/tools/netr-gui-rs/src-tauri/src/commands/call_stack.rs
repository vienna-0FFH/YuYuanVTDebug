//! 调用栈追踪 (P94)
//!
//! 简版: GetThreadContext (前端已暴露 dbg_get_thread_context) + 读 RSP 4KB 栈
//! 顺序扫每 8 字节, 若落在某模块 .text 范围内, 视为 return address.
//! 准确度 ~70%, 跟 CE 一样. 反汇编可证伪后续可加 unwind info.

use std::ffi::c_void;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;

use crate::commands::pe_util::{enum_modules, locate_text, open_for_read};
use crate::util::error::{AppError, AppResult};

#[derive(Debug, Serialize)]
pub struct CallFrame {
    pub rip: u64,
    pub rsp: u64,
    pub module: Option<String>,
    pub module_offset: Option<u64>,
    pub symbol: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CallStackReq {
    pub pid: u32,
    pub tid: u32,
    pub max_frames: Option<u32>,
    pub stack_scan_bytes: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct CallStackResp {
    pub tid: u32,
    pub frames: Vec<CallFrame>,
    pub stack_bytes_scanned: u32,
    pub note: &'static str,
}

#[tauri::command]
pub async fn dbg_call_stack(
    _handles: tauri::State<'_, Arc<crate::commands::debugger_ui::DebuggerHandles>>,
    req: CallStackReq,
) -> AppResult<CallStackResp> {
    let pid = req.pid;
    let tid = req.tid;
    let max_frames = req.max_frames.unwrap_or(32).clamp(1, 256) as usize;
    let scan_bytes = req.stack_scan_bytes.unwrap_or(4096).clamp(256, 65536) as usize;

    // 取 thread context (复用 dbg_get_thread_context 内部)
    let ctx = crate::commands::debugger_ui::dbg_get_thread_context(tid).await
        .map_err(|e| AppError::Internal(format!("get_thread_context: {e}")))?;
    let rip = ctx.rip;
    let rsp = ctx.rsp;

    tokio::task::spawn_blocking(move || -> AppResult<CallStackResp> {
        unsafe {
            let h = open_for_read(pid)?;
            let mods_raw = enum_modules(pid);
            let mut mods: Vec<(String, u64, u64)> = Vec::with_capacity(mods_raw.len());
            for m in mods_raw {
                let (tb, ts) = locate_text(h, m.base, m.size);
                mods.push((m.name, tb, ts));
            }
            let in_text = |a: u64| -> Option<(String, u64)> {
                for (name, base, size) in &mods {
                    if a >= *base && a < base + size {
                        return Some((name.clone(), a - base));
                    }
                }
                None
            };

            let mut frames = Vec::new();
            // 第 0 帧: 当前 RIP
            let (m0, off0) = match in_text(rip) {
                Some((n, o)) => (Some(n), Some(o)),
                None => (None, None),
            };
            frames.push(CallFrame { rip, rsp, module: m0, module_offset: off0, symbol: None });

            // 读栈
            let mut buf = vec![0u8; scan_bytes];
            let mut got = 0usize;
            let _ = ReadProcessMemory(h, rsp as *const c_void, buf.as_mut_ptr() as *mut c_void, scan_bytes, Some(&mut got));
            buf.truncate(got);
            let mut off = 0;
            while off + 8 <= buf.len() && frames.len() < max_frames {
                let v = u64::from_le_bytes(buf[off..off+8].try_into().unwrap());
                if let Some((name, foff)) = in_text(v) {
                    frames.push(CallFrame {
                        rip: v,
                        rsp: rsp + off as u64,
                        module: Some(name),
                        module_offset: Some(foff),
                        symbol: None,
                    });
                }
                off += 8;
            }
            let _ = windows::Win32::Foundation::CloseHandle(h);
            Ok(CallStackResp {
                tid,
                frames,
                stack_bytes_scanned: got as u32,
                note: "简版 stack scan (无 unwind info), 同 CE 风格. RIP 之外的项是猜测.",
            })
        }
    })
    .await
    .map_err(|e| AppError::Internal(format!("spawn_blocking: {e}")))?
}
