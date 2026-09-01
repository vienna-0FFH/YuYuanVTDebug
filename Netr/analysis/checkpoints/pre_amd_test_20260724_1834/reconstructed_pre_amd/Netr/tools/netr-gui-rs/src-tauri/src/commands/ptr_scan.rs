//! 指针扫描 (P53) — 简版
//!
//! 1 层: 在 target 进程的所有 commit + 可读 region 里,搜索值在 [target-window, target] 范围的
//! 8 字节 little-endian QWORD。命中即报告 (region_base, offset, value)。
//!
//! N 层多级指针: 用户拿到 1 层结果选一个,再以"该指针地址 ± 偏移"为新 target 继续。
//! 完全 N 层自动扫工作量很大(GB 内存,几千万 ptr),GUI 提供"递归一层"按钮逐层走。

use std::ffi::c_void;

use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::Memory::{
    VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, PAGE_GUARD, PAGE_NOACCESS,
};
use windows::Win32::System::Threading::{
    OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
};

use crate::util::error::{AppError, AppResult};

#[derive(Debug, Clone, serde::Serialize)]
pub struct PtrHit {
    /// 包含该指针的地址 (即 RPM 该 8 字节得 target±offset 的位置)
    pub container: u64,
    /// 指针真实值
    pub value: u64,
    /// value - target_addr (偏移, 可能负)
    pub offset: i64,
}

#[derive(Debug, serde::Serialize)]
pub struct PtrScanResult {
    pub regions_scanned: u32,
    pub hits: Vec<PtrHit>,
    pub truncated: bool,
}

#[tauri::command]
pub async fn dbg_ptr_scan(
    pid: u32,
    target: u64,
    window: u32,
    max_hits: u32,
) -> AppResult<PtrScanResult> {
    let window = window.min(0x10000) as u64; // 64KB 偏移上限
    let max_hits = max_hits.clamp(1, 10_000) as usize;
    let lo = target.saturating_sub(window);
    let hi = target.saturating_add(window);

    tokio::task::spawn_blocking(move || -> AppResult<PtrScanResult> {
        unsafe {
            let h = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, pid)
                .map_err(|e| AppError::Internal(format!("OpenProcess: {e}")))?;
            let mut hits = vec![];
            let mut truncated = false;
            let mut regions = 0u32;

            let mut va: u64 = 0;
            loop {
                let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
                let q = VirtualQueryEx(
                    h,
                    Some(va as *const c_void),
                    &mut mbi,
                    std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                );
                if q == 0 {
                    break;
                }
                let next = (mbi.BaseAddress as u64).saturating_add(mbi.RegionSize as u64);
                if next <= va {
                    break;
                }
                va = next;
                if va >= 0x7FFF_FFFF_FFFF {
                    break;
                }

                let usable = mbi.State == MEM_COMMIT
                    && (mbi.Protect.0 & PAGE_NOACCESS.0) == 0
                    && (mbi.Protect.0 & PAGE_GUARD.0) == 0;
                if !usable {
                    continue;
                }
                regions += 1;

                // 切片读以免单 region 太大爆内存 (1MB 一片)
                let base = mbi.BaseAddress as u64;
                let size = mbi.RegionSize as u64;
                const CHUNK: u64 = 0x100000;
                let mut buf = vec![0u8; CHUNK as usize];
                let mut off = 0u64;
                while off < size {
                    let take = (size - off).min(CHUNK) as usize;
                    if take < 8 {
                        break;
                    }
                    let mut got = 0usize;
                    let ok = ReadProcessMemory(
                        h,
                        (base + off) as *const c_void,
                        buf.as_mut_ptr() as *mut c_void,
                        take,
                        Some(&mut got),
                    )
                    .is_ok();
                    if !ok || got < 8 {
                        off += CHUNK;
                        continue;
                    }
                    // 扫 8 字节对齐(常规 ptr 对齐) — 速度提升 8 倍,几乎不漏
                    let end = got - 8;
                    let mut i = 0usize;
                    while i <= end {
                        let v = u64::from_le_bytes(buf[i..i + 8].try_into().unwrap());
                        if v >= lo && v <= hi {
                            hits.push(PtrHit {
                                container: base + off + i as u64,
                                value: v,
                                offset: v as i64 - target as i64,
                            });
                            if hits.len() >= max_hits {
                                truncated = true;
                                let _ = windows::Win32::Foundation::CloseHandle(h);
                                return Ok(PtrScanResult { regions_scanned: regions, hits, truncated });
                            }
                        }
                        i += 8;
                    }
                    off += CHUNK;
                }
            }
            let _ = windows::Win32::Foundation::CloseHandle(h);
            Ok(PtrScanResult { regions_scanned: regions, hits, truncated })
        }
    })
    .await
    .map_err(|e| AppError::Internal(format!("spawn_blocking: {e}")))?
}
