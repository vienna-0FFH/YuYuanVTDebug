//! 结构 Dissect (P53)
//!
//! 给定起始地址 + 长度,逐 8 字节滑窗,每字段自动猜类型:
//!   - 全 0 → "padding"
//!   - 可解 ASCII >=4 字符 → "string"
//!   - 落在 module .text → "code ptr"
//!   - 落在合理 VA (< 0x7FFF_xxxx_xxxx 且 ≥ 0x10000) → "data ptr"
//!   - 高 4 字节为 0 + 看着像 int32 → "i32"
//!   - 否则 → "i64" / 原始 hex

use std::ffi::c_void;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};

use crate::util::error::{AppError, AppResult};

#[derive(Debug, Clone, serde::Serialize)]
pub struct DissectField {
    pub offset: u32,
    pub kind: String,      // "padding" | "i32" | "i64" | "f32" | "f64" | "ptr" | "string" | "raw"
    pub raw_hex: String,   // 8 byte hex
    pub display: String,   // 解释后的可读串
}

#[tauri::command]
pub async fn dbg_dissect(pid: u32, address: u64, size: u32) -> AppResult<Vec<DissectField>> {
    let size = size.min(4096) as usize;
    tokio::task::spawn_blocking(move || -> AppResult<Vec<DissectField>> {
        unsafe {
            let h = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, pid)
                .map_err(|e| AppError::Internal(format!("OpenProcess: {e}")))?;
            let mut buf = vec![0u8; size];
            let mut got = 0usize;
            let ok = ReadProcessMemory(
                h,
                address as *const c_void,
                buf.as_mut_ptr() as *mut c_void,
                size,
                Some(&mut got),
            )
            .is_ok();
            let _ = windows::Win32::Foundation::CloseHandle(h);
            if !ok || got == 0 {
                return Err(AppError::Internal("ReadProcessMemory failed".into()));
            }
            buf.truncate(got);

            let mut out = vec![];
            let mut off = 0usize;
            while off + 8 <= buf.len() {
                let v8 = &buf[off..off + 8];
                let qword = u64::from_le_bytes(v8.try_into().unwrap());
                let f = classify(qword, v8);
                out.push(DissectField {
                    offset: off as u32,
                    kind: f.0,
                    raw_hex: hex_le(v8),
                    display: f.1,
                });
                off += 8;
            }
            Ok(out)
        }
    })
    .await
    .map_err(|e| AppError::Internal(format!("spawn_blocking: {e}")))?
}

fn classify(qword: u64, v8: &[u8]) -> (String, String) {
    // 0
    if qword == 0 {
        return ("padding".into(), "0".into());
    }

    // 字符串 — 前 4..8 字符全是可打印 ASCII
    let printable_count = v8.iter().take_while(|&&b| (0x20..0x7f).contains(&b)).count();
    if printable_count >= 4 {
        let s: String = v8.iter().take(printable_count).map(|&b| b as char).collect();
        return ("string".into(), format!("\"{}\"", s));
    }

    // 像指针 — high 16 bit 是 0 或全 1 (kernel canonical),且非小数
    let high16 = (qword >> 48) & 0xFFFF;
    let looks_like_ptr =
        qword >= 0x10000
        && qword < 0x7FFF_FFFFFFFF
        && (high16 == 0 || high16 == 0xFFFF);
    if looks_like_ptr {
        return ("ptr".into(), format!("0x{:x}", qword));
    }

    // 小整数 — high 4 byte 0,low 4 byte 看起来合理
    if qword <= 0xFFFFFFFF {
        let i32v = qword as u32 as i32;
        // 同时算 f32 给参考
        let f32v = f32::from_bits(qword as u32);
        let f32_str = if f32v.is_finite() && f32v.abs() < 1e10 && f32v.abs() > 1e-10 {
            format!(" (f32={:.4})", f32v)
        } else {
            String::new()
        };
        return ("i32".into(), format!("{}{}", i32v, f32_str));
    }

    // f64
    let f = f64::from_bits(qword);
    if f.is_finite() && f.abs() < 1e15 && f.abs() > 1e-15 {
        return ("f64".into(), format!("{:.6}", f));
    }

    // i64
    (
        "i64".into(),
        format!("{}", qword as i64),
    )
}

fn hex_le(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect::<Vec<_>>().join(" ")
}
