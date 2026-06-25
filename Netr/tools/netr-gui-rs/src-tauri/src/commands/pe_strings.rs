//! 字符串提取 (P92) — list_strings
//!
//! 扫一个模块的 .rdata / .data 段, 提 ASCII (>= min_len) 和 UTF-16LE 字符串.
//! 字符必须是可打印 ASCII (0x20..0x7E) 或常用控制符 (\t\n\r).

use std::ffi::c_void;

use serde::{Deserialize, Serialize};
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;

use crate::commands::pe_util::{enum_modules, locate_section, open_for_read, pick_module};
use crate::util::error::{AppError, AppResult};

#[derive(Debug, Serialize)]
pub struct StringEntry {
    pub address: u64,
    pub encoding: &'static str,  // "ascii" / "utf16le"
    pub text: String,
}

#[derive(Debug, Deserialize)]
pub struct ListStringsReq {
    pub pid: u32,
    pub module_name: Option<String>,
    pub min_len: Option<u32>,
    pub limit: Option<u32>,
    pub filter: Option<String>,   // 子串过滤(可选, case-insensitive)
}

#[derive(Debug, Serialize)]
pub struct ListStringsResult {
    pub module: String,
    pub module_base: u64,
    pub total: u32,
    pub returned: u32,
    pub strings: Vec<StringEntry>,
}

fn is_ascii_printable(b: u8) -> bool {
    (0x20..=0x7E).contains(&b) || b == b'\t' || b == b'\n' || b == b'\r'
}

fn scan_ascii(base: u64, buf: &[u8], min_len: usize, out: &mut Vec<StringEntry>, limit: usize) {
    let mut i = 0;
    while i < buf.len() && out.len() < limit {
        if is_ascii_printable(buf[i]) {
            let mut j = i;
            while j < buf.len() && is_ascii_printable(buf[j]) { j += 1; }
            if j - i >= min_len && j < buf.len() && buf[j] == 0 {
                let s = String::from_utf8_lossy(&buf[i..j]).to_string();
                out.push(StringEntry { address: base + i as u64, encoding: "ascii", text: s });
            }
            i = j + 1;
        } else {
            i += 1;
        }
    }
}

fn scan_utf16(base: u64, buf: &[u8], min_len: usize, out: &mut Vec<StringEntry>, limit: usize) {
    let mut i = 0;
    while i + 1 < buf.len() && out.len() < limit {
        // wide ascii: low byte 可打印, high byte 0
        if is_ascii_printable(buf[i]) && buf[i + 1] == 0 {
            let mut j = i;
            while j + 1 < buf.len() && is_ascii_printable(buf[j]) && buf[j + 1] == 0 {
                j += 2;
            }
            let chars = (j - i) / 2;
            if chars >= min_len && j + 1 < buf.len() && buf[j] == 0 && buf[j + 1] == 0 {
                let utf16: Vec<u16> = buf[i..j].chunks_exact(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
                let s = String::from_utf16_lossy(&utf16);
                out.push(StringEntry { address: base + i as u64, encoding: "utf16le", text: s });
            }
            i = j + 2;
        } else {
            i += 2;
        }
    }
}

#[tauri::command]
pub async fn dbg_list_strings(req: ListStringsReq) -> AppResult<ListStringsResult> {
    let pid = req.pid;
    let want = req.module_name;
    let min_len = req.min_len.unwrap_or(5).clamp(3, 200) as usize;
    let limit = req.limit.unwrap_or(2000).clamp(1, 50000) as usize;
    let filter = req.filter.map(|s| s.to_lowercase());

    tokio::task::spawn_blocking(move || -> AppResult<ListStringsResult> {
        unsafe {
            let h = open_for_read(pid)?;
            let mods = enum_modules(pid);
            let m = pick_module(&mods, want.as_deref())
                .ok_or_else(|| AppError::Internal("找不到模块".into()))?
                .clone();

            let mut out = Vec::new();
            // 扫 .rdata + .data
            for section in &[b".rdata\0\0", b".data\0\0\0", b".text\0\0\0"][..] {
                if out.len() >= limit { break; }
                let (range, _) = locate_section(h, m.base, m.size, section);
                let Some((sect_base, sect_size)) = range else { continue };
                if sect_size == 0 || sect_size > 64 * 1024 * 1024 { continue; }
                let mut buf = vec![0u8; sect_size as usize];
                let mut got = 0usize;
                if ReadProcessMemory(h, sect_base as *const c_void, buf.as_mut_ptr() as *mut c_void, buf.len(), Some(&mut got)).is_err() { continue; }
                buf.truncate(got);
                scan_ascii(sect_base, &buf, min_len, &mut out, limit);
                if out.len() < limit {
                    scan_utf16(sect_base, &buf, min_len, &mut out, limit);
                }
            }
            let _ = windows::Win32::Foundation::CloseHandle(h);

            let total_before_filter = out.len() as u32;
            if let Some(f) = filter {
                out.retain(|s| s.text.to_lowercase().contains(&f));
            }
            let returned = out.len() as u32;
            Ok(ListStringsResult {
                module: m.name,
                module_base: m.base,
                total: total_before_filter,
                returned,
                strings: out,
            })
        }
    })
    .await
    .map_err(|e| AppError::Internal(format!("spawn_blocking: {e}")))?
}
