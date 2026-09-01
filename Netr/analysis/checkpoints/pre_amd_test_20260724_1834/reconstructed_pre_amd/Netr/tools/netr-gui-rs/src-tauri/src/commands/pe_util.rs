//! PE / 模块通用 helper (P91+) — find_globals / xref / strings / imports 共用.
//!
//! 不开 public command, 只暴露给同 crate 其他 commands 模块.

use std::ffi::c_void;

use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, MODULEENTRY32W,
    TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32,
};
use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};

use crate::util::error::{AppError, AppResult};

#[derive(Debug, Clone)]
pub struct ModInfo {
    pub name: String,
    pub base: u64,
    pub size: u64,
    pub is_exe: bool,
}

pub unsafe fn open_for_read(pid: u32) -> AppResult<HANDLE> {
    OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, pid)
        .map_err(|e| AppError::Internal(format!("OpenProcess({pid}): {e}")))
}

pub unsafe fn enum_modules(pid: u32) -> Vec<ModInfo> {
    let snap = match CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid) {
        Ok(s) => s,
        Err(_) => return vec![],
    };
    let mut me: MODULEENTRY32W = std::mem::zeroed();
    me.dwSize = std::mem::size_of::<MODULEENTRY32W>() as u32;
    let mut out = vec![];
    if Module32FirstW(snap, &mut me).is_ok() {
        loop {
            let end = me.szModule.iter().position(|&c| c == 0).unwrap_or(me.szModule.len());
            let name = String::from_utf16_lossy(&me.szModule[..end]);
            let is_exe = name.to_lowercase().ends_with(".exe");
            out.push(ModInfo {
                name,
                base: me.modBaseAddr as u64,
                size: me.modBaseSize as u64,
                is_exe,
            });
            if Module32NextW(snap, &mut me).is_err() {
                break;
            }
        }
    }
    let _ = windows::Win32::Foundation::CloseHandle(snap);
    out
}

pub fn pick_module<'a>(mods: &'a [ModInfo], want_name: Option<&str>) -> Option<&'a ModInfo> {
    if let Some(name) = want_name.map(|s| s.trim()).filter(|s| !s.is_empty()) {
        let lc = name.to_lowercase();
        mods.iter().find(|m| m.name.to_lowercase() == lc)
    } else {
        mods.iter().find(|m| m.is_exe).or_else(|| mods.first())
    }
}

/// .text 段范围. 解析失败回退 (base, size).
pub unsafe fn locate_text(h: HANDLE, base: u64, size: u64) -> (u64, u64) {
    let (range, _) = locate_section(h, base, size, b".text\0\0\0");
    if let Some((a, b)) = range { (a, b) } else { (base, size) }
}

/// 通用段查找. name 必须 8 字节 (用 \0 补齐).
/// 返回 (start, size) 和 PE 头偏移信息(供后续 PE 解析复用).
pub unsafe fn locate_section(
    h: HANDLE,
    base: u64,
    _size: u64,
    section_name: &[u8; 8],
) -> (Option<(u64, u64)>, Option<PeHeader>) {
    let mut buf = vec![0u8; 4096];
    let mut got = 0usize;
    if ReadProcessMemory(h, base as *const c_void, buf.as_mut_ptr() as *mut c_void, buf.len(), Some(&mut got)).is_err() {
        return (None, None);
    }
    if got < 0x200 || buf[0] != b'M' || buf[1] != b'Z' { return (None, None); }
    let e_lfanew = i32::from_le_bytes([buf[0x3c], buf[0x3d], buf[0x3e], buf[0x3f]]) as usize;
    if e_lfanew + 0x118 > got { return (None, None); }
    if &buf[e_lfanew..e_lfanew + 4] != b"PE\0\0" { return (None, None); }
    // IMAGE_FILE_HEADER offset = e_lfanew + 4
    let num_sections = u16::from_le_bytes([buf[e_lfanew + 6], buf[e_lfanew + 7]]) as usize;
    let opt_size = u16::from_le_bytes([buf[e_lfanew + 20], buf[e_lfanew + 21]]) as usize;
    let opt_off = e_lfanew + 24;
    if opt_off + opt_size > got { return (None, None); }
    let magic = u16::from_le_bytes([buf[opt_off], buf[opt_off + 1]]);
    let is_pe32_plus = magic == 0x20b;
    let sections_off = opt_off + opt_size;
    if sections_off + num_sections * 40 > got { return (None, None); }

    let mut target_range: Option<(u64, u64)> = None;
    for i in 0..num_sections {
        let s = sections_off + i * 40;
        let name = &buf[s..s + 8];
        let virt_size = u32::from_le_bytes(buf[s + 8..s + 12].try_into().unwrap()) as u64;
        let virt_addr = u32::from_le_bytes(buf[s + 12..s + 16].try_into().unwrap()) as u64;
        if name == section_name && target_range.is_none() {
            target_range = Some((base + virt_addr, virt_size));
        }
    }

    // 也把 OptionalHeader 关键字段抽出来
    // PE32+: BaseOfCode @ +20, SizeOfCode @ +4, DataDirectory[16] @ +112
    // PE32:  BaseOfCode @ +20, SizeOfCode @ +4, BaseOfData @ +24, DataDirectory @ +96
    let data_dir_off = opt_off + if is_pe32_plus { 112 } else { 96 };
    let mut dirs = [(0u32, 0u32); 16];
    if data_dir_off + 16 * 8 <= got {
        for i in 0..16 {
            let d = data_dir_off + i * 8;
            let rva = u32::from_le_bytes(buf[d..d+4].try_into().unwrap());
            let sz = u32::from_le_bytes(buf[d+4..d+8].try_into().unwrap());
            dirs[i] = (rva, sz);
        }
    }
    let header = PeHeader {
        is_pe32_plus,
        num_sections: num_sections as u16,
        data_directories: dirs,
        sections_off_in_image: sections_off,
        opt_size,
        e_lfanew,
    };
    (target_range, Some(header))
}

#[derive(Debug, Clone)]
pub struct PeHeader {
    pub is_pe32_plus: bool,
    pub num_sections: u16,
    /// [export, import, resource, exception, security, base_reloc, debug, ..., iat, ...]
    pub data_directories: [(u32, u32); 16],
    pub sections_off_in_image: usize,
    pub opt_size: usize,
    pub e_lfanew: usize,
}

/// 读 RVA → VA. 不存在返 None.
pub unsafe fn read_at_rva(h: HANDLE, base: u64, rva: u32, buf: &mut [u8]) -> bool {
    if rva == 0 { return false; }
    let mut got = 0usize;
    ReadProcessMemory(
        h,
        (base + rva as u64) as *const c_void,
        buf.as_mut_ptr() as *mut c_void,
        buf.len(),
        Some(&mut got),
    ).is_ok() && got == buf.len()
}

pub unsafe fn read_va(h: HANDLE, addr: u64, buf: &mut [u8]) -> bool {
    let mut got = 0usize;
    ReadProcessMemory(
        h,
        addr as *const c_void,
        buf.as_mut_ptr() as *mut c_void,
        buf.len(),
        Some(&mut got),
    ).is_ok() && got == buf.len()
}

/// 读以 \0 结尾的 ASCII C 字符串. max_len 上限.
pub unsafe fn read_c_string(h: HANDLE, addr: u64, max: usize) -> Option<String> {
    let mut buf = vec![0u8; max];
    let mut got = 0usize;
    ReadProcessMemory(h, addr as *const c_void, buf.as_mut_ptr() as *mut c_void, max, Some(&mut got)).ok()?;
    if got == 0 { return None; }
    let n = buf[..got].iter().position(|&b| b == 0).unwrap_or(got);
    Some(String::from_utf8_lossy(&buf[..n]).to_string())
}
