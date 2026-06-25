//! PE 导入/导出表 (P92).
//!
//! list_imports → 解析 IMAGE_DIRECTORY_ENTRY_IMPORT (idx=1)
//! list_exports → 解析 IMAGE_DIRECTORY_ENTRY_EXPORT (idx=0)

use std::ffi::c_void;

use serde::{Deserialize, Serialize};
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;

use crate::commands::pe_util::{enum_modules, locate_section, open_for_read, pick_module, read_c_string};
use crate::util::error::{AppError, AppResult};

#[derive(Debug, Serialize)]
pub struct ImportEntry {
    pub dll: String,
    pub name: String,
    pub ordinal: Option<u16>,
    pub iat_address: u64,        // 进程里实际 IAT 项地址
    pub resolved_address: u64,   // 当前 IAT 项内容(运行时填好的 API 地址)
}

#[derive(Debug, Deserialize)]
pub struct ListImportsReq {
    pub pid: u32,
    pub module_name: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ListImportsResult {
    pub module: String,
    pub module_base: u64,
    pub count: u32,
    pub imports: Vec<ImportEntry>,
}

// IMAGE_IMPORT_DESCRIPTOR: 5 个 u32
// OriginalFirstThunk / TimeDateStamp / ForwarderChain / Name / FirstThunk
fn u32_at(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(buf[off..off + 4].try_into().unwrap_or([0; 4]))
}
fn u64_at(buf: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(buf[off..off + 8].try_into().unwrap_or([0; 8]))
}

#[tauri::command]
pub async fn dbg_list_imports(req: ListImportsReq) -> AppResult<ListImportsResult> {
    let pid = req.pid;
    let want = req.module_name;
    tokio::task::spawn_blocking(move || -> AppResult<ListImportsResult> {
        unsafe {
            let h = open_for_read(pid)?;
            let mods = enum_modules(pid);
            let m = pick_module(&mods, want.as_deref())
                .ok_or_else(|| AppError::Internal("找不到模块".into()))?
                .clone();

            let (_text, pe_opt) = locate_section(h, m.base, m.size, b".text\0\0\0");
            let header = pe_opt.ok_or_else(|| AppError::Internal("无 PE 头".into()))?;
            // import dir = data_directories[1]
            let (idir_rva, idir_size) = header.data_directories[1];
            if idir_rva == 0 || idir_size == 0 {
                let _ = windows::Win32::Foundation::CloseHandle(h);
                return Ok(ListImportsResult { module: m.name, module_base: m.base, count: 0, imports: vec![] });
            }
            let dir_va = m.base + idir_rva as u64;
            let dir_size = idir_size.min(1024 * 1024) as usize;
            let mut idesc = vec![0u8; dir_size];
            let mut got = 0usize;
            ReadProcessMemory(h, dir_va as *const c_void, idesc.as_mut_ptr() as *mut c_void, dir_size, Some(&mut got))
                .map_err(|e| AppError::Internal(format!("读 import dir: {e}")))?;
            idesc.truncate(got);

            let mut imports = Vec::new();
            let mut idx = 0;
            while idx + 20 <= idesc.len() {
                let original_first_thunk = u32_at(&idesc, idx);
                let _time = u32_at(&idesc, idx + 4);
                let _fwd = u32_at(&idesc, idx + 8);
                let name_rva = u32_at(&idesc, idx + 12);
                let first_thunk = u32_at(&idesc, idx + 16);
                idx += 20;
                if name_rva == 0 && first_thunk == 0 { break; }
                if name_rva == 0 { continue; }
                let dll = read_c_string(h, m.base + name_rva as u64, 256).unwrap_or_default();
                // OFT 描述 hint/name, FT 是 IAT (运行时被解析填地址).
                // 没有 OFT 就用 FT (bound import).
                let thunk_rva = if original_first_thunk != 0 { original_first_thunk } else { first_thunk };
                let mut tk_off = 0u64;
                loop {
                    if imports.len() >= 5000 { break; }
                    let tk_va = m.base + thunk_rva as u64 + tk_off;
                    let mut tk_buf = [0u8; 8];
                    let mut tg = 0usize;
                    if ReadProcessMemory(h, tk_va as *const c_void, tk_buf.as_mut_ptr() as *mut c_void, 8, Some(&mut tg)).is_err() || tg < 8 {
                        break;
                    }
                    let tk = u64::from_le_bytes(tk_buf);
                    if tk == 0 { break; }
                    let iat_va = m.base + first_thunk as u64 + tk_off;
                    let mut iat_buf = [0u8; 8];
                    let _ = ReadProcessMemory(h, iat_va as *const c_void, iat_buf.as_mut_ptr() as *mut c_void, 8, Some(&mut tg));
                    let resolved = u64::from_le_bytes(iat_buf);

                    let (name, ordinal) = if tk & (1u64 << 63) != 0 {
                        // 序号导入
                        let ord = (tk & 0xFFFF) as u16;
                        (format!("Ordinal_{}", ord), Some(ord))
                    } else {
                        // IMAGE_IMPORT_BY_NAME: u16 Hint + ASCII name
                        let by_name_va = m.base + tk as u64;
                        let mut hint_buf = [0u8; 2];
                        let _ = ReadProcessMemory(h, by_name_va as *const c_void, hint_buf.as_mut_ptr() as *mut c_void, 2, Some(&mut tg));
                        let name = read_c_string(h, by_name_va + 2, 256).unwrap_or_default();
                        (name, None)
                    };
                    imports.push(ImportEntry {
                        dll: dll.clone(),
                        name,
                        ordinal,
                        iat_address: iat_va,
                        resolved_address: resolved,
                    });
                    tk_off += 8;
                    if tk_off > 32 * 1024 * 8 { break; } // sanity
                }
            }

            let _ = windows::Win32::Foundation::CloseHandle(h);
            Ok(ListImportsResult { module: m.name, module_base: m.base, count: imports.len() as u32, imports })
        }
    })
    .await
    .map_err(|e| AppError::Internal(format!("spawn_blocking: {e}")))?
}

// ===== exports =====

#[derive(Debug, Serialize)]
pub struct ExportEntry {
    pub name: String,
    pub rva: u32,
    pub ordinal: u16,
    pub address: u64,   // = base + rva
}

#[derive(Debug, Deserialize)]
pub struct ListExportsReq {
    pub pid: u32,
    pub module_name: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ListExportsResult {
    pub module: String,
    pub module_base: u64,
    pub count: u32,
    pub exports: Vec<ExportEntry>,
}

#[tauri::command]
pub async fn dbg_list_exports(req: ListExportsReq) -> AppResult<ListExportsResult> {
    let pid = req.pid;
    let want = req.module_name;
    tokio::task::spawn_blocking(move || -> AppResult<ListExportsResult> {
        unsafe {
            let h = open_for_read(pid)?;
            let mods = enum_modules(pid);
            let m = pick_module(&mods, want.as_deref())
                .ok_or_else(|| AppError::Internal("找不到模块".into()))?
                .clone();

            let (_text, pe_opt) = locate_section(h, m.base, m.size, b".text\0\0\0");
            let header = pe_opt.ok_or_else(|| AppError::Internal("无 PE 头".into()))?;
            let (edir_rva, edir_size) = header.data_directories[0];
            if edir_rva == 0 {
                let _ = windows::Win32::Foundation::CloseHandle(h);
                return Ok(ListExportsResult { module: m.name, module_base: m.base, count: 0, exports: vec![] });
            }
            let dir_va = m.base + edir_rva as u64;
            // IMAGE_EXPORT_DIRECTORY 40 bytes
            let mut buf = [0u8; 40];
            let mut got = 0usize;
            ReadProcessMemory(h, dir_va as *const c_void, buf.as_mut_ptr() as *mut c_void, 40, Some(&mut got))
                .map_err(|e| AppError::Internal(format!("读 export dir: {e}")))?;
            // +0x14 NumberOfFunctions(u32), +0x18 NumberOfNames(u32),
            // +0x10 Base(u32, ordinal base),
            // +0x1C AddressOfFunctions(u32 RVA), +0x20 AddressOfNames(u32 RVA), +0x24 AddressOfNameOrdinals(u32 RVA)
            let _name_rva = u32_at(&buf, 0x0C);
            let ord_base = u32_at(&buf, 0x10);
            let nfunc = u32_at(&buf, 0x14) as usize;
            let nname = u32_at(&buf, 0x18) as usize;
            let funcs_rva = u32_at(&buf, 0x1C);
            let names_rva = u32_at(&buf, 0x20);
            let ords_rva = u32_at(&buf, 0x24);
            if nfunc == 0 || nfunc > 200000 || funcs_rva == 0 {
                let _ = windows::Win32::Foundation::CloseHandle(h);
                return Ok(ListExportsResult { module: m.name, module_base: m.base, count: 0, exports: vec![] });
            }

            // 读 functions[nfunc] 数组 (u32 RVAs)
            let mut funcs = vec![0u32; nfunc];
            let funcs_va = m.base + funcs_rva as u64;
            let mut tg = 0usize;
            ReadProcessMemory(h, funcs_va as *const c_void, funcs.as_mut_ptr() as *mut c_void, nfunc * 4, Some(&mut tg))
                .map_err(|e| AppError::Internal(format!("读 export funcs: {e}")))?;

            // ord_base 是基础, names[i] 对应的 ordinal[i] 索引到 functions
            let mut names = vec![0u32; nname];
            if names_rva != 0 && nname > 0 {
                let _ = ReadProcessMemory(h, (m.base + names_rva as u64) as *const c_void, names.as_mut_ptr() as *mut c_void, nname * 4, Some(&mut tg));
            }
            let mut ords = vec![0u16; nname];
            if ords_rva != 0 && nname > 0 {
                let _ = ReadProcessMemory(h, (m.base + ords_rva as u64) as *const c_void, ords.as_mut_ptr() as *mut c_void, nname * 2, Some(&mut tg));
            }

            let mut exports = Vec::with_capacity(nfunc);
            // 用 name 列表 (有名字的导出)
            for i in 0..nname {
                let ord = ords[i] as usize;
                if ord >= nfunc { continue; }
                let rva = funcs[ord];
                if rva == 0 { continue; }
                let name_va = m.base + names[i] as u64;
                let name = read_c_string(h, name_va, 512).unwrap_or_default();
                exports.push(ExportEntry {
                    name,
                    rva,
                    ordinal: (ord_base as u16).saturating_add(ord as u16),
                    address: m.base + rva as u64,
                });
                if exports.len() >= 10000 { break; }
            }
            // 无名导出 (只有 ordinal)
            let named_ords: std::collections::HashSet<u16> = exports.iter().map(|e| e.ordinal.saturating_sub(ord_base as u16)).collect();
            for i in 0..nfunc.min(50000) {
                if exports.len() >= 10000 { break; }
                if named_ords.contains(&(i as u16)) { continue; }
                let rva = funcs[i];
                if rva == 0 { continue; }
                exports.push(ExportEntry {
                    name: format!("Ordinal_{}", ord_base as usize + i),
                    rva,
                    ordinal: (ord_base as u16).saturating_add(i as u16),
                    address: m.base + rva as u64,
                });
            }

            let _ = windows::Win32::Foundation::CloseHandle(h);
            Ok(ListExportsResult {
                module: m.name, module_base: m.base,
                count: exports.len() as u32, exports,
            })
        }
    })
    .await
    .map_err(|e| AppError::Internal(format!("spawn_blocking: {e}")))?
}
