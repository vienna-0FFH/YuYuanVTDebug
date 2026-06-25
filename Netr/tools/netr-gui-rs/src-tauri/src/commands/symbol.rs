//! 符号解析 (P52)
//!
//! 简版: 只解析 PE 导出表 (EAT)。无 PDB / 无 symsrv。
//! 用 ReadProcessMemory 读 target 进程内的 module headers + export directory,
//! 把所有 export name → RVA 缓存,GUI 查地址时反查最近的 export。
//!
//! 覆盖率: 系统 dll 的所有公开 API (kernel32!CreateFileW, ntdll!NtClose ...).
//! 私有符号 / 游戏自己的函数: 看不到 (没 PDB),只能显示 modname+offset。

use std::collections::HashMap;
use std::ffi::c_void;
use std::sync::{Arc, Mutex};

use tauri::State;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, MODULEENTRY32W,
    TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32,
};
use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};

use crate::util::error::{AppError, AppResult};

#[derive(Debug, Clone, serde::Serialize)]
pub struct Symbol {
    pub address: u64,
    pub name: String,
    pub module: String,
    pub offset: u64, // 如果命中精确符号则 0,否则 = address - 最近符号地址
}

#[derive(Default)]
struct ModuleSyms {
    /// 该模块所有导出(已排序 by addr)
    items: Vec<(u64, String)>, // (abs_addr, name)
}

#[derive(Default)]
struct PidCache {
    /// pid → modname → ModuleSyms
    by_pid: HashMap<u32, HashMap<String, ModuleSyms>>,
}

#[derive(Default)]
pub struct SymbolStore(pub Arc<Mutex<PidCache>>);

unsafe fn read_pod<T: Copy>(h: HANDLE, addr: u64) -> Option<T> {
    let mut out = std::mem::zeroed::<T>();
    let mut got = 0usize;
    let ok = ReadProcessMemory(
        h,
        addr as *const c_void,
        &mut out as *mut T as *mut c_void,
        std::mem::size_of::<T>(),
        Some(&mut got),
    )
    .is_ok();
    if !ok || got != std::mem::size_of::<T>() {
        return None;
    }
    Some(out)
}

unsafe fn read_bytes(h: HANDLE, addr: u64, size: usize) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; size];
    let mut got = 0usize;
    let ok = ReadProcessMemory(
        h,
        addr as *const c_void,
        buf.as_mut_ptr() as *mut c_void,
        size,
        Some(&mut got),
    )
    .is_ok();
    if !ok || got != size {
        return None;
    }
    Some(buf)
}

unsafe fn read_cstr(h: HANDLE, addr: u64, max: usize) -> Option<String> {
    let buf = read_bytes(h, addr, max)?;
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    Some(String::from_utf8_lossy(&buf[..end]).into_owned())
}

/// 解析单个 module 的导出表
unsafe fn parse_exports(h: HANDLE, base: u64) -> Option<Vec<(u64, String)>> {
    // DOS header
    let e_lfanew: u32 = read_pod::<u32>(h, base + 0x3c)?;
    let nt_off = base + e_lfanew as u64;
    // PE signature 0x00004550
    let sig: u32 = read_pod::<u32>(h, nt_off)?;
    if sig != 0x00004550 {
        return None;
    }
    // IMAGE_NT_HEADERS64: Signature(4) + FileHeader(20) + OptionalHeader
    let opt_off = nt_off + 4 + 20;
    // OptionalHeader.Magic = 0x20b (PE32+)
    let magic: u16 = read_pod::<u16>(h, opt_off)?;
    if magic != 0x20b {
        return None;
    }
    // DataDirectory[0] = Export, 在 OptionalHeader 偏移 0x70 (PE32+)
    let exp_rva: u32 = read_pod::<u32>(h, opt_off + 0x70)?;
    let exp_size: u32 = read_pod::<u32>(h, opt_off + 0x74)?;
    if exp_rva == 0 || exp_size == 0 {
        return Some(vec![]);
    }
    let exp_va = base + exp_rva as u64;

    // IMAGE_EXPORT_DIRECTORY:
    //   +0x10 Base (ULONG)
    //   +0x14 NumberOfFunctions
    //   +0x18 NumberOfNames
    //   +0x1C AddressOfFunctions (RVA)
    //   +0x20 AddressOfNames (RVA)
    //   +0x24 AddressOfNameOrdinals (RVA)
    let num_funcs: u32 = read_pod::<u32>(h, exp_va + 0x14)?;
    let num_names: u32 = read_pod::<u32>(h, exp_va + 0x18)?;
    let funcs_rva: u32 = read_pod::<u32>(h, exp_va + 0x1c)?;
    let names_rva: u32 = read_pod::<u32>(h, exp_va + 0x20)?;
    let ords_rva: u32 = read_pod::<u32>(h, exp_va + 0x24)?;

    if num_funcs > 100_000 || num_names > 100_000 {
        return None;
    }
    let funcs_table = read_bytes(h, base + funcs_rva as u64, num_funcs as usize * 4)?;
    let names_table = read_bytes(h, base + names_rva as u64, num_names as usize * 4)?;
    let ords_table = read_bytes(h, base + ords_rva as u64, num_names as usize * 2)?;

    let mut out = Vec::with_capacity(num_names as usize);
    for i in 0..num_names as usize {
        let name_rva = u32::from_le_bytes(names_table[i * 4..i * 4 + 4].try_into().ok()?);
        let ord = u16::from_le_bytes(ords_table[i * 2..i * 2 + 2].try_into().ok()?) as usize;
        if ord >= num_funcs as usize {
            continue;
        }
        let func_rva = u32::from_le_bytes(funcs_table[ord * 4..ord * 4 + 4].try_into().ok()?);
        if func_rva == 0 {
            continue;
        }
        // forwarded export: rva 落在 export directory 范围内 → 指向 "module.func" 字符串,跳过
        if func_rva >= exp_rva && func_rva < exp_rva + exp_size {
            continue;
        }
        if let Some(name) = read_cstr(h, base + name_rva as u64, 256) {
            out.push((base + func_rva as u64, name));
        }
    }
    out.sort_by_key(|x| x.0);
    Some(out)
}

/// 批量解析: 一次接收多个地址,共用 module list 缓存,大幅减少 IPC 来回
#[tauri::command]
pub async fn dbg_resolve_symbols(
    store: State<'_, SymbolStore>,
    pid: u32,
    addresses: Vec<u64>,
) -> AppResult<Vec<Option<Symbol>>> {
    let cache = store.0.clone();
    tokio::task::spawn_blocking(move || -> AppResult<Vec<Option<Symbol>>> {
        let mods = unsafe { snapshot_modules(pid)? };
        let h = unsafe { open(pid)? };
        let mut guard = cache.lock().unwrap();
        let by_mod = guard.by_pid.entry(pid).or_default();
        let mut out = Vec::with_capacity(addresses.len());
        for addr in addresses {
            let m = mods.iter().find(|m| addr >= m.base && addr < m.base + m.size);
            let Some(m) = m else { out.push(None); continue; };
            if !by_mod.contains_key(&m.name) {
                let parsed = unsafe { parse_exports(h, m.base).unwrap_or_default() };
                by_mod.insert(m.name.clone(), ModuleSyms { items: parsed });
            }
            let syms = by_mod.get(&m.name).unwrap();
            if syms.items.is_empty() {
                out.push(Some(Symbol {
                    address: addr,
                    name: format!("0x{:x}", addr - m.base),
                    module: m.name.clone(),
                    offset: addr - m.base,
                }));
                continue;
            }
            let idx = match syms.items.binary_search_by_key(&addr, |x| x.0) {
                Ok(i) => i,
                Err(0) => {
                    out.push(Some(Symbol {
                        address: addr,
                        name: format!("0x{:x}", addr - m.base),
                        module: m.name.clone(),
                        offset: addr - m.base,
                    }));
                    continue;
                }
                Err(i) => i - 1,
            };
            let (sym_addr, sym_name) = &syms.items[idx];
            out.push(Some(Symbol {
                address: addr,
                name: sym_name.clone(),
                module: m.name.clone(),
                offset: addr - *sym_addr,
            }));
        }
        unsafe { let _ = windows::Win32::Foundation::CloseHandle(h); }
        Ok(out)
    })
    .await
    .map_err(|e| AppError::Internal(format!("spawn_blocking: {e}")))?
}

/// 公开命令: 解析地址(可选刷新缓存)
#[tauri::command]
pub async fn dbg_resolve_symbol(
    store: State<'_, SymbolStore>,
    pid: u32,
    address: u64,
    refresh: bool,
) -> AppResult<Option<Symbol>> {
    let cache = store.0.clone();
    tokio::task::spawn_blocking(move || -> AppResult<Option<Symbol>> {
        // 取当前进程 module 列表
        let mods = unsafe { snapshot_modules(pid)? };

        // 找包含 address 的 module
        let m = mods.iter().find(|m| address >= m.base && address < m.base + m.size);
        let Some(m) = m else { return Ok(None); };

        let mut guard = cache.lock().unwrap();
        let by_mod = guard.by_pid.entry(pid).or_default();
        if refresh || !by_mod.contains_key(&m.name) {
            let parsed = unsafe { parse_exports(open(pid)?, m.base).unwrap_or_default() };
            by_mod.insert(m.name.clone(), ModuleSyms { items: parsed });
        }
        let syms = by_mod.get(&m.name).unwrap();
        let res = if syms.items.is_empty() {
            // 没导出可解 — 返 modname+offset
            Some(Symbol {
                address,
                name: format!("0x{:x}", address - m.base),
                module: m.name.clone(),
                offset: address - m.base,
            })
        } else {
            // 二分: 找 <= address 的最大
            let idx = match syms.items.binary_search_by_key(&address, |x| x.0) {
                Ok(i) => i,
                Err(0) => {
                    return Ok(Some(Symbol {
                        address,
                        name: format!("0x{:x}", address - m.base),
                        module: m.name.clone(),
                        offset: address - m.base,
                    }));
                }
                Err(i) => i - 1,
            };
            let (sym_addr, sym_name) = &syms.items[idx];
            let offset = address - *sym_addr;
            Some(Symbol {
                address,
                name: sym_name.clone(),
                module: m.name.clone(),
                offset,
            })
        };
        Ok(res)
    })
    .await
    .map_err(|e| AppError::Internal(format!("spawn_blocking: {e}")))?
}

struct ModEntry {
    base: u64,
    size: u64,
    name: String,
}

unsafe fn open(pid: u32) -> AppResult<HANDLE> {
    OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, pid)
        .map_err(|e| AppError::Internal(format!("OpenProcess({pid}): {e}")))
}

unsafe fn snapshot_modules(pid: u32) -> AppResult<Vec<ModEntry>> {
    let snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
        .map_err(|e| AppError::Internal(format!("CreateToolhelp32Snapshot: {e}")))?;
    let mut me: MODULEENTRY32W = std::mem::zeroed();
    me.dwSize = std::mem::size_of::<MODULEENTRY32W>() as u32;
    let mut out = vec![];
    if Module32FirstW(snap, &mut me).is_ok() {
        loop {
            let name = String::from_utf16_lossy(
                &me.szModule[..me.szModule.iter().position(|&c| c == 0).unwrap_or(me.szModule.len())],
            );
            out.push(ModEntry {
                base: me.modBaseAddr as u64,
                size: me.modBaseSize as u64,
                name,
            });
            if Module32NextW(snap, &mut me).is_err() {
                break;
            }
        }
    }
    let _ = windows::Win32::Foundation::CloseHandle(snap);
    Ok(out)
}
