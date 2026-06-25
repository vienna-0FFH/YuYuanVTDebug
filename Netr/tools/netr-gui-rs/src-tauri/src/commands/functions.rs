//! 函数边界识别 (P91) — list_functions / get_function
//!
//! 主要来源: PE Exception Directory (.pdata 表) — Windows x64 ABI 要求函数入栈
//! 时必须有 UNWIND_INFO, 表项 RUNTIME_FUNCTION { BeginAddress, EndAddress,
//! UnwindData } 是权威函数边界. 几乎所有 MSVC 编译的 exe/dll 都有.
//!
//! 没有 .pdata 的回退: 扫描 .text 找 prologue (sub rsp / push rbp / ...)
//! 但 .pdata 覆盖 >99%, 暂只做 .pdata 路径.

use std::ffi::c_void;

use serde::{Deserialize, Serialize};
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;

use crate::commands::pe_util::{enum_modules, locate_section, open_for_read, pick_module};
use crate::util::error::{AppError, AppResult};

#[derive(Debug, Serialize, Clone)]
pub struct FunctionEntry {
    pub start: u64,
    pub end: u64,
    pub size: u32,
    pub rva: u32,
}

#[derive(Debug, Deserialize)]
pub struct ListFunctionsReq {
    pub pid: u32,
    pub module_name: Option<String>,
    pub limit: Option<u32>,
    pub offset: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct ListFunctionsResult {
    pub module: String,
    pub module_base: u64,
    pub total: u32,
    pub offset: u32,
    pub count: u32,
    pub functions: Vec<FunctionEntry>,
}

unsafe fn read_pdata(h: windows::Win32::Foundation::HANDLE, base: u64, size: u64) -> AppResult<Vec<FunctionEntry>> {
    // 找 .pdata section
    let (range, _) = locate_section(h, base, size, b".pdata\0\0");
    let (pdata_start, pdata_size) = match range {
        Some(r) => r,
        None => return Err(AppError::Internal(".pdata 段不存在".into())),
    };
    if pdata_size == 0 || pdata_size > 64 * 1024 * 1024 {
        return Err(AppError::Internal(format!(".pdata 大小异常: {pdata_size}")));
    }
    // 每项 12 字节: BeginAddress(u32), EndAddress(u32), UnwindData(u32) — 都是 RVA
    let mut buf = vec![0u8; pdata_size as usize];
    let mut got = 0usize;
    ReadProcessMemory(h, pdata_start as *const c_void, buf.as_mut_ptr() as *mut c_void, buf.len(), Some(&mut got))
        .map_err(|e| AppError::Internal(format!("读 .pdata: {e}")))?;
    if got < 12 { return Err(AppError::Internal(".pdata 读取过少".into())); }
    let n = got / 12;
    let mut funcs = Vec::with_capacity(n);
    for i in 0..n {
        let off = i * 12;
        let begin = u32::from_le_bytes(buf[off..off+4].try_into().unwrap());
        let end = u32::from_le_bytes(buf[off+4..off+8].try_into().unwrap());
        if begin == 0 || end <= begin { continue; }
        funcs.push(FunctionEntry {
            start: base + begin as u64,
            end: base + end as u64,
            size: end - begin,
            rva: begin,
        });
    }
    funcs.sort_by_key(|f| f.start);
    Ok(funcs)
}

#[tauri::command]
pub async fn dbg_list_functions(req: ListFunctionsReq) -> AppResult<ListFunctionsResult> {
    let pid = req.pid;
    let want = req.module_name;
    let limit = req.limit.unwrap_or(500).clamp(1, 50000) as usize;
    let offset = req.offset.unwrap_or(0) as usize;

    tokio::task::spawn_blocking(move || -> AppResult<ListFunctionsResult> {
        unsafe {
            let h = open_for_read(pid)?;
            let mods = enum_modules(pid);
            let m = pick_module(&mods, want.as_deref())
                .ok_or_else(|| AppError::Internal("找不到模块".into()))?
                .clone();
            let funcs = read_pdata(h, m.base, m.size);
            let _ = windows::Win32::Foundation::CloseHandle(h);
            let funcs = funcs?;
            let total = funcs.len() as u32;
            let start = offset.min(funcs.len());
            let end = (start + limit).min(funcs.len());
            Ok(ListFunctionsResult {
                module: m.name,
                module_base: m.base,
                total,
                offset: start as u32,
                count: (end - start) as u32,
                functions: funcs[start..end].to_vec(),
            })
        }
    })
    .await
    .map_err(|e| AppError::Internal(format!("spawn_blocking: {e}")))?
}

#[derive(Debug, Deserialize)]
pub struct GetFunctionReq {
    pub pid: u32,
    pub address: u64,
}

#[derive(Debug, Serialize)]
pub struct GetFunctionResult {
    pub found: bool,
    pub module: Option<String>,
    pub function: Option<FunctionEntry>,
    pub offset_in_function: Option<u32>,
}

#[tauri::command]
pub async fn dbg_get_function(req: GetFunctionReq) -> AppResult<GetFunctionResult> {
    let pid = req.pid;
    let addr = req.address;
    tokio::task::spawn_blocking(move || -> AppResult<GetFunctionResult> {
        unsafe {
            let h = open_for_read(pid)?;
            let mods = enum_modules(pid);
            // 找包含 addr 的模块
            let m = mods.iter().find(|m| addr >= m.base && addr < m.base + m.size).cloned();
            let m = match m {
                None => { let _ = windows::Win32::Foundation::CloseHandle(h); return Ok(GetFunctionResult { found: false, module: None, function: None, offset_in_function: None }); }
                Some(m) => m,
            };
            let funcs = read_pdata(h, m.base, m.size);
            let _ = windows::Win32::Foundation::CloseHandle(h);
            let funcs = match funcs { Ok(v) => v, Err(_) => return Ok(GetFunctionResult { found: false, module: Some(m.name), function: None, offset_in_function: None }) };
            // 二分: 找 start <= addr 的最右一个, 然后检查 addr < end
            let idx = funcs.partition_point(|f| f.start <= addr);
            if idx == 0 {
                return Ok(GetFunctionResult { found: false, module: Some(m.name), function: None, offset_in_function: None });
            }
            let f = &funcs[idx - 1];
            if addr >= f.start && addr < f.end {
                let off = (addr - f.start) as u32;
                Ok(GetFunctionResult {
                    found: true,
                    module: Some(m.name),
                    function: Some(f.clone()),
                    offset_in_function: Some(off),
                })
            } else {
                Ok(GetFunctionResult { found: false, module: Some(m.name), function: None, offset_in_function: None })
            }
        }
    })
    .await
    .map_err(|e| AppError::Internal(format!("spawn_blocking: {e}")))?
}
