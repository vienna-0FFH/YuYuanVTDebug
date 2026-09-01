//! 通用全局指针候选发现器 (P75)
//!
//! 扫主模块 .text 段所有 x64 指令,统计 RIP-relative 引用的"目标地址":
//!   LEA r64, [rip+disp32]   →  LEA 类引用 (常是全局变量地址)
//!   MOV r64, [rip+disp32]   →  MOV 类引用 (读全局指针/变量)
//!   CALL [rip+disp32]       →  CALL 间接表项
//!
//! 同一目标地址被多次引用 = 该地址是热点全局。GNames/GWorld/GEngine/GUObjectArray
//! 等都是被全引擎几千个函数引用的"超热点",所以按引用次数排序,Top-N 里几乎
//! 一定能找到。
//!
//! 不依赖签名 / 不依赖 LLM。对所有 UE/Unity 版本无差别工作。

use std::collections::HashMap;
use std::ffi::c_void;

use iced_x86::{Decoder, DecoderOptions, Instruction};
use tauri::AppHandle;
use tauri::Emitter;
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, MODULEENTRY32W,
    TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32,
};
use windows::Win32::System::Threading::{
    OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
};

use crate::util::error::{AppError, AppResult};

#[derive(Debug, Clone, serde::Serialize)]
pub struct GlobalCandidate {
    /// 全局地址(被引用的目标)
    pub address: u64,
    /// 引用次数总和
    pub refs: u32,
    /// LEA 引用数 (这种几乎一定是地址本身)
    pub lea_refs: u32,
    /// MOV 引用数 (这种是读这个全局的值)
    pub mov_refs: u32,
    /// 该地址处读到的 8 字节(低 8 字节十六进制,帮助辨认是不是指针/字符串)
    pub at_value_hex: String,
    /// 命中的几条 RIP-rel 指令地址(只留前 3 条用于跳转)
    pub sample_callers: Vec<u64>,
    /// 该地址落在哪个段(如果在模块内)
    pub in_module: bool,
}

#[derive(Debug, serde::Serialize)]
pub struct FindGlobalsResult {
    pub candidates: Vec<GlobalCandidate>,
    /// 主模块代码段范围(用户参考)
    pub text_base: u64,
    pub text_size: u64,
    /// 共反汇编了多少字节
    pub bytes_decoded: u64,
    /// 共发现多少条 RIP-rel 引用
    pub rip_refs_total: u32,
}

#[derive(serde::Deserialize)]
pub struct FindGlobalsReq {
    pub pid: u32,
    /// 主模块名(空 = 自动选 exe)
    pub module_name: Option<String>,
    /// 返回 Top-N 候选 (按 refs 降序)
    pub top_n: Option<u32>,
    /// 最低引用次数门槛(默认 5)
    pub min_refs: Option<u32>,
}

#[allow(dead_code)]
unsafe fn open_for_read(pid: u32) -> AppResult<windows::Win32::Foundation::HANDLE> {
    OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, pid)
        .map_err(|e| AppError::Internal(format!("OpenProcess({pid}): {e}")))
}

#[allow(dead_code)]
struct ModInfo {
    name: String,
    base: u64,
    size: u64,
    is_exe: bool,
}

#[allow(dead_code)]
unsafe fn enum_modules(pid: u32) -> Vec<ModInfo> {
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

/// 解析 PE 头取 .text 段范围。
/// 简化:读 IMAGE_NT_HEADERS64.OptionalHeader.BaseOfCode + SizeOfCode。
/// 失败时回退用 (base, size) 整个模块(慢但能跑)。
unsafe fn locate_text(
    h: windows::Win32::Foundation::HANDLE,
    base: u64,
    size: u64,
) -> (u64, u64) {
    let mut buf = [0u8; 1024];
    let mut got = 0usize;
    if ReadProcessMemory(h, base as *const c_void, buf.as_mut_ptr() as *mut c_void, 1024, Some(&mut got)).is_err() {
        return (base, size);
    }
    if got < 0x200 || buf[0] != b'M' || buf[1] != b'Z' {
        return (base, size);
    }
    let e_lfanew = i32::from_le_bytes([buf[0x3c], buf[0x3d], buf[0x3e], buf[0x3f]]) as usize;
    if e_lfanew + 0x80 > got { return (base, size); }
    // IMAGE_NT_HEADERS64.Signature 应为 "PE\0\0"
    if &buf[e_lfanew..e_lfanew + 4] != b"PE\0\0" { return (base, size); }
    // OptionalHeader 起点 = e_lfanew + 24
    let opt_off = e_lfanew + 24;
    // PE32+ OptionalHeader: +0 Magic, +4 SizeOfCode(u32), +8 SizeOfInitData, ..., +0x14 BaseOfCode(u32)
    if opt_off + 0x18 > got { return (base, size); }
    let magic = u16::from_le_bytes([buf[opt_off], buf[opt_off + 1]]);
    if magic != 0x20b { return (base, size); }
    let size_of_code = u32::from_le_bytes(buf[opt_off + 4..opt_off + 8].try_into().unwrap()) as u64;
    let base_of_code = u32::from_le_bytes(buf[opt_off + 20..opt_off + 24].try_into().unwrap()) as u64;
    if size_of_code == 0 || size_of_code > size { return (base, size); }
    (base + base_of_code, size_of_code)
}

#[tauri::command]
pub async fn dbg_find_globals(
    app: AppHandle,
    req: FindGlobalsReq,
) -> AppResult<FindGlobalsResult> {
    let pid = req.pid;
    let top_n = req.top_n.unwrap_or(50).max(1) as usize;
    let min_refs = req.min_refs.unwrap_or(5).max(1);
    let want_name = req.module_name.unwrap_or_default().to_lowercase();

    tokio::task::spawn_blocking(move || -> AppResult<FindGlobalsResult> {
        unsafe {
            let h = open_for_read(pid)?;
            let mods = enum_modules(pid);

            // 选模块
            let target_mod = if !want_name.is_empty() {
                mods.iter().find(|m| m.name.to_lowercase() == want_name)
            } else {
                mods.iter().find(|m| m.is_exe)
            };
            let m = match target_mod {
                Some(m) => m,
                None => {
                    let _ = windows::Win32::Foundation::CloseHandle(h);
                    return Err(AppError::Internal("找不到目标模块".into()));
                }
            };

            let (text_base, text_size) = locate_text(h, m.base, m.size);
            let module_base = m.base;
            let module_end = m.base + m.size;

            // 分块读 .text(1 MB / chunk)
            const CHUNK: u64 = 1024 * 1024;
            let mut refs_map: HashMap<u64, (u32, u32, u32, Vec<u64>)> = HashMap::new(); // target → (lea, mov, call, samples<=3)
            let mut rip_refs_total = 0u32;
            let mut bytes_decoded = 0u64;

            let mut off: u64 = 0;
            let mut last_emit = std::time::Instant::now();
            while off < text_size {
                let take = (text_size - off).min(CHUNK) as usize;
                let mut buf = vec![0u8; take];
                let mut got = 0usize;
                let ok = ReadProcessMemory(
                    h,
                    (text_base + off) as *const c_void,
                    buf.as_mut_ptr() as *mut c_void,
                    take,
                    Some(&mut got),
                )
                .is_ok();
                if !ok || got < 16 { off += CHUNK; continue; }
                buf.truncate(got);

                let mut decoder = Decoder::with_ip(64, &buf, text_base + off, DecoderOptions::NONE);
                let mut insn = Instruction::default();
                while decoder.can_decode() {
                    decoder.decode_out(&mut insn);
                    if insn.is_invalid() { continue; }
                    // 检查每个操作数是否有 RIP-rel 目标
                    let mut target: Option<u64> = None;
                    let mut kind_lea = false;
                    let mut kind_mov = false;
                    let mut kind_call = false;

                    // is_ip_rel_memory_operand 在 iced 是基于内存操作数的判定
                    if insn.is_ip_rel_memory_operand() {
                        let t = insn.ip_rel_memory_address();
                        target = Some(t);
                        // 区分指令类型 — 基于 mnemonic 字符串简单分流
                        let mnem = format!("{:?}", insn.mnemonic()).to_lowercase();
                        if mnem.contains("lea") { kind_lea = true; }
                        else if mnem.contains("mov") { kind_mov = true; }
                        else if mnem.contains("call") || mnem.contains("jmp") { kind_call = true; }
                        else {
                            // 其它类型(ADD/SUB/CMP/TEST 等访问全局变量)也算 MOV 类
                            kind_mov = true;
                        }
                    }

                    // 跳转/call 直接 immediate (E8/E9 near rel32) 也是 RIP-rel,
                    // 但目标是代码,不是数据,跳过(避免污染候选)。
                    // 这里 is_ip_rel_memory_operand 已经只捕捉 [rip+disp] 内存操作数。

                    if let Some(t) = target {
                        // 过滤太小 / 太大的 target
                        if t < 0x10000 || t > 0x7FFF_FFFFFFFF { continue; }
                        let entry = refs_map.entry(t).or_insert((0, 0, 0, Vec::new()));
                        if kind_lea { entry.0 += 1; }
                        else if kind_mov { entry.1 += 1; }
                        else if kind_call { entry.2 += 1; }
                        if entry.3.len() < 3 {
                            entry.3.push(insn.ip());
                        }
                        rip_refs_total += 1;
                    }
                }
                bytes_decoded += got as u64;
                off += CHUNK;

                let now = std::time::Instant::now();
                if now.duration_since(last_emit).as_millis() > 200 {
                    let pct = (off as f64 / text_size as f64 * 100.0).min(100.0);
                    let _ = app.emit("find_globals_progress", serde_json::json!({
                        "pct": pct,
                        "off": off,
                        "refs": rip_refs_total,
                        "uniq": refs_map.len(),
                    }));
                    last_emit = now;
                }
            }

            // 排序:lea + mov + call 总和 降序
            let mut sorted: Vec<(u64, u32, u32, u32, Vec<u64>)> = refs_map
                .into_iter()
                .map(|(addr, (lea, mov, call, samples))| (addr, lea, mov, call, samples))
                .collect();
            sorted.sort_by_key(|(_, l, m, c, _)| std::cmp::Reverse(l + m + c));

            // 取门槛以上、并读各候选地址处 8 字节
            let mut candidates = Vec::with_capacity(top_n);
            for (addr, lea, mov, call, samples) in sorted.into_iter().take(top_n * 4) {
                let refs = lea + mov + call;
                if refs < min_refs { break; }
                // 读 8 字节
                let mut v8 = [0u8; 8];
                let mut g = 0usize;
                let ok = ReadProcessMemory(
                    h,
                    addr as *const c_void,
                    v8.as_mut_ptr() as *mut c_void,
                    8,
                    Some(&mut g),
                )
                .is_ok();
                let at_value_hex = if ok && g == 8 {
                    format!("{:016x}", u64::from_le_bytes(v8))
                } else {
                    "????????????????".into()
                };
                let in_module = addr >= module_base && addr < module_end;
                candidates.push(GlobalCandidate {
                    address: addr,
                    refs,
                    lea_refs: lea,
                    mov_refs: mov,
                    at_value_hex,
                    sample_callers: samples,
                    in_module,
                });
                if candidates.len() >= top_n { break; }
            }

            let _ = app.emit("find_globals_progress", serde_json::json!({
                "pct": 100.0, "done": true, "uniq": candidates.len(), "refs": rip_refs_total,
            }));
            let _ = windows::Win32::Foundation::CloseHandle(h);

            Ok(FindGlobalsResult {
                candidates,
                text_base,
                text_size,
                bytes_decoded,
                rip_refs_total,
            })
        }
    })
    .await
    .map_err(|e| AppError::Internal(format!("spawn_blocking: {e}")))?
}
