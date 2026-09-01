//! AOB 特征扫描 (P66) — Array of Bytes
//!
//! 输入: "48 8B 05 ?? ?? ?? ?? 4C 8B 25" (CE / IDA 风格 hex + ?? wildcard)
//! 范围: 全部 commit + 可读 / 单个模块 / 自定义 [min, max]
//! 输出: 全部命中地址 + 每条的 RIP-relative 解算结果(LEA/MOV reg, [rip+disp32] → 真实地址)

use std::ffi::c_void;

use tauri::{AppHandle, Emitter};

use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, MODULEENTRY32W,
    TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32,
};
use windows::Win32::System::Memory::{
    VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, PAGE_GUARD, PAGE_NOACCESS,
};
use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};

use crate::util::error::{AppError, AppResult};

#[derive(Debug, Clone, serde::Serialize)]
pub struct AobHit {
    /// 命中起始地址
    pub address: u64,
    /// 如果可解析 RIP-relative(0x48 0x8B 0x05 disp32 / 0x4C 0x8D 0x05 disp32),返回最终目标地址
    pub rip_target: Option<u64>,
    /// 落在哪个模块(若有)
    pub module: Option<String>,
    /// 模块内偏移
    pub rva: Option<u64>,
}

#[derive(Debug, serde::Serialize)]
pub struct AobScanResult {
    pub hits: Vec<AobHit>,
    pub regions_scanned: u32,
    pub bytes_scanned: u64,
    pub truncated: bool,
}

#[derive(serde::Deserialize)]
pub struct AobScanReq {
    pub pid: u32,
    pub pattern: String,
    /// 0 = 全空间, 1 = 单模块(name), 2 = 自定义范围
    pub scope: u8,
    pub module_name: Option<String>,
    pub addr_min: Option<u64>,
    pub addr_max: Option<u64>,
    pub max_hits: Option<u32>,
}

fn parse_pattern(p: &str) -> Result<Vec<Option<u8>>, String> {
    let mut out = vec![];
    for raw in p.split_whitespace() {
        let tok = raw.trim_matches(|c: char| c == ',' || c.is_whitespace());
        if tok.is_empty() { continue; }
        // 支持 "??" 或 "?" 通配
        if tok == "?" || tok == "??" || tok == "*" {
            out.push(None);
            continue;
        }
        // "0x" 前缀
        let t = tok.trim_start_matches("0x").trim_start_matches("0X");
        if t.len() != 2 {
            return Err(format!("非法 token: {}", raw));
        }
        let b = u8::from_str_radix(t, 16).map_err(|_| format!("非 hex: {}", raw))?;
        out.push(Some(b));
    }
    if out.is_empty() { return Err("特征为空".into()); }
    Ok(out)
}

unsafe fn open_for_read(pid: u32) -> AppResult<HANDLE> {
    OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, pid)
        .map_err(|e| AppError::Internal(format!("OpenProcess({pid}): {e}")))
}

struct ModInfo {
    base: u64,
    size: u64,
    name: String,
}

unsafe fn snapshot_modules(pid: u32) -> Vec<ModInfo> {
    let snap = match CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid) {
        Ok(s) => s,
        Err(_) => return vec![],
    };
    let mut me: MODULEENTRY32W = std::mem::zeroed();
    me.dwSize = std::mem::size_of::<MODULEENTRY32W>() as u32;
    let mut out = vec![];
    if Module32FirstW(snap, &mut me).is_ok() {
        loop {
            let name_end = me.szModule.iter().position(|&c| c == 0).unwrap_or(me.szModule.len());
            let name = String::from_utf16_lossy(&me.szModule[..name_end]);
            out.push(ModInfo {
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
    out
}

fn module_of(addr: u64, mods: &[ModInfo]) -> Option<(&ModInfo, u64)> {
    for m in mods {
        if addr >= m.base && addr < m.base + m.size {
            return Some((m, addr - m.base));
        }
    }
    None
}

/// 解析常见 RIP-relative 指令:LEA reg,[rip+disp32] / MOV reg,[rip+disp32]
/// 命中地址处的指令应以以下字节序列开头:
///   48 8D 0D / 15 / 1D / 25 / 2D / 35 / 3D ... (LEA r64, [RIP+disp32])
///   48 8B 0D / 15 / 1D / 25 / 2D / 35 / 3D ... (MOV r64, [RIP+disp32])
///   4C 8D / 4C 8B (R8-R15 版本)
/// 偏移在指令末尾后 4 字节, target = hit + 7 + disp32(signed)
fn try_rip_target(bytes: &[u8], hit_abs: u64) -> Option<u64> {
    if bytes.len() < 7 { return None; }
    let rex = bytes[0];
    let op  = bytes[1];
    let modrm = bytes[2];
    // REX.W 必须置位 (0x48 / 0x4C)
    if rex != 0x48 && rex != 0x4C { return None; }
    // op 必须是 LEA(8D) 或 MOV r64,r/m64 (8B)
    if op != 0x8D && op != 0x8B { return None; }
    // mod=00, r/m=101 (RIP-relative) → mod==00 且 (modrm & 7)==5
    if modrm & 0xC7 == 0x05 || (modrm & 0xC7) == 0x05 {
        let disp32 = i32::from_le_bytes([bytes[3], bytes[4], bytes[5], bytes[6]]) as i64;
        let target = hit_abs.wrapping_add(7).wrapping_add(disp32 as u64);
        return Some(target);
    }
    None
}

#[tauri::command]
pub async fn dbg_aob_scan(app: AppHandle, req: AobScanReq) -> AppResult<AobScanResult> {
    let pat = parse_pattern(&req.pattern).map_err(AppError::Internal)?;
    let max_hits = req.max_hits.unwrap_or(5000).max(1) as usize;

    tokio::task::spawn_blocking(move || -> AppResult<AobScanResult> {
        unsafe {
            let h = open_for_read(req.pid)?;
            let mods = snapshot_modules(req.pid);

            // 决定扫描范围
            let (mut addr, max_addr): (u64, u64) = match req.scope {
                1 => {
                    let mn = req.module_name.as_deref().unwrap_or("").to_lowercase();
                    let m = mods.iter().find(|m| m.name.to_lowercase() == mn);
                    match m {
                        Some(m) => (m.base, m.base + m.size),
                        None => return Err(AppError::Internal(format!("模块未找到: {}", mn))),
                    }
                }
                2 => (req.addr_min.unwrap_or(0), req.addr_max.unwrap_or(0x7FFF_FFFFFFFF)),
                _ => (0, 0x7FFF_FFFFFFFF),
            };

            let mut hits = Vec::new();
            let mut truncated = false;
            let mut regions = 0u32;
            let mut bytes_scanned: u64 = 0;
            let plen = pat.len();
            let start = addr;
            let span = (max_addr - start).max(1) as f64;
            let mut last_emit = std::time::Instant::now();

            while addr < max_addr {
                let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
                if VirtualQueryEx(
                    h,
                    Some(addr as *const c_void),
                    &mut mbi,
                    std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                ) == 0
                {
                    break;
                }
                let next = (mbi.BaseAddress as u64).saturating_add(mbi.RegionSize as u64);
                if next <= addr { break; }
                addr = next;

                let usable = mbi.State == MEM_COMMIT
                    && (mbi.Protect.0 & PAGE_NOACCESS.0) == 0
                    && (mbi.Protect.0 & PAGE_GUARD.0) == 0;
                if !usable { continue; }
                regions += 1;

                let base = mbi.BaseAddress as u64;
                let size = mbi.RegionSize as u64;
                const CHUNK: u64 = 0x100000;
                let mut buf = vec![0u8; CHUNK as usize];
                let mut off = 0u64;
                while off < size {
                    let take = (size - off).min(CHUNK) as usize;
                    if take < plen { break; }
                    let mut got = 0usize;
                    let ok = ReadProcessMemory(
                        h,
                        (base + off) as *const c_void,
                        buf.as_mut_ptr() as *mut c_void,
                        take,
                        Some(&mut got),
                    )
                    .is_ok();
                    if ok && got >= plen {
                        bytes_scanned += got as u64;
                        // 朴素 sliding match — 对 10-30 字节特征足够快
                        let end = got - plen;
                        let mut i = 0usize;
                        while i <= end {
                            let mut ok2 = true;
                            for (k, p) in pat.iter().enumerate() {
                                if let Some(b) = p {
                                    if buf[i + k] != *b { ok2 = false; break; }
                                }
                            }
                            if ok2 {
                                let hit_abs = base + off + i as u64;
                                let rip_target = try_rip_target(&buf[i..i + plen.min(7)], hit_abs);
                                let (mname, rva) = match module_of(hit_abs, &mods) {
                                    Some((m, rva)) => (Some(m.name.clone()), Some(rva)),
                                    None => (None, None),
                                };
                                hits.push(AobHit {
                                    address: hit_abs,
                                    rip_target,
                                    module: mname,
                                    rva,
                                });
                                if hits.len() >= max_hits {
                                    truncated = true;
                                    let _ = windows::Win32::Foundation::CloseHandle(h);
                                    return Ok(AobScanResult { hits, regions_scanned: regions, bytes_scanned, truncated });
                                }
                            }
                            i += 1;
                        }
                    }
                    off += CHUNK;

                    // 进度
                    let now = std::time::Instant::now();
                    if now.duration_since(last_emit).as_millis() > 150 {
                        let pct = ((addr - start) as f64 / span * 100.0).min(100.0);
                        let _ = app.emit("aob_progress", serde_json::json!({
                            "pct": pct,
                            "addr": addr,
                            "hits": hits.len(),
                        }));
                        last_emit = now;
                    }
                }
            }
            let _ = app.emit("aob_progress", serde_json::json!({
                "pct": 100.0, "addr": addr, "hits": hits.len(), "done": true
            }));
            let _ = windows::Win32::Foundation::CloseHandle(h);
            Ok(AobScanResult { hits, regions_scanned: regions, bytes_scanned, truncated })
        }
    })
    .await
    .map_err(|e| AppError::Internal(format!("spawn_blocking: {e}")))?
}
