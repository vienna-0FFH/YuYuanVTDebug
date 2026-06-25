//! 交叉引用 (P91): xref_to / xref_from
//!
//! xref_to(pid, target):  扫一个模块 .text, 找所有 RIP-rel call/jmp/lea/mov 指向 target
//! xref_from(pid, source): 单条指令解码, 看它引用什么地址
//!
//! 大模块全扫 ~3-4 秒. 后续可加缓存(按模块基址 hash).

use std::ffi::c_void;

use iced_x86::{Decoder, DecoderOptions, Instruction};
use serde::{Deserialize, Serialize};
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;

use crate::commands::pe_util::{enum_modules, locate_text, open_for_read, pick_module};
use crate::util::error::{AppError, AppResult};

#[derive(Debug, Serialize)]
pub struct XrefHit {
    pub source: u64,        // 引用点指令地址
    pub kind: &'static str, // "call" / "jmp" / "lea" / "mov" / "other"
    pub mnemonic: String,
    pub target: u64,        // = req.target
    pub source_module_offset: u64,  // source - module_base
}

#[derive(Debug, Deserialize)]
pub struct XrefToReq {
    pub pid: u32,
    pub target: u64,
    pub module_name: Option<String>,
    pub max_hits: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct XrefToResult {
    pub module: String,
    pub module_base: u64,
    pub text_base: u64,
    pub text_size: u64,
    pub hits: Vec<XrefHit>,
    pub total_hits: u32,
    pub bytes_decoded: u64,
}

#[tauri::command]
pub async fn dbg_xref_to(req: XrefToReq) -> AppResult<XrefToResult> {
    let pid = req.pid;
    let target = req.target;
    let max_hits = req.max_hits.unwrap_or(256).max(1) as usize;
    let want = req.module_name;

    tokio::task::spawn_blocking(move || -> AppResult<XrefToResult> {
        unsafe {
            let h = open_for_read(pid)?;
            let mods = enum_modules(pid);
            let m = pick_module(&mods, want.as_deref())
                .ok_or_else(|| AppError::Internal("找不到模块".into()))?;
            let (text_base, text_size) = locate_text(h, m.base, m.size);

            const CHUNK: u64 = 1024 * 1024;
            let mut hits = Vec::with_capacity(max_hits);
            let mut total_hits = 0u32;
            let mut bytes_decoded = 0u64;
            let mut off = 0u64;
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
                ).is_ok();
                if !ok || got < 16 { off += CHUNK; continue; }
                buf.truncate(got);
                bytes_decoded += got as u64;
                let mut decoder = Decoder::with_ip(64, &buf, text_base + off, DecoderOptions::NONE);
                let mut insn = Instruction::default();
                while decoder.can_decode() {
                    decoder.decode_out(&mut insn);
                    if insn.is_invalid() { continue; }
                    let mut tgt: Option<u64> = None;
                    // RIP-rel memory operand
                    if insn.is_ip_rel_memory_operand() {
                        tgt = Some(insn.ip_rel_memory_address());
                    }
                    // call/jmp near rel32 (E8/E9/JCC)
                    if tgt.is_none() {
                        let near = insn.near_branch_target();
                        if near != 0 { tgt = Some(near); }
                    }
                    if tgt == Some(target) {
                        total_hits += 1;
                        if hits.len() < max_hits {
                            let mnem = format!("{:?}", insn.mnemonic()).to_lowercase();
                            let kind: &'static str =
                                if mnem.contains("call") { "call" }
                                else if mnem.contains("jmp") || mnem.starts_with("j") { "jmp" }
                                else if mnem.contains("lea") { "lea" }
                                else if mnem.contains("mov") { "mov" }
                                else { "other" };
                            hits.push(XrefHit {
                                source: insn.ip(),
                                kind,
                                mnemonic: mnem,
                                target,
                                source_module_offset: insn.ip().saturating_sub(m.base),
                            });
                        }
                    }
                }
                off += CHUNK;
            }
            let _ = windows::Win32::Foundation::CloseHandle(h);
            Ok(XrefToResult {
                module: m.name.clone(),
                module_base: m.base,
                text_base,
                text_size,
                hits,
                total_hits,
                bytes_decoded,
            })
        }
    })
    .await
    .map_err(|e| AppError::Internal(format!("spawn_blocking: {e}")))?
}

// ===== xref_from =====
//
// 单条指令的引用 — 不用扫整个 .text. 给一个 source 地址, 读 ~16 字节, 解码 1 条,
// 看它有没有 RIP-rel / near branch / immediate.

#[derive(Debug, Deserialize)]
pub struct XrefFromReq {
    pub pid: u32,
    pub source: u64,
}

#[derive(Debug, Serialize)]
pub struct XrefFromResult {
    pub source: u64,
    pub instruction: String,
    pub bytes_hex: String,
    pub length: u32,
    pub references: Vec<XrefRef>,
}

#[derive(Debug, Serialize)]
pub struct XrefRef {
    pub kind: &'static str,
    pub target: u64,
}

#[tauri::command]
pub async fn dbg_xref_from(req: XrefFromReq) -> AppResult<XrefFromResult> {
    let pid = req.pid;
    let source = req.source;
    tokio::task::spawn_blocking(move || -> AppResult<XrefFromResult> {
        unsafe {
            let h = open_for_read(pid)?;
            let mut buf = [0u8; 16];
            let mut got = 0usize;
            let ok = ReadProcessMemory(h, source as *const c_void, buf.as_mut_ptr() as *mut c_void, 16, Some(&mut got)).is_ok();
            let _ = windows::Win32::Foundation::CloseHandle(h);
            if !ok || got == 0 {
                return Err(AppError::Internal(format!("无法读取 0x{:x}", source)));
            }
            let mut decoder = Decoder::with_ip(64, &buf[..got], source, DecoderOptions::NONE);
            if !decoder.can_decode() {
                return Err(AppError::Internal("无法解码该地址".into()));
            }
            let mut insn = Instruction::default();
            decoder.decode_out(&mut insn);
            if insn.is_invalid() {
                return Err(AppError::Internal("非法指令".into()));
            }
            let len = insn.len() as u32;
            let bytes_hex: String = buf[..len as usize].iter().map(|b| format!("{:02x}", b)).collect();
            let mut refs = Vec::new();
            if insn.is_ip_rel_memory_operand() {
                refs.push(XrefRef { kind: "rip_rel_mem", target: insn.ip_rel_memory_address() });
            }
            let near = insn.near_branch_target();
            if near != 0 {
                refs.push(XrefRef { kind: "branch", target: near });
            }
            // immediate 可能是地址 (mov imm64, push imm 等)
            for i in 0..insn.op_count() {
                if matches!(insn.op_kind(i), iced_x86::OpKind::Immediate64) {
                    let v = insn.immediate64();
                    if v > 0x10000 && v < 0x7FFF_FFFFFFFF {
                        refs.push(XrefRef { kind: "imm64", target: v });
                    }
                }
            }
            Ok(XrefFromResult {
                source,
                instruction: format!("{}", insn),
                bytes_hex,
                length: len,
                references: refs,
            })
        }
    })
    .await
    .map_err(|e| AppError::Internal(format!("spawn_blocking: {e}")))?
}
