//! 签名发现 + 验证工具 (P99). 设计给 AI 闭环用.
//!
//! sig_test:    给一条 pattern, 返命中数 + 命中地址 + 跟随 RIP 后的最终地址
//! sig_derive:  给一个已知地址, 自动从 disasm 提取 AOB (RIP-rel 部分打 ??)
//! sig_validate: 项目内已有签名跑一遍, 检查是否仍 unique + 落点正确

use std::ffi::c_void;
use std::sync::Arc;

use iced_x86::{Decoder, DecoderOptions, Instruction, OpKind};
use serde::{Deserialize, Serialize};
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;

use crate::commands::aob_scan::{AobScanReq, dbg_aob_scan};
use crate::commands::pe_util::{enum_modules, open_for_read, pick_module};
use crate::commands::sig_store::{SignatureStore, mark_tested};
use crate::util::error::{AppError, AppResult};

#[derive(Debug, Deserialize)]
pub struct SigTestReq {
    pub pid: u32,
    pub pattern: String,
    pub follow_rip: bool,
    /// 0=all / 1=module / 2=range
    pub scope: u8,
    pub module_name: Option<String>,
    pub addr_min: Option<u64>,
    pub addr_max: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct SigHit {
    /// 命中点 (pattern 第一个字节的地址)
    pub at: u64,
    /// follow_rip 后的目标地址 (None = 解算失败或未启用)
    pub target: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct SigTestResp {
    pub hits: Vec<SigHit>,
    pub total_hits: u32,
    pub unique_target: Option<u64>,  // 所有命中的 target 都一样时填
    pub bytes_scanned: u64,
}

/// 单次扫. 命中后若 follow_rip, 在每个命中地址尝试 disasm 1 条指令找它的 RIP-rel 操作数 / near branch.
#[tauri::command]
pub async fn sig_test(app: tauri::AppHandle, req: SigTestReq) -> AppResult<SigTestResp> {
    let r = dbg_aob_scan(app, AobScanReq {
        pid: req.pid,
        pattern: req.pattern.clone(),
        scope: req.scope,
        module_name: req.module_name.clone(),
        addr_min: req.addr_min,
        addr_max: req.addr_max,
        max_hits: Some(64),
    }).await?;

    let pid = req.pid;
    let follow_rip = req.follow_rip;
    let hits = tokio::task::spawn_blocking(move || -> Vec<SigHit> {
        let mut out: Vec<SigHit> = Vec::with_capacity(r.hits.len());
        if !follow_rip {
            for h in &r.hits { out.push(SigHit { at: h.address, target: None }); }
            return out;
        }
        unsafe {
            let h = match open_for_read(pid) { Ok(h) => h, Err(_) => return out };
            for hit in &r.hits {
                let t = follow_rip_at(h, hit.address);
                out.push(SigHit { at: hit.address, target: t });
            }
            let _ = windows::Win32::Foundation::CloseHandle(h);
        }
        out
    }).await.map_err(|e| AppError::Internal(format!("spawn: {e}")))?;

    let total_hits = hits.len() as u32;
    let unique_target = {
        let mut iter = hits.iter().filter_map(|h| h.target);
        match iter.next() {
            None => None,
            Some(t0) => {
                if iter.all(|t| t == t0) { Some(t0) } else { None }
            }
        }
    };
    Ok(SigTestResp {
        hits,
        total_hits,
        unique_target,
        bytes_scanned: r.bytes_scanned as u64,
    })
}

/// 在 addr 处读 16 字节解码一条指令, 提它的 RIP-rel 操作数 / near branch target.
unsafe fn follow_rip_at(h: windows::Win32::Foundation::HANDLE, addr: u64) -> Option<u64> {
    let mut buf = [0u8; 16];
    let mut got = 0usize;
    if ReadProcessMemory(h, addr as *const c_void, buf.as_mut_ptr() as *mut c_void, 16, Some(&mut got)).is_err() {
        return None;
    }
    if got < 4 { return None; }
    let mut dec = Decoder::with_ip(64, &buf[..got], addr, DecoderOptions::NONE);
    if !dec.can_decode() { return None; }
    let mut insn = Instruction::default();
    dec.decode_out(&mut insn);
    if insn.is_invalid() { return None; }
    if insn.is_ip_rel_memory_operand() {
        return Some(insn.ip_rel_memory_address());
    }
    let near = insn.near_branch_target();
    if near != 0 { return Some(near); }
    // imm64 (mov r64, imm64) 也尝试
    for i in 0..insn.op_count() {
        if matches!(insn.op_kind(i), OpKind::Immediate64) {
            let v = insn.immediate64();
            if v > 0x10000 && v < 0x7FFF_FFFFFFFF { return Some(v); }
        }
    }
    None
}

// ===== sig_derive: 从已知地址逆推 AOB =====

#[derive(Debug, Deserialize)]
pub struct SigDeriveReq {
    pub pid: u32,
    /// 已知"特征点"地址 — 即 pattern 的起始位置
    pub address: u64,
    /// 抽多少字节生成 pattern. 默认 16. 8..48.
    pub length: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct SigDeriveResp {
    pub address: u64,
    pub pattern: String,
    pub bytes_hex: String,
    pub mask_explanation: String,
    /// 如果第一条指令是 RIP-rel, 给出推算的 target — 验证用
    pub follow_rip_target: Option<u64>,
}

/// 从 address 读 N 字节, disasm 流, 对每条指令的 RIP-rel disp32 / near jcc rel32 / call rel32
/// 自动打 4 个 ??. 其余字节保留原 hex.
#[tauri::command]
pub async fn sig_derive(req: SigDeriveReq) -> AppResult<SigDeriveResp> {
    let pid = req.pid;
    let address = req.address;
    let length = req.length.unwrap_or(16).clamp(8, 48) as usize;
    tokio::task::spawn_blocking(move || -> AppResult<SigDeriveResp> {
        unsafe {
            let h = open_for_read(pid)?;
            let mut buf = vec![0u8; length];
            let mut got = 0usize;
            let ok = ReadProcessMemory(
                h, address as *const c_void,
                buf.as_mut_ptr() as *mut c_void, length, Some(&mut got)
            ).is_ok();
            let _ = windows::Win32::Foundation::CloseHandle(h);
            if !ok || got < 4 {
                return Err(AppError::Internal(format!("RPM 0x{:x} 失败 / 字节数太少", address)));
            }
            buf.truncate(got);

            // disasm 流, 标记每条指令的 disp32 / rel32 偏移
            let mut mask = vec![false; buf.len()];
            let mut dec = Decoder::with_ip(64, &buf, address, DecoderOptions::NONE);
            let mut explain = String::new();
            let mut follow_target: Option<u64> = None;
            while dec.can_decode() {
                let mut insn = Instruction::default();
                let before_pos = dec.position();
                dec.decode_out(&mut insn);
                if insn.is_invalid() {
                    // 全标 ?? 这一条
                    let after = dec.position();
                    for i in before_pos..after { mask.get_mut(i).map(|b| *b = true); }
                    continue;
                }
                let insn_len = insn.len();
                let after = before_pos + insn_len;
                if after > buf.len() { break; }

                // RIP-rel mem 操作数 → 末尾 4 字节
                if insn.is_ip_rel_memory_operand() {
                    if follow_target.is_none() { follow_target = Some(insn.ip_rel_memory_address()); }
                    let start = after.saturating_sub(4);
                    for i in start..after { mask.get_mut(i).map(|b| *b = true); }
                    explain.push_str(&format!(
                        "  · 0x{:x}: {} → disp32 末 4 字节 → 0x{:x}\n",
                        insn.ip(), insn, insn.ip_rel_memory_address()
                    ));
                }
                // 近跳 (E8/E9/0F8x/JMP rel32) → 末尾 4 字节
                else if insn.near_branch_target() != 0 {
                    if follow_target.is_none() { follow_target = Some(insn.near_branch_target()); }
                    let start = after.saturating_sub(4);
                    for i in start..after { mask.get_mut(i).map(|b| *b = true); }
                    explain.push_str(&format!(
                        "  · 0x{:x}: {} → rel32 末 4 字节 → 0x{:x}\n",
                        insn.ip(), insn, insn.near_branch_target()
                    ));
                }
                // imm64 不打 ?? — 它通常是常数, 部分情况是地址但留着字节也能匹配
            }

            // 构造 pattern 字符串
            let pattern: String = buf.iter().enumerate().map(|(i, b)| {
                if mask[i] { "??".to_string() } else { format!("{:02X}", b) }
            }).collect::<Vec<_>>().join(" ");

            let bytes_hex: String = buf.iter().map(|b| format!("{:02x}", b)).collect();
            let mask_count = mask.iter().filter(|b| **b).count();
            let mut full_explain = format!(
                "字节 {}, 通配 {}/{}.\n{}",
                buf.len(), mask_count, buf.len(), explain
            );
            if mask_count == 0 {
                full_explain.push_str("⚠ 0 通配 — 此 pattern 可能包含编译期常量但无相对地址, 重新引用时可能 false positive.");
            }
            if buf.len() - mask_count < 6 {
                full_explain.push_str("⚠ 非通配字节 < 6, 唯一性可能不足. 建议加长 length.");
            }

            Ok(SigDeriveResp {
                address,
                pattern,
                bytes_hex,
                mask_explanation: full_explain,
                follow_rip_target: follow_target,
            })
        }
    })
    .await
    .map_err(|e| AppError::Internal(format!("spawn_blocking: {e}")))?
}

// ===== sig_validate: 跑某个/全部 stored sig, 看是否仍命中 =====

#[derive(Debug, Deserialize)]
pub struct SigValidateReq {
    pub pid: u32,
    /// 指定 id; None = 全跑
    pub sig_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SigValidationResult {
    pub id: String,
    pub name: String,
    pub status: &'static str,  // "ok_unique" / "multiple_hits" / "miss" / "drift" / "error"
    pub hits: u32,
    pub target: Option<u64>,
    pub previous_target: Option<u64>,
    pub note: String,
}

#[derive(Debug, Serialize)]
pub struct SigValidateResp {
    pub tested: u32,
    pub results: Vec<SigValidationResult>,
}

#[tauri::command]
pub async fn sig_validate(
    app: tauri::AppHandle,
    store: tauri::State<'_, Arc<SignatureStore>>,
    req: SigValidateReq,
) -> AppResult<SigValidateResp> {
    let store = store.inner().clone();
    let all_sigs = if let Some(id) = req.sig_id.as_ref() {
        match store.get(id) { Some(s) => vec![s], None => return Err(AppError::Internal(format!("未知签名 {id}"))) }
    } else {
        store.list()
    };
    // 解析 scope → AobScanReq fields
    let pid = req.pid;
    let mut results: Vec<SigValidationResult> = Vec::with_capacity(all_sigs.len());
    for sig in &all_sigs {
        let (scope, module_name, addr_min, addr_max) = parse_scope(&sig.scope);
        let test_req = SigTestReq {
            pid,
            pattern: sig.pattern.clone(),
            follow_rip: sig.follow_rip,
            scope, module_name, addr_min, addr_max,
        };
        let res = sig_test(app.clone(), test_req).await;
        let mut entry = SigValidationResult {
            id: sig.id.clone(),
            name: sig.name.clone(),
            status: "error",
            hits: 0,
            target: None,
            previous_target: sig.last_addr,
            note: String::new(),
        };
        match res {
            Ok(r) => {
                entry.hits = r.total_hits;
                entry.target = r.unique_target;
                entry.status = if r.total_hits == 0 {
                    entry.note = "0 命中 — 签名失效, 用 find_globals / 改 pattern 重新发现".into();
                    "miss"
                } else if r.total_hits > 1 && r.unique_target.is_none() {
                    entry.note = format!("{} 命中但 RIP 目标不唯一 — 加长 pattern 缩窄", r.total_hits);
                    "multiple_hits"
                } else if let Some(prev) = sig.last_addr {
                    if let Some(now) = r.unique_target {
                        if now == prev {
                            entry.note = "命中地址 = 上次记录".into();
                            "ok_unique"
                        } else {
                            entry.note = format!("命中变了: 0x{:x} → 0x{:x} (游戏重启或更新)", prev, now);
                            "drift"
                        }
                    } else { "miss" }
                } else {
                    entry.note = "首次命中".into();
                    "ok_unique"
                };
                // 落地 last_addr / last_tested_at
                mark_tested(&store, &sig.id, r.unique_target);
            }
            Err(e) => {
                entry.note = format!("扫描失败: {e}");
            }
        }
        results.push(entry);
    }
    let tested = results.len() as u32;
    Ok(SigValidateResp { tested, results })
}

fn parse_scope(scope: &str) -> (u8, Option<String>, Option<u64>, Option<u64>) {
    let s = scope.trim();
    if s == "main_module" {
        (1, None, None, None) // module_name=None 走 main exe (aob_scan 自己选)
    } else if let Some(m) = s.strip_prefix("specific_module:") {
        (1, Some(m.trim().to_string()), None, None)
    } else if s == "all" || s.is_empty() {
        (0, None, None, None)
    } else {
        (0, None, None, None)
    }
}

// ===== sig_test_in_main_module 便捷壳 — AI 调时 90% 是这个场景 =====

#[derive(Debug, Deserialize)]
pub struct SigSuggestReq {
    pub pid: u32,
    pub pattern: String,
    pub follow_rip: bool,
    pub module_name: Option<String>,
}

#[tauri::command]
pub async fn sig_quick_test(app: tauri::AppHandle, req: SigSuggestReq) -> AppResult<SigTestResp> {
    let module_name = req.module_name.clone();
    let scope = if module_name.is_some() { 1u8 } else { 1u8 };
    sig_test(app, SigTestReq {
        pid: req.pid,
        pattern: req.pattern,
        follow_rip: req.follow_rip,
        scope,
        module_name,
        addr_min: None,
        addr_max: None,
    }).await
}

// ===== 文本工具:看模块当前 main exe (AI 想给 target_exe 字段时用) =====
#[tauri::command]
pub fn sig_main_exe(pid: u32) -> AppResult<Option<String>> {
    unsafe {
        let _h = open_for_read(pid)?;
        let mods = enum_modules(pid);
        let m = pick_module(&mods, None);
        let _ = (&_h,);
        Ok(m.map(|m| m.name.clone()))
    }
}
