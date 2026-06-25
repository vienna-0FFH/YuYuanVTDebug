//! Assembler (P54 + P61)
//!
//! 用 iced-x86 的 CodeAssembler fluent API + 手写小型 Intel 风格解析器,支持:
//!   无操作数:   nop ret retn int3 ud2 cli sti hlt
//!   单操作数:   push reg/imm   pop reg   call imm/reg   jmp imm/reg
//!   单条件跳:  je/jne/jz/jnz/jg/jl/jge/jle/ja/jb/jae/jbe   imm
//!   双操作数:   mov/add/sub/xor/and/or/cmp/test reg, reg|imm|[mem]
//!                              [mem], reg|imm
//!                              reg, [mem]
//!   寄存器: rax..r15 / eax..r15d / ax..r15w / al..r15b
//!   立即数: 十进制 / 0xHEX / 'A' 单字节字符
//!   内存:   [reg] [reg+disp] [reg+reg*N+disp]  (N=1/2/4/8)
//!
//! 跳转/调用如果是绝对地址(立即数 > 2^32),iced 自动选择长跳/间接;否则用相对跳。
//! 复杂指令(SIMD/REX 控制)请用 Lua write_bytes 拼字节。

use std::collections::HashMap;
use std::ffi::c_void;

use windows::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
use windows::Win32::System::Memory::{
    VirtualProtectEx, PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS,
};
use windows::Win32::System::Threading::{
    OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_READ,
    PROCESS_VM_WRITE,
};

use iced_x86::code_asm::{
    AsmRegister64, AsmRegister32, AsmRegister16, AsmRegister8,
    AsmMemoryOperand, CodeAssembler, CodeLabel,
};
use iced_x86::code_asm::registers::*;
// 通配 import 寄存器常量;函数名 (mov/push 等) 通过 a.method() 调用,不需要 import

use crate::util::error::{AppError, AppResult};

#[derive(Debug, serde::Serialize)]
pub struct AsmResult {
    pub bytes: Vec<u8>,
    pub original: Vec<u8>,
    pub size: u32,
}

#[tauri::command]
pub async fn dbg_assemble_patch(
    pid: u32,
    address: u64,
    source: String,
    apply: bool,
) -> AppResult<AsmResult> {
    tokio::task::spawn_blocking(move || -> AppResult<AsmResult> {
        let bytes = assemble_x64(&source, address)?;
        let mut original = vec![0u8; bytes.len()];

        unsafe {
            let h = OpenProcess(
                PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION,
                false,
                pid,
            )
            .map_err(|e| AppError::Internal(format!("OpenProcess: {e}")))?;
            let mut got = 0usize;
            let _ = ReadProcessMemory(
                h,
                address as *const c_void,
                original.as_mut_ptr() as *mut c_void,
                bytes.len(),
                Some(&mut got),
            );
            original.truncate(got);

            if apply {
                let mut old: PAGE_PROTECTION_FLAGS = std::mem::zeroed();
                let _ = VirtualProtectEx(
                    h,
                    address as *const c_void,
                    bytes.len(),
                    PAGE_EXECUTE_READWRITE,
                    &mut old,
                );
                let mut wrote = 0usize;
                let ok = WriteProcessMemory(
                    h,
                    address as *const c_void,
                    bytes.as_ptr() as *const c_void,
                    bytes.len(),
                    Some(&mut wrote),
                )
                .is_ok();
                let mut _x: PAGE_PROTECTION_FLAGS = std::mem::zeroed();
                let _ = VirtualProtectEx(h, address as *const c_void, bytes.len(), old, &mut _x);
                let _ = windows::Win32::Foundation::CloseHandle(h);
                if !ok || wrote != bytes.len() {
                    return Err(AppError::Internal(format!("Write partial: {}/{}", wrote, bytes.len())));
                }
            } else {
                let _ = windows::Win32::Foundation::CloseHandle(h);
            }
        }

        let size = bytes.len() as u32;
        Ok(AsmResult { bytes, original, size })
    })
    .await
    .map_err(|e| AppError::Internal(format!("spawn_blocking: {e}")))?
}

// ============================================================
// 解析 + 编码
// ============================================================

#[derive(Debug, Clone)]
enum Operand {
    Reg64(AsmRegister64),
    Reg32(AsmRegister32),
    Reg16(AsmRegister16),
    Reg8(AsmRegister8),
    Imm(i64),
    Mem(AsmMemoryOperand),
}

fn parse_reg64(s: &str) -> Option<AsmRegister64> {
    match s {
        "rax" => Some(rax), "rbx" => Some(rbx), "rcx" => Some(rcx), "rdx" => Some(rdx),
        "rsi" => Some(rsi), "rdi" => Some(rdi), "rbp" => Some(rbp), "rsp" => Some(rsp),
        "r8" => Some(r8), "r9" => Some(r9), "r10" => Some(r10), "r11" => Some(r11),
        "r12" => Some(r12), "r13" => Some(r13), "r14" => Some(r14), "r15" => Some(r15),
        _ => None,
    }
}
fn parse_reg32(s: &str) -> Option<AsmRegister32> {
    match s {
        "eax" => Some(eax), "ebx" => Some(ebx), "ecx" => Some(ecx), "edx" => Some(edx),
        "esi" => Some(esi), "edi" => Some(edi), "ebp" => Some(ebp), "esp" => Some(esp),
        "r8d" => Some(r8d), "r9d" => Some(r9d), "r10d" => Some(r10d), "r11d" => Some(r11d),
        "r12d" => Some(r12d), "r13d" => Some(r13d), "r14d" => Some(r14d), "r15d" => Some(r15d),
        _ => None,
    }
}
fn parse_reg16(s: &str) -> Option<AsmRegister16> {
    match s {
        "ax" => Some(ax), "bx" => Some(bx), "cx" => Some(cx), "dx" => Some(dx),
        "si" => Some(si), "di" => Some(di), "bp" => Some(bp), "sp" => Some(sp),
        "r8w" => Some(r8w), "r9w" => Some(r9w), "r10w" => Some(r10w), "r11w" => Some(r11w),
        "r12w" => Some(r12w), "r13w" => Some(r13w), "r14w" => Some(r14w), "r15w" => Some(r15w),
        _ => None,
    }
}
fn parse_reg8(s: &str) -> Option<AsmRegister8> {
    match s {
        "al" => Some(al), "bl" => Some(bl), "cl" => Some(cl), "dl" => Some(dl),
        "sil" => Some(sil), "dil" => Some(dil), "bpl" => Some(bpl), "spl" => Some(spl),
        "ah" => Some(ah), "bh" => Some(bh), "ch" => Some(ch), "dh" => Some(dh),
        "r8b" => Some(r8b), "r9b" => Some(r9b), "r10b" => Some(r10b), "r11b" => Some(r11b),
        "r12b" => Some(r12b), "r13b" => Some(r13b), "r14b" => Some(r14b), "r15b" => Some(r15b),
        _ => None,
    }
}

fn parse_imm(s: &str) -> Option<i64> {
    let t = s.trim();
    if t.starts_with("0x") || t.starts_with("0X") {
        i64::from_str_radix(t.trim_start_matches("0x").trim_start_matches("0X"), 16).ok()
    } else if t.starts_with('-') {
        t.parse::<i64>().ok()
    } else if t.starts_with('\'') && t.ends_with('\'') && t.len() == 3 {
        let b = t.as_bytes()[1];
        Some(b as i64)
    } else if t.chars().all(|c| c.is_ascii_digit()) {
        t.parse::<i64>().ok()
    } else {
        i64::from_str_radix(t, 16).ok()
    }
}

fn mem_commit(
    cur: &mut String,
    sign: &mut i64,
    base: &mut Option<AsmRegister64>,
    index: &mut Option<(AsmRegister64, i32)>,
    disp: &mut i64,
) -> Result<(), String> {
    let tok = cur.trim().to_string();
    cur.clear();
    if tok.is_empty() { return Ok(()); }
    if let Some(p) = tok.find('*') {
        let r = tok[..p].trim();
        let s = tok[p + 1..].trim();
        let reg = parse_reg64(&r.to_lowercase()).ok_or_else(|| format!("非寄存器 {}", r))?;
        let scale: i32 = s.parse().map_err(|_| format!("非法 scale {}", s))?;
        if !matches!(scale, 1 | 2 | 4 | 8) {
            return Err(format!("scale 必须 1/2/4/8, got {}", scale));
        }
        *index = Some((reg, scale));
    } else if let Some(reg) = parse_reg64(&tok.to_lowercase()) {
        if base.is_none() {
            *base = Some(reg);
        } else if index.is_none() {
            *index = Some((reg, 1));
        } else {
            return Err("内存操作数 base/index 已满".into());
        }
    } else if let Some(v) = parse_imm(&tok) {
        *disp += *sign * v;
    } else {
        return Err(format!("无法解析 token: {}", tok));
    }
    *sign = 1;
    Ok(())
}

/// 解析 [reg+reg*N+disp] / [reg+disp] / [reg]
fn parse_mem(s: &str) -> Result<AsmMemoryOperand, String> {
    let inner = s.trim();
    if !inner.starts_with('[') || !inner.ends_with(']') {
        return Err("内存操作数必须 [...] 包围".into());
    }
    let body = &inner[1..inner.len() - 1];
    let mut base: Option<AsmRegister64> = None;
    let mut index: Option<(AsmRegister64, i32)> = None;
    let mut disp: i64 = 0;
    let mut sign: i64 = 1;
    let mut cur = String::new();
    for c in body.chars() {
        match c {
            '+' => { mem_commit(&mut cur, &mut sign, &mut base, &mut index, &mut disp)?; sign = 1; }
            '-' => { mem_commit(&mut cur, &mut sign, &mut base, &mut index, &mut disp)?; sign = -1; }
            ' ' | '\t' => { }
            _ => cur.push(c),
        }
    }
    mem_commit(&mut cur, &mut sign, &mut base, &mut index, &mut disp)?;

    let base = base.ok_or_else(|| "内存操作数缺 base".to_string())?;
    let mut m: AsmMemoryOperand = base + (disp as i32);
    if let Some((idx, scale)) = index {
        m = m + idx * scale;
    }
    Ok(m)
}

fn parse_operand(s: &str) -> Result<Operand, String> {
    let t = s.trim();
    let lo = t.to_lowercase();
    if let Some(r) = parse_reg64(&lo) { return Ok(Operand::Reg64(r)); }
    if let Some(r) = parse_reg32(&lo) { return Ok(Operand::Reg32(r)); }
    if let Some(r) = parse_reg16(&lo) { return Ok(Operand::Reg16(r)); }
    if let Some(r) = parse_reg8(&lo)  { return Ok(Operand::Reg8(r)); }
    if t.starts_with('[') { return parse_mem(t).map(Operand::Mem); }
    if let Some(v) = parse_imm(t) { return Ok(Operand::Imm(v)); }
    Err(format!("无法解析操作数: {}", t))
}

fn split_operands(s: &str) -> Vec<String> {
    // 按 ',' 分,但 [...] 内的 , 不算 — 我们的内存语法不用 , 所以简单 split 即可
    s.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect()
}

fn ie<E: std::fmt::Display>(e: E) -> AppError {
    AppError::Internal(format!("{}", e))
}

/// 主编译入口
fn assemble_x64(source: &str, ip: u64) -> AppResult<Vec<u8>> {
    let mut a = CodeAssembler::new(64).map_err(ie)?;
    // labels: 简单实现 — 用户写 `loop1:`,后续 jne loop1 跳到这
    let mut labels: HashMap<String, CodeLabel> = HashMap::new();

    for raw in source.lines() {
        let mut line = raw.trim().to_string();
        if let Some(c) = line.find(';') { line.truncate(c); }
        let line = line.trim().to_string();
        if line.is_empty() { continue; }

        // label: 行末冒号
        if let Some(stripped) = line.strip_suffix(':') {
            let name = stripped.trim().to_string();
            let lbl = labels.entry(name.clone()).or_insert_with(|| a.create_label());
            let mut lbl_copy = *lbl;
            a.set_label(&mut lbl_copy).map_err(ie)?;
            labels.insert(name, lbl_copy);
            continue;
        }

        // 拆 mnemonic + operands
        let (mnem, rest) = match line.find(char::is_whitespace) {
            Some(p) => (line[..p].to_lowercase(), line[p..].trim().to_string()),
            None => (line.to_lowercase(), String::new()),
        };
        let operands = split_operands(&rest);

        emit_one(&mut a, &mut labels, &mnem, &operands)?;
    }

    a.assemble(ip).map_err(ie)
}

fn emit_one(
    a: &mut CodeAssembler,
    labels: &mut HashMap<String, CodeLabel>,
    mnem: &str,
    operands: &[String],
) -> AppResult<()> {
    let ops: Vec<Operand> = operands
        .iter()
        .map(|s| parse_operand(s))
        .collect::<Result<_, _>>()
        .map_err(AppError::Internal)?;

    use Operand::*;

    macro_rules! handle_arith {
        ($name:ident) => {
            match (&ops[..]) {
                [Reg64(r), Reg64(s)] => a.$name(*r, *s).map_err(ie)?,
                [Reg64(r), Imm(v)] => a.$name(*r, *v as i32).map_err(ie)?,
                [Reg64(r), Mem(m)] => a.$name(*r, m.clone()).map_err(ie)?,
                [Mem(m), Reg64(r)] => a.$name(m.clone(), *r).map_err(ie)?,
                [Mem(m), Imm(v)] => a.$name(m.clone(), *v as i32).map_err(ie)?,
                [Reg32(r), Reg32(s)] => a.$name(*r, *s).map_err(ie)?,
                [Reg32(r), Imm(v)] => a.$name(*r, *v as i32).map_err(ie)?,
                [Reg32(r), Mem(m)] => a.$name(*r, m.clone()).map_err(ie)?,
                [Reg8(r), Reg8(s)] => a.$name(*r, *s).map_err(ie)?,
                [Reg8(r), Imm(v)] => a.$name(*r, *v as i32).map_err(ie)?,
                _ => return Err(AppError::Internal(format!("{} 操作数模式暂不支持", stringify!($name)))),
            }
        };
    }

    macro_rules! handle_jmp_imm {
        ($name:ident) => {
            match &ops[..] {
                [Imm(v)] => a.$name(*v as u64).map_err(ie)?,
                _ => {
                    if let Some(lbl_name) = operands.first() {
                        let lbl = labels.entry(lbl_name.clone()).or_insert_with(|| a.create_label());
                        a.$name(*lbl).map_err(ie)?;
                    } else {
                        return Err(AppError::Internal(format!("{} 缺操作数", stringify!($name))));
                    }
                }
            }
        };
    }

    match mnem {
        "nop"  => a.nop().map_err(ie)?,
        "ret" | "retn" => a.ret().map_err(ie)?,
        "int3" => a.int3().map_err(ie)?,
        "ud2"  => a.ud2().map_err(ie)?,
        "cli"  => a.cli().map_err(ie)?,
        "sti"  => a.sti().map_err(ie)?,
        "hlt"  => a.hlt().map_err(ie)?,
        "pushf" | "pushfq" => a.pushfq().map_err(ie)?,
        "popf"  | "popfq"  => a.popfq().map_err(ie)?,

        "push" => match &ops[..] {
            [Reg64(r)] => a.push(*r).map_err(ie)?,
            [Imm(v)] => a.push(*v as i32).map_err(ie)?,
            [Mem(m)] => a.push(m.clone()).map_err(ie)?,
            _ => return Err(AppError::Internal("push 操作数模式不支持".into())),
        },
        "pop" => match &ops[..] {
            [Reg64(r)] => a.pop(*r).map_err(ie)?,
            [Mem(m)] => a.pop(m.clone()).map_err(ie)?,
            _ => return Err(AppError::Internal("pop 操作数模式不支持".into())),
        },

        "mov" => match &ops[..] {
            [Reg64(r), Reg64(s)] => a.mov(*r, *s).map_err(ie)?,
            [Reg64(r), Imm(v)] => a.mov(*r, *v as u64).map_err(ie)?,
            [Reg64(r), Mem(m)] => a.mov(*r, m.clone()).map_err(ie)?,
            [Mem(m), Reg64(r)] => a.mov(m.clone(), *r).map_err(ie)?,
            [Reg32(r), Reg32(s)] => a.mov(*r, *s).map_err(ie)?,
            [Reg32(r), Imm(v)] => a.mov(*r, *v as u32).map_err(ie)?,
            [Reg32(r), Mem(m)] => a.mov(*r, m.clone()).map_err(ie)?,
            [Mem(m), Reg32(r)] => a.mov(m.clone(), *r).map_err(ie)?,
            [Reg8(r), Imm(v)] => a.mov(*r, *v as u32).map_err(ie)?,
            [Reg8(r), Reg8(s)] => a.mov(*r, *s).map_err(ie)?,
            _ => return Err(AppError::Internal("mov 模式暂不支持(SIMD/16-bit 用 Lua)".into())),
        },
        "lea" => match &ops[..] {
            [Reg64(r), Mem(m)] => a.lea(*r, m.clone()).map_err(ie)?,
            _ => return Err(AppError::Internal("lea 必须 reg64, [mem]".into())),
        },
        "xchg" => match &ops[..] {
            [Reg64(r), Reg64(s)] => a.xchg(*r, *s).map_err(ie)?,
            [Reg32(r), Reg32(s)] => a.xchg(*r, *s).map_err(ie)?,
            _ => return Err(AppError::Internal("xchg 模式暂不支持".into())),
        },

        "add"  => handle_arith!(add),
        "sub"  => handle_arith!(sub),
        "xor"  => handle_arith!(xor),
        "and"  => handle_arith!(and),
        "or"   => handle_arith!(or),
        "cmp"  => handle_arith!(cmp),
        "test" => match &ops[..] {
            [Reg64(r), Reg64(s)] => a.test(*r, *s).map_err(ie)?,
            [Reg64(r), Imm(v)] => a.test(*r, *v as i32).map_err(ie)?,
            [Mem(m), Reg64(r)] => a.test(m.clone(), *r).map_err(ie)?,
            [Mem(m), Imm(v)] => a.test(m.clone(), *v as i32).map_err(ie)?,
            [Reg32(r), Reg32(s)] => a.test(*r, *s).map_err(ie)?,
            [Reg32(r), Imm(v)] => a.test(*r, *v as i32).map_err(ie)?,
            [Reg8(r), Reg8(s)] => a.test(*r, *s).map_err(ie)?,
            [Reg8(r), Imm(v)] => a.test(*r, *v as i32).map_err(ie)?,
            _ => return Err(AppError::Internal("test 模式不支持".into())),
        },

        "inc" => match &ops[..] {
            [Reg64(r)] => a.inc(*r).map_err(ie)?,
            [Reg32(r)] => a.inc(*r).map_err(ie)?,
            [Mem(m)] => a.inc(m.clone()).map_err(ie)?,
            _ => return Err(AppError::Internal("inc 模式不支持".into())),
        },
        "dec" => match &ops[..] {
            [Reg64(r)] => a.dec(*r).map_err(ie)?,
            [Reg32(r)] => a.dec(*r).map_err(ie)?,
            [Mem(m)] => a.dec(m.clone()).map_err(ie)?,
            _ => return Err(AppError::Internal("dec 模式不支持".into())),
        },
        "neg" => match &ops[..] {
            [Reg64(r)] => a.neg(*r).map_err(ie)?,
            [Reg32(r)] => a.neg(*r).map_err(ie)?,
            _ => return Err(AppError::Internal("neg 模式不支持".into())),
        },
        "not" => match &ops[..] {
            [Reg64(r)] => a.not(*r).map_err(ie)?,
            [Reg32(r)] => a.not(*r).map_err(ie)?,
            _ => return Err(AppError::Internal("not 模式不支持".into())),
        },

        "jmp" => match &ops[..] {
            [Reg64(r)] => a.jmp(*r).map_err(ie)?,
            [Mem(m)] => a.jmp(m.clone()).map_err(ie)?,
            [Imm(v)] => a.jmp(*v as u64).map_err(ie)?,
            _ => {
                if let Some(lbl_name) = operands.first() {
                    let lbl = labels.entry(lbl_name.clone()).or_insert_with(|| a.create_label());
                    a.jmp(*lbl).map_err(ie)?;
                } else {
                    return Err(AppError::Internal("jmp 缺操作数".into()));
                }
            }
        },
        "call" => match &ops[..] {
            [Reg64(r)] => a.call(*r).map_err(ie)?,
            [Mem(m)] => a.call(m.clone()).map_err(ie)?,
            [Imm(v)] => a.call(*v as u64).map_err(ie)?,
            _ => return Err(AppError::Internal("call 缺操作数".into())),
        },

        "je"  | "jz"  => handle_jmp_imm!(je),
        "jne" | "jnz" => handle_jmp_imm!(jne),
        "jg"  | "jnle" => handle_jmp_imm!(jg),
        "jl"  | "jnge" => handle_jmp_imm!(jl),
        "jge" | "jnl"  => handle_jmp_imm!(jge),
        "jle" | "jng"  => handle_jmp_imm!(jle),
        "ja"  | "jnbe" => handle_jmp_imm!(ja),
        "jb"  | "jnae" => handle_jmp_imm!(jb),
        "jae" | "jnb"  => handle_jmp_imm!(jae),
        "jbe" | "jna"  => handle_jmp_imm!(jbe),
        "jo"  => handle_jmp_imm!(jo),
        "jno" => handle_jmp_imm!(jno),
        "js"  => handle_jmp_imm!(js),
        "jns" => handle_jmp_imm!(jns),

        _ => return Err(AppError::Internal(format!(
            "未支持指令: '{}'. 支持: nop/ret/int3/ud2/cli/sti/hlt/push/pop/mov/lea/xchg/add/sub/xor/and/or/cmp/test/inc/dec/neg/not/jmp/call/jXX. 复杂指令请用 Lua write_bytes。",
            mnem
        ))),
    };
    Ok(())
}
