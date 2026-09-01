//! Lua 脚本引擎 (P54)
//!
//! 暴露 API:
//!   read_bytes(pid, addr, n)            → 返 table 字节数组
//!   read_i32(pid, addr) / read_i64 / read_f32 / read_f64 / read_ptr
//!   write_bytes(pid, addr, table)       → 写一段字节
//!   write_i32(pid, addr, v)             → 同类
//!   find_pattern(pid, "48 89 5C 24 ?? 48 89 74 24 ?? 57") → 返 abs addr 或 nil
//!   log(...)                            → 累加进结果 string
//!
//! 脚本独立线程跑,超时强 stop。
//! 多次 run 自动 reset Lua state(避免上次脚本污染 global)。

use mlua::{Lua, Value};
use std::ffi::c_void;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
use windows::Win32::System::Memory::{
    VirtualProtectEx, VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, PAGE_EXECUTE_READWRITE,
    PAGE_GUARD, PAGE_NOACCESS, PAGE_PROTECTION_FLAGS,
};
use windows::Win32::System::Threading::{
    OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE,
};

use crate::util::error::{AppError, AppResult};

#[derive(Debug, serde::Serialize)]
pub struct LuaRunResult {
    pub output: String,
    pub error: Option<String>,
}

/// 把 Lua Value 拼到 buf — print/log 共用. table 递归 pretty-print, 深度限制防爆.
fn append_value(buf: &mut String, v: &Value, depth: usize) {
    match v {
        Value::Nil => buf.push_str("nil"),
        Value::Boolean(b) => buf.push_str(if *b { "true" } else { "false" }),
        Value::Integer(i) => buf.push_str(&i.to_string()),
        Value::Number(n) => buf.push_str(&n.to_string()),
        Value::String(s) => buf.push_str(&s.to_string_lossy()),
        Value::Table(t) => {
            if depth >= 3 {
                buf.push_str("{...}");
                return;
            }
            buf.push('{');
            let mut first = true;
            // 先按数组索引 1..n 出
            let mut idx = 1i64;
            loop {
                match t.get::<Value>(idx) {
                    Ok(Value::Nil) | Err(_) => break,
                    Ok(val) => {
                        if !first { buf.push_str(", "); }
                        first = false;
                        append_value(buf, &val, depth + 1);
                        idx += 1;
                        if idx > 64 { buf.push_str(", ..."); break; }
                    }
                }
            }
            // 再扫 hash 部分(不重复 1..idx-1 的 int key)
            let mut shown = 0;
            for kv in t.clone().pairs::<Value, Value>() {
                if let Ok((k, val)) = kv {
                    // 跳过已显示的 int 数组段
                    if let Value::Integer(ki) = &k {
                        if *ki >= 1 && *ki < idx { continue; }
                    }
                    if !first { buf.push_str(", "); }
                    first = false;
                    append_value(buf, &k, depth + 1);
                    buf.push('=');
                    append_value(buf, &val, depth + 1);
                    shown += 1;
                    if shown >= 32 { buf.push_str(", ..."); break; }
                }
            }
            buf.push('}');
        }
        Value::Function(_) => buf.push_str("<function>"),
        Value::Thread(_) => buf.push_str("<thread>"),
        Value::UserData(_) | Value::LightUserData(_) => buf.push_str("<userdata>"),
        Value::Error(e) => buf.push_str(&format!("<error: {}>", e)),
        other => buf.push_str(&format!("{:?}", other)),
    }
}

fn open_rw(pid: u32) -> AppResult<HANDLE> {
    unsafe {
        OpenProcess(
            PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION,
            false,
            pid,
        )
        .map_err(|e| AppError::Internal(format!("OpenProcess({pid}): {e}")))
    }
}

unsafe fn read_n(h: HANDLE, addr: u64, n: usize) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; n];
    let mut got = 0usize;
    ReadProcessMemory(h, addr as *const c_void, buf.as_mut_ptr() as *mut c_void, n, Some(&mut got))
        .ok()?;
    buf.truncate(got);
    Some(buf)
}

unsafe fn write_n(h: HANDLE, addr: u64, bytes: &[u8]) -> bool {
    let mut old: PAGE_PROTECTION_FLAGS = std::mem::zeroed();
    let _ = VirtualProtectEx(h, addr as *const c_void, bytes.len(), PAGE_EXECUTE_READWRITE, &mut old);
    let mut wrote = 0usize;
    let ok = WriteProcessMemory(
        h,
        addr as *const c_void,
        bytes.as_ptr() as *const c_void,
        bytes.len(),
        Some(&mut wrote),
    )
    .is_ok();
    let mut _x: PAGE_PROTECTION_FLAGS = std::mem::zeroed();
    let _ = VirtualProtectEx(h, addr as *const c_void, bytes.len(), old, &mut _x);
    ok && wrote == bytes.len()
}

fn parse_pattern(p: &str) -> Result<Vec<Option<u8>>, String> {
    let mut out = vec![];
    for tok in p.split_whitespace() {
        if tok == "?" || tok == "??" {
            out.push(None);
        } else {
            let b = u8::from_str_radix(tok, 16).map_err(|_| format!("bad token: {}", tok))?;
            out.push(Some(b));
        }
    }
    Ok(out)
}

unsafe fn pattern_find(h: HANDLE, pat: &[Option<u8>]) -> Option<u64> {
    let mut va: u64 = 0;
    loop {
        let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
        if VirtualQueryEx(
            h,
            Some(va as *const c_void),
            &mut mbi,
            std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
        ) == 0
        {
            break;
        }
        let next = (mbi.BaseAddress as u64).saturating_add(mbi.RegionSize as u64);
        if next <= va {
            break;
        }
        va = next;
        if va >= 0x7FFF_FFFF_FFFF {
            break;
        }
        if mbi.State != MEM_COMMIT
            || (mbi.Protect.0 & PAGE_NOACCESS.0) != 0
            || (mbi.Protect.0 & PAGE_GUARD.0) != 0
        {
            continue;
        }
        let base = mbi.BaseAddress as u64;
        let size = mbi.RegionSize as u64;
        const CHUNK: u64 = 0x100000;
        let mut buf = vec![0u8; CHUNK as usize];
        let mut off = 0u64;
        while off < size {
            let take = (size - off).min(CHUNK) as usize;
            if take < pat.len() {
                break;
            }
            let mut got = 0usize;
            let ok = ReadProcessMemory(
                h,
                (base + off) as *const c_void,
                buf.as_mut_ptr() as *mut c_void,
                take,
                Some(&mut got),
            )
            .is_ok();
            if !ok || got < pat.len() {
                off += CHUNK;
                continue;
            }
            for i in 0..=got - pat.len() {
                let mut ok = true;
                for (k, p) in pat.iter().enumerate() {
                    if let Some(b) = p {
                        if buf[i + k] != *b {
                            ok = false;
                            break;
                        }
                    }
                }
                if ok {
                    return Some(base + off + i as u64);
                }
            }
            off += CHUNK;
        }
    }
    None
}

#[tauri::command]
pub async fn dbg_lua_run(pid: u32, script: String) -> AppResult<LuaRunResult> {
    tokio::task::spawn_blocking(move || -> AppResult<LuaRunResult> {
        let lua = Lua::new();
        let output = std::sync::Arc::new(std::sync::Mutex::new(String::new()));

        // log(...) — 累加到 output. print/write/io.write 也指向同一个 sink,
        // 否则 Lua 默认 print 走 stdout 在 Tauri 进程被吞.
        // 同时 table 类型走 recursive pretty-print (大部分用户期望 print(t) 能看内容).
        let out2 = output.clone();
        let log_fn = lua
            .create_function(move |_, args: mlua::MultiValue| {
                let mut s = String::new();
                let mut first = true;
                for a in args {
                    if !first { s.push('\t'); }
                    first = false;
                    append_value(&mut s, &a, 0);
                }
                s.push('\n');
                out2.lock().unwrap().push_str(&s);
                Ok(())
            })
            .map_err(|e| AppError::Internal(format!("lua: {e}")))?;
        // 既绑 log, 也覆盖 print — lua 用户写 print(...) 不会丢
        lua.globals().set("log", log_fn.clone()).ok();
        lua.globals().set("print", log_fn).ok();

        // io.write(...) 也走 sink — 不少脚本用 io.write 替代 print
        let out3 = output.clone();
        let io_write_fn = lua
            .create_function(move |_, args: mlua::MultiValue| {
                let mut buf = out3.lock().unwrap();
                for a in args {
                    let mut tmp = String::new();
                    append_value(&mut tmp, &a, 0);
                    buf.push_str(&tmp);
                }
                Ok(())
            })
            .map_err(|e| AppError::Internal(format!("lua: {e}")))?;
        let io_tbl = lua.create_table().ok();
        if let Some(t) = &io_tbl {
            t.set("write", io_write_fn).ok();
            lua.globals().set("io", t.clone()).ok();
        }

        // hex(n) — 格式化为 0xHEX
        lua.globals()
            .set("hex", lua.create_function(|_, n: i64| Ok(format!("0x{:x}", n))).unwrap())
            .ok();

        // read_bytes(pid, addr, n)
        let pid_const = pid;
        lua.globals()
            .set(
                "read_bytes",
                lua.create_function(move |_lua, (p, addr, n): (u32, i64, u32)| {
                    let p = if p == 0 { pid_const } else { p };
                    unsafe {
                        let h = open_rw(p).map_err(|e| mlua::Error::external(e.to_string()))?;
                        let r = read_n(h, addr as u64, n as usize);
                        let _ = windows::Win32::Foundation::CloseHandle(h);
                        Ok(r.map(|v| v.into_iter().map(|b| b as i64).collect::<Vec<_>>()))
                    }
                })
                .unwrap(),
            )
            .ok();

        macro_rules! mkread {
            ($name:literal, $ty:ty, $size:expr) => {
                lua.globals()
                    .set(
                        $name,
                        lua.create_function(move |_lua, (p, addr): (u32, i64)| {
                            let p = if p == 0 { pid_const } else { p };
                            unsafe {
                                let h = open_rw(p).map_err(|e| mlua::Error::external(e.to_string()))?;
                                let r = read_n(h, addr as u64, $size);
                                let _ = windows::Win32::Foundation::CloseHandle(h);
                                Ok(r.and_then(|v| {
                                    if v.len() == $size {
                                        Some(<$ty>::from_le_bytes(v.try_into().unwrap()))
                                    } else {
                                        None
                                    }
                                }))
                            }
                        })
                        .unwrap(),
                    )
                    .ok();
            };
        }
        mkread!("read_i8",  i8,  1);
        mkread!("read_u8",  u8,  1);
        mkread!("read_i16", i16, 2);
        mkread!("read_u16", u16, 2);
        mkread!("read_i32", i32, 4);
        mkread!("read_u32", u32, 4);
        mkread!("read_i64", i64, 8);
        mkread!("read_u64", u64, 8);
        mkread!("read_f32", f32, 4);
        mkread!("read_f64", f64, 8);
        mkread!("read_ptr", u64, 8);

        // read_string(pid, addr [, max_len=128]) — 读 ascii / utf8 C 字符串,
        // 在 \0 截断, 或读到 max_len.
        lua.globals()
            .set(
                "read_string",
                lua.create_function(move |_lua, (p, addr, max): (u32, i64, Option<u32>)| {
                    let p = if p == 0 { pid_const } else { p };
                    let max = max.unwrap_or(128).min(8192) as usize;
                    unsafe {
                        let h = open_rw(p).map_err(|e| mlua::Error::external(e.to_string()))?;
                        let r = read_n(h, addr as u64, max);
                        let _ = windows::Win32::Foundation::CloseHandle(h);
                        match r {
                            None => Ok(None),
                            Some(buf) => {
                                let n = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
                                Ok(Some(String::from_utf8_lossy(&buf[..n]).to_string()))
                            }
                        }
                    }
                })
                .unwrap(),
            )
            .ok();

        // read_wstring(pid, addr [, max_wchars=128]) — UTF-16LE 字符串
        lua.globals()
            .set(
                "read_wstring",
                lua.create_function(move |_lua, (p, addr, max_wchars): (u32, i64, Option<u32>)| {
                    let p = if p == 0 { pid_const } else { p };
                    let max_wchars = max_wchars.unwrap_or(128).min(4096) as usize;
                    unsafe {
                        let h = open_rw(p).map_err(|e| mlua::Error::external(e.to_string()))?;
                        let r = read_n(h, addr as u64, max_wchars * 2);
                        let _ = windows::Win32::Foundation::CloseHandle(h);
                        match r {
                            None => Ok(None),
                            Some(buf) => {
                                let mut u16s: Vec<u16> = buf.chunks_exact(2)
                                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                                    .collect();
                                if let Some(n) = u16s.iter().position(|&w| w == 0) {
                                    u16s.truncate(n);
                                }
                                Ok(Some(String::from_utf16_lossy(&u16s)))
                            }
                        }
                    }
                })
                .unwrap(),
            )
            .ok();

        // write_bytes(pid, addr, table)
        lua.globals()
            .set(
                "write_bytes",
                lua.create_function(move |_lua, (p, addr, tbl): (u32, i64, mlua::Table)| {
                    let p = if p == 0 { pid_const } else { p };
                    let bytes: Vec<u8> = tbl
                        .pairs::<i64, i64>()
                        .filter_map(|kv| kv.ok().map(|(_, v)| v as u8))
                        .collect();
                    unsafe {
                        let h = open_rw(p).map_err(|e| mlua::Error::external(e.to_string()))?;
                        let ok = write_n(h, addr as u64, &bytes);
                        let _ = windows::Win32::Foundation::CloseHandle(h);
                        Ok(ok)
                    }
                })
                .unwrap(),
            )
            .ok();
        // write_i32 等
        macro_rules! mkwrite {
            ($name:literal, $ty:ty) => {
                lua.globals()
                    .set(
                        $name,
                        lua.create_function(move |_lua, (p, addr, v): (u32, i64, mlua::Number)| {
                            let p = if p == 0 { pid_const } else { p };
                            unsafe {
                                let h = open_rw(p).map_err(|e| mlua::Error::external(e.to_string()))?;
                                let bytes = (v as $ty).to_le_bytes();
                                let ok = write_n(h, addr as u64, &bytes);
                                let _ = windows::Win32::Foundation::CloseHandle(h);
                                Ok(ok)
                            }
                        })
                        .unwrap(),
                    )
                    .ok();
            };
        }
        mkwrite!("write_i32", i32);
        mkwrite!("write_u32", u32);
        mkwrite!("write_i64", i64);
        mkwrite!("write_u64", u64);
        mkwrite!("write_f32", f32);
        mkwrite!("write_f64", f64);

        // find_pattern(pid, "AA BB ? CC")
        lua.globals()
            .set(
                "find_pattern",
                lua.create_function(move |_lua, (p, pat): (u32, String)| {
                    let p = if p == 0 { pid_const } else { p };
                    let pat = parse_pattern(&pat).map_err(mlua::Error::external)?;
                    unsafe {
                        let h = open_rw(p).map_err(|e| mlua::Error::external(e.to_string()))?;
                        let r = pattern_find(h, &pat);
                        let _ = windows::Win32::Foundation::CloseHandle(h);
                        Ok(r.map(|x| x as i64))
                    }
                })
                .unwrap(),
            )
            .ok();

        // pid 全局
        lua.globals().set("PID", pid as i64).ok();

        let error = match lua.load(&script).exec() {
            Ok(()) => None,
            Err(e) => Some(format!("{}", e)),
        };
        let out = output.lock().unwrap().clone();
        Ok(LuaRunResult { output: out, error })
    })
    .await
    .map_err(|e| AppError::Internal(format!("spawn_blocking: {e}")))?
}
