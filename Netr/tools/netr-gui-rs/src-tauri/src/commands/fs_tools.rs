//! 文件系统工具 (P89) — read/write/append/list/mkdir/exists/delete
//!
//! 默认 workspace 根 %LOCALAPPDATA%\GuardMetaVSP\workspace.
//! 所有路径 join 到这个根下, 拒绝 .. 跳出 + 绝对路径.
//! 用户可以传 ROOT 之外的绝对路径 — 走 require_unrestricted=true (默认 false).
//!
//! AI tools 暴露:
//!   read_file (utf-8 文本)
//!   write_file (覆盖)
//!   append_file
//!   list_dir
//!   make_dir
//!   file_exists
//!   delete_file
//!   workspace_root  (查询当前 root)

use std::path::{Path, PathBuf};

use serde::Deserialize;
use serde_json::{json, Value};

const MAX_READ_BYTES: usize = 512 * 1024;   // 单次读取上限 512KB
const MAX_WRITE_BYTES: usize = 4 * 1024 * 1024; // 单次写入上限 4MB

fn workspace_root() -> PathBuf {
    let base = std::env::var_os("LOCALAPPDATA")
        .or_else(|| std::env::var_os("APPDATA"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    let dir = base.join("GuardMetaVSP").join("workspace");
    let _ = std::fs::create_dir_all(&dir);
    dir
}

fn resolve_path(input: &str, allow_absolute: bool) -> Result<PathBuf, String> {
    let p = Path::new(input);
    if p.is_absolute() {
        if !allow_absolute {
            return Err(format!(
                "禁止绝对路径 '{}'. 默认只能在 workspace 下写, \
                 如确需访问系统路径需用户许可 — 当前关闭. \
                 workspace 根可调 workspace_root 查询",
                input
            ));
        }
        return Ok(p.to_path_buf());
    }
    let root = workspace_root();
    let joined = root.join(p);
    // 规范化, 检查没跳出 root
    let canon_root = std::fs::canonicalize(&root).unwrap_or(root.clone());
    // joined 可能还不存在, 不能 canonicalize. 用 Path::components 校验 ..
    let mut depth = 0i32;
    for c in p.components() {
        use std::path::Component::*;
        match c {
            ParentDir => { depth -= 1; if depth < 0 { return Err("路径用 .. 跳出 workspace".into()); } }
            CurDir => {},
            Normal(_) => depth += 1,
            RootDir | Prefix(_) => return Err("路径不能含 root/prefix".into()),
        }
    }
    Ok(canon_root.join(p))
}

#[derive(Debug, Deserialize)]
pub struct PathReq { pub path: String, #[serde(default)] pub allow_absolute: bool }

#[derive(Debug, Deserialize)]
pub struct WriteReq {
    pub path: String,
    pub content: String,
    #[serde(default)]
    pub allow_absolute: bool,
}

#[derive(Debug, Deserialize)]
pub struct ReadReq {
    pub path: String,
    #[serde(default)]
    pub allow_absolute: bool,
    #[serde(default)]
    pub offset: u64,
    #[serde(default)]
    pub length: Option<u64>,
}

pub fn do_read_file(args: &Value) -> Value {
    let req: ReadReq = match serde_json::from_value(args.clone()) {
        Ok(r) => r,
        Err(e) => return json!({ "ok": false, "error": format!("参数: {e}") }),
    };
    let p = match resolve_path(&req.path, req.allow_absolute) {
        Ok(p) => p, Err(e) => return json!({ "ok": false, "error": e }),
    };
    let raw = match std::fs::read(&p) {
        Ok(b) => b,
        Err(e) => return json!({ "ok": false, "error": format!("读 {}: {e}", p.display()) }),
    };
    let total = raw.len();
    let start = (req.offset as usize).min(total);
    let want = req.length.map(|n| n as usize).unwrap_or(MAX_READ_BYTES).min(MAX_READ_BYTES);
    let end = (start + want).min(total);
    let slice = &raw[start..end];
    let text = String::from_utf8_lossy(slice).to_string();
    json!({
        "ok": true,
        "path": p.display().to_string(),
        "size": total,
        "offset": start,
        "length": end - start,
        "content": text,
        "truncated": end < total,
        "binary_hint": slice.iter().filter(|&&b| b == 0 || (b < 32 && b != b'\n' && b != b'\r' && b != b'\t')).count() > slice.len() / 16,
    })
}

pub fn do_write_file(args: &Value) -> Value {
    let req: WriteReq = match serde_json::from_value(args.clone()) {
        Ok(r) => r,
        Err(e) => return json!({ "ok": false, "error": format!("参数: {e}") }),
    };
    if req.content.len() > MAX_WRITE_BYTES {
        return json!({ "ok": false, "error": format!("写入内容 {} B 超过单次上限 {}", req.content.len(), MAX_WRITE_BYTES) });
    }
    let p = match resolve_path(&req.path, req.allow_absolute) {
        Ok(p) => p, Err(e) => return json!({ "ok": false, "error": e }),
    };
    if let Some(parent) = p.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            return json!({ "ok": false, "error": format!("mkdir {}: {e}", parent.display()) });
        }
    }
    match std::fs::write(&p, req.content.as_bytes()) {
        Ok(_) => json!({ "ok": true, "path": p.display().to_string(), "bytes_written": req.content.len() }),
        Err(e) => json!({ "ok": false, "error": format!("写 {}: {e}", p.display()) }),
    }
}

pub fn do_append_file(args: &Value) -> Value {
    use std::io::Write;
    let req: WriteReq = match serde_json::from_value(args.clone()) {
        Ok(r) => r,
        Err(e) => return json!({ "ok": false, "error": format!("参数: {e}") }),
    };
    let p = match resolve_path(&req.path, req.allow_absolute) {
        Ok(p) => p, Err(e) => return json!({ "ok": false, "error": e }),
    };
    if let Some(parent) = p.parent() { let _ = std::fs::create_dir_all(parent); }
    let mut f = match std::fs::OpenOptions::new().append(true).create(true).open(&p) {
        Ok(f) => f,
        Err(e) => return json!({ "ok": false, "error": format!("open {}: {e}", p.display()) }),
    };
    match f.write_all(req.content.as_bytes()) {
        Ok(_) => json!({ "ok": true, "path": p.display().to_string(), "appended_bytes": req.content.len() }),
        Err(e) => json!({ "ok": false, "error": format!("写 {}: {e}", p.display()) }),
    }
}

pub fn do_list_dir(args: &Value) -> Value {
    let req: PathReq = match serde_json::from_value(args.clone()) {
        Ok(r) => r,
        Err(e) => return json!({ "ok": false, "error": format!("参数: {e}") }),
    };
    let p = match resolve_path(&req.path, req.allow_absolute) {
        Ok(p) => p, Err(e) => return json!({ "ok": false, "error": e }),
    };
    let it = match std::fs::read_dir(&p) {
        Ok(i) => i,
        Err(e) => return json!({ "ok": false, "error": format!("read_dir {}: {e}", p.display()) }),
    };
    let mut entries = Vec::new();
    for e in it.flatten() {
        let meta = e.metadata().ok();
        entries.push(json!({
            "name": e.file_name().to_string_lossy().to_string(),
            "is_dir": meta.as_ref().map(|m| m.is_dir()).unwrap_or(false),
            "size": meta.as_ref().map(|m| m.len()).unwrap_or(0),
        }));
        if entries.len() >= 500 { break; }
    }
    entries.sort_by(|a, b| {
        let ad = a["is_dir"].as_bool().unwrap_or(false);
        let bd = b["is_dir"].as_bool().unwrap_or(false);
        if ad != bd { bd.cmp(&ad) }
        else { a["name"].as_str().unwrap_or("").cmp(b["name"].as_str().unwrap_or("")) }
    });
    json!({
        "ok": true,
        "path": p.display().to_string(),
        "count": entries.len(),
        "entries": entries,
    })
}

pub fn do_make_dir(args: &Value) -> Value {
    let req: PathReq = match serde_json::from_value(args.clone()) {
        Ok(r) => r,
        Err(e) => return json!({ "ok": false, "error": format!("参数: {e}") }),
    };
    let p = match resolve_path(&req.path, req.allow_absolute) {
        Ok(p) => p, Err(e) => return json!({ "ok": false, "error": e }),
    };
    match std::fs::create_dir_all(&p) {
        Ok(_) => json!({ "ok": true, "path": p.display().to_string() }),
        Err(e) => json!({ "ok": false, "error": format!("mkdir {}: {e}", p.display()) }),
    }
}

pub fn do_file_exists(args: &Value) -> Value {
    let req: PathReq = match serde_json::from_value(args.clone()) {
        Ok(r) => r,
        Err(e) => return json!({ "ok": false, "error": format!("参数: {e}") }),
    };
    let p = match resolve_path(&req.path, req.allow_absolute) {
        Ok(p) => p, Err(e) => return json!({ "ok": false, "error": e }),
    };
    let exists = p.exists();
    let is_dir = p.is_dir();
    let is_file = p.is_file();
    let size = if is_file { std::fs::metadata(&p).ok().map(|m| m.len()) } else { None };
    json!({
        "ok": true,
        "path": p.display().to_string(),
        "exists": exists,
        "is_dir": is_dir,
        "is_file": is_file,
        "size": size,
    })
}

pub fn do_delete_file(args: &Value) -> Value {
    let req: PathReq = match serde_json::from_value(args.clone()) {
        Ok(r) => r,
        Err(e) => return json!({ "ok": false, "error": format!("参数: {e}") }),
    };
    let p = match resolve_path(&req.path, req.allow_absolute) {
        Ok(p) => p, Err(e) => return json!({ "ok": false, "error": e }),
    };
    if !p.exists() {
        return json!({ "ok": false, "error": format!("{} 不存在", p.display()) });
    }
    let r = if p.is_dir() { std::fs::remove_dir_all(&p) } else { std::fs::remove_file(&p) };
    match r {
        Ok(_) => json!({ "ok": true, "path": p.display().to_string() }),
        Err(e) => json!({ "ok": false, "error": format!("删 {}: {e}", p.display()) }),
    }
}

// ===== P101: AI 拖放文件读取 =====
//
// 不走 workspace 限制 — 任意绝对路径. 限单文件 512KB.
// 调用方是 AI 面板拖放, 用户主动行为, 等同 SendMessage 的附件.

const MAX_DROP_KB: u64 = 512;

#[derive(serde::Deserialize)]
pub struct ReadDroppedReq {
    pub path: String,
    pub max_kb: Option<u32>,
}

#[derive(serde::Serialize)]
pub struct ReadDroppedResult {
    pub path: String,
    pub name: String,
    pub size: u64,
    pub truncated: bool,
    pub is_binary: bool,
    /// 文本时填这里, 二进制时空
    pub content: Option<String>,
    /// 二进制时填 hex (首 4KB)
    pub hex: Option<String>,
}

#[tauri::command]
pub fn ai_read_dropped_file(req: ReadDroppedReq) -> crate::util::error::AppResult<ReadDroppedResult> {
    use crate::util::error::AppError;

    let path = std::path::PathBuf::from(&req.path);
    if !path.is_file() {
        return Err(AppError::Internal(format!("{} 不是文件或不存在", req.path)));
    }
    let max_bytes = (req.max_kb.unwrap_or(MAX_DROP_KB as u32) as u64).min(MAX_DROP_KB) * 1024;
    let meta = std::fs::metadata(&path)
        .map_err(|e| AppError::Internal(format!("metadata: {e}")))?;
    let full_size = meta.len();
    let to_read = full_size.min(max_bytes) as usize;
    let raw = {
        use std::io::Read;
        let mut f = std::fs::File::open(&path)
            .map_err(|e| AppError::Internal(format!("open: {e}")))?;
        let mut buf = vec![0u8; to_read];
        let _ = f.read(&mut buf).map_err(|e| AppError::Internal(format!("read: {e}")))?;
        buf
    };
    let truncated = full_size > max_bytes;
    let name = path.file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_else(|| req.path.clone());

    // binary 检测: 含 \0 / 非 utf-8 / 控制字符比例高
    let nul_count = raw.iter().filter(|&&b| b == 0).count();
    let ctrl_count = raw.iter().filter(|&&b| b < 0x09 || (b > 0x0D && b < 0x20)).count();
    let is_binary = nul_count > 0 || ctrl_count * 16 > raw.len();

    if is_binary {
        let hex_head: String = raw.iter().take(4096).map(|b| format!("{:02x}", b)).collect();
        Ok(ReadDroppedResult {
            path: path.display().to_string(),
            name, size: full_size, truncated,
            is_binary: true,
            content: None,
            hex: Some(hex_head),
        })
    } else {
        let txt = String::from_utf8_lossy(&raw).to_string();
        Ok(ReadDroppedResult {
            path: path.display().to_string(),
            name, size: full_size, truncated,
            is_binary: false,
            content: Some(txt),
            hex: None,
        })
    }
}

pub fn do_workspace_root() -> Value {
    let root = workspace_root();
    json!({
        "ok": true,
        "root": root.display().to_string(),
        "note": "默认所有相对路径 join 到此. 写入和删除限制在此目录内, 除非 allow_absolute=true.",
    })
}
