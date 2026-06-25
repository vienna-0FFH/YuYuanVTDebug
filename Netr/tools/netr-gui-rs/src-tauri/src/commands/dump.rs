//! 内存 dump 提取 (P105) — region / module / process 三档.
//!
//! 输出默认到 %LOCALAPPDATA%\GuardMetaVSP\workspace\dumps\.
//! 单文件上限 256 MB 防误操作; process dump 拒绝镜像 > 1024 MB.

use std::ffi::c_void;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::Memory::{
    VirtualQueryEx, MEMORY_BASIC_INFORMATION,
    MEM_COMMIT, PAGE_GUARD, PAGE_NOACCESS,
};

use crate::commands::pe_util::{enum_modules, open_for_read, pick_module};
use crate::util::error::{AppError, AppResult};

const MAX_REGION_BYTES: u64 = 256 * 1024 * 1024;
const MAX_MODULE_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_PROCESS_TOTAL_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const CHUNK: usize = 1024 * 1024;

fn dumps_dir() -> AppResult<PathBuf> {
    let base = std::env::var_os("LOCALAPPDATA")
        .or_else(|| std::env::var_os("APPDATA"))
        .map(PathBuf::from)
        .ok_or_else(|| AppError::Internal("LOCALAPPDATA".into()))?;
    let dir = base.join("GuardMetaVSP").join("workspace").join("dumps");
    std::fs::create_dir_all(&dir).map_err(|e| AppError::Internal(format!("mkdir: {e}")))?;
    Ok(dir)
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs()).unwrap_or(0)
}

fn sanitize_filename(s: &str) -> String {
    s.chars().map(|c| {
        if c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-' { c } else { '_' }
    }).take(64).collect()
}

unsafe fn read_range_to_file(
    h: windows::Win32::Foundation::HANDLE,
    address: u64,
    size: u64,
    path: &Path,
) -> AppResult<(u64, u64, u32)> {
    use std::io::Write;
    if size == 0 { return Err(AppError::Internal("size 不能为 0".into())); }
    if size > MAX_REGION_BYTES {
        return Err(AppError::Internal(format!("size {} 超过单次上限 {}", size, MAX_REGION_BYTES)));
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| AppError::Internal(format!("mkdir: {e}")))?;
    }
    let mut f = std::fs::File::create(path)
        .map_err(|e| AppError::Internal(format!("create {}: {e}", path.display())))?;
    let mut buf = vec![0u8; CHUNK];
    let mut written = 0u64;
    let mut zero_filled = 0u64;
    let mut chunks_failed = 0u32;
    let mut off = 0u64;
    while off < size {
        let take = ((size - off) as usize).min(CHUNK);
        let mut got = 0usize;
        let ok = ReadProcessMemory(
            h,
            (address + off) as *const c_void,
            buf.as_mut_ptr() as *mut c_void,
            take, Some(&mut got),
        ).is_ok();
        if !ok || got == 0 {
            // 读不到的页, 写零保持文件偏移与内存偏移一致
            buf[..take].iter_mut().for_each(|b| *b = 0);
            f.write_all(&buf[..take]).map_err(|e| AppError::Internal(format!("write: {e}")))?;
            zero_filled += take as u64;
            chunks_failed += 1;
        } else {
            f.write_all(&buf[..got]).map_err(|e| AppError::Internal(format!("write: {e}")))?;
            if got < take {
                buf[..take - got].iter_mut().for_each(|b| *b = 0);
                f.write_all(&buf[..take - got]).map_err(|e| AppError::Internal(format!("write: {e}")))?;
                zero_filled += (take - got) as u64;
                chunks_failed += 1;
            }
            written += got as u64;
        }
        off += take as u64;
    }
    Ok((written, zero_filled, chunks_failed))
}

// ===== dump_region =====

#[derive(Debug, Deserialize)]
pub struct DumpRegionReq {
    pub pid: u32,
    /// 16 进制字符串 "0x..." (前端 bigint → string, JSON 安全)
    pub address: String,
    pub size: u64,
    pub out_path: Option<String>,
}

fn parse_address(s: &str) -> Result<u64, String> {
    let s = s.trim().trim_start_matches("0x").trim_start_matches("0X");
    u64::from_str_radix(s, 16)
        .map_err(|e| format!("无法解析地址 '{}': {}", s, e))
}

#[derive(Debug, Serialize)]
pub struct DumpResult {
    pub path: String,
    pub bytes_requested: u64,
    pub bytes_read: u64,
    pub bytes_zero_filled: u64,
    pub chunks_failed: u32,
}

#[tauri::command]
pub async fn dbg_dump_region(req: DumpRegionReq) -> AppResult<DumpResult> {
    let pid = req.pid;
    let address = parse_address(&req.address)
        .map_err(AppError::Internal)?;
    let size = req.size;
    let out_path = req.out_path;
    tokio::task::spawn_blocking(move || -> AppResult<DumpResult> {
        unsafe {
            let h = open_for_read(pid)?;
            let path: PathBuf = match out_path {
                Some(p) => PathBuf::from(p),
                None => dumps_dir()?.join(format!("{}_{:x}_{}b_{}.bin", pid, address, size, now_secs())),
            };
            let (written, zero, failed) = read_range_to_file(h, address, size, &path)?;
            let _ = windows::Win32::Foundation::CloseHandle(h);
            Ok(DumpResult {
                path: path.display().to_string(),
                bytes_requested: size,
                bytes_read: written,
                bytes_zero_filled: zero,
                chunks_failed: failed,
            })
        }
    })
    .await
    .map_err(|e| AppError::Internal(format!("spawn_blocking: {e}")))?
}

// ===== dump_module =====

#[derive(Debug, Deserialize)]
pub struct DumpModuleReq {
    pub pid: u32,
    pub module_name: Option<String>,
    /// 是否把 SizeOfRawData / PointerToRawData 重写成 VA 布局
    /// (运行时 dump 必做, 否则 IDA/x64dbg 加载会错位)
    #[serde(default = "default_true")]
    pub fix_sections: bool,
    pub out_path: Option<String>,
}
fn default_true() -> bool { true }

#[derive(Debug, Serialize)]
pub struct DumpModuleResult {
    pub path: String,
    pub module: String,
    pub base: u64,
    pub size: u64,
    pub fixed: bool,
    pub sections_fixed: u32,
    pub bytes_read: u64,
    pub bytes_zero_filled: u64,
    pub chunks_failed: u32,
}

/// PE 头修复: 把每个 section 的 SizeOfRawData/PointerToRawData 改成 VA 视图
/// (SizeOfRawData = VirtualSize 对齐到 SectionAlignment, PointerToRawData = VirtualAddress).
/// 让 dump 出来的文件像"已映射"的 PE.
fn fix_sections_in_memory_image(buf: &mut [u8]) -> Result<u32, String> {
    if buf.len() < 0x200 { return Err("PE 头太小".into()); }
    if buf[0] != b'M' || buf[1] != b'Z' { return Err("不是 MZ".into()); }
    let e_lfanew = u32::from_le_bytes(buf[0x3c..0x40].try_into().unwrap()) as usize;
    if e_lfanew + 0x118 > buf.len() { return Err("e_lfanew 出界".into()); }
    if &buf[e_lfanew..e_lfanew + 4] != b"PE\0\0" { return Err("PE 签名缺".into()); }
    let num_sections = u16::from_le_bytes([buf[e_lfanew + 6], buf[e_lfanew + 7]]) as usize;
    let opt_size = u16::from_le_bytes([buf[e_lfanew + 20], buf[e_lfanew + 21]]) as usize;
    let opt_off = e_lfanew + 24;
    if opt_off + opt_size > buf.len() { return Err("OptionalHeader 出界".into()); }
    let sections_off = opt_off + opt_size;
    if sections_off + num_sections * 40 > buf.len() { return Err("Sections 出界".into()); }

    let mut fixed = 0u32;
    for i in 0..num_sections {
        let s = sections_off + i * 40;
        // VirtualSize at +8, VirtualAddress at +12
        // SizeOfRawData at +16, PointerToRawData at +20
        let vsz = u32::from_le_bytes(buf[s + 8..s + 12].try_into().unwrap());
        let vaddr = u32::from_le_bytes(buf[s + 12..s + 16].try_into().unwrap());
        // SizeOfRawData = VirtualSize (alignment 是 FileAlignment, 这里粗略取相同; loader 实际宽容)
        let new_size_raw = vsz;
        buf[s + 16..s + 20].copy_from_slice(&new_size_raw.to_le_bytes());
        buf[s + 20..s + 24].copy_from_slice(&vaddr.to_le_bytes());
        fixed += 1;
    }
    Ok(fixed)
}

#[tauri::command]
pub async fn dbg_dump_module(req: DumpModuleReq) -> AppResult<DumpModuleResult> {
    let pid = req.pid;
    let want = req.module_name;
    let fix = req.fix_sections;
    let out_path = req.out_path;
    tokio::task::spawn_blocking(move || -> AppResult<DumpModuleResult> {
        unsafe {
            let h = open_for_read(pid)?;
            let mods = enum_modules(pid);
            let m = pick_module(&mods, want.as_deref())
                .ok_or_else(|| AppError::Internal("找不到模块".into()))?
                .clone();
            if m.size > MAX_MODULE_BYTES {
                let _ = windows::Win32::Foundation::CloseHandle(h);
                return Err(AppError::Internal(format!("模块 {} 超过上限 {} bytes", m.size, MAX_MODULE_BYTES)));
            }
            // 全部读到内存(模块通常 < 100MB)
            let mut buf = vec![0u8; m.size as usize];
            let mut total_read = 0u64;
            let mut total_zero = 0u64;
            let mut failed = 0u32;
            let mut off = 0u64;
            let size = m.size;
            while off < size {
                let take = ((size - off) as usize).min(CHUNK);
                let mut got = 0usize;
                let ok = ReadProcessMemory(
                    h,
                    (m.base + off) as *const c_void,
                    buf[off as usize..].as_mut_ptr() as *mut c_void,
                    take, Some(&mut got)
                ).is_ok();
                if !ok || got == 0 {
                    failed += 1; total_zero += take as u64;
                } else {
                    total_read += got as u64;
                    if got < take { failed += 1; total_zero += (take - got) as u64; }
                }
                off += take as u64;
            }

            let (fixed_n, was_fixed) = if fix {
                match fix_sections_in_memory_image(&mut buf) {
                    Ok(n) => (n, true),
                    Err(_) => (0, false),
                }
            } else { (0, false) };

            // 默认扩展名按 .dll/.exe/.bin 推断
            let ext = if m.name.to_lowercase().ends_with(".exe") { ".dump.exe" }
                else if m.name.to_lowercase().ends_with(".dll") { ".dump.dll" }
                else { ".dump.bin" };
            let path: PathBuf = match out_path {
                Some(p) => PathBuf::from(p),
                None => dumps_dir()?.join(format!(
                    "{}_{}_{:x}_{}{}",
                    pid,
                    sanitize_filename(&m.name).trim_end_matches(".exe").trim_end_matches(".dll"),
                    m.base, now_secs(), ext
                )),
            };
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).map_err(|e| AppError::Internal(format!("mkdir: {e}")))?;
            }
            std::fs::write(&path, &buf).map_err(|e| AppError::Internal(format!("写 {}: {e}", path.display())))?;
            let _ = windows::Win32::Foundation::CloseHandle(h);

            Ok(DumpModuleResult {
                path: path.display().to_string(),
                module: m.name,
                base: m.base,
                size: m.size,
                fixed: was_fixed,
                sections_fixed: fixed_n,
                bytes_read: total_read,
                bytes_zero_filled: total_zero,
                chunks_failed: failed,
            })
        }
    })
    .await
    .map_err(|e| AppError::Internal(format!("spawn_blocking: {e}")))?
}

// ===== dump_process =====

#[derive(Debug, Deserialize)]
pub struct DumpProcessReq {
    pub pid: u32,
    /// 输出目录; None = dumps/{pid}_proc_{ts}/
    pub out_dir: Option<String>,
    /// 是否包含 MEM_IMAGE 区(模块代码段). 默认 true.
    #[serde(default = "default_true")]
    pub include_images: bool,
    /// 是否包含 MEM_PRIVATE (堆/栈). 默认 true.
    #[serde(default = "default_true")]
    pub include_private: bool,
    /// 是否包含 MEM_MAPPED (文件映射). 默认 false (一般大且无用).
    #[serde(default)]
    pub include_mapped: bool,
}

#[derive(Debug, Serialize)]
pub struct DumpRegionEntry {
    pub file: String,
    pub base: u64,
    pub size: u64,
    pub protect: u32,
    pub mem_type: u32,
    pub bytes_read: u64,
    pub bytes_zero_filled: u64,
}

#[derive(Debug, Serialize)]
pub struct DumpProcessResult {
    pub out_dir: String,
    pub regions_total: u32,
    pub regions_dumped: u32,
    pub total_bytes: u64,
    pub regions: Vec<DumpRegionEntry>,
    pub manifest_path: String,
    pub aborted_reason: Option<String>,
}

#[tauri::command]
pub async fn dbg_dump_process(req: DumpProcessReq) -> AppResult<DumpProcessResult> {
    let pid = req.pid;
    let inc_img = req.include_images;
    let inc_priv = req.include_private;
    let inc_map = req.include_mapped;
    let out_dir = req.out_dir;

    tokio::task::spawn_blocking(move || -> AppResult<DumpProcessResult> {
        unsafe {
            let h = open_for_read(pid)?;
            let out: PathBuf = match out_dir {
                Some(p) => PathBuf::from(p),
                None => dumps_dir()?.join(format!("{}_proc_{}", pid, now_secs())),
            };
            std::fs::create_dir_all(&out).map_err(|e| AppError::Internal(format!("mkdir {}: {e}", out.display())))?;

            const MEM_PRIVATE: u32 = 0x20000;
            const MEM_MAPPED:  u32 = 0x40000;
            const MEM_IMAGE:   u32 = 0x1000000;

            let mut va: u64 = 0;
            let mut regions = Vec::new();
            let mut total_bytes = 0u64;
            let mut regions_total = 0u32;
            let mut regions_dumped = 0u32;
            let mut aborted: Option<String> = None;

            loop {
                let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
                let got = VirtualQueryEx(
                    h,
                    Some(va as *const c_void),
                    &mut mbi,
                    std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                );
                if got == 0 { break; }
                let region_base = mbi.BaseAddress as u64;
                let region_size = mbi.RegionSize as u64;
                let next = region_base.saturating_add(region_size);
                if next <= va { break; }
                va = next;
                if va >= 0x7FFF_FFFFFFFF { break; }

                if mbi.State != MEM_COMMIT { continue; }
                if (mbi.Protect.0 & PAGE_NOACCESS.0) != 0 { continue; }
                if (mbi.Protect.0 & PAGE_GUARD.0) != 0 { continue; }

                let t = mbi.Type.0;
                let is_image = (t & MEM_IMAGE) != 0;
                let is_private = (t & MEM_PRIVATE) != 0;
                let is_mapped = (t & MEM_MAPPED) != 0;
                let include = (is_image && inc_img) || (is_private && inc_priv) || (is_mapped && inc_map);
                regions_total += 1;
                if !include { continue; }

                if total_bytes.saturating_add(region_size) > MAX_PROCESS_TOTAL_BYTES {
                    aborted = Some(format!("达到总上限 {} bytes, 后续区域已跳过", MAX_PROCESS_TOTAL_BYTES));
                    break;
                }

                let file_name = format!("{:016x}_{:x}.bin", region_base, region_size);
                let file_path = out.join(&file_name);
                match read_range_to_file(h, region_base, region_size, &file_path) {
                    Ok((read, zero, _failed)) => {
                        regions_dumped += 1;
                        total_bytes += region_size;
                        regions.push(DumpRegionEntry {
                            file: file_name,
                            base: region_base,
                            size: region_size,
                            protect: mbi.Protect.0,
                            mem_type: t,
                            bytes_read: read,
                            bytes_zero_filled: zero,
                        });
                    }
                    Err(e) => {
                        // 单段失败不致命, 继续
                        let _ = e;
                        continue;
                    }
                }
            }
            let _ = windows::Win32::Foundation::CloseHandle(h);

            let manifest = serde_json::json!({
                "pid": pid,
                "timestamp": now_secs(),
                "regions_total": regions_total,
                "regions_dumped": regions_dumped,
                "total_bytes": total_bytes,
                "regions": regions,
            });
            let manifest_path = out.join("manifest.json");
            std::fs::write(&manifest_path, serde_json::to_string_pretty(&manifest).unwrap_or_default())
                .map_err(|e| AppError::Internal(format!("manifest: {e}")))?;

            Ok(DumpProcessResult {
                out_dir: out.display().to_string(),
                regions_total,
                regions_dumped,
                total_bytes,
                regions,
                manifest_path: manifest_path.display().to_string(),
                aborted_reason: aborted,
            })
        }
    })
    .await
    .map_err(|e| AppError::Internal(format!("spawn_blocking: {e}")))?
}
