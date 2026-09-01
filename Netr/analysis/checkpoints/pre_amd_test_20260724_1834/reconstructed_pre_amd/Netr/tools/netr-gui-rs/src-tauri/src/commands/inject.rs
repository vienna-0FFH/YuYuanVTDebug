use tauri::State;

use crate::ioctl::codes::*;
use crate::ioctl::DeviceState;
use crate::util::error::{AppError, AppResult};

// Driver.c injection structures are under #pragma pack(push, 1).
const DLL_PATH_WCHARS: usize = 520;
const INJECT_DLL_REQUEST_SIZE: usize = 4 + DLL_PATH_WCHARS * 2 + 3 + 4;
const INJECT_DLL_RESULT_SIZE: usize = 4 + 8 + 4;
const SHELLCODE_MAX: usize = 4096;
const INJECT_SHELLCODE_REQUEST_SIZE: usize = 4 + 4 + 8 + 1 + 1 + SHELLCODE_MAX;
const INJECT_SHELLCODE_RESULT_SIZE: usize = 4 + 8;

const _: [(); 1051] = [(); INJECT_DLL_REQUEST_SIZE];
const _: [(); 16] = [(); INJECT_DLL_RESULT_SIZE];
const _: [(); 4114] = [(); INJECT_SHELLCODE_REQUEST_SIZE];
const _: [(); 12] = [(); INJECT_SHELLCODE_RESULT_SIZE];

fn put_u32(buf: &mut [u8], offset: usize, value: u32) {
    buf[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(buf: &mut [u8], offset: usize, value: u64) {
    buf[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn get_u32(buf: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(buf[offset..offset + 4].try_into().expect("u32 ABI field"))
}

fn resolve_dll_path(dll_path: Option<String>, dll_bytes: Option<Vec<u8>>) -> AppResult<String> {
    if let Some(path) = dll_path.filter(|value| !value.trim().is_empty()) {
        return Ok(path);
    }

    // Compatibility with the old command argument: callers may pass a UTF-8
    // encoded path in dllBytes. Actual DLL image bytes are not this IOCTL's ABI.
    if let Some(bytes) = dll_bytes.filter(|value| !value.is_empty()) {
        return String::from_utf8(bytes).map_err(|_| {
            AppError::Internal(
                "inject_dll expects a DLL path; raw DLL image bytes are not supported by the driver IOCTL"
                    .into(),
            )
        });
    }

    Err(AppError::Internal("DLL path must not be empty".into()))
}

#[tauri::command]
pub fn inject_dll(
    device: State<'_, DeviceState>,
    pid: u32,
    dll_path: Option<String>,
    dll_bytes: Option<Vec<u8>>,
) -> AppResult<()> {
    if pid == 0 {
        return Err(AppError::Internal("target PID must be non-zero".into()));
    }
    let path = resolve_dll_path(dll_path, dll_bytes)?;
    let wide: Vec<u16> = path.encode_utf16().collect();
    if wide.len() >= DLL_PATH_WCHARS {
        return Err(AppError::Internal(format!(
            "DLL path is too long ({} UTF-16 code units; max {})",
            wide.len(),
            DLL_PATH_WCHARS - 1
        )));
    }

    let mut request = vec![0u8; INJECT_DLL_REQUEST_SIZE];
    put_u32(&mut request, 0, pid);
    for (index, value) in wide.iter().enumerate() {
        let offset = 4 + index * 2;
        request[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }
    // HideFromPeb, ErasePeHeader, UseManualMap and StealthLevel remain zero.
    // They are present on the wire and can be exposed by the UI independently.

    let mut output = [0u8; INJECT_DLL_RESULT_SIZE];
    let written = device.ioctl(IOCTL_HV_INJECT_DLL, &request, &mut output)? as usize;
    if written < INJECT_DLL_RESULT_SIZE {
        return Err(AppError::Internal(format!(
            "INJECT_DLL returned a short result ({written} bytes)"
        )));
    }
    let status = get_u32(&output, 0);
    if status != 0 {
        return Err(AppError::Internal(format!(
            "INJECT_DLL failed: driver status={status}"
        )));
    }
    Ok(())
}

#[tauri::command]
pub fn inject_shellcode(
    device: State<'_, DeviceState>,
    pid: u32,
    shellcode: Vec<u8>,
) -> AppResult<()> {
    if pid == 0 {
        return Err(AppError::Internal("target PID must be non-zero".into()));
    }
    if shellcode.is_empty() || shellcode.len() > SHELLCODE_MAX {
        return Err(AppError::Internal(format!(
            "shellcode size must be 1..={SHELLCODE_MAX} bytes"
        )));
    }

    let mut request = vec![0u8; INJECT_SHELLCODE_REQUEST_SIZE];
    put_u32(&mut request, 0, pid);
    put_u32(&mut request, 4, shellcode.len() as u32);
    put_u64(&mut request, 8, 0); // Parameter
    request[16] = 1; // ExecuteImmediately
    request[17] = 0; // HideMemory
    request[18..18 + shellcode.len()].copy_from_slice(&shellcode);

    let mut output = [0u8; INJECT_SHELLCODE_RESULT_SIZE];
    let written = device.ioctl(IOCTL_HV_INJECT_SHELLCODE, &request, &mut output)? as usize;
    if written < INJECT_SHELLCODE_RESULT_SIZE {
        return Err(AppError::Internal(format!(
            "INJECT_SHELLCODE returned a short result ({written} bytes)"
        )));
    }
    let status = get_u32(&output, 0);
    if status != 0 {
        return Err(AppError::Internal(format!(
            "INJECT_SHELLCODE failed: driver status={status}"
        )));
    }
    Ok(())
}
