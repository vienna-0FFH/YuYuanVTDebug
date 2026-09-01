use tauri::State;

use crate::ioctl::codes::*;
use crate::ioctl::DeviceState;
use crate::util::error::{AppError, AppResult};

// Driver.c keeps these structures inside #pragma pack(push, 1).
const LEGACY_PAYLOAD_MAX: usize = 4096;
const EX_PAYLOAD_MAX: usize = 0x10000;
const MEMORY_REQUEST_SIZE: usize = 4 + 8 + 4 + 4 + LEGACY_PAYLOAD_MAX;
const MEMORY_RESULT_SIZE: usize = 4 + 8 + 4 + LEGACY_PAYLOAD_MAX;
const MEMORY_REQUEST_BUFFER_OFFSET: usize = 20;
const MEMORY_RESULT_BUFFER_OFFSET: usize = 16;
const MEMORY_EX_HEADER_SIZE: usize = 24;

const _: [(); 4116] = [(); MEMORY_REQUEST_SIZE];
const _: [(); 4112] = [(); MEMORY_RESULT_SIZE];
const _: [(); 24] = [(); MEMORY_EX_HEADER_SIZE];

fn put_u32(buf: &mut [u8], offset: usize, value: u32) {
    buf[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(buf: &mut [u8], offset: usize, value: u64) {
    buf[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn get_u32(buf: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(buf[offset..offset + 4].try_into().expect("u32 ABI field"))
}

fn get_u64(buf: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(buf[offset..offset + 8].try_into().expect("u64 ABI field"))
}

fn ensure_nt_success(operation: &str, status: u32) -> AppResult<()> {
    if (status as i32) < 0 {
        return Err(AppError::Internal(format!(
            "{operation} failed: NTSTATUS=0x{status:08X}"
        )));
    }
    Ok(())
}

fn legacy_request(pid: u32, address: u64, size: u32, protection: u32) -> Vec<u8> {
    let mut request = vec![0u8; MEMORY_REQUEST_SIZE];
    put_u32(&mut request, 0, pid);
    put_u64(&mut request, 4, address);
    put_u32(&mut request, 12, size);
    put_u32(&mut request, 16, protection);
    request
}

fn ex_request(pid: u32, address: u64, size: u32) -> [u8; MEMORY_EX_HEADER_SIZE] {
    let mut request = [0u8; MEMORY_EX_HEADER_SIZE];
    put_u32(&mut request, 0, pid);
    // offset 4 is Reserved0
    put_u64(&mut request, 8, address);
    put_u32(&mut request, 16, size);
    // offset 20 is Reserved1
    request
}

fn read_legacy(device: &DeviceState, pid: u32, address: u64, size: usize) -> AppResult<Vec<u8>> {
    debug_assert!(size <= LEGACY_PAYLOAD_MAX);
    let request = legacy_request(pid, address, size as u32, 0);
    let mut output = vec![0u8; MEMORY_RESULT_SIZE];
    let written = device.ioctl(IOCTL_HV_MEMORY_READ, &request, &mut output)? as usize;
    if written < MEMORY_RESULT_BUFFER_OFFSET {
        return Err(AppError::Internal(format!(
            "MEMORY_READ returned a short result ({written} bytes)"
        )));
    }

    let status = get_u32(&output, 0);
    ensure_nt_success("MEMORY_READ", status)?;
    let returned_address = get_u64(&output, 4);
    let transferred = get_u32(&output, 12) as usize;
    if returned_address != address || transferred > size || transferred > LEGACY_PAYLOAD_MAX {
        return Err(AppError::Internal("MEMORY_READ returned an invalid result header".into()));
    }

    Ok(output[MEMORY_RESULT_BUFFER_OFFSET..MEMORY_RESULT_BUFFER_OFFSET + transferred].to_vec())
}

fn read_ex(device: &DeviceState, pid: u32, address: u64, size: usize) -> AppResult<Vec<u8>> {
    debug_assert!(size <= EX_PAYLOAD_MAX);
    let request = ex_request(pid, address, size as u32);
    let mut output = vec![0u8; MEMORY_EX_HEADER_SIZE + size];
    let written = device.ioctl(IOCTL_HV_MEMORY_READ_EX, &request, &mut output)? as usize;
    if written < MEMORY_EX_HEADER_SIZE {
        return Err(AppError::Internal(format!(
            "MEMORY_READ_EX returned a short result ({written} bytes)"
        )));
    }

    let status = get_u32(&output, 0);
    ensure_nt_success("MEMORY_READ_EX", status)?;
    let returned_address = get_u64(&output, 8);
    let transferred = get_u32(&output, 16) as usize;
    if returned_address != address
        || transferred > size
        || MEMORY_EX_HEADER_SIZE + transferred > written
    {
        return Err(AppError::Internal("MEMORY_READ_EX returned an invalid result header".into()));
    }

    Ok(output[MEMORY_EX_HEADER_SIZE..MEMORY_EX_HEADER_SIZE + transferred].to_vec())
}

pub(crate) fn memory_read_impl(
    device: &DeviceState,
    pid: u32,
    address: u64,
    size: u32,
) -> AppResult<Vec<u8>> {
    if pid == 0 || address == 0 {
        return Err(AppError::Internal("pid and address must be non-zero".into()));
    }
    if size == 0 {
        return Ok(Vec::new());
    }

    let mut result = Vec::with_capacity(size as usize);
    let mut remaining = size as usize;
    let mut current = address;
    while remaining != 0 {
        let chunk_size = if remaining <= LEGACY_PAYLOAD_MAX {
            remaining
        } else {
            remaining.min(EX_PAYLOAD_MAX)
        };
        let chunk = if chunk_size <= LEGACY_PAYLOAD_MAX {
            read_legacy(device, pid, current, chunk_size)?
        } else {
            read_ex(device, pid, current, chunk_size)?
        };
        if chunk.len() != chunk_size {
            return Err(AppError::Internal(format!(
                "memory read was partial at 0x{current:X}: {}/{} bytes",
                chunk.len(), chunk_size
            )));
        }
        result.extend_from_slice(&chunk);
        current = current
            .checked_add(chunk_size as u64)
            .ok_or_else(|| AppError::Internal("memory read address overflow".into()))?;
        remaining -= chunk_size;
    }
    Ok(result)
}

#[tauri::command]
pub fn memory_read(
    device: State<'_, DeviceState>,
    pid: u32,
    address: u64,
    size: u32,
) -> AppResult<Vec<u8>> {
    memory_read_impl(device.inner(), pid, address, size)
}

fn write_legacy(device: &DeviceState, pid: u32, address: u64, data: &[u8]) -> AppResult<()> {
    debug_assert!(data.len() <= LEGACY_PAYLOAD_MAX);
    let mut request = legacy_request(pid, address, data.len() as u32, 0);
    request[MEMORY_REQUEST_BUFFER_OFFSET..MEMORY_REQUEST_BUFFER_OFFSET + data.len()]
        .copy_from_slice(data);

    let mut output = vec![0u8; MEMORY_RESULT_SIZE];
    let written = device.ioctl(IOCTL_HV_MEMORY_WRITE, &request, &mut output)? as usize;
    if written < MEMORY_RESULT_BUFFER_OFFSET {
        return Err(AppError::Internal(format!(
            "MEMORY_WRITE returned a short result ({written} bytes)"
        )));
    }
    let status = get_u32(&output, 0);
    ensure_nt_success("MEMORY_WRITE", status)?;
    let transferred = get_u32(&output, 12) as usize;
    if get_u64(&output, 4) != address || transferred != data.len() {
        return Err(AppError::Internal(format!(
            "MEMORY_WRITE was partial: {transferred}/{} bytes",
            data.len()
        )));
    }
    Ok(())
}

fn write_ex(device: &DeviceState, pid: u32, address: u64, data: &[u8]) -> AppResult<()> {
    debug_assert!(data.len() <= EX_PAYLOAD_MAX);
    let header = ex_request(pid, address, data.len() as u32);
    let mut request = Vec::with_capacity(MEMORY_EX_HEADER_SIZE + data.len());
    request.extend_from_slice(&header);
    request.extend_from_slice(data);

    let mut output = [0u8; MEMORY_EX_HEADER_SIZE];
    let written = device.ioctl(IOCTL_HV_MEMORY_WRITE_EX, &request, &mut output)? as usize;
    if written < MEMORY_EX_HEADER_SIZE {
        return Err(AppError::Internal(format!(
            "MEMORY_WRITE_EX returned a short result ({written} bytes)"
        )));
    }
    let status = get_u32(&output, 0);
    ensure_nt_success("MEMORY_WRITE_EX", status)?;
    let transferred = get_u32(&output, 16) as usize;
    if get_u64(&output, 8) != address || transferred != data.len() {
        return Err(AppError::Internal(format!(
            "MEMORY_WRITE_EX was partial: {transferred}/{} bytes",
            data.len()
        )));
    }
    Ok(())
}

pub(crate) fn memory_write_impl(
    device: &DeviceState,
    pid: u32,
    address: u64,
    data: Vec<u8>,
) -> AppResult<()> {
    if pid == 0 || address == 0 {
        return Err(AppError::Internal("pid and address must be non-zero".into()));
    }
    if data.is_empty() {
        return Ok(());
    }

    let mut offset = 0usize;
    while offset < data.len() {
        let remaining = data.len() - offset;
        let chunk_size = if remaining <= LEGACY_PAYLOAD_MAX {
            remaining
        } else {
            remaining.min(EX_PAYLOAD_MAX)
        };
        let current = address
            .checked_add(offset as u64)
            .ok_or_else(|| AppError::Internal("memory write address overflow".into()))?;
        let chunk = &data[offset..offset + chunk_size];
        if chunk_size <= LEGACY_PAYLOAD_MAX {
            write_legacy(device, pid, current, chunk)?;
        } else {
            write_ex(device, pid, current, chunk)?;
        }
        offset += chunk_size;
    }
    Ok(())
}

#[tauri::command]
pub fn memory_write(
    device: State<'_, DeviceState>,
    pid: u32,
    address: u64,
    data: Vec<u8>,
) -> AppResult<()> {
    memory_write_impl(device.inner(), pid, address, data)
}

#[tauri::command]
pub fn memory_alloc(
    device: State<'_, DeviceState>,
    pid: u32,
    size: u32,
    protect: u32,
) -> AppResult<u64> {
    if pid == 0 || size == 0 {
        return Err(AppError::Internal("pid and allocation size must be non-zero".into()));
    }
    let request = legacy_request(pid, 0, size, protect);
    let mut output = vec![0u8; MEMORY_RESULT_SIZE];
    let written = device.ioctl(IOCTL_HV_MEMORY_ALLOC, &request, &mut output)? as usize;
    if written < MEMORY_RESULT_BUFFER_OFFSET {
        return Err(AppError::Internal(format!(
            "MEMORY_ALLOC returned a short result ({written} bytes)"
        )));
    }
    ensure_nt_success("MEMORY_ALLOC", get_u32(&output, 0))?;
    let address = get_u64(&output, 4);
    if address == 0 {
        return Err(AppError::Internal("MEMORY_ALLOC returned a null address".into()));
    }
    Ok(address)
}

#[tauri::command]
pub fn memory_free(device: State<'_, DeviceState>, pid: u32, address: u64) -> AppResult<()> {
    if pid == 0 || address == 0 {
        return Err(AppError::Internal("pid and address must be non-zero".into()));
    }
    let request = legacy_request(pid, address, 0, 0);
    let mut output = [];
    device.ioctl(IOCTL_HV_MEMORY_FREE, &request, &mut output)?;
    Ok(())
}
