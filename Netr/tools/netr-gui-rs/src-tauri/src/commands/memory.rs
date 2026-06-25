use tauri::State;

use crate::ioctl::codes::*;
use crate::ioctl::DeviceState;
use crate::util::error::AppResult;

#[repr(C, packed)]
struct MemReadReq {
    pid: u32,
    address: u64,
    size: u32,
}

#[tauri::command]
pub fn memory_read(
    device: State<'_, DeviceState>,
    pid: u32,
    address: u64,
    size: u32,
) -> AppResult<Vec<u8>> {
    let req = MemReadReq { pid, address, size };
    let in_buf = unsafe {
        std::slice::from_raw_parts(
            (&req as *const MemReadReq) as *const u8,
            std::mem::size_of::<MemReadReq>(),
        )
    };
    let mut out = vec![0u8; size as usize + 64];
    let n = device.ioctl(IOCTL_HV_MEMORY_READ, in_buf, &mut out)?;
    out.truncate(n as usize);
    Ok(out)
}

#[repr(C, packed)]
struct MemWriteReqHdr {
    pid: u32,
    address: u64,
    size: u32,
}

#[tauri::command]
pub fn memory_write(
    device: State<'_, DeviceState>,
    pid: u32,
    address: u64,
    data: Vec<u8>,
) -> AppResult<()> {
    let hdr = MemWriteReqHdr {
        pid,
        address,
        size: data.len() as u32,
    };
    let mut buf = Vec::with_capacity(std::mem::size_of::<MemWriteReqHdr>() + data.len());
    let hdr_bytes = unsafe {
        std::slice::from_raw_parts(
            (&hdr as *const MemWriteReqHdr) as *const u8,
            std::mem::size_of::<MemWriteReqHdr>(),
        )
    };
    buf.extend_from_slice(hdr_bytes);
    buf.extend_from_slice(&data);

    let mut out = [0u8; 16];
    device.ioctl(IOCTL_HV_MEMORY_WRITE, &buf, &mut out)?;
    Ok(())
}

#[repr(C, packed)]
struct MemAllocReq {
    pid: u32,
    size: u32,
    protect: u32,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct MemAllocResp {
    address: u64,
}

#[tauri::command]
pub fn memory_alloc(
    device: State<'_, DeviceState>,
    pid: u32,
    size: u32,
    protect: u32,
) -> AppResult<u64> {
    let req = MemAllocReq { pid, size, protect };
    let in_buf = unsafe {
        std::slice::from_raw_parts(
            (&req as *const MemAllocReq) as *const u8,
            std::mem::size_of::<MemAllocReq>(),
        )
    };
    let mut out = vec![0u8; std::mem::size_of::<MemAllocResp>()];
    device.ioctl(IOCTL_HV_MEMORY_ALLOC, in_buf, &mut out)?;
    let r: MemAllocResp = unsafe { *(out.as_ptr() as *const MemAllocResp) };
    Ok({ let a = r.address; a })
}

#[repr(C, packed)]
struct MemFreeReq {
    pid: u32,
    address: u64,
}

#[tauri::command]
pub fn memory_free(device: State<'_, DeviceState>, pid: u32, address: u64) -> AppResult<()> {
    let req = MemFreeReq { pid, address };
    let in_buf = unsafe {
        std::slice::from_raw_parts(
            (&req as *const MemFreeReq) as *const u8,
            std::mem::size_of::<MemFreeReq>(),
        )
    };
    let mut out = [0u8; 16];
    device.ioctl(IOCTL_HV_MEMORY_FREE, in_buf, &mut out)?;
    Ok(())
}
