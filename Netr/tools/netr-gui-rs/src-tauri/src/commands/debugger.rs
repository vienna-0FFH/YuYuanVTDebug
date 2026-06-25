use tauri::State;

use crate::ioctl::codes::*;
use crate::ioctl::DeviceState;
use crate::util::error::AppResult;

#[repr(C, packed)]
struct AddDebuggerReq {
    pid: u32,
    process_name: [u16; 260],
    enable_privilege: u8,
    protect_from_terminate: u8,
    hide_from_list: u8,
    _pad: u8,
}

fn write_wstr(dst: &mut [u16], src: &str) {
    let wide: Vec<u16> = src.encode_utf16().collect();
    let n = wide.len().min(dst.len() - 1);
    dst[..n].copy_from_slice(&wide[..n]);
    dst[n] = 0;
}

#[tauri::command]
pub fn debugger_add(
    device: State<'_, DeviceState>,
    pid: u32,
    process_name: String,
    enable_privilege: bool,
    protect_from_terminate: bool,
    hide_from_list: bool,
) -> AppResult<()> {
    let mut name_buf = [0u16; 260];
    write_wstr(&mut name_buf, &process_name);
    let req = AddDebuggerReq {
        pid,
        process_name: name_buf,
        enable_privilege: enable_privilege as u8,
        protect_from_terminate: protect_from_terminate as u8,
        hide_from_list: hide_from_list as u8,
        _pad: 0,
    };

    let buf = unsafe {
        std::slice::from_raw_parts(
            (&req as *const AddDebuggerReq) as *const u8,
            std::mem::size_of::<AddDebuggerReq>(),
        )
    };
    let mut out = [0u8; 16];
    device.ioctl(IOCTL_HV_ADD_DEBUGGER, buf, &mut out)?;
    Ok(())
}

#[tauri::command]
pub fn debugger_remove(device: State<'_, DeviceState>, pid: u32) -> AppResult<()> {
    // driver 期望完整 HV_DEBUGGER_REQUEST 结构 (4 + 520 + 3 字节 + padding),
    // 哪怕 remove 只读 ProcessId. 之前只发 4 字节 → inputLength 不足 →
    // STATUS_INVALID_PARAMETER (0x80070057). 用 AddDebuggerReq 同结构, 余字段 0.
    let req = AddDebuggerReq {
        pid,
        process_name: [0u16; 260],
        enable_privilege: 0,
        protect_from_terminate: 0,
        hide_from_list: 0,
        _pad: 0,
    };
    let buf = unsafe {
        std::slice::from_raw_parts(
            (&req as *const AddDebuggerReq) as *const u8,
            std::mem::size_of::<AddDebuggerReq>(),
        )
    };
    let mut out = [0u8; 16];
    device.ioctl(IOCTL_HV_REMOVE_DEBUGGER, buf, &mut out)?;
    Ok(())
}
