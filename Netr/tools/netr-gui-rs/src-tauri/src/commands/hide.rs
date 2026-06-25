use tauri::State;

use crate::ioctl::codes::*;
use crate::ioctl::DeviceState;
use crate::util::error::AppResult;

#[tauri::command]
pub fn hide_process(device: State<'_, DeviceState>, pid: u32) -> AppResult<()> {
    let buf = pid.to_le_bytes();
    let mut out = [0u8; 16];
    device.ioctl(IOCTL_HV_HIDE_PROCESS, &buf, &mut out)?;
    Ok(())
}

#[tauri::command]
pub fn unhide_process(device: State<'_, DeviceState>, pid: u32) -> AppResult<()> {
    let buf = pid.to_le_bytes();
    let mut out = [0u8; 16];
    device.ioctl(IOCTL_HV_UNHIDE_PROCESS, &buf, &mut out)?;
    Ok(())
}

#[tauri::command]
pub fn hide_driver(device: State<'_, DeviceState>, name: String) -> AppResult<()> {
    // 协议 name 是 UTF-16,固定 260 字符
    let mut buf = [0u8; 260 * 2];
    let wide: Vec<u16> = name.encode_utf16().take(259).collect();
    for (i, w) in wide.iter().enumerate() {
        buf[i * 2] = (*w & 0xFF) as u8;
        buf[i * 2 + 1] = (*w >> 8) as u8;
    }
    let mut out = [0u8; 16];
    device.ioctl(IOCTL_HV_HIDE_DRIVER, &buf, &mut out)?;
    Ok(())
}

#[tauri::command]
pub fn unhide_driver(device: State<'_, DeviceState>, name: String) -> AppResult<()> {
    let mut buf = [0u8; 260 * 2];
    let wide: Vec<u16> = name.encode_utf16().take(259).collect();
    for (i, w) in wide.iter().enumerate() {
        buf[i * 2] = (*w & 0xFF) as u8;
        buf[i * 2 + 1] = (*w >> 8) as u8;
    }
    let mut out = [0u8; 16];
    device.ioctl(IOCTL_HV_UNHIDE_DRIVER, &buf, &mut out)?;
    Ok(())
}
