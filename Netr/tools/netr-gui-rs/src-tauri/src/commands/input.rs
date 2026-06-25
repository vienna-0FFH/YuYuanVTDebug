use tauri::State;

use crate::ioctl::codes::*;
use crate::ioctl::DeviceState;
use crate::util::error::AppResult;

#[tauri::command]
pub fn input_enable(device: State<'_, DeviceState>) -> AppResult<()> {
    let mut out = [0u8; 16];
    device.ioctl(IOCTL_HV_INPUT_ENABLE, &[], &mut out)?;
    Ok(())
}

#[tauri::command]
pub fn input_disable(device: State<'_, DeviceState>) -> AppResult<()> {
    let mut out = [0u8; 16];
    device.ioctl(IOCTL_HV_INPUT_DISABLE, &[], &mut out)?;
    Ok(())
}

#[repr(C, packed)]
struct InputKeyReq {
    scancode: u16,
    is_extended: u8,
    is_break: u8,  // 0=down, 1=up
}

#[tauri::command]
pub fn input_send_key(
    device: State<'_, DeviceState>,
    scancode: u16,
    is_extended: bool,
    is_break: bool,
) -> AppResult<()> {
    let req = InputKeyReq {
        scancode,
        is_extended: is_extended as u8,
        is_break: is_break as u8,
    };
    let buf = unsafe {
        std::slice::from_raw_parts(
            (&req as *const InputKeyReq) as *const u8,
            std::mem::size_of::<InputKeyReq>(),
        )
    };
    let mut out = [0u8; 16];
    device.ioctl(IOCTL_HV_INPUT_SEND_KEY, buf, &mut out)?;
    Ok(())
}

#[repr(C, packed)]
struct InputMouseReq {
    dx: i32,
    dy: i32,
    buttons: u32,  // bit0=L, bit1=R, bit2=M
    wheel: i32,
}

#[tauri::command]
pub fn input_send_mouse(
    device: State<'_, DeviceState>,
    dx: i32,
    dy: i32,
    buttons: u32,
    wheel: i32,
) -> AppResult<()> {
    let req = InputMouseReq { dx, dy, buttons, wheel };
    let buf = unsafe {
        std::slice::from_raw_parts(
            (&req as *const InputMouseReq) as *const u8,
            std::mem::size_of::<InputMouseReq>(),
        )
    };
    let mut out = [0u8; 16];
    device.ioctl(IOCTL_HV_INPUT_SEND_MOUSE, buf, &mut out)?;
    Ok(())
}
