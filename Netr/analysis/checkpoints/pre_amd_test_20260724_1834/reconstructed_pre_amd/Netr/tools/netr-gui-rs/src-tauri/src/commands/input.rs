use tauri::State;

use crate::ioctl::codes::*;
use crate::ioctl::DeviceState;
use crate::util::error::{AppError, AppResult};

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

#[tauri::command]
pub fn input_send_key(
    device: State<'_, DeviceState>,
    scancode: u16,
    is_extended: bool,
    is_break: bool,
) -> AppResult<()> {
    let scancode = u8::try_from(scancode)
        .map_err(|_| AppError::Internal("scancode must fit in the driver's UCHAR field".into()))?;

    // HV_INPUT_KEY_REQUEST is pack(1): four UCHAR fields.
    let request = [
        scancode,
        u8::from(is_extended),
        u8::from(is_break),
        0, // AutoBreak: the existing UI sends explicit key-up requests.
    ];
    let mut out = [0u8; 16];
    device.ioctl(IOCTL_HV_INPUT_SEND_KEY, &request, &mut out)?;
    Ok(())
}

#[tauri::command]
pub fn input_send_mouse(
    device: State<'_, DeviceState>,
    dx: i32,
    dy: i32,
    buttons: u32,
    wheel: i32,
) -> AppResult<()> {
    let dx = i16::try_from(dx)
        .map_err(|_| AppError::Internal("mouse dx must fit in the driver's SHORT field".into()))?;
    let dy = i16::try_from(dy)
        .map_err(|_| AppError::Internal("mouse dy must fit in the driver's SHORT field".into()))?;
    let buttons = u8::try_from(buttons)
        .map_err(|_| AppError::Internal("mouse buttons must fit in the driver's UCHAR field".into()))?;
    if wheel != 0 {
        return Err(AppError::Internal(
            "the current HV_INPUT_MOUSE_REQUEST ABI has no wheel field".into(),
        ));
    }

    // HV_INPUT_MOUSE_REQUEST is pack(1): SHORT, SHORT, UCHAR, UCHAR, Reserved[2].
    let mut request = [0u8; 8];
    request[0..2].copy_from_slice(&dx.to_le_bytes());
    request[2..4].copy_from_slice(&dy.to_le_bytes());
    request[4] = buttons;
    request[5] = 0; // Smooth
    let mut out = [0u8; 16];
    device.ioctl(IOCTL_HV_INPUT_SEND_MOUSE, &request, &mut out)?;
    Ok(())
}
