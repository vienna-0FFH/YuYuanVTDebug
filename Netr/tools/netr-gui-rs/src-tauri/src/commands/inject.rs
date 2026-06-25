use tauri::State;

use crate::ioctl::codes::*;
use crate::ioctl::DeviceState;
use crate::util::error::AppResult;

#[repr(C, packed)]
struct InjectDllReqHdr {
    pid: u32,
    dll_size: u32,
}

#[tauri::command]
pub fn inject_dll(
    device: State<'_, DeviceState>,
    pid: u32,
    dll_bytes: Vec<u8>,
) -> AppResult<()> {
    let hdr = InjectDllReqHdr {
        pid,
        dll_size: dll_bytes.len() as u32,
    };
    let mut buf = Vec::with_capacity(std::mem::size_of::<InjectDllReqHdr>() + dll_bytes.len());
    let hb = unsafe {
        std::slice::from_raw_parts(
            (&hdr as *const InjectDllReqHdr) as *const u8,
            std::mem::size_of::<InjectDllReqHdr>(),
        )
    };
    buf.extend_from_slice(hb);
    buf.extend_from_slice(&dll_bytes);

    let mut out = [0u8; 32];
    device.ioctl(IOCTL_HV_INJECT_DLL, &buf, &mut out)?;
    Ok(())
}

#[repr(C, packed)]
struct InjectShellcodeReqHdr {
    pid: u32,
    sc_size: u32,
}

#[tauri::command]
pub fn inject_shellcode(
    device: State<'_, DeviceState>,
    pid: u32,
    shellcode: Vec<u8>,
) -> AppResult<()> {
    let hdr = InjectShellcodeReqHdr {
        pid,
        sc_size: shellcode.len() as u32,
    };
    let mut buf = Vec::with_capacity(std::mem::size_of::<InjectShellcodeReqHdr>() + shellcode.len());
    let hb = unsafe {
        std::slice::from_raw_parts(
            (&hdr as *const InjectShellcodeReqHdr) as *const u8,
            std::mem::size_of::<InjectShellcodeReqHdr>(),
        )
    };
    buf.extend_from_slice(hb);
    buf.extend_from_slice(&shellcode);

    let mut out = [0u8; 32];
    device.ioctl(IOCTL_HV_INJECT_SHELLCODE, &buf, &mut out)?;
    Ok(())
}
