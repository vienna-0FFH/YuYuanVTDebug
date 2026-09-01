//! Driver 设备封装。
//!
//! 设备名(\\.\<random16>)在 driver 启动时随机生成,写入注册表
//! HKLM\Software\NetrSvc\DeviceName。GUI 用 RegOpenKey 读这个值,然后
//! CreateFile 打开 `\\?\<DeviceName>`,后续 DeviceIoControl 调用都用这个 handle。
//!
//! Phase 2 阶段仅需:打开设备 + ioctl(SUBMIT_LICENSE)。Phase 3 扩展更多方法。

use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, GENERIC_READ, GENERIC_WRITE, HANDLE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows::Win32::System::IO::DeviceIoControl;
use windows::Win32::System::Registry::{
    RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY, HKEY_LOCAL_MACHINE, KEY_READ, REG_VALUE_TYPE,
};

use crate::util::error::{AppError, AppResult};

/// 从注册表读 driver 当前会话生成的设备名(16 字符)。
fn read_device_name_from_registry() -> AppResult<String> {
    let subkey = wide_str("Software\\NetrSvc");
    let value = wide_str("DeviceName");

    let mut hkey = HKEY::default();
    unsafe {
        RegOpenKeyExW(HKEY_LOCAL_MACHINE, PCWSTR(subkey.as_ptr()), 0, KEY_READ, &mut hkey)
            .ok()
            .map_err(|e| AppError::Io(format!("RegOpenKeyEx NetrSvc: {e}")))?;
    }

    let mut buf = [0u16; 64];
    let mut len = (buf.len() * 2) as u32;
    let mut ty = REG_VALUE_TYPE(0);

    let r = unsafe {
        RegQueryValueExW(
            hkey,
            PCWSTR(value.as_ptr()),
            None,
            Some(&mut ty),
            Some(buf.as_mut_ptr() as *mut u8),
            Some(&mut len),
        )
    };
    unsafe {
        let _ = RegCloseKey(hkey);
    }
    r.ok()
        .map_err(|e| AppError::Io(format!("RegQueryValueEx DeviceName: {e}")))?;

    // len 是字节数,wchars 是 len/2,去掉末尾 \0
    let wchar_count = (len / 2).saturating_sub(1) as usize;
    let s = OsString::from_wide(&buf[..wchar_count])
        .into_string()
        .map_err(|_| AppError::Io("DeviceName non-utf16".into()))?;
    Ok(s)
}

/// 打开驱动设备 handle。Phase 2 用法:open → ioctl → drop(自动 close)。
pub struct NetrDevice {
    handle: HANDLE,
}

impl NetrDevice {
    /// 自动从注册表读 DeviceName 然后打开。失败原因通常是 driver 未启动。
    pub fn open() -> AppResult<Self> {
        let name = read_device_name_from_registry()?;
        // 设备路径: \\.\<DeviceName>
        let path = format!("\\\\.\\{name}");
        let wide = wide_str(&path);

        let handle = unsafe {
            CreateFileW(
                PCWSTR(wide.as_ptr()),
                GENERIC_READ.0 | GENERIC_WRITE.0,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                None,
            )
        }
        .map_err(|e| AppError::Io(format!("CreateFile {path}: {e}")))?;

        if handle.is_invalid() {
            return Err(AppError::Io(format!("CreateFile {path}: INVALID_HANDLE")));
        }

        Ok(NetrDevice { handle })
    }

    /// 发起一次 DeviceIoControl。
    /// `input` 整块传入,`output` 整块接收(METHOD_BUFFERED 下两者共用 SystemBuffer)。
    /// 返回实际写到 output 的字节数。
    pub fn ioctl(&self, code: u32, input: &[u8], output: &mut [u8]) -> AppResult<u32> {
        let mut bytes_returned: u32 = 0;
        unsafe {
            DeviceIoControl(
                self.handle,
                code,
                Some(input.as_ptr() as *const _),
                input.len() as u32,
                Some(output.as_mut_ptr() as *mut _),
                output.len() as u32,
                Some(&mut bytes_returned),
                None,
            )
        }
        .map_err(|e| AppError::Io(format!("DeviceIoControl 0x{code:X}: {e}")))?;
        Ok(bytes_returned)
    }
}

impl Drop for NetrDevice {
    fn drop(&mut self) {
        if !self.handle.is_invalid() {
            unsafe {
                let _ = CloseHandle(self.handle);
            }
        }
    }
}

// 安全:NetrDevice 持有 Windows HANDLE,handle 本身是线程安全的(WinAPI 保证),
// 但我们在主路径 lock 串行调用,无并发问题。这里手动 impl Send/Sync 让它能进
// tauri::State 内 Mutex(Mutex 要求 Send)。
unsafe impl Send for NetrDevice {}
unsafe impl Sync for NetrDevice {}

fn wide_str(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}
