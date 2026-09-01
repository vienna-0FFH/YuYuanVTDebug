//! 全局 device handle state。
//!
//! 设计:
//!   - 启动时不打开(driver 可能没装/没起)
//!   - ServicePage 用户点"打开设备"后调 open_device command
//!   - 业务 command 用 with_device() 拿借用,自动处理"未打开"错
//!   - 关闭(close_device)或 ServicePage 停服务时 None

use parking_lot::Mutex;

use crate::ioctl::device::NetrDevice;
use crate::util::error::{AppError, AppResult};

pub struct DeviceState {
    inner: Mutex<Option<NetrDevice>>,
}

impl DeviceState {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(None),
        }
    }

    /// 打开 driver 设备。已打开时静默返回(幂等)。
    pub fn open(&self) -> AppResult<()> {
        let mut g = self.inner.lock();
        if g.is_some() {
            return Ok(());
        }
        *g = Some(NetrDevice::open()?);
        Ok(())
    }

    pub fn close(&self) {
        let mut g = self.inner.lock();
        g.take(); // Drop 自动 CloseHandle
    }

    pub fn is_open(&self) -> bool {
        self.inner.lock().is_some()
    }

    /// 对 device 借用执行操作。device 未打开时返 NotInitialized。
    pub fn ioctl(&self, code: u32, input: &[u8], output: &mut [u8]) -> AppResult<u32> {
        let g = self.inner.lock();
        let dev = g
            .as_ref()
            .ok_or_else(|| AppError::Io("device not open".into()))?;
        dev.ioctl(code, input, output)
    }
}
