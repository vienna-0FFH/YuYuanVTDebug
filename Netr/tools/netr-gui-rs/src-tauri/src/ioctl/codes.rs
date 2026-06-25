//! Driver IOCTL 码常量。与 Netr/Driver.c 同步。
//!
//! 计算公式(Win32 CTL_CODE):
//!   CTL_CODE(DeviceType, Function, Method, Access)
//!   = (DeviceType << 16) | (Access << 14) | (Function << 2) | Method
//!
//! 我们的 driver 都用:
//!   DeviceType = FILE_DEVICE_UNKNOWN (0x22)
//!   Method     = METHOD_BUFFERED (0)
//!   Access     = FILE_ANY_ACCESS (0)
//!
//! Driver.c 用 `CTL_CODE(_, HV_IOCTL_BASE + 0xXX, _, _)`,
//! HV_IOCTL_BASE = 0x800 是 function code 的起点(不是已 <<2 的偏移)。
//! 所以 GUI 必须 (Func + 0x800) << 2 才能与 driver 对齐。
//! 错算曾导致 0x22041C 与 driver 期望的 0x22241C 不一致 → 全部 IOCTL gate 拒绝。

#![allow(dead_code)] // Phase 3 之前部分常量未使用,先全部列出

/// HV_IOCTL_BASE,与 Driver.c 同步
const HV_IOCTL_BASE: u32 = 0x800;

const fn ctl_code(function: u32) -> u32 {
    (0x22u32 << 16) | ((HV_IOCTL_BASE + function) << 2)
}

// 与 Driver.c 同步(HV_IOCTL_BASE + 0x00..0x107)
pub const IOCTL_HV_GET_STATUS: u32 = ctl_code(0x00);
pub const IOCTL_HV_DISABLE_DSE: u32 = ctl_code(0x10);
pub const IOCTL_HV_ENABLE_DSE: u32 = ctl_code(0x11);
pub const IOCTL_HV_GET_DSE_STATUS: u32 = ctl_code(0x12);
pub const IOCTL_HV_HIDE_PROCESS: u32 = ctl_code(0x20);
pub const IOCTL_HV_UNHIDE_PROCESS: u32 = ctl_code(0x21);
pub const IOCTL_HV_HIDE_DRIVER: u32 = ctl_code(0x30);
pub const IOCTL_HV_UNHIDE_DRIVER: u32 = ctl_code(0x31);
pub const IOCTL_HV_ADD_DEBUGGER: u32 = ctl_code(0x40);
pub const IOCTL_HV_REMOVE_DEBUGGER: u32 = ctl_code(0x41);
pub const IOCTL_HV_PROTECT_PROCESS: u32 = ctl_code(0x43);
pub const IOCTL_HV_UNPROTECT_PROCESS: u32 = ctl_code(0x44);
pub const IOCTL_HV_ENABLE_ACCESS_BYPASS: u32 = ctl_code(0x4A);
pub const IOCTL_HV_DISABLE_ACCESS_BYPASS: u32 = ctl_code(0x4B);
pub const IOCTL_HV_INPUT_ENABLE: u32 = ctl_code(0x4C);
pub const IOCTL_HV_INPUT_DISABLE: u32 = ctl_code(0x4D);
pub const IOCTL_HV_INPUT_SEND_KEY: u32 = ctl_code(0x4E);
pub const IOCTL_HV_INPUT_SEND_MOUSE: u32 = ctl_code(0x4F);
pub const IOCTL_HV_ENABLE_ANTIANTIDEBUG: u32 = ctl_code(0x50);
pub const IOCTL_HV_DISABLE_ANTIANTIDEBUG: u32 = ctl_code(0x51);
pub const IOCTL_HV_MEMORY_READ: u32 = ctl_code(0x80);
pub const IOCTL_HV_MEMORY_WRITE: u32 = ctl_code(0x81);
pub const IOCTL_HV_MEMORY_ALLOC: u32 = ctl_code(0x82);
pub const IOCTL_HV_MEMORY_FREE: u32 = ctl_code(0x83);
pub const IOCTL_HV_ENUMERATE_MODULES: u32 = ctl_code(0x84);
pub const IOCTL_HV_INJECT_DLL: u32 = ctl_code(0x60);
pub const IOCTL_HV_INJECT_SHELLCODE: u32 = ctl_code(0x70);
pub const IOCTL_HV_DBG_SET_HWBP: u32 = ctl_code(0x100);
pub const IOCTL_HV_DBG_CLEAR_HWBP: u32 = ctl_code(0x101);
pub const IOCTL_HV_GET_DBGEVT: u32 = ctl_code(0x106);
pub const IOCTL_HV_DBG_SW_BP_ADD: u32 = ctl_code(0x108);
pub const IOCTL_HV_DBG_SW_BP_DEL: u32 = ctl_code(0x109);
pub const IOCTL_HV_DBG_STEP_ARM:  u32 = ctl_code(0x10A);

// Phase 2: 网络验证 license 提交
pub const IOCTL_HV_SUBMIT_LICENSE: u32 = ctl_code(0x107);
