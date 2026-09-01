//! Driver IOCTL 的 C struct 镜像。
//!
//! 用 #[repr(C, packed)] 与 driver 端 #pragma pack(push, 1) 对齐。

use serde::Serialize;

/// HV_LICENSE_REQ (driver HvLicense.h)
///
/// 严格 C 内存布局:
///   AppKey[128] | SubjectType[16] | SubjectId(i64) | MachineCode[128] |
///   ExpiresAt(i64) | Token[128] | AuthSig[64]
///
/// 字符串字段定长,NUL 填充到末尾。driver 端会强制 NUL 终结(最后一字节 = 0)。
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct HvLicenseReq {
    pub app_key: [u8; 128],
    pub subject_type: [u8; 16],
    pub subject_id: i64,
    pub machine_code: [u8; 128],
    pub expires_at: i64,
    pub token: [u8; 128],
    pub auth_sig: [u8; 64],
}

impl HvLicenseReq {
    pub fn zeroed() -> Self {
        Self {
            app_key: [0; 128],
            subject_type: [0; 16],
            subject_id: 0,
            machine_code: [0; 128],
            expires_at: 0,
            token: [0; 128],
            auth_sig: [0; 64],
        }
    }
}

/// HV_LICENSE_RES (driver HvLicense.h)
#[repr(C, packed)]
#[derive(Clone, Copy, Debug, Serialize)]
pub struct HvLicenseRes {
    pub status: i32,
    pub accepted_at: i64,
}

/// 写定长字符串字段(把 src 的字节填进 dst,后面填 0,不越界)
pub fn fill_cstr(dst: &mut [u8], src: &str) {
    let bytes = src.as_bytes();
    let n = bytes.len().min(dst.len() - 1);
    dst[..n].copy_from_slice(&bytes[..n]);
    dst[n] = 0;
    for i in n + 1..dst.len() {
        dst[i] = 0;
    }
}
