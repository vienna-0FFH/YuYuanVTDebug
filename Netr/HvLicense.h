/*
 * HvLicense.h - 内核态网络验证 license 校验
 *
 * 设计要点(2026-06-20):
 *   - GUI 通过御元网络验证 SDK 拿到 token + auth_sig 后,IOCTL_HV_SUBMIT_LICENSE
 *     把全套字段(app_key, subject_type, subject_id, machine_code, expires_at,
 *     token, auth_sig)交给 driver
 *   - driver 内嵌 deploy ed25519 公钥(下方常量),按 yuyuan-protocol 的 canonical
 *     格式拼字符串,ed25519 verify。验签通过 → g_LicenseValid = TRUE
 *   - 业务 IOCTL 调用时先查 g_LicenseValid,FALSE 则返 STATUS_ACCESS_DENIED
 *
 * 安全模型:
 *   - 即便 GUI 被完全破解(跳过登录、伪造 token),driver 这一关没有 deploy 私钥
 *     就构造不出合法 auth_sig,verify 必败 → 所有业务功能拒
 *   - driver 二进制有 /INTEGRITYCHECK 保护,改了公钥常量,Windows 加载器拒载
 *   - 公钥本身公开无所谓,加密学保证只有持有私钥的部署端能签
 */

#pragma once

#include <ntddk.h>

// 来自 GUI 的 license submit 请求
// (METHOD_BUFFERED 即在 SystemBuffer 里,字符串字段必须以 \0 结尾且 ≤ 限定长度)
#pragma pack(push, 1)
typedef struct _HV_LICENSE_REQ {
    CHAR    AppKey[128];        // 应用 key,如 "app_xxxxx"
    CHAR    SubjectType[16];    // "account" 或 "card"
    INT64   SubjectId;          // 业务 ID
    CHAR    MachineCode[128];   // SDK 算出的机器码
    INT64   ExpiresAt;          // Unix 秒到期 (0 = 次数卡)
    CHAR    Token[128];         // 会话 token
    UCHAR   AuthSig[64];        // ed25519 签名 (64 字节, 二进制)
} HV_LICENSE_REQ, *PHV_LICENSE_REQ;

typedef struct _HV_LICENSE_RES {
    NTSTATUS Status;            // STATUS_SUCCESS / STATUS_ACCESS_DENIED / 别的
    INT64    AcceptedAt;        // driver 当前 system time (KeQuerySystemTimePrecise)
} HV_LICENSE_RES, *PHV_LICENSE_RES;
#pragma pack(pop)

// 校验入口。inputBuffer 是 HV_LICENSE_REQ,inputLength 必须 == sizeof(...)。
// 成功返 STATUS_SUCCESS 并设 g_LicenseValid=TRUE;失败保持 FALSE。
NTSTATUS HvLicenseSubmit(
    _In_reads_bytes_(InputLength) PVOID InputBuffer,
    _In_ ULONG InputLength
);

// 业务 IOCTL gate。返 TRUE 才放行业务 dispatch。
BOOLEAN HvLicenseIsValid(VOID);

// DriverUnload 时清空状态(防止 license 残留)
VOID HvLicenseReset(VOID);

// DriverEntry 期跑 ed25519 实现 KAT 自检(RFC 8032 Test 1)
VOID HvLicenseSelfTest(VOID);
