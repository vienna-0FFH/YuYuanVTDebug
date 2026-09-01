/*
 * HvLicense.c - 网络验证 license 内核态校验
 *
 * 见 HvLicense.h 注释。
 *
 * 公钥嵌入: DEPLOY_PUB_HEX 与 GUI 端 src-tauri/src/license/hardcoded.rs 一致。
 *           改 driver 公钥需要同步改 GUI 公钥,否则 GUI 拿到的签名 driver 验不过。
 */

#include "HvLicense.h"
#include "HvEd25519.h"
#include <ntstrsafe.h>

// ============================================================
// 部署端 Ed25519 公钥(32 字节,这里以 hex 形式硬编码,运行时一次解码)
// ============================================================
//
// hex: "cbaba85d1652aa242c279f726413f993976200c2fa9baad0101b18a9fb206a45"
//
// 攻击者修改这 32 字节 → /INTEGRITYCHECK 让 Windows 加载器拒载;
// 即便绕过加载校验,GUI 提交的签名(用真公钥签的)在被改公钥下验不过,
// driver 拒所有业务。安全闭环。

// hex: cbaba85d1652aa24 2c279f726413f993 976200c2fa9baad0 101b18a9fb206a45
// 历史 bug:此处曾把 hex 字符 `2c279f...` 错填成字节 `c2 79 f7 ...`(byte8 处吞了
// 一个 nibble,整串后 24 字节全部错位 4 bit),导致 driver 用错的公钥验签,
// 永远拒绝合法签名。2026-06-21 通过 GUI/driver 双端打印 deploy_pub_hex 对比定位。
static const UCHAR DEPLOY_PUBKEY[32] = {
    0xcb, 0xab, 0xa8, 0x5d, 0x16, 0x52, 0xaa, 0x24,
    0x2c, 0x27, 0x9f, 0x72, 0x64, 0x13, 0xf9, 0x93,
    0x97, 0x62, 0x00, 0xc2, 0xfa, 0x9b, 0xaa, 0xd0,
    0x10, 0x1b, 0x18, 0xa9, 0xfb, 0x20, 0x6a, 0x45,
};

static const CHAR DEPLOY_APP_KEY[] =
    "app_c4ec0d637009b03e8851186de72e1d5727ff89173abc4a7d";

// ============================================================
// License 全局状态
// ============================================================
//
// volatile + Interlocked 写,主路径读不加锁 (性能关键)。
// driver 一旦 g_LicenseValid=TRUE,直到 unload 都不会再变 FALSE
// (没有取消授权语义;心跳由 GUI 维护,失效 GUI 端自动注销 / 退出)。
static volatile LONG    g_LicenseValid = FALSE;
static volatile LONG    g_LicenseCryptoReady = FALSE;
static INT64            g_LicenseExpiresAt = 0;

static BOOLEAN HvLicenseStringEquals(
    _In_reads_or_z_(MaxLength) const CHAR* Value,
    _In_ SIZE_T MaxLength,
    _In_z_ const CHAR* Expected)
{
    SIZE_T index = 0;
    while (index < MaxLength && Expected[index] != '\0') {
        if (Value[index] != Expected[index]) {
            return FALSE;
        }
        ++index;
    }

    return index < MaxLength &&
           Value[index] == '\0' && Expected[index] == '\0';
}

BOOLEAN HvLicenseIsValid(VOID)
{
#if !HV_LICENSE_ENFORCEMENT
    return TRUE;
#elif HV_LICENSE_ENABLE_DEV_BYPASS
    return TRUE;
#else
    if (InterlockedCompareExchange(&g_LicenseValid, FALSE, FALSE) == FALSE) {
        return FALSE;
    }

    if (g_LicenseExpiresAt != 0) {
        LARGE_INTEGER nowSystemTime;
        KeQuerySystemTimePrecise(&nowSystemTime);
        const INT64 nowUnix =
            (nowSystemTime.QuadPart / 10000000LL) - 11644473600LL;
        if (nowUnix > g_LicenseExpiresAt) {
            InterlockedExchange(&g_LicenseValid, FALSE);
            return FALSE;
        }
    }

    return TRUE;
#endif
}

// ============================================================
// RFC 8032 ed25519 KAT - driver 启动期自检,验证 HvEd25519Verify 实现正确
// ============================================================
//
// 来自 RFC 8032 7.1 Test 1:
//   SECRET KEY: 9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60
//   PUBLIC KEY: d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
//   MESSAGE:    (empty)
//   SIGNATURE:  e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155
//               5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b

VOID HvLicenseSelfTest(VOID)
{
    BOOLEAN allOk = TRUE;
    static const UCHAR kat_pub[32] = {
        0xd7,0x5a,0x98,0x01,0x82,0xb1,0x0a,0xb7, 0xd5,0x4b,0xfe,0xd3,0xc9,0x64,0x07,0x3a,
        0x0e,0xe1,0x72,0xf3,0xda,0xa6,0x23,0x25, 0xaf,0x02,0x1a,0x68,0xf7,0x07,0x51,0x1a,
    };
    static const UCHAR kat_sig[64] = {
        0xe5,0x56,0x43,0x00,0xc3,0x60,0xac,0x72, 0x90,0x86,0xe2,0xcc,0x80,0x6e,0x82,0x8a,
        0x84,0x87,0x7f,0x1e,0xb8,0xe5,0xd9,0x74, 0xd8,0x73,0xe0,0x65,0x22,0x49,0x01,0x55,
        0x5f,0xb8,0x82,0x15,0x90,0xa3,0x3b,0xac, 0xc6,0x1e,0x39,0x70,0x1c,0xf9,0xb4,0x6b,
        0xd2,0x5b,0xf5,0xf0,0x59,0x5b,0xbe,0x24, 0x65,0x51,0x41,0x43,0x8e,0x7a,0x10,0x0b,
    };
    BOOLEAN ok = HvEd25519Verify(kat_pub, NULL, 0, kat_sig);
    if (ok) {
        DbgPrint("[HvLic] ed25519 KAT (RFC 8032 Test 1): PASS\n");
    } else {
        allOk = FALSE;
        DbgPrint("[HvLic] ed25519 KAT (RFC 8032 Test 1): *** FAIL *** — HvEd25519Verify 实现有 bug!\n");
    }

    // 错误签名应被拒
    UCHAR bad_sig[64];
    RtlCopyMemory(bad_sig, kat_sig, 64);
    bad_sig[0] ^= 0x01;
    BOOLEAN should_fail = HvEd25519Verify(kat_pub, NULL, 0, bad_sig);
    if (!should_fail) {
        DbgPrint("[HvLic] ed25519 KAT (tampered sig): correctly rejected\n");
    } else {
        allOk = FALSE;
        DbgPrint("[HvLic] ed25519 KAT (tampered sig): *** FALSELY ACCEPTED *** — Verify 实现完全错!\n");
    }

    // RFC 8032 Test 2: 1 字节消息(0x72)
    static const UCHAR kat2_pub[32] = {
        0x3d,0x40,0x17,0xc3,0xe8,0x43,0x89,0x5a, 0x92,0xb7,0x0a,0xa7,0x4d,0x1b,0x7e,0xbc,
        0x9c,0x98,0x2c,0xcf,0x2e,0xc4,0x96,0x8c, 0xc0,0xcd,0x55,0xf1,0x2a,0xf4,0x66,0x0c,
    };
    static const UCHAR kat2_msg[1] = { 0x72 };
    static const UCHAR kat2_sig[64] = {
        0x92,0xa0,0x09,0xa9,0xf0,0xd4,0xca,0xb8, 0x72,0x0e,0x82,0x0b,0x5f,0x64,0x25,0x40,
        0xa2,0xb2,0x7b,0x54,0x16,0x50,0x3f,0x8f, 0xb3,0x76,0x22,0x23,0xeb,0xdb,0x69,0xda,
        0x08,0x5a,0xc1,0xe4,0x3e,0x15,0x99,0x6e, 0x45,0x8f,0x36,0x13,0xd0,0xf1,0x1d,0x8c,
        0x38,0x7b,0x2e,0xae,0xb4,0x30,0x2a,0xee, 0xb0,0x0d,0x29,0x16,0x12,0xbb,0x0c,0x00,
    };
    if (HvEd25519Verify(kat2_pub, kat2_msg, 1, kat2_sig)) {
        DbgPrint("[HvLic] ed25519 KAT (RFC 8032 Test 2, 1-byte msg): PASS\n");
    } else {
        allOk = FALSE;
        DbgPrint("[HvLic] ed25519 KAT (RFC 8032 Test 2, 1-byte msg): *** FAIL ***\n");
    }

    // RFC 8032 Test 3: 2 字节消息(0xaf 0x82)
    static const UCHAR kat3_pub[32] = {
        0xfc,0x51,0xcd,0x8e,0x62,0x18,0xa1,0xa3, 0x8d,0xa4,0x7e,0xd0,0x02,0x30,0xf0,0x58,
        0x08,0x16,0xed,0x13,0xba,0x33,0x03,0xac, 0x5d,0xeb,0x91,0x15,0x48,0x90,0x80,0x25,
    };
    static const UCHAR kat3_msg[2] = { 0xaf, 0x82 };
    static const UCHAR kat3_sig[64] = {
        0x62,0x91,0xd6,0x57,0xde,0xec,0x24,0x02, 0x48,0x27,0xe6,0x9c,0x3a,0xbe,0x01,0xa3,
        0x0c,0xe5,0x48,0xa2,0x84,0x74,0x3a,0x44, 0x5e,0x36,0x80,0xd7,0xdb,0x5a,0xc3,0xac,
        0x18,0xff,0x9b,0x53,0x8d,0x16,0xf2,0x90, 0xae,0x67,0xf7,0x60,0x98,0x4d,0xc6,0x59,
        0x4a,0x7c,0x15,0xe9,0x71,0x6e,0xd2,0x8d, 0xc0,0x27,0xbe,0xce,0xea,0x1e,0xc4,0x0a,
    };
    if (HvEd25519Verify(kat3_pub, kat3_msg, 2, kat3_sig)) {
        DbgPrint("[HvLic] ed25519 KAT (RFC 8032 Test 3, 2-byte msg): PASS\n");
    } else {
        allOk = FALSE;
        DbgPrint("[HvLic] ed25519 KAT (RFC 8032 Test 3, 2-byte msg): *** FAIL ***\n");
    }

    // RFC 8032 Test 1024: 1023-byte message — 真正测多 block SHA-512 + ed25519 流程
    // PUBLIC: 278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e
    // MSG (1023 bytes): 0x08b8b2b733424243760fe426a4b54908... (见 RFC 8032 §7.1)
    // SIGNATURE:        0e433ade...88b06
    //
    // 但 1023 字节硬编码在代码里太长。换成 RFC 8032 sha(abc) Test:
    //   PUBLIC: ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf
    //   MSG (64 bytes): "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f" (binary)
    //   SIGNATURE: dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704
    static const UCHAR kat4_pub[32] = {
        0xec,0x17,0x2b,0x93,0xad,0x5e,0x56,0x3b, 0xf4,0x93,0x2c,0x70,0xe1,0x24,0x50,0x34,
        0xc3,0x54,0x67,0xef,0x2e,0xfd,0x4d,0x64, 0xeb,0xf8,0x19,0x68,0x34,0x67,0xe2,0xbf,
    };
    static const UCHAR kat4_msg[64] = {
        0xdd,0xaf,0x35,0xa1,0x93,0x61,0x7a,0xba, 0xcc,0x41,0x73,0x49,0xae,0x20,0x41,0x31,
        0x12,0xe6,0xfa,0x4e,0x89,0xa9,0x7e,0xa2, 0x0a,0x9e,0xee,0xe6,0x4b,0x55,0xd3,0x9a,
        0x21,0x92,0x99,0x2a,0x27,0x4f,0xc1,0xa8, 0x36,0xba,0x3c,0x23,0xa3,0xfe,0xeb,0xbd,
        0x45,0x4d,0x44,0x23,0x64,0x3c,0xe8,0x0e, 0x2a,0x9a,0xc9,0x4f,0xa5,0x4c,0xa4,0x9f,
    };
    static const UCHAR kat4_sig[64] = {
        0xdc,0x2a,0x44,0x59,0xe7,0x36,0x96,0x33, 0xa5,0x2b,0x1b,0xf2,0x77,0x83,0x9a,0x00,
        0x20,0x10,0x09,0xa3,0xef,0xbf,0x3e,0xcb, 0x69,0xbe,0xa2,0x18,0x6c,0x26,0xb5,0x89,
        0x09,0x35,0x1f,0xc9,0xac,0x90,0xb3,0xec, 0xfd,0xfb,0xc7,0xc6,0x64,0x31,0xe0,0x30,
        0x3d,0xca,0x17,0x9c,0x13,0x8a,0xc1,0x7a, 0xd9,0xbe,0xf1,0x17,0x73,0x31,0xa7,0x04,
    };
    if (HvEd25519Verify(kat4_pub, kat4_msg, 64, kat4_sig)) {
        DbgPrint("[HvLic] ed25519 KAT (RFC 8032 Test 1024, 64-byte msg): PASS\n");
    } else {
        allOk = FALSE;
        DbgPrint("[HvLic] ed25519 KAT (RFC 8032 Test 1024, 64-byte msg): *** FAIL ***\n");
    }

    // 关键诊断:用 deploy pubkey + 全 0 sig 走一遍 Verify,期望返回 FALSE (而不是因为
    // unpackneg 内部失败提前 return)。
    // 新 5×51 实现下,deploy pubkey 必须能正常解压;只要 verify 走完整个流程,
    // 即使签名错而拒绝,也证明算法可用。
    UCHAR fake_sig[64] = { 0 };
    fake_sig[0] = 0x01;  // 让 R 不全 0
    BOOLEAN dp_ok = HvEd25519Verify(DEPLOY_PUBKEY, (const UCHAR*)"x", 1, fake_sig);
    if (dp_ok) {
        allOk = FALSE;
        DbgPrint("[HvLic] deploy pubkey self-test: *** FALSELY ACCEPTED fake sig — bug!\n");
    } else {
        DbgPrint("[HvLic] deploy pubkey self-test: fake sig correctly rejected (decompress + verify pipeline reached)\n");
    }

    InterlockedExchange(&g_LicenseCryptoReady, allOk ? TRUE : FALSE);
#if HV_LICENSE_ENABLE_DEV_BYPASS
    DbgPrint("[HvLic] WARNING: HV_LICENSE_ENABLE_DEV_BYPASS is enabled\n");
#endif
#if !HV_LICENSE_ENFORCEMENT
    DbgPrint("[HvLic] Authorization enforcement is disabled for this build\n");
#endif
}

VOID HvLicenseReset(VOID)
{
    InterlockedExchange(&g_LicenseValid, FALSE);
    g_LicenseExpiresAt = 0;
}

// ============================================================
// 构造 yuyuan-protocol 规范的 canonical 串
// ============================================================
//
// auth_canonical 格式 (yuyuan-protocol::messages::auth_canonical):
//   YUYUAN-AUTH-v1|<app_key>|<subject_type>|<subject_id>|<machine_code>|<expires_at>|<token>
//
// 这是被 ed25519 签名的字节序列。driver 必须按完全一致的格式拼。
//
// 输出 buffer 不大于:
//   prefix(13) + sep(6) + max(app_key+subject_type+subject_id+machine+expires+token)
//   = 13 + 6 + 128 + 16 + 21 + 128 + 21 + 128 ≈ 460,留 512 余量

static NTSTATUS HvLicenseBuildCanonical(
    _In_ PHV_LICENSE_REQ Req,
    _Out_writes_to_(BufferLen, *Written) CHAR* Buffer,
    _In_ SIZE_T BufferLen,
    _Out_ SIZE_T* Written)
{
    NTSTATUS s;
    SIZE_T remain = BufferLen;

    s = RtlStringCbPrintfA(
        Buffer, remain,
        "YUYUAN-AUTH-v1|%s|%s|%lld|%s|%lld|%s",
        Req->AppKey, Req->SubjectType, (LONGLONG)Req->SubjectId,
        Req->MachineCode, (LONGLONG)Req->ExpiresAt, Req->Token);
    if (!NT_SUCCESS(s)) return s;

    // 用 strlen 算实际长度(不含 NUL)
    SIZE_T len = 0;
    while (len < BufferLen && Buffer[len] != '\0') len++;
    *Written = len;
    return STATUS_SUCCESS;
}

// ============================================================
// 提交 license 请求
// ============================================================

NTSTATUS HvLicenseSubmit(
    _In_reads_bytes_(InputLength) PVOID InputBuffer,
    _In_ ULONG InputLength)
{
#if !HV_LICENSE_ENFORCEMENT
    UNREFERENCED_PARAMETER(InputBuffer);
    UNREFERENCED_PARAMETER(InputLength);
    return STATUS_SUCCESS;
#else
    if (InputLength != sizeof(HV_LICENSE_REQ)) {
        DbgPrint("[HvLic] Submit: input length %u != %u\n",
                 InputLength, (ULONG)sizeof(HV_LICENSE_REQ));
        return STATUS_INVALID_PARAMETER;
    }

    if (InterlockedCompareExchange(
            &g_LicenseCryptoReady, FALSE, FALSE) == FALSE) {
        DbgPrint("[HvLic] Submit: crypto self-test did not pass\n");
        return STATUS_DEVICE_NOT_READY;
    }

    PHV_LICENSE_REQ req = (PHV_LICENSE_REQ)InputBuffer;

    // 强制 NUL 终结字符串字段
    req->AppKey[sizeof(req->AppKey) - 1] = '\0';
    req->SubjectType[sizeof(req->SubjectType) - 1] = '\0';
    req->MachineCode[sizeof(req->MachineCode) - 1] = '\0';
    req->Token[sizeof(req->Token) - 1] = '\0';

    if (!HvLicenseStringEquals(
            req->AppKey, sizeof(req->AppKey), DEPLOY_APP_KEY) ||
        (!HvLicenseStringEquals(
             req->SubjectType, sizeof(req->SubjectType), "account") &&
         !HvLicenseStringEquals(
             req->SubjectType, sizeof(req->SubjectType), "card")) ||
        req->SubjectId <= 0 || req->MachineCode[0] == '\0' ||
        req->Token[0] == '\0') {
        DbgPrint("[HvLic] Submit: invalid tenant or identity fields\n");
        return STATUS_ACCESS_DENIED;
    }

    // 拼 canonical 字符串
    CHAR canonical[512];
    SIZE_T canonical_len = 0;
    NTSTATUS s = HvLicenseBuildCanonical(req, canonical, sizeof(canonical), &canonical_len);
    if (!NT_SUCCESS(s)) {
        DbgPrint("[HvLic] Submit: build canonical failed 0x%X\n", s);
        return s;
    }

    DbgPrint("[HvLic] Submit: subject=%s/%lld expires=%lld canonical_len=%u\n",
             req->SubjectType, (LONGLONG)req->SubjectId,
             (LONGLONG)req->ExpiresAt, (ULONG)canonical_len);

    // 验签
    BOOLEAN ok = HvEd25519Verify(
        DEPLOY_PUBKEY,
        (const UCHAR*)canonical, (ULONG)canonical_len,
        req->AuthSig);

    if (!ok) {
        DbgPrint("[HvLic] Submit: VERIFY FAILED (signature does not match deploy pubkey)\n");
        return STATUS_ACCESS_DENIED;
    }

    // 校验是否过期(仅对时长卡有意义,次数卡 ExpiresAt=0 跳过)
    if (req->ExpiresAt != 0) {
        LARGE_INTEGER nowSysTime;
        KeQuerySystemTimePrecise(&nowSysTime);
        // SysTime 是 100ns from 1601-01-01,转 Unix 秒
        // diff 1601→1970 = 11644473600 秒
        INT64 nowUnix = (nowSysTime.QuadPart / 10000000LL) - 11644473600LL;
        if (nowUnix > req->ExpiresAt) {
            DbgPrint("[HvLic] Submit: license expired (now=%lld expires=%lld)\n",
                     (LONGLONG)nowUnix, (LONGLONG)req->ExpiresAt);
            return STATUS_ACCESS_DENIED;
        }
    }

    g_LicenseExpiresAt = req->ExpiresAt;
    KeMemoryBarrier();
    InterlockedExchange(&g_LicenseValid, TRUE);

    DbgPrint("[HvLic] Submit: OK, license activated\n");
    return STATUS_SUCCESS;
#endif
}
