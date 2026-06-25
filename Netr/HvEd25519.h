/*
 * HvEd25519.h - 内核态 Ed25519 签名验证
 *
 * 基于 ref10(SUPERCOP 公开实现)简化:
 *   - 只导出 verify 路径,不导出 keygen / sign
 *   - 不依赖标准库的 malloc/printf/memcmp 之外的任何符号(memcmp 我们自己写)
 *   - 不使用 SIMD / XMM / FPU(driver 模式安全)
 *
 * 公开 API 只有一个:
 *
 *   BOOLEAN HvEd25519Verify(
 *       const UCHAR PublicKey[32],
 *       const UCHAR* Message, ULONG MessageLen,
 *       const UCHAR Signature[64]);
 *
 * 返回 TRUE 表示签名有效。算法:Ed25519 (RFC 8032 §5.1.7)。
 *
 * 性能 / 栈:单次 verify 约 250KB cycles,栈使用 ~3KB。
 */

#pragma once

#include <ntddk.h>

BOOLEAN HvEd25519Verify(
    _In_reads_bytes_(32) const UCHAR* PublicKey,
    _In_reads_bytes_(MessageLen) const UCHAR* Message,
    _In_ ULONG MessageLen,
    _In_reads_bytes_(64) const UCHAR* Signature
);
