/*
 * HvLde.h - 共享 x64 指令长度解码器 + Trampoline 指令重写器
 *
 * 设计目标: EPT/NPT 两路 inline hook 共享一份解码 + 重写实现, 取代
 * 原 EptHook.c::GetInstructionLength + RelocateRelativeInstructions 和
 * NptHook.c::NptGetInstructionLength + NptRelocateRelativeInstructions 两份 fork。
 *
 * 关键能力(新增, 旧实现没有):
 *   1. 短跳扩展: EB rel8 -> E9 rel32 (2 -> 5), 70-7F rel8 -> 0F 8x rel32 (2 -> 6)
 *   2. 短跳扩展后所有后续指令偏移重算, 后向 rel32 目标重指
 *   3. RIP-relative disp32 重定位 (trampoline 复制后 RIP 变了)
 *   4. LOOPxx/JECXZ (无 rel32 等价) 拒装
 *   5. F6/F7 /0|/1 imm 算对 (修原解码器 bug, Win11 24H2 SSDT stub 偏 8 的
 *      `F6 04 25 [addr32] 01` 现在算成 8 字节, 不再是 7)
 *
 * 不在范围:
 *   - VEX/EVEX 指令的 imm 保守不算 (Win11 SSDT 入口子集不出现); 真碰上靠
 *     重写器自检失败拒装, 不会沿用旧 fork 的误算路径。
 *   - 不重写 LDE 整体, 仅修需要的若干 opcode 子集。
 */

#ifndef _HV_LDE_H_
#define _HV_LDE_H_

#include "HvTypes.h"

// ============================================================
// IR 类型
// ============================================================

typedef enum _HV_INST_TYPE {
    HvInstUnknown = 0,    // 解码失败
    HvInstOrdinary,       // 普通指令 (可能含 RIP-relative disp32)
    HvInstJmpRel8,        // EB rel8
    HvInstJccRel8,        // 70-7F rel8
    HvInstLoopJecxz,      // E0/E1/E2/E3 - 拒装
    HvInstCallRel32,      // E8 rel32
    HvInstJmpRel32,       // E9 rel32
    HvInstJccRel32,       // 0F 80-8F rel32
    HvInstRet             // C3/C2/CB/CA
} HV_INST_TYPE;

// 单条指令解码结果
typedef struct _HV_INST_INFO {
    UCHAR Length;          // 整指令字节数 (1..15), 0 = 解码失败
    UCHAR Type;            // HV_INST_TYPE
    UCHAR DispOffset;      // RIP-relative disp32 在指令内的字节偏移; 0 = 无
    UCHAR ImmOffset;       // rel8/rel32 在指令内的字节偏移; 0 = 无
    UCHAR ImmSize;         // rel/imm 大小 (1 或 4); 0 = 无 (仅指 rel/imm, 非完整 imm)
    UCHAR IsRipRelative;   // TRUE = ModRM mod=00 rm=101, disp32 是 RIP-relative
    UCHAR _pad[2];
} HV_INST_INFO, *PHV_INST_INFO;

// trampoline 重写结果 (单条 hook 最多支持 16 条原始指令, 14 字节里实际不会超过 8 条)
#define HV_TRAMP_MAX_INSTS 16

typedef struct _HV_TRAMP_REWRITE_RESULT {
    ULONG DstLen;                         // 写入字节数 (不含 14 字节 jmp-back)
    ULONG InstCount;                      // 处理了几条原始指令
    UCHAR OrigOffsets[HV_TRAMP_MAX_INSTS]; // 第 i 条在 SrcBytes 中的偏移
    UCHAR NewOffsets[HV_TRAMP_MAX_INSTS];  // 第 i 条在 DstBuf 中的偏移
    UCHAR Types[HV_TRAMP_MAX_INSTS];       // HV_INST_TYPE
} HV_TRAMP_REWRITE_RESULT, *PHV_TRAMP_REWRITE_RESULT;

// ============================================================
// API
// ============================================================

/*
 * 解码一条 x64 指令, 返回长度 + 类型 + 偏移信息。
 * @param  Code   指令起点 (不应跨页, 至少能读 16 字节)
 * @param  Info   填充解码结果。Info->Length=0 表示解码失败 (函数返回 FALSE)。
 * @return TRUE = 解码成功; FALSE = 失败 (Info 被清零)
 */
BOOLEAN
HvLdeDecode(
    _In_ const UCHAR* Code,
    _Out_ PHV_INST_INFO Info
);

/*
 * 重写 trampoline 指令字节:
 *   - 短跳 EB/70-7F 扩成 rel32 (2->5 或 2->6)
 *   - 范围内 rel32 目标重新指向 trampoline 新偏移
 *   - 范围外 rel32 目标 + RIP-relative disp32 按新 RIP 重算
 *   - LOOPxx/JECXZ + 距离 >2GB + 解码失败 -> STATUS_NOT_SUPPORTED
 *
 * @param  SrcBytes   原函数前 N 字节的拷贝 (HookEntry->OriginalBytes)
 * @param  SrcLen     原始字节数 (HookEntry->OriginalBytesLength), 通常 14..32
 * @param  SrcVa      原函数起始 VA (用于绝对地址 / 范围判断)
 * @param  DstBuf     输出缓冲 (调用方栈或预分配)
 * @param  DstCap     DstBuf 容量
 * @param  DstVa      DstBuf 最终写入位置的 VA (重要: 用于 rel32 / disp32 计算)
 *                    调用方 = 池里 bump 出的 trampoline VA
 * @param  Result     填充重写结果, 含每条指令的 orig->new 偏移映射
 * @return STATUS_SUCCESS / NOT_SUPPORTED / NO_MEMORY / INVALID_IMAGE_FORMAT
 *
 * 注意 jmp-back 模板 (14 字节) 不在本函数写入, 由调用方在 DstBuf+DstLen 处自行写。
 */
NTSTATUS
HvHookRewriteTrampoline(
    _In_reads_(SrcLen) const UCHAR* SrcBytes,
    _In_ ULONG SrcLen,
    _In_ ULONG_PTR SrcVa,
    _Out_writes_(DstCap) UCHAR* DstBuf,
    _In_ ULONG DstCap,
    _In_ ULONG_PTR DstVa,
    _Out_ PHV_TRAMP_REWRITE_RESULT Result
);

#endif // _HV_LDE_H_
