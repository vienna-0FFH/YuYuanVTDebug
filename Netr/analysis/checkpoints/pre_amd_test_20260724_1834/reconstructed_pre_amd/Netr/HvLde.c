/*
 * HvLde.c - 共享指令解码器 + Trampoline 指令重写器
 *
 * 见 HvLde.h 注释。本文件实现 HvLdeDecode 和 HvHookRewriteTrampoline。
 */

#include "HvLde.h"

// P122: 全 driver DbgPrint → GUI ring
#define HV_TRACE_THIS_CAT HV_TRACE_CAT_UTIL
#include "HvTrace.h"

// ============================================================
// 解码器
// ============================================================

/*
 * 解码单条 x64 指令。
 *
 * 设计原则:
 *   - 不试图覆盖整个 ISA, 只覆盖 trampoline 重写需要的 opcode 子集 + 常见
 *     SSDT 入口字节 (REX, MOV, TEST imm, RIP-rel MOV, syscall, ret,
 *     rel8/rel32 跳转, CALL/JMP rel32, Jcc rel32)。
 *   - VEX/EVEX 指令出现在 SSDT 入口子集时极少, 保守不算 imm; 真碰上
 *     trampoline 自检会失败拒装, 而不是误算。
 *   - F6/F7 子操作码 imm 通过查 ModRM.reg 字段算 (修原 fork 解码器的
 *     "F6 04 25 [a32] 01" 被算成 7 字节而不是 8 字节的 bug)。
 *   - 0F 3A 立即数判定通过记录 opcode 字节位置 opIdx 锚定, 不再用
 *     "Code[length-4]==0x3A" 这种依赖前缀字节数的回看。
 */
BOOLEAN
HvLdeDecode(
    _In_ const UCHAR* Code,
    _Out_ PHV_INST_INFO Info
)
{
    UCHAR opcode;
    ULONG length = 0;
    ULONG prefixCount = 0;
    BOOLEAN hasModRM = FALSE;
    BOOLEAN hasSIB = FALSE;
    ULONG dispSize = 0;
    ULONG immSize = 0;
    UCHAR modRM, mod, rm;
    BOOLEAN hasREX = FALSE;
    BOOLEAN is64BitOperand = FALSE;
    UCHAR vexByte1 = 0;
    UCHAR evexP0 = 0;
    UCHAR opIdx = 0;          // 真正 opcode 字节(可能是 0F 后那字节)所在的位置
    BOOLEAN isTwoByte = FALSE;
    BOOLEAN isVexEvex = FALSE;
    HV_INST_TYPE instType = HvInstOrdinary;
    UCHAR immOffsetOut = 0;
    UCHAR immSizeOut = 0;

    RtlZeroMemory(Info, sizeof(*Info));

    // ---- 解析前缀 ----
    while (prefixCount < 15) {
        UCHAR b = Code[length];
        // Legacy prefixes
        if (b == 0x66 || b == 0x67 || b == 0xF0 || b == 0xF2 || b == 0xF3 ||
            b == 0x2E || b == 0x36 || b == 0x3E || b == 0x26 || b == 0x64 || b == 0x65) {
            if (b == 0x66) is64BitOperand = TRUE;
            length++;
            prefixCount++;
        }
        // REX prefix (0x40-0x4F)
        else if (b >= 0x40 && b <= 0x4F) {
            hasREX = TRUE;
            if (b & 0x08) is64BitOperand = TRUE; // REX.W
            length++;
            prefixCount++;
        }
        else {
            break;
        }
    }

    // ---- opcode ----
    opIdx = (UCHAR)length;
    opcode = Code[length++];

    // VEX 2-byte (C5)
    if (opcode == 0xC5) {
        isVexEvex = TRUE;
        length++;            // VEX byte 2
        length++;            // 真 opcode
        hasModRM = TRUE;
        // imm8 子集保守不算, 见头文件说明
        goto parse_modrm;
    }
    // VEX 3-byte (C4)
    if (opcode == 0xC4) {
        isVexEvex = TRUE;
        vexByte1 = Code[length++];
        length++;            // VEX byte 3
        length++;            // 真 opcode
        hasModRM = TRUE;
        // 3-byte VEX 的 mmmmm=3 (0F3A 类) 通常带 imm8, 仅在子集需要时再补
        if ((vexByte1 & 0x1F) == 3) {
            immSize = 1;
        }
        goto parse_modrm;
    }
    // EVEX 4-byte (62)
    if (opcode == 0x62) {
        isVexEvex = TRUE;
        evexP0 = Code[length++]; // P0
        (void)evexP0;
        length++;            // P1
        length++;            // P2
        length++;            // 真 opcode
        hasModRM = TRUE;
        // EVEX imm8 子集保守不算
        goto parse_modrm;
    }

    // 0F xx 两字节 opcode
    if (opcode == 0x0F) {
        isTwoByte = TRUE;
        opIdx = (UCHAR)length;       // 真 opcode 字节位置 = 0F 后一位
        opcode = Code[length++];

        // 三字节 (0F 38 xx, 0F 3A xx)
        if (opcode == 0x38 || opcode == 0x3A) {
            UCHAR escByte = opcode;
            opIdx = (UCHAR)length;   // 真 opcode = 0F 38/3A 后一位
            opcode = Code[length++];
            hasModRM = TRUE;
            // 0F 3A 系列通常有 imm8 (palignr / pclmul / vpalignr 等)
            // 用 opIdx 锚定, 不再依赖 length-4 回看
            if (escByte == 0x3A) {
                immSize = 1;
            }
        }
        // 双字节 Jcc rel32
        else if (opcode >= 0x80 && opcode <= 0x8F) {
            immSize = 4;
            instType = HvInstJccRel32;
            immOffsetOut = (UCHAR)length;  // rel32 紧跟在 0F 8x 之后
            immSizeOut = 4;
        }
        // MOVZX/MOVSX/IMUL/CMOVcc/SETcc 等带 ModRM 但无 imm
        else if (opcode == 0xB6 || opcode == 0xB7 ||  // MOVZX
                 opcode == 0xBE || opcode == 0xBF ||  // MOVSX
                 opcode == 0xAF ||                    // IMUL
                 (opcode >= 0x40 && opcode <= 0x4F) || // CMOVcc
                 (opcode >= 0x90 && opcode <= 0x9F)) { // SETcc (字节)
            hasModRM = TRUE;
        }
        else {
            // 大多数其他 0F 指令(SSE/控制寄存器等)有 ModRM
            hasModRM = TRUE;
        }
    }
    // 单字节 opcode 主分发
    else {
        switch (opcode) {
            // ---- 无操作数 ----
            case 0x90: // NOP / XCHG eax,eax
            case 0xCC: // INT3
            case 0xF4: // HLT
            case 0x9C: // PUSHFQ
            case 0x9D: // POPFQ
            case 0xC9: // LEAVE
            case 0xFA: // CLI (kernel-mode 函数序言常见, 例: ZwQueryVirtualMemory)
            case 0xFB: // STI
                break;

            case 0xC3: // RET
            case 0xCB: // RETF
                instType = HvInstRet;
                break;

            case 0xC2: // RET imm16
            case 0xCA: // RETF imm16
                instType = HvInstRet;
                immSize = 2;
                break;

            // ---- AL,imm8 / EAX,imm32 算术 ----
            case 0x04: case 0x0C: case 0x14: case 0x1C:
            case 0x24: case 0x2C: case 0x34: case 0x3C:
            case 0x6A: // PUSH imm8
            case 0xCD: // INT imm8
            case 0xE4: case 0xE5: case 0xE6: case 0xE7: // IN/OUT imm8
                immSize = 1;
                break;

            case 0x05: case 0x0D: case 0x15: case 0x1D:
            case 0x25: case 0x2D: case 0x35: case 0x3D:
            case 0x68: // PUSH imm32
                immSize = 4;
                break;

            // ---- rel8 跳转 ----
            case 0xEB: // JMP rel8
                immSize = 1;
                instType = HvInstJmpRel8;
                immOffsetOut = (UCHAR)length;
                immSizeOut = 1;
                break;

            // 70-7F: Jcc rel8
            case 0x70: case 0x71: case 0x72: case 0x73:
            case 0x74: case 0x75: case 0x76: case 0x77:
            case 0x78: case 0x79: case 0x7A: case 0x7B:
            case 0x7C: case 0x7D: case 0x7E: case 0x7F:
                immSize = 1;
                instType = HvInstJccRel8;
                immOffsetOut = (UCHAR)length;
                immSizeOut = 1;
                break;

            // E0-E3: LOOPxx / JECXZ - 无 rel32 等价, 重写器拒装
            case 0xE0: case 0xE1: case 0xE2: case 0xE3:
                immSize = 1;
                instType = HvInstLoopJecxz;
                immOffsetOut = (UCHAR)length;
                immSizeOut = 1;
                break;

            // ---- rel32 跳转 ----
            case 0xE8: // CALL rel32
                immSize = 4;
                instType = HvInstCallRel32;
                immOffsetOut = (UCHAR)length;
                immSizeOut = 4;
                break;
            case 0xE9: // JMP rel32
                immSize = 4;
                instType = HvInstJmpRel32;
                immOffsetOut = (UCHAR)length;
                immSizeOut = 4;
                break;

            // ---- MOV reg, imm ----
            case 0xB0: case 0xB1: case 0xB2: case 0xB3:
            case 0xB4: case 0xB5: case 0xB6: case 0xB7:
                immSize = 1;
                break;
            case 0xB8: case 0xB9: case 0xBA: case 0xBB:
            case 0xBC: case 0xBD: case 0xBE: case 0xBF:
                immSize = (hasREX && is64BitOperand) ? 8 : 4;
                break;

            // PUSH/POP reg (50-5F)
            case 0x50: case 0x51: case 0x52: case 0x53:
            case 0x54: case 0x55: case 0x56: case 0x57:
            case 0x58: case 0x59: case 0x5A: case 0x5B:
            case 0x5C: case 0x5D: case 0x5E: case 0x5F:
                break;

            // ---- 带 ModRM 的指令 ----
            default:
                // 算术 r/m, reg 类 (00-3F 大段)
                if ((opcode >= 0x00 && opcode <= 0x3F &&
                     (opcode & 0x06) != 0x06) || // 排除 06/07/0E/16/17/1E/1F (push/pop seg, 64-bit invalid)
                    (opcode >= 0x80 && opcode <= 0x83) ||  // 算术 + imm
                    (opcode >= 0x88 && opcode <= 0x8B) ||  // MOV
                    opcode == 0x8C || opcode == 0x8E ||   // MOV r/m, seg
                    (opcode >= 0xC0 && opcode <= 0xC1) ||  // 移位 imm
                    (opcode >= 0xD0 && opcode <= 0xD3) ||  // 移位
                    (opcode >= 0xD8 && opcode <= 0xDF) ||  // FPU
                    opcode == 0xF6 || opcode == 0xF7 ||   // TEST/NOT/NEG/MUL/IMUL/DIV/IDIV
                    opcode == 0xFE || opcode == 0xFF ||   // INC/DEC/CALL/JMP/PUSH (r/m)
                    opcode == 0x63 ||                     // MOVSXD
                    opcode == 0x69 || opcode == 0x6B ||   // IMUL r, r/m, imm
                    opcode == 0x84 || opcode == 0x85 ||   // TEST
                    opcode == 0x86 || opcode == 0x87 ||   // XCHG
                    opcode == 0x8D ||                     // LEA
                    opcode == 0x8F ||                     // POP r/m
                    opcode == 0xC6 || opcode == 0xC7) {   // MOV r/m, imm
                    hasModRM = TRUE;

                    // 80-83 + imm
                    if (opcode == 0x80 || opcode == 0x82 || opcode == 0x83) immSize = 1;
                    if (opcode == 0x81) immSize = 4;

                    // C6/C7 mov r/m, imm
                    if (opcode == 0xC6) immSize = 1;
                    if (opcode == 0xC7) immSize = 4;

                    // IMUL r, r/m, imm
                    if (opcode == 0x69) immSize = 4;
                    if (opcode == 0x6B) immSize = 1;

                    // F6/F7 的 imm 取决于 ModRM.reg (下面 ModRM 解析后回填)
                }
                break;
        }
    }

parse_modrm:
    // ---- 解析 ModRM ----
    if (hasModRM) {
        modRM = Code[length++];
        mod = (modRM >> 6) & 0x03;
        rm  = modRM & 0x07;

        // SIB 字节
        if (mod != 3 && rm == 4) {
            hasSIB = TRUE;
            length++;
        }

        // disp 大小 + RIP-relative 判定
        if (mod == 0) {
            if (rm == 5) {
                // mod=00 rm=101 -> disp32 是 RIP-relative
                dispSize = 4;
                if (!isVexEvex && !isTwoByte) {
                    // 标记给重写器, 让它修 disp32
                    // (双字节 / VEX 也可能有 RIP-rel; 但保守只对单字节场景启用)
                }
                Info->IsRipRelative = 1;
                Info->DispOffset = (UCHAR)length;
            }
            else if (hasSIB && (Code[length - 1] & 0x07) == 5) {
                // SIB base=5, mod=0 -> disp32 绝对寻址 (非 RIP-rel)
                dispSize = 4;
            }
        }
        else if (mod == 1) {
            dispSize = 1;
        }
        else if (mod == 2) {
            dispSize = 4;
        }
        // mod == 3 -> 寄存器, 无 disp

        // ---- F6/F7 子操作码回填 imm (修原解码器 bug) ----
        // 这里的 immSize 是在 switch 里没设过的; 如果已经设过(其他指令)就不动。
        if (!isTwoByte && !isVexEvex && (opcode == 0xF6 || opcode == 0xF7)) {
            UCHAR reg = (modRM >> 3) & 0x07;
            if (reg <= 1) {
                // /0 TEST imm, /1 也是 TEST (alias)
                immSize = (opcode == 0xF6) ? 1 : 4;
            }
        }
        // C7 /0 = MOV r/m, imm; C7 /7 是 XBEGIN rel32 -> 不在我们处理范围
        // 现行 immSize 已经在 switch 设过, 这里不动

        length += dispSize;
    }

    // ---- imm ----
    if (immSize > 0) {
        // 如果 switch 里设过 immOffsetOut, 这里以 switch 设的为准 (在 ModRM/disp 之后无 rel/imm)
        // ImmOffset 始终指向"原始" rel/imm 字节起点 (即 opcode 之后 + 可选 ModRM/SIB/disp 之后)
        if (immOffsetOut == 0) {
            // 对应不是 rel/imm 而是普通 imm, 重写器不用 ImmOffset, 留 0
        }
        length += immSize;
    }

    // ---- 安全检查 ----
    if (length == 0 || length > 15) {
        Info->Length = 0;
        Info->Type = HvInstUnknown;
        return FALSE;
    }

    Info->Length = (UCHAR)length;
    Info->Type = (UCHAR)instType;
    Info->ImmOffset = immOffsetOut;
    Info->ImmSize = immSizeOut;

    return TRUE;
}

// ============================================================
// 重写器
// ============================================================

/*
 * 在 NewOffsets[] 里线性查找原始偏移 SrcOff 对应的 New 偏移。
 * 找不到返回 (ULONG)-1 (表示目标落在指令中段, 非法)。
 */
static ULONG
HvLdepMapNewOffset(
    _In_ PHV_TRAMP_REWRITE_RESULT R,
    _In_ ULONG SrcOff
)
{
    ULONG i;
    for (i = 0; i < R->InstCount; i++) {
        if (R->OrigOffsets[i] == SrcOff) {
            return R->NewOffsets[i];
        }
    }
    return (ULONG)-1;
}

/*
 * 检查 (LONG64) delta 是否在 32 位 rel32 表达范围内。
 */
static BOOLEAN
HvLdepFitsRel32(
    _In_ LONG64 Delta
)
{
    return (Delta >= -(LONG64)0x80000000LL) && (Delta <= (LONG64)0x7FFFFFFFLL);
}

NTSTATUS
HvHookRewriteTrampoline(
    _In_reads_(SrcLen) const UCHAR* SrcBytes,
    _In_ ULONG SrcLen,
    _In_ ULONG_PTR SrcVa,
    _Out_writes_(DstCap) UCHAR* DstBuf,
    _In_ ULONG DstCap,
    _In_ ULONG_PTR DstVa,
    _Out_ PHV_TRAMP_REWRITE_RESULT Result
)
{
    HV_INST_INFO infos[HV_TRAMP_MAX_INSTS];
    ULONG srcOff = 0;
    ULONG newOff = 0;
    ULONG i = 0;

    RtlZeroMemory(Result, sizeof(*Result));
    if (SrcBytes == NULL || DstBuf == NULL || Result == NULL || SrcLen == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    // ============ Pass 1: 解码 + 算长度映射 ============
    while (srcOff < SrcLen) {
        HV_INST_INFO info;
        ULONG newLen;

        if (i >= HV_TRAMP_MAX_INSTS) {
            DbgPrint("[HvLde-TRACE] reject: TOO_MANY_INSTS at srcOff=%u\n", srcOff);
            return STATUS_NOT_SUPPORTED;  // 14 字节里不应有 16 条以上
        }

        if (!HvLdeDecode(SrcBytes + srcOff, &info) || info.Length == 0) {
            DbgPrint("[HvLde-TRACE] reject: DECODE_FAIL at srcOff=%u byte=0x%02X\n",
                     srcOff, SrcBytes[srcOff]);
            return STATUS_INVALID_IMAGE_FORMAT;
        }

        // LOOPxx / JECXZ 无 rel32 等价 -> 拒装
        if (info.Type == HvInstLoopJecxz) {
            DbgPrint("[HvLde-TRACE] reject: LOOP/JECXZ at srcOff=%u byte=0x%02X\n",
                     srcOff, SrcBytes[srcOff]);
            return STATUS_NOT_SUPPORTED;
        }

        // 计算新长度
        newLen = info.Length;
        if (info.Type == HvInstJmpRel8) {
            newLen = 5;   // EB rel8 -> E9 rel32
        } else if (info.Type == HvInstJccRel8) {
            newLen = 6;   // 7x rel8 -> 0F 8x rel32
        }

        // 容量检查 (含最终 14 字节 jmp-back)
        if (newOff + newLen + 14 > DstCap) {
            return STATUS_NO_MEMORY;
        }

        infos[i] = info;
        Result->OrigOffsets[i] = (UCHAR)srcOff;
        Result->NewOffsets[i]  = (UCHAR)newOff;
        Result->Types[i]       = info.Type;

        srcOff += info.Length;
        newOff += newLen;
        i++;
    }

    Result->InstCount = i;
    Result->DstLen = newOff;

    // ============ Pass 2: 写字节 + 修偏移 ============
    for (i = 0; i < Result->InstCount; i++) {
        HV_INST_INFO* info = &infos[i];
        ULONG srcInstOff = Result->OrigOffsets[i];
        ULONG newInstOff = Result->NewOffsets[i];
        UCHAR srcLen = info->Length;
        const UCHAR* src = SrcBytes + srcInstOff;
        UCHAR* dst = DstBuf + newInstOff;

        switch (info->Type) {
            // -------- 普通指令 (含 RIP-relative disp32) --------
            case HvInstOrdinary:
            case HvInstRet:
            case HvInstCallRel32:
            case HvInstJmpRel32:
            case HvInstJccRel32:
            {
                // 先整条复制
                RtlCopyMemory(dst, src, srcLen);

                // RIP-relative disp32 重定位
                if (info->IsRipRelative && info->DispOffset > 0) {
                    LONG32 origDisp = *(LONG32*)(src + info->DispOffset);
                    LONG64 absTgt = (LONG64)SrcVa + (LONG64)srcInstOff + (LONG64)srcLen + (LONG64)origDisp;
                    LONG64 newDisp = absTgt - (LONG64)(DstVa + newInstOff + srcLen);
                    if (!HvLdepFitsRel32(newDisp)) {
                        DbgPrint("[HvLde-TRACE] reject: RIPREL_DISP32_OVERFLOW srcOff=%u\n", srcInstOff);
                        return STATUS_NOT_SUPPORTED;
                    }
                    *(LONG32*)(dst + info->DispOffset) = (LONG32)newDisp;
                }

                // rel32 跳转目标修正 (CALL/JMP/Jcc rel32)
                if (info->Type == HvInstCallRel32 ||
                    info->Type == HvInstJmpRel32  ||
                    info->Type == HvInstJccRel32)
                {
                    LONG32 origRel = *(LONG32*)(src + info->ImmOffset);
                    LONG64 absTgt = (LONG64)SrcVa + (LONG64)srcInstOff + (LONG64)srcLen + (LONG64)origRel;
                    LONG64 newRel;

                    // 目标是否在复制范围内
                    if (absTgt >= (LONG64)SrcVa && absTgt < (LONG64)(SrcVa + SrcLen)) {
                        ULONG tgtSrcOff = (ULONG)(absTgt - (LONG64)SrcVa);
                        ULONG tgtNewOff = HvLdepMapNewOffset(Result, tgtSrcOff);
                        if (tgtNewOff == (ULONG)-1) {
                            DbgPrint("[HvLde-TRACE] reject: JUMP_INTO_MIDDLE srcOff=%u tgtSrcOff=%u\n",
                                     srcInstOff, tgtSrcOff);
                            return STATUS_NOT_SUPPORTED;  // 目标落在指令中段
                        }
                        // newRel = (DstVa + tgtNewOff) - (DstVa + newInstOff + srcLen)
                        //       = tgtNewOff - (newInstOff + srcLen)
                        newRel = (LONG64)tgtNewOff - (LONG64)(newInstOff + srcLen);
                    } else {
                        newRel = absTgt - (LONG64)(DstVa + newInstOff + srcLen);
                    }
                    if (!HvLdepFitsRel32(newRel)) {
                        DbgPrint("[HvLde-TRACE] reject: CALL/JMP_REL32_OVERFLOW srcOff=%u srcVa=%p dstVa=%p absTgt=%p\n",
                                 srcInstOff, (PVOID)SrcVa, (PVOID)DstVa, (PVOID)absTgt);
                        return STATUS_NOT_SUPPORTED;
                    }
                    *(LONG32*)(dst + info->ImmOffset) = (LONG32)newRel;
                }
                break;
            }

            // -------- 短跳 EB rel8 -> E9 rel32 --------
            case HvInstJmpRel8:
            {
                CHAR rel8 = (CHAR)src[info->ImmOffset];
                LONG64 absTgt = (LONG64)SrcVa + (LONG64)srcInstOff + 2 + (LONG64)rel8;
                LONG64 newRel;

                dst[0] = 0xE9;
                if (absTgt >= (LONG64)SrcVa && absTgt < (LONG64)(SrcVa + SrcLen)) {
                    ULONG tgtSrcOff = (ULONG)(absTgt - (LONG64)SrcVa);
                    ULONG tgtNewOff = HvLdepMapNewOffset(Result, tgtSrcOff);
                    if (tgtNewOff == (ULONG)-1) {
                        return STATUS_NOT_SUPPORTED;
                    }
                    newRel = (LONG64)tgtNewOff - (LONG64)(newInstOff + 5);
                } else {
                    newRel = absTgt - (LONG64)(DstVa + newInstOff + 5);
                }
                if (!HvLdepFitsRel32(newRel)) {
                    DbgPrint("[HvLde-TRACE] reject: JMP_REL8_OVERFLOW srcOff=%u\n", srcInstOff);
                    return STATUS_NOT_SUPPORTED;
                }
                *(LONG32*)(dst + 1) = (LONG32)newRel;
                break;
            }

            // -------- 短跳 70-7F rel8 -> 0F 8x rel32 --------
            case HvInstJccRel8:
            {
                CHAR rel8 = (CHAR)src[info->ImmOffset];
                LONG64 absTgt = (LONG64)SrcVa + (LONG64)srcInstOff + 2 + (LONG64)rel8;
                UCHAR cc = src[0] & 0x0F;
                LONG64 newRel;

                dst[0] = 0x0F;
                dst[1] = (UCHAR)(0x80 | cc);
                if (absTgt >= (LONG64)SrcVa && absTgt < (LONG64)(SrcVa + SrcLen)) {
                    ULONG tgtSrcOff = (ULONG)(absTgt - (LONG64)SrcVa);
                    ULONG tgtNewOff = HvLdepMapNewOffset(Result, tgtSrcOff);
                    if (tgtNewOff == (ULONG)-1) {
                        return STATUS_NOT_SUPPORTED;
                    }
                    newRel = (LONG64)tgtNewOff - (LONG64)(newInstOff + 6);
                } else {
                    newRel = absTgt - (LONG64)(DstVa + newInstOff + 6);
                }
                if (!HvLdepFitsRel32(newRel)) {
                    DbgPrint("[HvLde-TRACE] reject: JCC_REL8_OVERFLOW srcOff=%u\n", srcInstOff);
                    return STATUS_NOT_SUPPORTED;
                }
                *(LONG32*)(dst + 2) = (LONG32)newRel;
                break;
            }

            // LoopJecxz / Unknown 已在 Pass 1 拦截, 这里走不到
            case HvInstLoopJecxz:
            case HvInstUnknown:
            default:
                DbgPrint("[HvLde-TRACE] reject: UNKNOWN_INST_TYPE type=%u srcOff=%u\n",
                         info->Type, srcInstOff);
                return STATUS_NOT_SUPPORTED;
        }
    }

    return STATUS_SUCCESS;
}
