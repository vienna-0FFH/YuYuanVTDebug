/*
 * HvHostExc.h — Step 1 (虚幻调试器范式):
 *   r10/r11 软异常协议 + AsmMemcpySafe.
 *
 * 范式 (源自 D:/虚幻调试器源码/VT_Driver(4.2)/ASM/exception-routines.asm
 *       + idt.cpp::handle_host_interrupt):
 *
 *   1) Safe stub 入口:
 *        mov r10, <stub_local_ehandler_label>
 *        mov r11, rcx                  ; rcx = HV_HOST_EXC_INFO*
 *        mov byte ptr [rcx], 0         ; 默认 ExceptionOccurred=0
 *      然后做"可能在 host 里 #PF/#GP/#UD 的危险动作".
 *      正常 fall-through 落到 ehandler 标签 → 该标签处就是 stub 的 ret.
 *
 *   2) Host IDT 通用 handler (AsmHostGpStub / AsmHostPfStub) 收到 trap 时:
 *        if (frame->r10 && frame->r11) {
 *            HV_HOST_EXC_INFO* e = (HV_HOST_EXC_INFO*)frame->r11;
 *            e->ExceptionOccurred = TRUE;
 *            e->Vector = vector;
 *            e->ErrorCode = frame->error;
 *            frame->rip = frame->r10;
 *            frame->r10 = 0; frame->r11 = 0;     ; 防止无限异常
 *            iretq;
 *        }
 *
 * 这套机制让 host 内任何危险内存访问都能"软"被 fault 兜住,不撞 IDT/IST/TSS/CR3,
 * 配合 AsmMemcpySafe 包装 rep movsb 实现 host 内"会 #PF 不蓝屏"的 memcpy.
 *
 * 与 Netr 现有 AsmSafeReadMsr/AsmSafeWriteMsr (硬编码 RIP 比对) 关系:
 *   - 现存 Safe MSR 路径保留,仍走 AsmHostGpStub 内的 RIP 比对分支兼容
 *   - 新增的 stub 全部走 r10/r11 通用分支,IDT handler 优先看 r10/r11
 *   - 任何新增的 host-internal 危险操作走 r10/r11 范式,无需改 IDT handler
 */

#ifndef _HV_HOST_EXC_H_
#define _HV_HOST_EXC_H_

#include <ntddk.h>

#pragma pack(push, 1)
typedef struct _HV_HOST_EXC_INFO {
    UCHAR   ExceptionOccurred;   // 0 = ok, 1 = fault 在 stub 内发生
    UCHAR   Pad0[7];             // 8 字节对齐
    UINT64  Vector;              // 真正发生的 vec (14=#PF, 13=#GP, 6=#UD 等)
    UINT64  ErrorCode;           // CPU 推到栈上的 error code (有些 vec 没有 → 0)
} HV_HOST_EXC_INFO, *PHV_HOST_EXC_INFO;
#pragma pack(pop)

C_ASSERT(sizeof(HV_HOST_EXC_INFO) == 24);

/*
 * AsmMemcpySafe — host 内安全 memcpy. 走 rep movsb, 任何 #PF 会被 r10/r11 协议接住.
 *
 * 调用约定 (Windows x64):
 *   RCX = HV_HOST_EXC_INFO*   (必须非 NULL — stub 入口写 byte 0 默认值)
 *   RDX = dst
 *   R8  = src
 *   R9  = size  (字节数, rep movsb 直接喂)
 *
 * 返回:
 *   - 正常完成: ExceptionOccurred=0
 *   - fault:    ExceptionOccurred=1, Vector/ErrorCode 已填
 *
 * 不保存除 RSI/RDI 之外的非 volatile, MSVC x64 ABI: 调用方栈对齐 16, shadow 0x20.
 *
 * 注意: dst/src 必须是 host 视角下能访问的 HVA. 在 Step 4 (pml4[255] 段映射) 之后,
 *       任何 HPA 都可经 host_physical_memory_base + hpa 转 HVA.
 */
EXTERN_C ULONG AsmMemcpySafe(
    _Inout_ HV_HOST_EXC_INFO* Info,
    _Out_writes_bytes_(Size) void* Dst,
    _In_reads_bytes_(Size) const void* Src,
    _In_ SIZE_T Size);

/*
 * Step 1 一并补的 AsmHostPfStub (vec 14, #PF):
 *   原来 Netr 只装了 vec 13 (#GP) 走 AsmHostGpStub. 现在装上 vec 14 #PF 用同一套 r10/r11
 *   通用协议, 让 AsmMemcpySafe 命中已被 page-out / 非法 GVA 时不再撞 KiPageFault →
 *   triple fault.
 */
EXTERN_C VOID AsmHostPfStub(VOID);

#endif // _HV_HOST_EXC_H_
