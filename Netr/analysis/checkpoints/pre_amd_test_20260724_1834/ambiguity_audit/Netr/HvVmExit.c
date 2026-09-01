/*
 * HvVmExit.c - VM Exit 处理函数实现（完整版）
 *
 * 所有 VM Exit 处理逻辑都在这里实现，汇编只负责寄存器保存/恢复
 *
 * 支持：
 *   - Intel VMX: EPT Hook
 *   - AMD SVM: NPT Hook
 */

#include "HvVmExit.h"
#include "HvCompat.h"
#include "HvEpt.h"
#include "EptHook.h"
#include "NptHook.h"
#include "HvNested.h"
#include "HvNestedEpt.h"
#include "HvNestedSvm.h"
#include "HvNestedNpt.h"
#include "HvVtRoot.h"
#include "HvDebugger.h"
#include "HvHook.h"
#include "HvInput.h"
#include "HvUsbXhci.h"
#include "HvXhciEptTrap.h"
#include "HvCr3Snoop.h"
#include "HvPebCloak.h"  // P125: PEB 字段级 EPT spoof
#include "HvVwatch.h"    // P128: 虚拟硬件断点 (EPT-based)
#include "HvVmcb.h"

// P122: 全 driver DbgPrint → GUI ring
#define HV_TRACE_THIS_CAT HV_TRACE_CAT_VMEXIT
#include "HvTrace.h"

// ==================== 外部变量（汇编定义） ====================

extern ULONG64 g_VmExitCounter;
extern ULONG64 g_LastExitReason;
extern ULONG64 g_ExitCountCpuid;
extern ULONG64 g_ExitCountMsrRead;
extern ULONG64 g_ExitCountMsrWrite;
extern ULONG64 g_ExitCountCrAccess;
extern ULONG64 g_ExitCountException;
extern ULONG64 g_ExitCountVmcall;
extern ULONG64 g_ExitCountEptViolation;
extern ULONG64 g_ExitCountOther;
extern ULONG64 g_ExternalInterruptCount;
extern ULONG64 g_InterruptWindowExitCount;
extern ULONG64 g_UnknownExitReason;

// ==================== 内部变量 ====================

volatile BOOLEAN g_VmxTerminated = FALSE;

// 每 CPU Pending 中断队列（最多支持 64 个 CPU）
#define MAX_CPU_COUNT 64
// 用于 EPT_VIOLATION / EPT_MISCONFIG 兜底重复检测的最大 CPU 数
#define HV_MAX_TRACKED_CPUS 64

// EPT 死循环切断:同 CPU 上 fallback 路径连续 N 次看到同一 GPA 页 → 注 #UD 给
// guest,切断 root 模式无限循环。背景:fallback 修了 PDE/PTE 加 RWX,但若根因
// 不是权限(GPA>512GB 走不到 Pd[][];EptHook split 跨 vcpu SplitPt 找不到 PT;
// reserved bits 错误未修正等)→ guest 重试还是同样 EPT_VIOLATION,所有 CPU
// 困在 root → 看门狗(需 guest 模式调度才能发 IPI)发不出 → 系统纯卡死无 dump。
// 32 次阈值留出"first repair attempt + INVEPT 传播"的窗口,正常单次修复后下个
// GPA 会重置 LastGpaPage,只有真死循环才会触发。
#define EPT_REPEAT_GUARD_THRESHOLD 32
typedef struct _EPT_REPEAT_GUARD {
    volatile ULONG64 LastGpaPage;
    volatile LONG    Count;
} EPT_REPEAT_GUARD;
static EPT_REPEAT_GUARD g_EptRepeatGuard[HV_MAX_TRACKED_CPUS] = { 0 };

#define PENDING_INTR_QUEUE_SIZE 16
typedef struct _PENDING_INTR_QUEUE {
    volatile ULONG64 Entries[PENDING_INTR_QUEUE_SIZE];
    volatile LONG Head;
    volatile LONG Tail;
    volatile LONG Count;
} PENDING_INTR_QUEUE;
static PENDING_INTR_QUEUE g_PendingInterruptQueue[MAX_CPU_COUNT] = { 0 };

static BOOLEAN PendingIntrEnqueue(ULONG cpuIndex, ULONG64 intrInfo)
{
    PENDING_INTR_QUEUE* q = &g_PendingInterruptQueue[cpuIndex];
    LONG count = q->Count;
    if (count >= PENDING_INTR_QUEUE_SIZE) {
        return FALSE; // queue full, drop oldest not ideal but prevents overflow
    }
    LONG tail = q->Tail;
    q->Entries[tail] = intrInfo;
    q->Tail = (tail + 1) % PENDING_INTR_QUEUE_SIZE;
    InterlockedIncrement(&q->Count);
    return TRUE;
}

static ULONG64 PendingIntrDequeue(ULONG cpuIndex)
{
    PENDING_INTR_QUEUE* q = &g_PendingInterruptQueue[cpuIndex];
    if (q->Count <= 0) {
        return 0;
    }
    LONG head = q->Head;
    ULONG64 val = q->Entries[head];
    q->Entries[head] = 0;
    q->Head = (head + 1) % PENDING_INTR_QUEUE_SIZE;
    InterlockedDecrement(&q->Count);
    return val;
}

static BOOLEAN PendingIntrIsEmpty(ULONG cpuIndex)
{
    return g_PendingInterruptQueue[cpuIndex].Count <= 0;
}

// VMCALL 命令定义
#define VMCALL_TEST             1           // 测试调用
#define VMCALL_GET_VERSION      2           // 获取版本
#define VMCALL_TERMINATE        0x1337DEAD  // 退出虚拟化
#define VMCALL_INVEPT           0xEBF00001  // 执行 INVEPT
#define VMCALL_INVVPID          0xEBF00003  // 执行 INVVPID（VPID 跨模式刷新；与 EptHook.c 定义保持一致）

// Hypervisor 版本号
#define HV_VERSION_MAJOR        1
#define HV_VERSION_MINOR        0

// ==================== 反虚拟化检测配置 ====================

// 启用/禁用反检测功能; HV_MINIMAL_MODE 下默认 FALSE, CPUID/MSR 直接透传不伪造
#if HV_MINIMAL_MODE
static BOOLEAN g_AntiVmDetectionEnabled = FALSE;
#else
static BOOLEAN g_AntiVmDetectionEnabled = TRUE;
#endif

// TSC 时间补偿（每 CPU）
// 累积的 VM Exit 开销，用于补偿 RDTSC
static volatile ULONG64 g_TscOffset[MAX_CPU_COUNT] = { 0 };
static volatile ULONG64 g_LastVmExitTsc[MAX_CPU_COUNT] = { 0 };

// 平均 VM Exit 开销（用于补偿）
#define VM_EXIT_TSC_OVERHEAD    1000
// 最大 TSC 偏移量上限（约 1 秒 @ 3GHz），防止无限累积导致 TSC 非单调
#define MAX_TSC_OFFSET          3000000000ULL

// 注：MSR_IA32_FEATURE_CONTROL 与 FEATURE_CONTROL_* 位定义统一在 HvTypes.h

// EPT VMX root 模式标志
extern VOID EptSetVmxRootMode(PVCPU_DATA VcpuData, BOOLEAN InRootMode);
extern UCHAR AsmInveptAllContexts(VOID);
extern UCHAR AsmInvvpidAllContexts(VOID);
extern UCHAR AsmInvvpidSingleContext(USHORT Vpid);
extern UCHAR AsmInvvpidSingleContextRetainingGlobals(USHORT Vpid);
extern PEPT_PTE_ENTRY EptGetPteForPhysicalAddress(ULONG64 PhysicalAddress);
extern PNPT_PTE NptGetPteForPhysicalAddress(PVCPU_DATA VcpuData, ULONG64 PhysicalAddress);

// ==================== 辅助函数 ====================

/*
 * 前进 Guest RIP
 */
static VOID HvAdvanceGuestRip(VOID)
{
    SIZE_T rip, len;
    __vmx_vmread(GUEST_RIP, &rip);
    __vmx_vmread(VM_EXIT_INSTRUCTION_LEN, &len);
    if (len > 0 && len <= 15) {
        __vmx_vmwrite(GUEST_RIP, rip + len);
    }
}

/*
 * 注入中断到 Guest
 */
static VOID HvInjectInterrupt(ULONG vector, ULONG type)
{
    // VM_ENTRY_INTR_INFO: [7:0]=vector, [10:8]=type, [31]=valid
    ULONG64 info = vector | ((ULONG64)type << 8) | (1ULL << 31);
    __vmx_vmwrite(VMCS_CTRL_VMENTRY_INTERRUPTION_INFO, info);
}

/*
 * 2026-06-16: 注入 #GP (vector 13, hardware exception, error code 0) 到 Guest。
 *
 * 用途: SafeMsr 路径接到 #GP 时, 把异常反射回 guest, 让 guest 自己 SEH 接住,
 * 行为与 bare metal 完全一致 (避免反 VM 检测识破)。
 *
 * 关键: 不调 HvAdvanceGuestRip — guest 重新执行 rdmsr 时硬件直接交付 #GP。
 */
static VOID HvInjectGpToGuest(VOID)
{
    // #GP vector 13, type 3 (hardware exception), error code valid (bit 11), valid (bit 31)
    ULONG64 info = 13ULL | (3ULL << 8) | (1ULL << 11) | (1ULL << 31);
    __vmx_vmwrite(VMCS_CTRL_VMENTRY_INTERRUPTION_INFO, info);
    __vmx_vmwrite(VMCS_CTRL_VMENTRY_EXCEPTION_ERROR_CODE, 0);
}

#define HV_CR4_PCIDE_BIT                    (1ULL << 17)
#define HV_CR3_NO_FLUSH_BIT                 (1ULL << 63)
#define HV_CR3_NON_PCID_RESERVED_LOW_MASK   0xFE7ULL
#define HV_VPID_CAP_INVVPID                 (1ULL << 32)
#define HV_VPID_CAP_SINGLE_CONTEXT          (1ULL << 41)
#define HV_VPID_CAP_ALL_CONTEXTS            (1ULL << 42)
#define HV_VPID_CAP_SINGLE_RETAIN_GLOBALS   (1ULL << 43)

static ULONG HvGetMaxPhysicalAddressBits(VOID)
{
    int cpuInfo[4] = { 0 };
    ULONG maxPhysicalBits = 36;

    __cpuid(cpuInfo, 0x80000000);
    if ((ULONG)cpuInfo[0] >= 0x80000008UL) {
        __cpuid(cpuInfo, 0x80000008);
        maxPhysicalBits = (ULONG)cpuInfo[0] & 0xFF;
    }

    if (maxPhysicalBits < 32 || maxPhysicalBits > 63) {
        maxPhysicalBits = 36;
    }
    return maxPhysicalBits;
}

static BOOLEAN HvNormalizeGuestCr3(
    _In_ ULONG64 SourceValue,
    _In_ ULONG64 GuestCr4,
    _Out_ PULONG64 NormalizedCr3,
    _Out_ PBOOLEAN InvalidateTlb)
{
    BOOLEAN pcidEnabled = (GuestCr4 & HV_CR4_PCIDE_BIT) != 0;
    ULONG64 value = SourceValue;

    *InvalidateTlb = TRUE;
    if (value & HV_CR3_NO_FLUSH_BIT) {
        if (!pcidEnabled) {
            return FALSE;
        }
        value &= ~HV_CR3_NO_FLUSH_BIT;
        *InvalidateTlb = FALSE;
    }

    ULONG maxPhysicalBits = HvGetMaxPhysicalAddressBits();
    ULONG64 highReservedMask = ~((1ULL << maxPhysicalBits) - 1ULL);
    if (value & highReservedMask) {
        return FALSE;
    }

    if (!pcidEnabled &&
        (value & HV_CR3_NON_PCID_RESERVED_LOW_MASK) != 0) {
        return FALSE;
    }

    *NormalizedCr3 = value;
    return TRUE;
}

static VOID HvInvalidateCurrentVpidPreservingGlobals(VOID)
{
    SIZE_T secondaryControls = 0;
    SIZE_T vpid = 0;

    if (__vmx_vmread(
            VMCS_CTRL_SECONDARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS,
            &secondaryControls) != 0 ||
        (secondaryControls & SECONDARY_EXEC_ENABLE_VPID) == 0 ||
        __vmx_vmread(VMCS_CTRL_VIRTUAL_PROCESSOR_IDENTIFIER, &vpid) != 0 ||
        (USHORT)vpid == 0) {
        return;
    }

    ULONG64 caps = __readmsr(MSR_IA32_VMX_EPT_VPID_CAP);
    if ((caps & HV_VPID_CAP_INVVPID) == 0) {
        return;
    }

    if ((caps & HV_VPID_CAP_SINGLE_RETAIN_GLOBALS) != 0 &&
        AsmInvvpidSingleContextRetainingGlobals((USHORT)vpid) == 0) {
        return;
    }
    if ((caps & HV_VPID_CAP_SINGLE_CONTEXT) != 0 &&
        AsmInvvpidSingleContext((USHORT)vpid) == 0) {
        return;
    }
    if ((caps & HV_VPID_CAP_ALL_CONTEXTS) != 0) {
        AsmInvvpidAllContexts();
    }
}

static ULONG HvGetDebuggerControlMask(_In_ ULONG Mode)
{
    ULONG64 basic = __readmsr(MSR_IA32_VMX_BASIC);
    ULONG64 controlsMsr = __readmsr(
        (basic & (1ULL << 55))
            ? MSR_IA32_VMX_TRUE_PROCBASED_CTLS
            : MSR_IA32_VMX_PROCBASED_CTLS);
    ULONG allowed0 = (ULONG)controlsMsr;
    ULONG allowed1 = (ULONG)(controlsMsr >> 32);
    ULONG requested = 0;

    if (Mode & HV_DBG_INTERCEPT_MODE_CR3) {
        requested |= CPU_BASED_CR3_LOAD_EXITING;
    }
    if (Mode & HV_DBG_INTERCEPT_MODE_MOV_DR) {
        requested |= CPU_BASED_MOV_DR_EXITING;
    }

    // Bits forced to one belong to the VMX platform, not to the lazy
    // debugger publication state and therefore are never cleared here.
    return requested & allowed1 & ~allowed0;
}

/*
 * 检查 Guest 是否可以接收中断
 */
static BOOLEAN HvCanInjectInterrupt(VOID)
{
    SIZE_T rflags, interruptibility, pendingInfo;

    // Check if VMENTRY_INTERRUPTION_INFO already has a pending injection (bit 31 = valid)
    __vmx_vmread(VMCS_CTRL_VMENTRY_INTERRUPTION_INFO, &pendingInfo);
    if (pendingInfo & (1ULL << 31)) {
        return FALSE;
    }

    __vmx_vmread(GUEST_RFLAGS, &rflags);
    if (!(rflags & 0x200)) {  // IF=0
        return FALSE;
    }

    __vmx_vmread(GUEST_INTERRUPTIBILITY_STATE, &interruptibility);
    if (interruptibility & 0x3) {  // STI/MOV SS blocking
        return FALSE;
    }

    return TRUE;
}

/*
 * 启用中断窗口退出
 */
static VOID HvEnableInterruptWindowExiting(VOID)
{
    SIZE_T controls;
    __vmx_vmread(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, &controls);
    controls |= CPU_BASED_INTERRUPT_WINDOW_EXITING;
    __vmx_vmwrite(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, controls);
}

// P0-2 (2026-05-31): NMI window exiting 助手 + per-CPU pending NMI 计数
// 当 guest BlockingByNmi=1 时强 inject NMI 会 VM-entry failure → 部分 CPU 退 VMX,
// 跨核 IPI 死锁。HyperDbg 范式: 标记 pending, 启用 NMI window exiting, 等
// guest IRET 后(BlockingByNmi 自动清)硬件触发 NMI_WINDOW exit → 再 inject。
static volatile LONG g_PendingNmiPerCpu[MAX_CPU_COUNT] = { 0 };

static VOID HvEnableNmiWindowExiting(VOID)
{
    SIZE_T controls;
    __vmx_vmread(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, &controls);
    controls |= CPU_BASED_NMI_WINDOW_EXITING;
    __vmx_vmwrite(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, controls);
}

static VOID HvDisableNmiWindowExiting(VOID)
{
    SIZE_T controls;
    __vmx_vmread(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, &controls);
    controls &= ~(SIZE_T)CPU_BASED_NMI_WINDOW_EXITING;
    __vmx_vmwrite(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, controls);
}

/*
 * 禁用中断窗口退出
 */
static VOID HvDisableInterruptWindowExiting(VOID)
{
    SIZE_T controls;
    __vmx_vmread(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, &controls);
    controls &= ~(SIZE_T)CPU_BASED_INTERRUPT_WINDOW_EXITING;
    __vmx_vmwrite(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, controls);
}

// ============================================================
// 包装层 — 给 HvInput.c 等模块调用
// ============================================================

VOID HvVmExitInjectInterrupt(ULONG vector, ULONG type)
{
    HvInjectInterrupt(vector, type);
}

BOOLEAN HvVmExitCanInjectInterrupt(VOID)
{
    return HvCanInjectInterrupt();
}

VOID HvVmExitEnqueuePendingIntr(ULONG cpuIndex, ULONG64 intrInfo)
{
    if (cpuIndex < MAX_CPU_COUNT) {
        (VOID)PendingIntrEnqueue(cpuIndex, intrInfo);
    }
}

VOID HvVmExitEnableInterruptWindowExiting(VOID)
{
    HvEnableInterruptWindowExiting();
}

// ==================== P0-5: KeRegisterNmiCallback ====================
//
// HyperDbg 范式: 在 non-root 模式 (system normal context) 上注册 NMI callback,
// 让 hypervisor 能识别自投递的 broadcast NMI 与系统 NMI。Netr 现在不用 NMI 做
// broadcast (P2-5 已加 DPC broadcast 替代), 但注册 callback 仍有价值:
//   1) 诊断 Win11 NMI watchdog 频率 (Win10 几乎 0, Win11 高频)
//   2) 未来若 P0-2 NMI window 路径需要在 non-root 同步, 可在 callback 里挂钩
//
// callback signature: BOOLEAN (*PNMI_CALLBACK)(PVOID Context, BOOLEAN Handled)
// 返回 FALSE 让其他 callback 继续 (我们不抢占 Windows NMI 路径)。

typedef BOOLEAN (*PHV_NMI_CALLBACK)(PVOID Context, BOOLEAN Handled);

NTKERNELAPI PVOID KeRegisterNmiCallback(
    _In_ PHV_NMI_CALLBACK CallbackRoutine,
    _In_opt_ PVOID Context
);

NTKERNELAPI NTSTATUS KeDeregisterNmiCallback(
    _In_ PVOID Handle
);

volatile ULONG64 g_HvVmExitNmiCallbackCount = 0;
static PVOID g_HvNmiCallbackHandle = NULL;

static BOOLEAN HvVmExitNmiCallback(PVOID Context, BOOLEAN Handled)
{
    UNREFERENCED_PARAMETER(Context);
    InterlockedIncrement64((volatile LONG64*)&g_HvVmExitNmiCallbackCount);
    // 不抢占 Windows NMI 链, 返回 Handled 让链上其他 callback 继续
    return Handled;
}

NTSTATUS HvVmExitInitialize(VOID)
{
    if (g_HvNmiCallbackHandle != NULL) {
        return STATUS_SUCCESS;  // 已注册过
    }

    g_HvNmiCallbackHandle = KeRegisterNmiCallback(HvVmExitNmiCallback, NULL);
    if (g_HvNmiCallbackHandle == NULL) {
        DbgPrint("[HV] KeRegisterNmiCallback failed (no NMI diagnostic)\n");
        return STATUS_UNSUCCESSFUL;
    }
    DbgPrint("[HV] KeRegisterNmiCallback OK, handle=0x%llX\n", (ULONG64)g_HvNmiCallbackHandle);
    return STATUS_SUCCESS;
}

VOID HvVmExitCleanup(VOID)
{
    if (g_HvNmiCallbackHandle != NULL) {
        NTSTATUS s = KeDeregisterNmiCallback(g_HvNmiCallbackHandle);
        DbgPrint("[HV] KeDeregisterNmiCallback returned 0x%X (NMI callback count = %llu)\n",
                 s, g_HvVmExitNmiCallbackCount);
        g_HvNmiCallbackHandle = NULL;
    }
}

// ==================== VM Exit Handlers ====================

/*
 * 处理 CPUID - 完整反虚拟化检测
 * 
 * 隐藏以下特征：
 * - CPUID.1.ECX[5]  = VMX 支持位
 * - CPUID.1.ECX[31] = Hypervisor Present 位
 * - CPUID.0x40000000-0x4FFFFFFF = Hypervisor 信息叶
 * - CPUID.80000001H.ECX[2] = SVM 支持位
 */
static VOID HvHandleCpuid(PGUEST_CONTEXT ctx)
{
    int cpuInfo[4] = { 0 };
    ULONG32 leaf = (ULONG32)ctx->Rax;
    ULONG32 subleaf = (ULONG32)ctx->Rcx;
    PVCPU_DATA vcpuData = HvNestedGetCurrentVcpu();
    
    InterlockedIncrement64((volatile LONG64*)&g_ExitCountCpuid);
    
    // 处理 Hypervisor 保留叶（0x40000000 - 0x4FFFFFFF）
    if (g_AntiVmDetectionEnabled && (leaf >= 0x40000000 && leaf <= 0x4FFFFFFF)) {
        // 返回零值，表示不存在 Hypervisor 信息
        // 这会欺骗检测工具认为没有 Hypervisor
        ctx->Rax = 0;
        ctx->Rbx = 0;
        ctx->Rcx = 0;
        ctx->Rdx = 0;
        HvAdvanceGuestRip();
        return;
    }
    
    // 执行真正的 CPUID
    __cpuidex(cpuInfo, (int)leaf, (int)subleaf);
    
    // 嵌套虚拟化处理：
    // 当嵌套虚拟化启用时，保留 VMX/SVM 能力位，让 L1 Hypervisor 正常工作
    if (g_EnableNestedVirtualization && vcpuData) {
        switch (leaf) {
        case 0:
            // CPUID.0: 保持不变
            break;
            
        case 1:
            // CPUID.1: 处理器特性
            // 嵌套虚拟化启用时，保留 VMX 位，让 L1 认为支持虚拟化
            // ECX[5]  = VMX（Intel VT-x）支持 - 保留
            // ECX[31] = Hypervisor Present - 隐藏（让 L1 认为运行在真实硬件上）
            cpuInfo[2] &= ~(1 << 31);  // 清除 Hypervisor Present 位
            // 注意：VMX 位保持不变，允许 L1 使用虚拟化
            break;
            
        case 7:
            // CPUID.7: 扩展特性 - 保持不变
            break;
            
        case 0x80000001:
            // AMD 扩展特性
            // 嵌套虚拟化启用时保留 SVM 位
            // ECX[2] = SVM（AMD-V）支持 - 保留
            break;
            
        case 0x8000000A:
            // AMD SVM 特性 - 返回真实值让 L1 使用
            break;
        }
    }
    // 反虚拟化检测处理（仅当嵌套虚拟化未启用时）
    else if (g_AntiVmDetectionEnabled) {
        switch (leaf) {
        case 0:
            // CPUID.0: 保持最大叶号不变，但确保不超过 0x40000000 范围
            // 某些检测会检查最大叶号是否异常
            break;
            
        case 1:
            // CPUID.1: 处理器特性
            // ECX[5]  = VMX（Intel VT-x）支持 - 隐藏
            // ECX[31] = Hypervisor Present - 隐藏
            cpuInfo[2] &= ~(1 << 5);   // 清除 VMX 位
            cpuInfo[2] &= ~(1 << 31);  // 清除 Hypervisor Present 位
            break;
            
        case 6:
            // CPUID.6: 热量和电源管理
            // 某些 Hypervisor 会修改此值，保持原样
            break;
            
        case 7:
            // CPUID.7: 扩展特性
            if (subleaf == 0) {
                // EBX[0] = FSGSBASE, 保持
                // 不修改，避免破坏功能
            }
            break;
            
        case 0x80000001:
            // AMD 扩展特性
            // ECX[2] = SVM（AMD-V）支持 - 隐藏
            cpuInfo[2] &= ~(1 << 2);   // 清除 SVM 位
            break;
            
        case 0x8000000A:
            // AMD SVM 特性（如果支持）
            // 返回 0 表示不支持 SVM
            cpuInfo[0] = 0;  // SVM 版本 = 0
            cpuInfo[1] = 0;  // NASID = 0
            cpuInfo[3] = 0;  // SVM 特性 = 0
            break;
        }
    }
    
    ctx->Rax = cpuInfo[0];
    ctx->Rbx = cpuInfo[1];
    ctx->Rcx = cpuInfo[2];
    ctx->Rdx = cpuInfo[3];
    
    HvAdvanceGuestRip();
}

/*
 * 处理 VMCALL
 * 返回：TRUE = 继续执行，FALSE = 终止虚拟化
 */
static BOOLEAN HvHandleVmcall(PGUEST_CONTEXT ctx)
{
    InterlockedIncrement64((volatile LONG64*)&g_ExitCountVmcall);
    
    switch (ctx->Rcx) {
    case VMCALL_TEST:
        // 测试调用，返回魔数
        ctx->Rax = 0xDEADBEEF;
        break;
        
    case VMCALL_GET_VERSION:
        // 返回版本号
        ctx->Rax = (HV_VERSION_MAJOR << 16) | HV_VERSION_MINOR;
        break;
        
    case VMCALL_TERMINATE:
        // 终止虚拟化
        ctx->Rax = 0;
        HvAdvanceGuestRip();
        return FALSE;  // 终止
        
    case VMCALL_INVEPT:
        // 执行 INVEPT
        ctx->Rax = AsmInveptAllContexts();
        break;

    case VMCALL_INVVPID:
        // 执行 INVVPID（VPID 启用后 EptInvvpidAllContexts 高 IRQL 路径在这里落地）
        ctx->Rax = AsmInvvpidAllContexts();
        break;

    case VMCALL_REFRESH_HWBP_STATE: {
        SIZE_T guestCr3 = 0;
        __vmx_vmread(GUEST_CR3, &guestCr3);
        __vmx_vmwrite(
            GUEST_DR7,
            HvDbgRootOnCr3Switch((UINT64)guestCr3));
        ctx->Rax = 0;
        break;
    }

    case VMCALL_PHYS_COPY: {
        // Bounded VT-root service. PID/EPROCESS/CR3 discovery is completed
        // before VMCALL; root receives one validated CR3 and handles one page.
        //   RDX=target CR3, R8=target GVA, R9=nonpaged bounce buffer,
        //   R10=size/result, R11=read/write/GVA-to-HPA mode.
        PVCPU_DATA vcpu = HvNestedGetCurrentVcpu();
        ULONG mode = (ULONG)(ctx->R11 & 0xFFFFFFFFULL);
        UINT64 targetCr3 = ctx->Rdx;
        NTSTATUS s;

        if (mode == HV_VTROOT_MODE_PROCESS_READ ||
            mode == HV_VTROOT_MODE_PROCESS_WRITE ||
            mode == HV_VTROOT_MODE_PROCESS_RESOLVE ||
            mode == HV_VTROOT_MODE_PROCESS_WALK) {
            UINT64 result = 0;
            s = HvVtRootRootProcessRequest(
                vcpu, (PVOID)(ULONG_PTR)ctx->Rdx, mode, &result);
            ctx->R10 = result;
        } else if (mode == HV_VTROOT_MODE_GVA_TO_HPA) {
            UINT64 hpa = 0, pageSize = 0;
            s = HvVtRootRootWalkGvaToHpaWithCr3(
                vcpu, targetCr3, ctx->R8, &hpa, &pageSize);
            if (NT_SUCCESS(s)) {
                if (pageSize == PAGE_SIZE) {
                    ctx->R10 = hpa;
                } else {
                    ctx->R10 = pageSize;
                    s = STATUS_NOT_SUPPORTED;
                }
            } else {
                ctx->R10 = 0;
            }
        } else if (mode == HV_VTROOT_MODE_LEAF_PTE_INFO) {
            SIZE_T infoSize = (SIZE_T)ctx->R10;
            if (infoSize != sizeof(HV_VTROOT_LEAF_PTE_INFO)) {
                ctx->R10 = 0;
                s = STATUS_INFO_LENGTH_MISMATCH;
            } else {
                s = HvVtRootRootQueryLeafPteWithCr3(
                    vcpu, targetCr3, ctx->R8,
                    (PHV_VTROOT_LEAF_PTE_INFO)(ULONG_PTR)ctx->R9);
                ctx->R10 = NT_SUCCESS(s)
                    ? sizeof(HV_VTROOT_LEAF_PTE_INFO)
                    : 0;
            }
        } else if (mode == HV_VTROOT_DIR_READ ||
                   mode == HV_VTROOT_DIR_WRITE) {
            SIZE_T done = 0;
            s = HvVtRootRootCopyOnePage(
                vcpu, targetCr3,
                ctx->R8,                            // target GVA
                (PUCHAR)ctx->R9,                    // kernel buffer
                (SIZE_T)ctx->R10,                   // size
                (BOOLEAN)(mode == HV_VTROOT_DIR_WRITE),
                &done);
            ctx->R10 = (ULONG64)done;
        } else {
            ctx->R10 = 0;
            s = STATUS_NOT_SUPPORTED;
        }
        ctx->Rax = (ULONG64)s;
        break;
    }

    default:
        // Publish or withdraw debugger CR3/DR exits on this VMCS.
        if ((ctx->Rcx & ~(ULONG64)HV_DBG_INTERCEPT_MODE_MASK) ==
            VMCALL_SET_DEBUGGER_INTERCEPT_MODE) {
            SIZE_T controls = 0;
            ULONG mode = (ULONG)ctx->Rcx & HV_DBG_INTERCEPT_MODE_MASK;
            ULONG managedMask =
                HvGetDebuggerControlMask(HV_DBG_INTERCEPT_MODE_MASK);
            ULONG requestedMask = HvGetDebuggerControlMask(mode);
            BOOLEAN hadMovDr;
            __vmx_vmread(
                VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS,
                &controls);
            hadMovDr =
                (controls & HvGetDebuggerControlMask(
                    HV_DBG_INTERCEPT_MODE_MOV_DR)) != 0;
            controls &= ~(SIZE_T)managedMask;
            controls |= requestedMask;
            __vmx_vmwrite(
                VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS,
                controls);
            if (mode & HV_DBG_INTERCEPT_MODE_MOV_DR) {
                SIZE_T guestCr3 = 0;
                __vmx_vmread(GUEST_CR3, &guestCr3);
                __vmx_vmwrite(
                    GUEST_DR7,
                    HvDbgRootOnCr3Switch((UINT64)guestCr3));
            } else if (hadMovDr) {
                HvDbgClearHardwareDr();
                __vmx_vmwrite(GUEST_DR7, (1ULL << 10));
            }
            ctx->Rax = 0;
            break;
        }
        // 未知 VMCALL
        ctx->Rax = (ULONG64)-1;
        break;
    }
    
    HvAdvanceGuestRip();
    return TRUE;
}

/*
 * 处理 MSR 读取 - 带反虚拟化检测
 * 
 * 隐藏以下 MSR：
 * - IA32_FEATURE_CONTROL (0x3A): 隐藏 VMX 启用位
 * - IA32_VMX_BASIC 等 VMX MSR: 返回 0
 * - MSR_AMD_VM_CR (0xC0010114): 隐藏 SVM 状态
 */
static VOID HvHandleMsrRead(PGUEST_CONTEXT ctx)
{
    ULONG64 value = 0;
    ULONG32 msr = (ULONG32)ctx->Rcx;
    BOOLEAN shouldFake = FALSE;
    BOOLEAN gpRaised = FALSE;
    PVCPU_DATA vcpuData = HvNestedGetCurrentVcpu();

    InterlockedIncrement64((volatile LONG64*)&g_ExitCountMsrRead);

    // 首先检查是否需要为嵌套虚拟化返回 VMX MSR
    // 当嵌套虚拟化启用时，L1 Hypervisor 需要看到 VMX 能力
    if (g_EnableNestedVirtualization && vcpuData) {
        switch (msr) {
        case MSR_IA32_FEATURE_CONTROL:  // 0x3A
            // 返回允许 VMX 的值
            value = AsmSafeReadMsr(msr, &gpRaised);
            // 保留 VMX outside SMX 位，让 L1 认为可以使用 VMX
            value |= FEATURE_CONTROL_VMXON_OUTSIDE_SMX | FEATURE_CONTROL_LOCK;
            shouldFake = TRUE;
            break;

        // Intel VMX MSRs (0x480 - 0x491) - 为嵌套虚拟化返回真实值
        case 0x480:  // IA32_VMX_BASIC
        case 0x481:  // IA32_VMX_PINBASED_CTLS
        case 0x482:  // IA32_VMX_PROCBASED_CTLS
        case 0x483:  // IA32_VMX_EXIT_CTLS
        case 0x484:  // IA32_VMX_ENTRY_CTLS
        case 0x485:  // IA32_VMX_MISC
        case 0x486:  // IA32_VMX_CR0_FIXED0
        case 0x487:  // IA32_VMX_CR0_FIXED1
        case 0x488:  // IA32_VMX_CR4_FIXED0
        case 0x489:  // IA32_VMX_CR4_FIXED1
        case 0x48A:  // IA32_VMX_VMCS_ENUM
        case 0x48B:  // IA32_VMX_PROCBASED_CTLS2
        case 0x48C:  // IA32_VMX_EPT_VPID_CAP
        case 0x48D:  // IA32_VMX_TRUE_PINBASED_CTLS
        case 0x48E:  // IA32_VMX_TRUE_PROCBASED_CTLS
        case 0x48F:  // IA32_VMX_TRUE_EXIT_CTLS
        case 0x490:  // IA32_VMX_TRUE_ENTRY_CTLS
        case 0x491:  // IA32_VMX_VMFUNC
            // 为 L1 Hypervisor 返回真实的 VMX 能力
            // 这允许 L1 认为它可以使用虚拟化功能
            value = AsmSafeReadMsr(msr, &gpRaised);
            shouldFake = TRUE;
            break;
        }
    }

    // 如果嵌套虚拟化未启用，使用反检测逻辑
    if (!shouldFake && g_AntiVmDetectionEnabled) {
        switch (msr) {
        case MSR_IA32_FEATURE_CONTROL:  // 0x3A
            // 读取真实值，但隐藏 VMX 相关位
            value = AsmSafeReadMsr(msr, &gpRaised);
            // 清除 VMX outside SMX 位，保留 Lock 位
            value &= ~FEATURE_CONTROL_VMXON_OUTSIDE_SMX;
            shouldFake = TRUE;
            break;

        // Intel VMX MSRs (0x480 - 0x491)
        case 0x480:  // IA32_VMX_BASIC
        case 0x481:  // IA32_VMX_PINBASED_CTLS
        case 0x482:  // IA32_VMX_PROCBASED_CTLS
        case 0x483:  // IA32_VMX_EXIT_CTLS
        case 0x484:  // IA32_VMX_ENTRY_CTLS
        case 0x485:  // IA32_VMX_MISC
        case 0x486:  // IA32_VMX_CR0_FIXED0
        case 0x487:  // IA32_VMX_CR0_FIXED1
        case 0x488:  // IA32_VMX_CR4_FIXED0
        case 0x489:  // IA32_VMX_CR4_FIXED1
        case 0x48A:  // IA32_VMX_VMCS_ENUM
        case 0x48B:  // IA32_VMX_PROCBASED_CTLS2
        case 0x48C:  // IA32_VMX_EPT_VPID_CAP
        case 0x48D:  // IA32_VMX_TRUE_PINBASED_CTLS
        case 0x48E:  // IA32_VMX_TRUE_PROCBASED_CTLS
        case 0x48F:  // IA32_VMX_TRUE_EXIT_CTLS
        case 0x490:  // IA32_VMX_TRUE_ENTRY_CTLS
        case 0x491:  // IA32_VMX_VMFUNC
            // 返回 0，表示不支持 VMX（仅当嵌套虚拟化关闭时）
            value = 0;
            shouldFake = TRUE;
            break;

        // AMD SVM MSRs
        case 0xC0010114:  // MSR_AMD_VM_CR
            // 返回 SVM 禁用状态
            value = (1ULL << 4);  // SVMDIS = 1 (SVM 被禁用)
            shouldFake = TRUE;
            break;

        case 0xC0010117:  // MSR_AMD_VM_HSAVE_PA
            // 返回 0
            value = 0;
            shouldFake = TRUE;
            break;

        case 0xC001011F:  // MSR_AMD_SVM_KEY
            // 返回 0
            value = 0;
            shouldFake = TRUE;
            break;
        }
    }

    if (!shouldFake) {
        // 2026-06-16: SafeReadMsr 替换 __readmsr — vmx-root 上非法 MSR rdmsr 会
        // #GP, SEH 因 host RSP 不在已登记栈区间撞 0x1AA。SafeReadMsr 用裸 #GP stub
        // 接住。#GP 时反射给 guest, 使行为与 bare metal 一致 (避免反 VM 检测)。
        value = AsmSafeReadMsr(msr, &gpRaised);
        if (gpRaised) {
            HvInjectGpToGuest();
            return;   // 不 advance RIP, guest 重新执行 rdmsr 时硬件直接交付 #GP
        }
    }

    ctx->Rax = (ULONG32)value;
    ctx->Rdx = (ULONG32)(value >> 32);

    HvAdvanceGuestRip();
}

/*
 * 处理 MSR 写入 - 过滤危险 MSR 防止系统崩溃
 */
static VOID HvHandleMsrWrite(PGUEST_CONTEXT ctx)
{
    ULONG32 msr = (ULONG32)ctx->Rcx;
    ULONG64 value = ((ULONG64)(ULONG32)ctx->Rdx << 32) | (ULONG32)ctx->Rax;

    InterlockedIncrement64((volatile LONG64*)&g_ExitCountMsrWrite);

    // 阶段 8.0 反检测：写隐藏的 VMX/SVM 相关 MSR 一律静默吞掉，
    // 避免硬件 #GP 暴露"该 MSR 实际存在"的旁路信号。
    if (g_AntiVmDetectionEnabled) {
        switch (msr) {
        case MSR_IA32_FEATURE_CONTROL:   // 0x3A
        case 0x480: case 0x481: case 0x482: case 0x483:
        case 0x484: case 0x485: case 0x486: case 0x487:
        case 0x488: case 0x489: case 0x48A: case 0x48B:
        case 0x48C: case 0x48D: case 0x48E: case 0x48F:
        case 0x490: case 0x491:
        case 0xC0010114:                  // MSR_AMD_VM_CR
        case 0xC0010117:                  // MSR_AMD_VM_HSAVE_PA
        case 0xC001011F:                  // MSR_AMD_SVM_KEY
            HvAdvanceGuestRip();
            return;
        }
    }

    switch (msr) {
    case MSR_IA32_EFER:
        // 不允许 Guest 清除 LME/LMA/SVME，只更新 VMCS Guest EFER
        __vmx_vmwrite(GUEST_IA32_EFER, value);
        break;

    case 0x1B:  // IA32_APIC_BASE - 不允许修改 APIC 基址
        break;

    case 0xC0000082:  // IA32_LSTAR - SYSCALL 入口，直接写入物理 MSR
        if (!AsmSafeWriteMsr(msr, (ULONG32)value, (ULONG32)(value >> 32))) {
            HvInjectGpToGuest();
            return;
        }
        break;

    case MSR_IA32_PAT:
        __vmx_vmwrite(GUEST_IA32_PAT, value);
        break;

    default:
        if (!AsmSafeWriteMsr(msr, (ULONG32)value, (ULONG32)(value >> 32))) {
            HvInjectGpToGuest();
            return;
        }
        break;
    }

    HvAdvanceGuestRip();
}

/*
 * 处理 CR 访问
 */
static VOID HvHandleCrAccess(PGUEST_CONTEXT ctx)
{
    SIZE_T qualification;
    ULONG crNum, accessType, gprIndex;
    ULONG64 *gprPtr;
    ULONG64 gprArray[16];
    
    InterlockedIncrement64((volatile LONG64*)&g_ExitCountCrAccess);
    
    __vmx_vmread(VM_EXIT_QUALIFICATION, &qualification);
    
    crNum = qualification & 0xF;
    accessType = (qualification >> 4) & 0x3;
    gprIndex = (qualification >> 8) & 0xF;
    
    // 构建 GPR 数组
    gprArray[0] = ctx->Rax;
    gprArray[1] = ctx->Rcx;
    gprArray[2] = ctx->Rdx;
    gprArray[3] = ctx->Rbx;
    gprArray[4] = 0;  // RSP - 需要从 VMCS 读取
    gprArray[5] = ctx->Rbp;
    gprArray[6] = ctx->Rsi;
    gprArray[7] = ctx->Rdi;
    gprArray[8] = ctx->R8;
    gprArray[9] = ctx->R9;
    gprArray[10] = ctx->R10;
    gprArray[11] = ctx->R11;
    gprArray[12] = ctx->R12;
    gprArray[13] = ctx->R13;
    gprArray[14] = ctx->R14;
    gprArray[15] = ctx->R15;
    
    if (gprIndex == 4) {
        SIZE_T rsp;
        __vmx_vmread(GUEST_RSP, &rsp);
        gprArray[4] = rsp;
    }
    
    gprPtr = &gprArray[gprIndex];
    
    if (accessType == 0) {
        // MOV to CR
        switch (crNum) {
        case 0:
            __vmx_vmwrite(GUEST_CR0, *gprPtr);
            __vmx_vmwrite(VMCS_CTRL_CR0_READ_SHADOW, *gprPtr);
            break;
        case 3: {
            SIZE_T guestCr4 = 0;
            ULONG64 normalizedCr3 = 0;
            BOOLEAN invalidateTlb = TRUE;

            __vmx_vmread(GUEST_CR4, &guestCr4);
            if (!HvNormalizeGuestCr3(
                    *gprPtr,
                    (ULONG64)guestCr4,
                    &normalizedCr3,
                    &invalidateTlb)) {
                HvInjectGpToGuest();
                return;
            }

            if (invalidateTlb) {
                HvInvalidateCurrentVpidPreservingGlobals();
            }
            __vmx_vmwrite(GUEST_CR3, normalizedCr3);
            if (HvDebuggerPublishedMovDrExiting()) {
                __vmx_vmwrite(
                    GUEST_DR7,
                    HvDbgRootOnCr3Switch(normalizedCr3));
            }
            {
                PVCPU_DATA vcpuData = HvNestedGetCurrentVcpu();
                if (vcpuData) {
                    (void)HvVwatchTryAdoptScopedOverlayCr3ByMappingRoot(
                        vcpuData,
                        normalizedCr3);
                    HvPebCloakClassifyAndSwitchEptp(
                        vcpuData,
                        normalizedCr3);
                }
            }
            break;
        }
        case 4: {
            // 强制保留 VMXE=1（VMX 运行期间硬件要求），shadow 隐藏 VMXE
            ULONG64 cr4_vmxe = (1ULL << 13);
            __vmx_vmwrite(GUEST_CR4, (*gprPtr) | cr4_vmxe);
            __vmx_vmwrite(VMCS_CTRL_CR4_READ_SHADOW, (*gprPtr) & ~cr4_vmxe);
            break;
        }
        }
    }
    else if (accessType == 1) {
        // MOV from CR
        SIZE_T value = 0;
        switch (crNum) {
        case 0:
            __vmx_vmread(GUEST_CR0, &value);
            break;
        case 3:
            __vmx_vmread(GUEST_CR3, &value);
            break;
        case 4:
            // 走到这里说明 mask 命中，但 MOV from CR 通常硬件直接返回 shadow，
            // 罕见路径下保险：从 shadow 读，保持 VMXE 隐藏
            __vmx_vmread(VMCS_CTRL_CR4_READ_SHADOW, &value);
            break;
        }
        
        // 写回到上下文
        switch (gprIndex) {
        case 0: ctx->Rax = value; break;
        case 1: ctx->Rcx = value; break;
        case 2: ctx->Rdx = value; break;
        case 3: ctx->Rbx = value; break;
        case 4: __vmx_vmwrite(GUEST_RSP, value); break;
        case 5: ctx->Rbp = value; break;
        case 6: ctx->Rsi = value; break;
        case 7: ctx->Rdi = value; break;
        case 8: ctx->R8 = value; break;
        case 9: ctx->R9 = value; break;
        case 10: ctx->R10 = value; break;
        case 11: ctx->R11 = value; break;
        case 12: ctx->R12 = value; break;
        case 13: ctx->R13 = value; break;
        case 14: ctx->R14 = value; break;
        case 15: ctx->R15 = value; break;
        }
    }
    
    HvAdvanceGuestRip();
}

/*
 * 阶段 7: MOV-DR 处理 (VMX)
 *
 * Exit Qualification 位布局:
 *   bits 0-2  : DR 号 (DR0-DR7)
 *   bit  4    : 0=mov to dr (write), 1=mov from dr (read)
 *   bits 8-11 : GPR 编码 (RAX=0, RCX=1, ..., R15=15)
 *
 * 行为:
 *   - 被保护进程内: read 返回 0,write 静默吞掉(不让 guest 修改我们的断点状态)
 *   - 其他进程    : 透传真硬件 DR
 *
 * 注:启用 MOV-DR exiting 后,被监控进程的 DR 由 HvDbgLoadHardwareDr/Clear 在 CR3 切换时设;
 *    普通进程的 DR 透传到真硬件,他们的合法 DR 使用不被影响。
 */
static VOID HvHandleMovDr(_Inout_ PGUEST_CONTEXT ctx)
{
    SIZE_T qual = 0;
    __vmx_vmread(VM_EXIT_QUALIFICATION, &qual);

    ULONG drNum    = (ULONG)(qual & 0x7);
    BOOLEAN isRead = (qual & 0x10) != 0;
    ULONG gprIdx   = (ULONG)((qual >> 8) & 0xF);

    SIZE_T guestCr3 = 0;
    __vmx_vmread(GUEST_CR3, &guestCr3);
    BOOLEAN isProtectedTarget = HvDbgRootIsTargetCr3((UINT64)guestCr3);

    // 构建 GPR 数组(同 CR_ACCESS pattern)
    ULONG64 gprArray[16];
    gprArray[0]  = ctx->Rax;
    gprArray[1]  = ctx->Rcx;
    gprArray[2]  = ctx->Rdx;
    gprArray[3]  = ctx->Rbx;
    gprArray[4]  = 0;  // RSP 特殊
    gprArray[5]  = ctx->Rbp;
    gprArray[6]  = ctx->Rsi;
    gprArray[7]  = ctx->Rdi;
    gprArray[8]  = ctx->R8;
    gprArray[9]  = ctx->R9;
    gprArray[10] = ctx->R10;
    gprArray[11] = ctx->R11;
    gprArray[12] = ctx->R12;
    gprArray[13] = ctx->R13;
    gprArray[14] = ctx->R14;
    gprArray[15] = ctx->R15;

    if (gprIdx == 4) {
        SIZE_T rsp = 0;
        __vmx_vmread(GUEST_RSP, &rsp);
        gprArray[4] = rsp;
    }

    if (isRead) {
        // DR0-DR3/DR7 contain the hidden breakpoint state. DR6 remains the
        // guest's architectural value; synthetic vwatch causes are published
        // later through the debugger-context virtualization path.
        ULONG64 value = 0;
        if (!isProtectedTarget || drNum == 6) {
            if (drNum == 7) {
                SIZE_T guestDr7 = 0;
                __vmx_vmread(GUEST_DR7, &guestDr7);
                value = (ULONG64)guestDr7;
            } else {
                value = HvDbgReadRealDr(drNum);
            }
        }
        switch (gprIdx) {
        case 0:  ctx->Rax = value; break;
        case 1:  ctx->Rcx = value; break;
        case 2:  ctx->Rdx = value; break;
        case 3:  ctx->Rbx = value; break;
        case 4:  __vmx_vmwrite(GUEST_RSP, value); break;
        case 5:  ctx->Rbp = value; break;
        case 6:  ctx->Rsi = value; break;
        case 7:  ctx->Rdi = value; break;
        case 8:  ctx->R8  = value; break;
        case 9:  ctx->R9  = value; break;
        case 10: ctx->R10 = value; break;
        case 11: ctx->R11 = value; break;
        case 12: ctx->R12 = value; break;
        case 13: ctx->R13 = value; break;
        case 14: ctx->R14 = value; break;
        case 15: ctx->R15 = value; break;
        }
    } else {
        // MOV to DR
        if (!isProtectedTarget || drNum == 6) {
            if (drNum == 7) {
                __vmx_vmwrite(GUEST_DR7, gprArray[gprIdx]);
            } else {
                HvDbgWriteRealDr(drNum, gprArray[gprIdx]);
            }
        }
        // else: 静默吞掉,不让 guest 修改我们的 HWBP 状态
    }

    HvAdvanceGuestRip();
}

/*
 * 处理外部中断
 * 
 * 重要：如果 VM_EXIT_ACK_INTR_ON_EXIT 被启用，中断已被 acknowledge，
 * 必须重新注入到 Guest，否则系统会丢失中断导致卡死。
 * 
 * 如果 VM_EXIT_ACK_INTR_ON_EXIT 未启用，这个函数不会被调用
 * （外部中断不会触发 VM Exit，除非 PIN_BASED_EXTERNAL_INTERRUPT_EXITING 被强制启用）
 */
static VOID HvHandleExternalInterrupt(_In_ PVCPU_DATA VcpuData)
{
    SIZE_T intrInfo;
    ULONG vector;
    ULONG cpuIndex;

    InterlockedIncrement64((volatile LONG64*)&g_ExternalInterruptCount);

    // P1-9 (2026-05-31): 移除 ACK_INTR_ON_EXIT 兜底 return。
    //
    // 旧实现: !ackOnExit 时直接 return, 依赖 hardware redeliver。但 hardware
    // redeliver 只在 guest 可接收时 (IF=1, 非 STI/MOV-SS blocking) 才发生; 若
    // guest IF=0, 中断 latch 在 LAPIC ISR 永远不被 ACK → 后续同 vector 中断
    // 全部 stuck → HPET clock tick 死锁 → 整机卡死无 dump。
    //
    // 新策略: 始终 vmread VM_EXIT_INTERRUPTION_INFO, valid 则显式 enqueue
    // 或 inject (与 ackOnExit 启用时同款路径)。不影响 ackOnExit 关闭时的
    // hardware-自动 redeliver — 我们的 explicit inject 会被 hardware merge,
    // 无重复 (同 vector LAPIC 自动去重)。
    __vmx_vmread(VM_EXIT_INTERRUPTION_INFO, &intrInfo);

    if (!(intrInfo & (1ULL << 31))) {
        return;  // 无效
    }

    vector = (ULONG)(intrInfo & 0xFF);
    
    // 中断已被 acknowledge，必须重新注入
    if (HvCanInjectInterrupt()) {
        // Guest 可以接收中断，直接注入
        HvInjectInterrupt(vector, 0);  // type=0 外部中断
    }
    else {
        // Guest 暂时无法接收中断（IF=0 或 STI/MOV SS blocking）
        // 保存到 pending 队列（环形缓冲区，防止中断丢失）
        cpuIndex = VcpuData ? VcpuData->ProcessorNumber : MAX_CPU_COUNT;
        if (cpuIndex < MAX_CPU_COUNT) {
            PendingIntrEnqueue(cpuIndex, intrInfo);
        }

        // 启用中断窗口退出
        HvEnableInterruptWindowExiting();
    }
}

/*
 * 处理中断窗口
 * 
 * 当 Guest 变为可以接收中断状态时触发，注入之前保存的 pending 中断
 */
static VOID HvHandleInterruptWindow(_In_ PVCPU_DATA VcpuData)
{
    ULONG cpuIndex;
    ULONG64 pendingIntr;
    ULONG vector;

    InterlockedIncrement64((volatile LONG64*)&g_InterruptWindowExitCount);

    cpuIndex = VcpuData ? VcpuData->ProcessorNumber : MAX_CPU_COUNT;
    if (cpuIndex < MAX_CPU_COUNT) {
        pendingIntr = PendingIntrDequeue(cpuIndex);

        if (pendingIntr & (1ULL << 31)) {
            vector = (ULONG)(pendingIntr & 0xFF);
            HvInjectInterrupt(vector, 0);
        }

        // If more pending interrupts remain, keep interrupt-window exiting enabled
        if (!PendingIntrIsEmpty(cpuIndex)) {
            return; // don't disable interrupt-window exiting yet
        }
    }

    HvDisableInterruptWindowExiting();
}

/*
 * 处理异常/NMI
 */
static BOOLEAN HvHandleExceptionNmi(_Inout_ PGUEST_CONTEXT GuestContext)
{
    SIZE_T intrInfo, errorCode;
    ULONG vector, type;
    PVCPU_DATA vcpuData;

    InterlockedIncrement64((volatile LONG64*)&g_ExitCountException);

    __vmx_vmread(VM_EXIT_INTERRUPTION_INFO, &intrInfo);

    if (!(intrInfo & (1ULL << 31))) {
        return TRUE;  // 无效，继续
    }

    vector = (ULONG)(intrInfo & 0xFF);
    type = (ULONG)((intrInfo >> 8) & 0x7);

    // P0-2 (2026-05-31): NMI (type=2, vector=2) — 检查 BlockingByNmi 避免 vm-entry fail
    //
    // SDM 约束: NMI window exiting (Primary Proc-Based bit 22) 需要
    // PIN_BASED_VIRTUAL_NMIS (Pin-Based bit 5) 同时启用。Netr pin-based
    // controls 请求 0, 只靠 HvAdjustVmxControls 强制位 — 大多数 CPU 不强制
    // Virtual NMIs, 所以 HvEnableNmiWindowExiting() 会导致 vm-entry fail。
    //
    // 安全策略: 检查 BlockingByNmi, 若 set 则**直接丢弃** NMI (不 inject 也不
    // 排队)。NMI 是 edge-triggered, 丢一个不会死锁 — guest IRET 后 NMI 解除
    // blocking, 下一个 NMI 自然到来。这比 vm-entry fail 导致 12 CPU 全卡死强。
    //
    // 未来改进: 若需要 NMI window, 必须在 HvSetupVmcsControls 里显式请求
    // PIN_BASED_NMI_EXITING | PIN_BASED_VIRTUAL_NMIS, 然后才能安全用 bit 22。
    if (type == 2) {
        SIZE_T intState = 0;
        __vmx_vmread(GUEST_INTERRUPTIBILITY_STATE, &intState);
        if (!(intState & (1ULL << 3))) {
            // BlockingByNmi=0 → 可以安全 inject
            HvInjectInterrupt(2, 2);
        }
        // else: BlockingByNmi=1 → 丢弃 (NMI edge-triggered, 不堆栈)
        return TRUE;
    }

    // P50 (2026-06-22): #BP (vector=3) — 软断点命中 (guest 执行 int3)
    // type=6 = software exception (int3 是 0xCC 单字节,但 VT-x 仍报 type=6 / vector=3
    // 在某些 CPU 上;为稳妥 vector==3 即认 #BP,无论 type)
    if (vector == 3) {
        SIZE_T rip = 0;
        __vmx_vmread(GUEST_RIP, &rip);

        // Resolve the immutable per-vCPU root context before touching the
        // private breakpoint path.  HvVwatch uses guest CR3 and the current
        // KTHREAD token directly; it must not call process/thread-manager
        // helpers from VMX-root.
        vcpuData = HvNestedGetCurrentVcpu();
        if (HvVwatchHandleSwBpException(
                vcpuData,
                GuestContext,
                (UINT64)rip)) {
            return TRUE;
        }

#if 0
        /*
         * Legacy observational SWBP delivery used debugger PID tables and an
         * event-ring spin lock directly from VMX-root.  The private VT SWBP
         * implementation above owns the root-safe path now.  Keep this code
         * for ABI/history reference, but never enter Windows lock/object
         * helpers from the active root dispatcher.
         */
        SIZE_T guestCr3 = 0;
        HANDLE targetPid = NULL;
        __vmx_vmread(GUEST_CR3, &guestCr3);
        HANDLE debuggerPid = HvDbgLookupSwBpOwnerByCr3(
            (UINT64)guestCr3,
            (UINT64)rip,
            &targetPid);
        if (debuggerPid == NULL) {
            // 不是我们的断点 → 重新注入给 guest (让目标进程自己的 SEH / debugger 处理)
            // int3 长度 = 1, error code = 0
            ULONG64 entryInfo = vector | ((ULONG64)type << 8) | (1ULL << 31);
            __vmx_vmwrite(VMCS_CTRL_VMENTRY_INTERRUPTION_INFO, entryInfo);
            __vmx_vmwrite(VMCS_CTRL_VMENTRY_INSTRUCTION_LENGTH, 1);
            return TRUE;
        }

        HV_DEBUG_EVENT evt = { 0 };
        evt.Tid = NULL;
        evt.Pid = targetPid;
        evt.ThreadToken = (PVOID)(ULONG_PTR)__readgsqword(0x188);
        evt.Kind = HV_DBG_EVT_SWBP;
        evt.HitSlot = 0;
        evt.Dr6 = 0;
        {
            SIZE_T rsp = 0, rflags = 0, cr3 = 0;
            __vmx_vmread(GUEST_RSP, &rsp);
            __vmx_vmread(GUEST_RFLAGS, &rflags);
            __vmx_vmread(GUEST_CR3, &cr3);
            evt.Rip = (UINT64)rip;
            evt.Rsp = (UINT64)rsp;
            evt.Rflags = (UINT64)rflags;
            evt.Cr3 = (UINT64)cr3;
        }
        // P113: vmx root mode — 用 NoSignal 版避免 KeSetEvent BSOD.
        // 同时移除 HvDbgEvtPost (它内部 spinlock 在 root mode IRQL 行为不可信).
        HvDbgEnqueueEventNoSignal(debuggerPid, &evt);

        // Legacy registrations are observational only.  Keep delivery on the
        // Windows debug-port path; swallowing #BP here spun the target in
        // VMX-root and previously required unsafe PID/TID manager calls.
        {
            ULONG64 legacyEntryInfo =
                vector | ((ULONG64)type << 8) | (1ULL << 31);
            __vmx_vmwrite(
                VMCS_CTRL_VMENTRY_INTERRUPTION_INFO,
                legacyEntryInfo);
            __vmx_vmwrite(VMCS_CTRL_VMENTRY_INSTRUCTION_LENGTH, 1);
        }
#endif

        /* Not a private VT breakpoint: preserve normal guest/debugger #BP. */
        {
            ULONG64 entryInfo =
                vector | ((ULONG64)type << 8) | (1ULL << 31);
            __vmx_vmwrite(VMCS_CTRL_VMENTRY_INTERRUPTION_INFO, entryInfo);
            __vmx_vmwrite(VMCS_CTRL_VMENTRY_INSTRUCTION_LENGTH, 1);
        }
        return TRUE;

    }

    // P118+: replay a vector-1 debug exception once. The qualification cause
    // is carried through DR6; the pending-debug VMCS field is not a substitute
    // for DR6 and must not be combined with this explicit injection.
    if (type == 3 && vector == 1) {
        SIZE_T qual = 0;
        __vmx_vmread(VM_EXIT_QUALIFICATION, &qual);

        // An explicit VM-entry #DB is replayed once with its architectural
        // cause in DR6. GUEST_PENDING_DEBUG_EXCEPTIONS is not a DR6 transport;
        // combining it with this injection describes a second debug event.
        const ULONG64 causeMask = 0xFULL | (1ULL << 13) | (1ULL << 14);
        const ULONG64 cause = (ULONG64)qual & causeMask;
        if (cause != 0) {
            ULONG64 dr6 = HvDbgReadRealDr(6);
            HvDbgWriteRealDr(6, (dr6 & ~causeMask) | cause);
        }

        // 注入 #DB: vector=1, type=3 (hw exception), valid=1
        ULONG64 entryInfo = 1ULL | (3ULL << 8) | (1ULL << 31);
        __vmx_vmwrite(VMCS_CTRL_VMENTRY_INTERRUPTION_INFO, entryInfo);
        return TRUE;
    }

    // 硬件异常 (type=3)
    if (type == 3) {
        // 检查是否需要错误码
        if (intrInfo & (1ULL << 11)) {
            __vmx_vmread(VM_EXIT_INTERRUPTION_ERROR_CODE, &errorCode);
            __vmx_vmwrite(VMCS_CTRL_VMENTRY_EXCEPTION_ERROR_CODE, errorCode);
        }

        // 重新注入
        ULONG64 entryInfo = vector | ((ULONG64)type << 8) | (1ULL << 31);
        if (intrInfo & (1ULL << 11)) {
            entryInfo |= (1ULL << 11);  // 错误码有效
        }
        __vmx_vmwrite(VMCS_CTRL_VMENTRY_INTERRUPTION_INFO, entryInfo);
        return TRUE;
    }

    return TRUE;
}

/*
 * 处理 EPT 违规
 */
static BOOLEAN HvHandleEptViolation(PGUEST_CONTEXT GuestContext)
{
    SIZE_T gpa, qualification;
    PVCPU_DATA vcpuData;
    BOOLEAN injectToL1 = FALSE;

    InterlockedIncrement64((volatile LONG64*)&g_ExitCountEptViolation);

    __vmx_vmread(VMCS_GUEST_PHYSICAL_ADDRESS, &gpa);
    __vmx_vmread(VM_EXIT_QUALIFICATION, &qualification);

    // 获取当前 VCPU
    vcpuData = HvNestedGetCurrentVcpu();

    // 如果启用了嵌套虚拟化且在 L2 中
    if (g_EnableNestedVirtualization && vcpuData && vcpuData->IsInL2) {
        // 使用嵌套 EPT 处理
        if (NestedEptHandleViolation(vcpuData, (ULONG64)gpa, (ULONG64)qualification, &injectToL1)) {
            if (injectToL1) {
                // 需要将 EPT Violation 注入到 L1
                HvNestedVmExitFromL2ToL1(vcpuData, EXIT_REASON_EPT_VIOLATION, qualification);
            }
            return TRUE;
        }
        // 嵌套 EPT 没有处理，继续由 L0 处理（可能是 L0 的 Hook）
    }

    // 尝试用 EPT Hook 处理
    if (EptHookHandleViolation(
            vcpuData, (ULONG64)gpa, (ULONG64)qualification)) {
        return TRUE;
    }

    // P125 (2026-06-25): PEB 字段级 spoof — 在 EptPebSpoof 上 PEB 页 R=0,
    // target 自己读 PEB 触发 violation → 装补丁页 (3 字段被 0) + R=1 + MTF.
    if (HvPebCloakHandleEptViolation(
            vcpuData,
            (ULONG64)gpa,
            (ULONG64)qualification,
            GuestContext)) {
        return TRUE;
    }

    // P128 (2026-06-25): 虚拟硬件断点 (EPT-based HWBP, 替代 DR 透传).
    // CE 下硬断 → driver 在 EptPebSpoof 上把 watch 页改 R=0/W=0/X=0
    //          → target 访问触发 violation → 注 #DB 给 guest + MTF 单步恢复
    // 反作弊查 DR 永远 0 (driver 从不写 DR).
    if (HvVwatchHandleEptViolation(
            vcpuData,
            (ULONG64)gpa,
            (ULONG64)qualification,
            GuestContext)) {
        return TRUE;
    }

    // Item 2: xHCI USBSTS/IMAN read trap — 必须在 fallback grant-RWX 之前,
    // 否则 fallback 会把 R 位修回去,trap 失效。
    if (HvXhciEptTrapHandleViolation((ULONG64)gpa, (ULONG64)qualification, GuestContext)) {
        return TRUE;
    }
    
    // 如果在 L2 中且 L0 Hook 没有处理，注入到 L1
    if (g_EnableNestedVirtualization && vcpuData && vcpuData->IsInL2) {
        HvNestedVmExitFromL2ToL1(vcpuData, EXIT_REASON_EPT_VIOLATION, qualification);
        return TRUE;
    }

    // 未处理的违规:**真正的兜底必须修复 EPT entry 权限**,只 INVEPT 是
    // 死循环 —— TLB 清掉后 guest 重试,硬件再次 walk EPT 仍命中限制位,
    // 立刻再触发 EPT violation,我们再 INVEPT,如此往复,5 秒内 0x1DB IPI
    // 看门狗触发(2026-05-21 第四轮 BSOD 真元凶,之前误诊为 VtRoot)。
    //
    // 安全路径(root 模式合规):
    //   1. 直接遍历 vcpu->EptTables->Pd[pdpt][pd] (这是我们自己 NonPaged
    //      contiguous 分配的内存,VA 永远有效,无需 Mm* 查询)
    //   2. PDE.LargePage=1 → 直接给 PDE 赋 R=W=X=1
    //   3. PDE.LargePage=0 (已被 EPT Hook 分裂) → 用 PDE.PageFrameNumber
    //      在 EptTables->SplitPt[]/SplitPtPhysical[] 里 PFN 匹配找到 PT VA,
    //      给 PT[ptIdx] 赋 R=W=X=1 (SplitPtPhysical 在 split 时同步记录,
    //      无需 root 模式 MmGetPhysicalAddress)
    //   4. AsmInveptAllContexts() 纯汇编,无锁无分配,root 安全
    //
    // 已知代价:这会盲授 RWX 给未被 EptHook 识别的违规页,可能掩盖真正的
    // EPT 配置错误(如 #6 隐患)。但启动期 hook 安装窗口的竞态必须这样兜底,
    // 否则瞬间 0x1DB。后续若要更严格,可以加重复 GPA 计数器,>N 次再注 #GP。
    {
        static volatile LONG64 unhandledEptViolationCount = 0;
        InterlockedIncrement64(&unhandledEptViolationCount);

        // 死循环切断:同 CPU 连续 N 次同 GPA 走 fallback → 注 #UD 让 guest 自处理。
        // 若是用户态触发,目标进程崩;若是内核,蓝屏有 dump。无论哪种,系统恢复
        // 响应,不再纯卡死。
        {
            ULONG cpuIdx = vcpuData ? vcpuData->ProcessorNumber : HV_MAX_TRACKED_CPUS;
            if (cpuIdx < HV_MAX_TRACKED_CPUS) {
                ULONG64 gpaPage = ((ULONG64)gpa) >> 12;
                if (g_EptRepeatGuard[cpuIdx].LastGpaPage == gpaPage) {
                    if (InterlockedIncrement(&g_EptRepeatGuard[cpuIdx].Count) >= EPT_REPEAT_GUARD_THRESHOLD) {
                        HvInjectInterrupt(6, 3);  // #UD
                        g_EptRepeatGuard[cpuIdx].LastGpaPage = 0;
                        g_EptRepeatGuard[cpuIdx].Count = 0;
                        return TRUE;
                    }
                } else {
                    g_EptRepeatGuard[cpuIdx].LastGpaPage = gpaPage;
                    g_EptRepeatGuard[cpuIdx].Count = 1;
                }
            }
        }

        if (vcpuData && vcpuData->EptTables) {
            ULONG64 gpaVal = (ULONG64)gpa;
            ULONG64 pml4Idx = (gpaVal >> 39) & 0x1FF;
            ULONG64 pdptIdx = (gpaVal >> 30) & 0x1FF;
            ULONG64 pdIdx   = (gpaVal >> 21) & 0x1FF;
            ULONG64 ptIdx   = (gpaVal >> 12) & 0x1FF;

            // 我们只 identity-map PML4[0] (低 512GB) 用 Pd[][]。
            // PML4[1..3] 走 ExtraPdpt,不在 Pd[][] 范围,这里不处理。
            if (pml4Idx == 0 && pdptIdx < 512 && pdIdx < 512) {
                PEPT_PDE pde = &vcpuData->EptTables->Pd[pdptIdx][pdIdx];

                if (pde->Value & (1ULL << 7)) {
                    // 2MB Large Page:直接在 PDE 上加权限
                    pde->Read = 1;
                    pde->Write = 1;
                    pde->Execute = 1;
                } else {
                    // 已分裂:用 PageFrameNumber 在 SplitPt[] 找对应 PT
                    // P1-3 (HyperDbg 范式):每核独立 PT,直接查当前 vcpu 自己
                    // 的 SplitPt 即可,不再退化到 CPU 0(那是旧共享 PT 时代的
                    // workaround,per-CPU 后每个 EptTables 都有自己的 SplitPt)
                    ULONG64 ptPfn = pde->PageFrameNumber;
                    PEPT_TABLES lookupTables = vcpuData->EptTables;
                    PEPT_PTE pt = HvEptFindSplitPt(lookupTables, ptPfn);
                    if (pt) {
                        pt[ptIdx].Read = 1;
                        pt[ptIdx].Write = 1;
                        pt[ptIdx].Execute = 1;
                    } else {
                        // 找不到 PT —— 把 PDE 还原成 large page R=W=X=1
                        // (会破坏当前 hook,但能解死循环)
                        pde->Value = 0;
                        pde->Read = 1;
                        pde->Write = 1;
                        pde->Execute = 1;
                        pde->Value |= (1ULL << 7);  // LargePage
                        pde->Value |= ((ULONG64)HvEptGetMemoryType(
                            gpaVal & ~0x1FFFFFULL, 0x200000) << 3);
                        pde->PageFrameNumber = (gpaVal >> 21) << 9;  // 2MB-aligned
                    }
                }
            }
        }

        AsmInveptAllContexts();
    }

    return TRUE;
}

/*
 * 处理 Triple Fault
 */
static BOOLEAN HvHandleTripleFault(VOID)
{
    // 注意：VMX root 模式下不要调用 DbgPrint
    // Triple Fault 是致命错误，无法恢复
    return FALSE;  // 终止
}

/*
 * 处理 XSETBV
 */
static VOID HvHandleXsetbv(PGUEST_CONTEXT ctx)
{
    ULONG32 xcr = (ULONG32)ctx->Rcx;
    ULONG64 value = ((ULONG64)(ULONG32)ctx->Rdx << 32) | (ULONG32)ctx->Rax;
    
    __try {
        _xsetbv(xcr, value);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // 忽略失败
    }
    
    HvAdvanceGuestRip();
}

/*
 * 处理 RDTSC - 带时间补偿
 * 
 * 虚拟化检测常用方法：
 * 1. 执行 RDTSC
 * 2. 执行某个会触发 VM Exit 的指令（如 CPUID）
 * 3. 再执行 RDTSC
 * 4. 比较时间差，如果过大说明存在 Hypervisor
 * 
 * 解决方案：减去累积的 VM Exit 开销
 */
static VOID HvHandleRdtsc(PGUEST_CONTEXT ctx)
{
    UINT64 tsc = __rdtsc();
    PVCPU_DATA vcpuData = HvNestedGetCurrentVcpu();
    if (vcpuData) {
        tsc = (UINT64)((INT64)tsc + vcpuData->TscOffsetCompensation);
    }
    ctx->Rax = (UINT32)tsc;
    ctx->Rdx = (UINT32)(tsc >> 32);
    HvAdvanceGuestRip();
}

/*
 * 处理 RDTSCP (Exit reason 51) - 带时间补偿
 */
static VOID HvHandleRdtscp(PGUEST_CONTEXT ctx)
{
    ULONG32 aux;
    UINT64 tsc = __rdtscp(&aux);
    PVCPU_DATA vcpuData = HvNestedGetCurrentVcpu();
    if (vcpuData) {
        tsc = (UINT64)((INT64)tsc + vcpuData->TscOffsetCompensation);
    }
    ctx->Rax = (UINT32)tsc;
    ctx->Rdx = (UINT32)(tsc >> 32);
    ctx->Rcx = aux;
    HvAdvanceGuestRip();
}

/*
 * 处理 HLT
 */
static VOID HvHandleHlt(VOID)
{
    HvAdvanceGuestRip();
    // 可以选择：暂停 CPU 或继续
}

/*
 * 处理 INVD
 */
static VOID HvHandleInvd(VOID)
{
    __wbinvd();
    HvAdvanceGuestRip();
}

// ==================== 主分发函数 ====================

/*
 * VM Exit 主分发函数
 * 
 * 由汇编 AsmVmExitHandler 调用
 * 
 * 参数：GuestContext - 指向栈上保存的 Guest 寄存器
 * 返回：TRUE = VMRESUME 继续，FALSE = 终止虚拟化
 */
BOOLEAN HvVmExitDispatch(PGUEST_CONTEXT GuestContext)
{
    SIZE_T exitReason;
    SIZE_T qualification;
    BOOLEAN shouldContinue = TRUE;
    PVCPU_DATA vcpuData;

    // P3-6: 标记 C 端 vmexit dispatcher 入口
    //   flag=20 → AsmVmExitHandler 入口 (汇编)
    //   flag=30 → C 端 HvVmExitDispatch 入口 (host CR3 切换成功 + asm pop XMM 完成)
    // 如果 vmexit 发生但 flag 停在 20 → asm 内崩 (HOST_CR3 错可能性)
    // 如果 flag 停在 30 → C 函数内部某条 indirect call/access 崩
    g_AsmDebugFlag = 30;

    // 获取当前 VCPU
    vcpuData = HvNestedGetCurrentVcpu();
    if (!vcpuData) {
        return FALSE;
    }

    // 标记 VMX root 模式；CPU identity 来自 HOST_FS_BASE。
    EptSetVmxRootMode(vcpuData, TRUE);

    // Phase I: HWBP-only 路径 (常态累积撤回 2026-06-03)
    if (vcpuData && g_GlobalHwbpRefCount > 0) {
        vcpuData->LastVmExitHostTsc = __rdtsc();
    }

    // 检查并刷新 EPT TLB（如果其他 CPU 修改了 EPT）
    // 这确保当前 CPU 看到最新的 EPT 映射
    EptCheckAndInvalidateTlb(vcpuData);
    
    // 读取退出原因和 qualification
    __vmx_vmread(VM_EXIT_REASON, &exitReason);
    __vmx_vmread(VM_EXIT_QUALIFICATION, &qualification);
    exitReason &= 0xFFFF;
    g_LastExitReason = exitReason;

    // 被动嗅探当前 GUEST_CR3 (KVAS 系统上 VMENTRY 时已切到 user CR3)。
    // disabled 时 inline 直接 return,无开销。
    //
    // **关键**: 同时读 GUEST_RIP 传给 record, 让 ring 只接收 user-mode RIP
    // 时的 CR3 —— KVAS 启用时, kernel-mode VMEXIT 的 GUEST_CR3 是 shadow,
    // 对 user GVA walk 必败。
    if (HvCr3SnoopIsEnabled()) {
        SIZE_T snoopCr3 = 0, snoopRip = 0;
        __vmx_vmread(GUEST_CR3, &snoopCr3);
        __vmx_vmread(GUEST_RIP, &snoopRip);
        HvCr3SnoopRecord((UINT64)snoopCr3, (UINT64)snoopRip);

        // P125 (2026-06-25): PEB cloak classify — target CR3 命中切 EptPebSpoof,
        // 其他 CR3 用主 EPT. 空载(无注册 target)时近乎零开销 (一次 BOOLEAN check).
        //
        // KVAS 修复同旧 cloak: kernel-mode RIP 时 GUEST_CR3 是 shadow CR3, 不可信,
        // 传 0 让 classifier fallback 到 LastCallerClass.
        if (vcpuData) {
            UINT64 classifierCr3 = ((UINT64)snoopRip < 0x800000000000ULL)
                                   ? (UINT64)snoopCr3
                                   : 0;
            if (classifierCr3) {
                (void)HvVwatchTryAdoptScopedOverlayCr3ByMappingRoot(
                    vcpuData,
                    classifierCr3);
            }
            HvPebCloakClassifyAndSwitchEptp(vcpuData, classifierCr3);
        }
    }
    
    // ==================== L2 VM Exit 分发 ====================
    // 如果当前在 L2 中运行，需要判断是由 L0 处理还是注入给 L1
    if (vcpuData && HvNestedIsInL2(vcpuData)) {
        if (HvNestedIsQuiescing()) {
            shouldContinue = HvNestedInjectVmExitToL1(
                vcpuData, exitReason, GuestContext);
            EptSetVmxRootMode(vcpuData, FALSE);
            return shouldContinue;
        }
        if (exitReason == EXIT_REASON_EPT_VIOLATION &&
            vcpuData->NestedVmx.L1EptEnabled &&
            vcpuData->NestedVmx.L1Eptp != 0) {
            SIZE_T l2Gpa = 0;
            BOOLEAN injectToL1 = FALSE;

            __vmx_vmread(VMCS_GUEST_PHYSICAL_ADDRESS, &l2Gpa);
            if (NestedEptHandleViolation(
                    vcpuData, (UINT64)l2Gpa, (UINT64)qualification,
                    &injectToL1)) {
                if (injectToL1) {
                    shouldContinue = HvNestedInjectVmExitToL1(
                        vcpuData, exitReason, GuestContext);
                    EptSetVmxRootMode(vcpuData, FALSE);
                    return shouldContinue;
                }
                goto vmexit_finalize;
            }
        }

        if (HvNestedShouldL0HandleExit(vcpuData, exitReason, qualification)) {
            // L0 处理这个 VM Exit（如我们自己的 EPT Hook）
            shouldContinue = HvNestedHandleL2Exit(vcpuData, exitReason, GuestContext);
            // 根据 exitReason 执行相应的处理
            // 继续到下面的 switch 语句处理
        } else {
            // 将 VM Exit 注入到 L1 Hypervisor
            shouldContinue = HvNestedInjectVmExitToL1(vcpuData, exitReason, GuestContext);
#if !HV_DISABLE_TSC_COMPENSATION
            if (vcpuData && g_GlobalHwbpRefCount > 0) {
                UINT64 endTsc = __rdtsc();
                UINT64 delta = endTsc - vcpuData->LastVmExitHostTsc;
                vcpuData->TscOffsetCompensation -= (INT64)delta;
                __vmx_vmwrite(VMCS_CTRL_TSC_OFFSET, (SIZE_T)vcpuData->TscOffsetCompensation);
            }
#endif
            EptSetVmxRootMode(vcpuData, FALSE);
            return shouldContinue;
        }
    }

    // ==================== 主分发逻辑 ====================
    // 分发到具体 Handler
    switch (exitReason) {
    
    case EXIT_REASON_CPUID:  // 10
        HvHandleCpuid(GuestContext);
        break;
        
    case EXIT_REASON_VMCALL:  // 18
        shouldContinue = HvHandleVmcall(GuestContext);
        break;
        
    // ==================== VMX 指令处理（嵌套虚拟化） ====================
    case EXIT_REASON_VMXON:  // 27
        if (vcpuData && g_EnableNestedVirtualization) {
            HvNestedHandleVmxon(vcpuData, GuestContext);
            HvAdvanceGuestRip();
        } else {
            // 嵌套虚拟化未启用，注入 #UD
            HvInjectInterrupt(6, 3);  // #UD = vector 6, type 3 = hardware exception
        }
        break;

    case EXIT_REASON_VMXOFF:  // 26
        if (vcpuData && g_EnableNestedVirtualization) {
            HvNestedHandleVmxoff(vcpuData, GuestContext);
            HvAdvanceGuestRip();
        } else {
            HvInjectInterrupt(6, 3);
        }
        break;

    case EXIT_REASON_VMCLEAR:  // 19
        if (vcpuData && g_EnableNestedVirtualization) {
            HvNestedHandleVmclear(vcpuData, GuestContext);
            HvAdvanceGuestRip();
        } else {
            HvInjectInterrupt(6, 3);
        }
        break;

    case EXIT_REASON_VMPTRLD:  // 21
        if (vcpuData && g_EnableNestedVirtualization) {
            HvNestedHandleVmptrld(vcpuData, GuestContext);
            HvAdvanceGuestRip();
        } else {
            HvInjectInterrupt(6, 3);
        }
        break;

    case EXIT_REASON_VMPTRST:  // 22
        if (vcpuData && g_EnableNestedVirtualization) {
            HvNestedHandleVmptrst(vcpuData, GuestContext);
            HvAdvanceGuestRip();
        } else {
            HvInjectInterrupt(6, 3);
        }
        break;

    case EXIT_REASON_VMREAD:  // 23
        if (vcpuData && g_EnableNestedVirtualization) {
            HvNestedHandleVmread(vcpuData, GuestContext);
            HvAdvanceGuestRip();
        } else {
            HvInjectInterrupt(6, 3);
        }
        break;

    case EXIT_REASON_VMWRITE:  // 25
        if (vcpuData && g_EnableNestedVirtualization) {
            HvNestedHandleVmwrite(vcpuData, GuestContext);
            HvAdvanceGuestRip();
        } else {
            HvInjectInterrupt(6, 3);
        }
        break;

    case EXIT_REASON_VMLAUNCH:  // 20
        if (vcpuData && HvNestedCanEnterL2()) {
            if (HvNestedHandleVmlaunch(vcpuData, GuestContext)) {
                // VMLAUNCH 成功，不推进 RIP，直接进入 L2
            } else {
                HvAdvanceGuestRip();  // 失败时推进
            }
        } else {
            HvInjectInterrupt(6, 3);
        }
        break;

    case EXIT_REASON_VMRESUME:  // 24
        if (vcpuData && HvNestedCanEnterL2()) {
            if (HvNestedHandleVmresume(vcpuData, GuestContext)) {
                // VMRESUME 成功，不推进 RIP
            } else {
                HvAdvanceGuestRip();
            }
        } else {
            HvInjectInterrupt(6, 3);
        }
        break;

    case EXIT_REASON_INVEPT:  // 50
        if (vcpuData && g_EnableNestedVirtualization) {
            HvNestedHandleInvept(vcpuData, GuestContext);
            HvAdvanceGuestRip();
        } else {
            HvInjectInterrupt(6, 3);
        }
        break;

    case EXIT_REASON_INVVPID:  // 53
        if (vcpuData && g_EnableNestedVirtualization) {
            HvNestedHandleInvvpid(vcpuData, GuestContext);
            HvAdvanceGuestRip();
        } else {
            HvInjectInterrupt(6, 3);
        }
        break;
    // ==================== VMX 指令处理结束 ====================

    case EXIT_REASON_MSR_READ:  // 31
        HvHandleMsrRead(GuestContext);
        break;
        
    case EXIT_REASON_MSR_WRITE:  // 32
        HvHandleMsrWrite(GuestContext);
        break;
        
    case EXIT_REASON_CR_ACCESS:  // 28
        HvHandleCrAccess(GuestContext);
        break;

    case EXIT_REASON_MOV_DR:  // 29 - 阶段 7 HWBP
        HvHandleMovDr(GuestContext);
        break;

    case EXIT_REASON_IO_INSTRUCTION:  // 30 - 阶段 7.10 VT 透明键鼠注入
        (VOID)HvInputHandleIoExit(qualification, GuestContext);
        HvAdvanceGuestRip();
        break;

    case EXIT_REASON_EXTERNAL_INTERRUPT:  // 1
        HvHandleExternalInterrupt(vcpuData);
        break;

    case EXIT_REASON_EXCEPTION_NMI:  // 0
        shouldContinue = HvHandleExceptionNmi(GuestContext);
        break;

    case 7:  // INTERRUPT_WINDOW
        HvHandleInterruptWindow(vcpuData);
        break;

    case 8:  // NMI_WINDOW — P0-2: 当前不启用 NMI window exiting (需要 Virtual NMIs),
             // 此 case 理论上不会触发。保留作为防御性处理。
        {
            // 如果意外到达, 关掉 NMI window bit 防止 vm-entry fail 循环
            HvDisableNmiWindowExiting();
        }
        break;

    case EXIT_REASON_TRIPLE_FAULT:  // 2
        shouldContinue = HvHandleTripleFault();
        break;

    case EXIT_REASON_EPT_VIOLATION:  // 48
        shouldContinue = HvHandleEptViolation(GuestContext);
        break;
        
    case EXIT_REASON_EPT_MISCONFIG:  // 49
        {
            // EPT Misconfiguration: reserved bits set incorrectly in EPT PTE.
            //
            // 安全化 (2026-05-21 第四轮):同 EPT_VIOLATION 同款修复 ——
            //   仅 INVEPT 不修 entry 会死循环触发 0x1DB IPI 看门狗。
            //   直接遍历 vcpu->EptTables 把 PDE/PTE 修成 R=W=X=1,
            //   MemoryType=WB 修正配置错误。
            //
            // 真正的 EPT misconfig 在生产路径几乎不该发生 —— 它通常意味着
            // EptHook 安装时把 MemoryType 设错了(EPT 要求 MemoryType=WB(6))。
            // 我们这里强制修正 MemoryType=6 + R=W=X=1。

            SIZE_T misconfigGpa = 0;
            __vmx_vmread(VMCS_GUEST_PHYSICAL_ADDRESS, &misconfigGpa);

            static volatile LONG64 unhandledEptMisconfigCount = 0;
            InterlockedIncrement64(&unhandledEptMisconfigCount);

            // 死循环切断:同 EPT_VIOLATION 同款 — 同 CPU 连续 N 次同 GPA → 注 #UD
            {
                ULONG cpuIdx = vcpuData
                    ? vcpuData->ProcessorNumber
                    : HV_MAX_TRACKED_CPUS;
                if (cpuIdx < HV_MAX_TRACKED_CPUS) {
                    ULONG64 gpaPage = ((ULONG64)misconfigGpa) >> 12;
                    if (g_EptRepeatGuard[cpuIdx].LastGpaPage == gpaPage) {
                        if (InterlockedIncrement(&g_EptRepeatGuard[cpuIdx].Count) >= EPT_REPEAT_GUARD_THRESHOLD) {
                            HvInjectInterrupt(6, 3);  // #UD
                            g_EptRepeatGuard[cpuIdx].LastGpaPage = 0;
                            g_EptRepeatGuard[cpuIdx].Count = 0;
                            break;  // 跳出 EPT_MISCONFIG case
                        }
                    } else {
                        g_EptRepeatGuard[cpuIdx].LastGpaPage = gpaPage;
                        g_EptRepeatGuard[cpuIdx].Count = 1;
                    }
                }
            }

            PVCPU_DATA mcVcpu = HvNestedGetCurrentVcpu();
            if (mcVcpu && mcVcpu->EptTables) {
                ULONG64 gpaVal = (ULONG64)misconfigGpa;
                ULONG64 pml4Idx = (gpaVal >> 39) & 0x1FF;
                ULONG64 pdptIdx = (gpaVal >> 30) & 0x1FF;
                ULONG64 pdIdx   = (gpaVal >> 21) & 0x1FF;
                ULONG64 ptIdx   = (gpaVal >> 12) & 0x1FF;

                if (pml4Idx == 0 && pdptIdx < 512 && pdIdx < 512) {
                    PEPT_PDE pde = &mcVcpu->EptTables->Pd[pdptIdx][pdIdx];

                    if (pde->Value & (1ULL << 7)) {
                        // PDE 是 large page —— 修 R/W/X
                        pde->Read = 1;
                        pde->Write = 1;
                        pde->Execute = 1;
                        pde->Value = (pde->Value & ~(7ULL << 3)) |
                                     ((ULONG64)HvEptGetMemoryType(
                                         gpaVal & ~0x1FFFFFULL, 0x200000) << 3);
                    } else {
                        // 已分裂 — P1-3:每核 SplitPt 各自独立,直接查当前 vcpu
                        // (旧"退化到 CPU 0 SplitPt"workaround 已废弃)
                        ULONG64 ptPfn = pde->PageFrameNumber;
                        PEPT_TABLES lookupTables = mcVcpu->EptTables;
                        PEPT_PTE pt = HvEptFindSplitPt(lookupTables, ptPfn);
                        if (pt) {
                            pt[ptIdx].Read = 1;
                            pt[ptIdx].Write = 1;
                            pt[ptIdx].Execute = 1;
                            pt[ptIdx].MemoryType = HvEptGetMemoryType(
                                gpaVal & ~((ULONG64)PAGE_SIZE - 1ULL), PAGE_SIZE);
                        } else {
                            // 找不到 —— 还原大页 RWX
                            pde->Value = 0;
                            pde->Read = 1;
                            pde->Write = 1;
                            pde->Execute = 1;
                            pde->Value |= (1ULL << 7);
                            pde->Value |= ((ULONG64)HvEptGetMemoryType(
                                gpaVal & ~0x1FFFFFULL, 0x200000) << 3);
                            pde->PageFrameNumber = (gpaVal >> 21) << 9;
                        }
                    }
                }
            }

            AsmInveptAllContexts();
        }
        break;

    case EXIT_REASON_XSETBV:  // 55
        HvHandleXsetbv(GuestContext);
        break;
        
    case EXIT_REASON_RDTSC:  // 16
        HvHandleRdtsc(GuestContext);
        break;

    case EXIT_REASON_RDTSCP:  // 51
        HvHandleRdtscp(GuestContext);
        break;

    case EXIT_REASON_HLT:  // 12
        HvHandleHlt();
        break;
        
    case EXIT_REASON_INVD:  // 13
        HvHandleInvd();
        break;
        
    case EXIT_REASON_MONITOR_TRAP_FLAG:  // 37
        // MTF is shared by xHCI, Vwatch, PEB cloak, and EptHook.  A single
        // guest instruction can arm more than one owner, so every active
        // per-vCPU context must complete before VM entry resumes.
        {
            BOOLEAN handledMtf = FALSE;
            PVCPU_DATA mtfVcpu = HvNestedGetCurrentVcpu();
            if (HvXhciEptTrapHandleMtf(GuestContext)) handledMtf = TRUE;
            if (HvVwatchHandleMtfExit(mtfVcpu, GuestContext)) handledMtf = TRUE;
            if (HvPebCloakHandleMtfExit(mtfVcpu, GuestContext)) handledMtf = TRUE;
            if (EptHookHandleMtfExit(mtfVcpu)) handledMtf = TRUE;
            if (!handledMtf) {
                SIZE_T controls = 0;
                if (__vmx_vmread(
                        VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS,
                        &controls) == 0) {
                    controls &= ~(SIZE_T)CPU_BASED_MONITOR_TRAP_FLAG;
                    (void)__vmx_vmwrite(
                        VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS,
                        controls);
                }
            }
        }
        break;
        
    case EXIT_REASON_INIT:  // 3 - INIT signal
        // INIT 信号通常不应该在 hypervisor 运行时触发
        // 忽略它，让系统继续
        break;
        
    case EXIT_REASON_SIPI:  // 4 - Startup IPI
        // SIPI 用于启动其他 CPU，通常在启动阶段
        // 在 hypervisor 运行后不应该出现
        break;
        
    default:
        // 未知退出原因 — 必须 advance RIP 防止无限 vmexit 循环
        //
        // P0-3 教训 (2026-05-31): 曾删除 advance RIP 想防止 fault-class exit 损坏
        // guest RIP。但 Win11 上有未知 instruction-class exit reason 不在 switch 里,
        // 不 advance → guest 重试同一条指令 → 同一个 vmexit → 无限循环 → 所有 CPU
        // 困 root mode → debugger NMI 进不来 → 整机卡死。
        //
        // 正确策略: advance RIP (instruction-class exit 占绝大多数), 同时记录
        // exit reason 供诊断。若是 fault-class exit (极罕见走到 default), advance
        // 可能跳到指令中段, 但至少不会无限循环卡死整机。
        InterlockedIncrement64((volatile LONG64*)&g_ExitCountOther);
        g_UnknownExitReason = exitReason;
        {
            SIZE_T len = 0;
            __vmx_vmread(VM_EXIT_INSTRUCTION_LEN, &len);
            if (len > 0 && len <= 15) {
                HvAdvanceGuestRip();
            }
        }
        break;
    }

    // P1-8 (2026-05-31): IDT_VECTORING_INFO reinject
    //
    // 当 vmexit 发生在 guest 正在分派 IDT 事件 (异常/中断/NMI) 的瞬间时, 硬件
    // 把被打断的事件信息记录到 VMCS IDT_VECTORING_INFO (0x4408)。如果我们不
    // 把它写回 VMENTRY_INTR_INFO, 该事件在 vm-entry 后就**永远丢失** — Win11
    // EPT hook 风暴 + 高频中断 + 异常派发并行时, 经常丢 timer tick / IPI → HPET
    // 死锁。
    //
    // 策略: 若 IDT_VECTORING 标 valid, 且 dispatcher 没主动写 VMENTRY_INTR_INFO,
    // 把 IDT_VECTORING 透传过去 (含 error code)。
    //
    // 安全约束:
    //   - 若 IDT_VECTORING 是 NMI (type=2, vector=2) 且 BlockingByNmi=1,
    //     不能 reinject (否则 vm-entry fail)。丢弃。
    //   - 若 IDT_VECTORING 是外部中断 (type=0) 且 guest IF=0 / STI blocking,
    //     不能 reinject (否则 vm-entry fail)。走 pending queue。
vmexit_finalize:
    {
        SIZE_T idtVecInfo = 0, entryInfo = 0;
        __vmx_vmread(IDT_VECTORING_INFO, &idtVecInfo);
        if (idtVecInfo & (1ULL << 31)) {
            __vmx_vmread(VMCS_CTRL_VMENTRY_INTERRUPTION_INFO, &entryInfo);
            if (!(entryInfo & (1ULL << 31))) {
                ULONG vecType = (ULONG)((idtVecInfo >> 8) & 0x7);
                ULONG vecNum  = (ULONG)(idtVecInfo & 0xFF);
                BOOLEAN canReinject = TRUE;

                // NMI reinject 安全检查
                if (vecType == 2 || (vecType == 0 && vecNum == 2)) {
                    SIZE_T intState2 = 0;
                    __vmx_vmread(GUEST_INTERRUPTIBILITY_STATE, &intState2);
                    if (intState2 & (1ULL << 3)) {
                        canReinject = FALSE;  // BlockingByNmi → 丢弃
                    }
                }

                // 2026-06-16: 0x1AA 兜底 — 不 reinject 用 IST 的 vector。
                // #DF (8) / #MC (18) 在 guest Windows IDT 通常配 IST 索引;
                // 我们 reinject 后 guest 切到 Windows IST 栈,但 host 处理过程中
                // 可能动过 KPRCB / KTHREAD 字段导致 RtlpGetStackLimits 校验失败 →
                // 0x1AA。这两个 vector 在 hardware-exception 上下文几乎不该被
                // reinject (CPU 直接派发, 我们截到 IDT_VECTORING_INFO 几乎是误判),
                // 丢弃比错误注入安全。
                if (vecType == 3 && (vecNum == 8 || vecNum == 18)) {
                    canReinject = FALSE;
                }

                // 外部中断 reinject 安全检查
                if (vecType == 0 && vecNum != 2) {
                    if (!HvCanInjectInterrupt()) {
                        // IF=0 或 STI/MOV-SS blocking → 走 pending queue
                        ULONG cpuIdx2 = vcpuData
                            ? vcpuData->ProcessorNumber
                            : MAX_CPU_COUNT;
                        if (cpuIdx2 < MAX_CPU_COUNT) {
                            PendingIntrEnqueue(cpuIdx2, idtVecInfo);
                        }
                        HvEnableInterruptWindowExiting();
                        canReinject = FALSE;
                    }
                }

                if (canReinject) {
                    __vmx_vmwrite(VMCS_CTRL_VMENTRY_INTERRUPTION_INFO, idtVecInfo);
                    if (idtVecInfo & (1ULL << 11)) {
                        SIZE_T idtVecErr = 0;
                        __vmx_vmread(IDT_VECTORING_ERROR_CODE, &idtVecErr);
                        __vmx_vmwrite(VMCS_CTRL_VMENTRY_EXCEPTION_ERROR_CODE, idtVecErr);
                    }
                    ULONG itype = (ULONG)((idtVecInfo >> 8) & 0x7);
                    if (itype == 4 || itype == 6) {
                        SIZE_T ilen = 0;
                        __vmx_vmread(VM_EXIT_INSTRUCTION_LEN, &ilen);
                        __vmx_vmwrite(VMCS_CTRL_VMENTRY_INSTRUCTION_LENGTH, ilen);
                    }
                }
            }
        }
    }

    // Phase I: HWBP-only TSC 补偿路径
#if !HV_DISABLE_TSC_COMPENSATION
    if (vcpuData && g_GlobalHwbpRefCount > 0) {
        UINT64 endTsc = __rdtsc();
        UINT64 delta = endTsc - vcpuData->LastVmExitHostTsc;
        vcpuData->TscOffsetCompensation -= (INT64)delta;
        __vmx_vmwrite(VMCS_CTRL_TSC_OFFSET, (SIZE_T)vcpuData->TscOffsetCompensation);
    }
#endif

#if !HV_MINIMAL_MODE
    // 阶段 7.10: 任何 VMEXIT 末尾尝试投递 pending 合成键鼠中断 — TryDeliver
    // 内部用 InterlockedCompareExchange 单 CPU 抢锁,无 pending 时基本零开销。
    HvInputTryDeliver();

    // 阶段 7.10 Layer 4: xHCI MSI 注入 (USB HID Boot)
    // HvXhciInjectHid 在 PASSIVE_LEVEL 写完 Transfer/Event Ring 后,通过 IPI
    // 让我们在 root 模式抓到这一刻 — 这里检 PendingMsi 并 inject。
    HvUsbXhciTryDeliverMsi();
#endif

    EptSetVmxRootMode(vcpuData, FALSE);
    return shouldContinue;
}

/*
 * 兼容旧接口
 */
BOOLEAN HvVmExitHandlerC(PGUEST_CONTEXT GuestContext)
{
    return HvVmExitDispatch(GuestContext);
}

/*
 * VMX 终止回调
 */
VOID HvVmxTerminatedCallback(VOID)
{
    g_VmxTerminated = TRUE;
}

// ==================== AMD SVM #VMEXIT 处理 ====================

// SVM 退出计数
ULONG64 volatile g_SvmExitCountCpuid = 0;
ULONG64 volatile g_SvmExitCountVmmcall = 0;
ULONG64 volatile g_SvmExitCountMsr = 0;
ULONG64 volatile g_SvmExitCountNpf = 0;
ULONG64 volatile g_SvmExitCountOther = 0;

// SVM 终止标志
volatile BOOLEAN g_SvmTerminated = FALSE;

// VMMCALL 命令定义（与 VMX 保持一致）
#define SVM_VMMCALL_TEST            1
#define SVM_VMMCALL_GET_VERSION     2
#define SVM_VMMCALL_TERMINATE       0x1337DEAD

/*
 * SVM 前进 Guest RIP
 *
 * AMD SVM 在 VMCB 控制区提供 NRip 字段（下一条指令地址）
 * 如果处理器支持 NRIP Save，可以直接使用
 */
static VOID SvmAdvanceGuestRip(PVMCB Vmcb)
{
    if (Vmcb->ControlArea.NRip != 0) {
        Vmcb->StateSaveArea.Rip = Vmcb->ControlArea.NRip;
    } else {
        // NRip 不可用，根据退出码使用已知指令长度
        // NumOfBytesFetched 是缓存的字节数，不是指令长度
        ULONG64 exitCode = Vmcb->ControlArea.ExitCode;
        ULONG instrLen = 0;

        switch (exitCode) {
        case SVM_EXIT_CPUID:    instrLen = 2; break;  // 0F A2
        case SVM_EXIT_VMMCALL:  instrLen = 3; break;  // 0F 01 D9
        case SVM_EXIT_HLT:      instrLen = 1; break;  // F4
        case SVM_EXIT_INVD:     instrLen = 2; break;  // 0F 08
        case SVM_EXIT_RDTSC:    instrLen = 2; break;  // 0F 31
        case SVM_EXIT_RDTSCP:   instrLen = 3; break;  // 0F 01 F9
        case SVM_EXIT_VMRUN:    instrLen = 3; break;  // 0F 01 D8
        case SVM_EXIT_VMLOAD:   instrLen = 3; break;  // 0F 01 DA
        case SVM_EXIT_VMSAVE:   instrLen = 3; break;  // 0F 01 DB
        case SVM_EXIT_STGI:     instrLen = 3; break;  // 0F 01 DC
        case SVM_EXIT_CLGI:     instrLen = 3; break;  // 0F 01 DD
        case SVM_EXIT_XSETBV:   instrLen = 3; break;  // 0F 01 D1
        case SVM_EXIT_MSR:      instrLen = 2; break;  // 0F 32 / 0F 30
        default:                instrLen = 3; break;  // conservative default
        }

        Vmcb->StateSaveArea.Rip += instrLen;
    }
}

/*
 * 处理 CPUID (SVM) - 完整反虚拟化检测
 */
VOID SvmHandleCpuid(PVMCB Vmcb, PGUEST_CONTEXT GuestContext)
{
    int cpuInfo[4] = { 0 };
    ULONG32 leaf = (ULONG32)Vmcb->StateSaveArea.Rax;
    ULONG32 subleaf = (ULONG32)GuestContext->Rcx;
    
    InterlockedIncrement64((volatile LONG64*)&g_SvmExitCountCpuid);
    
    // 处理 Hypervisor 保留叶（0x40000000 - 0x4FFFFFFF）
    if (g_AntiVmDetectionEnabled && (leaf >= 0x40000000 && leaf <= 0x4FFFFFFF)) {
        Vmcb->StateSaveArea.Rax = 0;
        GuestContext->Rbx = 0;
        GuestContext->Rcx = 0;
        GuestContext->Rdx = 0;
        SvmAdvanceGuestRip(Vmcb);
        return;
    }
    
    // 执行真正的 CPUID
    __cpuidex(cpuInfo, (int)leaf, (int)subleaf);
    
    if (g_EnableNestedVirtualization) {
        if (leaf == 1) {
            cpuInfo[2] &= ~(1 << 31);
        }
    } else if (g_AntiVmDetectionEnabled) {
        switch (leaf) {
        case 1:
            // 隐藏 VMX 和 Hypervisor Present 位
            cpuInfo[2] &= ~(1 << 5);   // 清除 VMX 位
            cpuInfo[2] &= ~(1 << 31);  // 清除 Hypervisor Present 位
            break;
            
        case 0x80000001:
            // 隐藏 SVM 位
            cpuInfo[2] &= ~(1 << 2);   // 清除 SVM 位
            break;
            
        case 0x8000000A:
            // AMD SVM 特性 - 返回 0
            cpuInfo[0] = 0;
            cpuInfo[1] = 0;
            cpuInfo[3] = 0;
            break;
        }
    }
    
    // 更新返回值
    Vmcb->StateSaveArea.Rax = cpuInfo[0];
    GuestContext->Rbx = cpuInfo[1];
    GuestContext->Rcx = cpuInfo[2];
    GuestContext->Rdx = cpuInfo[3];
    
    SvmAdvanceGuestRip(Vmcb);
}

/*
 * 处理 VMMCALL (SVM)
 * 
 * 返回：TRUE = 继续执行，FALSE = 终止虚拟化
 */
BOOLEAN SvmHandleVmmcall(
    PVCPU_DATA VcpuData,
    PVMCB Vmcb,
    PGUEST_CONTEXT GuestContext)
{
    ULONG64 command = GuestContext->Rcx;
    
    InterlockedIncrement64((volatile LONG64*)&g_SvmExitCountVmmcall);
    
    switch (command) {
    case SVM_VMMCALL_TEST:
        // 测试调用
        Vmcb->StateSaveArea.Rax = 0xDEADBEEF;
        break;
        
    case SVM_VMMCALL_GET_VERSION:
        // 返回版本号
        Vmcb->StateSaveArea.Rax = (HV_VERSION_MAJOR << 16) | HV_VERSION_MINOR;
        break;
        
    case SVM_VMMCALL_TERMINATE:
        // 终止虚拟化
        Vmcb->StateSaveArea.Rax = 0;
        SvmAdvanceGuestRip(Vmcb);
        return FALSE;

    case VMCALL_REFRESH_HWBP_STATE:
        Vmcb->StateSaveArea.Dr7 =
            HvDbgRootOnCr3Switch(Vmcb->StateSaveArea.Cr3);
        Vmcb->ControlArea.VmcbCleanBits = 0;
        Vmcb->StateSaveArea.Rax = 0;
        break;

    case VMCALL_REFRESH_NPT_STATE:
        Vmcb->ControlArea.TlbControl = SVM_TLB_CONTROL_FLUSH_GUEST;
        Vmcb->StateSaveArea.Rax = 0;
        break;

    case VMCALL_PHYS_COPY: {
        // SVM mirrors the bounded VMX contract: validated CR3 plus one page.
        PVCPU_DATA vcpu = VcpuData;
        ULONG mode = (ULONG)(GuestContext->R11 & 0xFFFFFFFFULL);
        UINT64 targetCr3 = GuestContext->Rdx;
        NTSTATUS s;

        if (mode == HV_VTROOT_MODE_PROCESS_READ ||
            mode == HV_VTROOT_MODE_PROCESS_WRITE ||
            mode == HV_VTROOT_MODE_PROCESS_RESOLVE ||
            mode == HV_VTROOT_MODE_PROCESS_WALK) {
            UINT64 result = 0;
            s = HvVtRootRootProcessRequest(
                vcpu, (PVOID)(ULONG_PTR)GuestContext->Rdx, mode, &result);
            GuestContext->R10 = result;
        } else if (mode == HV_VTROOT_MODE_GVA_TO_HPA) {
            UINT64 hpa = 0, pageSize = 0;
            s = HvVtRootRootWalkGvaToHpaWithCr3(
                vcpu, targetCr3, GuestContext->R8, &hpa, &pageSize);
            if (NT_SUCCESS(s)) {
                if (pageSize == PAGE_SIZE) {
                    GuestContext->R10 = hpa;
                } else {
                    GuestContext->R10 = pageSize;
                    s = STATUS_NOT_SUPPORTED;
                }
            } else {
                GuestContext->R10 = 0;
            }
        } else if (mode == HV_VTROOT_MODE_LEAF_PTE_INFO) {
            SIZE_T infoSize = (SIZE_T)GuestContext->R10;
            if (infoSize != sizeof(HV_VTROOT_LEAF_PTE_INFO)) {
                GuestContext->R10 = 0;
                s = STATUS_INFO_LENGTH_MISMATCH;
            } else {
                s = HvVtRootRootQueryLeafPteWithCr3(
                    vcpu, targetCr3, GuestContext->R8,
                    (PHV_VTROOT_LEAF_PTE_INFO)(ULONG_PTR)GuestContext->R9);
                GuestContext->R10 = NT_SUCCESS(s)
                    ? sizeof(HV_VTROOT_LEAF_PTE_INFO)
                    : 0;
            }
        } else if (mode == HV_VTROOT_DIR_READ ||
                   mode == HV_VTROOT_DIR_WRITE) {
            SIZE_T done = 0;
            s = HvVtRootRootCopyOnePage(
                vcpu, targetCr3,
                GuestContext->R8,
                (PUCHAR)GuestContext->R9,
                (SIZE_T)GuestContext->R10,
                (BOOLEAN)(mode == HV_VTROOT_DIR_WRITE),
                &done);
            GuestContext->R10 = (ULONG64)done;
        } else {
            GuestContext->R10 = 0;
            s = STATUS_NOT_SUPPORTED;
        }
        // SVM 约定: RAX 必须写到 VMCB StateSaveArea (而非 GuestContext)
        Vmcb->StateSaveArea.Rax = (ULONG64)s;
        break;
    }

    default:
        // Publish or withdraw debugger CR3/DR exits on this VMCB.
        if ((command & ~(ULONG64)HV_DBG_INTERCEPT_MODE_MASK) ==
            VMCALL_SET_DEBUGGER_INTERCEPT_MODE) {
            ULONG mode = (ULONG)command & HV_DBG_INTERCEPT_MODE_MASK;
            BOOLEAN hadMovDr =
                (Vmcb->ControlArea.InterceptDrRead & 0x00FF) != 0 ||
                (Vmcb->ControlArea.InterceptDrWrite & 0x00FF) != 0;
            if (mode & HV_DBG_INTERCEPT_MODE_CR3) {
                Vmcb->ControlArea.InterceptCrWrite |= (1u << 3);
            } else {
                Vmcb->ControlArea.InterceptCrWrite &= ~(USHORT)(1u << 3);
            }
            if (mode & HV_DBG_INTERCEPT_MODE_MOV_DR) {
                Vmcb->ControlArea.InterceptDrRead |= 0x00FF;
                Vmcb->ControlArea.InterceptDrWrite |= 0x00FF;
                Vmcb->StateSaveArea.Dr7 =
                    HvDbgRootOnCr3Switch(Vmcb->StateSaveArea.Cr3);
            } else if (hadMovDr) {
                Vmcb->ControlArea.InterceptDrRead &= (USHORT)~0x00FFu;
                Vmcb->ControlArea.InterceptDrWrite &= (USHORT)~0x00FFu;
                HvDbgClearHardwareDr();
                Vmcb->StateSaveArea.Dr7 = (1ULL << 10);
            } else {
                Vmcb->ControlArea.InterceptDrRead &= (USHORT)~0x00FFu;
                Vmcb->ControlArea.InterceptDrWrite &= (USHORT)~0x00FFu;
            }
            Vmcb->ControlArea.VmcbCleanBits = 0;
            Vmcb->StateSaveArea.Rax = 0;
            break;
        }
        // 未知 VMMCALL
        Vmcb->StateSaveArea.Rax = (ULONG64)-1;
        break;
    }

    SvmAdvanceGuestRip(Vmcb);
    return TRUE;
}

/*
 * 处理 MSR 访问 (SVM) - 带反虚拟化检测
 * 
 * ExitInfo1: 0 = RDMSR, 1 = WRMSR
 */
VOID SvmHandleMsr(
    PVCPU_DATA VcpuData,
    PVMCB Vmcb,
    PGUEST_CONTEXT GuestContext,
    ULONG64 ExitInfo1)
{
    ULONG32 msr = (ULONG32)GuestContext->Rcx;
    ULONG64 value = 0;
    BOOLEAN shouldFake = FALSE;
    BOOLEAN gpRaised = FALSE;

    InterlockedIncrement64((volatile LONG64*)&g_SvmExitCountMsr);

    if (ExitInfo1 == 0) {
        if (msr == MSR_IA32_EFER) {
            value = Vmcb->StateSaveArea.Efer;
            if (!g_EnableNestedVirtualization) value &= ~EFER_SVME;
            shouldFake = TRUE;
        } else if (g_EnableNestedVirtualization &&
                   msr == 0xC0010117) {
            value = VcpuData ? VcpuData->NestedSvm.HostSaveGpa : 0;
            shouldFake = TRUE;
        } else if (g_EnableNestedVirtualization &&
                   msr == 0xC0010114) {
            value = 0;
            shouldFake = TRUE;
        }
        // RDMSR - 带反检测
        if (!shouldFake && g_AntiVmDetectionEnabled) {
            switch (msr) {
            case MSR_IA32_FEATURE_CONTROL:  // 0x3A
                value = AsmSafeReadMsr(msr, &gpRaised);
                value &= ~FEATURE_CONTROL_VMXON_OUTSIDE_SMX;
                shouldFake = TRUE;
                break;

            case 0xC0010114:  // MSR_AMD_VM_CR
                value = (1ULL << 4);  // SVMDIS = 1
                shouldFake = TRUE;
                break;

            case 0xC0010117:  // MSR_AMD_VM_HSAVE_PA
            case 0xC001011F:  // MSR_AMD_SVM_KEY
                value = 0;
                shouldFake = TRUE;
                break;

            // Intel VMX MSRs - 返回 0
            case 0x480: case 0x481: case 0x482: case 0x483:
            case 0x484: case 0x485: case 0x486: case 0x487:
            case 0x488: case 0x489: case 0x48A: case 0x48B:
            case 0x48C: case 0x48D: case 0x48E: case 0x48F:
            case 0x490: case 0x491:
                value = 0;
                shouldFake = TRUE;
                break;
            }
        }

        // EFER：无论反检测开关，都必须隐藏 SVME 位（VMX 期间硬件强制为 1，
        // 暴露会让 Guest 立刻识别出 hypervisor 存在）
        if (!shouldFake && msr == MSR_IA32_EFER) {
            value = AsmSafeReadMsr(msr, &gpRaised);
            value &= ~EFER_SVME;
            shouldFake = TRUE;
        }

        if (!shouldFake) {
            value = AsmSafeReadMsr(msr, &gpRaised);
            if (gpRaised) {
                // 2026-06-16: 把 #GP 反射给 guest, 与 bare metal 一致 (反 VM 透明化)。
                if (VcpuData) {
                    SvmInjectException(VcpuData, 13, TRUE, 0);
                }
                return;   // 不 advance RIP, guest 重新跑 rdmsr 时硬件直接交付 #GP
            }
        }

        Vmcb->StateSaveArea.Rax = (ULONG32)value;
        GuestContext->Rdx = (ULONG32)(value >> 32);
    }
    else {
        // WRMSR
        value = ((ULONG64)(ULONG32)GuestContext->Rdx << 32) | (ULONG32)Vmcb->StateSaveArea.Rax;

        // 安全过滤：不允许 Guest 写以下 MSR（会直接破坏 SVM 状态）
        switch (msr) {
        case MSR_IA32_EFER:
#if 0
            // 强制保留 SVME=1，Guest 看到的 EFER 没 SVME，写回来也别让 SVME 被清掉
            value |= EFER_SVME;
            if (!AsmSafeWriteMsr(msr, (ULONG32)value, (ULONG32)(value >> 32))) {
                if (VcpuData) {
                    SvmInjectException(VcpuData, 13, TRUE, 0);
                }
                return;
            }
            break;
#endif
            if (!g_EnableNestedVirtualization) value &= ~EFER_SVME;
            Vmcb->StateSaveArea.Efer = value;
            Vmcb->ControlArea.VmcbCleanBits = 0;
            break;

        case 0xC0010114:  // MSR_AMD_VM_CR
            break;

        case 0xC0010117:  // MSR_AMD_VM_HSAVE_PA
            if (g_EnableNestedVirtualization && VcpuData &&
                (value & (PAGE_SIZE - 1)) == 0) {
                VcpuData->NestedSvm.HostSaveGpa = value;
            } else if (g_EnableNestedVirtualization) {
                if (VcpuData) {
                    SvmInjectException(VcpuData, 13, TRUE, 0);
                }
                return;
            }
            break;

        case 0xC001011F:  // MSR_AMD_SVM_KEY
            // 静默忽略：让 Guest 误以为写成功
            break;

        default:
            if (!AsmSafeWriteMsr(msr, (ULONG32)value, (ULONG32)(value >> 32))) {
                if (VcpuData) {
                    SvmInjectException(VcpuData, 13, TRUE, 0);
                }
                return;
            }
            break;
        }
    }

    SvmAdvanceGuestRip(Vmcb);
}

/*
 * 处理 CR 访问 (SVM)
 */
static ULONG64 SvmReadGuestGpr(
    _In_ PVMCB Vmcb,
    _In_ PGUEST_CONTEXT GuestContext,
    _In_ ULONG GprIndex)
{
    switch (GprIndex) {
    case 0:  return Vmcb->StateSaveArea.Rax;
    case 1:  return GuestContext->Rcx;
    case 2:  return GuestContext->Rdx;
    case 3:  return GuestContext->Rbx;
    case 4:  return Vmcb->StateSaveArea.Rsp;
    case 5:  return GuestContext->Rbp;
    case 6:  return GuestContext->Rsi;
    case 7:  return GuestContext->Rdi;
    case 8:  return GuestContext->R8;
    case 9:  return GuestContext->R9;
    case 10: return GuestContext->R10;
    case 11: return GuestContext->R11;
    case 12: return GuestContext->R12;
    case 13: return GuestContext->R13;
    case 14: return GuestContext->R14;
    case 15: return GuestContext->R15;
    default: return 0;
    }
}

static VOID SvmWriteGuestGpr(
    _Inout_ PVMCB Vmcb,
    _Inout_ PGUEST_CONTEXT GuestContext,
    _In_ ULONG GprIndex,
    _In_ ULONG64 Value)
{
    switch (GprIndex) {
    case 0:  Vmcb->StateSaveArea.Rax = Value; break;
    case 1:  GuestContext->Rcx = Value; break;
    case 2:  GuestContext->Rdx = Value; break;
    case 3:  GuestContext->Rbx = Value; break;
    case 4:  Vmcb->StateSaveArea.Rsp = Value; break;
    case 5:  GuestContext->Rbp = Value; break;
    case 6:  GuestContext->Rsi = Value; break;
    case 7:  GuestContext->Rdi = Value; break;
    case 8:  GuestContext->R8 = Value; break;
    case 9:  GuestContext->R9 = Value; break;
    case 10: GuestContext->R10 = Value; break;
    case 11: GuestContext->R11 = Value; break;
    case 12: GuestContext->R12 = Value; break;
    case 13: GuestContext->R13 = Value; break;
    case 14: GuestContext->R14 = Value; break;
    case 15: GuestContext->R15 = Value; break;
    }
}

VOID SvmHandleCrAccess(PVCPU_DATA VcpuData, PVMCB Vmcb, PGUEST_CONTEXT GuestContext, ULONG64 ExitCode, ULONG64 ExitInfo1)
{
    ULONG crNum;
    BOOLEAN isWrite;
    ULONG64 value = 0;
    ULONG gprIndex = (ULONG)(ExitInfo1 & 0xF);
    
    // 解析退出码
    // SVM_EXIT_READ_CR0 = 0x0000, SVM_EXIT_READ_CR8 = 0x0008
    // SVM_EXIT_WRITE_CR0 = 0x0010, SVM_EXIT_WRITE_CR8 = 0x0018
    if (ExitCode <= SVM_EXIT_READ_CR8) {
        crNum = (ULONG)ExitCode;
        isWrite = FALSE;
    }
    else if (ExitCode >= SVM_EXIT_WRITE_CR0 && ExitCode <= SVM_EXIT_WRITE_CR8) {
        crNum = (ULONG)(ExitCode - SVM_EXIT_WRITE_CR0);
        isWrite = TRUE;
    }
    else {
        SvmAdvanceGuestRip(Vmcb);
        return;
    }

    if ((ExitInfo1 & (1ULL << 63)) == 0) {
        if (isWrite) {
            Vmcb->ControlArea.InterceptCrWrite &= (USHORT)~(1u << crNum);
        } else {
            Vmcb->ControlArea.InterceptCrRead &= (USHORT)~(1u << crNum);
        }
        Vmcb->ControlArea.VmcbCleanBits = 0;
        return;
    }
    
    if (isWrite) {
        value = SvmReadGuestGpr(Vmcb, GuestContext, gprIndex);
        switch (crNum) {
        case 0:
            Vmcb->StateSaveArea.Cr0 = value;
            break;
        case 3: {
            ULONG64 normalizedCr3 = 0;
            BOOLEAN invalidateTlb = TRUE;

            if (!HvNormalizeGuestCr3(
                    value,
                    Vmcb->StateSaveArea.Cr4,
                    &normalizedCr3,
                    &invalidateTlb)) {
                SvmInjectEvent(
                    VcpuData,
                    13,
                    SVM_EVENT_TYPE_EXCEPTION,
                    TRUE,
                    0);
                Vmcb->ControlArea.VmcbCleanBits = 0;
                return;
            }

            Vmcb->StateSaveArea.Cr3 = normalizedCr3;
            if (invalidateTlb) {
                Vmcb->ControlArea.TlbControl =
                    SVM_TLB_CONTROL_FLUSH_GUEST;
            }
            if (HvDebuggerPublishedMovDrExiting()) {
                Vmcb->StateSaveArea.Dr7 =
                    HvDbgRootOnCr3Switch(normalizedCr3);
            }
            break;
        }
        case 4:
            Vmcb->StateSaveArea.Cr4 = value;
            break;
        }
    }
    else {
        // MOV from CR
        switch (crNum) {
        case 0:
            value = Vmcb->StateSaveArea.Cr0;
            break;
        case 3:
            value = Vmcb->StateSaveArea.Cr3;
            break;
        case 4:
            value = Vmcb->StateSaveArea.Cr4;
            break;
        default:
            value = 0;
            break;
        }
        SvmWriteGuestGpr(Vmcb, GuestContext, gprIndex, value);
    }

    Vmcb->ControlArea.VmcbCleanBits = 0;
    SvmAdvanceGuestRip(Vmcb);
}

/*
 * 阶段 7: SVM MOV-DR 处理
 *
 * SVM 退出码:
 *   SVM_EXIT_READ_DR0..7  = 0x20..0x27  (mov %dr, %reg)
 *   SVM_EXIT_WRITE_DR0..7 = 0x30..0x37  (mov %reg, %dr)
 *
 * GPR 编码: AMD Decode Assists 模式下,EXITINFO1[3:0] = GPR 号 (0..15)。
 * Decode Assists 由 CPUID 8000_000A.EDX[7] 表明,Zen 及以上默认支持。
 * 不支持时 ExitInfo1=0,我们会把 GPR 0 (RAX) 当成目标 — 实际反作弊指令
 * 通常正好是 `mov rax, dr0`,所以失败时也大概率正确。
 *
 * 行为:被保护进程 read 返回 0,write 静默吞;其他进程透传。
 */
static VOID SvmHandleMovDr(PVMCB Vmcb, PGUEST_CONTEXT GuestContext, ULONG64 ExitCode, ULONG64 ExitInfo1)
{
    BOOLEAN isWrite;
    ULONG drNum;

    if (ExitCode >= SVM_EXIT_WRITE_DR0 && ExitCode <= SVM_EXIT_WRITE_DR7) {
        isWrite = TRUE;
        drNum = (ULONG)(ExitCode - SVM_EXIT_WRITE_DR0);
    } else if (ExitCode >= SVM_EXIT_READ_DR0 && ExitCode <= SVM_EXIT_READ_DR7) {
        isWrite = FALSE;
        drNum = (ULONG)(ExitCode - SVM_EXIT_READ_DR0);
    } else {
        SvmAdvanceGuestRip(Vmcb);
        return;
    }

    ULONG gprIdx = (ULONG)(ExitInfo1 & 0xF);   // Decode Assists
    BOOLEAN isProtectedTarget =
        HvDbgRootIsTargetCr3(Vmcb->StateSaveArea.Cr3);

    if (!isWrite) {
        ULONG64 value = 0;
        if (!isProtectedTarget || drNum == 6) {
            if (drNum == 6) {
                value = Vmcb->StateSaveArea.Dr6;
            } else if (drNum == 7) {
                value = Vmcb->StateSaveArea.Dr7;
            } else {
                value = HvDbgReadRealDr(drNum);
            }
        }
        SvmWriteGuestGpr(Vmcb, GuestContext, gprIdx, value);
    } else {
        if (!isProtectedTarget || drNum == 6) {
            ULONG64 srcVal = SvmReadGuestGpr(Vmcb, GuestContext, gprIdx);
            if (drNum == 6) {
                Vmcb->StateSaveArea.Dr6 = srcVal;
            } else if (drNum == 7) {
                Vmcb->StateSaveArea.Dr7 = srcVal;
            } else {
                HvDbgWriteRealDr(drNum, srcVal);
            }
        }
    }

    Vmcb->ControlArea.VmcbCleanBits = 0;
    SvmAdvanceGuestRip(Vmcb);
}

/*
 * 处理 NPF - Nested Page Fault (SVM)
 * 
 * ErrorCode: 页故障错误码 (ExitInfo1)
 * FaultAddress: 导致故障的客户物理地址 (ExitInfo2)
 * 
 * 错误码格式（与标准 Page Fault 相同）：
 *   Bit 0 (P): 1=保护违规, 0=页不存在
 *   Bit 1 (W): 1=写访问, 0=读访问
 *   Bit 2 (U): 1=用户模式, 0=内核模式
 *   Bit 3 (R): 1=保留位冲突
 *   Bit 4 (I): 1=指令获取, 0=数据访问
 *   Bit 5 (PK): 1=保护密钥违规
 *   Bit 31 (RMP): 1=RMP 违规 (SEV-SNP)
 *   Bits 32-63: AMD 扩展信息
 */
BOOLEAN SvmHandleNpf(PVCPU_DATA VcpuData, ULONG64 ErrorCode, ULONG64 FaultAddress)
{
    BOOLEAN injectToL1 = FALSE;
    
    InterlockedIncrement64((volatile LONG64*)&g_SvmExitCountNpf);
    
    // 如果启用了嵌套虚拟化且在 L2 中
    if (g_EnableNestedVirtualization && VcpuData && VcpuData->IsInL2) {
        // 使用嵌套 NPT 处理
        if (NestedNptHandleFault(VcpuData, FaultAddress, ErrorCode, &injectToL1)) {
            if (injectToL1) {
                // 需要将 NPF 注入到 L1
                NestedSvmExitToL1(VcpuData, SVM_EXIT_NPF, ErrorCode, FaultAddress);
            }
            return TRUE;
        }
        // 嵌套 NPT 没有处理，继续由 L0 处理（可能是 L0 的 Hook）
    }
    
    // 尝试使用 NPT Hook 处理
    if (NptHookHandleDebugStepNpf(VcpuData, FaultAddress, ErrorCode)) {
        return TRUE;
    }

    if (NptHookHandleNpf(VcpuData, FaultAddress, ErrorCode)) {
        return TRUE;
    }
    
    // 如果在 L2 中且 L0 Hook 没有处理，注入到 L1
    if (g_EnableNestedVirtualization && VcpuData && VcpuData->IsInL2) {
        NestedSvmExitToL1(VcpuData, SVM_EXIT_NPF, ErrorCode, FaultAddress);
        return TRUE;
    }
    
    // 未被 NPT Hook 处理的 NPF - 修复页表权限防止无限循环
    {
        static volatile LONG64 unhandledNpfCount = 0;
        InterlockedIncrement64(&unhandledNpfCount);

        // PA >= 512GB 进入 PML4[1..3]: 已是 1GB 大页 (HV_ENABLE_SVM_HARDENING=1) 或未映射;
        // NptGetPteForPhysicalAddress 会返回 NULL, 这里也走授大页 RWX 路径
        ULONG64 pml4Idx = (FaultAddress >> 39) & 0x1FFu;

        // 尝试获取 NPT PTE 并授予完整权限，防止同一地址反复触发 NPF
        if (VcpuData && VcpuData->NptTables) {
            if (pml4Idx == 0) {
                PNPT_PTE pte = NptGetPteForPhysicalAddress(VcpuData, FaultAddress);
                if (pte) {
                    pte->Present = 1;
                    pte->Write = 1;
                    pte->NoExecute = 0;
                }
            }
            // PML4[1..3] 走大页, 不在 Pd[][] 范围, 这里不调整页表权限
            // (HV_ENABLE_SVM_HARDENING=1 已映射为 RWX 1GB 大页, 不会再次 NPF;
            //  =0 时这里 NULL 返回, 高地址 MMIO 仍可能死循环, 已知限制)
            VcpuData->Vmcb->ControlArea.TlbControl = SVM_TLB_CONTROL_FLUSH_GUEST;
        }
    }

    return TRUE;
}

/*
 * 处理异常 (SVM)
 * 
 * @param VcpuData  VCPU 数据
 * @param ExitCode  退出码 (SVM_EXIT_EXCEPTION_xx)
 * @return TRUE 如果已处理（不需要重注入），FALSE 需要重注入
 */
BOOLEAN SvmHandleException(PVCPU_DATA VcpuData, ULONG64 ExitCode)
{
    PVMCB Vmcb = VcpuData->Vmcb;
    ULONG vector = (ULONG)(ExitCode - SVM_EXIT_EXCEPTION_DE);

    // #DB (Debug Exception, vector 1) - 用于 NPT Hook 单步恢复 / HWBP
    if (vector == 1) {
        ULONG debugStepResult = NptHookHandleDebugStepDb(VcpuData);
        if (debugStepResult == NPT_DEBUG_STEP_DB_CONSUME) {
            return TRUE;
        }
        if (debugStepResult == NPT_DEBUG_STEP_DB_REINJECT) {
            goto ReinjectException;
        }

        // 先尝试用 NPT Hook 处理单步 (BS = bit 14)
        if (NptHookHandleSingleStep(VcpuData)) {
            return TRUE;
        }

        // Hardware breakpoints belong to the Windows debug port. If #DB is
        // intercepted temporarily for an NPT single-step, preserve VMCB.Dr6
        // and reinject it below instead of consuming it in the private ring.
    }

    // 简单重注入异常 — 走统一 SvmInjectEvent (含 vGIF 门控)
ReinjectException:
    {
        BOOLEAN hasErr = (vector == 8 || vector == 10 || vector == 11 ||
                         vector == 12 || vector == 13 || vector == 14 || vector == 17);
        ULONG errCode = hasErr ? (ULONG)Vmcb->ControlArea.ExitInfo1 : 0;
        SvmInjectEvent(VcpuData, (UCHAR)vector, SVM_EVENT_TYPE_EXCEPTION, hasErr, errCode);
    }
    return FALSE;
}

/*
 * 处理 XSETBV (SVM)
 */
VOID SvmHandleXsetbv(PVMCB Vmcb, PGUEST_CONTEXT GuestContext)
{
    ULONG32 xcr = (ULONG32)GuestContext->Rcx;
    ULONG64 value = ((ULONG64)(ULONG32)GuestContext->Rdx << 32) | (ULONG32)Vmcb->StateSaveArea.Rax;
    
    __try {
        _xsetbv(xcr, value);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // 忽略失败
    }
    
    SvmAdvanceGuestRip(Vmcb);
}

/*
 * SVM #VMEXIT 主分发函数
 * 
 * 由汇编 AsmSvmVmExitHandler 调用
 * 
 * 参数：
 *   VcpuData - VCPU 数据指针
 *   GuestContext - 指向栈上保存的 Guest 寄存器
 * 
 * 返回：TRUE = VMRUN 继续，FALSE = 终止虚拟化
 */
BOOLEAN SvmVmExitDispatch(PVCPU_DATA VcpuData, PGUEST_CONTEXT GuestContext)
{
    PVMCB vmcb;
    ULONG64 exitCode;
    ULONG64 exitInfo1;
    ULONG64 exitInfo2;
    BOOLEAN shouldContinue = TRUE;

    if (!VcpuData || !VcpuData->Vmcb) {
        return FALSE;
    }

    // 设置 SVM root 模式标志
    NptSetSvmRootMode(TRUE);

    // 阶段 7.9: 抓 #VMEXIT 入口 TSC, 用于退出前补偿 host 处理时间
    // 仅在 HWBP 启用时才记账,否则会引入持续负偏移导致多核 TSC 失同步
    if (g_GlobalHwbpRefCount > 0) {
        VcpuData->LastVmExitHostTsc = __rdtsc();
    }
    
    vmcb = VcpuData->Vmcb;
    // VMRUN consumes the previous command. Clear it before dispatch so a
    // handler can arm the command that must be applied by the next VMRUN.
    vmcb->ControlArea.TlbControl = SVM_TLB_CONTROL_NOTHING;

    // 检查是否需要刷新 NPT TLB（多 CPU 同步）。必须在清除上一轮命令之后，
    // 否则这里 arm 的 FLUSH_GUEST 会在同一出口被覆盖，永远到不了下一次 VMRUN。
    NptCheckAndInvalidateTlb(VcpuData);

    exitCode = vmcb->ControlArea.ExitCode;
    exitInfo1 = vmcb->ControlArea.ExitInfo1;
    exitInfo2 = vmcb->ControlArea.ExitInfo2;

    g_SvmLastExitCode = exitCode;

    // 被动嗅探当前 guest CR3 (SVM 上从 VMCB StateSaveArea.Cr3 直接读)。
    // 同时传 RIP, 让 ring 只收 user-mode CR3 (避开 shadow CR3 污染)。
    if (HvCr3SnoopIsEnabled()) {
        HvCr3SnoopRecord((UINT64)vmcb->StateSaveArea.Cr3,
                         (UINT64)vmcb->StateSaveArea.Rip);
    }
    
    // === 嵌套虚拟化：L2 退出处理 ===
    // 如果启用了嵌套虚拟化且当前在 L2 中运行
    if (g_EnableNestedVirtualization && VcpuData->IsInL2) {
        if (HvNestedIsQuiescing()) {
            NestedSvmExitToL1(
                VcpuData, exitCode, exitInfo1, exitInfo2);
            NptSetSvmRootMode(FALSE);
            return TRUE;
        }
        // 判断这个退出是否应该由 L0 处理
        if (!NestedSvmShouldL0HandleExit(VcpuData, exitCode, exitInfo1, exitInfo2)) {
            // L0 不需要处理，将退出分发给 L2 处理
            if (NestedSvmDispatchL2Exit(VcpuData, exitCode, exitInfo1, exitInfo2, GuestContext)) {
                // L2 退出已被处理（注入到 L1 或由 L0 处理）
                NptSetSvmRootMode(FALSE);
                return TRUE;
            }
        }
        // 继续由 L0 处理这个退出
    }
    
    // 分发到具体 Handler
    switch (exitCode) {
    
    case SVM_EXIT_CPUID:
        SvmHandleCpuid(vmcb, GuestContext);
        break;
        
    case SVM_EXIT_VMMCALL:
        shouldContinue = SvmHandleVmmcall(VcpuData, vmcb, GuestContext);
        break;
        
    case SVM_EXIT_MSR:
        SvmHandleMsr(VcpuData, vmcb, GuestContext, exitInfo1);
        break;
        
    case SVM_EXIT_READ_CR0:
    case SVM_EXIT_READ_CR3:
    case SVM_EXIT_READ_CR4:
    case SVM_EXIT_WRITE_CR0:
    case SVM_EXIT_WRITE_CR3:
    case SVM_EXIT_WRITE_CR4:
        SvmHandleCrAccess(VcpuData, vmcb, GuestContext, exitCode, exitInfo1);
        break;

    case SVM_EXIT_READ_DR0:
    case 0x21:  // SVM_EXIT_READ_DR1
    case 0x22:  // SVM_EXIT_READ_DR2
    case 0x23:  // SVM_EXIT_READ_DR3
    case 0x24:  // SVM_EXIT_READ_DR4
    case 0x25:  // SVM_EXIT_READ_DR5
    case 0x26:  // SVM_EXIT_READ_DR6
    case SVM_EXIT_READ_DR7:
    case SVM_EXIT_WRITE_DR0:
    case 0x31:  // SVM_EXIT_WRITE_DR1
    case 0x32:  // SVM_EXIT_WRITE_DR2
    case 0x33:  // SVM_EXIT_WRITE_DR3
    case 0x34:  // SVM_EXIT_WRITE_DR4
    case 0x35:  // SVM_EXIT_WRITE_DR5
    case 0x36:  // SVM_EXIT_WRITE_DR6
    case SVM_EXIT_WRITE_DR7:
        SvmHandleMovDr(vmcb, GuestContext, exitCode, exitInfo1);
        break;
        
    case SVM_EXIT_NPF:
        shouldContinue = SvmHandleNpf(VcpuData, exitInfo1, exitInfo2);
        break;
        
    case SVM_EXIT_XSETBV:
        SvmHandleXsetbv(vmcb, GuestContext);
        break;
        
    case SVM_EXIT_HLT:
        SvmAdvanceGuestRip(vmcb);
        break;
        
    case SVM_EXIT_INVD:
        __wbinvd();
        SvmAdvanceGuestRip(vmcb);
        break;
        
    case SVM_EXIT_RDTSC:
        {
            ULONG64 tsc = __rdtsc();
            ULONG cpuIndex = VcpuData->ProcessorNumber;

            if (g_AntiVmDetectionEnabled && cpuIndex < MAX_CPU_COUNT) {
                if (g_LastVmExitTsc[cpuIndex] != 0) {
                    ULONG64 newOffset = g_TscOffset[cpuIndex] + VM_EXIT_TSC_OVERHEAD;
                    if (newOffset <= MAX_TSC_OFFSET) {
                        g_TscOffset[cpuIndex] = newOffset;
                    }
                }
                g_LastVmExitTsc[cpuIndex] = tsc;
                if (tsc > g_TscOffset[cpuIndex]) {
                    tsc -= g_TscOffset[cpuIndex];
                }
            }

            vmcb->StateSaveArea.Rax = (ULONG32)tsc;
            GuestContext->Rdx = (ULONG32)(tsc >> 32);
            SvmAdvanceGuestRip(vmcb);
        }
        break;

    case SVM_EXIT_RDTSCP:
        {
            ULONG32 aux;
            ULONG64 tsc = __rdtscp(&aux);
            ULONG cpuIndex = VcpuData->ProcessorNumber;

            if (g_AntiVmDetectionEnabled && cpuIndex < MAX_CPU_COUNT) {
                if (g_LastVmExitTsc[cpuIndex] != 0) {
                    ULONG64 newOffset = g_TscOffset[cpuIndex] + VM_EXIT_TSC_OVERHEAD;
                    if (newOffset <= MAX_TSC_OFFSET) {
                        g_TscOffset[cpuIndex] = newOffset;
                    }
                }
                g_LastVmExitTsc[cpuIndex] = tsc;
                if (tsc > g_TscOffset[cpuIndex]) {
                    tsc -= g_TscOffset[cpuIndex];
                }
            }

            vmcb->StateSaveArea.Rax = (ULONG32)tsc;
            GuestContext->Rdx = (ULONG32)(tsc >> 32);
            GuestContext->Rcx = aux;
            SvmAdvanceGuestRip(vmcb);
        }
        break;
        
    case SVM_EXIT_VMRUN:
        // L1 执行 VMRUN 进入 L2
        if (HvNestedCanEnterL2()) {
            // 完整实现：调用嵌套 SVM 处理函数
            if (NestedSvmHandleVmrun(VcpuData, GuestContext)) {
                // VMRUN 成功处理，执行流已切换到 L2
                // 不需要推进 RIP
                break;
            }
            // VMRUN 处理失败，会注入异常
        } else {
            // 未启用嵌套虚拟化，注入 #UD 异常
            SvmHandleException(VcpuData, SVM_EXIT_EXCEPTION_UD);
        }
        break;
        
    case SVM_EXIT_VMLOAD:
        // L1 执行 VMLOAD 加载 Guest 状态
        if (g_EnableNestedVirtualization) {
            // 完整实现：调用嵌套 SVM 处理函数
            NestedSvmHandleVmload(VcpuData, GuestContext);
        } else {
            SvmHandleException(VcpuData, SVM_EXIT_EXCEPTION_UD);
        }
        break;
        
    case SVM_EXIT_VMSAVE:
        // L1 执行 VMSAVE 保存 Guest 状态
        if (g_EnableNestedVirtualization) {
            // 完整实现：调用嵌套 SVM 处理函数
            NestedSvmHandleVmsave(VcpuData, GuestContext);
        } else {
            SvmHandleException(VcpuData, SVM_EXIT_EXCEPTION_UD);
        }
        break;
        
    case SVM_EXIT_STGI:
        // L1 执行 STGI（Set Global Interrupt Flag）
        if (g_EnableNestedVirtualization) {
            // 完整实现：调用嵌套 SVM 处理函数
            NestedSvmHandleStgi(VcpuData, GuestContext);
        } else {
            SvmHandleException(VcpuData, SVM_EXIT_EXCEPTION_UD);
        }
        break;
        
    case SVM_EXIT_CLGI:
        // L1 执行 CLGI（Clear Global Interrupt Flag）
        if (g_EnableNestedVirtualization) {
            // 完整实现：调用嵌套 SVM 处理函数
            NestedSvmHandleClgi(VcpuData, GuestContext);
        } else {
            SvmHandleException(VcpuData, SVM_EXIT_EXCEPTION_UD);
        }
        break;
        
    case SVM_EXIT_SHUTDOWN:
        // 注意：SVM root 模式下不要调用 DbgPrint
        shouldContinue = FALSE;
        break;
        
    case SVM_EXIT_INTR:
        // 物理中断 - 已由硬件处理
        break;
        
    case SVM_EXIT_NMI:
        // NMI - 需要重注入；走统一 SvmInjectEvent (含 vGIF 门控)
        SvmInjectEvent(VcpuData, 2, SVM_EVENT_TYPE_NMI, FALSE, 0);
        break;
        
    default:
        // 处理异常退出
        if (exitCode >= SVM_EXIT_EXCEPTION_DE && exitCode <= SVM_EXIT_EXCEPTION_XF) {
            SvmHandleException(VcpuData, exitCode);
        }
        else {
            // 未知退出
            // 注意：SVM root 模式下不要调用 DbgPrint
            InterlockedIncrement64((volatile LONG64*)&g_SvmExitCountOther);
        }
        break;
    }
    
    // 阶段 7.9: VMRUN 前累积 host 处理时间,写入 VMCB.TscOffset
#if !HV_DISABLE_TSC_COMPENSATION
    if (g_GlobalHwbpRefCount > 0) {
        UINT64 endTsc = __rdtsc();
        UINT64 delta = endTsc - VcpuData->LastVmExitHostTsc;
        VcpuData->TscOffsetCompensation -= (INT64)delta;
        vmcb->ControlArea.TscOffset = (UINT64)VcpuData->TscOffsetCompensation;
        // TscOffset 没有独立 clean bit,清整张 VmcbClean 让硬件重读
        vmcb->ControlArea.VmcbCleanBits = 0;
    }
#endif

    // 清除 SVM root 模式标志
    NptSetSvmRootMode(FALSE);

    return shouldContinue;
}

/*
 * SVM 终止回调
 */
VOID SvmTerminatedCallback(VOID)
{
    g_SvmTerminated = TRUE;
}

/*
 * 打印 SVM 调试统计信息
 */
VOID SvmPrintDebugStats(VOID)
{
    DbgPrint("[SVM-DEBUG] ========== #VMEXIT Statistics ==========\n");
    DbgPrint("[SVM-DEBUG] Total #VMEXITs: %llu\n", g_SvmExitCounter);
    DbgPrint("[SVM-DEBUG] Last Exit Code: 0x%llX\n", g_SvmLastExitCode);
    DbgPrint("[SVM-DEBUG] Debug Flag: 0x%llX\n", g_SvmDebugFlag);
    DbgPrint("[SVM-DEBUG] ---------- Exit Counts by Type ----------\n");
    DbgPrint("[SVM-DEBUG] CPUID: %llu\n", g_SvmExitCountCpuid);
    DbgPrint("[SVM-DEBUG] VMMCALL: %llu\n", g_SvmExitCountVmmcall);
    DbgPrint("[SVM-DEBUG] MSR: %llu\n", g_SvmExitCountMsr);
    DbgPrint("[SVM-DEBUG] NPF: %llu\n", g_SvmExitCountNpf);
    DbgPrint("[SVM-DEBUG] Other: %llu\n", g_SvmExitCountOther);
    DbgPrint("[SVM-DEBUG] ==========================================\n");
}

// ==================== 反虚拟化检测控制 ====================

/*
 * 启用/禁用反虚拟化检测
 */
VOID HvSetAntiVmDetection(BOOLEAN Enable)
{
    g_AntiVmDetectionEnabled = Enable;
    
    if (Enable) {
        DbgPrint("[HV] Anti-VM detection ENABLED\n");
        DbgPrint("[HV]   - CPUID: Hiding VMX/SVM/Hypervisor bits\n");
        DbgPrint("[HV]   - MSR: Filtering virtualization MSRs\n");
        DbgPrint("[HV]   - RDTSC: Compensating VM Exit overhead\n");
    } else {
        DbgPrint("[HV] Anti-VM detection DISABLED\n");
    }
}

/*
 * 获取反虚拟化检测状态
 */
BOOLEAN HvGetAntiVmDetection(VOID)
{
    return g_AntiVmDetectionEnabled;
}

/*
 * 重置 TSC 偏移
 */
VOID HvResetTscOffset(VOID)
{
    ULONG i;
    
    for (i = 0; i < MAX_CPU_COUNT; i++) {
        g_TscOffset[i] = 0;
        g_LastVmExitTsc[i] = 0;
    }
    
    DbgPrint("[HV] TSC offsets reset\n");
}
