/*
 * HvUtils.h - Hypervisor 工具函数声明
 */

#ifndef _HV_UTILS_H_
#define _HV_UTILS_H_

#include "HvTypes.h"

// ==================== Intel VMX 支持 ====================

// VMX 支持检查
BOOLEAN HvCheckVmxSupport(VOID);

// 控制寄存器调整 (Intel VMX)
VOID HvAdjustControlRegisters(VOID);

// VMX 控制字段调整
ULONG HvAdjustVmxControls(ULONG Msr, ULONG RequestedValue);

// VMCS 读写
ULONG HvVmRead(ULONG Field);
VOID HvVmWrite(ULONG Field, ULONG64 Value);

// ==================== AMD SVM 支持 ====================

// SVM 支持检查
BOOLEAN SvmCheckSupport(VOID);

// SVM 功能检测 (实现在 HvNpt.c 中，声明在 HvNpt.h 中)
// BOOLEAN SvmCheckNptSupport(VOID);

// 控制寄存器调整 (AMD SVM)
VOID SvmAdjustControlRegisters(VOID);

// ==================== 公共工具函数 ====================

// 内存分配
PVOID HvAllocateAlignedMemory(SIZE_T Size, PHYSICAL_ADDRESS* PhysicalAddress);

// 段描述符处理
VOID HvGetSegmentDescriptor(PSEGMENT_SELECTOR Selector, USHORT SegmentSelector, PUCHAR GdtBase);
ULONG HvGetSegmentAccessRights(USHORT SegmentSelector, PUCHAR GdtBase);

// P2-4 (HyperDbg 范式): LAR-based access rights
// 返回 LAR 指令原始结果; ZF=0 (selector 不可达) 时返回 0。
// VMCS access-rights 字段格式 = (AsmGetAccessRights(sel) >> 8)。
extern ULONG64 AsmGetAccessRights(USHORT Selector);

// ==================== OS 版本探测 (全局, DriverEntry 早期初始化) ====================
//
// 历史: 项目里只有 HvNetworkHook.c:218 一处调 RtlGetVersion, 结果埋在 net-hook 模块内.
// 其他模块需要 OS 版本时只能自己再调一次 RtlGetVersion 或硬编码偏移。
// 全局化后, DriverEntry 调一次, 全模块共享 source of truth.

extern ULONG g_HvOsBuildNumber;     // Windows Build (e.g. 19041, 22631, 26100)
extern ULONG g_HvOsMajorVersion;    // 主版本 (Win10/11 都是 10)
extern ULONG g_HvOsMinorVersion;    // 次版本

// 初始化全局 OS 版本; 失败时使用 Win10 19041 fallback
// 必须在 DriverEntry 早期 (HvInitialize 之前) 调用
NTSTATUS HvUtilsInitializeOsVersion(VOID);

// ==================== System CR3 (Win11 KVAS 兼容) ====================
//
// __readcr3() 在 Win11 24H2 KVAS 上可能返回 trampoline shadow CR3 (子集映射),
// 写入 HOST_CR3 会导致 vmexit 后 host #PF → triple fault → 12 CPU 全卡死无 dump。
// 必须从 PsInitialSystemProcess->DirectoryTableBase 取 hardware-loaded System CR3。

extern ULONG64 g_HvSystemCr3;

// DriverEntry 早期调用; 解析 PsInitialSystemProcess 的 DirectoryTableBase 字段
// 偏移(尝试 0x28,失败扫 0x20..0x60),验证后填 g_HvSystemCr3。
// 必须在 HvInitialize / VMCS setup 之前调用。
NTSTATUS HvUtilsInitializeSystemCr3(VOID);

// 返回写入 HOST_CR3 的安全值。HvSetupVmcsHostState 调用。
ULONG64 HvUtilsGetSystemCr3(VOID);

// ==================== Host IDT (vmx-root 专用 NMI/#MCE handler) ====================
//
// 共享 Windows IDT (HOST_IDTR_BASE = __sidt()) 让 NMI / #MCE 在 vmx-root 模式
// 落到 KiNmiInterrupt / KiMceTrap, 但此时 RSP=VMM stack、KPRCB.Prcb 内部状态
// 是 guest 离开瞬间的 → Win11 24H2 KCFG + 严苛 GS:[KPCR] 检查必崩, 12 CPU
// 全 triple fault 无 dump。HyperDbg 范式: 独立 HostIdt, NMI/#PF/#GP/#MCE
// 4 个 vector → 自定汇编 stub, 不让 Windows handler 跑在 VMM 上下文。
//
// Netr 最小实现: 一份全局 g_HvHostIdt (4KB, 256 entries) 全 CPU 共享, 拷贝
// 当前 Windows IDT 后覆盖 vector 2 (NMI)、18 (#MC) 指向 AsmHostNmiStub /
// AsmHostMceStub。这两个 stub 只做计数 + iretq, 不能在 vmx-root 跑 Windows
// handler 的复杂逻辑。其他 vector (#PF/#GP) 暂留 Windows handler — 走 P0-1
// HOST_CR3 修复后应不再触发, 真触发也比静默 triple fault 强 (会进 KiPageFault
// 至少留 BSOD 痕迹)。

#pragma pack(push, 1)
typedef struct _HV_IDT_ENTRY_64 {
    USHORT OffsetLow;
    USHORT Selector;
    UCHAR  IstIndex : 3;
    UCHAR  Reserved1 : 5;
    UCHAR  Type : 4;
    UCHAR  Zero : 1;
    UCHAR  Dpl : 2;
    UCHAR  Present : 1;
    USHORT OffsetMiddle;
    ULONG  OffsetHigh;
    ULONG  Reserved2;
} HV_IDT_ENTRY_64, *PHV_IDT_ENTRY_64;
#pragma pack(pop)

extern HV_IDT_ENTRY_64 g_HvHostIdt[256];

// 计数器, 用于诊断 host NMI 被 stub 吞掉的次数
extern volatile ULONG64 g_HvHostNmiCount;
extern volatile ULONG64 g_HvHostMceCount;
extern volatile ULONG64 g_HvHostDfCount;
extern volatile ULONG64 g_HvHostGpCount;

// DriverEntry 早期调用 (在 HvUtilsInitializeSystemCr3 之后, HvInitialize 之前):
// 拷贝 Windows IDT 到 g_HvHostIdt, 覆盖 vector 2 (NMI) / 18 (#MC) 指向 stub。
NTSTATUS HvUtilsInitializeHostIdt(VOID);

// 汇编 stub (定义在 AsmVmx.asm)
extern VOID AsmHostNmiStub(VOID);
extern VOID AsmHostMceStub(VOID);
extern VOID AsmHostDfStub(VOID);
extern VOID AsmHostGpStub(VOID);

// 2026-06-16: vmx-root 安全 MSR 读写 (替换 __readmsr/__writemsr 的透传路径)。
// 内部 #GP 时由 AsmHostGpStub 拦截。GpRaised/返回值告诉调用者是否 #GP, 调用者
// 把 #GP 注入回 guest 使行为与 bare metal 一致 (反 VM 透明化)。
extern ULONG64 AsmSafeReadMsr(ULONG32 Msr, BOOLEAN* GpRaised);
extern BOOLEAN AsmSafeWriteMsr(ULONG32 Msr, ULONG32 Lo, ULONG32 Hi);

// ==================== Host TSS + IST 栈 (0x1AA 全面修复) ====================
//
// 2026-06-16: bugcheck 0x1AA EXCEPTION_ON_INVALID_STACK 根因 = host 收 NMI/#DF/#MC
// 时 RSP (=VmExitStack 中段) 不在 Windows 任何已登记栈区间 (KTHREAD.Stack /
// KPRCB.IsrStack/DpcStack / TSS.IST[1..7])。Win11 24H2 的
// RtlpGetStackLimits 校验失败立即 0x1AA。
//
// 修复:per-CPU 独立 host TSS + 三段 IST 栈 (NMI/IST1, #MC/IST2, #DF/IST3) +
// 复制 GDT 改写 TR 描述符 base 指向我们的 TSS。VM-exit 时硬件按 HOST_GDTR_BASE
// 查 GDT,按 HOST_TR_SELECTOR 取 TR 描述符,看到 TSS base 已是我们的 TSS;
// NMI/#DF/#MC 走 IST 强制切栈到我们登记的栈,栈区间被 stub 全程独占,Windows
// 的 RtlpGetStackLimits 根本跑不到 (stub 是 lock inc + iretq, 不进 Windows)。
//
// Windows 原 GDT / IDT / TSS 完全不改, guest 视角无任何变化。

#define HV_MAX_CPUS  64

typedef struct _HV_HOST_CPU_CTX {
    PVOID     IstNmiStack;     // vector 2  → IST1
    PVOID     IstMceStack;     // vector 18 → IST2
    PVOID     IstDfStack;      // vector 8  → IST3
    HV_KTSS64 Tss;             // per-CPU host TSS (Ist1/2/3 填 IST 栈顶)
    PVOID     HostGdt;         // 复制的 Windows GDT, TR 描述符 base 改写为 &Tss
    USHORT    HostGdtLimit;    // Windows GDT 原 limit (拷贝原样)
    BOOLEAN   Initialized;
} HV_HOST_CPU_CTX, *PHV_HOST_CPU_CTX;

// DriverEntry 调用: 给所有 CPU 串行分配 TSS+IST+GDT。
// 内部走 KeSetSystemAffinityThread + KeGetCurrentProcessorNumber 双检 (与
// HvCore.c:519 同模式),确保 __readgdt / TR base 取自目标 CPU。
NTSTATUS HvUtilsInitializeHostTssAll(VOID);

// DriverUnload 调用: 释放所有 per-CPU TSS+IST+GDT。
// 必须在 HvCleanup (退出 VMX) 之后调用 —— vCPU 仍在 root 时释放会让 vmexit
// 异常入栈访问已释放页 → triple fault。
VOID HvUtilsCleanupHostTssAll(VOID);

// HvSetupVmcsHostState 调用: 取 per-CPU TSS+GDT 指针。
PHV_HOST_CPU_CTX HvUtilsGetHostCpuCtx(ULONG CpuIndex);

// ==================== 诊断快照 (用户态 IOCTL 0x8B0 可读) ====================
//
// 实机无 dmesg / 无 dump 时定位 0x1AA 的关键: 把所有计数器和 per-CPU 初始化状态
// 打包成一个结构, 用户态崩溃前调 IOCTL 拿到即可判断 host TSS 是否生效、是否高频
// NMI、是否某核 vmlaunch 失败等。

typedef struct _HV_DIAG_SNAPSHOT {
    ULONG64 HostNmiCount;          // g_HvHostNmiCount
    ULONG64 HostMceCount;          // g_HvHostMceCount
    ULONG64 HostDfCount;           // g_HvHostDfCount
    ULONG64 HostGpCount;           // g_HvHostGpCount (SafeMsr stub 接住的 #GP 次数)
    ULONG64 NmiCallbackCount;      // g_HvVmExitNmiCallbackCount
    ULONG64 VmExitCounter;         // g_VmExitCounter
    ULONG64 IstStackBase[3];       // CPU0 的 IST1/2/3 栈基址 (用于 dump 对照 RSP 落点)
    ULONG64 IstStackSize;          // HV_HOST_IST_STACK_SIZE
    ULONG32 HostTssInitMask;       // bit N = CPU N 的 TSS 初始化成功
    ULONG32 VcpuVirtualizedMask;   // bit N = CPU N 的 vmlaunch 成功
    ULONG32 ActiveCpuCount;        // KeQueryActiveProcessorCount(NULL)
    ULONG32 BuildFlags;            // 见 HV_BUILDFLAG_* 位定义
} HV_DIAG_SNAPSHOT, *PHV_DIAG_SNAPSHOT;

#define HV_BUILDFLAG_HOST_TSS_OVERRIDE  (1U << 0)
#define HV_BUILDFLAG_HOST_IDT_OVERRIDE  (1U << 1)
#define HV_BUILDFLAG_SYSTEM_CR3         (1U << 2)
#define HV_BUILDFLAG_KEEP_HOST_CR4_CET  (1U << 3)
#define HV_BUILDFLAG_VMEXIT_STACK_GUARD (1U << 4)
#define HV_BUILDFLAG_MINIMAL_MODE       (1U << 5)

extern volatile ULONG32 g_HvHostTssInitMask;

// 把当前诊断状态拷贝到调用者缓冲 (Out 必须非 NULL,调用方负责对齐)。
VOID HvUtilsGetDiagSnapshot(PHV_DIAG_SNAPSHOT Out);

// 是否 Win11 24H2+ (Build >= 26100)
// 24H2 引入 KVAS asymmetric superset shadow, CR4.CET 默认开等行为差异
static __forceinline BOOLEAN HvUtilsIsWin11_24H2OrLater(VOID)
{
    return g_HvOsBuildNumber >= 26100;
}

// 是否 Win11 (Build >= 22000)
static __forceinline BOOLEAN HvUtilsIsWin11OrLater(VOID)
{
    return g_HvOsBuildNumber >= 22000;
}

#endif // _HV_UTILS_H_
