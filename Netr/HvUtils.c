/*
 * HvUtils.c - Hypervisor 工具函数实现
 */

#include "HvUtils.h"
#include "HvCompat.h"

// P122: 全 driver DbgPrint → GUI ring
#define HV_TRACE_THIS_CAT HV_TRACE_CAT_UTIL
#include "HvTrace.h"

// ==================== OS 版本全局 (DriverEntry 早期初始化) ====================
ULONG g_HvOsBuildNumber  = 19041;  // Win10 1903 fallback
ULONG g_HvOsMajorVersion = 10;
ULONG g_HvOsMinorVersion = 0;

NTSYSAPI NTSTATUS NTAPI RtlGetVersion(_Out_ PRTL_OSVERSIONINFOW lpVersionInformation);

NTSTATUS HvUtilsInitializeOsVersion(VOID)
{
    RTL_OSVERSIONINFOW osInfo = { 0 };
    NTSTATUS status;

    osInfo.dwOSVersionInfoSize = sizeof(osInfo);
    status = RtlGetVersion(&osInfo);

    if (NT_SUCCESS(status)) {
        g_HvOsBuildNumber  = osInfo.dwBuildNumber;
        g_HvOsMajorVersion = osInfo.dwMajorVersion;
        g_HvOsMinorVersion = osInfo.dwMinorVersion;
        DbgPrint("[HV-Util] OS Version: %lu.%lu Build %lu\n",
                 g_HvOsMajorVersion, g_HvOsMinorVersion, g_HvOsBuildNumber);
    } else {
        DbgPrint("[HV-Util] RtlGetVersion failed (0x%08X), using fallback %lu.%lu Build %lu\n",
                 status, g_HvOsMajorVersion, g_HvOsMinorVersion, g_HvOsBuildNumber);
    }
    return status;
}

// ==================== System CR3 探测 (Win11 KVAS 兼容) ====================
//
// 核心问题: Win11 24H2 启用 KVAS (Kernel Virtual Address Shadowing),
// __readcr3() 在 DriverEntry 上下文可能返回 trampoline shadow CR3 (只映射 OS
// 跳板子集),而非 System full CR3。把它写入 HOST_CR3 会导致 vmexit 切回 host
// 时 AsmVmExitHandler 代码页/VMM stack/Windows IDT 中的部分 vector handler
// 不在映射里 → host #PF → KiPageFault 自身也不在映射里 → 嵌套 #PF →
// triple fault → 12 CPU 全卡死无 dump (这正是用户报告的 Win11 现象,Win10
// 不踩因为 KVAS shadow 设计在 Win10 上是 superset 不是 subset)。
//
// HyperDbg 范式: 走 PsInitialSystemProcess → KPROCESS.DirectoryTableBase。
// 这个值是 hardware-loaded System CR3,完整 kernel 映射,不受 KVAS 影子化影响。
//
// 偏移问题: HyperDbg 直接用 0x28 偏移(sizeof DISPATCHER_HEADER + sizeof
// LIST_ENTRY = 0x18 + 0x10)。这个偏移在 Win10 1903 - Win11 24H2 持续稳定。
// 即使个别版本漂移,我们用 __readcr3() 当 sanity 锚加偏移扫描兜底。
//
// 失败 fallback: 极端情况(早期 boot 阶段、PsInitialSystemProcess 未初始化、
// 偏移完全找不到)回退到 __readcr3()。打印警告供运维定位。

ULONG64 g_HvSystemCr3 = 0;             // 缓存解析结果,DriverEntry 后只读
static ULONG g_HvDtbProbedOffset = 0;  // 探到的真实 KPROCESS.DirectoryTableBase 偏移

//
// 验证 CR3 候选值是否合理:
//   - 非 0
//   - 高 12 位 (bit 52..63) 为 0 (物理地址 ≤ 52 位)
//   - 低 12 位除 PCID (bit 0..11) 外应为 0,实际 CR3 物理页对齐
//   - 不等于 user-space VA (高 bit47 不能是 1)
//
static BOOLEAN HvUtilsCr3IsPlausible(ULONG64 Cr3Candidate)
{
    if (Cr3Candidate == 0) return FALSE;

    // 高 12 位必须为 0 (Intel SDM Vol 3 4.5: CR3 物理地址 ≤ MAXPHYADDR ≤ 52)
    if (Cr3Candidate & 0xFFF0000000000000ULL) return FALSE;

    // CR3 不能是 kernel VA (典型 kernel VA 高 16 bit 全 1)
    if ((Cr3Candidate >> 47) == 0x1FFFFULL) return FALSE;

    // 物理基址应至少在 4KB 页帧 (bit 12+) 上,且不能是 PFN=0 (低物理页通常是 BIOS)
    ULONG64 pfn = (Cr3Candidate >> 12) & 0xFFFFFFFFFFULL;  // 40-bit PFN
    if (pfn < 0x100) return FALSE;  // 排除 < 1MB 的明显异常值

    return TRUE;
}

//
// 在 EPROCESS body 内扫描 DirectoryTableBase 真实偏移。
// 思路: __readcr3() 此时(DriverEntry, PASSIVE, System 上下文)的物理地址应该
// 与目标 KPROCESS.DirectoryTableBase 物理基址匹配(忽略低 12 bit 的 PCID)。
// 扫范围 0x20..0x60 (覆盖 Win10 - Win11 24H2 所有已知偏移)。
//
static ULONG HvUtilsProbeDtbOffset(PUCHAR EprocessBase)
{
    ULONG64 currentCr3 = __readcr3();
    ULONG64 currentBase = currentCr3 & ~0xFFFULL;  // 去 PCID 比 PFN
    ULONG offset;

    for (offset = 0x20; offset <= 0x60; offset += 8) {
        __try {
            ULONG64 candidate = *(ULONG64*)(EprocessBase + offset);
            if (!HvUtilsCr3IsPlausible(candidate)) continue;
            if ((candidate & ~0xFFFULL) == currentBase) {
                return offset;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            // 这个偏移读越界,继续找
        }
    }
    return 0;  // 找不到
}

//
// 初始化全局 g_HvSystemCr3。必须在 DriverEntry 早期、HvInitialize 之前调用。
// 失败时 g_HvSystemCr3 = __readcr3() (fallback)。
//
NTSTATUS HvUtilsInitializeSystemCr3(VOID)
{
    if (PsInitialSystemProcess == NULL) {
        g_HvSystemCr3 = __readcr3();
        DbgPrint("[HV-Util] WARN: PsInitialSystemProcess=NULL, fallback __readcr3()=0x%llX\n",
                 g_HvSystemCr3);
        return STATUS_UNSUCCESSFUL;
    }

    PUCHAR systemEprocess = (PUCHAR)PsInitialSystemProcess;

    // 步骤 1: 先尝试 HyperDbg 范式 0x28 偏移
    ULONG64 candidate028 = 0;
    __try {
        candidate028 = *(ULONG64*)(systemEprocess + 0x28);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        candidate028 = 0;
    }

    if (HvUtilsCr3IsPlausible(candidate028)) {
        g_HvSystemCr3 = candidate028;
        g_HvDtbProbedOffset = 0x28;
        DbgPrint("[HV-Util] System CR3 = 0x%llX (PsInitialSystemProcess+0x28, HyperDbg path)\n",
                 g_HvSystemCr3);
        return STATUS_SUCCESS;
    }

    // 步骤 2: 0x28 验证失败,扫描其他偏移
    ULONG probed = HvUtilsProbeDtbOffset(systemEprocess);
    if (probed != 0) {
        __try {
            ULONG64 candidate = *(ULONG64*)(systemEprocess + probed);
            if (HvUtilsCr3IsPlausible(candidate)) {
                g_HvSystemCr3 = candidate;
                g_HvDtbProbedOffset = probed;
                DbgPrint("[HV-Util] System CR3 = 0x%llX (PsInitialSystemProcess+0x%X, probed)\n",
                         g_HvSystemCr3, probed);
                return STATUS_SUCCESS;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
    }

    // 步骤 3: 都失败,fallback (但这条路径正是 Win11 KVAS 卡死的元凶,警告)
    g_HvSystemCr3 = __readcr3();
    DbgPrint("[HV-Util] ERROR: cannot locate DirectoryTableBase offset, fallback "
             "__readcr3()=0x%llX — Win11 KVAS will likely crash\n", g_HvSystemCr3);
    return STATUS_NOT_FOUND;
}

//
// 在 host setup 路径调用。返回应写入 HOST_CR3 的值。
// 调用方必须先调用过 HvUtilsInitializeSystemCr3()。
//
ULONG64 HvUtilsGetSystemCr3(VOID)
{
    if (g_HvSystemCr3 != 0) return g_HvSystemCr3;
    // 兜底: 没初始化就直接回 __readcr3() (但应该不会走到这条)
    return __readcr3();
}

// ==================== Host IDT (NMI/#MCE 隔离) ====================

DECLSPEC_ALIGN(16) HV_IDT_ENTRY_64 g_HvHostIdt[256] = { 0 };
volatile ULONG64 g_HvHostNmiCount = 0;
volatile ULONG64 g_HvHostMceCount = 0;
volatile ULONG64 g_HvHostDfCount  = 0;
volatile ULONG64 g_HvHostGpCount  = 0;

// (撤回 P133 generic catch-all stubs — 全部已删除, 共享 Windows IDT)

static VOID HvUtilsSetIdtGate(PHV_IDT_ENTRY_64 Entry, ULONG_PTR Handler, USHORT Selector, UCHAR IstIndex)
{
    Entry->OffsetLow    = (USHORT)(Handler & 0xFFFF);
    Entry->Selector     = Selector;
    Entry->IstIndex     = (UCHAR)(IstIndex & 0x7);
    Entry->Reserved1    = 0;
    Entry->Type         = 0xE;  // 64-bit interrupt gate
    Entry->Zero         = 0;
    Entry->Dpl          = 0;
    Entry->Present      = 1;
    Entry->OffsetMiddle = (USHORT)((Handler >> 16) & 0xFFFF);
    Entry->OffsetHigh   = (ULONG)((Handler >> 32) & 0xFFFFFFFF);
    Entry->Reserved2    = 0;
}

NTSTATUS HvUtilsInitializeHostIdt(VOID)
{
    UCHAR idtrBuf[10];
    __sidt(idtrBuf);
    ULONG64 windowsIdtBase = *(ULONG64*)(idtrBuf + 2);
    USHORT  windowsIdtLimit = *(USHORT*)(idtrBuf + 0);

    if (windowsIdtBase == 0 || windowsIdtLimit < 0xFF) {
        DbgPrint("[HV-Util] ERROR: __sidt returned suspicious IDT (base=0x%llX limit=0x%X)\n",
                 windowsIdtBase, windowsIdtLimit);
        return STATUS_UNSUCCESSFUL;
    }

    ULONG actualEntries = (windowsIdtLimit + 1) / sizeof(HV_IDT_ENTRY_64);
    if (actualEntries > 256) actualEntries = 256;

    __try {
        RtlCopyMemory(g_HvHostIdt, (PVOID)windowsIdtBase,
                      actualEntries * sizeof(HV_IDT_ENTRY_64));
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[HV-Util] ERROR: RtlCopyMemory from Windows IDT raised\n");
        return STATUS_UNSUCCESSFUL;
    }

    USHORT kernelCs = __readcs() & 0xF8;

    // IST 索引必须在 HV_USE_HOST_TSS_OVERRIDE=1 时由 host TSS 提供对应栈;
    // =0 时 IST=0 走当前 RSP (vmexit RSP, 也即 VmExitStack 中段) — 此时撞 0x1AA。
    // vector 13 (#GP) 总是装 AsmHostGpStub —— SafeMsr 路径依赖它接 rdmsr/wrmsr #GP。
    // 即使 IST=0, stub 是裸 asm 不调 Windows 不会撞 0x1AA。
#if HV_USE_HOST_TSS_OVERRIDE
    HvUtilsSetIdtGate(&g_HvHostIdt[2],  (ULONG_PTR)AsmHostNmiStub, kernelCs, 1);   // NMI  → IST1
    HvUtilsSetIdtGate(&g_HvHostIdt[8],  (ULONG_PTR)AsmHostDfStub,  kernelCs, 3);   // #DF  → IST3
    HvUtilsSetIdtGate(&g_HvHostIdt[13], (ULONG_PTR)AsmHostGpStub,  kernelCs, 3);   // #GP  → IST3 (与 #DF 共享, stub 自身不会再 #GP)
    HvUtilsSetIdtGate(&g_HvHostIdt[18], (ULONG_PTR)AsmHostMceStub, kernelCs, 2);   // #MC  → IST2
    DbgPrint("[HV-Util] HostIdt: NMI/IST1 #DF/IST3 #GP/IST3 #MC/IST2 (TSS override on)\n");
#else
    HvUtilsSetIdtGate(&g_HvHostIdt[2],  (ULONG_PTR)AsmHostNmiStub, kernelCs, 0);
    HvUtilsSetIdtGate(&g_HvHostIdt[13], (ULONG_PTR)AsmHostGpStub,  kernelCs, 0);
    HvUtilsSetIdtGate(&g_HvHostIdt[18], (ULONG_PTR)AsmHostMceStub, kernelCs, 0);
    DbgPrint("[HV-Util] HostIdt: NMI/IST=0 #GP/IST=0 #MC/IST=0 (TSS override off)\n");
#endif

    // (撤回 P133: 不再装 22 个 generic catch-all stubs)

    DbgPrint("[HV-Util] HostIdt initialized: base=0x%llX, NMI handler=0x%llX, MCE handler=0x%llX\n",
             (ULONG64)g_HvHostIdt,
             (ULONG_PTR)AsmHostNmiStub,
             (ULONG_PTR)AsmHostMceStub);
    return STATUS_SUCCESS;
}

// ==================== Host TSS + IST (0x1AA 全面修复) ====================

static HV_HOST_CPU_CTX g_HvHostCpuCtx[HV_MAX_CPUS] = { 0 };
static BOOLEAN         g_HvHostTssInitialized = FALSE;
volatile ULONG32       g_HvHostTssInitMask = 0;

PHV_HOST_CPU_CTX HvUtilsGetHostCpuCtx(ULONG CpuIndex)
{
    if (CpuIndex >= HV_MAX_CPUS) return NULL;
    if (!g_HvHostCpuCtx[CpuIndex].Initialized) return NULL;
    return &g_HvHostCpuCtx[CpuIndex];
}

// 改写复制 GDT 里 TR 描述符 (16 字节 system descriptor) 的 base 字段。
// AMD64 system descriptor 布局:
//   bytes 0-1   limit[15:0]
//   bytes 2-3   base[15:0]
//   byte  4     base[23:16]
//   byte  5     attributes (Type+S+DPL+P) — TSS busy bit 不动
//   byte  6     limit[19:16] + attributes2 (AVL+L+D+G)
//   byte  7     base[31:24]
//   bytes 8-11  base[63:32]
//   bytes 12-15 reserved (must be 0)
static VOID HvUtilsPatchTrDescBase(PVOID GdtBase, USHORT TrSelector, ULONG64 NewBase)
{
    USHORT idx = TrSelector & 0xFFF8;
    PUCHAR desc = (PUCHAR)GdtBase + idx;

    desc[2] = (UCHAR)(NewBase & 0xFF);
    desc[3] = (UCHAR)((NewBase >> 8) & 0xFF);
    desc[4] = (UCHAR)((NewBase >> 16) & 0xFF);
    desc[7] = (UCHAR)((NewBase >> 24) & 0xFF);
    *(PULONG)(desc + 8) = (ULONG)(NewBase >> 32);
    *(PULONG)(desc + 12) = 0;
}

// 改写 TR 描述符的 limit 字段为 NewLimit (20-bit, 单位由 G bit 决定)。
// 用 sizeof(HV_KTSS64)-1 = 0x67 写入, 满足 Intel SDM 26.3.1.2 最小 0x67 要求。
// G bit 保持不动 (Windows 原值通常 0 = byte granularity)。
static VOID HvUtilsPatchTrDescLimit(PVOID GdtBase, USHORT TrSelector, ULONG NewLimit)
{
    USHORT idx = TrSelector & 0xFFF8;
    PUCHAR desc = (PUCHAR)GdtBase + idx;

    desc[0] = (UCHAR)(NewLimit & 0xFF);
    desc[1] = (UCHAR)((NewLimit >> 8) & 0xFF);
    desc[6] = (UCHAR)((desc[6] & 0xF0) | ((NewLimit >> 16) & 0x0F));
}

static NTSTATUS HvUtilsAllocateHostTssForCurrentCpu(ULONG CpuIndex)
{
    if (CpuIndex >= HV_MAX_CPUS) return STATUS_INVALID_PARAMETER;

    PHV_HOST_CPU_CTX ctx = &g_HvHostCpuCtx[CpuIndex];
    if (ctx->Initialized) return STATUS_SUCCESS;

    ctx->IstNmiStack = HvAllocateNonPagedZeroed(HV_HOST_IST_STACK_SIZE, 'HTSI');
    ctx->IstMceStack = HvAllocateNonPagedZeroed(HV_HOST_IST_STACK_SIZE, 'HTSI');
    ctx->IstDfStack  = HvAllocateNonPagedZeroed(HV_HOST_IST_STACK_SIZE, 'HTSI');
    if (!ctx->IstNmiStack || !ctx->IstMceStack || !ctx->IstDfStack) {
        if (ctx->IstNmiStack) ExFreePoolWithTag(ctx->IstNmiStack, 'HTSI');
        if (ctx->IstMceStack) ExFreePoolWithTag(ctx->IstMceStack, 'HTSI');
        if (ctx->IstDfStack)  ExFreePoolWithTag(ctx->IstDfStack,  'HTSI');
        RtlZeroMemory(ctx, sizeof(*ctx));
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // IST 栈顶 = base + size - 0x10, 16 字节对齐 (x64 ABI)。
    ctx->Tss.Ist1 = ((ULONG64)ctx->IstNmiStack + HV_HOST_IST_STACK_SIZE - 0x10) & ~0xFULL;
    ctx->Tss.Ist2 = ((ULONG64)ctx->IstMceStack + HV_HOST_IST_STACK_SIZE - 0x10) & ~0xFULL;
    ctx->Tss.Ist3 = ((ULONG64)ctx->IstDfStack  + HV_HOST_IST_STACK_SIZE - 0x10) & ~0xFULL;
    // IoMapBase = sizeof(TSS) ≡ "no IO bitmap"
    ctx->Tss.IoMapBase = (USHORT)sizeof(HV_KTSS64);

    // 复制 Windows GDT 并改写 TR 描述符
    DESCRIPTOR_TABLE_REGISTER gdtr;
    _sgdt(&gdtr);
    ULONG64 winGdtBase = *(ULONG64*)&gdtr.Data[2];
    USHORT  winGdtLimit = *(USHORT*)&gdtr.Data[0];

    ULONG gdtSize = (ULONG)winGdtLimit + 1;
    ctx->HostGdt = HvAllocateNonPagedZeroed(gdtSize, 'HGDT');
    if (!ctx->HostGdt) {
        ExFreePoolWithTag(ctx->IstNmiStack, 'HTSI');
        ExFreePoolWithTag(ctx->IstMceStack, 'HTSI');
        ExFreePoolWithTag(ctx->IstDfStack,  'HTSI');
        RtlZeroMemory(ctx, sizeof(*ctx));
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    ctx->HostGdtLimit = winGdtLimit;

    __try {
        RtlCopyMemory(ctx->HostGdt, (PVOID)winGdtBase, gdtSize);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        ExFreePoolWithTag(ctx->HostGdt, 'HGDT');
        ExFreePoolWithTag(ctx->IstNmiStack, 'HTSI');
        ExFreePoolWithTag(ctx->IstMceStack, 'HTSI');
        ExFreePoolWithTag(ctx->IstDfStack,  'HTSI');
        RtlZeroMemory(ctx, sizeof(*ctx));
        return STATUS_UNSUCCESSFUL;
    }

    USHORT trSel = __readtr();
    HvUtilsPatchTrDescBase(ctx->HostGdt, trSel, (ULONG64)&ctx->Tss);
    HvUtilsPatchTrDescLimit(ctx->HostGdt, trSel, sizeof(HV_KTSS64) - 1);

    ctx->Initialized = TRUE;
    InterlockedOr((volatile LONG*)&g_HvHostTssInitMask, (LONG)(1U << CpuIndex));

    DbgPrint("[HV-Util] HostTss CPU %u: TSS=0x%llX IST1=0x%llX IST2=0x%llX IST3=0x%llX GDT=0x%llX (limit=0x%X) TR=0x%X\n",
             CpuIndex,
             (ULONG64)&ctx->Tss,
             ctx->Tss.Ist1, ctx->Tss.Ist2, ctx->Tss.Ist3,
             (ULONG64)ctx->HostGdt, ctx->HostGdtLimit, trSel);
    return STATUS_SUCCESS;
}

NTSTATUS HvUtilsInitializeHostTssAll(VOID)
{
    if (g_HvHostTssInitialized) return STATUS_SUCCESS;

#if !HV_USE_HOST_TSS_OVERRIDE
    DbgPrint("[HV-Util] HostTss init SKIPPED (HV_USE_HOST_TSS_OVERRIDE=0)\n");
    g_HvHostTssInitialized = TRUE;
    return STATUS_SUCCESS;
#else
    ULONG cpuCount = KeQueryActiveProcessorCount(NULL);
    if (cpuCount > HV_MAX_CPUS) cpuCount = HV_MAX_CPUS;

    for (ULONG i = 0; i < cpuCount; i++) {
        KAFFINITY mask = (KAFFINITY)1 << i;
        KeSetSystemAffinityThread(mask);
        // 双检 (同 HvCore.c:521-525 模式): affinity 切换可能在某些场景下不立即生效
        if (KeGetCurrentProcessorNumber() != i) {
            KeRevertToUserAffinityThread();
            DbgPrint("[HV-Util] HostTss CPU %u: affinity mismatch, skipped\n", i);
            continue;
        }
        (VOID)HvUtilsAllocateHostTssForCurrentCpu(i);
        KeRevertToUserAffinityThread();
    }

    g_HvHostTssInitialized = TRUE;
    return STATUS_SUCCESS;
#endif
}

VOID HvUtilsCleanupHostTssAll(VOID)
{
    if (!g_HvHostTssInitialized) return;

    for (ULONG i = 0; i < HV_MAX_CPUS; i++) {
        PHV_HOST_CPU_CTX ctx = &g_HvHostCpuCtx[i];
        if (!ctx->Initialized) continue;

        if (ctx->IstNmiStack) ExFreePoolWithTag(ctx->IstNmiStack, 'HTSI');
        if (ctx->IstMceStack) ExFreePoolWithTag(ctx->IstMceStack, 'HTSI');
        if (ctx->IstDfStack)  ExFreePoolWithTag(ctx->IstDfStack,  'HTSI');
        if (ctx->HostGdt)     ExFreePoolWithTag(ctx->HostGdt,     'HGDT');
        RtlZeroMemory(ctx, sizeof(*ctx));
    }

    g_HvHostTssInitMask = 0;
    g_HvHostTssInitialized = FALSE;
    DbgPrint("[HV-Util] HostTss cleanup done\n");
}

// ==================== 诊断快照 (IOCTL 0x8B0) ====================

extern volatile ULONG64 g_HvVmExitNmiCallbackCount;

VOID HvUtilsGetDiagSnapshot(PHV_DIAG_SNAPSHOT Out)
{
    if (!Out) return;

    RtlZeroMemory(Out, sizeof(*Out));

    Out->HostNmiCount      = g_HvHostNmiCount;
    Out->HostMceCount      = g_HvHostMceCount;
    Out->HostDfCount       = g_HvHostDfCount;
    Out->HostGpCount       = g_HvHostGpCount;
    Out->NmiCallbackCount  = g_HvVmExitNmiCallbackCount;
    Out->VmExitCounter     = g_VmExitCounter;
    Out->IstStackSize      = HV_HOST_IST_STACK_SIZE;
    Out->HostTssInitMask   = g_HvHostTssInitMask;
    Out->ActiveCpuCount    = KeQueryActiveProcessorCount(NULL);

    // CPU0 IST 栈基址供 RSP 落点比对 (足够代表性,其他核同 size 分配)
    PHV_HOST_CPU_CTX ctx0 = HvUtilsGetHostCpuCtx(0);
    if (ctx0) {
        Out->IstStackBase[0] = (ULONG64)ctx0->IstNmiStack;
        Out->IstStackBase[1] = (ULONG64)ctx0->IstMceStack;
        Out->IstStackBase[2] = (ULONG64)ctx0->IstDfStack;
    }

    // VcpuVirtualizedMask: 扫 g_HypervisorContext.VcpuData[].IsVirtualized
    if (g_HypervisorContext.VcpuData) {
        ULONG count = g_HypervisorContext.ProcessorCount;
        if (count > 32) count = 32;
        for (ULONG i = 0; i < count; i++) {
            if (g_HypervisorContext.VcpuData[i].IsVirtualized) {
                Out->VcpuVirtualizedMask |= (1U << i);
            }
        }
    }

    // BuildFlags
    ULONG32 flags = 0;
#if HV_USE_HOST_TSS_OVERRIDE
    flags |= HV_BUILDFLAG_HOST_TSS_OVERRIDE;
#endif
#if HV_USE_HOST_IDT_OVERRIDE
    flags |= HV_BUILDFLAG_HOST_IDT_OVERRIDE;
#endif
#if HV_USE_SYSTEM_CR3_FOR_HOST
    flags |= HV_BUILDFLAG_SYSTEM_CR3;
#endif
#if HV_DEBUG_KEEP_HOST_CR4_CET
    flags |= HV_BUILDFLAG_KEEP_HOST_CR4_CET;
#endif
#if defined(HV_VMEXIT_STACK_GUARD) && HV_VMEXIT_STACK_GUARD
    flags |= HV_BUILDFLAG_VMEXIT_STACK_GUARD;
#endif
#if HV_MINIMAL_MODE
    flags |= HV_BUILDFLAG_MINIMAL_MODE;
#endif
    Out->BuildFlags = flags;
}

/*
 * 检查CPU是否支持VMX
 */
BOOLEAN HvCheckVmxSupport(VOID)
{
    int cpuInfo[4];

    __cpuid(cpuInfo, 1);
    if (!(cpuInfo[2] & (1 << 5))) {
#if HV_FORCE_VMX_REGARDLESS_OF_HVPRESENT
        DbgPrint("[HV-Util] *** HV_FORCE_VMX=1 *** CPUID VMX bit5 hidden, forcing through.\n");
        // 不 return, 继续走 FEATURE_CONTROL 检查 + VMXON
#else
        return FALSE;
#endif
    }

    ULONG64 featureControl = 0;
    __try {
        featureControl = __readmsr(MSR_IA32_FEATURE_CONTROL);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
#if HV_FORCE_VMX_REGARDLESS_OF_HVPRESENT
        DbgPrint("[HV-Util] *** HV_FORCE_VMX=1 *** RDMSR FEATURE_CONTROL #GP, forcing through.\n");
        return TRUE;
#else
        return FALSE;
#endif
    }

    if (!(featureControl & 1)) {
        __try {
            __writemsr(MSR_IA32_FEATURE_CONTROL, featureControl | 5);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
#if HV_FORCE_VMX_REGARDLESS_OF_HVPRESENT
            DbgPrint("[HV-Util] *** HV_FORCE_VMX=1 *** WRMSR FEATURE_CONTROL #GP, forcing through.\n");
            return TRUE;
#else
            return FALSE;
#endif
        }
    }
    else if (!(featureControl & 4)) {
#if HV_FORCE_VMX_REGARDLESS_OF_HVPRESENT
        DbgPrint("[HV-Util] *** HV_FORCE_VMX=1 *** FEATURE_CONTROL locked w/o VMXON_OUTSIDE_SMX (=0x%llX), forcing through.\n", featureControl);
        return TRUE;
#else
        return FALSE;
#endif
    }

    return TRUE;
}

/*
 * 调整控制寄存器以满足VMX要求
 */
VOID HvAdjustControlRegisters(VOID)
{
    ULONG64 cr0 = __readcr0();
    ULONG64 cr4 = __readcr4();

    ULONG64 cr0_fixed0 = __readmsr(MSR_IA32_VMX_CR0_FIXED0);
    ULONG64 cr0_fixed1 = __readmsr(MSR_IA32_VMX_CR0_FIXED1);
    ULONG64 cr4_fixed0 = __readmsr(MSR_IA32_VMX_CR4_FIXED0);
    ULONG64 cr4_fixed1 = __readmsr(MSR_IA32_VMX_CR4_FIXED1);

    cr0 |= cr0_fixed0;
    cr0 &= cr0_fixed1;
    __try { __writecr0(cr0); } __except (EXCEPTION_EXECUTE_HANDLER) { }

    cr4 |= cr4_fixed0;
    cr4 &= cr4_fixed1;
    cr4 |= (1ULL << 13);  // VMXE
    __try { __writecr4(cr4); } __except (EXCEPTION_EXECUTE_HANDLER) { }
}

/*
 * 分配4KB对齐的内存
 */
PVOID HvAllocateAlignedMemory(SIZE_T Size, PHYSICAL_ADDRESS* PhysicalAddress)
{
    PVOID virtualAddress;

    virtualAddress = MmAllocateContiguousMemory(Size, (PHYSICAL_ADDRESS) { .QuadPart = -1LL });

    if (virtualAddress) {
        RtlZeroMemory(virtualAddress, Size);
        *PhysicalAddress = MmGetPhysicalAddress(virtualAddress);
    }

    return virtualAddress;
}

/*
 * 调整VMX控制字段
 */
ULONG HvAdjustVmxControls(ULONG Msr, ULONG RequestedValue)
{
    ULONG64 msrValue;
    ULONG allowed0, allowed1;

    msrValue = __readmsr(Msr);
    allowed0 = (ULONG)(msrValue & 0xFFFFFFFF);
    allowed1 = (ULONG)(msrValue >> 32);

    RequestedValue |= allowed0;
    RequestedValue &= allowed1;

    return RequestedValue;
}

/*
 * 获取段描述符
 */
VOID HvGetSegmentDescriptor(PSEGMENT_SELECTOR Selector, USHORT SegmentSelector, PUCHAR GdtBase)
{
    PSEGMENT_DESCRIPTOR descriptor;
    ULONG64 base;

    if (!Selector || !GdtBase) {
        return;
    }

    // 清零
    Selector->Selector = SegmentSelector;
    Selector->Base = 0;
    Selector->Limit = 0;
    Selector->AccessRights = 0;

    // 检查是否为空选择子
    if ((SegmentSelector & 0xFFF8) == 0) {
        Selector->AccessRights = 0x10000;  // Unusable
        return;
    }

    // 获取描述符
    descriptor = (PSEGMENT_DESCRIPTOR)(GdtBase + (SegmentSelector & 0xFFF8));

    // 计算基地址
    base = descriptor->Base0 | ((ULONG64)descriptor->Base1 << 16) | ((ULONG64)descriptor->Base2 << 24);

    // 检查是否为系统段（TSS等），系统段有扩展的基地址
    if (!(descriptor->Attributes1 & 0x10)) {
        // 系统段：64位模式下有16字节描述符
        // 字节 8-11 包含 Base[63:32]
        PULONG highBase = (PULONG)(((PUCHAR)descriptor) + 8);
        base |= ((ULONG64)*highBase) << 32;
    }

    Selector->Base = base;

    // 计算限制
    Selector->Limit = descriptor->Limit0 | ((ULONG)(descriptor->Attributes2 & 0x0F) << 16);
    if (descriptor->Attributes2 & 0x80) {
        // 粒度位设置，限制以4KB为单位
        Selector->Limit = (Selector->Limit << 12) | 0xFFF;
    }

    // 访问权限 - P2-4 (HyperDbg 范式): 优先用 LAR 指令
    //
    // LAR 内置 selector 可达性检查 (segment present、不超 GDT 范围、DPL/RPL),
    // 失败时 ZF=0 → AsmGetAccessRights 返回 0,我们标 Unusable。
    // 成功时 LAR 结果 bits 8-15 = Type+S+DPL+P, bits 20-23 = AVL+L+D+G,
    //   >> 8 后:bits 0-7 = Type+S+DPL+P, bits 12-15 = AVL+L+D+G,
    //   正好匹配 VMCS GUEST_xx_ACCESS_RIGHTS 字段 layout。
    //
    // Fallback (手动拼 byte 5/6):保留备用,LAR 失败但描述符 byte 仍可读时
    // (例如 selector valid 但 LAR 异常被 IDT 拦截) 用旧路径兜底。
    {
        ULONG64 larResult = AsmGetAccessRights(SegmentSelector);
        if (larResult != 0) {
            Selector->AccessRights = (ULONG)(larResult >> 8) & 0xF0FF;
        } else {
            // LAR 失败 → fallback 到手动拼接
            Selector->AccessRights =
                descriptor->Attributes1 |
                ((descriptor->Attributes2 & 0xF0) << 8);
            Selector->AccessRights &= 0xF0FF;
            // 同时标 Unusable,vmlaunch 不 validate 这个段
            Selector->AccessRights |= 0x10000;
        }
    }
}

/*
 * 获取段访问权限
 */
ULONG HvGetSegmentAccessRights(USHORT SegmentSelector, PUCHAR GdtBase)
{
    SEGMENT_SELECTOR selector = { 0 };
    HvGetSegmentDescriptor(&selector, SegmentSelector, GdtBase);
    return selector.AccessRights;
}

/*
 * VMCS读取
 */
ULONG HvVmRead(ULONG Field)
{
    SIZE_T value = 0;
    __vmx_vmread(Field, &value);
    return (ULONG)value;
}

/*
 * VMCS写入
 */
VOID HvVmWrite(ULONG Field, ULONG64 Value)
{
    __vmx_vmwrite(Field, Value);
}

// ==================== AMD SVM 支持函数 ====================

/*
 * 检查CPU是否支持SVM
 * 
 * 检查步骤：
 * 1. CPUID.80000001H.ECX[2] = SVM 位
 * 2. MSR_VM_CR.SVMDIS = 0 (SVM 未被禁用)
 */
BOOLEAN SvmCheckSupport(VOID)
{
    int cpuInfo[4];
    ULONG64 vmCr;

    // 检查是否支持扩展 CPUID
    __cpuid(cpuInfo, 0x80000000);
    if ((ULONG)cpuInfo[0] < 0x80000001) {
        DbgPrint("[SVM] Extended CPUID not supported\n");
        return FALSE;
    }

    // 检查 SVM 位 (CPUID.80000001H.ECX[2])
    __cpuid(cpuInfo, 0x80000001);
    if (!(cpuInfo[2] & (1 << 2))) {
        DbgPrint("[SVM] SVM not supported (CPUID.80000001H.ECX[2] = 0)\n");
        return FALSE;
    }

    // 检查 SVM 是否被 BIOS 禁用
    __try {
        vmCr = __readmsr(MSR_AMD_VM_CR);
        if (vmCr & VM_CR_SVMDIS) {
            DbgPrint("[SVM] SVM is disabled in BIOS (VM_CR.SVMDIS = 1)\n");
            
            // 检查是否可以解锁
            if (vmCr & VM_CR_LOCK) {
                DbgPrint("[SVM] SVM is locked and cannot be enabled\n");
                return FALSE;
            }
            
            // 尝试启用 SVM（清除 SVMDIS 位）
            DbgPrint("[SVM] Attempting to enable SVM...\n");
            vmCr &= ~VM_CR_SVMDIS;
            __writemsr(MSR_AMD_VM_CR, vmCr);
            
            // 验证是否成功
            vmCr = __readmsr(MSR_AMD_VM_CR);
            if (vmCr & VM_CR_SVMDIS) {
                DbgPrint("[SVM] Failed to enable SVM\n");
                return FALSE;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[SVM] Exception reading VM_CR MSR\n");
        return FALSE;
    }

    DbgPrint("[SVM] SVM is supported and enabled\n");
    return TRUE;
}

// 注意: SvmCheckNptSupport 已移至 HvNpt.c

/*
 * 调整控制寄存器以满足SVM要求
 * 
 * 主要是设置 EFER.SVME 位
 */
VOID SvmAdjustControlRegisters(VOID)
{
    ULONG64 efer;

    __try {
        // 读取 EFER
        efer = __readmsr(MSR_IA32_EFER);
        
        // 设置 SVME 位 (bit 12)
        if (!(efer & EFER_SVME)) {
            efer |= EFER_SVME;
            __writemsr(MSR_IA32_EFER, efer);
            DbgPrint("[SVM] EFER.SVME enabled\n");
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[SVM] Exception setting EFER.SVME\n");
    }
}
