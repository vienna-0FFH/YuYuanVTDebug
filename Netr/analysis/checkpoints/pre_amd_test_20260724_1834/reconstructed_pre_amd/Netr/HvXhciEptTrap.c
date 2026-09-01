/*
 * HvXhciEptTrap.c — Item 2: EPT read trap on xHCI USBSTS/IMAN
 *
 * 见 HvXhciEptTrap.h 顶部注释了解整体思路。
 *
 * 关键决策:
 *   - 我们的 R 位翻转操作发生在 PT entry (4KB 颗粒度),不是 PDE
 *     (避免改 PDE 影响 2MB 区域)。所以启动期必须先把包 USBSTS/IMAN 的
 *     2MB PDE 拆分成 512 个 4KB PT entry,然后清单个 PT entry 的 R 位。
 *
 *   - 每个 vCPU 有独立 EPT，因此每核保留自己的 split PT/leaf；Arm、violation
 *     和 MTF 只修改当前 `VCPU_DATA.ProcessorNumber` 对应的 leaf。
 *
 *   - 新分配的 PT 先在每个 EptTables->SplitPt[] 中登记并验证 512 项一致，
 *     全部成功后才原子发布 PDE；任一 CPU 失败会跨核恢复 PDE、撤销登记并释放。
 *
 *   - GPR diff 方式获取 MOV 目的寄存器:不需要 x86 指令解码。
 *     trade-off: 如果 MMIO 读的指令是 `TEST [mem], r` / `CMP [mem], r`
 *     这种不写寄存器的指令,我们 diff 不到目的 —— 这种情况 fall through
 *     不 OR-in,counter 不动,ISR 还是 fast-bail。但 xhci.sys 99% 是
 *     用 `mov eax, [usbsts]` 形式读的,影响极小。
 *
 *   - 短时窗口:每次 Arm 把 g_PendingIsrReads 设 16。这样一次 ISR pass
 *     里 USBSTS+IMAN 各读 2-4 次(进入/退出/clear-IP),16 个余量够。
 *     超过 16 次就关 trap,避免长期 trap 导致 BAR 上其他寄存器 (PortSc)
 *     被异常拦截。
 *
 * IRQL 约束:
 *   - HvXhciEptTrapInitialize: PASSIVE_LEVEL (HvCoreInitialize 末尾,
 *     必须在 g_HypervisorContext.IsActive=TRUE 之后,因为要遍历每个
 *     VCPU 的 EptTables 并改 PDE)。INVEPT 必须走 EptInveptAllContexts
 *     (IPI+VMCALL) 而非裸 AsmInveptAllContexts —— 调用方在 guest 模式。
 *   - HvXhciEptTrapShutdown: PASSIVE_LEVEL (同 Init,跨核 INVEPT 走 IPI)
 *   - HvXhciEptTrapArm: VMX root (从 HvUsbXhciTryDeliverMsi 调,只 INVEPT
 *     当前 CPU 即可,因为 MSI 也走当前 CPU 的 VMENTRY_INTERRUPTION_INFO)
 *   - HvXhciEptTrapHandleViolation/HandleMtf: VMX root, IPI_LEVEL
 */

#include "HvXhciEptTrap.h"
#include "HvCore.h"
#include "HvUsbXhci.h"
#include "HvNested.h"
#include "EptHook.h"   // EPT_VIOLATION_*, EPT permissions
#include "HvVmExit.h"  // 内部 helper 声明

// P122: 全 driver DbgPrint → GUI ring
#define HV_TRACE_THIS_CAT HV_TRACE_CAT_USB
#include "HvTrace.h"

extern UCHAR AsmInveptAllContexts(VOID);

#define HV_XHCI_TRAP_MAX_PAGES   2     // USBSTS_GPA 和 IMAN_GPA 在同一/不同 4K
#define HV_XHCI_TRAP_MAX_CPUS    64
#define HV_XHCI_TRAP_INITIAL_READS 16  // Arm 时设的 counter 上限

// 同 HvUsbXhci.c 的 log 风格 — 启动期 DbgPrint 可以,root 模式禁用
#define TRAP_LOG(fmt, ...) DbgPrint("[XHCI-TRAP] " fmt "\n", ##__VA_ARGS__)

// ============================================================
// 全局状态
// ============================================================

typedef struct _HV_XHCI_TRAP_PAGE {
    BOOLEAN  Valid;              // FALSE 表示空槽
    ULONG64  PageGpa;            // 4KB 对齐的 GPA
    ULONG    PtIndex;            // PageGpa 在所在 PT 里的 index (0..511)

    // Every vCPU owns an independent EPT.  Retain the leaf for every active
    // vCPU; using CPU 0's PT pointer on another CPU modifies the wrong EPT.
    PEPT_PTE Pte[HV_XHCI_TRAP_MAX_CPUS];

    // 该页里需要被"假冒"的两个偏移 — 通常 USBSTS 是 CapLen+4 在 OpBase,
    // IMAN 是 RtsOff+0x20 在 RtBase。两个偏移可能落在不同 PageGpa 上,
    // 也可能落在同一个 (RtsOff 小时)。每个 trap page 记录"在这个页里
    // 哪个偏移要伪 EINT、哪个偏移要伪 IP"。
    ULONG    UsbstsOffset;       // 0xFFFFFFFF 表示该页内没有 USBSTS
    ULONG    ImanOffset;         // 0xFFFFFFFF 表示该页内没有 IMAN
} HV_XHCI_TRAP_PAGE, *PHV_XHCI_TRAP_PAGE;

typedef struct _HV_XHCI_TRAP_CPU_SPLIT {
    PEPT_TABLES EptTables;
    PEPT_PDE Pde;
    PEPT_PTE Pt;
    PHYSICAL_ADDRESS PtPhysical;
    ULONG64 OriginalPdeValue;
    ULONG RegistrationIndex;
    BOOLEAN Allocated;
    BOOLEAN PdePublished;
} HV_XHCI_TRAP_CPU_SPLIT, *PHV_XHCI_TRAP_CPU_SPLIT;

typedef struct _HV_XHCI_TRAP_REGION {
    BOOLEAN Valid;
    ULONG64 RegionGpa;
    HV_XHCI_TRAP_CPU_SPLIT Cpu[HV_XHCI_TRAP_MAX_CPUS];
} HV_XHCI_TRAP_REGION, *PHV_XHCI_TRAP_REGION;

#define TRAP_OFFSET_NONE  0xFFFFFFFFUL

typedef struct _HV_XHCI_TRAP_MTF_STATE {
    volatile LONG  Active;                       // 0 = idle, 1 = waiting for MTF
    ULONG          PageIndex;                    // 触发 trap 的页 in g_TrapPages[]
    ULONG          OffsetInPage;                 // qual & 0xFFF
    GUEST_CONTEXT  GprSnapshot;                  // 进 trap 前所有 GPR
} HV_XHCI_TRAP_MTF_STATE, *PHV_XHCI_TRAP_MTF_STATE;

static volatile LONG       g_Initialized = 0;
// User-controlled enable flag. Default OFF so a freshly-loaded driver does NOT
// auto-arm the trap on first MSI — that lets users test the rest of the input
// chain (Items 1/3/4) in isolation, and opt in to Item 2 once they've confirmed
// the basics work. Toggled via HvXhciEptTrapSetUserEnabled (IOCTL).
static volatile LONG       g_UserEnabled = 0;
// Set in Initialize after we confirm CPU_BASED_MONITOR_TRAP_FLAG is in the
// allowed-1 mask of IA32_VMX_PROCBASED_CTLS. Without MTF we can't single-step
// after restoring R=1, so the trap design fundamentally won't work; if 0,
// the user-enable IOCTL refuses.
static BOOLEAN             g_MtfSupported = FALSE;
static HV_XHCI_TRAP_PAGE   g_TrapPages[HV_XHCI_TRAP_MAX_PAGES];
static ULONG               g_TrapPageCount = 0;
static HV_XHCI_TRAP_REGION g_TrapRegions[HV_XHCI_TRAP_MAX_PAGES];
static ULONG               g_TrapRegionCount = 0;

// 短时 trap 窗口的剩余读次数。Arm 设 N, 每次成功"假冒读"递减,降到 0
// 自动关 trap (R=1)。 用 volatile LONG 让多核观察一致。
static volatile LONG       g_PendingIsrReads[HV_XHCI_TRAP_MAX_CPUS];

// per-CPU MTF state (单步指令完成后的回 callback 上下文)
static HV_XHCI_TRAP_MTF_STATE g_MtfState[HV_XHCI_TRAP_MAX_CPUS];

// 诊断
static HV_XHCI_EPT_TRAP_STATS g_Stats;

// ============================================================
// MTF capability check
// ============================================================

// IA32_VMX_PROCBASED_CTLS = MSR 0x482. Allowed-1 mask is in the high 32 bits.
// CPU_BASED_MONITOR_TRAP_FLAG = bit 27. If allowed-1 bit 27 == 0, writing this
// control to VMCS will fail VMRESUME with VM-instruction error #12 (VM entry
// with invalid control field) — which is exactly the kind of failure that
// would manifest as a hard hang (vmresume keeps failing, host loops in handler).
static BOOLEAN HvXhciTrapCheckMtfSupport(VOID)
{
    ULONG processorCount = g_HypervisorContext.ProcessorCount;

    if (processorCount == 0 || processorCount > HV_XHCI_TRAP_MAX_CPUS) {
        return FALSE;
    }

    // The manager is all-or-nothing.  Do not publish MTF capability after
    // sampling only the caller CPU on a heterogeneous/partially-online set.
    for (ULONG cpu = 0; cpu < processorCount; cpu++) {
        ULONG64 ctls;
        ULONG allowed1;

        KeSetSystemAffinityThread((KAFFINITY)(1ULL << cpu));
        if (KeGetCurrentProcessorNumber() != cpu) {
            KeRevertToUserAffinityThread();
            return FALSE;
        }
        ctls = __readmsr(0x482);
        KeRevertToUserAffinityThread();

        allowed1 = (ULONG)(ctls >> 32);
        if ((allowed1 & (1U << 27)) == 0) {
            TRAP_LOG("CPU %u does not support MTF", cpu);
            return FALSE;
        }
    }
    return TRUE;
}

// ============================================================
// EPT 操作辅助
// ============================================================

// Atomically change one leaf's Read bit.  Hardware may set EPT A/D bits at
// the same time, so a C bitfield store is not safe: it can lose those updates.
static VOID HvXhciTrapSetPteRead(_Inout_opt_ PEPT_PTE pte, BOOLEAN allowRead)
{
    volatile LONG64* value;
    LONG64 observed;
    LONG64 desired;

    if (!pte) return;
    value = (volatile LONG64*)&pte->Value;
    do {
        observed = InterlockedCompareExchange64(value, 0, 0);
        desired = allowRead ? (observed | 1LL) : (observed & ~1LL);
        if (desired == observed) return;
    } while (InterlockedCompareExchange64(value, desired, observed) != observed);
}

// 在当前 CPU 上设置 / 清除 CPU_BASED_MONITOR_TRAP_FLAG。VMX root 安全。
// 注意:EptHook 自己的 EptSetMonitorTrapFlag 是 static,这里复制一份,
// 避免暴露和 link order 问题。
static VOID HvXhciTrapSetMtf(BOOLEAN enable)
{
    SIZE_T ctls = 0;
    __vmx_vmread(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, &ctls);
    if (enable) {
        ctls |= CPU_BASED_MONITOR_TRAP_FLAG;
    } else {
        ctls &= ~(SIZE_T)CPU_BASED_MONITOR_TRAP_FLAG;
    }
    __vmx_vmwrite(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, ctls);
}

// 比对两份 GUEST_CONTEXT, 找出唯一变化的字段。返回变化字段的指针 (写回用),
// 找不到/多个变化 返回 NULL。
//
// MOV reg, [mem] 一般只改一个寄存器 (或 zero-extend dword → qword,同一寄存器)。
// 我们逐字段 memcmp。注意 RSP/RBP 不在 GUEST_CONTEXT (Rsp 用 vmread 读),所以
// 只比对 GPR 数组。
static PULONG64 HvXhciTrapFindChangedGpr(PGUEST_CONTEXT before, PGUEST_CONTEXT after)
{
    PULONG64 changed = NULL;
    ULONG diffCount = 0;

    // 跟 GUEST_CONTEXT 字段顺序对齐
    PULONG64 beforeFields[] = {
        &before->Rax, &before->Rbx, &before->Rcx, &before->Rdx,
        &before->Rsi, &before->Rdi, &before->Rbp,
        &before->R8,  &before->R9,  &before->R10, &before->R11,
        &before->R12, &before->R13, &before->R14, &before->R15
    };
    PULONG64 afterFields[] = {
        &after->Rax, &after->Rbx, &after->Rcx, &after->Rdx,
        &after->Rsi, &after->Rdi, &after->Rbp,
        &after->R8,  &after->R9,  &after->R10, &after->R11,
        &after->R12, &after->R13, &after->R14, &after->R15
    };

    for (ULONG i = 0; i < RTL_NUMBER_OF(beforeFields); i++) {
        if (*beforeFields[i] != *afterFields[i]) {
            changed = afterFields[i];
            diffCount++;
        }
    }

    // 0 变化 → ISR 用 TEST/CMP 等不写寄存器的指令读 (不常见)
    // 1 变化 → 标准 MOV reg, [mem] (绝大多数)
    // 多变化 → 不应该发生 (单条 MOV 不该改多个 GPR);保守 fall through
    if (diffCount != 1) {
        return NULL;
    }
    return changed;
}

// ============================================================
// 2MB → 4KB 分裂 (本模块自管 PT,不复用 EptHook 的 split)
// ============================================================

// 为单个 4KB GPA 在所有 CPU 上分裂其所在 2MB PDE,返回共享 PT 的 VA。
// 失败返回 NULL。已分裂 (PDE.LargePage == 0) 时复用已有 PT — 这种情况
// 是 EptHook 已经为这个 2MB 范围做过 split (例如 BAR 上有其他 hook 页面),
// 我们直接拿到那个 PT。
//
// 必须在 PASSIVE_LEVEL 调用 (MmAllocateContiguousMemory)。
#if 0
// Legacy shared-PT implementation retained for design history.  It could
// publish only a subset of the CPU PDEs and had no transactional rollback.
static PEPT_PTE HvXhciTrapEnsureSplitPt(ULONG64 gpa)
{
    ULONG64 pml4Index = (gpa >> 39) & 0x1FF;
    ULONG64 pdptIndex = (gpa >> 30) & 0x1FF;
    ULONG64 pdIndex   = (gpa >> 21) & 0x1FF;

    if (pml4Index != 0 || pdptIndex >= 512) {
        TRAP_LOG("GPA 0x%llX outside low 512GB — trap not supported", gpa);
        return NULL;
    }
    if (!g_HypervisorContext.IsActive || !g_HypervisorContext.VcpuData) {
        TRAP_LOG("HV not active");
        return NULL;
    }

    PVCPU_DATA vcpu0 = &g_HypervisorContext.VcpuData[0];
    if (!vcpu0->EptTables) {
        TRAP_LOG("VCPU 0 has no EPT tables");
        return NULL;
    }
    PEPT_PDE pde0 = &vcpu0->EptTables->Pd[pdptIndex][pdIndex];

    // 已经被 split 过 (EptHook 在同一个 2MB 区域里安装过 hook) → 直接拿 PT
    if ((pde0->Value & (1ULL << 7)) == 0) {
        // 找 PT VA — 走 SplitPt[]/SplitPtPhysical[] 查找,匹配 PT 的 HPA
        ULONG64 ptPfn = pde0->PageFrameNumber;
        PEPT_PTE splitPt = HvEptFindSplitPt(vcpu0->EptTables, ptPfn);
        if (splitPt) {
            TRAP_LOG("GPA 0x%llX already split, reusing existing PT", gpa);
            return splitPt;
        }
        TRAP_LOG("GPA 0x%llX PDE not large but PT not in SplitPt[] — abort", gpa);
        return NULL;
    }

    // Capacity must be available on every EPT that will reference the shared
    // PT. Never publish an untracked PDE.
    for (ULONG cpu = 0; cpu < g_HypervisorContext.ProcessorCount; cpu++) {
        PVCPU_DATA v = &g_HypervisorContext.VcpuData[cpu];
        if (!v->EptTables) continue;
        PEPT_PDE pde = &v->EptTables->Pd[pdptIndex][pdIndex];
        if ((pde->Value & (1ULL << 7)) != 0 &&
            !HvEptCanRegisterSplitPt(v->EptTables)) {
            TRAP_LOG("CPU %u split PT tracking is full", cpu);
            return NULL;
        }
    }

    // 需要分裂 — 分配 PT,继承 PDE 的权限 (R=1 W=1 X=1, MemoryType=WB)
    // MMIO 的 MemoryType 实际由 PAT/MTRR 决定,EPT 的 MemoryType 写 6 (WB) 没问题
    PHYSICAL_ADDRESS maxAddr; maxAddr.QuadPart = -1LL;
    PEPT_PTE newPt = (PEPT_PTE)MmAllocateContiguousMemory(PAGE_SIZE, maxAddr);
    if (!newPt) {
        TRAP_LOG("MmAllocateContiguousMemory PT failed");
        return NULL;
    }
    RtlZeroMemory(newPt, PAGE_SIZE);

    PHYSICAL_ADDRESS newPtPhys = MmGetPhysicalAddress(newPt);

    // 填 512 个 4KB 条目,继承 PDE 的 R/W/X
    UCHAR origRwx = (UCHAR)(pde0->Value & 0x7);
    ULONG64 basePfn = (ULONG64)(pdptIndex * 512 + pdIndex) * 512ULL;  // 2MB start in 4KB pages
    for (ULONG i = 0; i < 512; i++) {
        newPt[i].Value = 0;
        newPt[i].Read = (origRwx & EPT_READ) ? 1 : 0;
        newPt[i].Write = (origRwx & EPT_WRITE) ? 1 : 0;
        newPt[i].Execute = (origRwx & EPT_EXECUTE) ? 1 : 0;
        newPt[i].MemoryType = HvEptGetMemoryType(
            (basePfn + i) << PAGE_SHIFT, PAGE_SIZE);
        newPt[i].PageFrameNumber = basePfn + i;
    }

    // 所有 CPU 都把 PDE 改为指向这个共享 PT,并写进各自的 SplitPt[] 表
    // (写 SplitPt[] 是为了让 HvHandleEptViolation 兜底 RWX 路径能找到 PT,
    //  否则它会重建 large page 把 trap 抹掉)
    ULONG cpuCount = g_HypervisorContext.ProcessorCount;
    BOOLEAN ownerAssigned = FALSE;

    // Register first, then publish PDEs. One EPT owns the shared allocation;
    // the remaining EPTs only hold lookup references.
    for (ULONG cpu = 0; cpu < cpuCount; cpu++) {
        PVCPU_DATA v = &g_HypervisorContext.VcpuData[cpu];
        if (!v->EptTables) continue;
        PEPT_PDE pde = &v->EptTables->Pd[pdptIndex][pdIndex];
        if ((pde->Value & (1ULL << 7)) == 0) continue;
        NTSTATUS registerStatus = HvEptRegisterSplitPt(
            v->EptTables, newPt, newPtPhys, ownerAssigned ? FALSE : TRUE);
        if (!NT_SUCCESS(registerStatus)) {
            TRAP_LOG("CPU %u failed to register shared PT: 0x%X",
                     cpu, registerStatus);
            if (!ownerAssigned) MmFreeContiguousMemory(newPt);
            return NULL;
        }
        ownerAssigned = TRUE;
    }

    if (!ownerAssigned) {
        MmFreeContiguousMemory(newPt);
        return NULL;
    }

    for (ULONG cpu = 0; cpu < cpuCount; cpu++) {
        PVCPU_DATA v = &g_HypervisorContext.VcpuData[cpu];
        if (!v->EptTables) continue;

        PEPT_PDE pde = &v->EptTables->Pd[pdptIndex][pdIndex];
        if ((pde->Value & (1ULL << 7)) == 0) {
            // 这个 CPU 已经被 EptHook 拆过了 — 我们用 newPt 替换会引起 conflict。
            // 保守做法:不替换,直接使用 CPU0 视角的 newPt 引用 (但 CPU 上 PDE 是
            // 不同的 PT)。这种情况会让 trap 在那个 CPU 上失效。极不常见的边界情况。
            TRAP_LOG("CPU %u PDE already split with different PT — trap may be partial", cpu);
            continue;
        }

        pde->Value = 0;
        pde->Read = 1;
        pde->Write = 1;
        pde->Execute = 1;
        pde->PageFrameNumber = newPtPhys.QuadPart >> 12;

    }

    TRAP_LOG("Split 2MB PDE @ PDPT[%llu][%llu] for GPA 0x%llX, PT VA=%p PA=0x%llX",
             pdptIndex, pdIndex, gpa, newPt, (ULONG64)newPtPhys.QuadPart);

    // INVEPT 在最外层批量做 (调用方 Initialize 处理)
    return newPt;
}
#endif

#define HV_XHCI_EPT_LARGE_PAGE_BIT  (1ULL << 7)
#define HV_XHCI_EPT_AD_MASK         ((1ULL << 8) | (1ULL << 9))
#define HV_XHCI_EPT_PFN_MASK        0x000FFFFFFFFFF000ULL

static VOID HvXhciTrapUnregisterAllocatedPt(
    _Inout_ PHV_XHCI_TRAP_CPU_SPLIT split)
{
    PEPT_TABLES tables;
    ULONG index;

    if (!split || !split->Allocated || !split->EptTables || !split->Pt) return;
    tables = split->EptTables;
    index = split->RegistrationIndex;

    if (index < tables->SplitPtCount && tables->SplitPt[index] == split->Pt) {
        for (ULONG i = index + 1; i < tables->SplitPtCount; i++) {
            tables->SplitPt[i - 1] = tables->SplitPt[i];
            tables->SplitPtPhysical[i - 1] = tables->SplitPtPhysical[i];
            tables->SplitPtOwned[i - 1] = tables->SplitPtOwned[i];
        }
        tables->SplitPtCount--;
        tables->SplitPt[tables->SplitPtCount] = NULL;
        tables->SplitPtPhysical[tables->SplitPtCount].QuadPart = 0;
        tables->SplitPtOwned[tables->SplitPtCount] = FALSE;
        MmFreeContiguousMemory(split->Pt);
    }

    split->Allocated = FALSE;
    split->Pt = NULL;
}

static VOID HvXhciTrapRollbackRegion(_Inout_ PHV_XHCI_TRAP_REGION region)
{
    BOOLEAN pdeChanged = FALSE;
    ULONG processorCount = g_HypervisorContext.ProcessorCount;

    if (!region) return;

    // Restore every already-published PDE before freeing transaction-owned PTs.
    for (ULONG cpu = 0; cpu < processorCount; cpu++) {
        PHV_XHCI_TRAP_CPU_SPLIT split = &region->Cpu[cpu];
        if (split->PdePublished && split->Pde) {
            InterlockedExchange64(
                (volatile LONG64*)&split->Pde->Value,
                (LONG64)split->OriginalPdeValue);
            split->PdePublished = FALSE;
            pdeChanged = TRUE;
        }
    }
    if (pdeChanged && g_HypervisorContext.IsActive) {
        EptInveptAllContexts();
    }

    for (LONG cpu = (LONG)processorCount - 1; cpu >= 0; cpu--) {
        HvXhciTrapUnregisterAllocatedPt(&region->Cpu[cpu]);
    }
    RtlZeroMemory(region, sizeof(*region));
}

static VOID HvXhciTrapRollbackAllRegions(VOID)
{
    for (LONG i = (LONG)g_TrapRegionCount - 1; i >= 0; i--) {
        HvXhciTrapRollbackRegion(&g_TrapRegions[i]);
    }
    g_TrapRegionCount = 0;
}

static BOOLEAN HvXhciTrapValidateRegionConsistency(
    _In_ PHV_XHCI_TRAP_REGION region)
{
    ULONG processorCount = g_HypervisorContext.ProcessorCount;

    if (!region || processorCount == 0 || !region->Cpu[0].Pt) return FALSE;
    for (ULONG entry = 0; entry < 512; entry++) {
        ULONG64 expected = region->Cpu[0].Pt[entry].Value & ~HV_XHCI_EPT_AD_MASK;
        for (ULONG cpu = 1; cpu < processorCount; cpu++) {
            ULONG64 actual;
            if (!region->Cpu[cpu].Pt) return FALSE;
            actual = region->Cpu[cpu].Pt[entry].Value & ~HV_XHCI_EPT_AD_MASK;
            if (actual != expected) {
                TRAP_LOG("EPT split mismatch: region=0x%llX entry=%u CPU=%u",
                         region->RegionGpa, entry, cpu);
                return FALSE;
            }
        }
    }
    return TRUE;
}

// Prepare one 2 MB region transactionally.  Every vCPU must obtain a tracked,
// complete PT.  PDE publication happens only after all allocations and the
// full 512-entry consistency check have succeeded.
static BOOLEAN HvXhciTrapPrepareRegion(
    _In_ ULONG64 gpa,
    _Out_ PHV_XHCI_TRAP_REGION region)
{
    ULONG64 pml4Index = (gpa >> 39) & 0x1FF;
    ULONG64 pdptIndex = (gpa >> 30) & 0x1FF;
    ULONG64 pdIndex = (gpa >> 21) & 0x1FF;
    ULONG processorCount = g_HypervisorContext.ProcessorCount;

    if (!region || pml4Index != 0 || pdptIndex >= 512 ||
        processorCount == 0 || processorCount > HV_XHCI_TRAP_MAX_CPUS ||
        !g_HypervisorContext.IsActive || !g_HypervisorContext.VcpuData) {
        return FALSE;
    }

    RtlZeroMemory(region, sizeof(*region));
    region->RegionGpa = gpa & ~0x1FFFFFULL;

    for (ULONG cpu = 0; cpu < processorCount; cpu++) {
        PVCPU_DATA vcpu = &g_HypervisorContext.VcpuData[cpu];
        PHV_XHCI_TRAP_CPU_SPLIT split = &region->Cpu[cpu];
        ULONG64 pdeValue;

        if (!vcpu->IsVirtualized || !vcpu->EptTables) goto Fail;
        split->EptTables = vcpu->EptTables;
        split->Pde = &vcpu->EptTables->Pd[pdptIndex][pdIndex];
        pdeValue = (ULONG64)InterlockedCompareExchange64(
            (volatile LONG64*)&split->Pde->Value, 0, 0);
        split->OriginalPdeValue = pdeValue;
        if ((pdeValue & 0x7) == 0) goto Fail;

        if ((pdeValue & HV_XHCI_EPT_LARGE_PAGE_BIT) != 0) {
            PHYSICAL_ADDRESS maxAddress;
            ULONG64 basePfn = (pdeValue & HV_XHCI_EPT_PFN_MASK) >> PAGE_SHIFT;
            UCHAR permissions = (UCHAR)(pdeValue & 0x7);
            BOOLEAN ignorePat = (pdeValue & (1ULL << 6)) != 0;
            NTSTATUS registerStatus;

            if (!HvEptCanRegisterSplitPt(split->EptTables)) goto Fail;
            maxAddress.QuadPart = -1LL;
            split->Pt = (PEPT_PTE)MmAllocateContiguousMemory(PAGE_SIZE, maxAddress);
            if (!split->Pt) goto Fail;
            RtlZeroMemory(split->Pt, PAGE_SIZE);
            split->PtPhysical = MmGetPhysicalAddress(split->Pt);
            split->RegistrationIndex = split->EptTables->SplitPtCount;

            for (ULONG entry = 0; entry < 512; entry++) {
                split->Pt[entry].Read = (permissions & EPT_READ) ? 1 : 0;
                split->Pt[entry].Write = (permissions & EPT_WRITE) ? 1 : 0;
                split->Pt[entry].Execute = (permissions & EPT_EXECUTE) ? 1 : 0;
                split->Pt[entry].MemoryType = HvEptGetMemoryType(
                    ((basePfn + entry) << PAGE_SHIFT), PAGE_SIZE);
                split->Pt[entry].IgnorePat = ignorePat ? 1 : 0;
                split->Pt[entry].PageFrameNumber = basePfn + entry;
            }

            registerStatus = HvEptRegisterSplitPt(
                split->EptTables, split->Pt, split->PtPhysical, TRUE);
            if (!NT_SUCCESS(registerStatus)) {
                MmFreeContiguousMemory(split->Pt);
                split->Pt = NULL;
                goto Fail;
            }
            split->Allocated = TRUE;
            if (split->EptTables->SplitPtCount != split->RegistrationIndex + 1 ||
                split->EptTables->SplitPt[split->RegistrationIndex] != split->Pt) {
                goto Fail;
            }
        } else {
            ULONG64 ptPfn = (pdeValue & HV_XHCI_EPT_PFN_MASK) >> PAGE_SHIFT;
            split->Pt = HvEptFindSplitPt(split->EptTables, ptPfn);
            if (!split->Pt) goto Fail;
            split->PtPhysical.QuadPart = ptPfn << PAGE_SHIFT;
        }
    }

    if (!HvXhciTrapValidateRegionConsistency(region)) goto Fail;

    for (ULONG cpu = 0; cpu < processorCount; cpu++) {
        PHV_XHCI_TRAP_CPU_SPLIT split = &region->Cpu[cpu];
        if (split->Allocated) {
            ULONG64 newPdeValue = (split->OriginalPdeValue & 0x7) |
                                  (split->OriginalPdeValue & (1ULL << 8)) |
                                  ((ULONG64)split->PtPhysical.QuadPart &
                                   HV_XHCI_EPT_PFN_MASK);
            LONG64 observed = InterlockedCompareExchange64(
                (volatile LONG64*)&split->Pde->Value,
                (LONG64)newPdeValue,
                (LONG64)split->OriginalPdeValue);
            if ((ULONG64)observed != split->OriginalPdeValue) goto Fail;
            split->PdePublished = TRUE;
        }
    }

    region->Valid = TRUE;
    return TRUE;

Fail:
    HvXhciTrapRollbackRegion(region);
    return FALSE;
}

// ============================================================
// Public API
// ============================================================

NTSTATUS HvXhciEptTrapInitialize(VOID)
{
    BOOLEAN mtfSupported;
    NTSTATUS failureStatus = STATUS_UNSUCCESSFUL;

    if (InterlockedCompareExchange(&g_Initialized, -1, 0) != 0) {
        return HvXhciEptTrapIsInitialized() ? STATUS_SUCCESS : STATUS_DEVICE_BUSY;
    }

    RtlZeroMemory(g_TrapPages, sizeof(g_TrapPages));
    RtlZeroMemory(g_TrapRegions, sizeof(g_TrapRegions));
    RtlZeroMemory(g_MtfState, sizeof(g_MtfState));
    RtlZeroMemory(&g_Stats, sizeof(g_Stats));
    RtlZeroMemory((PVOID)g_PendingIsrReads, sizeof(g_PendingIsrReads));
    g_TrapPageCount = 0;
    g_TrapRegionCount = 0;
    g_MtfSupported = FALSE;
    InterlockedExchange(&g_UserEnabled, 0);  // 默认 OFF — 用户必须显式开

    // MTF capability — 不支持就别 init (避免后续 HandleViolation 设 MTF 失败 BSOD)
    mtfSupported = HvXhciTrapCheckMtfSupport();
    if (!mtfSupported) {
        TRAP_LOG("aborting init: MTF unsupported, trap cannot work");
        failureStatus = STATUS_NOT_SUPPORTED;
        goto Fail;
    }

    // 必须等 xHCI BarPhys / CapLength / RtBase 都已经填好
    if (!HvUsbXhciIsReady()) {
        TRAP_LOG("xHCI not ready, trap will not arm");
        failureStatus = STATUS_DEVICE_NOT_READY;
        goto Fail;
    }
    if (g_HvUsbXhci.BarPhys == 0 || g_HvUsbXhci.Bar == NULL ||
        g_HvUsbXhci.OpBase == NULL || g_HvUsbXhci.RtBase == NULL) {
        TRAP_LOG("xHCI BAR pointers missing");
        failureStatus = STATUS_INVALID_DEVICE_STATE;
        goto Fail;
    }

    // 计算 USBSTS / IMAN 的 GPA (= 物理地址,身份映射下 GPA==HPA)
    ULONG64 usbstsGpa = g_HvUsbXhci.BarPhys + g_HvUsbXhci.CapLength + XHCI_OP_USBSTS;
    ULONG rtsOff = (ULONG)(g_HvUsbXhci.RtBase - g_HvUsbXhci.Bar);
    ULONG64 imanGpa = g_HvUsbXhci.BarPhys + rtsOff + XHCI_RT_IR0 + XHCI_IR_IMAN;

    ULONG64 usbstsPage = usbstsGpa & ~0xFFFULL;
    ULONG64 imanPage   = imanGpa   & ~0xFFFULL;
    ULONG   usbstsOff  = (ULONG)(usbstsGpa & 0xFFFULL);
    ULONG   imanOff    = (ULONG)(imanGpa   & 0xFFFULL);

    TRAP_LOG("BarPhys=0x%llX CapLen=%u RtsOff=0x%X",
             g_HvUsbXhci.BarPhys, g_HvUsbXhci.CapLength, rtsOff);
    TRAP_LOG("USBSTS GPA=0x%llX (page=0x%llX off=0x%X)",
             usbstsGpa, usbstsPage, usbstsOff);
    TRAP_LOG("IMAN   GPA=0x%llX (page=0x%llX off=0x%X)",
             imanGpa, imanPage, imanOff);

    // 收集 unique 页 (1 或 2)
    ULONG64 pages[2]   = { usbstsPage, imanPage };
    ULONG   usbOffs[2] = { usbstsOff,  TRAP_OFFSET_NONE };
    ULONG   imanOffs[2]= { TRAP_OFFSET_NONE, imanOff };

    if (usbstsPage == imanPage) {
        // 合并 — 同页
        imanOffs[0] = imanOff;
        pages[1] = 0;  // 标记为不存在
    }

    for (ULONG i = 0; i < 2; i++) {
        PHV_XHCI_TRAP_REGION region = NULL;
        ULONG64 regionGpa;

        if (i == 1 && pages[1] == 0) break;
        regionGpa = pages[i] & ~0x1FFFFFULL;

        for (ULONG r = 0; r < g_TrapRegionCount; r++) {
            if (g_TrapRegions[r].Valid && g_TrapRegions[r].RegionGpa == regionGpa) {
                region = &g_TrapRegions[r];
                break;
            }
        }
        if (!region) {
            if (g_TrapRegionCount >= RTL_NUMBER_OF(g_TrapRegions) ||
                !HvXhciTrapPrepareRegion(
                    pages[i], &g_TrapRegions[g_TrapRegionCount])) {
                TRAP_LOG("Failed to split GPA 0x%llX, aborting trap init", pages[i]);
                goto Fail;
            }
            region = &g_TrapRegions[g_TrapRegionCount++];
        }

        if (!region || !region->Valid) {
            TRAP_LOG("Failed to split GPA 0x%llX, aborting trap init", pages[i]);
            goto Fail;
        }

        g_TrapPages[i].Valid = TRUE;
        g_TrapPages[i].PageGpa = pages[i];
        g_TrapPages[i].PtIndex = (ULONG)((pages[i] >> 12) & 0x1FF);
        g_TrapPages[i].UsbstsOffset = usbOffs[i];
        g_TrapPages[i].ImanOffset   = imanOffs[i];
        for (ULONG cpu = 0; cpu < g_HypervisorContext.ProcessorCount; cpu++) {
            if (!region->Cpu[cpu].Pt) goto Fail;
            g_TrapPages[i].Pte[cpu] =
                &region->Cpu[cpu].Pt[g_TrapPages[i].PtIndex];
        }
        g_TrapPageCount++;

        TRAP_LOG("Trap page %u: GPA=0x%llX PtIdx=%u UsbstsOff=0x%X ImanOff=0x%X",
                 i, pages[i], g_TrapPages[i].PtIndex,
                 usbOffs[i], imanOffs[i]);
    }

    // 启动期 R 保持 1 (trap 未激活),Arm 时再清。INVEPT 一次确保 split 生效。
    // PASSIVE_LEVEL,vCPU 已经在运行 → 必须走 IPI+VMCALL 路径,不能直接 INVEPT
    EptInveptAllContexts();

    g_MtfSupported = mtfSupported;
    MemoryBarrier();
    InterlockedExchange(&g_Initialized, 1);
    TRAP_LOG("initialized %u trap page(s)", g_TrapPageCount);
    return STATUS_SUCCESS;

Fail:
    HvXhciTrapRollbackAllRegions();
    RtlZeroMemory(g_TrapPages, sizeof(g_TrapPages));
    g_TrapPageCount = 0;
    g_MtfSupported = FALSE;
    InterlockedExchange(&g_UserEnabled, 0);
    InterlockedExchange(&g_Initialized, 0);
    return failureStatus;
}

VOID HvXhciEptTrapShutdown(VOID)
{
    if (InterlockedCompareExchange(&g_Initialized, 0, 1) != 1) return;
    InterlockedExchange(&g_UserEnabled, 0);

    // 恢复所有 trap 页的 R=1 (写已经从来没碰过)
    for (ULONG cpu = 0; cpu < g_HypervisorContext.ProcessorCount; cpu++) {
        for (ULONG i = 0; i < HV_XHCI_TRAP_MAX_PAGES; i++) {
            if (g_TrapPages[i].Valid) {
                HvXhciTrapSetPteRead(g_TrapPages[i].Pte[cpu], TRUE);
            }
        }
        InterlockedExchange(&g_PendingIsrReads[cpu], 0);
    }
    // Shutdown 路径在 PASSIVE_LEVEL — 走 IPI+VMCALL 而非裸 INVEPT
    EptInveptAllContexts();

    // Keep the static leaf pointers until VMX is stopped.  An already-issued
    // MTF may still complete after Initialized is cleared; EPT cleanup owns
    // and frees transaction-created PTs after all CPUs are devirtualized.
    g_MtfSupported = FALSE;

    TRAP_LOG("shutdown");
}

BOOLEAN HvXhciEptTrapIsArmed(VOID)
{
    // "Armed" 含义 = "下次 MSI inject 时该不该 trap":Init 完 + 有页 + 用户允许。
    // 三者缺一不可。Arm()/HandleViolation/HandleMtf 都靠这个判断。
    return (InterlockedCompareExchange(&g_Initialized, 0, 0) == 1)
        && (InterlockedCompareExchange(&g_UserEnabled, 0, 0) != 0)
        && (g_TrapPageCount > 0);
}

BOOLEAN HvXhciEptTrapIsUserEnabled(VOID)
{
    return InterlockedCompareExchange(&g_UserEnabled, 0, 0) != 0;
}

BOOLEAN HvXhciEptTrapIsInitialized(VOID)
{
    return InterlockedCompareExchange(&g_Initialized, 0, 0) == 1;
}

BOOLEAN HvXhciEptTrapIsMtfSupported(VOID)
{
    return g_MtfSupported;
}

// 用户层切换 trap on/off。PASSIVE_LEVEL,IOCTL 路径调。
// - enable=TRUE  : Init 完了才行,标志位翻转,下一次 MSI 注入会 Arm
// - enable=FALSE : 翻转标志位,然后立即恢复所有 trap 页的 R=1 + 跨模式 INVEPT,
//                  确保即使刚刚 Arm 过 (R 已经被清),也立刻回到透传状态。
NTSTATUS HvXhciEptTrapSetUserEnabled(BOOLEAN enable)
{
    if (!HvXhciEptTrapIsInitialized()) {
        TRAP_LOG("SetUserEnabled(%u) refused: not initialized", enable ? 1 : 0);
        return STATUS_DEVICE_NOT_READY;
    }
    if (enable && !g_MtfSupported) {
        TRAP_LOG("SetUserEnabled(TRUE) refused: MTF unsupported");
        return STATUS_NOT_SUPPORTED;
    }

    LONG newVal = enable ? 1 : 0;
    LONG prev = InterlockedExchange(&g_UserEnabled, newVal);
    if (prev == newVal) {
        return STATUS_SUCCESS;  // no-op
    }

    TRAP_LOG("trap %s by user", enable ? "ENABLED" : "DISABLED");

    if (!enable) {
        // 即时复原 R=1,counter 清 0。可能与并发 Arm() 有窗口,但 Arm() 看 IsArmed
        // 返回 FALSE 会早 bail,所以 disable 完成后 trap 状态稳定。
        for (ULONG cpu = 0; cpu < g_HypervisorContext.ProcessorCount; cpu++) {
            for (ULONG i = 0; i < HV_XHCI_TRAP_MAX_PAGES; i++) {
                if (g_TrapPages[i].Valid) {
                    HvXhciTrapSetPteRead(g_TrapPages[i].Pte[cpu], TRUE);
                }
            }
            InterlockedExchange(&g_PendingIsrReads[cpu], 0);
        }
        // PASSIVE_LEVEL + vCPU running → 走 IPI+VMCALL,不能裸 INVEPT
        EptInveptAllContexts();
    }

    return STATUS_SUCCESS;
}

VOID HvXhciEptTrapArm(VOID)
{
    PVCPU_DATA vcpu;
    ULONG cpuIdx;

    if (!HvXhciEptTrapIsArmed()) return;
    vcpu = HvNestedGetCurrentVcpu();
    if (!vcpu || vcpu->ProcessorNumber >= g_HypervisorContext.ProcessorCount ||
        vcpu->ProcessorNumber >= HV_XHCI_TRAP_MAX_CPUS) return;
    cpuIdx = vcpu->ProcessorNumber;

    // 设新 counter (重置而不是累加,避免溢出)
    InterlockedExchange(&g_PendingIsrReads[cpuIdx], HV_XHCI_TRAP_INITIAL_READS);

    // 清所有 trap 页的 R bit,触发后续 read VMEXIT
    for (ULONG i = 0; i < HV_XHCI_TRAP_MAX_PAGES; i++) {
        if (g_TrapPages[i].Valid) {
            HvXhciTrapSetPteRead(g_TrapPages[i].Pte[cpuIdx], FALSE);
        }
    }

    // INVEPT — VMX root 安全
    AsmInveptAllContexts();

    InterlockedIncrement((volatile LONG*)&g_Stats.ArmCount);
}

// 关 trap (counter 用尽时调) — 内部 helper
static VOID HvXhciTrapDisarm(_In_ ULONG cpuIdx)
{
    for (ULONG i = 0; i < HV_XHCI_TRAP_MAX_PAGES; i++) {
        if (g_TrapPages[i].Valid) {
            HvXhciTrapSetPteRead(g_TrapPages[i].Pte[cpuIdx], TRUE);
        }
    }
    AsmInveptAllContexts();
}

// ============================================================
// EPT violation handler (从 HvHandleEptViolation 调)
// ============================================================

BOOLEAN HvXhciEptTrapHandleViolation(ULONG64 gpa, ULONG64 qualification, PGUEST_CONTEXT ctx)
{
    PVCPU_DATA vcpu;
    ULONG cpuIdx;

    if (!HvXhciEptTrapIsArmed()) return FALSE;
    if (!ctx) return FALSE;
    vcpu = HvNestedGetCurrentVcpu();
    if (!vcpu || vcpu->ProcessorNumber >= g_HypervisorContext.ProcessorCount ||
        vcpu->ProcessorNumber >= HV_XHCI_TRAP_MAX_CPUS) return FALSE;
    cpuIdx = vcpu->ProcessorNumber;
    if (InterlockedCompareExchange(&g_PendingIsrReads[cpuIdx], 0, 0) <= 0) {
        return FALSE;
    }

    // 只关心 read violation;write/execute 不是我们的
    if ((qualification & EPT_VIOLATION_READ) == 0) return FALSE;

    ULONG64 pageGpa = gpa & ~0xFFFULL;

    ULONG hitIdx = (ULONG)-1;
    for (ULONG i = 0; i < HV_XHCI_TRAP_MAX_PAGES; i++) {
        if (g_TrapPages[i].Valid && g_TrapPages[i].PageGpa == pageGpa) {
            hitIdx = i;
            break;
        }
    }
    if (hitIdx == (ULONG)-1) return FALSE;

    // 同 CPU 不应该同时进 2 次 trap;如果 Active=1 已经,说明上次没 MTF 收尾,
    // 异常状态 — 直接放过去走 fallback
    PHV_XHCI_TRAP_MTF_STATE st = &g_MtfState[cpuIdx];

    if (InterlockedCompareExchange(&st->Active, 1, 0) != 0) {
        // 异常 — 已经在等 MTF,可能上次 MTF 走掉了 EptHook 路径。
        // 把 R 恢复让 guest 继续,不假冒 (counter 不动)
        HvXhciTrapSetPteRead(g_TrapPages[hitIdx].Pte[cpuIdx], TRUE);
        AsmInveptAllContexts();
        return TRUE;
    }

    st->PageIndex = hitIdx;
    st->OffsetInPage = (ULONG)(gpa & 0xFFFULL);
    st->GprSnapshot = *ctx;  // 全 16 GPR 拷贝

    // 让指令能跑过去:恢复 R=1,INVEPT,然后 MTF 单步
    HvXhciTrapSetPteRead(g_TrapPages[hitIdx].Pte[cpuIdx], TRUE);
    AsmInveptAllContexts();

    HvXhciTrapSetMtf(TRUE);

    return TRUE;
}

// ============================================================
// MTF handler (从 EXIT_REASON_MONITOR_TRAP_FLAG case 调)
// ============================================================

BOOLEAN HvXhciEptTrapHandleMtf(PGUEST_CONTEXT ctx)
{
    PVCPU_DATA vcpu;
    ULONG cpuIdx;

    if (!ctx) return FALSE;
    vcpu = HvNestedGetCurrentVcpu();
    if (!vcpu || vcpu->ProcessorNumber >= g_HypervisorContext.ProcessorCount ||
        vcpu->ProcessorNumber >= HV_XHCI_TRAP_MAX_CPUS) return FALSE;
    cpuIdx = vcpu->ProcessorNumber;
    PHV_XHCI_TRAP_MTF_STATE st = &g_MtfState[cpuIdx];

    if (InterlockedCompareExchange(&st->Active, 0, 1) != 1) {
        // 不是我们设的 MTF
        return FALSE;
    }

    // 我们的 MTF — 先关 MTF (否则下一条指令还会触发)
    HvXhciTrapSetMtf(FALSE);

    PHV_XHCI_TRAP_PAGE page = &g_TrapPages[st->PageIndex];

    // GPR diff 找目的寄存器
    PULONG64 dst = HvXhciTrapFindChangedGpr(&st->GprSnapshot, ctx);

    if (dst != NULL) {
        // 判断 offset 在该页里属于哪个寄存器
        if (page->UsbstsOffset != TRAP_OFFSET_NONE &&
            st->OffsetInPage == page->UsbstsOffset) {
            // USBSTS 读 — OR 进 EINT (bit 3)
            *dst |= XHCI_STS_EINT;
            InterlockedIncrement((volatile LONG*)&g_Stats.UsbstsReadFaked);
            InterlockedDecrement(&g_PendingIsrReads[cpuIdx]);
        } else if (page->ImanOffset != TRAP_OFFSET_NONE &&
                   st->OffsetInPage == page->ImanOffset) {
            // IMAN 读 — OR 进 IP (bit 0)
            *dst |= XHCI_IMAN_IP;
            InterlockedIncrement((volatile LONG*)&g_Stats.ImanReadFaked);
            InterlockedDecrement(&g_PendingIsrReads[cpuIdx]);
        } else {
            // 同页但读的是其他寄存器 (例如 USBCMD/PortSc) — passthrough,不计入 counter
            InterlockedIncrement((volatile LONG*)&g_Stats.OtherReadOnTrapPage);
        }
    } else {
        // GPR 没变化 / 多个变化 — 怪指令,放过去不假冒
        InterlockedIncrement((volatile LONG*)&g_Stats.MtfMisses);
    }

    // 决定是否继续 trap:counter > 0 重清 R=0 重新武装;<=0 关 trap
    LONG remaining = InterlockedCompareExchange(&g_PendingIsrReads[cpuIdx], 0, 0);
    if (remaining > 0 && HvXhciEptTrapIsArmed()) {
        for (ULONG i = 0; i < HV_XHCI_TRAP_MAX_PAGES; i++) {
            if (g_TrapPages[i].Valid) {
                HvXhciTrapSetPteRead(g_TrapPages[i].Pte[cpuIdx], FALSE);
            }
        }
        AsmInveptAllContexts();
    } else {
        // counter 用尽 — 让 trap 池静默,等下次 Arm 重新激活
        HvXhciTrapDisarm(cpuIdx);
    }

    return TRUE;
}

VOID HvXhciEptTrapQueryStats(PHV_XHCI_EPT_TRAP_STATS stats)
{
    if (!stats) return;
    *stats = g_Stats;
}

VOID HvXhciEptTrapQueryState(PHV_XHCI_EPT_TRAP_STATE state)
{
    LONG pendingReads = 0;

    if (!state) return;
    RtlZeroMemory(state, sizeof(*state));
    state->Initialized  = (UCHAR)(HvXhciEptTrapIsInitialized() ? 1 : 0);
    state->UserEnabled  = (UCHAR)(InterlockedCompareExchange(&g_UserEnabled, 0, 0) != 0);
    state->MtfSupported = (UCHAR)(g_MtfSupported ? 1 : 0);
    state->TrapPageCount = g_TrapPageCount;
    for (ULONG cpu = 0;
         cpu < g_HypervisorContext.ProcessorCount &&
         cpu < HV_XHCI_TRAP_MAX_CPUS;
         ++cpu) {
        LONG cpuPending = InterlockedCompareExchange(
            &g_PendingIsrReads[cpu], 0, 0);
        if (cpuPending > 0 && pendingReads <= MAXLONG - cpuPending) {
            pendingReads += cpuPending;
        }
    }
    state->PendingIsrReads = pendingReads;
    state->Stats = g_Stats;
}
