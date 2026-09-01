/*
 * HvDebugger.c
 *
 * 阶段 7: 调试器赋能 - 多目标 DR 虚拟化 / event ring / 拦截策略
 */

#include "HvDebugger.h"
#include "HvTypes.h"
#include "HvCompat.h"
#include "HvCore.h"
#include "HvBroadcast.h"
#include "NptHook.h"
#include "HvHook.h"
#include "HvPhysAccess.h"
#include "HvVtRoot.h"
#include "HvPebCloak.h"  // P125: PEB cloak process-exit cleanup
#include "HvVwatch.h"    // P128: 虚拟硬断 process-exit cleanup
#include "HvPrivateDebugObject.h"
#include <intrin.h>

NTKERNELAPI PVOID PsGetProcessWow64Process(_In_ PEPROCESS Process);

// P122: 全 driver DbgPrint → GUI ring
#define HV_TRACE_THIS_CAT HV_TRACE_CAT_DEBUG
#include "HvTrace.h"

// ============================================================
// 全局状态
// ============================================================

static BOOLEAN g_HvDbgInitialized = FALSE;
static volatile LONG g_HvDbgClosing = FALSE;

// HWBP 列表 (per-process)
KSPIN_LOCK g_HwbpListLock;
static LIST_ENTRY g_HwbpList;

// 全局引用计数 (有几个生效 HWBP)
volatile LONG  g_GlobalHwbpRefCount = 0;
volatile LONG g_VwatchCr3InterceptRefCount = 0;
volatile LONG g_DebugInterceptPublishedMode = 0;
volatile LONG g_DebugInterceptPublishFailures = 0;

BOOLEAN HvDebuggerPublishedMovDrExiting(VOID)
{
    LONG publishedMode = InterlockedCompareExchange(
        &g_DebugInterceptPublishedMode,
        0,
        0);
    return publishedMode >= 0 &&
        (((ULONG)publishedMode & HV_DBG_INTERCEPT_MODE_MOV_DR) != 0);
}

static KMUTEX g_DebugInterceptMutex;

#define HV_DBG_MAX_HWBP_TARGETS 32

typedef struct _HV_DBG_HWBP_SNAPSHOT_ENTRY {
    UINT64 TargetCr3Base;
    UINT64 Dr[4];
    UINT64 Dr7;
} HV_DBG_HWBP_SNAPSHOT_ENTRY, *PHV_DBG_HWBP_SNAPSHOT_ENTRY;

// Writers hold g_HwbpListLock. VM-exit readers use Sequence as a seqlock, so
// CR3 switches never acquire a kernel spin lock and every active target is
// represented instead of only the most recently configured target.
static volatile LONG g_HwbpSnapshotSequence = 0;
static volatile ULONG g_HwbpSnapshotCount = 0;
static HV_DBG_HWBP_SNAPSHOT_ENTRY
    g_HwbpSnapshot[HV_DBG_MAX_HWBP_TARGETS];

// 全局事件序号
static volatile LONG64 g_EventSeq = 0;

// 进程退出回调注册标志
static BOOLEAN g_ProcessNotifyRegistered = FALSE;

// forward
static VOID HvDbgpProcessNotifyCallback(
    _In_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _In_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo);

VOID HvDbgResetTscCompensationAllCpus(VOID);
static NTSTATUS HvDbgpAcquireInterceptMutex(VOID);
static VOID HvDbgpReleaseInterceptMutex(VOID);
static ULONG HvDbgpDesiredInterceptModeLocked(VOID);
static NTSTATUS HvDbgpPublishInterceptModeLocked(_In_ ULONG DesiredMode);

// 多目标无锁快照 — 实现在文件靠后
static VOID HvDbgpRebuildSnapshotLocked(VOID);

// ============================================================
// Ring buffer (每个调试器 PID 一份)
// ============================================================

typedef struct _HV_DEBUG_RING {
    BOOLEAN    InUse;
    BOOLEAN    DeletePending;
    USHORT     Reserved;
    LONG       WaiterCount;
    HANDLE     OwnerDebuggerPid;
    KSPIN_LOCK Lock;
    KEVENT     Event;
    ULONG      Head;   // 下一个写入位置 (mod RING_SIZE)
    ULONG      Tail;   // 下一个读取位置 (mod RING_SIZE)
    HV_DEBUG_EVENT Entries[HV_DBG_RING_SIZE];
    UCHAR       PreserveOnOverflow[HV_DBG_RING_SIZE];
} HV_DEBUG_RING, *PHV_DEBUG_RING;

static HV_DEBUG_RING g_Rings[HV_DBG_MAX_RINGS];
static KSPIN_LOCK    g_RingsTableLock;

#define HV_DBG_ROOT_MAX_CPUS       64
#define HV_DBG_ROOT_QUEUE_SIZE     16
#define HV_DBG_ROOT_QUEUE_MASK     (HV_DBG_ROOT_QUEUE_SIZE - 1)

typedef struct _HV_DBG_ROOT_EVENT_SLOT {
    HANDLE         DebuggerPid;
    HV_DEBUG_EVENT Event;
} HV_DBG_ROOT_EVENT_SLOT, *PHV_DBG_ROOT_EVENT_SLOT;

typedef struct _HV_DBG_ROOT_EVENT_QUEUE {
    volatile ULONG WriteIndex;
    volatile ULONG ReadIndex;
    HV_DBG_ROOT_EVENT_SLOT Slots[HV_DBG_ROOT_QUEUE_SIZE];
} HV_DBG_ROOT_EVENT_QUEUE, *PHV_DBG_ROOT_EVENT_QUEUE;

static HV_DBG_ROOT_EVENT_QUEUE g_RootEventQueues[HV_DBG_ROOT_MAX_CPUS];
static volatile LONG g_RootEventDrainLock = 0;
static volatile LONG64 g_RootEventsQueued = 0;
static volatile LONG64 g_RootEventsDrained = 0;
static volatile LONG64 g_RootEventsDropped = 0;

static VOID HvDbgpCloseRingLocked(_In_ PHV_DEBUG_RING Ring);
static VOID HvDbgpReleaseRingWaiter(_In_ PHV_DEBUG_RING Ring);
static VOID HvDbgpSignalAllRingsClosing(VOID);
static VOID HvDbgpDrainRootEventQueues(VOID);

// ============================================================
// 软断点注册表 (P50)
// 每条记 (target_pid, address, debugger_pid)。#BP vmexit 时 O(N) 反查。
// 量级:数十~百条,linked list 够用。
// ============================================================
typedef struct _HV_SWBP_ENTRY {
    LIST_ENTRY ListEntry;
    HANDLE TargetPid;
    UINT64 Address;
    HANDLE DebuggerPid;
    UINT64 UserCr3;
} HV_SWBP_ENTRY, *PHV_SWBP_ENTRY;

static LIST_ENTRY g_SwBpList;
static KSPIN_LOCK g_SwBpLock;
static volatile LONG g_SwBpCount = 0;
#define HV_SWBP_TAG 'BSvH'

// 单步 set (P51) — fixed-size 64 槽 (一次单步通常 1-2 个 tid 在飞)
typedef struct _HV_STEP_ENTRY {
    HANDLE Tid;
    HANDLE DebuggerPid;
    BOOLEAN InUse;
} HV_STEP_ENTRY;
#define HV_STEP_MAX 64
static HV_STEP_ENTRY g_StepTab[HV_STEP_MAX];
static KSPIN_LOCK    g_StepLock;

// 查找/创建一个调试器 PID 对应的 ring (调用者持 g_RingsTableLock)
static PHV_DEBUG_RING HvDbgpGetOrCreateRingLocked(HANDLE DebuggerPid)
{
    PHV_DEBUG_RING freeSlot = NULL;
    for (ULONG i = 0; i < HV_DBG_MAX_RINGS; i++) {
        if (g_Rings[i].InUse && g_Rings[i].OwnerDebuggerPid == DebuggerPid) {
            return &g_Rings[i];
        }
        if (!g_Rings[i].InUse && !freeSlot) {
            freeSlot = &g_Rings[i];
        }
    }
    if (freeSlot) {
        freeSlot->InUse = TRUE;
        freeSlot->DeletePending = FALSE;
        freeSlot->WaiterCount = 0;
        freeSlot->OwnerDebuggerPid = DebuggerPid;
        freeSlot->Head = 0;
        freeSlot->Tail = 0;
        KeInitializeSpinLock(&freeSlot->Lock);
        KeInitializeEvent(&freeSlot->Event, NotificationEvent, FALSE);
    }
    return freeSlot;
}

static VOID HvDbgpCloseRingLocked(_In_ PHV_DEBUG_RING Ring)
{
    KIRQL ringIrql;

    if (!Ring || !Ring->InUse) return;

    KeAcquireSpinLock(&Ring->Lock, &ringIrql);
    Ring->Head = 0;
    Ring->Tail = 0;
    RtlZeroMemory(
        Ring->PreserveOnOverflow,
        sizeof(Ring->PreserveOnOverflow));
    Ring->DeletePending = TRUE;
    KeSetEvent(&Ring->Event, 0, FALSE);
    if (Ring->WaiterCount == 0) {
        Ring->InUse = FALSE;
        Ring->DeletePending = FALSE;
        Ring->OwnerDebuggerPid = NULL;
        KeClearEvent(&Ring->Event);
    }
    KeReleaseSpinLock(&Ring->Lock, ringIrql);
}

static VOID HvDbgpReleaseRingWaiter(_In_ PHV_DEBUG_RING Ring)
{
    KIRQL tableIrql;
    KIRQL ringIrql;

    if (!Ring) return;

    KeAcquireSpinLock(&g_RingsTableLock, &tableIrql);
    KeAcquireSpinLock(&Ring->Lock, &ringIrql);
    if (Ring->WaiterCount > 0) --Ring->WaiterCount;
    if (Ring->WaiterCount == 0 && Ring->DeletePending) {
        Ring->InUse = FALSE;
        Ring->DeletePending = FALSE;
        Ring->OwnerDebuggerPid = NULL;
        Ring->Head = 0;
        Ring->Tail = 0;
        RtlZeroMemory(
            Ring->PreserveOnOverflow,
            sizeof(Ring->PreserveOnOverflow));
        KeClearEvent(&Ring->Event);
    }
    KeReleaseSpinLock(&Ring->Lock, ringIrql);
    KeReleaseSpinLock(&g_RingsTableLock, tableIrql);
}

static VOID HvDbgpSignalAllRingsClosing(VOID)
{
    KIRQL tableIrql;

    KeAcquireSpinLock(&g_RingsTableLock, &tableIrql);
    for (ULONG i = 0; i < HV_DBG_MAX_RINGS; i++) {
        if (g_Rings[i].InUse) HvDbgpCloseRingLocked(&g_Rings[i]);
    }
    KeReleaseSpinLock(&g_RingsTableLock, tableIrql);
}

static PHV_DEBUG_RING HvDbgpFindRingLocked(HANDLE DebuggerPid)
{
    for (ULONG i = 0; i < HV_DBG_MAX_RINGS; i++) {
        if (g_Rings[i].InUse && g_Rings[i].OwnerDebuggerPid == DebuggerPid) {
            return &g_Rings[i];
        }
    }
    return NULL;
}

// ============================================================
// 初始化/清理
// ============================================================

NTSTATUS HvDbgInitialize(VOID)
{
    if (g_HvDbgInitialized) {
        return STATUS_SUCCESS;
    }

    InterlockedExchange(&g_HvDbgClosing, FALSE);
    KeInitializeSpinLock(&g_HwbpListLock);
    KeInitializeMutex(&g_DebugInterceptMutex, 0);
    InitializeListHead(&g_HwbpList);
    KeInitializeSpinLock(&g_RingsTableLock);
    KeInitializeSpinLock(&g_SwBpLock);
    InitializeListHead(&g_SwBpList);
    g_SwBpCount = 0;
    KeInitializeSpinLock(&g_StepLock);
    RtlZeroMemory(g_StepTab, sizeof(g_StepTab));
    RtlZeroMemory(g_Rings, sizeof(g_Rings));
    RtlZeroMemory(g_RootEventQueues, sizeof(g_RootEventQueues));
    g_RootEventDrainLock = 0;
    g_RootEventsQueued = 0;
    g_RootEventsDrained = 0;
    g_RootEventsDropped = 0;

    g_GlobalHwbpRefCount = 0;
    g_VwatchCr3InterceptRefCount = 0;
    g_DebugInterceptPublishedMode = 0;
    g_DebugInterceptPublishFailures = 0;
    g_HwbpSnapshotSequence = 0;
    g_HwbpSnapshotCount = 0;
    RtlZeroMemory(g_HwbpSnapshot, sizeof(g_HwbpSnapshot));
    g_EventSeq = 0;

    // 注:调试器代理 hook (NtSetContextThread + Nt[R/W]VirtualMemory) 不在这里
    // 装载。EPT-hook 与相邻 syscall 共享 4KB code page,装上后空驱动状态下也会
    // 不停 EPT-violation,挤垮多核中断,触发 CLOCK_WATCHDOG_TIMEOUT。
    // 改由 HvHookAddDebugger 在 0->1 调试器注册时按需装载。

    // 注册进程退出回调,自动清理崩溃/退出进程残留的 HWBP 条目
    NTSTATUS regSt = PsSetCreateProcessNotifyRoutineEx(HvDbgpProcessNotifyCallback, FALSE);
    if (NT_SUCCESS(regSt)) {
        g_ProcessNotifyRegistered = TRUE;
    } else {
        DbgPrint("[HvDbg] PsSetCreateProcessNotifyRoutineEx failed: 0x%08X\n", regSt);
        InterlockedExchange(&g_HvDbgClosing, TRUE);
        return regSt;
    }

    g_HvDbgInitialized = TRUE;
    DbgPrint("[HvDbg] Initialized\n");
    return STATUS_SUCCESS;
}

NTSTATUS HvDbgBeginShutdown(VOID)
{
    NTSTATUS status = STATUS_SUCCESS;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (!g_HvDbgInitialized) {
        return STATUS_SUCCESS;
    }

    InterlockedExchange(&g_HvDbgClosing, TRUE);
    HvDbgpSignalAllRingsClosing();
    if (g_ProcessNotifyRegistered) {
        status = PsSetCreateProcessNotifyRoutineEx(
            HvDbgpProcessNotifyCallback, TRUE);
        if (status == STATUS_INVALID_PARAMETER) {
            status = STATUS_SUCCESS;
        }
        if (NT_SUCCESS(status)) {
            g_ProcessNotifyRegistered = FALSE;
        }
    }
    return status;
}

VOID HvDbgCleanup(VOID)
{
    KIRQL irql;
    PLIST_ENTRY entry;
    PHV_PROCESS_HWBP hwbp;
    LIST_ENTRY pendingSwBpFree;

    if (!g_HvDbgInitialized) {
        return;
    }

    // 先卸进程退出回调,避免 cleanup 过程中还有 PID 走进来
    if (g_ProcessNotifyRegistered) {
        (void)PsSetCreateProcessNotifyRoutineEx(HvDbgpProcessNotifyCallback, TRUE);
        g_ProcessNotifyRegistered = FALSE;
    }

    // 先卸调试器代理 hook,免得 cleanup 过程中还有调用进来
    HvHookDisableDebuggerProxy();

    // 如果还有生效断点,先关掉拦截位
    InterlockedExchange(&g_GlobalHwbpRefCount, 0);
    InterlockedExchange(&g_VwatchCr3InterceptRefCount, 0);
    (void)HvDbgDisableInterceptsAllCpus();
    g_HvDbgInitialized = FALSE;

    // 清 HWBP 列表
    KeAcquireSpinLock(&g_HwbpListLock, &irql);
    while (!IsListEmpty(&g_HwbpList)) {
        entry = RemoveHeadList(&g_HwbpList);
        hwbp = CONTAINING_RECORD(entry, HV_PROCESS_HWBP, Link);
        ExFreePoolWithTag(hwbp, HV_DBG_TAG);
    }
    KeReleaseSpinLock(&g_HwbpListLock, irql);

    InitializeListHead(&pendingSwBpFree);
    KeAcquireSpinLock(&g_SwBpLock, &irql);
    while (!IsListEmpty(&g_SwBpList)) {
        entry = RemoveHeadList(&g_SwBpList);
        InsertTailList(&pendingSwBpFree, entry);
    }
    KeReleaseSpinLock(&g_SwBpLock, irql);
    while (!IsListEmpty(&pendingSwBpFree)) {
        entry = RemoveHeadList(&pendingSwBpFree);
        PHV_SWBP_ENTRY swBp =
            CONTAINING_RECORD(entry, HV_SWBP_ENTRY, ListEntry);
        ExFreePoolWithTag(swBp, HV_SWBP_TAG);
    }
    InterlockedExchange(&g_SwBpCount, 0);

    KeAcquireSpinLock(&g_StepLock, &irql);
    RtlZeroMemory(g_StepTab, sizeof(g_StepTab));
    KeReleaseSpinLock(&g_StepLock, irql);

    // 唤醒所有 ring 上的 waiter
    HvDbgpSignalAllRingsClosing();

    InterlockedExchange(&g_GlobalHwbpRefCount, 0);
    InterlockedIncrement(&g_HwbpSnapshotSequence);
    KeMemoryBarrier();
    g_HwbpSnapshotCount = 0;
    RtlZeroMemory(g_HwbpSnapshot, sizeof(g_HwbpSnapshot));
    KeMemoryBarrier();
    InterlockedIncrement(&g_HwbpSnapshotSequence);
    DbgPrint("[HvDbg] Cleaned up\n");
}

BOOLEAN HvDbgIsInitialized(VOID)
{
    return g_HvDbgInitialized;
}

// ============================================================
// 内部辅助: 查找
// ============================================================

PHV_PROCESS_HWBP HvDbgFindByPidLocked(_In_ HANDLE Pid)
{
    PLIST_ENTRY entry;
    PHV_PROCESS_HWBP h;

    for (entry = g_HwbpList.Flink; entry != &g_HwbpList; entry = entry->Flink) {
        h = CONTAINING_RECORD(entry, HV_PROCESS_HWBP, Link);
        if (h->TargetPid == Pid) {
            return h;
        }
    }
    return NULL;
}

PHV_PROCESS_HWBP HvDbgFindByCr3Locked(_In_ UINT64 Cr3)
{
    PLIST_ENTRY entry;
    PHV_PROCESS_HWBP h;

    // CR3 通常有 PCID 在低 12 位,先 mask 掉
    UINT64 cr3Base = Cr3 & ~0xFFFULL;

    for (entry = g_HwbpList.Flink; entry != &g_HwbpList; entry = entry->Flink) {
        h = CONTAINING_RECORD(entry, HV_PROCESS_HWBP, Link);
        if ((h->CachedCr3 & ~0xFFFULL) == cr3Base) {
            return h;
        }
    }
    return NULL;
}

// ============================================================
// 计算 DR7 (根据 Slots 状态)
// ============================================================

static UINT64 HvDbgpComputeDr7(_In_ const HV_HWBP_SLOT* Slots)
{
    // DR7 布局:
    //   bit 0/2/4/6  = L0/L1/L2/L3 (local enable)
    //   bit 1/3/5/7  = G0/G1/G2/G3 (global enable)
    //   bit 8        = LE (废弃)
    //   bit 9        = GE (废弃)
    //   bit 10       = 保留必须为 1
    //   bit 11       = RTM
    //   bit 12       = 保留 (0)
    //   bit 13       = GD
    //   bit 14-15    = 保留 (0)
    //   bit 16-17    = R/W0 (type)
    //   bit 18-19    = LEN0 (00=1,01=2,10=8,11=4)
    //   ... 同模式 R/W1/LEN1 (20-23), R/W2/LEN2 (24-27), R/W3/LEN3 (28-31)
    UINT64 dr7 = (1ULL << 10);   // 保留位

    for (ULONG i = 0; i < 4; i++) {
        if (!Slots[i].Active) continue;
        dr7 |= (1ULL << (i * 2));      // L_i (local enable)

        // R/W field
        dr7 |= ((UINT64)(Slots[i].Type & 3)) << (16 + i * 4);

        // LEN field
        UCHAR lenBits = 0;
        switch (Slots[i].Length) {
            case 1: lenBits = 0; break;
            case 2: lenBits = 1; break;
            case 8: lenBits = 2; break;
            case 4: lenBits = 3; break;
            default: lenBits = 0; break;
        }
        dr7 |= ((UINT64)lenBits) << (18 + i * 4);
    }

    return dr7;
}

// ============================================================
// 真硬件 DR 访问
// ============================================================

UINT64 HvDbgReadRealDr(_In_ ULONG DrNum)
{
    switch (DrNum) {
        case 0: return __readdr(0);
        case 1: return __readdr(1);
        case 2: return __readdr(2);
        case 3: return __readdr(3);
        case 6: return __readdr(6);
        case 7: return __readdr(7);
        default: return 0;
    }
}

VOID HvDbgWriteRealDr(_In_ ULONG DrNum, _In_ UINT64 Value)
{
    switch (DrNum) {
        case 0: __writedr(0, Value); break;
        case 1: __writedr(1, Value); break;
        case 2: __writedr(2, Value); break;
        case 3: __writedr(3, Value); break;
        case 6: __writedr(6, Value); break;
        case 7: __writedr(7, Value); break;
        default: break;
    }
}

VOID HvDbgLoadHardwareDr(_In_ PHV_PROCESS_HWBP Hwbp)
{
    if (!Hwbp) return;
    __writedr(0, Hwbp->Slots[0].Active ? Hwbp->Slots[0].Address : 0);
    __writedr(1, Hwbp->Slots[1].Active ? Hwbp->Slots[1].Address : 0);
    __writedr(2, Hwbp->Slots[2].Active ? Hwbp->Slots[2].Address : 0);
    __writedr(3, Hwbp->Slots[3].Active ? Hwbp->Slots[3].Address : 0);
    __writedr(7, Hwbp->ComputedDr7);
}

VOID HvDbgClearHardwareDr(VOID)
{
    __writedr(0, 0);
    __writedr(1, 0);
    __writedr(2, 0);
    __writedr(3, 0);
    // DR7 保留位 bit 10 必须为 1
    __writedr(7, (1ULL << 10));
}

// ============================================================
// HWBP 管理
// ============================================================

NTSTATUS
HvDbgSetHwBp(
    _In_ HANDLE DebuggerPid,
    _In_ HANDLE TargetPid,
    _In_ ULONG SlotIndex,
    _In_ UINT64 Address,
    _In_ UCHAR Length,
    _In_ UCHAR Type)
{
    KIRQL irql;
    PHV_PROCESS_HWBP h;
    BOOLEAN created = FALSE;
    BOOLEAN wasActive;
    UINT64 targetCr3 = 0;
    NTSTATUS cr3Status;

    if (!g_HvDbgInitialized) return STATUS_NOT_INITIALIZED;
    if (SlotIndex >= 4) return STATUS_INVALID_PARAMETER;
    if (Length != 1 && Length != 2 && Length != 4 && Length != 8) {
        return STATUS_INVALID_PARAMETER;
    }
    if (Type > HV_HWBP_TYPE_RW) return STATUS_INVALID_PARAMETER;
    if (Address == 0 || (Type == HV_HWBP_TYPE_EXEC && Length != 1) ||
        (Type != HV_HWBP_TYPE_EXEC && (Address & (Length - 1)) != 0)) {
        return STATUS_DATATYPE_MISALIGNMENT;
    }

    cr3Status = HvVtRootResolveUserCr3(
        (ULONG)(ULONG_PTR)TargetPid, &targetCr3);
    if (!NT_SUCCESS(cr3Status) || targetCr3 == 0) {
        return NT_SUCCESS(cr3Status) ? STATUS_NOT_FOUND : cr3Status;
    }
    KeAcquireSpinLock(&g_HwbpListLock, &irql);

    h = HvDbgFindByPidLocked(TargetPid);
    if (h && h->DebuggerPid != DebuggerPid) {
        KeReleaseSpinLock(&g_HwbpListLock, irql);
        return STATUS_ACCESS_DENIED;
    }
    if (!h) {
        ULONG targetCount = 0;
        for (PLIST_ENTRY entry = g_HwbpList.Flink;
             entry != &g_HwbpList;
             entry = entry->Flink) {
            targetCount++;
        }
        if (targetCount >= HV_DBG_MAX_HWBP_TARGETS) {
            KeReleaseSpinLock(&g_HwbpListLock, irql);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        h = (PHV_PROCESS_HWBP)HvAllocateNonPagedZeroed(sizeof(HV_PROCESS_HWBP), HV_DBG_TAG);
        if (!h) {
            KeReleaseSpinLock(&g_HwbpListLock, irql);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        h->TargetPid = TargetPid;
        h->DebuggerPid = DebuggerPid;
        InsertTailList(&g_HwbpList, &h->Link);
        created = TRUE;
    }

    h->DebuggerPid = DebuggerPid;
    h->CachedCr3 = targetCr3 & ~0xFFFULL;

    wasActive = h->Slots[SlotIndex].Active;

    h->Slots[SlotIndex].Active  = TRUE;
    h->Slots[SlotIndex].Address = Address;
    h->Slots[SlotIndex].Length  = Length;
    h->Slots[SlotIndex].Type    = Type;

    // 重新计算 ActiveCount 和 DR7
    LONG cnt = 0;
    for (ULONG i = 0; i < 4; i++) {
        if (h->Slots[i].Active) cnt++;
    }
    h->ActiveCount = cnt;
    h->ComputedDr7 = HvDbgpComputeDr7(h->Slots);
    HvDbgpRebuildSnapshotLocked();

    KeReleaseSpinLock(&g_HwbpListLock, irql);

    // 引用计数:如果该槽位之前未生效 → +1
    if (!wasActive) {
        LONG newRef = InterlockedIncrement(&g_GlobalHwbpRefCount);
        if (newRef == 1) {
            // 第一个生效断点 → 先清零所有核的 TSC 补偿状态,再启用拦截位。
            // 否则 stale 的累积负偏移会被立刻写到 VMCS,跨核 TSC 失同步 → BSOD。
            (void)HvDbgEnableInterceptsAllCpus();
        }
    }

    DbgPrint("[HvDbg] SetHwBp: DbgPid=%llu TargetPid=%llu Slot=%u Addr=0x%llX Len=%u Type=%u (created=%d ref=%d)\n",
        (ULONG64)(ULONG_PTR)DebuggerPid, (ULONG64)(ULONG_PTR)TargetPid,
        SlotIndex, Address, Length, Type, created, g_GlobalHwbpRefCount);

    return STATUS_SUCCESS;
}

static NTSTATUS
HvDbgpClearHwBpInternal(
    _In_opt_ HANDLE DebuggerPid,
    _In_ HANDLE TargetPid,
    _In_ ULONG SlotIndex)
{
    KIRQL irql;
    PHV_PROCESS_HWBP h;
    BOOLEAN wasActive = FALSE;
    BOOLEAN removeEntry = FALSE;

    if (!g_HvDbgInitialized) return STATUS_NOT_INITIALIZED;
    if (SlotIndex >= 4) return STATUS_INVALID_PARAMETER;

    KeAcquireSpinLock(&g_HwbpListLock, &irql);
    h = HvDbgFindByPidLocked(TargetPid);
    if (!h) {
        KeReleaseSpinLock(&g_HwbpListLock, irql);
        return STATUS_NOT_FOUND;
    }
    if (DebuggerPid && h->DebuggerPid != DebuggerPid) {
        KeReleaseSpinLock(&g_HwbpListLock, irql);
        return STATUS_ACCESS_DENIED;
    }

    wasActive = h->Slots[SlotIndex].Active;
    h->Slots[SlotIndex].Active = FALSE;
    h->Slots[SlotIndex].Address = 0;
    h->Slots[SlotIndex].Length = 0;
    h->Slots[SlotIndex].Type = 0;

    LONG cnt = 0;
    for (ULONG i = 0; i < 4; i++) {
        if (h->Slots[i].Active) cnt++;
    }
    h->ActiveCount = cnt;
    h->ComputedDr7 = HvDbgpComputeDr7(h->Slots);

    if (cnt == 0) {
        RemoveEntryList(&h->Link);
        removeEntry = TRUE;
    }
    HvDbgpRebuildSnapshotLocked();
    KeReleaseSpinLock(&g_HwbpListLock, irql);

    if (removeEntry) {
        ExFreePoolWithTag(h, HV_DBG_TAG);
    }

    if (wasActive) {
        LONG newRef = InterlockedDecrement(&g_GlobalHwbpRefCount);
        if (newRef == 0) {
            HvDbgDisableInterceptsAllCpus();
        }
    }

    DbgPrint("[HvDbg] ClearHwBp: TargetPid=%llu Slot=%u (ref=%d)\n",
        (ULONG64)(ULONG_PTR)TargetPid, SlotIndex, g_GlobalHwbpRefCount);

    return STATUS_SUCCESS;
}

NTSTATUS
HvDbgClearAllForDebugger(_In_ HANDLE DebuggerPid)
{
    KIRQL irql;
    LIST_ENTRY pendingFree;
    PLIST_ENTRY entry, nextEntry;
    PHV_PROCESS_HWBP h;
    LONG removedActive = 0;

    if (!g_HvDbgInitialized) return STATUS_NOT_INITIALIZED;

    InitializeListHead(&pendingFree);

    KeAcquireSpinLock(&g_HwbpListLock, &irql);
    for (entry = g_HwbpList.Flink; entry != &g_HwbpList; entry = nextEntry) {
        nextEntry = entry->Flink;
        h = CONTAINING_RECORD(entry, HV_PROCESS_HWBP, Link);
        if (h->DebuggerPid == DebuggerPid) {
            removedActive += h->ActiveCount;
            RemoveEntryList(&h->Link);
            InsertTailList(&pendingFree, &h->Link);
        }
    }
    HvDbgpRebuildSnapshotLocked();
    KeReleaseSpinLock(&g_HwbpListLock, irql);

    while (!IsListEmpty(&pendingFree)) {
        entry = RemoveHeadList(&pendingFree);
        h = CONTAINING_RECORD(entry, HV_PROCESS_HWBP, Link);
        ExFreePoolWithTag(h, HV_DBG_TAG);
    }

    if (removedActive > 0) {
        LONG newRef = InterlockedExchangeAdd(&g_GlobalHwbpRefCount, -removedActive) - removedActive;
        if (newRef == 0) {
            HvDbgDisableInterceptsAllCpus();
        }
    }

    HvDbgDiscardEventsForDebugger(DebuggerPid);
    return STATUS_SUCCESS;
}

NTSTATUS
HvDbgClearAllForDebuggerTarget(
    _In_ HANDLE DebuggerPid,
    _In_ HANDLE TargetPid)
{
    KIRQL irql;
    LIST_ENTRY pendingFree;
    PLIST_ENTRY entry, nextEntry;
    PHV_PROCESS_HWBP h;
    LONG removedActive = 0;

    if (!g_HvDbgInitialized) return STATUS_NOT_INITIALIZED;
    if (!DebuggerPid || !TargetPid) return STATUS_INVALID_PARAMETER;

    InitializeListHead(&pendingFree);

    KeAcquireSpinLock(&g_HwbpListLock, &irql);
    for (entry = g_HwbpList.Flink; entry != &g_HwbpList; entry = nextEntry) {
        nextEntry = entry->Flink;
        h = CONTAINING_RECORD(entry, HV_PROCESS_HWBP, Link);
        if (h->DebuggerPid == DebuggerPid && h->TargetPid == TargetPid) {
            removedActive += h->ActiveCount;
            RemoveEntryList(&h->Link);
            InsertTailList(&pendingFree, &h->Link);
        }
    }
    HvDbgpRebuildSnapshotLocked();
    KeReleaseSpinLock(&g_HwbpListLock, irql);

    while (!IsListEmpty(&pendingFree)) {
        entry = RemoveHeadList(&pendingFree);
        h = CONTAINING_RECORD(entry, HV_PROCESS_HWBP, Link);
        ExFreePoolWithTag(h, HV_DBG_TAG);
    }

    if (removedActive > 0) {
        LONG newRef = InterlockedExchangeAdd(
            &g_GlobalHwbpRefCount, -removedActive) - removedActive;
        if (newRef == 0) {
            HvDbgDisableInterceptsAllCpus();
        }
    }

    return STATUS_SUCCESS;
}

NTSTATUS
HvDbgClearHwBp(
    _In_ HANDLE TargetPid,
    _In_ ULONG SlotIndex)
{
    return HvDbgpClearHwBpInternal(NULL, TargetPid, SlotIndex);
}

NTSTATUS
HvDbgClearHwBpOwned(
    _In_ HANDLE DebuggerPid,
    _In_ HANDLE TargetPid,
    _In_ ULONG SlotIndex)
{
    if (!DebuggerPid) return STATUS_INVALID_PARAMETER;
    return HvDbgpClearHwBpInternal(DebuggerPid, TargetPid, SlotIndex);
}

// ============================================================
// 事件 ring
// ============================================================

// 内部实现 — Signal 参数控制是否调 KeSetEvent.
UINT64 HvDbgReserveEventSequence(VOID)
{
    return (UINT64)InterlockedIncrement64(
        (volatile LONG64*)&g_EventSeq);
}

static NTSTATUS
HvDbgEnqueueEventInternal(
    _In_ HANDLE DebuggerPid,
    _In_ const HV_DEBUG_EVENT* Event,
    _In_ BOOLEAN Signal,
    _In_ BOOLEAN PreserveOnOverflow)
{
    KIRQL irql;
    KIRQL ringIrql;
    PHV_DEBUG_RING ring;

    if (!g_HvDbgInitialized || !Event) return STATUS_INVALID_PARAMETER;
    if (InterlockedCompareExchange(&g_HvDbgClosing, 0, 0) != 0) {
        return STATUS_DELETE_PENDING;
    }

    KeAcquireSpinLock(&g_RingsTableLock, &irql);
    ring = HvDbgpGetOrCreateRingLocked(DebuggerPid);
    if (!ring) {
        KeReleaseSpinLock(&g_RingsTableLock, irql);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    KeAcquireSpinLock(&ring->Lock, &ringIrql);
    if (ring->DeletePending) {
        KeReleaseSpinLock(&ring->Lock, ringIrql);
        KeReleaseSpinLock(&g_RingsTableLock, irql);
        return STATUS_DELETE_PENDING;
    }

    ULONG nextHead = (ring->Head + 1) & HV_DBG_RING_MASK;
    if (nextHead == ring->Tail) {
        if (ring->PreserveOnOverflow[ring->Tail]) {
            KeReleaseSpinLock(&ring->Lock, ringIrql);
            KeReleaseSpinLock(&g_RingsTableLock, irql);
            return STATUS_BUFFER_OVERFLOW;
        }
        ring->Tail = (ring->Tail + 1) & HV_DBG_RING_MASK;
    }
    ring->Entries[ring->Head] = *Event;
    ring->PreserveOnOverflow[ring->Head] =
        PreserveOnOverflow ? TRUE : FALSE;
    // 如果调用者没设序号,自动分配
    if (ring->Entries[ring->Head].Sequence == 0) {
        ring->Entries[ring->Head].Sequence = HvDbgReserveEventSequence();
    }
    ring->Head = nextHead;

    KeReleaseSpinLock(&ring->Lock, ringIrql);
    KeReleaseSpinLock(&g_RingsTableLock, irql);

    if (Signal) {
        KeSetEvent(&ring->Event, 0, FALSE);
    }
    return STATUS_SUCCESS;
}

// 公开: 标准入口 (PASSIVE_LEVEL caller 用 — Signal=TRUE)
NTSTATUS
HvDbgEnqueueEvent(
    _In_ HANDLE DebuggerPid,
    _In_ const HV_DEBUG_EVENT* Event)
{
    return HvDbgEnqueueEventInternal(DebuggerPid, Event, TRUE, FALSE);
}

// 公开: 高 IRQL 入口 (vmx root mode / #DB vmexit 用 — Signal=FALSE).
// KeSetEvent 会走调度器, root mode 调直接 BSOD IRQL_NOT_LESS_OR_EQUAL.
// user-mode poller 是 1Hz 轮询, 没 signal 也照样能收到事件, 只是延迟最多 +1s.
NTSTATUS
HvDbgEnqueueEventNoSignal(
    _In_ HANDLE DebuggerPid,
    _In_ const HV_DEBUG_EVENT* Event)
{
    return HvDbgEnqueueEventInternal(DebuggerPid, Event, FALSE, FALSE);
}

NTSTATUS
HvDbgEnqueuePrivateSwBpEventNoSignal(
    _In_ HANDLE DebuggerPid,
    _In_ const HV_DEBUG_EVENT* Event)
{
    return HvDbgEnqueueEventInternal(DebuggerPid, Event, FALSE, TRUE);
}

NTSTATUS
HvDbgEnqueuePrivateSwBpEventRootNoSignal(
    _In_ ULONG CpuIndex,
    _In_ HANDLE DebuggerPid,
    _In_ const HV_DEBUG_EVENT* Event)
{
    if (!g_HvDbgInitialized || !DebuggerPid || !Event ||
        CpuIndex >= HV_DBG_ROOT_MAX_CPUS) {
        return STATUS_INVALID_PARAMETER;
    }
    if (InterlockedCompareExchange(&g_HvDbgClosing, 0, 0) != 0) {
        return STATUS_DELETE_PENDING;
    }

    PHV_DBG_ROOT_EVENT_QUEUE queue = &g_RootEventQueues[CpuIndex];
    ULONG writeIndex = (ULONG)InterlockedCompareExchange(
        (volatile LONG*)&queue->WriteIndex, 0, 0);
    ULONG readIndex = (ULONG)InterlockedCompareExchange(
        (volatile LONG*)&queue->ReadIndex, 0, 0);
    if ((ULONG)(writeIndex - readIndex) >= HV_DBG_ROOT_QUEUE_SIZE) {
        InterlockedIncrement64(&g_RootEventsDropped);
        return STATUS_BUFFER_OVERFLOW;
    }

    PHV_DBG_ROOT_EVENT_SLOT slot =
        &queue->Slots[writeIndex & HV_DBG_ROOT_QUEUE_MASK];
    slot->DebuggerPid = DebuggerPid;
    slot->Event = *Event;
    KeMemoryBarrier();
    InterlockedExchange(
        (volatile LONG*)&queue->WriteIndex,
        (LONG)(writeIndex + 1));
    InterlockedIncrement64(&g_RootEventsQueued);
    return STATUS_SUCCESS;
}

static VOID HvDbgpDrainRootEventQueues(VOID)
{
    if (!g_HvDbgInitialized ||
        InterlockedCompareExchange(&g_HvDbgClosing, 0, 0) != 0 ||
        InterlockedCompareExchange(&g_RootEventDrainLock, 1, 0) != 0) {
        return;
    }

    ULONG cpuCount = g_HypervisorContext.ProcessorCount;
    if (cpuCount > HV_DBG_ROOT_MAX_CPUS) cpuCount = HV_DBG_ROOT_MAX_CPUS;
    for (ULONG cpuIndex = 0; cpuIndex < cpuCount; cpuIndex++) {
        PHV_DBG_ROOT_EVENT_QUEUE queue = &g_RootEventQueues[cpuIndex];
        for (;;) {
            ULONG readIndex = (ULONG)InterlockedCompareExchange(
                (volatile LONG*)&queue->ReadIndex, 0, 0);
            ULONG writeIndex = (ULONG)InterlockedCompareExchange(
                (volatile LONG*)&queue->WriteIndex, 0, 0);
            if (readIndex == writeIndex) break;

            KeMemoryBarrier();
            PHV_DBG_ROOT_EVENT_SLOT slot =
                &queue->Slots[readIndex & HV_DBG_ROOT_QUEUE_MASK];
            NTSTATUS status = HvDbgEnqueueEventInternal(
                slot->DebuggerPid,
                &slot->Event,
                FALSE,
                TRUE);
            if (status == STATUS_BUFFER_OVERFLOW ||
                status == STATUS_INSUFFICIENT_RESOURCES) {
                break;
            }

            if (NT_SUCCESS(status)) {
                InterlockedIncrement64(&g_RootEventsDrained);
            } else {
                InterlockedIncrement64(&g_RootEventsDropped);
            }
            RtlZeroMemory(slot, sizeof(*slot));
            KeMemoryBarrier();
            InterlockedExchange(
                (volatile LONG*)&queue->ReadIndex,
                (LONG)(readIndex + 1));
        }
    }

    InterlockedExchange(&g_RootEventDrainLock, 0);
}

VOID HvDbgDiscardEventsForDebugger(_In_ HANDLE DebuggerPid)
{
    KIRQL tableIrql;

    if (!DebuggerPid) return;

    KeAcquireSpinLock(&g_RingsTableLock, &tableIrql);
    PHV_DEBUG_RING ring = HvDbgpFindRingLocked(DebuggerPid);
    if (ring) HvDbgpCloseRingLocked(ring);
    KeReleaseSpinLock(&g_RingsTableLock, tableIrql);
}

VOID
HvDbgDiscardEventsForTarget(
    _In_ HANDLE DebuggerPid,
    _In_ HANDLE TargetPid)
{
    KIRQL tableIrql;
    KIRQL ringIrql;

    if (!DebuggerPid || !TargetPid) return;

    KeAcquireSpinLock(&g_RingsTableLock, &tableIrql);
    PHV_DEBUG_RING ring = HvDbgpFindRingLocked(DebuggerPid);
    if (ring) {
        KeAcquireSpinLock(&ring->Lock, &ringIrql);
        if (ring->DeletePending) {
            KeReleaseSpinLock(&ring->Lock, ringIrql);
            KeReleaseSpinLock(&g_RingsTableLock, tableIrql);
            return;
        }

        // Compact in queue order.  The write cursor can only trail the read
        // cursor, so an unread event is never overwritten while entries for
        // the detached target are removed.
        const ULONG oldHead = ring->Head;
        ULONG read = ring->Tail;
        ULONG write = ring->Tail;
        while (read != oldHead) {
            const ULONG next = (read + 1) & HV_DBG_RING_MASK;
            if (ring->Entries[read].Pid != TargetPid) {
                if (write != read) {
                    ring->Entries[write] = ring->Entries[read];
                    ring->PreserveOnOverflow[write] =
                        ring->PreserveOnOverflow[read];
                }
                write = (write + 1) & HV_DBG_RING_MASK;
            }
            read = next;
        }

        ULONG clear = write;
        while (clear != oldHead) {
            RtlZeroMemory(&ring->Entries[clear], sizeof(ring->Entries[clear]));
            ring->PreserveOnOverflow[clear] = FALSE;
            clear = (clear + 1) & HV_DBG_RING_MASK;
        }
        ring->Head = write;
        if (ring->Head == ring->Tail) {
            KeClearEvent(&ring->Event);
        } else {
            KeSetEvent(&ring->Event, 0, FALSE);
        }

        KeReleaseSpinLock(&ring->Lock, ringIrql);
    }
    KeReleaseSpinLock(&g_RingsTableLock, tableIrql);
}

// ============================================================
// 软断点注册表 API
// ============================================================
NTSTATUS HvDbgRegisterSwBp(
    _In_ HANDLE DebuggerPid,
    _In_ HANDLE TargetPid,
    _In_ UINT64 Address)
{
    KIRQL irql;
    PLIST_ENTRY e;
    PHV_SWBP_ENTRY entry;
    BOOLEAN exists = FALSE;
    UINT64 userCr3 = 0;

    if (!g_HvDbgInitialized) return STATUS_NOT_INITIALIZED;
    NTSTATUS cr3Status = HvVtRootResolveUserCr3(
        (ULONG)(ULONG_PTR)TargetPid,
        &userCr3);
    if (!NT_SUCCESS(cr3Status) || !userCr3) {
        return NT_SUCCESS(cr3Status) ? STATUS_NOT_FOUND : cr3Status;
    }
    userCr3 &= ~0xFFFULL;

    KeAcquireSpinLock(&g_SwBpLock, &irql);
    for (e = g_SwBpList.Flink; e != &g_SwBpList; e = e->Flink) {
        entry = CONTAINING_RECORD(e, HV_SWBP_ENTRY, ListEntry);
        if (entry->TargetPid == TargetPid && entry->Address == Address) {
            // 已存在 → 更新 debugger 拥有者
            entry->DebuggerPid = DebuggerPid;
            entry->UserCr3 = userCr3;
            exists = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&g_SwBpLock, irql);
    if (exists) return STATUS_SUCCESS;

    entry = (PHV_SWBP_ENTRY)HvAllocateNonPagedZeroed(sizeof(HV_SWBP_ENTRY), HV_SWBP_TAG);
    if (!entry) return STATUS_INSUFFICIENT_RESOURCES;
    entry->TargetPid = TargetPid;
    entry->Address = Address;
    entry->DebuggerPid = DebuggerPid;
    entry->UserCr3 = userCr3;

    KeAcquireSpinLock(&g_SwBpLock, &irql);
    InsertTailList(&g_SwBpList, &entry->ListEntry);
    InterlockedIncrement(&g_SwBpCount);
    KeReleaseSpinLock(&g_SwBpLock, irql);

    DbgPrint("[HvDbg] SwBp registered: target=%u rip=0x%llX (debugger=%u)\n",
             (ULONG)(ULONG_PTR)TargetPid, Address, (ULONG)(ULONG_PTR)DebuggerPid);
    return STATUS_SUCCESS;
}

NTSTATUS HvDbgUnregisterSwBp(
    _In_ HANDLE TargetPid,
    _In_ UINT64 Address)
{
    KIRQL irql;
    PLIST_ENTRY e, n;
    PHV_SWBP_ENTRY entry, found = NULL;

    if (!g_HvDbgInitialized) return STATUS_NOT_INITIALIZED;

    KeAcquireSpinLock(&g_SwBpLock, &irql);
    for (e = g_SwBpList.Flink, n = e->Flink; e != &g_SwBpList; e = n, n = e->Flink) {
        entry = CONTAINING_RECORD(e, HV_SWBP_ENTRY, ListEntry);
        if (entry->TargetPid == TargetPid && entry->Address == Address) {
            RemoveEntryList(&entry->ListEntry);
            found = entry;
            break;
        }
    }
    KeReleaseSpinLock(&g_SwBpLock, irql);
    if (found) {
        InterlockedDecrement(&g_SwBpCount);
        ExFreePoolWithTag(found, HV_SWBP_TAG);
        return STATUS_SUCCESS;
    }
    return STATUS_NOT_FOUND;
}

VOID HvDbgClearAllSwBpForPid(_In_ HANDLE TargetPid)
{
    KIRQL irql;
    PLIST_ENTRY e, n;
    PHV_SWBP_ENTRY entry;
    LIST_ENTRY toFree;
    InitializeListHead(&toFree);

    if (!g_HvDbgInitialized) return;
    KeAcquireSpinLock(&g_SwBpLock, &irql);
    for (e = g_SwBpList.Flink, n = e->Flink; e != &g_SwBpList; e = n, n = e->Flink) {
        entry = CONTAINING_RECORD(e, HV_SWBP_ENTRY, ListEntry);
        if (entry->TargetPid == TargetPid) {
            RemoveEntryList(&entry->ListEntry);
            InterlockedDecrement(&g_SwBpCount);
            InsertTailList(&toFree, &entry->ListEntry);
        }
    }
    KeReleaseSpinLock(&g_SwBpLock, irql);

    while (!IsListEmpty(&toFree)) {
        PLIST_ENTRY le = RemoveHeadList(&toFree);
        entry = CONTAINING_RECORD(le, HV_SWBP_ENTRY, ListEntry);
        ExFreePoolWithTag(entry, HV_SWBP_TAG);
    }
}

VOID HvDbgClearAllSwBpForDebugger(_In_ HANDLE DebuggerPid)
{
    KIRQL irql;
    PLIST_ENTRY e, n;
    PHV_SWBP_ENTRY entry;
    LIST_ENTRY toFree;
    InitializeListHead(&toFree);

    if (!g_HvDbgInitialized) return;
    KeAcquireSpinLock(&g_SwBpLock, &irql);
    for (e = g_SwBpList.Flink, n = e->Flink; e != &g_SwBpList; e = n, n = e->Flink) {
        entry = CONTAINING_RECORD(e, HV_SWBP_ENTRY, ListEntry);
        if (entry->DebuggerPid == DebuggerPid) {
            RemoveEntryList(&entry->ListEntry);
            InterlockedDecrement(&g_SwBpCount);
            InsertTailList(&toFree, &entry->ListEntry);
        }
    }
    KeReleaseSpinLock(&g_SwBpLock, irql);

    while (!IsListEmpty(&toFree)) {
        PLIST_ENTRY le = RemoveHeadList(&toFree);
        entry = CONTAINING_RECORD(le, HV_SWBP_ENTRY, ListEntry);
        ExFreePoolWithTag(entry, HV_SWBP_TAG);
    }
}

HANDLE HvDbgLookupSwBpOwner(_In_ HANDLE TargetPid, _In_ UINT64 Address)
{
    KIRQL irql;
    PLIST_ENTRY e;
    PHV_SWBP_ENTRY entry;
    HANDLE owner = NULL;

    if (!g_HvDbgInitialized) return NULL;
    KeAcquireSpinLock(&g_SwBpLock, &irql);
    for (e = g_SwBpList.Flink; e != &g_SwBpList; e = e->Flink) {
        entry = CONTAINING_RECORD(e, HV_SWBP_ENTRY, ListEntry);
        if (entry->TargetPid == TargetPid && entry->Address == Address) {
            owner = entry->DebuggerPid;
            break;
        }
    }
    KeReleaseSpinLock(&g_SwBpLock, irql);
    return owner;
}

HANDLE HvDbgLookupSwBpOwnerByCr3(
    _In_ UINT64 GuestCr3,
    _In_ UINT64 Address,
    _Out_opt_ HANDLE* OutTargetPid)
{
    if (OutTargetPid) *OutTargetPid = NULL;
    if (!g_HvDbgInitialized || !GuestCr3 ||
        InterlockedCompareExchange(&g_SwBpCount, 0, 0) <= 0) {
        return NULL;
    }

    GuestCr3 &= ~0xFFFULL;
    KIRQL irql;
    HANDLE owner = NULL;
    KeAcquireSpinLock(&g_SwBpLock, &irql);
    for (PLIST_ENTRY link = g_SwBpList.Flink;
         link != &g_SwBpList;
         link = link->Flink) {
        PHV_SWBP_ENTRY entry =
            CONTAINING_RECORD(link, HV_SWBP_ENTRY, ListEntry);
        if (entry->UserCr3 == GuestCr3 &&
            (entry->Address == Address || entry->Address + 1 == Address)) {
            owner = entry->DebuggerPid;
            if (OutTargetPid) *OutTargetPid = entry->TargetPid;
            break;
        }
    }
    KeReleaseSpinLock(&g_SwBpLock, irql);
    return owner;
}

// ============================================================
// 单步 (P51) 注册表
// ============================================================
NTSTATUS HvDbgArmStep(_In_ HANDLE DebuggerPid, _In_ HANDLE TargetTid)
{
    KIRQL irql;
    INT freeSlot = -1, existing = -1;
    if (!g_HvDbgInitialized) return STATUS_NOT_INITIALIZED;

    KeAcquireSpinLock(&g_StepLock, &irql);
    for (INT i = 0; i < HV_STEP_MAX; i++) {
        if (g_StepTab[i].InUse) {
            if (g_StepTab[i].Tid == TargetTid) { existing = i; break; }
        } else if (freeSlot < 0) {
            freeSlot = i;
        }
    }
    INT slot = (existing >= 0) ? existing : freeSlot;
    if (slot < 0) {
        KeReleaseSpinLock(&g_StepLock, irql);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    g_StepTab[slot].Tid = TargetTid;
    g_StepTab[slot].DebuggerPid = DebuggerPid;
    g_StepTab[slot].InUse = TRUE;
    KeReleaseSpinLock(&g_StepLock, irql);
    return STATUS_SUCCESS;
}

BOOLEAN HvDbgConsumeStep(_In_ HANDLE TargetTid, _Out_ HANDLE* OutDebuggerPid)
{
    KIRQL irql;
    BOOLEAN found = FALSE;
    if (OutDebuggerPid) *OutDebuggerPid = NULL;
    if (!g_HvDbgInitialized) return FALSE;

    KeAcquireSpinLock(&g_StepLock, &irql);
    for (INT i = 0; i < HV_STEP_MAX; i++) {
        if (g_StepTab[i].InUse && g_StepTab[i].Tid == TargetTid) {
            if (OutDebuggerPid) *OutDebuggerPid = g_StepTab[i].DebuggerPid;
            g_StepTab[i].InUse = FALSE;  // 消费掉,下一步不再触发
            found = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&g_StepLock, irql);
    return found;
}

VOID HvDbgClearAllStepForDebugger(_In_ HANDLE DebuggerPid)
{
    KIRQL irql;
    if (!g_HvDbgInitialized) return;
    KeAcquireSpinLock(&g_StepLock, &irql);
    for (INT i = 0; i < HV_STEP_MAX; i++) {
        if (g_StepTab[i].InUse && g_StepTab[i].DebuggerPid == DebuggerPid) {
            g_StepTab[i].InUse = FALSE;
        }
    }
    KeReleaseSpinLock(&g_StepLock, irql);
}

NTSTATUS
HvDbgWaitDequeueEvent(
    _In_ HANDLE DebuggerPid,
    _Out_ HV_DEBUG_EVENT* OutEvent,
    _In_ ULONG TimeoutMs)
{
    KIRQL irql;
    KIRQL ringIrql;
    PHV_DEBUG_RING ring;
    NTSTATUS status;
    LARGE_INTEGER timeout;
    PLARGE_INTEGER pTimeout = NULL;

    if (!g_HvDbgInitialized || !OutEvent) return STATUS_INVALID_PARAMETER;
    if (InterlockedCompareExchange(&g_HvDbgClosing, 0, 0) != 0) {
        return STATUS_DELETE_PENDING;
    }

    HvDbgpDrainRootEventQueues();

    KeAcquireSpinLock(&g_RingsTableLock, &irql);
    ring = HvDbgpGetOrCreateRingLocked(DebuggerPid);
    if (!ring) {
        KeReleaseSpinLock(&g_RingsTableLock, irql);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    KeAcquireSpinLock(&ring->Lock, &ringIrql);
    if (ring->DeletePending) {
        KeReleaseSpinLock(&ring->Lock, ringIrql);
        KeReleaseSpinLock(&g_RingsTableLock, irql);
        return STATUS_DELETE_PENDING;
    }
    ++ring->WaiterCount;
    KeReleaseSpinLock(&ring->Lock, ringIrql);
    KeReleaseSpinLock(&g_RingsTableLock, irql);

    if (TimeoutMs == 0) {
        timeout.QuadPart = 0;
        pTimeout = &timeout;
    } else if (TimeoutMs != MAXULONG) {
        timeout.QuadPart = -(LONGLONG)TimeoutMs * 10000LL;  // 100ns 单位
        pTimeout = &timeout;
    }
    // TimeoutMs == MAXULONG → pTimeout 留 NULL = INFINITE

    for (;;) {
        // 先尝试无锁地看 ring 是否有数据
        KeAcquireSpinLock(&ring->Lock, &irql);
        if (ring->DeletePending) {
            KeReleaseSpinLock(&ring->Lock, irql);
            status = STATUS_DELETE_PENDING;
            break;
        }
        if (ring->Head != ring->Tail) {
            *OutEvent = ring->Entries[ring->Tail];
            ring->PreserveOnOverflow[ring->Tail] = FALSE;
            ring->Tail = (ring->Tail + 1) & HV_DBG_RING_MASK;
            // ring 空了 → 复位 event,后续 wait 才会阻塞
            if (ring->Head == ring->Tail) {
                KeClearEvent(&ring->Event);
            }
            KeReleaseSpinLock(&ring->Lock, irql);
            status = STATUS_SUCCESS;
            break;
        }
        KeClearEvent(&ring->Event);
        KeReleaseSpinLock(&ring->Lock, irql);

        // 阻塞等
        status = KeWaitForSingleObject(&ring->Event, Executive, KernelMode, FALSE, pTimeout);
        if (status == STATUS_TIMEOUT) {
            break;
        }
        if (!NT_SUCCESS(status)) {
            break;
        }
        // 醒了再回到循环顶取数据 (可能被 cleanup 唤醒空)
        if (!g_HvDbgInitialized) {
            status = STATUS_CANCELLED;
            break;
        }
        if (InterlockedCompareExchange(&g_HvDbgClosing, 0, 0) != 0) {
            status = STATUS_DELETE_PENDING;
            break;
        }
    }
    HvDbgpReleaseRingWaiter(ring);
    return status;
}

// ============================================================
// VMCS/VMCB 调试拦截策略
// ============================================================
//
// CR3-load/MOV-DR remain clear while idle. The first/last active HWBP uses a
// synchronized per-CPU VMCALL to publish or withdraw the debugger exits.

static NTSTATUS HvDbgpAcquireInterceptMutex(VOID)
{
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_LEVEL;
    }
    return KeWaitForSingleObject(
        &g_DebugInterceptMutex,
        Executive,
        KernelMode,
        FALSE,
        NULL);
}

static VOID HvDbgpReleaseInterceptMutex(VOID)
{
    KeReleaseMutex(&g_DebugInterceptMutex, FALSE);
}

static ULONG HvDbgpDesiredInterceptModeLocked(VOID)
{
    ULONG mode = 0;
    if (InterlockedCompareExchange(&g_VwatchCr3InterceptRefCount, 0, 0) > 0) {
        mode |= HV_DBG_INTERCEPT_MODE_CR3;
    }
    if (InterlockedCompareExchange(&g_GlobalHwbpRefCount, 0, 0) > 0) {
        mode |= HV_DBG_INTERCEPT_MODE_CR3 | HV_DBG_INTERCEPT_MODE_MOV_DR;
    }
    return mode;
}

static NTSTATUS
HvDbgpPublishInterceptModeLocked(_In_ ULONG DesiredMode)
{
    LONG published = InterlockedCompareExchange(
        &g_DebugInterceptPublishedMode, 0, 0);
    ULONG previousMode = published >= 0
        ? ((ULONG)published & HV_DBG_INTERCEPT_MODE_MASK)
        : 0;
    NTSTATUS status;

    DesiredMode &= HV_DBG_INTERCEPT_MODE_MASK;
    if (published >= 0 && previousMode == DesiredMode) {
        return STATUS_SUCCESS;
    }

    if ((DesiredMode & HV_DBG_INTERCEPT_MODE_MOV_DR) != 0 &&
        (published < 0 ||
         (previousMode & HV_DBG_INTERCEPT_MODE_MOV_DR) == 0)) {
        HvDbgResetTscCompensationAllCpus();
    }

    status = HvBroadcastVmCallToAllCpus(
        VMCALL_SET_DEBUGGER_INTERCEPT_MODE | DesiredMode);
    if (NT_SUCCESS(status)) {
        InterlockedExchange(
            &g_DebugInterceptPublishedMode,
            (LONG)DesiredMode);
        return STATUS_SUCCESS;
    }

    InterlockedIncrement(&g_DebugInterceptPublishFailures);
    if (published >= 0 && (DesiredMode & ~previousMode) != 0) {
        NTSTATUS rollbackStatus = HvBroadcastVmCallToAllCpus(
            VMCALL_SET_DEBUGGER_INTERCEPT_MODE | previousMode);
        if (NT_SUCCESS(rollbackStatus)) {
            InterlockedExchange(
                &g_DebugInterceptPublishedMode,
                (LONG)previousMode);
        } else {
            InterlockedExchange(
                &g_DebugInterceptPublishedMode,
                HV_DBG_INTERCEPT_MODE_UNKNOWN);
        }
    } else {
        InterlockedExchange(
            &g_DebugInterceptPublishedMode,
            HV_DBG_INTERCEPT_MODE_UNKNOWN);
    }

    DbgPrint(
        "[HvDbg] debugger-exit mode publish failed: desired=0x%X previous=0x%X status=0x%08X\n",
        DesiredMode,
        previousMode,
        status);
    return status;
}

NTSTATUS HvDbgEnableInterceptsAllCpus(VOID)
{
    NTSTATUS status = HvDbgpAcquireInterceptMutex();
    if (!NT_SUCCESS(status)) return status;
    status = HvDbgpPublishInterceptModeLocked(
        HvDbgpDesiredInterceptModeLocked());
    HvDbgpReleaseInterceptMutex();
    return status;
}

NTSTATUS HvDbgDisableInterceptsAllCpus(VOID)
{
    return HvDbgEnableInterceptsAllCpus();
}

NTSTATUS HvDbgAcquireVwatchCr3Intercept(VOID)
{
    NTSTATUS status;

    if (!g_HvDbgInitialized) return STATUS_DEVICE_NOT_READY;
    if (InterlockedCompareExchange(&g_HvDbgClosing, 0, 0) != 0) {
        return STATUS_DELETE_PENDING;
    }

    status = HvDbgpAcquireInterceptMutex();
    if (!NT_SUCCESS(status)) return status;
    if (!g_HvDbgInitialized ||
        InterlockedCompareExchange(&g_HvDbgClosing, 0, 0) != 0) {
        HvDbgpReleaseInterceptMutex();
        return STATUS_DELETE_PENDING;
    }

    InterlockedIncrement(&g_VwatchCr3InterceptRefCount);
    status = HvDbgpPublishInterceptModeLocked(
        HvDbgpDesiredInterceptModeLocked());
    if (!NT_SUCCESS(status)) {
        InterlockedDecrement(&g_VwatchCr3InterceptRefCount);
    }
    HvDbgpReleaseInterceptMutex();
    return status;
}

NTSTATUS HvDbgReleaseVwatchCr3Intercepts(_In_ ULONG Count)
{
    NTSTATUS status;
    LONG current;
    LONG remaining;

    if (Count == 0) return STATUS_SUCCESS;
    if (!g_HvDbgInitialized) return STATUS_DEVICE_NOT_READY;

    status = HvDbgpAcquireInterceptMutex();
    if (!NT_SUCCESS(status)) return status;

    current = InterlockedCompareExchange(
        &g_VwatchCr3InterceptRefCount, 0, 0);
    if (current < 0) current = 0;
    remaining = current - (LONG)Count;
    if (remaining < 0) {
        DbgPrint(
            "[HvDbg] vwatch CR3 reference underflow: current=%ld release=%lu\n",
            current,
            Count);
        remaining = 0;
    }
    InterlockedExchange(&g_VwatchCr3InterceptRefCount, remaining);
    status = HvDbgpPublishInterceptModeLocked(
        HvDbgpDesiredInterceptModeLocked());
    HvDbgpReleaseInterceptMutex();
    return status;
}

// 0->1 转换时调用:把所有 VCPU 的 TSC 补偿状态归零。
// 否则上次 HWBP 周期遗留的(可能很大的)负 TscOffsetCompensation 在重启 TSC
// 补偿后会被立刻写到 VMCS_CTRL_TSC_OFFSET,跨核还不一致 → guest 立马 BSOD
// (CLOCK_WATCHDOG_TIMEOUT)。
VOID HvDbgResetTscCompensationAllCpus(VOID)
{
    ULONG count = g_HypervisorContext.ProcessorCount;
    PVCPU_DATA arr = g_HypervisorContext.VcpuData;
    if (!arr) {
        return;
    }
    for (ULONG i = 0; i < count; i++) {
        arr[i].LastVmExitHostTsc = 0;
        arr[i].TscOffsetCompensation = 0;
    }
    DbgPrint("[HvDbg] Reset TSC compensation across %u CPUs\n", count);
}

// ============================================================
// 多目标 HWBP seqlock 快照 — CR3-Load hot path 0 锁
// ============================================================
//
// 写者持 g_HwbpListLock 重建完整快照，并以奇偶序列号发布。VM-exit 读者
// 最多重试三次，命中 CR3 后直接装载 DR0..3/DR7；更新冲突时 fail closed，
// 清 DR7 使旧断点不会泄漏到无关地址空间。

static VOID HvDbgpRebuildSnapshotLocked(VOID)
{
    ULONG count = 0;

    InterlockedIncrement(&g_HwbpSnapshotSequence); // odd: writer active
    KeMemoryBarrier();
    RtlZeroMemory(g_HwbpSnapshot, sizeof(g_HwbpSnapshot));

    for (PLIST_ENTRY entry = g_HwbpList.Flink;
         entry != &g_HwbpList && count < HV_DBG_MAX_HWBP_TARGETS;
         entry = entry->Flink) {
        PHV_PROCESS_HWBP h = CONTAINING_RECORD(entry, HV_PROCESS_HWBP, Link);
        if (h->ActiveCount <= 0 || h->CachedCr3 == 0) continue;

        PHV_DBG_HWBP_SNAPSHOT_ENTRY dst = &g_HwbpSnapshot[count++];
        dst->TargetCr3Base = h->CachedCr3 & ~0xFFFULL;
        for (ULONG slot = 0; slot < 4; slot++) {
            dst->Dr[slot] = h->Slots[slot].Active ? h->Slots[slot].Address : 0;
        }
        dst->Dr7 = h->ComputedDr7;
    }

    g_HwbpSnapshotCount = count;
    KeMemoryBarrier();
    InterlockedIncrement(&g_HwbpSnapshotSequence); // even: published
}

UINT64 HvDbgRootOnCr3Switch(_In_ UINT64 NewCr3)
{
    const UINT64 newCr3Base = NewCr3 & ~0xFFFULL;
    const UINT64 disabledDr7 = (1ULL << 10);

    if (InterlockedCompareExchange(&g_GlobalHwbpRefCount, 0, 0) == 0) {
        __writedr(7, disabledDr7);
        return disabledDr7;
    }

    for (ULONG attempt = 0; attempt < 3; attempt++) {
        LONG sequence = InterlockedCompareExchange(
            &g_HwbpSnapshotSequence, 0, 0);
        if (sequence & 1) {
            _mm_pause();
            continue;
        }

        ULONG count = g_HwbpSnapshotCount;
        if (count > HV_DBG_MAX_HWBP_TARGETS) count = HV_DBG_MAX_HWBP_TARGETS;

        BOOLEAN found = FALSE;
        HV_DBG_HWBP_SNAPSHOT_ENTRY selected = { 0 };
        for (ULONG i = 0; i < count; i++) {
            if (g_HwbpSnapshot[i].TargetCr3Base == newCr3Base) {
                selected = g_HwbpSnapshot[i];
                found = TRUE;
                break;
            }
        }

        KeMemoryBarrier();
        if (sequence != InterlockedCompareExchange(
                            &g_HwbpSnapshotSequence, 0, 0)) {
            continue;
        }

        if (found) {
            __writedr(0, selected.Dr[0]);
            __writedr(1, selected.Dr[1]);
            __writedr(2, selected.Dr[2]);
            __writedr(3, selected.Dr[3]);
            __writedr(7, selected.Dr7);
            return selected.Dr7;
        } else {
            __writedr(7, disabledDr7);
            return disabledDr7;
        }
    }

    // A concurrent update is rare and short. Failing closed prevents stale
    // breakpoints leaking into an unrelated address space.
    __writedr(7, disabledDr7);
    return disabledDr7;
}

BOOLEAN HvDbgRootIsTargetCr3(_In_ UINT64 Cr3)
{
    const UINT64 cr3Base = Cr3 & ~0xFFFULL;

    if (InterlockedCompareExchange(&g_GlobalHwbpRefCount, 0, 0) == 0) {
        return FALSE;
    }

    for (ULONG attempt = 0; attempt < 3; attempt++) {
        LONG sequence = InterlockedCompareExchange(
            &g_HwbpSnapshotSequence, 0, 0);
        if (sequence & 1) {
            _mm_pause();
            continue;
        }

        ULONG count = g_HwbpSnapshotCount;
        if (count > HV_DBG_MAX_HWBP_TARGETS) count = HV_DBG_MAX_HWBP_TARGETS;

        BOOLEAN found = FALSE;
        for (ULONG index = 0; index < count; index++) {
            if (g_HwbpSnapshot[index].TargetCr3Base == cr3Base) {
                found = TRUE;
                break;
            }
        }

        KeMemoryBarrier();
        if (sequence == InterlockedCompareExchange(
                            &g_HwbpSnapshotSequence, 0, 0)) {
            return found;
        }
    }

    return FALSE;
}

// ============================================================
// 兼容保留的 root-mode 拦截入口
// ============================================================
//
// The VMCALL handler owns live VMCS/VMCB control mutation. These entry points
// remain ABI-compatible placeholders.

VOID HvDbgRootEnableInterceptsCurrentCpu(VOID)
{
}

VOID HvDbgRootDisableInterceptsCurrentCpu(VOID)
{
}

// ============================================================
// 进程退出清理 (PsSetCreateProcessNotifyRoutineEx 回调)
// ============================================================

NTSTATUS
HvDbgClearAllForPid(_In_ HANDLE TargetPid)
{
    KIRQL irql;
    LIST_ENTRY pendingFree;
    PLIST_ENTRY entry, nextEntry;
    PHV_PROCESS_HWBP h;
    LONG removedActive = 0;

    if (!g_HvDbgInitialized) return STATUS_NOT_INITIALIZED;

    InitializeListHead(&pendingFree);

    KeAcquireSpinLock(&g_HwbpListLock, &irql);
    for (entry = g_HwbpList.Flink; entry != &g_HwbpList; entry = nextEntry) {
        nextEntry = entry->Flink;
        h = CONTAINING_RECORD(entry, HV_PROCESS_HWBP, Link);
        if (h->TargetPid == TargetPid) {
            removedActive += h->ActiveCount;
            RemoveEntryList(&h->Link);
            InsertTailList(&pendingFree, &h->Link);
        }
    }
    HvDbgpRebuildSnapshotLocked();
    KeReleaseSpinLock(&g_HwbpListLock, irql);

    while (!IsListEmpty(&pendingFree)) {
        entry = RemoveHeadList(&pendingFree);
        h = CONTAINING_RECORD(entry, HV_PROCESS_HWBP, Link);
        ExFreePoolWithTag(h, HV_DBG_TAG);
    }

    if (removedActive > 0) {
        LONG newRef = InterlockedExchangeAdd(&g_GlobalHwbpRefCount, -removedActive) - removedActive;
        if (newRef == 0) {
            HvDbgDisableInterceptsAllCpus();
        }
    }
    return STATUS_SUCCESS;
}

#define HV_PEB64_BEING_DEBUGGED     0x002
#define HV_PEB64_NT_GLOBAL_FLAG     0x0BC

#define HV_PEB32_BEING_DEBUGGED     0x002
#define HV_PEB32_NT_GLOBAL_FLAG     0x068

static BOOLEAN HvDbgpIsUserAddress(_In_ UINT64 Address)
{
    return Address >= 0x10000ULL && Address < 0x0000800000000000ULL;
}

static NTSTATUS HvDbgpReadExact(
    _In_ ULONG TargetPid,
    _In_ UINT64 Address,
    _Out_writes_bytes_(Size) PVOID Buffer,
    _In_ SIZE_T Size)
{
    SIZE_T done = 0;
    NTSTATUS status = HvPhysReadProcessMemory(
        TargetPid, Address, Buffer, Size, &done);
    if (!NT_SUCCESS(status)) return status;
    return done == Size ? STATUS_SUCCESS : STATUS_PARTIAL_COPY;
}

static NTSTATUS HvDbgpWriteExact(
    _In_ ULONG TargetPid,
    _In_ UINT64 Address,
    _In_reads_bytes_(Size) PVOID Buffer,
    _In_ SIZE_T Size)
{
    SIZE_T done = 0;
    NTSTATUS status = HvPhysWriteProcessMemory(
        TargetPid, Address, Buffer, Size, &done);
    if (!NT_SUCCESS(status)) return status;
    return done == Size ? STATUS_SUCCESS : STATUS_PARTIAL_COPY;
}

static BOOLEAN HvDbgpScrubPeb64(_In_ ULONG TargetPid, _In_ UINT64 Peb)
{
    if (!HvDbgpIsUserAddress(Peb)) return FALSE;

    BOOLEAN changed = FALSE;
    UCHAR beingDebugged = 0;
    ULONG ntGlobalFlag = 0;
    NTSTATUS flagStatus = HvDbgpReadExact(
            TargetPid, Peb + HV_PEB64_NT_GLOBAL_FLAG,
            &ntGlobalFlag, sizeof(ntGlobalFlag));
    if (NT_SUCCESS(flagStatus)) {
        ntGlobalFlag &= ~0x70UL;
    }

    if (NT_SUCCESS(HvDbgpWriteExact(
            TargetPid, Peb + HV_PEB64_BEING_DEBUGGED,
            &beingDebugged, sizeof(beingDebugged)))) {
        changed = TRUE;
    }
    if (NT_SUCCESS(flagStatus) && NT_SUCCESS(HvDbgpWriteExact(
            TargetPid, Peb + HV_PEB64_NT_GLOBAL_FLAG,
            &ntGlobalFlag, sizeof(ntGlobalFlag)))) {
        changed = TRUE;
    }
    return changed;
}

static BOOLEAN HvDbgpScrubPeb32(_In_ ULONG TargetPid, _In_ UINT64 Peb)
{
    if (!HvDbgpIsUserAddress(Peb) || Peb > MAXULONG) return FALSE;

    BOOLEAN changed = FALSE;
    UCHAR beingDebugged = 0;
    ULONG ntGlobalFlag = 0;
    NTSTATUS flagStatus = HvDbgpReadExact(
            TargetPid, Peb + HV_PEB32_NT_GLOBAL_FLAG,
            &ntGlobalFlag, sizeof(ntGlobalFlag));
    if (NT_SUCCESS(flagStatus)) {
        ntGlobalFlag &= ~0x70UL;
    }

    if (NT_SUCCESS(HvDbgpWriteExact(
            TargetPid, Peb + HV_PEB32_BEING_DEBUGGED,
            &beingDebugged, sizeof(beingDebugged)))) {
        changed = TRUE;
    }
    if (NT_SUCCESS(flagStatus) && NT_SUCCESS(HvDbgpWriteExact(
            TargetPid, Peb + HV_PEB32_NT_GLOBAL_FLAG,
            &ntGlobalFlag, sizeof(ntGlobalFlag)))) {
        changed = TRUE;
    }
    return changed;
}

NTSTATUS HvDbgScrubPebDebugState(_In_ ULONG TargetPid)
{
    if (!g_HvDbgInitialized) return STATUS_NOT_INITIALIZED;
    if (TargetPid == 0) return STATUS_INVALID_PARAMETER;
    if (KeGetCurrentIrql() > APC_LEVEL) return STATUS_INVALID_LEVEL;

    BOOLEAN scrubbed = FALSE;
    UINT64 peb64 = 0;
    NTSTATUS status = HvVtRootGetPebByPid(TargetPid, &peb64);
    if (NT_SUCCESS(status) && peb64 != 0) {
        scrubbed |= HvDbgpScrubPeb64(TargetPid, peb64);
    }

    PEPROCESS process = NULL;
    if (NT_SUCCESS(PsLookupProcessByProcessId(
            (HANDLE)(ULONG_PTR)TargetPid, &process)) && process) {
        PVOID wow64 = PsGetProcessWow64Process(process);
        if (wow64) {
            UINT64 peb32 = 0;
            __try {
                peb32 = (UINT64)(ULONG_PTR)(*(PVOID*)wow64);
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                peb32 = 0;
            }
            if (peb32 != 0) {
                scrubbed |= HvDbgpScrubPeb32(TargetPid, peb32);
            }
        }
        ObDereferenceObject(process);
    }

    if (scrubbed) {
        DbgPrint("[HvDbg] PEB debug state scrubbed for PID=%u\n", TargetPid);
        return STATUS_SUCCESS;
    }
    return NT_SUCCESS(status) ? STATUS_NOT_FOUND : status;
}

static VOID HvDbgpProcessNotifyCallback(
    _In_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _In_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    // CreateInfo != NULL: 进程创建; CreateInfo == NULL: 进程退出
    if (CreateInfo != NULL ||
        InterlockedCompareExchange(&g_HvDbgClosing, 0, 0) != 0) return;
    if (!g_HvDbgInitialized) return;

    // 退出进程可能既是 target 也是 debugger,两个清理路径都跑一遍
    // (两个 API 内部都做存在性判断,缺一个不影响另一个)
    (void)HvPrivateDebugObjectNotifyProcessExit(Process, ProcessId);
    (void)HvDbgClearAllForPid(ProcessId);
    (void)HvDbgClearAllForDebugger(ProcessId);
    HvPrivateDebugObjectUnbindOnProcessExit(ProcessId);

    // P50: 软断点同样按 target / debugger 清
    HvDbgClearAllSwBpForPid(ProcessId);
    HvDbgClearAllSwBpForDebugger(ProcessId);
    // P51: 进程退出 → debugger 走了, 清掉它 arm 的所有未消费 step
    HvDbgClearAllStepForDebugger(ProcessId);

    // 2026-06-21: 同步清 ProtectedDebugger + Cloak 列表。
    // 否则 GUI 没显式 REMOVE_DEBUGGER 就退出 → driver 还把旧 PID 当受保护项,
    // Windows 复用 PID 给新 GUI 时 loader 期就被 hook 路径误处理 (0xC0000005)。
    // HvHookRemoveDebugger 内部自带"找不到就 NOT_FOUND 不副作用",所以
    // 对非 debugger 的普通退出进程零成本。
    (void)HvHookRemoveDebugger((ULONG)(ULONG_PTR)ProcessId);

    // Process-exit is the sole any-owner teardown path. Match the retained
    // EPROCESS + creation time instead of trusting a recyclable PID.
    (void)HvHookCleanupProtectedProcessOnExit(Process, ProcessId);

    // P125 (2026-06-25): 进程退出顺便撤 PEB cloak 注册.
    // HvPebCloakUnregisterTarget 内部对未注册 PID 零成本.
    HvPebCloakOnProcessExit(ProcessId);

    // P128 (2026-06-25): 进程退出清虚拟硬断.
    //   target 退出 → 清这个 target 上所有 watch
    //   debugger 退出 → 清这个 debugger 设的所有 watch
    HvVwatchClearAllForTarget(ProcessId);
    HvVwatchClearAllForDebugger(ProcessId);
    NptHookDebugStepClearAll(NULL, ProcessId);
    NptHookDebugStepClearAll(ProcessId, NULL);
}
