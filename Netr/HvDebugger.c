/*
 * HvDebugger.c
 *
 * 阶段 7: 调试器赋能 - DR shadow / event ring / 拦截位开关
 */

#include "HvDebugger.h"
#include "HvTypes.h"
#include "HvCompat.h"
#include "HvHook.h"
#include "HvPhysAccess.h"
#include "HvPebCloak.h"  // P125: PEB cloak process-exit cleanup
#include "HvVwatch.h"    // P128: 虚拟硬断 process-exit cleanup
#include <intrin.h>

// P122: 全 driver DbgPrint → GUI ring
#define HV_TRACE_THIS_CAT HV_TRACE_CAT_DEBUG
#include "HvTrace.h"

// ============================================================
// 全局状态
// ============================================================

static BOOLEAN g_HvDbgInitialized = FALSE;

// HWBP 列表 (per-process)
KSPIN_LOCK g_HwbpListLock;
static LIST_ENTRY g_HwbpList;

// 全局引用计数 (有几个生效 HWBP) + 当前活跃 target CR3 快速比对 cache
volatile LONG  g_GlobalHwbpRefCount = 0;
volatile UINT64 g_ActiveTargetCr3 = 0;

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

// P117 forward decls — 实现在文件靠后
static VOID HvDbgpBuildShadowLocked(VOID);
static VOID HvDbgpPublishShadowAllCpus(VOID);

// ============================================================
// Ring buffer (每个调试器 PID 一份)
// ============================================================

typedef struct _HV_DEBUG_RING {
    BOOLEAN    InUse;
    HANDLE     OwnerDebuggerPid;
    KSPIN_LOCK Lock;
    KEVENT     Event;
    ULONG      Head;   // 下一个写入位置 (mod RING_SIZE)
    ULONG      Tail;   // 下一个读取位置 (mod RING_SIZE)
    HV_DEBUG_EVENT Entries[HV_DBG_RING_SIZE];
} HV_DEBUG_RING, *PHV_DEBUG_RING;

static HV_DEBUG_RING g_Rings[HV_DBG_MAX_RINGS];
static KSPIN_LOCK    g_RingsTableLock;

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
} HV_SWBP_ENTRY, *PHV_SWBP_ENTRY;

static LIST_ENTRY g_SwBpList;
static KSPIN_LOCK g_SwBpLock;
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
        freeSlot->OwnerDebuggerPid = DebuggerPid;
        freeSlot->Head = 0;
        freeSlot->Tail = 0;
        KeInitializeSpinLock(&freeSlot->Lock);
        KeInitializeEvent(&freeSlot->Event, NotificationEvent, FALSE);
    }
    return freeSlot;
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

    KeInitializeSpinLock(&g_HwbpListLock);
    InitializeListHead(&g_HwbpList);
    KeInitializeSpinLock(&g_RingsTableLock);
    KeInitializeSpinLock(&g_SwBpLock);
    InitializeListHead(&g_SwBpList);
    KeInitializeSpinLock(&g_StepLock);
    RtlZeroMemory(g_StepTab, sizeof(g_StepTab));
    RtlZeroMemory(g_Rings, sizeof(g_Rings));

    g_GlobalHwbpRefCount = 0;
    g_ActiveTargetCr3 = 0;
    g_EventSeq = 0;

    g_HvDbgInitialized = TRUE;

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
    }

    DbgPrint("[HvDbg] Initialized\n");
    return STATUS_SUCCESS;
}

VOID HvDbgCleanup(VOID)
{
    KIRQL irql;
    PLIST_ENTRY entry;
    PHV_PROCESS_HWBP hwbp;

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
    if (InterlockedCompareExchange(&g_GlobalHwbpRefCount, 0, 0) > 0) {
        HvDbgDisableInterceptsAllCpus();
    }

    // 清 HWBP 列表
    KeAcquireSpinLock(&g_HwbpListLock, &irql);
    while (!IsListEmpty(&g_HwbpList)) {
        entry = RemoveHeadList(&g_HwbpList);
        hwbp = CONTAINING_RECORD(entry, HV_PROCESS_HWBP, Link);
        ExFreePoolWithTag(hwbp, HV_DBG_TAG);
    }
    KeReleaseSpinLock(&g_HwbpListLock, irql);

    // 唤醒所有 ring 上的 waiter
    KeAcquireSpinLock(&g_RingsTableLock, &irql);
    for (ULONG i = 0; i < HV_DBG_MAX_RINGS; i++) {
        if (g_Rings[i].InUse) {
            KeSetEvent(&g_Rings[i].Event, 0, FALSE);
        }
    }
    KeReleaseSpinLock(&g_RingsTableLock, irql);

    g_HvDbgInitialized = FALSE;
    g_ActiveTargetCr3 = 0;
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

    if (!g_HvDbgInitialized) return STATUS_NOT_INITIALIZED;
    if (SlotIndex >= 4) return STATUS_INVALID_PARAMETER;
    if (Length != 1 && Length != 2 && Length != 4 && Length != 8) {
        return STATUS_INVALID_PARAMETER;
    }
    if (Type > HV_HWBP_TYPE_RW) return STATUS_INVALID_PARAMETER;

    KeAcquireSpinLock(&g_HwbpListLock, &irql);

    h = HvDbgFindByPidLocked(TargetPid);
    if (!h) {
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

    KeReleaseSpinLock(&g_HwbpListLock, irql);

    // 在锁外解析 target CR3 (HvPhysGetProcessCr3 可能调用 Ps* API)
    if (created || h->CachedCr3 == 0) {
        UINT64 targetCr3 = 0;
        NTSTATUS cr3St = HvPhysGetProcessCr3((ULONG)(ULONG_PTR)TargetPid, &targetCr3);
        if (NT_SUCCESS(cr3St) && targetCr3 != 0) {
            KeAcquireSpinLock(&g_HwbpListLock, &irql);
            // 重新查找 (entry 可能在我们等锁时被 ClearAllForDebugger 清掉)
            PHV_PROCESS_HWBP hh = HvDbgFindByPidLocked(TargetPid);
            if (hh) {
                hh->CachedCr3 = targetCr3 & ~0xFFFULL;
            }
            KeReleaseSpinLock(&g_HwbpListLock, irql);
            // 同步到全局快速比对 cache (V1 单 target,直接覆盖)
            InterlockedExchange64((volatile LONG64*)&g_ActiveTargetCr3,
                                   (LONG64)(targetCr3 & ~0xFFFULL));
        }
    }

    // 引用计数:如果该槽位之前未生效 → +1
    if (!wasActive) {
        LONG newRef = InterlockedIncrement(&g_GlobalHwbpRefCount);
        if (newRef == 1) {
            // 第一个生效断点 → 先清零所有核的 TSC 补偿状态,再启用拦截位。
            // 否则 stale 的累积负偏移会被立刻写到 VMCS,跨核 TSC 失同步 → BSOD。
            HvDbgResetTscCompensationAllCpus();
            HvDbgEnableInterceptsAllCpus();
        }
    }

    // P117: 更新 per-CPU shadow, 让 CR3-Load hot path 无锁看到新断点
    KeAcquireSpinLock(&g_HwbpListLock, &irql);
    HvDbgpBuildShadowLocked();
    KeReleaseSpinLock(&g_HwbpListLock, irql);
    HvDbgpPublishShadowAllCpus();

    DbgPrint("[HvDbg] SetHwBp: DbgPid=%llu TargetPid=%llu Slot=%u Addr=0x%llX Len=%u Type=%u (created=%d ref=%d)\n",
        (ULONG64)(ULONG_PTR)DebuggerPid, (ULONG64)(ULONG_PTR)TargetPid,
        SlotIndex, Address, Length, Type, created, g_GlobalHwbpRefCount);

    return STATUS_SUCCESS;
}

NTSTATUS
HvDbgClearHwBp(
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
    KeReleaseSpinLock(&g_HwbpListLock, irql);

    if (removeEntry) {
        ExFreePoolWithTag(h, HV_DBG_TAG);
    }

    if (wasActive) {
        LONG newRef = InterlockedDecrement(&g_GlobalHwbpRefCount);
        if (newRef == 0) {
            HvDbgDisableInterceptsAllCpus();
            // 清掉 active CR3 cache
            InterlockedExchange64((volatile LONG64*)&g_ActiveTargetCr3, 0);
        }
    }

    // P117: 同步 per-CPU shadow (槽位变化或 target 清空都要广播)
    KeAcquireSpinLock(&g_HwbpListLock, &irql);
    HvDbgpBuildShadowLocked();
    KeReleaseSpinLock(&g_HwbpListLock, irql);
    HvDbgpPublishShadowAllCpus();

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
            InterlockedExchange64((volatile LONG64*)&g_ActiveTargetCr3, 0);
        }
    }

    // P117: 同步 per-CPU shadow
    KeAcquireSpinLock(&g_HwbpListLock, &irql);
    HvDbgpBuildShadowLocked();
    KeReleaseSpinLock(&g_HwbpListLock, irql);
    HvDbgpPublishShadowAllCpus();

    return STATUS_SUCCESS;
}

// ============================================================
// 事件 ring
// ============================================================

// 内部实现 — Signal 参数控制是否调 KeSetEvent.
static NTSTATUS
HvDbgEnqueueEventInternal(
    _In_ HANDLE DebuggerPid,
    _In_ const HV_DEBUG_EVENT* Event,
    _In_ BOOLEAN Signal)
{
    KIRQL irql;
    PHV_DEBUG_RING ring;

    if (!g_HvDbgInitialized || !Event) return STATUS_INVALID_PARAMETER;

    KeAcquireSpinLock(&g_RingsTableLock, &irql);
    ring = HvDbgpGetOrCreateRingLocked(DebuggerPid);
    KeReleaseSpinLock(&g_RingsTableLock, irql);
    if (!ring) return STATUS_INSUFFICIENT_RESOURCES;

    KeAcquireSpinLock(&ring->Lock, &irql);

    ULONG nextHead = (ring->Head + 1) & HV_DBG_RING_MASK;
    if (nextHead == ring->Tail) {
        // 满了 → 丢最老的
        ring->Tail = (ring->Tail + 1) & HV_DBG_RING_MASK;
    }
    ring->Entries[ring->Head] = *Event;
    // 如果调用者没设序号,自动分配
    if (ring->Entries[ring->Head].Sequence == 0) {
        ring->Entries[ring->Head].Sequence =
            (UINT64)InterlockedIncrement64((volatile LONG64*)&g_EventSeq);
    }
    ring->Head = nextHead;

    KeReleaseSpinLock(&ring->Lock, irql);

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
    return HvDbgEnqueueEventInternal(DebuggerPid, Event, TRUE);
}

// 公开: 高 IRQL 入口 (vmx root mode / #DB vmexit 用 — Signal=FALSE).
// KeSetEvent 会走调度器, root mode 调直接 BSOD IRQL_NOT_LESS_OR_EQUAL.
// user-mode poller 是 1Hz 轮询, 没 signal 也照样能收到事件, 只是延迟最多 +1s.
NTSTATUS
HvDbgEnqueueEventNoSignal(
    _In_ HANDLE DebuggerPid,
    _In_ const HV_DEBUG_EVENT* Event)
{
    return HvDbgEnqueueEventInternal(DebuggerPid, Event, FALSE);
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

    if (!g_HvDbgInitialized) return STATUS_NOT_INITIALIZED;

    KeAcquireSpinLock(&g_SwBpLock, &irql);
    for (e = g_SwBpList.Flink; e != &g_SwBpList; e = e->Flink) {
        entry = CONTAINING_RECORD(e, HV_SWBP_ENTRY, ListEntry);
        if (entry->TargetPid == TargetPid && entry->Address == Address) {
            // 已存在 → 更新 debugger 拥有者
            entry->DebuggerPid = DebuggerPid;
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

    KeAcquireSpinLock(&g_SwBpLock, &irql);
    InsertTailList(&g_SwBpList, &entry->ListEntry);
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
    PHV_DEBUG_RING ring;
    NTSTATUS status;
    LARGE_INTEGER timeout;
    PLARGE_INTEGER pTimeout = NULL;

    if (!g_HvDbgInitialized || !OutEvent) return STATUS_INVALID_PARAMETER;

    KeAcquireSpinLock(&g_RingsTableLock, &irql);
    ring = HvDbgpGetOrCreateRingLocked(DebuggerPid);
    KeReleaseSpinLock(&g_RingsTableLock, irql);
    if (!ring) return STATUS_INSUFFICIENT_RESOURCES;

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
        if (ring->Head != ring->Tail) {
            *OutEvent = ring->Entries[ring->Tail];
            ring->Tail = (ring->Tail + 1) & HV_DBG_RING_MASK;
            // ring 空了 → 复位 event,后续 wait 才会阻塞
            if (ring->Head == ring->Tail) {
                KeClearEvent(&ring->Event);
            }
            KeReleaseSpinLock(&ring->Lock, irql);
            return STATUS_SUCCESS;
        }
        KeClearEvent(&ring->Event);
        KeReleaseSpinLock(&ring->Lock, irql);

        // 阻塞等
        status = KeWaitForSingleObject(&ring->Event, Executive, KernelMode, FALSE, pTimeout);
        if (status == STATUS_TIMEOUT) {
            return STATUS_TIMEOUT;
        }
        if (!NT_SUCCESS(status)) {
            return status;
        }
        // 醒了再回到循环顶取数据 (可能被 cleanup 唤醒空)
        if (!g_HvDbgInitialized) return STATUS_CANCELLED;
    }
}

// ============================================================
// VMCS/VMCB 拦截位开关
// ============================================================
//
// 注:enable/disable 的具体 VMCS 写要在 root 模式做。
//    我们通过 VMCALL 钩到 SvmVmExitDispatch / HvVmExitDispatch,
//    在 root 模式 handler 内调用 HvDbgRootEnable/DisableInterceptsCurrentCpu。
//
// 这里的 EnableAll/DisableAll 通过 KeIpiGenericCall 在每个 CPU 上发 VMCALL。

typedef struct _HV_DBG_IPI_CTX {
    ULONG Enable;   // 1 = enable, 0 = disable
} HV_DBG_IPI_CTX;

extern UINT64 AsmVmCallWithResult(UINT64 ServiceNum);   // VMX
extern UINT64 AsmVmmcallWithResult(UINT64 ServiceNum);  // SVM

// 子命令通过寄存器: RAX = ServiceNum, RCX = ServiceNum (调用约定),
// 我们需要 RDX 携带 Enable 标志。封装一个汇编不容易,所以用 ServiceNum 内联编码:
//   VMCALL_TOGGLE_HWBP_INTERCEPTS + 1 = enable
//   VMCALL_TOGGLE_HWBP_INTERCEPTS + 0 = disable
// VMCALL handler 内 mask 出 enable bit。

static ULONG_PTR NTAPI HvDbgpIpiToggleProc(_In_ ULONG_PTR Argument)
{
    HV_DBG_IPI_CTX* ctx = (HV_DBG_IPI_CTX*)Argument;
    UINT64 serviceNum = (UINT64)VMCALL_TOGGLE_HWBP_INTERCEPTS | (ctx->Enable ? 1ULL : 0ULL);

    // 判 CPU 类型 — 但 IPI 内不能调 KeBugCheck/PsLookup;用全局 vendor 标志。
    // 为简单起见,两种都试,内核里 VMCALL/VMMCALL 在错误 CPU 会触发 #UD,
    // 我们要捕住 #UD 或检测一次。这里假设 vendor 已知:
    extern CPU_VENDOR HvGetCpuVendor(VOID);
    CPU_VENDOR v = HvGetCpuVendor();
    if (v == CPU_VENDOR_INTEL) {
        (void)AsmVmCallWithResult(serviceNum);
    } else if (v == CPU_VENDOR_AMD) {
        (void)AsmVmmcallWithResult(serviceNum);
    }
    return 0;
}

VOID HvDbgEnableInterceptsAllCpus(VOID)
{
    HV_DBG_IPI_CTX ctx = { 1 };
    DbgPrint("[HvDbg] EnableInterceptsAllCpus\n");
    KeIpiGenericCall(HvDbgpIpiToggleProc, (ULONG_PTR)&ctx);
}

VOID HvDbgDisableInterceptsAllCpus(VOID)
{
    HV_DBG_IPI_CTX ctx = { 0 };
    DbgPrint("[HvDbg] DisableInterceptsAllCpus\n");
    KeIpiGenericCall(HvDbgpIpiToggleProc, (ULONG_PTR)&ctx);
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
// P117: per-CPU HWBP 快照同步 — 让 CR3-Load hot path 0 锁 0 遍历
// ============================================================
//
// 写者: HvDbgSetHwBp / Clear* API 改完全局 list 后调这个, 通过 IPI 把当前
//       "活跃 target CR3 + DR0..3 + DR7" 快照拷贝到每个 CPU 的 HwbpShadow.
//       IPI 用 KeIpiGenericCall, 写期间所有 CPU 都在 IPI handler 内, 不会同时
//       有别的 CPU 在 CR3-Load hot path 读, 因此免锁.
//
// 读者: CR3-Load vmexit handler, 只读 HwbpShadow.HwbpActive/HwbpTargetCr3Base
//       一个 64-bit 比较, 命中直接 __writedr. 不再调 HvDbgFindByCr3Locked.
//
// 写者持 g_HwbpListLock (PASSIVE), 读者完全不持锁 — 这是基础.

typedef struct _HV_DBG_SHADOW_VIEW {
    BOOLEAN  Active;
    UINT64   TargetCr3Base;
    UINT64   Dr[4];
    UINT64   Dr7;
} HV_DBG_SHADOW_VIEW;

// 当前要广播的快照 — IPI dispatch 期间只读, 写者持 g_HwbpListLock 时填
static HV_DBG_SHADOW_VIEW g_DbgShadowPending;

static ULONG_PTR NTAPI HvDbgpIpiPublishShadowProc(_In_ ULONG_PTR Argument)
{
    UNREFERENCED_PARAMETER(Argument);
    PVCPU_DATA arr = g_HypervisorContext.VcpuData;
    if (!arr) return 0;
    ULONG cpu = KeGetCurrentProcessorNumber();
    if (cpu >= g_HypervisorContext.ProcessorCount) return 0;
    PVCPU_DATA me = &arr[cpu];

    // 整页 dword 复制, 顺序: 先写数据再 publish Active flag (memory barrier 由 IPI 跨核同步保证)
    me->HwbpShadow.HwbpTargetCr3Base = g_DbgShadowPending.TargetCr3Base;
    me->HwbpShadow.HwbpDr0 = g_DbgShadowPending.Dr[0];
    me->HwbpShadow.HwbpDr1 = g_DbgShadowPending.Dr[1];
    me->HwbpShadow.HwbpDr2 = g_DbgShadowPending.Dr[2];
    me->HwbpShadow.HwbpDr3 = g_DbgShadowPending.Dr[3];
    me->HwbpShadow.HwbpDr7 = g_DbgShadowPending.Dr7;
    InterlockedExchange(&me->HwbpShadow.HwbpActive, g_DbgShadowPending.Active ? 1 : 0);

    // 如果本 CPU 当前 guest 不在 target 进程, 把硬件 DR 也清掉 (避免泄漏到其他进程)
    // 如果在 target — 不主动写, 等下次 CR3-Load 或下一次跑到该进程时 hot path 会装载
    if (!g_DbgShadowPending.Active) {
        __writedr(0, 0); __writedr(1, 0); __writedr(2, 0); __writedr(3, 0);
        __writedr(7, (1ULL << 10));
    }
    return 0;
}

// 写者调用 (持 g_HwbpListLock 或刚释放). 不持锁也可以, 因为 g_DbgShadowPending 只在
// 这个函数串行用, 同时这条路径只在 set/clear API (PASSIVE) 走, 不会从 vmexit 调.
static VOID HvDbgpPublishShadowAllCpus(VOID)
{
    // 锁外快照 — 简单起见我们在锁内构造好 g_DbgShadowPending, 这里只 IPI 派发
    KeIpiGenericCall(HvDbgpIpiPublishShadowProc, 0);
}

// P117: CR3-Load vmexit hot path. 完全 lockless, list 不遍历, 只读 per-CPU shadow.
VOID HvDbgRootOnCr3Switch(_In_ UINT64 NewCr3)
{
    // 全局快速判断: 0 个生效 HWBP 时直接退出, 不碰任何 per-CPU 状态
    if (InterlockedCompareExchange(&g_GlobalHwbpRefCount, 0, 0) == 0) return;

    PVCPU_DATA arr = g_HypervisorContext.VcpuData;
    if (!arr) return;
    ULONG cpu = KeGetCurrentProcessorNumber();
    if (cpu >= g_HypervisorContext.ProcessorCount) return;
    PVCPU_DATA me = &arr[cpu];

    if (!InterlockedCompareExchange(&me->HwbpShadow.HwbpActive, 0, 0)) {
        // 本 CPU 无活跃 HWBP, 但全局有 — 仍然清一次 DR (防 stale)
        // 极少走到 (只在 set/clear 期间 + 本 CPU 还没收到 IPI 的窗口)
        __writedr(7, (1ULL << 10));
        return;
    }

    UINT64 newCr3Base = NewCr3 & ~0xFFFULL;
    if (newCr3Base == me->HwbpShadow.HwbpTargetCr3Base) {
        // 命中 — 装 DR. 无锁直接写, 数据来自 IPI 已 publish 的 per-CPU snapshot.
        __writedr(0, me->HwbpShadow.HwbpDr0);
        __writedr(1, me->HwbpShadow.HwbpDr1);
        __writedr(2, me->HwbpShadow.HwbpDr2);
        __writedr(3, me->HwbpShadow.HwbpDr3);
        __writedr(7, me->HwbpShadow.HwbpDr7);
    } else {
        // 切到非 target 进程 — 只清 DR7 enable 位 (保留 bit10), DR0..3 留旧值无害
        __writedr(7, (1ULL << 10));
    }
}

// 持 g_HwbpListLock 调用 — 把当前活跃 target 的状态填到 g_DbgShadowPending.
// 注意: 此函数 *不* 调 IPI (KeIpiGenericCall 不能在持 spinlock 时调). caller
// 必须释放锁后再调 HvDbgpPublishShadowAllCpus 触发 IPI.
//
// 因为 g_DbgShadowPending 是个全局 staging 区, 当前调用方持有 g_HwbpListLock
// 防止其他 set/clear 也同时来改它. IPI 派发到 worker 后, 释放 list lock 仍然
// 持有这个区, 因此 caller 必须 "build → release lock → IPI" 的顺序串行.
//
// 简化方案: 持锁内构造, 释放锁后 IPI 之前另一个 caller 可能进来覆盖. 不致命 —
// 双方都是合法目标, 最后一个 IPI 赢; per-CPU 状态最终一致.
static VOID HvDbgpBuildShadowLocked(VOID)
{
    RtlZeroMemory(&g_DbgShadowPending, sizeof(g_DbgShadowPending));
    UINT64 activeCr3 = (UINT64)InterlockedCompareExchange64(
        (volatile LONG64*)&g_ActiveTargetCr3, 0, 0);
    if (activeCr3 != 0) {
        PHV_PROCESS_HWBP h = HvDbgFindByCr3Locked(activeCr3);
        if (h && h->ActiveCount > 0) {
            g_DbgShadowPending.Active = TRUE;
            g_DbgShadowPending.TargetCr3Base = activeCr3 & ~0xFFFULL;
            g_DbgShadowPending.Dr[0] = h->Slots[0].Active ? h->Slots[0].Address : 0;
            g_DbgShadowPending.Dr[1] = h->Slots[1].Active ? h->Slots[1].Address : 0;
            g_DbgShadowPending.Dr[2] = h->Slots[2].Active ? h->Slots[2].Address : 0;
            g_DbgShadowPending.Dr[3] = h->Slots[3].Active ? h->Slots[3].Address : 0;
            g_DbgShadowPending.Dr7 = h->ComputedDr7;
        }
    }
}

// ============================================================
// Root-mode 拦截位修改 (由 VM-Exit handler 调)
// ============================================================
//
// 实际的 VMCS/VMCB 写入在 HvVmExit.c 的 VMCALL_TOGGLE_HWBP_INTERCEPTS case 里完成,
// 那里直接访问 PVCPU_DATA / Vmcb,所以这里只留一个 weak stub 给未来扩展。
//
// 之所以分到 HvVmExit.c: 那里已经有 VMCS 字段编码常量 + vmread/vmwrite 帮手,
// 也保有 Vmcb 指针的 vcpu 上下文,直接就近修改成本最低。

VOID HvDbgRootEnableInterceptsCurrentCpu(VOID)
{
    // 实现在 HvVmExit.c 的 VMCALL handler 里
}

VOID HvDbgRootDisableInterceptsCurrentCpu(VOID)
{
    // 实现在 HvVmExit.c 的 VMCALL handler 里
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
    BOOLEAN matchedActiveTarget = FALSE;
    UINT64 activeCr3Snapshot;

    if (!g_HvDbgInitialized) return STATUS_NOT_INITIALIZED;

    InitializeListHead(&pendingFree);
    activeCr3Snapshot = (UINT64)InterlockedCompareExchange64(
        (volatile LONG64*)&g_ActiveTargetCr3, 0, 0);

    KeAcquireSpinLock(&g_HwbpListLock, &irql);
    for (entry = g_HwbpList.Flink; entry != &g_HwbpList; entry = nextEntry) {
        nextEntry = entry->Flink;
        h = CONTAINING_RECORD(entry, HV_PROCESS_HWBP, Link);
        if (h->TargetPid == TargetPid) {
            removedActive += h->ActiveCount;
            if (activeCr3Snapshot != 0 &&
                (h->CachedCr3 & ~0xFFFULL) == (activeCr3Snapshot & ~0xFFFULL)) {
                matchedActiveTarget = TRUE;
            }
            RemoveEntryList(&h->Link);
            InsertTailList(&pendingFree, &h->Link);
        }
    }
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
            InterlockedExchange64((volatile LONG64*)&g_ActiveTargetCr3, 0);
        } else if (matchedActiveTarget) {
            // 当前活跃 target 走了但还有别的 target -> 让下一次 CR3 切换重新拉取
            InterlockedExchange64((volatile LONG64*)&g_ActiveTargetCr3, 0);
        }
    } else if (matchedActiveTarget) {
        // 没移除活跃 entry,但 CR3 cache 失效了(保险)
        InterlockedExchange64((volatile LONG64*)&g_ActiveTargetCr3, 0);
    }

    // P117: 同步 per-CPU shadow
    {
        KIRQL irql2;
        KeAcquireSpinLock(&g_HwbpListLock, &irql2);
        HvDbgpBuildShadowLocked();
        KeReleaseSpinLock(&g_HwbpListLock, irql2);
    }
    HvDbgpPublishShadowAllCpus();

    return STATUS_SUCCESS;
}

static VOID HvDbgpProcessNotifyCallback(
    _In_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _In_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    UNREFERENCED_PARAMETER(Process);

    // CreateInfo != NULL: 进程创建; CreateInfo == NULL: 进程退出
    if (CreateInfo != NULL) return;
    if (!g_HvDbgInitialized) return;

    // 退出进程可能既是 target 也是 debugger,两个清理路径都跑一遍
    // (两个 API 内部都做存在性判断,缺一个不影响另一个)
    (void)HvDbgClearAllForPid(ProcessId);
    (void)HvDbgClearAllForDebugger(ProcessId);

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

    // P125 (2026-06-25): 进程退出顺便撤 PEB cloak 注册.
    // HvPebCloakUnregisterTarget 内部对未注册 PID 零成本.
    HvPebCloakOnProcessExit(ProcessId);

    // P128 (2026-06-25): 进程退出清虚拟硬断.
    //   target 退出 → 清这个 target 上所有 watch
    //   debugger 退出 → 清这个 debugger 设的所有 watch
    HvVwatchClearAllForTarget(ProcessId);
    HvVwatchClearAllForDebugger(ProcessId);
}
