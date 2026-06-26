/*
 * HvVwatch.h - 虚拟硬件断点 (EPT-based watch point)
 *
 * P128 (2026-06-25): 替代 DR-based HWBP. 反作弊查 DR 永远 0.
 * P129 (2026-06-25): 全面优化:
 *   - 同页多 watch:引用计数 + 按位 OR 累积 trap (4KB 页里可放任意多 watch)
 *   - EXECUTE watch:注 #BP (vector 3) 走 KiUserExceptionDispatcher 软断路径
 *   - R/W watch:注 #DB (vector 1) 走 single-step 路径
 *   - per-target 虚拟 DR 缓存:GetContextThread O(1) 命中
 *   - 同页非 watch 字节访问:透传单步, 不注异常 (性能优化)
 *   - 精确字节级 + 方向命中判定 (GLA in [WatchVa, WatchVa+Length) && type 匹配)
 *
 * 架构层次:
 *   Page    — 4KB EPT 页 (GpaPage 唯一键),保存 per-CPU PT slot + 当前 trap mask
 *   Entry   — 一个 watch (TargetPid, WatchVa, Length, Type, DebuggerPid),指向所属 Page
 *
 * 复用 EptPebSpoof EPT 实例 (P125 PebCloak 维护). PEB cloak 跟 vwatch
 * 共存:violation handler 先查 PebCloak(它有自己的 page set),未命中再查 vwatch.
 *
 * IRQL:
 *   Init/Shutdown/Set/Clear* = PASSIVE_LEVEL
 *   ViolationHandler/MtfExit/BuildVirtualDrState = root mode 任意
 */

#ifndef _HV_VWATCH_H_
#define _HV_VWATCH_H_

#include "HvTypes.h"
#include "EptHook.h"   // EPT_PTE_ENTRY

// ============================================================
// 常量
// ============================================================

#define HV_VWATCH_MAX_ENTRIES        128     // 总 watch 槽数
#define HV_VWATCH_MAX_PAGES          64      // 不同 GpaPage 上限 (一般 <= MAX_ENTRIES)
#define HV_VWATCH_MAX_CPUS           64
#define HV_VWATCH_MAX_TARGETS_CACHE  16      // per-target 虚拟 DR cache

// Watch 类型 (跟虚幻调试器对齐)
#define HV_VWATCH_TYPE_NONE      0
#define HV_VWATCH_TYPE_WRITE     1       // 监视写
#define HV_VWATCH_TYPE_READWRITE 2       // 监视读 + 写
#define HV_VWATCH_TYPE_EXECUTE   3       // 监视执行

// 内部 trap mask bits (PT slot 上要 关 哪些位)
#define HV_VWATCH_TRAP_READ      0x1
#define HV_VWATCH_TRAP_WRITE     0x2
#define HV_VWATCH_TRAP_EXECUTE   0x4

// ============================================================
// Page 数据结构
// ============================================================

/*
 * 一个被监视的 4KB EPT 页 (跨多 entry 共享).
 *
 * RefCount       同页 entry 总数
 * CombinedTrapMask  EPT 上当前关闭的位 (OR 所有 entry 的需求)
 * CloakedPte     每核 PT slot 指针 (install 时 split + 缓存)
 */
typedef struct _HV_VWATCH_PAGE {
    volatile LONG  InUse;                          // 1=活跃
    ULONG64        GpaPage;                        // 4KB-aligned GPA (Page table 唯一键)
    ULONG64        OriginalPfn;                    // = GpaPage >> 12
    volatile LONG  RefCount;                       // 引用该页的 entry 数
    ULONG          CombinedTrapMask;               // HV_VWATCH_TRAP_* OR 累积
    PEPT_PTE_ENTRY CloakedPte[HV_VWATCH_MAX_CPUS]; // 每核 PT slot
} HV_VWATCH_PAGE, *PHV_VWATCH_PAGE;

// ============================================================
// Entry 数据结构
// ============================================================

typedef struct _HV_VWATCH_ENTRY {
    volatile LONG    InUse;            // 1=活跃
    HANDLE           TargetPid;
    HANDLE           DebuggerPid;
    UINT64           UserCr3;          // target user CR3 (cache)
    ULONG64          WatchVa;          // 字节级
    ULONG            Length;           // 1/2/4/8
    ULONG            Type;             // HV_VWATCH_TYPE_*
    LONG             PageIndex;        // 关联的 Pages[] 索引, -1 表示无效
} HV_VWATCH_ENTRY, *PHV_VWATCH_ENTRY;

// ============================================================
// MTF context (per-CPU)
// ============================================================

// MTF reason: 命中 watch 注异常后单步 (恢复 PT slot 到 trap), 或
//             命中同页非 watch 透传单步 (恢复 PT 到 trap, 不注异常)
typedef enum _HV_VWATCH_MTF_REASON {
    HV_VWATCH_MTF_NONE    = 0,
    HV_VWATCH_MTF_HIT     = 1,    // 真命中 (已注异常, 等单步完)
    HV_VWATCH_MTF_PASSTHROUGH = 2 // 同页非 watch 字节访问, 透传单步
} HV_VWATCH_MTF_REASON;

typedef struct _HV_VWATCH_MTF_CONTEXT {
    volatile PHV_VWATCH_PAGE PendingPage;
    volatile LONG            Active;       // 0=空闲 1=已 arm
    LONG                     Reason;       // HV_VWATCH_MTF_REASON
    // 2026-06-26 v2: HIT 时记下 hit type 给 MTF exit 决定注 #BP 还是 #DB
    UCHAR                    HitType;      // HV_VWATCH_TYPE_*
} HV_VWATCH_MTF_CONTEXT, *PHV_VWATCH_MTF_CONTEXT;

// ============================================================
// Per-target 虚拟 DR 缓存 (GetContextThread O(1))
// ============================================================

typedef struct _HV_VWATCH_VDR_CACHE {
    volatile LONG  InUse;
    HANDLE         TargetPid;
    UINT64         Dr0;
    UINT64         Dr1;
    UINT64         Dr2;
    UINT64         Dr3;
    UINT64         Dr7;
    volatile LONG  Valid;       // 0 = 需重算 (Set/Clear 后置 0)
} HV_VWATCH_VDR_CACHE, *PHV_VWATCH_VDR_CACHE;

// ============================================================
// Manager
// ============================================================

typedef struct _HV_VWATCH_MANAGER {
    BOOLEAN                Initialized;
    BOOLEAN                GloballyEnabled;
    KSPIN_LOCK             Lock;
    HV_VWATCH_PAGE         Pages[HV_VWATCH_MAX_PAGES];
    HV_VWATCH_ENTRY        Entries[HV_VWATCH_MAX_ENTRIES];
    HV_VWATCH_VDR_CACHE    VDrCache[HV_VWATCH_MAX_TARGETS_CACHE];
    volatile LONG          EntryCount;
    HV_VWATCH_MTF_CONTEXT  MtfContext[HV_VWATCH_MAX_CPUS];

    // 统计
    volatile LONG64        ViolationHits;       // 命中 (含透传)
    volatile LONG64        TrueHits;            // 真命中 (注了异常)
    volatile LONG64        PassthroughHits;     // 同页非 watch 透传
    volatile LONG64        InjectedDbCount;
    volatile LONG64        InjectedBpCount;
    volatile LONG64        MtfCompletions;
    volatile LONG64        VDrCacheHits;
    volatile LONG64        VDrCacheRebuilds;
} HV_VWATCH_MANAGER, *PHV_VWATCH_MANAGER;

extern HV_VWATCH_MANAGER g_VwatchManager;

// ============================================================
// 生命周期 API
// ============================================================

NTSTATUS HvVwatchInitialize(VOID);
VOID     HvVwatchShutdown(VOID);

// ============================================================
// Set / Clear (PASSIVE 入口)
// ============================================================

NTSTATUS HvVwatchSet(
    _In_ HANDLE DebuggerPid,
    _In_ HANDLE TargetPid,
    _In_ ULONG SlotIndex,
    _In_ UINT64 Address,
    _In_ UCHAR Length,
    _In_ UCHAR Type);

NTSTATUS HvVwatchClear(
    _In_ HANDLE TargetPid,
    _In_ ULONG SlotIndex);

VOID HvVwatchClearAllForDebugger(_In_ HANDLE DebuggerPid);
VOID HvVwatchClearAllForTarget(_In_ HANDLE TargetPid);

BOOLEAN HvVwatchBuildVirtualDrState(
    _In_ HANDLE TargetPid,
    _Out_ PUINT64 OutDr0,
    _Out_ PUINT64 OutDr1,
    _Out_ PUINT64 OutDr2,
    _Out_ PUINT64 OutDr3,
    _Out_ PUINT64 OutDr7);

// ============================================================
// Hot path (vmexit)
// ============================================================

BOOLEAN HvVwatchHandleEptViolation(
    _In_ ULONG64 Gpa,
    _In_ ULONG64 Qualification,
    _Inout_ PGUEST_CONTEXT Ctx);

BOOLEAN HvVwatchHandleMtfExit(_Inout_ PGUEST_CONTEXT Ctx);

#endif // _HV_VWATCH_H_
