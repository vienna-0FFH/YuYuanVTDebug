/*
 * HvPebCloak.h - PEB / ProcessHeap 字段级 EPT spoof
 *
 * P125 (2026-06-25): 旧 HvCloak (整页 ZeroPage dual-EPTP) 已删除. 此处只做
 *   "target 进程自己读自己 PEB / ProcessHeap 时,把调试相关字段返回成未调试态".
 *
 * P126 (2026-06-25): 扩展 cloak ProcessHeap header (Flags + ForceFlags).
 *   一个 target 现在绑两个 cloak page: PEB 页 + ProcessHeap 页.
 *   架构改成通用 per-page field-patch.
 *
 * 设计:
 *   - 每核维护两份 EPT 实例
 *       VcpuData->EptTables     主 EPT (identity 2MB 大页, 老路径)
 *       VcpuData->EptPebSpoof   spoof EPT (identity 2MB 大页 + target 的若干
 *                               cloak page 各自 split 成 4KB 小页, R=0 强制 violation)
 *   - vmexit 入口按 GUEST_CR3 classify:
 *       target CR3  → EptPebSpoof  (cloak 页 violation → 装补丁页喂回去)
 *       其他 CR3    → 主 EPT       (零开销)
 *   - 注册一个 target:
 *       记录 target user CR3 + 多个 cloak page (PEB / ProcessHeap)
 *       在所有 vcpu 的 EptPebSpoof 上把对应 2MB split 成 PT, 每个 cloak 页 PT slot R=0
 *   - EPT violation 命中任一 cloak 页 (任何读写都触发, R=0):
 *       PT slot 临时改成指向补丁页 + R=1/W=0
 *       arm MTF, guest 单步执行 mov 读到补丁数据
 *       MTF exit → PT slot 改回原 PFN + R=0
 *
 * Cloak page 1: PEB
 *   PEB.BeingDebugged          offset 0x002, 1 byte    → 0
 *   PEB.NtGlobalFlag           offset 0x068, 4 bytes   → &= ~0x70
 *
 * Cloak page 2: ProcessHeap (= PEB + 0x30 deref)
 *   _HEAP.Flags                offset 0x070, 4 bytes   → 强制 HEAP_GROWABLE(0x2) only
 *   _HEAP.ForceFlags           offset 0x074, 4 bytes   → 0
 *   (Win10 1809+ / Win11 整套 NT heap 偏移稳定; segment heap 默认未开)
 *
 * 已知限制:
 *   - 反作弊如果用 segment heap (Win10 RS5+ 极少进程开启) → _HEAP.Flags 偏移不同
 *   - 反作弊用 GetProcessHeaps 拿子 heap 而非 ProcessHeap → 漏抹
 *     (扩展容易: 注册时 walk PEB.NumberOfHeaps + ProcessHeaps[])
 *   - target CR3 在生命周期内可能因 KVAS 切换有 shadow/user 两份, 我们用
 *     HvVtRootGetResolvedUserCr3 拿真 user CR3, 仅 user-mode 访问会被分类.
 *
 * IRQL:
 *   Initialize/Shutdown/SetupVcpu/Register/Unregister 都在 PASSIVE.
 *   ClassifyAndSwitchEptp/HandleEptViolation/HandleMtfExit 都在 root mode
 *   (任意 IRQL), 严禁调 DbgPrint 之外的 Pa*** / Mm***.
 */

#ifndef _HV_PEB_CLOAK_H_
#define _HV_PEB_CLOAK_H_

#include "HvTypes.h"
#include "EptHook.h"   // EPT_PTE_ENTRY

// ============================================================
// 常量
// ============================================================

#define HV_PEB_CLOAK_MAX_TARGETS  16
#define HV_PEB_CLOAK_MAX_CPUS     64
#define HV_PEB_CLOAK_MAX_PAGES_PER_TARGET 4   // PEB + ProcessHeap (+预留 2 个扩展槽)

// caller class (per-vcpu LastCallerClass)
#define HV_PEB_CLASS_UNKNOWN     0xFF
#define HV_PEB_CLASS_MAIN        0     // 主 EPT
#define HV_PEB_CLASS_PEB_SPOOF   1     // spoof EPT

// PEB 字段偏移 (x64)
#define HV_PEB_OFF_BEING_DEBUGGED   0x002
#define HV_PEB_OFF_NT_GLOBAL_FLAG   0x068
#define HV_PEB_OFF_PROCESS_HEAP     0x030   // PEB.ProcessHeap (PVOID, 指 _HEAP)
#define HV_PEB_NT_GLOBAL_FLAG_MASK  0x70   // FLG_HEAP_ENABLE_TAIL_CHECK | VALIDATE_PARAMS | FREE_CHECK

// _HEAP 字段偏移 (x64, Win10 1809+ ~ Win11 24H2 稳定)
#define HV_HEAP_OFF_FLAGS           0x070   // ULONG _HEAP.Flags
#define HV_HEAP_OFF_FORCE_FLAGS     0x074   // ULONG _HEAP.ForceFlags
// 正常态 (未调试):
//   Flags      = HEAP_GROWABLE (0x2) — 极少叠加, 直接强 set 为 0x2
//   ForceFlags = 0
// 调试态:
//   Flags      |= HEAP_TAIL_CHECKING_ENABLED(0x20) | HEAP_FREE_CHECKING_ENABLED(0x40) |
//                 HEAP_VALIDATE_PARAMETERS_ENABLED(0x40000000)
//   ForceFlags |= 同上 (子集)
#define HV_HEAP_FLAGS_CLEAN         0x00000002UL   // HEAP_GROWABLE only
#define HV_HEAP_FORCE_FLAGS_CLEAN   0x00000000UL

// ============================================================
// 数据结构
// ============================================================

/*
 * 一个被 cloak 的页 (PEB 页 / ProcessHeap 页 / ...).
 *
 * GuestVa      page-aligned guest VA (调试用)
 * GpaPage      page-aligned guest physical address
 * OriginalPfn  = GpaPage >> 12
 * PatchVa      补丁页 KVA (PASSIVE 层填补丁数据用)
 * PatchPfn     补丁页 PFN
 * CloakedPte   每核 spoof EPT 上对应的 PT slot 指针
 */
typedef struct _HV_PEB_CLOAK_PAGE {
    ULONG64        GuestVa;         // page-aligned user VA
    ULONG64        GpaPage;         // page-aligned GPA
    ULONG64        OriginalPfn;
    PVOID          PatchVa;
    ULONG64        PatchPfn;
    PEPT_PTE_ENTRY CloakedPte[HV_PEB_CLOAK_MAX_CPUS];
    volatile LONG  Installed;       // 1=已在 EPT 上安装 R=0
} HV_PEB_CLOAK_PAGE, *PHV_PEB_CLOAK_PAGE;

/*
 * 一个被 cloak 的 target 进程, 关联若干 cloak page.
 */
typedef struct _HV_PEB_CLOAK_TARGET {
    HANDLE             Pid;
    UINT64             UserCr3;
    HV_PEB_CLOAK_PAGE  Pages[HV_PEB_CLOAK_MAX_PAGES_PER_TARGET];
    ULONG              PageCount;
    volatile LONG      Active;       // 1=注册中, 0=已撤销
} HV_PEB_CLOAK_TARGET, *PHV_PEB_CLOAK_TARGET;

/*
 * MTF 仿真上下文 (per-CPU).
 * violation 命中后, 临时把 PT slot 切到补丁页 R=1,
 * arm MTF; guest 单步 mov 完成后, MTF exit 切回 R=0 + 原 PFN.
 *
 * 注意: P126 后 PendingPage 比 PendingTarget 更精准 (一个 target 多 page).
 */
typedef struct _HV_PEB_MTF_CONTEXT {
    volatile PHV_PEB_CLOAK_PAGE PendingPage;
    volatile LONG               Active;       // 0=空闲 1=已 arm
} HV_PEB_MTF_CONTEXT, *PHV_PEB_MTF_CONTEXT;

/*
 * Manager.
 */
typedef struct _HV_PEB_CLOAK_MANAGER {
    BOOLEAN                Initialized;
    BOOLEAN                GloballyEnabled;     // 至少一个 target 注册时 = TRUE
    KSPIN_LOCK             Lock;                // 保护 Targets[] 数组
    HV_PEB_CLOAK_TARGET    Targets[HV_PEB_CLOAK_MAX_TARGETS];
    volatile LONG          TargetCount;
    HV_PEB_MTF_CONTEXT     MtfContext[HV_PEB_CLOAK_MAX_CPUS];

    // 统计
    volatile LONG64        SwitchCountMain;
    volatile LONG64        SwitchCountPebSpoof;
    volatile LONG64        ViolationHits;
    volatile LONG64        MtfCompletions;
} HV_PEB_CLOAK_MANAGER, *PHV_PEB_CLOAK_MANAGER;

extern HV_PEB_CLOAK_MANAGER g_PebCloakManager;

// ============================================================
// 生命周期 API
// ============================================================

/*
 * Driver init 调一次.
 * IRQL = PASSIVE_LEVEL.
 */
NTSTATUS HvPebCloakInitialize(VOID);

/*
 * Driver unload 调.
 * IRQL = PASSIVE_LEVEL.
 */
VOID HvPebCloakShutdown(VOID);

/*
 * 给指定 vcpu 建第二份 EPT 实例 (EptPebSpoof) + 缓存两个 EPTP.
 * 调用时机: HvSetupEpt 之后, 每核一次.
 * IRQL = PASSIVE_LEVEL.
 */
NTSTATUS HvPebCloakSetupVcpu(_Inout_ PVCPU_DATA Vcpu);

// ============================================================
// Target 注册
// ============================================================

/*
 * 注册一个 target 进程做 PEB cloak.
 *   - 解析 target user CR3 (VtRoot KVAS-safe)
 *   - 解析 PEB VA (PsGetProcessPeb) → walk page table → 拿 PA → PFN
 *   - 分配补丁页, 复制原 PEB 页内容, 把 3 字段改 0
 *   - 在所有 vcpu 的 EptPebSpoof 上 split 那 2MB 大页 → PT, PEB 页 PT slot R=0
 * 重复注册同一 PID 直接返回成功.
 * IRQL = PASSIVE_LEVEL.
 */
NTSTATUS HvPebCloakRegisterTarget(_In_ HANDLE Pid);

/*
 * 撤销 target 注册. 释放补丁页, 把 PEB 页 PT slot 改回原 PFN + R/W/X.
 * 安全:重复撤销/未注册都 no-op.
 * IRQL = PASSIVE_LEVEL.
 */
VOID HvPebCloakUnregisterTarget(_In_ HANDLE Pid);

// ============================================================
// Hot path (vmexit)
// ============================================================

/*
 * vmexit 入口分类: 当前 vcpu 应该用哪份 EPT.
 *   SnoopedCr3 = target user CR3 → 切到 EptPebSpoof
 *   其他       → 切到主 EPT
 * 空载 (无 target 注册) 时一次 BOOLEAN 即返回.
 * IRQL = root mode 任意.
 */
VOID HvPebCloakClassifyAndSwitchEptp(
    _Inout_ PVCPU_DATA Vcpu,
    _In_ UINT64 SnoopedCr3);

/*
 * EPT violation 入口: 检查 Gpa 是否命中 cloak 的 PEB 页.
 *   命中 → 切补丁页 PFN + R=1/W=0/X=0, arm MTF, return TRUE
 *   未命中 → return FALSE
 * IRQL = root mode 任意.
 */
BOOLEAN HvPebCloakHandleEptViolation(
    _In_ ULONG64 Gpa,
    _In_ ULONG64 Qualification,
    _Inout_ PGUEST_CONTEXT Ctx);

/*
 * MTF vmexit 入口: 切回原 PFN + R=0, 关 MTF.
 * 返回 TRUE = 这次 MTF 是 PEB cloak 触发的.
 * IRQL = root mode 任意.
 */
BOOLEAN HvPebCloakHandleMtfExit(_Inout_ PGUEST_CONTEXT Ctx);

/*
 * Process notify: target 退出时自动撤销.
 * IRQL = PASSIVE_LEVEL.
 */
VOID HvPebCloakOnProcessExit(_In_ HANDLE Pid);

#endif // _HV_PEB_CLOAK_H_
