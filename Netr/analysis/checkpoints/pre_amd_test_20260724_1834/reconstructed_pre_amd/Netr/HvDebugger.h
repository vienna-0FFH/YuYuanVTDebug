/*
 * HvDebugger.h
 *
 * 阶段 7: 调试器赋能模块
 *
 * 提供:
 *  - 每被保护进程的 DR0-DR3 + DR7 影子寄存器表
 *  - CR3 切换时硬件 DR 装载/清零
 *  - #DB 命中事件投递到调试器的 ring buffer
 *  - VMCS/VMCB 预置 MOV-DR/CR3 拦截，引用计数提供空闲 fast path
 *
 * 设计:
 *  - V1: per-process HWBP (一个被保护进程共享一套 DR0-3+DR7)
 *  - V2: 最多 32 个 target 共享一个无锁 CR3 快照
 *  - V1: 命中 #DB 后只投递事件,调试器用户态自行 NtSuspendThread
 */

#ifndef _HV_DEBUGGER_H_
#define _HV_DEBUGGER_H_

#pragma once

#include <ntddk.h>

// ============================================================
// 常量
// ============================================================

#define HV_DBG_TAG              'gbDH'
#define HV_DBG_MAX_RINGS        8       // 最多并发调试器
#define HV_DBG_RING_SIZE        256     // 每个 ring 的事件数(必须是 2 的幂)
#define HV_DBG_RING_MASK        (HV_DBG_RING_SIZE - 1)

// HWBP 类型 (DR7 R/W bits 编码)
#define HV_HWBP_TYPE_EXEC       0
#define HV_HWBP_TYPE_WRITE      1
#define HV_HWBP_TYPE_IO         2       // (保留,通常不可用)
#define HV_HWBP_TYPE_RW         3

// ============================================================
// 数据结构
// ============================================================

// 单个 HWBP 槽位
typedef struct _HV_HWBP_SLOT {
    BOOLEAN Active;          // 该 DR 槽是否启用
    UCHAR   Length;          // 1/2/4/8 字节
    UCHAR   Type;            // HV_HWBP_TYPE_*
    UCHAR   Reserved;
    UINT64  Address;         // DR0/1/2/3 值
} HV_HWBP_SLOT, *PHV_HWBP_SLOT;

// 每被保护进程的断点集合
typedef struct _HV_PROCESS_HWBP {
    LIST_ENTRY Link;
    HANDLE TargetPid;
    HANDLE DebuggerPid;       // 谁拥有这些断点
    HV_HWBP_SLOT Slots[4];    // DR0-DR3
    UINT64 ComputedDr7;       // 根据 Slots 计算的 DR7
    LONG   ActiveCount;       // 几个槽位生效
    UINT64 CachedCr3;         // 目标进程的 CR3 (cache,加速 VM-Exit 比对)
} HV_PROCESS_HWBP, *PHV_PROCESS_HWBP;

// HV_DEBUG_EVENT::Kind
#define HV_DBG_EVT_HWBP   0u    // 硬件断点命中 (Dr6 + HitSlot 有效)
#define HV_DBG_EVT_SWBP   1u    // 软断点命中  (int3)
#define HV_DBG_EVT_STEP   2u    // 单步         (P51)

// 调试事件 (HWBP / SWBP / STEP 命中时投递)
typedef struct _HV_DEBUG_EVENT {
    UINT64 Sequence;
    HANDLE Tid;
    HANDLE Pid;
    UINT64 Cr3;
    UINT64 Rip;
    UINT64 Rsp;
    UINT64 Rflags;
    // GPR 顺序与 GUEST_CONTEXT 一致: Rax,Rbx,Rcx,Rdx,Rsi,Rdi,Rbp,R8..R15
    UINT64 Gpr[15];
    UINT64 Dr6;
    ULONG  HitSlot;           // HWBP: 0-3,哪个 DR 触发的; SWBP/STEP: 0
    ULONG  Kind;              // HV_DBG_EVT_*
    PVOID  ThreadToken;       // root-captured ETHREAD/KTHREAD identity; opaque
} HV_DEBUG_EVENT, *PHV_DEBUG_EVENT;

// ============================================================
// 初始化/清理
// ============================================================

NTSTATUS HvDbgInitialize(VOID);
NTSTATUS HvDbgBeginShutdown(VOID);
VOID     HvDbgCleanup(VOID);
BOOLEAN  HvDbgIsInitialized(VOID);

// ============================================================
// HWBP 管理
// ============================================================

NTSTATUS
HvDbgSetHwBp(
    _In_ HANDLE DebuggerPid,
    _In_ HANDLE TargetPid,
    _In_ ULONG SlotIndex,         // 0-3
    _In_ UINT64 Address,
    _In_ UCHAR Length,            // 1/2/4/8
    _In_ UCHAR Type               // HV_HWBP_TYPE_*
);

NTSTATUS
HvDbgClearHwBp(
    _In_ HANDLE TargetPid,
    _In_ ULONG SlotIndex
);

NTSTATUS
HvDbgClearHwBpOwned(
    _In_ HANDLE DebuggerPid,
    _In_ HANDLE TargetPid,
    _In_ ULONG SlotIndex
);

NTSTATUS
HvDbgClearAllForDebugger(
    _In_ HANDLE DebuggerPid
);

// 按 debugger + target 所有权精确清理 DR fallback。
// Bridge UNBIND 使用该入口，避免一个目标解绑时影响同一调试器的其他目标。
NTSTATUS
HvDbgClearAllForDebuggerTarget(
    _In_ HANDLE DebuggerPid,
    _In_ HANDLE TargetPid
);

// 按 target PID 清理 (进程退出时由 Ps notify 回调使用)
// 同步清理无锁 CR3 快照中的对应项
NTSTATUS
HvDbgClearAllForPid(
    _In_ HANDLE TargetPid
);

// 内部查询 (供 VM-Exit handler 使用)
// 注:调用者必须自己持锁 g_HwbpListLock
PHV_PROCESS_HWBP HvDbgFindByPidLocked(_In_ HANDLE Pid);
PHV_PROCESS_HWBP HvDbgFindByCr3Locked(_In_ UINT64 Cr3);

// 锁 (供外部 VM-Exit handler 用)
extern KSPIN_LOCK g_HwbpListLock;

// 全局生效 HWBP 引用计数
extern volatile LONG  g_GlobalHwbpRefCount;

// Shared debugger-exit ownership. Real DR breakpoints require CR3-load and
// MOV-DR exits; EPT vwatch entries require CR3-load exits only.
#define HV_DBG_INTERCEPT_MODE_CR3       0x1U
#define HV_DBG_INTERCEPT_MODE_MOV_DR    0x2U
#define HV_DBG_INTERCEPT_MODE_MASK      0x3U
#define HV_DBG_INTERCEPT_MODE_UNKNOWN   ((LONG)-1)

extern volatile LONG g_VwatchCr3InterceptRefCount;
extern volatile LONG g_DebugInterceptPublishedMode;
extern volatile LONG g_DebugInterceptPublishFailures;

BOOLEAN HvDebuggerPublishedMovDrExiting(VOID);

// ============================================================
// 硬件 DR 装载/清零 (CR3 切换路径调用)
// ============================================================

VOID HvDbgLoadHardwareDr(_In_ PHV_PROCESS_HWBP Hwbp);
VOID HvDbgClearHardwareDr(VOID);

UINT64 HvDbgReadRealDr(_In_ ULONG DrNum);
VOID   HvDbgWriteRealDr(_In_ ULONG DrNum, _In_ UINT64 Value);

// CR3-Load vmexit hot path 调用。0 锁，只读多目标 seqlock 快照。
// NewCr3 是即将写入 GUEST_CR3/VMCB.CR3 的值；命中时装载真硬件
// DR0..3，并返回应写入 guest-state 的 DR7。
UINT64 HvDbgRootOnCr3Switch(_In_ UINT64 NewCr3);
BOOLEAN HvDbgRootIsTargetCr3(_In_ UINT64 Cr3);

// Clear BeingDebugged, NtGlobalFlag, and debug heap flags in native/WOW64
// PEBs after a debugger-target relationship has been established.
NTSTATUS HvDbgScrubPebDebugState(_In_ ULONG TargetPid);

// ============================================================
// 事件 ring
// ============================================================

NTSTATUS
HvDbgEnqueueEvent(
    _In_ HANDLE DebuggerPid,
    _In_ const HV_DEBUG_EVENT* Event
);

UINT64 HvDbgReserveEventSequence(VOID);

// P113: 高 IRQL 入口 (vmx root mode / #DB vmexit). 跳过 KeSetEvent 防 BSOD.
NTSTATUS
HvDbgEnqueueEventNoSignal(
    _In_ HANDLE DebuggerPid,
    _In_ const HV_DEBUG_EVENT* Event
);

NTSTATUS
HvDbgEnqueuePrivateSwBpEventNoSignal(
    _In_ HANDLE DebuggerPid,
    _In_ const HV_DEBUG_EVENT* Event
);

NTSTATUS
HvDbgEnqueuePrivateSwBpEventRootNoSignal(
    _In_ ULONG CpuIndex,
    _In_ HANDLE DebuggerPid,
    _In_ const HV_DEBUG_EVENT* Event
);

NTSTATUS
HvDbgWaitDequeueEvent(
    _In_ HANDLE DebuggerPid,
    _Out_ HV_DEBUG_EVENT* OutEvent,
    _In_ ULONG TimeoutMs   // MAXULONG = INFINITE
);

VOID HvDbgDiscardEventsForDebugger(_In_ HANDLE DebuggerPid);
VOID HvDbgDiscardEventsForTarget(
    _In_ HANDLE DebuggerPid,
    _In_ HANDLE TargetPid);

// ============================================================
// VMCS/VMCB debugger exits are published only while HWBP state is active.
// ============================================================

NTSTATUS HvDbgEnableInterceptsAllCpus(VOID);
NTSTATUS HvDbgDisableInterceptsAllCpus(VOID);

NTSTATUS HvDbgAcquireVwatchCr3Intercept(VOID);
NTSTATUS HvDbgReleaseVwatchCr3Intercepts(_In_ ULONG Count);

// Compatibility entry points retained for existing callers.
VOID HvDbgRootEnableInterceptsCurrentCpu(VOID);
VOID HvDbgRootDisableInterceptsCurrentCpu(VOID);

// VMCALL service used to publish or withdraw debugger exits per CPU.
#define VMCALL_SET_DEBUGGER_INTERCEPT_MODE  0xEBF00024U

// 重新按当前 guest CR3 发布 DR0..3/DR7。解绑后广播到所有 VCPU，
// 消除“等下一次 CR3 switch 才清掉旧 DR”的残留窗口。
#define VMCALL_REFRESH_HWBP_STATE      0xEBF00022U

// ============================================================
// 软断点 (P50) — driver 维护注册列表,#BP vmexit 时反查
//   GUI 通过 IOCTL_HV_SW_BP_ADD / _DEL 注册 (实际 int3 字节由 R3
//   WriteProcessMemory 写;driver 只需要记 (target_pid, rip, debugger_pid)
//   命中时 enqueue 到对应 debugger 的 ring)。
// ============================================================
NTSTATUS HvDbgRegisterSwBp(
    _In_ HANDLE DebuggerPid,
    _In_ HANDLE TargetPid,
    _In_ UINT64 Address);

NTSTATUS HvDbgUnregisterSwBp(
    _In_ HANDLE TargetPid,
    _In_ UINT64 Address);

VOID HvDbgClearAllSwBpForPid(_In_ HANDLE TargetPid);
VOID HvDbgClearAllSwBpForDebugger(_In_ HANDLE DebuggerPid);

// VMExit handler 调,查命中 #BP 的 (target_pid, rip) 是否登记过 sw bp。
// 返回对应的 debugger_pid 用于事件投递。0 = 不是我们的断点。
HANDLE HvDbgLookupSwBpOwner(_In_ HANDLE TargetPid, _In_ UINT64 Address);
HANDLE HvDbgLookupSwBpOwnerByCr3(
    _In_ UINT64 GuestCr3,
    _In_ UINT64 Address,
    _Out_opt_ HANDLE* OutTargetPid);

// ============================================================
// 单步 (P51) — debugger 标记某 tid 要单步, R3 set TF=1+resume,
//   下一条指令引发 #DB(BS bit), vmexit handler 检查是不是我们标记的 tid,
//   是则上报 cat=BREAK_HIT 不重新注入; 否则照旧重新注入给 guest。
// ============================================================
NTSTATUS HvDbgArmStep(_In_ HANDLE DebuggerPid, _In_ HANDLE TargetTid);
BOOLEAN  HvDbgConsumeStep(_In_ HANDLE TargetTid, _Out_ HANDLE* OutDebuggerPid);
VOID     HvDbgClearAllStepForDebugger(_In_ HANDLE DebuggerPid);

#endif // _HV_DEBUGGER_H_
