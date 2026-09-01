/*
 * EptHook.h
 * 
 * EPT Hook 模块 - 用于实现隐身 Hook（绕过 PatchGuard）
 * 
 * 原理：
 *   - 使用 EPT 分页欺骗技术
 *   - 读取时返回原始代码（PG 检查通过）
 *   - 执行时跳转到 Hook 代码
 */

#ifndef _EPT_HOOK_H_
#define _EPT_HOOK_H_

#pragma once

#include <ntddk.h>
#include <intrin.h>

typedef struct _VCPU_DATA VCPU_DATA, *PVCPU_DATA;

// ============================================================
// 常量定义
// ============================================================

#define MAX_EPT_HOOKS           64
#define EPT_HOOK_TAG            'kpEH'
#define EPT_HOOK_PAGE_TAG       'gpEH'
#define PAGE_SIZE_4KB           0x1000
#define PAGE_MASK               (~0xFFFULL)
#define EPT_HOOK_PATCH_SIZE     14
#define EPT_HOOK_MAX_PENDING_PAGES 8

// ============================================================
// 调试开关
// ============================================================
#define EPT_HOOK_SIMPLE_MODE    0   // 1=简单模式(固定14字节,无重定位), 0=完整模式(带指令解码和重定位)
#define EPT_HOOK_TEST_NO_CALL   0   // 1=禁用跳板调用(直接返回,用于测试), 0=正常调用

// EPT 权限位
#define EPT_READ                (1 << 0)
#define EPT_WRITE               (1 << 1)
#define EPT_EXECUTE             (1 << 2)
#define EPT_RWX                 (EPT_READ | EPT_WRITE | EPT_EXECUTE)

// EPT Violation Exit Qualification
#define EPT_VIOLATION_READ      (1 << 0)
#define EPT_VIOLATION_WRITE     (1 << 1)
#define EPT_VIOLATION_EXECUTE   (1 << 2)

// ============================================================
// 数据结构
// ============================================================

// Hook 类型
typedef enum _EPT_HOOK_TYPE {
    EptHookTypeInline,      // 内联 Hook（修改函数开头）
    EptHookTypePage,        // 整页 Hook
} EPT_HOOK_TYPE;

// Hook 状态
typedef enum _EPT_HOOK_STATE {
    EptHookStatePrepared  = 0, // 资源/跳板已就绪，尚未修改 EPT leaf
    EptHookStateActive    = 1, // 已发布到 EPT，可进入 HookFunction
    EptHookStateQuiescing = 2, // 正在撤销；失败时保持此态供同一句柄重试
    EptHookStateRetired   = 3, // 已从活动链摘除，资源等待 manager cleanup 回收
} EPT_HOOK_STATE;

// EPT PTE 结构（用于修改权限）
typedef union _EPT_PTE_ENTRY {
    ULONG64 Value;
    struct {
        ULONG64 Read : 1;
        ULONG64 Write : 1;
        ULONG64 Execute : 1;
        ULONG64 MemoryType : 3;
        ULONG64 IgnorePat : 1;
        ULONG64 LargePage : 1;
        ULONG64 Accessed : 1;
        ULONG64 Dirty : 1;
        ULONG64 ExecuteForUserMode : 1;
        ULONG64 Ignored1 : 1;
        ULONG64 PhysicalAddress : 40;
        ULONG64 Ignored2 : 11;
        ULONG64 SuppressVe : 1;
    };
} EPT_PTE_ENTRY, *PEPT_PTE_ENTRY;

// EPT Hook 条目
typedef struct _EPT_HOOK_ENTRY {
    struct _EPT_HOOK_PAGE* PageOwner;
    UCHAR PatchBytes[EPT_HOOK_PATCH_SIZE];
    BOOLEAN PatchInstalled;
    LIST_ENTRY ListEntry;           // 链表节点
    
    volatile EPT_HOOK_STATE State;  // Hook 状态（control/root 跨 CPU 发布）
    EPT_HOOK_TYPE Type;             // Hook 类型
    
    // 目标信息
    PVOID TargetVirtualAddress;     // 目标虚拟地址
    ULONG64 TargetPhysicalAddress;  // 目标物理地址（页对齐）
    ULONG OffsetInPage;             // 页内偏移
    
    // 伪造页（包含 Hook 代码）
    PVOID FakePageVirtual;          // 伪造页虚拟地址
    ULONG64 FakePagePhysical;       // 伪造页物理地址
    
    // 目标页对应的 EPT 条目 — per-CPU 数组 (P1-3, HyperDbg 范式)
    // 每个 CPU 的 EPT 表独立 split,自己的 PT,自己的 PTE 指针。
    // 安装时遍历填充 (PASSIVE_LEVEL); root mode 使用 VCPU_DATA.ProcessorNumber。
    // 旧实现是单指针共享 PT,Win11 高频 syscall 多核策略冲突死循环。
    PEPT_PTE_ENTRY TargetPte[64];
    ULONG TargetPteCount;           // Activate 成功发布的 per-CPU leaf 数
    ULONG64 OriginalPteValue[64];   // Activate 前的完整 per-CPU leaf，Remove 必须逐值恢复
    
    // 原始数据
    UCHAR OriginalBytes[32];        // 原始字节（增大以容纳完整指令序列）
    ULONG OriginalBytesLength;      // 原始字节长度（由指令长度解码器计算）

    // 跳板重写元信息 (方案 A: 真指令重写器)
    ULONG TrampolineWriteLength;    // trampoline 池里实际写入字节(不含 14 字节 jmp-back)
    ULONG TrampolineInstCount;      // 重写器处理的指令条数 (调试用)

    // Hook 函数
    PVOID HookFunction;             // Hook 处理函数
    PVOID TrampolineAddress;        // 跳板地址（调用原函数）
    
    // 统计
    volatile LONG64 HitCount;       // 命中次数
    volatile LONG   Removing;       // control-plane removal owner
    BOOLEAN OverlayVisible;
    
} EPT_HOOK_ENTRY, *PEPT_HOOK_ENTRY;

/* Unique SLAT/fake-page owner for one target GPA page. */
typedef struct _EPT_HOOK_PAGE {
    LIST_ENTRY ListEntry;
    volatile EPT_HOOK_STATE State;
    PVOID TargetPageVirtual;
    ULONG64 TargetPhysicalAddress;
    PVOID FakePageVirtual;
    ULONG64 FakePagePhysical;
    PEPT_PTE_ENTRY TargetPte[64];
    ULONG TargetPteCount;
    ULONG64 OriginalPteValue[64];
    PEPT_PTE_ENTRY OverlayTargetPte[64];
    ULONG OverlayTargetPteCount;
    ULONG64 OverlayOriginalPteValue[64];
    ULONG SiteCount;
    ULONG ActiveSiteCount;
    ULONG OverlaySiteCount;
    volatile PEPT_HOOK_ENTRY AccountingSite;
    volatile PEPT_HOOK_ENTRY MutationSite;
    volatile LONG MutationKind;
    BOOLEAN PageUnlinked;
    volatile LONG64 HitCount;
} EPT_HOOK_PAGE, *PEPT_HOOK_PAGE;

// 每 CPU MTF 上下文
// 注意：使用 volatile 确保编译器不会优化掉内存访问
// MtfActive 使用 LONG 以支持 Interlocked 原子操作
typedef struct _EPT_MTF_CONTEXT {
    volatile PEPT_HOOK_PAGE PendingPage[EPT_HOOK_MAX_PENDING_PAGES];
    volatile LONG PendingPageCount;
    volatile LONG MtfActive; // 0=IDLE, 1=PUBLISHING, 2=ARMED, 3=COMPLETING
} EPT_MTF_CONTEXT, *PEPT_MTF_CONTEXT;

// EPT Hook 管理器
typedef struct _EPT_HOOK_MANAGER {
    LIST_ENTRY PageList;
    ULONG PageCount;
    LIST_ENTRY RetiredPageList;
    ULONG RetiredPageCount;
    // Hook 链表
    LIST_ENTRY HookList;
    ULONG HookCount;
    LIST_ENTRY RetiredHookList;
    ULONG RetiredHookCount;
    
    // 同步
    KSPIN_LOCK Lock;
    FAST_MUTEX MutationMutex;
    volatile LONG RootEpoch;
    volatile LONG RootReaders[2];
    
    // 跳板页（存放跳板代码）
    PVOID TrampolinePool;
    ULONG64 TrampolinePoolPhysical;
    ULONG TrampolinePoolUsed;
    
    // 每 CPU MTF 上下文（最多 64 个 CPU）
    EPT_MTF_CONTEXT MtfContext[64];
    
    // 状态
    BOOLEAN Initialized;
    
    // Execute-Only EPT 支持
    // 如果支持，使用 R=0,W=0,X=1 配置，读取时触发 Violation
    // 如果不支持，使用 R=1,W=1,X=0 配置，执行时触发 Violation（有竞态风险）
    BOOLEAN ExecuteOnlySupported;
    
} EPT_HOOK_MANAGER, *PEPT_HOOK_MANAGER;

// Hook 回调函数类型
typedef NTSTATUS(*EPT_HOOK_CALLBACK)(
    PEPT_HOOK_ENTRY HookEntry,
    PVOID Context
);

// ============================================================
// 函数声明
// ============================================================

//
// 初始化和清理
//

/*
 * 初始化 EPT Hook 管理器
 */
NTSTATUS
EptHookInitialize(VOID);

/*
 * 清理 EPT Hook 管理器
 */
VOID
EptHookCleanup(VOID);

//
// Hook 管理
//

/*
 * 安装 EPT Hook
 * 
 * @param TargetAddress  要 Hook 的目标地址
 * @param HookFunction   Hook 处理函数
 * @param OutHookEntry   返回 Hook 条目（可选）。如果 Activate 失败且回滚
 *                       Remove 也未完成，仍返回保留的 Quiescing 句柄，
 *                       以便调用方重试 EptHookRemove。未提供输出时由
 *                       manager HookList 保留归属，RemoveAll 后续重试。
 * @return NTSTATUS
 */
NTSTATUS
EptHookInstall(
    _In_ PVOID TargetAddress,
    _In_ PVOID HookFunction,
    _Out_opt_ PEPT_HOOK_ENTRY* OutHookEntry
);

/*
 * Two-phase publication. Prepare reserves the target/GPA and constructs the
 * fake page and trampoline, but never redirects an EPT leaf. The returned
 * handle and trampoline may therefore be published by the owner before
 * EptHookActivate makes HookFunction reachable.
 */
NTSTATUS
EptHookPrepare(
    _In_ PVOID TargetAddress,
    _In_ PVOID HookFunction,
    _Out_ PEPT_HOOK_ENTRY* OutHookEntry,
    _Out_ PVOID* OutTrampoline
);

NTSTATUS
EptHookSetOverlayVisiblePrepared(
    _In_ PEPT_HOOK_ENTRY HookEntry,
    _In_ BOOLEAN Visible
);

NTSTATUS
EptHookActivate(
    _In_ PEPT_HOOK_ENTRY HookEntry
);

/*
 * 移除 EPT Hook
 */
NTSTATUS
EptHookRemove(
    _In_ PEPT_HOOK_ENTRY HookEntry
);

/*
 * 移除指定地址的 Hook
 */
NTSTATUS
EptHookRemoveByAddress(
    _In_ PVOID TargetAddress
);

/*
 * 移除所有 Hook
 */
VOID
EptHookRemoveAll(VOID);

//
// EPT Violation 处理
//

/*
 * 处理 EPT Violation
 * 由 VM Exit Handler 调用
 * 
 * @param GuestPhysicalAddress  触发违规的物理地址
 * @param ExitQualification     退出资格
 * @return TRUE 如果已处理，FALSE 如果需要其他处理
 */
BOOLEAN
EptHookHandleViolation(
    _In_ PVCPU_DATA VcpuData,
    _In_ ULONG64 GuestPhysicalAddress,
    _In_ ULONG64 ExitQualification
);

/*
 * 处理 Monitor Trap Flag Exit
 * 由 VM Exit Handler 调用
 * 用于在单步执行后恢复 EPT 权限（防止 PatchGuard 检测）
 * 
 * @return TRUE 如果已处理，FALSE 如果需要其他处理
 */
BOOLEAN
EptHookHandleMtfExit(_In_ PVCPU_DATA VcpuData);

//
// EPT 页表操作
//

/*
 * 修改 EPT PTE 权限
 */
NTSTATUS
EptModifyPagePermissions(
    _In_ ULONG64 PhysicalAddress,
    _In_ ULONG64 NewPermissions
);

/*
 * 将物理页映射到另一个物理页
 */
NTSTATUS
EptRemapPage(
    _In_ ULONG64 OriginalPhysical,
    _In_ ULONG64 NewPhysical,
    _In_ ULONG64 Permissions
);

//
// 辅助函数
//

/*
 * 根据物理地址查找 Hook
 */
PEPT_HOOK_ENTRY
EptHookFindByPhysicalAddress(
    _In_ ULONG64 PhysicalAddress
);

BOOLEAN
EptHookRootOwnsPhysicalPage(
    _In_ PVCPU_DATA VcpuData,
    _In_ ULONG64 PhysicalAddress
);

/*
 * 根据虚拟地址查找 Hook
 */
PEPT_HOOK_ENTRY
EptHookFindByVirtualAddress(
    _In_ PVOID VirtualAddress
);

/*
 * 调用原函数（通过跳板）
 */
PVOID
EptHookGetTrampoline(
    _In_ PEPT_HOOK_ENTRY HookEntry
);

//
// 调试函数
//

/*
 * 打印当前 EPT 结构信息
 * 自动检测 EPTP 和页表结构
 */
VOID
EptPrintInfo(VOID);

/*
 * 检查 EPT 是否正确配置
 */
BOOLEAN
EptIsConfigured(VOID);

//
// 高级功能：进程/驱动隐藏
//

/*
 * 安装进程隐藏 Hook（按进程ID）
 * Hook NtQuerySystemInformation 来过滤进程列表
 * 
 * @param ProcessId  要隐藏的进程 ID（0 表示只安装 Hook）
 * @return NTSTATUS
 */
NTSTATUS
EptHookHideProcess(
    _In_ ULONG ProcessId
);

/*
 * Hidden-process backend state. These routines never install or remove an
 * EPT hook; HvHook uses them when it owns the shared syscall interception.
 */
NTSTATUS
EptHookAddHiddenProcessState(
    _In_ ULONG ProcessId
);

NTSTATUS
EptHookRemoveHiddenProcessState(
    _In_ ULONG ProcessId
);

BOOLEAN
EptHookIsProcessHidden(
    _In_ ULONG ProcessId
);

ULONG
EptHookGetHiddenProcessCount(VOID);

VOID
EptHookFilterProcessInformation(
    _In_ ULONG SystemInformationClass,
    _Inout_updates_bytes_(SystemInformationLength) PVOID SystemInformation,
    _In_ ULONG SystemInformationLength
);

// 2026-06-18: 检查 PID 是否在隐藏列表里。给 HvHook.c::HookedNtOpenProcess
// (合并后唯一的 NtOpenProcess hook) 用。
/* Legacy compatibility alias. */
BOOLEAN IsProcessHiddenById(ULONG ProcessId);

// 2026-06-18: SystemProcessInformation 过滤函数 — 合并到 HvHook.c::HookedNtQuerySystemInformation 用
// 实现在 EptHook.c, 但通过 HvHook 入口调用 (统一 hook)
VOID FilterProcessList(PVOID SystemInformation);
VOID FilterHandleList(PVOID SystemInformation, ULONG SystemInformationLength);
VOID FilterExtendedHandleList(PVOID SystemInformation, ULONG SystemInformationLength);
VOID FilterSessionProcessList(PVOID SystemInformation);
// 隐藏进程/驱动 PID 计数, 给 hook 内 fast-path 用
extern ULONG g_HiddenProcessCount;
extern ULONG g_HiddenDriverCount;

/*
 * 根据进程名隐藏进程
 * 会自动安装 Hook（如果尚未安装）
 * 
 * @param ProcessName  要隐藏的进程名（如 "notepad.exe"）
 *                     不区分大小写，最大长度 63 字符
 * @return NTSTATUS
 */
NTSTATUS
EptHookHideProcessByName(
    _In_ PCWSTR ProcessName
);

/*
 * 取消隐藏指定进程名
 * 
 * @param ProcessName  要取消隐藏的进程名
 * @return NTSTATUS
 */
NTSTATUS
EptHookUnhideProcessByName(
    _In_ PCWSTR ProcessName
);

/*
 * 取消隐藏指定进程ID
 * 
 * @param ProcessId  要取消隐藏的进程ID
 * @return NTSTATUS
 */
NTSTATUS
EptHookUnhideProcess(
    _In_ ULONG ProcessId
);

//
// 高级功能：文件隐藏
//

/*
 * 安装文件隐藏 Hook (NtQueryDirectoryFile)
 * 
 * @return NTSTATUS
 */
NTSTATUS
EptHookInstallFileHideHook(VOID);

NTSTATUS
EptHookInstallFileHideHookAtAddress(
    _In_ PVOID NtQueryDirectoryFileAddress
);

/*
 * 移除文件隐藏 Hook
 * 
 * @return NTSTATUS
 */
NTSTATUS
EptHookRemoveFileHideHook(VOID);

/*
 * 添加文件到隐藏列表
 * 
 * @param FileName  文件名（可带或不带路径）
 * @return NTSTATUS
 */
NTSTATUS
EptHookHideFile(
    _In_ PCWSTR FileName
);

/*
 * 从隐藏列表移除文件
 * 
 * @param FileName  文件名
 * @return NTSTATUS
 */
NTSTATUS
EptHookUnhideFile(
    _In_ PCWSTR FileName
);

//
// 高级功能：驱动隐藏（基于 EPT Hook，不触发 PatchGuard）
//
// 原理：
//   - Hook NtQuerySystemInformation 过滤 SystemModuleInformation (11)
//   - Hook ObReferenceObjectByName 阻止通过名称查找驱动对象
//   - 不修改任何内核数据结构（不断链、不修改 PsLoadedModuleList）
//

/*
 * 安装驱动隐藏 Hook
 * 包括 NtQuerySystemInformation 和 ObReferenceObjectByName
 * 
 * @return NTSTATUS
 */
NTSTATUS
EptHookInstallDriverHideHook(VOID);

/*
 * 移除驱动隐藏 Hook
 * 
 * @return NTSTATUS
 */
NTSTATUS
EptHookRemoveDriverHideHook(VOID);

/*
 * Apply the Intel hidden-driver list to a validated
 * SystemModuleInformation buffer.  The shared NtQuerySystemInformation
 * hook in HvHook owns the syscall interception; the backend owns only the
 * hidden-driver data and filtering policy.
 */
VOID
EptHookFilterModuleList(
    _Inout_updates_bytes_(ModuleInfoLength) PVOID ModuleInfo,
    _In_ ULONG ModuleInfoLength
);

/*
 * 隐藏驱动（通过驱动对象）
 * 将驱动添加到隐藏列表，不修改任何内核结构
 * 
 * @param DriverObject  驱动对象
 * @return NTSTATUS
 */
NTSTATUS
EptHookHideDriver(
    _In_ PDRIVER_OBJECT DriverObject
);

/*
 * 隐藏驱动（通过名称）
 * 
 * @param DriverName  驱动服务名（如 "Netr"，不带 .sys）
 * @return NTSTATUS
 */
NTSTATUS
EptHookHideDriverByName(
    _In_ PCWSTR DriverName
);

/*
 * 取消隐藏驱动
 * 
 * @param DriverObject  驱动对象
 * @return NTSTATUS
 */
NTSTATUS
EptHookUnhideDriver(
    _In_ PDRIVER_OBJECT DriverObject
);

/*
 * 获取隐藏驱动数量
 * 
 * @return 隐藏驱动数量
 */
ULONG
EptHookGetHiddenDriverCount(VOID);

/*
 * 打印隐藏驱动列表
 */
VOID
EptHookPrintHiddenDrivers(VOID);

//
// VMX 模式管理（供 VM Exit Handler 使用）
//

/*
 * 设置 VMX root 模式标志
 * 在 VM Exit Handler 进入/退出时调用
 * 
 * @param InRootMode  TRUE = 进入 VMX root 模式, FALSE = 退出
 */
VOID
EptSetVmxRootMode(
    _In_ PVCPU_DATA VcpuData,
    _In_ BOOLEAN InRootMode
);

// ============================================================
// 全局变量
// ============================================================

extern EPT_HOOK_MANAGER g_EptHookManager;

// EPT 版本号（用于多 CPU TLB 同步）
extern volatile LONG64 g_EptVersion;

// ============================================================
// 多 CPU EPT TLB 同步
// ============================================================

/*
 * 检查并刷新 EPT TLB（如果需要）
 * 在每次 VM Exit 开始时调用
 * 确保当前 CPU 看到最新的 EPT 映射
 */
VOID EptCheckAndInvalidateTlb(_In_ PVCPU_DATA VcpuData);

/*
 * 跨模式 INVEPT - 自动选择正确路径
 *   - VMX root  → 直接 AsmInveptAllContexts
 *   - PASSIVE/APC + IsActive → KeIpiGenericCall 广播 VMCALL_EPT_INVEPT
 *   - 高 IRQL 但非 root + IsActive → 直接 AsmVmCall(VMCALL_EPT_INVEPT)
 *   - HV 未激活 → no-op
 *
 * 外部模块 (HvXhciEptTrap 等) 在 PASSIVE_LEVEL 修改 EPT 后必须调本函数,
 * 不能直接调 AsmInveptAllContexts (在 guest 模式会 #UD)。
 */
VOID EptInveptAllContexts(VOID);

/*
 * 跨模式 INVVPID — 与 EptInveptAllContexts 同形派发
 * 用于 Guest 页表/CR3 变化后失效 VPID 标签的 linear-translation TLB。
 * 调用规则与 EptInveptAllContexts 完全相同;严禁直接调 AsmInvvpidAllContexts
 * (在 guest 模式且无 VPID 启用时会 #UD)。
 */
VOID EptInvvpidAllContexts(VOID);

PEPT_PTE_ENTRY EptGetPteForPhysicalAddress(_In_ ULONG64 PhysicalAddress);

/*
 * 防御性恢复 (#24): 当 HvHandleEptViolation 的兜底逻辑发现某 GPA 有 EPT
 * violation 但 EptHookHandleViolation 已声明 "不是我的 hook" 时,尝试再
 * 二次定位 hook (覆盖 install/remove 竞态窗口),并做 shadow swap + MTF
 * 单步恢复,而不是盲授 RWX。
 *   - 找到活跃 hook → 切回原始页 + 开 RWX + 武装 MTF,返回 TRUE。
 *   - 找到的 hook 正在卸载 → 切回原始页 + 开 RWX,不武装 MTF,返回 TRUE。
 *   - 找不到 → 返回 FALSE,由上层决定 (#GP 注入或丢弃)。
 * 调用方运行在 VMX root 模式,IRQL=IPI_LEVEL。禁用 DbgPrint。
 */
BOOLEAN
EptHookDefensiveRecover(
    _In_ PVCPU_DATA VcpuData,
    _In_ ULONG64 GuestPhysicalAddress,
    _In_ ULONG64 ExitQualification
);

#endif // _EPT_HOOK_H_
