/*
 * HvHook.h
 * 
 * Hypervisor Hook 抽象层 - 统一 Intel EPT Hook 和 AMD NPT Hook 接口
 * 
 * 功能：
 *   - 自动检测 CPU 类型（Intel/AMD）
 *   - 提供统一的 Hook 安装/移除接口
 *   - 提供统一的进程隐藏接口
 *   - 屏蔽底层实现差异
 * 
 * 使用方式：
 *   1. 调用 HvHookInitialize() 初始化（自动检测 CPU 类型）
 *   2. 调用 HvHookInstall() 安装 Hook
 *   3. 调用 HvHookCleanup() 清理
 */

#ifndef _HV_HOOK_H_
#define _HV_HOOK_H_

#pragma once

#include <ntddk.h>
#include "HvCpu.h"

/*
 * P114: 高频 DbgPrint 开关.
 *
 * Hook 命中体内 / RPM walk / OpenProcess bypass 这些路径每次 syscall / scan
 * 都被穿过, 默认关闭日志噪声. 真要调试某个 hook 时把这个改 1 重新编译.
 *
 * 受这个开关控制的日志:
 *   - [HvHook-Spoof] / [HvHook-Restore] / [HvHook-TRACE] / [HvHook-AAD]
 *   - [HvHook] bypass open ok (失败路径 'bypass open failed' 仍正常打)
 *   - HvPhys CR3 walk / GetCr3 / GvaToHpa 信息性日志 (失败路径仍打)
 *
 * 不受影响 (永远打):
 *   - ERROR / WARN / failure 路径
 *   - Init / DriverEntry / IOCTL handler 一次性输出
 */
#ifndef HV_VERBOSE_HOOK_LOG
#define HV_VERBOSE_HOOK_LOG 0
#endif

#if HV_VERBOSE_HOOK_LOG
#define HV_HOT_DBG(...) DbgPrint(__VA_ARGS__)
#else
#define HV_HOT_DBG(...) ((void)0)
#endif

// ============================================================
// 常量定义
// ============================================================

#define HV_HOOK_TAG             'kHvH'
#define MAX_HV_HOOKS            64

// ============================================================
// 类型定义
// ============================================================

// Hook 类型（与底层实现对应）
typedef enum _HV_HOOK_TYPE {
    HvHookTypeInline,       // 内联 Hook（修改函数开头）
    HvHookTypePage,         // 整页 Hook
} HV_HOOK_TYPE;

// Hook 状态
typedef enum _HV_HOOK_STATE {
    HvHookStateInactive,    // 未激活
    HvHookStateActive,      // 已激活
    HvHookStatePaused,      // 暂停
} HV_HOOK_STATE;

// 统一的 Hook 句柄（不透明类型）
// 底层可能是 EPT_HOOK_ENTRY* 或 NPT_HOOK_ENTRY*
typedef PVOID HV_HOOK_HANDLE;

// Hook 回调函数类型
typedef NTSTATUS(*HV_HOOK_CALLBACK)(
    HV_HOOK_HANDLE HookHandle,
    PVOID Context
);

// Hook 信息结构（用于查询）
typedef struct _HV_HOOK_INFO {
    HV_HOOK_STATE State;            // Hook 状态
    HV_HOOK_TYPE Type;              // Hook 类型
    PVOID TargetVirtualAddress;     // 目标虚拟地址
    ULONG64 TargetPhysicalAddress;  // 目标物理地址
    PVOID HookFunction;             // Hook 处理函数
    PVOID TrampolineAddress;        // 跳板地址
    LONG64 HitCount;                // 命中次数
} HV_HOOK_INFO, *PHV_HOOK_INFO;

// ============================================================
// 初始化和清理
// ============================================================

/*
 * 初始化 Hypervisor Hook 管理器
 * 自动检测 CPU 类型并初始化对应的 EPT/NPT Hook 模块
 * 
 * @return NTSTATUS
 */
NTSTATUS
HvHookInitialize(VOID);

/*
 * 清理 Hypervisor Hook 管理器
 * 移除所有 Hook 并释放资源
 */
VOID
HvHookCleanup(VOID);

/* Close installation, drain/remove callbacks and report whether ownership
 * is fully retired. Safe to call repeatedly from DriverUnload. */
NTSTATUS
HvHookShutdownAndDrain(VOID);

/* Close new hook mutations and asynchronous hook-owned work before the
 * debugger/private-DebugObject teardown starts. Existing callbacks are still
 * drained by HvHookShutdownAndDrain. */
VOID
HvHookBeginShutdown(VOID);

/* Drain hook-owned PASSIVE workers after all dependent subsystem admission
 * gates have closed. This does not remove EPT/NPT hooks. */
VOID
HvHookDrainAsyncWorkers(VOID);

/*
 * 检查 Hook 管理器是否已初始化
 * 
 * @return TRUE 如果已初始化
 */
BOOLEAN
HvHookIsInitialized(VOID);

/*
 * 获取当前使用的 Hook 后端类型
 * 
 * @return CPU_VENDOR_INTEL 或 CPU_VENDOR_AMD
 */
CPU_VENDOR
HvHookGetBackendType(VOID);

// ============================================================
// Hook 管理
// ============================================================

/*
 * 安装 Hook
 * 
 * @param TargetAddress  要 Hook 的目标地址
 * @param HookFunction   Hook 处理函数
 * @param OutHandle      返回 Hook 句柄（可选）
 * @return NTSTATUS
 * 
 * 用法示例：
 *   HV_HOOK_HANDLE handle;
 *   status = HvHookInstall(NtQuerySystemInformation, MyHookFunc, &handle);
 */
NTSTATUS
HvHookInstall(
    _In_ PVOID TargetAddress,
    _In_ PVOID HookFunction,
    _Out_opt_ HV_HOOK_HANDLE* OutHandle
);

/*
 * 移除 Hook（通过句柄）
 * 
 * @param Handle  Hook 句柄
 * @return NTSTATUS
 */
NTSTATUS
HvHookRemove(
    _In_ HV_HOOK_HANDLE Handle
);

/*
 * 移除指定地址的 Hook
 * 
 * @param TargetAddress  目标地址
 * @return NTSTATUS
 */
NTSTATUS
HvHookRemoveByAddress(
    _In_ PVOID TargetAddress
);

/*
 * 移除所有 Hook
 */
VOID
HvHookRemoveAll(VOID);

/*
 * HookFunction lifetime guard. Every callback published by HvHookInstall
 * must acquire at entry before reading its trampoline or owner state, and
 * release on every exit path. A failed acquire must fail closed without
 * dereferencing the handle or trampoline.
 */
BOOLEAN
HvHookCallbackAcquire(
    _In_ HV_HOOK_HANDLE Handle
);

/* Two-phase publication. Prepare allocates the backend entry and trampoline
 * without changing EPT/NPT reachability; Activate publishes it only after the
 * caller has made the handle and trampoline visible to its callback. */
NTSTATUS
HvHookPrepare(
    _In_ PVOID TargetAddress,
    _In_ PVOID HookFunction,
    _Out_ HV_HOOK_HANDLE* OutHandle
);

NTSTATUS
HvHookSetOverlayVisiblePrepared(
    _In_ HV_HOOK_HANDLE Handle,
    _In_ BOOLEAN Visible
);

NTSTATUS
HvHookActivate(
    _In_ HV_HOOK_HANDLE Handle
);

VOID
HvHookCallbackRelease(
    _In_ HV_HOOK_HANDLE Handle
);

// ============================================================
// Hook 查询
// ============================================================

/*
 * 根据物理地址查找 Hook
 * 
 * @param PhysicalAddress  物理地址
 * @return Hook 句柄，失败返回 NULL
 */
HV_HOOK_HANDLE
HvHookFindByPhysicalAddress(
    _In_ ULONG64 PhysicalAddress
);

/*
 * 根据虚拟地址查找 Hook
 * 
 * @param VirtualAddress  虚拟地址
 * @return Hook 句柄，失败返回 NULL
 */
HV_HOOK_HANDLE
HvHookFindByVirtualAddress(
    _In_ PVOID VirtualAddress
);

/*
 * 获取 Hook 信息
 * 
 * @param Handle   Hook 句柄
 * @param OutInfo  输出的 Hook 信息
 * @return NTSTATUS
 */
NTSTATUS
HvHookGetInfo(
    _In_ HV_HOOK_HANDLE Handle,
    _Out_ PHV_HOOK_INFO OutInfo
);

/*
 * 获取 Hook 数量
 * 
 * @return 当前安装的 Hook 数量
 */
ULONG
HvHookGetCount(VOID);

// ============================================================
// 跳板（调用原函数）
// ============================================================

/*
 * 获取跳板地址（用于调用原函数）
 * 
 * @param Handle  Hook 句柄
 * @return 跳板地址，失败返回 NULL
 * 
 * 用法示例（在 Hook 函数中）：
 *   typedef NTSTATUS (*ORIG_FUNC)(ULONG, PVOID, ULONG, PULONG);
 *   ORIG_FUNC OriginalFunc = (ORIG_FUNC)HvHookGetTrampoline(g_MyHookHandle);
 *   return OriginalFunc(arg1, arg2, arg3, arg4);
 */
PVOID
HvHookGetTrampoline(
    _In_ HV_HOOK_HANDLE Handle
);

// ============================================================
// 高级功能：进程隐藏
// ============================================================

/*
 * 按进程 ID 隐藏进程
 * 
 * @param ProcessId  要隐藏的进程 ID（0 表示只安装 Hook）
 * @return NTSTATUS
 */
NTSTATUS
HvHookHideProcess(
    _In_ ULONG ProcessId
);

/* Backend-neutral hidden-process state used by the shared syscall hooks. */
BOOLEAN
HvHookIsProcessHidden(
    _In_ ULONG ProcessId
);

ULONG
HvHookGetHiddenProcessCount(VOID);

VOID
HvHookFilterHiddenProcessInformation(
    _In_ ULONG SystemInformationClass,
    _Inout_updates_bytes_(SystemInformationLength) PVOID SystemInformation,
    _In_ ULONG SystemInformationLength
);

/*
 * 按进程名隐藏进程
 * 
 * @param ProcessName  要隐藏的进程名（如 L"notepad.exe"）
 * @return NTSTATUS
 */
NTSTATUS
HvHookHideProcessByName(
    _In_ PCWSTR ProcessName
);

/*
 * 取消隐藏进程（按 ID）
 * 
 * @param ProcessId  要取消隐藏的进程 ID
 * @return NTSTATUS
 */
NTSTATUS
HvHookUnhideProcess(
    _In_ ULONG ProcessId
);

/*
 * 取消隐藏进程（按名称）
 * 
 * @param ProcessName  要取消隐藏的进程名
 * @return NTSTATUS
 */
NTSTATUS
HvHookUnhideProcessByName(
    _In_ PCWSTR ProcessName
);

// ============================================================
// 驱动文件隐藏
// ============================================================

/*
 * 安装文件隐藏 Hook
 * 对 NtQueryDirectoryFile 进行 Hook 以隐藏驱动文件
 * 
 * @return NTSTATUS
 */
NTSTATUS
HvHookInstallFileHideHook(VOID);

/* Resolve the kernel implementation behind an Nt/Zw syscall stub. */
PVOID
HvHookResolveNtRoutine(
    _In_ PCWSTR RoutineName
);

/*
 * 移除文件隐藏 Hook
 * 
 * @return NTSTATUS
 */
NTSTATUS
HvHookRemoveFileHideHook(VOID);

/*
 * 隐藏驱动文件
 * 
 * @param FileName  文件名（可带或不带路径）
 * @return NTSTATUS
 */
NTSTATUS
HvHookHideDriverFile(
    _In_ PCWSTR FileName
);

/*
 * 取消隐藏驱动文件
 * 
 * @param FileName  文件名
 * @return NTSTATUS
 */
NTSTATUS
HvHookUnhideDriverFile(
    _In_ PCWSTR FileName
);

// ============================================================
// 内存区域隐藏
// ============================================================

/*
 * 隐藏内存区域
 * 通过 Hook NtQueryVirtualMemory 等函数隐藏指定内存区域
 * 
 * @param ProcessId     进程 ID
 * @param Address       地址
 * @param Size          大小
 * @return NTSTATUS
 */
NTSTATUS
HvHookHideMemoryRegion(
    _In_ ULONG ProcessId,
    _In_ PVOID Address,
    _In_ SIZE_T Size
);

/*
 * 取消隐藏内存区域
 * 
 * @param ProcessId     进程 ID
 * @param Address       地址
 * @return NTSTATUS
 */
NTSTATUS
HvHookUnhideMemoryRegion(
    _In_ ULONG ProcessId,
    _In_ PVOID Address
);

/*
 * 隐藏模块（从 PEB 的模块列表）
 * 
 * @param ProcessId     进程 ID
 * @param ModuleBase    模块基址
 * @return NTSTATUS
 */
NTSTATUS
HvHookHideModule(
    _In_ ULONG ProcessId,
    _In_ PVOID ModuleBase
);

// ============================================================
// 驱动隐藏（基于 EPT/NPT Hook，完美隐身）
// ============================================================

/*
 * 安装驱动隐藏 Hook
 * 使用 EPT/NPT Hook 实现，不修改任何内核结构
 * 
 * @return NTSTATUS
 */
NTSTATUS
HvHookInstallDriverHideHook(VOID);

/*
 * 移除驱动隐藏 Hook
 * 
 * @return NTSTATUS
 */
NTSTATUS
HvHookRemoveDriverHideHook(VOID);

/*
 * 隐藏驱动（基于 EPT/NPT Hook）
 * 不会修改 PsLoadedModuleList，完美规避 PatchGuard
 * 
 * @param DriverObject  驱动对象
 * @return NTSTATUS
 */
NTSTATUS
HvHookHideDriverSafe(
    _In_ PDRIVER_OBJECT DriverObject
);

/*
 * 通过名称隐藏驱动
 * 
 * @param DriverName  驱动服务名（不带 .sys）
 * @return NTSTATUS
 */
NTSTATUS
HvHookHideDriverByNameSafe(
    _In_ PCWSTR DriverName
);

/*
 * 取消隐藏驱动
 * 
 * @param DriverObject  驱动对象
 * @return NTSTATUS
 */
NTSTATUS
HvHookUnhideDriverSafe(
    _In_ PDRIVER_OBJECT DriverObject
);

// ============================================================
// 反反调试功能
// ============================================================

#define HV_AAD_FEATURE_PROCESS_DEBUG_QUERY   0x00000001UL
#define HV_AAD_FEATURE_KERNEL_DEBUG_QUERY    0x00000002UL
#define HV_AAD_FEATURE_THREAD_HIDE           0x00000004UL
#define HV_AAD_FEATURE_INVALID_HANDLE        0x00000008UL
#define HV_AAD_FEATURE_DEBUG_OBJECT          0x00000010UL
#define HV_AAD_FEATURE_DEBUG_REGISTERS       0x00000020UL
#define HV_AAD_FEATURE_SYSTEM_DEBUG_CONTROL  0x00000040UL
#define HV_AAD_FEATURE_ALL                   0x0000007FUL
#define HV_AAD_FEATURE_DEFAULT               HV_AAD_FEATURE_ALL

/*
 * 反反调试配置
 */
typedef struct _HV_ANTIANTIDEBUG_CONFIG {
    ULONG   TargetPid;                      // 目标进程 ID（0 表示跟随 Bridge 绑定目标）
    BOOLEAN HookNtQueryInformationProcess;  // Hook NtQueryInformationProcess
    BOOLEAN HookNtQuerySystemInformation;   // Hook NtQuerySystemInformation
    BOOLEAN HookNtSetInformationThread;     // Hook NtSetInformationThread
    BOOLEAN HookNtClose;                    // Hook NtClose（检测无效句柄）
    BOOLEAN HookNtQueryObject;              // Hook NtQueryObject
    BOOLEAN HookNtGetContextThread;         // Hook NtGetContextThread
    BOOLEAN HookNtSetContextThread;         // Hook NtSetContextThread
    BOOLEAN HookNtQueryInformationThread;   // Spoof ThreadHideFromDebugger 查询
    BOOLEAN HookNtSystemDebugControl;       // 隐藏内核调试控制面
} HV_ANTIANTIDEBUG_CONFIG, *PHV_ANTIANTIDEBUG_CONFIG;

/*
 * 启用反反调试
 * 
 * @param Config  配置参数（NULL 使用默认配置）
 * @return NTSTATUS
 */
NTSTATUS
HvHookEnableAntiAntiDebug(
    _In_opt_ PHV_ANTIANTIDEBUG_CONFIG Config
);

/*
 * 禁用反反调试
 * 
 * @return NTSTATUS
 */
NTSTATUS
HvHookDisableAntiAntiDebug(VOID);

/*
 * 检查反反调试是否启用
 * 
 * @return TRUE 如果已启用
 */
BOOLEAN
HvHookIsAntiAntiDebugEnabled(VOID);

ULONG HvHookGetAntiAntiDebugTargetPid(VOID);
ULONG HvHookGetAntiAntiDebugConfiguredMask(VOID);
ULONG HvHookGetAntiAntiDebugInstalledMask(VOID);
BOOLEAN HvHookIsBridgeAntiDebugEnabled(VOID);

/*
 * 检查调试器代理 hook 是否安装 (NtSetContextThread + Nt[R/W]VirtualMemory)
 *
 * 由 HvHookAddDebugger 在 0→1 时自动启用,HvHookRemoveDebugger 在 1→0 时卸载。
 * 此函数让 GUI 验证"启动并保护"是否真把代理链路装上了。
 */
BOOLEAN
HvHookIsDebuggerProxyEnabled(VOID);

/*
 * 检查 NtOpenProcess access bypass hook 是否安装。
 *
 * 由 HvHookAddDebugger 在 0→1 时自动启用,HvHookRemoveDebugger 在 1→0 时卸载。
 * 此函数让 GUI 验证 PPL/System OpenProcess 能否绕过 Protection。
 */
BOOLEAN
HvHookIsAccessBypassEnabled(VOID);

/*
 * Phase K: 受信 caller 白名单查询 (反向保护放行系统进程用)
 *
 * 返回 TRUE 表示该 PID 是 driver init 时枚举到的可信系统进程
 * (System=4 / csrss / wininit / smss / services / lsass / winlogon / WerFault)。
 * 反向保护拒绝外部 caller 访问 debugger 进程,但放行 trusted caller,
 * 避免 SCM / 崩溃处理 / 登录会话管理被卡死。
 */
BOOLEAN
HvHookIsTrustedSystemCaller(_In_ HANDLE Pid);

// ============================================================
// 调试器保护功能
// ============================================================

/*
 * 调试器保护配置
 */
typedef struct _HV_DEBUGGER_CONFIG {
    ULONG   ProcessId;              // 调试器进程 ID
    WCHAR   ProcessName[260];       // 调试器进程名（可选）
    BOOLEAN EnablePrivilege;        // 提升权限
    BOOLEAN ProtectFromTerminate;   // 保护不被终止
    BOOLEAN HideFromList;           // 从进程列表隐藏
    BOOLEAN BridgeIdentityOnly;     // Bridge 身份/所有权登记，不自动安装通用 syscall hook
} HV_DEBUGGER_CONFIG, *PHV_DEBUGGER_CONFIG;

/*
 * 添加受保护的调试器
 * 
 * @param Config  调试器配置
 * @return NTSTATUS
 */
NTSTATUS
HvHookAddDebugger(
    _In_ PHV_DEBUGGER_CONFIG Config
);

/*
 * 移除受保护的调试器
 * 
 * @param ProcessId  调试器进程 ID
 * @return NTSTATUS
 */
NTSTATUS
HvHookRemoveDebugger(
    _In_ ULONG ProcessId
);

/*
 * 获取受保护的调试器数量
 *
 * @return 调试器数量
 */
ULONG
HvHookGetDebuggerCount(VOID);

/*
 * 2026-06-20 方案 A: DriverUnload 时强制 terminate 所有注册过的 debugger 进程。
 *
 * 卸载驱动后所有 syscall hook / ObCallback / 文件防护全部失效, 仍活着的 debugger
 * 进程会立刻被反作弊 / CE / Spy++ 看穿真名 / 真路径 / 真窗口属性。为避免暴露,
 * 卸载链路入口先把它们 ZwTerminateProcess 掉。
 *
 * 调用时机: DriverUnload 早期, 在 HvHookCleanup / HvDbgCleanup 之前。
 *
 * 副作用: 用户当前的调试任务会丢失。但替代方案 (留在那让反作弊看到) 更糟。
 *
 * @return 实际 terminate 的进程数
 */
ULONG
HvHookTerminateAllDebuggers(VOID);

// ============================================================
// 进程保护功能
// ============================================================

/*
 * 进程保护配置
 */
typedef struct _HV_PROTECT_CONFIG {
    ULONG   ProcessId;              // 被保护进程 ID
    WCHAR   ProcessName[260];       // 进程名（可选）
    ULONG   DebuggerPid;            // 允许访问的调试器 PID（0 表示不限制）
    BOOLEAN PreventTerminate;       // 防止被终止
    BOOLEAN PreventSuspend;         // 防止被挂起
    BOOLEAN PreventMemoryAccess;    // 防止内存访问（调试器除外）
} HV_PROTECT_CONFIG, *PHV_PROTECT_CONFIG;

/*
 * 保护进程
 * 
 * @param Config  保护配置
 * @return NTSTATUS
 */
NTSTATUS
HvHookProtectProcess(
    _In_ PHV_PROTECT_CONFIG Config
);

/*
 * 取消保护进程
 * 
 * @param ProcessId  进程 ID
 * @return NTSTATUS
 */
NTSTATUS
HvHookUnprotectProcess(
    _In_ ULONG ProcessId
);

/* Manual owner-domain teardown. Neither entry point may remove a
 * BridgeOwned record; Bridge bindings are retired by UNBIND or exact process
 * exit cleanup. */
NTSTATUS
HvHookUnprotectProcessForDebugger(
    _In_ ULONG ProcessId,
    _In_ ULONG DebuggerPid
);

/* Process-notify cleanup is the only any-owner target teardown path. It
 * validates the exiting EPROCESS and creation time before removing either a
 * manual record or a Bridge-owned binding, so PID reuse cannot cross owners. */
NTSTATUS
HvHookCleanupProtectedProcessOnExit(
    _In_ PEPROCESS Process,
    _In_ HANDLE ProcessId
);

/*
 * Atomic debugger-bridge ownership transaction. BIND requires a prior
 * explicit debugger_add with matching EPROCESS/create-time identity; it never
 * creates debugger policy implicitly. These entry points serialize bridge
 * hook ownership and target publication under the hook mutation lock.
 */
NTSTATUS
HvHookBindBridgeTarget(
    _In_ ULONG DebuggerPid,
    _In_ PHV_PROTECT_CONFIG Config,
    _In_ ULONG BindFlags
);

NTSTATUS
HvHookUnbindBridgeTarget(
    _In_ ULONG ProcessId,
    _In_ ULONG DebuggerPid
);

ULONG
HvHookUnprotectAllForDebugger(
    _In_ ULONG DebuggerPid
);

ULONG
HvHookGetBoundTargetCount(
    _In_ ULONG DebuggerPid
);

BOOLEAN
HvHookIsBoundTargetForDebugger(
    _In_ ULONG ProcessId,
    _In_ ULONG DebuggerPid
);

/* Complete a launch-time deferred PEB cloak only after the PE entry event is
 * pending. The binding record is the lifetime/ownership authority. */
NTSTATUS
HvHookActivateDeferredPebCloak(
    _In_ ULONG ProcessId,
    _In_ ULONG DebuggerPid
);

/*
 * 获取受保护进程数量
 *
 * @return 受保护进程数量
 */
ULONG
HvHookGetProtectedProcessCount(VOID);

// ============================================================
// 调试器/进程白名单查询 (阶段 7.1)
// 给 HvDebugger / IOCTL handler / EPT-hook 路径快速判定调用方身份
// ============================================================

/*
 * 检查指定 PID 是否在调试器白名单中
 *
 * @param Pid  进程 ID (HANDLE 类型,与 PsGetCurrentProcessId 兼容)
 * @return TRUE 表示该 PID 是注册的受保护调试器
 */
BOOLEAN
HvHookIsDebuggerPid(
    _In_ HANDLE Pid
);

/*
 * 检查指定 PID 是否是受保护进程 (HWBP 目标)
 *
 * @param Pid  进程 ID
 * @return TRUE 表示该 PID 是被保护的目标
 */
BOOLEAN
HvHookIsProtectedProcessPid(
    _In_ HANDLE Pid
);

/* Exact-live-identity query for Bridge-owned targets. */
BOOLEAN
HvHookIsBridgeOwnedTargetPid(
    _In_ HANDLE Pid
);

/*
 * 查询某个调试器当前关联的保护目标 PID
 * V1 假设一个调试器最多对应一个 target
 *
 * @param DebuggerPid  调试器 PID
 * @param OutTargetPid 输出关联的目标 PID
 * @return STATUS_SUCCESS 找到,STATUS_NOT_FOUND 该调试器无关联 target
 */
NTSTATUS
HvHookGetProtectedTargetForDebugger(
    _In_ HANDLE DebuggerPid,
    _Out_ PHANDLE OutTargetPid
);

// ============================================================
// 阶段 7.8: 调试器代理 (NtSetContextThread / Nt[R/W]VirtualMemory)
// 由 HvDbgInitialize / HvDbgCleanup 自动调用,
// 也可以单独控制 (用于热切换)
// ============================================================

// Phase L6 (2026-06-04): 加 CallerPid 参数,作为 ntdll syscall index 解析的 anchor。
// 调用者必须传一个已运行的 user 进程 PID (一定有 ntdll),通常是 ADD_DEBUGGER 时
// 注册的 debugger 自身的 PID。CallerPid=0 时跳过 SSDT fallback (会让 Win10 19045
// 等不导出 NtRead/Write/SetContext 的内核上 hook 装载失败)。
NTSTATUS HvHookEnableDebuggerProxy(_In_ ULONG CallerPid);
VOID     HvHookDisableDebuggerProxy(VOID);

// Bridge baseline: install only NtQueryInformationProcess. Its handler is
// scoped to protected debugger targets, avoiding the broad syscall-hook set.
NTSTATUS HvHookEnableBridgeAntiDebug(_In_ ULONG CallerPid);
NTSTATUS HvHookSetPrivateDebugObjectEnabled(_In_ BOOLEAN Enabled);
struct _HV_PRIVATE_DBGK_SYMBOLS;
NTSTATUS HvHookConfigurePrivateDebugObjectSymbols(
    _In_ const struct _HV_PRIVATE_DBGK_SYMBOLS* Symbols);

// ============================================================
// 阶段 7.9: NtOpenProcess 访问控制 bypass (高危,默认 OFF)
// 让 ADD_DEBUGGER 注册的进程能对配对的 PROTECT_PROCESS 目标
// 调用 OpenProcess(),包括 PPL / System=4 / lsass。
// 走 EPT-hook + 临时 EPROCESS.Protection 抹零,PG-immune。
// ============================================================

NTSTATUS HvHookEnableAccessBypass(VOID);
NTSTATUS HvHookDisableAccessBypass(VOID);

// ============================================================
// Phase G: 根因事件 ring buffer (调试器全权限链路诊断)
// ============================================================
//
// 驱动里关键路径 (ADD_DEBUGGER hook 装载 / NtOpenProcess bypass / NtR/W 失败)
// Post 事件到 256-entry ring,GUI 通过 IOCTL_HV_GET_DBGEVT 1s 轮询拉取,显示
// 在日志面板。让"启动并保护没生效"这种问题不需要 DbgView 就能定位。
//
// 设计:
//   - 单一 ring + KSPIN_LOCK,任何 IRQL <= DISPATCH 都能 Post
//   - 单调递增 Sequence,客户端持久化 last seen,拉只取新事件
//   - 满了从尾巴覆盖最旧的,客户端能感知 (NextSequence > lastSeen + maxCount → 有丢失)

// P122: ring 扩到 4096 容纳 driver-wide trace. detail 加长到 192.
#define HV_DBGEVT_RING_SIZE  4096
#define HV_DBGEVT_DETAIL_MAX 192  // ASCII, 含 NUL

#define HV_DBGEVT_SEV_INFO   0
#define HV_DBGEVT_SEV_WARN   1
#define HV_DBGEVT_SEV_ERROR  2

#define HV_DBGEVT_CAT_ADD_DEBUGGER     1   // 三组 hook 装载结果
#define HV_DBGEVT_CAT_REMOVE_DEBUGGER  2   // 三组 hook 卸载结果
#define HV_DBGEVT_CAT_OPEN_PROCESS     3   // NtOpenProcess bypass 调用
#define HV_DBGEVT_CAT_READ_MEMORY      4   // NtReadVirtualMemory hook 失败
#define HV_DBGEVT_CAT_WRITE_MEMORY     5   // NtWriteVirtualMemory hook 失败
#define HV_DBGEVT_CAT_AAD              6   // 反反调试 hook 装载/触发
#define HV_DBGEVT_CAT_HWBP_HIT         7   // 硬件断点命中 (P50)
#define HV_DBGEVT_CAT_BREAK_HIT        8   // 软断点/单步命中 (P50/P51)
#define HV_DBGEVT_CAT_DEBUGGER_OP      9   // P106 调试器线程访问/控制 (Suspend/Resume/OpenThread/GetContext)

// P122: trace category — driver 全局 DbgPrint 自动捕获 (HvTrace.h 重定义 DbgPrint).
//   100-199 段, 按源文件分类. GUI 用 cat tab 切换视图.
#define HV_TRACE_CAT_VM        100   // HvVmcs/HvVmcb/HvVmExit/HvCore 虚拟化生命周期
#define HV_TRACE_CAT_HOOK      101   // HvHook syscall hook
#define HV_TRACE_CAT_EPT       102   // EptHook / HvEpt EPT 操作
#define HV_TRACE_CAT_NPT       103   // NptHook / HvNpt AMD NPT
#define HV_TRACE_CAT_PHYS      104   // HvPhysAccess 物理直通
#define HV_TRACE_CAT_VMEXIT    105   // HvVmExit dispatch
#define HV_TRACE_CAT_INJECT    106   // HvInjection DLL 注入
#define HV_TRACE_CAT_NETWORK   107   // HvNetworkHook
#define HV_TRACE_CAT_NESTED    108   // HvNested* 嵌套虚拟化
#define HV_TRACE_CAT_CLOAK     109   // HvCloak EPT cloak
#define HV_TRACE_CAT_DEBUG     110   // HvDebugger HWBP/swbp/step
#define HV_TRACE_CAT_DRIVER    111   // Driver.c / IOCTL handler
#define HV_TRACE_CAT_INPUT     112   // HvInput 键鼠注入
#define HV_TRACE_CAT_REGISTRY  113   // HvRegistryHook
#define HV_TRACE_CAT_VTROOT    114   // HvVtRoot
#define HV_TRACE_CAT_UTIL      115   // HvUtils/HvCompat/HvLde 等
#define HV_TRACE_CAT_USB       116   // HvUsbXhci / HvXhciEptTrap
#define HV_TRACE_CAT_GENERIC   199   // 兜底

#pragma pack(push, 8)
typedef struct _HV_DBGEVT {
    UINT64   Sequence;            // 单调递增, 从 1 开始
    UINT64   TimestampQpc;        // KeQueryPerformanceCounter
    ULONG    Severity;            // HV_DBGEVT_SEV_*
    ULONG    Category;            // HV_DBGEVT_CAT_*
    NTSTATUS Status;              // 0 = info-only;非 0 = NTSTATUS 错误
    ULONG    CallerPid;
    ULONG    TargetPid;
    ULONG    _pad;
    UINT64   Addr;                // optional 读写地址 / hook 函数地址
    UINT64   Size;                // optional 读写大小
    char     Detail[HV_DBGEVT_DETAIL_MAX];   // ASCII 短描述
} HV_DBGEVT, *PHV_DBGEVT;
#pragma pack(pop)

// 内核内部 Post (从 hook / IOCTL handler 调用,IRQL <= DISPATCH)
VOID
HvDbgEvtPost(
    _In_ ULONG    Severity,
    _In_ ULONG    Category,
    _In_ NTSTATUS Status,
    _In_ ULONG    CallerPid,
    _In_ ULONG    TargetPid,
    _In_ UINT64   Addr,
    _In_ UINT64   Size,
    _In_ PCSTR    Detail
);

// 从 ring 拉新事件 (供 Driver.c IOCTL handler 用)。
// SinceSequence: 客户端上次见过的最大 Sequence (从 0 开始)
// OutEvents:    输出缓冲区
// MaxOut:       上限 (推荐 64)
// OutCount:     实际写入的条数
// OutNextSequence: ring 中最新事件的 Sequence (客户端下次传入)
NTSTATUS
HvDbgEvtPull(
    _In_  UINT64    SinceSequence,
    _Out_writes_to_(MaxOut, *OutCount) PHV_DBGEVT OutEvents,
    _In_  ULONG     MaxOut,
    _Out_ PULONG    OutCount,
    _Out_ PUINT64   OutNextSequence
);

// ============================================================
// DSE (Driver Signature Enforcement) 控制
// ============================================================

/*
 * 禁用 DSE
 * 通过修改 ci.dll 中的 g_CiOptions 变量
 * 
 * @return NTSTATUS
 */
NTSTATUS
HvDseDisable(VOID);

/*
 * 启用 DSE
 * 恢复 g_CiOptions 原始值
 * 
 * @return NTSTATUS
 */
NTSTATUS
HvDseEnable(VOID);

/*
 * 获取 DSE 状态
 * 
 * @param OutEnabled    输出 DSE 是否启用
 * @param OutCiOptions  输出 g_CiOptions 当前值（可选）
 * @param OutCiAddress  输出 g_CiOptions 地址（可选）
 * @return NTSTATUS
 */
NTSTATUS
HvDseGetStatus(
    _Out_ PBOOLEAN OutEnabled,
    _Out_opt_ PULONG OutCiOptions,
    _Out_opt_ PUINT64 OutCiAddress
);

// ============================================================
// 调试函数
// ============================================================

/*
 * 打印 Hook 管理器信息
 */
VOID
HvHookPrintInfo(VOID);

/*
 * 检查页表是否正确配置
 * 
 * @return TRUE 如果配置正确
 */
BOOLEAN
HvHookIsConfigured(VOID);

#endif // _HV_HOOK_H_
