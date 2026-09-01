/*
 * NptHook.h
 * 
 * AMD NPT Hook 模块 - 用于实现隐身 Hook（绕过 PatchGuard）
 * 
 * 原理：
 *   - 使用 NPT 分页欺骗技术（类似于 Intel EPT）
 *   - 读取时返回原始代码（PG 检查通过）
 *   - 执行时跳转到 Hook 代码
 * 
 * 注意：
 *   - AMD NPT 不支持 Execute-Only 模式（与 Intel EPT 不同）
 *   - 使用 NX (No Execute) 位来控制执行权限
 *   - Hook 策略：P=1, W=1, NX=1 触发执行时 NPF
 */

#ifndef _NPT_HOOK_H_
#define _NPT_HOOK_H_

#pragma once

#include <ntddk.h>
#include <intrin.h>
#include "HvTypes.h"
#include "HvNpt.h"

// ============================================================
// 常量定义
// ============================================================

#define MAX_NPT_HOOKS           64
#define NPT_HOOK_TAG            'kpNH'
#define NPT_HOOK_PAGE_TAG       'gpNH'
#define PAGE_SIZE_4KB           0x1000
#define PAGE_MASK               (~0xFFFULL)
#define NPT_INLINE_PATCH_SIZE   14
#define NPT_MAX_PENDING_STEP_PAGES MAX_NPT_HOOKS

// ============================================================
// 调试开关
// ============================================================
#define NPT_HOOK_SIMPLE_MODE    0   // 1=简单模式(固定14字节,无重定位), 0=完整模式(带指令解码和重定位)
#define NPT_HOOK_TEST_NO_CALL   0   // 1=禁用跳板调用(直接返回,用于测试), 0=正常调用

// NPF (Nested Page Fault) 错误码位定义
// 与标准 Page Fault 错误码相同
#define NPF_PRESENT             (1 << 0)    // P - 页存在
#define NPF_WRITE               (1 << 1)    // R/W - 写操作
#define NPF_USER                (1 << 2)    // U/S - 用户模式
#define NPF_RESERVED            (1 << 3)    // RSV - 保留位设置
#define NPF_FETCH               (1 << 4)    // I/D - 指令获取
#define NPF_PROTECTION_KEY      (1 << 5)    // PK - 保护密钥
#define NPF_SHADOW_STACK        (1 << 6)    // SS - 影子栈
#define NPF_RMP                 (1 << 31)   // RMP - 反向映射表（SEV-SNP）

// AMD NPT 特有的高级错误码位（ExitInfo1 高32位）
#define NPF_NOT_PRESENT_GUEST   (1ULL << 32)  // 客户页表中页不存在
#define NPF_FINAL_ADDR          (1ULL << 33)  // 最终物理地址转换
#define NPF_GUEST_PT_ACCESS     (1ULL << 34)  // 客户页表访问
#define NPF_ENCRYPT_PAGE        (1ULL << 35)  // 加密页访问

// ============================================================
// 数据结构
// ============================================================

// Hook 类型
typedef enum _NPT_HOOK_TYPE {
    NptHookTypeInline,      // 内联 Hook（修改函数开头）
    NptHookTypePage,        // 整页 Hook
} NPT_HOOK_TYPE;

// Hook 状态
typedef enum _NPT_HOOK_STATE {
    NptHookStatePrepared  = 0, // 资源/跳板已就绪，尚未修改 NPT leaf
    NptHookStateActive    = 1, // 已发布到 NPT，可进入 HookFunction
    NptHookStateQuiescing = 2, // 正在撤销；失败时保持此态供同一句柄重试
    NptHookStateRetired   = 3, // 已从活动链摘除，资源等待 manager cleanup 回收
} NPT_HOOK_STATE;

typedef enum _NPT_HOOK_PAGE_MUTATION {
    NptHookPageMutationNone = 0,
    NptHookPageMutationActivate,
    NptHookPageMutationRemove,
} NPT_HOOK_PAGE_MUTATION;

struct _NPT_HOOK_ENTRY;

/*
 * A target GPA has exactly one NPT leaf owner and one live fake page.  Hook
 * entries below are independent sites/handles linked to this owner.  Keeping
 * SLAT and single-step state here prevents two sites on the same 4-KiB page
 * from publishing competing fake PFNs or restoring each other's leaves.
 */
typedef struct _NPT_HOOK_PAGE {
    LIST_ENTRY ListEntry;
    LIST_ENTRY SiteList;

    volatile NPT_HOOK_STATE State;
    ULONG64 TargetPhysicalAddress;
    PVOID TargetPageVirtualAddress;

    PVOID FakePageVirtual;
    ULONG64 FakePagePhysical;

    PNPT_PTE TargetPte[64];
    ULONG TargetPteCount;
    ULONG64 OriginalPteValue[64];

    ULONG SiteCount;
    ULONG ActiveSiteCount;
    struct _NPT_HOOK_ENTRY* volatile AccountingSite;
    struct _NPT_HOOK_ENTRY* volatile MutationSite;
    volatile NPT_HOOK_PAGE_MUTATION MutationKind;
    volatile LONG RootDrainPending;
    ULONG RootDrainEpoch;
} NPT_HOOK_PAGE, *PNPT_HOOK_PAGE;

// NPT Hook site/handle
typedef struct _NPT_HOOK_ENTRY {
    LIST_ENTRY ListEntry;           // manager site list
    LIST_ENTRY PageListEntry;       // owning page's site list
    
    volatile NPT_HOOK_STATE State;  // Hook 状态（control/root 跨 CPU 发布）
    NPT_HOOK_TYPE Type;             // Hook 类型
    
    // 目标信息
    PVOID TargetVirtualAddress;     // 目标虚拟地址
    ULONG64 TargetPhysicalAddress;  // 目标物理地址（页对齐）
    ULONG OffsetInPage;             // 页内偏移
    PNPT_HOOK_PAGE PageOwner;        // unique GPA/fake-page/leaf owner
    UCHAR PatchBytes[NPT_INLINE_PATCH_SIZE];
    BOOLEAN PatchInstalled;
    
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
    
} NPT_HOOK_ENTRY, *PNPT_HOOK_ENTRY;

// 每 CPU 单步上下文（用于恢复 NPT 状态）
// 注意：使用 volatile 确保编译器不会优化掉内存访问
// StepActive 使用 LONG 以支持 Interlocked 原子操作
typedef struct _NPT_STEP_CONTEXT {
    volatile LONG StepActive;                    // 0=idle, 1=armed, 2=completing
    ULONG PendingPageCount;
    PNPT_HOOK_PAGE PendingPages[NPT_MAX_PENDING_STEP_PAGES];
    BOOLEAN GuestTfWasSet;
    BOOLEAN DbInterceptWasSet;
} NPT_STEP_CONTEXT, *PNPT_STEP_CONTEXT;

// NPT Hook 管理器
typedef struct _NPT_HOOK_MANAGER {
    // Hook 链表
    LIST_ENTRY HookList;
    ULONG HookCount;
    LIST_ENTRY RetiredHookList;
    ULONG RetiredHookCount;
    LIST_ENTRY PageList;
    ULONG PageCount;
    LIST_ENTRY RetiredPageList;
    ULONG RetiredPageCount;
    
    // 同步
    KSPIN_LOCK Lock;
    FAST_MUTEX MutationMutex;
    volatile LONG RootEpoch;
    volatile LONG RootReaders[2];
    
    // 跳板页（存放跳板代码）
    PVOID TrampolinePool;
    ULONG64 TrampolinePoolPhysical;
    ULONG TrampolinePoolUsed;
    
    // 每 CPU 单步上下文（最多 64 个 CPU）
    NPT_STEP_CONTEXT StepContext[64];
    
    // 状态
    BOOLEAN Initialized;
    
    // NX 支持标志
    // AMD CPU 通常支持 NX，但需要确认 EFER.NXE=1
    BOOLEAN NxSupported;
    
} NPT_HOOK_MANAGER, *PNPT_HOOK_MANAGER;

// Hook 回调函数类型
typedef NTSTATUS(*NPT_HOOK_CALLBACK)(
    PNPT_HOOK_ENTRY HookEntry,
    PVOID Context
);

// ============================================================
// 函数声明
// ============================================================

//
// 初始化和清理
//

/*
 * 初始化 NPT Hook 管理器
 */
NTSTATUS
NptHookInitialize(VOID);

/*
 * 清理 NPT Hook 管理器
 */
VOID
NptHookCleanup(VOID);

//
// Hook 管理
//

/*
 * 安装 NPT Hook
 * 
 * @param TargetAddress  要 Hook 的目标地址
 * @param HookFunction   Hook 处理函数
 * @param OutHookEntry   返回 Hook 条目（可选）。如果 Activate 失败且回滚
 *                       Remove 也未完成，仍返回保留的 Quiescing 句柄，
 *                       以便调用方重试 NptHookRemove。未提供输出时由
 *                       manager HookList 保留归属，RemoveAll 后续重试。
 * @return NTSTATUS
 */
NTSTATUS
NptHookInstall(
    _In_ PVOID TargetAddress,
    _In_ PVOID HookFunction,
    _Out_opt_ PNPT_HOOK_ENTRY* OutHookEntry
);

/*
 * Two-phase publication. Prepare reserves the target/GPA and constructs the
 * fake page and trampoline, but never redirects an NPT leaf. The owner can
 * publish the returned handle/trampoline before Activate makes the callback
 * reachable on any processor.
 */
NTSTATUS
NptHookPrepare(
    _In_ PVOID TargetAddress,
    _In_ PVOID HookFunction,
    _Out_ PNPT_HOOK_ENTRY* OutHookEntry,
    _Out_ PVOID* OutTrampoline
);

NTSTATUS
NptHookActivate(
    _In_ PNPT_HOOK_ENTRY HookEntry
);

/*
 * 移除 NPT Hook
 */
NTSTATUS
NptHookRemove(
    _In_ PNPT_HOOK_ENTRY HookEntry
);

/*
 * 移除指定地址的 Hook
 */
NTSTATUS
NptHookRemoveByAddress(
    _In_ PVOID TargetAddress
);

/*
 * 移除所有 Hook
 */
VOID
NptHookRemoveAll(VOID);

//
// NPF (Nested Page Fault) 处理
//

/*
 * 处理 NPF
 * 由 SVM VM Exit Handler 调用
 * 
 * @param VcpuData             当前 VCPU 数据
 * @param GuestPhysicalAddress 触发故障的物理地址
 * @param ErrorCode            NPF 错误码 (ExitInfo1)
 * @return TRUE 如果已处理，FALSE 如果需要其他处理
 */
BOOLEAN
NptHookHandleNpf(
    _In_ PVCPU_DATA VcpuData,
    _In_ ULONG64 GuestPhysicalAddress,
    _In_ ULONG64 ErrorCode
);

/*
 * 处理单步执行后的恢复
 * 由 SVM VM Exit Handler 在 #DB 异常后调用
 * 
 * @param VcpuData  当前 VCPU 数据
 * @return TRUE 如果已处理，FALSE 如果需要其他处理
 */
BOOLEAN
NptHookHandleSingleStep(
    _In_ PVCPU_DATA VcpuData
);

#define NPT_DEBUG_STEP_DB_NONE     0u
#define NPT_DEBUG_STEP_DB_CONSUME  1u
#define NPT_DEBUG_STEP_DB_REINJECT 2u
#define VMCALL_REFRESH_NPT_STATE   0xEBF00023U

BOOLEAN NptHookIsDebugStepSupported(VOID);

NTSTATUS NptHookDebugStepArm(
    _In_ HANDLE DebuggerPid,
    _In_ HANDLE TargetPid,
    _In_ HANDLE TargetTid,
    _In_ PVOID ThreadToken,
    _In_ UINT64 Address);

NTSTATUS NptHookDebugStepClear(
    _In_ HANDLE DebuggerPid,
    _In_ HANDLE TargetPid,
    _In_ HANDLE TargetTid);

VOID NptHookDebugStepClearAll(
    _In_opt_ HANDLE DebuggerPid,
    _In_opt_ HANDLE TargetPid);

BOOLEAN NptHookHandleDebugStepNpf(
    _In_ PVCPU_DATA VcpuData,
    _In_ ULONG64 GuestPhysicalAddress,
    _In_ ULONG64 ErrorCode);

ULONG NptHookHandleDebugStepDb(
    _In_ PVCPU_DATA VcpuData);

//
// NPT 页表操作
//

/*
 * 修改 NPT PTE 权限
 */
NTSTATUS
NptModifyPagePermissions(
    _In_ PVCPU_DATA VcpuData,
    _In_ ULONG64 PhysicalAddress,
    _In_ BOOLEAN Present,
    _In_ BOOLEAN Write,
    _In_ BOOLEAN NoExecute
);

/*
 * 将物理页映射到另一个物理页
 */
NTSTATUS
NptRemapPage(
    _In_ PVCPU_DATA VcpuData,
    _In_ ULONG64 OriginalPhysical,
    _In_ ULONG64 NewPhysical,
    _In_ BOOLEAN Present,
    _In_ BOOLEAN Write,
    _In_ BOOLEAN NoExecute
);

//
// 辅助函数
//

/*
 * 根据物理地址查找 Hook
 */
PNPT_HOOK_ENTRY
NptHookFindByPhysicalAddress(
    _In_ ULONG64 PhysicalAddress
);

/*
 * 根据虚拟地址查找 Hook
 */
PNPT_HOOK_ENTRY
NptHookFindByVirtualAddress(
    _In_ PVOID VirtualAddress
);

/*
 * 调用原函数（通过跳板）
 */
PVOID
NptHookGetTrampoline(
    _In_ PNPT_HOOK_ENTRY HookEntry
);

//
// 调试函数
//

/*
 * 打印当前 NPT 结构信息
 */
VOID
NptPrintInfo(VOID);

/*
 * 检查 NPT 是否正确配置
 */
BOOLEAN
NptIsConfigured(VOID);

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
NptHookHideProcess(
    _In_ ULONG ProcessId
);

/*
 * Hidden-process backend state. These routines never install or remove an
 * NPT hook; HvHook uses them when it owns the shared syscall interception.
 */
NTSTATUS
NptHookAddHiddenProcessState(
    _In_ ULONG ProcessId
);

NTSTATUS
NptHookRemoveHiddenProcessState(
    _In_ ULONG ProcessId
);

BOOLEAN
NptHookIsProcessHidden(
    _In_ ULONG ProcessId
);

ULONG
NptHookGetHiddenProcessCount(VOID);

VOID
NptHookFilterProcessInformation(
    _In_ ULONG SystemInformationClass,
    _Inout_updates_bytes_(SystemInformationLength) PVOID SystemInformation,
    _In_ ULONG SystemInformationLength
);

/*
 * 根据进程名隐藏进程
 * 
 * @param ProcessName  要隐藏的进程名（如 "notepad.exe"）
 * @return NTSTATUS
 */
NTSTATUS
NptHookHideProcessByName(
    _In_ PCWSTR ProcessName
);

/*
 * 取消隐藏指定进程名
 */
NTSTATUS
NptHookUnhideProcessByName(
    _In_ PCWSTR ProcessName
);

/*
 * 取消隐藏指定进程ID
 */
NTSTATUS
NptHookUnhideProcess(
    _In_ ULONG ProcessId
);

//
// 高级功能：文件隐藏
//

/*
 * 安装文件隐藏 Hook (NtQueryDirectoryFile)
 */
NTSTATUS
NptHookInstallFileHideHook(VOID);

NTSTATUS
NptHookInstallFileHideHookAtAddress(
    _In_ PVOID NtQueryDirectoryFileAddress
);

/*
 * 移除文件隐藏 Hook
 */
NTSTATUS
NptHookRemoveFileHideHook(VOID);

/*
 * 添加文件到隐藏列表
 */
NTSTATUS
NptHookHideFile(
    _In_ PCWSTR FileName
);

/*
 * 从隐藏列表移除文件
 */
NTSTATUS
NptHookUnhideFile(
    _In_ PCWSTR FileName
);

//
// 高级功能：驱动隐藏（绕过 PatchGuard）
//

/*
 * 安装驱动隐藏 Hook
 * Hook ZwQuerySystemInformation 来过滤 SystemModuleInformation
 * 
 * @return NTSTATUS
 */
NTSTATUS
NptHookInstallDriverHideHook(VOID);

/*
 * 移除驱动隐藏 Hook
 * 
 * @return NTSTATUS
 */
NTSTATUS
NptHookRemoveDriverHideHook(VOID);

/* AMD counterpart used by HvHook's shared NtQuerySystemInformation hook. */
VOID
NptHookFilterModuleList(
    _Inout_updates_bytes_(ModuleInfoLength) PVOID ModuleInfo,
    _In_ ULONG ModuleInfoLength
);

/*
 * 隐藏指定驱动
 * 
 * @param DriverObject  要隐藏的驱动对象
 * @return NTSTATUS
 */
NTSTATUS
NptHookHideDriver(
    _In_ PDRIVER_OBJECT DriverObject
);

/*
 * 根据名称隐藏驱动
 * 
 * @param DriverName  要隐藏的驱动名称
 * @return NTSTATUS
 */
NTSTATUS
NptHookHideDriverByName(
    _In_ PCWSTR DriverName
);

/*
 * 取消隐藏指定驱动
 * 
 * @param DriverObject  要取消隐藏的驱动对象
 * @return NTSTATUS
 */
NTSTATUS
NptHookUnhideDriver(
    _In_ PDRIVER_OBJECT DriverObject
);

//
// SVM 模式管理（供 VM Exit Handler 使用）
//

/*
 * 设置 SVM root 模式标志
 * 在 VM Exit Handler 进入/退出时调用
 */
VOID
NptSetSvmRootMode(
    _In_ BOOLEAN InRootMode
);

// ============================================================
// 全局变量
// ============================================================

extern NPT_HOOK_MANAGER g_NptHookManager;

// NPT 版本号（用于多 CPU TLB 同步）
extern volatile LONG64 g_NptVersion;

// ============================================================
// 多 CPU NPT TLB 同步
// ============================================================

/*
 * 检查并刷新 NPT TLB（如果需要）
 * 在每次 VM Exit 开始时调用
 * 确保当前 CPU 看到最新的 NPT 映射
 */
VOID NptCheckAndInvalidateTlb(PVCPU_DATA VcpuData);

PNPT_PTE NptGetPteForPhysicalAddress(_In_ PVCPU_DATA VcpuData, _In_ ULONG64 PhysicalAddress);

#endif // _NPT_HOOK_H_
