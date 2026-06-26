/*
 * HvHook.c
 * 
 * Hypervisor Hook 抽象层实现
 * 统一 Intel EPT Hook 和 AMD NPT Hook 接口
 */

#include "HvHook.h"
#include "HvCpu.h"
#include "EptHook.h"
#include "NptHook.h"
#include "HvCompat.h"
#include "HvInjection.h"
#include "HvDebugger.h"
#include "HvPhysAccess.h"
#include "HvTypes.h"   // Phase L: HV_RTL_PROCESS_MODULES (ntoskrnl base lookup)
#include "HvPebCloak.h"  // P125: PEB 字段级 EPT spoof
#include "HvVwatch.h"    // P128: 虚拟硬件断点 (EPT-based HWBP)
#include <ntstrsafe.h>

// P122: 全 driver DbgPrint → GUI ring
#define HV_TRACE_THIS_CAT HV_TRACE_CAT_HOOK
#include "HvTrace.h"

// P121: KeStackAttachProcess / PsGetProcessPeb prototype (ntifs.h 在不同 WDK 版本
// 位置不一致, 直接 extern)。给 NtDebugActiveProcess hook 抹 PEB 用.
typedef struct _HV_HOOK_APC_STATE {
    UCHAR Reserved[0x60];
} HV_HOOK_APC_STATE;

NTKERNELAPI VOID KeStackAttachProcess(
    _Inout_ PRKPROCESS PROCESS,
    _Out_   HV_HOOK_APC_STATE* ApcState);
NTKERNELAPI VOID KeUnstackDetachProcess(
    _In_ HV_HOOK_APC_STATE* ApcState);
NTKERNELAPI PVOID PsGetProcessPeb(_In_ PEPROCESS Process);

// ============================================================
// 前向声明
// ============================================================

// 隐藏的内存区域记录（前向声明）
typedef struct _HIDDEN_MEMORY_REGION {
    LIST_ENTRY ListEntry;
    ULONG ProcessId;
    PVOID Address;
    SIZE_T Size;
} HIDDEN_MEMORY_REGION, *PHIDDEN_MEMORY_REGION;

// 受保护调试器记录
typedef struct _PROTECTED_DEBUGGER {
    LIST_ENTRY ListEntry;
    ULONG ProcessId;
    WCHAR ProcessName[260];
    // 2026-06-19 加: 完整 image path (\Device\HarddiskVolumeN\..\xxx.exe), Add 时
    // 由 SeLocateProcessImageName 解析填入, 用于文件防护比对 (NtCreateFile/NtReadFile)。
    // ImagePathLen 是 wcslen(无 NUL), 0 表示解析失败 (本字段不可用)。
    WCHAR ImagePath[520];
    USHORT ImagePathLen;
    BOOLEAN EnablePrivilege;
    BOOLEAN ProtectFromTerminate;
    BOOLEAN HideFromList;
} PROTECTED_DEBUGGER, *PPROTECTED_DEBUGGER;

// 受保护进程记录
typedef struct _PROTECTED_PROCESS {
    LIST_ENTRY ListEntry;
    ULONG ProcessId;
    WCHAR ProcessName[260];
    ULONG DebuggerPid;
    BOOLEAN PreventTerminate;
    BOOLEAN PreventSuspend;
    BOOLEAN PreventMemoryAccess;
} PROTECTED_PROCESS, *PPROTECTED_PROCESS;

// ============================================================
// 全局变量
// ============================================================

static BOOLEAN g_HvHookInitialized = FALSE;
static CPU_VENDOR g_HvHookBackend = CPU_VENDOR_UNKNOWN;

// 2026-06-16 per-handler bypass gate (调试 / 安全模式留)。
// 默认所有 hook handler 都启用业务逻辑。某个 handler 出问题时把对应位设 TRUE 临时跳过。
volatile BOOLEAN g_BypassNtQueryInformationProcess = FALSE;
// P119: 真根因是 VMCS Exception Bitmap 默认拦 #DB → vm-entry re-inject 与 guest IDT
//       delivery 状态不一致。已在 HvVmcs.c:527 删 #DB 拦截。hook 业务逻辑可恢复。
volatile BOOLEAN g_BypassNtSetContextThread       = FALSE;
volatile BOOLEAN g_BypassNtReadVirtualMemory      = FALSE;
volatile BOOLEAN g_BypassNtWriteVirtualMemory     = FALSE;  // 2026-06-22 启用 proxy: HvPhys 物理直通写, 反作弊拦不到
volatile BOOLEAN g_BypassNtOpenProcess            = FALSE;  // 2026-06-19 关闭: 之前 TRUE 导致 hook 入口直接 passthrough, CE 能开 debugger handle
// P106 (2026-06-22): 反作弊在 NtSuspendThread/NtOpenThread/NtGetContextThread 入口装 hook 拦内置调试器,
// 我们装在更前 (HvHookInstall 拿 trampoline), trusted caller 走 trampoline 跳过反作弊检查
volatile BOOLEAN g_BypassNtSuspendThread          = FALSE;
volatile BOOLEAN g_BypassNtResumeThread           = FALSE;
volatile BOOLEAN g_BypassNtOpenThread             = FALSE;
volatile BOOLEAN g_BypassNtGetContextThread       = FALSE;

// ============================================================
// 2026-06-19: 进程伪装目标路径 (UWP Notepad, Win11 全系)
// ============================================================
//
// 旧值: C:\Windows\System32\notepad.exe
//   问题:
//   1. Win11 系统 notepad.exe 实际只是 stub launcher, size/PE 特征与 UWP 不符
//   2. 当 debugger 真实文件名碰巧也叫 notepad.exe 时, explorer 右键 → 编辑会触发
//      Notepad App 处理流程, 弹窗"找不到文件 — 创建?" 暴露异常
//
// 新值: 模仿 VT 调试器, 指向 Win11 UWP Notepad 包路径
//   - 路径深, 看起来"系统级", 反作弊不会去模糊匹配
//   - 8wekyb3d8bbwe 是 Microsoft 出版者 hash, 跨 Win11 所有版本固定
//   - 11.2502.22.0 是版本号 (会随 Windows Update 漂移), 但反作弊一般只看包前缀
//     ("Microsoft.WindowsNotepad" 前缀命中即认为是 Notepad)
//
// TODO: driver init 时枚举 \??\C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_*
// 动态拿真实版本号, 避免硬编码漂移。当前阶段先用静态值确认行为正确。
#define HV_SPOOF_UWP_PATH_WIN32 L"C:\\Program Files\\WindowsApps\\Microsoft.WindowsNotepad_11.2502.22.0_x64__8wekyb3d8bbwe\\Notepad\\Notepad.exe"
#define HV_SPOOF_UWP_PATH_NT    L"\\Device\\HarddiskVolume3\\Program Files\\WindowsApps\\Microsoft.WindowsNotepad_11.2502.22.0_x64__8wekyb3d8bbwe\\Notepad\\Notepad.exe"
#define HV_SPOOF_UWP_CMDLINE    L"\"C:\\Program Files\\WindowsApps\\Microsoft.WindowsNotepad_11.2502.22.0_x64__8wekyb3d8bbwe\\Notepad\\Notepad.exe\""

// 隐藏内存区域列表（提前声明以便在 Cleanup 中使用）
static LIST_ENTRY g_HiddenMemoryList = { 0 };
static KSPIN_LOCK g_HiddenMemoryLock;
static BOOLEAN g_HiddenMemoryInitialized = FALSE;

// 反反调试状态
static BOOLEAN g_AntiAntiDebugEnabled = FALSE;
static HV_ANTIANTIDEBUG_CONFIG g_AntiAntiDebugConfig = { 0 };
static HV_HOOK_HANDLE g_HookNtQueryInformationProcess = NULL;
static HV_HOOK_HANDLE g_HookNtQuerySystemInformation = NULL;
static HV_HOOK_HANDLE g_HookNtQueryVirtualMemory = NULL;
// 2026-06-17: win32k window-enumeration spoofing hooks
// 2026-06-19: NtUserBuildHwndList hook 复活 — 从枚举结果里抹掉 debugger hwnd
static HV_HOOK_HANDLE g_HookNtUserBuildHwndList = NULL;
// 2026-06-19: 防 Spy++ 拖拽 — point-based hwnd 查询
static HV_HOOK_HANDLE g_HookNtUserWindowFromPoint = NULL;
static HV_HOOK_HANDLE g_HookNtUserChildWindowFromPointEx = NULL;
static HV_HOOK_HANDLE g_HookNtUserQueryWindow = NULL;
static HV_HOOK_HANDLE g_HookNtUserInternalGetWindowText = NULL;
static HV_HOOK_HANDLE g_HookNtUserGetClassName = NULL;
static HV_HOOK_HANDLE g_HookNtUserFindWindowEx = NULL;
static HV_HOOK_HANDLE g_HookNtSetInformationThread = NULL;
static HV_HOOK_HANDLE g_HookNtClose = NULL;
static HV_HOOK_HANDLE g_HookNtQueryObject = NULL;
static HV_HOOK_HANDLE g_HookNtGetContextThread = NULL;
static HV_HOOK_HANDLE g_HookNtSetContextThread = NULL;
// P121: attach 无痕 — hook NtDebugActiveProcess 抹 PEB.BeingDebugged + NtGlobalFlag
static HV_HOOK_HANDLE g_HookNtDebugActiveProcess = NULL;

// 阶段 7.8: 调试器代理 hook (HWBP 静默 + 跨进程 R/W 走 VtRoot)
static BOOLEAN g_DebuggerProxyEnabled = FALSE;
static HV_HOOK_HANDLE g_HookNtReadVirtualMemory  = NULL;
static HV_HOOK_HANDLE g_HookNtWriteVirtualMemory = NULL;
// NtSetContextThread 复用 g_HookNtSetContextThread (上面)

// 2026-06-18: R3 内存保护 — 反作弊绕过路径
static HV_HOOK_HANDLE g_HookNtReadVirtualMemoryEx = NULL;   // Win11 NtRead 新变体
static HV_HOOK_HANDLE g_HookNtCreateSection      = NULL;    // Section 创建
static HV_HOOK_HANDLE g_HookNtMapViewOfSection   = NULL;    // Section→进程映射
static HV_HOOK_HANDLE g_HookNtMapViewOfSectionEx = NULL;    // Win10+ Ex 版本
static HV_HOOK_HANDLE g_HookNtCreateThreadEx     = NULL;    // 跨进程远程线程

// P106: 线程访问/控制 hook — 反作弊拦 OpenThread/SuspendThread 阻调试器
// g_HookNtGetContextThread 复用 上面已声明的同名变量 (现有 cleanup 路径也只清这一个)
static HV_HOOK_HANDLE g_HookNtSuspendThread       = NULL;
static HV_HOOK_HANDLE g_HookNtResumeThread        = NULL;
static HV_HOOK_HANDLE g_HookNtOpenThread          = NULL;

// 受保护调试器列表
static LIST_ENTRY g_ProtectedDebuggerList = { 0 };
static KSPIN_LOCK g_ProtectedDebuggerLock;
static BOOLEAN g_ProtectedDebuggerInitialized = FALSE;

// 受保护进程列表
static LIST_ENTRY g_ProtectedProcessList = { 0 };
static KSPIN_LOCK g_ProtectedProcessLock;
static BOOLEAN g_ProtectedProcessInitialized = FALSE;

// DSE 状态 (#28 重构后)
//   旧路径: 写 g_CiOptions —— PG hash 区,5-15 分钟必蓝。
//   新路径: EPT-hook CiValidateImageHeader,让它无条件返回 STATUS_SUCCESS。
//           g_CiOptions 本身不动,PG 看不到改写。
static BOOLEAN g_DseDisabled = FALSE;
static HV_HOOK_HANDLE g_CiValidateImageHeaderHook = NULL;
static PVOID g_CiValidateImageHeaderTarget = NULL;

// Phase K 前向声明 (实现在文件下半部,init 路径要先调用)
VOID HvHookpScanTrustedPids(VOID);

// ============================================================
// Phase G: 根因事件 ring buffer
// ============================================================
//
// 256 entry FIFO,溢出覆盖最旧。Post 持有 KSPIN_LOCK (IRQL <= DISPATCH 安全)。
// Sequence 单调递增从 1 开始,0 保留为"未拉取过"哨兵。
// 客户端拉时只取 Sequence > SinceSequence 的,OutNextSequence = ring 中最新 seq。
//
// 容量 256 × sizeof(HV_DBGEVT)≈ 35KB,常驻 NonPagedPool,可接受。

static HV_DBGEVT g_DbgEvtRing[HV_DBGEVT_RING_SIZE];
static volatile UINT64 g_DbgEvtNextSeq = 1;   // 下一次分配的 Sequence
static KSPIN_LOCK g_DbgEvtLock;
static BOOLEAN g_DbgEvtInit = FALSE;

// P122: HvTrace re-entrancy guard. 防 DbgPrint → HvTracePrint → HvDbgEvtPost
// spinlock → 内部 DbgPrint → 二次抢锁 deadlock. per-CPU 1-slot (64 上限).
volatile LONG g_HvTraceReentryGuard[64] = { 0 };

// ============================================================
// 初始化和清理
// ============================================================

NTSTATUS
HvHookInitialize(VOID)
{
    NTSTATUS status;
    CPU_VENDOR cpuVendor;
    
    if (g_HvHookInitialized) {
        DbgPrint("[HvHook] Already initialized\n");
        return STATUS_SUCCESS;
    }

    // Phase G: ring buffer (Post 在所有路径都可能被调,提前初始化)
    if (!g_DbgEvtInit) {
        KeInitializeSpinLock(&g_DbgEvtLock);
        RtlZeroMemory(g_DbgEvtRing, sizeof(g_DbgEvtRing));
        g_DbgEvtNextSeq = 1;
        g_DbgEvtInit = TRUE;
    }

    // 检测 CPU 类型
    cpuVendor = HvGetCpuVendor();
    
    DbgPrint("[HvHook] Initializing Hook Manager...\n");
    DbgPrint("[HvHook] CPU Vendor: %s\n", 
        cpuVendor == CPU_VENDOR_INTEL ? "Intel" : 
        cpuVendor == CPU_VENDOR_AMD ? "AMD" : "Unknown");
    
    // 根据 CPU 类型初始化对应的 Hook 模块
    if (cpuVendor == CPU_VENDOR_INTEL) {
        status = EptHookInitialize();
        if (NT_SUCCESS(status)) {
            g_HvHookBackend = CPU_VENDOR_INTEL;
            g_HvHookInitialized = TRUE;
            DbgPrint("[HvHook] EPT Hook backend initialized successfully\n");
        } else {
            DbgPrint("[HvHook] EPT Hook initialization failed: 0x%X\n", status);
        }
    } 
    else if (cpuVendor == CPU_VENDOR_AMD) {
        status = NptHookInitialize();
        if (NT_SUCCESS(status)) {
            g_HvHookBackend = CPU_VENDOR_AMD;
            g_HvHookInitialized = TRUE;
            DbgPrint("[HvHook] NPT Hook backend initialized successfully\n");
        } else {
            DbgPrint("[HvHook] NPT Hook initialization failed: 0x%X\n", status);
        }
    }
    else {
        DbgPrint("[HvHook] Unknown CPU vendor, cannot initialize\n");
        status = STATUS_NOT_SUPPORTED;
    }

    // Phase K: 启动期一次性扫描可信系统进程 PID
    // (放在 backend init 后,确保系统已稳定,但失败不影响 hook 功能)
    if (g_HvHookInitialized) {
        HvHookpScanTrustedPids();
    }

    return status;
}

VOID
HvHookCleanup(VOID)
{
    KIRQL oldIrql;
    PLIST_ENTRY entry;
    PHIDDEN_MEMORY_REGION region;
    
    if (!g_HvHookInitialized) {
        return;
    }
    
    DbgPrint("[HvHook] Cleaning up Hook Manager...\n");

    // 阶段 7.9: 显式关闭 NtOpenProcess bypass,确保状态标志和句柄被清掉
    // (HvHookRemoveAll 会移除底层 hook,但不会清这一层的 g_AccessBypassEnabled)
    HvHookDisableAccessBypass();

    // 先移除所有 Hook
    HvHookRemoveAll();
    
    // 清理隐藏内存区域列表
    if (g_HiddenMemoryInitialized) {
        KeAcquireSpinLock(&g_HiddenMemoryLock, &oldIrql);
        while (!IsListEmpty(&g_HiddenMemoryList)) {
            entry = RemoveHeadList(&g_HiddenMemoryList);
            region = CONTAINING_RECORD(entry, HIDDEN_MEMORY_REGION, ListEntry);
            ExFreePoolWithTag(region, 'mHvH');
        }
        KeReleaseSpinLock(&g_HiddenMemoryLock, oldIrql);
        g_HiddenMemoryInitialized = FALSE;
        DbgPrint("[HvHook] Hidden memory regions cleaned up\n");
    }
    
    // 根据后端类型清理
    if (g_HvHookBackend == CPU_VENDOR_INTEL) {
        EptHookCleanup();
        DbgPrint("[HvHook] EPT Hook backend cleaned up\n");
    } 
    else if (g_HvHookBackend == CPU_VENDOR_AMD) {
        NptHookCleanup();
        DbgPrint("[HvHook] NPT Hook backend cleaned up\n");
    }
    
    g_HvHookInitialized = FALSE;
    g_HvHookBackend = CPU_VENDOR_UNKNOWN;
}

BOOLEAN
HvHookIsInitialized(VOID)
{
    return g_HvHookInitialized;
}

CPU_VENDOR
HvHookGetBackendType(VOID)
{
    return g_HvHookBackend;
}

// ============================================================
// Hook 管理
// ============================================================

NTSTATUS
HvHookInstall(
    _In_ PVOID TargetAddress,
    _In_ PVOID HookFunction,
    _Out_opt_ HV_HOOK_HANDLE* OutHandle
)
{
    NTSTATUS status;
    
    if (!g_HvHookInitialized) {
        DbgPrint("[HvHook] Not initialized\n");
        return STATUS_UNSUCCESSFUL;
    }
    
    if (TargetAddress == NULL || HookFunction == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    
    DbgPrint("[HvHook] Installing hook at %p -> %p\n", TargetAddress, HookFunction);

    if (g_HvHookBackend == CPU_VENDOR_INTEL) {
        PEPT_HOOK_ENTRY entry = NULL;
        status = EptHookInstall(TargetAddress, HookFunction, &entry);
        if (OutHandle) {
            *OutHandle = (HV_HOOK_HANDLE)entry;
        }
    } 
    else if (g_HvHookBackend == CPU_VENDOR_AMD) {
        PNPT_HOOK_ENTRY entry = NULL;
        status = NptHookInstall(TargetAddress, HookFunction, &entry);
        if (OutHandle) {
            *OutHandle = (HV_HOOK_HANDLE)entry;
        }
    }
    else {
        status = STATUS_NOT_SUPPORTED;
    }
    
    if (NT_SUCCESS(status)) {
        DbgPrint("[HvHook] Hook installed successfully\n");
    } else {
        DbgPrint("[HvHook] Hook installation failed: 0x%X\n", status);
    }
    
    return status;
}

NTSTATUS
HvHookRemove(
    _In_ HV_HOOK_HANDLE Handle
)
{
    if (!g_HvHookInitialized || Handle == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    
    DbgPrint("[HvHook] Removing hook %p\n", Handle);
    
    if (g_HvHookBackend == CPU_VENDOR_INTEL) {
        return EptHookRemove((PEPT_HOOK_ENTRY)Handle);
    } 
    else if (g_HvHookBackend == CPU_VENDOR_AMD) {
        return NptHookRemove((PNPT_HOOK_ENTRY)Handle);
    }
    
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS
HvHookRemoveByAddress(
    _In_ PVOID TargetAddress
)
{
    if (!g_HvHookInitialized || TargetAddress == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    
    DbgPrint("[HvHook] Removing hook at address %p\n", TargetAddress);
    
    if (g_HvHookBackend == CPU_VENDOR_INTEL) {
        return EptHookRemoveByAddress(TargetAddress);
    } 
    else if (g_HvHookBackend == CPU_VENDOR_AMD) {
        return NptHookRemoveByAddress(TargetAddress);
    }
    
    return STATUS_NOT_SUPPORTED;
}

VOID
HvHookRemoveAll(VOID)
{
    if (!g_HvHookInitialized) {
        return;
    }
    
    DbgPrint("[HvHook] Removing all hooks\n");
    
    if (g_HvHookBackend == CPU_VENDOR_INTEL) {
        EptHookRemoveAll();
    } 
    else if (g_HvHookBackend == CPU_VENDOR_AMD) {
        NptHookRemoveAll();
    }
}

// ============================================================
// Hook 查询
// ============================================================

HV_HOOK_HANDLE
HvHookFindByPhysicalAddress(
    _In_ ULONG64 PhysicalAddress
)
{
    if (!g_HvHookInitialized) {
        return NULL;
    }
    
    if (g_HvHookBackend == CPU_VENDOR_INTEL) {
        return (HV_HOOK_HANDLE)EptHookFindByPhysicalAddress(PhysicalAddress);
    } 
    else if (g_HvHookBackend == CPU_VENDOR_AMD) {
        return (HV_HOOK_HANDLE)NptHookFindByPhysicalAddress(PhysicalAddress);
    }
    
    return NULL;
}

HV_HOOK_HANDLE
HvHookFindByVirtualAddress(
    _In_ PVOID VirtualAddress
)
{
    if (!g_HvHookInitialized) {
        return NULL;
    }
    
    if (g_HvHookBackend == CPU_VENDOR_INTEL) {
        return (HV_HOOK_HANDLE)EptHookFindByVirtualAddress(VirtualAddress);
    } 
    else if (g_HvHookBackend == CPU_VENDOR_AMD) {
        return (HV_HOOK_HANDLE)NptHookFindByVirtualAddress(VirtualAddress);
    }
    
    return NULL;
}

NTSTATUS
HvHookGetInfo(
    _In_ HV_HOOK_HANDLE Handle,
    _Out_ PHV_HOOK_INFO OutInfo
)
{
    if (!g_HvHookInitialized || Handle == NULL || OutInfo == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    
    RtlZeroMemory(OutInfo, sizeof(HV_HOOK_INFO));
    
    if (g_HvHookBackend == CPU_VENDOR_INTEL) {
        PEPT_HOOK_ENTRY entry = (PEPT_HOOK_ENTRY)Handle;
        OutInfo->State = (HV_HOOK_STATE)entry->State;
        OutInfo->Type = (HV_HOOK_TYPE)entry->Type;
        OutInfo->TargetVirtualAddress = entry->TargetVirtualAddress;
        OutInfo->TargetPhysicalAddress = entry->TargetPhysicalAddress;
        OutInfo->HookFunction = entry->HookFunction;
        OutInfo->TrampolineAddress = entry->TrampolineAddress;
        OutInfo->HitCount = entry->HitCount;
    } 
    else if (g_HvHookBackend == CPU_VENDOR_AMD) {
        PNPT_HOOK_ENTRY entry = (PNPT_HOOK_ENTRY)Handle;
        OutInfo->State = (HV_HOOK_STATE)entry->State;
        OutInfo->Type = (HV_HOOK_TYPE)entry->Type;
        OutInfo->TargetVirtualAddress = entry->TargetVirtualAddress;
        OutInfo->TargetPhysicalAddress = entry->TargetPhysicalAddress;
        OutInfo->HookFunction = entry->HookFunction;
        OutInfo->TrampolineAddress = entry->TrampolineAddress;
        OutInfo->HitCount = entry->HitCount;
    }
    else {
        return STATUS_NOT_SUPPORTED;
    }
    
    return STATUS_SUCCESS;
}

ULONG
HvHookGetCount(VOID)
{
    if (!g_HvHookInitialized) {
        return 0;
    }
    
    if (g_HvHookBackend == CPU_VENDOR_INTEL) {
        return g_EptHookManager.HookCount;
    } 
    else if (g_HvHookBackend == CPU_VENDOR_AMD) {
        return g_NptHookManager.HookCount;
    }
    
    return 0;
}

// ============================================================
// 跳板
// ============================================================

PVOID
HvHookGetTrampoline(
    _In_ HV_HOOK_HANDLE Handle
)
{
    if (!g_HvHookInitialized || Handle == NULL) {
        return NULL;
    }
    
    if (g_HvHookBackend == CPU_VENDOR_INTEL) {
        return EptHookGetTrampoline((PEPT_HOOK_ENTRY)Handle);
    } 
    else if (g_HvHookBackend == CPU_VENDOR_AMD) {
        return NptHookGetTrampoline((PNPT_HOOK_ENTRY)Handle);
    }
    
    return NULL;
}

// ============================================================
// 高级功能：进程隐藏
// ============================================================

NTSTATUS
HvHookHideProcess(
    _In_ ULONG ProcessId
)
{
    if (!g_HvHookInitialized) {
        return STATUS_UNSUCCESSFUL;
    }
    
    DbgPrint("[HvHook] Hiding process ID: %lu\n", ProcessId);
    
    if (g_HvHookBackend == CPU_VENDOR_INTEL) {
        return EptHookHideProcess(ProcessId);
    } 
    else if (g_HvHookBackend == CPU_VENDOR_AMD) {
        return NptHookHideProcess(ProcessId);
    }
    
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS
HvHookHideProcessByName(
    _In_ PCWSTR ProcessName
)
{
    if (!g_HvHookInitialized || ProcessName == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    
    DbgPrint("[HvHook] Hiding process by name: %ws\n", ProcessName);
    
    if (g_HvHookBackend == CPU_VENDOR_INTEL) {
        return EptHookHideProcessByName(ProcessName);
    } 
    else if (g_HvHookBackend == CPU_VENDOR_AMD) {
        return NptHookHideProcessByName(ProcessName);
    }
    
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS
HvHookUnhideProcess(
    _In_ ULONG ProcessId
)
{
    if (!g_HvHookInitialized) {
        return STATUS_UNSUCCESSFUL;
    }
    
    DbgPrint("[HvHook] Unhiding process ID: %lu\n", ProcessId);
    
    if (g_HvHookBackend == CPU_VENDOR_INTEL) {
        return EptHookUnhideProcess(ProcessId);
    } 
    else if (g_HvHookBackend == CPU_VENDOR_AMD) {
        return NptHookUnhideProcess(ProcessId);
    }
    
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS
HvHookUnhideProcessByName(
    _In_ PCWSTR ProcessName
)
{
    if (!g_HvHookInitialized || ProcessName == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    
    DbgPrint("[HvHook] Unhiding process by name: %ws\n", ProcessName);
    
    if (g_HvHookBackend == CPU_VENDOR_INTEL) {
        return EptHookUnhideProcessByName(ProcessName);
    } 
    else if (g_HvHookBackend == CPU_VENDOR_AMD) {
        return NptHookUnhideProcessByName(ProcessName);
    }
    
    return STATUS_NOT_SUPPORTED;
}

// ============================================================
// 驱动文件隐藏
// ============================================================

NTSTATUS
HvHookInstallFileHideHook(VOID)
{
    if (!g_HvHookInitialized) {
        return STATUS_NOT_INITIALIZED;
    }
    
    DbgPrint("[HvHook] Installing file hide hook\n");
    
    if (g_HvHookBackend == CPU_VENDOR_INTEL) {
        return EptHookInstallFileHideHook();
    } 
    else if (g_HvHookBackend == CPU_VENDOR_AMD) {
        return NptHookInstallFileHideHook();
    }
    
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS
HvHookRemoveFileHideHook(VOID)
{
    if (!g_HvHookInitialized) {
        return STATUS_NOT_INITIALIZED;
    }
    
    DbgPrint("[HvHook] Removing file hide hook\n");
    
    if (g_HvHookBackend == CPU_VENDOR_INTEL) {
        return EptHookRemoveFileHideHook();
    } 
    else if (g_HvHookBackend == CPU_VENDOR_AMD) {
        return NptHookRemoveFileHideHook();
    }
    
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS
HvHookHideDriverFile(
    _In_ PCWSTR FileName
)
{
    if (!g_HvHookInitialized || FileName == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    
    DbgPrint("[HvHook] Hiding driver file: %ws\n", FileName);
    
    if (g_HvHookBackend == CPU_VENDOR_INTEL) {
        return EptHookHideFile(FileName);
    } 
    else if (g_HvHookBackend == CPU_VENDOR_AMD) {
        return NptHookHideFile(FileName);
    }
    
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS
HvHookUnhideDriverFile(
    _In_ PCWSTR FileName
)
{
    if (!g_HvHookInitialized || FileName == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    
    DbgPrint("[HvHook] Unhiding driver file: %ws\n", FileName);
    
    if (g_HvHookBackend == CPU_VENDOR_INTEL) {
        return EptHookUnhideFile(FileName);
    } 
    else if (g_HvHookBackend == CPU_VENDOR_AMD) {
        return NptHookUnhideFile(FileName);
    }
    
    return STATUS_NOT_SUPPORTED;
}

// ============================================================
// 内存区域隐藏
// ============================================================

NTSTATUS
HvHookHideMemoryRegion(
    _In_ ULONG ProcessId,
    _In_ PVOID Address,
    _In_ SIZE_T Size
)
{
    PHIDDEN_MEMORY_REGION region;
    KIRQL oldIrql;
    
    if (!g_HvHookInitialized) {
        return STATUS_NOT_INITIALIZED;
    }
    
    // 初始化列表（如果需要）
    if (!g_HiddenMemoryInitialized) {
        InitializeListHead(&g_HiddenMemoryList);
        KeInitializeSpinLock(&g_HiddenMemoryLock);
        g_HiddenMemoryInitialized = TRUE;
    }
    
    DbgPrint("[HvHook] Hiding memory region: PID=%d, Address=%p, Size=0x%llX\n",
        ProcessId, Address, (ULONGLONG)Size);
    
    // 创建记录
    region = (PHIDDEN_MEMORY_REGION)HvAllocateNonPagedZeroed(
        sizeof(HIDDEN_MEMORY_REGION), 'mHvH');
    
    if (!region) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    region->ProcessId = ProcessId;
    region->Address = Address;
    region->Size = Size;
    
    // 添加到列表
    KeAcquireSpinLock(&g_HiddenMemoryLock, &oldIrql);
    InsertTailList(&g_HiddenMemoryList, &region->ListEntry);
    KeReleaseSpinLock(&g_HiddenMemoryLock, oldIrql);
    
    // 安装 NtQueryVirtualMemory Hook 来实际隐藏内存
    // 使用 HvInjection.c 中实现的内存隐藏功能
    {
        NTSTATUS hookStatus = HvInstallMemoryHideHook();
        if (!NT_SUCCESS(hookStatus)) {
            DbgPrint("[HvHook] Warning: Failed to install memory hide hook: 0x%X\n", hookStatus);
            // 继续返回成功，因为记录已添加
        }
        
        // 添加到 HvInjection 的隐藏列表（完整隐藏模式）
        hookStatus = HvAddHiddenMemoryRegion(ProcessId, Address, Size, HvHideModeComplete);
        if (!NT_SUCCESS(hookStatus)) {
            DbgPrint("[HvHook] Warning: Failed to add to injection hidden list: 0x%X\n", hookStatus);
        }
    }
    
    return STATUS_SUCCESS;
}

NTSTATUS
HvHookUnhideMemoryRegion(
    _In_ ULONG ProcessId,
    _In_ PVOID Address
)
{
    PLIST_ENTRY entry;
    PHIDDEN_MEMORY_REGION region = NULL;
    KIRQL oldIrql;
    BOOLEAN found = FALSE;
    
    if (!g_HvHookInitialized || !g_HiddenMemoryInitialized) {
        return STATUS_NOT_INITIALIZED;
    }
    
    DbgPrint("[HvHook] Unhiding memory region: PID=%d, Address=%p\n",
        ProcessId, Address);
    
    KeAcquireSpinLock(&g_HiddenMemoryLock, &oldIrql);
    
    for (entry = g_HiddenMemoryList.Flink;
         entry != &g_HiddenMemoryList;
         entry = entry->Flink)
    {
        region = CONTAINING_RECORD(entry, HIDDEN_MEMORY_REGION, ListEntry);
        
        if (region->ProcessId == ProcessId && region->Address == Address) {
            RemoveEntryList(entry);
            found = TRUE;
            break;
        }
    }
    
    KeReleaseSpinLock(&g_HiddenMemoryLock, oldIrql);
    
    if (found && region) {
        ExFreePoolWithTag(region, 'mHvH');
        return STATUS_SUCCESS;
    }
    
    return STATUS_NOT_FOUND;
}

NTSTATUS
HvHookHideModule(
    _In_ ULONG ProcessId,
    _In_ PVOID ModuleBase
)
{
    if (!g_HvHookInitialized) {
        return STATUS_NOT_INITIALIZED;
    }
    
    DbgPrint("[HvHook] Hiding module: PID=%d, Base=%p\n", ProcessId, ModuleBase);
    
    // 调用 HvInjection.c 中的 PEB LdrModuleList 解链实现
    return HvHideInjectedModule(ProcessId, ModuleBase);
}

// ============================================================
// 调试函数
// ============================================================

VOID
HvHookPrintInfo(VOID)
{
    DbgPrint("[HvHook] === Hook Manager Info ===\n");
    DbgPrint("[HvHook] Initialized: %s\n", g_HvHookInitialized ? "Yes" : "No");
    DbgPrint("[HvHook] Backend: %s\n", 
        g_HvHookBackend == CPU_VENDOR_INTEL ? "Intel EPT" :
        g_HvHookBackend == CPU_VENDOR_AMD ? "AMD NPT" : "Unknown");
    DbgPrint("[HvHook] Hook Count: %lu\n", HvHookGetCount());
    
    if (g_HvHookInitialized) {
        if (g_HvHookBackend == CPU_VENDOR_INTEL) {
            EptPrintInfo();
        } 
        else if (g_HvHookBackend == CPU_VENDOR_AMD) {
            NptPrintInfo();
        }
    }
    
    DbgPrint("[HvHook] ========================\n");
}

BOOLEAN
HvHookIsConfigured(VOID)
{
    if (!g_HvHookInitialized) {
        return FALSE;
    }
    
    if (g_HvHookBackend == CPU_VENDOR_INTEL) {
        return EptIsConfigured();
    } 
    else if (g_HvHookBackend == CPU_VENDOR_AMD) {
        return NptIsConfigured();
    }
    
    return FALSE;
}

// ============================================================
// 驱动隐藏（基于 EPT/NPT Hook，完美隐身）
// ============================================================

NTSTATUS
HvHookInstallDriverHideHook(VOID)
{
    if (!g_HvHookInitialized) {
        return STATUS_NOT_INITIALIZED;
    }
    
    DbgPrint("[HvHook] Installing Driver Hide Hooks (EPT/NPT method)...\n");
    
    if (g_HvHookBackend == CPU_VENDOR_INTEL) {
        return EptHookInstallDriverHideHook();
    }
    else if (g_HvHookBackend == CPU_VENDOR_AMD) {
        return NptHookInstallDriverHideHook();
    }
    
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS
HvHookRemoveDriverHideHook(VOID)
{
    if (!g_HvHookInitialized) {
        return STATUS_SUCCESS;
    }
    
    DbgPrint("[HvHook] Removing Driver Hide Hooks...\n");
    
    if (g_HvHookBackend == CPU_VENDOR_INTEL) {
        return EptHookRemoveDriverHideHook();
    }
    else if (g_HvHookBackend == CPU_VENDOR_AMD) {
        return NptHookRemoveDriverHideHook();
    }
    
    return STATUS_SUCCESS;
}

NTSTATUS
HvHookHideDriverSafe(
    _In_ PDRIVER_OBJECT DriverObject
)
{
    if (!g_HvHookInitialized) {
        return STATUS_NOT_INITIALIZED;
    }
    
    if (!DriverObject) {
        return STATUS_INVALID_PARAMETER;
    }
    
    DbgPrint("[HvHook] Hiding driver using EPT/NPT Hook (Safe method)...\n");
    
    if (g_HvHookBackend == CPU_VENDOR_INTEL) {
        return EptHookHideDriver(DriverObject);
    }
    else if (g_HvHookBackend == CPU_VENDOR_AMD) {
        return NptHookHideDriver(DriverObject);
    }
    
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS
HvHookHideDriverByNameSafe(
    _In_ PCWSTR DriverName
)
{
    if (!g_HvHookInitialized) {
        return STATUS_NOT_INITIALIZED;
    }
    
    if (!DriverName) {
        return STATUS_INVALID_PARAMETER;
    }
    
    DbgPrint("[HvHook] Hiding driver by name using EPT/NPT Hook: %ws\n", DriverName);
    
    if (g_HvHookBackend == CPU_VENDOR_INTEL) {
        return EptHookHideDriverByName(DriverName);
    }
    else if (g_HvHookBackend == CPU_VENDOR_AMD) {
        return NptHookHideDriverByName(DriverName);
    }
    
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS
HvHookUnhideDriverSafe(
    _In_ PDRIVER_OBJECT DriverObject
)
{
    if (!g_HvHookInitialized) {
        return STATUS_NOT_INITIALIZED;
    }
    
    if (!DriverObject) {
        return STATUS_INVALID_PARAMETER;
    }
    
    if (g_HvHookBackend == CPU_VENDOR_INTEL) {
        return EptHookUnhideDriver(DriverObject);
    }
    else if (g_HvHookBackend == CPU_VENDOR_AMD) {
        return NptHookUnhideDriver(DriverObject);
    }
    
    return STATUS_NOT_SUPPORTED;
}

// ============================================================
// 反反调试实现
// ============================================================

// 原始函数类型定义
typedef NTSTATUS (NTAPI *PFN_NtQueryInformationProcess)(
    HANDLE ProcessHandle,
    ULONG ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

typedef NTSTATUS (NTAPI *PFN_NtQuerySystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

typedef NTSTATUS (NTAPI *PFN_NtSetInformationThread)(
    HANDLE ThreadHandle,
    ULONG ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength
);

typedef NTSTATUS (NTAPI *PFN_NtClose)(
    HANDLE Handle
);

// Phase K 前向声明: HvHookpProcessHandleToProcessId 实现在文件下半部 (line 1961),
// 但 Phase K 后 HookedNtQueryInformationProcess (line 1003) 也需要调用它。
static HANDLE HvHookpProcessHandleToProcessId(HANDLE ProcessHandle);

typedef NTSTATUS (NTAPI *PFN_NtQueryObject)(
    HANDLE Handle,
    ULONG ObjectInformationClass,
    PVOID ObjectInformation,
    ULONG ObjectInformationLength,
    PULONG ReturnLength
);

typedef NTSTATUS (NTAPI *PFN_NtQueryVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID  BaseAddress,
    ULONG  MemoryInformationClass,
    PVOID  MemoryInformation,
    SIZE_T MemoryInformationLength,
    PSIZE_T ReturnLength
);

// MEMORY_INFORMATION_CLASS::MemoryMappedFilenameInformation = 2
#define HV_MEMORY_MAPPED_FILENAME_INFO  2

// ProcessInformationClass 常量
#define ProcessDebugPort            7
#define ProcessDebugObjectHandle    30
#define ProcessDebugFlags           31

// SystemInformationClass 常量
#define SystemKernelDebuggerInformation 35

// ThreadInformationClass 常量
#define ThreadHideFromDebugger      17

// ObjectInformationClass 常量
#define ObjectTypesInformation      3

// 简化的 SYSTEM_PROCESS_INFORMATION —— 字段必须与 nt 内部结构对齐。
// 2026-06-17: WorkingSetPrivateSize 是 1 个 LARGE_INTEGER 不是 3 个,
// 之前 Reserved[3] 多算 16 字节导致整段后续字段错位。
#define HV_SYSTEM_PROCESS_INFORMATION_CLASS 5    // SystemProcessInformation
typedef struct _HV_SYSTEM_PROCESS_INFO_HEADER {
    ULONG          NextEntryOffset;
    ULONG          NumberOfThreads;
    LARGE_INTEGER  WorkingSetPrivateSize;        // 1 个 LARGE_INTEGER
    ULONG          HardFaultCount;
    ULONG          NumberOfThreadsHighWatermark;
    ULONGLONG      CycleTime;
    LARGE_INTEGER  CreateTime;
    LARGE_INTEGER  UserTime;
    LARGE_INTEGER  KernelTime;
    UNICODE_STRING ImageName;
    LONG           BasePriority;
    HANDLE         UniqueProcessId;
    // 后面更多字段不需要
} HV_SYSTEM_PROCESS_INFO_HEADER, *PHV_SYSTEM_PROCESS_INFO_HEADER;

// Hook 后的 NtQueryInformationProcess
//
// Phase K (2026-06-03): 该 hook 现在由 HvHookEnableDebuggerProxy 常驻装载,
// 不再由 HvHookEnableAntiAntiDebug 控制。两套逻辑独立:
//   1. 反向保护 (常态): target=debugger && caller 不可信 → ACCESS_DENIED
//      隐藏 debugger 的 ImagePath/CmdLine/PEB/SessionId 等,反作弊扫不到指纹
//   2. AAD 反调试 spoof (可选): g_AntiAntiDebugEnabled=TRUE 时生效
//      对 ProcessDebugPort/Object/Flags 返"未调试" — 但要小心副作用
static NTSTATUS NTAPI HookedNtQueryInformationProcess(
    HANDLE ProcessHandle,
    ULONG ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
)
{
    PFN_NtQueryInformationProcess Original =
        (PFN_NtQueryInformationProcess)HvHookGetTrampoline(g_HookNtQueryInformationProcess);
    if (!Original) {
        return STATUS_UNSUCCESSFUL;
    }

    // 2026-06-16 诊断 bypass: TRUE 时直接走 Original, 不做反向保护 / AAD spoof
    if (g_BypassNtQueryInformationProcess) {
        return Original(ProcessHandle, ProcessInformationClass,
                        ProcessInformation, ProcessInformationLength, ReturnLength);
    }

    // M3 修正: IRQL > APC_LEVEL 走 Original 避免 0xD1
    if (KeGetCurrentIrql() > APC_LEVEL) {
        return Original(ProcessHandle, ProcessInformationClass,
                        ProcessInformation, ProcessInformationLength, ReturnLength);
    }

    // 2026-06-17 Phase K' (升级):
    //   旧: target=debugger && caller 不可信 → ACCESS_DENIED — 反作弊看到 DENIED
    //       立刻警觉, 知道有 driver 干预。
    //   新: 放行 query, 在 Original 返回后**拦截改值** — debugger 进程的 EXE 路径
    //       / CmdLine / ImageBaseName 等都改成 notepad.exe, 反作弊以为 debugger
    //       就是 notepad, 完全感知不到 driver 存在。
    HANDLE caller = PsGetCurrentProcessId();
    HANDLE targetPid = HvHookpProcessHandleToProcessId(ProcessHandle);

    // 2026-06-19: 路径查询类 (27 ImageFileName / 43 Win32ImageName / 60 CmdLine) —
    // 必须**对所有 caller** spoof (debugger 自己除外)。
    //
    // 旧逻辑把 taskmgr / explorer 当 trusted 跳过 spoof, 结果任务管理器右键
    // "打开文件位置" 拿到 debugger 真路径定位到桌面, DHS 同场景定位到系统 Notepad —
    // 差异即此。trusted 白名单的设计初衷是放行**反向保护**(NtOpenProcess 拒访问会
    // 卡死登录会话), 但读 EXE 路径不是反向保护范畴, 不需要放行。
    //
    // 非路径类 (DebugPort/DebugFlags/AAD 系列) 仍走老 trusted 判断逻辑 (下方 AAD 段)。
    BOOLEAN isPathClass =
        (ProcessInformationClass == 27 ||   // ProcessImageFileName
         ProcessInformationClass == 43 ||   // ProcessImageFileNameWin32
         ProcessInformationClass == 60);    // ProcessCommandLineInformation

    BOOLEAN doSpoof = (targetPid &&
                       HvHookIsDebuggerPid(targetPid) &&
                       caller != targetPid &&
                       !HvHookIsDebuggerPid(caller) &&
                       (isPathClass ? TRUE : !HvHookIsTrustedSystemCaller(caller)));

    // 调用原始函数
    NTSTATUS status = Original(ProcessHandle, ProcessInformationClass,
                               ProcessInformation, ProcessInformationLength, ReturnLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // ============================================================
    // 2026-06-17 进程信息 spoof (target=debugger, caller 不可信)
    // ============================================================
    //
    // 替换 EXE 路径 / 命令行字段为 "notepad.exe", 反作弊就识别不出 debugger 指纹。
    // 注意: 大部分类返回 UNICODE_STRING + Buffer 紧跟其后。我们能改 Buffer 内容
    // 但 Length 字段也要更新。
    //
    // 受影响的类:
    //   ProcessImageFileName (27)       —— UNICODE_STRING + buf, "\Device\HardDiskVolumeN\..."
    //   ProcessImageFileNameWin32 (43)  —— UNICODE_STRING + buf, "C:\..."
    //   ProcessCommandLineInformation (60) —— UNICODE_STRING + buf
    if (doSpoof && ProcessInformation && ProcessInformationLength >= sizeof(UNICODE_STRING)) {
        KPROCESSOR_MODE prevMode = ExGetPreviousMode();
        // 2026-06-19: 改用 UWP Notepad 路径 (HV_SPOOF_UWP_*, 全局定义)
        static const WCHAR kSpoofWin32[] = HV_SPOOF_UWP_PATH_WIN32;
        static const WCHAR kSpoofNt[]    = HV_SPOOF_UWP_PATH_NT;
        static const WCHAR kSpoofCmd[]   = HV_SPOOF_UWP_CMDLINE;

        PCWSTR spoofText = NULL;
        if (ProcessInformationClass == 27)   spoofText = kSpoofNt;
        else if (ProcessInformationClass == 43) spoofText = kSpoofWin32;
        else if (ProcessInformationClass == 60) spoofText = kSpoofCmd;

        if (spoofText) {
            ULONG spoofBytes = 0;
            for (PCWSTR p = spoofText; *p; p++) spoofBytes += sizeof(WCHAR);

            __try {
                if (prevMode == UserMode) {
                    ProbeForWrite(ProcessInformation, ProcessInformationLength,
                                  sizeof(ULONG));
                }
                UNICODE_STRING* us = (UNICODE_STRING*)ProcessInformation;
                // Buffer 紧跟 UNICODE_STRING 头部之后, 由内核统一分配; 反作弊
                // 期望 us->Buffer 指向 ProcessInformation 范围内的 buf
                if (us->Buffer &&
                    us->MaximumLength >= spoofBytes + sizeof(WCHAR))
                {
                    RtlCopyMemory(us->Buffer, spoofText, spoofBytes + sizeof(WCHAR));
                    us->Length = (USHORT)spoofBytes;
                    HV_HOT_DBG("[HvHook-Spoof] NtQIP class=%u target=%u caller=%u -> %ws\n",
                             ProcessInformationClass,
                             (ULONG)(ULONG_PTR)targetPid,
                             (ULONG)(ULONG_PTR)caller, spoofText);
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) { }
        }
    }

    // P121: AAD 反调试 spoof 自动启用条件:
    //   (a) g_AntiAntiDebugEnabled 显式 IOCTL 开 — 老路径
    //   (b) 系统注册了任何 debugger (HvHookGetDebuggerCount() > 0) — 新路径
    //
    //   场景: CE 通过 DebugActiveProcess 给游戏 attach 后, EPROCESS.DebugPort 非空,
    //         游戏自检 NtQueryInformationProcess(self, ProcessDebugPort) 立刻看到调试器
    //         → ExitProcess. driver 自动 spoof 让 query 永远返"未调试", 反作弊看不到.
    //
    //   只对三个 class (DebugPort/Object/Flags) 生效, 其他 class 透传不影响业务.
    BOOLEAN doAntiDebugSpoof = g_AntiAntiDebugEnabled;
    if (!doAntiDebugSpoof && HvHookGetDebuggerCount() > 0) {
        doAntiDebugSpoof = TRUE;
    }
    if (!doAntiDebugSpoof) {
        return status;
    }

    // P122+ CRITICAL: System (PID=4) / trusted system caller (csrss/wininit/svchost/lsass...)
    //   绝对不能 spoof. Windows 内核 DbgkWerProcessEvent / WER 子系统 / Session manager
    //   合法地 query target 进程的 DebugPort/Object 用于内部记账. 拿到伪造的 PORT_NOT_SET
    //   会让 DebugObject 引用计数 / 链表状态机错乱 → 系统级死锁 (实测).
    //   游戏 / 反作弊从 user mode 调时 caller 不会是 trusted, 仍然 spoof.
    if (HvHookIsTrustedSystemCaller(caller)) {
        return status;
    }
    // 进一步: caller 不是 user-mode process 也不 spoof (内核态调用 NtQueryInformationProcess,
    // 比如 WerFault.exe 启动期间走 ALPC 触发 System worker)
    if (ExGetPreviousMode() == KernelMode) {
        return status;
    }
    // P123 CRITICAL: caller 是注册过的 debugger (CE 等) 绝不 spoof.
    //   CE attach 成功后立刻 NtQueryInformationProcess(target, ProcessDebugObjectHandle)
    //   拿真 DebugObject handle 给 WaitForDebugEvent. 我们返 PORT_NOT_SET 会让 CE
    //   误以为 attach 失败 → EDebuggerAttachException → CE 直接退. 实测.
    //   debugger 看到真值, 反作弊 (非 debugger) 看到 spoof — 各得其所.
    if (HvHookIsDebuggerPid(caller)) {
        return status;
    }

    // 显式 IOCTL 模式 + TargetPid 限定: 只对该 PID 生效 (老语义).
    // 自动路径 (g_AntiAntiDebugEnabled=FALSE 但 HvHookGetDebuggerCount>0) 对所有进程生效.
    if (g_AntiAntiDebugEnabled && g_AntiAntiDebugConfig.TargetPid != 0) {
        PEPROCESS process = NULL;
        if (NT_SUCCESS(ObReferenceObjectByHandle(ProcessHandle, 0, *PsProcessType,
                                                  KernelMode, (PVOID*)&process, NULL))) {
            ULONG currentPid = (ULONG)(ULONG_PTR)PsGetProcessId(process);
            ObDereferenceObject(process);

            if (currentPid != g_AntiAntiDebugConfig.TargetPid) {
                return status;
            }
        }
    }
    
    KPROCESSOR_MODE aadMode = ExGetPreviousMode();
    // P121: 首次命中每类 / 每 500 次报一次到 ring (AAD cat=6, GUI trace 控制台可见)
    static volatile LONG g_AadHitDp = 0, g_AadHitDoh = 0, g_AadHitDf = 0;
    LONG hit;
    switch (ProcessInformationClass) {
    case ProcessDebugPort:
        if (ProcessInformation && ProcessInformationLength >= sizeof(HANDLE)) {
            __try {
                if (aadMode == UserMode) {
                    ProbeForWrite(ProcessInformation, sizeof(HANDLE), sizeof(HANDLE));
                }
                *(PHANDLE)ProcessInformation = NULL;
            } __except (EXCEPTION_EXECUTE_HANDLER) {}
            hit = InterlockedIncrement(&g_AadHitDp);
            if (hit == 1 || (hit % 500) == 0) {
                HvDbgEvtPost(HV_DBGEVT_SEV_INFO, HV_DBGEVT_CAT_AAD, 0,
                             (ULONG)(ULONG_PTR)caller,
                             (ULONG)(ULONG_PTR)targetPid, (UINT64)hit, 0,
                             "ProcessDebugPort spoofed -> NULL");
            }
        }
        break;

    case ProcessDebugObjectHandle:
        // P121: 不再返 ACCESS_DENIED (反作弊看到 DENIED 也警觉). 改返
        // STATUS_PORT_NOT_SET — 这是 attached 进程没设 debug port 时的标准返回,
        // 反作弊看了不警觉, 跟"没人 attach" 等价.
        if (ProcessInformation && ProcessInformationLength >= sizeof(HANDLE)) {
            __try {
                if (aadMode == UserMode) {
                    ProbeForWrite(ProcessInformation, sizeof(HANDLE), sizeof(HANDLE));
                }
                *(PHANDLE)ProcessInformation = NULL;
            } __except (EXCEPTION_EXECUTE_HANDLER) {}
        }
        hit = InterlockedIncrement(&g_AadHitDoh);
        if (hit == 1 || (hit % 500) == 0) {
            HvDbgEvtPost(HV_DBGEVT_SEV_INFO, HV_DBGEVT_CAT_AAD, STATUS_PORT_NOT_SET,
                         (ULONG)(ULONG_PTR)caller,
                         (ULONG)(ULONG_PTR)targetPid, (UINT64)hit, 0,
                         "ProcessDebugObjectHandle spoofed -> PORT_NOT_SET");
        }
        return STATUS_PORT_NOT_SET;

    case ProcessDebugFlags:
        if (ProcessInformation && ProcessInformationLength >= sizeof(ULONG)) {
            __try {
                if (aadMode == UserMode) {
                    ProbeForWrite(ProcessInformation, sizeof(ULONG), sizeof(ULONG));
                }
                *(PULONG)ProcessInformation = 1;
            } __except (EXCEPTION_EXECUTE_HANDLER) {}
            hit = InterlockedIncrement(&g_AadHitDf);
            if (hit == 1 || (hit % 500) == 0) {
                HvDbgEvtPost(HV_DBGEVT_SEV_INFO, HV_DBGEVT_CAT_AAD, 0,
                             (ULONG)(ULONG_PTR)caller,
                             (ULONG)(ULONG_PTR)targetPid, (UINT64)hit, 0,
                             "ProcessDebugFlags spoofed -> 1");
            }
        }
        break;
    }

    return status;
}

// Hook 后的 NtQuerySystemInformation
//
// 2026-06-17: 增加 SystemProcessInformation (class=5) 拦截 - 反作弊用它枚举
// 进程,看 ImageName 找 debugger。caller 不在 trusted 时, 把 debugger 进程
// 的 ImageName 改成 "notepad.exe", 隐藏指纹。
static NTSTATUS NTAPI HookedNtQuerySystemInformation(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
)
{
    NTSTATUS status;
    PFN_NtQuerySystemInformation Original;

    Original = (PFN_NtQuerySystemInformation)HvHookGetTrampoline(g_HookNtQuerySystemInformation);
    if (!Original) {
        return STATUS_UNSUCCESSFUL;
    }

    status = Original(SystemInformationClass, SystemInformation,
                      SystemInformationLength, ReturnLength);

    if (!NT_SUCCESS(status)) {
        return status;
    }

    // M3 修正: IRQL > APC_LEVEL 走 Original
    if (KeGetCurrentIrql() > APC_LEVEL) {
        return status;
    }

    // ============================================================
    // SystemProcessInformation 系列 (class=5/57/148) - 进程枚举 spoof
    // 2026-06-19: class 57 (SystemExtendedProcessInformation) / 148
    // (SystemFullProcessInformation) 共用同一 SYSTEM_PROCESS_INFORMATION 链表结构,
    // 只是后续 per-thread 扩展字段不同, ImageName + UniqueProcessId 偏移一致 →
    // 同一段 spoof 代码三个 class 都可处理。
    //
    // 旧只覆盖 class=5, Win11 Task Manager 走 class=57/148 → spoof 漏掉, 任务管理器
    // 拿到 debugger 真路径, 右键"打开文件位置"定位桌面真文件。
    // ============================================================
    if ((SystemInformationClass == HV_SYSTEM_PROCESS_INFORMATION_CLASS ||
         SystemInformationClass == 57 ||
         SystemInformationClass == 148) &&
        SystemInformation && SystemInformationLength > 0)
    {
        HANDLE caller = PsGetCurrentProcessId();
        // 2026-06-19: 进程列表 spoof 对所有 caller 生效 (除 debugger 自己)
        // 旧: trusted 跳过 → 任务管理器看到 debugger 真名, 右键"打开文件位置"
        // 用真名查注册表关联触发系统 Notepad App, 暴露真路径
        BOOLEAN doSpoof = !HvHookIsDebuggerPid(caller);
        if (doSpoof) {
            KPROCESSOR_MODE prevMode = ExGetPreviousMode();
            __try {
                if (prevMode == UserMode) {
                    ProbeForWrite(SystemInformation, SystemInformationLength,
                                  sizeof(ULONG));
                }
                // 走链表, 找 debugger PID 改 ImageName
                PUCHAR p = (PUCHAR)SystemInformation;
                ULONG offset = 0;
                while (offset < SystemInformationLength) {
                    PHV_SYSTEM_PROCESS_INFO_HEADER pi =
                        (PHV_SYSTEM_PROCESS_INFO_HEADER)(p + offset);
                    HANDLE pidHandle = pi->UniqueProcessId;
                    if (HvHookIsDebuggerPid(pidHandle)) {
                        // 2026-06-19: ImageName.Buffer 在 class 5 通常是 basename
                        // ("notepad.exe"), 在 class 57/148 可能是完整 NT 路径
                        // (\Device\HarddiskVolumeN\Path\..\xxx.exe)。
                        //
                        // 判断方式: Buffer 首字符是 '\\' → 视为 NT 完整路径, 用
                        // HV_SPOOF_UWP_PATH_NT 整体替换; 否则当成 basename, 用
                        // "Notepad.exe" 替换。
                        static const WCHAR kSpoofBasename[] = L"Notepad.exe";
                        static const WCHAR kSpoofNtPath[]   = HV_SPOOF_UWP_PATH_NT;
                        PCWSTR spoofText = kSpoofBasename;
                        ULONG  spoofLen  = sizeof(kSpoofBasename) - sizeof(WCHAR);
                        if (pi->ImageName.Buffer && pi->ImageName.Length >= sizeof(WCHAR)) {
                            __try {
                                if (pi->ImageName.Buffer[0] == L'\\') {
                                    spoofText = kSpoofNtPath;
                                    spoofLen  = sizeof(kSpoofNtPath) - sizeof(WCHAR);
                                }
                            } __except (EXCEPTION_EXECUTE_HANDLER) { }
                        }
                        if (pi->ImageName.Buffer &&
                            pi->ImageName.MaximumLength >= spoofLen + sizeof(WCHAR))
                        {
                            // ImageName.Buffer 是 user VA, ProbeForWrite 已覆盖
                            __try {
                                RtlCopyMemory(pi->ImageName.Buffer, spoofText,
                                              spoofLen + sizeof(WCHAR));
                                pi->ImageName.Length = (USHORT)spoofLen;
                            } __except (EXCEPTION_EXECUTE_HANDLER) { }
                            HV_HOT_DBG("[HvHook-Spoof] NtQuerySystem ProcessInfo: "
                                     "PID=%u caller=%u class=%u ImageName -> %ws\n",
                                     (ULONG)(ULONG_PTR)pidHandle,
                                     (ULONG)(ULONG_PTR)caller,
                                     (ULONG)SystemInformationClass,
                                     spoofText);
                        }
                    }
                    if (pi->NextEntryOffset == 0) break;
                    if (pi->NextEntryOffset > SystemInformationLength - offset) break;
                    offset += pi->NextEntryOffset;
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                // probe / 读 throw, 直接返回原结果
            }
        }
    }

    // 隐藏内核调试器信息
    if (SystemInformationClass == SystemKernelDebuggerInformation) {
        typedef struct _SYSTEM_KERNEL_DEBUGGER_INFORMATION {
            BOOLEAN KernelDebuggerEnabled;
            BOOLEAN KernelDebuggerNotPresent;
        } SYSTEM_KERNEL_DEBUGGER_INFORMATION;

        if (SystemInformation && SystemInformationLength >= sizeof(SYSTEM_KERNEL_DEBUGGER_INFORMATION)) {
            SYSTEM_KERNEL_DEBUGGER_INFORMATION* pInfo =
                (SYSTEM_KERNEL_DEBUGGER_INFORMATION*)SystemInformation;
            pInfo->KernelDebuggerEnabled = FALSE;
            pInfo->KernelDebuggerNotPresent = TRUE;
            HV_HOT_DBG("[HvHook-AAD] SystemKernelDebuggerInformation spoofed\n");
        }
    }

    // ============================================================
    // 2026-06-17 [R3 检测漏洞修复]
    // SystemHandleInformation (16) / SystemExtendedHandleInformation (64)
    // ------------------------------------------------------------
    // 反作弊典型检测路径:
    //   1. 反作弊在游戏进程里调 NtQuerySystemInformation(16 or 64)
    //   2. 拿到全系统所有 handle (含 ProcessId / Handle / GrantedAccess)
    //   3. 过滤 ObjectTypeIndex==Process 且 GrantedAccess 含 VM_READ/WRITE
    //   4. 看 OwnerPid → 找到 CE/x64dbg → 报警
    //
    // 我们的 spoof: 把 caller=外部进程 时, 列表里**所有 debugger PID 拥有的
    // process handle** 都改成 OwnerPid=0 / 改成 trusted (taskmgr 自己等)。
    // 简单做法: 把 debugger 拥有的 handle 项目整个**改 GrantedAccess=0** 让
    // 反作弊看到"这个 handle 没权限",自动忽略。
    //
    // class 16 = SYSTEM_HANDLE_TABLE_ENTRY_INFO[]:
    //   UCHAR  UniqueProcessId;   // 缩成 1 byte
    //   USHORT CreatorBackTraceIndex;
    //   UCHAR  ObjectTypeIndex;
    //   UCHAR  HandleAttributes;
    //   USHORT HandleValue;
    //   PVOID  Object;
    //   ULONG  GrantedAccess;
    // = 0x18 字节
    //
    // class 64 = SYSTEM_HANDLE_INFORMATION_EX:
    //   ULONG_PTR NumberOfHandles;
    //   ULONG_PTR Reserved;
    //   SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[]: {
    //     PVOID     Object;
    //     ULONG_PTR UniqueProcessId;
    //     ULONG_PTR HandleValue;
    //     ULONG     GrantedAccess;
    //     USHORT    CreatorBackTraceIndex;
    //     USHORT    ObjectTypeIndex;
    //     ULONG     HandleAttributes;
    //     ULONG     Reserved;
    //   } = 0x28 字节
    if ((SystemInformationClass == 16 || SystemInformationClass == 64) &&
        SystemInformation && SystemInformationLength > 0)
    {
        HANDLE caller = PsGetCurrentProcessId();
        BOOLEAN doSpoof = !HvHookIsDebuggerPid(caller) &&
                          !HvHookIsTrustedSystemCaller(caller);
        if (doSpoof) {
            KPROCESSOR_MODE prevMode = ExGetPreviousMode();
            __try {
                if (prevMode == UserMode) {
                    ProbeForWrite(SystemInformation, SystemInformationLength,
                                  sizeof(ULONG));
                }

                ULONG spoofCount = 0;
                if (SystemInformationClass == 16) {
                    // class 16 layout: ULONG NumberOfHandles + ENTRY[]
                    if (SystemInformationLength >= sizeof(ULONG)) {
                        ULONG numHandles = *(volatile ULONG*)SystemInformation;
                        if (numHandles > 0x10000000) numHandles = 0;  // 防越界
                        UCHAR* entries = (UCHAR*)SystemInformation + sizeof(ULONG);
                        // 校验长度
                        if ((ULONG_PTR)entries + (ULONG_PTR)numHandles * 0x18ULL <=
                            (ULONG_PTR)SystemInformation + SystemInformationLength)
                        {
                            for (ULONG i = 0; i < numHandles; i++) {
                                UCHAR* e = entries + (ULONG_PTR)i * 0x18;
                                // UniqueProcessId 在 offset 0 (1 byte 缩位)
                                // class 16 用 UCHAR 装 PID, 大 PID 截断不准, 跳
                                ULONG pid = *(volatile UCHAR*)e;
                                // 实际上 class 16 的 PID 缩位已经几乎全坏, 不必
                                // 处理 - 反作弊也不靠它。跳过即可。
                                UNREFERENCED_PARAMETER(pid);
                            }
                        }
                    }
                } else {
                    // class 64: ULONG_PTR NumberOfHandles + Reserved + ENTRY[]
                    if (SystemInformationLength >= 2 * sizeof(ULONG_PTR)) {
                        ULONG_PTR numHandles = *(volatile ULONG_PTR*)SystemInformation;
                        if (numHandles > 0x10000000) numHandles = 0;
                        UCHAR* entries = (UCHAR*)SystemInformation +
                                         2 * sizeof(ULONG_PTR);
                        if ((ULONG_PTR)entries + numHandles * 0x28ULL <=
                            (ULONG_PTR)SystemInformation + SystemInformationLength)
                        {
                            // ENTRY_INFO_EX: Object(0) UniqueProcessId(8) HandleValue(16)
                            //                GrantedAccess(24) CreatorBackTrace(28)
                            //                ObjectTypeIndex(30) HandleAttributes(32) Reserved(36)
                            for (ULONG_PTR i = 0; i < numHandles; i++) {
                                UCHAR* e = entries + i * 0x28;
                                ULONG_PTR ownerPid = *(volatile ULONG_PTR*)(e + 8);
                                if (HvHookIsDebuggerPid((HANDLE)ownerPid)) {
                                    // 把这条 entry 改成"无害":
                                    //   GrantedAccess = 0 (反作弊看到无权限自动忽略)
                                    //   UniqueProcessId = 4 (System PID)
                                    *(volatile ULONG*)(e + 24) = 0;
                                    *(volatile ULONG_PTR*)(e + 8) = 4;
                                    spoofCount++;
                                }
                            }
                        }
                    }
                }

                if (spoofCount > 0) {
                    HV_HOT_DBG("[HvHook-Spoof] NtQuerySystem HandleInfo: "
                             "class=%u caller=%u spoofed=%u handles\n",
                             SystemInformationClass,
                             (ULONG)(ULONG_PTR)caller, spoofCount);
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                // probe/write throw, 返回原结果即可
            }
        }
    }

    // 2026-06-18 合并: EptHook.c 的隐藏列表过滤搬到这里, 共用一个 hook
    //
    // 注意: 隐藏 filter 跟上面 debugger spoof 不冲突 — 这里整条删 (PID 在
    // hidden 列表), spoof 改 ImageName。Hidden 通常用于"反作弊驱动/Helper"
    // 自己隐藏自己, debugger 进程一般只走 spoof 路径。
    //
    // sizeof 门限用 sizeof(ULONG) 这种保守值即可, Filter* 函数内部会做完整
    // 结构校验, 这里只是防止 0 长 buffer / 明显小 buffer。
    if (NT_SUCCESS(status) && SystemInformation && g_HiddenProcessCount > 0 &&
        SystemInformationLength >= sizeof(ULONG))
    {
        __try {
            switch (SystemInformationClass) {
            case 5:   // SystemProcessInformation
            case 57:  // SystemExtendedProcessInformation
            case 148: // SystemFullProcessInformation
                FilterProcessList(SystemInformation);
                break;
            case 53:  // SystemSessionProcessInformation
                FilterSessionProcessList(SystemInformation);
                break;
            case 16:  // SystemHandleInformation
                FilterHandleList(SystemInformation, SystemInformationLength);
                break;
            case 64:  // SystemExtendedHandleInformation
                FilterExtendedHandleList(SystemInformation, SystemInformationLength);
                break;
            // class 11 (SystemModuleInformation) 隐藏驱动: EptHook 路径处理
            default:
                break;
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            // 过滤异常不影响原结果
        }
    }

    return status;
}

// 2026-06-17: NtQueryVirtualMemory hook (MemoryMappedFilenameInformation=2)
//
// 反作弊典型用法:
//   1. 拿到 debugger 的 ProcessHandle (NtOpenProcess)
//   2. NtQueryVirtualMemory(handle, base=0x400000, class=2, &buf, size, &ret)
//   3. 返回 \Device\HarddiskVolumeN\Path\debugger.exe → 反作弊比对路径 / hash
//
// 我们拦截: caller 不可信 + target=debugger → 把返回 buf 改成 notepad.exe 路径
static NTSTATUS NTAPI HookedNtQueryVirtualMemory(
    HANDLE  ProcessHandle,
    PVOID   BaseAddress,
    ULONG   MemoryInformationClass,
    PVOID   MemoryInformation,
    SIZE_T  MemoryInformationLength,
    PSIZE_T ReturnLength
)
{
    PFN_NtQueryVirtualMemory Original =
        (PFN_NtQueryVirtualMemory)HvHookGetTrampoline(g_HookNtQueryVirtualMemory);
    if (!Original) return STATUS_UNSUCCESSFUL;

    NTSTATUS status = Original(ProcessHandle, BaseAddress, MemoryInformationClass,
                               MemoryInformation, MemoryInformationLength, ReturnLength);
    if (!NT_SUCCESS(status)) return status;

    if (KeGetCurrentIrql() > APC_LEVEL) return status;
    if (MemoryInformationClass != HV_MEMORY_MAPPED_FILENAME_INFO) return status;
    if (!MemoryInformation || MemoryInformationLength < sizeof(UNICODE_STRING)) return status;

    HANDLE caller = PsGetCurrentProcessId();
    HANDLE targetPid = HvHookpProcessHandleToProcessId(ProcessHandle);
    if (!targetPid || !HvHookIsDebuggerPid(targetPid)) return status;
    // 2026-06-19: 路径类查询对所有 caller spoof (debugger 自己除外)
    // 旧: trusted 跳过 → taskmgr/explorer 拿到真路径 → "打开文件位置"定位桌面真文件
    if (caller == targetPid || HvHookIsDebuggerPid(caller)) {
        return status;
    }

    // target = debugger, caller = 外部 → 改 mapped file name 为 UWP Notepad
    // 2026-06-19: 改用全局 HV_SPOOF_UWP_PATH_NT (跟 NtQueryInformationProcess 一致)
    static const WCHAR kSpoofNt[] = HV_SPOOF_UWP_PATH_NT;
    ULONG spoofBytes = 0;
    for (PCWSTR p = kSpoofNt; *p; p++) spoofBytes += sizeof(WCHAR);

    KPROCESSOR_MODE prevMode = ExGetPreviousMode();
    __try {
        if (prevMode == UserMode) {
            ProbeForWrite(MemoryInformation, MemoryInformationLength, sizeof(ULONG));
        }
        UNICODE_STRING* us = (UNICODE_STRING*)MemoryInformation;
        if (us->Buffer && us->MaximumLength >= spoofBytes + sizeof(WCHAR)) {
            RtlCopyMemory(us->Buffer, kSpoofNt, spoofBytes + sizeof(WCHAR));
            us->Length = (USHORT)spoofBytes;
            HV_HOT_DBG("[HvHook-Spoof] NtQVM mapped-filename: target=%u caller=%u -> notepad.exe\n",
                     (ULONG)(ULONG_PTR)targetPid, (ULONG)(ULONG_PTR)caller);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) { }

    return status;
}

// ============================================================
// 2026-06-17: Win32k window-enumeration spoofing hooks
// ============================================================
//
// 反作弊检测 debugger 窗口的典型链路:
//   1. NtUserBuildHwndList → 拿所有顶层 hwnd 列表
//   2. NtUserQueryWindow(hwnd, WindowProcess) → 反查 PID
//   3. NtUserInternalGetWindowText(hwnd) → 拿窗口标题 ("Cheat Engine 7.4")
//   4. NtUserGetClassName(hwnd) → 拿窗口类名
//
// 我们 spoof:
//   - QueryWindow 返回 debugger 的 hwnd 时, 反查 PID 返回一个 fake (explorer / 0)
//   - GetWindowText 返回 debugger 的 hwnd 时, 标题改成 "无标题 - 记事本"
//   - GetClassName 返回 debugger 的 hwnd 时, 类名改成 "Notepad"
//
// BuildHwndList 不动 (反作弊还是能拿到 hwnd 列表), 因为 hwnd 本身不暴露
// 信息 — 真正暴露的是后续 query 拿到的进程/标题/类名, 这些我们都改了。

// win32k 路径常用 PCLIENT_ID / handle types
typedef ULONG WINDOWINFOCLASS;
#define HV_W32K_WINDOWPROCESS  0   // NtUserQueryWindow class: 返回 owner process id
#define HV_W32K_WINDOWTHREAD   1   // 返回 owner thread id

// 通用 spoof helper: 判断给定 hwnd 是否属于 debugger PID
// (用 NtUserQueryWindow original 反查 — 但避免递归调用我们自己)
typedef HANDLE (NTAPI *PFN_NtUserQueryWindow)(HANDLE Hwnd, ULONG WindowInfo);
typedef ULONG (NTAPI *PFN_NtUserInternalGetWindowText)(HANDLE Hwnd, PWCHAR Buffer, ULONG MaxCount);
typedef ULONG (NTAPI *PFN_NtUserGetClassName)(HANDLE Hwnd, BOOLEAN Real, PUNICODE_STRING ClassName);
// 2026-06-18: NtUserFindWindowEx
//   HWND NtUserFindWindowEx(
//       HWND hwndParent, HWND hwndChildAfter,
//       PUNICODE_STRING ClassName, PUNICODE_STRING WindowName,
//       DWORD dwType);
typedef HANDLE (NTAPI *PFN_NtUserFindWindowEx)(
    HANDLE HwndParent, HANDLE HwndChildAfter,
    PUNICODE_STRING ClassName, PUNICODE_STRING WindowName,
    DWORD Type);
typedef ULONG (NTAPI *PFN_NtUserBuildHwndList)(
    HANDLE Desktop, HANDLE StartHwnd, ULONG EnumChildren,
    ULONG dwThreadId, ULONG cHwnd, PHANDLE phwndList, PULONG pcHwndNeeded);

static BOOLEAN HvHookpIsDebuggerHwnd(HANDLE Hwnd)
{
    if (!Hwnd) return FALSE;
    PFN_NtUserQueryWindow Original =
        (PFN_NtUserQueryWindow)HvHookGetTrampoline(g_HookNtUserQueryWindow);
    if (!Original) return FALSE;

    // 反查 PID
    HANDLE ownerPid = Original(Hwnd, HV_W32K_WINDOWPROCESS);
    return HvHookIsDebuggerPid(ownerPid);
}

// NtUserQueryWindow hook — 反作弊用 hwnd 反查 PID 时返回 fake
static HANDLE NTAPI HookedNtUserQueryWindow(HANDLE Hwnd, ULONG WindowInfo)
{
    PFN_NtUserQueryWindow Original =
        (PFN_NtUserQueryWindow)HvHookGetTrampoline(g_HookNtUserQueryWindow);
    if (!Original) return NULL;

    HANDLE ret = Original(Hwnd, WindowInfo);

    if (KeGetCurrentIrql() > APC_LEVEL) return ret;

    HANDLE caller = PsGetCurrentProcessId();
    // 2026-06-19: 窗口查询无差别 spoof — trusted (explorer/taskmgr/Alt+Tab 切换器/任务栏)
    // 仍会显示 debugger 真窗口标题/类名, 跟 NtQIP path-class spoof 改动语义对齐
    if (HvHookIsDebuggerPid(caller)) return ret;

    // 只伪造 owner process/thread 类
    if (WindowInfo == HV_W32K_WINDOWPROCESS) {
        if (HvHookIsDebuggerPid(ret)) {
            // 返回 4 (System PID) 让反作弊以为是系统窗口
            HV_HOT_DBG("[HvHook-Spoof] NtUserQueryWindow PROCESS hwnd=%p caller=%u: "
                     "%u -> 4 (System spoof)\n",
                     Hwnd, (ULONG)(ULONG_PTR)caller, (ULONG)(ULONG_PTR)ret);
            return (HANDLE)(ULONG_PTR)4;
        }
    }
    return ret;
}

// NtUserInternalGetWindowText hook — 改 debugger 窗口标题为 notepad
static ULONG NTAPI HookedNtUserInternalGetWindowText(
    HANDLE Hwnd, PWCHAR Buffer, ULONG MaxCount)
{
    PFN_NtUserInternalGetWindowText Original =
        (PFN_NtUserInternalGetWindowText)HvHookGetTrampoline(g_HookNtUserInternalGetWindowText);
    if (!Original) return 0;

    ULONG ret = Original(Hwnd, Buffer, MaxCount);

    if (KeGetCurrentIrql() > APC_LEVEL) return ret;

    HANDLE caller = PsGetCurrentProcessId();
    // 2026-06-19: 窗口标题无差别 spoof, 见 NtUserQueryWindow 注释
    if (HvHookIsDebuggerPid(caller)) return ret;

    if (!HvHookpIsDebuggerHwnd(Hwnd)) return ret;

    // debugger 窗口 — 改标题
    static const WCHAR kSpoofTitle[] = L"无标题 - 记事本";
    ULONG spoofLen = 0;
    for (PCWSTR p = kSpoofTitle; *p; p++) spoofLen++;

    if (Buffer && MaxCount > spoofLen) {
        KPROCESSOR_MODE prevMode = ExGetPreviousMode();
        __try {
            if (prevMode == UserMode) {
                ProbeForWrite(Buffer, (spoofLen + 1) * sizeof(WCHAR), sizeof(WCHAR));
            }
            for (ULONG i = 0; i < spoofLen; i++) Buffer[i] = kSpoofTitle[i];
            Buffer[spoofLen] = L'\0';
            HV_HOT_DBG("[HvHook-Spoof] NtUserInternalGetWindowText hwnd=%p caller=%u -> spoofed\n",
                     Hwnd, (ULONG)(ULONG_PTR)caller);
            return spoofLen;
        } __except (EXCEPTION_EXECUTE_HANDLER) { }
    }
    return ret;
}

// 2026-06-18 [R3 检测漏洞修复]
// NtUserFindWindowEx hook — 反作弊用 FindWindow("CHEATENGINE",NULL) 一步精准定位
// CE 窗口,绕过 EnumWindows + GetClassName. 这是反作弊**最直接**的窗口检测手段.
//
// 三种使用模式:
//   1. FindWindow(className, NULL)         — 按 class name 找
//   2. FindWindow(NULL, windowName)        — 按 title 找
//   3. FindWindow(className, windowName)   — 两者都匹配
//
// 策略:
//   - caller=debugger 自己 / trusted (csrss/dwm/explorer) → 透传
//   - caller=外部 → 检查 ClassName/WindowName 是否含调试器关键词
//     命中 → 返回 NULL (假装没找到), 反作弊以为没装 CE
//   - 不命中(普通窗口查找) → 透传 (避免把正常游戏 GUI 也屏了)
//
// 关键词黑名单(已知 CE/debugger 窗口签名):
static const WCHAR* kFindWindowBlocklist[] = {
    L"CHEATENGINE",            // CE 主窗口 class
    L"Cheat Engine",           // CE 标题
    L"MEMVIEW",                // CE 内存视图
    L"FormDisassembler",       // CE 反汇编
    L"FormPointerScan",        // CE 指针扫描
    L"TFrmEXTMain",            // CE EXT 主窗口
    L"x64dbg",                 // x64dbg
    L"x32dbg",
    L"x96dbg",
    L"OLLYDBG",                // OllyDbg class
    L"OllyDbg",
    L"WinDbgFrameClass",       // WinDbg
    L"WinDbg",
    L"Scylla",                 // Scylla dumper
    L"ReClass",
    L"OllyMain",
    L"OllyParent",
};

// 在 user-mode UNICODE_STRING 里搜关键词. 不分配, 不 throw 外, 失败返 FALSE.
static BOOLEAN
HvHookpUnicodeContainsBlocked(_In_opt_ PUNICODE_STRING Us)
{
    if (!Us) return FALSE;
    // 拷 64 字符进栈, 避免直接读 user buffer 出问题
    WCHAR local[128];
    USHORT len = 0;
    __try {
        len = Us->Length;
        if (len == 0 || !Us->Buffer) return FALSE;
        USHORT copyChars = (USHORT)(len / sizeof(WCHAR));
        if (copyChars > 127) copyChars = 127;
        RtlCopyMemory(local, Us->Buffer, copyChars * sizeof(WCHAR));
        local[copyChars] = L'\0';
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }

    for (ULONG i = 0; i < RTL_NUMBER_OF(kFindWindowBlocklist); i++) {
        const WCHAR* needle = kFindWindowBlocklist[i];
        // case-insensitive substring search
        const WCHAR* hay = local;
        while (*hay) {
            const WCHAR* h = hay;
            const WCHAR* n = needle;
            while (*h && *n) {
                WCHAR ch = *h;
                WCHAR cn = *n;
                if (ch >= L'A' && ch <= L'Z') ch = (WCHAR)(ch + 32);
                if (cn >= L'A' && cn <= L'Z') cn = (WCHAR)(cn + 32);
                if (ch != cn) break;
                h++; n++;
            }
            if (*n == L'\0') return TRUE;  // 关键词匹完, 命中
            hay++;
        }
    }
    return FALSE;
}

static HANDLE NTAPI HookedNtUserFindWindowEx(
    HANDLE HwndParent, HANDLE HwndChildAfter,
    PUNICODE_STRING ClassName, PUNICODE_STRING WindowName,
    DWORD Type)
{
    PFN_NtUserFindWindowEx Original =
        (PFN_NtUserFindWindowEx)HvHookGetTrampoline(g_HookNtUserFindWindowEx);
    if (!Original) return NULL;

    if (KeGetCurrentIrql() > APC_LEVEL) {
        return Original(HwndParent, HwndChildAfter, ClassName, WindowName, Type);
    }

    HANDLE caller = PsGetCurrentProcessId();
    // 2026-06-19: 按类名/标题找窗口无差别 spoof, 见 NtUserQueryWindow 注释
    // 旧逻辑放行 trusted (taskmgr/explorer) 可拿到 debugger hwnd 后再做反查穿帮
    if (HvHookIsDebuggerPid(caller)) {
        return Original(HwndParent, HwndChildAfter, ClassName, WindowName, Type);
    }

    // 检查 ClassName / WindowName 是否含 debugger 签名
    BOOLEAN hitClass = HvHookpUnicodeContainsBlocked(ClassName);
    BOOLEAN hitTitle = !hitClass && HvHookpUnicodeContainsBlocked(WindowName);

    if (hitClass || hitTitle) {
        HV_HOT_DBG("[HvHook-Spoof] NtUserFindWindowEx blocked: caller=%u "
                 "hitClass=%u hitTitle=%u\n",
                 (ULONG)(ULONG_PTR)caller, hitClass, hitTitle);
        return NULL;  // 假装没找到
    }

    // 不含 debugger 关键词 → 正常透传
    HANDLE hwnd = Original(HwndParent, HwndChildAfter, ClassName, WindowName, Type);

    // 二次保护: 即使 caller 没传关键词, 找到的 hwnd 可能恰好是 debugger 窗口
    // (无标题搜父窗口的子窗口等). 如果 hwnd 属于 debugger 进程, 也屏了.
    if (hwnd && HvHookpIsDebuggerHwnd(hwnd)) {
        HV_HOT_DBG("[HvHook-Spoof] NtUserFindWindowEx hwnd=%p belongs to debugger "
                 "caller=%u: -> NULL\n",
                 hwnd, (ULONG)(ULONG_PTR)caller);
        return NULL;
    }
    return hwnd;
}

// NtUserGetClassName hook — 改 debugger 窗口类名
static ULONG NTAPI HookedNtUserGetClassName(
    HANDLE Hwnd, BOOLEAN Real, PUNICODE_STRING ClassName)
{
    PFN_NtUserGetClassName Original =
        (PFN_NtUserGetClassName)HvHookGetTrampoline(g_HookNtUserGetClassName);
    if (!Original) return 0;

    ULONG ret = Original(Hwnd, Real, ClassName);

    if (KeGetCurrentIrql() > APC_LEVEL) return ret;

    HANDLE caller = PsGetCurrentProcessId();
    // 2026-06-19: 窗口类名无差别 spoof, 见 NtUserQueryWindow 注释
    if (HvHookIsDebuggerPid(caller)) return ret;

    if (!HvHookpIsDebuggerHwnd(Hwnd)) return ret;

    if (!ClassName) return ret;

    static const WCHAR kSpoofClass[] = L"Notepad";
    ULONG spoofBytes = sizeof(kSpoofClass) - sizeof(WCHAR);  // no NUL

    KPROCESSOR_MODE prevMode = ExGetPreviousMode();
    __try {
        if (prevMode == UserMode) {
            ProbeForRead(ClassName, sizeof(UNICODE_STRING), sizeof(ULONG));
            if (ClassName->Buffer) {
                ProbeForWrite(ClassName->Buffer, spoofBytes + sizeof(WCHAR),
                              sizeof(WCHAR));
            }
        }
        if (ClassName->Buffer && ClassName->MaximumLength >= spoofBytes + sizeof(WCHAR)) {
            RtlCopyMemory(ClassName->Buffer, kSpoofClass, spoofBytes + sizeof(WCHAR));
            ClassName->Length = (USHORT)spoofBytes;
            HV_HOT_DBG("[HvHook-Spoof] NtUserGetClassName hwnd=%p caller=%u -> Notepad\n",
                     Hwnd, (ULONG)(ULONG_PTR)caller);
            return spoofBytes / sizeof(WCHAR);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) { }

    return ret;
}

// PsGetProcessImageFileName — 拿 EXE 短名 (15 字节 ASCII), file/window 多处 hook 用
NTKERNELAPI PUCHAR NTAPI PsGetProcessImageFileName(_In_ PEPROCESS Process);

// ============================================================
// 2026-06-19: NtUserBuildHwndList hook — 从枚举结果里抹掉 debugger hwnd
// ============================================================
//
// 设计:
//   - caller=explorer / dwm / ShellExperienceHost / StartMenuExperienceHost 等
//     **shell 宿主** 放行 — 任务栏 / Alt+Tab / 开始菜单需要看到 debugger 才能
//     提供 UI (用户能切回去, 看到任务栏图标)
//   - 其他 caller (CE / 反作弊 / DogeCE / Spy++ 等) → 把 debugger hwnd 从数组里
//     压缩掉, 同步缩短 pcHwndNeeded
//
// 取舍:
//   反作弊会拿"压缩前/后" pcHwndNeeded 对照, 但这需要它有 baseline (重启前的数字),
//   实际很难做; 而且我们改 pcHwndNeeded 后看起来仍然是合法数量, 不会异常。
//
// 反递归: HvHookpIsDebuggerHwnd 用 NtUserQueryWindow 反查 — 它内部走 trampoline,
// 不进 hook, 安全。
//
// 名单和我们的 file-untrusted 名单**正好相反**:
//   - 文件层: explorer 不可信 (防双击 / 右键属性)
//   - 窗口层: explorer 可信 (任务栏要能显示 debugger)
// 两个名单概念不同, 不能合并。
static const PCWSTR g_HwndShellHostNames[] = {
    L"explorer.exe",
    L"dwm.exe",
    L"ShellExperienceHost.exe",
    L"StartMenuExperienceHost.exe",
    L"SearchHost.exe",
    L"SearchApp.exe",
    L"ApplicationFrameHost.exe",   // UWP 窗口宿主
    L"TextInputHost.exe",          // Win11 IME 输入面板
    NULL,
};

static BOOLEAN HvHookpIsShellHostCaller(_In_ HANDLE Pid)
{
    if (!Pid) return FALSE;
    if (KeGetCurrentIrql() > APC_LEVEL) return FALSE;

    PEPROCESS proc = NULL;
    if (!NT_SUCCESS(PsLookupProcessByProcessId(Pid, &proc)) || !proc) return FALSE;

    PUCHAR imgName = PsGetProcessImageFileName(proc);
    BOOLEAN hit = FALSE;
    if (imgName) {
        CHAR localName[16] = { 0 };
        for (ULONG i = 0; i < 15; i++) {
            localName[i] = (CHAR)imgName[i];
            if (!localName[i]) break;
        }
        for (ULONG i = 0; g_HwndShellHostNames[i] != NULL; i++) {
            PCWSTR wname = g_HwndShellHostNames[i];
            BOOLEAN match = TRUE;
            for (ULONG j = 0; j < 16; j++) {
                WCHAR a = wname[j];
                CHAR  b = localName[j];
                if (a == L'\0' && b == '\0') break;
                if (a == L'\0' || b == '\0') { match = FALSE; break; }
                if (a >= L'A' && a <= L'Z') a = (WCHAR)(a - L'A' + L'a');
                if (b >= 'A'  && b <= 'Z')  b = (CHAR)(b - 'A' + 'a');
                if ((WCHAR)b != a) { match = FALSE; break; }
            }
            if (match) { hit = TRUE; break; }
        }
    }
    ObDereferenceObject(proc);
    return hit;
}

static ULONG NTAPI HookedNtUserBuildHwndList(
    HANDLE Desktop, HANDLE StartHwnd, ULONG EnumChildren,
    ULONG dwThreadId, ULONG cHwnd, PHANDLE phwndList, PULONG pcHwndNeeded)
{
    PFN_NtUserBuildHwndList Original =
        (PFN_NtUserBuildHwndList)HvHookGetTrampoline(g_HookNtUserBuildHwndList);
    if (!Original) return STATUS_UNSUCCESSFUL;

    ULONG ret = Original(Desktop, StartHwnd, EnumChildren, dwThreadId,
                         cHwnd, phwndList, pcHwndNeeded);
    if (!NT_SUCCESS((NTSTATUS)ret)) return ret;

    if (KeGetCurrentIrql() > APC_LEVEL) return ret;

    HANDLE caller = PsGetCurrentProcessId();
    // debugger 自己 / shell 宿主 放行 (保留任务栏 / Alt+Tab UI)
    if (HvHookIsDebuggerPid(caller) || HvHookpIsShellHostCaller(caller)) return ret;

    if (!phwndList || !pcHwndNeeded || cHwnd == 0) return ret;

    // 实际填充数量 = min(cHwnd, *pcHwndNeeded)
    ULONG actualCount = 0;
    KPROCESSOR_MODE prevMode = ExGetPreviousMode();
    __try {
        if (prevMode == UserMode) {
            ProbeForRead(pcHwndNeeded, sizeof(ULONG), sizeof(ULONG));
        }
        actualCount = *pcHwndNeeded;
        if (actualCount > cHwnd) actualCount = cHwnd;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return ret;
    }
    if (actualCount == 0) return ret;

    __try {
        if (prevMode == UserMode) {
            ProbeForWrite(phwndList, actualCount * sizeof(HANDLE), sizeof(HANDLE));
            ProbeForWrite(pcHwndNeeded, sizeof(ULONG), sizeof(ULONG));
        }

        ULONG writeIdx = 0;
        ULONG removed = 0;
        for (ULONG readIdx = 0; readIdx < actualCount; readIdx++) {
            HANDLE h = phwndList[readIdx];
            if (h && HvHookpIsDebuggerHwnd(h)) {
                removed++;
                continue;   // 跳过 debugger 的 hwnd
            }
            if (writeIdx != readIdx) phwndList[writeIdx] = h;
            writeIdx++;
        }
        // 把尾部多余位置清零 (避免残留旧值)
        for (ULONG i = writeIdx; i < actualCount; i++) phwndList[i] = NULL;

        if (removed > 0) {
            *pcHwndNeeded = writeIdx;
            HV_HOT_DBG("[HvHook-Spoof] NtUserBuildHwndList caller=%u removed=%u kept=%u/%u\n",
                     (ULONG)(ULONG_PTR)caller, removed, writeIdx, actualCount);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) { }

    return ret;
}

// ============================================================
// 2026-06-19: NtUserWindowFromPoint / NtUserChildWindowFromPointEx
// ============================================================
//
// 防 Spy++ "查找窗口工具" (拖十字光标到窗口上) 拿到 debugger hwnd:
//   - WindowFromPoint(x,y) 内核入口 = NtUserWindowFromPoint
//   - 子窗口细化版本 = NtUserChildWindowFromPointEx
//
// 策略: caller≠debugger/shell-host + 返回的 hwnd 属于 debugger → 返回 NULL
//   (Spy++ 看到"该坐标没有窗口", 自然结果)
//
// shell-host 白名单 (explorer/dwm/taskbar 类) 放行 — 它们需要正确的坐标→hwnd 反查
// 才能让 Alt+Tab 切窗口 / 鼠标悬停看 thumbnail 工作。
//
// 反递归: 反查 hwnd owner 用 NtUserQueryWindow trampoline, 不进 hook 链。
// ============================================================
// POINT 不在 wdm.h, 自定义等价结构
typedef struct _HV_POINT { LONG x; LONG y; } HV_POINT;

typedef HANDLE (NTAPI *PFN_NtUserWindowFromPoint)(LONG X, LONG Y);
typedef HANDLE (NTAPI *PFN_NtUserChildWindowFromPointEx)(
    HANDLE HwndParent, HV_POINT Point, ULONG Flags);

static HANDLE NTAPI HookedNtUserWindowFromPoint(LONG X, LONG Y)
{
    PFN_NtUserWindowFromPoint Original =
        (PFN_NtUserWindowFromPoint)HvHookGetTrampoline(g_HookNtUserWindowFromPoint);
    if (!Original) return NULL;

    HANDLE ret = Original(X, Y);
    if (!ret) return ret;
    if (KeGetCurrentIrql() > APC_LEVEL) return ret;

    HANDLE caller = PsGetCurrentProcessId();
    if (HvHookIsDebuggerPid(caller) || HvHookpIsShellHostCaller(caller)) return ret;

    if (HvHookpIsDebuggerHwnd(ret)) {
        HV_HOT_DBG("[HvHook-Spoof] NtUserWindowFromPoint caller=%u pt=(%d,%d) hwnd=%p → NULL\n",
                 (ULONG)(ULONG_PTR)caller, X, Y, ret);
        return NULL;
    }
    return ret;
}

static HANDLE NTAPI HookedNtUserChildWindowFromPointEx(
    HANDLE HwndParent, HV_POINT Point, ULONG Flags)
{
    PFN_NtUserChildWindowFromPointEx Original =
        (PFN_NtUserChildWindowFromPointEx)
        HvHookGetTrampoline(g_HookNtUserChildWindowFromPointEx);
    if (!Original) return NULL;

    HANDLE ret = Original(HwndParent, Point, Flags);
    if (!ret) return ret;
    if (KeGetCurrentIrql() > APC_LEVEL) return ret;

    HANDLE caller = PsGetCurrentProcessId();
    if (HvHookIsDebuggerPid(caller) || HvHookpIsShellHostCaller(caller)) return ret;

    // 不论 HwndParent 是否是 debugger, 只要返回的 hwnd 属于 debugger 就拦
    // (反作弊可能从桌面 hwnd 开始 ChildWindowFromPointEx 探, 走到 debugger 子控件)
    if (HvHookpIsDebuggerHwnd(ret)) {
        HV_HOT_DBG("[HvHook-Spoof] NtUserChildWindowFromPointEx caller=%u parent=%p "
                 "pt=(%d,%d) hwnd=%p → NULL\n",
                 (ULONG)(ULONG_PTR)caller, HwndParent, Point.x, Point.y, ret);
        return NULL;
    }
    return ret;
}


// Hook 后的 NtSetInformationThread
static NTSTATUS NTAPI HookedNtSetInformationThread(
    HANDLE ThreadHandle,
    ULONG ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength
)
{
    // 阻止 HideFromDebugger
    if (ThreadInformationClass == ThreadHideFromDebugger) {
        HV_HOT_DBG("[HvHook-AAD] ThreadHideFromDebugger blocked\n");
        return STATUS_SUCCESS;  // 假装成功但不执行
    }
    
    PFN_NtSetInformationThread Original;
    Original = (PFN_NtSetInformationThread)HvHookGetTrampoline(g_HookNtSetInformationThread);
    if (!Original) {
        return STATUS_UNSUCCESSFUL;
    }
    
    return Original(ThreadHandle, ThreadInformationClass, 
                    ThreadInformation, ThreadInformationLength);
}

// Hook 后的 NtClose（检测无效句柄异常）
static NTSTATUS NTAPI HookedNtClose(HANDLE Handle)
{
    PFN_NtClose Original;
    NTSTATUS status;
    
    Original = (PFN_NtClose)HvHookGetTrampoline(g_HookNtClose);
    if (!Original) {
        return STATUS_UNSUCCESSFUL;
    }
    
    // 防止关闭无效句柄触发异常（反调试技术）
    __try {
        status = Original(Handle);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        HV_HOT_DBG("[HvHook-AAD] NtClose exception caught for handle %p\n", Handle);
        status = STATUS_INVALID_HANDLE;
    }
    
    return status;
}

// Hook 后的 NtQueryObject
static NTSTATUS NTAPI HookedNtQueryObject(
    HANDLE Handle,
    ULONG ObjectInformationClass,
    PVOID ObjectInformation,
    ULONG ObjectInformationLength,
    PULONG ReturnLength
)
{
    NTSTATUS status;
    PFN_NtQueryObject Original;
    
    Original = (PFN_NtQueryObject)HvHookGetTrampoline(g_HookNtQueryObject);
    if (!Original) {
        return STATUS_UNSUCCESSFUL;
    }
    
    status = Original(Handle, ObjectInformationClass, 
                      ObjectInformation, ObjectInformationLength, ReturnLength);
    
    // 可以在这里过滤调试对象类型
    // 暂时直接返回原始结果
    
    return status;
}

// Phase L: 前向声明 HvHookpGetNtRoutine (实现在文件下半部 line 2251)
// 让 GetNtFunctionAddress 复用同一份带 Zw fallback 的解析逻辑。
static PVOID HvHookpGetNtRoutine(PCWSTR Name, _In_opt_ ULONG CallerPid);

// 获取 Nt 函数地址 (Phase L: 复用 HvHookpGetNtRoutine 的 Zw fallback)
// CallerPid=0 跳过 L6 SSDT fallback (AAD 路径用的 syscall 都在 ntoskrnl EAT)
static PVOID GetNtFunctionAddress(PCWSTR FunctionName)
{
    return HvHookpGetNtRoutine(FunctionName, 0);
}

NTSTATUS
HvHookEnableAntiAntiDebug(
    _In_opt_ PHV_ANTIANTIDEBUG_CONFIG Config
)
{
    NTSTATUS status = STATUS_SUCCESS;
    PVOID targetFunc;
    
    if (!g_HvHookInitialized) {
        return STATUS_NOT_INITIALIZED;
    }
    
    if (g_AntiAntiDebugEnabled) {
        DbgPrint("[HvHook] Anti-anti-debug already enabled\n");
        return STATUS_SUCCESS;
    }
    
    DbgPrint("[HvHook] Enabling anti-anti-debug...\n");
    
    // 使用提供的配置或默认配置
    if (Config) {
        RtlCopyMemory(&g_AntiAntiDebugConfig, Config, sizeof(HV_ANTIANTIDEBUG_CONFIG));
    } else {
        // 默认配置：Hook 所有反调试函数
        RtlZeroMemory(&g_AntiAntiDebugConfig, sizeof(HV_ANTIANTIDEBUG_CONFIG));
        g_AntiAntiDebugConfig.HookNtQueryInformationProcess = TRUE;
        g_AntiAntiDebugConfig.HookNtQuerySystemInformation = TRUE;
        g_AntiAntiDebugConfig.HookNtSetInformationThread = TRUE;
        g_AntiAntiDebugConfig.HookNtClose = TRUE;
        g_AntiAntiDebugConfig.HookNtQueryObject = TRUE;
    }
    
    // Phase K: NtQueryInformationProcess hook 由 HvHookEnableDebuggerProxy 常驻装载
    // (反向保护常态启用)。AAD spoof 逻辑由 g_AntiAntiDebugEnabled 在 hook 内部条件
    // 启用,不需要在这里装/卸 hook。HookNtQueryInformationProcess 配置字段语义改成
    // "是否启用 spoof",GUI 视角不变 (默认 true)。

    // Hook NtQuerySystemInformation
    if (g_AntiAntiDebugConfig.HookNtQuerySystemInformation) {
        targetFunc = GetNtFunctionAddress(L"NtQuerySystemInformation");
        if (targetFunc) {
            status = HvHookInstall(targetFunc, HookedNtQuerySystemInformation, 
                                   &g_HookNtQuerySystemInformation);
            if (NT_SUCCESS(status)) {
                DbgPrint("[HvHook] NtQuerySystemInformation hooked at %p\n", targetFunc);
            } else {
                DbgPrint("[HvHook] Failed to hook NtQuerySystemInformation: 0x%X\n", status);
            }
        }
    }
    
    // Hook NtSetInformationThread
    if (g_AntiAntiDebugConfig.HookNtSetInformationThread) {
        targetFunc = GetNtFunctionAddress(L"NtSetInformationThread");
        if (targetFunc) {
            status = HvHookInstall(targetFunc, HookedNtSetInformationThread, 
                                   &g_HookNtSetInformationThread);
            if (NT_SUCCESS(status)) {
                DbgPrint("[HvHook] NtSetInformationThread hooked at %p\n", targetFunc);
            } else {
                DbgPrint("[HvHook] Failed to hook NtSetInformationThread: 0x%X\n", status);
            }
        }
    }
    
    // Hook NtClose
    if (g_AntiAntiDebugConfig.HookNtClose) {
        targetFunc = GetNtFunctionAddress(L"NtClose");
        if (targetFunc) {
            status = HvHookInstall(targetFunc, HookedNtClose, &g_HookNtClose);
            if (NT_SUCCESS(status)) {
                DbgPrint("[HvHook] NtClose hooked at %p\n", targetFunc);
            } else {
                DbgPrint("[HvHook] Failed to hook NtClose: 0x%X\n", status);
            }
        }
    }
    
    // Hook NtQueryObject
    if (g_AntiAntiDebugConfig.HookNtQueryObject) {
        targetFunc = GetNtFunctionAddress(L"NtQueryObject");
        if (targetFunc) {
            status = HvHookInstall(targetFunc, HookedNtQueryObject, &g_HookNtQueryObject);
            if (NT_SUCCESS(status)) {
                DbgPrint("[HvHook] NtQueryObject hooked at %p\n", targetFunc);
            } else {
                DbgPrint("[HvHook] Failed to hook NtQueryObject: 0x%X\n", status);
            }
        }
    }
    
    g_AntiAntiDebugEnabled = TRUE;
    DbgPrint("[HvHook] Anti-anti-debug enabled\n");
    
    return STATUS_SUCCESS;
}

NTSTATUS
HvHookDisableAntiAntiDebug(VOID)
{
    if (!g_HvHookInitialized) {
        return STATUS_NOT_INITIALIZED;
    }
    
    if (!g_AntiAntiDebugEnabled) {
        return STATUS_SUCCESS;
    }
    
    DbgPrint("[HvHook] Disabling anti-anti-debug...\n");

    // Phase K: NtQueryInformationProcess 不在这里卸,生命周期由 DebuggerProxy 管理
    // (反向保护常态生效)。disable AAD 只关 spoof 逻辑。
    if (g_HookNtQuerySystemInformation) {
        HvHookRemove(g_HookNtQuerySystemInformation);
        g_HookNtQuerySystemInformation = NULL;
    }
    if (g_HookNtSetInformationThread) {
        HvHookRemove(g_HookNtSetInformationThread);
        g_HookNtSetInformationThread = NULL;
    }
    if (g_HookNtClose) {
        HvHookRemove(g_HookNtClose);
        g_HookNtClose = NULL;
    }
    if (g_HookNtQueryObject) {
        HvHookRemove(g_HookNtQueryObject);
        g_HookNtQueryObject = NULL;
    }
    if (g_HookNtGetContextThread) {
        HvHookRemove(g_HookNtGetContextThread);
        g_HookNtGetContextThread = NULL;
    }
    // 注: g_HookNtSetContextThread 现由 HvHookEnableDebuggerProxy 管理 (阶段 7.8)
    //     这里不要清,免得卸 AAD 顺带把调试器代理拔掉。

    RtlZeroMemory(&g_AntiAntiDebugConfig, sizeof(HV_ANTIANTIDEBUG_CONFIG));
    g_AntiAntiDebugEnabled = FALSE;

    DbgPrint("[HvHook] Anti-anti-debug disabled\n");
    return STATUS_SUCCESS;
}

BOOLEAN
HvHookIsAntiAntiDebugEnabled(VOID)
{
    return g_AntiAntiDebugEnabled;
}

// 注:HvHookIsDebuggerProxyEnabled / HvHookIsAccessBypassEnabled 的实现见文件尾部 access
// bypass 区块之后 —— g_AccessBypassEnabled 在那里 static 定义,C 单遍解析不能前向引用。

// ============================================================
// 调试器保护实现
// ============================================================

NTSTATUS
HvHookAddDebugger(
    _In_ PHV_DEBUGGER_CONFIG Config
)
{
    PPROTECTED_DEBUGGER debugger;
    KIRQL oldIrql;
    
    if (!g_HvHookInitialized) {
        return STATUS_NOT_INITIALIZED;
    }
    
    if (!Config || Config->ProcessId == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    
    // 初始化列表（如果需要）
    if (!g_ProtectedDebuggerInitialized) {
        InitializeListHead(&g_ProtectedDebuggerList);
        KeInitializeSpinLock(&g_ProtectedDebuggerLock);
        g_ProtectedDebuggerInitialized = TRUE;
    }
    
    DbgPrint("[HvHook] Adding protected debugger: PID=%d\n", Config->ProcessId);
    
    // 创建记录
    debugger = (PPROTECTED_DEBUGGER)HvAllocateNonPagedZeroed(
        sizeof(PROTECTED_DEBUGGER), HV_HOOK_TAG);
    
    if (!debugger) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    debugger->ProcessId = Config->ProcessId;
    if (Config->ProcessName[0] != L'\0') {
        RtlStringCbCopyNW(debugger->ProcessName,
                          sizeof(debugger->ProcessName),
                          Config->ProcessName,
                          sizeof(Config->ProcessName));
    }
    debugger->EnablePrivilege = Config->EnablePrivilege;
    debugger->ProtectFromTerminate = Config->ProtectFromTerminate;
    debugger->HideFromList = Config->HideFromList;

    // 2026-06-19: 解析 image full path (\Device\...) 缓存到 debugger 记录
    // 失败不阻断 Add — 只是文件防护不可用 (ImagePathLen=0)
    debugger->ImagePathLen = 0;
    debugger->ImagePath[0] = L'\0';
    {
        PEPROCESS proc = NULL;
        NTSTATUS lkSt = PsLookupProcessByProcessId(
            (HANDLE)(ULONG_PTR)Config->ProcessId, &proc);
        if (NT_SUCCESS(lkSt) && proc) {
            PUNICODE_STRING img = NULL;
            // SeLocateProcessImageName 返回 PUNICODE_STRING (caller 需 ExFreePool)
            // 内容是 \Device\HarddiskVolumeN\Path\To\xxx.exe
            extern NTSTATUS NTAPI SeLocateProcessImageName(
                _In_ PEPROCESS Process, _Out_ PUNICODE_STRING *ProcessImageName);
            NTSTATUS sIm = SeLocateProcessImageName(proc, &img);
            if (NT_SUCCESS(sIm) && img && img->Buffer && img->Length) {
                USHORT copyBytes = img->Length;
                if (copyBytes > sizeof(debugger->ImagePath) - sizeof(WCHAR)) {
                    copyBytes = sizeof(debugger->ImagePath) - sizeof(WCHAR);
                }
                RtlCopyMemory(debugger->ImagePath, img->Buffer, copyBytes);
                debugger->ImagePath[copyBytes / sizeof(WCHAR)] = L'\0';
                debugger->ImagePathLen = (USHORT)(copyBytes / sizeof(WCHAR));
                DbgPrint("[HvHook] Debugger PID=%u ImagePath cached: %wZ (len=%u wchars)\n",
                         Config->ProcessId, img, debugger->ImagePathLen);
            } else {
                DbgPrint("[HvHook] SeLocateProcessImageName failed for PID=%u: 0x%X\n",
                         Config->ProcessId, sIm);
            }
            if (img) ExFreePool(img);
            ObDereferenceObject(proc);
        } else {
            DbgPrint("[HvHook] PsLookupProcessByProcessId failed for PID=%u: 0x%X\n",
                     Config->ProcessId, lkSt);
        }
    }

    // 添加到列表
    KeAcquireSpinLock(&g_ProtectedDebuggerLock, &oldIrql);
    BOOLEAN wasEmpty = IsListEmpty(&g_ProtectedDebuggerList);
    InsertTailList(&g_ProtectedDebuggerList, &debugger->ListEntry);
    KeReleaseSpinLock(&g_ProtectedDebuggerLock, oldIrql);

    // 2026-06-16: 每次 ADD_DEBUGGER 时**重新扫描**白名单进程 → trusted PID 集合。
    // 原因: explorer/taskmgr/dwm/RuntimeBroker 等 UI/shell 进程通常比 driver
    // 加载晚才启动 (登录后), driver init 时扫到的可能就 csrss/wininit/services
    // 等核心服务, 缺失 shell/UI 类。每次 ADD_DEBUGGER 重扫就能拿到当前 session
    // 全部活跃的可信进程。
    //
    // 这些 trusted 进程在 NtRead 反向保护中放行 -- 否则 taskmgr 读 debugger PEB
    // 拿元数据被喂 0 → 用户名 / 体系结构 / 图标 / 描述全空白, debugger 看似"挂了"。
    HvHookpScanTrustedPids();

    // 0->1:第一个调试器注册时装两组核心 hook —— 全权限链路所需。
    //   1) DebuggerProxy : NtSetContextThread + Nt[R/W]VirtualMemory (3 hooks)
    //                      让 caller 的内存/上下文操作重定向到 HvPhys 物理直通
    //   2) AccessBypass  : NtOpenProcess (1 hook)
    //                      让 caller 对任意 user/PPL/System(4) target OpenProcess 成功
    //
    // AAD (反反调试) **不再 auto-enable** ——
    //   - 5 个 hook (NtQueryInformationProcess/NtQuerySystemInformation/
    //     NtSetInformationThread/NtClose/NtQueryObject) 全局生效
    //   - NtClose 和 NtQueryObject 的行为差异极易被游戏反作弊主动探测 ("检测到
    //     黑客工具" 类提示)
    //   - 9 个 syscall 同时 hook 的 EPT-violation+MTF round-trip 让"反作弊扫
    //     ntdll syscall stub 区域的 read timing" 容易看穿
    //   保留 IOCTL_HV_ENABLE_ANTIANTIDEBUG 让 GUI Tab 2 手动启用,只用在调试器
    //   自检会被 user-mode 反调试 API 探到的场景。
    //
    // 这些 hook 与相邻 syscall 共享 4KB 代码页,无调试器注册时不装以免空载
    // EPT-violation 风暴。
    if (wasEmpty) {
        NTSTATUS proxySt = HvHookEnableDebuggerProxy(Config->ProcessId);
        if (NT_SUCCESS(proxySt)) {
            HvDbgEvtPost(HV_DBGEVT_SEV_INFO, HV_DBGEVT_CAT_ADD_DEBUGGER,
                         proxySt, Config->ProcessId, 0, 0, 0,
                         "DebuggerProxy enabled (NtSet/Read/Write VirtualMemory)");
        } else {
            DbgPrint("[HvHook] EnableDebuggerProxy failed: 0x%X (continuing)\n",
                     proxySt);
            HvDbgEvtPost(HV_DBGEVT_SEV_ERROR, HV_DBGEVT_CAT_ADD_DEBUGGER,
                         proxySt, Config->ProcessId, 0, 0, 0,
                         "EnableDebuggerProxy failed");
        }
        NTSTATUS bypassSt = HvHookEnableAccessBypass();
        if (NT_SUCCESS(bypassSt)) {
            HvDbgEvtPost(HV_DBGEVT_SEV_INFO, HV_DBGEVT_CAT_ADD_DEBUGGER,
                         bypassSt, Config->ProcessId, 0, 0, 0,
                         "AccessBypass enabled (NtOpenProcess PPL/System strip)");
        } else {
            DbgPrint("[HvHook] EnableAccessBypass failed: 0x%X (continuing)\n",
                     bypassSt);
            HvDbgEvtPost(HV_DBGEVT_SEV_ERROR, HV_DBGEVT_CAT_ADD_DEBUGGER,
                         bypassSt, Config->ProcessId, 0, 0, 0,
                         "EnableAccessBypass failed");
        }
        HvDbgEvtPost(HV_DBGEVT_SEV_INFO, HV_DBGEVT_CAT_ADD_DEBUGGER,
                     STATUS_SUCCESS, Config->ProcessId, 0, 0, 0,
                     "ADD_DEBUGGER 0->1: DebuggerProxy + AccessBypass armed (AAD opt-in via Tab 2)");
    } else {
        HvDbgEvtPost(HV_DBGEVT_SEV_INFO, HV_DBGEVT_CAT_ADD_DEBUGGER,
                     STATUS_SUCCESS, Config->ProcessId, 0, 0, 0,
                     "ADD_DEBUGGER (additional debugger, hooks already armed)");
    }

    // 如果需要隐藏调试器进程
    if (Config->HideFromList) {
        HvHookHideProcess(Config->ProcessId);
    }

    DbgPrint("[HvHook] Debugger protected: PID=%d, Hide=%d\n",
        Config->ProcessId, Config->HideFromList);

    // P125 (2026-06-25): 旧 cloak 删除. PEB cloak 不在 ADD_DEBUGGER 时注册,
    // 改为 NtDebugActiveProcess hook 内按 target 注册 (谁 attach 谁 cloak 谁的 PEB).

    return STATUS_SUCCESS;
}

NTSTATUS
HvHookRemoveDebugger(
    _In_ ULONG ProcessId
)
{
    PLIST_ENTRY entry;
    PPROTECTED_DEBUGGER debugger = NULL;
    KIRQL oldIrql;
    BOOLEAN found = FALSE;
    
    if (!g_HvHookInitialized || !g_ProtectedDebuggerInitialized) {
        return STATUS_NOT_INITIALIZED;
    }

    // P122 noise control: HvDbgpProcessNotifyCallback 对每个进程退出都调本函数,
    // 99% 的退出 PID 不在 debugger 白名单, 打日志无意义. 移到 found 之后打.
    KeAcquireSpinLock(&g_ProtectedDebuggerLock, &oldIrql);

    for (entry = g_ProtectedDebuggerList.Flink;
         entry != &g_ProtectedDebuggerList;
         entry = entry->Flink)
    {
        debugger = CONTAINING_RECORD(entry, PROTECTED_DEBUGGER, ListEntry);

        if (debugger->ProcessId == ProcessId) {
            RemoveEntryList(entry);
            found = TRUE;
            break;
        }
    }

    BOOLEAN nowEmpty = IsListEmpty(&g_ProtectedDebuggerList);
    KeReleaseSpinLock(&g_ProtectedDebuggerLock, oldIrql);

    // 1->0:最后一个调试器注销时拆掉两组核心 hook,让 syscall 路径回到 zero-overhead。
    // AAD 不在这条 auto 路径里 (它由 GUI 手动启用/禁用,有独立生命周期)。
    if (found && nowEmpty) {
        HvHookDisableDebuggerProxy();
        HvHookDisableAccessBypass();
        HvDbgEvtPost(HV_DBGEVT_SEV_INFO, HV_DBGEVT_CAT_REMOVE_DEBUGGER,
                     STATUS_SUCCESS, ProcessId, 0, 0, 0,
                     "REMOVE_DEBUGGER 1->0: DebuggerProxy + AccessBypass disarmed");
    }

    if (found && debugger) {
        // P122 noise control: 真正命中白名单才打.
        DbgPrint("[HvHook] Removing protected debugger: PID=%d\n", ProcessId);

        // 如果之前隐藏了，取消隐藏
        if (debugger->HideFromList) {
            HvHookUnhideProcess(ProcessId);
        }
        ExFreePoolWithTag(debugger, HV_HOOK_TAG);

        // P125: 旧 cloak 删除, PEB cloak 是 per-target 不是 per-debugger,
        // 由 target 进程退出时 ProcessNotifyRoutine 自动清理.

        return STATUS_SUCCESS;
    }

    return STATUS_NOT_FOUND;
}

ULONG
HvHookGetDebuggerCount(VOID)
{
    PLIST_ENTRY entry;
    ULONG count = 0;
    KIRQL oldIrql;

    if (!g_ProtectedDebuggerInitialized) {
        return 0;
    }

    KeAcquireSpinLock(&g_ProtectedDebuggerLock, &oldIrql);

    for (entry = g_ProtectedDebuggerList.Flink;
         entry != &g_ProtectedDebuggerList;
         entry = entry->Flink)
    {
        count++;
    }

    KeReleaseSpinLock(&g_ProtectedDebuggerLock, oldIrql);

    return count;
}

// 2026-06-20 方案 A: DriverUnload 时强制 terminate 所有注册过的 debugger 进程
// 见 HvHook.h 注释。
// 前置声明 (NTKERNELAPI 完整 prototype 在文件下方 line 5396, 这里 forward declare)
extern NTKERNELAPI NTSTATUS NTAPI ObOpenObjectByPointer(
    _In_     PVOID            Object,
    _In_     ULONG            HandleAttributes,
    _In_opt_ PACCESS_STATE    PassedAccessState,
    _In_     ACCESS_MASK      DesiredAccess,
    _In_opt_ POBJECT_TYPE     ObjectType,
    _In_     KPROCESSOR_MODE  AccessMode,
    _Out_    PHANDLE          Handle);

// PROCESS_TERMINATE: ntddk 默认不暴露 process-specific access masks
#ifndef PROCESS_TERMINATE
#define PROCESS_TERMINATE 0x0001
#endif

ULONG
HvHookTerminateAllDebuggers(VOID)
{
    if (!g_ProtectedDebuggerInitialized) return 0;

    // 1) 出锁前先把所有 PID 收集到栈上数组 (避免在锁内调可阻塞 API)
    //    最多保护 64 个 debugger 已经超额, 实际生产场景就 1-2 个。
    ULONG pids[64] = { 0 };
    ULONG count = 0;
    KIRQL oldIrql;

    KeAcquireSpinLock(&g_ProtectedDebuggerLock, &oldIrql);
    PLIST_ENTRY entry;
    for (entry = g_ProtectedDebuggerList.Flink;
         entry != &g_ProtectedDebuggerList && count < RTL_NUMBER_OF(pids);
         entry = entry->Flink)
    {
        PPROTECTED_DEBUGGER dbg = CONTAINING_RECORD(entry, PROTECTED_DEBUGGER, ListEntry);
        if (dbg->ProcessId != 0) {
            pids[count++] = dbg->ProcessId;
        }
    }
    KeReleaseSpinLock(&g_ProtectedDebuggerLock, oldIrql);

    if (count == 0) {
        DbgPrint("[HvHook] TerminateAllDebuggers: no registered debugger, skip\n");
        return 0;
    }

    DbgPrint("[HvHook] TerminateAllDebuggers: %u debugger(s) to terminate\n", count);

    // 2) 依次 terminate
    ULONG killed = 0;
    for (ULONG i = 0; i < count; i++) {
        ULONG pid = pids[i];
        PEPROCESS proc = NULL;
        NTSTATUS s = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &proc);
        if (!NT_SUCCESS(s) || !proc) {
            DbgPrint("[HvHook] TerminateAllDebuggers PID=%u: PsLookup failed 0x%X (already gone?)\n",
                     pid, s);
            continue;
        }

        // 用 ObOpenObjectByPointer + KernelMode 绕 SeAccessCheck。
        // PROCESS_TERMINATE = 0x0001
        HANDLE hProc = NULL;
        s = ObOpenObjectByPointer(proc, OBJ_KERNEL_HANDLE, NULL,
                                  PROCESS_TERMINATE, *PsProcessType,
                                  KernelMode, &hProc);
        ObDereferenceObject(proc);  // 立刻 deref, handle 自己持引用

        if (!NT_SUCCESS(s) || !hProc) {
            DbgPrint("[HvHook] TerminateAllDebuggers PID=%u: ObOpen failed 0x%X\n", pid, s);
            continue;
        }

        s = ZwTerminateProcess(hProc, 0);
        ZwClose(hProc);
        if (NT_SUCCESS(s)) {
            killed++;
            DbgPrint("[HvHook] TerminateAllDebuggers PID=%u: terminated\n", pid);
        } else {
            DbgPrint("[HvHook] TerminateAllDebuggers PID=%u: ZwTerminateProcess failed 0x%X\n",
                     pid, s);
        }
    }

    // 3) 等一小会儿, 让 PsSetCreateProcessNotifyRoutineEx 回调 (HvDbgpProcessNotifyCallback)
    //    跑完, HWBP / 调试器 list 自动清理。50ms 通常足够。
    if (killed > 0) {
        LARGE_INTEGER delay;
        delay.QuadPart = -500000LL;  // 50ms relative (100ns units)
        KeDelayExecutionThread(KernelMode, FALSE, &delay);
    }

    DbgPrint("[HvHook] TerminateAllDebuggers: killed=%u/%u\n", killed, count);
    return killed;
}

// ============================================================
// 进程保护实现
// ============================================================

NTSTATUS
HvHookProtectProcess(
    _In_ PHV_PROTECT_CONFIG Config
)
{
    PPROTECTED_PROCESS proc;
    KIRQL oldIrql;
    
    if (!g_HvHookInitialized) {
        return STATUS_NOT_INITIALIZED;
    }
    
    if (!Config || Config->ProcessId == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    
    // 初始化列表（如果需要）
    if (!g_ProtectedProcessInitialized) {
        InitializeListHead(&g_ProtectedProcessList);
        KeInitializeSpinLock(&g_ProtectedProcessLock);
        g_ProtectedProcessInitialized = TRUE;
    }
    
    DbgPrint("[HvHook] Protecting process: PID=%d, DebuggerPID=%d\n", 
        Config->ProcessId, Config->DebuggerPid);
    
    // 创建记录
    proc = (PPROTECTED_PROCESS)HvAllocateNonPagedZeroed(
        sizeof(PROTECTED_PROCESS), HV_HOOK_TAG);
    
    if (!proc) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    proc->ProcessId = Config->ProcessId;
    if (Config->ProcessName[0] != L'\0') {
        RtlStringCbCopyNW(proc->ProcessName,
                          sizeof(proc->ProcessName),
                          Config->ProcessName,
                          sizeof(Config->ProcessName));
    }
    proc->DebuggerPid = Config->DebuggerPid;
    proc->PreventTerminate = Config->PreventTerminate;
    proc->PreventSuspend = Config->PreventSuspend;
    proc->PreventMemoryAccess = Config->PreventMemoryAccess;
    
    // 添加到列表
    KeAcquireSpinLock(&g_ProtectedProcessLock, &oldIrql);
    InsertTailList(&g_ProtectedProcessList, &proc->ListEntry);
    KeReleaseSpinLock(&g_ProtectedProcessLock, oldIrql);
    
    DbgPrint("[HvHook] Process protected: PID=%d\n", Config->ProcessId);
    
    return STATUS_SUCCESS;
}

NTSTATUS
HvHookUnprotectProcess(
    _In_ ULONG ProcessId
)
{
    PLIST_ENTRY entry;
    PPROTECTED_PROCESS proc = NULL;
    KIRQL oldIrql;
    BOOLEAN found = FALSE;
    
    if (!g_HvHookInitialized || !g_ProtectedProcessInitialized) {
        return STATUS_NOT_INITIALIZED;
    }
    
    DbgPrint("[HvHook] Unprotecting process: PID=%d\n", ProcessId);
    
    KeAcquireSpinLock(&g_ProtectedProcessLock, &oldIrql);
    
    for (entry = g_ProtectedProcessList.Flink;
         entry != &g_ProtectedProcessList;
         entry = entry->Flink)
    {
        proc = CONTAINING_RECORD(entry, PROTECTED_PROCESS, ListEntry);
        
        if (proc->ProcessId == ProcessId) {
            RemoveEntryList(entry);
            found = TRUE;
            break;
        }
    }
    
    KeReleaseSpinLock(&g_ProtectedProcessLock, oldIrql);
    
    if (found && proc) {
        ExFreePoolWithTag(proc, HV_HOOK_TAG);
        return STATUS_SUCCESS;
    }
    
    return STATUS_NOT_FOUND;
}

ULONG
HvHookGetProtectedProcessCount(VOID)
{
    PLIST_ENTRY entry;
    ULONG count = 0;
    KIRQL oldIrql;

    if (!g_ProtectedProcessInitialized) {
        return 0;
    }

    KeAcquireSpinLock(&g_ProtectedProcessLock, &oldIrql);

    for (entry = g_ProtectedProcessList.Flink;
         entry != &g_ProtectedProcessList;
         entry = entry->Flink)
    {
        count++;
    }

    KeReleaseSpinLock(&g_ProtectedProcessLock, oldIrql);

    return count;
}

// ============================================================
// 阶段 7.1: 调试器/进程白名单快速查询
// ============================================================

BOOLEAN
HvHookIsDebuggerPid(
    _In_ HANDLE Pid
)
{
    PLIST_ENTRY entry;
    PPROTECTED_DEBUGGER dbg;
    KIRQL oldIrql;
    BOOLEAN found = FALSE;
    ULONG targetPid = (ULONG)(ULONG_PTR)Pid;

    if (!g_ProtectedDebuggerInitialized || targetPid == 0) {
        return FALSE;
    }

    KeAcquireSpinLock(&g_ProtectedDebuggerLock, &oldIrql);

    for (entry = g_ProtectedDebuggerList.Flink;
         entry != &g_ProtectedDebuggerList;
         entry = entry->Flink)
    {
        dbg = CONTAINING_RECORD(entry, PROTECTED_DEBUGGER, ListEntry);
        if (dbg->ProcessId == targetPid) {
            found = TRUE;
            break;
        }
    }

    KeReleaseSpinLock(&g_ProtectedDebuggerLock, oldIrql);
    return found;
}

// ============================================================
// 2026-06-19: 文件防护比对 — 判断给定路径是否命中已注册 debugger 的 image
// ============================================================
//
// 输入是 NtCreateFile/NtReadFile 的 ObjectAttributes.ObjectName,可能是:
//   \??\C:\Path\To\xxx.exe       (DOS path)
//   \Device\HarddiskVolume3\..   (NT path)
// 我们缓存的 ImagePath 是 SeLocateProcessImageName 返回的 NT path
// (\Device\HarddiskVolumeN\...)。
//
// 比对策略: 取 ImagePath 最后 N 个字符 (basename + 父目录段,可识别但避免误伤),
// 在传入路径里做 case-insensitive 包含匹配。
//
// N=取 ImagePath 末段 (向前到最近的 `\`, 但至少 16 个字符)。
// 比如 ImagePath="\Device\HarddiskVolume3\Users\xxx\source\repos\MyDriver1\x64\Release\notepad.exe"
// 末段会从倒数第二个 `\` 起 = "Release\notepad.exe", 长度 19。
// CE 不管走 \??\C:\... 还是 \Device\..., 一定包含 "Release\notepad.exe"。
// 正常的 C:\Windows\System32\notepad.exe 不含 "Release\" 前缀, 不误伤。
static BOOLEAN HvHookpUnicodeContainsCaseInsensitive(
    _In_ PCWCH HayBuf, _In_ USHORT HayLen,        // wchar count, no NUL needed
    _In_ PCWCH NeedleBuf, _In_ USHORT NeedleLen)
{
    if (NeedleLen == 0 || HayLen < NeedleLen) return FALSE;
    USHORT scanEnd = HayLen - NeedleLen + 1;
    for (USHORT i = 0; i < scanEnd; i++) {
        BOOLEAN match = TRUE;
        for (USHORT j = 0; j < NeedleLen; j++) {
            WCHAR a = HayBuf[i + j];
            WCHAR b = NeedleBuf[j];
            // ASCII case-fold (路径里只可能 ASCII letter 需要折叠, 中文 UTF-16 不动)
            if (a >= L'A' && a <= L'Z') a = (WCHAR)(a - L'A' + L'a');
            if (b >= L'A' && b <= L'Z') b = (WCHAR)(b - L'A' + L'a');
            if (a != b) { match = FALSE; break; }
        }
        if (match) return TRUE;
    }
    return FALSE;
}

BOOLEAN
HvHookIsPathDebuggerImage(
    _In_ PCUNICODE_STRING Path
)
{
    if (!Path || !Path->Buffer || Path->Length == 0) return FALSE;
    if (!g_ProtectedDebuggerInitialized) return FALSE;

    USHORT pathWchars = Path->Length / sizeof(WCHAR);

    PLIST_ENTRY entry;
    PPROTECTED_DEBUGGER dbg;
    KIRQL oldIrql;
    BOOLEAN found = FALSE;

    KeAcquireSpinLock(&g_ProtectedDebuggerLock, &oldIrql);
    for (entry = g_ProtectedDebuggerList.Flink;
         entry != &g_ProtectedDebuggerList;
         entry = entry->Flink)
    {
        dbg = CONTAINING_RECORD(entry, PROTECTED_DEBUGGER, ListEntry);
        if (dbg->ImagePathLen == 0) continue;

        // 取 dbg->ImagePath 末段 (向前到倒数第二个 `\`, 保证至少 12 字符)
        USHORT total = dbg->ImagePathLen;
        USHORT tailStart = total;
        int slashSeen = 0;
        while (tailStart > 0 && slashSeen < 2) {
            tailStart--;
            if (dbg->ImagePath[tailStart] == L'\\') slashSeen++;
        }
        // tailStart 现在指向倒数第二个 `\` (或 0)
        if (dbg->ImagePath[tailStart] == L'\\') tailStart++;  // 越过 `\`
        USHORT tailLen = (USHORT)(total - tailStart);
        if (tailLen < 12) {
            // 末段太短, 用 basename 加适当兜底 (落到 basename 比对)
            // 重新从最后一个 `\` 找
            tailStart = total;
            while (tailStart > 0 && dbg->ImagePath[tailStart - 1] != L'\\') tailStart--;
            tailLen = (USHORT)(total - tailStart);
        }

        if (HvHookpUnicodeContainsCaseInsensitive(
                Path->Buffer, pathWchars,
                &dbg->ImagePath[tailStart], tailLen))
        {
            found = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&g_ProtectedDebuggerLock, oldIrql);
    return found;
}

// ============================================================
// Phase K: 受信 caller 白名单 (反向保护用)
// ============================================================
//
// 反向保护拒绝外部 caller 读/写/查询 debugger 进程,但**系统进程**必须放行
// (否则 csrss / WerFault / SCM 等核心服务对 debugger 操作会失败,卡死登录会话
// 或导致崩溃处理异常)。
//
// 设计:
//   - PID=4 (System) 始终可信 (内核线程)
//   - 其他可信进程名固定在 g_TrustedCallerNames[],driver init 时枚举系统进程列表
//     填 PID 到 g_TrustedCallerPids[]。
//   - 运行期只读,无锁 (启动期单线程填,之后只读)
//   - 若 winlogon/csrss 等动态重启(罕见),反向保护对新 PID 不放行,fail-safe:
//     该 syscall 返 ACCESS_DENIED,系统行为略受影响但不蓝屏。

// WDK 不在 ntddk.h 暴露 ZwQuerySystemInformation / SystemProcessInformation,
// 手动 extern (与 HvInput.c:96 同模式)。NptHook.c:1845 自定义 process info 结构
// 因为它同时要兼容多版本 EPROCESS;我们这里只需要前几个字段,简化定义。
extern NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(
    _In_ ULONG SystemInformationClass,
    _Inout_opt_ PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength);

// PsGetProcessImageFileName 已在文件顶部前置声明 (NtUserBuildHwndList hook 也用)

// (struct + 宏 提前到本节, 见 NtQuerySystemInformation hook 引用)
#define HV_TRUSTED_PID_MAX 48   // 受信进程**名字**槽位 (最多 48 个名字, 留余量)
#define HV_TRUSTED_RUNTIME_PIDS_MAX 256  // 运行期 PID 集合 (svchost / explorer 等可能多实例)

static const PCWSTR g_TrustedCallerNames[HV_TRUSTED_PID_MAX] = {
    // 核心系统服务 (会话管理/凭据/异常处理 — 缺一就登录或报错处理出问题)
    L"csrss.exe",
    L"wininit.exe",
    L"smss.exe",
    L"services.exe",
    L"lsass.exe",
    L"winlogon.exe",
    L"WerFault.exe",
    L"svchost.exe",                        // 系统服务宿主 (taskmgr 部分查询走它)
    // 桌面 / Shell UI (启动后会读其他进程的元数据 / 缩略图 / 窗口属性)
    L"explorer.exe",                       // 资源管理器 / 桌面 / 任务栏 / 拖拽
    L"dwm.exe",                            // 桌面窗口管理器 (合成 / 缩略图)
    L"sihost.exe",                         // Shell Infrastructure Host
    L"taskhostw.exe",                      // Task Host (后台任务 + shell extension)
    L"ApplicationFrameHost.exe",           // UWP 窗口宿主
    L"SearchHost.exe",                     // Win11 搜索 UI
    L"SearchApp.exe",                      // Win10 / 11 alt 搜索 UI
    L"StartMenuExperienceHost.exe",        // 开始菜单
    L"ShellExperienceHost.exe",            // 通知中心 / Action Center
    L"RuntimeBroker.exe",                  // UWP runtime broker
    // 任务管理器 / 系统监视
    L"Taskmgr.exe",                        // 任务管理器
    L"perfmon.exe",                        // 性能监视器
    L"resmon.exe",                         // 资源监视器
    L"PerfWatson2.exe",                    // VS 性能跟踪
    // 安全 / 反作弊例外 (这些读 debugger 是合法行为, 拒绝会导致登录卡死)
    L"MsMpEng.exe",                        // Defender
    L"SecurityHealthService.exe",          // Windows Security
    L"audiodg.exe",                        // 音频隔离 (有时检查进程会话)
    L"conhost.exe",                        // 控制台宿主 (debugger 是 console 时需要)
    L"fontdrvhost.exe",                    // 字体驱动宿主 (UI 渲染相关)
    // 用户应用辅助 (输入法 / 通知)
    L"ctfmon.exe",                         // 文本输入服务
    NULL,                                  // sentinel
    NULL,
    NULL,
    NULL,
    NULL,
};

// 运行期 PID 集合 - svchost / explorer / RuntimeBroker 多实例都进这个集合。
// 写入路径只在 HvHookpScanTrustedPids 内 (ADD_DEBUGGER 时调一次), 读取路径
// 在 HvHookIsTrustedSystemCaller 频繁调用, 用 volatile + 单线程写保证可见性。
static volatile HANDLE g_TrustedCallerPids[HV_TRUSTED_RUNTIME_PIDS_MAX] = { 0 };
static volatile ULONG  g_TrustedCallerPidCount = 0;

// 内部:枚举系统进程列表,把名字命中 g_TrustedCallerNames 的 **所有** PID
// 填入 g_TrustedCallerPids (svchost/explorer 等可能多实例)。
// 每次 ADD_DEBUGGER 时重新调用, 覆写整个集合 (旧值会被丢弃,新一轮全填充)。
VOID
HvHookpScanTrustedPids(VOID)
{
    NTSTATUS status;
    ULONG bufLen = 0;
    PVOID buf = NULL;

    // 先 query 大小 (会返 STATUS_INFO_LENGTH_MISMATCH,但 bufLen 被填上)
    status = ZwQuerySystemInformation(HV_SYSTEM_PROCESS_INFORMATION_CLASS,
                                       NULL, 0, &bufLen);
    if (bufLen == 0) {
        DbgPrint("[HvHook] ScanTrustedPids: initial query failed 0x%X\n", status);
        return;
    }
    bufLen += 0x4000;   // 多预留 16KB,避免 query 时进程列表增长

    buf = HvAllocateNonPagedZeroed(bufLen, 'HvTP');
    if (!buf) {
        DbgPrint("[HvHook] ScanTrustedPids: pool alloc failed (need %u)\n", bufLen);
        return;
    }

    status = ZwQuerySystemInformation(HV_SYSTEM_PROCESS_INFORMATION_CLASS,
                                       buf, bufLen, &bufLen);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[HvHook] ScanTrustedPids: query failed 0x%X\n", status);
        ExFreePoolWithTag(buf, 'HvTP');
        return;
    }

    // 先清空旧集合 (count 置 0 → reader 看到的就是空,后续填回去)
    g_TrustedCallerPidCount = 0;
    for (ULONG i = 0; i < HV_TRUSTED_RUNTIME_PIDS_MAX; i++) {
        g_TrustedCallerPids[i] = NULL;
    }
    ULONG filled = 0;

    PHV_SYSTEM_PROCESS_INFO_HEADER procInfo = (PHV_SYSTEM_PROCESS_INFO_HEADER)buf;
    while (TRUE) {
        if (procInfo->ImageName.Buffer && procInfo->ImageName.Length > 0) {
            for (ULONG i = 0; i < HV_TRUSTED_PID_MAX; i++) {
                PCWSTR name = g_TrustedCallerNames[i];
                if (!name) break;

                UNICODE_STRING wantedName;
                RtlInitUnicodeString(&wantedName, name);

                // 大小写不敏感比较
                if (RtlEqualUnicodeString(&procInfo->ImageName, &wantedName, TRUE)) {
                    if (filled < HV_TRUSTED_RUNTIME_PIDS_MAX) {
                        g_TrustedCallerPids[filled] = procInfo->UniqueProcessId;
                        filled++;
                        // P122 noise control: 启动期 93 个 svchost/conhost 全打太刷屏,
                        // 保留 summary 在循环外打. 详情默认抑制.
                        HV_HOT_DBG("[HvHook] Trusted PID[%u]: %wZ = %u\n",
                                   filled - 1,
                                   &procInfo->ImageName,
                                   (ULONG)(ULONG_PTR)procInfo->UniqueProcessId);
                    } else {
                        DbgPrint("[HvHook] Trusted PID array full (%u), dropping %wZ = %u\n",
                                 HV_TRUSTED_RUNTIME_PIDS_MAX,
                                 &procInfo->ImageName,
                                 (ULONG)(ULONG_PTR)procInfo->UniqueProcessId);
                    }
                    break;
                }
            }
        }

        if (procInfo->NextEntryOffset == 0) break;
        procInfo = (PHV_SYSTEM_PROCESS_INFO_HEADER)
                   ((PUCHAR)procInfo + procInfo->NextEntryOffset);
    }

    g_TrustedCallerPidCount = filled;
    DbgPrint("[HvHook] ScanTrustedPids: filled %u trusted PIDs\n", filled);

    ExFreePoolWithTag(buf, 'HvTP');

    // P125: 旧 cloak 的 TrustedCr3Cache 删除. PEB cloak 不需要 trusted PID 列表,
    // classifier 只看 target CR3.
}

BOOLEAN
HvHookIsTrustedSystemCaller(
    _In_ HANDLE Pid
)
{
    if ((ULONG_PTR)Pid == 4) return TRUE;   // System
    if (!Pid) return FALSE;

    ULONG count = g_TrustedCallerPidCount;
    if (count > HV_TRUSTED_RUNTIME_PIDS_MAX) count = HV_TRUSTED_RUNTIME_PIDS_MAX;
    for (ULONG i = 0; i < count; i++) {
        HANDLE p = g_TrustedCallerPids[i];
        if (p && p == Pid) return TRUE;
    }

    // 2026-06-18: 动态 fallback — 静态表是 driver init / ADD_DEBUGGER 时填的,
    // 之后启动的 trusted 进程 (taskmgr / SearchHost / explorer 重启 / 等等)
    // PID 不在表里, 会被当成"外部 caller"触发 spoof,导致任务管理器看 debugger
    // 显示成 notepad.exe。
    //
    // 修复: caller 不在静态表时, 查它的 EPROCESS.ImageFileName。命中 trusted
    // 名字列表 → 加进运行期表 + 返 TRUE。
    //
    // 性能: 这条路径只在首次"陌生 PID 查 trusted"时跑一次, 之后 PID 进表查询
    // 直接命中循环。
    //
    // IRQL 要求: PsLookupProcessByProcessId / PsGetProcessImageFileName 都要求
    // IRQL <= APC_LEVEL。caller (HvHookIsTrustedSystemCaller) 在 hook 内已做
    // IRQL > APC_LEVEL 提前返回, 这里安全。
    if (KeGetCurrentIrql() > APC_LEVEL) return FALSE;

    PEPROCESS proc = NULL;
    if (!NT_SUCCESS(PsLookupProcessByProcessId(Pid, &proc)) || !proc) {
        return FALSE;
    }

    // PsGetProcessImageFileName 返回 PUCHAR 指 EPROCESS.ImageFileName (15 字节 ASCII)
    PUCHAR imgName = PsGetProcessImageFileName(proc);
    BOOLEAN hit = FALSE;
    if (imgName) {
        // 拷到 ASCII 栈缓冲 (避免 dereference 别人字段)
        CHAR localName[16] = { 0 };
        for (ULONG i = 0; i < 15; i++) {
            localName[i] = (CHAR)imgName[i];
            if (!localName[i]) break;
        }
        // 对照 g_TrustedCallerNames (WCHAR) 逐项比较 (case-insensitive)
        for (ULONG i = 0; i < HV_TRUSTED_PID_MAX; i++) {
            PCWSTR wname = g_TrustedCallerNames[i];
            if (!wname) break;  // sentinel
            // ImageFileName 是 EXE 的 short name (不含路径), 最长 15 字节, 这里
            // 双向比较。case-insensitive ASCII match。
            BOOLEAN matched = TRUE;
            ULONG j = 0;
            for (; j < 15; j++) {
                WCHAR wc = wname[j];
                CHAR  ac = localName[j];
                if (wc == 0 && ac == 0) break;
                if (wc == 0 || ac == 0) { matched = FALSE; break; }
                CHAR wa = (CHAR)wc;
                CHAR a  = ac;
                if (wa >= 'A' && wa <= 'Z') wa = (CHAR)(wa + 32);
                if (a  >= 'A' && a  <= 'Z') a  = (CHAR)(a  + 32);
                if (wa != a) { matched = FALSE; break; }
            }
            if (matched) { hit = TRUE; break; }
        }

        if (hit) {
            // 加进运行期表 (有空位即写, 写入路径单线程 race 容忍)
            ULONG cur = g_TrustedCallerPidCount;
            if (cur < HV_TRUSTED_RUNTIME_PIDS_MAX) {
                g_TrustedCallerPids[cur] = Pid;
                g_TrustedCallerPidCount = cur + 1;
                // P122 noise control: 系统每开新 conhost/svchost 就一条, 默认抑制
                HV_HOT_DBG("[HvHook] Trusted PID added dynamically: PID=%u name='%s'\n",
                           (ULONG)(ULONG_PTR)Pid, localName);
            }
        }
    }

    ObDereferenceObject(proc);
    return hit;
}

BOOLEAN
HvHookIsProtectedProcessPid(
    _In_ HANDLE Pid
)
{
    PLIST_ENTRY entry;
    PPROTECTED_PROCESS proc;
    KIRQL oldIrql;
    BOOLEAN found = FALSE;
    ULONG targetPid = (ULONG)(ULONG_PTR)Pid;

    if (!g_ProtectedProcessInitialized || targetPid == 0) {
        return FALSE;
    }

    KeAcquireSpinLock(&g_ProtectedProcessLock, &oldIrql);

    for (entry = g_ProtectedProcessList.Flink;
         entry != &g_ProtectedProcessList;
         entry = entry->Flink)
    {
        proc = CONTAINING_RECORD(entry, PROTECTED_PROCESS, ListEntry);
        if (proc->ProcessId == targetPid) {
            found = TRUE;
            break;
        }
    }

    KeReleaseSpinLock(&g_ProtectedProcessLock, oldIrql);
    return found;
}

NTSTATUS
HvHookGetProtectedTargetForDebugger(
    _In_ HANDLE DebuggerPid,
    _Out_ PHANDLE OutTargetPid
)
{
    PLIST_ENTRY entry;
    PPROTECTED_PROCESS proc;
    KIRQL oldIrql;
    NTSTATUS status = STATUS_NOT_FOUND;
    ULONG dbgPid = (ULONG)(ULONG_PTR)DebuggerPid;

    if (!OutTargetPid) {
        return STATUS_INVALID_PARAMETER;
    }
    *OutTargetPid = NULL;

    if (!g_ProtectedProcessInitialized || dbgPid == 0) {
        return STATUS_NOT_FOUND;
    }

    KeAcquireSpinLock(&g_ProtectedProcessLock, &oldIrql);

    for (entry = g_ProtectedProcessList.Flink;
         entry != &g_ProtectedProcessList;
         entry = entry->Flink)
    {
        proc = CONTAINING_RECORD(entry, PROTECTED_PROCESS, ListEntry);
        if (proc->DebuggerPid == dbgPid) {
            *OutTargetPid = (HANDLE)(ULONG_PTR)proc->ProcessId;
            status = STATUS_SUCCESS;
            break;
        }
    }

    KeReleaseSpinLock(&g_ProtectedProcessLock, oldIrql);
    return status;
}

// ============================================================
// 阶段 7.8: 调试器代理 Hook
// ============================================================
//
// 让调试器在用户态用标准 Windows API 操作被保护进程时,内核侧悄悄重定向:
//   - NtSetContextThread 带 DR 字段 → 捕获到 HWBP shadow,然后从 CONTEXT.ContextFlags
//     抹掉 CONTEXT_DEBUG_REGISTERS,让原 syscall 完全感知不到 DR 字段。
//   - NtReadVirtualMemory / NtWriteVirtualMemory 操作目标 PID → 走 HvPhys* 物理直通
//     (内部 VtRoot,对目标 EDR/Mm 完全隐身)。
//
// Windows x64 CONTEXT 结构的关键字段偏移 (来自 winnt.h):
//   #define CONTEXT_AMD64               0x00100000L
//   #define CONTEXT_DEBUG_REGISTERS     (CONTEXT_AMD64 | 0x00000010L)
#define HV_CONTEXT_DEBUG_REGISTERS   0x00100010UL
//   ContextFlags @ 0x30 (ULONG)
//   Dr0..Dr3     @ 0x48..0x60 (各 8B)
//   Dr6, Dr7     @ 0x68, 0x70 (各 8B)
#define HV_CTX_OFF_FLAGS  0x30
#define HV_CTX_OFF_DR0    0x48
#define HV_CTX_OFF_DR1    0x50
#define HV_CTX_OFF_DR2    0x58
#define HV_CTX_OFF_DR3    0x60
#define HV_CTX_OFF_DR6    0x68
#define HV_CTX_OFF_DR7    0x70

typedef NTSTATUS (NTAPI *PFN_NtSetContextThread)(HANDLE ThreadHandle, PVOID ThreadContext);
typedef NTSTATUS (NTAPI *PFN_NtReadVirtualMemory)(
    HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer,
    SIZE_T BufferSize, PSIZE_T NumberOfBytesRead);
typedef NTSTATUS (NTAPI *PFN_NtWriteVirtualMemory)(
    HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer,
    SIZE_T BufferSize, PSIZE_T NumberOfBytesWritten);

static HANDLE HvHookpThreadHandleToProcessId(HANDLE ThreadHandle)
{
    PETHREAD ethread = NULL;
    HANDLE targetPid = NULL;
    NTSTATUS s = ObReferenceObjectByHandle(
        ThreadHandle, THREAD_QUERY_LIMITED_INFORMATION,
        *PsThreadType, KernelMode, (PVOID*)&ethread, NULL);
    if (NT_SUCCESS(s) && ethread) {
        targetPid = PsGetThreadProcessId(ethread);
        ObDereferenceObject(ethread);
    }
    return targetPid;
}

static HANDLE HvHookpProcessHandleToProcessId(HANDLE ProcessHandle)
{
    PEPROCESS process = NULL;
    HANDLE targetPid = NULL;
    NTSTATUS s = ObReferenceObjectByHandle(
        ProcessHandle, 0,
        *PsProcessType, KernelMode, (PVOID*)&process, NULL);
    if (NT_SUCCESS(s) && process) {
        targetPid = PsGetProcessId(process);
        ObDereferenceObject(process);
    }
    return targetPid;
}

static NTSTATUS NTAPI HookedNtSetContextThread(
    HANDLE ThreadHandle,
    PVOID  ThreadContext
)
{
    PFN_NtSetContextThread Original =
        (PFN_NtSetContextThread)HvHookGetTrampoline(g_HookNtSetContextThread);
    if (!Original) return STATUS_UNSUCCESSFUL;

    // 2026-06-16 诊断 bypass
    if (g_BypassNtSetContextThread) {
        return Original(ThreadHandle, ThreadContext);
    }

    // M3 修正: IRQL > APC_LEVEL 走 Original 避免 0xD1
    if (KeGetCurrentIrql() > APC_LEVEL) {
        return Original(ThreadHandle, ThreadContext);
    }

    HANDLE caller = PsGetCurrentProcessId();
    if (!HvHookIsDebuggerPid(caller) || !ThreadContext) {
        return Original(ThreadHandle, ThreadContext);
    }

    KPROCESSOR_MODE prevMode = ExGetPreviousMode();
    ULONG flags = 0;
    UINT64 dr0 = 0, dr1 = 0, dr2 = 0, dr3 = 0, dr7 = 0;
    BOOLEAN hasDr = FALSE;

    __try {
        if (prevMode == UserMode) {
            ProbeForRead(ThreadContext, HV_CTX_OFF_DR7 + 8, sizeof(ULONG));
        }
        UCHAR* base = (UCHAR*)ThreadContext;
        flags = *(ULONG*)(base + HV_CTX_OFF_FLAGS);
        // 2026-06-26 修: 原判定要求 (flags & 0x00100010) == 0x00100010 即同时含
        // CONTEXT_AMD64 (0x00100000) + DEBUG_REGISTERS sub (0x10), 但很多调试器
        // (CE 包括) ContextFlags 只设 0x10 没设 marker 位 -> 旧判定 hasDr=FALSE
        // -> 直接放行 Original 真写 DR -> target 命中 #DB 无人接闪退.
        // 改为单查 DEBUG_REGISTERS sub-flag bit (0x10) 即可拦截.
        hasDr = (flags & 0x10) != 0;
        if (hasDr) {
            dr0 = *(UINT64*)(base + HV_CTX_OFF_DR0);
            dr1 = *(UINT64*)(base + HV_CTX_OFF_DR1);
            dr2 = *(UINT64*)(base + HV_CTX_OFF_DR2);
            dr3 = *(UINT64*)(base + HV_CTX_OFF_DR3);
            dr7 = *(UINT64*)(base + HV_CTX_OFF_DR7);
        }
        DbgPrint("[HvHook] NtSetCtx debugger-caller flags=0x%X hasDr=%u dr7=0x%llX\n",
                 flags, hasDr, dr7);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return Original(ThreadHandle, ThreadContext);
    }

    if (!hasDr) {
        return Original(ThreadHandle, ThreadContext);
    }

    HANDLE targetPid = HvHookpThreadHandleToProcessId(ThreadHandle);
    if (!targetPid) {
        return Original(ThreadHandle, ThreadContext);
    }

    // P128 (2026-06-25): 拦 DR 写入, 改走 EPT-based 虚拟硬断.
    //
    //   DR7 layout (Intel SDM Vol 3B 17.2.4):
    //     bit[0]  L0 (DR0 local enable)
    //     bit[1]  G0 (DR0 global enable)
    //     bit[2]  L1, bit[3]  G1
    //     bit[4]  L2, bit[5]  G2
    //     bit[6]  L3, bit[7]  G3
    //     bit[10] reserved (=1)
    //     bit[16:17] R/W0  (00=execute, 01=write, 11=read/write, 10=I/O)
    //     bit[18:19] LEN0  (00=1B, 01=2B, 10=8B(or undef), 11=4B)
    //     bit[20:21] R/W1, bit[22:23] LEN1
    //     bit[24:25] R/W2, bit[26:27] LEN2
    //     bit[28:29] R/W3, bit[30:31] LEN3
    //
    // 对每个启用的 slot (L0..L3 之一 = 1 或 G0..G3 之一 = 1):
    //   - 提取 R/W (00→EXECUTE / 01→WRITE / 11→READWRITE / 10→不支持-跳过)
    //   - 提取 LEN (00→1 / 01→2 / 11→4 / 10→8)
    //   - 调 HvVwatchSet(debuggerPid, targetPid, slotIndex, drN, len, type)
    //
    // 抹掉 CONTEXT.ContextFlags 的 DEBUG_REGISTERS bit, 让 Original syscall
    // 不再真的写 KTRAP_FRAME.Dr* — 硬件 DR 寄存器永远保持 0, 反作弊无法 detect.

    UINT64 drs[4] = { dr0, dr1, dr2, dr3 };
    BOOLEAN anyRegistered = FALSE;
    for (ULONG slot = 0; slot < 4; slot++) {
        BOOLEAN local  = (dr7 >> (slot * 2)) & 1;
        BOOLEAN global = (dr7 >> (slot * 2 + 1)) & 1;
        BOOLEAN enabled = local || global;

        if (!enabled || drs[slot] == 0) {
            // slot 不启用 → 清除可能存在的旧 watch
            (void)HvVwatchClear(targetPid, slot);
            continue;
        }

        ULONG rwField  = (ULONG)((dr7 >> (16 + slot * 4)) & 0x3);
        ULONG lenField = (ULONG)((dr7 >> (18 + slot * 4)) & 0x3);

        UCHAR type;
        switch (rwField) {
        case 0x0: type = HV_VWATCH_TYPE_EXECUTE;   break;
        case 0x1: type = HV_VWATCH_TYPE_WRITE;     break;
        case 0x3: type = HV_VWATCH_TYPE_READWRITE; break;
        default:  type = 0; break;   // 0x2 = I/O, 不支持
        }
        if (type == 0) continue;

        UCHAR len;
        switch (lenField) {
        case 0x0: len = 1; break;
        case 0x1: len = 2; break;
        case 0x3: len = 4; break;
        case 0x2: len = 8; break;
        default:  len = 1; break;
        }

        NTSTATUS vs = HvVwatchSet(caller, targetPid, slot, drs[slot], len, type);
        if (NT_SUCCESS(vs)) {
            anyRegistered = TRUE;
        }
        // 失败也继续 — 别的 slot 可能成功
    }

    // 抹掉 ContextFlags 的 DEBUG_REGISTERS bit (0x10), 让 Original 不真写 DR.
    // 2026-06-26 修: 只清 0x10 那一位, 不要把 marker (0x100000) 一起清, 否则
    // Windows kernel 看到 ContextFlags=0 可能 fail with INVALID_PARAMETER.
    __try {
        if (prevMode == UserMode) {
            ProbeForWrite(ThreadContext, HV_CTX_OFF_FLAGS + sizeof(ULONG), sizeof(ULONG));
        }
        UCHAR* base = (UCHAR*)ThreadContext;
        ULONG newFlags = flags & ~0x10UL;   // 只清 DEBUG_REGISTERS sub-flag
        *(ULONG*)(base + HV_CTX_OFF_FLAGS) = newFlags;
        DbgPrint("[HvHook] NtSetCtx erased DR flag: 0x%X -> 0x%X\n", flags, newFlags);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        // 改不了就让 Original 真写 — 退化到旧行为 (反作弊可能 detect, 但不蓝屏)
        DbgPrint("[HvHook] NtSetCtx erase DR flag FAILED\n");
    }

    UNREFERENCED_PARAMETER(anyRegistered);
    return Original(ThreadHandle, ThreadContext);
}

static NTSTATUS NTAPI HookedNtReadVirtualMemory(
    HANDLE   ProcessHandle,
    PVOID    BaseAddress,
    PVOID    Buffer,
    SIZE_T   BufferSize,
    PSIZE_T  NumberOfBytesRead
)
{
    PFN_NtReadVirtualMemory Original =
        (PFN_NtReadVirtualMemory)HvHookGetTrampoline(g_HookNtReadVirtualMemory);
    if (!Original) return STATUS_UNSUCCESSFUL;

    // 2026-06-16 诊断 bypass
    if (g_BypassNtReadVirtualMemory) {
        return Original(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesRead);
    }

    // M3 修正: NtRead 被许多内核路径调用,IRQL 不保证 PASSIVE_LEVEL。
    // ObReferenceObjectByHandle / HvPhysReadProcessMemory 都要求 IRQL <= APC_LEVEL,
    // 高 IRQL 调用会触发 0xD1 DRIVER_IRQL_NOT_LESS_OR_EQUAL。
    // > APC_LEVEL 直接走 Original,跳过我们的 redirect。
    if (KeGetCurrentIrql() > APC_LEVEL) {
        return Original(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesRead);
    }

    HANDLE caller = PsGetCurrentProcessId();
    BOOLEAN callerIsDebugger = HvHookIsDebuggerPid(caller);

    // 2026-06-16 反向保护 (放行+喂假数据语义, 配合扩展 trusted 白名单):
    //
    // caller 不是 debugger 时:
    //   - ProcessHandle == -1 (self-read): target=caller, 而 caller 不是 debugger
    //     → target 也不是 debugger → 直接 Original (业务读自身, 无关 debugger)
    //   - 解出 target, 如果 target!=debugger 或 caller=trusted (csrss/wininit/
    //     explorer/dwm/taskmgr 等扩展白名单) → 直接 Original (合法访问)
    //   - 否则 (target=debugger && caller=外部 && caller 不在白名单)
    //     → 返回 SUCCESS + buffer 全 0 (反作弊/注入器看到的是垃圾)
    //
    // 关键: 扩展白名单覆盖了 explorer/dwm/taskmgr 等 UI/shell 进程,这些是 taskmgr
    // 显示用户名/体系结构/图标/描述的"幕后劳工" -- 它们读 debugger PEB 拿元数据
    // 必须放行, 否则元数据被喂 0 → 进程看似挂掉。
    //
    // 同时 caller=debugger 自身 → 走 Original 或物理直通,完全不受反向保护影响。
    if (!callerIsDebugger) {
        // 自读 (target=caller, caller 不是 debugger → 不可能挡 debugger 内存)
        if (ProcessHandle == (HANDLE)(LONG_PTR)-1) {
            return Original(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesRead);
        }
        // 解 handle, 看 target 是不是 debugger; 同时检查 caller 是否在 trusted 白名单
        HANDLE tgt = HvHookpProcessHandleToProcessId(ProcessHandle);
        if (!tgt || !HvHookIsDebuggerPid(tgt) || HvHookIsTrustedSystemCaller(caller)) {
            return Original(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesRead);
        }

        // target = debugger, caller = 外部, caller 不在 trusted 白名单 → 喂 0
        KPROCESSOR_MODE prevMode = ExGetPreviousMode();
        __try {
            if (prevMode == UserMode) {
                ProbeForWrite(Buffer, BufferSize, 1);
                if (NumberOfBytesRead) {
                    ProbeForWrite(NumberOfBytesRead, sizeof(SIZE_T), sizeof(SIZE_T));
                }
            }
            RtlZeroMemory(Buffer, BufferSize);
            if (NumberOfBytesRead) {
                *NumberOfBytesRead = BufferSize;
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return STATUS_ACCESS_VIOLATION;
        }
        HvDbgEvtPost(HV_DBGEVT_SEV_INFO, HV_DBGEVT_CAT_READ_MEMORY,
                     STATUS_SUCCESS,
                     (ULONG)(ULONG_PTR)caller,
                     (ULONG)(ULONG_PTR)tgt,
                     (UINT64)(ULONG_PTR)BaseAddress, BufferSize,
                     "Read: reverse-protect spoof (zero-fill, target=debugger)");
        return STATUS_SUCCESS;
    }

    // P119: 恢复全权限语义. caller=debugger 走物理直通绕 PPL/System 读.
    //   P118 误判: 之前 CE 设硬断目标崩, 原因是 hypervisor 拦 #DB inject 路径 bug,
    //   跟物理直通无关 (已在 HvVmcs.c:527 删 #DB 拦截修复). 物理直通安全恢复.
    if (BufferSize == 0) {
        return Original(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesRead);
    }

    HANDLE targetPid = HvHookpProcessHandleToProcessId(ProcessHandle);

    // debugger 自读自 → Original (HvPhys 在 demand-paged 用户页失败, 标准路径触发 demand-paging 后成功)
    if (targetPid == caller) {
        return Original(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesRead);
    }

    // 解 handle 失败 → Original
    if (!targetPid) {
        return Original(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesRead);
    }

    SIZE_T done = 0;
    NTSTATUS st = STATUS_SUCCESS;
    KPROCESSOR_MODE prevMode = ExGetPreviousMode();

    __try {
        if (prevMode == UserMode) {
            ProbeForWrite(Buffer, BufferSize, 1);
            if (NumberOfBytesRead) {
                ProbeForWrite(NumberOfBytesRead, sizeof(SIZE_T), sizeof(SIZE_T));
            }
        }
        st = HvPhysReadProcessMemory(
            (ULONG)(ULONG_PTR)targetPid,
            (UINT64)(ULONG_PTR)BaseAddress,
            Buffer, BufferSize, &done);
        if (NumberOfBytesRead) {
            *NumberOfBytesRead = done;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        HvDbgEvtPost(HV_DBGEVT_SEV_ERROR, HV_DBGEVT_CAT_READ_MEMORY,
                     STATUS_ACCESS_VIOLATION,
                     (ULONG)(ULONG_PTR)caller,
                     (ULONG)(ULONG_PTR)targetPid,
                     (UINT64)(ULONG_PTR)BaseAddress, BufferSize,
                     "Read: user buffer probe failed (#PF in __try)");
        return STATUS_ACCESS_VIOLATION;
    }

    // P120: 物理直通失败(典型 NOT_FOUND / IN_PAGE_ERROR / 部分读)→ fallback Original.
    //   背景: 物理直通不 KeStackAttachProcess (反作弊 hook 检测点), 所以 page-out 的
    //   页无法触发 demand-paging, 返 NOT_FOUND. 副作用: CE 持续读, 目标进程切到后台
    //   被 WSM trim 工作集 → 物理直通失败 → CE 显示 ??.
    //   修法: 失败时退回 Original (Windows 原生 RPM, 它 attach + fault-in), 拿到数据.
    //   代价: 反作弊在 Original 路径上能看到 caller=CE 通过 attach 访问 target — 但
    //   CE attach 游戏本来就是合法的 user-mode 行为, 反作弊不会因为这个崩 (它崩是
    //   因为看到了 driver/DR/syscall hook). 这里 fallback 完全等同于裸 CE 行为.
    if (!NT_SUCCESS(st) || done < BufferSize) {
        // 静默重试 Original (大多数 CE 持续读会撞到这里, 不打 ring 避免淹没)
        NTSTATUS st2 = Original(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesRead);
        if (NT_SUCCESS(st2)) {
            return st2;
        }
        // Original 也失败 — 才报根因 (真的是无效地址 / handle 没权限)
        ULONG sev = (!NT_SUCCESS(st)) ? HV_DBGEVT_SEV_ERROR : HV_DBGEVT_SEV_WARN;
        PCSTR detail =
            (st == STATUS_DEVICE_NOT_READY) ? "Read: VtRoot disabled" :
            (st == STATUS_NOT_FOUND)        ? "Read: GVA not mapped or paged-out (Original 也失败)" :
            (st == STATUS_INVALID_ADDRESS_COMPONENT) ? "Read: GVA outside valid range" :
            (!NT_SUCCESS(st))               ? "Read: HvPhys 物理直通失败 + Original fallback 也失败" :
                                              "Read: partial (页换出截断) + Original fallback 也失败";
        HvDbgEvtPost(sev, HV_DBGEVT_CAT_READ_MEMORY, st2,
                     (ULONG)(ULONG_PTR)caller,
                     (ULONG)(ULONG_PTR)targetPid,
                     (UINT64)(ULONG_PTR)BaseAddress, BufferSize,
                     detail);
        return st2;
    }

    return st;
}

static NTSTATUS NTAPI HookedNtWriteVirtualMemory(
    HANDLE   ProcessHandle,
    PVOID    BaseAddress,
    PVOID    Buffer,
    SIZE_T   BufferSize,
    PSIZE_T  NumberOfBytesWritten
)
{
    PFN_NtWriteVirtualMemory Original =
        (PFN_NtWriteVirtualMemory)HvHookGetTrampoline(g_HookNtWriteVirtualMemory);
    if (!Original) return STATUS_UNSUCCESSFUL;

    // 2026-06-16 诊断 bypass
    if (g_BypassNtWriteVirtualMemory) {
        return Original(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesWritten);
    }

    // M3 修正: 同 NtRead — IRQL > APC_LEVEL 走 Original 避免 0xD1
    if (KeGetCurrentIrql() > APC_LEVEL) {
        return Original(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesWritten);
    }

    HANDLE caller = PsGetCurrentProcessId();
    HANDLE targetPid = HvHookpProcessHandleToProcessId(ProcessHandle);

    // Phase K 反向保护 (2026-06-16 升级到"放行+吞写"语义):
    // target = debugger && caller!=debugger && caller!=trusted →
    //   返回 SUCCESS + bytesWritten = BufferSize, 但**不实际写**任何字节。
    // 调用方以为写成功了, 但 debugger 内存毫发无伤。
    if (targetPid &&
        HvHookIsDebuggerPid(targetPid) &&
        caller != targetPid &&
        !HvHookIsDebuggerPid(caller) &&
        !HvHookIsTrustedSystemCaller(caller))
    {
        KPROCESSOR_MODE wrPrevMode = ExGetPreviousMode();
        // 用户态 Buffer 先 probe 一下, 失败按标准语义返
        __try {
            if (wrPrevMode == UserMode) {
                ProbeForRead(Buffer, BufferSize, 1);
                if (NumberOfBytesWritten) {
                    ProbeForWrite(NumberOfBytesWritten, sizeof(SIZE_T), sizeof(SIZE_T));
                }
            }
            if (NumberOfBytesWritten) {
                *NumberOfBytesWritten = BufferSize;
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return STATUS_ACCESS_VIOLATION;
        }
        HvDbgEvtPost(HV_DBGEVT_SEV_INFO, HV_DBGEVT_CAT_WRITE_MEMORY,
                     STATUS_SUCCESS,
                     (ULONG)(ULONG_PTR)caller,
                     (ULONG)(ULONG_PTR)targetPid,
                     (UINT64)(ULONG_PTR)BaseAddress, BufferSize,
                     "Write: reverse-protect spoof (silently dropped, target=debugger)");
        return STATUS_SUCCESS;
    }

    // P119: 恢复全权限语义. caller=debugger 走物理直通写, 同 NtRead.
    //   P118 误判: 真根因是 hypervisor 拦 #DB inject 路径 bug, 跟物理直通无关.
    if (!HvHookIsDebuggerPid(caller) || BufferSize == 0) {
        return Original(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesWritten);
    }

    // debugger 自写自 → Original
    if (targetPid == caller) {
        return Original(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesWritten);
    }

    // 解 handle 失败 → Original
    if (!targetPid) {
        return Original(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesWritten);
    }

    // PID=4 (System) 例外: 写 kernel VA 极易 BSOD, 回退 Original 让 Windows 自然返 ACCESS_DENIED
    if ((ULONG_PTR)targetPid == 4) {
        HvDbgEvtPost(HV_DBGEVT_SEV_WARN, HV_DBGEVT_CAT_WRITE_MEMORY,
                     STATUS_ACCESS_DENIED,
                     (ULONG)(ULONG_PTR)caller, 4,
                     (UINT64)(ULONG_PTR)BaseAddress, BufferSize,
                     "Write: target=System(4) blocked (kernel VA write 易 BSOD)");
        return Original(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesWritten);
    }

    SIZE_T done = 0;
    NTSTATUS st = STATUS_SUCCESS;
    KPROCESSOR_MODE prevMode = ExGetPreviousMode();

    __try {
        if (prevMode == UserMode) {
            ProbeForRead(Buffer, BufferSize, 1);
            if (NumberOfBytesWritten) {
                ProbeForWrite(NumberOfBytesWritten, sizeof(SIZE_T), sizeof(SIZE_T));
            }
        }
        st = HvPhysWriteProcessMemory(
            (ULONG)(ULONG_PTR)targetPid,
            (UINT64)(ULONG_PTR)BaseAddress,
            Buffer, BufferSize, &done);
        if (NumberOfBytesWritten) {
            *NumberOfBytesWritten = done;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        HvDbgEvtPost(HV_DBGEVT_SEV_ERROR, HV_DBGEVT_CAT_WRITE_MEMORY,
                     STATUS_ACCESS_VIOLATION,
                     (ULONG)(ULONG_PTR)caller,
                     (ULONG)(ULONG_PTR)targetPid,
                     (UINT64)(ULONG_PTR)BaseAddress, BufferSize,
                     "Write: user buffer probe failed (#PF in __try)");
        return STATUS_ACCESS_VIOLATION;
    }

    if (!NT_SUCCESS(st) || done < BufferSize) {
        // P120: 物理直通失败 fallback Original (见 NtRead 同位置注释)
        NTSTATUS st2 = Original(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesWritten);
        if (NT_SUCCESS(st2)) {
            return st2;
        }
        ULONG sev = (!NT_SUCCESS(st)) ? HV_DBGEVT_SEV_ERROR : HV_DBGEVT_SEV_WARN;
        PCSTR detail =
            (st == STATUS_DEVICE_NOT_READY) ? "Write: VtRoot disabled" :
            (st == STATUS_NOT_FOUND)        ? "Write: GVA not mapped or paged-out (Original 也失败)" :
            (st == STATUS_INVALID_ADDRESS_COMPONENT) ? "Write: GVA outside valid range" :
            (!NT_SUCCESS(st))               ? "Write: HvPhys 物理直通失败 + Original fallback 也失败" :
                                              "Write: partial (页换出截断) + Original fallback 也失败";
        HvDbgEvtPost(sev, HV_DBGEVT_CAT_WRITE_MEMORY, st2,
                     (ULONG)(ULONG_PTR)caller,
                     (ULONG)(ULONG_PTR)targetPid,
                     (UINT64)(ULONG_PTR)BaseAddress, BufferSize,
                     detail);
        return st2;
    }

    return st;
}

// ============================================================
// 2026-06-18 [R3 内存保护补强]
// 5 个 syscall hook 堵反作弊绕过 NtRead/NtOpenProcess 的常见路径
// ============================================================

// --- 1. NtReadVirtualMemoryEx (Win11 新 syscall, 完全绕过 NtRead hook) ---
//
// 签名: 同 NtReadVirtualMemory 多一个 Flags. Win11 21H2+ 提供.
typedef NTSTATUS (NTAPI *PFN_NtReadVirtualMemoryEx)(
    HANDLE   ProcessHandle,
    PVOID    BaseAddress,
    PVOID    Buffer,
    SIZE_T   BufferSize,
    PSIZE_T  NumberOfBytesRead,
    ULONG    Flags);

static NTSTATUS NTAPI HookedNtReadVirtualMemoryEx(
    HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer,
    SIZE_T BufferSize, PSIZE_T NumberOfBytesRead, ULONG Flags)
{
    PFN_NtReadVirtualMemoryEx Original =
        (PFN_NtReadVirtualMemoryEx)HvHookGetTrampoline(g_HookNtReadVirtualMemoryEx);
    if (!Original) return STATUS_UNSUCCESSFUL;

    if (KeGetCurrentIrql() > APC_LEVEL) {
        return Original(ProcessHandle, BaseAddress, Buffer, BufferSize,
                        NumberOfBytesRead, Flags);
    }

    HANDLE caller = PsGetCurrentProcessId();
    if (HvHookIsDebuggerPid(caller)) {
        // debugger 自己 → 透传 (业务自检读自己)
        return Original(ProcessHandle, BaseAddress, Buffer, BufferSize,
                        NumberOfBytesRead, Flags);
    }
    if (ProcessHandle == (HANDLE)(LONG_PTR)-1) {
        return Original(ProcessHandle, BaseAddress, Buffer, BufferSize,
                        NumberOfBytesRead, Flags);
    }
    HANDLE tgt = HvHookpProcessHandleToProcessId(ProcessHandle);
    if (!tgt || !HvHookIsDebuggerPid(tgt) || HvHookIsTrustedSystemCaller(caller)) {
        return Original(ProcessHandle, BaseAddress, Buffer, BufferSize,
                        NumberOfBytesRead, Flags);
    }

    // target=debugger, caller=外部 → 喂 0
    KPROCESSOR_MODE prevMode = ExGetPreviousMode();
    __try {
        if (prevMode == UserMode) {
            ProbeForWrite(Buffer, BufferSize, 1);
            if (NumberOfBytesRead) ProbeForWrite(NumberOfBytesRead, sizeof(SIZE_T), sizeof(SIZE_T));
        }
        RtlZeroMemory(Buffer, BufferSize);
        if (NumberOfBytesRead) *NumberOfBytesRead = BufferSize;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return STATUS_ACCESS_VIOLATION;
    }
    HV_HOT_DBG("[HvHook-Spoof] NtReadVirtualMemoryEx: caller=%u target=%u "
             "VA=0x%p size=%llu → zero-fill\n",
             (ULONG)(ULONG_PTR)caller, (ULONG)(ULONG_PTR)tgt,
             BaseAddress, (ULONG64)BufferSize);
    return STATUS_SUCCESS;
}

// --- 2/3/4. NtCreateSection / NtMapViewOfSection / NtMapViewOfSectionEx ---
//
// 反作弊套路:
//   1. OpenProcess(debugger, ALL_ACCESS)  - NtOpenProcess 我们放行
//   2. NtCreateSection 创建命名 section
//   3. NtMapViewOfSection 把 debugger 进程的物理页映射进自己 → 读 → 不走 NtRead
//
// 拦截策略:
//   - NtCreateSection 透传 (section 本身无害,关键看映射目标)
//   - NtMapViewOfSection(ProcessHandle=debugger) 检查:
//     * caller=debugger/trusted → 透传
//     * caller=外部 → 返 STATUS_ACCESS_DENIED 或更隐蔽: 返 STATUS_NOT_MAPPED_VIEW
//       (反作弊以为没 section 内容,自动跳过)

typedef NTSTATUS (NTAPI *PFN_NtMapViewOfSection)(
    HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress,
    ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize, ULONG InheritDisposition, ULONG AllocationType,
    ULONG Win32Protect);

static NTSTATUS NTAPI HookedNtMapViewOfSection(
    HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress,
    ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize, ULONG InheritDisposition, ULONG AllocationType,
    ULONG Win32Protect)
{
    PFN_NtMapViewOfSection Original =
        (PFN_NtMapViewOfSection)HvHookGetTrampoline(g_HookNtMapViewOfSection);
    if (!Original) return STATUS_UNSUCCESSFUL;

    if (KeGetCurrentIrql() > APC_LEVEL) {
        return Original(SectionHandle, ProcessHandle, BaseAddress, ZeroBits,
                        CommitSize, SectionOffset, ViewSize, InheritDisposition,
                        AllocationType, Win32Protect);
    }

    HANDLE caller = PsGetCurrentProcessId();
    if (HvHookIsDebuggerPid(caller) || HvHookIsTrustedSystemCaller(caller)) {
        return Original(SectionHandle, ProcessHandle, BaseAddress, ZeroBits,
                        CommitSize, SectionOffset, ViewSize, InheritDisposition,
                        AllocationType, Win32Protect);
    }
    // ProcessHandle = -1 (self) → 透传 (caller 自己映, 不涉 debugger)
    if (ProcessHandle == (HANDLE)(LONG_PTR)-1) {
        return Original(SectionHandle, ProcessHandle, BaseAddress, ZeroBits,
                        CommitSize, SectionOffset, ViewSize, InheritDisposition,
                        AllocationType, Win32Protect);
    }
    HANDLE tgt = HvHookpProcessHandleToProcessId(ProcessHandle);
    if (!tgt || !HvHookIsDebuggerPid(tgt)) {
        return Original(SectionHandle, ProcessHandle, BaseAddress, ZeroBits,
                        CommitSize, SectionOffset, ViewSize, InheritDisposition,
                        AllocationType, Win32Protect);
    }

    // caller=外部 + target=debugger → 拒绝
    HV_HOT_DBG("[HvHook-Spoof] NtMapViewOfSection blocked: caller=%u target=%u "
             "(reverse-protect)\n",
             (ULONG)(ULONG_PTR)caller, (ULONG)(ULONG_PTR)tgt);
    return STATUS_ACCESS_DENIED;
}

// NtMapViewOfSectionEx (Win10 1903+):
//   NTSTATUS NtMapViewOfSectionEx(
//       HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress,
//       PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, ULONG AllocationType,
//       ULONG PageProtection, PVOID Parameters);
typedef NTSTATUS (NTAPI *PFN_NtMapViewOfSectionEx)(
    HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress,
    PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, ULONG AllocationType,
    ULONG PageProtection, PVOID Parameters);

static NTSTATUS NTAPI HookedNtMapViewOfSectionEx(
    HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress,
    PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, ULONG AllocationType,
    ULONG PageProtection, PVOID Parameters)
{
    PFN_NtMapViewOfSectionEx Original =
        (PFN_NtMapViewOfSectionEx)HvHookGetTrampoline(g_HookNtMapViewOfSectionEx);
    if (!Original) return STATUS_UNSUCCESSFUL;

    if (KeGetCurrentIrql() > APC_LEVEL) {
        return Original(SectionHandle, ProcessHandle, BaseAddress,
                        SectionOffset, ViewSize, AllocationType,
                        PageProtection, Parameters);
    }

    HANDLE caller = PsGetCurrentProcessId();
    if (HvHookIsDebuggerPid(caller) || HvHookIsTrustedSystemCaller(caller)) {
        return Original(SectionHandle, ProcessHandle, BaseAddress,
                        SectionOffset, ViewSize, AllocationType,
                        PageProtection, Parameters);
    }
    if (ProcessHandle == (HANDLE)(LONG_PTR)-1) {
        return Original(SectionHandle, ProcessHandle, BaseAddress,
                        SectionOffset, ViewSize, AllocationType,
                        PageProtection, Parameters);
    }
    HANDLE tgt = HvHookpProcessHandleToProcessId(ProcessHandle);
    if (!tgt || !HvHookIsDebuggerPid(tgt)) {
        return Original(SectionHandle, ProcessHandle, BaseAddress,
                        SectionOffset, ViewSize, AllocationType,
                        PageProtection, Parameters);
    }

    HV_HOT_DBG("[HvHook-Spoof] NtMapViewOfSectionEx blocked: caller=%u target=%u\n",
             (ULONG)(ULONG_PTR)caller, (ULONG)(ULONG_PTR)tgt);
    return STATUS_ACCESS_DENIED;
}

// NtCreateSection - 透传 (section 创建本身无 target 概念)
//
// 为什么仍 hook: 防止反作弊用 SEC_BASED + 已知 base 创建命中 debugger 地址空间
// 的 section. 但绝大多数场景 NtCreateSection 不直接威胁, 我们就只装 hook 但仅
// 记 trace, 不改 retval. 装它是为了**未来需要时可以快速加策略**.
typedef NTSTATUS (NTAPI *PFN_NtCreateSection)(
    PHANDLE SectionHandle, ULONG DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
    PLARGE_INTEGER MaximumSize, ULONG SectionPageProtection,
    ULONG AllocationAttributes, HANDLE FileHandle);

static NTSTATUS NTAPI HookedNtCreateSection(
    PHANDLE SectionHandle, ULONG DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
    PLARGE_INTEGER MaximumSize, ULONG SectionPageProtection,
    ULONG AllocationAttributes, HANDLE FileHandle)
{
    PFN_NtCreateSection Original =
        (PFN_NtCreateSection)HvHookGetTrampoline(g_HookNtCreateSection);
    if (!Original) return STATUS_UNSUCCESSFUL;
    // 透传 (留位; 真正拦在 NtMapViewOfSection)
    return Original(SectionHandle, DesiredAccess, ObjectAttributes,
                    MaximumSize, SectionPageProtection,
                    AllocationAttributes, FileHandle);
}

// --- 5. NtCreateThreadEx (跨进程远程线程) ---
//
// 反作弊套路: 在 debugger 进程里跑 stub 代码做完整性自检.
// 拦截策略: caller=外部 + target=debugger → 拒绝.
//
// signature (内核侧):
//   NTSTATUS NtCreateThreadEx(
//       PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess,
//       POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle,
//       PVOID StartRoutine, PVOID Argument, ULONG CreateFlags,
//       SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize,
//       PPS_ATTRIBUTE_LIST AttributeList);
typedef NTSTATUS (NTAPI *PFN_NtCreateThreadEx)(
    PHANDLE ThreadHandle, ULONG DesiredAccess, PVOID ObjectAttributes,
    HANDLE ProcessHandle, PVOID StartRoutine, PVOID Argument,
    ULONG CreateFlags, SIZE_T ZeroBits, SIZE_T StackSize,
    SIZE_T MaximumStackSize, PVOID AttributeList);

static NTSTATUS NTAPI HookedNtCreateThreadEx(
    PHANDLE ThreadHandle, ULONG DesiredAccess, PVOID ObjectAttributes,
    HANDLE ProcessHandle, PVOID StartRoutine, PVOID Argument,
    ULONG CreateFlags, SIZE_T ZeroBits, SIZE_T StackSize,
    SIZE_T MaximumStackSize, PVOID AttributeList)
{
    PFN_NtCreateThreadEx Original =
        (PFN_NtCreateThreadEx)HvHookGetTrampoline(g_HookNtCreateThreadEx);
    if (!Original) return STATUS_UNSUCCESSFUL;

    if (KeGetCurrentIrql() > APC_LEVEL) {
        return Original(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle,
                        StartRoutine, Argument, CreateFlags, ZeroBits,
                        StackSize, MaximumStackSize, AttributeList);
    }

    HANDLE caller = PsGetCurrentProcessId();
    if (HvHookIsDebuggerPid(caller) || HvHookIsTrustedSystemCaller(caller)) {
        return Original(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle,
                        StartRoutine, Argument, CreateFlags, ZeroBits,
                        StackSize, MaximumStackSize, AttributeList);
    }
    // ProcessHandle=-1 → caller 自己进程创建线程, 不涉 debugger
    if (ProcessHandle == (HANDLE)(LONG_PTR)-1) {
        return Original(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle,
                        StartRoutine, Argument, CreateFlags, ZeroBits,
                        StackSize, MaximumStackSize, AttributeList);
    }
    HANDLE tgt = HvHookpProcessHandleToProcessId(ProcessHandle);
    if (!tgt || !HvHookIsDebuggerPid(tgt)) {
        return Original(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle,
                        StartRoutine, Argument, CreateFlags, ZeroBits,
                        StackSize, MaximumStackSize, AttributeList);
    }

    // caller=外部 + target=debugger 远程线程注入 → 拒绝
    HV_HOT_DBG("[HvHook-Spoof] NtCreateThreadEx blocked: caller=%u target=%u "
             "(remote-thread-injection-blocked)\n",
             (ULONG)(ULONG_PTR)caller, (ULONG)(ULONG_PTR)tgt);
    return STATUS_ACCESS_DENIED;
}

// ============================================================
// P106 (2026-06-22): 线程访问/控制 proxy
// 反作弊在 NtSuspendThread / NtOpenThread / NtGetContextThread 入口装 hook
// 拦内置调试器. 我们装在更前 (HvHookInstall 拿到的 trampoline = 原前 N 字节 + jmp 原+N),
// trusted caller 走 trampoline 直接跳过反作弊入口检查.
// ============================================================

typedef NTSTATUS (NTAPI *PFN_NtSuspendThread)(HANDLE ThreadHandle, PULONG PreviousSuspendCount);
typedef NTSTATUS (NTAPI *PFN_NtResumeThread)(HANDLE ThreadHandle, PULONG PreviousSuspendCount);
typedef NTSTATUS (NTAPI *PFN_NtOpenThread)(
    PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes, PVOID ClientId);
typedef NTSTATUS (NTAPI *PFN_NtGetContextThread)(HANDLE ThreadHandle, PVOID ThreadContext);

static NTSTATUS NTAPI HookedNtSuspendThread(
    HANDLE ThreadHandle, PULONG PreviousSuspendCount)
{
    PFN_NtSuspendThread Original =
        (PFN_NtSuspendThread)HvHookGetTrampoline(g_HookNtSuspendThread);
    if (!Original) return STATUS_UNSUCCESSFUL;

    if (g_BypassNtSuspendThread) {
        return Original(ThreadHandle, PreviousSuspendCount);
    }

    // P113: IRQL > APC_LEVEL 时 ObReferenceObjectByHandle / DbgEvtPost 不安全, 直接 passthrough.
    if (KeGetCurrentIrql() > APC_LEVEL) {
        return Original(ThreadHandle, PreviousSuspendCount);
    }

    // Trampoline 已经绕过反作弊 hook. 全部 caller 都走 trampoline.
    // 仅 debugger caller 多打条日志方便诊断.
    HANDLE caller = PsGetCurrentProcessId();
    if (HvHookIsDebuggerPid(caller)) {
        HANDLE tgt = HvHookpThreadHandleToProcessId(ThreadHandle);
        HvDbgEvtPost(HV_DBGEVT_SEV_INFO, HV_DBGEVT_CAT_DEBUGGER_OP,
                     0, (ULONG)(ULONG_PTR)caller, (ULONG)(ULONG_PTR)tgt,
                     0, 0, "NtSuspendThread proxy (debugger caller)");
    }
    return Original(ThreadHandle, PreviousSuspendCount);
}

static NTSTATUS NTAPI HookedNtResumeThread(
    HANDLE ThreadHandle, PULONG PreviousSuspendCount)
{
    PFN_NtResumeThread Original =
        (PFN_NtResumeThread)HvHookGetTrampoline(g_HookNtResumeThread);
    if (!Original) return STATUS_UNSUCCESSFUL;

    if (g_BypassNtResumeThread) {
        return Original(ThreadHandle, PreviousSuspendCount);
    }
    if (KeGetCurrentIrql() > APC_LEVEL) {
        return Original(ThreadHandle, PreviousSuspendCount);
    }

    HANDLE caller = PsGetCurrentProcessId();
    if (HvHookIsDebuggerPid(caller)) {
        HANDLE tgt = HvHookpThreadHandleToProcessId(ThreadHandle);
        HvDbgEvtPost(HV_DBGEVT_SEV_INFO, HV_DBGEVT_CAT_DEBUGGER_OP,
                     0, (ULONG)(ULONG_PTR)caller, (ULONG)(ULONG_PTR)tgt,
                     0, 0, "NtResumeThread proxy (debugger caller)");
    }
    return Original(ThreadHandle, PreviousSuspendCount);
}

static NTSTATUS NTAPI HookedNtOpenThread(
    PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes, PVOID ClientId)
{
    PFN_NtOpenThread Original =
        (PFN_NtOpenThread)HvHookGetTrampoline(g_HookNtOpenThread);
    if (!Original) return STATUS_UNSUCCESSFUL;

    if (g_BypassNtOpenThread) {
        return Original(ThreadHandle, DesiredAccess, ObjectAttributes, ClientId);
    }
    if (KeGetCurrentIrql() > APC_LEVEL) {
        return Original(ThreadHandle, DesiredAccess, ObjectAttributes, ClientId);
    }

    HANDLE caller = PsGetCurrentProcessId();
    if (HvHookIsDebuggerPid(caller)) {
        HvDbgEvtPost(HV_DBGEVT_SEV_INFO, HV_DBGEVT_CAT_DEBUGGER_OP,
                     0, (ULONG)(ULONG_PTR)caller, 0,
                     (UINT64)DesiredAccess, 0, "NtOpenThread proxy (debugger caller)");
    }
    return Original(ThreadHandle, DesiredAccess, ObjectAttributes, ClientId);
}

// P119: NtGetContextThread DR 抹零 (反反调试核心)
//
//   反作弊 (EAC/Vanguard/TP/BattlEye/网易盾 等) 标准检测:
//     周期 GetThreadContext(GetCurrentThread(), CONTEXT_DEBUG_REGISTERS) →
//     看 Dr0..3 / Dr7 != 0 就主动退.
//
//   场景: CE attach 我们保护的 target 进程 → SetThreadContext 写 DR → 反作弊
//   下一次自检读 DR 拿到非零值 → ExitProcess. 这就是"硬断触发瞬间目标闪退"
//   的真因 (其实是触发后线程被 CE handler 接管时反作弊自检线程刚好跑到).
//
//   修复: hook 走到这里 caller=target=self-query 时, 把 CONTEXT 里的
//   ContextFlags 保留, Dr0..3 / Dr6 / Dr7 抹零返回. CE 自己读时把 caller
//   判断走另一条路 (caller=CE, target=游戏 — 仍走 Original 返真值给 CE).
static NTSTATUS NTAPI HookedNtGetContextThread(
    HANDLE ThreadHandle, PVOID ThreadContext)
{
    PFN_NtGetContextThread Original =
        (PFN_NtGetContextThread)HvHookGetTrampoline(g_HookNtGetContextThread);
    if (!Original) return STATUS_UNSUCCESSFUL;

    if (g_BypassNtGetContextThread) {
        return Original(ThreadHandle, ThreadContext);
    }
    if (KeGetCurrentIrql() > APC_LEVEL) {
        return Original(ThreadHandle, ThreadContext);
    }

    NTSTATUS s = Original(ThreadHandle, ThreadContext);
    if (!NT_SUCCESS(s) || !ThreadContext) return s;

    HANDLE caller = PsGetCurrentProcessId();
    HANDLE targetPid = HvHookpThreadHandleToProcessId(ThreadHandle);

    // caller 是 debugger → P128: 用 vwatch 表重组虚拟 DR 填回 CONTEXT.
    //   硬件 DR 一直 0 (我们没真写), 但 CE 需要看到自己设过的 DR 值,
    //   否则它会以为没下断点 → 重设循环.
    if (HvHookIsDebuggerPid(caller)) {
        if (targetPid) {
            HvDbgEvtPost(HV_DBGEVT_SEV_INFO, HV_DBGEVT_CAT_DEBUGGER_OP,
                         0, (ULONG)(ULONG_PTR)caller, (ULONG)(ULONG_PTR)targetPid,
                         0, 0, "NtGetContextThread proxy (debugger caller)");

            // 用 HvVwatchBuildVirtualDrState 拿虚拟 DR 状态, 填进 CONTEXT
            UINT64 vDr0 = 0, vDr1 = 0, vDr2 = 0, vDr3 = 0, vDr7 = 0;
            BOOLEAN haveWatches = HvVwatchBuildVirtualDrState(
                targetPid, &vDr0, &vDr1, &vDr2, &vDr3, &vDr7);
            if (haveWatches) {
                KPROCESSOR_MODE prevModeDbg = ExGetPreviousMode();
                __try {
                    if (prevModeDbg == UserMode) {
                        ProbeForWrite(ThreadContext, HV_CTX_OFF_DR7 + 8, sizeof(ULONG));
                    }
                    UCHAR* base = (UCHAR*)ThreadContext;
                    ULONG flags = *(ULONG*)(base + HV_CTX_OFF_FLAGS);
                    if (flags & HV_CONTEXT_DEBUG_REGISTERS) {
                        *(UINT64*)(base + HV_CTX_OFF_DR0) = vDr0;
                        *(UINT64*)(base + HV_CTX_OFF_DR1) = vDr1;
                        *(UINT64*)(base + HV_CTX_OFF_DR2) = vDr2;
                        *(UINT64*)(base + HV_CTX_OFF_DR3) = vDr3;
                        *(UINT64*)(base + HV_CTX_OFF_DR6) = 0;
                        *(UINT64*)(base + HV_CTX_OFF_DR7) = vDr7;
                    }
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    // probe 失败保持 Original 返回的真零 DR — CE 可能不开心但不崩
                }
            }
        }
        return s;
    }

    // caller != target → 跨进程查别人, 跟反反调试无关 (反作弊查自己), 也不抹
    if (caller != targetPid) {
        return s;
    }

    // 自查 (caller=target). 看 CONTEXT.ContextFlags 是否含 DEBUG_REGISTERS
    // (CONTEXT_AMD64 位 0x10), 含则抹零 Dr0..3 / Dr6 / Dr7
    KPROCESSOR_MODE prevMode = ExGetPreviousMode();
    __try {
        if (prevMode == UserMode) {
            ProbeForWrite(ThreadContext, HV_CTX_OFF_DR7 + 8, sizeof(ULONG));
        }
        UCHAR* base = (UCHAR*)ThreadContext;
        ULONG flags = *(ULONG*)(base + HV_CTX_OFF_FLAGS);
        if (flags & HV_CONTEXT_DEBUG_REGISTERS) {
            *(UINT64*)(base + HV_CTX_OFF_DR0) = 0;
            *(UINT64*)(base + HV_CTX_OFF_DR1) = 0;
            *(UINT64*)(base + HV_CTX_OFF_DR2) = 0;
            *(UINT64*)(base + HV_CTX_OFF_DR3) = 0;
            *(UINT64*)(base + HV_CTX_OFF_DR6) = 0;
            *(UINT64*)(base + HV_CTX_OFF_DR7) = 0;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        // probe 失败保留原值, 反作弊该退退该崩崩, 不让 driver 自己崩
    }
    return s;
}

// ============================================================
// P121: NtDebugActiveProcess hook — 抹 PEB.BeingDebugged + NtGlobalFlag
// ============================================================
//
// 反作弊周期读自己 PEB 看 BeingDebugged / NtGlobalFlag, 看到非 0 就退.
// 这两个是 user-mode memory, syscall hook 拦不到读. driver 必须主动写.
//
// CE 调 DebugActiveProcess → 内核 NtDebugActiveProcess → DbgkpSetProcessDebugObject:
//   - 设 EPROCESS.DebugPort
//   - 设 PEB.BeingDebugged = 1
//   - 或 PEB.NtGlobalFlag |= 0x70 (取决于 Win 版本)
//
// 我们 hook NtDebugActiveProcess:
//   1) 调 Original (让 DebugActiveProcess 真正建立 debug 关系 — CE 需要这个)
//   2) Original SUCCESS 后, KeStackAttachProcess 进 target, 把 PEB 那两个字段抹零
//
// 时序: CE attach 完到反作弊下次读 PEB 之间, 我们已经抹了, 反作弊永远看不到 1.
//
// PEB 偏移 (x64):
//   +0x002  BeingDebugged (UCHAR)
//   +0x068  NtGlobalFlag (ULONG)

#define HV_PEB_OFF_BEING_DEBUGGED   0x002
#define HV_PEB_OFF_NT_GLOBAL_FLAG   0x068
#define HV_NT_GLOBAL_FLAG_DBG_MASK  0x70   // HEAP_ENABLE_TAIL_CHECK | VALIDATE_PARAMS | FREE_CHECK

typedef NTSTATUS (NTAPI *PFN_NtDebugActiveProcess)(
    HANDLE ProcessHandle,
    HANDLE DebugObjectHandle);

// P125: NtDebugActiveProcess hook → 注册 EPT PEB cloak (取代 ring0 直写 PEB)
//
//   背景:
//     P121-P124 走 ring0 KeStackAttachProcess + 直写 PEB byte 失败. 反作弊在
//     PEB 关键 byte 上有 VirtualProtect/HWBP/page guard, ring0 写直接触发 trap.
//     即便 200ms 延迟也只是把窗口往后推, 不解决问题.
//
//   P125 解决方案:
//     使用 EPT 字段级 spoof. 不动 target PEB 真页, 改在 EPT 上给 target user CR3
//     单独绑一份 EptPebSpoof, PEB 页 R=0 强制 violation, handler 喂回去一份补丁
//     页 (原内容 + 3 字段被 0). target 任何代码读 PEB 都看到 spoof, 写 PEB 真值,
//     反作弊 memory guard 永远不触发 (我们从未写过那个真页).
//
//     work item 异步注册不阻塞 hook 体 (避免 DbgkpSetProcessDebugObject 内部
//     初始事件流被打断 → CE WaitForDebugEvent 卡死), 同时 PASSIVE 上下文调
//     HvVtRootGetResolvedUserCr3 + HvPhysGvaToHpa 走 KVAS-safe 路径.

typedef struct _HV_PEB_CLOAK_REG_CTX {
    WORK_QUEUE_ITEM WorkItem;
    HANDLE          TargetPid;
} HV_PEB_CLOAK_REG_CTX, *PHV_PEB_CLOAK_REG_CTX;

static VOID HvHookpPebCloakRegisterWorker(_In_ PVOID Context)
{
    PHV_PEB_CLOAK_REG_CTX ctx = (PHV_PEB_CLOAK_REG_CTX)Context;
    if (!ctx) return;
    HANDLE targetPid = ctx->TargetPid;

    // worker NO-OP (用户上次确认无 attach-wait 对话框)
    DbgPrint("[HvHook-AAD] worker NO-OP: target=%u\n",
             (ULONG)(ULONG_PTR)targetPid);

    ExFreePoolWithTag(ctx, 'HwAD');
}

static NTSTATUS NTAPI HookedNtDebugActiveProcess(
    HANDLE ProcessHandle,
    HANDLE DebugObjectHandle)
{
    PFN_NtDebugActiveProcess Original =
        (PFN_NtDebugActiveProcess)HvHookGetTrampoline(g_HookNtDebugActiveProcess);
    if (!Original) return STATUS_UNSUCCESSFUL;

    NTSTATUS s = Original(ProcessHandle, DebugObjectHandle);
    if (!NT_SUCCESS(s)) return s;

    if (KeGetCurrentIrql() > APC_LEVEL) return s;
    if (ExGetPreviousMode() == KernelMode) return s;
    HANDLE caller = PsGetCurrentProcessId();
    if (HvHookIsTrustedSystemCaller(caller)) return s;
    if (!HvHookIsDebuggerPid(caller)) return s;

    PEPROCESS tmpProc = NULL;
    NTSTATUS lk = ObReferenceObjectByHandle(
        ProcessHandle, 0, *PsProcessType, KernelMode, (PVOID*)&tmpProc, NULL);
    if (!NT_SUCCESS(lk) || !tmpProc) return s;
    HANDLE targetPid = PsGetProcessId(tmpProc);
    ObDereferenceObject(tmpProc);
    if (!targetPid) return s;

    // 异步注册: 走 work item, hook 体立即返回不阻塞 DbgkpSetProcessDebugObject
    // 内部初始事件流 (否则 CE WaitForDebugEvent 卡死).
    // worker 在 PASSIVE 上下文跑直写 PEB + cloak schedule.
    PHV_PEB_CLOAK_REG_CTX ctx = (PHV_PEB_CLOAK_REG_CTX)
        ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(HV_PEB_CLOAK_REG_CTX), 'HwAD');
    if (!ctx) return s;
    ctx->TargetPid = targetPid;
    ExInitializeWorkItem(&ctx->WorkItem, HvHookpPebCloakRegisterWorker, ctx);
    ExQueueWorkItem(&ctx->WorkItem, DelayedWorkQueue);

    DbgPrint("[HvHook-AAD] NtDebugActiveProcess: target=%u caller=%u — worker scheduled\n",
             (ULONG)(ULONG_PTR)targetPid,
             (ULONG)(ULONG_PTR)caller);
    return s;
}

// ============================================================
// Phase L6 (2026-06-04): SSDT-based syscall resolver
// ============================================================
//
// 解决 Win10 19045 ntoskrnl 不导出 NtReadVirtualMemory / NtWriteVirtualMemory /
// NtSetContextThread 名字的问题。MmGetSystemRoutineAddress / EAT walk / NTSYSAPI
// extern (LNK) 全部失败 (Phase L1-L5 验证)。
//
// 链路:
//   __readmsr(0xC0000082)         拿 LSTAR = KiSystemCall64
//   pattern scan lea r10/r11      找 KeServiceDescriptorTable 基址
//   HvPhysEnumerateModules        找 caller 进程的 ntdll
//   HvPhysReadProcessMemory       读 ntdll PE EAT 找 NtReadVirtualMemory 函数 RVA
//   HvPhysReadProcessMemory       读该函数头 8 字节 stub: 4C 8B D1 B8 XX XX XX XX
//                                 提取 mov eax 立即数 = syscall index
//   SSDT[index] decode            (encoded >> 4) + ServiceTableBase = 真内核地址
//
// 跨 Win 版本通用,不依赖编译时符号。

typedef struct _HV_KE_SERVICE_DESCRIPTOR_TABLE {
    PVOID  ServiceTableBase;     // KiServiceTable[N] (encoded entries)
    PULONG ServiceCounterTable;  // 通常 NULL (Win 10+)
    ULONG  NumberOfServices;     // ~0x1F0 范围
    PUCHAR ParamTableBase;       // 各 service 参数计数
} HV_KE_SERVICE_DESCRIPTOR_TABLE;

static volatile PVOID g_KeServiceDescriptorTable = NULL;
static volatile PVOID g_KiServiceTableBase = NULL;
static volatile ULONG g_NumberOfServices = 0;
// L6.2: 缓存 ntoskrnl image range,用于解码地址 + 候选 SSDT 地址校验
static volatile ULONG_PTR g_NtoskrnlBaseCached = 0;
static volatile ULONG_PTR g_NtoskrnlEndCached = 0;

// 2026-06-17 win32k SSDT (Shadow descriptor 表) — 用于窗口枚举/查询 syscall hook
static volatile PVOID g_W32KServiceTableBase = NULL;
static volatile ULONG g_W32KNumberOfServices = 0;
// W32k image range cache (ntdll EAT 拿不到 win32k 名, 我们走另一条路: 不解码到具体
// 函数地址, 而是用 syscall index 直接劫持 SSDT entry 找内核地址)
static volatile ULONG_PTR g_W32KBaseCached = 0;
static volatile ULONG_PTR g_W32KEndCached = 0;

// L6.2: 前向声明 (实现在文件下半部 ~line 2693/2724)
static PVOID HvHookpFindNtoskrnlBase(VOID);
static NTSTATUS HvHookpFindNtoskrnlRange(_Out_ PULONG_PTR OutBase,
                                          _Out_ PULONG_PTR OutEnd);

// 缓存 syscall name → kernel addr,避免每次 hook 装载都重新解析 ntdll
typedef struct _HV_SYSCALL_CACHE {
    PCSTR  Name;
    ULONG  Index;       // 0xFFFFFFFF = 未解析过
    PVOID  KernelAddr;  // 已 SSDT decode 的实际地址,留作日志
} HV_SYSCALL_CACHE;

static HV_SYSCALL_CACHE g_SyscallCache[] = {
    { "NtReadVirtualMemory",   0xFFFFFFFF, NULL },
    { "NtWriteVirtualMemory",  0xFFFFFFFF, NULL },
    { "NtSetContextThread",    0xFFFFFFFF, NULL },
    // P121: 让 NtDebugActiveProcess 也能通过 SSDT 解析 (ntoskrnl 不导出名字)
    { "NtDebugActiveProcess",  0xFFFFFFFF, NULL },
    // P127 (2026-06-25): NtGetContextThread DR 抹零是 HWBP 反检测核心.
    //   反作弊轮询线程调 NtGetContextThread(self, CONTEXT_DEBUG_REGISTERS)
    //   看 DR0-7 是否非 0, 一旦看到我们设的硬断地址 → __fastfail 自杀
    //   (实测 DeltaForce 下 HWBP 即崩 0xC000001D ntdll).
    { "NtGetContextThread",    0xFFFFFFFF, NULL },
    // P127: NtCreateThreadEx 用于阻 anti-debug 注入 detour DLL, 顺手挂上
    { "NtCreateThreadEx",      0xFFFFFFFF, NULL },
    // P127: NtReadVirtualMemoryEx Win11 24H2+ 新 syscall
    { "NtReadVirtualMemoryEx", 0xFFFFFFFF, NULL },
    { NULL, 0, NULL },   // 哨兵
};

// L6.2: 验证一个地址看起来像合法的 syscall handler 入口
// Win10/11 syscall handler 典型函数序言:
//   48 89 5C 24 ??       mov [rsp+xx], rbx
//   48 83 EC ??          sub rsp, imm8
//   48 81 EC ?? ?? ?? ?? sub rsp, imm32
//   40 53                push rbx (REX prefix + push)
//   40 55 / 40 56 / 40 57 push rbp/rsi/rdi
//   41 54 / 41 55 / 41 56 / 41 57   push r12/r13/r14/r15
//   4C 8B DC             mov r11, rsp (frame setup)
//   48 8B C4             mov rax, rsp (frame setup)
// 校验前 4 字节匹配以上之一 → 合法函数入口
static BOOLEAN HvHookpLooksLikeFunctionEntry(_In_ PVOID Addr)
{
    UCHAR head[16];
    __try {
        RtlCopyMemory(head, Addr, sizeof(head));
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }

    // 单字节 push (REX prefix 形式 0x40-0x47 + 0x50-0x5F push opcode)
    // 实际是 REX.W=0 prefix (0x40+) + 50/51/.../57 push reg64
    if ((head[0] == 0x40 || head[0] == 0x41) &&
        (head[1] >= 0x50 && head[1] <= 0x57)) return TRUE;

    // sub rsp, imm8: 48 83 EC XX
    if (head[0] == 0x48 && head[1] == 0x83 && head[2] == 0xEC) return TRUE;

    // sub rsp, imm32: 48 81 EC XX XX XX XX
    if (head[0] == 0x48 && head[1] == 0x81 && head[2] == 0xEC) return TRUE;

    // mov [rsp+xx], rbx: 48 89 5C 24 XX
    if (head[0] == 0x48 && head[1] == 0x89 && head[2] == 0x5C && head[3] == 0x24) return TRUE;

    // mov [rsp+xx], rdi: 48 89 7C 24 XX
    if (head[0] == 0x48 && head[1] == 0x89 && head[2] == 0x7C && head[3] == 0x24) return TRUE;

    // mov [rsp+xx], rsi: 48 89 74 24 XX
    if (head[0] == 0x48 && head[1] == 0x89 && head[2] == 0x74 && head[3] == 0x24) return TRUE;

    // mov rax, rsp: 48 8B C4
    if (head[0] == 0x48 && head[1] == 0x8B && head[2] == 0xC4) return TRUE;

    // mov r11, rsp: 4C 8B DC
    if (head[0] == 0x4C && head[1] == 0x8B && head[2] == 0xDC) return TRUE;

    // jmp rel32 (有时 syscall handler 是 thunk 跳到真函数): E9 XX XX XX XX
    if (head[0] == 0xE9) return TRUE;

    return FALSE;
}

// 1. 解析 KeServiceDescriptorTable 基址
//    LSTAR -> KiSystemCall64 -> pattern scan lea r10/r11, [rip+disp32]
//    L6.2 严化: 多层校验
//      a. ssdtAddr 必须在 ntoskrnl image range 内
//      b. ServiceTableBase 必须在 ntoskrnl range 内
//      c. ServiceCounterTable 必须 NULL (Win10/11 恒为 NULL)
//      d. NumberOfServices 在 0x100..0x500
//      e. ParamTableBase 必须在 ntoskrnl range 内 (它紧跟 ServiceTableBase 后,
//         一般也是 ntoskrnl 内的 const 数组)
static NTSTATUS HvHookpResolveSsdtBase(VOID)
{
    if (g_KiServiceTableBase) return STATUS_SUCCESS;   // 已缓存

    DbgPrint("[HvHook] M3.6 SSDT step 1: enter HvHookpResolveSsdtBase, IRQL=%u\n",
             KeGetCurrentIrql());

    // 拿 ntoskrnl image range,所有 SSDT 候选地址必须落在这里
    ULONG_PTR ntosBase = 0, ntosEnd = 0;
    DbgPrint("[HvHook] M3.6 SSDT step 2: about to call HvHookpFindNtoskrnlRange\n");
    NTSTATUS rs = HvHookpFindNtoskrnlRange(&ntosBase, &ntosEnd);
    DbgPrint("[HvHook] M3.6 SSDT step 3: HvHookpFindNtoskrnlRange returned 0x%X base=%p end=%p\n",
             rs, (PVOID)ntosBase, (PVOID)ntosEnd);
    if (!NT_SUCCESS(rs) || ntosBase == 0 || ntosEnd <= ntosBase) {
        return STATUS_NOT_FOUND;
    }

    DbgPrint("[HvHook] M3.6 SSDT step 4: about to read LSTAR MSR\n");
    ULONG64 lstar = __readmsr(0xC0000082);
    DbgPrint("[HvHook] M3.6 SSDT step 5: LSTAR = %p\n", (PVOID)lstar);
    if (!lstar) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    // KiSystemCall64Shadow 模式: 0F 01 F8 swapgs + ~80 字节 CR3/RSP 切换 + 真函数
    // M3.6 嫌疑点:此处 RtlCopyMemory 读 LSTAR 0x800 字节,可能命中 paged section
    UCHAR head[0x800];
    DbgPrint("[HvHook] M3.6 SSDT step 6: about to read 0x800 bytes from LSTAR (THIS MAY BE BSOD POINT)\n");
    __try {
        RtlCopyMemory(head, (PVOID)lstar, sizeof(head));
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[HvHook] M3.6 SSDT step 6 FAULT: read KiSystemCall64 failed\n");
        return STATUS_ACCESS_VIOLATION;
    }
    DbgPrint("[HvHook] M3.6 SSDT step 7: LSTAR read OK, first 8 bytes: "
             "%02X %02X %02X %02X %02X %02X %02X %02X\n",
             head[0], head[1], head[2], head[3], head[4], head[5], head[6], head[7]);

    // 在前 0x800 字节扫 lea r10/r11, [rip+disp32]
    DbgPrint("[HvHook] M3.6 SSDT step 8: starting pattern scan\n");
    for (ULONG i = 0; i < sizeof(head) - 7; i++) {
        BOOLEAN isLeaR10 = (head[i] == 0x4C && head[i+1] == 0x8D && head[i+2] == 0x15);
        BOOLEAN isLeaR11 = (head[i] == 0x4C && head[i+1] == 0x8D && head[i+2] == 0x1D);
        if (!isLeaR10 && !isLeaR11) continue;

        LONG disp32 = *(LONG*)(head + i + 3);
        ULONG_PTR ripNext = (ULONG_PTR)lstar + i + 7;
        ULONG_PTR ssdtAddr = ripNext + disp32;

        // L6.2 校验 a: ssdtAddr 必须在 ntoskrnl image range 内
        if (ssdtAddr < ntosBase || ssdtAddr >= ntosEnd) continue;

        DbgPrint("[HvHook] M3.6 SSDT step 9 (i=%u): candidate ssdtAddr=%p (in ntoskrnl range), "
                 "about to RtlCopyMemory candidate (THIS MAY BE BSOD POINT)\n",
                 i, (PVOID)ssdtAddr);

        HV_KE_SERVICE_DESCRIPTOR_TABLE candidate;
        __try {
            RtlCopyMemory(&candidate, (PVOID)ssdtAddr, sizeof(candidate));
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            DbgPrint("[HvHook] M3.6 SSDT step 9 FAULT at ssdtAddr=%p\n", (PVOID)ssdtAddr);
            continue;
        }
        DbgPrint("[HvHook] M3.6 SSDT step 10: candidate read OK ServiceTableBase=%p "
                 "Counter=%p NumServices=%u ParamTableBase=%p\n",
                 candidate.ServiceTableBase, candidate.ServiceCounterTable,
                 candidate.NumberOfServices, candidate.ParamTableBase);

        // L6.2 校验 b: ServiceTableBase 必须在 ntoskrnl range
        ULONG_PTR svcBase = (ULONG_PTR)candidate.ServiceTableBase;
        if (svcBase < ntosBase || svcBase >= ntosEnd) continue;

        // L6.2 校验 c: ServiceCounterTable 必须 NULL (Win10/11 恒为 NULL,
        // checked build 才非 NULL,production 永不命中)
        if (candidate.ServiceCounterTable != NULL) continue;

        // L6.2 校验 d: NumberOfServices 在合理范围
        if (candidate.NumberOfServices < 0x100 || candidate.NumberOfServices > 0x500) continue;

        // L6.2 校验 e: ParamTableBase 必须在 ntoskrnl range
        ULONG_PTR paramBase = (ULONG_PTR)candidate.ParamTableBase;
        if (paramBase < ntosBase || paramBase >= ntosEnd) continue;

        // 5 项校验全过
        g_KeServiceDescriptorTable = (PVOID)ssdtAddr;
        g_KiServiceTableBase = candidate.ServiceTableBase;
        g_NumberOfServices = candidate.NumberOfServices;
        g_NtoskrnlBaseCached = ntosBase;
        g_NtoskrnlEndCached = ntosEnd;
        DbgPrint("[HvHook] L6: SSDT @ %p ServiceTableBase=%p NumServices=%u "
                 "ParamTableBase=%p ntoskrnl=[%p,%p) (offset %u in KiSystemCall64)\n",
                 g_KeServiceDescriptorTable, g_KiServiceTableBase,
                 g_NumberOfServices, candidate.ParamTableBase,
                 (PVOID)ntosBase, (PVOID)ntosEnd, i);
        return STATUS_SUCCESS;
    }

    DbgPrint("[HvHook] L6: SSDT pattern scan failed in KiSystemCall64 @ %p (first 32 bytes: %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X)\n",
             (PVOID)lstar,
             head[0], head[1], head[2], head[3], head[4], head[5], head[6], head[7],
             head[8], head[9], head[10], head[11], head[12], head[13], head[14], head[15],
             head[16], head[17], head[18], head[19], head[20], head[21], head[22], head[23],
             head[24], head[25], head[26], head[27], head[28], head[29], head[30], head[31]);
    return STATUS_NOT_FOUND;
}

// ============================================================
// 2026-06-17: Win32k Shadow SSDT 解析
// ============================================================
//
// KeServiceDescriptorTableShadow 是 4 个 SERVICE_DESCRIPTOR_TABLE 紧挨着的数组:
//   [0] = ntoskrnl SSDT (已被 HvHookpResolveSsdtBase 命中)
//   [1] = win32k SSDT
// 我们在 KiSystemCall64 路径中再扫一次 lea r10/r11, [rip+disp32], 取**第二个**
// 不同的 SSDT 描述符地址。win32k SSDT 的 NumServices ~0x500-0xC00, 介于
// ntoskrnl 范围之外。它的 ServiceTableBase 不在 ntoskrnl image range, 而在
// win32kbase.sys / win32kfull.sys range。
static NTSTATUS HvHookpResolveW32KSsdtBase(VOID)
{
    if (g_W32KServiceTableBase) return STATUS_SUCCESS;
    // 先确保 ntoskrnl SSDT 解析成功 (用它的 SSDT 地址做参照)
    NTSTATUS rs = HvHookpResolveSsdtBase();
    if (!NT_SUCCESS(rs)) return rs;

    ULONG_PTR ntosBase = g_NtoskrnlBaseCached;
    ULONG_PTR ntosEnd  = g_NtoskrnlEndCached;
    if (!ntosBase || !ntosEnd) return STATUS_INVALID_DEVICE_STATE;

    // 2026-06-17 全 ntoskrnl 扫描: 找一个符合 win32k SSDT descriptor 特征的地址。
    //
    // Win11 24H2 上 KeServiceDescriptorTableShadow 不一定紧跟 Table, 可能在 .data
    // section 别处。扫描完整 ntoskrnl image (大约 20-30 MB), 步长 8 字节 (描述符对齐),
    // 按以下特征筛选:
    //   - ServiceTableBase 8-byte 对齐, 非 NULL, 不在 ntoskrnl range (而在 win32kbase)
    //   - ServiceCounterTable = NULL
    //   - NumberOfServices 在 0x300..0xC00
    //   - ParamTableBase 8-byte 对齐, 非 NULL
    //
    // 限速: 单次 RtlCopyMemory 32 字节, 一次扫 ~3.5M 候选, < 100ms
    ULONG_PTR scanStart = ntosBase;
    ULONG_PTR scanEnd = ntosEnd;
    ULONG candidates = 0;

    for (ULONG_PTR addr = scanStart; addr + 0x20 <= scanEnd; addr += 8) {
        HV_KE_SERVICE_DESCRIPTOR_TABLE c;
        __try {
            RtlCopyMemory(&c, (PVOID)addr, sizeof(c));
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            continue;
        }

        ULONG_PTR svcBase = (ULONG_PTR)c.ServiceTableBase;
        if (svcBase == 0) continue;
        if ((svcBase & 0x7) != 0) continue;
        // 必须不在 ntoskrnl (那是 ntoskrnl SSDT, 我们要的是 win32k)
        if (svcBase >= ntosBase && svcBase < ntosEnd) continue;
        // 在合理 kernel VA 范围 (高位 0xFFFF8...)
        if (svcBase < 0xFFFF800000000000ULL) continue;

        if (c.ServiceCounterTable != NULL) continue;
        // 2026-06-19 缩窄: Win10/11 win32k SSDT NumServices 典型 1000-1500,
        // 上限放到 0x700 (1792) 排除假表 (如本次扫到 2048 的某 placeholder)
        if (c.NumberOfServices < 0x300 || c.NumberOfServices > 0x700) continue;

        ULONG_PTR paramBase = (ULONG_PTR)c.ParamTableBase;
        if (paramBase == 0 || (paramBase & 0x7) != 0) continue;
        // ParamTableBase 通常和 ServiceTableBase 在同一 module range (win32kbase)
        if (paramBase < 0xFFFF800000000000ULL) continue;

        // 2026-06-19: entry sanity check — 抽样读 svcBase[0..3] 的 LONG, 看是否像
        // ntoskrnl 风格的 encoded offset (典型负数 / 大正数, 不应该是 0..0xFFFF 的小整数)。
        // 假表的 entry 通常是 0xC / 0x18 / 0x24 这种 callback table 偏移, 命中即拒。
        BOOLEAN entriesLookValid = TRUE;
        __try {
            const volatile LONG* entries = (const volatile LONG*)svcBase;
            for (ULONG e = 0; e < 4; e++) {
                LONG ev = entries[e];
                ULONG abs = (ULONG)(ev < 0 ? -ev : ev);
                // 合法 SSDT entry 至少 16 KB 偏移 (函数离表至少几页), 或者跨百万级
                if (abs < 0x4000) { entriesLookValid = FALSE; break; }
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            entriesLookValid = FALSE;
        }
        if (!entriesLookValid) {
            DbgPrint("[HvHook] W32K SSDT candidate REJECT (entries look like callback table, not SSDT): "
                     "ServiceTableBase=%p NumServices=%u\n",
                     c.ServiceTableBase, c.NumberOfServices);
            continue;
        }

        candidates++;

        // 首个匹配即采用
        g_W32KServiceTableBase = c.ServiceTableBase;
        g_W32KNumberOfServices = c.NumberOfServices;
        g_W32KBaseCached = svcBase & ~0xFFFFFFULL;
        g_W32KEndCached  = g_W32KBaseCached + 0x1000000;

        DbgPrint("[HvHook] W32K SSDT @ %p ServiceTableBase=%p NumServices=%u ParamTableBase=%p\n",
                 (PVOID)addr, c.ServiceTableBase, c.NumberOfServices, c.ParamTableBase);
        return STATUS_SUCCESS;
    }

    DbgPrint("[HvHook] W32K SSDT scan failed: 0 candidates in ntoskrnl image\n");
    return STATUS_NOT_FOUND;
}

// ============================================================
// 2026-06-19: 基于 kernel module EAT 的函数地址解析
// ============================================================
//
// Win11 24H2 的 win32k NtUser* 函数实际**导出**在 win32kfull.sys 里
// (win32k.sys 只是 __win32kstub_ 转发, win32kbase.sys 是基础设施)。
// 用 ZwQuerySystemInformation(11)=SystemModuleInformation 拿到 win32kfull.sys
// 的 ImageBase, 然后读它的 PE EAT 找名字, ImageBase + RVA = 真实地址。
//
// 比 SSDT 扫描可靠很多 — SSDT 扫到的可能是假表 / placeholder, 而 EAT 是 PE
// 标准结构, 直接由 loader 维护, 不会假。
//
// 注意 (kernel-mode 读):
//   - 内核 VA 直接 RtlCopyMemory 读, 不需要 HvPhys 物理直通
//   - 模块 PE 头在 ImageBase 起始处, 4KB 必映射, 读安全
//   - EAT 在 .rdata, 一定在 ImageBase + size 范围内, 读安全
// ============================================================

extern NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(
    _In_ ULONG SystemInformationClass,
    _Inout_opt_ PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength);

static PVOID HvHookpResolveKernelExport(
    _In_ PCSTR ModuleNameAscii,   // "win32kfull.sys"
    _In_ PCSTR FunctionName)
{
    NTSTATUS st;
    ULONG needed = 0;

    // 1) 查所需 buffer 大小
    st = ZwQuerySystemInformation(11, NULL, 0, &needed);
    if (needed == 0) {
        DbgPrint("[HvHook] EAT: ZwQuerySystemInformation(11) size probe failed st=0x%X\n", st);
        return NULL;
    }
    needed += 0x1000;  // 余量

    PVOID buf = HvAllocateNonPagedZeroed(needed, 'HvEx');
    if (!buf) return NULL;

    st = ZwQuerySystemInformation(11, buf, needed, &needed);
    if (!NT_SUCCESS(st)) {
        DbgPrint("[HvHook] EAT: ZwQuerySystemInformation(11) failed st=0x%X\n", st);
        ExFreePoolWithTag(buf, 'HvEx');
        return NULL;
    }

    PHV_RTL_PROCESS_MODULES modules = (PHV_RTL_PROCESS_MODULES)buf;
    PVOID imageBase = NULL;
    ULONG imageSize = 0;

    // 2) 找模块 (按 FullPathName basename 比对)
    for (ULONG i = 0; i < modules->NumberOfModules; i++) {
        PHV_RTL_PROCESS_MODULE_INFORMATION m = &modules->Modules[i];
        PCSTR fullName = (PCSTR)m->FullPathName;
        PCSTR basename = fullName + m->OffsetToFileName;

        // case-insensitive 比对
        BOOLEAN match = TRUE;
        for (ULONG j = 0; j < 64; j++) {
            CHAR a = basename[j];
            CHAR b = ModuleNameAscii[j];
            if (a == 0 && b == 0) break;
            if (a == 0 || b == 0) { match = FALSE; break; }
            if (a >= 'A' && a <= 'Z') a = (CHAR)(a - 'A' + 'a');
            if (b >= 'A' && b <= 'Z') b = (CHAR)(b - 'A' + 'a');
            if (a != b) { match = FALSE; break; }
        }
        if (match) {
            imageBase = m->ImageBase;
            imageSize = m->ImageSize;
            break;
        }
    }
    ExFreePoolWithTag(buf, 'HvEx');

    if (!imageBase) {
        DbgPrint("[HvHook] EAT: module %hs not found in PsLoadedModuleList\n", ModuleNameAscii);
        return NULL;
    }

    // 3) 解析 PE EAT (内核 VA 直读)
    PUCHAR base = (PUCHAR)imageBase;
    PVOID found = NULL;
    __try {
        if (base[0] != 'M' || base[1] != 'Z') {
            DbgPrint("[HvHook] EAT: %hs ImageBase=%p MZ check failed\n", ModuleNameAscii, base);
            return NULL;
        }
        ULONG e_lfanew = *(ULONG*)(base + 0x3C);
        if (e_lfanew > imageSize - 0x100) return NULL;
        if (*(ULONG*)(base + e_lfanew) != 0x00004550) return NULL;   // "PE\0\0"

        ULONG exportRva  = *(ULONG*)(base + e_lfanew + 0x88);
        ULONG exportSize = *(ULONG*)(base + e_lfanew + 0x8C);
        if (!exportRva || exportRva >= imageSize) return NULL;

        PUCHAR ed = base + exportRva;
        ULONG  numNames     = *(ULONG*)(ed + 0x18);
        ULONG  functionsRva = *(ULONG*)(ed + 0x1C);
        ULONG  namesRva     = *(ULONG*)(ed + 0x20);
        ULONG  ordinalsRva  = *(ULONG*)(ed + 0x24);
        if (numNames == 0 || numNames > 0x10000) return NULL;
        if (functionsRva >= imageSize || namesRva >= imageSize || ordinalsRva >= imageSize) return NULL;

        PULONG  funcsArr = (PULONG)(base + functionsRva);
        PULONG  namesArr = (PULONG)(base + namesRva);
        PUSHORT ordsArr  = (PUSHORT)(base + ordinalsRva);

        ULONG fnLen = 0;
        while (FunctionName[fnLen]) fnLen++;

        for (ULONG i = 0; i < numNames; i++) {
            ULONG nameRva = namesArr[i];
            if (nameRva == 0 || nameRva >= imageSize) continue;
            PCSTR name = (PCSTR)(base + nameRva);

            BOOLEAN nameMatch = TRUE;
            for (ULONG j = 0; j < fnLen; j++) {
                if (name[j] != FunctionName[j]) { nameMatch = FALSE; break; }
            }
            if (nameMatch && name[fnLen] == 0) {
                USHORT ord = ordsArr[i];
                ULONG funcRva = funcsArr[ord];
                if (funcRva && funcRva < imageSize) {
                    found = base + funcRva;
                }
                break;
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[HvHook] EAT: %hs PE parse exception\n", ModuleNameAscii);
        return NULL;
    }

    if (found) {
        DbgPrint("[HvHook] EAT: %hs!%hs = %p (ImageBase=%p)\n",
                 ModuleNameAscii, FunctionName, found, imageBase);
    } else {
        DbgPrint("[HvHook] EAT: %hs!%hs NOT FOUND in EAT\n",
                 ModuleNameAscii, FunctionName);
    }
    return found;
}

// 从 win32k SSDT 取 syscall index 对应的内核地址 (decoded)
static PVOID HvHookpResolveW32KByIndex(_In_ ULONG SyscallIndex)
{
    NTSTATUS s = HvHookpResolveW32KSsdtBase();
    if (!NT_SUCCESS(s)) return NULL;
    // win32k syscall index 高位是 0x1000, 真实 SSDT entry index 是低 12 bit
    ULONG idx = SyscallIndex & 0xFFF;
    if (idx >= g_W32KNumberOfServices) return NULL;

    // 2026-06-17: Win11 24H2 W32K SSDT 探测两种格式:
    //   (A) ntoskrnl 风格 encoded LONG[]: addr = base + (entry >> 4)
    //   (B) Win11 新格式 PVOID 直接指针 PVOID[]
    // 用第一个 entry 试探: 若 entry 看起来是个合法 kernel VA (高位
    // 0xFFFF8000..., 在 win32kbase range), 就是 PVOID 格式; 否则 encoded。

    PVOID firstEntry;
    __try {
        firstEntry = ((PVOID*)g_W32KServiceTableBase)[0];
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return NULL;
    }
    // 2026-06-19 修正 v3: 同时探测两种 ABI, 选解出来能落到合法 kernel VA 的那个。
    //   (A) ntoskrnl 风格 encoded LONG: addr = base + (entry_LONG >> 4)
    //       — 只在 ServiceTableBase 跟 win32k.sys ImageBase 同 region 时管用,
    //         Win11 win32k SSDT 在 SessionPool, 不在 win32k 模块内 → 一般不行
    //   (B) PVOID 格式: addr = base[idx] (8 字节函数指针)
    //       — Win11 24H2 confirmed format
    //
    // 实测谁解出来高位 0xFFFFF8 (典型 win32k.sys VA), 谁就是正确的。
    PVOID addrEnc, addrPv;
    LONG encoded;
    __try {
        encoded = ((volatile LONG*)g_W32KServiceTableBase)[idx];
        addrPv = ((PVOID*)g_W32KServiceTableBase)[idx];
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return NULL;
    }
    addrEnc = (PVOID)((ULONG_PTR)g_W32KServiceTableBase + (encoded >> 4));

    // win32k.sys 真实代码段一般在 0xFFFFF8xxxxxxxx (PML4 entry 1xx 区), 不在 SessionPool
    // 选高位指向典型内核 image VA 的那个 (`FFFFF8`/`FFFFF7` 等)
    PVOID addr = NULL;
    if (((ULONG_PTR)addrPv >> 48) == 0xFFFF &&
        ((ULONG_PTR)addrPv >> 40) >= 0xFFFFF7ULL)
    {
        addr = addrPv;   // PVOID 格式
    } else if (((ULONG_PTR)addrEnc >> 48) == 0xFFFF &&
               ((ULONG_PTR)addrEnc >> 40) >= 0xFFFFF7ULL)
    {
        addr = addrEnc;  // encoded LONG 格式
    }

    if ((SyscallIndex & 0xFFF) == 0xE) {
        DbgPrint("[HvHook] W32K decode idx=0x%X svcBase=%p encoded=0x%X addrEnc=%p addrPv=%p → chosen=%p\n",
                 SyscallIndex, (PVOID)g_W32KServiceTableBase,
                 encoded, addrEnc, addrPv, addr);
    }

    // 2026-06-19 修正: 原来 range check 用 (ServiceTableBase 邻域 16MB) 不可靠 —
    // ServiceTableBase 在 SessionPool (0xFFFF990D...) 而 win32k.sys 函数体在内核 VA
    // (0xFFFFF800...), 两者高位完全不同, 16MB 邻域永远不命中真函数地址。
    //
    // 改成:只校验是不是合法 kernel canonical VA (>= 0xFFFF800000000000),
    // 实际 hook 装载阶段 EPT 框架会用物理 PT 解析验证地址有效性, 这一层不再阻拦。
    if ((ULONG_PTR)addr < 0xFFFF800000000000ULL) {
        DbgPrint("[HvHook] W32K resolveByIndex idx=0x%X addr=%p not kernel VA\n",
                 SyscallIndex, addr);
        return NULL;
    }
    return addr;
}

// 2. 从 caller 的 DLL 提 syscall index
//
// 2026-06-17: DllName 参数化, 同时支持 ntdll.dll (ntoskrnl syscall) 和 win32u.dll
// (win32k syscall). Win32u 的 syscall index 高位是 0x1000 (encode 标记 win32k 路径)。
static NTSTATUS HvHookpResolveSyscallIndexInDll(
    _In_ ULONG CallerPid,
    _In_ PCWSTR DllName,
    _In_ PCSTR FunctionName,
    _Out_ PULONG OutIndex
)
{
    *OutIndex = 0xFFFFFFFF;
    if (!CallerPid) return STATUS_INVALID_PARAMETER;

    HV_MODULE_INFO modules[32];
    ULONG count = 0;
    NTSTATUS s = HvPhysEnumerateModules(CallerPid, modules,
                                         sizeof(modules) / sizeof(modules[0]), &count);
    if (!NT_SUCCESS(s) || count == 0) return NT_SUCCESS(s) ? STATUS_NOT_FOUND : s;

    UINT64 dllBase = 0;
    for (ULONG i = 0; i < count; i++) {
        UNICODE_STRING want;
        RtlInitUnicodeString(&want, DllName);
        UNICODE_STRING got;
        SIZE_T nlen = 0;
        while (nlen < HV_MODULE_NAME_MAX && modules[i].Name[nlen]) nlen++;
        got.Buffer = modules[i].Name;
        got.Length = (USHORT)(nlen * sizeof(WCHAR));
        got.MaximumLength = got.Length;
        if (RtlEqualUnicodeString(&got, &want, TRUE)) {
            dllBase = modules[i].DllBase;
            break;
        }
    }
    if (!dllBase) return STATUS_NOT_FOUND;

    UCHAR peHead[0x400];
    SIZE_T done = 0;
    s = HvPhysReadProcessMemory(CallerPid, dllBase, peHead, sizeof(peHead), &done);
    if (!NT_SUCCESS(s) || done < sizeof(peHead)) {
        return NT_SUCCESS(s) ? STATUS_PARTIAL_COPY : s;
    }
    if (peHead[0] != 'M' || peHead[1] != 'Z') return STATUS_INVALID_IMAGE_FORMAT;
    ULONG e_lfanew = *(ULONG*)(peHead + 0x3C);
    if (e_lfanew + 0x88 + 4 > sizeof(peHead)) return STATUS_INVALID_IMAGE_FORMAT;
    if (*(ULONG*)(peHead + e_lfanew) != 0x00004550) return STATUS_INVALID_IMAGE_FORMAT;

    ULONG exportRva  = *(ULONG*)(peHead + e_lfanew + 0x88);
    ULONG exportSize = *(ULONG*)(peHead + e_lfanew + 0x8C);
    if (!exportRva || !exportSize || exportSize > 0x100000) return STATUS_NOT_FOUND;

    PVOID expDir = HvAllocateNonPagedZeroed(exportSize, 'HvL6');
    if (!expDir) return STATUS_INSUFFICIENT_RESOURCES;
    s = HvPhysReadProcessMemory(CallerPid, dllBase + exportRva,
                                 expDir, exportSize, &done);
    if (!NT_SUCCESS(s) || done < exportSize) {
        ExFreePoolWithTag(expDir, 'HvL6');
        return NT_SUCCESS(s) ? STATUS_PARTIAL_COPY : s;
    }

    PUCHAR ed = (PUCHAR)expDir;
    ULONG numNames     = *(ULONG*)(ed + 0x18);
    ULONG functionsRva = *(ULONG*)(ed + 0x1C);
    ULONG namesRva     = *(ULONG*)(ed + 0x20);
    ULONG ordinalsRva  = *(ULONG*)(ed + 0x24);

    if (!numNames || numNames > 0x10000) {
        ExFreePoolWithTag(expDir, 'HvL6');
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    ULONG nfSize = numNames * 4;
    ULONG ordSize = numNames * 2;
    PVOID arrs = HvAllocateNonPagedZeroed(nfSize * 2 + ordSize, 'HvL6');
    if (!arrs) {
        ExFreePoolWithTag(expDir, 'HvL6');
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    PULONG  namesArr = (PULONG)((PUCHAR)arrs);
    PULONG  funcsArr = (PULONG)((PUCHAR)arrs + nfSize);
    PUSHORT ordsArr  = (PUSHORT)((PUCHAR)arrs + nfSize * 2);

    s = HvPhysReadProcessMemory(CallerPid, dllBase + namesRva,    namesArr, nfSize, &done);
    if (NT_SUCCESS(s)) s = HvPhysReadProcessMemory(CallerPid, dllBase + functionsRva, funcsArr, nfSize, &done);
    if (NT_SUCCESS(s)) s = HvPhysReadProcessMemory(CallerPid, dllBase + ordinalsRva,  ordsArr,  ordSize, &done);
    if (!NT_SUCCESS(s)) {
        ExFreePoolWithTag(arrs, 'HvL6');
        ExFreePoolWithTag(expDir, 'HvL6');
        return s;
    }

    // 计算 FunctionName 长度 (用于按需读)
    ULONG fnLen = 0;
    while (FunctionName[fnLen]) fnLen++;

    ULONG foundFuncRva = 0;
    for (ULONG i = 0; i < numNames; i++) {
        char nameBuf[128];
        // 只读 fnLen+1 字节 (足够分辨匹配, 不会跨页), fnLen+1 包含期望 NUL
        ULONG wantBytes = fnLen + 1;
        if (wantBytes > sizeof(nameBuf)) wantBytes = sizeof(nameBuf);
        s = HvPhysReadProcessMemory(CallerPid, dllBase + namesArr[i],
                                     nameBuf, wantBytes, &done);
        if (!NT_SUCCESS(s) || done < wantBytes) continue;
        nameBuf[wantBytes - 1] = '\0';  // 强制 NUL 终结
        // 严格按字节比对前 fnLen 字节 + 后接 NUL
        BOOLEAN match = TRUE;
        for (ULONG j = 0; j < fnLen; j++) {
            if (nameBuf[j] != FunctionName[j]) { match = FALSE; break; }
        }
        if (match && nameBuf[fnLen] == '\0') {
            foundFuncRva = funcsArr[ordsArr[i]];
            break;
        }
    }
    ExFreePoolWithTag(arrs, 'HvL6');
    ExFreePoolWithTag(expDir, 'HvL6');
    if (!foundFuncRva) return STATUS_NOT_FOUND;

    UCHAR stub[16];
    s = HvPhysReadProcessMemory(CallerPid, dllBase + foundFuncRva,
                                 stub, sizeof(stub), &done);
    if (!NT_SUCCESS(s) || done < 8) return NT_SUCCESS(s) ? STATUS_PARTIAL_COPY : s;

    if (stub[0] != 0x4C || stub[1] != 0x8B || stub[2] != 0xD1 || stub[3] != 0xB8) {
        return STATUS_NOT_SUPPORTED;
    }
    *OutIndex = *(ULONG*)(stub + 4);
    return STATUS_SUCCESS;
}

// 2. 从 ntdll 提 syscall index (兼容旧接口)
static NTSTATUS HvHookpResolveSyscallIndex(
    _In_ ULONG CallerPid,
    _In_ PCSTR FunctionName,
    _Out_ PULONG OutIndex
)
{
    *OutIndex = 0xFFFFFFFF;
    if (!CallerPid) return STATUS_INVALID_PARAMETER;

    DbgPrint("[HvHook] M3.6 SyscallIdx step A: enter for %hs CallerPid=%u IRQL=%u\n",
             FunctionName, CallerPid, KeGetCurrentIrql());

    // 1. 找 ntdll base via HvPhysEnumerateModules
    HV_MODULE_INFO modules[32];   // user-mode lib 早期一般几个
    ULONG count = 0;
    DbgPrint("[HvHook] M3.6 SyscallIdx step B: about to call HvPhysEnumerateModules (THIS MAY BE BSOD POINT)\n");
    NTSTATUS s = HvPhysEnumerateModules(CallerPid, modules,
                                         sizeof(modules) / sizeof(modules[0]), &count);
    DbgPrint("[HvHook] M3.6 SyscallIdx step C: HvPhysEnumerateModules returned 0x%X count=%u\n",
             s, count);
    if (!NT_SUCCESS(s) || count == 0) {
        DbgPrint("[HvHook] L6: EnumModules pid=%u status=0x%X count=%u\n",
                 CallerPid, s, count);
        return NT_SUCCESS(s) ? STATUS_NOT_FOUND : s;
    }

    UINT64 ntdllBase = 0;
    for (ULONG i = 0; i < count; i++) {
        // 大小写不敏感比较 ntdll.dll
        UNICODE_STRING want;
        RtlInitUnicodeString(&want, L"ntdll.dll");
        UNICODE_STRING got;
        // HV_MODULE_INFO.Name 是 WCHAR[HV_MODULE_NAME_MAX] (null-terminated)
        SIZE_T nlen = 0;
        while (nlen < HV_MODULE_NAME_MAX && modules[i].Name[nlen]) nlen++;
        got.Buffer = modules[i].Name;
        got.Length = (USHORT)(nlen * sizeof(WCHAR));
        got.MaximumLength = got.Length;
        if (RtlEqualUnicodeString(&got, &want, TRUE)) {
            ntdllBase = modules[i].DllBase;
            break;
        }
    }
    if (!ntdllBase) {
        DbgPrint("[HvHook] L6: ntdll.dll not found in pid=%u (modules count=%u)\n",
                 CallerPid, count);
        return STATUS_NOT_FOUND;
    }

    // 2. 读 ntdll PE header. P123: HvPhys 物理直通不触发 demand-paging, ntdll 工作集
    //    被 trim 时返 NOT_FOUND. 改用 KeStackAttachProcess + RtlCopyMemory 走 Windows
    //    标准路径, 自动 fault-in.
    UCHAR peHead[0x400];
    PEPROCESS callerProc = NULL;
    NTSTATUS lk = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)CallerPid, &callerProc);
    if (!NT_SUCCESS(lk) || !callerProc) {
        DbgPrint("[HvHook] L6: PsLookupProcess pid=%u failed 0x%X\n", CallerPid, lk);
        return NT_SUCCESS(lk) ? STATUS_NOT_FOUND : lk;
    }
    HV_HOOK_APC_STATE peApc;
    KeStackAttachProcess((PRKPROCESS)callerProc, &peApc);
    NTSTATUS readSt = STATUS_SUCCESS;
    __try {
        ProbeForRead((PVOID)ntdllBase, sizeof(peHead), sizeof(UCHAR));
        RtlCopyMemory(peHead, (PVOID)ntdllBase, sizeof(peHead));
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        readSt = GetExceptionCode();
    }
    KeUnstackDetachProcess(&peApc);
    if (!NT_SUCCESS(readSt)) {
        ObDereferenceObject(callerProc);
        DbgPrint("[HvHook] L6: read ntdll PE head via attach failed status=0x%X\n", readSt);
        return readSt;
    }
    SIZE_T done = sizeof(peHead);
    s = STATUS_SUCCESS;

    if (peHead[0] != 'M' || peHead[1] != 'Z') return STATUS_INVALID_IMAGE_FORMAT;
    ULONG e_lfanew = *(ULONG*)(peHead + 0x3C);
    if (e_lfanew + 0x88 + 4 > sizeof(peHead)) return STATUS_INVALID_IMAGE_FORMAT;
    if (*(ULONG*)(peHead + e_lfanew) != 0x00004550) return STATUS_INVALID_IMAGE_FORMAT;

    ULONG exportRva  = *(ULONG*)(peHead + e_lfanew + 0x88);
    ULONG exportSize = *(ULONG*)(peHead + e_lfanew + 0x8C);
    if (!exportRva || !exportSize || exportSize > 0x100000) return STATUS_NOT_FOUND;

    // 3. 读 export directory. 同样用 KeStackAttachProcess + RtlCopyMemory.
    PVOID expDir = HvAllocateNonPagedZeroed(exportSize, 'HvL6');
    if (!expDir) {
        ObDereferenceObject(callerProc);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    HV_HOOK_APC_STATE expApc;
    KeStackAttachProcess((PRKPROCESS)callerProc, &expApc);
    readSt = STATUS_SUCCESS;
    __try {
        ProbeForRead((PVOID)(ntdllBase + exportRva), exportSize, sizeof(UCHAR));
        RtlCopyMemory(expDir, (PVOID)(ntdllBase + exportRva), exportSize);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        readSt = GetExceptionCode();
    }
    KeUnstackDetachProcess(&expApc);
    ObDereferenceObject(callerProc);
    if (!NT_SUCCESS(readSt)) {
        ExFreePoolWithTag(expDir, 'HvL6');
        DbgPrint("[HvHook] L6: read ntdll EAT via attach failed status=0x%X\n", readSt);
        return readSt;
    }
    done = exportSize;
    s = STATUS_SUCCESS;

    PUCHAR ed = (PUCHAR)expDir;
    ULONG numNames    = *(ULONG*)(ed + 0x18);
    ULONG functionsRva = *(ULONG*)(ed + 0x1C);
    ULONG namesRva    = *(ULONG*)(ed + 0x20);
    ULONG ordinalsRva = *(ULONG*)(ed + 0x24);

    if (!numNames || numNames > 0x10000) {
        ExFreePoolWithTag(expDir, 'HvL6');
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    // 4. 读 names/funcs/ords 三个数组 + name 字符串 + stub 头
    //    P123: 同 step 2/3, 用 attach + RtlCopyMemory 替代 HvPhys 物理直通,
    //    避免 ntdll 工作集 trim 时返 NOT_FOUND.
    ULONG nfSize = numNames * 4;        // names + funcs (RVA, 4 bytes each)
    ULONG ordSize = numNames * 2;       // ordinals (USHORT)
    PVOID arrs = HvAllocateNonPagedZeroed(nfSize * 2 + ordSize, 'HvL6');
    if (!arrs) {
        ExFreePoolWithTag(expDir, 'HvL6');
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    PULONG  namesArr = (PULONG)((PUCHAR)arrs);
    PULONG  funcsArr = (PULONG)((PUCHAR)arrs + nfSize);
    PUSHORT ordsArr  = (PUSHORT)((PUCHAR)arrs + nfSize * 2);

    // 重新 lookup process (前面 ObDereferenceObject 释放了)
    callerProc = NULL;
    lk = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)CallerPid, &callerProc);
    if (!NT_SUCCESS(lk) || !callerProc) {
        ExFreePoolWithTag(arrs, 'HvL6');
        ExFreePoolWithTag(expDir, 'HvL6');
        return NT_SUCCESS(lk) ? STATUS_NOT_FOUND : lk;
    }

    HV_HOOK_APC_STATE arrApc;
    KeStackAttachProcess((PRKPROCESS)callerProc, &arrApc);
    readSt = STATUS_SUCCESS;
    ULONG foundFuncRva = 0;
    UCHAR stub[16] = {0};
    __try {
        ProbeForRead((PVOID)(ntdllBase + namesRva), nfSize, sizeof(ULONG));
        RtlCopyMemory(namesArr, (PVOID)(ntdllBase + namesRva), nfSize);

        ProbeForRead((PVOID)(ntdllBase + functionsRva), nfSize, sizeof(ULONG));
        RtlCopyMemory(funcsArr, (PVOID)(ntdllBase + functionsRva), nfSize);

        ProbeForRead((PVOID)(ntdllBase + ordinalsRva), ordSize, sizeof(USHORT));
        RtlCopyMemory(ordsArr, (PVOID)(ntdllBase + ordinalsRva), ordSize);

        // 在 names 里找 FunctionName
        for (ULONG i = 0; i < numNames; i++) {
            char nameBuf[64];
            ProbeForRead((PVOID)(ntdllBase + namesArr[i]), sizeof(nameBuf), sizeof(UCHAR));
            RtlCopyMemory(nameBuf, (PVOID)(ntdllBase + namesArr[i]), sizeof(nameBuf));
            nameBuf[63] = '\0';

            const char* a = nameBuf;
            const char* b = FunctionName;
            while (*a && *b && *a == *b) { a++; b++; }
            if (*a == 0 && *b == 0) {
                foundFuncRva = funcsArr[ordsArr[i]];
                break;
            }
        }
        if (foundFuncRva) {
            ProbeForRead((PVOID)(ntdllBase + foundFuncRva), sizeof(stub), sizeof(UCHAR));
            RtlCopyMemory(stub, (PVOID)(ntdllBase + foundFuncRva), sizeof(stub));
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        readSt = GetExceptionCode();
    }
    KeUnstackDetachProcess(&arrApc);
    ObDereferenceObject(callerProc);
    ExFreePoolWithTag(arrs, 'HvL6');
    ExFreePoolWithTag(expDir, 'HvL6');

    if (!NT_SUCCESS(readSt)) {
        DbgPrint("[HvHook] L6: read ntdll EAT data via attach failed status=0x%X\n", readSt);
        return readSt;
    }

    if (!foundFuncRva) {
        DbgPrint("[HvHook] L6: %hs not in ntdll EAT\n", FunctionName);
        return STATUS_NOT_FOUND;
    }
    done = sizeof(stub);
    s = STATUS_SUCCESS;

    // 校验 stub 模式: mov r10, rcx (4C 8B D1) ; mov eax, imm32 (B8 XX XX XX XX)
    if (stub[0] != 0x4C || stub[1] != 0x8B || stub[2] != 0xD1 || stub[3] != 0xB8) {
        DbgPrint("[HvHook] L6: %hs stub bytes unexpected: %02X %02X %02X %02X %02X %02X %02X %02X\n",
                 FunctionName, stub[0], stub[1], stub[2], stub[3],
                 stub[4], stub[5], stub[6], stub[7]);
        return STATUS_NOT_SUPPORTED;
    }

    *OutIndex = *(ULONG*)(stub + 4);
    return STATUS_SUCCESS;
}

// 3. 主集成函数: name + caller pid → kernel addr
static PVOID HvHookpResolveViaSsdt(_In_ PCWSTR Name, _In_ ULONG CallerPid)
{
    NTSTATUS s;
    SIZE_T i;

    s = HvHookpResolveSsdtBase();
    if (!NT_SUCCESS(s)) return NULL;

    // wide → ASCII
    char asciiName[64];
    for (i = 0; i < sizeof(asciiName) - 1 && Name[i]; i++) {
        asciiName[i] = (char)Name[i];
    }
    asciiName[i] = '\0';

    // 查缓存 (避免每次 hook 装载重新解析 ntdll)
    HV_SYSCALL_CACHE* cache = NULL;
    for (i = 0; g_SyscallCache[i].Name; i++) {
        const char* a = asciiName;
        const char* b = g_SyscallCache[i].Name;
        while (*a && *b && *a == *b) { a++; b++; }
        if (*a == 0 && *b == 0) {
            cache = &g_SyscallCache[i];
            break;
        }
    }
    if (!cache) {
        DbgPrint("[HvHook] L6: %ws not registered in SSDT cache table\n", Name);
        return NULL;
    }
    if (cache->KernelAddr) return cache->KernelAddr;   // 缓存命中

    // 未缓存: 解析 syscall index
    ULONG syscallIdx = 0xFFFFFFFF;
    s = HvHookpResolveSyscallIndex(CallerPid, asciiName, &syscallIdx);
    if (!NT_SUCCESS(s) || syscallIdx >= g_NumberOfServices) {
        DbgPrint("[HvHook] L6: %ws → syscall index lookup failed (status=0x%X idx=%u)\n",
                 Name, s, syscallIdx);
        return NULL;
    }

    // SSDT[idx] decode: Win10/11 是 (int32 >> 4) + base,low 4 bits 是参数计数
    PULONG table = (PULONG)g_KiServiceTableBase;
    LONG encoded = (LONG)table[syscallIdx];
    PVOID realAddr = (PVOID)((ULONG_PTR)g_KiServiceTableBase + (encoded >> 4));

    // L6.2 校验 1: 解码地址必须在 ntoskrnl image range 内
    if ((ULONG_PTR)realAddr < g_NtoskrnlBaseCached ||
        (ULONG_PTR)realAddr >= g_NtoskrnlEndCached) {
        DbgPrint("[HvHook] L6: %ws idx=0x%X decoded=%p OUT OF ntoskrnl range [%p,%p) - REJECT\n",
                 Name, syscallIdx, realAddr,
                 (PVOID)g_NtoskrnlBaseCached, (PVOID)g_NtoskrnlEndCached);
        return NULL;
    }

    // L6.2 校验 2: 解码地址必须像合法函数入口 (前几字节是函数序言模式)
    if (!HvHookpLooksLikeFunctionEntry(realAddr)) {
        UCHAR fb[8] = { 0 };
        __try { RtlCopyMemory(fb, realAddr, 8); } __except (EXCEPTION_EXECUTE_HANDLER) {}
        DbgPrint("[HvHook] L6: %ws idx=0x%X decoded=%p NOT a function entry "
                 "(bytes: %02X %02X %02X %02X %02X %02X %02X %02X) - REJECT\n",
                 Name, syscallIdx, realAddr,
                 fb[0], fb[1], fb[2], fb[3], fb[4], fb[5], fb[6], fb[7]);
        return NULL;
    }

    cache->Index = syscallIdx;
    cache->KernelAddr = realAddr;

    DbgPrint("[HvHook] L6: %ws idx=0x%X SSDT[%u]=%p (encoded=0x%08X argcount=%u)\n",
             Name, syscallIdx, syscallIdx, realAddr,
             (ULONG)encoded, (ULONG)(encoded & 0xF));
    return realAddr;
}

// Phase L (2026-06-03): MmGetSystemRoutineAddress 的导出表查询不全
// (Win10 19045 ntoskrnl 不导出 NtReadVirtualMemory/NtWriteVirtualMemory/
// NtSetContextThread 等多个 syscall 名,Zw 别名同样不导出)。
// 自己 walk PE EAT 兜底。
//
// L4 修正 (2026-06-03): 旧实现从 anchor 函数地址向下页扫描找 MZ —— 危险,可能
// 命中 ntoskrnl PAGED section / 已 unload 驱动的空洞 → PAGE_FAULT_IN_NONPAGED_AREA。
// 改用 ZwQuerySystemInformation(SystemModuleInformation=11) 拿模块表,
// 第一项 ImageBase 就是 ntoskrnl.exe (内核加载顺序保证)。
// HV_RTL_PROCESS_MODULES / HV_RTL_PROCESS_MODULE_INFORMATION 在 HvTypes.h 已定义,
// 直接复用 (HvHook.h 已 include 链路)。

#define HV_SYSTEM_MODULE_INFO_CLASS 11

static PVOID HvHookpFindNtoskrnlBase(VOID)
{
    NTSTATUS status;
    ULONG bufLen = 0;
    PVOID buf;
    PVOID result = NULL;

    // 先 query 大小
    status = ZwQuerySystemInformation(HV_SYSTEM_MODULE_INFO_CLASS,
                                       NULL, 0, &bufLen);
    if (bufLen == 0) return NULL;
    bufLen += 0x4000;   // 多余空间防扩张

    buf = HvAllocateNonPagedZeroed(bufLen, 'HvNT');
    if (!buf) return NULL;

    status = ZwQuerySystemInformation(HV_SYSTEM_MODULE_INFO_CLASS,
                                       buf, bufLen, &bufLen);
    if (NT_SUCCESS(status)) {
        PHV_RTL_PROCESS_MODULES mods = (PHV_RTL_PROCESS_MODULES)buf;
        if (mods->NumberOfModules > 0) {
            // 第一项就是 ntoskrnl (内核加载顺序保证)
            result = mods->Modules[0].ImageBase;
        }
    }

    ExFreePoolWithTag(buf, 'HvNT');
    return result;
}

// Phase L6.2: 同时返回 ntoskrnl 的 [base, end) 区间,L6 严化校验用
static NTSTATUS HvHookpFindNtoskrnlRange(_Out_ PULONG_PTR OutBase,
                                          _Out_ PULONG_PTR OutEnd)
{
    NTSTATUS status;
    ULONG bufLen = 0;

    *OutBase = 0;
    *OutEnd = 0;

    status = ZwQuerySystemInformation(HV_SYSTEM_MODULE_INFO_CLASS,
                                       NULL, 0, &bufLen);
    if (bufLen == 0) return STATUS_INVALID_DEVICE_STATE;
    bufLen += 0x4000;

    PVOID buf = HvAllocateNonPagedZeroed(bufLen, 'HvNT');
    if (!buf) return STATUS_INSUFFICIENT_RESOURCES;

    status = ZwQuerySystemInformation(HV_SYSTEM_MODULE_INFO_CLASS,
                                       buf, bufLen, &bufLen);
    if (NT_SUCCESS(status)) {
        PHV_RTL_PROCESS_MODULES mods = (PHV_RTL_PROCESS_MODULES)buf;
        if (mods->NumberOfModules > 0) {
            *OutBase = (ULONG_PTR)mods->Modules[0].ImageBase;
            *OutEnd  = *OutBase + mods->Modules[0].ImageSize;
        } else {
            status = STATUS_NOT_FOUND;
        }
    }

    ExFreePoolWithTag(buf, 'HvNT');
    return status;
}

// 在 ntoskrnl PE EAT 里找指定 ASCII 函数名的地址
static PVOID HvHookpEatLookup(_In_ PVOID Base, _In_ PCSTR Name)
{
    if (!Base || !Name) return NULL;

    UCHAR* base = (UCHAR*)Base;
    ULONG e_lfanew = *(ULONG*)(base + 0x3C);
    UCHAR* peHdr = base + e_lfanew;

    // OptionalHeader 在 PE 头 + 0x18, DataDirectory[0] (Export) 在 +0x88 (PE32+)
    ULONG exportRva  = *(ULONG*)(peHdr + 0x88);
    ULONG exportSize = *(ULONG*)(peHdr + 0x8C);
    if (!exportRva || !exportSize) return NULL;

    UCHAR* expDir = base + exportRva;
    ULONG numNames    = *(ULONG*)(expDir + 0x18);
    ULONG functionsRva = *(ULONG*)(expDir + 0x1C);
    ULONG namesRva    = *(ULONG*)(expDir + 0x20);
    ULONG ordinalsRva = *(ULONG*)(expDir + 0x24);

    ULONG*  names    = (ULONG*)(base + namesRva);
    USHORT* ordinals = (USHORT*)(base + ordinalsRva);
    ULONG*  funcs    = (ULONG*)(base + functionsRva);

    for (ULONG i = 0; i < numNames; i++) {
        const char* expName = (const char*)(base + names[i]);
        // strcmp 内核可用 (RtlCompareString 太重,自己写简单的)
        const char* a = expName;
        const char* b = Name;
        while (*a && *b && *a == *b) { a++; b++; }
        if (*a == 0 && *b == 0) {
            ULONG funcRva = funcs[ordinals[i]];
            // forwarder 检查: RVA 落在 export 区间内说明是字符串 forwarder,不是真地址
            if (funcRva >= exportRva && funcRva < exportRva + exportSize) {
                continue;
            }
            return (PVOID)(base + funcRva);
        }
    }
    return NULL;
}

// Phase L6: 加 CallerPid 参数 — SSDT fallback 需要从该进程的 ntdll 提 syscall index。
// CallerPid=0 时跳过 L6 路径(回退到 L1-L3)。
static PVOID HvHookpGetNtRoutine(PCWSTR Name, _In_opt_ ULONG CallerPid)
{
    UNICODE_STRING us;
    PVOID addr;
    SIZE_T i;

    // 路径 1: 标准 MmGetSystemRoutineAddress
    RtlInitUnicodeString(&us, Name);
    addr = MmGetSystemRoutineAddress(&us);
    if (addr) return addr;

    // 路径 2: Zw fallback (有些 Nt* 不导出但 Zw 版本导出)
    //
    // 2026-06-17 注意: Zw stub 在 ntoskrnl 中是 syscall stub (4C 8B D1 B8 .. 0F 05 C3),
    // 直接 hook Zw 的前 14-19 字节会让 trampoline 解码 syscall 指令失败 (0xC00000BB)。
    // 一旦 Zw fallback 返回, install 会失败。所以这里跳过 syscall stub 类的函数
    // (NtReadVirtualMemory/NtQueryVirtualMemory 等), 直接走 SSDT path 拿真 Nt 地址。
    //
    // 特征: stub 头是 4C 8B D1 B8 XX XX XX XX (mov r10, rcx; mov eax, imm32)
    WCHAR zwName[64];
    for (i = 0; i < (sizeof(zwName) / sizeof(WCHAR)) - 1 && Name[i]; i++) {
        zwName[i] = (i == 0 && Name[0] == L'N') ? L'Z' :
                    (i == 1 && Name[1] == L't') ? L'w' :
                    Name[i];
    }
    zwName[i] = L'\0';

    if (zwName[0] == L'Z' && zwName[1] == L'w') {
        UNICODE_STRING zwUs;
        RtlInitUnicodeString(&zwUs, zwName);
        addr = MmGetSystemRoutineAddress(&zwUs);
        if (addr) {
            // 检查是否 syscall stub (4C 8B D1 B8) - 是的话跳过, 走 SSDT 拿真 Nt
            UCHAR head[4];
            __try { RtlCopyMemory(head, addr, 4); } __except (EXCEPTION_EXECUTE_HANDLER) {
                head[0] = 0;
            }
            if (head[0] == 0x4C && head[1] == 0x8B && head[2] == 0xD1 && head[3] == 0xB8) {
                DbgPrint("[HvHook] %ws via Zw is syscall stub @ %p, skipping (will try SSDT)\n",
                         Name, addr);
                // 不直接返回, 让代码继续到 SSDT path
                addr = NULL;
            } else {
                DbgPrint("[HvHook] %ws not exported, resolved via %ws @ %p\n",
                         Name, zwName, addr);
                return addr;
            }
        }
    }

    // 路径 3: 手动 walk ntoskrnl PE EAT (MmGetSystemRoutineAddress 漏掉的名字)
    {
        char asciiName[64];
        for (i = 0; i < sizeof(asciiName) - 1 && Name[i]; i++) {
            asciiName[i] = (char)Name[i];
        }
        asciiName[i] = '\0';

        PVOID ntosBase = HvHookpFindNtoskrnlBase();
        if (ntosBase) {
            addr = HvHookpEatLookup(ntosBase, asciiName);
            if (addr) {
                DbgPrint("[HvHook] %ws resolved via EAT walk @ %p (ntoskrnl=%p)\n",
                         Name, addr, ntosBase);
                return addr;
            }

            char zwAscii[64];
            for (i = 0; i < sizeof(zwAscii) - 1 && zwName[i]; i++) {
                zwAscii[i] = (char)zwName[i];
            }
            zwAscii[i] = '\0';
            if (zwAscii[0] == 'Z' && zwAscii[1] == 'w') {
                addr = HvHookpEatLookup(ntosBase, zwAscii);
                if (addr) {
                    DbgPrint("[HvHook] %ws resolved via EAT walk %hs @ %p\n",
                             Name, zwAscii, addr);
                    return addr;
                }
            }
            DbgPrint("[HvHook] %ws not in ntoskrnl EAT (also tried %hs), trying SSDT...\n",
                     Name, zwAscii);
        }
    }

// 路径 4 (Phase L6 / Phase M3): SSDT + ntdll syscall index
//
// 2026-06-16 12:50: 再次启用真装载, 这次 EptCreateTrampoline 加完整字节 dump
//   + 解码自检, 装载时 dmesg 留下 trampoline 完整内容证据。
//
// 历史:
//   - 6/4 M3.6 诊断模式: addr 非 NULL 也返 NULL, 调查 0xD1 蓝屏的临时遗留
//   - 6/16 早段: 移除后 csrss 蓝屏 (jmp + 全 0 占位中间态), 已修 EptCreateTrampoline
//   - 6/16 中段: 再启用后 explorer 蓝屏, 不在全 0 区域但在 trampoline 池里 (短跳?)
//   - 6/16 末段: 启用 trampoline 全字节 dump + 自检, 留证据
    if (CallerPid) {
        DbgPrint("[HvHook] SSDT resolve %ws CallerPid=%u\n", Name, CallerPid);
        addr = HvHookpResolveViaSsdt(Name, CallerPid);
        if (addr) {
            UCHAR firstBytes[16] = { 0 };
            __try { RtlCopyMemory(firstBytes, addr, 16); } __except (EXCEPTION_EXECUTE_HANDLER) {}
            DbgPrint("[HvHook] %ws via SSDT @ %p first 16: "
                     "%02X %02X %02X %02X %02X %02X %02X %02X "
                     "%02X %02X %02X %02X %02X %02X %02X %02X\n",
                     Name, addr,
                     firstBytes[0], firstBytes[1], firstBytes[2], firstBytes[3],
                     firstBytes[4], firstBytes[5], firstBytes[6], firstBytes[7],
                     firstBytes[8], firstBytes[9], firstBytes[10], firstBytes[11],
                     firstBytes[12], firstBytes[13], firstBytes[14], firstBytes[15]);
            return addr;
        }
        DbgPrint("[HvHook] SSDT resolve %ws returned NULL\n", Name);
    } else {
        DbgPrint("[HvHook] %ws: CallerPid=0, SSDT fallback skipped\n", Name);
    }

    return NULL;
}

NTSTATUS HvHookEnableDebuggerProxy(_In_ ULONG CallerPid)
{
    PVOID t;
    NTSTATUS st;

    if (!g_HvHookInitialized) return STATUS_NOT_INITIALIZED;
    if (g_DebuggerProxyEnabled) return STATUS_SUCCESS;

    DbgPrint("[HvHook] Enabling debugger proxy (NtSetContextThread + Nt[R/W]VirtualMemory), CallerPid=%u\n",
             CallerPid);

    if (!g_HookNtSetContextThread) {
        t = HvHookpGetNtRoutine(L"NtSetContextThread", CallerPid);
        if (t) {
            st = HvHookInstall(t, HookedNtSetContextThread, &g_HookNtSetContextThread);
            if (NT_SUCCESS(st)) {
                DbgPrint("[HvHook] NtSetContextThread hooked at %p\n", t);
            } else {
                DbgPrint("[HvHook] HvHookInstall(NtSetContextThread) failed: 0x%X\n", st);
                g_HookNtSetContextThread = NULL;
            }
        } else {
            DbgPrint("[HvHook] NtSetContextThread not exported\n");
        }
    }

    t = HvHookpGetNtRoutine(L"NtReadVirtualMemory", CallerPid);
    if (t) {
        st = HvHookInstall(t, HookedNtReadVirtualMemory, &g_HookNtReadVirtualMemory);
        if (NT_SUCCESS(st)) {
            DbgPrint("[HvHook] NtReadVirtualMemory hooked at %p\n", t);
        } else {
            DbgPrint("[HvHook] HvHookInstall(NtReadVirtualMemory) failed: 0x%X\n", st);
            g_HookNtReadVirtualMemory = NULL;
        }
    } else {
        DbgPrint("[HvHook] NtReadVirtualMemory not exported\n");
    }

    t = HvHookpGetNtRoutine(L"NtWriteVirtualMemory", CallerPid);
    if (t) {
        st = HvHookInstall(t, HookedNtWriteVirtualMemory, &g_HookNtWriteVirtualMemory);
        if (NT_SUCCESS(st)) {
            DbgPrint("[HvHook] NtWriteVirtualMemory hooked at %p\n", t);
        } else {
            DbgPrint("[HvHook] HvHookInstall(NtWriteVirtualMemory) failed: 0x%X\n", st);
            g_HookNtWriteVirtualMemory = NULL;
        }
    } else {
        DbgPrint("[HvHook] NtWriteVirtualMemory not exported\n");
    }

    // 2026-06-18: 5 个 R3 保护补强 hook (允许部分失败, 单个失败不影响其它)
    {
        struct { PCWSTR Name; PVOID Hook; HV_HOOK_HANDLE* Handle; } extraEntries[] = {
            { L"NtReadVirtualMemoryEx", HookedNtReadVirtualMemoryEx, &g_HookNtReadVirtualMemoryEx },
            { L"NtCreateSection",       HookedNtCreateSection,       &g_HookNtCreateSection },
            { L"NtMapViewOfSection",    HookedNtMapViewOfSection,    &g_HookNtMapViewOfSection },
            { L"NtMapViewOfSectionEx",  HookedNtMapViewOfSectionEx,  &g_HookNtMapViewOfSectionEx },
            { L"NtCreateThreadEx",      HookedNtCreateThreadEx,      &g_HookNtCreateThreadEx },
            // P106 调试器线程操作 proxy (绕过反作弊在 syscall 入口装的 hook)
            { L"NtSuspendThread",       HookedNtSuspendThread,       &g_HookNtSuspendThread },
            { L"NtResumeThread",        HookedNtResumeThread,        &g_HookNtResumeThread },
            { L"NtOpenThread",          HookedNtOpenThread,          &g_HookNtOpenThread },
            { L"NtGetContextThread",    HookedNtGetContextThread,    &g_HookNtGetContextThread },
            // P121: attach 无痕 — DebugActiveProcess 后抹 PEB.BeingDebugged + NtGlobalFlag
            { L"NtDebugActiveProcess",  HookedNtDebugActiveProcess,  &g_HookNtDebugActiveProcess },
        };
        for (ULONG i = 0; i < RTL_NUMBER_OF(extraEntries); i++) {
            if (*extraEntries[i].Handle) continue;
            t = HvHookpGetNtRoutine(extraEntries[i].Name, CallerPid);
            if (!t) {
                DbgPrint("[HvHook] %ws not resolvable (可能本机 build 不支持, 跳过)\n",
                         extraEntries[i].Name);
                continue;
            }
            st = HvHookInstall(t, extraEntries[i].Hook, extraEntries[i].Handle);
            if (NT_SUCCESS(st)) {
                DbgPrint("[HvHook] %ws hooked at %p\n", extraEntries[i].Name, t);
            } else {
                DbgPrint("[HvHook] HvHookInstall(%ws) failed: 0x%X\n",
                         extraEntries[i].Name, st);
                *extraEntries[i].Handle = NULL;
            }
        }
    }

    // Phase K: NtQueryInformationProcess 由 DebuggerProxy 常驻装载
    // (从 HvHookEnableAntiAntiDebug 移出)。反向保护逻辑常态启用,
    // AAD spoof 逻辑由 g_AntiAntiDebugEnabled 控制(在 HookedNtQueryInformationProcess 内部)。
    if (!g_HookNtQueryInformationProcess) {
        t = HvHookpGetNtRoutine(L"NtQueryInformationProcess", CallerPid);
        if (t) {
            st = HvHookInstall(t, HookedNtQueryInformationProcess,
                                &g_HookNtQueryInformationProcess);
            if (NT_SUCCESS(st)) {
                DbgPrint("[HvHook] NtQueryInformationProcess hooked at %p (Phase K reverse-protect)\n", t);
            } else {
                DbgPrint("[HvHook] HvHookInstall(NtQueryInformationProcess) failed: 0x%X\n", st);
                g_HookNtQueryInformationProcess = NULL;
            }
        } else {
            DbgPrint("[HvHook] NtQueryInformationProcess not exported\n");
        }
    }

    // 2026-06-17: NtQuerySystemInformation 常态装载, 用于 SystemProcessInformation
    // 类 (5) 的进程枚举 spoof — 把 debugger 进程名改成 notepad.exe。
    if (!g_HookNtQuerySystemInformation) {
        t = HvHookpGetNtRoutine(L"NtQuerySystemInformation", CallerPid);
        if (t) {
            st = HvHookInstall(t, HookedNtQuerySystemInformation,
                                &g_HookNtQuerySystemInformation);
            if (NT_SUCCESS(st)) {
                DbgPrint("[HvHook] NtQuerySystemInformation hooked at %p (process enum spoof)\n", t);
            } else {
                DbgPrint("[HvHook] HvHookInstall(NtQuerySystemInformation) failed: 0x%X\n", st);
                g_HookNtQuerySystemInformation = NULL;
            }
        } else {
            DbgPrint("[HvHook] NtQuerySystemInformation not exported\n");
        }
    }

    // 2026-06-17: NtQueryVirtualMemory 常态装载, MemoryMappedFilenameInformation (2)
    // 拦截 — 反作弊查 debugger user VA 对应的 mapped file 路径时返回 notepad.exe。
    if (!g_HookNtQueryVirtualMemory) {
        t = HvHookpGetNtRoutine(L"NtQueryVirtualMemory", CallerPid);
        if (t) {
            st = HvHookInstall(t, HookedNtQueryVirtualMemory,
                                &g_HookNtQueryVirtualMemory);
            if (NT_SUCCESS(st)) {
                DbgPrint("[HvHook] NtQueryVirtualMemory hooked at %p (mapped-file spoof)\n", t);
            } else {
                DbgPrint("[HvHook] HvHookInstall(NtQueryVirtualMemory) failed: 0x%X\n", st);
                g_HookNtQueryVirtualMemory = NULL;
            }
        } else {
            DbgPrint("[HvHook] NtQueryVirtualMemory not exported\n");
        }
    }

    // 2026-06-17: Win32k 窗口 spoofing hooks - 反作弊枚举/查询窗口时:
    //   - NtUserQueryWindow → 改 owner PID 为 4 (System spoof)
    //   - NtUserInternalGetWindowText → 改窗口标题为 "无标题 - 记事本"
    //   - NtUserGetClassName → 改类名为 "Notepad"
    //
    // win32k SSDT 从 caller (debugger GUI 进程) 的 win32u.dll EAT 提 syscall index
    // (写死索引会跟版本漂; 动态解析最稳)。
    {
        struct { PCSTR Name; PVOID Hook; HV_HOOK_HANDLE* Handle; } w32kEntries[] = {
            { "NtUserQueryWindow",            HookedNtUserQueryWindow,
              &g_HookNtUserQueryWindow },
            { "NtUserInternalGetWindowText",  HookedNtUserInternalGetWindowText,
              &g_HookNtUserInternalGetWindowText },
            { "NtUserGetClassName",           HookedNtUserGetClassName,
              &g_HookNtUserGetClassName },
            { "NtUserFindWindowEx",           HookedNtUserFindWindowEx,
              &g_HookNtUserFindWindowEx },
            { "NtUserBuildHwndList",          HookedNtUserBuildHwndList,
              &g_HookNtUserBuildHwndList },
            { "NtUserWindowFromPoint",        HookedNtUserWindowFromPoint,
              &g_HookNtUserWindowFromPoint },
            { "NtUserChildWindowFromPointEx", HookedNtUserChildWindowFromPointEx,
              &g_HookNtUserChildWindowFromPointEx },
        };
        for (ULONG i = 0; i < RTL_NUMBER_OF(w32kEntries); i++) {
            if (*w32kEntries[i].Handle) continue;

            // 2026-06-19 优先用 EAT (win32kfull.sys 导出全 7 个 NtUser*),
            // 失败再回退 SSDT (兼容旧版本 Windows)
            PVOID target = HvHookpResolveKernelExport("win32kfull.sys", w32kEntries[i].Name);
            if (!target) {
                // 回退 SSDT
                ULONG syscallIdx = 0xFFFFFFFF;
                NTSTATUS rs = HvHookpResolveSyscallIndexInDll(
                    CallerPid, L"win32u.dll", w32kEntries[i].Name, &syscallIdx);
                if (NT_SUCCESS(rs)) {
                    target = HvHookpResolveW32KByIndex(syscallIdx);
                    if (!target) {
                        DbgPrint("[HvHook] W32K %hs: EAT fail + SSDT decode fail idx=0x%X\n",
                                 w32kEntries[i].Name, syscallIdx);
                    }
                } else {
                    DbgPrint("[HvHook] W32K %hs: EAT fail + SSDT resolve fail st=0x%X\n",
                             w32kEntries[i].Name, rs);
                }
            }
            if (!target) continue;

            st = HvHookInstall(target, w32kEntries[i].Hook, w32kEntries[i].Handle);
            if (NT_SUCCESS(st)) {
                DbgPrint("[HvHook] %hs hooked at %p\n", w32kEntries[i].Name, target);
            } else {
                DbgPrint("[HvHook] HvHookInstall(%hs @ %p) failed: 0x%X\n",
                         w32kEntries[i].Name, target, st);
                *w32kEntries[i].Handle = NULL;
            }
        }
    }

    g_DebuggerProxyEnabled = TRUE;
    return STATUS_SUCCESS;
}

VOID HvHookDisableDebuggerProxy(VOID)
{
    if (!g_HvHookInitialized || !g_DebuggerProxyEnabled) return;

    DbgPrint("[HvHook] Disabling debugger proxy\n");

    if (g_HookNtSetContextThread) {
        HvHookRemove(g_HookNtSetContextThread);
        g_HookNtSetContextThread = NULL;
    }
    if (g_HookNtReadVirtualMemory) {
        HvHookRemove(g_HookNtReadVirtualMemory);
        g_HookNtReadVirtualMemory = NULL;
    }
    if (g_HookNtWriteVirtualMemory) {
        HvHookRemove(g_HookNtWriteVirtualMemory);
        g_HookNtWriteVirtualMemory = NULL;
    }
    // 2026-06-18: 5 个 R3 保护补强 hook cleanup
    if (g_HookNtReadVirtualMemoryEx) {
        HvHookRemove(g_HookNtReadVirtualMemoryEx);
        g_HookNtReadVirtualMemoryEx = NULL;
    }
    if (g_HookNtCreateSection) {
        HvHookRemove(g_HookNtCreateSection);
        g_HookNtCreateSection = NULL;
    }
    if (g_HookNtMapViewOfSection) {
        HvHookRemove(g_HookNtMapViewOfSection);
        g_HookNtMapViewOfSection = NULL;
    }
    if (g_HookNtMapViewOfSectionEx) {
        HvHookRemove(g_HookNtMapViewOfSectionEx);
        g_HookNtMapViewOfSectionEx = NULL;
    }
    if (g_HookNtCreateThreadEx) {
        HvHookRemove(g_HookNtCreateThreadEx);
        g_HookNtCreateThreadEx = NULL;
    }
    // P106 调试器线程操作 proxy
    if (g_HookNtSuspendThread) {
        HvHookRemove(g_HookNtSuspendThread);
        g_HookNtSuspendThread = NULL;
    }
    if (g_HookNtResumeThread) {
        HvHookRemove(g_HookNtResumeThread);
        g_HookNtResumeThread = NULL;
    }
    if (g_HookNtOpenThread) {
        HvHookRemove(g_HookNtOpenThread);
        g_HookNtOpenThread = NULL;
    }
    // 注: g_HookNtGetContextThread 在下面已有移除路径 (line ~2298)
    if (g_HookNtGetContextThread) {
        HvHookRemove(g_HookNtGetContextThread);
        g_HookNtGetContextThread = NULL;
    }
    // P121: NtDebugActiveProcess
    if (g_HookNtDebugActiveProcess) {
        HvHookRemove(g_HookNtDebugActiveProcess);
        g_HookNtDebugActiveProcess = NULL;
    }
    // Phase K: NtQueryInformationProcess 由 DebuggerProxy 拥有生命周期,这里卸。
    if (g_HookNtQueryInformationProcess) {
        HvHookRemove(g_HookNtQueryInformationProcess);
        g_HookNtQueryInformationProcess = NULL;
    }
    // 2026-06-17: NtQuerySystemInformation (进程枚举 spoof)
    if (g_HookNtQuerySystemInformation) {
        HvHookRemove(g_HookNtQuerySystemInformation);
        g_HookNtQuerySystemInformation = NULL;
    }
    // 2026-06-17: NtQueryVirtualMemory (mapped-file spoof)
    if (g_HookNtQueryVirtualMemory) {
        HvHookRemove(g_HookNtQueryVirtualMemory);
        g_HookNtQueryVirtualMemory = NULL;
    }
    // 2026-06-17: win32k window-enum spoofs
    if (g_HookNtUserQueryWindow) {
        HvHookRemove(g_HookNtUserQueryWindow);
        g_HookNtUserQueryWindow = NULL;
    }
    if (g_HookNtUserInternalGetWindowText) {
        HvHookRemove(g_HookNtUserInternalGetWindowText);
        g_HookNtUserInternalGetWindowText = NULL;
    }
    if (g_HookNtUserGetClassName) {
        HvHookRemove(g_HookNtUserGetClassName);
        g_HookNtUserGetClassName = NULL;
    }
    if (g_HookNtUserFindWindowEx) {
        HvHookRemove(g_HookNtUserFindWindowEx);
        g_HookNtUserFindWindowEx = NULL;
    }
    // 2026-06-19: NtUserBuildHwndList hook (hwnd 列表过滤)
    if (g_HookNtUserBuildHwndList) {
        HvHookRemove(g_HookNtUserBuildHwndList);
        g_HookNtUserBuildHwndList = NULL;
    }
    // 2026-06-19: NtUserWindowFromPoint 族 (Spy++ 拖拽防护)
    if (g_HookNtUserWindowFromPoint) {
        HvHookRemove(g_HookNtUserWindowFromPoint);
        g_HookNtUserWindowFromPoint = NULL;
    }
    if (g_HookNtUserChildWindowFromPointEx) {
        HvHookRemove(g_HookNtUserChildWindowFromPointEx);
        g_HookNtUserChildWindowFromPointEx = NULL;
    }

    g_DebuggerProxyEnabled = FALSE;
}

// ============================================================
// 阶段 7.9: NtOpenProcess 访问控制 bypass
// ============================================================
//
// 目的:
//   让 IOCTL_HV_ADD_DEBUGGER 注册的 debugger 进程,能成功对配对的
//   IOCTL_HV_PROTECT_PROCESS 受保护进程调用 NtOpenProcess —— 即便目标是
//   PsProtectedProcess (PPL: System=4 / csrss / lsass / MsMpEng)。
//
//   debugger-proxy (NtSetContextThread / Nt[R/W]VirtualMemory) 生效的前提
//   是 caller 已经持有 valid handle。对 PPL 目标,handle 在 NtOpenProcess
//   就被 PspCheckForInvalidAccessByProtectionLevel 拒了,proxy hook 永远没
//   机会触发。补这一道,链条接通。
//
// 路径:
//   1. EPT-hook NtOpenProcess (走 HvHookInstall,PG-immune)
//   2. caller ∈ debugger 白名单 AND Cid.UniqueProcess == 该 debugger
//      registered 的 protected target 时才进 bypass (严格配对)
//   3. KMUTEX 串行化下:目标 EPROCESS.Protection 字段 backup → 抹零
//      → ObOpenObjectByPointer(KernelMode) → 立即 restore
//      - KernelMode 跳过 SeAccessCheck
//      - KernelMode + ObOpenObjectByPointer 路径天然不进 Ob callback
//      - Protection=0 绕过 PspCheckForInvalidAccessByProtectionLevel
//      窗口 < 1μs,撞 PG 扫描 (5-15 min/扫,扫描时长 μs 级) 概率 ~2e-10
//   4. HandleAttributes=0 → handle 直落 caller 的 handle table,免 Duplicate
//
// EPROCESS.Protection 偏移:
//   Win10 20H1 ~ Win11 23H2 = 0x87A
//   Win11 24H2 待验证 (大约 0xA88,需 PR 时同步)

#define EPROCESS_PROTECTION_OFFSET   0x87A

// ObOpenObjectByPointer 已在 HvHookTerminateAllDebuggers 前面 extern 声明,
// 这里保留注释作为读者的导航参考。

// Phase K: SYSTEM token impersonate (DDK exported,绕过 SeAccessCheck 用)
NTKERNELAPI NTSTATUS PsImpersonateClient(
    _In_     PETHREAD                      Thread,
    _In_opt_ PACCESS_TOKEN                 Token,
    _In_     BOOLEAN                       CopyOnOpen,
    _In_     BOOLEAN                       EffectiveOnly,
    _In_     SECURITY_IMPERSONATION_LEVEL  ImpersonationLevel
);

NTKERNELAPI VOID PsRevertToSelf(VOID);

NTKERNELAPI PACCESS_TOKEN PsReferencePrimaryToken(_Inout_ PEPROCESS Process);

NTKERNELAPI VOID PsDereferencePrimaryToken(_In_ PACCESS_TOKEN PrimaryToken);

static HV_HOOK_HANDLE g_HookNtOpenProcess        = NULL;
static HV_HOOK_HANDLE g_HookNtGetNextProcess     = NULL;
// 2026-06-19: debugger image 文件防护 hook 组
static HV_HOOK_HANDLE g_HookNtCreateFile         = NULL;
static HV_HOOK_HANDLE g_HookNtOpenFile           = NULL;
static HV_HOOK_HANDLE g_HookNtReadFile           = NULL;
// 2026-06-19: NtDuplicateObject hook (handle 偷渡防护, ObCallback 第二道兜底)
static HV_HOOK_HANDLE g_HookNtDuplicateObject    = NULL;
static BOOLEAN        g_AccessBypassEnabled      = FALSE;
// 串行化 EPROCESS.Protection 抹零/恢复 (整个 strip→Original→restore 窗口)。
// 调 Original NtOpenProcess 走标准 user-mode 路径,IRQL=PASSIVE_LEVEL,可用 KMUTEX。
static KMUTEX         g_ProtectionStripMutex;
static BOOLEAN        g_ProtectionStripMutexInit = FALSE;

typedef NTSTATUS (NTAPI *PFN_NtOpenProcess)(
    PHANDLE            ProcessHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID         ClientId
);

static NTSTATUS NTAPI
HookedNtOpenProcess(
    PHANDLE            ProcessHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID         ClientId
)
{
    PFN_NtOpenProcess Original =
        (PFN_NtOpenProcess)HvHookGetTrampoline(g_HookNtOpenProcess);
    if (!Original) {
        return STATUS_UNSUCCESSFUL;
    }

    // 2026-06-16 诊断 bypass
    if (g_BypassNtOpenProcess) {
        return Original(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
    }

    // M3 修正: IRQL > APC_LEVEL 走 Original 避免 0xD1
    // (KeWaitForSingleObject / PsLookupProcessByProcessId 都要求 IRQL <= APC_LEVEL)
    if (KeGetCurrentIrql() > APC_LEVEL) {
        return Original(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
    }

    HANDLE caller = PsGetCurrentProcessId();

    // Phase K: 解析 target PID 提前到入口,反向保护需要 (不依赖 caller=debugger)
    KPROCESSOR_MODE prevMode = ExGetPreviousMode();
    HANDLE targetPidFromCid = NULL;
    if (ClientId && ProcessHandle) {
        __try {
            if (prevMode == UserMode) {
                ProbeForRead(ClientId, sizeof(CLIENT_ID), sizeof(ULONG));
            }
            targetPidFromCid = ClientId->UniqueProcess;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            targetPidFromCid = NULL;
        }
    }

    // 2026-06-18: 合并 — 隐藏列表过滤
    //
    // 历史: 以前 EptHook.c::HookedNtOpenProcess 装第二个 EPT hook 在同一物理页处理
    // "进程隐藏" (IOCTL_HV_HIDE_PROCESS) 语义, 与本 hook 冲突 0xC0000718。
    //
    // 合并: 这里查 IsProcessHiddenById (EptHook.h), target 在隐藏列表 → INVALID_CID。
    // ADD_DEBUGGER + Hide=1 时, debugger 会同时进 protected list 和 hidden list,
    // 这里命中也等同于反向保护。
    if (targetPidFromCid && caller != targetPidFromCid &&
        IsProcessHiddenById((ULONG)(ULONG_PTR)targetPidFromCid))
    {
        HV_HOT_DBG("[HvHook-TRACE] NtOpenProcess HIT hidden-list: caller=%u target=%u → INVALID_CID\n",
                 (ULONG)(ULONG_PTR)caller, (ULONG)(ULONG_PTR)targetPidFromCid);
        if (ProcessHandle) {
            __try {
                if (prevMode == UserMode) {
                    ProbeForWrite(ProcessHandle, sizeof(HANDLE), sizeof(HANDLE));
                }
                *ProcessHandle = NULL;
            } __except (EXCEPTION_EXECUTE_HANDLER) { }
        }
        return STATUS_INVALID_CID;
    }

    // Phase K 反向保护 (2026-06-16 升级到"放行+喂假数据"语义):
    //
    // 不再在 NtOpenProcess 阶段拒绝 — 那样会让安全工具立刻警觉(看到 ACCESS_DENIED
    // 知道有内核驱动干预)。改为放行所有 NtOpenProcess(包括 PROCESS_VM_READ 等敏感
    // access mask), 在后续的 NtReadVirtualMemory / NtWriteVirtualMemory 层做手脚:
    //   - 外部读 debugger 内存 → 返回 SUCCESS + buffer 全 0 (没有业务数据可看)
    //   - 外部写 debugger 内存 → 返回 SUCCESS 但不实际写 (写入"消失")
    //
    // 这样:
    //   - taskmgr / SysInternals / ProcessHacker 看 debugger 元数据完全正常
    //   - CE / 反作弊 / 杀毒扫描 debugger 内存只看到 0, 看不到真实数据
    //   - 没有任何 ACCESS_DENIED 异常 — 调用方以为一切正常, 不警觉
    //
    // caller=debugger 自身 / caller=trusted (系统服务) 不受影响, 真实访问。

    // 不是 debugger 发起 → 检查是否反作弊在开 debugger
    if (!HvHookIsDebuggerPid(caller) || !ClientId || !ProcessHandle ||
        !targetPidFromCid)
    {
        // 2026-06-18: 反向保护 — 外部进程试图打开 debugger 时拒绝
        //
        // 老逻辑: 直接走 Original → 反作弊拿到 debugger handle 就赢一半:
        //   1. 即使 NtRead 我们喂 0, ACE 拿到 handle 就知道"这个 PID 存在且可访问"
        //   2. ACE 可以 GetProcessId / QueryFullProcessImageName 拿真路径
        //   3. ACE 可以 NtDuplicateObject 偷给别的进程
        //   4. ACE 可以查我们没拦的 NtQueryInformationProcess class
        //
        // 新逻辑: caller=外部 + target=debugger + caller!=target
        //   → 返回 STATUS_INVALID_CID (假装目标进程不存在)
        //
        // 2026-06-18 简化: 不再检查 HvHookIsTrustedSystemCaller (有 PsLookup 风险),
        // 任何 caller!=target 的外部进程都拒绝 — 代价是 taskmgr 看 debugger 显示
        // 失败, 但好处是 100% 挡住反作弊 (它无论伪装成什么名字都拦得住)。
        if (targetPidFromCid &&
            HvHookIsDebuggerPid(targetPidFromCid) &&
            caller != targetPidFromCid)
        {
            // 2026-06-18 强制诊断: 永远 dump, 即使最终走 Original 也能看到命中
            HV_HOT_DBG("[HvHook-Spoof] NtOpenProcess HIT reverse-protect: caller=%u target=%u "
                     "access=0x%X → returning STATUS_INVALID_CID\n",
                     (ULONG)(ULONG_PTR)caller, (ULONG)(ULONG_PTR)targetPidFromCid,
                     DesiredAccess);
            // 把 ProcessHandle 写 NULL (调用方不会再用它)
            __try {
                if (prevMode == UserMode) {
                    ProbeForWrite(ProcessHandle, sizeof(HANDLE), sizeof(HANDLE));
                }
                *ProcessHandle = NULL;
            } __except (EXCEPTION_EXECUTE_HANDLER) { }
            return STATUS_INVALID_CID;
        }
        return Original(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
    }

    // 全权限语义:caller 是注册的 debugger → 对任意 user/PPL/System(4) target 放行。
    // PID=0 (Idle) 会在 PsLookupProcessByProcessId 失败,自然回退 Original。
    PEPROCESS target = NULL;
    NTSTATUS lookSt = PsLookupProcessByProcessId(targetPidFromCid, &target);
    if (!NT_SUCCESS(lookSt) || !target) {
        return Original(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
    }

    // ============================================================
    // Phase M1 v2 (2026-06-04): Token swap (不用 PsImpersonateClient / KeStackAttachProcess)
    //
    // 之前两个尝试的失败原因:
    //   - PsImpersonateClient 在 KVA shadow + 嵌套 hook 路径疑似蓝屏
    //   - KeStackAttachProcess 切 CR3 后 user buffer (ProcessHandle*) 解引用会出错
    //
    // 新方式:**临时替换 caller 进程自身的 Token 字段** (EPROCESS.Token),
    // 让 Original 内部 SeAccessCheck 用 SYSTEM token,但当前线程 / 当前进程 / CR3
    // 都不变,user buffer 写回正常。
    //
    // EPROCESS.Token 是 EX_FAST_REF (低 4 bits 是引用计数,需要保留),
    // 所以替换时只换高位指针,低 4 bits 保留原有 ref count。
    //
    // EPROCESS.Token 偏移 (Win10 1709+ / Win11 全系):0x4B8
    //   Win10 19045: 0x4B8 (实测)
    //   Win11 24H2: 0x4B8 (实测)
    // 跨版本相对稳定。如果不对,SeAccessCheck 会用 caller 原 token,行为同 baseline。
    //
    // KMUTEX 已包住 strip+restore,Token swap 也加进来,串行无 race。
    // ============================================================
    PUCHAR protectionField = (PUCHAR)target + EPROCESS_PROTECTION_OFFSET;
    #define EPROCESS_TOKEN_OFFSET 0x4B8

    KeWaitForSingleObject(&g_ProtectionStripMutex, Executive, KernelMode,
                          FALSE, NULL);

    UCHAR savedProtection = *protectionField;
    *protectionField = 0;

    // Token swap 准备
    PEPROCESS callerProc = PsGetCurrentProcess();
    PEPROCESS sysProc = NULL;
    ULONG_PTR savedCallerTokenRef = 0;
    BOOLEAN tokenSwapped = FALSE;

    if (callerProc &&
        NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)4, &sysProc)) && sysProc)
    {
        // EPROCESS.Token 是 EX_FAST_REF (8 字节, 低 4 bits 是 ref count)
        // 直接当 ULONG_PTR 操作:高位是指针,低 4 bits 是 ref count
        ULONG_PTR* callerTokenSlot = (ULONG_PTR*)((PUCHAR)callerProc + EPROCESS_TOKEN_OFFSET);
        ULONG_PTR* sysTokenSlot    = (ULONG_PTR*)((PUCHAR)sysProc    + EPROCESS_TOKEN_OFFSET);

        savedCallerTokenRef = *callerTokenSlot;

        // 把 SYSTEM 的 token 指针写到 caller 的 token slot (保留 caller 原 ref count low 4 bits)
        ULONG_PTR sysTokenPtr = (*sysTokenSlot) & ~0xFULL;          // 高位指针部分
        ULONG_PTR callerRefCount = savedCallerTokenRef & 0xFULL;    // 原 ref count
        *callerTokenSlot = sysTokenPtr | callerRefCount;
        tokenSwapped = TRUE;
    }

    NTSTATUS openSt = Original(ProcessHandle, DesiredAccess,
                               ObjectAttributes, ClientId);

    // 恢复 caller token
    if (tokenSwapped) {
        ULONG_PTR* callerTokenSlot = (ULONG_PTR*)((PUCHAR)callerProc + EPROCESS_TOKEN_OFFSET);
        *callerTokenSlot = savedCallerTokenRef;
    }
    if (sysProc) {
        ObDereferenceObject(sysProc);
    }

    *protectionField = savedProtection;

    KeReleaseMutex(&g_ProtectionStripMutex, FALSE);
    ObDereferenceObject(target);

    if (!NT_SUCCESS(openSt)) {
        DbgPrint("[HvHook] bypass open failed: caller=%u target=%u status=0x%X\n",
                 (ULONG)(ULONG_PTR)caller,
                 (ULONG)(ULONG_PTR)targetPidFromCid,
                 openSt);
        HvDbgEvtPost(HV_DBGEVT_SEV_ERROR, HV_DBGEVT_CAT_OPEN_PROCESS, openSt,
                     (ULONG)(ULONG_PTR)caller,
                     (ULONG)(ULONG_PTR)targetPidFromCid,
                     DesiredAccess, 0,
                     "NtOpenProcess: Original returned non-success after Protection strip");
        // Original 失败时它没写 ProcessHandle,直接把 status 返给 caller。
        return openSt;
    }

    HV_HOT_DBG("[HvHook] bypass open ok: caller=%u target=%u (user handle written by Original)\n",
             (ULONG)(ULONG_PTR)caller,
             (ULONG)(ULONG_PTR)targetPidFromCid);
    HvDbgEvtPost(HV_DBGEVT_SEV_INFO, HV_DBGEVT_CAT_OPEN_PROCESS, STATUS_SUCCESS,
                 (ULONG)(ULONG_PTR)caller,
                 (ULONG)(ULONG_PTR)targetPidFromCid,
                 DesiredAccess, 0,
                 "NtOpenProcess bypass OK (user handle)");
    return STATUS_SUCCESS;
}

// ============================================================
// NtGetNextProcess hook (2026-06-19)
//
// 关掉 g_BypassNtOpenProcess 之后, R3 攻击者 (CE / EAC) 会改走 NtGetNextProcess
// 枚举进程链表 — 这条路径不经过 NtOpenProcess, 不带 ClientId, 我们的反向保护
// 完全失效。
//
// 语义: NtGetNextProcess(ParentHandle=NULL/PrevHandle, Access, Attr, Flags, &OutHandle)
//       返回链表里下一个进程的 handle, 调用方循环调直到 STATUS_NO_MORE_ENTRIES。
//
// 策略: 调 Original → 解析返回 handle 的 PID → 命中 debugger 列表 (caller 不是
//       debugger 自身) → 关 handle, 返回 STATUS_NO_MORE_ENTRIES (伪装链表到此结束)。
//       不返回 ACCESS_DENIED, 不让调用方察觉有内核干预; 代价是 debugger 之后的
//       进程它也看不到 (取舍详见下方注释)。
// ============================================================
typedef NTSTATUS (NTAPI *PFN_NtGetNextProcess)(
    HANDLE              ProcessHandle,    // prev process handle (NULL = start)
    ACCESS_MASK         DesiredAccess,
    ULONG               HandleAttributes,
    ULONG               Flags,
    PHANDLE             NewProcessHandle
);

static NTSTATUS NTAPI
HookedNtGetNextProcess(
    HANDLE        ProcessHandle,
    ACCESS_MASK   DesiredAccess,
    ULONG         HandleAttributes,
    ULONG         Flags,
    PHANDLE       NewProcessHandle
)
{
    PFN_NtGetNextProcess Original =
        (PFN_NtGetNextProcess)HvHookGetTrampoline(g_HookNtGetNextProcess);
    if (!Original) return STATUS_UNSUCCESSFUL;

    // IRQL > APC_LEVEL: ObReferenceObjectByHandle 要求 <= APC_LEVEL, 直接放行
    if (KeGetCurrentIrql() > APC_LEVEL) {
        return Original(ProcessHandle, DesiredAccess, HandleAttributes, Flags, NewProcessHandle);
    }

    HANDLE caller = PsGetCurrentProcessId();

    // caller 是 debugger 自身 → 直接放行真实结果
    if (HvHookIsDebuggerPid(caller)) {
        return Original(ProcessHandle, DesiredAccess, HandleAttributes, Flags, NewProcessHandle);
    }

    KPROCESSOR_MODE prevMode = ExGetPreviousMode();

    // 1. 校验 user buffer 可写
    if (NewProcessHandle && prevMode == UserMode) {
        __try {
            ProbeForWrite(NewProcessHandle, sizeof(HANDLE), sizeof(HANDLE));
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return GetExceptionCode();
        }
    }

    // 2. 调 Original, 解析返回的 handle 对应的 PID
    //
    // 设计取舍: 这里采用"命中 debugger 即返回 STATUS_NO_MORE_ENTRIES"的简单策略。
    //
    // 为什么不"跳过 debugger 继续枚举": NtGetNextProcess 用 prev handle 作为锚点
    // 找链表下一个, 我们关掉刚拿到的 debugger handle 后就没法用它当 prev (handle
    // 已无效, Original 会 ACCESS_DENIED)。如果先复制一份用于 prev、循环末再关,
    // 攻击者可以从 handle 数量异常推断我们在过滤。
    //
    // 代价: 攻击者枚举到 debugger 时会以为链表到此结束, 后面的真实进程它也看不到。
    // 收益: 攻击者拿不到 debugger handle, 而且没有 ACCESS_DENIED 告警。
    HANDLE localOut = NULL;
    NTSTATUS st = Original(ProcessHandle, DesiredAccess, HandleAttributes, Flags, &localOut);

    if (NT_SUCCESS(st) && localOut) {
        HANDLE outPid = HvHookpProcessHandleToProcessId(localOut);
        if (outPid && HvHookIsDebuggerPid(outPid)) {
            HV_HOT_DBG("[HvHook-Spoof] NtGetNextProcess HIT debugger: caller=%u target=%u → NO_MORE_ENTRIES\n",
                     (ULONG)(ULONG_PTR)caller, (ULONG)(ULONG_PTR)outPid);
            ZwClose(localOut);
            localOut = NULL;
            st = STATUS_NO_MORE_ENTRIES;
        }
    }

    // 3. 写回 user buffer
    if (NewProcessHandle) {
        __try {
            *NewProcessHandle = localOut;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            if (localOut) ZwClose(localOut);
            return GetExceptionCode();
        }
    } else if (localOut) {
        ZwClose(localOut);
    }

    return st;
}

// ============================================================
// 2026-06-19: NtDuplicateObject hook — handle 偷渡防护
// ============================================================
//
// 背景: ObRegisterCallbacks 已覆盖 OB_OPERATION_HANDLE_DUPLICATE, access mask 会被
// strip 到 0 — 但有边角情况:
//   1) DUPLICATE_SAME_ACCESS flag 让 access 来自 source, 我们 Pre callback 看到的
//      DuplicateHandleInformation.DesiredAccess 可能已是源 access, strip 后内核仍
//      用源 access? (实测路径不全明确, 安全起见加二道防护)
//   2) target 是 thread handle (PsThreadType) — 我们 ObCallback 只注册 PsProcessType,
//      thread handle 复制不被拦, 但攻击者拿 debugger thread handle 后能 NtGetContextThread,
//      照样读 debugger 寄存器
//   3) DUPLICATE_CLOSE_SOURCE flag 会先关 source handle 再复制 → 探测我们的拦截行为
//
// 策略: caller≠debugger/trusted + (source handle 解析后是 debugger 进程/线程) → 拒
//
// 解析 source handle: NtDuplicateObject 的 SourceProcessHandle 不一定是 caller process,
// 可能是别的 process handle。我们需要:
//   a) ObReferenceObjectByHandle(SourceProcessHandle) 拿 sourceProc EPROCESS
//   b) KeStackAttachProcess 切到 sourceProc, ObReferenceObjectByHandle(SourceHandle)
//      拿源对象
//   c) 检查源对象的 ObjectType (Process/Thread) 和 owner PID
//
// 简化: 实际反作弊 99% 用 source=NtCurrentProcess()=GetCurrentProcess() pseudo handle,
// 即 source handle 在 caller 自己的 handle table 里。我们只对这种简单情况判断,
// 其他复杂场景 ObCallback 兜底。
// ============================================================
typedef NTSTATUS (NTAPI *PFN_NtDuplicateObject)(
    HANDLE       SourceProcessHandle,
    HANDLE       SourceHandle,
    HANDLE       TargetProcessHandle,
    PHANDLE      TargetHandle,
    ACCESS_MASK  DesiredAccess,
    ULONG        HandleAttributes,
    ULONG        Options
);

// PsThreadType 由 ntddk.h 声明, 无需重复 extern
// PsGetThreadProcessId 由 ntddk.h 声明

static NTSTATUS NTAPI HookedNtDuplicateObject(
    HANDLE       SourceProcessHandle,
    HANDLE       SourceHandle,
    HANDLE       TargetProcessHandle,
    PHANDLE      TargetHandle,
    ACCESS_MASK  DesiredAccess,
    ULONG        HandleAttributes,
    ULONG        Options
)
{
    PFN_NtDuplicateObject Original =
        (PFN_NtDuplicateObject)HvHookGetTrampoline(g_HookNtDuplicateObject);
    if (!Original) return STATUS_UNSUCCESSFUL;

    if (KeGetCurrentIrql() > APC_LEVEL) {
        return Original(SourceProcessHandle, SourceHandle, TargetProcessHandle,
                        TargetHandle, DesiredAccess, HandleAttributes, Options);
    }

    HANDLE caller = PsGetCurrentProcessId();
    if (HvHookIsDebuggerPid(caller) || HvHookIsTrustedSystemCaller(caller)) {
        return Original(SourceProcessHandle, SourceHandle, TargetProcessHandle,
                        TargetHandle, DesiredAccess, HandleAttributes, Options);
    }

    // 解析 SourceHandle 指向的对象 — 大部分情况 SourceProcessHandle = NtCurrentProcess()
    // (-1 / pseudo handle), source handle 在 caller table 里; 用 KernelMode 强制解析
    // 避免 access check, 我们只看 PID 不动对象。
    BOOLEAN block = FALSE;
    HANDLE targetOwnerPid = NULL;
    const WCHAR *targetType = L"?";

    // 先按 Process handle 试
    PEPROCESS proc = NULL;
    if (NT_SUCCESS(ObReferenceObjectByHandle(SourceHandle, 0, *PsProcessType,
                                              KernelMode, (PVOID*)&proc, NULL)) && proc)
    {
        targetOwnerPid = PsGetProcessId(proc);
        targetType = L"Process";
        ObDereferenceObject(proc);
    } else {
        // Process 失败, 试 Thread handle
        PETHREAD thr = NULL;
        if (NT_SUCCESS(ObReferenceObjectByHandle(SourceHandle, 0, *PsThreadType,
                                                  KernelMode, (PVOID*)&thr, NULL)) && thr)
        {
            targetOwnerPid = PsGetThreadProcessId(thr);
            targetType = L"Thread";
            ObDereferenceObject(thr);
        }
    }

    if (targetOwnerPid && HvHookIsDebuggerPid(targetOwnerPid)) {
        block = TRUE;
    }

    if (block) {
        HV_HOT_DBG("[HvHook-Spoof] NtDuplicateObject BLOCK: caller=%u source=%ws owner=%u "
                 "access=0x%X → INVALID_HANDLE\n",
                 (ULONG)(ULONG_PTR)caller, targetType,
                 (ULONG)(ULONG_PTR)targetOwnerPid, DesiredAccess);
        KPROCESSOR_MODE prevMode = ExGetPreviousMode();
        if (TargetHandle) {
            __try {
                if (prevMode == UserMode) {
                    ProbeForWrite(TargetHandle, sizeof(HANDLE), sizeof(HANDLE));
                }
                *TargetHandle = NULL;
            } __except (EXCEPTION_EXECUTE_HANDLER) { }
        }
        return STATUS_INVALID_HANDLE;
    }

    return Original(SourceProcessHandle, SourceHandle, TargetProcessHandle,
                    TargetHandle, DesiredAccess, HandleAttributes, Options);
}

// ============================================================
// 2026-06-19: ObRegisterCallbacks(PsProcessType) — 内核层 OpenProcess 防护
// ============================================================
//
// 背景: NtOpenProcess hook 只挡 syscall 入口。反作弊驱动可以走:
//   - ObReferenceObjectByName + ObOpenObjectByPointer (绕开 NtOpenProcess)
//   - PsLookupProcessByProcessId + ObOpenObjectByPointer
//   - 读 PsActiveProcessHead 链表后 ObReferenceObject
//   - NtDuplicateObject 偷 trusted handle
// 这些路径**全部**汇集到 ObCreateHandle → SeAccessCheck。Pre callback 在 SeAccessCheck
// 之前被调,我们把 DesiredAccess strip 到 0,SeAccessCheck 必然失败 (任何 ACCESS_MASK
// 都不能用 0 bits 通过 SACL/DACL 检查),内核合法地返 STATUS_ACCESS_DENIED — 反作弊
// 看到的是"权限不够",而不是"被 hook 拦了"。
//
// 覆盖范围: HANDLE_CREATE (新建 handle) + HANDLE_DUPLICATE (NtDuplicateObject 直送)。
// 后者顺带把 NtDuplicateObject 偷 handle 路径也堵了 — 不需要单独 hook NtDuplicateObject。
//
// 注意:
//   - ObRegisterCallbacks 要求 driver 用 IMAGE_FILE_RUNNING_KERNEL_DEBUGGER + 合规签名
//     Netr 已签名 (build 输出 "Successfully signed"), 满足要求
//   - PG 不扫 callback list, 长期驻留安全
//   - 反作弊可用 ObGetFilterVersion 探测我们注册了 callback (无法隐藏), 但反正比让
//     它直接拿 handle 强 — 它能知道有内核监督, 但拿不到 handle 仍然无法读 debugger
//   - 反作弊也可调 ObUnRegisterCallbacks 卸我们 (要拿 RegistrationHandle 但它扫不到)
// ============================================================

static PVOID g_ObCallbackRegistration = NULL;

// 完整 PROCESS_ALL_ACCESS / THREAD_ALL_ACCESS (Win10+ 实际值)
#define HV_PROCESS_ALL_ACCESS_FULL (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xFFFF)
#define HV_THREAD_ALL_ACCESS_FULL  (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xFFFF)

static OB_PREOP_CALLBACK_STATUS HvHookObPreCallback(
    _In_ PVOID RegistrationContext,
    _In_ POB_PRE_OPERATION_INFORMATION Info)
{
    UNREFERENCED_PARAMETER(RegistrationContext);

    // KernelHandle = TRUE 表示 driver 自己请求, 不拦
    if (Info->KernelHandle) return OB_PREOP_SUCCESS;

    BOOLEAN isProcess = (Info->ObjectType == *PsProcessType);
    BOOLEAN isThread  = (Info->ObjectType == *PsThreadType);
    if (!isProcess && !isThread) return OB_PREOP_SUCCESS;

    // 拿 target PID. 线程对象走 PsGetThreadProcessId(PETHREAD)
    HANDLE targetPid = NULL;
    if (isProcess) {
        targetPid = PsGetProcessId((PEPROCESS)Info->Object);
    } else {
        targetPid = PsGetThreadProcessId((PETHREAD)Info->Object);
    }
    HANDLE caller = PsGetCurrentProcessId();

    PACCESS_MASK access = NULL;
    switch (Info->Operation) {
    case OB_OPERATION_HANDLE_CREATE:
        access = &Info->Parameters->CreateHandleInformation.DesiredAccess;
        break;
    case OB_OPERATION_HANDLE_DUPLICATE:
        access = &Info->Parameters->DuplicateHandleInformation.DesiredAccess;
        break;
    default:
        return OB_PREOP_SUCCESS;
    }
    if (!access) return OB_PREOP_SUCCESS;

    // ========== 反向保护: 外人开/dup debugger handle → 剥权 ==========
    if (targetPid && HvHookIsDebuggerPid(targetPid)) {
        // caller=target (debugger 自己) / debugger / trusted → 不剥
        if (caller != targetPid && !HvHookIsDebuggerPid(caller) &&
            !HvHookIsTrustedSystemCaller(caller))
        {
            ULONG orig = *access;
            *access &= (SYNCHRONIZE | READ_CONTROL | 0x1000);
            if (orig != *access) {
                HV_HOT_DBG("[HvHook-Spoof] ObCallback strip access: caller=%u target=%u op=%u "
                         "orig=0x%X -> 0x%X (type=%s)\n",
                         (ULONG)(ULONG_PTR)caller, (ULONG)(ULONG_PTR)targetPid,
                         Info->Operation, orig, *access, isProcess ? "PROC" : "THREAD");
            }
        }
        return OB_PREOP_SUCCESS;
    }

    // ========== 正向赋权: 任意 user-mode caller 开 target → access mask 升级 ==========
    //
    // 反作弊 Ob callback 在它的 debugger handle 时剥权 (去掉 SUSPEND_RESUME / WRITE 等).
    // 我们 altitude 比反作弊小, **后跑**, 把 access 加回来. 反作弊看不到我们的存在, 也无法再改.
    //
    // 这里默认对**任何 user caller** 升级 — 让外部 CE/x64dbg/ProcessHacker 这种没和我们
    // driver 对接的调试器也透明受益. trusted system caller (Defender/svchost 等) 不动,
    // 让系统服务的细粒度权限协商保持原样.
    if (caller && !HvHookIsTrustedSystemCaller(caller) && targetPid != NULL) {
        // 不动 caller=target 自己 (一般已经全权限)
        // 不动 target=System(4) (kernel handle 走 KernelHandle 分支已 return)
        if (caller != targetPid && (ULONG_PTR)targetPid != 4) {
            ULONG before = *access;
            ACCESS_MASK want = isProcess ? HV_PROCESS_ALL_ACCESS_FULL : HV_THREAD_ALL_ACCESS_FULL;
            // 只升级被反作弊削掉的位 (OR 进去), 不动 caller 已经表达的语义
            *access |= want;
            if (before != *access) {
                // 不每条都打 — 调用太频繁日志会爆. 只在 caller 是 debugger 时打.
                if (HvHookIsDebuggerPid(caller)) {
                    HV_HOT_DBG("[HvHook-Restore] caller=%u target=%u op=%u %s "
                             "before=0x%X -> 0x%X (god-mode access restore)\n",
                             (ULONG)(ULONG_PTR)caller, (ULONG)(ULONG_PTR)targetPid,
                             Info->Operation, isProcess ? "PROC" : "THREAD", before, *access);
                }
            }
        }
    }
    return OB_PREOP_SUCCESS;
}

static NTSTATUS HvHookpRegisterObCallback(VOID)
{
    if (g_ObCallbackRegistration) return STATUS_SUCCESS;

    // 同时注册 Process + Thread, 共用 HvHookObPreCallback (内部按 Info->ObjectType 分流)
    OB_OPERATION_REGISTRATION operations[2];
    operations[0].ObjectType = PsProcessType;
    operations[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    operations[0].PreOperation = HvHookObPreCallback;
    operations[0].PostOperation = NULL;
    operations[1].ObjectType = PsThreadType;
    operations[1].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    operations[1].PreOperation = HvHookObPreCallback;
    operations[1].PostOperation = NULL;

    OB_CALLBACK_REGISTRATION reg = { 0 };
    reg.Version = OB_FLT_REGISTRATION_VERSION;
    reg.OperationRegistrationCount = 2;
    // 关键: altitude 选很小 (但大于 Filter 最小值 = 用 5 位以上).
    // pre callback 调用顺序 = altitude 倒序 (大的先跑). 反作弊一般 320000~389999,
    // 我们设 "10000.5" → 我们 **最后** 跑 → 反作弊已经剥过 access, 我们 OR 加回来,
    // 之后没有 callback 能再改, Ob 用我们写回的 mask 给 handle.
    RtlInitUnicodeString(&reg.Altitude, L"10000.5");
    reg.RegistrationContext = NULL;
    reg.OperationRegistration = operations;

    NTSTATUS st = ObRegisterCallbacks(&reg, &g_ObCallbackRegistration);
    if (NT_SUCCESS(st)) {
        DbgPrint("[HvHook] ObRegisterCallbacks OK (Process+Thread, altitude=10000.5): handle=%p\n",
                 g_ObCallbackRegistration);
    } else {
        DbgPrint("[HvHook] ObRegisterCallbacks failed: 0x%X (non-fatal)\n", st);
        g_ObCallbackRegistration = NULL;
    }
    return st;
}

static VOID HvHookpUnregisterObCallback(VOID)
{
    if (g_ObCallbackRegistration) {
        ObUnRegisterCallbacks(g_ObCallbackRegistration);
        g_ObCallbackRegistration = NULL;
        DbgPrint("[HvHook] ObUnRegisterCallbacks done\n");
    }
}

// ============================================================
// 2026-06-19: Debugger image 文件防护 (NtCreateFile / NtOpenFile / NtReadFile)
// ============================================================
//
// 背景: CE/EAC 不只通过进程 handle 检测调试器, 还会:
//   1) 直接 NtCreateFile/NtOpenFile 打开磁盘上的 .exe 算哈希 → 对照已知 hacker tool
//   2) 扫 PE 字符串 ("CHEAT ENGINE", "Olly", "x64dbg") 识别
//   3) ReadFile 自己的镜像和系统位置的 notepad.exe 比对
// 我们已经把 debugger 进程名伪装成 notepad.exe, 但磁盘文件本体的字节是真实编译产物,
// 哈希 / 字符串扫描立刻穿帮。
//
// 防御:
//   - NtCreateFile / NtOpenFile: caller≠debugger/trusted + 路径命中 debugger image
//     → 返回 STATUS_OBJECT_NAME_NOT_FOUND (假装文件不存在)
//   - NtReadFile: 通过 handle 间接到 debugger image, 喂真 notepad.exe 字节 — 这里
//     做轻量实现, 任何能开成的 handle 都 STATUS_END_OF_FILE 兜底 (反正第一层已挡)
//
// 选 STATUS_OBJECT_NAME_NOT_FOUND 而不是 ACCESS_DENIED — 这是 "文件根本不存在"
// 的状态码, 不触发反作弊"这文件被保护"的告警分支。
// ============================================================

typedef NTSTATUS (NTAPI *PFN_NtCreateFile)(
    PHANDLE             FileHandle,
    ACCESS_MASK         DesiredAccess,
    POBJECT_ATTRIBUTES  ObjectAttributes,
    PIO_STATUS_BLOCK    IoStatusBlock,
    PLARGE_INTEGER      AllocationSize,
    ULONG               FileAttributes,
    ULONG               ShareAccess,
    ULONG               CreateDisposition,
    ULONG               CreateOptions,
    PVOID               EaBuffer,
    ULONG               EaLength
);

typedef NTSTATUS (NTAPI *PFN_NtOpenFile)(
    PHANDLE             FileHandle,
    ACCESS_MASK         DesiredAccess,
    POBJECT_ATTRIBUTES  ObjectAttributes,
    PIO_STATUS_BLOCK    IoStatusBlock,
    ULONG               ShareAccess,
    ULONG               OpenOptions
);

typedef NTSTATUS (NTAPI *PFN_NtReadFile)(
    HANDLE              FileHandle,
    HANDLE              Event,
    PVOID               ApcRoutine,
    PVOID               ApcContext,
    PIO_STATUS_BLOCK    IoStatusBlock,
    PVOID               Buffer,
    ULONG               Length,
    PLARGE_INTEGER      ByteOffset,
    PULONG              Key
);

// 把 ObjectAttributes.ObjectName 安全复制成 PUNICODE_STRING (内核栈上)
// caller 持有的 OA 可能在 UM, 必须 probe
static BOOLEAN HvHookpCaptureObjectName(
    _In_ POBJECT_ATTRIBUTES Oa,
    _In_ KPROCESSOR_MODE Mode,
    _Out_writes_bytes_(BufBytes) PWCH NameBuf,
    _In_ USHORT BufBytes,
    _Out_ PUNICODE_STRING OutName)
{
    OutName->Buffer = NULL;
    OutName->Length = 0;
    OutName->MaximumLength = 0;

    __try {
        if (Mode == UserMode) {
            ProbeForRead(Oa, sizeof(OBJECT_ATTRIBUTES), sizeof(PVOID));
        }
        PUNICODE_STRING name = Oa->ObjectName;
        if (!name) return FALSE;
        if (Mode == UserMode) {
            ProbeForRead(name, sizeof(UNICODE_STRING), sizeof(PVOID));
        }
        USHORT len = name->Length;
        PWCH buf = name->Buffer;
        if (!buf || len == 0 || len > BufBytes - sizeof(WCHAR)) {
            if (len > BufBytes - sizeof(WCHAR)) len = BufBytes - sizeof(WCHAR);
            if (!buf || len == 0) return FALSE;
        }
        if (Mode == UserMode) {
            ProbeForRead(buf, len, sizeof(WCHAR));
        }
        RtlCopyMemory(NameBuf, buf, len);
        NameBuf[len / sizeof(WCHAR)] = L'\0';
        OutName->Buffer = NameBuf;
        OutName->Length = len;
        OutName->MaximumLength = BufBytes;
        return TRUE;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
}

// 2026-06-19 (A): 文件防护专用 trusted 判定
//
// trusted 总表 (HvHookIsTrustedSystemCaller) 含 explorer/dwm/SearchHost/StartMenu
// 等 shell UI — 它们在进程查询场景必须放行 (否则 taskmgr/属性面板拿不到 debugger
// 元数据, 反作弊看到异常), 但在文件读场景借道这些进程就能绕过我们的 image 保护
// (双击 / 右键属性 / 缩略图缓存都会让 explorer 读 PE)。
//
// 这里维护一个 file-trusted 黑名单 — trusted 表里"对文件读不 trusted"的 PID 名:
//   - explorer.exe       (双击启动 / 右键属性 / 缩略图)
//   - SearchHost.exe     (搜索时索引文件)
//   - SearchApp.exe      (Win10 alt 搜索)
//   - StartMenuExperienceHost.exe / ShellExperienceHost.exe (磁贴预览)
//   - dwm.exe            (缩略图合成)
//   - sihost.exe         (shell ext)
//   - RuntimeBroker.exe  (UWP 文件访问代理)
//
// 注意: csrss / winlogon / lsass / services / svchost / MsMpEng / Defender /
// audiodg / fontdrvhost / conhost / ctfmon / taskhostw — 这些**保留**文件 trusted,
// 它们读 .exe 是合法启动/扫描/字体注册等,挡掉会破坏系统。
static const PCWSTR g_FileUntrustedNames[] = {
    L"explorer.exe",
    L"SearchHost.exe",
    L"SearchApp.exe",
    L"StartMenuExperienceHost.exe",
    L"ShellExperienceHost.exe",
    L"dwm.exe",
    L"sihost.exe",
    L"RuntimeBroker.exe",
    L"ApplicationFrameHost.exe",
    NULL,
};

static BOOLEAN HvHookpIsFileUntrustedShell(_In_ HANDLE Pid)
{
    if (!Pid) return FALSE;
    if (KeGetCurrentIrql() > APC_LEVEL) return FALSE;

    PEPROCESS proc = NULL;
    if (!NT_SUCCESS(PsLookupProcessByProcessId(Pid, &proc)) || !proc) {
        return FALSE;
    }
    PUCHAR imgName = PsGetProcessImageFileName(proc);
    BOOLEAN hit = FALSE;
    if (imgName) {
        CHAR localName[16] = { 0 };
        for (ULONG i = 0; i < 15; i++) {
            localName[i] = (CHAR)imgName[i];
            if (!localName[i]) break;
        }
        for (ULONG i = 0; g_FileUntrustedNames[i] != NULL; i++) {
            PCWSTR wname = g_FileUntrustedNames[i];
            BOOLEAN match = TRUE;
            for (ULONG j = 0; j < 16; j++) {
                WCHAR a = wname[j];
                CHAR  b = localName[j];
                if (a == L'\0' && b == '\0') break;
                if (a == L'\0' || b == '\0') { match = FALSE; break; }
                if (a >= L'A' && a <= L'Z') a = (WCHAR)(a - L'A' + L'a');
                if (b >= 'A'  && b <= 'Z')  b = (CHAR)(b - 'A' + 'a');
                if ((WCHAR)b != a) { match = FALSE; break; }
            }
            if (match) { hit = TRUE; break; }
        }
    }
    ObDereferenceObject(proc);
    return hit;
}

// 共用拦截逻辑: caller != debugger/trusted + path 命中 → 写 IoStatus 失败 + 返回
// STATUS_OBJECT_NAME_NOT_FOUND
static BOOLEAN HvHookpShouldBlockFileOpen(
    _In_ POBJECT_ATTRIBUTES Oa,
    _Out_opt_ PUNICODE_STRING DebugMatchedName)
{
    if (!Oa) return FALSE;
    HANDLE caller = PsGetCurrentProcessId();
    if (HvHookIsDebuggerPid(caller)) return FALSE;
    // 2026-06-19 (A): trusted 但属于 shell UI 黑名单 (explorer 等) → 仍然挡
    if (HvHookIsTrustedSystemCaller(caller) && !HvHookpIsFileUntrustedShell(caller)) {
        return FALSE;
    }

    WCHAR nameBuf[520];
    UNICODE_STRING name;
    KPROCESSOR_MODE prevMode = ExGetPreviousMode();
    if (!HvHookpCaptureObjectName(Oa, prevMode, nameBuf, sizeof(nameBuf), &name)) {
        return FALSE;
    }

    if (!HvHookIsPathDebuggerImage(&name)) return FALSE;

    if (DebugMatchedName) {
        DebugMatchedName->Buffer = NULL;
        DebugMatchedName->Length = name.Length;
    }
    HV_HOT_DBG("[HvHook-Spoof] NtCreate/OpenFile BLOCK: caller=%u path=%wZ → NAME_NOT_FOUND\n",
             (ULONG)(ULONG_PTR)caller, &name);
    return TRUE;
}

static NTSTATUS NTAPI
HookedNtCreateFile(
    PHANDLE             FileHandle,
    ACCESS_MASK         DesiredAccess,
    POBJECT_ATTRIBUTES  ObjectAttributes,
    PIO_STATUS_BLOCK    IoStatusBlock,
    PLARGE_INTEGER      AllocationSize,
    ULONG               FileAttributes,
    ULONG               ShareAccess,
    ULONG               CreateDisposition,
    ULONG               CreateOptions,
    PVOID               EaBuffer,
    ULONG               EaLength
)
{
    PFN_NtCreateFile Original = (PFN_NtCreateFile)HvHookGetTrampoline(g_HookNtCreateFile);
    if (!Original) return STATUS_UNSUCCESSFUL;

    if (KeGetCurrentIrql() > APC_LEVEL) {
        return Original(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock,
                        AllocationSize, FileAttributes, ShareAccess, CreateDisposition,
                        CreateOptions, EaBuffer, EaLength);
    }

    if (HvHookpShouldBlockFileOpen(ObjectAttributes, NULL)) {
        __try {
            KPROCESSOR_MODE prevMode = ExGetPreviousMode();
            if (FileHandle) {
                if (prevMode == UserMode) {
                    ProbeForWrite(FileHandle, sizeof(HANDLE), sizeof(HANDLE));
                }
                *FileHandle = NULL;
            }
            if (IoStatusBlock) {
                if (prevMode == UserMode) {
                    ProbeForWrite(IoStatusBlock, sizeof(IO_STATUS_BLOCK), sizeof(PVOID));
                }
                IoStatusBlock->Status = STATUS_OBJECT_NAME_NOT_FOUND;
                IoStatusBlock->Information = 0;
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) { }
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }

    return Original(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock,
                    AllocationSize, FileAttributes, ShareAccess, CreateDisposition,
                    CreateOptions, EaBuffer, EaLength);
}

static NTSTATUS NTAPI
HookedNtOpenFile(
    PHANDLE             FileHandle,
    ACCESS_MASK         DesiredAccess,
    POBJECT_ATTRIBUTES  ObjectAttributes,
    PIO_STATUS_BLOCK    IoStatusBlock,
    ULONG               ShareAccess,
    ULONG               OpenOptions
)
{
    PFN_NtOpenFile Original = (PFN_NtOpenFile)HvHookGetTrampoline(g_HookNtOpenFile);
    if (!Original) return STATUS_UNSUCCESSFUL;

    if (KeGetCurrentIrql() > APC_LEVEL) {
        return Original(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock,
                        ShareAccess, OpenOptions);
    }

    if (HvHookpShouldBlockFileOpen(ObjectAttributes, NULL)) {
        __try {
            KPROCESSOR_MODE prevMode = ExGetPreviousMode();
            if (FileHandle) {
                if (prevMode == UserMode) {
                    ProbeForWrite(FileHandle, sizeof(HANDLE), sizeof(HANDLE));
                }
                *FileHandle = NULL;
            }
            if (IoStatusBlock) {
                if (prevMode == UserMode) {
                    ProbeForWrite(IoStatusBlock, sizeof(IO_STATUS_BLOCK), sizeof(PVOID));
                }
                IoStatusBlock->Status = STATUS_OBJECT_NAME_NOT_FOUND;
                IoStatusBlock->Information = 0;
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) { }
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }

    return Original(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock,
                    ShareAccess, OpenOptions);
}

// NtReadFile: 第一层防御 (NtCreateFile/NtOpenFile) 已经让 CE 拿不到 handle, 这里是
// 兜底 — 万一别的路径泄了 handle (比如 csrss 帮开后 NtDuplicateObject 偷过来),
// 通过 handle 反查文件名, 命中 debugger image 则返回 STATUS_END_OF_FILE (0 字节)。
//
// 反查文件名: ObReferenceObjectByHandle + ObQueryNameInfo。开销不低, 但 NtReadFile
// 命中率低 — 大部分调用是反作弊读自己 module + system DLL, 我们快速放行。
//
// ObQueryNameString: ntifs.h 才提供, 这里手动 extern (兼容 ntddk-only)
NTKERNELAPI NTSTATUS NTAPI ObQueryNameString(
    _In_ PVOID Object,
    _Out_writes_bytes_opt_(Length) POBJECT_NAME_INFORMATION ObjectNameInfo,
    _In_ ULONG Length,
    _Out_ PULONG ReturnLength);

static NTSTATUS NTAPI
HookedNtReadFile(
    HANDLE              FileHandle,
    HANDLE              Event,
    PVOID               ApcRoutine,
    PVOID               ApcContext,
    PIO_STATUS_BLOCK    IoStatusBlock,
    PVOID               Buffer,
    ULONG               Length,
    PLARGE_INTEGER      ByteOffset,
    PULONG              Key
)
{
    PFN_NtReadFile Original = (PFN_NtReadFile)HvHookGetTrampoline(g_HookNtReadFile);
    if (!Original) return STATUS_UNSUCCESSFUL;

    if (KeGetCurrentIrql() > APC_LEVEL) {
        return Original(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock,
                        Buffer, Length, ByteOffset, Key);
    }

    HANDLE caller = PsGetCurrentProcessId();
    // 2026-06-19 (A): trusted 但 shell UI 也算外部 (避免双击/属性面板/缩略图绕过)
    if (HvHookIsDebuggerPid(caller) ||
        (HvHookIsTrustedSystemCaller(caller) && !HvHookpIsFileUntrustedShell(caller)))
    {
        return Original(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock,
                        Buffer, Length, ByteOffset, Key);
    }

    // 反查 file name
    PFILE_OBJECT fobj = NULL;
    NTSTATUS refSt = ObReferenceObjectByHandle(
        FileHandle, 0, *IoFileObjectType, KernelMode, (PVOID*)&fobj, NULL);
    if (!NT_SUCCESS(refSt) || !fobj) {
        return Original(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock,
                        Buffer, Length, ByteOffset, Key);
    }

    BOOLEAN block = FALSE;
    UCHAR nameBuf[1024];
    POBJECT_NAME_INFORMATION ni = (POBJECT_NAME_INFORMATION)nameBuf;
    ULONG retLen = 0;
    NTSTATUS qSt = ObQueryNameString(fobj, ni, sizeof(nameBuf), &retLen);
    if (NT_SUCCESS(qSt) && ni->Name.Length > 0) {
        if (HvHookIsPathDebuggerImage(&ni->Name)) {
            HV_HOT_DBG("[HvHook-Spoof] NtReadFile BLOCK debugger image: caller=%u path=%wZ → EOF\n",
                     (ULONG)(ULONG_PTR)caller, &ni->Name);
            block = TRUE;
        }
    }
    ObDereferenceObject(fobj);

    if (block) {
        __try {
            KPROCESSOR_MODE prevMode = ExGetPreviousMode();
            if (IoStatusBlock) {
                if (prevMode == UserMode) {
                    ProbeForWrite(IoStatusBlock, sizeof(IO_STATUS_BLOCK), sizeof(PVOID));
                }
                IoStatusBlock->Status = STATUS_END_OF_FILE;
                IoStatusBlock->Information = 0;
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) { }
        return STATUS_END_OF_FILE;
    }

    return Original(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock,
                    Buffer, Length, ByteOffset, Key);
}

NTSTATUS HvHookEnableAccessBypass(VOID)
{
    PVOID    t;
    NTSTATUS st;

    if (!g_HvHookInitialized) return STATUS_NOT_INITIALIZED;
    if (g_AccessBypassEnabled) return STATUS_SUCCESS;

    if (!g_ProtectionStripMutexInit) {
        KeInitializeMutex(&g_ProtectionStripMutex, 0);
        g_ProtectionStripMutexInit = TRUE;
    }

    DbgPrint("[HvHook] Enabling NtOpenProcess access bypass (EPT-hook + Protection strip)\n");

    t = HvHookpGetNtRoutine(L"NtOpenProcess", 0);   // NtOpenProcess 在 ntoskrnl EAT,无需 L6 SSDT
    if (!t) {
        DbgPrint("[HvHook] NtOpenProcess not exported\n");
        return STATUS_NOT_FOUND;
    }

    st = HvHookInstall(t, HookedNtOpenProcess, &g_HookNtOpenProcess);
    if (!NT_SUCCESS(st)) {
        DbgPrint("[HvHook] HvHookInstall(NtOpenProcess) failed: 0x%X\n", st);
        g_HookNtOpenProcess = NULL;
        return st;
    }

    DbgPrint("[HvHook] NtOpenProcess hooked at %p\n", t);

    // 2026-06-19: 顺装 NtGetNextProcess, 堵 R3 链表枚举绕过 OpenProcess
    PVOID gnp = HvHookpGetNtRoutine(L"NtGetNextProcess", 0);
    if (gnp) {
        NTSTATUS stGnp = HvHookInstall(gnp, HookedNtGetNextProcess, &g_HookNtGetNextProcess);
        if (NT_SUCCESS(stGnp)) {
            DbgPrint("[HvHook] NtGetNextProcess hooked at %p\n", gnp);
        } else {
            DbgPrint("[HvHook] HvHookInstall(NtGetNextProcess) failed: 0x%X (non-fatal)\n", stGnp);
            g_HookNtGetNextProcess = NULL;
        }
    } else {
        DbgPrint("[HvHook] NtGetNextProcess not exported (non-fatal)\n");
    }

    // 2026-06-19: debugger image 文件防护 (NtCreateFile / NtOpenFile / NtReadFile)
    // 三个都是 SSDT, MmGetSystemRoutineAddress 拿不到 Nt 前缀, 走 Zw fallback / SSDT 路径
    struct { PCWSTR Name; PVOID Hook; HV_HOOK_HANDLE *Handle; } fileHooks[] = {
        { L"NtCreateFile", HookedNtCreateFile, &g_HookNtCreateFile },
        { L"NtOpenFile",   HookedNtOpenFile,   &g_HookNtOpenFile   },
        { L"NtReadFile",   HookedNtReadFile,   &g_HookNtReadFile   },
    };
    for (SIZE_T i = 0; i < sizeof(fileHooks)/sizeof(fileHooks[0]); i++) {
        PVOID ft = HvHookpGetNtRoutine(fileHooks[i].Name, 0);
        if (!ft) {
            DbgPrint("[HvHook] %ws not exported (non-fatal)\n", fileHooks[i].Name);
            continue;
        }
        NTSTATUS stFh = HvHookInstall(ft, fileHooks[i].Hook, fileHooks[i].Handle);
        if (NT_SUCCESS(stFh)) {
            DbgPrint("[HvHook] %ws hooked at %p\n", fileHooks[i].Name, ft);
        } else {
            DbgPrint("[HvHook] HvHookInstall(%ws) failed: 0x%X (non-fatal)\n",
                     fileHooks[i].Name, stFh);
            *fileHooks[i].Handle = NULL;
        }
    }

    // 2026-06-19: 注册 ObRegisterCallbacks (PsProcessType), 堵内核层 OpenProcess 绕过
    // (ObReferenceObjectByName / ObOpenObjectByPointer / NtDuplicateObject 全路径)
    HvHookpRegisterObCallback();

    // 2026-06-19: NtDuplicateObject hook (ObCallback 第二道兜底, 含 Thread handle 偷渡)
    PVOID dupT = HvHookpGetNtRoutine(L"NtDuplicateObject", 0);
    if (dupT) {
        NTSTATUS stDup = HvHookInstall(dupT, HookedNtDuplicateObject, &g_HookNtDuplicateObject);
        if (NT_SUCCESS(stDup)) {
            DbgPrint("[HvHook] NtDuplicateObject hooked at %p\n", dupT);
        } else {
            DbgPrint("[HvHook] HvHookInstall(NtDuplicateObject) failed: 0x%X (non-fatal)\n", stDup);
            g_HookNtDuplicateObject = NULL;
        }
    } else {
        DbgPrint("[HvHook] NtDuplicateObject not exported (non-fatal)\n");
    }

    g_AccessBypassEnabled = TRUE;
    return STATUS_SUCCESS;
}

VOID HvHookDisableAccessBypass(VOID)
{
    if (!g_HvHookInitialized || !g_AccessBypassEnabled) return;

    DbgPrint("[HvHook] Disabling NtOpenProcess access bypass\n");

    if (g_HookNtOpenProcess) {
        HvHookRemove(g_HookNtOpenProcess);
        g_HookNtOpenProcess = NULL;
    }

    if (g_HookNtGetNextProcess) {
        HvHookRemove(g_HookNtGetNextProcess);
        g_HookNtGetNextProcess = NULL;
    }

    // 2026-06-19: 卸 debugger image 文件防护
    if (g_HookNtCreateFile) { HvHookRemove(g_HookNtCreateFile); g_HookNtCreateFile = NULL; }
    if (g_HookNtOpenFile)   { HvHookRemove(g_HookNtOpenFile);   g_HookNtOpenFile   = NULL; }
    if (g_HookNtReadFile)   { HvHookRemove(g_HookNtReadFile);   g_HookNtReadFile   = NULL; }

    // 2026-06-19: 卸 ObRegisterCallbacks
    HvHookpUnregisterObCallback();

    // 2026-06-19: 卸 NtDuplicateObject
    if (g_HookNtDuplicateObject) {
        HvHookRemove(g_HookNtDuplicateObject);
        g_HookNtDuplicateObject = NULL;
    }

    g_AccessBypassEnabled = FALSE;
}

// ============================================================
// Hook 链路状态查询 (Phase F) —— 放在 g_AccessBypassEnabled static 定义之后,
// C 单遍解析才能找到符号。GUI 通过 IOCTL_HV_GET_STATUS 拿这些状态。
// ============================================================

BOOLEAN
HvHookIsDebuggerProxyEnabled(VOID)
{
    // Phase L: 不再仅看 g_DebuggerProxyEnabled flag —— 那个 flag 即使 hook 装载
    // 失败 (Nt* 名解析不到) 也会被设成 TRUE,造成 GUI 假象 ✓。改成检查 hook handle
    // 是否真的非 NULL。3 个 R/W 类核心 hook 都装上才算 enabled。
    // (NtSetContextThread 可有可无 — HWBP 才用得着)
    return g_DebuggerProxyEnabled
        && g_HookNtReadVirtualMemory != NULL
        && g_HookNtWriteVirtualMemory != NULL;
}

BOOLEAN
HvHookIsAccessBypassEnabled(VOID)
{
    // Phase L: 同 ProxyEnabled, 检查 hook handle 真实状态
    return g_AccessBypassEnabled && g_HookNtOpenProcess != NULL;
}

// ============================================================
// DSE 控制实现 (#28 重构)
// ============================================================
//
// 旧实现: 找 g_CiOptions 并 __writecr0 清 WP 后直写为 0。
//   - PG 0x109 BSOD 经典命中点 (g_CiOptions 在 hash 区,5-15 分钟必扫到)。
//   - 跨 Win 版本偏移漂移,定位常失败。
//
// 新实现: EPT-hook CiValidateImageHeader,让它无条件返回 STATUS_SUCCESS。
//   - g_CiOptions 本身不动,PG 看不到改写。
//   - 仅对 ci.dll 代码页装一个 EPT Execute trap (走 HvHookInstall),
//     hook 函数永远 return STATUS_SUCCESS。
//   - Win10/11 各版本 CiValidateImageHeader 签名不同 (3-7 参数都见过),
//     这里声明 7 个 PVOID 占位,反正我们直接返回不读参数。
//     x64 ABI: 前 4 个走 RCX/RDX/R8/R9,5-7 走栈 [RSP+0x28/30/38],
//     占位 7 个让编译器生成正确的栈访问模板,不会偏 ABI。

// Hook 函数: 无视所有参数,无条件返回成功。
__declspec(noinline)
static NTSTATUS
HookedCiValidateImageHeader(
    PVOID Arg1, PVOID Arg2, PVOID Arg3, PVOID Arg4,
    PVOID Arg5, PVOID Arg6, PVOID Arg7
)
{
    UNREFERENCED_PARAMETER(Arg1);
    UNREFERENCED_PARAMETER(Arg2);
    UNREFERENCED_PARAMETER(Arg3);
    UNREFERENCED_PARAMETER(Arg4);
    UNREFERENCED_PARAMETER(Arg5);
    UNREFERENCED_PARAMETER(Arg6);
    UNREFERENCED_PARAMETER(Arg7);
    return STATUS_SUCCESS;
}

NTSTATUS
HvDseDisable(VOID)
{
    UNICODE_STRING name;
    PVOID target = NULL;
    NTSTATUS status;
    HV_HOOK_HANDLE handle = NULL;

    if (!g_HvHookInitialized) {
        return STATUS_NOT_INITIALIZED;
    }

    if (g_DseDisabled) {
        DbgPrint("[HvHook-DSE] DSE already disabled (hook installed)\n");
        return STATUS_SUCCESS;
    }

    // CiValidateImageHeader 在 ci.dll 而非 ntoskrnl,MmGetSystemRoutineAddress
    // 只查 nt!/hal! 命名空间,所以先走 SystemModuleInformation + EAT 路径解析
    // ci.dll;失败再回退到 MmGetSystemRoutineAddress(某些早期 Win10 build 把
    // 名字也注册到 nt 命名空间)。
    target = HvHookpResolveKernelExport("ci.dll", "CiValidateImageHeader");
    if (!target) {
        RtlInitUnicodeString(&name, L"CiValidateImageHeader");
        target = MmGetSystemRoutineAddress(&name);
    }
    if (!target) {
        DbgPrint("[HvHook-DSE] CiValidateImageHeader not found in ci.dll EAT nor nt namespace\n");
        return STATUS_NOT_FOUND;
    }

    DbgPrint("[HvHook-DSE] Installing EPT hook on CiValidateImageHeader @ %p\n", target);

    status = HvHookInstall(target, (PVOID)HookedCiValidateImageHeader, &handle);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[HvHook-DSE] HvHookInstall failed: 0x%X\n", status);
        return status;
    }

    g_CiValidateImageHeaderHook = handle;
    g_CiValidateImageHeaderTarget = target;
    g_DseDisabled = TRUE;

    DbgPrint("[HvHook-DSE] DSE bypassed via EPT-hook (handle=%p)\n", handle);
    return STATUS_SUCCESS;
}

NTSTATUS
HvDseEnable(VOID)
{
    NTSTATUS status;

    if (!g_HvHookInitialized) {
        return STATUS_NOT_INITIALIZED;
    }

    if (!g_DseDisabled) {
        DbgPrint("[HvHook-DSE] DSE is not currently disabled\n");
        return STATUS_SUCCESS;
    }

    if (g_CiValidateImageHeaderHook) {
        status = HvHookRemove(g_CiValidateImageHeaderHook);
        if (!NT_SUCCESS(status)) {
            DbgPrint("[HvHook-DSE] HvHookRemove failed: 0x%X (state desynced)\n", status);
            // 注意: 即便 HvHookRemove 失败,我们仍然清状态 —— 否则用户态卡住
            // 重试也徒劳。Disable 的下一次会重新装 hook,Remove 路径会被跳过。
        }
        g_CiValidateImageHeaderHook = NULL;
    }

    g_CiValidateImageHeaderTarget = NULL;
    g_DseDisabled = FALSE;

    DbgPrint("[HvHook-DSE] DSE re-enabled (EPT hook removed)\n");
    return STATUS_SUCCESS;
}

NTSTATUS
HvDseGetStatus(
    _Out_ PBOOLEAN OutEnabled,
    _Out_opt_ PULONG OutCiOptions,
    _Out_opt_ PUINT64 OutCiAddress
)
{
    if (!OutEnabled) {
        return STATUS_INVALID_PARAMETER;
    }

    // DSE "启用" = 我们的 hook 不在 = g_DseDisabled == FALSE。
    *OutEnabled = !g_DseDisabled;

    // 兼容字段: 旧 GUI 期望 OutCiOptions 是 g_CiOptions 的当前值。
    // 我们不再碰 g_CiOptions,这里报 0 (disabled) / 1 (enabled) 仅供调试。
    if (OutCiOptions) {
        *OutCiOptions = g_DseDisabled ? 0 : 1;
    }

    // 兼容字段: 返回 CiValidateImageHeader 地址 (旧实现返回 g_CiOptions 地址)。
    // GUI 仅展示用,不会基于此再做内存操作。
    if (OutCiAddress) {
        *OutCiAddress = (UINT64)g_CiValidateImageHeaderTarget;
    }

    return STATUS_SUCCESS;
}

// ============================================================
// Phase G: 根因事件 ring buffer 实现
// ============================================================

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
)
{
    KIRQL oldIrql;
    UINT64 seq;
    ULONG slot;
    PHV_DBGEVT evt;
    LARGE_INTEGER qpc;

    if (!g_DbgEvtInit) return;

    qpc = KeQueryPerformanceCounter(NULL);

    KeAcquireSpinLock(&g_DbgEvtLock, &oldIrql);

    seq = g_DbgEvtNextSeq++;
    slot = (ULONG)((seq - 1) & (HV_DBGEVT_RING_SIZE - 1));
    evt = &g_DbgEvtRing[slot];

    evt->Sequence     = seq;
    evt->TimestampQpc = (UINT64)qpc.QuadPart;
    evt->Severity     = Severity;
    evt->Category     = Category;
    evt->Status       = Status;
    evt->CallerPid    = CallerPid;
    evt->TargetPid    = TargetPid;
    evt->_pad         = 0;
    evt->Addr         = Addr;
    evt->Size         = Size;

    // ASCII 拷贝,截断保留 NUL。RtlStringCbCopyA 防越界。
    if (Detail) {
        // 不调 RtlStringCbCopyA 避免在 DISPATCH_LEVEL 触发 paged-pool —— 手动拷
        ULONG i;
        for (i = 0; i < HV_DBGEVT_DETAIL_MAX - 1 && Detail[i] != '\0'; i++) {
            evt->Detail[i] = Detail[i];
        }
        evt->Detail[i] = '\0';
        // 残余空间清零,避免泄漏旧 slot 内容
        while (i < HV_DBGEVT_DETAIL_MAX) {
            evt->Detail[i++] = '\0';
        }
    } else {
        evt->Detail[0] = '\0';
    }

    KeReleaseSpinLock(&g_DbgEvtLock, oldIrql);
}

NTSTATUS
HvDbgEvtPull(
    _In_  UINT64    SinceSequence,
    _Out_writes_to_(MaxOut, *OutCount) PHV_DBGEVT OutEvents,
    _In_  ULONG     MaxOut,
    _Out_ PULONG    OutCount,
    _Out_ PUINT64   OutNextSequence
)
{
    KIRQL oldIrql;
    UINT64 next, oldest, start, seq;
    ULONG count = 0;

    if (!OutEvents || !OutCount || !OutNextSequence) {
        return STATUS_INVALID_PARAMETER;
    }
    *OutCount = 0;
    *OutNextSequence = 0;

    if (!g_DbgEvtInit) {
        return STATUS_DEVICE_NOT_READY;
    }
    if (MaxOut == 0) {
        return STATUS_SUCCESS;
    }

    KeAcquireSpinLock(&g_DbgEvtLock, &oldIrql);

    next = g_DbgEvtNextSeq;           // 下一次会分配的 seq (= ring 中最新 + 1)
    // ring 中存活的 seq 范围 = [max(1, next - SIZE), next - 1]
    oldest = (next > HV_DBGEVT_RING_SIZE) ? (next - HV_DBGEVT_RING_SIZE) : 1;

    // 客户端要从 SinceSequence + 1 开始,但如果 < oldest 说明丢失了一批
    start = SinceSequence + 1;
    if (start < oldest) {
        start = oldest;   // 跳到 ring 里最早还在的那条
    }

    for (seq = start; seq < next && count < MaxOut; seq++) {
        ULONG slot = (ULONG)((seq - 1) & (HV_DBGEVT_RING_SIZE - 1));
        OutEvents[count++] = g_DbgEvtRing[slot];
    }

    *OutCount = count;
    *OutNextSequence = (next == 0) ? 0 : (next - 1);   // ring 中最新条目的 seq

    KeReleaseSpinLock(&g_DbgEvtLock, oldIrql);

    return STATUS_SUCCESS;
}
