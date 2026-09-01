/*
 * HvInjection.h
 * 
 * 无痕注入框架 - 基于 EPT/NPT Hook 的隐蔽代码注入
 * 
 * 功能：
 *   - DLL 手动映射（无 LdrLoadDll 调用）
 *   - Shellcode 注入
 *   - 跨进程内存读写
 *   - APC 代码执行引擎
 *   - 通过 EPT/NPT Hook 隐藏注入痕迹
 */

#ifndef _HV_INJECTION_H_
#define _HV_INJECTION_H_

#pragma once

#include <ntddk.h>
#include <intrin.h>

// ============================================================
// 常量定义
// ============================================================

#define HV_INJECTION_TAG            'jnIH'
#define MAX_INJECTION_MODULES       32
#define MAX_MODULE_NAME_LENGTH      256
#define MAX_TRACKED_ALLOCATIONS     256

// ============================================================
// 注入模式枚举
// ============================================================

typedef enum _HV_INJECTION_MODE {
    HvInjectModeDll,            // DLL 手动映射
    HvInjectModeShellcode,      // Shellcode 注入
    HvInjectModeMemory,         // 内存读写（无执行）
} HV_INJECTION_MODE;

// 执行方式枚举
typedef enum _HV_EXECUTION_METHOD {
    HvExecMethodApc,            // 用户 APC
    HvExecMethodThread,         // 创建远程线程
    HvExecMethodHijack,         // 线程劫持
    HvExecMethodCallback,       // 回调注入
} HV_EXECUTION_METHOD;

// ============================================================
// PE 结构定义（用于手动映射）
// ============================================================

// DOS Header
typedef struct _IMAGE_DOS_HEADER_INJ {
    USHORT e_magic;
    USHORT e_cblp;
    USHORT e_cp;
    USHORT e_crlc;
    USHORT e_cparhdr;
    USHORT e_minalloc;
    USHORT e_maxalloc;
    USHORT e_ss;
    USHORT e_sp;
    USHORT e_csum;
    USHORT e_ip;
    USHORT e_cs;
    USHORT e_lfarlc;
    USHORT e_ovno;
    USHORT e_res[4];
    USHORT e_oemid;
    USHORT e_oeminfo;
    USHORT e_res2[10];
    LONG   e_lfanew;
} IMAGE_DOS_HEADER_INJ, *PIMAGE_DOS_HEADER_INJ;

// File Header
typedef struct _IMAGE_FILE_HEADER_INJ {
    USHORT Machine;
    USHORT NumberOfSections;
    ULONG  TimeDateStamp;
    ULONG  PointerToSymbolTable;
    ULONG  NumberOfSymbols;
    USHORT SizeOfOptionalHeader;
    USHORT Characteristics;
} IMAGE_FILE_HEADER_INJ, *PIMAGE_FILE_HEADER_INJ;

// Data Directory
typedef struct _IMAGE_DATA_DIRECTORY_INJ {
    ULONG VirtualAddress;
    ULONG Size;
} IMAGE_DATA_DIRECTORY_INJ, *PIMAGE_DATA_DIRECTORY_INJ;

// Optional Header (64-bit)
typedef struct _IMAGE_OPTIONAL_HEADER64_INJ {
    USHORT Magic;
    UCHAR  MajorLinkerVersion;
    UCHAR  MinorLinkerVersion;
    ULONG  SizeOfCode;
    ULONG  SizeOfInitializedData;
    ULONG  SizeOfUninitializedData;
    ULONG  AddressOfEntryPoint;
    ULONG  BaseOfCode;
    ULONGLONG ImageBase;
    ULONG  SectionAlignment;
    ULONG  FileAlignment;
    USHORT MajorOperatingSystemVersion;
    USHORT MinorOperatingSystemVersion;
    USHORT MajorImageVersion;
    USHORT MinorImageVersion;
    USHORT MajorSubsystemVersion;
    USHORT MinorSubsystemVersion;
    ULONG  Win32VersionValue;
    ULONG  SizeOfImage;
    ULONG  SizeOfHeaders;
    ULONG  CheckSum;
    USHORT Subsystem;
    USHORT DllCharacteristics;
    ULONGLONG SizeOfStackReserve;
    ULONGLONG SizeOfStackCommit;
    ULONGLONG SizeOfHeapReserve;
    ULONGLONG SizeOfHeapCommit;
    ULONG  LoaderFlags;
    ULONG  NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY_INJ DataDirectory[16];
} IMAGE_OPTIONAL_HEADER64_INJ, *PIMAGE_OPTIONAL_HEADER64_INJ;

// NT Headers
typedef struct _IMAGE_NT_HEADERS64_INJ {
    ULONG Signature;
    IMAGE_FILE_HEADER_INJ FileHeader;
    IMAGE_OPTIONAL_HEADER64_INJ OptionalHeader;
} IMAGE_NT_HEADERS64_INJ, *PIMAGE_NT_HEADERS64_INJ;

// Section Header
typedef struct _IMAGE_SECTION_HEADER_INJ {
    UCHAR  Name[8];
    union {
        ULONG PhysicalAddress;
        ULONG VirtualSize;
    } Misc;
    ULONG  VirtualAddress;
    ULONG  SizeOfRawData;
    ULONG  PointerToRawData;
    ULONG  PointerToRelocations;
    ULONG  PointerToLinenumbers;
    USHORT NumberOfRelocations;
    USHORT NumberOfLinenumbers;
    ULONG  Characteristics;
} IMAGE_SECTION_HEADER_INJ, *PIMAGE_SECTION_HEADER_INJ;

// Import Descriptor
typedef struct _IMAGE_IMPORT_DESCRIPTOR_INJ {
    union {
        ULONG Characteristics;
        ULONG OriginalFirstThunk;
    };
    ULONG TimeDateStamp;
    ULONG ForwarderChain;
    ULONG Name;
    ULONG FirstThunk;
} IMAGE_IMPORT_DESCRIPTOR_INJ, *PIMAGE_IMPORT_DESCRIPTOR_INJ;

// Import By Name
typedef struct _IMAGE_IMPORT_BY_NAME_INJ {
    USHORT Hint;
    CHAR   Name[1];
} IMAGE_IMPORT_BY_NAME_INJ, *PIMAGE_IMPORT_BY_NAME_INJ;

// Base Relocation
typedef struct _IMAGE_BASE_RELOCATION_INJ {
    ULONG VirtualAddress;
    ULONG SizeOfBlock;
} IMAGE_BASE_RELOCATION_INJ, *PIMAGE_BASE_RELOCATION_INJ;

// TLS Directory
typedef struct _IMAGE_TLS_DIRECTORY64_INJ {
    ULONGLONG StartAddressOfRawData;
    ULONGLONG EndAddressOfRawData;
    ULONGLONG AddressOfIndex;
    ULONGLONG AddressOfCallBacks;
    ULONG SizeOfZeroFill;
    ULONG Characteristics;
} IMAGE_TLS_DIRECTORY64_INJ, *PIMAGE_TLS_DIRECTORY64_INJ;

// 数据目录索引
#define IMAGE_DIRECTORY_ENTRY_EXPORT          0
#define IMAGE_DIRECTORY_ENTRY_IMPORT          1
#define IMAGE_DIRECTORY_ENTRY_RESOURCE        2
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION       3
#define IMAGE_DIRECTORY_ENTRY_SECURITY        4
#define IMAGE_DIRECTORY_ENTRY_BASERELOC       5
#define IMAGE_DIRECTORY_ENTRY_DEBUG           6
#define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE    7
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR       8
#define IMAGE_DIRECTORY_ENTRY_TLS             9
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    10
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   11
#define IMAGE_DIRECTORY_ENTRY_IAT            12
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   13
#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14

// 重定位类型
#define IMAGE_REL_BASED_ABSOLUTE        0
#define IMAGE_REL_BASED_HIGH            1
#define IMAGE_REL_BASED_LOW             2
#define IMAGE_REL_BASED_HIGHLOW         3
#define IMAGE_REL_BASED_HIGHADJ         4
#define IMAGE_REL_BASED_DIR64          10

// ============================================================
// 数据结构
// ============================================================

// 注入请求
typedef struct _HV_INJECTION_REQUEST {
    ULONG ProcessId;                    // 目标进程 ID
    HV_INJECTION_MODE Mode;             // 注入模式
    HV_EXECUTION_METHOD ExecMethod;     // 执行方式
    PVOID Data;                         // 数据指针（DLL 或 Shellcode）
    SIZE_T DataSize;                    // 数据大小
    PVOID EntryPoint;                   // 入口点（可选，用于 Shellcode）
    PVOID Parameter;                    // 参数（传递给入口函数）
    BOOLEAN WaitComplete;               // 是否等待执行完成
    BOOLEAN HideMemory;                 // 是否隐藏注入的内存
} HV_INJECTION_REQUEST, *PHV_INJECTION_REQUEST;

// 注入结果
typedef struct _HV_INJECTION_RESULT {
    NTSTATUS Status;                    // 操作状态
    PVOID ModuleBase;                   // 模块基址（DLL 注入）
    SIZE_T ModuleSize;                  // 模块大小
    PVOID EntryPointAddress;            // 实际入口点地址
    PVOID ExecutionResult;              // 执行结果
} HV_INJECTION_RESULT, *PHV_INJECTION_RESULT;

// 已注入模块信息
typedef struct _INJECTED_MODULE_ENTRY {
    LIST_ENTRY ListEntry;
    ULONG ProcessId;
    UINT64 ProcessCreateTime;
    PVOID ModuleBase;
    SIZE_T ModuleSize;
    WCHAR ModuleName[MAX_MODULE_NAME_LENGTH];
    BOOLEAN IsHidden;
    volatile LONG Removing;
} INJECTED_MODULE_ENTRY, *PINJECTED_MODULE_ENTRY;

typedef struct _HV_MEMORY_ALLOCATION_ENTRY {
    LIST_ENTRY ListEntry;
    ULONG ProcessId;
    UINT64 ProcessCreateTime;
    PVOID BaseAddress;
    SIZE_T RegionSize;
    ULONG Protection;
} HV_MEMORY_ALLOCATION_ENTRY, *PHV_MEMORY_ALLOCATION_ENTRY;

// APC 上下文
typedef struct _HV_APC_CONTEXT {
    PVOID TargetRoutine;                // 目标例程
    PVOID Parameter;                    // 参数
    KEVENT CompletionEvent;             // 完成事件
    NTSTATUS Status;                    // 执行状态
    PVOID Result;                       // 返回值
} HV_APC_CONTEXT, *PHV_APC_CONTEXT;

// 注入管理器
typedef struct _HV_INJECTION_MANAGER {
    // 已注入模块列表
    LIST_ENTRY InjectedModuleList;
    ULONG InjectedModuleCount;

    LIST_ENTRY AllocationList;
    ULONG AllocationCount;
    
    // 同步
    KSPIN_LOCK Lock;
    FAST_MUTEX FastMutex;
    
    // 状态
    BOOLEAN Initialized;
    
} HV_INJECTION_MANAGER, *PHV_INJECTION_MANAGER;

// ============================================================
// 函数声明 - 初始化和清理
// ============================================================

/*
 * 初始化注入管理器
 */
NTSTATUS
HvInjectionInitialize(VOID);

/* Phase one: close admission and synchronously detach process notification. */
NTSTATUS
HvInjectionBeginShutdown(VOID);

/* Phase two: release list ownership after operation and hook rundown. */
NTSTATUS
HvInjectionFinalizeCleanup(VOID);

/*
 * 清理注入管理器
 */
/* Compatibility entry point; fail-closed because it cannot prove hook rundown. */
NTSTATUS
HvInjectionCleanup(VOID);

/*
 * 检查是否已初始化
 */
BOOLEAN
HvInjectionIsInitialized(VOID);

// ============================================================
// 函数声明 - DLL 注入
// ============================================================

/*
 * 手动映射 DLL 到目标进程
 * 
 * @param ProcessId     目标进程 ID
 * @param DllBuffer     DLL 文件内容（完整 PE 文件）
 * @param DllSize       DLL 大小
 * @param OutResult     输出注入结果（可选）
 * @return NTSTATUS
 * 
 * 此函数执行完整的手动映射：
 * 1. 解析 PE 头
 * 2. 分配内存
 * 3. 复制节区
 * 4. 处理重定位
 * 5. 解析导入
 * 6. 调用 TLS 回调
 * 7. 调用 DllMain
 */
NTSTATUS
HvInjectDll(
    _In_ ULONG ProcessId,
    _In_ PVOID DllBuffer,
    _In_ SIZE_T DllSize,
    _Out_opt_ PHV_INJECTION_RESULT OutResult
);

/*
 * 手动映射 DLL（带文件路径）
 * 
 * @param ProcessId     目标进程 ID
 * @param DllPath       DLL 文件路径
 * @param OutResult     输出注入结果（可选）
 * @return NTSTATUS
 */
NTSTATUS
HvInjectDllFromFile(
    _In_ ULONG ProcessId,
    _In_ PCWSTR DllPath,
    _Out_opt_ PHV_INJECTION_RESULT OutResult
);

/*
 * 卸载已注入的 DLL
 * 
 * @param ProcessId     进程 ID
 * @param ModuleBase    模块基址
 * @return NTSTATUS
 */
NTSTATUS
HvUnloadInjectedDll(
    _In_ ULONG ProcessId,
    _In_ PVOID ModuleBase
);

// ============================================================
// 函数声明 - Shellcode 注入
// ============================================================

/*
 * 注入并执行 Shellcode
 * 
 * @param ProcessId     目标进程 ID
 * @param Shellcode     Shellcode 数据
 * @param Size          Shellcode 大小
 * @param Parameter     传递给 Shellcode 的参数（可选）
 * @param OutAddress    输出 Shellcode 地址（可选）
 * @return NTSTATUS
 */
NTSTATUS
HvInjectShellcode(
    _In_ ULONG ProcessId,
    _In_ PVOID Shellcode,
    _In_ SIZE_T Size,
    _In_opt_ PVOID Parameter,
    _Out_opt_ PVOID* OutAddress
);

/*
 * 注入 Shellcode（不立即执行）
 * 
 * @param ProcessId     目标进程 ID
 * @param Shellcode     Shellcode 数据
 * @param Size          Shellcode 大小
 * @param OutAddress    输出 Shellcode 地址
 * @return NTSTATUS
 */
NTSTATUS
HvInjectShellcodeNoExecute(
    _In_ ULONG ProcessId,
    _In_ PVOID Shellcode,
    _In_ SIZE_T Size,
    _Out_ PVOID* OutAddress
);

/*
 * 执行已注入的 Shellcode
 * 
 * @param ProcessId     进程 ID
 * @param Address       Shellcode 地址
 * @param Parameter     参数（可选）
 * @param ExecMethod    执行方式
 * @return NTSTATUS
 */
NTSTATUS
HvExecuteShellcode(
    _In_ ULONG ProcessId,
    _In_ PVOID Address,
    _In_opt_ PVOID Parameter,
    _In_ HV_EXECUTION_METHOD ExecMethod
);

// ============================================================
// 函数声明 - 内存操作
// ============================================================

/*
 * 读取目标进程内存
 * 
 * @param ProcessId     目标进程 ID
 * @param Address       源地址（目标进程中）
 * @param Buffer        目标缓冲区
 * @param Size          读取大小
 * @param BytesRead     实际读取的字节数（可选）
 * @return NTSTATUS
 */
NTSTATUS
HvMemoryRead(
    _In_ ULONG ProcessId,
    _In_ PVOID Address,
    _Out_ PVOID Buffer,
    _In_ SIZE_T Size,
    _Out_opt_ PSIZE_T BytesRead
);

/*
 * 写入目标进程内存
 * 
 * @param ProcessId     目标进程 ID
 * @param Address       目标地址（目标进程中）
 * @param Buffer        源缓冲区
 * @param Size          写入大小
 * @param BytesWritten  实际写入的字节数（可选）
 * @return NTSTATUS
 */
NTSTATUS
HvMemoryWrite(
    _In_ ULONG ProcessId,
    _In_ PVOID Address,
    _In_ PVOID Buffer,
    _In_ SIZE_T Size,
    _Out_opt_ PSIZE_T BytesWritten
);

NTSTATUS
HvMemoryWriteCow(
    _In_ ULONG ProcessId,
    _In_ PVOID Address,
    _In_reads_bytes_(Size) PVOID Buffer,
    _In_ SIZE_T Size,
    _Out_opt_ PSIZE_T BytesWritten
);

/*
 * 在目标进程分配内存
 * 
 * @param ProcessId     目标进程 ID
 * @param Size          分配大小
 * @param Protection    内存保护属性
 * @param OutAddress    输出分配的地址
 * @return NTSTATUS
 */
NTSTATUS
HvMemoryAllocate(
    _In_ ULONG ProcessId,
    _In_ SIZE_T Size,
    _In_ ULONG Protection,
    _Out_ PVOID* OutAddress
);

/*
 * 释放目标进程内存
 * 
 * @param ProcessId     目标进程 ID
 * @param Address       要释放的地址
 * @return NTSTATUS
 */
NTSTATUS
HvMemoryFree(
    _In_ ULONG ProcessId,
    _In_ PVOID Address
);

/*
 * 修改目标进程内存保护
 * 
 * @param ProcessId         目标进程 ID
 * @param Address           地址
 * @param Size              大小
 * @param NewProtection     新保护属性
 * @param OldProtection     旧保护属性（可选）
 * @return NTSTATUS
 */
NTSTATUS
HvMemoryProtect(
    _In_ ULONG ProcessId,
    _In_ PVOID Address,
    _In_ SIZE_T Size,
    _In_ ULONG NewProtection,
    _Out_opt_ PULONG OldProtection
);

// ============================================================
// 函数声明 - APC 执行引擎
// ============================================================

/*
 * 排队用户模式 APC
 * 
 * @param ProcessId     目标进程 ID
 * @param ThreadId      目标线程 ID（0 = 任意可警告线程）
 * @param ApcRoutine    APC 例程地址
 * @param ApcContext    APC 参数
 * @param WaitComplete  是否等待完成
 * @return NTSTATUS
 */
NTSTATUS
HvQueueUserApc(
    _In_ ULONG ProcessId,
    _In_ ULONG ThreadId,
    _In_ PVOID ApcRoutine,
    _In_opt_ PVOID ApcContext,
    _In_ BOOLEAN WaitComplete
);

/*
 * 查找可警告的线程
 * 
 * @param Process       目标进程
 * @param OutThread     输出找到的线程
 * @return NTSTATUS
 */
NTSTATUS
HvFindAlertableThread(
    _In_ PEPROCESS Process,
    _Out_ PETHREAD* OutThread
);

// ============================================================
// 函数声明 - 进程操作
// ============================================================

/*
 * 附加到目标进程
 * 
 * @param ProcessId     目标进程 ID
 * @param OutProcess    输出进程对象
 * @param OutApcState   输出 APC 状态（用于分离），类型为 KAPC_STATE*
 * @return NTSTATUS
 */
NTSTATUS
HvAttachProcess(
    _In_ ULONG ProcessId,
    _Out_ PEPROCESS* OutProcess,
    _Out_ PVOID OutApcState
);

/*
 * 从目标进程分离
 * 
 * @param Process       进程对象
 * @param ApcState      APC 状态，类型为 KAPC_STATE*
 */
VOID
HvDetachProcess(
    _In_ PEPROCESS Process,
    _In_ PVOID ApcState
);

// ============================================================
// 函数声明 - 内核态无痕隐藏功能
// ============================================================

/*
 * 隐藏已注入的内存区域（真正的内核态无痕）
 * 
 * 实现以下隐藏措施：
 * 1. Hook NtQueryVirtualMemory 过滤内存查询
 * 2. 擦除 PE 头
 * 3. 修改 VAD 属性
 * 4. 从 Working Set 中移除
 * 
 * @param ProcessId     进程 ID
 * @param Address       地址
 * @param Size          大小
 * @return NTSTATUS
 */
NTSTATUS
HvHideInjectedMemory(
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
HvUnhideInjectedMemory(
    _In_ ULONG ProcessId,
    _In_ PVOID Address
);

/*
 * 隐藏注入的模块（从 PEB LdrModuleList）
 * 
 * @param ProcessId     进程 ID
 * @param ModuleBase    模块基址
 * @return NTSTATUS
 */
NTSTATUS
HvHideInjectedModule(
    _In_ ULONG ProcessId,
    _In_ PVOID ModuleBase
);

/*
 * 擦除 PE 头（DOS Header + NT Headers）
 * 防止内存扫描检测
 * 
 * @param ProcessId     进程 ID
 * @param ModuleBase    模块基址
 * @param HeaderSize    要擦除的头部大小（0 = 自动检测）
 * @return NTSTATUS
 */
NTSTATUS
HvErasePeHeader(
    _In_ ULONG ProcessId,
    _In_ PVOID ModuleBase,
    _In_ ULONG HeaderSize
);

/*
 * 修改 VAD 保护属性（伪装为普通内存）
 * 
 * @param ProcessId         进程 ID
 * @param Address           地址
 * @param FakeProtection    伪装的保护属性 (如 PAGE_READWRITE)
 * @return NTSTATUS
 */
NTSTATUS
HvSpoofVadProtection(
    _In_ ULONG ProcessId,
    _In_ PVOID Address,
    _In_ ULONG FakeProtection
);

/*
 * 安装内存隐藏 Hook（NtQueryVirtualMemory）
 * 
 * @return NTSTATUS
 */
NTSTATUS
HvInstallMemoryHideHook(VOID);

/*
 * 移除内存隐藏 Hook
 * 
 * @return NTSTATUS
 */
NTSTATUS
HvRemoveMemoryHideHook(VOID);

/*
 * 添加内存区域到隐藏列表
 * 
 * @param ProcessId     进程 ID
 * @param Address       起始地址
 * @param Size          大小
 * @param HideMode      隐藏模式
 * @return NTSTATUS
 */
NTSTATUS
HvAddHiddenMemoryRegion(
    _In_ ULONG ProcessId,
    _In_ PVOID Address,
    _In_ SIZE_T Size,
    _In_ ULONG HideMode
);

/*
 * 从隐藏列表移除内存区域
 * 
 * @param ProcessId     进程 ID
 * @param Address       起始地址
 * @return NTSTATUS
 */
NTSTATUS
HvRemoveHiddenMemoryRegion(
    _In_ ULONG ProcessId,
    _In_ PVOID Address
);

/*
 * 检查地址是否在隐藏列表中
 * 
 * @param ProcessId     进程 ID
 * @param Address       要检查的地址
 * @return TRUE 如果应该隐藏
 */
BOOLEAN
HvIsAddressHidden(
    _In_ ULONG ProcessId,
    _In_ PVOID Address
);

// 隐藏模式枚举
typedef enum _HV_HIDE_MODE {
    HvHideModeNone = 0,             // 不隐藏
    HvHideModeQueryFilter = 1,      // 过滤 NtQueryVirtualMemory
    HvHideModeSpoofProtection = 2,  // 伪装保护属性
    HvHideModeVadModify = 4,        // 修改 VAD
    HvHideModePeErase = 8,          // 擦除 PE 头
    HvHideModeComplete = 0xFF       // 完整隐藏（所有措施）
} HV_HIDE_MODE;

// 隐藏的内存区域信息
typedef struct _HIDDEN_MEMORY_ENTRY {
    LIST_ENTRY ListEntry;
    ULONG ProcessId;
    UINT64 ProcessCreateTime;
    PVOID BaseAddress;
    SIZE_T RegionSize;
    ULONG HideMode;
    ULONG OriginalProtection;
    ULONG SpoofedProtection;
    BOOLEAN PeHeaderErased;
    BOOLEAN VadModified;
} HIDDEN_MEMORY_ENTRY, *PHIDDEN_MEMORY_ENTRY;

#define MAX_HIDDEN_MEMORY_REGIONS 64

// ============================================================
// 函数声明 - 调试和诊断
// ============================================================

/*
 * 打印注入管理器状态
 */
VOID
HvInjectionPrintStatus(VOID);

/*
 * 获取已注入模块数量
 */
ULONG
HvGetInjectedModuleCount(VOID);

// ============================================================
// 全局变量声明
// ============================================================

extern HV_INJECTION_MANAGER g_InjectionManager;

#endif // _HV_INJECTION_H_
