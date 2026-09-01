/*
 * HvInjection.c
 * 
 * 无痕注入框架实现
 * 
 * 功能：
 *   - Windows loader DLL 注入与 DLL 手动映射
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

#define HV_INJECTION_MAX_PATH_CHARS       520
#define HV_INJECTION_NATIVE_PATH_CHARS    (HV_INJECTION_MAX_PATH_CHARS + 8)
#define HV_INJECTION_MAX_PROCESS_INFO     (64UL * 1024 * 1024)

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

/*
 * Injection shutdown is deliberately split around hook rundown.  The
 * process-notify registration belongs to phase one; list storage belongs to
 * phase two.  The lifecycle push lock serializes initialize/unregister/final
 * cleanup, while Closing is published atomically so callbacks and request
 * paths can fail closed without taking that lock.
 */
#define HV_INJECTION_NOTIFY_UNREGISTERED 0L
#define HV_INJECTION_NOTIFY_REGISTERED   1L

static EX_PUSH_LOCK g_InjectionLifecycleLock = 0;
static volatile LONG g_InjectionClosing = 0;
static volatile LONG g_InjectionListsInitialized = 0;
static volatile LONG g_InjectionProcessNotifyState =
    HV_INJECTION_NOTIFY_UNREGISTERED;
static volatile LONG g_InjectionFinalized = 0;
static volatile LONG g_InjectionLastNotifyStatus = STATUS_SUCCESS;

/* Every public operation that can own injection bookkeeping holds one
 * rundown token.  Queued APCs hold an additional persistent token until the
 * kernel, rundown, insertion-failure, or shutdown-cancel path retires them. */
static EX_RUNDOWN_REF g_InjectionOperationRundown;
static volatile LONG g_InjectionOperationRundownInitialized = 0;
static volatile LONG g_InjectionOperationRundownDrained = 0;

typedef struct _HV_INJECTION_PENDING_APC {
    KAPC Apc;
    LIST_ENTRY ListEntry;
    KEVENT CompletionEvent;
    volatile LONG References;
    volatile LONG CompletionClaimed;
    volatile LONG Listed;
    volatile LONG CancelRequested;
    volatile LONG RundownHeld;
    volatile LONG KernelRoutineEntered;
    volatile LONG UserRoutineDispatched;
    PETHREAD Thread;
} HV_INJECTION_PENDING_APC, *PHV_INJECTION_PENDING_APC;

typedef struct _HV_INJECTION_LDR_LOAD_CONTEXT {
    UNICODE_STRING DllName;
    PVOID ModuleHandle;
    WCHAR SearchPath[HV_INJECTION_MAX_PATH_CHARS];
    WCHAR DllPath[HV_INJECTION_MAX_PATH_CHARS];
} HV_INJECTION_LDR_LOAD_CONTEXT, *PHV_INJECTION_LDR_LOAD_CONTEXT;

typedef struct _HV_INJECTION_DEPENDENCY_PLAN {
    ULONG Count;
    WCHAR SearchPath[HV_INJECTION_MAX_PATH_CHARS];
    WCHAR ModuleNames[MAX_INJECTION_DEPENDENCIES][MAX_MODULE_NAME_LENGTH];
} HV_INJECTION_DEPENDENCY_PLAN, *PHV_INJECTION_DEPENDENCY_PLAN;

static LIST_ENTRY g_InjectionPendingApcList = { 0 };
static KSPIN_LOCK g_InjectionPendingApcLock;
static volatile LONG g_InjectionPendingApcInitialized = 0;
static volatile LONG g_InjectionPendingApcCount = 0;

typedef BOOLEAN (NTAPI *PFN_KE_REMOVE_QUEUE_APC)(
    _Inout_ PRKAPC Apc
);

typedef BOOLEAN (NTAPI *PFN_KE_TEST_ALERT_THREAD)(
    _In_ KPROCESSOR_MODE AlertMode
);

typedef NTSTATUS (NTAPI *PFN_PS_WRAP_APC_WOW64_THREAD)(
    _Inout_ PVOID* ApcContext,
    _Inout_ PVOID* ApcRoutine
);

typedef PEPROCESS (NTAPI *PFN_PS_GET_THREAD_PROCESS)(
    _In_ PETHREAD Thread
);

static PFN_KE_REMOVE_QUEUE_APC g_KeRemoveQueueApc = NULL;
static PFN_KE_TEST_ALERT_THREAD g_KeTestAlertThread = NULL;
static PFN_PS_WRAP_APC_WOW64_THREAD g_PsWrapApcWow64Thread = NULL;
static PFN_PS_GET_THREAD_PROCESS g_PsGetThreadProcess = NULL;

static VOID
InjectionDiagnosticInitialize(
    _Out_opt_ PHV_INJECTION_RESULT Result,
    _In_ ULONG Flags
)
{
    if (!Result) {
        return;
    }

    RtlZeroMemory(Result, sizeof(*Result));
    Result->Diagnostics.Version = HV_INJECTION_DIAGNOSTIC_VERSION;
    Result->Diagnostics.Size = (USHORT)sizeof(Result->Diagnostics);
    Result->Diagnostics.Flags = Flags;
    Result->Diagnostics.PrimaryStatus = STATUS_SUCCESS;
    Result->Diagnostics.CleanupStatus = STATUS_SUCCESS;
    Result->Diagnostics.DependencyIndex = 0xFFFFFFFFUL;
}

static VOID
InjectionDiagnosticRecord(
    _Inout_opt_ PHV_INJECTION_RESULT Result,
    _In_ USHORT Stage,
    _In_ USHORT Phase,
    _In_ NTSTATUS Status,
    _In_ ULONG Detail
)
{
    PHV_INJECTION_DIAGNOSTICS diagnostics;
    PHV_INJECTION_DIAGNOSTIC_EVENT event;

    if (!Result ||
        Result->Diagnostics.Version != HV_INJECTION_DIAGNOSTIC_VERSION) {
        return;
    }

    diagnostics = &Result->Diagnostics;
    if (diagnostics->EventCount >= HV_INJECTION_DIAGNOSTIC_MAX_EVENTS) {
        diagnostics->DroppedEventCount++;
        diagnostics->Flags |= HV_INJECTION_DIAG_FLAG_EVENTS_DROPPED;
        return;
    }

    event = &diagnostics->Events[diagnostics->EventCount++];
    event->Stage = Stage;
    event->Phase = Phase;
    event->Status = Status;
    event->Detail = Detail;
}

static VOID
InjectionDiagnosticFailure(
    _Inout_opt_ PHV_INJECTION_RESULT Result,
    _In_ USHORT Stage,
    _In_ NTSTATUS Status,
    _In_ ULONG Detail
)
{
    PHV_INJECTION_DIAGNOSTICS diagnostics;
    PHV_INJECTION_DIAGNOSTIC_EVENT lastEvent;
    BOOLEAN alreadyRecorded = FALSE;

    if (Result &&
        Result->Diagnostics.Version == HV_INJECTION_DIAGNOSTIC_VERSION) {
        diagnostics = &Result->Diagnostics;
        if (diagnostics->EventCount != 0) {
            lastEvent = &diagnostics->Events[diagnostics->EventCount - 1];
            alreadyRecorded =
                lastEvent->Stage == Stage &&
                lastEvent->Phase == HvInjectDiagnosticPhaseOperation &&
                lastEvent->Status == Status &&
                lastEvent->Detail == Detail;
        }
    }
    if (!alreadyRecorded) {
        InjectionDiagnosticRecord(
            Result,
            Stage,
            HvInjectDiagnosticPhaseOperation,
            Status,
            Detail);
    }
    if (Result &&
        Result->Diagnostics.Version == HV_INJECTION_DIAGNOSTIC_VERSION &&
        Result->Diagnostics.PrimaryStage == HvInjectStageNone) {
        Result->Diagnostics.PrimaryStage = Stage;
        Result->Diagnostics.PrimaryStatus = Status;
    }
}

static VOID
InjectionDiagnosticCleanup(
    _Inout_opt_ PHV_INJECTION_RESULT Result,
    _In_ USHORT Stage,
    _In_ NTSTATUS Status,
    _In_ ULONG Detail
)
{
    InjectionDiagnosticRecord(
        Result,
        Stage,
        HvInjectDiagnosticPhaseCleanup,
        Status,
        Detail);
    if (!Result ||
        Result->Diagnostics.Version != HV_INJECTION_DIAGNOSTIC_VERSION) {
        return;
    }

    Result->Diagnostics.Flags |= HV_INJECTION_DIAG_FLAG_ROLLBACK_STARTED;
    if (!NT_SUCCESS(Status)) {
        Result->Diagnostics.Flags |=
            HV_INJECTION_DIAG_FLAG_CLEANUP_FAILED;
        if (Result->Diagnostics.CleanupStage == HvInjectStageNone) {
            Result->Diagnostics.CleanupStage = Stage;
            Result->Diagnostics.CleanupStatus = Status;
        }
    }
}

static VOID
InjectionDiagnosticSubject(
    _Inout_opt_ PHV_INJECTION_RESULT Result,
    _In_opt_ PCWSTR Subject,
    _In_ BOOLEAN CleanupSubject
)
{
    PWCHAR destination;
    ULONG index;

    if (!Result || !Subject ||
        Result->Diagnostics.Version != HV_INJECTION_DIAGNOSTIC_VERSION) {
        return;
    }

    destination = CleanupSubject
        ? Result->Diagnostics.CleanupSubject
        : Result->Diagnostics.FailureSubject;
    RtlZeroMemory(
        destination,
        sizeof(Result->Diagnostics.FailureSubject));
    for (index = 0;
         index + 1 < HV_INJECTION_DIAGNOSTIC_SUBJECT_CHARS &&
         Subject[index] != L'\0';
         index++) {
        destination[index] = Subject[index];
    }
    destination[index] = L'\0';
}

static VOID
InjectionDiagnosticFinalize(
    _Inout_opt_ PHV_INJECTION_RESULT Result,
    _In_ NTSTATUS Status,
    _In_ USHORT FallbackStage
)
{
    if (!Result) {
        return;
    }

    Result->Status = Status;
    if (!NT_SUCCESS(Status) &&
        Result->Diagnostics.PrimaryStage == HvInjectStageNone) {
        InjectionDiagnosticFailure(Result, FallbackStage, Status, 0);
    }
    InjectionDiagnosticRecord(
        Result,
        HvInjectStageComplete,
        HvInjectDiagnosticPhaseOperation,
        Status,
        0);
}

// 隐藏内存区域全局列表（前向声明，用于 HvInjectionCleanup）
static LIST_ENTRY g_HiddenMemoryList = { 0 };
static KSPIN_LOCK g_HiddenMemoryLock;
static BOOLEAN g_HiddenMemoryInitialized = FALSE;
static ULONG g_HiddenMemoryCount = 0;

static VOID InitHiddenMemoryList(VOID);

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

typedef NTSTATUS (NTAPI *PFN_MM_COPY_VIRTUAL_MEMORY)(
    _In_ PEPROCESS FromProcess,
    _In_ PVOID FromAddress,
    _In_ PEPROCESS ToProcess,
    _In_ PVOID ToAddress,
    _In_ SIZE_T BufferSize,
    _In_ KPROCESSOR_MODE PreviousMode,
    _Out_ PSIZE_T NumberOfBytesCopied
);

static PFN_MM_COPY_VIRTUAL_MEMORY g_MmCopyVirtualMemory = NULL;

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

NTKERNELAPI PVOID PsGetProcessWow64Process(
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

// ============================================================
// 内部函数声明
// ============================================================

static VOID InjectionResolveOptionalApcRoutines(VOID);

static BOOLEAN
InjectionRangeWithinSize(
    _In_ SIZE_T Offset,
    _In_ SIZE_T Length,
    _In_ SIZE_T TotalSize
);

static BOOLEAN
InjectionRvaRangeValid(
    _In_ PIMAGE_NT_HEADERS64_INJ NtHeaders,
    _In_ ULONG Rva,
    _In_ SIZE_T Length
);

static BOOLEAN
InjectionAnsiStringRvaValid(
    _In_ PVOID ImageBase,
    _In_ PIMAGE_NT_HEADERS64_INJ NtHeaders,
    _In_ ULONG Rva,
    _In_ SIZE_T MaximumLength
);

static NTSTATUS
InjectionMemoryAllocateCore(
    _In_ ULONG ProcessId,
    _In_ SIZE_T Size,
    _In_ ULONG Protection,
    _Out_ PVOID* OutAddress
);

static NTSTATUS
InjectionMemoryFreeCore(
    _In_ ULONG ProcessId,
    _In_ PVOID Address
);

static VOID
InjectionPendingApcDereference(
    _Inout_ PHV_INJECTION_PENDING_APC PendingApc
);

static BOOLEAN
InjectionCancelPendingApc(
    _Inout_ PHV_INJECTION_PENDING_APC PendingApc
);

static VOID
NTAPI
ApcKernelRoutine(
    _In_ PRKAPC Apc,
    _Inout_ PKNORMAL_ROUTINE_INJ* NormalRoutine,
    _Inout_ PVOID* NormalContext,
    _Inout_ PVOID* SystemArgument1,
    _Inout_ PVOID* SystemArgument2
);

static VOID
NTAPI
ApcForceDeliveryKernelRoutine(
    _In_ PRKAPC Apc,
    _Inout_ PKNORMAL_ROUTINE_INJ* NormalRoutine,
    _Inout_ PVOID* NormalContext,
    _Inout_ PVOID* SystemArgument1,
    _Inout_ PVOID* SystemArgument2
);

static NTSTATUS
InjectionNormalizeFilePath(
    _In_ PCWSTR InputPath,
    _Out_writes_(OutputChars) PWSTR OutputPath,
    _In_ SIZE_T OutputChars,
    _Out_ PUNICODE_STRING NativePath
);

static NTSTATUS
InjectionNormalizeUserLoaderPath(
    _In_ PCWSTR InputPath,
    _Out_writes_(OutputChars) PWSTR OutputPath,
    _In_ SIZE_T OutputChars,
    _Out_ PSIZE_T OutputLength
);

static NTSTATUS
InjectionBuildDependencySearchPath(
    _In_opt_ PCWSTR SourcePath,
    _Out_writes_(OutputChars) PWSTR OutputPath,
    _In_ SIZE_T OutputChars
);

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
InjectionCollectImportModules(
    _In_ PVOID ImageBase,
    _In_ PIMAGE_NT_HEADERS64_INJ NtHeaders,
    _Inout_ PHV_INJECTION_DEPENDENCY_PLAN Plan
)
{
    PIMAGE_DATA_DIRECTORY_INJ importDirectory;
    PIMAGE_IMPORT_DESCRIPTOR_INJ importDescriptor;
    ULONG descriptorCount;
    ULONG descriptorIndex;
    BOOLEAN terminated = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    if (!ImageBase || !NtHeaders || !Plan) {
        return STATUS_INVALID_PARAMETER;
    }
    Plan->Count = 0;
    RtlZeroMemory(Plan->ModuleNames, sizeof(Plan->ModuleNames));

    importDirectory = &NtHeaders->OptionalHeader.DataDirectory[
        IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDirectory->VirtualAddress == 0 ||
        importDirectory->Size == 0) {
        return STATUS_SUCCESS;
    }
    if (importDirectory->Size < sizeof(IMAGE_IMPORT_DESCRIPTOR_INJ) ||
        !InjectionRvaRangeValid(
            NtHeaders,
            importDirectory->VirtualAddress,
            importDirectory->Size)) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    descriptorCount = importDirectory->Size /
        sizeof(IMAGE_IMPORT_DESCRIPTOR_INJ);
    importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR_INJ)(
        (PUCHAR)ImageBase + importDirectory->VirtualAddress);

    __try {
        for (descriptorIndex = 0;
             descriptorIndex < descriptorCount;
             descriptorIndex++, importDescriptor++) {
            PCSTR moduleName;
            ANSI_STRING ansiName;
            UNICODE_STRING unicodeName;
            WCHAR moduleNameBuffer[MAX_MODULE_NAME_LENGTH] = { 0 };
            BOOLEAN duplicate = FALSE;
            ULONG existingIndex;

            if (importDescriptor->Name == 0) {
                terminated = TRUE;
                break;
            }
            if (!InjectionAnsiStringRvaValid(
                    ImageBase,
                    NtHeaders,
                    importDescriptor->Name,
                    MAX_MODULE_NAME_LENGTH)) {
                return STATUS_INVALID_IMAGE_FORMAT;
            }

            moduleName = (PCSTR)(
                (PUCHAR)ImageBase + importDescriptor->Name);
            RtlInitAnsiString(&ansiName, moduleName);
            unicodeName.Buffer = moduleNameBuffer;
            unicodeName.Length = 0;
            unicodeName.MaximumLength = sizeof(moduleNameBuffer);
            status = RtlAnsiStringToUnicodeString(
                &unicodeName, &ansiName, FALSE);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            if (unicodeName.Length == 0 ||
                unicodeName.Length / sizeof(WCHAR) >=
                    RTL_NUMBER_OF(moduleNameBuffer)) {
                return STATUS_NAME_TOO_LONG;
            }
            moduleNameBuffer[unicodeName.Length / sizeof(WCHAR)] = L'\0';

            for (existingIndex = 0;
                 existingIndex < Plan->Count;
                 existingIndex++) {
                UNICODE_STRING existingName;
                RtlInitUnicodeString(
                    &existingName, Plan->ModuleNames[existingIndex]);
                if (RtlCompareUnicodeString(
                        &existingName, &unicodeName, TRUE) == 0) {
                    duplicate = TRUE;
                    break;
                }
            }
            if (duplicate) {
                continue;
            }
            if (Plan->Count == MAX_INJECTION_DEPENDENCIES) {
                return STATUS_BUFFER_OVERFLOW;
            }

            RtlCopyMemory(
                Plan->ModuleNames[Plan->Count],
                moduleNameBuffer,
                unicodeName.Length);
            Plan->ModuleNames[Plan->Count][
                unicodeName.Length / sizeof(WCHAR)] = L'\0';
            Plan->Count++;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }

    return terminated ? STATUS_SUCCESS : STATUS_INVALID_IMAGE_FORMAT;
}

static NTSTATUS
InjectionCollectTlsCallbacks(
    _In_ PVOID ImageBase,
    _In_ PIMAGE_NT_HEADERS64_INJ NtHeaders,
    _Out_writes_(MAX_INJECTION_TLS_CALLBACKS) PVOID* Callbacks,
    _Out_ PULONG CallbackCount
);

static NTSTATUS
InjectionAttachTlsCallbacks(
    _In_ ULONG ProcessId,
    _Inout_ PINJECTED_MODULE_ENTRY ModuleEntry,
    _Inout_ PBOOLEAN RollbackSafe
);

static NTSTATUS
InjectionDetachTlsCallbacks(
    _In_ ULONG ProcessId,
    _Inout_ PINJECTED_MODULE_ENTRY ModuleEntry,
    _Inout_ PBOOLEAN RollbackSafe
);

static NTSTATUS
InjectionCallUserRoutine(
    _In_ ULONG ProcessId,
    _In_ UINT64 ProcessCreateTime,
    _In_ PVOID Routine,
    _In_opt_ PVOID Argument1,
    _In_opt_ PVOID Argument2,
    _In_opt_ PVOID Argument3,
    _In_opt_ PVOID Argument4,
    _Out_opt_ PULONGLONG ReturnValue,
    _Inout_ PBOOLEAN RollbackSafe
);

static NTSTATUS
InjectionLoadModuleReference(
    _In_ ULONG ProcessId,
    _In_ UINT64 ProcessCreateTime,
    _In_ PVOID LoadRoutine,
    _In_opt_ PCWSTR SearchPath,
    _In_ PCWSTR DllName,
    _Out_ PVOID* ModuleBase,
    _Inout_ PBOOLEAN RollbackSafe,
    _In_ ULONG DependencyIndex,
    _Inout_opt_ PHV_INJECTION_RESULT DiagnosticResult,
    _Out_opt_ PUSHORT FailureStage
);

static NTSTATUS
InjectionAcquireDependencyReferences(
    _In_ ULONG ProcessId,
    _In_ UINT64 ProcessCreateTime,
    _In_ PVOID LoadRoutine,
    _In_ PVOID UnloadRoutine,
    _In_ PHV_INJECTION_DEPENDENCY_PLAN Plan,
    _Inout_ PINJECTED_MODULE_ENTRY ModuleEntry,
    _Inout_ PBOOLEAN RollbackSafe,
    _Inout_opt_ PHV_INJECTION_RESULT DiagnosticResult
);

static NTSTATUS
InjectionReleaseDependencyReferences(
    _In_ ULONG ProcessId,
    _Inout_ PINJECTED_MODULE_ENTRY ModuleEntry,
    _Inout_ PBOOLEAN RollbackSafe,
    _In_opt_ PHV_INJECTION_DEPENDENCY_PLAN Plan,
    _Inout_opt_ PHV_INJECTION_RESULT DiagnosticResult
);

static PVOID
InjectionGetModuleBase(
    _In_ PEPROCESS Process,
    _In_ PCWSTR ModuleName
);

static PVOID
InjectionGetProcAddress(
    _In_ PEPROCESS Process,
    _In_ PVOID ModuleBase,
    _In_ ULONG_PTR NameOrOrdinal,
    _In_ ULONG RecursionDepth
);

static PINJECTED_MODULE_ENTRY
InjectionClaimModule(
    _In_ ULONG ProcessId,
    _In_ UINT64 ProcessCreateTime,
    _In_ PVOID ModuleBase
);

static VOID
InjectionRestoreClaimedModule(
    _Inout_ PINJECTED_MODULE_ENTRY ModuleEntry
);

static NTSTATUS
InjectionSetModuleHiddenState(
    _In_ ULONG ProcessId,
    _In_ UINT64 ProcessCreateTime,
    _In_ PVOID ModuleBase,
    _In_ BOOLEAN IsHidden
);

static VOID
InjectionProcessNotifyCallback(
    _In_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _In_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
);

static VOID InjectionCancelPendingApcs(VOID);

static NTSTATUS
InjectionQueueUserApcCore(
    _In_ ULONG ProcessId,
    _In_ ULONG ThreadId,
    _In_ PVOID ApcRoutine,
    _In_opt_ PVOID ApcContext,
    _In_ BOOLEAN WaitComplete
);

static NTSTATUS
InjectionQueueUserApcExCore(
    _In_ ULONG ProcessId,
    _In_ ULONG ThreadId,
    _In_ PVOID ApcRoutine,
    _In_opt_ PVOID ApcContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2,
    _In_ BOOLEAN WaitComplete
);

static NTSTATUS
InjectionQueueKernelApc(
    _In_ PETHREAD Thread,
    _In_ PVOID KernelRoutine,
    _In_opt_ PVOID NormalRoutine,
    _In_ KPROCESSOR_MODE ProcessorMode,
    _In_opt_ PVOID NormalContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2,
    _Outptr_opt_result_maybenull_ PHV_INJECTION_PENDING_APC* OutPendingApc
);

static NTSTATUS
InjectionHideInjectedModuleCore(
    _In_ ULONG ProcessId,
    _In_ PVOID ModuleBase
);

static NTSTATUS
InjectionInjectDllFromFileCore(
    _In_ ULONG ProcessId,
    _In_ PCWSTR DllPath,
    _Out_opt_ PHV_INJECTION_RESULT OutResult
);

static NTSTATUS
InjectionInjectDllViaLoaderCore(
    _In_ ULONG ProcessId,
    _In_ PCWSTR DllPath,
    _Out_opt_ PHV_INJECTION_RESULT OutResult
);

static BOOLEAN
InjectionIsValidProtection(
    _In_ ULONG Protection
)
{
    ULONG baseProtection = Protection & 0xFFUL;
    ULONG allowedModifiers = PAGE_GUARD | PAGE_NOCACHE | PAGE_WRITECOMBINE;

    if ((Protection & ~(0xFFUL | allowedModifiers)) != 0) {
        return FALSE;
    }

    return baseProtection == PAGE_NOACCESS ||
           baseProtection == PAGE_READONLY ||
           baseProtection == PAGE_READWRITE ||
           baseProtection == PAGE_WRITECOPY ||
           baseProtection == PAGE_EXECUTE ||
           baseProtection == PAGE_EXECUTE_READ ||
           baseProtection == PAGE_EXECUTE_READWRITE ||
           baseProtection == PAGE_EXECUTE_WRITECOPY;
}

// ============================================================
// 初始化和清理
// ============================================================

static BOOLEAN
InjectionIsOpen(VOID)
{
    return InterlockedCompareExchange(&g_InjectionClosing, 0, 0) == 0 &&
           g_InjectionManager.Initialized;
}

static BOOLEAN
InjectionApcExecutionAvailable(VOID)
{
    return g_KeRemoveQueueApc != NULL &&
           g_KeTestAlertThread != NULL &&
           g_PsGetThreadProcess != NULL;
}

static BOOLEAN
InjectionIsPathSeparator(
    _In_ WCHAR Character
)
{
    return Character == L'\\' || Character == L'/';
}

static NTSTATUS
InjectionOperationAcquire(VOID)
{
    if (!InjectionIsOpen() ||
        InterlockedCompareExchange(
            &g_InjectionOperationRundownInitialized, 0, 0) == 0) {
        return InterlockedCompareExchange(&g_InjectionClosing, 0, 0) != 0
            ? STATUS_DELETE_PENDING
            : STATUS_DEVICE_NOT_READY;
    }

    if (!ExAcquireRundownProtection(&g_InjectionOperationRundown)) {
        return STATUS_DELETE_PENDING;
    }

    /* Closing may have published between the first test and acquisition. */
    if (!InjectionIsOpen()) {
        ExReleaseRundownProtection(&g_InjectionOperationRundown);
        return STATUS_DELETE_PENDING;
    }
    return STATUS_SUCCESS;
}

static BOOLEAN
InjectionAppendCallStubBytes(
    _Out_writes_bytes_(BufferSize) PUCHAR Buffer,
    _In_ SIZE_T BufferSize,
    _Inout_ PSIZE_T Offset,
    _In_reads_bytes_(ValueSize) const VOID* Value,
    _In_ SIZE_T ValueSize
)
{
    if (!Buffer || !Offset || !Value ||
        !InjectionRangeWithinSize(*Offset, ValueSize, BufferSize)) {
        return FALSE;
    }
    RtlCopyMemory(Buffer + *Offset, Value, ValueSize);
    *Offset += ValueSize;
    return TRUE;
}

static BOOLEAN
InjectionCancelCallApcAndCheckStubSafe(
    _Inout_ PHV_INJECTION_PENDING_APC PendingApc
)
{
    LARGE_INTEGER timeout;
    NTSTATUS waitStatus;

    if (!PendingApc) {
        return TRUE;
    }
    if (InjectionCancelPendingApc(PendingApc)) {
        return TRUE;
    }

    timeout.QuadPart = -10LL * 10 * 1000 * 1000;
    waitStatus = KeWaitForSingleObject(
        &PendingApc->CompletionEvent,
        Executive,
        KernelMode,
        FALSE,
        &timeout);
    if (waitStatus != STATUS_SUCCESS) {
        return FALSE;
    }
    return InterlockedCompareExchange(
        &PendingApc->UserRoutineDispatched, 0, 0) == 0;
}

static NTSTATUS
InjectionBuildCallStub64(
    _Out_writes_bytes_(BufferSize) PUCHAR Buffer,
    _In_ SIZE_T BufferSize,
    _In_ PVOID Routine,
    _In_opt_ PVOID Argument1,
    _In_opt_ PVOID Argument2,
    _In_opt_ PVOID Argument3,
    _In_opt_ PVOID Argument4,
    _In_ PVOID ResultAddress,
    _Out_ PSIZE_T StubSize
)
{
    static const UCHAR endBranch64[] = { 0xF3, 0x0F, 0x1E, 0xFA };
    static const UCHAR stackPrologue[] = { 0x48, 0x83, 0xEC, 0x28 };
    static const UCHAR moveRcx[] = { 0x48, 0xB9 };
    static const UCHAR moveRdx[] = { 0x48, 0xBA };
    static const UCHAR moveR8[] = { 0x49, 0xB8 };
    static const UCHAR moveR9[] = { 0x49, 0xB9 };
    static const UCHAR moveRax[] = { 0x48, 0xB8 };
    static const UCHAR callRax[] = { 0xFF, 0xD0 };
    static const UCHAR moveR10[] = { 0x49, 0xBA };
    static const UCHAR storeRax[] = { 0x49, 0x89, 0x02 };
    static const UCHAR stackEpilogue[] = {
        0x48, 0x83, 0xC4, 0x28, 0xC3
    };
    SIZE_T offset = 0;
    ULONGLONG immediate;

    if (!Buffer || !Routine || !ResultAddress || !StubSize) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(Buffer, BufferSize);

#define APPEND_STUB_VALUE(value) \
    InjectionAppendCallStubBytes( \
        Buffer, BufferSize, &offset, (value), sizeof(*(value)))

    if (!InjectionAppendCallStubBytes(
            Buffer, BufferSize, &offset,
            endBranch64, sizeof(endBranch64)) ||
        !InjectionAppendCallStubBytes(
            Buffer, BufferSize, &offset,
            stackPrologue, sizeof(stackPrologue)) ||
        !InjectionAppendCallStubBytes(
            Buffer, BufferSize, &offset, moveRcx, sizeof(moveRcx))) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    immediate = (ULONGLONG)(ULONG_PTR)Argument1;
    if (!APPEND_STUB_VALUE(&immediate) ||
        !InjectionAppendCallStubBytes(
            Buffer, BufferSize, &offset, moveRdx, sizeof(moveRdx))) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    immediate = (ULONGLONG)(ULONG_PTR)Argument2;
    if (!APPEND_STUB_VALUE(&immediate) ||
        !InjectionAppendCallStubBytes(
            Buffer, BufferSize, &offset, moveR8, sizeof(moveR8))) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    immediate = (ULONGLONG)(ULONG_PTR)Argument3;
    if (!APPEND_STUB_VALUE(&immediate) ||
        !InjectionAppendCallStubBytes(
            Buffer, BufferSize, &offset, moveR9, sizeof(moveR9))) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    immediate = (ULONGLONG)(ULONG_PTR)Argument4;
    if (!APPEND_STUB_VALUE(&immediate) ||
        !InjectionAppendCallStubBytes(
            Buffer, BufferSize, &offset, moveRax, sizeof(moveRax))) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    immediate = (ULONGLONG)(ULONG_PTR)Routine;
    if (!APPEND_STUB_VALUE(&immediate) ||
        !InjectionAppendCallStubBytes(
            Buffer, BufferSize, &offset, callRax, sizeof(callRax)) ||
        !InjectionAppendCallStubBytes(
            Buffer, BufferSize, &offset, moveR10, sizeof(moveR10))) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    immediate = (ULONGLONG)(ULONG_PTR)ResultAddress;
    if (!APPEND_STUB_VALUE(&immediate) ||
        !InjectionAppendCallStubBytes(
            Buffer, BufferSize, &offset, storeRax, sizeof(storeRax)) ||
        !InjectionAppendCallStubBytes(
            Buffer, BufferSize, &offset,
            stackEpilogue, sizeof(stackEpilogue))) {
        return STATUS_BUFFER_TOO_SMALL;
    }

#undef APPEND_STUB_VALUE

    *StubSize = offset;
    return STATUS_SUCCESS;
}

static NTSTATUS
InjectionCallUserRoutine(
    _In_ ULONG ProcessId,
    _In_ UINT64 ProcessCreateTime,
    _In_ PVOID Routine,
    _In_opt_ PVOID Argument1,
    _In_opt_ PVOID Argument2,
    _In_opt_ PVOID Argument3,
    _In_opt_ PVOID Argument4,
    _Out_opt_ PULONGLONG ReturnValue,
    _Inout_ PBOOLEAN RollbackSafe
)
{
    NTSTATUS status;
    NTSTATUS waitStatus;
    NTSTATUS forceStatus;
    PEPROCESS process = NULL;
    PETHREAD thread = NULL;
    KAPC_STATE_INJ apcState;
    PVOID ntdllBase = NULL;
    PVOID fenceRoutine = NULL;
    PVOID stubBase = NULL;
    PVOID resultAddress;
    PHV_INJECTION_PENDING_APC callApc = NULL;
    PHV_INJECTION_PENDING_APC fenceApc = NULL;
    UCHAR stubBuffer[128];
    SIZE_T stubSize = 0;
    ULONGLONG routineResult = 0;
    LARGE_INTEGER timeout;
    BOOLEAN freeStub = TRUE;

    if (ReturnValue) {
        *ReturnValue = 0;
    }
    if (!RollbackSafe || !*RollbackSafe || ProcessId == 0 ||
        ProcessCreateTime == 0 || !Routine) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!InjectionApcExecutionAvailable()) {
        return STATUS_NOT_SUPPORTED;
    }

    status = PsLookupProcessByProcessId(
        (HANDLE)(ULONG_PTR)ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }
    if ((UINT64)PsGetProcessCreateTimeQuadPart(process) !=
            ProcessCreateTime ||
        PsGetProcessExitStatus(process) != STATUS_PENDING) {
        status = STATUS_INVALID_CID;
        goto Exit;
    }
    if (PsGetProcessWow64Process(process) != NULL) {
        status = STATUS_IMAGE_MACHINE_TYPE_MISMATCH;
        goto Exit;
    }

    KeStackAttachProcess((PRKPROCESS)process, &apcState);
    __try {
        ntdllBase = InjectionGetModuleBase(process, L"ntdll.dll");
        if (ntdllBase) {
            fenceRoutine = InjectionGetProcAddress(
                process,
                ntdllBase,
                (ULONG_PTR)"NtYieldExecution",
                0);
        }
    }
    __finally {
        KeUnstackDetachProcess(&apcState);
    }
    if (!fenceRoutine) {
        status = STATUS_PROCEDURE_NOT_FOUND;
        goto Exit;
    }

    status = HvFindAlertableThread(process, &thread);
    if (!NT_SUCCESS(status) || !thread) {
        goto Exit;
    }
    if (PsGetThreadProcessId(thread) != (HANDLE)(ULONG_PTR)ProcessId ||
        g_PsGetThreadProcess(thread) != process) {
        status = STATUS_INVALID_CID;
        goto Exit;
    }

    status = InjectionMemoryAllocateCore(
        ProcessId, PAGE_SIZE, PAGE_EXECUTE_READWRITE, &stubBase);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }
    if ((UINT64)PsGetProcessCreateTimeQuadPart(process) !=
            ProcessCreateTime ||
        PsGetProcessExitStatus(process) != STATUS_PENDING) {
        status = STATUS_INVALID_CID;
        goto Exit;
    }
    resultAddress = (PUCHAR)stubBase + 0x100;

    status = InjectionBuildCallStub64(
        stubBuffer,
        sizeof(stubBuffer),
        Routine,
        Argument1,
        Argument2,
        Argument3,
        Argument4,
        resultAddress,
        &stubSize);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }
    status = HvMemoryWrite(
        ProcessId, stubBase, stubBuffer, stubSize, NULL);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }
    status = HvMemoryWrite(
        ProcessId,
        resultAddress,
        &routineResult,
        sizeof(routineResult),
        NULL);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

    status = InjectionQueueKernelApc(
        thread,
        (PVOID)ApcKernelRoutine,
        stubBase,
        UserMode,
        NULL,
        NULL,
        NULL,
        &callApc);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }
    status = InjectionQueueKernelApc(
        thread,
        (PVOID)ApcKernelRoutine,
        fenceRoutine,
        UserMode,
        NULL,
        NULL,
        NULL,
        &fenceApc);
    if (!NT_SUCCESS(status)) {
        if (!InjectionCancelCallApcAndCheckStubSafe(callApc)) {
            freeStub = FALSE;
        }
        goto Exit;
    }

    forceStatus = InjectionQueueKernelApc(
        thread,
        (PVOID)ApcForceDeliveryKernelRoutine,
        NULL,
        KernelMode,
        NULL,
        NULL,
        NULL,
        NULL);
    if (!NT_SUCCESS(forceStatus)) {
        if (InterlockedCompareExchange(
                &fenceApc->KernelRoutineEntered, 0, 0) == 0) {
            (void)InjectionCancelPendingApc(fenceApc);
            if (!InjectionCancelCallApcAndCheckStubSafe(callApc)) {
                freeStub = FALSE;
            }
            status = forceStatus;
            goto Exit;
        }
    }

    timeout.QuadPart = -10LL * 10 * 1000 * 1000;
    waitStatus = KeWaitForSingleObject(
        &fenceApc->CompletionEvent,
        Executive,
        KernelMode,
        FALSE,
        &timeout);
    if (waitStatus != STATUS_SUCCESS ||
        InterlockedCompareExchange(
            &fenceApc->KernelRoutineEntered, 0, 0) == 0) {
        (void)InjectionCancelPendingApc(fenceApc);
        if (!InjectionCancelCallApcAndCheckStubSafe(callApc)) {
            freeStub = FALSE;
        }
        status = waitStatus == STATUS_SUCCESS
            ? STATUS_THREAD_IS_TERMINATING
            : waitStatus;
        goto Exit;
    }

    if (InterlockedCompareExchange(
            &callApc->UserRoutineDispatched, 0, 0) == 0) {
        status = InterlockedCompareExchange(
            &g_InjectionClosing, 0, 0) != 0
            ? STATUS_DELETE_PENDING
            : STATUS_THREAD_IS_TERMINATING;
        goto Exit;
    }

    if (ReturnValue) {
        status = HvMemoryRead(
            ProcessId,
            resultAddress,
            &routineResult,
            sizeof(routineResult),
            NULL);
        if (NT_SUCCESS(status)) {
            *ReturnValue = routineResult;
        } else {
            *RollbackSafe = FALSE;
        }
    } else {
        status = STATUS_SUCCESS;
    }

Exit:
    if (fenceApc) {
        InjectionPendingApcDereference(fenceApc);
    }
    if (callApc) {
        InjectionPendingApcDereference(callApc);
    }
    if (thread) {
        ObDereferenceObject(thread);
    }
    if (process) {
        ObDereferenceObject(process);
    }
    if (stubBase && freeStub) {
        NTSTATUS freeStatus = InjectionMemoryFreeCore(
            ProcessId, stubBase);
        if (!NT_SUCCESS(freeStatus)) {
            DbgPrint("[Injection] User-call stub cleanup failed: 0x%X\n",
                freeStatus);
        }
    } else if (stubBase) {
        *RollbackSafe = FALSE;
        DbgPrint("[Injection] User call did not reach its completion fence; target allocation retained\n");
    }
    return status;
}

static NTSTATUS
InjectionLoadModuleReference(
    _In_ ULONG ProcessId,
    _In_ UINT64 ProcessCreateTime,
    _In_ PVOID LoadRoutine,
    _In_opt_ PCWSTR SearchPath,
    _In_ PCWSTR DllName,
    _Out_ PVOID* ModuleBase,
    _Inout_ PBOOLEAN RollbackSafe,
    _In_ ULONG DependencyIndex,
    _Inout_opt_ PHV_INJECTION_RESULT DiagnosticResult,
    _Out_opt_ PUSHORT FailureStage
)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    NTSTATUS loaderStatus;
    NTSTATUS cleanupStatus;
    PHV_INJECTION_LDR_LOAD_CONTEXT localContext = NULL;
    PVOID remoteContext = NULL;
    SIZE_T nameLength = 0;
    SIZE_T searchLength = 0;
    SIZE_T dllPathLength;
    SIZE_T contextSize;
    SIZE_T bytesTransferred = 0;
    ULONGLONG routineResult = 0;
    ULONG detail = DependencyIndex & HV_INJECTION_DIAG_DETAIL_INDEX_MASK;
    BOOLEAN appendSeparator = FALSE;

    if (!SearchPath || SearchPath[0] == L'\0') {
        detail |= HV_INJECTION_DIAG_DETAIL_DEFAULT_SEARCH;
    }
    if (FailureStage) {
        *FailureStage = HvInjectStageManualLoadDependencies;
    }

    if (ModuleBase) {
        *ModuleBase = NULL;
    }
    if (ProcessId == 0 || ProcessCreateTime == 0 || !LoadRoutine ||
        !DllName || !ModuleBase || !RollbackSafe || !*RollbackSafe) {
        InjectionDiagnosticRecord(
            DiagnosticResult,
            HvInjectStageManualLoadDependencies,
            HvInjectDiagnosticPhaseOperation,
            STATUS_INVALID_PARAMETER,
            detail);
        return STATUS_INVALID_PARAMETER;
    }

    while (nameLength < MAX_MODULE_NAME_LENGTH &&
           DllName[nameLength] != L'\0') {
        nameLength++;
    }
    if (nameLength == 0 || nameLength == MAX_MODULE_NAME_LENGTH) {
        InjectionDiagnosticRecord(
            DiagnosticResult,
            HvInjectStageManualLoadDependencies,
            HvInjectDiagnosticPhaseOperation,
            STATUS_NAME_TOO_LONG,
            detail);
        return STATUS_NAME_TOO_LONG;
    }
    if (SearchPath) {
        while (searchLength < HV_INJECTION_MAX_PATH_CHARS &&
               SearchPath[searchLength] != L'\0') {
            searchLength++;
        }
        if (searchLength == HV_INJECTION_MAX_PATH_CHARS) {
            InjectionDiagnosticRecord(
                DiagnosticResult,
                HvInjectStageManualLoadDependencies,
                HvInjectDiagnosticPhaseOperation,
                STATUS_NAME_TOO_LONG,
                detail);
            return STATUS_NAME_TOO_LONG;
        }
    }
    dllPathLength = nameLength;
    if (searchLength != 0) {
        appendSeparator =
            !InjectionIsPathSeparator(SearchPath[searchLength - 1]);
        if (searchLength + (appendSeparator ? 1 : 0) + nameLength >=
            HV_INJECTION_MAX_PATH_CHARS) {
            InjectionDiagnosticRecord(
                DiagnosticResult,
                HvInjectStageManualLoadDependencies,
                HvInjectDiagnosticPhaseOperation,
                STATUS_NAME_TOO_LONG,
                detail);
            return STATUS_NAME_TOO_LONG;
        }
        dllPathLength = searchLength +
            (appendSeparator ? 1 : 0) + nameLength;
    }

    localContext = (PHV_INJECTION_LDR_LOAD_CONTEXT)
        HvAllocateNonPagedZeroed(sizeof(*localContext), HV_INJECTION_TAG);
    if (!localContext) {
        if (FailureStage) {
            *FailureStage = HvInjectStageDependencyAllocateContext;
        }
        InjectionDiagnosticRecord(
            DiagnosticResult,
            HvInjectStageDependencyAllocateContext,
            HvInjectDiagnosticPhaseOperation,
            STATUS_INSUFFICIENT_RESOURCES,
            detail);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    if (searchLength != 0) {
        RtlCopyMemory(
            localContext->DllPath,
            SearchPath,
            searchLength * sizeof(WCHAR));
        if (appendSeparator) {
            localContext->DllPath[searchLength++] = L'\\';
        }
    }
    RtlCopyMemory(
        localContext->DllPath + searchLength,
        DllName,
        nameLength * sizeof(WCHAR));
    localContext->DllPath[dllPathLength] = L'\0';

    contextSize = FIELD_OFFSET(HV_INJECTION_LDR_LOAD_CONTEXT, DllPath) +
        (dllPathLength + 1) * sizeof(WCHAR);
    status = InjectionMemoryAllocateCore(
        ProcessId, contextSize, PAGE_READWRITE, &remoteContext);
    if (!NT_SUCCESS(status)) {
        if (FailureStage) {
            *FailureStage = HvInjectStageDependencyAllocateContext;
        }
        InjectionDiagnosticRecord(
            DiagnosticResult,
            HvInjectStageDependencyAllocateContext,
            HvInjectDiagnosticPhaseOperation,
            status,
            detail);
        goto Exit;
    }

    localContext->DllName.Buffer = (PWSTR)(
        (PUCHAR)remoteContext +
        FIELD_OFFSET(HV_INJECTION_LDR_LOAD_CONTEXT, DllPath));
    localContext->DllName.Length =
        (USHORT)(dllPathLength * sizeof(WCHAR));
    localContext->DllName.MaximumLength =
        (USHORT)((dllPathLength + 1) * sizeof(WCHAR));

    status = HvMemoryWrite(
        ProcessId,
        remoteContext,
        localContext,
        contextSize,
        &bytesTransferred);
    if (!NT_SUCCESS(status) || bytesTransferred != contextSize) {
        status = NT_SUCCESS(status) ? STATUS_PARTIAL_COPY : status;
        if (FailureStage) {
            *FailureStage = HvInjectStageDependencyWriteContext;
        }
        InjectionDiagnosticRecord(
            DiagnosticResult,
            HvInjectStageDependencyWriteContext,
            HvInjectDiagnosticPhaseOperation,
            status,
            detail);
        goto Exit;
    }

    status = InjectionCallUserRoutine(
        ProcessId,
        ProcessCreateTime,
        LoadRoutine,
        NULL,
        NULL,
        (PUCHAR)remoteContext +
            FIELD_OFFSET(HV_INJECTION_LDR_LOAD_CONTEXT, DllName),
        (PUCHAR)remoteContext +
            FIELD_OFFSET(HV_INJECTION_LDR_LOAD_CONTEXT, ModuleHandle),
        &routineResult,
        RollbackSafe);
    if (!NT_SUCCESS(status)) {
        if (FailureStage) {
            *FailureStage = HvInjectStageDependencyCallLoader;
        }
        InjectionDiagnosticRecord(
            DiagnosticResult,
            HvInjectStageDependencyCallLoader,
            HvInjectDiagnosticPhaseOperation,
            status,
            detail);
        goto Exit;
    }

    loaderStatus = (NTSTATUS)(ULONG)routineResult;
    if (!NT_SUCCESS(loaderStatus)) {
        status = loaderStatus;
        if (FailureStage) {
            *FailureStage = HvInjectStageDependencyCallLoader;
        }
        InjectionDiagnosticRecord(
            DiagnosticResult,
            HvInjectStageDependencyCallLoader,
            HvInjectDiagnosticPhaseOperation,
            status,
            detail);
        goto Exit;
    }

    bytesTransferred = 0;
    status = HvMemoryRead(
        ProcessId,
        (PUCHAR)remoteContext +
            FIELD_OFFSET(HV_INJECTION_LDR_LOAD_CONTEXT, ModuleHandle),
        ModuleBase,
        sizeof(*ModuleBase),
        &bytesTransferred);
    if (!NT_SUCCESS(status) || bytesTransferred != sizeof(*ModuleBase)) {
        status = NT_SUCCESS(status) ? STATUS_PARTIAL_COPY : status;
        *RollbackSafe = FALSE;
        if (FailureStage) {
            *FailureStage = HvInjectStageDependencyReadModuleHandle;
        }
        InjectionDiagnosticRecord(
            DiagnosticResult,
            HvInjectStageDependencyReadModuleHandle,
            HvInjectDiagnosticPhaseOperation,
            status,
            detail);
        goto Exit;
    }
    if (!*ModuleBase) {
        status = STATUS_DLL_INIT_FAILED;
        *RollbackSafe = FALSE;
        if (FailureStage) {
            *FailureStage = HvInjectStageDependencyReadModuleHandle;
        }
        InjectionDiagnosticRecord(
            DiagnosticResult,
            HvInjectStageDependencyReadModuleHandle,
            HvInjectDiagnosticPhaseOperation,
            status,
            detail);
        goto Exit;
    }
    status = STATUS_SUCCESS;

Exit:
    if (remoteContext && *RollbackSafe) {
        cleanupStatus = InjectionMemoryFreeCore(ProcessId, remoteContext);
        if (!NT_SUCCESS(status)) {
            InjectionDiagnosticCleanup(
                DiagnosticResult,
                HvInjectStageDependencyFreeContext,
                cleanupStatus,
                detail);
        } else {
            InjectionDiagnosticRecord(
                DiagnosticResult,
                HvInjectStageDependencyFreeContext,
                HvInjectDiagnosticPhaseWarning,
                cleanupStatus,
                detail);
        }
        if (!NT_SUCCESS(cleanupStatus)) {
            if (DiagnosticResult) {
                DiagnosticResult->Diagnostics.Flags |=
                    HV_INJECTION_DIAG_FLAG_LOADER_CONTEXT_RETAINED |
                    HV_INJECTION_DIAG_FLAG_CLEANUP_FAILED;
                if (DiagnosticResult->Diagnostics.CleanupStage ==
                    HvInjectStageNone) {
                    DiagnosticResult->Diagnostics.CleanupStage =
                        HvInjectStageDependencyFreeContext;
                    DiagnosticResult->Diagnostics.CleanupStatus =
                        cleanupStatus;
                }
            }
            InjectionDiagnosticSubject(
                DiagnosticResult, DllName, TRUE);
            DbgPrint("[Injection] Loader dependency context cleanup failed: 0x%X\n",
                cleanupStatus);
        }
    } else if (remoteContext) {
        cleanupStatus = STATUS_CANNOT_DELETE;
        InjectionDiagnosticCleanup(
            DiagnosticResult,
            HvInjectStageDependencyFreeContext,
            cleanupStatus,
            detail);
        if (DiagnosticResult) {
            DiagnosticResult->Diagnostics.Flags |=
                HV_INJECTION_DIAG_FLAG_LOADER_CONTEXT_RETAINED;
        }
        InjectionDiagnosticSubject(DiagnosticResult, DllName, TRUE);
        DbgPrint("[Injection] Loader dependency call is uncertain; context retained\n");
    }
    if (localContext) {
        ExFreePoolWithTag(localContext, HV_INJECTION_TAG);
    }
    return status;
}

static NTSTATUS
InjectionAcquireDependencyReferences(
    _In_ ULONG ProcessId,
    _In_ UINT64 ProcessCreateTime,
    _In_ PVOID LoadRoutine,
    _In_ PVOID UnloadRoutine,
    _In_ PHV_INJECTION_DEPENDENCY_PLAN Plan,
    _Inout_ PINJECTED_MODULE_ENTRY ModuleEntry,
    _Inout_ PBOOLEAN RollbackSafe,
    _Inout_opt_ PHV_INJECTION_RESULT DiagnosticResult
)
{
    NTSTATUS status;
    NTSTATUS releaseStatus;
    ULONG dependencyIndex;
    PVOID moduleBase;
    USHORT failureStage;
    BOOLEAN defaultSearchTried;

    if (ProcessId == 0 || ProcessCreateTime == 0 || !Plan ||
        !ModuleEntry || !RollbackSafe || !*RollbackSafe ||
        Plan->Count > MAX_INJECTION_DEPENDENCIES ||
        ModuleEntry->DependencyCount != 0) {
        return STATUS_INVALID_PARAMETER;
    }
    if (Plan->Count == 0) {
        return STATUS_SUCCESS;
    }
    if (!LoadRoutine || !UnloadRoutine) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    if (DiagnosticResult) {
        DiagnosticResult->Diagnostics.DependencyCount = Plan->Count;
    }

    ModuleEntry->DependencyUnloadRoutine = UnloadRoutine;
    for (dependencyIndex = 0;
         dependencyIndex < Plan->Count;
         dependencyIndex++) {
        moduleBase = NULL;
        failureStage = HvInjectStageManualLoadDependencies;
        defaultSearchTried = FALSE;
        status = InjectionLoadModuleReference(
            ProcessId,
            ProcessCreateTime,
            LoadRoutine,
            Plan->SearchPath[0] != L'\0' ? Plan->SearchPath : NULL,
            Plan->ModuleNames[dependencyIndex],
            &moduleBase,
            RollbackSafe,
            dependencyIndex,
            DiagnosticResult,
            &failureStage);
        if (!NT_SUCCESS(status) && *RollbackSafe &&
            Plan->SearchPath[0] != L'\0' &&
            (status == STATUS_DLL_NOT_FOUND ||
             status == STATUS_OBJECT_NAME_NOT_FOUND ||
             status == STATUS_OBJECT_PATH_NOT_FOUND)) {
            defaultSearchTried = TRUE;
            status = InjectionLoadModuleReference(
                ProcessId,
                ProcessCreateTime,
                LoadRoutine,
                NULL,
                Plan->ModuleNames[dependencyIndex],
                &moduleBase,
                RollbackSafe,
                dependencyIndex,
                DiagnosticResult,
                &failureStage);
        }
        if (!NT_SUCCESS(status)) {
            if (DiagnosticResult) {
                DiagnosticResult->Diagnostics.DependencyIndex =
                    dependencyIndex;
            }
            InjectionDiagnosticSubject(
                DiagnosticResult,
                Plan->ModuleNames[dependencyIndex],
                FALSE);
            InjectionDiagnosticFailure(
                DiagnosticResult,
                failureStage,
                status,
                dependencyIndex |
                    (defaultSearchTried
                        ? HV_INJECTION_DIAG_DETAIL_DEFAULT_SEARCH
                        : 0));
            DbgPrint("[Injection] Dependency load failed for %ws: 0x%X\n",
                Plan->ModuleNames[dependencyIndex], status);
            if (ModuleEntry->DependencyCount != 0 && *RollbackSafe) {
                releaseStatus = InjectionReleaseDependencyReferences(
                    ProcessId,
                    ModuleEntry,
                    RollbackSafe,
                    Plan,
                    DiagnosticResult);
                if (!NT_SUCCESS(releaseStatus)) {
                    DbgPrint("[Injection] Dependency rollback failed: 0x%X\n",
                        releaseStatus);
                }
            }
            return status;
        }

        ModuleEntry->DependencyModules[ModuleEntry->DependencyCount] =
            moduleBase;
        ModuleEntry->DependencyCount++;
    }
    return STATUS_SUCCESS;
}

static NTSTATUS
InjectionReleaseDependencyReferences(
    _In_ ULONG ProcessId,
    _Inout_ PINJECTED_MODULE_ENTRY ModuleEntry,
    _Inout_ PBOOLEAN RollbackSafe,
    _In_opt_ PHV_INJECTION_DEPENDENCY_PLAN Plan,
    _Inout_opt_ PHV_INJECTION_RESULT DiagnosticResult
)
{
    NTSTATUS status;
    ULONGLONG routineResult;
    ULONG dependencyIndex;
    PVOID moduleBase;

    if (ProcessId == 0 || !ModuleEntry || !RollbackSafe ||
        !*RollbackSafe ||
        ModuleEntry->DependencyCount > MAX_INJECTION_DEPENDENCIES) {
        InjectionDiagnosticCleanup(
            DiagnosticResult,
            HvInjectStageCleanupDependencies,
            STATUS_INVALID_PARAMETER,
            ModuleEntry ? ModuleEntry->DependencyCount : 0);
        return STATUS_INVALID_PARAMETER;
    }
    if (ModuleEntry->DependencyCount == 0) {
        ModuleEntry->DependencyUnloadRoutine = NULL;
        return STATUS_SUCCESS;
    }
    if (!ModuleEntry->DependencyUnloadRoutine ||
        ModuleEntry->ProcessCreateTime == 0) {
        InjectionDiagnosticCleanup(
            DiagnosticResult,
            HvInjectStageCleanupDependencies,
            STATUS_INVALID_DEVICE_STATE,
            ModuleEntry->DependencyCount);
        return STATUS_INVALID_DEVICE_STATE;
    }

    while (ModuleEntry->DependencyCount != 0) {
        dependencyIndex = ModuleEntry->DependencyCount - 1;
        moduleBase = ModuleEntry->DependencyModules[dependencyIndex];
        if (!moduleBase) {
            if (Plan && dependencyIndex < Plan->Count) {
                InjectionDiagnosticSubject(
                    DiagnosticResult,
                    Plan->ModuleNames[dependencyIndex],
                    TRUE);
            }
            InjectionDiagnosticCleanup(
                DiagnosticResult,
                HvInjectStageCleanupDependencies,
                STATUS_INVALID_DEVICE_STATE,
                dependencyIndex);
            return STATUS_INVALID_DEVICE_STATE;
        }

        routineResult = 0;
        status = InjectionCallUserRoutine(
            ProcessId,
            ModuleEntry->ProcessCreateTime,
            ModuleEntry->DependencyUnloadRoutine,
            moduleBase,
            NULL,
            NULL,
            NULL,
            &routineResult,
            RollbackSafe);
        if (!NT_SUCCESS(status)) {
            if (Plan && dependencyIndex < Plan->Count) {
                InjectionDiagnosticSubject(
                    DiagnosticResult,
                    Plan->ModuleNames[dependencyIndex],
                    TRUE);
            }
            InjectionDiagnosticCleanup(
                DiagnosticResult,
                HvInjectStageCleanupDependencies,
                status,
                dependencyIndex);
            return status;
        }
        status = (NTSTATUS)(ULONG)routineResult;
        if (!NT_SUCCESS(status)) {
            if (Plan && dependencyIndex < Plan->Count) {
                InjectionDiagnosticSubject(
                    DiagnosticResult,
                    Plan->ModuleNames[dependencyIndex],
                    TRUE);
            }
            InjectionDiagnosticCleanup(
                DiagnosticResult,
                HvInjectStageCleanupDependencies,
                status,
                dependencyIndex);
            return status;
        }

        InjectionDiagnosticCleanup(
            DiagnosticResult,
            HvInjectStageCleanupDependencies,
            STATUS_SUCCESS,
            dependencyIndex);

        ModuleEntry->DependencyModules[dependencyIndex] = NULL;
        ModuleEntry->DependencyCount = dependencyIndex;
    }

    ModuleEntry->DependencyUnloadRoutine = NULL;
    return STATUS_SUCCESS;
}

static VOID
InjectionOperationRelease(VOID)
{
    ExReleaseRundownProtection(&g_InjectionOperationRundown);
}

static PVOID
InjectionResolveSystemRoutine(
    _In_ PCWSTR RoutineName
)
{
    UNICODE_STRING name;

    RtlInitUnicodeString(&name, RoutineName);
    return MmGetSystemRoutineAddress(&name);
}

static VOID
InjectionResolveOptionalApcRoutines(VOID)
{
    g_KeRemoveQueueApc = (PFN_KE_REMOVE_QUEUE_APC)
        InjectionResolveSystemRoutine(L"KeRemoveQueueApc");
    g_KeTestAlertThread = (PFN_KE_TEST_ALERT_THREAD)
        InjectionResolveSystemRoutine(L"KeTestAlertThread");
    g_PsWrapApcWow64Thread = (PFN_PS_WRAP_APC_WOW64_THREAD)
        InjectionResolveSystemRoutine(L"PsWrapApcWow64Thread");
    g_PsGetThreadProcess = (PFN_PS_GET_THREAD_PROCESS)
        InjectionResolveSystemRoutine(L"PsGetThreadProcess");

    if (!g_KeRemoveQueueApc) {
        DbgPrint("[Injection] KeRemoveQueueApc is unavailable; APC execution is disabled on this kernel\n");
    }
}

NTSTATUS
HvInjectionInitialize(VOID)
{
    NTSTATUS status = STATUS_SUCCESS;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_InjectionLifecycleLock);

    if (InterlockedCompareExchange(&g_InjectionClosing, 0, 0) != 0) {
        status = STATUS_DELETE_PENDING;
        goto Exit;
    }
    if (g_InjectionManager.Initialized) {
        DbgPrint("[Injection] Already initialized\n");
        goto Exit;
    }

    DbgPrint("[Injection] Initializing Injection Manager...\n");

    InjectionResolveOptionalApcRoutines();

    // 初始化链表
    if (InterlockedCompareExchange(
            &g_InjectionListsInitialized, 0, 0) == 0) {
        InitializeListHead(&g_InjectionManager.InjectedModuleList);
        g_InjectionManager.InjectedModuleCount = 0;
        InitializeListHead(&g_InjectionManager.AllocationList);
        g_InjectionManager.AllocationCount = 0;

    // 初始化同步原语
        KeInitializeSpinLock(&g_InjectionManager.Lock);
        ExInitializeFastMutex(&g_InjectionManager.FastMutex);
        InitHiddenMemoryList();
        ExInitializeRundownProtection(&g_InjectionOperationRundown);
        InterlockedExchange(
            &g_InjectionOperationRundownInitialized, 1);
        InterlockedExchange(&g_InjectionOperationRundownDrained, 0);
        InitializeListHead(&g_InjectionPendingApcList);
        KeInitializeSpinLock(&g_InjectionPendingApcLock);
        InterlockedExchange(&g_InjectionPendingApcCount, 0);
        InterlockedExchange(&g_InjectionPendingApcInitialized, 1);
        InterlockedExchange(&g_InjectionListsInitialized, 1);
    }

    status = PsSetCreateProcessNotifyRoutineEx(
        InjectionProcessNotifyCallback, FALSE);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[Injection] Process notify registration failed: 0x%X\n", status);
        goto Exit;
    }

    InterlockedExchange(
        &g_InjectionProcessNotifyState,
        HV_INJECTION_NOTIFY_REGISTERED);
    InterlockedExchange(&g_InjectionLastNotifyStatus, STATUS_SUCCESS);
    g_InjectionManager.Initialized = TRUE;

    DbgPrint("[Injection] Injection Manager initialized successfully\n");

Exit:
    ExReleasePushLockExclusive(&g_InjectionLifecycleLock);
    KeLeaveCriticalRegion();
    return status;
}

NTSTATUS
HvInjectDllFromFile(
    _In_ ULONG ProcessId,
    _In_ PCWSTR DllPath,
    _Out_opt_ PHV_INJECTION_RESULT OutResult
)
{
    NTSTATUS status;

    InjectionDiagnosticInitialize(
        OutResult, HV_INJECTION_DIAG_FLAG_MANUAL_MAP);

    if (!InjectionIsOpen()) {
        status = HvInjectionInitialize();
        if (!NT_SUCCESS(status)) {
            InjectionDiagnosticFailure(
                OutResult,
                HvInjectStageManagerInitialize,
                status,
                0);
            InjectionDiagnosticFinalize(
                OutResult, status, HvInjectStageManagerInitialize);
            return status;
        }
    }
    InjectionDiagnosticRecord(
        OutResult,
        HvInjectStageManagerInitialize,
        HvInjectDiagnosticPhaseOperation,
        STATUS_SUCCESS,
        0);
    status = InjectionOperationAcquire();
    if (!NT_SUCCESS(status)) {
        InjectionDiagnosticFailure(
            OutResult,
            HvInjectStageOperationAcquire,
            status,
            0);
        InjectionDiagnosticFinalize(
            OutResult, status, HvInjectStageOperationAcquire);
        return status;
    }
    InjectionDiagnosticRecord(
        OutResult,
        HvInjectStageOperationAcquire,
        HvInjectDiagnosticPhaseOperation,
        STATUS_SUCCESS,
        0);
    status = InjectionInjectDllFromFileCore(
        ProcessId, DllPath, OutResult);
    InjectionOperationRelease();
    InjectionDiagnosticFinalize(
        OutResult, status, HvInjectStageFileNormalizePath);
    return status;
}

NTSTATUS
HvInjectDllViaLoader(
    _In_ ULONG ProcessId,
    _In_ PCWSTR DllPath,
    _Out_opt_ PHV_INJECTION_RESULT OutResult
)
{
    NTSTATUS status;

    InjectionDiagnosticInitialize(
        OutResult, HV_INJECTION_DIAG_FLAG_WINDOWS_LOADER);

    if (!InjectionIsOpen()) {
        status = HvInjectionInitialize();
        if (!NT_SUCCESS(status)) {
            InjectionDiagnosticFailure(
                OutResult,
                HvInjectStageManagerInitialize,
                status,
                0);
            InjectionDiagnosticFinalize(
                OutResult, status, HvInjectStageManagerInitialize);
            return status;
        }
    }
    InjectionDiagnosticRecord(
        OutResult,
        HvInjectStageManagerInitialize,
        HvInjectDiagnosticPhaseOperation,
        STATUS_SUCCESS,
        0);
    status = InjectionOperationAcquire();
    if (!NT_SUCCESS(status)) {
        InjectionDiagnosticFailure(
            OutResult,
            HvInjectStageOperationAcquire,
            status,
            0);
        InjectionDiagnosticFinalize(
            OutResult, status, HvInjectStageOperationAcquire);
        return status;
    }
    InjectionDiagnosticRecord(
        OutResult,
        HvInjectStageOperationAcquire,
        HvInjectDiagnosticPhaseOperation,
        STATUS_SUCCESS,
        0);
    status = InjectionInjectDllViaLoaderCore(
        ProcessId, DllPath, OutResult);
    InjectionOperationRelease();
    InjectionDiagnosticFinalize(
        OutResult, status, HvInjectStageLoaderValidateInput);
    return status;
}

NTSTATUS
HvInjectionBeginShutdown(VOID)
{
    NTSTATUS status = STATUS_SUCCESS;
    
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_InjectionLifecycleLock);

    /* Close admission before waiting for an already-entered callback. */
    InterlockedExchange(&g_InjectionClosing, 1);
    g_InjectionManager.Initialized = FALSE;

    if (InterlockedCompareExchange(
            &g_InjectionProcessNotifyState, 0, 0) ==
        HV_INJECTION_NOTIFY_REGISTERED) {
        DbgPrint("[Injection] Detaching process notify callback...\n");
        status = PsSetCreateProcessNotifyRoutineEx(
            InjectionProcessNotifyCallback, TRUE);
        if (status == STATUS_INVALID_PARAMETER) {
            /* The kernel reports that this exact callback is no longer in
             * its notify table.  Normalize that idempotent remove result:
             * there is no callback ownership left to retain. */
            DbgPrint("[Injection] Process notify callback was already absent\n");
            status = STATUS_SUCCESS;
        }
        InterlockedExchange(&g_InjectionLastNotifyStatus, status);
        if (!NT_SUCCESS(status)) {
            DbgPrint("[Injection] Process notify detach failed: 0x%X; ownership retained and unload must fail-stop\n",
                     status);
            goto BeginExit;
        }
        InterlockedExchange(
            &g_InjectionProcessNotifyState,
            HV_INJECTION_NOTIFY_UNREGISTERED);
        DbgPrint("[Injection] Process notify callback detached\n");
    }

    if (InterlockedCompareExchange(
            &g_InjectionOperationRundownInitialized, 0, 0) != 0 &&
        InterlockedCompareExchange(
            &g_InjectionOperationRundownDrained, 0, 0) == 0) {
        DbgPrint("[Injection] Cancelling pending APC callbacks...\n");
        InjectionCancelPendingApcs();
        DbgPrint("[Injection] Waiting for admitted operations/APCs...\n");
        ExWaitForRundownProtectionRelease(
            &g_InjectionOperationRundown);
        InterlockedExchange(&g_InjectionOperationRundownDrained, 1);
        DbgPrint("[Injection] Operation/APC rundown drained\n");
    }

BeginExit:
    ExReleasePushLockExclusive(&g_InjectionLifecycleLock);
    KeLeaveCriticalRegion();
    return status;
}

NTSTATUS
HvInjectionFinalizeCleanup(VOID)
{
    NTSTATUS status = STATUS_SUCCESS;
    PLIST_ENTRY entry;
    LIST_ENTRY retiredAllocations;
    LIST_ENTRY retiredModules;
    LIST_ENTRY retiredHidden;
    KIRQL oldIrql;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    InitializeListHead(&retiredAllocations);
    InitializeListHead(&retiredModules);
    InitializeListHead(&retiredHidden);
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_InjectionLifecycleLock);

    if (InterlockedCompareExchange(&g_InjectionClosing, 0, 0) == 0) {
        status = STATUS_INVALID_DEVICE_STATE;
        goto Exit;
    }
    if (InterlockedCompareExchange(
            &g_InjectionProcessNotifyState, 0, 0) !=
        HV_INJECTION_NOTIFY_UNREGISTERED) {
        status = (NTSTATUS)InterlockedCompareExchange(
            &g_InjectionLastNotifyStatus, 0, 0);
        if (NT_SUCCESS(status)) {
            status = STATUS_DEVICE_BUSY;
        }
        goto Exit;
    }
    if (InterlockedCompareExchange(
            &g_InjectionOperationRundownInitialized, 0, 0) != 0 &&
        InterlockedCompareExchange(
            &g_InjectionOperationRundownDrained, 0, 0) == 0) {
        status = STATUS_DEVICE_BUSY;
        goto Exit;
    }
    if (InterlockedCompareExchange(
            &g_InjectionPendingApcCount, 0, 0) != 0) {
        status = STATUS_DEVICE_BUSY;
        goto Exit;
    }
    if (InterlockedCompareExchange(&g_InjectionFinalized, 0, 0) != 0 ||
        InterlockedCompareExchange(
            &g_InjectionListsInitialized, 0, 0) == 0) {
        InterlockedExchange(&g_InjectionFinalized, 1);
        goto Exit;
    }

    DbgPrint("[Injection] Finalizing tracking lists after hook rundown...\n");

    ExAcquireFastMutex(&g_InjectionManager.FastMutex);
    while (!IsListEmpty(&g_InjectionManager.AllocationList)) {
        entry = RemoveHeadList(&g_InjectionManager.AllocationList);
        InsertTailList(&retiredAllocations, entry);
    }
    g_InjectionManager.AllocationCount = 0;
    ExReleaseFastMutex(&g_InjectionManager.FastMutex);

    // 清理已注入模块列表
    KeAcquireSpinLock(&g_InjectionManager.Lock, &oldIrql);
    
    while (!IsListEmpty(&g_InjectionManager.InjectedModuleList)) {
        entry = RemoveHeadList(&g_InjectionManager.InjectedModuleList);
        InsertTailList(&retiredModules, entry);

        // 注意：不卸载模块，仅清理记录
    }
    
    g_InjectionManager.InjectedModuleCount = 0;

    KeReleaseSpinLock(&g_InjectionManager.Lock, oldIrql);

    // 清理隐藏内存区域列表
    if (g_HiddenMemoryInitialized) {
        KeAcquireSpinLock(&g_HiddenMemoryLock, &oldIrql);
        while (!IsListEmpty(&g_HiddenMemoryList)) {
            entry = RemoveHeadList(&g_HiddenMemoryList);
            InsertTailList(&retiredHidden, entry);
        }
        g_HiddenMemoryCount = 0;
        g_HiddenMemoryInitialized = FALSE;
        KeReleaseSpinLock(&g_HiddenMemoryLock, oldIrql);
    }

    InterlockedExchange(&g_InjectionListsInitialized, 0);
    InterlockedExchange(&g_InjectionFinalized, 1);
Exit:
    ExReleasePushLockExclusive(&g_InjectionLifecycleLock);
    KeLeaveCriticalRegion();

    while (!IsListEmpty(&retiredAllocations)) {
        entry = RemoveHeadList(&retiredAllocations);
        ExFreePoolWithTag(
            CONTAINING_RECORD(
                entry, HV_MEMORY_ALLOCATION_ENTRY, ListEntry),
            HV_INJECTION_TAG);
    }
    while (!IsListEmpty(&retiredModules)) {
        entry = RemoveHeadList(&retiredModules);
        ExFreePoolWithTag(
            CONTAINING_RECORD(entry, INJECTED_MODULE_ENTRY, ListEntry),
            HV_INJECTION_TAG);
    }
    while (!IsListEmpty(&retiredHidden)) {
        entry = RemoveHeadList(&retiredHidden);
        ExFreePoolWithTag(
            CONTAINING_RECORD(entry, HIDDEN_MEMORY_ENTRY, ListEntry),
            HV_INJECTION_TAG);
    }

    if (NT_SUCCESS(status) &&
        InterlockedCompareExchange(&g_InjectionFinalized, 0, 0) != 0) {
        DbgPrint("[Injection] Injection Manager finalized\n");
    }
    return status;
}

NTSTATUS
HvInjectionCleanup(VOID)
{
    /* A one-shot compatibility cleanup cannot prove that
     * HookedNtQueryVirtualMemory has completed global hook rundown.  Callers
     * must use BeginShutdown before hook removal and FinalizeCleanup after
     * HvHookShutdownAndDrain. */
    return STATUS_INVALID_DEVICE_STATE;
}

BOOLEAN
HvInjectionIsInitialized(VOID)
{
    return InjectionIsOpen();
}

static VOID
InjectionProcessNotifyCallback(
    _In_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _In_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
)
{
    PLIST_ENTRY entry;
    PLIST_ENTRY next;
    LIST_ENTRY retiredEntries;
    LIST_ENTRY retiredHiddenEntries;
    LIST_ENTRY retiredModuleEntries;
    UINT64 createTime;
    ULONG processId;
    KIRQL oldIrql;

    if (CreateInfo != NULL || !Process || !InjectionIsOpen()) {
        return;
    }

    createTime = (UINT64)PsGetProcessCreateTimeQuadPart(Process);
    processId = (ULONG)(ULONG_PTR)ProcessId;
    if (createTime == 0 || processId == 0) {
        return;
    }

    InitializeListHead(&retiredEntries);
    InitializeListHead(&retiredHiddenEntries);
    InitializeListHead(&retiredModuleEntries);
    ExAcquireFastMutex(&g_InjectionManager.FastMutex);
    for (entry = g_InjectionManager.AllocationList.Flink;
         entry != &g_InjectionManager.AllocationList;
         entry = next) {
        PHV_MEMORY_ALLOCATION_ENTRY allocationEntry;

        next = entry->Flink;
        allocationEntry = CONTAINING_RECORD(
            entry, HV_MEMORY_ALLOCATION_ENTRY, ListEntry);
        if (allocationEntry->ProcessId == processId &&
            allocationEntry->ProcessCreateTime == createTime) {
            RemoveEntryList(entry);
            InsertTailList(&retiredEntries, entry);
            if (g_InjectionManager.AllocationCount != 0) {
                g_InjectionManager.AllocationCount--;
            }
        }
    }
    ExReleaseFastMutex(&g_InjectionManager.FastMutex);

    while (!IsListEmpty(&retiredEntries)) {
        entry = RemoveHeadList(&retiredEntries);
        ExFreePoolWithTag(
            CONTAINING_RECORD(entry, HV_MEMORY_ALLOCATION_ENTRY, ListEntry),
            HV_INJECTION_TAG);
    }

    /* Module records are process-identity scoped just like allocation and
     * hidden-memory records.  Removing them on exit prevents PID reuse from
     * exposing or mutating a stale module entry. */
    KeAcquireSpinLock(&g_InjectionManager.Lock, &oldIrql);
    for (entry = g_InjectionManager.InjectedModuleList.Flink;
         entry != &g_InjectionManager.InjectedModuleList;
         entry = next) {
        PINJECTED_MODULE_ENTRY moduleEntry;

        next = entry->Flink;
        moduleEntry = CONTAINING_RECORD(
            entry, INJECTED_MODULE_ENTRY, ListEntry);
        if (moduleEntry->ProcessId == processId &&
            moduleEntry->ProcessCreateTime == createTime &&
            InterlockedCompareExchange(&moduleEntry->Removing, 0, 0) == 0) {
            RemoveEntryList(entry);
            InsertTailList(&retiredModuleEntries, entry);
            if (g_InjectionManager.InjectedModuleCount != 0) {
                g_InjectionManager.InjectedModuleCount--;
            }
        }
    }
    KeReleaseSpinLock(&g_InjectionManager.Lock, oldIrql);

    while (!IsListEmpty(&retiredModuleEntries)) {
        entry = RemoveHeadList(&retiredModuleEntries);
        ExFreePoolWithTag(
            CONTAINING_RECORD(entry, INJECTED_MODULE_ENTRY, ListEntry),
            HV_INJECTION_TAG);
    }

    if (g_HiddenMemoryInitialized) {
        KeAcquireSpinLock(&g_HiddenMemoryLock, &oldIrql);
        for (entry = g_HiddenMemoryList.Flink;
             entry != &g_HiddenMemoryList;
             entry = next) {
            PHIDDEN_MEMORY_ENTRY hiddenEntry;

            next = entry->Flink;
            hiddenEntry = CONTAINING_RECORD(
                entry, HIDDEN_MEMORY_ENTRY, ListEntry);
            if (hiddenEntry->ProcessId == processId &&
                hiddenEntry->ProcessCreateTime == createTime) {
                RemoveEntryList(entry);
                InsertTailList(&retiredHiddenEntries, entry);
                if (g_HiddenMemoryCount != 0) {
                    g_HiddenMemoryCount--;
                }
            }
        }
        KeReleaseSpinLock(&g_HiddenMemoryLock, oldIrql);
    }
    while (!IsListEmpty(&retiredHiddenEntries)) {
        entry = RemoveHeadList(&retiredHiddenEntries);
        ExFreePoolWithTag(
            CONTAINING_RECORD(entry, HIDDEN_MEMORY_ENTRY, ListEntry),
            HV_INJECTION_TAG);
    }
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
    // Current data plane: HvPhysAccess -> VtRoot. CR3 ownership, page-table
    // walk and final physical copy stay in VMX-root/SVM-host; there is no
    // MmMapIoSpace/attach-process fallback for this request path.
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
HvMemoryWriteCow(
    _In_ ULONG ProcessId,
    _In_ PVOID Address,
    _In_reads_bytes_(Size) PVOID Buffer,
    _In_ SIZE_T Size,
    _Out_opt_ PSIZE_T BytesWritten
)
{
    PEPROCESS targetProcess = NULL;
    SIZE_T transferred = 0;

    if (ProcessId == 0 || !Address || !Buffer || Size == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    if (KeGetCurrentIrql() > APC_LEVEL) {
        return STATUS_INVALID_LEVEL;
    }

    PFN_MM_COPY_VIRTUAL_MEMORY copyRoutine = g_MmCopyVirtualMemory;
    if (!copyRoutine) {
        UNICODE_STRING routineName;
        RtlInitUnicodeString(&routineName, L"MmCopyVirtualMemory");
        copyRoutine = (PFN_MM_COPY_VIRTUAL_MEMORY)
            MmGetSystemRoutineAddress(&routineName);
        if (!copyRoutine) {
            return STATUS_PROCEDURE_NOT_FOUND;
        }
        InterlockedCompareExchangePointer(
            (PVOID volatile*)&g_MmCopyVirtualMemory,
            (PVOID)copyRoutine,
            NULL);
        copyRoutine = g_MmCopyVirtualMemory;
    }

    NTSTATUS status = PsLookupProcessByProcessId(
        (HANDLE)(ULONG_PTR)ProcessId, &targetProcess);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = copyRoutine(
        PsGetCurrentProcess(), Buffer,
        targetProcess, Address,
        Size, KernelMode, &transferred);
    ObDereferenceObject(targetProcess);

    if (BytesWritten) {
        *BytesWritten = transferred;
    }
    return status;
}

static NTSTATUS
InjectionMemoryAllocateCore(
    _In_ ULONG ProcessId,
    _In_ SIZE_T Size,
    _In_ ULONG Protection,
    _Out_ PVOID* OutAddress
)
{
    NTSTATUS status = STATUS_SUCCESS;
    PHV_MEMORY_ALLOCATION_ENTRY allocationEntry;
    PEPROCESS process = NULL;
    KAPC_STATE_INJ apcState;
    PVOID baseAddress = NULL;
    SIZE_T regionSize = Size;
    UINT64 createTime = 0;

    if (ProcessId == 0 || !OutAddress || Size == 0 || Size > MAXULONG ||
        !InjectionIsValidProtection(Protection)) {
        return STATUS_INVALID_PARAMETER;
    }
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_LEVEL;
    }

    *OutAddress = NULL;
    allocationEntry = (PHV_MEMORY_ALLOCATION_ENTRY)HvAllocateNonPagedZeroed(
        sizeof(HV_MEMORY_ALLOCATION_ENTRY), HV_INJECTION_TAG);
    if (!allocationEntry) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    ExAcquireFastMutex(&g_InjectionManager.FastMutex);
    __try {
        if (g_InjectionManager.AllocationCount >=
            MAX_TRACKED_ALLOCATIONS) {
            status = STATUS_INSUFFICIENT_RESOURCES;
        } else {
            status = HvAttachProcess(ProcessId, &process, &apcState);
            if (NT_SUCCESS(status)) {
                createTime = (UINT64)PsGetProcessCreateTimeQuadPart(process);
                if (createTime == 0) {
                    status = STATUS_INVALID_CID;
                    HvDetachProcess(process, &apcState);
                } else {
                    __try {
                        status = ZwAllocateVirtualMemory(
                            ZwCurrentProcess(),
                            &baseAddress,
                            0,
                            &regionSize,
                            MEM_RESERVE | MEM_COMMIT,
                            Protection);
                    } __finally {
                        HvDetachProcess(process, &apcState);
                    }
                }
            }

            if (NT_SUCCESS(status)) {
                allocationEntry->ProcessId = ProcessId;
                allocationEntry->ProcessCreateTime = createTime;
                allocationEntry->BaseAddress = baseAddress;
                allocationEntry->RegionSize = regionSize;
                allocationEntry->Protection = Protection;
                InsertTailList(
                    &g_InjectionManager.AllocationList,
                    &allocationEntry->ListEntry);
                g_InjectionManager.AllocationCount++;
                *OutAddress = baseAddress;
            }
        }
    } __finally {
        ExReleaseFastMutex(&g_InjectionManager.FastMutex);
    }

    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(allocationEntry, HV_INJECTION_TAG);
    }
    return status;
}

NTSTATUS
HvMemoryAllocate(
    _In_ ULONG ProcessId,
    _In_ SIZE_T Size,
    _In_ ULONG Protection,
    _Out_ PVOID* OutAddress
)
{
    NTSTATUS status = InjectionOperationAcquire();
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = InjectionMemoryAllocateCore(
        ProcessId, Size, Protection, OutAddress);
    InjectionOperationRelease();
    return status;
}

static NTSTATUS
InjectionMemoryFreeCore(
    _In_ ULONG ProcessId,
    _In_ PVOID Address
)
{
    NTSTATUS status = STATUS_NOT_FOUND;
    PLIST_ENTRY entry;
    PHV_MEMORY_ALLOCATION_ENTRY allocationEntry = NULL;
    PHV_MEMORY_ALLOCATION_ENTRY releasedEntry = NULL;
    PEPROCESS process = NULL;
    KAPC_STATE_INJ apcState;
    PVOID baseAddress = Address;
    SIZE_T regionSize = 0;
    UINT64 createTime;

    if (ProcessId == 0 || !Address) {
        return STATUS_INVALID_PARAMETER;
    }
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_LEVEL;
    }
    ExAcquireFastMutex(&g_InjectionManager.FastMutex);
    __try {
        {
            for (entry = g_InjectionManager.AllocationList.Flink;
                 entry != &g_InjectionManager.AllocationList;
                 entry = entry->Flink) {
                PHV_MEMORY_ALLOCATION_ENTRY candidate;

                candidate = CONTAINING_RECORD(
                    entry, HV_MEMORY_ALLOCATION_ENTRY, ListEntry);
                if (candidate->ProcessId == ProcessId &&
                    candidate->BaseAddress == Address) {
                    allocationEntry = candidate;
                    break;
                }
            }

            if (allocationEntry) {
                status = HvAttachProcess(ProcessId, &process, &apcState);
                if (NT_SUCCESS(status)) {
                    createTime =
                        (UINT64)PsGetProcessCreateTimeQuadPart(process);
                    if (createTime != allocationEntry->ProcessCreateTime) {
                        status = STATUS_NOT_FOUND;
                        HvDetachProcess(process, &apcState);
                    } else {
                        __try {
                            status = ZwFreeVirtualMemory(
                                ZwCurrentProcess(),
                                &baseAddress,
                                &regionSize,
                                MEM_RELEASE);
                        } __finally {
                            HvDetachProcess(process, &apcState);
                        }

                        if (NT_SUCCESS(status)) {
                            RemoveEntryList(&allocationEntry->ListEntry);
                            if (g_InjectionManager.AllocationCount != 0) {
                                g_InjectionManager.AllocationCount--;
                            }
                            releasedEntry = allocationEntry;
                        }
                    }
                }
            }
        }
    } __finally {
        ExReleaseFastMutex(&g_InjectionManager.FastMutex);
    }

    if (releasedEntry) {
        ExFreePoolWithTag(releasedEntry, HV_INJECTION_TAG);
    }
    return status;
}

NTSTATUS
HvMemoryFree(
    _In_ ULONG ProcessId,
    _In_ PVOID Address
)
{
    NTSTATUS status = InjectionOperationAcquire();
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = InjectionMemoryFreeCore(ProcessId, Address);
    InjectionOperationRelease();
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
    PEPROCESS process = NULL;
    KAPC_STATE_INJ apcState;
    PVOID baseAddress = Address;
    SIZE_T regionSize = Size;
    ULONG oldProtect = 0;

    if (ProcessId == 0 || !Address || Size == 0 ||
        (ULONG_PTR)Address + Size < (ULONG_PTR)Address ||
        !InjectionIsValidProtection(NewProtection)) {
        return STATUS_INVALID_PARAMETER;
    }
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_LEVEL;
    }
    if (OldProtection) {
        *OldProtection = 0;
    }

    status = HvAttachProcess(ProcessId, &process, &apcState);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    __try {
        status = ZwProtectVirtualMemory(
            ZwCurrentProcess(),
            &baseAddress,
            &regionSize,
            NewProtection,
            &oldProtect);
    } __finally {
        HvDetachProcess(process, &apcState);
    }

    if (NT_SUCCESS(status) && OldProtection) {
        *OldProtection = oldProtect;
    }

    return status;
}

// ============================================================
// PE 验证和解析
// ============================================================

static BOOLEAN
InjectionRangeWithinSize(
    _In_ SIZE_T Offset,
    _In_ SIZE_T Length,
    _In_ SIZE_T TotalSize
)
{
    return Offset <= TotalSize && Length <= TotalSize - Offset;
}

static BOOLEAN
InjectionRvaRangeValid(
    _In_ PIMAGE_NT_HEADERS64_INJ NtHeaders,
    _In_ ULONG Rva,
    _In_ SIZE_T Length
)
{
    return NtHeaders &&
           InjectionRangeWithinSize(
               (SIZE_T)Rva,
               Length,
               (SIZE_T)NtHeaders->OptionalHeader.SizeOfImage);
}

static BOOLEAN
InjectionAnsiStringRvaValid(
    _In_ PVOID ImageBase,
    _In_ PIMAGE_NT_HEADERS64_INJ NtHeaders,
    _In_ ULONG Rva,
    _In_ SIZE_T MaximumLength
)
{
    SIZE_T available;
    SIZE_T index;
    PCSTR value;

    if (!ImageBase || !NtHeaders ||
        Rva >= NtHeaders->OptionalHeader.SizeOfImage) {
        return FALSE;
    }

    available = NtHeaders->OptionalHeader.SizeOfImage - (SIZE_T)Rva;
    if (available > MaximumLength) {
        available = MaximumLength;
    }
    value = (PCSTR)((PUCHAR)ImageBase + Rva);
    for (index = 0; index < available; index++) {
        if (value[index] == '\0') {
            return TRUE;
        }
    }
    return FALSE;
}

static NTSTATUS
InjectionValidatePe(
    _In_ PVOID ImageBase,
    _In_ SIZE_T ImageSize,
    _Out_ PIMAGE_NT_HEADERS64_INJ* OutNtHeaders
)
{
    PIMAGE_DOS_HEADER_INJ dosHeader;
    PIMAGE_NT_HEADERS64_INJ ntHeaders;
    PIMAGE_SECTION_HEADER_INJ section;
    SIZE_T ntOffset;
    SIZE_T sectionTableOffset;
    SIZE_T sectionTableSize;
    ULONG directoryIndex;
    ULONG sectionIndex;

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
        if (dosHeader->e_lfanew < 0) {
            DbgPrint("[Injection] Invalid PE header offset\n");
            return STATUS_INVALID_IMAGE_FORMAT;
        }
        ntOffset = (SIZE_T)dosHeader->e_lfanew;
        if (!InjectionRangeWithinSize(
                ntOffset, sizeof(IMAGE_NT_HEADERS64_INJ), ImageSize)) {
            DbgPrint("[Injection] Invalid PE header range\n");
            return STATUS_INVALID_IMAGE_FORMAT;
        }

        ntHeaders = (PIMAGE_NT_HEADERS64_INJ)((PUCHAR)ImageBase + ntOffset);

        // 验证 PE 签名
        if (ntHeaders->Signature != 0x4550) {  // "PE\0\0"
            DbgPrint("[Injection] Invalid PE signature\n");
            return STATUS_INVALID_IMAGE_FORMAT;
        }

        // 验证是否为 64 位
        if (ntHeaders->OptionalHeader.Magic != 0x20B ||
            ntHeaders->FileHeader.Machine != 0x8664 ||
            (ntHeaders->FileHeader.Characteristics & 0x2000) == 0 ||
            ntHeaders->FileHeader.SizeOfOptionalHeader <
                sizeof(IMAGE_OPTIONAL_HEADER64_INJ) ||
            ntHeaders->OptionalHeader.NumberOfRvaAndSizes < 16) {
            DbgPrint("[Injection] Not a 64-bit PE\n");
            return STATUS_INVALID_IMAGE_FORMAT;
        }

        if (ntHeaders->FileHeader.NumberOfSections == 0 ||
            ntHeaders->FileHeader.NumberOfSections > 96) {
            return STATUS_INVALID_IMAGE_FORMAT;
        }

        sectionTableOffset = ntOffset +
            FIELD_OFFSET(IMAGE_NT_HEADERS64_INJ, OptionalHeader) +
            ntHeaders->FileHeader.SizeOfOptionalHeader;
        sectionTableSize =
            (SIZE_T)ntHeaders->FileHeader.NumberOfSections *
            sizeof(IMAGE_SECTION_HEADER_INJ);
        if (!InjectionRangeWithinSize(
                sectionTableOffset, sectionTableSize, ImageSize)) {
            return STATUS_INVALID_IMAGE_FORMAT;
        }

        // 验证映像大小
        if (ntHeaders->OptionalHeader.SizeOfImage == 0 ||
            ntHeaders->OptionalHeader.SizeOfImage > 0x10000000 ||
            ntHeaders->OptionalHeader.SizeOfHeaders == 0 ||
            ntHeaders->OptionalHeader.SizeOfHeaders > ImageSize ||
            ntHeaders->OptionalHeader.SizeOfHeaders >
                ntHeaders->OptionalHeader.SizeOfImage ||
            sectionTableOffset + sectionTableSize >
                ntHeaders->OptionalHeader.SizeOfHeaders ||
            ntHeaders->OptionalHeader.SectionAlignment == 0 ||
            ntHeaders->OptionalHeader.FileAlignment == 0) {
            DbgPrint("[Injection] Image too large\n");
            return STATUS_INVALID_IMAGE_FORMAT;
        }

        if (ntHeaders->OptionalHeader.AddressOfEntryPoint != 0 &&
            !InjectionRvaRangeValid(
                ntHeaders,
                ntHeaders->OptionalHeader.AddressOfEntryPoint,
                1)) {
            return STATUS_INVALID_IMAGE_FORMAT;
        }

        for (directoryIndex = 0; directoryIndex < 16; directoryIndex++) {
            PIMAGE_DATA_DIRECTORY_INJ directory =
                &ntHeaders->OptionalHeader.DataDirectory[directoryIndex];
            if (directory->VirtualAddress == 0 && directory->Size == 0) {
                continue;
            }
            if (directory->VirtualAddress == 0 || directory->Size == 0) {
                return STATUS_INVALID_IMAGE_FORMAT;
            }
            if (directoryIndex == IMAGE_DIRECTORY_ENTRY_SECURITY) {
                if (!InjectionRangeWithinSize(
                        directory->VirtualAddress,
                        directory->Size,
                        ImageSize)) {
                    return STATUS_INVALID_IMAGE_FORMAT;
                }
            } else if (!InjectionRvaRangeValid(
                           ntHeaders,
                           directory->VirtualAddress,
                           directory->Size)) {
                return STATUS_INVALID_IMAGE_FORMAT;
            }
        }

        section = (PIMAGE_SECTION_HEADER_INJ)(
            (PUCHAR)ImageBase + sectionTableOffset);
        for (sectionIndex = 0;
             sectionIndex < ntHeaders->FileHeader.NumberOfSections;
             sectionIndex++, section++) {
            SIZE_T virtualSpan = section->Misc.VirtualSize;
            if (virtualSpan < section->SizeOfRawData) {
                virtualSpan = section->SizeOfRawData;
            }
            if (virtualSpan != 0 &&
                !InjectionRvaRangeValid(
                    ntHeaders, section->VirtualAddress, virtualSpan)) {
                return STATUS_INVALID_IMAGE_FORMAT;
            }
            if (section->SizeOfRawData != 0 &&
                !InjectionRangeWithinSize(
                    section->PointerToRawData,
                    section->SizeOfRawData,
                    ImageSize)) {
                return STATUS_INVALID_IMAGE_FORMAT;
            }
        }

        *OutNtHeaders = ntHeaders;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }

    return STATUS_SUCCESS;
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
    NTSTATUS status = InjectionOperationAcquire();
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = InjectionQueueUserApcCore(
        ProcessId, ThreadId, ApcRoutine, ApcContext, WaitComplete);
    InjectionOperationRelease();
    return status;
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
            SIZE_T copySize = section->SizeOfRawData;

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

#define IMAGE_SCN_MEM_NOT_CACHED_INJ 0x04000000UL
#define IMAGE_SCN_MEM_EXECUTE_INJ    0x20000000UL
#define IMAGE_SCN_MEM_READ_INJ       0x40000000UL
#define IMAGE_SCN_MEM_WRITE_INJ      0x80000000UL

static ULONG
InjectionSectionProtection(
    _In_ ULONG Characteristics
)
{
    BOOLEAN executable =
        (Characteristics & IMAGE_SCN_MEM_EXECUTE_INJ) != 0;
    BOOLEAN readable =
        (Characteristics & IMAGE_SCN_MEM_READ_INJ) != 0;
    BOOLEAN writable =
        (Characteristics & IMAGE_SCN_MEM_WRITE_INJ) != 0;
    ULONG protection;

    if (executable) {
        protection = writable
            ? PAGE_EXECUTE_READWRITE
            : (readable ? PAGE_EXECUTE_READ : PAGE_EXECUTE);
    } else {
        protection = writable
            ? PAGE_READWRITE
            : (readable ? PAGE_READONLY : PAGE_NOACCESS);
    }
    if (protection != PAGE_NOACCESS &&
        (Characteristics & IMAGE_SCN_MEM_NOT_CACHED_INJ) != 0) {
        protection |= PAGE_NOCACHE;
    }
    return protection;
}

static NTSTATUS
InjectionProtectAttachedRange(
    _In_ PVOID Address,
    _In_ SIZE_T Size,
    _In_ ULONG Protection
)
{
    PVOID baseAddress = Address;
    SIZE_T regionSize = Size;
    ULONG oldProtection = 0;

    if (!Address || Size == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    return ZwProtectVirtualMemory(
        ZwCurrentProcess(),
        &baseAddress,
        &regionSize,
        Protection,
        &oldProtection);
}

static NTSTATUS
InjectionApplyImageProtections(
    _In_ PVOID ImageBase,
    _In_ PIMAGE_NT_HEADERS64_INJ NtHeaders
)
{
    PIMAGE_SECTION_HEADER_INJ section;
    NTSTATUS status;
    ULONG sectionIndex;

    status = InjectionProtectAttachedRange(
        ImageBase,
        NtHeaders->OptionalHeader.SizeOfImage,
        PAGE_NOACCESS);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = InjectionProtectAttachedRange(
        ImageBase,
        NtHeaders->OptionalHeader.SizeOfHeaders,
        PAGE_READONLY);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    section = (PIMAGE_SECTION_HEADER_INJ)(
        (PUCHAR)&NtHeaders->OptionalHeader +
        NtHeaders->FileHeader.SizeOfOptionalHeader);
    for (sectionIndex = 0;
         sectionIndex < NtHeaders->FileHeader.NumberOfSections;
         sectionIndex++, section++) {
        SIZE_T sectionSize = section->Misc.VirtualSize;

        if (sectionSize < section->SizeOfRawData) {
            sectionSize = section->SizeOfRawData;
        }
        if (sectionSize == 0) {
            continue;
        }
        status = InjectionProtectAttachedRange(
            (PUCHAR)ImageBase + section->VirtualAddress,
            sectionSize,
            InjectionSectionProtection(section->Characteristics));
        if (!NT_SUCCESS(status)) {
            return status;
        }
    }
    return STATUS_SUCCESS;
}

static BOOLEAN
InjectionTrackModuleEntry(
    _Inout_ PINJECTED_MODULE_ENTRY ModuleEntry,
    _In_ PEPROCESS Process
)
{
    KIRQL oldIrql;
    BOOLEAN inserted = FALSE;

    if (!ModuleEntry || !Process ||
        InterlockedCompareExchange(
            &g_InjectionListsInitialized, 0, 0) == 0) {
        return FALSE;
    }

    KeAcquireSpinLock(&g_InjectionManager.Lock, &oldIrql);
    if (InterlockedCompareExchange(
            &g_InjectionListsInitialized, 0, 0) != 0 &&
        PsGetProcessExitStatus(Process) == STATUS_PENDING &&
        (UINT64)PsGetProcessCreateTimeQuadPart(Process) ==
            ModuleEntry->ProcessCreateTime) {
        InterlockedExchange(&ModuleEntry->Removing, 0);
        InsertTailList(
            &g_InjectionManager.InjectedModuleList,
            &ModuleEntry->ListEntry);
        g_InjectionManager.InjectedModuleCount++;
        inserted = TRUE;
    }
    KeReleaseSpinLock(&g_InjectionManager.Lock, oldIrql);
    return inserted;
}

static NTSTATUS
InjectionValidateRuntimeFunctionTable(
    _In_ PVOID FunctionTable,
    _In_ ULONG FunctionCount,
    _In_ PIMAGE_NT_HEADERS64_INJ NtHeaders
)
{
    ULONG functionIndex;

    if (!FunctionTable || FunctionCount == 0 || !NtHeaders) {
        return STATUS_INVALID_PARAMETER;
    }

    __try {
        for (functionIndex = 0;
             functionIndex < FunctionCount;
             functionIndex++) {
            PIMAGE_RUNTIME_FUNCTION_ENTRY_INJ runtimeFunction =
                &((PIMAGE_RUNTIME_FUNCTION_ENTRY_INJ)
                    FunctionTable)[functionIndex];

            if (runtimeFunction->BeginAddress >=
                    runtimeFunction->EndAddress ||
                runtimeFunction->EndAddress >
                    NtHeaders->OptionalHeader.SizeOfImage ||
                !InjectionRvaRangeValid(
                    NtHeaders,
                    runtimeFunction->UnwindInfoAddress,
                    sizeof(ULONG))) {
                return STATUS_INVALID_IMAGE_FORMAT;
            }
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
        return STATUS_CONFLICTING_ADDRESSES;
    }

    __try {
        reloc = (PIMAGE_BASE_RELOCATION_INJ)((PUCHAR)ImageBase + relocDir->VirtualAddress);
        relocSize = relocDir->Size;

        while (relocSize > 0) {
            if (relocSize < sizeof(IMAGE_BASE_RELOCATION_INJ) ||
                reloc->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION_INJ) ||
                reloc->SizeOfBlock > relocSize ||
                ((reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION_INJ)) & 1) != 0) {
                return STATUS_INVALID_IMAGE_FORMAT;
            }
            ULONG numEntries = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION_INJ)) / sizeof(USHORT);
            relocData = (PUSHORT)((PUCHAR)reloc + sizeof(IMAGE_BASE_RELOCATION_INJ));

            for (i = 0; i < numEntries; i++) {
                USHORT entry = relocData[i];
                USHORT type = entry >> 12;
                USHORT offset = entry & 0xFFF;
                SIZE_T targetRva =
                    (SIZE_T)reloc->VirtualAddress + (SIZE_T)offset;
                PVOID address;

                if (targetRva > MAXULONG) {
                    return STATUS_INVALID_IMAGE_FORMAT;
                }
                address = (PUCHAR)ImageBase + targetRva;

                switch (type) {
                    case IMAGE_REL_BASED_ABSOLUTE:
                        // 无需处理
                        break;

                    case IMAGE_REL_BASED_DIR64:
                        if (!InjectionRvaRangeValid(
                                NtHeaders,
                                (ULONG)targetRva,
                                sizeof(ULONGLONG))) {
                            return STATUS_INVALID_IMAGE_FORMAT;
                        }
                        *(PULONGLONG)address += Delta;
                        break;

                    case IMAGE_REL_BASED_HIGHLOW:
                        if (!InjectionRvaRangeValid(
                                NtHeaders,
                                (ULONG)targetRva,
                                sizeof(ULONG))) {
                            return STATUS_INVALID_IMAGE_FORMAT;
                        }
                        *(PULONG)address += (ULONG)Delta;
                        break;

                    case IMAGE_REL_BASED_HIGH:
                        if (!InjectionRvaRangeValid(
                                NtHeaders,
                                (ULONG)targetRva,
                                sizeof(USHORT))) {
                            return STATUS_INVALID_IMAGE_FORMAT;
                        }
                        *(PUSHORT)address += HIWORD(Delta);
                        break;

                    case IMAGE_REL_BASED_LOW:
                        if (!InjectionRvaRangeValid(
                                NtHeaders,
                                (ULONG)targetRva,
                                sizeof(USHORT))) {
                            return STATUS_INVALID_IMAGE_FORMAT;
                        }
                        *(PUSHORT)address += LOWORD(Delta);
                        break;

                    default:
                        DbgPrint("[Injection] Unknown relocation type: %d\n", type);
                        return STATUS_NOT_SUPPORTED;
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

typedef struct _API_SET_NAMESPACE_INJ {
    ULONG Version;
    ULONG Size;
    ULONG Flags;
    ULONG Count;
    ULONG EntryOffset;
    ULONG HashOffset;
    ULONG HashFactor;
} API_SET_NAMESPACE_INJ, *PAPI_SET_NAMESPACE_INJ;

typedef struct _API_SET_NAMESPACE_ENTRY_INJ {
    ULONG Flags;
    ULONG NameOffset;
    ULONG NameLength;
    ULONG HashedLength;
    ULONG ValueOffset;
    ULONG ValueCount;
} API_SET_NAMESPACE_ENTRY_INJ, *PAPI_SET_NAMESPACE_ENTRY_INJ;

typedef struct _API_SET_VALUE_ENTRY_INJ {
    ULONG Flags;
    ULONG NameOffset;
    ULONG NameLength;
    ULONG ValueOffset;
    ULONG ValueLength;
} API_SET_VALUE_ENTRY_INJ, *PAPI_SET_VALUE_ENTRY_INJ;

static NTSTATUS
InjectionResolveApiSetModule(
    _In_ PEPROCESS Process,
    _In_ PCWSTR ModuleName,
    _Out_writes_(ResolvedChars) PWSTR ResolvedName,
    _In_ SIZE_T ResolvedChars
)
{
    PPEB peb;
    PAPI_SET_NAMESPACE_INJ nameSpace;
    UNICODE_STRING requested;
    SIZE_T requestedChars = 0;
    ULONG entryIndex;

    if (!Process || !ModuleName || !ResolvedName || ResolvedChars == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    ResolvedName[0] = L'\0';

    while (requestedChars < MAX_MODULE_NAME_LENGTH &&
           ModuleName[requestedChars] != L'\0') {
        requestedChars++;
    }
    if (requestedChars == 0 || requestedChars == MAX_MODULE_NAME_LENGTH) {
        return STATUS_INVALID_PARAMETER;
    }
    if (requestedChars >= 4 &&
        ModuleName[requestedChars - 4] == L'.' &&
        (ModuleName[requestedChars - 3] == L'd' ||
         ModuleName[requestedChars - 3] == L'D') &&
        (ModuleName[requestedChars - 2] == L'l' ||
         ModuleName[requestedChars - 2] == L'L') &&
        (ModuleName[requestedChars - 1] == L'l' ||
         ModuleName[requestedChars - 1] == L'L')) {
        requestedChars -= 4;
    }
    if (requestedChars < 4 ||
        !((((ModuleName[0] == L'a' || ModuleName[0] == L'A') &&
            (ModuleName[1] == L'p' || ModuleName[1] == L'P') &&
            (ModuleName[2] == L'i' || ModuleName[2] == L'I')) ||
           ((ModuleName[0] == L'e' || ModuleName[0] == L'E') &&
            (ModuleName[1] == L'x' || ModuleName[1] == L'X') &&
            (ModuleName[2] == L't' || ModuleName[2] == L'T'))) &&
          ModuleName[3] == L'-')) {
        return STATUS_NOT_FOUND;
    }

    requested.Buffer = (PWSTR)ModuleName;
    requested.Length = (USHORT)(requestedChars * sizeof(WCHAR));
    requested.MaximumLength = requested.Length;

    peb = PsGetProcessPeb(Process);
    if (!peb) {
        return STATUS_NOT_FOUND;
    }

    __try {
        /* ApiSetMap is stable at PEB+0x68 for the x64 Win10/Win11 PEB. */
        nameSpace = *(PAPI_SET_NAMESPACE_INJ*)((PUCHAR)peb + 0x68);
        if (!nameSpace || nameSpace->Version != 6 ||
            nameSpace->Size < sizeof(*nameSpace) ||
            nameSpace->Size > 4 * 1024 * 1024 ||
            nameSpace->Count > 4096 ||
            !InjectionRangeWithinSize(
                nameSpace->EntryOffset,
                (SIZE_T)nameSpace->Count *
                    sizeof(API_SET_NAMESPACE_ENTRY_INJ),
                nameSpace->Size)) {
            return STATUS_NOT_SUPPORTED;
        }

        for (entryIndex = 0; entryIndex < nameSpace->Count; entryIndex++) {
            PAPI_SET_NAMESPACE_ENTRY_INJ entry =
                (PAPI_SET_NAMESPACE_ENTRY_INJ)(
                    (PUCHAR)nameSpace + nameSpace->EntryOffset) + entryIndex;
            UNICODE_STRING contract;
            PAPI_SET_VALUE_ENTRY_INJ values;
            PAPI_SET_VALUE_ENTRY_INJ selected = NULL;
            ULONG valueIndex;

            if ((entry->NameLength & 1) != 0 ||
                !InjectionRangeWithinSize(
                    entry->NameOffset, entry->NameLength, nameSpace->Size) ||
                entry->ValueCount == 0 || entry->ValueCount > 64 ||
                !InjectionRangeWithinSize(
                    entry->ValueOffset,
                    (SIZE_T)entry->ValueCount *
                        sizeof(API_SET_VALUE_ENTRY_INJ),
                    nameSpace->Size)) {
                return STATUS_INVALID_IMAGE_FORMAT;
            }

            contract.Buffer = (PWSTR)(
                (PUCHAR)nameSpace + entry->NameOffset);
            contract.Length = (USHORT)entry->NameLength;
            contract.MaximumLength = contract.Length;
            if (RtlCompareUnicodeString(&contract, &requested, TRUE) != 0) {
                continue;
            }

            values = (PAPI_SET_VALUE_ENTRY_INJ)(
                (PUCHAR)nameSpace + entry->ValueOffset);
            for (valueIndex = 0;
                 valueIndex < entry->ValueCount;
                 valueIndex++) {
                if (!selected || values[valueIndex].NameLength == 0) {
                    selected = &values[valueIndex];
                }
                if (values[valueIndex].NameLength == 0) {
                    break;
                }
            }
            if (!selected || selected->ValueLength == 0 ||
                (selected->ValueLength & 1) != 0 ||
                !InjectionRangeWithinSize(
                    selected->ValueOffset,
                    selected->ValueLength,
                    nameSpace->Size) ||
                selected->ValueLength / sizeof(WCHAR) + 1 > ResolvedChars) {
                return STATUS_INVALID_IMAGE_FORMAT;
            }

            RtlCopyMemory(
                ResolvedName,
                (PUCHAR)nameSpace + selected->ValueOffset,
                selected->ValueLength);
            ResolvedName[selected->ValueLength / sizeof(WCHAR)] = L'\0';
            return STATUS_SUCCESS;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }

    return STATUS_NOT_FOUND;
}

static PVOID
InjectionFindLoadedModuleBase(
    _In_ PEPROCESS Process,
    _In_ PCWSTR ModuleName
)
{
    PPEB peb;
    PVOID ldr;
    PLIST_ENTRY listHead;
    PLIST_ENTRY listEntry;
    UNICODE_STRING targetName;
    ULONG visited = 0;

    peb = PsGetProcessPeb(Process);
    if (!peb) {
        return NULL;
    }
    RtlInitUnicodeString(&targetName, ModuleName);

    __try {
        ldr = *(PVOID*)((PUCHAR)peb + 0x18);
        if (!ldr) {
            return NULL;
        }
        listHead = (PLIST_ENTRY)((PUCHAR)ldr + 0x10);
        for (listEntry = listHead->Flink;
             listEntry != listHead && visited++ < 1024;
             listEntry = listEntry->Flink) {
            PUNICODE_STRING baseName =
                (PUNICODE_STRING)((PUCHAR)listEntry + 0x58);
            PVOID dllBase = *(PVOID*)((PUCHAR)listEntry + 0x30);
            if (baseName->Buffer && baseName->Length > 0 &&
                baseName->Length <= baseName->MaximumLength &&
                baseName->Length <= MAX_MODULE_NAME_LENGTH * sizeof(WCHAR) &&
                RtlCompareUnicodeString(baseName, &targetName, TRUE) == 0) {
                return dllBase;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return NULL;
    }
    return NULL;
}

static PVOID
InjectionGetModuleBase(
    _In_ PEPROCESS Process,
    _In_ PCWSTR ModuleName
)
{
    WCHAR resolvedName[MAX_MODULE_NAME_LENGTH];
    PVOID moduleBase;

    if (!Process || !ModuleName) {
        return NULL;
    }

    moduleBase = InjectionFindLoadedModuleBase(Process, ModuleName);
    if (moduleBase) {
        return moduleBase;
    }

    if (NT_SUCCESS(InjectionResolveApiSetModule(
            Process,
            ModuleName,
            resolvedName,
            RTL_NUMBER_OF(resolvedName)))) {
        return InjectionFindLoadedModuleBase(Process, resolvedName);
    }
    return NULL;
}

static NTSTATUS
InjectionQueryRemoteImage(
    _In_ ULONG ProcessId,
    _In_ PVOID ModuleBase,
    _Out_ PSIZE_T ImageSize,
    _Out_opt_ PVOID* EntryPoint
)
{
    IMAGE_DOS_HEADER_INJ dosHeader;
    IMAGE_NT_HEADERS64_INJ ntHeaders;
    SIZE_T bytesRead = 0;
    ULONG ntOffset;
    NTSTATUS status;

    if (ProcessId == 0 || !ModuleBase || !ImageSize) {
        return STATUS_INVALID_PARAMETER;
    }
    *ImageSize = 0;
    if (EntryPoint) {
        *EntryPoint = NULL;
    }

    status = HvMemoryRead(
        ProcessId,
        ModuleBase,
        &dosHeader,
        sizeof(dosHeader),
        &bytesRead);
    if (!NT_SUCCESS(status) || bytesRead != sizeof(dosHeader)) {
        return NT_SUCCESS(status) ? STATUS_PARTIAL_COPY : status;
    }
    if (dosHeader.e_magic != 0x5A4D || dosHeader.e_lfanew < 0 ||
        (ULONG)dosHeader.e_lfanew > 1024 * 1024) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }
    ntOffset = (ULONG)dosHeader.e_lfanew;
    if ((ULONG_PTR)ModuleBase > MAXULONG_PTR - ntOffset) {
        return STATUS_INTEGER_OVERFLOW;
    }

    bytesRead = 0;
    status = HvMemoryRead(
        ProcessId,
        (PUCHAR)ModuleBase + ntOffset,
        &ntHeaders,
        sizeof(ntHeaders),
        &bytesRead);
    if (!NT_SUCCESS(status) || bytesRead != sizeof(ntHeaders)) {
        return NT_SUCCESS(status) ? STATUS_PARTIAL_COPY : status;
    }
    if (ntHeaders.Signature != 0x4550 ||
        ntHeaders.OptionalHeader.Magic != 0x20B ||
        ntHeaders.OptionalHeader.SizeOfImage == 0) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    *ImageSize = ntHeaders.OptionalHeader.SizeOfImage;
    if (EntryPoint && ntHeaders.OptionalHeader.AddressOfEntryPoint != 0) {
        if (ntHeaders.OptionalHeader.AddressOfEntryPoint >=
            ntHeaders.OptionalHeader.SizeOfImage) {
            return STATUS_INVALID_IMAGE_FORMAT;
        }
        *EntryPoint = (PUCHAR)ModuleBase +
            ntHeaders.OptionalHeader.AddressOfEntryPoint;
    }
    return STATUS_SUCCESS;
}

static PVOID
InjectionGetProcAddress(
    _In_ PEPROCESS Process,
    _In_ PVOID ModuleBase,
    _In_ ULONG_PTR NameOrOrdinal,
    _In_ ULONG RecursionDepth
)
{
    PIMAGE_DOS_HEADER_INJ dosHeader;
    PIMAGE_NT_HEADERS64_INJ ntHeaders;
    PIMAGE_DATA_DIRECTORY_INJ exportDir;
    PULONG addressOfFunctions;
    PULONG addressOfNames;
    PUSHORT addressOfOrdinals;
    ULONG functionIndex = MAXULONG;
    ULONG functionRva;
    ULONG i;

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

    if (!Process || !ModuleBase || NameOrOrdinal == 0 ||
        RecursionDepth > 8) {
        return NULL;
    }

    __try {
        PIMAGE_EXPORT_DIRECTORY_INJ exports;

        dosHeader = (PIMAGE_DOS_HEADER_INJ)ModuleBase;
        if (dosHeader->e_magic != 0x5A4D || dosHeader->e_lfanew < 0) {
            return NULL;
        }

        ntHeaders = (PIMAGE_NT_HEADERS64_INJ)((PUCHAR)ModuleBase + dosHeader->e_lfanew);
        if (ntHeaders->Signature != 0x4550 ||
            ntHeaders->OptionalHeader.Magic != 0x20B ||
            !InjectionRvaRangeValid(
                ntHeaders, (ULONG)dosHeader->e_lfanew,
                sizeof(IMAGE_NT_HEADERS64_INJ))) {
            return NULL;
        }

        exportDir = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (exportDir->VirtualAddress == 0 ||
            exportDir->Size < sizeof(IMAGE_EXPORT_DIRECTORY_INJ) ||
            !InjectionRvaRangeValid(
                ntHeaders, exportDir->VirtualAddress, exportDir->Size)) {
            return NULL;
        }

        exports =
            (PIMAGE_EXPORT_DIRECTORY_INJ)((PUCHAR)ModuleBase + exportDir->VirtualAddress);
        if (exports->NumberOfFunctions == 0 ||
            !InjectionRvaRangeValid(
                ntHeaders,
                exports->AddressOfFunctions,
                (SIZE_T)exports->NumberOfFunctions * sizeof(ULONG))) {
            return NULL;
        }

        addressOfFunctions = (PULONG)((PUCHAR)ModuleBase + exports->AddressOfFunctions);

        if (NameOrOrdinal <= MAXUSHORT) {
            ULONG ordinal = (ULONG)NameOrOrdinal;
            if (ordinal < exports->Base ||
                ordinal - exports->Base >= exports->NumberOfFunctions) {
                return NULL;
            }
            functionIndex = ordinal - exports->Base;
        } else {
            PCSTR functionName = (PCSTR)NameOrOrdinal;
            if (exports->NumberOfNames == 0 ||
                exports->NumberOfNames > exports->NumberOfFunctions ||
                !InjectionRvaRangeValid(
                    ntHeaders,
                    exports->AddressOfNames,
                    (SIZE_T)exports->NumberOfNames * sizeof(ULONG)) ||
                !InjectionRvaRangeValid(
                    ntHeaders,
                    exports->AddressOfNameOrdinals,
                    (SIZE_T)exports->NumberOfNames * sizeof(USHORT))) {
                return NULL;
            }

            addressOfNames = (PULONG)(
                (PUCHAR)ModuleBase + exports->AddressOfNames);
            addressOfOrdinals = (PUSHORT)(
                (PUCHAR)ModuleBase + exports->AddressOfNameOrdinals);
            for (i = 0; i < exports->NumberOfNames; i++) {
                PCSTR currentName;
                if (!InjectionAnsiStringRvaValid(
                        ModuleBase, ntHeaders, addressOfNames[i], 4096)) {
                    return NULL;
                }
                currentName = (PCSTR)(
                    (PUCHAR)ModuleBase + addressOfNames[i]);
                if (strcmp(currentName, functionName) == 0) {
                    if (addressOfOrdinals[i] >= exports->NumberOfFunctions) {
                        return NULL;
                    }
                    functionIndex = addressOfOrdinals[i];
                    break;
                }
            }
        }

        if (functionIndex == MAXULONG) {
            return NULL;
        }
        functionRva = addressOfFunctions[functionIndex];
        if (functionRva == 0) {
            return NULL;
        }

        if ((SIZE_T)functionRva >= exportDir->VirtualAddress &&
            (SIZE_T)functionRva <
                (SIZE_T)exportDir->VirtualAddress + exportDir->Size) {
            CHAR forwarder[256];
            WCHAR moduleName[MAX_MODULE_NAME_LENGTH];
            PCSTR source;
            SIZE_T length = 0;
            SIZE_T delimiter = MAXULONG_PTR;
            SIZE_T moduleLength;
            SIZE_T functionOffset;
            PVOID forwardModule;
            ULONG_PTR forwardedName;

            if (!InjectionAnsiStringRvaValid(
                    ModuleBase, ntHeaders, functionRva, sizeof(forwarder))) {
                return NULL;
            }
            source = (PCSTR)((PUCHAR)ModuleBase + functionRva);
            while (source[length] != '\0' && length + 1 < sizeof(forwarder)) {
                forwarder[length] = source[length];
                if (source[length] == '.') {
                    delimiter = length;
                }
                length++;
            }
            forwarder[length] = '\0';
            if (delimiter == MAXULONG_PTR || delimiter == 0 ||
                delimiter + 1 >= length) {
                return NULL;
            }

            moduleLength = delimiter;
            if (moduleLength + 5 >= RTL_NUMBER_OF(moduleName)) {
                return NULL;
            }
            for (i = 0; i < moduleLength; i++) {
                moduleName[i] = (WCHAR)(UCHAR)forwarder[i];
            }
            moduleName[moduleLength] = L'\0';
            if (moduleLength < 4 ||
                moduleName[moduleLength - 4] != L'.') {
                moduleName[moduleLength++] = L'.';
                moduleName[moduleLength++] = L'd';
                moduleName[moduleLength++] = L'l';
                moduleName[moduleLength++] = L'l';
                moduleName[moduleLength] = L'\0';
            }

            forwardModule = InjectionGetModuleBase(Process, moduleName);
            if (!forwardModule) {
                return NULL;
            }

            functionOffset = delimiter + 1;
            if (forwarder[functionOffset] == '#') {
                ULONG ordinal = 0;
                functionOffset++;
                if (functionOffset >= length) {
                    return NULL;
                }
                while (functionOffset < length) {
                    UCHAR digit = (UCHAR)forwarder[functionOffset++];
                    if (digit < '0' || digit > '9' ||
                        ordinal >
                            ((ULONG)MAXUSHORT - (ULONG)(digit - '0')) / 10) {
                        return NULL;
                    }
                    ordinal = ordinal * 10 + (digit - '0');
                }
                forwardedName = ordinal;
            } else {
                forwardedName = (ULONG_PTR)&forwarder[functionOffset];
            }

            return InjectionGetProcAddress(
                Process,
                forwardModule,
                forwardedName,
                RecursionDepth + 1);
        }

        if (!InjectionRvaRangeValid(ntHeaders, functionRva, 1)) {
            return NULL;
        }
        return (PUCHAR)ModuleBase + functionRva;
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
    NTSTATUS status = STATUS_SUCCESS;
    ULONG descriptorCount;
    ULONG descriptorIndex;
    BOOLEAN terminated = FALSE;

    importDir = &NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

    if (importDir->VirtualAddress == 0 || importDir->Size == 0) {
        DbgPrint("[Injection] No imports\n");
        return STATUS_SUCCESS;
    }

    __try {
        PIMAGE_IMPORT_DESCRIPTOR_INJ importDesc =
            (PIMAGE_IMPORT_DESCRIPTOR_INJ)(
                (PUCHAR)ImageBase + importDir->VirtualAddress);

        descriptorCount = importDir->Size /
            sizeof(IMAGE_IMPORT_DESCRIPTOR_INJ);
        if (descriptorCount == 0) {
            return STATUS_INVALID_IMAGE_FORMAT;
        }

        for (descriptorIndex = 0;
             descriptorIndex < descriptorCount;
             descriptorIndex++, importDesc++) {
            PCSTR moduleName = (PCSTR)((PUCHAR)ImageBase + importDesc->Name);
            PVOID moduleBase;
            PULONGLONG thunk;
            PULONGLONG origThunk;
            ULONG origThunkRva;
            ULONG thunkIndex;
            ULONG maximumThunks;

            if (importDesc->Name == 0) {
                terminated = TRUE;
                break;
            }
            if (!InjectionAnsiStringRvaValid(
                    ImageBase, NtHeaders, importDesc->Name,
                    MAX_MODULE_NAME_LENGTH)) {
                return STATUS_INVALID_IMAGE_FORMAT;
            }

            // 将 ANSI 转换为 Unicode
            WCHAR moduleNameW[MAX_MODULE_NAME_LENGTH] = { 0 };
            ANSI_STRING ansiName;
            UNICODE_STRING uniName;

            RtlInitAnsiString(&ansiName, moduleName);
            uniName.Buffer = moduleNameW;
            uniName.Length = 0;
            uniName.MaximumLength = sizeof(moduleNameW);

            status = RtlAnsiStringToUnicodeString(&uniName, &ansiName, FALSE);
            if (!NT_SUCCESS(status)) {
                DbgPrint("[Injection] Failed to convert module name\n");
                return status;
            }
            moduleNameW[uniName.Length / sizeof(WCHAR)] = L'\0';

            DbgPrint("[Injection] Resolving imports from: %s\n", moduleName);

            // 获取模块基址
            moduleBase = InjectionGetModuleBase(Process, moduleNameW);
            if (!moduleBase) {
                DbgPrint("[Injection] Module not found: %s\n", moduleName);
                return STATUS_DLL_NOT_FOUND;
            }

            // 获取 thunk 数组
            if (importDesc->OriginalFirstThunk) {
                origThunkRva = importDesc->OriginalFirstThunk;
            } else {
                origThunkRva = importDesc->FirstThunk;
            }

            if (!InjectionRvaRangeValid(
                    NtHeaders, origThunkRva, sizeof(ULONGLONG)) ||
                !InjectionRvaRangeValid(
                    NtHeaders, importDesc->FirstThunk, sizeof(ULONGLONG))) {
                return STATUS_INVALID_IMAGE_FORMAT;
            }
            origThunk = (PULONGLONG)(
                (PUCHAR)ImageBase + origThunkRva);
            thunk = (PULONGLONG)((PUCHAR)ImageBase + importDesc->FirstThunk);
            maximumThunks = (ULONG)min(
                (NtHeaders->OptionalHeader.SizeOfImage - origThunkRva) /
                    sizeof(ULONGLONG),
                (NtHeaders->OptionalHeader.SizeOfImage - importDesc->FirstThunk) /
                    sizeof(ULONGLONG));

            for (thunkIndex = 0;
                 thunkIndex < maximumThunks;
                 thunkIndex++, origThunk++, thunk++) {
                PVOID funcAddress = NULL;

                if (*origThunk == 0) {
                    break;
                }
                if (*origThunk & 0x8000000000000000ULL) {
                    // 按序号导入
                    USHORT ordinal = (USHORT)(*origThunk & 0xFFFF);
                    funcAddress = InjectionGetProcAddress(
                        Process, moduleBase, ordinal, 0);
                } else {
                    ULONGLONG importNameRva64 =
                        *origThunk & 0x7FFFFFFFFFFFFFFFULL;
                    ULONG importNameRva;
                    // 按名称导入
                    PIMAGE_IMPORT_BY_NAME_INJ importByName;
                    if (importNameRva64 > MAXULONG) {
                        return STATUS_INVALID_IMAGE_FORMAT;
                    }
                    importNameRva = (ULONG)importNameRva64;
                    if (!InjectionRvaRangeValid(
                            NtHeaders,
                            importNameRva,
                            FIELD_OFFSET(IMAGE_IMPORT_BY_NAME_INJ, Name) + 1) ||
                        !InjectionAnsiStringRvaValid(
                            ImageBase,
                            NtHeaders,
                            importNameRva +
                                FIELD_OFFSET(IMAGE_IMPORT_BY_NAME_INJ, Name),
                            4096)) {
                        return STATUS_INVALID_IMAGE_FORMAT;
                    }
                    importByName = (PIMAGE_IMPORT_BY_NAME_INJ)(
                        (PUCHAR)ImageBase + importNameRva);
                    funcAddress = InjectionGetProcAddress(
                        Process,
                        moduleBase,
                        (ULONG_PTR)importByName->Name,
                        0);
                }

                if (!funcAddress) {
                    DbgPrint("[Injection] Import not found in %s\n", moduleName);
                    return STATUS_ENTRYPOINT_NOT_FOUND;
                }
                *thunk = (ULONGLONG)funcAddress;
            }
            if (thunkIndex == maximumThunks) {
                return STATUS_INVALID_IMAGE_FORMAT;
            }
        }

        if (!terminated) {
            status = STATUS_INVALID_IMAGE_FORMAT;
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
InjectionCollectTlsCallbacks(
    _In_ PVOID ImageBase,
    _In_ PIMAGE_NT_HEADERS64_INJ NtHeaders,
    _Out_writes_(MAX_INJECTION_TLS_CALLBACKS) PVOID* Callbacks,
    _Out_ PULONG CallbackCount
)
{
    PIMAGE_DATA_DIRECTORY_INJ tlsDir;
    PIMAGE_TLS_DIRECTORY64_INJ tlsDirectory;
    PULONGLONG callbackTable;
    ULONG callbackIndex;

    if (!ImageBase || !NtHeaders || !Callbacks || !CallbackCount) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(
        Callbacks,
        MAX_INJECTION_TLS_CALLBACKS * sizeof(PVOID));
    *CallbackCount = 0;

    tlsDir = &NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (tlsDir->VirtualAddress == 0 || tlsDir->Size == 0) {
        return STATUS_SUCCESS;
    }
    if (tlsDir->Size < sizeof(IMAGE_TLS_DIRECTORY64_INJ) ||
        !InjectionRvaRangeValid(
            NtHeaders,
            tlsDir->VirtualAddress,
            sizeof(IMAGE_TLS_DIRECTORY64_INJ))) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    __try {
        ULONG_PTR imageStart = (ULONG_PTR)ImageBase;
        ULONG_PTR imageEnd;
        ULONG_PTR tableAddress;

        if (imageStart > MAXULONG_PTR -
                NtHeaders->OptionalHeader.SizeOfImage) {
            return STATUS_INVALID_IMAGE_FORMAT;
        }
        imageEnd = imageStart + NtHeaders->OptionalHeader.SizeOfImage;

        tlsDirectory = (PIMAGE_TLS_DIRECTORY64_INJ)(
            (PUCHAR)ImageBase + tlsDir->VirtualAddress);
        if (tlsDirectory->EndAddressOfRawData <
                tlsDirectory->StartAddressOfRawData ||
            tlsDirectory->EndAddressOfRawData !=
                tlsDirectory->StartAddressOfRawData ||
            tlsDirectory->SizeOfZeroFill != 0) {
            return STATUS_NOT_SUPPORTED;
        }
        if (tlsDirectory->AddressOfCallBacks == 0) {
            return STATUS_SUCCESS;
        }

        tableAddress = (ULONG_PTR)tlsDirectory->AddressOfCallBacks;
        if (tableAddress < imageStart ||
            tableAddress > imageEnd - sizeof(ULONGLONG)) {
            return STATUS_INVALID_IMAGE_FORMAT;
        }
        callbackTable = (PULONGLONG)tableAddress;
        for (callbackIndex = 0;
             callbackIndex < MAX_INJECTION_TLS_CALLBACKS;
             callbackIndex++) {
            if (!InjectionRangeWithinSize(
                    (SIZE_T)(tableAddress - imageStart),
                    ((SIZE_T)callbackIndex + 1) * sizeof(ULONGLONG),
                    NtHeaders->OptionalHeader.SizeOfImage)) {
                return STATUS_INVALID_IMAGE_FORMAT;
            }
            ULONG_PTR callbackAddress =
                (ULONG_PTR)callbackTable[callbackIndex];
            if (callbackAddress == 0) {
                *CallbackCount = callbackIndex;
                return STATUS_SUCCESS;
            }
            if (callbackAddress < imageStart || callbackAddress >= imageEnd) {
                return STATUS_INVALID_IMAGE_FORMAT;
            }
            Callbacks[callbackIndex] = (PVOID)callbackAddress;
        }
        return STATUS_BUFFER_OVERFLOW;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }
}

static NTSTATUS
InjectionAttachTlsCallbacks(
    _In_ ULONG ProcessId,
    _Inout_ PINJECTED_MODULE_ENTRY ModuleEntry,
    _Inout_ PBOOLEAN RollbackSafe
)
{
    NTSTATUS status;
    ULONG callbackIndex;

    if (!ModuleEntry || !RollbackSafe ||
        ModuleEntry->TlsCallbackCount > MAX_INJECTION_TLS_CALLBACKS ||
        ModuleEntry->TlsAttachedCount > ModuleEntry->TlsCallbackCount) {
        return STATUS_INVALID_PARAMETER;
    }

    for (callbackIndex = ModuleEntry->TlsAttachedCount;
         callbackIndex < ModuleEntry->TlsCallbackCount;
         callbackIndex++) {
        status = InjectionCallUserRoutine(
            ProcessId,
            ModuleEntry->ProcessCreateTime,
            ModuleEntry->TlsCallbacks[callbackIndex],
            ModuleEntry->ModuleBase,
            (PVOID)(ULONG_PTR)1,
            NULL,
            NULL,
            NULL,
            RollbackSafe);
        if (!NT_SUCCESS(status)) {
            ModuleEntry->TlsAttached =
                ModuleEntry->TlsAttachedCount != 0;
            return status;
        }
        ModuleEntry->TlsAttachedCount = callbackIndex + 1;
        ModuleEntry->TlsAttached = TRUE;
    }
    return STATUS_SUCCESS;
}

static NTSTATUS
InjectionDetachTlsCallbacks(
    _In_ ULONG ProcessId,
    _Inout_ PINJECTED_MODULE_ENTRY ModuleEntry,
    _Inout_ PBOOLEAN RollbackSafe
)
{
    NTSTATUS status;

    if (!ModuleEntry || !RollbackSafe ||
        ModuleEntry->TlsAttachedCount > ModuleEntry->TlsCallbackCount ||
        ModuleEntry->TlsDetachIndex > ModuleEntry->TlsAttachedCount) {
        return STATUS_INVALID_PARAMETER;
    }

    while (ModuleEntry->TlsDetachIndex <
           ModuleEntry->TlsAttachedCount) {
        status = InjectionCallUserRoutine(
            ProcessId,
            ModuleEntry->ProcessCreateTime,
            ModuleEntry->TlsCallbacks[ModuleEntry->TlsDetachIndex],
            ModuleEntry->ModuleBase,
            NULL,
            NULL,
            NULL,
            NULL,
            RollbackSafe);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        ModuleEntry->TlsDetachIndex++;
    }

    ModuleEntry->TlsAttachedCount = 0;
    ModuleEntry->TlsDetachIndex = 0;
    ModuleEntry->TlsAttached = FALSE;
    return STATUS_SUCCESS;
}

// ============================================================
// DLL 注入
// ============================================================

#if 0
static NTSTATUS
InjectionInjectDllCoreLegacy(
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

    if (OutResult &&
        OutResult->Diagnostics.Version !=
            HV_INJECTION_DIAGNOSTIC_VERSION) {
        InjectionDiagnosticInitialize(
            OutResult, HV_INJECTION_DIAG_FLAG_MANUAL_MAP);
    }

    // 验证 PE
    status = InjectionValidatePe(DllBuffer, DllSize, &ntHeaders);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[Injection] PE validation failed: 0x%X\n", status);
        return status;
    }

    imageSize = ntHeaders->OptionalHeader.SizeOfImage;
    DbgPrint("[Injection] Image size: 0x%llX\n", (ULONGLONG)imageSize);

    // Allocation remains Windows-managed so VAD/PFN/commit and process-exit
    // lifetimes stay coherent. Subsequent data reads/writes still use VT.
    status = InjectionMemoryAllocateCore(
        ProcessId, imageSize, PAGE_EXECUTE_READWRITE, &targetBase);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[Injection] HvMemoryAllocate failed: 0x%X\n", status);
        return status;
    }
    // Attach for the existing section-mapping/relocation/import code.
    status = HvAttachProcess(ProcessId, &process, &apcState);
    if (!NT_SUCCESS(status)) {
        (void)InjectionMemoryFreeCore(ProcessId, targetBase);
        return status;
    }

    DbgPrint("[Injection] Allocated at: %p (Windows-managed VAD)\n", targetBase);

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
        moduleEntry->ProcessCreateTime =
            (UINT64)PsGetProcessCreateTimeQuadPart(process);
        moduleEntry->ModuleBase = targetBase;
        moduleEntry->ModuleSize = imageSize;
        moduleEntry->Removing = 0;

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
        // Detach before HvMemoryFree performs its own target-context operation.
        HvDetachProcess(process, &apcState);
        (void)InjectionMemoryFreeCore(ProcessId, targetBase);
        return status;
    }
    HvDetachProcess(process, &apcState);
    return status;
}

#endif

static NTSTATUS
InjectionInjectDllCore(
    _In_ ULONG ProcessId,
    _In_ PVOID DllBuffer,
    _In_ SIZE_T DllSize,
    _In_opt_ PCWSTR SourcePath,
    _Out_opt_ PHV_INJECTION_RESULT OutResult
)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    NTSTATUS cleanupStatus;
    PEPROCESS process = NULL;
    PEPROCESS processReference = NULL;
    KAPC_STATE_INJ apcState;
    PIMAGE_NT_HEADERS64_INJ ntHeaders = NULL;
    PIMAGE_NT_HEADERS64_INJ targetHeaders = NULL;
    PIMAGE_DATA_DIRECTORY_INJ exceptionDirectory;
    PVOID targetBase = NULL;
    PVOID ntdllBase = NULL;
    PVOID loadRoutine = NULL;
    PVOID unloadRoutine = NULL;
    PVOID flushInstructionCacheRoutine = NULL;
    PVOID addFunctionTableRoutine = NULL;
    PVOID deleteFunctionTableRoutine = NULL;
    PVOID functionTable = NULL;
    PVOID entryPoint = NULL;
    SIZE_T imageSize = 0;
    LONGLONG delta;
    PINJECTED_MODULE_ENTRY moduleEntry = NULL;
    PHV_INJECTION_DEPENDENCY_PLAN dependencyPlan = NULL;
    ULONGLONG routineResult = 0;
    ULONG functionTableCount = 0;
    BOOLEAN attached = FALSE;
    BOOLEAN rollbackSafe = TRUE;
    USHORT failureStage = HvInjectStageManualValidateInput;

    if (OutResult &&
        OutResult->Diagnostics.Version !=
            HV_INJECTION_DIAGNOSTIC_VERSION) {
        InjectionDiagnosticInitialize(
            OutResult, HV_INJECTION_DIAG_FLAG_MANUAL_MAP);
    } else if (OutResult) {
        OutResult->Diagnostics.Flags |=
            HV_INJECTION_DIAG_FLAG_MANUAL_MAP;
    }
    if (ProcessId == 0 || !DllBuffer || DllSize == 0) {
        status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }
    InjectionDiagnosticRecord(
        OutResult,
        HvInjectStageManualValidateInput,
        HvInjectDiagnosticPhaseOperation,
        STATUS_SUCCESS,
        0);

    failureStage = HvInjectStageManualValidateEnvironment;
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        status = STATUS_INVALID_LEVEL;
        goto Exit;
    }
    if (!InjectionApcExecutionAvailable()) {
        status = STATUS_NOT_SUPPORTED;
        goto Exit;
    }
    InjectionDiagnosticRecord(
        OutResult,
        HvInjectStageManualValidateEnvironment,
        HvInjectDiagnosticPhaseOperation,
        STATUS_SUCCESS,
        0);

    failureStage = HvInjectStageManualValidatePe;
    status = InjectionValidatePe(DllBuffer, DllSize, &ntHeaders);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }
    InjectionDiagnosticRecord(
        OutResult,
        HvInjectStageManualValidatePe,
        HvInjectDiagnosticPhaseOperation,
        STATUS_SUCCESS,
        0);

    failureStage = HvInjectStageManualValidateFeatures;
    if (ntHeaders->OptionalHeader.DataDirectory[
            IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress != 0 ||
        ntHeaders->OptionalHeader.DataDirectory[
            IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].Size != 0 ||
        ntHeaders->OptionalHeader.DataDirectory[
            IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress != 0 ||
        ntHeaders->OptionalHeader.DataDirectory[
            IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].Size != 0) {
        status = STATUS_NOT_SUPPORTED;
        goto Exit;
    }
    InjectionDiagnosticRecord(
        OutResult,
        HvInjectStageManualValidateFeatures,
        HvInjectDiagnosticPhaseOperation,
        STATUS_SUCCESS,
        0);

    imageSize = ntHeaders->OptionalHeader.SizeOfImage;
    failureStage = HvInjectStageManualAllocateMetadata;
    moduleEntry = (PINJECTED_MODULE_ENTRY)HvAllocateNonPagedZeroed(
        sizeof(INJECTED_MODULE_ENTRY), HV_INJECTION_TAG);
    dependencyPlan = (PHV_INJECTION_DEPENDENCY_PLAN)
        HvAllocateNonPagedZeroed(
            sizeof(*dependencyPlan), HV_INJECTION_TAG);
    if (!moduleEntry || !dependencyPlan) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }
    InjectionDiagnosticRecord(
        OutResult,
        HvInjectStageManualAllocateMetadata,
        HvInjectDiagnosticPhaseOperation,
        STATUS_SUCCESS,
        0);

    failureStage = HvInjectStageManualBuildSearchPath;
    status = InjectionBuildDependencySearchPath(
        SourcePath,
        dependencyPlan->SearchPath,
        RTL_NUMBER_OF(dependencyPlan->SearchPath));
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }
    InjectionDiagnosticRecord(
        OutResult,
        HvInjectStageManualBuildSearchPath,
        HvInjectDiagnosticPhaseOperation,
        STATUS_SUCCESS,
        0);

    failureStage = HvInjectStageManualAllocateImage;
    status = InjectionMemoryAllocateCore(
        ProcessId, imageSize, PAGE_EXECUTE_READWRITE, &targetBase);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }
    InjectionDiagnosticRecord(
        OutResult,
        HvInjectStageManualAllocateImage,
        HvInjectDiagnosticPhaseOperation,
        STATUS_SUCCESS,
        0);

    failureStage = HvInjectStageManualAttachProcess;
    status = HvAttachProcess(ProcessId, &process, &apcState);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }
    attached = TRUE;
    InjectionDiagnosticRecord(
        OutResult,
        HvInjectStageManualAttachProcess,
        HvInjectDiagnosticPhaseOperation,
        STATUS_SUCCESS,
        0);

    failureStage = HvInjectStageManualValidateTarget;
    if (PsGetProcessWow64Process(process) != NULL) {
        status = STATUS_IMAGE_MACHINE_TYPE_MISMATCH;
        goto Cleanup;
    }
    moduleEntry->ProcessCreateTime =
        (UINT64)PsGetProcessCreateTimeQuadPart(process);
    if (moduleEntry->ProcessCreateTime == 0) {
        status = STATUS_INVALID_CID;
        goto Cleanup;
    }
    moduleEntry->ProcessId = ProcessId;
    moduleEntry->ModuleBase = targetBase;
    moduleEntry->ModuleSize = imageSize;
    ObReferenceObject(process);
    processReference = process;
    InjectionDiagnosticRecord(
        OutResult,
        HvInjectStageManualValidateTarget,
        HvInjectDiagnosticPhaseOperation,
        STATUS_SUCCESS,
        0);

    failureStage = HvInjectStageManualMapSections;
    status = InjectionMapSections(DllBuffer, targetBase, ntHeaders);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }
    InjectionDiagnosticRecord(
        OutResult,
        HvInjectStageManualMapSections,
        HvInjectDiagnosticPhaseOperation,
        STATUS_SUCCESS,
        0);
    targetHeaders = (PIMAGE_NT_HEADERS64_INJ)(
        (PUCHAR)targetBase + ((PIMAGE_DOS_HEADER_INJ)DllBuffer)->e_lfanew);
    delta = (LONGLONG)(
        (ULONGLONG)targetBase - ntHeaders->OptionalHeader.ImageBase);
    failureStage = HvInjectStageManualRelocate;
    status = InjectionProcessRelocations(targetBase, targetHeaders, delta);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }
    InjectionDiagnosticRecord(
        OutResult,
        HvInjectStageManualRelocate,
        HvInjectDiagnosticPhaseOperation,
        STATUS_SUCCESS,
        0);

    failureStage = HvInjectStageManualCollectImports;
    status = InjectionCollectImportModules(
        targetBase, targetHeaders, dependencyPlan);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }
    InjectionDiagnosticRecord(
        OutResult,
        HvInjectStageManualCollectImports,
        HvInjectDiagnosticPhaseOperation,
        STATUS_SUCCESS,
        dependencyPlan->Count);

    failureStage = HvInjectStageManualCollectTls;
    status = InjectionCollectTlsCallbacks(
        targetBase,
        targetHeaders,
        moduleEntry->TlsCallbacks,
        &moduleEntry->TlsCallbackCount);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }
    InjectionDiagnosticRecord(
        OutResult,
        HvInjectStageManualCollectTls,
        HvInjectDiagnosticPhaseOperation,
        STATUS_SUCCESS,
        moduleEntry->TlsCallbackCount);

    failureStage = HvInjectStageManualFindNtdll;
    ntdllBase = InjectionGetModuleBase(process, L"ntdll.dll");
    if (!ntdllBase) {
        status = STATUS_DLL_NOT_FOUND;
        goto Cleanup;
    }
    InjectionDiagnosticRecord(
        OutResult,
        HvInjectStageManualFindNtdll,
        HvInjectDiagnosticPhaseOperation,
        STATUS_SUCCESS,
        0);

    failureStage = HvInjectStageManualResolveDependencyLoader;
    if (dependencyPlan->Count != 0) {
        loadRoutine = InjectionGetProcAddress(
            process, ntdllBase, (ULONG_PTR)"LdrLoadDll", 0);
        unloadRoutine = InjectionGetProcAddress(
            process, ntdllBase, (ULONG_PTR)"LdrUnloadDll", 0);
        if (!loadRoutine || !unloadRoutine) {
            status = STATUS_PROCEDURE_NOT_FOUND;
            goto Cleanup;
        }
    }
    InjectionDiagnosticRecord(
        OutResult,
        HvInjectStageManualResolveDependencyLoader,
        HvInjectDiagnosticPhaseOperation,
        STATUS_SUCCESS,
        dependencyPlan->Count);

    failureStage = HvInjectStageManualResolveFlush;
    flushInstructionCacheRoutine = InjectionGetProcAddress(
        process,
        ntdllBase,
        (ULONG_PTR)"NtFlushInstructionCache",
        0);
    if (!flushInstructionCacheRoutine) {
        status = STATUS_PROCEDURE_NOT_FOUND;
        goto Cleanup;
    }
    InjectionDiagnosticRecord(
        OutResult,
        HvInjectStageManualResolveFlush,
        HvInjectDiagnosticPhaseOperation,
        STATUS_SUCCESS,
        0);

    exceptionDirectory = &ntHeaders->OptionalHeader.DataDirectory[
        IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    failureStage = HvInjectStageManualValidateUnwind;
    if (exceptionDirectory->VirtualAddress != 0) {
        if (exceptionDirectory->Size == 0 ||
            exceptionDirectory->Size %
                sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY_INJ) != 0) {
            status = STATUS_INVALID_IMAGE_FORMAT;
            goto Cleanup;
        }
        functionTable = (PUCHAR)targetBase +
            exceptionDirectory->VirtualAddress;
        functionTableCount = exceptionDirectory->Size /
            sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY_INJ);
        status = InjectionValidateRuntimeFunctionTable(
            functionTable, functionTableCount, ntHeaders);
        if (!NT_SUCCESS(status)) {
            goto Cleanup;
        }
        InjectionDiagnosticRecord(
            OutResult,
            HvInjectStageManualValidateUnwind,
            HvInjectDiagnosticPhaseOperation,
            STATUS_SUCCESS,
            functionTableCount);

        failureStage = HvInjectStageManualResolveUnwind;
        addFunctionTableRoutine = InjectionGetProcAddress(
            process,
            ntdllBase,
            (ULONG_PTR)"RtlAddFunctionTable",
            0);
        deleteFunctionTableRoutine = InjectionGetProcAddress(
            process,
            ntdllBase,
            (ULONG_PTR)"RtlDeleteFunctionTable",
            0);
        if (!addFunctionTableRoutine || !deleteFunctionTableRoutine) {
            status = STATUS_PROCEDURE_NOT_FOUND;
            goto Cleanup;
        }
        InjectionDiagnosticRecord(
            OutResult,
            HvInjectStageManualResolveUnwind,
            HvInjectDiagnosticPhaseOperation,
            STATUS_SUCCESS,
            functionTableCount);
    } else {
        InjectionDiagnosticRecord(
            OutResult,
            HvInjectStageManualValidateUnwind,
            HvInjectDiagnosticPhaseOperation,
            STATUS_SUCCESS,
            0);
        InjectionDiagnosticRecord(
            OutResult,
            HvInjectStageManualResolveUnwind,
            HvInjectDiagnosticPhaseOperation,
            STATUS_SUCCESS,
            0);
    }

    entryPoint = ntHeaders->OptionalHeader.AddressOfEntryPoint == 0
        ? NULL
        : (PUCHAR)targetBase +
            ntHeaders->OptionalHeader.AddressOfEntryPoint;
    moduleEntry->ProcessId = ProcessId;
    moduleEntry->ModuleBase = targetBase;
    moduleEntry->ModuleSize = imageSize;
    moduleEntry->EntryPoint = entryPoint;
    moduleEntry->FunctionTable = functionTable;
    moduleEntry->FunctionTableDeleteRoutine = deleteFunctionTableRoutine;
    moduleEntry->FunctionTableCount = functionTableCount;

    failureStage = HvInjectStageManualLoadDependencies;
    if (dependencyPlan->Count != 0) {
        HvDetachProcess(process, &apcState);
        attached = FALSE;
        process = NULL;

        status = InjectionAcquireDependencyReferences(
            ProcessId,
            moduleEntry->ProcessCreateTime,
            loadRoutine,
            unloadRoutine,
            dependencyPlan,
            moduleEntry,
            &rollbackSafe,
            OutResult);
        if (!NT_SUCCESS(status)) {
            goto Cleanup;
        }
        InjectionDiagnosticRecord(
            OutResult,
            HvInjectStageManualLoadDependencies,
            HvInjectDiagnosticPhaseOperation,
            STATUS_SUCCESS,
            dependencyPlan->Count);

        failureStage = HvInjectStageManualReattachProcess;
        status = HvAttachProcess(ProcessId, &process, &apcState);
        if (!NT_SUCCESS(status)) {
            goto Cleanup;
        }
        attached = TRUE;
        InjectionDiagnosticRecord(
            OutResult,
            HvInjectStageManualReattachProcess,
            HvInjectDiagnosticPhaseOperation,
            STATUS_SUCCESS,
            0);

        failureStage = HvInjectStageManualValidateProcessIdentity;
        if (process != processReference ||
            (UINT64)PsGetProcessCreateTimeQuadPart(process) !=
                moduleEntry->ProcessCreateTime ||
            PsGetProcessExitStatus(process) != STATUS_PENDING) {
            status = STATUS_INVALID_CID;
            goto Cleanup;
        }
        InjectionDiagnosticRecord(
            OutResult,
            HvInjectStageManualValidateProcessIdentity,
            HvInjectDiagnosticPhaseOperation,
            STATUS_SUCCESS,
            0);
    } else {
        InjectionDiagnosticRecord(
            OutResult,
            HvInjectStageManualLoadDependencies,
            HvInjectDiagnosticPhaseOperation,
            STATUS_SUCCESS,
            0);
    }

    failureStage = HvInjectStageManualResolveImports;
    status = InjectionResolveImports(process, targetBase, targetHeaders);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }
    InjectionDiagnosticRecord(
        OutResult,
        HvInjectStageManualResolveImports,
        HvInjectDiagnosticPhaseOperation,
        STATUS_SUCCESS,
        0);

    failureStage = HvInjectStageManualProtectImage;
    status = InjectionApplyImageProtections(targetBase, ntHeaders);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }
    InjectionDiagnosticRecord(
        OutResult,
        HvInjectStageManualProtectImage,
        HvInjectDiagnosticPhaseOperation,
        STATUS_SUCCESS,
        0);

    HvDetachProcess(process, &apcState);
    attached = FALSE;
    process = NULL;

    failureStage = HvInjectStageManualFlushInstructionCache;
    status = InjectionCallUserRoutine(
        ProcessId,
        moduleEntry->ProcessCreateTime,
        flushInstructionCacheRoutine,
        (PVOID)(LONG_PTR)-1,
        targetBase,
        (PVOID)imageSize,
        NULL,
        NULL,
        &rollbackSafe);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }
    InjectionDiagnosticRecord(
        OutResult,
        HvInjectStageManualFlushInstructionCache,
        HvInjectDiagnosticPhaseOperation,
        STATUS_SUCCESS,
        0);

    failureStage = HvInjectStageManualRegisterUnwind;
    if (functionTable) {
        status = InjectionCallUserRoutine(
            ProcessId,
            moduleEntry->ProcessCreateTime,
            addFunctionTableRoutine,
            functionTable,
            (PVOID)(ULONG_PTR)functionTableCount,
            targetBase,
            NULL,
            &routineResult,
            &rollbackSafe);
        if (!NT_SUCCESS(status)) {
            goto Cleanup;
        }
        if (routineResult == 0) {
            status = STATUS_INVALID_IMAGE_FORMAT;
            goto Cleanup;
        }
        moduleEntry->FunctionTableRegistered = TRUE;
    }
    InjectionDiagnosticRecord(
        OutResult,
        HvInjectStageManualRegisterUnwind,
        HvInjectDiagnosticPhaseOperation,
        STATUS_SUCCESS,
        functionTableCount);

    failureStage = HvInjectStageManualAttachTls;
    status = InjectionAttachTlsCallbacks(
        ProcessId, moduleEntry, &rollbackSafe);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }
    InjectionDiagnosticRecord(
        OutResult,
        HvInjectStageManualAttachTls,
        HvInjectDiagnosticPhaseOperation,
        STATUS_SUCCESS,
        moduleEntry->TlsAttachedCount);

    failureStage = HvInjectStageManualCallDllMain;
    if (entryPoint) {
        routineResult = 0;
        status = InjectionCallUserRoutine(
            ProcessId,
            moduleEntry->ProcessCreateTime,
            entryPoint,
            targetBase,
            (PVOID)(ULONG_PTR)1,
            NULL,
            NULL,
            &routineResult,
            &rollbackSafe);
        if (!NT_SUCCESS(status)) {
            goto Cleanup;
        }
        if (routineResult == 0) {
            status = STATUS_DLL_INIT_FAILED;
            goto Cleanup;
        }
        moduleEntry->EntryPointAttached = TRUE;
    }
    InjectionDiagnosticRecord(
        OutResult,
        HvInjectStageManualCallDllMain,
        HvInjectDiagnosticPhaseOperation,
        STATUS_SUCCESS,
        entryPoint ? 1 : 0);

    failureStage = HvInjectStageManualTrackModule;
    if (!InjectionTrackModuleEntry(moduleEntry, processReference)) {
        status = STATUS_PROCESS_IS_TERMINATING;
        goto Cleanup;
    }
    InjectionDiagnosticRecord(
        OutResult,
        HvInjectStageManualTrackModule,
        HvInjectDiagnosticPhaseOperation,
        STATUS_SUCCESS,
        0);
    if (OutResult) {
        OutResult->Diagnostics.Flags |=
            HV_INJECTION_DIAG_FLAG_MODULE_TRACKED;
    }

    if (OutResult) {
        OutResult->Status = STATUS_SUCCESS;
        OutResult->ModuleBase = targetBase;
        OutResult->ModuleSize = imageSize;
        OutResult->EntryPointAddress = entryPoint;
    }
    moduleEntry = NULL;
    status = STATUS_SUCCESS;
    goto Exit;

Cleanup:
    InjectionDiagnosticFailure(
        OutResult, failureStage, status, 0);

    if (attached) {
        HvDetachProcess(process, &apcState);
        attached = FALSE;
        process = NULL;
    }

    if (moduleEntry && targetBase && processReference &&
        PsGetProcessExitStatus(processReference) == STATUS_PENDING) {
        if (moduleEntry->EntryPointAttached) {
            cleanupStatus = InjectionCallUserRoutine(
                ProcessId,
                moduleEntry->ProcessCreateTime,
                moduleEntry->EntryPoint,
                targetBase,
                NULL,
                NULL,
                NULL,
                NULL,
                &rollbackSafe);
            InjectionDiagnosticCleanup(
                OutResult,
                HvInjectStageCleanupDllMain,
                cleanupStatus,
                0);
            if (NT_SUCCESS(cleanupStatus)) {
                moduleEntry->EntryPointAttached = FALSE;
            }
        }
        if (!moduleEntry->EntryPointAttached && moduleEntry->TlsAttached) {
            cleanupStatus = InjectionDetachTlsCallbacks(
                ProcessId, moduleEntry, &rollbackSafe);
            InjectionDiagnosticCleanup(
                OutResult,
                HvInjectStageCleanupTls,
                cleanupStatus,
                moduleEntry->TlsDetachIndex);
        }
        if (!moduleEntry->EntryPointAttached &&
            !moduleEntry->TlsAttached &&
            moduleEntry->FunctionTableRegistered) {
            routineResult = 0;
            cleanupStatus = InjectionCallUserRoutine(
                ProcessId,
                moduleEntry->ProcessCreateTime,
                moduleEntry->FunctionTableDeleteRoutine,
                moduleEntry->FunctionTable,
                NULL,
                NULL,
                NULL,
                &routineResult,
                &rollbackSafe);
            if (NT_SUCCESS(cleanupStatus) && routineResult != 0) {
                moduleEntry->FunctionTableRegistered = FALSE;
            } else if (NT_SUCCESS(cleanupStatus)) {
                cleanupStatus = STATUS_UNSUCCESSFUL;
            }
            InjectionDiagnosticCleanup(
                OutResult,
                HvInjectStageCleanupUnwind,
                cleanupStatus,
                functionTableCount);
        }
        if (!moduleEntry->EntryPointAttached &&
            !moduleEntry->TlsAttached &&
            !moduleEntry->FunctionTableRegistered &&
            moduleEntry->DependencyCount != 0 &&
            rollbackSafe) {
            cleanupStatus = InjectionReleaseDependencyReferences(
                ProcessId,
                moduleEntry,
                &rollbackSafe,
                dependencyPlan,
                OutResult);
            if (!NT_SUCCESS(cleanupStatus)) {
                DbgPrint("[Injection] Dependency cleanup failed: 0x%X\n",
                    cleanupStatus);
            }
        }
    }

    if (!rollbackSafe && moduleEntry) {
        moduleEntry->UnsafeToUnload = TRUE;
        if (OutResult) {
            OutResult->Diagnostics.Flags |=
                HV_INJECTION_DIAG_FLAG_ROLLBACK_UNSAFE;
        }
    }
    if (targetBase && processReference &&
        PsGetProcessExitStatus(processReference) != STATUS_PENDING) {
        if (OutResult) {
            OutResult->Diagnostics.Flags |=
                HV_INJECTION_DIAG_FLAG_PROCESS_EXITED;
        }
        InjectionDiagnosticRecord(
            OutResult,
            HvInjectStageCleanupImage,
            HvInjectDiagnosticPhaseWarning,
            STATUS_PROCESS_IS_TERMINATING,
            0);
        targetBase = NULL;
    }
    if (targetBase && moduleEntry && rollbackSafe &&
        !moduleEntry->EntryPointAttached &&
        !moduleEntry->TlsAttached &&
        !moduleEntry->FunctionTableRegistered &&
        moduleEntry->DependencyCount == 0) {
        cleanupStatus = InjectionMemoryFreeCore(ProcessId, targetBase);
        InjectionDiagnosticCleanup(
            OutResult,
            HvInjectStageCleanupImage,
            cleanupStatus,
            0);
        if (NT_SUCCESS(cleanupStatus)) {
            targetBase = NULL;
        }
    }
    if (targetBase && moduleEntry && processReference) {
        if (InjectionTrackModuleEntry(moduleEntry, processReference)) {
            InjectionDiagnosticCleanup(
                OutResult,
                HvInjectStageCleanupTrackRetained,
                STATUS_SUCCESS,
                0);
            if (OutResult) {
                OutResult->ModuleBase = targetBase;
                OutResult->ModuleSize = imageSize;
                OutResult->EntryPointAddress = entryPoint;
                OutResult->Diagnostics.Flags |=
                    HV_INJECTION_DIAG_FLAG_MAPPING_RETAINED |
                    HV_INJECTION_DIAG_FLAG_MODULE_TRACKED;
                if (moduleEntry->DependencyCount != 0) {
                    OutResult->Diagnostics.Flags |=
                        HV_INJECTION_DIAG_FLAG_DEPENDENCIES_RETAINED;
                }
            }
            moduleEntry = NULL;
        } else {
            InjectionDiagnosticCleanup(
                OutResult,
                HvInjectStageCleanupTrackRetained,
                STATUS_PROCESS_IS_TERMINATING,
                0);
        }
    }
    if (targetBase && OutResult) {
        OutResult->Diagnostics.Flags |=
            HV_INJECTION_DIAG_FLAG_MAPPING_RETAINED;
        if (moduleEntry && moduleEntry->DependencyCount != 0) {
            OutResult->Diagnostics.Flags |=
                HV_INJECTION_DIAG_FLAG_DEPENDENCIES_RETAINED;
        }
    }

Exit:
    if (OutResult) {
        if (!rollbackSafe) {
            OutResult->Diagnostics.Flags |=
                HV_INJECTION_DIAG_FLAG_ROLLBACK_UNSAFE;
        }
        if (!NT_SUCCESS(status) &&
            OutResult->Diagnostics.PrimaryStage == HvInjectStageNone) {
            InjectionDiagnosticFailure(
                OutResult, failureStage, status, 0);
        }
        OutResult->Status = status;
    }
    if (moduleEntry) {
        ExFreePoolWithTag(moduleEntry, HV_INJECTION_TAG);
    }
    if (dependencyPlan) {
        ExFreePoolWithTag(dependencyPlan, HV_INJECTION_TAG);
    }
    if (processReference) {
        ObDereferenceObject(processReference);
    }
    return status;
}

NTSTATUS
HvInjectDll(
    _In_ ULONG ProcessId,
    _In_ PVOID DllBuffer,
    _In_ SIZE_T DllSize,
    _Out_opt_ PHV_INJECTION_RESULT OutResult
)
{
    NTSTATUS status;

    InjectionDiagnosticInitialize(
        OutResult, HV_INJECTION_DIAG_FLAG_MANUAL_MAP);

    if (!InjectionIsOpen()) {
        status = HvInjectionInitialize();
        if (!NT_SUCCESS(status)) {
            InjectionDiagnosticFailure(
                OutResult,
                HvInjectStageManagerInitialize,
                status,
                0);
            InjectionDiagnosticFinalize(
                OutResult, status, HvInjectStageManagerInitialize);
            return status;
        }
    }

    InjectionDiagnosticRecord(
        OutResult,
        HvInjectStageManagerInitialize,
        HvInjectDiagnosticPhaseOperation,
        STATUS_SUCCESS,
        0);

    status = InjectionOperationAcquire();
    if (!NT_SUCCESS(status)) {
        InjectionDiagnosticFailure(
            OutResult,
            HvInjectStageOperationAcquire,
            status,
            0);
        InjectionDiagnosticFinalize(
            OutResult, status, HvInjectStageOperationAcquire);
        return status;
    }
    InjectionDiagnosticRecord(
        OutResult,
        HvInjectStageOperationAcquire,
        HvInjectDiagnosticPhaseOperation,
        STATUS_SUCCESS,
        0);
    status = InjectionInjectDllCore(
        ProcessId, DllBuffer, DllSize, NULL, OutResult);
    InjectionOperationRelease();
    InjectionDiagnosticFinalize(
        OutResult, status, HvInjectStageManualValidateInput);
    return status;
}

#if 0
static NTSTATUS
InjectionUnloadInjectedDllCoreLegacy(
    _In_ ULONG ProcessId,
    _In_ PVOID ModuleBase
)
{
    PINJECTED_MODULE_ENTRY moduleEntry;
    PEPROCESS process = NULL;
    UINT64 createTime;
    NTSTATUS status;

    status = PsLookupProcessByProcessId(
        (HANDLE)(ULONG_PTR)ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    createTime = (UINT64)PsGetProcessCreateTimeQuadPart(process);
    if (createTime == 0) {
        ObDereferenceObject(process);
        return STATUS_INVALID_CID;
    }

    /* Claim by unlinking under the list lock.  No unlocked raw pointer remains
     * visible to hide/unhide, process-exit cleanup, or manager cleanup while
     * the Windows allocation release runs. */
    moduleEntry = InjectionClaimModule(
        ProcessId, createTime, ModuleBase);
    if (!moduleEntry) {
        ObDereferenceObject(process);
        return STATUS_NOT_FOUND;
    }
    
    // 释放内存
    status = InjectionMemoryFreeCore(ProcessId, ModuleBase);
    if (!NT_SUCCESS(status)) {
        if (InterlockedCompareExchange(
                &g_InjectionListsInitialized, 0, 0) != 0 &&
            PsGetProcessExitStatus(process) == STATUS_PENDING) {
            InjectionRestoreClaimedModule(moduleEntry);
        } else {
            ExFreePoolWithTag(moduleEntry, HV_INJECTION_TAG);
        }
        ObDereferenceObject(process);
        return status;
    }

    ExFreePoolWithTag(moduleEntry, HV_INJECTION_TAG);
    ObDereferenceObject(process);
    return status;
}

#endif

static NTSTATUS
InjectionUnloadInjectedDllCore(
    _In_ ULONG ProcessId,
    _In_ PVOID ModuleBase
)
{
    PINJECTED_MODULE_ENTRY moduleEntry;
    PEPROCESS process = NULL;
    UINT64 createTime;
    ULONGLONG routineResult = 0;
    NTSTATUS status;
    BOOLEAN rollbackSafe = TRUE;

    status = PsLookupProcessByProcessId(
        (HANDLE)(ULONG_PTR)ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    createTime = (UINT64)PsGetProcessCreateTimeQuadPart(process);
    if (createTime == 0) {
        ObDereferenceObject(process);
        return STATUS_INVALID_CID;
    }

    moduleEntry = InjectionClaimModule(
        ProcessId, createTime, ModuleBase);
    if (!moduleEntry) {
        ObDereferenceObject(process);
        return STATUS_NOT_FOUND;
    }

    if (PsGetProcessExitStatus(process) != STATUS_PENDING) {
        ExFreePoolWithTag(moduleEntry, HV_INJECTION_TAG);
        ObDereferenceObject(process);
        return STATUS_SUCCESS;
    }
    if (moduleEntry->UnsafeToUnload) {
        status = STATUS_DEVICE_BUSY;
        goto Restore;
    }
    if (moduleEntry->LoaderManaged) {
        if (!moduleEntry->LoaderUnloadRoutine) {
            status = STATUS_INVALID_DEVICE_STATE;
            goto Restore;
        }
        status = InjectionCallUserRoutine(
            ProcessId,
            moduleEntry->ProcessCreateTime,
            moduleEntry->LoaderUnloadRoutine,
            moduleEntry->ModuleBase,
            NULL,
            NULL,
            NULL,
            &routineResult,
            &rollbackSafe);
        if (!NT_SUCCESS(status)) {
            goto Restore;
        }
        status = (NTSTATUS)(ULONG)routineResult;
        if (!NT_SUCCESS(status)) {
            goto Restore;
        }
        ExFreePoolWithTag(moduleEntry, HV_INJECTION_TAG);
        ObDereferenceObject(process);
        return STATUS_SUCCESS;
    }

    if (moduleEntry->EntryPointAttached) {
        status = InjectionCallUserRoutine(
            ProcessId,
            moduleEntry->ProcessCreateTime,
            moduleEntry->EntryPoint,
            moduleEntry->ModuleBase,
            NULL,
            NULL,
            NULL,
            NULL,
            &rollbackSafe);
        if (!NT_SUCCESS(status)) {
            goto Restore;
        }
        moduleEntry->EntryPointAttached = FALSE;
    }

    if (moduleEntry->TlsAttached) {
        status = InjectionDetachTlsCallbacks(
            ProcessId, moduleEntry, &rollbackSafe);
        if (!NT_SUCCESS(status)) {
            goto Restore;
        }
    }

    if (moduleEntry->FunctionTableRegistered) {
        if (!moduleEntry->FunctionTableDeleteRoutine ||
            !moduleEntry->FunctionTable) {
            status = STATUS_INVALID_DEVICE_STATE;
            goto Restore;
        }
        status = InjectionCallUserRoutine(
            ProcessId,
            moduleEntry->ProcessCreateTime,
            moduleEntry->FunctionTableDeleteRoutine,
            moduleEntry->FunctionTable,
            NULL,
            NULL,
            NULL,
            &routineResult,
            &rollbackSafe);
        if (!NT_SUCCESS(status)) {
            goto Restore;
        }
        if (routineResult == 0) {
            status = STATUS_UNSUCCESSFUL;
            goto Restore;
        }
        moduleEntry->FunctionTableRegistered = FALSE;
    }

    if (moduleEntry->DependencyCount != 0) {
        status = InjectionReleaseDependencyReferences(
            ProcessId,
            moduleEntry,
            &rollbackSafe,
            NULL,
            NULL);
        if (!NT_SUCCESS(status)) {
            goto Restore;
        }
    }

    status = InjectionMemoryFreeCore(ProcessId, ModuleBase);
    if (!NT_SUCCESS(status)) {
        if (PsGetProcessExitStatus(process) != STATUS_PENDING) {
            status = STATUS_SUCCESS;
        } else {
            goto Restore;
        }
    }

    ExFreePoolWithTag(moduleEntry, HV_INJECTION_TAG);
    ObDereferenceObject(process);
    return status;

Restore:
    if (!rollbackSafe) {
        moduleEntry->UnsafeToUnload = TRUE;
    }
    if (InterlockedCompareExchange(
            &g_InjectionListsInitialized, 0, 0) != 0 &&
        PsGetProcessExitStatus(process) == STATUS_PENDING) {
        InjectionRestoreClaimedModule(moduleEntry);
    } else {
        ExFreePoolWithTag(moduleEntry, HV_INJECTION_TAG);
    }
    ObDereferenceObject(process);
    return status;
}

NTSTATUS
HvUnloadInjectedDll(
    _In_ ULONG ProcessId,
    _In_ PVOID ModuleBase
)
{
    NTSTATUS status = InjectionOperationAcquire();
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = InjectionUnloadInjectedDllCore(ProcessId, ModuleBase);
    InjectionOperationRelease();
    return status;
}

// ============================================================
// Shellcode 注入
// ============================================================

static NTSTATUS
InjectionInjectShellcodeCore(
    _In_ ULONG ProcessId,
    _In_ PVOID Shellcode,
    _In_ SIZE_T Size,
    _In_opt_ PVOID Parameter,
    _Out_opt_ PVOID* OutAddress
)
{
    NTSTATUS status;
    PVOID targetAddress = NULL;

    if (OutAddress) {
        *OutAddress = NULL;
    }
    if (!InjectionApcExecutionAvailable()) {
        return STATUS_NOT_SUPPORTED;
    }

    DbgPrint("[Injection] Injecting shellcode, PID=%d, Size=0x%llX\n", 
        ProcessId, (ULONGLONG)Size);
    
    // 分配内存
    status = InjectionMemoryAllocateCore(
        ProcessId, Size, PAGE_EXECUTE_READWRITE, &targetAddress);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    
    // 写入 Shellcode
    status = HvMemoryWrite(ProcessId, targetAddress, Shellcode, Size, NULL);
    if (!NT_SUCCESS(status)) {
        (void)InjectionMemoryFreeCore(ProcessId, targetAddress);
        return status;
    }
    status = HvMemoryProtect(
        ProcessId,
        targetAddress,
        Size,
        PAGE_EXECUTE_READ,
        NULL);
    if (!NT_SUCCESS(status)) {
        (void)InjectionMemoryFreeCore(ProcessId, targetAddress);
        return status;
    }
    
    DbgPrint("[Injection] Shellcode written at %p\n", targetAddress);
    
    // 执行（通过 APC）
    status = InjectionQueueUserApcCore(
        ProcessId, 0, targetAddress, Parameter, FALSE);
    if (!NT_SUCCESS(status)) {
        (void)InjectionMemoryFreeCore(ProcessId, targetAddress);
        return status;
    }

    if (OutAddress) {
        *OutAddress = targetAddress;
    }

    return STATUS_SUCCESS;
}

NTSTATUS
HvInjectShellcode(
    _In_ ULONG ProcessId,
    _In_ PVOID Shellcode,
    _In_ SIZE_T Size,
    _In_opt_ PVOID Parameter,
    _Out_opt_ PVOID* OutAddress
)
{
    NTSTATUS status = InjectionOperationAcquire();
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = InjectionInjectShellcodeCore(
        ProcessId, Shellcode, Size, Parameter, OutAddress);
    InjectionOperationRelease();
    return status;
}

static NTSTATUS
InjectionInjectShellcodeNoExecuteCore(
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
    status = InjectionMemoryAllocateCore(
        ProcessId, Size, PAGE_EXECUTE_READWRITE, &targetAddress);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    
    // 写入 Shellcode
    status = HvMemoryWrite(ProcessId, targetAddress, Shellcode, Size, NULL);
    if (!NT_SUCCESS(status)) {
        (void)InjectionMemoryFreeCore(ProcessId, targetAddress);
        return status;
    }

    *OutAddress = targetAddress;

    DbgPrint("[Injection] Shellcode injected (no execute) at %p\n", targetAddress);

    return STATUS_SUCCESS;
}

NTSTATUS
HvInjectShellcodeNoExecute(
    _In_ ULONG ProcessId,
    _In_ PVOID Shellcode,
    _In_ SIZE_T Size,
    _Out_ PVOID* OutAddress
)
{
    NTSTATUS status = InjectionOperationAcquire();
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = InjectionInjectShellcodeNoExecuteCore(
        ProcessId, Shellcode, Size, OutAddress);
    InjectionOperationRelease();
    return status;
}

static NTSTATUS
InjectionExecuteShellcodeCore(
    _In_ ULONG ProcessId,
    _In_ PVOID Address,
    _In_opt_ PVOID Parameter,
    _In_ HV_EXECUTION_METHOD ExecMethod
)
{
    switch (ExecMethod) {
        case HvExecMethodApc:
            return InjectionQueueUserApcCore(
                ProcessId, 0, Address, Parameter, FALSE);
            
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

NTSTATUS
HvExecuteShellcode(
    _In_ ULONG ProcessId,
    _In_ PVOID Address,
    _In_opt_ PVOID Parameter,
    _In_ HV_EXECUTION_METHOD ExecMethod
)
{
    NTSTATUS status = InjectionOperationAcquire();
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = InjectionExecuteShellcodeCore(
        ProcessId, Address, Parameter, ExecMethod);
    InjectionOperationRelease();
    return status;
}

// ============================================================
// APC 执行引擎
// ============================================================

// APC 内核例程
static VOID
InjectionPendingApcDereference(
    _Inout_ PHV_INJECTION_PENDING_APC PendingApc
)
{
    if (InterlockedDecrement(&PendingApc->References) == 0) {
        ExFreePoolWithTag(PendingApc, HV_INJECTION_TAG);
    }
}

static VOID
InjectionPendingApcReference(
    _Inout_ PHV_INJECTION_PENDING_APC PendingApc
)
{
    InterlockedIncrement(&PendingApc->References);
}

static VOID
InjectionCompletePendingApc(
    _Inout_ PHV_INJECTION_PENDING_APC PendingApc
)
{
    KIRQL oldIrql;
    PETHREAD thread;
    BOOLEAN releaseRundown = FALSE;

    if (InterlockedCompareExchange(
            &PendingApc->CompletionClaimed, 1, 0) != 0) {
        return;
    }

    if (InterlockedCompareExchange(
            &g_InjectionPendingApcInitialized, 0, 0) != 0) {
        KeAcquireSpinLock(&g_InjectionPendingApcLock, &oldIrql);
        if (InterlockedCompareExchange(&PendingApc->Listed, 0, 1) == 1) {
            RemoveEntryList(&PendingApc->ListEntry);
            if (InterlockedCompareExchange(
                    &g_InjectionPendingApcCount, 0, 0) != 0) {
                InterlockedDecrement(&g_InjectionPendingApcCount);
            }
        }
        KeReleaseSpinLock(&g_InjectionPendingApcLock, oldIrql);
    }

    thread = (PETHREAD)InterlockedExchangePointer(
        (PVOID volatile*)&PendingApc->Thread, NULL);
    if (thread) {
        ObDereferenceObject(thread);
    }

    if (InterlockedExchange(&PendingApc->RundownHeld, 0) != 0) {
        releaseRundown = TRUE;
    }

    KeSetEvent(&PendingApc->CompletionEvent, IO_NO_INCREMENT, FALSE);
    InjectionPendingApcDereference(PendingApc);
    if (releaseRundown) {
        ExReleaseRundownProtection(&g_InjectionOperationRundown);
    }
}

static BOOLEAN
InjectionCancelPendingApc(
    _Inout_ PHV_INJECTION_PENDING_APC PendingApc
)
{
    if (!PendingApc || !g_KeRemoveQueueApc) {
        return FALSE;
    }

    InterlockedExchange(&PendingApc->CancelRequested, 1);
    if (g_KeRemoveQueueApc(&PendingApc->Apc)) {
        InjectionCompletePendingApc(PendingApc);
        return TRUE;
    }
    return FALSE;
}

static VOID
InjectionCancelPendingApcs(VOID)
{
    if (InterlockedCompareExchange(
            &g_InjectionPendingApcInitialized, 0, 0) == 0) {
        return;
    }

    if (!g_KeRemoveQueueApc) {
        if (InterlockedCompareExchange(
                &g_InjectionPendingApcCount, 0, 0) != 0) {
            DbgPrint("[Injection] Pending APC invariant violated without KeRemoveQueueApc\n");
        }
        return;
    }

    for (;;) {
        PHV_INJECTION_PENDING_APC pendingApc = NULL;
        PLIST_ENTRY entry;
        KIRQL oldIrql;

        KeAcquireSpinLock(&g_InjectionPendingApcLock, &oldIrql);
        for (entry = g_InjectionPendingApcList.Flink;
             entry != &g_InjectionPendingApcList;
             entry = entry->Flink) {
            PHV_INJECTION_PENDING_APC candidate = CONTAINING_RECORD(
                entry, HV_INJECTION_PENDING_APC, ListEntry);
            if (InterlockedCompareExchange(
                    &candidate->CancelRequested, 1, 0) == 0) {
                InterlockedIncrement(&candidate->References);
                pendingApc = candidate;
                break;
            }
        }
        KeReleaseSpinLock(&g_InjectionPendingApcLock, oldIrql);

        if (!pendingApc) {
            break;
        }

        if (g_KeRemoveQueueApc(&pendingApc->Apc)) {
            InjectionCompletePendingApc(pendingApc);
        }
        InjectionPendingApcDereference(pendingApc);
    }
}

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
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);
    
    // 释放 APC 结构
    if (Apc) {
        PHV_INJECTION_PENDING_APC pendingApc = CONTAINING_RECORD(
            Apc, HV_INJECTION_PENDING_APC, Apc);
        InterlockedExchange(&pendingApc->KernelRoutineEntered, 1);
        if (NormalRoutine) {
            if (InterlockedCompareExchange(&g_InjectionClosing, 0, 0) != 0 ||
                PsIsThreadTerminating(PsGetCurrentThread())) {
                *NormalRoutine = NULL;
            } else if (PsGetProcessWow64Process(PsGetCurrentProcess()) != NULL) {
                if (!g_PsWrapApcWow64Thread || !NormalContext ||
                    !NT_SUCCESS(g_PsWrapApcWow64Thread(
                        NormalContext, (PVOID*)NormalRoutine))) {
                    *NormalRoutine = NULL;
                }
            }
            if (*NormalRoutine != NULL) {
                InterlockedExchange(
                    &pendingApc->UserRoutineDispatched, 1);
            }
        }
        InjectionCompletePendingApc(pendingApc);
    }
}

static VOID
NTAPI
ApcForceDeliveryKernelRoutine(
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

    if (Apc) {
        PHV_INJECTION_PENDING_APC pendingApc = CONTAINING_RECORD(
            Apc, HV_INJECTION_PENDING_APC, Apc);
        InterlockedExchange(&pendingApc->KernelRoutineEntered, 1);
        if (InterlockedCompareExchange(&g_InjectionClosing, 0, 0) == 0 &&
            g_KeTestAlertThread) {
            (void)g_KeTestAlertThread(UserMode);
        }
        InjectionCompletePendingApc(pendingApc);
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
        InjectionCompletePendingApc(CONTAINING_RECORD(
            Apc, HV_INJECTION_PENDING_APC, Apc));
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
    if (!g_PsGetThreadProcess) {
        return STATUS_NOT_SUPPORTED;
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
            if (returnLength <= bufferSize ||
                returnLength > HV_INJECTION_MAX_PROCESS_INFO - 0x1000) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }
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
                        if (!PsIsThreadTerminating(thread) &&
                            g_PsGetThreadProcess(thread) == Process) {
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

static NTSTATUS
InjectionQueueUserApcCore(
    _In_ ULONG ProcessId,
    _In_ ULONG ThreadId,
    _In_ PVOID ApcRoutine,
    _In_opt_ PVOID ApcContext,
    _In_ BOOLEAN WaitComplete
)
{
    return InjectionQueueUserApcExCore(
        ProcessId,
        ThreadId,
        ApcRoutine,
        ApcContext,
        NULL,
        NULL,
        WaitComplete);
}

static NTSTATUS
InjectionQueueUserApcExCore(
    _In_ ULONG ProcessId,
    _In_ ULONG ThreadId,
    _In_ PVOID ApcRoutine,
    _In_opt_ PVOID ApcContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2,
    _In_ BOOLEAN WaitComplete
)
{
    NTSTATUS status;
    NTSTATUS forceStatus;
    PEPROCESS process = NULL;
    PETHREAD thread = NULL;
    PHV_INJECTION_PENDING_APC pendingApc = NULL;
    BOOLEAN canceled;
    
    if (ProcessId == 0 || !ApcRoutine) {
        return STATUS_INVALID_PARAMETER;
    }
    if (WaitComplete) {
        return STATUS_NOT_SUPPORTED;
    }

    /* A driver-owned KAPC must be removable during unload.  Win10 builds
     * that do not export KeRemoveQueueApc can still load and use the rest of
     * the driver, but must not admit an APC that could retain driver code. */
    if (!InjectionApcExecutionAvailable()) {
        return STATUS_NOT_SUPPORTED;
    }
    
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
    
    if (PsGetThreadProcessId(thread) != (HANDLE)(ULONG_PTR)ProcessId ||
        g_PsGetThreadProcess(thread) != process) {
        ObDereferenceObject(thread);
        ObDereferenceObject(process);
        return STATUS_INVALID_CID;
    }

    if (PsGetProcessWow64Process(process) != NULL &&
        !g_PsWrapApcWow64Thread) {
        ObDereferenceObject(thread);
        ObDereferenceObject(process);
        return STATUS_NOT_SUPPORTED;
    }

    status = InjectionQueueKernelApc(
        thread,
        (PVOID)ApcKernelRoutine,
        (PVOID)ApcRoutine,
        UserMode,
        ApcContext,
        SystemArgument1,
        SystemArgument2,
        &pendingApc);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

    /* Match Unreal's delivery preparation: a kernel APC alerts the selected
     * thread in UserMode after the real user APC has been queued. */
    forceStatus = InjectionQueueKernelApc(
        thread,
        (PVOID)ApcForceDeliveryKernelRoutine,
        NULL,
        KernelMode,
        NULL,
        NULL,
        NULL,
        NULL);
    if (!NT_SUCCESS(forceStatus)) {
        canceled = InjectionCancelPendingApc(pendingApc);
        if (canceled) {
            status = forceStatus;
            DbgPrint("[Injection] Force-delivery APC failed and user APC was canceled: 0x%X\n",
                forceStatus);
        } else {
            /* KeRemoveQueueApc returning FALSE means delivery already won the
             * race; report the admitted user APC rather than a false failure. */
            status = STATUS_SUCCESS;
        }
    }

Exit:
    if (pendingApc) {
        InjectionPendingApcDereference(pendingApc);
    }
    if (thread) {
        ObDereferenceObject(thread);
    }
    if (process) {
        ObDereferenceObject(process);
    }

    if (NT_SUCCESS(status)) {
        DbgPrint("[Injection] APC queued with force delivery\n");
    }
    return status;
}

// ============================================================
// 内核态无痕隐藏功能
// ============================================================

// 注意: g_HiddenMemory* 变量已在文件顶部定义

// NtQueryVirtualMemory Hook 相关
static PVOID g_NtQueryVirtualMemoryHook = NULL;
static PVOID g_OriginalNtQueryVirtualMemory = NULL;
static EX_PUSH_LOCK g_MemoryHideHookLock = 0;

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
static BOOLEAN
FindHiddenMemorySnapshot(
    _In_ ULONG ProcessId,
    _In_ UINT64 ProcessCreateTime,
    _In_ PVOID Address,
    _Out_opt_ PHIDDEN_MEMORY_ENTRY Snapshot
)
{
    PLIST_ENTRY entry;
    PHIDDEN_MEMORY_ENTRY memEntry;
    KIRQL oldIrql;
    BOOLEAN found = FALSE;
    
    if (!g_HiddenMemoryInitialized) {
        return FALSE;
    }
    
    KeAcquireSpinLock(&g_HiddenMemoryLock, &oldIrql);
    
    for (entry = g_HiddenMemoryList.Flink;
         entry != &g_HiddenMemoryList;
         entry = entry->Flink)
    {
        memEntry = CONTAINING_RECORD(entry, HIDDEN_MEMORY_ENTRY, ListEntry);
        
        if (memEntry->ProcessId == ProcessId &&
            (ProcessCreateTime == 0 ||
             memEntry->ProcessCreateTime == ProcessCreateTime)) {
            ULONG_PTR start = (ULONG_PTR)memEntry->BaseAddress;
            ULONG_PTR end = start + memEntry->RegionSize;
            ULONG_PTR addr = (ULONG_PTR)Address;
            
            if (addr >= start && addr < end) {
                if (Snapshot) {
                    RtlCopyMemory(Snapshot, memEntry, sizeof(*Snapshot));
                    Snapshot->ListEntry.Flink = NULL;
                    Snapshot->ListEntry.Blink = NULL;
                }
                found = TRUE;
                break;
            }
        }
    }
    
    KeReleaseSpinLock(&g_HiddenMemoryLock, oldIrql);
    
    return found;
}

static NTSTATUS
InjectionQueueKernelApc(
    _In_ PETHREAD Thread,
    _In_ PVOID KernelRoutine,
    _In_opt_ PVOID NormalRoutine,
    _In_ KPROCESSOR_MODE ProcessorMode,
    _In_opt_ PVOID NormalContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2,
    _Outptr_opt_result_maybenull_ PHV_INJECTION_PENDING_APC* OutPendingApc
)
{
    NTSTATUS status;
    PHV_INJECTION_PENDING_APC pendingApc;
    KIRQL oldIrql;
    BOOLEAN inserted = FALSE;

    if (OutPendingApc) {
        *OutPendingApc = NULL;
    }

    status = InjectionOperationAcquire();
    if (!NT_SUCCESS(status)) {
        return status;
    }

    pendingApc = (PHV_INJECTION_PENDING_APC)HvAllocateNonPagedZeroed(
        sizeof(HV_INJECTION_PENDING_APC), HV_INJECTION_TAG);
    if (!pendingApc) {
        InjectionOperationRelease();
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    pendingApc->References = 1;
    pendingApc->RundownHeld = 1;
    pendingApc->Thread = Thread;
    KeInitializeEvent(
        &pendingApc->CompletionEvent, NotificationEvent, FALSE);
    ObReferenceObject(Thread);

    if (OutPendingApc) {
        InjectionPendingApcReference(pendingApc);
        *OutPendingApc = pendingApc;
    }

    KeInitializeApc(
        &pendingApc->Apc,
        (PRKTHREAD)Thread,
        OriginalApcEnvironmentInj,
        KernelRoutine,
        (PVOID)ApcRundownRoutine,
        NormalRoutine,
        ProcessorMode,
        NormalContext);

    KeAcquireSpinLock(&g_InjectionPendingApcLock, &oldIrql);
    if (InterlockedCompareExchange(&g_InjectionClosing, 0, 0) == 0) {
        InsertTailList(
            &g_InjectionPendingApcList,
            &pendingApc->ListEntry);
        InterlockedExchange(&pendingApc->Listed, 1);
        InterlockedIncrement(&g_InjectionPendingApcCount);
        inserted = KeInsertQueueApc(
            &pendingApc->Apc,
            SystemArgument1,
            SystemArgument2,
            0);
        if (!inserted &&
            InterlockedCompareExchange(&pendingApc->Listed, 0, 1) == 1) {
            RemoveEntryList(&pendingApc->ListEntry);
            InterlockedDecrement(&g_InjectionPendingApcCount);
        }
    }
    KeReleaseSpinLock(&g_InjectionPendingApcLock, oldIrql);

    if (!inserted) {
        status = InterlockedCompareExchange(&g_InjectionClosing, 0, 0) != 0
            ? STATUS_DELETE_PENDING
            : STATUS_UNSUCCESSFUL;
        InjectionCompletePendingApc(pendingApc);
        if (OutPendingApc) {
            InjectionPendingApcDereference(*OutPendingApc);
            *OutPendingApc = NULL;
        }
        return status;
    }

    return STATUS_SUCCESS;
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
    NTSTATUS status = InjectionOperationAcquire();
    BOOLEAN hidden;

    if (!NT_SUCCESS(status)) {
        return FALSE;
    }
    hidden = FindHiddenMemorySnapshot(ProcessId, 0, Address, NULL);
    InjectionOperationRelease();
    return hidden;
}

/*
 * 添加内存区域到隐藏列表
 */
static NTSTATUS
InjectionAddHiddenMemoryRegionCore(
    _In_ ULONG ProcessId,
    _In_ PVOID Address,
    _In_ SIZE_T Size,
    _In_ ULONG HideMode
)
{
    PHIDDEN_MEMORY_ENTRY memEntry;
    KIRQL oldIrql;
    PEPROCESS process = NULL;
    UINT64 createTime;
    NTSTATUS status;
    
    if (!g_HiddenMemoryInitialized ||
        ProcessId == 0 || Address == NULL || Size == 0 ||
        KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    status = PsLookupProcessByProcessId(
        (HANDLE)(ULONG_PTR)ProcessId, &process);
    if (!NT_SUCCESS(status) || !process) {
        return NT_SUCCESS(status) ? STATUS_INVALID_CID : status;
    }
    createTime = (UINT64)PsGetProcessCreateTimeQuadPart(process);
    ObDereferenceObject(process);
    if (createTime == 0) return STATUS_INVALID_CID;
    
    // 分配条目
    memEntry = (PHIDDEN_MEMORY_ENTRY)HvAllocateNonPagedZeroed(
        sizeof(HIDDEN_MEMORY_ENTRY), HV_INJECTION_TAG);
    
    if (!memEntry) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    memEntry->ProcessId = ProcessId;
    memEntry->ProcessCreateTime = createTime;
    memEntry->BaseAddress = Address;
    memEntry->RegionSize = Size;
    memEntry->HideMode = HideMode;
    
    // Duplicate detection, capacity accounting and publication are one
    // transaction under the list lock.  Returning an unlocked entry pointer
    // here used to race query/remove and caused a use-after-free.
    KeAcquireSpinLock(&g_HiddenMemoryLock, &oldIrql);
    for (PLIST_ENTRY entry = g_HiddenMemoryList.Flink;
         entry != &g_HiddenMemoryList;
         entry = entry->Flink) {
        PHIDDEN_MEMORY_ENTRY existing = CONTAINING_RECORD(
            entry, HIDDEN_MEMORY_ENTRY, ListEntry);
        ULONG_PTR start = (ULONG_PTR)existing->BaseAddress;
        ULONG_PTR end = start + existing->RegionSize;
        ULONG_PTR address = (ULONG_PTR)Address;
        if (existing->ProcessId == ProcessId &&
            address >= start && address < end) {
            existing->HideMode |= HideMode;
            KeReleaseSpinLock(&g_HiddenMemoryLock, oldIrql);
            ExFreePoolWithTag(memEntry, HV_INJECTION_TAG);
            return STATUS_SUCCESS;
        }
    }
    if (g_HiddenMemoryCount >= MAX_HIDDEN_MEMORY_REGIONS) {
        KeReleaseSpinLock(&g_HiddenMemoryLock, oldIrql);
        ExFreePoolWithTag(memEntry, HV_INJECTION_TAG);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
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
HvAddHiddenMemoryRegion(
    _In_ ULONG ProcessId,
    _In_ PVOID Address,
    _In_ SIZE_T Size,
    _In_ ULONG HideMode
)
{
    NTSTATUS status = InjectionOperationAcquire();
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = InjectionAddHiddenMemoryRegionCore(
        ProcessId, Address, Size, HideMode);
    InjectionOperationRelease();
    return status;
}

static NTSTATUS
InjectionRemoveHiddenMemoryRegionCore(
    _In_ ULONG ProcessId,
    _In_ PVOID Address
)
{
    PHIDDEN_MEMORY_ENTRY memEntry = NULL;
    KIRQL oldIrql;

    if (!g_HiddenMemoryInitialized) return STATUS_NOT_INITIALIZED;
    KeAcquireSpinLock(&g_HiddenMemoryLock, &oldIrql);
    for (PLIST_ENTRY entry = g_HiddenMemoryList.Flink;
         entry != &g_HiddenMemoryList;
         entry = entry->Flink) {
        PHIDDEN_MEMORY_ENTRY candidate = CONTAINING_RECORD(
            entry, HIDDEN_MEMORY_ENTRY, ListEntry);
        ULONG_PTR start = (ULONG_PTR)candidate->BaseAddress;
        ULONG_PTR end = start + candidate->RegionSize;
        ULONG_PTR address = (ULONG_PTR)Address;
        if (candidate->ProcessId == ProcessId &&
            address >= start && address < end) {
            RemoveEntryList(entry);
            if (g_HiddenMemoryCount != 0) g_HiddenMemoryCount--;
            memEntry = candidate;
            break;
        }
    }
    KeReleaseSpinLock(&g_HiddenMemoryLock, oldIrql);

    if (!memEntry) return STATUS_NOT_FOUND;
    
    ExFreePoolWithTag(memEntry, HV_INJECTION_TAG);
    
    DbgPrint("[Injection-Hide] Removed hidden region: PID=%d, Addr=%p\n",
        ProcessId, Address);
    
    return STATUS_SUCCESS;
}

/*
 * 擦除 PE 头
 */
NTSTATUS
HvRemoveHiddenMemoryRegion(
    _In_ ULONG ProcessId,
    _In_ PVOID Address
)
{
    NTSTATUS status = InjectionOperationAcquire();
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = InjectionRemoveHiddenMemoryRegionCore(ProcessId, Address);
    InjectionOperationRelease();
    return status;
}

static NTSTATUS
InjectionErasePeHeaderCore(
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
    
    // Update the record while it is still protected by the list lock.  The old
    // unlocked pointer could be freed concurrently by unhide/process exit.
    if (NT_SUCCESS(status) && g_HiddenMemoryInitialized) {
        KIRQL oldIrql;
        KeAcquireSpinLock(&g_HiddenMemoryLock, &oldIrql);
        for (PLIST_ENTRY entry = g_HiddenMemoryList.Flink;
             entry != &g_HiddenMemoryList;
             entry = entry->Flink) {
            PHIDDEN_MEMORY_ENTRY candidate = CONTAINING_RECORD(
                entry, HIDDEN_MEMORY_ENTRY, ListEntry);
            if (candidate->ProcessId == ProcessId &&
                candidate->BaseAddress == ModuleBase) {
                candidate->PeHeaderErased = TRUE;
                break;
            }
        }
        KeReleaseSpinLock(&g_HiddenMemoryLock, oldIrql);
    }
    
    return status;
}

/*
 * 伪装 VAD 保护属性
 * 注意：直接修改 VAD 需要 undocumented 结构，这里通过修改返回给查询的结果来实现
 */
NTSTATUS
HvErasePeHeader(
    _In_ ULONG ProcessId,
    _In_ PVOID ModuleBase,
    _In_ ULONG HeaderSize
)
{
    NTSTATUS status = InjectionOperationAcquire();
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = InjectionErasePeHeaderCore(
        ProcessId, ModuleBase, HeaderSize);
    InjectionOperationRelease();
    return status;
}

static NTSTATUS
InjectionSpoofVadProtectionCore(
    _In_ ULONG ProcessId,
    _In_ PVOID Address,
    _In_ ULONG FakeProtection
)
{
    NTSTATUS status;

    if (!FindHiddenMemorySnapshot(ProcessId, 0, Address, NULL)) {
        // 如果不在列表中，先添加
        status = InjectionAddHiddenMemoryRegionCore(
            ProcessId, Address, PAGE_SIZE, HvHideModeSpoofProtection);
        if (!NT_SUCCESS(status)) {
            return status;
        }
    }

    if (g_HiddenMemoryInitialized) {
        BOOLEAN updated = FALSE;
        KIRQL oldIrql;
        KeAcquireSpinLock(&g_HiddenMemoryLock, &oldIrql);
        for (PLIST_ENTRY entry = g_HiddenMemoryList.Flink;
             entry != &g_HiddenMemoryList;
             entry = entry->Flink) {
            PHIDDEN_MEMORY_ENTRY candidate = CONTAINING_RECORD(
                entry, HIDDEN_MEMORY_ENTRY, ListEntry);
            ULONG_PTR start = (ULONG_PTR)candidate->BaseAddress;
            ULONG_PTR end = start + candidate->RegionSize;
            ULONG_PTR address = (ULONG_PTR)Address;
            if (candidate->ProcessId == ProcessId &&
                address >= start && address < end) {
                candidate->SpoofedProtection = FakeProtection;
                candidate->HideMode |= HvHideModeSpoofProtection;
                updated = TRUE;
                break;
            }
        }
        KeReleaseSpinLock(&g_HiddenMemoryLock, oldIrql);
        if (!updated) return STATUS_NOT_FOUND;
    }

    DbgPrint("[Injection-Hide] Set spoofed protection: PID=%d, Addr=%p, Prot=0x%X\n",
        ProcessId, Address, FakeProtection);
    
    return STATUS_SUCCESS;
}

/*
 * Hooked NtQueryVirtualMemory
 * 过滤隐藏的内存区域
 */
NTSTATUS
HvSpoofVadProtection(
    _In_ ULONG ProcessId,
    _In_ PVOID Address,
    _In_ ULONG FakeProtection
)
{
    NTSTATUS status = InjectionOperationAcquire();
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = InjectionSpoofVadProtectionCore(
        ProcessId, Address, FakeProtection);
    InjectionOperationRelease();
    return status;
}

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
    HV_HOOK_HANDLE callbackHandle =
        (HV_HOOK_HANDLE)g_NtQueryVirtualMemoryHook;

    if (!HvHookCallbackAcquire(callbackHandle)) {
        return STATUS_DELETE_PENDING;
    }

    __try {
    NTSTATUS status;
    PFN_NtQueryVirtualMemory originalFunc;
    ULONG targetPid = 0;
    UINT64 targetCreateTime = 0;
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
            targetCreateTime =
                (UINT64)PsGetProcessCreateTimeQuadPart(PsGetCurrentProcess());
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
                targetCreateTime =
                    (UINT64)PsGetProcessCreateTimeQuadPart(targetProcess);
                ObDereferenceObject(targetProcess);
            }
        }
        
        // 检查是否需要隐藏
        if (targetPid != 0) {
            PMEMORY_BASIC_INFORMATION_INJ memInfo = 
                (PMEMORY_BASIC_INFORMATION_INJ)MemoryInformation;

            HIDDEN_MEMORY_ENTRY hiddenEntry;
            RtlZeroMemory(&hiddenEntry, sizeof(hiddenEntry));
            if (FindHiddenMemorySnapshot(
                    targetPid,
                    targetCreateTime,
                    memInfo->BaseAddress,
                    &hiddenEntry)) {
                // 根据隐藏模式处理
                if (hiddenEntry.HideMode & HvHideModeQueryFilter) {
                    // 完全隐藏：报告为 FREE 内存
                    memInfo->State = MEM_FREE;
                    memInfo->Protect = PAGE_NOACCESS;
                    memInfo->Type = 0;
                    memInfo->AllocationBase = NULL;
                    memInfo->AllocationProtect = 0;
                    
                    DbgPrint("[Injection-Hide] Filtered query for PID=%d, Addr=%p\n",
                        targetPid, BaseAddress);
                }
                else if (hiddenEntry.HideMode & HvHideModeSpoofProtection) {
                    // 伪装保护属性
                    if (hiddenEntry.SpoofedProtection != 0) {
                        memInfo->Protect = hiddenEntry.SpoofedProtection;
                        memInfo->AllocationProtect = hiddenEntry.SpoofedProtection;
                    }
                }
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // 忽略异常，返回原始结果
    }
    
    return status;
    } __finally {
        HvHookCallbackRelease(callbackHandle);
    }
}

/*
 * 安装内存隐藏 Hook
 */
static NTSTATUS
InjectionInstallMemoryHideHookCore(VOID)
{
    NTSTATUS status;
    NTSTATUS rollbackStatus;
    UNICODE_STRING funcName;
    PVOID ntQueryVirtualMemory;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL ||
        !HvHookIsInitialized()) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_MemoryHideHookLock);

    DbgPrint("[Injection-Hide] Installing NtQueryVirtualMemory hook...\n");

    if (g_NtQueryVirtualMemoryHook != NULL) {
        status = g_OriginalNtQueryVirtualMemory
            ? STATUS_SUCCESS
            : STATUS_INVALID_DEVICE_STATE;
        goto Exit;
    }
    
    // 获取函数地址
    RtlInitUnicodeString(&funcName, L"NtQueryVirtualMemory");
    ntQueryVirtualMemory = MmGetSystemRoutineAddress(&funcName);
    
    if (!ntQueryVirtualMemory) {
        DbgPrint("[Injection-Hide] Failed to find NtQueryVirtualMemory\n");
        status = STATUS_NOT_FOUND;
        goto Exit;
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
        if (!g_OriginalNtQueryVirtualMemory) {
            rollbackStatus = HvHookRemove(g_NtQueryVirtualMemoryHook);
            if (NT_SUCCESS(rollbackStatus)) {
                g_NtQueryVirtualMemoryHook = NULL;
            }
            status = STATUS_PROCEDURE_NOT_FOUND;
            DbgPrint("[Injection-Hide] Missing trampoline; rollback=0x%X\n",
                rollbackStatus);
        } else {
            DbgPrint("[Injection-Hide] Hook installed, trampoline at %p\n",
                g_OriginalNtQueryVirtualMemory);
        }
    } else {
        g_NtQueryVirtualMemoryHook = NULL;
        g_OriginalNtQueryVirtualMemory = NULL;
        DbgPrint("[Injection-Hide] Hook installation failed: 0x%X\n", status);
    }

Exit:
    ExReleasePushLockExclusive(&g_MemoryHideHookLock);
    KeLeaveCriticalRegion();
    return status;
}

/*
 * 移除内存隐藏 Hook
 */
NTSTATUS
HvInstallMemoryHideHook(VOID)
{
    NTSTATUS status = InjectionOperationAcquire();
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = InjectionInstallMemoryHideHookCore();
    InjectionOperationRelease();
    return status;
}

NTSTATUS
HvRemoveMemoryHideHook(VOID)
{
    NTSTATUS status = STATUS_SUCCESS;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_MemoryHideHookLock);

    if (g_NtQueryVirtualMemoryHook) {
        DbgPrint("[Injection-Hide] Removing NtQueryVirtualMemory hook...\n");
        status = HvHookRemove(g_NtQueryVirtualMemoryHook);
        if (NT_SUCCESS(status)) {
            g_NtQueryVirtualMemoryHook = NULL;
            g_OriginalNtQueryVirtualMemory = NULL;
        } else {
            DbgPrint("[Injection-Hide] Hook removal retained ownership: 0x%X\n",
                status);
        }
    }

    ExReleasePushLockExclusive(&g_MemoryHideHookLock);
    KeLeaveCriticalRegion();
    return status;
}

/*
 * 完整的内存隐藏（内核态无痕）
 */
static NTSTATUS
InjectionHideInjectedMemoryCore(
    _In_ ULONG ProcessId,
    _In_ PVOID Address,
    _In_ SIZE_T Size
)
{
    NTSTATUS status;
    PEPROCESS process = NULL;
    UINT64 processCreateTime = 0;
    
    DbgPrint("[Injection-Hide] ========== Hiding Memory (Kernel-Level) ==========\n");
    DbgPrint("[Injection-Hide] PID=%d, Address=%p, Size=0x%llX\n",
        ProcessId, Address, (ULONGLONG)Size);
    
    // 1. 确保 Hook 已安装
    status = InjectionInstallMemoryHideHookCore();
    if (!NT_SUCCESS(status)) {
        DbgPrint("[Injection-Hide] Hook installation failed; no destructive hide changes published\n");
        return status;
    }
    
    // 2. 添加到隐藏列表（启用完整隐藏模式）
    status = InjectionAddHiddenMemoryRegionCore(
        ProcessId, Address, Size, HvHideModeComplete);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[Injection-Hide] Failed to add to hidden list: 0x%X\n", status);
        return status;
    }
    
    // 3. 擦除 PE 头
    status = InjectionErasePeHeaderCore(ProcessId, Address, 0);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[Injection-Hide] Warning: PE header erase failed\n");
    }
    
    // 4. 伪装保护属性（PAGE_READWRITE 比 PAGE_EXECUTE_READWRITE 不那么可疑）
    status = InjectionSpoofVadProtectionCore(
        ProcessId, Address, PAGE_READWRITE);
    
    // 5. 从 PEB 模块列表解链（如果是 DLL）
    status = InjectionHideInjectedModuleCore(ProcessId, Address);

    // 6. 更新模块条目（锁内按 PID + CreateTime + base 定位）
    if (NT_SUCCESS(PsLookupProcessByProcessId(
            (HANDLE)(ULONG_PTR)ProcessId, &process))) {
        processCreateTime =
            (UINT64)PsGetProcessCreateTimeQuadPart(process);
        ObDereferenceObject(process);
        (void)InjectionSetModuleHiddenState(
            ProcessId, processCreateTime, Address, TRUE);
    }
    
    DbgPrint("[Injection-Hide] ========== Memory Hidden Successfully ==========\n");
    
    return STATUS_SUCCESS;
}

/*
 * 取消隐藏内存
 */
NTSTATUS
HvHideInjectedMemory(
    _In_ ULONG ProcessId,
    _In_ PVOID Address,
    _In_ SIZE_T Size
)
{
    NTSTATUS status = InjectionOperationAcquire();
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = InjectionHideInjectedMemoryCore(ProcessId, Address, Size);
    InjectionOperationRelease();
    return status;
}

static NTSTATUS
InjectionUnhideInjectedMemoryCore(
    _In_ ULONG ProcessId,
    _In_ PVOID Address
)
{
    NTSTATUS status;
    PEPROCESS process = NULL;
    UINT64 processCreateTime = 0;
    
    DbgPrint("[Injection-Hide] Unhiding memory: PID=%d, Address=%p\n",
        ProcessId, Address);
    
    // 从隐藏列表移除
    status = InjectionRemoveHiddenMemoryRegionCore(ProcessId, Address);
    
    // 更新模块条目
    if (NT_SUCCESS(PsLookupProcessByProcessId(
            (HANDLE)(ULONG_PTR)ProcessId, &process))) {
        processCreateTime =
            (UINT64)PsGetProcessCreateTimeQuadPart(process);
        ObDereferenceObject(process);
        (void)InjectionSetModuleHiddenState(
            ProcessId, processCreateTime, Address, FALSE);
    }

    return status;
}

/*
 * 隐藏注入的模块（从 PEB LdrModuleList 解链）
 */
NTSTATUS
HvUnhideInjectedMemory(
    _In_ ULONG ProcessId,
    _In_ PVOID Address
)
{
    NTSTATUS status = InjectionOperationAcquire();
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = InjectionUnhideInjectedMemoryCore(ProcessId, Address);
    InjectionOperationRelease();
    return status;
}

static NTSTATUS
InjectionHideInjectedModuleCore(
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

NTSTATUS
HvHideInjectedModule(
    _In_ ULONG ProcessId,
    _In_ PVOID ModuleBase
)
{
    NTSTATUS status = InjectionOperationAcquire();
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = InjectionHideInjectedModuleCore(ProcessId, ModuleBase);
    InjectionOperationRelease();
    return status;
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
    NTSTATUS admissionStatus = InjectionOperationAcquire();

    if (!NT_SUCCESS(admissionStatus)) {
        DbgPrint("[Injection] Status unavailable during shutdown: 0x%X\n",
                 admissionStatus);
        return;
    }
    
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
    InjectionOperationRelease();
}

ULONG
HvGetInjectedModuleCount(VOID)
{
    NTSTATUS status = InjectionOperationAcquire();
    ULONG count;

    if (!NT_SUCCESS(status)) {
        return 0;
    }
    count = g_InjectionManager.InjectedModuleCount;
    InjectionOperationRelease();
    return count;
}

// ============================================================
// 内部辅助函数
// ============================================================

static PINJECTED_MODULE_ENTRY
InjectionClaimModule(
    _In_ ULONG ProcessId,
    _In_ UINT64 ProcessCreateTime,
    _In_ PVOID ModuleBase
)
{
    PLIST_ENTRY entry;
    PINJECTED_MODULE_ENTRY moduleEntry;
    KIRQL oldIrql;
    PINJECTED_MODULE_ENTRY result = NULL;
    
    if (InterlockedCompareExchange(
            &g_InjectionListsInitialized, 0, 0) == 0) {
        return NULL;
    }
    
    KeAcquireSpinLock(&g_InjectionManager.Lock, &oldIrql);
    
    for (entry = g_InjectionManager.InjectedModuleList.Flink;
         entry != &g_InjectionManager.InjectedModuleList;
         entry = entry->Flink)
    {
        moduleEntry = CONTAINING_RECORD(entry, INJECTED_MODULE_ENTRY, ListEntry);
        
        if (moduleEntry->ProcessId == ProcessId &&
            moduleEntry->ProcessCreateTime == ProcessCreateTime &&
            moduleEntry->ModuleBase == ModuleBase &&
            InterlockedCompareExchange(&moduleEntry->Removing, 1, 0) == 0) {
            RemoveEntryList(&moduleEntry->ListEntry);
            if (g_InjectionManager.InjectedModuleCount != 0) {
                g_InjectionManager.InjectedModuleCount--;
            }
            result = moduleEntry;
            break;
        }
    }
    
    KeReleaseSpinLock(&g_InjectionManager.Lock, oldIrql);
    
    return result;
}

static VOID
InjectionRestoreClaimedModule(
    _Inout_ PINJECTED_MODULE_ENTRY ModuleEntry
)
{
    KIRQL oldIrql;

    if (!ModuleEntry) return;

    KeAcquireSpinLock(&g_InjectionManager.Lock, &oldIrql);
    if (InterlockedCompareExchange(
            &g_InjectionListsInitialized, 0, 0) != 0) {
        InterlockedExchange(&ModuleEntry->Removing, 0);
        InsertTailList(
            &g_InjectionManager.InjectedModuleList,
            &ModuleEntry->ListEntry);
        g_InjectionManager.InjectedModuleCount++;
        ModuleEntry = NULL;
    }
    KeReleaseSpinLock(&g_InjectionManager.Lock, oldIrql);

    if (ModuleEntry) {
        ExFreePoolWithTag(ModuleEntry, HV_INJECTION_TAG);
    }
}

static NTSTATUS
InjectionSetModuleHiddenState(
    _In_ ULONG ProcessId,
    _In_ UINT64 ProcessCreateTime,
    _In_ PVOID ModuleBase,
    _In_ BOOLEAN IsHidden
)
{
    PLIST_ENTRY entry;
    KIRQL oldIrql;
    NTSTATUS status = STATUS_NOT_FOUND;

    if (InterlockedCompareExchange(
            &g_InjectionListsInitialized, 0, 0) == 0 ||
        ProcessCreateTime == 0) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    KeAcquireSpinLock(&g_InjectionManager.Lock, &oldIrql);
    for (entry = g_InjectionManager.InjectedModuleList.Flink;
         entry != &g_InjectionManager.InjectedModuleList;
         entry = entry->Flink) {
        PINJECTED_MODULE_ENTRY moduleEntry = CONTAINING_RECORD(
            entry, INJECTED_MODULE_ENTRY, ListEntry);
        if (moduleEntry->ProcessId == ProcessId &&
            moduleEntry->ProcessCreateTime == ProcessCreateTime &&
            moduleEntry->ModuleBase == ModuleBase &&
            InterlockedCompareExchange(&moduleEntry->Removing, 0, 0) == 0) {
            moduleEntry->IsHidden = IsHidden;
            status = STATUS_SUCCESS;
            break;
        }
    }
    KeReleaseSpinLock(&g_InjectionManager.Lock, oldIrql);
    return status;
}

// ============================================================
// HvInjectDllFromFile - 从文件路径注入 DLL
// ============================================================

static BOOLEAN
InjectionHasUncMarker(
    _In_ PCWSTR Path,
    _In_ SIZE_T PathLength,
    _In_ SIZE_T Offset
)
{
    return PathLength >= Offset + 4 &&
           (Path[Offset] == L'U' || Path[Offset] == L'u') &&
           (Path[Offset + 1] == L'N' || Path[Offset + 1] == L'n') &&
           (Path[Offset + 2] == L'C' || Path[Offset + 2] == L'c') &&
           InjectionIsPathSeparator(Path[Offset + 3]);
}

static NTSTATUS
InjectionNormalizeUserLoaderPath(
    _In_ PCWSTR InputPath,
    _Out_writes_(OutputChars) PWSTR OutputPath,
    _In_ SIZE_T OutputChars,
    _Out_ PSIZE_T OutputLength
)
{
    SIZE_T inputLength = 0;
    SIZE_T sourceOffset = 0;
    SIZE_T prefixLength = 0;
    SIZE_T outputLength;
    SIZE_T pathIndex;

    if (!InputPath || !OutputPath || OutputChars == 0 || !OutputLength) {
        return STATUS_INVALID_PARAMETER;
    }
    *OutputLength = 0;

    __try {
        while (inputLength < HV_INJECTION_MAX_PATH_CHARS &&
               InputPath[inputLength] != L'\0') {
            inputLength++;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }
    if (inputLength == 0) {
        return STATUS_OBJECT_NAME_INVALID;
    }
    if (inputLength == HV_INJECTION_MAX_PATH_CHARS) {
        return STATUS_NAME_TOO_LONG;
    }

    if (inputLength >= 4 &&
        InjectionIsPathSeparator(InputPath[0]) &&
        InjectionIsPathSeparator(InputPath[1]) &&
        (InputPath[2] == L'?' || InputPath[2] == L'.') &&
        InjectionIsPathSeparator(InputPath[3])) {
        sourceOffset = 4;
        if (InjectionHasUncMarker(InputPath, inputLength, 4)) {
            sourceOffset = 8;
            prefixLength = 2;
        }
    } else if (inputLength >= 4 &&
               InjectionIsPathSeparator(InputPath[0]) &&
               InputPath[1] == L'?' && InputPath[2] == L'?' &&
               InjectionIsPathSeparator(InputPath[3])) {
        sourceOffset = 4;
        if (InjectionHasUncMarker(InputPath, inputLength, 4)) {
            sourceOffset = 8;
            prefixLength = 2;
        }
    } else if ((inputLength >= 2 &&
                InjectionIsPathSeparator(InputPath[0]) &&
                InjectionIsPathSeparator(InputPath[1])) ||
               InjectionIsPathSeparator(InputPath[0]) ||
               (inputLength >= 3 && InputPath[1] == L':' &&
                InjectionIsPathSeparator(InputPath[2]))) {
        sourceOffset = 0;
    } else {
        return STATUS_OBJECT_PATH_SYNTAX_BAD;
    }

    outputLength = prefixLength + inputLength - sourceOffset;
    if (outputLength == 0 || outputLength + 1 > OutputChars ||
        outputLength > MAXUSHORT / sizeof(WCHAR)) {
        return STATUS_NAME_TOO_LONG;
    }
    if (prefixLength == 2) {
        OutputPath[0] = L'\\';
        OutputPath[1] = L'\\';
    }
    __try {
        RtlCopyMemory(
            OutputPath + prefixLength,
            InputPath + sourceOffset,
            (inputLength - sourceOffset) * sizeof(WCHAR));
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }
    for (pathIndex = 0; pathIndex < outputLength; pathIndex++) {
        if (OutputPath[pathIndex] == L'/') {
            OutputPath[pathIndex] = L'\\';
        }
    }
    OutputPath[outputLength] = L'\0';
    *OutputLength = outputLength;
    return STATUS_SUCCESS;
}

static NTSTATUS
InjectionBuildDependencySearchPath(
    _In_opt_ PCWSTR SourcePath,
    _Out_writes_(OutputChars) PWSTR OutputPath,
    _In_ SIZE_T OutputChars
)
{
    NTSTATUS status;
    SIZE_T pathLength = 0;
    SIZE_T pathIndex;
    SIZE_T separatorIndex = MAXULONG_PTR;

    if (!OutputPath || OutputChars == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    OutputPath[0] = L'\0';
    if (!SourcePath || SourcePath[0] == L'\0') {
        return STATUS_SUCCESS;
    }

    status = InjectionNormalizeUserLoaderPath(
        SourcePath, OutputPath, OutputChars, &pathLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    for (pathIndex = 0; pathIndex < pathLength; pathIndex++) {
        if (InjectionIsPathSeparator(OutputPath[pathIndex])) {
            separatorIndex = pathIndex;
        }
    }
    if (separatorIndex == MAXULONG_PTR ||
        separatorIndex + 1 >= pathLength) {
        OutputPath[0] = L'\0';
        return STATUS_OBJECT_PATH_SYNTAX_BAD;
    }

    if (separatorIndex == 0) {
        OutputPath[1] = L'\0';
    } else if (separatorIndex == 2 && OutputPath[1] == L':') {
        OutputPath[3] = L'\0';
    } else {
        OutputPath[separatorIndex] = L'\0';
    }
    return STATUS_SUCCESS;
}

static VOID
InjectionStoreModuleBaseName(
    _Inout_ PINJECTED_MODULE_ENTRY ModuleEntry,
    _In_ PCWSTR DllPath
)
{
    PCWSTR baseName = DllPath;
    SIZE_T pathIndex;
    SIZE_T nameIndex = 0;

    if (!ModuleEntry || !DllPath) {
        return;
    }
    for (pathIndex = 0; DllPath[pathIndex] != L'\0'; pathIndex++) {
        if (InjectionIsPathSeparator(DllPath[pathIndex])) {
            baseName = &DllPath[pathIndex + 1];
        }
    }
    while (baseName[nameIndex] != L'\0' &&
           nameIndex + 1 < RTL_NUMBER_OF(ModuleEntry->ModuleName)) {
        ModuleEntry->ModuleName[nameIndex] = baseName[nameIndex];
        nameIndex++;
    }
    ModuleEntry->ModuleName[nameIndex] = L'\0';
}

static NTSTATUS
InjectionInjectDllViaLoaderCore(
    _In_ ULONG ProcessId,
    _In_ PCWSTR DllPath,
    _Out_opt_ PHV_INJECTION_RESULT OutResult
)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    NTSTATUS loaderStatus;
    NTSTATUS cleanupStatus;
    PEPROCESS process = NULL;
    PEPROCESS processReference = NULL;
    KAPC_STATE_INJ apcState;
    BOOLEAN attached = FALSE;
    BOOLEAN rollbackSafe = TRUE;
    BOOLEAN moduleLoaded = FALSE;
    UINT64 processCreateTime = 0;
    PVOID ntdllBase = NULL;
    PVOID loadRoutine = NULL;
    PVOID unloadRoutine = NULL;
    PVOID remoteContext = NULL;
    PVOID moduleBase = NULL;
    PVOID entryPoint = NULL;
    SIZE_T moduleSize = 0;
    SIZE_T pathLength = 0;
    SIZE_T contextSize;
    SIZE_T bytesTransferred = 0;
    ULONGLONG routineResult = 0;
    ULONGLONG unloadResult = 0;
    PHV_INJECTION_LDR_LOAD_CONTEXT localContext = NULL;
    PINJECTED_MODULE_ENTRY moduleEntry = NULL;
    USHORT failureStage = HvInjectStageLoaderValidateInput;

    if (OutResult &&
        OutResult->Diagnostics.Version !=
            HV_INJECTION_DIAGNOSTIC_VERSION) {
        InjectionDiagnosticInitialize(
            OutResult, HV_INJECTION_DIAG_FLAG_WINDOWS_LOADER);
    } else if (OutResult) {
        OutResult->Diagnostics.Flags |=
            HV_INJECTION_DIAG_FLAG_WINDOWS_LOADER;
    }
    if (ProcessId == 0 || !DllPath || DllPath[0] == L'\0') {
        status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }
    InjectionDiagnosticRecord(
        OutResult,
        HvInjectStageLoaderValidateInput,
        HvInjectDiagnosticPhaseOperation,
        STATUS_SUCCESS,
        0);

    failureStage = HvInjectStageLoaderValidateEnvironment;
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        status = STATUS_INVALID_LEVEL;
        goto Exit;
    }
    if (!InjectionApcExecutionAvailable()) {
        status = STATUS_NOT_SUPPORTED;
        goto Exit;
    }
    InjectionDiagnosticRecord(
        OutResult,
        HvInjectStageLoaderValidateEnvironment,
        HvInjectDiagnosticPhaseOperation,
        STATUS_SUCCESS,
        0);

    failureStage = HvInjectStageLoaderAllocateMetadata;
    localContext = (PHV_INJECTION_LDR_LOAD_CONTEXT)
        HvAllocateNonPagedZeroed(sizeof(*localContext), HV_INJECTION_TAG);
    moduleEntry = (PINJECTED_MODULE_ENTRY)
        HvAllocateNonPagedZeroed(sizeof(*moduleEntry), HV_INJECTION_TAG);
    if (!localContext || !moduleEntry) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }
    InjectionDiagnosticRecord(
        OutResult,
        HvInjectStageLoaderAllocateMetadata,
        HvInjectDiagnosticPhaseOperation,
        STATUS_SUCCESS,
        0);

    failureStage = HvInjectStageLoaderNormalizePath;
    status = InjectionNormalizeUserLoaderPath(
        DllPath,
        localContext->DllPath,
        RTL_NUMBER_OF(localContext->DllPath),
        &pathLength);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }
    InjectionDiagnosticRecord(
        OutResult,
        HvInjectStageLoaderNormalizePath,
        HvInjectDiagnosticPhaseOperation,
        STATUS_SUCCESS,
        (ULONG)pathLength);

    failureStage = HvInjectStageLoaderBuildSearchPath;
    status = InjectionBuildDependencySearchPath(
        DllPath,
        localContext->SearchPath,
        RTL_NUMBER_OF(localContext->SearchPath));
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }
    InjectionDiagnosticRecord(
        OutResult,
        HvInjectStageLoaderBuildSearchPath,
        HvInjectDiagnosticPhaseOperation,
        STATUS_SUCCESS,
        0);

    failureStage = HvInjectStageLoaderAttachProcess;
    status = HvAttachProcess(ProcessId, &process, &apcState);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }
    attached = TRUE;
    InjectionDiagnosticRecord(
        OutResult,
        HvInjectStageLoaderAttachProcess,
        HvInjectDiagnosticPhaseOperation,
        STATUS_SUCCESS,
        0);

    failureStage = HvInjectStageLoaderValidateTarget;
    if (PsGetProcessWow64Process(process) != NULL) {
        status = STATUS_IMAGE_MACHINE_TYPE_MISMATCH;
        goto Exit;
    }
    processCreateTime = (UINT64)PsGetProcessCreateTimeQuadPart(process);
    if (processCreateTime == 0) {
        status = STATUS_INVALID_CID;
        goto Exit;
    }
    InjectionDiagnosticRecord(
        OutResult,
        HvInjectStageLoaderValidateTarget,
        HvInjectDiagnosticPhaseOperation,
        STATUS_SUCCESS,
        0);

    failureStage = HvInjectStageLoaderFindNtdll;
    ntdllBase = InjectionGetModuleBase(process, L"ntdll.dll");
    if (!ntdllBase) {
        status = STATUS_DLL_NOT_FOUND;
        goto Exit;
    }
    InjectionDiagnosticRecord(
        OutResult,
        HvInjectStageLoaderFindNtdll,
        HvInjectDiagnosticPhaseOperation,
        STATUS_SUCCESS,
        0);

    failureStage = HvInjectStageLoaderResolveRoutines;
    loadRoutine = InjectionGetProcAddress(
        process, ntdllBase, (ULONG_PTR)"LdrLoadDll", 0);
    unloadRoutine = InjectionGetProcAddress(
        process, ntdllBase, (ULONG_PTR)"LdrUnloadDll", 0);
    if (!loadRoutine || !unloadRoutine) {
        status = STATUS_PROCEDURE_NOT_FOUND;
        goto Exit;
    }
    InjectionDiagnosticRecord(
        OutResult,
        HvInjectStageLoaderResolveRoutines,
        HvInjectDiagnosticPhaseOperation,
        STATUS_SUCCESS,
        0);
    ObReferenceObject(process);
    processReference = process;
    HvDetachProcess(process, &apcState);
    process = NULL;
    attached = FALSE;

    contextSize = FIELD_OFFSET(HV_INJECTION_LDR_LOAD_CONTEXT, DllPath) +
        (pathLength + 1) * sizeof(WCHAR);
    failureStage = HvInjectStageLoaderAllocateContext;
    status = InjectionMemoryAllocateCore(
        ProcessId, contextSize, PAGE_READWRITE, &remoteContext);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }
    InjectionDiagnosticRecord(
        OutResult,
        HvInjectStageLoaderAllocateContext,
        HvInjectDiagnosticPhaseOperation,
        STATUS_SUCCESS,
        (ULONG)contextSize);
    localContext->DllName.Buffer = (PWSTR)(
        (PUCHAR)remoteContext +
        FIELD_OFFSET(HV_INJECTION_LDR_LOAD_CONTEXT, DllPath));
    localContext->DllName.Length = (USHORT)(pathLength * sizeof(WCHAR));
    localContext->DllName.MaximumLength =
        (USHORT)((pathLength + 1) * sizeof(WCHAR));

    failureStage = HvInjectStageLoaderWriteContext;
    status = HvMemoryWrite(
        ProcessId,
        remoteContext,
        localContext,
        contextSize,
        &bytesTransferred);
    if (!NT_SUCCESS(status) || bytesTransferred != contextSize) {
        status = NT_SUCCESS(status) ? STATUS_PARTIAL_COPY : status;
        goto Exit;
    }
    InjectionDiagnosticRecord(
        OutResult,
        HvInjectStageLoaderWriteContext,
        HvInjectDiagnosticPhaseOperation,
        STATUS_SUCCESS,
        (ULONG)bytesTransferred);

    failureStage = HvInjectStageLoaderCallLdrLoadDll;
    status = InjectionCallUserRoutine(
        ProcessId,
        processCreateTime,
        loadRoutine,
        NULL,
        NULL,
        (PUCHAR)remoteContext +
            FIELD_OFFSET(HV_INJECTION_LDR_LOAD_CONTEXT, DllName),
        (PUCHAR)remoteContext +
            FIELD_OFFSET(HV_INJECTION_LDR_LOAD_CONTEXT, ModuleHandle),
        &routineResult,
        &rollbackSafe);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }
    loaderStatus = (NTSTATUS)(ULONG)routineResult;
    if (!NT_SUCCESS(loaderStatus)) {
        status = loaderStatus;
        goto Exit;
    }
    InjectionDiagnosticRecord(
        OutResult,
        HvInjectStageLoaderCallLdrLoadDll,
        HvInjectDiagnosticPhaseOperation,
        STATUS_SUCCESS,
        0);

    bytesTransferred = 0;
    failureStage = HvInjectStageLoaderReadModuleHandle;
    status = HvMemoryRead(
        ProcessId,
        (PUCHAR)remoteContext +
            FIELD_OFFSET(HV_INJECTION_LDR_LOAD_CONTEXT, ModuleHandle),
        &moduleBase,
        sizeof(moduleBase),
        &bytesTransferred);
    if (!NT_SUCCESS(status) || bytesTransferred != sizeof(moduleBase)) {
        status = NT_SUCCESS(status) ? STATUS_PARTIAL_COPY : status;
        rollbackSafe = FALSE;
        goto Exit;
    }
    if (!moduleBase) {
        status = STATUS_DLL_INIT_FAILED;
        goto Exit;
    }
    InjectionDiagnosticRecord(
        OutResult,
        HvInjectStageLoaderReadModuleHandle,
        HvInjectDiagnosticPhaseOperation,
        STATUS_SUCCESS,
        0);
    moduleLoaded = TRUE;

    cleanupStatus = InjectionQueryRemoteImage(
        ProcessId, moduleBase, &moduleSize, &entryPoint);
    InjectionDiagnosticRecord(
        OutResult,
        HvInjectStageLoaderQueryImage,
        NT_SUCCESS(cleanupStatus)
            ? HvInjectDiagnosticPhaseOperation
            : HvInjectDiagnosticPhaseWarning,
        cleanupStatus,
        (ULONG)moduleSize);
    if (!NT_SUCCESS(cleanupStatus)) {
        moduleSize = 0;
        entryPoint = NULL;
        DbgPrint("[Injection] Loader image metadata query failed: 0x%X\n",
            cleanupStatus);
    }

    moduleEntry->ProcessId = ProcessId;
    moduleEntry->ProcessCreateTime = processCreateTime;
    moduleEntry->ModuleBase = moduleBase;
    moduleEntry->ModuleSize = moduleSize;
    moduleEntry->EntryPoint = entryPoint;
    moduleEntry->LoaderUnloadRoutine = unloadRoutine;
    moduleEntry->LoaderManaged = TRUE;
    InjectionStoreModuleBaseName(moduleEntry, localContext->DllPath);
    failureStage = HvInjectStageLoaderTrackModule;
    if (!InjectionTrackModuleEntry(moduleEntry, processReference)) {
        status = STATUS_PROCESS_IS_TERMINATING;
        goto Exit;
    }
    InjectionDiagnosticRecord(
        OutResult,
        HvInjectStageLoaderTrackModule,
        HvInjectDiagnosticPhaseOperation,
        STATUS_SUCCESS,
        0);
    if (OutResult) {
        OutResult->Diagnostics.Flags |=
            HV_INJECTION_DIAG_FLAG_MODULE_TRACKED;
    }
    moduleEntry = NULL;

    if (OutResult) {
        OutResult->ModuleBase = moduleBase;
        OutResult->ModuleSize = moduleSize;
        OutResult->EntryPointAddress = entryPoint;
    }
    status = STATUS_SUCCESS;

Exit:
    if (!NT_SUCCESS(status)) {
        InjectionDiagnosticFailure(
            OutResult, failureStage, status, 0);
    }
    if (attached) {
        HvDetachProcess(process, &apcState);
        process = NULL;
    }
    if (status != STATUS_SUCCESS && moduleLoaded && moduleEntry &&
        processReference &&
        PsGetProcessExitStatus(processReference) == STATUS_PENDING &&
        unloadRoutine && rollbackSafe) {
        cleanupStatus = InjectionCallUserRoutine(
            ProcessId,
            processCreateTime,
            unloadRoutine,
            moduleBase,
            NULL,
            NULL,
            NULL,
            &unloadResult,
            &rollbackSafe);
        if (NT_SUCCESS(cleanupStatus)) {
            cleanupStatus = (NTSTATUS)(ULONG)unloadResult;
        }
        InjectionDiagnosticCleanup(
            OutResult,
            HvInjectStageCleanupLoaderUnload,
            cleanupStatus,
            0);
        if (NT_SUCCESS(cleanupStatus)) {
            moduleLoaded = FALSE;
        }
    }
    if (status != STATUS_SUCCESS && moduleLoaded && moduleEntry &&
        processReference &&
        PsGetProcessExitStatus(processReference) == STATUS_PENDING) {
        moduleEntry->UnsafeToUnload = !rollbackSafe;
        if (InjectionTrackModuleEntry(moduleEntry, processReference)) {
            InjectionDiagnosticCleanup(
                OutResult,
                HvInjectStageCleanupTrackRetained,
                STATUS_SUCCESS,
                0);
            if (OutResult) {
                OutResult->ModuleBase = moduleBase;
                OutResult->ModuleSize = moduleSize;
                OutResult->EntryPointAddress = entryPoint;
                OutResult->Diagnostics.Flags |=
                    HV_INJECTION_DIAG_FLAG_MAPPING_RETAINED |
                    HV_INJECTION_DIAG_FLAG_MODULE_TRACKED;
            }
            moduleEntry = NULL;
        } else {
            InjectionDiagnosticCleanup(
                OutResult,
                HvInjectStageCleanupTrackRetained,
                STATUS_PROCESS_IS_TERMINATING,
                0);
        }
    }
    if (status != STATUS_SUCCESS && moduleLoaded && processReference &&
        PsGetProcessExitStatus(processReference) != STATUS_PENDING) {
        if (OutResult) {
            OutResult->Diagnostics.Flags |=
                HV_INJECTION_DIAG_FLAG_PROCESS_EXITED;
        }
        InjectionDiagnosticRecord(
            OutResult,
            HvInjectStageCleanupTrackRetained,
            HvInjectDiagnosticPhaseWarning,
            STATUS_PROCESS_IS_TERMINATING,
            0);
    }
    if (remoteContext && rollbackSafe) {
        cleanupStatus = InjectionMemoryFreeCore(ProcessId, remoteContext);
        if (!NT_SUCCESS(status)) {
            InjectionDiagnosticCleanup(
                OutResult,
                HvInjectStageCleanupLoaderContext,
                cleanupStatus,
                0);
        } else {
            InjectionDiagnosticRecord(
                OutResult,
                HvInjectStageCleanupLoaderContext,
                HvInjectDiagnosticPhaseWarning,
                cleanupStatus,
                0);
        }
        if (!NT_SUCCESS(cleanupStatus)) {
            if (OutResult) {
                OutResult->Diagnostics.Flags |=
                    HV_INJECTION_DIAG_FLAG_LOADER_CONTEXT_RETAINED |
                    HV_INJECTION_DIAG_FLAG_CLEANUP_FAILED;
                if (OutResult->Diagnostics.CleanupStage ==
                    HvInjectStageNone) {
                    OutResult->Diagnostics.CleanupStage =
                        HvInjectStageCleanupLoaderContext;
                    OutResult->Diagnostics.CleanupStatus = cleanupStatus;
                }
            }
            DbgPrint("[Injection] Loader parameter cleanup failed: 0x%X\n",
                cleanupStatus);
        }
    } else if (remoteContext) {
        cleanupStatus = STATUS_CANNOT_DELETE;
        if (NT_SUCCESS(status)) {
            InjectionDiagnosticRecord(
                OutResult,
                HvInjectStageCleanupLoaderContext,
                HvInjectDiagnosticPhaseWarning,
                cleanupStatus,
                0);
        } else {
            InjectionDiagnosticCleanup(
                OutResult,
                HvInjectStageCleanupLoaderContext,
                cleanupStatus,
                0);
        }
        if (OutResult) {
            OutResult->Diagnostics.Flags |=
                HV_INJECTION_DIAG_FLAG_LOADER_CONTEXT_RETAINED;
        }
        DbgPrint("[Injection] Loader call completion is uncertain; parameter allocation retained\n");
    }
    if (moduleEntry) {
        ExFreePoolWithTag(moduleEntry, HV_INJECTION_TAG);
    }
    if (localContext) {
        ExFreePoolWithTag(localContext, HV_INJECTION_TAG);
    }
    if (processReference) {
        ObDereferenceObject(processReference);
    }
    if (OutResult) {
        if (!rollbackSafe) {
            OutResult->Diagnostics.Flags |=
                HV_INJECTION_DIAG_FLAG_ROLLBACK_UNSAFE;
        }
        if (!NT_SUCCESS(status) && moduleLoaded) {
            OutResult->Diagnostics.Flags |=
                HV_INJECTION_DIAG_FLAG_MAPPING_RETAINED;
        }
        OutResult->Status = status;
    }
    return status;
}

static NTSTATUS
InjectionNormalizeFilePath(
    _In_ PCWSTR InputPath,
    _Out_writes_(OutputChars) PWSTR OutputPath,
    _In_ SIZE_T OutputChars,
    _Out_ PUNICODE_STRING NativePath
)
{
    SIZE_T inputLength = 0;
    SIZE_T sourceOffset = 0;
    PCWSTR prefix = NULL;
    SIZE_T prefixLength = 0;
    SIZE_T outputLength;
    SIZE_T index;

    if (!InputPath || !OutputPath || !NativePath || OutputChars == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    __try {
        while (inputLength < HV_INJECTION_MAX_PATH_CHARS &&
               InputPath[inputLength] != L'\0') {
            inputLength++;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }

    if (inputLength == 0) {
        return STATUS_OBJECT_NAME_INVALID;
    }
    if (inputLength == HV_INJECTION_MAX_PATH_CHARS) {
        return STATUS_NAME_TOO_LONG;
    }

    if (inputLength >= 4 &&
        InjectionIsPathSeparator(InputPath[0]) &&
        InjectionIsPathSeparator(InputPath[1]) &&
        (InputPath[2] == L'?' || InputPath[2] == L'.') &&
        InjectionIsPathSeparator(InputPath[3])) {
        prefix = L"\\??\\";
        prefixLength = 4;
        sourceOffset = 4;
    } else if (inputLength >= 2 &&
               InjectionIsPathSeparator(InputPath[0]) &&
               InjectionIsPathSeparator(InputPath[1])) {
        prefix = L"\\??\\UNC\\";
        prefixLength = 8;
        sourceOffset = 2;
    } else if (InjectionIsPathSeparator(InputPath[0])) {
        sourceOffset = 0;
    } else if (inputLength >= 3 && InputPath[1] == L':' &&
               InjectionIsPathSeparator(InputPath[2])) {
        prefix = L"\\??\\";
        prefixLength = 4;
    } else {
        return STATUS_OBJECT_PATH_SYNTAX_BAD;
    }

    outputLength = prefixLength + inputLength - sourceOffset;
    if (outputLength + 1 > OutputChars ||
        outputLength > (MAXUSHORT / sizeof(WCHAR))) {
        return STATUS_NAME_TOO_LONG;
    }

    if (prefixLength != 0) {
        RtlCopyMemory(OutputPath, prefix, prefixLength * sizeof(WCHAR));
    }
    __try {
        RtlCopyMemory(
            OutputPath + prefixLength,
            InputPath + sourceOffset,
            (inputLength - sourceOffset) * sizeof(WCHAR));
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }

    for (index = 0; index < outputLength; index++) {
        if (OutputPath[index] == L'/') {
            OutputPath[index] = L'\\';
        }
    }
    OutputPath[outputLength] = L'\0';

    NativePath->Buffer = OutputPath;
    NativePath->Length = (USHORT)(outputLength * sizeof(WCHAR));
    NativePath->MaximumLength = (USHORT)((outputLength + 1) * sizeof(WCHAR));
    return STATUS_SUCCESS;
}

static NTSTATUS
InjectionInjectDllFromFileCore(
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
    WCHAR normalizedPath[HV_INJECTION_NATIVE_PATH_CHARS];
    FILE_STANDARD_INFORMATION fileInfo;
    PVOID fileBuffer = NULL;
    LARGE_INTEGER fileSize;
    LARGE_INTEGER byteOffset;
    
    if (OutResult &&
        OutResult->Diagnostics.Version !=
            HV_INJECTION_DIAGNOSTIC_VERSION) {
        InjectionDiagnosticInitialize(
            OutResult, HV_INJECTION_DIAG_FLAG_MANUAL_MAP);
    }
    
    // 验证参数
    if (ProcessId == 0 || DllPath == NULL || DllPath[0] == L'\0') {
        InjectionDiagnosticFailure(
            OutResult,
            HvInjectStageRequestValidate,
            STATUS_INVALID_PARAMETER,
            0);
        DbgPrint("[Injection] Invalid parameters\n");
        return STATUS_INVALID_PARAMETER;
    }
    if (!InjectionApcExecutionAvailable()) {
        InjectionDiagnosticFailure(
            OutResult,
            HvInjectStageRequestValidate,
            STATUS_NOT_SUPPORTED,
            0);
        return STATUS_NOT_SUPPORTED;
    }
    InjectionDiagnosticRecord(
        OutResult,
        HvInjectStageRequestValidate,
        HvInjectDiagnosticPhaseOperation,
        STATUS_SUCCESS,
        0);
    
    status = InjectionNormalizeFilePath(
        DllPath,
        normalizedPath,
        RTL_NUMBER_OF(normalizedPath),
        &filePath);
    if (!NT_SUCCESS(status)) {
        InjectionDiagnosticFailure(
            OutResult,
            HvInjectStageFileNormalizePath,
            status,
            0);
        DbgPrint("[Injection] Invalid DLL path: 0x%X\n", status);
        return status;
    }
    InjectionDiagnosticRecord(
        OutResult,
        HvInjectStageFileNormalizePath,
        HvInjectDiagnosticPhaseOperation,
        STATUS_SUCCESS,
        0);

    DbgPrint("[Injection] HvInjectDllFromFile: PID=%d, NativePath=%wZ\n",
        ProcessId, &filePath);
    
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
        InjectionDiagnosticFailure(
            OutResult,
            HvInjectStageFileOpen,
            status,
            0);
        DbgPrint("[Injection] Failed to open file: 0x%X\n", status);
        return status;
    }
    InjectionDiagnosticRecord(
        OutResult,
        HvInjectStageFileOpen,
        HvInjectDiagnosticPhaseOperation,
        STATUS_SUCCESS,
        0);
    
    // 获取文件大小
    status = ZwQueryInformationFile(
        fileHandle,
        &ioStatus,
        &fileInfo,
        sizeof(fileInfo),
        FileStandardInformation
    );
    
    if (!NT_SUCCESS(status)) {
        InjectionDiagnosticFailure(
            OutResult,
            HvInjectStageFileQuery,
            status,
            0);
        DbgPrint("[Injection] Failed to query file info: 0x%X\n", status);
        ZwClose(fileHandle);
        return status;
    }
    InjectionDiagnosticRecord(
        OutResult,
        HvInjectStageFileQuery,
        HvInjectDiagnosticPhaseOperation,
        STATUS_SUCCESS,
        0);
    
    fileSize = fileInfo.EndOfFile;
    
    if (fileSize.QuadPart == 0 || fileSize.QuadPart > 100 * 1024 * 1024) {  // 最大 100MB
        InjectionDiagnosticFailure(
            OutResult,
            HvInjectStageFileValidateSize,
            STATUS_INVALID_IMAGE_FORMAT,
            (ULONG)(fileSize.QuadPart > MAXULONG
                ? MAXULONG
                : fileSize.QuadPart));
        DbgPrint("[Injection] Invalid file size: %lld\n", fileSize.QuadPart);
        ZwClose(fileHandle);
        return STATUS_INVALID_IMAGE_FORMAT;
    }
    InjectionDiagnosticRecord(
        OutResult,
        HvInjectStageFileValidateSize,
        HvInjectDiagnosticPhaseOperation,
        STATUS_SUCCESS,
        (ULONG)fileSize.QuadPart);
    
    // 分配缓冲区（走 HvCompat 包装，避免 ExAllocatePoolWithTag 弃用警告）
    fileBuffer = HvAllocateNonPaged((SIZE_T)fileSize.QuadPart, 'jnID');
    if (!fileBuffer) {
        InjectionDiagnosticFailure(
            OutResult,
            HvInjectStageFileAllocateBuffer,
            STATUS_INSUFFICIENT_RESOURCES,
            (ULONG)fileSize.QuadPart);
        DbgPrint("[Injection] Failed to allocate buffer for file\n");
        ZwClose(fileHandle);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    InjectionDiagnosticRecord(
        OutResult,
        HvInjectStageFileAllocateBuffer,
        HvInjectDiagnosticPhaseOperation,
        STATUS_SUCCESS,
        (ULONG)fileSize.QuadPart);
    
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
    
    if (!NT_SUCCESS(status) ||
        ioStatus.Information != (ULONG_PTR)fileSize.QuadPart) {
        if (NT_SUCCESS(status)) {
            status = STATUS_END_OF_FILE;
        }
        InjectionDiagnosticFailure(
            OutResult,
            HvInjectStageFileRead,
            status,
            (ULONG)ioStatus.Information);
        DbgPrint("[Injection] Failed to read file: 0x%X\n", status);
        ExFreePoolWithTag(fileBuffer, 'jnID');
        return status;
    }
    InjectionDiagnosticRecord(
        OutResult,
        HvInjectStageFileRead,
        HvInjectDiagnosticPhaseOperation,
        STATUS_SUCCESS,
        (ULONG)ioStatus.Information);
    
    // 验证 PE 头 (使用已定义的类型)
    if (((PIMAGE_DOS_HEADER_INJ)fileBuffer)->e_magic != 0x5A4D) {  // "MZ"
        InjectionDiagnosticFailure(
            OutResult,
            HvInjectStageFileValidateDos,
            STATUS_INVALID_IMAGE_FORMAT,
            ((PIMAGE_DOS_HEADER_INJ)fileBuffer)->e_magic);
        DbgPrint("[Injection] Invalid DOS signature\n");
        ExFreePoolWithTag(fileBuffer, 'jnID');
        return STATUS_INVALID_IMAGE_FORMAT;
    }
    InjectionDiagnosticRecord(
        OutResult,
        HvInjectStageFileValidateDos,
        HvInjectDiagnosticPhaseOperation,
        STATUS_SUCCESS,
        0);
    
    // 调用 DLL 注入
    status = InjectionInjectDllCore(
        ProcessId,
        fileBuffer,
        (SIZE_T)fileSize.QuadPart,
        DllPath,
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
