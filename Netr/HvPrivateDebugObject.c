#include "HvPrivateDebugObject.h"
#include "HvCompat.h"
#include "HvHook.h"
#include "HvPebCloak.h"
#include "HvTypes.h"
#include "HvVwatch.h"

NTKERNELAPI NTSTATUS PsLookupProcessByProcessId(
    _In_ HANDLE ProcessId,
    _Out_ PEPROCESS* Process);
NTKERNELAPI PVOID PsGetProcessSectionBaseAddress(_In_ PEPROCESS Process);
NTKERNELAPI NTSTATUS ObOpenObjectByPointer(
    _In_ PVOID Object,
    _In_ ULONG HandleAttributes,
    _In_opt_ PACCESS_STATE PassedAccessState,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_TYPE ObjectType,
    _In_ KPROCESSOR_MODE AccessMode,
    _Out_ PHANDLE Handle);
NTSYSAPI NTSTATUS NTAPI ZwCreateEvent(
    _Out_ PHANDLE EventHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ EVENT_TYPE EventType,
    _In_ BOOLEAN InitialState);
#define HV_PRIVATE_DEBUG_OBJECT_TAG 'dOvH'
#define HV_PRIVATE_DEBUG_OBJECT_MAX_SESSIONS 32
#define HV_PRIVATE_DBGK_EVENT_TAG 'eDvH'

#ifndef STATUS_WX86_BREAKPOINT
#define STATUS_WX86_BREAKPOINT ((NTSTATUS)0x4000001FL)
#endif
#ifndef STATUS_WX86_SINGLE_STEP
#define STATUS_WX86_SINGLE_STEP ((NTSTATUS)0x4000001EL)
#endif

typedef struct _HV_PRIVATE_DBGK_EVENT_NODE {
    LIST_ENTRY Link;
    ULONG64 Sequence;
    HANDLE ProcessId;
    HANDLE ThreadId;
    PEPROCESS Process;
    PETHREAD Thread;
    ULONG State;
    ULONG Flags;
    NTSTATUS ContinueStatus;
    BOOLEAN Delivered;
    BOOLEAN Synchronous;
    BOOLEAN FreedByDetach;
    KEVENT ContinueEvent;
    HV_BRIDGE_DBGK_EVENT Wire;
} HV_PRIVATE_DBGK_EVENT_NODE, *PHV_PRIVATE_DBGK_EVENT_NODE;

typedef struct _HV_PRIVATE_DEBUG_SESSION {
    LIST_ENTRY Link;
    HANDLE DebuggerPid;
    HANDLE TargetPid;
    PEPROCESS DebuggerProcess;
    PEPROCESS TargetProcess;
    UINT64 DebuggerCreateTime;
    UINT64 TargetCreateTime;
    KEVENT EventsPresent;
    KEVENT NoUsers;
    LIST_ENTRY EventList;
    LONG ActiveUsers;
    volatile LONG DeletePending;
    volatile LONG InitialEventQueued;
    volatile LONG InitialSuspendOwned;
    volatile LONG ExitEventQueued;
} HV_PRIVATE_DEBUG_SESSION, *PHV_PRIVATE_DEBUG_SESSION;

static volatile LONG g_Initialized = FALSE;
static volatile LONG g_Closing = FALSE;
static volatile LONG g_Enabled = FALSE;
static KSPIN_LOCK g_Lock;
static LIST_ENTRY g_Sessions;
static volatile LONG64 g_DbgkSequence = 0;
static HV_PRIVATE_DBGK_SYMBOLS g_Symbols;
static HV_HOOK_HANDLE g_HookDbgkForwardException = NULL;
static HV_HOOK_HANDLE g_HookDbgkCreateThread = NULL;
static HV_HOOK_HANDLE g_HookDbgkExitThread = NULL;
static HV_HOOK_HANDLE g_HookDbgkExitProcess = NULL;
static HV_HOOK_HANDLE g_HookDbgkMapViewOfSection = NULL;
static HV_HOOK_HANDLE g_HookDbgkUnMapViewOfSection = NULL;
static HV_HOOK_HANDLE g_HookNtCreateDebugObject = NULL;
static HV_HOOK_HANDLE g_HookNtSetInformationDebugObject = NULL;
static HV_HOOK_HANDLE g_HookNtWaitForDebugEvent = NULL;
static HV_HOOK_HANDLE g_HookNtDebugContinue = NULL;
static HV_HOOK_HANDLE g_HookNtRemoveProcessDebug = NULL;

static NTSTATUS HvPrivateDebugObjectInstallSyscallHooks(VOID);
static VOID HvPrivateDebugObjectRemoveHooks(VOID);
static VOID HvPrivateDebugObjectDetachAllSessions(VOID);
static NTSTATUS HvPrivateDebugObjectQueueInitialProcess(
    _In_ HANDLE DebuggerPid,
    _In_ HANDLE TargetPid);
static NTSTATUS HvPrivateDebugObjectReleaseInitialSuspend(
    _In_ PHV_PRIVATE_DEBUG_SESSION Session);
static VOID HvPrivateDebugObjectConvertWaitState(
    _In_ const HV_BRIDGE_DBGK_EVENT* Event,
    _Out_ struct _HV_DBGUI_WAIT_STATE_CHANGE* State);

#define HV_PRIVATE_HOOK_BEGIN(_Local, _Global, _Failure)                  \
    HV_HOOK_HANDLE _Local = (_Global);                                    \
    if (!_Local || !HvHookCallbackAcquire(_Local)) return _Failure;       \
    __try {

#define HV_PRIVATE_HOOK_END(_Local)                                       \
    } __finally { HvHookCallbackRelease(_Local); }

typedef NTSTATUS (NTAPI *PFN_NtCreateDebugObject)(
    _Out_ PHANDLE DebugHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ ULONG Flags);
typedef NTSTATUS (NTAPI *PFN_NtSetInformationDebugObject)(
    _In_ HANDLE DebugObjectHandle,
    _In_ ULONG DebugObjectInformationClass,
    _In_reads_bytes_(DebugInformationLength) PVOID DebugInformation,
    _In_ ULONG DebugInformationLength,
    _Out_opt_ PULONG ReturnLength);
typedef NTSTATUS (NTAPI *PFN_NtWaitForDebugEvent)(
    _In_ HANDLE DebugHandle,
    _In_ BOOLEAN Alertable,
    _In_opt_ PLARGE_INTEGER Timeout,
    _Out_ PVOID StateChange);
typedef NTSTATUS (NTAPI *PFN_NtDebugContinue)(
    _In_ HANDLE DebugObjectHandle,
    _In_ PCLIENT_ID ClientId,
    _In_ NTSTATUS ContinueStatus);
typedef NTSTATUS (NTAPI *PFN_NtRemoveProcessDebug)(
    _In_ HANDLE ProcessHandle,
    _In_ HANDLE DebugObjectHandle);
typedef BOOLEAN (NTAPI *PFN_DbgkForwardException)(
    _In_ PEXCEPTION_RECORD ExceptionRecord,
    _In_ BOOLEAN DebugPort,
    _In_ BOOLEAN SecondChance);
typedef VOID (NTAPI *PFN_DbgkCreateThread)(_In_ PETHREAD Thread);
typedef VOID (NTAPI *PFN_DbgkExitThread)(_In_ NTSTATUS ExitStatus);
typedef VOID (NTAPI *PFN_DbgkExitProcess)(_In_ NTSTATUS ExitStatus);
typedef VOID (NTAPI *PFN_DbgkMapViewOfSection)(
    _In_ PEPROCESS Process, _In_ PVOID SectionObject,
    _In_ PVOID BaseAddress, _In_ ULONG SectionOffset,
    _In_ SIZE_T ViewSize);
typedef VOID (NTAPI *PFN_DbgkUnMapViewOfSection)(
    _In_ PEPROCESS Process, _In_ PVOID BaseAddress);

static PHV_PRIVATE_DEBUG_SESSION
HvPrivateDebugObjectFindLocked(
    _In_ HANDLE DebuggerPid,
    _In_ HANDLE TargetPid)
{
    PLIST_ENTRY entry;

    for (entry = g_Sessions.Flink;
         entry != &g_Sessions;
         entry = entry->Flink) {
        PHV_PRIVATE_DEBUG_SESSION session = CONTAINING_RECORD(
            entry, HV_PRIVATE_DEBUG_SESSION, Link);
        if ((DebuggerPid == NULL || session->DebuggerPid == DebuggerPid) &&
            (TargetPid == NULL || session->TargetPid == TargetPid)) {
            return session;
        }
    }
    return NULL;
}

static PHV_PRIVATE_DEBUG_SESSION
HvPrivateDebugObjectAcquireSession(
    _In_opt_ HANDLE DebuggerPid,
    _In_opt_ HANDLE TargetPid)
{
    KIRQL irql;
    PHV_PRIVATE_DEBUG_SESSION session = NULL;

    KeAcquireSpinLock(&g_Lock, &irql);
    session = HvPrivateDebugObjectFindLocked(DebuggerPid, TargetPid);
    if (session &&
        InterlockedCompareExchange(&session->DeletePending, 0, 0) == 0) {
        InterlockedIncrement(&session->ActiveUsers);
        KeClearEvent(&session->NoUsers);
    } else {
        session = NULL;
    }
    KeReleaseSpinLock(&g_Lock, irql);
    return session;
}

static VOID
HvPrivateDebugObjectReleaseSession(
    _In_ PHV_PRIVATE_DEBUG_SESSION Session)
{
    if (!Session) return;
    if (InterlockedDecrement(&Session->ActiveUsers) == 0) {
        KeSetEvent(&Session->NoUsers, IO_NO_INCREMENT, FALSE);
    }
}

static PHV_PRIVATE_DBGK_EVENT_NODE
HvPrivateDebugObjectFindEventLocked(
    _In_ PHV_PRIVATE_DEBUG_SESSION Session,
    _In_ ULONG64 Sequence,
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId)
{
    for (PLIST_ENTRY entry = Session->EventList.Flink;
         entry != &Session->EventList;
         entry = entry->Flink) {
        PHV_PRIVATE_DBGK_EVENT_NODE event = CONTAINING_RECORD(
            entry, HV_PRIVATE_DBGK_EVENT_NODE, Link);
        if (event->Sequence == Sequence &&
            event->ProcessId == ProcessId &&
            event->ThreadId == ThreadId) {
            return event;
        }
    }
    return NULL;
}

static VOID
HvPrivateDebugObjectFreeEvent(
    _In_ PHV_PRIVATE_DBGK_EVENT_NODE Event)
{
    if (!Event) return;
    if (Event->Thread) {
        ObDereferenceObject(Event->Thread);
        Event->Thread = NULL;
    }
    if (Event->Process) {
        ObDereferenceObject(Event->Process);
        Event->Process = NULL;
    }
    ExFreePoolWithTag(Event, HV_PRIVATE_DBGK_EVENT_TAG);
}

static VOID
HvPrivateDebugObjectCancelEventsLocked(
    _In_ PHV_PRIVATE_DEBUG_SESSION Session,
    _Out_ PLIST_ENTRY FreeList)
{
    for (PLIST_ENTRY entry = Session->EventList.Flink, next = NULL;
         entry != &Session->EventList;
         entry = next) {
        next = entry->Flink;
        PHV_PRIVATE_DBGK_EVENT_NODE event = CONTAINING_RECORD(
            entry, HV_PRIVATE_DBGK_EVENT_NODE, Link);
        RemoveEntryList(entry);
        event->ContinueStatus = STATUS_DEBUGGER_INACTIVE;
        if (event->Synchronous) {
            KeSetEvent(&event->ContinueEvent, IO_NO_INCREMENT, FALSE);
        } else {
            InsertTailList(FreeList, entry);
        }
    }
}

static VOID
HvPrivateDebugObjectFreeSession(
    _In_ PHV_PRIVATE_DEBUG_SESSION Session)
{
    LIST_ENTRY freeList;
    KIRQL irql;

    if (!Session) return;
    InitializeListHead(&freeList);
    KeAcquireSpinLock(&g_Lock, &irql);
    InterlockedExchange(&Session->DeletePending, TRUE);
    HvPrivateDebugObjectCancelEventsLocked(Session, &freeList);
    KeSetEvent(&Session->EventsPresent, IO_NO_INCREMENT, FALSE);
    KeReleaseSpinLock(&g_Lock, irql);
    while (!IsListEmpty(&freeList)) {
        PLIST_ENTRY entry = RemoveHeadList(&freeList);
        HvPrivateDebugObjectFreeEvent(CONTAINING_RECORD(
            entry, HV_PRIVATE_DBGK_EVENT_NODE, Link));
    }
    if (InterlockedCompareExchange(&Session->ActiveUsers, 0, 0) != 0) {
        (void)KeWaitForSingleObject(
            &Session->NoUsers, Executive, KernelMode, FALSE, NULL);
    }
    {
        NTSTATUS resumeStatus =
            HvPrivateDebugObjectReleaseInitialSuspend(Session);
        if (!NT_SUCCESS(resumeStatus)) {
            DbgPrint("[HV][PrivateDbgk] failed to release initial suspend for PID=%llu: 0x%X\n",
                     (ULONG64)(ULONG_PTR)Session->TargetPid,
                     resumeStatus);
        }
    }
    if (Session->DebuggerProcess) {
        ObDereferenceObject(Session->DebuggerProcess);
        Session->DebuggerProcess = NULL;
    }
    if (Session->TargetProcess) {
        ObDereferenceObject(Session->TargetProcess);
        Session->TargetProcess = NULL;
    }
    ExFreePoolWithTag(Session, HV_PRIVATE_DEBUG_OBJECT_TAG);
}

NTSTATUS HvPrivateDebugObjectInitialize(VOID)
{
    if (InterlockedCompareExchange(&g_Initialized, 0, 0) != 0) {
        return STATUS_SUCCESS;
    }
    KeInitializeSpinLock(&g_Lock);
    InitializeListHead(&g_Sessions);
    RtlZeroMemory(&g_Symbols, sizeof(g_Symbols));
    InterlockedExchange64(&g_DbgkSequence, 0);
    InterlockedExchange(&g_Closing, FALSE);
    InterlockedExchange(&g_Enabled, FALSE);
    InterlockedExchange(&g_Initialized, TRUE);
    return STATUS_SUCCESS;
}

NTSTATUS HvPrivateDebugObjectBeginShutdown(VOID)
{
    if (InterlockedCompareExchange(&g_Initialized, 0, 0) == 0) {
        return STATUS_SUCCESS;
    }
    InterlockedExchange(&g_Closing, TRUE);
    InterlockedExchange(&g_Enabled, FALSE);
    HvPrivateDebugObjectDetachAllSessions();
    HvPrivateDebugObjectRemoveHooks();
    return STATUS_SUCCESS;
}

VOID HvPrivateDebugObjectCleanup(VOID)
{
    if (InterlockedCompareExchange(&g_Initialized, 0, 0) == 0) {
        return;
    }
    HvPrivateDebugObjectDetachAllSessions();
    InterlockedExchange(&g_Enabled, FALSE);
    InterlockedExchange(&g_Closing, FALSE);
    InterlockedExchange(&g_Initialized, FALSE);
}

NTSTATUS HvPrivateDebugObjectSetEnabled(_In_ BOOLEAN Enabled)
{
    NTSTATUS status = STATUS_SUCCESS;

    if (InterlockedCompareExchange(&g_Initialized, 0, 0) == 0) {
        return STATUS_DEVICE_NOT_READY;
    }
    if (InterlockedCompareExchange(&g_Closing, 0, 0) != 0) {
        return STATUS_DELETE_PENDING;
    }
    if (Enabled) {
        InterlockedExchange(&g_Enabled, TRUE);
        if (g_Symbols.NtCreateDebugObject || g_Symbols.DbgkForwardException) {
            status = HvPrivateDebugObjectInstallSyscallHooks();
            if (!NT_SUCCESS(status)) {
                InterlockedExchange(&g_Enabled, FALSE);
                return status;
            }
        }
    } else {
        InterlockedExchange(&g_Enabled, FALSE);
        HvPrivateDebugObjectDetachAllSessions();
        HvPrivateDebugObjectRemoveHooks();
    }
    return STATUS_SUCCESS;
}

BOOLEAN HvPrivateDebugObjectIsEnabled(VOID)
{
    return InterlockedCompareExchange(&g_Enabled, 0, 0) != 0 &&
           InterlockedCompareExchange(&g_Closing, 0, 0) == 0;
}

NTSTATUS HvPrivateDebugObjectBind(
    _In_ HANDLE DebuggerPid,
    _In_ HANDLE TargetPid)
{
    PEPROCESS debuggerProcess = NULL;
    PEPROCESS targetProcess = NULL;
    PHV_PRIVATE_DEBUG_SESSION session = NULL;
    KIRQL irql;
    NTSTATUS status;

    if (!DebuggerPid || !TargetPid || DebuggerPid == TargetPid) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!HvPrivateDebugObjectIsEnabled()) {
        return STATUS_NOT_SUPPORTED;
    }
    status = PsLookupProcessByProcessId(DebuggerPid, &debuggerProcess);
    if (!NT_SUCCESS(status)) return status;
    status = PsLookupProcessByProcessId(TargetPid, &targetProcess);
    if (!NT_SUCCESS(status)) {
        ObDereferenceObject(debuggerProcess);
        return status;
    }

    session = (PHV_PRIVATE_DEBUG_SESSION)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(*session),
        HV_PRIVATE_DEBUG_OBJECT_TAG);
    if (!session) {
        ObDereferenceObject(targetProcess);
        ObDereferenceObject(debuggerProcess);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(session, sizeof(*session));
    session->DebuggerPid = DebuggerPid;
    session->TargetPid = TargetPid;
    session->DebuggerProcess = debuggerProcess;
    session->TargetProcess = targetProcess;
    session->DebuggerCreateTime = (UINT64)PsGetProcessCreateTimeQuadPart(debuggerProcess);
    session->TargetCreateTime = (UINT64)PsGetProcessCreateTimeQuadPart(targetProcess);
    KeInitializeEvent(&session->EventsPresent, NotificationEvent, FALSE);
    KeInitializeEvent(&session->NoUsers, NotificationEvent, TRUE);
    InitializeListHead(&session->EventList);
    session->ActiveUsers = 0;

    KeAcquireSpinLock(&g_Lock, &irql);
    if (InterlockedCompareExchange(&g_Closing, 0, 0) != 0) {
        status = STATUS_DELETE_PENDING;
    } else {
        PHV_PRIVATE_DEBUG_SESSION existing = HvPrivateDebugObjectFindLocked(
            DebuggerPid, TargetPid);
        PHV_PRIVATE_DEBUG_SESSION targetOwner = HvPrivateDebugObjectFindLocked(
            NULL, TargetPid);
        if (existing || (targetOwner && targetOwner->DebuggerPid == DebuggerPid)) {
            status = STATUS_SUCCESS;
        } else if (targetOwner && targetOwner->DebuggerPid != DebuggerPid) {
            status = STATUS_SHARING_VIOLATION;
        } else if (HvPrivateDebugObjectFindLocked(DebuggerPid, NULL) == NULL &&
                   HvPrivateDebugObjectFindLocked(NULL, TargetPid) == NULL) {
            ULONG count = 0;
            PLIST_ENTRY entry;
            for (entry = g_Sessions.Flink;
                 entry != &g_Sessions;
                 entry = entry->Flink) {
                ++count;
            }
            if (count >= HV_PRIVATE_DEBUG_OBJECT_MAX_SESSIONS) {
                status = STATUS_INSUFFICIENT_RESOURCES;
            } else {
                InsertTailList(&g_Sessions, &session->Link);
                session = NULL;
                status = STATUS_SUCCESS;
            }
        } else {
            InsertTailList(&g_Sessions, &session->Link);
            session = NULL;
            status = STATUS_SUCCESS;
        }
    }
    KeReleaseSpinLock(&g_Lock, irql);

    if (session) HvPrivateDebugObjectFreeSession(session);
    if (NT_SUCCESS(status)) {
        HvPebCloakSetPrivateDbgkTarget(TargetPid, TRUE);
    }
    return status;
}

NTSTATUS HvPrivateDebugObjectUnbind(
    _In_ HANDLE DebuggerPid,
    _In_ HANDLE TargetPid)
{
    KIRQL irql;
    PHV_PRIVATE_DEBUG_SESSION session = NULL;

    KeAcquireSpinLock(&g_Lock, &irql);
    session = HvPrivateDebugObjectFindLocked(DebuggerPid, TargetPid);
    if (session) {
        RemoveEntryList(&session->Link);
        InterlockedExchange(&session->DeletePending, TRUE);
        KeSetEvent(&session->EventsPresent, IO_NO_INCREMENT, FALSE);
    }
    KeReleaseSpinLock(&g_Lock, irql);
    if (!session) return STATUS_NOT_FOUND;
    HvPebCloakSetPrivateDbgkTarget(TargetPid, FALSE);
    HvPrivateDebugObjectFreeSession(session);
    return STATUS_SUCCESS;
}

VOID HvPrivateDebugObjectUnbindAllForDebugger(_In_ HANDLE DebuggerPid)
{
    KIRQL irql;
    LIST_ENTRY freeList;
    InitializeListHead(&freeList);
    KeAcquireSpinLock(&g_Lock, &irql);
    for (PLIST_ENTRY entry = g_Sessions.Flink, next = NULL;
         entry != &g_Sessions;
         entry = next) {
        next = entry->Flink;
        PHV_PRIVATE_DEBUG_SESSION session = CONTAINING_RECORD(
            entry, HV_PRIVATE_DEBUG_SESSION, Link);
        if (session->DebuggerPid == DebuggerPid) {
            RemoveEntryList(entry);
        InterlockedExchange(&session->DeletePending, TRUE);
        KeSetEvent(&session->EventsPresent, IO_NO_INCREMENT, FALSE);
            InsertTailList(&freeList, entry);
        }
    }
    KeReleaseSpinLock(&g_Lock, irql);
    while (!IsListEmpty(&freeList)) {
        PLIST_ENTRY entry = RemoveHeadList(&freeList);
        PHV_PRIVATE_DEBUG_SESSION session = CONTAINING_RECORD(
            entry, HV_PRIVATE_DEBUG_SESSION, Link);
        HvPebCloakSetPrivateDbgkTarget(session->TargetPid, FALSE);
        HvPrivateDebugObjectFreeSession(session);
    }
}

VOID HvPrivateDebugObjectUnbindOnProcessExit(_In_ HANDLE ProcessId)
{
    KIRQL irql;
    LIST_ENTRY freeList;
    InitializeListHead(&freeList);
    KeAcquireSpinLock(&g_Lock, &irql);
    for (PLIST_ENTRY entry = g_Sessions.Flink, next = NULL;
         entry != &g_Sessions;
         entry = next) {
        next = entry->Flink;
        PHV_PRIVATE_DEBUG_SESSION session = CONTAINING_RECORD(
            entry, HV_PRIVATE_DEBUG_SESSION, Link);
        if (session->DebuggerPid == ProcessId ||
            (session->TargetPid == ProcessId &&
             InterlockedCompareExchange(
                 &session->ExitEventQueued, 0, 0) == FALSE)) {
            RemoveEntryList(entry);
            InterlockedExchange(&session->DeletePending, TRUE);
            KeSetEvent(&session->EventsPresent, IO_NO_INCREMENT, FALSE);
            InsertTailList(&freeList, entry);
        }
    }
    KeReleaseSpinLock(&g_Lock, irql);
    while (!IsListEmpty(&freeList)) {
        PLIST_ENTRY entry = RemoveHeadList(&freeList);
        PHV_PRIVATE_DEBUG_SESSION session = CONTAINING_RECORD(
            entry, HV_PRIVATE_DEBUG_SESSION, Link);
        HvPebCloakSetPrivateDbgkTarget(session->TargetPid, FALSE);
        HvPrivateDebugObjectFreeSession(session);
    }
}

BOOLEAN HvPrivateDebugObjectIsTarget(_In_ HANDLE TargetPid)
{
    KIRQL irql;
    BOOLEAN found;
    if (!HvPrivateDebugObjectIsEnabled() || !TargetPid) return FALSE;
    KeAcquireSpinLock(&g_Lock, &irql);
    found = HvPrivateDebugObjectFindLocked(NULL, TargetPid) != NULL;
    KeReleaseSpinLock(&g_Lock, irql);
    return found;
}

BOOLEAN HvPrivateDebugObjectIsBound(
    _In_ HANDLE DebuggerPid,
    _In_ HANDLE TargetPid)
{
    KIRQL irql;
    BOOLEAN found;
    if (!HvPrivateDebugObjectIsEnabled()) return FALSE;
    KeAcquireSpinLock(&g_Lock, &irql);
    found = HvPrivateDebugObjectFindLocked(DebuggerPid, TargetPid) != NULL;
    KeReleaseSpinLock(&g_Lock, irql);
    return found;
}

HANDLE HvPrivateDebugObjectGetDebugger(_In_ HANDLE TargetPid)
{
    KIRQL irql;
    HANDLE debuggerPid = NULL;
    PHV_PRIVATE_DEBUG_SESSION session = NULL;
    if (!HvPrivateDebugObjectIsEnabled()) return NULL;
    KeAcquireSpinLock(&g_Lock, &irql);
    session = HvPrivateDebugObjectFindLocked(NULL, TargetPid);
    if (session && !InterlockedCompareExchange(&session->DeletePending, 0, 0)) {
        debuggerPid = session->DebuggerPid;
    }
    KeReleaseSpinLock(&g_Lock, irql);
    return debuggerPid;
}

VOID HvPrivateDebugObjectGetStatus(
    _Out_ PHV_PRIVATE_DEBUG_OBJECT_STATUS Status)
{
    KIRQL irql;
    ULONG sessionCount = 0;
    ULONG deletePendingCount = 0;
    if (!Status) return;
    RtlZeroMemory(Status, sizeof(*Status));
    Status->Version = HV_PRIVATE_DEBUG_OBJECT_VERSION;
    Status->Enabled = HvPrivateDebugObjectIsEnabled() ? 1UL : 0UL;
    if (InterlockedCompareExchange(&g_Initialized, 0, 0) == 0) return;
    KeAcquireSpinLock(&g_Lock, &irql);
    for (PLIST_ENTRY entry = g_Sessions.Flink;
         entry != &g_Sessions;
         entry = entry->Flink) {
        PHV_PRIVATE_DEBUG_SESSION session = CONTAINING_RECORD(
            entry, HV_PRIVATE_DEBUG_SESSION, Link);
        ++sessionCount;
        if (InterlockedCompareExchange(&session->DeletePending, 0, 0) != 0) {
            ++deletePendingCount;
        }
    }
    KeReleaseSpinLock(&g_Lock, irql);
    Status->SessionCount = sessionCount;
    Status->DeletePendingCount = deletePendingCount;
}

#ifndef DBG_EXCEPTION_HANDLED
#define DBG_EXCEPTION_HANDLED     ((NTSTATUS)0x00010001L)
#define DBG_CONTINUE              ((NTSTATUS)0x00010002L)
#define DBG_TERMINATE_THREAD      ((NTSTATUS)0x40010003L)
#define DBG_TERMINATE_PROCESS     ((NTSTATUS)0x40010004L)
#define DBG_EXCEPTION_NOT_HANDLED ((NTSTATUS)0x80010001L)
#endif

typedef struct _HV_DBGUI_WAIT_STATE_CHANGE {
    ULONG NewState;
    ULONG Reserved;
    CLIENT_ID AppClientId;
    union {
        struct {
            HANDLE HandleToThread;
            struct {
                ULONG SubSystemKey;
                ULONG Reserved;
                PVOID StartAddress;
            } NewThread;
        } CreateThread;
        struct {
            HANDLE HandleToProcess;
            HANDLE HandleToThread;
            struct {
                ULONG SubSystemKey;
                ULONG Reserved;
                HANDLE FileHandle;
                PVOID BaseOfImage;
                ULONG DebugInfoFileOffset;
                ULONG DebugInfoSize;
                struct {
                    ULONG SubSystemKey;
                    ULONG Reserved;
                    PVOID StartAddress;
                } InitialThread;
            } NewProcess;
        } CreateProcessInfo;
        struct { NTSTATUS ExitStatus; } ExitThread;
        struct { NTSTATUS ExitStatus; } ExitProcess;
        struct {
            EXCEPTION_RECORD ExceptionRecord;
            ULONG FirstChance;
        } Exception;
        struct {
            HANDLE FileHandle;
            PVOID BaseOfDll;
            ULONG DebugInfoFileOffset;
            ULONG DebugInfoSize;
            PVOID NamePointer;
        } LoadDll;
        struct { PVOID BaseAddress; } UnloadDll;
    } StateInfo;
} HV_DBGUI_WAIT_STATE_CHANGE, *PHV_DBGUI_WAIT_STATE_CHANGE;

typedef PETHREAD (NTAPI *PFN_PsGetNextProcessThread)(
    _In_ PEPROCESS Process,
    _In_opt_ PETHREAD Thread);
typedef NTSTATUS (NTAPI *PFN_PsSuspendResumeProcess)(_In_ PEPROCESS Process);

static PFN_PsGetNextProcessThread HvPrivateDebugObjectGetNextThreadRoutine(VOID)
{
    return (PFN_PsGetNextProcessThread)g_Symbols.PsGetNextProcessThread;
}

static NTSTATUS HvPrivateDebugObjectSuspendResumeProcess(
    _In_ PEPROCESS Process,
    _In_ BOOLEAN Suspend)
{
    static PFN_PsSuspendResumeProcess suspendRoutine = NULL;
    static PFN_PsSuspendResumeProcess resumeRoutine = NULL;
    static volatile LONG resolved = FALSE;
    if (!Process) return STATUS_INVALID_PARAMETER;
    if (InterlockedCompareExchange(&resolved, TRUE, FALSE) == FALSE) {
        UNICODE_STRING name;
        RtlInitUnicodeString(&name, L"PsSuspendProcess");
        suspendRoutine = (PFN_PsSuspendResumeProcess)
            MmGetSystemRoutineAddress(&name);
        RtlInitUnicodeString(&name, L"PsResumeProcess");
        resumeRoutine = (PFN_PsSuspendResumeProcess)
            MmGetSystemRoutineAddress(&name);
    }
    PFN_PsSuspendResumeProcess routine = Suspend
        ? suspendRoutine : resumeRoutine;
    return routine ? routine(Process) : STATUS_PROCEDURE_NOT_FOUND;
}

static NTSTATUS HvPrivateDebugObjectReleaseInitialSuspend(
    _In_ PHV_PRIVATE_DEBUG_SESSION Session)
{
    NTSTATUS status;

    if (!Session ||
        InterlockedCompareExchange(
            &Session->InitialSuspendOwned, FALSE, TRUE) != TRUE) {
        return STATUS_SUCCESS;
    }
    if (!Session->TargetProcess ||
        PsGetProcessExitStatus(Session->TargetProcess) != STATUS_PENDING) {
        return STATUS_SUCCESS;
    }

    status = HvPrivateDebugObjectSuspendResumeProcess(
        Session->TargetProcess, FALSE);
    if (!NT_SUCCESS(status)) {
        InterlockedExchange(&Session->InitialSuspendOwned, TRUE);
    }
    return status;
}

static NTSTATUS
HvPrivateDebugObjectOpenEventHandles(
    _In_ PHV_PRIVATE_DBGK_EVENT_NODE Event,
    _Inout_ PHV_BRIDGE_DBGK_EVENT Wire)
{
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE processHandle = NULL;
    HANDLE threadHandle = NULL;

    if (Event->Process &&
        (Event->State == HV_BRIDGE_DBGK_CREATE_PROCESS)) {
        status = ObOpenObjectByPointer(
            Event->Process, 0, NULL, PROCESS_ALL_ACCESS,
            *PsProcessType, KernelMode, &processHandle);
        if (!NT_SUCCESS(status)) return status;
    }
    if (Event->Thread &&
        (Event->State == HV_BRIDGE_DBGK_CREATE_PROCESS ||
         Event->State == HV_BRIDGE_DBGK_CREATE_THREAD)) {
        status = ObOpenObjectByPointer(
            Event->Thread, 0, NULL, THREAD_ALL_ACCESS,
            *PsThreadType, KernelMode, &threadHandle);
        if (!NT_SUCCESS(status)) {
            if (processHandle) ZwClose(processHandle);
            return status;
        }
    }

    Wire->ProcessHandle = (ULONG64)(ULONG_PTR)processHandle;
    Wire->ThreadHandle = (ULONG64)(ULONG_PTR)threadHandle;
    return STATUS_SUCCESS;
}

static NTSTATUS
HvPrivateDebugObjectQueueEventOwned(
    _In_opt_ HANDLE DebuggerPid,
    _In_ HANDLE TargetPid,
    _In_opt_ PETHREAD Thread,
    _In_ ULONG State,
    _In_ ULONG Flags,
    _In_opt_ const HV_BRIDGE_DBGK_EVENT* Template,
    _In_ BOOLEAN Synchronous,
    _Out_opt_ PNTSTATUS ContinueStatus)
{
    PHV_PRIVATE_DEBUG_SESSION session;
    PHV_PRIVATE_DBGK_EVENT_NODE event;
    NTSTATUS status = STATUS_SUCCESS;
    BOOLEAN exitEventClaimed = FALSE;
    KIRQL irql;

    session = HvPrivateDebugObjectAcquireSession(DebuggerPid, TargetPid);
    if (!session) return STATUS_PORT_NOT_SET;

    if (State == HV_BRIDGE_DBGK_EXIT_PROCESS) {
        if (InterlockedCompareExchange(
                &session->ExitEventQueued, TRUE, FALSE) != FALSE) {
            HvPrivateDebugObjectReleaseSession(session);
            return STATUS_OBJECT_NAME_EXISTS;
        }
        exitEventClaimed = TRUE;
    }

    event = (PHV_PRIVATE_DBGK_EVENT_NODE)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(*event), HV_PRIVATE_DBGK_EVENT_TAG);
    if (!event) {
        if (exitEventClaimed) {
            InterlockedExchange(&session->ExitEventQueued, FALSE);
        }
        HvPrivateDebugObjectReleaseSession(session);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(event, sizeof(*event));
    event->Sequence = (ULONG64)InterlockedIncrement64(&g_DbgkSequence);
    event->ProcessId = TargetPid;
    event->ThreadId = Thread ? PsGetThreadId(Thread) : NULL;
    event->Process = session->TargetProcess;
    event->Thread = Thread;
    event->State = State;
    event->Flags = Flags | (Synchronous ? HV_BRIDGE_DBGK_EVENT_SYNCHRONOUS : 0);
    event->ContinueStatus = DBG_CONTINUE;
    event->Synchronous = Synchronous;
    KeInitializeEvent(&event->ContinueEvent, SynchronizationEvent, FALSE);
    if (event->Process) ObReferenceObject(event->Process);
    if (event->Thread) ObReferenceObject(event->Thread);
    if (Template) event->Wire = *Template;
    event->Wire.Sequence = event->Sequence;
    event->Wire.ProcessId = (ULONG)(ULONG_PTR)event->ProcessId;
    event->Wire.ThreadId = (ULONG)(ULONG_PTR)event->ThreadId;
    event->Wire.State = State;
    event->Wire.Flags = event->Flags;

    KeAcquireSpinLock(&g_Lock, &irql);
    if (InterlockedCompareExchange(&session->DeletePending, 0, 0) != 0 ||
        InterlockedCompareExchange(&g_Closing, 0, 0) != 0) {
        status = STATUS_DEBUGGER_INACTIVE;
    } else {
        InsertTailList(&session->EventList, &event->Link);
        KeSetEvent(&session->EventsPresent, IO_NO_INCREMENT, FALSE);
    }
    KeReleaseSpinLock(&g_Lock, irql);

    if (!NT_SUCCESS(status)) {
        if (exitEventClaimed) {
            InterlockedExchange(&session->ExitEventQueued, FALSE);
        }
        HvPrivateDebugObjectFreeEvent(event);
        HvPrivateDebugObjectReleaseSession(session);
        return status;
    }

    if (Synchronous) {
        status = KeWaitForSingleObject(
            &event->ContinueEvent, Executive, KernelMode, FALSE, NULL);
        if (NT_SUCCESS(status)) status = event->ContinueStatus;
        if (ContinueStatus) *ContinueStatus = event->ContinueStatus;
        HvPrivateDebugObjectFreeEvent(event);
    }
    HvPrivateDebugObjectReleaseSession(session);
    return status;
}

static NTSTATUS
HvPrivateDebugObjectQueueEvent(
    _In_ HANDLE TargetPid,
    _In_opt_ PETHREAD Thread,
    _In_ ULONG State,
    _In_ ULONG Flags,
    _In_opt_ const HV_BRIDGE_DBGK_EVENT* Template,
    _In_ BOOLEAN Synchronous,
    _Out_opt_ PNTSTATUS ContinueStatus)
{
    return HvPrivateDebugObjectQueueEventOwned(
        NULL,
        TargetPid,
        Thread,
        State,
        Flags,
        Template,
        Synchronous,
        ContinueStatus);
}

NTSTATUS HvPrivateDebugObjectNotifyProcessExit(
    _In_ PEPROCESS Process,
    _In_ HANDLE ProcessId)
{
    HV_BRIDGE_DBGK_EVENT event = { 0 };
    PETHREAD thread;
    NTSTATUS exitStatus;
    NTSTATUS status;

    if (!Process || !ProcessId || PsGetProcessId(Process) != ProcessId) {
        return STATUS_INVALID_CID;
    }
    thread = PsGetCurrentThread();
    if (!thread || PsGetThreadProcessId(thread) != ProcessId) {
        return STATUS_INVALID_CID;
    }

    exitStatus = PsGetProcessExitStatus(Process);
    event.ExitStatus = exitStatus == STATUS_PENDING
        ? STATUS_SUCCESS
        : exitStatus;
    status = HvPrivateDebugObjectQueueEvent(
        ProcessId,
        thread,
        HV_BRIDGE_DBGK_EXIT_PROCESS,
        0,
        &event,
        FALSE,
        NULL);
    return status == STATUS_OBJECT_NAME_EXISTS ? STATUS_SUCCESS : status;
}

static NTSTATUS HvPrivateDebugObjectQueueInitialProcess(
    _In_ HANDLE DebuggerPid,
    _In_ HANDLE TargetPid)
{
    PHV_PRIVATE_DEBUG_SESSION session;
    PFN_PsGetNextProcessThread nextThread;
    PETHREAD thread = NULL;
    HV_BRIDGE_DBGK_EVENT event;
    NTSTATUS status = STATUS_SUCCESS;

    session = HvPrivateDebugObjectAcquireSession(DebuggerPid, TargetPid);
    if (!session) return STATUS_NOT_FOUND;
    if (InterlockedCompareExchange(
            &session->InitialEventQueued, TRUE, FALSE) != FALSE) {
        HvPrivateDebugObjectReleaseSession(session);
        return STATUS_OBJECT_NAME_EXISTS;
    }

    RtlZeroMemory(&event, sizeof(event));
    event.Flags = HV_BRIDGE_DBGK_EVENT_INITIAL;
    event.BaseAddress = (ULONG64)(ULONG_PTR)
        PsGetProcessSectionBaseAddress(session->TargetProcess);

    nextThread = HvPrivateDebugObjectGetNextThreadRoutine();
    if (nextThread) thread = nextThread(session->TargetProcess, NULL);
    if (thread) {
        status = HvPrivateDebugObjectSuspendResumeProcess(
            session->TargetProcess, TRUE);
        if (!NT_SUCCESS(status)) {
            ObDereferenceObject(thread);
            thread = NULL;
        } else {
            InterlockedExchange(&session->InitialSuspendOwned, TRUE);
        }
    }
    if (!thread) {
        InterlockedExchange(&session->InitialEventQueued, FALSE);
        HvPrivateDebugObjectReleaseSession(session);
        return NT_SUCCESS(status) ? STATUS_NOT_FOUND : status;
    }

    event.StartAddress = event.BaseAddress;
    status = HvPrivateDebugObjectQueueEvent(
        TargetPid, thread, HV_BRIDGE_DBGK_CREATE_PROCESS,
        HV_BRIDGE_DBGK_EVENT_INITIAL, &event, FALSE, NULL);
    if (!NT_SUCCESS(status)) {
        (void)HvPrivateDebugObjectReleaseInitialSuspend(session);
        InterlockedExchange(&session->InitialEventQueued, FALSE);
    }
    HvPrivateDebugObjectReleaseSession(session);
    ObDereferenceObject(thread);
    return status;
}

NTSTATUS HvPrivateDebugObjectWait(
    _In_ HANDLE DebuggerPid,
    _Out_ PHV_BRIDGE_DBGK_EVENT Event,
    _In_ ULONG TimeoutMs)
{
    PHV_PRIVATE_DEBUG_SESSION session;
    LARGE_INTEGER timeout;
    PLARGE_INTEGER timeoutPointer = NULL;
    NTSTATUS status;

    if (!Event || !DebuggerPid) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(Event, sizeof(*Event));
    session = HvPrivateDebugObjectAcquireSession(DebuggerPid, NULL);
    if (!session) return STATUS_PORT_NOT_SET;

    if (TimeoutMs == 0) {
        timeout.QuadPart = 0;
        timeoutPointer = &timeout;
    } else if (TimeoutMs != MAXULONG) {
        timeout.QuadPart = -(LONGLONG)TimeoutMs * 10000LL;
        timeoutPointer = &timeout;
    }

    for (;;) {
        PHV_PRIVATE_DBGK_EVENT_NODE selected = NULL;
        KIRQL irql;

        KeAcquireSpinLock(&g_Lock, &irql);
        if (InterlockedCompareExchange(&session->DeletePending, 0, 0) != 0) {
            KeReleaseSpinLock(&g_Lock, irql);
            status = STATUS_DEBUGGER_INACTIVE;
            break;
        }
        for (PLIST_ENTRY entry = session->EventList.Flink;
             entry != &session->EventList;
             entry = entry->Flink) {
            PHV_PRIVATE_DBGK_EVENT_NODE candidate = CONTAINING_RECORD(
                entry, HV_PRIVATE_DBGK_EVENT_NODE, Link);
            if (!candidate->Delivered) {
                candidate->Delivered = TRUE;
                candidate->Wire.Flags |= HV_BRIDGE_DBGK_EVENT_DELIVERED;
                selected = candidate;
                break;
            }
        }
        if (!selected) KeClearEvent(&session->EventsPresent);
        KeReleaseSpinLock(&g_Lock, irql);

        if (selected) {
            *Event = selected->Wire;
            status = HvPrivateDebugObjectOpenEventHandles(selected, Event);
            if (!NT_SUCCESS(status)) {
                KeAcquireSpinLock(&g_Lock, &irql);
                selected->Delivered = FALSE;
                selected->Wire.Flags &= ~HV_BRIDGE_DBGK_EVENT_DELIVERED;
                KeSetEvent(&session->EventsPresent, IO_NO_INCREMENT, FALSE);
                KeReleaseSpinLock(&g_Lock, irql);
            }
            break;
        }

        status = KeWaitForSingleObject(
            &session->EventsPresent, Executive, KernelMode, FALSE,
            timeoutPointer);
        if (status == STATUS_TIMEOUT || !NT_SUCCESS(status)) break;
    }

    HvPrivateDebugObjectReleaseSession(session);
    return status;
}

NTSTATUS HvPrivateDebugObjectContinue(
    _In_ HANDLE DebuggerPid,
    _In_ const HV_BRIDGE_DBGK_CONTINUE_REQUEST* Request)
{
    PHV_PRIVATE_DEBUG_SESSION session;
    PHV_PRIVATE_DBGK_EVENT_NODE event;
    BOOLEAN freeEvent = FALSE;
    BOOLEAN releaseInitialSuspend = FALSE;
    KIRQL irql;

    if (!Request || Request->Version != HV_BRIDGE_PROTOCOL_VERSION ||
        !Request->Sequence || !Request->ProcessId || !Request->ThreadId) {
        return STATUS_INVALID_PARAMETER;
    }
    switch ((NTSTATUS)Request->ContinueStatus) {
    case DBG_EXCEPTION_HANDLED:
    case DBG_EXCEPTION_NOT_HANDLED:
    case DBG_TERMINATE_THREAD:
    case DBG_TERMINATE_PROCESS:
    case DBG_CONTINUE:
        break;
    default:
        return STATUS_INVALID_PARAMETER;
    }

    session = HvPrivateDebugObjectAcquireSession(
        DebuggerPid, (HANDLE)(ULONG_PTR)Request->ProcessId);
    if (!session) return STATUS_PORT_NOT_SET;

    KeAcquireSpinLock(&g_Lock, &irql);
    event = HvPrivateDebugObjectFindEventLocked(
        session, Request->Sequence,
        (HANDLE)(ULONG_PTR)Request->ProcessId,
        (HANDLE)(ULONG_PTR)Request->ThreadId);
    if (!event || !event->Delivered) {
        KeReleaseSpinLock(&g_Lock, irql);
        HvPrivateDebugObjectReleaseSession(session);
        return STATUS_INVALID_PARAMETER;
    }
    RemoveEntryList(&event->Link);
    event->ContinueStatus = (NTSTATUS)Request->ContinueStatus;
    freeEvent = !event->Synchronous;
    if ((event->Flags & HV_BRIDGE_DBGK_EVENT_VT_HWBP) != 0 &&
        event->Thread && event->ProcessId) {
        const ULONG64 generation =
            event->Wire.ExceptionInformation[
                HV_BRIDGE_DBGK_VT_GENERATION_INDEX];
        if (generation != 0) {
            (void)HvVwatchRetirePendingHardwareHitOwned(
                event->Thread,
                DebuggerPid,
                event->ProcessId,
                generation);
        } else {
            HvVwatchAcknowledgePendingHardwareHit(
                event->Thread, event->ProcessId, 0);
        }
    }
    if ((event->Flags & HV_BRIDGE_DBGK_EVENT_INITIAL) != 0 &&
        event->Process) {
        releaseInitialSuspend = TRUE;
    }
    if (event->Synchronous) {
        KeSetEvent(&event->ContinueEvent, IO_NO_INCREMENT, FALSE);
    }
    KeReleaseSpinLock(&g_Lock, irql);

    if (releaseInitialSuspend &&
        Request->ContinueStatus != (ULONG)DBG_TERMINATE_PROCESS) {
        NTSTATUS resumeStatus =
            HvPrivateDebugObjectReleaseInitialSuspend(session);
        if (!NT_SUCCESS(resumeStatus)) {
            KeAcquireSpinLock(&g_Lock, &irql);
            if (InterlockedCompareExchange(
                    &session->DeletePending, 0, 0) == 0) {
                InsertHeadList(&session->EventList, &event->Link);
                freeEvent = FALSE;
            }
            KeReleaseSpinLock(&g_Lock, irql);
            HvPrivateDebugObjectReleaseSession(session);
            if (freeEvent) HvPrivateDebugObjectFreeEvent(event);
            return resumeStatus;
        }
    }
    if (freeEvent) HvPrivateDebugObjectFreeEvent(event);
    HvPrivateDebugObjectReleaseSession(session);
    return STATUS_SUCCESS;
}

NTSTATUS HvPrivateDebugObjectDetach(
    _In_ HANDLE DebuggerPid,
    _In_ HANDLE TargetPid)
{
    return HvPrivateDebugObjectUnbind(DebuggerPid, TargetPid);
}

NTSTATUS HvPrivateDebugObjectAttach(
    _In_ HANDLE DebuggerPid,
    _In_ HANDLE ProcessHandle,
    _Out_opt_ HANDLE* TargetPid)
{
    PEPROCESS process = NULL;
    HANDLE targetPid;
    NTSTATUS status;

    if (TargetPid) *TargetPid = NULL;
    if (!HvPrivateDebugObjectIsEnabled() || !DebuggerPid || !ProcessHandle) {
        return STATUS_NOT_SUPPORTED;
    }
    status = ObReferenceObjectByHandle(
        ProcessHandle, 0,
        *PsProcessType, KernelMode, (PVOID*)&process, NULL);
    if (!NT_SUCCESS(status)) return status;
    targetPid = PsGetProcessId(process);
    if (!targetPid || targetPid == DebuggerPid) {
        ObDereferenceObject(process);
        return STATUS_INVALID_CID;
    }
    if (!HvHookIsBoundTargetForDebugger(
            (ULONG)(ULONG_PTR)targetPid,
            (ULONG)(ULONG_PTR)DebuggerPid)) {
        ObDereferenceObject(process);
        return STATUS_ACCESS_DENIED;
    }
    status = HvPrivateDebugObjectBind(DebuggerPid, targetPid);
    if (NT_SUCCESS(status)) {
        NTSTATUS queueStatus = HvPrivateDebugObjectQueueInitialProcess(
            DebuggerPid, targetPid);
        if (queueStatus == STATUS_OBJECT_NAME_EXISTS) {
            queueStatus = STATUS_SUCCESS;
        }
        status = queueStatus;
    }
    if (NT_SUCCESS(status) && TargetPid) *TargetPid = targetPid;
    ObDereferenceObject(process);
    return status;
}

static VOID HvPrivateDebugObjectDetachAllSessions(VOID)
{
    LIST_ENTRY freeList;
    KIRQL irql;
    InitializeListHead(&freeList);
    KeAcquireSpinLock(&g_Lock, &irql);
    while (!IsListEmpty(&g_Sessions)) {
        PLIST_ENTRY entry = RemoveHeadList(&g_Sessions);
        PHV_PRIVATE_DEBUG_SESSION session = CONTAINING_RECORD(
            entry, HV_PRIVATE_DEBUG_SESSION, Link);
        InterlockedExchange(&session->DeletePending, TRUE);
        KeSetEvent(&session->EventsPresent, IO_NO_INCREMENT, FALSE);
        InsertTailList(&freeList, entry);
    }
    KeReleaseSpinLock(&g_Lock, irql);
    while (!IsListEmpty(&freeList)) {
        PLIST_ENTRY entry = RemoveHeadList(&freeList);
        PHV_PRIVATE_DEBUG_SESSION session = CONTAINING_RECORD(
            entry, HV_PRIVATE_DEBUG_SESSION, Link);
        HvPebCloakSetPrivateDbgkTarget(session->TargetPid, FALSE);
        HvPrivateDebugObjectFreeSession(session);
    }
}

static BOOLEAN HvPrivateDebugObjectIsPrivateCaller(VOID)
{
    HANDLE caller = PsGetCurrentProcessId();
    return HvPrivateDebugObjectIsEnabled() &&
           ExGetPreviousMode() != KernelMode &&
           HvHookIsDebuggerPid(caller);
}

static NTSTATUS NTAPI HvPrivateHookNtCreateDebugObject(
    _Out_ PHANDLE DebugHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ ULONG Flags)
{
    HV_PRIVATE_HOOK_BEGIN(hook, g_HookNtCreateDebugObject, STATUS_DELETE_PENDING)
    UNREFERENCED_PARAMETER(DesiredAccess);
    UNREFERENCED_PARAMETER(ObjectAttributes);
    UNREFERENCED_PARAMETER(Flags);
    if (!HvPrivateDebugObjectIsPrivateCaller()) {
        PFN_NtCreateDebugObject original = (PFN_NtCreateDebugObject)
            HvHookGetTrampoline(hook);
        return original ? original(DebugHandle, DesiredAccess,
                                    ObjectAttributes, Flags) : STATUS_UNSUCCESSFUL;
    }
    if (!DebugHandle) return STATUS_INVALID_PARAMETER;
    __try {
        HANDLE eventHandle = NULL;
        NTSTATUS status = ZwCreateEvent(
            &eventHandle, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE);
        if (NT_SUCCESS(status)) *DebugHandle = eventHandle;
        return status;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }
    HV_PRIVATE_HOOK_END(hook)
}

static NTSTATUS NTAPI HvPrivateHookNtSetInformationDebugObject(
    _In_ HANDLE DebugObjectHandle,
    _In_ ULONG DebugObjectInformationClass,
    _In_reads_bytes_(DebugInformationLength) PVOID DebugInformation,
    _In_ ULONG DebugInformationLength,
    _Out_opt_ PULONG ReturnLength)
{
    HV_PRIVATE_HOOK_BEGIN(hook, g_HookNtSetInformationDebugObject, STATUS_DELETE_PENDING)
    if (HvPrivateDebugObjectIsPrivateCaller()) {
        UNREFERENCED_PARAMETER(DebugObjectHandle);
        if (DebugObjectInformationClass == 0) {
            if (ReturnLength) {
                __try { *ReturnLength = 0; }
                __except (EXCEPTION_EXECUTE_HANDLER) {
                    return GetExceptionCode();
                }
            }
            return STATUS_SUCCESS;
        }
        if (DebugObjectInformationClass != 1 ||
            !DebugInformation ||
            DebugInformationLength != sizeof(ULONG)) {
            return STATUS_INFO_LENGTH_MISMATCH;
        }
        __try {
            ULONG killOnClose = *(PULONG)DebugInformation;
            if (killOnClose > 1) return STATUS_INVALID_PARAMETER;
            if (ReturnLength) *ReturnLength = sizeof(ULONG);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return GetExceptionCode();
        }
        return STATUS_SUCCESS;
    }
    PFN_NtSetInformationDebugObject original =
        (PFN_NtSetInformationDebugObject)HvHookGetTrampoline(
            hook);
    return original ? original(DebugObjectHandle, DebugObjectInformationClass,
                               DebugInformation, DebugInformationLength,
                               ReturnLength) : STATUS_UNSUCCESSFUL;
    HV_PRIVATE_HOOK_END(hook)
}

static NTSTATUS NTAPI HvPrivateHookNtWaitForDebugEvent(
    _In_ HANDLE DebugHandle,
    _In_ BOOLEAN Alertable,
    _In_opt_ PLARGE_INTEGER Timeout,
    _Out_ PVOID StateChange)
{
    HV_PRIVATE_HOOK_BEGIN(hook, g_HookNtWaitForDebugEvent, STATUS_DELETE_PENDING)
    UNREFERENCED_PARAMETER(Alertable);
    if (!HvPrivateDebugObjectIsPrivateCaller()) {
        PFN_NtWaitForDebugEvent original = (PFN_NtWaitForDebugEvent)
            HvHookGetTrampoline(hook);
        return original ? original(DebugHandle, Alertable, Timeout, StateChange) :
            STATUS_UNSUCCESSFUL;
    }
    ULONG timeoutMs = MAXULONG;
    if (Timeout) {
        __try {
            LONGLONG value = Timeout->QuadPart;
            timeoutMs = value >= 0 ? 0 :
                (ULONG)min((ULONGLONG)(-(value) / 10000LL), (ULONGLONG)MAXULONG);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return GetExceptionCode();
        }
    }
    HV_BRIDGE_DBGK_EVENT event;
    NTSTATUS status = HvPrivateDebugObjectWait(
        PsGetCurrentProcessId(), &event, timeoutMs);
    if (status != STATUS_SUCCESS) return status;
    __try {
        HV_DBGUI_WAIT_STATE_CHANGE state;
        HvPrivateDebugObjectConvertWaitState(&event, &state);
        RtlCopyMemory(StateChange, &state, sizeof(state));
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }
    return STATUS_SUCCESS;
    HV_PRIVATE_HOOK_END(hook)
}

static NTSTATUS NTAPI HvPrivateHookNtDebugContinue(
    _In_ HANDLE DebugObjectHandle,
    _In_ PCLIENT_ID ClientId,
    _In_ NTSTATUS ContinueStatus)
{
    HV_PRIVATE_HOOK_BEGIN(hook, g_HookNtDebugContinue, STATUS_DELETE_PENDING)
    UNREFERENCED_PARAMETER(DebugObjectHandle);
    if (!HvPrivateDebugObjectIsPrivateCaller()) {
        PFN_NtDebugContinue original = (PFN_NtDebugContinue)
            HvHookGetTrampoline(hook);
        return original ? original(DebugObjectHandle, ClientId, ContinueStatus) :
            STATUS_UNSUCCESSFUL;
    }
    CLIENT_ID client;
    __try { client = *ClientId; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return GetExceptionCode(); }
    HV_BRIDGE_DBGK_CONTINUE_REQUEST request = { 0 };
    request.Version = HV_BRIDGE_PROTOCOL_VERSION;
    request.ContinueStatus = (ULONG)ContinueStatus;
    request.ProcessId = (ULONG)(ULONG_PTR)client.UniqueProcess;
    request.ThreadId = (ULONG)(ULONG_PTR)client.UniqueThread;
    /* NtDebugContinue does not expose the sequence. Continue the first
     * delivered event for this client, preserving native API semantics. */
    PHV_PRIVATE_DEBUG_SESSION session = HvPrivateDebugObjectAcquireSession(
        PsGetCurrentProcessId(), client.UniqueProcess);
    if (!session) return STATUS_PORT_NOT_SET;
    KIRQL irql;
    PHV_PRIVATE_DBGK_EVENT_NODE found = NULL;
    KeAcquireSpinLock(&g_Lock, &irql);
    for (PLIST_ENTRY entry = session->EventList.Flink;
         entry != &session->EventList; entry = entry->Flink) {
        PHV_PRIVATE_DBGK_EVENT_NODE candidate = CONTAINING_RECORD(
            entry, HV_PRIVATE_DBGK_EVENT_NODE, Link);
        if (candidate->Delivered && candidate->ThreadId == client.UniqueThread) {
            found = candidate;
            request.Sequence = candidate->Sequence;
            break;
        }
    }
    KeReleaseSpinLock(&g_Lock, irql);
    HvPrivateDebugObjectReleaseSession(session);
    if (!found) return STATUS_INVALID_PARAMETER;
    return HvPrivateDebugObjectContinue(PsGetCurrentProcessId(), &request);
    HV_PRIVATE_HOOK_END(hook)
}

static NTSTATUS NTAPI HvPrivateHookNtRemoveProcessDebug(
    _In_ HANDLE ProcessHandle,
    _In_ HANDLE DebugObjectHandle)
{
    HV_PRIVATE_HOOK_BEGIN(hook, g_HookNtRemoveProcessDebug, STATUS_DELETE_PENDING)
    if (!HvPrivateDebugObjectIsPrivateCaller()) {
        PFN_NtRemoveProcessDebug original = (PFN_NtRemoveProcessDebug)
            HvHookGetTrampoline(hook);
        return original ? original(ProcessHandle, DebugObjectHandle) :
            STATUS_UNSUCCESSFUL;
    }
    PEPROCESS process = NULL;
    NTSTATUS status = ObReferenceObjectByHandle(
        ProcessHandle, 0, *PsProcessType,
        KernelMode, (PVOID*)&process, NULL);
    if (!NT_SUCCESS(status)) return status;
    HANDLE targetPid = PsGetProcessId(process);
    ObDereferenceObject(process);
    return HvPrivateDebugObjectDetach(PsGetCurrentProcessId(), targetPid);
    HV_PRIVATE_HOOK_END(hook)
}

typedef enum _HV_PRIVATE_EXCEPTION_DISPOSITION {
    HvPrivateExceptionNotTarget = 0,
    HvPrivateExceptionHandled,
    HvPrivateExceptionNotHandled,
    HvPrivateExceptionFailed
} HV_PRIVATE_EXCEPTION_DISPOSITION;

static BOOLEAN
HvPrivateDebugObjectIsSingleStepCode(_In_ NTSTATUS Code)
{
    return Code == STATUS_SINGLE_STEP || Code == STATUS_WX86_SINGLE_STEP;
}

static ULONG
HvPrivateDebugObjectExceptionState(_In_ NTSTATUS Code)
{
    if (Code == STATUS_BREAKPOINT || Code == STATUS_WX86_BREAKPOINT) {
        return HV_BRIDGE_DBGK_BREAKPOINT;
    }
    if (HvPrivateDebugObjectIsSingleStepCode(Code)) {
        return HV_BRIDGE_DBGK_SINGLE_STEP;
    }
    return HV_BRIDGE_DBGK_EXCEPTION;
}

static HV_PRIVATE_EXCEPTION_DISPOSITION
HvPrivateDebugObjectDispatchException(
    _In_ PEXCEPTION_RECORD ExceptionRecord,
    _In_ BOOLEAN SecondChance)
{
    HANDLE targetPid;
    HANDLE debuggerPid;
    HV_BRIDGE_DBGK_EVENT event = { 0 };
    ULONG64 hwbpGeneration = 0;
    ULONG eventFlags = 0;
    NTSTATUS continueStatus = DBG_CONTINUE;
    NTSTATUS status;
    ULONG state;

    if (!ExceptionRecord || KeGetCurrentIrql() > APC_LEVEL) {
        return HvPrivateExceptionFailed;
    }
    targetPid = PsGetCurrentProcessId();
    if (!HvPrivateDebugObjectIsTarget(targetPid)) {
        return HvPrivateExceptionNotTarget;
    }
    debuggerPid = HvPrivateDebugObjectGetDebugger(targetPid);
    if (!debuggerPid) return HvPrivateExceptionNotTarget;

    state = HvPrivateDebugObjectExceptionState(ExceptionRecord->ExceptionCode);
    event.FirstChance = SecondChance ? 0 : 1;
    event.ExceptionCode = ExceptionRecord->ExceptionCode;
    event.ExceptionFlags = ExceptionRecord->ExceptionFlags;
    event.ExceptionAddress =
        (ULONG64)(ULONG_PTR)ExceptionRecord->ExceptionAddress;
    event.NumberParameters = min(
        ExceptionRecord->NumberParameters,
        EXCEPTION_MAXIMUM_PARAMETERS);
    RtlCopyMemory(
        event.ExceptionInformation,
        ExceptionRecord->ExceptionInformation,
        event.NumberParameters * sizeof(ULONG_PTR));
    if (HvPrivateDebugObjectIsSingleStepCode(
            ExceptionRecord->ExceptionCode)) {
        UINT64 virtualDr6 = 0;
        if (HvVwatchQueryPendingHardwareHitOwned(
                PsGetCurrentThread(),
                debuggerPid,
                targetPid,
                &virtualDr6,
                &hwbpGeneration)) {
            eventFlags |= HV_BRIDGE_DBGK_EVENT_VT_HWBP;
            event.ExceptionInformation[
                HV_BRIDGE_DBGK_VT_GENERATION_INDEX] = hwbpGeneration;
            event.ExceptionInformation[HV_BRIDGE_DBGK_VT_DR6_INDEX] =
                virtualDr6 & 0xFULL;
        }
    }

    status = HvPrivateDebugObjectQueueEventOwned(
        debuggerPid,
        targetPid,
        PsGetCurrentThread(),
        state,
        eventFlags,
        &event,
        TRUE,
        &continueStatus);
    if (!NT_SUCCESS(status)) {
        if (hwbpGeneration != 0) {
            (void)HvVwatchRetirePendingHardwareHitOwned(
                PsGetCurrentThread(),
                debuggerPid,
                targetPid,
                hwbpGeneration);
        }
        return HvPrivateExceptionFailed;
    }
    if (continueStatus == DBG_EXCEPTION_NOT_HANDLED) {
        return HvPrivateDebugObjectIsSingleStepCode(
            ExceptionRecord->ExceptionCode)
            ? HvPrivateExceptionHandled
            : HvPrivateExceptionNotHandled;
    }
    return HvPrivateExceptionHandled;
}

static BOOLEAN HvPrivateDebugObjectOwnsSingleStep(VOID)
{
    const ULONG64 dr6 = __readdr(6);
    const ULONG64 breakpointBits = dr6 & 0xFULL;
    const BOOLEAN trapFlagStep = (dr6 & (1ULL << 14)) != 0;
    UINT64 dr0 = 0;
    UINT64 dr1 = 0;
    UINT64 dr2 = 0;
    UINT64 dr3 = 0;
    UINT64 dr7 = 0;
    ULONG virtualSlotMask = 0;

    if (breakpointBits != 0 && HvVwatchBuildVirtualDrState(
            PsGetCurrentProcessId(),
            &dr0,
            &dr1,
            &dr2,
            &dr3,
            &dr7)) {
        UNREFERENCED_PARAMETER(dr0);
        UNREFERENCED_PARAMETER(dr1);
        UNREFERENCED_PARAMETER(dr2);
        UNREFERENCED_PARAMETER(dr3);
        for (ULONG slot = 0; slot < 4; slot++) {
            if ((dr7 & (3ULL << (slot * 2))) != 0) {
                virtualSlotMask |= 1UL << slot;
            }
        }
    }

    return trapFlagStep || breakpointBits == 0 ||
        (breakpointBits & virtualSlotMask) != 0;
}

static BOOLEAN NTAPI HvPrivateHookDbgkForwardException(
    _In_ PEXCEPTION_RECORD ExceptionRecord,
    _In_ BOOLEAN DebugPort,
    _In_ BOOLEAN SecondChance)
{
    HV_HOOK_HANDLE hook = g_HookDbgkForwardException;
    PFN_DbgkForwardException original;
    HV_PRIVATE_EXCEPTION_DISPOSITION disposition;
    BOOLEAN result = FALSE;

    /*
     * Do not use HV_PRIVATE_HOOK_BEGIN/END here.  A return from that
     * __try/__finally scope performs a kernel SEH local unwind.  This hook is
     * itself on the exception-forwarding path, so the unwind can re-enter
     * DbgkForwardException recursively before rundown has been released.
     */
    if (!hook || !HvHookCallbackAcquire(hook)) {
        return FALSE;
    }
    original = (PFN_DbgkForwardException)HvHookGetTrampoline(hook);

    if (!DebugPort || !ExceptionRecord ||
        !HvPrivateDebugObjectIsTarget(PsGetCurrentProcessId())) {
        result = original
            ? original(ExceptionRecord, DebugPort, SecondChance)
            : FALSE;
        goto Exit;
    }
    if (HvPrivateDebugObjectIsSingleStepCode(
            ExceptionRecord->ExceptionCode) &&
        !HvPrivateDebugObjectOwnsSingleStep()) {
        result = original
            ? original(ExceptionRecord, DebugPort, SecondChance)
            : FALSE;
        goto Exit;
    }
    disposition = HvPrivateDebugObjectDispatchException(
        ExceptionRecord,
        SecondChance);
    if (disposition != HvPrivateExceptionHandled) {
        /* The private session already offered this exception to its debugger.
         * FALSE returns it to the target's normal SEH/second-chance path.
         * Re-entering the original DebugPort path here forwards it twice even
         * though private mode deliberately owns no EPROCESS.DebugPort. */
        result = FALSE;
        goto Exit;
    }
    result = TRUE;

Exit:
    HvHookCallbackRelease(hook);
    return result;
}

static VOID NTAPI HvPrivateHookDbgkCreateThread(_In_ PETHREAD Thread)
{
    HV_PRIVATE_HOOK_BEGIN(hook, g_HookDbgkCreateThread, )
    PFN_DbgkCreateThread original = (PFN_DbgkCreateThread)
        HvHookGetTrampoline(hook);
    HANDLE targetPid = PsGetThreadProcessId(Thread);
    if (!HvPrivateDebugObjectIsTarget(targetPid)) {
        if (original) original(Thread);
        return;
    }
    if (original) original(Thread);
    if (!HvPrivateDebugObjectIsTarget(targetPid)) return;
    HV_BRIDGE_DBGK_EVENT event = { 0 };
    (void)HvPrivateDebugObjectQueueEvent(
        targetPid, Thread, HV_BRIDGE_DBGK_CREATE_THREAD, 0,
        &event, TRUE, NULL);
    HV_PRIVATE_HOOK_END(hook)
}

static VOID NTAPI HvPrivateHookDbgkExitThread(_In_ NTSTATUS ExitStatus)
{
    HV_PRIVATE_HOOK_BEGIN(hook, g_HookDbgkExitThread, )
    PFN_DbgkExitThread original = (PFN_DbgkExitThread)
        HvHookGetTrampoline(hook);
    HANDLE targetPid = PsGetCurrentProcessId();
    if (!HvPrivateDebugObjectIsTarget(targetPid)) {
        if (original) original(ExitStatus);
        return;
    }
    HV_BRIDGE_DBGK_EVENT event = { 0 };
    event.ExitStatus = ExitStatus;
    (void)HvPrivateDebugObjectQueueEvent(
        targetPid, PsGetCurrentThread(), HV_BRIDGE_DBGK_EXIT_THREAD,
        0, &event, TRUE, NULL);
    if (original) original(ExitStatus);
    HV_PRIVATE_HOOK_END(hook)
}

static VOID NTAPI HvPrivateHookDbgkExitProcess(_In_ NTSTATUS ExitStatus)
{
    HV_PRIVATE_HOOK_BEGIN(hook, g_HookDbgkExitProcess, )
    PFN_DbgkExitProcess original = (PFN_DbgkExitProcess)
        HvHookGetTrampoline(hook);
    HANDLE targetPid = PsGetCurrentProcessId();
    if (!HvPrivateDebugObjectIsTarget(targetPid)) {
        if (original) original(ExitStatus);
        return;
    }
    HV_BRIDGE_DBGK_EVENT event = { 0 };
    event.ExitStatus = ExitStatus;
    (void)HvPrivateDebugObjectQueueEvent(
        targetPid, PsGetCurrentThread(), HV_BRIDGE_DBGK_EXIT_PROCESS,
        0, &event, TRUE, NULL);
    if (original) original(ExitStatus);
    HV_PRIVATE_HOOK_END(hook)
}

static VOID NTAPI HvPrivateHookDbgkMapViewOfSection(
    _In_ PEPROCESS Process, _In_ PVOID SectionObject,
    _In_ PVOID BaseAddress, _In_ ULONG SectionOffset,
    _In_ SIZE_T ViewSize)
{
    HV_PRIVATE_HOOK_BEGIN(hook, g_HookDbgkMapViewOfSection, )
    PFN_DbgkMapViewOfSection original = (PFN_DbgkMapViewOfSection)
        HvHookGetTrampoline(hook);
    HANDLE targetPid = Process ? PsGetProcessId(Process) : NULL;
    if (!targetPid || !HvPrivateDebugObjectIsTarget(targetPid)) {
        if (original) original(Process, SectionObject, BaseAddress,
                               SectionOffset, ViewSize);
        return;
    }
    if (original) original(Process, SectionObject, BaseAddress,
                           SectionOffset, ViewSize);
    if (!HvPrivateDebugObjectIsTarget(targetPid)) return;
    HV_BRIDGE_DBGK_EVENT event = { 0 };
    event.BaseAddress = (ULONG64)(ULONG_PTR)BaseAddress;
    (void)HvPrivateDebugObjectQueueEvent(
        targetPid, PsGetCurrentThread(), HV_BRIDGE_DBGK_LOAD_DLL,
        0, &event, TRUE, NULL);
    HV_PRIVATE_HOOK_END(hook)
}

static VOID NTAPI HvPrivateHookDbgkUnMapViewOfSection(
    _In_ PEPROCESS Process, _In_ PVOID BaseAddress)
{
    HV_PRIVATE_HOOK_BEGIN(hook, g_HookDbgkUnMapViewOfSection, )
    PFN_DbgkUnMapViewOfSection original = (PFN_DbgkUnMapViewOfSection)
        HvHookGetTrampoline(hook);
    HANDLE targetPid = Process ? PsGetProcessId(Process) : NULL;
    if (!targetPid || !HvPrivateDebugObjectIsTarget(targetPid)) {
        if (original) original(Process, BaseAddress);
        return;
    }
    if (original) original(Process, BaseAddress);
    if (!HvPrivateDebugObjectIsTarget(targetPid)) return;
    HV_BRIDGE_DBGK_EVENT event = { 0 };
    event.BaseAddress = (ULONG64)(ULONG_PTR)BaseAddress;
    (void)HvPrivateDebugObjectQueueEvent(
        targetPid, PsGetCurrentThread(), HV_BRIDGE_DBGK_UNLOAD_DLL,
        0, &event, TRUE, NULL);
    HV_PRIVATE_HOOK_END(hook)
}

static NTSTATUS HvPrivateDebugObjectInstallHook(
    _In_ PVOID Target,
    _In_ PVOID Callback,
    _Inout_ HV_HOOK_HANDLE* Handle,
    _In_ BOOLEAN OverlayVisible)
{
    HV_HOOK_HANDLE prepared = NULL;
    NTSTATUS status;
    NTSTATUS rollbackStatus;

    if (!Handle) return STATUS_INVALID_PARAMETER;
    if (*Handle) return STATUS_SUCCESS;
    if (!Target || !Callback) return STATUS_NOT_FOUND;

    status = HvHookPrepare(Target, Callback, &prepared);
    if (!NT_SUCCESS(status)) {
        if (prepared) {
            InterlockedExchangePointer(
                (PVOID volatile*)Handle, prepared);
        }
        return status;
    }

    if (OverlayVisible) {
        status = HvHookSetOverlayVisiblePrepared(prepared, TRUE);
        if (!NT_SUCCESS(status)) {
            rollbackStatus = HvHookRemove(prepared);
            if (!NT_SUCCESS(rollbackStatus)) {
                InterlockedExchangePointer(
                    (PVOID volatile*)Handle, prepared);
                DbgPrint("[HV][PrivateDbgk] overlay opt-in failed 0x%X; retained hook %p after rollback 0x%X\n",
                         status, prepared, rollbackStatus);
            }
            return status;
        }
    }

    /* The callback reads the global handle at entry.  Publish ownership
     * before the SLAT leaf can make the callback reachable. */
    InterlockedExchangePointer((PVOID volatile*)Handle, prepared);
    status = HvHookActivate(prepared);
    if (NT_SUCCESS(status)) return STATUS_SUCCESS;

    rollbackStatus = HvHookRemove(prepared);
    if (NT_SUCCESS(rollbackStatus)) {
        InterlockedCompareExchangePointer(
            (PVOID volatile*)Handle, NULL, prepared);
    } else {
        DbgPrint("[HV][PrivateDbgk] activation failed 0x%X; retained hook %p after rollback 0x%X\n",
                 status, prepared, rollbackStatus);
    }
    return status;
}

static NTSTATUS HvPrivateDebugObjectInstallNtHook(
    _In_ PCWSTR Name,
    _In_opt_ PVOID Resolved,
    _In_ PVOID Callback,
    _Inout_ HV_HOOK_HANDLE* Handle)
{
    PVOID target = Resolved ? Resolved : HvHookResolveNtRoutine(Name);
    if (!target) return STATUS_PROCEDURE_NOT_FOUND;
    return HvPrivateDebugObjectInstallHook(
        target, Callback, Handle, TRUE);
}

static NTSTATUS HvPrivateDebugObjectRemoveOneHook(
    _Inout_ HV_HOOK_HANDLE* Handle)
{
    HV_HOOK_HANDLE handle = *Handle;
    NTSTATUS status;

    if (!handle) return STATUS_SUCCESS;
    status = HvHookRemove(handle);
    if (NT_SUCCESS(status)) {
        *Handle = NULL;
    } else {
        DbgPrint("[HV][PrivateDbgk] hook removal retained handle %p: 0x%X\n",
                 handle, status);
    }
    return status;
}

static VOID HvPrivateDebugObjectRemoveProducerHooks(VOID)
{
    HvPrivateDebugObjectRemoveOneHook(&g_HookDbgkUnMapViewOfSection);
    HvPrivateDebugObjectRemoveOneHook(&g_HookDbgkMapViewOfSection);
    HvPrivateDebugObjectRemoveOneHook(&g_HookDbgkExitProcess);
    HvPrivateDebugObjectRemoveOneHook(&g_HookDbgkExitThread);
    HvPrivateDebugObjectRemoveOneHook(&g_HookDbgkCreateThread);
    HvPrivateDebugObjectRemoveOneHook(&g_HookDbgkForwardException);
}

static VOID HvPrivateDebugObjectRemoveHooks(VOID)
{
    HvPrivateDebugObjectRemoveProducerHooks();
    HvPrivateDebugObjectRemoveOneHook(&g_HookNtRemoveProcessDebug);
    HvPrivateDebugObjectRemoveOneHook(&g_HookNtDebugContinue);
    HvPrivateDebugObjectRemoveOneHook(&g_HookNtWaitForDebugEvent);
    HvPrivateDebugObjectRemoveOneHook(&g_HookNtSetInformationDebugObject);
    HvPrivateDebugObjectRemoveOneHook(&g_HookNtCreateDebugObject);
}

static NTSTATUS HvPrivateDebugObjectInstallProducerHooks(VOID)
{
    NTSTATUS status;
    if (!g_Symbols.DbgkForwardException ||
        !g_Symbols.DbgkCreateThread ||
        !g_Symbols.DbgkExitThread ||
        !g_Symbols.DbgkExitProcess ||
        !g_Symbols.DbgkMapViewOfSection ||
        !g_Symbols.DbgkUnMapViewOfSection) {
        return STATUS_NOT_FOUND;
    }

    status = HvPrivateDebugObjectInstallHook(
        g_Symbols.DbgkForwardException,
        HvPrivateHookDbgkForwardException,
        &g_HookDbgkForwardException,
        TRUE);
    if (!NT_SUCCESS(status)) goto Rollback;
    status = HvPrivateDebugObjectInstallHook(
        g_Symbols.DbgkCreateThread,
        HvPrivateHookDbgkCreateThread,
        &g_HookDbgkCreateThread,
        FALSE);
    if (!NT_SUCCESS(status)) goto Rollback;
    status = HvPrivateDebugObjectInstallHook(
        g_Symbols.DbgkExitThread,
        HvPrivateHookDbgkExitThread,
        &g_HookDbgkExitThread,
        FALSE);
    if (!NT_SUCCESS(status)) goto Rollback;
    status = HvPrivateDebugObjectInstallHook(
        g_Symbols.DbgkExitProcess,
        HvPrivateHookDbgkExitProcess,
        &g_HookDbgkExitProcess,
        FALSE);
    if (!NT_SUCCESS(status)) goto Rollback;
    status = HvPrivateDebugObjectInstallHook(
        g_Symbols.DbgkMapViewOfSection,
        HvPrivateHookDbgkMapViewOfSection,
        &g_HookDbgkMapViewOfSection,
        FALSE);
    if (!NT_SUCCESS(status)) goto Rollback;
    status = HvPrivateDebugObjectInstallHook(
        g_Symbols.DbgkUnMapViewOfSection,
        HvPrivateHookDbgkUnMapViewOfSection,
        &g_HookDbgkUnMapViewOfSection,
        FALSE);
    if (!NT_SUCCESS(status)) goto Rollback;
    return STATUS_SUCCESS;

Rollback:
    HvPrivateDebugObjectRemoveProducerHooks();
    return status;
}

static NTSTATUS HvPrivateDebugObjectInstallSyscallHooks(VOID)
{
    NTSTATUS status;
    status = HvPrivateDebugObjectInstallNtHook(
        L"NtCreateDebugObject", g_Symbols.NtCreateDebugObject,
        HvPrivateHookNtCreateDebugObject,
        &g_HookNtCreateDebugObject);
    if (!NT_SUCCESS(status)) goto Rollback;
    status = HvPrivateDebugObjectInstallNtHook(
        L"NtSetInformationDebugObject", g_Symbols.NtSetInformationDebugObject,
        HvPrivateHookNtSetInformationDebugObject,
        &g_HookNtSetInformationDebugObject);
    if (!NT_SUCCESS(status)) goto Rollback;
    status = HvPrivateDebugObjectInstallNtHook(
        L"NtWaitForDebugEvent", g_Symbols.NtWaitForDebugEvent,
        HvPrivateHookNtWaitForDebugEvent,
        &g_HookNtWaitForDebugEvent);
    if (!NT_SUCCESS(status)) goto Rollback;
    status = HvPrivateDebugObjectInstallNtHook(
        L"NtDebugContinue", g_Symbols.NtDebugContinue,
        HvPrivateHookNtDebugContinue,
        &g_HookNtDebugContinue);
    if (!NT_SUCCESS(status)) goto Rollback;
    status = HvPrivateDebugObjectInstallNtHook(
        L"NtRemoveProcessDebug", g_Symbols.NtRemoveProcessDebug,
        HvPrivateHookNtRemoveProcessDebug,
        &g_HookNtRemoveProcessDebug);
    if (!NT_SUCCESS(status)) goto Rollback;

    if (g_Symbols.DbgkForwardException) {
        status = HvPrivateDebugObjectInstallProducerHooks();
        if (!NT_SUCCESS(status)) goto Rollback;
    }
    return STATUS_SUCCESS;

Rollback:
    HvPrivateDebugObjectRemoveHooks();
    return status;
}

NTSTATUS HvPrivateDebugObjectConfigureSymbols(
    _In_ const HV_PRIVATE_DBGK_SYMBOLS* Symbols)
{
    NTSTATUS status = STATUS_SUCCESS;
    if (!Symbols || Symbols->Version != HV_BRIDGE_PROTOCOL_VERSION ||
        KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!Symbols->NtCreateDebugObject || !Symbols->NtDebugActiveProcess ||
        !Symbols->NtSetInformationDebugObject ||
        !Symbols->NtWaitForDebugEvent || !Symbols->NtDebugContinue ||
        !Symbols->NtRemoveProcessDebug || !Symbols->DbgkForwardException ||
        !Symbols->DbgkCreateThread ||
        !Symbols->DbgkExitThread || !Symbols->DbgkExitProcess ||
        !Symbols->DbgkMapViewOfSection || !Symbols->DbgkUnMapViewOfSection ||
        !Symbols->PsGetNextProcessThread || !Symbols->NtSetContextThread ||
        !Symbols->NtReadVirtualMemory || !Symbols->NtWriteVirtualMemory) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    HvPrivateDebugObjectRemoveProducerHooks();
    g_Symbols = *Symbols;
    if (HvPrivateDebugObjectIsEnabled()) {
        status = HvPrivateDebugObjectInstallSyscallHooks();
        if (!NT_SUCCESS(status)) RtlZeroMemory(&g_Symbols, sizeof(g_Symbols));
    }
    return status;
}

static VOID HvPrivateDebugObjectConvertWaitState(
    _In_ const HV_BRIDGE_DBGK_EVENT* Event,
    _Out_ PHV_DBGUI_WAIT_STATE_CHANGE State)
{
    RtlZeroMemory(State, sizeof(*State));
    State->NewState = Event->State;
    State->AppClientId.UniqueProcess =
        (HANDLE)(ULONG_PTR)Event->ProcessId;
    State->AppClientId.UniqueThread =
        (HANDLE)(ULONG_PTR)Event->ThreadId;
    switch (Event->State) {
    case HV_BRIDGE_DBGK_CREATE_PROCESS:
        State->StateInfo.CreateProcessInfo.HandleToProcess =
            (HANDLE)(ULONG_PTR)Event->ProcessHandle;
        State->StateInfo.CreateProcessInfo.HandleToThread =
            (HANDLE)(ULONG_PTR)Event->ThreadHandle;
        State->StateInfo.CreateProcessInfo.NewProcess.FileHandle =
            (HANDLE)(ULONG_PTR)Event->FileHandle;
        State->StateInfo.CreateProcessInfo.NewProcess.BaseOfImage =
            (PVOID)(ULONG_PTR)Event->BaseAddress;
        State->StateInfo.CreateProcessInfo.NewProcess.DebugInfoFileOffset =
            Event->DebugInfoFileOffset;
        State->StateInfo.CreateProcessInfo.NewProcess.DebugInfoSize =
            Event->DebugInfoSize;
        State->StateInfo.CreateProcessInfo.NewProcess.InitialThread.StartAddress =
            (PVOID)(ULONG_PTR)Event->StartAddress;
        break;
    case HV_BRIDGE_DBGK_CREATE_THREAD:
        State->StateInfo.CreateThread.HandleToThread =
            (HANDLE)(ULONG_PTR)Event->ThreadHandle;
        State->StateInfo.CreateThread.NewThread.StartAddress =
            (PVOID)(ULONG_PTR)Event->StartAddress;
        break;
    case HV_BRIDGE_DBGK_EXIT_THREAD:
        State->StateInfo.ExitThread.ExitStatus = Event->ExitStatus;
        break;
    case HV_BRIDGE_DBGK_EXIT_PROCESS:
        State->StateInfo.ExitProcess.ExitStatus = Event->ExitStatus;
        break;
    case HV_BRIDGE_DBGK_EXCEPTION:
    case HV_BRIDGE_DBGK_BREAKPOINT:
    case HV_BRIDGE_DBGK_SINGLE_STEP:
        State->StateInfo.Exception.ExceptionRecord.ExceptionCode =
            Event->ExceptionCode;
        State->StateInfo.Exception.ExceptionRecord.ExceptionFlags =
            Event->ExceptionFlags;
        State->StateInfo.Exception.ExceptionRecord.ExceptionAddress =
            (PVOID)(ULONG_PTR)Event->ExceptionAddress;
        State->StateInfo.Exception.ExceptionRecord.NumberParameters =
            min(Event->NumberParameters, EXCEPTION_MAXIMUM_PARAMETERS);
        RtlCopyMemory(
            State->StateInfo.Exception.ExceptionRecord.ExceptionInformation,
            Event->ExceptionInformation,
            State->StateInfo.Exception.ExceptionRecord.NumberParameters *
                sizeof(ULONG_PTR));
        State->StateInfo.Exception.FirstChance = Event->FirstChance;
        break;
    case HV_BRIDGE_DBGK_LOAD_DLL:
        State->StateInfo.LoadDll.FileHandle =
            (HANDLE)(ULONG_PTR)Event->FileHandle;
        State->StateInfo.LoadDll.BaseOfDll =
            (PVOID)(ULONG_PTR)Event->BaseAddress;
        State->StateInfo.LoadDll.DebugInfoFileOffset =
            Event->DebugInfoFileOffset;
        State->StateInfo.LoadDll.DebugInfoSize = Event->DebugInfoSize;
        State->StateInfo.LoadDll.NamePointer =
            (PVOID)(ULONG_PTR)Event->NamePointer;
        break;
    case HV_BRIDGE_DBGK_UNLOAD_DLL:
        State->StateInfo.UnloadDll.BaseAddress =
            (PVOID)(ULONG_PTR)Event->BaseAddress;
        break;
    default:
        break;
    }
}
