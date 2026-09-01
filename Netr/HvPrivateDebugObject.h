#ifndef _HV_PRIVATE_DEBUG_OBJECT_H_
#define _HV_PRIVATE_DEBUG_OBJECT_H_

#include <ntddk.h>
#include "NetrBridgeProtocol.h"

#define HV_PRIVATE_DEBUG_OBJECT_VERSION 1UL

typedef struct _HV_PRIVATE_DEBUG_OBJECT_STATUS {
    ULONG Version;
    ULONG Enabled;
    ULONG SessionCount;
    ULONG DeletePendingCount;
} HV_PRIVATE_DEBUG_OBJECT_STATUS, *PHV_PRIVATE_DEBUG_OBJECT_STATUS;

typedef struct _HV_PRIVATE_DBGK_SYMBOLS {
    ULONG Version;
    ULONG Reserved;
    PVOID NtCreateDebugObject;
    PVOID NtDebugActiveProcess;
    PVOID NtSetInformationDebugObject;
    PVOID NtWaitForDebugEvent;
    PVOID NtDebugContinue;
    PVOID NtRemoveProcessDebug;
    PVOID DbgkForwardException;
    PVOID DbgkCreateThread;
    PVOID DbgkExitThread;
    PVOID DbgkExitProcess;
    PVOID DbgkMapViewOfSection;
    PVOID DbgkUnMapViewOfSection;
    PVOID PsGetNextProcessThread;
    PVOID NtSetContextThread;
    PVOID NtReadVirtualMemory;
    PVOID NtWriteVirtualMemory;
} HV_PRIVATE_DBGK_SYMBOLS, *PHV_PRIVATE_DBGK_SYMBOLS;

NTSTATUS HvPrivateDebugObjectInitialize(VOID);
NTSTATUS HvPrivateDebugObjectBeginShutdown(VOID);
VOID HvPrivateDebugObjectCleanup(VOID);

NTSTATUS HvPrivateDebugObjectSetEnabled(_In_ BOOLEAN Enabled);
BOOLEAN HvPrivateDebugObjectIsEnabled(VOID);

NTSTATUS HvPrivateDebugObjectBind(
    _In_ HANDLE DebuggerPid,
    _In_ HANDLE TargetPid);

NTSTATUS HvPrivateDebugObjectUnbind(
    _In_ HANDLE DebuggerPid,
    _In_ HANDLE TargetPid);

VOID HvPrivateDebugObjectUnbindAllForDebugger(_In_ HANDLE DebuggerPid);
NTSTATUS HvPrivateDebugObjectNotifyProcessExit(
    _In_ PEPROCESS Process,
    _In_ HANDLE ProcessId);
VOID HvPrivateDebugObjectUnbindOnProcessExit(_In_ HANDLE ProcessId);

BOOLEAN HvPrivateDebugObjectIsTarget(
    _In_ HANDLE TargetPid);

BOOLEAN HvPrivateDebugObjectIsBound(
    _In_ HANDLE DebuggerPid,
    _In_ HANDLE TargetPid);

HANDLE HvPrivateDebugObjectGetDebugger(
    _In_ HANDLE TargetPid);

VOID HvPrivateDebugObjectGetStatus(
    _Out_ PHV_PRIVATE_DEBUG_OBJECT_STATUS Status);

NTSTATUS HvPrivateDebugObjectConfigureSymbols(
    _In_ const HV_PRIVATE_DBGK_SYMBOLS* Symbols);

NTSTATUS HvPrivateDebugObjectWait(
    _In_ HANDLE DebuggerPid,
    _Out_ PHV_BRIDGE_DBGK_EVENT Event,
    _In_ ULONG TimeoutMs);

NTSTATUS HvPrivateDebugObjectContinue(
    _In_ HANDLE DebuggerPid,
    _In_ const HV_BRIDGE_DBGK_CONTINUE_REQUEST* Request);

NTSTATUS HvPrivateDebugObjectDetach(
    _In_ HANDLE DebuggerPid,
    _In_ HANDLE TargetPid);

NTSTATUS HvPrivateDebugObjectAttach(
    _In_ HANDLE DebuggerPid,
    _In_ HANDLE ProcessHandle,
    _Out_opt_ HANDLE* TargetPid);

#endif
