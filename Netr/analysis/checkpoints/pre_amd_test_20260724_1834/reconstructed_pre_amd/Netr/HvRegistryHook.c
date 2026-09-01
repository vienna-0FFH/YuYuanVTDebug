/*
 * HvRegistryHook.c
 *
 * NtEnumerateKey registry enumeration filter.
 */

#include "HvRegistryHook.h"
#include "HvHook.h"
#include "HvCompat.h"

#define HV_TRACE_THIS_CAT HV_TRACE_CAT_REGISTRY
#include "HvTrace.h"

#ifndef STATUS_NOT_INITIALIZED
#define STATUS_NOT_INITIALIZED ((NTSTATUS)0xC000000BL)
#endif

/* Keep the hook frame small on the 24/28-KB kernel stack.  Long key names
 * already use the bounded nonpaged expansion path below. */
#define HV_REG_ENUM_INITIAL_BYTES 256UL
#define HV_REG_ENUM_MAX_BYTES     (64UL * 1024UL)
#define HV_REG_ENUM_MAX_RETRIES   4UL

typedef enum _KEY_INFORMATION_CLASS_LOCAL {
    KeyBasicInformationLocal          = 0,
    KeyNodeInformationLocal           = 1,
    KeyFullInformationLocal           = 2,
    KeyNameInformationLocal           = 3,
    KeyCachedInformationLocal         = 4,
    KeyFlagsInformationLocal          = 5,
    KeyVirtualizationInformationLocal = 6,
    KeyHandleTagsInformationLocal     = 7,
    MaxKeyInfoClassLocal              = 12
} KEY_INFORMATION_CLASS_LOCAL;

typedef NTSTATUS (NTAPI *PFN_NtEnumerateKey)(
    _In_  HANDLE                       KeyHandle,
    _In_  ULONG                        Index,
    _In_  KEY_INFORMATION_CLASS_LOCAL  KeyInformationClass,
    _Out_writes_bytes_opt_(Length) PVOID KeyInformation,
    _In_  ULONG                        Length,
    _Out_ PULONG                       ResultLength);

typedef struct _KEY_BASIC_INFORMATION_LOCAL {
    LARGE_INTEGER LastWriteTime;
    ULONG         TitleIndex;
    ULONG         NameLength;
    WCHAR         Name[1];
} KEY_BASIC_INFORMATION_LOCAL, *PKEY_BASIC_INFORMATION_LOCAL;

typedef struct _KEY_NODE_INFORMATION_LOCAL {
    LARGE_INTEGER LastWriteTime;
    ULONG         TitleIndex;
    ULONG         ClassOffset;
    ULONG         ClassLength;
    ULONG         NameLength;
    WCHAR         Name[1];
} KEY_NODE_INFORMATION_LOCAL, *PKEY_NODE_INFORMATION_LOCAL;

typedef enum _HV_REG_HOOK_STATE {
    HvRegHookStateIdle = 0,
    HvRegHookStatePreparedBypass,
    HvRegHookStateActive,
    HvRegHookStateQuiescing
} HV_REG_HOOK_STATE;

static volatile LONG          g_RegHookLockState       = 0;
static EX_PUSH_LOCK           g_RegHookStateLock       = 0;
static KSPIN_LOCK             g_HiddenKeyLock;
static BOOLEAN                g_HiddenKeyLockReady     = FALSE;
static EX_RUNDOWN_REF         g_RegHookRundown;
static BOOLEAN                g_RegHookRundownReady    = FALSE;
static BOOLEAN                g_RegHookRundownActive   = FALSE;
static volatile LONG          g_RegHookInitialized     = FALSE;
static volatile LONG          g_RegHookInstalled      = FALSE;
static volatile LONG          g_RegHookState          = HvRegHookStateIdle;
static PVOID                  g_RegHookHandle         = NULL;
static PVOID                  g_RegHookTarget         = NULL;
static PFN_NtEnumerateKey     g_OriginalNtEnumerateKey = NULL;

static WCHAR g_HiddenKeyNames[HV_REG_MAX_HIDDEN][HV_REG_NAME_MAX];
static ULONG g_HiddenKeyCount = 0;

static VOID
RegEnsureStateLock(VOID)
{
    LONG state;

    state = InterlockedCompareExchange(&g_RegHookLockState, 0, 0);
    if (state == 2) {
        return;
    }

    if (InterlockedCompareExchange(&g_RegHookLockState, 1, 0) == 0) {
        ExInitializePushLock(&g_RegHookStateLock);
        InterlockedExchange(&g_RegHookLockState, 2);
        return;
    }

    while (InterlockedCompareExchange(&g_RegHookLockState, 0, 0) == 1) {
        YieldProcessor();
    }
}

static VOID
RegAcquireStateLock(VOID)
{
    RegEnsureStateLock();
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_RegHookStateLock);
}

static VOID
RegReleaseStateLock(VOID)
{
    ExReleasePushLockExclusive(&g_RegHookStateLock);
    KeLeaveCriticalRegion();
}

static BOOLEAN
RegIsInitialized(VOID)
{
    return InterlockedCompareExchange(&g_RegHookInitialized, 0, 0) != 0;
}

static HV_REG_HOOK_STATE RegReadState(VOID);

static BOOLEAN
RegIsInstalledAtomic(VOID)
{
    return InterlockedCompareExchange(&g_RegHookInstalled, 0, 0) != 0 &&
           RegReadState() == HvRegHookStateActive;
}

static PFN_NtEnumerateKey
RegReadOriginal(VOID)
{
    return (PFN_NtEnumerateKey)InterlockedCompareExchangePointer(
        (PVOID volatile *)&g_OriginalNtEnumerateKey, NULL, NULL);
}

static HV_REG_HOOK_STATE
RegReadState(VOID)
{
    return (HV_REG_HOOK_STATE)InterlockedCompareExchange(
        &g_RegHookState, 0, 0);
}

static PVOID
RegReadHandle(VOID)
{
    return InterlockedCompareExchangePointer(
        (PVOID volatile *)&g_RegHookHandle, NULL, NULL);
}

static NTSTATUS
RegEnsureRundownActiveLocked(VOID)
{
    if (!g_RegHookRundownReady) {
        return STATUS_NOT_INITIALIZED;
    }

    if (!g_RegHookRundownActive) {
        ExReInitializeRundownProtection(&g_RegHookRundown);
        g_RegHookRundownActive = TRUE;
    }

    return STATUS_SUCCESS;
}

static VOID
RegBeginRundownLocked(VOID)
{
    if (g_RegHookRundownReady && g_RegHookRundownActive) {
        ExWaitForRundownProtectionRelease(&g_RegHookRundown);
        g_RegHookRundownActive = FALSE;
    }
}

static NTSTATUS
RegExtractName(
    _In_  PVOID                       Info,
    _In_  ULONG                       BufferLength,
    _In_  ULONG                       ResultLength,
    _In_  KEY_INFORMATION_CLASS_LOCAL Class,
    _Out_ PCWSTR*                     OutName,
    _Out_ PULONG                      OutNameLengthBytes)
{
    ULONG headerLength;
    ULONG nameLength;

    if (!OutName || !OutNameLengthBytes) {
        return STATUS_INVALID_PARAMETER;
    }

    *OutName = NULL;
    *OutNameLengthBytes = 0;

    if (!Info || ResultLength == 0 || ResultLength > BufferLength) {
        return STATUS_INFO_LENGTH_MISMATCH;
    }

    switch (Class) {
    case KeyBasicInformationLocal:
        headerLength = FIELD_OFFSET(KEY_BASIC_INFORMATION_LOCAL, Name);
        if (ResultLength < headerLength) {
            return STATUS_INFO_LENGTH_MISMATCH;
        }
        nameLength = ((PKEY_BASIC_INFORMATION_LOCAL)Info)->NameLength;
        *OutName = ((PKEY_BASIC_INFORMATION_LOCAL)Info)->Name;
        break;

    case KeyNodeInformationLocal:
    {
        PKEY_NODE_INFORMATION_LOCAL node;

        headerLength = FIELD_OFFSET(KEY_NODE_INFORMATION_LOCAL, Name);
        if (ResultLength < headerLength) {
            return STATUS_INFO_LENGTH_MISMATCH;
        }

        node = (PKEY_NODE_INFORMATION_LOCAL)Info;
        nameLength = node->NameLength;
        *OutName = node->Name;

        if (node->ClassLength != 0) {
            if ((node->ClassOffset & (sizeof(WCHAR) - 1)) != 0 ||
                node->ClassOffset < headerLength ||
                node->ClassOffset > ResultLength ||
                node->ClassLength > ResultLength - node->ClassOffset ||
                node->ClassOffset > BufferLength ||
                node->ClassLength > BufferLength - node->ClassOffset ||
                (node->ClassLength & (sizeof(WCHAR) - 1)) != 0) {
                return STATUS_INFO_LENGTH_MISMATCH;
            }
        }
        break;
    }

    default:
        return STATUS_INVALID_INFO_CLASS;
    }

    if ((nameLength & (sizeof(WCHAR) - 1)) != 0 ||
        nameLength > ResultLength - headerLength ||
        nameLength > BufferLength - headerLength) {
        return STATUS_INFO_LENGTH_MISMATCH;
    }

    *OutNameLengthBytes = nameLength;
    return STATUS_SUCCESS;
}

BOOLEAN
HvRegHookIsHidden(
    _In_ PCWSTR Name,
    _In_ ULONG  NameLengthBytes)
{
    KIRQL oldIrql;
    ULONG nameChars;
    BOOLEAN hidden = FALSE;

    if (!RegIsInitialized() || !Name || NameLengthBytes == 0 ||
        (NameLengthBytes & (sizeof(WCHAR) - 1)) != 0) {
        return FALSE;
    }

    if (NameLengthBytes > (HV_REG_NAME_MAX - 1) * sizeof(WCHAR)) {
        return FALSE;
    }

    nameChars = NameLengthBytes / sizeof(WCHAR);

    KeAcquireSpinLock(&g_HiddenKeyLock, &oldIrql);
    for (ULONG i = 0; i < g_HiddenKeyCount; ++i) {
        ULONG entryLength = 0;
        BOOLEAN equal = TRUE;

        while (entryLength < HV_REG_NAME_MAX &&
               g_HiddenKeyNames[i][entryLength] != L'\0') {
            ++entryLength;
        }

        if (entryLength != nameChars) {
            continue;
        }

        for (ULONG j = 0; j < nameChars; ++j) {
            WCHAR left = Name[j];
            WCHAR right = g_HiddenKeyNames[i][j];

            if (left >= L'A' && left <= L'Z') {
                left = (WCHAR)(left + (L'a' - L'A'));
            }
            if (right >= L'A' && right <= L'Z') {
                right = (WCHAR)(right + (L'a' - L'A'));
            }
            if (left != right) {
                equal = FALSE;
                break;
            }
        }

        if (equal) {
            hidden = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&g_HiddenKeyLock, oldIrql);
    return hidden;
}

NTSTATUS
HvRegHookAddHiddenKeyName(_In_ PCWSTR KeyName)
{
    SIZE_T length;
    NTSTATUS status = STATUS_INSUFFICIENT_RESOURCES;
    KIRQL oldIrql;

    if (KeGetCurrentIrql() > APC_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (!RegIsInitialized()) {
        return STATUS_NOT_INITIALIZED;
    }
    if (!KeyName) {
        return STATUS_INVALID_PARAMETER;
    }

    length = wcslen(KeyName);
    if (length == 0 || length >= HV_REG_NAME_MAX) {
        return STATUS_NAME_TOO_LONG;
    }

    RegAcquireStateLock();
    if (!RegIsInitialized()) {
        RegReleaseStateLock();
        return STATUS_NOT_INITIALIZED;
    }

    KeAcquireSpinLock(&g_HiddenKeyLock, &oldIrql);
    for (ULONG i = 0; i < g_HiddenKeyCount; ++i) {
        if (_wcsicmp(g_HiddenKeyNames[i], KeyName) == 0) {
            KeReleaseSpinLock(&g_HiddenKeyLock, oldIrql);
            RegReleaseStateLock();
            return STATUS_SUCCESS;
        }
    }

    if (g_HiddenKeyCount < HV_REG_MAX_HIDDEN) {
        wcscpy_s(g_HiddenKeyNames[g_HiddenKeyCount], HV_REG_NAME_MAX, KeyName);
        ++g_HiddenKeyCount;
        status = STATUS_SUCCESS;
    }
    KeReleaseSpinLock(&g_HiddenKeyLock, oldIrql);
    RegReleaseStateLock();
    return status;
}

NTSTATUS
HvRegHookRemoveHiddenKeyName(_In_ PCWSTR KeyName)
{
    KIRQL oldIrql;

    if (KeGetCurrentIrql() > APC_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (!RegIsInitialized()) {
        return STATUS_NOT_INITIALIZED;
    }
    if (!KeyName) {
        return STATUS_INVALID_PARAMETER;
    }

    RegAcquireStateLock();
    if (!RegIsInitialized()) {
        RegReleaseStateLock();
        return STATUS_NOT_INITIALIZED;
    }

    KeAcquireSpinLock(&g_HiddenKeyLock, &oldIrql);
    for (ULONG i = 0; i < g_HiddenKeyCount; ++i) {
        if (_wcsicmp(g_HiddenKeyNames[i], KeyName) == 0) {
            for (ULONG j = i; j + 1 < g_HiddenKeyCount; ++j) {
                wcscpy_s(g_HiddenKeyNames[j], HV_REG_NAME_MAX,
                         g_HiddenKeyNames[j + 1]);
            }
            g_HiddenKeyNames[g_HiddenKeyCount - 1][0] = L'\0';
            --g_HiddenKeyCount;
            KeReleaseSpinLock(&g_HiddenKeyLock, oldIrql);
            RegReleaseStateLock();
            return STATUS_SUCCESS;
        }
    }
    KeReleaseSpinLock(&g_HiddenKeyLock, oldIrql);
    RegReleaseStateLock();
    return STATUS_NOT_FOUND;
}

static NTSTATUS
RegQueryRawKeyHidden(
    _In_  PFN_NtEnumerateKey Original,
    _In_  HANDLE KeyHandle,
    _In_  ULONG  RawIndex,
    _Out_ PBOOLEAN Hidden)
{
    DECLSPEC_ALIGN(8) UCHAR stackBuffer[HV_REG_ENUM_INITIAL_BYTES];
    PVOID buffer = stackBuffer;
    PVOID allocatedBuffer = NULL;
    ULONG bufferLength = sizeof(stackBuffer);
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    if (!Original || !Hidden) {
        return STATUS_INVALID_PARAMETER;
    }
    *Hidden = FALSE;

    __try {
        for (ULONG attempt = 0; attempt < HV_REG_ENUM_MAX_RETRIES; ++attempt) {
            ULONG resultLength = 0;
            PCWSTR name = NULL;
            ULONG nameLength = 0;

            /*
             * Stay on the saved trampoline.  ZwEnumerateKey resolves to the
             * hooked entry point and would recursively re-enter this filter.
             */
            status = Original(
                KeyHandle,
                RawIndex,
                KeyBasicInformationLocal,
                buffer,
                bufferLength,
                &resultLength);

            if (status == STATUS_BUFFER_OVERFLOW ||
                status == STATUS_BUFFER_TOO_SMALL) {
                PVOID newBuffer;

                if (resultLength <= bufferLength ||
                    resultLength > HV_REG_ENUM_MAX_BYTES) {
                    status = STATUS_INFO_LENGTH_MISMATCH;
                    break;
                }

                newBuffer = HvAllocateNonPagedZeroed(
                    resultLength, HV_REG_HIDE_TAG);
                if (!newBuffer) {
                    status = STATUS_INSUFFICIENT_RESOURCES;
                    break;
                }

                if (allocatedBuffer) {
                    ExFreePoolWithTag(allocatedBuffer, HV_REG_HIDE_TAG);
                }
                allocatedBuffer = newBuffer;
                buffer = newBuffer;
                bufferLength = resultLength;
                continue;
            }

            if (!NT_SUCCESS(status)) {
                break;
            }

            status = RegExtractName(
                buffer,
                bufferLength,
                resultLength,
                KeyBasicInformationLocal,
                &name,
                &nameLength);
            if (!NT_SUCCESS(status)) {
                break;
            }

            *Hidden = HvRegHookIsHidden(name, nameLength);
            status = STATUS_SUCCESS;
            break;
        }
    }
    __finally {
        if (allocatedBuffer) {
            ExFreePoolWithTag(allocatedBuffer, HV_REG_HIDE_TAG);
        }
    }

    return status;
}

static NTSTATUS
RegFindVisibleRawIndex(
    _In_  PFN_NtEnumerateKey Original,
    _In_  HANDLE KeyHandle,
    _In_  ULONG  RequestedIndex,
    _Out_ PULONG RawIndex)
{
    ULONG rawIndex = 0;
    ULONG visibleIndex = 0;

    if (!Original || !RawIndex) {
        return STATUS_INVALID_PARAMETER;
    }

    for (;;) {
        BOOLEAN hidden;
        NTSTATUS status = RegQueryRawKeyHidden(
            Original, KeyHandle, rawIndex, &hidden);

        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (!hidden) {
            if (visibleIndex == RequestedIndex) {
                *RawIndex = rawIndex;
                return STATUS_SUCCESS;
            }
            ++visibleIndex;
        }

        if (rawIndex == MAXULONG) {
            return STATUS_NO_MORE_ENTRIES;
        }
        ++rawIndex;
    }
}

static NTSTATUS NTAPI
HookedNtEnumerateKey(
    _In_  HANDLE                       KeyHandle,
    _In_  ULONG                        Index,
    _In_  KEY_INFORMATION_CLASS_LOCAL  KeyInformationClass,
    _Out_writes_bytes_opt_(Length) PVOID KeyInformation,
    _In_  ULONG                        Length,
    _Out_ PULONG                       ResultLength)
{
    PFN_NtEnumerateKey original;
    NTSTATUS status = STATUS_NOT_INITIALIZED;
    HV_HOOK_HANDLE callbackHandle = (HV_HOOK_HANDLE)RegReadHandle();

    if (!HvHookCallbackAcquire(callbackHandle)) {
        return STATUS_DELETE_PENDING;
    }

    if (!ExAcquireRundownProtection(&g_RegHookRundown)) {
        HvHookCallbackRelease(callbackHandle);
        return STATUS_NOT_INITIALIZED;
    }

    __try {
    original = RegReadOriginal();
    if (!original) {
        return STATUS_NOT_INITIALIZED;
    }

    if (RegReadState() != HvRegHookStateActive) {
        return original(
            KeyHandle,
            Index,
            KeyInformationClass,
            KeyInformation,
            Length,
            ResultLength);
    }

    __try {
        if (ExGetPreviousMode() != UserMode ||
            KeGetCurrentIrql() != PASSIVE_LEVEL ||
            (KeyInformationClass != KeyBasicInformationLocal &&
             KeyInformationClass != KeyNodeInformationLocal)) {
            status = original(
                KeyHandle,
                Index,
                KeyInformationClass,
                KeyInformation,
                Length,
                ResultLength);
        } else {
            ULONG rawIndex;

            status = RegFindVisibleRawIndex(
                original, KeyHandle, Index, &rawIndex);
            if (NT_SUCCESS(status)) {
                status = original(
                    KeyHandle,
                    rawIndex,
                    KeyInformationClass,
                    KeyInformation,
                    Length,
                    ResultLength);

                if (NT_SUCCESS(status)) {
                    ULONG returnedLength = *ResultLength;
                    PCWSTR name;
                    ULONG nameLength;
                    NTSTATUS validation = RegExtractName(
                        KeyInformation,
                        Length,
                        returnedLength,
                        KeyInformationClass,
                        &name,
                        &nameLength);
                    UNREFERENCED_PARAMETER(name);
                    UNREFERENCED_PARAMETER(nameLength);
                    if (!NT_SUCCESS(validation)) {
                        status = validation;
                    }
                }
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }

    return status;
    } __finally {
        ExReleaseRundownProtection(&g_RegHookRundown);
        HvHookCallbackRelease(callbackHandle);
    }
}

static NTSTATUS
RegDetachHookLocked(VOID)
{
    NTSTATUS status;
    PVOID handle = RegReadHandle();

    if (!handle) {
        return RegReadState() == HvRegHookStateIdle
            ? STATUS_SUCCESS : STATUS_INVALID_DEVICE_STATE;
    }

    /* Publish bypass before restoring SLAT. Callbacks that are already in
     * flight keep using the immutable trampoline while Remove drains backend
     * readers. A failed Remove remains Quiescing and is retryable. */
    InterlockedExchange(&g_RegHookState, HvRegHookStateQuiescing);
    InterlockedExchange(&g_RegHookInstalled, FALSE);
    status = HvHookRemove(handle);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RegBeginRundownLocked();
    InterlockedExchangePointer(
        (PVOID volatile *)&g_OriginalNtEnumerateKey, NULL);
    InterlockedExchangePointer(
        (PVOID volatile *)&g_RegHookHandle, NULL);
    g_RegHookTarget = NULL;
    InterlockedExchange(&g_RegHookState, HvRegHookStateIdle);
    return STATUS_SUCCESS;
}

NTSTATUS
HvRegHookInitialize(VOID)
{
    KIRQL oldIrql;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    RegAcquireStateLock();
    if (RegIsInitialized()) {
        RegReleaseStateLock();
        return STATUS_SUCCESS;
    }

    if (!g_HiddenKeyLockReady) {
        KeInitializeSpinLock(&g_HiddenKeyLock);
        g_HiddenKeyLockReady = TRUE;
    }

    if (!g_RegHookRundownReady) {
        ExInitializeRundownProtection(&g_RegHookRundown);
        g_RegHookRundownReady = TRUE;
        g_RegHookRundownActive = TRUE;
    } else if (!g_RegHookRundownActive) {
        ExReInitializeRundownProtection(&g_RegHookRundown);
        g_RegHookRundownActive = TRUE;
    }

    KeAcquireSpinLock(&g_HiddenKeyLock, &oldIrql);
    RtlZeroMemory(g_HiddenKeyNames, sizeof(g_HiddenKeyNames));
    g_HiddenKeyCount = 0;
    KeReleaseSpinLock(&g_HiddenKeyLock, oldIrql);

    InterlockedExchange(&g_RegHookInstalled, FALSE);
    InterlockedExchange(&g_RegHookState, HvRegHookStateIdle);
    InterlockedExchange(&g_RegHookInitialized, TRUE);
    RegReleaseStateLock();
    DbgPrint("[RegHook] Initialized\n");
    return STATUS_SUCCESS;
}

NTSTATUS
HvRegHookCleanup(VOID)
{
    NTSTATUS status;
    KIRQL oldIrql;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        DbgPrint("[RegHook] Cleanup called above PASSIVE_LEVEL\n");
        return STATUS_INVALID_DEVICE_STATE;
    }

    RegAcquireStateLock();
    if (!RegIsInitialized()) {
        RegReleaseStateLock();
        return STATUS_SUCCESS;
    }

    status = RegDetachHookLocked();
    if (!NT_SUCCESS(status)) {
        DbgPrint("[RegHook] Cleanup could not remove hook: 0x%X\n", status);
        RegReleaseStateLock();
        return status;
    }

    RegBeginRundownLocked();
    KeAcquireSpinLock(&g_HiddenKeyLock, &oldIrql);
    RtlZeroMemory(g_HiddenKeyNames, sizeof(g_HiddenKeyNames));
    g_HiddenKeyCount = 0;
    KeReleaseSpinLock(&g_HiddenKeyLock, oldIrql);
    InterlockedExchange(&g_RegHookInitialized, FALSE);
    RegReleaseStateLock();
    DbgPrint("[RegHook] Cleaned up\n");
    return STATUS_SUCCESS;
}

NTSTATUS
HvRegHookInstallAtAddress(_In_ PVOID NtEnumerateKeyAddress)
{
    NTSTATUS status;
    PVOID trampoline;
    PVOID hookHandle = NULL;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (!NtEnumerateKeyAddress) {
        return STATUS_INVALID_PARAMETER;
    }

    RegAcquireStateLock();
    if (!RegIsInitialized()) {
        RegReleaseStateLock();
        return STATUS_NOT_INITIALIZED;
    }

    if (RegReadHandle()) {
        if (RegReadState() == HvRegHookStateActive &&
            g_RegHookTarget == NtEnumerateKeyAddress &&
            RegReadOriginal() != NULL) {
            RegReleaseStateLock();
            return STATUS_SUCCESS;
        }
        RegReleaseStateLock();
        return STATUS_INVALID_DEVICE_STATE;
    }

    status = RegEnsureRundownActiveLocked();
    if (!NT_SUCCESS(status)) {
        RegReleaseStateLock();
        return status;
    }

    status = HvHookPrepare(
        NtEnumerateKeyAddress,
        (PVOID)HookedNtEnumerateKey,
        &hookHandle);
    if (!NT_SUCCESS(status)) {
        if (hookHandle) {
            trampoline = HvHookGetTrampoline(hookHandle);
            InterlockedExchangePointer(
                (PVOID volatile *)&g_RegHookHandle, hookHandle);
            g_RegHookTarget = NtEnumerateKeyAddress;
            if (trampoline) {
                InterlockedExchangePointer(
                    (PVOID volatile *)&g_OriginalNtEnumerateKey, trampoline);
            }
            InterlockedExchange(
                &g_RegHookState, HvRegHookStateQuiescing);
        }
        RegReleaseStateLock();
        DbgPrint("[RegHook] HvHookPrepare failed: 0x%X handle=%p\n",
                 status, hookHandle);
        return status;
    }

    if (!hookHandle) {
        RegReleaseStateLock();
        return STATUS_UNSUCCESSFUL;
    }

    InterlockedExchangePointer(
        (PVOID volatile *)&g_RegHookHandle, hookHandle);
    g_RegHookTarget = NtEnumerateKeyAddress;
    trampoline = HvHookGetTrampoline(hookHandle);
    if (!trampoline) {
        InterlockedExchange(&g_RegHookState, HvRegHookStateQuiescing);
        status = RegDetachHookLocked();
        if (!NT_SUCCESS(status)) {
            DbgPrint("[RegHook] Trampoline missing and rollback failed: 0x%X\n",
                     status);
            RegReleaseStateLock();
            return status;
        }
        RegReleaseStateLock();
        return STATUS_UNSUCCESSFUL;
    }

    InterlockedExchangePointer(
        (PVOID volatile *)&g_OriginalNtEnumerateKey, trampoline);
    InterlockedExchange(
        &g_RegHookState, HvRegHookStatePreparedBypass);

    status = HvHookActivate(hookHandle);
    if (!NT_SUCCESS(status)) {
        NTSTATUS rollbackStatus;
        InterlockedExchange(&g_RegHookState, HvRegHookStateQuiescing);
        rollbackStatus = RegDetachHookLocked();
        if (!NT_SUCCESS(rollbackStatus)) {
            DbgPrint("[RegHook] Activate failed 0x%X and rollback retained handle: 0x%X\n",
                     status, rollbackStatus);
            RegReleaseStateLock();
            return rollbackStatus;
        }
        RegReleaseStateLock();
        return status;
    }

    InterlockedExchange(&g_RegHookState, HvRegHookStateActive);
    InterlockedExchange(&g_RegHookInstalled, TRUE);
    RegReleaseStateLock();
    DbgPrint("[RegHook] Installed at %p, trampoline=%p\n",
             NtEnumerateKeyAddress, trampoline);
    return STATUS_SUCCESS;
}

NTSTATUS
HvRegHookInstall(VOID)
{
    PVOID ntEnumerateKey;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (!RegIsInitialized()) {
        return STATUS_NOT_INITIALIZED;
    }

    ntEnumerateKey = HvHookResolveNtRoutine(L"NtEnumerateKey");
    if (!ntEnumerateKey) {
        DbgPrint("[RegHook] NtEnumerateKey implementation not found\n");
        return STATUS_NOT_FOUND;
    }

    return HvRegHookInstallAtAddress(ntEnumerateKey);
}

NTSTATUS
HvRegHookUninstall(VOID)
{
    NTSTATUS status;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (!RegIsInitialized()) {
        return STATUS_NOT_INITIALIZED;
    }

    RegAcquireStateLock();
    if (!RegIsInitialized()) {
        RegReleaseStateLock();
        return STATUS_NOT_INITIALIZED;
    }

    status = RegDetachHookLocked();
    RegReleaseStateLock();
    if (!NT_SUCCESS(status)) {
        DbgPrint("[RegHook] Uninstall failed: 0x%X\n", status);
        return status;
    }

    DbgPrint("[RegHook] Uninstalled\n");
    return STATUS_SUCCESS;
}

BOOLEAN
HvRegHookIsInstalled(VOID)
{
    return RegIsInstalledAtomic();
}
