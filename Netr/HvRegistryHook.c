/*
 * HvRegistryHook.c
 *
 * 阶段 8.2 — 注册表枚举隐藏
 *
 * 仅 Hook NtEnumerateKey；直接路径打开 (NtOpenKey) 仍走原始路径，
 * 让 GUI 通过已知路径访问驱动私有 reg 区不受影响。
 *
 * 隐藏策略:
 *   - 维护 g_HiddenKeyNames[] (UNICODE 名 < 64 字符)
 *   - NtEnumerateKey(Index=N) 返回的子键名若匹配隐藏列表 → 用 Index=N+1
 *     再次调用原函数，把结果当作 N 返回；如此循环直到非隐藏或 NO_MORE_ENTRIES。
 *   - 对调用者透明: 它们以为某个 Index 不存在 Netr 子键。
 */

#include "HvRegistryHook.h"
#include "HvHook.h"

// P122: 全 driver DbgPrint → GUI ring
#define HV_TRACE_THIS_CAT HV_TRACE_CAT_REGISTRY
#include "HvTrace.h"

// STATUS_NOT_INITIALIZED 在 ntstatus.h 中定义,但驱动构建通常用 WIN32_NO_STATUS
// 屏蔽 ntstatus.h 重复定义,所以这里本地声明。
#ifndef STATUS_NOT_INITIALIZED
#define STATUS_NOT_INITIALIZED ((NTSTATUS)0xC0000001L)
#endif

// =============================================================================
// Nt 函数原型
// =============================================================================

typedef enum _KEY_INFORMATION_CLASS_LOCAL {
    KeyBasicInformationLocal              = 0,
    KeyNodeInformationLocal               = 1,
    KeyFullInformationLocal               = 2,
    KeyNameInformationLocal               = 3,
    KeyCachedInformationLocal             = 4,
    KeyFlagsInformationLocal              = 5,
    KeyVirtualizationInformationLocal     = 6,
    KeyHandleTagsInformationLocal         = 7,
    MaxKeyInfoClassLocal                  = 12
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

// =============================================================================
// 全局状态
// =============================================================================

static BOOLEAN              g_RegHookInitialized      = FALSE;
static BOOLEAN              g_RegHookInstalled        = FALSE;
static PVOID                g_RegHookHandle           = NULL;
static PFN_NtEnumerateKey   g_OriginalNtEnumerateKey  = NULL;

static KSPIN_LOCK g_HiddenKeyLock;
static WCHAR      g_HiddenKeyNames[HV_REG_MAX_HIDDEN][HV_REG_NAME_MAX];
static ULONG      g_HiddenKeyCount = 0;

// 来自 HvHook.c — 统一 Hook 安装接口
extern NTSTATUS HvHookInstall(_In_ PVOID Target, _In_ PVOID Hook, _Out_ PVOID* OutHandle);
extern NTSTATUS HvHookRemove(_In_ PVOID Handle);
extern PVOID    HvHookGetTrampoline(_In_ PVOID Handle);

// =============================================================================
// 名字匹配辅助
// =============================================================================

BOOLEAN
HvRegHookIsHidden(_In_ PCWSTR Name, _In_ USHORT NameLengthBytes)
{
    KIRQL old;
    BOOLEAN hit = FALSE;
    ULONG nameChars;

    if (!Name || NameLengthBytes == 0) return FALSE;
    nameChars = NameLengthBytes / sizeof(WCHAR);
    if (nameChars >= HV_REG_NAME_MAX) nameChars = HV_REG_NAME_MAX - 1;

    KeAcquireSpinLock(&g_HiddenKeyLock, &old);
    for (ULONG i = 0; i < g_HiddenKeyCount; i++) {
        SIZE_T entryLen = wcslen(g_HiddenKeyNames[i]);
        if (entryLen == nameChars) {
            // 大小写不敏感比较；NtEnumerateKey 返回的 Name 字段非以 0 结尾，
            // 所以用长度精确比较，避免越界。
            BOOLEAN eq = TRUE;
            for (ULONG k = 0; k < nameChars; k++) {
                WCHAR a = Name[k], b = g_HiddenKeyNames[i][k];
                if (a >= L'A' && a <= L'Z') a += (WCHAR)(L'a' - L'A');
                if (b >= L'A' && b <= L'Z') b += (WCHAR)(L'a' - L'A');
                if (a != b) { eq = FALSE; break; }
            }
            if (eq) { hit = TRUE; break; }
        }
    }
    KeReleaseSpinLock(&g_HiddenKeyLock, old);
    return hit;
}

NTSTATUS
HvRegHookAddHiddenKeyName(_In_ PCWSTR KeyName)
{
    KIRQL old;
    SIZE_T len;
    NTSTATUS status = STATUS_INSUFFICIENT_RESOURCES;

    if (!g_RegHookInitialized) return STATUS_NOT_INITIALIZED;
    if (!KeyName) return STATUS_INVALID_PARAMETER;

    len = wcslen(KeyName);
    if (len == 0 || len >= HV_REG_NAME_MAX) return STATUS_NAME_TOO_LONG;

    KeAcquireSpinLock(&g_HiddenKeyLock, &old);
    for (ULONG i = 0; i < g_HiddenKeyCount; i++) {
        if (_wcsicmp(g_HiddenKeyNames[i], KeyName) == 0) {
            KeReleaseSpinLock(&g_HiddenKeyLock, old);
            return STATUS_SUCCESS;
        }
    }
    if (g_HiddenKeyCount < HV_REG_MAX_HIDDEN) {
        wcscpy_s(g_HiddenKeyNames[g_HiddenKeyCount], HV_REG_NAME_MAX, KeyName);
        g_HiddenKeyCount++;
        status = STATUS_SUCCESS;
    }
    KeReleaseSpinLock(&g_HiddenKeyLock, old);
    return status;
}

NTSTATUS
HvRegHookRemoveHiddenKeyName(_In_ PCWSTR KeyName)
{
    KIRQL old;
    NTSTATUS status = STATUS_NOT_FOUND;

    if (!g_RegHookInitialized || !KeyName) return STATUS_INVALID_PARAMETER;

    KeAcquireSpinLock(&g_HiddenKeyLock, &old);
    for (ULONG i = 0; i < g_HiddenKeyCount; i++) {
        if (_wcsicmp(g_HiddenKeyNames[i], KeyName) == 0) {
            for (ULONG j = i; j + 1 < g_HiddenKeyCount; j++) {
                wcscpy_s(g_HiddenKeyNames[j], HV_REG_NAME_MAX, g_HiddenKeyNames[j + 1]);
            }
            g_HiddenKeyNames[g_HiddenKeyCount - 1][0] = L'\0';
            g_HiddenKeyCount--;
            status = STATUS_SUCCESS;
            break;
        }
    }
    KeReleaseSpinLock(&g_HiddenKeyLock, old);
    return status;
}

// =============================================================================
// 从返回 buffer 提取 Name 字段 (按 KEY_INFORMATION_CLASS)
// =============================================================================

static BOOLEAN
RegExtractName(
    _In_  PVOID Info,
    _In_  KEY_INFORMATION_CLASS_LOCAL Class,
    _Out_ PCWSTR* OutName,
    _Out_ PUSHORT OutNameLenBytes)
{
    if (!Info) return FALSE;
    switch (Class) {
    case KeyBasicInformationLocal: {
        PKEY_BASIC_INFORMATION_LOCAL k = (PKEY_BASIC_INFORMATION_LOCAL)Info;
        *OutName = k->Name;
        *OutNameLenBytes = (USHORT)k->NameLength;
        return TRUE;
    }
    case KeyNodeInformationLocal: {
        PKEY_NODE_INFORMATION_LOCAL k = (PKEY_NODE_INFORMATION_LOCAL)Info;
        *OutName = k->Name;
        *OutNameLenBytes = (USHORT)k->NameLength;
        return TRUE;
    }
    default:
        // KeyFullInformation 不含 Name，只含 ClassName；不在隐藏范畴
        return FALSE;
    }
}

// =============================================================================
// Hooked NtEnumerateKey
// =============================================================================

static NTSTATUS NTAPI
HookedNtEnumerateKey(
    _In_  HANDLE                       KeyHandle,
    _In_  ULONG                        Index,
    _In_  KEY_INFORMATION_CLASS_LOCAL  KeyInformationClass,
    _Out_writes_bytes_opt_(Length) PVOID KeyInformation,
    _In_  ULONG                        Length,
    _Out_ PULONG                       ResultLength)
{
    NTSTATUS status;
    ULONG probeIndex = Index;
    PCWSTR  name = NULL;
    USHORT  nameLen = 0;
    ULONG   safety = 0;
    const ULONG MAX_SKIPS = 128;  // 防止恶意/损坏 reg 死循环

    if (!g_OriginalNtEnumerateKey) {
        return STATUS_NOT_INITIALIZED;
    }

    __try {
        for (;;) {
            status = g_OriginalNtEnumerateKey(
                KeyHandle, probeIndex, KeyInformationClass,
                KeyInformation, Length, ResultLength);

            if (!NT_SUCCESS(status)) {
                // BUFFER_OVERFLOW / NO_MORE_ENTRIES / 等错误透传
                return status;
            }

            // 仅过滤含 Name 字段的 class
            if (!RegExtractName(KeyInformation, KeyInformationClass, &name, &nameLen)) {
                return status;
            }

            if (!HvRegHookIsHidden(name, nameLen)) {
                return status;
            }

            // 命中隐藏 → 探下一个 Index 重试
            probeIndex++;
            if (++safety > MAX_SKIPS) {
                return STATUS_NO_MORE_ENTRIES;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }
}

// =============================================================================
// 初始化 / 安装
// =============================================================================

NTSTATUS
HvRegHookInitialize(VOID)
{
    if (g_RegHookInitialized) return STATUS_SUCCESS;
    KeInitializeSpinLock(&g_HiddenKeyLock);
    RtlZeroMemory(g_HiddenKeyNames, sizeof(g_HiddenKeyNames));
    g_HiddenKeyCount = 0;
    g_RegHookInitialized = TRUE;
    DbgPrint("[RegHook] Initialized\n");
    return STATUS_SUCCESS;
}

VOID
HvRegHookCleanup(VOID)
{
    if (g_RegHookInstalled) {
        HvRegHookUninstall();
    }
    g_RegHookInitialized = FALSE;
}

NTSTATUS
HvRegHookInstall(VOID)
{
    NTSTATUS status;
    UNICODE_STRING funcName;
    PVOID ntEnumerateKey;

    if (!g_RegHookInitialized) return STATUS_NOT_INITIALIZED;
    if (g_RegHookInstalled) return STATUS_SUCCESS;

    RtlInitUnicodeString(&funcName, L"ZwEnumerateKey");
    ntEnumerateKey = MmGetSystemRoutineAddress(&funcName);
    if (!ntEnumerateKey) {
        DbgPrint("[RegHook] ZwEnumerateKey not found\n");
        return STATUS_NOT_FOUND;
    }

    status = HvHookInstall(ntEnumerateKey, HookedNtEnumerateKey, &g_RegHookHandle);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[RegHook] HvHookInstall failed: 0x%X\n", status);
        return status;
    }

    g_OriginalNtEnumerateKey =
        (PFN_NtEnumerateKey)HvHookGetTrampoline(g_RegHookHandle);
    if (!g_OriginalNtEnumerateKey) {
        DbgPrint("[RegHook] Trampoline NULL after install\n");
        HvHookRemove(g_RegHookHandle);
        g_RegHookHandle = NULL;
        return STATUS_UNSUCCESSFUL;
    }

    g_RegHookInstalled = TRUE;
    DbgPrint("[RegHook] Installed: trampoline=%p\n", g_OriginalNtEnumerateKey);
    return STATUS_SUCCESS;
}

VOID
HvRegHookUninstall(VOID)
{
    if (!g_RegHookInstalled) return;
    if (g_RegHookHandle) {
        HvHookRemove(g_RegHookHandle);
        g_RegHookHandle = NULL;
    }
    g_OriginalNtEnumerateKey = NULL;
    g_RegHookInstalled = FALSE;
    DbgPrint("[RegHook] Uninstalled\n");
}
