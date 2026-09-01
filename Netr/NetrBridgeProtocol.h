#pragma once

#ifndef NETR_BRIDGE_PROTOCOL_H
#define NETR_BRIDGE_PROTOCOL_H

/* Shared ABI between GuardMetaCore.sys and NetrDebuggerBridge. */

#define HV_BRIDGE_PROTOCOL_VERSION 6u

#ifndef HV_IOCTL_BASE
#define HV_IOCTL_BASE 0x800
#endif

#define HV_BRIDGE_CAP_DEBUG_EVENTS       0x00000001u
#define HV_BRIDGE_CAP_DYNAMIC_IMPORTS    0x00000002u
#define HV_BRIDGE_CAP_MEMORY_IO          0x00000004u /* VT-root R/W only */
#define HV_BRIDGE_CAP_THREAD_CONTEXT     0x00000008u
#define HV_BRIDGE_CAP_PEB_SCRUB          0x00000010u /* VT-root PEB R/W */
/*
 * Legacy generic bits.  They do not prove a VT-root implementation and new
 * peers must not use them to describe one.  They remain assigned so protocol
 * v4 binaries keep their original wire layout and bit values.
 */
#define HV_BRIDGE_CAP_MEMORY_PROTECT     0x00000020u
#define HV_BRIDGE_CAP_COW_WRITE          0x00000040u
#define HV_BRIDGE_CAP_PRIVATE_SWBP       0x00000080u
#define HV_BRIDGE_CAP_VT_HWBP            0x00000100u
#define HV_BRIDGE_CAP_DR_HWBP_FALLBACK   0x00000200u
/* Explicit Windows-assisted fallbacks; neither flag is a VT capability. */
#define HV_BRIDGE_CAP_OS_MEMORY_PROTECT  0x00000400u
#define HV_BRIDGE_CAP_OS_COW_WRITE       0x00000800u
#define HV_BRIDGE_CAP_VT_STEP            0x00001000u
#define HV_BRIDGE_CAP_PRIVATE_DEBUG_OBJECT 0x00002000u

/* Runtime state carried in HV_BRIDGE_RESULT.Flags without changing its ABI. */
#define HV_BRIDGE_STATE_DRIVER_HIDE      0x01000000u
#define HV_BRIDGE_STATE_FILE_HIDE        0x02000000u
#define HV_BRIDGE_STATE_REGISTRY_HIDE    0x04000000u
#define HV_BRIDGE_STATE_NETWORK_HOOK     0x08000000u
#define HV_BRIDGE_STATE_PRIVATE_DEBUG_OBJECT 0x10000000u

#define HV_BRIDGE_HWBP_ALLOW_VT          0x00000001u
#define HV_BRIDGE_HWBP_ALLOW_DR          0x00000002u
// Legacy observational delivery through IOCTL_HV_DBG_WAIT_EVENT. Precise
// debugger stops must leave this clear and route the injected #DB through the
// target's Windows or private DebugObject.
#define HV_BRIDGE_HWBP_PRIVATE_EVENT     0x00000004u

#define HV_BRIDGE_HWBP_MODE_NONE         0u
#define HV_BRIDGE_HWBP_MODE_VT           1u
#define HV_BRIDGE_HWBP_MODE_DR           2u

#define HV_BRIDGE_BIND_PREVENT_TERMINATE 0x00000001u
#define HV_BRIDGE_BIND_PREVENT_SUSPEND   0x00000002u
#define HV_BRIDGE_BIND_PREVENT_MEMORY    0x00000004u
#define HV_BRIDGE_BIND_EXPECT_WINDOWS_DEBUG_OBJECT 0x00010000u
#define HV_BRIDGE_BIND_EXPECT_PRIVATE_DBGK         0x00020000u
#define HV_BRIDGE_BIND_DEFER_PEB_CLOAK             0x00040000u
#define HV_BRIDGE_BIND_EXPECT_DEBUG_OBJECT_MASK    \
    (HV_BRIDGE_BIND_EXPECT_WINDOWS_DEBUG_OBJECT |  \
     HV_BRIDGE_BIND_EXPECT_PRIVATE_DBGK)
#define HV_BRIDGE_BIND_DEFAULT_FLAGS     \
    (HV_BRIDGE_BIND_PREVENT_TERMINATE | \
     HV_BRIDGE_BIND_PREVENT_SUSPEND |   \
     HV_BRIDGE_BIND_PREVENT_MEMORY)

#define IOCTL_HV_BRIDGE_REGISTER \
    CTL_CODE(FILE_DEVICE_UNKNOWN, HV_IOCTL_BASE + 0x45, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HV_BRIDGE_BIND_TARGET \
    CTL_CODE(FILE_DEVICE_UNKNOWN, HV_IOCTL_BASE + 0x46, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HV_BRIDGE_UNBIND_TARGET \
    CTL_CODE(FILE_DEVICE_UNKNOWN, HV_IOCTL_BASE + 0x47, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HV_BRIDGE_SCRUB_PEB \
    CTL_CODE(FILE_DEVICE_UNKNOWN, HV_IOCTL_BASE + 0x48, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* IOCTL_HV_BRIDGE_SCRUB_PEB request flags. */
#define HV_BRIDGE_PEB_CLOAK_ACTIVATE      0x00000001u

/* Aliases for the existing driver operations used by the injected bridge. */
#define IOCTL_HV_BRIDGE_MEMORY_READ \
    CTL_CODE(FILE_DEVICE_UNKNOWN, HV_IOCTL_BASE + 0x85, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HV_BRIDGE_MEMORY_WRITE \
    CTL_CODE(FILE_DEVICE_UNKNOWN, HV_IOCTL_BASE + 0x86, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HV_BRIDGE_MEMORY_PROTECT \
    CTL_CODE(FILE_DEVICE_UNKNOWN, HV_IOCTL_BASE + 0x89, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HV_BRIDGE_MEMORY_WRITE_COW \
    CTL_CODE(FILE_DEVICE_UNKNOWN, HV_IOCTL_BASE + 0x8A, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HV_BRIDGE_SET_HWBP \
    CTL_CODE(FILE_DEVICE_UNKNOWN, HV_IOCTL_BASE + 0x100, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HV_BRIDGE_CLEAR_HWBP \
    CTL_CODE(FILE_DEVICE_UNKNOWN, HV_IOCTL_BASE + 0x101, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HV_BRIDGE_WAIT_EVENT \
    CTL_CODE(FILE_DEVICE_UNKNOWN, HV_IOCTL_BASE + 0x102, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HV_BRIDGE_CONTINUE_EVENT \
    CTL_CODE(FILE_DEVICE_UNKNOWN, HV_IOCTL_BASE + 0x103, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HV_BRIDGE_GET_DBGEVT \
    CTL_CODE(FILE_DEVICE_UNKNOWN, HV_IOCTL_BASE + 0x106, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HV_BRIDGE_SWBP_ADD \
    CTL_CODE(FILE_DEVICE_UNKNOWN, HV_IOCTL_BASE + 0x108, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HV_BRIDGE_SWBP_DEL \
    CTL_CODE(FILE_DEVICE_UNKNOWN, HV_IOCTL_BASE + 0x109, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HV_BRIDGE_RESOLVE_THREAD \
    CTL_CODE(FILE_DEVICE_UNKNOWN, HV_IOCTL_BASE + 0x10B, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HV_BRIDGE_STEP_ARM \
    CTL_CODE(FILE_DEVICE_UNKNOWN, HV_IOCTL_BASE + 0x10A, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HV_BRIDGE_STEP_CLEAR \
    CTL_CODE(FILE_DEVICE_UNKNOWN, HV_IOCTL_BASE + 0x10C, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HV_BRIDGE_DBGK_WAIT \
    CTL_CODE(FILE_DEVICE_UNKNOWN, HV_IOCTL_BASE + 0x10D, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HV_BRIDGE_DBGK_CONTINUE \
    CTL_CODE(FILE_DEVICE_UNKNOWN, HV_IOCTL_BASE + 0x10E, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HV_BRIDGE_DBGK_SYMBOLS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, HV_IOCTL_BASE + 0x10F, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HV_BRIDGE_PENDING_HWBP \
    CTL_CODE(FILE_DEVICE_UNKNOWN, HV_IOCTL_BASE + 0x110, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define HV_BRIDGE_MEMORY_MAX_PAYLOAD 0x10000u
#define HV_BRIDGE_STATUS_SUCCESS     0u
#define HV_BRIDGE_STATUS_NOT_FOUND   4u

#define HV_BRIDGE_PRIVATE_EVENT_HWBP 0u
#define HV_BRIDGE_PRIVATE_EVENT_SWBP 1u
#define HV_BRIDGE_PRIVATE_EVENT_STEP 2u

#define HV_BRIDGE_DBGK_CREATE_THREAD  2u
#define HV_BRIDGE_DBGK_CREATE_PROCESS 3u
#define HV_BRIDGE_DBGK_EXIT_THREAD    4u
#define HV_BRIDGE_DBGK_EXIT_PROCESS   5u
#define HV_BRIDGE_DBGK_EXCEPTION      6u
#define HV_BRIDGE_DBGK_BREAKPOINT     7u
#define HV_BRIDGE_DBGK_SINGLE_STEP    8u
#define HV_BRIDGE_DBGK_LOAD_DLL       9u
#define HV_BRIDGE_DBGK_UNLOAD_DLL     10u

#define HV_BRIDGE_DBGK_EVENT_SYNCHRONOUS 0x00000001u
#define HV_BRIDGE_DBGK_EVENT_INITIAL     0x00000002u
#define HV_BRIDGE_DBGK_EVENT_DELIVERED   0x00000004u
#define HV_BRIDGE_DBGK_EVENT_VT_HWBP     0x00000008u
#define HV_BRIDGE_DBGK_VT_GENERATION_INDEX 13u
#define HV_BRIDGE_DBGK_VT_DR6_INDEX      14u

#define HV_BRIDGE_PENDING_HWBP_QUERY      0u
#define HV_BRIDGE_PENDING_HWBP_RETIRE     1u

typedef struct _HV_BRIDGE_REGISTER_REQUEST {
    ULONG Version;
    ULONG Capabilities;
} HV_BRIDGE_REGISTER_REQUEST, *PHV_BRIDGE_REGISTER_REQUEST;

typedef struct _HV_BRIDGE_TARGET_REQUEST {
    ULONG Version;
    ULONG TargetPid;
    ULONG Flags;
    ULONG Reserved;
} HV_BRIDGE_TARGET_REQUEST, *PHV_BRIDGE_TARGET_REQUEST;

typedef struct _HV_BRIDGE_RESULT {
    ULONG Version;
    LONG  Status;
    ULONG DebuggerPid;
    ULONG TargetPid;
    ULONG ActiveBindings;
    ULONG Flags;
} HV_BRIDGE_RESULT, *PHV_BRIDGE_RESULT;

typedef struct _HV_BRIDGE_MEMORY_REQUEST {
    ULONG   ProcessId;
    ULONG   Reserved0;
    ULONG64 Address;
    ULONG   Size;
    ULONG   Reserved1;
} HV_BRIDGE_MEMORY_REQUEST, *PHV_BRIDGE_MEMORY_REQUEST;

typedef struct _HV_BRIDGE_MEMORY_RESULT {
    LONG    Status;
    ULONG   Reserved0;
    ULONG64 Address;
    ULONG   BytesTransferred;
    ULONG   Reserved1;
} HV_BRIDGE_MEMORY_RESULT, *PHV_BRIDGE_MEMORY_RESULT;

typedef struct _HV_BRIDGE_PROTECT_REQUEST {
    ULONG   ProcessId;
    ULONG   NewProtection;
    ULONG64 Address;
    ULONG64 Size;
} HV_BRIDGE_PROTECT_REQUEST, *PHV_BRIDGE_PROTECT_REQUEST;

typedef struct _HV_BRIDGE_PROTECT_RESULT {
    LONG    Status;
    ULONG   OldProtection;
    ULONG64 Address;
    ULONG64 Size;
} HV_BRIDGE_PROTECT_RESULT, *PHV_BRIDGE_PROTECT_RESULT;

typedef struct _HV_BRIDGE_HWBP_REQUEST {
    ULONG   DebuggerPid;
    ULONG   TargetPid;
    ULONG   SlotIndex;
    ULONG   Reserved0;
    ULONG64 Address;
    UCHAR   Length;
    UCHAR   Type;
    UCHAR   Reserved1[2];
    ULONG   TargetTid;
} HV_BRIDGE_HWBP_REQUEST, *PHV_BRIDGE_HWBP_REQUEST;

typedef struct _HV_BRIDGE_OPERATION_RESULT {
    ULONG   Status;
    ULONG   Reserved;
    ULONG64 Info;
} HV_BRIDGE_OPERATION_RESULT, *PHV_BRIDGE_OPERATION_RESULT;

typedef struct _HV_BRIDGE_SWBP_REQUEST {
    ULONG   Version;
    ULONG   TargetPid;
    ULONG   ScopeThreadId;
    ULONG   Flags;
    ULONG64 Address;
} HV_BRIDGE_SWBP_REQUEST, *PHV_BRIDGE_SWBP_REQUEST;

#define HV_BRIDGE_SWBP_SCOPE_THREAD 0x00000001u

typedef struct _HV_BRIDGE_STEP_REQUEST {
    ULONG   Version;
    ULONG   TargetPid;
    ULONG   ThreadId;
    ULONG   Reserved;
    ULONG64 Address;
} HV_BRIDGE_STEP_REQUEST, *PHV_BRIDGE_STEP_REQUEST;

typedef struct _HV_BRIDGE_PENDING_HWBP_REQUEST {
    ULONG   Version;
    ULONG   TargetPid;
    ULONG   ThreadId;
    ULONG   Operation;
    ULONG64 Generation;
} HV_BRIDGE_PENDING_HWBP_REQUEST, *PHV_BRIDGE_PENDING_HWBP_REQUEST;

typedef struct _HV_BRIDGE_PENDING_HWBP_RESULT {
    LONG    Status;
    ULONG   Reserved;
    ULONG64 Generation;
    ULONG64 Dr6Mask;
} HV_BRIDGE_PENDING_HWBP_RESULT, *PHV_BRIDGE_PENDING_HWBP_RESULT;

typedef struct _HV_BRIDGE_PRIVATE_WAIT_REQUEST {
    ULONG Version;
    ULONG TimeoutMs;
} HV_BRIDGE_PRIVATE_WAIT_REQUEST, *PHV_BRIDGE_PRIVATE_WAIT_REQUEST;

typedef struct _HV_BRIDGE_PRIVATE_EVENT {
    ULONG64 Sequence;
    ULONG   ThreadId;
    ULONG   ProcessId;
    ULONG64 Cr3;
    ULONG64 Rip;
    ULONG64 Rsp;
    ULONG64 Rflags;
    ULONG64 Gpr[15];
    ULONG64 Dr6;
    ULONG   HitSlot;
    ULONG   Kind;
    ULONG64 ThreadToken;
} HV_BRIDGE_PRIVATE_EVENT, *PHV_BRIDGE_PRIVATE_EVENT;

typedef struct _HV_BRIDGE_PRIVATE_WAIT_RESULT {
    LONG                    Status;
    ULONG                   Reserved;
    HV_BRIDGE_PRIVATE_EVENT Event;
} HV_BRIDGE_PRIVATE_WAIT_RESULT, *PHV_BRIDGE_PRIVATE_WAIT_RESULT;

typedef struct _HV_BRIDGE_PRIVATE_CONTINUE_REQUEST {
    ULONG   Version;
    ULONG   ContinueStatus;
    ULONG64 Sequence;
    ULONG   ProcessId;
    ULONG   ThreadId;
    ULONG64 ThreadToken;
} HV_BRIDGE_PRIVATE_CONTINUE_REQUEST,
  *PHV_BRIDGE_PRIVATE_CONTINUE_REQUEST;

typedef struct _HV_BRIDGE_DBGK_EVENT {
    ULONG64 Sequence;
    ULONG   ProcessId;
    ULONG   ThreadId;
    ULONG   State;
    ULONG   Flags;
    LONG    Status;
    ULONG   FirstChance;
    ULONG64 ProcessHandle;
    ULONG64 ThreadHandle;
    ULONG64 FileHandle;
    ULONG64 BaseAddress;
    ULONG64 StartAddress;
    ULONG64 NamePointer;
    ULONG   DebugInfoFileOffset;
    ULONG   DebugInfoSize;
    LONG    ExitStatus;
    ULONG   ExceptionCode;
    ULONG   ExceptionFlags;
    ULONG   NumberParameters;
    ULONG64 ExceptionAddress;
    ULONG64 ExceptionInformation[15];
} HV_BRIDGE_DBGK_EVENT, *PHV_BRIDGE_DBGK_EVENT;

typedef struct _HV_BRIDGE_DBGK_WAIT_RESULT {
    LONG                   Status;
    ULONG                  Reserved;
    HV_BRIDGE_DBGK_EVENT   Event;
} HV_BRIDGE_DBGK_WAIT_RESULT, *PHV_BRIDGE_DBGK_WAIT_RESULT;

typedef struct _HV_BRIDGE_DBGK_CONTINUE_REQUEST {
    ULONG   Version;
    ULONG   ContinueStatus;
    ULONG64 Sequence;
    ULONG   ProcessId;
    ULONG   ThreadId;
    ULONG64 Reserved;
} HV_BRIDGE_DBGK_CONTINUE_REQUEST,
  *PHV_BRIDGE_DBGK_CONTINUE_REQUEST;

typedef struct _HV_BRIDGE_DBGK_SYMBOLS_REQUEST {
    ULONG   Version;
    ULONG   Reserved;
    ULONG64 NtCreateDebugObject;
    ULONG64 NtDebugActiveProcess;
    ULONG64 NtSetInformationDebugObject;
    ULONG64 NtWaitForDebugEvent;
    ULONG64 NtDebugContinue;
    ULONG64 NtRemoveProcessDebug;
    ULONG64 DbgkForwardException;
    ULONG64 DbgkCreateThread;
    ULONG64 DbgkExitThread;
    ULONG64 DbgkExitProcess;
    ULONG64 DbgkMapViewOfSection;
    ULONG64 DbgkUnMapViewOfSection;
    ULONG64 PsGetNextProcessThread;
    ULONG64 NtSetContextThread;
    ULONG64 NtReadVirtualMemory;
    ULONG64 NtWriteVirtualMemory;
} HV_BRIDGE_DBGK_SYMBOLS_REQUEST,
  *PHV_BRIDGE_DBGK_SYMBOLS_REQUEST;

typedef struct _HV_BRIDGE_THREAD_RESOLVE_REQUEST {
    ULONG   Version;
    ULONG   ProcessId;
    ULONG   ThreadId;
    ULONG   Reserved;
    ULONG64 ThreadToken;
} HV_BRIDGE_THREAD_RESOLVE_REQUEST, *PHV_BRIDGE_THREAD_RESOLVE_REQUEST;

typedef struct _HV_BRIDGE_THREAD_RESOLVE_RESULT {
    LONG    Status;
    ULONG   ThreadId;
    ULONG64 ThreadToken;
} HV_BRIDGE_THREAD_RESOLVE_RESULT, *PHV_BRIDGE_THREAD_RESOLVE_RESULT;

#define HV_BRIDGE_DBGEVT_DETAIL_MAX 192u

typedef struct _HV_BRIDGE_DBGEVT_PULL_REQUEST {
    ULONG64 SinceSequence;
    ULONG   MaxCount;
    ULONG   Reserved;
} HV_BRIDGE_DBGEVT_PULL_REQUEST, *PHV_BRIDGE_DBGEVT_PULL_REQUEST;

typedef struct _HV_BRIDGE_DBGEVT_PULL_RESULT {
    ULONG   Count;
    ULONG   Reserved;
    ULONG64 NextSequence;
} HV_BRIDGE_DBGEVT_PULL_RESULT, *PHV_BRIDGE_DBGEVT_PULL_RESULT;

typedef struct _HV_BRIDGE_DBGEVT {
    ULONG64 Sequence;
    ULONG64 TimestampQpc;
    ULONG   Severity;
    ULONG   Category;
    LONG    Status;
    ULONG   CallerPid;
    ULONG   TargetPid;
    ULONG   Reserved;
    ULONG64 Address;
    ULONG64 Size;
    CHAR    Detail[HV_BRIDGE_DBGEVT_DETAIL_MAX];
} HV_BRIDGE_DBGEVT, *PHV_BRIDGE_DBGEVT;

#if defined(__cplusplus)
static_assert(sizeof(HV_BRIDGE_REGISTER_REQUEST) == 8, "bridge register ABI drift");
static_assert(sizeof(HV_BRIDGE_TARGET_REQUEST) == 16, "bridge target ABI drift");
static_assert(sizeof(HV_BRIDGE_RESULT) == 24, "bridge result ABI drift");
static_assert(sizeof(HV_BRIDGE_MEMORY_REQUEST) == 24, "bridge memory request ABI drift");
static_assert(sizeof(HV_BRIDGE_MEMORY_RESULT) == 24, "bridge memory result ABI drift");
static_assert(sizeof(HV_BRIDGE_PROTECT_REQUEST) == 24, "bridge protect request ABI drift");
static_assert(sizeof(HV_BRIDGE_PROTECT_RESULT) == 24, "bridge protect result ABI drift");
static_assert(sizeof(HV_BRIDGE_HWBP_REQUEST) == 32, "bridge HWBP request ABI drift");
static_assert(sizeof(HV_BRIDGE_OPERATION_RESULT) == 16, "bridge operation result ABI drift");
static_assert(sizeof(HV_BRIDGE_SWBP_REQUEST) == 24, "bridge SWBP request ABI drift");
static_assert(sizeof(HV_BRIDGE_STEP_REQUEST) == 24, "bridge step request ABI drift");
static_assert(sizeof(HV_BRIDGE_PENDING_HWBP_REQUEST) == 24, "bridge pending HWBP request ABI drift");
static_assert(sizeof(HV_BRIDGE_PENDING_HWBP_RESULT) == 24, "bridge pending HWBP result ABI drift");
static_assert(sizeof(HV_BRIDGE_PRIVATE_WAIT_REQUEST) == 8, "bridge private wait request ABI drift");
static_assert(sizeof(HV_BRIDGE_PRIVATE_EVENT) == 192, "bridge private event ABI drift");
static_assert(sizeof(HV_BRIDGE_PRIVATE_WAIT_RESULT) == 200, "bridge private wait result ABI drift");
static_assert(sizeof(HV_BRIDGE_PRIVATE_CONTINUE_REQUEST) == 32, "bridge private continue request ABI drift");
static_assert(sizeof(HV_BRIDGE_DBGK_EVENT) == 232, "bridge Dbgk event ABI drift");
static_assert(sizeof(HV_BRIDGE_DBGK_WAIT_RESULT) == 240, "bridge Dbgk wait result ABI drift");
static_assert(sizeof(HV_BRIDGE_DBGK_CONTINUE_REQUEST) == 32, "bridge Dbgk continue request ABI drift");
static_assert(sizeof(HV_BRIDGE_DBGK_SYMBOLS_REQUEST) == 136, "bridge Dbgk symbols ABI drift");
static_assert(sizeof(HV_BRIDGE_THREAD_RESOLVE_REQUEST) == 24, "bridge thread resolve request ABI drift");
static_assert(sizeof(HV_BRIDGE_THREAD_RESOLVE_RESULT) == 16, "bridge thread resolve result ABI drift");
static_assert(sizeof(HV_BRIDGE_DBGEVT_PULL_REQUEST) == 16, "bridge event pull request ABI drift");
static_assert(sizeof(HV_BRIDGE_DBGEVT_PULL_RESULT) == 16, "bridge event pull result ABI drift");
static_assert(sizeof(HV_BRIDGE_DBGEVT) == 248, "bridge event ABI drift");
#elif defined(C_ASSERT)
C_ASSERT(sizeof(HV_BRIDGE_REGISTER_REQUEST) == 8);
C_ASSERT(sizeof(HV_BRIDGE_TARGET_REQUEST) == 16);
C_ASSERT(sizeof(HV_BRIDGE_RESULT) == 24);
C_ASSERT(sizeof(HV_BRIDGE_MEMORY_REQUEST) == 24);
C_ASSERT(sizeof(HV_BRIDGE_MEMORY_RESULT) == 24);
C_ASSERT(sizeof(HV_BRIDGE_PROTECT_REQUEST) == 24);
C_ASSERT(sizeof(HV_BRIDGE_PROTECT_RESULT) == 24);
C_ASSERT(sizeof(HV_BRIDGE_HWBP_REQUEST) == 32);
C_ASSERT(sizeof(HV_BRIDGE_OPERATION_RESULT) == 16);
C_ASSERT(sizeof(HV_BRIDGE_SWBP_REQUEST) == 24);
C_ASSERT(sizeof(HV_BRIDGE_STEP_REQUEST) == 24);
C_ASSERT(sizeof(HV_BRIDGE_PENDING_HWBP_REQUEST) == 24);
C_ASSERT(sizeof(HV_BRIDGE_PENDING_HWBP_RESULT) == 24);
C_ASSERT(sizeof(HV_BRIDGE_PRIVATE_WAIT_REQUEST) == 8);
C_ASSERT(sizeof(HV_BRIDGE_PRIVATE_EVENT) == 192);
C_ASSERT(sizeof(HV_BRIDGE_PRIVATE_WAIT_RESULT) == 200);
C_ASSERT(sizeof(HV_BRIDGE_PRIVATE_CONTINUE_REQUEST) == 32);
C_ASSERT(sizeof(HV_BRIDGE_DBGK_EVENT) == 232);
C_ASSERT(sizeof(HV_BRIDGE_DBGK_WAIT_RESULT) == 240);
C_ASSERT(sizeof(HV_BRIDGE_DBGK_CONTINUE_REQUEST) == 32);
C_ASSERT(sizeof(HV_BRIDGE_DBGK_SYMBOLS_REQUEST) == 136);
C_ASSERT(sizeof(HV_BRIDGE_THREAD_RESOLVE_REQUEST) == 24);
C_ASSERT(sizeof(HV_BRIDGE_THREAD_RESOLVE_RESULT) == 16);
C_ASSERT(sizeof(HV_BRIDGE_DBGEVT_PULL_REQUEST) == 16);
C_ASSERT(sizeof(HV_BRIDGE_DBGEVT_PULL_RESULT) == 16);
C_ASSERT(sizeof(HV_BRIDGE_DBGEVT) == 248);
#endif

#endif /* NETR_BRIDGE_PROTOCOL_H */
