/*
 * HvPhysAccess.h
 *
 * VT-first process-memory data path. Windows context owns referenced-process
 * and MDL lifetimes; VMX-root/SVM-host owns CR3 validation, page-table walks
 * and the actual copy.
 */

#ifndef _HV_PHYS_ACCESS_H_
#define _HV_PHYS_ACCESS_H_

#pragma once

#include <ntddk.h>

#define HV_PHYS_TAG  'hPvH'

// ============================================================
// Process snapshot candidate offsets
// ============================================================
//
// The control plane reads only these candidate offsets while holding a
// referenced EPROCESS. Page-table validation, walking and copying stay in VT.

#define HV_PHYS_KNOWN_USER_DTB_OFFSETS_MAX  8

typedef struct _HV_PHYS_ROOT_CTX {
    // KPROCESS::DirectoryTableBase offset, probed against the current CR3.
    ULONG  DtbOff;

    // Version-dependent candidate offsets captured without dereferencing the
    // candidate page tables in Windows context.
    UINT64 KnownUserDtbOffs[HV_PHYS_KNOWN_USER_DTB_OFFSETS_MAX];
    ULONG  KnownUserDtbOffCount;

    // Published only after the offset snapshot is complete.
    BOOLEAN Initialized;
} HV_PHYS_ROOT_CTX, *PHV_PHYS_ROOT_CTX;

// Global immutable candidate-offset snapshot.
extern HV_PHYS_ROOT_CTX g_HvPhysRootCtx;


// ============================================================
// CR3 validation / GVA -> HPA compatibility surface
// ============================================================
//
// These entry points intentionally preserve the old HvPhysAccess API shape,
// but their implementation is VT-first.  PID based operations never walk a
// page table in Windows context: PASSIVE_LEVEL captures a lifetime-protected
// process snapshot and VMX-root/SVM-host validates the CR3 and performs the
// walk through the pre-mapped per-VCPU physical window.

/*
 * Return the validated user CR3 for ProcessId.  Unlike the historical
 * implementation this does not expose EPROCESS::DirectoryTableBase directly;
 * the value is accepted only after the VT-root PEB/ImageBase/MZ ownership
 * check succeeds.
 */
NTSTATUS
HvPhysGetProcessCr3(
    _In_ ULONG ProcessId,
    _Out_ PUINT64 OutCr3
);

/*
 * Validate that CandidateCr3 is the CR3 currently resolved for ProcessId.
 * PID reuse is covered by the create-time keyed resolver in HvVtRoot.
 */
NTSTATUS
HvPhysValidateProcessCr3(
    _In_ ULONG ProcessId,
    _In_ UINT64 CandidateCr3
);

/*
 * Preferred PID-safe GVA translation.  CR3 ownership validation and the walk
 * both execute in VT root.  OutPteFlags is currently returned as zero because
 * the root request ABI does not yet export leaf flags.
 */
NTSTATUS
HvPhysGvaToHpaByPid(
    _In_ ULONG ProcessId,
    _In_ UINT64 Gva,
    _Out_ PPHYSICAL_ADDRESS OutHpa,
    _Out_opt_ PSIZE_T OutPageSize,
    _Out_opt_ PUINT64 OutPteFlags
);

/*
 * Source-compatible trusted-CR3 translator.  The page-table walk still runs
 * in VT root and rejects non-RAM table PFNs.  It is not a PID lookup API and
 * therefore must only receive a CR3 previously returned by the validated
 * resolver above while the caller retains the CR3 owner's lifetime. New
 * PID-based callers must use HvPhysGvaToHpaByPid.
 *
 * The compatibility entry now uses the trusted-CR3 leaf-info root ABI, so
 * 4KB/2MB/1GB leaves all return HPA and page size. OutPteFlags preserves the
 * historical contract and receives the complete original PTE/PDE/PDPTE value.
 */
NTSTATUS
HvPhysGvaToHpa(
    _In_ UINT64 TargetCr3,
    _In_ UINT64 Gva,
    _Out_ PPHYSICAL_ADDRESS OutHpa,
    _Out_opt_ PSIZE_T OutPageSize,
    _Out_opt_ PUINT64 OutPteFlags
);

/*
 * Compatibility control.  Root walkers are already quiet on ordinary
 * not-present entries, so this is retained as a source-compatible no-op state
 * rather than deleting callers that still pair set/clear operations.
 */
VOID
HvPhysSetWalkQuiet(
    _In_ BOOLEAN Quiet
);


/*
 * Compatibility aliases for the VT-root resolver. The GVA form validates the
 * hint range but process identity is always anchored by PEB/ImageBase/MZ.
 */
NTSTATUS
HvPhysFindUserCr3ByPid(
    _In_ ULONG ProcessId,
    _Out_ PUINT64 OutCr3
);

NTSTATUS
HvPhysFindUserCr3ForGvaByPid(
    _In_ ULONG ProcessId,
    _In_ UINT64 GvaHint,
    _Out_ PUINT64 OutCr3
);

BOOLEAN
HvPhysIsRamRangeRootSafe(
    _In_ UINT64 PhysicalAddress,
    _In_ SIZE_T Size
);


#define HV_PHYS_COPY_STAGE_VALIDATE       1u
#define HV_PHYS_COPY_STAGE_BUFFER_LOCK    2u
#define HV_PHYS_COPY_STAGE_PROCESS_LOOKUP 3u
#define HV_PHYS_COPY_STAGE_TARGET_LOCK    4u
#define HV_PHYS_COPY_STAGE_CR3_RESOLVE    5u
#define HV_PHYS_COPY_STAGE_VT_ROOT_COPY   6u
#define HV_PHYS_COPY_STAGE_COMPLETE       7u
#define HV_PHYS_COPY_STAGE_MDL_FALLBACK   8u

typedef struct _HV_PHYS_COPY_DIAG {
    ULONG    Stage;
    NTSTATUS DetailStatus;
    UINT64   TargetCr3;
} HV_PHYS_COPY_DIAG, *PHV_PHYS_COPY_DIAG;

// ============================================================
// 跨进程 Read / Write
// ============================================================

/*
 * Cross-process read. The target and identity anchors are MDL-locked before
 * root mode performs a page-bounded walk and copy.
 *
 * 失败码:
 *   STATUS_INVALID_PARAMETER —— 参数为 NULL 或 Size=0。
 *   STATUS_NOT_FOUND          —— GVA 未映射或被换出。读取在该页处中止,
 *                                BytesRead 反映成功的字节数。
 *   STATUS_INSUFFICIENT_RESOURCES —— request/bounce/MDL allocation failed.
 */
NTSTATUS
HvPhysReadProcessMemory(
    _In_ ULONG TargetPid,
    _In_ UINT64 Gva,
    _Out_writes_bytes_(Size) PVOID Buffer,
    _In_ SIZE_T Size,
    _Out_opt_ PSIZE_T BytesRead
);

NTSTATUS
HvPhysReadProcessMemoryDiagnosed(
    _In_ ULONG TargetPid,
    _In_ UINT64 Gva,
    _Out_writes_bytes_(Size) PVOID Buffer,
    _In_ SIZE_T Size,
    _Out_opt_ PSIZE_T BytesRead,
    _Out_ PHV_PHYS_COPY_DIAG Diag
);

/*
 * Cross-process write through the same VT-root request path.
 *
 * 失败码同 Read。
 */
NTSTATUS
HvPhysWriteProcessMemory(
    _In_ ULONG TargetPid,
    _In_ UINT64 Gva,
    _In_reads_bytes_(Size) PVOID Buffer,
    _In_ SIZE_T Size,
    _Out_opt_ PSIZE_T BytesWritten
);


// ============================================================
// Leaf-PTE query and staged page-table management surface
// ============================================================
//
// Leaf lookup is implemented by HV_VTROOT_MODE_LEAF_PTE_INFO and never maps
// paging structures in Windows context. The Ex form reports 4KB/2MB/1GB leaf
// metadata. The source-compatible form below succeeds only for 4KB leaves.
//
// The backup implementation wrote target PTEs and allocated backing pages
// without creating a VAD or maintaining PFN/commit accounting.  That path is
// deliberately fail-closed.  The allocation interfaces remain present so the
// subsystem can be completed with a real lifetime/rollback owner instead of
// being silently deleted.

#define HV_PHYS_LEAF_LEVEL_PT                  1UL
#define HV_PHYS_LEAF_LEVEL_PD                  2UL
#define HV_PHYS_LEAF_LEVEL_PDPT                3UL

typedef struct _HV_PHYS_LEAF_PTE_INFO {
    UINT64 LeafTablePa;
    ULONG  LeafIndex;
    ULONG  LeafLevel;
    UINT64 OriginalPte;
    UINT64 LeafHpa;
    SIZE_T PageSize;
    UINT64 LeafFlags;
} HV_PHYS_LEAF_PTE_INFO, *PHV_PHYS_LEAF_PTE_INFO;

/*
 * Query a 4KB/2MB/1GB leaf through the trusted-CR3 VT-root ABI. TargetVa may
 * be canonical user or kernel VA. A non-present 4KB PTE slot is returned
 * successfully with LeafHpa=0 and its original software PTE value. The caller
 * must retain the address-space owner and mapping-table lifetime for the
 * synchronous call.
 */
NTSTATUS
HvPhysFindLeafPteLocationEx(
    _In_ UINT64 TargetCr3,
    _In_ UINT64 TargetVa,
    _Out_ PHV_PHYS_LEAF_PTE_INFO OutInfo
);

// Retained bit value for source compatibility. Leaf-PTE location is no longer
// reported as staged by HvPhysQueryStagedCapabilities.
#define HV_PHYS_STAGED_LEAF_PTE_LOCATION       0x00000001UL
#define HV_PHYS_STAGED_RAW_PTE_PROCESS_ALLOC   0x00000002UL

ULONG
HvPhysQueryStagedCapabilities(VOID);

NTSTATUS
HvPhysAllocateInProcess(
    _In_ ULONG TargetPid,
    _In_ SIZE_T Size,
    _In_ ULONG Protection,
    _Inout_ PUINT64 InOutGva
);

NTSTATUS
HvPhysFreeInProcess(
    _In_ ULONG TargetPid,
    _In_ UINT64 Gva,
    _In_ SIZE_T Size
);

/*
 * Source-compatible 4KB leaf query. For a 2MB/1GB leaf it returns
 * STATUS_NOT_SUPPORTED with zero outputs, preventing legacy callers from
 * treating a PDE/PDPTE as a 4KB PTE. Use HvPhysFindLeafPteLocationEx to
 * inspect all leaf sizes.
 */
NTSTATUS
HvPhysFindLeafPteLocation(
    _In_ UINT64 TargetCr3,
    _In_ UINT64 TargetVa,
    _Out_ PUINT64 OutPtPagePa,
    _Out_ PULONG OutPteIndex,
    _Out_opt_ PUINT64 OutOrigPte
);



// ============================================================
// 模块枚举 (无痕, 经 VtRoot 读 PEB.Ldr 链表)
// ============================================================

#define HV_MODULE_NAME_MAX        128   // WCHAR 数, 含末尾 0
#define HV_MAX_MODULES_PER_PROCESS 384  // 上限, 防 LDR 链表 corruption 跑飞

#pragma pack(push, 8)
typedef struct _HV_MODULE_INFO {
    UINT64 DllBase;                          // LDR_DATA_TABLE_ENTRY.DllBase
    ULONG  SizeOfImage;                      // LDR_DATA_TABLE_ENTRY.SizeOfImage
    ULONG  Reserved;                         // 对齐
    WCHAR  Name[HV_MODULE_NAME_MAX];         // BaseDllName, null-terminated
} HV_MODULE_INFO, *PHV_MODULE_INFO;
#pragma pack(pop)

/*
 * Enumerate target modules. PASSIVE obtains the PEB from a referenced process;
 * every PEB/Ldr data read then uses the VT-root copy path.
 *
 * 流程:
 *   1) Reference PID and capture PsGetProcessPeb
 *   2) HvVtRootCopyByPid 读 PEB[+0x18] = Ldr (PEB_LDR_DATA*)
 *   3) HvVtRootCopyByPid 读 Ldr[+0x10..+0x20] = InLoadOrderModuleList (LIST_ENTRY)
 *   4) 沿 Flink 遍历, 每个 LDR_DATA_TABLE_ENTRY 读 DllBase/SizeOfImage/BaseDllName
 *   5) BaseDllName.Buffer 单独读为 WCHAR[]
 *
 * 返回:
 *   STATUS_SUCCESS           —— *OutCount 是实际写入的模块数 (≤ MaxCount)
 *   STATUS_INVALID_PARAMETER —— OutModules/OutCount NULL 或 MaxCount=0
 *   STATUS_INVALID_LEVEL     —— IRQL > APC_LEVEL
 *   STATUS_DEVICE_NOT_READY  —— VtRoot 未启用或 RootCtx 未初始化
 *   STATUS_NOT_FOUND         —— PID 不存在 / 目标进程无 user-mode (System 等)
 */
NTSTATUS
HvPhysEnumerateModules(
    _In_ ULONG TargetPid,
    _Out_writes_to_(MaxCount, *OutCount) PHV_MODULE_INFO OutModules,
    _In_ ULONG MaxCount,
    _Out_ PULONG OutCount
);

// ============================================================
// 生命周期
// ============================================================

/*
 * 初始化 HvPhysAccess 控制面状态。Read/Write 的 runtime readiness 仍取决于
 * VtRoot；raw-PTE Alloc/Free 因缺少 VAD/PFN/commit 生命周期而固定 fail-closed。
 */
NTSTATUS
HvPhysAccessInitialize(VOID);

VOID
HvPhysAccessCleanup(VOID);

#endif // _HV_PHYS_ACCESS_H_
