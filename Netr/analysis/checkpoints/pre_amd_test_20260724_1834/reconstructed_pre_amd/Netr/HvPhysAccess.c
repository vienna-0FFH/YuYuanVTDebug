/*
 * VT-first process memory access. PASSIVE code captures a referenced process
 * snapshot and locks the relevant pages; VMX-root/SVM-host validates the CR3,
 * walks the page tables and copies through the per-VCPU scratch mapping.
 */

#include "HvPhysAccess.h"
#include "HvVtRoot.h"
#include "HvCompat.h"
#include "HvUtils.h"
#include "HvCpu.h"
#include "HvHook.h"  // P114: HV_HOT_DBG 宏 (高频 walk 日志默认关)
#include <intrin.h>

// P122: 全 driver DbgPrint → GUI ring
#define HV_TRACE_THIS_CAT HV_TRACE_CAT_PHYS
#include "HvTrace.h"

static BOOLEAN g_PhysAccessInitialized = FALSE;
static volatile LONG g_PhysWalkQuiet = 0;

#define HV_PHYS_CR3_ADDRESS_MASK  0x000FFFFFFFFFF000ULL
#define HV_PHYS_2M_ADDRESS_MASK   0x000FFFFFFFE00000ULL
#define HV_PHYS_1G_ADDRESS_MASK   0x000FFFFFC0000000ULL
#define HV_PHYS_2M_RESERVED_LOW_MASK 0x00000000001FE000ULL
#define HV_PHYS_1G_RESERVED_LOW_MASK 0x000000003FFFE000ULL

// EPROCESS::DirectoryTableBase 偏移 —— Win10/Win11 通常是 0x28,但 24H2/25H2
// 内部结构调整时偏移可能漂移。HvPhysProbeDtbOffset 在首次 GetCr3 调用时
// 用 __readcr3() vs PsGetCurrentProcess() 的 EPROCESS body 自检真实偏移,
// 这里只作为兜底默认值。
#define EPROCESS_DTB_OFFSET_DEFAULT     0x28
static ULONG g_DtbOffset = EPROCESS_DTB_OFFSET_DEFAULT;
static volatile LONG g_DtbOffsetProbed = 0;

// ============================================================
// PA-is-RAM snapshot for root scratch-window validation
// ============================================================
//
// Root mode rejects page-table and leaf PFNs outside this immutable RAM list,
// preventing the scratch mapping from treating MMIO as ordinary WB memory.
typedef struct _HV_PHYS_RAM_RANGE {
    UINT64 Base;   // PA 起始 (4KB 对齐)
    UINT64 End;    // Base + Length, exclusive
} HV_PHYS_RAM_RANGE;

#define HV_PHYS_MAX_RAM_RANGES  64
static HV_PHYS_RAM_RANGE g_RamRanges[HV_PHYS_MAX_RAM_RANGES];
static ULONG g_RamRangeCount = 0;
static volatile LONG g_RamRangesInit = 0;

// ============================================================
// 内部辅助
// ============================================================

/*
 * 初始化 RAM 范围缓存。线程安全:用 Interlocked 抢锁,仅第一线程执行。
 * Failure leaves the root whitelist unavailable; root requests then fail
 * closed instead of mapping an unclassified physical address.
 */
static VOID
HvPhysInitRamRangesIfNeeded(VOID)
{
    if (g_RamRangesInit != 0) return;
    if (InterlockedCompareExchange(&g_RamRangesInit, 1, 0) != 0) return;

    PPHYSICAL_MEMORY_RANGE ranges = MmGetPhysicalMemoryRanges();
    if (!ranges) {
        DbgPrint("[HvPhys] WARNING: MmGetPhysicalMemoryRanges() returned NULL, "
                 "PA-is-RAM check will be disabled\n");
        InterlockedExchange(&g_RamRangesInit, -1);
        return;
    }

    ULONG count = 0;
    UINT64 totalBytes = 0;
    for (ULONG i = 0; i < HV_PHYS_MAX_RAM_RANGES; i++) {
        UINT64 base   = (UINT64)ranges[i].BaseAddress.QuadPart;
        UINT64 length = (UINT64)ranges[i].NumberOfBytes.QuadPart;
        if (base == 0 && length == 0) break;  // 数组结束符
        if (length == 0) continue;            // 跳过 0 长度条目
        g_RamRanges[count].Base = base;
        g_RamRanges[count].End  = base + length;
        totalBytes += length;
        count++;
    }
    g_RamRangeCount = count;

    ExFreePool(ranges);

    if (count == 0) {
        InterlockedExchange(&g_RamRangesInit, -1);
        return;
    }

    InterlockedExchange(&g_RamRangesInit, 2);

    HV_HOT_DBG("[HvPhys] RAM ranges loaded: %u entries, total %llu MB\n",
             count, totalBytes >> 20);
    for (ULONG i = 0; i < count; i++) {
        HV_HOT_DBG("[HvPhys]   range[%u]: 0x%llX - 0x%llX (%llu MB)\n",
                 i, g_RamRanges[i].Base, g_RamRanges[i].End,
                 (g_RamRanges[i].End - g_RamRanges[i].Base) >> 20);
    }
}

BOOLEAN
HvPhysIsRamRangeRootSafe(
    _In_ UINT64 PhysicalAddress,
    _In_ SIZE_T Size)
{
    if (g_RamRangesInit != 2 || g_RamRangeCount == 0 || Size == 0) {
        return FALSE;
    }

    UINT64 end = PhysicalAddress + (UINT64)Size;
    if (end <= PhysicalAddress) {
        return FALSE;
    }

    for (ULONG index = 0; index < g_RamRangeCount; index++) {
        if (PhysicalAddress >= g_RamRanges[index].Base &&
            end <= g_RamRanges[index].End) {
            return TRUE;
        }
    }

    return FALSE;
}


// ============================================================
// Root-mode context (HvPhysAccess.h 中声明的 g_HvPhysRootCtx 定义)
// ============================================================
//
// 在 HvPhysAccessInitialize 中填充, 之后只读, root mode 直接访问。
// 反作弊视角:hot path (memory_read/write IOCTL) 零 Mm*/Ps* 的关键。
HV_PHYS_ROOT_CTX g_HvPhysRootCtx = { 0 };

// 首次调用时确定 EPROCESS::DirectoryTableBase 的真实偏移。
// 思路:当前在 PASSIVE_LEVEL 且没换上下文时, __readcr3() == 当前进程的
// KPROCESS::DirectoryTableBase。扫 0x20..0x100 找匹配偏移。
static VOID
HvPhysProbeDtbOffset(VOID)
{
    if (InterlockedCompareExchange(&g_DtbOffsetProbed, 1, 0) != 0) return;

    PEPROCESS me = PsGetCurrentProcess();
    UINT64 myCr3 = __readcr3() & ~0xFFFULL;

    // 默认值先试一次, 命中就用它(避免偶发 alias)。
    UINT64 defv = *(UINT64*)((PUCHAR)me + EPROCESS_DTB_OFFSET_DEFAULT) & ~0xFFFULL;
    if (defv == myCr3) {
        HV_HOT_DBG("[HvPhys] DTB offset confirmed at default 0x%X (cr3=0x%llX)\n",
                 EPROCESS_DTB_OFFSET_DEFAULT, myCr3);
        return;
    }

    // 默认失配, 扫描。注意先把 DbgPrint 默认值不匹配, 帮 user 诊断。
    HV_HOT_DBG("[HvPhys] DTB at default 0x%X = 0x%llX != cr3=0x%llX, scanning...\n",
             EPROCESS_DTB_OFFSET_DEFAULT, defv, myCr3);

    for (ULONG off = 0x20; off <= 0x100; off += 8) {
        UINT64 cand = *(UINT64*)((PUCHAR)me + off) & ~0xFFFULL;
        if (cand == myCr3) {
            g_DtbOffset = off;
            HV_HOT_DBG("[HvPhys] DTB offset probed -> 0x%X (cr3=0x%llX)\n", off, myCr3);
            return;
        }
    }

    DbgPrint("[HvPhys] DTB probe FAILED, keeping default 0x%X (cr3=0x%llX)\n",
             EPROCESS_DTB_OFFSET_DEFAULT, myCr3);
}


// ============================================================
// VT-root compatibility entry points
// ============================================================

NTSTATUS
HvPhysGetProcessCr3(
    _In_ ULONG ProcessId,
    _Out_ PUINT64 OutCr3
)
{
    // Preserve the public API, not the old unvalidated EPROCESS field read.
    // The resolver publishes a CR3 only after root-mode PEB/ImageBase/MZ
    // ownership validation succeeds.
    return HvVtRootResolveUserCr3(ProcessId, OutCr3);
}

NTSTATUS
HvPhysValidateProcessCr3(
    _In_ ULONG ProcessId,
    _In_ UINT64 CandidateCr3
)
{
    UINT64 resolvedCr3 = 0;

    CandidateCr3 &= HV_PHYS_CR3_ADDRESS_MASK;
    if (ProcessId == 0 || CandidateCr3 == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!HvPhysIsRamRangeRootSafe(CandidateCr3, PAGE_SIZE)) {
        return STATUS_INVALID_ADDRESS_COMPONENT;
    }

    NTSTATUS status = HvVtRootResolveUserCr3(ProcessId, &resolvedCr3);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    return ((resolvedCr3 & HV_PHYS_CR3_ADDRESS_MASK) == CandidateCr3)
        ? STATUS_SUCCESS
        : STATUS_NOT_FOUND;
}

NTSTATUS
HvPhysGvaToHpaByPid(
    _In_ ULONG ProcessId,
    _In_ UINT64 Gva,
    _Out_ PPHYSICAL_ADDRESS OutHpa,
    _Out_opt_ PSIZE_T OutPageSize,
    _Out_opt_ PUINT64 OutPteFlags
)
{
    UINT64 hpa = 0;
    UINT64 pageSize = 0;

    if (!OutHpa) return STATUS_INVALID_PARAMETER;
    OutHpa->QuadPart = 0;
    if (OutPageSize) *OutPageSize = 0;
    if (OutPteFlags) *OutPteFlags = 0;

    NTSTATUS status = HvVtRootWalkGvaToHpa(
        ProcessId, Gva, &hpa, &pageSize);

    // The process request ABI returns both values for large pages while using
    // STATUS_NOT_SUPPORTED to keep old 4KB-only PTE editors fail-closed.
    if (NT_SUCCESS(status) || status == STATUS_NOT_SUPPORTED) {
        OutHpa->QuadPart = (LONGLONG)hpa;
        if (OutPageSize) *OutPageSize = (SIZE_T)pageSize;
        if (status == STATUS_NOT_SUPPORTED && hpa != 0 &&
            (pageSize == 0x200000ULL ||
             pageSize == 0x40000000ULL)) {
            // HvVtRootWalkGvaToHpa retains a legacy 4KB-only status contract,
            // but this API explicitly reports page size and supports large
            // leaves, so translate the complete result to success.
            status = STATUS_SUCCESS;
        }
    }
    return status;
}

static NTSTATUS
HvPhysQueryLeafPteTrusted(
    _In_ UINT64 TargetCr3,
    _In_ UINT64 Gva,
    _Out_ PHV_VTROOT_LEAF_PTE_INFO RootInfo)
{
    SIZE_T returnedSize = 0;
    NTSTATUS status;
    UINT64 addressMask;
    UINT64 offsetMask;

    if (!RootInfo) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(RootInfo, sizeof(*RootInfo));

    if (KeGetCurrentIrql() > APC_LEVEL) return STATUS_INVALID_LEVEL;
    if (!g_VtRootEnabled) return STATUS_DEVICE_NOT_READY;
    if (!((Gva >= 0x10000ULL && Gva < 0x800000000000ULL) ||
          Gva >= 0xFFFF800000000000ULL)) {
        return STATUS_INVALID_PARAMETER;
    }

    TargetCr3 &= HV_PHYS_CR3_ADDRESS_MASK;
    if (!HvPhysIsRamRangeRootSafe(TargetCr3, PAGE_SIZE)) {
        return STATUS_INVALID_ADDRESS_COMPONENT;
    }

    RootInfo->Magic = HV_VTROOT_LEAF_INFO_MAGIC;
    RootInfo->Version = HV_VTROOT_LEAF_INFO_VERSION;
    RootInfo->Size = sizeof(*RootInfo);

    status = HvVtRootInvokeService(
        TargetCr3, Gva, RootInfo, sizeof(*RootInfo),
        HV_VTROOT_MODE_LEAF_PTE_INFO, &returnedSize);

    if (!NT_SUCCESS(status)) return status;
    if (returnedSize != sizeof(*RootInfo) ||
        RootInfo->Magic != HV_VTROOT_LEAF_INFO_MAGIC ||
        RootInfo->Version != HV_VTROOT_LEAF_INFO_VERSION ||
        RootInfo->Size != sizeof(*RootInfo) ||
        RootInfo->LeafIndex >= 512 ||
        !HvPhysIsRamRangeRootSafe(RootInfo->LeafTablePa, PAGE_SIZE)) {
        return STATUS_DATA_ERROR;
    }

    switch (RootInfo->LeafLevel) {
    case HV_VTROOT_LEAF_LEVEL_PT:
        if (RootInfo->PageSize != PAGE_SIZE) return STATUS_DATA_ERROR;
        // PTE bit 7 is PAT, not PS; it is valid in either state and remains
        // in LeafFlags because it is not part of the 4KB address field.
        addressMask = HV_PHYS_CR3_ADDRESS_MASK;
        offsetMask = PAGE_SIZE - 1;
        break;
    case HV_VTROOT_LEAF_LEVEL_PD:
        if (RootInfo->PageSize != 0x200000ULL ||
            !(RootInfo->OriginalEntry & HV_VTROOT_LEAF_BIT7) ||
            (RootInfo->OriginalEntry & HV_PHYS_2M_RESERVED_LOW_MASK)) {
            return STATUS_DATA_ERROR;
        }
        addressMask = HV_PHYS_2M_ADDRESS_MASK;
        offsetMask = 0x1FFFFFULL;
        break;
    case HV_VTROOT_LEAF_LEVEL_PDPT:
        if (RootInfo->PageSize != 0x40000000ULL ||
            !(RootInfo->OriginalEntry & HV_VTROOT_LEAF_BIT7) ||
            (RootInfo->OriginalEntry & HV_PHYS_1G_RESERVED_LOW_MASK)) {
            return STATUS_DATA_ERROR;
        }
        addressMask = HV_PHYS_1G_ADDRESS_MASK;
        offsetMask = 0x3FFFFFFFULL;
        break;
    default:
        return STATUS_DATA_ERROR;
    }

    if (RootInfo->LeafFlags !=
            (RootInfo->OriginalEntry & ~addressMask)) {
        return STATUS_DATA_ERROR;
    }

    if (!(RootInfo->OriginalEntry & 1ULL)) {
        // Only the PT level has a meaningful locatable non-present leaf slot.
        return (RootInfo->LeafLevel == HV_VTROOT_LEAF_LEVEL_PT &&
                RootInfo->LeafHpa == 0)
            ? STATUS_SUCCESS
            : STATUS_DATA_ERROR;
    }

    if (RootInfo->LeafHpa !=
            ((RootInfo->OriginalEntry & addressMask) | (Gva & offsetMask)) ||
        !HvPhysIsRamRangeRootSafe(
            RootInfo->LeafHpa & ~0xFFFULL, PAGE_SIZE)) {
        return STATUS_DATA_ERROR;
    }

    return STATUS_SUCCESS;
}

NTSTATUS
HvPhysGvaToHpa(
    _In_ UINT64 TargetCr3,
    _In_ UINT64 Gva,
    _Out_ PPHYSICAL_ADDRESS OutHpa,
    _Out_opt_ PSIZE_T OutPageSize,
    _Out_opt_ PUINT64 OutPteFlags
)
{
    HV_VTROOT_LEAF_PTE_INFO rootInfo;

    if (!OutHpa) return STATUS_INVALID_PARAMETER;
    OutHpa->QuadPart = 0;
    if (OutPageSize) *OutPageSize = 0;
    if (OutPteFlags) *OutPteFlags = 0;

    NTSTATUS status = HvPhysQueryLeafPteTrusted(
        TargetCr3, Gva, &rootInfo);
    if (!NT_SUCCESS(status)) return status;
    if (!(rootInfo.OriginalEntry & 1ULL)) return STATUS_NOT_FOUND;

    OutHpa->QuadPart = (LONGLONG)rootInfo.LeafHpa;
    if (OutPageSize) *OutPageSize = (SIZE_T)rootInfo.PageSize;
    if (OutPteFlags) *OutPteFlags = rootInfo.OriginalEntry;
    return status;
}

VOID
HvPhysSetWalkQuiet(
    _In_ BOOLEAN Quiet
)
{
    // Root walkers are already quiet for ordinary not-present entries. Keep
    // paired set/clear callers source-compatible for future diagnostics.
    InterlockedExchange(&g_PhysWalkQuiet, Quiet ? 1 : 0);
}

NTSTATUS
HvPhysFindUserCr3ByPid(
    _In_ ULONG TargetPid,
    _Out_ PUINT64 OutCr3
)
{
    return HvVtRootResolveUserCr3(TargetPid, OutCr3);
}

NTSTATUS
HvPhysFindUserCr3ForGvaByPid(
    _In_ ULONG TargetPid,
    _In_ UINT64 GvaHint,
    _Out_ PUINT64 OutCr3
)
{
    if (GvaHint < 0x10000ULL || GvaHint >= 0x800000000000ULL) {
        if (OutCr3) *OutCr3 = 0;
        return STATUS_INVALID_PARAMETER;
    }
    return HvVtRootResolveUserCr3(TargetPid, OutCr3);
}


// ============================================================
// Read / Write
// ============================================================

/*
 * 跨页 R/W 的核心循环 —— Phase D 重构为薄壳。
 *
 * The Windows side builds a lifetime-bound snapshot and locks target pages;
 * candidate validation, page-table walking and copying execute in VT root.
 *
 * There is no Windows page-table walker or MmMapIoSpace fallback.
 *
 * 若 g_VtRootEnabled = FALSE (未初始化或初始化失败), 直接返回 NOT_READY。
 * Direction: 0 = read (target→Buffer), 1 = write (Buffer→target)。
 */
static __forceinline VOID
HvPhysSetCopyDiag(
    _Out_opt_ PHV_PHYS_COPY_DIAG Diag,
    _In_ ULONG Stage,
    _In_ NTSTATUS DetailStatus,
    _In_ UINT64 TargetCr3)
{
    if (!Diag) return;
    Diag->Stage = Stage;
    Diag->DetailStatus = DetailStatus;
    Diag->TargetCr3 = TargetCr3;
}

static NTSTATUS
HvPhysCopyAcrossPages(
    _In_ ULONG TargetPid,
    _In_ UINT64 Gva,
    _Inout_updates_bytes_(Size) PVOID Buffer,
    _In_ SIZE_T Size,
    _In_ ULONG Direction,            // 0=read, 1=write
    _Out_opt_ PSIZE_T BytesDone,
    _Out_opt_ PHV_PHYS_COPY_DIAG Diag
)
{
    if (BytesDone) *BytesDone = 0;
    HvPhysSetCopyDiag(Diag, HV_PHYS_COPY_STAGE_VALIDATE, STATUS_SUCCESS, 0);
    if (!Buffer || Size == 0 || Size > MAXULONG) {
        HvPhysSetCopyDiag(Diag, HV_PHYS_COPY_STAGE_VALIDATE,
                          STATUS_INVALID_PARAMETER, 0);
        return STATUS_INVALID_PARAMETER;
    }
    if (KeGetCurrentIrql() > APC_LEVEL) {
        HvPhysSetCopyDiag(Diag, HV_PHYS_COPY_STAGE_VALIDATE,
                          STATUS_INVALID_LEVEL, 0);
        return STATUS_INVALID_LEVEL;
    }
    if (!g_VtRootEnabled) {
        HvPhysSetCopyDiag(Diag, HV_PHYS_COPY_STAGE_VALIDATE,
                          STATUS_DEVICE_NOT_READY, 0);
        return STATUS_DEVICE_NOT_READY;
    }

    // 2026-06-16: Buffer 是 kernel VA (内部 driver 调用,如 SSDT 解析) 直接传,
    // 不走 MDL (kernel VA 在 host CR3 下永远 resident, 不会 paged-out)。
    //
    // Buffer 是 user VA (NtReadVirtualMemory 转发的 user buffer) → 必须锁 + 取
    // system VA 别名, 否则 root mode 写 paged-out user 页 → BSOD 0xD1。
    //
    // 判定: canonical low half (< 0x0000800000000000) 为 user VA。
    ULONG_PTR bufAddr = (ULONG_PTR)Buffer;
    BOOLEAN isUserBuffer = (bufAddr < 0x0000800000000000ULL);

    PVOID systemVa = Buffer;
    PMDL bufferMdl = NULL;
    if (isUserBuffer) {
        HvPhysSetCopyDiag(Diag, HV_PHYS_COPY_STAGE_BUFFER_LOCK,
                          STATUS_SUCCESS, 0);
        // User buffer: 锁定 + system VA 别名
        bufferMdl = IoAllocateMdl(Buffer, (ULONG)Size, FALSE, FALSE, NULL);
        if (!bufferMdl) {
            HvPhysSetCopyDiag(Diag, HV_PHYS_COPY_STAGE_BUFFER_LOCK,
                              STATUS_INSUFFICIENT_RESOURCES, 0);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        // Direction=0(读) 时 Buffer 被写入 → IoWriteAccess
        // Direction=1(写) 时 Buffer 被读取 → IoReadAccess
        LOCK_OPERATION lockOp = (Direction == 0) ? IoWriteAccess : IoReadAccess;
        NTSTATUS lockSt = STATUS_SUCCESS;
        __try {
            MmProbeAndLockPages(bufferMdl, UserMode, lockOp);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            lockSt = GetExceptionCode();
            if (NT_SUCCESS(lockSt)) lockSt = STATUS_ACCESS_VIOLATION;
        }
        if (!NT_SUCCESS(lockSt)) {
            IoFreeMdl(bufferMdl);
            HvPhysSetCopyDiag(Diag, HV_PHYS_COPY_STAGE_BUFFER_LOCK,
                              lockSt, 0);
            return lockSt;
        }

        systemVa = MmGetSystemAddressForMdlSafe(
            bufferMdl, NormalPagePriority);
        if (!systemVa) {
            MmUnlockPages(bufferMdl);
            IoFreeMdl(bufferMdl);
            HvPhysSetCopyDiag(Diag, HV_PHYS_COPY_STAGE_BUFFER_LOCK,
                              STATUS_INSUFFICIENT_RESOURCES, 0);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
    }

    HvPhysSetCopyDiag(Diag, HV_PHYS_COPY_STAGE_VT_ROOT_COPY,
                      STATUS_SUCCESS, 0);
    NTSTATUS st = HvVtRootCopyByPid(
        TargetPid, Gva, systemVa, Size,
        (BOOLEAN)(Direction != 0), BytesDone);
    if (!NT_SUCCESS(st)) {
        HvPhysSetCopyDiag(Diag, HV_PHYS_COPY_STAGE_VT_ROOT_COPY, st, 0);
    }

    if (bufferMdl) {
        MmUnlockPages(bufferMdl);
        IoFreeMdl(bufferMdl);
    }
    if (NT_SUCCESS(st) &&
        (!Diag || Diag->Stage != HV_PHYS_COPY_STAGE_MDL_FALLBACK)) {
        HvPhysSetCopyDiag(Diag, HV_PHYS_COPY_STAGE_COMPLETE,
                          st, Diag ? Diag->TargetCr3 : 0);
    }
    return st;
}

NTSTATUS
HvPhysReadProcessMemory(
    _In_ ULONG TargetPid,
    _In_ UINT64 Gva,
    _Out_writes_bytes_(Size) PVOID Buffer,
    _In_ SIZE_T Size,
    _Out_opt_ PSIZE_T BytesRead
)
{
    return HvPhysCopyAcrossPages(
        TargetPid, Gva, Buffer, Size, 0, BytesRead, NULL);
}

NTSTATUS
HvPhysReadProcessMemoryDiagnosed(
    _In_ ULONG TargetPid,
    _In_ UINT64 Gva,
    _Out_writes_bytes_(Size) PVOID Buffer,
    _In_ SIZE_T Size,
    _Out_opt_ PSIZE_T BytesRead,
    _Out_ PHV_PHYS_COPY_DIAG Diag
)
{
    if (!Diag) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(Diag, sizeof(*Diag));
    return HvPhysCopyAcrossPages(
        TargetPid, Gva, Buffer, Size, 0, BytesRead, Diag);
}

NTSTATUS
HvPhysWriteProcessMemory(
    _In_ ULONG TargetPid,
    _In_ UINT64 Gva,
    _In_reads_bytes_(Size) PVOID Buffer,
    _In_ SIZE_T Size,
    _Out_opt_ PSIZE_T BytesWritten
)
{
    return HvPhysCopyAcrossPages(
        TargetPid, Gva, Buffer, Size, 1, BytesWritten, NULL);
}

// ============================================================
// 生命周期
// ============================================================

// ============================================================
// Staged page-table management compatibility entry points
// ============================================================
//
// The historical allocator directly inserted pool PFNs into a target page
// table. It did not create a VAD or maintain PFN, commit, working-set and
// process-exit accounting, so a successful call left Windows with a mapping
// it did not own. Preserve the subsystem interface, but fail closed until a
// root request ABI and a complete lifetime/rollback owner are implemented.

ULONG
HvPhysQueryStagedCapabilities(VOID)
{
    return HV_PHYS_STAGED_RAW_PTE_PROCESS_ALLOC;
}

NTSTATUS
HvPhysAllocateInProcess(
    _In_ ULONG TargetPid,
    _In_ SIZE_T Size,
    _In_ ULONG Protection,
    _Inout_ PUINT64 InOutGva
)
{
    UNREFERENCED_PARAMETER(Protection);

    if (TargetPid == 0 || Size == 0 || !InOutGva) {
        return STATUS_INVALID_PARAMETER;
    }
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_LEVEL;
    }
    // This is a compile-time staged capability, not a transient runtime
    // outage. Return NOT_SUPPORTED so callers do not retry it as NOT_READY.
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS
HvPhysFreeInProcess(
    _In_ ULONG TargetPid,
    _In_ UINT64 Gva,
    _In_ SIZE_T Size
)
{
    if (TargetPid == 0 || Gva < 0x10000ULL ||
        Gva >= 0x800000000000ULL || Size == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_LEVEL;
    }
    // This is a compile-time staged capability, not a transient runtime
    // outage. Return NOT_SUPPORTED so callers do not retry it as NOT_READY.
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS
HvPhysFindLeafPteLocationEx(
    _In_ UINT64 TargetCr3,
    _In_ UINT64 TargetVa,
    _Out_ PHV_PHYS_LEAF_PTE_INFO OutInfo
)
{
    HV_VTROOT_LEAF_PTE_INFO rootInfo;

    if (!OutInfo) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(OutInfo, sizeof(*OutInfo));

    NTSTATUS status = HvPhysQueryLeafPteTrusted(
        TargetCr3, TargetVa, &rootInfo);
    if (!NT_SUCCESS(status)) return status;

    OutInfo->LeafTablePa = rootInfo.LeafTablePa;
    OutInfo->LeafIndex = rootInfo.LeafIndex;
    OutInfo->LeafLevel = rootInfo.LeafLevel;
    OutInfo->OriginalPte = rootInfo.OriginalEntry;
    OutInfo->LeafHpa = rootInfo.LeafHpa;
    OutInfo->PageSize = (SIZE_T)rootInfo.PageSize;
    OutInfo->LeafFlags = rootInfo.LeafFlags;
    return STATUS_SUCCESS;
}

NTSTATUS
HvPhysFindLeafPteLocation(
    _In_ UINT64 TargetCr3,
    _In_ UINT64 TargetVa,
    _Out_ PUINT64 OutPtPagePa,
    _Out_ PULONG OutPteIndex,
    _Out_opt_ PUINT64 OutOrigPte
)
{
    HV_PHYS_LEAF_PTE_INFO info;

    if (!OutPtPagePa || !OutPteIndex) {
        return STATUS_INVALID_PARAMETER;
    }
    *OutPtPagePa = 0;
    *OutPteIndex = 0;
    if (OutOrigPte) *OutOrigPte = 0;

    NTSTATUS status = HvPhysFindLeafPteLocationEx(
        TargetCr3, TargetVa, &info);
    if (!NT_SUCCESS(status)) return status;

    // Keep the legacy mutation surface strictly 4KB-only. Leave all outputs
    // zero for a large leaf so a caller that mishandles NOT_SUPPORTED cannot
    // accidentally edit a PDE/PDPTE.
    if (info.PageSize != PAGE_SIZE) {
        return STATUS_NOT_SUPPORTED;
    }

    *OutPtPagePa = info.LeafTablePa;
    *OutPteIndex = info.LeafIndex;
    if (OutOrigPte) *OutOrigPte = info.OriginalPte;
    return STATUS_SUCCESS;
}

/*
 * Capture only the EPROCESS offsets needed to build a referenced process
 * snapshot. No PID lookup or page-table dereference occurs in root mode.
 */
static VOID
HvPhysInitRootCtx(VOID)
{
    static const UINT64 kKnownUserDtbOffsets[] = {
        0x158, 0x388, 0x3A0, 0x3C0, 0x3F0, 0x440, 0x550, 0x580
    };

    if (g_HvPhysRootCtx.Initialized) return;

    HvPhysProbeDtbOffset();
    RtlZeroMemory(&g_HvPhysRootCtx, sizeof(g_HvPhysRootCtx));
    g_HvPhysRootCtx.DtbOff = g_DtbOffset;
    for (ULONG index = 0;
         index < RTL_NUMBER_OF(kKnownUserDtbOffsets) &&
             index < HV_PHYS_KNOWN_USER_DTB_OFFSETS_MAX;
         ++index) {
        g_HvPhysRootCtx.KnownUserDtbOffs[index] =
            kKnownUserDtbOffsets[index];
        g_HvPhysRootCtx.KnownUserDtbOffCount++;
    }

    KeMemoryBarrier();
    g_HvPhysRootCtx.Initialized = TRUE;
    HV_HOT_DBG("[HvPhys] RootCtx: candidate offsets ready "
               "(Dtb=0x%X KnownOffs=%u)\n",
               g_HvPhysRootCtx.DtbOff,
               g_HvPhysRootCtx.KnownUserDtbOffCount);
}
NTSTATUS
HvPhysAccessInitialize(VOID)
{
    if (g_PhysAccessInitialized) return STATUS_SUCCESS;
    HvPhysInitRamRangesIfNeeded();
    HvPhysProbeDtbOffset();

    // Publish the candidate-offset snapshot used by VT process requests.
    HvPhysInitRootCtx();

    g_PhysAccessInitialized = TRUE;
    return STATUS_SUCCESS;
}

// ============================================================
// 模块枚举 (无痕)
// ============================================================
//
// PEB → Ldr → InLoadOrderModuleList → LDR_DATA_TABLE_ENTRY 链表遍历,
// 数据读取全部走 HvVtRootCopyByPid (VMCALL → root mode), 无 Mm*/Ps*/Ob*。
//
// x64 用户态结构偏移 (winternl.h / ntdll!_PEB / ntdll!_LDR_DATA_TABLE_ENTRY,
// Win10/11 全系稳定):
//   PEB:
//     +0x18  Ldr (PEB_LDR_DATA*)
//   PEB_LDR_DATA:
//     +0x10  InLoadOrderModuleList (LIST_ENTRY) {Flink, Blink}
//   LDR_DATA_TABLE_ENTRY:
//     +0x00  InLoadOrderLinks (LIST_ENTRY) —— 这就是 list 节点本体
//     +0x30  DllBase (PVOID)
//     +0x40  SizeOfImage (ULONG)
//     +0x48  FullDllName (UNICODE_STRING)
//     +0x58  BaseDllName (UNICODE_STRING) { USHORT Length; USHORT Max; ULONG _pad; PVOID Buffer; }
//
// 这些偏移对 Win10/11 x64 是 ABI 级稳定的 (公开 PEB 结构), 不需要探测。

#define HV_LDR_OFF_PEB_LDR              0x18
#define HV_LDR_OFF_LDR_INLOAD_LIST      0x10
#define HV_LDR_OFF_ENTRY_DLLBASE        0x30
#define HV_LDR_OFF_ENTRY_SIZEOFIMAGE    0x40
#define HV_LDR_OFF_ENTRY_BASEDLLNAME    0x58

// LDR_DATA_TABLE_ENTRY 我们关心字段的子集 (按文件偏移布局, 一次读完)
#pragma pack(push, 1)
typedef struct _HV_LDR_ENTRY_VIEW {
    UINT64 InLoadFlink;       // +0x00
    UINT64 InLoadBlink;       // +0x08
    UINT64 _InMemFlink;       // +0x10
    UINT64 _InMemBlink;       // +0x18
    UINT64 _InInitFlink;      // +0x20
    UINT64 _InInitBlink;      // +0x28
    UINT64 DllBase;           // +0x30
    UINT64 EntryPoint;        // +0x38
    ULONG  SizeOfImage;       // +0x40
    ULONG  _pad44;            // +0x44 (padding for UNICODE_STRING align)
    USHORT FullName_Len;      // +0x48
    USHORT FullName_Max;      // +0x4A
    ULONG  _pad4C;            // +0x4C (UNICODE_STRING padding to 8-byte)
    UINT64 FullName_Buf;      // +0x50
    USHORT BaseName_Len;      // +0x58
    USHORT BaseName_Max;      // +0x5A
    ULONG  _pad5C;            // +0x5C
    UINT64 BaseName_Buf;      // +0x60
} HV_LDR_ENTRY_VIEW;
#pragma pack(pop)

C_ASSERT(FIELD_OFFSET(HV_LDR_ENTRY_VIEW, DllBase)        == 0x30);
C_ASSERT(FIELD_OFFSET(HV_LDR_ENTRY_VIEW, SizeOfImage)    == 0x40);
C_ASSERT(FIELD_OFFSET(HV_LDR_ENTRY_VIEW, BaseName_Len)   == 0x58);
C_ASSERT(FIELD_OFFSET(HV_LDR_ENTRY_VIEW, BaseName_Buf)   == 0x60);

NTSTATUS
HvPhysEnumerateModules(
    _In_ ULONG TargetPid,
    _Out_writes_to_(MaxCount, *OutCount) PHV_MODULE_INFO OutModules,
    _In_ ULONG MaxCount,
    _Out_ PULONG OutCount)
{
    if (!OutModules || !OutCount || MaxCount == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    *OutCount = 0;
    if (KeGetCurrentIrql() > APC_LEVEL) return STATUS_INVALID_LEVEL;
    if (!g_VtRootEnabled) return STATUS_DEVICE_NOT_READY;

    // 1) 取 PEB user VA (一次 VMCALL)
    UINT64 pebVa = 0;
    NTSTATUS s = HvVtRootGetPebByPid(TargetPid, &pebVa);
    if (!NT_SUCCESS(s)) return s;
    if (pebVa == 0) {
        // 进程是 kernel-only (System/Registry 等), 没有用户模块
        return STATUS_SUCCESS;  // OutCount = 0
    }

    // 2) 读 PEB.Ldr (PEB_LDR_DATA*)
    UINT64 ldrVa = 0;
    SIZE_T done = 0;
    s = HvPhysReadProcessMemory(
        TargetPid, pebVa + HV_LDR_OFF_PEB_LDR,
        &ldrVa, sizeof(UINT64), &done);
    if (!NT_SUCCESS(s) || done != sizeof(UINT64) || ldrVa == 0) {
        DbgPrint("[HvPhys] EnumModules: PID=%u read PEB.Ldr failed (s=0x%X, done=%llu, ldr=0x%llX)\n",
                 TargetPid, s, (ULONGLONG)done, ldrVa);
        return NT_SUCCESS(s) ? STATUS_NOT_FOUND : s;
    }

    // 3) 读 InLoadOrderModuleList head (LIST_ENTRY = 16 bytes)
    UINT64 listHeadVa = ldrVa + HV_LDR_OFF_LDR_INLOAD_LIST;
    UINT64 head[2] = { 0, 0 };
    s = HvPhysReadProcessMemory(
        TargetPid, listHeadVa, &head, sizeof(head), &done);
    if (!NT_SUCCESS(s) || done != sizeof(head) || head[0] == 0) {
        DbgPrint("[HvPhys] EnumModules: PID=%u read InLoadList head failed (s=0x%X)\n",
                 TargetPid, s);
        return NT_SUCCESS(s) ? STATUS_NOT_FOUND : s;
    }

    // 4) 沿 Flink 遍历, 每个节点就是 LDR_DATA_TABLE_ENTRY.InLoadOrderLinks
    UINT64 cur = head[0];
    ULONG written = 0;

    for (ULONG i = 0; i < HV_MAX_MODULES_PER_PROCESS && written < MaxCount; i++) {
        if (cur == 0 || cur == listHeadVa) break;     // 链表头, 完成

        HV_LDR_ENTRY_VIEW view = { 0 };
        s = HvPhysReadProcessMemory(
            TargetPid, cur, &view, sizeof(view), &done);
        if (!NT_SUCCESS(s) || done != sizeof(view)) {
            DbgPrint("[HvPhys] EnumModules: PID=%u entry @0x%llX read failed (s=0x%X)\n",
                     TargetPid, cur, s);
            break;
        }

        // ntdll 文档行为: list 尾部存在 DllBase=0 哨兵, 跳过但继续遍历
        if (view.DllBase == 0) {
            cur = view.InLoadFlink;
            continue;
        }

        PHV_MODULE_INFO out = &OutModules[written];
        out->DllBase     = view.DllBase;
        out->SizeOfImage = view.SizeOfImage;
        out->Reserved    = 0;
        RtlZeroMemory(out->Name, sizeof(out->Name));

        // 5) 读 BaseDllName.Buffer (WCHAR[]), 限制到 Name 缓冲减一槽留 NUL
        if (view.BaseName_Buf != 0 && view.BaseName_Len > 0) {
            USHORT lenBytes = view.BaseName_Len;
            const USHORT maxBytes = (USHORT)((HV_MODULE_NAME_MAX - 1) * sizeof(WCHAR));
            if (lenBytes > maxBytes) lenBytes = maxBytes;

            SIZE_T nameDone = 0;
            NTSTATUS ns = HvPhysReadProcessMemory(
                TargetPid, view.BaseName_Buf,
                out->Name, lenBytes, &nameDone);
            if (!NT_SUCCESS(ns) || nameDone == 0) {
                // 名字读不到不致命, 留空名继续
                out->Name[0] = L'\0';
            } else {
                // 确保 null 终结 (HV_MODULE_NAME_MAX-1 处 zero 已由 RtlZeroMemory 保证)
                USHORT charCount = (USHORT)(nameDone / sizeof(WCHAR));
                if (charCount < HV_MODULE_NAME_MAX) {
                    out->Name[charCount] = L'\0';
                }
            }
        }

        written++;
        cur = view.InLoadFlink;
    }

    *OutCount = written;
    return STATUS_SUCCESS;
}

VOID
HvPhysAccessCleanup(VOID)
{
    g_PhysAccessInitialized = FALSE;
}
