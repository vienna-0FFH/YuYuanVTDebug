/*
 * HvVtRoot.c (阶段 8.5 V2: 独立 PT 岛)
 *
 * 真·VT 无痕物理 R/W —— V2 设计。
 *
 * ============================================================
 * 历史与动机
 * ============================================================
 *
 * V1 (阶段 6, "PTE 劫持"): 通过 MmAllocateContiguousMemory 拿到一个
 * scratch 内核 VA,然后在 root 模式改它的叶 PTE 让其指向任意 HPA。
 *
 * V1 bug (BSOD 0x1DB CHKIMG, 2026-05-21):
 *   MM zero-page worker / WS trimmer 周期遍历 PFN 数据库;ScratchData 那
 *   一页 PFN 仍然挂在我们的分配上,但其反向 PTE 已经指向 nt 代码页 ——
 *   worker 通过 PFN→PTE→VA 反查写 zero,**直接 zero 了 nt 代码字节**。
 *   后续 IPI 调用 HalpGetPteAddress / MiGetSinglePageToZero 时执行到被
 *   损坏的代码,5 秒不响应触发 0x1DB。
 *
 * V2 修复:
 *   完全不动 MM 跟踪的 PTE。在 kernel CR3 的一个**未使用** PML4 槽位插入
 *   完全私有的 PML4→PDPT→PD→PT 链。
 *
 *   - 该 PT 链上的 VA 没有 VAD / 系统 PTE / PFN 反向映射条目 → MM 看不见
 *   - PDPT/PD/PT/backing 是普通 NonPagedPool 页,MM 只跟"这是一个 pool
 *     allocation",不递归看内容 → 我们任意改 PT 内容,MM 不会扫到
 *   - 任意时刻 PT[cpu_idx].PFN 要么是 backing 页(空闲态),要么是目标
 *     HPA(拷贝瞬间)。运行时不再操作任何 MM 跟踪的 PTE。
 *
 * ============================================================
 * Root-mode 操作
 * ============================================================
 *
 *   1) InterlockedExchange64(ScratchPtePtr, target_pa | flags)
 *   2) __invlpg(ScratchVa)   —— 只刷自己核,其他核 ScratchVa 不同,互不干扰
 *   3) RtlCopyMemory ← / → ScratchVa
 *   4) 拷贝完成,InterlockedExchange64 回 backing 防御性归位
 *
 * ============================================================
 * 数据结构
 * ============================================================
 *
 * 全局(共享):
 *   g_VrSharedPml4Index   —— PML4 中我们占用的槽位号 (256..511)
 *   g_VrSharedPdptVa / Pa —— 私有 PDPT (一页)
 *   g_VrSharedPdVa   / Pa —— 私有 PD   (一页)
 *   g_VrSharedPtVa   / Pa —— 私有 PT   (一页, 至多 512 个 CPU entry)
 *   g_VrBackingVa    / Pa —— 静态 backing(空闲态 PT entry 指向这里)
 *   g_VrBaseVa            —— 该 PML4 槽起始 canonical VA
 *
 * Per-CPU (VCPU_DATA.VtRootGadget):
 *   ScratchVa             —— g_VrBaseVa + (cpu_idx << 12)
 *   ScratchPtePtr         —— &g_VrSharedPtVa[cpu_idx]
 *   BackingPagePa         —— g_VrBackingPa
 *
 * ============================================================
 * IRQL / 上下文
 * ============================================================
 *
 *   HvVtRootInitializeAll  —— PASSIVE_LEVEL (DriverEntry)
 *   HvVtRootCleanupAll     —— PASSIVE_LEVEL (DriverUnload)
 *   HvVtRootRootCopyOnePage—— root mode (interrupts disabled, 单核)
 *   HvVtRootCopy           —— PASSIVE_LEVEL (IOCTL)
 */

#include "HvVtRoot.h"
#include "HvPhysAccess.h"
#include "HvCr3Snoop.h"
#include "HvTypes.h"
#include "HvCpu.h"
#include "HvCore.h"
#include "HvBroadcast.h"
#include "HvCompat.h"
#include "HvUtils.h"
#include <intrin.h>

// P122: 全 driver DbgPrint → GUI ring
#define HV_TRACE_THIS_CAT HV_TRACE_CAT_VTROOT
#include "HvTrace.h"

// AsmVmCallPhysCopy / AsmVmmCallPhysCopy 在 AsmVmx.asm / AsmSvm.asm 实现
extern NTSTATUS AsmVmCallPhysCopy(
    UINT64 TargetCr3,
    UINT64 TargetGva,
    PVOID  KernelBuf,
    SIZE_T Size,
    ULONG  Direction,
    PSIZE_T OutBytesDone
);

extern NTSTATUS AsmVmmCallPhysCopy(
    UINT64 TargetCr3,
    UINT64 TargetGva,
    PVOID  KernelBuf,
    SIZE_T Size,
    ULONG  Direction,
    PSIZE_T OutBytesDone
);

NTKERNELAPI NTSTATUS PsLookupProcessByProcessId(
    _In_ HANDLE ProcessId,
    _Out_ PEPROCESS* Process);

NTKERNELAPI PVOID PsGetProcessPeb(_In_ PEPROCESS Process);
NTKERNELAPI PVOID PsGetProcessSectionBaseAddress(_In_ PEPROCESS Process);
NTKERNELAPI VOID MmProbeAndLockProcessPages(
    _Inout_ PMDL MemoryDescriptorList,
    _In_ PEPROCESS Process,
    _In_ KPROCESSOR_MODE AccessMode,
    _In_ LOCK_OPERATION Operation);

// ============================================================
// PTE 位域
// ============================================================

#define VR_PTE_PRESENT      (1ULL << 0)
#define VR_PTE_RW           (1ULL << 1)
#define VR_PTE_USER         (1ULL << 2)
#define VR_PTE_PS           (1ULL << 7)
#define VR_PTE_GLOBAL       (1ULL << 8)
#define VR_PTE_NX           (1ULL << 63)
#define VR_PTE_PFN_MASK     0x000FFFFFFFFFF000ULL
#define VR_PDE_2M_PFN_MASK  0x000FFFFFFFE00000ULL
#define VR_PDPTE_1G_PFN_MASK 0x000FFFFFC0000000ULL

// With PS=1, bit 12 is PAT rather than an address bit. Bits 13..20 (2MB)
// and 13..29 (1GB) are reserved and must be zero; silently folding them into
// LeafFlags would make the software walker accept an entry hardware rejects.
#define VR_PDE_2M_RESERVED_LOW_MASK   0x00000000001FE000ULL
#define VR_PDPTE_1G_RESERVED_LOW_MASK 0x000000003FFFE000ULL

#define VR_PML4_INDEX(va)   (((UINT64)(va) >> 39) & 0x1FF)
#define VR_PDPT_INDEX(va)   (((UINT64)(va) >> 30) & 0x1FF)
#define VR_PD_INDEX(va)     (((UINT64)(va) >> 21) & 0x1FF)
#define VR_PT_INDEX(va)     (((UINT64)(va) >> 12) & 0x1FF)

#define VR_TAG              'rVvH'
#define VR_COPY_TAG         'cVvH'
#define VR_REQUEST_TAG      'qVvH'

// 私有 PT entry 标志: P|RW|NX|Global (内核数据,绝不可执行)
#define VR_LEAF_FLAGS       (VR_PTE_PRESENT | VR_PTE_RW | VR_PTE_NX | VR_PTE_GLOBAL)
// 中间表 entry 标志: P|RW|NX
#define VR_INTR_FLAGS       (VR_PTE_PRESENT | VR_PTE_RW | VR_PTE_NX)

// ============================================================
// 全局
// ============================================================

volatile BOOLEAN g_VtRootEnabled = FALSE;

typedef enum _VR_PUBLICATION_STATE {
    VrPublicationOffline = 0,
    VrPublicationInitializing,
    VrPublicationOnline,
    VrPublicationFailed,
    VrPublicationQuiescing,
    VrPublicationRetained
} VR_PUBLICATION_STATE;

static volatile LONG g_VrPublicationState = VrPublicationOffline;
static EX_RUNDOWN_REF g_VrInvocationRundown;
static BOOLEAN g_VrInvocationRundownInitialized = FALSE;
static KEVENT g_VrCleanupCompleteEvent;
static BOOLEAN g_VrCleanupEventInitialized = FALSE;

static ULONG  g_VrSharedPml4Index = 0;
static UINT64 g_VrBaseVa          = 0;

static PVOID  g_VrSharedPdptVa = NULL;
static UINT64 g_VrSharedPdptPa = 0;
static PVOID  g_VrSharedPdVa   = NULL;
static UINT64 g_VrSharedPdPa   = 0;
static PVOID  g_VrSharedPtVa   = NULL;
static UINT64 g_VrSharedPtPa   = 0;
static PVOID  g_VrBackingVa    = NULL;
static UINT64 g_VrBackingPa    = 0;
static UINT64 g_VrHostCr3      = 0;
static UINT64 g_VrPml4Entry    = 0;

// ============================================================
// Lifecycle-bound PID → resolved user CR3 cache
// ============================================================
//
// Entries are keyed by PID plus PsGetProcessCreateTimeQuadPart. A reused PID
// cannot inherit a stale CR3. Access is serialized because the three identity
// fields must be observed as one snapshot.

#define VR_CR3_CACHE_SLOTS          256
#define VR_CR3_CACHE_MASK           (VR_CR3_CACHE_SLOTS - 1)
#define VR_PROCESS_REQUEST_MAGIC    0x5152545652545648ULL
#define VR_PROCESS_REQUEST_VERSION  1
#define VR_PROCESS_MAX_CANDIDATES   24

typedef struct _VR_CR3_CACHE_ENTRY {
    ULONG Pid;
    ULONG Reserved;
    UINT64 CreateTime;
    UINT64 Cr3;
} VR_CR3_CACHE_ENTRY;

typedef struct _VR_PROCESS_REQUEST {
    UINT64 Magic;
    ULONG Size;
    ULONG Version;
    ULONG TargetPid;
    ULONG CandidateCount;
    UINT64 CreateTime;
    UINT64 PebGva;
    UINT64 ImageBase;
    UINT64 TargetGva;
    PUCHAR Bounce;
    SIZE_T TransferSize;
    UINT64 ResolvedCr3;
    UINT64 ResultPageSize;
    UINT64 Candidates[VR_PROCESS_MAX_CANDIDATES];
} VR_PROCESS_REQUEST, *PVR_PROCESS_REQUEST;

typedef struct _VR_LOCKED_ANCHORS {
    PMDL PebMdl;
    PMDL ImageMdl;
    BOOLEAN PebLocked;
    BOOLEAN ImageLocked;
} VR_LOCKED_ANCHORS, *PVR_LOCKED_ANCHORS;

static VR_CR3_CACHE_ENTRY g_VrPidCr3Cache[VR_CR3_CACHE_SLOTS] = { 0 };
static KSPIN_LOCK g_VrPidCr3CacheLock;
static BOOLEAN g_VrPidCr3CacheInitialized = FALSE;

static BOOLEAN
VrCacheLookup(
    _In_ ULONG Pid,
    _In_ UINT64 CreateTime,
    _Out_ PUINT64 OutCr3)
{
    KIRQL oldIrql;
    VR_CR3_CACHE_ENTRY entry;

    *OutCr3 = 0;
    if (!g_VrPidCr3CacheInitialized || Pid == 0 || CreateTime == 0) {
        return FALSE;
    }

    KeAcquireSpinLock(&g_VrPidCr3CacheLock, &oldIrql);
    if (g_VrPidCr3CacheInitialized) {
        entry = g_VrPidCr3Cache[Pid & VR_CR3_CACHE_MASK];
    } else {
        RtlZeroMemory(&entry, sizeof(entry));
    }
    KeReleaseSpinLock(&g_VrPidCr3CacheLock, oldIrql);

    if (entry.Pid != Pid || entry.CreateTime != CreateTime || entry.Cr3 == 0) {
        return FALSE;
    }
    *OutCr3 = entry.Cr3 & VR_PTE_PFN_MASK;
    return TRUE;
}

static VOID
VrCacheStore(
    _In_ ULONG Pid,
    _In_ UINT64 CreateTime,
    _In_ UINT64 Cr3)
{
    KIRQL oldIrql;
    ULONG slot;

    Cr3 &= VR_PTE_PFN_MASK;
    if (!g_VrPidCr3CacheInitialized || Pid == 0 ||
        CreateTime == 0 || Cr3 == 0) {
        return;
    }

    slot = Pid & VR_CR3_CACHE_MASK;
    KeAcquireSpinLock(&g_VrPidCr3CacheLock, &oldIrql);
    if (g_VrPidCr3CacheInitialized) {
        g_VrPidCr3Cache[slot].Pid = Pid;
        g_VrPidCr3Cache[slot].Reserved = 0;
        g_VrPidCr3Cache[slot].CreateTime = CreateTime;
        g_VrPidCr3Cache[slot].Cr3 = Cr3;
    }
    KeReleaseSpinLock(&g_VrPidCr3CacheLock, oldIrql);
}

// ============================================================
// helpers
// ============================================================

/*
 * 把 PML4 槽号 (0..511) 转换为该槽对应的最低 canonical VA。
 * 槽 256..511 是 kernel half (bit 47 = 1, 高 16 位符号扩展为 1)。
 */
static __forceinline UINT64 VrSlotToBaseVa(_In_ ULONG Slot)
{
    UINT64 va = ((UINT64)Slot) << 39;
    if (va & (1ULL << 47)) {
        va |= 0xFFFF000000000000ULL;
    } else {
        va &= 0x0000FFFFFFFFFFFFULL;
    }
    return va;
}

/*
 * 分配一个 NonPaged 4KB 页 (ExAllocatePool2 对 PAGE_SIZE 请求返回页对齐),
 * 同时拿到它的 HPA。
 */
static NTSTATUS VrAllocateAndGetPa(_Out_ PVOID* OutVa, _Out_ PUINT64 OutPa)
{
    PVOID va = HvAllocateNonPagedZeroed(PAGE_SIZE, VR_TAG);
    if (!va) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    PHYSICAL_ADDRESS pa = MmGetPhysicalAddress(va);
    if (pa.QuadPart == 0) {
        ExFreePoolWithTag(va, VR_TAG);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    *OutVa = va;
    *OutPa = (UINT64)pa.QuadPart;
    return STATUS_SUCCESS;
}

static VOID VrFreeIfAllocated(_Inout_ PVOID* OutVa)
{
    if (*OutVa) {
        ExFreePoolWithTag(*OutVa, VR_TAG);
        *OutVa = NULL;
    }
}

/*
 * 扫 PML4 高半空间 (256..511, kernel half) 找首个 Present=0 槽位。
 * Pml4Va 必须是 PASSIVE 端 MmMapIoSpace 出来的 mapping。
 */
static NTSTATUS VrFindFreePml4Slot(
    _In_ volatile UINT64* Pml4Va,
    _Out_ PULONG OutIndex)
{
    for (ULONG i = 256; i < 512; i++) {
        if (!(Pml4Va[i] & VR_PTE_PRESENT)) {
            *OutIndex = i;
            return STATUS_SUCCESS;
        }
    }
    return STATUS_NOT_FOUND;
}

static volatile UINT64* VrMapHostPml4(
    _In_ UINT64 HostCr3,
    _Out_ PBOOLEAN NeedsUnmap)
{
    PHYSICAL_ADDRESS pml4Pa;

    *NeedsUnmap = FALSE;
    pml4Pa.QuadPart = (LONGLONG)(HostCr3 & VR_PTE_PFN_MASK);
    if (pml4Pa.QuadPart == 0) return NULL;
    return (volatile UINT64*)MmGetVirtualForPhysical(pml4Pa);
}

static VOID VrUnmapHostPml4(
    _In_opt_ volatile UINT64* Pml4Va,
    _In_ BOOLEAN NeedsUnmap)
{
    if (Pml4Va && NeedsUnmap) {
        MmUnmapIoSpace((PVOID)Pml4Va, PAGE_SIZE);
    }
}

/*
 * IPI:让每个 CPU 在本核 invlpg 自己的 ScratchVa。用于
 *   - 初始安装后(防御性,清掉历史 stale TLB)
 *   - 清理时(零 PML4 entry 后必须刷各核 TLB,否则 stale entry 仍指向已释放
 *     的 pool page,任意核访问 ScratchVa 都会写错地址)
 */
static ULONG_PTR VrInvlpgSelfIpi(_In_ ULONG_PTR Ctx)
{
    UNREFERENCED_PARAMETER(Ctx);
    ULONG cpuIdx = KeGetCurrentProcessorNumber();
    if (g_HypervisorContext.VcpuData &&
        cpuIdx < g_HypervisorContext.ProcessorCount) {
        PVOID va = g_HypervisorContext.VcpuData[cpuIdx].VtRootGadget.ScratchVa;
        if (va) {
            __invlpg(va);
        }
    }
    return 0;
}

// ============================================================
// HvVtRootInitializeAll: 一次性建立 PT 岛 + 每 CPU 分片
// ============================================================

// 调试器物理直通编译开关。运行时仍以 g_VtRootEnabled 为准；只有 PT 岛
// 完整初始化成功后才允许 VMCALL 读写。
#ifndef HV_ENABLE_VT_ROOT
#define HV_ENABLE_VT_ROOT 1
#endif

NTSTATUS HvVtRootInitializeAll(VOID)
{
#if !HV_ENABLE_VT_ROOT
    DbgPrint("[VtRoot V2] HV_ENABLE_VT_ROOT=0, init skipped\n");
    return STATUS_SUCCESS;
#endif

    ULONG total = g_HypervisorContext.ProcessorCount;
    if (!g_HypervisorContext.VcpuData || total == 0) {
        DbgPrint("[VtRoot V2] no VCPU data, skip\n");
        return STATUS_DEVICE_NOT_READY;
    }
    if (total > 512) {
        DbgPrint("[VtRoot V2] CPU count %u > 512 PT entries, abort\n", total);
        return STATUS_NOT_SUPPORTED;
    }
    if (KeGetCurrentIrql() > APC_LEVEL) {
        return STATUS_INVALID_LEVEL;
    }

    if (InterlockedCompareExchange(
            &g_VrPublicationState,
            VrPublicationInitializing,
            VrPublicationOffline) != VrPublicationOffline) {
        return STATUS_DEVICE_BUSY;
    }
    if (!g_VrInvocationRundownInitialized) {
        ExInitializeRundownProtection(&g_VrInvocationRundown);
        g_VrInvocationRundownInitialized = TRUE;
    } else {
        ExReInitializeRundownProtection(&g_VrInvocationRundown);
    }
    if (!g_VrCleanupEventInitialized) {
        KeInitializeEvent(
            &g_VrCleanupCompleteEvent, NotificationEvent, FALSE);
        g_VrCleanupEventInitialized = TRUE;
    } else {
        KeClearEvent(&g_VrCleanupCompleteEvent);
    }

    g_VtRootEnabled = FALSE;
    g_VrHostCr3 = 0;
    g_VrPml4Entry = 0;
    RtlZeroMemory(g_VrPidCr3Cache, sizeof(g_VrPidCr3Cache));
    KeInitializeSpinLock(&g_VrPidCr3CacheLock);
    g_VrPidCr3CacheInitialized = TRUE;

    NTSTATUS s;

    // 1) 分配 PDPT / PD / PT / Backing 四张 pool 页
    s = VrAllocateAndGetPa(&g_VrSharedPdptVa, &g_VrSharedPdptPa);
    if (!NT_SUCCESS(s)) { DbgPrint("[VtRoot V2] PDPT alloc fail 0x%X\n", s); goto fail; }
    s = VrAllocateAndGetPa(&g_VrSharedPdVa, &g_VrSharedPdPa);
    if (!NT_SUCCESS(s)) { DbgPrint("[VtRoot V2] PD alloc fail 0x%X\n", s); goto fail; }
    s = VrAllocateAndGetPa(&g_VrSharedPtVa, &g_VrSharedPtPa);
    if (!NT_SUCCESS(s)) { DbgPrint("[VtRoot V2] PT alloc fail 0x%X\n", s); goto fail; }
    s = VrAllocateAndGetPa(&g_VrBackingVa, &g_VrBackingPa);
    if (!NT_SUCCESS(s)) { DbgPrint("[VtRoot V2] backing alloc fail 0x%X\n", s); goto fail; }

    if (!HvPhysIsRamRangeRootSafe(g_VrSharedPdptPa, PAGE_SIZE) ||
        !HvPhysIsRamRangeRootSafe(g_VrSharedPdPa, PAGE_SIZE) ||
        !HvPhysIsRamRangeRootSafe(g_VrSharedPtPa, PAGE_SIZE) ||
        !HvPhysIsRamRangeRootSafe(g_VrBackingPa, PAGE_SIZE)) {
        DbgPrint("[VtRoot V2] RAM range snapshot unavailable or PT pages invalid\n");
        s = STATUS_DEVICE_CONFIGURATION_ERROR;
        goto fail;
    }

    // 2) 填 PT[0..total-1] → backing (空闲态)
    {
        UINT64 backingEntry = (g_VrBackingPa & VR_PTE_PFN_MASK) | VR_LEAF_FLAGS;
        volatile UINT64* pt = (volatile UINT64*)g_VrSharedPtVa;
        for (ULONG i = 0; i < total; i++) {
            pt[i] = backingEntry;
        }
    }

    // 3) 填 PD[0] → PT
    ((volatile UINT64*)g_VrSharedPdVa)[0] =
        (g_VrSharedPtPa & VR_PTE_PFN_MASK) | VR_INTR_FLAGS;

    // 4) 填 PDPT[0] → PD
    ((volatile UINT64*)g_VrSharedPdptVa)[0] =
        (g_VrSharedPdPa & VR_PTE_PFN_MASK) | VR_INTR_FLAGS;

    // 5) 在 kernel CR3 的 PML4 找未用槽位
    //
    // Win11 24H2/25H2 + HVCI/VBS 环境下, MmMapIoSpace 对 RAM 范围内的 PA
    // (尤其是 critical 内核结构如 PML4 物理页) 经常返回 NULL 而无 status。
    // 多路径策略:
    //   a) MmGetVirtualForPhysical — host PML4 在 PFN database 里一定有 KVA
    //      反向索引, 这是最干净的路径(零额外映射)
    //   b) MmMapIoSpace(MmCached) — 经典路径
    //   c) MmMapIoSpace(MmNonCached) — HAL cache attribute conflict 时
    if (g_HvSystemCr3 == 0) {
        DbgPrint("[VtRoot V2] System CR3 unavailable, abort\n");
        s = STATUS_DEVICE_NOT_READY;
        goto fail;
    }

    UINT64 hostCr3 = HvUtilsGetSystemCr3() & VR_PTE_PFN_MASK;
    BOOLEAN needUnmap = FALSE;
    volatile UINT64* pml4Va = VrMapHostPml4(hostCr3, &needUnmap);

    if (!pml4Va) {
        DbgPrint("[VtRoot V2] all PML4 mapping paths failed (hostCr3=0x%llX)\n", hostCr3);
        s = STATUS_INSUFFICIENT_RESOURCES;
        goto fail;
    }

    ULONG slot = 0;
    s = VrFindFreePml4Slot(pml4Va, &slot);
    if (!NT_SUCCESS(s)) {
        DbgPrint("[VtRoot V2] no free PML4 slot in kernel half\n");
        VrUnmapHostPml4(pml4Va, needUnmap);
        goto fail;
    }

    // 6) 原子安装 PML4 entry → PDPT
    UINT64 pml4Entry = (g_VrSharedPdptPa & VR_PTE_PFN_MASK) | VR_INTR_FLAGS;
    InterlockedExchange64((LONG64*)&pml4Va[slot], (LONG64)pml4Entry);
    VrUnmapHostPml4(pml4Va, needUnmap);

    g_VrSharedPml4Index = slot;
    g_VrBaseVa = VrSlotToBaseVa(slot);
    g_VrHostCr3 = hostCr3;
    g_VrPml4Entry = pml4Entry;

    // 7) 配置每 CPU 的 gadget slice (per-CPU 4KB scratch VA + PT entry 指针)
    {
        volatile UINT64* pt = (volatile UINT64*)g_VrSharedPtVa;
        for (ULONG i = 0; i < total; i++) {
            PVCPU_DATA vcpu = &g_HypervisorContext.VcpuData[i];
            if (vcpu->ProcessorNumber != i) vcpu->ProcessorNumber = i;

            RtlZeroMemory(&vcpu->VtRootGadget, sizeof(vcpu->VtRootGadget));
            vcpu->VtRootGadget.ScratchVa     = (PVOID)(g_VrBaseVa + ((UINT64)i << 12));
            vcpu->VtRootGadget.ScratchPtePtr = (UINT64*)&pt[i];
            vcpu->VtRootGadget.BackingPagePa = g_VrBackingPa;
            vcpu->VtRootGadget.Initialized   = TRUE;
        }
    }

    // 8) IPI 全核 invlpg 各自的 ScratchVa (防御性 —— 历史 TLB 几乎不可能有
    //    这些刚映射出来的 VA 项,但保险)
    KeIpiGenericCall(VrInvlpgSelfIpi, 0);

    s = HvBroadcastVmCallToAllCpus(1);
    if (!NT_SUCCESS(s)) {
        DbgPrint("[VtRoot V2] all-CPU VMCALL health gate failed: 0x%X\n", s);
        HvVtRootCleanupAll();
        return s;
    }

    InterlockedExchange(&g_VrPublicationState, VrPublicationOnline);
    KeMemoryBarrier();
    g_VtRootEnabled = TRUE;
    DbgPrint("[VtRoot V2] === ENABLED. PML4[%u] @ baseVA=0x%llX, %u CPU slices ===\n",
             slot, g_VrBaseVa, total);
    return STATUS_SUCCESS;

fail:
    VrFreeIfAllocated(&g_VrBackingVa);
    VrFreeIfAllocated(&g_VrSharedPtVa);
    VrFreeIfAllocated(&g_VrSharedPdVa);
    VrFreeIfAllocated(&g_VrSharedPdptVa);
    g_VrBackingPa = g_VrSharedPtPa = g_VrSharedPdPa = g_VrSharedPdptPa = 0;
    g_VrBaseVa = 0;
    g_VrSharedPml4Index = 0;
    g_VrHostCr3 = 0;
    g_VrPml4Entry = 0;
    InterlockedExchange(&g_VrPublicationState, VrPublicationFailed);
    return s;
}

// ============================================================
// HvVtRootCleanupAll
// ============================================================

VOID HvVtRootCleanupAll(VOID)
{
    BOOLEAN mayFreeTables = TRUE;
    LONG previousState;
    KIRQL cacheIrql;

    for (;;) {
        previousState = g_VrPublicationState;
        if (previousState == VrPublicationOffline) return;
        if (previousState == VrPublicationRetained) return;
        if (previousState == VrPublicationQuiescing) {
            if (g_VrCleanupEventInitialized &&
                KeGetCurrentIrql() == PASSIVE_LEVEL) {
                (VOID)KeWaitForSingleObject(
                    &g_VrCleanupCompleteEvent,
                    Executive, KernelMode, FALSE, NULL);
            }
            return;
        }
        if (InterlockedCompareExchange(
                &g_VrPublicationState,
                VrPublicationQuiescing,
                previousState) == previousState) {
            break;
        }
    }

    g_VtRootEnabled = FALSE;
    KeMemoryBarrier();
    if (g_VrInvocationRundownInitialized &&
        previousState != VrPublicationOffline) {
        ExWaitForRundownProtectionRelease(&g_VrInvocationRundown);
    }
    KeAcquireSpinLock(&g_VrPidCr3CacheLock, &cacheIrql);
    g_VrPidCr3CacheInitialized = FALSE;
    RtlZeroMemory(g_VrPidCr3Cache, sizeof(g_VrPidCr3Cache));
    KeReleaseSpinLock(&g_VrPidCr3CacheLock, cacheIrql);

    // 1) 原子零 PML4 entry (前置条件:slot != 0 表示安装过)
    if (g_VrSharedPml4Index >= 256 && g_VrSharedPml4Index < 512) {
        BOOLEAN needUnmap = FALSE;
        volatile UINT64* pml4Va = VrMapHostPml4(g_VrHostCr3, &needUnmap);
        if (pml4Va) {
            volatile LONG64* entry =
                (volatile LONG64*)&pml4Va[g_VrSharedPml4Index];
            LONG64 current = *entry;
            if (((UINT64)current & VR_PTE_PFN_MASK) ==
                (g_VrPml4Entry & VR_PTE_PFN_MASK)) {
                LONG64 previous = InterlockedCompareExchange64(
                    entry, 0, current);
                if (previous != current) mayFreeTables = FALSE;
            }
            VrUnmapHostPml4(pml4Va, needUnmap);
        } else {
            mayFreeTables = FALSE;
        }

        // 2) IPI 全核 invlpg 自己的 ScratchVa (清掉 stale TLB)
        KeIpiGenericCall(VrInvlpgSelfIpi, 0);
    }

    // 3) 清每 CPU gadget
    if (g_HypervisorContext.VcpuData) {
        for (ULONG i = 0; i < g_HypervisorContext.ProcessorCount; i++) {
            RtlZeroMemory(&g_HypervisorContext.VcpuData[i].VtRootGadget,
                          sizeof(g_HypervisorContext.VcpuData[i].VtRootGadget));
        }
    }

    // 4) 释放 pool 页
    if (mayFreeTables) {
        VrFreeIfAllocated(&g_VrBackingVa);
        VrFreeIfAllocated(&g_VrSharedPtVa);
        VrFreeIfAllocated(&g_VrSharedPdVa);
        VrFreeIfAllocated(&g_VrSharedPdptVa);
        g_VrBackingPa = g_VrSharedPtPa = g_VrSharedPdPa = g_VrSharedPdptPa = 0;
        g_VrBaseVa = 0;
        g_VrSharedPml4Index = 0;
        g_VrHostCr3 = 0;
        g_VrPml4Entry = 0;
    } else {
        DbgPrint("[VtRoot V2] PML4 unlink failed; retaining PT island pages\n");
    }
    if (g_VrCleanupEventInitialized) {
        KeSetEvent(&g_VrCleanupCompleteEvent, IO_NO_INCREMENT, FALSE);
    }
    KeMemoryBarrier();
    InterlockedExchange(
        &g_VrPublicationState,
        mayFreeTables ? VrPublicationOffline : VrPublicationRetained);

    DbgPrint("[VtRoot V2] cleaned up\n");
}

static VOID VrRevokePublication(VOID)
{
    g_VtRootEnabled = FALSE;
    KeMemoryBarrier();
    (VOID)InterlockedCompareExchange(
        &g_VrPublicationState,
        VrPublicationFailed,
        VrPublicationOnline);
}

NTSTATUS
HvVtRootInvokeService(
    _In_ UINT64 TargetCr3,
    _In_ UINT64 TargetGva,
    _Inout_opt_ PVOID KernelBuffer,
    _In_ SIZE_T Size,
    _In_ ULONG Mode,
    _Out_ PSIZE_T OutResult)
{
    NTSTATUS status = STATUS_DEVICE_NOT_READY;
    BOOLEAN invalidateProcessor = FALSE;
    BOOLEAN revokePublication = FALSE;
    BOOLEAN irqlRaised = FALSE;
    ULONG processorNumber = MAXULONG;
    KIRQL oldIrql = PASSIVE_LEVEL;
    CPU_VENDOR vendor;

    if (!OutResult) return STATUS_INVALID_PARAMETER;
    *OutResult = 0;
    if (KeGetCurrentIrql() > APC_LEVEL) return STATUS_INVALID_LEVEL;

    if (HvIsPowerOffline() ||
        !g_VtRootEnabled ||
        g_VrPublicationState != VrPublicationOnline ||
        !g_VrInvocationRundownInitialized) {
        return STATUS_DEVICE_NOT_READY;
    }
    if (!ExAcquireRundownProtection(&g_VrInvocationRundown)) {
        return STATUS_DELETE_PENDING;
    }

    KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);
    irqlRaised = TRUE;
    processorNumber = KeGetCurrentProcessorNumber();

    if (!g_VtRootEnabled ||
        g_VrPublicationState != VrPublicationOnline) {
        status = STATUS_DELETE_PENDING;
        goto ExitRaised;
    }
    if (HvIsPowerOffline() || !g_HypervisorContext.IsActive) {
        revokePublication = TRUE;
        goto ExitRaised;
    }
    if (!HvIsCurrentProcessorVirtualized()) {
        invalidateProcessor = TRUE;
        revokePublication = TRUE;
        goto ExitRaised;
    }

    vendor = HvGetCpuVendor();
    __try {
        if (vendor == CPU_VENDOR_AMD) {
            status = AsmVmmCallPhysCopy(
                TargetCr3, TargetGva, KernelBuffer, Size, Mode, OutResult);
        } else if (vendor == CPU_VENDOR_INTEL) {
            status = AsmVmCallPhysCopy(
                TargetCr3, TargetGva, KernelBuffer, Size, Mode, OutResult);
        } else {
            status = STATUS_NOT_SUPPORTED;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        invalidateProcessor = (status == STATUS_ILLEGAL_INSTRUCTION);
        status = STATUS_DEVICE_NOT_READY;
        revokePublication = TRUE;
    }

ExitRaised:
    if (invalidateProcessor && processorNumber != MAXULONG) {
        HvInvalidateProcessorVirtualization(processorNumber);
    }
    if (irqlRaised) KeLowerIrql(oldIrql);
    if (revokePublication) VrRevokePublication();
    ExReleaseRundownProtection(&g_VrInvocationRundown);
    return status;
}

// ============================================================
// Per-CPU stubs (V2 在 InitializeAll 一次性建好,保留以兼容头文件 ABI)
// ============================================================

NTSTATUS HvVtRootInitializePerCpu(_Inout_ PVCPU_DATA Vcpu)
{
    UNREFERENCED_PARAMETER(Vcpu);
    // V2 不再使用 per-CPU init;gadget slice 在 InitializeAll 中一次性建立。
    return STATUS_SUCCESS;
}

VOID HvVtRootCleanupPerCpu(_Inout_ PVCPU_DATA Vcpu)
{
    UNREFERENCED_PARAMETER(Vcpu);
}

// ============================================================
// Root-mode 单页拷贝
// ============================================================

/*
 * 原子重定位 ScratchVa → NewPa,然后 invlpg 当前核。
 * Root 模式安全:仅 InterlockedExchange64 + __invlpg(单核,各 CPU 互不干扰)。
 */
static __forceinline VOID
VrRedirectScratch(_In_ PVCPU_DATA Vcpu, _In_ UINT64 NewPa)
{
    UINT64 newEntry = (NewPa & VR_PTE_PFN_MASK) | VR_LEAF_FLAGS;
    InterlockedExchange64((LONG64*)Vcpu->VtRootGadget.ScratchPtePtr,
                          (LONG64)newEntry);
    __invlpg(Vcpu->VtRootGadget.ScratchVa);
}

/*
 * 拷贝完成后把 ScratchPte 重新指向 backing 页 —— 防御性,保证空闲态
 * TLB 落到一块"我们控制的"无害页上。
 */
static __forceinline VOID
VrRestoreToBacking(_In_ PVCPU_DATA Vcpu)
{
    UINT64 backingEntry =
        (Vcpu->VtRootGadget.BackingPagePa & VR_PTE_PFN_MASK) | VR_LEAF_FLAGS;
    InterlockedExchange64((LONG64*)Vcpu->VtRootGadget.ScratchPtePtr,
                          (LONG64)backingEntry);
    __invlpg(Vcpu->VtRootGadget.ScratchVa);
}

/*
 * VrRootWalkAndCopyOnePage —— 在 root mode 用给定 CR3 走 4 级页表 + 拷贝。
 *
 * 与 HvVtRootRootCopyOnePage 的区别:这个 helper 不做参数校验 (调用方
 * 已校验过), 也不打 walk-fail 日志 (调用方在 multi-cr3 candidates 场景
 * 会大量 walk-fail, 日志会爆)。只返回成功/失败状态。
 *
 * 全程仅靠 VrRedirectScratch + __invlpg, 不调任何 NT API。
 * 调用方负责在最后(或失败时)调 VrRestoreToBacking。
 *
 * Quiet 参数: TRUE 时彻底静默, FALSE 时仅在最终 walk 出错时打印一条诊断。
 */
static NTSTATUS
VrRootWalkAndCopyOnePage(
    _Inout_ PVCPU_DATA Vcpu,
    _In_ UINT64 TargetCr3,
    _In_ UINT64 TargetGva,
    _Inout_updates_bytes_(Size) PUCHAR KernelBuf,
    _In_ SIZE_T Size,
    _In_ BOOLEAN IsWrite,
    _In_ BOOLEAN Quiet,
    _Out_ PSIZE_T BytesDone)
{
    if (BytesDone) *BytesDone = 0;
    Quiet = TRUE;

    // 2026-06-16: GVA sanity check — TargetGva 必须是 canonical user 半空间。
    // Multi-CR3 candidate 场景: 上层从某进程 EPROCESS 取 PEB 字段, 但 candidate CR3
    // 可能是别的进程的 → PEB 字段读出来是垃圾(可能是 kernel VA、非 canonical 等)。
    // 不校验直接 walk 那个垃圾 GVA → 拿到垃圾 PA → root mode 访问垃圾 PA →
    // host #PF / machine-check → triple fault (无 dump 蓝屏)。
    if (TargetGva < 0x10000ULL || TargetGva >= 0x800000000000ULL) {
        return STATUS_INVALID_PARAMETER;
    }
    // 不跨页
    if ((TargetGva & 0xFFFULL) + Size > PAGE_SIZE) {
        return STATUS_INVALID_PARAMETER;
    }

    PUCHAR scratch = (PUCHAR)Vcpu->VtRootGadget.ScratchVa;
    UINT64 cr3Base = TargetCr3 & VR_PTE_PFN_MASK;

    // 2026-06-16: CR3 sanity — snoop ring 可能有非法 CR3 (老进程的 / 边缘 entry)。
    // 不校验直接 VrRedirectScratch 到非法 PA → CPU 读 MMIO/越界 → host #MC/triple fault。
    // PA 必须在 1TB 内 + 非零 + 4KB 对齐 (cr3Base 已 mask 高位, 这里再 sanity)。
    if (!HvPhysIsRamRangeRootSafe(cr3Base, PAGE_SIZE)) {
        return STATUS_INVALID_PARAMETER;
    }

    ULONG pml4i = (ULONG)VR_PML4_INDEX(TargetGva);
    ULONG pdpti = (ULONG)VR_PDPT_INDEX(TargetGva);
    ULONG pdi   = (ULONG)VR_PD_INDEX(TargetGva);
    ULONG pti   = (ULONG)VR_PT_INDEX(TargetGva);

    // 2026-06-16: 每个中间表 PA 也做 sanity, 防止用错 CR3 时 walk 出垃圾 PA
    // 指向 MMIO/越界, 之后 VrRedirectScratch + 读 → host triple fault。
    //
    // 黑名单覆盖主流 MMIO 区:
    //   - 0xFEC00000-0xFEC01000:  IOAPIC
    //   - 0xFEE00000-0xFEE01000:  LAPIC
    //   - 0xFED00000-0xFED10000:  HPET / TPM
    //   - 0xE0000000-0xF0000000:  PCI ECAM (MCFG)
    //   - 0xC0000000 以上 (32-bit PCI BAR 常用)
    // 简化判定: PA 落在 0xC0000000 以上但 < 0x100000000 (4GB 以下高位) 视为危险。
    // user-mode PEB/Image 物理页几乎不可能落这里 (Win 不把 user heap 分到 reserved 区)。
    #define VR_PA_SANE(pa) HvPhysIsRamRangeRootSafe((pa), PAGE_SIZE)

    VrRedirectScratch(Vcpu, cr3Base);
    UINT64 pml4e = ((volatile UINT64*)scratch)[pml4i];
    if (!(pml4e & VR_PTE_PRESENT)) {
        if (!Quiet) {
            DbgPrint("[VtRoot] Walk FAIL @PML4: cr3=0x%llX gva=0x%llX idx[%u]=0x%llX\n",
                     TargetCr3, TargetGva, pml4i, pml4e);
        }
        return STATUS_INVALID_ADDRESS_COMPONENT;
    }
    UINT64 pdptPa = pml4e & VR_PTE_PFN_MASK;
    if (!VR_PA_SANE(pdptPa)) {
        return STATUS_INVALID_ADDRESS_COMPONENT;
    }

    VrRedirectScratch(Vcpu, pdptPa);
    UINT64 pdpte = ((volatile UINT64*)scratch)[pdpti];
    if (!(pdpte & VR_PTE_PRESENT)) {
        if (!Quiet) {
            DbgPrint("[VtRoot] Walk FAIL @PDPT: cr3=0x%llX gva=0x%llX pml4[%u]=0x%llX pdpt[%u]=0x%llX\n",
                     TargetCr3, TargetGva, pml4i, pml4e, pdpti, pdpte);
        }
        return STATUS_INVALID_ADDRESS_COMPONENT;
    }

    UINT64 targetPa;
    SIZE_T pageSize;

    if (pdpte & VR_PTE_PS) {
        targetPa = (pdpte & 0x000FFFFFC0000000ULL) | (TargetGva & 0x3FFFFFFFULL);
        pageSize = 0x40000000ULL;
    } else {
        UINT64 pdPa = pdpte & VR_PTE_PFN_MASK;
        if (!VR_PA_SANE(pdPa)) {
            return STATUS_INVALID_ADDRESS_COMPONENT;
        }
        VrRedirectScratch(Vcpu, pdPa);
        UINT64 pde = ((volatile UINT64*)scratch)[pdi];
        if (!(pde & VR_PTE_PRESENT)) {
            if (!Quiet) {
                DbgPrint("[VtRoot] Walk FAIL @PD: cr3=0x%llX gva=0x%llX pml4[%u]=0x%llX pdpt[%u]=0x%llX pd[%u]=0x%llX\n",
                         TargetCr3, TargetGva, pml4i, pml4e, pdpti, pdpte, pdi, pde);
            }
            return STATUS_INVALID_ADDRESS_COMPONENT;
        }

        if (pde & VR_PTE_PS) {
            targetPa = (pde & 0x000FFFFFFFE00000ULL) | (TargetGva & 0x1FFFFFULL);
            pageSize = 0x200000ULL;
        } else {
            UINT64 ptPa = pde & VR_PTE_PFN_MASK;
            if (!VR_PA_SANE(ptPa)) {
                return STATUS_INVALID_ADDRESS_COMPONENT;
            }
            VrRedirectScratch(Vcpu, ptPa);
            UINT64 pte = ((volatile UINT64*)scratch)[pti];
            if (!(pte & VR_PTE_PRESENT)) {
                if (!Quiet) {
                    DbgPrint("[VtRoot] Walk FAIL @PT: cr3=0x%llX gva=0x%llX pml4[%u]=0x%llX pdpt[%u]=0x%llX pd[%u]=0x%llX pt[%u]=0x%llX\n",
                             TargetCr3, TargetGva, pml4i, pml4e, pdpti, pdpte, pdi, pde, pti, pte);
                }
                return STATUS_NOT_FOUND;
            }
            targetPa = (pte & VR_PTE_PFN_MASK) | (TargetGva & 0xFFFULL);
            pageSize = PAGE_SIZE;
        }
    }

    #undef VR_PA_SANE

    UINT64 dataPageBase = targetPa & ~0xFFFULL;

    // 2026-06-16: Leaf PA sanity check — 见 VR_PA_SANE 宏(包含 MMIO 黑名单)。
    if (!HvPhysIsRamRangeRootSafe(dataPageBase, PAGE_SIZE)) {
        if (!Quiet) {
            DbgPrint("[VtRoot] Walk FAIL: leaf PA out of range / MMIO cr3=0x%llX gva=0x%llX pa=0x%llX\n",
                     TargetCr3, TargetGva, dataPageBase);
        }
        return STATUS_INVALID_ADDRESS_COMPONENT;
    }

    SIZE_T inPageOff = (SIZE_T)(targetPa & 0xFFF);
    SIZE_T pageMask  = (SIZE_T)(pageSize - 1);
    SIZE_T inPageLeft = (SIZE_T)(pageSize - (SIZE_T)(targetPa & pageMask));
    if (inPageLeft > PAGE_SIZE - inPageOff) inPageLeft = PAGE_SIZE - inPageOff;
    SIZE_T chunk = (Size < inPageLeft) ? Size : inPageLeft;

    VrRedirectScratch(Vcpu, dataPageBase);
    PUCHAR src = scratch + inPageOff;

    if (IsWrite) {
        RtlCopyMemory(src, KernelBuf, chunk);
    } else {
        RtlCopyMemory(KernelBuf, src, chunk);
    }

    *BytesDone = chunk;
    return STATUS_SUCCESS;
}

/*
 * Validate a PASSIVE-captured process identity snapshot entirely through the
 * candidate CR3. Both anchor pages are MDL-locked while the request is live.
 */
static NTSTATUS
VrRootValidateCr3Snapshot(
    _Inout_ PVCPU_DATA Vcpu,
    _In_ UINT64 PebGva,
    _In_ UINT64 ExpectedImageBase,
    _In_ UINT64 CandidateCr3)
{
    UINT64 imageBase = 0;
    USHORT magic = 0;
    SIZE_T done = 0;
    NTSTATUS status;

    if (PebGva < 0x10000ULL || PebGva >= 0x800000000000ULL ||
        ExpectedImageBase < 0x10000ULL ||
        ExpectedImageBase >= 0x800000000000ULL ||
        (ExpectedImageBase & (PAGE_SIZE - 1)) != 0) {
        return STATUS_NOT_SUPPORTED;
    }
    if ((PebGva & (PAGE_SIZE - 1)) + 0x18 > PAGE_SIZE) {
        return STATUS_NOT_SUPPORTED;
    }

    status = VrRootWalkAndCopyOnePage(
        Vcpu, CandidateCr3, PebGva + 0x10,
        (PUCHAR)&imageBase, sizeof(imageBase), FALSE, TRUE, &done);
    if (!NT_SUCCESS(status) || done != sizeof(imageBase) ||
        imageBase != ExpectedImageBase) {
        return STATUS_NOT_FOUND;
    }

    done = 0;
    status = VrRootWalkAndCopyOnePage(
        Vcpu, CandidateCr3, ExpectedImageBase,
        (PUCHAR)&magic, sizeof(magic), FALSE, TRUE, &done);
    if (!NT_SUCCESS(status) || done != sizeof(magic) || magic != 0x5A4D) {
        return STATUS_NOT_FOUND;
    }
    return STATUS_SUCCESS;
}

NTSTATUS
HvVtRootRootCopyOnePage(
    _Inout_ PVCPU_DATA Vcpu,
    _In_ UINT64 TargetCr3,
    _In_ UINT64 TargetGva,
    _Inout_updates_bytes_(Size) PUCHAR KernelBuf,
    _In_ SIZE_T Size,
    _In_ BOOLEAN IsWrite,
    _Out_ PSIZE_T BytesDone
)
{
    if (BytesDone) *BytesDone = 0;

    if (!Vcpu || !Vcpu->VtRootGadget.Initialized) {
        return STATUS_DEVICE_NOT_READY;
    }
    if (!KernelBuf || !BytesDone || Size == 0 || Size > PAGE_SIZE) {
        return STATUS_INVALID_PARAMETER;
    }
    UINT64 bufferStart = (UINT64)(ULONG_PTR)KernelBuf;
    UINT64 bufferEnd = bufferStart + (UINT64)Size;
    if ((bufferStart >> 48) != 0xFFFFULL ||
        bufferEnd <= bufferStart ||
        ((bufferEnd - 1) >> 48) != 0xFFFFULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (((TargetGva & 0xFFF) + Size) > PAGE_SIZE) {
        return STATUS_INVALID_PARAMETER;
    }

    NTSTATUS status = VrRootWalkAndCopyOnePage(
        Vcpu, TargetCr3, TargetGva, KernelBuf, Size, IsWrite,
        TRUE,
        BytesDone);

    VrRestoreToBacking(Vcpu);
    return status;
}

// ============================================================
// Root-mode: 仅 walk + 返回 HPA (不拷贝数据)
// ============================================================
//
// 镜像 VrRootWalkAndCopyOnePage 的 walk 逻辑, 但不进入数据拷贝阶段。
// 只到 leaf PA + pageSize 就返回。caller (RootWalkGvaToHpa) 负责
// 调 VrRestoreToBacking。
//
// IRQL: root mode (interrupts off)
static NTSTATUS
VrRootQueryLeaf(
    _Inout_ PVCPU_DATA Vcpu,
    _In_ UINT64 TargetCr3,
    _In_ UINT64 TargetGva,
    _Out_ PUINT64 OutHpa,
    _Out_ PUINT64 OutPageSize,
    _Out_opt_ PHV_VTROOT_LEAF_PTE_INFO OutLeafInfo)
{
    *OutHpa = 0;
    *OutPageSize = 0;

    if (OutLeafInfo) {
        RtlZeroMemory(OutLeafInfo, sizeof(*OutLeafInfo));
        OutLeafInfo->Magic = HV_VTROOT_LEAF_INFO_MAGIC;
        OutLeafInfo->Version = HV_VTROOT_LEAF_INFO_VERSION;
        OutLeafInfo->Size = sizeof(*OutLeafInfo);
    }

    if (!((TargetGva >= 0x10000ULL &&
           TargetGva < 0x800000000000ULL) ||
          TargetGva >= 0xFFFF800000000000ULL)) {
        return STATUS_INVALID_PARAMETER;
    }

    PUCHAR scratch = (PUCHAR)Vcpu->VtRootGadget.ScratchVa;
    UINT64 cr3Base = TargetCr3 & VR_PTE_PFN_MASK;
    if (!HvPhysIsRamRangeRootSafe(cr3Base, PAGE_SIZE)) {
        return STATUS_INVALID_PARAMETER;
    }

    ULONG pml4i = (ULONG)VR_PML4_INDEX(TargetGva);
    ULONG pdpti = (ULONG)VR_PDPT_INDEX(TargetGva);
    ULONG pdi   = (ULONG)VR_PD_INDEX(TargetGva);
    ULONG pti   = (ULONG)VR_PT_INDEX(TargetGva);

    #define VR_WO_PA_SANE(pa) HvPhysIsRamRangeRootSafe((pa), PAGE_SIZE)

    VrRedirectScratch(Vcpu, cr3Base);
    UINT64 pml4e = ((volatile UINT64*)scratch)[pml4i];
    if (!(pml4e & VR_PTE_PRESENT)) return STATUS_INVALID_ADDRESS_COMPONENT;
    UINT64 pdptPa = pml4e & VR_PTE_PFN_MASK;
    if (!VR_WO_PA_SANE(pdptPa)) return STATUS_INVALID_ADDRESS_COMPONENT;

    VrRedirectScratch(Vcpu, pdptPa);
    UINT64 pdpte = ((volatile UINT64*)scratch)[pdpti];
    if (!(pdpte & VR_PTE_PRESENT)) return STATUS_INVALID_ADDRESS_COMPONENT;

    if (pdpte & VR_PTE_PS) {
        if (pdpte & VR_PDPTE_1G_RESERVED_LOW_MASK) {
            return STATUS_INVALID_ADDRESS_COMPONENT;
        }
        UINT64 leaf = (pdpte & VR_PDPTE_1G_PFN_MASK) |
                      (TargetGva & 0x3FFFFFFFULL);
        if (!VR_WO_PA_SANE(leaf & ~0xFFFULL)) {
            return STATUS_INVALID_ADDRESS_COMPONENT;
        }
        *OutHpa = leaf;
        *OutPageSize = 0x40000000ULL;
        if (OutLeafInfo) {
            OutLeafInfo->LeafTablePa = pdptPa;
            OutLeafInfo->LeafIndex = pdpti;
            OutLeafInfo->LeafLevel = HV_VTROOT_LEAF_LEVEL_PDPT;
            OutLeafInfo->OriginalEntry = pdpte;
            OutLeafInfo->LeafHpa = leaf;
            OutLeafInfo->PageSize = 0x40000000ULL;
            OutLeafInfo->LeafFlags =
                pdpte & ~VR_PDPTE_1G_PFN_MASK;
        }
        return STATUS_SUCCESS;
    }

    UINT64 pdPa = pdpte & VR_PTE_PFN_MASK;
    if (!VR_WO_PA_SANE(pdPa)) return STATUS_INVALID_ADDRESS_COMPONENT;
    VrRedirectScratch(Vcpu, pdPa);
    UINT64 pde = ((volatile UINT64*)scratch)[pdi];
    if (!(pde & VR_PTE_PRESENT)) return STATUS_INVALID_ADDRESS_COMPONENT;

    if (pde & VR_PTE_PS) {
        if (pde & VR_PDE_2M_RESERVED_LOW_MASK) {
            return STATUS_INVALID_ADDRESS_COMPONENT;
        }
        UINT64 leaf = (pde & VR_PDE_2M_PFN_MASK) |
                      (TargetGva & 0x1FFFFFULL);
        if (!VR_WO_PA_SANE(leaf & ~0xFFFULL)) {
            return STATUS_INVALID_ADDRESS_COMPONENT;
        }
        *OutHpa = leaf;
        *OutPageSize = 0x200000ULL;
        if (OutLeafInfo) {
            OutLeafInfo->LeafTablePa = pdPa;
            OutLeafInfo->LeafIndex = pdi;
            OutLeafInfo->LeafLevel = HV_VTROOT_LEAF_LEVEL_PD;
            OutLeafInfo->OriginalEntry = pde;
            OutLeafInfo->LeafHpa = leaf;
            OutLeafInfo->PageSize = 0x200000ULL;
            OutLeafInfo->LeafFlags =
                pde & ~VR_PDE_2M_PFN_MASK;
        }
        return STATUS_SUCCESS;
    }

    UINT64 ptPa = pde & VR_PTE_PFN_MASK;
    if (!VR_WO_PA_SANE(ptPa)) return STATUS_INVALID_ADDRESS_COMPONENT;
    VrRedirectScratch(Vcpu, ptPa);
    UINT64 pte = ((volatile UINT64*)scratch)[pti];
    if (!(pte & VR_PTE_PRESENT)) {
        // Leaf-location callers need to locate an empty PT slot as well. The
        // ordinary GVA walker passes OutLeafInfo=NULL and keeps NOT_FOUND
        // semantics for an unmapped page.
        if (!OutLeafInfo) return STATUS_NOT_FOUND;

        OutLeafInfo->LeafTablePa = ptPa;
        OutLeafInfo->LeafIndex = pti;
        OutLeafInfo->LeafLevel = HV_VTROOT_LEAF_LEVEL_PT;
        OutLeafInfo->OriginalEntry = pte;
        OutLeafInfo->LeafHpa = 0;
        OutLeafInfo->PageSize = PAGE_SIZE;
        OutLeafInfo->LeafFlags = pte & ~VR_PTE_PFN_MASK;
        return STATUS_SUCCESS;
    }

    UINT64 leaf = (pte & VR_PTE_PFN_MASK) | (TargetGva & 0xFFFULL);
    if (!VR_WO_PA_SANE(leaf & ~0xFFFULL)) return STATUS_INVALID_ADDRESS_COMPONENT;

    *OutHpa = leaf;
    *OutPageSize = PAGE_SIZE;
    if (OutLeafInfo) {
        OutLeafInfo->LeafTablePa = ptPa;
        OutLeafInfo->LeafIndex = pti;
        OutLeafInfo->LeafLevel = HV_VTROOT_LEAF_LEVEL_PT;
        OutLeafInfo->OriginalEntry = pte;
        OutLeafInfo->LeafHpa = leaf;
        OutLeafInfo->PageSize = PAGE_SIZE;
        OutLeafInfo->LeafFlags = pte & ~VR_PTE_PFN_MASK;
    }

    #undef VR_WO_PA_SANE
    return STATUS_SUCCESS;
}

static NTSTATUS
VrRootWalkOnly(
    _Inout_ PVCPU_DATA Vcpu,
    _In_ UINT64 TargetCr3,
    _In_ UINT64 TargetGva,
    _Out_ PUINT64 OutHpa,
    _Out_ PUINT64 OutPageSize)
{
    // PID/process request modes are user-address APIs. The generalized
    // trusted-CR3 query below also supports canonical kernel addresses.
    if (TargetGva < 0x10000ULL || TargetGva >= 0x800000000000ULL) {
        return STATUS_INVALID_PARAMETER;
    }
    return VrRootQueryLeaf(
        Vcpu, TargetCr3, TargetGva, OutHpa, OutPageSize, NULL);
}

NTSTATUS
HvVtRootRootWalkGvaToHpaWithCr3(
    _Inout_ PVCPU_DATA Vcpu,
    _In_ UINT64 TargetCr3,
    _In_ UINT64 Gva,
    _Out_ PUINT64 OutHpa,
    _Out_ PUINT64 OutPageSize)
{
    if (!OutHpa || !OutPageSize) return STATUS_INVALID_PARAMETER;
    *OutHpa = 0;
    *OutPageSize = 0;

    if (!Vcpu || !Vcpu->VtRootGadget.Initialized) {
        return STATUS_DEVICE_NOT_READY;
    }
    if (Gva < 0x10000ULL || Gva >= 0x800000000000ULL) {
        return STATUS_INVALID_PARAMETER;
    }

    NTSTATUS status = VrRootWalkOnly(
        Vcpu, TargetCr3, Gva, OutHpa, OutPageSize);
    VrRestoreToBacking(Vcpu);
    return status;
}

NTSTATUS
HvVtRootRootQueryLeafPteWithCr3(
    _Inout_ PVCPU_DATA Vcpu,
    _In_ UINT64 TargetCr3,
    _In_ UINT64 Gva,
    _Inout_ PHV_VTROOT_LEAF_PTE_INFO LeafInfo)
{
    UINT64 infoStart;
    UINT64 infoEnd;
    UINT64 hpa = 0;
    UINT64 pageSize = 0;

    if (!Vcpu || !Vcpu->VtRootGadget.Initialized) {
        return STATUS_DEVICE_NOT_READY;
    }
    if (!LeafInfo) return STATUS_INVALID_PARAMETER;

    infoStart = (UINT64)(ULONG_PTR)LeafInfo;
    infoEnd = infoStart + sizeof(*LeafInfo);
    if ((infoStart >> 48) != 0xFFFFULL ||
        infoEnd <= infoStart ||
        ((infoEnd - 1) >> 48) != 0xFFFFULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (LeafInfo->Magic != HV_VTROOT_LEAF_INFO_MAGIC ||
        LeafInfo->Version != HV_VTROOT_LEAF_INFO_VERSION ||
        LeafInfo->Size != sizeof(*LeafInfo)) {
        return STATUS_REVISION_MISMATCH;
    }
    if (!((Gva >= 0x10000ULL && Gva < 0x800000000000ULL) ||
          Gva >= 0xFFFF800000000000ULL)) {
        return STATUS_INVALID_PARAMETER;
    }

    NTSTATUS status = VrRootQueryLeaf(
        Vcpu, TargetCr3, Gva, &hpa, &pageSize, LeafInfo);
    VrRestoreToBacking(Vcpu);
    return status;
}

NTSTATUS
HvVtRootRootProcessRequest(
    _Inout_ PVCPU_DATA Vcpu,
    _In_ PVOID RequestAddress,
    _In_ ULONG Mode,
    _Out_ PUINT64 OutResult)
{
    PVR_PROCESS_REQUEST request;
    UINT64 requestStart;
    UINT64 requestEnd;
    NTSTATUS lastStatus = STATUS_NOT_FOUND;

    if (OutResult) *OutResult = 0;
    if (!Vcpu || !Vcpu->VtRootGadget.Initialized || !OutResult) {
        return STATUS_DEVICE_NOT_READY;
    }

    requestStart = (UINT64)(ULONG_PTR)RequestAddress;
    requestEnd = requestStart + sizeof(VR_PROCESS_REQUEST);
    if ((requestStart >> 48) != 0xFFFFULL ||
        requestEnd <= requestStart ||
        ((requestEnd - 1) >> 48) != 0xFFFFULL) {
        return STATUS_INVALID_PARAMETER;
    }

    request = (PVR_PROCESS_REQUEST)RequestAddress;
    if (request->Magic != VR_PROCESS_REQUEST_MAGIC ||
        request->Version != VR_PROCESS_REQUEST_VERSION ||
        request->Size != sizeof(VR_PROCESS_REQUEST) ||
        request->TargetPid == 0 || request->CreateTime == 0 ||
        request->CandidateCount == 0 ||
        request->CandidateCount > VR_PROCESS_MAX_CANDIDATES) {
        return STATUS_INVALID_PARAMETER;
    }
    if (Mode != HV_VTROOT_MODE_PROCESS_READ &&
        Mode != HV_VTROOT_MODE_PROCESS_WRITE &&
        Mode != HV_VTROOT_MODE_PROCESS_RESOLVE &&
        Mode != HV_VTROOT_MODE_PROCESS_WALK) {
        return STATUS_NOT_SUPPORTED;
    }

    if (Mode == HV_VTROOT_MODE_PROCESS_READ ||
        Mode == HV_VTROOT_MODE_PROCESS_WRITE) {
        UINT64 bufferStart = (UINT64)(ULONG_PTR)request->Bounce;
        UINT64 bufferEnd = bufferStart + request->TransferSize;
        if (!request->Bounce || request->TransferSize == 0 ||
            request->TransferSize > PAGE_SIZE ||
            (request->TargetGva & (PAGE_SIZE - 1)) +
                request->TransferSize > PAGE_SIZE ||
            (bufferStart >> 48) != 0xFFFFULL ||
            bufferEnd <= bufferStart ||
            ((bufferEnd - 1) >> 48) != 0xFFFFULL) {
            return STATUS_INVALID_PARAMETER;
        }
    }

    for (ULONG index = 0; index < request->CandidateCount; ++index) {
        UINT64 candidate = request->Candidates[index] & VR_PTE_PFN_MASK;
        if (!HvPhysIsRamRangeRootSafe(candidate, PAGE_SIZE)) {
            continue;
        }

        NTSTATUS status = STATUS_SUCCESS;
        if (request->ResolvedCr3 != candidate) {
            status = VrRootValidateCr3Snapshot(
                Vcpu, request->PebGva, request->ImageBase, candidate);
            if (!NT_SUCCESS(status)) {
                lastStatus = status;
                continue;
            }
        }

        if (Mode == HV_VTROOT_MODE_PROCESS_RESOLVE) {
            request->ResolvedCr3 = candidate;
            *OutResult = candidate;
            VrRestoreToBacking(Vcpu);
            return STATUS_SUCCESS;
        }

        if (Mode == HV_VTROOT_MODE_PROCESS_WALK) {
            UINT64 hpa = 0;
            UINT64 pageSize = 0;
            status = VrRootWalkOnly(
                Vcpu, candidate, request->TargetGva, &hpa, &pageSize);
            if (NT_SUCCESS(status)) {
                request->ResolvedCr3 = candidate;
                request->ResultPageSize = pageSize;
                *OutResult = hpa;
                VrRestoreToBacking(Vcpu);
                return STATUS_SUCCESS;
            }
            lastStatus = status;
            continue;
        }

        SIZE_T done = 0;
        status = VrRootWalkAndCopyOnePage(
            Vcpu, candidate, request->TargetGva,
            request->Bounce, request->TransferSize,
            (BOOLEAN)(Mode == HV_VTROOT_MODE_PROCESS_WRITE),
            TRUE, &done);
        if (NT_SUCCESS(status) && done == request->TransferSize) {
            request->ResolvedCr3 = candidate;
            *OutResult = done;
            VrRestoreToBacking(Vcpu);
            return STATUS_SUCCESS;
        }
        lastStatus = NT_SUCCESS(status) ? STATUS_PARTIAL_COPY : status;
    }

    VrRestoreToBacking(Vcpu);
    return lastStatus;
}

// ============================================================
// PASSIVE-level by-PID copy (Phase C)
// ============================================================
//
// PASSIVE owns the referenced process and immutable identity/candidate
// snapshot. Candidate validation, page-table walking and copying are performed
// synchronously in VMX-root/SVM-host mode.

static VOID
VrAddProcessCandidate(
    _Inout_ PVR_PROCESS_REQUEST Request,
    _In_ UINT64 Candidate)
{
    Candidate &= VR_PTE_PFN_MASK;
    if (!HvPhysIsRamRangeRootSafe(Candidate, PAGE_SIZE)) return;

    for (ULONG index = 0; index < Request->CandidateCount; ++index) {
        if (Request->Candidates[index] == Candidate) return;
    }
    if (Request->CandidateCount < VR_PROCESS_MAX_CANDIDATES) {
        Request->Candidates[Request->CandidateCount++] = Candidate;
    }
}

static VOID
VrAddProcessCandidateAtOffset(
    _Inout_ PVR_PROCESS_REQUEST Request,
    _In_ PEPROCESS Process,
    _In_ ULONG Offset)
{
    UINT64 candidate = 0;

    if (Offset < 0x20 || Offset > 0xC00) return;
    __try {
        candidate = *(volatile UINT64*)((PUCHAR)Process + Offset);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return;
    }
    VrAddProcessCandidate(Request, candidate);
}

static NTSTATUS
VrBuildProcessRequest(
    _In_ ULONG TargetPid,
    _In_ PEPROCESS Process,
    _Out_ PVR_PROCESS_REQUEST Request)
{
    UINT64 cachedCr3 = 0;
    UINT64 snoopCr3s[HV_CR3_SNOOP_RING_SIZE];

    RtlZeroMemory(Request, sizeof(*Request));
    if (!Process || TargetPid == 0 || !g_HvPhysRootCtx.Initialized) {
        return STATUS_DEVICE_NOT_READY;
    }

    Request->Magic = VR_PROCESS_REQUEST_MAGIC;
    Request->Size = sizeof(*Request);
    Request->Version = VR_PROCESS_REQUEST_VERSION;
    Request->TargetPid = TargetPid;
    Request->CreateTime = (UINT64)PsGetProcessCreateTimeQuadPart(Process);
    Request->PebGva = (UINT64)(ULONG_PTR)PsGetProcessPeb(Process);
    Request->ImageBase = (UINT64)(ULONG_PTR)
        PsGetProcessSectionBaseAddress(Process);

    if (Request->CreateTime == 0 ||
        Request->PebGva < 0x10000ULL ||
        Request->PebGva >= 0x800000000000ULL ||
        Request->ImageBase < 0x10000ULL ||
        Request->ImageBase >= 0x800000000000ULL ||
        (Request->ImageBase & (PAGE_SIZE - 1)) != 0) {
        return STATUS_NOT_SUPPORTED;
    }

    if (VrCacheLookup(TargetPid, Request->CreateTime, &cachedCr3)) {
        VrAddProcessCandidate(Request, cachedCr3);
    }
    for (ULONG index = 0;
         index < g_HvPhysRootCtx.KnownUserDtbOffCount;
        ++index) {
        VrAddProcessCandidateAtOffset(
            Request, Process,
            (ULONG)g_HvPhysRootCtx.KnownUserDtbOffs[index]);
    }
    VrAddProcessCandidateAtOffset(
        Request, Process, g_HvPhysRootCtx.DtbOff);

    ULONG snoopCount = HvCr3SnoopSnapshot(
        snoopCr3s, RTL_NUMBER_OF(snoopCr3s));
    for (ULONG index = 0; index < snoopCount; ++index) {
        VrAddProcessCandidate(Request, snoopCr3s[index]);
    }

    return Request->CandidateCount != 0
        ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}

static NTSTATUS
VrLockProcessRange(
    _In_ PEPROCESS Process,
    _In_ UINT64 Address,
    _In_ SIZE_T Size,
    _In_ LOCK_OPERATION Operation,
    _Out_ PMDL* OutMdl,
    _Out_ PBOOLEAN OutLocked)
{
    PMDL mdl;
    NTSTATUS status = STATUS_SUCCESS;

    *OutMdl = NULL;
    *OutLocked = FALSE;
    if (!Process || Address < 0x10000ULL ||
        Address >= 0x800000000000ULL || Size == 0 || Size > MAXULONG ||
        Address + Size <= Address ||
        Address + Size > 0x800000000000ULL) {
        return STATUS_INVALID_PARAMETER;
    }

    mdl = IoAllocateMdl(
        (PVOID)(ULONG_PTR)Address, (ULONG)Size, FALSE, FALSE, NULL);
    if (!mdl) return STATUS_INSUFFICIENT_RESOURCES;

    __try {
        MmProbeAndLockProcessPages(mdl, Process, UserMode, Operation);
        *OutLocked = TRUE;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        if (NT_SUCCESS(status)) status = STATUS_ACCESS_VIOLATION;
    }

    if (!NT_SUCCESS(status)) {
        IoFreeMdl(mdl);
        return status;
    }
    *OutMdl = mdl;
    return STATUS_SUCCESS;
}

static VOID
VrUnlockProcessRange(
    _Inout_ PMDL* Mdl,
    _Inout_ PBOOLEAN Locked)
{
    if (*Mdl) {
        if (*Locked) MmUnlockPages(*Mdl);
        IoFreeMdl(*Mdl);
    }
    *Mdl = NULL;
    *Locked = FALSE;
}

static NTSTATUS
VrLockProcessAnchors(
    _In_ PEPROCESS Process,
    _In_ PVR_PROCESS_REQUEST Request,
    _Out_ PVR_LOCKED_ANCHORS Anchors)
{
    NTSTATUS status;

    RtlZeroMemory(Anchors, sizeof(*Anchors));
    status = VrLockProcessRange(
        Process, Request->PebGva + 0x10, sizeof(UINT64), IoReadAccess,
        &Anchors->PebMdl, &Anchors->PebLocked);
    if (!NT_SUCCESS(status)) return status;

    status = VrLockProcessRange(
        Process, Request->ImageBase, sizeof(USHORT), IoReadAccess,
        &Anchors->ImageMdl, &Anchors->ImageLocked);
    if (!NT_SUCCESS(status)) {
        VrUnlockProcessRange(&Anchors->PebMdl, &Anchors->PebLocked);
    }
    return status;
}

static VOID
VrUnlockProcessAnchors(_Inout_ PVR_LOCKED_ANCHORS Anchors)
{
    VrUnlockProcessRange(&Anchors->ImageMdl, &Anchors->ImageLocked);
    VrUnlockProcessRange(&Anchors->PebMdl, &Anchors->PebLocked);
}

static NTSTATUS
VrInvokeProcessRequest(
    _Inout_ PVR_PROCESS_REQUEST Request,
    _In_ ULONG Mode,
    _Out_ PUINT64 OutResult)
{
    SIZE_T resultSlot = 0;
    NTSTATUS status;

    status = HvVtRootInvokeService(
        (UINT64)(ULONG_PTR)Request, 0, NULL, 0, Mode, &resultSlot);

    *OutResult = (UINT64)resultSlot;
    if (NT_SUCCESS(status) && Request->ResolvedCr3 != 0) {
        VrCacheStore(
            Request->TargetPid, Request->CreateTime, Request->ResolvedCr3);
    }
    return status;
}

NTSTATUS
HvVtRootCopyByPid(
    _In_ ULONG TargetPid,
    _In_ UINT64 Gva,
    _Inout_updates_bytes_(Size) PVOID Buffer,
    _In_ SIZE_T Size,
    _In_ BOOLEAN IsWrite,
    _Out_opt_ PSIZE_T BytesDone)
{
    PEPROCESS process = NULL;
    PVR_PROCESS_REQUEST request = NULL;
    PUCHAR bounce = NULL;
    PMDL targetMdl = NULL;
    BOOLEAN targetLocked = FALSE;
    VR_LOCKED_ANCHORS anchors;
    BOOLEAN anchorsLocked = FALSE;
    NTSTATUS status;
    SIZE_T totalDone = 0;

    if (BytesDone) *BytesDone = 0;
    if (!Buffer || Size == 0) return STATUS_INVALID_PARAMETER;
    if (KeGetCurrentIrql() > APC_LEVEL) return STATUS_INVALID_LEVEL;
    if (!g_VtRootEnabled) return STATUS_DEVICE_NOT_READY;
    if (TargetPid == 0 || Gva < 0x10000ULL ||
        Gva >= 0x800000000000ULL || Size > MAXULONG ||
        Gva + Size <= Gva || Gva + Size > 0x800000000000ULL) {
        return STATUS_INVALID_PARAMETER;
    }

    status = PsLookupProcessByProcessId(
        (HANDLE)(ULONG_PTR)TargetPid, &process);
    if (!NT_SUCCESS(status) || !process) {
        return NT_SUCCESS(status) ? STATUS_INVALID_CID : status;
    }

    request = (PVR_PROCESS_REQUEST)HvAllocateNonPagedZeroed(
        sizeof(*request), VR_REQUEST_TAG);
    bounce = (PUCHAR)HvAllocateNonPaged(PAGE_SIZE, VR_COPY_TAG);
    if (!request || !bounce) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto cleanup;
    }

    status = VrBuildProcessRequest(TargetPid, process, request);
    if (!NT_SUCCESS(status)) goto cleanup;

    status = VrLockProcessRange(
        process, Gva, Size,
        IsWrite ? IoWriteAccess : IoReadAccess,
        &targetMdl, &targetLocked);
    if (!NT_SUCCESS(status)) goto cleanup;

    status = VrLockProcessAnchors(process, request, &anchors);
    if (!NT_SUCCESS(status)) goto cleanup;
    anchorsLocked = TRUE;
    request->Bounce = bounce;

    PUCHAR currentBuffer = (PUCHAR)Buffer;
    UINT64 currentGva = Gva;
    SIZE_T remaining = Size;
    while (remaining != 0) {
        SIZE_T pageRemaining = PAGE_SIZE - (SIZE_T)(currentGva & 0xFFF);
        SIZE_T chunk = remaining < pageRemaining ? remaining : pageRemaining;
        UINT64 result = 0;

        if (IsWrite) {
            __try {
                RtlCopyMemory(bounce, currentBuffer, chunk);
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                status = GetExceptionCode();
                if (NT_SUCCESS(status)) status = STATUS_ACCESS_VIOLATION;
                goto cleanup;
            }
        }

        request->TargetGva = currentGva;
        request->TransferSize = chunk;
        status = VrInvokeProcessRequest(
            request,
            IsWrite ? HV_VTROOT_MODE_PROCESS_WRITE
                    : HV_VTROOT_MODE_PROCESS_READ,
            &result);
        if (!NT_SUCCESS(status) || result != chunk) {
            if (NT_SUCCESS(status)) status = STATUS_PARTIAL_COPY;
            goto cleanup;
        }

        if (!IsWrite) {
            __try {
                RtlCopyMemory(currentBuffer, bounce, (SIZE_T)result);
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                status = GetExceptionCode();
                if (NT_SUCCESS(status)) status = STATUS_ACCESS_VIOLATION;
                goto cleanup;
            }
        }

        if (request->Candidates[0] != request->ResolvedCr3) {
            for (ULONG index = 1; index < request->CandidateCount; ++index) {
                if (request->Candidates[index] == request->ResolvedCr3) {
                    UINT64 first = request->Candidates[0];
                    request->Candidates[0] = request->ResolvedCr3;
                    request->Candidates[index] = first;
                    break;
                }
            }
        }

        totalDone += (SIZE_T)result;
        currentBuffer += result;
        currentGva += result;
        remaining -= (SIZE_T)result;
    }
    status = STATUS_SUCCESS;

cleanup:
    if (anchorsLocked) VrUnlockProcessAnchors(&anchors);
    VrUnlockProcessRange(&targetMdl, &targetLocked);
    if (bounce) ExFreePoolWithTag(bounce, VR_COPY_TAG);
    if (request) ExFreePoolWithTag(request, VR_REQUEST_TAG);
    if (process) ObDereferenceObject(process);
    if (BytesDone) *BytesDone = totalDone;
    return status;
}

// ============================================================
// HvVtRootResolveUserCr3 - PASSIVE-level resolver
// ============================================================
//
// Uses the lifecycle-bound PASSIVE cache; no PID lookup runs in root mode.
NTSTATUS
HvVtRootResolveUserCr3(
    _In_ ULONG TargetPid,
    _Out_ PUINT64 OutCr3)
{
    PEPROCESS process = NULL;
    PVR_PROCESS_REQUEST request = NULL;
    VR_LOCKED_ANCHORS anchors;
    BOOLEAN anchorsLocked = FALSE;
    UINT64 result = 0;
    NTSTATUS status;

    if (!OutCr3) return STATUS_INVALID_PARAMETER;
    *OutCr3 = 0;
    if (TargetPid == 0) return STATUS_INVALID_PARAMETER;
    if (KeGetCurrentIrql() > APC_LEVEL) return STATUS_INVALID_LEVEL;
    if (!g_VtRootEnabled) return STATUS_DEVICE_NOT_READY;

    status = PsLookupProcessByProcessId(
        (HANDLE)(ULONG_PTR)TargetPid, &process);
    if (!NT_SUCCESS(status) || !process) {
        return NT_SUCCESS(status) ? STATUS_INVALID_CID : status;
    }

    request = (PVR_PROCESS_REQUEST)HvAllocateNonPagedZeroed(
        sizeof(*request), VR_REQUEST_TAG);
    if (!request) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto cleanup;
    }

    status = VrBuildProcessRequest(TargetPid, process, request);
    if (!NT_SUCCESS(status)) goto cleanup;
    status = VrLockProcessAnchors(process, request, &anchors);
    if (!NT_SUCCESS(status)) goto cleanup;
    anchorsLocked = TRUE;

    status = VrInvokeProcessRequest(
        request, HV_VTROOT_MODE_PROCESS_RESOLVE, &result);
    if (NT_SUCCESS(status) && result != 0) {
        *OutCr3 = result & VR_PTE_PFN_MASK;
    } else if (NT_SUCCESS(status)) {
        status = STATUS_NOT_FOUND;
    }

cleanup:
    if (anchorsLocked) VrUnlockProcessAnchors(&anchors);
    if (request) ExFreePoolWithTag(request, VR_REQUEST_TAG);
    if (process) ObDereferenceObject(process);
    return status;
}

NTSTATUS
HvVtRootAdoptObservedUserCr3(
    _In_ ULONG TargetPid,
    _In_ UINT64 CandidateCr3)
{
    PEPROCESS process = NULL;
    PVR_PROCESS_REQUEST request = NULL;
    VR_LOCKED_ANCHORS anchors;
    BOOLEAN anchorsLocked = FALSE;
    UINT64 result = 0;
    NTSTATUS status;

    CandidateCr3 &= VR_PTE_PFN_MASK;
    if (TargetPid == 0 || CandidateCr3 == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    if (KeGetCurrentIrql() > APC_LEVEL) return STATUS_INVALID_LEVEL;
    if (!g_VtRootEnabled) return STATUS_DEVICE_NOT_READY;

    status = PsLookupProcessByProcessId(
        (HANDLE)(ULONG_PTR)TargetPid, &process);
    if (!NT_SUCCESS(status) || !process) {
        return NT_SUCCESS(status) ? STATUS_INVALID_CID : status;
    }

    request = (PVR_PROCESS_REQUEST)HvAllocateNonPagedZeroed(
        sizeof(*request), VR_REQUEST_TAG);
    if (!request) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto cleanup;
    }

    status = VrBuildProcessRequest(TargetPid, process, request);
    if (!NT_SUCCESS(status)) goto cleanup;
    request->CandidateCount = 0;
    request->ResolvedCr3 = 0;
    VrAddProcessCandidate(request, CandidateCr3);
    if (request->CandidateCount != 1) {
        status = STATUS_INVALID_ADDRESS_COMPONENT;
        goto cleanup;
    }

    status = VrLockProcessAnchors(process, request, &anchors);
    if (!NT_SUCCESS(status)) goto cleanup;
    anchorsLocked = TRUE;

    status = VrInvokeProcessRequest(
        request, HV_VTROOT_MODE_PROCESS_RESOLVE, &result);
    if (NT_SUCCESS(status) &&
        (result & VR_PTE_PFN_MASK) != CandidateCr3) {
        status = STATUS_NOT_FOUND;
    }

cleanup:
    if (anchorsLocked) VrUnlockProcessAnchors(&anchors);
    if (request) ExFreePoolWithTag(request, VR_REQUEST_TAG);
    if (process) ObDereferenceObject(process);
    return status;
}

// ============================================================
// HvVtRootWalkGvaToHpa - PASSIVE 触发 root-mode walk GVA→HPA
// ============================================================
//
// 复用 VMCALL_PHYS_COPY, mode=4 (HV_VTROOT_MODE_GVA_TO_HPA)。
// 入: R8 = GVA。出: R10 = HPA (4KB leaf) | pageSize (2MB/1GB, status=NOT_SUPPORTED)。
//
// 只支持 4KB 粒度; 命中 2MB/1GB 大页时返 STATUS_NOT_SUPPORTED 让 caller 跳过。
NTSTATUS
HvVtRootWalkGvaToHpa(
    _In_ ULONG TargetPid,
    _In_ UINT64 Gva,
    _Out_ PUINT64 OutHpa,
    _Out_opt_ PUINT64 OutPageSize)
{
    PEPROCESS process = NULL;
    PVR_PROCESS_REQUEST request = NULL;
    PMDL targetMdl = NULL;
    BOOLEAN targetLocked = FALSE;
    VR_LOCKED_ANCHORS anchors;
    BOOLEAN anchorsLocked = FALSE;
    UINT64 result = 0;
    NTSTATUS status;

    if (!OutHpa) return STATUS_INVALID_PARAMETER;
    *OutHpa = 0;
    if (OutPageSize) *OutPageSize = 0;
    if (TargetPid == 0) return STATUS_INVALID_PARAMETER;
    if (KeGetCurrentIrql() > APC_LEVEL) return STATUS_INVALID_LEVEL;
    if (!g_VtRootEnabled) return STATUS_DEVICE_NOT_READY;
    if (Gva < 0x10000ULL || Gva >= 0x800000000000ULL) return STATUS_INVALID_PARAMETER;

    status = PsLookupProcessByProcessId(
        (HANDLE)(ULONG_PTR)TargetPid, &process);
    if (!NT_SUCCESS(status) || !process) {
        return NT_SUCCESS(status) ? STATUS_INVALID_CID : status;
    }

    request = (PVR_PROCESS_REQUEST)HvAllocateNonPagedZeroed(
        sizeof(*request), VR_REQUEST_TAG);
    if (!request) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto cleanup;
    }

    status = VrBuildProcessRequest(TargetPid, process, request);
    if (!NT_SUCCESS(status)) goto cleanup;
    request->TargetGva = Gva;

    status = VrLockProcessRange(
        process, Gva, 1, IoReadAccess, &targetMdl, &targetLocked);
    if (!NT_SUCCESS(status)) goto cleanup;
    status = VrLockProcessAnchors(process, request, &anchors);
    if (!NT_SUCCESS(status)) goto cleanup;
    anchorsLocked = TRUE;

    status = VrInvokeProcessRequest(
        request, HV_VTROOT_MODE_PROCESS_WALK, &result);
    if (NT_SUCCESS(status)) {
        *OutHpa = result;
        if (OutPageSize) *OutPageSize = request->ResultPageSize;
        if (request->ResultPageSize != PAGE_SIZE) {
            status = STATUS_NOT_SUPPORTED;
        }
    }

cleanup:
    if (anchorsLocked) VrUnlockProcessAnchors(&anchors);
    VrUnlockProcessRange(&targetMdl, &targetLocked);
    if (request) ExFreePoolWithTag(request, VR_REQUEST_TAG);
    if (process) ObDereferenceObject(process);
    return status;
}

// ============================================================
// Source-compatible alias for the validated VT-root resolver.
//
NTSTATUS
HvVtRootGetResolvedUserCr3(
    _In_ ULONG TargetPid,
    _Out_ PUINT64 OutCr3)
{
    if (!OutCr3) return STATUS_INVALID_PARAMETER;
    *OutCr3 = 0;
    if (TargetPid == 0) return STATUS_INVALID_PARAMETER;
    if (KeGetCurrentIrql() > APC_LEVEL) return STATUS_INVALID_LEVEL;

    return HvVtRootResolveUserCr3(TargetPid, OutCr3);
}

NTSTATUS
HvVtRootGetPebByPid(
    _In_ ULONG TargetPid,
    _Out_ PUINT64 OutPebVa)
{
    if (!OutPebVa) return STATUS_INVALID_PARAMETER;
    *OutPebVa = 0;
    if (TargetPid == 0) return STATUS_INVALID_PARAMETER;
    if (KeGetCurrentIrql() > APC_LEVEL) return STATUS_INVALID_LEVEL;

    PEPROCESS process = NULL;
    NTSTATUS status = PsLookupProcessByProcessId(
        (HANDLE)(ULONG_PTR)TargetPid, &process);
    if (!NT_SUCCESS(status)) return status;

    UINT64 pebVa = (UINT64)(ULONG_PTR)PsGetProcessPeb(process);
    ObDereferenceObject(process);

    if (pebVa != 0 &&
        (pebVa < 0x10000ULL || pebVa >= 0x800000000000ULL)) {
        return STATUS_INVALID_ADDRESS_COMPONENT;
    }

    *OutPebVa = pebVa;
    return STATUS_SUCCESS;
}

// ============================================================
// PASSIVE-level 跨页包装
// ============================================================

NTSTATUS
HvVtRootCopyWithCr3(
    _In_ UINT64 TargetCr3,
    _In_ UINT64 Gva,
    _Inout_updates_bytes_(Size) PVOID Buffer,
    _In_ SIZE_T Size,
    _In_ BOOLEAN IsWrite,
    _Out_opt_ PSIZE_T BytesDone
)
{
    if (BytesDone) *BytesDone = 0;
    if (!Buffer || Size == 0) return STATUS_INVALID_PARAMETER;
    if (KeGetCurrentIrql() > APC_LEVEL) return STATUS_INVALID_LEVEL;
    if (!g_VtRootEnabled) return STATUS_DEVICE_NOT_READY;
    TargetCr3 &= VR_PTE_PFN_MASK;
    if (!HvPhysIsRamRangeRootSafe(TargetCr3, PAGE_SIZE)) {
        return STATUS_INVALID_PARAMETER;
    }

    ULONG dir = IsWrite ? HV_VTROOT_DIR_WRITE : HV_VTROOT_DIR_READ;

    PUCHAR bounce = (PUCHAR)HvAllocateNonPaged(PAGE_SIZE, VR_COPY_TAG);
    if (!bounce) return STATUS_INSUFFICIENT_RESOURCES;

    SIZE_T totalDone = 0;
    PUCHAR userBuf = (PUCHAR)Buffer;
    UINT64 curGva = Gva;
    SIZE_T remaining = Size;

    while (remaining > 0) {
        SIZE_T inPageOff = (SIZE_T)(curGva & 0xFFF);
        SIZE_T inPageLeft = PAGE_SIZE - inPageOff;
        SIZE_T chunk = (remaining < inPageLeft) ? remaining : inPageLeft;

        SIZE_T thisDone = 0;
        NTSTATUS vs;
        if (IsWrite) {
            __try {
                RtlCopyMemory(bounce, userBuf, chunk);
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                vs = GetExceptionCode();
                ExFreePoolWithTag(bounce, VR_COPY_TAG);
                if (BytesDone) *BytesDone = totalDone;
                return NT_SUCCESS(vs) ? STATUS_ACCESS_VIOLATION : vs;
            }
        }

        vs = HvVtRootInvokeService(
            TargetCr3, curGva, bounce, chunk, dir, &thisDone);

        if (!IsWrite && thisDone > 0) {
            __try {
                RtlCopyMemory(userBuf, bounce, thisDone);
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                NTSTATUS copyStatus = GetExceptionCode();
                ExFreePoolWithTag(bounce, VR_COPY_TAG);
                if (BytesDone) *BytesDone = totalDone;
                return NT_SUCCESS(copyStatus) ? STATUS_ACCESS_VIOLATION : copyStatus;
            }
        }

        totalDone += thisDone;
        if (!NT_SUCCESS(vs) || thisDone == 0) {
            ExFreePoolWithTag(bounce, VR_COPY_TAG);
            if (BytesDone) *BytesDone = totalDone;
            return NT_SUCCESS(vs) ? STATUS_NOT_FOUND : vs;
        }

        userBuf   += thisDone;
        curGva    += thisDone;
        remaining -= thisDone;
    }

    ExFreePoolWithTag(bounce, VR_COPY_TAG);
    if (BytesDone) *BytesDone = totalDone;
    return STATUS_SUCCESS;
}

NTSTATUS
HvVtRootCopy(
    _In_ ULONG TargetPid,
    _In_ UINT64 Gva,
    _Inout_updates_bytes_(Size) PVOID Buffer,
    _In_ SIZE_T Size,
    _In_ BOOLEAN IsWrite,
    _Out_opt_ PSIZE_T BytesDone
)
{
    if (BytesDone) *BytesDone = 0;
    if (!Buffer || Size == 0) return STATUS_INVALID_PARAMETER;
    if (KeGetCurrentIrql() > APC_LEVEL) return STATUS_INVALID_LEVEL;
    if (!g_VtRootEnabled) return STATUS_DEVICE_NOT_READY;

    return HvVtRootCopyByPid(
        TargetPid, Gva, Buffer, Size, IsWrite, BytesDone);
}
