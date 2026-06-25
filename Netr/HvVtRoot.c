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
#include "HvCompat.h"
#include "HvNested.h"   // HvNestedGetCurrentVcpu (root mode)
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

#define VR_PML4_INDEX(va)   (((UINT64)(va) >> 39) & 0x1FF)
#define VR_PDPT_INDEX(va)   (((UINT64)(va) >> 30) & 0x1FF)
#define VR_PD_INDEX(va)     (((UINT64)(va) >> 21) & 0x1FF)
#define VR_PT_INDEX(va)     (((UINT64)(va) >> 12) & 0x1FF)

#define VR_TAG              'rVvH'

// 私有 PT entry 标志: P|RW|NX|Global (内核数据,绝不可执行)
#define VR_LEAF_FLAGS       (VR_PTE_PRESENT | VR_PTE_RW | VR_PTE_NX | VR_PTE_GLOBAL)
// 中间表 entry 标志: P|RW|NX
#define VR_INTR_FLAGS       (VR_PTE_PRESENT | VR_PTE_RW | VR_PTE_NX)

// ============================================================
// 全局
// ============================================================

BOOLEAN g_VtRootEnabled = FALSE;

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

// ============================================================
// PID → resolved user CR3 cache (2026-06-17)
// ============================================================
//
// HvVtRootRootCopyByPid 在 root mode 收集 24 个候选 CR3, 用 MZ 锚点验证,
// 第一个验证通过且 walk 成功的 CR3 就是真 user CR3。这条信息**只在 root
// mode 知道**,PASSIVE 层(如 HvCloak)拿不到。
//
// 现在加一层 cache: walk 成功后 root mode 写 (pid, cr3) 到这张表,PASSIVE
// 层调 HvVtRootGetResolvedUserCr3(pid, &cr3) 读出来。Cloak 用这个 CR3 走
// EnumWorkingSet 就能拿到真 user-half PFN, 不再依赖 KeStackAttachProcess +
// __readcr3() (KVAS 下永远拿到 shadow CR3)。
//
// 256 槽,按 PID 直接哈希 (pid % 256)。冲突时新值覆盖旧值 —— 反正进程退出
// 后 PID 会被复用,cache 中的 stale 项也会被新进程覆盖,代价可接受。
//
// 读写都是单 64-bit InterlockedExchange / InterlockedCompareExchange,无锁。

#define VR_CR3_CACHE_SLOTS  256
#define VR_CR3_CACHE_MASK   (VR_CR3_CACHE_SLOTS - 1)

typedef struct _VR_CR3_CACHE_ENTRY {
    volatile UINT64 PidAndCr3;   // 高 16 bit = PID, 低 48 bit = CR3 >> 12 (PFN)
                                 // 0 = 空槽 (PID=0 不会进缓存)
} VR_CR3_CACHE_ENTRY;

static VR_CR3_CACHE_ENTRY g_VrPidCr3Cache[VR_CR3_CACHE_SLOTS] = { 0 };

// PID + CR3 → packed 64-bit. PID 限 16-bit (PID 一般 < 2^20, 我们截高 16-bit
// 仍能区分大多数; 不行的话 PID=0xFFFFF 仍会命中, 偶发 cache miss 不致命)。
static __forceinline UINT64
VrPackPidCr3(_In_ ULONG Pid, _In_ UINT64 Cr3)
{
    UINT64 pfn = (Cr3 >> 12) & 0xFFFFFFFFFFFFULL;   // 48-bit PFN
    UINT64 pidHi = ((UINT64)(Pid & 0xFFFF)) << 48;
    return pidHi | pfn;
}

static __forceinline VOID
VrUnpackPidCr3(_In_ UINT64 Packed, _Out_ PULONG Pid, _Out_ PUINT64 Cr3)
{
    *Pid = (ULONG)((Packed >> 48) & 0xFFFF);
    *Cr3 = (Packed & 0xFFFFFFFFFFFFULL) << 12;
}

// Root-mode 写入:成功 walk 后调。无锁单 64-bit 写。
static __forceinline VOID
VrCacheSet(_In_ ULONG Pid, _In_ UINT64 Cr3)
{
    if (Pid == 0 || Cr3 == 0) return;
    ULONG slot = Pid & VR_CR3_CACHE_MASK;
    UINT64 packed = VrPackPidCr3(Pid, Cr3);
    InterlockedExchange64((volatile LONG64*)&g_VrPidCr3Cache[slot].PidAndCr3,
                          (LONG64)packed);
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

NTSTATUS HvVtRootInitializeAll(VOID)
{
    g_VtRootEnabled = FALSE;

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
    UINT64 hostCr3 = __readcr3() & VR_PTE_PFN_MASK;
    PHYSICAL_ADDRESS pml4Pa;
    pml4Pa.QuadPart = (LONGLONG)hostCr3;

    volatile UINT64* pml4Va = NULL;
    BOOLEAN needUnmap = FALSE;

    // 路径 a: MmGetVirtualForPhysical
    PVOID gvfp = MmGetVirtualForPhysical(pml4Pa);
    if (gvfp) {
        pml4Va = (volatile UINT64*)gvfp;
        DbgPrint("[VtRoot V2] PML4 KVA via MmGetVirtualForPhysical @ %p (hostCr3=0x%llX)\n",
                 pml4Va, hostCr3);
    } else {
        // 路径 b/c: MmMapIoSpace 兜底
        pml4Va = (volatile UINT64*)MmMapIoSpace(pml4Pa, PAGE_SIZE, MmCached);
        if (pml4Va) {
            needUnmap = TRUE;
            DbgPrint("[VtRoot V2] PML4 mapped via MmMapIoSpace(MmCached) @ %p\n", pml4Va);
        } else {
            pml4Va = (volatile UINT64*)MmMapIoSpace(pml4Pa, PAGE_SIZE, MmNonCached);
            if (pml4Va) {
                needUnmap = TRUE;
                DbgPrint("[VtRoot V2] PML4 mapped via MmMapIoSpace(MmNonCached) @ %p\n", pml4Va);
            }
        }
    }

    if (!pml4Va) {
        DbgPrint("[VtRoot V2] all PML4 mapping paths failed (hostCr3=0x%llX)\n", hostCr3);
        s = STATUS_INSUFFICIENT_RESOURCES;
        goto fail;
    }

    ULONG slot = 0;
    s = VrFindFreePml4Slot(pml4Va, &slot);
    if (!NT_SUCCESS(s)) {
        DbgPrint("[VtRoot V2] no free PML4 slot in kernel half\n");
        if (needUnmap) MmUnmapIoSpace((PVOID)pml4Va, PAGE_SIZE);
        goto fail;
    }

    // 6) 原子安装 PML4 entry → PDPT
    UINT64 pml4Entry = (g_VrSharedPdptPa & VR_PTE_PFN_MASK) | VR_INTR_FLAGS;
    InterlockedExchange64((LONG64*)&pml4Va[slot], (LONG64)pml4Entry);
    if (needUnmap) MmUnmapIoSpace((PVOID)pml4Va, PAGE_SIZE);

    g_VrSharedPml4Index = slot;
    g_VrBaseVa = VrSlotToBaseVa(slot);

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
    return s;
}

// ============================================================
// HvVtRootCleanupAll
// ============================================================

VOID HvVtRootCleanupAll(VOID)
{
    g_VtRootEnabled = FALSE;

    // 1) 原子零 PML4 entry (前置条件:slot != 0 表示安装过)
    if (g_VrSharedPml4Index >= 256 && g_VrSharedPml4Index < 512) {
        UINT64 hostCr3 = __readcr3() & VR_PTE_PFN_MASK;
        PHYSICAL_ADDRESS pml4Pa;
        pml4Pa.QuadPart = (LONGLONG)hostCr3;
        volatile UINT64* pml4Va = (volatile UINT64*)MmMapIoSpace(pml4Pa, PAGE_SIZE, MmCached);
        if (pml4Va) {
            InterlockedExchange64((LONG64*)&pml4Va[g_VrSharedPml4Index], 0);
            MmUnmapIoSpace((PVOID)pml4Va, PAGE_SIZE);
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
    VrFreeIfAllocated(&g_VrBackingVa);
    VrFreeIfAllocated(&g_VrSharedPtVa);
    VrFreeIfAllocated(&g_VrSharedPdVa);
    VrFreeIfAllocated(&g_VrSharedPdptVa);
    g_VrBackingPa = g_VrSharedPtPa = g_VrSharedPdPa = g_VrSharedPdptPa = 0;
    g_VrBaseVa = 0;
    g_VrSharedPml4Index = 0;

    DbgPrint("[VtRoot V2] cleaned up\n");
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
    if (cr3Base == 0 || cr3Base < 0x1000ULL || cr3Base >= 0x10000000000ULL) {
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
    #define VR_PA_SANE(pa) \
        ((pa) != 0 && (pa) >= 0x1000ULL && (pa) < 0x10000000000ULL && \
         !((pa) >= 0xC0000000ULL && (pa) < 0x100000000ULL))

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
    if (dataPageBase == 0 || dataPageBase < 0x1000ULL ||
        dataPageBase >= 0x10000000000ULL ||
        (dataPageBase >= 0xC0000000ULL && dataPageBase < 0x100000000ULL)) {
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
        for (SIZE_T i = 0; i < chunk; i++) src[i] = KernelBuf[i];
    } else {
        for (SIZE_T i = 0; i < chunk; i++) KernelBuf[i] = src[i];
    }

    *BytesDone = chunk;
    return STATUS_SUCCESS;
}

/*
 * VrRootValidateCr3OwnsProcess —— 在 root mode 验证 candidate CR3 是不是真属于
 * eproc 进程, 防止 multi-candidate 路径(尤其 snoop ring 含其他进程 CR3)
 * "假成功"读到错的 PA。
 *
 * 镜像 HvPhysValidateCr3OwnsProcess (HvPhysAccess.c) 的双重 MZ 锚点算法:
 *   1. 取 eproc.EPROCESS+PebOff = PEB user VA, 必须在 user 半空间
 *   2. 用 candidate CR3 走 PEB, 读 PEB+0x10 = ImageBaseAddress
 *   3. ImageBase 必须 4K 对齐 + user 半空间
 *   4. 用 candidate CR3 走 ImageBase, 读首 2 字节, 必须 'MZ' (0x5A4D)
 *
 * 假阳性: 两个无关进程同时在 pebGva 处都有有效 PEB + ImageBase 又能 walk
 * + 起首 MZ —— 实际不可能。
 *
 * 返回:
 *   STATUS_SUCCESS         — candidate 几乎确定属于 eproc
 *   STATUS_NOT_SUPPORTED   — eproc 没 PEB (System / Idle / Minimal),
 *                            调用方按老语义接受 (无法验证 → 仍尝试)
 *   STATUS_NOT_FOUND       — candidate 不属于 eproc, 跳到下一个
 *   其他                   — walk 出错, 跳到下一个
 */
static NTSTATUS
VrRootValidateCr3OwnsProcess(
    _Inout_ PVCPU_DATA Vcpu,
    _In_ PEPROCESS Eproc,
    _In_ UINT64 CandidateCr3)
{
    // 1) 取 PEB user VA
    if (g_HvPhysRootCtx.PebOff == 0) {
        return STATUS_NOT_SUPPORTED;
    }
    UINT64 pebGva = *(UINT64*)((PUCHAR)Eproc + g_HvPhysRootCtx.PebOff);
    if (pebGva == 0) {
        return STATUS_NOT_SUPPORTED;  // System / Idle / Minimal
    }
    if (pebGva < 0x10000ULL || pebGva >= 0x800000000000ULL) {
        return STATUS_NOT_SUPPORTED;
    }

    // PEB.ImageBaseAddress 在 PEB+0x10, 必须不跨页 (PEB 极少跨页)
    SIZE_T inPageOff = (SIZE_T)(pebGva & 0xFFFULL);
    if (inPageOff + 0x18 > PAGE_SIZE) {
        return STATUS_NOT_SUPPORTED;
    }

    // 2) 用 candidate CR3 walk PEB+0x10, 读 8 字节 ImageBase
    UINT64 imageBase = 0;
    SIZE_T doneIb = 0;
    NTSTATUS s = VrRootWalkAndCopyOnePage(
        Vcpu, CandidateCr3, pebGva + 0x10,
        (PUCHAR)&imageBase, sizeof(imageBase),
        FALSE,  // read
        TRUE,   // quiet
        &doneIb);
    if (!NT_SUCCESS(s) || doneIb != sizeof(imageBase)) {
        return STATUS_NOT_FOUND;
    }

    // 3) ImageBase sanity
    if (imageBase < 0x10000ULL || imageBase >= 0x800000000000ULL) {
        return STATUS_NOT_FOUND;
    }
    if (imageBase & 0xFFFULL) {
        return STATUS_NOT_FOUND;
    }

    // 4) 用 candidate CR3 walk ImageBase, 读首 2 字节 (MZ magic)
    USHORT magic = 0;
    SIZE_T doneMz = 0;
    s = VrRootWalkAndCopyOnePage(
        Vcpu, CandidateCr3, imageBase,
        (PUCHAR)&magic, sizeof(magic),
        FALSE,  // read
        TRUE,   // quiet
        &doneMz);
    if (!NT_SUCCESS(s) || doneMz != sizeof(magic)) {
        return STATUS_NOT_FOUND;
    }

    if (magic != 0x5A4D) {  // 'MZ'
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
    if (!KernelBuf || Size == 0 || Size > PAGE_SIZE) {
        return STATUS_INVALID_PARAMETER;
    }
    if (((TargetGva & 0xFFF) + Size) > PAGE_SIZE) {
        return STATUS_INVALID_PARAMETER;
    }

    NTSTATUS status = VrRootWalkAndCopyOnePage(
        Vcpu, TargetCr3, TargetGva, KernelBuf, Size, IsWrite,
        FALSE,  // 单 CR3 路径, 保留诊断日志
        BytesDone);

    VrRestoreToBacking(Vcpu);
    return status;
}

// ============================================================
// Root mode by-PID copy (Phase C)
// ============================================================
//
// 设计:把 PASSIVE-level 的 EPROCESS 链表遍历 + CR3 候选收集 + walk-validation
// 全部搬进 root mode handler。Hot path (PASSIVE) 只传 PID,完全不调
// Mm* / Ps* / Ob*。
//
// 反作弊视角:
//   - PsLookupProcessByProcessId 被替换为"沿 PsInitialSystemProcess 的
//     ActiveProcessLinks 链表步进", 完全是内存读, 不引用 OB_TYPE 系统结构,
//     无 reference count 变化, ETWTI 看不到任何 Ps* / Ob* 调用
//   - HvPhysGetProcessCr3 的 MmMapIoSpace 数 PML4E 启发式被替换为"挨个
//     候选 CR3 直接 walk 目标 GVA", 全部用 VrRedirectScratch + invlpg
//   - CR3 snoop ring 在 root mode 读 (HvCr3SnoopSnapshot 只读 ring buffer)
//
// 单页约束: ≤ 4KB, 调用方按页切分。

#define HV_VR_MAX_CR3_CANDIDATES   24

/*
 * VrRootResolvePidToEprocess —— 沿 PsActiveProcessHead 链表找匹配 PID 的
 * EPROCESS。
 *
 * Root mode 安全:仅做指针解引用 + LIST_ENTRY 步进, 无任何 NT API。
 * EPROCESS 在 non-paged kernel pool, host CR3 直接可访问。
 *
 * UAF 保护:4096 步上限防死链。链表本身无锁, 其他 CPU 可能在 guest mode 修改,
 * 但 root mode IRQ-off 期间链表结构不会破坏 (插入/删除是 atomic LIST_ENTRY
 * 操作), 最坏情况是看到旧 snapshot, walk 不到 PID 返回 NULL。
 */
static PEPROCESS
VrRootResolvePidToEprocess(_In_ ULONG TargetPid)
{
    if (!g_HvPhysRootCtx.Initialized) return NULL;

    PEPROCESS systemEproc = (PEPROCESS)g_HvPhysRootCtx.PsInitialSystemProcess;
    if (!systemEproc) return NULL;

    ULONG linksOff = g_HvPhysRootCtx.ActiveLinksOff;
    ULONG pidOff   = g_HvPhysRootCtx.PidOff;

    // ----- Fast path: cache hit (优化 #2)
    // 单 32-bit + 单 64-bit volatile load, 多核 race 最坏看到 stale 配对,
    // 校验阶段 (再读 cached EPROCESS 的 PID) 失配后退回 walk。
    {
        ULONG  cachedPid   = g_HvPhysRootCtx.CachedPid;
        UINT64 cachedEproc = g_HvPhysRootCtx.CachedEproc;
        if (cachedPid == TargetPid && cachedEproc != 0) {
            ULONG_PTR livePid = *(volatile ULONG_PTR*)
                ((PUCHAR)(ULONG_PTR)cachedEproc + pidOff);
            if (livePid == TargetPid) {
                return (PEPROCESS)(ULONG_PTR)cachedEproc;
            }
            // 验证失败 (进程退出 / pool 复用 / cache 撕裂) → walk
        }
    }

    // ----- Slow path: walk ActiveProcessLinks
    PLIST_ENTRY head = (PLIST_ENTRY)((PUCHAR)systemEproc + linksOff);

    // 先校验 head 自身 PID = 4 (System)。Walk 从 head->Flink 开始。
    {
        ULONG_PTR sysPid = *(ULONG_PTR*)((PUCHAR)systemEproc + pidOff);
        if (sysPid == TargetPid) {
            // 更新缓存: 先写 Eproc 再写 Pid, 保证其他核读 Pid 时 Eproc 已就绪
            g_HvPhysRootCtx.CachedEproc = (UINT64)(ULONG_PTR)systemEproc;
            g_HvPhysRootCtx.CachedPid   = TargetPid;
            return systemEproc;
        }
    }

    PLIST_ENTRY cur = head->Flink;
    for (ULONG i = 0; i < 4096; i++) {
        if (!cur || cur == head) break;

        PUCHAR ep = (PUCHAR)cur - linksOff;
        ULONG_PTR pid = *(ULONG_PTR*)(ep + pidOff);
        if (pid == TargetPid) {
            g_HvPhysRootCtx.CachedEproc = (UINT64)(ULONG_PTR)ep;
            g_HvPhysRootCtx.CachedPid   = TargetPid;
            return (PEPROCESS)ep;
        }

        cur = cur->Flink;
    }
    return NULL;
}

/*
 * VrRootCollectCr3Candidates —— 从 EPROCESS 提取候选 CR3, 追加 snoop ring。
 *
 * 候选来源(按优先级排序):
 *   1) EPROCESS + UserDtbOff (KVAS 已探到时, 真 user CR3)
 *   2) EPROCESS + KnownUserDtbOffs[8] (Win 各版本观察到的 UserDTB 偏移)
 *   3) EPROCESS + DtbOff (KPROCESS.DirectoryTableBase, 可能是 shadow)
 *   4) CR3 snoop ring (硬件层观察到的真 CR3)
 *
 * 去重 + 上限 HV_VR_MAX_CR3_CANDIDATES。
 */
static ULONG
VrRootCollectCr3Candidates(
    _In_ PEPROCESS Eproc,
    _Out_writes_to_(HV_VR_MAX_CR3_CANDIDATES, return) UINT64* Candidates)
{
    ULONG n = 0;

    #define VR_TRY_ADD_CR3(val) do { \
        UINT64 _v = (val) & 0x000FFFFFFFFFF000ULL; \
        if (_v != 0 && _v >= 0x100000ULL && _v < 0x10000000000ULL) { \
            BOOLEAN _dup = FALSE; \
            for (ULONG _i = 0; _i < n; _i++) { \
                if (Candidates[_i] == _v) { _dup = TRUE; break; } \
            } \
            if (!_dup && n < HV_VR_MAX_CR3_CANDIDATES) { \
                Candidates[n++] = _v; \
            } \
        } \
    } while (0)

    // 1) UserDTB 已探到的偏移
    if (g_HvPhysRootCtx.UserDtbOff != 0) {
        UINT64 cr3 = *(UINT64*)((PUCHAR)Eproc + g_HvPhysRootCtx.UserDtbOff);
        VR_TRY_ADD_CR3(cr3);
    }

    // 2) Known UserDTB 备选偏移表 (Win 版本各异)
    for (ULONG i = 0; i < g_HvPhysRootCtx.KnownUserDtbOffCount; i++) {
        UINT64 off = g_HvPhysRootCtx.KnownUserDtbOffs[i];
        UINT64 cr3 = *(UINT64*)((PUCHAR)Eproc + off);
        VR_TRY_ADD_CR3(cr3);
    }

    // 3) KPROCESS.DirectoryTableBase (可能是 shadow, 也可能就是 user CR3)
    if (g_HvPhysRootCtx.DtbOff != 0) {
        UINT64 cr3 = *(UINT64*)((PUCHAR)Eproc + g_HvPhysRootCtx.DtbOff);
        VR_TRY_ADD_CR3(cr3);
    }

    // 4) CR3 snoop ring (硬件层 VMEXIT 时观察的真 user CR3)
    {
        UINT64 snoopCr3s[HV_CR3_SNOOP_RING_SIZE];
        ULONG snoopCount = HvCr3SnoopSnapshot(snoopCr3s, HV_CR3_SNOOP_RING_SIZE);
        for (ULONG i = 0; i < snoopCount; i++) {
            VR_TRY_ADD_CR3(snoopCr3s[i]);
        }
    }

    #undef VR_TRY_ADD_CR3
    return n;
}

NTSTATUS
HvVtRootRootCopyByPid(
    _Inout_ PVCPU_DATA Vcpu,
    _In_ ULONG TargetPid,
    _In_ UINT64 TargetGva,
    _Inout_updates_bytes_(Size) PUCHAR KernelBuf,
    _In_ SIZE_T Size,
    _In_ BOOLEAN IsWrite,
    _Out_ PSIZE_T BytesDone)
{
    if (BytesDone) *BytesDone = 0;

    if (!Vcpu || !Vcpu->VtRootGadget.Initialized) {
        return STATUS_DEVICE_NOT_READY;
    }
    if (!KernelBuf || Size == 0 || Size > PAGE_SIZE) {
        return STATUS_INVALID_PARAMETER;
    }
    if (((TargetGva & 0xFFF) + Size) > PAGE_SIZE) {
        return STATUS_INVALID_PARAMETER;
    }
    if (TargetPid == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!g_HvPhysRootCtx.Initialized) {
        return STATUS_DEVICE_NOT_READY;
    }

    // 1) PID → EPROCESS (root mode, 链表 walk, 无 Ps*/Ob*)
    PEPROCESS eproc = VrRootResolvePidToEprocess(TargetPid);
    if (!eproc) {
        return STATUS_NOT_FOUND;
    }

    // 2) 收集 CR3 候选
    UINT64 candidates[HV_VR_MAX_CR3_CANDIDATES];
    ULONG nCand = VrRootCollectCr3Candidates(eproc, candidates);
    if (nCand == 0) {
        return STATUS_NOT_FOUND;
    }

    // 3) 挨个 CR3 尝试 walk + 拷贝。第一个**通过 MZ 锚点验证**且 walk 成功的 wins。
    //
    // 2026-06-16: 加 MZ 锚点验证 (镜像 HvPhysValidateCr3OwnsProcess), 防止
    // snoop ring 含的其他进程 CR3 在目标 GVA 上恰好"假成功 walk" → 读到错的数据。
    // 验证失败的 candidate 跳过, 没有任何拷贝发生, 不污染 KernelBuf。
    //
    // System / Idle / Minimal 进程没 PEB (validate 返 NOT_SUPPORTED), 退化为
    // 老行为 (直接尝试拷贝, 第一个 thisDone>0 wins) —— 维持对内核进程内存兼容。
    NTSTATUS lastStatus = STATUS_NOT_FOUND;
    BOOLEAN canValidate = (g_HvPhysRootCtx.PebOff != 0);
    BOOLEAN sawNotSupported = FALSE;

    for (ULONG i = 0; i < nCand; i++) {
        // ---- MZ 锚点验证 (双重 walk) ----
        if (canValidate) {
            NTSTATUS vs = VrRootValidateCr3OwnsProcess(Vcpu, eproc, candidates[i]);
            if (vs == STATUS_NOT_SUPPORTED) {
                // eproc 没 PEB (System / Minimal) — 整个验证失效, 切兼容路径
                sawNotSupported = TRUE;
            } else if (!NT_SUCCESS(vs)) {
                // candidate 不属于该进程, 跳过 (不拷贝)
                lastStatus = vs;
                continue;
            }
            // 验证通过 (或没 PEB 时按兼容路径走) → 落到 walk+copy
        }

        SIZE_T thisDone = 0;
        NTSTATUS s = VrRootWalkAndCopyOnePage(
            Vcpu, candidates[i], TargetGva, KernelBuf, Size, IsWrite,
            TRUE,  // Quiet: multi-candidate, 不打 walk-fail 日志
            &thisDone);

        if (NT_SUCCESS(s) && thisDone > 0) {
            // 找到正确 CR3 — 完成拷贝。同时把 (PID, CR3) 写进 cache, 让
            // PASSIVE 层 (HvCloak) 能直接拿到真 user CR3, 不再依赖 KVAS 下
            // 永远拿到 shadow CR3 的 __readcr3() 路径。
            VrCacheSet(TargetPid, candidates[i]);
            *BytesDone = thisDone;
            VrRestoreToBacking(Vcpu);
            return STATUS_SUCCESS;
        }
        lastStatus = s;
    }

    UNREFERENCED_PARAMETER(sawNotSupported);
    VrRestoreToBacking(Vcpu);
    return lastStatus;
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
VrRootWalkOnly(
    _Inout_ PVCPU_DATA Vcpu,
    _In_ UINT64 TargetCr3,
    _In_ UINT64 TargetGva,
    _Out_ PUINT64 OutHpa,
    _Out_ PUINT64 OutPageSize)
{
    *OutHpa = 0;
    *OutPageSize = 0;

    if (TargetGva < 0x10000ULL || TargetGva >= 0x800000000000ULL) {
        return STATUS_INVALID_PARAMETER;
    }

    PUCHAR scratch = (PUCHAR)Vcpu->VtRootGadget.ScratchVa;
    UINT64 cr3Base = TargetCr3 & VR_PTE_PFN_MASK;
    if (cr3Base == 0 || cr3Base < 0x1000ULL || cr3Base >= 0x10000000000ULL) {
        return STATUS_INVALID_PARAMETER;
    }

    ULONG pml4i = (ULONG)VR_PML4_INDEX(TargetGva);
    ULONG pdpti = (ULONG)VR_PDPT_INDEX(TargetGva);
    ULONG pdi   = (ULONG)VR_PD_INDEX(TargetGva);
    ULONG pti   = (ULONG)VR_PT_INDEX(TargetGva);

    #define VR_WO_PA_SANE(pa) \
        ((pa) != 0 && (pa) >= 0x1000ULL && (pa) < 0x10000000000ULL && \
         !((pa) >= 0xC0000000ULL && (pa) < 0x100000000ULL))

    VrRedirectScratch(Vcpu, cr3Base);
    UINT64 pml4e = ((volatile UINT64*)scratch)[pml4i];
    if (!(pml4e & VR_PTE_PRESENT)) return STATUS_INVALID_ADDRESS_COMPONENT;
    UINT64 pdptPa = pml4e & VR_PTE_PFN_MASK;
    if (!VR_WO_PA_SANE(pdptPa)) return STATUS_INVALID_ADDRESS_COMPONENT;

    VrRedirectScratch(Vcpu, pdptPa);
    UINT64 pdpte = ((volatile UINT64*)scratch)[pdpti];
    if (!(pdpte & VR_PTE_PRESENT)) return STATUS_INVALID_ADDRESS_COMPONENT;

    if (pdpte & VR_PTE_PS) {
        UINT64 leaf = (pdpte & 0x000FFFFFC0000000ULL) | (TargetGva & 0x3FFFFFFFULL);
        *OutHpa = leaf;
        *OutPageSize = 0x40000000ULL;
        return STATUS_SUCCESS;
    }

    UINT64 pdPa = pdpte & VR_PTE_PFN_MASK;
    if (!VR_WO_PA_SANE(pdPa)) return STATUS_INVALID_ADDRESS_COMPONENT;
    VrRedirectScratch(Vcpu, pdPa);
    UINT64 pde = ((volatile UINT64*)scratch)[pdi];
    if (!(pde & VR_PTE_PRESENT)) return STATUS_INVALID_ADDRESS_COMPONENT;

    if (pde & VR_PTE_PS) {
        UINT64 leaf = (pde & 0x000FFFFFFFE00000ULL) | (TargetGva & 0x1FFFFFULL);
        *OutHpa = leaf;
        *OutPageSize = 0x200000ULL;
        return STATUS_SUCCESS;
    }

    UINT64 ptPa = pde & VR_PTE_PFN_MASK;
    if (!VR_WO_PA_SANE(ptPa)) return STATUS_INVALID_ADDRESS_COMPONENT;
    VrRedirectScratch(Vcpu, ptPa);
    UINT64 pte = ((volatile UINT64*)scratch)[pti];
    if (!(pte & VR_PTE_PRESENT)) return STATUS_NOT_FOUND;

    UINT64 leaf = (pte & VR_PTE_PFN_MASK) | (TargetGva & 0xFFFULL);
    if (!VR_WO_PA_SANE(leaf & ~0xFFFULL)) return STATUS_INVALID_ADDRESS_COMPONENT;

    *OutHpa = leaf;
    *OutPageSize = PAGE_SIZE;

    #undef VR_WO_PA_SANE
    return STATUS_SUCCESS;
}

// ============================================================
// RootResolveUserCr3 - 用 24 候选+MZ 验证选真 user CR3 (root mode)
// ============================================================
NTSTATUS
HvVtRootRootResolveUserCr3(
    _In_ ULONG TargetPid,
    _Out_ PUINT64 OutCr3)
{
    *OutCr3 = 0;
    if (TargetPid == 0) return STATUS_INVALID_PARAMETER;
    if (!g_HvPhysRootCtx.Initialized) return STATUS_DEVICE_NOT_READY;

    PVCPU_DATA vcpu = HvNestedGetCurrentVcpu();
    if (!vcpu || !vcpu->VtRootGadget.Initialized) return STATUS_DEVICE_NOT_READY;

    PEPROCESS eproc = VrRootResolvePidToEprocess(TargetPid);
    if (!eproc) return STATUS_NOT_FOUND;

    UINT64 candidates[HV_VR_MAX_CR3_CANDIDATES];
    ULONG nCand = VrRootCollectCr3Candidates(eproc, candidates);
    if (nCand == 0) return STATUS_NOT_FOUND;

    BOOLEAN canValidate = (g_HvPhysRootCtx.PebOff != 0);
    NTSTATUS lastStatus = STATUS_NOT_FOUND;

    for (ULONG i = 0; i < nCand; i++) {
        if (canValidate) {
            NTSTATUS vs = VrRootValidateCr3OwnsProcess(vcpu, eproc, candidates[i]);
            if (vs == STATUS_NOT_SUPPORTED) {
                // 没 PEB 进程 - 跳过, 不参与 cloak
                continue;
            }
            if (!NT_SUCCESS(vs)) {
                lastStatus = vs;
                continue;
            }
        }
        // MZ 验证通过 = 真 user CR3
        VrCacheSet(TargetPid, candidates[i]);
        *OutCr3 = candidates[i];
        VrRestoreToBacking(vcpu);
        return STATUS_SUCCESS;
    }

    VrRestoreToBacking(vcpu);
    return lastStatus;
}

// ============================================================
// RootWalkGvaToHpa - 找真 user CR3 + walk GVA → HPA (root mode)
// ============================================================
NTSTATUS
HvVtRootRootWalkGvaToHpa(
    _Inout_ PVCPU_DATA Vcpu,
    _In_ ULONG TargetPid,
    _In_ UINT64 Gva,
    _Out_ PUINT64 OutHpa,
    _Out_ PUINT64 OutPageSize)
{
    *OutHpa = 0;
    *OutPageSize = 0;

    if (!Vcpu || !Vcpu->VtRootGadget.Initialized) return STATUS_DEVICE_NOT_READY;
    if (TargetPid == 0) return STATUS_INVALID_PARAMETER;
    if (Gva < 0x10000ULL || Gva >= 0x800000000000ULL) return STATUS_INVALID_PARAMETER;
    if (!g_HvPhysRootCtx.Initialized) return STATUS_DEVICE_NOT_READY;

    // 优先从 cache 取真 user CR3 (前面 ResolveUserCr3 一定写过)
    UINT64 cr3 = 0;
    NTSTATUS cs = HvVtRootGetResolvedUserCr3(TargetPid, &cr3);

    if (NT_SUCCESS(cs) && cr3 != 0) {
        // Cache 有 — 直接 walk
        NTSTATUS ws = VrRootWalkOnly(Vcpu, cr3, Gva, OutHpa, OutPageSize);
        VrRestoreToBacking(Vcpu);
        if (NT_SUCCESS(ws)) return STATUS_SUCCESS;
        // Cache CR3 走不通 (working set 变了?) - 继续走候选
    }

    // Cache 没有 / 失效 — 走 24 候选
    PEPROCESS eproc = VrRootResolvePidToEprocess(TargetPid);
    if (!eproc) { VrRestoreToBacking(Vcpu); return STATUS_NOT_FOUND; }

    UINT64 candidates[HV_VR_MAX_CR3_CANDIDATES];
    ULONG nCand = VrRootCollectCr3Candidates(eproc, candidates);
    if (nCand == 0) { VrRestoreToBacking(Vcpu); return STATUS_NOT_FOUND; }

    BOOLEAN canValidate = (g_HvPhysRootCtx.PebOff != 0);
    NTSTATUS lastStatus = STATUS_NOT_FOUND;

    for (ULONG i = 0; i < nCand; i++) {
        if (canValidate) {
            NTSTATUS vs = VrRootValidateCr3OwnsProcess(Vcpu, eproc, candidates[i]);
            if (vs == STATUS_NOT_SUPPORTED) continue;
            if (!NT_SUCCESS(vs)) { lastStatus = vs; continue; }
        }
        NTSTATUS ws = VrRootWalkOnly(Vcpu, candidates[i], Gva, OutHpa, OutPageSize);
        if (NT_SUCCESS(ws)) {
            VrCacheSet(TargetPid, candidates[i]);
            VrRestoreToBacking(Vcpu);
            return STATUS_SUCCESS;
        }
        lastStatus = ws;
    }

    VrRestoreToBacking(Vcpu);
    return lastStatus;
}

// ============================================================
// PASSIVE-level by-PID copy (Phase C)
// ============================================================
//
// 与 HvVtRootCopyWithCr3 镜像, 但 RDX 寄存器传 PID 而非 CR3。
// 调用 AsmVmCallPhysCopy / AsmVmmCallPhysCopy 时, 第一个参数 (走 RCX → RDX
// 的命名是 "TargetCr3" 但语义上现在是 PID, 因为 root handler 改了)。

NTSTATUS
HvVtRootCopyByPid(
    _In_ ULONG TargetPid,
    _In_ UINT64 Gva,
    _Inout_updates_bytes_(Size) PVOID Buffer,
    _In_ SIZE_T Size,
    _In_ BOOLEAN IsWrite,
    _Out_opt_ PSIZE_T BytesDone)
{
    if (BytesDone) *BytesDone = 0;
    if (!Buffer || Size == 0) return STATUS_INVALID_PARAMETER;
    if (KeGetCurrentIrql() > APC_LEVEL) return STATUS_INVALID_LEVEL;
    if (!g_VtRootEnabled) return STATUS_DEVICE_NOT_READY;
    if (TargetPid == 0) return STATUS_INVALID_PARAMETER;

    CPU_VENDOR vendor = HvGetCpuVendor();
    ULONG dir = IsWrite ? HV_VTROOT_DIR_WRITE : HV_VTROOT_DIR_READ;

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
        // 注意:第一个参数槽 (RCX 经 ASM 重洗到 RDX) 现在传 PID, 而非 CR3。
        // ASM 不变, 只是 root handler 改成把 RDX 解释为 PID。
        if (vendor == CPU_VENDOR_AMD) {
            vs = AsmVmmCallPhysCopy((UINT64)TargetPid, curGva, userBuf, chunk, dir, &thisDone);
        } else {
            vs = AsmVmCallPhysCopy((UINT64)TargetPid, curGva, userBuf, chunk, dir, &thisDone);
        }

        totalDone += thisDone;
        if (!NT_SUCCESS(vs) || thisDone == 0) {
            if (BytesDone) *BytesDone = totalDone;
            return NT_SUCCESS(vs) ? STATUS_NOT_FOUND : vs;
        }

        userBuf   += thisDone;
        curGva    += thisDone;
        remaining -= thisDone;
    }

    if (BytesDone) *BytesDone = totalDone;
    return STATUS_SUCCESS;
}

// ============================================================
// HvVtRootResolveUserCr3 - PASSIVE 触发 root-mode 解析 (2026-06-17)
// ============================================================
//
// 复用 VMCALL_PHYS_COPY, mode=3 (HV_VTROOT_MODE_RESOLVE_CR3)。
// AsmVmCallPhysCopy 把 R10 写到 *OutBytesDone, root handler 把 real CR3 放 R10。
// 我们传 NULL kernelBuf + size=0 是合法的 (root handler 在 mode=3 不读它们)。
//
// 实际上 AsmVmCallPhysCopy 要求 OutBytesDone 非 NULL 才回写, NULL 时直接丢
// (见 AsmVmx.asm:799-802)。我们传一个 stack UINT64。
NTSTATUS
HvVtRootResolveUserCr3(
    _In_ ULONG TargetPid,
    _Out_ PUINT64 OutCr3)
{
    if (!OutCr3) return STATUS_INVALID_PARAMETER;
    *OutCr3 = 0;
    if (TargetPid == 0) return STATUS_INVALID_PARAMETER;
    if (KeGetCurrentIrql() > APC_LEVEL) return STATUS_INVALID_LEVEL;
    if (!g_VtRootEnabled) return STATUS_DEVICE_NOT_READY;

    CPU_VENDOR vendor = HvGetCpuVendor();
    SIZE_T outSlot = 0;
    NTSTATUS s;

    // RCX=cmd, RDX=pid, R8=0, R9=NULL, R10(size)=0, R11(mode)=3
    if (vendor == CPU_VENDOR_AMD) {
        s = AsmVmmCallPhysCopy((UINT64)TargetPid, 0, NULL, 0,
                                HV_VTROOT_MODE_RESOLVE_CR3, &outSlot);
    } else {
        s = AsmVmCallPhysCopy((UINT64)TargetPid, 0, NULL, 0,
                               HV_VTROOT_MODE_RESOLVE_CR3, &outSlot);
    }

    if (NT_SUCCESS(s)) {
        *OutCr3 = (UINT64)outSlot;
        if (*OutCr3 == 0) return STATUS_NOT_FOUND;
    }
    return s;
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
    if (!OutHpa) return STATUS_INVALID_PARAMETER;
    *OutHpa = 0;
    if (OutPageSize) *OutPageSize = 0;
    if (TargetPid == 0) return STATUS_INVALID_PARAMETER;
    if (KeGetCurrentIrql() > APC_LEVEL) return STATUS_INVALID_LEVEL;
    if (!g_VtRootEnabled) return STATUS_DEVICE_NOT_READY;
    if (Gva < 0x10000ULL || Gva >= 0x800000000000ULL) return STATUS_INVALID_PARAMETER;

    CPU_VENDOR vendor = HvGetCpuVendor();
    SIZE_T outSlot = 0;
    NTSTATUS s;

    // RDX=pid, R8=gva, R9=NULL, R10(size)=0, R11(mode)=4
    if (vendor == CPU_VENDOR_AMD) {
        s = AsmVmmCallPhysCopy((UINT64)TargetPid, Gva, NULL, 0,
                                HV_VTROOT_MODE_GVA_TO_HPA, &outSlot);
    } else {
        s = AsmVmCallPhysCopy((UINT64)TargetPid, Gva, NULL, 0,
                               HV_VTROOT_MODE_GVA_TO_HPA, &outSlot);
    }

    if (NT_SUCCESS(s)) {
        // 4KB leaf
        *OutHpa = (UINT64)outSlot;
        if (OutPageSize) *OutPageSize = PAGE_SIZE;
        return STATUS_SUCCESS;
    }
    if (s == STATUS_NOT_SUPPORTED) {
        // 命中 2MB/1GB; outSlot = pageSize
        if (OutPageSize) *OutPageSize = (UINT64)outSlot;
        return STATUS_NOT_SUPPORTED;
    }
    return s;
}

// ============================================================
// HvVtRootGetResolvedUserCr3 - PASSIVE 查询 PID → 真 user CR3
// ============================================================
//
// HvCloak.c 调用: 在 ADD_DEBUGGER 路径上, 先发一次 dummy read 触发 VtRoot
// 走 24 候选 walk 流程, 让真 user CR3 落到 g_VrPidCr3Cache, 然后用这个
// API 读出来给 EnumWorkingSet。
//
// 返回:
//   STATUS_SUCCESS      *OutCr3 = 缓存中的真 user CR3
//   STATUS_NOT_FOUND    cache miss (PID 没在最近一次 VtRoot walk 中出现)
//
NTSTATUS
HvVtRootGetResolvedUserCr3(
    _In_ ULONG TargetPid,
    _Out_ PUINT64 OutCr3)
{
    if (!OutCr3) return STATUS_INVALID_PARAMETER;
    *OutCr3 = 0;
    if (TargetPid == 0) return STATUS_INVALID_PARAMETER;

    ULONG slot = TargetPid & VR_CR3_CACHE_MASK;
    UINT64 packed = (UINT64)InterlockedOr64(
        (volatile LONG64*)&g_VrPidCr3Cache[slot].PidAndCr3, 0);
    if (packed == 0) return STATUS_NOT_FOUND;

    ULONG cachedPid = 0;
    UINT64 cachedCr3 = 0;
    VrUnpackPidCr3(packed, &cachedPid, &cachedCr3);

    // PID 哈希冲突: cache 槽是另一个 PID。pack 时 PID 截高 16-bit, 验证时也
    // 比同样的 16-bit, 否则两个 PID 撞同 slot + 同 hi-16 时会假命中。
    if (cachedPid != (TargetPid & 0xFFFF)) {
        return STATUS_NOT_FOUND;
    }
    if (cachedCr3 == 0) return STATUS_NOT_FOUND;

    *OutCr3 = cachedCr3;
    return STATUS_SUCCESS;
}

// ============================================================
// GetPeb: PID → PEB user VA (root mode + PASSIVE 入口)
// ============================================================

NTSTATUS
HvVtRootRootGetPebByPid(
    _In_ ULONG TargetPid,
    _Out_ PUINT64 OutPebVa)
{
    if (!OutPebVa) return STATUS_INVALID_PARAMETER;
    *OutPebVa = 0;
    if (TargetPid == 0) return STATUS_INVALID_PARAMETER;
    if (!g_HvPhysRootCtx.Initialized) return STATUS_DEVICE_NOT_READY;
    if (g_HvPhysRootCtx.PebOff == 0) return STATUS_NOT_SUPPORTED;

    PEPROCESS eproc = VrRootResolvePidToEprocess(TargetPid);
    if (!eproc) return STATUS_NOT_FOUND;

    // PEB 在 EPROCESS+PebOff, 是个 user VA。System / Registry / Memory
    // Compression / Secure System 等内核进程的 Peb = NULL, 不算错误。
    UINT64 peb = *(UINT64*)((PUCHAR)eproc + g_HvPhysRootCtx.PebOff);

    // 鲁棒性校验: 值必须在 user-VA 范围, 否则当作 NULL (可能撞 garbage 偏移)
    if (peb != 0 && (peb < 0x10000ULL || peb >= 0x00007FFFFFFFFFFFULL)) {
        peb = 0;
    }

    *OutPebVa = peb;
    return STATUS_SUCCESS;
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
    if (!g_VtRootEnabled) return STATUS_DEVICE_NOT_READY;

    CPU_VENDOR vendor = HvGetCpuVendor();

    // 复用 AsmVmCallPhysCopy:
    //   RDX = PID, R8/R9 = 0, R10 = 0 (返回 peb_va), R11 = HV_VTROOT_MODE_GET_PEB
    // 注意: BytesDone 形参在 ASM 端就是 [rsp+30h] 写回 R10, 我们把它指到
    // pebVa 即可拿到结果 (SIZE_T 和 UINT64 在 x64 同宽 8 字节)。
    SIZE_T pebVa = 0;
    NTSTATUS s;
    if (vendor == CPU_VENDOR_AMD) {
        s = AsmVmmCallPhysCopy((UINT64)TargetPid, 0, NULL, 0, HV_VTROOT_MODE_GET_PEB, &pebVa);
    } else {
        s = AsmVmCallPhysCopy((UINT64)TargetPid, 0, NULL, 0, HV_VTROOT_MODE_GET_PEB, &pebVa);
    }

    if (NT_SUCCESS(s)) {
        *OutPebVa = (UINT64)pebVa;
    }
    return s;
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
    if (TargetCr3 == 0) return STATUS_INVALID_PARAMETER;

    CPU_VENDOR vendor = HvGetCpuVendor();
    ULONG dir = IsWrite ? HV_VTROOT_DIR_WRITE : HV_VTROOT_DIR_READ;

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
        if (vendor == CPU_VENDOR_AMD) {
            vs = AsmVmmCallPhysCopy(TargetCr3, curGva, userBuf, chunk, dir, &thisDone);
        } else {
            vs = AsmVmCallPhysCopy(TargetCr3, curGva, userBuf, chunk, dir, &thisDone);
        }

        totalDone += thisDone;
        if (!NT_SUCCESS(vs) || thisDone == 0) {
            if (BytesDone) *BytesDone = totalDone;
            return NT_SUCCESS(vs) ? STATUS_NOT_FOUND : vs;
        }

        userBuf   += thisDone;
        curGva    += thisDone;
        remaining -= thisDone;
    }

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

    UINT64 cr3 = 0;
    NTSTATUS s = HvPhysGetProcessCr3(TargetPid, &cr3);
    if (!NT_SUCCESS(s)) return s;

    return HvVtRootCopyWithCr3(cr3, Gva, Buffer, Size, IsWrite, BytesDone);
}
