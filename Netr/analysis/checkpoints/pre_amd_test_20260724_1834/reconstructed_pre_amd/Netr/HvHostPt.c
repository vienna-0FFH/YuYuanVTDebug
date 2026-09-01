/*
 * HvHostPt.c — Step 4 (虚幻范式): host 自家页表 + 0..64GB 物理直通段映射
 *
 * 参考: D:/虚幻调试器源码/VT_Driver(4.2)/Globals.cpp:114-231
 */

#include "HvHostPt.h"
#include "HvUtils.h"   // g_HvSystemCr3

// ============================================================
// 全局
// ============================================================

PHV_HOST_PAGE_TABLES g_HvHostPt           = NULL;
UINT64               g_HvHostPtPa         = 0;
BOOLEAN              g_HvHostPtInitialized = FALSE;

#define HV_HOST_PT_TAG  'tPhH'

// ============================================================
// helpers
// ============================================================

/*
 * 给中间表 (PDPT, PD) entry 用的 flag 组合: P|RW|NX
 * 中间表必须 RW=1 (Intel SDM Vol 3 4.5.4), NX 是 host 侧选择 (host 内任何代码
 * 都不可能落到 PT 内部物理页执行).
 */
#define HV_HOST_PT_INTR_FLAGS    (HV_PTE_PRESENT | HV_PTE_RW | HV_PTE_NX)

/*
 * 2MB 大页叶子 entry: P|RW|PS|NX|Global.
 * - PS=1 (large page)
 * - NX=1 (host 绝不在物理直通段执行代码 — 我们只在这里读写数据)
 * - Global=1 (TLB 全局, 减少切 CR3 时的 invlpg 风暴 — 但这要 CR4.PGE=1, host CR4 我们没动)
 * - PCD/PWT = 0 (默认 WB, 跟 Windows kernel pool 一致). MMIO 区会有 cache 一致性问题,
 *   但本 step 不真访问 MMIO HPA (Step 4b/5 后才可能).
 */
#define HV_HOST_PT_LEAF_FLAGS    (HV_PTE_PRESENT | HV_PTE_RW | HV_PTE_PS | HV_PTE_NX | HV_PTE_GLOBAL)

/*
 * 拿到 4KB 对齐的连续物理内存. 264KB > 4KB 不能用普通 ExAllocatePool2 (后者不保证页对齐).
 * 用 MmAllocateContiguousMemory 拿足够大块.
 */
static PVOID HvHostPtAllocContiguous(SIZE_T Size)
{
    PHYSICAL_ADDRESS maxPa;
    maxPa.QuadPart = -1LL;
    PVOID va = MmAllocateContiguousMemory(Size, maxPa);
    if (va) {
        RtlZeroMemory(va, Size);
    }
    return va;
}

// ============================================================
// 物理段映射 (虚幻 map_physical_memory 1:1)
// ============================================================

static VOID HvHostPtMapPhysical(VOID)
{
    // 1) pml4[255] → PhysPdpt
    PHYSICAL_ADDRESS phys = MmGetPhysicalAddress(&g_HvHostPt->PhysPdpt[0]);
    g_HvHostPt->Pml4[HV_HOST_PT_PML4_SLOT].Value =
        (phys.QuadPart & HV_PTE_PFN_MASK) | HV_HOST_PT_INTR_FLAGS;

    // 2) PhysPdpt[i] → PhysPds[i],  i ∈ [0, 64)
    for (ULONG i = 0; i < HV_HOST_PT_PHYS_PD_COUNT; i++) {
        phys = MmGetPhysicalAddress(&g_HvHostPt->PhysPds[i][0]);
        g_HvHostPt->PhysPdpt[i].Value =
            (phys.QuadPart & HV_PTE_PFN_MASK) | HV_HOST_PT_INTR_FLAGS;
    }
    // PhysPdpt[64..511] 保持 0 (RtlZeroMemory 已清)

    // 3) PhysPds[i][j].PFN = (i<<9) + j, 大页 (2MB)
    for (ULONG i = 0; i < HV_HOST_PT_PHYS_PD_COUNT; i++) {
        for (ULONG j = 0; j < 512; j++) {
            UINT64 pfn = ((UINT64)i << 9) + j;
            UINT64 hpa = pfn << 21;  // 2MB 大页对齐: PFN << 21 给出 2MB-aligned HPA
            // 注意: 大页的 page_frame_number 字段实际占 bit 21..(MAXPHYADDR-1),
            // 而不是 bit 12..(MAXPHYADDR-1). 但 HV_PTE_PFN_MASK 是 bit 12..51,
            // 写入 HPA & MASK 后, 低 9 bit (bit 12..20) 必为 0 因为 hpa 已 2MB-aligned.
            // Intel SDM Vol 3 表 4-17 大页 PDE: bit 21..MAXPHYADDR-1 是 PFN, bit 12..20 是 PAT/Reserved
            g_HvHostPt->PhysPds[i][j].Value =
                (hpa & HV_PTE_PFN_MASK) | HV_HOST_PT_LEAF_FLAGS;
        }
    }
}

// ============================================================
// 拷贝 System PML4 高 256 项 (kernel 半空间)
// ============================================================

static NTSTATUS HvHostPtCopyKernelPml4(VOID)
{
    if (g_HvSystemCr3 == 0) {
        DbgPrint("[HvHostPt] ERROR: g_HvSystemCr3 == 0, did HvUtilsInitializeSystemCr3 run?\n");
        return STATUS_DEVICE_NOT_READY;
    }

    PHYSICAL_ADDRESS pml4Pa;
    pml4Pa.QuadPart = (LONGLONG)(g_HvSystemCr3 & HV_PTE_PFN_MASK);

    // 走 MmGetVirtualForPhysical (Win 10/11 都支持, 不需要任何 user 上下文 attach,
    //   PFN database 反查). 虚幻原版用 KeStackAttachProcess(dwm) — 那是为了让
    //   原 system_cr3 探测路径在 dwm 上下文工作; 我们已有 g_HvSystemCr3 直接用.
    PVOID systemPml4Va = MmGetVirtualForPhysical(pml4Pa);
    if (!systemPml4Va) {
        DbgPrint("[HvHostPt] ERROR: MmGetVirtualForPhysical(0x%llX) returned NULL\n",
                 pml4Pa.QuadPart);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // 拷 PML4[256..511] (256 项 × 8 字节 = 2 KB)
    __try {
        RtlCopyMemory(&g_HvHostPt->Pml4[256],
                      (PUCHAR)systemPml4Va + 256 * sizeof(UINT64),
                      256 * sizeof(UINT64));
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[HvHostPt] ERROR: RtlCopyMemory from System PML4 raised exception\n");
        return STATUS_UNSUCCESSFUL;
    }

    DbgPrint("[HvHostPt] PML4[256..511] copied from System PML4 @ %p (PA=0x%llX)\n",
             systemPml4Va, pml4Pa.QuadPart);
    return STATUS_SUCCESS;
}

// ============================================================
// HvHostPtInitialize
// ============================================================

NTSTATUS HvHostPtInitialize(VOID)
{
    NTSTATUS status;

    if (g_HvHostPtInitialized) {
        return STATUS_SUCCESS;
    }

    if (KeGetCurrentIrql() > APC_LEVEL) {
        DbgPrint("[HvHostPt] ERROR: must be called at PASSIVE/APC (IRQL=%u)\n",
                 KeGetCurrentIrql());
        return STATUS_INVALID_LEVEL;
    }

    // 1) 分配 264 KB 连续内存. MmAllocateContiguousMemory 自动返回 PAGE_SIZE 对齐.
    g_HvHostPt = (PHV_HOST_PAGE_TABLES)HvHostPtAllocContiguous(sizeof(HV_HOST_PAGE_TABLES));
    if (!g_HvHostPt) {
        DbgPrint("[HvHostPt] ERROR: cannot allocate %llu bytes contiguous\n",
                 (ULONG64)sizeof(HV_HOST_PAGE_TABLES));
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // 验证 4KB 对齐 (MmAllocateContiguousMemory 历史上一定返回页对齐, 但 paranoia 检查)
    if ((ULONG64)g_HvHostPt & 0xFFF) {
        DbgPrint("[HvHostPt] ERROR: alloc not 4KB aligned: %p\n", g_HvHostPt);
        MmFreeContiguousMemory(g_HvHostPt);
        g_HvHostPt = NULL;
        return STATUS_UNSUCCESSFUL;
    }

    // 2) 拿 pml4 的 HPA — 这是未来写 HOST_CR3 的值
    PHYSICAL_ADDRESS pml4Phys = MmGetPhysicalAddress(&g_HvHostPt->Pml4[0]);
    if (pml4Phys.QuadPart == 0) {
        DbgPrint("[HvHostPt] ERROR: MmGetPhysicalAddress(Pml4) == 0\n");
        MmFreeContiguousMemory(g_HvHostPt);
        g_HvHostPt = NULL;
        return STATUS_UNSUCCESSFUL;
    }
    g_HvHostPtPa = (UINT64)pml4Phys.QuadPart;

    // 3) 填物理段映射: pml4[255] → PhysPdpt → PhysPds → 2MB 大页 (PFN = i*512+j)
    HvHostPtMapPhysical();

    // 4) 拷 System PML4[256..511] 到我们 pml4[256..511] (kernel 半空间)
    status = HvHostPtCopyKernelPml4();
    if (!NT_SUCCESS(status)) {
        MmFreeContiguousMemory(g_HvHostPt);
        g_HvHostPt = NULL;
        g_HvHostPtPa = 0;
        return status;
    }

    g_HvHostPtInitialized = TRUE;

    DbgPrint("[HvHostPt] === INITIALIZED ===\n");
    DbgPrint("[HvHostPt]   g_HvHostPt = %p (size=%llu KB)\n",
             g_HvHostPt, (ULONG64)sizeof(HV_HOST_PAGE_TABLES) / 1024);
    DbgPrint("[HvHostPt]   pml4 HPA = 0x%llX (future HOST_CR3 candidate)\n", g_HvHostPtPa);
    DbgPrint("[HvHostPt]   pml4[255] -> PhysPdpt -> %u PDs (0..%llu GB phys mapped)\n",
             HV_HOST_PT_PHYS_PD_COUNT, HV_HOST_PT_PHYS_BYTES >> 30);
    DbgPrint("[HvHostPt]   HVA base = 0x%llX (HPA + base = HVA)\n",
             HV_HOST_PT_PHYS_BASE_VA);
    DbgPrint("[HvHostPt]   pml4[256..511] copied from System CR3=0x%llX\n", g_HvSystemCr3);
    DbgPrint("[HvHostPt]   *** NOT YET wired to HOST_CR3 — Step 4b will switch ***\n");

    return STATUS_SUCCESS;
}

// ============================================================
// HvHostPtCleanup
// ============================================================

VOID HvHostPtCleanup(VOID)
{
    if (!g_HvHostPtInitialized) return;

    // 必须在 VMXOFF 之后. 调用方 (DriverUnload) 负责顺序.
    if (g_HvHostPt) {
        MmFreeContiguousMemory(g_HvHostPt);
        g_HvHostPt = NULL;
    }
    g_HvHostPtPa = 0;
    g_HvHostPtInitialized = FALSE;
    DbgPrint("[HvHostPt] cleanup done\n");
}

// ============================================================
// HvHostPtGetCr3 (Step 4b 才会被调用写 HOST_CR3)
// ============================================================

UINT64 HvHostPtGetCr3(VOID)
{
    if (!g_HvHostPtInitialized) return 0;
    return g_HvHostPtPa;
}
