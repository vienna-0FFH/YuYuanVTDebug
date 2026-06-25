/*
 * HvEpt.c - EPT 操作函数实现
 */

#include "HvEpt.h"
#include "HvCompat.h"

// P122: 全 driver DbgPrint → GUI ring
#define HV_TRACE_THIS_CAT HV_TRACE_CAT_EPT
#include "HvTrace.h"

/*
 * 检查EPT支持
 */
BOOLEAN HvCheckEptSupport(VOID)
{
    ULONG64 eptVpidCap;

    eptVpidCap = __readmsr(MSR_IA32_VMX_EPT_VPID_CAP);

    if (!(eptVpidCap & 0x1)) {
        DbgPrint("[HV] CPU does not support EPT\n");
        return FALSE;
    }

    if (!(eptVpidCap & (1 << 14))) {
        DbgPrint("[HV] CPU does not support EPT WB memory type\n");
        return FALSE;
    }

    if (!(eptVpidCap & (1 << 6))) {
        DbgPrint("[HV] CPU does not support EPT 4-level page walk\n");
        return FALSE;
    }

#if HV_DIAG_VMCS_SETUP
    DbgPrint("[HV] CPU supports EPT\n");
#endif
    return TRUE;
}

/*
 * 初始化EPT页表
 */
NTSTATUS HvSetupEpt(PVCPU_DATA VcpuData)
{
    PHYSICAL_ADDRESS maxPhysicalAddress;
    SIZE_T eptTablesSize;

    if (!HvCheckEptSupport()) {
        return STATUS_NOT_SUPPORTED;
    }

    eptTablesSize = sizeof(EPT_TABLES);
    maxPhysicalAddress.QuadPart = -1LL;
    VcpuData->EptTables = (PEPT_TABLES)MmAllocateContiguousMemory(eptTablesSize, maxPhysicalAddress);

    if (!VcpuData->EptTables) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(VcpuData->EptTables, eptTablesSize);
    VcpuData->EptTables->Pml4Physical = MmGetPhysicalAddress(VcpuData->EptTables);

    if (!NT_SUCCESS(HvBuildEptIdentityMap(VcpuData))) {
        MmFreeContiguousMemory(VcpuData->EptTables);
        VcpuData->EptTables = NULL;
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}

/*
 * 构建EPT身份映射（1:1映射）
 * 使用 2MB 大页映射物理内存
 *
 * 映射策略：
 *   PML4[0] 覆盖 0 - 512GB（主内存 + 大部分 MMIO）
 *   PML4[1..3] 覆盖 512GB - 2TB（高地址 MMIO：GPU BAR、NVMe 等）
 * 总共映射 2TB 物理地址空间，覆盖绝大多数现代系统
 */
/*
 * HvEptBuildIdentityInto -- 在给定的 EPT_TABLES 上建立 identity map。
 *
 * 2026-06-16: 从 HvBuildEptIdentityMap 抽出, 让 HvCloak.c 能复用建第二份 EPT 实例。
 * 不依赖 VCPU_DATA, 纯操作传入的 EPT_TABLES。
 *
 * PML4[0] 覆盖 0 - 512GB (主内存 + 大部分 MMIO), 用 2MB 大页 WB
 * PML4[1..3] 覆盖 512GB - 2TB (高地址 MMIO: GPU BAR/NVMe), 用 1GB 大页 UC
 */
NTSTATUS HvEptBuildIdentityInto(PEPT_TABLES EptTables)
{
    PHYSICAL_ADDRESS pdptPhysical, pdPhysical;
    ULONG64 pdptIndex, pdIndex;
    EPT_PML4E* pml4e;
    EPT_PDPTE* pdpte;
    EPT_PDE* pde;
    ULONG64 physicalAddress;
    ULONG pml4Index;

    if (!EptTables) {
        return STATUS_INVALID_PARAMETER;
    }

    EptTables->SplitPtCount = 0;
    RtlZeroMemory(EptTables->SplitPt, sizeof(EptTables->SplitPt));
    RtlZeroMemory(EptTables->SplitPtPhysical, sizeof(EptTables->SplitPtPhysical));

    pdptPhysical = MmGetPhysicalAddress(&EptTables->Pdpt[0]);
    EptTables->PdptPhysical = pdptPhysical;

    // 设置 PML4[0] - 覆盖 0 到 512GB
    pml4e = &EptTables->Pml4[0];
    pml4e->Value = 0;
    pml4e->PageFrameNumber = pdptPhysical.QuadPart >> 12;
    pml4e->Read = 1;
    pml4e->Write = 1;
    pml4e->Execute = 1;

    for (pdptIndex = 0; pdptIndex < 512; pdptIndex++) {
        pdpte = &EptTables->Pdpt[pdptIndex];
        pdPhysical = MmGetPhysicalAddress(&EptTables->Pd[pdptIndex][0]);

        pdpte->Value = 0;
        pdpte->PageFrameNumber = pdPhysical.QuadPart >> 12;
        pdpte->Read = 1;
        pdpte->Write = 1;
        pdpte->Execute = 1;

        for (pdIndex = 0; pdIndex < 512; pdIndex++) {
            pde = &EptTables->Pd[pdptIndex][pdIndex];
            physicalAddress = (pdptIndex * 512 + pdIndex) * 0x200000ULL;

            pde->Value = 0;
            pde->Read = 1;
            pde->Write = 1;
            pde->Execute = 1;
            pde->Value |= (1 << 7);      // LargePage
            pde->Value |= (6ULL << 3);   // MemoryType = WB
            pde->PageFrameNumber = physicalAddress >> 12;
        }
    }

    // 设置 PML4[1..3] - 覆盖 512GB 到 2TB (高地址 MMIO 区域)
    // 使用 1GB 大页 (PDPTE.LargePage=1) 避免额外分配 PD 数组
    for (pml4Index = 1; pml4Index < 4; pml4Index++) {
        PHYSICAL_ADDRESS maxPhysAddr = { .QuadPart = -1LL };
        EPT_PDPTE* extraPdpt;
        PHYSICAL_ADDRESS extraPdptPhysical;

        extraPdpt = (EPT_PDPTE*)MmAllocateContiguousMemory(
            PAGE_SIZE, maxPhysAddr);
        if (!extraPdpt) {
            DbgPrint("[HV] EPT WARNING: Failed to allocate PDPT for PML4[%d] (covers %lluGB-%lluGB), "
                     "high MMIO access from Guest will fault\n",
                     pml4Index,
                     (ULONG64)pml4Index * 512ULL,
                     ((ULONG64)pml4Index + 1ULL) * 512ULL);
            break;
        }
        RtlZeroMemory(extraPdpt, PAGE_SIZE);
        extraPdptPhysical = MmGetPhysicalAddress(extraPdpt);

        EptTables->ExtraPdpt[pml4Index - 1] = extraPdpt;

        pml4e = &EptTables->Pml4[pml4Index];
        pml4e->Value = 0;
        pml4e->PageFrameNumber = extraPdptPhysical.QuadPart >> 12;
        pml4e->Read = 1;
        pml4e->Write = 1;
        pml4e->Execute = 1;

        // 使用 1GB 大页, MemoryType = UC (Intel SDM 28.2.6, MMIO 必须 UC)
        for (pdptIndex = 0; pdptIndex < 512; pdptIndex++) {
            pdpte = &extraPdpt[pdptIndex];
            physicalAddress = ((ULONG64)pml4Index * 512 + pdptIndex) * 0x40000000ULL; // 1GB per entry

            pdpte->Value = 0;
            pdpte->Read = 1;
            pdpte->Write = 1;
            pdpte->Execute = 1;
            pdpte->Value |= (1 << 7);      // LargePage (1GB)
            pdpte->Value |= (0ULL << 3);   // MemoryType = UC
            pdpte->PageFrameNumber = physicalAddress >> 12;
        }
    }

    return STATUS_SUCCESS;
}

/*
 * 建立EPT身份映射 (薄 wrapper, 复用 HvEptBuildIdentityInto)。
 */
NTSTATUS HvBuildEptIdentityMap(PVCPU_DATA VcpuData)
{
    if (!VcpuData || !VcpuData->EptTables) {
        return STATUS_INVALID_PARAMETER;
    }
    return HvEptBuildIdentityInto(VcpuData->EptTables);
}

/*
 * 清理EPT
 */
VOID HvCleanupEpt(PVCPU_DATA VcpuData)
{
    if (VcpuData->EptTables) {
        // Free extra PDPT allocations for high-address MMIO mapping
        ULONG i;
        for (i = 0; i < 3; i++) {
            if (VcpuData->EptTables->ExtraPdpt[i]) {
                MmFreeContiguousMemory(VcpuData->EptTables->ExtraPdpt[i]);
                VcpuData->EptTables->ExtraPdpt[i] = NULL;
            }
        }
        MmFreeContiguousMemory(VcpuData->EptTables);
        VcpuData->EptTables = NULL;
    }
}
