/*
 * HvNpt.c - AMD NPT (Nested Page Tables) 实现
 */

#include "HvNpt.h"
#include "HvUtils.h"
#include "HvCpu.h"
#include "HvCompat.h"

// P122: 全 driver DbgPrint → GUI ring
#define HV_TRACE_THIS_CAT HV_TRACE_CAT_NPT
#include "HvTrace.h"

// ==================== NPT 支持检查 ====================

/*
 * 检查 NPT 支持
 * 
 * AMD NPT 通过 CPUID 80000001H:EDX[26] 指示
 * 或者通过 CPUID 8000000AH:EDX[0] 指示
 */
BOOLEAN SvmCheckNptSupport(VOID)
{
    int cpuInfo[4];
    
    // 检查 CPUID 最大扩展功能号
    __cpuid(cpuInfo, 0x80000000);
    if ((ULONG)cpuInfo[0] < 0x8000000A) {
        DbgPrint("[NPT] CPUID extended function 8000000AH not supported\n");
        return FALSE;
    }
    
    // 检查 CPUID 8000000AH:EDX[0] = NPT 支持
    __cpuid(cpuInfo, 0x8000000A);
    if (!(cpuInfo[3] & (1 << 0))) {
        DbgPrint("[NPT] CPUID 8000000AH:EDX[0] NPT bit not set\n");
        return FALSE;
    }
    
    DbgPrint("[NPT] NPT support confirmed via CPUID 8000000AH\n");
    DbgPrint("[NPT]   SVM Features (EDX): 0x%08X\n", cpuInfo[3]);
    DbgPrint("[NPT]   NPT: %s\n", (cpuInfo[3] & (1 << 0)) ? "Yes" : "No");
    DbgPrint("[NPT]   LBR Virtualization: %s\n", (cpuInfo[3] & (1 << 1)) ? "Yes" : "No");
    DbgPrint("[NPT]   SVM Lock: %s\n", (cpuInfo[3] & (1 << 2)) ? "Yes" : "No");
    DbgPrint("[NPT]   NRIP Save: %s\n", (cpuInfo[3] & (1 << 3)) ? "Yes" : "No");
    DbgPrint("[NPT]   TSC Rate MSR: %s\n", (cpuInfo[3] & (1 << 4)) ? "Yes" : "No");
    DbgPrint("[NPT]   VMCB Clean: %s\n", (cpuInfo[3] & (1 << 5)) ? "Yes" : "No");
    DbgPrint("[NPT]   Flush by ASID: %s\n", (cpuInfo[3] & (1 << 6)) ? "Yes" : "No");
    DbgPrint("[NPT]   Decode Assists: %s\n", (cpuInfo[3] & (1 << 7)) ? "Yes" : "No");
    
    return TRUE;
}

/*
 * 检查 NX (No Execute) 位支持
 */
BOOLEAN SvmCheckNxSupport(VOID)
{
    int cpuInfo[4];
    ULONG64 efer;
    
    // 检查 CPUID 80000001H:EDX[20] = NX 支持
    __cpuid(cpuInfo, 0x80000001);
    if (!(cpuInfo[3] & (1 << 20))) {
        DbgPrint("[NPT] CPU does not support NX bit\n");
        return FALSE;
    }
    
    // 检查 EFER.NXE 是否启用
    efer = __readmsr(MSR_IA32_EFER);
    if (!(efer & EFER_NXE)) {
        DbgPrint("[NPT] EFER.NXE not enabled (EFER=0x%llX)\n", efer);
        // 不返回 FALSE，因为 Windows 通常会启用 NXE
        // 可以在这里尝试启用它
    } else {
        DbgPrint("[NPT] EFER.NXE is enabled\n");
    }
    
    return TRUE;
}

// ==================== NPT 初始化 ====================

/*
 * 初始化 NPT 页表
 */
NTSTATUS SvmSetupNpt(PVCPU_DATA VcpuData)
{
    PHYSICAL_ADDRESS maxPhysAddr = { .QuadPart = -1LL };
    SIZE_T nptTablesSize;

    // 检查 NPT 支持
    if (!SvmCheckNptSupport()) {
        DbgPrint("[NPT] CPU %d: NPT not supported\n", VcpuData->ProcessorNumber);
        return STATUS_NOT_SUPPORTED;
    }

    // 分配 NPT 页表结构
    nptTablesSize = sizeof(NPT_TABLES);
    VcpuData->NptTables = (PNPT_TABLES)MmAllocateContiguousMemory(nptTablesSize, maxPhysAddr);

    if (!VcpuData->NptTables) {
        DbgPrint("[NPT] CPU %d: Failed to allocate NPT tables\n", VcpuData->ProcessorNumber);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(VcpuData->NptTables, nptTablesSize);
    VcpuData->NptTables->Pml4Physical = MmGetPhysicalAddress(VcpuData->NptTables);
    VcpuData->NptTables->SplitPtCount = 0;

    DbgPrint("[NPT] CPU %d: NPT tables allocated at PA 0x%llX\n",
             VcpuData->ProcessorNumber, VcpuData->NptTables->Pml4Physical.QuadPart);

    // 构建身份映射
    if (!NT_SUCCESS(SvmBuildNptIdentityMap(VcpuData))) {
        MmFreeContiguousMemory(VcpuData->NptTables);
        VcpuData->NptTables = NULL;
        return STATUS_UNSUCCESSFUL;
    }

    DbgPrint("[NPT] CPU %d: NPT initialized successfully\n", VcpuData->ProcessorNumber);
    return STATUS_SUCCESS;
}

/*
 * 构建 NPT 身份映射
 * 
 * 使用 2MB 大页映射前 512GB 物理内存
 */
NTSTATUS SvmBuildNptIdentityMap(PVCPU_DATA VcpuData)
{
    PHYSICAL_ADDRESS pdptPhysical, pdPhysical;
    ULONG64 pdptIndex, pdIndex;
    NPT_PML4E* pml4e;
    NPT_PDPTE* pdpte;
    NPT_PDE* pde;
    ULONG64 physicalAddress;

    if (!VcpuData->NptTables) {
        return STATUS_INVALID_PARAMETER;
    }

    // 清零分割页表数组
    RtlZeroMemory(VcpuData->NptTables->SplitPt, sizeof(VcpuData->NptTables->SplitPt));
    VcpuData->NptTables->SplitPtCount = 0;

    // 获取 PDPT 物理地址
    pdptPhysical = MmGetPhysicalAddress(&VcpuData->NptTables->Pdpt[0]);
    VcpuData->NptTables->PdptPhysical = pdptPhysical;

    // 设置 PML4E[0] 指向 PDPT
    pml4e = &VcpuData->NptTables->Pml4[0];
    pml4e->Value = 0;
    pml4e->PageFrameNumber = pdptPhysical.QuadPart >> 12;
    pml4e->Present = 1;
    pml4e->Write = 1;
    pml4e->User = 1;  // NPT 需要 User 位

    DbgPrint("[NPT] PML4E[0]: PA=0x%llX, Value=0x%llX\n",
             pdptPhysical.QuadPart, pml4e->Value);

    // 遍历所有 512 个 PDPT 条目 (每个条目覆盖 1GB)
    for (pdptIndex = 0; pdptIndex < 512; pdptIndex++) {
        pdpte = &VcpuData->NptTables->Pdpt[pdptIndex];
        pdPhysical = MmGetPhysicalAddress(&VcpuData->NptTables->Pd[pdptIndex][0]);

        // 设置 PDPTE 指向 PD
        pdpte->Value = 0;
        pdpte->PageFrameNumber = pdPhysical.QuadPart >> 12;
        pdpte->Present = 1;
        pdpte->Write = 1;
        pdpte->User = 1;

        // 遍历所有 512 个 PD 条目 (每个条目覆盖 2MB)
        for (pdIndex = 0; pdIndex < 512; pdIndex++) {
            pde = &VcpuData->NptTables->Pd[pdptIndex][pdIndex];
            
            // 计算这个 2MB 页的物理地址
            physicalAddress = (pdptIndex * 512 + pdIndex) * 0x200000ULL;  // 2MB = 0x200000

            pde->Value = 0;
            pde->Large.Present = 1;
            pde->Large.Write = 1;
            pde->Large.User = 1;
            pde->Large.LargePage = 1;  // 2MB 大页
            pde->Large.PageFrameNumber = physicalAddress >> 21;  // 2MB 对齐
            
            // 设置缓存类型为 Write-Back (通过 PAT)
            // 默认 PAT 配置: PAT=0, PCD=0, PWT=0 -> WB
        }
    }

    DbgPrint("[NPT] Identity map created: 512GB using 2MB pages\n");

#if HV_ENABLE_SVM_HARDENING
    // 镜像 EPT 设计 (HvEpt.c:130): PML4[1..3] 用 1GB 大页扩展到 2TB
    // 解决 NptGetPteForPhysicalAddress / NPF fallback 处理 >=512GB 时
    // 误改低位 PTE 或死循环 NPF 的安全问题。
    if (HvSvmSupports1GBPages()) {
        PHYSICAL_ADDRESS maxPhys = { .QuadPart = -1LL };
        for (ULONG pml4Idx = 1; pml4Idx <= 3; pml4Idx++) {
            PVOID extraPdptVa = MmAllocateContiguousMemory(PAGE_SIZE, maxPhys);
            if (!extraPdptVa) {
                DbgPrint("[NPT] ExtraPdpt[%u] alloc failed, stop at PML4[%u]\n",
                         pml4Idx - 1, pml4Idx);
                break;  // fail-soft, 已映射部分仍可用
            }
            RtlZeroMemory(extraPdptVa, PAGE_SIZE);
            VcpuData->NptTables->ExtraPdpt[pml4Idx - 1] = extraPdptVa;

            // PML4[pml4Idx] -> ExtraPdpt
            PHYSICAL_ADDRESS extraPdptPa = MmGetPhysicalAddress(extraPdptVa);
            NPT_PML4E* extraPml4e = &VcpuData->NptTables->Pml4[pml4Idx];
            extraPml4e->Value = 0;
            extraPml4e->PageFrameNumber = extraPdptPa.QuadPart >> 12;
            extraPml4e->Present = 1;
            extraPml4e->Write = 1;
            extraPml4e->User = 1;

            // 填 512 个 1GB-page PDPTE
            // 每个 PDPTE 覆盖 1GB; 物理基址 = pml4Idx*512GB + pdptIdx*1GB
            NPT_PDPTE* extraPdpt = (NPT_PDPTE*)extraPdptVa;
            for (ULONG pdptIdx = 0; pdptIdx < 512; pdptIdx++) {
                ULONG64 pa1G = ((ULONG64)pml4Idx * 512ULL + (ULONG64)pdptIdx) * 0x40000000ULL;
                NPT_PDPTE* pdpte1G = &extraPdpt[pdptIdx];
                pdpte1G->Value = 0;
                pdpte1G->Present = 1;
                pdpte1G->Write = 1;
                pdpte1G->User = 1;
                pdpte1G->LargePage = 1;                  // 1GB 大页
                pdpte1G->PageFrameNumber = pa1G >> 12;   // PFN, 注意硬件按低 30 bit 对齐
            }
        }
        DbgPrint("[NPT] Extended map: PML4[1..3] = 1.5TB via 1GB pages (total 2TB)\n");
    } else {
        DbgPrint("[NPT] CPU 不支持 1GB pages, 仅保留 PML4[0] = 512GB\n");
    }
#endif

    return STATUS_SUCCESS;
}

/*
 * 清理 NPT 页表
 */
VOID SvmCleanupNpt(PVCPU_DATA VcpuData)
{
    ULONG i;

    if (!VcpuData->NptTables) {
        return;
    }

    // 释放分割的 4KB 页表
    for (i = 0; i < VcpuData->NptTables->SplitPtCount; i++) {
        if (VcpuData->NptTables->SplitPt[i]) {
            MmFreeContiguousMemory(VcpuData->NptTables->SplitPt[i]);
            VcpuData->NptTables->SplitPt[i] = NULL;
        }
    }

#if HV_ENABLE_SVM_HARDENING
    // 释放 ExtraPdpt[0..2]
    for (i = 0; i < 3; i++) {
        if (VcpuData->NptTables->ExtraPdpt[i]) {
            MmFreeContiguousMemory(VcpuData->NptTables->ExtraPdpt[i]);
            VcpuData->NptTables->ExtraPdpt[i] = NULL;
        }
    }
#endif

    // 释放主 NPT 结构
    MmFreeContiguousMemory(VcpuData->NptTables);
    VcpuData->NptTables = NULL;

    DbgPrint("[NPT] NPT cleanup complete\n");
}

/*
 * 刷新 NPT TLB
 */
VOID SvmInvalidateNptTlb(PVCPU_DATA VcpuData)
{
    if (VcpuData->Vmcb) {
        // 设置 TLB 控制为刷新所有
        VcpuData->Vmcb->ControlArea.TlbControl = SVM_TLB_CONTROL_FLUSH_GUEST;
    }
}

/*
 * 分割 2MB 大页为 4KB 页
 * 
 * 用于需要细粒度控制的场景（如 hook）
 */
NTSTATUS SvmSplitNptLargePage(PVCPU_DATA VcpuData, ULONG64 PhysicalAddress)
{
    PHYSICAL_ADDRESS maxPhysAddr = { .QuadPart = -1LL };
    PNPT_PTE ptPage;
    PHYSICAL_ADDRESS ptPhysical;
    ULONG64 pdptIndex, pdIndex, ptIndex;
    ULONG64 basePhysAddr;
    NPT_PDE* pde;

    if (!VcpuData->NptTables) {
        return STATUS_INVALID_PARAMETER;
    }

    if (VcpuData->NptTables->SplitPtCount >= 64) {
        DbgPrint("[NPT] Split PT limit reached\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // 计算索引
    pdptIndex = (PhysicalAddress >> 30) & 0x1FF;  // 1GB 索引
    pdIndex = (PhysicalAddress >> 21) & 0x1FF;    // 2MB 索引

    pde = &VcpuData->NptTables->Pd[pdptIndex][pdIndex];

    // 检查是否已经是大页
    if (!pde->Large.LargePage) {
        DbgPrint("[NPT] Page at 0x%llX is already split\n", PhysicalAddress);
        return STATUS_SUCCESS;
    }

    // 分配新的 4KB 页表
    ptPage = (PNPT_PTE)MmAllocateContiguousMemory(PAGE_SIZE, maxPhysAddr);
    if (!ptPage) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    ptPhysical = MmGetPhysicalAddress(ptPage);

    // 计算 2MB 页的基地址
    basePhysAddr = (pdptIndex << 30) | (pdIndex << 21);

    // 填充 512 个 4KB 页表项
    for (ptIndex = 0; ptIndex < 512; ptIndex++) {
        ptPage[ptIndex].Value = 0;
        ptPage[ptIndex].Present = 1;
        ptPage[ptIndex].Write = 1;
        ptPage[ptIndex].User = 1;
        ptPage[ptIndex].PageFrameNumber = (basePhysAddr + (ptIndex << 12)) >> 12;
    }

    // 更新 PDE 指向新的页表
    pde->Value = 0;
    pde->Small.Present = 1;
    pde->Small.Write = 1;
    pde->Small.User = 1;
    pde->Small.LargePage = 0;  // 不是大页
    pde->Small.PageFrameNumber = ptPhysical.QuadPart >> 12;

    // 保存页表指针用于清理
    VcpuData->NptTables->SplitPt[VcpuData->NptTables->SplitPtCount++] = ptPage;

    // 刷新 TLB
    SvmInvalidateNptTlb(VcpuData);

    DbgPrint("[NPT] Split 2MB page at 0x%llX into 4KB pages\n", basePhysAddr);
    return STATUS_SUCCESS;
}

/*
 * 修改 NPT 页权限
 */
VOID SvmSetNptPagePermissions(
    PVCPU_DATA VcpuData,
    ULONG64 PhysicalAddress,
    BOOLEAN Read,
    BOOLEAN Write,
    BOOLEAN Execute)
{
    ULONG64 pdptIndex, pdIndex, ptIndex;
    NPT_PDE* pde;
    NPT_PTE* pte;

    if (!VcpuData->NptTables) {
        return;
    }

    // 计算索引
    pdptIndex = (PhysicalAddress >> 30) & 0x1FF;
    pdIndex = (PhysicalAddress >> 21) & 0x1FF;
    ptIndex = (PhysicalAddress >> 12) & 0x1FF;

    pde = &VcpuData->NptTables->Pd[pdptIndex][pdIndex];

    if (pde->Large.LargePage) {
        // 2MB 大页 - 需要先分割
        if (!NT_SUCCESS(SvmSplitNptLargePage(VcpuData, PhysicalAddress))) {
            DbgPrint("[NPT] Failed to split page for permission change\n");
            return;
        }
        // 重新获取 PDE
        pde = &VcpuData->NptTables->Pd[pdptIndex][pdIndex];
    }

    // 获取 PTE
    PHYSICAL_ADDRESS ptPhysical = { .QuadPart = (LONGLONG)(pde->Small.PageFrameNumber << 12) };
    pte = (PNPT_PTE)MmGetVirtualForPhysical(ptPhysical);
    
    if (!pte) {
        DbgPrint("[NPT] Cannot get virtual address for PT\n");
        return;
    }

    pte = &pte[ptIndex];

    // 设置权限
    pte->Present = Read ? 1 : 0;
    pte->Write = Write ? 1 : 0;
    pte->NoExecute = Execute ? 0 : 1;

    // 刷新 TLB
    SvmInvalidateNptTlb(VcpuData);

    DbgPrint("[NPT] Set permissions for PA 0x%llX: R=%d W=%d X=%d\n",
             PhysicalAddress, Read, Write, Execute);
}
