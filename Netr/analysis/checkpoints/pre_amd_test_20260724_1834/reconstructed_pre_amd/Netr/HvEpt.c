/*
 * HvEpt.c - Intel EPT setup and cache-type handling.
 */

#include "HvEpt.h"
#include "HvCompat.h"

#define HV_TRACE_THIS_CAT HV_TRACE_CAT_EPT
#include "HvTrace.h"

#define IA32_MTRRCAP                 0x000000FEu
#define IA32_MTRR_DEF_TYPE           0x000002FFu
#define IA32_MTRR_PHYSBASE0          0x00000200u
#define IA32_MTRR_PHYSMASK0          0x00000201u
#define IA32_MTRR_FIX64K_00000       0x00000250u
#define IA32_MTRR_FIX16K_80000       0x00000258u
#define IA32_MTRR_FIX16K_A0000       0x00000259u
#define IA32_MTRR_FIX4K_C0000        0x00000268u
#define IA32_SMRR_PHYSBASE           0x000001F2u
#define IA32_SMRR_PHYSMASK           0x000001F3u

#define HV_MEMORY_TYPE_UC            0u
#define HV_MEMORY_TYPE_WT            4u
#define HV_MEMORY_TYPE_WB            6u
#define HV_EPT_MAX_MTRR_RANGES       384u

typedef struct _HV_EPT_MTRR_RANGE {
    ULONG64 Base;
    ULONG64 End;
    UCHAR MemoryType;
    BOOLEAN Fixed;
} HV_EPT_MTRR_RANGE, *PHV_EPT_MTRR_RANGE;

typedef struct _HV_EPT_MTRR_STATE {
    BOOLEAN Initialized;
    BOOLEAN Enabled;
    UCHAR DefaultMemoryType;
    UCHAR PhysicalAddressBits;
    ULONG RangeCount;
    HV_EPT_MTRR_RANGE Ranges[HV_EPT_MAX_MTRR_RANGES];
} HV_EPT_MTRR_STATE;

static HV_EPT_MTRR_STATE g_EptMtrr;

static BOOLEAN
HvEptpIsValidMemoryType(_In_ UCHAR MemoryType)
{
    return MemoryType == 0 || MemoryType == 1 || MemoryType == 4 ||
           MemoryType == 5 || MemoryType == 6;
}

static NTSTATUS
HvEptpAddMtrrRange(
    _In_ ULONG64 Base,
    _In_ ULONG64 End,
    _In_ UCHAR MemoryType,
    _In_ BOOLEAN Fixed
)
{
    PHV_EPT_MTRR_RANGE range;

    if (End < Base || !HvEptpIsValidMemoryType(MemoryType)) {
        return STATUS_INVALID_PARAMETER;
    }
    if (g_EptMtrr.RangeCount >= RTL_NUMBER_OF(g_EptMtrr.Ranges)) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    range = &g_EptMtrr.Ranges[g_EptMtrr.RangeCount++];
    range->Base = Base;
    range->End = End;
    range->MemoryType = MemoryType;
    range->Fixed = Fixed;
    return STATUS_SUCCESS;
}

static NTSTATUS
HvEptpAddFixedMtrr(
    _In_ ULONG Msr,
    _In_ ULONG64 Base,
    _In_ ULONG64 Granularity
)
{
    ULONG64 value = __readmsr(Msr);

    for (ULONG i = 0; i < 8; i++) {
        UCHAR type = (UCHAR)((value >> (i * 8)) & 0xFF);
        ULONG64 start = Base + ((ULONG64)i * Granularity);
        NTSTATUS status = HvEptpAddMtrrRange(
            start, start + Granularity - 1, type, TRUE);
        if (!NT_SUCCESS(status)) {
            return status;
        }
    }
    return STATUS_SUCCESS;
}

static NTSTATUS
HvEptpAddVariableMtrr(
    _In_ ULONG64 BaseMsr,
    _In_ ULONG64 MaskMsr,
    _In_ ULONG64 AddressMask,
    _In_ BOOLEAN Fixed
)
{
    ULONG64 base;
    ULONG64 mask;
    ULONG64 size;
    ULONG64 end;
    UCHAR type;

    if ((MaskMsr & (1ULL << 11)) == 0) {
        return STATUS_SUCCESS;
    }

    type = (UCHAR)(BaseMsr & 0xFF);
    base = BaseMsr & AddressMask;
    mask = MaskMsr & AddressMask;
    size = ((~mask) & AddressMask) + PAGE_SIZE;
    if (size == 0 || base > MAXULONG64 - (size - 1)) {
        return STATUS_INVALID_PARAMETER;
    }
    end = base + size - 1;
    return HvEptpAddMtrrRange(base, end, type, Fixed);
}

NTSTATUS
HvEptInitializeMemoryTypes(VOID)
{
    int cpuInfo[4] = { 0 };
    ULONG64 cap;
    ULONG64 defType;
    ULONG64 addressMask;
    ULONG variableCount;
    NTSTATUS status = STATUS_SUCCESS;

    if (g_EptMtrr.Initialized) {
        return STATUS_SUCCESS;
    }

    RtlZeroMemory(&g_EptMtrr, sizeof(g_EptMtrr));

    __try {
        __cpuid(cpuInfo, 0x80000000);
        if ((ULONG)cpuInfo[0] >= 0x80000008u) {
            __cpuid(cpuInfo, 0x80000008);
            g_EptMtrr.PhysicalAddressBits = (UCHAR)(cpuInfo[0] & 0xFF);
        }
        if (g_EptMtrr.PhysicalAddressBits < 32 ||
            g_EptMtrr.PhysicalAddressBits > 52) {
            g_EptMtrr.PhysicalAddressBits = 36;
        }

        addressMask = ((1ULL << g_EptMtrr.PhysicalAddressBits) - 1ULL) &
                      ~((ULONG64)PAGE_SIZE - 1ULL);

        cap = __readmsr(IA32_MTRRCAP);
        defType = __readmsr(IA32_MTRR_DEF_TYPE);
        g_EptMtrr.Enabled = (defType & (1ULL << 11)) != 0;
        g_EptMtrr.DefaultMemoryType = g_EptMtrr.Enabled
            ? (UCHAR)(defType & 0xFF)
            : HV_MEMORY_TYPE_UC;
        if (!HvEptpIsValidMemoryType(g_EptMtrr.DefaultMemoryType)) {
            g_EptMtrr.DefaultMemoryType = HV_MEMORY_TYPE_UC;
        }

        if (g_EptMtrr.Enabled && (cap & (1ULL << 8)) != 0 &&
            (defType & (1ULL << 10)) != 0) {
            status = HvEptpAddFixedMtrr(IA32_MTRR_FIX64K_00000, 0, 0x10000);
            if (!NT_SUCCESS(status)) __leave;
            status = HvEptpAddFixedMtrr(IA32_MTRR_FIX16K_80000, 0x80000, 0x4000);
            if (!NT_SUCCESS(status)) __leave;
            status = HvEptpAddFixedMtrr(IA32_MTRR_FIX16K_A0000, 0xA0000, 0x4000);
            if (!NT_SUCCESS(status)) __leave;
            for (ULONG i = 0; i < 8; i++) {
                status = HvEptpAddFixedMtrr(
                    IA32_MTRR_FIX4K_C0000 + i,
                    0xC0000 + ((ULONG64)i * 0x8000),
                    0x1000);
                if (!NT_SUCCESS(status)) __leave;
            }
        }

        if (g_EptMtrr.Enabled && (cap & (1ULL << 11)) != 0) {
            status = HvEptpAddVariableMtrr(
                __readmsr(IA32_SMRR_PHYSBASE),
                __readmsr(IA32_SMRR_PHYSMASK),
                addressMask,
                FALSE);
            if (!NT_SUCCESS(status)) __leave;
        }

        if (g_EptMtrr.Enabled) {
            variableCount = (ULONG)(cap & 0xFF);
            for (ULONG i = 0; i < variableCount; i++) {
                status = HvEptpAddVariableMtrr(
                    __readmsr(IA32_MTRR_PHYSBASE0 + (i * 2)),
                    __readmsr(IA32_MTRR_PHYSMASK0 + (i * 2)),
                    addressMask,
                    FALSE);
                if (!NT_SUCCESS(status)) __leave;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }

    if (!NT_SUCCESS(status)) {
        RtlZeroMemory(&g_EptMtrr, sizeof(g_EptMtrr));
        DbgPrint("[HV] MTRR discovery failed: 0x%08X\n", status);
        return status;
    }

    g_EptMtrr.Initialized = TRUE;
    DbgPrint("[HV] MTRR map ready: enabled=%u default=%u ranges=%u physBits=%u\n",
             g_EptMtrr.Enabled,
             g_EptMtrr.DefaultMemoryType,
             g_EptMtrr.RangeCount,
             g_EptMtrr.PhysicalAddressBits);
    return STATUS_SUCCESS;
}

static UCHAR
HvEptpCombineMemoryTypes(_In_ UCHAR Left, _In_ UCHAR Right)
{
    if (Left == Right) return Left;
    if (Left == HV_MEMORY_TYPE_UC || Right == HV_MEMORY_TYPE_UC) {
        return HV_MEMORY_TYPE_UC;
    }
    if ((Left == HV_MEMORY_TYPE_WT && Right == HV_MEMORY_TYPE_WB) ||
        (Left == HV_MEMORY_TYPE_WB && Right == HV_MEMORY_TYPE_WT)) {
        return HV_MEMORY_TYPE_WT;
    }
    return HV_MEMORY_TYPE_UC;
}

static UCHAR
HvEptpMemoryTypeAt(_In_ ULONG64 PhysicalAddress)
{
    UCHAR type;
    BOOLEAN matched = FALSE;

    if (!g_EptMtrr.Initialized) {
        return HV_MEMORY_TYPE_UC;
    }

    if (PhysicalAddress < 0x100000) {
        for (ULONG i = 0; i < g_EptMtrr.RangeCount; i++) {
            PHV_EPT_MTRR_RANGE range = &g_EptMtrr.Ranges[i];
            if (range->Fixed && PhysicalAddress >= range->Base &&
                PhysicalAddress <= range->End) {
                return range->MemoryType;
            }
        }
    }

    type = g_EptMtrr.DefaultMemoryType;
    for (ULONG i = 0; i < g_EptMtrr.RangeCount; i++) {
        PHV_EPT_MTRR_RANGE range = &g_EptMtrr.Ranges[i];
        if (range->Fixed || PhysicalAddress < range->Base ||
            PhysicalAddress > range->End) {
            continue;
        }
        if (!matched) {
            type = range->MemoryType;
            matched = TRUE;
        } else {
            type = HvEptpCombineMemoryTypes(type, range->MemoryType);
        }
    }
    return type;
}

UCHAR
HvEptGetMemoryType(_In_ ULONG64 PhysicalAddress, _In_ SIZE_T Size)
{
    UNREFERENCED_PARAMETER(Size);
    return HvEptpMemoryTypeAt(PhysicalAddress);
}

BOOLEAN
HvEptIsUniformMemoryType(
    _In_ ULONG64 PhysicalAddress,
    _In_ SIZE_T Size,
    _Out_ PUCHAR MemoryType
)
{
    ULONG64 end;

    if (!MemoryType || Size == 0 ||
        PhysicalAddress > MAXULONG64 - ((ULONG64)Size - 1ULL)) {
        return FALSE;
    }

    end = PhysicalAddress + (ULONG64)Size - 1ULL;
    *MemoryType = HvEptpMemoryTypeAt(PhysicalAddress);

    for (ULONG i = 0; i < g_EptMtrr.RangeCount; i++) {
        PHV_EPT_MTRR_RANGE range = &g_EptMtrr.Ranges[i];
        if (range->Fixed && PhysicalAddress >= 0x100000) {
            continue;
        }
        if ((range->Base > PhysicalAddress && range->Base <= end) ||
            (range->End >= PhysicalAddress && range->End < end)) {
            return FALSE;
        }
    }
    return TRUE;
}

BOOLEAN
HvCheckEptSupport(VOID)
{
    ULONG64 eptVpidCap = __readmsr(MSR_IA32_VMX_EPT_VPID_CAP);

    if (!(eptVpidCap & 0x1)) {
        DbgPrint("[HV] CPU does not support EPT execute-only pages\n");
        return FALSE;
    }
    if (!(eptVpidCap & (1ULL << 8)) || !(eptVpidCap & (1ULL << 14))) {
        DbgPrint("[HV] CPU does not support required EPT UC/WB memory types\n");
        return FALSE;
    }
    if (!(eptVpidCap & (1ULL << 6))) {
        DbgPrint("[HV] CPU does not support EPT 4-level page walks\n");
        return FALSE;
    }
    return TRUE;
}

BOOLEAN
HvEptCanRegisterSplitPt(_In_ PEPT_TABLES EptTables)
{
    return EptTables &&
           EptTables->SplitPtCount < RTL_NUMBER_OF(EptTables->SplitPt);
}

NTSTATUS
HvEptRegisterSplitPt(
    _Inout_ PEPT_TABLES EptTables,
    _In_ PEPT_PTE SplitPt,
    _In_ PHYSICAL_ADDRESS SplitPtPhysical,
    _In_ BOOLEAN Owned
)
{
    ULONG index;

    if (!EptTables || !SplitPt) {
        return STATUS_INVALID_PARAMETER;
    }

    for (index = 0; index < EptTables->SplitPtCount; index++) {
        if (EptTables->SplitPt[index] == SplitPt ||
            EptTables->SplitPtPhysical[index].QuadPart == SplitPtPhysical.QuadPart) {
            if (Owned) EptTables->SplitPtOwned[index] = TRUE;
            return STATUS_SUCCESS;
        }
    }

    if (!HvEptCanRegisterSplitPt(EptTables)) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    index = EptTables->SplitPtCount++;
    EptTables->SplitPt[index] = SplitPt;
    EptTables->SplitPtPhysical[index] = SplitPtPhysical;
    EptTables->SplitPtOwned[index] = Owned;
    return STATUS_SUCCESS;
}

PEPT_PTE
HvEptAllocateSplitPt(
    _Inout_ PEPT_TABLES EptTables,
    _Out_ PPHYSICAL_ADDRESS SplitPtPhysical
)
{
    PHYSICAL_ADDRESS maxAddress;
    PEPT_PTE splitPt;

    if (!SplitPtPhysical || !HvEptCanRegisterSplitPt(EptTables)) {
        return NULL;
    }

    maxAddress.QuadPart = -1LL;
    splitPt = (PEPT_PTE)MmAllocateContiguousMemory(PAGE_SIZE, maxAddress);
    if (!splitPt) {
        return NULL;
    }

    RtlZeroMemory(splitPt, PAGE_SIZE);
    *SplitPtPhysical = MmGetPhysicalAddress(splitPt);
    if (!NT_SUCCESS(HvEptRegisterSplitPt(
            EptTables, splitPt, *SplitPtPhysical, TRUE))) {
        MmFreeContiguousMemory(splitPt);
        SplitPtPhysical->QuadPart = 0;
        return NULL;
    }
    return splitPt;
}

PEPT_PTE
HvEptFindSplitPt(
    _In_ PEPT_TABLES EptTables,
    _In_ ULONG64 SplitPtPfn
)
{
    if (!EptTables) return NULL;

    for (ULONG i = 0; i < EptTables->SplitPtCount; i++) {
        if ((ULONG64)(EptTables->SplitPtPhysical[i].QuadPart >> PAGE_SHIFT) ==
            SplitPtPfn) {
            return EptTables->SplitPt[i];
        }
    }
    return NULL;
}

VOID
HvEptFreeTables(_In_opt_ PEPT_TABLES EptTables)
{
    if (!EptTables) return;

    for (ULONG i = 0; i < EptTables->SplitPtCount; i++) {
        if (EptTables->SplitPt[i] && EptTables->SplitPtOwned[i]) {
            MmFreeContiguousMemory(EptTables->SplitPt[i]);
        }
        EptTables->SplitPt[i] = NULL;
        EptTables->SplitPtPhysical[i].QuadPart = 0;
        EptTables->SplitPtOwned[i] = FALSE;
    }
    EptTables->SplitPtCount = 0;

    for (ULONG i = 0; i < RTL_NUMBER_OF(EptTables->ExtraPdpt); i++) {
        if (EptTables->ExtraPdpt[i]) {
            MmFreeContiguousMemory(EptTables->ExtraPdpt[i]);
            EptTables->ExtraPdpt[i] = NULL;
        }
    }
    MmFreeContiguousMemory(EptTables);
}

NTSTATUS
HvSetupEpt(_Inout_ PVCPU_DATA VcpuData)
{
    PHYSICAL_ADDRESS maxPhysicalAddress;
    NTSTATUS status;

    if (!VcpuData || !HvCheckEptSupport()) {
        return STATUS_NOT_SUPPORTED;
    }
    if (!g_EptMtrr.Initialized) {
        return STATUS_DEVICE_NOT_READY;
    }

    maxPhysicalAddress.QuadPart = -1LL;
    VcpuData->EptTables = (PEPT_TABLES)MmAllocateContiguousMemory(
        sizeof(EPT_TABLES), maxPhysicalAddress);
    if (!VcpuData->EptTables) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(VcpuData->EptTables, sizeof(EPT_TABLES));
    VcpuData->EptTables->Pml4Physical =
        MmGetPhysicalAddress(&VcpuData->EptTables->Pml4[0]);

    status = HvBuildEptIdentityMap(VcpuData);
    if (!NT_SUCCESS(status)) {
        HvEptFreeTables(VcpuData->EptTables);
        VcpuData->EptTables = NULL;
        return status;
    }
    return STATUS_SUCCESS;
}

NTSTATUS
HvEptBuildIdentityInto(_Inout_ PEPT_TABLES EptTables)
{
    PHYSICAL_ADDRESS pdptPhysical;
    ULONG splitCount = 0;

    if (!EptTables) return STATUS_INVALID_PARAMETER;
    if (!g_EptMtrr.Initialized) return STATUS_DEVICE_NOT_READY;

    EptTables->SplitPtCount = 0;
    RtlZeroMemory(EptTables->SplitPt, sizeof(EptTables->SplitPt));
    RtlZeroMemory(EptTables->SplitPtPhysical, sizeof(EptTables->SplitPtPhysical));
    RtlZeroMemory(EptTables->SplitPtOwned, sizeof(EptTables->SplitPtOwned));
    RtlZeroMemory(EptTables->ExtraPdpt, sizeof(EptTables->ExtraPdpt));

    EptTables->Pml4Physical = MmGetPhysicalAddress(&EptTables->Pml4[0]);
    pdptPhysical = MmGetPhysicalAddress(&EptTables->Pdpt[0]);
    EptTables->PdptPhysical = pdptPhysical;

    EptTables->Pml4[0].Value = 0;
    EptTables->Pml4[0].PageFrameNumber = pdptPhysical.QuadPart >> PAGE_SHIFT;
    EptTables->Pml4[0].Read = 1;
    EptTables->Pml4[0].Write = 1;
    EptTables->Pml4[0].Execute = 1;

    for (ULONG64 pdptIndex = 0; pdptIndex < 512; pdptIndex++) {
        EPT_PDPTE* pdpte = &EptTables->Pdpt[pdptIndex];
        PHYSICAL_ADDRESS pdPhysical =
            MmGetPhysicalAddress(&EptTables->Pd[pdptIndex][0]);

        pdpte->Value = 0;
        pdpte->PageFrameNumber = pdPhysical.QuadPart >> PAGE_SHIFT;
        pdpte->Read = 1;
        pdpte->Write = 1;
        pdpte->Execute = 1;

        for (ULONG64 pdIndex = 0; pdIndex < 512; pdIndex++) {
            EPT_PDE* pde = &EptTables->Pd[pdptIndex][pdIndex];
            ULONG64 physicalAddress =
                (pdptIndex * 512ULL + pdIndex) * 0x200000ULL;
            UCHAR memoryType = HV_MEMORY_TYPE_UC;

            if (HvEptIsUniformMemoryType(
                    physicalAddress, 0x200000, &memoryType)) {
                pde->Value = 0;
                pde->Read = 1;
                pde->Write = 1;
                pde->Execute = 1;
                pde->Value |= (1ULL << 7);
                pde->Value |= ((ULONG64)memoryType << 3);
                pde->PageFrameNumber = physicalAddress >> PAGE_SHIFT;
            } else {
                PHYSICAL_ADDRESS ptPhysical;
                PEPT_PTE pt = HvEptAllocateSplitPt(EptTables, &ptPhysical);
                if (!pt) {
                    DbgPrint("[HV] EPT MTRR split allocation failed at PA 0x%llX\n",
                             physicalAddress);
                    return STATUS_INSUFFICIENT_RESOURCES;
                }

                for (ULONG i = 0; i < 512; i++) {
                    ULONG64 pageAddress = physicalAddress +
                                          ((ULONG64)i * PAGE_SIZE);
                    pt[i].Value = 0;
                    pt[i].Read = 1;
                    pt[i].Write = 1;
                    pt[i].Execute = 1;
                    pt[i].MemoryType = HvEptGetMemoryType(pageAddress, PAGE_SIZE);
                    pt[i].PageFrameNumber = pageAddress >> PAGE_SHIFT;
                }

                pde->Value = 0;
                pde->Read = 1;
                pde->Write = 1;
                pde->Execute = 1;
                pde->PageFrameNumber = ptPhysical.QuadPart >> PAGE_SHIFT;
                splitCount++;
            }
        }
    }

    for (ULONG pml4Index = 1; pml4Index < 4; pml4Index++) {
        PHYSICAL_ADDRESS maxPhysicalAddress;
        PEPT_PDPTE extraPdpt;
        PHYSICAL_ADDRESS extraPdptPhysical;

        maxPhysicalAddress.QuadPart = -1LL;
        extraPdpt = (PEPT_PDPTE)MmAllocateContiguousMemory(
            PAGE_SIZE, maxPhysicalAddress);
        if (!extraPdpt) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        RtlZeroMemory(extraPdpt, PAGE_SIZE);
        extraPdptPhysical = MmGetPhysicalAddress(extraPdpt);
        EptTables->ExtraPdpt[pml4Index - 1] = extraPdpt;

        EptTables->Pml4[pml4Index].Value = 0;
        EptTables->Pml4[pml4Index].PageFrameNumber =
            extraPdptPhysical.QuadPart >> PAGE_SHIFT;
        EptTables->Pml4[pml4Index].Read = 1;
        EptTables->Pml4[pml4Index].Write = 1;
        EptTables->Pml4[pml4Index].Execute = 1;

        for (ULONG64 pdptIndex = 0; pdptIndex < 512; pdptIndex++) {
            ULONG64 physicalAddress =
                ((ULONG64)pml4Index * 512ULL + pdptIndex) * 0x40000000ULL;
            EPT_PDPTE* pdpte = &extraPdpt[pdptIndex];
            pdpte->Value = 0;
            pdpte->Read = 1;
            pdpte->Write = 1;
            pdpte->Execute = 1;
            pdpte->Value |= (1ULL << 7);
            pdpte->Value |= ((ULONG64)HV_MEMORY_TYPE_UC << 3);
            pdpte->PageFrameNumber = physicalAddress >> PAGE_SHIFT;
        }
    }

    DbgPrint("[HV] EPT identity map ready: %u MTRR-split 2MB ranges\n",
             splitCount);
    return STATUS_SUCCESS;
}

NTSTATUS
HvBuildEptIdentityMap(_Inout_ PVCPU_DATA VcpuData)
{
    if (!VcpuData || !VcpuData->EptTables) {
        return STATUS_INVALID_PARAMETER;
    }
    return HvEptBuildIdentityInto(VcpuData->EptTables);
}

VOID
HvCleanupEpt(_Inout_ PVCPU_DATA VcpuData)
{
    if (!VcpuData) return;

    if (VcpuData->EptPebSpoof &&
        VcpuData->EptPebSpoof != VcpuData->EptTables) {
        HvEptFreeTables(VcpuData->EptPebSpoof);
        VcpuData->EptPebSpoof = NULL;
    }
    if (VcpuData->EptTables) {
        HvEptFreeTables(VcpuData->EptTables);
        VcpuData->EptTables = NULL;
    }
}
