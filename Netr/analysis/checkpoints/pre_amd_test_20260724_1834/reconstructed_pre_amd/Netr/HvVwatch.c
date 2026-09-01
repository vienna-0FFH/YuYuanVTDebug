/*
 * HvVwatch.c - 虚拟硬件断点 (EPT-based watch point) — P129 全面优化版
 */

#include "HvVwatch.h"
#include "HvCompat.h"
#include "HvEpt.h"
#include "HvPebCloak.h"        // EptPebSpoof 实例 (P125)
#include "EptHook.h"           // EptInveptAllContexts
#include "HvPhysAccess.h"
#include "HvVtRoot.h"          // HvVtRootResolveUserCr3 / HvVtRootWalkGvaToHpa
#include "HvDebugger.h"
#include "HvInjection.h"
#include "HvCore.h"
#include "SimpleHypervisor.h"
#include <ntstrsafe.h>

NTKERNELAPI NTSTATUS PsLookupThreadByThreadId(
    _In_ HANDLE ThreadId,
    _Out_ PETHREAD* Thread);

#define HV_TRACE_THIS_CAT HV_TRACE_CAT_DEBUG
#include "HvTrace.h"

#ifndef HV_ENABLE_VWATCH
#define HV_ENABLE_VWATCH 1
#endif

#define HV_VWATCH_TAG  'WvCh'

// VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS bit27 = MTF
#ifndef CPU_BASED_MONITOR_TRAP_FLAG
#define CPU_BASED_MONITOR_TRAP_FLAG (1U << 27)
#endif

// EPT violation Exit qualification bits
#define EPT_VIO_READ    (1ULL << 0)
#define EPT_VIO_WRITE   (1ULL << 1)
#define EPT_VIO_FETCH   (1ULL << 2)

// ============================================================
// 全局
// ============================================================

HV_VWATCH_MANAGER g_VwatchManager = { 0 };

#define HV_VWATCH_RUNDOWN_CLOSED   0x1
#define HV_VWATCH_RUNDOWN_REF_BIAS 0x2

#define HV_VWATCH_MTF_IDLE         0
#define HV_VWATCH_MTF_PUBLISHING   1
#define HV_VWATCH_MTF_ARMED        2
#define HV_VWATCH_MTF_COMPLETING   3

static __forceinline ULONG
HvVwatchpCpuIndex(_In_opt_ PVCPU_DATA VcpuData)
{
    if (!VcpuData || VcpuData->ProcessorNumber >= HV_VWATCH_MAX_CPUS) {
        return MAXULONG;
    }
    return VcpuData->ProcessorNumber;
}

static __forceinline UINT64
HvVwatchpGuestCr3(_In_ PVCPU_DATA VcpuData)
{
    if (HvGetCpuVendor() == CPU_VENDOR_AMD) {
        return (VcpuData && VcpuData->Vmcb)
            ? VcpuData->Vmcb->StateSaveArea.Cr3
            : 0;
    }

    SIZE_T value = 0;
    __vmx_vmread(GUEST_CR3, &value);
    return (UINT64)value;
}

static __forceinline VOID
HvVwatchpInvalidateCurrentEpt(_In_ PVCPU_DATA VcpuData)
{
    SIZE_T eptp = 0;
    if (!VcpuData || HvGetCpuVendor() != CPU_VENDOR_INTEL ||
        __vmx_vmread(VMCS_CTRL_EPTP, &eptp) != 0 || !eptp ||
        AsmInveptSingleContext((ULONG64)eptp) != 0) {
        (void)AsmInveptAllContexts();
    }
}

static __forceinline VOID
HvVwatchpSetGuestRip(_In_ PVCPU_DATA VcpuData, _In_ UINT64 Rip)
{
    if (HvGetCpuVendor() == CPU_VENDOR_AMD) {
        if (VcpuData && VcpuData->Vmcb) {
            VcpuData->Vmcb->StateSaveArea.Rip = Rip;
            VcpuData->Vmcb->ControlArea.VmcbCleanBits = 0;
        }
        return;
    }
    __vmx_vmwrite(GUEST_RIP, Rip);
}

static __forceinline PVOID
HvVwatchpCurrentThreadToken(VOID)
{
#if defined(_M_AMD64)
    return (PVOID)(ULONG_PTR)__readgsqword(0x188);
#else
    return NULL;
#endif
}

static __forceinline BOOLEAN
HvVwatchpAcquireRootRundown(_Inout_ volatile LONG* Rundown)
{
    LONG value = InterlockedCompareExchange(Rundown, 0, 0);
    for (;;) {
        if (value & HV_VWATCH_RUNDOWN_CLOSED) return FALSE;
        LONG observed = InterlockedCompareExchange(
            Rundown,
            value + HV_VWATCH_RUNDOWN_REF_BIAS,
            value);
        if (observed == value) return TRUE;
        value = observed;
    }
}

static __forceinline VOID
HvVwatchpReleaseRootRundown(_Inout_ volatile LONG* Rundown)
{
    InterlockedAdd(Rundown, -HV_VWATCH_RUNDOWN_REF_BIAS);
}

static VOID
HvVwatchpBeginRootRundown(_Inout_ volatile LONG* Rundown)
{
    LONG value = InterlockedCompareExchange(Rundown, 0, 0);
    while (!(value & HV_VWATCH_RUNDOWN_CLOSED)) {
        LONG observed = InterlockedCompareExchange(
            Rundown,
            value | HV_VWATCH_RUNDOWN_CLOSED,
            value);
        if (observed == value) return;
        value = observed;
    }
}

static VOID
HvVwatchpWaitForRootRundown(_Inout_ volatile LONG* Rundown)
{
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
    while (InterlockedCompareExchange(Rundown, 0, 0) !=
           HV_VWATCH_RUNDOWN_CLOSED) {
        LARGE_INTEGER delay;
        delay.QuadPart = -10000;
        KeDelayExecutionThread(KernelMode, FALSE, &delay);
    }
}

static VOID
HvVwatchpAcquireRefreshLockPassive(_Inout_ PHV_PRIVATE_SWBP_PAGE Page)
{
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
    while (InterlockedCompareExchange(&Page->RefreshLock, 1, 0) != 0) {
        LARGE_INTEGER delay;
        delay.QuadPart = -10000;
        KeDelayExecutionThread(KernelMode, FALSE, &delay);
    }
}

static VOID
HvVwatchpRebuildOverlaySnapshotLocked(VOID)
{
    ULONG count = 0;
    InterlockedIncrement(&g_VwatchManager.OverlaySnapshotSequence);
    KeMemoryBarrier();

    for (LONG index = 0; index < HV_VWATCH_MAX_ENTRIES; index++) {
        PHV_VWATCH_ENTRY entry = &g_VwatchManager.Entries[index];
        if (!entry->InUse || !entry->UserCr3) continue;

        UINT64 cr3 = entry->UserCr3 & ~((UINT64)0xFFF);
        BOOLEAN duplicate = FALSE;
        for (ULONG targetIndex = 0; targetIndex < count; targetIndex++) {
            if (g_VwatchManager.OverlayTargetCr3[targetIndex] == cr3) {
                duplicate = TRUE;
                break;
            }
        }
        if (!duplicate && count < HV_VWATCH_MAX_OVERLAY_TARGETS) {
            g_VwatchManager.OverlayTargetCr3[count++] = cr3;
        }
    }

    for (LONG index = 0; index < HV_PRIVATE_SWBP_MAX_PAGES; index++) {
        PHV_PRIVATE_SWBP_PAGE page = &g_VwatchManager.SwBpPages[index];
        if (!page->InUse || page->DirectMainEpt || !page->UserCr3) continue;

        UINT64 cr3 = page->UserCr3 & ~((UINT64)0xFFF);
        BOOLEAN duplicate = FALSE;
        for (ULONG targetIndex = 0; targetIndex < count; targetIndex++) {
            if (g_VwatchManager.OverlayTargetCr3[targetIndex] == cr3) {
                duplicate = TRUE;
                break;
            }
        }
        if (!duplicate && count < HV_VWATCH_MAX_OVERLAY_TARGETS) {
            g_VwatchManager.OverlayTargetCr3[count++] = cr3;
        }
    }

    g_VwatchManager.OverlayTargetCount = count;
    KeMemoryBarrier();
    InterlockedIncrement(&g_VwatchManager.OverlaySnapshotSequence);
}

static VOID
HvVwatchpInvalidateOverlayClassifierCache(VOID)
{
    if (!g_HypervisorContext.VcpuData) return;

    ULONG cpuCount = g_HypervisorContext.ProcessorCount;
    if (cpuCount > HV_VWATCH_MAX_CPUS) cpuCount = HV_VWATCH_MAX_CPUS;
    for (ULONG cpuIndex = 0; cpuIndex < cpuCount; cpuIndex++) {
        PVCPU_DATA vcpu = &g_HypervisorContext.VcpuData[cpuIndex];
        InterlockedExchange64((volatile LONG64*)&vcpu->LastSnoopedCr3, 0);
        InterlockedExchange(
            (volatile LONG*)&vcpu->LastCallerClass,
            HV_PEB_CLASS_UNKNOWN);
    }
}

BOOLEAN HvVwatchHasOverlayTargets(VOID)
{
    for (ULONG retry = 0; retry < 4; retry++) {
        LONG before = InterlockedCompareExchange(
            &g_VwatchManager.OverlaySnapshotSequence, 0, 0);
        if (before & 1) break;
        ULONG count = g_VwatchManager.OverlayTargetCount;
        KeMemoryBarrier();
        LONG after = InterlockedCompareExchange(
            &g_VwatchManager.OverlaySnapshotSequence, 0, 0);
        if (before == after) return count != 0;
    }
    if (InterlockedCompareExchange(&g_VwatchManager.EntryCount, 0, 0) > 0) {
        return TRUE;
    }
    for (LONG index = 0; index < HV_PRIVATE_SWBP_MAX_PAGES; index++) {
        PHV_PRIVATE_SWBP_PAGE page = &g_VwatchManager.SwBpPages[index];
        if (InterlockedCompareExchange(&page->InUse, 0, 0) != 0 &&
            !page->DirectMainEpt) {
            return TRUE;
        }
    }
    return FALSE;
}

static BOOLEAN
HvVwatchpTryAdoptScopedOverlayCr3Root(
    _In_ UINT64 UserCr3,
    _In_opt_ PVOID ThreadToken)
{
    if (!ThreadToken ||
        InterlockedCompareExchange(
            &g_VwatchManager.ScopedSwBpEntryCount, 0, 0) == 0) {
        return FALSE;
    }
    UserCr3 &= ~((UINT64)0xFFF);
    if (!UserCr3) return FALSE;

    for (LONG index = 0; index < HV_PRIVATE_SWBP_MAX_ENTRIES; index++) {
        PHV_PRIVATE_SWBP_ENTRY entry = &g_VwatchManager.SwBpEntries[index];
        if (InterlockedCompareExchange(&entry->InUse, 0, 0) == 0 ||
            (PVOID)InterlockedCompareExchangePointer(
                (PVOID volatile*)&entry->ScopeThreadToken,
                NULL,
                NULL) != ThreadToken ||
            !HvVwatchpAcquireRootRundown(&entry->RootRundown)) {
            continue;
        }

        KeMemoryBarrier();
        BOOLEAN adopted = FALSE;
        if (InterlockedCompareExchange(&entry->InUse, 0, 0) != 0 &&
            (PVOID)InterlockedCompareExchangePointer(
                (PVOID volatile*)&entry->ScopeThreadToken,
                NULL,
                NULL) == ThreadToken &&
            entry->PageIndex >= 0 &&
            entry->PageIndex < HV_PRIVATE_SWBP_MAX_PAGES) {
            PHV_PRIVATE_SWBP_PAGE page =
                &g_VwatchManager.SwBpPages[entry->PageIndex];
            if (InterlockedCompareExchange(&page->InUse, 0, 0) != 0 &&
                !page->DirectMainEpt &&
                InterlockedCompareExchange(&page->Invalidated, 0, 0) == 0 &&
                page->TargetPid == entry->TargetPid) {
                InterlockedExchange64(
                    (volatile LONG64*)&entry->UserCr3,
                    (LONG64)UserCr3);
                InterlockedExchange64(
                    (volatile LONG64*)&page->UserCr3,
                    (LONG64)UserCr3);
                adopted = TRUE;
            }
        }
        HvVwatchpReleaseRootRundown(&entry->RootRundown);
        if (adopted) return TRUE;
    }
    return FALSE;
}

static BOOLEAN
HvVwatchpIsScopedOverlayCr3Root(_In_ UINT64 UserCr3)
{
    if (InterlockedCompareExchange(
            &g_VwatchManager.ScopedSwBpEntryCount, 0, 0) == 0) {
        return FALSE;
    }
    UserCr3 &= ~((UINT64)0xFFF);
    if (!UserCr3) return FALSE;

    for (LONG index = 0; index < HV_PRIVATE_SWBP_MAX_ENTRIES; index++) {
        PHV_PRIVATE_SWBP_ENTRY entry = &g_VwatchManager.SwBpEntries[index];
        if (InterlockedCompareExchange(&entry->InUse, 0, 0) == 0 ||
            !InterlockedCompareExchangePointer(
                (PVOID volatile*)&entry->ScopeThreadToken,
                NULL,
                NULL) ||
            (entry->UserCr3 & ~((UINT64)0xFFF)) != UserCr3 ||
            !HvVwatchpAcquireRootRundown(&entry->RootRundown)) {
            continue;
        }

        KeMemoryBarrier();
        BOOLEAN found =
            InterlockedCompareExchange(&entry->InUse, 0, 0) != 0 &&
            InterlockedCompareExchangePointer(
                (PVOID volatile*)&entry->ScopeThreadToken,
                NULL,
                NULL) != NULL &&
            (entry->UserCr3 & ~((UINT64)0xFFF)) == UserCr3;
        HvVwatchpReleaseRootRundown(&entry->RootRundown);
        if (found) return TRUE;
    }
    return FALSE;
}

BOOLEAN HvVwatchTryAdoptScopedOverlayCr3ByMappingRoot(
    _In_ PVCPU_DATA VcpuData,
    _In_ UINT64 Cr3)
{
    if (!VcpuData || VcpuData->IsInL2 ||
        InterlockedCompareExchange(
            &g_VwatchManager.ScopedSwBpEntryCount, 0, 0) == 0) {
        return FALSE;
    }
    Cr3 &= ~((UINT64)0xFFF);
    if (!Cr3) return FALSE;
    if (HvVwatchpIsScopedOverlayCr3Root(Cr3)) return TRUE;

    for (LONG index = 0; index < HV_PRIVATE_SWBP_MAX_ENTRIES; index++) {
        PHV_PRIVATE_SWBP_ENTRY entry = &g_VwatchManager.SwBpEntries[index];
        if (InterlockedCompareExchange(&entry->InUse, 0, 0) == 0 ||
            !InterlockedCompareExchangePointer(
                (PVOID volatile*)&entry->ScopeThreadToken,
                NULL,
                NULL) ||
            !HvVwatchpAcquireRootRundown(&entry->RootRundown)) {
            continue;
        }

        KeMemoryBarrier();
        BOOLEAN adopted = FALSE;
        LONG pageIndex = entry->PageIndex;
        if (InterlockedCompareExchange(&entry->InUse, 0, 0) != 0 &&
            InterlockedCompareExchangePointer(
                (PVOID volatile*)&entry->ScopeThreadToken,
                NULL,
                NULL) != NULL &&
            pageIndex >= 0 && pageIndex < HV_PRIVATE_SWBP_MAX_PAGES) {
            PHV_PRIVATE_SWBP_PAGE page =
                &g_VwatchManager.SwBpPages[pageIndex];
            if (InterlockedCompareExchange(&page->InUse, 0, 0) != 0 &&
                !page->DirectMainEpt &&
                InterlockedCompareExchange(&page->Invalidated, 0, 0) == 0 &&
                page->TargetPid == entry->TargetPid) {
                UINT64 hpa = 0;
                UINT64 pageSize = 0;
                NTSTATUS status = HvVtRootRootWalkGvaToHpaWithCr3(
                    VcpuData,
                    Cr3,
                    entry->Address,
                    &hpa,
                    &pageSize);
                UNREFERENCED_PARAMETER(pageSize);
                if (NT_SUCCESS(status) &&
                    (hpa & ~((UINT64)PAGE_SIZE - 1)) == page->GpaPage) {
                    InterlockedExchange64(
                        (volatile LONG64*)&entry->UserCr3,
                        (LONG64)Cr3);
                    InterlockedExchange64(
                        (volatile LONG64*)&page->UserCr3,
                        (LONG64)Cr3);
                    adopted = TRUE;
                }
            }
        }
        HvVwatchpReleaseRootRundown(&entry->RootRundown);
        if (adopted) return TRUE;
    }
    return FALSE;
}

BOOLEAN HvVwatchTryIsOverlayTargetCr3Ex(
    _In_ UINT64 Cr3,
    _Out_ PBOOLEAN IsTarget,
    _Out_ PULONG Generation)
{
    if (!IsTarget || !Generation) return FALSE;
    *IsTarget = FALSE;
    *Generation = 0;
    if (!Cr3) return TRUE;
    Cr3 &= ~((UINT64)0xFFF);

    for (ULONG retry = 0; retry < 4; retry++) {
        LONG before = InterlockedCompareExchange(
            &g_VwatchManager.OverlaySnapshotSequence, 0, 0);
        if (before & 1) return FALSE;

        ULONG count = g_VwatchManager.OverlayTargetCount;
        if (count > HV_VWATCH_MAX_OVERLAY_TARGETS) {
            count = HV_VWATCH_MAX_OVERLAY_TARGETS;
        }
        BOOLEAN found = FALSE;
        for (ULONG index = 0; index < count; index++) {
            if (g_VwatchManager.OverlayTargetCr3[index] == Cr3) {
                found = TRUE;
                break;
            }
        }

        KeMemoryBarrier();
        LONG after = InterlockedCompareExchange(
            &g_VwatchManager.OverlaySnapshotSequence, 0, 0);
        if (before == after) {
            if (!found) {
                found = HvVwatchpTryAdoptScopedOverlayCr3Root(
                    Cr3,
                    HvVwatchpCurrentThreadToken());
            }
            if (!found) {
                found = HvVwatchpIsScopedOverlayCr3Root(Cr3);
            }
            *IsTarget = found;
            *Generation = (ULONG)after;
            return TRUE;
        }
    }
    return FALSE;
}

BOOLEAN HvVwatchTryIsOverlayTargetCr3(
    _In_ UINT64 Cr3,
    _Out_ PBOOLEAN IsTarget)
{
    ULONG generation = 0;
    return HvVwatchTryIsOverlayTargetCr3Ex(
        Cr3,
        IsTarget,
        &generation);
}

BOOLEAN HvVwatchOverlayGenerationIsCurrent(_In_ ULONG Generation)
{
    LONG current = InterlockedCompareExchange(
        &g_VwatchManager.OverlaySnapshotSequence,
        0,
        0);
    return !(current & 1) && (ULONG)current == Generation;
}

BOOLEAN HvVwatchIsOverlayTargetCr3(_In_ UINT64 Cr3)
{
    BOOLEAN isTarget = FALSE;
    return HvVwatchTryIsOverlayTargetCr3(Cr3, &isTarget) && isTarget;
}

BOOLEAN HvVwatchIsVirtualHardwareBreakpointSupported(VOID)
{
    if (!g_VwatchManager.Initialized ||
        HvGetCpuVendor() != CPU_VENDOR_INTEL ||
        !g_HypervisorContext.IsActive ||
        !g_HypervisorContext.VcpuData ||
        g_HypervisorContext.ProcessorCount == 0 ||
        g_HypervisorContext.ProcessorCount > HV_VWATCH_MAX_CPUS) {
        return FALSE;
    }

    for (ULONG cpuIndex = 0;
         cpuIndex < g_HypervisorContext.ProcessorCount;
         cpuIndex++) {
        if (!g_HypervisorContext.VcpuData[cpuIndex].EptPebSpoof) {
            return FALSE;
        }
    }
    return TRUE;
}

BOOLEAN HvVwatchIsPrivateSoftwareBreakpointSupported(VOID)
{
    return HvVwatchIsVirtualHardwareBreakpointSupported() &&
           g_EptHookManager.ExecuteOnlySupported;
}

BOOLEAN HvVwatchIsVtStepSupported(VOID)
{
    return HvVwatchIsPrivateSoftwareBreakpointSupported();
}

BOOLEAN HvVwatchOverlayPageOwned(_In_ ULONG64 GpaPage)
{
    if (!g_VwatchManager.Initialized) return FALSE;
    GpaPage &= ~((ULONG64)PAGE_SIZE - 1);

    BOOLEAN owned = FALSE;
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_VwatchManager.Lock, &oldIrql);
    for (LONG index = 0; index < HV_VWATCH_MAX_PAGES; index++) {
        PHV_VWATCH_PAGE page = &g_VwatchManager.Pages[index];
        if (page->InUse && page->GpaPage == GpaPage) {
            owned = TRUE;
            break;
        }
    }
    if (!owned) {
        for (LONG index = 0;
             index < HV_PRIVATE_SWBP_MAX_PAGES;
             index++) {
            PHV_PRIVATE_SWBP_PAGE page =
                &g_VwatchManager.SwBpPages[index];
            if (page->InUse && page->GpaPage == GpaPage) {
                owned = TRUE;
                break;
            }
        }
    }
    KeReleaseSpinLock(&g_VwatchManager.Lock, oldIrql);
    return owned;
}

// ============================================================
// 辅助 - PT slot 操作
// ============================================================

/*
 * 找 EptPebSpoof 上某 GPA 的 PT slot. 必要时 split 2MB.
 */
static PEPT_PTE_ENTRY
HvVwatchpFindOrSplitPtSlot(
    _In_ PEPT_TABLES EptTables,
    _In_ ULONG64 Gpa)
{
    ULONG64 pml4Index = (Gpa >> 39) & 0x1FF;
    ULONG64 pdptIndex = (Gpa >> 30) & 0x1FF;
    ULONG64 pdIndex   = (Gpa >> 21) & 0x1FF;
    ULONG64 ptIndex   = (Gpa >> 12) & 0x1FF;

    if (pml4Index != 0 || pdptIndex >= 512) return NULL;

    EPT_PDE* pde = &EptTables->Pd[pdptIndex][pdIndex];
    if (!(pde->Read || pde->Write || pde->Execute)) return NULL;

    ULONG64 baseGpa = (pdptIndex * 512 + pdIndex) * 0x200000ULL;

    if (pde->Value & (1ULL << 7)) {
        // 2MB Large Page → split
        PHYSICAL_ADDRESS ptPa;
        PEPT_PTE_ENTRY ptTable =
            (PEPT_PTE_ENTRY)HvEptAllocateSplitPt(EptTables, &ptPa);
        if (!ptTable) return NULL;
        RtlZeroMemory(ptTable, PAGE_SIZE);

        for (ULONG i = 0; i < 512; i++) {
            ptTable[i].Value = 0;
            ptTable[i].Read = 1;
            ptTable[i].Write = 1;
            ptTable[i].Execute = 1;
            ptTable[i].MemoryType = HvEptGetMemoryType(
                baseGpa + ((ULONG64)i * PAGE_SIZE), PAGE_SIZE);
            ptTable[i].PhysicalAddress = ((baseGpa >> 12) + i);
        }

        EPT_PDE newPde; newPde.Value = 0;
        newPde.Read = 1;
        newPde.Write = 1;
        newPde.Execute = 1;
        newPde.PageFrameNumber = (ULONG64)(ptPa.QuadPart >> 12);
        pde->Value = newPde.Value;

        return &ptTable[ptIndex];
    } else {
        ULONG64 ptPa = (ULONG64)pde->PageFrameNumber << 12;
        PEPT_PTE splitPt = HvEptFindSplitPt(EptTables, ptPa >> PAGE_SHIFT);
        if (splitPt) return &((PEPT_PTE_ENTRY)splitPt)[ptIndex];
        return NULL;
    }
}

/*
 * 按 trap mask 重写 PT slot. mask=0 → 全 R/W/X 允许.
 */
static VOID
HvVwatchpWritePtSlot(_Inout_ PEPT_PTE_ENTRY Slot, _In_ ULONG64 Pfn, _In_ ULONG Mask)
{
    EPT_PTE_ENTRY newPte; newPte.Value = 0;
    newPte.Read    = (Mask & HV_VWATCH_TRAP_READ)    ? 0 : 1;
    newPte.Write   = (Mask & HV_VWATCH_TRAP_WRITE)   ? 0 : 1;
    newPte.Execute = (Mask & HV_VWATCH_TRAP_EXECUTE) ? 0 : 1;
    newPte.MemoryType = HvEptGetMemoryType(Pfn << PAGE_SHIFT, PAGE_SIZE);
    newPte.PhysicalAddress = Pfn;
    Slot->Value = newPte.Value;
}

static VOID
HvVwatchpWriteSwBpSlot(
    _Inout_ PEPT_PTE_ENTRY Slot,
    _In_ ULONG64 Pfn,
    _In_ BOOLEAN Read,
    _In_ BOOLEAN Write,
    _In_ BOOLEAN Execute)
{
    EPT_PTE_ENTRY newPte;
    newPte.Value = 0;
    newPte.Read = Read ? 1 : 0;
    newPte.Write = Write ? 1 : 0;
    newPte.Execute = Execute ? 1 : 0;
    newPte.MemoryType = HvEptGetMemoryType(Pfn << PAGE_SHIFT, PAGE_SIZE);
    newPte.PhysicalAddress = Pfn;
    InterlockedExchange64(
        (volatile LONG64*)&Slot->Value,
        (LONG64)newPte.Value);
}

/*
 * Type → trap mask
 */
static __forceinline ULONG
HvVwatchpTypeToMask(_In_ ULONG Type)
{
    switch (Type) {
    case HV_VWATCH_TYPE_WRITE:
        return HV_VWATCH_TRAP_WRITE;
    case HV_VWATCH_TYPE_READWRITE:
        return HV_VWATCH_TRAP_READ | HV_VWATCH_TRAP_WRITE;
    case HV_VWATCH_TYPE_EXECUTE:
        return HV_VWATCH_TRAP_EXECUTE;
    default:
        return 0;
    }
}

// ============================================================
// CR3 / GVA 解析
// ============================================================

static NTSTATUS
HvVwatchpResolveUserCr3(_In_ HANDLE Pid, _Out_ PUINT64 OutCr3)
{
    *OutCr3 = 0;
    if (!Pid) return STATUS_INVALID_PARAMETER;

    UINT64 cr3 = 0;
    ULONG pid32 = (ULONG)(ULONG_PTR)Pid;

    NTSTATUS s = HvVtRootResolveUserCr3(pid32, &cr3);
    if (NT_SUCCESS(s) && cr3) { *OutCr3 = cr3; return STATUS_SUCCESS; }

    return NT_SUCCESS(s) ? STATUS_NOT_FOUND : s;
}

static NTSTATUS
HvVwatchpGvaToGpa(
    _In_ ULONG Pid,
    _In_ ULONG64 Gva,
    _Out_ PULONG64 OutGpa)
{
    *OutGpa = 0;
    UINT64 hpa = 0;
    UINT64 pageSize = 0;
    NTSTATUS s = HvVtRootWalkGvaToHpa(Pid, Gva, &hpa, &pageSize);
    if (!NT_SUCCESS(s) || !hpa) return STATUS_NOT_FOUND;
    *OutGpa = hpa;
    return STATUS_SUCCESS;
}

static PHV_PRIVATE_SWBP_ENTRY
HvVwatchpFindSwBpEntryLocked(
    _In_ HANDLE TargetPid,
    _In_ UINT64 Address)
{
    for (LONG index = 0; index < HV_PRIVATE_SWBP_MAX_ENTRIES; index++) {
        PHV_PRIVATE_SWBP_ENTRY entry = &g_VwatchManager.SwBpEntries[index];
        if (entry->InUse &&
            entry->TargetPid == TargetPid &&
            entry->Address == Address) {
            return entry;
        }
    }
    return NULL;
}

static PHV_PRIVATE_SWBP_ENTRY
HvVwatchpFindFreeSwBpEntryLocked(VOID)
{
    for (LONG index = 0; index < HV_PRIVATE_SWBP_MAX_ENTRIES; index++) {
        if (!g_VwatchManager.SwBpEntries[index].InUse &&
            InterlockedCompareExchange(
                &g_VwatchManager.SwBpEntries[index].RootRundown,
                0,
                0) == 0) {
            return &g_VwatchManager.SwBpEntries[index];
        }
    }
    return NULL;
}

static PETHREAD
HvVwatchpTakeSwBpScopeThreadLocked(
    _Inout_ PHV_PRIVATE_SWBP_ENTRY Entry)
{
    PETHREAD thread = (PETHREAD)InterlockedExchangePointer(
        (PVOID volatile*)&Entry->ScopeThreadToken,
        NULL);
    if (thread) {
        InterlockedDecrement(&g_VwatchManager.ScopedSwBpEntryCount);
    }
    return thread;
}

static PHV_PRIVATE_SWBP_PAGE
HvVwatchpFindSwBpPageForVaLocked(
    _In_ HANDLE TargetPid,
    _In_ UINT64 Address)
{
    UINT64 pageVa = Address & ~((UINT64)PAGE_SIZE - 1);
    for (LONG index = 0; index < HV_PRIVATE_SWBP_MAX_ENTRIES; index++) {
        PHV_PRIVATE_SWBP_ENTRY entry = &g_VwatchManager.SwBpEntries[index];
        if (!entry->InUse || entry->TargetPid != TargetPid || entry->PageIndex < 0) {
            continue;
        }
        if ((entry->Address & ~((UINT64)PAGE_SIZE - 1)) == pageVa) {
            return &g_VwatchManager.SwBpPages[entry->PageIndex];
        }
    }
    return NULL;
}

static PHV_PRIVATE_SWBP_PAGE
HvVwatchpFindFreeSwBpPageLocked(VOID)
{
    for (LONG index = 0; index < HV_PRIVATE_SWBP_MAX_PAGES; index++) {
        if (!g_VwatchManager.SwBpPages[index].InUse &&
            InterlockedCompareExchange(
                &g_VwatchManager.SwBpPages[index].RootRundown,
                0,
                0) == 0 &&
            g_VwatchManager.SwBpPages[index].ShadowPageVirtual == NULL &&
            g_VwatchManager.SwBpPages[index].RefreshPageVirtual == NULL) {
            return &g_VwatchManager.SwBpPages[index];
        }
    }
    return NULL;
}

static NTSTATUS
HvVwatchpResolveSwBpPtes(_Inout_ PHV_PRIVATE_SWBP_PAGE Page)
{
    ULONG cpuCount = g_HypervisorContext.ProcessorCount;
    if (!g_HypervisorContext.VcpuData || cpuCount == 0) {
        return STATUS_DEVICE_NOT_READY;
    }
    if (Page->MirrorOverlayEpt && !Page->DirectMainEpt) {
        return STATUS_INVALID_PARAMETER;
    }
    if (cpuCount > HV_VWATCH_MAX_CPUS) cpuCount = HV_VWATCH_MAX_CPUS;

    ULONG resolved = 0;
    for (ULONG cpuIndex = 0; cpuIndex < cpuCount; cpuIndex++) {
        PVCPU_DATA vcpu = &g_HypervisorContext.VcpuData[cpuIndex];
        PEPT_TABLES ept = Page->DirectMainEpt
            ? vcpu->EptTables
            : vcpu->EptPebSpoof;
        if (!ept) return STATUS_DEVICE_NOT_READY;

        PEPT_PTE_ENTRY slot = HvVwatchpFindOrSplitPtSlot(
            ept,
            Page->GpaPage);
        if (!slot) return STATUS_INSUFFICIENT_RESOURCES;

        EPT_PTE_ENTRY current;
        current.Value = *(volatile ULONG64*)&slot->Value;
        if (current.PhysicalAddress != Page->OriginalPfn &&
            current.PhysicalAddress != Page->ShadowPfn) {
            return STATUS_CONFLICTING_ADDRESSES;
        }
        if (current.PhysicalAddress == Page->OriginalPfn &&
            (!current.Read || !current.Write || !current.Execute)) {
            return STATUS_CONFLICTING_ADDRESSES;
        }

        Page->ShadowPte[cpuIndex] = slot;

        if (Page->MirrorOverlayEpt) {
            if (!vcpu->EptPebSpoof) return STATUS_DEVICE_NOT_READY;

            PEPT_PTE_ENTRY mirrorSlot = HvVwatchpFindOrSplitPtSlot(
                vcpu->EptPebSpoof,
                Page->GpaPage);
            if (!mirrorSlot) return STATUS_INSUFFICIENT_RESOURCES;

            EPT_PTE_ENTRY mirrorCurrent;
            mirrorCurrent.Value = *(volatile ULONG64*)&mirrorSlot->Value;
            if (mirrorCurrent.PhysicalAddress != Page->OriginalPfn &&
                mirrorCurrent.PhysicalAddress != Page->ShadowPfn) {
                return STATUS_CONFLICTING_ADDRESSES;
            }
            if (mirrorCurrent.PhysicalAddress == Page->OriginalPfn &&
                (!mirrorCurrent.Read || !mirrorCurrent.Write ||
                 !mirrorCurrent.Execute)) {
                return STATUS_CONFLICTING_ADDRESSES;
            }

            Page->MirrorShadowPte[cpuIndex] = mirrorSlot;
        }
        resolved++;
    }

    return resolved == cpuCount ? STATUS_SUCCESS : STATUS_DEVICE_NOT_READY;
}

static __forceinline VOID
HvVwatchpWriteSwBpPageSlots(
    _Inout_ PHV_PRIVATE_SWBP_PAGE Page,
    _In_ ULONG CpuIndex,
    _In_ ULONG64 Pfn,
    _In_ BOOLEAN Read,
    _In_ BOOLEAN Write,
    _In_ BOOLEAN Execute)
{
    PEPT_PTE_ENTRY slot = Page->ShadowPte[CpuIndex];
    if (slot) {
        HvVwatchpWriteSwBpSlot(slot, Pfn, Read, Write, Execute);
    }

    PEPT_PTE_ENTRY mirrorSlot = Page->MirrorShadowPte[CpuIndex];
    if (mirrorSlot && mirrorSlot != slot) {
        HvVwatchpWriteSwBpSlot(mirrorSlot, Pfn, Read, Write, Execute);
    }
}

static __forceinline PEPT_PTE_ENTRY
HvVwatchpGetActiveSwBpPte(
    _In_ PHV_PRIVATE_SWBP_PAGE Page,
    _In_ PVCPU_DATA Vcpu,
    _In_ ULONG CpuIndex)
{
    if (Page->MirrorOverlayEpt && Vcpu &&
        InterlockedCompareExchange(
            &Vcpu->ActiveEptpIsPebSpoof, 0, 0) != 0) {
        PEPT_PTE_ENTRY mirrorSlot = Page->MirrorShadowPte[CpuIndex];
        if (mirrorSlot) return mirrorSlot;
    }
    return Page->ShadowPte[CpuIndex];
}

static VOID
HvVwatchpActivateSwBpPage(_Inout_ PHV_PRIVATE_SWBP_PAGE Page)
{
    ULONG cpuCount = g_HypervisorContext.ProcessorCount;
    if (cpuCount > HV_VWATCH_MAX_CPUS) cpuCount = HV_VWATCH_MAX_CPUS;
    for (ULONG cpuIndex = 0; cpuIndex < cpuCount; cpuIndex++) {
        PEPT_PTE_ENTRY slot = Page->ShadowPte[cpuIndex];
        if (slot) {
            HvVwatchpWriteSwBpSlot(slot, Page->ShadowPfn, FALSE, FALSE, TRUE);
            InterlockedIncrement64(
                Page->DirectMainEpt
                    ? &g_VwatchManager.SwBpMainSlotPublishes
                    : &g_VwatchManager.SwBpOverlaySlotPublishes);
        }
        PEPT_PTE_ENTRY mirrorSlot = Page->MirrorShadowPte[cpuIndex];
        if (mirrorSlot && mirrorSlot != slot) {
            HvVwatchpWriteSwBpSlot(
                mirrorSlot,
                Page->ShadowPfn,
                FALSE,
                FALSE,
                TRUE);
            InterlockedIncrement64(
                &g_VwatchManager.SwBpOverlaySlotPublishes);
        }
    }
    EptInveptAllContexts();
}

static VOID
HvVwatchpDisableSwBpPageRoot(_Inout_ PHV_PRIVATE_SWBP_PAGE Page)
{
    InterlockedExchange(&Page->Invalidated, 1);
    KeMemoryBarrier();

    ULONG cpuCount = g_HypervisorContext.ProcessorCount;
    if (cpuCount > HV_VWATCH_MAX_CPUS) cpuCount = HV_VWATCH_MAX_CPUS;
    for (ULONG cpuIndex = 0; cpuIndex < cpuCount; cpuIndex++) {
        HvVwatchpWriteSwBpPageSlots(
            Page,
            cpuIndex,
            Page->OriginalPfn,
            TRUE,
            TRUE,
            TRUE);
    }
    EptInveptAllContexts();
}

static BOOLEAN
HvVwatchpRefreshSwBpShadowRoot(
    _Inout_ PHV_PRIVATE_SWBP_PAGE Page,
    _In_ ULONG CpuIndex)
{
    BOOLEAN acquiredEntries[HV_PRIVATE_SWBP_MAX_ENTRIES];
    RtlZeroMemory(acquiredEntries, sizeof(acquiredEntries));

    if (InterlockedCompareExchange(&Page->RefreshLock, 1, 0) != 0) {
        InterlockedExchange(&Page->Invalidated, 1);
        for (ULONG retry = 0;
             retry < 100000 &&
             InterlockedCompareExchange(&Page->RefreshLock, 0, 0) != 0;
             retry++) {
            _mm_pause();
        }
        HvVwatchpDisableSwBpPageRoot(Page);
        return FALSE;
    }
    if (InterlockedCompareExchange(&Page->RootRefreshUsed, 1, 0) != 0) {
        HvVwatchpDisableSwBpPageRoot(Page);
        InterlockedExchange(&Page->RefreshLock, 0);
        return FALSE;
    }

    BOOLEAN refreshed = FALSE;
    PVCPU_DATA vcpu = NULL;
    if (g_HypervisorContext.VcpuData && CpuIndex < HV_VWATCH_MAX_CPUS) {
        vcpu = &g_HypervisorContext.VcpuData[CpuIndex];
    }

    UINT64 currentHpa = 0;
    UINT64 pageSize = 0;
    SIZE_T copied = 0;
    NTSTATUS status = vcpu
        ? HvVtRootRootWalkGvaToHpaWithCr3(
              vcpu,
              Page->UserCr3,
              Page->UserPageVa,
              &currentHpa,
              &pageSize)
        : STATUS_DEVICE_NOT_READY;
    if (!NT_SUCCESS(status) ||
        (currentHpa & ~((UINT64)PAGE_SIZE - 1)) != Page->GpaPage ||
        !Page->RefreshPageVirtual) {
        goto Exit;
    }

    status = HvVtRootRootCopyOnePage(
        vcpu,
        Page->UserCr3,
        Page->UserPageVa,
        (PUCHAR)Page->RefreshPageVirtual,
        PAGE_SIZE,
        FALSE,
        &copied);
    if (!NT_SUCCESS(status) || copied != PAGE_SIZE) goto Exit;

    LONG pageIndex = (LONG)(Page - g_VwatchManager.SwBpPages);
    for (LONG index = 0; index < HV_PRIVATE_SWBP_MAX_ENTRIES; index++) {
        PHV_PRIVATE_SWBP_ENTRY entry = &g_VwatchManager.SwBpEntries[index];
        if (InterlockedCompareExchange(&entry->InUse, 0, 0) == 0 ||
            entry->PageIndex != pageIndex ||
            !HvVwatchpAcquireRootRundown(&entry->RootRundown)) continue;
        acquiredEntries[index] = TRUE;

        KeMemoryBarrier();
        if (InterlockedCompareExchange(&entry->InUse, 0, 0) != 0 &&
            entry->PageIndex == pageIndex &&
            entry->OffsetInPage < PAGE_SIZE) {
            entry->OriginalByte =
                ((PUCHAR)Page->RefreshPageVirtual)[entry->OffsetInPage];
            ((PUCHAR)Page->RefreshPageVirtual)[entry->OffsetInPage] = 0xCC;
        }
    }

    if (InterlockedCompareExchange(&Page->InUse, 0, 0) == 0 ||
        InterlockedCompareExchange(&Page->Invalidated, 0, 0) != 0 ||
        (InterlockedCompareExchange(&Page->RootRundown, 0, 0) &
         HV_VWATCH_RUNDOWN_CLOSED)) goto Exit;

    PVOID oldShadow = Page->ShadowPageVirtual;
    ULONG64 oldShadowPfn = Page->ShadowPfn;
    Page->ShadowPageVirtual = Page->RefreshPageVirtual;
    Page->ShadowPfn = Page->RefreshPfn;
    Page->RefreshPageVirtual = oldShadow;
    Page->RefreshPfn = oldShadowPfn;
    KeMemoryBarrier();

    ULONG cpuCount = g_HypervisorContext.ProcessorCount;
    if (cpuCount > HV_VWATCH_MAX_CPUS) cpuCount = HV_VWATCH_MAX_CPUS;
    for (ULONG cpu = 0; cpu < cpuCount; cpu++) {
        HvVwatchpWriteSwBpPageSlots(
            Page,
            cpu,
            Page->ShadowPfn,
            FALSE,
            FALSE,
            TRUE);
    }
    EptInveptAllContexts();
    if (InterlockedCompareExchange(&Page->Invalidated, 0, 0) == 0) {
        refreshed = TRUE;
    }

Exit:
    if (!refreshed) HvVwatchpDisableSwBpPageRoot(Page);
    for (LONG index = 0; index < HV_PRIVATE_SWBP_MAX_ENTRIES; index++) {
        if (acquiredEntries[index]) {
            HvVwatchpReleaseRootRundown(
                &g_VwatchManager.SwBpEntries[index].RootRundown);
        }
    }
    InterlockedExchange(&Page->RefreshLock, 0);
    return refreshed;
}

static VOID
HvVwatchpDestroySwBpPage(_Inout_ PHV_PRIVATE_SWBP_PAGE Page)
{
    HvVwatchpBeginRootRundown(&Page->RootRundown);
    InterlockedExchange(&Page->InUse, 0);
    KeMemoryBarrier();

    KIRQL oldIrql;
    KeAcquireSpinLock(&g_VwatchManager.Lock, &oldIrql);
    HvVwatchpRebuildOverlaySnapshotLocked();
    KeReleaseSpinLock(&g_VwatchManager.Lock, oldIrql);
    HvVwatchpInvalidateOverlayClassifierCache();

    HvVwatchpWaitForRootRundown(&Page->RootRundown);

    ULONG cpuCount = g_HypervisorContext.ProcessorCount;
    if (cpuCount > HV_VWATCH_MAX_CPUS) cpuCount = HV_VWATCH_MAX_CPUS;
    for (ULONG cpuIndex = 0; cpuIndex < cpuCount; cpuIndex++) {
        PEPT_PTE_ENTRY slot = Page->ShadowPte[cpuIndex];
        if (slot) {
            EPT_PTE_ENTRY current;
            current.Value = *(volatile ULONG64*)&slot->Value;
            if (current.PhysicalAddress == Page->ShadowPfn) {
                HvVwatchpWriteSwBpSlot(
                    slot,
                    Page->OriginalPfn,
                    TRUE,
                    TRUE,
                    TRUE);
            }
        }

        PEPT_PTE_ENTRY mirrorSlot = Page->MirrorShadowPte[cpuIndex];
        if (mirrorSlot && mirrorSlot != slot) {
            EPT_PTE_ENTRY mirrorCurrent;
            mirrorCurrent.Value = *(volatile ULONG64*)&mirrorSlot->Value;
            if (mirrorCurrent.PhysicalAddress == Page->ShadowPfn) {
                HvVwatchpWriteSwBpSlot(
                    mirrorSlot,
                    Page->OriginalPfn,
                    TRUE,
                    TRUE,
                    TRUE);
            }
        }
    }
    EptInveptAllContexts();

    PVOID shadowPage = Page->ShadowPageVirtual;
    PVOID refreshPage = Page->RefreshPageVirtual;
    Page->ShadowPageVirtual = NULL;
    Page->RefreshPageVirtual = NULL;
    if (shadowPage) {
        MmFreeContiguousMemory(shadowPage);
    }
    if (refreshPage) {
        MmFreeContiguousMemory(refreshPage);
    }

    KeAcquireSpinLock(&g_VwatchManager.Lock, &oldIrql);
    RtlZeroMemory(Page, sizeof(*Page));
    KeReleaseSpinLock(&g_VwatchManager.Lock, oldIrql);
}

static VOID
HvVwatchpDetachSwBpEntryLocked(
    _Inout_ PHV_PRIVATE_SWBP_ENTRY Entry,
    _Outptr_result_maybenull_ PHV_PRIVATE_SWBP_PAGE* EmptyPage)
{
    *EmptyPage = NULL;
    if (Entry->PageIndex >= 0 && Entry->PageIndex < HV_PRIVATE_SWBP_MAX_PAGES) {
        PHV_PRIVATE_SWBP_PAGE page =
            &g_VwatchManager.SwBpPages[Entry->PageIndex];
        if (page->ShadowPageVirtual) {
            ((volatile UCHAR*)page->ShadowPageVirtual)[Entry->OffsetInPage] =
                Entry->OriginalByte;
        }
        if (page->RefreshPageVirtual) {
            ((volatile UCHAR*)page->RefreshPageVirtual)[Entry->OffsetInPage] =
                Entry->OriginalByte;
        }
        if (InterlockedDecrement(&page->RefCount) <= 0) {
            page->RefCount = 0;
            *EmptyPage = page;
        }
    }

    Entry->PageIndex = -1;
}

static NTSTATUS
HvVwatchpRebindSwBpPagePassive(
    _Inout_ PHV_PRIVATE_SWBP_PAGE Page,
    _In_ LONG PageIndex,
    _In_ UINT64 UserCr3,
    _In_ ULONG64 NewGpa)
{
    InterlockedExchange(&Page->Invalidated, 1);
    KeMemoryBarrier();

    ULONG cpuCount = g_HypervisorContext.ProcessorCount;
    if (cpuCount > HV_VWATCH_MAX_CPUS) cpuCount = HV_VWATCH_MAX_CPUS;
    for (ULONG cpuIndex = 0; cpuIndex < cpuCount; cpuIndex++) {
        HvVwatchpWriteSwBpPageSlots(
            Page,
            cpuIndex,
            Page->OriginalPfn,
            TRUE,
            TRUE,
            TRUE);
    }
    EptInveptAllContexts();

    while (InterlockedCompareExchange(&Page->RootRundown, 0, 0) !=
           HV_VWATCH_RUNDOWN_REF_BIAS) {
        LARGE_INTEGER delay;
        delay.QuadPart = -10000;
        KeDelayExecutionThread(KernelMode, FALSE, &delay);
    }

    ULONG64 newGpaPage = NewGpa & ~((ULONG64)PAGE_SIZE - 1);
    if (HvPebCloakOverlayPageOwned(newGpaPage)) {
        return STATUS_CONFLICTING_ADDRESSES;
    }
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_VwatchManager.Lock, &oldIrql);
    for (LONG watchPageIndex = 0;
         watchPageIndex < HV_VWATCH_MAX_PAGES;
         watchPageIndex++) {
        PHV_VWATCH_PAGE watchPage = &g_VwatchManager.Pages[watchPageIndex];
        if (watchPage->InUse && watchPage->GpaPage == newGpaPage) {
            KeReleaseSpinLock(&g_VwatchManager.Lock, oldIrql);
            return STATUS_CONFLICTING_ADDRESSES;
        }
    }
    for (LONG swBpPageIndex = 0;
         swBpPageIndex < HV_PRIVATE_SWBP_MAX_PAGES;
         swBpPageIndex++) {
        PHV_PRIVATE_SWBP_PAGE other =
            &g_VwatchManager.SwBpPages[swBpPageIndex];
        if (swBpPageIndex != PageIndex && other->InUse &&
            other->GpaPage == newGpaPage) {
            KeReleaseSpinLock(&g_VwatchManager.Lock, oldIrql);
            return STATUS_CONFLICTING_ADDRESSES;
        }
    }
    KeReleaseSpinLock(&g_VwatchManager.Lock, oldIrql);

    HV_PRIVATE_SWBP_PAGE candidate;
    RtlZeroMemory(&candidate, sizeof(candidate));
    candidate.TargetPid = Page->TargetPid;
    candidate.UserCr3 = UserCr3;
    candidate.UserPageVa = Page->UserPageVa;
    candidate.GpaPage = newGpaPage;
    candidate.OriginalPfn = newGpaPage >> PAGE_SHIFT;
    candidate.DirectMainEpt = Page->DirectMainEpt;
    candidate.MirrorOverlayEpt = Page->MirrorOverlayEpt;
    candidate.ShadowPageVirtual = Page->RefreshPageVirtual;
    candidate.ShadowPfn = Page->RefreshPfn;

    NTSTATUS status = HvVwatchpResolveSwBpPtes(&candidate);
    if (!NT_SUCCESS(status)) return status;

    SIZE_T transferred = 0;
    status = HvPhysReadProcessMemory(
        (ULONG)(ULONG_PTR)Page->TargetPid,
        Page->UserPageVa,
        Page->RefreshPageVirtual,
        PAGE_SIZE,
        &transferred);
    if (!NT_SUCCESS(status) || transferred != PAGE_SIZE) {
        return NT_SUCCESS(status) ? STATUS_PARTIAL_COPY : status;
    }

    KeAcquireSpinLock(&g_VwatchManager.Lock, &oldIrql);
    for (LONG entryIndex = 0;
         entryIndex < HV_PRIVATE_SWBP_MAX_ENTRIES;
         entryIndex++) {
        PHV_PRIVATE_SWBP_ENTRY entry =
            &g_VwatchManager.SwBpEntries[entryIndex];
        if (!entry->InUse || entry->PageIndex != PageIndex ||
            entry->OffsetInPage >= PAGE_SIZE) continue;
        entry->UserCr3 = UserCr3;
        entry->OriginalByte =
            ((PUCHAR)Page->RefreshPageVirtual)[entry->OffsetInPage];
        ((PUCHAR)Page->RefreshPageVirtual)[entry->OffsetInPage] = 0xCC;
    }

    PVOID oldShadow = Page->ShadowPageVirtual;
    ULONG64 oldShadowPfn = Page->ShadowPfn;
    Page->ShadowPageVirtual = Page->RefreshPageVirtual;
    Page->ShadowPfn = Page->RefreshPfn;
    Page->RefreshPageVirtual = oldShadow;
    Page->RefreshPfn = oldShadowPfn;
    Page->UserCr3 = UserCr3;
    Page->GpaPage = candidate.GpaPage;
    Page->OriginalPfn = candidate.OriginalPfn;
    RtlCopyMemory(
        Page->ShadowPte,
        candidate.ShadowPte,
        sizeof(Page->ShadowPte));
    RtlCopyMemory(
        Page->MirrorShadowPte,
        candidate.MirrorShadowPte,
        sizeof(Page->MirrorShadowPte));
    HvVwatchpRebuildOverlaySnapshotLocked();
    KeReleaseSpinLock(&g_VwatchManager.Lock, oldIrql);

    HvVwatchpActivateSwBpPage(Page);
    InterlockedExchange(&Page->RootRefreshUsed, 0);
    InterlockedExchange(&Page->Invalidated, 0);
    HvVwatchpInvalidateOverlayClassifierCache();
    return STATUS_SUCCESS;
}

NTSTATUS HvVwatchRefreshPrivateSwBpRange(
    _In_ HANDLE TargetPid,
    _In_ UINT64 Address,
    _In_ SIZE_T Size)
{
    if (!g_VwatchManager.Initialized || !TargetPid || !Address || !Size) {
        return STATUS_INVALID_PARAMETER;
    }
    if (InterlockedCompareExchange(
            &g_VwatchManager.SwBpEntryCount,
            0,
            0) == 0) return STATUS_NOT_FOUND;
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) return STATUS_INVALID_LEVEL;
    if (Address + Size < Address) return STATUS_INTEGER_OVERFLOW;

    UINT64 firstPage = Address & ~((UINT64)PAGE_SIZE - 1);
    UINT64 lastPage = (Address + Size - 1) & ~((UINT64)PAGE_SIZE - 1);
    NTSTATUS result = STATUS_NOT_FOUND;
    BOOLEAN snapshotChanged = FALSE;

    HvOverlayEptAcquireMutation();
    for (LONG pageIndex = 0;
         pageIndex < HV_PRIVATE_SWBP_MAX_PAGES;
         pageIndex++) {
        PHV_PRIVATE_SWBP_PAGE page = &g_VwatchManager.SwBpPages[pageIndex];
        KIRQL oldIrql;
        KeAcquireSpinLock(&g_VwatchManager.Lock, &oldIrql);
        if (!page->InUse || page->TargetPid != TargetPid ||
            page->UserPageVa < firstPage || page->UserPageVa > lastPage ||
            !HvVwatchpAcquireRootRundown(&page->RootRundown)) {
            KeReleaseSpinLock(&g_VwatchManager.Lock, oldIrql);
            continue;
        }
        KeReleaseSpinLock(&g_VwatchManager.Lock, oldIrql);

        while (InterlockedCompareExchange(&page->RefreshLock, 1, 0) != 0) {
            LARGE_INTEGER delay;
            delay.QuadPart = -10000;
            KeDelayExecutionThread(KernelMode, FALSE, &delay);
        }
        if (!page->RefreshPageVirtual) {
            HvVwatchpDisableSwBpPageRoot(page);
            result = STATUS_DEVICE_NOT_READY;
            InterlockedExchange(&page->RefreshLock, 0);
            HvVwatchpReleaseRootRundown(&page->RootRundown);
            continue;
        }
        EptInveptAllContexts();

        UINT64 userCr3 = 0;
        ULONG64 currentGpa = 0;
        NTSTATUS status = HvVwatchpResolveUserCr3(TargetPid, &userCr3);
        if (NT_SUCCESS(status)) {
            status = HvVwatchpGvaToGpa(
                (ULONG)(ULONG_PTR)TargetPid,
                page->UserPageVa,
                &currentGpa);
        }
        if (!NT_SUCCESS(status) || !currentGpa) {
            HvVwatchpDisableSwBpPageRoot(page);
            result = NT_SUCCESS(status) ? STATUS_NOT_FOUND : status;
            InterlockedExchange(&page->RefreshLock, 0);
            HvVwatchpReleaseRootRundown(&page->RootRundown);
            continue;
        }
        if ((currentGpa & ~((ULONG64)PAGE_SIZE - 1)) != page->GpaPage) {
            status = HvVwatchpRebindSwBpPagePassive(
                page,
                pageIndex,
                userCr3,
                currentGpa);
            if (!NT_SUCCESS(status)) {
                HvVwatchpDisableSwBpPageRoot(page);
                result = status;
            } else if (result == STATUS_NOT_FOUND) {
                result = STATUS_SUCCESS;
            }
            InterlockedExchange(&page->RefreshLock, 0);
            HvVwatchpReleaseRootRundown(&page->RootRundown);
            continue;
        }

        SIZE_T transferred = 0;
        status = HvPhysReadProcessMemory(
            (ULONG)(ULONG_PTR)TargetPid,
            page->UserPageVa,
            page->RefreshPageVirtual,
            PAGE_SIZE,
            &transferred);
        if (!NT_SUCCESS(status) || transferred != PAGE_SIZE) {
            HvVwatchpDisableSwBpPageRoot(page);
            result = NT_SUCCESS(status) ? STATUS_PARTIAL_COPY : status;
            InterlockedExchange(&page->RefreshLock, 0);
            HvVwatchpReleaseRootRundown(&page->RootRundown);
            continue;
        }

        KeAcquireSpinLock(&g_VwatchManager.Lock, &oldIrql);
        for (LONG entryIndex = 0;
             entryIndex < HV_PRIVATE_SWBP_MAX_ENTRIES;
             entryIndex++) {
            PHV_PRIVATE_SWBP_ENTRY entry =
                &g_VwatchManager.SwBpEntries[entryIndex];
            if (!entry->InUse || entry->PageIndex != pageIndex ||
                entry->OffsetInPage >= PAGE_SIZE) continue;
            entry->OriginalByte =
                ((PUCHAR)page->RefreshPageVirtual)[entry->OffsetInPage];
            ((PUCHAR)page->RefreshPageVirtual)[entry->OffsetInPage] = 0xCC;
        }

        if (page->UserCr3 != userCr3) {
            for (LONG entryIndex = 0;
                 entryIndex < HV_PRIVATE_SWBP_MAX_ENTRIES;
                 entryIndex++) {
                PHV_PRIVATE_SWBP_ENTRY entry =
                    &g_VwatchManager.SwBpEntries[entryIndex];
                if (entry->InUse && entry->PageIndex == pageIndex) {
                    entry->UserCr3 = userCr3;
                }
            }
            page->UserCr3 = userCr3;
            snapshotChanged = TRUE;
        }
        PVOID oldShadow = page->ShadowPageVirtual;
        ULONG64 oldShadowPfn = page->ShadowPfn;
        page->ShadowPageVirtual = page->RefreshPageVirtual;
        page->ShadowPfn = page->RefreshPfn;
        page->RefreshPageVirtual = oldShadow;
        page->RefreshPfn = oldShadowPfn;
        InterlockedExchange(&page->Invalidated, 0);
        KeMemoryBarrier();

        ULONG cpuCount = g_HypervisorContext.ProcessorCount;
        if (cpuCount > HV_VWATCH_MAX_CPUS) cpuCount = HV_VWATCH_MAX_CPUS;
        for (ULONG cpuIndex = 0; cpuIndex < cpuCount; cpuIndex++) {
            HvVwatchpWriteSwBpPageSlots(
                page,
                cpuIndex,
                page->ShadowPfn,
                FALSE,
                FALSE,
                TRUE);
        }
        if (snapshotChanged) HvVwatchpRebuildOverlaySnapshotLocked();
        KeReleaseSpinLock(&g_VwatchManager.Lock, oldIrql);

        EptInveptAllContexts();
        InterlockedExchange(&page->RootRefreshUsed, 0);
        InterlockedExchange(&page->RefreshLock, 0);
        HvVwatchpReleaseRootRundown(&page->RootRundown);
        if (result == STATUS_NOT_FOUND) result = STATUS_SUCCESS;
    }
    HvOverlayEptReleaseMutation();

    if (snapshotChanged) HvVwatchpInvalidateOverlayClassifierCache();
    return result;
}

static NTSTATUS
HvVwatchpMaterializePrivateSwBpPage(
    _In_ HANDLE TargetPid,
    _In_ UINT64 Address,
    _In_ UCHAR OriginalByte)
{
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) return STATUS_INVALID_LEVEL;

    ULONG oldProtection = 0;
    NTSTATUS status = HvMemoryProtect(
        (ULONG)(ULONG_PTR)TargetPid,
        (PVOID)(ULONG_PTR)Address,
        sizeof(OriginalByte),
        PAGE_EXECUTE_WRITECOPY,
        &oldProtection);
    if (!NT_SUCCESS(status)) return status;

    SIZE_T transferred = 0;
    NTSTATUS writeStatus = HvMemoryWriteCow(
        (ULONG)(ULONG_PTR)TargetPid,
        (PVOID)(ULONG_PTR)Address,
        &OriginalByte,
        sizeof(OriginalByte),
        &transferred);
    if (NT_SUCCESS(writeStatus) && transferred != sizeof(OriginalByte)) {
        writeStatus = STATUS_PARTIAL_COPY;
    }

    NTSTATUS restoreStatus = HvMemoryProtect(
        (ULONG)(ULONG_PTR)TargetPid,
        (PVOID)(ULONG_PTR)Address,
        sizeof(OriginalByte),
        oldProtection,
        NULL);
    return NT_SUCCESS(restoreStatus) ? writeStatus : restoreStatus;
}

NTSTATUS HvVwatchSwBpAdd(
    _In_ HANDLE DebuggerPid,
    _In_ HANDLE TargetPid,
    _In_ UINT64 Address,
    _In_opt_ HANDLE ScopeThreadId)
{
    if (!g_VwatchManager.Initialized) return STATUS_DEVICE_NOT_READY;
    if (!g_EptHookManager.ExecuteOnlySupported) return STATUS_NOT_SUPPORTED;
    if (!DebuggerPid || !TargetPid || Address <= 0x10000ULL ||
        Address >= 0x00007FFFFFFFFFFFULL ||
        KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_PARAMETER;
    }

    NTSTATUS status = STATUS_SUCCESS;
    PHV_PRIVATE_SWBP_PAGE preparedPage = NULL;
    PHV_PRIVATE_SWBP_PAGE activePage = NULL;
    PVOID preparedShadow = NULL;
    PVOID preparedRefresh = NULL;
    UINT64 userCr3 = 0;
    ULONG64 gpa = 0;
    UCHAR originalByte = 0;
    UCHAR opcodeWindow[3] = { 0 };
    SIZE_T transferred = 0;
    PETHREAD scopeThread = NULL;
    UINT64 pageVa = Address & ~((UINT64)PAGE_SIZE - 1);
    ULONG offset = (ULONG)(Address & (PAGE_SIZE - 1));

    status = HvPhysReadProcessMemory(
        (ULONG)(ULONG_PTR)TargetPid,
        Address - 1,
        opcodeWindow,
        sizeof(opcodeWindow),
        &transferred);
    if (!NT_SUCCESS(status) || transferred != sizeof(opcodeWindow)) {
        if (NT_SUCCESS(status)) status = STATUS_PARTIAL_COPY;
        return status;
    }
    if (opcodeWindow[1] == 0xCC ||
        (opcodeWindow[0] == 0xCD && opcodeWindow[1] == 0x03) ||
        (opcodeWindow[1] == 0xCD && opcodeWindow[2] == 0x03)) {
        return STATUS_NOT_SUPPORTED;
    }
    originalByte = opcodeWindow[1];

    status = HvVwatchpResolveUserCr3(TargetPid, &userCr3);
    if (!NT_SUCCESS(status)) return status;
    status = HvVwatchpGvaToGpa(
        (ULONG)(ULONG_PTR)TargetPid,
        Address,
        &gpa);
    if (!NT_SUCCESS(status) || !gpa) return STATUS_NOT_FOUND;

    if (ScopeThreadId) {
        status = PsLookupThreadByThreadId(ScopeThreadId, &scopeThread);
        if (!NT_SUCCESS(status)) return status;
        if (PsGetThreadProcessId(scopeThread) != TargetPid) {
            ObDereferenceObject(scopeThread);
            return STATUS_INVALID_CID;
        }
    }

    HvOverlayEptAcquireMutation();
    if (HvPebCloakOverlayPageOwned(
            gpa & ~((ULONG64)PAGE_SIZE - 1))) {
        status = STATUS_CONFLICTING_ADDRESSES;
        goto Exit;
    }

    KIRQL oldIrql;
    KeAcquireSpinLock(&g_VwatchManager.Lock, &oldIrql);
    PHV_PRIVATE_SWBP_ENTRY existing =
        HvVwatchpFindSwBpEntryLocked(TargetPid, Address);
    if (existing) {
        if (existing->DebuggerPid != DebuggerPid) {
            status = STATUS_OBJECT_NAME_COLLISION;
        } else if (InterlockedCompareExchange(&existing->State, 0, 0) !=
                   HvPrivateSwBpArmed) {
            status = STATUS_DEVICE_BUSY;
        } else if (existing->PageIndex < 0 ||
                   existing->PageIndex >= HV_PRIVATE_SWBP_MAX_PAGES ||
                   InterlockedCompareExchange(
                       &g_VwatchManager.SwBpPages[existing->PageIndex].Invalidated,
                       0,
                       0) != 0) {
            status = STATUS_RETRY;
        } else {
            if (scopeThread) {
                PVOID existingScope = (PVOID)InterlockedCompareExchangePointer(
                    (PVOID volatile*)&existing->ScopeThreadToken,
                    NULL,
                    NULL);
                if (existingScope && existingScope != scopeThread) {
                    status = STATUS_OBJECT_NAME_COLLISION;
                } else if (!existingScope) {
                    KeMemoryBarrier();
                    if (InterlockedCompareExchangePointer(
                            (PVOID volatile*)&existing->ScopeThreadToken,
                            scopeThread,
                            NULL) == NULL) {
                        scopeThread = NULL;
                        InterlockedIncrement(
                            &g_VwatchManager.ScopedSwBpEntryCount);
                    } else {
                        status = STATUS_OBJECT_NAME_COLLISION;
                    }
                }
            }
        }
        KeReleaseSpinLock(&g_VwatchManager.Lock, oldIrql);
        goto Exit;
    }

    activePage = HvVwatchpFindSwBpPageForVaLocked(TargetPid, Address);
    if (activePage) {
        if (ScopeThreadId &&
            (!activePage->DirectMainEpt || !activePage->MirrorOverlayEpt)) {
            KeReleaseSpinLock(&g_VwatchManager.Lock, oldIrql);
            status = STATUS_RETRY;
            goto Exit;
        }
        if (InterlockedCompareExchange(&activePage->Invalidated, 0, 0) != 0) {
            KeReleaseSpinLock(&g_VwatchManager.Lock, oldIrql);
            status = STATUS_RETRY;
            goto Exit;
        }
        if ((activePage->UserCr3 & ~((UINT64)0xFFF)) !=
                (userCr3 & ~((UINT64)0xFFF)) ||
            activePage->GpaPage !=
                (gpa & ~((ULONG64)PAGE_SIZE - 1))) {
            KeReleaseSpinLock(&g_VwatchManager.Lock, oldIrql);
            status = STATUS_RETRY;
            goto Exit;
        }
        PHV_PRIVATE_SWBP_ENTRY entry = HvVwatchpFindFreeSwBpEntryLocked();
        if (!entry) {
            KeReleaseSpinLock(&g_VwatchManager.Lock, oldIrql);
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto Exit;
        }
        if (InterlockedCompareExchange(&activePage->RefreshLock, 1, 0) != 0) {
            KeReleaseSpinLock(&g_VwatchManager.Lock, oldIrql);
            status = STATUS_DEVICE_BUSY;
            goto Exit;
        }

        RtlZeroMemory(entry, sizeof(*entry));
        entry->TargetPid = TargetPid;
        entry->DebuggerPid = DebuggerPid;
        if (scopeThread) {
            entry->ScopeThreadToken = scopeThread;
            scopeThread = NULL;
            InterlockedIncrement(&g_VwatchManager.ScopedSwBpEntryCount);
        }
        entry->UserCr3 = userCr3;
        entry->Address = Address;
        entry->OffsetInPage = offset;
        entry->PageIndex = (LONG)(activePage - g_VwatchManager.SwBpPages);
        entry->OriginalByte = originalByte;
        entry->State = HvPrivateSwBpArmed;
        KeMemoryBarrier();
        InterlockedExchange(&entry->InUse, 1);
        InterlockedIncrement(&activePage->RefCount);
        InterlockedIncrement(&g_VwatchManager.SwBpEntryCount);
        ((volatile UCHAR*)activePage->ShadowPageVirtual)[offset] = 0xCC;
        ((volatile UCHAR*)activePage->RefreshPageVirtual)[offset] = 0xCC;
        InterlockedExchange(&activePage->RefreshLock, 0);
        HvVwatchpRebuildOverlaySnapshotLocked();
        KeReleaseSpinLock(&g_VwatchManager.Lock, oldIrql);
        HvVwatchpInvalidateOverlayClassifierCache();
        EptInveptAllContexts();
        goto Exit;
    }
    KeReleaseSpinLock(&g_VwatchManager.Lock, oldIrql);

    status = HvVwatchpMaterializePrivateSwBpPage(
        TargetPid,
        Address,
        originalByte);
    if (!NT_SUCCESS(status)) goto Exit;

    status = HvVwatchpResolveUserCr3(TargetPid, &userCr3);
    if (!NT_SUCCESS(status)) goto Exit;
    status = HvVwatchpGvaToGpa(
        (ULONG)(ULONG_PTR)TargetPid,
        Address,
        &gpa);
    if (!NT_SUCCESS(status) || !gpa) goto Exit;

    PHYSICAL_ADDRESS highest;
    highest.QuadPart = -1LL;
    preparedShadow = MmAllocateContiguousMemory(PAGE_SIZE, highest);
    if (!preparedShadow) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }
    preparedRefresh = MmAllocateContiguousMemory(PAGE_SIZE, highest);
    if (!preparedRefresh) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }

    transferred = 0;
    status = HvPhysReadProcessMemory(
        (ULONG)(ULONG_PTR)TargetPid,
        pageVa,
        preparedShadow,
        PAGE_SIZE,
        &transferred);
    if (!NT_SUCCESS(status) || transferred != PAGE_SIZE) {
        if (NT_SUCCESS(status)) status = STATUS_PARTIAL_COPY;
        goto Exit;
    }
    RtlCopyMemory(preparedRefresh, preparedShadow, PAGE_SIZE);
    ((PUCHAR)preparedShadow)[offset] = 0xCC;
    ((PUCHAR)preparedRefresh)[offset] = 0xCC;

    HV_PRIVATE_SWBP_PAGE candidate;
    RtlZeroMemory(&candidate, sizeof(candidate));
    candidate.TargetPid = TargetPid;
    candidate.UserCr3 = userCr3;
    candidate.UserPageVa = pageVa;
    candidate.GpaPage = gpa & ~((ULONG64)PAGE_SIZE - 1);
    candidate.OriginalPfn = candidate.GpaPage >> PAGE_SHIFT;
    candidate.DirectMainEpt = TRUE;
    candidate.MirrorOverlayEpt = TRUE;
    candidate.ShadowPageVirtual = preparedShadow;
    candidate.ShadowPfn =
        MmGetPhysicalAddress(preparedShadow).QuadPart >> PAGE_SHIFT;
    candidate.RefreshPageVirtual = preparedRefresh;
    candidate.RefreshPfn =
        MmGetPhysicalAddress(preparedRefresh).QuadPart >> PAGE_SHIFT;

    status = HvVwatchpResolveSwBpPtes(&candidate);
    if (!NT_SUCCESS(status)) goto Exit;

    UINT64 verifyCr3 = 0;
    ULONG64 verifyGpa = 0;
    status = HvVwatchpResolveUserCr3(TargetPid, &verifyCr3);
    if (NT_SUCCESS(status)) {
        status = HvVwatchpGvaToGpa(
            (ULONG)(ULONG_PTR)TargetPid,
            Address,
            &verifyGpa);
    }
    if (!NT_SUCCESS(status) ||
        (verifyCr3 & ~((UINT64)0xFFF)) !=
            (candidate.UserCr3 & ~((UINT64)0xFFF)) ||
        (verifyGpa & ~((ULONG64)PAGE_SIZE - 1)) != candidate.GpaPage) {
        status = STATUS_RETRY;
        goto Exit;
    }
    if (HvPebCloakOverlayPageOwned(candidate.GpaPage)) {
        status = STATUS_CONFLICTING_ADDRESSES;
        goto Exit;
    }

    transferred = 0;
    status = HvPhysReadProcessMemory(
        (ULONG)(ULONG_PTR)TargetPid,
        Address - 1,
        opcodeWindow,
        sizeof(opcodeWindow),
        &transferred);
    if (!NT_SUCCESS(status) || transferred != sizeof(opcodeWindow) ||
        opcodeWindow[1] != originalByte || opcodeWindow[1] == 0xCC ||
        (opcodeWindow[0] == 0xCD && opcodeWindow[1] == 0x03) ||
        (opcodeWindow[1] == 0xCD && opcodeWindow[2] == 0x03)) {
        status = STATUS_RETRY;
        goto Exit;
    }

    KeAcquireSpinLock(&g_VwatchManager.Lock, &oldIrql);
    for (LONG watchPageIndex = 0;
         watchPageIndex < HV_VWATCH_MAX_PAGES;
         watchPageIndex++) {
        PHV_VWATCH_PAGE watchPage = &g_VwatchManager.Pages[watchPageIndex];
        if (watchPage->InUse && watchPage->GpaPage == candidate.GpaPage) {
            KeReleaseSpinLock(&g_VwatchManager.Lock, oldIrql);
            status = STATUS_CONFLICTING_ADDRESSES;
            goto Exit;
        }
    }
    preparedPage = HvVwatchpFindFreeSwBpPageLocked();
    PHV_PRIVATE_SWBP_ENTRY entry = HvVwatchpFindFreeSwBpEntryLocked();
    if (!preparedPage || !entry) {
        KeReleaseSpinLock(&g_VwatchManager.Lock, oldIrql);
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }

    RtlCopyMemory(preparedPage, &candidate, sizeof(candidate));
    preparedPage->RefCount = 1;
    KeMemoryBarrier();
    InterlockedExchange(&preparedPage->InUse, 1);

    RtlZeroMemory(entry, sizeof(*entry));
    entry->TargetPid = TargetPid;
    entry->DebuggerPid = DebuggerPid;
    if (scopeThread) {
        entry->ScopeThreadToken = scopeThread;
        scopeThread = NULL;
        InterlockedIncrement(&g_VwatchManager.ScopedSwBpEntryCount);
    }
    entry->UserCr3 = userCr3;
    entry->Address = Address;
    entry->OffsetInPage = offset;
    entry->PageIndex = (LONG)(preparedPage - g_VwatchManager.SwBpPages);
    entry->OriginalByte = originalByte;
    entry->State = HvPrivateSwBpArmed;
    KeMemoryBarrier();
    InterlockedExchange(&entry->InUse, 1);
    InterlockedIncrement(&g_VwatchManager.SwBpEntryCount);
    HvVwatchpRebuildOverlaySnapshotLocked();
    KeReleaseSpinLock(&g_VwatchManager.Lock, oldIrql);

    preparedShadow = NULL;
    preparedRefresh = NULL;
    HvVwatchpInvalidateOverlayClassifierCache();
    HvVwatchpActivateSwBpPage(preparedPage);
    DbgPrint("[Vwatch] Private SWBP add: debugger=%u target=%u address=0x%llX gpa=0x%llX ept=%s\n",
        (ULONG)(ULONG_PTR)DebuggerPid,
        (ULONG)(ULONG_PTR)TargetPid,
        Address,
        candidate.GpaPage,
        candidate.MirrorOverlayEpt
            ? "main+overlay(private-dbgk)"
            : (candidate.DirectMainEpt ? "main" : "overlay"));

Exit:
    if (scopeThread) ObDereferenceObject(scopeThread);
    if (preparedShadow) MmFreeContiguousMemory(preparedShadow);
    if (preparedRefresh) MmFreeContiguousMemory(preparedRefresh);
    HvOverlayEptReleaseMutation();
    return status;
}

NTSTATUS HvVwatchSwBpRemove(
    _In_ HANDLE DebuggerPid,
    _In_ HANDLE TargetPid,
    _In_ UINT64 Address)
{
    if (!g_VwatchManager.Initialized || !DebuggerPid || !TargetPid || !Address) {
        return STATUS_INVALID_PARAMETER;
    }
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) return STATUS_INVALID_LEVEL;

    NTSTATUS status = STATUS_NOT_FOUND;
    PHV_PRIVATE_SWBP_ENTRY entry = NULL;
    PHV_PRIVATE_SWBP_PAGE emptyPage = NULL;
    PETHREAD scopeThread = NULL;
    HvOverlayEptAcquireMutation();

    KIRQL oldIrql;
    KeAcquireSpinLock(&g_VwatchManager.Lock, &oldIrql);
    entry = HvVwatchpFindSwBpEntryLocked(TargetPid, Address);
    if (entry && entry->DebuggerPid == DebuggerPid) {
        HvVwatchpBeginRootRundown(&entry->RootRundown);
        status = STATUS_SUCCESS;
    } else if (entry) {
        status = STATUS_ACCESS_DENIED;
    }
    KeReleaseSpinLock(&g_VwatchManager.Lock, oldIrql);

    if (NT_SUCCESS(status)) {
        HvVwatchpWaitForRootRundown(&entry->RootRundown);

        PHV_PRIVATE_SWBP_PAGE lockedPage = NULL;
        if (entry->PageIndex >= 0 &&
            entry->PageIndex < HV_PRIVATE_SWBP_MAX_PAGES) {
            lockedPage = &g_VwatchManager.SwBpPages[entry->PageIndex];
            HvVwatchpAcquireRefreshLockPassive(lockedPage);
        }

        KeAcquireSpinLock(&g_VwatchManager.Lock, &oldIrql);
        LONG state = InterlockedCompareExchange(&entry->State, 0, 0);
        BOOLEAN preservePending = state == HvPrivateSwBpHitPending;
        HvVwatchpDetachSwBpEntryLocked(entry, &emptyPage);
        scopeThread = HvVwatchpTakeSwBpScopeThreadLocked(entry);
        if (preservePending) {
            InterlockedExchange(
                &entry->State,
                HvPrivateSwBpDisarmedPending);
        } else {
            InterlockedExchange(&entry->InUse, 0);
            InterlockedDecrement(&g_VwatchManager.SwBpEntryCount);
            RtlZeroMemory(entry, sizeof(*entry));
        }
        KeReleaseSpinLock(&g_VwatchManager.Lock, oldIrql);

        if (scopeThread) ObDereferenceObject(scopeThread);

        if (emptyPage) {
            HvVwatchpDestroySwBpPage(emptyPage);
        } else {
            if (lockedPage) InterlockedExchange(&lockedPage->RefreshLock, 0);
            EptInveptAllContexts();
        }
    }

    HvOverlayEptReleaseMutation();
    return status;
}

NTSTATUS HvVwatchSwBpContinue(
    _In_ HANDLE DebuggerPid,
    _In_ HANDLE TargetPid,
    _In_ HANDLE TargetTid,
    _In_opt_ PVOID ThreadToken,
    _In_ UINT64 Sequence,
    _In_ ULONG ContinueStatus)
{
    UNREFERENCED_PARAMETER(ContinueStatus);
    if (!g_VwatchManager.Initialized || !DebuggerPid || !TargetPid ||
        (!TargetTid && !ThreadToken) || !Sequence ||
        KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_PARAMETER;
    }

    PETHREAD targetThread = NULL;
    if (TargetTid) {
        NTSTATUS lookupStatus = PsLookupThreadByThreadId(
            TargetTid,
            &targetThread);
        if (!NT_SUCCESS(lookupStatus)) return lookupStatus;
        if (PsGetThreadProcessId(targetThread) != TargetPid ||
            (ThreadToken && ThreadToken != (PVOID)targetThread)) {
            ObDereferenceObject(targetThread);
            return STATUS_INVALID_CID;
        }
        ThreadToken = (PVOID)targetThread;
    }

    NTSTATUS status = STATUS_NOT_FOUND;
    PETHREAD scopeThread = NULL;
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_VwatchManager.Lock, &oldIrql);
    for (LONG index = 0; index < HV_PRIVATE_SWBP_MAX_ENTRIES; index++) {
        PHV_PRIVATE_SWBP_ENTRY entry = &g_VwatchManager.SwBpEntries[index];
        if (!entry->InUse ||
            entry->DebuggerPid != DebuggerPid ||
            entry->TargetPid != TargetPid ||
            entry->Sequence != Sequence) {
            continue;
        }

        if (entry->HitThreadToken != ThreadToken) {
            status = STATUS_INVALID_CID;
            break;
        }

        LONG state = InterlockedCompareExchange(&entry->State, 0, 0);
        if ((InterlockedCompareExchange(&entry->RootRundown, 0, 0) &
             HV_VWATCH_RUNDOWN_CLOSED) &&
            state != HvPrivateSwBpDisarmedPending) {
            status = STATUS_DELETE_PENDING;
            break;
        }
        if (state == HvPrivateSwBpHitPending) {
            entry->HitTid = TargetTid;
            InterlockedExchange(&entry->State, HvPrivateSwBpContinueArmed);
            status = STATUS_SUCCESS;
        } else if (state == HvPrivateSwBpDisarmedPending) {
            scopeThread = HvVwatchpTakeSwBpScopeThreadLocked(entry);
            InterlockedExchange(&entry->InUse, 0);
            InterlockedDecrement(&g_VwatchManager.SwBpEntryCount);
            RtlZeroMemory(entry, sizeof(*entry));
            status = STATUS_SUCCESS;
        } else {
            status = STATUS_INVALID_DEVICE_STATE;
        }
        break;
    }
    KeReleaseSpinLock(&g_VwatchManager.Lock, oldIrql);
    if (scopeThread) ObDereferenceObject(scopeThread);
    if (targetThread) ObDereferenceObject(targetThread);
    return status;
}

NTSTATUS HvVwatchStepArm(
    _In_ HANDLE DebuggerPid,
    _In_ HANDLE TargetPid,
    _In_ HANDLE TargetTid,
    _In_ PVOID ThreadToken,
    _In_ UINT64 Address)
{
    if (!HvVwatchIsVtStepSupported()) return STATUS_NOT_SUPPORTED;
    if (!DebuggerPid || !TargetPid || !TargetTid || !ThreadToken ||
        Address < 0x10000ULL || Address >= 0x0000800000000000ULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) return STATUS_INVALID_LEVEL;

    NTSTATUS status = STATUS_NOT_FOUND;
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_VwatchManager.Lock, &oldIrql);
    PHV_PRIVATE_SWBP_ENTRY entry =
        HvVwatchpFindSwBpEntryLocked(TargetPid, Address);
    if (entry && entry->DebuggerPid != DebuggerPid) {
        status = STATUS_ACCESS_DENIED;
    } else if (entry &&
               InterlockedCompareExchange(&entry->InUse, 0, 0) != 0 &&
               InterlockedCompareExchange(&entry->State, 0, 0) !=
                   HvPrivateSwBpDisarmedPending) {
        LONG stepState = InterlockedCompareExchange(
            &entry->StepState,
            HV_VWATCH_STEP_ARMED,
            HV_VWATCH_STEP_ARMED);
        if (stepState == HV_VWATCH_STEP_COMPLETING) {
            status = STATUS_DEVICE_BUSY;
        } else {
            entry->StepTid = TargetTid;
            entry->StepThreadToken = ThreadToken;
            KeMemoryBarrier();
            InterlockedExchange(&entry->StepState, HV_VWATCH_STEP_ARMED);
            status = STATUS_SUCCESS;
        }
    }
    KeReleaseSpinLock(&g_VwatchManager.Lock, oldIrql);
    return status;
}

NTSTATUS HvVwatchStepClear(
    _In_ HANDLE DebuggerPid,
    _In_ HANDLE TargetPid,
    _In_ HANDLE TargetTid)
{
    if (!g_VwatchManager.Initialized) return STATUS_DEVICE_NOT_READY;
    if (!DebuggerPid || !TargetPid || !TargetTid) {
        return STATUS_INVALID_PARAMETER;
    }
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) return STATUS_INVALID_LEVEL;

    NTSTATUS status = STATUS_NOT_FOUND;
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_VwatchManager.Lock, &oldIrql);
    for (LONG index = 0; index < HV_PRIVATE_SWBP_MAX_ENTRIES; index++) {
        PHV_PRIVATE_SWBP_ENTRY entry =
            &g_VwatchManager.SwBpEntries[index];
        if (!entry->InUse || entry->DebuggerPid != DebuggerPid ||
            entry->TargetPid != TargetPid || entry->StepTid != TargetTid) {
            continue;
        }
        if (InterlockedCompareExchange(
                &entry->StepState,
                HV_VWATCH_STEP_COMPLETING,
                HV_VWATCH_STEP_COMPLETING) == HV_VWATCH_STEP_COMPLETING) {
            status = STATUS_DEVICE_BUSY;
            break;
        }
        InterlockedExchange(&entry->StepState, HV_VWATCH_STEP_IDLE);
        KeMemoryBarrier();
        entry->StepTid = NULL;
        entry->StepThreadToken = NULL;
        status = STATUS_SUCCESS;
    }
    KeReleaseSpinLock(&g_VwatchManager.Lock, oldIrql);
    return status;
}

static VOID
HvVwatchpClearSwBpMatching(
    _In_opt_ HANDLE DebuggerPid,
    _In_opt_ HANDLE TargetPid)
{
    if (!g_VwatchManager.Initialized || KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return;
    }

    BOOLEAN retiringEntries[HV_PRIVATE_SWBP_MAX_ENTRIES];
    BOOLEAN lockedPages[HV_PRIVATE_SWBP_MAX_PAGES];
    BOOLEAN emptyPages[HV_PRIVATE_SWBP_MAX_PAGES];
    PETHREAD scopeThreads[HV_PRIVATE_SWBP_MAX_ENTRIES];
    RtlZeroMemory(retiringEntries, sizeof(retiringEntries));
    RtlZeroMemory(lockedPages, sizeof(lockedPages));
    RtlZeroMemory(emptyPages, sizeof(emptyPages));
    RtlZeroMemory(scopeThreads, sizeof(scopeThreads));
    HvOverlayEptAcquireMutation();

    KIRQL oldIrql;
    KeAcquireSpinLock(&g_VwatchManager.Lock, &oldIrql);
    for (LONG index = 0; index < HV_PRIVATE_SWBP_MAX_ENTRIES; index++) {
        PHV_PRIVATE_SWBP_ENTRY entry = &g_VwatchManager.SwBpEntries[index];
        if (!entry->InUse) continue;
        if (DebuggerPid && entry->DebuggerPid != DebuggerPid) continue;
        if (TargetPid && entry->TargetPid != TargetPid) continue;

        HvVwatchpBeginRootRundown(&entry->RootRundown);
        retiringEntries[index] = TRUE;
    }
    KeReleaseSpinLock(&g_VwatchManager.Lock, oldIrql);

    for (LONG index = 0; index < HV_PRIVATE_SWBP_MAX_ENTRIES; index++) {
        if (retiringEntries[index]) {
            HvVwatchpWaitForRootRundown(
                &g_VwatchManager.SwBpEntries[index].RootRundown);
        }
    }

    KeAcquireSpinLock(&g_VwatchManager.Lock, &oldIrql);
    for (LONG index = 0; index < HV_PRIVATE_SWBP_MAX_ENTRIES; index++) {
        if (!retiringEntries[index]) continue;
        PHV_PRIVATE_SWBP_ENTRY entry = &g_VwatchManager.SwBpEntries[index];
        if (entry->InUse && entry->PageIndex >= 0 &&
            entry->PageIndex < HV_PRIVATE_SWBP_MAX_PAGES) {
            lockedPages[entry->PageIndex] = TRUE;
        }
    }
    KeReleaseSpinLock(&g_VwatchManager.Lock, oldIrql);

    for (LONG pageIndex = 0;
         pageIndex < HV_PRIVATE_SWBP_MAX_PAGES;
         pageIndex++) {
        if (lockedPages[pageIndex]) {
            HvVwatchpAcquireRefreshLockPassive(
                &g_VwatchManager.SwBpPages[pageIndex]);
        }
    }

    KeAcquireSpinLock(&g_VwatchManager.Lock, &oldIrql);
    for (LONG index = 0; index < HV_PRIVATE_SWBP_MAX_ENTRIES; index++) {
        if (!retiringEntries[index]) continue;
        PHV_PRIVATE_SWBP_ENTRY entry = &g_VwatchManager.SwBpEntries[index];
        if (!entry->InUse) continue;

        PHV_PRIVATE_SWBP_PAGE emptyPage = NULL;
        HvVwatchpDetachSwBpEntryLocked(entry, &emptyPage);
        scopeThreads[index] = HvVwatchpTakeSwBpScopeThreadLocked(entry);
        if (emptyPage) {
            LONG pageIndex = (LONG)(emptyPage - g_VwatchManager.SwBpPages);
            if (pageIndex >= 0 && pageIndex < HV_PRIVATE_SWBP_MAX_PAGES) {
                emptyPages[pageIndex] = TRUE;
            }
        }
        InterlockedExchange(&entry->InUse, 0);
        InterlockedDecrement(&g_VwatchManager.SwBpEntryCount);
        RtlZeroMemory(entry, sizeof(*entry));
    }
    KeReleaseSpinLock(&g_VwatchManager.Lock, oldIrql);

    for (LONG index = 0; index < HV_PRIVATE_SWBP_MAX_ENTRIES; index++) {
        if (scopeThreads[index]) ObDereferenceObject(scopeThreads[index]);
    }

    for (LONG pageIndex = 0;
         pageIndex < HV_PRIVATE_SWBP_MAX_PAGES;
         pageIndex++) {
        if (lockedPages[pageIndex] && !emptyPages[pageIndex]) {
            InterlockedExchange(
                &g_VwatchManager.SwBpPages[pageIndex].RefreshLock,
                0);
        }
    }

    for (LONG pageIndex = 0;
         pageIndex < HV_PRIVATE_SWBP_MAX_PAGES;
         pageIndex++) {
        if (emptyPages[pageIndex]) {
            HvVwatchpDestroySwBpPage(
                &g_VwatchManager.SwBpPages[pageIndex]);
        }
    }

    HvOverlayEptReleaseMutation();
}

// ============================================================
// VDR cache 操作 (调用方持 Lock 或在 vmexit 上下文)
// ============================================================

static VOID
HvVwatchpInvalidateVDrCacheForTarget(_In_ HANDLE TargetPid)
{
    for (LONG i = 0; i < HV_VWATCH_MAX_TARGETS_CACHE; i++) {
        PHV_VWATCH_VDR_CACHE c = &g_VwatchManager.VDrCache[i];
        if (c->InUse && c->TargetPid == TargetPid) {
            InterlockedExchange(&c->Valid, 0);
        }
    }
}

// ============================================================
// Page 管理
// ============================================================

/*
 * 找/分配该 GpaPage 对应的 Page slot. Locked 调用 (调用方持 Lock).
 *
 * 返回 NULL = 表满.
 */
static PHV_VWATCH_PAGE
HvVwatchpGetOrAllocPageLocked(_In_ ULONG64 GpaPage)
{
    LONG freeIdx = -1;
    for (LONG i = 0; i < HV_VWATCH_MAX_PAGES; i++) {
        PHV_VWATCH_PAGE p = &g_VwatchManager.Pages[i];
        if (p->InUse && p->GpaPage == GpaPage) return p;
        if (!p->InUse &&
            InterlockedCompareExchange(&p->RootRundown, 0, 0) == 0 &&
            freeIdx < 0) freeIdx = i;
    }
    if (freeIdx < 0) return NULL;

    PHV_VWATCH_PAGE p = &g_VwatchManager.Pages[freeIdx];
    RtlZeroMemory(p, sizeof(*p));
    p->GpaPage = GpaPage;
    p->OriginalPfn = GpaPage >> 12;
    p->RefCount = 0;
    p->CombinedTrapMask = 0;
    p->InUse = 0;  // caller publishes only after every per-vCPU PTE is ready
    return p;
}

/*
 * 重算某 page 的 CombinedTrapMask (扫该 page 上所有 entry). Locked.
 */
static ULONG
HvVwatchpRecomputeMaskLocked(_In_ LONG PageIndex)
{
    ULONG mask = 0;
    for (LONG i = 0; i < HV_VWATCH_MAX_ENTRIES; i++) {
        PHV_VWATCH_ENTRY e = &g_VwatchManager.Entries[i];
        if (!e->InUse) continue;
        if (e->PageIndex != PageIndex) continue;
        mask |= HvVwatchpTypeToMask(e->Type);
    }
    return mask;
}

/*
 * 把 page 的 PT slot 在所有 vcpu 上写为 mask 指定的 trap 位.
 * Mask=0 → 完全恢复 R/W/X (page 即将释放).
 *
 * 首次安装时 page->CloakedPte[*] 为 NULL, 自动找/split.
 */
static NTSTATUS
HvVwatchpApplyMaskAllVcpus(_Inout_ PHV_VWATCH_PAGE Page, _In_ ULONG Mask)
{
    ULONG cpuCount = g_HypervisorContext.ProcessorCount;
    if (!g_HypervisorContext.VcpuData || cpuCount == 0 ||
        cpuCount > HV_VWATCH_MAX_CPUS) {
        return STATUS_DEVICE_NOT_READY;
    }

    ULONG ok = 0;
    for (ULONG c = 0; c < cpuCount; c++) {
        PVCPU_DATA vcpu = &g_HypervisorContext.VcpuData[c];
        if (!vcpu->EptPebSpoof) continue;

        PEPT_PTE_ENTRY slot = Page->CloakedPte[c];
        if (!slot) {
            slot = HvVwatchpFindOrSplitPtSlot(vcpu->EptPebSpoof, Page->GpaPage);
            if (!slot) continue;
            Page->CloakedPte[c] = slot;
        }
        HvVwatchpWritePtSlot(slot, Page->OriginalPfn, Mask);
        ok++;
    }
    // A watch page is an all-vCPU publication.  Accepting a partial update
    // lets the target evade the breakpoint after migration and leaves cleanup
    // unable to prove that every EPT view was restored.
    return ok == cpuCount ? STATUS_SUCCESS : STATUS_DEVICE_NOT_READY;
}

/*
 * 释放 page (清所有 PT slot 回 R/W/X, mark not in use). Locked.
 * 调用方保证 Page->RefCount == 0.
 */
static VOID
HvVwatchpBeginRetirePageLocked(_Inout_ PHV_VWATCH_PAGE Page)
{
    HvVwatchpBeginRootRundown(&Page->RootRundown);
    InterlockedExchange(&Page->InUse, 0);
    KeMemoryBarrier();
    (void)HvVwatchpApplyMaskAllVcpus(Page, 0);   // 全 R/W/X
    Page->RefCount = 0;
    Page->CombinedTrapMask = 0;
    EptInveptAllContexts();
}

static VOID
HvVwatchpFinishRetirePagePassive(_Inout_ PHV_VWATCH_PAGE Page)
{
    HvVwatchpWaitForRootRundown(&Page->RootRundown);

    KIRQL oldIrql;
    KeAcquireSpinLock(&g_VwatchManager.Lock, &oldIrql);
    RtlZeroMemory(Page, sizeof(*Page));
    KeReleaseSpinLock(&g_VwatchManager.Lock, oldIrql);
}

// ============================================================
// 生命周期
// ============================================================

NTSTATUS HvVwatchInitialize(VOID)
{
#if !HV_ENABLE_VWATCH
    DbgPrint("[Vwatch] Init: disabled (HV_ENABLE_VWATCH=0)\n");
    return STATUS_SUCCESS;
#else
    if (g_VwatchManager.Initialized) return STATUS_SUCCESS;
    RtlZeroMemory(&g_VwatchManager, sizeof(g_VwatchManager));
    KeInitializeSpinLock(&g_VwatchManager.Lock);
    g_VwatchManager.Initialized = TRUE;
    g_VwatchManager.GloballyEnabled = FALSE;
    DbgPrint("[Vwatch] Init OK (EPT-based virtual HWBP, P129)\n");
    return STATUS_SUCCESS;
#endif
}

VOID HvVwatchShutdown(VOID)
{
    if (!g_VwatchManager.Initialized) return;
    BOOLEAN retiringPages[HV_VWATCH_MAX_PAGES];
    BOOLEAN retiringEntries[HV_VWATCH_MAX_ENTRIES];
    PETHREAD targetThreads[HV_VWATCH_MAX_ENTRIES];
    ULONG removedEntries = 0;
    RtlZeroMemory(retiringPages, sizeof(retiringPages));
    RtlZeroMemory(retiringEntries, sizeof(retiringEntries));
    RtlZeroMemory(targetThreads, sizeof(targetThreads));
    g_VwatchManager.GloballyEnabled = FALSE;
    HvVwatchpClearSwBpMatching(NULL, NULL);

    HvOverlayEptAcquireMutation();
    KIRQL old;
    KeAcquireSpinLock(&g_VwatchManager.Lock, &old);

    // 清所有 entry
    for (LONG i = 0; i < HV_VWATCH_MAX_ENTRIES; i++) {
        PHV_VWATCH_ENTRY entry = &g_VwatchManager.Entries[i];
        if (entry->InUse) {
            HvVwatchpBeginRootRundown(&entry->RootRundown);
            retiringEntries[i] = TRUE;
        }
        InterlockedIncrement(&entry->Sequence);
        KeMemoryBarrier();
        if (InterlockedExchange(&entry->InUse, 0) != 0) {
            removedEntries++;
        }
        KeMemoryBarrier();
        InterlockedIncrement(&entry->Sequence);
    }
    g_VwatchManager.EntryCount = 0;

    // 清所有 page
    for (LONG i = 0; i < HV_VWATCH_MAX_PAGES; i++) {
        PHV_VWATCH_PAGE p = &g_VwatchManager.Pages[i];
        if (p->InUse) {
            HvVwatchpBeginRetirePageLocked(p);
            retiringPages[i] = TRUE;
        }
    }

    // 清 VDR cache
    for (LONG i = 0; i < HV_VWATCH_MAX_TARGETS_CACHE; i++) {
        g_VwatchManager.VDrCache[i].InUse = 0;
    }
    HvVwatchpRebuildOverlaySnapshotLocked();

    KeReleaseSpinLock(&g_VwatchManager.Lock, old);
    for (LONG i = 0; i < HV_VWATCH_MAX_PAGES; i++) {
        if (retiringPages[i]) {
            HvVwatchpFinishRetirePagePassive(&g_VwatchManager.Pages[i]);
        }
    }
    for (LONG i = 0; i < HV_VWATCH_MAX_ENTRIES; i++) {
        if (retiringEntries[i]) {
            HvVwatchpWaitForRootRundown(
                &g_VwatchManager.Entries[i].RootRundown);
            targetThreads[i] = (PETHREAD)InterlockedExchangePointer(
                (PVOID volatile*)&g_VwatchManager.Entries[i].TargetThreadToken,
                NULL);
            RtlZeroMemory(
                &g_VwatchManager.Entries[i],
                sizeof(g_VwatchManager.Entries[i]));
        }
    }
    for (LONG i = 0; i < HV_VWATCH_MAX_ENTRIES; i++) {
        if (targetThreads[i]) ObDereferenceObject(targetThreads[i]);
    }
    HvVwatchpInvalidateOverlayClassifierCache();
    EptInveptAllContexts();
    (void)HvDbgReleaseVwatchCr3Intercepts(removedEntries);
    HvOverlayEptReleaseMutation();

    g_VwatchManager.Initialized = FALSE;
    DbgPrint("[Vwatch] Shutdown\n");
}

// ============================================================
// Set / Clear
// ============================================================

#if 0 /* replaced by transactional VT-root publication below */
NTSTATUS HvVwatchSet(
    _In_ HANDLE DebuggerPid,
    _In_ HANDLE TargetPid,
    _In_ ULONG SlotIndex,
    _In_ UINT64 Address,
    _In_ UCHAR Length,
    _In_ UCHAR Type)
{
#if !HV_ENABLE_VWATCH
    UNREFERENCED_PARAMETER(DebuggerPid);
    UNREFERENCED_PARAMETER(TargetPid);
    UNREFERENCED_PARAMETER(SlotIndex);
    UNREFERENCED_PARAMETER(Address);
    UNREFERENCED_PARAMETER(Length);
    UNREFERENCED_PARAMETER(Type);
    return STATUS_NOT_IMPLEMENTED;
#else
    if (!g_VwatchManager.Initialized) return STATUS_DEVICE_NOT_READY;
    if (!TargetPid || !Address) return STATUS_INVALID_PARAMETER;
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) return STATUS_INVALID_LEVEL;
    if (SlotIndex >= 4) return STATUS_INVALID_PARAMETER;
    if (Length != 1 && Length != 2 && Length != 4 && Length != 8) {
        return STATUS_INVALID_PARAMETER;
    }
    if (Type < HV_VWATCH_TYPE_WRITE || Type > HV_VWATCH_TYPE_EXECUTE) {
        return STATUS_INVALID_PARAMETER;
    }

    // 1) 解 user CR3 + GVA→GPA
    UINT64 userCr3 = 0;
    NTSTATUS s = HvVwatchpResolveUserCr3(TargetPid, &userCr3);
    if (!NT_SUCCESS(s) || !userCr3) {
        DbgPrint("[Vwatch] Set PID=%u: resolve user CR3 failed 0x%X\n",
                 (ULONG)(ULONG_PTR)TargetPid, s);
        return s;
    }

    ULONG64 gpa = 0;
    s = HvVwatchpGvaToGpa((ULONG)(ULONG_PTR)TargetPid, Address, &gpa);
    if (!NT_SUCCESS(s) || !gpa) {
        DbgPrint("[Vwatch] Set PID=%u GVA=0x%llX: walk failed 0x%X\n",
                 (ULONG)(ULONG_PTR)TargetPid, Address, s);
        return s;
    }
    ULONG64 gpaPage = gpa & ~((ULONG64)0xFFF);

    HvOverlayEptAcquireMutation();
    KIRQL old;
    KeAcquireSpinLock(&g_VwatchManager.Lock, &old);

    for (LONG swBpPageIndex = 0;
         swBpPageIndex < HV_PRIVATE_SWBP_MAX_PAGES;
         swBpPageIndex++) {
        PHV_PRIVATE_SWBP_PAGE swBpPage =
            &g_VwatchManager.SwBpPages[swBpPageIndex];
        if (swBpPage->InUse && swBpPage->GpaPage == gpaPage) {
            KeReleaseSpinLock(&g_VwatchManager.Lock, old);
            HvOverlayEptReleaseMutation();
            return STATUS_CONFLICTING_ADDRESSES;
        }
    }

    // 2) 找/复用 entry: 同 (target, slot) 视为更新, 否则找空槽
    LONG entryIdx = -1;
    for (LONG i = 0; i < HV_VWATCH_MAX_ENTRIES; i++) {
        PHV_VWATCH_ENTRY e = &g_VwatchManager.Entries[i];
        if (e->InUse && e->TargetPid == TargetPid && (i % 4) == (LONG)SlotIndex) {
            entryIdx = i;
            break;
        }
    }
    LONG oldPageIdx = -1;
    if (entryIdx >= 0) {
        oldPageIdx = g_VwatchManager.Entries[entryIdx].PageIndex;
    } else {
        for (LONG i = (LONG)SlotIndex; i < HV_VWATCH_MAX_ENTRIES; i += 4) {
            if (!g_VwatchManager.Entries[i].InUse) {
                entryIdx = i;
                break;
            }
        }
    }
    if (entryIdx < 0) {
        KeReleaseSpinLock(&g_VwatchManager.Lock, old);
        HvOverlayEptReleaseMutation();
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // 3) 找/分配新 page
    PHV_VWATCH_PAGE newPage = HvVwatchpGetOrAllocPageLocked(gpaPage);
    if (!newPage) {
        KeReleaseSpinLock(&g_VwatchManager.Lock, old);
        HvOverlayEptReleaseMutation();
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    LONG newPageIdx = (LONG)(newPage - g_VwatchManager.Pages);

    // 4) 旧 entry 撤掉旧 page 的 ref (如果在不同 page)
    if (oldPageIdx >= 0 && oldPageIdx != newPageIdx) {
        PHV_VWATCH_PAGE oldPage = &g_VwatchManager.Pages[oldPageIdx];
        if (InterlockedDecrement(&oldPage->RefCount) <= 0) {
            HvVwatchpFreePageLocked(oldPage);
        } else {
            // 旧 page 还有别的 entry, 重算 mask 重写 PT
            ULONG newMask = HvVwatchpRecomputeMaskLocked(oldPageIdx);
            // 把当前 entry 排除掉 (它即将换 page)
            // RecomputeMask 已经扫 InUse 全部 entry, 包含当前 entry
            // 简化:这里我们先 invalidate 当前 entry, 再 Recompute
            g_VwatchManager.Entries[entryIdx].InUse = 0;
            newMask = HvVwatchpRecomputeMaskLocked(oldPageIdx);
            g_VwatchManager.Entries[entryIdx].InUse = 1;   // 恢复(下面会重写)

            oldPage->CombinedTrapMask = newMask;
            (void)HvVwatchpApplyMaskAllVcpus(oldPage, newMask);
        }
    }

    // 5) 写新 entry
    PHV_VWATCH_ENTRY e = &g_VwatchManager.Entries[entryIdx];
    BOOLEAN wasInUse = e->InUse ? TRUE : FALSE;
    e->TargetPid = TargetPid;
    e->DebuggerPid = DebuggerPid;
    e->UserCr3 = userCr3;
    e->WatchVa = Address;
    e->Length = Length;
    e->Type = Type;
    e->PageIndex = newPageIdx;
    e->InUse = 1;

    if (!wasInUse) {
        InterlockedIncrement(&g_VwatchManager.EntryCount);
    }

    // 6) 新 page 增加 ref + 重算 mask + apply
    if (oldPageIdx != newPageIdx) {
        InterlockedIncrement(&newPage->RefCount);
    }
    ULONG combinedMask = HvVwatchpRecomputeMaskLocked(newPageIdx);
    newPage->CombinedTrapMask = combinedMask;
    NTSTATUS as = HvVwatchpApplyMaskAllVcpus(newPage, combinedMask);

    if (!NT_SUCCESS(as)) {
        // 回滚 entry
        e->InUse = 0;
        if (!wasInUse) InterlockedDecrement(&g_VwatchManager.EntryCount);
        if (oldPageIdx != newPageIdx) {
            if (InterlockedDecrement(&newPage->RefCount) <= 0) {
                HvVwatchpFreePageLocked(newPage);
            }
        }
        HvVwatchpRebuildOverlaySnapshotLocked();
        KeReleaseSpinLock(&g_VwatchManager.Lock, old);
        HvVwatchpInvalidateOverlayClassifierCache();
        HvOverlayEptReleaseMutation();
        DbgPrint("[Vwatch] Set: ApplyMask failed for page 0x%llX\n", gpaPage);
        return as;
    }

    g_VwatchManager.GloballyEnabled = TRUE;
    HvVwatchpInvalidateVDrCacheForTarget(TargetPid);
    HvVwatchpRebuildOverlaySnapshotLocked();

    KeReleaseSpinLock(&g_VwatchManager.Lock, old);
    HvVwatchpInvalidateOverlayClassifierCache();
    EptInveptAllContexts();
    HvOverlayEptReleaseMutation();

    DbgPrint("[Vwatch] Set OK: ent=%d page=%d (mask=0x%X ref=%d) Dbg=%u Target=%u Slot=%u VA=0x%llX Len=%u Type=%u GpaPage=0x%llX\n",
             entryIdx, newPageIdx, combinedMask, newPage->RefCount,
             (ULONG)(ULONG_PTR)DebuggerPid,
             (ULONG)(ULONG_PTR)TargetPid,
             SlotIndex, Address, Length, Type, gpaPage);
    return STATUS_SUCCESS;
#endif
}
#endif

NTSTATUS HvVwatchSetThreadScopedEx(
    _In_ HANDLE DebuggerPid,
    _In_ HANDLE TargetPid,
    _In_opt_ HANDLE TargetTid,
    _In_ ULONG SlotIndex,
    _In_ UINT64 Address,
    _In_ UCHAR Length,
    _In_ UCHAR Type,
    _In_ BOOLEAN PrivateEvent)
{
#if !HV_ENABLE_VWATCH
    UNREFERENCED_PARAMETER(DebuggerPid);
    UNREFERENCED_PARAMETER(TargetPid);
    UNREFERENCED_PARAMETER(TargetTid);
    UNREFERENCED_PARAMETER(SlotIndex);
    UNREFERENCED_PARAMETER(Address);
    UNREFERENCED_PARAMETER(Length);
    UNREFERENCED_PARAMETER(Type);
    return STATUS_NOT_IMPLEMENTED;
#else
    if (!g_VwatchManager.Initialized) return STATUS_DEVICE_NOT_READY;
    if (!HvVwatchIsVirtualHardwareBreakpointSupported()) {
        return STATUS_NOT_SUPPORTED;
    }
    if (!DebuggerPid || !TargetPid || Address < 0x10000ULL ||
        Address >= 0x0000800000000000ULL ||
        Address + Length < Address) return STATUS_INVALID_PARAMETER;
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) return STATUS_INVALID_LEVEL;
    if (SlotIndex >= 4) return STATUS_INVALID_PARAMETER;
    if (Length != 1 && Length != 2 && Length != 4 && Length != 8) {
        return STATUS_INVALID_PARAMETER;
    }
    if (Type < HV_VWATCH_TYPE_WRITE || Type > HV_VWATCH_TYPE_EXECUTE) {
        return STATUS_INVALID_PARAMETER;
    }
    if ((Type == HV_VWATCH_TYPE_EXECUTE && Length != 1) ||
        (Type != HV_VWATCH_TYPE_EXECUTE &&
         (Address & (Length - 1)) != 0) ||
        ((Address & (PAGE_SIZE - 1)) + Length > PAGE_SIZE)) {
        return STATUS_DATATYPE_MISALIGNMENT;
    }

    UINT64 userCr3 = 0;
    ULONG64 gpa = 0;
    NTSTATUS status = HvVwatchpResolveUserCr3(TargetPid, &userCr3);
    if (!NT_SUCCESS(status) || !userCr3) {
        return NT_SUCCESS(status) ? STATUS_NOT_FOUND : status;
    }
    status = HvVwatchpGvaToGpa(
        (ULONG)(ULONG_PTR)TargetPid,
        Address,
        &gpa);
    if (!NT_SUCCESS(status) || !gpa) {
        return NT_SUCCESS(status) ? STATUS_NOT_FOUND : status;
    }
    const ULONG64 gpaPage = gpa & ~((ULONG64)PAGE_SIZE - 1);
    PETHREAD targetThread = NULL;
    if (TargetTid) {
        status = PsLookupThreadByThreadId(TargetTid, &targetThread);
        if (!NT_SUCCESS(status)) return status;
        if (PsGetThreadProcessId(targetThread) != TargetPid) {
            ObDereferenceObject(targetThread);
            return STATUS_INVALID_CID;
        }
    }

    PHV_VWATCH_PAGE retirePage = NULL;
    ULONG combinedMask = 0;
    LONG entryIdx = -1;
    LONG newPageIdx = -1;
    BOOLEAN interceptAcquired = FALSE;
    HvOverlayEptAcquireMutation();

    if (HvPebCloakOverlayPageOwned(gpaPage)) {
        HvOverlayEptReleaseMutation();
        if (targetThread) ObDereferenceObject(targetThread);
        return STATUS_CONFLICTING_ADDRESSES;
    }

    KIRQL oldIrql;
    KeAcquireSpinLock(&g_VwatchManager.Lock, &oldIrql);

    for (LONG index = 0; index < HV_PRIVATE_SWBP_MAX_PAGES; index++) {
        PHV_PRIVATE_SWBP_PAGE swPage =
            &g_VwatchManager.SwBpPages[index];
        if (swPage->InUse && swPage->GpaPage == gpaPage) {
            status = STATUS_CONFLICTING_ADDRESSES;
            goto ExitLocked;
        }
    }

    for (LONG index = (LONG)SlotIndex;
         index < HV_VWATCH_MAX_ENTRIES;
         index += 4) {
        PHV_VWATCH_ENTRY candidate = &g_VwatchManager.Entries[index];
        if (candidate->InUse && candidate->TargetPid == TargetPid &&
            candidate->TargetTid == TargetTid) {
            if (candidate->DebuggerPid != DebuggerPid) {
                status = STATUS_ACCESS_DENIED;
                goto ExitLocked;
            }
            if ((PVOID)InterlockedCompareExchangePointer(
                    (PVOID volatile*)&candidate->TargetThreadToken,
                    NULL,
                    NULL) != targetThread) {
                status = STATUS_OBJECT_NAME_COLLISION;
                goto ExitLocked;
            }
            entryIdx = index;
            break;
        }
        if (!candidate->InUse &&
            InterlockedCompareExchange(&candidate->RootRundown, 0, 0) == 0 &&
            entryIdx < 0) {
            entryIdx = index;
        }
    }
    if (entryIdx < 0) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto ExitLocked;
    }

    PHV_VWATCH_ENTRY entry = &g_VwatchManager.Entries[entryIdx];
    const BOOLEAN wasInUse = entry->InUse ? TRUE : FALSE;
    const LONG oldPageIdx = wasInUse ? entry->PageIndex : -1;
    if (!wasInUse) {
        KeReleaseSpinLock(&g_VwatchManager.Lock, oldIrql);
        status = HvDbgAcquireVwatchCr3Intercept();
        if (!NT_SUCCESS(status)) {
            HvOverlayEptReleaseMutation();
            if (targetThread) ObDereferenceObject(targetThread);
            return status;
        }
        interceptAcquired = TRUE;
        KeAcquireSpinLock(&g_VwatchManager.Lock, &oldIrql);
        entry = &g_VwatchManager.Entries[entryIdx];
        if (entry->InUse) {
            status = STATUS_RETRY;
            goto ExitLocked;
        }
    }
    PHV_VWATCH_PAGE newPage = HvVwatchpGetOrAllocPageLocked(gpaPage);
    if (!newPage) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto ExitLocked;
    }
    newPageIdx = (LONG)(newPage - g_VwatchManager.Pages);
    const BOOLEAN newPageCreated = newPage->InUse ? FALSE : TRUE;
    const ULONG previousMask = newPage->CombinedTrapMask;

    for (LONG index = 0; index < HV_VWATCH_MAX_ENTRIES; index++) {
        PHV_VWATCH_ENTRY current = &g_VwatchManager.Entries[index];
        if (index == entryIdx || !current->InUse ||
            current->PageIndex != newPageIdx) continue;
        combinedMask |= HvVwatchpTypeToMask(current->Type);
    }
    combinedMask |= HvVwatchpTypeToMask(Type);

    status = HvVwatchpApplyMaskAllVcpus(newPage, combinedMask);
    if (!NT_SUCCESS(status)) {
        if (newPageCreated) {
            (void)HvVwatchpApplyMaskAllVcpus(newPage, 0);
            RtlZeroMemory(newPage, sizeof(*newPage));
        } else {
            (void)HvVwatchpApplyMaskAllVcpus(newPage, previousMask);
        }
        goto ExitLocked;
    }

    if (newPageCreated) {
        newPage->CombinedTrapMask = combinedMask;
        KeMemoryBarrier();
        InterlockedExchange(&newPage->InUse, 1);
    }

    if (!wasInUse) {
        RtlZeroMemory(entry, sizeof(*entry));
    }
    InterlockedIncrement(&entry->Sequence);
    KeMemoryBarrier();
    entry->TargetPid = TargetPid;
    entry->TargetTid = TargetTid;
    if (!wasInUse && targetThread) {
        entry->TargetThreadToken = targetThread;
        targetThread = NULL;
    }
    entry->DebuggerPid = DebuggerPid;
    entry->UserCr3 = userCr3;
    entry->WatchVa = Address;
    entry->Length = Length;
    entry->Type = Type;
    entry->PageIndex = newPageIdx;
    entry->PrivateEvent = PrivateEvent;
    InterlockedExchange(&entry->InUse, 1);
    KeMemoryBarrier();
    InterlockedIncrement(&entry->Sequence);

    if (!wasInUse) {
        InterlockedIncrement(&g_VwatchManager.EntryCount);
    }
    if (oldPageIdx != newPageIdx) {
        InterlockedIncrement(&newPage->RefCount);
        if (oldPageIdx >= 0 && oldPageIdx < HV_VWATCH_MAX_PAGES) {
            PHV_VWATCH_PAGE oldPage =
                &g_VwatchManager.Pages[oldPageIdx];
            if (InterlockedDecrement(&oldPage->RefCount) <= 0) {
                HvVwatchpBeginRetirePageLocked(oldPage);
                retirePage = oldPage;
            } else {
                ULONG oldMask = HvVwatchpRecomputeMaskLocked(oldPageIdx);
                oldPage->CombinedTrapMask = oldMask;
                (void)HvVwatchpApplyMaskAllVcpus(oldPage, oldMask);
            }
        }
    }
    newPage->CombinedTrapMask = combinedMask;
    g_VwatchManager.GloballyEnabled = TRUE;
    HvVwatchpInvalidateVDrCacheForTarget(TargetPid);
    HvVwatchpRebuildOverlaySnapshotLocked();
    status = STATUS_SUCCESS;

ExitLocked:
    KeReleaseSpinLock(&g_VwatchManager.Lock, oldIrql);
    if (retirePage) HvVwatchpFinishRetirePagePassive(retirePage);
    if (NT_SUCCESS(status)) {
        HvVwatchpInvalidateOverlayClassifierCache();
        EptInveptAllContexts();
    } else if (interceptAcquired) {
        (void)HvDbgReleaseVwatchCr3Intercepts(1);
    }
    HvOverlayEptReleaseMutation();
    if (targetThread) ObDereferenceObject(targetThread);
    return status;
#endif
}

NTSTATUS HvVwatchSetEx(
    _In_ HANDLE DebuggerPid,
    _In_ HANDLE TargetPid,
    _In_ ULONG SlotIndex,
    _In_ UINT64 Address,
    _In_ UCHAR Length,
    _In_ UCHAR Type,
    _In_ BOOLEAN PrivateEvent)
{
    return HvVwatchSetThreadScopedEx(
        DebuggerPid,
        TargetPid,
        NULL,
        SlotIndex,
        Address,
        Length,
        Type,
        PrivateEvent);
}

NTSTATUS HvVwatchSet(
    _In_ HANDLE DebuggerPid,
    _In_ HANDLE TargetPid,
    _In_ ULONG SlotIndex,
    _In_ UINT64 Address,
    _In_ UCHAR Length,
    _In_ UCHAR Type)
{
    return HvVwatchSetEx(
        DebuggerPid,
        TargetPid,
        SlotIndex,
        Address,
        Length,
        Type,
        FALSE);
}

static NTSTATUS
HvVwatchpClearOwnedInternal(
    _In_opt_ HANDLE DebuggerPid,
    _In_ HANDLE TargetPid,
    _In_opt_ HANDLE TargetTid,
    _In_ BOOLEAN MatchAnyThread,
    _In_ ULONG SlotIndex)
{
#if !HV_ENABLE_VWATCH
    UNREFERENCED_PARAMETER(DebuggerPid);
    UNREFERENCED_PARAMETER(TargetPid);
    UNREFERENCED_PARAMETER(TargetTid);
    UNREFERENCED_PARAMETER(MatchAnyThread);
    UNREFERENCED_PARAMETER(SlotIndex);
    return STATUS_NOT_IMPLEMENTED;
#else
    if (!g_VwatchManager.Initialized) return STATUS_DEVICE_NOT_READY;
    if (!TargetPid || SlotIndex >= 4) return STATUS_INVALID_PARAMETER;
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) return STATUS_INVALID_LEVEL;

    NTSTATUS status = STATUS_NOT_FOUND;
    PHV_VWATCH_PAGE retirePage = NULL;
    PHV_VWATCH_ENTRY retireEntry = NULL;
    PETHREAD targetThread = NULL;
    BOOLEAN removedEntry = FALSE;
    HvOverlayEptAcquireMutation();

    KIRQL oldIrql;
    KeAcquireSpinLock(&g_VwatchManager.Lock, &oldIrql);
    for (LONG index = (LONG)SlotIndex;
         index < HV_VWATCH_MAX_ENTRIES;
         index += 4) {
        PHV_VWATCH_ENTRY entry = &g_VwatchManager.Entries[index];
        if (!entry->InUse || entry->TargetPid != TargetPid) continue;
        if (!MatchAnyThread && entry->TargetTid != TargetTid) continue;
        if (DebuggerPid && entry->DebuggerPid != DebuggerPid) {
            status = STATUS_ACCESS_DENIED;
            break;
        }

        LONG pageIndex = entry->PageIndex;
        HvVwatchpBeginRootRundown(&entry->RootRundown);
        retireEntry = entry;
        InterlockedIncrement(&entry->Sequence);
        KeMemoryBarrier();
        InterlockedExchange(&entry->InUse, 0);
        entry->PageIndex = -1;
        KeMemoryBarrier();
        InterlockedIncrement(&entry->Sequence);
        if (InterlockedDecrement(&g_VwatchManager.EntryCount) < 0) {
            InterlockedExchange(&g_VwatchManager.EntryCount, 0);
        }
        removedEntry = TRUE;

        if (pageIndex >= 0 && pageIndex < HV_VWATCH_MAX_PAGES) {
            PHV_VWATCH_PAGE page = &g_VwatchManager.Pages[pageIndex];
            if (InterlockedDecrement(&page->RefCount) <= 0) {
                HvVwatchpBeginRetirePageLocked(page);
                retirePage = page;
            } else {
                ULONG newMask = HvVwatchpRecomputeMaskLocked(pageIndex);
                page->CombinedTrapMask = newMask;
                (void)HvVwatchpApplyMaskAllVcpus(page, newMask);
            }
        }

        if (g_VwatchManager.EntryCount <= 0) {
            g_VwatchManager.EntryCount = 0;
            g_VwatchManager.GloballyEnabled = FALSE;
        }
        HvVwatchpInvalidateVDrCacheForTarget(TargetPid);
        HvVwatchpRebuildOverlaySnapshotLocked();
        status = STATUS_SUCCESS;
        break;
    }
    KeReleaseSpinLock(&g_VwatchManager.Lock, oldIrql);

    if (retirePage) HvVwatchpFinishRetirePagePassive(retirePage);
    if (NT_SUCCESS(status)) {
        HvVwatchpInvalidateOverlayClassifierCache();
        EptInveptAllContexts();
    }
    if (retireEntry) {
        HvVwatchpWaitForRootRundown(&retireEntry->RootRundown);
        targetThread = (PETHREAD)InterlockedExchangePointer(
            (PVOID volatile*)&retireEntry->TargetThreadToken,
            NULL);
        RtlZeroMemory(retireEntry, sizeof(*retireEntry));
    }
    if (targetThread) ObDereferenceObject(targetThread);
    if (removedEntry) {
        (void)HvDbgReleaseVwatchCr3Intercepts(1);
    }
    HvOverlayEptReleaseMutation();
    return status;
#endif
}

NTSTATUS HvVwatchClear(_In_ HANDLE TargetPid, _In_ ULONG SlotIndex)
{
    NTSTATUS result = STATUS_NOT_FOUND;
    for (;;) {
        NTSTATUS status = HvVwatchpClearOwnedInternal(
            NULL, TargetPid, NULL, TRUE, SlotIndex);
        if (status == STATUS_NOT_FOUND) return result;
        if (!NT_SUCCESS(status)) return status;
        result = STATUS_SUCCESS;
    }
}

NTSTATUS HvVwatchClearOwned(
    _In_ HANDLE DebuggerPid,
    _In_ HANDLE TargetPid,
    _In_ ULONG SlotIndex)
{
    if (!DebuggerPid) return STATUS_INVALID_PARAMETER;
    return HvVwatchClearThreadOwned(
        DebuggerPid, TargetPid, NULL, SlotIndex);
}

NTSTATUS HvVwatchClearThreadOwned(
    _In_ HANDLE DebuggerPid,
    _In_ HANDLE TargetPid,
    _In_opt_ HANDLE TargetTid,
    _In_ ULONG SlotIndex)
{
    if (!DebuggerPid) return STATUS_INVALID_PARAMETER;
    if (TargetTid) {
        return HvVwatchpClearOwnedInternal(
            DebuggerPid, TargetPid, TargetTid, FALSE, SlotIndex);
    }

    NTSTATUS result = STATUS_NOT_FOUND;
    for (;;) {
        NTSTATUS status = HvVwatchpClearOwnedInternal(
            DebuggerPid, TargetPid, NULL, TRUE, SlotIndex);
        if (status == STATUS_NOT_FOUND) return result;
        if (!NT_SUCCESS(status)) return status;
        result = STATUS_SUCCESS;
    }
}

static ULONG
HvVwatchpClearAllMatching(
    _In_opt_ HANDLE DebuggerPid,
    _In_opt_ HANDLE TargetPid)
{
    if (!g_VwatchManager.Initialized ||
        (!DebuggerPid && !TargetPid) ||
        KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return 0;
    }

    BOOLEAN affectedPages[HV_VWATCH_MAX_PAGES];
    BOOLEAN retiringPages[HV_VWATCH_MAX_PAGES];
    BOOLEAN retiringEntries[HV_VWATCH_MAX_ENTRIES];
    PETHREAD targetThreads[HV_VWATCH_MAX_ENTRIES];
    RtlZeroMemory(affectedPages, sizeof(affectedPages));
    RtlZeroMemory(retiringPages, sizeof(retiringPages));
    RtlZeroMemory(retiringEntries, sizeof(retiringEntries));
    RtlZeroMemory(targetThreads, sizeof(targetThreads));
    ULONG cleared = 0;

    HvOverlayEptAcquireMutation();
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_VwatchManager.Lock, &oldIrql);
    for (LONG index = 0; index < HV_VWATCH_MAX_ENTRIES; index++) {
        PHV_VWATCH_ENTRY entry = &g_VwatchManager.Entries[index];
        if (!entry->InUse) continue;
        if (DebuggerPid && entry->DebuggerPid != DebuggerPid) continue;
        if (TargetPid && entry->TargetPid != TargetPid) continue;

        HANDLE entryTarget = entry->TargetPid;
        LONG pageIndex = entry->PageIndex;
        HvVwatchpBeginRootRundown(&entry->RootRundown);
        retiringEntries[index] = TRUE;
        InterlockedIncrement(&entry->Sequence);
        KeMemoryBarrier();
        InterlockedExchange(&entry->InUse, 0);
        entry->PageIndex = -1;
        KeMemoryBarrier();
        InterlockedIncrement(&entry->Sequence);
        InterlockedDecrement(&g_VwatchManager.EntryCount);
        if (pageIndex >= 0 && pageIndex < HV_VWATCH_MAX_PAGES) {
            affectedPages[pageIndex] = TRUE;
            InterlockedDecrement(
                &g_VwatchManager.Pages[pageIndex].RefCount);
        }
        HvVwatchpInvalidateVDrCacheForTarget(entryTarget);
        cleared++;
    }

    for (LONG pageIndex = 0;
         pageIndex < HV_VWATCH_MAX_PAGES;
         pageIndex++) {
        if (!affectedPages[pageIndex]) continue;
        PHV_VWATCH_PAGE page = &g_VwatchManager.Pages[pageIndex];
        if (!page->InUse) continue;
        if (page->RefCount <= 0) {
            HvVwatchpBeginRetirePageLocked(page);
            retiringPages[pageIndex] = TRUE;
        } else {
            ULONG mask = HvVwatchpRecomputeMaskLocked(pageIndex);
            page->CombinedTrapMask = mask;
            (void)HvVwatchpApplyMaskAllVcpus(page, mask);
        }
    }

    if (g_VwatchManager.EntryCount <= 0) {
        g_VwatchManager.EntryCount = 0;
        g_VwatchManager.GloballyEnabled = FALSE;
    }
    HvVwatchpRebuildOverlaySnapshotLocked();
    KeReleaseSpinLock(&g_VwatchManager.Lock, oldIrql);

    for (LONG pageIndex = 0;
         pageIndex < HV_VWATCH_MAX_PAGES;
         pageIndex++) {
        if (retiringPages[pageIndex]) {
            HvVwatchpFinishRetirePagePassive(
                &g_VwatchManager.Pages[pageIndex]);
        }
    }
    for (LONG index = 0; index < HV_VWATCH_MAX_ENTRIES; index++) {
        if (retiringEntries[index]) {
            HvVwatchpWaitForRootRundown(
                &g_VwatchManager.Entries[index].RootRundown);
        }
    }
    KeAcquireSpinLock(&g_VwatchManager.Lock, &oldIrql);
    for (LONG index = 0; index < HV_VWATCH_MAX_ENTRIES; index++) {
        if (!retiringEntries[index]) continue;
        PHV_VWATCH_ENTRY entry = &g_VwatchManager.Entries[index];
        targetThreads[index] = (PETHREAD)InterlockedExchangePointer(
            (PVOID volatile*)&entry->TargetThreadToken,
            NULL);
        RtlZeroMemory(entry, sizeof(*entry));
    }
    KeReleaseSpinLock(&g_VwatchManager.Lock, oldIrql);
    for (LONG index = 0; index < HV_VWATCH_MAX_ENTRIES; index++) {
        if (targetThreads[index]) ObDereferenceObject(targetThreads[index]);
    }
    if (cleared) {
        HvVwatchpInvalidateOverlayClassifierCache();
        EptInveptAllContexts();
        (void)HvDbgReleaseVwatchCr3Intercepts(cleared);
    }
    HvOverlayEptReleaseMutation();
    return cleared;
}

static BOOLEAN
HvVwatchpClaimPendingHitEntry(_Inout_ PHV_VWATCH_PENDING_HIT PendingHit)
{
    return InterlockedCompareExchange(
        &PendingHit->State,
        HV_VWATCH_PENDING_HIT_PUBLISHING,
        HV_VWATCH_PENDING_HIT_VALID) == HV_VWATCH_PENDING_HIT_VALID;
}

static VOID
HvVwatchpReleasePendingHitEntry(_Inout_ PHV_VWATCH_PENDING_HIT PendingHit)
{
    KeMemoryBarrier();
    InterlockedExchange(&PendingHit->State, HV_VWATCH_PENDING_HIT_VALID);
}

static VOID
HvVwatchpClearClaimedPendingHitEntry(
    _Inout_ PHV_VWATCH_PENDING_HIT PendingHit)
{

    InterlockedIncrement(&PendingHit->Sequence);
    PendingHit->ThreadToken = NULL;
    PendingHit->DebuggerPid = NULL;
    PendingHit->TargetPid = NULL;
    PendingHit->Dr6Mask = 0;
    InterlockedExchange(&PendingHit->EventLatched, 0);
    KeMemoryBarrier();
    InterlockedIncrement(&PendingHit->Sequence);
    InterlockedExchange(&PendingHit->State, HV_VWATCH_PENDING_HIT_FREE);
    InterlockedIncrement64(&g_VwatchManager.PendingHitClears);
}

static VOID
HvVwatchpClearPendingHardwareHits(
    _In_opt_ HANDLE DebuggerPid,
    _In_opt_ HANDLE TargetPid)
{
    for (ULONG index = 0; index < HV_VWATCH_MAX_PENDING_HITS; index++) {
        PHV_VWATCH_PENDING_HIT pendingHit =
            &g_VwatchManager.PendingHits[index];
        if (!HvVwatchpClaimPendingHitEntry(pendingHit)) continue;
        if ((!DebuggerPid || pendingHit->DebuggerPid == DebuggerPid) &&
            (!TargetPid || pendingHit->TargetPid == TargetPid)) {
            HvVwatchpClearClaimedPendingHitEntry(pendingHit);
        } else {
            HvVwatchpReleasePendingHitEntry(pendingHit);
        }
    }
}

VOID HvVwatchClearAllForDebugger(_In_ HANDLE DebuggerPid)
{
    if (!DebuggerPid) return;
    (void)HvVwatchpClearAllMatching(DebuggerPid, NULL);
    HvVwatchpClearSwBpMatching(DebuggerPid, NULL);
    HvVwatchpClearPendingHardwareHits(DebuggerPid, NULL);
    HvDbgDiscardEventsForDebugger(DebuggerPid);
}

VOID HvVwatchClearAllForTarget(_In_ HANDLE TargetPid)
{
    if (!TargetPid) return;
    (void)HvVwatchpClearAllMatching(NULL, TargetPid);
    HvVwatchpClearSwBpMatching(NULL, TargetPid);
    HvVwatchpClearPendingHardwareHits(NULL, TargetPid);
}

VOID HvVwatchClearAllForDebuggerTarget(
    _In_ HANDLE DebuggerPid,
    _In_ HANDLE TargetPid)
{
    if (!DebuggerPid || !TargetPid) return;
    (void)HvVwatchpClearAllMatching(DebuggerPid, TargetPid);
    HvVwatchpClearSwBpMatching(DebuggerPid, TargetPid);
    HvVwatchpClearPendingHardwareHits(DebuggerPid, TargetPid);
}

// ============================================================
// 虚拟 DR 缓存 (GetContextThread O(1) 命中)
// ============================================================

/*
 * 拿到指定 target 的 VDR cache slot (找已有或分配新). Locked.
 */
static PHV_VWATCH_VDR_CACHE
HvVwatchpGetOrAllocVDrCacheLocked(_In_ HANDLE TargetPid)
{
    LONG freeIdx = -1;
    for (LONG i = 0; i < HV_VWATCH_MAX_TARGETS_CACHE; i++) {
        PHV_VWATCH_VDR_CACHE c = &g_VwatchManager.VDrCache[i];
        if (c->InUse && c->TargetPid == TargetPid) return c;
        if (!c->InUse && freeIdx < 0) freeIdx = i;
    }
    if (freeIdx < 0) return NULL;
    PHV_VWATCH_VDR_CACHE c = &g_VwatchManager.VDrCache[freeIdx];
    RtlZeroMemory(c, sizeof(*c));
    c->TargetPid = TargetPid;
    c->InUse = 1;
    c->Valid = 0;
    return c;
}

BOOLEAN HvVwatchBuildVirtualDrState(
    _In_ HANDLE TargetPid,
    _Out_ PUINT64 OutDr0,
    _Out_ PUINT64 OutDr1,
    _Out_ PUINT64 OutDr2,
    _Out_ PUINT64 OutDr3,
    _Out_ PUINT64 OutDr7)
{
    *OutDr0 = 0; *OutDr1 = 0; *OutDr2 = 0; *OutDr3 = 0;
    *OutDr7 = (1ULL << 10);

    if (!g_VwatchManager.Initialized || !TargetPid) return FALSE;

    KIRQL old;
    KeAcquireSpinLock(&g_VwatchManager.Lock, &old);

    PHV_VWATCH_VDR_CACHE c = HvVwatchpGetOrAllocVDrCacheLocked(TargetPid);
    if (c && InterlockedCompareExchange(&c->Valid, 0, 0)) {
        // cache hit
        *OutDr0 = c->Dr0; *OutDr1 = c->Dr1; *OutDr2 = c->Dr2; *OutDr3 = c->Dr3;
        *OutDr7 = c->Dr7;
        BOOLEAN any = (c->Dr0 | c->Dr1 | c->Dr2 | c->Dr3) != 0;
        KeReleaseSpinLock(&g_VwatchManager.Lock, old);
        InterlockedIncrement64(&g_VwatchManager.VDrCacheHits);
        return any;
    }

    // 重算
    UINT64 drs[4] = { 0, 0, 0, 0 };
    UINT64 dr7 = (1ULL << 10);
    BOOLEAN any = FALSE;

    for (LONG i = 0; i < HV_VWATCH_MAX_ENTRIES; i++) {
        PHV_VWATCH_ENTRY e = &g_VwatchManager.Entries[i];
        if (!e->InUse) continue;
        if (e->TargetPid != TargetPid) continue;

        ULONG slot = (ULONG)(i % 4);
        drs[slot] = e->WatchVa;

        // L[slot] = 1
        dr7 |= (1ULL << (slot * 2));

        ULONG rw;
        switch (e->Type) {
        case HV_VWATCH_TYPE_EXECUTE:   rw = 0x0; break;
        case HV_VWATCH_TYPE_WRITE:     rw = 0x1; break;
        case HV_VWATCH_TYPE_READWRITE: rw = 0x3; break;
        default:                       rw = 0x0; break;
        }
        dr7 |= ((UINT64)rw << (16 + slot * 4));

        ULONG len;
        switch (e->Length) {
        case 1: len = 0x0; break;
        case 2: len = 0x1; break;
        case 4: len = 0x3; break;
        case 8: len = 0x2; break;
        default: len = 0x0; break;
        }
        dr7 |= ((UINT64)len << (18 + slot * 4));
        any = TRUE;
    }

    if (c) {
        c->Dr0 = drs[0]; c->Dr1 = drs[1]; c->Dr2 = drs[2]; c->Dr3 = drs[3];
        c->Dr7 = dr7;
        InterlockedExchange(&c->Valid, 1);
    }

    KeReleaseSpinLock(&g_VwatchManager.Lock, old);

    *OutDr0 = drs[0]; *OutDr1 = drs[1]; *OutDr2 = drs[2]; *OutDr3 = drs[3];
    *OutDr7 = dr7;
    InterlockedIncrement64(&g_VwatchManager.VDrCacheRebuilds);
    return any;
}

static BOOLEAN
HvVwatchpQueryPendingHardwareHit(
    _In_ PVOID ThreadToken,
    _In_opt_ HANDLE DebuggerPid,
    _In_ HANDLE TargetPid,
    _Out_ PUINT64 Dr6Mask,
    _Out_opt_ PULONG64 Generation)
{
    if (!Dr6Mask) return FALSE;
    *Dr6Mask = 0;
    if (Generation) *Generation = 0;
    if (!g_VwatchManager.Initialized || !ThreadToken || !TargetPid) {
        return FALSE;
    }

    for (ULONG index = 0; index < HV_VWATCH_MAX_PENDING_HITS; index++) {
        PHV_VWATCH_PENDING_HIT pendingHit =
            &g_VwatchManager.PendingHits[index];
        if (!HvVwatchpClaimPendingHitEntry(pendingHit)) continue;

        LONG sequence = InterlockedCompareExchange(
            &pendingHit->Sequence, 0, 0);
        PVOID pendingThread = pendingHit->ThreadToken;
        HANDLE pendingDebugger = pendingHit->DebuggerPid;
        HANDLE pendingTarget = pendingHit->TargetPid;
        UINT64 pendingMask = pendingHit->Dr6Mask & 0xFULL;
        if ((sequence & 1) != 0 ||
            pendingThread != ThreadToken ||
            (DebuggerPid && pendingDebugger != DebuggerPid) ||
            pendingTarget != TargetPid ||
            pendingMask == 0) {
            HvVwatchpReleasePendingHitEntry(pendingHit);
            continue;
        }

        if (DebuggerPid) {
            InterlockedExchange(&pendingHit->EventLatched, 1);
        }
        InterlockedIncrement64(&g_VwatchManager.PendingHitReads);
        *Dr6Mask = pendingMask;
        if (Generation) *Generation = (ULONG64)(ULONG)sequence;
        HvVwatchpReleasePendingHitEntry(pendingHit);
        return TRUE;
    }
    return FALSE;
}

BOOLEAN HvVwatchQueryPendingHardwareHit(
    _In_ PVOID ThreadToken,
    _In_ HANDLE TargetPid,
    _Out_ PUINT64 Dr6Mask)
{
    return HvVwatchpQueryPendingHardwareHit(
        ThreadToken,
        NULL,
        TargetPid,
        Dr6Mask,
        NULL);
}

BOOLEAN HvVwatchQueryPendingHardwareHitOwned(
    _In_ PVOID ThreadToken,
    _In_ HANDLE DebuggerPid,
    _In_ HANDLE TargetPid,
    _Out_ PUINT64 Dr6Mask,
    _Out_ PULONG64 Generation)
{
    if (!DebuggerPid || !Generation) return FALSE;
    return HvVwatchpQueryPendingHardwareHit(
        ThreadToken,
        DebuggerPid,
        TargetPid,
        Dr6Mask,
        Generation);
}

VOID HvVwatchAcknowledgePendingHardwareHit(
    _In_ PVOID ThreadToken,
    _In_ HANDLE TargetPid,
    _In_ UINT64 Dr6)
{
    if (!g_VwatchManager.Initialized || !ThreadToken || !TargetPid) return;

    for (ULONG index = 0; index < HV_VWATCH_MAX_PENDING_HITS; index++) {
        PHV_VWATCH_PENDING_HIT pendingHit =
            &g_VwatchManager.PendingHits[index];
        if (!HvVwatchpClaimPendingHitEntry(pendingHit)) continue;
        if (pendingHit->ThreadToken == ThreadToken &&
            pendingHit->TargetPid == TargetPid &&
            InterlockedCompareExchange(
                &pendingHit->EventLatched, 0, 0) != 0 &&
            (Dr6 & pendingHit->Dr6Mask & 0xFULL) == 0) {
            HvVwatchpClearClaimedPendingHitEntry(pendingHit);
            return;
        }
        HvVwatchpReleasePendingHitEntry(pendingHit);
    }
}

BOOLEAN HvVwatchRetirePendingHardwareHitOwned(
    _In_ PVOID ThreadToken,
    _In_ HANDLE DebuggerPid,
    _In_ HANDLE TargetPid,
    _In_ ULONG64 Generation)
{
    if (!g_VwatchManager.Initialized || !ThreadToken || !DebuggerPid ||
        !TargetPid || Generation == 0 || Generation > MAXULONG) {
        return FALSE;
    }

    for (ULONG index = 0; index < HV_VWATCH_MAX_PENDING_HITS; index++) {
        PHV_VWATCH_PENDING_HIT pendingHit =
            &g_VwatchManager.PendingHits[index];
        if (!HvVwatchpClaimPendingHitEntry(pendingHit)) continue;

        LONG sequence = InterlockedCompareExchange(
            &pendingHit->Sequence, 0, 0);
        if ((sequence & 1) != 0 ||
            (ULONG)sequence != (ULONG)Generation) {
            HvVwatchpReleasePendingHitEntry(pendingHit);
            continue;
        }
        if (pendingHit->ThreadToken != ThreadToken ||
            pendingHit->DebuggerPid != DebuggerPid ||
            pendingHit->TargetPid != TargetPid ||
            InterlockedCompareExchange(
                &pendingHit->EventLatched, 0, 0) == 0) {
            HvVwatchpReleasePendingHitEntry(pendingHit);
            continue;
        }
        HvVwatchpClearClaimedPendingHitEntry(pendingHit);
        return TRUE;
    }
    return FALSE;
}

// ============================================================
// Hot path (vmexit, IRQL = root mode 任意)
// ============================================================

static __forceinline VOID
HvVwatchpSetMtf(_In_ BOOLEAN Enable)
{
    SIZE_T ctls = 0;
    __vmx_vmread(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, &ctls);
    if (Enable) ctls |= CPU_BASED_MONITOR_TRAP_FLAG;
    else        ctls &= ~(SIZE_T)CPU_BASED_MONITOR_TRAP_FLAG;
    __vmx_vmwrite(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, ctls);
}

static __forceinline BOOLEAN
HvVwatchpTryReserveMtf(_Inout_ PHV_VWATCH_MTF_CONTEXT Mtf)
{
    SIZE_T controls = 0;
    if (__vmx_vmread(
            VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS,
            &controls) != 0) {
        return FALSE;
    }
    if (InterlockedCompareExchange(
            &Mtf->Active,
            HV_VWATCH_MTF_PUBLISHING,
            HV_VWATCH_MTF_IDLE) != HV_VWATCH_MTF_IDLE) {
        return FALSE;
    }
    if (controls & CPU_BASED_MONITOR_TRAP_FLAG) {
        InterlockedIncrement64(&g_VwatchManager.MtfSharedReservations);
    }
    return TRUE;
}

static __forceinline BOOLEAN
HvVwatchpCanMergeWatchIntoSwBpMtf(_In_ PHV_VWATCH_MTF_CONTEXT Mtf)
{
    SIZE_T controls = 0;
    if (__vmx_vmread(
            VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS,
            &controls) != 0 ||
        (controls & CPU_BASED_MONITOR_TRAP_FLAG) == 0) {
        return FALSE;
    }

    KeMemoryBarrier();
    return InterlockedCompareExchange(
               &Mtf->Active, 0, 0) == HV_VWATCH_MTF_ARMED &&
           Mtf->Reason == HV_VWATCH_MTF_SWBP_REARM &&
           Mtf->PendingPage == NULL &&
           Mtf->PendingSwBpPage != NULL &&
           Mtf->PendingSwBpEntry != NULL;
}

static __forceinline VOID
HvVwatchpPublishMtf(_Inout_ PHV_VWATCH_MTF_CONTEXT Mtf)
{
    KeMemoryBarrier();
    InterlockedExchange(&Mtf->Active, HV_VWATCH_MTF_ARMED);
    HvVwatchpSetMtf(TRUE);
}

static __forceinline VOID
HvVwatchpCancelMtfPublish(_Inout_ PHV_VWATCH_MTF_CONTEXT Mtf)
{
    Mtf->PendingPage = NULL;
    Mtf->PendingSwBpPage = NULL;
    Mtf->PendingSwBpEntry = NULL;
    Mtf->PendingSwBpPte = NULL;
    Mtf->Reason = HV_VWATCH_MTF_NONE;
    Mtf->HitType = 0;
    Mtf->HitSlot = 0;
    Mtf->SwBpDataWrite = FALSE;
    Mtf->HitPrivateEvent = FALSE;
    Mtf->HitDebuggerPid = NULL;
    Mtf->HitTargetPid = NULL;
    Mtf->HitThreadToken = NULL;
    KeMemoryBarrier();
    InterlockedExchange(&Mtf->Active, HV_VWATCH_MTF_IDLE);
}

static PHV_PRIVATE_SWBP_PAGE
HvVwatchpFindSwBpPageRoot(_In_ ULONG64 GpaPage)
{
    for (LONG index = 0; index < HV_PRIVATE_SWBP_MAX_PAGES; index++) {
        PHV_PRIVATE_SWBP_PAGE page = &g_VwatchManager.SwBpPages[index];
        if (InterlockedCompareExchange(&page->InUse, 0, 0) == 0 ||
            InterlockedCompareExchange(&page->Invalidated, 0, 0) != 0 ||
            page->GpaPage != GpaPage ||
            !HvVwatchpAcquireRootRundown(&page->RootRundown)) continue;

        KeMemoryBarrier();
        if (InterlockedCompareExchange(&page->InUse, 0, 0) != 0 &&
            InterlockedCompareExchange(&page->Invalidated, 0, 0) == 0 &&
            page->GpaPage == GpaPage) return page;
        HvVwatchpReleaseRootRundown(&page->RootRundown);
    }
    return NULL;
}

static PHV_PRIVATE_SWBP_ENTRY
HvVwatchpFindSwBpEntryRoot(
    _In_ UINT64 UserCr3,
    _In_ UINT64 Rip)
{
    UserCr3 &= ~((UINT64)0xFFF);
    for (LONG index = 0; index < HV_PRIVATE_SWBP_MAX_ENTRIES; index++) {
        PHV_PRIVATE_SWBP_ENTRY entry = &g_VwatchManager.SwBpEntries[index];
        if (InterlockedCompareExchange(&entry->InUse, 0, 0) == 0 ||
            (entry->UserCr3 & ~((UINT64)0xFFF)) != UserCr3 ||
            (entry->Address != Rip && entry->Address + 1 != Rip) ||
            !HvVwatchpAcquireRootRundown(&entry->RootRundown)) continue;

        KeMemoryBarrier();
        if (InterlockedCompareExchange(&entry->InUse, 0, 0) != 0 &&
            (entry->UserCr3 & ~((UINT64)0xFFF)) == UserCr3 &&
            (entry->Address == Rip || entry->Address + 1 == Rip)) return entry;
        HvVwatchpReleaseRootRundown(&entry->RootRundown);
    }
    return NULL;
}

static PHV_PRIVATE_SWBP_ENTRY
HvVwatchpFindScopedSwBpEntryRoot(
    _In_ UINT64 UserCr3,
    _In_ UINT64 Rip,
    _In_opt_ PVOID ThreadToken)
{
    if (!ThreadToken ||
        InterlockedCompareExchange(
            &g_VwatchManager.ScopedSwBpEntryCount, 0, 0) == 0) {
        return NULL;
    }
    UserCr3 &= ~((UINT64)0xFFF);
    if (!UserCr3) return NULL;

    for (LONG index = 0; index < HV_PRIVATE_SWBP_MAX_ENTRIES; index++) {
        PHV_PRIVATE_SWBP_ENTRY entry = &g_VwatchManager.SwBpEntries[index];
        if (InterlockedCompareExchange(&entry->InUse, 0, 0) == 0 ||
            (PVOID)InterlockedCompareExchangePointer(
                (PVOID volatile*)&entry->ScopeThreadToken,
                NULL,
                NULL) != ThreadToken ||
            (entry->Address != Rip && entry->Address + 1 != Rip) ||
            !HvVwatchpAcquireRootRundown(&entry->RootRundown)) continue;

        KeMemoryBarrier();
        if (InterlockedCompareExchange(&entry->InUse, 0, 0) != 0 &&
            (PVOID)InterlockedCompareExchangePointer(
                (PVOID volatile*)&entry->ScopeThreadToken,
                NULL,
                NULL) == ThreadToken &&
            (entry->Address == Rip || entry->Address + 1 == Rip)) {
            InterlockedExchange64(
                (volatile LONG64*)&entry->UserCr3,
                (LONG64)UserCr3);
            if (entry->PageIndex >= 0 &&
                entry->PageIndex < HV_PRIVATE_SWBP_MAX_PAGES) {
                PHV_PRIVATE_SWBP_PAGE page =
                    &g_VwatchManager.SwBpPages[entry->PageIndex];
                if (InterlockedCompareExchange(&page->InUse, 0, 0) != 0 &&
                    page->TargetPid == entry->TargetPid) {
                    InterlockedExchange64(
                        (volatile LONG64*)&page->UserCr3,
                        (LONG64)UserCr3);
                }
            }
            return entry;
        }
        HvVwatchpReleaseRootRundown(&entry->RootRundown);
    }
    return NULL;
}

static BOOLEAN
HvVwatchpArmSwBpStepOverRoot(
    _In_ PVCPU_DATA VcpuData,
    _Inout_ PHV_PRIVATE_SWBP_ENTRY Entry)
{
    if (Entry->PageIndex < 0 ||
        Entry->PageIndex >= HV_PRIVATE_SWBP_MAX_PAGES) return FALSE;

    LONG pageIndex = Entry->PageIndex;
    PHV_PRIVATE_SWBP_PAGE page =
        &g_VwatchManager.SwBpPages[pageIndex];
    ULONG cpuIndex = HvVwatchpCpuIndex(VcpuData);
    if (cpuIndex >= HV_VWATCH_MAX_CPUS ||
        InterlockedCompareExchange(&page->InUse, 0, 0) == 0 ||
        InterlockedCompareExchange(&page->Invalidated, 0, 0) != 0 ||
        Entry->HitThreadToken != HvVwatchpCurrentThreadToken() ||
        !HvVwatchpAcquireRootRundown(&page->RootRundown)) return FALSE;

    KeMemoryBarrier();
    if (InterlockedCompareExchange(&page->InUse, 0, 0) == 0 ||
        InterlockedCompareExchange(&page->Invalidated, 0, 0) != 0 ||
        Entry->PageIndex != pageIndex) {
        HvVwatchpReleaseRootRundown(&page->RootRundown);
        return FALSE;
    }

    PEPT_PTE_ENTRY slot = HvVwatchpGetActiveSwBpPte(
        page,
        VcpuData,
        cpuIndex);
    PHV_VWATCH_MTF_CONTEXT mtf = &g_VwatchManager.MtfContext[cpuIndex];
    if (!slot || !HvVwatchpTryReserveMtf(mtf) ||
        InterlockedCompareExchange(
            &Entry->State,
            HvPrivateSwBpStepping,
            HvPrivateSwBpContinueArmed) != HvPrivateSwBpContinueArmed) {
        if (InterlockedCompareExchange(&mtf->Active, 0, 0) ==
            HV_VWATCH_MTF_PUBLISHING) {
            HvVwatchpCancelMtfPublish(mtf);
        }
        HvVwatchpReleaseRootRundown(&page->RootRundown);
        return FALSE;
    }

    mtf->PendingPage = NULL;
    mtf->PendingSwBpPage = page;
    mtf->PendingSwBpEntry = Entry;
    mtf->PendingSwBpPte = slot;
    mtf->Reason = HV_VWATCH_MTF_SWBP_REARM;
    mtf->HitType = 0;
    mtf->HitSlot = 0;
    mtf->SwBpDataWrite = FALSE;
    mtf->HitPrivateEvent = FALSE;
    mtf->HitDebuggerPid = NULL;
    mtf->HitTargetPid = NULL;
    mtf->HitThreadToken = NULL;
    if (Entry->StepThreadToken == HvVwatchpCurrentThreadToken()) {
        (void)InterlockedCompareExchange(
            &Entry->StepState,
            HV_VWATCH_STEP_COMPLETING,
            HV_VWATCH_STEP_ARMED);
    }
    HvVwatchpWriteSwBpSlot(slot, page->OriginalPfn, TRUE, TRUE, TRUE);
    HvVwatchpInvalidateCurrentEpt(VcpuData);
    HvVwatchpPublishMtf(mtf);
    return TRUE;
}

BOOLEAN HvVwatchHandleSwBpException(
    _In_ PVCPU_DATA VcpuData,
    _Inout_ PGUEST_CONTEXT Ctx,
    _In_ UINT64 Rip)
{
    if (!g_VwatchManager.Initialized || !VcpuData || !Ctx ||
        VcpuData->IsInL2) return FALSE;

    UINT64 guestCr3 = HvVwatchpGuestCr3(VcpuData);
    PVOID threadToken = HvVwatchpCurrentThreadToken();
    PHV_PRIVATE_SWBP_ENTRY entry =
        HvVwatchpFindSwBpEntryRoot(guestCr3, Rip);
    if (!entry) {
        entry = HvVwatchpFindScopedSwBpEntryRoot(
            guestCr3,
            Rip,
            threadToken);
    }
    if (!entry) return FALSE;

    HANDLE targetPid = entry->TargetPid;
    HANDLE targetTid = NULL;

    if (Rip != entry->Address) {
        HvVwatchpSetGuestRip(VcpuData, entry->Address);
    }

    LONG state = InterlockedCompareExchange(&entry->State, 0, 0);
    if (state == HvPrivateSwBpArmed) {
        if (entry->StepThreadToken == threadToken &&
            InterlockedCompareExchange(
                &entry->StepState,
                HV_VWATCH_STEP_ARMED,
                HV_VWATCH_STEP_ARMED) == HV_VWATCH_STEP_ARMED &&
            InterlockedCompareExchange(
                &entry->State,
                HvPrivateSwBpContinueArmed,
                HvPrivateSwBpArmed) == HvPrivateSwBpArmed) {
            entry->HitTid = entry->StepTid;
            entry->HitThreadToken = threadToken;
            if (HvVwatchpArmSwBpStepOverRoot(VcpuData, entry)) return TRUE;
            entry->HitTid = NULL;
            entry->HitThreadToken = NULL;
            InterlockedCompareExchange(
                &entry->State,
                HvPrivateSwBpArmed,
                HvPrivateSwBpContinueArmed);
        }
        if (InterlockedCompareExchange(
                &entry->State,
                HvPrivateSwBpHitPending,
                HvPrivateSwBpArmed) == HvPrivateSwBpArmed) {
            HV_DEBUG_EVENT event;
            RtlZeroMemory(&event, sizeof(event));
            event.Sequence = HvDbgReserveEventSequence();
            event.Tid = targetTid;
            event.Pid = targetPid;
            event.ThreadToken = threadToken;
            event.Rip = entry->Address;
            event.Kind = HV_DBG_EVT_SWBP;
            RtlCopyMemory(event.Gpr, Ctx, sizeof(event.Gpr));
            if (HvGetCpuVendor() == CPU_VENDOR_AMD) {
                event.Rsp = VcpuData->Vmcb->StateSaveArea.Rsp;
                event.Rflags = VcpuData->Vmcb->StateSaveArea.Rflags;
                event.Cr3 = VcpuData->Vmcb->StateSaveArea.Cr3;
            } else {
                SIZE_T value = 0;
                __vmx_vmread(GUEST_RSP, &value);
                event.Rsp = value;
                __vmx_vmread(GUEST_RFLAGS, &value);
                event.Rflags = value;
                __vmx_vmread(GUEST_CR3, &value);
                event.Cr3 = value;
            }

            entry->HitTid = targetTid;
            entry->HitThreadToken = threadToken;
            entry->Sequence = event.Sequence;
            KeMemoryBarrier();
            NTSTATUS enqueueStatus =
                HvDbgEnqueuePrivateSwBpEventRootNoSignal(
                HvVwatchpCpuIndex(VcpuData),
                entry->DebuggerPid,
                &event);
            if (!NT_SUCCESS(enqueueStatus)) {
                entry->Sequence = 0;
                entry->HitTid = targetTid;
                KeMemoryBarrier();
                if (InterlockedCompareExchange(
                    &entry->State,
                    HvPrivateSwBpContinueArmed,
                    HvPrivateSwBpHitPending) == HvPrivateSwBpHitPending &&
                    HvVwatchpArmSwBpStepOverRoot(VcpuData, entry)) {
                    return TRUE;
                }
                entry->HitTid = NULL;
                entry->HitThreadToken = NULL;
                InterlockedCompareExchange(
                    &entry->State,
                    HvPrivateSwBpArmed,
                    HvPrivateSwBpContinueArmed);
                HvVwatchpReleaseRootRundown(&entry->RootRundown);
                return TRUE;
            }
            InterlockedIncrement64(&g_VwatchManager.SwBpHits);
        }
        HvVwatchpReleaseRootRundown(&entry->RootRundown);
        return TRUE;
    }

    if (state == HvPrivateSwBpContinueArmed &&
        entry->HitThreadToken == threadToken) {
        if (HvVwatchpArmSwBpStepOverRoot(VcpuData, entry)) return TRUE;
    }

    HvVwatchpReleaseRootRundown(&entry->RootRundown);
    return TRUE;
}

/* 注 #DB (vector 1, hardware exception). */
static VOID HvVwatchpInjectDb(VOID)
{
    ULONG64 info = 1ULL | (3ULL << 8) | (1ULL << 31);
    __vmx_vmwrite(VMCS_CTRL_VMENTRY_INTERRUPTION_INFO, info);
}

static VOID
HvVwatchpCommitPendingHardwareHit(
    _Inout_ PHV_VWATCH_PENDING_HIT PendingHit,
    _In_ PVOID ThreadToken,
    _In_ HANDLE DebuggerPid,
    _In_ HANDLE TargetPid,
    _In_ ULONG HitSlot)
{
    InterlockedIncrement(&PendingHit->Sequence);
    PendingHit->ThreadToken = ThreadToken;
    PendingHit->DebuggerPid = DebuggerPid;
    PendingHit->TargetPid = TargetPid;
    PendingHit->Dr6Mask = 1ULL << (HitSlot & 3);
    InterlockedExchange(&PendingHit->EventLatched, 0);
    KeMemoryBarrier();
    InterlockedIncrement(&PendingHit->Sequence);
    InterlockedExchange(
        &PendingHit->State, HV_VWATCH_PENDING_HIT_VALID);
    InterlockedIncrement64(&g_VwatchManager.PendingHitPublishes);
}

static BOOLEAN
HvVwatchpPublishPendingHardwareHit(
    _In_ PVOID ThreadToken,
    _In_ HANDLE DebuggerPid,
    _In_ HANDLE TargetPid,
    _In_ ULONG HitSlot)
{
    if (!ThreadToken || !DebuggerPid || !TargetPid || HitSlot >= 4) {
        InterlockedIncrement64(
            &g_VwatchManager.PendingHitPublishFailures);
        return FALSE;
    }

    for (ULONG attempt = 0; attempt < 4; attempt++) {
        LONG freeIndex = -1;
        LONG latchedIndex = -1;

        for (ULONG index = 0; index < HV_VWATCH_MAX_PENDING_HITS; index++) {
            PHV_VWATCH_PENDING_HIT pendingHit =
                &g_VwatchManager.PendingHits[index];
            LONG state = InterlockedCompareExchange(
                &pendingHit->State, 0, 0);
            if (state == HV_VWATCH_PENDING_HIT_FREE) {
                if (freeIndex < 0) freeIndex = (LONG)index;
                continue;
            }
            if (state != HV_VWATCH_PENDING_HIT_VALID) continue;

            KeMemoryBarrier();
            if (pendingHit->ThreadToken == ThreadToken &&
                pendingHit->TargetPid == TargetPid) {
                if (InterlockedCompareExchange(
                        &pendingHit->State,
                        HV_VWATCH_PENDING_HIT_PUBLISHING,
                        HV_VWATCH_PENDING_HIT_VALID) ==
                    HV_VWATCH_PENDING_HIT_VALID) {
                    if (InterlockedCompareExchange(
                            &pendingHit->EventLatched, 0, 0) == 0) {
                        InterlockedIncrement64(
                            &g_VwatchManager.PendingHitOverwrites);
                    }
                    HvVwatchpCommitPendingHardwareHit(
                        pendingHit,
                        ThreadToken,
                        DebuggerPid,
                        TargetPid,
                        HitSlot);
                    return TRUE;
                }
                continue;
            }
            if (latchedIndex < 0 && InterlockedCompareExchange(
                    &pendingHit->EventLatched, 0, 0) != 0) {
                latchedIndex = (LONG)index;
            }
        }

        LONG candidate = freeIndex >= 0 ? freeIndex : latchedIndex;
        LONG expectedState = freeIndex >= 0
            ? HV_VWATCH_PENDING_HIT_FREE
            : HV_VWATCH_PENDING_HIT_VALID;
        if (candidate >= 0) {
            PHV_VWATCH_PENDING_HIT pendingHit =
                &g_VwatchManager.PendingHits[candidate];
            if (InterlockedCompareExchange(
                    &pendingHit->State,
                    HV_VWATCH_PENDING_HIT_PUBLISHING,
                    expectedState) == expectedState) {
                HvVwatchpCommitPendingHardwareHit(
                    pendingHit,
                    ThreadToken,
                    DebuggerPid,
                    TargetPid,
                    HitSlot);
                return TRUE;
            }
        }
    }

    InterlockedIncrement64(&g_VwatchManager.PendingHitPublishFailures);
    return FALSE;
}

/*
 * A private VT step synthesizes one #DB after MTF has executed the target
 * instruction.  It is not a hardware-created pending debug condition: setting
 * GUEST_PENDING_DEBUG_EXCEPTIONS.BS as well would describe a second #DB.
 *
 * Keep this gate private to the built-in step path.  Real guest exceptions and
 * the external-debugger vwatch path retain their existing replay semantics.
 */
static BOOLEAN HvVwatchpTryInjectPrivateStepDb(VOID)
{
    SIZE_T csSelector = 0;
    SIZE_T activityState = 0;
    SIZE_T entryInfo = 0;
    SIZE_T vectoringInfo = 0;

    __vmx_vmread(GUEST_CS_SELECTOR, &csSelector);
    __vmx_vmread(GUEST_ACTIVITY_STATE, &activityState);
    __vmx_vmread(VMCS_CTRL_VMENTRY_INTERRUPTION_INFO, &entryInfo);
    __vmx_vmread(IDT_VECTORING_INFO, &vectoringInfo);

    if ((csSelector & 3ULL) != 3ULL ||
        activityState != 0 ||
        (entryInfo & (1ULL << 31)) != 0 ||
        (vectoringInfo & (1ULL << 31)) != 0) {
        return FALSE;
    }

    HvVwatchpInjectDb();
    return TRUE;
}

/*
 * 注 #BP (vector 3, software exception). 用于 EXECUTE watch.
 * type=6 (software exception). instruction length=1 (单字节 0xCC).
 *
 * CE / WinDbg 看到 EXCEPTION_BREAKPOINT, 标准 INT3 处理路径.
 *
 * 关键: 注 #BP 后 guest 重新执行那条指令时, 我们必须**先**把 PT 切到允许
 * execute 的状态再 vmentry, 否则又触发 EPT violation 死循环.
 */
static VOID HvVwatchpInjectBp(VOID)
{
    // vector=3, type=6 (software exception, instr length 用 VMENTRY_INSTRUCTION_LENGTH)
    ULONG64 info = 3ULL | (6ULL << 8) | (1ULL << 31);
    __vmx_vmwrite(VMCS_CTRL_VMENTRY_INTERRUPTION_INFO, info);
    __vmx_vmwrite(VMCS_CTRL_VMENTRY_INSTRUCTION_LENGTH, 1);
}

/*
 * 方案 B (CE 硬断闪退修复, 2026-06-26): vwatch 命中后注异常前的三态门控.
 *
 * 根因: vwatch 命中后无条件注 #BP/#DB 给当前 guest. 但:
 *   - 当前 guest 不是 target (同物理页共享 dll/PE 头被别人访问) -> 误注异常
 *     给别的进程 -> 那个进程闪退
 *   - target 没人 attach (CE 没 attach, 没 vectored handler) -> 没人接异常
 *     -> KiUserExceptionDispatcher -> unhandled -> target 闪退
 *
 * 方案 B 三态:
 *   INJECT      curPid == TargetPid AND _EPROCESS.DebugPort != NULL
 *               -> 注异常. KiDispatchException -> DbgkForwardException 把事件给
 *               已 attach 的 CE (CE 用 'Tools->Debugger Options->Use Windows
 *               debugger' + 'Attach to process' 后 DebugPort 非空).
 *   PASS        curPid == TargetPid AND DebugPort == NULL
 *               -> 透传, 不注异常. target 不崩, CE 也收不到 (反正没事件渠道).
 *   WRONG_PROC  curPid != TargetPid
 *               -> 透传, 不跨进程伤人.
 *
 * EPROCESS.DebugPort 偏移按 Win build number 选 (硬编码表).
 * 虚幻调试器不靠 PDB, Netr 上次 PDB 路线卡死撤回, 改硬编码同样工作.
 *
 * 偏移参考 (来自 Windows debugger / Volatility profile 验证, Win 各版本):
 *   Win10 1903-22H2 (build 18362-19045): 0x420
 *   Win11 21H2-23H2 (build 22000-22631): 0x550
 *   Win11 24H2+     (build 26100+):      0x568
 * 不在表内的版本 (新版/老版): fallback 视为 attach (INJECT 路径), 维持闪退修复
 * 之前的老行为 (但 PID 校验仍生效, 不跨进程伤人).
 */
typedef enum _HV_VWATCH_GATE {
    HV_VWATCH_GATE_INJECT = 0,
    HV_VWATCH_GATE_PASS,
    HV_VWATCH_GATE_WRONG_PROC,
} HV_VWATCH_GATE;

#if 0 /* retired: root classification now uses immutable CR3 snapshots */
static ULONG HvVwatchpGetDebugPortOffset(VOID)
{
    ULONG build = g_HvOsBuildNumber;
    // Win11 24H2+
    if (build >= 26100) return 0x568;
    // Win11 21H2 - 23H2
    if (build >= 22000) return 0x550;
    // Win10 1903 - 22H2
    if (build >= 18362) return 0x420;
    // 老 Win10 / 未知 — 返 0 表 "不可用",caller fallback 视为 INJECT
    return 0;
}

static HV_VWATCH_GATE
HvVwatchpGateForCurrentGuest(_In_ HANDLE TargetPid)
{
    // 1) PID 校验 (vmexit handler 上下文 PsGetCurrentProcessId 可用)
    HANDLE curPid = PsGetCurrentProcessId();
    if (curPid != TargetPid) {
        return HV_VWATCH_GATE_WRONG_PROC;
    }

    // 2) DebugPort 校验
    PEPROCESS eproc = PsGetCurrentProcess();
    if (!eproc) {
        return HV_VWATCH_GATE_WRONG_PROC;
    }

    ULONG dpOff = HvVwatchpGetDebugPortOffset();
    if (dpOff == 0) {
        // 未知 Win 版本 — fallback 当 attach. 至少 PID 校验过了, 不会跨进程伤人.
        return HV_VWATCH_GATE_INJECT;
    }

    PVOID dbgPort = NULL;
    __try {
        dbgPort = *(PVOID*)((PUCHAR)eproc + dpOff);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return HV_VWATCH_GATE_WRONG_PROC;
    }

    if (dbgPort == NULL) {
        // target 没被 attach -> 不注异常 (避免闪退)
        return HV_VWATCH_GATE_PASS;
    }

    return HV_VWATCH_GATE_INJECT;
}
#endif

/*
 * 找 GpaPage 对应的 page (不加锁, 用 InUse 原子读).
 */
static PHV_VWATCH_PAGE
HvVwatchpFindPageRoot(_In_ ULONG64 GpaPage)
{
    for (LONG i = 0; i < HV_VWATCH_MAX_PAGES; i++) {
        PHV_VWATCH_PAGE p = &g_VwatchManager.Pages[i];
        if (!InterlockedCompareExchange(&p->InUse, 0, 0) ||
            p->GpaPage != GpaPage ||
            !HvVwatchpAcquireRootRundown(&p->RootRundown)) continue;

        KeMemoryBarrier();
        if (InterlockedCompareExchange(&p->InUse, 0, 0) &&
            p->GpaPage == GpaPage) return p;
        HvVwatchpReleaseRootRundown(&p->RootRundown);
    }
    return NULL;
}

/*
 * 找该 page 上 GLA + 方向真正命中的 entry.
 * Qualification 决定方向 (read/write/fetch), GLA 决定字节范围.
 *
 * 返回 NULL = 未命中任何 entry (只是同页其他字节被访问).
 */
static BOOLEAN
HvVwatchpFindHitEntry(
    _In_ ULONG64 Gla,
    _In_ ULONG64 Qualification,
    _In_ LONG PageIndex,
    _In_ UINT64 GuestCr3,
    _In_opt_ PVOID CurrentThreadToken,
    _Out_ PUCHAR HitType,
    _Out_ PUCHAR HitSlot,
    _Out_ PBOOLEAN HitPrivateEvent,
    _Out_ PHANDLE HitDebuggerPid,
    _Out_ PHANDLE HitTargetPid)
{
    *HitType = 0;
    *HitSlot = 0;
    *HitPrivateEvent = FALSE;
    *HitDebuggerPid = NULL;
    *HitTargetPid = NULL;
    GuestCr3 &= ~((UINT64)0xFFF);
    for (LONG i = 0; i < HV_VWATCH_MAX_ENTRIES; i++) {
        PHV_VWATCH_ENTRY e = &g_VwatchManager.Entries[i];
        if (InterlockedCompareExchange(&e->InUse, 0, 0) == 0 ||
            !HvVwatchpAcquireRootRundown(&e->RootRundown)) {
            continue;
        }
        LONG before = InterlockedCompareExchange(&e->Sequence, 0, 0);
        if (before & 1) {
            HvVwatchpReleaseRootRundown(&e->RootRundown);
            continue;
        }

        LONG inUse = InterlockedCompareExchange(&e->InUse, 0, 0);
        LONG entryPageIndex = e->PageIndex;
        UINT64 entryCr3 = e->UserCr3 & ~((UINT64)0xFFF);
        ULONG64 watchVa = e->WatchVa;
        ULONG length = e->Length;
        ULONG type = e->Type;
        BOOLEAN privateEvent = e->PrivateEvent;
        HANDLE debuggerPid = e->DebuggerPid;
        HANDLE targetPid = e->TargetPid;
        PVOID targetThreadToken = (PVOID)InterlockedCompareExchangePointer(
            (PVOID volatile*)&e->TargetThreadToken,
            NULL,
            NULL);
        KeMemoryBarrier();
        if (before != InterlockedCompareExchange(&e->Sequence, 0, 0) ||
            !inUse || entryPageIndex != PageIndex || entryCr3 != GuestCr3 ||
            (targetThreadToken && targetThreadToken != CurrentThreadToken)) {
            HvVwatchpReleaseRootRundown(&e->RootRundown);
            continue;
        }

        // 字节范围: GLA 落在 [WatchVa, WatchVa+Length) 内 OR
        //         access 覆盖 watch range 内某字节 (GLA == WatchVa-offset 也算)
        // 严格 byte-level: 如果 access size 不知道(EPT violation 不提供), 我们
        // 用 GLA 落在 watch 范围内判定 — 实际访问可能覆盖更大, 但 CE 关心的是
        // 是否触及 watch 字节, 所以 GLA in range 判定足够.
        if (Gla < watchVa || Gla >= watchVa + length) {
            HvVwatchpReleaseRootRundown(&e->RootRundown);
            continue;
        }

        // 方向匹配
        BOOLEAN typeMatch = FALSE;
        switch (type) {
        case HV_VWATCH_TYPE_WRITE:
            typeMatch = (Qualification & EPT_VIO_WRITE) != 0;
            break;
        case HV_VWATCH_TYPE_READWRITE:
            typeMatch = (Qualification & (EPT_VIO_READ | EPT_VIO_WRITE)) != 0;
            break;
        case HV_VWATCH_TYPE_EXECUTE:
            typeMatch = (Qualification & EPT_VIO_FETCH) != 0;
            break;
        default:
            break;
        }
        if (typeMatch) {
            *HitType = (UCHAR)type;
            *HitSlot = (UCHAR)(i % 4);
            *HitPrivateEvent = privateEvent;
            *HitDebuggerPid = debuggerPid;
            *HitTargetPid = targetPid;
            HvVwatchpReleaseRootRundown(&e->RootRundown);
            return TRUE;
        }
        HvVwatchpReleaseRootRundown(&e->RootRundown);
    }
    return FALSE;
}

BOOLEAN HvVwatchHandleEptViolation(
    _In_ PVCPU_DATA VcpuData,
    _In_ ULONG64 Gpa,
    _In_ ULONG64 Qualification,
    _Inout_ PGUEST_CONTEXT Ctx)
{
    UNREFERENCED_PARAMETER(Ctx);

    if (!g_VwatchManager.Initialized || !VcpuData || VcpuData->IsInL2 ||
        (!g_VwatchManager.GloballyEnabled &&
         InterlockedCompareExchange(&g_VwatchManager.SwBpEntryCount, 0, 0) == 0)) {
        return FALSE;
    }

    ULONG64 gpaPage = Gpa & ~((ULONG64)0xFFF);
    PHV_PRIVATE_SWBP_PAGE swBpPage = HvVwatchpFindSwBpPageRoot(gpaPage);
    if (swBpPage) {
        ULONG cpuIndex = HvVwatchpCpuIndex(VcpuData);
        if (cpuIndex >= HV_VWATCH_MAX_CPUS) {
            HvVwatchpReleaseRootRundown(&swBpPage->RootRundown);
            return FALSE;
        }

        PEPT_PTE_ENTRY swBpSlot = HvVwatchpGetActiveSwBpPte(
            swBpPage,
            VcpuData,
            cpuIndex);
        if (!swBpSlot) {
            HvVwatchpReleaseRootRundown(&swBpPage->RootRundown);
            return FALSE;
        }

        if (Qualification & EPT_VIO_FETCH) {
            HvVwatchpWriteSwBpSlot(
                swBpSlot,
                swBpPage->ShadowPfn,
                FALSE,
                FALSE,
                TRUE);
            HvVwatchpInvalidateCurrentEpt(VcpuData);
            HvVwatchpReleaseRootRundown(&swBpPage->RootRundown);
            return TRUE;
        }

        if (Qualification & (EPT_VIO_READ | EPT_VIO_WRITE)) {
            PHV_VWATCH_MTF_CONTEXT swBpMtf =
                &g_VwatchManager.MtfContext[cpuIndex];
            if (!HvVwatchpTryReserveMtf(swBpMtf)) {
                HvVwatchpWriteSwBpSlot(
                    swBpSlot,
                    swBpPage->OriginalPfn,
                    TRUE,
                    TRUE,
                    TRUE);
                HvVwatchpInvalidateCurrentEpt(VcpuData);
                InterlockedIncrement64(
                    &g_VwatchManager.MtfConflictFailOpens);
                HvVwatchpReleaseRootRundown(&swBpPage->RootRundown);
                return TRUE;
            }

            swBpMtf->PendingPage = NULL;
            swBpMtf->PendingSwBpPage = swBpPage;
            swBpMtf->PendingSwBpEntry = NULL;
            swBpMtf->PendingSwBpPte = swBpSlot;
            swBpMtf->Reason = HV_VWATCH_MTF_SWBP_DATA;
            swBpMtf->HitType = 0;
            swBpMtf->HitSlot = 0;
            swBpMtf->SwBpDataWrite =
                (Qualification & EPT_VIO_WRITE) ? TRUE : FALSE;
            swBpMtf->HitPrivateEvent = FALSE;
            swBpMtf->HitDebuggerPid = NULL;
            swBpMtf->HitTargetPid = NULL;
            swBpMtf->HitThreadToken = NULL;
            HvVwatchpWriteSwBpSlot(
                swBpSlot,
                swBpPage->OriginalPfn,
                TRUE,
                TRUE,
                TRUE);
            HvVwatchpInvalidateCurrentEpt(VcpuData);
            HvVwatchpPublishMtf(swBpMtf);
            InterlockedIncrement64(&g_VwatchManager.SwBpDataPasses);
            return TRUE;
        }

        HvVwatchpReleaseRootRundown(&swBpPage->RootRundown);
    }

    PHV_VWATCH_PAGE page = HvVwatchpFindPageRoot(gpaPage);
    if (!page) return FALSE;

    ULONG cpu = HvVwatchpCpuIndex(VcpuData);
    if (cpu >= HV_VWATCH_MAX_CPUS) {
        HvVwatchpReleaseRootRundown(&page->RootRundown);
        return FALSE;
    }

    PEPT_PTE_ENTRY slot = page->CloakedPte[cpu];
    if (!slot) {
        HvVwatchpReleaseRootRundown(&page->RootRundown);
        return FALSE;
    }

    PHV_VWATCH_MTF_CONTEXT mtf = &g_VwatchManager.MtfContext[cpu];
    BOOLEAN mergedMtf = FALSE;
    if (!HvVwatchpTryReserveMtf(mtf)) {
        if (!HvVwatchpCanMergeWatchIntoSwBpMtf(mtf)) {
            InterlockedIncrement64(&g_VwatchManager.MtfMergeFailures);
            HvVwatchpWritePtSlot(slot, page->OriginalPfn, 0);
            HvVwatchpInvalidateCurrentEpt(VcpuData);
            InterlockedIncrement64(
                &g_VwatchManager.MtfConflictFailOpens);
            HvVwatchpReleaseRootRundown(&page->RootRundown);
            return TRUE;
        }
        mergedMtf = TRUE;
    }

    InterlockedIncrement64(&g_VwatchManager.ViolationHits);

    // 检查是否真命中 (GLA + 方向 vs 任意 entry)
    SIZE_T gla = 0;
    __vmx_vmread(GUEST_LINEAR_ADDRESS, &gla);
    LONG pageIdx = (LONG)(page - g_VwatchManager.Pages);
    UCHAR hitType = 0;
    UCHAR hitSlot = 0;
    BOOLEAN hitPrivateEvent = FALSE;
    HANDLE hitDebuggerPid = NULL;
    HANDLE hitTargetPid = NULL;
    BOOLEAN hitEntry = HvVwatchpFindHitEntry(
        (ULONG64)gla,
        Qualification,
        pageIdx,
        HvVwatchpGuestCr3(VcpuData),
        HvVwatchpCurrentThreadToken(),
        &hitType,
        &hitSlot,
        &hitPrivateEvent,
        &hitDebuggerPid,
        &hitTargetPid);

    mtf->HitType = 0;
    mtf->HitSlot = 0;
    mtf->HitPrivateEvent = FALSE;
    mtf->HitDebuggerPid = NULL;
    mtf->HitTargetPid = NULL;
    mtf->HitThreadToken = NULL;

    LONG watchReason = HV_VWATCH_MTF_PASSTHROUGH;
    if (hitEntry) {
        // 字节范围 + 方向匹配. 还要过 "方案 B 闪退修复 gate" 决定是否注异常.
        HV_VWATCH_GATE gate = HV_VWATCH_GATE_INJECT;
        if (gate == HV_VWATCH_GATE_INJECT) {
            // 2026-06-26 v2 致命 bug 修复 (虚幻范式 EPT.cpp:2629-2645):
            // 不能 violation 时立刻注 #DB! 那会让 guest 跳 KiUserExceptionDispatcher,
            // 而那条访问 watch 字节的指令永远没执行 -> debugger continue 后又重新
            // 执行那条指令 -> 再次 violation -> 无限循环 -> target 崩.
            //
            // 正确范式: PT 切全 RWX (已经在 line 981 做了) + arm MTF -> 让 guest
            // 单步过那条指令 -> MTF exit 时再注 #DB. 这时 guest 已经在那条指令的
            // 下一条 RIP, 注 #DB 触发 debugger break, continue 后从下一条指令继续,
            // 不会再回头触发 violation.
            //
            // mtf->Reason = HV_VWATCH_MTF_HIT 让 MTF exit handler 知道单步完后要
            // 注 #DB/#BP, 不是单纯恢复 trap mask.
            watchReason = HV_VWATCH_MTF_HIT;
            mtf->HitType = hitType;   // EXECUTE / WRITE / READWRITE
            mtf->HitSlot = hitSlot;
            mtf->HitPrivateEvent = hitPrivateEvent;
            mtf->HitDebuggerPid = hitDebuggerPid;
            mtf->HitTargetPid = hitTargetPid;
            mtf->HitThreadToken = HvVwatchpCurrentThreadToken();
            InterlockedIncrement64(&g_VwatchManager.TrueHits);
            // 不立刻 inject, 等 MTF exit 再 inject.
        } else {
            // 是 target 但没 attach (PASS) 或 不是 target (WRONG_PROC) —— 都透传不注异常.
            InterlockedIncrement64(&g_VwatchManager.PassthroughHits);
        }
    } else {
        // 同页非 watch 字节访问 → 透传单步, 不注异常
        InterlockedIncrement64(&g_VwatchManager.PassthroughHits);
    }

    if (!mergedMtf) {
        mtf->Reason = watchReason;
        mtf->PendingSwBpPage = NULL;
        mtf->PendingSwBpEntry = NULL;
        mtf->PendingSwBpPte = NULL;
    }
    mtf->SwBpDataWrite = FALSE;
    // 临时切到全 RWX (允许这条指令完成)
    HvVwatchpWritePtSlot(slot, page->OriginalPfn, 0);
    HvVwatchpInvalidateCurrentEpt(VcpuData);
    KeMemoryBarrier();
    mtf->PendingPage = page;

    if (mergedMtf) {
        InterlockedIncrement64(&g_VwatchManager.MtfMergedCollisions);
        if (watchReason == HV_VWATCH_MTF_HIT) {
            InterlockedIncrement64(&g_VwatchManager.MtfMergedTrueHits);
        }
    } else {
        HvVwatchpPublishMtf(mtf);
    }
    return TRUE;
}

static VOID
HvVwatchpDeliverCompletedWatchHit(
    _In_ PVCPU_DATA VcpuData,
    _In_ PGUEST_CONTEXT Ctx,
    _In_ ULONG Cpu,
    _In_ UCHAR HitType,
    _In_ UCHAR HitSlot,
    _In_ BOOLEAN HitPrivateEvent,
    _In_opt_ HANDLE HitDebuggerPid,
    _In_opt_ HANDLE HitTargetPid,
    _In_opt_ PVOID HitThreadToken)
{
    UNREFERENCED_PARAMETER(HitType);

    if (HitPrivateEvent && HitDebuggerPid && HitTargetPid) {
        HV_DEBUG_EVENT event;
        RtlZeroMemory(&event, sizeof(event));
        event.Sequence = HvDbgReserveEventSequence();
        event.Pid = HitTargetPid;
        event.ThreadToken = HitThreadToken;
        event.Kind = HV_DBG_EVT_HWBP;
        event.HitSlot = HitSlot & 3;
        event.Dr6 = 1ULL << (HitSlot & 3);
        RtlCopyMemory(event.Gpr, Ctx, sizeof(event.Gpr));
        if (HvGetCpuVendor() == CPU_VENDOR_AMD) {
            event.Rip = VcpuData->Vmcb->StateSaveArea.Rip;
            event.Rsp = VcpuData->Vmcb->StateSaveArea.Rsp;
            event.Rflags = VcpuData->Vmcb->StateSaveArea.Rflags;
            event.Cr3 = VcpuData->Vmcb->StateSaveArea.Cr3;
        } else {
            SIZE_T value = 0;
            __vmx_vmread(GUEST_RIP, &value);
            event.Rip = value;
            __vmx_vmread(GUEST_RSP, &value);
            event.Rsp = value;
            __vmx_vmread(GUEST_RFLAGS, &value);
            event.Rflags = value;
            __vmx_vmread(GUEST_CR3, &value);
            event.Cr3 = value;
        }
        (void)HvDbgEnqueuePrivateSwBpEventRootNoSignal(
            Cpu,
            HitDebuggerPid,
            &event);
    } else {
        (void)HvVwatchpPublishPendingHardwareHit(
            HitThreadToken,
            HitDebuggerPid,
            HitTargetPid,
            HitSlot);
        HvVwatchpInjectDb();
        InterlockedIncrement64(&g_VwatchManager.InjectedDbCount);
    }
}

BOOLEAN HvVwatchHandleMtfExit(
    _In_ PVCPU_DATA VcpuData,
    _Inout_ PGUEST_CONTEXT Ctx)
{
    if (!g_VwatchManager.Initialized || !VcpuData || !Ctx) return FALSE;

    ULONG cpu = HvVwatchpCpuIndex(VcpuData);
    if (cpu >= HV_VWATCH_MAX_CPUS) return FALSE;

    PHV_VWATCH_MTF_CONTEXT mtf = &g_VwatchManager.MtfContext[cpu];
    if (InterlockedCompareExchange(
            &mtf->Active,
            HV_VWATCH_MTF_COMPLETING,
            HV_VWATCH_MTF_ARMED) != HV_VWATCH_MTF_ARMED) {
        return FALSE;
    }
    KeMemoryBarrier();

    PHV_VWATCH_PAGE page = (PHV_VWATCH_PAGE)mtf->PendingPage;
    PHV_PRIVATE_SWBP_PAGE swBpPage =
        (PHV_PRIVATE_SWBP_PAGE)mtf->PendingSwBpPage;
    PHV_PRIVATE_SWBP_ENTRY swBpEntry =
        (PHV_PRIVATE_SWBP_ENTRY)mtf->PendingSwBpEntry;
    PEPT_PTE_ENTRY swBpPte =
        (PEPT_PTE_ENTRY)mtf->PendingSwBpPte;
    LONG reason = mtf->Reason;
    UCHAR hitType = mtf->HitType;
    UCHAR hitSlot = mtf->HitSlot;
    UCHAR swBpDataWrite = mtf->SwBpDataWrite;
    BOOLEAN hitPrivateEvent = mtf->HitPrivateEvent;
    HANDLE hitDebuggerPid = mtf->HitDebuggerPid;
    HANDLE hitTargetPid = mtf->HitTargetPid;
    PVOID hitThreadToken = mtf->HitThreadToken;

    if (reason == HV_VWATCH_MTF_SWBP_DATA ||
        reason == HV_VWATCH_MTF_SWBP_REARM) {
        BOOLEAN debuggerStepCompleted = FALSE;
        BOOLEAN mergedWatchHit = page && hitType != HV_VWATCH_TYPE_NONE;
        if (swBpPage &&
            InterlockedCompareExchange(&swBpPage->InUse, 0, 0) != 0 &&
            InterlockedCompareExchange(&swBpPage->Invalidated, 0, 0) == 0) {
            if (reason == HV_VWATCH_MTF_SWBP_DATA && swBpDataWrite) {
                (void)HvVwatchpRefreshSwBpShadowRoot(swBpPage, cpu);
            } else {
                if (swBpPte) {
                    HvVwatchpWriteSwBpSlot(
                        swBpPte,
                        swBpPage->ShadowPfn,
                        FALSE,
                        FALSE,
                        TRUE);
                    HvVwatchpInvalidateCurrentEpt(VcpuData);
                }
            }
        }

        if (reason == HV_VWATCH_MTF_SWBP_REARM && swBpEntry &&
            InterlockedCompareExchange(&swBpEntry->InUse, 0, 0) != 0 &&
            InterlockedCompareExchange(
                &swBpEntry->State,
                0,
                0) == HvPrivateSwBpStepping) {
            swBpEntry->HitTid = NULL;
            swBpEntry->HitThreadToken = NULL;
            swBpEntry->Sequence = 0;
            KeMemoryBarrier();
            InterlockedCompareExchange(
                &swBpEntry->State,
                HvPrivateSwBpArmed,
                HvPrivateSwBpStepping);
            InterlockedIncrement64(&g_VwatchManager.SwBpRearms);
            debuggerStepCompleted =
                InterlockedCompareExchange(
                    &swBpEntry->StepState,
                    HV_VWATCH_STEP_COMPLETED,
                    HV_VWATCH_STEP_COMPLETING) ==
                HV_VWATCH_STEP_COMPLETING;
        }

        if (page) {
            PEPT_PTE_ENTRY slot = page->CloakedPte[cpu];
            if (slot && InterlockedCompareExchange(&page->InUse, 0, 0)) {
                HvVwatchpWritePtSlot(
                    slot,
                    page->OriginalPfn,
                    page->CombinedTrapMask);
                HvVwatchpInvalidateCurrentEpt(VcpuData);
            }
        }

        HvVwatchpSetMtf(FALSE);
        mtf->PendingPage = NULL;
        mtf->PendingSwBpPage = NULL;
        mtf->PendingSwBpEntry = NULL;
        mtf->PendingSwBpPte = NULL;
        mtf->Reason = HV_VWATCH_MTF_NONE;
        mtf->HitType = 0;
        mtf->HitSlot = 0;
        mtf->SwBpDataWrite = FALSE;
        mtf->HitPrivateEvent = FALSE;
        mtf->HitDebuggerPid = NULL;
        mtf->HitTargetPid = NULL;
        mtf->HitThreadToken = NULL;
        KeMemoryBarrier();
        if (swBpEntry) {
            HvVwatchpReleaseRootRundown(&swBpEntry->RootRundown);
        }
        if (swBpPage) {
            HvVwatchpReleaseRootRundown(&swBpPage->RootRundown);
        }
        if (page) {
            HvVwatchpReleaseRootRundown(&page->RootRundown);
        }
        InterlockedExchange(&mtf->Active, HV_VWATCH_MTF_IDLE);
        InterlockedIncrement64(&g_VwatchManager.MtfCompletions);
        if (mergedWatchHit) {
            HvVwatchpDeliverCompletedWatchHit(
                VcpuData,
                Ctx,
                cpu,
                hitType,
                hitSlot,
                hitPrivateEvent,
                hitDebuggerPid,
                hitTargetPid,
                hitThreadToken);
        } else if (debuggerStepCompleted) {
            (void)HvVwatchpTryInjectPrivateStepDb();
        }
        return TRUE;
    }

    if (page) {
        PEPT_PTE_ENTRY slot = page->CloakedPte[cpu];
        if (slot && InterlockedCompareExchange(&page->InUse, 0, 0)) {
            // 切回 trap 状态 (按 page 当前 CombinedTrapMask)
            HvVwatchpWritePtSlot(slot, page->OriginalPfn, page->CombinedTrapMask);
            HvVwatchpInvalidateCurrentEpt(VcpuData);
        }
    }
    HvVwatchpSetMtf(FALSE);

    // 2026-06-26 v2 修复 (虚幻范式):
    // MTF exit 时 guest 已经单步过那条访问 watch 字节的指令, RIP 在下一条指令.
    // 现在注 #DB/#BP — debugger 看到 break, continue 后从下一条指令继续,
    // 不会再回头触发 violation.
    if (reason == HV_VWATCH_MTF_HIT) {
        HvVwatchpDeliverCompletedWatchHit(
            VcpuData,
            Ctx,
            cpu,
            hitType,
            hitSlot,
            hitPrivateEvent,
            hitDebuggerPid,
            hitTargetPid,
            hitThreadToken);
    }
    if (page) {
        HvVwatchpReleaseRootRundown(&page->RootRundown);
    }

    mtf->PendingPage = NULL;
    mtf->PendingSwBpPage = NULL;
    mtf->PendingSwBpEntry = NULL;
    mtf->PendingSwBpPte = NULL;
    mtf->Reason = HV_VWATCH_MTF_NONE;
    mtf->HitType = 0;
    mtf->HitSlot = 0;
    mtf->SwBpDataWrite = FALSE;
    mtf->HitPrivateEvent = FALSE;
    mtf->HitDebuggerPid = NULL;
    mtf->HitTargetPid = NULL;
    mtf->HitThreadToken = NULL;
    KeMemoryBarrier();
    InterlockedExchange(&mtf->Active, HV_VWATCH_MTF_IDLE);
    InterlockedIncrement64(&g_VwatchManager.MtfCompletions);
    return TRUE;
}
