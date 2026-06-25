/*
 * HvVwatch.c - 虚拟硬件断点 (EPT-based watch point) — P129 全面优化版
 */

#include "HvVwatch.h"
#include "HvCompat.h"
#include "HvEpt.h"
#include "HvPebCloak.h"        // EptPebSpoof 实例 (P125)
#include "EptHook.h"           // EptInveptAllContexts
#include "HvPhysAccess.h"      // HvPhysFindUserCr3ByPid
#include "HvVtRoot.h"          // HvVtRootResolveUserCr3 / HvVtRootWalkGvaToHpa
#include "SimpleHypervisor.h"
#include <ntstrsafe.h>

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
        PHYSICAL_ADDRESS maxAddr; maxAddr.QuadPart = -1LL;
        PEPT_PTE_ENTRY ptTable =
            (PEPT_PTE_ENTRY)MmAllocateContiguousMemory(PAGE_SIZE, maxAddr);
        if (!ptTable) return NULL;
        RtlZeroMemory(ptTable, PAGE_SIZE);

        for (ULONG i = 0; i < 512; i++) {
            ptTable[i].Value = 0;
            ptTable[i].Read = 1;
            ptTable[i].Write = 1;
            ptTable[i].Execute = 1;
            ptTable[i].MemoryType = 6;
            ptTable[i].PhysicalAddress = ((baseGpa >> 12) + i);
        }

        PHYSICAL_ADDRESS ptPa = MmGetPhysicalAddress(ptTable);

        if (EptTables->SplitPtCount < RTL_NUMBER_OF(EptTables->SplitPt)) {
            EptTables->SplitPt[EptTables->SplitPtCount] = (PEPT_PTE)ptTable;
            EptTables->SplitPtPhysical[EptTables->SplitPtCount] = ptPa;
            EptTables->SplitPtCount++;
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
        for (ULONG i = 0; i < EptTables->SplitPtCount; i++) {
            if ((ULONG64)EptTables->SplitPtPhysical[i].QuadPart == ptPa) {
                return &((PEPT_PTE_ENTRY)EptTables->SplitPt[i])[ptIndex];
            }
        }
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
    newPte.MemoryType = 6;   // WB
    newPte.PhysicalAddress = Pfn;
    Slot->Value = newPte.Value;
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

    s = HvPhysFindUserCr3ByPid(pid32, &cr3);
    if (NT_SUCCESS(s) && cr3) { *OutCr3 = cr3; return STATUS_SUCCESS; }
    return STATUS_NOT_FOUND;
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
        if (!p->InUse && freeIdx < 0) freeIdx = i;
    }
    if (freeIdx < 0) return NULL;

    PHV_VWATCH_PAGE p = &g_VwatchManager.Pages[freeIdx];
    RtlZeroMemory(p, sizeof(*p));
    p->GpaPage = GpaPage;
    p->OriginalPfn = GpaPage >> 12;
    p->RefCount = 0;
    p->CombinedTrapMask = 0;
    p->InUse = 1;
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
    ULONG cpuCount = KeQueryActiveProcessorCount(NULL);
    if (cpuCount > HV_VWATCH_MAX_CPUS) cpuCount = HV_VWATCH_MAX_CPUS;

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
    return ok > 0 ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

/*
 * 释放 page (清所有 PT slot 回 R/W/X, mark not in use). Locked.
 * 调用方保证 Page->RefCount == 0.
 */
static VOID
HvVwatchpFreePageLocked(_Inout_ PHV_VWATCH_PAGE Page)
{
    (void)HvVwatchpApplyMaskAllVcpus(Page, 0);   // 全 R/W/X
    for (ULONG c = 0; c < HV_VWATCH_MAX_CPUS; c++) Page->CloakedPte[c] = NULL;
    Page->InUse = 0;
    Page->GpaPage = 0;
    Page->OriginalPfn = 0;
    Page->RefCount = 0;
    Page->CombinedTrapMask = 0;
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
    g_VwatchManager.GloballyEnabled = FALSE;

    KIRQL old;
    KeAcquireSpinLock(&g_VwatchManager.Lock, &old);

    // 清所有 entry
    for (LONG i = 0; i < HV_VWATCH_MAX_ENTRIES; i++) {
        g_VwatchManager.Entries[i].InUse = 0;
    }
    g_VwatchManager.EntryCount = 0;

    // 清所有 page
    for (LONG i = 0; i < HV_VWATCH_MAX_PAGES; i++) {
        PHV_VWATCH_PAGE p = &g_VwatchManager.Pages[i];
        if (p->InUse) HvVwatchpFreePageLocked(p);
    }

    // 清 VDR cache
    for (LONG i = 0; i < HV_VWATCH_MAX_TARGETS_CACHE; i++) {
        g_VwatchManager.VDrCache[i].InUse = 0;
    }

    KeReleaseSpinLock(&g_VwatchManager.Lock, old);
    EptInveptAllContexts();

    g_VwatchManager.Initialized = FALSE;
    DbgPrint("[Vwatch] Shutdown\n");
}

// ============================================================
// Set / Clear
// ============================================================

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

    KIRQL old;
    KeAcquireSpinLock(&g_VwatchManager.Lock, &old);

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
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // 3) 找/分配新 page
    PHV_VWATCH_PAGE newPage = HvVwatchpGetOrAllocPageLocked(gpaPage);
    if (!newPage) {
        KeReleaseSpinLock(&g_VwatchManager.Lock, old);
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
        KeReleaseSpinLock(&g_VwatchManager.Lock, old);
        DbgPrint("[Vwatch] Set: ApplyMask failed for page 0x%llX\n", gpaPage);
        return as;
    }

    g_VwatchManager.GloballyEnabled = TRUE;
    HvVwatchpInvalidateVDrCacheForTarget(TargetPid);

    KeReleaseSpinLock(&g_VwatchManager.Lock, old);
    EptInveptAllContexts();

    DbgPrint("[Vwatch] Set OK: ent=%d page=%d (mask=0x%X ref=%d) Dbg=%u Target=%u Slot=%u VA=0x%llX Len=%u Type=%u GpaPage=0x%llX\n",
             entryIdx, newPageIdx, combinedMask, newPage->RefCount,
             (ULONG)(ULONG_PTR)DebuggerPid,
             (ULONG)(ULONG_PTR)TargetPid,
             SlotIndex, Address, Length, Type, gpaPage);
    return STATUS_SUCCESS;
#endif
}

NTSTATUS HvVwatchClear(_In_ HANDLE TargetPid, _In_ ULONG SlotIndex)
{
#if !HV_ENABLE_VWATCH
    UNREFERENCED_PARAMETER(TargetPid);
    UNREFERENCED_PARAMETER(SlotIndex);
    return STATUS_NOT_IMPLEMENTED;
#else
    if (!g_VwatchManager.Initialized) return STATUS_DEVICE_NOT_READY;
    if (!TargetPid) return STATUS_INVALID_PARAMETER;
    if (SlotIndex >= 4) return STATUS_INVALID_PARAMETER;

    KIRQL old;
    KeAcquireSpinLock(&g_VwatchManager.Lock, &old);

    LONG entryIdx = -1;
    for (LONG i = (LONG)SlotIndex; i < HV_VWATCH_MAX_ENTRIES; i += 4) {
        PHV_VWATCH_ENTRY e = &g_VwatchManager.Entries[i];
        if (e->InUse && e->TargetPid == TargetPid) {
            entryIdx = i;
            break;
        }
    }
    if (entryIdx < 0) {
        KeReleaseSpinLock(&g_VwatchManager.Lock, old);
        return STATUS_NOT_FOUND;
    }

    PHV_VWATCH_ENTRY e = &g_VwatchManager.Entries[entryIdx];
    LONG pageIdx = e->PageIndex;
    e->InUse = 0;
    e->PageIndex = -1;
    InterlockedDecrement(&g_VwatchManager.EntryCount);

    if (pageIdx >= 0) {
        PHV_VWATCH_PAGE page = &g_VwatchManager.Pages[pageIdx];
        if (InterlockedDecrement(&page->RefCount) <= 0) {
            HvVwatchpFreePageLocked(page);
        } else {
            ULONG newMask = HvVwatchpRecomputeMaskLocked(pageIdx);
            page->CombinedTrapMask = newMask;
            (void)HvVwatchpApplyMaskAllVcpus(page, newMask);
        }
    }

    if (g_VwatchManager.EntryCount <= 0) {
        g_VwatchManager.GloballyEnabled = FALSE;
        g_VwatchManager.EntryCount = 0;
    }
    HvVwatchpInvalidateVDrCacheForTarget(TargetPid);

    KeReleaseSpinLock(&g_VwatchManager.Lock, old);
    EptInveptAllContexts();

    DbgPrint("[Vwatch] Clear PID=%u Slot=%u (ent=%d page=%d)\n",
             (ULONG)(ULONG_PTR)TargetPid, SlotIndex, entryIdx, pageIdx);
    return STATUS_SUCCESS;
#endif
}

VOID HvVwatchClearAllForDebugger(_In_ HANDLE DebuggerPid)
{
    if (!g_VwatchManager.Initialized || !DebuggerPid) return;

    KIRQL old;
    KeAcquireSpinLock(&g_VwatchManager.Lock, &old);

    ULONG cleared = 0;
    LONG affectedPages[HV_VWATCH_MAX_PAGES] = { 0 };

    for (LONG i = 0; i < HV_VWATCH_MAX_ENTRIES; i++) {
        PHV_VWATCH_ENTRY e = &g_VwatchManager.Entries[i];
        if (!e->InUse) continue;
        if (e->DebuggerPid != DebuggerPid) continue;
        HANDLE tgt = e->TargetPid;
        LONG pageIdx = e->PageIndex;
        e->InUse = 0;
        e->PageIndex = -1;
        InterlockedDecrement(&g_VwatchManager.EntryCount);
        if (pageIdx >= 0 && pageIdx < HV_VWATCH_MAX_PAGES) {
            affectedPages[pageIdx] = 1;
            InterlockedDecrement(&g_VwatchManager.Pages[pageIdx].RefCount);
        }
        HvVwatchpInvalidateVDrCacheForTarget(tgt);
        cleared++;
    }

    for (LONG i = 0; i < HV_VWATCH_MAX_PAGES; i++) {
        if (!affectedPages[i]) continue;
        PHV_VWATCH_PAGE p = &g_VwatchManager.Pages[i];
        if (!p->InUse) continue;
        if (p->RefCount <= 0) {
            HvVwatchpFreePageLocked(p);
        } else {
            ULONG mask = HvVwatchpRecomputeMaskLocked(i);
            p->CombinedTrapMask = mask;
            (void)HvVwatchpApplyMaskAllVcpus(p, mask);
        }
    }

    if (g_VwatchManager.EntryCount <= 0) {
        g_VwatchManager.GloballyEnabled = FALSE;
        g_VwatchManager.EntryCount = 0;
    }
    KeReleaseSpinLock(&g_VwatchManager.Lock, old);

    if (cleared) {
        EptInveptAllContexts();
        DbgPrint("[Vwatch] ClearAllForDebugger PID=%u cleared %u entries\n",
                 (ULONG)(ULONG_PTR)DebuggerPid, cleared);
    }
}

VOID HvVwatchClearAllForTarget(_In_ HANDLE TargetPid)
{
    if (!g_VwatchManager.Initialized || !TargetPid) return;

    KIRQL old;
    KeAcquireSpinLock(&g_VwatchManager.Lock, &old);

    ULONG cleared = 0;
    LONG affectedPages[HV_VWATCH_MAX_PAGES] = { 0 };

    for (LONG i = 0; i < HV_VWATCH_MAX_ENTRIES; i++) {
        PHV_VWATCH_ENTRY e = &g_VwatchManager.Entries[i];
        if (!e->InUse) continue;
        if (e->TargetPid != TargetPid) continue;
        LONG pageIdx = e->PageIndex;
        e->InUse = 0;
        e->PageIndex = -1;
        InterlockedDecrement(&g_VwatchManager.EntryCount);
        if (pageIdx >= 0 && pageIdx < HV_VWATCH_MAX_PAGES) {
            affectedPages[pageIdx] = 1;
            InterlockedDecrement(&g_VwatchManager.Pages[pageIdx].RefCount);
        }
        cleared++;
    }

    for (LONG i = 0; i < HV_VWATCH_MAX_PAGES; i++) {
        if (!affectedPages[i]) continue;
        PHV_VWATCH_PAGE p = &g_VwatchManager.Pages[i];
        if (!p->InUse) continue;
        if (p->RefCount <= 0) {
            HvVwatchpFreePageLocked(p);
        } else {
            ULONG mask = HvVwatchpRecomputeMaskLocked(i);
            p->CombinedTrapMask = mask;
            (void)HvVwatchpApplyMaskAllVcpus(p, mask);
        }
    }

    if (g_VwatchManager.EntryCount <= 0) {
        g_VwatchManager.GloballyEnabled = FALSE;
        g_VwatchManager.EntryCount = 0;
    }
    HvVwatchpInvalidateVDrCacheForTarget(TargetPid);

    KeReleaseSpinLock(&g_VwatchManager.Lock, old);
    if (cleared) {
        EptInveptAllContexts();
        DbgPrint("[Vwatch] ClearAllForTarget PID=%u cleared %u entries\n",
                 (ULONG)(ULONG_PTR)TargetPid, cleared);
    }
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

/*
 * 注 #DB (vector 1, hardware exception). 用于 R/W watch.
 * 硬件在 #DB delivery 时根据 DR6 cause 自动设位 (B0..B3 / BS), 但我们没设过
 * DR6, 所以 KiUserExceptionDispatcher 看到 EXCEPTION_SINGLE_STEP 而不是 HWBP
 * 命中——这跟 CE 软件单步行为一致, CE 调试器路径都能处理.
 */
static VOID HvVwatchpInjectDb(VOID)
{
    ULONG64 info = 1ULL | (3ULL << 8) | (1ULL << 31);
    __vmx_vmwrite(VMCS_CTRL_VMENTRY_INTERRUPTION_INFO, info);
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
 * 找 GpaPage 对应的 page (不加锁, 用 InUse 原子读).
 */
static PHV_VWATCH_PAGE
HvVwatchpFindPageRoot(_In_ ULONG64 GpaPage)
{
    for (LONG i = 0; i < HV_VWATCH_MAX_PAGES; i++) {
        PHV_VWATCH_PAGE p = &g_VwatchManager.Pages[i];
        if (InterlockedCompareExchange(&p->InUse, 0, 0) && p->GpaPage == GpaPage) {
            return p;
        }
    }
    return NULL;
}

/*
 * 找该 page 上 GLA + 方向真正命中的 entry.
 * Qualification 决定方向 (read/write/fetch), GLA 决定字节范围.
 *
 * 返回 NULL = 未命中任何 entry (只是同页其他字节被访问).
 */
static PHV_VWATCH_ENTRY
HvVwatchpFindHitEntry(_In_ ULONG64 Gla, _In_ ULONG64 Qualification, _In_ LONG PageIndex)
{
    for (LONG i = 0; i < HV_VWATCH_MAX_ENTRIES; i++) {
        PHV_VWATCH_ENTRY e = &g_VwatchManager.Entries[i];
        if (!InterlockedCompareExchange(&e->InUse, 0, 0)) continue;
        if (e->PageIndex != PageIndex) continue;

        // 字节范围: GLA 落在 [WatchVa, WatchVa+Length) 内 OR
        //         access 覆盖 watch range 内某字节 (GLA == WatchVa-offset 也算)
        // 严格 byte-level: 如果 access size 不知道(EPT violation 不提供), 我们
        // 用 GLA 落在 watch 范围内判定 — 实际访问可能覆盖更大, 但 CE 关心的是
        // 是否触及 watch 字节, 所以 GLA in range 判定足够.
        if (Gla < e->WatchVa) continue;
        if (Gla >= e->WatchVa + e->Length) continue;

        // 方向匹配
        BOOLEAN typeMatch = FALSE;
        switch (e->Type) {
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
        if (typeMatch) return e;
    }
    return NULL;
}

BOOLEAN HvVwatchHandleEptViolation(
    _In_ ULONG64 Gpa,
    _In_ ULONG64 Qualification,
    _Inout_ PGUEST_CONTEXT Ctx)
{
    UNREFERENCED_PARAMETER(Ctx);

    if (!g_VwatchManager.Initialized || !g_VwatchManager.GloballyEnabled) {
        return FALSE;
    }

    ULONG64 gpaPage = Gpa & ~((ULONG64)0xFFF);
    PHV_VWATCH_PAGE page = HvVwatchpFindPageRoot(gpaPage);
    if (!page) return FALSE;

    ULONG cpu = KeGetCurrentProcessorNumberEx(NULL);
    if (cpu >= HV_VWATCH_MAX_CPUS) return FALSE;

    PEPT_PTE_ENTRY slot = page->CloakedPte[cpu];
    if (!slot) return FALSE;

    PHV_VWATCH_MTF_CONTEXT mtf = &g_VwatchManager.MtfContext[cpu];
    if (InterlockedCompareExchange(&mtf->Active, 1, 0) != 0) {
        return FALSE;
    }
    mtf->PendingPage = page;

    InterlockedIncrement64(&g_VwatchManager.ViolationHits);

    // 检查是否真命中 (GLA + 方向 vs 任意 entry)
    SIZE_T gla = 0;
    __vmx_vmread(GUEST_LINEAR_ADDRESS, &gla);
    LONG pageIdx = (LONG)(page - g_VwatchManager.Pages);
    PHV_VWATCH_ENTRY hitEntry = HvVwatchpFindHitEntry((ULONG64)gla, Qualification, pageIdx);

    // 临时切到全 RWX (允许这条指令完成)
    HvVwatchpWritePtSlot(slot, page->OriginalPfn, 0);
    EptInveptAllContexts();

    if (hitEntry) {
        // 真命中
        mtf->Reason = HV_VWATCH_MTF_HIT;
        InterlockedIncrement64(&g_VwatchManager.TrueHits);

        if (hitEntry->Type == HV_VWATCH_TYPE_EXECUTE) {
            HvVwatchpInjectBp();
            InterlockedIncrement64(&g_VwatchManager.InjectedBpCount);
        } else {
            HvVwatchpInjectDb();
            InterlockedIncrement64(&g_VwatchManager.InjectedDbCount);
        }
    } else {
        // 同页非 watch 字节访问 → 透传单步, 不注异常
        mtf->Reason = HV_VWATCH_MTF_PASSTHROUGH;
        InterlockedIncrement64(&g_VwatchManager.PassthroughHits);
    }

    HvVwatchpSetMtf(TRUE);
    return TRUE;
}

BOOLEAN HvVwatchHandleMtfExit(_Inout_ PGUEST_CONTEXT Ctx)
{
    UNREFERENCED_PARAMETER(Ctx);

    if (!g_VwatchManager.Initialized) return FALSE;

    ULONG cpu = KeGetCurrentProcessorNumberEx(NULL);
    if (cpu >= HV_VWATCH_MAX_CPUS) return FALSE;

    PHV_VWATCH_MTF_CONTEXT mtf = &g_VwatchManager.MtfContext[cpu];
    if (!InterlockedCompareExchange(&mtf->Active, 0, 1)) {
        return FALSE;
    }

    PHV_VWATCH_PAGE page = (PHV_VWATCH_PAGE)mtf->PendingPage;
    mtf->PendingPage = NULL;
    LONG reason = mtf->Reason;
    mtf->Reason = HV_VWATCH_MTF_NONE;

    UNREFERENCED_PARAMETER(reason);

    if (page) {
        PEPT_PTE_ENTRY slot = page->CloakedPte[cpu];
        if (slot && InterlockedCompareExchange(&page->InUse, 0, 0)) {
            // 切回 trap 状态 (按 page 当前 CombinedTrapMask)
            HvVwatchpWritePtSlot(slot, page->OriginalPfn, page->CombinedTrapMask);
            EptInveptAllContexts();
        }
    }
    HvVwatchpSetMtf(FALSE);
    InterlockedIncrement64(&g_VwatchManager.MtfCompletions);
    return TRUE;
}
