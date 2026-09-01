/*
 * HvPebCloak.c - PEB 字段级 EPT spoof
 *
 * P125 (2026-06-25): 见 HvPebCloak.h 顶部说明.
 */

#include "HvPebCloak.h"
#include "HvCompat.h"
#include "HvCpu.h"
#include "HvEpt.h"            // HvEptBuildIdentityInto
#include "EptHook.h"          // EPT_PTE_ENTRY, EptInveptAllContexts, EptGetPteForPhysicalAddress
#include "HvPhysAccess.h"     // HvPhysGvaToHpa
#include "HvVtRoot.h"         // HvVtRootGetResolvedUserCr3
#include "HvVwatch.h"
#include "HvPrivateDebugObject.h"

NTSYSAPI NTSTATUS NTAPI ZwWaitForSingleObject(
    _In_ HANDLE Handle,
    _In_ BOOLEAN Alertable,
    _In_opt_ PLARGE_INTEGER Timeout);
#include "HvNested.h"
#include "SimpleHypervisor.h"
#include <ntstrsafe.h>

// P122: 全 driver DbgPrint → GUI ring
#define HV_TRACE_THIS_CAT HV_TRACE_CAT_CLOAK
#include "HvTrace.h"

// PEB cloak is compiled in.  Runtime publication still requires a complete
// overlay EPT on every virtualized Intel CPU and a lifetime-safe target.
#ifndef HV_ENABLE_PEB_CLOAK
#define HV_ENABLE_PEB_CLOAK 1
#endif

// PsGetProcessPeb prototype (ntifs.h 在 WDK 中不一定可用)
NTKERNELAPI PVOID PsGetProcessPeb(_In_ PEPROCESS Process);

#define HV_PEB_TAG     'kCbP'  // PbCk
#define HV_PEB_EPT_READ_ACCESS     (1ULL << 0)
#define HV_PEB_EPT_WRITE_ACCESS    (1ULL << 1)
#define HV_PEB_EPT_EXECUTE_ACCESS  (1ULL << 2)
#define HV_PEB_REBIND_POLL_100NS   (250ULL * 10ULL * 1000ULL)
#define HV_PEB_REBIND_MAX_SHIFT    5
#define HV_PEB_PAGE_DRAIN_POLLS    2000

// ============================================================
// 全局
// ============================================================

HV_PEB_CLOAK_MANAGER g_PebCloakManager = { 0 };

// EX_PUSH_LOCK is valid when zero initialized. Keeping this lock independent
// from the PEB manager also allows the overlay EPT to remain usable by vwatch.
static EX_PUSH_LOCK g_OverlayEptMutationLock = 0;

static VOID HvPebCloakpRebindWorker(_In_ PVOID Context);
static NTSTATUS HvPebCloakpRebindTargetLocked(
    _Inout_ PHV_PEB_CLOAK_TARGET Target);

VOID HvOverlayEptAcquireMutation(VOID)
{
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_OverlayEptMutationLock);
}

VOID HvOverlayEptReleaseMutation(VOID)
{
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
    ExReleasePushLockExclusive(&g_OverlayEptMutationLock);
    KeLeaveCriticalRegion();
}

static __forceinline BOOLEAN
HvPebCloakpAcquireRootReference(VOID)
{
    if (InterlockedCompareExchange(
            &g_PebCloakManager.ShuttingDown, 0, 0) != 0 ||
        InterlockedCompareExchange(
            &g_PebCloakManager.Initialized, 0, 0) == 0) {
        return FALSE;
    }

    InterlockedIncrement(&g_PebCloakManager.RootReaders);
    MemoryBarrier();
    if (InterlockedCompareExchange(
            &g_PebCloakManager.ShuttingDown, 0, 0) != 0 ||
        InterlockedCompareExchange(
            &g_PebCloakManager.Initialized, 0, 0) == 0) {
        InterlockedDecrement(&g_PebCloakManager.RootReaders);
        return FALSE;
    }
    return TRUE;
}

static __forceinline VOID
HvPebCloakpReleaseRootReference(VOID)
{
    InterlockedDecrement(&g_PebCloakManager.RootReaders);
}

static __forceinline BOOLEAN
HvPebCloakpAcquirePageRootReference(
    _Inout_ PHV_PEB_CLOAK_PAGE Page)
{
    LONG gate;

    if (!Page) return FALSE;
    for (;;) {
        gate = InterlockedCompareExchange(&Page->RootGate, 0, 0);
        if ((gate & HV_PEB_PAGE_ROOT_CLOSING) != 0 ||
            (gate & HV_PEB_PAGE_ROOT_COUNT_MASK) ==
                HV_PEB_PAGE_ROOT_COUNT_MASK) {
            return FALSE;
        }
        if (InterlockedCompareExchange(
                &Page->RootGate, gate + 1, gate) == gate) {
            return TRUE;
        }
    }
}

static __forceinline VOID
HvPebCloakpReleasePageRootReference(
    _Inout_ PHV_PEB_CLOAK_PAGE Page)
{
    InterlockedDecrement(&Page->RootGate);
}

static VOID
HvPebCloakpClosePageRootGate(
    _Inout_ PHV_PEB_CLOAK_PAGE Page)
{
    InterlockedOr(&Page->RootGate, HV_PEB_PAGE_ROOT_CLOSING);
    MemoryBarrier();
}

static BOOLEAN
HvPebCloakpWaitForPageRootReaders(
    _Inout_ PHV_PEB_CLOAK_PAGE Page)
{
    LARGE_INTEGER delay;

    delay.QuadPart = -10000LL; /* 1 ms */
    for (ULONG poll = 0; poll < HV_PEB_PAGE_DRAIN_POLLS; ++poll) {
        LONG gate = InterlockedCompareExchange(&Page->RootGate, 0, 0);
        if ((gate & HV_PEB_PAGE_ROOT_COUNT_MASK) == 0) {
            return TRUE;
        }
        KeDelayExecutionThread(KernelMode, FALSE, &delay);
    }
    return FALSE;
}

static VOID
HvPebCloakpDrainPageRootReaders(
    _Inout_ PHV_PEB_CLOAK_PAGE Page)
{
    while (!HvPebCloakpWaitForPageRootReaders(Page)) {
        DbgPrint("[PebCloak] Waiting for page root/MTF owner to drain\n");
    }
}

static __forceinline VOID
HvPebCloakpOpenPageRootGate(
    _Inout_ PHV_PEB_CLOAK_PAGE Page)
{
    NT_ASSERT((InterlockedCompareExchange(&Page->RootGate, 0, 0) &
               HV_PEB_PAGE_ROOT_COUNT_MASK) == 0);
    MemoryBarrier();
    InterlockedExchange(&Page->RootGate, 0);
}

static VOID
HvPebCloakpWaitForRootReaders(VOID)
{
    LARGE_INTEGER delay;
    delay.QuadPart = -10000LL; /* 1 ms */
    while (InterlockedCompareExchange(
               &g_PebCloakManager.RootReaders, 0, 0) != 0) {
        KeDelayExecutionThread(KernelMode, FALSE, &delay);
    }
}

static __forceinline VOID
HvPebCloakpWritePte(
    _Inout_ PEPT_PTE_ENTRY Slot,
    _In_ EPT_PTE_ENTRY Value)
{
    InterlockedExchange64(
        (volatile LONG64*)&Slot->Value,
        (LONG64)Value.Value);
}

static BOOLEAN
HvPebCloakpGetVcpuIndex(
    _In_ PVCPU_DATA Vcpu,
    _Out_ PULONG CpuIndex)
{
    ULONG_PTR index;

    *CpuIndex = MAXULONG;
    if (!Vcpu || !g_HypervisorContext.VcpuData) {
        return FALSE;
    }

    index = (ULONG_PTR)(Vcpu - g_HypervisorContext.VcpuData);
    if (index >= g_HypervisorContext.ProcessorCount ||
        index >= HV_PEB_CLOAK_MAX_CPUS) {
        return FALSE;
    }

    *CpuIndex = (ULONG)index;
    return TRUE;
}

// ============================================================
// 内部 helpers
// ============================================================

/*
 * 找 EptPebSpoof 中某 GPA 的 PT slot 指针. 必要时 split 2MB 大页.
 * IRQL = PASSIVE.
 *
 * EptPebSpoof 由 HvPebCloakSetupVcpu 在 HvEptBuildIdentityInto 之后建好,
 * 整个低 512GB 都是 2MB 大页. 第一次 cloak 某个 PEB 页时, 我们要把
 * 那个 2MB 大页拆成 PT, 把目标 PT slot 配出来.
 */
static PEPT_PTE_ENTRY
HvPebCloakpFindOrSplitPtSlot(
    _In_ PEPT_TABLES EptTables,
    _In_ ULONG64 Gpa)
{
    ULONG64 pml4Index = (Gpa >> 39) & 0x1FF;
    ULONG64 pdptIndex = (Gpa >> 30) & 0x1FF;
    ULONG64 pdIndex   = (Gpa >> 21) & 0x1FF;
    ULONG64 ptIndex   = (Gpa >> 12) & 0x1FF;

    if (pml4Index != 0 || pdptIndex >= 512) {
        // 当前只 cloak 主内存区域 (低 512GB), PEB 永远在这里
        return NULL;
    }

    EPT_PDE* pde = &EptTables->Pd[pdptIndex][pdIndex];
    if (!(pde->Read || pde->Write || pde->Execute)) {
        return NULL;
    }

    ULONG64 baseGpa = (pdptIndex * 512 + pdIndex) * 0x200000ULL;

    if (pde->Value & (1ULL << 7)) {
        // 2MB 大页, 需要 split
        PHYSICAL_ADDRESS ptPa;
        PEPT_PTE_ENTRY ptTable =
            (PEPT_PTE_ENTRY)HvEptAllocateSplitPt(EptTables, &ptPa);
        if (!ptTable) return NULL;
        RtlZeroMemory(ptTable, PAGE_SIZE);

        // 把 512 个 4KB slot 填成 identity, R/W/X 继承
        for (ULONG i = 0; i < 512; i++) {
            ptTable[i].Value = 0;
            ptTable[i].Read = 1;
            ptTable[i].Write = 1;
            ptTable[i].Execute = 1;
            ptTable[i].MemoryType = HvEptGetMemoryType(
                baseGpa + ((ULONG64)i * PAGE_SIZE), PAGE_SIZE);
            ptTable[i].PhysicalAddress = ((baseGpa >> 12) + i);
        }

        // 把 PDE 改成指向 PT (清 LargePage 位)
        EPT_PDE newPde; newPde.Value = 0;
        newPde.Read = 1;
        newPde.Write = 1;
        newPde.Execute = 1;
        newPde.PageFrameNumber = (ULONG64)(ptPa.QuadPart >> 12);
        pde->Value = newPde.Value;

        return &ptTable[ptIndex];
    } else {
        // 已 split, 从 SplitPt[] 反查 PT base
        ULONG64 ptPa = (ULONG64)pde->PageFrameNumber << 12;
        PEPT_PTE splitPt = HvEptFindSplitPt(EptTables, ptPa >> PAGE_SHIFT);
        if (splitPt) return &((PEPT_PTE_ENTRY)splitPt)[ptIndex];
        // 没记录, 兜底返 NULL
        return NULL;
    }
}

/*
 * 切某 vcpu 的 VMCS_CTRL_EPTP. 必须 vmexit 上下文调用 (vmread/vmwrite 都需 VMX root).
 */
static __forceinline VOID
HvPebCloakpVmwriteEptpAndInvept(_In_ ULONG64 Eptp)
{
    __vmx_vmwrite(VMCS_CTRL_EPTP, Eptp);
    EptInveptAllContexts();
}

/*
 * 设置 / 清除 CPU_BASED_MONITOR_TRAP_FLAG. VMX root 安全.
 */
static __forceinline VOID
HvPebCloakpSetMtf(_In_ BOOLEAN Enable)
{
    SIZE_T ctls = 0;
    __vmx_vmread(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, &ctls);
    if (Enable) {
        ctls |= CPU_BASED_MONITOR_TRAP_FLAG;
    } else {
        ctls &= ~(SIZE_T)CPU_BASED_MONITOR_TRAP_FLAG;
    }
    __vmx_vmwrite(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, ctls);
}

static __forceinline BOOLEAN
HvPebCloakpTryReserveMtf(_Inout_ PHV_PEB_MTF_CONTEXT Mtf)
{
    SIZE_T controls = 0;

    __vmx_vmread(
        VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS,
        &controls);
    if ((controls & CPU_BASED_MONITOR_TRAP_FLAG) != 0) {
        return FALSE;
    }
    return InterlockedCompareExchange(
               &Mtf->Active,
               HV_PEB_MTF_PUBLISHING,
               HV_PEB_MTF_IDLE) == HV_PEB_MTF_IDLE;
}

/*
 * 解出 target user CR3. 走 VtRoot KVAS-safe 路径.
 *
 * P126.2 fix (2026-06-25): 直接调 HvVtRootResolveUserCr3 (mode=3 VMCALL),
 *   root mode 跑 24 候选 + MDL 锁定 PFN 双锚点 + 返回真 CR3. 不依赖 cache 命中,
 *   不依赖 dummy read 副作用. 这是 KVAS Win11 24H2 唯一可靠路径.
 *
 *   之前 P126.1 试图 cache + dummy HvVtRootCopyByPid 触发, 但 CopyByPid
 *   走的是 mode=0 (Read), root handler 在那条路径上**不会主动写 cache** —
 *   只有 mode=3 (RESOLVE_CR3) 才会跑 24 候选 + 必填 cache. 实测 trace 2026-06-25.
 */
static NTSTATUS
HvPebCloakpResolveUserCr3(_In_ HANDLE Pid, _Out_ PUINT64 OutCr3)
{
    *OutCr3 = 0;
    if (!Pid) return STATUS_INVALID_PARAMETER;

    UINT64 cr3 = 0;
    ULONG pid32 = (ULONG)(ULONG_PTR)Pid;

    // 1) 直接调 ResolveUserCr3 (mode=3 VMCALL), 必走 24-候选 walk
    NTSTATUS s = HvVtRootResolveUserCr3(pid32, &cr3);
    if (NT_SUCCESS(s) && cr3) {
        *OutCr3 = cr3;
        return STATUS_SUCCESS;
    }

    return NT_SUCCESS(s) ? STATUS_NOT_FOUND : s;
}

/*
 * Page patch 描述符 (HvPebCloakpResolveAndPatch 用).
 * Offset/Size/Mask/SetTo 共同定义一处字段抹除规则.
 */
typedef HV_PEB_PATCH_RULE HV_PEB_FIELD_PATCH;

/*
 * 在补丁页 PatchVa 上, 按 patches[] 修改若干字段. 每个 patch 是字段 VA →
 * 页内 offset 的转换 + 操作.
 */
static VOID
HvPebCloakpApplyPatches(
    _Inout_ PVOID PatchVa,
    _In_reads_(Count) const HV_PEB_FIELD_PATCH* Patches,
    _In_ ULONG Count)
{
    UCHAR* p = (UCHAR*)PatchVa;
    for (ULONG i = 0; i < Count; i++) {
        const HV_PEB_FIELD_PATCH* pp = &Patches[i];
        switch (pp->Operation) {
        case HV_PEB_PATCH_SET_BYTE:
            if (pp->Offset < PAGE_SIZE) {
                p[pp->Offset] = (UCHAR)(pp->Value & 0xFF);
            }
            break;
        case HV_PEB_PATCH_AND_DWORD:
            if (pp->Offset + 4 <= PAGE_SIZE) {
                *(volatile ULONG*)(p + pp->Offset) &= pp->Value;
            }
            break;
        case HV_PEB_PATCH_SET_DWORD:
            if (pp->Offset + 4 <= PAGE_SIZE) {
                *(volatile ULONG*)(p + pp->Offset) = pp->Value;
            }
            break;
        }
    }
}

static NTSTATUS
HvPebCloakpRefreshPatchPageRoot(
    _Inout_ PVCPU_DATA Vcpu,
    _Inout_ PHV_PEB_CLOAK_PAGE Page)
{
    SIZE_T bytesDone = 0;
    NTSTATUS status;
    LONG activeIndex;
    LONG refreshIndex;
    PVOID refreshVa;

    if (!Vcpu || !Page || !Page->PatchVa || !Page->PatchVaAlt ||
        !Page->UserCr3 ||
        Page->PatchCount == 0 ||
        Page->PatchCount > HV_PEB_CLOAK_MAX_PATCHES_PER_PAGE) {
        return STATUS_INVALID_PARAMETER;
    }
    if (InterlockedCompareExchange(&Page->RefreshBusy, 1, 0) != 0) {
        InterlockedExchange(&Page->Stale, TRUE);
        return STATUS_DEVICE_BUSY;
    }

    activeIndex = InterlockedCompareExchange(
        &Page->ActivePatchIndex, 0, 0);
    refreshIndex = activeIndex == 0 ? 1 : 0;
    if (InterlockedCompareExchange(
            &Page->PatchReaders[refreshIndex], 0, 0) != 0) {
        InterlockedExchange(&Page->Stale, TRUE);
        InterlockedExchange(&Page->RefreshBusy, FALSE);
        return STATUS_RETRY;
    }
    refreshVa = refreshIndex == 0 ? Page->PatchVa : Page->PatchVaAlt;

    status = HvVtRootRootCopyOnePage(
        Vcpu,
        Page->UserCr3,
        Page->GuestVa,
        (PUCHAR)refreshVa,
        PAGE_SIZE,
        FALSE,
        &bytesDone);
    if (!NT_SUCCESS(status) || bytesDone != PAGE_SIZE) {
        status = NT_SUCCESS(status) ? STATUS_PARTIAL_COPY : status;
        InterlockedExchange(&Page->Stale, TRUE);
        InterlockedExchange(&Page->RefreshBusy, FALSE);
        return status;
    }

    HvPebCloakpApplyPatches(
        refreshVa,
        Page->PatchRules,
        Page->PatchCount);
    MemoryBarrier();
    InterlockedExchange(&Page->ActivePatchIndex, refreshIndex);
    InterlockedExchange(&Page->Stale, FALSE);
    InterlockedExchange(&Page->RefreshBusy, FALSE);
    return STATUS_SUCCESS;
}

/*
 * 解 GVA → GPA.
 *
 * P126.2 fix: 走 root mode HvVtRootWalkGvaToHpa (mode=4 VMCALL), 不依赖
 *   PASSIVE 层 walker (HvPhysGvaToHpa 在 KVAS Win11 24H2 走 host shadow PT
 *   完全看不见 user PT). UserCr3 参数保留作 future 用, 当前 root mode 自己
 *   按 PID 解 CR3 (Pid 参数走 mode=3 cache 命中).
 */
static NTSTATUS
HvPebCloakpGvaToGpa(
    _In_ ULONG Pid,
    _In_ UINT64 UserCr3,
    _In_ ULONG64 Gva,
    _Out_ PULONG64 OutGpa)
{
    UNREFERENCED_PARAMETER(UserCr3);
    *OutGpa = 0;
    UINT64 hpa = 0;
    UINT64 pageSize = 0;
    NTSTATUS s = HvVtRootWalkGvaToHpa(
        Pid, Gva, &hpa, &pageSize);
    if (!NT_SUCCESS(s) || hpa == 0 || pageSize != PAGE_SIZE) {
        return NT_SUCCESS(s) ? STATUS_NOT_SUPPORTED : s;
    }
    *OutGpa = hpa;
    return STATUS_SUCCESS;
}

/*
 * 准备一个 cloak page:
 *   1) 解 GVA → GPA → 页基
 *   2) 分配 4KB 补丁页
 *   3) 通过 HvVtRootCopyByPid 在 VT-root 复制原页内容 → 补丁页
 *   4) 按 patches[] 抹字段
 * 失败回滚 (释放补丁页).
 */
static NTSTATUS
HvPebCloakpPrepareCloakPage(
    _In_ HANDLE Pid,
    _In_ UINT64 UserCr3,
    _In_ ULONG64 FieldVa,
    _In_reads_(PatchCount) const HV_PEB_FIELD_PATCH* Patches,
    _In_ ULONG PatchCount,
    _Out_ PHV_PEB_CLOAK_PAGE OutPage)
{
    RtlZeroMemory(OutPage, sizeof(*OutPage));
    if (!Patches || PatchCount == 0 ||
        PatchCount > HV_PEB_CLOAK_MAX_PATCHES_PER_PAGE) {
        return STATUS_INVALID_PARAMETER;
    }

    ULONG64 pageVa = FieldVa & ~((ULONG64)0xFFF);
    OutPage->GuestVa = pageVa;
    OutPage->UserCr3 = UserCr3;
    OutPage->PatchCount = PatchCount;
    RtlCopyMemory(
        OutPage->PatchRules,
        Patches,
        sizeof(HV_PEB_PATCH_RULE) * PatchCount);

    NTSTATUS s = HvPebCloakpGvaToGpa((ULONG)(ULONG_PTR)Pid, UserCr3, pageVa, &OutPage->GpaPage);
    if (!NT_SUCCESS(s)) return s;
    OutPage->OriginalPfn = OutPage->GpaPage >> 12;

    PHYSICAL_ADDRESS maxAddr; maxAddr.QuadPart = -1LL;
    PVOID patch = MmAllocateContiguousMemory(PAGE_SIZE, maxAddr);
    if (!patch) return STATUS_INSUFFICIENT_RESOURCES;
    PVOID patchAlt = MmAllocateContiguousMemory(PAGE_SIZE, maxAddr);
    if (!patchAlt) {
        MmFreeContiguousMemory(patch);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(patch, PAGE_SIZE);
    RtlZeroMemory(patchAlt, PAGE_SIZE);

    SIZE_T bytesDone = 0;
    s = HvVtRootCopyByPid(
        (ULONG)(ULONG_PTR)Pid,
        pageVa,
        patch,
        PAGE_SIZE,
        FALSE,
        &bytesDone);
    if (NT_SUCCESS(s) && bytesDone != PAGE_SIZE) {
        s = STATUS_PARTIAL_COPY;
    }

    if (!NT_SUCCESS(s)) {
        MmFreeContiguousMemory(patch);
        MmFreeContiguousMemory(patchAlt);
        return s;
    }

    HvPebCloakpApplyPatches(patch, Patches, PatchCount);
    RtlCopyMemory(patchAlt, patch, PAGE_SIZE);

    OutPage->PatchVa = patch;
    OutPage->PatchPfn = MmGetPhysicalAddress(patch).QuadPart >> 12;
    OutPage->PatchVaAlt = patchAlt;
    OutPage->PatchPfnAlt = MmGetPhysicalAddress(patchAlt).QuadPart >> 12;
    InterlockedExchange(&OutPage->ActivePatchIndex, 0);
    return STATUS_SUCCESS;
}

/*
 * 在所有 vcpu 的 EptPebSpoof 上 install 一个 page cloak:
 *   PT slot 指向 OriginalPfn, R=0/W=0/X=0 强制 violation
 */
static NTSTATUS
HvPebCloakpPreparePageSlotsOnAllVcpus(
    _Inout_ PHV_PEB_CLOAK_PAGE Page)
{
    if (HvVwatchOverlayPageOwned(Page->GpaPage)) {
        return STATUS_CONFLICTING_ADDRESSES;
    }

    ULONG cpuCount = g_HypervisorContext.ProcessorCount;
    if (!g_HypervisorContext.VcpuData || cpuCount == 0 ||
        cpuCount > HV_PEB_CLOAK_MAX_CPUS) {
        return STATUS_NOT_SUPPORTED;
    }

    ULONG ok = 0;
    for (ULONG c = 0; c < cpuCount; c++) {
        PVCPU_DATA vcpu = &g_HypervisorContext.VcpuData[c];
        if (!vcpu->IsVirtualized || !vcpu->EptPebSpoof) {
            break;
        }

        PEPT_PTE_ENTRY slot = HvPebCloakpFindOrSplitPtSlot(vcpu->EptPebSpoof, Page->GpaPage);
        if (!slot) continue;

        EPT_PTE_ENTRY identity; identity.Value = 0;
        identity.Read = 1;
        identity.Write = 1;
        identity.Execute = 1;
        identity.MemoryType = HvEptGetMemoryType(Page->GpaPage, PAGE_SIZE);
        identity.PhysicalAddress = Page->OriginalPfn;
        HvPebCloakpWritePte(slot, identity);

        Page->CloakedPte[c] = slot;
        ok++;
    }
    if (ok == cpuCount) return STATUS_SUCCESS;

    for (ULONG c = 0; c < cpuCount; c++) {
        PEPT_PTE_ENTRY slot = Page->CloakedPte[c];
        if (slot) {
            EPT_PTE_ENTRY restored;
            restored.Value = 0;
            restored.Read = 1;
            restored.Write = 1;
            restored.Execute = 1;
            restored.MemoryType = HvEptGetMemoryType(
                Page->GpaPage, PAGE_SIZE);
            restored.PhysicalAddress = Page->OriginalPfn;
            HvPebCloakpWritePte(slot, restored);
            Page->CloakedPte[c] = NULL;
        }
    }
    EptInveptAllContexts();
    return STATUS_DEVICE_NOT_READY;
}

static VOID
HvPebCloakpArmPreparedPageOnAllVcpus(
    _Inout_ PHV_PEB_CLOAK_PAGE Page)
{
    ULONG cpuCount = g_HypervisorContext.ProcessorCount;

    InterlockedExchange(&Page->Retiring, FALSE);
    MemoryBarrier();
    InterlockedExchange(&Page->Installed, 1);
    for (ULONG c = 0; c < cpuCount; ++c) {
        PEPT_PTE_ENTRY slot = Page->CloakedPte[c];
        EPT_PTE_ENTRY cloaked;

        if (!slot) continue;
        cloaked.Value = 0;
        cloaked.MemoryType = HvEptGetMemoryType(
            Page->GpaPage, PAGE_SIZE);
        cloaked.PhysicalAddress = Page->OriginalPfn;
        HvPebCloakpWritePte(slot, cloaked);
    }
    EptInveptAllContexts();
}

static NTSTATUS
HvPebCloakpInstallPageOnAllVcpus(_Inout_ PHV_PEB_CLOAK_PAGE Page)
{
    NTSTATUS status = HvPebCloakpPreparePageSlotsOnAllVcpus(Page);
    if (!NT_SUCCESS(status)) return status;
    HvPebCloakpArmPreparedPageOnAllVcpus(Page);
    return STATUS_SUCCESS;
}

/*
 * 撤销一个 page cloak.
 */
static VOID
HvPebCloakpRestorePageMappings(_Inout_ PHV_PEB_CLOAK_PAGE Page)
{
    ULONG cpuCount = g_HypervisorContext.ProcessorCount;
    if (cpuCount > HV_PEB_CLOAK_MAX_CPUS) {
        cpuCount = HV_PEB_CLOAK_MAX_CPUS;
    }

    if (InterlockedExchange(&Page->Installed, 0) != 0) {
        for (ULONG c = 0; c < cpuCount; c++) {
            PEPT_PTE_ENTRY slot = Page->CloakedPte[c];
            if (!slot) continue;
            EPT_PTE_ENTRY restored; restored.Value = 0;
            restored.Read = 1;
            restored.Write = 1;
            restored.Execute = 1;
            restored.MemoryType = HvEptGetMemoryType(Page->GpaPage, PAGE_SIZE);
            restored.PhysicalAddress = Page->OriginalPfn;
            HvPebCloakpWritePte(slot, restored);
        }
        EptInveptAllContexts();
    }
}

static VOID
HvPebCloakpFreePageAfterQuiesce(_Inout_ PHV_PEB_CLOAK_PAGE Page)
{
    InterlockedExchange(&Page->Installed, 0);
    for (ULONG c = 0; c < HV_PEB_CLOAK_MAX_CPUS; c++) {
        Page->CloakedPte[c] = NULL;
    }
    if (Page->PatchVa) {
        MmFreeContiguousMemory(Page->PatchVa);
        Page->PatchVa = NULL;
    }
    if (Page->PatchVaAlt) {
        MmFreeContiguousMemory(Page->PatchVaAlt);
        Page->PatchVaAlt = NULL;
    }
}

static VOID
HvPebCloakpUninstallPageOnAllVcpus(_Inout_ PHV_PEB_CLOAK_PAGE Page)
{
    HvPebCloakpClosePageRootGate(Page);
    HvPebCloakpRestorePageMappings(Page);
    HvPebCloakpDrainPageRootReaders(Page);
    HvPebCloakpFreePageAfterQuiesce(Page);
}

/*
 * 撤销一个 target 的所有 cloak page.
 */
static VOID
HvPebCloakpUninstallTarget(_Inout_ PHV_PEB_CLOAK_TARGET Target)
{
    for (ULONG i = 0; i < Target->PageCount; i++) {
        HvPebCloakpUninstallPageOnAllVcpus(&Target->Pages[i]);
    }
    Target->PageCount = 0;
    if (Target->Process) {
        ObDereferenceObject(Target->Process);
        Target->Process = NULL;
    }
}

static VOID
HvPebCloakpRestoreTargetMappings(_Inout_ PHV_PEB_CLOAK_TARGET Target)
{
    for (ULONG i = 0; i < Target->PageCount; i++) {
        InterlockedExchange(&Target->Pages[i].Retiring, TRUE);
        HvPebCloakpClosePageRootGate(&Target->Pages[i]);
        MemoryBarrier();
        HvPebCloakpRestorePageMappings(&Target->Pages[i]);
    }
}

static VOID
HvPebCloakpFreeTargetAfterQuiesce(_Inout_ PHV_PEB_CLOAK_TARGET Target)
{
    for (ULONG i = 0; i < Target->PageCount; i++) {
        HvPebCloakpDrainPageRootReaders(&Target->Pages[i]);
        HvPebCloakpFreePageAfterQuiesce(&Target->Pages[i]);
    }
    Target->PageCount = 0;
    if (Target->Process) {
        ObDereferenceObject(Target->Process);
        Target->Process = NULL;
    }
}

/*
 * 解 PEB VA + ProcessHeap VA；ProcessHeap 指针通过 VT-root PID copy 读取。
 */
static NTSTATUS
HvPebCloakpResolvePebAndHeapVa(
    _In_ HANDLE Pid,
    _In_ PEPROCESS Process,
    _Out_ PULONG64 OutPebVa,
    _Out_ PULONG64 OutHeapVa)
{
    *OutPebVa = 0; *OutHeapVa = 0;

    if (!Process) return STATUS_INVALID_PARAMETER;
    PVOID pebVa = PsGetProcessPeb(Process);
    if (!pebVa) {
        return STATUS_NOT_FOUND;
    }
    *OutPebVa = (ULONG64)pebVa;

    PVOID heapVa = NULL;
    SIZE_T bytesDone = 0;
    NTSTATUS s = HvVtRootCopyByPid(
        (ULONG)(ULONG_PTR)Pid,
        (UINT64)(ULONG_PTR)pebVa + HV_PEB_OFF_PROCESS_HEAP,
        &heapVa,
        sizeof(heapVa),
        FALSE,
        &bytesDone);
    if (NT_SUCCESS(s) && bytesDone != sizeof(heapVa)) {
        s = STATUS_PARTIAL_COPY;
    }

    if (!NT_SUCCESS(s)) return s;
    *OutHeapVa = (ULONG64)heapVa;   // 可能 0 (进程极早期 ldr 没建 heap), 调用方自查
    return STATUS_SUCCESS;
}

// ============================================================
// 生命周期
// ============================================================

static NTSTATUS
HvPebCloakpValidateTargetIdentity(
    _In_ PHV_PEB_CLOAK_TARGET Target)
{
    PEPROCESS process = NULL;
    NTSTATUS status;

    if (!Target || !Target->Pid || !Target->Process ||
        Target->CreateTime == 0) {
        return STATUS_INVALID_CID;
    }

    status = PsLookupProcessByProcessId(Target->Pid, &process);
    if (!NT_SUCCESS(status) || !process) {
        return NT_SUCCESS(status) ? STATUS_INVALID_CID : status;
    }
    if (process != Target->Process ||
        (UINT64)PsGetProcessCreateTimeQuadPart(process) !=
            Target->CreateTime) {
        status = STATUS_INVALID_CID;
    }
    ObDereferenceObject(process);
    return status;
}

static BOOLEAN
HvPebCloakpGpaOwnedByOtherTargetLocked(
    _In_ PHV_PEB_CLOAK_TARGET Owner,
    _In_ ULONG64 GpaPage)
{
    for (LONG targetIndex = 0;
         targetIndex < HV_PEB_CLOAK_MAX_TARGETS;
         ++targetIndex) {
        PHV_PEB_CLOAK_TARGET target =
            &g_PebCloakManager.Targets[targetIndex];
        LONG state;

        if (target == Owner) continue;
        state = InterlockedCompareExchange(&target->Active, 0, 0);
        if (state == HV_PEB_TARGET_FREE ||
            state == HV_PEB_TARGET_QUIESCED) {
            continue;
        }
        for (ULONG pageIndex = 0;
             pageIndex < target->PageCount;
             ++pageIndex) {
            PHV_PEB_CLOAK_PAGE page = &target->Pages[pageIndex];
            if (page->GpaPage == GpaPage &&
                InterlockedCompareExchange(
                    &page->Installed, 0, 0) != 0) {
                return TRUE;
            }
        }
    }
    return FALSE;
}

static NTSTATUS
HvPebCloakpRebindTargetLocked(
    _Inout_ PHV_PEB_CLOAK_TARGET Target)
{
    UINT64 newGpa[HV_PEB_CLOAK_MAX_PAGES_PER_TARGET] = { 0 };
    UINT64 newCr3 = 0;
    NTSTATUS status = STATUS_SUCCESS;
    BOOLEAN drained = TRUE;

    if (!Target || Target->PageCount == 0 ||
        Target->PageCount > HV_PEB_CLOAK_MAX_PAGES_PER_TARGET) {
        return STATUS_INVALID_PARAMETER;
    }
    status = HvPebCloakpValidateTargetIdentity(Target);
    if (!NT_SUCCESS(status)) return status;
    if (InterlockedCompareExchange(
            &Target->Active,
            HV_PEB_TARGET_BUILDING,
            HV_PEB_TARGET_ACTIVE) != HV_PEB_TARGET_ACTIVE) {
        return STATUS_DEVICE_BUSY;
    }
    InterlockedIncrement(&g_PebCloakManager.Generation);

    // Close page-local rundown before restoring old GPAs to identity.  MTF
    // users retain this gate across the guest instruction and completion.
    HvPebCloakpRestoreTargetMappings(Target);
    for (ULONG pageIndex = 0;
         pageIndex < Target->PageCount;
         ++pageIndex) {
        if (!HvPebCloakpWaitForPageRootReaders(
                &Target->Pages[pageIndex])) {
            drained = FALSE;
        }
    }
    if (!drained) {
        status = STATUS_TIMEOUT;
        goto FailOpen;
    }

    status = HvPebCloakpValidateTargetIdentity(Target);
    if (!NT_SUCCESS(status)) goto FailOpen;
    status = HvVtRootResolveUserCr3(
        (ULONG)(ULONG_PTR)Target->Pid, &newCr3);
    if (!NT_SUCCESS(status) || newCr3 == 0) {
        if (NT_SUCCESS(status)) status = STATUS_NOT_FOUND;
        goto FailOpen;
    }

    for (ULONG pageIndex = 0;
         pageIndex < Target->PageCount;
         ++pageIndex) {
        PHV_PEB_CLOAK_PAGE page = &Target->Pages[pageIndex];
        SIZE_T bytesDone = 0;

        status = HvVtRootWalkGvaToHpa(
            (ULONG)(ULONG_PTR)Target->Pid,
            page->GuestVa,
            &newGpa[pageIndex],
            NULL);
        if (!NT_SUCCESS(status) || newGpa[pageIndex] == 0) {
            if (NT_SUCCESS(status)) status = STATUS_NOT_FOUND;
            goto FailOpen;
        }
        newGpa[pageIndex] &= ~((UINT64)PAGE_SIZE - 1);
        if (HvVwatchOverlayPageOwned(newGpa[pageIndex]) ||
            HvPebCloakpGpaOwnedByOtherTargetLocked(
                Target, newGpa[pageIndex])) {
            status = STATUS_CONFLICTING_ADDRESSES;
            goto FailOpen;
        }
        for (ULONG previous = 0; previous < pageIndex; ++previous) {
            if (newGpa[previous] == newGpa[pageIndex]) {
                status = STATUS_CONFLICTING_ADDRESSES;
                goto FailOpen;
            }
        }

        status = HvVtRootCopyByPid(
            (ULONG)(ULONG_PTR)Target->Pid,
            page->GuestVa,
            page->PatchVa,
            PAGE_SIZE,
            FALSE,
            &bytesDone);
        if (!NT_SUCCESS(status) || bytesDone != PAGE_SIZE) {
            if (NT_SUCCESS(status)) status = STATUS_PARTIAL_COPY;
            goto FailOpen;
        }
        HvPebCloakpApplyPatches(
            page->PatchVa, page->PatchRules, page->PatchCount);
        RtlCopyMemory(page->PatchVaAlt, page->PatchVa, PAGE_SIZE);
        InterlockedExchange(&page->ActivePatchIndex, 0);
        InterlockedExchange(&page->RefreshBusy, 0);
    }

    status = HvPebCloakpValidateTargetIdentity(Target);
    if (!NT_SUCCESS(status)) goto FailOpen;

    Target->UserCr3 = newCr3;
    for (ULONG pageIndex = 0;
         pageIndex < Target->PageCount;
         ++pageIndex) {
        PHV_PEB_CLOAK_PAGE page = &Target->Pages[pageIndex];

        page->UserCr3 = newCr3;
        page->GpaPage = newGpa[pageIndex];
        page->OriginalPfn = newGpa[pageIndex] >> PAGE_SHIFT;
        for (ULONG cpu = 0; cpu < HV_PEB_CLOAK_MAX_CPUS; ++cpu) {
            page->CloakedPte[cpu] = NULL;
        }
        status = HvPebCloakpPreparePageSlotsOnAllVcpus(page);
        if (!NT_SUCCESS(status)) goto FailOpen;
    }

    // Publish metadata before restrictive PTEs.  The transition window is
    // intentionally identity/fail-open, never an unowned EPT denial.
    for (ULONG pageIndex = 0;
         pageIndex < Target->PageCount;
         ++pageIndex) {
        PHV_PEB_CLOAK_PAGE page = &Target->Pages[pageIndex];
        InterlockedExchange(&page->Stale, FALSE);
        InterlockedExchange(&page->Retiring, FALSE);
        HvPebCloakpOpenPageRootGate(page);
    }
    MemoryBarrier();
    InterlockedExchange(&Target->Active, HV_PEB_TARGET_ACTIVE);
    InterlockedIncrement(&g_PebCloakManager.Generation);
    for (ULONG pageIndex = 0;
         pageIndex < Target->PageCount;
         ++pageIndex) {
        HvPebCloakpArmPreparedPageOnAllVcpus(
            &Target->Pages[pageIndex]);
    }
    InterlockedExchange(&Target->RebindFailures, 0);
    InterlockedExchange64(&Target->RebindDueTime, 0);
    return STATUS_SUCCESS;

FailOpen:
    // Preserve the target and its buffers for retry, but publish no stale or
    // partially prepared restrictive mapping.
    for (ULONG pageIndex = 0;
         pageIndex < Target->PageCount;
         ++pageIndex) {
        PHV_PEB_CLOAK_PAGE page = &Target->Pages[pageIndex];
        InterlockedExchange(&page->Installed, 0);
        InterlockedExchange(&page->Stale, TRUE);
        InterlockedExchange(&page->Retiring, TRUE);
        if ((InterlockedCompareExchange(&page->RootGate, 0, 0) &
             HV_PEB_PAGE_ROOT_COUNT_MASK) == 0) {
            HvPebCloakpOpenPageRootGate(page);
        }
    }
    MemoryBarrier();
    InterlockedExchange(&Target->Active, HV_PEB_TARGET_ACTIVE);
    InterlockedIncrement(&g_PebCloakManager.Generation);
    return status;
}

NTSTATUS HvPebCloakRefreshTargetCr3(
    _In_ HANDLE Pid,
    _In_ UINT64 ExpectedCr3)
{
    NTSTATUS status = STATUS_NOT_FOUND;

    ExpectedCr3 &= 0x000FFFFFFFFFF000ULL;
    if (!Pid || !ExpectedCr3) return STATUS_INVALID_PARAMETER;
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) return STATUS_INVALID_LEVEL;
    if (InterlockedCompareExchange(
            &g_PebCloakManager.Initialized, 0, 0) == 0 ||
        InterlockedCompareExchange(
            &g_PebCloakManager.GloballyEnabled, 0, 0) == 0) {
        return STATUS_NOT_SUPPORTED;
    }

    HvOverlayEptAcquireMutation();
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_PebCloakManager.ControlLock);
    if (InterlockedCompareExchange(
            &g_PebCloakManager.ShuttingDown, 0, 0) != 0) {
        status = STATUS_DELETE_PENDING;
    } else {
        for (LONG index = 0; index < HV_PEB_CLOAK_MAX_TARGETS; index++) {
            PHV_PEB_CLOAK_TARGET target =
                &g_PebCloakManager.Targets[index];
            if (InterlockedCompareExchange(
                    &target->Active, 0, 0) != HV_PEB_TARGET_ACTIVE ||
                target->Pid != Pid) {
                continue;
            }
            if ((target->UserCr3 & 0x000FFFFFFFFFF000ULL) ==
                ExpectedCr3) {
                status = STATUS_SUCCESS;
            } else {
                status = HvPebCloakpRebindTargetLocked(target);
            }
            break;
        }
    }
    ExReleasePushLockExclusive(&g_PebCloakManager.ControlLock);
    KeLeaveCriticalRegion();
    HvOverlayEptReleaseMutation();
    return status;
}

static BOOLEAN
HvPebCloakpTargetHasStalePage(
    _In_ PHV_PEB_CLOAK_TARGET Target)
{
    for (ULONG pageIndex = 0;
         pageIndex < Target->PageCount;
         ++pageIndex) {
        if (InterlockedCompareExchange(
                &Target->Pages[pageIndex].Stale, 0, 0) != 0) {
            return TRUE;
        }
    }
    return FALSE;
}

static VOID
HvPebCloakpRebindWorker(_In_ PVOID Context)
{
    LARGE_INTEGER timeout;

    UNREFERENCED_PARAMETER(Context);
    timeout.QuadPart = -(LONGLONG)HV_PEB_REBIND_POLL_100NS;
    for (;;) {
        NTSTATUS waitStatus = KeWaitForSingleObject(
            &g_PebCloakManager.RebindStopEvent,
            Executive,
            KernelMode,
            FALSE,
            &timeout);
        if (waitStatus == STATUS_SUCCESS ||
            InterlockedCompareExchange(
                &g_PebCloakManager.ShuttingDown, 0, 0) != 0) {
            break;
        }
        if (waitStatus != STATUS_TIMEOUT ||
            InterlockedCompareExchange(
                &g_PebCloakManager.Initialized, 0, 0) == 0) {
            continue;
        }

        HvOverlayEptAcquireMutation();
        KeEnterCriticalRegion();
        ExAcquirePushLockExclusive(&g_PebCloakManager.ControlLock);
        if (InterlockedCompareExchange(
                &g_PebCloakManager.ShuttingDown, 0, 0) == 0) {
            UINT64 now = KeQueryInterruptTime();
            for (LONG targetIndex = 0;
                 targetIndex < HV_PEB_CLOAK_MAX_TARGETS;
                 ++targetIndex) {
                PHV_PEB_CLOAK_TARGET target =
                    &g_PebCloakManager.Targets[targetIndex];
                LONG64 due;

                if (InterlockedCompareExchange(
                        &target->Active, 0, 0) !=
                        HV_PEB_TARGET_ACTIVE ||
                    !HvPebCloakpTargetHasStalePage(target)) {
                    continue;
                }
                due = InterlockedCompareExchange64(
                    &target->RebindDueTime, 0, 0);
                if (due > 0 && now < (UINT64)due) continue;

                NTSTATUS status = HvPebCloakpRebindTargetLocked(target);
                if (!NT_SUCCESS(status)) {
                    LONG failures = InterlockedIncrement(
                        &target->RebindFailures);
                    ULONG shift = (ULONG)(failures >
                        HV_PEB_REBIND_MAX_SHIFT
                            ? HV_PEB_REBIND_MAX_SHIFT
                            : failures);
                    UINT64 delay = HV_PEB_REBIND_POLL_100NS << shift;
                    InterlockedExchange64(
                        &target->RebindDueTime,
                        (LONG64)(KeQueryInterruptTime() + delay));
                }
                break;
            }
        }
        ExReleasePushLockExclusive(&g_PebCloakManager.ControlLock);
        KeLeaveCriticalRegion();
        HvOverlayEptReleaseMutation();
    }
    PsTerminateSystemThread(STATUS_SUCCESS);
}

NTSTATUS HvPebCloakInitialize(VOID)
{
#if !HV_ENABLE_PEB_CLOAK
    DbgPrint("[PebCloak] Init: HV_ENABLE_PEB_CLOAK=0, manager skipped\n");
    return STATUS_SUCCESS;
#else
    if (InterlockedCompareExchange(
            &g_PebCloakManager.Initialized, 0, 0) != 0) {
        return STATUS_SUCCESS;
    }
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    RtlZeroMemory(&g_PebCloakManager, sizeof(g_PebCloakManager));
    ExInitializePushLock(&g_PebCloakManager.ControlLock);
    KeInitializeEvent(
        &g_PebCloakManager.RebindStopEvent,
        NotificationEvent,
        FALSE);
    InterlockedExchange(&g_PebCloakManager.Generation, 1);
    InterlockedExchange(&g_PebCloakManager.ShuttingDown, FALSE);
    InterlockedExchange(&g_PebCloakManager.GloballyEnabled, FALSE);
    NTSTATUS status = PsCreateSystemThread(
        &g_PebCloakManager.RebindThreadHandle,
        THREAD_ALL_ACCESS,
        NULL,
        NULL,
        NULL,
        HvPebCloakpRebindWorker,
        NULL);
    if (!NT_SUCCESS(status)) {
        g_PebCloakManager.RebindThreadHandle = NULL;
        InterlockedExchange(&g_PebCloakManager.ShuttingDown, TRUE);
        return status;
    }
    MemoryBarrier();
    InterlockedExchange(&g_PebCloakManager.Initialized, TRUE);

    DbgPrint("[PebCloak] Init OK\n");
    return STATUS_SUCCESS;
#endif
}

VOID HvPebCloakBeginShutdown(VOID)
{
    if (InterlockedCompareExchange(
            &g_PebCloakManager.Initialized, 0, 0) == 0) {
        return;
    }

    if (InterlockedCompareExchange(
            &g_PebCloakManager.ShuttingDown, TRUE, FALSE) == FALSE) {
        InterlockedExchange(&g_PebCloakManager.GloballyEnabled, FALSE);
        InterlockedIncrement(&g_PebCloakManager.Generation);
        MemoryBarrier();
    }
    KeSetEvent(&g_PebCloakManager.RebindStopEvent, IO_NO_INCREMENT, FALSE);
}

VOID HvPebCloakShutdown(VOID)
{
    if (InterlockedCompareExchange(
            &g_PebCloakManager.Initialized, 0, 0) == 0) {
        return;
    }
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return;
    }

    // Stop the PASSIVE poller before taking either control-plane lock; it may
    // itself be inside a rebind transaction under those locks.
    HvPebCloakBeginShutdown();
    if (g_PebCloakManager.RebindThreadHandle) {
        (VOID)ZwWaitForSingleObject(
            g_PebCloakManager.RebindThreadHandle, FALSE, NULL);
        ZwClose(g_PebCloakManager.RebindThreadHandle);
        g_PebCloakManager.RebindThreadHandle = NULL;
    }

    HvOverlayEptAcquireMutation();
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_PebCloakManager.ControlLock);
    InterlockedExchange(&g_PebCloakManager.GloballyEnabled, FALSE);
    InterlockedIncrement(&g_PebCloakManager.Generation);

    for (LONG i = 0; i < HV_PEB_CLOAK_MAX_TARGETS; i++) {
        PHV_PEB_CLOAK_TARGET t = &g_PebCloakManager.Targets[i];
        if (InterlockedCompareExchange(
                &t->Active,
                HV_PEB_TARGET_RETIRING,
                HV_PEB_TARGET_ACTIVE) == HV_PEB_TARGET_ACTIVE) {
            continue;
        }
    }

    for (LONG i = 0; i < HV_PEB_CLOAK_MAX_TARGETS; i++) {
        PHV_PEB_CLOAK_TARGET t = &g_PebCloakManager.Targets[i];
        LONG oldState = InterlockedCompareExchange(&t->Active, 0, 0);
        if (oldState != HV_PEB_TARGET_FREE) {
            HvPebCloakpRestoreTargetMappings(t);
            MemoryBarrier();
            InterlockedExchange(&t->Active, HV_PEB_TARGET_QUIESCED);
        }
    }

    MemoryBarrier();
    HvPebCloakpWaitForRootReaders();

    for (LONG i = 0; i < HV_PEB_CLOAK_MAX_TARGETS; i++) {
        PHV_PEB_CLOAK_TARGET t = &g_PebCloakManager.Targets[i];
        HvPebCloakpFreeTargetAfterQuiesce(t);
        RtlZeroMemory(t, sizeof(*t));
    }
    InterlockedExchange(&g_PebCloakManager.TargetCount, 0);
    MemoryBarrier();
    InterlockedExchange(&g_PebCloakManager.Initialized, FALSE);
    ExReleasePushLockExclusive(&g_PebCloakManager.ControlLock);
    KeLeaveCriticalRegion();
    HvOverlayEptReleaseMutation();
    DbgPrint("[PebCloak] Shutdown\n");
}

NTSTATUS HvPebCloakSetupVcpu(_Inout_ PVCPU_DATA Vcpu)
{
    if (!Vcpu || !Vcpu->EptTables) return STATUS_INVALID_PARAMETER;
    if (Vcpu->EptPebSpoof) return STATUS_SUCCESS;   // 已建好

    PHYSICAL_ADDRESS maxAddr; maxAddr.QuadPart = -1LL;
    PEPT_TABLES ept = (PEPT_TABLES)MmAllocateContiguousMemory(sizeof(EPT_TABLES), maxAddr);
    if (!ept) return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(ept, sizeof(EPT_TABLES));
    ept->Pml4Physical = MmGetPhysicalAddress(ept);

    NTSTATUS s = HvEptBuildIdentityInto(ept);
    if (!NT_SUCCESS(s)) {
        HvEptFreeTables(ept);
        return s;
    }
    Vcpu->EptPebSpoof = ept;

    // 计算两份 EPTP. 等同 HvVmcs.c 里设主 EPT 那段:
    //   bits[2:0]   MemoryType = WB (6)
    //   bits[5:3]   PageWalkLength = 3 (即 4 级页表)
    //   bits[11:6]  保留
    //   bits[51:12] PML4 PFN
    EPTP eptpM; eptpM.Value = 0;
    eptpM.MemoryType = 6;
    eptpM.PageWalkLength = 3;
    eptpM.PageFrameNumber = Vcpu->EptTables->Pml4Physical.QuadPart >> 12;

    EPTP eptpP; eptpP.Value = 0;
    eptpP.MemoryType = 6;
    eptpP.PageWalkLength = 3;
    eptpP.PageFrameNumber = ept->Pml4Physical.QuadPart >> 12;

    Vcpu->EptpMain = eptpM.Value;
    Vcpu->EptpPebSpoof = eptpP.Value;
    Vcpu->ActiveEptpIsPebSpoof = 0;
    Vcpu->LastSnoopedCr3 = 0;
    Vcpu->LastCallerClass = HV_PEB_CLASS_UNKNOWN;

    DbgPrint("[PebCloak] SetupVcpu OK: EptpMain=0x%llX EptpPebSpoof=0x%llX\n",
             Vcpu->EptpMain, Vcpu->EptpPebSpoof);
    return STATUS_SUCCESS;
}

// ============================================================
// Target 注册
// ============================================================

NTSTATUS HvPebCloakRegisterTarget(_In_ HANDLE Pid)
{
#if !HV_ENABLE_PEB_CLOAK
    UNREFERENCED_PARAMETER(Pid);
    return STATUS_SUCCESS;
#else
    PHV_PEB_CLOAK_TARGET t = NULL;
    PEPROCESS process = NULL;
    UINT64 createTime = 0;
    NTSTATUS s;
    LONG idx = -1;
    BOOLEAN privateDbgkTarget = FALSE;

    if (InterlockedCompareExchange(
            &g_PebCloakManager.Initialized, 0, 0) == 0) {
        return STATUS_DEVICE_NOT_READY;
    }
    if (InterlockedCompareExchange(
            &g_PebCloakManager.ShuttingDown, 0, 0) != 0) {
        return STATUS_DELETE_PENDING;
    }
    if (!Pid) return STATUS_INVALID_PARAMETER;
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (HvGetCpuVendor() != CPU_VENDOR_INTEL) {
        return STATUS_NOT_SUPPORTED;
    }
    privateDbgkTarget = HvPrivateDebugObjectIsTarget(Pid);

    s = PsLookupProcessByProcessId(Pid, &process);
    if (!NT_SUCCESS(s) || !process) {
        return NT_SUCCESS(s) ? STATUS_INVALID_CID : s;
    }
    createTime = (UINT64)PsGetProcessCreateTimeQuadPart(process);
    if (createTime == 0) {
        ObDereferenceObject(process);
        return STATUS_INVALID_CID;
    }
    if (InterlockedCompareExchange(
            &g_PebCloakManager.ShuttingDown, 0, 0) != 0) {
        ObDereferenceObject(process);
        return STATUS_DELETE_PENDING;
    }

    // 解 user CR3
    UINT64 userCr3 = 0;
    s = HvPebCloakpResolveUserCr3(Pid, &userCr3);
    if (!NT_SUCCESS(s) || !userCr3) {
        DbgPrint("[PebCloak] Register PID=%u: resolve user CR3 failed 0x%X\n",
                 (ULONG)(ULONG_PTR)Pid, s);
        ObDereferenceObject(process);
        return s;
    }
    if (InterlockedCompareExchange(
            &g_PebCloakManager.ShuttingDown, 0, 0) != 0) {
        ObDereferenceObject(process);
        return STATUS_DELETE_PENDING;
    }

    // 解 PEB VA + ProcessHeap VA；不 attach 目标进程，字段读取留在 VT-root。
    ULONG64 pebVa = 0, heapVa = 0;
    s = HvPebCloakpResolvePebAndHeapVa(
        Pid, process, &pebVa, &heapVa);
    if (!NT_SUCCESS(s) || !pebVa) {
        DbgPrint("[PebCloak] Register PID=%u: resolve PEB/Heap VA failed 0x%X\n",
                 (ULONG)(ULONG_PTR)Pid, s);
        ObDereferenceObject(process);
        return s;
    }
    if (InterlockedCompareExchange(
            &g_PebCloakManager.ShuttingDown, 0, 0) != 0) {
        ObDereferenceObject(process);
        return STATUS_DELETE_PENDING;
    }

    HvOverlayEptAcquireMutation();
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_PebCloakManager.ControlLock);
    if (InterlockedCompareExchange(
            &g_PebCloakManager.ShuttingDown, 0, 0) != 0) {
        s = STATUS_DELETE_PENDING;
        goto ExitControl;
    }

    // 已注册?
    for (LONG i = 0; i < HV_PEB_CLOAK_MAX_TARGETS; i++) {
        LONG state = InterlockedCompareExchange(
            &g_PebCloakManager.Targets[i].Active, 0, 0);
        if (g_PebCloakManager.Targets[i].Pid == Pid &&
            (state == HV_PEB_TARGET_ACTIVE ||
             state == HV_PEB_TARGET_BUILDING)) {
            LONG oldPrivate = InterlockedExchange(
                &g_PebCloakManager.Targets[i].PrivateDbgkTarget,
                privateDbgkTarget ? TRUE : FALSE);
            if (oldPrivate != (privateDbgkTarget ? TRUE : FALSE)) {
                InterlockedIncrement(&g_PebCloakManager.Generation);
            }
            s = STATUS_SUCCESS;
            goto ExitControl;
        }
    }

    // 找空槽
    for (LONG i = 0; i < HV_PEB_CLOAK_MAX_TARGETS; i++) {
        if (InterlockedCompareExchange(
                &g_PebCloakManager.Targets[i].Active, 0, 0) ==
            HV_PEB_TARGET_FREE) {
            idx = i;
            break;
        }
    }
    if (idx < 0) {
        s = STATUS_INSUFFICIENT_RESOURCES;
        goto ExitControl;
    }

    t = &g_PebCloakManager.Targets[idx];
    RtlZeroMemory(t, sizeof(*t));
    t->Pid = Pid;
    t->Process = process;
    process = NULL;
    t->CreateTime = createTime;
    t->UserCr3 = userCr3;
    InterlockedExchange(
        &t->PrivateDbgkTarget,
        privateDbgkTarget ? TRUE : FALSE);
    InterlockedExchange(&t->Active, HV_PEB_TARGET_BUILDING);

    // ---- Page 1: PEB (BeingDebugged + NtGlobalFlag) ----
    {
        ULONG_PTR pebOffInPage = (ULONG_PTR)pebVa & 0xFFF;
        HV_PEB_FIELD_PATCH pebPatches[2] = {
            { (ULONG)(pebOffInPage + HV_PEB_OFF_BEING_DEBUGGED), HV_PEB_PATCH_SET_BYTE,  0 },
            { (ULONG)(pebOffInPage + HV_PEB_OFF_NT_GLOBAL_FLAG), HV_PEB_PATCH_AND_DWORD, ~(ULONG)HV_PEB_NT_GLOBAL_FLAG_MASK },
        };
        s = HvPebCloakpPrepareCloakPage(Pid, userCr3, pebVa, pebPatches, 2, &t->Pages[t->PageCount]);
        if (!NT_SUCCESS(s)) {
            DbgPrint("[PebCloak] Register PID=%u: PEB page prepare failed 0x%X\n",
                     (ULONG)(ULONG_PTR)Pid, s);
            goto RollbackTarget;
        }
        s = HvPebCloakpInstallPageOnAllVcpus(&t->Pages[t->PageCount]);
        if (!NT_SUCCESS(s)) {
            DbgPrint("[PebCloak] Register PID=%u: PEB page install failed 0x%X\n",
                     (ULONG)(ULONG_PTR)Pid, s);
            HvPebCloakpUninstallPageOnAllVcpus(&t->Pages[t->PageCount]);
            goto RollbackTarget;
        }
        t->PageCount++;
    }
    if (InterlockedCompareExchange(
            &g_PebCloakManager.ShuttingDown, 0, 0) != 0) {
        s = STATUS_DELETE_PENDING;
        goto RollbackTarget;
    }

    // ---- Page 2: ProcessHeap header (Flags + ForceFlags) ----
    // heapVa==0 → 进程还没建 default heap, 跳过 (loader 跑完会有)
    if (heapVa) {
        ULONG_PTR heapOffInPage = (ULONG_PTR)heapVa & 0xFFF;
        // 确认 Flags/ForceFlags 都在 ProcessHeap 所在 4KB 页内 (offset 0x70+8 = 0x78,
        // 远小于 PAGE_SIZE - heap header 大小 0x78, 几乎 100% 落同页 — 否则 skip)
        if (heapOffInPage + HV_HEAP_OFF_FORCE_FLAGS + 4 <= PAGE_SIZE) {
            HV_PEB_FIELD_PATCH heapPatches[2] = {
                { (ULONG)(heapOffInPage + HV_HEAP_OFF_FLAGS),       HV_PEB_PATCH_SET_DWORD, HV_HEAP_FLAGS_CLEAN },
                { (ULONG)(heapOffInPage + HV_HEAP_OFF_FORCE_FLAGS), HV_PEB_PATCH_SET_DWORD, HV_HEAP_FORCE_FLAGS_CLEAN },
            };
            NTSTATUS hs = HvPebCloakpPrepareCloakPage(Pid, userCr3, heapVa, heapPatches, 2, &t->Pages[t->PageCount]);
            if (NT_SUCCESS(hs)) {
                hs = HvPebCloakpInstallPageOnAllVcpus(&t->Pages[t->PageCount]);
                if (NT_SUCCESS(hs)) {
                    t->PageCount++;
                } else {
                    // install 失败 → 释放 patch 页, 跳过 (PEB 页已成功)
                    HvPebCloakpUninstallPageOnAllVcpus(&t->Pages[t->PageCount]);
                    DbgPrint("[PebCloak] Register PID=%u: heap page install failed 0x%X — skip\n",
                             (ULONG)(ULONG_PTR)Pid, hs);
                }
            } else {
                DbgPrint("[PebCloak] Register PID=%u: heap page prepare failed 0x%X — skip\n",
                         (ULONG)(ULONG_PTR)Pid, hs);
            }
        } else {
            DbgPrint("[PebCloak] Register PID=%u: heap header crosses page boundary, skip heap cloak\n",
                     (ULONG)(ULONG_PTR)Pid);
        }
    }

    // 至少 PEB 页要成功才算 Register 成功
    if (t->PageCount == 0) {
        DbgPrint("[PebCloak] Register PID=%u: no cloak page installed, abort\n",
                 (ULONG)(ULONG_PTR)Pid);
        s = STATUS_UNSUCCESSFUL;
        goto RollbackTarget;
    }
    if (InterlockedCompareExchange(
            &g_PebCloakManager.ShuttingDown, 0, 0) != 0) {
        s = STATUS_DELETE_PENDING;
        goto RollbackTarget;
    }

    // 完整字段与所有 EPT slot 先发布，最后才发布 ACTIVE.
    MemoryBarrier();
    InterlockedExchange(&t->Active, HV_PEB_TARGET_ACTIVE);
    InterlockedIncrement(&g_PebCloakManager.TargetCount);
    InterlockedExchange(&g_PebCloakManager.GloballyEnabled, TRUE);
    InterlockedIncrement(&g_PebCloakManager.Generation);

    DbgPrint("[PebCloak] Registered PID=%u userCr3=0x%llX PEB.GVA=0x%llX Heap.GVA=0x%llX pages=%u\n",
             (ULONG)(ULONG_PTR)Pid, userCr3, pebVa, heapVa, t->PageCount);
    for (ULONG i = 0; i < t->PageCount; i++) {
        DbgPrint("[PebCloak]   page[%u] GVA=0x%llX GPA=0x%llX PatchPfn=0x%llX\n",
                 i, t->Pages[i].GuestVa, t->Pages[i].GpaPage, t->Pages[i].PatchPfn);
    }

    s = STATUS_SUCCESS;
    goto ExitControl;

RollbackTarget:
    HvPebCloakpUninstallTarget(t);
    RtlZeroMemory(t, sizeof(*t));

ExitControl:
    ExReleasePushLockExclusive(&g_PebCloakManager.ControlLock);
    KeLeaveCriticalRegion();
    HvOverlayEptReleaseMutation();
    if (process) {
        ObDereferenceObject(process);
    }
    return s;
#endif
}

VOID HvPebCloakUnregisterTarget(_In_ HANDLE Pid)
{
#if !HV_ENABLE_PEB_CLOAK
    UNREFERENCED_PARAMETER(Pid);
    return;
#else
    if (InterlockedCompareExchange(
            &g_PebCloakManager.Initialized, 0, 0) == 0 ||
        !Pid || KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return;
    }

    HvOverlayEptAcquireMutation();
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_PebCloakManager.ControlLock);

    LONG hit = -1;
    for (LONG i = 0; i < HV_PEB_CLOAK_MAX_TARGETS; i++) {
        if (g_PebCloakManager.Targets[i].Pid == Pid &&
            InterlockedCompareExchange(
                &g_PebCloakManager.Targets[i].Active,
                HV_PEB_TARGET_RETIRING,
                HV_PEB_TARGET_ACTIVE) == HV_PEB_TARGET_ACTIVE)
        {
            hit = i;
            break;
        }
    }

    if (hit < 0) {
        ExReleasePushLockExclusive(&g_PebCloakManager.ControlLock);
        KeLeaveCriticalRegion();
        HvOverlayEptReleaseMutation();
        return;
    }

    PHV_PEB_CLOAK_TARGET t = &g_PebCloakManager.Targets[hit];

    if (InterlockedDecrement(&g_PebCloakManager.TargetCount) <= 0) {
        InterlockedExchange(&g_PebCloakManager.TargetCount, 0);
        InterlockedExchange(&g_PebCloakManager.GloballyEnabled, FALSE);
    }
    InterlockedIncrement(&g_PebCloakManager.Generation);

    /*
     * First make every CPU's overlay identity again while the target/page
     * storage remains alive.  Existing MTF completions write the same identity
     * value.  After QUIESCED no new target lookup is possible and no PTE can
     * generate a fresh cloak violation.
     */
    HvPebCloakpRestoreTargetMappings(t);
    MemoryBarrier();
    InterlockedExchange(&t->Active, HV_PEB_TARGET_QUIESCED);
    HvPebCloakpWaitForRootReaders();
    HvPebCloakpFreeTargetAfterQuiesce(t);
    RtlZeroMemory(t, sizeof(*t));
    ExReleasePushLockExclusive(&g_PebCloakManager.ControlLock);
    KeLeaveCriticalRegion();
    HvOverlayEptReleaseMutation();

    DbgPrint("[PebCloak] Unregistered PID=%u\n", (ULONG)(ULONG_PTR)Pid);
#endif
}

VOID HvPebCloakOnProcessExit(_In_ HANDLE Pid)
{
    HvPebCloakUnregisterTarget(Pid);
}

VOID HvPebCloakSetPrivateDbgkTarget(
    _In_ HANDLE Pid,
    _In_ BOOLEAN Enabled)
{
    if (!Pid || KeGetCurrentIrql() != PASSIVE_LEVEL ||
        InterlockedCompareExchange(
            &g_PebCloakManager.Initialized, 0, 0) == 0) {
        return;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_PebCloakManager.ControlLock);
    for (LONG index = 0; index < HV_PEB_CLOAK_MAX_TARGETS; index++) {
        PHV_PEB_CLOAK_TARGET target =
            &g_PebCloakManager.Targets[index];
        LONG state = InterlockedCompareExchange(&target->Active, 0, 0);
        if (target->Pid != Pid ||
            (state != HV_PEB_TARGET_ACTIVE &&
             state != HV_PEB_TARGET_BUILDING)) {
            continue;
        }

        LONG wanted = Enabled ? TRUE : FALSE;
        if (InterlockedExchange(
                &target->PrivateDbgkTarget, wanted) != wanted) {
            InterlockedIncrement(&g_PebCloakManager.Generation);
        }
        break;
    }
    ExReleasePushLockExclusive(&g_PebCloakManager.ControlLock);
    KeLeaveCriticalRegion();
}

BOOLEAN HvPebCloakOverlayPageOwned(_In_ ULONG64 GpaPage)
{
    GpaPage &= ~((ULONG64)PAGE_SIZE - 1);
    for (LONG i = 0; i < HV_PEB_CLOAK_MAX_TARGETS; i++) {
        PHV_PEB_CLOAK_TARGET target =
            &g_PebCloakManager.Targets[i];
        LONG state = InterlockedCompareExchange(
            &target->Active, 0, 0);
        if (state == HV_PEB_TARGET_FREE) {
            continue;
        }
        for (ULONG pageIndex = 0;
             pageIndex < target->PageCount;
             pageIndex++) {
            PHV_PEB_CLOAK_PAGE page = &target->Pages[pageIndex];
            if (page->GpaPage == GpaPage &&
                InterlockedCompareExchange(
                    &page->Installed, 0, 0) != 0) {
                return TRUE;
            }
        }
    }
    return FALSE;
}

// ============================================================
// Hot path (vmexit, IRQL = root mode 任意)
// ============================================================

/*
 * 内部:检查 SnoopedCr3 是不是已注册 target.
 * 不加锁 — Targets[] 是定长数组, Active 用 InterlockedCompareExchange 检查.
 */
static __forceinline BOOLEAN
HvPebCloakpIsTargetCr3(
    _In_ UINT64 Cr3,
    _Out_ PBOOLEAN PrivateDbgkTarget)
{
    *PrivateDbgkTarget = FALSE;
    if (!Cr3) return FALSE;
    Cr3 &= ~((UINT64)0xFFF);
    for (LONG i = 0; i < HV_PEB_CLOAK_MAX_TARGETS; i++) {
        PHV_PEB_CLOAK_TARGET t = &g_PebCloakManager.Targets[i];
        if (InterlockedCompareExchange(&t->Active, 0, 0) ==
            HV_PEB_TARGET_ACTIVE) {
            if ((t->UserCr3 & ~((UINT64)0xFFF)) == Cr3) {
                *PrivateDbgkTarget =
                    InterlockedCompareExchange(
                        &t->PrivateDbgkTarget, 0, 0) != 0;
                return TRUE;
            }
        }
    }
    return FALSE;
}

VOID HvPebCloakClassifyAndSwitchEptp(
    _Inout_ PVCPU_DATA Vcpu,
    _In_ UINT64 SnoopedCr3)
{
    if (!Vcpu || !Vcpu->EptPebSpoof || !Vcpu->EptpMain || !Vcpu->EptpPebSpoof) {
        return;
    }
    ULONG cpuIndex = MAXULONG;
    BOOLEAN haveCpuIndex = HvPebCloakpGetVcpuIndex(Vcpu, &cpuIndex);
    LONG pebGeneration = InterlockedCompareExchange(
        &g_PebCloakManager.Generation, 0, 0);
    BOOLEAN pebCacheCurrent = haveCpuIndex &&
        InterlockedCompareExchange(
            &g_PebCloakManager.LastClassGeneration[cpuIndex], 0, 0) ==
        pebGeneration;
    BOOLEAN pebTargetsActive =
        InterlockedCompareExchange(
            &g_PebCloakManager.Initialized, 0, 0) != 0 &&
        InterlockedCompareExchange(
            &g_PebCloakManager.GloballyEnabled, 0, 0) != 0;
    BOOLEAN vwatchTargetsActive = HvVwatchHasOverlayTargets();
    if (!pebTargetsActive && !vwatchTargetsActive) {
        // 空载 fast path: 永远保持 EptpMain.
        if (Vcpu->ActiveEptpIsPebSpoof) {
            HvPebCloakpVmwriteEptpAndInvept(Vcpu->EptpMain);
            Vcpu->ActiveEptpIsPebSpoof = 0;
        }
        Vcpu->LastSnoopedCr3 = 0;
        Vcpu->LastCallerClass = HV_PEB_CLASS_MAIN;
        if (haveCpuIndex) {
            InterlockedExchange(
                &g_PebCloakManager.LastOverlayTargetIsPrivateDbgk[cpuIndex],
                FALSE);
            InterlockedExchange(
                &g_PebCloakManager.LastClassGeneration[cpuIndex],
                pebGeneration);
        }
        return;
    }

    ULONG newClass;
    BOOLEAN privateKernelMainOverride = FALSE;
    if (SnoopedCr3 == 0) {
        // KVAS kernel-mode 上下文, snoop 不可信. 保留 LastCallerClass.
        if (!pebCacheCurrent ||
            Vcpu->LastCallerClass == HV_PEB_CLASS_UNKNOWN) {
            Vcpu->LastSnoopedCr3 = 0;
            Vcpu->LastCallerClass = HV_PEB_CLASS_MAIN;
            if (haveCpuIndex) {
                InterlockedExchange(
                    &g_PebCloakManager.LastOverlayTargetIsPrivateDbgk[cpuIndex],
                    FALSE);
            }
        }
        privateKernelMainOverride = haveCpuIndex &&
            Vcpu->LastCallerClass == HV_PEB_CLASS_PEB_SPOOF &&
            InterlockedCompareExchange(
                &g_PebCloakManager.LastOverlayTargetIsPrivateDbgk[cpuIndex],
                0,
                0) != 0;
        newClass = privateKernelMainOverride
            ? HV_PEB_CLASS_MAIN
            : Vcpu->LastCallerClass;
    } else if (SnoopedCr3 != Vcpu->LastSnoopedCr3 ||
               Vcpu->LastCallerClass == HV_PEB_CLASS_UNKNOWN ||
               !pebCacheCurrent) {
        BOOLEAN useOverlay = FALSE;
        BOOLEAN privateDbgkTarget = FALSE;
        if (pebTargetsActive && HvPebCloakpAcquireRootReference()) {
            useOverlay = HvPebCloakpIsTargetCr3(
                SnoopedCr3,
                &privateDbgkTarget);
            HvPebCloakpReleaseRootReference();
        }
        BOOLEAN cacheClassification = TRUE;
        ULONG vwatchGeneration = 0;
        if (!useOverlay && vwatchTargetsActive) {
            BOOLEAN vwatchTarget = FALSE;
            if (!HvVwatchTryIsOverlayTargetCr3Ex(
                    SnoopedCr3,
                    &vwatchTarget,
                    &vwatchGeneration)) {
                cacheClassification = FALSE;
            } else {
                useOverlay = vwatchTarget;
            }
        }
        if (cacheClassification && vwatchGeneration != 0 &&
            !HvVwatchOverlayGenerationIsCurrent(vwatchGeneration)) {
            cacheClassification = FALSE;
            useOverlay = FALSE;
        }
        newClass = useOverlay ? HV_PEB_CLASS_PEB_SPOOF
                              : HV_PEB_CLASS_MAIN;
        if (cacheClassification) {
            Vcpu->LastSnoopedCr3 = SnoopedCr3;
            Vcpu->LastCallerClass = newClass;
            if (haveCpuIndex) {
                InterlockedExchange(
                    &g_PebCloakManager.LastOverlayTargetIsPrivateDbgk[cpuIndex],
                    useOverlay && privateDbgkTarget);
                InterlockedExchange(
                    &g_PebCloakManager.LastClassGeneration[cpuIndex],
                    pebGeneration);
            }
            if ((vwatchGeneration != 0 &&
                 !HvVwatchOverlayGenerationIsCurrent(vwatchGeneration)) ||
                InterlockedCompareExchange(
                    &g_PebCloakManager.Generation, 0, 0) !=
                    pebGeneration) {
                Vcpu->LastSnoopedCr3 = 0;
                Vcpu->LastCallerClass = HV_PEB_CLASS_UNKNOWN;
                if (haveCpuIndex) {
                    InterlockedExchange(
                        &g_PebCloakManager.LastOverlayTargetIsPrivateDbgk[cpuIndex],
                        FALSE);
                    InterlockedExchange(
                        &g_PebCloakManager.LastClassGeneration[cpuIndex], 0);
                }
                newClass = HV_PEB_CLASS_MAIN;
            }
        } else {
            Vcpu->LastSnoopedCr3 = 0;
            Vcpu->LastCallerClass = HV_PEB_CLASS_UNKNOWN;
            if (haveCpuIndex) {
                InterlockedExchange(
                    &g_PebCloakManager.LastOverlayTargetIsPrivateDbgk[cpuIndex],
                    FALSE);
            }
        }
    } else {
        newClass = Vcpu->LastCallerClass;
    }

    LONG wantPebSpoof = (newClass == HV_PEB_CLASS_PEB_SPOOF) ? 1 : 0;
    if (wantPebSpoof == Vcpu->ActiveEptpIsPebSpoof) {
        return;
    }

    ULONG64 want = wantPebSpoof ? Vcpu->EptpPebSpoof : Vcpu->EptpMain;
    HvPebCloakpVmwriteEptpAndInvept(want);
    Vcpu->ActiveEptpIsPebSpoof = wantPebSpoof;

    if (wantPebSpoof) {
        InterlockedIncrement64(&g_PebCloakManager.SwitchCountPebSpoof);
    } else {
        InterlockedIncrement64(&g_PebCloakManager.SwitchCountMain);
        if (privateKernelMainOverride) {
            InterlockedIncrement64(
                &g_PebCloakManager.PrivateDbgkKernelMainSwitches);
        }
    }
}

BOOLEAN HvPebCloakHandleEptViolation(
    _Inout_ PVCPU_DATA Vcpu,
    _In_ ULONG64 Gpa,
    _In_ ULONG64 Qualification,
    _Inout_ PGUEST_CONTEXT Ctx)
{
    UNREFERENCED_PARAMETER(Ctx);

    if (!Vcpu || Vcpu->IsInL2 ||
        !Vcpu->ActiveEptpIsPebSpoof) {
        return FALSE;
    }

    SIZE_T currentEptp = 0;
    SIZE_T currentCr3 = 0;
    __vmx_vmread(VMCS_CTRL_EPTP, &currentEptp);
    __vmx_vmread(GUEST_CR3, &currentCr3);
    if ((ULONG64)currentEptp != Vcpu->EptpPebSpoof) {
        return FALSE;
    }

    if (!HvPebCloakpAcquireRootReference()) {
        return FALSE;
    }

    ULONG64 gpaPage = Gpa & ~((ULONG64)0xFFF);

    // 在所有 target 的所有 page 中找命中
    PHV_PEB_CLOAK_PAGE hitPage = NULL;
    PHV_PEB_CLOAK_TARGET hitTarget = NULL;
    BOOLEAN retiring = FALSE;
    for (LONG i = 0; i < HV_PEB_CLOAK_MAX_TARGETS; i++) {
        PHV_PEB_CLOAK_TARGET t = &g_PebCloakManager.Targets[i];
        LONG state = InterlockedCompareExchange(&t->Active, 0, 0);
        if (state != HV_PEB_TARGET_ACTIVE &&
            state != HV_PEB_TARGET_RETIRING) {
            continue;
        }
        if ((t->UserCr3 & 0x000FFFFFFFFFF000ULL) !=
            ((ULONG64)currentCr3 & 0x000FFFFFFFFFF000ULL)) {
            continue;
        }
        for (ULONG j = 0; j < t->PageCount; j++) {
            if (t->Pages[j].GpaPage == gpaPage &&
                InterlockedCompareExchange(&t->Pages[j].Installed, 0, 0))
            {
                hitPage = &t->Pages[j];
                hitTarget = t;
                retiring = (state == HV_PEB_TARGET_RETIRING) ||
                    (InterlockedCompareExchange(
                        &t->Pages[j].Retiring, 0, 0) != 0) ||
                    (InterlockedCompareExchange(
                        &t->Pages[j].Stale, 0, 0) != 0);
                break;
            }
        }
        if (hitPage) break;
    }
    if (!hitPage) {
        HvPebCloakpReleaseRootReference();
        return FALSE;
    }
    if (!HvPebCloakpAcquirePageRootReference(hitPage)) {
        HvPebCloakpReleaseRootReference();
        return FALSE;
    }

    ULONG cpu;
    if (!HvPebCloakpGetVcpuIndex(Vcpu, &cpu)) {
        HvPebCloakpReleasePageRootReference(hitPage);
        HvPebCloakpReleaseRootReference();
        return FALSE;
    }

    PEPT_PTE_ENTRY slot = hitPage->CloakedPte[cpu];
    if (!slot) {
        HvPebCloakpReleasePageRootReference(hitPage);
        HvPebCloakpReleaseRootReference();
        return FALSE;
    }

    UINT64 currentHpa = 0;
    UINT64 currentPageSize = 0;
    NTSTATUS verifyStatus = HvVtRootRootWalkGvaToHpaWithCr3(
        Vcpu,
        hitTarget->UserCr3,
        hitPage->GuestVa,
        &currentHpa,
        &currentPageSize);
    if (!NT_SUCCESS(verifyStatus) || currentPageSize == 0 ||
        (currentHpa & ~((UINT64)PAGE_SIZE - 1)) != hitPage->GpaPage) {
        EPT_PTE_ENTRY identity;
        identity.Value = 0;
        identity.Read = 1;
        identity.Write = 1;
        identity.Execute = 1;
        identity.MemoryType = HvEptGetMemoryType(
            hitPage->GpaPage, PAGE_SIZE);
        identity.PhysicalAddress = hitPage->OriginalPfn;
        InterlockedExchange(&hitPage->Stale, TRUE);
        HvPebCloakpWritePte(slot, identity);
        EptInveptAllContexts();
        HvPebCloakpReleasePageRootReference(hitPage);
        HvPebCloakpReleaseRootReference();
        return TRUE;
    }

    PHV_PEB_MTF_CONTEXT mtf = &g_PebCloakManager.MtfContext[cpu];
    if (!HvPebCloakpTryReserveMtf(mtf)) {
        EPT_PTE_ENTRY identity;
        identity.Value = 0;
        identity.Read = 1;
        identity.Write = 1;
        identity.Execute = 1;
        identity.MemoryType = HvEptGetMemoryType(
            hitPage->GpaPage, PAGE_SIZE);
        identity.PhysicalAddress = hitPage->OriginalPfn;
        InterlockedExchange(&hitPage->Stale, TRUE);
        HvPebCloakpWritePte(slot, identity);
        EptInveptAllContexts();
        HvPebCloakpReleasePageRootReference(hitPage);
        HvPebCloakpReleaseRootReference();
        return TRUE;
    }

    BOOLEAN passOriginal = retiring ||
        ((Qualification & HV_PEB_EPT_WRITE_ACCESS) != 0) ||
        ((Qualification & HV_PEB_EPT_EXECUTE_ACCESS) != 0);
    LONG activePatchIndex = InterlockedCompareExchange(
        &hitPage->ActivePatchIndex, 0, 0);
    if (!passOriginal) {
        InterlockedIncrement(
            &hitPage->PatchReaders[activePatchIndex == 0 ? 0 : 1]);
    }
    mtf->PendingPage = hitPage;
    mtf->PassOriginal = passOriginal ? TRUE : FALSE;
    mtf->Retiring = retiring ? TRUE : FALSE;
    mtf->PatchIndex = passOriginal
        ? 0xFF
        : (UCHAR)(activePatchIndex == 0 ? 0 : 1);
    MemoryBarrier();
    InterlockedExchange(&mtf->Active, HV_PEB_MTF_ARMED);

    // Reads see the patched page. Writes/RMW/execute must run against the
    // original page; mapping a write to the read-only patch caused the old
    // endless EPT-violation loop before MTF could ever fire.
    EPT_PTE_ENTRY patched; patched.Value = 0;
    ULONG64 patchPfn = activePatchIndex == 0
        ? hitPage->PatchPfn
        : hitPage->PatchPfnAlt;
    patched.Read = 1;
    patched.Write = passOriginal ? 1 : 0;
    patched.Execute = passOriginal ? 1 : 0;
    patched.MemoryType = HvEptGetMemoryType(
        (passOriginal ? hitPage->OriginalPfn : patchPfn) << PAGE_SHIFT,
        PAGE_SIZE);
    patched.PhysicalAddress = passOriginal
        ? hitPage->OriginalPfn
        : patchPfn;
    HvPebCloakpWritePte(slot, patched);

    EptInveptAllContexts();
    HvPebCloakpSetMtf(TRUE);
    InterlockedIncrement64(&g_PebCloakManager.ViolationHits);

    return TRUE;
}

BOOLEAN HvPebCloakHandleMtfExit(
    _Inout_ PVCPU_DATA Vcpu,
    _Inout_ PGUEST_CONTEXT Ctx)
{
    UNREFERENCED_PARAMETER(Ctx);

    if (InterlockedCompareExchange(
            &g_PebCloakManager.Initialized, 0, 0) == 0) {
        return FALSE;
    }

    ULONG cpu;
    if (!HvPebCloakpGetVcpuIndex(Vcpu, &cpu)) return FALSE;

    PHV_PEB_MTF_CONTEXT mtf = &g_PebCloakManager.MtfContext[cpu];
    if (InterlockedCompareExchange(
            &mtf->Active,
            HV_PEB_MTF_COMPLETING,
            HV_PEB_MTF_ARMED) != HV_PEB_MTF_ARMED) {
        return FALSE;
    }

    PHV_PEB_CLOAK_PAGE hitPage = (PHV_PEB_CLOAK_PAGE)mtf->PendingPage;
    BOOLEAN passOriginal = mtf->PassOriginal != FALSE;
    BOOLEAN retiring = mtf->Retiring != FALSE;
    UCHAR patchIndex = mtf->PatchIndex;
    if (hitPage && InterlockedCompareExchange(
            &hitPage->Retiring, 0, 0) != 0) {
        retiring = TRUE;
    }
    if (!hitPage) {
        HvPebCloakpSetMtf(FALSE);
        mtf->PassOriginal = FALSE;
        mtf->Retiring = FALSE;
        mtf->PatchIndex = 0xFF;
        MemoryBarrier();
        InterlockedExchange(&mtf->Active, HV_PEB_MTF_IDLE);
        HvPebCloakpReleaseRootReference();
        return TRUE;
    }

    PEPT_PTE_ENTRY slot = hitPage->CloakedPte[cpu];
    if (slot) {
        EPT_PTE_ENTRY next; next.Value = 0;
        if (!retiring && passOriginal) {
            NTSTATUS refreshStatus =
                HvPebCloakpRefreshPatchPageRoot(Vcpu, hitPage);
            if (!NT_SUCCESS(refreshStatus)) {
                retiring = TRUE;
            }
        }
        if (retiring) {
            next.Read = 1;
            next.Write = 1;
            next.Execute = 1;
        } else {
            next.Read = 0;
            next.Write = 0;
            next.Execute = 0;
        }
        next.MemoryType = HvEptGetMemoryType(
            hitPage->GpaPage, PAGE_SIZE);
        next.PhysicalAddress = hitPage->OriginalPfn;
        HvPebCloakpWritePte(slot, next);
        EptInveptAllContexts();
    }
    HvPebCloakpSetMtf(FALSE);
    mtf->PendingPage = NULL;
    mtf->PassOriginal = FALSE;
    mtf->Retiring = FALSE;
    mtf->PatchIndex = 0xFF;
    if (!passOriginal && patchIndex < 2) {
        InterlockedDecrement(&hitPage->PatchReaders[patchIndex]);
    }
    MemoryBarrier();
    InterlockedExchange(&mtf->Active, HV_PEB_MTF_IDLE);
    HvPebCloakpReleasePageRootReference(hitPage);
    HvPebCloakpReleaseRootReference();
    InterlockedIncrement64(&g_PebCloakManager.MtfCompletions);
    return TRUE;
}
