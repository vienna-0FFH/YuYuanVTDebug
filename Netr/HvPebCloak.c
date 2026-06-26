/*
 * HvPebCloak.c - PEB 字段级 EPT spoof
 *
 * P125 (2026-06-25): 见 HvPebCloak.h 顶部说明.
 */

#include "HvPebCloak.h"
#include "HvCompat.h"
#include "HvEpt.h"            // HvEptBuildIdentityInto
#include "EptHook.h"          // EPT_PTE_ENTRY, EptInveptAllContexts, EptGetPteForPhysicalAddress
#include "HvPhysAccess.h"     // HvPhysGvaToHpa
#include "HvVtRoot.h"         // HvVtRootGetResolvedUserCr3
#include "SimpleHypervisor.h"
#include <ntstrsafe.h>

// P122: 全 driver DbgPrint → GUI ring
#define HV_TRACE_THIS_CAT HV_TRACE_CAT_CLOAK
#include "HvTrace.h"

// 2026-06-25: 全局开关. 让现场可以一次性灰度.
#ifndef HV_ENABLE_PEB_CLOAK
// 2026-06-26: 关闭过验证 -> 确认根因 = vwatch inject 后 mtf->Active 永远卡 1
// 导致死循环 violation. 已在 HvVwatch.c::HvVwatchHandleEptViolation INJECT
// 分支修复 (inject 后立刻清 Active + 恢复 trap mask, 不 arm MTF).
// 重新打开 cloak.
#define HV_ENABLE_PEB_CLOAK 1
#endif

// KeStackAttachProcess prototype (KAPC_STATE opaque)
typedef struct _HV_PEB_APC_STATE {
    UCHAR Reserved[0x60];
} HV_PEB_APC_STATE;

NTKERNELAPI VOID KeStackAttachProcess(
    _Inout_ PRKPROCESS PROCESS,
    _Out_ HV_PEB_APC_STATE* ApcState);

NTKERNELAPI VOID KeUnstackDetachProcess(
    _In_ HV_PEB_APC_STATE* ApcState);

// PsGetProcessPeb prototype (ntifs.h 在 WDK 中不一定可用)
NTKERNELAPI PVOID PsGetProcessPeb(_In_ PEPROCESS Process);

#define HV_PEB_TAG     'kCbP'  // PbCk

// ============================================================
// 全局
// ============================================================

HV_PEB_CLOAK_MANAGER g_PebCloakManager = { 0 };

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
        PHYSICAL_ADDRESS maxAddr; maxAddr.QuadPart = -1LL;
        PEPT_PTE_ENTRY ptTable =
            (PEPT_PTE_ENTRY)MmAllocateContiguousMemory(PAGE_SIZE, maxAddr);
        if (!ptTable) return NULL;
        RtlZeroMemory(ptTable, PAGE_SIZE);

        // 把 512 个 4KB slot 填成 identity, R/W/X 继承
        for (ULONG i = 0; i < 512; i++) {
            ptTable[i].Value = 0;
            ptTable[i].Read = 1;
            ptTable[i].Write = 1;
            ptTable[i].Execute = 1;
            ptTable[i].MemoryType = 6;   // WB
            ptTable[i].PhysicalAddress = ((baseGpa >> 12) + i);
        }

        PHYSICAL_ADDRESS ptPa = MmGetPhysicalAddress(ptTable);

        // 记到 SplitPt[] (供 fallback walk 用)
        if (EptTables->SplitPtCount < RTL_NUMBER_OF(EptTables->SplitPt)) {
            EptTables->SplitPt[EptTables->SplitPtCount] = (PEPT_PTE)ptTable;
            EptTables->SplitPtPhysical[EptTables->SplitPtCount] = ptPa;
            EptTables->SplitPtCount++;
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
        for (ULONG i = 0; i < EptTables->SplitPtCount; i++) {
            if ((ULONG64)EptTables->SplitPtPhysical[i].QuadPart == ptPa) {
                return &((PEPT_PTE_ENTRY)EptTables->SplitPt[i])[ptIndex];
            }
        }
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

/*
 * 解出 target user CR3. 走 VtRoot KVAS-safe 路径.
 *
 * P126.2 fix (2026-06-25): 直接调 HvVtRootResolveUserCr3 (mode=3 VMCALL),
 *   root mode 跑 24 候选 + MZ 锚点 + 返回真 CR3. 不依赖 cache 命中,
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

    // 2) 兜底 PASSIVE 路径 (KVAS 下不可靠, 但保留)
    s = HvPhysFindUserCr3ByPid(pid32, &cr3);
    if (NT_SUCCESS(s) && cr3) {
        *OutCr3 = cr3;
        return STATUS_SUCCESS;
    }

    return STATUS_NOT_FOUND;
}

/*
 * Page patch 描述符 (HvPebCloakpResolveAndPatch 用).
 * Offset/Size/Mask/SetTo 共同定义一处字段抹除规则.
 */
typedef enum _HV_PATCH_OP {
    HV_PATCH_SET_BYTE,      // 写 1 字节 (SetTo[0])
    HV_PATCH_AND_DWORD,     // dw &= AndMask
    HV_PATCH_SET_DWORD,     // dw = SetTo (取 SetTo 低 32)
} HV_PATCH_OP;

typedef struct _HV_PEB_FIELD_PATCH {
    ULONG       Offset;     // 页内 offset (= field VA - page base)
    HV_PATCH_OP Op;
    ULONG       Value;      // SET_BYTE 取低 8; AND_DWORD = AndMask; SET_DWORD = 新值
} HV_PEB_FIELD_PATCH;

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
        switch (pp->Op) {
        case HV_PATCH_SET_BYTE:
            if (pp->Offset < PAGE_SIZE) {
                p[pp->Offset] = (UCHAR)(pp->Value & 0xFF);
            }
            break;
        case HV_PATCH_AND_DWORD:
            if (pp->Offset + 4 <= PAGE_SIZE) {
                *(volatile ULONG*)(p + pp->Offset) &= pp->Value;
            }
            break;
        case HV_PATCH_SET_DWORD:
            if (pp->Offset + 4 <= PAGE_SIZE) {
                *(volatile ULONG*)(p + pp->Offset) = pp->Value;
            }
            break;
        }
    }
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
    NTSTATUS s = HvVtRootWalkGvaToHpa(Pid, Gva, &hpa, &pageSize);
    if (!NT_SUCCESS(s) || !hpa) {
        // 兜底: PASSIVE walker (KVAS 下大概率失败)
        PHYSICAL_ADDRESS phpa = { 0 };
        s = HvPhysGvaToHpa(UserCr3, Gva, &phpa, NULL, NULL);
        if (!NT_SUCCESS(s) || !phpa.QuadPart) return STATUS_NOT_FOUND;
        *OutGpa = (ULONG64)phpa.QuadPart;
        return STATUS_SUCCESS;
    }
    *OutGpa = hpa;
    return STATUS_SUCCESS;
}

/*
 * 准备一个 cloak page:
 *   1) 解 GVA → GPA → 页基
 *   2) 分配 4KB 补丁页
 *   3) KeStackAttachProcess 复制原页内容 → 补丁页
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

    ULONG64 pageVa = FieldVa & ~((ULONG64)0xFFF);
    OutPage->GuestVa = pageVa;

    NTSTATUS s = HvPebCloakpGvaToGpa((ULONG)(ULONG_PTR)Pid, UserCr3, pageVa, &OutPage->GpaPage);
    if (!NT_SUCCESS(s)) return s;
    OutPage->OriginalPfn = OutPage->GpaPage >> 12;

    PHYSICAL_ADDRESS maxAddr; maxAddr.QuadPart = -1LL;
    PVOID patch = MmAllocateContiguousMemory(PAGE_SIZE, maxAddr);
    if (!patch) return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(patch, PAGE_SIZE);

    PEPROCESS proc = NULL;
    s = PsLookupProcessByProcessId(Pid, &proc);
    if (!NT_SUCCESS(s) || !proc) {
        MmFreeContiguousMemory(patch);
        return s;
    }

    HV_PEB_APC_STATE apc;
    KeStackAttachProcess((PRKPROCESS)proc, &apc);
    __try {
        ProbeForRead((PVOID)pageVa, PAGE_SIZE, sizeof(UCHAR));
        RtlCopyMemory(patch, (PVOID)pageVa, PAGE_SIZE);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        s = STATUS_ACCESS_VIOLATION;
    }
    KeUnstackDetachProcess(&apc);
    ObDereferenceObject(proc);

    if (!NT_SUCCESS(s)) {
        MmFreeContiguousMemory(patch);
        return s;
    }

    HvPebCloakpApplyPatches(patch, Patches, PatchCount);

    OutPage->PatchVa = patch;
    OutPage->PatchPfn = MmGetPhysicalAddress(patch).QuadPart >> 12;
    return STATUS_SUCCESS;
}

/*
 * 在所有 vcpu 的 EptPebSpoof 上 install 一个 page cloak:
 *   PT slot 指向 OriginalPfn, R=0/W=0/X=0 强制 violation
 */
static NTSTATUS
HvPebCloakpInstallPageOnAllVcpus(_Inout_ PHV_PEB_CLOAK_PAGE Page)
{
    ULONG cpuCount = KeQueryActiveProcessorCount(NULL);
    if (cpuCount > HV_PEB_CLOAK_MAX_CPUS) cpuCount = HV_PEB_CLOAK_MAX_CPUS;

    ULONG ok = 0;
    for (ULONG c = 0; c < cpuCount; c++) {
        PVCPU_DATA vcpu = &g_HypervisorContext.VcpuData[c];
        if (!vcpu->EptPebSpoof) continue;

        PEPT_PTE_ENTRY slot = HvPebCloakpFindOrSplitPtSlot(vcpu->EptPebSpoof, Page->GpaPage);
        if (!slot) continue;

        EPT_PTE_ENTRY newPte; newPte.Value = 0;
        newPte.Read = 0;
        newPte.Write = 0;
        newPte.Execute = 0;
        newPte.MemoryType = 6;
        newPte.PhysicalAddress = Page->OriginalPfn;
        slot->Value = newPte.Value;

        Page->CloakedPte[c] = slot;
        ok++;
    }
    if (ok > 0) {
        InterlockedExchange(&Page->Installed, 1);
        return STATUS_SUCCESS;
    }
    return STATUS_UNSUCCESSFUL;
}

/*
 * 撤销一个 page cloak.
 */
static VOID
HvPebCloakpUninstallPageOnAllVcpus(_Inout_ PHV_PEB_CLOAK_PAGE Page)
{
    if (!InterlockedExchange(&Page->Installed, 0)) return;

    ULONG cpuCount = KeQueryActiveProcessorCount(NULL);
    if (cpuCount > HV_PEB_CLOAK_MAX_CPUS) cpuCount = HV_PEB_CLOAK_MAX_CPUS;

    for (ULONG c = 0; c < cpuCount; c++) {
        PEPT_PTE_ENTRY slot = Page->CloakedPte[c];
        if (!slot) continue;
        EPT_PTE_ENTRY restored; restored.Value = 0;
        restored.Read = 1;
        restored.Write = 1;
        restored.Execute = 1;
        restored.MemoryType = 6;
        restored.PhysicalAddress = Page->OriginalPfn;
        slot->Value = restored.Value;
        Page->CloakedPte[c] = NULL;
    }
    if (Page->PatchVa) {
        MmFreeContiguousMemory(Page->PatchVa);
        Page->PatchVa = NULL;
    }
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
}

/*
 * 解 PEB VA + ProcessHeap VA (KeStackAttachProcess 读 PEB.ProcessHeap 指针).
 */
static NTSTATUS
HvPebCloakpResolvePebAndHeapVa(
    _In_ HANDLE Pid,
    _Out_ PULONG64 OutPebVa,
    _Out_ PULONG64 OutHeapVa)
{
    *OutPebVa = 0; *OutHeapVa = 0;

    PEPROCESS proc = NULL;
    NTSTATUS s = PsLookupProcessByProcessId(Pid, &proc);
    if (!NT_SUCCESS(s) || !proc) return s;

    PVOID pebVa = PsGetProcessPeb(proc);
    if (!pebVa) {
        ObDereferenceObject(proc);
        return STATUS_NOT_FOUND;
    }
    *OutPebVa = (ULONG64)pebVa;

    PVOID heapVa = NULL;
    HV_PEB_APC_STATE apc;
    KeStackAttachProcess((PRKPROCESS)proc, &apc);
    __try {
        ProbeForRead((PUCHAR)pebVa + HV_PEB_OFF_PROCESS_HEAP, sizeof(PVOID), sizeof(UCHAR));
        heapVa = *(PVOID*)((PUCHAR)pebVa + HV_PEB_OFF_PROCESS_HEAP);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        s = STATUS_ACCESS_VIOLATION;
    }
    KeUnstackDetachProcess(&apc);
    ObDereferenceObject(proc);

    if (!NT_SUCCESS(s)) return s;
    *OutHeapVa = (ULONG64)heapVa;   // 可能 0 (进程极早期 ldr 没建 heap), 调用方自查
    return STATUS_SUCCESS;
}

// ============================================================
// 生命周期
// ============================================================

NTSTATUS HvPebCloakInitialize(VOID)
{
#if !HV_ENABLE_PEB_CLOAK
    DbgPrint("[PebCloak] Init: HV_ENABLE_PEB_CLOAK=0, manager skipped\n");
    return STATUS_SUCCESS;
#else
    if (g_PebCloakManager.Initialized) return STATUS_SUCCESS;

    RtlZeroMemory(&g_PebCloakManager, sizeof(g_PebCloakManager));
    KeInitializeSpinLock(&g_PebCloakManager.Lock);
    g_PebCloakManager.Initialized = TRUE;
    g_PebCloakManager.GloballyEnabled = FALSE;

    DbgPrint("[PebCloak] Init OK\n");
    return STATUS_SUCCESS;
#endif
}

VOID HvPebCloakShutdown(VOID)
{
    if (!g_PebCloakManager.Initialized) return;
    g_PebCloakManager.GloballyEnabled = FALSE;

    KIRQL old;
    KeAcquireSpinLock(&g_PebCloakManager.Lock, &old);
    for (LONG i = 0; i < HV_PEB_CLOAK_MAX_TARGETS; i++) {
        PHV_PEB_CLOAK_TARGET t = &g_PebCloakManager.Targets[i];
        if (InterlockedExchange(&t->Active, 0)) {
            HvPebCloakpUninstallTarget(t);
        }
    }
    g_PebCloakManager.TargetCount = 0;
    KeReleaseSpinLock(&g_PebCloakManager.Lock, old);

    g_PebCloakManager.Initialized = FALSE;
    DbgPrint("[PebCloak] Shutdown\n");
}

NTSTATUS HvPebCloakSetupVcpu(_Inout_ PVCPU_DATA Vcpu)
{
#if !HV_ENABLE_PEB_CLOAK
    UNREFERENCED_PARAMETER(Vcpu);
    return STATUS_SUCCESS;
#else
    if (!Vcpu || !Vcpu->EptTables) return STATUS_INVALID_PARAMETER;
    if (Vcpu->EptPebSpoof) return STATUS_SUCCESS;   // 已建好

    PHYSICAL_ADDRESS maxAddr; maxAddr.QuadPart = -1LL;
    PEPT_TABLES ept = (PEPT_TABLES)MmAllocateContiguousMemory(sizeof(EPT_TABLES), maxAddr);
    if (!ept) return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(ept, sizeof(EPT_TABLES));
    ept->Pml4Physical = MmGetPhysicalAddress(ept);

    NTSTATUS s = HvEptBuildIdentityInto(ept);
    if (!NT_SUCCESS(s)) {
        MmFreeContiguousMemory(ept);
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
#endif
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
    if (!g_PebCloakManager.Initialized) return STATUS_DEVICE_NOT_READY;
    if (!Pid) return STATUS_INVALID_PARAMETER;

    // 解 user CR3
    UINT64 userCr3 = 0;
    NTSTATUS s = HvPebCloakpResolveUserCr3(Pid, &userCr3);
    if (!NT_SUCCESS(s) || !userCr3) {
        DbgPrint("[PebCloak] Register PID=%u: resolve user CR3 failed 0x%X\n",
                 (ULONG)(ULONG_PTR)Pid, s);
        return s;
    }

    // 解 PEB VA + ProcessHeap VA (一次性 attach 拿两值)
    ULONG64 pebVa = 0, heapVa = 0;
    s = HvPebCloakpResolvePebAndHeapVa(Pid, &pebVa, &heapVa);
    if (!NT_SUCCESS(s) || !pebVa) {
        DbgPrint("[PebCloak] Register PID=%u: resolve PEB/Heap VA failed 0x%X\n",
                 (ULONG)(ULONG_PTR)Pid, s);
        return s;
    }

    KIRQL old;
    KeAcquireSpinLock(&g_PebCloakManager.Lock, &old);

    // 已注册?
    for (LONG i = 0; i < HV_PEB_CLOAK_MAX_TARGETS; i++) {
        if (g_PebCloakManager.Targets[i].Pid == Pid &&
            InterlockedCompareExchange(&g_PebCloakManager.Targets[i].Active, 0, 0))
        {
            KeReleaseSpinLock(&g_PebCloakManager.Lock, old);
            return STATUS_SUCCESS;
        }
    }

    // 找空槽
    LONG idx = -1;
    for (LONG i = 0; i < HV_PEB_CLOAK_MAX_TARGETS; i++) {
        if (!InterlockedCompareExchange(&g_PebCloakManager.Targets[i].Active, 0, 0)) {
            idx = i;
            break;
        }
    }
    if (idx < 0) {
        KeReleaseSpinLock(&g_PebCloakManager.Lock, old);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    PHV_PEB_CLOAK_TARGET t = &g_PebCloakManager.Targets[idx];
    RtlZeroMemory(t, sizeof(*t));
    t->Pid = Pid;
    t->UserCr3 = userCr3;
    KeReleaseSpinLock(&g_PebCloakManager.Lock, old);

    // ---- Page 1: PEB (BeingDebugged + NtGlobalFlag) ----
    {
        ULONG_PTR pebOffInPage = (ULONG_PTR)pebVa & 0xFFF;
        HV_PEB_FIELD_PATCH pebPatches[2] = {
            { (ULONG)(pebOffInPage + HV_PEB_OFF_BEING_DEBUGGED), HV_PATCH_SET_BYTE,  0 },
            { (ULONG)(pebOffInPage + HV_PEB_OFF_NT_GLOBAL_FLAG), HV_PATCH_AND_DWORD, ~(ULONG)HV_PEB_NT_GLOBAL_FLAG_MASK },
        };
        s = HvPebCloakpPrepareCloakPage(Pid, userCr3, pebVa, pebPatches, 2, &t->Pages[t->PageCount]);
        if (!NT_SUCCESS(s)) {
            DbgPrint("[PebCloak] Register PID=%u: PEB page prepare failed 0x%X\n",
                     (ULONG)(ULONG_PTR)Pid, s);
            HvPebCloakpUninstallTarget(t);
            return s;
        }
        s = HvPebCloakpInstallPageOnAllVcpus(&t->Pages[t->PageCount]);
        if (!NT_SUCCESS(s)) {
            DbgPrint("[PebCloak] Register PID=%u: PEB page install failed 0x%X\n",
                     (ULONG)(ULONG_PTR)Pid, s);
            HvPebCloakpUninstallPageOnAllVcpus(&t->Pages[t->PageCount]);
            HvPebCloakpUninstallTarget(t);
            return s;
        }
        t->PageCount++;
    }

    // ---- Page 2: ProcessHeap header (Flags + ForceFlags) ----
    // heapVa==0 → 进程还没建 default heap, 跳过 (loader 跑完会有)
    if (heapVa) {
        ULONG_PTR heapOffInPage = (ULONG_PTR)heapVa & 0xFFF;
        // 确认 Flags/ForceFlags 都在 ProcessHeap 所在 4KB 页内 (offset 0x70+8 = 0x78,
        // 远小于 PAGE_SIZE - heap header 大小 0x78, 几乎 100% 落同页 — 否则 skip)
        if (heapOffInPage + HV_HEAP_OFF_FORCE_FLAGS + 4 <= PAGE_SIZE) {
            HV_PEB_FIELD_PATCH heapPatches[2] = {
                { (ULONG)(heapOffInPage + HV_HEAP_OFF_FLAGS),       HV_PATCH_SET_DWORD, HV_HEAP_FLAGS_CLEAN },
                { (ULONG)(heapOffInPage + HV_HEAP_OFF_FORCE_FLAGS), HV_PATCH_SET_DWORD, HV_HEAP_FORCE_FLAGS_CLEAN },
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
        return STATUS_UNSUCCESSFUL;
    }

    // 激活
    KeAcquireSpinLock(&g_PebCloakManager.Lock, &old);
    InterlockedExchange(&t->Active, 1);
    InterlockedIncrement(&g_PebCloakManager.TargetCount);
    g_PebCloakManager.GloballyEnabled = TRUE;
    KeReleaseSpinLock(&g_PebCloakManager.Lock, old);

    DbgPrint("[PebCloak] Registered PID=%u userCr3=0x%llX PEB.GVA=0x%llX Heap.GVA=0x%llX pages=%u\n",
             (ULONG)(ULONG_PTR)Pid, userCr3, pebVa, heapVa, t->PageCount);
    for (ULONG i = 0; i < t->PageCount; i++) {
        DbgPrint("[PebCloak]   page[%u] GVA=0x%llX GPA=0x%llX PatchPfn=0x%llX\n",
                 i, t->Pages[i].GuestVa, t->Pages[i].GpaPage, t->Pages[i].PatchPfn);
    }

    return STATUS_SUCCESS;
#endif
}

VOID HvPebCloakUnregisterTarget(_In_ HANDLE Pid)
{
#if !HV_ENABLE_PEB_CLOAK
    UNREFERENCED_PARAMETER(Pid);
    return;
#else
    if (!g_PebCloakManager.Initialized || !Pid) return;

    KIRQL old;
    KeAcquireSpinLock(&g_PebCloakManager.Lock, &old);

    LONG hit = -1;
    for (LONG i = 0; i < HV_PEB_CLOAK_MAX_TARGETS; i++) {
        if (g_PebCloakManager.Targets[i].Pid == Pid &&
            InterlockedCompareExchange(&g_PebCloakManager.Targets[i].Active, 0, 1) == 1)
        {
            hit = i;
            break;
        }
    }

    KeReleaseSpinLock(&g_PebCloakManager.Lock, old);

    if (hit < 0) return;

    PHV_PEB_CLOAK_TARGET t = &g_PebCloakManager.Targets[hit];

    // 撤销所有 cloak page
    HvPebCloakpUninstallTarget(t);

    KeAcquireSpinLock(&g_PebCloakManager.Lock, &old);
    InterlockedDecrement(&g_PebCloakManager.TargetCount);
    if (g_PebCloakManager.TargetCount <= 0) {
        g_PebCloakManager.GloballyEnabled = FALSE;
        g_PebCloakManager.TargetCount = 0;
    }
    KeReleaseSpinLock(&g_PebCloakManager.Lock, old);

    DbgPrint("[PebCloak] Unregistered PID=%u\n", (ULONG)(ULONG_PTR)Pid);
#endif
}

VOID HvPebCloakOnProcessExit(_In_ HANDLE Pid)
{
    HvPebCloakUnregisterTarget(Pid);
}

// ============================================================
// Hot path (vmexit, IRQL = root mode 任意)
// ============================================================

/*
 * 内部:检查 SnoopedCr3 是不是已注册 target.
 * 不加锁 — Targets[] 是定长数组, Active 用 InterlockedCompareExchange 检查.
 */
static __forceinline BOOLEAN
HvPebCloakpIsTargetCr3(_In_ UINT64 Cr3)
{
    if (!Cr3) return FALSE;
    Cr3 &= ~((UINT64)0xFFF);
    for (LONG i = 0; i < HV_PEB_CLOAK_MAX_TARGETS; i++) {
        PHV_PEB_CLOAK_TARGET t = &g_PebCloakManager.Targets[i];
        if (InterlockedCompareExchange(&t->Active, 0, 0)) {
            if ((t->UserCr3 & ~((UINT64)0xFFF)) == Cr3) {
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
    if (!g_PebCloakManager.Initialized || !g_PebCloakManager.GloballyEnabled) {
        // 空载 fast path: 永远保持 EptpMain.
        if (Vcpu->ActiveEptpIsPebSpoof) {
            HvPebCloakpVmwriteEptpAndInvept(Vcpu->EptpMain);
            Vcpu->ActiveEptpIsPebSpoof = 0;
        }
        return;
    }

    ULONG newClass;
    if (SnoopedCr3 == 0) {
        // KVAS kernel-mode 上下文, snoop 不可信. 保留 LastCallerClass.
        if (Vcpu->LastCallerClass == HV_PEB_CLASS_UNKNOWN) {
            Vcpu->LastCallerClass = HV_PEB_CLASS_MAIN;
        }
        newClass = Vcpu->LastCallerClass;
    } else if (SnoopedCr3 != Vcpu->LastSnoopedCr3 ||
               Vcpu->LastCallerClass == HV_PEB_CLASS_UNKNOWN) {
        Vcpu->LastSnoopedCr3 = SnoopedCr3;
        newClass = HvPebCloakpIsTargetCr3(SnoopedCr3) ? HV_PEB_CLASS_PEB_SPOOF
                                                     : HV_PEB_CLASS_MAIN;
        Vcpu->LastCallerClass = newClass;
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
    }
}

BOOLEAN HvPebCloakHandleEptViolation(
    _In_ ULONG64 Gpa,
    _In_ ULONG64 Qualification,
    _Inout_ PGUEST_CONTEXT Ctx)
{
    UNREFERENCED_PARAMETER(Qualification);
    UNREFERENCED_PARAMETER(Ctx);

    if (!g_PebCloakManager.Initialized || !g_PebCloakManager.GloballyEnabled) {
        return FALSE;
    }

    ULONG64 gpaPage = Gpa & ~((ULONG64)0xFFF);

    // 在所有 target 的所有 page 中找命中
    PHV_PEB_CLOAK_PAGE hitPage = NULL;
    for (LONG i = 0; i < HV_PEB_CLOAK_MAX_TARGETS; i++) {
        PHV_PEB_CLOAK_TARGET t = &g_PebCloakManager.Targets[i];
        if (!InterlockedCompareExchange(&t->Active, 0, 0)) continue;
        for (ULONG j = 0; j < t->PageCount; j++) {
            if (t->Pages[j].GpaPage == gpaPage &&
                InterlockedCompareExchange(&t->Pages[j].Installed, 0, 0))
            {
                hitPage = &t->Pages[j];
                break;
            }
        }
        if (hitPage) break;
    }
    if (!hitPage) return FALSE;

    ULONG cpu = KeGetCurrentProcessorNumberEx(NULL);
    if (cpu >= HV_PEB_CLOAK_MAX_CPUS) return FALSE;

    PEPT_PTE_ENTRY slot = hitPage->CloakedPte[cpu];
    if (!slot) return FALSE;

    PHV_PEB_MTF_CONTEXT mtf = &g_PebCloakManager.MtfContext[cpu];
    if (InterlockedCompareExchange(&mtf->Active, 1, 0) != 0) {
        return FALSE;
    }
    mtf->PendingPage = hitPage;

    // 切到补丁页 + R=1/W=0/X=0
    EPT_PTE_ENTRY patched; patched.Value = 0;
    patched.Read = 1;
    patched.Write = 0;
    patched.Execute = 0;
    patched.MemoryType = 6;
    patched.PhysicalAddress = hitPage->PatchPfn;
    slot->Value = patched.Value;

    EptInveptAllContexts();
    HvPebCloakpSetMtf(TRUE);
    InterlockedIncrement64(&g_PebCloakManager.ViolationHits);

    return TRUE;
}

BOOLEAN HvPebCloakHandleMtfExit(_Inout_ PGUEST_CONTEXT Ctx)
{
    UNREFERENCED_PARAMETER(Ctx);

    if (!g_PebCloakManager.Initialized) return FALSE;

    ULONG cpu = KeGetCurrentProcessorNumberEx(NULL);
    if (cpu >= HV_PEB_CLOAK_MAX_CPUS) return FALSE;

    PHV_PEB_MTF_CONTEXT mtf = &g_PebCloakManager.MtfContext[cpu];
    if (!InterlockedCompareExchange(&mtf->Active, 0, 1)) {
        return FALSE;
    }

    PHV_PEB_CLOAK_PAGE hitPage = (PHV_PEB_CLOAK_PAGE)mtf->PendingPage;
    mtf->PendingPage = NULL;
    if (!hitPage) {
        HvPebCloakpSetMtf(FALSE);
        return TRUE;
    }

    PEPT_PTE_ENTRY slot = hitPage->CloakedPte[cpu];
    if (slot) {
        EPT_PTE_ENTRY r0; r0.Value = 0;
        r0.Read = 0;
        r0.Write = 0;
        r0.Execute = 0;
        r0.MemoryType = 6;
        r0.PhysicalAddress = hitPage->OriginalPfn;
        slot->Value = r0.Value;
        EptInveptAllContexts();
    }
    HvPebCloakpSetMtf(FALSE);
    InterlockedIncrement64(&g_PebCloakManager.MtfCompletions);
    return TRUE;
}
