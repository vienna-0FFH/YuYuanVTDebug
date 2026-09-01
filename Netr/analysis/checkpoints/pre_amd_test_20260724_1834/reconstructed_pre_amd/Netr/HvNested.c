/*
 * HvNested.c - 嵌套虚拟化核心实现
 * 
 * 实现 Intel VMX 嵌套虚拟化，包括：
 * - VMX 指令处理（VMXON, VMXOFF, VMCLEAR, VMPTRLD, VMREAD, VMWRITE, VMLAUNCH, VMRESUME）
 * - VMCS 合并逻辑（VMCS01 + VMCS12 -> VMCS02）
 * - L2 VM Exit 分发
 * - 嵌套 EPT 支持
 */

#include "HvNested.h"
#include "HvVmcs.h"
#include "HvCompat.h"
#include "HvPhysAccess.h"
#include "HvVtRoot.h"
#include "HvEpt.h"
#include "HvNpt.h"
#include <intrin.h>  // __readmsr (Step 3 虚幻范式 — 用 RDMSR(IA32_FS_BASE) 代替
                     // _readfsbase_u64, 后者需 CR4.FSGSBASE=1, 不普适)
#include "EptHook.h"
#include "HvNestedEpt.h"
#include "HvNestedSvm.h"
#include "HvNestedNpt.h"

// P122: 全 driver DbgPrint → GUI ring
#define HV_TRACE_THIS_CAT HV_TRACE_CAT_NESTED
#include "HvTrace.h"

// ==================== 内部变量 ====================

// 嵌套虚拟化统计
static volatile LONG64 g_NestedVmxonCount = 0;
static volatile LONG64 g_NestedVmlaunchCount = 0;
static volatile LONG64 g_NestedVmExitCount = 0;

typedef struct _HV_NESTED_EVENT_SLOT {
    volatile LONG64 PublishedSequence;
    HV_NESTED_EVENT Event;
} HV_NESTED_EVENT_SLOT, *PHV_NESTED_EVENT_SLOT;

static volatile LONG g_NestedLifecycle = HvNestedStateUninitialized;
static volatile LONG64 g_NestedEventWriteSequence = 0;
static volatile LONG64 g_NestedEventClearSequence = 0;
static HV_NESTED_EVENT_SLOT g_NestedEventRing[HV_NESTED_EVENT_CAPACITY];
static BOOLEAN g_NestedEptInitialized = FALSE;
static BOOLEAN g_NestedSvmInitialized = FALSE;
static BOOLEAN g_NestedNptInitialized = FALSE;

static ULONG_PTR HvNestedQuiesceIpiCallback(_In_ ULONG_PTR Context)
{
    UNREFERENCED_PARAMETER(Context);
    // Reaching this callback proves the processor has returned to the L1
    // Windows context.  While the lifecycle is Quiescing, the VM-exit paths
    // reflect the first L2 exit to L1 and reject every new nested entry.
    return 0;
}

#define HV_NESTED_ROOT_PTE_PRESENT  (1ULL << 0)
#define HV_NESTED_ROOT_PTE_RW       (1ULL << 1)
#define HV_NESTED_ROOT_PTE_GLOBAL   (1ULL << 8)
#define HV_NESTED_ROOT_PTE_NX       (1ULL << 63)
#define HV_NESTED_ROOT_PTE_MASK     0x000FFFFFFFFFF000ULL
#define HV_NESTED_ROOT_PTE_FLAGS    (HV_NESTED_ROOT_PTE_PRESENT | \
                                     HV_NESTED_ROOT_PTE_RW | \
                                     HV_NESTED_ROOT_PTE_GLOBAL | \
                                     HV_NESTED_ROOT_PTE_NX)

static __forceinline VOID
HvNestedRootRedirectScratch(
    _Inout_ PVCPU_DATA VcpuData,
    _In_ ULONG64 PhysicalPage)
{
    ULONG64 entry = (PhysicalPage & HV_NESTED_ROOT_PTE_MASK) |
                    HV_NESTED_ROOT_PTE_FLAGS;
    InterlockedExchange64(
        (volatile LONG64*)VcpuData->VtRootGadget.ScratchPtePtr,
        (LONG64)entry);
    __invlpg(VcpuData->VtRootGadget.ScratchVa);
}

static __forceinline VOID
HvNestedRootRestoreScratch(_Inout_ PVCPU_DATA VcpuData)
{
    HvNestedRootRedirectScratch(
        VcpuData,
        VcpuData->VtRootGadget.BackingPagePa);
}

static BOOLEAN
HvNestedRootCopyPhysical(
    _Inout_ PVCPU_DATA VcpuData,
    _In_ ULONG64 PhysicalAddress,
    _Inout_updates_bytes_(Size) PVOID Buffer,
    _In_ SIZE_T Size,
    _In_ BOOLEAN WriteToPhysical)
{
    PUCHAR bytes = (PUCHAR)Buffer;
    SIZE_T remaining = Size;

    if (!VcpuData || !Buffer || Size == 0 ||
        !g_VtRootEnabled ||
        !VcpuData->VtRootGadget.Initialized ||
        !VcpuData->VtRootGadget.ScratchVa ||
        !VcpuData->VtRootGadget.ScratchPtePtr ||
        PhysicalAddress > MAXULONG64 - ((ULONG64)Size - 1ULL)) {
        return FALSE;
    }

    while (remaining != 0) {
        ULONG64 pageBase = PhysicalAddress & HV_NESTED_ROOT_PTE_MASK;
        SIZE_T pageOffset = (SIZE_T)(PhysicalAddress & (PAGE_SIZE - 1));
        SIZE_T chunk = PAGE_SIZE - pageOffset;
        PUCHAR scratch;

        if (chunk > remaining) chunk = remaining;
        if (!HvPhysIsRamRangeRootSafe(pageBase, PAGE_SIZE)) {
            HvNestedRootRestoreScratch(VcpuData);
            return FALSE;
        }

        HvNestedRootRedirectScratch(VcpuData, pageBase);
        scratch = (PUCHAR)VcpuData->VtRootGadget.ScratchVa + pageOffset;
        if (WriteToPhysical) {
            __movsb(scratch, bytes, chunk);
        } else {
            __movsb(bytes, scratch, chunk);
        }

        bytes += chunk;
        PhysicalAddress += chunk;
        remaining -= chunk;
    }

    HvNestedRootRestoreScratch(VcpuData);
    return TRUE;
}

// VMCS 字段编码到索引的映射表
static const struct {
    ULONG VmcsField;
    VMCS12_FIELD_INDEX Index;
} g_VmcsFieldMap[] = {
    // 控制字段
    { VMCS_CTRL_PIN_BASED_VM_EXECUTION_CONTROLS, VMCS12_PIN_BASED_CONTROLS },
    { VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, VMCS12_CPU_BASED_CONTROLS },
    { VMCS_CTRL_SECONDARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, VMCS12_SECONDARY_CONTROLS },
    { VMCS_CTRL_EXCEPTION_BITMAP, VMCS12_EXCEPTION_BITMAP },
    { VMCS_CTRL_VMEXIT_CONTROLS, VMCS12_EXIT_CONTROLS },
    { VMCS_CTRL_VMENTRY_CONTROLS, VMCS12_ENTRY_CONTROLS },
    { VMCS_CTRL_CR0_GUEST_HOST_MASK, VMCS12_CR0_GUEST_HOST_MASK },
    { VMCS_CTRL_CR4_GUEST_HOST_MASK, VMCS12_CR4_GUEST_HOST_MASK },
    { VMCS_CTRL_CR0_READ_SHADOW, VMCS12_CR0_READ_SHADOW },
    { VMCS_CTRL_CR4_READ_SHADOW, VMCS12_CR4_READ_SHADOW },
    { VMCS_CTRL_EPTP, VMCS12_EPTP },
    { VMCS_CTRL_MSR_BITMAP, VMCS12_MSR_BITMAP },
    { VMCS_CTRL_TSC_OFFSET, VMCS12_TSC_OFFSET },
    
    // Guest 状态字段
    { GUEST_CR0, VMCS12_GUEST_CR0 },
    { GUEST_CR3, VMCS12_GUEST_CR3 },
    { GUEST_CR4, VMCS12_GUEST_CR4 },
    { GUEST_DR7, VMCS12_GUEST_DR7 },
    { GUEST_RSP, VMCS12_GUEST_RSP },
    { GUEST_RIP, VMCS12_GUEST_RIP },
    { GUEST_RFLAGS, VMCS12_GUEST_RFLAGS },
    { GUEST_CS_SELECTOR, VMCS12_GUEST_CS_SELECTOR },
    { GUEST_CS_BASE, VMCS12_GUEST_CS_BASE },
    { GUEST_CS_LIMIT, VMCS12_GUEST_CS_LIMIT },
    { GUEST_CS_ACCESS_RIGHTS, VMCS12_GUEST_CS_ACCESS },
    { GUEST_SS_SELECTOR, VMCS12_GUEST_SS_SELECTOR },
    { GUEST_SS_BASE, VMCS12_GUEST_SS_BASE },
    { GUEST_SS_LIMIT, VMCS12_GUEST_SS_LIMIT },
    { GUEST_SS_ACCESS_RIGHTS, VMCS12_GUEST_SS_ACCESS },
    { GUEST_DS_SELECTOR, VMCS12_GUEST_DS_SELECTOR },
    { GUEST_DS_BASE, VMCS12_GUEST_DS_BASE },
    { GUEST_DS_LIMIT, VMCS12_GUEST_DS_LIMIT },
    { GUEST_DS_ACCESS_RIGHTS, VMCS12_GUEST_DS_ACCESS },
    { GUEST_ES_SELECTOR, VMCS12_GUEST_ES_SELECTOR },
    { GUEST_ES_BASE, VMCS12_GUEST_ES_BASE },
    { GUEST_ES_LIMIT, VMCS12_GUEST_ES_LIMIT },
    { GUEST_ES_ACCESS_RIGHTS, VMCS12_GUEST_ES_ACCESS },
    { GUEST_FS_SELECTOR, VMCS12_GUEST_FS_SELECTOR },
    { GUEST_FS_BASE, VMCS12_GUEST_FS_BASE },
    { GUEST_FS_LIMIT, VMCS12_GUEST_FS_LIMIT },
    { GUEST_FS_ACCESS_RIGHTS, VMCS12_GUEST_FS_ACCESS },
    { GUEST_GS_SELECTOR, VMCS12_GUEST_GS_SELECTOR },
    { GUEST_GS_BASE, VMCS12_GUEST_GS_BASE },
    { GUEST_GS_LIMIT, VMCS12_GUEST_GS_LIMIT },
    { GUEST_GS_ACCESS_RIGHTS, VMCS12_GUEST_GS_ACCESS },
    { GUEST_LDTR_SELECTOR, VMCS12_GUEST_LDTR_SELECTOR },
    { GUEST_LDTR_BASE, VMCS12_GUEST_LDTR_BASE },
    { GUEST_LDTR_LIMIT, VMCS12_GUEST_LDTR_LIMIT },
    { GUEST_LDTR_ACCESS_RIGHTS, VMCS12_GUEST_LDTR_ACCESS },
    { GUEST_TR_SELECTOR, VMCS12_GUEST_TR_SELECTOR },
    { GUEST_TR_BASE, VMCS12_GUEST_TR_BASE },
    { GUEST_TR_LIMIT, VMCS12_GUEST_TR_LIMIT },
    { GUEST_TR_ACCESS_RIGHTS, VMCS12_GUEST_TR_ACCESS },
    { GUEST_GDTR_BASE, VMCS12_GUEST_GDTR_BASE },
    { GUEST_GDTR_LIMIT, VMCS12_GUEST_GDTR_LIMIT },
    { GUEST_IDTR_BASE, VMCS12_GUEST_IDTR_BASE },
    { GUEST_IDTR_LIMIT, VMCS12_GUEST_IDTR_LIMIT },
    { GUEST_IA32_EFER, VMCS12_GUEST_EFER },
    { GUEST_IA32_PAT, VMCS12_GUEST_PAT },
    { GUEST_IA32_DEBUGCTL, VMCS12_GUEST_DEBUGCTL },
    { GUEST_IA32_SYSENTER_CS, VMCS12_GUEST_SYSENTER_CS },
    { GUEST_IA32_SYSENTER_ESP, VMCS12_GUEST_SYSENTER_ESP },
    { GUEST_IA32_SYSENTER_EIP, VMCS12_GUEST_SYSENTER_EIP },
    { GUEST_ACTIVITY_STATE, VMCS12_GUEST_ACTIVITY_STATE },
    { GUEST_INTERRUPTIBILITY_STATE, VMCS12_GUEST_INTERRUPTIBILITY },
    { GUEST_PENDING_DEBUG_EXCEPTIONS, VMCS12_GUEST_PENDING_DBG_EXCEPTIONS },
    { VMCS_LINK_POINTER, VMCS12_VMCS_LINK_POINTER },
    
    // Host 状态字段
    { HOST_CR0, VMCS12_HOST_CR0 },
    { HOST_CR3, VMCS12_HOST_CR3 },
    { HOST_CR4, VMCS12_HOST_CR4 },
    { HOST_RSP, VMCS12_HOST_RSP },
    { HOST_RIP, VMCS12_HOST_RIP },
    { HOST_CS_SELECTOR, VMCS12_HOST_CS_SELECTOR },
    { HOST_SS_SELECTOR, VMCS12_HOST_SS_SELECTOR },
    { HOST_DS_SELECTOR, VMCS12_HOST_DS_SELECTOR },
    { HOST_ES_SELECTOR, VMCS12_HOST_ES_SELECTOR },
    { HOST_FS_SELECTOR, VMCS12_HOST_FS_SELECTOR },
    { HOST_FS_BASE, VMCS12_HOST_FS_BASE },
    { HOST_GS_SELECTOR, VMCS12_HOST_GS_SELECTOR },
    { HOST_GS_BASE, VMCS12_HOST_GS_BASE },
    { HOST_TR_SELECTOR, VMCS12_HOST_TR_SELECTOR },
    { HOST_TR_BASE, VMCS12_HOST_TR_BASE },
    { HOST_GDTR_BASE, VMCS12_HOST_GDTR_BASE },
    { HOST_IDTR_BASE, VMCS12_HOST_IDTR_BASE },
    { HOST_IA32_EFER, VMCS12_HOST_EFER },
    { HOST_IA32_PAT, VMCS12_HOST_PAT },
    { HOST_IA32_SYSENTER_CS, VMCS12_HOST_SYSENTER_CS },
    { HOST_IA32_SYSENTER_ESP, VMCS12_HOST_SYSENTER_ESP },
    { HOST_IA32_SYSENTER_EIP, VMCS12_HOST_SYSENTER_EIP },
    
    // 退出信息
    { VM_EXIT_REASON, VMCS12_EXIT_REASON },
    { VM_EXIT_QUALIFICATION, VMCS12_EXIT_QUALIFICATION },
    { VM_EXIT_INTERRUPTION_INFO, VMCS12_EXIT_INTR_INFO },
    { VM_EXIT_INTERRUPTION_ERROR_CODE, VMCS12_EXIT_INTR_ERROR_CODE },
    { IDT_VECTORING_INFO, VMCS12_IDT_VECTORING_INFO },
    { IDT_VECTORING_ERROR_CODE, VMCS12_IDT_VECTORING_ERROR },
    { VM_EXIT_INSTRUCTION_LEN, VMCS12_EXIT_INSTRUCTION_LEN },
    { VM_EXIT_INSTRUCTION_INFO, VMCS12_EXIT_INSTRUCTION_INFO },
    { VMCS_GUEST_PHYSICAL_ADDRESS, VMCS12_GUEST_PHYSICAL_ADDRESS },
    { GUEST_LINEAR_ADDRESS, VMCS12_GUEST_LINEAR_ADDRESS },
    
    // 入口字段
    { VMCS_CTRL_VMENTRY_INTERRUPTION_INFO, VMCS12_ENTRY_INTR_INFO },
    { VMCS_CTRL_VMENTRY_EXCEPTION_ERROR_CODE, VMCS12_ENTRY_EXCEPTION_ERROR_CODE },
    { VMCS_CTRL_VMENTRY_INSTRUCTION_LENGTH, VMCS12_ENTRY_INSTRUCTION_LEN },
};

#define VMCS_FIELD_MAP_SIZE (sizeof(g_VmcsFieldMap) / sizeof(g_VmcsFieldMap[0]))

// ==================== 启用/禁用嵌套虚拟化 ====================

VOID HvNestedSetEnabled(BOOLEAN Enable)
{
#if HV_ENABLE_NESTED_VIRTUALIZATION
    HV_NESTED_LIFECYCLE_STATE state = HvNestedGetLifecycleState();

    if (Enable) {
        ULONG i;

        if (state != HvNestedStateReady || !g_VtRootEnabled ||
            !g_HypervisorContext.VcpuData ||
            g_HypervisorContext.ProcessorCount == 0) {
            g_EnableNestedVirtualization = FALSE;
            return;
        }

        for (i = 0; i < g_HypervisorContext.ProcessorCount; ++i) {
            PVCPU_DATA vcpu = &g_HypervisorContext.VcpuData[i];
            if (!vcpu->IsVirtualized || !vcpu->VtRootGadget.Initialized) {
                g_EnableNestedVirtualization = FALSE;
                return;
            }
        }

        InterlockedExchange(&g_NestedLifecycle, HvNestedStateRunning);
        _WriteBarrier();
        g_EnableNestedVirtualization = TRUE;
        HvNestedRecordEvent(NULL, HvNestedEventEnabled, 0, 0, 0);
        DbgPrint("[HV-NESTED] Nested virtualization enabled\n");
    } else {
        if (state == HvNestedStateRunning) {
            // Do not withdraw the VM-exit handlers from underneath an L2.
            // The explicit quiesce path will reflect every active L2 to L1,
            // then unpublish the execution gate.
            HvNestedBeginShutdown();
            return;
        }

        g_EnableNestedVirtualization = FALSE;
        _WriteBarrier();
        if (state == HvNestedStateQuiescing && HvNestedAllVcpusInL1()) {
            InterlockedExchange(&g_NestedLifecycle, HvNestedStateReady);
        }
        HvNestedRecordEvent(NULL, HvNestedEventDisabled, 0, 0, 0);
        DbgPrint("[HV-NESTED] Nested virtualization disabled\n");
    }
#else
    g_EnableNestedVirtualization = FALSE;
    UNREFERENCED_PARAMETER(Enable);
#endif
}

BOOLEAN HvNestedIsEnabled(VOID)
{
    return g_EnableNestedVirtualization &&
           HvNestedGetLifecycleState() == HvNestedStateRunning;
}

BOOLEAN HvNestedIsInitialized(VOID)
{
    HV_NESTED_LIFECYCLE_STATE state = HvNestedGetLifecycleState();
    return state == HvNestedStateReady ||
           state == HvNestedStateRunning ||
           state == HvNestedStateQuiescing;
}

BOOLEAN HvNestedIsQuiescing(VOID)
{
    return HvNestedGetLifecycleState() == HvNestedStateQuiescing;
}

BOOLEAN HvNestedCanEnterL2(VOID)
{
    return HvNestedIsEnabled();
}

BOOLEAN HvNestedIsVmxSupported(VOID)
{
#if HV_ENABLE_NESTED_VIRTUALIZATION
    ULONG i;

    if (HvGetCpuVendor() != CPU_VENDOR_INTEL ||
        !g_VtRootEnabled ||
        !g_HypervisorContext.VcpuData ||
        g_HypervisorContext.ProcessorCount == 0) {
        return FALSE;
    }

    for (i = 0; i < g_HypervisorContext.ProcessorCount; ++i) {
        PVCPU_DATA vcpu = &g_HypervisorContext.VcpuData[i];
        if (!vcpu->IsVirtualized || !vcpu->EptTables ||
            !vcpu->VtRootGadget.Initialized) {
            return FALSE;
        }
    }
    return TRUE;
#else
    return FALSE;
#endif
}

BOOLEAN HvNestedIsSvmSupported(VOID)
{
#if HV_ENABLE_NESTED_VIRTUALIZATION
    ULONG i;

    if (HvGetCpuVendor() != CPU_VENDOR_AMD ||
        !g_VtRootEnabled ||
        !g_HypervisorContext.VcpuData ||
        g_HypervisorContext.ProcessorCount == 0) {
        return FALSE;
    }

    for (i = 0; i < g_HypervisorContext.ProcessorCount; ++i) {
        PVCPU_DATA vcpu = &g_HypervisorContext.VcpuData[i];
        if (!vcpu->IsVirtualized || !vcpu->NptTables ||
            !vcpu->VtRootGadget.Initialized) {
            return FALSE;
        }
    }
    return TRUE;
#else
    return FALSE;
#endif
}

HV_NESTED_LIFECYCLE_STATE HvNestedGetLifecycleState(VOID)
{
    return (HV_NESTED_LIFECYCLE_STATE)InterlockedCompareExchange(
        &g_NestedLifecycle, 0, 0);
}

VOID HvNestedBeginShutdown(VOID)
{
    LONG state = InterlockedCompareExchange(
        &g_NestedLifecycle, HvNestedStateQuiescing, HvNestedStateRunning);

    if (state == HvNestedStateRunning) {
        // Keep the execution gate published while an existing L2 is reflected
        // back to L1.  HvNestedCanEnterL2() is false while quiescing, so no new
        // nested entry can be committed.
        HvNestedRecordEvent(NULL, HvNestedEventQuiesceBegin, 0, 0, 0);
    }
}

NTSTATUS HvNestedQuiesce(VOID)
{
    HV_NESTED_LIFECYCLE_STATE state = HvNestedGetLifecycleState();

    if (state == HvNestedStateUninitialized || state == HvNestedStateReady) {
        g_EnableNestedVirtualization = FALSE;
        return STATUS_SUCCESS;
    }
    if (state == HvNestedStateInitializing) {
        return STATUS_DEVICE_BUSY;
    }

    HvNestedBeginShutdown();

    if (KeGetCurrentIrql() > DISPATCH_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    // The IPI forces every logical processor out of L2.  The quiescing checks
    // in both VMX and SVM dispatch reflect that exit to L1 before this callback
    // is delivered, so KeIpiGenericCall returning is a full nested rundown.
    KeIpiGenericCall(HvNestedQuiesceIpiCallback, 0);
    if (!HvNestedAllVcpusInL1()) {
        return STATUS_DEVICE_BUSY;
    }

    g_EnableNestedVirtualization = FALSE;
    _WriteBarrier();
    InterlockedExchange(&g_NestedLifecycle, HvNestedStateReady);
    HvNestedRecordEvent(NULL, HvNestedEventQuiesceComplete, 0, 0, 0);
    HvNestedRecordEvent(NULL, HvNestedEventDisabled, 0, 0, 0);
    return STATUS_SUCCESS;
}

BOOLEAN HvNestedAllVcpusInL1(VOID)
{
    ULONG i;

    if (!g_HypervisorContext.VcpuData) return TRUE;
    for (i = 0; i < g_HypervisorContext.ProcessorCount; ++i) {
        if (g_HypervisorContext.VcpuData[i].IsInL2) return FALSE;
    }
    return TRUE;
}

VOID HvNestedRecordEvent(
    _In_opt_ PVCPU_DATA VcpuData,
    _In_ HV_NESTED_EVENT_TYPE Type,
    _In_ UINT64 Code,
    _In_ UINT64 Information1,
    _In_ UINT64 Information2)
{
    LONG64 sequence = InterlockedIncrement64(&g_NestedEventWriteSequence) - 1;
    PHV_NESTED_EVENT_SLOT slot =
        &g_NestedEventRing[(ULONG64)sequence & (HV_NESTED_EVENT_CAPACITY - 1)];

    slot->Event.Sequence = (UINT64)sequence;
    slot->Event.Tsc = __rdtsc();
    slot->Event.ProcessorNumber = VcpuData ? VcpuData->ProcessorNumber : MAXULONG;
    slot->Event.Type = (ULONG)Type;
    slot->Event.Code = Code;
    slot->Event.Information1 = Information1;
    slot->Event.Information2 = Information2;
    _WriteBarrier();
    InterlockedExchange64(&slot->PublishedSequence, sequence);
}

NTSTATUS HvNestedQueryEvents(
    _Out_writes_bytes_(OutputLength) PVOID OutputBuffer,
    _In_ ULONG OutputLength,
    _Out_ PULONG BytesWritten)
{
    const ULONG headerSize = FIELD_OFFSET(HV_NESTED_EVENT_BATCH, Events);
    PHV_NESTED_EVENT_BATCH batch = (PHV_NESTED_EVENT_BATCH)OutputBuffer;
    ULONG outputCapacity;
    LONG64 writeSequence;
    LONG64 clearSequence;
    LONG64 retainedStart;
    LONG64 startSequence;
    ULONG wanted;
    ULONG copied = 0;

    if (BytesWritten) *BytesWritten = 0;
    if (!OutputBuffer || !BytesWritten || OutputLength < headerSize) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    outputCapacity = (OutputLength - headerSize) / sizeof(HV_NESTED_EVENT);
    writeSequence = InterlockedCompareExchange64(
        &g_NestedEventWriteSequence, 0, 0);
    clearSequence = InterlockedCompareExchange64(
        &g_NestedEventClearSequence, 0, 0);
    retainedStart = writeSequence > HV_NESTED_EVENT_CAPACITY
        ? writeSequence - HV_NESTED_EVENT_CAPACITY
        : 0;
    startSequence = clearSequence > retainedStart ? clearSequence : retainedStart;
    wanted = (ULONG)(writeSequence - startSequence);
    if (wanted > outputCapacity) {
        startSequence = writeSequence - outputCapacity;
        wanted = outputCapacity;
    }

    RtlZeroMemory(batch, headerSize);
    batch->Version = HV_NESTED_EVENT_VERSION;
    batch->EventSize = sizeof(HV_NESTED_EVENT);
    batch->Capacity = HV_NESTED_EVENT_CAPACITY;
    batch->FirstSequence = (UINT64)startSequence;
    batch->NextSequence = (UINT64)writeSequence;
    batch->LostEvents = clearSequence < retainedStart
        ? (UINT64)(retainedStart - clearSequence)
        : 0;

    for (ULONG i = 0; i < wanted; ++i) {
        LONG64 sequence = startSequence + i;
        PHV_NESTED_EVENT_SLOT slot =
            &g_NestedEventRing[(ULONG64)sequence & (HV_NESTED_EVENT_CAPACITY - 1)];
        LONG64 publishedBefore = InterlockedCompareExchange64(
            &slot->PublishedSequence, 0, 0);
        HV_NESTED_EVENT event;
        LONG64 publishedAfter;

        if (publishedBefore != sequence) continue;
        event = slot->Event;
        _ReadBarrier();
        publishedAfter = InterlockedCompareExchange64(
            &slot->PublishedSequence, 0, 0);
        if (publishedAfter != sequence || event.Sequence != (UINT64)sequence) {
            continue;
        }
        batch->Events[copied++] = event;
    }

    batch->Count = copied;
    *BytesWritten = headerSize + copied * sizeof(HV_NESTED_EVENT);
    return STATUS_SUCCESS;
}

VOID HvNestedClearEvents(VOID)
{
    LONG64 writeSequence = InterlockedCompareExchange64(
        &g_NestedEventWriteSequence, 0, 0);
    InterlockedExchange64(&g_NestedEventClearSequence, writeSequence);
}

BOOLEAN HvNestedRootReadPhysical(
    _Inout_ PVCPU_DATA VcpuData,
    _In_ ULONG64 PhysicalAddress,
    _Out_writes_bytes_(Size) PVOID Buffer,
    _In_ SIZE_T Size)
{
    return HvNestedRootCopyPhysical(
        VcpuData, PhysicalAddress, Buffer, Size, FALSE);
}

BOOLEAN HvNestedRootWritePhysical(
    _Inout_ PVCPU_DATA VcpuData,
    _In_ ULONG64 PhysicalAddress,
    _In_reads_bytes_(Size) const VOID* Buffer,
    _In_ SIZE_T Size)
{
    return HvNestedRootCopyPhysical(
        VcpuData, PhysicalAddress, (PVOID)Buffer, Size, TRUE);
}

// ==================== VCPU 辅助函数 ====================

PVCPU_DATA HvNestedGetCurrentVcpu(VOID)
{
    // Step 3 (虚幻范式): 优先用 HOST_FS_BASE 直接拿到 vcpu 指针.
    // VMCS 在 HvSetupVmcsHostState 里把 HOST_FS_BASE 写成了当前 vcpu 的指针,
    // host 路径 (VM-Exit 之后) RDMSR(IA32_FS_BASE) 直接返回 vcpu*.
    //
    // 用 RDMSR 而非 _readfsbase_u64 intrinsic — 后者需 CR4.FSGSBASE=1 才能执行,
    // 不是所有 host 上下文都保证, RDMSR 永远可用.
    //
    // 校验: 拿到的指针必须落在 g_HypervisorContext.VcpuData[0..ProcessorCount) 范围内.
    // 落在范围外 = guest 路径调的 (此时 FS_BASE 是 Windows kernel FS) 或还没 vmlaunch,
    // 退回老 KPCR 路径.
    ULONG64 fsBase = __readmsr(0xC0000100);  // MSR_IA32_FS_BASE
    if (g_HypervisorContext.VcpuData &&
        g_HypervisorContext.ProcessorCount > 0)
    {
        ULONG64 base = (ULONG64)g_HypervisorContext.VcpuData;
        ULONG64 end  = base + (ULONG64)g_HypervisorContext.ProcessorCount * sizeof(VCPU_DATA);
        if (fsBase >= base && fsBase < end &&
            ((fsBase - base) % sizeof(VCPU_DATA)) == 0)
        {
            return (PVCPU_DATA)fsBase;
        }
    }

    // Fallback: 老路径 (PASSIVE / 未启用 VMX / KPCR 可靠时)
    // VM-exit/root callers must never fall back through KPCR/Ke* services.
    // An invalid HOST_FS_BASE means that the per-VCPU root identity is not
    // trustworthy, so fail closed.
    return NULL;
}

BOOLEAN HvNestedIsInL2(PVCPU_DATA VcpuData)
{
    return VcpuData && VcpuData->IsInL2;
}

// ==================== VMX 失败处理 ====================

VOID HvNestedSetVmxSuccess(PGUEST_CONTEXT GuestContext)
{
    SIZE_T rflags;
    __vmx_vmread(GUEST_RFLAGS, &rflags);
    // 清除 CF 和 ZF
    rflags &= ~((SIZE_T)0x41); // CF=bit0, ZF=bit6
    __vmx_vmwrite(GUEST_RFLAGS, rflags);
}

VOID HvNestedSetVmxFailInvalid(PGUEST_CONTEXT GuestContext)
{
    SIZE_T rflags;
    __vmx_vmread(GUEST_RFLAGS, &rflags);
    // 设置 CF=1, 清除 ZF
    rflags |= 1;      // CF=1
    rflags &= ~0x40;  // ZF=0
    __vmx_vmwrite(GUEST_RFLAGS, rflags);
}

VOID HvNestedSetVmxFailValid(PVCPU_DATA VcpuData, PGUEST_CONTEXT GuestContext, ULONG ErrorNumber)
{
    SIZE_T rflags;
    __vmx_vmread(GUEST_RFLAGS, &rflags);
    // 设置 ZF=1, 清除 CF
    rflags &= ~1;     // CF=0
    rflags |= 0x40;   // ZF=1
    __vmx_vmwrite(GUEST_RFLAGS, rflags);
    
    // 在 VMCS12 中存储错误码
    if (VcpuData->NestedVmx.Vmcs12Valid) {
        VcpuData->NestedVmx.Vmcs12[VMCS12_EXIT_REASON] = ErrorNumber;
    }
}

// ==================== VMCS 字段操作 ====================

VMCS12_FIELD_INDEX HvNestedVmcsFieldToIndex(ULONG VmcsField)
{
    for (ULONG i = 0; i < VMCS_FIELD_MAP_SIZE; i++) {
        if (g_VmcsFieldMap[i].VmcsField == VmcsField) {
            return g_VmcsFieldMap[i].Index;
        }
    }
    return VMCS12_FIELD_MAX; // 无效索引
}

ULONG HvNestedIndexToVmcsField(VMCS12_FIELD_INDEX Index)
{
    for (ULONG i = 0; i < VMCS_FIELD_MAP_SIZE; i++) {
        if (g_VmcsFieldMap[i].Index == Index) {
            return g_VmcsFieldMap[i].VmcsField;
        }
    }
    return 0; // 无效
}

ULONG64 HvNestedVmcs12Read(PVCPU_DATA VcpuData, VMCS12_FIELD_INDEX Index)
{
    if (Index < VMCS12_FIELD_MAX) {
        return VcpuData->NestedVmx.Vmcs12[Index];
    }
    return 0;
}

VOID HvNestedVmcs12Write(PVCPU_DATA VcpuData, VMCS12_FIELD_INDEX Index, ULONG64 Value)
{
    if (Index < VMCS12_FIELD_MAX) {
        VcpuData->NestedVmx.Vmcs12[Index] = Value;
    }
}

// ==================== 先决条件检查 ====================

BOOLEAN HvNestedCheckVmxonPreconditions(PVCPU_DATA VcpuData, PGUEST_CONTEXT GuestContext)
{
    SIZE_T cr0, cr4;
    
    // 检查 L1 是否已经在 VMX 操作中
    if (VcpuData->NestedVmx.VmxEnabled) {
        return FALSE; // VMXON 在 VMX 操作中是无效的
    }
    
    // 检查 CR0.PE 和 CR0.NE
    __vmx_vmread(GUEST_CR0, &cr0);
    if (!(cr0 & 1) || !(cr0 & (1 << 5))) {
        return FALSE; // PE=0 或 NE=0
    }
    
    // 检查 CR4.VMXE
    __vmx_vmread(GUEST_CR4, &cr4);
    if (!(cr4 & (1 << 13))) {
        return FALSE; // VMXE=0
    }
    
    // 检查 CPL（必须为 0）
    SIZE_T csAccess;
    __vmx_vmread(GUEST_CS_ACCESS_RIGHTS, &csAccess);
    ULONG dpl = (csAccess >> 5) & 3;
    if (dpl != 0) {
        return FALSE;
    }
    
    return TRUE;
}

BOOLEAN HvNestedCheckVmxPreconditions(PVCPU_DATA VcpuData, PGUEST_CONTEXT GuestContext)
{
    // 检查 L1 是否已执行 VMXON
    if (!VcpuData->NestedVmx.VmxEnabled) {
        return FALSE;
    }
    
    // 检查 CPL
    SIZE_T csAccess;
    __vmx_vmread(GUEST_CS_ACCESS_RIGHTS, &csAccess);
    ULONG dpl = (csAccess >> 5) & 3;
    if (dpl != 0) {
        return FALSE;
    }
    
    return TRUE;
}

BOOLEAN HvNestedCheckVmcsLoaded(PVCPU_DATA VcpuData)
{
    return VcpuData->NestedVmx.CurrentVmcsGpa != 0 && 
           VcpuData->NestedVmx.Vmcs12Valid;
}

// ==================== 内存操作数解析 ====================

ULONG64 HvNestedGetMemoryOperand(PVCPU_DATA VcpuData, PGUEST_CONTEXT GuestContext)
{
    SIZE_T qualification;
    SIZE_T displacement;
    SIZE_T instrInfo;
    ULONG64 effectiveAddress = 0;
    
    __vmx_vmread(VM_EXIT_QUALIFICATION, &qualification);
    __vmx_vmread(VM_EXIT_INSTRUCTION_INFO, &instrInfo);
    
    // 解析 VM-exit instruction information
    // 位 [2:0] = scaling
    // 位 [9:7] = address size
    // 位 [17:15] = segment register
    // 位 [21:18] = index register
    // 位 [22] = index register invalid
    // 位 [27:23] = base register
    // 位 [28] = base register invalid
    
    ULONG scaling = instrInfo & 0x3;
    ULONG indexReg = (instrInfo >> 18) & 0xF;
    BOOLEAN indexInvalid = (instrInfo >> 22) & 1;
    ULONG baseReg = (instrInfo >> 23) & 0xF;
    BOOLEAN baseInvalid = (instrInfo >> 28) & 1;
    
    // Qualification 包含位移
    displacement = qualification;
    
    // 计算有效地址
    effectiveAddress = displacement;
    
    if (!baseInvalid) {
        ULONG64 baseValue = 0;
        // 获取基址寄存器值
        switch (baseReg) {
            case 0: baseValue = GuestContext->Rax; break;
            case 1: baseValue = GuestContext->Rcx; break;
            case 2: baseValue = GuestContext->Rdx; break;
            case 3: baseValue = GuestContext->Rbx; break;
            case 4: __vmx_vmread(GUEST_RSP, (SIZE_T*)&baseValue); break;
            case 5: baseValue = GuestContext->Rbp; break;
            case 6: baseValue = GuestContext->Rsi; break;
            case 7: baseValue = GuestContext->Rdi; break;
            case 8: baseValue = GuestContext->R8; break;
            case 9: baseValue = GuestContext->R9; break;
            case 10: baseValue = GuestContext->R10; break;
            case 11: baseValue = GuestContext->R11; break;
            case 12: baseValue = GuestContext->R12; break;
            case 13: baseValue = GuestContext->R13; break;
            case 14: baseValue = GuestContext->R14; break;
            case 15: baseValue = GuestContext->R15; break;
        }
        effectiveAddress += baseValue;
    }
    
    if (!indexInvalid) {
        ULONG64 indexValue = 0;
        // 获取索引寄存器值
        switch (indexReg) {
            case 0: indexValue = GuestContext->Rax; break;
            case 1: indexValue = GuestContext->Rcx; break;
            case 2: indexValue = GuestContext->Rdx; break;
            case 3: indexValue = GuestContext->Rbx; break;
            case 4: break; // RSP 不能作为索引
            case 5: indexValue = GuestContext->Rbp; break;
            case 6: indexValue = GuestContext->Rsi; break;
            case 7: indexValue = GuestContext->Rdi; break;
            case 8: indexValue = GuestContext->R8; break;
            case 9: indexValue = GuestContext->R9; break;
            case 10: indexValue = GuestContext->R10; break;
            case 11: indexValue = GuestContext->R11; break;
            case 12: indexValue = GuestContext->R12; break;
            case 13: indexValue = GuestContext->R13; break;
            case 14: indexValue = GuestContext->R14; break;
            case 15: indexValue = GuestContext->R15; break;
        }
        effectiveAddress += indexValue << scaling;
    }
    
    return effectiveAddress;
}

// ==================== VMX 指令处理器 ====================

BOOLEAN HvNestedHandleVmxon(PVCPU_DATA VcpuData, PGUEST_CONTEXT GuestContext)
{
    ULONG64 vmxonRegionGpa;
    
    // 检查先决条件
    if (!HvNestedCheckVmxonPreconditions(VcpuData, GuestContext)) {
        HvNestedSetVmxFailInvalid(GuestContext);
        return TRUE;
    }
    
    // 获取 VMXON 区域地址
    vmxonRegionGpa = HvNestedGetMemoryOperand(VcpuData, GuestContext);
    
    // 验证地址对齐（4KB）
    if (vmxonRegionGpa & 0xFFF) {
        HvNestedSetVmxFailInvalid(GuestContext);
        return TRUE;
    }
    
    // 验证 VMXON 区域的 revision ID
    {
        ULONG vmxonRevisionId = 0;
        ULONG expectedRevisionId;
        
        // 从 L1 内存读取 VMXON 区域的 revision ID（前 4 字节）
        if (!HvNestedReadL1Memory(VcpuData, vmxonRegionGpa, &vmxonRevisionId, sizeof(ULONG))) {
            DbgPrint("[HV-NESTED] Failed to read VMXON region at GPA 0x%llx\n", vmxonRegionGpa);
            HvNestedSetVmxFailInvalid(GuestContext);
            return TRUE;
        }
        
        // 清除 bit 31（shadow VMCS 标志）
        vmxonRevisionId &= ~(1UL << 31);
        
        // 获取期望的 revision ID（从 IA32_VMX_BASIC MSR）
        expectedRevisionId = (ULONG)(__readmsr(MSR_IA32_VMX_BASIC) & 0x7FFFFFFF);
        
        if (vmxonRevisionId != expectedRevisionId) {
            DbgPrint("[HV-NESTED] VMXON revision ID mismatch: got 0x%x, expected 0x%x\n",
                vmxonRevisionId, expectedRevisionId);
            HvNestedSetVmxFailInvalid(GuestContext);
            return TRUE;
        }
    }
    
    // 初始化嵌套 VMX 状态
    VcpuData->NestedVmx.VmxEnabled = TRUE;
    VcpuData->NestedVmx.VmxonRegionGpa = vmxonRegionGpa;
    VcpuData->NestedVmx.CurrentVmcsGpa = 0;
    VcpuData->NestedVmx.VmcsState = VMCS_STATE_CLEAR;
    VcpuData->NestedVmx.Vmcs12Valid = FALSE;
    RtlZeroMemory(VcpuData->NestedVmx.Vmcs12, sizeof(VcpuData->NestedVmx.Vmcs12));
    
    InterlockedIncrement64(&g_NestedVmxonCount);
    HvNestedRecordEvent(
        VcpuData, HvNestedEventVmxon, 0, vmxonRegionGpa, 0);
    
    HvNestedSetVmxSuccess(GuestContext);
    return TRUE;
}

BOOLEAN HvNestedHandleVmxoff(PVCPU_DATA VcpuData, PGUEST_CONTEXT GuestContext)
{
    if (!HvNestedCheckVmxPreconditions(VcpuData, GuestContext)) {
        HvNestedSetVmxFailInvalid(GuestContext);
        return TRUE;
    }
    
    // 清理嵌套 VMX 状态
    VcpuData->NestedVmx.VmxEnabled = FALSE;
    VcpuData->NestedVmx.VmxonRegionGpa = 0;
    VcpuData->NestedVmx.CurrentVmcsGpa = 0;
    VcpuData->NestedVmx.VmcsState = VMCS_STATE_CLEAR;
    VcpuData->NestedVmx.Vmcs12Valid = FALSE;
    
    // 清理嵌套 EPT
    if (VcpuData->NestedVmx.NestedEptTables) {
        HvNestedCleanupEpt(VcpuData);
    }
    
    HvNestedSetVmxSuccess(GuestContext);
    return TRUE;
}

BOOLEAN HvNestedHandleVmclear(PVCPU_DATA VcpuData, PGUEST_CONTEXT GuestContext)
{
    ULONG64 vmcsGpa;
    
    if (!HvNestedCheckVmxPreconditions(VcpuData, GuestContext)) {
        HvNestedSetVmxFailInvalid(GuestContext);
        return TRUE;
    }
    
    vmcsGpa = HvNestedGetMemoryOperand(VcpuData, GuestContext);
    
    // 验证地址
    if (vmcsGpa & 0xFFF) {
        HvNestedSetVmxFailValid(VcpuData, GuestContext, VMXERR_VMCLEAR_INVALID_ADDRESS);
        return TRUE;
    }
    
    // 不能 VMCLEAR VMXON 区域
    if (vmcsGpa == VcpuData->NestedVmx.VmxonRegionGpa) {
        HvNestedSetVmxFailValid(VcpuData, GuestContext, VMXERR_VMCLEAR_WITH_VMXON);
        return TRUE;
    }
    
    // 如果 VMCLEAR 的是当前 VMCS，清除当前状态
    if (vmcsGpa == VcpuData->NestedVmx.CurrentVmcsGpa) {
        // 将 VMCS12 数据写回 L1 内存
        // 根据 Intel 手册，VMCLEAR 会将 VMCS 数据同步到内存
        // VMCS 区域的前 4 字节是 revision ID，我们只需要保留它
        // 之后是 VMX abort indicator（4 字节）
        // VMCS 数据从偏移 8 开始
        
        // 写入 VMCS12 数据到 L1 内存（从偏移 8 开始）
        if (VcpuData->NestedVmx.Vmcs12Valid) {
            HvNestedWriteL1Memory(VcpuData, vmcsGpa + 8, 
                VcpuData->NestedVmx.Vmcs12, 
                sizeof(VcpuData->NestedVmx.Vmcs12));
        }
        
        VcpuData->NestedVmx.CurrentVmcsGpa = 0;
        VcpuData->NestedVmx.Vmcs12Valid = FALSE;
    }
    
    VcpuData->NestedVmx.VmcsState = VMCS_STATE_CLEAR;
    
    HvNestedSetVmxSuccess(GuestContext);
    return TRUE;
}

BOOLEAN HvNestedHandleVmptrld(PVCPU_DATA VcpuData, PGUEST_CONTEXT GuestContext)
{
    ULONG64 vmcsGpa;
    
    if (!HvNestedCheckVmxPreconditions(VcpuData, GuestContext)) {
        HvNestedSetVmxFailInvalid(GuestContext);
        return TRUE;
    }
    
    vmcsGpa = HvNestedGetMemoryOperand(VcpuData, GuestContext);
    
    // 验证地址
    if (vmcsGpa & 0xFFF) {
        HvNestedSetVmxFailValid(VcpuData, GuestContext, VMXERR_VMPTRLD_INVALID_ADDRESS);
        return TRUE;
    }
    
    // 不能加载 VMXON 区域
    if (vmcsGpa == VcpuData->NestedVmx.VmxonRegionGpa) {
        HvNestedSetVmxFailValid(VcpuData, GuestContext, VMXERR_VMPTRLD_WITH_VMXON);
        return TRUE;
    }
    
    // 从 L1 内存读取 VMCS 数据并验证 revision ID
    {
        ULONG vmcsRevisionId = 0;
        ULONG expectedRevisionId;
        
        // 读取 VMCS 区域的 revision ID（前 4 字节）
        if (!HvNestedReadL1Memory(VcpuData, vmcsGpa, &vmcsRevisionId, sizeof(ULONG))) {
            DbgPrint("[HV-NESTED] Failed to read VMCS region at GPA 0x%llx\n", vmcsGpa);
            HvNestedSetVmxFailValid(VcpuData, GuestContext, VMXERR_VMPTRLD_INVALID_ADDRESS);
            return TRUE;
        }
        
        // 清除 bit 31（shadow VMCS 标志）- 暂不支持 shadow VMCS
        if (vmcsRevisionId & (1UL << 31)) {
            DbgPrint("[HV-NESTED] Shadow VMCS not supported\n");
            HvNestedSetVmxFailValid(VcpuData, GuestContext, VMXERR_VMPTRLD_INVALID_ADDRESS);
            return TRUE;
        }
        
        // 获取期望的 revision ID
        expectedRevisionId = (ULONG)(__readmsr(MSR_IA32_VMX_BASIC) & 0x7FFFFFFF);
        
        if (vmcsRevisionId != expectedRevisionId) {
            DbgPrint("[HV-NESTED] VMCS revision ID mismatch: got 0x%x, expected 0x%x\n",
                vmcsRevisionId, expectedRevisionId);
            HvNestedSetVmxFailValid(VcpuData, GuestContext, VMXERR_VMPTRLD_INVALID_ADDRESS);
            return TRUE;
        }
        
        // 从 L1 内存读取 VMCS12 数据（从偏移 8 开始）
        // 只有当加载不同的 VMCS 时才读取
        if (vmcsGpa != VcpuData->NestedVmx.CurrentVmcsGpa) {
            // 如果之前有活动的 VMCS，先保存它
            if (VcpuData->NestedVmx.Vmcs12Valid && VcpuData->NestedVmx.CurrentVmcsGpa != 0) {
                HvNestedWriteL1Memory(VcpuData, VcpuData->NestedVmx.CurrentVmcsGpa + 8,
                    VcpuData->NestedVmx.Vmcs12,
                    sizeof(VcpuData->NestedVmx.Vmcs12));
            }
            
            // 读取新 VMCS 的数据
            RtlZeroMemory(VcpuData->NestedVmx.Vmcs12, sizeof(VcpuData->NestedVmx.Vmcs12));
            HvNestedReadL1Memory(VcpuData, vmcsGpa + 8,
                VcpuData->NestedVmx.Vmcs12,
                sizeof(VcpuData->NestedVmx.Vmcs12));
        }
    }
    
    // 设置当前 VMCS
    VcpuData->NestedVmx.CurrentVmcsGpa = vmcsGpa;
    VcpuData->NestedVmx.VmcsState = VMCS_STATE_ACTIVE;
    VcpuData->NestedVmx.Vmcs12Valid = TRUE;
    
    HvNestedSetVmxSuccess(GuestContext);
    return TRUE;
}

BOOLEAN HvNestedHandleVmptrst(PVCPU_DATA VcpuData, PGUEST_CONTEXT GuestContext)
{
    ULONG64 destAddress;
    
    if (!HvNestedCheckVmxPreconditions(VcpuData, GuestContext)) {
        HvNestedSetVmxFailInvalid(GuestContext);
        return TRUE;
    }
    
    destAddress = HvNestedGetMemoryOperand(VcpuData, GuestContext);
    
    // 将当前 VMCS 指针写入 L1 内存
    {
        ULONG64 vmcsPtr = VcpuData->NestedVmx.CurrentVmcsGpa;
        if (!HvNestedWriteL1Memory(VcpuData, destAddress, &vmcsPtr, sizeof(ULONG64))) {
            DbgPrint("[HV-NESTED] Failed to write VMCS pointer to GPA 0x%llx\n", destAddress);
            // VMPTRST 不应该失败，但如果写入失败，继续执行
        }
    }
    
    HvNestedSetVmxSuccess(GuestContext);
    return TRUE;
}

BOOLEAN HvNestedHandleVmread(PVCPU_DATA VcpuData, PGUEST_CONTEXT GuestContext)
{
    SIZE_T qualification;
    ULONG vmcsField;
    VMCS12_FIELD_INDEX fieldIndex;
    ULONG64 value;
    
    if (!HvNestedCheckVmxPreconditions(VcpuData, GuestContext)) {
        HvNestedSetVmxFailInvalid(GuestContext);
        return TRUE;
    }
    
    if (!HvNestedCheckVmcsLoaded(VcpuData)) {
        HvNestedSetVmxFailValid(VcpuData, GuestContext, VMXERR_VMREAD_INVALID_COMPONENT);
        return TRUE;
    }
    
    // VMCS 字段编码在 qualification 中
    __vmx_vmread(VM_EXIT_QUALIFICATION, &qualification);
    
    // 获取 VMCS 字段（在 RCX 中）
    vmcsField = (ULONG)GuestContext->Rcx;
    
    fieldIndex = HvNestedVmcsFieldToIndex(vmcsField);
    if (fieldIndex == VMCS12_FIELD_MAX) {
        HvNestedSetVmxFailValid(VcpuData, GuestContext, VMXERR_VMREAD_INVALID_COMPONENT);
        return TRUE;
    }
    
    value = HvNestedVmcs12Read(VcpuData, fieldIndex);
    
    // 结果放入 RAX
    GuestContext->Rax = value;
    
    HvNestedSetVmxSuccess(GuestContext);
    return TRUE;
}

BOOLEAN HvNestedHandleVmwrite(PVCPU_DATA VcpuData, PGUEST_CONTEXT GuestContext)
{
    SIZE_T qualification;
    ULONG vmcsField;
    VMCS12_FIELD_INDEX fieldIndex;
    ULONG64 value;
    
    if (!HvNestedCheckVmxPreconditions(VcpuData, GuestContext)) {
        HvNestedSetVmxFailInvalid(GuestContext);
        return TRUE;
    }
    
    if (!HvNestedCheckVmcsLoaded(VcpuData)) {
        HvNestedSetVmxFailValid(VcpuData, GuestContext, VMXERR_VMWRITE_INVALID_COMPONENT);
        return TRUE;
    }
    
    __vmx_vmread(VM_EXIT_QUALIFICATION, &qualification);
    
    // VMCS 字段在 RCX 中，值在 RAX 中
    vmcsField = (ULONG)GuestContext->Rcx;
    value = GuestContext->Rax;
    
    fieldIndex = HvNestedVmcsFieldToIndex(vmcsField);
    if (fieldIndex == VMCS12_FIELD_MAX) {
        HvNestedSetVmxFailValid(VcpuData, GuestContext, VMXERR_VMWRITE_INVALID_COMPONENT);
        return TRUE;
    }
    
    // 检查只读字段
    // VMCS 字段编码格式: [15:14]=类型, [13]=宽度, [12:10]=索引类型, [9:1]=索引, [0]=访问类型
    // 类型 01b (bits 15:14) = 退出信息字段，这些是只读的
    {
        ULONG fieldType = (vmcsField >> 10) & 0x3;  // bits 11:10
        
        // 如果是 VM-exit information 字段 (type = 01b)，则为只读
        // 具体字段包括: EXIT_REASON, EXIT_QUALIFICATION, GUEST_LINEAR_ADDRESS,
        // GUEST_PHYSICAL_ADDRESS, VM_EXIT_INTERRUPTION_INFO, VM_EXIT_INTERRUPTION_ERROR_CODE,
        // IDT_VECTORING_INFO, IDT_VECTORING_ERROR_CODE, VM_EXIT_INSTRUCTION_LEN,
        // VM_EXIT_INSTRUCTION_INFO
        switch (vmcsField) {
        case VM_EXIT_REASON:
        case VM_EXIT_QUALIFICATION:
        case GUEST_LINEAR_ADDRESS:
        case VMCS_GUEST_PHYSICAL_ADDRESS:
        case VM_EXIT_INTERRUPTION_INFO:
        case VM_EXIT_INTERRUPTION_ERROR_CODE:
        case IDT_VECTORING_INFO:
        case IDT_VECTORING_ERROR_CODE:
        case VM_EXIT_INSTRUCTION_LEN:
        case VM_EXIT_INSTRUCTION_INFO:
            // 这些是只读字段，VMWRITE 应该失败
            HvNestedSetVmxFailValid(VcpuData, GuestContext, VMXERR_VMWRITE_READONLY);
            return TRUE;
        }
    }
    
    HvNestedVmcs12Write(VcpuData, fieldIndex, value);
    
    HvNestedSetVmxSuccess(GuestContext);
    return TRUE;
}

// ==================== VMCS12 验证 ====================

/*
 * 验证 VMCS12 配置是否有效
 * 
 * 根据 Intel SDM Volume 3C 检查 VMCS 一致性
 * 返回 TRUE 如果配置有效，FALSE 如果无效
 */
BOOLEAN HvNestedValidateVmcs12(PVCPU_DATA VcpuData)
{
    PNESTED_VMX_STATE nested = &VcpuData->NestedVmx;
    ULONG64 guestCr0, guestCr3, guestCr4;
    ULONG64 guestEfer;
    ULONG64 guestActivityState;
    ULONG64 pinControls, procControls, secondaryControls;
    ULONG64 exitControls, entryControls;
    ULONG64 csAccessRights, ssAccessRights;
    ULONG64 trAccessRights;
    
    if (!nested->Vmcs12Valid) {
        return FALSE;
    }
    
    // 读取 Guest 状态
    guestCr0 = nested->Vmcs12[VMCS12_GUEST_CR0];
    guestCr3 = nested->Vmcs12[VMCS12_GUEST_CR3];
    guestCr4 = nested->Vmcs12[VMCS12_GUEST_CR4];
    guestEfer = nested->Vmcs12[VMCS12_GUEST_EFER];
    guestActivityState = nested->Vmcs12[VMCS12_GUEST_ACTIVITY_STATE];
    
    // 读取控制字段
    pinControls = nested->Vmcs12[VMCS12_PIN_BASED_CONTROLS];
    procControls = nested->Vmcs12[VMCS12_CPU_BASED_CONTROLS];
    secondaryControls = nested->Vmcs12[VMCS12_SECONDARY_CONTROLS];
    exitControls = nested->Vmcs12[VMCS12_EXIT_CONTROLS];
    entryControls = nested->Vmcs12[VMCS12_ENTRY_CONTROLS];
    
    // ===== CR0 检查 =====
    // CR0.PE 和 CR0.PG 的组合约束
    // 如果 "unrestricted guest" 未启用，PE 必须为 1
    if (!(secondaryControls & (1ULL << 7))) {  // Unrestricted guest
        if (!(guestCr0 & 1)) {  // PE bit
            DbgPrint("[HV-NESTED] VMCS12 validation failed: CR0.PE must be 1 without unrestricted guest\n");
            return FALSE;
        }
        // 如果 CR0.PG=1，CR0.PE 必须为 1
        if ((guestCr0 & (1ULL << 31)) && !(guestCr0 & 1)) {
            DbgPrint("[HV-NESTED] VMCS12 validation failed: CR0.PE must be 1 if CR0.PG is 1\n");
            return FALSE;
        }
    }
    
    // CR0.NW 和 CR0.CD 约束：如果 CD=0，NW 必须为 0
    if (!(guestCr0 & (1ULL << 30)) && (guestCr0 & (1ULL << 29))) {
        DbgPrint("[HV-NESTED] VMCS12 validation failed: CR0.NW must be 0 if CR0.CD is 0\n");
        return FALSE;
    }
    
    // ===== CR4 检查 =====
    // 如果 CR0.PG=1 且启用 IA-32e mode guest，CR4.PAE 必须为 1
    if ((guestCr0 & (1ULL << 31)) && (entryControls & (1ULL << 9))) {  // IA-32e mode guest
        if (!(guestCr4 & (1ULL << 5))) {  // PAE
            DbgPrint("[HV-NESTED] VMCS12 validation failed: CR4.PAE must be 1 for IA-32e mode\n");
            return FALSE;
        }
    }
    
    // ===== EFER 检查 =====
    // 如果 IA-32e mode guest，EFER.LMA 和 EFER.LME 必须为 1
    if (entryControls & (1ULL << 9)) {  // IA-32e mode guest
        if (!(guestEfer & EFER_LMA) || !(guestEfer & EFER_LME)) {
            DbgPrint("[HV-NESTED] VMCS12 validation failed: EFER.LMA/LME must be 1 for IA-32e mode\n");
            return FALSE;
        }
    } else {
        // 如果不是 IA-32e mode guest
        if (guestCr0 & (1ULL << 31)) {  // CR0.PG=1
            if (guestEfer & EFER_LMA) {
                DbgPrint("[HV-NESTED] VMCS12 validation failed: EFER.LMA must be 0 if not IA-32e mode and CR0.PG=1\n");
                return FALSE;
            }
        }
    }
    
    // ===== Activity State 检查 =====
    // 值必须是 0-3 之间
    if (guestActivityState > 3) {
        DbgPrint("[HV-NESTED] VMCS12 validation failed: invalid activity state %llu\n", guestActivityState);
        return FALSE;
    }
    
    // ===== CS 访问权限检查 =====
    csAccessRights = nested->Vmcs12[VMCS12_GUEST_CS_ACCESS];
    // CS 必须是存在的（bit 7 = Present）
    if (!(csAccessRights & 0x80)) {
        // 除非是 unusable (bit 16)
        if (!(csAccessRights & 0x10000)) {
            DbgPrint("[HV-NESTED] VMCS12 validation failed: CS must be present or unusable\n");
            return FALSE;
        }
    }
    
    // ===== SS 访问权限检查 =====
    ssAccessRights = nested->Vmcs12[VMCS12_GUEST_SS_ACCESS];
    // 在 64 位模式下，SS 可以是 unusable
    // DPL 检查
    if (!(ssAccessRights & 0x10000)) {  // Not unusable
        // SS.DPL 必须等于 CS.DPL（在某些情况下）
        // 这里简化处理
    }
    
    // ===== TR 访问权限检查 =====
    trAccessRights = nested->Vmcs12[VMCS12_GUEST_TR_ACCESS];
    // TR 不能是 unusable
    if (trAccessRights & 0x10000) {
        DbgPrint("[HV-NESTED] VMCS12 validation failed: TR cannot be unusable\n");
        return FALSE;
    }
    // TR type 必须是 busy TSS (3 或 11)
    ULONG trType = (ULONG)(trAccessRights & 0xF);
    if (trType != 3 && trType != 11) {
        DbgPrint("[HV-NESTED] VMCS12 validation failed: TR type must be 3 or 11, got %u\n", trType);
        return FALSE;
    }
    
    // ===== Host 状态检查 =====
    // Host CR0 检查
    ULONG64 hostCr0 = nested->Vmcs12[VMCS12_HOST_CR0];
    if (!(hostCr0 & 1) || !(hostCr0 & (1ULL << 31))) {  // PE=1, PG=1
        DbgPrint("[HV-NESTED] VMCS12 validation failed: Host CR0.PE and CR0.PG must be 1\n");
        return FALSE;
    }
    
    // Host CR4.PAE 检查（64 位模式）
    ULONG64 hostCr4 = nested->Vmcs12[VMCS12_HOST_CR4];
    if (exitControls & (1ULL << 9)) {  // Host address-space size
        if (!(hostCr4 & (1ULL << 5))) {  // PAE
            DbgPrint("[HV-NESTED] VMCS12 validation failed: Host CR4.PAE must be 1 for 64-bit host\n");
            return FALSE;
        }
    }
    
    // Host EFER 检查
    ULONG64 hostEfer = nested->Vmcs12[VMCS12_HOST_EFER];
    if (exitControls & (1ULL << 9)) {  // Host address-space size
        if (!(hostEfer & EFER_LMA) || !(hostEfer & EFER_LME)) {
            DbgPrint("[HV-NESTED] VMCS12 validation failed: Host EFER.LMA/LME must be 1 for 64-bit host\n");
            return FALSE;
        }
    }
    
    // ===== 控制字段检查 =====
    // 某些控制位是保留位，必须为特定值
    // 这里简化处理，实际应该检查 MSR 获取的允许值
    
    DbgPrint("[HV-NESTED] VMCS12 validation passed\n");
    return TRUE;
}

// ==================== VMCS 合并 ====================

VOID HvNestedSaveL1State(PVCPU_DATA VcpuData)
{
    PNESTED_VMX_STATE nested = &VcpuData->NestedVmx;
    
    // 保存 L1 的基本寄存器状态
    __vmx_vmread(GUEST_RIP, (SIZE_T*)&nested->L1GuestRip);
    __vmx_vmread(GUEST_RSP, (SIZE_T*)&nested->L1GuestRsp);
    __vmx_vmread(GUEST_RFLAGS, (SIZE_T*)&nested->L1GuestRflags);
    __vmx_vmread(GUEST_CR0, (SIZE_T*)&nested->L1GuestCr0);
    __vmx_vmread(GUEST_CR3, (SIZE_T*)&nested->L1GuestCr3);
    __vmx_vmread(GUEST_CR4, (SIZE_T*)&nested->L1GuestCr4);
    __vmx_vmread(GUEST_IA32_EFER, (SIZE_T*)&nested->L1GuestEfer);
    __vmx_vmread(GUEST_DR7, (SIZE_T*)&nested->L1GuestDr7);
    
    // 保存 L1 的段寄存器
    __vmx_vmread(GUEST_CS_SELECTOR, (SIZE_T*)&nested->L1CsSelector);
    __vmx_vmread(GUEST_SS_SELECTOR, (SIZE_T*)&nested->L1SsSelector);
    __vmx_vmread(GUEST_DS_SELECTOR, (SIZE_T*)&nested->L1DsSelector);
    __vmx_vmread(GUEST_ES_SELECTOR, (SIZE_T*)&nested->L1EsSelector);
    __vmx_vmread(GUEST_FS_SELECTOR, (SIZE_T*)&nested->L1FsSelector);
    __vmx_vmread(GUEST_GS_SELECTOR, (SIZE_T*)&nested->L1GsSelector);
    __vmx_vmread(GUEST_TR_SELECTOR, (SIZE_T*)&nested->L1TrSelector);
    __vmx_vmread(GUEST_LDTR_SELECTOR, (SIZE_T*)&nested->L1LdtrSelector);
    
    __vmx_vmread(GUEST_CS_BASE, (SIZE_T*)&nested->L1CsBase);
    __vmx_vmread(GUEST_SS_BASE, (SIZE_T*)&nested->L1SsBase);
    __vmx_vmread(GUEST_DS_BASE, (SIZE_T*)&nested->L1DsBase);
    __vmx_vmread(GUEST_ES_BASE, (SIZE_T*)&nested->L1EsBase);
    __vmx_vmread(GUEST_FS_BASE, (SIZE_T*)&nested->L1FsBase);
    __vmx_vmread(GUEST_GS_BASE, (SIZE_T*)&nested->L1GsBase);
    __vmx_vmread(GUEST_TR_BASE, (SIZE_T*)&nested->L1TrBase);
    __vmx_vmread(GUEST_LDTR_BASE, (SIZE_T*)&nested->L1LdtrBase);
    __vmx_vmread(GUEST_GDTR_BASE, (SIZE_T*)&nested->L1GdtrBase);
    __vmx_vmread(GUEST_IDTR_BASE, (SIZE_T*)&nested->L1IdtrBase);
    
    __vmx_vmread(GUEST_CS_LIMIT, (SIZE_T*)&nested->L1CsLimit);
    __vmx_vmread(GUEST_SS_LIMIT, (SIZE_T*)&nested->L1SsLimit);
    __vmx_vmread(GUEST_DS_LIMIT, (SIZE_T*)&nested->L1DsLimit);
    __vmx_vmread(GUEST_ES_LIMIT, (SIZE_T*)&nested->L1EsLimit);
    __vmx_vmread(GUEST_FS_LIMIT, (SIZE_T*)&nested->L1FsLimit);
    __vmx_vmread(GUEST_GS_LIMIT, (SIZE_T*)&nested->L1GsLimit);
    __vmx_vmread(GUEST_TR_LIMIT, (SIZE_T*)&nested->L1TrLimit);
    __vmx_vmread(GUEST_LDTR_LIMIT, (SIZE_T*)&nested->L1LdtrLimit);
    __vmx_vmread(GUEST_GDTR_LIMIT, (SIZE_T*)&nested->L1GdtrLimit);
    __vmx_vmread(GUEST_IDTR_LIMIT, (SIZE_T*)&nested->L1IdtrLimit);
    
    __vmx_vmread(GUEST_CS_ACCESS_RIGHTS, (SIZE_T*)&nested->L1CsAccessRights);
    __vmx_vmread(GUEST_SS_ACCESS_RIGHTS, (SIZE_T*)&nested->L1SsAccessRights);
    __vmx_vmread(GUEST_DS_ACCESS_RIGHTS, (SIZE_T*)&nested->L1DsAccessRights);
    __vmx_vmread(GUEST_ES_ACCESS_RIGHTS, (SIZE_T*)&nested->L1EsAccessRights);
    __vmx_vmread(GUEST_FS_ACCESS_RIGHTS, (SIZE_T*)&nested->L1FsAccessRights);
    __vmx_vmread(GUEST_GS_ACCESS_RIGHTS, (SIZE_T*)&nested->L1GsAccessRights);
    __vmx_vmread(GUEST_TR_ACCESS_RIGHTS, (SIZE_T*)&nested->L1TrAccessRights);
    __vmx_vmread(GUEST_LDTR_ACCESS_RIGHTS, (SIZE_T*)&nested->L1LdtrAccessRights);
    
    // 保存 L1 的 SYSENTER
    __vmx_vmread(GUEST_IA32_SYSENTER_CS, (SIZE_T*)&nested->L1SysenterCs);
    __vmx_vmread(GUEST_IA32_SYSENTER_ESP, (SIZE_T*)&nested->L1SysenterEsp);
    __vmx_vmread(GUEST_IA32_SYSENTER_EIP, (SIZE_T*)&nested->L1SysenterEip);
    
    // 保存 L0 原始 VMCS 控制字段
    __vmx_vmread(VMCS_CTRL_PIN_BASED_VM_EXECUTION_CONTROLS, (SIZE_T*)&nested->SavedPinBasedControls);
    __vmx_vmread(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, (SIZE_T*)&nested->SavedProcBasedControls);
    __vmx_vmread(VMCS_CTRL_SECONDARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, (SIZE_T*)&nested->SavedSecondaryControls);
    __vmx_vmread(VMCS_CTRL_VMEXIT_CONTROLS, (SIZE_T*)&nested->SavedExitControls);
    __vmx_vmread(VMCS_CTRL_VMENTRY_CONTROLS, (SIZE_T*)&nested->SavedEntryControls);
    __vmx_vmread(VMCS_CTRL_EXCEPTION_BITMAP, (SIZE_T*)&nested->SavedExceptionBitmap);
    __vmx_vmread(VMCS_CTRL_EPTP, (SIZE_T*)&nested->SavedEptp);
    __vmx_vmread(VMCS_CTRL_TSC_OFFSET, (SIZE_T*)&nested->SavedTscOffset);
    __vmx_vmread(VMCS_CTRL_MSR_BITMAP, (SIZE_T*)&nested->SavedMsrBitmap);
}

VOID HvNestedRestoreL1State(PVCPU_DATA VcpuData)
{
    PNESTED_VMX_STATE nested = &VcpuData->NestedVmx;
    
    // 恢复 L1 的 Host 状态（来自 VMCS12）
    // 当 L2 退出时，L1 作为 Host 会恢复这些状态
    __vmx_vmwrite(GUEST_RIP, nested->Vmcs12[VMCS12_HOST_RIP]);
    __vmx_vmwrite(GUEST_RSP, nested->Vmcs12[VMCS12_HOST_RSP]);
    __vmx_vmwrite(GUEST_CR0, nested->Vmcs12[VMCS12_HOST_CR0]);
    __vmx_vmwrite(GUEST_CR3, nested->Vmcs12[VMCS12_HOST_CR3]);
    __vmx_vmwrite(GUEST_CR4, nested->Vmcs12[VMCS12_HOST_CR4]);
    
    // 恢复 L1 Host 段寄存器（选择子）
    __vmx_vmwrite(GUEST_CS_SELECTOR, nested->Vmcs12[VMCS12_HOST_CS_SELECTOR]);
    __vmx_vmwrite(GUEST_SS_SELECTOR, nested->Vmcs12[VMCS12_HOST_SS_SELECTOR]);
    __vmx_vmwrite(GUEST_DS_SELECTOR, nested->Vmcs12[VMCS12_HOST_DS_SELECTOR]);
    __vmx_vmwrite(GUEST_ES_SELECTOR, nested->Vmcs12[VMCS12_HOST_ES_SELECTOR]);
    __vmx_vmwrite(GUEST_FS_SELECTOR, nested->Vmcs12[VMCS12_HOST_FS_SELECTOR]);
    __vmx_vmwrite(GUEST_GS_SELECTOR, nested->Vmcs12[VMCS12_HOST_GS_SELECTOR]);
    __vmx_vmwrite(GUEST_TR_SELECTOR, nested->Vmcs12[VMCS12_HOST_TR_SELECTOR]);
    
    // 恢复 L1 Host 段基址
    __vmx_vmwrite(GUEST_FS_BASE, nested->Vmcs12[VMCS12_HOST_FS_BASE]);
    __vmx_vmwrite(GUEST_GS_BASE, nested->Vmcs12[VMCS12_HOST_GS_BASE]);
    __vmx_vmwrite(GUEST_TR_BASE, nested->Vmcs12[VMCS12_HOST_TR_BASE]);
    __vmx_vmwrite(GUEST_GDTR_BASE, nested->Vmcs12[VMCS12_HOST_GDTR_BASE]);
    __vmx_vmwrite(GUEST_IDTR_BASE, nested->Vmcs12[VMCS12_HOST_IDTR_BASE]);
    
    // 设置 Host 模式的段属性（代码段和数据段）
    // VMX Host 模式下，CS 是代码段，SS/DS/ES 是数据段
    __vmx_vmwrite(GUEST_CS_BASE, 0);
    __vmx_vmwrite(GUEST_SS_BASE, 0);
    __vmx_vmwrite(GUEST_DS_BASE, 0);
    __vmx_vmwrite(GUEST_ES_BASE, 0);
    
    // 设置默认的 64 位模式段限制和访问权限
    __vmx_vmwrite(GUEST_CS_LIMIT, 0xFFFFFFFF);
    __vmx_vmwrite(GUEST_SS_LIMIT,
        nested->Vmcs12[VMCS12_HOST_SS_SELECTOR] ? 0xFFFFFFFF : 0);
    __vmx_vmwrite(GUEST_DS_LIMIT,
        nested->Vmcs12[VMCS12_HOST_DS_SELECTOR] ? 0xFFFFFFFF : 0);
    __vmx_vmwrite(GUEST_ES_LIMIT,
        nested->Vmcs12[VMCS12_HOST_ES_SELECTOR] ? 0xFFFFFFFF : 0);
    __vmx_vmwrite(GUEST_FS_LIMIT,
        nested->Vmcs12[VMCS12_HOST_FS_SELECTOR] ? 0xFFFFFFFF : 0);
    __vmx_vmwrite(GUEST_GS_LIMIT,
        nested->Vmcs12[VMCS12_HOST_GS_SELECTOR] ? 0xFFFFFFFF : 0);
    
    // 代码段访问权限：可执行、可读、存在、64位模式
    __vmx_vmwrite(GUEST_CS_ACCESS_RIGHTS, 0xA09B);  // 64-bit code, P=1, S=1, Type=11 (exec/read)
    // 数据段访问权限：可读写、存在
    __vmx_vmwrite(GUEST_SS_ACCESS_RIGHTS,
        nested->Vmcs12[VMCS12_HOST_SS_SELECTOR] ? 0xC093 : 0x10000);
    __vmx_vmwrite(GUEST_DS_ACCESS_RIGHTS,
        nested->Vmcs12[VMCS12_HOST_DS_SELECTOR] ? 0xC093 : 0x10000);
    __vmx_vmwrite(GUEST_ES_ACCESS_RIGHTS,
        nested->Vmcs12[VMCS12_HOST_ES_SELECTOR] ? 0xC093 : 0x10000);
    __vmx_vmwrite(GUEST_FS_ACCESS_RIGHTS,
        nested->Vmcs12[VMCS12_HOST_FS_SELECTOR] ? 0xC093 : 0x10000);
    __vmx_vmwrite(GUEST_GS_ACCESS_RIGHTS,
        nested->Vmcs12[VMCS12_HOST_GS_SELECTOR] ? 0xC093 : 0x10000);

    __vmx_vmwrite(GUEST_TR_LIMIT, 0x67);
    __vmx_vmwrite(GUEST_TR_ACCESS_RIGHTS, 0x008B);
    __vmx_vmwrite(GUEST_LDTR_SELECTOR, 0);
    __vmx_vmwrite(GUEST_LDTR_BASE, 0);
    __vmx_vmwrite(GUEST_LDTR_LIMIT, 0);
    __vmx_vmwrite(GUEST_LDTR_ACCESS_RIGHTS, 0x10000);
    __vmx_vmwrite(GUEST_GDTR_LIMIT, 0xFFFF);
    __vmx_vmwrite(GUEST_IDTR_LIMIT, 0xFFFF);
    
    // 恢复 EFER 和 SYSENTER MSRs
    __vmx_vmwrite(GUEST_IA32_EFER, nested->Vmcs12[VMCS12_HOST_EFER]);
    __vmx_vmwrite(GUEST_IA32_PAT, nested->Vmcs12[VMCS12_HOST_PAT]);
    __vmx_vmwrite(GUEST_IA32_SYSENTER_CS, nested->Vmcs12[VMCS12_HOST_SYSENTER_CS]);
    __vmx_vmwrite(GUEST_IA32_SYSENTER_ESP, nested->Vmcs12[VMCS12_HOST_SYSENTER_ESP]);
    __vmx_vmwrite(GUEST_IA32_SYSENTER_EIP, nested->Vmcs12[VMCS12_HOST_SYSENTER_EIP]);
    
    // 设置 RFLAGS（Host 进入时通常为固定值）
    __vmx_vmwrite(GUEST_RFLAGS, 0x2);  // 仅 Reserved 位
    
    // 恢复 L0 的原始 VMCS 控制字段
    __vmx_vmwrite(GUEST_DR7, 0x400);
    __vmx_vmwrite(GUEST_ACTIVITY_STATE, 0);
    __vmx_vmwrite(GUEST_INTERRUPTIBILITY_STATE, 0);
    __vmx_vmwrite(GUEST_PENDING_DEBUG_EXCEPTIONS, 0);

    __vmx_vmwrite(VMCS_CTRL_PIN_BASED_VM_EXECUTION_CONTROLS, nested->SavedPinBasedControls);
    __vmx_vmwrite(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, nested->SavedProcBasedControls);
    __vmx_vmwrite(VMCS_CTRL_SECONDARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, nested->SavedSecondaryControls);
    __vmx_vmwrite(VMCS_CTRL_VMEXIT_CONTROLS, nested->SavedExitControls);
    __vmx_vmwrite(VMCS_CTRL_VMENTRY_CONTROLS, nested->SavedEntryControls);
    __vmx_vmwrite(VMCS_CTRL_EXCEPTION_BITMAP, nested->SavedExceptionBitmap);
    __vmx_vmwrite(VMCS_CTRL_EPTP, nested->SavedEptp);
    __vmx_vmwrite(VMCS_CTRL_TSC_OFFSET, nested->SavedTscOffset);
    __vmx_vmwrite(VMCS_CTRL_MSR_BITMAP, nested->SavedMsrBitmap);
    
    // 标记退出 L2
    VcpuData->IsInL2 = FALSE;
}

NTSTATUS HvNestedPrepareVmcs02(PVCPU_DATA VcpuData)
{
    PNESTED_VMX_STATE nested = &VcpuData->NestedVmx;
    SIZE_T l1PinBased, l1ProcBased, l1SecondaryProc, l1Exit, l1Entry;
    SIZE_T mergedPinBased, mergedProcBased, mergedSecondaryProc, mergedExit, mergedEntry;
    SIZE_T mergedExceptionBitmap;
    SIZE_T l1Eptp, mergedEptp;
    SIZE_T l1TscOffset, mergedTscOffset;
    SIZE_T tempValue;
    
    // 保存 L1 状态
    HvNestedSaveL1State(VcpuData);
    
    // ==================== 控制字段合并 ====================
    // L0 和 L1 控制字段的合并规则：
    // - 对于"设置为 1 表示启用拦截"的位，使用 OR（任一方要求拦截则拦截）
    // - 对于"设置为 0 表示启用拦截"的位，使用 AND
    // - 某些位必须由 L0 控制（如 EPT）
    
    // 读取 L1 的控制字段
    l1PinBased = nested->Vmcs12[VMCS12_PIN_BASED_CONTROLS];
    l1ProcBased = nested->Vmcs12[VMCS12_CPU_BASED_CONTROLS];
    l1SecondaryProc = nested->Vmcs12[VMCS12_SECONDARY_CONTROLS];
    l1Exit = nested->Vmcs12[VMCS12_EXIT_CONTROLS];
    l1Entry = nested->Vmcs12[VMCS12_ENTRY_CONTROLS];
    
    // Pin-Based Controls 合并（OR 合并）
    // L0 和 L1 的任何拦截请求都应该被满足
    mergedPinBased = nested->SavedPinBasedControls | l1PinBased;
    
    // Primary Processor-Based Controls 合并
    // 大部分位使用 OR 合并
    mergedProcBased = nested->SavedProcBasedControls | l1ProcBased;
    // 确保 "Activate secondary controls" 位被设置（如果 L0 使用 secondary controls）
    if (nested->SavedProcBasedControls & (1ULL << 31)) {
        mergedProcBased |= (1ULL << 31);
    }
    
    // Secondary Processor-Based Controls 合并
    mergedSecondaryProc = nested->SavedSecondaryControls | l1SecondaryProc;
    // L0 必须保持 EPT 启用
    if (nested->SavedSecondaryControls & (1ULL << 1)) {  // Enable EPT
        mergedSecondaryProc |= (1ULL << 1);
    }
    // L0 必须保持 VPID 启用（如果原来启用）
    if (nested->SavedSecondaryControls & (1ULL << 5)) {  // Enable VPID
        mergedSecondaryProc |= (1ULL << 5);
    }
    // 确保 VMX 指令继续被拦截
    mergedSecondaryProc &= ~(1ULL << 13);  // Disable VMCS shadowing for now
    
    // VM-Exit Controls 合并
    mergedExit = nested->SavedExitControls | l1Exit;
    // L0 需要控制某些关键位
    // Host address-space size 必须由 L0 控制
    mergedExit = (mergedExit & ~(1ULL << 9)) | (nested->SavedExitControls & (1ULL << 9));
    
    // VM-Entry Controls 合并
    mergedEntry = nested->SavedEntryControls | l1Entry;
    // IA-32e mode guest 应该来自 L1 的 Guest EFER.LMA
    if (nested->Vmcs12[VMCS12_GUEST_EFER] & EFER_LMA) {
        mergedEntry |= (1ULL << 9);  // IA-32e mode guest
    } else {
        mergedEntry &= ~(1ULL << 9);
    }
    
    // Exception Bitmap 合并（OR 合并）
    // L0 和 L1 要求拦截的异常都应该被拦截
    mergedExceptionBitmap = nested->SavedExceptionBitmap | 
                            (SIZE_T)nested->Vmcs12[VMCS12_EXCEPTION_BITMAP];
    
    // EPT Pointer 处理
    // 如果 L1 启用了 EPT，我们需要构建 EPT02
    // 否则使用 L0 的 EPT
    l1Eptp = nested->Vmcs12[VMCS12_EPTP];
    if ((l1SecondaryProc & (1ULL << 1)) && l1Eptp != 0) {
        // L1 启用了 EPT，需要使用嵌套 EPT
        PNESTED_EPT_CONTEXT eptContext = NULL;

        if (NT_SUCCESS(HvNestedSetupEpt(VcpuData, l1Eptp))) {
            eptContext = (PNESTED_EPT_CONTEXT)nested->NestedEptTables;
        }
        if (eptContext && eptContext->Valid) {
            // 使用 EPT02 的 EPTP
            mergedEptp = eptContext->Pml4Physical.QuadPart | 
                         (l1Eptp & 0x3F);  // 保留内存类型和页遍历长度
            nested->L1Eptp = l1Eptp;
            nested->L1EptEnabled = TRUE;
            DbgPrint("[HV-NESTED] Using EPT02 context for L1 EPTP 0x%llx\n", l1Eptp);
        } else {
            // 如果创建 EPT02 失败，回退到 L0 的 EPT
            // 这会导致地址翻译不正确，但至少不会崩溃
            DbgPrint("[HV-NESTED] Failed to create EPT02; nested entry rejected\n");
            nested->L1EptEnabled = FALSE;
            return STATUS_INSUFFICIENT_RESOURCES;
        }
    } else {
        // L1 没有启用 EPT，使用 L0 的 EPT
        mergedEptp = nested->SavedEptp;
        nested->L1EptEnabled = FALSE;
    }
    
    // TSC Offset 合并（累加）
    // L2 看到的 TSC = 物理 TSC + L0 Offset + L1 Offset
    l1TscOffset = nested->Vmcs12[VMCS12_TSC_OFFSET];
    __vmx_vmread(VMCS_CTRL_TSC_OFFSET, &tempValue);
    mergedTscOffset = tempValue + l1TscOffset;
    
    // 写入合并后的控制字段
    __vmx_vmwrite(VMCS_CTRL_PIN_BASED_VM_EXECUTION_CONTROLS, mergedPinBased);
    __vmx_vmwrite(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, mergedProcBased);
    __vmx_vmwrite(VMCS_CTRL_SECONDARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, mergedSecondaryProc);
    __vmx_vmwrite(VMCS_CTRL_VMEXIT_CONTROLS, mergedExit);
    __vmx_vmwrite(VMCS_CTRL_VMENTRY_CONTROLS, mergedEntry);
    __vmx_vmwrite(VMCS_CTRL_EXCEPTION_BITMAP, mergedExceptionBitmap);
    __vmx_vmwrite(VMCS_CTRL_EPTP, mergedEptp);
    __vmx_vmwrite(VMCS_CTRL_TSC_OFFSET, mergedTscOffset);
    
    // ==================== Guest 状态设置 ====================
    // 使用 L1 的 Guest 状态作为 L2 的 Guest 状态
    __vmx_vmwrite(GUEST_CR0, nested->Vmcs12[VMCS12_GUEST_CR0]);
    __vmx_vmwrite(GUEST_CR3, nested->Vmcs12[VMCS12_GUEST_CR3]);
    __vmx_vmwrite(GUEST_CR4, nested->Vmcs12[VMCS12_GUEST_CR4]);
    __vmx_vmwrite(GUEST_DR7, nested->Vmcs12[VMCS12_GUEST_DR7]);
    __vmx_vmwrite(GUEST_RSP, nested->Vmcs12[VMCS12_GUEST_RSP]);
    __vmx_vmwrite(GUEST_RIP, nested->Vmcs12[VMCS12_GUEST_RIP]);
    __vmx_vmwrite(GUEST_RFLAGS, nested->Vmcs12[VMCS12_GUEST_RFLAGS]);
    
    // Guest 段寄存器
    __vmx_vmwrite(GUEST_CS_SELECTOR, nested->Vmcs12[VMCS12_GUEST_CS_SELECTOR]);
    __vmx_vmwrite(GUEST_CS_BASE, nested->Vmcs12[VMCS12_GUEST_CS_BASE]);
    __vmx_vmwrite(GUEST_CS_LIMIT, (ULONG)nested->Vmcs12[VMCS12_GUEST_CS_LIMIT]);
    __vmx_vmwrite(GUEST_CS_ACCESS_RIGHTS, (ULONG)nested->Vmcs12[VMCS12_GUEST_CS_ACCESS]);
    
    __vmx_vmwrite(GUEST_SS_SELECTOR, nested->Vmcs12[VMCS12_GUEST_SS_SELECTOR]);
    __vmx_vmwrite(GUEST_SS_BASE, nested->Vmcs12[VMCS12_GUEST_SS_BASE]);
    __vmx_vmwrite(GUEST_SS_LIMIT, (ULONG)nested->Vmcs12[VMCS12_GUEST_SS_LIMIT]);
    __vmx_vmwrite(GUEST_SS_ACCESS_RIGHTS, (ULONG)nested->Vmcs12[VMCS12_GUEST_SS_ACCESS]);
    
    __vmx_vmwrite(GUEST_DS_SELECTOR, nested->Vmcs12[VMCS12_GUEST_DS_SELECTOR]);
    __vmx_vmwrite(GUEST_DS_BASE, nested->Vmcs12[VMCS12_GUEST_DS_BASE]);
    __vmx_vmwrite(GUEST_DS_LIMIT, (ULONG)nested->Vmcs12[VMCS12_GUEST_DS_LIMIT]);
    __vmx_vmwrite(GUEST_DS_ACCESS_RIGHTS, (ULONG)nested->Vmcs12[VMCS12_GUEST_DS_ACCESS]);
    
    __vmx_vmwrite(GUEST_ES_SELECTOR, nested->Vmcs12[VMCS12_GUEST_ES_SELECTOR]);
    __vmx_vmwrite(GUEST_ES_BASE, nested->Vmcs12[VMCS12_GUEST_ES_BASE]);
    __vmx_vmwrite(GUEST_ES_LIMIT, (ULONG)nested->Vmcs12[VMCS12_GUEST_ES_LIMIT]);
    __vmx_vmwrite(GUEST_ES_ACCESS_RIGHTS, (ULONG)nested->Vmcs12[VMCS12_GUEST_ES_ACCESS]);
    
    __vmx_vmwrite(GUEST_FS_SELECTOR, nested->Vmcs12[VMCS12_GUEST_FS_SELECTOR]);
    __vmx_vmwrite(GUEST_FS_BASE, nested->Vmcs12[VMCS12_GUEST_FS_BASE]);
    __vmx_vmwrite(GUEST_FS_LIMIT, (ULONG)nested->Vmcs12[VMCS12_GUEST_FS_LIMIT]);
    __vmx_vmwrite(GUEST_FS_ACCESS_RIGHTS, (ULONG)nested->Vmcs12[VMCS12_GUEST_FS_ACCESS]);
    
    __vmx_vmwrite(GUEST_GS_SELECTOR, nested->Vmcs12[VMCS12_GUEST_GS_SELECTOR]);
    __vmx_vmwrite(GUEST_GS_BASE, nested->Vmcs12[VMCS12_GUEST_GS_BASE]);
    __vmx_vmwrite(GUEST_GS_LIMIT, (ULONG)nested->Vmcs12[VMCS12_GUEST_GS_LIMIT]);
    __vmx_vmwrite(GUEST_GS_ACCESS_RIGHTS, (ULONG)nested->Vmcs12[VMCS12_GUEST_GS_ACCESS]);
    
    __vmx_vmwrite(GUEST_LDTR_SELECTOR, nested->Vmcs12[VMCS12_GUEST_LDTR_SELECTOR]);
    __vmx_vmwrite(GUEST_LDTR_BASE, nested->Vmcs12[VMCS12_GUEST_LDTR_BASE]);
    __vmx_vmwrite(GUEST_LDTR_LIMIT, (ULONG)nested->Vmcs12[VMCS12_GUEST_LDTR_LIMIT]);
    __vmx_vmwrite(GUEST_LDTR_ACCESS_RIGHTS, (ULONG)nested->Vmcs12[VMCS12_GUEST_LDTR_ACCESS]);
    
    __vmx_vmwrite(GUEST_TR_SELECTOR, nested->Vmcs12[VMCS12_GUEST_TR_SELECTOR]);
    __vmx_vmwrite(GUEST_TR_BASE, nested->Vmcs12[VMCS12_GUEST_TR_BASE]);
    __vmx_vmwrite(GUEST_TR_LIMIT, (ULONG)nested->Vmcs12[VMCS12_GUEST_TR_LIMIT]);
    __vmx_vmwrite(GUEST_TR_ACCESS_RIGHTS, (ULONG)nested->Vmcs12[VMCS12_GUEST_TR_ACCESS]);
    
    __vmx_vmwrite(GUEST_GDTR_BASE, nested->Vmcs12[VMCS12_GUEST_GDTR_BASE]);
    __vmx_vmwrite(GUEST_GDTR_LIMIT, (ULONG)nested->Vmcs12[VMCS12_GUEST_GDTR_LIMIT]);
    __vmx_vmwrite(GUEST_IDTR_BASE, nested->Vmcs12[VMCS12_GUEST_IDTR_BASE]);
    __vmx_vmwrite(GUEST_IDTR_LIMIT, (ULONG)nested->Vmcs12[VMCS12_GUEST_IDTR_LIMIT]);
    
    // Guest 其他状态
    __vmx_vmwrite(GUEST_IA32_EFER, nested->Vmcs12[VMCS12_GUEST_EFER]);
    __vmx_vmwrite(GUEST_ACTIVITY_STATE, (ULONG)nested->Vmcs12[VMCS12_GUEST_ACTIVITY_STATE]);
    __vmx_vmwrite(GUEST_INTERRUPTIBILITY_STATE, (ULONG)nested->Vmcs12[VMCS12_GUEST_INTERRUPTIBILITY]);
    
    // 注意：Host 状态保持为 L0（我们自己），不使用 L1 的 Host 状态
    // 这样所有的 VM Exit 都会回到 L0
    
    // 标记进入 L2
    VcpuData->IsInL2 = TRUE;
    nested->NestedVmEntryCount++;
    
    return STATUS_SUCCESS;
}

// ==================== L2 VM Exit 处理 ====================

BOOLEAN HvNestedShouldL0HandleExit(PVCPU_DATA VcpuData, SIZE_T ExitReason, SIZE_T Qualification)
{
    PNESTED_VMX_STATE nested = &VcpuData->NestedVmx;
    
    // L0 必须处理的退出：
    // - EPT Violation（L0 的 EPT Hook）
    // - EPT Misconfiguration
    // - VMX 指令（嵌套虚拟化）
    // - External Interrupt（如果 L0 需要处理）
    
    switch (ExitReason) {
    case EXIT_REASON_EPT_VIOLATION:
        // 区分是 L0 Hook 还是应该传递给 L1
        {
            ULONG64 guestPhysical;
            BOOLEAN isL0Hook = FALSE;
            
            __vmx_vmread(VMCS_GUEST_PHYSICAL_ADDRESS, (SIZE_T*)&guestPhysical);
            
            // 检查这个物理地址是否有 L0 的 EPT Hook
            // 通过检查 g_EptHookManager 中是否有对应的 Hook 条目
            // 如果有 L0 Hook，由 L0 处理；否则检查是否应该注入给 L1
            
            // 首先检查是否是 L0 的 Hook 地址
            isL0Hook = EptHookRootOwnsPhysicalPage(
                VcpuData, guestPhysical);
            
            if (isL0Hook) {
                // 是 L0 的 Hook，由 L0 处理
                return TRUE;
            }
            
            // 如果 L1 启用了 EPT，检查是否是 L1 EPT 导致的 Violation
            if (FALSE && nested->L1EptEnabled && nested->L1Eptp != 0) {
                // 需要检查 L1 的 EPT 是否覆盖了这个地址
                // 如果 L1 EPT 没有映射或权限不足，应该注入给 L1
                BOOLEAN shouldInjectToL1 = FALSE;
                
                if (NestedEptHandleViolation(VcpuData, guestPhysical, Qualification, &shouldInjectToL1)) {
                    if (shouldInjectToL1) {
                        // 应该注入给 L1 处理
                        return FALSE;
                    }
                    // L0 已经处理了（例如惰性映射）
                    return TRUE;
                }
            }
            
            // 默认由 L0 处理
            return TRUE;
        }
        
    case EXIT_REASON_EPT_MISCONFIG:
        // 总是由 L0 处理
        return TRUE;
        
    case EXIT_REASON_VMXON:
    case EXIT_REASON_VMXOFF:
    case EXIT_REASON_VMCLEAR:
    case EXIT_REASON_VMPTRLD:
    case EXIT_REASON_VMPTRST:
    case EXIT_REASON_VMREAD:
    case EXIT_REASON_VMWRITE:
    case EXIT_REASON_VMLAUNCH:
    case EXIT_REASON_VMRESUME:
        // L2 执行 VMX 指令需要 L0 处理（三层嵌套，当前不支持）
        // 注入 #UD 异常给 L2
        return TRUE;
        
    case EXIT_REASON_EXTERNAL_INTERRUPT:
        // 外部中断由 L0 处理
        return TRUE;
        
    default:
        // 其他退出检查 L1 的 exception bitmap 等
        // 如果 L1 要求拦截，则注入给 L1
        return FALSE;
    }
}

BOOLEAN HvNestedHandleL2Exit(PVCPU_DATA VcpuData, SIZE_T ExitReason, PGUEST_CONTEXT GuestContext)
{
    // L0 处理 L2 的 VM Exit
    // 这里处理 L0 关心的退出（如 EPT Hook）
    
    InterlockedIncrement64(&g_NestedVmExitCount);
    
    // 处理完后继续在 L2 中运行
    return TRUE;
}

VOID HvNestedVmExitFromL2ToL1(PVCPU_DATA VcpuData, SIZE_T ExitReason, SIZE_T Qualification)
{
    PNESTED_VMX_STATE nested = &VcpuData->NestedVmx;
    
    // 同步 L2 状态到 VMCS12
    HvNestedSyncVmcs12FromVmcs02(VcpuData, ExitReason);
    
    // 设置 VMCS12 的退出信息
    nested->Vmcs12[VMCS12_EXIT_REASON] = ExitReason;
    nested->Vmcs12[VMCS12_EXIT_QUALIFICATION] = Qualification;
    
    // 恢复 L1 状态
    HvNestedRestoreL1State(VcpuData);
    
    // 标记退出 L2
    VcpuData->IsInL2 = FALSE;
    nested->L2VmExitCount++;
    HvNestedRecordEvent(
        VcpuData, HvNestedEventVmExit, ExitReason,
        Qualification, nested->CurrentVmcsGpa);
}

BOOLEAN HvNestedInjectVmExitToL1(PVCPU_DATA VcpuData, SIZE_T ExitReason, PGUEST_CONTEXT GuestContext)
{
    SIZE_T qualification;
    
    __vmx_vmread(VM_EXIT_QUALIFICATION, &qualification);
    
    // 执行 L2 -> L1 的 VM Exit
    HvNestedVmExitFromL2ToL1(VcpuData, ExitReason, qualification);
    
    // 返回 TRUE 继续执行（现在是 L1）
    return TRUE;
}

VOID HvNestedSyncVmcs12FromVmcs02(PVCPU_DATA VcpuData, SIZE_T ExitReason)
{
    PNESTED_VMX_STATE nested = &VcpuData->NestedVmx;
    SIZE_T value;
    
    // ===== 同步 Guest 基本状态 =====
    __vmx_vmread(GUEST_RIP, &value);
    nested->Vmcs12[VMCS12_GUEST_RIP] = value;
    
    __vmx_vmread(GUEST_RSP, &value);
    nested->Vmcs12[VMCS12_GUEST_RSP] = value;
    
    __vmx_vmread(GUEST_RFLAGS, &value);
    nested->Vmcs12[VMCS12_GUEST_RFLAGS] = value;
    
    __vmx_vmread(GUEST_CR0, &value);
    nested->Vmcs12[VMCS12_GUEST_CR0] = value;
    
    __vmx_vmread(GUEST_CR3, &value);
    nested->Vmcs12[VMCS12_GUEST_CR3] = value;
    
    __vmx_vmread(GUEST_CR4, &value);
    nested->Vmcs12[VMCS12_GUEST_CR4] = value;
    
    __vmx_vmread(GUEST_DR7, &value);
    nested->Vmcs12[VMCS12_GUEST_DR7] = value;
    
    __vmx_vmread(GUEST_IA32_EFER, &value);
    nested->Vmcs12[VMCS12_GUEST_EFER] = value;
    
    // ===== 同步 Guest 段寄存器 =====
    __vmx_vmread(GUEST_CS_SELECTOR, &value);
    nested->Vmcs12[VMCS12_GUEST_CS_SELECTOR] = value;
    __vmx_vmread(GUEST_CS_BASE, &value);
    nested->Vmcs12[VMCS12_GUEST_CS_BASE] = value;
    __vmx_vmread(GUEST_CS_LIMIT, &value);
    nested->Vmcs12[VMCS12_GUEST_CS_LIMIT] = value;
    __vmx_vmread(GUEST_CS_ACCESS_RIGHTS, &value);
    nested->Vmcs12[VMCS12_GUEST_CS_ACCESS] = value;
    
    __vmx_vmread(GUEST_SS_SELECTOR, &value);
    nested->Vmcs12[VMCS12_GUEST_SS_SELECTOR] = value;
    __vmx_vmread(GUEST_SS_BASE, &value);
    nested->Vmcs12[VMCS12_GUEST_SS_BASE] = value;
    __vmx_vmread(GUEST_SS_LIMIT, &value);
    nested->Vmcs12[VMCS12_GUEST_SS_LIMIT] = value;
    __vmx_vmread(GUEST_SS_ACCESS_RIGHTS, &value);
    nested->Vmcs12[VMCS12_GUEST_SS_ACCESS] = value;
    
    __vmx_vmread(GUEST_DS_SELECTOR, &value);
    nested->Vmcs12[VMCS12_GUEST_DS_SELECTOR] = value;
    __vmx_vmread(GUEST_DS_BASE, &value);
    nested->Vmcs12[VMCS12_GUEST_DS_BASE] = value;
    __vmx_vmread(GUEST_DS_LIMIT, &value);
    nested->Vmcs12[VMCS12_GUEST_DS_LIMIT] = value;
    __vmx_vmread(GUEST_DS_ACCESS_RIGHTS, &value);
    nested->Vmcs12[VMCS12_GUEST_DS_ACCESS] = value;
    
    __vmx_vmread(GUEST_ES_SELECTOR, &value);
    nested->Vmcs12[VMCS12_GUEST_ES_SELECTOR] = value;
    __vmx_vmread(GUEST_ES_BASE, &value);
    nested->Vmcs12[VMCS12_GUEST_ES_BASE] = value;
    __vmx_vmread(GUEST_ES_LIMIT, &value);
    nested->Vmcs12[VMCS12_GUEST_ES_LIMIT] = value;
    __vmx_vmread(GUEST_ES_ACCESS_RIGHTS, &value);
    nested->Vmcs12[VMCS12_GUEST_ES_ACCESS] = value;
    
    __vmx_vmread(GUEST_FS_SELECTOR, &value);
    nested->Vmcs12[VMCS12_GUEST_FS_SELECTOR] = value;
    __vmx_vmread(GUEST_FS_BASE, &value);
    nested->Vmcs12[VMCS12_GUEST_FS_BASE] = value;
    __vmx_vmread(GUEST_FS_LIMIT, &value);
    nested->Vmcs12[VMCS12_GUEST_FS_LIMIT] = value;
    __vmx_vmread(GUEST_FS_ACCESS_RIGHTS, &value);
    nested->Vmcs12[VMCS12_GUEST_FS_ACCESS] = value;
    
    __vmx_vmread(GUEST_GS_SELECTOR, &value);
    nested->Vmcs12[VMCS12_GUEST_GS_SELECTOR] = value;
    __vmx_vmread(GUEST_GS_BASE, &value);
    nested->Vmcs12[VMCS12_GUEST_GS_BASE] = value;
    __vmx_vmread(GUEST_GS_LIMIT, &value);
    nested->Vmcs12[VMCS12_GUEST_GS_LIMIT] = value;
    __vmx_vmread(GUEST_GS_ACCESS_RIGHTS, &value);
    nested->Vmcs12[VMCS12_GUEST_GS_ACCESS] = value;
    
    __vmx_vmread(GUEST_LDTR_SELECTOR, &value);
    nested->Vmcs12[VMCS12_GUEST_LDTR_SELECTOR] = value;
    __vmx_vmread(GUEST_LDTR_BASE, &value);
    nested->Vmcs12[VMCS12_GUEST_LDTR_BASE] = value;
    __vmx_vmread(GUEST_LDTR_LIMIT, &value);
    nested->Vmcs12[VMCS12_GUEST_LDTR_LIMIT] = value;
    __vmx_vmread(GUEST_LDTR_ACCESS_RIGHTS, &value);
    nested->Vmcs12[VMCS12_GUEST_LDTR_ACCESS] = value;
    
    __vmx_vmread(GUEST_TR_SELECTOR, &value);
    nested->Vmcs12[VMCS12_GUEST_TR_SELECTOR] = value;
    __vmx_vmread(GUEST_TR_BASE, &value);
    nested->Vmcs12[VMCS12_GUEST_TR_BASE] = value;
    __vmx_vmread(GUEST_TR_LIMIT, &value);
    nested->Vmcs12[VMCS12_GUEST_TR_LIMIT] = value;
    __vmx_vmread(GUEST_TR_ACCESS_RIGHTS, &value);
    nested->Vmcs12[VMCS12_GUEST_TR_ACCESS] = value;
    
    __vmx_vmread(GUEST_GDTR_BASE, &value);
    nested->Vmcs12[VMCS12_GUEST_GDTR_BASE] = value;
    __vmx_vmread(GUEST_GDTR_LIMIT, &value);
    nested->Vmcs12[VMCS12_GUEST_GDTR_LIMIT] = value;
    
    __vmx_vmread(GUEST_IDTR_BASE, &value);
    nested->Vmcs12[VMCS12_GUEST_IDTR_BASE] = value;
    __vmx_vmread(GUEST_IDTR_LIMIT, &value);
    nested->Vmcs12[VMCS12_GUEST_IDTR_LIMIT] = value;
    
    // ===== 同步 Guest 其他状态 =====
    __vmx_vmread(GUEST_ACTIVITY_STATE, &value);
    nested->Vmcs12[VMCS12_GUEST_ACTIVITY_STATE] = value;
    
    __vmx_vmread(GUEST_INTERRUPTIBILITY_STATE, &value);
    nested->Vmcs12[VMCS12_GUEST_INTERRUPTIBILITY] = value;
    
    __vmx_vmread(GUEST_PENDING_DEBUG_EXCEPTIONS, &value);
    nested->Vmcs12[VMCS12_GUEST_PENDING_DBG_EXCEPTIONS] = value;
    
    // ===== 同步退出信息 =====
    __vmx_vmread(VM_EXIT_INTERRUPTION_INFO, &value);
    nested->Vmcs12[VMCS12_EXIT_INTR_INFO] = value;
    
    __vmx_vmread(VM_EXIT_INTERRUPTION_ERROR_CODE, &value);
    nested->Vmcs12[VMCS12_EXIT_INTR_ERROR_CODE] = value;
    
    __vmx_vmread(VM_EXIT_INSTRUCTION_LEN, &value);
    nested->Vmcs12[VMCS12_EXIT_INSTRUCTION_LEN] = value;
    
    __vmx_vmread(VM_EXIT_INSTRUCTION_INFO, &value);
    nested->Vmcs12[VMCS12_EXIT_INSTRUCTION_INFO] = value;
    
    __vmx_vmread(VMCS_GUEST_PHYSICAL_ADDRESS, &value);
    nested->Vmcs12[VMCS12_GUEST_PHYSICAL_ADDRESS] = value;
    
    __vmx_vmread(GUEST_LINEAR_ADDRESS, &value);
    nested->Vmcs12[VMCS12_GUEST_LINEAR_ADDRESS] = value;
    
    // IDT/GDT vectoring info (for event injection during exit)
    __vmx_vmread(IDT_VECTORING_INFO, &value);
    nested->Vmcs12[VMCS12_IDT_VECTORING_INFO] = value;
    
    __vmx_vmread(IDT_VECTORING_ERROR_CODE, &value);
    nested->Vmcs12[VMCS12_IDT_VECTORING_ERROR] = value;
}

// ==================== VMLAUNCH/VMRESUME ====================

BOOLEAN HvNestedHandleVmlaunch(PVCPU_DATA VcpuData, PGUEST_CONTEXT GuestContext)
{
    NTSTATUS status;

    if (!HvNestedCanEnterL2()) {
        HvNestedSetVmxFailValid(
            VcpuData, GuestContext, VMXERR_VMENTRY_INVALID_CONTROL);
        return FALSE;
    }
    
    if (!HvNestedCheckVmxPreconditions(VcpuData, GuestContext)) {
        HvNestedSetVmxFailInvalid(GuestContext);
        return FALSE;
    }
    
    if (!HvNestedCheckVmcsLoaded(VcpuData)) {
        HvNestedSetVmxFailValid(VcpuData, GuestContext, VMXERR_VMLAUNCH_NONCLEAR_VMCS);
        return FALSE;
    }
    
    // 检查 VMCS 状态
    if (VcpuData->NestedVmx.VmcsState == VMCS_STATE_LAUNCHED) {
        HvNestedSetVmxFailValid(VcpuData, GuestContext, VMXERR_VMLAUNCH_NONCLEAR_VMCS);
        return FALSE;
    }
    
    // 验证 VMCS12 配置
    if (!HvNestedValidateVmcs12(VcpuData)) {
        HvNestedSetVmxFailValid(VcpuData, GuestContext, VMXERR_VMENTRY_INVALID_CONTROL);
        return FALSE;
    }
    
    // 准备 VMCS02（合并 VMCS）
    status = HvNestedPrepareVmcs02(VcpuData);
    if (!NT_SUCCESS(status)) {
        HvNestedSetVmxFailValid(VcpuData, GuestContext, VMXERR_VMENTRY_INVALID_CONTROL);
        return FALSE;
    }
    
    VcpuData->NestedVmx.VmcsState = VMCS_STATE_LAUNCHED;
    InterlockedIncrement64(&g_NestedVmlaunchCount);
    HvNestedRecordEvent(
        VcpuData, HvNestedEventVmEntry, 0,
        VcpuData->NestedVmx.CurrentVmcsGpa,
        VcpuData->NestedVmx.L1Eptp);
    
    // 不设置成功标志，不推进 RIP
    // VMLAUNCH 成功会直接进入 L2
    return TRUE;
}

BOOLEAN HvNestedHandleVmresume(PVCPU_DATA VcpuData, PGUEST_CONTEXT GuestContext)
{
    NTSTATUS status;

    if (!HvNestedCanEnterL2()) {
        HvNestedSetVmxFailValid(
            VcpuData, GuestContext, VMXERR_VMENTRY_INVALID_CONTROL);
        return FALSE;
    }
    
    if (!HvNestedCheckVmxPreconditions(VcpuData, GuestContext)) {
        HvNestedSetVmxFailInvalid(GuestContext);
        return FALSE;
    }
    
    if (!HvNestedCheckVmcsLoaded(VcpuData)) {
        HvNestedSetVmxFailValid(VcpuData, GuestContext, VMXERR_VMRESUME_NONLAUNCHED);
        return FALSE;
    }
    
    // 检查 VMCS 状态（必须是 launched）
    if (VcpuData->NestedVmx.VmcsState != VMCS_STATE_LAUNCHED) {
        HvNestedSetVmxFailValid(VcpuData, GuestContext, VMXERR_VMRESUME_NONLAUNCHED);
        return FALSE;
    }
    
    // 验证 VMCS12 配置
    if (!HvNestedValidateVmcs12(VcpuData)) {
        HvNestedSetVmxFailValid(VcpuData, GuestContext, VMXERR_VMENTRY_INVALID_CONTROL);
        return FALSE;
    }
    
    // 准备 VMCS02
    status = HvNestedPrepareVmcs02(VcpuData);
    if (!NT_SUCCESS(status)) {
        HvNestedSetVmxFailValid(VcpuData, GuestContext, VMXERR_VMENTRY_INVALID_CONTROL);
        return FALSE;
    }
    
    return TRUE;
}

// ==================== INVEPT/INVVPID ====================

BOOLEAN HvNestedHandleInvept(PVCPU_DATA VcpuData, PGUEST_CONTEXT GuestContext)
{
    if (!HvNestedCheckVmxPreconditions(VcpuData, GuestContext)) {
        HvNestedSetVmxFailInvalid(GuestContext);
        return TRUE;
    }
    
    // 执行真正的 INVEPT
    AsmInveptAllContexts();
    
    HvNestedSetVmxSuccess(GuestContext);
    return TRUE;
}

BOOLEAN HvNestedHandleInvvpid(PVCPU_DATA VcpuData, PGUEST_CONTEXT GuestContext)
{
    if (!HvNestedCheckVmxPreconditions(VcpuData, GuestContext)) {
        HvNestedSetVmxFailInvalid(GuestContext);
        return TRUE;
    }
    
    // 执行真正的 INVVPID
    AsmInvvpidAllContexts();
    
    HvNestedSetVmxSuccess(GuestContext);
    return TRUE;
}

// ==================== 嵌套 EPT ====================

/*
 * 嵌套 EPT 合并策略：
 * 
 * 当 L1 Hypervisor 启用 EPT 时，我们需要创建一个 "合并" 的 EPT 表（称为 EPT02）：
 * - L2 GPA -> L1 GPA：通过 L1 的 EPT（EPT12）
 * - L1 GPA -> HPA：通过 L0 的 EPT（EPT01）
 * 
 * 最终效果是 L2 GPA -> HPA 的映射。
 * 
 * 有两种实现方式：
 * 1. 预构建：在 VMLAUNCH 时遍历 L1 EPT，构建完整的 EPT02
 *    - 优点：运行时快
 *    - 缺点：内存开销大，需要处理 L1 EPT 更新
 * 
 * 2. 惰性构建：初始不映射，EPT Violation 时按需构建
 *    - 优点：内存开销小
 *    - 缺点：初始运行时有更多 EPT Violation
 * 
 * 当前实现采用简化策略：直接使用 L0 的 EPT，
 * L1 的 EPT 操作只记录但不实际应用（即 L2 直接使用 L1 GPA = HPA 的假设）
 * 这对于大多数简单情况是可行的。
 * 
 * 完整实现需要：
 * - 分配 EPT02 页表
 * - 遍历 L1 EPT 获取 L2 GPA -> L1 GPA 映射
 * - 对于每个映射，通过 L0 EPT 翻译 L1 GPA -> HPA
 * - 合并权限位（取交集）
 * - 处理 EPT Violation 时区分是 L0 Hook 还是 L1 EPT 问题
 */

// 从 L1 Guest 物理地址读取数据
static BOOLEAN HvNestedReadL1Memory(PVCPU_DATA VcpuData, ULONG64 L1Gpa, PVOID Buffer, SIZE_T Size)
{
    if (!Buffer || Size == 0) {
        return FALSE;
    }

    return HvNestedRootReadPhysical(VcpuData, L1Gpa, Buffer, Size);
#if 0
    
    // 将 L1 的物理地址映射到虚拟地址
    // 对于 identity mapping，L1 GPA = HPA
    pa.QuadPart = L1Gpa;
    
    mapped = MmMapIoSpace(pa, Size, MmNonCached);
    if (!mapped) {
        return FALSE;
    }
    
    __try {
        RtlCopyMemory(Buffer, mapped, Size);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        MmUnmapIoSpace(mapped, Size);
        return FALSE;
    }
    
    MmUnmapIoSpace(mapped, Size);
    return TRUE;
#endif
}

// 向 L1 Guest 物理地址写入数据
static BOOLEAN HvNestedWriteL1Memory(PVCPU_DATA VcpuData, ULONG64 L1Gpa, PVOID Buffer, SIZE_T Size)
{
    if (!Buffer || Size == 0) {
        return FALSE;
    }

    return HvNestedRootWritePhysical(VcpuData, L1Gpa, Buffer, Size);
#if 0
    
    // 将 L1 的物理地址映射到虚拟地址
    pa.QuadPart = L1Gpa;
    
    mapped = MmMapIoSpace(pa, Size, MmNonCached);
    if (!mapped) {
        return FALSE;
    }
    
    __try {
        RtlCopyMemory(mapped, Buffer, Size);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        MmUnmapIoSpace(mapped, Size);
        return FALSE;
    }
    
    MmUnmapIoSpace(mapped, Size);
    return TRUE;
#endif
}

// 从 L1 EPT 读取条目（需要通过 L0 翻译地址）
static BOOLEAN HvNestedReadL1EptEntry(PVCPU_DATA VcpuData, ULONG64 L1EptPa, PULONG64 Entry)
{
    if (!Entry) return FALSE;
    return HvNestedRootReadPhysical(VcpuData, L1EptPa, Entry, sizeof(*Entry));
#if 0
    PVOID mapped;
    PHYSICAL_ADDRESS pa;
    
    // 将 L1 看到的物理地址映射到虚拟地址
    // 由于 L1 的物理地址可能被 L0 EPT 映射，需要先翻译
    pa.QuadPart = L1EptPa;
    
    mapped = MmMapIoSpace(pa, sizeof(ULONG64), MmNonCached);
    if (!mapped) {
        return FALSE;
    }
    
    *Entry = *(PULONG64)mapped;
    MmUnmapIoSpace(mapped, sizeof(ULONG64));
    
    return TRUE;
#endif
}

// 翻译 L2 GPA 到 L1 GPA（通过 L1 EPT）
static BOOLEAN HvNestedTranslateL2GpaToL1Gpa(
    PVCPU_DATA VcpuData, 
    ULONG64 L2Gpa, 
    PULONG64 L1Gpa,
    PULONG64 Permissions)
{
    PNESTED_VMX_STATE nested = &VcpuData->NestedVmx;
    ULONG64 eptp = nested->L1Eptp;
    ULONG64 pml4Pa, pdptPa, pdPa, ptPa;
    ULONG64 pml4e, pdpte, pde, pte;
    ULONG64 pml4Index, pdptIndex, pdIndex, ptIndex;
    ULONG64 pageOffset;
    
    if (!nested->L1EptEnabled || eptp == 0) {
        // L1 没有启用 EPT，L2 GPA = L1 GPA
        *L1Gpa = L2Gpa;
        *Permissions = 0x7; // RWX
        return TRUE;
    }
    
    // 计算索引
    pml4Index = (L2Gpa >> 39) & 0x1FF;
    pdptIndex = (L2Gpa >> 30) & 0x1FF;
    pdIndex = (L2Gpa >> 21) & 0x1FF;
    ptIndex = (L2Gpa >> 12) & 0x1FF;
    pageOffset = L2Gpa & 0xFFF;
    
    // 获取 PML4 基址
    pml4Pa = (eptp >> 12) << 12;
    
    // 读取 PML4E
    if (!HvNestedReadL1EptEntry(VcpuData, pml4Pa + pml4Index * 8, &pml4e)) {
        return FALSE;
    }
    
    if (!(pml4e & 0x7)) {
        return FALSE; // 没有映射
    }
    
    // 读取 PDPTE
    pdptPa = (pml4e >> 12) << 12;
    if (!HvNestedReadL1EptEntry(VcpuData, pdptPa + pdptIndex * 8, &pdpte)) {
        return FALSE;
    }
    
    if (!(pdpte & 0x7)) {
        return FALSE;
    }
    
    // 检查 1GB 大页
    if (pdpte & 0x80) {
        *L1Gpa = ((pdpte >> 30) << 30) | (L2Gpa & 0x3FFFFFFF);
        *Permissions = pdpte & 0x7;
        return TRUE;
    }
    
    // 读取 PDE
    pdPa = (pdpte >> 12) << 12;
    if (!HvNestedReadL1EptEntry(VcpuData, pdPa + pdIndex * 8, &pde)) {
        return FALSE;
    }
    
    if (!(pde & 0x7)) {
        return FALSE;
    }
    
    // 检查 2MB 大页
    if (pde & 0x80) {
        *L1Gpa = ((pde >> 21) << 21) | (L2Gpa & 0x1FFFFF);
        *Permissions = pde & 0x7;
        return TRUE;
    }
    
    // 读取 PTE
    ptPa = (pde >> 12) << 12;
    if (!HvNestedReadL1EptEntry(VcpuData, ptPa + ptIndex * 8, &pte)) {
        return FALSE;
    }
    
    if (!(pte & 0x7)) {
        return FALSE;
    }
    
    *L1Gpa = ((pte >> 12) << 12) | pageOffset;
    *Permissions = pte & 0x7;
    
    return TRUE;
}

NTSTATUS HvNestedSetupEpt(PVCPU_DATA VcpuData, ULONG64 L1Eptp)
{
    PNESTED_VMX_STATE nested = &VcpuData->NestedVmx;
    PNESTED_EPT_CONTEXT eptContext;

    if (nested->NestedEptTables && nested->L1Eptp == L1Eptp) {
        return STATUS_SUCCESS;
    }
    if (nested->NestedEptTables) {
        NestedEptReleaseContext(
            (PNESTED_EPT_CONTEXT)nested->NestedEptTables);
        nested->NestedEptTables = NULL;
    }
    
    // 保存 L1 的 EPTP
    nested->L1Eptp = L1Eptp;
    nested->L1EptEnabled = (L1Eptp != 0);
    
    if (!nested->L1EptEnabled) {
        return STATUS_SUCCESS;
    }
    
    DbgPrint("[HV-NESTED] Setting up nested EPT, L1 EPTP=0x%llX\n", L1Eptp);
    
    // 使用新的嵌套 EPT 管理器创建上下文
    eptContext = NestedEptGetOrCreateContext(VcpuData, L1Eptp);
    if (!eptContext) {
        DbgPrint("[HV-NESTED] Failed to create nested EPT context\n");
        nested->L1EptEnabled = FALSE;
        nested->L1Eptp = 0;
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    // 保存上下文指针（转换为 PVOID 存储）
    nested->NestedEptTables = (PVOID)eptContext;
    
    // 使 EPT TLB 无效
    AsmInveptAllContexts();
    
    DbgPrint("[HV-NESTED] Nested EPT context created, PML4 PA=0x%llX\n", 
             eptContext->Pml4Physical.QuadPart);
    
    return STATUS_SUCCESS;
}

VOID HvNestedCleanupEpt(PVCPU_DATA VcpuData)
{
    PNESTED_VMX_STATE nested = &VcpuData->NestedVmx;
    PNESTED_EPT_CONTEXT eptContext;
    
    if (nested->NestedEptTables) {
        // 销毁嵌套 EPT 上下文
        eptContext = (PNESTED_EPT_CONTEXT)nested->NestedEptTables;
        NestedEptDestroyContext(eptContext);
        nested->NestedEptTables = NULL;
    }
    
    nested->L1Eptp = 0;
    nested->L1EptEnabled = FALSE;
    
    // 使 EPT TLB 无效
    AsmInveptAllContexts();
}

VOID HvNestedInvalidateEptTlb(PVCPU_DATA VcpuData)
{
    AsmInveptAllContexts();
}

BOOLEAN HvNestedTranslateL1GpaToHpa(PVCPU_DATA VcpuData, ULONG64 L1Gpa, PULONG64 Hpa)
{
    // 通过 L0 的 EPT 翻译 L1 GPA 到 HPA
    
    // 检查是否有自定义 EPT 映射
    // 使用 NestedEptTranslateL1GpaToHpa 来进行翻译（如果可用）
    ULONG64 permissions;
    
    if (NestedEptTranslateL1GpaToHpa(VcpuData, L1Gpa, Hpa, &permissions)) {
        return TRUE;
    }
    
    // 回退到 identity mapping
    // 这适用于大多数情况，因为 L0 通常使用 identity-mapped EPT
    *Hpa = L1Gpa;
    
    return TRUE;
}

BOOLEAN HvNestedTranslateL2GpaToHpa(PVCPU_DATA VcpuData, ULONG64 L2Gpa, PULONG64 Hpa)
{
    ULONG64 l1Gpa;
    ULONG64 permissions;
    
    // 步骤1：L2 GPA -> L1 GPA（通过 L1 EPT）
    if (!HvNestedTranslateL2GpaToL1Gpa(VcpuData, L2Gpa, &l1Gpa, &permissions)) {
        return FALSE;
    }
    
    // 步骤2：L1 GPA -> HPA（通过 L0 EPT）
    if (!HvNestedTranslateL1GpaToHpa(VcpuData, l1Gpa, Hpa)) {
        return FALSE;
    }
    
    return TRUE;
}

// ==================== 调试和统计 ====================

VOID HvNestedPrintStatus(PVCPU_DATA VcpuData)
{
    PNESTED_VMX_STATE nested = &VcpuData->NestedVmx;
    
    DbgPrint("[HV-NESTED] CPU %d Nested VMX Status:\n", VcpuData->ProcessorNumber);
    DbgPrint("[HV-NESTED]   VMX Enabled: %s\n", nested->VmxEnabled ? "YES" : "NO");
    DbgPrint("[HV-NESTED]   In L2: %s\n", VcpuData->IsInL2 ? "YES" : "NO");
    DbgPrint("[HV-NESTED]   VMXON Region GPA: 0x%llX\n", nested->VmxonRegionGpa);
    DbgPrint("[HV-NESTED]   Current VMCS GPA: 0x%llX\n", nested->CurrentVmcsGpa);
    DbgPrint("[HV-NESTED]   VMCS State: %d\n", nested->VmcsState);
    DbgPrint("[HV-NESTED]   L2 VM Exit Count: %llu\n", nested->L2VmExitCount);
    DbgPrint("[HV-NESTED]   Nested VM Entry Count: %llu\n", nested->NestedVmEntryCount);
}

VOID HvNestedPrintStats(VOID)
{
    DbgPrint("[HV-NESTED] Global Statistics:\n");
    DbgPrint("[HV-NESTED]   Total VMXON: %lld\n", g_NestedVmxonCount);
    DbgPrint("[HV-NESTED]   Total VMLAUNCH: %lld\n", g_NestedVmlaunchCount);
    DbgPrint("[HV-NESTED]   Total Nested VM Exit: %lld\n", g_NestedVmExitCount);
}

// ==================== 初始化和清理 ====================

NTSTATUS HvNestedInitialize(VOID)
{
#if !HV_ENABLE_NESTED_VIRTUALIZATION
    g_EnableNestedVirtualization = FALSE;
    return STATUS_NOT_SUPPORTED;
#else
    NTSTATUS status = STATUS_NOT_SUPPORTED;
    CPU_VENDOR vendor;
    LONG previousState;

    previousState = InterlockedCompareExchange(
        &g_NestedLifecycle,
        HvNestedStateInitializing,
        HvNestedStateUninitialized);
    if (previousState != HvNestedStateUninitialized) {
        return HvNestedIsInitialized() ? STATUS_SUCCESS : STATUS_DEVICE_BUSY;
    }

    g_EnableNestedVirtualization = FALSE;
    g_NestedEptInitialized = FALSE;
    g_NestedSvmInitialized = FALSE;
    g_NestedNptInitialized = FALSE;
    
    DbgPrint("[HV-NESTED] Initializing nested virtualization support\n");
    
    // 初始化 VMX 嵌套统计
    g_NestedVmxonCount = 0;
    g_NestedVmlaunchCount = 0;
    g_NestedVmExitCount = 0;
    
    // 初始化嵌套 EPT 管理器
#if 0
    status = NestedEptInitialize();
    if (!NT_SUCCESS(status)) {
        DbgPrint("[HV-NESTED] Failed to initialize nested EPT: 0x%X\n", status);
        return status;
    }
    
    // 初始化嵌套 SVM 支持
    status = NestedSvmInitialize();
    if (!NT_SUCCESS(status)) {
        DbgPrint("[HV-NESTED] Failed to initialize nested SVM: 0x%X\n", status);
        NestedEptCleanup();
        return status;
    }
    
    // 初始化嵌套 NPT 管理器
    status = NestedNptInitialize();
    if (!NT_SUCCESS(status)) {
        DbgPrint("[HV-NESTED] Failed to initialize nested NPT: 0x%X\n", status);
        NestedSvmCleanup();
        NestedEptCleanup();
        return status;
    }
    
    DbgPrint("[HV-NESTED] All nested virtualization components initialized\n");
#endif

    vendor = HvGetCpuVendor();
    if (vendor == CPU_VENDOR_INTEL) {
        if (!HvNestedIsVmxSupported()) {
            status = STATUS_NOT_SUPPORTED;
            goto fail;
        }
        status = NestedEptInitialize();
        if (!NT_SUCCESS(status)) goto fail;
        g_NestedEptInitialized = TRUE;
    } else if (vendor == CPU_VENDOR_AMD) {
        if (!HvNestedIsSvmSupported()) {
            status = STATUS_NOT_SUPPORTED;
            goto fail;
        }
        status = NestedSvmInitialize();
        if (!NT_SUCCESS(status)) goto fail;
        g_NestedSvmInitialized = TRUE;

        status = NestedNptInitialize();
        if (!NT_SUCCESS(status)) goto fail;
        g_NestedNptInitialized = TRUE;
    } else {
        status = STATUS_NOT_SUPPORTED;
        goto fail;
    }

    _WriteBarrier();
    InterlockedExchange(&g_NestedLifecycle, HvNestedStateReady);
    DbgPrint("[HV-NESTED] All nested virtualization components initialized\n");
    return STATUS_SUCCESS;

fail:
    if (g_NestedNptInitialized) {
        NestedNptCleanup();
        g_NestedNptInitialized = FALSE;
    }
    if (g_NestedSvmInitialized) {
        NestedSvmCleanup();
        g_NestedSvmInitialized = FALSE;
    }
    if (g_NestedEptInitialized) {
        NestedEptCleanup();
        g_NestedEptInitialized = FALSE;
    }
    InterlockedExchange(&g_NestedLifecycle, HvNestedStateUninitialized);
    return status;
#endif
}

NTSTATUS HvNestedCleanup(VOID)
{
    HV_NESTED_LIFECYCLE_STATE state = HvNestedGetLifecycleState();
    NTSTATUS status;

    if (state == HvNestedStateUninitialized) {
        g_EnableNestedVirtualization = FALSE;
        return STATUS_SUCCESS;
    }
    if (state == HvNestedStateRunning || state == HvNestedStateQuiescing) {
        status = HvNestedQuiesce();
        if (!NT_SUCCESS(status)) {
            return status;
        }
    }

    DbgPrint("[HV-NESTED] Cleaning up nested virtualization\n");
    
    // 打印统计信息
    HvNestedPrintStats();
    if (g_NestedEptInitialized) NestedEptPrintGlobalStats();
    if (g_NestedNptInitialized) NestedNptPrintGlobalStats();
    
    // 清理嵌套 NPT
    if (g_NestedNptInitialized) {
        NestedNptCleanup();
        g_NestedNptInitialized = FALSE;
    }
    
    // 清理嵌套 SVM
    if (g_NestedSvmInitialized) {
        NestedSvmCleanup();
        g_NestedSvmInitialized = FALSE;
    }
    
    // 清理嵌套 EPT
    if (g_NestedEptInitialized) {
        NestedEptCleanup();
        g_NestedEptInitialized = FALSE;
    }

    g_EnableNestedVirtualization = FALSE;
    InterlockedExchange(&g_NestedLifecycle, HvNestedStateUninitialized);
    
    DbgPrint("[HV-NESTED] All nested virtualization components cleaned up\n");
    return STATUS_SUCCESS;
}
