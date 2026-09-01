/*
 * HvNestedEpt.c - 嵌套 EPT (Extended Page Tables) 完整实现
 * 
 * 实现完整的嵌套 EPT 支持，包括：
 * - EPT02 页表构建和管理
 * - L1 EPT 遍历和地址翻译
 * - L0 和 L1 EPT 权限合并
 * - EPT Violation 处理和注入
 * - 翻译缓存加速
 */

#include "HvNestedEpt.h"
#include "HvNested.h"
#include "HvEpt.h"
#include "EptHook.h"
#include "HvCompat.h"

// P122: 全 driver DbgPrint → GUI ring
#define HV_TRACE_THIS_CAT HV_TRACE_CAT_NESTED
#include "HvTrace.h"

// VM-exit paths in this unit use bounded, non-blocking interlocked locks.
// They must not enter the Windows dispatcher through KeAcquireSpinLock.
static __forceinline VOID NestedEptRootLock(_Inout_ volatile LONG* Lock)
{
    while (InterlockedCompareExchange(Lock, 1, 0) != 0) {
        _mm_pause();
    }
}

static __forceinline VOID NestedEptRootUnlock(_Inout_ volatile LONG* Lock)
{
    InterlockedExchange(Lock, 0);
}

#undef KeAcquireSpinLock
#undef KeReleaseSpinLock
#define KeAcquireSpinLock(_Lock, _OldIrql) \
    do { *(_OldIrql) = 0; NestedEptRootLock((volatile LONG*)(_Lock)); } while (0)
#define KeReleaseSpinLock(_Lock, _OldIrql) \
    do { UNREFERENCED_PARAMETER(_OldIrql); NestedEptRootUnlock((volatile LONG*)(_Lock)); } while (0)

// Root diagnostics are exported through HvNestedRecordEvent; formatted kernel
// logging is intentionally compiled out of nested VM-exit paths.
#undef DbgPrint
#define DbgPrint(...) ((void)0)

// ==================== 全局变量 ====================

NESTED_EPT_MANAGER g_NestedEptManager;

// ==================== 内部辅助函数 ====================

/*
 * 分配对齐的物理页
 */
static PVOID NestedEptAllocatePage(PPHYSICAL_ADDRESS PhysicalAddress)
{
    PHYSICAL_ADDRESS low, high, boundary;
    PVOID va;
    
    low.QuadPart = 0;
    high.QuadPart = ~0ULL;
    boundary.QuadPart = 0;
    
    va = MmAllocateContiguousMemorySpecifyCache(
        PAGE_SIZE,
        low,
        high,
        boundary,
        MmCached
    );
    
    if (va) {
        RtlZeroMemory(va, PAGE_SIZE);
        PhysicalAddress->QuadPart = MmGetPhysicalAddress(va).QuadPart;
    }
    
    return va;
}

/*
 * 释放物理页
 */
static VOID NestedEptFreePage(PVOID VirtualAddress)
{
    if (VirtualAddress) {
        MmFreeContiguousMemory(VirtualAddress);
    }
}

/*
 * 从物理地址映射到虚拟地址
 */
static PVOID NestedEptMapPhysicalPage(ULONG64 PhysicalAddress)
{
    ULONG64 page = PhysicalAddress & ~0xFFFULL;

    for (ULONG i = 0; i < g_NestedEptManager.ProvisionedCount; ++i) {
        PNESTED_EPT_CONTEXT context = &g_NestedEptManager.Contexts[i];
        if (!context->Provisioned) continue;
        if (((ULONG64)context->Pml4Physical.QuadPart & ~0xFFFULL) == page) {
            return context->Pml4;
        }
        for (ULONG j = 0; j < context->MaxAllocatedPages; ++j) {
            if (((ULONG64)context->PreallocatedPhysical[j].QuadPart & ~0xFFFULL) == page) {
                return context->PreallocatedPages[j];
            }
        }
    }
    return NULL;
}

/*
 * 取消映射
 */
static VOID NestedEptUnmapPhysicalPage(PVOID VirtualAddress)
{
    UNREFERENCED_PARAMETER(VirtualAddress);
}

/*
 * 读取 L1 EPT 条目（通过物理地址）
 */
static BOOLEAN NestedEptReadL1Entry(
    PVCPU_DATA VcpuData,
    ULONG64 EntryPhysical,
    PULONG64 Entry)
{
    return Entry && HvNestedRootReadPhysical(
        VcpuData, EntryPhysical, Entry, sizeof(*Entry));
}

/*
 * 计算缓存索引
 */
static ULONG NestedEptCacheIndex(ULONG64 L2Gpa)
{
    // 使用简单的哈希函数
    ULONG64 pageNumber = L2Gpa >> 12;
    return (ULONG)(pageNumber % NESTED_EPT_CACHE_SIZE);
}

// ==================== 初始化和清理 ====================

NTSTATUS NestedEptInitialize(VOID)
{
    ULONG provisioned;
    NTSTATUS status = STATUS_SUCCESS;

    RtlZeroMemory(&g_NestedEptManager, sizeof(NESTED_EPT_MANAGER));
    KeInitializeSpinLock(&g_NestedEptManager.Lock);
    g_NestedEptManager.Initialized = TRUE;

    provisioned = g_HypervisorContext.ProcessorCount;
    if (provisioned == 0 || provisioned > MAX_NESTED_EPT_CONTEXTS) {
        g_NestedEptManager.Initialized = FALSE;
        return STATUS_NOT_SUPPORTED;
    }

    for (ULONG i = 0; i < provisioned; ++i) {
        PNESTED_EPT_CONTEXT context = &g_NestedEptManager.Contexts[i];

        KeInitializeSpinLock(&context->Lock);
        context->OwnerProcessor = i;
        context->MaxAllocatedPages = NESTED_EPT_PREALLOC_PAGES;
        context->AllocatedPages = context->PreallocatedPages;
        context->Provisioned = TRUE;
        g_NestedEptManager.ProvisionedCount = i + 1;
        context->Pml4 = (PEPT_PML4E)NestedEptAllocatePage(
            &context->Pml4Physical);
        if (!context->Pml4) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto fail;
        }

        for (ULONG j = 0; j < NESTED_EPT_PREALLOC_PAGES; ++j) {
            context->PreallocatedPages[j] = NestedEptAllocatePage(
                &context->PreallocatedPhysical[j]);
            if (!context->PreallocatedPages[j]) {
                status = STATUS_INSUFFICIENT_RESOURCES;
                goto fail;
            }
        }
    }

    return STATUS_SUCCESS;

fail:
    NestedEptCleanup();
    return status;
}

VOID NestedEptCleanup(VOID)
{
#if 1
    if (!g_NestedEptManager.Initialized) return;

    for (ULONG i = 0; i < g_NestedEptManager.ProvisionedCount; ++i) {
        PNESTED_EPT_CONTEXT context = &g_NestedEptManager.Contexts[i];
        if (context->Pml4) {
            NestedEptFreePage(context->Pml4);
            context->Pml4 = NULL;
        }
        for (ULONG j = 0; j < NESTED_EPT_PREALLOC_PAGES; ++j) {
            if (context->PreallocatedPages[j]) {
                NestedEptFreePage(context->PreallocatedPages[j]);
                context->PreallocatedPages[j] = NULL;
            }
            context->PreallocatedPhysical[j].QuadPart = 0;
        }
    }

    RtlZeroMemory(&g_NestedEptManager, sizeof(g_NestedEptManager));
    return;
#else
    KIRQL oldIrql;
    ULONG i;
    
    if (!g_NestedEptManager.Initialized) {
        return;
    }
    
    KeAcquireSpinLock(&g_NestedEptManager.Lock, &oldIrql);
    
    // 清理所有上下文
    for (i = 0; i < MAX_NESTED_EPT_CONTEXTS; i++) {
        if (g_NestedEptManager.Contexts[i].Initialized) {
            PNESTED_EPT_CONTEXT ctx = &g_NestedEptManager.Contexts[i];
            
            // 释放 PML4
            if (ctx->Pml4) {
                NestedEptFreePage(ctx->Pml4);
            }
            
            // 释放所有分配的页表页
            if (ctx->AllocatedPages) {
                for (ULONG j = 0; j < ctx->AllocatedPageCount; j++) {
                    if (ctx->AllocatedPages[j]) {
                        NestedEptFreePage(ctx->AllocatedPages[j]);
                    }
                }
                ExFreePoolWithTag(ctx->AllocatedPages, 'NEPT');
            }
            
            ctx->Initialized = FALSE;
        }
    }
    
    g_NestedEptManager.Initialized = FALSE;
    KeReleaseSpinLock(&g_NestedEptManager.Lock, oldIrql);
    
    DbgPrint("[HV-NESTED-EPT] Nested EPT manager cleaned up\n");
#endif
}

// ==================== 上下文管理 ====================

PNESTED_EPT_CONTEXT NestedEptCreateContext(PVCPU_DATA VcpuData, ULONG64 L1Eptp)
{
#if 1
    PNESTED_EPT_CONTEXT context = NULL;

    if (!VcpuData ||
        VcpuData->ProcessorNumber >= g_NestedEptManager.ProvisionedCount ||
        !g_NestedEptManager.Initialized ||
        (L1Eptp & 0x7) != EPT_MEMTYPE_WB ||
        ((L1Eptp >> 3) & 0x7) != 3 ||
        (L1Eptp & 0x000FFFFFFFFFF000ULL) == 0) {
        return NULL;
    }

    NestedEptRootLock(&g_NestedEptManager.RootLock);
    context = &g_NestedEptManager.Contexts[VcpuData->ProcessorNumber];
    if (!context->Provisioned || context->Initialized ||
        context->OwnerProcessor != VcpuData->ProcessorNumber) {
        context = NULL;
    }

    if (context) {
        RtlZeroMemory(context->Pml4, PAGE_SIZE);
        RtlZeroMemory(context->Cache, sizeof(context->Cache));
        context->L1Eptp = L1Eptp;
        context->AllocatedPageCount = 0;
        context->CacheHits = 0;
        context->CacheMisses = 0;
        context->TotalTranslations = 0;
        context->EptViolations = 0;
        context->PageFaults = 0;
        context->RefCount = 1;
        context->Valid = TRUE;
        _WriteBarrier();
        context->Initialized = TRUE;
        g_NestedEptManager.ActiveCount++;
        g_NestedEptManager.TotalContextsCreated++;
    }
    NestedEptRootUnlock(&g_NestedEptManager.RootLock);

    if (!context) {
        HvNestedRecordEvent(NULL, HvNestedEventPoolExhausted, 'TPEN', L1Eptp, 0);
    }
    return context;
#else
    KIRQL oldIrql;
    PNESTED_EPT_CONTEXT context = NULL;
    ULONG i;
    
    if (!g_NestedEptManager.Initialized) {
        return NULL;
    }
    
    KeAcquireSpinLock(&g_NestedEptManager.Lock, &oldIrql);
    
    // 查找空闲槽位
    for (i = 0; i < MAX_NESTED_EPT_CONTEXTS; i++) {
        if (!g_NestedEptManager.Contexts[i].Initialized) {
            context = &g_NestedEptManager.Contexts[i];
            break;
        }
    }
    
    if (!context) {
        KeReleaseSpinLock(&g_NestedEptManager.Lock, oldIrql);
        DbgPrint("[HV-NESTED-EPT] No free context slot available\n");
        return NULL;
    }
    
    // 初始化上下文
    RtlZeroMemory(context, sizeof(NESTED_EPT_CONTEXT));
    context->L1Eptp = L1Eptp;
    KeInitializeSpinLock(&context->Lock);
    
    // 分配 PML4 表
    context->Pml4 = (PEPT_PML4E)NestedEptAllocatePage(&context->Pml4Physical);
    if (!context->Pml4) {
        KeReleaseSpinLock(&g_NestedEptManager.Lock, oldIrql);
        DbgPrint("[HV-NESTED-EPT] Failed to allocate PML4\n");
        return NULL;
    }
    
    // 分配页表页数组
    context->MaxAllocatedPages = 1024;  // 最多 1024 个页表页
    context->AllocatedPages = (PVOID*)HvAllocateNonPagedZeroed(
        context->MaxAllocatedPages * sizeof(PVOID),
        'NEPT'
    );
    
    if (!context->AllocatedPages) {
        NestedEptFreePage(context->Pml4);
        context->Pml4 = NULL;
        KeReleaseSpinLock(&g_NestedEptManager.Lock, oldIrql);
        DbgPrint("[HV-NESTED-EPT] Failed to allocate page tracking array\n");
        return NULL;
    }
    context->AllocatedPageCount = 0;
    
    context->Initialized = TRUE;
    context->Valid = TRUE;
    context->RefCount = 1;
    
    g_NestedEptManager.ActiveCount++;
    g_NestedEptManager.TotalContextsCreated++;
    
    KeReleaseSpinLock(&g_NestedEptManager.Lock, oldIrql);
    
    DbgPrint("[HV-NESTED-EPT] Created context for L1 EPTP=0x%llX, PML4 PA=0x%llX\n",
             L1Eptp, context->Pml4Physical.QuadPart);
    
    return context;
#endif
}

VOID NestedEptDestroyContext(PNESTED_EPT_CONTEXT Context)
{
#if 1
    if (!Context || !Context->Initialized) return;
    if (InterlockedDecrement(&Context->RefCount) > 0) return;

    NestedEptRootLock(&g_NestedEptManager.RootLock);
    if (Context->Initialized && Context->RefCount == 0) {
        Context->Initialized = FALSE;
        _WriteBarrier();
        Context->Valid = FALSE;
        Context->L1Eptp = 0;
        Context->AllocatedPageCount = 0;
        RtlZeroMemory(Context->Pml4, PAGE_SIZE);
        RtlZeroMemory(Context->Cache, sizeof(Context->Cache));
        if (g_NestedEptManager.ActiveCount != 0) {
            g_NestedEptManager.ActiveCount--;
        }
        g_NestedEptManager.TotalContextsDestroyed++;
    }
    NestedEptRootUnlock(&g_NestedEptManager.RootLock);
    return;
#else
    KIRQL oldIrql;
    ULONG i;
    
    if (!Context || !Context->Initialized) {
        return;
    }
    
    // 减少引用计数
    if (InterlockedDecrement(&Context->RefCount) > 0) {
        return;
    }
    
    KeAcquireSpinLock(&g_NestedEptManager.Lock, &oldIrql);
    
    DbgPrint("[HV-NESTED-EPT] Destroying context for L1 EPTP=0x%llX\n", Context->L1Eptp);
    
    // 释放 PML4
    if (Context->Pml4) {
        NestedEptFreePage(Context->Pml4);
        Context->Pml4 = NULL;
    }
    
    // 释放所有分配的页表页
    if (Context->AllocatedPages) {
        for (i = 0; i < Context->AllocatedPageCount; i++) {
            if (Context->AllocatedPages[i]) {
                NestedEptFreePage(Context->AllocatedPages[i]);
            }
        }
        ExFreePoolWithTag(Context->AllocatedPages, 'NEPT');
        Context->AllocatedPages = NULL;
    }
    
    Context->Initialized = FALSE;
    Context->Valid = FALSE;
    
    g_NestedEptManager.ActiveCount--;
    g_NestedEptManager.TotalContextsDestroyed++;
    
    KeReleaseSpinLock(&g_NestedEptManager.Lock, oldIrql);
#endif
}

PNESTED_EPT_CONTEXT NestedEptFindContext(PVCPU_DATA VcpuData, ULONG64 L1Eptp)
{
#if 1
    PNESTED_EPT_CONTEXT result = NULL;

    if (!VcpuData || !g_NestedEptManager.Initialized ||
        VcpuData->ProcessorNumber >= g_NestedEptManager.ProvisionedCount) {
        return NULL;
    }
    NestedEptRootLock(&g_NestedEptManager.RootLock);
    {
        PNESTED_EPT_CONTEXT candidate =
            &g_NestedEptManager.Contexts[VcpuData->ProcessorNumber];
        if (candidate->Initialized && candidate->Valid &&
            candidate->OwnerProcessor == VcpuData->ProcessorNumber &&
            candidate->L1Eptp == L1Eptp) {
            result = candidate;
        }
    }
    NestedEptRootUnlock(&g_NestedEptManager.RootLock);
    return result;
#else
    KIRQL oldIrql;
    PNESTED_EPT_CONTEXT result = NULL;
    ULONG i;
    
    if (!g_NestedEptManager.Initialized) {
        return NULL;
    }
    
    KeAcquireSpinLock(&g_NestedEptManager.Lock, &oldIrql);
    
    for (i = 0; i < MAX_NESTED_EPT_CONTEXTS; i++) {
        if (g_NestedEptManager.Contexts[i].Initialized &&
            g_NestedEptManager.Contexts[i].L1Eptp == L1Eptp) {
            result = &g_NestedEptManager.Contexts[i];
            break;
        }
    }
    
    KeReleaseSpinLock(&g_NestedEptManager.Lock, oldIrql);
    return result;
#endif
}

PNESTED_EPT_CONTEXT NestedEptGetOrCreateContext(PVCPU_DATA VcpuData, ULONG64 L1Eptp)
{
    PNESTED_EPT_CONTEXT context;
    
    context = NestedEptFindContext(VcpuData, L1Eptp);
    if (context) {
        InterlockedIncrement(&context->RefCount);
        return context;
    }
    
    return NestedEptCreateContext(VcpuData, L1Eptp);
}

/*
 * 释放 EPT 上下文的引用
 * 当引用计数降为 0 时会自动销毁上下文
 */
VOID NestedEptReleaseContext(PNESTED_EPT_CONTEXT Context)
{
    if (Context) {
        NestedEptDestroyContext(Context);  // DestroyContext 会减少引用计数
    }
}

// ==================== L1 EPT 遍历 ====================

BOOLEAN NestedEptWalkL1Ept(
    PVCPU_DATA VcpuData,
    ULONG64 L1Eptp,
    ULONG64 L2Gpa,
    PULONG64 L1Gpa,
    PULONG64 Permissions,
    PULONG MemoryType,
    PULONG PageSize)
{
    ULONG64 pml4Pa, pdptPa, pdPa, ptPa;
    ULONG64 pml4e, pdpte, pde, pte;
    ULONG pml4Index, pdptIndex, pdIndex, ptIndex;
    ULONG64 pageOffset;
    ULONG64 perms = EPT_PERM_ALL;
    
    // 验证 EPTP
    if (L1Eptp == 0) {
        *L1Gpa = L2Gpa;  // 没有 L1 EPT，直通
        *Permissions = EPT_PERM_ALL;
        *MemoryType = EPT_MEMTYPE_WB;
        *PageSize = PAGE_SIZE;
        return TRUE;
    }
    
    // 计算索引
    pml4Index = (L2Gpa >> 39) & 0x1FF;
    pdptIndex = (L2Gpa >> 30) & 0x1FF;
    pdIndex = (L2Gpa >> 21) & 0x1FF;
    ptIndex = (L2Gpa >> 12) & 0x1FF;
    pageOffset = L2Gpa & 0xFFF;
    
    // 获取 PML4 基址
    pml4Pa = ((L1Eptp >> 12) << 12);
    
    // 读取 PML4E
    if (!NestedEptReadL1Entry(VcpuData, pml4Pa + pml4Index * 8, &pml4e)) {
        return FALSE;
    }
    
    // 检查 PML4E 是否存在
    if (!(pml4e & 0x7)) {
        return FALSE;  // 不存在
    }
    
    perms &= pml4e & 0x7;  // 合并权限
    
    // 读取 PDPTE
    pdptPa = (pml4e >> 12) << 12;
    if (!NestedEptReadL1Entry(VcpuData, pdptPa + pdptIndex * 8, &pdpte)) {
        return FALSE;
    }
    
    if (!(pdpte & 0x7)) {
        return FALSE;
    }
    
    perms &= pdpte & 0x7;
    
    // 检查 1GB 大页
    if (pdpte & EPT_LARGE_PAGE) {
        *L1Gpa = ((pdpte >> 30) << 30) | (L2Gpa & 0x3FFFFFFF);
        *Permissions = perms;
        *MemoryType = (pdpte >> 3) & 0x7;
        *PageSize = 1024 * 1024 * 1024;  // 1GB
        return TRUE;
    }
    
    // 读取 PDE
    pdPa = (pdpte >> 12) << 12;
    if (!NestedEptReadL1Entry(VcpuData, pdPa + pdIndex * 8, &pde)) {
        return FALSE;
    }
    
    if (!(pde & 0x7)) {
        return FALSE;
    }
    
    perms &= pde & 0x7;
    
    // 检查 2MB 大页
    if (pde & EPT_LARGE_PAGE) {
        *L1Gpa = ((pde >> 21) << 21) | (L2Gpa & 0x1FFFFF);
        *Permissions = perms;
        *MemoryType = (pde >> 3) & 0x7;
        *PageSize = 2 * 1024 * 1024;  // 2MB
        return TRUE;
    }
    
    // 读取 PTE
    ptPa = (pde >> 12) << 12;
    if (!NestedEptReadL1Entry(VcpuData, ptPa + ptIndex * 8, &pte)) {
        return FALSE;
    }
    
    if (!(pte & 0x7)) {
        return FALSE;
    }
    
    perms &= pte & 0x7;
    
    *L1Gpa = ((pte >> 12) << 12) | pageOffset;
    *Permissions = perms;
    *MemoryType = (pte >> 3) & 0x7;
    *PageSize = PAGE_SIZE;  // 4KB
    
    return TRUE;
}

// ==================== L0 EPT 翻译 ====================

BOOLEAN NestedEptTranslateL1GpaToHpa(
    PVCPU_DATA VcpuData,
    ULONG64 L1Gpa,
    PULONG64 Hpa,
    PULONG64 Permissions)
{
    PEPT_TABLES eptTables;
    ULONG pml4Index, pdptIndex, pdIndex, ptIndex;
    ULONG64 pageOffset;
    EPT_PML4E pml4e;
    EPT_PDPTE pdpte;
    EPT_PDE pde;
    EPT_PTE pte;
    ULONG64 perms = EPT_PERM_ALL;
    
    // 获取 L0 EPT 表
    eptTables = VcpuData->EptTables;
    
    // 如果 L0 没有 EPT，使用直通映射
    if (!eptTables || !eptTables->Pml4) {
        *Hpa = L1Gpa;
        *Permissions = EPT_PERM_ALL;
        return TRUE;
    }
    
    // 计算索引
    pml4Index = (L1Gpa >> 39) & 0x1FF;
    pdptIndex = (L1Gpa >> 30) & 0x1FF;
    pdIndex = (L1Gpa >> 21) & 0x1FF;
    ptIndex = (L1Gpa >> 12) & 0x1FF;
    pageOffset = L1Gpa & 0xFFF;
    
    // PML4E
    pml4e = eptTables->Pml4[pml4Index];
    if (!(pml4e.Value & 0x7)) {
        return FALSE;
    }
    perms &= pml4e.Value & 0x7;
    
    // PDPTE
    pdpte = eptTables->Pdpt[pdptIndex];
    if (!(pdpte.Value & 0x7)) {
        return FALSE;
    }
    perms &= pdpte.Value & 0x7;
    
    // 检查 1GB 大页（不太常见）
    // 简化处理，假设使用 2MB 大页
    
    // PDE
    pde = eptTables->Pd[pdptIndex][pdIndex];
    if (!(pde.Value & 0x7)) {
        return FALSE;
    }
    perms &= pde.Value & 0x7;
    
    // 检查 2MB 大页
    if (pde.Value & EPT_LARGE_PAGE) {
        *Hpa = ((pde.Value >> 21) << 21) | (L1Gpa & 0x1FFFFF);
        *Permissions = perms;
        return TRUE;
    }
    
    // A split L0 mapping must be resolved through the permanently tracked PT
    // VA.  Reconstructing a 2-MB address from a non-large PDE silently bypasses
    // EPT hooks and is architecturally incorrect.
    {
        PEPT_PTE splitPt = HvEptFindSplitPt(
            eptTables, pde.PageFrameNumber);
        if (!splitPt) return FALSE;
        pte = splitPt[ptIndex];
        if (!(pte.Value & 0x7)) return FALSE;
        perms &= pte.Value & 0x7;
        *Hpa = (pte.PageFrameNumber << PAGE_SHIFT) | pageOffset;
        *Permissions = perms;
    }
    
    return TRUE;
}

// ==================== 地址翻译（完整） ====================

BOOLEAN NestedEptTranslateAddress(
    PVCPU_DATA VcpuData,
    PNESTED_EPT_CONTEXT Context,
    ULONG64 L2Gpa,
    ULONG64 AccessType,
    PNESTED_EPT_TRANSLATION Result)
{
    NESTED_EPT_CACHE_ENTRY cacheEntry;
    ULONG64 l1Gpa, l1Perms, l0Perms;
    ULONG l1MemType, l1PageSize;
    ULONG64 hpa;
    
    RtlZeroMemory(Result, sizeof(NESTED_EPT_TRANSLATION));
    
    if (!Context || !Context->Valid) {
        Result->FailureReason = NESTED_EPT_FAIL_INVALID_L1_EPTP;
        return FALSE;
    }
    
    Context->TotalTranslations++;
    
    // 先查缓存
    if (NestedEptLookupCache(Context, L2Gpa, &cacheEntry)) {
        Context->CacheHits++;
        
        // 检查权限
        if ((AccessType & EPT_PERM_READ) && !(cacheEntry.Permissions & EPT_PERM_READ)) {
            Result->FailureReason = NESTED_EPT_FAIL_L1_NO_READ;
            return FALSE;
        }
        if ((AccessType & EPT_PERM_WRITE) && !(cacheEntry.Permissions & EPT_PERM_WRITE)) {
            Result->FailureReason = NESTED_EPT_FAIL_L1_NO_WRITE;
            return FALSE;
        }
        if ((AccessType & EPT_PERM_EXECUTE) && !(cacheEntry.Permissions & EPT_PERM_EXECUTE)) {
            Result->FailureReason = NESTED_EPT_FAIL_L1_NO_EXECUTE;
            return FALSE;
        }
        
        Result->Hpa = cacheEntry.Hpa;
        Result->MergedPermissions = cacheEntry.Permissions;
        Result->MemoryType = (ULONG)cacheEntry.MemoryType;
        Result->PageSize = cacheEntry.PageSize;
        Result->Success = TRUE;
        return TRUE;
    }
    
    Context->CacheMisses++;
    
    // 步骤1：L2 GPA -> L1 GPA（通过 L1 EPT）
    if (!NestedEptWalkL1Ept(VcpuData, Context->L1Eptp, L2Gpa, 
                           &l1Gpa, &l1Perms, &l1MemType, &l1PageSize)) {
        Result->FailureReason = NESTED_EPT_FAIL_L1_NOT_PRESENT;
        return FALSE;
    }
    
    Result->L1Gpa = l1Gpa;
    Result->L1Permissions = l1Perms;
    
    // 检查 L1 权限
    if ((AccessType & EPT_PERM_READ) && !(l1Perms & EPT_PERM_READ)) {
        Result->FailureReason = NESTED_EPT_FAIL_L1_NO_READ;
        return FALSE;
    }
    if ((AccessType & EPT_PERM_WRITE) && !(l1Perms & EPT_PERM_WRITE)) {
        Result->FailureReason = NESTED_EPT_FAIL_L1_NO_WRITE;
        return FALSE;
    }
    if ((AccessType & EPT_PERM_EXECUTE) && !(l1Perms & EPT_PERM_EXECUTE)) {
        Result->FailureReason = NESTED_EPT_FAIL_L1_NO_EXECUTE;
        return FALSE;
    }
    
    // 步骤2：L1 GPA -> HPA（通过 L0 EPT）
    if (!NestedEptTranslateL1GpaToHpa(VcpuData, l1Gpa, &hpa, &l0Perms)) {
        Result->FailureReason = NESTED_EPT_FAIL_L0_NOT_PRESENT;
        return FALSE;
    }
    
    Result->Hpa = hpa;
    Result->L0Permissions = l0Perms;
    
    // 检查 L0 权限
    if ((AccessType & EPT_PERM_READ) && !(l0Perms & EPT_PERM_READ)) {
        Result->FailureReason = NESTED_EPT_FAIL_L0_NO_READ;
        return FALSE;
    }
    if ((AccessType & EPT_PERM_WRITE) && !(l0Perms & EPT_PERM_WRITE)) {
        Result->FailureReason = NESTED_EPT_FAIL_L0_NO_WRITE;
        return FALSE;
    }
    if ((AccessType & EPT_PERM_EXECUTE) && !(l0Perms & EPT_PERM_EXECUTE)) {
        Result->FailureReason = NESTED_EPT_FAIL_L0_NO_EXECUTE;
        return FALSE;
    }
    
    // 合并权限
    Result->MergedPermissions = NestedEptMergePermissions(l1Perms, l0Perms);
    Result->MemoryType = NestedEptMergeMemoryType(l1MemType, EPT_MEMTYPE_WB);
    Result->PageSize = l1PageSize;
    Result->Success = TRUE;
    
    // 更新缓存
    NestedEptUpdateCache(Context, L2Gpa, hpa, Result->MergedPermissions, 
                         Result->MemoryType, l1PageSize);
    
    // 构建 EPT02 映射
    if (!NT_SUCCESS(NestedEptBuildMapping(
            Context,
            L2Gpa & ~(l1PageSize - 1),
            hpa & ~(l1PageSize - 1),
            Result->MergedPermissions,
            Result->MemoryType,
            l1PageSize))) {
        Result->Success = FALSE;
        Result->FailureReason = NESTED_EPT_FAIL_MEMORY_ERROR;
        HvNestedRecordEvent(
            VcpuData, HvNestedEventPoolExhausted, 'TPEN', L2Gpa, hpa);
        return FALSE;
    }
    
    return TRUE;
}

// ==================== EPT02 页表操作 ====================

/*
 * 分配并跟踪页表页（内部版本，调用者必须持有 Context->Lock）
 * 注意：此函数假设调用者已经持有锁
 */
static PVOID NestedEptAllocateTablePageLocked(PNESTED_EPT_CONTEXT Context, PPHYSICAL_ADDRESS PhysicalAddress)
{
    PVOID page;
    
    if (Context->AllocatedPageCount >= Context->MaxAllocatedPages) {
        return NULL;
    }
    
    page = Context->PreallocatedPages[Context->AllocatedPageCount];
    *PhysicalAddress =
        Context->PreallocatedPhysical[Context->AllocatedPageCount];
    Context->AllocatedPages[Context->AllocatedPageCount++] = page;
    RtlZeroMemory(page, PAGE_SIZE);
    
    return page;
}

NTSTATUS NestedEptBuildMapping(
    PNESTED_EPT_CONTEXT Context,
    ULONG64 L2Gpa,
    ULONG64 Hpa,
    ULONG64 Permissions,
    ULONG MemoryType,
    ULONG PageSize)
{
    ULONG pml4Index, pdptIndex, pdIndex, ptIndex;
    PEPT_PML4E pml4e;
    PEPT_PDPTE pdpt = NULL;
    PEPT_PDE pd = NULL;
    PEPT_PTE pt = NULL;
    PHYSICAL_ADDRESS pa;
    KIRQL oldIrql;
    BOOLEAN pdptMapped = FALSE, pdMapped = FALSE, ptMapped = FALSE;
    NTSTATUS status = STATUS_SUCCESS;
    
    if (!Context || !Context->Pml4) {
        return STATUS_INVALID_PARAMETER;
    }
    
    KeAcquireSpinLock(&Context->Lock, &oldIrql);
    
    // 计算索引
    pml4Index = (L2Gpa >> 39) & 0x1FF;
    pdptIndex = (L2Gpa >> 30) & 0x1FF;
    pdIndex = (L2Gpa >> 21) & 0x1FF;
    ptIndex = (L2Gpa >> 12) & 0x1FF;
    
    // PML4E
    pml4e = &Context->Pml4[pml4Index];
    if (!(pml4e->Value & 0x7)) {
        // 分配 PDPT（新分配的页直接在虚拟地址，不需要映射）
        pdpt = (PEPT_PDPTE)NestedEptAllocateTablePageLocked(Context, &pa);
        if (!pdpt) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto cleanup;
        }
        pml4e->Value = (pa.QuadPart & ~0xFFFULL) | EPT_PERM_ALL;
    } else {
        pdpt = (PEPT_PDPTE)NestedEptMapPhysicalPage(pml4e->Value & ~0xFFFULL);
        if (!pdpt) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto cleanup;
        }
        pdptMapped = TRUE;
    }
    
    // 1GB 大页
    if (PageSize >= (1024 * 1024 * 1024)) {
        pdpt[pdptIndex].Value = (Hpa & ~0x3FFFFFFFULL) | 
                                 (MemoryType << 3) | 
                                 EPT_LARGE_PAGE | 
                                 Permissions;
        goto cleanup;
    }
    
    // PDPTE
    if (!(pdpt[pdptIndex].Value & 0x7)) {
        // 分配 PD
        pd = (PEPT_PDE)NestedEptAllocateTablePageLocked(Context, &pa);
        if (!pd) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto cleanup;
        }
        pdpt[pdptIndex].Value = (pa.QuadPart & ~0xFFFULL) | EPT_PERM_ALL;
    } else {
        pd = (PEPT_PDE)NestedEptMapPhysicalPage(pdpt[pdptIndex].Value & ~0xFFFULL);
        if (!pd) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto cleanup;
        }
        pdMapped = TRUE;
    }
    
    // 2MB 大页
    if (PageSize >= (2 * 1024 * 1024)) {
        pd[pdIndex].Value = (Hpa & ~0x1FFFFFULL) | 
                            (MemoryType << 3) | 
                            EPT_LARGE_PAGE | 
                            Permissions;
        goto cleanup;
    }
    
    // PDE
    if (!(pd[pdIndex].Value & 0x7)) {
        // 分配 PT
        pt = (PEPT_PTE)NestedEptAllocateTablePageLocked(Context, &pa);
        if (!pt) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto cleanup;
        }
        pd[pdIndex].Value = (pa.QuadPart & ~0xFFFULL) | EPT_PERM_ALL;
    } else {
        pt = (PEPT_PTE)NestedEptMapPhysicalPage(pd[pdIndex].Value & ~0xFFFULL);
        if (!pt) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto cleanup;
        }
        ptMapped = TRUE;
    }
    
    // 4KB 页
    pt[ptIndex].Value = (Hpa & ~0xFFFULL) | 
                        (MemoryType << 3) | 
                        Permissions;

cleanup:
    // 取消映射已映射的页表页
    if (ptMapped && pt) {
        NestedEptUnmapPhysicalPage(pt);
    }
    if (pdMapped && pd) {
        NestedEptUnmapPhysicalPage(pd);
    }
    if (pdptMapped && pdpt) {
        NestedEptUnmapPhysicalPage(pdpt);
    }
    
    KeReleaseSpinLock(&Context->Lock, oldIrql);
    return status;
}

NTSTATUS NestedEptRemoveMapping(PNESTED_EPT_CONTEXT Context, ULONG64 L2Gpa)
{
    ULONG pml4Index, pdptIndex, pdIndex, ptIndex;
    PEPT_PDPTE pdpt = NULL;
    PEPT_PDE pd = NULL;
    PEPT_PTE pt = NULL;
    KIRQL oldIrql;
    NTSTATUS status = STATUS_SUCCESS;
    
    if (!Context || !Context->Pml4) {
        return STATUS_INVALID_PARAMETER;
    }
    
    KeAcquireSpinLock(&Context->Lock, &oldIrql);
    
    pml4Index = (L2Gpa >> 39) & 0x1FF;
    pdptIndex = (L2Gpa >> 30) & 0x1FF;
    pdIndex = (L2Gpa >> 21) & 0x1FF;
    ptIndex = (L2Gpa >> 12) & 0x1FF;
    
    if (!(Context->Pml4[pml4Index].Value & 0x7)) {
        status = STATUS_NOT_FOUND;
        goto cleanup;
    }
    
    pdpt = (PEPT_PDPTE)NestedEptMapPhysicalPage(Context->Pml4[pml4Index].Value & ~0xFFFULL);
    if (!pdpt) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto cleanup;
    }
    
    if (!(pdpt[pdptIndex].Value & 0x7)) {
        status = STATUS_NOT_FOUND;
        goto cleanup;
    }
    
    // 1GB 大页
    if (pdpt[pdptIndex].Value & EPT_LARGE_PAGE) {
        pdpt[pdptIndex].Value = 0;
        goto cleanup;
    }
    
    pd = (PEPT_PDE)NestedEptMapPhysicalPage(pdpt[pdptIndex].Value & ~0xFFFULL);
    if (!pd) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto cleanup;
    }
    
    if (!(pd[pdIndex].Value & 0x7)) {
        status = STATUS_NOT_FOUND;
        goto cleanup;
    }
    
    // 2MB 大页
    if (pd[pdIndex].Value & EPT_LARGE_PAGE) {
        pd[pdIndex].Value = 0;
        goto cleanup;
    }
    
    pt = (PEPT_PTE)NestedEptMapPhysicalPage(pd[pdIndex].Value & ~0xFFFULL);
    if (!pt) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto cleanup;
    }
    
    pt[ptIndex].Value = 0;

cleanup:
    // 取消映射
    if (pt) NestedEptUnmapPhysicalPage(pt);
    if (pd) NestedEptUnmapPhysicalPage(pd);
    if (pdpt) NestedEptUnmapPhysicalPage(pdpt);
    
    KeReleaseSpinLock(&Context->Lock, oldIrql);
    return status;
}

// ==================== EPT Violation 处理 ====================

BOOLEAN NestedEptHandleViolation(
    PVCPU_DATA VcpuData,
    ULONG64 L2Gpa,
    ULONG64 Qualification,
    PBOOLEAN InjectToL1)
{
    PNESTED_EPT_CONTEXT context;
    NESTED_EPT_TRANSLATION translation;
    ULONG64 accessType = 0;
    BOOLEAN result;
    BOOLEAN handled = TRUE;
    
    *InjectToL1 = FALSE;
    
    // 确定访问类型
    if (Qualification & 0x1) accessType |= EPT_PERM_READ;
    if (Qualification & 0x2) accessType |= EPT_PERM_WRITE;
    if (Qualification & 0x4) accessType |= EPT_PERM_EXECUTE;
    
    // 检查是否有 L1 EPT
    if (!VcpuData->NestedVmx.L1EptEnabled || VcpuData->NestedVmx.L1Eptp == 0) {
        // 没有 L1 EPT，这是 L0 的 EPT Violation
        return FALSE;  // 由调用者处理
    }
    
    // 获取嵌套 EPT 上下文
    context = NestedEptGetOrCreateContext(
        VcpuData, VcpuData->NestedVmx.L1Eptp);
    if (!context) {
        *InjectToL1 = TRUE;
        return TRUE;
    }
    
    context->EptViolations++;
    
    // 尝试翻译地址
    result = NestedEptTranslateAddress(VcpuData, context, L2Gpa, accessType, &translation);
    
    if (result && translation.Success) {
        // 翻译成功，映射已建立，可以继续执行
        // 无效化 TLB
        AsmInveptAllContexts();
        handled = TRUE;
        goto cleanup;
    }
    
    // 翻译失败，判断是 L1 还是 L0 的问题
    switch (translation.FailureReason) {
    case NESTED_EPT_FAIL_L1_NOT_PRESENT:
    case NESTED_EPT_FAIL_L1_NO_READ:
    case NESTED_EPT_FAIL_L1_NO_WRITE:
    case NESTED_EPT_FAIL_L1_NO_EXECUTE:
        // L1 EPT 问题，注入到 L1
        *InjectToL1 = TRUE;
        context->PageFaults++;
        handled = TRUE;
        goto cleanup;
        
    case NESTED_EPT_FAIL_L0_NOT_PRESENT:
    case NESTED_EPT_FAIL_L0_NO_READ:
    case NESTED_EPT_FAIL_L0_NO_WRITE:
    case NESTED_EPT_FAIL_L0_NO_EXECUTE:
        // L0 EPT 问题（可能是 Hook），由 L0 处理
        handled = FALSE;
        goto cleanup;
        
    default:
        // 其他错误，注入到 L1
        *InjectToL1 = TRUE;
        handled = TRUE;
        goto cleanup;
    }

cleanup:
    // 释放上下文引用
    NestedEptReleaseContext(context);
    return handled;
}

// ==================== TLB 无效化 ====================

VOID NestedEptInvalidateContext(PNESTED_EPT_CONTEXT Context)
{
    if (Context) {
        NestedEptInvalidateCache(Context);
    }
    AsmInveptAllContexts();
}

VOID NestedEptInvalidateAll(VOID)
{
    ULONG i;
    
    for (i = 0; i < MAX_NESTED_EPT_CONTEXTS; i++) {
        if (g_NestedEptManager.Contexts[i].Initialized) {
            NestedEptInvalidateCache(&g_NestedEptManager.Contexts[i]);
        }
    }
    
    AsmInveptAllContexts();
}

VOID NestedEptInvalidatePage(PNESTED_EPT_CONTEXT Context, ULONG64 L2Gpa)
{
    ULONG cacheIndex;
    
    if (!Context) {
        return;
    }
    
    // 无效化缓存条目
    cacheIndex = NestedEptCacheIndex(L2Gpa);
    if (Context->Cache[cacheIndex].Valid &&
        (Context->Cache[cacheIndex].L2Gpa & ~0xFFFULL) == (L2Gpa & ~0xFFFULL)) {
        Context->Cache[cacheIndex].Valid = FALSE;
    }
    
    // 从 EPT02 移除映射
    NestedEptRemoveMapping(Context, L2Gpa);
    
    // 无效化 TLB
    AsmInveptAllContexts();
}

// ==================== 缓存操作 ====================

VOID NestedEptInvalidateCache(PNESTED_EPT_CONTEXT Context)
{
    if (!Context) {
        return;
    }
    
    RtlZeroMemory(Context->Cache, sizeof(Context->Cache));
    Context->CacheHits = 0;
    Context->CacheMisses = 0;
}

BOOLEAN NestedEptLookupCache(
    PNESTED_EPT_CONTEXT Context,
    ULONG64 L2Gpa,
    PNESTED_EPT_CACHE_ENTRY Entry)
{
    ULONG index;
    ULONG64 pageBase;
    
    if (!Context) {
        return FALSE;
    }
    
    index = NestedEptCacheIndex(L2Gpa);
    
    if (!Context->Cache[index].Valid) {
        return FALSE;
    }
    
    // 根据页大小比较
    pageBase = L2Gpa & ~((ULONG64)Context->Cache[index].PageSize - 1);
    
    if (Context->Cache[index].L2Gpa == pageBase) {
        *Entry = Context->Cache[index];
        // 调整 HPA 以匹配页内偏移
        Entry->Hpa = Context->Cache[index].Hpa + (L2Gpa - pageBase);
        return TRUE;
    }
    
    return FALSE;
}

VOID NestedEptUpdateCache(
    PNESTED_EPT_CONTEXT Context,
    ULONG64 L2Gpa,
    ULONG64 Hpa,
    ULONG64 Permissions,
    ULONG MemoryType,
    ULONG PageSize)
{
    ULONG index;
    ULONG64 pageBase;
    
    if (!Context) {
        return;
    }
    
    index = NestedEptCacheIndex(L2Gpa);
    pageBase = L2Gpa & ~((ULONG64)PageSize - 1);
    
    Context->Cache[index].L2Gpa = pageBase;
    Context->Cache[index].Hpa = Hpa & ~((ULONG64)PageSize - 1);
    Context->Cache[index].Permissions = Permissions;
    Context->Cache[index].MemoryType = MemoryType;
    Context->Cache[index].PageSize = PageSize;
    Context->Cache[index].LargePage = (PageSize > PAGE_SIZE);
    Context->Cache[index].Valid = TRUE;
}

// ==================== 权限和内存类型合并 ====================

ULONG64 NestedEptMergePermissions(ULONG64 L1Perm, ULONG64 L0Perm)
{
    // 权限取交集
    return L1Perm & L0Perm;
}

ULONG NestedEptMergeMemoryType(ULONG L1Type, ULONG L0Type)
{
    // 内存类型合并规则：
    // UC (0) 是最严格的，总是胜出
    // WC (1) 次之
    // 然后是 WT (4), WP (5), WB (6)
    
    // 简化规则：取较低的值（更严格）
    if (L1Type == EPT_MEMTYPE_UC || L0Type == EPT_MEMTYPE_UC) {
        return EPT_MEMTYPE_UC;
    }
    if (L1Type == EPT_MEMTYPE_WC || L0Type == EPT_MEMTYPE_WC) {
        return EPT_MEMTYPE_WC;
    }
    if (L1Type == EPT_MEMTYPE_WT || L0Type == EPT_MEMTYPE_WT) {
        return EPT_MEMTYPE_WT;
    }
    if (L1Type == EPT_MEMTYPE_WP || L0Type == EPT_MEMTYPE_WP) {
        return EPT_MEMTYPE_WP;
    }
    
    return EPT_MEMTYPE_WB;
}

// ==================== 调试和统计 ====================

VOID NestedEptPrintContextStats(PNESTED_EPT_CONTEXT Context)
{
    if (!Context) {
        return;
    }
    
    DbgPrint("[HV-NESTED-EPT] Context for L1 EPTP=0x%llX:\n", Context->L1Eptp);
    DbgPrint("  Total Translations: %llu\n", Context->TotalTranslations);
    DbgPrint("  EPT Violations: %llu\n", Context->EptViolations);
    DbgPrint("  Page Faults: %llu\n", Context->PageFaults);
    DbgPrint("  Cache Hits: %u\n", Context->CacheHits);
    DbgPrint("  Cache Misses: %u\n", Context->CacheMisses);
    DbgPrint("  Allocated Pages: %u\n", Context->AllocatedPageCount);
}

VOID NestedEptPrintGlobalStats(VOID)
{
    DbgPrint("[HV-NESTED-EPT] Global Statistics:\n");
    DbgPrint("  Active Contexts: %u\n", g_NestedEptManager.ActiveCount);
    DbgPrint("  Total Created: %llu\n", g_NestedEptManager.TotalContextsCreated);
    DbgPrint("  Total Destroyed: %llu\n", g_NestedEptManager.TotalContextsDestroyed);
}
