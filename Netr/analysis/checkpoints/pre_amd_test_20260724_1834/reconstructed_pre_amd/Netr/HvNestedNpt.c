/*
 * HvNestedNpt.c - 嵌套 NPT (Nested Page Tables) 完整实现
 * 
 * 实现完整的嵌套 NPT 支持，包括：
 * - NPT02 页表构建和管理
 * - L1 NPT 遍历和地址翻译
 * - L0 和 L1 NPT 权限合并
 * - NPT Fault 处理和注入
 * - 翻译缓存加速
 */

#include "HvNestedNpt.h"
#include "HvNested.h"
#include "HvNestedSvm.h"
#include "HvNpt.h"
#include "NptHook.h"
#include "HvCompat.h"

// P122: 全 driver DbgPrint → GUI ring
#define HV_TRACE_THIS_CAT HV_TRACE_CAT_NESTED
#include "HvTrace.h"

static __forceinline VOID NestedNptRootLock(_Inout_ volatile LONG* Lock)
{
    while (InterlockedCompareExchange(Lock, 1, 0) != 0) {
        _mm_pause();
    }
}

static __forceinline VOID NestedNptRootUnlock(_Inout_ volatile LONG* Lock)
{
    InterlockedExchange(Lock, 0);
}

#undef KeAcquireSpinLock
#undef KeReleaseSpinLock
#define KeAcquireSpinLock(_Lock, _OldIrql) \
    do { *(_OldIrql) = 0; NestedNptRootLock((volatile LONG*)(_Lock)); } while (0)
#define KeReleaseSpinLock(_Lock, _OldIrql) \
    do { UNREFERENCED_PARAMETER(_OldIrql); NestedNptRootUnlock((volatile LONG*)(_Lock)); } while (0)

#undef DbgPrint
#define DbgPrint(...) ((void)0)

// ==================== 全局变量 ====================

NESTED_NPT_MANAGER g_NestedNptManager;

// ==================== 内部辅助函数 ====================

/*
 * 分配对齐的物理页
 */
static PVOID NestedNptAllocatePage(PPHYSICAL_ADDRESS PhysicalAddress)
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
static VOID NestedNptFreePage(PVOID VirtualAddress)
{
    if (VirtualAddress) {
        MmFreeContiguousMemory(VirtualAddress);
    }
}

/*
 * 从物理地址映射到虚拟地址
 */
static PVOID NestedNptMapPhysicalPage(ULONG64 PhysicalAddress)
{
    ULONG64 page = PhysicalAddress & ~0xFFFULL;

    for (ULONG i = 0; i < g_NestedNptManager.ProvisionedCount; ++i) {
        PNESTED_NPT_CONTEXT context = &g_NestedNptManager.Contexts[i];
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
static VOID NestedNptUnmapPhysicalPage(PVOID VirtualAddress)
{
    UNREFERENCED_PARAMETER(VirtualAddress);
}

/*
 * 读取 L1 NPT 条目
 */
static BOOLEAN NestedNptReadL1Entry(
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
static ULONG NestedNptCacheIndex(ULONG64 L2Gpa)
{
    ULONG64 pageNumber = L2Gpa >> 12;
    return (ULONG)(pageNumber % NESTED_NPT_CACHE_SIZE);
}

// ==================== 初始化和清理 ====================

NTSTATUS NestedNptInitialize(VOID)
{
    ULONG provisioned;
    NTSTATUS status = STATUS_SUCCESS;

    RtlZeroMemory(&g_NestedNptManager, sizeof(NESTED_NPT_MANAGER));
    KeInitializeSpinLock(&g_NestedNptManager.Lock);
    g_NestedNptManager.Initialized = TRUE;

    provisioned = g_HypervisorContext.ProcessorCount;
    if (provisioned == 0 || provisioned > MAX_NESTED_NPT_CONTEXTS) {
        g_NestedNptManager.Initialized = FALSE;
        return STATUS_NOT_SUPPORTED;
    }

    for (ULONG i = 0; i < provisioned; ++i) {
        PNESTED_NPT_CONTEXT context = &g_NestedNptManager.Contexts[i];

        KeInitializeSpinLock(&context->Lock);
        context->OwnerProcessor = i;
        context->MaxAllocatedPages = NESTED_NPT_PREALLOC_PAGES;
        context->AllocatedPages = context->PreallocatedPages;
        context->Provisioned = TRUE;
        g_NestedNptManager.ProvisionedCount = i + 1;
        context->Pml4 = NestedNptAllocatePage(&context->Pml4Physical);
        if (!context->Pml4) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto fail;
        }

        for (ULONG j = 0; j < NESTED_NPT_PREALLOC_PAGES; ++j) {
            context->PreallocatedPages[j] = NestedNptAllocatePage(
                &context->PreallocatedPhysical[j]);
            if (!context->PreallocatedPages[j]) {
                status = STATUS_INSUFFICIENT_RESOURCES;
                goto fail;
            }
        }
    }

    return STATUS_SUCCESS;

fail:
    NestedNptCleanup();
    return status;
}

VOID NestedNptCleanup(VOID)
{
#if 1
    if (!g_NestedNptManager.Initialized) return;

    for (ULONG i = 0; i < g_NestedNptManager.ProvisionedCount; ++i) {
        PNESTED_NPT_CONTEXT context = &g_NestedNptManager.Contexts[i];
        if (context->Pml4) {
            NestedNptFreePage(context->Pml4);
            context->Pml4 = NULL;
        }
        for (ULONG j = 0; j < NESTED_NPT_PREALLOC_PAGES; ++j) {
            if (context->PreallocatedPages[j]) {
                NestedNptFreePage(context->PreallocatedPages[j]);
                context->PreallocatedPages[j] = NULL;
            }
            context->PreallocatedPhysical[j].QuadPart = 0;
        }
    }

    RtlZeroMemory(&g_NestedNptManager, sizeof(g_NestedNptManager));
    return;
#else
    KIRQL oldIrql;
    ULONG i;
    
    if (!g_NestedNptManager.Initialized) {
        return;
    }
    
    KeAcquireSpinLock(&g_NestedNptManager.Lock, &oldIrql);
    
    for (i = 0; i < MAX_NESTED_NPT_CONTEXTS; i++) {
        if (g_NestedNptManager.Contexts[i].Initialized) {
            PNESTED_NPT_CONTEXT ctx = &g_NestedNptManager.Contexts[i];
            
            if (ctx->Pml4) {
                NestedNptFreePage(ctx->Pml4);
            }
            
            if (ctx->AllocatedPages) {
                for (ULONG j = 0; j < ctx->AllocatedPageCount; j++) {
                    if (ctx->AllocatedPages[j]) {
                        NestedNptFreePage(ctx->AllocatedPages[j]);
                    }
                }
                ExFreePoolWithTag(ctx->AllocatedPages, 'NNPT');
            }
            
            ctx->Initialized = FALSE;
        }
    }
    
    g_NestedNptManager.Initialized = FALSE;
    KeReleaseSpinLock(&g_NestedNptManager.Lock, oldIrql);
    
    DbgPrint("[HV-NESTED-NPT] Nested NPT manager cleaned up\n");
#endif
}

// ==================== 上下文管理 ====================

PNESTED_NPT_CONTEXT NestedNptCreateContext(PVCPU_DATA VcpuData, ULONG64 L1NCr3)
{
#if 1
    PNESTED_NPT_CONTEXT context = NULL;

    if (!VcpuData ||
        VcpuData->ProcessorNumber >= g_NestedNptManager.ProvisionedCount ||
        !g_NestedNptManager.Initialized ||
        (L1NCr3 & 0xFFFULL) != 0 || L1NCr3 == 0) {
        return NULL;
    }

    NestedNptRootLock(&g_NestedNptManager.RootLock);
    context = &g_NestedNptManager.Contexts[VcpuData->ProcessorNumber];
    if (!context->Provisioned || context->Initialized ||
        context->OwnerProcessor != VcpuData->ProcessorNumber) {
        context = NULL;
    }

    if (context) {
        RtlZeroMemory(context->Pml4, PAGE_SIZE);
        RtlZeroMemory(context->Cache, sizeof(context->Cache));
        context->L1NCr3 = L1NCr3;
        context->AllocatedPageCount = 0;
        context->CacheHits = 0;
        context->CacheMisses = 0;
        context->TotalTranslations = 0;
        context->NptFaults = 0;
        context->PageFaults = 0;
        context->RefCount = 1;
        context->Valid = TRUE;
        _WriteBarrier();
        context->Initialized = TRUE;
        g_NestedNptManager.ActiveCount++;
        g_NestedNptManager.TotalContextsCreated++;
    }
    NestedNptRootUnlock(&g_NestedNptManager.RootLock);

    if (!context) {
        HvNestedRecordEvent(NULL, HvNestedEventPoolExhausted, 'TPNN', L1NCr3, 0);
    }
    return context;
#else
    KIRQL oldIrql;
    PNESTED_NPT_CONTEXT context = NULL;
    ULONG i;
    
    if (!g_NestedNptManager.Initialized) {
        return NULL;
    }
    
    KeAcquireSpinLock(&g_NestedNptManager.Lock, &oldIrql);
    
    for (i = 0; i < MAX_NESTED_NPT_CONTEXTS; i++) {
        if (!g_NestedNptManager.Contexts[i].Initialized) {
            context = &g_NestedNptManager.Contexts[i];
            break;
        }
    }
    
    if (!context) {
        KeReleaseSpinLock(&g_NestedNptManager.Lock, oldIrql);
        DbgPrint("[HV-NESTED-NPT] No free context slot available\n");
        return NULL;
    }
    
    RtlZeroMemory(context, sizeof(NESTED_NPT_CONTEXT));
    context->L1NCr3 = L1NCr3;
    KeInitializeSpinLock(&context->Lock);
    
    // 分配 PML4 表
    context->Pml4 = NestedNptAllocatePage(&context->Pml4Physical);
    if (!context->Pml4) {
        KeReleaseSpinLock(&g_NestedNptManager.Lock, oldIrql);
        DbgPrint("[HV-NESTED-NPT] Failed to allocate PML4\n");
        return NULL;
    }
    
    // 分配页表页数组
    context->MaxAllocatedPages = 1024;
    context->AllocatedPages = (PVOID*)HvAllocateNonPagedZeroed(
        context->MaxAllocatedPages * sizeof(PVOID),
        'NNPT'
    );
    
    if (!context->AllocatedPages) {
        NestedNptFreePage(context->Pml4);
        context->Pml4 = NULL;
        KeReleaseSpinLock(&g_NestedNptManager.Lock, oldIrql);
        DbgPrint("[HV-NESTED-NPT] Failed to allocate page tracking array\n");
        return NULL;
    }
    context->AllocatedPageCount = 0;
    
    context->Initialized = TRUE;
    context->Valid = TRUE;
    context->RefCount = 1;
    
    g_NestedNptManager.ActiveCount++;
    g_NestedNptManager.TotalContextsCreated++;
    
    KeReleaseSpinLock(&g_NestedNptManager.Lock, oldIrql);
    
    DbgPrint("[HV-NESTED-NPT] Created context for L1 NCR3=0x%llX, PML4 PA=0x%llX\n",
             L1NCr3, context->Pml4Physical.QuadPart);
    
    return context;
#endif
}

VOID NestedNptDestroyContext(PNESTED_NPT_CONTEXT Context)
{
#if 1
    if (!Context || !Context->Initialized) return;
    if (InterlockedDecrement(&Context->RefCount) > 0) return;

    NestedNptRootLock(&g_NestedNptManager.RootLock);
    if (Context->Initialized && Context->RefCount == 0) {
        Context->Initialized = FALSE;
        _WriteBarrier();
        Context->Valid = FALSE;
        Context->L1NCr3 = 0;
        Context->AllocatedPageCount = 0;
        RtlZeroMemory(Context->Pml4, PAGE_SIZE);
        RtlZeroMemory(Context->Cache, sizeof(Context->Cache));
        if (g_NestedNptManager.ActiveCount != 0) {
            g_NestedNptManager.ActiveCount--;
        }
        g_NestedNptManager.TotalContextsDestroyed++;
    }
    NestedNptRootUnlock(&g_NestedNptManager.RootLock);
    return;
#else
    KIRQL oldIrql;
    ULONG i;
    
    if (!Context || !Context->Initialized) {
        return;
    }
    
    if (InterlockedDecrement(&Context->RefCount) > 0) {
        return;
    }
    
    KeAcquireSpinLock(&g_NestedNptManager.Lock, &oldIrql);
    
    DbgPrint("[HV-NESTED-NPT] Destroying context for L1 NCR3=0x%llX\n", Context->L1NCr3);
    
    if (Context->Pml4) {
        NestedNptFreePage(Context->Pml4);
        Context->Pml4 = NULL;
    }
    
    if (Context->AllocatedPages) {
        for (i = 0; i < Context->AllocatedPageCount; i++) {
            if (Context->AllocatedPages[i]) {
                NestedNptFreePage(Context->AllocatedPages[i]);
            }
        }
        ExFreePoolWithTag(Context->AllocatedPages, 'NNPT');
        Context->AllocatedPages = NULL;
    }
    
    Context->Initialized = FALSE;
    Context->Valid = FALSE;
    
    g_NestedNptManager.ActiveCount--;
    g_NestedNptManager.TotalContextsDestroyed++;
    
    KeReleaseSpinLock(&g_NestedNptManager.Lock, oldIrql);
#endif
}

PNESTED_NPT_CONTEXT NestedNptFindContext(PVCPU_DATA VcpuData, ULONG64 L1NCr3)
{
#if 1
    PNESTED_NPT_CONTEXT result = NULL;

    if (!VcpuData || !g_NestedNptManager.Initialized ||
        VcpuData->ProcessorNumber >= g_NestedNptManager.ProvisionedCount) {
        return NULL;
    }
    NestedNptRootLock(&g_NestedNptManager.RootLock);
    {
        PNESTED_NPT_CONTEXT candidate =
            &g_NestedNptManager.Contexts[VcpuData->ProcessorNumber];
        if (candidate->Initialized && candidate->Valid &&
            candidate->OwnerProcessor == VcpuData->ProcessorNumber &&
            candidate->L1NCr3 == L1NCr3) {
            result = candidate;
        }
    }
    NestedNptRootUnlock(&g_NestedNptManager.RootLock);
    return result;
#else
    KIRQL oldIrql;
    PNESTED_NPT_CONTEXT result = NULL;
    ULONG i;
    
    if (!g_NestedNptManager.Initialized) {
        return NULL;
    }
    
    KeAcquireSpinLock(&g_NestedNptManager.Lock, &oldIrql);
    
    for (i = 0; i < MAX_NESTED_NPT_CONTEXTS; i++) {
        if (g_NestedNptManager.Contexts[i].Initialized &&
            g_NestedNptManager.Contexts[i].L1NCr3 == L1NCr3) {
            result = &g_NestedNptManager.Contexts[i];
            break;
        }
    }
    
    KeReleaseSpinLock(&g_NestedNptManager.Lock, oldIrql);
    return result;
#endif
}

PNESTED_NPT_CONTEXT NestedNptGetOrCreateContext(PVCPU_DATA VcpuData, ULONG64 L1NCr3)
{
    PNESTED_NPT_CONTEXT context;
    
    context = NestedNptFindContext(VcpuData, L1NCr3);
    if (context) {
        InterlockedIncrement(&context->RefCount);
        return context;
    }
    
    return NestedNptCreateContext(VcpuData, L1NCr3);
}

/*
 * 释放 NPT 上下文的引用
 * 当引用计数降为 0 时会自动销毁上下文
 */
VOID NestedNptReleaseContext(PNESTED_NPT_CONTEXT Context)
{
    if (Context) {
        NestedNptDestroyContext(Context);  // DestroyContext 会减少引用计数
    }
}

// ==================== L1 NPT 遍历 ====================

BOOLEAN NestedNptWalkL1Npt(
    PVCPU_DATA VcpuData,
    ULONG64 L1NCr3,
    ULONG64 L2Gpa,
    PULONG64 L1Gpa,
    PULONG64 Permissions,
    PULONG PageSize)
{
    ULONG64 pml4Pa, pdptPa, pdPa, ptPa;
    ULONG64 pml4e, pdpte, pde, pte;
    ULONG pml4Index, pdptIndex, pdIndex, ptIndex;
    ULONG64 pageOffset;
    ULONG64 perms = NPT_PERM_PRESENT | NPT_PERM_WRITE | NPT_PERM_USER;
    
    // 验证 NCR3
    if (L1NCr3 == 0) {
        *L1Gpa = L2Gpa;
        *Permissions = perms;
        *PageSize = PAGE_SIZE;
        return TRUE;
    }
    
    // 计算索引
    pml4Index = (L2Gpa >> 39) & 0x1FF;
    pdptIndex = (L2Gpa >> 30) & 0x1FF;
    pdIndex = (L2Gpa >> 21) & 0x1FF;
    ptIndex = (L2Gpa >> 12) & 0x1FF;
    pageOffset = L2Gpa & 0xFFF;
    
    // PML4 基址
    pml4Pa = L1NCr3 & ~0xFFFULL;
    
    // 读取 PML4E
    if (!NestedNptReadL1Entry(VcpuData, pml4Pa + pml4Index * 8, &pml4e)) {
        return FALSE;
    }
    
    if (!(pml4e & NPT_PERM_PRESENT)) {
        return FALSE;
    }
    
    perms &= pml4e;
    
    // 读取 PDPTE
    pdptPa = pml4e & ~0xFFFULL & 0x000FFFFFFFFFF000ULL;
    if (!NestedNptReadL1Entry(VcpuData, pdptPa + pdptIndex * 8, &pdpte)) {
        return FALSE;
    }
    
    if (!(pdpte & NPT_PERM_PRESENT)) {
        return FALSE;
    }
    
    perms &= pdpte;
    
    // 检查 1GB 大页
    if (pdpte & NPT_PERM_LARGE_PAGE) {
        *L1Gpa = (pdpte & 0x000FFFFFC0000000ULL) | (L2Gpa & 0x3FFFFFFF);
        *Permissions = perms;
        *PageSize = 1024 * 1024 * 1024;
        return TRUE;
    }
    
    // 读取 PDE
    pdPa = pdpte & ~0xFFFULL & 0x000FFFFFFFFFF000ULL;
    if (!NestedNptReadL1Entry(VcpuData, pdPa + pdIndex * 8, &pde)) {
        return FALSE;
    }
    
    if (!(pde & NPT_PERM_PRESENT)) {
        return FALSE;
    }
    
    perms &= pde;
    
    // 检查 2MB 大页
    if (pde & NPT_PERM_LARGE_PAGE) {
        *L1Gpa = (pde & 0x000FFFFFFFE00000ULL) | (L2Gpa & 0x1FFFFF);
        *Permissions = perms;
        *PageSize = 2 * 1024 * 1024;
        return TRUE;
    }
    
    // 读取 PTE
    ptPa = pde & ~0xFFFULL & 0x000FFFFFFFFFF000ULL;
    if (!NestedNptReadL1Entry(VcpuData, ptPa + ptIndex * 8, &pte)) {
        return FALSE;
    }
    
    if (!(pte & NPT_PERM_PRESENT)) {
        return FALSE;
    }
    
    perms &= pte;
    
    *L1Gpa = (pte & 0x000FFFFFFFFFF000ULL) | pageOffset;
    *Permissions = perms;
    *PageSize = PAGE_SIZE;
    
    return TRUE;
}

// ==================== L0 NPT 翻译 ====================

BOOLEAN NestedNptTranslateL1GpaToHpa(
    PVCPU_DATA VcpuData,
    ULONG64 L1Gpa,
    PULONG64 Hpa,
    PULONG64 Permissions)
{
    PNPT_TABLES nptTables;
    ULONG pml4Index, pdptIndex, pdIndex, ptIndex;
    ULONG64 pageOffset;
    ULONG64 pml4e, pdpte, pde, pte;
    ULONG64 perms = NPT_PERM_PRESENT | NPT_PERM_WRITE | NPT_PERM_USER;
    
    nptTables = VcpuData->NptTables;
    
    if (!nptTables || !nptTables->Pml4) {
        *Hpa = L1Gpa;
        *Permissions = perms;
        return TRUE;
    }
    
    pml4Index = (L1Gpa >> 39) & 0x1FF;
    pdptIndex = (L1Gpa >> 30) & 0x1FF;
    pdIndex = (L1Gpa >> 21) & 0x1FF;
    ptIndex = (L1Gpa >> 12) & 0x1FF;
    pageOffset = L1Gpa & 0xFFF;
    
    // PML4E
    pml4e = nptTables->Pml4[pml4Index].Value;
    if (!(pml4e & NPT_PERM_PRESENT)) {
        return FALSE;
    }
    perms &= pml4e;
    
    // PDPTE
    pdpte = nptTables->Pdpt[pdptIndex].Value;
    if (!(pdpte & NPT_PERM_PRESENT)) {
        return FALSE;
    }
    perms &= pdpte;
    
    // PDE
    pde = nptTables->Pd[pdptIndex][pdIndex].Value;
    if (!(pde & NPT_PERM_PRESENT)) {
        return FALSE;
    }
    perms &= pde;
    
    // 检查 2MB 大页
    if (pde & NPT_PERM_LARGE_PAGE) {
        *Hpa = (pde & 0x000FFFFFFFE00000ULL) | (L1Gpa & 0x1FFFFF);
        *Permissions = perms;
        return TRUE;
    }
    
    {
        ULONG64 splitPfn = (pde & 0x000FFFFFFFFFF000ULL) >> PAGE_SHIFT;
        PNPT_PTE splitPt = NULL;

        for (ULONG i = 0; i < nptTables->SplitPtCount; ++i) {
            if (((ULONG64)nptTables->SplitPtPhysical[i].QuadPart >> PAGE_SHIFT) ==
                splitPfn) {
                splitPt = nptTables->SplitPt[i];
                break;
            }
        }
        if (!splitPt) return FALSE;
        pte = splitPt[ptIndex].Value;
        if (!(pte & NPT_PERM_PRESENT)) return FALSE;
        perms &= pte;
        *Hpa = (pte & 0x000FFFFFFFFFF000ULL) | pageOffset;
        *Permissions = perms;
    }
    
    return TRUE;
}

// ==================== 地址翻译（完整） ====================

BOOLEAN NestedNptTranslateAddress(
    PVCPU_DATA VcpuData,
    PNESTED_NPT_CONTEXT Context,
    ULONG64 L2Gpa,
    ULONG64 AccessType,
    PNESTED_NPT_TRANSLATION Result)
{
    NESTED_NPT_CACHE_ENTRY cacheEntry;
    ULONG64 l1Gpa, l1Perms, l0Perms;
    ULONG l1PageSize;
    ULONG64 hpa;
    
    RtlZeroMemory(Result, sizeof(NESTED_NPT_TRANSLATION));
    
    if (!Context || !Context->Valid) {
        Result->FailureReason = NESTED_NPT_FAIL_INVALID_NCR3;
        return FALSE;
    }
    
    Context->TotalTranslations++;
    
    // 查缓存
    if (NestedNptLookupCache(Context, L2Gpa, &cacheEntry)) {
        Context->CacheHits++;
        
        // 检查权限
        if ((AccessType & NPT_PERM_WRITE) && !(cacheEntry.Permissions & NPT_PERM_WRITE)) {
            Result->FailureReason = NESTED_NPT_FAIL_L1_NO_WRITE;
            return FALSE;
        }
        
        Result->Hpa = cacheEntry.Hpa;
        Result->MergedPermissions = cacheEntry.Permissions;
        Result->PageSize = cacheEntry.PageSize;
        Result->Success = TRUE;
        return TRUE;
    }
    
    Context->CacheMisses++;
    
    // 步骤1：L2 GPA -> L1 GPA
    if (!NestedNptWalkL1Npt(VcpuData, Context->L1NCr3, L2Gpa, 
                           &l1Gpa, &l1Perms, &l1PageSize)) {
        Result->FailureReason = NESTED_NPT_FAIL_L1_NOT_PRESENT;
        return FALSE;
    }
    
    Result->L1Gpa = l1Gpa;
    Result->L1Permissions = l1Perms;
    
    // 检查 L1 权限
    if (!(l1Perms & NPT_PERM_PRESENT)) {
        Result->FailureReason = NESTED_NPT_FAIL_L1_NOT_PRESENT;
        return FALSE;
    }
    if ((AccessType & NPT_PERM_WRITE) && !(l1Perms & NPT_PERM_WRITE)) {
        Result->FailureReason = NESTED_NPT_FAIL_L1_NO_WRITE;
        return FALSE;
    }
    
    // 步骤2：L1 GPA -> HPA
    if (!NestedNptTranslateL1GpaToHpa(VcpuData, l1Gpa, &hpa, &l0Perms)) {
        Result->FailureReason = NESTED_NPT_FAIL_L0_NOT_PRESENT;
        return FALSE;
    }
    
    Result->Hpa = hpa;
    Result->L0Permissions = l0Perms;
    
    // 检查 L0 权限
    if (!(l0Perms & NPT_PERM_PRESENT)) {
        Result->FailureReason = NESTED_NPT_FAIL_L0_NOT_PRESENT;
        return FALSE;
    }
    if ((AccessType & NPT_PERM_WRITE) && !(l0Perms & NPT_PERM_WRITE)) {
        Result->FailureReason = NESTED_NPT_FAIL_L0_NO_WRITE;
        return FALSE;
    }
    
    // 合并权限
    Result->MergedPermissions = NestedNptMergePermissions(l1Perms, l0Perms);
    Result->PageSize = l1PageSize;
    Result->Success = TRUE;
    
    // 更新缓存
    NestedNptUpdateCache(Context, L2Gpa, hpa, Result->MergedPermissions, l1PageSize);
    
    // 构建 NPT02 映射
    if (!NT_SUCCESS(NestedNptBuildMapping(
            Context,
            L2Gpa & ~((ULONG64)l1PageSize - 1),
            hpa & ~((ULONG64)l1PageSize - 1),
            Result->MergedPermissions,
            l1PageSize))) {
        Result->Success = FALSE;
        Result->FailureReason = NESTED_NPT_FAIL_MEMORY_ERROR;
        HvNestedRecordEvent(
            VcpuData, HvNestedEventPoolExhausted, 'TPNN', L2Gpa, hpa);
        return FALSE;
    }
    
    return TRUE;
}

// ==================== NPT02 页表操作 ====================

/*
 * 分配并跟踪页表页（内部版本，调用者必须持有 Context->Lock）
 */
static PVOID NestedNptAllocateTablePageLocked(PNESTED_NPT_CONTEXT Context, PPHYSICAL_ADDRESS PhysicalAddress)
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

NTSTATUS NestedNptBuildMapping(
    PNESTED_NPT_CONTEXT Context,
    ULONG64 L2Gpa,
    ULONG64 Hpa,
    ULONG64 Permissions,
    ULONG PageSize)
{
    ULONG pml4Index, pdptIndex, pdIndex, ptIndex;
    PULONG64 pml4, pdpt = NULL, pd = NULL, pt = NULL;
    PHYSICAL_ADDRESS pa;
    KIRQL oldIrql;
    BOOLEAN pdptMapped = FALSE, pdMapped = FALSE, ptMapped = FALSE;
    NTSTATUS status = STATUS_SUCCESS;
    
    if (!Context || !Context->Pml4) {
        return STATUS_INVALID_PARAMETER;
    }
    
    KeAcquireSpinLock(&Context->Lock, &oldIrql);
    
    pml4Index = (L2Gpa >> 39) & 0x1FF;
    pdptIndex = (L2Gpa >> 30) & 0x1FF;
    pdIndex = (L2Gpa >> 21) & 0x1FF;
    ptIndex = (L2Gpa >> 12) & 0x1FF;
    
    pml4 = (PULONG64)Context->Pml4;
    
    // PML4E
    if (!(pml4[pml4Index] & NPT_PERM_PRESENT)) {
        pdpt = (PULONG64)NestedNptAllocateTablePageLocked(Context, &pa);
        if (!pdpt) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto cleanup;
        }
        pml4[pml4Index] = (pa.QuadPart & ~0xFFFULL) | NPT_PERM_PRESENT | NPT_PERM_WRITE | NPT_PERM_USER;
    } else {
        pdpt = (PULONG64)NestedNptMapPhysicalPage(pml4[pml4Index] & ~0xFFFULL);
        if (!pdpt) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto cleanup;
        }
        pdptMapped = TRUE;
    }
    
    // 1GB 大页
    if (PageSize >= (1024 * 1024 * 1024)) {
        pdpt[pdptIndex] = (Hpa & 0x000FFFFFC0000000ULL) | NPT_PERM_LARGE_PAGE | Permissions;
        goto cleanup;
    }
    
    // PDPTE
    if (!(pdpt[pdptIndex] & NPT_PERM_PRESENT)) {
        pd = (PULONG64)NestedNptAllocateTablePageLocked(Context, &pa);
        if (!pd) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto cleanup;
        }
        pdpt[pdptIndex] = (pa.QuadPart & ~0xFFFULL) | NPT_PERM_PRESENT | NPT_PERM_WRITE | NPT_PERM_USER;
    } else {
        pd = (PULONG64)NestedNptMapPhysicalPage(pdpt[pdptIndex] & ~0xFFFULL);
        if (!pd) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto cleanup;
        }
        pdMapped = TRUE;
    }
    
    // 2MB 大页
    if (PageSize >= (2 * 1024 * 1024)) {
        pd[pdIndex] = (Hpa & 0x000FFFFFFFE00000ULL) | NPT_PERM_LARGE_PAGE | Permissions;
        goto cleanup;
    }
    
    // PDE
    if (!(pd[pdIndex] & NPT_PERM_PRESENT)) {
        pt = (PULONG64)NestedNptAllocateTablePageLocked(Context, &pa);
        if (!pt) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto cleanup;
        }
        pd[pdIndex] = (pa.QuadPart & ~0xFFFULL) | NPT_PERM_PRESENT | NPT_PERM_WRITE | NPT_PERM_USER;
    } else {
        pt = (PULONG64)NestedNptMapPhysicalPage(pd[pdIndex] & ~0xFFFULL);
        if (!pt) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto cleanup;
        }
        ptMapped = TRUE;
    }
    
    // 4KB 页
    pt[ptIndex] = (Hpa & 0x000FFFFFFFFFF000ULL) | Permissions;

cleanup:
    // 取消映射已映射的页表页
    if (ptMapped && pt) NestedNptUnmapPhysicalPage(pt);
    if (pdMapped && pd) NestedNptUnmapPhysicalPage(pd);
    if (pdptMapped && pdpt) NestedNptUnmapPhysicalPage(pdpt);
    
    KeReleaseSpinLock(&Context->Lock, oldIrql);
    return status;
}

NTSTATUS NestedNptRemoveMapping(PNESTED_NPT_CONTEXT Context, ULONG64 L2Gpa)
{
    ULONG pml4Index, pdptIndex, pdIndex, ptIndex;
    PULONG64 pml4, pdpt = NULL, pd = NULL, pt = NULL;
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
    
    pml4 = (PULONG64)Context->Pml4;
    
    if (!(pml4[pml4Index] & NPT_PERM_PRESENT)) {
        status = STATUS_NOT_FOUND;
        goto cleanup;
    }
    
    pdpt = (PULONG64)NestedNptMapPhysicalPage(pml4[pml4Index] & ~0xFFFULL);
    if (!pdpt) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto cleanup;
    }
    
    if (!(pdpt[pdptIndex] & NPT_PERM_PRESENT)) {
        status = STATUS_NOT_FOUND;
        goto cleanup;
    }
    
    if (pdpt[pdptIndex] & NPT_PERM_LARGE_PAGE) {
        pdpt[pdptIndex] = 0;
        goto cleanup;
    }
    
    pd = (PULONG64)NestedNptMapPhysicalPage(pdpt[pdptIndex] & ~0xFFFULL);
    if (!pd) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto cleanup;
    }
    
    if (!(pd[pdIndex] & NPT_PERM_PRESENT)) {
        status = STATUS_NOT_FOUND;
        goto cleanup;
    }
    
    if (pd[pdIndex] & NPT_PERM_LARGE_PAGE) {
        pd[pdIndex] = 0;
        goto cleanup;
    }
    
    pt = (PULONG64)NestedNptMapPhysicalPage(pd[pdIndex] & ~0xFFFULL);
    if (!pt) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto cleanup;
    }
    
    pt[ptIndex] = 0;

cleanup:
    // 取消映射
    if (pt) NestedNptUnmapPhysicalPage(pt);
    if (pd) NestedNptUnmapPhysicalPage(pd);
    if (pdpt) NestedNptUnmapPhysicalPage(pdpt);
    
    KeReleaseSpinLock(&Context->Lock, oldIrql);
    return status;
}

// ==================== NPF 处理 ====================

BOOLEAN NestedNptHandleFault(
    PVCPU_DATA VcpuData,
    ULONG64 L2Gpa,
    ULONG64 ErrorCode,
    PBOOLEAN InjectToL1)
{
    PNESTED_NPT_CONTEXT context;
    NESTED_NPT_TRANSLATION translation;
    ULONG64 accessType = 0;
    BOOLEAN result;
    BOOLEAN handled = TRUE;
    
    *InjectToL1 = FALSE;
    
    // 确定访问类型
    if (ErrorCode & 0x1) accessType |= NPT_PERM_PRESENT;
    if (ErrorCode & 0x2) accessType |= NPT_PERM_WRITE;
    if (ErrorCode & 0x4) accessType |= NPT_PERM_USER;
    
    // 检查是否有 L1 NPT
    if (!VcpuData->NestedSvm.L1NptEnabled || VcpuData->NestedSvm.L1NCr3 == 0) {
        return FALSE;
    }
    
    context = NestedNptGetOrCreateContext(
        VcpuData, VcpuData->NestedSvm.L1NCr3);
    if (!context) {
        *InjectToL1 = TRUE;
        return TRUE;
    }
    
    context->NptFaults++;
    
    result = NestedNptTranslateAddress(VcpuData, context, L2Gpa, accessType, &translation);
    
    if (result && translation.Success) {
        // 翻译成功，刷新 TLB
        if (VcpuData->Vmcb) {
            VcpuData->Vmcb->ControlArea.TlbControl =
                SVM_TLB_CONTROL_FLUSH_GUEST;
            VcpuData->Vmcb->ControlArea.VmcbCleanBits = 0;
        }
        handled = TRUE;
        goto cleanup;
    }
    
    switch (translation.FailureReason) {
    case NESTED_NPT_FAIL_L1_NOT_PRESENT:
    case NESTED_NPT_FAIL_L1_NO_WRITE:
    case NESTED_NPT_FAIL_L1_NO_USER:
    case NESTED_NPT_FAIL_L1_NX:
        *InjectToL1 = TRUE;
        context->PageFaults++;
        handled = TRUE;
        goto cleanup;
        
    case NESTED_NPT_FAIL_L0_NOT_PRESENT:
    case NESTED_NPT_FAIL_L0_NO_WRITE:
    case NESTED_NPT_FAIL_L0_NO_USER:
    case NESTED_NPT_FAIL_L0_NX:
        handled = FALSE;
        goto cleanup;
        
    default:
        *InjectToL1 = TRUE;
        handled = TRUE;
        goto cleanup;
    }

cleanup:
    // 释放上下文引用
    NestedNptReleaseContext(context);
    return handled;
}

// ==================== TLB 无效化 ====================

VOID NestedNptInvalidateContext(PNESTED_NPT_CONTEXT Context)
{
    if (Context) {
        NestedNptInvalidateCache(Context);
    }
    // AMD 使用 INVLPGA 或 ASID 切换来无效化 TLB
}

VOID NestedNptInvalidateAll(VOID)
{
    ULONG i;
    
    for (i = 0; i < MAX_NESTED_NPT_CONTEXTS; i++) {
        if (g_NestedNptManager.Contexts[i].Initialized) {
            NestedNptInvalidateCache(&g_NestedNptManager.Contexts[i]);
        }
    }
}

VOID NestedNptInvalidatePage(PNESTED_NPT_CONTEXT Context, ULONG64 L2Gpa)
{
    ULONG cacheIndex;
    
    if (!Context) {
        return;
    }
    
    cacheIndex = NestedNptCacheIndex(L2Gpa);
    if (Context->Cache[cacheIndex].Valid &&
        (Context->Cache[cacheIndex].L2Gpa & ~0xFFFULL) == (L2Gpa & ~0xFFFULL)) {
        Context->Cache[cacheIndex].Valid = FALSE;
    }
    
    NestedNptRemoveMapping(Context, L2Gpa);
    __invlpg((PVOID)L2Gpa);
}

// ==================== 缓存操作 ====================

VOID NestedNptInvalidateCache(PNESTED_NPT_CONTEXT Context)
{
    if (!Context) {
        return;
    }
    
    RtlZeroMemory(Context->Cache, sizeof(Context->Cache));
    Context->CacheHits = 0;
    Context->CacheMisses = 0;
}

BOOLEAN NestedNptLookupCache(
    PNESTED_NPT_CONTEXT Context,
    ULONG64 L2Gpa,
    PNESTED_NPT_CACHE_ENTRY Entry)
{
    ULONG index;
    ULONG64 pageBase;
    
    if (!Context) {
        return FALSE;
    }
    
    index = NestedNptCacheIndex(L2Gpa);
    
    if (!Context->Cache[index].Valid) {
        return FALSE;
    }
    
    pageBase = L2Gpa & ~((ULONG64)Context->Cache[index].PageSize - 1);
    
    if (Context->Cache[index].L2Gpa == pageBase) {
        *Entry = Context->Cache[index];
        Entry->Hpa = Context->Cache[index].Hpa + (L2Gpa - pageBase);
        return TRUE;
    }
    
    return FALSE;
}

VOID NestedNptUpdateCache(
    PNESTED_NPT_CONTEXT Context,
    ULONG64 L2Gpa,
    ULONG64 Hpa,
    ULONG64 Permissions,
    ULONG PageSize)
{
    ULONG index;
    ULONG64 pageBase;
    
    if (!Context) {
        return;
    }
    
    index = NestedNptCacheIndex(L2Gpa);
    pageBase = L2Gpa & ~((ULONG64)PageSize - 1);
    
    Context->Cache[index].L2Gpa = pageBase;
    Context->Cache[index].Hpa = Hpa & ~((ULONG64)PageSize - 1);
    Context->Cache[index].Permissions = Permissions;
    Context->Cache[index].PageSize = PageSize;
    Context->Cache[index].LargePage = (PageSize > PAGE_SIZE);
    Context->Cache[index].Valid = TRUE;
}

// ==================== 权限合并 ====================

ULONG64 NestedNptMergePermissions(ULONG64 L1Perm, ULONG64 L0Perm)
{
    // 权限取交集
    ULONG64 result = 0;
    
    // Present 位
    if ((L1Perm & NPT_PERM_PRESENT) && (L0Perm & NPT_PERM_PRESENT)) {
        result |= NPT_PERM_PRESENT;
    }
    
    // Write 位
    if ((L1Perm & NPT_PERM_WRITE) && (L0Perm & NPT_PERM_WRITE)) {
        result |= NPT_PERM_WRITE;
    }
    
    // User 位
    if ((L1Perm & NPT_PERM_USER) && (L0Perm & NPT_PERM_USER)) {
        result |= NPT_PERM_USER;
    }
    
    // NX 位（取并集，任一不可执行则不可执行）
    if ((L1Perm & NPT_PERM_NX) || (L0Perm & NPT_PERM_NX)) {
        result |= NPT_PERM_NX;
    }
    
    return result;
}

// ==================== 调试和统计 ====================

VOID NestedNptPrintContextStats(PNESTED_NPT_CONTEXT Context)
{
    if (!Context) {
        return;
    }
    
    DbgPrint("[HV-NESTED-NPT] Context for L1 NCR3=0x%llX:\n", Context->L1NCr3);
    DbgPrint("  Total Translations: %llu\n", Context->TotalTranslations);
    DbgPrint("  NPT Faults: %llu\n", Context->NptFaults);
    DbgPrint("  Page Faults: %llu\n", Context->PageFaults);
    DbgPrint("  Cache Hits: %u\n", Context->CacheHits);
    DbgPrint("  Cache Misses: %u\n", Context->CacheMisses);
    DbgPrint("  Allocated Pages: %u\n", Context->AllocatedPageCount);
}

VOID NestedNptPrintGlobalStats(VOID)
{
    DbgPrint("[HV-NESTED-NPT] Global Statistics:\n");
    DbgPrint("  Active Contexts: %u\n", g_NestedNptManager.ActiveCount);
    DbgPrint("  Total Created: %llu\n", g_NestedNptManager.TotalContextsCreated);
    DbgPrint("  Total Destroyed: %llu\n", g_NestedNptManager.TotalContextsDestroyed);
}
