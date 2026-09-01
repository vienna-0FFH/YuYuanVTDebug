/*
 * HvNestedEpt.h - 嵌套 EPT (Extended Page Tables) 完整实现
 * 
 * 嵌套 EPT 用于支持 L1 Hypervisor 的内存虚拟化。
 * 当 L1 为 L2 配置 EPT 时，需要将 L1 EPT 和 L0 EPT 合并。
 * 
 * 地址翻译链：
 *   L2 GPA (Guest Physical Address)
 *      ↓ [通过 L1 EPT (EPT12)]
 *   L1 GPA
 *      ↓ [通过 L0 EPT (EPT01)]  
 *   HPA (Host Physical Address)
 * 
 * 我们构建 EPT02，直接实现 L2 GPA → HPA 的映射
 */

#ifndef _HV_NESTED_EPT_H_
#define _HV_NESTED_EPT_H_

#include "HvTypes.h"

// ==================== 嵌套 EPT 配置 ====================

// 嵌套 EPT 表的最大数量（每个 L1 VMCS 可能有不同的 EPT）
#define MAX_NESTED_EPT_CONTEXTS     64
#define NESTED_EPT_PREALLOC_PAGES   32

// EPT 缓存条目数量（用于加速地址翻译）
#define NESTED_EPT_CACHE_SIZE       256

// 是否启用惰性 EPT 构建（按需填充 EPT02）
#define NESTED_EPT_LAZY_BUILD       TRUE

// ==================== EPT 条目权限位 ====================

#define EPT_PERM_READ               0x01
#define EPT_PERM_WRITE              0x02
#define EPT_PERM_EXECUTE            0x04
#define EPT_PERM_USER_EXECUTE       0x400   // 用于 Mode-based execute control
#define EPT_PERM_ALL                (EPT_PERM_READ | EPT_PERM_WRITE | EPT_PERM_EXECUTE)

// EPT 大页标志
#define EPT_LARGE_PAGE              0x80

// EPT 内存类型
#define EPT_MEMTYPE_UC              0
#define EPT_MEMTYPE_WC              1
#define EPT_MEMTYPE_WT              4
#define EPT_MEMTYPE_WP              5
#define EPT_MEMTYPE_WB              6

// ==================== 嵌套 EPT 数据结构 ====================

// EPT 缓存条目（加速地址翻译）
typedef struct _NESTED_EPT_CACHE_ENTRY {
    ULONG64 L2Gpa;                  // L2 Guest Physical Address (页对齐)
    ULONG64 Hpa;                    // Host Physical Address
    ULONG64 Permissions;            // 合并后的权限
    ULONG64 MemoryType;             // 内存类型
    BOOLEAN Valid;                  // 条目是否有效
    BOOLEAN LargePage;              // 是否为大页
    ULONG PageSize;                 // 页大小 (4KB, 2MB, 1GB)
} NESTED_EPT_CACHE_ENTRY, *PNESTED_EPT_CACHE_ENTRY;

// 嵌套 EPT 上下文（每个 L1 EPT 配置对应一个）
typedef struct _NESTED_EPT_CONTEXT {
    // L1 配置的 EPTP
    ULONG64 L1Eptp;
    
    // EPT02 页表（合并后的 EPT）
    PEPT_PML4E Pml4;                // PML4 表（512 条目）
    PHYSICAL_ADDRESS Pml4Physical;
    
    // 动态分配的页表页
    PVOID *AllocatedPages;          // 已分配的页表页数组
    ULONG AllocatedPageCount;       // 已分配页数
    ULONG MaxAllocatedPages;        // 最大页数
    PVOID PreallocatedPages[NESTED_EPT_PREALLOC_PAGES];
    PHYSICAL_ADDRESS PreallocatedPhysical[NESTED_EPT_PREALLOC_PAGES];
    BOOLEAN Provisioned;
    ULONG OwnerProcessor;
    
    // 翻译缓存
    NESTED_EPT_CACHE_ENTRY Cache[NESTED_EPT_CACHE_SIZE];
    ULONG CacheHits;
    ULONG CacheMisses;
    
    // 统计信息
    ULONG64 TotalTranslations;
    ULONG64 EptViolations;
    ULONG64 PageFaults;
    
    // 状态
    BOOLEAN Initialized;
    BOOLEAN Valid;
    
    // 引用计数
    volatile LONG RefCount;
    
    // 用于同步的自旋锁
    KSPIN_LOCK Lock;
    volatile LONG RootLock;
} NESTED_EPT_CONTEXT, *PNESTED_EPT_CONTEXT;

// 嵌套 EPT 全局管理器
typedef struct _NESTED_EPT_MANAGER {
    // 上下文数组
    NESTED_EPT_CONTEXT Contexts[MAX_NESTED_EPT_CONTEXTS];
    
    // 当前活动的上下文数量
    ULONG ActiveCount;
    
    // 全局统计
    ULONG64 TotalContextsCreated;
    ULONG64 TotalContextsDestroyed;
    
    // 管理器锁
    KSPIN_LOCK Lock;
    
    // 初始化标志
    ULONG ProvisionedCount;
    volatile LONG RootLock;
    BOOLEAN Initialized;
} NESTED_EPT_MANAGER, *PNESTED_EPT_MANAGER;

// EPT 翻译结果
typedef struct _NESTED_EPT_TRANSLATION {
    ULONG64 Hpa;                    // 翻译后的 HPA
    ULONG64 L1Gpa;                  // 中间的 L1 GPA
    ULONG64 L1Permissions;          // L1 EPT 的权限
    ULONG64 L0Permissions;          // L0 EPT 的权限
    ULONG64 MergedPermissions;      // 合并后的权限
    ULONG MemoryType;               // 内存类型
    ULONG PageSize;                 // 页大小
    BOOLEAN Success;                // 翻译是否成功
    ULONG FailureReason;            // 失败原因
} NESTED_EPT_TRANSLATION, *PNESTED_EPT_TRANSLATION;

// 翻译失败原因
#define NESTED_EPT_FAIL_NONE                0
#define NESTED_EPT_FAIL_L1_NOT_PRESENT      1   // L1 EPT 条目不存在
#define NESTED_EPT_FAIL_L1_NO_READ          2   // L1 EPT 不允许读
#define NESTED_EPT_FAIL_L1_NO_WRITE         3   // L1 EPT 不允许写
#define NESTED_EPT_FAIL_L1_NO_EXECUTE       4   // L1 EPT 不允许执行
#define NESTED_EPT_FAIL_L0_NOT_PRESENT      5   // L0 EPT 条目不存在
#define NESTED_EPT_FAIL_L0_NO_READ          6   // L0 EPT 不允许读
#define NESTED_EPT_FAIL_L0_NO_WRITE         7   // L0 EPT 不允许写
#define NESTED_EPT_FAIL_L0_NO_EXECUTE       8   // L0 EPT 不允许执行
#define NESTED_EPT_FAIL_INVALID_L1_EPTP     9   // L1 EPTP 无效
#define NESTED_EPT_FAIL_MEMORY_ERROR        10  // 内存访问错误

// ==================== 函数声明 ====================

// 初始化和清理
NTSTATUS NestedEptInitialize(VOID);
VOID NestedEptCleanup(VOID);

// 上下文管理
PNESTED_EPT_CONTEXT NestedEptCreateContext(PVCPU_DATA VcpuData, ULONG64 L1Eptp);
VOID NestedEptDestroyContext(PNESTED_EPT_CONTEXT Context);
VOID NestedEptReleaseContext(PNESTED_EPT_CONTEXT Context);  // 释放引用计数
PNESTED_EPT_CONTEXT NestedEptFindContext(PVCPU_DATA VcpuData, ULONG64 L1Eptp);
PNESTED_EPT_CONTEXT NestedEptGetOrCreateContext(PVCPU_DATA VcpuData, ULONG64 L1Eptp);

// 地址翻译
BOOLEAN NestedEptTranslateAddress(
    PVCPU_DATA VcpuData,
    PNESTED_EPT_CONTEXT Context,
    ULONG64 L2Gpa,
    ULONG64 AccessType,             // EPT_PERM_READ/WRITE/EXECUTE
    PNESTED_EPT_TRANSLATION Result
);

// EPT02 页表操作
NTSTATUS NestedEptBuildMapping(
    PNESTED_EPT_CONTEXT Context,
    ULONG64 L2Gpa,
    ULONG64 Hpa,
    ULONG64 Permissions,
    ULONG MemoryType,
    ULONG PageSize
);

NTSTATUS NestedEptRemoveMapping(
    PNESTED_EPT_CONTEXT Context,
    ULONG64 L2Gpa
);

// L1 EPT 遍历
BOOLEAN NestedEptWalkL1Ept(
    PVCPU_DATA VcpuData,
    ULONG64 L1Eptp,
    ULONG64 L2Gpa,
    PULONG64 L1Gpa,
    PULONG64 Permissions,
    PULONG MemoryType,
    PULONG PageSize
);

// L0 EPT 翻译（使用现有 EPT）
BOOLEAN NestedEptTranslateL1GpaToHpa(
    PVCPU_DATA VcpuData,
    ULONG64 L1Gpa,
    PULONG64 Hpa,
    PULONG64 Permissions
);

// EPT Violation 处理
BOOLEAN NestedEptHandleViolation(
    PVCPU_DATA VcpuData,
    ULONG64 L2Gpa,
    ULONG64 Qualification,
    PBOOLEAN InjectToL1
);

// TLB 无效化
VOID NestedEptInvalidateContext(PNESTED_EPT_CONTEXT Context);
VOID NestedEptInvalidateAll(VOID);
VOID NestedEptInvalidatePage(PNESTED_EPT_CONTEXT Context, ULONG64 L2Gpa);

// 缓存操作
VOID NestedEptInvalidateCache(PNESTED_EPT_CONTEXT Context);
BOOLEAN NestedEptLookupCache(
    PNESTED_EPT_CONTEXT Context,
    ULONG64 L2Gpa,
    PNESTED_EPT_CACHE_ENTRY Entry
);
VOID NestedEptUpdateCache(
    PNESTED_EPT_CONTEXT Context,
    ULONG64 L2Gpa,
    ULONG64 Hpa,
    ULONG64 Permissions,
    ULONG MemoryType,
    ULONG PageSize
);

// 辅助函数
ULONG64 NestedEptMergePermissions(ULONG64 L1Perm, ULONG64 L0Perm);
ULONG NestedEptMergeMemoryType(ULONG L1Type, ULONG L0Type);

// 调试和统计
VOID NestedEptPrintContextStats(PNESTED_EPT_CONTEXT Context);
VOID NestedEptPrintGlobalStats(VOID);

// 全局管理器
extern NESTED_EPT_MANAGER g_NestedEptManager;

#endif // _HV_NESTED_EPT_H_
