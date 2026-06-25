/*
 * HvNestedNpt.h - 嵌套 NPT (Nested Page Tables) 完整实现
 * 
 * 嵌套 NPT 用于支持 L1 Hypervisor 在 AMD SVM 下的内存虚拟化。
 * 当 L1 为 L2 配置 NPT 时，需要将 L1 NPT 和 L0 NPT 合并。
 * 
 * 地址翻译链（与嵌套 EPT 类似）：
 *   L2 GPA (Guest Physical Address)
 *      ↓ [通过 L1 NPT (NPT12)]
 *   L1 GPA
 *      ↓ [通过 L0 NPT (NPT01)]
 *   HPA (Host Physical Address)
 * 
 * 我们构建 NPT02，直接实现 L2 GPA → HPA 的映射
 */

#ifndef _HV_NESTED_NPT_H_
#define _HV_NESTED_NPT_H_

#include "HvTypes.h"

// ==================== 嵌套 NPT 配置 ====================

// 嵌套 NPT 上下文最大数量
#define MAX_NESTED_NPT_CONTEXTS     16

// NPT 缓存条目数量
#define NESTED_NPT_CACHE_SIZE       256

// ==================== NPT 条目权限位（与 x86 页表类似） ====================

#define NPT_PERM_PRESENT            0x001
#define NPT_PERM_WRITE              0x002
#define NPT_PERM_USER               0x004
#define NPT_PERM_PWT                0x008
#define NPT_PERM_PCD                0x010
#define NPT_PERM_ACCESSED           0x020
#define NPT_PERM_DIRTY              0x040
#define NPT_PERM_LARGE_PAGE         0x080
#define NPT_PERM_GLOBAL             0x100
#define NPT_PERM_NX                 0x8000000000000000ULL

// ==================== 嵌套 NPT 数据结构 ====================

// NPT 缓存条目
typedef struct _NESTED_NPT_CACHE_ENTRY {
    ULONG64 L2Gpa;                  // L2 Guest Physical Address (页对齐)
    ULONG64 Hpa;                    // Host Physical Address
    ULONG64 Permissions;            // 合并后的权限
    BOOLEAN Valid;                  // 条目是否有效
    BOOLEAN LargePage;              // 是否为大页
    ULONG PageSize;                 // 页大小 (4KB, 2MB, 1GB)
} NESTED_NPT_CACHE_ENTRY, *PNESTED_NPT_CACHE_ENTRY;

// 嵌套 NPT 上下文
typedef struct _NESTED_NPT_CONTEXT {
    // L1 配置的 NCR3
    ULONG64 L1NCr3;
    
    // NPT02 页表（合并后的 NPT）
    PVOID Pml4;                     // PML4 表
    PHYSICAL_ADDRESS Pml4Physical;
    
    // 动态分配的页表页
    PVOID *AllocatedPages;
    ULONG AllocatedPageCount;
    ULONG MaxAllocatedPages;
    
    // 翻译缓存
    NESTED_NPT_CACHE_ENTRY Cache[NESTED_NPT_CACHE_SIZE];
    ULONG CacheHits;
    ULONG CacheMisses;
    
    // 统计信息
    ULONG64 TotalTranslations;
    ULONG64 NptFaults;
    ULONG64 PageFaults;
    
    // 状态
    BOOLEAN Initialized;
    BOOLEAN Valid;
    
    // 引用计数
    volatile LONG RefCount;
    
    // 自旋锁
    KSPIN_LOCK Lock;
} NESTED_NPT_CONTEXT, *PNESTED_NPT_CONTEXT;

// 嵌套 NPT 全局管理器
typedef struct _NESTED_NPT_MANAGER {
    NESTED_NPT_CONTEXT Contexts[MAX_NESTED_NPT_CONTEXTS];
    ULONG ActiveCount;
    ULONG64 TotalContextsCreated;
    ULONG64 TotalContextsDestroyed;
    KSPIN_LOCK Lock;
    BOOLEAN Initialized;
} NESTED_NPT_MANAGER, *PNESTED_NPT_MANAGER;

// NPT 翻译结果
typedef struct _NESTED_NPT_TRANSLATION {
    ULONG64 Hpa;                    // 翻译后的 HPA
    ULONG64 L1Gpa;                  // 中间的 L1 GPA
    ULONG64 L1Permissions;          // L1 NPT 的权限
    ULONG64 L0Permissions;          // L0 NPT 的权限
    ULONG64 MergedPermissions;      // 合并后的权限
    ULONG PageSize;                 // 页大小
    BOOLEAN Success;                // 翻译是否成功
    ULONG FailureReason;            // 失败原因
} NESTED_NPT_TRANSLATION, *PNESTED_NPT_TRANSLATION;

// 翻译失败原因
#define NESTED_NPT_FAIL_NONE                0
#define NESTED_NPT_FAIL_L1_NOT_PRESENT      1
#define NESTED_NPT_FAIL_L1_NO_WRITE         2
#define NESTED_NPT_FAIL_L1_NO_USER          3
#define NESTED_NPT_FAIL_L1_NX               4
#define NESTED_NPT_FAIL_L0_NOT_PRESENT      5
#define NESTED_NPT_FAIL_L0_NO_WRITE         6
#define NESTED_NPT_FAIL_L0_NO_USER          7
#define NESTED_NPT_FAIL_L0_NX               8
#define NESTED_NPT_FAIL_INVALID_NCR3        9
#define NESTED_NPT_FAIL_MEMORY_ERROR        10

// ==================== 函数声明 ====================

// 初始化和清理
NTSTATUS NestedNptInitialize(VOID);
VOID NestedNptCleanup(VOID);

// 上下文管理
PNESTED_NPT_CONTEXT NestedNptCreateContext(ULONG64 L1NCr3);
VOID NestedNptDestroyContext(PNESTED_NPT_CONTEXT Context);
VOID NestedNptReleaseContext(PNESTED_NPT_CONTEXT Context);  // 释放引用计数
PNESTED_NPT_CONTEXT NestedNptFindContext(ULONG64 L1NCr3);
PNESTED_NPT_CONTEXT NestedNptGetOrCreateContext(ULONG64 L1NCr3);

// 地址翻译
BOOLEAN NestedNptTranslateAddress(
    PVCPU_DATA VcpuData,
    PNESTED_NPT_CONTEXT Context,
    ULONG64 L2Gpa,
    ULONG64 AccessType,             // 访问类型（读/写/执行）
    PNESTED_NPT_TRANSLATION Result
);

// NPT02 页表操作
NTSTATUS NestedNptBuildMapping(
    PNESTED_NPT_CONTEXT Context,
    ULONG64 L2Gpa,
    ULONG64 Hpa,
    ULONG64 Permissions,
    ULONG PageSize
);

NTSTATUS NestedNptRemoveMapping(
    PNESTED_NPT_CONTEXT Context,
    ULONG64 L2Gpa
);

// L1 NPT 遍历
BOOLEAN NestedNptWalkL1Npt(
    PVCPU_DATA VcpuData,
    ULONG64 L1NCr3,
    ULONG64 L2Gpa,
    PULONG64 L1Gpa,
    PULONG64 Permissions,
    PULONG PageSize
);

// L0 NPT 翻译
BOOLEAN NestedNptTranslateL1GpaToHpa(
    PVCPU_DATA VcpuData,
    ULONG64 L1Gpa,
    PULONG64 Hpa,
    PULONG64 Permissions
);

// NPF 处理
BOOLEAN NestedNptHandleFault(
    PVCPU_DATA VcpuData,
    ULONG64 L2Gpa,
    ULONG64 ErrorCode,
    PBOOLEAN InjectToL1
);

// TLB 无效化
VOID NestedNptInvalidateContext(PNESTED_NPT_CONTEXT Context);
VOID NestedNptInvalidateAll(VOID);
VOID NestedNptInvalidatePage(PNESTED_NPT_CONTEXT Context, ULONG64 L2Gpa);

// 缓存操作
VOID NestedNptInvalidateCache(PNESTED_NPT_CONTEXT Context);
BOOLEAN NestedNptLookupCache(
    PNESTED_NPT_CONTEXT Context,
    ULONG64 L2Gpa,
    PNESTED_NPT_CACHE_ENTRY Entry
);
VOID NestedNptUpdateCache(
    PNESTED_NPT_CONTEXT Context,
    ULONG64 L2Gpa,
    ULONG64 Hpa,
    ULONG64 Permissions,
    ULONG PageSize
);

// 辅助函数
ULONG64 NestedNptMergePermissions(ULONG64 L1Perm, ULONG64 L0Perm);

// 调试和统计
VOID NestedNptPrintContextStats(PNESTED_NPT_CONTEXT Context);
VOID NestedNptPrintGlobalStats(VOID);

// 全局管理器
extern NESTED_NPT_MANAGER g_NestedNptManager;

#endif // _HV_NESTED_NPT_H_
