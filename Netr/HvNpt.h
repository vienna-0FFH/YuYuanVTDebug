/*
 * HvNpt.h - AMD NPT (Nested Page Tables) 实现
 * 
 * NPT 与 Intel EPT 类似，但使用标准 x86-64 页表格式
 */

#ifndef _HV_NPT_H_
#define _HV_NPT_H_

#include "HvTypes.h"

// ==================== NPT 常量 ====================

// 页面属性
#define NPT_PRESENT         (1ULL << 0)
#define NPT_WRITE           (1ULL << 1)
#define NPT_USER            (1ULL << 2)
#define NPT_WRITE_THROUGH   (1ULL << 3)
#define NPT_CACHE_DISABLE   (1ULL << 4)
#define NPT_ACCESSED        (1ULL << 5)
#define NPT_DIRTY           (1ULL << 6)
#define NPT_LARGE_PAGE      (1ULL << 7)     // PS bit for 2MB/1GB pages
#define NPT_GLOBAL          (1ULL << 8)
#define NPT_NO_EXECUTE      (1ULL << 63)

// 内存类型 (通过 PAT 控制)
#define NPT_PAT             (1ULL << 7)     // PAT bit for 4KB pages
#define NPT_PAT_LARGE       (1ULL << 12)    // PAT bit for large pages

// ==================== NPT 页表项结构 ====================

// NPT PML4E (Page Map Level 4 Entry)
typedef union _NPT_PML4E {
    ULONG64 Value;
    struct {
        ULONG64 Present : 1;            // [0] P
        ULONG64 Write : 1;              // [1] R/W
        ULONG64 User : 1;               // [2] U/S
        ULONG64 WriteThrough : 1;       // [3] PWT
        ULONG64 CacheDisable : 1;       // [4] PCD
        ULONG64 Accessed : 1;           // [5] A
        ULONG64 Ignored1 : 1;           // [6]
        ULONG64 Reserved1 : 1;          // [7] Must be 0
        ULONG64 Ignored2 : 4;           // [8:11]
        ULONG64 PageFrameNumber : 40;   // [12:51] PFN
        ULONG64 Ignored3 : 11;          // [52:62]
        ULONG64 NoExecute : 1;          // [63] NX
    };
} NPT_PML4E, *PNPT_PML4E;

// NPT PDPTE (Page Directory Pointer Table Entry)
typedef union _NPT_PDPTE {
    ULONG64 Value;
    struct {
        ULONG64 Present : 1;            // [0] P
        ULONG64 Write : 1;              // [1] R/W
        ULONG64 User : 1;               // [2] U/S
        ULONG64 WriteThrough : 1;       // [3] PWT
        ULONG64 CacheDisable : 1;       // [4] PCD
        ULONG64 Accessed : 1;           // [5] A
        ULONG64 Ignored1 : 1;           // [6]
        ULONG64 LargePage : 1;          // [7] PS (1GB page if 1)
        ULONG64 Ignored2 : 4;           // [8:11]
        ULONG64 PageFrameNumber : 40;   // [12:51] PFN
        ULONG64 Ignored3 : 11;          // [52:62]
        ULONG64 NoExecute : 1;          // [63] NX
    };
} NPT_PDPTE, *PNPT_PDPTE;

// NPT PDE (Page Directory Entry)
typedef union _NPT_PDE {
    ULONG64 Value;
    struct {
        ULONG64 Present : 1;            // [0] P
        ULONG64 Write : 1;              // [1] R/W
        ULONG64 User : 1;               // [2] U/S
        ULONG64 WriteThrough : 1;       // [3] PWT
        ULONG64 CacheDisable : 1;       // [4] PCD
        ULONG64 Accessed : 1;           // [5] A
        ULONG64 Dirty : 1;              // [6] D (只对大页有效)
        ULONG64 LargePage : 1;          // [7] PS (2MB page if 1)
        ULONG64 Global : 1;             // [8] G
        ULONG64 Ignored1 : 3;           // [9:11]
        ULONG64 Pat : 1;                // [12] PAT (大页)
        ULONG64 Reserved1 : 8;          // [13:20] Must be 0 for 2MB pages
        ULONG64 PageFrameNumber : 31;   // [21:51] PFN for 2MB pages
        ULONG64 Ignored2 : 11;          // [52:62]
        ULONG64 NoExecute : 1;          // [63] NX
    } Large;
    struct {
        ULONG64 Present : 1;
        ULONG64 Write : 1;
        ULONG64 User : 1;
        ULONG64 WriteThrough : 1;
        ULONG64 CacheDisable : 1;
        ULONG64 Accessed : 1;
        ULONG64 Ignored1 : 1;
        ULONG64 LargePage : 1;          // Must be 0
        ULONG64 Ignored2 : 4;
        ULONG64 PageFrameNumber : 40;   // [12:51] PFN
        ULONG64 Ignored3 : 11;
        ULONG64 NoExecute : 1;
    } Small;
} NPT_PDE, *PNPT_PDE;

// NPT PTE (Page Table Entry)
typedef union _NPT_PTE {
    ULONG64 Value;
    struct {
        ULONG64 Present : 1;            // [0] P
        ULONG64 Write : 1;              // [1] R/W
        ULONG64 User : 1;               // [2] U/S
        ULONG64 WriteThrough : 1;       // [3] PWT
        ULONG64 CacheDisable : 1;       // [4] PCD
        ULONG64 Accessed : 1;           // [5] A
        ULONG64 Dirty : 1;              // [6] D
        ULONG64 Pat : 1;                // [7] PAT
        ULONG64 Global : 1;             // [8] G
        ULONG64 Ignored1 : 3;           // [9:11]
        ULONG64 PageFrameNumber : 40;   // [12:51] PFN
        ULONG64 Ignored2 : 11;          // [52:62]
        ULONG64 NoExecute : 1;          // [63] NX
    };
} NPT_PTE, *PNPT_PTE;

// ==================== NPT 页表结构 ====================

// NPT 页表集合
struct _NPT_TABLES {
    DECLSPEC_ALIGN(PAGE_SIZE) NPT_PML4E Pml4[512];
    DECLSPEC_ALIGN(PAGE_SIZE) NPT_PDPTE Pdpt[512];
    DECLSPEC_ALIGN(PAGE_SIZE) NPT_PDE Pd[512][512];  // PML4[0]: 512GB 用 2MB 大页
    PHYSICAL_ADDRESS Pml4Physical;
    PHYSICAL_ADDRESS PdptPhysical;
    // 用于需要 4KB 页的分割
    PNPT_PTE SplitPt[64];
    ULONG SplitPtCount;
    // 镜像 EPT 设计: PML4[1..3] 用 1GB 大页扩展到 2TB (HV_ENABLE_SVM_HARDENING)
    // 每个 ExtraPdpt[i] = 1 个分配的 PDPT 页, 512 个 1GB PDPTE
    PVOID ExtraPdpt[3];
    // 4KB split PT 的 HPA 缓存 (镜像 EPT_TABLES.SplitPtPhysical, root-mode 查找无 Mm* 调用)
    PHYSICAL_ADDRESS SplitPtPhysical[64];
};

// ==================== 函数声明 ====================

/*
 * 检查 NPT 支持
 * 检查 CPUID 和 MSR 以确认 CPU 支持 NPT
 */
BOOLEAN SvmCheckNptSupport(VOID);

/*
 * 检查 NX (No Execute) 位支持
 */
BOOLEAN SvmCheckNxSupport(VOID);

/*
 * 初始化 NPT 页表
 */
NTSTATUS SvmSetupNpt(PVCPU_DATA VcpuData);

/*
 * 构建 NPT 身份映射 (1:1 物理到物理映射)
 */
NTSTATUS SvmBuildNptIdentityMap(PVCPU_DATA VcpuData);

/*
 * 清理 NPT 页表
 */
VOID SvmCleanupNpt(PVCPU_DATA VcpuData);

/*
 * 刷新 NPT TLB
 */
VOID SvmInvalidateNptTlb(PVCPU_DATA VcpuData);

/*
 * 分割 2MB 大页为 4KB 页
 */
NTSTATUS SvmSplitNptLargePage(PVCPU_DATA VcpuData, ULONG64 PhysicalAddress);

/*
 * 修改 NPT 页权限
 */
VOID SvmSetNptPagePermissions(
    PVCPU_DATA VcpuData,
    ULONG64 PhysicalAddress,
    BOOLEAN Read,
    BOOLEAN Write,
    BOOLEAN Execute
);

#endif // _HV_NPT_H_
