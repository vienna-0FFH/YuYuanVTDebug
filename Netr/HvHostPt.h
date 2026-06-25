/*
 * HvHostPt.h — Step 4 (虚幻范式): host 自家页表 + 0..64GB 物理直通段映射
 *
 * 参考: D:/虚幻调试器源码/VT_Driver(4.2)/Globals.h:1126-1135 (host_page_tables 结构)
 *       D:/虚幻调试器源码/VT_Driver(4.2)/Globals.cpp:116-231 (map_physical_memory + prepare_host_page_tables)
 *
 * ============================================================
 * 设计目标
 * ============================================================
 *
 * host 路径任意 HPA → HVA 转换:
 *   HVA = host_physical_memory_base + HPA
 *   host_physical_memory_base = 255ULL << 39 = 0xFFFF_FF80_0000_0000 (canonical)
 *
 * 不再依赖:
 *   - MmGetVirtualForPhysical (需 user CR3 上下文)
 *   - MmMapIoSpace (慢, 且 KVAS 下可能 NULL)
 *   - PFN database 反查
 *
 * 代价: 264 KB 静态内存 (PML4 1 页 + PDPT 1 页 + 64 PD = 64 页)
 *
 * ============================================================
 * 页表布局
 * ============================================================
 *
 *   pml4[256..511]  ← memcpy 自 System PML4[256..511]  (kernel 半空间, driver/host stack/IDT 等)
 *   pml4[255]       → phys_pdpt  (我们的物理直通段, 占用 pml4 idx 255)
 *   pml4[0..254]    = 0  (user 半空间, host 不需要)
 *
 *   phys_pdpt[0..63] → phys_pds[0..63]  (64 GB 物理映射)
 *   phys_pdpt[64..511] = 0
 *
 *   phys_pds[i][j].large_page = 1, page_frame_number = (i<<9) + j
 *   → 每个 PDE 指向 PFN = i*512+j 的 2MB 大页 (HPA = (i*512+j)*2MB)
 *
 * ============================================================
 * 本步范围 (Step 4 仅建数据结构)
 * ============================================================
 *
 * - 分配 + 初始化 g_HvHostPt
 * - 不在 HvVmcs.c 切 HOST_CR3 (仍用 System CR3 — 现有路径不变)
 * - 不在 VtRoot 等模块替换物理 R/W 路径
 *
 * 装机验证不卡死后, 下一步 (Step 4b 可选) 再讨论:
 *   (a) 切 HOST_CR3 = HvHostPtGetCr3()  让 host 真在自家 PT 里跑
 *   (b) 在 VtRoot / EPT hook handler 里用 HV_HPA_TO_HVA() 替代 scratch PT 路径
 *
 * 但即使 (a)(b) 都不做, 本步起码:
 *   - 走通分配 + 物理映射 + PML4[256..] 拷贝路径
 *   - 验证 264 KB 连续分配在 Win10/Win11 都能拿到
 *   - 留下接口供 Step 5 (SymbolicAccess) 用 host PT 访问 PDB 解析需要的物理页
 *
 * ============================================================
 * IRQL / 上下文
 * ============================================================
 *
 *   HvHostPtInitialize   — PASSIVE (DriverEntry, 必须能调 MmGetPhysicalAddress
 *                          + MmGetVirtualForPhysical + KeStackAttachProcess(dwm))
 *   HvHostPtCleanup      — PASSIVE (DriverUnload)
 *   HV_HPA_TO_HVA        — 任意上下文, 纯算术
 */

#ifndef _HV_HOST_PT_H_
#define _HV_HOST_PT_H_

#include <ntddk.h>

// ============================================================
// 常量
// ============================================================

#define HV_HOST_PT_PML4_SLOT             255              // 占用 pml4 槽位 255
#define HV_HOST_PT_PHYS_BASE_VA          0xFFFFFF8000000000ULL  // 255 << 39, sign-extended canonical
#define HV_HOST_PT_PHYS_PD_COUNT         64               // 64 个 PD = 64 GB
#define HV_HOST_PT_PHYS_BYTES            (HV_HOST_PT_PHYS_PD_COUNT * (1ULL << 30))  // 64 GB

// ============================================================
// PTE 位布局 (host PT 用, 非 EPT)
// ============================================================

#define HV_PTE_PRESENT           (1ULL << 0)
#define HV_PTE_RW                (1ULL << 1)
#define HV_PTE_USER              (1ULL << 2)
#define HV_PTE_PWT               (1ULL << 3)
#define HV_PTE_PCD               (1ULL << 4)
#define HV_PTE_ACCESSED          (1ULL << 5)
#define HV_PTE_DIRTY             (1ULL << 6)
#define HV_PTE_PS                (1ULL << 7)              // 2MB / 1GB large page
#define HV_PTE_GLOBAL            (1ULL << 8)
#define HV_PTE_NX                (1ULL << 63)
#define HV_PTE_PFN_MASK          0x000FFFFFFFFFF000ULL

// ============================================================
// host_page_tables 结构 (虚幻范式 1:1)
//
// alignas(0x1000) 在 C 里用 DECLSPEC_ALIGN(PAGE_SIZE).
// 注意: 静态全局 264KB. NTOSKRNL 镜像 BSS 段大概率装得下, 但 WDK 限制
//       NonPagedPool 段不一定大. 实际走 ExAllocatePool2 动态分配.
// ============================================================

#pragma pack(push, 1)

typedef struct _HV_HOST_PT_PML4E {
    UINT64 Value;
} HV_HOST_PT_PML4E;

typedef struct _HV_HOST_PT_PDPTE {
    UINT64 Value;
} HV_HOST_PT_PDPTE;

typedef struct _HV_HOST_PT_PDE_2MB {
    UINT64 Value;
} HV_HOST_PT_PDE_2MB;

typedef struct _HV_HOST_PAGE_TABLES {
    HV_HOST_PT_PML4E   Pml4[512];                                    // 1 页
    HV_HOST_PT_PDPTE   PhysPdpt[512];                                // 1 页 (只用前 64)
    HV_HOST_PT_PDE_2MB PhysPds[HV_HOST_PT_PHYS_PD_COUNT][512];       // 64 页
} HV_HOST_PAGE_TABLES, *PHV_HOST_PAGE_TABLES;

#pragma pack(pop)

// 总大小 = 66 页 = 270336 字节
C_ASSERT(sizeof(HV_HOST_PAGE_TABLES) == (1 + 1 + HV_HOST_PT_PHYS_PD_COUNT) * 4096);

// ============================================================
// 全局
// ============================================================

extern PHV_HOST_PAGE_TABLES g_HvHostPt;            // VA, 4KB 对齐
extern UINT64                g_HvHostPtPa;          // pml4 的 HPA (可写入 HOST_CR3)
extern BOOLEAN               g_HvHostPtInitialized;

// ============================================================
// API
// ============================================================

/*
 * 在 DriverEntry 调 (PASSIVE).
 *   - 分配 264KB 连续 + 4KB 对齐
 *   - 填 pml4[255] → PhysPdpt
 *   - 填 PhysPdpt[0..63] → PhysPds[0..63]
 *   - 填 PhysPds[i][j].PFN = (i<<9)+j, large_page=1, P|RW|G|NX
 *   - 把 System PML4 的 [256..511] 256 项拷贝到 g_HvHostPt->Pml4[256..511]
 *
 * 失败时返回 STATUS_INSUFFICIENT_RESOURCES, g_HvHostPtInitialized = FALSE.
 * 调用方应继续走老路径 (现状是 System CR3 + VtRoot scratch).
 *
 * 注意: 不写 HOST_CR3 (那是 Step 4b 可选). 本函数只把数据结构建好.
 */
NTSTATUS HvHostPtInitialize(VOID);

/*
 * 在 DriverUnload 调 (PASSIVE).
 *   必须在 HvCleanup (VMXOFF) 之后调 — vCPU 仍在 root 时释放 PT 会让 vmexit
 *   访问已释放页 → triple fault.
 */
VOID HvHostPtCleanup(VOID);

/*
 * HOST_CR3 候选值 (Step 4b 才会真写 VMCS). 返回 pml4 的 HPA.
 * 未初始化时返回 0.
 */
UINT64 HvHostPtGetCr3(VOID);

/*
 * HPA → HVA 宏 (HPA 必须 < 64GB, 否则越界).
 * 纯算术, 任何上下文都能调.
 *
 * 用法示例 (Step 5 SymbolicAccess 会用):
 *   PUCHAR hva = HV_HPA_TO_HVA(MmGetPhysicalAddress(some_kernel_va).QuadPart);
 *
 * 安全检查: caller 必须保证 HPA < 64GB. 越界 cast 出来的 VA 落在我们 PT 没填的
 * pml4 槽位 → host #PF → AsmHostPfStub r10/r11 救生圈接住 (Step 1).
 */
static __forceinline PVOID HV_HPA_TO_HVA(UINT64 Hpa)
{
    return (PVOID)(HV_HOST_PT_PHYS_BASE_VA + Hpa);
}

/*
 * 边界检查版 (推荐用这个):
 *   返回 HVA, 或 NULL 表示 HPA 超出 64GB 段映射范围.
 */
static __forceinline PVOID HvHostPtHpaToHva(UINT64 Hpa)
{
    if (Hpa >= HV_HOST_PT_PHYS_BYTES) return NULL;
    return HV_HPA_TO_HVA(Hpa);
}

#endif // _HV_HOST_PT_H_
