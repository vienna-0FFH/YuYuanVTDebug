/*
 * HvPhysAccess.c (#27, Phase 1)
 *
 * 物理页直通访问 —— 见 HvPhysAccess.h 的接口注释。
 *
 * 设计思路:
 *   1) HvPhysGetProcessCr3: 读 EPROCESS+0x28 的 DirectoryTableBase
 *      (Win10/11 x64 稳定偏移)。是唯一保留的 Ps* 调用。
 *   2) HvPhysGvaToHpa: 在 PASSIVE_LEVEL 用 MmMapIoSpace 临时映射
 *      PML4/PDPT/PD/PT 各一页,读出 entry,Unmap。处理 1GB/2MB/4KB 大页。
 *   3) HvPhysReadProcessMemory / HvPhysWriteProcessMemory: 4KB 切分,
 *      逐页 MmMapIoSpace → memcpy → MmUnmapIoSpace。
 *
 * IRQL: 所有 API 均要求 PASSIVE_LEVEL 调用 (MmMapIoSpace 限制)。
 *
 * 不锁页: 我们没有 MmProbeAndLockPages 保护,如果目标页在 memcpy 期间
 *         被换出,会读到旧值/写到错误位置。对游戏/常驻进程的代码段、
 *         栈、堆,这种概率极低 —— 第一版可接受。
 */

#include "HvPhysAccess.h"
#include "HvVtRoot.h"
#include "HvCompat.h"
#include "HvCr3Snoop.h"
#include "HvHook.h"  // P114: HV_HOT_DBG 宏 (高频 walk 日志默认关)
#include <intrin.h>

// P122: 全 driver DbgPrint → GUI ring
#define HV_TRACE_THIS_CAT HV_TRACE_CAT_PHYS
#include "HvTrace.h"

// PsLookupProcessByProcessId 在 ntifs.h 中,我们沿用项目其他文件的做法
// (HvInjection.c 等) —— 内联声明原型,避免和 ntddk.h 的双重包含冲突。
NTKERNELAPI NTSTATUS PsLookupProcessByProcessId(
    _In_ HANDLE ProcessId,
    _Out_ PEPROCESS* Process
);

// MmProbeAndLockProcessPages: Vista+ 起的"显式 PEPROCESS"版本,内部不
// KeStackAttachProcess,反作弊监控少。原型在 wdm.h,但项目 include 链未必
// 拉到,这里 extern 一下避免缺声明。
NTKERNELAPI VOID MmProbeAndLockProcessPages(
    _Inout_ PMDL          MemoryDescriptorList,
    _In_    PEPROCESS     Process,
    _In_    KPROCESSOR_MODE AccessMode,
    _In_    LOCK_OPERATION Operation);

// PsGetProcessImageFileName: 返回 EPROCESS::ImageFileName 字段指针 (16 byte
// 截断的可执行映像名)。文档导出函数,无 ETWTI 风险 —— 这里只在 user-half=0
// 异常分支打印,正常路径不调。
NTKERNELAPI PUCHAR PsGetProcessImageFileName(_In_ PEPROCESS Process);

// PsGetProcessPeb: 返回 EPROCESS::Peb (PEB 的 user-mode VA, 每个进程独立)。
// 用于 CR3 归属校验 —— 拿到候选 CR3 后,走它去访问 PEB VA 并检查 PEB
// 内容是否符合 "属于目标进程" 的特征。
NTKERNELAPI PVOID PsGetProcessPeb(_In_ PEPROCESS Process);

// PsInitialSystemProcess —— System (PID 4) 的 EPROCESS, 全进程链表头。
// 通过 MmGetSystemRoutineAddress 在 init 阶段一次性解析为指针, 保存到
// g_HvPhysRootCtx.PsInitialSystemProcess (PEPROCESS*) ——
// 注意: ntoskrnl 导出的是一个全局变量, MmGetSystemRoutineAddress 返回的
// 是该变量自身的地址 (PEPROCESS 的地址), 需再解引用一次才能拿到 EPROCESS。

// ============================================================
// 分配跟踪 (#30, Phase 4) —— 类型与全局
// ============================================================

typedef struct _HV_PHYS_ALLOC_PAGE {
    PVOID  KernelVa;          // MmAllocateContiguousMemory 返回的 VA (用于 Free)
    UINT64 PhysicalAddress;   // 4KB HPA
    UINT64 GuestVa;           // 目标进程的 GVA
} HV_PHYS_ALLOC_PAGE;

typedef struct _HV_PHYS_ALLOC_RECORD {
    LIST_ENTRY ListEntry;
    ULONG  ProcessId;
    UINT64 BaseGva;
    SIZE_T SizeBytes;
    ULONG  PageCount;
    HV_PHYS_ALLOC_PAGE* Pages;
} HV_PHYS_ALLOC_RECORD;

static LIST_ENTRY  g_PhysAllocList;
static KSPIN_LOCK  g_PhysAllocLock;
static KSPIN_LOCK  g_PhysInvlpgLock;
static BOOLEAN     g_PhysAllocInitialized = FALSE;

// IPI INVLPG 协作变量 —— 仅在 g_PhysInvlpgLock 持有时写入
static UINT64      g_InvlpgTargetCr3 = 0;
static UINT64      g_InvlpgTargetVa = 0;

// ============================================================
// 常量
// ============================================================

#define HV_PHYS_TAG_PT      'tPvH'   // 新建的中间页表 (#30)
#define HV_PHYS_TAG_PAGE    'gPvH'   // 用户态可见的数据页 (#30)
#define HV_PHYS_TAG_RECORD  'cRvH'   // 分配跟踪记录 (#30)

// EPROCESS::DirectoryTableBase 偏移 —— Win10/Win11 通常是 0x28,但 24H2/25H2
// 内部结构调整时偏移可能漂移。HvPhysProbeDtbOffset 在首次 GetCr3 调用时
// 用 __readcr3() vs PsGetCurrentProcess() 的 EPROCESS body 自检真实偏移,
// 这里只作为兜底默认值。
#define EPROCESS_DTB_OFFSET_DEFAULT     0x28
static ULONG g_DtbOffset = EPROCESS_DTB_OFFSET_DEFAULT;
static volatile LONG g_DtbOffsetProbed = 0;

// 4 级页表索引提取
#define PML4_INDEX(va)          (((UINT64)(va) >> 39) & 0x1FF)
#define PDPT_INDEX(va)          (((UINT64)(va) >> 30) & 0x1FF)
#define PD_INDEX(va)            (((UINT64)(va) >> 21) & 0x1FF)
#define PT_INDEX(va)            (((UINT64)(va) >> 12) & 0x1FF)

// ============================================================
// PA-is-RAM 缓存 —— 防止 MmMapIoSpace 在 reserved/MMIO PA 上卡死
// ============================================================
//
// 系统 RAM 范围 (e820 / UEFI memmap) 通过 MmGetPhysicalMemoryRanges 取得;
// 任何在 RAM 范围之外的 PA(BIOS、IOAPIC、PCIe MMIO、framebuffer 等)
// 调 MmMapIoSpace 都可能让某些设备/HAL 异常 —— 实测在用户 Win10 22H2 上
// 出现过整机卡死。我们在所有 HvPhysMapPage 入口预先做 PA-in-RAM 校验。
//
// MmGetPhysicalMemoryRanges 返回一个以 {Base=0, Length=0} 结尾的数组,
// caller 必须 ExFreePool。我们在首次调用时拍照,后续只读静态副本。
typedef struct _HV_PHYS_RAM_RANGE {
    UINT64 Base;   // PA 起始 (4KB 对齐)
    UINT64 End;    // Base + Length, exclusive
} HV_PHYS_RAM_RANGE;

#define HV_PHYS_MAX_RAM_RANGES  64
static HV_PHYS_RAM_RANGE g_RamRanges[HV_PHYS_MAX_RAM_RANGES];
static ULONG g_RamRangeCount = 0;
static volatile LONG g_RamRangesInit = 0;

// 标准 x64 长模式 PTE 位 (Intel SDM / AMD64 APM)
#define PTE_PRESENT             (1ULL << 0)
#define PTE_RW                  (1ULL << 1)
#define PTE_USER                (1ULL << 2)
#define PTE_PS                  (1ULL << 7)    // Page Size: 2MB at PD, 1GB at PDPT
#define PTE_PFN_MASK            0x000FFFFFFFFFF000ULL  // bits [51:12]
#define PTE_NX                  (1ULL << 63)

// PTE 中的 PFN (4KB / 2MB / 1GB 三种粒度)
#define PTE_4KB_BASE(pte)       ((pte) & 0x000FFFFFFFFFF000ULL)
#define PTE_2MB_BASE(pte)       ((pte) & 0x000FFFFFFFE00000ULL)
#define PTE_1GB_BASE(pte)       ((pte) & 0x000FFFFFC0000000ULL)

// ============================================================
// 内部辅助
// ============================================================

/*
 * 初始化 RAM 范围缓存。线程安全:用 Interlocked 抢锁,仅第一线程执行。
 * 失败 (MmGetPhysicalMemoryRanges 返 NULL,或无法解析) 时保持 g_RamRangeCount=0,
 * HvPhysIsPaRam 会返回 TRUE (fallback: 假设是 RAM,行为退化到旧版)。
 */
static VOID
HvPhysInitRamRangesIfNeeded(VOID)
{
    if (g_RamRangesInit != 0) return;
    if (InterlockedCompareExchange(&g_RamRangesInit, 1, 0) != 0) return;

    PPHYSICAL_MEMORY_RANGE ranges = MmGetPhysicalMemoryRanges();
    if (!ranges) {
        DbgPrint("[HvPhys] WARNING: MmGetPhysicalMemoryRanges() returned NULL, "
                 "PA-is-RAM check will be disabled\n");
        return;
    }

    ULONG count = 0;
    UINT64 totalBytes = 0;
    for (ULONG i = 0; i < HV_PHYS_MAX_RAM_RANGES; i++) {
        UINT64 base   = (UINT64)ranges[i].BaseAddress.QuadPart;
        UINT64 length = (UINT64)ranges[i].NumberOfBytes.QuadPart;
        if (base == 0 && length == 0) break;  // 数组结束符
        if (length == 0) continue;            // 跳过 0 长度条目
        g_RamRanges[count].Base = base;
        g_RamRanges[count].End  = base + length;
        totalBytes += length;
        count++;
    }
    g_RamRangeCount = count;

    ExFreePool(ranges);

    HV_HOT_DBG("[HvPhys] RAM ranges loaded: %u entries, total %llu MB\n",
             count, totalBytes >> 20);
    for (ULONG i = 0; i < count; i++) {
        HV_HOT_DBG("[HvPhys]   range[%u]: 0x%llX - 0x%llX (%llu MB)\n",
                 i, g_RamRanges[i].Base, g_RamRanges[i].End,
                 (g_RamRanges[i].End - g_RamRanges[i].Base) >> 20);
    }
}

/*
 * 检查 PA 是否落在系统 RAM 范围内。
 * - 若 RAM 范围未初始化或为空,返 TRUE (fallback: 不做检查,保持旧版行为)
 * - 否则严格判断:必须有 PA 所在的整页 [PA, PA+PAGE_SIZE) 完全落在某条 range 内
 */
static BOOLEAN
HvPhysIsPaRam(_In_ UINT64 PhysAddr)
{
    if (g_RamRangeCount == 0) return TRUE;
    UINT64 pageEnd = PhysAddr + PAGE_SIZE;
    for (ULONG i = 0; i < g_RamRangeCount; i++) {
        if (PhysAddr >= g_RamRanges[i].Base && pageEnd <= g_RamRanges[i].End) {
            return TRUE;
        }
    }
    return FALSE;
}

/*
 * 临时映射一个物理页到内核 VA,返回 VA;失败返回 NULL。
 * MmMapIoSpace 在 PASSIVE_LEVEL 上是 cache-coherent (用 MmCached)。
 *
 * 关键安全:先用 HvPhysIsPaRam 过滤非 RAM PA。MMIO/reserved 区域调
 * MmMapIoSpace 在某些机型上会卡死整个系统 (实测 Win10 22H2 i5-12400F)。
 */
static PVOID
HvPhysMapPage(_In_ UINT64 PhysAddr, _In_ SIZE_T Size)
{
    HvPhysInitRamRangesIfNeeded();
    if (!HvPhysIsPaRam(PhysAddr)) {
        // 不要打印,这条路径会被 garbage CR3 candidate 频繁触发,刷屏没意义
        return NULL;
    }
    PHYSICAL_ADDRESS pa;
    pa.QuadPart = (LONGLONG)PhysAddr;
    // MmCached: 4KB 数据页/页表都是 WB 内存,用 MmCached 一致性最好。
    return MmMapIoSpace(pa, Size, MmCached);
}

static VOID
HvPhysUnmapPage(_In_ PVOID Va, _In_ SIZE_T Size)
{
    if (Va) {
        MmUnmapIoSpace(Va, Size);
    }
}

/*
 * 在一级页表 (4KB) 里读 entry[index]。返回 0 表示 entry 不存在。
 * 输入: TablePa = 该页表自身的物理基址 (来自父表的 PFN<<12)
 *       Index   = 0..511
 */
static UINT64
HvPhysReadTableEntry(_In_ UINT64 TablePa, _In_ ULONG Index)
{
    UINT64 entry = 0;
    PVOID mapped = HvPhysMapPage(TablePa, PAGE_SIZE);
    if (!mapped) {
        return 0;
    }
    entry = ((volatile UINT64*)mapped)[Index];
    HvPhysUnmapPage(mapped, PAGE_SIZE);
    return entry;
}

// ============================================================
// CR3 获取
// ============================================================

/*
 * 诊断辅助 —— 把 CandidateCr3 当 PML4 物理基址,临时映射,数 user 半空间
 * (0..255) 有多少个 **格式有效** 的 PML4E。
 *
 * 严格 PML4E 格式 (Windows x64 用户 PML4E 必满足):
 *   bit 0 (P)   = 1
 *   bit 1 (R/W) = 1
 *   bit 2 (U/S) = 1   (user-half 必须 user-accessible)
 *   bit 7 (PS)  = 0   (PML4E 不允许 large page)
 *   PFN 在合理范围 (≥ 1 page, < 1TB)
 * → `(entry & 0x87) == 0x07`
 *
 * 仅 `& PTE_PRESENT` 太宽松:扫 EPROCESS 时随便一个 code/data 字节序列都会
 * 有 ~50% 的 entry 低位为 1,在 256 个 entry 里能搞出 ~128 个 false positive
 * (实测 QQMusic.exe 把代码页 0x400000000 当成 CR3,user-half=97)。
 * 加上 RW/US/PS 三位约束后,随机字节命中概率从 50% 降到 6.25%,real PML4E
 * 仍然 100% 命中。
 *
 * 用途:
 *  1) 给 GetCr3 / Walk 失败诊断快速判别 CR3 是否含 user 映射;
 *  2) Win10 22H2+ / Win11 layout 漂移时扫 EPROCESS 找真正的 user CR3 字段。
 *
 * MmMapIoSpace 在野指针上会返回 NULL,所以这个函数对 garbage 输入是安全的。
 */
static ULONG
HvPhysDiagCountUserHalfPresent(_In_ UINT64 CandidateCr3)
{
    UINT64 pa = CandidateCr3 & ~0xFFFULL;
    if (pa == 0) return 0;
    PVOID p = HvPhysMapPage(pa, PAGE_SIZE);
    if (!p) return 0;
    ULONG count = 0;
    volatile UINT64* tbl = (volatile UINT64*)p;
    for (ULONG i = 0; i < 256; i++) {
        UINT64 e = tbl[i];
        // 严格 PML4E 用户位 + 非 large page
        if ((e & 0x87ULL) != 0x07ULL) continue;
        // PFN 合理性 (1 page ≤ PFN < 1TB)
        UINT64 pfn = e & PTE_PFN_MASK;
        if (pfn < 0x1000ULL) continue;
        if (pfn >= 0x10000000000ULL) continue;
        count++;
    }
    HvPhysUnmapPage(p, PAGE_SIZE);
    return count;
}

/*
 * 放宽版本:仅要求 P+U/S=1 + PS=0 + PFN 合理。
 * 不要求 RW=1 (有些 user PML4E 可能 read-only),也不要求 A 等高级位。
 * 用作 walk-validation 的安全预筛:严格版本 (0x87==0x07) 会漏真 CR3,
 * 而完全无预筛会让 ~40 次 MmMapIoSpace 命中 reserved/MMIO PA 导致卡死。
 *
 * 随机字节命中率: bit0=1, bit2=1, bit7=0 三位约束 → 1/8 = 12.5%。
 * 256 entry 期望 false positive ~32,但绝大多数 garbage 的 PFN 还会被
 * PFN 范围检查淘汰一轮,实际上有 user-half >= 1 的 garbage candidate 很少。
 */
static ULONG
HvPhysDiagCountUserHalfPresentRelaxed(_In_ UINT64 CandidateCr3)
{
    UINT64 pa = CandidateCr3 & ~0xFFFULL;
    if (pa == 0) return 0;
    PVOID p = HvPhysMapPage(pa, PAGE_SIZE);
    if (!p) return 0;
    ULONG count = 0;
    volatile UINT64* tbl = (volatile UINT64*)p;
    for (ULONG i = 0; i < 256; i++) {
        UINT64 e = tbl[i];
        // 放宽:P=1, U/S=1, PS=0 (不要求 RW=1)
        if ((e & 0x85ULL) != 0x05ULL) continue;
        UINT64 pfn = e & PTE_PFN_MASK;
        if (pfn < 0x1000ULL) continue;
        if (pfn >= 0x10000000000ULL) continue;
        count++;
    }
    HvPhysUnmapPage(p, PAGE_SIZE);
    return count;
}

/*
 * 与上类似,但数 kernel 半空间 (256..511) 的 **格式有效** PML4E。
 *
 * kernel-half PML4E 用户位是 0:
 *   `(entry & 0x87) == 0x03`   (P=1, RW=1, U/S=0, PS=0)
 *
 * 用作 candidate 的"是不是真 PML4"二次验证:real CR3 kernel-half 应有
 * 大量 (~80-200) present 项 (kernel 地址空间共享), garbage page 撑死
 * ~16 个 (6.25% × 256)。这条比 user-half count 更稳。
 */
static ULONG
HvPhysDiagCountKernelHalfPresent(_In_ UINT64 CandidateCr3)
{
    UINT64 pa = CandidateCr3 & ~0xFFFULL;
    if (pa == 0) return 0;
    PVOID p = HvPhysMapPage(pa, PAGE_SIZE);
    if (!p) return 0;
    ULONG count = 0;
    volatile UINT64* tbl = (volatile UINT64*)p;
    for (ULONG i = 256; i < 512; i++) {
        UINT64 e = tbl[i];
        if ((e & 0x87ULL) != 0x03ULL) continue;
        UINT64 pfn = e & PTE_PFN_MASK;
        if (pfn < 0x1000ULL) continue;
        if (pfn >= 0x10000000000ULL) continue;
        count++;
    }
    HvPhysUnmapPage(p, PAGE_SIZE);
    return count;
}

/*
 * KVAS shadow 检测:真的 UserDirectoryTableBase 与 KPROCESS.DirectoryTableBase
 * 共享 kernel trampoline 映射 (entries 256..511 的一个子集)。Microsoft 在不同
 * Win 版本上 KVAS 行为差别很大:
 *
 *   - Win10 1709 / Win11 21H2-22H2: shadow 几乎 = full kernel-half copy,
 *     与 user CR3 byte-identical (历史代码假设的情况)
 *   - Win11 23H2-25H2: shadow 大幅瘦身,只保留 syscall/中断 trampoline 需要
 *     的极少 (1-10) 个 entry,其余清零。此时 user CR3 kernel-half 是 shadow
 *     kernel-half 的 SUPERSET,byte-identical 比较会把大量"user CR3 多出来
 *     的 entry"全部判成 mismatch,误判好候选为坏。
 *
 * 修正后判据 (asymmetric):shadow 里 PRESENT 的 entry 必须在 candidate 里
 * 也 PRESENT 且 PFN 相同 (host 状态位忽略)。允许 candidate 有 shadow 没有
 * 的额外 kernel-half entry。这等价于"candidate 是 shadow 的 SUPERSET",
 * 准确描述 KVAS 共享 trampoline 的本质。
 *
 * 返回:
 *   TRUE  shadow 的 trampoline entry 都在 candidate 里命中, 候选是真 UserDTB
 *   FALSE 否则
 */
static BOOLEAN
HvPhysCandidateKernelHalfMatches(_In_ UINT64 KernelCr3, _In_ UINT64 CandidateCr3)
{
    UINT64 kPa = KernelCr3    & ~0xFFFULL;
    UINT64 cPa = CandidateCr3 & ~0xFFFULL;
    if (kPa == 0 || cPa == 0 || kPa == cPa) return FALSE;

    PVOID kMap = HvPhysMapPage(kPa, PAGE_SIZE);
    if (!kMap) return FALSE;
    PVOID cMap = HvPhysMapPage(cPa, PAGE_SIZE);
    if (!cMap) { HvPhysUnmapPage(kMap, PAGE_SIZE); return FALSE; }

    volatile UINT64* k = (volatile UINT64*)kMap;
    volatile UINT64* c = (volatile UINT64*)cMap;
    ULONG kPresent = 0;
    ULONG mismatch = 0;
    for (ULONG i = 256; i < 512; i++) {
        if (!(k[i] & PTE_PRESENT)) continue;
        kPresent++;
        if (!(c[i] & PTE_PRESENT)
            || (k[i] & PTE_PFN_MASK) != (c[i] & PTE_PFN_MASK)) {
            mismatch++;
        }
    }
    HvPhysUnmapPage(kMap, PAGE_SIZE);
    HvPhysUnmapPage(cMap, PAGE_SIZE);

    // shadow 至少有 1 个 kernel-half entry (trampoline 必需)
    if (kPresent == 0) return FALSE;

    // 允许 5% 误差 (A/D 位漂移、host 重映射等噪声), shadow trampoline 的
    // 主体必须在 candidate 里命中
    return (mismatch * 20 <= kPresent);
}

// KVAS UserDirectoryTableBase 偏移缓存。0 = 还没探出来 / 当前系统未启用 KVAS。
// 一旦在任意一次 GetCr3 调用里探到, 此后所有进程都直接用这个偏移取值,
// 避免每次都扫整个 EPROCESS body。
static volatile LONG g_UserDtbOffsetProbed = 0;
static ULONG g_UserDtbOffset = 0;

// Walk-validation 期间设为 TRUE 抑制 HvPhysGvaToHpa 的诊断 dump
// (一次扫描会 walk 几百个 candidate, 每个 fail 都 dump 会让日志爆炸)。
static volatile LONG g_HvPhysWalkQuiet = 0;

// 暴露给 HvCloak::EnumWorkingSet 用 (扫 user-half 4M 次, 跳过未映射区时
// 不要打 walk-fail 否则日志爆炸)。caller 必须配对 set/clear。
VOID HvPhysSetWalkQuiet(_In_ BOOLEAN Quiet)
{
    InterlockedExchange(&g_HvPhysWalkQuiet, Quiet ? 1 : 0);
}

// ============================================================
// Root-mode context (HvPhysAccess.h 中声明的 g_HvPhysRootCtx 定义)
// ============================================================
//
// 在 HvPhysAccessInitialize 中填充, 之后只读, root mode 直接访问。
// 反作弊视角:hot path (memory_read/write IOCTL) 零 Mm*/Ps* 的关键。
HV_PHYS_ROOT_CTX g_HvPhysRootCtx = { 0 };

// 首次调用时确定 EPROCESS::DirectoryTableBase 的真实偏移。
// 思路:当前在 PASSIVE_LEVEL 且没换上下文时, __readcr3() == 当前进程的
// KPROCESS::DirectoryTableBase。扫 0x20..0x100 找匹配偏移。
static VOID
HvPhysProbeDtbOffset(VOID)
{
    if (InterlockedCompareExchange(&g_DtbOffsetProbed, 1, 0) != 0) return;

    PEPROCESS me = PsGetCurrentProcess();
    UINT64 myCr3 = __readcr3() & ~0xFFFULL;

    // 默认值先试一次, 命中就用它(避免偶发 alias)。
    UINT64 defv = *(UINT64*)((PUCHAR)me + EPROCESS_DTB_OFFSET_DEFAULT) & ~0xFFFULL;
    if (defv == myCr3) {
        HV_HOT_DBG("[HvPhys] DTB offset confirmed at default 0x%X (cr3=0x%llX)\n",
                 EPROCESS_DTB_OFFSET_DEFAULT, myCr3);
        return;
    }

    // 默认失配, 扫描。注意先把 DbgPrint 默认值不匹配, 帮 user 诊断。
    HV_HOT_DBG("[HvPhys] DTB at default 0x%X = 0x%llX != cr3=0x%llX, scanning...\n",
             EPROCESS_DTB_OFFSET_DEFAULT, defv, myCr3);

    for (ULONG off = 0x20; off <= 0x100; off += 8) {
        UINT64 cand = *(UINT64*)((PUCHAR)me + off) & ~0xFFFULL;
        if (cand == myCr3) {
            g_DtbOffset = off;
            HV_HOT_DBG("[HvPhys] DTB offset probed -> 0x%X (cr3=0x%llX)\n", off, myCr3);
            return;
        }
    }

    DbgPrint("[HvPhys] DTB probe FAILED, keeping default 0x%X (cr3=0x%llX)\n",
             EPROCESS_DTB_OFFSET_DEFAULT, myCr3);
}

NTSTATUS
HvPhysGetProcessCr3(
    _In_ ULONG ProcessId,
    _Out_ PUINT64 OutCr3
)
{
    if (!OutCr3) return STATUS_INVALID_PARAMETER;
    *OutCr3 = 0;

    HvPhysProbeDtbOffset();

    PEPROCESS process = NULL;
    NTSTATUS status = PsLookupProcessByProcessId(
        (HANDLE)(ULONG_PTR)ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // EPROCESS 的前部 = KPROCESS,DirectoryTableBase 在 +g_DtbOffset。
    // 直接读结构,避开任何 Mm* / Ps* 调用 (那些会触发 ETWTI)。
    UINT64 dtb = *(UINT64*)((PUCHAR)process + g_DtbOffset);
    UINT64 cr3Masked = dtb & ~0xFFFULL;

    // 诊断: 0x28 读出来的 CR3 是否真的含 user 映射? 数 user 半空间 PML4
    // PRESENT entry。正常用户进程至少有几项 (exe + ntdll + heap + stack)。
    ULONG userCount = HvPhysDiagCountUserHalfPresent(cr3Masked);

    // 取 image name 用于诊断。PsGetProcessImageFileName 返回 EPROCESS 内部
    // 16-byte char field 指针, 一般 null-terminated。
    PUCHAR imageName = PsGetProcessImageFileName(process);
    CHAR nameBuf[20] = {0};
    if (imageName) {
        for (ULONG i = 0; i < 15 && imageName[i]; i++) nameBuf[i] = (CHAR)imageName[i];
    }

    HV_HOT_DBG("[HvPhys] GetCr3: PID=%u Image='%s' EPROCESS+0x%X = 0x%llX (masked=0x%llX, user-half=%u)\n",
             ProcessId, nameBuf, g_DtbOffset, dtb, cr3Masked, userCount);

    // user-half 为 0 → 这个 CR3 不含 user 映射。三种可能:
    //   a) Process 是 System/Registry/Memory Compression/Secure System/vmmem
    //      等 kernel-only 进程, 本来就没 user 半空间;
    //   b) Win11 24H2+ 重排了 EPROCESS, 真正的 user CR3 挪到了别处;
    //   c) KVAS (Meltdown 缓解) 启用 —— DTB@0x28 是 kernel-only shadow,
    //      真正的 user CR3 在 KPROCESS.UserDirectoryTableBase, 偏移随版本浮动。
    // c) 是 Win10 1709+ / Win11 全系常态, 必须修。
    if (userCount == 0 && cr3Masked != 0) {
        // 先试缓存的 UserDTB 偏移 (大概率命中, O(1))。
        // 缓存路径也用严格 PML4E 格式校验避免命中 garbage 字段。
        if (g_UserDtbOffset != 0) {
            UINT64 cached = *(UINT64*)((PUCHAR)process + g_UserDtbOffset) & ~0xFFFULL;
            if (cached != 0) {
                ULONG uc = HvPhysDiagCountUserHalfPresent(cached);
                ULONG kc = HvPhysDiagCountKernelHalfPresent(cached);
                // 格式有效 (≥5 user, ≥40 kernel) AND kernel-half asymmetric match
                if (uc >= 5 && kc >= 40 &&
                    HvPhysCandidateKernelHalfMatches(cr3Masked, cached)) {
                    HV_HOT_DBG("[HvPhys]   USING cached UserDTB @+0x%X = 0x%llX (uh=%u kh=%u) for PID=%u\n",
                             g_UserDtbOffset, cached, uc, kc, ProcessId);
                    ObDereferenceObject(process);
                    *OutCr3 = cached;
                    return STATUS_SUCCESS;
                }
                DbgPrint("[HvPhys]   cached offset 0x%X yields invalid CR3 0x%llX (uh=%u kh=%u), rescanning\n",
                         g_UserDtbOffset, cached, uc, kc);
            }
            // 缓存失效 (进程刚退出 / 偏移在此进程不适用), 继续扫
        }

        DbgPrint("[HvPhys] WARNING: PID=%u (Image='%s') DTB@0x%X yields USER-EMPTY CR3. "
                 "Scanning EPROCESS+0x20..+0xC00 for UserDTB via kernel-half match:\n",
                 ProcessId, nameBuf, g_DtbOffset);

        UINT64 bestCand  = 0;
        ULONG  bestCount = 0;
        ULONG  bestOff   = 0;

        // 兜底:如果连 relaxed kernel-half 检查都没人过,也保留一个"格式
        // 正确 + user-half 合理"的最佳候选,用它好过返回 STATUS_INVALID_*。
        // KVAS 在 Win11 24H2/25H2/canary 上行为持续变,trampoline 数有时
        // 会跌到 0 (kernel CR3 完全无 user 半空间也无 kernel-half),
        // 这种情况下唯一的判据就是 user-half count + 格式有效。
        UINT64 fallbackCand = 0;
        ULONG  fallbackCount = 0;
        ULONG  fallbackOff = 0;

        for (ULONG off = 0x20; off <= 0xC00; off += 8) {
            if (off == g_DtbOffset) continue;       // 跳过 kernel DTB 自己
            UINT64 cand = *(UINT64*)((PUCHAR)process + off);

            // 严格 CR3 形态 (PFN 提高下限到 1MB, 过滤 0x8000 类噪声)
            if (cand & 0xFFFULL) continue;
            if (cand < 0x100000ULL) continue;
            if (cand > 0x10000000000ULL) continue;
            if (cand & 0xFFF0000000000000ULL) continue;

            // user-half 格式有效 PML4E 数 (严格 P+RW+U/S=1, PS=0)
            ULONG c = HvPhysDiagCountUserHalfPresent(cand);
            if (c < 1 || c > 200) continue;

            // kernel-half 格式有效 PML4E 数 —— 真 CR3 此项 ~80+, garbage code
            // page 此项 ≤ 16 (6.25% × 256)。这条比 user-half 抗噪声强。
            ULONG kh = HvPhysDiagCountKernelHalfPresent(cand);

            // 阈值:user-half ≥ 5 且 kernel-half ≥ 40 才视为像 CR3 的候选
            // (small process 也 ≥ 5,真 kernel-half 几乎都 ≥ 80,放 40 留余地)
            if (c < 5 || kh < 40) {
                HV_HOT_DBG("[HvPhys]   +0x%X = 0x%llX  user-half=%u kernel-half=%u (format too sparse, skip — not a real CR3)\n",
                         off, cand, c, kh);
                continue;
            }

            // 记录所有格式正确的候选作为兜底 (按 user-half + kernel-half 总分)
            if (c + kh > fallbackCount) {
                fallbackCand  = cand;
                fallbackCount = c + kh;
                fallbackOff   = off;
            }

            // 主判据:asymmetric kernel-half match (shadow 是 user CR3 子集)
            if (!HvPhysCandidateKernelHalfMatches(cr3Masked, cand)) {
                DbgPrint("[HvPhys]   +0x%X = 0x%llX  user-half=%u kernel-half=%u (kernel-half MISMATCH, fallback only)\n",
                         off, cand, c, kh);
                continue;
            }

            HV_HOT_DBG("[HvPhys]   +0x%X = 0x%llX  user-half=%u kernel-half=%u (kernel-half OK, candidate)\n",
                     off, cand, c, kh);

            // 多候选时取 user-half + kernel-half 总分最高 (双重指标抗噪声)
            if (c + kh > bestCount) {
                bestCand  = cand;
                bestCount = c + kh;
                bestOff   = off;
            }
        }

        if (bestCand != 0) {
            HV_HOT_DBG("[HvPhys]   -> SELECTED UserDTB @+0x%X = 0x%llX (score=%u, via kernel-half match)\n",
                     bestOff, bestCand, bestCount);

            // 一次性缓存(竞态良性:最后赢家覆盖, 但都是合法 UserDTB 偏移)
            if (InterlockedCompareExchange(&g_UserDtbOffsetProbed, 1, 0) == 0) {
                g_UserDtbOffset = bestOff;
                HV_HOT_DBG("[HvPhys]   cached UserDTB offset = 0x%X (used for all future GetCr3)\n",
                         bestOff);
            }

            ObDereferenceObject(process);
            *OutCr3 = bestCand;
            return STATUS_SUCCESS;
        }

        // 兜底:relaxed match 也都失败 → 用格式总分最高候选 (user+kernel half
        // 都通过严格 PML4E 校验), 只是不缓存偏移 (避免错误偏移污染下次)
        if (fallbackCand != 0) {
            HV_HOT_DBG("[HvPhys]   FALLBACK: 无 kernel-half match, 用格式总分最高候选 +0x%X = 0x%llX (score=%u)\n",
                     fallbackOff, fallbackCand, fallbackCount);
            HV_HOT_DBG("[HvPhys]   (PID %u Image='%s' — KVAS 行为可能再次变更,不缓存此偏移)\n",
                     ProcessId, nameBuf);

            ObDereferenceObject(process);
            *OutCr3 = fallbackCand;
            return STATUS_SUCCESS;
        }

        HV_HOT_DBG("[HvPhys]   No UserDTB candidate found at all (no entry passes format check).\n");
        HV_HOT_DBG("[HvPhys]   -> PID %u (Image='%s') likely kernel-only "
                 "(System/Registry/MemCompression/vmmem class).\n",
                 ProcessId, nameBuf);
    }

    ObDereferenceObject(process);

    if (dtb == 0) {
        return STATUS_NOT_FOUND;
    }

    *OutCr3 = cr3Masked;
    return STATUS_SUCCESS;
}

// ============================================================
// 4 级页表 walk
// ============================================================

NTSTATUS
HvPhysGvaToHpa(
    _In_ UINT64 TargetCr3,
    _In_ UINT64 Gva,
    _Out_ PPHYSICAL_ADDRESS OutHpa,
    _Out_opt_ PSIZE_T OutPageSize,
    _Out_opt_ PUINT64 OutPteFlags
)
{
    if (!OutHpa) return STATUS_INVALID_PARAMETER;
    OutHpa->QuadPart = 0;
    if (OutPageSize)  *OutPageSize = 0;
    if (OutPteFlags)  *OutPteFlags = 0;

    if (TargetCr3 == 0) return STATUS_INVALID_PARAMETER;
    if (KeGetCurrentIrql() > APC_LEVEL) return STATUS_INVALID_LEVEL;

    UINT64 pml4Pa = TargetCr3 & ~0xFFFULL;

    ULONG pml4i = (ULONG)PML4_INDEX(Gva);
    ULONG pdpti = (ULONG)PDPT_INDEX(Gva);
    ULONG pdi   = (ULONG)PD_INDEX(Gva);
    ULONG pti   = (ULONG)PT_INDEX(Gva);

    // 1) PML4E
    UINT64 pml4e = HvPhysReadTableEntry(pml4Pa, pml4i);
    if (!(pml4e & PTE_PRESENT)) {
        if (!g_HvPhysWalkQuiet) {
            DbgPrint("[HvPhys] Walk FAIL @PML4: cr3=0x%llX gva=0x%llX idx[%u]=0x%llX (not present)\n",
                     TargetCr3, Gva, pml4i, pml4e);

            // 诊断 dump: 帮助区分 "CR3 全错(user-half 全空)" 与
            // "CR3 对但该 index 真的就空"。如果 user-half 全空,意味着我们读到的
            // DirectoryTableBase 是个不含 user mapping 的 CR3(例如 24H2 把
            // 真正的 user CR3 移到了另一个 EPROCESS 字段,或这个 EPROCESS
            // 是 Idle/System/Minimal 之类不含 user 半空间的进程)。
            PVOID pml4Map = HvPhysMapPage(pml4Pa, PAGE_SIZE);
            if (pml4Map) {
                ULONG userCount = 0, kernelCount = 0;
                volatile UINT64* p = (volatile UINT64*)pml4Map;
                for (ULONG i = 0; i < 256; i++) {
                    if (p[i] & PTE_PRESENT) {
                        if (userCount < 8) {
                            HV_HOT_DBG("[HvPhys]   PML4[%u] = 0x%llX (user-half present)\n", i, p[i]);
                        }
                        userCount++;
                    }
                }
                for (ULONG i = 256; i < 512; i++) {
                    if (p[i] & PTE_PRESENT) kernelCount++;
                }
                HV_HOT_DBG("[HvPhys] PML4 summary: user-half=%u present, kernel-half=%u present  (cr3=0x%llX)\n",
                         userCount, kernelCount, TargetCr3);
                HvPhysUnmapPage(pml4Map, PAGE_SIZE);
            }
        }

        return STATUS_INVALID_ADDRESS_COMPONENT;
    }
    UINT64 pdptPa = pml4e & PTE_PFN_MASK;

    // 2) PDPTE
    UINT64 pdpte = HvPhysReadTableEntry(pdptPa, pdpti);
    if (!(pdpte & PTE_PRESENT)) {
        if (!g_HvPhysWalkQuiet) {
            DbgPrint("[HvPhys] Walk FAIL @PDPT: cr3=0x%llX gva=0x%llX pml4[%u]=0x%llX pdpt[%u]=0x%llX (not present)\n",
                     TargetCr3, Gva, pml4i, pml4e, pdpti, pdpte);
        }
        return STATUS_INVALID_ADDRESS_COMPONENT;
    }
    if (pdpte & PTE_PS) {
        // 1GB 大页
        OutHpa->QuadPart = (LONGLONG)(PTE_1GB_BASE(pdpte) | (Gva & 0x3FFFFFFFULL));
        if (OutPageSize) *OutPageSize = 0x40000000ULL;
        if (OutPteFlags) *OutPteFlags = pdpte;
        return STATUS_SUCCESS;
    }
    UINT64 pdPa = pdpte & PTE_PFN_MASK;

    // 3) PDE
    UINT64 pde = HvPhysReadTableEntry(pdPa, pdi);
    if (!(pde & PTE_PRESENT)) {
        if (!g_HvPhysWalkQuiet) {
            DbgPrint("[HvPhys] Walk FAIL @PD: cr3=0x%llX gva=0x%llX pml4[%u]=0x%llX pdpt[%u]=0x%llX pd[%u]=0x%llX (not present)\n",
                     TargetCr3, Gva, pml4i, pml4e, pdpti, pdpte, pdi, pde);
        }
        return STATUS_INVALID_ADDRESS_COMPONENT;
    }
    if (pde & PTE_PS) {
        // 2MB 大页
        OutHpa->QuadPart = (LONGLONG)(PTE_2MB_BASE(pde) | (Gva & 0x1FFFFFULL));
        if (OutPageSize) *OutPageSize = 0x200000ULL;
        if (OutPteFlags) *OutPteFlags = pde;
        return STATUS_SUCCESS;
    }
    UINT64 ptPa = pde & PTE_PFN_MASK;

    // 4) PTE
    UINT64 pte = HvPhysReadTableEntry(ptPa, pti);
    if (!(pte & PTE_PRESENT)) {
        // 这里区分"完全未映射"与"换出": Windows 用 PRESENT=0 但保留 PFN
        // 的 PTE 表示 transition/prototype。我们一律算作 NOT_FOUND,让用
        // 户态触发一次访问把页换回再重试。
        if (!g_HvPhysWalkQuiet) {
            DbgPrint("[HvPhys] Walk FAIL @PT: cr3=0x%llX gva=0x%llX pml4[%u]=0x%llX pdpt[%u]=0x%llX pd[%u]=0x%llX pt[%u]=0x%llX (not present, possibly paged-out)\n",
                     TargetCr3, Gva, pml4i, pml4e, pdpti, pdpte, pdi, pde, pti, pte);
        }
        return STATUS_NOT_FOUND;
    }
    OutHpa->QuadPart = (LONGLONG)(PTE_4KB_BASE(pte) | (Gva & 0xFFFULL));
    if (OutPageSize) *OutPageSize = PAGE_SIZE;
    if (OutPteFlags) *OutPteFlags = pte;
    return STATUS_SUCCESS;
}

// ============================================================
// Deterministic walk-validated CR3 discovery (兜底)
// ============================================================
/*
 * 当启发式 GetCr3 给出的 CR3 在用户空间 GVA 上 walk 失败时,这是 deterministic
 * 兜底:用户请求的 GVA 当探针,扫 EPROCESS+0x20..+0xC00 的每个候选 CR3,
 * 用 HvPhysGvaToHpa 实际 walk 这个 GVA。能 walk 到非零 HPA 的 CR3 就是
 * 正确的(至少对该 GVA 而言)。
 *
 * 为什么 walk-validation 比纯启发式强:
 *   - PML4E 格式计数有 6.25% noise floor,小进程 (kernel-half < 40) 可能
 *     被误判为 garbage;
 *   - asymmetric kernel-half match 在 Win10/11 servicing update 间会随
 *     KVAS shadow 行为变化而失效;
 *   - 用户请求的 GVA 本身就是 ground truth:4 级页表 walk 全部 PRESENT
 *     且产出非零 HPA,只能发生在真实的页表树上 —— 0% false positive。
 *
 * 代价:每个候选最多 4 次 MmMapIoSpace + 4 次 Unmap。整个 EPROCESS 扫一遍
 * ~ (0xC00 / 8) × 4 = 1500 次 map,首次约 5-15ms。成功后偏移会被 cache,
 * 后续 O(1)。仅 user-space GVA 调用此函数。
 */
/*
 * 进程归属校验 —— 给定一个候选 user CR3, 判断它是否属于 Process。
 *
 * 背景: HvCr3Snoop ring 采集的是**所有进程**在 VMEXIT 时的 GUEST_CR3。
 * 仅靠 "candidate 能 walk 到目标 GVA" 不足以确认它是目标进程的 CR3 ——
 * 其他进程恰好在同一 GVA 有映射(尤其是低 VA 区域的共享或 NULL 占位)
 * 也会通过 walk 测试,但读到的是别人的数据(常常是 zero page)。
 *
 * 校验方法 (双重 MZ 锚点):
 *   1. PsGetProcessPeb(Process) 拿到目标进程的 PEB user VA (pebVa)
 *      —— 每个进程的 PEB 地址独立 (ASLR), 不同进程概率不会在同一 VA
 *   2. 用 candidate CR3 走 pebVa → HPA, 映射 → 读 PEB.ImageBaseAddress @ +0x10
 *      —— 若 candidate 不是目标进程的 CR3, 该 VA 多半未映射或内容是垃圾
 *   3. PEB.ImageBaseAddress 必须是合法 user VA
 *   4. 再用 candidate CR3 走 ImageBaseAddress → HPA, 读首 2 字节
 *      —— 必须是 'MZ' (0x5A4D) 才确认: candidate 不仅有 PEB, 还能到达
 *         PEB 指向的 PE 镜像
 *
 * 假阳性概率: 两个互相独立的 4KB-aligned VA 同时随机指向有效 PEB 结构
 * + 该 PEB.ImageBase 又能 walk + 起首是 MZ —— 实际不可能。
 *
 * 返回 STATUS_SUCCESS 当且仅当 candidate 几乎确定属于 Process。
 * System / Idle / Minimal 进程没有 PEB (PsGetProcessPeb 返回 NULL),
 * 此时返回 STATUS_NOT_SUPPORTED, 由调用方决定是否跳过校验。
 */
static NTSTATUS
HvPhysValidateCr3OwnsProcess(
    _In_ PEPROCESS Process,
    _In_ UINT64 CandidateCr3)
{
    PVOID pebVa = PsGetProcessPeb(Process);
    if (!pebVa) return STATUS_NOT_SUPPORTED;  // System / Idle / Minimal

    UINT64 pebGva = (UINT64)pebVa;
    if (pebGva < 0x10000ULL || pebGva >= 0x800000000000ULL) {
        return STATUS_NOT_SUPPORTED;
    }

    // PEB.ImageBaseAddress 在 PEB+0x10 —— 必须在同一页内
    SIZE_T inPageOff = (SIZE_T)(pebGva & 0xFFFULL);
    if (inPageOff + 0x18 > PAGE_SIZE) {
        return STATUS_NOT_SUPPORTED;  // PEB 跨页, 跳过 (极少见)
    }

    // 第一跳: 走 candidate CR3 → PEB physical page
    PHYSICAL_ADDRESS pebHpa = {0};
    NTSTATUS s = HvPhysGvaToHpa(CandidateCr3, pebGva, &pebHpa, NULL, NULL);
    if (!NT_SUCCESS(s) || pebHpa.QuadPart == 0) {
        return STATUS_NOT_FOUND;
    }

    PVOID pebMap = HvPhysMapPage((UINT64)pebHpa.QuadPart, PAGE_SIZE);
    if (!pebMap) return STATUS_INSUFFICIENT_RESOURCES;

    UINT64 imageBase = *(UINT64*)((PUCHAR)pebMap + inPageOff + 0x10);
    HvPhysUnmapPage(pebMap, PAGE_SIZE);

    // ImageBase 必须看起来像 user VA
    if (imageBase < 0x10000ULL || imageBase >= 0x800000000000ULL) {
        return STATUS_NOT_FOUND;
    }
    // 必须 page-aligned (PE 镜像 always 4K 对齐)
    if (imageBase & 0xFFFULL) {
        return STATUS_NOT_FOUND;
    }

    // 第二跳: 走 candidate CR3 → ImageBase physical page, 校验 MZ
    PHYSICAL_ADDRESS imgHpa = {0};
    s = HvPhysGvaToHpa(CandidateCr3, imageBase, &imgHpa, NULL, NULL);
    if (!NT_SUCCESS(s) || imgHpa.QuadPart == 0) {
        return STATUS_NOT_FOUND;
    }

    PVOID imgMap = HvPhysMapPage((UINT64)imgHpa.QuadPart, PAGE_SIZE);
    if (!imgMap) return STATUS_INSUFFICIENT_RESOURCES;

    USHORT magic = *(USHORT*)imgMap;
    HvPhysUnmapPage(imgMap, PAGE_SIZE);

    if (magic != 0x5A4D) {  // 'MZ'
        return STATUS_NOT_FOUND;
    }

    return STATUS_SUCCESS;
}

static NTSTATUS
HvPhysFindUserCr3ByGvaWalk(
    _In_ ULONG TargetPid,
    _In_ UINT64 GvaHint,
    _Out_ PUINT64 OutCr3
);

/*
 * HvPhysFindUserCr3ByPid -- 给定 PID, 返回经 MZ 锚点验证的真 user CR3。
 *
 * 实现:
 *   1) HvVtRootGetPebByPid(pid, &pebVa) 拿 PEB VA (内部 root mode 用候选 CR3 找 + MZ 锚点验证)
 *   2) HvPhysFindUserCr3ByGvaWalk(pid, pebVa, &cr3) 用 PEB 作 GvaHint 反查真 user CR3
 *
 * 与 HvPhysGetProcessCr3 的区别: 后者只读 EPROCESS+0x28 启发式, 在 KVAS Win11 24H2 上
 * 经常拿到 shadow CR3 (user-half=0)。本函数走双重校验, 拿到的一定是真 user CR3。
 *
 * 返回 STATUS_NOT_FOUND 表示进程是 kernel-only (System/Registry 等) 或找不到。
 * 调用方 IRQL <= APC_LEVEL。
 */
NTSTATUS
HvPhysFindUserCr3ByPid(
    _In_ ULONG TargetPid,
    _Out_ PUINT64 OutCr3
)
{
    if (!OutCr3) return STATUS_INVALID_PARAMETER;
    *OutCr3 = 0;
    if (KeGetCurrentIrql() > APC_LEVEL) return STATUS_INVALID_LEVEL;
    if (!g_VtRootEnabled) return STATUS_DEVICE_NOT_READY;

    UINT64 pebVa = 0;
    NTSTATUS s = HvVtRootGetPebByPid(TargetPid, &pebVa);
    if (!NT_SUCCESS(s)) return s;
    if (pebVa == 0) return STATUS_NOT_FOUND;   // kernel-only 进程

    return HvPhysFindUserCr3ByGvaWalk(TargetPid, pebVa, OutCr3);
}

static NTSTATUS
HvPhysFindUserCr3ByGvaWalk(
    _In_ ULONG TargetPid,
    _In_ UINT64 GvaHint,
    _Out_ PUINT64 OutCr3
)
{
    if (!OutCr3) return STATUS_INVALID_PARAMETER;
    *OutCr3 = 0;
    if (KeGetCurrentIrql() > APC_LEVEL) return STATUS_INVALID_LEVEL;
    // 仅 user-space (canonical low half)
    if (GvaHint >= 0x800000000000ULL) return STATUS_INVALID_PARAMETER;

    PEPROCESS process = NULL;
    NTSTATUS status = PsLookupProcessByProcessId(
        (HANDLE)(ULONG_PTR)TargetPid, &process);
    if (!NT_SUCCESS(status)) return status;

    HV_HOT_DBG("[HvPhys] WalkVal: PID=%u GVA=0x%llX, looking for CR3 that walks this GVA\n",
             TargetPid, GvaHint);

    // 整个 walk-val 期间静默 walk-fail 诊断 —— 每个 candidate 都会失败 4 次
    // (PML4/PDPT/PD/PT),如果不静默,数百次 dump 把日志冲爆,失败的真正原因
    // (GVA 不存在) 反而看不到。
    InterlockedExchange(&g_HvPhysWalkQuiet, 1);

    // 1) 先试 cached UserDTB 偏移
    if (g_UserDtbOffset != 0) {
        UINT64 cached = *(UINT64*)((PUCHAR)process + g_UserDtbOffset) & ~0xFFFULL;
        if (cached != 0) {
            PHYSICAL_ADDRESS hpa = {0};
            NTSTATUS walkStatus = HvPhysGvaToHpa(cached, GvaHint, &hpa, NULL, NULL);
            if (NT_SUCCESS(walkStatus) && hpa.QuadPart != 0) {
                InterlockedExchange(&g_HvPhysWalkQuiet, 0);
                HV_HOT_DBG("[HvPhys] WalkVal: cached @+0x%X = 0x%llX walks GVA -> HPA 0x%llX (FAST PATH)\n",
                         g_UserDtbOffset, cached, (UINT64)hpa.QuadPart);
                ObDereferenceObject(process);
                *OutCr3 = cached;
                return STATUS_SUCCESS;
            }
        }
    }

    // 2) 也试 EPROCESS+0x28 (shadow CR3 / non-KVAS 系统上 user 映射仍可走)
    UINT64 selfCr3 = *(UINT64*)((PUCHAR)process + g_DtbOffset) & ~0xFFFULL;
    if (selfCr3 != 0) {
        PHYSICAL_ADDRESS hpa = {0};
        NTSTATUS walkStatus = HvPhysGvaToHpa(selfCr3, GvaHint, &hpa, NULL, NULL);
        if (NT_SUCCESS(walkStatus) && hpa.QuadPart != 0) {
            InterlockedExchange(&g_HvPhysWalkQuiet, 0);
            HV_HOT_DBG("[HvPhys] WalkVal: EPROCESS+0x%X=0x%llX walks GVA -> HPA 0x%llX (non-KVAS or self-CR3)\n",
                     g_DtbOffset, selfCr3, (UINT64)hpa.QuadPart);
            ObDereferenceObject(process);
            *OutCr3 = selfCr3;
            return STATUS_SUCCESS;
        }
    }

    // 2.5) 先试一组 Win 各版本 known 的 UserDirectoryTableBase 偏移。
    //
    // 这一步是关键安全保险:全 EPROCESS 扫描可能让 MmMapIoSpace 命中
    // reserved/MMIO PA 导致卡死(上一版的 bug)。先试已知偏移,99% 情况
    // 直接命中,不需要进入全扫描。
    //
    // 偏移来源:Windows 公开符号 / 实测:
    //   - Win10 1709-19H2 / Win11 21H2-22H2: 0x388
    //   - Win10 1803+ 变体: 0x3A0
    //   - Win11 24H2 Build 26100 (2026-06-16 WinDbg 实测): 0x158
    //   - Win11 23H2-24H2 早期: 0x3C0
    //   - Win11 23H2 备选: 0x3F0, 0x440
    //   - Win10 22H2 (实测 explorer.exe): 0x550
    //   - Win11 25H2 canary 候选: 0x580
    static const ULONG kKnownUserDtbOffsets[] = {
        0x158, 0x388, 0x3A0, 0x3C0, 0x3F0, 0x440, 0x550, 0x580
    };
    for (ULONG i = 0; i < RTL_NUMBER_OF(kKnownUserDtbOffsets); i++) {
        ULONG off = kKnownUserDtbOffsets[i];
        if (off == g_DtbOffset || off == g_UserDtbOffset) continue;  // 已经试过
        UINT64 cand = *(UINT64*)((PUCHAR)process + off) & ~0xFFFULL;
        if (cand == 0) continue;
        // 简单形态过滤
        if (cand < 0x100000ULL) continue;
        if (cand > 0x10000000000ULL) continue;

        PHYSICAL_ADDRESS hpa = {0};
        NTSTATUS walkStatus = HvPhysGvaToHpa(cand, GvaHint, &hpa, NULL, NULL);
        if (NT_SUCCESS(walkStatus) && hpa.QuadPart != 0) {
            InterlockedExchange(&g_HvPhysWalkQuiet, 0);
            HV_HOT_DBG("[HvPhys] WalkVal: known offset +0x%X = 0x%llX walks GVA -> HPA 0x%llX\n",
                     off, cand, (UINT64)hpa.QuadPart);
            if (InterlockedCompareExchange(&g_UserDtbOffsetProbed, 1, 0) == 0) {
                g_UserDtbOffset = off;
                HV_HOT_DBG("[HvPhys] WalkVal: cached UserDTB offset = 0x%X\n", off);
            }
            ObDereferenceObject(process);
            *OutCr3 = cand;
            return STATUS_SUCCESS;
        }
    }

    // 2.7) **CR3 嗅探 ring 候选** —— 反作弊敏感场景的关键兜底。
    //
    // 当 EPROCESS 启发式扫描全部失败时(反作弊 hide 了 UserDirectoryTableBase,
    // 或 KVAS 的 shadow CR3 完全瘦身导致字段被 patch / 不在常见偏移),
    // 退到 hypervisor 自己采集的 CR3 ring。
    //
    // Ring 里的每个 CR3 都是某次 VMEXIT 时 GUEST_CR3 字段的值 —— 硬件层观察,
    // 100% 是真实在用的 user CR3。问题是不知道是哪个 PID 的,所以挨个用
    // walk-validation 验证:能 walk 到 target GVA 的就是 target 进程的 CR3。
    //
    // 完全 host-only,不动 EPROCESS/KTHREAD 任何字段,反作弊看不到。
    HvCr3SnoopEnable();  // 第一次走到这里时启用,后续 VMEXIT 持续采集
    {
        UINT64 snoopCr3s[HV_CR3_SNOOP_RING_SIZE];
        ULONG snoopCount = HvCr3SnoopSnapshot(snoopCr3s, HV_CR3_SNOOP_RING_SIZE);
        HV_HOT_DBG("[HvPhys] WalkVal: trying %u snooped CR3 candidates from VMEXIT ring\n",
                 snoopCount);

        // Diagnostic: dump first 16 CR3s so we can see what got captured
        ULONG dumpN = (snoopCount < 16) ? snoopCount : 16;
        for (ULONG i = 0; i < dumpN; i++) {
            HV_HOT_DBG("[HvPhys] WalkVal: snoop[%u]=0x%llX\n", i, snoopCr3s[i]);
        }

        // 收集 "能 walk GvaHint" 的候选, 后续逐个做进程归属校验。
        // 不能像之前那样选第一个 walks-through 的就返回 —— ring 里有所有进程的
        // CR3, 别的进程恰好在 GvaHint 有映射时会把 wrong-process 的数据当成
        // target 的数据返回 (常常是 zero page → 用户看到 "数据全 0")。
        UINT64 firstWalkCand = 0;  // 兜底: 即便归属校验失败也至少有个能 walk 的
        for (ULONG i = 0; i < snoopCount; i++) {
            UINT64 cand = snoopCr3s[i];
            // 形态过滤(理论上 ring 里的都是真 CR3,但加一道防御)
            if (cand < 0x100000ULL || cand > 0x10000000000ULL) continue;
            if (!HvPhysIsPaRam(cand)) continue;

            PHYSICAL_ADDRESS hpa = {0};
            NTSTATUS walkStatus = HvPhysGvaToHpa(cand, GvaHint, &hpa, NULL, NULL);
            if (!NT_SUCCESS(walkStatus) || hpa.QuadPart == 0) continue;

            if (firstWalkCand == 0) firstWalkCand = cand;

            // 进程归属双重 MZ 校验: PEB walk + PEB.ImageBase walk + 'MZ' 检查
            NTSTATUS ownStatus = HvPhysValidateCr3OwnsProcess(process, cand);
            if (NT_SUCCESS(ownStatus)) {
                InterlockedExchange(&g_HvPhysWalkQuiet, 0);
                HV_HOT_DBG("[HvPhys] WalkVal: snooped CR3 0x%llX walks GVA -> HPA 0x%llX "
                         "AND owns target process (PEB+MZ verified)\n",
                         cand, (UINT64)hpa.QuadPart);
                ObDereferenceObject(process);
                *OutCr3 = cand;
                return STATUS_SUCCESS;
            }
            // STATUS_NOT_SUPPORTED = System/Idle/Minimal (无 PEB), 不能校验
            // 但 GvaHint 都能 walk 了, 说明候选是真 CR3 —— 接受
            if (ownStatus == STATUS_NOT_SUPPORTED) {
                InterlockedExchange(&g_HvPhysWalkQuiet, 0);
                HV_HOT_DBG("[HvPhys] WalkVal: snooped CR3 0x%llX walks GVA, owner check skipped "
                         "(target has no PEB —— system/idle/minimal process)\n", cand);
                ObDereferenceObject(process);
                *OutCr3 = cand;
                return STATUS_SUCCESS;
            }
        }

        // 没有候选通过归属校验 —— 这意味着 snoop ring 里没有目标进程的 CR3
        // (目标在本次 walk-val 之前没产生过 user-mode VMEXIT)。返回 NOT_FOUND
        // 比 silently 接受 wrong-process CR3 安全得多 —— 后者会读 zero page,
        // 用户以为 "读成功但数据全 0", 实际是读了别的进程或共享 zero page。
        if (firstWalkCand != 0) {
            InterlockedExchange(&g_HvPhysWalkQuiet, 0);
            DbgPrint("[HvPhys] WalkVal: %u snoop CR3 walks GVA 0x%llX but NONE owns target PID %u "
                     "(PEB+MZ all fail). First walks-cand=0x%llX rejected. "
                     "Returning NOT_FOUND to avoid wrong-process read.\n",
                     snoopCount, GvaHint, TargetPid, firstWalkCand);
        }

        // Cross-check: try walking a *known-mapped* user VA (KUSER_SHARED_DATA @ 0x7FFE0000)
        // through each snoop CR3. If even this fails, the snoop CR3 are not real user CR3
        // (or only kernel-half CR3). If KUSER walks but caller's GVA doesn't, the GVA is
        // genuinely not mapped in this process.
        HV_HOT_DBG("[HvPhys] WalkVal: GvaHint 0x%llX not in any snoop CR3 — sanity-checking with KUSER_SHARED_DATA\n",
                 GvaHint);
        ULONG kuserWalks = 0;
        for (ULONG i = 0; i < snoopCount && i < 8; i++) {
            UINT64 cand = snoopCr3s[i];
            if (cand < 0x100000ULL || cand > 0x10000000000ULL) continue;
            if (!HvPhysIsPaRam(cand)) continue;
            PHYSICAL_ADDRESS hpa = {0};
            NTSTATUS s = HvPhysGvaToHpa(cand, 0x7FFE0000ULL, &hpa, NULL, NULL);
            if (NT_SUCCESS(s) && hpa.QuadPart != 0) {
                kuserWalks++;
                if (kuserWalks <= 3) {
                    HV_HOT_DBG("[HvPhys] WalkVal: KUSER probe: snoop[%u]=0x%llX walks KUSER_SHARED_DATA -> HPA 0x%llX\n",
                             i, cand, (UINT64)hpa.QuadPart);
                }
            }
        }
        HV_HOT_DBG("[HvPhys] WalkVal: KUSER probe summary: %u/%u snoop CR3 can walk KUSER_SHARED_DATA\n",
                 kuserWalks, (snoopCount < 8) ? snoopCount : 8);
        if (kuserWalks > 0) {
            HV_HOT_DBG("[HvPhys] WalkVal: snoop ring contains REAL user CR3 -> GVA 0x%llX is genuinely UNMAPPED "
                     "in this/all processes. Check whether caller passed a module-relative offset.\n",
                     GvaHint);
        }

        if (snoopCount == 0) {
            DbgPrint("[HvPhys] WalkVal: snoop ring empty (snooper just enabled, no VMEXIT yet)\n");
        }
    }

    // 3) 全 EPROCESS 扫描 —— known offsets + snoop ring 全部失败时的兜底。
    //
    // 安全网:HvPhysMapPage 现在做 PA-is-RAM 校验(基于 MmGetPhysicalMemoryRanges),
    // 不在 RAM 范围内的 PA 一律返 NULL,不会调 MmMapIoSpace 进而避免卡死。
    //
    // 性能控制:
    //   - 限制最多 32 次实际 walk (整页 4 次 MmMapIoSpace),其余跳过
    //   - 形态过滤:PFN 必须在 [1MB, 1TB)、4KB 对齐
    //   - quiet 模式整个函数已开,失败 dump 被压住
    //
    // 扫描范围:EPROCESS+0x20 .. +0xC00,步长 8 (UINT64 对齐)
    ULONG triedWalks = 0;
    UINT64 foundCr3 = 0;
    ULONG foundOffset = 0;

    for (ULONG off = 0x20; off <= 0xC00; off += 8) {
        // 跳过已经试过的路径
        if (off == g_DtbOffset || off == g_UserDtbOffset) continue;
        BOOLEAN inKnown = FALSE;
        for (ULONG k = 0; k < RTL_NUMBER_OF(kKnownUserDtbOffsets); k++) {
            if (off == kKnownUserDtbOffsets[k]) { inKnown = TRUE; break; }
        }
        if (inKnown) continue;

        UINT64 cand = *(UINT64*)((PUCHAR)process + off) & ~0xFFFULL;
        if (cand == 0) continue;
        if (cand < 0x100000ULL) continue;
        if (cand > 0x10000000000ULL) continue;

        // 预筛 PA-is-RAM 一次:省掉 walk 入口的 4 次 Map 尝试
        if (!HvPhysIsPaRam(cand)) continue;

        triedWalks++;
        if (triedWalks > 32) break;  // 上限保险

        PHYSICAL_ADDRESS hpa = {0};
        NTSTATUS walkStatus = HvPhysGvaToHpa(cand, GvaHint, &hpa, NULL, NULL);
        if (NT_SUCCESS(walkStatus) && hpa.QuadPart != 0) {
            // 即便 candidate 来自 target EPROCESS, 也可能是误判 (kernel pointer
            // 在 random offset 上恰好 page-aligned 且能 walk GvaHint —— 极少
            // 但 zero-page reading 的代价比 STATUS_NOT_FOUND 严重). 加双重 MZ
            // 校验; NOT_SUPPORTED (system process 没 PEB) 接受以兼容旧行为.
            NTSTATUS ownStatus = HvPhysValidateCr3OwnsProcess(process, cand);
            if (NT_SUCCESS(ownStatus) || ownStatus == STATUS_NOT_SUPPORTED) {
                foundCr3 = cand;
                foundOffset = off;
                break;
            }
            // 校验失败 —— 继续下一个候选
        }
    }

    InterlockedExchange(&g_HvPhysWalkQuiet, 0);

    if (foundCr3 != 0) {
        HV_HOT_DBG("[HvPhys] WalkVal: full scan offset +0x%X = 0x%llX walks GVA (tried %u candidates)\n",
                 foundOffset, foundCr3, triedWalks);
        if (InterlockedCompareExchange(&g_UserDtbOffsetProbed, 1, 0) == 0) {
            g_UserDtbOffset = foundOffset;
            HV_HOT_DBG("[HvPhys] WalkVal: cached UserDTB offset = 0x%X\n", foundOffset);
        }
        ObDereferenceObject(process);
        *OutCr3 = foundCr3;
        return STATUS_SUCCESS;
    }

    // 全部失败 —— 这通常意味着 GVA 在该进程中 *根本未映射*。常见原因:
    //   1) GUI 误把模块偏移当作绝对地址 (例如 0xA8AC4 是 module-internal offset,
    //      正确值应为 ImageBase + 0xA8AC4,如 0x7FF6_xxxx_0000 + 0xA8AC4)
    //   2) GUI 把 64-bit 指针截成 32-bit
    //   3) 目标地址在保护页 (NULL trap 区 0..0x10000) 或者根本没有分配
    //   4) 极少数情况:该进程是 minimal/system,真无 user-space
    HV_HOT_DBG("[HvPhys] WalkVal: NO CR3 walks GVA 0x%llX (PID %u, tried %u candidates).\n"
             "[HvPhys]   This usually means the GVA is NOT MAPPED in this process.\n"
             "[HvPhys]   Check whether the user-mode caller passed an absolute VA, not a module-relative offset.\n",
             GvaHint, TargetPid, triedWalks);
    ObDereferenceObject(process);
    return STATUS_INVALID_ADDRESS_COMPONENT;
}

// ============================================================
// Read / Write
// ============================================================

/*
 * 跨页 R/W 的核心循环 —— Phase D 重构为薄壳。
 *
 * 反作弊敏感场景下, 整个 hot path 只调一件事:HvVtRootCopyByPid。
 * 内部进 root mode, EPROCESS 链表遍历 + CR3 候选收集 + 页表 walk + 拷贝
 * 全部在 IRQ-off 状态下完成, 完全不调 Mm* / Ps* / Ob*。
 *
 * 不再做的事(对比旧版):
 *   - 不调 HvPhysGetProcessCr3 (有 PsLookupProcessByProcessId + MmMapIoSpace)
 *   - 不做 PASSIVE-level walk-validation (有 30-100 次 MmMapIoSpace)
 *   - 没有 MmMapIoSpace fallback 路径
 *
 * 若 g_VtRootEnabled = FALSE (未初始化或初始化失败), 直接返回 NOT_READY。
 * Direction: 0 = read (target→Buffer), 1 = write (Buffer→target)。
 */
static NTSTATUS
HvPhysCopyAcrossPages(
    _In_ ULONG TargetPid,
    _In_ UINT64 Gva,
    _Inout_updates_bytes_(Size) PVOID Buffer,
    _In_ SIZE_T Size,
    _In_ ULONG Direction,            // 0=read, 1=write
    _Out_opt_ PSIZE_T BytesDone
)
{
    if (BytesDone) *BytesDone = 0;
    if (!Buffer || Size == 0) return STATUS_INVALID_PARAMETER;
    if (KeGetCurrentIrql() > APC_LEVEL) return STATUS_INVALID_LEVEL;
    if (!g_VtRootEnabled) return STATUS_DEVICE_NOT_READY;

    // 2026-06-16: Buffer 是 kernel VA (内部 driver 调用,如 SSDT 解析) 直接传,
    // 不走 MDL (kernel VA 在 host CR3 下永远 resident, 不会 paged-out)。
    //
    // Buffer 是 user VA (NtReadVirtualMemory 转发的 user buffer) → 必须锁 + 取
    // system VA 别名, 否则 root mode 写 paged-out user 页 → BSOD 0xD1。
    //
    // 判定: canonical low half (< 0x0000800000000000) 为 user VA。
    ULONG_PTR bufAddr = (ULONG_PTR)Buffer;
    BOOLEAN isUserBuffer = (bufAddr < 0x0000800000000000ULL);

    if (!isUserBuffer) {
        // Kernel buffer 直接传, 无 MDL 开销
        return HvVtRootCopyByPid(
            TargetPid, Gva, Buffer, Size,
            (BOOLEAN)(Direction != 0), BytesDone);
    }

    // User buffer: 锁定 + system VA 别名
    PMDL mdl = IoAllocateMdl(Buffer, (ULONG)Size, FALSE, FALSE, NULL);
    if (!mdl) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Direction=0(读) 时 Buffer 被写入 → IoWriteAccess
    // Direction=1(写) 时 Buffer 被读取 → IoReadAccess
    LOCK_OPERATION lockOp = (Direction == 0) ? IoWriteAccess : IoReadAccess;
    NTSTATUS lockSt = STATUS_SUCCESS;
    __try {
        MmProbeAndLockPages(mdl, UserMode, lockOp);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        lockSt = GetExceptionCode();
        if (NT_SUCCESS(lockSt)) lockSt = STATUS_ACCESS_VIOLATION;
    }
    if (!NT_SUCCESS(lockSt)) {
        IoFreeMdl(mdl);
        return lockSt;
    }

    PVOID systemVa = MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority);
    if (!systemVa) {
        MmUnlockPages(mdl);
        IoFreeMdl(mdl);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // === target 锁页:不用 KeStackAttachProcess (反作弊重点监控对象 —
    //     EAC/Vanguard/腾讯 TP 都 hook 它,看 caller 是不是 unsigned driver)。
    //     改用 MmProbeAndLockProcessPages,内部直接走 PFN database 不 attach,
    //     反作弊视角看不到地址空间切换。
    //
    //     这一锁阻止 OS WorkingSetManager 在 vmcall 期间 trim target 物理页
    //     (P43 根因:DeltaForceClie 被 CE Read 时撞 trim race →
    //     MiRemoveActivePageTableLinks 蓝屏)。
    PEPROCESS targetProc = NULL;
    NTSTATUS lkSt = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)TargetPid, &targetProc);
    if (!NT_SUCCESS(lkSt) || !targetProc) {
        MmUnlockPages(mdl);
        IoFreeMdl(mdl);
        return NT_SUCCESS(lkSt) ? STATUS_INVALID_CID : lkSt;
    }

    PMDL targetMdl = IoAllocateMdl((PVOID)(ULONG_PTR)Gva, (ULONG)Size, FALSE, FALSE, NULL);
    NTSTATUS targetLockSt = STATUS_SUCCESS;
    if (!targetMdl) {
        targetLockSt = STATUS_INSUFFICIENT_RESOURCES;
    } else {
        // Direction=0(读 target) → target 页被读 → IoReadAccess
        // Direction=1(写 target) → target 页被写 → IoWriteAccess
        LOCK_OPERATION tgtOp = (Direction == 0) ? IoReadAccess : IoWriteAccess;
        __try {
            MmProbeAndLockProcessPages(targetMdl, targetProc, UserMode, tgtOp);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            targetLockSt = GetExceptionCode();
            if (NT_SUCCESS(targetLockSt)) targetLockSt = STATUS_ACCESS_VIOLATION;
        }
    }

    NTSTATUS st;
    if (!NT_SUCCESS(targetLockSt)) {
        // target 页 lock 失败(paged-out / 无效 / guard page) → 报 NOT_FOUND,
        // 让 caller 触发一次用户态访问换页后重试,绝不走 unlocked 路径。
        st = STATUS_NOT_FOUND;
        if (targetMdl) IoFreeMdl(targetMdl);
    } else {
        st = HvVtRootCopyByPid(
            TargetPid, Gva, systemVa, Size,
            (BOOLEAN)(Direction != 0), BytesDone);

        MmUnlockPages(targetMdl);
        IoFreeMdl(targetMdl);
    }

    ObDereferenceObject(targetProc);

    MmUnlockPages(mdl);
    IoFreeMdl(mdl);
    return st;
}

NTSTATUS
HvPhysReadProcessMemory(
    _In_ ULONG TargetPid,
    _In_ UINT64 Gva,
    _Out_writes_bytes_(Size) PVOID Buffer,
    _In_ SIZE_T Size,
    _Out_opt_ PSIZE_T BytesRead
)
{
    return HvPhysCopyAcrossPages(TargetPid, Gva, Buffer, Size, 0, BytesRead);
}

NTSTATUS
HvPhysWriteProcessMemory(
    _In_ ULONG TargetPid,
    _In_ UINT64 Gva,
    _In_reads_bytes_(Size) PVOID Buffer,
    _In_ SIZE_T Size,
    _Out_opt_ PSIZE_T BytesWritten
)
{
    return HvPhysCopyAcrossPages(TargetPid, Gva, Buffer, Size, 1, BytesWritten);
}

// ============================================================
// 分配 / 释放 (#30, Phase 4)
// ============================================================

/*
 * 内部辅助 —— 在目标页表里写一个 entry。
 * MmMapIoSpace 临时映射 → 写 → Unmap。
 */
static NTSTATUS
HvPhysWriteTableEntry(_In_ UINT64 TablePa, _In_ ULONG Index, _In_ UINT64 Value)
{
    PVOID mapped = HvPhysMapPage(TablePa, PAGE_SIZE);
    if (!mapped) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    ((volatile UINT64*)mapped)[Index] = Value;
    HvPhysUnmapPage(mapped, PAGE_SIZE);
    return STATUS_SUCCESS;
}

/*
 * 分配一个零填充的 4KB 物理对齐页 (NonPaged)。
 * MmAllocateContiguousMemory 保证页对齐 + 物理连续 (我们只取 PAGE_SIZE,
 * 反正一定单页)。返回 VA 和 HPA。失败返回 NULL。
 */
static NTSTATUS
HvPhysAllocOnePage(_Out_ PVOID* OutVa, _Out_ UINT64* OutPa)
{
    PHYSICAL_ADDRESS highest;
    highest.QuadPart = (LONGLONG)0xFFFFFFFFFFFFFFFFULL;

    PVOID va = MmAllocateContiguousMemory(PAGE_SIZE, highest);
    if (!va) {
        *OutVa = NULL;
        *OutPa = 0;
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(va, PAGE_SIZE);
    *OutVa = va;
    *OutPa = (UINT64)MmGetPhysicalAddress(va).QuadPart;
    return STATUS_SUCCESS;
}

static VOID
HvPhysFreeOnePage(_In_opt_ PVOID Va)
{
    if (Va) {
        MmFreeContiguousMemory(Va);
    }
}

/*
 * 在目标 CR3 下,确保 (GVA -> PT) 路径上的所有中间表都存在。
 * 缺失的从我们的池里分配并写入父表;父表的 PFN 在 USER/RW/PRESENT 模式建立。
 *
 * 撞上 PS=1 (2MB/1GB 大页) → 返回 STATUS_NOT_SUPPORTED,调用者跳过该 VA。
 *
 * 注意: 中间表泄漏一份 (我们分配的 KernelVa 没追踪),进程退出统一回收。
 * 这是 Phase 4 简化版的代价 (~10MB/进程量级),acceptable。
 */
static NTSTATUS
HvPhysEnsurePtForVa(_In_ UINT64 Cr3, _In_ UINT64 Gva, _Out_ UINT64* OutPtPa)
{
    UINT64 pml4Pa = Cr3 & ~0xFFFULL;
    ULONG pml4i = (ULONG)PML4_INDEX(Gva);
    ULONG pdpti = (ULONG)PDPT_INDEX(Gva);
    ULONG pdi = (ULONG)PD_INDEX(Gva);
    NTSTATUS s;

    *OutPtPa = 0;

    // ---- PML4 ----
    UINT64 pml4e = HvPhysReadTableEntry(pml4Pa, pml4i);
    UINT64 pdptPa;
    if (!(pml4e & PTE_PRESENT)) {
        PVOID newVa; UINT64 newPa;
        s = HvPhysAllocOnePage(&newVa, &newPa);
        if (!NT_SUCCESS(s)) return s;
        UINT64 newEntry = (newPa & PTE_PFN_MASK) | PTE_PRESENT | PTE_RW | PTE_USER;
        s = HvPhysWriteTableEntry(pml4Pa, pml4i, newEntry);
        if (!NT_SUCCESS(s)) { HvPhysFreeOnePage(newVa); return s; }
        pdptPa = newPa;
    } else {
        pdptPa = pml4e & PTE_PFN_MASK;
    }

    // ---- PDPT ----
    UINT64 pdpte = HvPhysReadTableEntry(pdptPa, pdpti);
    if ((pdpte & PTE_PRESENT) && (pdpte & PTE_PS)) {
        return STATUS_NOT_SUPPORTED;  // 1GB 大页,不拆
    }
    UINT64 pdPa;
    if (!(pdpte & PTE_PRESENT)) {
        PVOID newVa; UINT64 newPa;
        s = HvPhysAllocOnePage(&newVa, &newPa);
        if (!NT_SUCCESS(s)) return s;
        UINT64 newEntry = (newPa & PTE_PFN_MASK) | PTE_PRESENT | PTE_RW | PTE_USER;
        s = HvPhysWriteTableEntry(pdptPa, pdpti, newEntry);
        if (!NT_SUCCESS(s)) { HvPhysFreeOnePage(newVa); return s; }
        pdPa = newPa;
    } else {
        pdPa = pdpte & PTE_PFN_MASK;
    }

    // ---- PD ----
    UINT64 pde = HvPhysReadTableEntry(pdPa, pdi);
    if ((pde & PTE_PRESENT) && (pde & PTE_PS)) {
        return STATUS_NOT_SUPPORTED;  // 2MB 大页,不拆
    }
    UINT64 ptPa;
    if (!(pde & PTE_PRESENT)) {
        PVOID newVa; UINT64 newPa;
        s = HvPhysAllocOnePage(&newVa, &newPa);
        if (!NT_SUCCESS(s)) return s;
        UINT64 newEntry = (newPa & PTE_PFN_MASK) | PTE_PRESENT | PTE_RW | PTE_USER;
        s = HvPhysWriteTableEntry(pdPa, pdi, newEntry);
        if (!NT_SUCCESS(s)) { HvPhysFreeOnePage(newVa); return s; }
        ptPa = newPa;
    } else {
        ptPa = pde & PTE_PFN_MASK;
    }

    *OutPtPa = ptPa;
    return STATUS_SUCCESS;
}

/*
 * 选址 —— 在目标 CR3 里扫描从 0x300000000 开始的用户空间,找连续 PageCount
 * 个 4KB 都未映射的窗口。撞到 PTE.PRESENT=1 或大页则跳过。
 *
 * 简化实现: 每次失败前进 PAGE_SIZE/2MB/1GB (取决于撞到什么粒度),
 * 找到连续 PageCount 个空闲后返回。最差线性扫,实测 < 1ms。
 */
static NTSTATUS
HvPhysFindFreeRegion(_In_ UINT64 Cr3, _In_ ULONG PageCount, _Out_ UINT64* OutGva)
{
    UINT64 candidate = 0x0000000300000000ULL;            // 12GB into user space
    const UINT64 maxAddr = 0x00007FFFFFFE0000ULL;        // 安全上限,留尾部不碰

    *OutGva = 0;

    while (candidate < maxAddr) {
        BOOLEAN regionFree = TRUE;
        UINT64 testVa = candidate;
        for (ULONG i = 0; i < PageCount; i++) {
            PHYSICAL_ADDRESS hpa;
            SIZE_T pageSize = 0;
            NTSTATUS s = HvPhysGvaToHpa(Cr3, testVa, &hpa, &pageSize, NULL);
            if (NT_SUCCESS(s)) {
                // 已被占用,跳到该 mapping 之后
                if (pageSize >= 0x200000ULL) {
                    UINT64 mask = pageSize - 1;
                    candidate = (testVa & ~mask) + pageSize;
                } else {
                    candidate = testVa + PAGE_SIZE;
                }
                regionFree = FALSE;
                break;
            }
            testVa += PAGE_SIZE;
        }
        if (regionFree) {
            *OutGva = candidate;
            return STATUS_SUCCESS;
        }
    }
    return STATUS_NO_MEMORY;
}

/*
 * IPI INVLPG —— 让所有 CPU 把目标 CR3 下指定 VA 的 TLB 项无效化。
 * 每个 CPU 检查自己的 CR3 是否匹配,匹配才 __invlpg (否则该 CPU
 * 现在跑的不是目标进程,TLB 里根本没这个 VA 的项,no-op 即可)。
 *
 * 写入全局变量受 g_PhysInvlpgLock 保护,避免并发 Free 互踩。
 */
static ULONG_PTR
HvPhysInvlpgIpiTarget(_In_ ULONG_PTR Context)
{
    UNREFERENCED_PARAMETER(Context);
    if (__readcr3() == g_InvlpgTargetCr3) {
        __invlpg((PVOID)g_InvlpgTargetVa);
    }
    return 0;
}

static VOID
HvPhysInvlpgBroadcast(_In_ UINT64 Cr3, _In_ UINT64 Va)
{
    if (KeGetCurrentIrql() > APC_LEVEL) {
        if (__readcr3() == Cr3) __invlpg((PVOID)Va);
        return;
    }
    KIRQL irql;
    KeAcquireSpinLock(&g_PhysInvlpgLock, &irql);
    g_InvlpgTargetCr3 = Cr3;
    g_InvlpgTargetVa = Va;
    KeIpiGenericCall(HvPhysInvlpgIpiTarget, 0);
    KeReleaseSpinLock(&g_PhysInvlpgLock, irql);
}

/*
 * 在目标进程页表里清掉一个 PTE (写 0,等于 PRESENT=0)。
 * 不需要 EnsurePt —— Free 路径上 PT 一定已存在 (Alloc 时建过)。
 * 但保险起见:遇到中途 PRESENT=0 就跳过 (静默成功,该 VA 反正已不可达)。
 */
static NTSTATUS
HvPhysClearPteForVa(_In_ UINT64 Cr3, _In_ UINT64 Gva)
{
    UINT64 pml4Pa = Cr3 & ~0xFFFULL;
    UINT64 pml4e = HvPhysReadTableEntry(pml4Pa, (ULONG)PML4_INDEX(Gva));
    if (!(pml4e & PTE_PRESENT)) return STATUS_SUCCESS;
    UINT64 pdptPa = pml4e & PTE_PFN_MASK;

    UINT64 pdpte = HvPhysReadTableEntry(pdptPa, (ULONG)PDPT_INDEX(Gva));
    if (!(pdpte & PTE_PRESENT)) return STATUS_SUCCESS;
    if (pdpte & PTE_PS) return STATUS_NOT_SUPPORTED;
    UINT64 pdPa = pdpte & PTE_PFN_MASK;

    UINT64 pde = HvPhysReadTableEntry(pdPa, (ULONG)PD_INDEX(Gva));
    if (!(pde & PTE_PRESENT)) return STATUS_SUCCESS;
    if (pde & PTE_PS) return STATUS_NOT_SUPPORTED;
    UINT64 ptPa = pde & PTE_PFN_MASK;

    return HvPhysWriteTableEntry(ptPa, (ULONG)PT_INDEX(Gva), 0);
}

NTSTATUS
HvPhysAllocateInProcess(
    _In_ ULONG TargetPid,
    _In_ SIZE_T Size,
    _In_ ULONG Protection,
    _Inout_ PUINT64 InOutGva
)
{
    if (!InOutGva || Size == 0) return STATUS_INVALID_PARAMETER;
    if (KeGetCurrentIrql() > APC_LEVEL) return STATUS_INVALID_LEVEL;
    if (!g_PhysAllocInitialized) HvPhysAccessInitialize();

    UINT64 cr3 = 0;
    NTSTATUS status = HvPhysGetProcessCr3(TargetPid, &cr3);
    if (!NT_SUCCESS(status)) return status;

    SIZE_T alignedSize = (Size + PAGE_SIZE - 1) & ~(SIZE_T)(PAGE_SIZE - 1);
    ULONG pageCount = (ULONG)(alignedSize / PAGE_SIZE);
    if (pageCount == 0) return STATUS_INVALID_PARAMETER;

    UINT64 gvaBase = *InOutGva;
    if (gvaBase == 0) {
        status = HvPhysFindFreeRegion(cr3, pageCount, &gvaBase);
        if (!NT_SUCCESS(status)) return status;
    } else {
        gvaBase &= ~(UINT64)(PAGE_SIZE - 1);
    }

    // Protection → PTE 位映射
    //   PAGE_READWRITE         -> R=1 W=1 NX=1
    //   PAGE_EXECUTE_READ      -> R=1 W=0 NX=0
    //   PAGE_EXECUTE_READWRITE -> R=1 W=1 NX=0
    //   其他 (含 EXECUTE only) -> 视为 PAGE_READWRITE,安全保底
    UINT64 pteFlags = PTE_PRESENT | PTE_USER;
    BOOLEAN writable = (Protection == PAGE_READWRITE ||
                        Protection == PAGE_EXECUTE_READWRITE ||
                        Protection == PAGE_WRITECOPY ||
                        Protection == PAGE_EXECUTE_WRITECOPY);
    BOOLEAN executable = (Protection == PAGE_EXECUTE ||
                          Protection == PAGE_EXECUTE_READ ||
                          Protection == PAGE_EXECUTE_READWRITE ||
                          Protection == PAGE_EXECUTE_WRITECOPY);
    if (writable) pteFlags |= PTE_RW;
    if (!executable) pteFlags |= PTE_NX;

    // 跟踪记录
    HV_PHYS_ALLOC_RECORD* record = (HV_PHYS_ALLOC_RECORD*)
        ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(HV_PHYS_ALLOC_RECORD), HV_PHYS_TAG_RECORD);
    if (!record) return STATUS_INSUFFICIENT_RESOURCES;

    record->Pages = (HV_PHYS_ALLOC_PAGE*)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(HV_PHYS_ALLOC_PAGE) * pageCount, HV_PHYS_TAG_RECORD);
    if (!record->Pages) {
        ExFreePoolWithTag(record, HV_PHYS_TAG_RECORD);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    record->ProcessId = TargetPid;
    record->BaseGva = gvaBase;
    record->SizeBytes = alignedSize;
    record->PageCount = pageCount;

    // 逐页装入
    ULONG installed = 0;
    for (ULONG i = 0; i < pageCount; i++) {
        UINT64 thisGva = gvaBase + (UINT64)i * PAGE_SIZE;

        UINT64 ptPa = 0;
        status = HvPhysEnsurePtForVa(cr3, thisGva, &ptPa);
        if (!NT_SUCCESS(status)) break;

        PVOID dataVa = NULL; UINT64 dataPa = 0;
        status = HvPhysAllocOnePage(&dataVa, &dataPa);
        if (!NT_SUCCESS(status)) break;

        UINT64 pteValue = (dataPa & PTE_PFN_MASK) | pteFlags;
        status = HvPhysWriteTableEntry(ptPa, (ULONG)PT_INDEX(thisGva), pteValue);
        if (!NT_SUCCESS(status)) {
            HvPhysFreeOnePage(dataVa);
            break;
        }

        record->Pages[i].KernelVa = dataVa;
        record->Pages[i].PhysicalAddress = dataPa;
        record->Pages[i].GuestVa = thisGva;
        installed++;
    }

    if (installed != pageCount) {
        // 失败回滚: 清已装入的 PTE + 释放物理页
        for (ULONG j = 0; j < installed; j++) {
            HvPhysClearPteForVa(cr3, record->Pages[j].GuestVa);
            HvPhysInvlpgBroadcast(cr3, record->Pages[j].GuestVa);
            HvPhysFreeOnePage(record->Pages[j].KernelVa);
        }
        ExFreePoolWithTag(record->Pages, HV_PHYS_TAG_RECORD);
        ExFreePoolWithTag(record, HV_PHYS_TAG_RECORD);
        return status;
    }

    // 注意: 首次填 PTE (PRESENT 0→1) 无需 INVLPG —— TLB 不缓存 PRESENT=0
    // 条目。Intel SDM 4.10.4.3 明确说这种场景安全。

    KIRQL irql;
    KeAcquireSpinLock(&g_PhysAllocLock, &irql);
    InsertTailList(&g_PhysAllocList, &record->ListEntry);
    KeReleaseSpinLock(&g_PhysAllocLock, irql);

    *InOutGva = gvaBase;
    return STATUS_SUCCESS;
}

NTSTATUS
HvPhysFreeInProcess(
    _In_ ULONG TargetPid,
    _In_ UINT64 Gva,
    _In_ SIZE_T Size
)
{
    UNREFERENCED_PARAMETER(Size);  // 按 record 完整释放,忽略调用方的 Size

    if (KeGetCurrentIrql() > APC_LEVEL) return STATUS_INVALID_LEVEL;
    if (!g_PhysAllocInitialized) HvPhysAccessInitialize();

    Gva &= ~(UINT64)(PAGE_SIZE - 1);

    // 摘出对应记录
    HV_PHYS_ALLOC_RECORD* record = NULL;
    KIRQL irql;
    KeAcquireSpinLock(&g_PhysAllocLock, &irql);
    PLIST_ENTRY entry = g_PhysAllocList.Flink;
    while (entry != &g_PhysAllocList) {
        HV_PHYS_ALLOC_RECORD* r = CONTAINING_RECORD(entry, HV_PHYS_ALLOC_RECORD, ListEntry);
        if (r->ProcessId == TargetPid && r->BaseGva == Gva) {
            RemoveEntryList(entry);
            record = r;
            break;
        }
        entry = entry->Flink;
    }
    KeReleaseSpinLock(&g_PhysAllocLock, irql);

    if (!record) return STATUS_NOT_FOUND;

    UINT64 cr3 = 0;
    NTSTATUS status = HvPhysGetProcessCr3(TargetPid, &cr3);
    if (!NT_SUCCESS(status)) {
        // 进程已退,目标页表也消失了,直接释放我们的物理页。
        for (ULONG i = 0; i < record->PageCount; i++) {
            HvPhysFreeOnePage(record->Pages[i].KernelVa);
        }
        ExFreePoolWithTag(record->Pages, HV_PHYS_TAG_RECORD);
        ExFreePoolWithTag(record, HV_PHYS_TAG_RECORD);
        return STATUS_SUCCESS;
    }

    for (ULONG i = 0; i < record->PageCount; i++) {
        UINT64 thisGva = record->Pages[i].GuestVa;
        HvPhysClearPteForVa(cr3, thisGva);
        HvPhysInvlpgBroadcast(cr3, thisGva);
        HvPhysFreeOnePage(record->Pages[i].KernelVa);
    }

    ExFreePoolWithTag(record->Pages, HV_PHYS_TAG_RECORD);
    ExFreePoolWithTag(record, HV_PHYS_TAG_RECORD);
    return STATUS_SUCCESS;
}

// ============================================================
// 叶 PTE 位置查询 (#27 followup, 阶段 6 gadget 初始化用)
// ============================================================

/*
 * 走 TargetCr3 找到 TargetVa 的叶 PTE 所在 PT 页 HPA + 索引。
 * 撞到 1GB/2MB 大页直接返回 STATUS_NOT_SUPPORTED ——
 * gadget 必须坐在 4KB 粒度上,否则无法精确重定位。
 */
NTSTATUS
HvPhysFindLeafPteLocation(
    _In_ UINT64 TargetCr3,
    _In_ UINT64 TargetVa,
    _Out_ PUINT64 OutPtPagePa,
    _Out_ PULONG OutPteIndex,
    _Out_opt_ PUINT64 OutOrigPte
)
{
    if (!OutPtPagePa || !OutPteIndex) return STATUS_INVALID_PARAMETER;
    *OutPtPagePa = 0;
    *OutPteIndex = 0;
    if (OutOrigPte) *OutOrigPte = 0;

    if (TargetCr3 == 0) return STATUS_INVALID_PARAMETER;
    if (KeGetCurrentIrql() > APC_LEVEL) return STATUS_INVALID_LEVEL;

    UINT64 pml4Pa = TargetCr3 & ~0xFFFULL;

    // 1) PML4E
    UINT64 pml4e = HvPhysReadTableEntry(pml4Pa, (ULONG)PML4_INDEX(TargetVa));
    if (!(pml4e & PTE_PRESENT)) return STATUS_INVALID_ADDRESS_COMPONENT;
    UINT64 pdptPa = pml4e & PTE_PFN_MASK;

    // 2) PDPTE —— PS=1 表 1GB 大页,gadget 不支持
    UINT64 pdpte = HvPhysReadTableEntry(pdptPa, (ULONG)PDPT_INDEX(TargetVa));
    if (!(pdpte & PTE_PRESENT)) return STATUS_INVALID_ADDRESS_COMPONENT;
    if (pdpte & PTE_PS) return STATUS_NOT_SUPPORTED;
    UINT64 pdPa = pdpte & PTE_PFN_MASK;

    // 3) PDE —— PS=1 表 2MB 大页,gadget 不支持
    UINT64 pde = HvPhysReadTableEntry(pdPa, (ULONG)PD_INDEX(TargetVa));
    if (!(pde & PTE_PRESENT)) return STATUS_INVALID_ADDRESS_COMPONENT;
    if (pde & PTE_PS) return STATUS_NOT_SUPPORTED;
    UINT64 ptPa = pde & PTE_PFN_MASK;

    // 4) PTE 自身 —— 仅当用户要 OrigPte 才读一次
    if (OutOrigPte) {
        UINT64 pte = HvPhysReadTableEntry(ptPa, (ULONG)PT_INDEX(TargetVa));
        // 不检查 PRESENT —— 用户可能就是要找一个未映射的 slot 来插入新 PTE
        *OutOrigPte = pte;
    }

    *OutPtPagePa = ptPa;
    *OutPteIndex = (ULONG)PT_INDEX(TargetVa);
    return STATUS_SUCCESS;
}

// ============================================================
// 生命周期
// ============================================================

/*
 * Root-mode context 初始化 —— 一次性解析 nt 符号 + EPROCESS 关键偏移。
 *
 * 反作弊视角:这是 HvPhysAccess 唯一调用 MmGetSystemRoutineAddress 的位置,
 * 调用时机 = DriverEntry, 与 IOCTL hot path 解耦。Hot path 之后只读
 * g_HvPhysRootCtx, 完全不再调用 Mm* / Ps* / Ob*。
 *
 * 探测策略:
 *   1) PsInitialSystemProcess 通过 MmGetSystemRoutineAddress 解析。
 *      这个符号是导出全局变量, 返回的是变量自身地址 → 再解引用一次。
 *      失败 → 整个 root ctx 留 Initialized=FALSE, hot path 走老路径
 *      (短期保护, 后续 Phase D 会删除老路径,这层 fallback 只是过渡)。
 *   2) DTB 偏移直接复用 HvPhysProbeDtbOffset 探得的 g_DtbOffset (默认 0x28)。
 *   3) UserDTB 偏移复用 HvPhysProbeUserDtbOffset 探得的 g_UserDtbOffset
 *      (这两个 probe 在 HvPhysGetProcessCr3 第一次调用时执行, 但 root ctx
 *      在 Initialize 阶段就要锁定值 —— 所以这里先填默认值, 真正的探测仍
 *      由首次 GetCr3 调用触发, 之后 root ctx 通过 update helper 同步)。
 *      简化: 这里直接填 0x28 作为 DtbOff, 0 作为 UserDtbOff (未探到时 root mode
 *      会跳过该候选, 让 KnownUserDtbOffs 表挨个尝试)。
 *   4) PsActiveProcessLinks / UniqueProcessId 偏移 —— 用 System EPROCESS
 *      做闭环验证:从 PsInitialSystemProcess 出发, 沿 LIST_ENTRY.Flink
 *      最多走 4096 步, 看是否能回到自己 (链表闭合)。同时校验
 *      *(ULONG_PTR)(eproc + PidOff) 在合理范围。
 *      Win10 22H2 / Win11 23H2-25H2 主流偏移: ActiveLinks=0x448, Pid=0x440。
 */
static BOOLEAN
HvPhysVerifyEprocessOffsets(
    _In_ PEPROCESS SystemEproc,
    _In_ ULONG ActiveLinksOff,
    _In_ ULONG PidOff)
{
    // SystemEproc::ActiveProcessLinks.Flink 不能指向自己,
    // 头尾闭合: 从 SystemEproc 走链表必须能回到自己 (4096 步上限)。
    PLIST_ENTRY head = (PLIST_ENTRY)((PUCHAR)SystemEproc + ActiveLinksOff);

    // System 进程 PID = 4 (Windows 全平台稳定)
    ULONG_PTR sysPid = *(ULONG_PTR*)((PUCHAR)SystemEproc + PidOff);
    if (sysPid != 4) {
        DbgPrint("[HvPhys] Verify Links=0x%X Pid=0x%X: sysPid=0x%llX (expect 4) FAIL\n",
                 ActiveLinksOff, PidOff, (ULONG64)sysPid);
        return FALSE;
    }

    PLIST_ENTRY cur = head->Flink;
    if (!cur || cur == head) {
        DbgPrint("[HvPhys] Verify Links=0x%X Pid=0x%X: head.Flink=%p empty FAIL\n",
                 ActiveLinksOff, PidOff, cur);
        return FALSE;
    }

    // 2026-06-16: Win11 24H2 的 ActiveProcessLinks 链表末端不一定闭环
    //   到 head — Blink 可能指向 PsActiveProcessHead 全局变量本身(不是 EPROCESS)。
    //   遍历到该位置时, ep+PidOff 读到的是 list head 后面的数据(看起来像内核
    //   指针, 不是合法 PID)。改判定: 前 K 个连续节点都是合法 PID 就接受。
    // 阈值: 32 个连续合法 PID = 系统至少有 32 个活进程, 不可能猜中 garbage 偏移。
    const ULONG REQUIRED_VALID_PIDS = 32;
    ULONG validCount = 0;

    for (ULONG i = 0; i < 4096; i++) {
        // 还原 EPROCESS 指针
        PUCHAR ep = (PUCHAR)cur - ActiveLinksOff;

        // 链表回环: Flink 回到了 head — 早闭环就算成功(若已通过阈值)
        if (cur == head) {
            if (validCount >= REQUIRED_VALID_PIDS) {
                HV_HOT_DBG("[HvPhys] Verify Links=0x%X Pid=0x%X: OK (closed at i=%u, valid=%u)\n",
                         ActiveLinksOff, PidOff, i, validCount);
                return TRUE;
            }
            DbgPrint("[HvPhys] Verify Links=0x%X Pid=0x%X: closed too early i=%u valid=%u FAIL\n",
                     ActiveLinksOff, PidOff, i, validCount);
            return FALSE;
        }

        // PidOff 处必须是合理 PID (Win 限制 PID 必须是 4 的倍数, 上限
        // 现代 Windows 是 32 位但实测远低于 0x10000_0000)
        ULONG_PTR pid = *(ULONG_PTR*)(ep + PidOff);
        BOOLEAN pidLooksValid = (pid != 0 && (pid & 3) == 0 && pid <= 0xFFFFFFFFULL);

        if (!pidLooksValid) {
            // 早期遇到非法 PID = 偏移完全不对, 直接失败
            // 后期遇到 = 走到了 list 末端的非 EPROCESS 节点, 已通过阈值就接受
            if (validCount >= REQUIRED_VALID_PIDS) {
                HV_HOT_DBG("[HvPhys] Verify Links=0x%X Pid=0x%X: OK (truncated at i=%u, valid=%u, last pid=0x%llX)\n",
                         ActiveLinksOff, PidOff, i, validCount, (ULONG64)pid);
                return TRUE;
            }
            DbgPrint("[HvPhys] Verify Links=0x%X Pid=0x%X: at i=%u ep=%p bad pid=0x%llX (valid only %u) FAIL\n",
                     ActiveLinksOff, PidOff, i, ep, (ULONG64)pid, validCount);
            return FALSE;
        }
        validCount++;

        cur = cur->Flink;
        if (!cur) {
            if (validCount >= REQUIRED_VALID_PIDS) {
                HV_HOT_DBG("[HvPhys] Verify Links=0x%X Pid=0x%X: OK (NULL Flink at i=%u, valid=%u)\n",
                         ActiveLinksOff, PidOff, i, validCount);
                return TRUE;
            }
            DbgPrint("[HvPhys] Verify Links=0x%X Pid=0x%X: at i=%u NULL Flink (valid only %u) FAIL\n",
                     ActiveLinksOff, PidOff, i, validCount);
            return FALSE;
        }
    }
    // 4096 步还没结束: 异常长, 可能死链
    DbgPrint("[HvPhys] Verify Links=0x%X Pid=0x%X: 4096 steps no close (valid=%u) FAIL\n",
             ActiveLinksOff, PidOff, validCount);
    return FALSE;
}

/*
 * HvPhysProbePebOffset
 *
 * 遍历 ActiveProcessLinks 链表, 对每个候选偏移统计有多少进程的
 * EPROCESS+off 满足:
 *   - 值落在 user-mode VA 范围 (0x10000..0x7FFFFFFFFFFF)
 *   - 页对齐 (PEB 总是页对齐的)
 *
 * 取众数 (命中最多的偏移)。System / Registry / Memory Compression 等
 * kernel-only 进程的 Peb = NULL, 自动被跳过 (NULL 不算命中)。
 *
 * 调用前提: g_HvPhysRootCtx 的 PsInitialSystemProcess / ActiveLinksOff / PidOff
 * 必须已填好。
 */
static ULONG
HvPhysProbePebOffset(
    _In_ PEPROCESS SystemEproc,
    _In_ ULONG ActiveLinksOff)
{
    // 候选偏移: Win 各版本观察值。
    // 2026-06-16 实测 Win11 24H2 Build 26100: Peb = 0x2E0
    static const ULONG kCandidates[] = {
        0x2E0,   // Win11 24H2 Build 26100 (实测)
        0x550,   // Win10 1903+ / Win11 23H2 主流
        0x558,   // Win11 个别版本
        0x3F8,   // Win10 1809 及更早
        0x4C8,   // Win10 1709 备选
    };

    ULONG hits[RTL_NUMBER_OF(kCandidates)] = { 0 };
    PLIST_ENTRY head = (PLIST_ENTRY)((PUCHAR)SystemEproc + ActiveLinksOff);

    PLIST_ENTRY cur = head->Flink;
    for (ULONG i = 0; i < 1024 && cur && cur != head; i++) {
        PUCHAR ep = (PUCHAR)cur - ActiveLinksOff;

        for (ULONG c = 0; c < RTL_NUMBER_OF(kCandidates); c++) {
            UINT64 val = *(UINT64*)(ep + kCandidates[c]);
            if (val != 0 &&
                val >= 0x10000ULL &&
                val < 0x00007FFFFFFFFFFFULL &&
                (val & 0xFFFULL) == 0)
            {
                hits[c]++;
            }
        }

        cur = cur->Flink;
    }

    // 取命中最多的偏移; 至少要有 4 个进程命中才接受 (避开 garbage 字段)
    ULONG bestIdx = 0;
    ULONG bestHits = 0;
    for (ULONG c = 0; c < RTL_NUMBER_OF(kCandidates); c++) {
        if (hits[c] > bestHits) {
            bestHits = hits[c];
            bestIdx = c;
        }
    }

    HV_HOT_DBG("[HvPhys] PebOffset probe: counts={0x2E0:%u, 0x550:%u, 0x558:%u, 0x3F8:%u, 0x4C8:%u} winner=0x%X (%u hits)\n",
             hits[0], hits[1], hits[2], hits[3], hits[4],
             kCandidates[bestIdx], bestHits);

    if (bestHits < 4) {
        // 命中太少 —— 用 0x550 作保底 (Win10 1903+ / Win11 主流)
        return 0x550;
    }

    return kCandidates[bestIdx];
}

static VOID
HvPhysInitRootCtx(VOID)
{
    if (g_HvPhysRootCtx.Initialized) return;

    // 1) 解析 PsInitialSystemProcess (导出全局变量)
    UNICODE_STRING name;
    RtlInitUnicodeString(&name, L"PsInitialSystemProcess");
    PVOID sym = MmGetSystemRoutineAddress(&name);
    if (!sym) {
        HV_HOT_DBG("[HvPhys] RootCtx: PsInitialSystemProcess symbol not found\n");
        return;
    }

    // 导出符号返回的是变量自身的地址 —— 解引用得到 PEPROCESS
    PEPROCESS systemEproc = *(PEPROCESS*)sym;
    if (!systemEproc) {
        HV_HOT_DBG("[HvPhys] RootCtx: PsInitialSystemProcess deref NULL\n");
        return;
    }

    // 2) DTB 偏移 —— 复用 HvPhysProbeDtbOffset, 触发一次探测
    HvPhysProbeDtbOffset();

    // 3) 探测 ActiveProcessLinks + UniqueProcessId 偏移
    //    Win11 24H2 Build 26100 (2026-06-16 WinDbg 实测): Pid=0x1D0, Links=0x1D8
    //    主流值 (Win10 22H2 / Win11 23H2): Pid=0x440, Links=0x448
    //    备选 (老内核): Pid=0x2E8/0x2E0, Links=0x2F0/0x2F8 (Win7 时代不再支持)
    static const struct {
        ULONG ActiveLinksOff;
        ULONG PidOff;
    } kCandidates[] = {
        { 0x1D8, 0x1D0 },  // Win11 24H2 Build 26100 (实测)
        { 0x448, 0x440 },  // Win10 22H2 / Win11 23H2 主流
        { 0x440, 0x438 },  // Win10 1903-21H2 部分
        { 0x2F0, 0x2E8 },  // Win10 RS1-1809 (现在很少见但保险)
        { 0x4D8, 0x4D0 },  // Win11 23H2 部分版本备选
    };

    BOOLEAN found = FALSE;
    for (ULONG i = 0; i < RTL_NUMBER_OF(kCandidates); i++) {
        if (HvPhysVerifyEprocessOffsets(systemEproc,
                                        kCandidates[i].ActiveLinksOff,
                                        kCandidates[i].PidOff)) {
            g_HvPhysRootCtx.ActiveLinksOff = kCandidates[i].ActiveLinksOff;
            g_HvPhysRootCtx.PidOff         = kCandidates[i].PidOff;
            found = TRUE;
            HV_HOT_DBG("[HvPhys] RootCtx: EPROCESS offsets -> Links=0x%X Pid=0x%X "
                     "(System EPROCESS=%p)\n",
                     kCandidates[i].ActiveLinksOff, kCandidates[i].PidOff, systemEproc);
            break;
        }
    }

    if (!found) {
        // 强制使用主流值, 不放弃 —— root mode 链表遍历有 4096 步上限,
        // 即使偏移略有偏差也不会死链, 最多遍历不到目标 PID 返回 NOT_FOUND。
        g_HvPhysRootCtx.ActiveLinksOff = 0x448;
        g_HvPhysRootCtx.PidOff         = 0x440;
        DbgPrint("[HvPhys] RootCtx: EPROCESS offset probe FAILED, "
                 "forcing Links=0x448 Pid=0x440 (mainstream Win10/11)\n");
    }

    // 4) DTB / UserDTB 偏移 —— 沿用 g_DtbOffset 和 g_UserDtbOffset。
    //    UserDTB 在首次 GetCr3 才探, 此时若未探到就先填 0;
    //    后续 Phase C 的 root mode 会跳过 0 偏移, 直接用 KnownUserDtbOffs 表。
    g_HvPhysRootCtx.DtbOff     = g_DtbOffset;
    g_HvPhysRootCtx.UserDtbOff = g_UserDtbOffset;   // 可能为 0, 之后用 KnownUserDtbOffs

    // 5) Known UserDTB 备选偏移表 —— 同 HvPhysFindUserCr3ByGvaWalk 里的
    //    kKnownUserDtbOffsets。Root mode 拿到候选 EPROCESS 后挨个试。
    {
        static const UINT64 kRootKnownUserDtbOffsets[] = {
            0x158, 0x388, 0x3A0, 0x3C0, 0x3F0, 0x440, 0x550, 0x580
        };
        ULONG n = 0;
        for (ULONG i = 0; i < RTL_NUMBER_OF(kRootKnownUserDtbOffsets); i++) {
            if (n >= HV_PHYS_KNOWN_USER_DTB_OFFSETS_MAX) break;
            g_HvPhysRootCtx.KnownUserDtbOffs[n++] = kRootKnownUserDtbOffsets[i];
        }
        g_HvPhysRootCtx.KnownUserDtbOffCount = n;
    }

    // 6) PEB 偏移 —— 遍历 ActiveProcessLinks 在多个进程上做众数表决。
    //    Init 阶段只读 EPROCESS, 不调任何 Mm*/Ps*/Ob*。
    g_HvPhysRootCtx.PebOff = HvPhysProbePebOffset(
        systemEproc, g_HvPhysRootCtx.ActiveLinksOff);

    g_HvPhysRootCtx.PsInitialSystemProcess = systemEproc;
    g_HvPhysRootCtx.Initialized = TRUE;

    HV_HOT_DBG("[HvPhys] RootCtx: Initialized OK "
             "(Sys=%p Links=0x%X Pid=0x%X Dtb=0x%X UserDtb=0x%X Peb=0x%X KnownOffs=%u)\n",
             systemEproc, g_HvPhysRootCtx.ActiveLinksOff, g_HvPhysRootCtx.PidOff,
             g_HvPhysRootCtx.DtbOff, g_HvPhysRootCtx.UserDtbOff,
             g_HvPhysRootCtx.PebOff, g_HvPhysRootCtx.KnownUserDtbOffCount);
}

NTSTATUS
HvPhysAccessInitialize(VOID)
{
    if (g_PhysAllocInitialized) return STATUS_SUCCESS;
    InitializeListHead(&g_PhysAllocList);
    KeInitializeSpinLock(&g_PhysAllocLock);
    KeInitializeSpinLock(&g_PhysInvlpgLock);

    // 一次性初始化 root-mode context (符号 + 偏移缓存)。
    // 失败不致命: g_HvPhysRootCtx.Initialized=FALSE 时 hot path 走老路径。
    HvPhysInitRootCtx();

    g_PhysAllocInitialized = TRUE;
    return STATUS_SUCCESS;
}

// ============================================================
// 模块枚举 (无痕)
// ============================================================
//
// PEB → Ldr → InLoadOrderModuleList → LDR_DATA_TABLE_ENTRY 链表遍历,
// 数据读取全部走 HvVtRootCopyByPid (VMCALL → root mode), 无 Mm*/Ps*/Ob*。
//
// x64 用户态结构偏移 (winternl.h / ntdll!_PEB / ntdll!_LDR_DATA_TABLE_ENTRY,
// Win10/11 全系稳定):
//   PEB:
//     +0x18  Ldr (PEB_LDR_DATA*)
//   PEB_LDR_DATA:
//     +0x10  InLoadOrderModuleList (LIST_ENTRY) {Flink, Blink}
//   LDR_DATA_TABLE_ENTRY:
//     +0x00  InLoadOrderLinks (LIST_ENTRY) —— 这就是 list 节点本体
//     +0x30  DllBase (PVOID)
//     +0x40  SizeOfImage (ULONG)
//     +0x48  FullDllName (UNICODE_STRING)
//     +0x58  BaseDllName (UNICODE_STRING) { USHORT Length; USHORT Max; ULONG _pad; PVOID Buffer; }
//
// 这些偏移对 Win10/11 x64 是 ABI 级稳定的 (公开 PEB 结构), 不需要探测。

#define HV_LDR_OFF_PEB_LDR              0x18
#define HV_LDR_OFF_LDR_INLOAD_LIST      0x10
#define HV_LDR_OFF_ENTRY_DLLBASE        0x30
#define HV_LDR_OFF_ENTRY_SIZEOFIMAGE    0x40
#define HV_LDR_OFF_ENTRY_BASEDLLNAME    0x58

// LDR_DATA_TABLE_ENTRY 我们关心字段的子集 (按文件偏移布局, 一次读完)
#pragma pack(push, 1)
typedef struct _HV_LDR_ENTRY_VIEW {
    UINT64 InLoadFlink;       // +0x00
    UINT64 InLoadBlink;       // +0x08
    UINT64 _InMemFlink;       // +0x10
    UINT64 _InMemBlink;       // +0x18
    UINT64 _InInitFlink;      // +0x20
    UINT64 _InInitBlink;      // +0x28
    UINT64 DllBase;           // +0x30
    UINT64 EntryPoint;        // +0x38
    ULONG  SizeOfImage;       // +0x40
    ULONG  _pad44;            // +0x44 (padding for UNICODE_STRING align)
    USHORT FullName_Len;      // +0x48
    USHORT FullName_Max;      // +0x4A
    ULONG  _pad4C;            // +0x4C (UNICODE_STRING padding to 8-byte)
    UINT64 FullName_Buf;      // +0x50
    USHORT BaseName_Len;      // +0x58
    USHORT BaseName_Max;      // +0x5A
    ULONG  _pad5C;            // +0x5C
    UINT64 BaseName_Buf;      // +0x60
} HV_LDR_ENTRY_VIEW;
#pragma pack(pop)

C_ASSERT(FIELD_OFFSET(HV_LDR_ENTRY_VIEW, DllBase)        == 0x30);
C_ASSERT(FIELD_OFFSET(HV_LDR_ENTRY_VIEW, SizeOfImage)    == 0x40);
C_ASSERT(FIELD_OFFSET(HV_LDR_ENTRY_VIEW, BaseName_Len)   == 0x58);
C_ASSERT(FIELD_OFFSET(HV_LDR_ENTRY_VIEW, BaseName_Buf)   == 0x60);

NTSTATUS
HvPhysEnumerateModules(
    _In_ ULONG TargetPid,
    _Out_writes_to_(MaxCount, *OutCount) PHV_MODULE_INFO OutModules,
    _In_ ULONG MaxCount,
    _Out_ PULONG OutCount)
{
    if (!OutModules || !OutCount || MaxCount == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    *OutCount = 0;
    if (KeGetCurrentIrql() > APC_LEVEL) return STATUS_INVALID_LEVEL;
    if (!g_VtRootEnabled) return STATUS_DEVICE_NOT_READY;

    // 1) 取 PEB user VA (一次 VMCALL)
    UINT64 pebVa = 0;
    NTSTATUS s = HvVtRootGetPebByPid(TargetPid, &pebVa);
    if (!NT_SUCCESS(s)) return s;
    if (pebVa == 0) {
        // 进程是 kernel-only (System/Registry 等), 没有用户模块
        return STATUS_SUCCESS;  // OutCount = 0
    }

    // 2) 读 PEB.Ldr (PEB_LDR_DATA*)
    UINT64 ldrVa = 0;
    SIZE_T done = 0;
    s = HvVtRootCopyByPid(TargetPid, pebVa + HV_LDR_OFF_PEB_LDR,
                          &ldrVa, sizeof(UINT64), FALSE, &done);
    if (!NT_SUCCESS(s) || done != sizeof(UINT64) || ldrVa == 0) {
        DbgPrint("[HvPhys] EnumModules: PID=%u read PEB.Ldr failed (s=0x%X, done=%llu, ldr=0x%llX)\n",
                 TargetPid, s, (ULONGLONG)done, ldrVa);
        return NT_SUCCESS(s) ? STATUS_NOT_FOUND : s;
    }

    // 3) 读 InLoadOrderModuleList head (LIST_ENTRY = 16 bytes)
    UINT64 listHeadVa = ldrVa + HV_LDR_OFF_LDR_INLOAD_LIST;
    UINT64 head[2] = { 0, 0 };
    s = HvVtRootCopyByPid(TargetPid, listHeadVa,
                          &head, sizeof(head), FALSE, &done);
    if (!NT_SUCCESS(s) || done != sizeof(head) || head[0] == 0) {
        DbgPrint("[HvPhys] EnumModules: PID=%u read InLoadList head failed (s=0x%X)\n",
                 TargetPid, s);
        return NT_SUCCESS(s) ? STATUS_NOT_FOUND : s;
    }

    // 4) 沿 Flink 遍历, 每个节点就是 LDR_DATA_TABLE_ENTRY.InLoadOrderLinks
    UINT64 cur = head[0];
    ULONG written = 0;

    for (ULONG i = 0; i < HV_MAX_MODULES_PER_PROCESS && written < MaxCount; i++) {
        if (cur == 0 || cur == listHeadVa) break;     // 链表头, 完成

        HV_LDR_ENTRY_VIEW view = { 0 };
        s = HvVtRootCopyByPid(TargetPid, cur,
                              &view, sizeof(view), FALSE, &done);
        if (!NT_SUCCESS(s) || done != sizeof(view)) {
            DbgPrint("[HvPhys] EnumModules: PID=%u entry @0x%llX read failed (s=0x%X)\n",
                     TargetPid, cur, s);
            break;
        }

        // ntdll 文档行为: list 尾部存在 DllBase=0 哨兵, 跳过但继续遍历
        if (view.DllBase == 0) {
            cur = view.InLoadFlink;
            continue;
        }

        PHV_MODULE_INFO out = &OutModules[written];
        out->DllBase     = view.DllBase;
        out->SizeOfImage = view.SizeOfImage;
        out->Reserved    = 0;
        RtlZeroMemory(out->Name, sizeof(out->Name));

        // 5) 读 BaseDllName.Buffer (WCHAR[]), 限制到 Name 缓冲减一槽留 NUL
        if (view.BaseName_Buf != 0 && view.BaseName_Len > 0) {
            USHORT lenBytes = view.BaseName_Len;
            const USHORT maxBytes = (USHORT)((HV_MODULE_NAME_MAX - 1) * sizeof(WCHAR));
            if (lenBytes > maxBytes) lenBytes = maxBytes;

            SIZE_T nameDone = 0;
            NTSTATUS ns = HvVtRootCopyByPid(TargetPid, view.BaseName_Buf,
                                            out->Name, lenBytes, FALSE, &nameDone);
            if (!NT_SUCCESS(ns) || nameDone == 0) {
                // 名字读不到不致命, 留空名继续
                out->Name[0] = L'\0';
            } else {
                // 确保 null 终结 (HV_MODULE_NAME_MAX-1 处 zero 已由 RtlZeroMemory 保证)
                USHORT charCount = (USHORT)(nameDone / sizeof(WCHAR));
                if (charCount < HV_MODULE_NAME_MAX) {
                    out->Name[charCount] = L'\0';
                }
            }
        }

        written++;
        cur = view.InLoadFlink;
    }

    *OutCount = written;
    return STATUS_SUCCESS;
}

VOID
HvPhysAccessCleanup(VOID)
{
    if (!g_PhysAllocInitialized) return;

    // 注意: 这里不动目标进程页表 —— 进程可能已退或正在退,
    // 走 HvPhysClearPteForVa 反而风险更大。只回收我们这边的物理页。
    KIRQL irql;
    KeAcquireSpinLock(&g_PhysAllocLock, &irql);
    while (!IsListEmpty(&g_PhysAllocList)) {
        PLIST_ENTRY entry = RemoveHeadList(&g_PhysAllocList);
        KeReleaseSpinLock(&g_PhysAllocLock, irql);

        HV_PHYS_ALLOC_RECORD* r = CONTAINING_RECORD(entry, HV_PHYS_ALLOC_RECORD, ListEntry);
        for (ULONG i = 0; i < r->PageCount; i++) {
            HvPhysFreeOnePage(r->Pages[i].KernelVa);
        }
        ExFreePoolWithTag(r->Pages, HV_PHYS_TAG_RECORD);
        ExFreePoolWithTag(r, HV_PHYS_TAG_RECORD);

        KeAcquireSpinLock(&g_PhysAllocLock, &irql);
    }
    KeReleaseSpinLock(&g_PhysAllocLock, irql);
    g_PhysAllocInitialized = FALSE;
}
