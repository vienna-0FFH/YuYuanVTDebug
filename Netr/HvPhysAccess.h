/*
 * HvPhysAccess.h
 *
 * 物理页直通访问 (#27)
 *
 * 用 4 级页表 walk + MmMapIoSpace 实现跨进程内存读写,完全绕开
 * KeStackAttachProcess / Zw*VirtualMemory,在 ETWTI/EDR 视野下静默。
 *
 * 服务对象:
 *   - HvMemoryRead / HvMemoryWrite (#29) —— 内存 R/W
 *   - HvMemoryAllocate / HvMemoryFree (#30) —— Alloc/Free
 *   - HvInjectShellcode / HvInjectDll (#31) —— 注入路径里的内存操作
 *
 * 限制(本期):
 *   - 不锁页:遇到被换出的 GVA 返回 STATUS_NOT_FOUND,由用户态重试。
 *   - 不拆 2MB/1GB 大页:Allocate 选址时跳过命中大页的区域。
 *   - 不走 root 模式 VMCALL:直接在 IOCTL 路径 (PASSIVE_LEVEL) 调用。
 */

#ifndef _HV_PHYS_ACCESS_H_
#define _HV_PHYS_ACCESS_H_

#pragma once

#include <ntddk.h>

#define HV_PHYS_TAG  'hPvH'

// ============================================================
// Root-mode context (init 阶段一次性填充, 之后只读)
// ============================================================
//
// HvVtRootRootCopyByPid 在 root mode (IRQ-off) 解 PID → EPROCESS 时需要
// 一份在 init 阶段已经解析好的 nt 符号 + EPROCESS 偏移表。所有 Mm* / Ps*
// 调用集中到 HvPhysAccessInitialize, hot path 完全静默。
//
// 反作弊视角:
//   - init 阶段的 MmGetSystemRoutineAddress 是 DriverEntry 后期单次行为,
//     与 hot path 解耦, 不在反作弊关注的内存读写时间窗内
//   - hot path 只读这个 const struct, 不调任何 Mm* / Ps* / Ob*

#define HV_PHYS_KNOWN_USER_DTB_OFFSETS_MAX  8

typedef struct _HV_PHYS_ROOT_CTX {
    // PsInitialSystemProcess (PEPROCESS*) —— 通过 MmGetSystemRoutineAddress
    // 一次性解析得到。Root mode 从这里出发遍历 ActiveProcessLinks 链表
    // 找匹配 PID, 完全不调 PsLookupProcessByProcessId / Ob*。
    PVOID  PsInitialSystemProcess;

    // EPROCESS::ActiveProcessLinks (LIST_ENTRY) 偏移。Win10 22H2 / Win11
    // 普遍为 0x448, 但版本会漂移。InitProbe 会校验头尾闭合。
    ULONG  ActiveLinksOff;

    // EPROCESS::UniqueProcessId (HANDLE → ULONG_PTR) 偏移。普遍为 0x440。
    ULONG  PidOff;

    // KPROCESS::DirectoryTableBase 偏移, 普遍为 0x28 (由 g_DtbOffset 探得)。
    ULONG  DtbOff;

    // EPROCESS::UserDirectoryTableBase (KVAS 系统) 偏移。0 表示
    // 当前系统未启用 KVAS 或本字段未探到, 此时 root mode 应跳过此候选。
    ULONG  UserDtbOff;

    // Win10/11 各版本观察到的 UserDirectoryTableBase 备选偏移表。
    // Root mode 不去探, 把这些当成"可能的 user CR3 字段"挨个尝试。
    UINT64 KnownUserDtbOffs[HV_PHYS_KNOWN_USER_DTB_OFFSETS_MAX];
    ULONG  KnownUserDtbOffCount;

    // EPROCESS::Peb 偏移。Win10 1903+ / Win11 全系普遍为 0x550, 个别版本
    // 微调到 0x558 / 0x3F8。0 表示未探到 (模块枚举不可用)。
    // 探测策略: 遍历 ActiveProcessLinks, 统计候选偏移在多少进程上落在
    // user-VA 范围且页对齐, 取众数。
    ULONG  PebOff;

    // 是否已成功初始化。Root mode 在 FALSE 时直接 fallback 到老路径
    // (虽然老路径在 hot path 不应被走到, 但保险起见保留分支)。
    BOOLEAN Initialized;

    // ============================================================
    // EPROCESS lookup cache (root mode, 优化 #2)
    // ============================================================
    // 缓存最近一次 PID → EPROCESS 映射, 避免每次 read/write 都重走 4096 步
    // ActiveProcessLinks 链表 (CheatEngine-style 同 PID 高频轮询场景下,
    // 链表 walk 是 EPROCESS 解析的最大开销, 缓存命中省 3-10 us 每次)。
    //
    // 一致性保护:
    //   - 命中后先读 *(ULONG*)(CachedEproc + PidOff) 验 PID 仍匹配
    //   - 失配 (进程退出 / EPROCESS pool 复用 / TargetPid 不同) → 回退 walk
    //   - 多核竞争: CachedPid / CachedEproc 用 volatile 单 64-bit 写,
    //     最坏看到 stale 配对, 校验阶段必然 PID 失配, 退回 walk, 不会用错指针
    //   - 4-byte CachedPid + 8-byte CachedEproc 均自然对齐, x64 单次 mov 原子
    volatile ULONG  CachedPid;     // 0 = 未缓存
    ULONG           _CacheAlign;   // 保 CachedEproc 8-byte 对齐
    volatile UINT64 CachedEproc;   // PEPROCESS, 0 = 未缓存
} HV_PHYS_ROOT_CTX, *PHV_PHYS_ROOT_CTX;

// 全局单例, 在 HvPhysAccessInitialize 中填充, 之后只读。
// HvVtRoot.c 通过 extern 访问, 在 root mode 安全。
extern HV_PHYS_ROOT_CTX g_HvPhysRootCtx;

// ============================================================
// CR3 / GVA → HPA 翻译
// ============================================================

/*
 * 从 PsLookupProcessByProcessId 拿到的 EPROCESS 读出 DirectoryTableBase。
 * 仅这一步还走 Ps API,只读 EPROCESS,不引发任何状态变化。
 * 返回值的低 12 位已清零 (CR3 物理页基址)。
 */
NTSTATUS
HvPhysGetProcessCr3(
    _In_ ULONG ProcessId,
    _Out_ PUINT64 OutCr3
);

/*
 * HvPhysFindUserCr3ByPid -- 真 user CR3 双重 MZ 锚点查找 (PEB→ImageBase→MZ)。
 * 在 KVAS Win11 24H2 上 HvPhysGetProcessCr3 经常返 shadow CR3,本函数返真 user CR3。
 * IRQL <= APC_LEVEL, 需 g_VtRootEnabled。
 * 返 STATUS_NOT_FOUND 表示进程是 kernel-only 或找不到。
 */
NTSTATUS
HvPhysFindUserCr3ByPid(
    _In_ ULONG ProcessId,
    _Out_ PUINT64 OutCr3
);

/*
 * 走给定 CR3 的 4 级页表,把 Guest VA 翻译为 Host 物理地址。
 * 处理 1GB/2MB/4KB 大页。
 *
 * Out 参数:
 *   OutHpa       —— 必填,翻译结果。
 *   OutPageSize  —— 可选,实际页大小 (4096/0x200000/0x40000000)。
 *   OutPteFlags  —— 可选,叶子 PTE 的原始 64 位值 (含 P/RW/US/NX 等位)。
 *
 * 失败码:
 *   STATUS_INVALID_ADDRESS_COMPONENT —— 中间表 PRESENT=0,GVA 未映射。
 *   STATUS_NOT_FOUND                  —— 页被换出 (PTE PRESENT=0 但 transition)。
 *   STATUS_UNSUCCESSFUL               —— MmMapIoSpace 映 PT 失败。
 */
NTSTATUS
HvPhysGvaToHpa(
    _In_ UINT64 TargetCr3,
    _In_ UINT64 Gva,
    _Out_ PPHYSICAL_ADDRESS OutHpa,
    _Out_opt_ PSIZE_T OutPageSize,
    _Out_opt_ PUINT64 OutPteFlags
);

/*
 * HvPhysSetWalkQuiet —— TRUE 时抑制 HvPhysGvaToHpa 的 walk-fail 诊断 dump。
 * HvCloak::EnumWorkingSet 扫 user-half 4M 次, 跳过未映射区时不能让日志爆炸。
 * caller 必须配对 set/clear。
 */
VOID HvPhysSetWalkQuiet(_In_ BOOLEAN Quiet);

// ============================================================
// 跨进程 Read / Write
// ============================================================

/*
 * 跨进程内存读 —— 按 4KB 边界切分,逐页 MmMapIoSpace + memcpy + Unmap。
 * 不调用 KeStackAttachProcess,不调 ZwReadVirtualMemory。
 *
 * 失败码:
 *   STATUS_INVALID_PARAMETER —— 参数为 NULL 或 Size=0。
 *   STATUS_NOT_FOUND          —— GVA 未映射或被换出。读取在该页处中止,
 *                                BytesRead 反映成功的字节数。
 *   STATUS_INSUFFICIENT_RESOURCES —— MmMapIoSpace 失败。
 */
NTSTATUS
HvPhysReadProcessMemory(
    _In_ ULONG TargetPid,
    _In_ UINT64 Gva,
    _Out_writes_bytes_(Size) PVOID Buffer,
    _In_ SIZE_T Size,
    _Out_opt_ PSIZE_T BytesRead
);

/*
 * 跨进程内存写 —— 同样按 4KB 切分。写之前不验证 PTE.RW,因为内核映射后
 * memcpy 写到的是物理页,Guest 视角看到的就是新内容。
 *
 * 失败码同 Read。
 */
NTSTATUS
HvPhysWriteProcessMemory(
    _In_ ULONG TargetPid,
    _In_ UINT64 Gva,
    _In_reads_bytes_(Size) PVOID Buffer,
    _In_ SIZE_T Size,
    _Out_opt_ PSIZE_T BytesWritten
);

// ============================================================
// 目标进程地址空间内分配 / 释放 (#30, Phase 4)
// ============================================================

/*
 * 在目标进程地址空间分配虚拟内存 —— 不走 ZwAllocateVirtualMemory。
 *
 * 实现:扫目标 CR3 的 PML4/PDPT/PD/PT 找连续空洞,逐 4KB 分配新物理页
 * (HvAllocateNonPagedZeroed) 并在目标页表插入 PTE。缺失的中间表也从
 * 我们的池里分配并写入父表。
 *
 * 参数:
 *   InOutGva   —— 输入: 0 = 自动选址; 非 0 = 尝试指定 VA (失败返回错误)。
 *                  输出: 实际分配到的 VA。
 *   Protection —— PAGE_READWRITE / PAGE_EXECUTE_READ / PAGE_EXECUTE_READWRITE。
 *                  其他 PROTECTION_MASK 值视为 PAGE_READWRITE。
 *
 * 限制(本期):选址时如果撞上 2MB/1GB 大页,跳过该 VA 区间,不拆大页。
 */
NTSTATUS
HvPhysAllocateInProcess(
    _In_ ULONG TargetPid,
    _In_ SIZE_T Size,
    _In_ ULONG Protection,
    _Inout_ PUINT64 InOutGva
);

/*
 * 在目标进程地址空间释放虚拟内存 —— 清 PTE PRESENT=0,广播 INVLPG,
 * 然后释放物理页。中间表暂不回收(可空但不释放,留待目标进程退出统一清理)。
 */
NTSTATUS
HvPhysFreeInProcess(
    _In_ ULONG TargetPid,
    _In_ UINT64 Gva,
    _In_ SIZE_T Size
);

// ============================================================
// 叶 PTE 位置查询 (用于阶段 6 VT 无痕 gadget 初始化)
// ============================================================

/*
 * 走 TargetCr3 的页表,找到 TargetVa 对应的**叶 PTE 所在 PT 页**的 HPA
 * 与 entry 索引。仅对 4KB 粒度成立 —— 若中间表撞到 PS=1(2MB/1GB 大页)
 * 返回 STATUS_NOT_SUPPORTED。
 *
 * 用途: HvVtRoot 初始化 scratch 自映射 gadget 时,需要知道
 *       "ScratchVa 的 PTE 写在哪个 PT 物理页的第几个 slot"。
 *
 * 输出:
 *   OutPtPagePa  —— 包含该 PTE 的 PT 页 HPA (4KB 对齐)。
 *   OutPteIndex  —— PTE 在该页内的索引 (0..511)。
 *   OutOrigPte   —— 可选,该 PTE 当前 64 位值,便于 cleanup 还原。
 */
NTSTATUS
HvPhysFindLeafPteLocation(
    _In_ UINT64 TargetCr3,
    _In_ UINT64 TargetVa,
    _Out_ PUINT64 OutPtPagePa,
    _Out_ PULONG OutPteIndex,
    _Out_opt_ PUINT64 OutOrigPte
);

// ============================================================
// 模块枚举 (无痕, 经 VtRoot 读 PEB.Ldr 链表)
// ============================================================

#define HV_MODULE_NAME_MAX        128   // WCHAR 数, 含末尾 0
#define HV_MAX_MODULES_PER_PROCESS 384  // 上限, 防 LDR 链表 corruption 跑飞

#pragma pack(push, 8)
typedef struct _HV_MODULE_INFO {
    UINT64 DllBase;                          // LDR_DATA_TABLE_ENTRY.DllBase
    ULONG  SizeOfImage;                      // LDR_DATA_TABLE_ENTRY.SizeOfImage
    ULONG  Reserved;                         // 对齐
    WCHAR  Name[HV_MODULE_NAME_MAX];         // BaseDllName, null-terminated
} HV_MODULE_INFO, *PHV_MODULE_INFO;
#pragma pack(pop)

/*
 * 枚举目标进程加载的模块 (DLL/EXE)。整条数据路径基于 VtRoot, 完全不触发
 * Mm* / Ps* / Ob* / Nt* API。
 *
 * 流程:
 *   1) VMCALL (mode=GetPeb) → root mode 解 PID → EPROCESS → 读 EPROCESS.Peb
 *   2) HvVtRootCopyByPid 读 PEB[+0x18] = Ldr (PEB_LDR_DATA*)
 *   3) HvVtRootCopyByPid 读 Ldr[+0x10..+0x20] = InLoadOrderModuleList (LIST_ENTRY)
 *   4) 沿 Flink 遍历, 每个 LDR_DATA_TABLE_ENTRY 读 DllBase/SizeOfImage/BaseDllName
 *   5) BaseDllName.Buffer 单独读为 WCHAR[]
 *
 * 返回:
 *   STATUS_SUCCESS           —— *OutCount 是实际写入的模块数 (≤ MaxCount)
 *   STATUS_INVALID_PARAMETER —— OutModules/OutCount NULL 或 MaxCount=0
 *   STATUS_INVALID_LEVEL     —— IRQL > APC_LEVEL
 *   STATUS_DEVICE_NOT_READY  —— VtRoot 未启用或 RootCtx 未初始化
 *   STATUS_NOT_FOUND         —— PID 不存在 / 目标进程无 user-mode (System 等)
 */
NTSTATUS
HvPhysEnumerateModules(
    _In_ ULONG TargetPid,
    _Out_writes_to_(MaxCount, *OutCount) PHV_MODULE_INFO OutModules,
    _In_ ULONG MaxCount,
    _Out_ PULONG OutCount
);

// ============================================================
// 生命周期
// ============================================================

/*
 * 初始化 HvPhysAccess (DriverEntry 后期调用) —— 当前用于初始化分配跟踪表。
 * 若初始化失败,Read/Write 仍可用,只是 Alloc/Free 不可用。
 */
NTSTATUS
HvPhysAccessInitialize(VOID);

VOID
HvPhysAccessCleanup(VOID);

#endif // _HV_PHYS_ACCESS_H_
