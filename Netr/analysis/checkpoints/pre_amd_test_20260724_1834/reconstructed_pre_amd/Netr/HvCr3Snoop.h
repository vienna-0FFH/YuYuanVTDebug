/*
 * HvCr3Snoop.h
 *
 * VMEXIT 期间被动嗅探 GUEST_CR3 的环形缓存。
 *
 * 设计动机:
 *   KVAS 系统上 EPROCESS+0x28 是 shadow CR3 (user-half=0),启发式扫描
 *   KPROCESS.UserDirectoryTableBase 受版本偏移漂移影响,且某些进程(QQMusic
 *   等)上失败 —— 测得 21 个候选全部 PML4[0]=not_present。
 *
 *   反作弊敏感的 API (KeStackAttachProcess / ZwReadVirtualMemory /
 *   MmCopyVirtualMemory) 严禁使用。
 *
 *   解决方案:每次 VMEXIT 时,GUEST_CR3 (VMCS 字段) 或 Vmcb->StateSaveArea.Cr3
 *   都是硬件层观察到的目标进程的**真 user CR3** (KVAS 在 VMENTRY 时已切换)。
 *   把最近 N 个不同的 CR3 记入环形 buffer,后续 walk-validation 时把它们
 *   作为高优先级候选。
 *
 * 反作弊视角:
 *   - 完全 host-only,不动 EPROCESS/KTHREAD/KPCR 任何字段
 *   - 不调任何 NT API,纯内存写入
 *   - PG / EDR 看不到任何动作
 *
 * 性能:
 *   - Record: 1 次 InterlockedIncrement + 1 次写,~10 ns
 *   - 在每个 VMEXIT 入口调用,VMEXIT 频率本身就 < 1M/s,影响可忽略
 */

#ifndef _HV_CR3_SNOOP_H_
#define _HV_CR3_SNOOP_H_

#pragma once

#include <ntddk.h>

// 环形 buffer 容量。64 足够覆盖典型 Windows 桌面同时活跃的进程数。
#define HV_CR3_SNOOP_RING_SIZE  64

/*
 * VMEXIT 入口调用 —— 把当前 GUEST_CR3 写入环形 buffer。
 *
 * Lock-free,root mode 安全。GuestCr3 可以含 PCID 低位,内部自动 mask。
 * 重复值不去重(写开销远低于扫描),Snapshot 时再去重。
 *
 * GuestRip 用来过滤 shadow CR3:KVAS 系统大部分 VMEXIT 在 kernel-mode
 * 触发,GUEST_CR3 此时是 shadow CR3 (user-half empty),对 user-GVA walk
 * 一律失败。所以只在 GuestRip 在 user 半空间 (< 0x800000000000) 时记录,
 * 这样 ring 里只有真 user CR3。传 0 等价于不过滤(用于兼容旧调用)。
 */
VOID HvCr3SnoopRecord(_In_ UINT64 GuestCr3, _In_ UINT64 GuestRip);

/*
 * PASSIVE_LEVEL 调用 —— 拷贝当前 ring 内所有非零、去重后的 CR3。
 *
 * 返回实际写入的 CR3 个数。OutBuffer 容量必须 >= HV_CR3_SNOOP_RING_SIZE。
 */
ULONG HvCr3SnoopSnapshot(
    _Out_writes_to_(MaxCount, return) UINT64* OutBuffer,
    _In_ ULONG MaxCount);

/*
 * 启用/禁用嗅探(默认禁用)。HvCr3SnoopRecord 在 disabled 时直接 return,
 * 避免常驻 VMEXIT 路径的固定开销。HvPhysGetProcessCr3 第一次启发式失败时
 * 自动 enable,之后保持。
 */
VOID HvCr3SnoopEnable(VOID);
VOID HvCr3SnoopDisable(VOID);
BOOLEAN HvCr3SnoopIsEnabled(VOID);

#endif // _HV_CR3_SNOOP_H_
