/*
 * HvVtRoot.h
 *
 * 阶段 6: 真·VT 无痕物理 R/W
 *
 * 把 HvPhysReadProcessMemory / HvPhysWriteProcessMemory 的"实际拷贝"
 * 一步搬到 root 模式: PASSIVE 端 IOCTL → AsmVmCallPhysCopy → VM-Exit
 * 进 root handler → 通过 per-VCPU self-map gadget 改 host PTE 重定位一个
 * scratch 内核 VA 到目标 HPA → memcpy → 回 guest。
 *
 * 整条数据路径不调任何 Mm* / Ke* / Ps* / Zw* API (Init 阶段一次性除外),
 * EDR / AC 内核 API 监控视角完全静默。
 *
 * 设计要点见 HvVtRoot.c 文件头注释,以及 plan 文件阶段 6 章节。
 */

#ifndef _HV_VT_ROOT_H_
#define _HV_VT_ROOT_H_

#pragma once

#include <ntddk.h>
#include "HvTypes.h"

// VMCALL/VMMCALL service number 选用 0xEBF00010 (沿用项目里现有 0xEBF00001
// INVEPT 的命名约定)
#define VMCALL_PHYS_COPY    0xEBF00010ULL

// Direction / mode 编码 (在 r11)
// 0/1 是原始 R/W 路径; 2+ 是辅助查询服务 (复用同一 VMCALL 服务号 +
// 同一 AsmVmCallPhysCopy ASM 入口, 由 root mode dispatch on R11)
#define HV_VTROOT_DIR_READ      0   // target → kernel buffer
#define HV_VTROOT_DIR_WRITE     1   // kernel buffer → target
#define HV_VTROOT_MODE_GET_PEB  2   // 取目标 PID 的 PEB user VA, 经 R10 返回
#define HV_VTROOT_MODE_RESOLVE_CR3  3   // 走 24 候选+MZ 验证, R10=真 user CR3
#define HV_VTROOT_MODE_GVA_TO_HPA   4   // walk GVA, R10=HPA, R9=pageSize

// ============================================================
// 全局灰度开关
// ============================================================

/*
 * 默认 FALSE。在 HvVtRootInitializeAll 全部 CPU 成功后置 TRUE。
 * HvPhysCopyAcrossPages 检查这个 flag 决定走 VMCALL 路径还是回退到
 * 旧的 MmMapIoSpace 路径。出问题改回 FALSE 即可回滚。
 */
extern BOOLEAN g_VtRootEnabled;

// ============================================================
// Init / Cleanup
// ============================================================

/*
 * 单个 VCPU 的 gadget 初始化:
 *   1) MmAllocateContiguousMemory 分配 ScratchData / ScratchPte 两页
 *   2) HvPhysFindLeafPteLocation 在 host CR3 找两个 VA 的 leaf PTE
 *   3) 临时 MmMapIoSpace 改 ScratchPte 的 PTE,让它指向 ScratchData 的
 *      PT 物理页 —— ScratchPte 从此永久映射"ScratchData 的 PT 页",
 *      运行时改 ScratchData 的 PTE 直接写 ScratchPte 即可,完全不依赖
 *      Mm*
 *   4) 失败任一步,清理已分配资源,留 Initialized = FALSE
 *
 * 仅在 PASSIVE_LEVEL 调用 (DriverEntry 时机)。
 */
NTSTATUS
HvVtRootInitializePerCpu(_Inout_ PVCPU_DATA Vcpu);

VOID
HvVtRootCleanupPerCpu(_Inout_ PVCPU_DATA Vcpu);

/*
 * 遍历所有 VCPU 调上面两个。成功 init 全部 CPU 后,把
 * g_VtRootEnabled 置 TRUE。任一失败也不算致命:fallback 路径仍可用。
 */
NTSTATUS
HvVtRootInitializeAll(VOID);

VOID
HvVtRootCleanupAll(VOID);

// ============================================================
// Root-mode copy entry (由 HvVmExit.c 的 VMCALL handler 调用)
// ============================================================

/*
 * 在 root 模式执行单页内的拷贝。
 * 输入:
 *   Vcpu        —— 当前 VCPU 的数据 (gadget 在里面)
 *   TargetCr3   —— 目标进程 CR3
 *   TargetGva   —— 目标 GVA
 *   KernelBuf   —— 内核 buffer (host CR3 可访问的 KVA)
 *   Size        —— 必须 ≤ 4KB 且不跨页 (PASSIVE 端切片)
 *   IsWrite     —— 0=read, 1=write
 *   BytesDone   —— 出参,实际拷贝字节数
 *
 * 不进任何 Mm* / Ke* API。只用 __invlpg。
 * 错误:
 *   STATUS_DEVICE_NOT_READY        —— gadget 未初始化
 *   STATUS_INVALID_ADDRESS_COMPONENT —— 中间页表 PRESENT=0
 *   STATUS_NOT_FOUND               —— 叶 PTE PRESENT=0
 */
NTSTATUS
HvVtRootRootCopyOnePage(
    _Inout_ PVCPU_DATA Vcpu,
    _In_ UINT64 TargetCr3,
    _In_ UINT64 TargetGva,
    _Inout_updates_bytes_(Size) PUCHAR KernelBuf,
    _In_ SIZE_T Size,
    _In_ BOOLEAN IsWrite,
    _Out_ PSIZE_T BytesDone
);

// ============================================================
// PASSIVE-level entry (供 HvPhysAccess 调用)
// ============================================================

/*
 * 在 PASSIVE_LEVEL 跨页执行 R/W。内部循环按 4KB 边界切分,逐页 VMCALL。
 * 这是 HvPhysReadProcessMemory/Write 的新内核路径 (走 VMCALL,绕 Mm*)。
 *
 * 不调用 ZwReadVirtualMemory / KeStackAttachProcess / MmCopyVirtualMemory,
 * 也不调用 MmMapIoSpace —— 完全在 root 模式做实际数据拷贝。
 *
 * 失败码同 HvPhysReadProcessMemory:
 *   STATUS_INVALID_PARAMETER      —— Buffer NULL 或 Size=0
 *   STATUS_INVALID_LEVEL          —— IRQL > APC_LEVEL
 *   STATUS_DEVICE_NOT_READY       —— gadget 未初始化
 *   STATUS_NOT_FOUND              —— 目标页未映射或被换出
 *
 * 部分成功的字节数由 BytesDone 返回 (与旧 API 行为一致)。
 */
NTSTATUS
HvVtRootCopy(
    _In_ ULONG TargetPid,
    _In_ UINT64 Gva,
    _Inout_updates_bytes_(Size) PVOID Buffer,
    _In_ SIZE_T Size,
    _In_ BOOLEAN IsWrite,
    _Out_opt_ PSIZE_T BytesDone
);

/*
 * 与 HvVtRootCopy 相同,但跳过 HvPhysGetProcessCr3 启发式 —— caller 已经
 * 通过 walk-validation / CR3 snoop ring 拿到了校正的真 user CR3,直接传入。
 *
 * 这是反作弊敏感场景的关键路径:校正 CR3 之后,数据拷贝完全在 root mode
 * 完成,不动 EPROCESS、不调 MmMapIoSpace。
 */
NTSTATUS
HvVtRootCopyWithCr3(
    _In_ UINT64 TargetCr3,
    _In_ UINT64 Gva,
    _Inout_updates_bytes_(Size) PVOID Buffer,
    _In_ SIZE_T Size,
    _In_ BOOLEAN IsWrite,
    _Out_opt_ PSIZE_T BytesDone
);

// ============================================================
// PASSIVE-level by-PID copy (Phase C, 反作弊敏感 hot path)
// ============================================================
//
// 把 PID + GVA 传给 root mode handler, EPROCESS 链表遍历 + CR3 候选收集
// 全部在 root mode 完成。Hot path 完全不调 Mm* / Ps* / Ob*。
//
// 这是 HvPhysCopyAcrossPages 的新内核路径, 与 HvVtRootCopy 不同的是:
//   - HvVtRootCopy: 调 HvPhysGetProcessCr3 (Mm*/Ps*) 再传 CR3 给 root mode
//   - HvVtRootCopyByPid: 只传 PID, root mode 自己解析 EPROCESS
//
// 失败码同 HvVtRootCopyWithCr3。
//
NTSTATUS
HvVtRootCopyByPid(
    _In_ ULONG TargetPid,
    _In_ UINT64 Gva,
    _Inout_updates_bytes_(Size) PVOID Buffer,
    _In_ SIZE_T Size,
    _In_ BOOLEAN IsWrite,
    _Out_opt_ PSIZE_T BytesDone);

// Root mode 入口 (HvVmExit.c VMCALL handler 调用)
NTSTATUS
HvVtRootRootCopyByPid(
    _Inout_ PVCPU_DATA Vcpu,
    _In_ ULONG TargetPid,
    _In_ UINT64 TargetGva,
    _Inout_updates_bytes_(Size) PUCHAR KernelBuf,
    _In_ SIZE_T Size,
    _In_ BOOLEAN IsWrite,
    _Out_ PSIZE_T BytesDone);

// ============================================================
// GetPeb: PID → PEB user VA (复用 VMCALL_PHYS_COPY, R11 = 2)
// ============================================================
//
// 用于模块枚举。Root mode 解 PID → EPROCESS → 读 EPROCESS+PebOff,
// 整条路径不触发 Mm*/Ps*/Ob*。
//
// PASSIVE 入口失败码:
//   STATUS_INVALID_PARAMETER —— OutPebVa NULL 或 Pid=0
//   STATUS_INVALID_LEVEL     —— IRQL > APC_LEVEL
//   STATUS_DEVICE_NOT_READY  —— g_VtRootEnabled=FALSE 或 RootCtx 未 Init
//   STATUS_NOT_FOUND         —— PID 未找到
//   *OutPebVa = 0            —— 进程是 kernel-only (System/Registry 等),
//                               不算错误, 返回 STATUS_SUCCESS

NTSTATUS
HvVtRootGetPebByPid(
    _In_ ULONG TargetPid,
    _Out_ PUINT64 OutPebVa);

// Root mode 入口 (HvVmExit.c VMCALL handler 调用)
NTSTATUS
HvVtRootRootGetPebByPid(
    _In_ ULONG TargetPid,
    _Out_ PUINT64 OutPebVa);

// ============================================================
// HvVtRootGetResolvedUserCr3 - PASSIVE 查 PID → 真 user CR3 cache
// ============================================================
//
// HvVtRootRootCopyByPid 在 root mode 成功 walk + MZ 验证后, 把
// (PID, CR3) 写到全局 cache。本 API 提供 PASSIVE 查询接口。
//
// 使用模式 (HvCloak.c::HvCloakAddDebugger):
//   1) 发一次 dummy HvPhysReadProcessMemory(pid, KUSER_SHARED_DATA, ...)
//      触发 VtRoot 24 候选 walk + 缓存写入
//   2) 调本 API 取真 user CR3
//   3) 用真 CR3 走 EnumWorkingSet
//
// 这条路径完全不依赖 __readcr3() / KeStackAttachProcess —— KVAS 启用时
// driver 在 kernel mode 永远 read shadow CR3, 那条路径在 Win11 24H2
// 拿不到真 user CR3。
//
// 返回:
//   STATUS_SUCCESS         *OutCr3 = 真 user CR3
//   STATUS_NOT_FOUND       cache 中没这个 PID (没人 VtRoot walk 过)
//   STATUS_INVALID_PARAMETER
NTSTATUS
HvVtRootGetResolvedUserCr3(
    _In_ ULONG TargetPid,
    _Out_ PUINT64 OutCr3);

// ============================================================
// Root-mode user CR3 解析 + GVA→HPA walker (PASSIVE 入口)
// ============================================================
//
// 2026-06-17: KVAS Win11 24H2 PASSIVE 层 walker (MmMapIoSpace 走 host
// shadow PT) 看不到真 user PT 物理页内容,任何基于 PASSIVE walker 的
// "找真 user CR3" 都失败。
//
// 解决:把整条 walk 路径下到 root mode — root mode 用 EPT identity,
// 不走 host PT,能正确读 PT 物理页。
//
// HvVtRootResolveUserCr3 - 走 VMCALL 进 root mode, 让 root 用 24 候选+MZ
// 验证选对真 user CR3, 写回 OutCr3。
//
// HvVtRootWalkGvaToHpa - 走 VMCALL 进 root mode, 让 root 用 24 候选选对
// 真 user CR3, walk GVA, 返回 HPA + pageSize (4KB/2MB/1GB)。
//
// 两个 API 都在 PASSIVE_LEVEL 调用, 内部走 vmcall 同步执行。
NTSTATUS
HvVtRootResolveUserCr3(
    _In_ ULONG TargetPid,
    _Out_ PUINT64 OutCr3);

NTSTATUS
HvVtRootWalkGvaToHpa(
    _In_ ULONG TargetPid,
    _In_ UINT64 Gva,
    _Out_ PUINT64 OutHpa,
    _Out_opt_ PUINT64 OutPageSize);

// Root mode 入口 (HvVmExit.c VMCALL handler 调用)
NTSTATUS
HvVtRootRootResolveUserCr3(
    _In_ ULONG TargetPid,
    _Out_ PUINT64 OutCr3);

NTSTATUS
HvVtRootRootWalkGvaToHpa(
    _Inout_ PVCPU_DATA Vcpu,
    _In_ ULONG TargetPid,
    _In_ UINT64 Gva,
    _Out_ PUINT64 OutHpa,
    _Out_ PUINT64 OutPageSize);

#endif // _HV_VT_ROOT_H_
