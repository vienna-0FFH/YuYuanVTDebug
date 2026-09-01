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
#define HV_VTROOT_DIR_READ      0   // validated CR3: target -> kernel buffer
#define HV_VTROOT_DIR_WRITE     1   // validated CR3: kernel buffer -> target
#define HV_VTROOT_MODE_GET_PEB  2   // reserved legacy ABI
#define HV_VTROOT_MODE_RESOLVE_CR3  3   // reserved legacy ABI
#define HV_VTROOT_MODE_GVA_TO_HPA   4   // validated CR3: walk GVA
#define HV_VTROOT_MODE_PROCESS_READ 5   // RDX = nonpaged process snapshot request
#define HV_VTROOT_MODE_PROCESS_WRITE 6  // RDX = nonpaged process snapshot request
#define HV_VTROOT_MODE_PROCESS_RESOLVE 7 // root validates and returns CR3
#define HV_VTROOT_MODE_PROCESS_WALK 8    // root validates CR3 and walks GVA
#define HV_VTROOT_MODE_LEAF_PTE_INFO 9   // trusted CR3: return leaf entry metadata

#define HV_VTROOT_LEAF_INFO_MAGIC    0x3146504C52545648ULL /* "HVTRLPF1" */
#define HV_VTROOT_LEAF_INFO_VERSION  1UL

#define HV_VTROOT_LEAF_LEVEL_PT      1UL  // 4KB PTE in PT
#define HV_VTROOT_LEAF_LEVEL_PD      2UL  // 2MB PDE in PD
#define HV_VTROOT_LEAF_LEVEL_PDPT    3UL  // 1GB PDPTE in PDPT

// LeafFlags is the original leaf entry with only its address field removed.
// Bit 7 is deliberately level-dependent: PAT for a 4KB PTE, PS for a
// 2MB/1GB PDE/PDPTE. Large-page PAT remains at bit 12.
#define HV_VTROOT_LEAF_BIT7           (1ULL << 7)
#define HV_VTROOT_LEAF_LARGE_PAT      (1ULL << 12)

typedef struct _HV_VTROOT_LEAF_PTE_INFO {
    UINT64 Magic;
    ULONG  Version;
    ULONG  Size;
    UINT64 LeafTablePa;
    ULONG  LeafIndex;
    ULONG  LeafLevel;
    UINT64 OriginalEntry; // complete PTE/PDE/PDPTE value
    UINT64 LeafHpa;       // translated HPA including the GVA page offset
    UINT64 PageSize;      // 4KB, 2MB or 1GB
    UINT64 LeafFlags;     // OriginalEntry with the level-specific address removed
} HV_VTROOT_LEAF_PTE_INFO, *PHV_VTROOT_LEAF_PTE_INFO;

C_ASSERT(sizeof(HV_VTROOT_LEAF_PTE_INFO) == 64);

// ============================================================
// 全局灰度开关
// ============================================================

/*
 * 默认 FALSE。在 HvVtRootInitializeAll 全部 CPU 成功后置 TRUE。
 * PID 物理数据面只在该 flag 为 TRUE 时发布；失败返回
 * STATUS_DEVICE_NOT_READY，不存在 Windows/MmMapIoSpace walker fallback。
 */
extern volatile BOOLEAN g_VtRootEnabled;

// ============================================================
// Init / Cleanup
// ============================================================

/*
 * 单个 VCPU 的 V2 gadget 初始化:
 *   1) 分配 nonpaged/contiguous scratch backing 与私有页表岛资源；
 *   2) 在预留 PML4 槽建立每 CPU 独占的 scratch VA/PTE 所有权；
 *   3) root 运行时只改本 CPU 私有 PTE、INVLPG 并复制一页；
 *   4) 任一步失败都回滚本 CPU 资源并保持 Initialized = FALSE。
 *
 * 仅在 PASSIVE_LEVEL 调用 (DriverEntry 时机)。
 */
NTSTATUS
HvVtRootInitializePerCpu(_Inout_ PVCPU_DATA Vcpu);

VOID
HvVtRootCleanupPerCpu(_Inout_ PVCPU_DATA Vcpu);

/*
 * 遍历所有 VCPU 调上面两个。成功 init 全部 CPU 后,把
 * g_VtRootEnabled 置 TRUE。任一失败都会撤销发布；普通 hypervisor 可继续
 * 运行，但 PID 物理访问明确不可用。
 */
NTSTATUS
HvVtRootInitializeAll(VOID);

VOID
HvVtRootCleanupAll(VOID);

NTSTATUS
HvVtRootInvokeService(
    _In_ UINT64 TargetCr3,
    _In_ UINT64 TargetGva,
    _Inout_opt_ PVOID KernelBuffer,
    _In_ SIZE_T Size,
    _In_ ULONG Mode,
    _Out_ PSIZE_T OutResult);

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

NTSTATUS
HvVtRootRootProcessRequest(
    _Inout_ PVCPU_DATA Vcpu,
    _In_ PVOID RequestAddress,
    _In_ ULONG Mode,
    _Out_ PUINT64 OutResult);

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
// PASSIVE-level by-PID copy (VT-first data path)
// ============================================================
//
// PASSIVE obtains a referenced EPROCESS, captures immutable PID/create-time/
// PEB/image/CR3-candidate metadata, and MDL-locks the target plus validation
// anchors. VMX-root/SVM-host then validates ownership, walks and copies without
// calling Windows memory-manager or object-manager services.
//
NTSTATUS
HvVtRootCopyByPid(
    _In_ ULONG TargetPid,
    _In_ UINT64 Gva,
    _Inout_updates_bytes_(Size) PVOID Buffer,
    _In_ SIZE_T Size,
    _In_ BOOLEAN IsWrite,
    _Out_opt_ PSIZE_T BytesDone);

// ============================================================
// GetPeb: referenced process snapshot helper
// ============================================================
//
// Module enumeration obtains the PEB while holding an EPROCESS reference.
// The subsequent PEB/Ldr reads still use the VT-root copy path.

NTSTATUS
HvVtRootGetPebByPid(
    _In_ ULONG TargetPid,
    _Out_ PUINT64 OutPebVa);

// ============================================================
// HvVtRootGetResolvedUserCr3 - validated VT-root resolver
// ============================================================
//
// Builds the same lifetime-bound snapshot as HvVtRootCopyByPid and asks root
// mode to validate the MDL-locked PEB/image PFNs through each candidate CR3.
// The cache key includes process create time, so PID reuse cannot inherit a
// stale CR3, while debugger edits to PEB or image-header bytes remain valid.
NTSTATUS
HvVtRootGetResolvedUserCr3(
    _In_ ULONG TargetPid,
    _Out_ PUINT64 OutCr3);

// ============================================================
// Root-mode user CR3 解析 + GVA→HPA walker (PASSIVE 入口)
// ============================================================
//
// Both APIs capture process metadata at PASSIVE_LEVEL, then synchronously
// validate candidates and walk the target page tables in root mode.
NTSTATUS
HvVtRootResolveUserCr3(
    _In_ ULONG TargetPid,
    _Out_ PUINT64 OutCr3);

NTSTATUS
HvVtRootAdoptObservedUserCr3(
    _In_ ULONG TargetPid,
    _In_ UINT64 CandidateCr3);

NTSTATUS
HvVtRootWalkGvaToHpa(
    _In_ ULONG TargetPid,
    _In_ UINT64 Gva,
    _Out_ PUINT64 OutHpa,
    _Out_opt_ PUINT64 OutPageSize);

NTSTATUS
HvVtRootRootWalkGvaToHpaWithCr3(
    _Inout_ PVCPU_DATA Vcpu,
    _In_ UINT64 TargetCr3,
    _In_ UINT64 Gva,
    _Out_ PUINT64 OutHpa,
    _Out_ PUINT64 OutPageSize);

// Trusted-CR3 root primitive used by the compatibility leaf-PTE API. LeafInfo
// must be a resident kernel buffer initialized with Magic/Version/Size. The
// caller owns CR3/address-space lifetime; PID request paths must use modes 5-8.
NTSTATUS
HvVtRootRootQueryLeafPteWithCr3(
    _Inout_ PVCPU_DATA Vcpu,
    _In_ UINT64 TargetCr3,
    _In_ UINT64 Gva,
    _Inout_ PHV_VTROOT_LEAF_PTE_INFO LeafInfo);

#endif // _HV_VT_ROOT_H_
