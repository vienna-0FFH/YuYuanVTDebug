/*
 * HvEpt.h - EPT 操作函数声明
 */

#ifndef _HV_EPT_H_
#define _HV_EPT_H_

#include "HvTypes.h"

// EPT 支持检查
BOOLEAN HvCheckEptSupport(VOID);

// Read the platform MTRRs once before any EPT is built.
NTSTATUS HvEptInitializeMemoryTypes(VOID);

// Resolve the effective cache type for a physical range. The uniform helper
// decides whether a 2 MB EPT leaf is legal or must be split.
UCHAR HvEptGetMemoryType(_In_ ULONG64 PhysicalAddress, _In_ SIZE_T Size);
BOOLEAN HvEptIsUniformMemoryType(
    _In_ ULONG64 PhysicalAddress,
    _In_ SIZE_T Size,
    _Out_ PUCHAR MemoryType
);

// Dynamic 4 KB EPT page-table bookkeeping. Register a PT before publishing
// its PDE so cleanup and VM-exit lookups always see the same set.
BOOLEAN HvEptCanRegisterSplitPt(_In_ PEPT_TABLES EptTables);
NTSTATUS HvEptRegisterSplitPt(
    _Inout_ PEPT_TABLES EptTables,
    _In_ PEPT_PTE SplitPt,
    _In_ PHYSICAL_ADDRESS SplitPtPhysical,
    _In_ BOOLEAN Owned
);
PEPT_PTE HvEptAllocateSplitPt(
    _Inout_ PEPT_TABLES EptTables,
    _Out_ PPHYSICAL_ADDRESS SplitPtPhysical
);
PEPT_PTE HvEptFindSplitPt(
    _In_ PEPT_TABLES EptTables,
    _In_ ULONG64 SplitPtPfn
);
VOID HvEptFreeTables(_In_opt_ PEPT_TABLES EptTables);

// EPT 初始化和清理
NTSTATUS HvSetupEpt(PVCPU_DATA VcpuData);
VOID HvCleanupEpt(PVCPU_DATA VcpuData);

// EPT 映射构建
NTSTATUS HvBuildEptIdentityMap(PVCPU_DATA VcpuData);

// 2026-06-16: 抽出的低层 identity builder, 接受 PEPT_TABLES, 不依赖 VCPU_DATA。
// HvCloak.c 用它建第二份 EPT 实例 (EptCloaked)。
NTSTATUS HvEptBuildIdentityInto(PEPT_TABLES EptTables);

#endif // _HV_EPT_H_
