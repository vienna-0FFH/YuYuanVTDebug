/*
 * HvEpt.h - EPT 操作函数声明
 */

#ifndef _HV_EPT_H_
#define _HV_EPT_H_

#include "HvTypes.h"

// EPT 支持检查
BOOLEAN HvCheckEptSupport(VOID);

// EPT 初始化和清理
NTSTATUS HvSetupEpt(PVCPU_DATA VcpuData);
VOID HvCleanupEpt(PVCPU_DATA VcpuData);

// EPT 映射构建
NTSTATUS HvBuildEptIdentityMap(PVCPU_DATA VcpuData);

// 2026-06-16: 抽出的低层 identity builder, 接受 PEPT_TABLES, 不依赖 VCPU_DATA。
// HvCloak.c 用它建第二份 EPT 实例 (EptCloaked)。
NTSTATUS HvEptBuildIdentityInto(PEPT_TABLES EptTables);

#endif // _HV_EPT_H_
