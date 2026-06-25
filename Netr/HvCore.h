/*
 * HvCore.h - Hypervisor 核心功能函数声明
 * 
 * 支持 Intel VMX 和 AMD SVM
 */

#ifndef _HV_CORE_H_
#define _HV_CORE_H_

#include "HvTypes.h"
#include "HvUtils.h"
#include "HvCpu.h"
#include "HvEpt.h"
#include "HvVmcs.h"
#include "HvVmExit.h"
#include "HvVmcb.h"
#include "HvNpt.h"

// ==================== 统一接口 ====================

// 初始化和清理
NTSTATUS HvInitialize(VOID);
VOID HvCleanup(VOID);

// 每 CPU 回调
VOID HvStartOnProcessor(PVOID Context);

// Hypervisor 状态检查
BOOLEAN HvIsHypervisorRunning(VOID);
ULONG HvGetHypervisorVersion(VOID);

// 卸载请求
VOID HvRequestUnload(VOID);

// 调试统计
VOID HvPrintDebugStats(VOID);

// ==================== Intel VMX 接口 ====================

// VMLAUNCH
NTSTATUS HvLaunchVm(PVCPU_DATA VcpuData);

// ==================== AMD SVM 接口 ====================

// 在每个 CPU 上启动 SVM
VOID SvmStartOnProcessor(PVOID Context);

#endif // _HV_CORE_H_
