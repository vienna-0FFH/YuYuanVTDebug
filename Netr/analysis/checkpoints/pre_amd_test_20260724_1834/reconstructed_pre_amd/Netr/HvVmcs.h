/*
 * HvVmcs.h - VMCS 配置和 VMX 操作函数声明
 */

#ifndef _HV_VMCS_H_
#define _HV_VMCS_H_

#include "HvTypes.h"
#include "HvUtils.h"
#include "HvEpt.h"

// VMX 启用
NTSTATUS HvEnableVmxOnCpu(PVOID Context);

// VMCS 配置
NTSTATUS HvSetupVmcs(PVCPU_DATA VcpuData);
NTSTATUS HvSetupVmcsControlFields(PVCPU_DATA VcpuData);
NTSTATUS HvSetupVmcsGuestState(PVCPU_DATA VcpuData);
NTSTATUS HvSetupVmcsHostState(PVCPU_DATA VcpuData);

#endif // _HV_VMCS_H_
