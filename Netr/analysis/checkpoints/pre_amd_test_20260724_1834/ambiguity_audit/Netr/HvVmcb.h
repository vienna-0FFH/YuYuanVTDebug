/*
 * HvVmcb.h - AMD SVM VMCB 配置和管理
 */

#ifndef _HV_VMCB_H_
#define _HV_VMCB_H_

#include "HvTypes.h"
#include "HvUtils.h"

// ==================== SVM 初始化和启用 ====================

/*
 * 在当前CPU上启用SVM
 * 
 * 步骤：
 * 1. 设置 EFER.SVME
 * 2. 分配 Host Save Area
 * 3. 设置 MSR_VM_HSAVE_PA
 * 4. 分配并初始化 VMCB
 */
NTSTATUS SvmEnableOnCpu(PVCPU_DATA VcpuData);

/*
 * 配置 VMCB
 */
NTSTATUS SvmSetupVmcb(PVCPU_DATA VcpuData);

/*
 * 配置 VMCB 控制区
 */
NTSTATUS SvmSetupVmcbControlArea(PVCPU_DATA VcpuData);

/*
 * 配置 VMCB 状态保存区
 */
NTSTATUS SvmSetupVmcbStateSave(PVCPU_DATA VcpuData);

/*
 * 配置 MSR 权限位图
 */
NTSTATUS SvmSetupMsrPermissionMap(PVCPU_DATA VcpuData);

/*
 * 启动虚拟机 (VMRUN)
 */
NTSTATUS SvmLaunchVm(PVCPU_DATA VcpuData);

/*
 * 清理 SVM 资源
 */
VOID SvmCleanup(PVCPU_DATA VcpuData);

// ==================== VMCB 操作函数 ====================

/*
 * 设置 VMCB 拦截位
 */
VOID SvmSetInterceptCr(PVCPU_DATA VcpuData, ULONG CrNumber, BOOLEAN Read, BOOLEAN Write);
VOID SvmSetInterceptDr(PVCPU_DATA VcpuData, ULONG DrNumber, BOOLEAN Read, BOOLEAN Write);
VOID SvmSetInterceptException(PVCPU_DATA VcpuData, ULONG ExceptionVector);
VOID SvmSetInterceptMisc1(PVCPU_DATA VcpuData, ULONG64 Flags);
VOID SvmSetInterceptMisc2(PVCPU_DATA VcpuData, ULONG64 Flags);

/*
 * 事件注入
 */
VOID SvmInjectEvent(PVCPU_DATA VcpuData, UCHAR Vector, UCHAR Type, BOOLEAN HasErrorCode, ULONG ErrorCode);
VOID SvmInjectInterrupt(PVCPU_DATA VcpuData, UCHAR Vector);
VOID SvmInjectException(PVCPU_DATA VcpuData, UCHAR Vector, BOOLEAN HasErrorCode, ULONG ErrorCode);

/*
 * TLB 控制
 */
VOID SvmFlushTlb(PVCPU_DATA VcpuData, ULONG FlushType);

/*
 * AMD ASID 池接口 (HV_ENABLE_SVM_HARDENING)
 * 嵌套 SVM 路径 (HvNestedSvm.c) 通过它分配/释放 L2 ASID
 */
ULONG SvmPoolAllocateAsid(VOID);
VOID  SvmPoolReleaseAsid(ULONG Asid);

/*
 * vGIF pending queue flush (HV_ENABLE_SVM_HARDENING)
 * STGI handler 在设 vGIF=TRUE 后调用此函数投递挂起中断
 */
VOID SvmFlushPendingEvents(PVCPU_DATA VcpuData);

#endif // _HV_VMCB_H_
