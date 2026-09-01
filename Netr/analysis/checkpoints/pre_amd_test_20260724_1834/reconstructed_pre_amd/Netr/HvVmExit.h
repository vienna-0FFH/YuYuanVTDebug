/*
 * HvVmExit.h - VM Exit 处理函数声明
 * 
 * 支持 Intel VMX 和 AMD SVM
 */

#ifndef _HV_VMEXIT_H_
#define _HV_VMEXIT_H_

#include "HvTypes.h"

// ==================== Intel VMX Exit 处理 ====================

// VM Exit 主分发函数（由汇编调用）
BOOLEAN HvVmExitDispatch(PGUEST_CONTEXT GuestContext);

// 兼容旧接口
BOOLEAN HvVmExitHandlerC(PGUEST_CONTEXT GuestContext);

// VMX 终止回调
VOID HvVmxTerminatedCallback(VOID);

// ==================== AMD SVM #VMEXIT 处理 ====================

// SVM #VMEXIT 主分发函数（由汇编调用）
BOOLEAN SvmVmExitDispatch(PVCPU_DATA VcpuData, PGUEST_CONTEXT GuestContext);

// SVM 终止回调
VOID SvmTerminatedCallback(VOID);

// ==================== SVM Exit Handlers ====================

// CPUID 处理
VOID SvmHandleCpuid(PVMCB Vmcb, PGUEST_CONTEXT GuestContext);

// VMMCALL 处理
BOOLEAN SvmHandleVmmcall(
    PVCPU_DATA VcpuData,
    PVMCB Vmcb,
    PGUEST_CONTEXT GuestContext);

// MSR 处理
VOID SvmHandleMsr(
    PVCPU_DATA VcpuData,
    PVMCB Vmcb,
    PGUEST_CONTEXT GuestContext,
    ULONG64 ExitInfo1);

// CR 访问处理
VOID SvmHandleCrAccess(PVCPU_DATA VcpuData, PVMCB Vmcb, PGUEST_CONTEXT GuestContext, ULONG64 ExitCode, ULONG64 ExitInfo1);

// NPF (Nested Page Fault) 处理
// VcpuData - VCPU 数据结构
// ErrorCode - NPF 错误码 (ExitInfo1)
// FaultAddress - 触发 NPF 的物理地址 (ExitInfo2)
BOOLEAN SvmHandleNpf(PVCPU_DATA VcpuData, ULONG64 ErrorCode, ULONG64 FaultAddress);

// 中断/异常处理
// 返回 TRUE 如果已处理（不需要重注入），FALSE 需要重注入
BOOLEAN SvmHandleException(PVCPU_DATA VcpuData, ULONG64 ExitCode);

// XSETBV 处理
VOID SvmHandleXsetbv(PVMCB Vmcb, PGUEST_CONTEXT GuestContext);

// ==================== 全局变量声明 ====================

// SVM 调试变量（定义在 AsmSvm.asm）
extern ULONG64 g_SvmDebugFlag;
extern ULONG64 g_SvmExitCounter;
extern ULONG64 g_SvmLastExitCode;
extern ULONG64 g_SvmRestoreRsp;
extern ULONG64 g_SvmRestoreRip;

// SVM 退出计数（定义在本文件）
extern ULONG64 volatile g_SvmExitCountCpuid;
extern ULONG64 volatile g_SvmExitCountVmmcall;
extern ULONG64 volatile g_SvmExitCountMsr;
extern ULONG64 volatile g_SvmExitCountNpf;
extern ULONG64 volatile g_SvmExitCountOther;

// 打印 SVM 调试统计信息
VOID SvmPrintDebugStats(VOID);

// ==================== 反虚拟化检测 ====================

/*
 * 启用/禁用反虚拟化检测
 * 
 * 反检测功能包括：
 * - CPUID: 隐藏 VMX/SVM/Hypervisor Present 位
 * - MSR: 隐藏虚拟化相关 MSR
 * - RDTSC: 补偿 VM Exit 时间差
 * 
 * @param Enable  TRUE = 启用, FALSE = 禁用
 */
VOID HvSetAntiVmDetection(BOOLEAN Enable);

/*
 * 获取反虚拟化检测状态
 * 
 * @return TRUE = 已启用, FALSE = 已禁用
 */
BOOLEAN HvGetAntiVmDetection(VOID);

/*
 * 重置 TSC 偏移
 * 在某些情况下可能需要重置累积的时间补偿
 */
VOID HvResetTscOffset(VOID);

// ==================== 中断注入包装层 (供 HvInput.c 等模块使用) ====================
//
// 设计:内部 helper (HvInjectInterrupt / HvCanInjectInterrupt /
// PendingIntrEnqueue / HvEnableInterruptWindowExiting) 保持 static —
// dispatcher 私有。其他模块通过本节的 HvVmExit* 符号调用,
// 接口稳定不暴露 VMCS 字段编码。
//
// 必须在 VMX root (VMEXIT handler) 上下文调用。

// VM-entry 写 VMCS_CTRL_VMENTRY_INTERRUPTION_INFO
//   vector = IDT 向量号 (0x00-0xFF)
//   type   = 0 external interrupt / 2 NMI / 3 hw exception / 4 sw int / 6 sw exception
VOID HvVmExitInjectInterrupt(ULONG vector, ULONG type);

// 检查 RFLAGS.IF 和 GUEST_INTERRUPTIBILITY_STATE,判断现在能否注入
BOOLEAN HvVmExitCanInjectInterrupt(VOID);

// per-CPU pending 中断队列入队 (IF=0 时延迟注入)
// intrInfo 格式: vector | (type<<8) | (1<<31)
VOID HvVmExitEnqueuePendingIntr(ULONG cpuIndex, ULONG64 intrInfo);

// 在 CPU_BASED_VM_EXECUTION_CONTROLS 上 OR 上 INTERRUPT_WINDOW_EXITING bit
VOID HvVmExitEnableInterruptWindowExiting(VOID);

// ==================== HvVmExit 模块全局初始化 / 卸载 ====================
//
// P0-5: DriverEntry 早期调用 HvVmExitInitialize 注册 KeRegisterNmiCallback;
// DriverUnload 调用 HvVmExitCleanup 注销 (否则 BSOD)。
NTSTATUS HvVmExitInitialize(VOID);
VOID     HvVmExitCleanup(VOID);

// 诊断计数器
extern volatile ULONG64 g_HvVmExitNmiCallbackCount;

#endif // _HV_VMEXIT_H_
