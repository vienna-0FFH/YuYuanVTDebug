/*
 * HvNested.h - 嵌套虚拟化支持
 * 
 * 实现 Intel VMX 嵌套虚拟化，允许 L1 Hypervisor（如 VMware、VirtualBox）
 * 在我们的 L0 Hypervisor 之上正常运行
 * 
 * 三层虚拟化模型：
 *   L0 - 我们的 Hypervisor（真正的 VMX root）
 *   L1 - Guest Hypervisor（在 L0 中运行的虚拟化软件）
 *   L2 - Nested Guest（L1 创建的虚拟机）
 */

#ifndef _HV_NESTED_H_
#define _HV_NESTED_H_

#include "HvTypes.h"

// ==================== 嵌套虚拟化全局配置 ====================

// 外部声明
extern BOOLEAN g_EnableNestedVirtualization;

// 启用/禁用嵌套虚拟化
VOID HvNestedSetEnabled(BOOLEAN Enable);
BOOLEAN HvNestedIsEnabled(VOID);

// ==================== VCPU 辅助函数 ====================

// 获取当前 CPU 的 VCPU_DATA
PVCPU_DATA HvNestedGetCurrentVcpu(VOID);

// 检查是否在 L2 中运行
BOOLEAN HvNestedIsInL2(PVCPU_DATA VcpuData);

// ==================== VMX 指令处理器 ====================

// VMXON - L1 启动 VMX 操作
// 返回：TRUE 成功，FALSE 失败（已设置 RFLAGS）
BOOLEAN HvNestedHandleVmxon(PVCPU_DATA VcpuData, PGUEST_CONTEXT GuestContext);

// VMXOFF - L1 关闭 VMX 操作
BOOLEAN HvNestedHandleVmxoff(PVCPU_DATA VcpuData, PGUEST_CONTEXT GuestContext);

// VMCLEAR - L1 清除 VMCS
BOOLEAN HvNestedHandleVmclear(PVCPU_DATA VcpuData, PGUEST_CONTEXT GuestContext);

// VMPTRLD - L1 加载 VMCS 指针
BOOLEAN HvNestedHandleVmptrld(PVCPU_DATA VcpuData, PGUEST_CONTEXT GuestContext);

// VMPTRST - L1 存储 VMCS 指针
BOOLEAN HvNestedHandleVmptrst(PVCPU_DATA VcpuData, PGUEST_CONTEXT GuestContext);

// VMREAD - L1 读取 VMCS 字段
BOOLEAN HvNestedHandleVmread(PVCPU_DATA VcpuData, PGUEST_CONTEXT GuestContext);

// VMWRITE - L1 写入 VMCS 字段
BOOLEAN HvNestedHandleVmwrite(PVCPU_DATA VcpuData, PGUEST_CONTEXT GuestContext);

// VMLAUNCH - L1 启动 L2
BOOLEAN HvNestedHandleVmlaunch(PVCPU_DATA VcpuData, PGUEST_CONTEXT GuestContext);

// VMRESUME - L1 恢复 L2
BOOLEAN HvNestedHandleVmresume(PVCPU_DATA VcpuData, PGUEST_CONTEXT GuestContext);

// INVEPT - L1 使 EPT TLB 无效
BOOLEAN HvNestedHandleInvept(PVCPU_DATA VcpuData, PGUEST_CONTEXT GuestContext);

// INVVPID - L1 使 VPID TLB 无效
BOOLEAN HvNestedHandleInvvpid(PVCPU_DATA VcpuData, PGUEST_CONTEXT GuestContext);

// ==================== VMCS 操作 ====================

// VMCS 字段编码到索引的转换
VMCS12_FIELD_INDEX HvNestedVmcsFieldToIndex(ULONG VmcsField);

// 从索引获取 VMCS 字段编码
ULONG HvNestedIndexToVmcsField(VMCS12_FIELD_INDEX Index);

// 读取 VMCS12 字段
ULONG64 HvNestedVmcs12Read(PVCPU_DATA VcpuData, VMCS12_FIELD_INDEX Index);

// 写入 VMCS12 字段
VOID HvNestedVmcs12Write(PVCPU_DATA VcpuData, VMCS12_FIELD_INDEX Index, ULONG64 Value);

// 验证 VMCS12 配置是否有效
BOOLEAN HvNestedValidateVmcs12(PVCPU_DATA VcpuData);

// ==================== VMCS 合并 ====================

// 准备 VMCS02（合并 VMCS01 和 VMCS12）
NTSTATUS HvNestedPrepareVmcs02(PVCPU_DATA VcpuData);

// 从 L2 退出后同步 VMCS12
VOID HvNestedSyncVmcs12FromVmcs02(PVCPU_DATA VcpuData, SIZE_T ExitReason);

// 保存 L1 状态（进入 L2 前）
VOID HvNestedSaveL1State(PVCPU_DATA VcpuData);

// 恢复 L1 状态（从 L2 退出后）
VOID HvNestedRestoreL1State(PVCPU_DATA VcpuData);

// ==================== L2 VM Exit 处理 ====================

// 判断 L2 VM Exit 是否应由 L0 处理
// 返回 TRUE 表示 L0 处理，FALSE 表示注入到 L1
BOOLEAN HvNestedShouldL0HandleExit(PVCPU_DATA VcpuData, SIZE_T ExitReason, SIZE_T Qualification);

// 处理 L2 的 VM Exit（L0 处理的情况）
BOOLEAN HvNestedHandleL2Exit(PVCPU_DATA VcpuData, SIZE_T ExitReason, PGUEST_CONTEXT GuestContext);

// 将 VM Exit 注入到 L1（让 L1 处理 L2 的退出）
BOOLEAN HvNestedInjectVmExitToL1(PVCPU_DATA VcpuData, SIZE_T ExitReason, PGUEST_CONTEXT GuestContext);

// 从 L2 返回 L1（执行嵌套 VM Exit）
VOID HvNestedVmExitFromL2ToL1(PVCPU_DATA VcpuData, SIZE_T ExitReason, SIZE_T Qualification);

// ==================== 嵌套 EPT 支持 ====================

// 设置嵌套 EPT（合并 L0 和 L1 的 EPT）
NTSTATUS HvNestedSetupEpt(PVCPU_DATA VcpuData, ULONG64 L1Eptp);

// 清理嵌套 EPT
VOID HvNestedCleanupEpt(PVCPU_DATA VcpuData);

// 使嵌套 EPT TLB 无效
VOID HvNestedInvalidateEptTlb(PVCPU_DATA VcpuData);

// 翻译 L1 GPA 到 HPA（通过 L0 EPT）
BOOLEAN HvNestedTranslateL1GpaToHpa(PVCPU_DATA VcpuData, ULONG64 L1Gpa, PULONG64 Hpa);

// 翻译 L2 GPA 到 HPA（通过嵌套 EPT）
BOOLEAN HvNestedTranslateL2GpaToHpa(PVCPU_DATA VcpuData, ULONG64 L2Gpa, PULONG64 Hpa);

// ==================== VMX 失败处理 ====================

// 设置 VMX 成功标志（清除 CF 和 ZF）
VOID HvNestedSetVmxSuccess(PGUEST_CONTEXT GuestContext);

// 设置 VMX 无效失败（CF=1，没有错误码）
VOID HvNestedSetVmxFailInvalid(PGUEST_CONTEXT GuestContext);

// 设置 VMX 有效失败（ZF=1，有错误码）
VOID HvNestedSetVmxFailValid(PVCPU_DATA VcpuData, PGUEST_CONTEXT GuestContext, ULONG ErrorNumber);

// ==================== 内存操作数解析 ====================

// 解析 VMX 指令的内存操作数
// 返回操作数的 GPA（Guest Physical Address）
ULONG64 HvNestedGetMemoryOperand(PVCPU_DATA VcpuData, PGUEST_CONTEXT GuestContext);

// 从 L1 地址空间读取数据
BOOLEAN HvNestedReadL1Memory(PVCPU_DATA VcpuData, ULONG64 L1Gva, PVOID Buffer, SIZE_T Size);

// 向 L1 地址空间写入数据
BOOLEAN HvNestedWriteL1Memory(PVCPU_DATA VcpuData, ULONG64 L1Gva, PVOID Buffer, SIZE_T Size);

// ==================== 先决条件检查 ====================

// 检查 VMXON 先决条件
BOOLEAN HvNestedCheckVmxonPreconditions(PVCPU_DATA VcpuData, PGUEST_CONTEXT GuestContext);

// 检查 VMX 指令的通用先决条件（VMXON 已执行，CPL=0 等）
BOOLEAN HvNestedCheckVmxPreconditions(PVCPU_DATA VcpuData, PGUEST_CONTEXT GuestContext);

// 检查 VMCS 是否已加载
BOOLEAN HvNestedCheckVmcsLoaded(PVCPU_DATA VcpuData);

// ==================== MSR 虚拟化 ====================

// 获取虚拟化的 VMX MSR 值（给 L1 看的）
ULONG64 HvNestedGetVirtualVmxMsr(ULONG MsrIndex);

// 检查 L1 是否可以使用某个 VMX 功能
BOOLEAN HvNestedCheckVmxCapability(ULONG64 CapabilityMsr, ULONG64 RequestedBit);

// ==================== CPUID 虚拟化 ====================

// 处理嵌套虚拟化场景下的 CPUID
// 返回 TRUE 表示已处理，FALSE 表示使用默认处理
BOOLEAN HvNestedHandleCpuid(PVCPU_DATA VcpuData, PGUEST_CONTEXT GuestContext);

// ==================== 调试和统计 ====================

// 打印嵌套虚拟化状态
VOID HvNestedPrintStatus(PVCPU_DATA VcpuData);

// 打印嵌套虚拟化统计信息
VOID HvNestedPrintStats(VOID);

// ==================== 初始化和清理 ====================

// 初始化嵌套虚拟化子系统
NTSTATUS HvNestedInitialize(VOID);

// 清理嵌套虚拟化子系统
VOID HvNestedCleanup(VOID);

#endif // _HV_NESTED_H_
