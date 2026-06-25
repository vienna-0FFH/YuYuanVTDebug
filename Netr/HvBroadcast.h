/*
 * HvBroadcast.h — DPC-based per-CPU VMCALL broadcast (HyperDbg 范式, P2-5)
 *
 * 现有 EptInveptAllContexts 用 KeIpiGenericCall + IRQL/root 模式三路径派发,
 * 已通过 critical bugs #11 的"root 判定先于 IRQL"修复,但 IPI 同步等待性强
 * (所有核必须立刻响应),全核高负载时偶有压力。
 *
 * HyperDbg 用 KeGenericCallDpc + per-CPU VMCALL:
 *   - DPC 走调度器,不要求所有 CPU 立刻同步
 *   - 每核独立 VMCALL 进入自己 vCPU 的 root mode → 处理 → resume
 *   - 跨核物理隔离,根除 IPI-in-root-mode 死锁面
 *
 * 此 helper 提供并存的备用通道。不替换现有 EptInveptAllContexts。
 * 后续增量切换 (例如 EptHook unhook 路径) 可直接用此 API。
 *
 * 与 HyperDbg 参考:
 *   hyperdbg/hyperhv/code/broadcast/DpcRoutines.c
 *     DpcRoutineInvalidateEptOnAllCores / DpcRoutineRemoveHookAndInvalidate*
 */

#pragma once

#include <ntddk.h>

/*
 * 在所有 CPU 上执行 VMCALL 服务号 VmcallNum。
 *
 * 调用约束:
 *   - 必须 IRQL ≤ APC_LEVEL (KeGenericCallDpc 限制)
 *   - hypervisor 必须已激活 (g_HypervisorContext.IsActive)
 *   - 调用方不能在 VMX root mode (此 helper 调度 DPC,root mode 下不能调度)
 *
 * 返回:
 *   STATUS_SUCCESS         所有可用 CPU 都成功 VMCALL
 *   STATUS_INVALID_LEVEL   IRQL 太高
 *   STATUS_NOT_SUPPORTED   hypervisor 未激活
 *   STATUS_UNSUCCESSFUL    KeGenericCallDpc 调度失败
 */
NTSTATUS
HvBroadcastVmCallToAllCpus(
    _In_ ULONG VmcallNum
);
