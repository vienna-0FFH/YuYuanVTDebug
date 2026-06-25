/*
 * HvXhciEptTrap.h — Item 2: EPT read trap on xHCI USBSTS/IMAN
 *
 * 问题:
 *   Layer 4 通过 VMENTRY_INTERRUPTION_INFO 给 guest 注入 MSI,但物理 xHCI
 *   控制器从未触发真中断,所以 USBSTS.EINT (bit 3) 和 IR[0].IMAN.IP (bit 0)
 *   都是 0。xhci.sys ISR 入口的 fast-path 检查这两位 — 0 就 fast-bail,
 *   不会处理 Event Ring,我们写进 Event Ring 的 Transfer Event TRB 永远
 *   不被消费,GUI 上 StatErdpStalled 一直涨。
 *
 * 解决:
 *   用 EPT 把 USBSTS 和 IMAN 所在的 4KB GPA 设为 R=0(读触发 VMEXIT),
 *   写位保留(让 ISR 写 1 清位的语义透传过去,反正硬件位本来就是 0,
 *   写 1 是 no-op)。
 *
 *   流程:
 *     1) HvCoreInitialize 在 vCPU 启动并 IsActive=TRUE 后调
 *        HvXhciEptTrapInitialize (HvUsbXhciIsReady 时),
 *        分裂包含 USBSTS_GPA 和 IMAN_GPA 的 2MB 大页到 4KB PT,
 *        记下对应 PT entry 指针,初始 R=1 (trap 未启用)。
 *        关键:必须在 IsActive=TRUE 之后,因为 HvXhciTrapEnsureSplitPt
 *        要遍历每个 VCPU 的 EptTables;此时调用方在 guest 模式,
 *        INVEPT 必须走 EptInveptAllContexts (IPI+VMCALL) 而非裸指令。
 *     2) HvUsbXhciTryDeliverMsi 成功调用 HvVmExitInjectInterrupt 后,
 *        调 HvXhciEptTrapArm() —— 设 g_PendingIsrReads = N,
 *        清 R bit,INVEPT。
 *     3) Guest 进入 ISR,读 USBSTS → EPT violation。
 *        HvHandleEptViolation 调 HvXhciEptTrapHandleViolation:
 *          - 快照全部 16 个 GPR
 *          - 恢复 R=1 (单步要能跑过去)
 *          - INVEPT
 *          - 置 CPU_BASED_MONITOR_TRAP_FLAG
 *          - 返回 TRUE
 *     4) Guest 重新执行 MOV reg, [MMIO] — 这次 EPT 让过,真值进 reg。
 *        MTF 在指令完成后触发 VMEXIT。
 *     5) HvXhciEptTrapHandleMtf:
 *          - 对比 GPR snapshot 找到改动的寄存器(就是 MOV 的目的寄存器)
 *          - 把 (XHCI_STS_EINT or XHCI_IMAN_IP) OR 进该寄存器值
 *          - 重清 R=0 (如果 PendingIsrReads 还 > 0,继续 trap)
 *          - 清 CPU_BASED_MONITOR_TRAP_FLAG
 *          - INVEPT
 *          - 返回 TRUE
 *
 * PG 安全:
 *   - 不动任何代码页 / 静态内核结构
 *   - EPT 是 VMCS 管的,PG 看不到
 *   - 仅在 inject 后短时窗口里 trap (counter 限制),平时透明
 *
 * 多核:
 *   - PT 单页全 CPU 共享 (同 EptHook 的 EptGetOrCreatePteForHook 模式)
 *   - 改一处 R bit 对所有 CPU 立即生效 (INVEPT all-contexts)
 *   - 每 CPU 自己的 GPR snapshot + active flag
 */

#ifndef _HV_XHCI_EPT_TRAP_H_
#define _HV_XHCI_EPT_TRAP_H_

#pragma once

#include <ntddk.h>
#include "HvTypes.h"

// 启动期:分裂 USBSTS_GPA / IMAN_GPA 所在 2MB PDE,记下 PT entry 指针。
// 调用约束:
//   - PASSIVE_LEVEL
//   - g_HypervisorContext.IsActive == TRUE (vCPU 已启动)
//   - HvUsbXhciIsReady() == TRUE (BAR/CapLength/RtBase 已填)
// 失败返回非 SUCCESS,Layer 4 仍能注入但 ISR 会 fast-bail。
NTSTATUS HvXhciEptTrapInitialize(VOID);

// 卸载:恢复 R=1,清 g_TrapState,放掉我们分配的 PT (如有)。
VOID HvXhciEptTrapShutdown(VOID);

// 检查 trap 是否激活 (HvHandleEptViolation 用):
//   = Init 完 + 用户允许 + 有 trap 页。Arm/HandleViolation/HandleMtf 都靠这个。
BOOLEAN HvXhciEptTrapIsArmed(VOID);

// 仅检查 Init 是否完成 (不看 user enable)。诊断/IOCTL 用。
BOOLEAN HvXhciEptTrapIsInitialized(VOID);

// 用户层 enable 标志位。默认 OFF。
BOOLEAN HvXhciEptTrapIsUserEnabled(VOID);

// CPU 是否支持 MTF (Init 时检测,影响 SetUserEnabled(TRUE) 是否允许)
BOOLEAN HvXhciEptTrapIsMtfSupported(VOID);

// 用户层切换 trap on/off。PASSIVE_LEVEL,IOCTL 路径调用。
// enable=TRUE  : Init 完成且 MTF 支持才允许;翻转标志位,下次 MSI 注入会 Arm
// enable=FALSE : 翻转标志位,立即恢复所有 trap 页 R=1 + 跨模式 INVEPT
NTSTATUS HvXhciEptTrapSetUserEnabled(_In_ BOOLEAN enable);

// 在 HvVmExitInjectInterrupt 成功后调用,激活短时 trap 窗口。
// VMX root 模式,IPI_LEVEL 安全。
VOID HvXhciEptTrapArm(VOID);

// 在 HvHandleEptViolation 里调用 (EptHookHandleViolation 之后, fallback 之前)。
// 返回 TRUE: 已处理,handler 立即返回
// 返回 FALSE: 不是我们的 trap 页,让 fallback 处理
BOOLEAN HvXhciEptTrapHandleViolation(ULONG64 gpa, ULONG64 qualification, PGUEST_CONTEXT ctx);

// 在 EXIT_REASON_MONITOR_TRAP_FLAG 里调用 (EptHookHandleMtfExit 之前)。
// 返回 TRUE: 是我们的 MTF,已处理,跳过 EptHook 的 MTF 处理
// 返回 FALSE: 不是我们的,EptHook 处理
BOOLEAN HvXhciEptTrapHandleMtf(PGUEST_CONTEXT ctx);

// 诊断 (可选,以后可放进 HV_USB_XHCI_STATUS)
typedef struct _HV_XHCI_EPT_TRAP_STATS {
    ULONG ArmCount;                // 调 Arm 次数 (= 注入 MSI 成功次数)
    ULONG UsbstsReadFaked;         // USBSTS 读被 OR 进 EINT 的次数
    ULONG ImanReadFaked;           // IMAN 读被 OR 进 IP 的次数
    ULONG OtherReadOnTrapPage;     // 同页其他地址读 (passthrough, 计数仅诊断)
    ULONG MtfMisses;               // GPR diff 没找到改动寄存器
} HV_XHCI_EPT_TRAP_STATS, *PHV_XHCI_EPT_TRAP_STATS;

VOID HvXhciEptTrapQueryStats(_Out_ PHV_XHCI_EPT_TRAP_STATS stats);

// 完整状态查询 (IOCTL_HV_XHCI_TRAP_GET_STATS 用)
typedef struct _HV_XHCI_EPT_TRAP_STATE {
    UCHAR  Initialized;            // Init 是否成功 (页都已分裂,PT 已建)
    UCHAR  UserEnabled;            // 用户开关
    UCHAR  MtfSupported;           // CPU 是否支持 MTF
    UCHAR  Padding;
    ULONG  TrapPageCount;          // 实际 trap 的 4KB 页数 (1 或 2)
    LONG   PendingIsrReads;        // 当前剩余 "假冒读" 配额
    HV_XHCI_EPT_TRAP_STATS Stats;
} HV_XHCI_EPT_TRAP_STATE, *PHV_XHCI_EPT_TRAP_STATE;

VOID HvXhciEptTrapQueryState(_Out_ PHV_XHCI_EPT_TRAP_STATE state);

#endif // _HV_XHCI_EPT_TRAP_H_
