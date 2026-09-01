/*
 * HvNestedSvm.h - AMD SVM 嵌套虚拟化完整实现
 * 
 * 实现完整的 AMD SVM 嵌套虚拟化支持，包括：
 * - VMRUN 指令处理（启动 L2）
 * - VMLOAD/VMSAVE 指令处理
 * - STGI/CLGI 指令处理（虚拟 GIF）
 * - VMCB 合并逻辑
 * - L2 #VMEXIT 分发和处理
 * - 嵌套 NPT 支持
 * 
 * 三层虚拟化模型：
 *   L0 - 我们的 Hypervisor（真正的 Host）
 *   L1 - Guest Hypervisor（在 L0 中运行）
 *   L2 - Nested Guest（L1 创建的虚拟机）
 */

#ifndef _HV_NESTED_SVM_H_
#define _HV_NESTED_SVM_H_

#include "HvTypes.h"

// ==================== SVM 嵌套配置 ====================

// 虚拟 GIF（Global Interrupt Flag）
#define NESTED_SVM_VGIF_ENABLED         TRUE

// 是否支持虚拟 VMLOAD/VMSAVE
#define NESTED_SVM_VVMLOAD_VMSAVE       TRUE

// ==================== VMCB 字段常量 ====================

// VMCB 控制区偏移
#define VMCB_INTERCEPT_CR_READ          0x000
#define VMCB_INTERCEPT_CR_WRITE         0x002
#define VMCB_INTERCEPT_DR_READ          0x004
#define VMCB_INTERCEPT_DR_WRITE         0x006
#define VMCB_INTERCEPT_EXCEPTIONS       0x008
#define VMCB_INTERCEPT_MISC1            0x00C
#define VMCB_INTERCEPT_MISC2            0x014
#define VMCB_PAUSE_FILTER_THRESHOLD     0x03C
#define VMCB_PAUSE_FILTER_COUNT         0x03E
#define VMCB_IOPM_BASE_PA               0x040
#define VMCB_MSRPM_BASE_PA              0x048
#define VMCB_TSC_OFFSET                 0x050
#define VMCB_GUEST_ASID                 0x058
#define VMCB_TLB_CONTROL                0x05C
#define VMCB_V_INTR                     0x060
#define VMCB_INTERRUPT_SHADOW           0x068
#define VMCB_EXIT_CODE                  0x070
#define VMCB_EXIT_INFO1                 0x078
#define VMCB_EXIT_INFO2                 0x080
#define VMCB_EXIT_INT_INFO              0x088
#define VMCB_NP_ENABLE                  0x090
#define VMCB_AVIC_APIC_BAR              0x098
#define VMCB_GHCB_PA                    0x0A0
#define VMCB_EVENT_INJ                  0x0A8
#define VMCB_N_CR3                      0x0B0
#define VMCB_LBR_VIRTUALIZATION_ENABLE  0x0B8
#define VMCB_VMCB_CLEAN_BITS            0x0C0
#define VMCB_NRIP                       0x0C8
#define VMCB_NUM_BYTES_FETCHED          0x0D0
#define VMCB_GUEST_INSTRUCTION_BYTES    0x0D1

// VMCB 状态保存区偏移（相对于 0x400）
#define VMCB_SAVE_ES                    0x000
#define VMCB_SAVE_CS                    0x010
#define VMCB_SAVE_SS                    0x020
#define VMCB_SAVE_DS                    0x030
#define VMCB_SAVE_FS                    0x040
#define VMCB_SAVE_GS                    0x050
#define VMCB_SAVE_GDTR                  0x060
#define VMCB_SAVE_LDTR                  0x070
#define VMCB_SAVE_IDTR                  0x080
#define VMCB_SAVE_TR                    0x090
#define VMCB_SAVE_CPL                   0x0CB
#define VMCB_SAVE_EFER                  0x0D0
#define VMCB_SAVE_CR4                   0x148
#define VMCB_SAVE_CR3                   0x150
#define VMCB_SAVE_CR0                   0x158
#define VMCB_SAVE_DR7                   0x160
#define VMCB_SAVE_DR6                   0x168
#define VMCB_SAVE_RFLAGS                0x170
#define VMCB_SAVE_RIP                   0x178
#define VMCB_SAVE_RSP                   0x1D8
#define VMCB_SAVE_RAX                   0x1F8
#define VMCB_SAVE_STAR                  0x200
#define VMCB_SAVE_LSTAR                 0x208
#define VMCB_SAVE_CSTAR                 0x210
#define VMCB_SAVE_SFMASK                0x218
#define VMCB_SAVE_KERNEL_GS_BASE        0x220
#define VMCB_SAVE_SYSENTER_CS           0x228
#define VMCB_SAVE_SYSENTER_ESP          0x230
#define VMCB_SAVE_SYSENTER_EIP          0x238
#define VMCB_SAVE_CR2                   0x240
#define VMCB_SAVE_G_PAT                 0x268
#define VMCB_SAVE_DBGCTL                0x270

// ==================== 嵌套 SVM 数据结构 ====================

// L1 VMCB 缓存（VMCB12）
typedef struct _NESTED_VMCB_CACHE {
    // 控制区字段
    USHORT InterceptCrRead;
    USHORT InterceptCrWrite;
    USHORT InterceptDrRead;
    USHORT InterceptDrWrite;
    ULONG InterceptExceptions;
    ULONG64 InterceptMisc1;
    ULONG64 InterceptMisc2;
    ULONG64 IopmBasePa;
    ULONG64 MsrpmBasePa;
    ULONG64 TscOffset;
    ULONG GuestAsid;
    ULONG TlbControl;
    ULONG64 VIntr;
    ULONG64 InterruptShadow;
    ULONG64 NpEnable;
    ULONG64 NCr3;
    ULONG64 EventInj;
    
    // Guest 状态字段
    ULONG64 GuestCr0;
    ULONG64 GuestCr2;
    ULONG64 GuestCr3;
    ULONG64 GuestCr4;
    ULONG64 GuestDr6;
    ULONG64 GuestDr7;
    ULONG64 GuestRip;
    ULONG64 GuestRsp;
    ULONG64 GuestRax;
    ULONG64 GuestRflags;
    ULONG64 GuestEfer;
    
    // 段寄存器
    SVM_SEGMENT_REGISTER Es;
    SVM_SEGMENT_REGISTER Cs;
    SVM_SEGMENT_REGISTER Ss;
    SVM_SEGMENT_REGISTER Ds;
    SVM_SEGMENT_REGISTER Fs;
    SVM_SEGMENT_REGISTER Gs;
    SVM_SEGMENT_REGISTER Gdtr;
    SVM_SEGMENT_REGISTER Ldtr;
    SVM_SEGMENT_REGISTER Idtr;
    SVM_SEGMENT_REGISTER Tr;
    
    // SYSENTER/SYSCALL
    ULONG64 Star;
    ULONG64 LStar;
    ULONG64 CStar;
    ULONG64 SfMask;
    ULONG64 KernelGsBase;
    ULONG64 SysenterCs;
    ULONG64 SysenterEsp;
    ULONG64 SysenterEip;
    
    // 其他
    ULONG64 GPat;
    ULONG64 DbgCtl;
    UCHAR Cpl;
    
    // Host 状态（用于 #VMEXIT）
    ULONG64 HostRip;
    ULONG64 HostRsp;
    ULONG64 HostRax;
    
    // 缓存有效性
    BOOLEAN Valid;
} NESTED_VMCB_CACHE, *PNESTED_VMCB_CACHE;

// 合并后的 VMCB 控制字段
typedef struct _NESTED_VMCB_MERGED_CONTROLS {
    USHORT InterceptCrRead;
    USHORT InterceptCrWrite;
    USHORT InterceptDrRead;
    USHORT InterceptDrWrite;
    ULONG InterceptExceptions;
    ULONG64 InterceptMisc1;
    ULONG64 InterceptMisc2;
    ULONG64 TscOffset;
    ULONG64 VIntr;
    BOOLEAN NpEnabled;
    
    // ASID
    ULONG GuestAsid;
    
    // IOPM/MSRPM（合并后的物理地址）
    ULONG64 IopmBasePa;
    ULONG64 MsrpmBasePa;
    BOOLEAN UseL1Iopm;
    BOOLEAN UseL1Msrpm;
} NESTED_VMCB_MERGED_CONTROLS, *PNESTED_VMCB_MERGED_CONTROLS;

// ==================== 函数声明 ====================

// 初始化和清理
NTSTATUS NestedSvmInitialize(VOID);
VOID NestedSvmCleanup(VOID);

// 嵌套状态初始化
NTSTATUS NestedSvmInitializeState(PVCPU_DATA VcpuData);
VOID NestedSvmCleanupState(PVCPU_DATA VcpuData);

// VMRUN 处理
BOOLEAN NestedSvmHandleVmrun(
    PVCPU_DATA VcpuData,
    PGUEST_CONTEXT GuestContext
);

// VMLOAD 处理
BOOLEAN NestedSvmHandleVmload(
    PVCPU_DATA VcpuData,
    PGUEST_CONTEXT GuestContext
);

// VMSAVE 处理
BOOLEAN NestedSvmHandleVmsave(
    PVCPU_DATA VcpuData,
    PGUEST_CONTEXT GuestContext
);

// STGI 处理
BOOLEAN NestedSvmHandleStgi(
    PVCPU_DATA VcpuData,
    PGUEST_CONTEXT GuestContext
);

// CLGI 处理
BOOLEAN NestedSvmHandleClgi(
    PVCPU_DATA VcpuData,
    PGUEST_CONTEXT GuestContext
);

// VMCB 操作
BOOLEAN NestedSvmReadVmcb12(
    PVCPU_DATA VcpuData,
    ULONG64 VmcbGpa,
    PNESTED_VMCB_CACHE Cache
);

BOOLEAN NestedSvmWriteVmcb12(
    PVCPU_DATA VcpuData,
    ULONG64 VmcbGpa,
    PNESTED_VMCB_CACHE Cache
);

// VMCB 合并
VOID NestedSvmMergeVmcbControls(
    PVCPU_DATA VcpuData,
    PNESTED_VMCB_CACHE Vmcb12,
    PNESTED_VMCB_MERGED_CONTROLS Merged
);

// 进入 L2
NTSTATUS NestedSvmEnterL2(
    PVCPU_DATA VcpuData,
    PNESTED_VMCB_CACHE Vmcb12
);

// 从 L2 退出到 L1
VOID NestedSvmExitToL1(
    PVCPU_DATA VcpuData,
    ULONG64 ExitCode,
    ULONG64 ExitInfo1,
    ULONG64 ExitInfo2
);

// L2 #VMEXIT 分发
BOOLEAN NestedSvmDispatchL2Exit(
    PVCPU_DATA VcpuData,
    ULONG64 ExitCode,
    ULONG64 ExitInfo1,
    ULONG64 ExitInfo2,
    PGUEST_CONTEXT GuestContext
);

// 判断 L2 Exit 是否应该由 L0 处理
BOOLEAN NestedSvmShouldL0HandleExit(
    PVCPU_DATA VcpuData,
    ULONG64 ExitCode,
    ULONG64 ExitInfo1,
    ULONG64 ExitInfo2
);

// 保存/恢复 L1 状态
VOID NestedSvmSaveL1State(PVCPU_DATA VcpuData);
VOID NestedSvmRestoreL1State(PVCPU_DATA VcpuData);

// 同步 L2 状态到 VMCB12
VOID NestedSvmSyncVmcb12(
    PVCPU_DATA VcpuData,
    ULONG64 ExitCode,
    ULONG64 ExitInfo1,
    ULONG64 ExitInfo2
);

// 虚拟 GIF 操作
BOOLEAN NestedSvmGetVirtualGif(PVCPU_DATA VcpuData);
VOID NestedSvmSetVirtualGif(PVCPU_DATA VcpuData, BOOLEAN Value);

// 事件注入
BOOLEAN NestedSvmInjectEvent(
    PVCPU_DATA VcpuData,
    ULONG Vector,
    ULONG Type,
    BOOLEAN HasErrorCode,
    ULONG ErrorCode
);

// 先决条件检查
BOOLEAN NestedSvmCheckVmrunPreconditions(
    PVCPU_DATA VcpuData,
    ULONG64 VmcbGpa
);

// 辅助函数
VOID NestedSvmAdvanceRip(PVCPU_DATA VcpuData);
ULONG64 NestedSvmGetVmcbGpaFromRax(PVCPU_DATA VcpuData, PGUEST_CONTEXT GuestContext);

// 调试和统计
VOID NestedSvmPrintStatus(PVCPU_DATA VcpuData);
VOID NestedSvmPrintStats(VOID);

// 全局统计
extern volatile LONG64 g_NestedSvmVmrunCount;
extern volatile LONG64 g_NestedSvmVmExitCount;
extern volatile LONG64 g_NestedSvmL2ExitCount;

#endif // _HV_NESTED_SVM_H_
