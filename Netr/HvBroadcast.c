/*
 * HvBroadcast.c — DPC-based per-CPU VMCALL broadcast (P2-5)
 *
 * 见 HvBroadcast.h 的注释。
 */

#include "HvBroadcast.h"
#include "HvTypes.h"
#include "HvCore.h"

// P122: 全 driver DbgPrint → GUI ring
#define HV_TRACE_THIS_CAT HV_TRACE_CAT_UTIL
#include "HvTrace.h"

// AsmVmCall 在 AsmVmx.asm 定义。
// 注:实际签名 = VOID (ULONG64),不返回 NTSTATUS,我们通过 SEH 捕获 #UD 判断失败。
extern VOID AsmVmCall(ULONG64 HypercallNumber);

// g_InVmxRootModePerCpu 在 EptHook.c 定义 (无公共 header,本地 extern)
extern volatile BOOLEAN g_InVmxRootModePerCpu[64];

// KeGenericCallDpc / KeSignalCallDpcSynchronize / KeSignalCallDpcDone
// 在 ntddk.h 中受 _KERNEL_MODE/_NTDDK_/NTDDI_VERSION 等 macro 控制可见性,
// 某些 WDK 配置下不直接暴露 — 与 Driver.c 中 RtlRandomEx 同样问题。
// 显式 forward declaration 绕过 (函数本身在 ntoskrnl.lib 中,链接器找得到)。
NTKERNELAPI
VOID
KeGenericCallDpc(
    _In_ PKDEFERRED_ROUTINE Routine,
    _In_opt_ PVOID Context
);

NTKERNELAPI
VOID
KeSignalCallDpcDone(
    _In_ PVOID SystemArgument1
);

NTKERNELAPI
LOGICAL
KeSignalCallDpcSynchronize(
    _In_ PVOID SystemArgument2
);

typedef struct _BROADCAST_CONTEXT {
    ULONG64 VmcallNum;
    volatile LONG SuccessCount;
    volatile LONG FailureCount;
} BROADCAST_CONTEXT, * PBROADCAST_CONTEXT;

/*
 * DPC routine: 每核执行 VMCALL,然后 KeSignalCallDpcSynchronize/Done 完成同步。
 *
 * 注意: KeGenericCallDpc 会在每个 CPU 上调度此 DPC,IRQL 升到 DISPATCH_LEVEL。
 * VMCALL 在 DISPATCH_LEVEL 安全执行(它进 root mode 后 IRQL 在 root 模式无意义)。
 *
 * 如果该 CPU 上 hypervisor 未激活,VMCALL 会触发 #UD —— 用 __try/__except 吞掉,
 * 计入 FailureCount。
 */
static VOID
HvBroadcastVmcallDpcRoutine(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
)
{
    PBROADCAST_CONTEXT ctx = (PBROADCAST_CONTEXT)DeferredContext;

    UNREFERENCED_PARAMETER(Dpc);

    if (ctx) {
        __try {
            AsmVmCall(ctx->VmcallNum);
            InterlockedIncrement(&ctx->SuccessCount);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            // VMCALL #UD — 该核 hypervisor 未激活,记入失败计数
            InterlockedIncrement(&ctx->FailureCount);
        }
    }

    // KeGenericCallDpc 同步原语 — 等所有 DPC 进入同步点,然后标记完成
    KeSignalCallDpcSynchronize(SystemArgument2);
    KeSignalCallDpcDone(SystemArgument1);
}

NTSTATUS
HvBroadcastVmCallToAllCpus(
    _In_ ULONG VmcallNum
)
{
    BROADCAST_CONTEXT ctx;

    // IRQL 检查 (KeGenericCallDpc 要求 ≤ APC_LEVEL)
    if (KeGetCurrentIrql() > APC_LEVEL) {
        return STATUS_INVALID_LEVEL;
    }

    // hypervisor 必须激活
    if (!g_HypervisorContext.IsActive) {
        return STATUS_NOT_SUPPORTED;
    }

    // 不能在 VMX root mode 内调用 (KeGenericCallDpc 不能在 root 模式调度)
    {
        ULONG cpuIndex = KeGetCurrentProcessorNumber();
        if (cpuIndex < 64 && g_InVmxRootModePerCpu[cpuIndex]) {
            return STATUS_INVALID_DEVICE_STATE;
        }
    }

    ctx.VmcallNum = (ULONG64)VmcallNum;
    ctx.SuccessCount = 0;
    ctx.FailureCount = 0;

    // KeGenericCallDpc 在所有逻辑 CPU 上调度 DPC,同步等待全部完成后返回
    KeGenericCallDpc(HvBroadcastVmcallDpcRoutine, &ctx);

    // 至少有一个 CPU 成功就算成功 (其他失败的核可能 hypervisor 未启动)
    if (ctx.SuccessCount > 0) {
        return STATUS_SUCCESS;
    }
    return STATUS_UNSUCCESSFUL;
}
