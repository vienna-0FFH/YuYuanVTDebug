/*
 * HvVmcs.c - VMCS 配置和 VMX 操作函数实现
 */

#include "HvVmcs.h"
#include "HvCompat.h"
#include "HvInput.h"

// P122: 全 driver DbgPrint → GUI ring
#define HV_TRACE_THIS_CAT HV_TRACE_CAT_VM
#include "HvTrace.h"

BOOLEAN g_EnableNestedVirtualization = FALSE;

// VMCS Shadowing 支持检测
static BOOLEAN g_VmcsShadowingSupported = FALSE;

/*
 * 内部 helper：在 Intel MSR Bitmap 上设置某 MSR 的拦截位
 * Intel MSR Bitmap 布局（4KB = 4 块 × 1KB）：
 *   Block 0  (0x000-0x3FF): 读，MSR 0x00000000 - 0x00001FFF
 *   Block 1  (0x400-0x7FF): 读，MSR 0xC0000000 - 0xC0001FFF
 *   Block 2  (0x800-0xBFF): 写，MSR 0x00000000 - 0x00001FFF
 *   Block 3  (0xC00-0xFFF): 写，MSR 0xC0000000 - 0xC0001FFF
 * 每 MSR 1 bit。落在覆盖范围外的 MSR (例如 AMD 的 0xC001xxxx)
 * 在 Intel 上硬件默认触发 VM Exit，无需设位。
 */
static VOID HvVmcsSetMsrBitmapBit(PUCHAR Bitmap, ULONG32 Msr, BOOLEAN Read, BOOLEAN Write)
{
    ULONG readBase, writeBase, offset, byteOffset;
    UCHAR bitMask;

    if (Msr <= 0x00001FFFu) {
        readBase  = 0x000;
        writeBase = 0x800;
        offset = Msr;
    } else if (Msr >= 0xC0000000u && Msr <= 0xC0001FFFu) {
        readBase  = 0x400;
        writeBase = 0xC00;
        offset = Msr - 0xC0000000u;
    } else {
        // 覆盖范围外，Intel 默认 VM Exit
        return;
    }

    byteOffset = offset / 8u;
    bitMask = (UCHAR)(1u << (offset % 8u));

    if (Read)  Bitmap[readBase  + byteOffset] |= bitMask;
    if (Write) Bitmap[writeBase + byteOffset] |= bitMask;
}

/*
 * 配置 Intel MSR Bitmap 拦截
 *
 * 拦截目的：反检测 — 隐藏 hypervisor 在以下 MSR 上的印迹：
 *   1) IA32_FEATURE_CONTROL（暴露 VMXON 状态）
 *   2) IA32_VMX_BASIC..VMX_VMFUNC（VMX capability MSRs，Guest 读到非零说明 VMX 可用）
 *
 * HvHandleMsrRead/Write (HvVmExit.c) 已完整处理这些 MSR 的伪造逻辑，
 * 此处仅打开拦截位让 VM Exit 真正触发。
 *
 * AMD MSR (0xC001xxxx) 落在 Intel MSR Bitmap 覆盖范围外，硬件默认 VM Exit，
 * 不在此处理（实际处理在 HvHandleMsrRead 0xC0010114/0117/011F 分支）。
 */
static VOID HvVmcsSetupMsrBitmapIntercepts(PUCHAR Bitmap)
{
    ULONG32 msr;

    // IA32_FEATURE_CONTROL — 反检测核心
    HvVmcsSetMsrBitmapBit(Bitmap, MSR_IA32_FEATURE_CONTROL, TRUE, TRUE);

    // Intel VMX MSRs (0x480 - 0x491) — 整个 VMX capability 窗口
    for (msr = 0x480u; msr <= 0x491u; msr++) {
        HvVmcsSetMsrBitmapBit(Bitmap, msr, TRUE, TRUE);
    }
}

/*
 * 检查处理器是否支持 VMCS Shadowing
 */
BOOLEAN HvCheckVmcsShadowingSupport(VOID)
{
    ULONG64 procBasedCtls2Msr;
    ULONG allowed1;
    
    __try {
        procBasedCtls2Msr = __readmsr(MSR_IA32_VMX_PROCBASED_CTLS2);
        allowed1 = (ULONG)(procBasedCtls2Msr >> 32);
        
        if (allowed1 & SECONDARY_EXEC_SHADOW_VMCS) {
            return TRUE;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
    }
    
    return FALSE;
}

/*
 * 初始化嵌套虚拟化状态
 */
static VOID HvInitializeNestedState(PVCPU_DATA vcpuData)
{
    PNESTED_VMX_STATE nested = &vcpuData->NestedVmx;
    
    RtlZeroMemory(nested, sizeof(NESTED_VMX_STATE));
    
    nested->VmxEnabled = FALSE;
    nested->VmxonRegionGpa = 0;
    nested->CurrentVmcsGpa = 0;
    nested->VmcsState = VMCS_STATE_CLEAR;
    nested->ShadowVmcs = NULL;
    nested->Vmcs12Valid = FALSE;
    nested->NestedEptTables = NULL;
    nested->L1Eptp = 0;
    nested->L1EptEnabled = FALSE;
    nested->L2VmExitCount = 0;
    nested->NestedVmEntryCount = 0;
    
    vcpuData->IsInL2 = FALSE;
    
    // 分配 Shadow VMCS（如果支持且启用嵌套虚拟化）
    if (g_EnableNestedVirtualization && g_VmcsShadowingSupported) {
        nested->ShadowVmcs = HvAllocateAlignedMemory(PAGE_SIZE, &nested->ShadowVmcsPhysical);
        if (nested->ShadowVmcs) {
            ULONG64 vmxBasicMsr = __readmsr(MSR_IA32_VMX_BASIC);
            ULONG revisionId = (ULONG)(vmxBasicMsr & 0xFFFFFFFF);
            // Shadow VMCS 需要设置 shadow 位
            *(PULONG)nested->ShadowVmcs = revisionId | (1UL << 31);
#if HV_DIAG_VMCS_SETUP
            DbgPrint("[HV-NESTED] Shadow VMCS allocated at PA=0x%llX\n",
                     nested->ShadowVmcsPhysical.QuadPart);
#endif
        }
    }
}

/*
 * 清理 VCPU 资源的辅助函数
 */
static VOID HvCleanupVcpuResources(PVCPU_DATA vcpuData)
{
    if (vcpuData->VmxonRegion) {
        MmFreeContiguousMemory(vcpuData->VmxonRegion);
        vcpuData->VmxonRegion = NULL;
    }
    if (vcpuData->VmcsRegion) {
        MmFreeContiguousMemory(vcpuData->VmcsRegion);
        vcpuData->VmcsRegion = NULL;
    }
    if (vcpuData->MsrBitmap) {
        MmFreeContiguousMemory(vcpuData->MsrBitmap);
        vcpuData->MsrBitmap = NULL;
    }
    if (vcpuData->VmExitStack) {
        ExFreePoolWithTag(vcpuData->VmExitStack, 'HVST');
        vcpuData->VmExitStack = NULL;
    }
    
    // 清理嵌套虚拟化资源
    if (vcpuData->NestedVmx.ShadowVmcs) {
        MmFreeContiguousMemory(vcpuData->NestedVmx.ShadowVmcs);
        vcpuData->NestedVmx.ShadowVmcs = NULL;
    }
    if (vcpuData->NestedVmx.NestedEptTables) {
        // EPT 清理由专用函数处理
        vcpuData->NestedVmx.NestedEptTables = NULL;
    }
}

/*
 * 为每个CPU启用VMX
 */
NTSTATUS HvEnableVmxOnCpu(PVOID Context)
{
    PVCPU_DATA vcpuData = (PVCPU_DATA)Context;
    ULONG64 vmxBasicMsr;
    ULONG revisionId;
    int result;

    vcpuData->IsVmxOn = FALSE;

    HvAdjustControlRegisters();

    // 检测 VMCS Shadowing 支持（只在第一个 CPU 上检测一次）
    if (vcpuData->ProcessorNumber == 0) {
        g_VmcsShadowingSupported = HvCheckVmcsShadowingSupport();
        DbgPrint("[HV-NESTED] VMCS Shadowing supported: %s\n", 
                 g_VmcsShadowingSupported ? "YES" : "NO");
        DbgPrint("[HV-NESTED] Nested Virtualization enabled: %s\n",
                 g_EnableNestedVirtualization ? "YES" : "NO");
    }

    // 分配内存
    vcpuData->VmxonRegion = HvAllocateAlignedMemory(PAGE_SIZE, &vcpuData->VmxonRegionPhysical);
    vcpuData->VmcsRegion = HvAllocateAlignedMemory(PAGE_SIZE, &vcpuData->VmcsRegionPhysical);
    vcpuData->MsrBitmap = HvAllocateAlignedMemory(PAGE_SIZE, &vcpuData->MsrBitmapPhysical);
    vcpuData->VmExitStack = HvAllocateNonPagedZeroed(0x10000, 'HVST');
    
    if (!vcpuData->VmxonRegion || !vcpuData->VmcsRegion || 
        !vcpuData->MsrBitmap || !vcpuData->VmExitStack) {
        HvCleanupVcpuResources(vcpuData);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    RtlZeroMemory(vcpuData->MsrBitmap, PAGE_SIZE);
#if !HV_MINIMAL_MODE
    HvVmcsSetupMsrBitmapIntercepts((PUCHAR)vcpuData->MsrBitmap);
#endif
    RtlZeroMemory(vcpuData->VmExitStack, 0x10000);

    // VPID 分配：1-based，0 保留；同一个 CPU 每次都用同一个 VPID 避免不必要 TLB 失效
    vcpuData->Vpid = (USHORT)(vcpuData->ProcessorNumber + 1);

    // 初始化嵌套虚拟化状态
    HvInitializeNestedState(vcpuData);

    // EPT 暂时禁用
    vcpuData->EptTables = NULL;

    // 设置版本ID
    vmxBasicMsr = __readmsr(MSR_IA32_VMX_BASIC);
    revisionId = (ULONG)(vmxBasicMsr & 0xFFFFFFFF);
    *(PULONG)vcpuData->VmxonRegion = revisionId;
    *(PULONG)vcpuData->VmcsRegion = revisionId;
    
    // 验证 CR4.VMXE
    if (!(__readcr4() & (1ULL << 13))) {
        return STATUS_UNSUCCESSFUL;
    }
    
    // 验证 CR0/CR4 符合 VMX 要求
    ULONG64 cr0 = __readcr0(), cr4 = __readcr4();
    ULONG64 cr0_fixed0 = __readmsr(MSR_IA32_VMX_CR0_FIXED0);
    ULONG64 cr0_fixed1 = __readmsr(MSR_IA32_VMX_CR0_FIXED1);
    ULONG64 cr4_fixed0 = __readmsr(MSR_IA32_VMX_CR4_FIXED0);
    ULONG64 cr4_fixed1 = __readmsr(MSR_IA32_VMX_CR4_FIXED1);
    
    if (((cr0 & cr0_fixed0) != cr0_fixed0) || ((cr0 & ~cr0_fixed1) != 0) ||
        ((cr4 & cr4_fixed0) != cr4_fixed0) || ((cr4 & ~cr4_fixed1) != 0)) {
        return STATUS_NOT_SUPPORTED;
    }
    
    // 清理残留 VMX 状态
    __try { __vmx_off(); } __except (EXCEPTION_EXECUTE_HANDLER) { }
    
    // VMXON
    result = __vmx_on(&vcpuData->VmxonRegionPhysical.QuadPart);
    if (result != VMX_OK) {
        return STATUS_UNSUCCESSFUL;
    }
    vcpuData->IsVmxOn = TRUE;

    // VMCLEAR + VMPTRLD
    result = __vmx_vmclear(&vcpuData->VmcsRegionPhysical.QuadPart);
    if (result != VMX_OK) {
        __vmx_off();
        vcpuData->IsVmxOn = FALSE;
        return STATUS_UNSUCCESSFUL;
    }

    result = __vmx_vmptrld(&vcpuData->VmcsRegionPhysical.QuadPart);
    if (result != VMX_OK) {
        __vmx_off();
        vcpuData->IsVmxOn = FALSE;
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}

/*
 * 设置VMCS控制字段
 */
NTSTATUS HvSetupVmcsControlFields(PVCPU_DATA VcpuData)
{
    ULONG pinBasedControls, cpuBasedControls, secondaryControls;
    ULONG vmexitControls, vmentryControls;
    EPTP eptp;
    ULONG64 vmxBasicMsr;
    BOOLEAN useTrueControls;
    ULONG64 pinBasedMsr;
    BOOLEAN extIntForced, nmiForced;

    vmxBasicMsr = __readmsr(MSR_IA32_VMX_BASIC);
    useTrueControls = (vmxBasicMsr >> 55) & 1;

    // Pin-Based Controls
    // 检查处理器是否强制要求外部中断退出
    pinBasedMsr = __readmsr(useTrueControls ? MSR_IA32_VMX_TRUE_PINBASED_CTLS : MSR_IA32_VMX_PINBASED_CTLS);
    
    // allowed0 (低32位) 中的位如果为1，则必须启用
    // allowed1 (高32位) 中的位如果为0，则必须禁用
    ULONG allowed0 = (ULONG)(pinBasedMsr & 0xFFFFFFFF);
    ULONG allowed1 = (ULONG)(pinBasedMsr >> 32);
    
    extIntForced = (allowed0 & PIN_BASED_EXTERNAL_INTERRUPT_EXITING) != 0;
    nmiForced = (allowed0 & PIN_BASED_NMI_EXITING) != 0;
    
    // 我们请求 0（不启用任何可选功能）
    pinBasedControls = 0;
    pinBasedControls = HvAdjustVmxControls(
        useTrueControls ? MSR_IA32_VMX_TRUE_PINBASED_CTLS : MSR_IA32_VMX_PINBASED_CTLS, 
        pinBasedControls);
    
    // 打印详细信息用于调试
#if HV_DIAG_VMCS_SETUP
    DbgPrint("[HV] Pin-based controls MSR: allowed0=0x%X, allowed1=0x%X\n", allowed0, allowed1);
    DbgPrint("[HV] Pin-based controls = 0x%X (ExtInt forced=%d, NMI forced=%d)\n",
        pinBasedControls, extIntForced, nmiForced);
#endif
    
    // 警告：如果外部中断退出被强制启用，需要确保中断处理正确
    if (pinBasedControls & PIN_BASED_EXTERNAL_INTERRUPT_EXITING) {
        DbgPrint("[HV] WARNING: External interrupt exiting is ENABLED (may be forced by CPU)\n");
        DbgPrint("[HV] External interrupts will cause VM Exit and must be handled!\n");
    }
    
    __vmx_vmwrite(VMCS_CTRL_PIN_BASED_VM_EXECUTION_CONTROLS, pinBasedControls);

    // Primary Processor-Based Controls
    // 注意：只有当 ACTIVATE_SECONDARY_CONTROLS 被支持时才设置它
    //
    // Phase I (2026-06-03; USE_TSC_OFFSETING 撤回):
    //   常态启用 USE_TSC_OFFSETING + per-VCPU 累积 TscOffsetCompensation 会导致
    //   Steam (Chromium UI) 崩溃 —— 多核 thread schedule 时不同 CPU 的 offset
    //   累积量不同,guest 看到 TSC 倒退,chromium TimeTicks::Now 非单调 assert 失败。
    //   要正确修复需要跨核 IPI 同步 offset,工程量大。
    //
    //   现策略:USE_TSC_OFFSETING 仅在 HWBP 启用时由统一 debugger-intercept
    //   动态打开,99% 场景 offset=0 = bare-metal 行为。
    //
    //   代价:无 HWBP 时反作弊 RDTSC 包夹 ReadProcessMemory 能看到 EPT-hook
    //   timing 抖动,Tier 1 #1 部分有效(只在 CE 注册成 debugger + HWBP 启用时
    //   才有补偿)。这是性能 / 稳定性 / 隐身的三角折中。
    // Debugger CR3/DR exits are published lazily when the first HWBP is active.
    // Leaving them clear preserves the ordinary Windows CR3 switch path.
    cpuBasedControls = CPU_BASED_ACTIVATE_MSR_BITMAP;

    // 阶段 7.10: VT 透明键鼠注入需要拦截 PS/2 端口 0x60/0x64
    // bitmap 在 HvInputInitialize 时已分配并配置,此处只 OR 上 bit 25 让 CPU 用它。
    // HvInputInitialize 失败的机器(USB-only laptop 等)走 dormant 路径,
    // 不设此 bit → I/O 全直通,等效于功能 disable。
    if (HvInputIsInitialized()) {
        cpuBasedControls |= CPU_BASED_USE_IO_BITMAPS;
    }
    
    // 检查是否支持 Secondary Controls
    {
        ULONG64 procBasedMsr = __readmsr(useTrueControls ? MSR_IA32_VMX_TRUE_PROCBASED_CTLS : MSR_IA32_VMX_PROCBASED_CTLS);
        ULONG allowed1 = (ULONG)(procBasedMsr >> 32);
        
        if (allowed1 & CPU_BASED_ACTIVATE_SECONDARY_CONTROLS) {
            cpuBasedControls |= CPU_BASED_ACTIVATE_SECONDARY_CONTROLS;
            DbgPrint("[HV] Secondary controls supported\n");
        } else {
            DbgPrint("[HV] Secondary controls NOT supported\n");
        }
    }
    
    cpuBasedControls = HvAdjustVmxControls(
        useTrueControls ? MSR_IA32_VMX_TRUE_PROCBASED_CTLS : MSR_IA32_VMX_PROCBASED_CTLS,
        cpuBasedControls);

#if HV_DIAG_VMCS_SETUP
    DbgPrint("[HV] Primary CPU-based controls = 0x%X\n", cpuBasedControls);
#endif
    __vmx_vmwrite(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, cpuBasedControls);

    // Secondary Controls (只有当 Primary 中启用了 ACTIVATE_SECONDARY_CONTROLS 时才设置)
    if (cpuBasedControls & CPU_BASED_ACTIVATE_SECONDARY_CONTROLS) {
        secondaryControls = 0;
        if (VcpuData->EptTables) {
            secondaryControls |= SECONDARY_EXEC_ENABLE_EPT;
        }
        // 启用 RDTSCP 支持（如果可用）
        secondaryControls |= SECONDARY_EXEC_ENABLE_RDTSCP;
        // 启用 INVPCID 支持（如果可用）
        secondaryControls |= SECONDARY_EXEC_ENABLE_INVPCID;
        // 启用 XSAVES/XRSTORS 支持（如果可用）
        secondaryControls |= SECONDARY_EXEC_ENABLE_XSAVES_XRSTORS;
        // CR3-load exiting 会由软件模拟 MOV CR3。只有 CPU 提供可用的
        // INVVPID context invalidation 时才启用 VPID，否则无法安全清除旧地址空间翻译。
        {
            ULONG64 vpidCaps = __readmsr(MSR_IA32_VMX_EPT_VPID_CAP);
            const ULONG64 invvpidSupported = (1ULL << 32);
            const ULONG64 usableContextTypes =
                (1ULL << 41) | (1ULL << 42) | (1ULL << 43);
            if ((vpidCaps & invvpidSupported) &&
                (vpidCaps & usableContextTypes)) {
                secondaryControls |= SECONDARY_EXEC_ENABLE_VPID;
            }
        }

        // 关键 (Win11 24H2 + Alder Lake 12 代): 启用 TPAUSE/UMONITOR/UMWAIT (WAITPKG)。
        // Win11 的 HalpTimerStallExecutionProcessor 用 TPAUSE 做省电延迟, guest 执行
        // TPAUSE 时若此位 = 0 → #UD (0xC000001D) → BSOD/卡死。HvAdjustVmxControls 会在
        // CPU 不支持时自动清掉此位 (allowed1 不含 bit 26), 所以无脑设是安全的。
        secondaryControls |= SECONDARY_EXEC_ENABLE_USER_WAIT_PAUSE;

        // 嵌套虚拟化：记录是否支持 VMCS Shadowing（实际启用会在进入 L2 时）
        // 注意：初始化时不启用 VMCS Shadowing，因为我们需要拦截所有 VMX 指令
        // 来正确处理 L1 对虚拟 VMCS 的操作
#if HV_DIAG_VMCS_SETUP
        if (g_EnableNestedVirtualization && g_VmcsShadowingSupported) {
            DbgPrint("[HV-NESTED] VMCS Shadowing available (will be used when entering L2)\n");
        }
#endif

        secondaryControls = HvAdjustVmxControls(MSR_IA32_VMX_PROCBASED_CTLS2, secondaryControls);
#if HV_DIAG_VMCS_SETUP
        DbgPrint("[HV] Secondary CPU-based controls = 0x%X\n", secondaryControls);
#endif
        __vmx_vmwrite(VMCS_CTRL_SECONDARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, secondaryControls);

        // VPID 字段：只有当 SECONDARY_EXEC_ENABLE_VPID 真的被 MSR adjust 保留时才写
        if (secondaryControls & SECONDARY_EXEC_ENABLE_VPID) {
            __vmx_vmwrite(VMCS_CTRL_VIRTUAL_PROCESSOR_IDENTIFIER, VcpuData->Vpid);
#if HV_DIAG_VMCS_SETUP
            DbgPrint("[HV] VPID enabled for CPU %u → vpid=%u\n",
                     VcpuData->ProcessorNumber, VcpuData->Vpid);
#endif
        }
    } else {
#if HV_DIAG_VMCS_SETUP
        DbgPrint("[HV] Skipping secondary controls (not enabled)\n");
#endif
    }

    // VM-Exit Controls
    vmexitControls = VM_EXIT_HOST_ADDR_SPACE_SIZE |
                     VM_EXIT_SAVE_IA32_PAT |
                     VM_EXIT_LOAD_IA32_PAT |
                     VM_EXIT_SAVE_IA32_EFER |
                     VM_EXIT_LOAD_IA32_EFER |
                     // 关键 (Win11 24H2 + Alder Lake 12 代): 启用 LOAD_HOST_CET_STATE
                     // VM-Exit 时硬件从 VMCS HOST_S_CET/HOST_SSP/HOST_INTR_SSP_TABLE
                     // 字段 load host CET state. 这些字段我们不写, 所以全为 0,
                     // 等于 VM-Exit 时强制清掉 host CET. 这避免了 host CET shadow
                     // stack 与 hypervisor 栈布局不一致导致的 ret #CP.
                     // 参考 HyperDbg Vmx.c:911 同样做法.
                     VM_EXIT_LOAD_HOST_CET_STATE;
    
    // 关键：如果外部中断退出被强制启用，必须启用 ACK_INTR_ON_EXIT
    // 否则中断不会被 acknowledge，会导致无限 VM Exit 循环
    if (pinBasedControls & PIN_BASED_EXTERNAL_INTERRUPT_EXITING) {
        vmexitControls |= VM_EXIT_ACK_INTR_ON_EXIT;
        DbgPrint("[HV] Enabling VM_EXIT_ACK_INTR_ON_EXIT (required for interrupt handling)\n");
    }
    
    vmexitControls = HvAdjustVmxControls(
        useTrueControls ? MSR_IA32_VMX_TRUE_EXIT_CTLS : MSR_IA32_VMX_EXIT_CTLS,
        vmexitControls);

#if HV_DIAG_VMCS_SETUP
    DbgPrint("[HV] VM-Exit controls = 0x%X (ACK_INTR=%d)\n",
        vmexitControls, (vmexitControls & VM_EXIT_ACK_INTR_ON_EXIT) ? 1 : 0);
#endif

    __vmx_vmwrite(VMCS_CTRL_VMEXIT_CONTROLS, vmexitControls);

    // VM-Entry Controls
    vmentryControls = VM_ENTRY_IA32E_MODE |
                      VM_ENTRY_LOAD_IA32_PAT |
                      VM_ENTRY_LOAD_IA32_EFER |
                      // 关键 (Win11 24H2 + Alder Lake 12 代): 启用 LOAD_GUEST_CET_STATE
                      // VM-Entry 时硬件从 VMCS GUEST_S_CET/GUEST_SSP/GUEST_INTR_SSP_TABLE
                      // 字段 load guest CET state. 字段全为 0 → guest CET 完全禁用,
                      // guest 内 ret 不查 shadow stack. 这是 vmlaunch 后 GuestEntry
                      // 末尾 ret 触发 #UD (0xC000001D) 的根本修复.
                      // 参考 HyperDbg Vmx.c:917 同样做法.
                      VM_ENTRY_LOAD_GUEST_CET_STATE;
    {
        ULONG vmentryRequested = vmentryControls;
        vmentryControls = HvAdjustVmxControls(
            useTrueControls ? MSR_IA32_VMX_TRUE_ENTRY_CTLS : MSR_IA32_VMX_ENTRY_CTLS,
            vmentryControls);
#if HV_DIAG_VMCS_SETUP
        DbgPrint("[HV] VM-Entry controls: requested=0x%X actual=0x%X (LOAD_GUEST_CET=%d)\n",
                 vmentryRequested, vmentryControls,
                 (vmentryControls & VM_ENTRY_LOAD_GUEST_CET_STATE) ? 1 : 0);
#else
        (VOID)vmentryRequested;
#endif
        __vmx_vmwrite(VMCS_CTRL_VMENTRY_CONTROLS, vmentryControls);
    }

    // CET VMCS fields - 改 HyperDbg 风格 (2026-05-31 P0-1):
    // 不显式 vmwrite GUEST_S_CET/GUEST_SSP/GUEST_INTR_SSP_TABLE/HOST_S_CET/HOST_SSP/
    // HOST_INTR_SSP_TABLE,依赖 VMCLEAR 后这些字段为 0。
    //
    // 原因:对某些 CPU/μcode 组合,显式写非默认值即便是 0 也会触发额外 VMCS
    // consistency check,与 CR4.CET 配对错乱导致 vmlaunch 成功但 ret 后 #UD
    // (g_AsmDebugFlag=11, 0xC000001D)。HyperDbg 范式从不显式 vmwrite 这些字段,
    // 让硬件用 VMCLEAR 默认 0 加载 — 实测无 #UD。
    //
    // 参考: HyperDbg hyperhv/code/vmm/vmx/Vmx.c (无任何 GUEST_S_CET / HOST_S_CET
    // vmwrite),只启用 LOAD_GUEST_CET_STATE + LOAD_HOST_CET_STATE 控制位。
    //
    // VMCS field encodings (备查):
    //   GUEST_S_CET=0x6828  GUEST_SSP=0x682A  GUEST_INTR_SSP_TABLE=0x682C
    //   HOST_S_CET =0x6C18  HOST_SSP =0x6C1A  HOST_INTR_SSP_TABLE =0x6C1C

    // MSR Bitmap
    __vmx_vmwrite(VMCS_CTRL_MSR_BITMAP, VcpuData->MsrBitmapPhysical.QuadPart);

    // I/O Bitmap A/B (阶段 7.10: 透明键鼠注入)
    if (cpuBasedControls & CPU_BASED_USE_IO_BITMAPS) {
        PHYSICAL_ADDRESS paA = HvInputGetIoBitmapAPhys();
        PHYSICAL_ADDRESS paB = HvInputGetIoBitmapBPhys();
        __vmx_vmwrite(VMCS_CTRL_IO_BITMAP_A, paA.QuadPart);
        __vmx_vmwrite(VMCS_CTRL_IO_BITMAP_B, paB.QuadPart);
        DbgPrint("[HV] IO Bitmap: A_PA=0x%llX B_PA=0x%llX\n",
                 paA.QuadPart, paB.QuadPart);
    }

    // EPT Pointer
    if (VcpuData->EptTables) {
        eptp.Value = 0;
        eptp.MemoryType = EPTP_MEMORY_TYPE_WB >> 0;
        eptp.PageWalkLength = EPTP_PAGE_WALK_LENGTH_4 >> 3;
        eptp.PageFrameNumber = VcpuData->EptTables->Pml4Physical.QuadPart >> 12;
        __vmx_vmwrite(VMCS_CTRL_EPTP, eptp.Value);
#if HV_DIAG_VMCS_SETUP
        DbgPrint("[HV] EPT enabled: EPTP=0x%llX (PML4 PA=0x%llX)\n",
                 eptp.Value, VcpuData->EptTables->Pml4Physical.QuadPart);
#endif
    } else {
#if HV_DIAG_VMCS_SETUP
        DbgPrint("[HV] EPT disabled (no EptTables)\n");
#endif
    }

    // Other VMCS fields
    __vmx_vmwrite(VMCS_LINK_POINTER, 0xFFFFFFFFFFFFFFFF);

    // #BP is intercepted for private EPT-shadow software breakpoints. Events
    // that do not belong to the private registry are reinjected unchanged.
    __vmx_vmwrite(VMCS_CTRL_EXCEPTION_BITMAP, (1u << 3));

    // CR0/CR4 Guest-Host Mask 与 Read Shadow
    //
    // Phase I (2026-06-03): Tier 1 反检测修复 — CR4 mask 重启为 (1<<13) VMXE。
    //   反作弊用 mov rax,cr4 + test rax,(1<<13) 探测 hypervisor 存在,mask=0
    //   时直接看到 VMXE=1。mask=(1<<13) 时硬件读 CR4 自动返 SHADOW (VMXE=0),
    //   写 CR4 vmexit 到 case 4 handler 强制保留 VMXE + clear shadow VMXE。
    //
    // 历史注释 (P1-11, 2026-05-31): Win11 boot 期 HVCI/VBS/secure launch 频繁
    //   RMW CR4 触发的 vmexit storm 曾导致 BSOD。已通过 HvHandleCrAccess case 4
    //   修正 (HvVmExit.c:828-834): write 时强制 GUEST_CR4 |= VMXE,shadow &= ~VMXE,
    //   HvAdvanceGuestRip 无条件推进。case 4 read 路径从 SHADOW 读保证一致。
    //   如果实测 BSOD,把 cr4_mask 改回 0 即可单点回滚。
    //
    // VM-entry consistency: GUEST_CR4.VMXE 必须 =1,case 4 write handler 强制 OR
    //   VMXE bit 保证。CR4 一旦失同步,VM-entry consistency check 会 fail。
    {
        ULONG64 cr0_now = __readcr0();
        ULONG64 cr4_now = __readcr4();
        ULONG64 cr4_mask = (1ULL << 13);   // CR4.VMXE — 反检测唯一关注的位

        __vmx_vmwrite(VMCS_CTRL_CR0_GUEST_HOST_MASK, 0);
        __vmx_vmwrite(VMCS_CTRL_CR0_READ_SHADOW, cr0_now);

        __vmx_vmwrite(VMCS_CTRL_CR4_GUEST_HOST_MASK, cr4_mask);
        __vmx_vmwrite(VMCS_CTRL_CR4_READ_SHADOW, cr4_now & ~cr4_mask);
    }

    return STATUS_SUCCESS;
}

/*
 * 设置VMCS Guest状态
 */
NTSTATUS HvSetupVmcsGuestState(PVCPU_DATA VcpuData)
{
    DESCRIPTOR_TABLE_REGISTER gdtr, idtr;
    SEGMENT_SELECTOR cs, ss, ds, es, fs, gs, ldtr, tr;
    ULONG_PTR gdt_base;

    _sgdt(&gdtr);
    __sidt(&idtr);
    
    USHORT gdt_limit = *(USHORT*)&gdtr.Data[0];
    ULONG64 gdt_base_64 = *(ULONG64*)&gdtr.Data[2];
    gdt_base = (ULONG_PTR)gdt_base_64;
    
    USHORT idt_limit = *(USHORT*)&idtr.Data[0];
    ULONG64 idt_base = *(ULONG64*)&idtr.Data[2];

    // 获取段寄存器
    HvGetSegmentDescriptor(&cs, __readcs(), (PUCHAR)gdt_base);
    HvGetSegmentDescriptor(&ss, __readss(), (PUCHAR)gdt_base);
    HvGetSegmentDescriptor(&ds, __readds(), (PUCHAR)gdt_base);
    HvGetSegmentDescriptor(&es, __reades(), (PUCHAR)gdt_base);
    HvGetSegmentDescriptor(&fs, __readfs(), (PUCHAR)gdt_base);
    HvGetSegmentDescriptor(&gs, __readgs(), (PUCHAR)gdt_base);
    HvGetSegmentDescriptor(&ldtr, __readldtr(), (PUCHAR)gdt_base);
    HvGetSegmentDescriptor(&tr, __readtr(), (PUCHAR)gdt_base);

    // Guest段选择子
    __vmx_vmwrite(GUEST_CS_SELECTOR, cs.Selector);
    __vmx_vmwrite(GUEST_SS_SELECTOR, ss.Selector);
    __vmx_vmwrite(GUEST_DS_SELECTOR, ds.Selector);
    __vmx_vmwrite(GUEST_ES_SELECTOR, es.Selector);
    __vmx_vmwrite(GUEST_FS_SELECTOR, fs.Selector);
    __vmx_vmwrite(GUEST_GS_SELECTOR, gs.Selector);
    __vmx_vmwrite(GUEST_LDTR_SELECTOR, ldtr.Selector);
    __vmx_vmwrite(GUEST_TR_SELECTOR, tr.Selector);

    // Guest段基址
    __vmx_vmwrite(GUEST_CS_BASE, cs.Base);
    __vmx_vmwrite(GUEST_SS_BASE, ss.Base);
    __vmx_vmwrite(GUEST_DS_BASE, ds.Base);
    __vmx_vmwrite(GUEST_ES_BASE, es.Base);
    __vmx_vmwrite(GUEST_FS_BASE, __readmsr(MSR_IA32_FS_BASE));
    __vmx_vmwrite(GUEST_GS_BASE, __readmsr(MSR_IA32_GS_BASE));
    __vmx_vmwrite(GUEST_LDTR_BASE, ldtr.Base);
    __vmx_vmwrite(GUEST_TR_BASE, tr.Base);

    // Guest段限制
    __vmx_vmwrite(GUEST_CS_LIMIT, cs.Limit);
    __vmx_vmwrite(GUEST_SS_LIMIT, ss.Limit);
    __vmx_vmwrite(GUEST_DS_LIMIT, ds.Limit);
    __vmx_vmwrite(GUEST_ES_LIMIT, es.Limit);
    __vmx_vmwrite(GUEST_FS_LIMIT, fs.Limit);
    __vmx_vmwrite(GUEST_GS_LIMIT, gs.Limit);
    __vmx_vmwrite(GUEST_LDTR_LIMIT, ldtr.Limit);
    __vmx_vmwrite(GUEST_TR_LIMIT, tr.Limit);

    // Guest段访问权限
    __vmx_vmwrite(GUEST_CS_ACCESS_RIGHTS, cs.AccessRights);
    __vmx_vmwrite(GUEST_SS_ACCESS_RIGHTS, ss.AccessRights);
    __vmx_vmwrite(GUEST_DS_ACCESS_RIGHTS, ds.AccessRights);
    __vmx_vmwrite(GUEST_ES_ACCESS_RIGHTS, es.AccessRights);
    __vmx_vmwrite(GUEST_FS_ACCESS_RIGHTS, fs.AccessRights);
    __vmx_vmwrite(GUEST_GS_ACCESS_RIGHTS, gs.AccessRights);
    __vmx_vmwrite(GUEST_LDTR_ACCESS_RIGHTS, ldtr.AccessRights);
    __vmx_vmwrite(GUEST_TR_ACCESS_RIGHTS, tr.AccessRights);

    // Guest GDTR和IDTR
    __vmx_vmwrite(GUEST_GDTR_BASE, gdt_base_64);
    __vmx_vmwrite(GUEST_GDTR_LIMIT, gdt_limit);
    __vmx_vmwrite(GUEST_IDTR_BASE, idt_base);
    __vmx_vmwrite(GUEST_IDTR_LIMIT, idt_limit);

    // Guest控制寄存器
    __vmx_vmwrite(GUEST_CR0, __readcr0());
    __vmx_vmwrite(GUEST_CR3, __readcr3());
    {
        ULONG64 guestCr4 = __readcr4();
#if HV_DEBUG_CLEAR_GUEST_CR4_CET
        const ULONG64 CR4_CET_BIT = (1ULL << 23);
        if (guestCr4 & CR4_CET_BIT) {
            guestCr4 &= ~CR4_CET_BIT;
            DbgPrint("[HV] GUEST_CR4: *** clearing CET bit *** (Win11 24H2 ret #CP fix)\n");
        }
#endif
        __vmx_vmwrite(GUEST_CR4, guestCr4);
    }
    __vmx_vmwrite(GUEST_DR7, __readdr(7));

    // Guest RSP, RIP, RFLAGS
    ULONG_PTR current_rsp = (ULONG_PTR)_AddressOfReturnAddress();
    ULONG_PTR current_rip = (ULONG_PTR)_ReturnAddress();
    
    __vmx_vmwrite(GUEST_RSP, current_rsp);
    __vmx_vmwrite(GUEST_RIP, current_rip);
    __vmx_vmwrite(GUEST_RFLAGS, __readeflags());
    
    VcpuData->GuestState.Rsp = current_rsp;
    VcpuData->GuestState.Rip = current_rip;

    // Guest SYSENTER MSRs
    __vmx_vmwrite(GUEST_IA32_SYSENTER_CS, __readmsr(MSR_IA32_SYSENTER_CS));
    __vmx_vmwrite(GUEST_IA32_SYSENTER_ESP, __readmsr(MSR_IA32_SYSENTER_ESP));
    __vmx_vmwrite(GUEST_IA32_SYSENTER_EIP, __readmsr(MSR_IA32_SYSENTER_EIP));

    // Guest PAT / EFER / DEBUGCTL
    __vmx_vmwrite(GUEST_IA32_PAT, __readmsr(MSR_IA32_PAT));
    __vmx_vmwrite(GUEST_IA32_EFER, __readmsr(MSR_IA32_EFER));
    __vmx_vmwrite(GUEST_IA32_DEBUGCTL, __readmsr(MSR_IA32_DEBUGCTL));

    // Guest非寄存器状态
    __vmx_vmwrite(GUEST_ACTIVITY_STATE, 0);
    __vmx_vmwrite(GUEST_INTERRUPTIBILITY_STATE, 0);
    __vmx_vmwrite(GUEST_PENDING_DEBUG_EXCEPTIONS, 0);

    return STATUS_SUCCESS;
}

/*
 * 设置VMCS Host状态
 */
NTSTATUS HvSetupVmcsHostState(PVCPU_DATA VcpuData)
{
    DESCRIPTOR_TABLE_REGISTER gdtr, idtr;
    SEGMENT_SELECTOR tr;
    ULONG_PTR gdt_base;
    ULONG64 gdt_base_64, idt_base_64;

    _sgdt(&gdtr);
    __sidt(&idtr);
    
    gdt_base_64 = *(ULONG64*)&gdtr.Data[2];
    idt_base_64 = *(ULONG64*)&idtr.Data[2];
    gdt_base = (ULONG_PTR)gdt_base_64;

    HvGetSegmentDescriptor(&tr, __readtr(), (PUCHAR)gdt_base);

    // Host段选择子
    __vmx_vmwrite(HOST_CS_SELECTOR, __readcs() & 0xF8);
    __vmx_vmwrite(HOST_SS_SELECTOR, __readss() & 0xF8);
    __vmx_vmwrite(HOST_DS_SELECTOR, __readds() & 0xF8);
    __vmx_vmwrite(HOST_ES_SELECTOR, __reades() & 0xF8);
    // Step 3 (虚幻范式): HOST_FS_SELECTOR = 0 (空段), HOST_FS_BASE = vcpu 指针.
    // host 路径任何代码调 __readfsbase_u64() 直接拿到 PVCPU_DATA, 不再依赖
    // KeGetCurrentProcessorNumberEx (后者在 host 上下文读 KPCR 不一定可靠).
    //
    // 之前 HOST_FS_SELECTOR/HOST_FS_BASE 写 Windows kernel FS — 现在覆写, 不影响:
    // (1) driver 内核代码无任何 fs:[xxx] / __readfsbase_u64 调用 (grep 全确认)
    // (2) HOST_GS 继续走 Windows GS_BASE 保留 KPCR 访问以防万一 (虚幻置 0 是更激进)
    __vmx_vmwrite(HOST_FS_SELECTOR, 0);
    __vmx_vmwrite(HOST_GS_SELECTOR, __readgs() & 0xF8);
    __vmx_vmwrite(HOST_TR_SELECTOR, __readtr() & 0xF8);

    // Host段基址
    __vmx_vmwrite(HOST_FS_BASE, (ULONG64)VcpuData);
    __vmx_vmwrite(HOST_GS_BASE, __readmsr(MSR_IA32_GS_BASE));

    // P0-6 (2026-06-16): 0x1AA 全面修复 — host TSS + 复制 GDT。
    // 开启 HV_USE_HOST_TSS_OVERRIDE 时, HOST_TR_BASE 指向 per-CPU 独立 TSS
    // (其内 IST1/2/3 已填入 per-CPU IST 栈), HOST_GDTR_BASE 指向 per-CPU 复制
    // GDT (TR 描述符 base 已改写)。NMI/#DF/#MC 经 IDT IST 字段切栈到登记好的
    // IST 栈, 0x1AA EXCEPTION_ON_INVALID_STACK 永久消失。
    // 默认 OFF 时退化为读 Windows TR/GDT,与历史行为完全一致。
#if HV_USE_HOST_TSS_OVERRIDE
    {
        PHV_HOST_CPU_CTX ctx = HvUtilsGetHostCpuCtx(VcpuData->ProcessorNumber);
        if (ctx && ctx->Initialized && ctx->HostGdt) {
            __vmx_vmwrite(HOST_TR_BASE, (ULONG64)&ctx->Tss);
            __vmx_vmwrite(HOST_GDTR_BASE, (ULONG64)ctx->HostGdt);
#if HV_DIAG_VMCS_SETUP
            DbgPrint("[HV] HOST_TR_BASE = 0x%llX (per-CPU HostTss), HOST_GDTR_BASE = 0x%llX (copy)\n",
                     (ULONG64)&ctx->Tss, (ULONG64)ctx->HostGdt);
#endif
        } else {
            __vmx_vmwrite(HOST_TR_BASE, tr.Base);
            __vmx_vmwrite(HOST_GDTR_BASE, gdt_base_64);
            DbgPrint("[HV] WARN: HostTss not init for CPU %u, fallback to Windows TR/GDT\n",
                     VcpuData->ProcessorNumber);
        }
    }
#else
    __vmx_vmwrite(HOST_TR_BASE, tr.Base);
    __vmx_vmwrite(HOST_GDTR_BASE, gdt_base_64);
#endif

    // P0-4 (2026-05-31): HOST_IDTR_BASE — 开关化, 默认 OFF (共享 Windows IDT)。
    // 见 HvCompat.h HV_USE_HOST_IDT_OVERRIDE 注释。
#if HV_USE_HOST_IDT_OVERRIDE
    if (g_HvHostIdt[2].Present) {
        __vmx_vmwrite(HOST_IDTR_BASE, (ULONG64)g_HvHostIdt);
#if HV_DIAG_VMCS_SETUP
        DbgPrint("[HV] HOST_IDTR_BASE = 0x%llX (HvHostIdt, NMI/MCE stub)\n",
                 (ULONG64)g_HvHostIdt);
#endif
    } else {
        __vmx_vmwrite(HOST_IDTR_BASE, idt_base_64);
        DbgPrint("[HV] WARN: HostIdt not initialized, fallback to Windows IDT\n");
    }
#else
    __vmx_vmwrite(HOST_IDTR_BASE, idt_base_64);
#if HV_DIAG_VMCS_SETUP
    DbgPrint("[HV] HOST_IDTR_BASE = 0x%llX (Windows IDT — P0-4 disabled)\n", idt_base_64);
#endif
#endif

    // Host控制寄存器
    __vmx_vmwrite(HOST_CR0, __readcr0());

    // HOST_CR3 — P0-1 (2026-05-31): 开关化, 默认 OFF。
    // 见 HvCompat.h HV_USE_SYSTEM_CR3_FOR_HOST 注释。
#if HV_USE_SYSTEM_CR3_FOR_HOST
    {
        ULONG64 systemCr3 = HvUtilsGetSystemCr3();
        __vmx_vmwrite(HOST_CR3, systemCr3);
#if HV_DIAG_VMCS_SETUP
        DbgPrint("[HV] HOST_CR3 = 0x%llX (system, %s)\n",
                 systemCr3,
                 (systemCr3 == __readcr3()) ? "matches __readcr3" : "differs from __readcr3 (KVAS)");
#endif
    }
#else
    {
        ULONG64 currentCr3 = __readcr3();
        __vmx_vmwrite(HOST_CR3, currentCr3);
#if HV_DIAG_VMCS_SETUP
        DbgPrint("[HV] HOST_CR3 = 0x%llX (__readcr3 — P0-1 disabled)\n", currentCr3);
#endif
    }
#endif

    // Win11 CET 兼容: 清掉 HOST_CR4.CET (bit 23)
    //
    // Win11 在 Intel 11+/12+ CPU 默认启用 CR4.CET=1 (kernel shadow stack +
    // IBT)。本 hypervisor 没有保存/恢复 host 的 shadow stack 状态
    // (IA32_S_CET / SSP / IA32_INTERRUPT_SSP_TABLE_ADDR),也没启用
    // VM_EXIT_LOAD_CET_STATE 控制位。
    //
    // 后果 (无此修复):VM-exit 后 host 沿用 guest 离开时的 SSP, host 的
    // AsmVmExitHandler 大量 CALL/RET 在错误 shadow stack 上读写 → #CP →
    // host IDT handler 嵌套 #CP → 三重故障 → 整机卡死无 dump (Win11 加载
    // 0-3s 现象的根因)。
    //
    // 修复原理:CR4.CET 是 CET 总开关。HOST_CR4.CET=0 → host 不查 shadow
    // stack, CALL/RET 完全安全;GUEST_CR4 保留原值 (含 CET=1) → guest CET
    // 透传, 用户进程/内核 CET 行为不变。host 不动 IA32_S_CET MSR, 所以
    // VM-resume 后 guest 看到的 CET 状态与离开时完全一致。
    {
        ULONG64 hostCr4 = __readcr4();
        const ULONG64 CR4_CET_BIT = (1ULL << 23);
#if HV_DEBUG_KEEP_HOST_CR4_CET
        // 调试模式: 不清 CET, 让 host CR4 = guest CR4
#if HV_DIAG_VMCS_SETUP
        if (hostCr4 & CR4_CET_BIT) {
            DbgPrint("[HV] HOST_CR4: *** KEEPING CET=1 *** (HV_DEBUG_KEEP_HOST_CR4_CET=1)\n");
        }
#endif
#else
        if (hostCr4 & CR4_CET_BIT) {
            hostCr4 &= ~CR4_CET_BIT;
            DbgPrint("[HV] HOST_CR4: clearing CET bit (Win11 shadow stack compat)\n");
        }
#endif
        __vmx_vmwrite(HOST_CR4, hostCr4);
    }

    // Host RSP和RIP
    ULONG64 stackTop = (ULONG64)VcpuData->VmExitStack + 0x10000;
    ULONG64 hostRsp = (stackTop - 0x80) & ~0xFULL;
    VcpuData->HostRsp = hostRsp;
    
    RtlZeroMemory((PVOID)hostRsp, 0x80);
    
    __vmx_vmwrite(HOST_RSP, hostRsp);
    __vmx_vmwrite(HOST_RIP, (ULONG64)AsmVmExitHandler);

    // Host SYSENTER MSRs
    __vmx_vmwrite(HOST_IA32_SYSENTER_CS, __readmsr(MSR_IA32_SYSENTER_CS));
    __vmx_vmwrite(HOST_IA32_SYSENTER_ESP, __readmsr(MSR_IA32_SYSENTER_ESP));
    __vmx_vmwrite(HOST_IA32_SYSENTER_EIP, __readmsr(MSR_IA32_SYSENTER_EIP));

    // Host PAT / EFER
    __vmx_vmwrite(HOST_IA32_PAT, __readmsr(MSR_IA32_PAT));
    __vmx_vmwrite(HOST_IA32_EFER, __readmsr(MSR_IA32_EFER));

    return STATUS_SUCCESS;
}

/*
 * 设置VMCS字段（主函数）
 */
NTSTATUS HvSetupVmcs(PVCPU_DATA VcpuData)
{
    NTSTATUS status;

    __try {
        status = HvSetupVmcsControlFields(VcpuData);
        if (!NT_SUCCESS(status)) return status;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return STATUS_UNSUCCESSFUL;
    }

    __try {
        status = HvSetupVmcsGuestState(VcpuData);
        if (!NT_SUCCESS(status)) return status;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return STATUS_UNSUCCESSFUL;
    }

    __try {
        status = HvSetupVmcsHostState(VcpuData);
        if (!NT_SUCCESS(status)) return status;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}
