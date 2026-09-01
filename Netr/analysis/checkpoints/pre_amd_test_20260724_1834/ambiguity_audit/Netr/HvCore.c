/*
 * HvCore.c - Hypervisor 核心功能实现
 *
 * 支持 Intel VMX 和 AMD SVM
 */

#include "HvCore.h"
#include "HvCompat.h"
#include "HvInput.h"
#include "HvUsbXhci.h"
#include "HvXhciEptTrap.h"
#include "HvPebCloak.h"     // P125: PEB 字段级 EPT spoof
#include "HvUtils.h"

extern volatile BOOLEAN g_VtRootEnabled;

// P122: 全 driver DbgPrint → GUI ring
#define HV_TRACE_THIS_CAT HV_TRACE_CAT_VM
#include "HvTrace.h"

// 全局上下文
HYPERVISOR_CONTEXT g_HypervisorContext = { 0 };

static volatile LONG g_HvPowerOffline = FALSE;

// 内部静态变量
static volatile BOOLEAN s_VmLaunchContinue = FALSE;

// ============================================================
// 2026-06-20: VMXOFF / VMRUN-stop 之后描述符表恢复
// ============================================================
//
// 根因: Intel SDM / AMD APM 规定 VMXOFF (Intel) 和 VMRUN-stop (AMD) 都**不会**
// 自动恢复 IDTR/GDTR/TR/LDTR。这些寄存器保持执行 VMXOFF/STGI 时的值。
//
// Host 模式下 IDTR = HOST_IDTR_BASE = g_HvHostIdt (driver BSS),
//             GDTR = HOST_GDTR_BASE = ctx->HostGdt (NonPaged pool),
//             TR   = HOST_TR_SELECTOR = 0x40 但 base 由 HOST_TR_BASE 给。
//
// VMXOFF 之后, 这些寄存器仍然指向我们分配的内存。HvUtilsCleanupHostTssAll
// 释放 ctx->HostGdt/Tss, 然后 MmUnloadSystemImage 释放 driver image 包括
// g_HvHostIdt。任何中断/异常都会通过 IDTR 跳到已释放页 → triple fault → 整机
// 卡死无 BSOD。
//
// 修复: vmcall 前 sidt/sgdt/str/sldt 保存 Windows 原值, vmcall 之后立刻 lidt/
// lgdt/ltr/lldt 恢复。AsmLoadIdtr / AsmLoadGdtr / AsmLoadTr / AsmLoadLdtr 是
// 裸 asm 包装 (AsmVmx.asm 末尾)。
//
// per-CPU 静态数组, 不动 VCPU_DATA 布局。
#pragma pack(push, 1)
typedef struct _HV_VMOFF_DESC_SAVE {
    UCHAR  IdtrBuf[10];     // sidt: limit(2) + base(8)
    UCHAR  GdtrBuf[10];     // sgdt: limit(2) + base(8)
    USHORT TrSel;           // str
    USHORT LdtrSel;         // sldt
} HV_VMOFF_DESC_SAVE;
#pragma pack(pop)

static HV_VMOFF_DESC_SAVE g_VmoffDescSave[HV_MAX_CPUS] = { 0 };

// Asm helpers (AsmVmx.asm)
extern VOID AsmLoadIdtr(_In_ PVOID IdtrBuffer);
extern VOID AsmLoadGdtr(_In_ PVOID GdtrBuffer);
extern VOID AsmLoadTr(_In_ USHORT Selector);
extern VOID AsmLoadLdtr(_In_ USHORT Selector);

// 清掉 GDT 中某个 TR descriptor 的 busy bit (位 9)。
// LTR 要求 descriptor 的 type 是 9 (available 64-bit TSS), 而 SIDT 时 TR 已是
// 11 (busy), 直接 ltr 会 #GP。必须先 patch type 11 → 9。
//
// 64-bit TSS descriptor 在 GDT 占 16 字节, byte 5 是 access byte:
//   bit 0: A (accessed, 不用)
//   bit 1-3: type 低 3 位
//   bit 4: S (system=0)
//   bit 5-6: DPL
//   bit 7: P (present)
// type = 9 (1001b) = available 64-bit TSS
// type = 11 (1011b) = busy 64-bit TSS
// 区别在 bit 1 (本字节 bit 1 是 type bit1, 不要混淆 bit 9 的说法)
// 实际上 access byte bit 1 = 0 → available, bit 1 = 1 → busy
static VOID HvpClearTrBusyBit(_In_ PVOID GdtBase, _In_ USHORT TrSel)
{
    USHORT idx = TrSel & 0xFFF8;
    PUCHAR desc = (PUCHAR)GdtBase + idx;
    // access byte at offset 5, clear bit 1 (busy → available)
    desc[5] &= (UCHAR)~0x02;
}

/*
 * 启动虚拟机（持续虚拟化模式）
 */
NTSTATUS HvLaunchVm(PVCPU_DATA VcpuData)
{
    int result;
    SIZE_T vmxError = 0;

    s_VmLaunchContinue = FALSE;
    g_VmxTerminated = FALSE;

    VcpuData->IsVirtualized = FALSE;

    result = AsmVmLaunchAndSaveState(VcpuData);

    // 2026-05-31 P3-5: vmlaunch 进 guest 后第一次跨模块 indirect call (DbgPrint)
    // 必 #UD (g_AsmDebugFlag=103/101 验证过 wrmsr S_CET=0 也无效,排除 CET)。
    // 根因未定 (怀疑 Win11 24H2 + 12 代 CPU 微架构对 vmlaunch 后 indirect call
    // 有某种 silicon-level 强制检查),但绕过方案确定:vmlaunch 之后 guest 模式
    // 跑的 C 路径绝不调任何会展开成 indirect-call 的 NT API。
    //
    // 流程:
    //   - g_AsmDebugFlag = 200 标记进入 vmlaunch-成功 路径
    //   - 仅做必要的状态记录 (volatile 写 IsVirtualized)
    //   - 不调任何 DbgPrint / NT API / 间接函数
    //   - 返回 STATUS_SUCCESS,让 caller (在 vmexit 之后才回到 host mode) 打印
    g_AsmDebugFlag = 200;

    if (result == 0) {
        // 直接 volatile 写,不调任何函数。VcpuData->IsVirtualized 后续 host
        // mode 上下文 (KeSetSystemAffinityThread 循环 + __except 返回点) 读取。
        *((volatile BOOLEAN*)&VcpuData->IsVirtualized) = TRUE;
        g_AsmDebugFlag = 201;
        return STATUS_SUCCESS;
    }

    VcpuData->IsVirtualized = FALSE;
    
    __try {
        __vmx_vmread(VM_INSTRUCTION_ERROR, &vmxError);
        DbgPrint("[HV] VMLAUNCH failed: VMX error=%llu\n", vmxError);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[HV] VMLAUNCH failed (cannot read error code)\n");
    }
    
    DbgPrint("[HV] CPU %d: VMLAUNCH failed with result=0x%X\n", 
             VcpuData->ProcessorNumber, result);

    return STATUS_UNSUCCESSFUL;
}

/*
 * 在每个CPU上启动Hypervisor的回调
 */
VOID HvStartOnProcessor(PVOID Context)
{
    ULONG cpuNumber = KeGetCurrentProcessorNumber();
    PVCPU_DATA vcpuData = &g_HypervisorContext.VcpuData[cpuNumber];
    NTSTATUS status;

    UNREFERENCED_PARAMETER(Context);
    
    vcpuData->ProcessorNumber = cpuNumber;
    vcpuData->IsVirtualized = FALSE;
    vcpuData->IsVmxOn = FALSE;

    // Enable VMX
    status = HvEnableVmxOnCpu(vcpuData);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[HV] CPU %d: VMXON failed 0x%X\n", cpuNumber, status);
        return;
    }

#if HV_DISABLE_SLAT
    // 显式跳过 EPT 设置, guest 用自己的 CR3 做 GVA→PA 翻译
    vcpuData->EptTables = NULL;
    DbgPrint("[HV] CPU %d: HV_DISABLE_SLAT=1 — EPT 不分配 (no second-level translation)\n",
             cpuNumber);
#else
    // Setup EPT (Extended Page Tables)
    status = HvSetupEpt(vcpuData);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[HV] CPU %d: EPT setup failed 0x%X (continuing without EPT)\n", cpuNumber, status);
        // EPT 失败不是致命错误，可以继续运行（不使用 EPT）
        vcpuData->EptTables = NULL;
    } else {
#if HV_DIAG_VMCS_SETUP
        DbgPrint("[HV] CPU %d: EPT initialized successfully\n", cpuNumber);
#endif
        // P125 (2026-06-25): 给本 vcpu 建第二份 EPT 实例 (EptPebSpoof) —
        // PEB 字段级 spoof 专用. target CR3 命中时 vmexit 切到这份 EPT.
        // 失败不影响主路径, PEB spoof 不生效, NtQuery hook 仍可挡反检测.
        NTSTATUS pebSt = HvPebCloakSetupVcpu(vcpuData);
        if (!NT_SUCCESS(pebSt)) {
            DbgPrint("[HV] CPU %d: HvPebCloakSetupVcpu failed 0x%X (PEB spoof 将不可用)\n",
                     cpuNumber, pebSt);
        }
    }
#endif

    // Configure VMCS
#if HV_DIAG_VMCS_SETUP
    DbgPrint("[HV] CPU %d: Setting up VMCS...\n", cpuNumber);
#endif
    status = HvSetupVmcs(vcpuData);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[HV] CPU %d: VMCS failed 0x%X\n", cpuNumber, status);
        HvCleanupEpt(vcpuData);
        __vmx_off();
        vcpuData->IsVmxOn = FALSE;
        return;
    }
#if HV_DIAG_VMCS_SETUP
    DbgPrint("[HV] CPU %d: VMCS OK, launching...\n", cpuNumber);
#endif

    // ============================================================
    // 精准诊断: vmlaunch 前 dump 完整硬件状态
    // 目的: 当 vmlaunch 触发 #UD 时, 从 CPU 自己的状态确定根因,
    //       不再依赖外部猜测 (是 VBS / 嵌套 / VMCS 没激活 / ...)
    // 2026-06-16: HV_DIAG_VMCS_SETUP=0 时默认跳过 (启动后不再需要)。
    // ============================================================
#if HV_DIAG_VMCS_SETUP
    {
        ULONG64 diag_cr0  = __readcr0();
        ULONG64 diag_cr4  = __readcr4();
        ULONG64 diag_efer = __readmsr(MSR_IA32_EFER);
        ULONG64 diag_vmxBasic = __readmsr(MSR_IA32_VMX_BASIC);
        ULONG64 diag_featCtl = 0xDEADBEEFDEADBEEFULL;
        ULONG64 diag_currentVmcsPa = 0xDEADBEEFDEADBEEFULL;
        SIZE_T  diag_testGuestRip = 0;
        UCHAR   diag_vmptrstStatus = 0xFF;
        UCHAR   diag_vmreadStatus = 0xFF;
        BOOLEAN diag_inVmxOperation = FALSE;

        __try {
            diag_featCtl = __readmsr(MSR_IA32_FEATURE_CONTROL);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            diag_featCtl = 0xDEADBEEFDEADBEEFULL;
        }

        // === CET MSR 状态 (Win11 24H2 vmlaunch 后 ret #UD 调查) ===
        {
            ULONG64 sCet = 0xDEADBEEFDEADBEEFULL;
            ULONG64 uCet = 0xDEADBEEFDEADBEEFULL;
            ULONG64 pl0Ssp = 0xDEADBEEFDEADBEEFULL;
            ULONG64 intrSspTbl = 0xDEADBEEFDEADBEEFULL;
            UCHAR sCetOk = 1, uCetOk = 1, sspOk = 1, tblOk = 1;

            __try { sCet = __readmsr(0x6A2); }    // IA32_S_CET (supervisor CET)
            __except (EXCEPTION_EXECUTE_HANDLER) { sCetOk = 0; }

            __try { uCet = __readmsr(0x6A0); }    // IA32_U_CET (user CET)
            __except (EXCEPTION_EXECUTE_HANDLER) { uCetOk = 0; }

            __try { pl0Ssp = __readmsr(0x6A4); }  // IA32_PL0_SSP
            __except (EXCEPTION_EXECUTE_HANDLER) { sspOk = 0; }

            __try { intrSspTbl = __readmsr(0x6A8); }  // IA32_INTERRUPT_SSP_TABLE_ADDR
            __except (EXCEPTION_EXECUTE_HANDLER) { tblOk = 0; }

            DbgPrint("[HV-DIAG]  IA32_S_CET (0x6A2) = 0x%llX %s  SH_STK_EN=%llu WR_SHSTK=%llu ENDBR=%llu\n",
                     sCet, sCetOk ? "" : "[#GP]",
                     sCetOk ? (sCet & 1) : 0,
                     sCetOk ? ((sCet >> 1) & 1) : 0,
                     sCetOk ? ((sCet >> 2) & 1) : 0);
            DbgPrint("[HV-DIAG]  IA32_U_CET (0x6A0) = 0x%llX %s\n",
                     uCet, uCetOk ? "" : "[#GP]");
            DbgPrint("[HV-DIAG]  IA32_PL0_SSP (0x6A4) = 0x%llX %s\n",
                     pl0Ssp, sspOk ? "" : "[#GP]");
            DbgPrint("[HV-DIAG]  IA32_INTERRUPT_SSP_TABLE (0x6A8) = 0x%llX %s\n",
                     intrSspTbl, tblOk ? "" : "[#GP]");
            if (sCetOk && (sCet & 1)) {
                DbgPrint("[HV-DIAG]  *** SUPERVISOR SHADOW STACK ENABLED - ret will check ***\n");
            }
        }

        // vmptrst: 不在 VMX operation 触发 #UD; 在 root 模式返回当前 VMCS PA
        __try {
            __vmx_vmptrst(&diag_currentVmcsPa);
            diag_vmptrstStatus = 0;
            diag_inVmxOperation = TRUE;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            diag_vmptrstStatus = 0xEE;
            diag_inVmxOperation = FALSE;
        }

        // vmread VMCS_GUEST_RIP (0x681E): 验证 VMCS 真的激活且能访问
        if (diag_inVmxOperation) {
            __try {
                diag_vmreadStatus = __vmx_vmread(0x681E, &diag_testGuestRip);
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                diag_vmreadStatus = 0xEE;
            }
        }

        DbgPrint("[HV-DIAG] === Pre-VMLAUNCH state on CPU %u ===\n", cpuNumber);
        DbgPrint("[HV-DIAG]  CR0  = 0x%016llX  PE=%llu PG=%llu NE=%llu\n",
                 diag_cr0, (diag_cr0 >> 0) & 1, (diag_cr0 >> 31) & 1, (diag_cr0 >> 5) & 1);
        DbgPrint("[HV-DIAG]  CR4  = 0x%016llX  VMXE=%llu SMXE=%llu CET=%llu\n",
                 diag_cr4, (diag_cr4 >> 13) & 1, (diag_cr4 >> 14) & 1, (diag_cr4 >> 23) & 1);
        DbgPrint("[HV-DIAG]  EFER = 0x%016llX  LMA=%llu LME=%llu NXE=%llu\n",
                 diag_efer, (diag_efer >> 10) & 1, (diag_efer >> 8) & 1, (diag_efer >> 11) & 1);
        DbgPrint("[HV-DIAG]  FEATURE_CONTROL = 0x%016llX  LOCK=%llu INSMX=%llu OUTSMX=%llu\n",
                 diag_featCtl, diag_featCtl & 1, (diag_featCtl >> 1) & 1, (diag_featCtl >> 2) & 1);
        DbgPrint("[HV-DIAG]  VMX_BASIC = 0x%016llX  revID=0x%X regionSize=%llu\n",
                 diag_vmxBasic, (ULONG)(diag_vmxBasic & 0xFFFFFFFFULL),
                 (diag_vmxBasic >> 32) & 0x1FFF);
        DbgPrint("[HV-DIAG]  IRQL = %u\n", (ULONG)KeGetCurrentIrql());
        DbgPrint("[HV-DIAG]  Expected VMCS PA (we wrote) = 0x%016llX\n",
                 (ULONG64)vcpuData->VmcsRegionPhysical.QuadPart);

        // === Magic test: 写 magic 到 GUEST_RSP, 读回, 看一致 ===
        // 不一致 = L0 hypervisor 在 trap-emulate, 我们其实在 non-root
        // 一致 = 真的在 root, VMCS 是我们的
        if (diag_inVmxOperation) {
            SIZE_T savedRsp = 0;
            SIZE_T magicWrite = 0xCAFEBABE12345678ULL;
            SIZE_T magicRead = 0xDEADBEEFDEADBEEFULL;

            __try {
                __vmx_vmread(0x681C, &savedRsp);  // GUEST_RSP
                __vmx_vmwrite(0x681C, magicWrite);
                __vmx_vmread(0x681C, &magicRead);
                __vmx_vmwrite(0x681C, savedRsp);  // 恢复
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                magicRead = 0xFFFFFFFFFFFFFFFFULL;
            }

            if ((ULONG64)magicWrite == (ULONG64)magicRead) {
                DbgPrint("[HV-DIAG]  Magic test: wrote 0x%llX read 0x%llX [MATCH - we ARE in root]\n",
                         (ULONG64)magicWrite, (ULONG64)magicRead);
            } else {
                DbgPrint("[HV-DIAG]  Magic test: wrote 0x%llX read 0x%llX\n",
                         (ULONG64)magicWrite, (ULONG64)magicRead);
                DbgPrint("[HV-DIAG]  *** MISMATCH - L0 hypervisor is trap-emulating our VMCS! ***\n");
                DbgPrint("[HV-DIAG]  We are NOT in real VMX root - vmlaunch will #UD by injection.\n");
            }
        }

        // === CPUID 0x40000000: hypervisor 厂商标识 ===
        {
            int cpuInfo40[4] = {0};
            char vendor[13] = {0};
            __cpuid(cpuInfo40, 0x40000000);
            *((int *)&vendor[0]) = cpuInfo40[1];
            *((int *)&vendor[4]) = cpuInfo40[2];
            *((int *)&vendor[8]) = cpuInfo40[3];
            vendor[12] = 0;
            DbgPrint("[HV-DIAG]  CPUID(0x40000000): max=0x%X vendor=\"%s\"\n",
                     cpuInfo40[0], vendor);
            if (cpuInfo40[0] != 0 || vendor[0] != 0) {
                DbgPrint("[HV-DIAG]  *** HYPERVISOR PRESENT at CPUID leaf 0x40000000 ***\n");
                if (vendor[0] == 'M' && vendor[1] == 'i' && vendor[2] == 'c')
                    DbgPrint("[HV-DIAG]      Microsoft Hyper-V detected\n");
                else if (vendor[0] == 'V' && vendor[1] == 'M' && vendor[2] == 'w')
                    DbgPrint("[HV-DIAG]      VMware detected\n");
                else if (vendor[0] == 'K' && vendor[1] == 'V' && vendor[2] == 'M')
                    DbgPrint("[HV-DIAG]      KVM detected\n");
                else if (vendor[0] == 'V' && vendor[1] == 'B' && vendor[2] == 'o')
                    DbgPrint("[HV-DIAG]      VirtualBox detected\n");
            } else {
                DbgPrint("[HV-DIAG]  No hypervisor vendor at CPUID 0x40000000\n");
            }
        }

        if (!diag_inVmxOperation) {
            DbgPrint("[HV-DIAG]  *** vmptrst #UD - CPU IS NOT IN VMX OPERATION ***\n");
            DbgPrint("[HV-DIAG]  ROOT CAUSE: __vmx_on appeared to return success but\n");
            DbgPrint("[HV-DIAG]  the CPU never actually entered VMX root mode.\n");
            DbgPrint("[HV-DIAG]  This typically means a higher-level hypervisor (Hyper-V\n");
            DbgPrint("[HV-DIAG]  L0 / VBS) intercepted VMXON and rejected nested entry.\n");
        } else {
            DbgPrint("[HV-DIAG]  Current VMCS PA (vmptrst) = 0x%016llX\n", diag_currentVmcsPa);
            if (diag_currentVmcsPa != (ULONG64)vcpuData->VmcsRegionPhysical.QuadPart) {
                DbgPrint("[HV-DIAG]  *** MISMATCH: VMPTRLD did not stick! ***\n");
                DbgPrint("[HV-DIAG]  Expected 0x%llX got 0x%llX\n",
                         (ULONG64)vcpuData->VmcsRegionPhysical.QuadPart, diag_currentVmcsPa);
            } else {
                DbgPrint("[HV-DIAG]  VMCS PA matches expected - VMPTRLD held\n");
            }
            if (diag_vmreadStatus == 0xEE) {
                DbgPrint("[HV-DIAG]  *** vmread triggered #UD - VMCS not accessible ***\n");
            } else if (diag_vmreadStatus == 0) {
                DbgPrint("[HV-DIAG]  VMREAD GUEST_RIP OK = 0x%llX (VMCS truly active)\n",
                         (ULONG64)diag_testGuestRip);
            } else {
                DbgPrint("[HV-DIAG]  VMREAD failed with VMX status code %u (1=Valid 2=Invalid)\n",
                         diag_vmreadStatus);
            }
        }

        // 自检 vmlaunch 触发 #UD 的其他常见原因:
        if (!(diag_cr0 & 1)) DbgPrint("[HV-DIAG]  *** CR0.PE=0 - real mode! vmlaunch will #UD ***\n");
        if (!(diag_cr4 & (1ULL << 13))) DbgPrint("[HV-DIAG]  *** CR4.VMXE=0 - VMX not enabled! ***\n");
        if (!(diag_efer & (1ULL << 10))) DbgPrint("[HV-DIAG]  *** EFER.LMA=0 - not in long mode! ***\n");

        DbgPrint("[HV-DIAG] === End diagnostics ===\n");
    }
#endif  // HV_DIAG_VMCS_SETUP

    // P3-8 (2026-05-31): HvStartOnProcessor 改成 "只 setup,不 vmlaunch"。
    // vmlaunch 移到 HvLaunchVmDpcRoutine 用 KeGenericCallDpc 并行调度,
    // 避免串行 vmlaunch 时"部分 CPU root mode + 部分 guest mode"窗口期间
    // Win11 scheduler 跨核同步触发死锁(用户报告 random-position 卡死的真根因)。
    //
    // 此时 vcpuData 已 setup 完: VMXON+VMCLEAR+VMPTRLD+一堆 vmwrite 都 OK,
    // 只差最后的 vmlaunch。后续 HvInitialize 用 KeGenericCallDpc 在 12 CPU
    // 上并行调 HvLaunchVm,几乎瞬间全部进 guest mode。
    g_AsmDebugFlag = 250;  // marker: HvStartOnProcessor 完成 setup(未 vmlaunch)
}

/*
 * 在每个CPU上启动 SVM 的回调 (AMD)
 */
VOID SvmStartOnProcessor(PVOID Context)
{
    ULONG cpuNumber = KeGetCurrentProcessorNumber();
    PVCPU_DATA vcpuData = &g_HypervisorContext.VcpuData[cpuNumber];
    NTSTATUS status;

    UNREFERENCED_PARAMETER(Context);
    
    vcpuData->ProcessorNumber = cpuNumber;
    vcpuData->IsVirtualized = FALSE;

    // Enable SVM
    status = SvmEnableOnCpu(vcpuData);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[SVM] CPU %d: SVM enable failed 0x%X\n", cpuNumber, status);
        return;
    }

#if HV_DISABLE_SLAT
    // 显式跳过 NPT 设置, guest 用自己的 CR3 做 GVA→PA 翻译
    vcpuData->NptTables = NULL;
    DbgPrint("[SVM] CPU %d: HV_DISABLE_SLAT=1 — NPT 不分配 (no second-level translation)\n",
             cpuNumber);
#else
    // Setup NPT (Nested Page Tables) - 可选
    status = SvmSetupNpt(vcpuData);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[SVM] CPU %d: NPT setup failed 0x%X (continuing without NPT)\n", cpuNumber, status);
        vcpuData->NptTables = NULL;
    } else {
        DbgPrint("[SVM] CPU %d: NPT initialized successfully\n", cpuNumber);
    }
#endif

    // Configure VMCB
    status = SvmSetupVmcb(vcpuData);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[SVM] CPU %d: VMCB setup failed 0x%X\n", cpuNumber, status);
        SvmCleanupNpt(vcpuData);
        SvmCleanup(vcpuData);
        return;
    }

    // Launch VM (VMRUN)
    status = SvmLaunchVm(vcpuData);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[SVM] CPU %d: VMRUN failed 0x%X\n", cpuNumber, status);
        SvmCleanupNpt(vcpuData);
        SvmCleanup(vcpuData);
        vcpuData->IsVirtualized = FALSE;
        return;
    }

    DbgPrint("[SVM] CPU %d: *** NOW RUNNING IN GUEST MODE *** (NPT=%s)\n", 
             cpuNumber, vcpuData->NptTables ? "ON" : "OFF");
}

// ============================================================
// P3-8 (2026-05-31): 并行 vmlaunch broadcast — HyperDbg 范式
// ============================================================
// 用 KeGenericCallDpc 在所有 CPU 上并行调用 HvLaunchVm,避免串行 vmlaunch
// 时跨 CPU thread 切换在 Win11 上触发死锁 (用户报告 random-position 卡死)。

// KeGenericCallDpc / KeSignalCallDpcSynchronize / KeSignalCallDpcDone 在
// 某些 WDK 配置下 ntddk.h 不暴露 — 显式 forward declaration (跟 HvBroadcast.c
// 同款方法,避免 C4013 undefined 警告)。
NTKERNELAPI VOID KeGenericCallDpc(_In_ PKDEFERRED_ROUTINE Routine, _In_opt_ PVOID Context);
NTKERNELAPI VOID KeSignalCallDpcDone(_In_ PVOID SystemArgument1);
NTKERNELAPI LOGICAL KeSignalCallDpcSynchronize(_In_ PVOID SystemArgument2);

static volatile LONG g_LaunchSuccessCount = 0;
static volatile LONG g_LaunchAttemptCount = 0;

static VOID
HvLaunchVmDpcRoutine(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
)
{
    ULONG cpuNumber = KeGetCurrentProcessorNumber();
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(DeferredContext);

    InterlockedIncrement(&g_LaunchAttemptCount);

    if (cpuNumber < g_HypervisorContext.ProcessorCount &&
        g_HypervisorContext.VcpuData) {
        PVCPU_DATA vcpuData = &g_HypervisorContext.VcpuData[cpuNumber];

        // setup 已经在 PASSIVE 串行阶段完成 (VMXON+VMCLEAR+VMPTRLD+vmwrite 全 OK)
        // 这里只跑 vmlaunch
        if (vcpuData->VmcsRegion != NULL && vcpuData->ProcessorNumber == cpuNumber) {
            __try {
                NTSTATUS launchStatus = HvLaunchVm(vcpuData);
                if (NT_SUCCESS(launchStatus)) {
                    InterlockedIncrement(&g_LaunchSuccessCount);
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                // 不能 DbgPrint(可能 guest mode indirect call 崩)
                // 只设 per-CPU flag (400+cpu),后续 host context 读
                g_AsmDebugFlag = 400 + cpuNumber;
            }
        }
    }

    // KeGenericCallDpc 同步原语 — 所有 DPC 都到这里后才放行
    KeSignalCallDpcSynchronize(SystemArgument2);
    KeSignalCallDpcDone(SystemArgument1);
}

/*
 * 初始化Hypervisor (统一入口)
 *
 * 自动检测 CPU 厂商并选择 VMX 或 SVM
 */
NTSTATUS HvInitialize(VOID)
{
    ULONG i;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG successCount = 0;
    CPU_VENDOR cpuVendor;

    HvClearPowerOffline();
    DbgPrint("[HV] ========================================\n");
    DbgPrint("[HV] Initializing Hypervisor...\n");
    DbgPrint("[HV] ========================================\n");
    
    // 显示反虚拟化检测状态
    DbgPrint("[HV] Anti-VM Detection: %s\n", 
             HvGetAntiVmDetection() ? "ENABLED" : "DISABLED");

    if (g_HypervisorContext.IsActive) {
        return STATUS_ALREADY_REGISTERED;
    }

    // 检测 CPU 厂商
    cpuVendor = HvDetectCpuVendor();
    HvPrintCpuInfo();

    // 根据 CPU 厂商检查虚拟化支持
    if (cpuVendor == CPU_VENDOR_INTEL) {
        DbgPrint("[HV] Intel CPU detected, using VMX\n");
        if (!HvCheckVmxSupport()) {
            DbgPrint("[HV] VMX not supported or disabled\n");
            return STATUS_NOT_SUPPORTED;
        }
    }
    else if (cpuVendor == CPU_VENDOR_AMD) {
        DbgPrint("[HV] AMD CPU detected, using SVM\n");
        if (!SvmCheckSupport()) {
            DbgPrint("[HV] SVM not supported or disabled\n");
            return STATUS_NOT_SUPPORTED;
        }
    }
    else {
        DbgPrint("[HV] Unknown CPU vendor, virtualization not supported\n");
        return STATUS_NOT_SUPPORTED;
    }

#if !HV_DISABLE_SLAT
    if (cpuVendor == CPU_VENDOR_INTEL) {
        status = HvEptInitializeMemoryTypes();
        if (!NT_SUCCESS(status)) {
            DbgPrint("[HV] Refusing VMX startup without a valid MTRR map: 0x%08X\n",
                     status);
            return status;
        }
    }
#endif

    g_HypervisorContext.ProcessorCount = KeQueryActiveProcessorCount(NULL);
    DbgPrint("[HV] CPU count: %d\n", g_HypervisorContext.ProcessorCount);

    if (g_HypervisorContext.ProcessorCount == 0) {
        return STATUS_UNSUCCESSFUL;
    }

    size_t allocSize = sizeof(VCPU_DATA) * g_HypervisorContext.ProcessorCount;
    g_HypervisorContext.VcpuData = (PVCPU_DATA)HvAllocateNonPagedZeroed(
        allocSize, 'VCPU');

    if (!g_HypervisorContext.VcpuData) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(g_HypervisorContext.VcpuData, allocSize);

#if !HV_MINIMAL_MODE
    // 阶段 7.10 Layer 4: 真 VT-透明 USB HID 注入
    {
        NTSTATUS xhciStatus = HvUsbXhciInitialize();
        if (!NT_SUCCESS(xhciStatus)) {
            DbgPrint("[HV] HvUsbXhciInitialize failed 0x%X (Layer 4 disabled, falling back to v3)\n",
                     xhciStatus);
        }
    }

    // 阶段 7.10: VT 透明键鼠注入
    {
        NTSTATUS inputStatus = HvInputInitialize();
        if (!NT_SUCCESS(inputStatus)) {
            DbgPrint("[HV] HvInputInitialize failed 0x%X (input injection disabled)\n",
                     inputStatus);
        }
    }
#else
    DbgPrint("[HV] HV_MINIMAL_MODE=1 — xHCI Layer 4 + Input 模块不初始化\n");
#endif

    // 在所有CPU上串行初始化
    for (i = 0; i < g_HypervisorContext.ProcessorCount; i++) {
        KAFFINITY affinity = (KAFFINITY)(1ULL << i);
        
        KeSetSystemAffinityThread(affinity);
        
        ULONG actualCpu = KeGetCurrentProcessorNumber();
        if (actualCpu != i) {
            KeRevertToUserAffinityThread();
            continue;
        }
        
        __try {
            // 根据 CPU 厂商调用不同的启动函数
            if (cpuVendor == CPU_VENDOR_INTEL) {
                HvStartOnProcessor(&g_HypervisorContext.VcpuData[i]);
            }
            else {
                SvmStartOnProcessor(&g_HypervisorContext.VcpuData[i]);
            }
            
            if (g_HypervisorContext.VcpuData[i].IsVirtualized) {
                successCount++;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            ULONG excCode = GetExceptionCode();
            ULONG64 flag = g_AsmDebugFlag;
            DbgPrint("[HV] CPU %d: Exception 0x%X (g_AsmDebugFlag=%llu)\n",
                     i, excCode, flag);
            // 精准定位 #UD 触发点:
            //   1  = AsmVmLaunchAndSaveState entry
            //   2  = GPR pushed
            //   3  = HOST_RSP vmread done
            //   4  = before vmlaunch (if exception with flag=4, vmlaunch itself #UD)
            //   5  = after vmlaunch fallthrough (VMfail, not #UD on vmlaunch)
            //   10 = GuestEntry (vmlaunch succeeded, guest ran)
            //   20 = AsmVmExitHandler entry (guest exited normally to host)
            //   99 = VmLaunchFailed branch reached
            switch (flag) {
            case 4:
                DbgPrint("[HV] -> #UD on vmlaunch instruction itself\n");
                break;
            case 5:
                DbgPrint("[HV] -> vmlaunch returned (VMfail), exception in fallthrough\n");
                break;
            case 10:
                DbgPrint("[HV] -> vmlaunch SUCCEEDED, exception in GuestEntry epilog (pop/popfq)\n");
                break;
            case 11:
                DbgPrint("[HV] -> popfq OK, exception on (xor rax,rax) or (mov flag=12) — g_AsmDebugFlag page may be RO under guest CR3?\n");
                break;
            case 12:
                DbgPrint("[HV] -> ret-prep OK, exception on RET or RET target — guest CR3/RIP issue (caller code page unreachable?)\n");
                break;
            case 20:
                DbgPrint("[HV] -> guest VM-Exit reached host handler, exception there\n");
                break;
            case 100:
                DbgPrint("[HV] -> ret to C OK, #UD on rdmsr/wrmsr IA32_S_CET — MSR access not allowed\n");
                break;
            case 101:
                DbgPrint("[HV] -> rdmsr/wrmsr OK, #UD on DbgPrint after wrmsr-clear (CET still active?)\n");
                break;
            case 102:
                DbgPrint("[HV] -> DbgPrint OK! #UD on second DbgPrint or result==0 branch\n");
                break;
            case 103:
                DbgPrint("[HV] -> reached *** VIRT ACTIVE *** print path, #UD on epilog/ret\n");
                break;
            default:
                DbgPrint("[HV] -> exception in pre-vmlaunch setup (flag=%llu)\n", flag);
                break;
            }
        }
        
        KeRevertToUserAffinityThread();
    }

    // P1-10 (2026-05-31): DPC vmlaunch 暂回退到 serial loop。
    //
    // 用户报告 2026-05-31 DPC 路径在 P0-1/P0-4 修复后仍 raised 异常 →
    // 卡死。怀疑 KeGenericCallDpc 内部某条 indirect call (KeSignalCallDpc*)
    // 在 guest mode 跑出 #UD/#CP。serial loop 是用户已验证的稳定路径。
    // 待 P0-* 全部确认后再回切 DPC。
    DbgPrint("[HV] [POST-SETUP-LOOP] for loop exited, cpuVendor=%d\n", cpuVendor);

    // P3-14: 多 CPU 串行 vmlaunch + 双层 SEH 保护
    if (cpuVendor == CPU_VENDOR_INTEL) {
        DbgPrint("[HV] [MULTI-CPU-MODE] Starting serial vmlaunch on %u CPUs\n",
                 g_HypervisorContext.ProcessorCount);
        for (ULONG cpu = 0; cpu < g_HypervisorContext.ProcessorCount; cpu++) {
            KeSetSystemAffinityThread((KAFFINITY)(1ULL << cpu));
            ULONG actualCpu = KeGetCurrentProcessorNumber();
            if (actualCpu != cpu) { KeRevertToUserAffinityThread(); continue; }
            __try {
                NTSTATUS launchStatus = HvLaunchVm(&g_HypervisorContext.VcpuData[cpu]);
                __try {
                    if (NT_SUCCESS(launchStatus)) {
                        InterlockedIncrement((volatile LONG*)&successCount);
                    }
                } __except (EXCEPTION_EXECUTE_HANDLER) { g_AsmDebugFlag = 600 + cpu; }
            } __except (EXCEPTION_EXECUTE_HANDLER) { g_AsmDebugFlag = 700 + cpu; }
            KeRevertToUserAffinityThread();
        }
        DbgPrint("[HV] Serial vmlaunch done: succeeded=%u/%u\n",
                 successCount, g_HypervisorContext.ProcessorCount);

        // DIAG-3 (2026-05-31): 打印第一次 vmexit 的诊断快照 (自终止 handler 填)
        {
            extern ULONG64 g_DiagFirstExitReason;
            extern ULONG64 g_DiagFirstExitQual;
            extern ULONG64 g_DiagFirstGuestRip;
            extern ULONG64 g_DiagFirstInstrLen;
            extern ULONG64 g_DiagFirstExitIntrInfo;
            DbgPrint("[HV-DIAG3] === FIRST VMEXIT SNAPSHOT ===\n");
            DbgPrint("[HV-DIAG3]   ExitReason      = %llu (0x%llX), basic=%llu\n",
                     g_DiagFirstExitReason, g_DiagFirstExitReason,
                     g_DiagFirstExitReason & 0xFFFF);
            DbgPrint("[HV-DIAG3]   ExitQualification = 0x%llX\n", g_DiagFirstExitQual);
            DbgPrint("[HV-DIAG3]   GuestRIP        = 0x%llX\n", g_DiagFirstGuestRip);
            DbgPrint("[HV-DIAG3]   InstructionLen  = %llu\n", g_DiagFirstInstrLen);
            DbgPrint("[HV-DIAG3]   ExitIntrInfo    = 0x%llX\n", g_DiagFirstExitIntrInfo);
            DbgPrint("[HV-DIAG3]   (basic reason: 0=Exception/NMI 1=ExtInt 28=CR 31=RDMSR 32=WRMSR 48=EPTviol 49=EPTmisc)\n");
            DbgPrint("[HV-DIAG3] === END SNAPSHOT ===\n");
        }
    }

    // Publish the hypervisor only when every processor actually completed
    // VMLAUNCH/VMRUN. Later IPI paths require this all-or-nothing invariant.
    successCount = 0;
    for (i = 0; i < g_HypervisorContext.ProcessorCount; i++) {
        if (g_HypervisorContext.VcpuData[i].IsVirtualized) {
            successCount++;
        }
    }

    if (successCount == g_HypervisorContext.ProcessorCount) {
        g_HypervisorContext.IsActive = TRUE;
        g_AsmDebugFlag = 300;  // marker: 进入 IsActive=TRUE 路径

        // P3-15 (2026-05-31): vmlaunch 后 driver 在 guest mode 跑。
        // P3-13/P3-14 证明 vmlaunch 后 DbgPrint indirect call **偶发** #UD,
        // 多 CPU 同时 vmlaunch 时频率剧增,且 SEH unwind 自身也是 indirect call,
        // SEH 框架可能跟着 #UD → 死锁。
        // 唯一稳定方案:vmlaunch 后**绝对不调 DbgPrint 或任何复杂 indirect call**。
        // hypervisor 启动成功的标记只用 g_AsmDebugFlag 数字传递,不输出文本。
        // xHCI EPT trap 内部大量 DbgPrint,也得关掉 (HV_MINIMAL_MODE=0 时它会跑)
        g_AsmDebugFlag = 305;  // marker: Hypervisor ACTIVE,无 DbgPrint
        status = STATUS_SUCCESS;

#if !HV_MINIMAL_MODE
        // P3-15: xHCI EPT trap 内部多个 DbgPrint,在 guest mode 高频崩。禁用。
        g_AsmDebugFlag = 310;  // marker: 跳过 xHCI trap init (P3-15 disabled)
#endif
    }
    else {
        DbgPrint("[HV] Hypervisor startup rejected: only %u/%u CPUs virtualized\n",
                 successCount, g_HypervisorContext.ProcessorCount);
        status = STATUS_UNSUCCESSFUL;
        HvCleanup();
    }

    return status;
}

/*
 * 测试 Hypervisor 是否正在运行 (统一接口)
 */
BOOLEAN HvIsHypervisorRunning(VOID)
{
    ULONG64 result = 0;
    CPU_VENDOR cpuVendor = HvGetCpuVendor();

    if (HvIsPowerOffline()) {
        return FALSE;
    }

    if (!HvIsCurrentProcessorVirtualized()) {
        return FALSE;
    }
    
    __try {
        if (cpuVendor == CPU_VENDOR_INTEL) {
            result = AsmVmCallWithResult(1);
        }
        else if (cpuVendor == CPU_VENDOR_AMD) {
            result = AsmVmmcallWithResult(1);
        }
        
        if (result == 0xDEADBEEF) {
            return TRUE;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        HvInvalidateCurrentProcessorVirtualization();
    }
    
    return FALSE;
}

BOOLEAN HvIsCurrentProcessorVirtualized(VOID)
{
    ULONG cpuNumber = KeGetCurrentProcessorNumber();
    PVCPU_DATA vcpuData = g_HypervisorContext.VcpuData;

    if (HvIsPowerOffline()) {
        return FALSE;
    }

    if (!vcpuData || cpuNumber >= g_HypervisorContext.ProcessorCount) {
        return FALSE;
    }

    return vcpuData[cpuNumber].IsVirtualized ? TRUE : FALSE;
}

BOOLEAN HvAreAllProcessorsVirtualized(VOID)
{
    PVCPU_DATA vcpuData = g_HypervisorContext.VcpuData;
    ULONG processorCount = g_HypervisorContext.ProcessorCount;

    if (HvIsPowerOffline() ||
        !g_HypervisorContext.IsActive || !vcpuData || processorCount == 0) {
        return FALSE;
    }
    for (ULONG processor = 0; processor < processorCount; ++processor) {
        if (!vcpuData[processor].IsVirtualized) return FALSE;
    }
    return TRUE;
}

BOOLEAN HvIsPowerOffline(VOID)
{
    return InterlockedCompareExchange(&g_HvPowerOffline, 0, 0) != 0;
}

VOID HvMarkPowerOffline(VOID)
{
    InterlockedExchange(&g_HvPowerOffline, TRUE);
    g_HypervisorContext.IsActive = FALSE;
    g_VtRootEnabled = FALSE;
    KeMemoryBarrier();
}

VOID HvClearPowerOffline(VOID)
{
    InterlockedExchange(&g_HvPowerOffline, FALSE);
}

VOID HvInvalidateProcessorVirtualization(_In_ ULONG ProcessorNumber)
{
    PVCPU_DATA vcpuData = g_HypervisorContext.VcpuData;

    if (vcpuData && ProcessorNumber < g_HypervisorContext.ProcessorCount) {
        *((volatile BOOLEAN*)&vcpuData[ProcessorNumber].IsVirtualized) = FALSE;
    }
    KeMemoryBarrier();
}

VOID HvInvalidateCurrentProcessorVirtualization(VOID)
{
    HvInvalidateProcessorVirtualization(KeGetCurrentProcessorNumber());
}

/*
 * 获取 Hypervisor 版本 (统一接口)
 */
ULONG HvGetHypervisorVersion(VOID)
{
    ULONG64 result = 0;
    CPU_VENDOR cpuVendor = HvGetCpuVendor();

    if (!HvIsCurrentProcessorVirtualized()) {
        return 0;
    }
    
    __try {
        if (cpuVendor == CPU_VENDOR_INTEL) {
            result = AsmVmCallWithResult(2);
        }
        else if (cpuVendor == CPU_VENDOR_AMD) {
            result = AsmVmmcallWithResult(2);
        }
        return (ULONG)result;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
    }
    
    return 0;
}

/*
 * 执行 VMCALL/VMMCALL 请求卸载 (统一接口)
 */
VOID HvRequestUnload(VOID)
{
    int result[4];
    CPU_VENDOR cpuVendor = HvGetCpuVendor();

    if (!HvIsCurrentProcessorVirtualized()) {
        return;
    }
    
    __cpuidex(result, 0, 0);
    
    __try {
        if (cpuVendor == CPU_VENDOR_INTEL) {
            AsmVmCall(0x1337DEAD);
        }
        else if (cpuVendor == CPU_VENDOR_AMD) {
            AsmVmmcall(0x1337DEAD);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
    }
}

/*
 * IPI 回调：在每个 CPU 上同步执行卸载
 * 使用 KeIpiGenericCall 确保所有 CPU 同时退出虚拟化，
 * 防止某个 CPU 还在 VM Exit handler 中引用已释放的内存
 */
static volatile LONG g_UnloadBarrierCount = 0;

static ULONG_PTR HvUnloadIpiCallback(ULONG_PTR Context)
{
    ULONG cpuNumber = KeGetCurrentProcessorNumber();
    PVCPU_DATA vcpuData;
    CPU_VENDOR cpuVendor = (CPU_VENDOR)Context;

    if (cpuNumber >= g_HypervisorContext.ProcessorCount) {
        InterlockedIncrement(&g_UnloadBarrierCount);
        return 0;
    }

    vcpuData = &g_HypervisorContext.VcpuData[cpuNumber];

    if (vcpuData->IsVirtualized) {
        // ============================================================
        // 2026-06-20: VMXOFF 之后必须恢复 IDTR/GDTR/TR/LDTR (仅 Intel)
        // ============================================================
        // VMX 规范: VMXOFF 不自动恢复 IDTR/GDTR/TR/LDTR, 保持 HOST_* 字段
        // (我们分配的 g_HvHostIdt / ctx->HostGdt / ctx->Tss) 状态。
        // 必须显式 lidt/lgdt/ltr/lldt 恢复 Windows 原值, 否则 driver 卸载
        // 后中断派发野指针 → triple fault → 整机卡死无 BSOD。
        //
        // SVM 不需要: VMRUN 时硬件自动保存 host state 到 HSAVE_PA,
        // VMEXIT 自动恢复, 包括 IDTR/GDTR。无 hypervisor bug。
        //
        // 中断窗口: vmxoff 到 4 个 load 指令之间 ~30 条 C/ASM 指令。IPI_LEVEL
        // 关了 IRQ; NMI/MCE 不可屏蔽但概率极低 (μs 窗口)。
        BOOLEAN doRestore = (cpuVendor == CPU_VENDOR_INTEL) &&
                            (cpuNumber < HV_MAX_CPUS);
        if (doRestore) {
            __sidt(g_VmoffDescSave[cpuNumber].IdtrBuf);
            _sgdt(g_VmoffDescSave[cpuNumber].GdtrBuf);
            g_VmoffDescSave[cpuNumber].TrSel = __readtr();
            g_VmoffDescSave[cpuNumber].LdtrSel = __readldtr();
        }

        __try {
            if (cpuVendor == CPU_VENDOR_INTEL) {
                AsmVmCall(0x1337DEAD);
            } else {
                AsmVmmcall(0x1337DEAD);
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
        }

        // VMXOFF 后立刻恢复 — 不能调任何 NT API (它们可能用 GS/IDT)
        if (doRestore) {
            // LTR 要求 GDT 中对应 TR descriptor 的 busy bit (access byte bit 1)
            // 已清, 否则 #GP。STR 时 TR 是 busy 状态, 必须先 patch GDT。
            // GDT base 在 GdtrBuf+2 处 (limit:2 + base:8)。
            ULONG64 gdtBase = *(ULONG64 UNALIGNED*)(g_VmoffDescSave[cpuNumber].GdtrBuf + 2);
            HvpClearTrBusyBit((PVOID)gdtBase, g_VmoffDescSave[cpuNumber].TrSel);

            AsmLoadGdtr(g_VmoffDescSave[cpuNumber].GdtrBuf);
            AsmLoadIdtr(g_VmoffDescSave[cpuNumber].IdtrBuf);
            AsmLoadTr(g_VmoffDescSave[cpuNumber].TrSel);
            AsmLoadLdtr(g_VmoffDescSave[cpuNumber].LdtrSel);
        }

    }
    else if (cpuVendor == CPU_VENDOR_INTEL && vcpuData->IsVmxOn) {
        // VMXON succeeded but VMLAUNCH did not. Host descriptor state was not
        // loaded, so a local VMXOFF is sufficient before freeing resources.
        __try {
            __vmx_off();
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
        }
        vcpuData->IsVmxOn = FALSE;
    }

    InterlockedIncrement(&g_UnloadBarrierCount);
    return 0;
}

/*
 * 清理Hypervisor (统一接口)
 */
VOID HvCleanup(VOID)
{
    ULONG i;
    CPU_VENDOR cpuVendor = HvGetCpuVendor();

    if (!g_HypervisorContext.IsActive && !g_HypervisorContext.VcpuData) {
        DbgPrint("[HV] HvCleanup: Not active, skipping\n");
        return;
    }

    DbgPrint("[HV] Unloading Hypervisor (%s)...\n",
             cpuVendor == CPU_VENDOR_INTEL ? "VMX" : "SVM");

    if (!g_HypervisorContext.VcpuData) {
        DbgPrint("[HV] HvCleanup: VcpuData is NULL, nothing to cleanup\n");
        g_HypervisorContext.IsActive = FALSE;
        return;
    }

    // Stop asynchronous producers before any VMXOFF or VCPU/EPT release.
    // The final resource release remains below, after every CPU is out of VMX.
    HvInputBeginShutdown();
    HvUsbXhciBeginShutdown();

    // 使用 IPI 同步所有 CPU 同时退出虚拟化
    // 这确保没有 CPU 还在 VM Exit handler 中引用共享数据
    g_UnloadBarrierCount = 0;
    KeIpiGenericCall(HvUnloadIpiCallback, (ULONG_PTR)cpuVendor);

    // 等待所有 CPU 完成卸载（IPI 是同步的，这里是额外保障）
    DbgPrint("[HV] All CPUs devirtualized (%d responded)\n", g_UnloadBarrierCount);

    /* xHCI trap state points into the per-VCPU EPT tables, while VMCS still
     * references the input bitmaps.  Tear both managers down before freeing
     * any VCPU/EPT storage. */
    HvUsbXhciShutdown(); /* teardown while VCPU/EPT state is still valid */
    HvInputShutdown();    /* release bitmap after VMXOFF, before VCPU free */

    // 所有 CPU 已退出虚拟化，安全释放资源
    for (i = 0; i < g_HypervisorContext.ProcessorCount; i++) {
        PVCPU_DATA vcpuData = &g_HypervisorContext.VcpuData[i];

        if (cpuVendor == CPU_VENDOR_INTEL) {
            HvCleanupEpt(vcpuData);

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
        }
        else if (cpuVendor == CPU_VENDOR_AMD) {
            SvmCleanupNpt(vcpuData);
            SvmCleanup(vcpuData);
        }
    }

    ExFreePoolWithTag(g_HypervisorContext.VcpuData, 'VCPU');
    g_HypervisorContext.VcpuData = NULL;

    // 阶段 7.10 Layer 4: 卸 xHCI BAR 映射 + 清状态 (必须在 HvInputShutdown 之前,
    // 否则 IPI 还可能在 KeIpiGenericCall 路径上跑)
    /* xHCI teardown already completed before VCPU/EPT release. */

    // 阶段 7.10: 释放 IO bitmap + 取消所有 AutoBreak timer
    /* Input teardown already completed before VCPU/EPT release. */

    g_HypervisorContext.IsActive = FALSE;
    DbgPrint("[HV] Hypervisor unloaded\n");
}

/*
 * 打印调试统计信息 (统一接口)
 */
VOID HvPrintDebugStats(VOID)
{
    CPU_VENDOR cpuVendor = HvGetCpuVendor();
    ULONG64 totalExits;
    
    if (cpuVendor == CPU_VENDOR_INTEL) {
        DbgPrint("[HV-DEBUG] ========== Intel VMX Exit Statistics ==========\n");
        DbgPrint("[HV-DEBUG] Total VM Exits: %llu\n", g_VmExitCounter);
        DbgPrint("[HV-DEBUG] Last Exit Reason: %llu\n", g_LastExitReason);
        DbgPrint("[HV-DEBUG] Debug Flag: 0x%llX\n", g_AsmDebugFlag);
        DbgPrint("[HV-DEBUG] ---------- Exit Counts by Type ----------\n");
        DbgPrint("[HV-DEBUG] CPUID: %llu\n", g_ExitCountCpuid);
        DbgPrint("[HV-DEBUG] VMCALL: %llu\n", g_ExitCountVmcall);
        DbgPrint("[HV-DEBUG] MSR Read: %llu\n", g_ExitCountMsrRead);
        DbgPrint("[HV-DEBUG] MSR Write: %llu\n", g_ExitCountMsrWrite);
        DbgPrint("[HV-DEBUG] CR Access: %llu\n", g_ExitCountCrAccess);
        DbgPrint("[HV-DEBUG] Exception/NMI: %llu\n", g_ExitCountException);
        DbgPrint("[HV-DEBUG] External Interrupt: %llu\n", g_ExternalInterruptCount);
        DbgPrint("[HV-DEBUG] Interrupt Window: %llu\n", g_InterruptWindowExitCount);
        DbgPrint("[HV-DEBUG] EPT Violation: %llu\n", g_ExitCountEptViolation);
        DbgPrint("[HV-DEBUG] Other: %llu\n", g_ExitCountOther);
        DbgPrint("[HV-DEBUG] ================================================\n");
        
        totalExits = g_ExitCountCpuid + g_ExitCountVmcall + g_ExitCountMsrRead + 
                     g_ExitCountMsrWrite + g_ExitCountCrAccess + g_ExitCountException +
                     g_ExternalInterruptCount + g_InterruptWindowExitCount +
                     g_ExitCountEptViolation + g_ExitCountOther;
        
        if (g_ExternalInterruptCount > 1000 && g_InterruptWindowExitCount == 0) {
            DbgPrint("[HV-DEBUG] WARNING: High interrupt count with no window exits!\n");
        }
    }
    else if (cpuVendor == CPU_VENDOR_AMD) {
        // AMD SVM 统计
        SvmPrintDebugStats();
        vcpuData->IsVirtualized = FALSE;
        vcpuData->IsVmxOn = FALSE;
    }
}
