/*
 * HvVmcb.c - AMD SVM VMCB 配置和管理实现
 */

#include "HvVmcb.h"
#include "HvNpt.h"
#include "HvCompat.h"
#include "HvCpu.h"

// P122: 全 driver DbgPrint → GUI ring
#define HV_TRACE_THIS_CAT HV_TRACE_CAT_VM
#include "HvTrace.h"

// ==================== AMD SVM ASID 池 ====================
//
// 默认行为 (HV_ENABLE_SVM_HARDENING=0):
//   所有 vCPU 共享 ASID=1, 无池, 无 CPUID 探测; 行为与历史保持一致。
//
// HV_ENABLE_SVM_HARDENING=1 时:
//   启动期一次性 CPUID 80000008H.EBX 探测 MaxAsid (硬件典型 64..32768);
//   ASID 0 保留给 host, ASID 1..MaxAsid-1 进入位图自由分配;
//   每 vCPU 一个 L1 ASID, 嵌套 L2 也走同一池, 真正实现 TLB 隔离域。
//
// 位图容量 8192 (256 ASID groups × 32-bit), 足以覆盖所有已知 AMD CPU。

#define SVM_ASID_BITMAP_BITS    8192u
#define SVM_ASID_BITMAP_LONGS   (SVM_ASID_BITMAP_BITS / 32u)

static volatile LONG g_SvmAsidBitmap[SVM_ASID_BITMAP_LONGS] = { 0 };
static ULONG g_SvmMaxAsid = 0;       // 实际可用 ASID 上限 (CPUID 报告值, ≤ 8192)
static LONG g_SvmAsidInitialized = 0;

/*
 * 初始化 ASID 池 (幂等, 第一个调用方完成探测)
 */
static VOID SvmInitializeAsidPool(VOID)
{
    if (InterlockedCompareExchange(&g_SvmAsidInitialized, 1, 0) != 0) {
        return;  // 已初始化
    }

    ULONG maxFromHw = HvSvmGetMaxAsid();
    if (maxFromHw == 0 || maxFromHw > SVM_ASID_BITMAP_BITS) {
        maxFromHw = SVM_ASID_BITMAP_BITS;
    }
    g_SvmMaxAsid = maxFromHw;

    // ASID 0 保留给 host
    InterlockedOr((volatile LONG*)&g_SvmAsidBitmap[0], 1);

    DbgPrint("[SVM] ASID pool initialized: MaxAsid=%u (CPUID 80000008H.EBX)\n", g_SvmMaxAsid);
}

/*
 * 从池中分配一个 ASID; 失败返回 0 (调用方应回退到旧的 ASID=1 行为)
 */
static ULONG SvmAllocateAsid(VOID)
{
    SvmInitializeAsidPool();

    for (ULONG i = 0; i < SVM_ASID_BITMAP_LONGS; i++) {
        ULONG baseBit = i * 32u;
        if (baseBit >= g_SvmMaxAsid) break;

        LONG cur = g_SvmAsidBitmap[i];
        for (ULONG b = 0; b < 32u; b++) {
            ULONG asid = baseBit + b;
            if (asid == 0) continue;
            if (asid >= g_SvmMaxAsid) return 0;
            if (cur & (1L << b)) continue;
            LONG newVal = cur | (1L << b);
            if (InterlockedCompareExchange((volatile LONG*)&g_SvmAsidBitmap[i], newVal, cur) == cur) {
                return asid;
            }
            // CAS 失败重试本字
            cur = g_SvmAsidBitmap[i];
            b = (ULONG)-1;  // 重新扫描该 32-bit 字
        }
    }
    return 0;
}

/*
 * 释放 ASID 回池
 */
static VOID SvmReleaseAsid(ULONG Asid)
{
    if (Asid == 0 || Asid >= SVM_ASID_BITMAP_BITS) return;
    ULONG word = Asid / 32u;
    LONG mask = ~(1L << (Asid % 32u));
    InterlockedAnd((volatile LONG*)&g_SvmAsidBitmap[word], mask);
}

// 对外暴露的池接口 (供 HvNestedSvm.c L2 ASID 分配复用同池)
ULONG SvmPoolAllocateAsid(VOID)
{
#if HV_ENABLE_SVM_HARDENING
    return SvmAllocateAsid();
#else
    return 0;  // 默认禁用; 调用方应 fallback
#endif
}

VOID SvmPoolReleaseAsid(ULONG Asid)
{
#if HV_ENABLE_SVM_HARDENING
    SvmReleaseAsid(Asid);
#else
    UNREFERENCED_PARAMETER(Asid);
#endif
}

// ==================== 内部辅助函数 ====================

/*
 * 清理 SVM VCPU 资源
 */
static VOID SvmCleanupVcpuResources(PVCPU_DATA VcpuData)
{
#if HV_ENABLE_SVM_HARDENING
    if (VcpuData->Vmcb) {
        ULONG asid = VcpuData->Vmcb->ControlArea.GuestAsid;
        SvmReleaseAsid(asid);  // 释放 ASID 回池
    }
#endif
    if (VcpuData->Vmcb) {
        MmFreeContiguousMemory(VcpuData->Vmcb);
        VcpuData->Vmcb = NULL;
    }
    if (VcpuData->HostSaveArea) {
        MmFreeContiguousMemory(VcpuData->HostSaveArea);
        VcpuData->HostSaveArea = NULL;
    }
    if (VcpuData->MsrPermissionMap) {
        MmFreeContiguousMemory(VcpuData->MsrPermissionMap);
        VcpuData->MsrPermissionMap = NULL;
    }
    if (VcpuData->VmExitStack) {
        ExFreePoolWithTag(VcpuData->VmExitStack, 'SVMS');
        VcpuData->VmExitStack = NULL;
    }
}

// ==================== SVM 初始化 ====================

/*
 * 在当前CPU上启用SVM
 */
NTSTATUS SvmEnableOnCpu(PVCPU_DATA VcpuData)
{
    PHYSICAL_ADDRESS maxPhysAddr = { .QuadPart = -1LL };
    
    DbgPrint("[SVM] CPU %d: Enabling SVM...\n", VcpuData->ProcessorNumber);
    
    // 设置 EFER.SVME
    SvmAdjustControlRegisters();
    
    // 验证 EFER.SVME 已设置
    ULONG64 efer = __readmsr(MSR_IA32_EFER);
    if (!(efer & EFER_SVME)) {
        DbgPrint("[SVM] CPU %d: Failed to enable EFER.SVME\n", VcpuData->ProcessorNumber);
        return STATUS_UNSUCCESSFUL;
    }
    
    // 分配 Host Save Area (4KB 对齐)
    VcpuData->HostSaveArea = MmAllocateContiguousMemory(PAGE_SIZE, maxPhysAddr);
    if (!VcpuData->HostSaveArea) {
        DbgPrint("[SVM] CPU %d: Failed to allocate Host Save Area\n", VcpuData->ProcessorNumber);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(VcpuData->HostSaveArea, PAGE_SIZE);
    VcpuData->HostSaveAreaPhysical = MmGetPhysicalAddress(VcpuData->HostSaveArea);
    
    // 设置 VM_HSAVE_PA MSR
    __writemsr(MSR_AMD_VM_HSAVE_PA, VcpuData->HostSaveAreaPhysical.QuadPart);
    DbgPrint("[SVM] CPU %d: Host Save Area at PA 0x%llX\n", 
             VcpuData->ProcessorNumber, VcpuData->HostSaveAreaPhysical.QuadPart);
    
    // 分配 VMCB (4KB 对齐)
    VcpuData->Vmcb = (PVMCB)MmAllocateContiguousMemory(PAGE_SIZE, maxPhysAddr);
    if (!VcpuData->Vmcb) {
        DbgPrint("[SVM] CPU %d: Failed to allocate VMCB\n", VcpuData->ProcessorNumber);
        SvmCleanupVcpuResources(VcpuData);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(VcpuData->Vmcb, PAGE_SIZE);
    VcpuData->VmcbPhysical = MmGetPhysicalAddress(VcpuData->Vmcb);
    DbgPrint("[SVM] CPU %d: VMCB at PA 0x%llX\n", 
             VcpuData->ProcessorNumber, VcpuData->VmcbPhysical.QuadPart);
    
    // 分配 MSR 权限位图 (2 页 = 8KB)
    VcpuData->MsrPermissionMap = MmAllocateContiguousMemory(PAGE_SIZE * 2, maxPhysAddr);
    if (!VcpuData->MsrPermissionMap) {
        DbgPrint("[SVM] CPU %d: Failed to allocate MSR Permission Map\n", VcpuData->ProcessorNumber);
        SvmCleanupVcpuResources(VcpuData);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    // 初始化为全1 (不拦截任何MSR)，稍后会设置特定拦截
    RtlFillMemory(VcpuData->MsrPermissionMap, PAGE_SIZE * 2, 0);
    VcpuData->MsrPermissionMapPhysical = MmGetPhysicalAddress(VcpuData->MsrPermissionMap);
    
    // 分配 VM Exit 栈
    VcpuData->VmExitStack = HvAllocateNonPagedZeroed(0x10000, 'SVMS');
    if (!VcpuData->VmExitStack) {
        DbgPrint("[SVM] CPU %d: Failed to allocate VM Exit stack\n", VcpuData->ProcessorNumber);
        SvmCleanupVcpuResources(VcpuData);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    DbgPrint("[SVM] CPU %d: SVM enabled successfully\n", VcpuData->ProcessorNumber);
    return STATUS_SUCCESS;
}

/*
 * 配置 VMCB
 */
NTSTATUS SvmSetupVmcb(PVCPU_DATA VcpuData)
{
    NTSTATUS status;
    
    DbgPrint("[SVM] CPU %d: Setting up VMCB...\n", VcpuData->ProcessorNumber);
    
    // 配置控制区
    status = SvmSetupVmcbControlArea(VcpuData);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    
    // 配置状态保存区
    status = SvmSetupVmcbStateSave(VcpuData);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    
    // 配置 MSR 权限位图
    status = SvmSetupMsrPermissionMap(VcpuData);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    
    DbgPrint("[SVM] CPU %d: VMCB setup complete\n", VcpuData->ProcessorNumber);
    return STATUS_SUCCESS;
}

/*
 * 配置 VMCB 控制区
 */
NTSTATUS SvmSetupVmcbControlArea(PVCPU_DATA VcpuData)
{
    PVMCB_CONTROL_AREA control = &VcpuData->Vmcb->ControlArea;
    
    // 清零控制区
    RtlZeroMemory(control, sizeof(VMCB_CONTROL_AREA));
    
    // 设置拦截 - InterceptMisc1
    control->InterceptMisc1 = 
        SVM_INTERCEPT_CPUID |           // 拦截 CPUID
        SVM_INTERCEPT_MSR |             // 拦截 MSR 访问
        SVM_INTERCEPT_SHUTDOWN;         // 拦截 Shutdown
    
    // 设置拦截 - InterceptMisc2
    control->InterceptMisc2 = 
        SVM_INTERCEPT_VMRUN |           // 拦截 VMRUN
        SVM_INTERCEPT_VMMCALL |         // 拦截 VMMCALL
        SVM_INTERCEPT_VMLOAD |          // 拦截 VMLOAD
        SVM_INTERCEPT_VMSAVE |          // 拦截 VMSAVE
        SVM_INTERCEPT_STGI |            // 拦截 STGI
        SVM_INTERCEPT_CLGI |            // 拦截 CLGI
        SVM_INTERCEPT_XSETBV;           // 拦截 XSETBV
    
    // 设置 Guest ASID (必须非零)
#if HV_ENABLE_SVM_HARDENING
    {
        ULONG allocAsid = SvmAllocateAsid();
        control->GuestAsid = (allocAsid != 0) ? allocAsid : 1;  // 池耗尽时 fallback
    }
#else
    control->GuestAsid = 1;  // 历史默认值, 所有 vCPU 共享; 启用 HV_ENABLE_SVM_HARDENING 切换为 per-vCPU
#endif
    
    // 设置 MSR 权限位图地址
    control->MsrpmBasePa = VcpuData->MsrPermissionMapPhysical.QuadPart;
    
    // NPT 配置
    if (VcpuData->NptTables) {
        control->NpEnable = 1;                                    // 启用 NPT
        control->NCr3 = VcpuData->NptTables->Pml4Physical.QuadPart;  // NPT CR3
        DbgPrint("[SVM] CPU %d: NPT enabled, NCR3=0x%llX\n", 
                 VcpuData->ProcessorNumber, control->NCr3);
    } else {
        control->NpEnable = 0;
        DbgPrint("[SVM] CPU %d: NPT disabled\n", VcpuData->ProcessorNumber);
    }
    
    // TLB 控制 - 首次运行时刷新 TLB
    control->TlbControl = SVM_TLB_CONTROL_FLUSH_ALL;
    
    // 虚拟中断配置
    // 虚拟中断控制: bit 24 = V_INTR_MASKING
    control->VIntr = (1ULL << 24);  // 启用虚拟中断掩码
    
    DbgPrint("[SVM] CPU %d: Control Area configured\n", VcpuData->ProcessorNumber);
    DbgPrint("[SVM]   InterceptMisc1: 0x%llX\n", control->InterceptMisc1);
    DbgPrint("[SVM]   InterceptMisc2: 0x%llX\n", control->InterceptMisc2);
    DbgPrint("[SVM]   GuestAsid: %d\n", control->GuestAsid);
    
    return STATUS_SUCCESS;
}

/*
 * 配置 VMCB 状态保存区
 */
NTSTATUS SvmSetupVmcbStateSave(PVCPU_DATA VcpuData)
{
    PVMCB_STATE_SAVE_AREA state = &VcpuData->Vmcb->StateSaveArea;
    DESCRIPTOR_TABLE_REGISTER gdtr, idtr;
    
    // 清零状态保存区
    RtlZeroMemory(state, sizeof(VMCB_STATE_SAVE_AREA));
    
    // 获取 GDTR 和 IDTR
    _sgdt(&gdtr);
    __sidt(&idtr);
    
    USHORT gdt_limit = *(USHORT*)&gdtr.Data[0];
    ULONG64 gdt_base = *(ULONG64*)&gdtr.Data[2];
    USHORT idt_limit = *(USHORT*)&idtr.Data[0];
    ULONG64 idt_base = *(ULONG64*)&idtr.Data[2];
    
    // 段寄存器 - CS
    state->Cs.Selector = __readcs();
    state->Cs.Attributes = 0x029B;  // 64-bit code segment
    state->Cs.Limit = 0xFFFFFFFF;
    state->Cs.Base = 0;
    
    // 段寄存器 - SS
    state->Ss.Selector = __readss();
    state->Ss.Attributes = 0x0093;  // 64-bit data segment
    state->Ss.Limit = 0xFFFFFFFF;
    state->Ss.Base = 0;
    
    // 段寄存器 - DS
    state->Ds.Selector = __readds();
    state->Ds.Attributes = 0x0093;
    state->Ds.Limit = 0xFFFFFFFF;
    state->Ds.Base = 0;
    
    // 段寄存器 - ES
    state->Es.Selector = __reades();
    state->Es.Attributes = 0x0093;
    state->Es.Limit = 0xFFFFFFFF;
    state->Es.Base = 0;
    
    // 段寄存器 - FS
    state->Fs.Selector = __readfs();
    state->Fs.Attributes = 0x0093;
    state->Fs.Limit = 0xFFFFFFFF;
    state->Fs.Base = __readmsr(MSR_IA32_FS_BASE);
    
    // 段寄存器 - GS
    state->Gs.Selector = __readgs();
    state->Gs.Attributes = 0x0093;
    state->Gs.Limit = 0xFFFFFFFF;
    state->Gs.Base = __readmsr(MSR_IA32_GS_BASE);
    
    // GDTR
    state->Gdtr.Limit = gdt_limit;
    state->Gdtr.Base = gdt_base;
    
    // IDTR
    state->Idtr.Limit = idt_limit;
    state->Idtr.Base = idt_base;
    
    // LDTR (通常为空)
    state->Ldtr.Selector = __readldtr();
    state->Ldtr.Attributes = 0x0082;  // LDT
    state->Ldtr.Limit = 0;
    state->Ldtr.Base = 0;
    
    // TR
    state->Tr.Selector = __readtr();
    state->Tr.Attributes = 0x008B;  // 64-bit TSS (Busy)
    // 需要从 GDT 获取 TR base 和 limit
    {
        SEGMENT_SELECTOR trSel = { 0 };
        HvGetSegmentDescriptor(&trSel, __readtr(), (PUCHAR)gdt_base);
        state->Tr.Base = trSel.Base;
        state->Tr.Limit = trSel.Limit;
    }
    
    // 控制寄存器
    state->Cr0 = __readcr0();
    state->Cr2 = __readcr2();
    state->Cr3 = __readcr3();
    state->Cr4 = __readcr4();
    
    // EFER
    state->Efer = __readmsr(MSR_IA32_EFER);
    
    // CPL
    state->Cpl = 0;  // Ring 0
    
    // 调试寄存器
    state->Dr6 = __readdr(6);
    state->Dr7 = __readdr(7);
    
    // RFLAGS (确保 IF=1)
    state->Rflags = __readeflags() | 0x200;
    
    // RIP 和 RSP 将在 VMRUN 之前由汇编代码设置
    state->Rip = 0;
    state->Rsp = 0;
    state->Rax = 0;
    
    // 系统 MSR
    state->Star = __readmsr(0xC0000081);        // STAR
    state->LStar = __readmsr(0xC0000082);       // LSTAR
    state->CStar = __readmsr(0xC0000083);       // CSTAR
    state->SfMask = __readmsr(0xC0000084);      // SFMASK
    state->KernelGsBase = __readmsr(0xC0000102); // KernelGSBase
    
    // SYSENTER MSR
    state->SysenterCs = __readmsr(MSR_IA32_SYSENTER_CS);
    state->SysenterEsp = __readmsr(MSR_IA32_SYSENTER_ESP);
    state->SysenterEip = __readmsr(MSR_IA32_SYSENTER_EIP);
    
    // PAT
    state->GPat = __readmsr(MSR_IA32_PAT);
    
    DbgPrint("[SVM] CPU %d: State Save Area configured\n", VcpuData->ProcessorNumber);
    DbgPrint("[SVM]   CR0: 0x%llX, CR3: 0x%llX, CR4: 0x%llX\n", 
             state->Cr0, state->Cr3, state->Cr4);
    DbgPrint("[SVM]   EFER: 0x%llX\n", state->Efer);
    
    return STATUS_SUCCESS;
}

/*
 * 内部 helper：在 SVM MSR 权限位图上设置/清除某 MSR 的拦截位
 * bit 0 = 拦截读，bit 1 = 拦截写
 */
static VOID SvmBitmapSetIntercept(PUCHAR Bitmap, ULONG32 Msr, BOOLEAN Read, BOOLEAN Write)
{
    ULONG block;
    ULONG offset;

    if (Msr <= 0x00001FFFu) {
        block = 0;
        offset = Msr;
    } else if (Msr >= 0xC0000000u && Msr <= 0xC0001FFFu) {
        block = 1;
        offset = Msr - 0xC0000000u;
    } else if (Msr >= 0xC0010000u && Msr <= 0xC0011FFFu) {
        block = 2;
        offset = Msr - 0xC0010000u;
    } else {
        // 超出位图覆盖范围，AMD 文档：未覆盖的 MSR 默认拦截读写（行为同 bit=1）
        return;
    }

    ULONG byteOffset = block * 0x800u + (offset / 4u);
    ULONG bitInByte = (offset % 4u) * 2u;

    if (Read)  Bitmap[byteOffset] |= (UCHAR)(1u << bitInByte);
    if (Write) Bitmap[byteOffset] |= (UCHAR)(1u << (bitInByte + 1u));
}

/*
 * 配置 MSR 权限位图
 *
 * MSR Permission Map 布局 (8KB = 2页):
 * - 第 0-2KB: 拦截 MSR 0x00000000 - 0x00001FFF
 * - 第 2-4KB: 拦截 MSR 0xC0000000 - 0xC0001FFF
 * - 第 4-6KB: 拦截 MSR 0xC0010000 - 0xC0011FFF
 * - 第 6-8KB: 保留
 *
 * 每个 MSR 用 2 位表示: bit 0 = 拦截读, bit 1 = 拦截写
 */
NTSTATUS SvmSetupMsrPermissionMap(PVCPU_DATA VcpuData)
{
    PUCHAR bitmap = (PUCHAR)VcpuData->MsrPermissionMap;

    // 默认初始化为 0（即不拦截）后，下面挑出真正需要拦截的 MSR
    // 拦截目的：1) 反检测 — 隐藏 SVME/HSAVE_PA 等暴露 SVM 状态的 MSR
    //          2) 稳定性 — 防止 Guest 把 EFER.SVME 清掉破坏 VMRUN

    // EFER 包含 SVME 位（bit 12），Guest 读到会暴露 SVM 已启用
    SvmBitmapSetIntercept(bitmap, MSR_IA32_EFER,           TRUE,  TRUE);

    // AMD SVM 相关 MSR — Guest 不该看到/修改
    SvmBitmapSetIntercept(bitmap, MSR_AMD_VM_CR,           TRUE,  TRUE);
    SvmBitmapSetIntercept(bitmap, MSR_AMD_VM_HSAVE_PA,     TRUE,  TRUE);

    // Intel VMX feature control（AMD 平台理论上不存在，但有些 Guest OS 会读，伪造 0）
    SvmBitmapSetIntercept(bitmap, MSR_IA32_FEATURE_CONTROL, TRUE, FALSE);

    DbgPrint("[SVM] CPU %d: MSR Permission Map configured (EFER/VM_CR/HSAVE_PA intercepted)\n",
             VcpuData->ProcessorNumber);

    return STATUS_SUCCESS;
}

/*
 * 启动虚拟机
 */
NTSTATUS SvmLaunchVm(PVCPU_DATA VcpuData)
{
    int result;

    VcpuData->IsVirtualized = FALSE;

    DbgPrint("[SVM] CPU %d: Launching VM...\n", VcpuData->ProcessorNumber);

    if (!VcpuData->Vmcb) {
        DbgPrint("[SVM] CPU %d: ERROR - VMCB is NULL\n", VcpuData->ProcessorNumber);
        return STATUS_INVALID_PARAMETER;
    }

    result = AsmSvmLaunch(VcpuData);
    
    if (result == 0) {
        VcpuData->IsVirtualized = TRUE;
        DbgPrint("[SVM] CPU %d: *** VIRTUALIZATION ACTIVE ***\n", 
                 VcpuData->ProcessorNumber);
        return STATUS_SUCCESS;
    }
    
    // VMRUN 失败
    VcpuData->IsVirtualized = FALSE;
    DbgPrint("[SVM] CPU %d: VMRUN failed with result=0x%X\n", 
             VcpuData->ProcessorNumber, result);
    
    // 检查退出码
    if (VcpuData->Vmcb) {
        DbgPrint("[SVM] CPU %d: Exit Code: 0x%llX\n", 
                 VcpuData->ProcessorNumber, 
                 VcpuData->Vmcb->ControlArea.ExitCode);
    }
    
    return STATUS_UNSUCCESSFUL;
}

/*
 * 清理 SVM 资源
 */
VOID SvmCleanup(PVCPU_DATA VcpuData)
{
    // 清理 NPT
    if (VcpuData->NptTables) {
        SvmCleanupNpt(VcpuData);
    }
    
    // 清理其他资源
    SvmCleanupVcpuResources(VcpuData);
    
    DbgPrint("[SVM] CPU %d: Cleanup complete\n", VcpuData->ProcessorNumber);
}

// ==================== VMCB 操作函数 ====================

/*
 * 设置 CR 拦截
 */
VOID SvmSetInterceptCr(PVCPU_DATA VcpuData, ULONG CrNumber, BOOLEAN Read, BOOLEAN Write)
{
    if (CrNumber > 15) return;
    
    if (Read) {
        VcpuData->Vmcb->ControlArea.InterceptCrRead |= (1 << CrNumber);
    }
    if (Write) {
        VcpuData->Vmcb->ControlArea.InterceptCrWrite |= (1 << CrNumber);
    }
}

/*
 * 设置 DR 拦截
 */
VOID SvmSetInterceptDr(PVCPU_DATA VcpuData, ULONG DrNumber, BOOLEAN Read, BOOLEAN Write)
{
    if (DrNumber > 15) return;
    
    if (Read) {
        VcpuData->Vmcb->ControlArea.InterceptDrRead |= (1 << DrNumber);
    }
    if (Write) {
        VcpuData->Vmcb->ControlArea.InterceptDrWrite |= (1 << DrNumber);
    }
}

/*
 * 设置异常拦截
 */
VOID SvmSetInterceptException(PVCPU_DATA VcpuData, ULONG ExceptionVector)
{
    if (ExceptionVector > 31) return;
    VcpuData->Vmcb->ControlArea.InterceptExceptions |= (1 << ExceptionVector);
}

/*
 * 设置 InterceptMisc1 标志
 */
VOID SvmSetInterceptMisc1(PVCPU_DATA VcpuData, ULONG64 Flags)
{
    VcpuData->Vmcb->ControlArea.InterceptMisc1 |= Flags;
}

/*
 * 设置 InterceptMisc2 标志
 */
VOID SvmSetInterceptMisc2(PVCPU_DATA VcpuData, ULONG64 Flags)
{
    VcpuData->Vmcb->ControlArea.InterceptMisc2 |= Flags;
}

// ==================== vGIF 中断门控 (HV_ENABLE_SVM_HARDENING) ====================
//
// AMD SVM: STGI 设 GIF=1, CLGI 设 GIF=0. GIF=0 时硬件不递送任何中断.
// 历史代码 g_VirtualGif (HvNestedSvm.c:21) 只记录状态, 没有任何注入路径
// 检查它, 即使 L1 调 CLGI 关中断, L0 仍会忽略门控直接写 EventInj.
// 修复: 拦截所有 EventInj 写入, vGIF=0 时入队 per-CPU pending, STGI 时 flush.

#if HV_ENABLE_SVM_HARDENING

typedef struct _SVM_PENDING_EVENT {
    ULONG  Vector;
    ULONG  Type;
    ULONG  ErrorCode;
    BOOLEAN HasErrorCode;
    BOOLEAN Valid;
} SVM_PENDING_EVENT;

#define SVM_MAX_PENDING_PER_CPU 8
#define SVM_MAX_CPU             256
static SVM_PENDING_EVENT g_SvmPendingQueue[SVM_MAX_CPU][SVM_MAX_PENDING_PER_CPU];
static KSPIN_LOCK g_SvmPendingLock;
static volatile LONG g_SvmPendingLockInit = 0;

// vGIF 状态由 HvNestedSvm.c 维护; 这里前向声明 getter
extern BOOLEAN NestedSvmGetVirtualGif(PVCPU_DATA VcpuData);

static VOID SvmPendingLockInit(VOID)
{
    if (InterlockedCompareExchange(&g_SvmPendingLockInit, 1, 0) == 0) {
        KeInitializeSpinLock(&g_SvmPendingLock);
    }
}

// 入队一个 pending event
static VOID SvmEnqueuePendingEvent(PVCPU_DATA VcpuData, UCHAR Vector, UCHAR Type,
                                    BOOLEAN HasErrorCode, ULONG ErrorCode)
{
    KIRQL oldIrql;
    ULONG cpu;
    ULONG i;

    if (!VcpuData) return;
    cpu = VcpuData->ProcessorNumber;
    if (cpu >= SVM_MAX_CPU) return;

    SvmPendingLockInit();

    KeAcquireSpinLock(&g_SvmPendingLock, &oldIrql);
    for (i = 0; i < SVM_MAX_PENDING_PER_CPU; i++) {
        if (!g_SvmPendingQueue[cpu][i].Valid) {
            g_SvmPendingQueue[cpu][i].Vector = Vector;
            g_SvmPendingQueue[cpu][i].Type = Type;
            g_SvmPendingQueue[cpu][i].ErrorCode = ErrorCode;
            g_SvmPendingQueue[cpu][i].HasErrorCode = HasErrorCode;
            g_SvmPendingQueue[cpu][i].Valid = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&g_SvmPendingLock, oldIrql);
    // 队列满则丢弃 (与硬件 GIF=0 时收到突发中断行为一致)
}

// flush per-CPU pending 队列到 VMCB.EventInj
// 调用条件: vGIF 刚被设为 TRUE (STGI handler 调用)
VOID SvmFlushPendingEvents(PVCPU_DATA VcpuData)
{
    KIRQL oldIrql;
    ULONG cpu;
    ULONG i;

    if (!VcpuData) return;
    cpu = VcpuData->ProcessorNumber;
    if (cpu >= SVM_MAX_CPU) return;

    SvmPendingLockInit();

    KeAcquireSpinLock(&g_SvmPendingLock, &oldIrql);
    for (i = 0; i < SVM_MAX_PENDING_PER_CPU; i++) {
        if (g_SvmPendingQueue[cpu][i].Valid) {
            SVM_EVENT_INJECTION event = { 0 };
            event.Vector = (UCHAR)g_SvmPendingQueue[cpu][i].Vector;
            event.Type = (UCHAR)g_SvmPendingQueue[cpu][i].Type;
            event.ErrorCodeValid = g_SvmPendingQueue[cpu][i].HasErrorCode ? 1 : 0;
            event.Valid = 1;
            event.ErrorCode = g_SvmPendingQueue[cpu][i].ErrorCode;
            VcpuData->Vmcb->ControlArea.EventInj = event.Value;
            g_SvmPendingQueue[cpu][i].Valid = FALSE;
            break;  // 每次 VM-Entry 只能注入一个; 剩余等下次 STGI
        }
    }
    KeReleaseSpinLock(&g_SvmPendingLock, oldIrql);
}

#endif // HV_ENABLE_SVM_HARDENING

/*
 * 注入事件 (统一入口)
 *
 * HV_ENABLE_SVM_HARDENING=1: 检查 vGIF, 若 GIF=0 入队挂起,
 *                            STGI 时由 SvmFlushPendingEvents 投递.
 * HV_ENABLE_SVM_HARDENING=0: 历史行为, 直接写 EventInj (忽略 vGIF).
 */
VOID SvmInjectEvent(PVCPU_DATA VcpuData, UCHAR Vector, UCHAR Type, BOOLEAN HasErrorCode, ULONG ErrorCode)
{
    SVM_EVENT_INJECTION event = { 0 };

#if HV_ENABLE_SVM_HARDENING
    // vGIF 门控: 只对硬件中断 (INTR/NMI) 门控, 异常 (#PF/#GP 等) 不受 GIF 影响
    if ((Type == SVM_EVENT_TYPE_INTR || Type == SVM_EVENT_TYPE_NMI) &&
        !NestedSvmGetVirtualGif(VcpuData)) {
        SvmEnqueuePendingEvent(VcpuData, Vector, Type, HasErrorCode, ErrorCode);
        return;
    }
#endif

    event.Vector = Vector;
    event.Type = Type;
    event.ErrorCodeValid = HasErrorCode ? 1 : 0;
    event.Valid = 1;
    event.ErrorCode = ErrorCode;

    VcpuData->Vmcb->ControlArea.EventInj = event.Value;
}

/*
 * 注入中断
 */
VOID SvmInjectInterrupt(PVCPU_DATA VcpuData, UCHAR Vector)
{
    SvmInjectEvent(VcpuData, Vector, SVM_EVENT_TYPE_INTR, FALSE, 0);
}

/*
 * 注入异常
 */
VOID SvmInjectException(PVCPU_DATA VcpuData, UCHAR Vector, BOOLEAN HasErrorCode, ULONG ErrorCode)
{
    SvmInjectEvent(VcpuData, Vector, SVM_EVENT_TYPE_EXCEPTION, HasErrorCode, ErrorCode);
}

/*
 * TLB 刷新
 */
VOID SvmFlushTlb(PVCPU_DATA VcpuData, ULONG FlushType)
{
    VcpuData->Vmcb->ControlArea.TlbControl = FlushType;
}
