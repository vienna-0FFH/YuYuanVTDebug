/*
 * HvNestedSvm.c - AMD SVM 嵌套虚拟化完整实现
 * 
 * 实现完整的 AMD SVM 嵌套虚拟化支持
 */

#include "HvNestedSvm.h"
#include "HvNested.h"
#include "HvNpt.h"
#include "HvNestedNpt.h"
#include "NptHook.h"
#include "HvVmcb.h"
#include "HvCompat.h"

// P122: 全 driver DbgPrint → GUI ring
#define HV_TRACE_THIS_CAT HV_TRACE_CAT_NESTED
#include "HvTrace.h"

// ==================== 全局变量 ====================

volatile LONG64 g_NestedSvmVmrunCount = 0;
volatile LONG64 g_NestedSvmVmExitCount = 0;
volatile LONG64 g_NestedSvmL2ExitCount = 0;

// 虚拟 GIF 状态（每 CPU）
#define MAX_NESTED_SVM_CPU 256
static volatile BOOLEAN g_VirtualGif[MAX_NESTED_SVM_CPU] = { 0 };

// ==================== 内部辅助函数 ====================

/*
 * 从物理地址映射 VMCB
 */
static PVMCB NestedSvmMapVmcb(ULONG64 PhysicalAddress)
{
    PHYSICAL_ADDRESS pa;
    pa.QuadPart = PhysicalAddress & ~0xFFFULL;
    return (PVMCB)MmMapIoSpace(pa, PAGE_SIZE, MmNonCached);
}

/*
 * 取消映射 VMCB
 */
static VOID NestedSvmUnmapVmcb(PVMCB Vmcb)
{
    if (Vmcb) {
        MmUnmapIoSpace(Vmcb, PAGE_SIZE);
    }
}

/*
 * 翻译 GPA 到 HPA（使用 L0 NPT）
 */
static BOOLEAN NestedSvmTranslateGpaToHpa(PVCPU_DATA VcpuData, ULONG64 Gpa, PULONG64 Hpa)
{
    PNPT_TABLES nptTables;
    ULONG pml4Index, pdptIndex, pdIndex;
    ULONG64 pde;
    
    // 如果没有 NPT，直通映射
    if (!VcpuData->NptTables) {
        *Hpa = Gpa;
        return TRUE;
    }
    
    nptTables = VcpuData->NptTables;
    
    // 计算索引
    pml4Index = (Gpa >> 39) & 0x1FF;
    pdptIndex = (Gpa >> 30) & 0x1FF;
    pdIndex = (Gpa >> 21) & 0x1FF;
    
    // 检查 PML4E
    if (!(nptTables->Pml4[pml4Index].Value & 0x1)) {
        return FALSE;
    }
    
    // 检查 PDPTE
    if (!(nptTables->Pdpt[pdptIndex].Value & 0x1)) {
        return FALSE;
    }
    
    // 检查 PDE
    pde = nptTables->Pd[pdptIndex][pdIndex].Value;
    if (!(pde & 0x1)) {
        return FALSE;
    }
    
    // 假设使用 2MB 大页
    if (pde & 0x80) {
        *Hpa = (pde & 0x000FFFFFFFE00000ULL) | (Gpa & 0x1FFFFF);
        return TRUE;
    }
    
    // 4KB 页情况（需要查找分割页表）
    // 简化处理：返回 2MB 对齐的地址
    *Hpa = (pde & 0x000FFFFFFFE00000ULL) | (Gpa & 0x1FFFFF);
    return TRUE;
}

// ==================== 初始化和清理 ====================

NTSTATUS NestedSvmInitialize(VOID)
{
    RtlZeroMemory((PVOID)g_VirtualGif, sizeof(g_VirtualGif));
    
    DbgPrint("[HV-NESTED-SVM] Nested SVM support initialized\n");
    return STATUS_SUCCESS;
}

VOID NestedSvmCleanup(VOID)
{
    DbgPrint("[HV-NESTED-SVM] Nested SVM support cleaned up\n");
    NestedSvmPrintStats();
}

VOID NestedSvmInitializeState(PVCPU_DATA VcpuData)
{
    PNESTED_SVM_STATE nested;
    
    if (!VcpuData) {
        return;
    }
    
    nested = &VcpuData->NestedSvm;
    RtlZeroMemory(nested, sizeof(NESTED_SVM_STATE));
    
    nested->SvmEnabled = FALSE;
    nested->InGuestMode = FALSE;
    nested->VmcbGpa = 0;
    nested->HostSaveGpa = 0;
    
    // 分配 VMCB12 缓存
    nested->Vmcb12 = MmAllocateContiguousMemory(PAGE_SIZE, (PHYSICAL_ADDRESS){ .QuadPart = ~0ULL });
    if (nested->Vmcb12) {
        nested->Vmcb12Physical.QuadPart = MmGetPhysicalAddress(nested->Vmcb12).QuadPart;
        RtlZeroMemory(nested->Vmcb12, PAGE_SIZE);
    }
    
    VcpuData->IsInL2 = FALSE;
}

VOID NestedSvmCleanupState(PVCPU_DATA VcpuData)
{
    PNESTED_SVM_STATE nested;
    PNESTED_NPT_CONTEXT nptContext;
    
    if (!VcpuData) {
        return;
    }
    
    nested = &VcpuData->NestedSvm;
    
    if (nested->Vmcb12) {
        MmFreeContiguousMemory(nested->Vmcb12);
        nested->Vmcb12 = NULL;
    }
    
    if (nested->NestedNptTables) {
        // 释放嵌套 NPT 上下文
        nptContext = NestedNptFindContext(nested->L1NCr3);
        if (nptContext) {
            NestedNptDestroyContext(nptContext);
        }
        nested->NestedNptTables = NULL;
    }

#if HV_ENABLE_SVM_HARDENING
    // 释放合并的 MSRPM/IOPM
    if (nested->MergedMsrpm) {
        MmFreeContiguousMemory(nested->MergedMsrpm);
        nested->MergedMsrpm = NULL;
        nested->MergedMsrpmPhysical.QuadPart = 0;
    }
    if (nested->MergedIopm) {
        MmFreeContiguousMemory(nested->MergedIopm);
        nested->MergedIopm = NULL;
        nested->MergedIopmPhysical.QuadPart = 0;
    }
    // L2 ASID 归还池
    if (nested->L2Asid != 0) {
        SvmPoolReleaseAsid(nested->L2Asid);
        nested->L2Asid = 0;
    }
#endif

    nested->L1NCr3 = 0;
    nested->L1NptEnabled = FALSE;
}

// ==================== VMCB 操作 ====================

BOOLEAN NestedSvmReadVmcb12(
    PVCPU_DATA VcpuData,
    ULONG64 VmcbGpa,
    PNESTED_VMCB_CACHE Cache)
{
    PVMCB vmcb;
    ULONG64 vmcbHpa;
    
    if (!NestedSvmTranslateGpaToHpa(VcpuData, VmcbGpa, &vmcbHpa)) {
        return FALSE;
    }
    
    vmcb = NestedSvmMapVmcb(vmcbHpa);
    if (!vmcb) {
        return FALSE;
    }
    
    // 读取控制区
    Cache->InterceptCrRead = vmcb->ControlArea.InterceptCrRead;
    Cache->InterceptCrWrite = vmcb->ControlArea.InterceptCrWrite;
    Cache->InterceptDrRead = vmcb->ControlArea.InterceptDrRead;
    Cache->InterceptDrWrite = vmcb->ControlArea.InterceptDrWrite;
    Cache->InterceptExceptions = vmcb->ControlArea.InterceptExceptions;
    Cache->InterceptMisc1 = vmcb->ControlArea.InterceptMisc1;
    Cache->InterceptMisc2 = vmcb->ControlArea.InterceptMisc2;
    Cache->IopmBasePa = vmcb->ControlArea.IopmBasePa;
    Cache->MsrpmBasePa = vmcb->ControlArea.MsrpmBasePa;
    Cache->TscOffset = vmcb->ControlArea.TscOffset;
    Cache->GuestAsid = vmcb->ControlArea.GuestAsid;
    Cache->TlbControl = vmcb->ControlArea.TlbControl;
    Cache->VIntr = vmcb->ControlArea.VIntr;
    Cache->InterruptShadow = vmcb->ControlArea.InterruptShadow;
    Cache->NpEnable = vmcb->ControlArea.NpEnable;
    Cache->NCr3 = vmcb->ControlArea.NCr3;
    Cache->EventInj = vmcb->ControlArea.EventInj;
    
    // 读取 Guest 状态
    Cache->GuestCr0 = vmcb->StateSaveArea.Cr0;
    Cache->GuestCr2 = vmcb->StateSaveArea.Cr2;
    Cache->GuestCr3 = vmcb->StateSaveArea.Cr3;
    Cache->GuestCr4 = vmcb->StateSaveArea.Cr4;
    Cache->GuestDr6 = vmcb->StateSaveArea.Dr6;
    Cache->GuestDr7 = vmcb->StateSaveArea.Dr7;
    Cache->GuestRip = vmcb->StateSaveArea.Rip;
    Cache->GuestRsp = vmcb->StateSaveArea.Rsp;
    Cache->GuestRax = vmcb->StateSaveArea.Rax;
    Cache->GuestRflags = vmcb->StateSaveArea.Rflags;
    Cache->GuestEfer = vmcb->StateSaveArea.Efer;
    
    // 读取段寄存器
    Cache->Es = vmcb->StateSaveArea.Es;
    Cache->Cs = vmcb->StateSaveArea.Cs;
    Cache->Ss = vmcb->StateSaveArea.Ss;
    Cache->Ds = vmcb->StateSaveArea.Ds;
    Cache->Fs = vmcb->StateSaveArea.Fs;
    Cache->Gs = vmcb->StateSaveArea.Gs;
    Cache->Gdtr = vmcb->StateSaveArea.Gdtr;
    Cache->Ldtr = vmcb->StateSaveArea.Ldtr;
    Cache->Idtr = vmcb->StateSaveArea.Idtr;
    Cache->Tr = vmcb->StateSaveArea.Tr;
    
    // 读取 SYSENTER/SYSCALL
    Cache->Star = vmcb->StateSaveArea.Star;
    Cache->LStar = vmcb->StateSaveArea.LStar;
    Cache->CStar = vmcb->StateSaveArea.CStar;
    Cache->SfMask = vmcb->StateSaveArea.SfMask;
    Cache->KernelGsBase = vmcb->StateSaveArea.KernelGsBase;
    Cache->SysenterCs = vmcb->StateSaveArea.SysenterCs;
    Cache->SysenterEsp = vmcb->StateSaveArea.SysenterEsp;
    Cache->SysenterEip = vmcb->StateSaveArea.SysenterEip;
    
    // 读取其他
    Cache->GPat = vmcb->StateSaveArea.GPat;
    Cache->DbgCtl = vmcb->StateSaveArea.DbgCtl;
    Cache->Cpl = vmcb->StateSaveArea.Cpl;
    
    Cache->Valid = TRUE;
    
    NestedSvmUnmapVmcb(vmcb);
    return TRUE;
}

BOOLEAN NestedSvmWriteVmcb12(
    PVCPU_DATA VcpuData,
    ULONG64 VmcbGpa,
    PNESTED_VMCB_CACHE Cache)
{
    PVMCB vmcb;
    ULONG64 vmcbHpa;
    
    if (!Cache->Valid) {
        return FALSE;
    }
    
    if (!NestedSvmTranslateGpaToHpa(VcpuData, VmcbGpa, &vmcbHpa)) {
        return FALSE;
    }
    
    vmcb = NestedSvmMapVmcb(vmcbHpa);
    if (!vmcb) {
        return FALSE;
    }
    
    // 写入退出信息（控制区的只读字段由硬件设置）
    // 我们需要写入 Guest 状态
    
    vmcb->StateSaveArea.Cr0 = Cache->GuestCr0;
    vmcb->StateSaveArea.Cr2 = Cache->GuestCr2;
    vmcb->StateSaveArea.Cr3 = Cache->GuestCr3;
    vmcb->StateSaveArea.Cr4 = Cache->GuestCr4;
    vmcb->StateSaveArea.Dr6 = Cache->GuestDr6;
    vmcb->StateSaveArea.Dr7 = Cache->GuestDr7;
    vmcb->StateSaveArea.Rip = Cache->GuestRip;
    vmcb->StateSaveArea.Rsp = Cache->GuestRsp;
    vmcb->StateSaveArea.Rax = Cache->GuestRax;
    vmcb->StateSaveArea.Rflags = Cache->GuestRflags;
    vmcb->StateSaveArea.Efer = Cache->GuestEfer;
    
    // 写入段寄存器
    vmcb->StateSaveArea.Es = Cache->Es;
    vmcb->StateSaveArea.Cs = Cache->Cs;
    vmcb->StateSaveArea.Ss = Cache->Ss;
    vmcb->StateSaveArea.Ds = Cache->Ds;
    vmcb->StateSaveArea.Fs = Cache->Fs;
    vmcb->StateSaveArea.Gs = Cache->Gs;
    vmcb->StateSaveArea.Gdtr = Cache->Gdtr;
    vmcb->StateSaveArea.Ldtr = Cache->Ldtr;
    vmcb->StateSaveArea.Idtr = Cache->Idtr;
    vmcb->StateSaveArea.Tr = Cache->Tr;
    
    vmcb->StateSaveArea.Cpl = Cache->Cpl;
    
    NestedSvmUnmapVmcb(vmcb);
    return TRUE;
}

// ==================== VMCB 合并 ====================

/*
 * 分配 L2 使用的 ASID
 *
 * HV_ENABLE_SVM_HARDENING=1: 走 HvVmcb.c 全局 ASID 池, 真正 per-vCPU TLB 隔离;
 *   已分配的 L2 ASID 缓存在 NestedSvm.L2Asid, 复用避免反复进出池。
 * HV_ENABLE_SVM_HARDENING=0: 简化策略 L1+1 ∈ [1, 255], 与历史行为一致。
 */
static ULONG NestedSvmAllocateL2Asid(PVCPU_DATA VcpuData, ULONG L1Asid)
{
#if HV_ENABLE_SVM_HARDENING
    if (VcpuData && VcpuData->NestedSvm.L2Asid != 0 &&
        VcpuData->NestedSvm.L2Asid != L1Asid) {
        return VcpuData->NestedSvm.L2Asid;  // 缓存命中
    }
    ULONG fromPool = SvmPoolAllocateAsid();
    if (fromPool != 0 && fromPool != L1Asid) {
        if (VcpuData) {
            VcpuData->NestedSvm.L2Asid = fromPool;
        }
        return fromPool;
    }
    // 池耗尽或撞 L1: fallback 到 L1+1 / 1
    if (fromPool != 0) {
        SvmPoolReleaseAsid(fromPool);  // 不用的归还
    }
#else
    UNREFERENCED_PARAMETER(VcpuData);
#endif

    ULONG l2Asid = L1Asid + 1;

    // ASID 0 保留给 Host
    if (l2Asid == 0 || l2Asid > 255) {
        l2Asid = 1;
    }
    if (l2Asid == L1Asid) {
        l2Asid = (l2Asid % 255) + 1;
    }
    return l2Asid;
}

VOID NestedSvmMergeVmcbControls(
    PVCPU_DATA VcpuData,
    PNESTED_VMCB_CACHE Vmcb12,
    PNESTED_VMCB_MERGED_CONTROLS Merged)
{
    PVMCB vmcb01 = VcpuData->Vmcb;
    PNESTED_SVM_STATE nested = &VcpuData->NestedSvm;
    
    // 合并 CR 拦截（OR）
    Merged->InterceptCrRead = vmcb01->ControlArea.InterceptCrRead | Vmcb12->InterceptCrRead;
    Merged->InterceptCrWrite = vmcb01->ControlArea.InterceptCrWrite | Vmcb12->InterceptCrWrite;
    
    // 合并 DR 拦截（OR）
    Merged->InterceptDrRead = vmcb01->ControlArea.InterceptDrRead | Vmcb12->InterceptDrRead;
    Merged->InterceptDrWrite = vmcb01->ControlArea.InterceptDrWrite | Vmcb12->InterceptDrWrite;
    
    // 合并异常拦截（OR）
    Merged->InterceptExceptions = vmcb01->ControlArea.InterceptExceptions | Vmcb12->InterceptExceptions;
    
    // 合并杂项拦截（OR）
    // L0 必须拦截的指令保持拦截
    Merged->InterceptMisc1 = vmcb01->ControlArea.InterceptMisc1 | Vmcb12->InterceptMisc1;
    Merged->InterceptMisc2 = vmcb01->ControlArea.InterceptMisc2 | Vmcb12->InterceptMisc2;
    
    // 确保 L0 必须拦截的指令
    Merged->InterceptMisc2 |= SVM_INTERCEPT_VMRUN;   // 总是拦截 VMRUN（防止 L2 执行）
    Merged->InterceptMisc2 |= SVM_INTERCEPT_VMMCALL; // 总是拦截 VMMCALL
    Merged->InterceptMisc2 |= SVM_INTERCEPT_VMLOAD;  // 总是拦截 VMLOAD
    Merged->InterceptMisc2 |= SVM_INTERCEPT_VMSAVE;  // 总是拦截 VMSAVE
    Merged->InterceptMisc2 |= SVM_INTERCEPT_STGI;    // 总是拦截 STGI
    Merged->InterceptMisc2 |= SVM_INTERCEPT_CLGI;    // 总是拦截 CLGI
    
    // TSC 偏移累加
    Merged->TscOffset = vmcb01->ControlArea.TscOffset + Vmcb12->TscOffset;
    
    // 虚拟中断控制
    Merged->VIntr = Vmcb12->VIntr;
    
    // NPT
    // 如果 L1 启用 NPT，我们需要合并
    Merged->NpEnabled = (Vmcb12->NpEnable & 1) != 0;
    
    // ASID 管理
    // 为 L2 分配一个不同于 L1 的 ASID
    nested->L1Asid = vmcb01->ControlArea.GuestAsid;
    nested->L2Asid = NestedSvmAllocateL2Asid(VcpuData, nested->L1Asid);
    Merged->GuestAsid = nested->L2Asid;
    
    // IOPM/MSRPM 处理
#if HV_ENABLE_SVM_HARDENING
    {
        PNESTED_SVM_STATE nested = &VcpuData->NestedSvm;
        PHYSICAL_ADDRESS maxPhys = { .QuadPart = -1LL };

        // 懒分配 MergedMsrpm (8KB = 2 页) 和 MergedIopm (12KB = 3 页)
        if (!nested->MergedMsrpm) {
            nested->MergedMsrpm = MmAllocateContiguousMemory(PAGE_SIZE * 2, maxPhys);
            if (nested->MergedMsrpm) {
                nested->MergedMsrpmPhysical = MmGetPhysicalAddress(nested->MergedMsrpm);
            }
        }
        if (!nested->MergedIopm) {
            nested->MergedIopm = MmAllocateContiguousMemory(PAGE_SIZE * 3, maxPhys);
            if (nested->MergedIopm) {
                nested->MergedIopmPhysical = MmGetPhysicalAddress(nested->MergedIopm);
            }
        }

        // ===== MSRPM 合并 =====
        if (nested->MergedMsrpm && Vmcb12->MsrpmBasePa != 0) {
            // 1) 拷 L0 MSRPM
            PVOID l0Msrpm = MmGetVirtualForPhysical(
                (PHYSICAL_ADDRESS){ .QuadPart = (LONGLONG)vmcb01->ControlArea.MsrpmBasePa });
            if (l0Msrpm) {
                RtlCopyMemory(nested->MergedMsrpm, l0Msrpm, PAGE_SIZE * 2);
            } else {
                RtlZeroMemory(nested->MergedMsrpm, PAGE_SIZE * 2);
            }
            // 2) 把 L1 MSRPM 按位 OR 进来 (L1 GPA → L0 HPA)
            ULONG64 l1MsrpmHpa = 0;
            if (NestedSvmTranslateGpaToHpa(VcpuData, Vmcb12->MsrpmBasePa, &l1MsrpmHpa)
                && l1MsrpmHpa != 0) {
                PHYSICAL_ADDRESS l1pa = { .QuadPart = (LONGLONG)l1MsrpmHpa };
                PUCHAR l1Msrpm = (PUCHAR)MmGetVirtualForPhysical(l1pa);
                if (l1Msrpm) {
                    PUCHAR mergedBytes = (PUCHAR)nested->MergedMsrpm;
                    for (SIZE_T i = 0; i < PAGE_SIZE * 2; i++) {
                        mergedBytes[i] |= l1Msrpm[i];
                    }
                }
            }
            Merged->MsrpmBasePa = (ULONG64)nested->MergedMsrpmPhysical.QuadPart;
            Merged->UseL1Msrpm = TRUE;
        } else {
            // L1 未配置 → 直接用 L0 MSRPM (与历史行为兼容)
            Merged->MsrpmBasePa = vmcb01->ControlArea.MsrpmBasePa;
            Merged->UseL1Msrpm = FALSE;
        }

        // ===== IOPM 合并 (12KB) =====
        // 当前 L0 不配置 IOPM (VcpuData 没有 IoPermissionMap 字段), L0 端为 0.
        // L1 IOPM 直接透传; 若未来 L0 启用 IOPM, 这里走同 MSRPM 一样的 byte-OR
        if (Vmcb12->IopmBasePa != 0) {
            Merged->IopmBasePa = Vmcb12->IopmBasePa;
            Merged->UseL1Iopm = TRUE;
        } else {
            Merged->IopmBasePa = vmcb01->ControlArea.IopmBasePa;
            Merged->UseL1Iopm = FALSE;
        }
    }
#else
    // 历史行为: 谁配置用谁的 (简化, 但 L0 拦截 MSR 在 L2 里会失效, 已知 gap)
    if (Vmcb12->IopmBasePa != 0) {
        Merged->IopmBasePa = Vmcb12->IopmBasePa;
        Merged->UseL1Iopm = TRUE;
    } else {
        Merged->IopmBasePa = vmcb01->ControlArea.IopmBasePa;
        Merged->UseL1Iopm = FALSE;
    }

    if (Vmcb12->MsrpmBasePa != 0) {
        Merged->MsrpmBasePa = Vmcb12->MsrpmBasePa;
        Merged->UseL1Msrpm = TRUE;
    } else {
        Merged->MsrpmBasePa = vmcb01->ControlArea.MsrpmBasePa;
        Merged->UseL1Msrpm = FALSE;
    }
#endif
}

// ==================== 进入/退出 L2 ====================

VOID NestedSvmSaveL1State(PVCPU_DATA VcpuData)
{
    PNESTED_SVM_STATE nested = &VcpuData->NestedSvm;
    PVMCB vmcb = VcpuData->Vmcb;
    
    // 保存 L1 的基本寄存器状态
    nested->L1GuestRip = vmcb->StateSaveArea.Rip;
    nested->L1GuestRsp = vmcb->StateSaveArea.Rsp;
    nested->L1GuestRax = vmcb->StateSaveArea.Rax;
    nested->L1GuestRflags = vmcb->StateSaveArea.Rflags;
    nested->L1GuestCr0 = vmcb->StateSaveArea.Cr0;
    nested->L1GuestCr2 = vmcb->StateSaveArea.Cr2;
    nested->L1GuestCr3 = vmcb->StateSaveArea.Cr3;
    nested->L1GuestCr4 = vmcb->StateSaveArea.Cr4;
    nested->L1GuestEfer = vmcb->StateSaveArea.Efer;
    nested->L1GuestDr6 = vmcb->StateSaveArea.Dr6;
    nested->L1GuestDr7 = vmcb->StateSaveArea.Dr7;
    
    // 保存 L1 的段寄存器
    nested->L1Es = vmcb->StateSaveArea.Es;
    nested->L1Cs = vmcb->StateSaveArea.Cs;
    nested->L1Ss = vmcb->StateSaveArea.Ss;
    nested->L1Ds = vmcb->StateSaveArea.Ds;
    nested->L1Fs = vmcb->StateSaveArea.Fs;
    nested->L1Gs = vmcb->StateSaveArea.Gs;
    nested->L1Gdtr = vmcb->StateSaveArea.Gdtr;
    nested->L1Ldtr = vmcb->StateSaveArea.Ldtr;
    nested->L1Idtr = vmcb->StateSaveArea.Idtr;
    nested->L1Tr = vmcb->StateSaveArea.Tr;
    nested->L1Cpl = vmcb->StateSaveArea.Cpl;
    
    // 保存 L1 的 SYSENTER/SYSCALL 寄存器
    nested->L1Star = vmcb->StateSaveArea.Star;
    nested->L1LStar = vmcb->StateSaveArea.LStar;
    nested->L1CStar = vmcb->StateSaveArea.CStar;
    nested->L1SfMask = vmcb->StateSaveArea.SfMask;
    nested->L1KernelGsBase = vmcb->StateSaveArea.KernelGsBase;
    nested->L1SysenterCs = vmcb->StateSaveArea.SysenterCs;
    nested->L1SysenterEsp = vmcb->StateSaveArea.SysenterEsp;
    nested->L1SysenterEip = vmcb->StateSaveArea.SysenterEip;
    
    // 保存 L0 的原始 VMCB 控制字段（用于从 L2 退出时恢复）
    nested->SavedInterceptCrRead = vmcb->ControlArea.InterceptCrRead;
    nested->SavedInterceptCrWrite = vmcb->ControlArea.InterceptCrWrite;
    nested->SavedInterceptDrRead = vmcb->ControlArea.InterceptDrRead;
    nested->SavedInterceptDrWrite = vmcb->ControlArea.InterceptDrWrite;
    nested->SavedInterceptExceptions = vmcb->ControlArea.InterceptExceptions;
    nested->SavedInterceptMisc1 = vmcb->ControlArea.InterceptMisc1;
    nested->SavedInterceptMisc2 = vmcb->ControlArea.InterceptMisc2;
    nested->SavedTscOffset = vmcb->ControlArea.TscOffset;
    nested->SavedNpEnable = vmcb->ControlArea.NpEnable;
    nested->SavedNCr3 = vmcb->ControlArea.NCr3;
    nested->SavedAsid = vmcb->ControlArea.GuestAsid;
    nested->SavedIopmBasePa = vmcb->ControlArea.IopmBasePa;
    nested->SavedMsrpmBasePa = vmcb->ControlArea.MsrpmBasePa;
    
    // 保存 L1 的 ASID
    nested->L1Asid = vmcb->ControlArea.GuestAsid;
}

VOID NestedSvmRestoreL1State(PVCPU_DATA VcpuData)
{
    PNESTED_SVM_STATE nested = &VcpuData->NestedSvm;
    PVMCB vmcb = VcpuData->Vmcb;
    
    // 恢复 L1 的基本寄存器状态
    vmcb->StateSaveArea.Rip = nested->L1GuestRip;
    vmcb->StateSaveArea.Rsp = nested->L1GuestRsp;
    vmcb->StateSaveArea.Rax = nested->L1GuestRax;
    vmcb->StateSaveArea.Rflags = nested->L1GuestRflags;
    vmcb->StateSaveArea.Cr0 = nested->L1GuestCr0;
    vmcb->StateSaveArea.Cr2 = nested->L1GuestCr2;
    vmcb->StateSaveArea.Cr3 = nested->L1GuestCr3;
    vmcb->StateSaveArea.Cr4 = nested->L1GuestCr4;
    vmcb->StateSaveArea.Efer = nested->L1GuestEfer;
    vmcb->StateSaveArea.Dr6 = nested->L1GuestDr6;
    vmcb->StateSaveArea.Dr7 = nested->L1GuestDr7;
    
    // 恢复 L1 的段寄存器
    vmcb->StateSaveArea.Es = nested->L1Es;
    vmcb->StateSaveArea.Cs = nested->L1Cs;
    vmcb->StateSaveArea.Ss = nested->L1Ss;
    vmcb->StateSaveArea.Ds = nested->L1Ds;
    vmcb->StateSaveArea.Fs = nested->L1Fs;
    vmcb->StateSaveArea.Gs = nested->L1Gs;
    vmcb->StateSaveArea.Gdtr = nested->L1Gdtr;
    vmcb->StateSaveArea.Ldtr = nested->L1Ldtr;
    vmcb->StateSaveArea.Idtr = nested->L1Idtr;
    vmcb->StateSaveArea.Tr = nested->L1Tr;
    vmcb->StateSaveArea.Cpl = nested->L1Cpl;
    
    // 恢复 L1 的 SYSENTER/SYSCALL 寄存器
    vmcb->StateSaveArea.Star = nested->L1Star;
    vmcb->StateSaveArea.LStar = nested->L1LStar;
    vmcb->StateSaveArea.CStar = nested->L1CStar;
    vmcb->StateSaveArea.SfMask = nested->L1SfMask;
    vmcb->StateSaveArea.KernelGsBase = nested->L1KernelGsBase;
    vmcb->StateSaveArea.SysenterCs = nested->L1SysenterCs;
    vmcb->StateSaveArea.SysenterEsp = nested->L1SysenterEsp;
    vmcb->StateSaveArea.SysenterEip = nested->L1SysenterEip;
    
    // 恢复 L0 的原始 VMCB 控制字段
    vmcb->ControlArea.InterceptCrRead = nested->SavedInterceptCrRead;
    vmcb->ControlArea.InterceptCrWrite = nested->SavedInterceptCrWrite;
    vmcb->ControlArea.InterceptDrRead = nested->SavedInterceptDrRead;
    vmcb->ControlArea.InterceptDrWrite = nested->SavedInterceptDrWrite;
    vmcb->ControlArea.InterceptExceptions = nested->SavedInterceptExceptions;
    vmcb->ControlArea.InterceptMisc1 = nested->SavedInterceptMisc1;
    vmcb->ControlArea.InterceptMisc2 = nested->SavedInterceptMisc2;
    vmcb->ControlArea.TscOffset = nested->SavedTscOffset;
    vmcb->ControlArea.NpEnable = nested->SavedNpEnable;
    vmcb->ControlArea.NCr3 = nested->SavedNCr3;
    vmcb->ControlArea.GuestAsid = nested->SavedAsid;
    vmcb->ControlArea.IopmBasePa = nested->SavedIopmBasePa;
    vmcb->ControlArea.MsrpmBasePa = nested->SavedMsrpmBasePa;
    
    // 清除 VMCB Clean Bits
    vmcb->ControlArea.VmcbCleanBits = 0;
    
    // 刷新 TLB（因为 ASID 变化了）
    vmcb->ControlArea.TlbControl = SVM_TLB_CONTROL_FLUSH_GUEST;
}

NTSTATUS NestedSvmEnterL2(
    PVCPU_DATA VcpuData,
    PNESTED_VMCB_CACHE Vmcb12)
{
    PNESTED_SVM_STATE nested = &VcpuData->NestedSvm;
    PVMCB vmcb = VcpuData->Vmcb;
    NESTED_VMCB_MERGED_CONTROLS merged;
    
    // 保存 L1 状态
    NestedSvmSaveL1State(VcpuData);
    
    // 合并控制字段
    NestedSvmMergeVmcbControls(VcpuData, Vmcb12, &merged);
    
    // 应用合并的控制字段到 VMCB01
    vmcb->ControlArea.InterceptCrRead = merged.InterceptCrRead;
    vmcb->ControlArea.InterceptCrWrite = merged.InterceptCrWrite;
    vmcb->ControlArea.InterceptDrRead = merged.InterceptDrRead;
    vmcb->ControlArea.InterceptDrWrite = merged.InterceptDrWrite;
    vmcb->ControlArea.InterceptExceptions = merged.InterceptExceptions;
    vmcb->ControlArea.InterceptMisc1 = merged.InterceptMisc1;
    vmcb->ControlArea.InterceptMisc2 = merged.InterceptMisc2;
    vmcb->ControlArea.TscOffset = merged.TscOffset;
    vmcb->ControlArea.VIntr = merged.VIntr;
    
    // 应用 ASID（L2 使用不同的 ASID）
    vmcb->ControlArea.GuestAsid = merged.GuestAsid;
    
    // 应用 IOPM/MSRPM
    vmcb->ControlArea.IopmBasePa = merged.IopmBasePa;
    vmcb->ControlArea.MsrpmBasePa = merged.MsrpmBasePa;
    
    // 设置 L2 Guest 状态
    vmcb->StateSaveArea.Cr0 = Vmcb12->GuestCr0;
    vmcb->StateSaveArea.Cr2 = Vmcb12->GuestCr2;
    vmcb->StateSaveArea.Cr3 = Vmcb12->GuestCr3;
    vmcb->StateSaveArea.Cr4 = Vmcb12->GuestCr4;
    vmcb->StateSaveArea.Dr6 = Vmcb12->GuestDr6;
    vmcb->StateSaveArea.Dr7 = Vmcb12->GuestDr7;
    vmcb->StateSaveArea.Rip = Vmcb12->GuestRip;
    vmcb->StateSaveArea.Rsp = Vmcb12->GuestRsp;
    vmcb->StateSaveArea.Rax = Vmcb12->GuestRax;
    vmcb->StateSaveArea.Rflags = Vmcb12->GuestRflags;
    vmcb->StateSaveArea.Efer = Vmcb12->GuestEfer;
    
    // 设置段寄存器
    vmcb->StateSaveArea.Es = Vmcb12->Es;
    vmcb->StateSaveArea.Cs = Vmcb12->Cs;
    vmcb->StateSaveArea.Ss = Vmcb12->Ss;
    vmcb->StateSaveArea.Ds = Vmcb12->Ds;
    vmcb->StateSaveArea.Fs = Vmcb12->Fs;
    vmcb->StateSaveArea.Gs = Vmcb12->Gs;
    vmcb->StateSaveArea.Gdtr = Vmcb12->Gdtr;
    vmcb->StateSaveArea.Ldtr = Vmcb12->Ldtr;
    vmcb->StateSaveArea.Idtr = Vmcb12->Idtr;
    vmcb->StateSaveArea.Tr = Vmcb12->Tr;
    vmcb->StateSaveArea.Cpl = Vmcb12->Cpl;
    
    // 设置 SYSENTER/SYSCALL
    vmcb->StateSaveArea.Star = Vmcb12->Star;
    vmcb->StateSaveArea.LStar = Vmcb12->LStar;
    vmcb->StateSaveArea.CStar = Vmcb12->CStar;
    vmcb->StateSaveArea.SfMask = Vmcb12->SfMask;
    vmcb->StateSaveArea.KernelGsBase = Vmcb12->KernelGsBase;
    vmcb->StateSaveArea.SysenterCs = Vmcb12->SysenterCs;
    vmcb->StateSaveArea.SysenterEsp = Vmcb12->SysenterEsp;
    vmcb->StateSaveArea.SysenterEip = Vmcb12->SysenterEip;
    
    // 处理嵌套 NPT
    if (merged.NpEnabled) {
        PNESTED_NPT_CONTEXT nptContext;
        
        nested->L1NptEnabled = TRUE;
        nested->L1NCr3 = Vmcb12->NCr3;
        
        // 使用嵌套 NPT 管理器创建或获取上下文
        nptContext = NestedNptGetOrCreateContext(Vmcb12->NCr3);
        if (nptContext) {
            nested->NestedNptTables = (PVOID)nptContext;
            // 更新 VMCB 中的 NCR3 指向合并后的 NPT
            // 注意：实际实现中可能需要使用 NPT02 的物理地址
            vmcb->ControlArea.NCr3 = nptContext->Pml4Physical.QuadPart;
            vmcb->ControlArea.NpEnable = 1;
            
            DbgPrint("[HV-NESTED-SVM] Nested NPT enabled, L1 NCR3=0x%llX, NPT02 PA=0x%llX\n",
                     Vmcb12->NCr3, nptContext->Pml4Physical.QuadPart);
        } else {
            // 无法创建 NPT 上下文，禁用 NPT
            nested->L1NptEnabled = FALSE;
            vmcb->ControlArea.NpEnable = 0;
            DbgPrint("[HV-NESTED-SVM] Failed to create nested NPT context\n");
        }
    }
    
    // 处理事件注入
    if (Vmcb12->EventInj & (1ULL << 31)) {
        vmcb->ControlArea.EventInj = Vmcb12->EventInj;
    }
    
    // 清除 VMCB Clean Bits（表示所有字段都已修改）
    vmcb->ControlArea.VmcbCleanBits = 0;
    
    // 设置 TLB 控制
    vmcb->ControlArea.TlbControl = SVM_TLB_CONTROL_FLUSH_GUEST;
    
    // 标记进入 L2
    VcpuData->IsInL2 = TRUE;
    nested->InGuestMode = TRUE;
    nested->NestedVmrunCount++;
    
    InterlockedIncrement64(&g_NestedSvmVmrunCount);
    
    return STATUS_SUCCESS;
}

VOID NestedSvmSyncVmcb12(
    PVCPU_DATA VcpuData,
    ULONG64 ExitCode,
    ULONG64 ExitInfo1,
    ULONG64 ExitInfo2)
{
    PNESTED_SVM_STATE nested = &VcpuData->NestedSvm;
    PVMCB vmcb = VcpuData->Vmcb;
    NESTED_VMCB_CACHE cache;
    
    // 读取当前 VMCB12
    if (!NestedSvmReadVmcb12(VcpuData, nested->VmcbGpa, &cache)) {
        return;
    }
    
    // 同步 Guest 状态
    cache.GuestCr0 = vmcb->StateSaveArea.Cr0;
    cache.GuestCr2 = vmcb->StateSaveArea.Cr2;
    cache.GuestCr3 = vmcb->StateSaveArea.Cr3;
    cache.GuestCr4 = vmcb->StateSaveArea.Cr4;
    cache.GuestDr6 = vmcb->StateSaveArea.Dr6;
    cache.GuestDr7 = vmcb->StateSaveArea.Dr7;
    cache.GuestRip = vmcb->StateSaveArea.Rip;
    cache.GuestRsp = vmcb->StateSaveArea.Rsp;
    cache.GuestRax = vmcb->StateSaveArea.Rax;
    cache.GuestRflags = vmcb->StateSaveArea.Rflags;
    
    // 同步段寄存器
    cache.Es = vmcb->StateSaveArea.Es;
    cache.Cs = vmcb->StateSaveArea.Cs;
    cache.Ss = vmcb->StateSaveArea.Ss;
    cache.Ds = vmcb->StateSaveArea.Ds;
    cache.Fs = vmcb->StateSaveArea.Fs;
    cache.Gs = vmcb->StateSaveArea.Gs;
    cache.Cpl = vmcb->StateSaveArea.Cpl;
    
    // 写回 VMCB12
    NestedSvmWriteVmcb12(VcpuData, nested->VmcbGpa, &cache);
    
    // 更新 VMCB12 控制区的退出信息
    {
        ULONG64 vmcb12Hpa;
        PVMCB vmcb12;
        
        // 必须先将 GPA 翻译为 HPA 才能映射
        if (!NestedSvmTranslateGpaToHpa(VcpuData, nested->VmcbGpa, &vmcb12Hpa)) {
            DbgPrint("[HV-NESTED-SVM] Failed to translate VMCB12 GPA in SyncVmcb12\n");
            return;
        }
        
        vmcb12 = NestedSvmMapVmcb(vmcb12Hpa);
        if (vmcb12) {
            vmcb12->ControlArea.ExitCode = ExitCode;
            vmcb12->ControlArea.ExitInfo1 = ExitInfo1;
            vmcb12->ControlArea.ExitInfo2 = ExitInfo2;
            vmcb12->ControlArea.ExitIntInfo = vmcb->ControlArea.ExitIntInfo;
            vmcb12->ControlArea.NRip = vmcb->ControlArea.NRip;
            NestedSvmUnmapVmcb(vmcb12);
        }
    }
}

VOID NestedSvmExitToL1(
    PVCPU_DATA VcpuData,
    ULONG64 ExitCode,
    ULONG64 ExitInfo1,
    ULONG64 ExitInfo2)
{
    PNESTED_SVM_STATE nested = &VcpuData->NestedSvm;
    
    // 同步 L2 状态到 VMCB12
    NestedSvmSyncVmcb12(VcpuData, ExitCode, ExitInfo1, ExitInfo2);
    
    // 恢复 L1 状态
    NestedSvmRestoreL1State(VcpuData);
    
    // 推进 L1 RIP（VMRUN 之后的指令）
    // 注意：RIP 已经在进入 L2 时保存
    
    // 标记退出 L2
    VcpuData->IsInL2 = FALSE;
    nested->InGuestMode = FALSE;
    nested->L2VmExitCount++;
    
    InterlockedIncrement64(&g_NestedSvmL2ExitCount);
}

// ==================== L2 Exit 分发 ====================

BOOLEAN NestedSvmShouldL0HandleExit(
    PVCPU_DATA VcpuData,
    ULONG64 ExitCode,
    ULONG64 ExitInfo1,
    ULONG64 ExitInfo2)
{
    // L0 必须处理的退出
    switch (ExitCode) {
    case SVM_EXIT_NPF:
        // NPT Fault - 需要判断是 L0 Hook 还是 L1 NPT 问题
        // ExitInfo2 包含故障地址
        // 
        // L0 总是先尝试处理 NPF：
        // 1. 如果是 L0 的 NPT Hook 引起的，NptHookHandleNpf 会处理
        // 2. 如果是 L1 NPT 问题，会由 NestedNptHandleFault 判断并可能注入到 L1
        // 3. 如果两者都不是，则可能是真正的内存错误
        return TRUE;  // L0 先处理
        
    case SVM_EXIT_VMRUN:
    case SVM_EXIT_VMLOAD:
    case SVM_EXIT_VMSAVE:
    case SVM_EXIT_STGI:
    case SVM_EXIT_CLGI:
        // SVM 指令 - L0 处理（L2 不允许执行）
        return TRUE;
        
    case SVM_EXIT_INTR:
        // 外部中断 - L0 处理
        return TRUE;
        
    case SVM_EXIT_NMI:
        // NMI - L0 处理
        return TRUE;
        
    case SVM_EXIT_SHUTDOWN:
        // Shutdown - L0 处理
        return TRUE;
        
    default:
        // 其他退出检查 L1 的拦截设置
        return FALSE;
    }
}

BOOLEAN NestedSvmDispatchL2Exit(
    PVCPU_DATA VcpuData,
    ULONG64 ExitCode,
    ULONG64 ExitInfo1,
    ULONG64 ExitInfo2,
    PGUEST_CONTEXT GuestContext)
{
    InterlockedIncrement64(&g_NestedSvmVmExitCount);
    
    // 判断应该由谁处理
    if (NestedSvmShouldL0HandleExit(VcpuData, ExitCode, ExitInfo1, ExitInfo2)) {
        // L0 处理
        // 这里可以处理 L0 关心的退出（如 NPT Hook）
        
        // 对于 SVM 指令，注入 #UD 给 L2
        if (ExitCode >= SVM_EXIT_VMRUN && ExitCode <= SVM_EXIT_CLGI) {
            NestedSvmInjectEvent(VcpuData, 6, SVM_EVENT_TYPE_EXCEPTION, FALSE, 0);
            return TRUE;
        }
        
        // 其他由 L0 处理的情况返回 FALSE，让调用者处理
        return FALSE;
    }
    
    // 注入到 L1
    NestedSvmExitToL1(VcpuData, ExitCode, ExitInfo1, ExitInfo2);
    return TRUE;
}

// ==================== VMRUN 处理 ====================

/*
 * VMCB12 一致性检查
 * 根据 AMD64 Architecture Programmer's Manual Volume 2 进行验证
 */
static BOOLEAN NestedSvmValidateVmcb12(
    PVCPU_DATA VcpuData,
    PNESTED_VMCB_CACHE Vmcb12,
    PULONG64 ErrorCode)
{
    *ErrorCode = 0;
    
    // 1. 检查 EFER 一致性
    // EFER.SVME 必须在 Guest 中启用（如果 L2 也要运行 SVM）
    // LME 和 LMA 必须一致
    if ((Vmcb12->GuestEfer & EFER_LME) != 0) {
        // 如果 LME=1，CR0.PG 必须为 0 或者 LMA 也必须为 1
        if ((Vmcb12->GuestCr0 & (1ULL << 31)) != 0) {
            if ((Vmcb12->GuestEfer & EFER_LMA) == 0) {
                *ErrorCode = 1;  // EFER.LMA/LME 不一致
                return FALSE;
            }
        }
    }
    
    // 2. 检查 CR0 一致性
    // CR0.CD=0 且 CR0.NW=1 是非法的
    if (((Vmcb12->GuestCr0 & (1ULL << 30)) == 0) &&  // CD=0
        ((Vmcb12->GuestCr0 & (1ULL << 29)) != 0)) {  // NW=1
        *ErrorCode = 2;  // CR0.CD/NW 组合非法
        return FALSE;
    }
    
    // 3. 检查 CR3 和 CR4 
    // 在长模式下，CR3 的某些位必须为 0
    if ((Vmcb12->GuestEfer & EFER_LMA) != 0) {
        // 长模式：检查 CR4.PAE
        if ((Vmcb12->GuestCr4 & (1ULL << 5)) == 0) {
            *ErrorCode = 3;  // 长模式下 CR4.PAE 必须为 1
            return FALSE;
        }
    }
    
    // 4. 检查 ASID
    // ASID 不能为 0
    if (Vmcb12->GuestAsid == 0) {
        *ErrorCode = 4;  // ASID 为 0
        return FALSE;
    }
    
    // 5. 检查段选择子在保护模式下的有效性
    // （简化：只检查 CS 选择子不为 0）
    if ((Vmcb12->GuestCr0 & 1) != 0) {  // PE=1
        if (Vmcb12->Cs.Selector == 0 && (Vmcb12->GuestEfer & EFER_LMA) == 0) {
            // 在 32 位保护模式下 CS=0 可能是错误的
            // 但这不一定是致命错误，取决于具体场景
        }
    }
    
    // 6. 检查保留位
    // InterceptMisc2 的某些位是保留的
    // （这里简化处理，不严格检查所有保留位）
    
    return TRUE;
}

/*
 * 处理 Host Save Area
 * 在 VMRUN 时保存 Host 状态到 Host Save Area
 */
static VOID NestedSvmSaveToHostSaveArea(PVCPU_DATA VcpuData, ULONG64 HostSaveAreaGpa)
{
    PNESTED_SVM_STATE nested = &VcpuData->NestedSvm;
    PVMCB vmcb = VcpuData->Vmcb;
    PVOID hostSave;
    ULONG64 hpa;
    
    // 翻译 GPA 到 HPA
    if (!NestedSvmTranslateGpaToHpa(VcpuData, HostSaveAreaGpa, &hpa)) {
        return;
    }
    
    // 映射 Host Save Area
    hostSave = NestedSvmMapVmcb(hpa);
    if (!hostSave) {
        return;
    }
    
    // 保存 Host 状态（这些是 L1 作为 Host 的状态）
    // Host Save Area 格式与 VMCB State Save Area 类似
    // 保存段寄存器
    RtlCopyMemory((PUCHAR)hostSave + VMCB_SAVE_ES + 0x400, &vmcb->StateSaveArea.Es, sizeof(SVM_SEGMENT_REGISTER));
    RtlCopyMemory((PUCHAR)hostSave + VMCB_SAVE_CS + 0x400, &vmcb->StateSaveArea.Cs, sizeof(SVM_SEGMENT_REGISTER));
    RtlCopyMemory((PUCHAR)hostSave + VMCB_SAVE_SS + 0x400, &vmcb->StateSaveArea.Ss, sizeof(SVM_SEGMENT_REGISTER));
    RtlCopyMemory((PUCHAR)hostSave + VMCB_SAVE_DS + 0x400, &vmcb->StateSaveArea.Ds, sizeof(SVM_SEGMENT_REGISTER));
    RtlCopyMemory((PUCHAR)hostSave + VMCB_SAVE_FS + 0x400, &vmcb->StateSaveArea.Fs, sizeof(SVM_SEGMENT_REGISTER));
    RtlCopyMemory((PUCHAR)hostSave + VMCB_SAVE_GS + 0x400, &vmcb->StateSaveArea.Gs, sizeof(SVM_SEGMENT_REGISTER));
    RtlCopyMemory((PUCHAR)hostSave + VMCB_SAVE_GDTR + 0x400, &vmcb->StateSaveArea.Gdtr, sizeof(SVM_SEGMENT_REGISTER));
    RtlCopyMemory((PUCHAR)hostSave + VMCB_SAVE_LDTR + 0x400, &vmcb->StateSaveArea.Ldtr, sizeof(SVM_SEGMENT_REGISTER));
    RtlCopyMemory((PUCHAR)hostSave + VMCB_SAVE_IDTR + 0x400, &vmcb->StateSaveArea.Idtr, sizeof(SVM_SEGMENT_REGISTER));
    RtlCopyMemory((PUCHAR)hostSave + VMCB_SAVE_TR + 0x400, &vmcb->StateSaveArea.Tr, sizeof(SVM_SEGMENT_REGISTER));
    
    // 保存控制寄存器
    *(PULONG64)((PUCHAR)hostSave + VMCB_SAVE_CR0 + 0x400) = vmcb->StateSaveArea.Cr0;
    *(PULONG64)((PUCHAR)hostSave + VMCB_SAVE_CR3 + 0x400) = vmcb->StateSaveArea.Cr3;
    *(PULONG64)((PUCHAR)hostSave + VMCB_SAVE_CR4 + 0x400) = vmcb->StateSaveArea.Cr4;
    *(PULONG64)((PUCHAR)hostSave + VMCB_SAVE_EFER + 0x400) = vmcb->StateSaveArea.Efer;
    
    // 保存 RIP, RSP, RAX
    *(PULONG64)((PUCHAR)hostSave + VMCB_SAVE_RIP + 0x400) = nested->L1GuestRip;
    *(PULONG64)((PUCHAR)hostSave + VMCB_SAVE_RSP + 0x400) = vmcb->StateSaveArea.Rsp;
    *(PULONG64)((PUCHAR)hostSave + VMCB_SAVE_RAX + 0x400) = vmcb->StateSaveArea.Rax;
    *(PULONG64)((PUCHAR)hostSave + VMCB_SAVE_RFLAGS + 0x400) = vmcb->StateSaveArea.Rflags;
    
    // 记录 Host Save Area 地址
    nested->HostSaveGpa = HostSaveAreaGpa;
    
    NestedSvmUnmapVmcb(hostSave);
}

/*
 * 从 Host Save Area 加载状态
 * 在 #VMEXIT 时恢复 Host 状态
 */
static VOID NestedSvmLoadFromHostSaveArea(PVCPU_DATA VcpuData)
{
    PNESTED_SVM_STATE nested = &VcpuData->NestedSvm;
    PVMCB vmcb = VcpuData->Vmcb;
    PVOID hostSave;
    ULONG64 hpa;
    
    if (nested->HostSaveGpa == 0) {
        return;
    }
    
    // 翻译 GPA 到 HPA
    if (!NestedSvmTranslateGpaToHpa(VcpuData, nested->HostSaveGpa, &hpa)) {
        return;
    }
    
    // 映射 Host Save Area
    hostSave = NestedSvmMapVmcb(hpa);
    if (!hostSave) {
        return;
    }
    
    // 加载 Host 状态
    // 注意：我们主要使用保存在 nested 结构中的状态
    // Host Save Area 主要用于 L1 的一致性
    
    NestedSvmUnmapVmcb(hostSave);
}

BOOLEAN NestedSvmCheckVmrunPreconditions(
    PVCPU_DATA VcpuData,
    ULONG64 VmcbGpa)
{
    PVMCB vmcb = VcpuData->Vmcb;
    
    // 检查 EFER.SVME
    if (!(vmcb->StateSaveArea.Efer & EFER_SVME)) {
        DbgPrint("[HV-NESTED-SVM] VMRUN failed: EFER.SVME not set\n");
        return FALSE;
    }
    
    // 检查 CPL（必须为 0）
    if (vmcb->StateSaveArea.Cpl != 0) {
        DbgPrint("[HV-NESTED-SVM] VMRUN failed: CPL=%d (must be 0)\n", vmcb->StateSaveArea.Cpl);
        return FALSE;
    }
    
    // 检查 VMCB 地址对齐（必须 4KB 对齐）
    if (VmcbGpa & 0xFFF) {
        DbgPrint("[HV-NESTED-SVM] VMRUN failed: VMCB GPA 0x%llX not page aligned\n", VmcbGpa);
        return FALSE;
    }
    
    // 检查 VMCB 地址有效性（不能超过物理地址空间）
    if (VmcbGpa >= (1ULL << 52)) {
        DbgPrint("[HV-NESTED-SVM] VMRUN failed: VMCB GPA 0x%llX out of range\n", VmcbGpa);
        return FALSE;
    }
    
    return TRUE;
}

ULONG64 NestedSvmGetVmcbGpaFromRax(PVCPU_DATA VcpuData, PGUEST_CONTEXT GuestContext)
{
    // VMRUN 的 VMCB 地址在 RAX 中
    return VcpuData->Vmcb->StateSaveArea.Rax;
}

BOOLEAN NestedSvmHandleVmrun(
    PVCPU_DATA VcpuData,
    PGUEST_CONTEXT GuestContext)
{
    PNESTED_SVM_STATE nested = &VcpuData->NestedSvm;
    ULONG64 vmcbGpa;
    ULONG64 hostSaveGpa;
    NESTED_VMCB_CACHE vmcb12Cache;
    NTSTATUS status;
    ULONG64 validationError;
    
    // 获取 VMCB 地址
    vmcbGpa = NestedSvmGetVmcbGpaFromRax(VcpuData, GuestContext);
    
    DbgPrint("[HV-NESTED-SVM] VMRUN: VMCB GPA=0x%llX\n", vmcbGpa);
    
    // 检查先决条件
    if (!NestedSvmCheckVmrunPreconditions(VcpuData, vmcbGpa)) {
        // 注入 #GP(0)
        NestedSvmInjectEvent(VcpuData, 13, SVM_EVENT_TYPE_EXCEPTION, TRUE, 0);
        return TRUE;
    }
    
    // 读取 L1 的 VMCB
    if (!NestedSvmReadVmcb12(VcpuData, vmcbGpa, &vmcb12Cache)) {
        DbgPrint("[HV-NESTED-SVM] VMRUN failed: Cannot read VMCB12\n");
        // 注入 #GP(0)
        NestedSvmInjectEvent(VcpuData, 13, SVM_EVENT_TYPE_EXCEPTION, TRUE, 0);
        return TRUE;
    }
    
    // 验证 VMCB12 一致性
    if (!NestedSvmValidateVmcb12(VcpuData, &vmcb12Cache, &validationError)) {
        DbgPrint("[HV-NESTED-SVM] VMRUN failed: VMCB12 validation error %llu\n", validationError);
        // 根据 AMD 手册，VMCB 不一致会导致 #VMEXIT(VMEXIT_INVALID)
        // 但由于我们还没有进入 L2，这里注入 #GP
        NestedSvmInjectEvent(VcpuData, 13, SVM_EVENT_TYPE_EXCEPTION, TRUE, 0);
        return TRUE;
    }
    
    // 保存 VMCB 地址
    nested->VmcbGpa = vmcbGpa;
    nested->SvmEnabled = TRUE;
    
    // 计算 L1 RIP（VMRUN 之后的指令地址）
    if (VcpuData->Vmcb->ControlArea.NRip != 0) {
        nested->L1GuestRip = VcpuData->Vmcb->ControlArea.NRip;
    } else {
        // NRIP 不可用，假设 VMRUN 指令长度为 3 字节
        nested->L1GuestRip = VcpuData->Vmcb->StateSaveArea.Rip + 3;
    }
    
    // 获取 Host Save Area 地址（从 VM_HSAVE_PA MSR）
    // 这个 MSR 包含 L1 的 Host Save Area 物理地址
    hostSaveGpa = __readmsr(0xC0010117);  // MSR_VM_HSAVE_PA
    if (hostSaveGpa != 0 && (hostSaveGpa & 0xFFF) == 0) {
        // 保存 L1 Host 状态到 Host Save Area
        NestedSvmSaveToHostSaveArea(VcpuData, hostSaveGpa);
    }
    
    // 进入 L2
    status = NestedSvmEnterL2(VcpuData, &vmcb12Cache);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[HV-NESTED-SVM] VMRUN failed: NestedSvmEnterL2 returned 0x%X\n", status);
        // 注入 #GP(0)
        NestedSvmInjectEvent(VcpuData, 13, SVM_EVENT_TYPE_EXCEPTION, TRUE, 0);
        return TRUE;
    }
    
    DbgPrint("[HV-NESTED-SVM] VMRUN success: Entered L2, RIP=0x%llX\n", 
             VcpuData->Vmcb->StateSaveArea.Rip);
    
    // 不推进 RIP，VMRUN 成功后执行流已经切换到 L2
    return TRUE;
}

// ==================== VMLOAD/VMSAVE 处理 ====================

BOOLEAN NestedSvmHandleVmload(
    PVCPU_DATA VcpuData,
    PGUEST_CONTEXT GuestContext)
{
    ULONG64 vmcbGpa;
    PVMCB targetVmcb;
    PVMCB currentVmcb = VcpuData->Vmcb;
    ULONG64 hpa;
    
    // 检查 EFER.SVME
    if (!(currentVmcb->StateSaveArea.Efer & EFER_SVME)) {
        NestedSvmInjectEvent(VcpuData, 6, SVM_EVENT_TYPE_EXCEPTION, FALSE, 0);
        return TRUE;
    }
    
    // 检查 CPL
    if (currentVmcb->StateSaveArea.Cpl != 0) {
        NestedSvmInjectEvent(VcpuData, 13, SVM_EVENT_TYPE_EXCEPTION, TRUE, 0);
        return TRUE;
    }
    
    // 获取 VMCB 地址（从 RAX）
    vmcbGpa = currentVmcb->StateSaveArea.Rax;
    
    // 检查对齐
    if (vmcbGpa & 0xFFF) {
        NestedSvmInjectEvent(VcpuData, 13, SVM_EVENT_TYPE_EXCEPTION, TRUE, 0);
        return TRUE;
    }
    
    // 翻译地址
    if (!NestedSvmTranslateGpaToHpa(VcpuData, vmcbGpa, &hpa)) {
        NestedSvmInjectEvent(VcpuData, 14, SVM_EVENT_TYPE_EXCEPTION, TRUE, 0);
        return TRUE;
    }
    
    // 映射目标 VMCB
    targetVmcb = NestedSvmMapVmcb(hpa);
    if (!targetVmcb) {
        NestedSvmInjectEvent(VcpuData, 14, SVM_EVENT_TYPE_EXCEPTION, TRUE, 0);
        return TRUE;
    }
    
    // 从目标 VMCB 加载 Host 状态到当前 VMCB
    currentVmcb->StateSaveArea.Fs = targetVmcb->StateSaveArea.Fs;
    currentVmcb->StateSaveArea.Gs = targetVmcb->StateSaveArea.Gs;
    currentVmcb->StateSaveArea.Tr = targetVmcb->StateSaveArea.Tr;
    currentVmcb->StateSaveArea.Ldtr = targetVmcb->StateSaveArea.Ldtr;
    currentVmcb->StateSaveArea.KernelGsBase = targetVmcb->StateSaveArea.KernelGsBase;
    currentVmcb->StateSaveArea.Star = targetVmcb->StateSaveArea.Star;
    currentVmcb->StateSaveArea.LStar = targetVmcb->StateSaveArea.LStar;
    currentVmcb->StateSaveArea.CStar = targetVmcb->StateSaveArea.CStar;
    currentVmcb->StateSaveArea.SfMask = targetVmcb->StateSaveArea.SfMask;
    currentVmcb->StateSaveArea.SysenterCs = targetVmcb->StateSaveArea.SysenterCs;
    currentVmcb->StateSaveArea.SysenterEsp = targetVmcb->StateSaveArea.SysenterEsp;
    currentVmcb->StateSaveArea.SysenterEip = targetVmcb->StateSaveArea.SysenterEip;
    
    NestedSvmUnmapVmcb(targetVmcb);
    
    // 推进 RIP
    NestedSvmAdvanceRip(VcpuData);
    
    return TRUE;
}

BOOLEAN NestedSvmHandleVmsave(
    PVCPU_DATA VcpuData,
    PGUEST_CONTEXT GuestContext)
{
    ULONG64 vmcbGpa;
    PVMCB targetVmcb;
    PVMCB currentVmcb = VcpuData->Vmcb;
    ULONG64 hpa;
    
    // 检查 EFER.SVME
    if (!(currentVmcb->StateSaveArea.Efer & EFER_SVME)) {
        NestedSvmInjectEvent(VcpuData, 6, SVM_EVENT_TYPE_EXCEPTION, FALSE, 0);
        return TRUE;
    }
    
    // 检查 CPL
    if (currentVmcb->StateSaveArea.Cpl != 0) {
        NestedSvmInjectEvent(VcpuData, 13, SVM_EVENT_TYPE_EXCEPTION, TRUE, 0);
        return TRUE;
    }
    
    // 获取 VMCB 地址
    vmcbGpa = currentVmcb->StateSaveArea.Rax;
    
    // 检查对齐
    if (vmcbGpa & 0xFFF) {
        NestedSvmInjectEvent(VcpuData, 13, SVM_EVENT_TYPE_EXCEPTION, TRUE, 0);
        return TRUE;
    }
    
    // 翻译地址
    if (!NestedSvmTranslateGpaToHpa(VcpuData, vmcbGpa, &hpa)) {
        NestedSvmInjectEvent(VcpuData, 14, SVM_EVENT_TYPE_EXCEPTION, TRUE, 0);
        return TRUE;
    }
    
    // 映射目标 VMCB
    targetVmcb = NestedSvmMapVmcb(hpa);
    if (!targetVmcb) {
        NestedSvmInjectEvent(VcpuData, 14, SVM_EVENT_TYPE_EXCEPTION, TRUE, 0);
        return TRUE;
    }
    
    // 保存当前状态到目标 VMCB
    targetVmcb->StateSaveArea.Fs = currentVmcb->StateSaveArea.Fs;
    targetVmcb->StateSaveArea.Gs = currentVmcb->StateSaveArea.Gs;
    targetVmcb->StateSaveArea.Tr = currentVmcb->StateSaveArea.Tr;
    targetVmcb->StateSaveArea.Ldtr = currentVmcb->StateSaveArea.Ldtr;
    targetVmcb->StateSaveArea.KernelGsBase = currentVmcb->StateSaveArea.KernelGsBase;
    targetVmcb->StateSaveArea.Star = currentVmcb->StateSaveArea.Star;
    targetVmcb->StateSaveArea.LStar = currentVmcb->StateSaveArea.LStar;
    targetVmcb->StateSaveArea.CStar = currentVmcb->StateSaveArea.CStar;
    targetVmcb->StateSaveArea.SfMask = currentVmcb->StateSaveArea.SfMask;
    targetVmcb->StateSaveArea.SysenterCs = currentVmcb->StateSaveArea.SysenterCs;
    targetVmcb->StateSaveArea.SysenterEsp = currentVmcb->StateSaveArea.SysenterEsp;
    targetVmcb->StateSaveArea.SysenterEip = currentVmcb->StateSaveArea.SysenterEip;
    
    NestedSvmUnmapVmcb(targetVmcb);
    
    // 推进 RIP
    NestedSvmAdvanceRip(VcpuData);
    
    return TRUE;
}

// ==================== STGI/CLGI 处理 ====================

BOOLEAN NestedSvmGetVirtualGif(PVCPU_DATA VcpuData)
{
    ULONG cpuIndex;
    
    if (!VcpuData) {
        return TRUE;  // 默认启用中断
    }
    
    cpuIndex = VcpuData->ProcessorNumber;
    if (cpuIndex < MAX_NESTED_SVM_CPU) {
        return g_VirtualGif[cpuIndex];
    }
    return TRUE;  // 超出范围，默认启用
}

VOID NestedSvmSetVirtualGif(PVCPU_DATA VcpuData, BOOLEAN Value)
{
    ULONG cpuIndex;
    
    if (!VcpuData) {
        return;
    }
    
    cpuIndex = VcpuData->ProcessorNumber;
    if (cpuIndex < MAX_NESTED_SVM_CPU) {
        g_VirtualGif[cpuIndex] = Value;
    }
}

BOOLEAN NestedSvmHandleStgi(
    PVCPU_DATA VcpuData,
    PGUEST_CONTEXT GuestContext)
{
    PVMCB vmcb = VcpuData->Vmcb;
    
    // 检查 EFER.SVME
    if (!(vmcb->StateSaveArea.Efer & EFER_SVME)) {
        NestedSvmInjectEvent(VcpuData, 6, SVM_EVENT_TYPE_EXCEPTION, FALSE, 0);
        return TRUE;
    }
    
    // 检查 CPL
    if (vmcb->StateSaveArea.Cpl != 0) {
        NestedSvmInjectEvent(VcpuData, 13, SVM_EVENT_TYPE_EXCEPTION, TRUE, 0);
        return TRUE;
    }
    
    // 设置虚拟 GIF
    NestedSvmSetVirtualGif(VcpuData, TRUE);

#if HV_ENABLE_SVM_HARDENING
    // vGIF 翻为 TRUE 后, 投递 CLGI 期间挂起的中断
    SvmFlushPendingEvents(VcpuData);
#endif

    // 推进 RIP
    NestedSvmAdvanceRip(VcpuData);

    return TRUE;
}

BOOLEAN NestedSvmHandleClgi(
    PVCPU_DATA VcpuData,
    PGUEST_CONTEXT GuestContext)
{
    PVMCB vmcb = VcpuData->Vmcb;
    
    // 检查 EFER.SVME
    if (!(vmcb->StateSaveArea.Efer & EFER_SVME)) {
        NestedSvmInjectEvent(VcpuData, 6, SVM_EVENT_TYPE_EXCEPTION, FALSE, 0);
        return TRUE;
    }
    
    // 检查 CPL
    if (vmcb->StateSaveArea.Cpl != 0) {
        NestedSvmInjectEvent(VcpuData, 13, SVM_EVENT_TYPE_EXCEPTION, TRUE, 0);
        return TRUE;
    }
    
    // 清除虚拟 GIF
    NestedSvmSetVirtualGif(VcpuData, FALSE);
    
    // 推进 RIP
    NestedSvmAdvanceRip(VcpuData);
    
    return TRUE;
}

// ==================== 事件注入 ====================

BOOLEAN NestedSvmInjectEvent(
    PVCPU_DATA VcpuData,
    ULONG Vector,
    ULONG Type,
    BOOLEAN HasErrorCode,
    ULONG ErrorCode)
{
#if HV_ENABLE_SVM_HARDENING
    // 走统一入口 (内部含 vGIF 门控)
    SvmInjectEvent(VcpuData, (UCHAR)Vector, (UCHAR)Type, HasErrorCode, ErrorCode);
#else
    PVMCB vmcb = VcpuData->Vmcb;
    SVM_EVENT_INJECTION event = { 0 };

    event.Vector = Vector;
    event.Type = Type;
    event.ErrorCodeValid = HasErrorCode ? 1 : 0;
    event.Valid = 1;
    event.ErrorCode = ErrorCode;

    vmcb->ControlArea.EventInj = event.Value;
#endif

    return TRUE;
}

// ==================== 辅助函数 ====================

VOID NestedSvmAdvanceRip(PVCPU_DATA VcpuData)
{
    PVMCB vmcb = VcpuData->Vmcb;
    
    // 使用 NRIP 如果可用
    if (vmcb->ControlArea.NRip != 0) {
        vmcb->StateSaveArea.Rip = vmcb->ControlArea.NRip;
    } else {
        // 手动推进（假设指令长度为 3）
        vmcb->StateSaveArea.Rip += 3;
    }
}

// ==================== 调试和统计 ====================

VOID NestedSvmPrintStatus(PVCPU_DATA VcpuData)
{
    PNESTED_SVM_STATE nested = &VcpuData->NestedSvm;
    
    DbgPrint("[HV-NESTED-SVM] CPU %d Status:\n", VcpuData->ProcessorNumber);
    DbgPrint("  SVM Enabled: %s\n", nested->SvmEnabled ? "YES" : "NO");
    DbgPrint("  In L2: %s\n", VcpuData->IsInL2 ? "YES" : "NO");
    DbgPrint("  VMCB GPA: 0x%llX\n", nested->VmcbGpa);
    DbgPrint("  Virtual GIF: %s\n", NestedSvmGetVirtualGif(VcpuData) ? "SET" : "CLEAR");
    DbgPrint("  VMRUN Count: %llu\n", nested->NestedVmrunCount);
    DbgPrint("  L2 Exit Count: %llu\n", nested->L2VmExitCount);
}

VOID NestedSvmPrintStats(VOID)
{
    DbgPrint("[HV-NESTED-SVM] Global Statistics:\n");
    DbgPrint("  Total VMRUN: %lld\n", g_NestedSvmVmrunCount);
    DbgPrint("  Total VM Exit: %lld\n", g_NestedSvmVmExitCount);
    DbgPrint("  Total L2 Exit: %lld\n", g_NestedSvmL2ExitCount);
}
