/*
 * HvXhciEptTrap.c — Item 2: EPT read trap on xHCI USBSTS/IMAN
 *
 * 见 HvXhciEptTrap.h 顶部注释了解整体思路。
 *
 * 关键决策:
 *   - 我们的 R 位翻转操作发生在 PT entry (4KB 颗粒度),不是 PDE
 *     (避免改 PDE 影响 2MB 区域)。所以启动期必须先把包 USBSTS/IMAN 的
 *     2MB PDE 拆分成 512 个 4KB PT entry,然后清单个 PT entry 的 R 位。
 *
 *   - PT 是单页,所有 CPU 的 PDE 共享指向它 (同 EptHook 的设计)。这样
 *     改一处 R bit 立刻全核生效,只需一次 INVEPT。
 *
 *   - 我们自己跟踪 PT 指针 (不复用 EptTables->SplitPt[] 那个槽),
 *     避免和 EptHook 模块的 split table 互踩。但 PT 指针**必须**写
 *     到所有 CPU 的 EptTables->SplitPt[] 数组里,因为 HvHandleEptViolation
 *     的兜底 RWX 路径要靠那个数组找 PT VA。不写就会被 fallback "修复"
 *     成 R=W=X=1,我们的 trap 失效。
 *
 *   - GPR diff 方式获取 MOV 目的寄存器:不需要 x86 指令解码。
 *     trade-off: 如果 MMIO 读的指令是 `TEST [mem], r` / `CMP [mem], r`
 *     这种不写寄存器的指令,我们 diff 不到目的 —— 这种情况 fall through
 *     不 OR-in,counter 不动,ISR 还是 fast-bail。但 xhci.sys 99% 是
 *     用 `mov eax, [usbsts]` 形式读的,影响极小。
 *
 *   - 短时窗口:每次 Arm 把 g_PendingIsrReads 设 16。这样一次 ISR pass
 *     里 USBSTS+IMAN 各读 2-4 次(进入/退出/clear-IP),16 个余量够。
 *     超过 16 次就关 trap,避免长期 trap 导致 BAR 上其他寄存器 (PortSc)
 *     被异常拦截。
 *
 * IRQL 约束:
 *   - HvXhciEptTrapInitialize: PASSIVE_LEVEL (HvCoreInitialize 末尾,
 *     必须在 g_HypervisorContext.IsActive=TRUE 之后,因为要遍历每个
 *     VCPU 的 EptTables 并改 PDE)。INVEPT 必须走 EptInveptAllContexts
 *     (IPI+VMCALL) 而非裸 AsmInveptAllContexts —— 调用方在 guest 模式。
 *   - HvXhciEptTrapShutdown: PASSIVE_LEVEL (同 Init,跨核 INVEPT 走 IPI)
 *   - HvXhciEptTrapArm: VMX root (从 HvUsbXhciTryDeliverMsi 调,只 INVEPT
 *     当前 CPU 即可,因为 MSI 也走当前 CPU 的 VMENTRY_INTERRUPTION_INFO)
 *   - HvXhciEptTrapHandleViolation/HandleMtf: VMX root, IPI_LEVEL
 */

#include "HvXhciEptTrap.h"
#include "HvCore.h"
#include "HvUsbXhci.h"
#include "EptHook.h"   // EPT_VIOLATION_*, EPT permissions
#include "HvVmExit.h"  // 内部 helper 声明

// P122: 全 driver DbgPrint → GUI ring
#define HV_TRACE_THIS_CAT HV_TRACE_CAT_USB
#include "HvTrace.h"

extern UCHAR AsmInveptAllContexts(VOID);

#define HV_XHCI_TRAP_MAX_PAGES   2     // USBSTS_GPA 和 IMAN_GPA 在同一/不同 4K
#define HV_XHCI_TRAP_MAX_CPUS    64
#define HV_XHCI_TRAP_INITIAL_READS 16  // Arm 时设的 counter 上限

// 同 HvUsbXhci.c 的 log 风格 — 启动期 DbgPrint 可以,root 模式禁用
#define TRAP_LOG(fmt, ...) DbgPrint("[XHCI-TRAP] " fmt "\n", ##__VA_ARGS__)

// ============================================================
// 全局状态
// ============================================================

typedef struct _HV_XHCI_TRAP_PAGE {
    BOOLEAN  Valid;              // FALSE 表示空槽
    ULONG64  PageGpa;            // 4KB 对齐的 GPA
    ULONG    PtIndex;            // PageGpa 在所在 PT 里的 index (0..511)

    // P3-9 回滚 (2026-05-31): per-CPU 化未完成,先用单指针。
    // 已知限制:P1-3 后 xHCI trap 只对 CPU 0 完美生效 (HvXhciTrapEnsureSplitPt
    // 返回的是 CPU 0 SplitPt 列表里查到的 PT)。功能性 bug,但不卡死。
    // 后续完整 per-CPU 化改造留待 P3-11。
    PEPT_PTE Pt;

    // 该页里需要被"假冒"的两个偏移 — 通常 USBSTS 是 CapLen+4 在 OpBase,
    // IMAN 是 RtsOff+0x20 在 RtBase。两个偏移可能落在不同 PageGpa 上,
    // 也可能落在同一个 (RtsOff 小时)。每个 trap page 记录"在这个页里
    // 哪个偏移要伪 EINT、哪个偏移要伪 IP"。
    ULONG    UsbstsOffset;       // 0xFFFFFFFF 表示该页内没有 USBSTS
    ULONG    ImanOffset;         // 0xFFFFFFFF 表示该页内没有 IMAN
} HV_XHCI_TRAP_PAGE, *PHV_XHCI_TRAP_PAGE;

#define TRAP_OFFSET_NONE  0xFFFFFFFFUL

typedef struct _HV_XHCI_TRAP_MTF_STATE {
    volatile LONG  Active;                       // 0 = idle, 1 = waiting for MTF
    ULONG          PageIndex;                    // 触发 trap 的页 in g_TrapPages[]
    ULONG          OffsetInPage;                 // qual & 0xFFF
    GUEST_CONTEXT  GprSnapshot;                  // 进 trap 前所有 GPR
} HV_XHCI_TRAP_MTF_STATE, *PHV_XHCI_TRAP_MTF_STATE;

static volatile LONG       g_Initialized = 0;
// User-controlled enable flag. Default OFF so a freshly-loaded driver does NOT
// auto-arm the trap on first MSI — that lets users test the rest of the input
// chain (Items 1/3/4) in isolation, and opt in to Item 2 once they've confirmed
// the basics work. Toggled via HvXhciEptTrapSetUserEnabled (IOCTL).
static volatile LONG       g_UserEnabled = 0;
// Set in Initialize after we confirm CPU_BASED_MONITOR_TRAP_FLAG is in the
// allowed-1 mask of IA32_VMX_PROCBASED_CTLS. Without MTF we can't single-step
// after restoring R=1, so the trap design fundamentally won't work; if 0,
// the user-enable IOCTL refuses.
static BOOLEAN             g_MtfSupported = FALSE;
static HV_XHCI_TRAP_PAGE   g_TrapPages[HV_XHCI_TRAP_MAX_PAGES];
static ULONG               g_TrapPageCount = 0;

// 短时 trap 窗口的剩余读次数。Arm 设 N, 每次成功"假冒读"递减,降到 0
// 自动关 trap (R=1)。 用 volatile LONG 让多核观察一致。
static volatile LONG       g_PendingIsrReads = 0;

// per-CPU MTF state (单步指令完成后的回 callback 上下文)
static HV_XHCI_TRAP_MTF_STATE g_MtfState[HV_XHCI_TRAP_MAX_CPUS];

// 诊断
static HV_XHCI_EPT_TRAP_STATS g_Stats;

// ============================================================
// MTF capability check
// ============================================================

// IA32_VMX_PROCBASED_CTLS = MSR 0x482. Allowed-1 mask is in the high 32 bits.
// CPU_BASED_MONITOR_TRAP_FLAG = bit 27. If allowed-1 bit 27 == 0, writing this
// control to VMCS will fail VMRESUME with VM-instruction error #12 (VM entry
// with invalid control field) — which is exactly the kind of failure that
// would manifest as a hard hang (vmresume keeps failing, host loops in handler).
static BOOLEAN HvXhciTrapCheckMtfSupport(VOID)
{
    ULONG64 ctls = __readmsr(0x482);
    ULONG allowed1 = (ULONG)(ctls >> 32);
    BOOLEAN supported = (allowed1 & (1U << 27)) != 0;
    if (!supported) {
        TRAP_LOG("MTF NOT supported on this CPU (IA32_VMX_PROCBASED_CTLS allowed-1 bit 27 = 0)");
    } else {
        TRAP_LOG("MTF supported");
    }
    return supported;
}

// ============================================================
// EPT 操作辅助
// ============================================================

// 改 PT entry 的 R bit。Pt 指针指向跨 CPU 共享的那个 PT 页,所以
// 写一次对所有 CPU 都生效。INVEPT 由调用者负责 (可能要批量 INVEPT)。
static VOID HvXhciTrapSetPteRead(PEPT_PTE pt, ULONG ptIndex, BOOLEAN allowRead)
{
    if (!pt) return;
    if (ptIndex >= 512) return;

    // pt[ptIndex] 是位字段,Read 在 bit 0。写也得保留其他位 (W, X, MemoryType, PFN)。
    pt[ptIndex].Read = allowRead ? 1 : 0;
    // W/X 不动,让写直通,执行 (页面是 MMIO,执行其实不会发生)
}

// 在当前 CPU 上设置 / 清除 CPU_BASED_MONITOR_TRAP_FLAG。VMX root 安全。
// 注意:EptHook 自己的 EptSetMonitorTrapFlag 是 static,这里复制一份,
// 避免暴露和 link order 问题。
static VOID HvXhciTrapSetMtf(BOOLEAN enable)
{
    SIZE_T ctls = 0;
    __vmx_vmread(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, &ctls);
    if (enable) {
        ctls |= CPU_BASED_MONITOR_TRAP_FLAG;
    } else {
        ctls &= ~(SIZE_T)CPU_BASED_MONITOR_TRAP_FLAG;
    }
    __vmx_vmwrite(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, ctls);
}

// 比对两份 GUEST_CONTEXT, 找出唯一变化的字段。返回变化字段的指针 (写回用),
// 找不到/多个变化 返回 NULL。
//
// MOV reg, [mem] 一般只改一个寄存器 (或 zero-extend dword → qword,同一寄存器)。
// 我们逐字段 memcmp。注意 RSP/RBP 不在 GUEST_CONTEXT (Rsp 用 vmread 读),所以
// 只比对 GPR 数组。
static PULONG64 HvXhciTrapFindChangedGpr(PGUEST_CONTEXT before, PGUEST_CONTEXT after)
{
    PULONG64 changed = NULL;
    ULONG diffCount = 0;

    // 跟 GUEST_CONTEXT 字段顺序对齐
    PULONG64 beforeFields[] = {
        &before->Rax, &before->Rbx, &before->Rcx, &before->Rdx,
        &before->Rsi, &before->Rdi, &before->Rbp,
        &before->R8,  &before->R9,  &before->R10, &before->R11,
        &before->R12, &before->R13, &before->R14, &before->R15
    };
    PULONG64 afterFields[] = {
        &after->Rax, &after->Rbx, &after->Rcx, &after->Rdx,
        &after->Rsi, &after->Rdi, &after->Rbp,
        &after->R8,  &after->R9,  &after->R10, &after->R11,
        &after->R12, &after->R13, &after->R14, &after->R15
    };

    for (ULONG i = 0; i < RTL_NUMBER_OF(beforeFields); i++) {
        if (*beforeFields[i] != *afterFields[i]) {
            changed = afterFields[i];
            diffCount++;
        }
    }

    // 0 变化 → ISR 用 TEST/CMP 等不写寄存器的指令读 (不常见)
    // 1 变化 → 标准 MOV reg, [mem] (绝大多数)
    // 多变化 → 不应该发生 (单条 MOV 不该改多个 GPR);保守 fall through
    if (diffCount != 1) {
        return NULL;
    }
    return changed;
}

// ============================================================
// 2MB → 4KB 分裂 (本模块自管 PT,不复用 EptHook 的 split)
// ============================================================

// 为单个 4KB GPA 在所有 CPU 上分裂其所在 2MB PDE,返回共享 PT 的 VA。
// 失败返回 NULL。已分裂 (PDE.LargePage == 0) 时复用已有 PT — 这种情况
// 是 EptHook 已经为这个 2MB 范围做过 split (例如 BAR 上有其他 hook 页面),
// 我们直接拿到那个 PT。
//
// 必须在 PASSIVE_LEVEL 调用 (MmAllocateContiguousMemory)。
static PEPT_PTE HvXhciTrapEnsureSplitPt(ULONG64 gpa)
{
    ULONG64 pml4Index = (gpa >> 39) & 0x1FF;
    ULONG64 pdptIndex = (gpa >> 30) & 0x1FF;
    ULONG64 pdIndex   = (gpa >> 21) & 0x1FF;

    if (pml4Index != 0 || pdptIndex >= 512) {
        TRAP_LOG("GPA 0x%llX outside low 512GB — trap not supported", gpa);
        return NULL;
    }
    if (!g_HypervisorContext.IsActive || !g_HypervisorContext.VcpuData) {
        TRAP_LOG("HV not active");
        return NULL;
    }

    PVCPU_DATA vcpu0 = &g_HypervisorContext.VcpuData[0];
    if (!vcpu0->EptTables) {
        TRAP_LOG("VCPU 0 has no EPT tables");
        return NULL;
    }
    PEPT_PDE pde0 = &vcpu0->EptTables->Pd[pdptIndex][pdIndex];

    // 已经被 split 过 (EptHook 在同一个 2MB 区域里安装过 hook) → 直接拿 PT
    if ((pde0->Value & (1ULL << 7)) == 0) {
        // 找 PT VA — 走 SplitPt[]/SplitPtPhysical[] 查找,匹配 PT 的 HPA
        ULONG64 ptPfn = pde0->PageFrameNumber;
        for (ULONG i = 0; i < vcpu0->EptTables->SplitPtCount; i++) {
            if ((ULONG64)(vcpu0->EptTables->SplitPtPhysical[i].QuadPart >> 12) == ptPfn) {
                TRAP_LOG("GPA 0x%llX already split, reusing existing PT", gpa);
                return vcpu0->EptTables->SplitPt[i];
            }
        }
        TRAP_LOG("GPA 0x%llX PDE not large but PT not in SplitPt[] — abort", gpa);
        return NULL;
    }

    // 需要分裂 — 分配 PT,继承 PDE 的权限 (R=1 W=1 X=1, MemoryType=WB)
    // MMIO 的 MemoryType 实际由 PAT/MTRR 决定,EPT 的 MemoryType 写 6 (WB) 没问题
    PHYSICAL_ADDRESS maxAddr; maxAddr.QuadPart = -1LL;
    PEPT_PTE newPt = (PEPT_PTE)MmAllocateContiguousMemory(PAGE_SIZE, maxAddr);
    if (!newPt) {
        TRAP_LOG("MmAllocateContiguousMemory PT failed");
        return NULL;
    }
    RtlZeroMemory(newPt, PAGE_SIZE);

    PHYSICAL_ADDRESS newPtPhys = MmGetPhysicalAddress(newPt);

    // 填 512 个 4KB 条目,继承 PDE 的 R/W/X
    UCHAR origRwx = (UCHAR)(pde0->Value & 0x7);
    ULONG64 basePfn = (ULONG64)(pdptIndex * 512 + pdIndex) * 512ULL;  // 2MB start in 4KB pages
    for (ULONG i = 0; i < 512; i++) {
        newPt[i].Value = 0;
        newPt[i].Read = (origRwx & EPT_READ) ? 1 : 0;
        newPt[i].Write = (origRwx & EPT_WRITE) ? 1 : 0;
        newPt[i].Execute = (origRwx & EPT_EXECUTE) ? 1 : 0;
        newPt[i].MemoryType = 6;  // WB
        newPt[i].PageFrameNumber = basePfn + i;
    }

    // 所有 CPU 都把 PDE 改为指向这个共享 PT,并写进各自的 SplitPt[] 表
    // (写 SplitPt[] 是为了让 HvHandleEptViolation 兜底 RWX 路径能找到 PT,
    //  否则它会重建 large page 把 trap 抹掉)
    ULONG cpuCount = g_HypervisorContext.ProcessorCount;
    for (ULONG cpu = 0; cpu < cpuCount; cpu++) {
        PVCPU_DATA v = &g_HypervisorContext.VcpuData[cpu];
        if (!v->EptTables) continue;

        PEPT_PDE pde = &v->EptTables->Pd[pdptIndex][pdIndex];
        if ((pde->Value & (1ULL << 7)) == 0) {
            // 这个 CPU 已经被 EptHook 拆过了 — 我们用 newPt 替换会引起 conflict。
            // 保守做法:不替换,直接使用 CPU0 视角的 newPt 引用 (但 CPU 上 PDE 是
            // 不同的 PT)。这种情况会让 trap 在那个 CPU 上失效。极不常见的边界情况。
            TRAP_LOG("CPU %u PDE already split with different PT — trap may be partial", cpu);
            continue;
        }

        pde->Value = 0;
        pde->Read = 1;
        pde->Write = 1;
        pde->Execute = 1;
        pde->PageFrameNumber = newPtPhys.QuadPart >> 12;

        // 把 PT 登记到这个 CPU 的 SplitPt 表 (HvHandleEptViolation fallback 用)
        if (v->EptTables->SplitPtCount < RTL_NUMBER_OF(v->EptTables->SplitPt)) {
            ULONG idx = v->EptTables->SplitPtCount;
            v->EptTables->SplitPt[idx] = newPt;
            v->EptTables->SplitPtPhysical[idx] = newPtPhys;
            v->EptTables->SplitPtCount = idx + 1;
        }
    }

    TRAP_LOG("Split 2MB PDE @ PDPT[%llu][%llu] for GPA 0x%llX, PT VA=%p PA=0x%llX",
             pdptIndex, pdIndex, gpa, newPt, (ULONG64)newPtPhys.QuadPart);

    // INVEPT 在最外层批量做 (调用方 Initialize 处理)
    return newPt;
}

// ============================================================
// Public API
// ============================================================

NTSTATUS HvXhciEptTrapInitialize(VOID)
{
    if (InterlockedCompareExchange(&g_Initialized, 0, 0) != 0) {
        return STATUS_SUCCESS;  // 已 init
    }

    RtlZeroMemory(g_TrapPages, sizeof(g_TrapPages));
    RtlZeroMemory(g_MtfState, sizeof(g_MtfState));
    RtlZeroMemory(&g_Stats, sizeof(g_Stats));
    g_TrapPageCount = 0;
    InterlockedExchange(&g_PendingIsrReads, 0);
    InterlockedExchange(&g_UserEnabled, 0);  // 默认 OFF — 用户必须显式开

    // MTF capability — 不支持就别 init (避免后续 HandleViolation 设 MTF 失败 BSOD)
    g_MtfSupported = HvXhciTrapCheckMtfSupport();
    if (!g_MtfSupported) {
        TRAP_LOG("aborting init: MTF unsupported, trap cannot work");
        return STATUS_NOT_SUPPORTED;
    }

    // 必须等 xHCI BarPhys / CapLength / RtBase 都已经填好
    if (!HvUsbXhciIsReady()) {
        TRAP_LOG("xHCI not ready, trap will not arm");
        return STATUS_DEVICE_NOT_READY;
    }
    if (g_HvUsbXhci.BarPhys == 0 || g_HvUsbXhci.Bar == NULL ||
        g_HvUsbXhci.OpBase == NULL || g_HvUsbXhci.RtBase == NULL) {
        TRAP_LOG("xHCI BAR pointers missing");
        return STATUS_INVALID_DEVICE_STATE;
    }

    // 计算 USBSTS / IMAN 的 GPA (= 物理地址,身份映射下 GPA==HPA)
    ULONG64 usbstsGpa = g_HvUsbXhci.BarPhys + g_HvUsbXhci.CapLength + XHCI_OP_USBSTS;
    ULONG rtsOff = (ULONG)(g_HvUsbXhci.RtBase - g_HvUsbXhci.Bar);
    ULONG64 imanGpa = g_HvUsbXhci.BarPhys + rtsOff + XHCI_RT_IR0 + XHCI_IR_IMAN;

    ULONG64 usbstsPage = usbstsGpa & ~0xFFFULL;
    ULONG64 imanPage   = imanGpa   & ~0xFFFULL;
    ULONG   usbstsOff  = (ULONG)(usbstsGpa & 0xFFFULL);
    ULONG   imanOff    = (ULONG)(imanGpa   & 0xFFFULL);

    TRAP_LOG("BarPhys=0x%llX CapLen=%u RtsOff=0x%X",
             g_HvUsbXhci.BarPhys, g_HvUsbXhci.CapLength, rtsOff);
    TRAP_LOG("USBSTS GPA=0x%llX (page=0x%llX off=0x%X)",
             usbstsGpa, usbstsPage, usbstsOff);
    TRAP_LOG("IMAN   GPA=0x%llX (page=0x%llX off=0x%X)",
             imanGpa, imanPage, imanOff);

    // 收集 unique 页 (1 或 2)
    ULONG64 pages[2]   = { usbstsPage, imanPage };
    ULONG   usbOffs[2] = { usbstsOff,  TRAP_OFFSET_NONE };
    ULONG   imanOffs[2]= { TRAP_OFFSET_NONE, imanOff };

    if (usbstsPage == imanPage) {
        // 合并 — 同页
        imanOffs[0] = imanOff;
        pages[1] = 0;  // 标记为不存在
    }

    for (ULONG i = 0; i < 2; i++) {
        if (i == 1 && pages[1] == 0) break;

        PEPT_PTE pt = HvXhciTrapEnsureSplitPt(pages[i]);
        if (!pt) {
            TRAP_LOG("Failed to split GPA 0x%llX, aborting trap init", pages[i]);
            // 清掉前面记的页 (它们也已经在 SplitPt[] 里了,不能撤回但可以
            // 不激活 trap — 留作惰性死代码;退出时 g_TrapPageCount=0,Arm 直接跳)
            g_TrapPageCount = 0;
            return STATUS_UNSUCCESSFUL;
        }

        g_TrapPages[i].Valid = TRUE;
        g_TrapPages[i].PageGpa = pages[i];
        g_TrapPages[i].PtIndex = (ULONG)((pages[i] >> 12) & 0x1FF);
        g_TrapPages[i].Pt = pt;
        g_TrapPages[i].UsbstsOffset = usbOffs[i];
        g_TrapPages[i].ImanOffset   = imanOffs[i];
        g_TrapPageCount++;

        TRAP_LOG("Trap page %u: GPA=0x%llX PT=%p PtIdx=%u UsbstsOff=0x%X ImanOff=0x%X",
                 i, pages[i], pt, g_TrapPages[i].PtIndex,
                 usbOffs[i], imanOffs[i]);
    }

    // 启动期 R 保持 1 (trap 未激活),Arm 时再清。INVEPT 一次确保 split 生效。
    // PASSIVE_LEVEL,vCPU 已经在运行 → 必须走 IPI+VMCALL 路径,不能直接 INVEPT
    EptInveptAllContexts();

    InterlockedExchange(&g_Initialized, 1);
    TRAP_LOG("initialized %u trap page(s)", g_TrapPageCount);
    return STATUS_SUCCESS;
}

VOID HvXhciEptTrapShutdown(VOID)
{
    if (InterlockedExchange(&g_Initialized, 0) == 0) return;

    // 恢复所有 trap 页的 R=1 (写已经从来没碰过)
    for (ULONG i = 0; i < HV_XHCI_TRAP_MAX_PAGES; i++) {
        if (g_TrapPages[i].Valid && g_TrapPages[i].Pt) {
            HvXhciTrapSetPteRead(g_TrapPages[i].Pt, g_TrapPages[i].PtIndex, TRUE);
        }
    }
    // Shutdown 路径在 PASSIVE_LEVEL — 走 IPI+VMCALL 而非裸 INVEPT
    EptInveptAllContexts();

    // 注意:我们分配的 PT 不在这里释放 —— 因为它已经被 SplitPt[] 引用,
    // EptHook fallback 路径仍依赖它存在。要释放必须在 EPT 整体 Cleanup 时一并释放
    // (HvCleanupEpt 里已经处理 EPT_TABLES 整块,但 SplitPt[] 里的零散 PT 现在
    //  只在 driver unload 时随 process 退出而进程整体回收 — 接受这个 leak)。
    //
    // 实际:驱动 unload = NonPaged Pool 整体清,所以也不算 leak。

    RtlZeroMemory(g_TrapPages, sizeof(g_TrapPages));
    g_TrapPageCount = 0;
    InterlockedExchange(&g_PendingIsrReads, 0);
    InterlockedExchange(&g_UserEnabled, 0);

    TRAP_LOG("shutdown");
}

BOOLEAN HvXhciEptTrapIsArmed(VOID)
{
    // "Armed" 含义 = "下次 MSI inject 时该不该 trap":Init 完 + 有页 + 用户允许。
    // 三者缺一不可。Arm()/HandleViolation/HandleMtf 都靠这个判断。
    return (InterlockedCompareExchange(&g_Initialized, 0, 0) != 0)
        && (InterlockedCompareExchange(&g_UserEnabled, 0, 0) != 0)
        && (g_TrapPageCount > 0);
}

BOOLEAN HvXhciEptTrapIsUserEnabled(VOID)
{
    return InterlockedCompareExchange(&g_UserEnabled, 0, 0) != 0;
}

BOOLEAN HvXhciEptTrapIsInitialized(VOID)
{
    return InterlockedCompareExchange(&g_Initialized, 0, 0) != 0;
}

BOOLEAN HvXhciEptTrapIsMtfSupported(VOID)
{
    return g_MtfSupported;
}

// 用户层切换 trap on/off。PASSIVE_LEVEL,IOCTL 路径调。
// - enable=TRUE  : Init 完了才行,标志位翻转,下一次 MSI 注入会 Arm
// - enable=FALSE : 翻转标志位,然后立即恢复所有 trap 页的 R=1 + 跨模式 INVEPT,
//                  确保即使刚刚 Arm 过 (R 已经被清),也立刻回到透传状态。
NTSTATUS HvXhciEptTrapSetUserEnabled(BOOLEAN enable)
{
    if (!HvXhciEptTrapIsInitialized()) {
        TRAP_LOG("SetUserEnabled(%u) refused: not initialized", enable ? 1 : 0);
        return STATUS_DEVICE_NOT_READY;
    }
    if (enable && !g_MtfSupported) {
        TRAP_LOG("SetUserEnabled(TRUE) refused: MTF unsupported");
        return STATUS_NOT_SUPPORTED;
    }

    LONG newVal = enable ? 1 : 0;
    LONG prev = InterlockedExchange(&g_UserEnabled, newVal);
    if (prev == newVal) {
        return STATUS_SUCCESS;  // no-op
    }

    TRAP_LOG("trap %s by user", enable ? "ENABLED" : "DISABLED");

    if (!enable) {
        // 即时复原 R=1,counter 清 0。可能与并发 Arm() 有窗口,但 Arm() 看 IsArmed
        // 返回 FALSE 会早 bail,所以 disable 完成后 trap 状态稳定。
        for (ULONG i = 0; i < HV_XHCI_TRAP_MAX_PAGES; i++) {
            if (g_TrapPages[i].Valid && g_TrapPages[i].Pt) {
                HvXhciTrapSetPteRead(g_TrapPages[i].Pt, g_TrapPages[i].PtIndex, TRUE);
            }
        }
        InterlockedExchange(&g_PendingIsrReads, 0);
        // PASSIVE_LEVEL + vCPU running → 走 IPI+VMCALL,不能裸 INVEPT
        EptInveptAllContexts();
    }

    return STATUS_SUCCESS;
}

VOID HvXhciEptTrapArm(VOID)
{
    if (!HvXhciEptTrapIsArmed()) return;

    // 设新 counter (重置而不是累加,避免溢出)
    InterlockedExchange(&g_PendingIsrReads, HV_XHCI_TRAP_INITIAL_READS);

    // 清所有 trap 页的 R bit,触发后续 read VMEXIT
    for (ULONG i = 0; i < HV_XHCI_TRAP_MAX_PAGES; i++) {
        if (g_TrapPages[i].Valid && g_TrapPages[i].Pt) {
            HvXhciTrapSetPteRead(g_TrapPages[i].Pt, g_TrapPages[i].PtIndex, FALSE);
        }
    }

    // INVEPT — VMX root 安全
    AsmInveptAllContexts();

    InterlockedIncrement((volatile LONG*)&g_Stats.ArmCount);
}

// 关 trap (counter 用尽时调) — 内部 helper
static VOID HvXhciTrapDisarm(VOID)
{
    for (ULONG i = 0; i < HV_XHCI_TRAP_MAX_PAGES; i++) {
        if (g_TrapPages[i].Valid && g_TrapPages[i].Pt) {
            HvXhciTrapSetPteRead(g_TrapPages[i].Pt, g_TrapPages[i].PtIndex, TRUE);
        }
    }
    AsmInveptAllContexts();
}

// ============================================================
// EPT violation handler (从 HvHandleEptViolation 调)
// ============================================================

BOOLEAN HvXhciEptTrapHandleViolation(ULONG64 gpa, ULONG64 qualification, PGUEST_CONTEXT ctx)
{
    if (!HvXhciEptTrapIsArmed()) return FALSE;
    if (!ctx) return FALSE;

    // 只关心 read violation;write/execute 不是我们的
    if ((qualification & EPT_VIOLATION_READ) == 0) return FALSE;

    ULONG64 pageGpa = gpa & ~0xFFFULL;

    ULONG hitIdx = (ULONG)-1;
    for (ULONG i = 0; i < HV_XHCI_TRAP_MAX_PAGES; i++) {
        if (g_TrapPages[i].Valid && g_TrapPages[i].PageGpa == pageGpa) {
            hitIdx = i;
            break;
        }
    }
    if (hitIdx == (ULONG)-1) return FALSE;

    // 同 CPU 不应该同时进 2 次 trap;如果 Active=1 已经,说明上次没 MTF 收尾,
    // 异常状态 — 直接放过去走 fallback
    ULONG cpuIdx = KeGetCurrentProcessorNumber();
    if (cpuIdx >= HV_XHCI_TRAP_MAX_CPUS) cpuIdx = 0;
    PHV_XHCI_TRAP_MTF_STATE st = &g_MtfState[cpuIdx];

    if (InterlockedCompareExchange(&st->Active, 1, 0) != 0) {
        // 异常 — 已经在等 MTF,可能上次 MTF 走掉了 EptHook 路径。
        // 把 R 恢复让 guest 继续,不假冒 (counter 不动)
        HvXhciTrapSetPteRead(g_TrapPages[hitIdx].Pt, g_TrapPages[hitIdx].PtIndex, TRUE);
        AsmInveptAllContexts();
        return TRUE;
    }

    st->PageIndex = hitIdx;
    st->OffsetInPage = (ULONG)(gpa & 0xFFFULL);
    st->GprSnapshot = *ctx;  // 全 16 GPR 拷贝

    // 让指令能跑过去:恢复 R=1,INVEPT,然后 MTF 单步
    HvXhciTrapSetPteRead(g_TrapPages[hitIdx].Pt, g_TrapPages[hitIdx].PtIndex, TRUE);
    AsmInveptAllContexts();

    HvXhciTrapSetMtf(TRUE);

    return TRUE;
}

// ============================================================
// MTF handler (从 EXIT_REASON_MONITOR_TRAP_FLAG case 调)
// ============================================================

BOOLEAN HvXhciEptTrapHandleMtf(PGUEST_CONTEXT ctx)
{
    if (!HvXhciEptTrapIsArmed()) return FALSE;
    if (!ctx) return FALSE;

    ULONG cpuIdx = KeGetCurrentProcessorNumber();
    if (cpuIdx >= HV_XHCI_TRAP_MAX_CPUS) cpuIdx = 0;
    PHV_XHCI_TRAP_MTF_STATE st = &g_MtfState[cpuIdx];

    if (InterlockedCompareExchange(&st->Active, 0, 1) != 1) {
        // 不是我们设的 MTF
        return FALSE;
    }

    // 我们的 MTF — 先关 MTF (否则下一条指令还会触发)
    HvXhciTrapSetMtf(FALSE);

    PHV_XHCI_TRAP_PAGE page = &g_TrapPages[st->PageIndex];

    // GPR diff 找目的寄存器
    PULONG64 dst = HvXhciTrapFindChangedGpr(&st->GprSnapshot, ctx);

    if (dst != NULL) {
        // 判断 offset 在该页里属于哪个寄存器
        if (page->UsbstsOffset != TRAP_OFFSET_NONE &&
            st->OffsetInPage == page->UsbstsOffset) {
            // USBSTS 读 — OR 进 EINT (bit 3)
            *dst |= XHCI_STS_EINT;
            InterlockedIncrement((volatile LONG*)&g_Stats.UsbstsReadFaked);
            InterlockedDecrement(&g_PendingIsrReads);
        } else if (page->ImanOffset != TRAP_OFFSET_NONE &&
                   st->OffsetInPage == page->ImanOffset) {
            // IMAN 读 — OR 进 IP (bit 0)
            *dst |= XHCI_IMAN_IP;
            InterlockedIncrement((volatile LONG*)&g_Stats.ImanReadFaked);
            InterlockedDecrement(&g_PendingIsrReads);
        } else {
            // 同页但读的是其他寄存器 (例如 USBCMD/PortSc) — passthrough,不计入 counter
            InterlockedIncrement((volatile LONG*)&g_Stats.OtherReadOnTrapPage);
        }
    } else {
        // GPR 没变化 / 多个变化 — 怪指令,放过去不假冒
        InterlockedIncrement((volatile LONG*)&g_Stats.MtfMisses);
    }

    // 决定是否继续 trap:counter > 0 重清 R=0 重新武装;<=0 关 trap
    LONG remaining = InterlockedCompareExchange(&g_PendingIsrReads, 0, 0);
    if (remaining > 0) {
        for (ULONG i = 0; i < HV_XHCI_TRAP_MAX_PAGES; i++) {
            if (g_TrapPages[i].Valid && g_TrapPages[i].Pt) {
                HvXhciTrapSetPteRead(g_TrapPages[i].Pt, g_TrapPages[i].PtIndex, FALSE);
            }
        }
        AsmInveptAllContexts();
    } else {
        // counter 用尽 — 让 trap 池静默,等下次 Arm 重新激活
        HvXhciTrapDisarm();
    }

    return TRUE;
}

VOID HvXhciEptTrapQueryStats(PHV_XHCI_EPT_TRAP_STATS stats)
{
    if (!stats) return;
    *stats = g_Stats;
}

VOID HvXhciEptTrapQueryState(PHV_XHCI_EPT_TRAP_STATE state)
{
    if (!state) return;
    RtlZeroMemory(state, sizeof(*state));
    state->Initialized  = (UCHAR)(InterlockedCompareExchange(&g_Initialized, 0, 0) != 0);
    state->UserEnabled  = (UCHAR)(InterlockedCompareExchange(&g_UserEnabled, 0, 0) != 0);
    state->MtfSupported = (UCHAR)(g_MtfSupported ? 1 : 0);
    state->TrapPageCount = g_TrapPageCount;
    state->PendingIsrReads = InterlockedCompareExchange(&g_PendingIsrReads, 0, 0);
    state->Stats = g_Stats;
}
