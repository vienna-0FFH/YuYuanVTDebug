/*
 * HvCompat.h
 *
 * 兼容性头文件 - 提供跨 Windows 版本的 API 兼容性
 *
 * 主要功能：
 *   1. 内存分配 API 兼容性 (ExAllocatePool2 替代 ExAllocatePoolWithTag)
 *   2. 时间查询 API 兼容性
 *   3. 其他已弃用 API 的替代方案
 *
 * 支持的 Windows 版本：
 *   - Windows 10 版本 2004 (Build 19041) 及更高版本 - 使用新 API
 *   - 较旧版本 - 使用旧 API (如果需要兼容)
 */

#ifndef _HV_COMPAT_H_
#define _HV_COMPAT_H_

#pragma once

#include <ntddk.h>

// ============================================================
// 编译时功能开关
// ============================================================

// AMD SVM 路径加固 (ASID 池 / NPT 2TB / vGIF 中断门控 / IOPM-MSRPM 按位 OR 合并)
//
// 默认 OFF: 当前项目主要在 Intel 真机上验证; AMD 路径加固代码完整、可编译、
// 可静态审查，但等到 AMD 真机验证后再启用。开启方法:把下面 0 改成 1，或在
// 项目属性页 PreprocessorDefinitions 加 HV_ENABLE_SVM_HARDENING=1。
//
// 关闭时:AMD 路径保持原有行为 (硬编码 GuestAsid=1, NPT 仅 512GB, vGIF 仅记录,
// IOPM/MSRPM "谁配置用谁的"), 已经在功能上可用，但留有上述四项已知 gap。
#ifndef HV_ENABLE_SVM_HARDENING
#define HV_ENABLE_SVM_HARDENING 0
#endif

// AMD NPT cloaking gate (HvCloak 镜像到 NPT)
// 默认 0:Intel VMX 路径下的 EPT cloak 完整运行,AMD 仍走传统 NPT identity, 无 cloak。
// 待 Intel 完成验证后,把 1 加到此处启用 NPT cloak 镜像实现。
// 当前状态:NPT cloak 代码框架未实现 (Stage 8 占位,见 HvCloak.h 注释)。
#ifndef HV_ENABLE_SVM_CLOAK
#define HV_ENABLE_SVM_CLOAK 0
#endif

// 临时 A/B 测试: 禁用 TSC offset 补偿 (Win11 卡死根因排查 2026-05-30)
//
// = 1: VMCS_CTRL_TSC_OFFSET / VMCB.TscOffset 全程保持 0, guest 直接看到硬件 TSC
//      验证 Win11 卡死是否来自:
//        - per-CPU TSC offset 不同步 (线程迁移看见跳变, spin watchdog 触发)
//        - VMCS_CTRL_TSC_OFFSET 类型混淆 (INT64 → ULONG_PTR 强转)
//        - 缺 MAX_TSC_OFFSET 上限保护导致失控累积
//      代价: 反虚拟检测时序窗口暴露; HWBP 启用时 RDTSC 看得见 VM Exit 开销.
//      因为默认 g_GlobalHwbpRefCount == 0 不启 HWBP, 实际影响几乎为零.
// = 0: 恢复阶段 7.9 原始 TSC 补偿行为
#ifndef HV_DISABLE_TSC_COMPENSATION
#define HV_DISABLE_TSC_COMPENSATION 0
#endif

// 关闭 SLAT (Second-Level Address Translation = EPT/NPT) 完全裸虚拟化
//
// = 1: 不分配 EPT/NPT 表, secondary control 不设 ENABLE_EPT/NpEnable=0,
//      EPTP/NCr3 字段保持 0. Guest 用自己的 CR3 直接做 GVA→PA 翻译,
//      硬件完全旁路第二级翻译. 这是最"裸"的虚拟化:
//        - 没有 hypervisor 控制的内存映射
//        - 没有 EPT violation / NPT fault 可能性
//        - 任何 EPT/NPT Hook 自动失效 (本来 minimal mode 已关)
//        - hypervisor 无法看到 guest 物理访问 (本来就不关心)
//      用途: 排除 EPT/NPT 表本身的配置问题作为 Win11 卡死根因
// = 0: 启用 EPT/NPT 身份映射 (2TB / 512GB), 默认行为
//
// 项目本来就支持 no-SLAT 模式: HvSetupEpt 失败时 EptTables=NULL,
// HvVmcs.c 全部用 if (VcpuData->EptTables) 条件配置. 这里只是显式跳过.
#ifndef HV_DISABLE_SLAT
#define HV_DISABLE_SLAT 0
#endif

// 强制 VMXON 无视 Hypervisor Present (CPUID.01H.ECX[31]=1) (2026-05-30)
//
// 默认 = 0: HvCheckVirtualizationSupport 检测到 bit31=1 时 return FALSE,
//   驱动跳过 VMXON 不进入虚拟化 (项目原始保护逻辑, 防 BSOD)。
//
// = 1: 无视 bit31=1 的报告, 也无视 bit5(VMX)=0 的隐藏, 直接尝试 VMXON。
//   两种结果:
//     a) 进 guest 成功 → 之前 bit31=1 是固件/Defender 残留谎报,
//        VBS 实际没在跑, hypervisor 完全可用。这是我们想要的结论。
//     b) VMXON 立即 #UD 或 #GP → VBS 真的在跑 root mode 占着 VMX, 我们
//        是嵌套调用。结果是立刻 BSOD (0x7E / 0x1E) 或者 hypervisor 把
//        我们注入的 #UD 转给 Windows 内核 → BSOD。
//
// 用途: 当 disable-virtualization.ps1 + BIOS 全关后 CPUID bit31 仍 = 1
//   时, 用此宏验证是固件谎报还是真有 hypervisor。一次性诊断, 不用于生产。
//
// 风险: 真有 hypervisor 时强制 VMXON = 即时 BSOD。务必先备份重要数据,
//   并在调试机 (非生产机) 启用。
#ifndef HV_FORCE_VMX_REGARDLESS_OF_HVPRESENT
#define HV_FORCE_VMX_REGARDLESS_OF_HVPRESENT 0   // 关闭 — 系统已确认能 force 但 vmlaunch 卡死
#endif

// 2026-06-16: per-CPU VMCS setup / vmlaunch 前的诊断输出。
// 启动正常后这些 [HV-DIAG] / [HV] CPU N: ... 日志量很大 (12 核 × 数十行),
// 默认关掉。出问题(vmlaunch fail / #UD)时改回 1 再编。
#ifndef HV_DIAG_VMCS_SETUP
#define HV_DIAG_VMCS_SETUP 0
#endif

// CR4.CET 处理 — 固化为 HyperDbg 风格 (2026-05-31 P0-1)
//
// HyperDbg 范式:GUEST_CR4 = HOST_CR4 = __readcr4() 原样写入,不清 CET bit。
// 总开关 CR4.CET=1,但靠 LOAD_GUEST/HOST_CET_STATE + VMCS CET 字段=0 (VMCLEAR
// 默认) 把 IA32_S_CET 子开关 SH_STK_EN/ENDBR_EN 全清 → CET 子功能不工作。
//
// 历史 (供回滚参考):清 HOST_CR4.CET=0 + 显式 vmwrite HOST_S_CET=0 这组合
// 在某些 CPU 上会触发 vmlaunch 后 ret #UD (g_AsmDebugFlag=11, 0xC000001D),
// 怀疑是 VMCS host state consistency check 把 "CR4.CET=0 + LOAD_HOST_CET_
// STATE=1 + 显式写 HOST_S_CET=0" 判为微架构不一致。
//
// 保留宏 toggle 仅供调试,生产默认锁定为 HyperDbg 风格。
//
// = 1: 保留 HOST_CR4.CET=1 (HyperDbg 风格, 默认)
// = 0: 清 HOST_CR4.CET=0 (历史路径, 在 Win11 24H2 + Alder Lake 触发 #UD)
#ifndef HV_DEBUG_KEEP_HOST_CR4_CET
#define HV_DEBUG_KEEP_HOST_CR4_CET 1
#endif

// = 0: 保留 GUEST_CR4.CET=1 (HyperDbg 风格, 默认)
// = 1: 清 GUEST_CR4.CET=0 (历史路径)
#ifndef HV_DEBUG_CLEAR_GUEST_CR4_CET
#define HV_DEBUG_CLEAR_GUEST_CR4_CET 0
#endif

// ============================================================
// 2026-05-31 新一轮 HyperDbg 范式修复的逐项开关
// 默认全 0 — 由用户上机逐项开启验证, 避免一次性引入多个 P0 改动定位不到 bug。
// ============================================================

// P0-1: HOST_CR3 改用 PsInitialSystemProcess->DirectoryTableBase
// = 0: __readcr3() (原行为)
// = 1: HvUtilsGetSystemCr3() (HyperDbg 范式, 跳过 KVAS shadow CR3 子集)
//
// 现状: 默认 1 — 这是 Win11 卡死的核心修复。之前测试因 movaps 对齐 BSOD
//   和 DPC 异常干扰, 从未干净验证过。现在 movaps 已修 + DPC 已回退, 重新启用。
//   若仍卡死, 贴 dmesg 看 "[HV-Util] System CR3 = ..." 行确认值是否合理。
#ifndef HV_USE_SYSTEM_CR3_FOR_HOST
#define HV_USE_SYSTEM_CR3_FOR_HOST 1
#endif

// P0-4: HOST_IDTR_BASE 用独立 g_HvHostIdt + AsmHostNmiStub / AsmHostMceStub
// = 0: 共享 Windows IDT (__sidt() 拿来用, 原行为)
// = 1: 独立 IDT (替换 vector 2 NMI / 18 #MC 为 Netr stub)
//
// 现状: 默认 0 — 2026-06-01 WeGame 启动触发 bugcheck 0x1AA
// EXCEPTION_ON_INVALID_STACK。AsmHostNmiStub 的 iretq 让 host 栈落在
// 不在 Win11 24H2 KCFG 已知栈范围内,被 KiExceptionDispatchOnExceptionStack
// 抓。关掉此 override 走 Windows 原 IDT, Win11 自己的 NMI handler 能正确
// 派发栈类型, 0x1AA 应消失。
//
// 2026-06-16: 0x1AA 真根因 = host RSP (VmExitStack) 不在任何 Windows 已登记
// 栈区间。彻底修复需配合 HV_USE_HOST_TSS_OVERRIDE = 1 使用独立 host TSS +
// IST 栈,让 NMI/#MC/#DF 硬件切栈到 per-CPU 已登记栈。仅开此宏(不开 TSS
// override) 仍会撞 0x1AA — 历史教训。
//
// 2026-06-16 启用: 默认改 1, 与 HV_USE_HOST_TSS_OVERRIDE 配对生效。
#ifndef HV_USE_HOST_IDT_OVERRIDE
#define HV_USE_HOST_IDT_OVERRIDE 1
#endif

// 2026-06-16: 0x1AA EXCEPTION_ON_INVALID_STACK 全面修复 — host TSS + IST 栈
//
// 启用后:
//   1. DriverEntry 给每核分配独立 HV_KTSS64 + 三段 IST 栈(NMI/#MC/#DF)
//      + 复制 Windows GDT 并改写 TR 描述符 base 指向我们的 TSS。
//   2. HOST_GDTR_BASE / HOST_TR_BASE 改指 per-CPU 数据。
//   3. HV_USE_HOST_IDT_OVERRIDE 配套启用,IDT vector 2/8/18 走 IST 1/3/2。
//   4. Windows 原 GDT/IDT/TSS 完全不改,guest 视角无任何变化。
//
// 不启用 (=0): 走 6/1 后已知"不崩但有暗雷"的路径(共享 Windows IDT/TSS)。
// 启用后失败:直接回退 = 0 即可,不需 git revert。
//
// 2026-06-16 启用: 默认改 1, 实机验证 Win11 24H2 + WeGame/ACE 触发场景。
#ifndef HV_USE_HOST_TSS_OVERRIDE
#define HV_USE_HOST_TSS_OVERRIDE 1
#endif

// IST 栈大小 — 16 KB 容纳 KiNmiInterrupt 嵌套 trap frame (~5 KB) 留 3x 余量。
// 如启用 HV_USE_HOST_TSS_OVERRIDE 后仍偶发 0x1AA 且 Arg3 落在 IST 范围内,
// 改 0x8000 (32 KB)。
#ifndef HV_HOST_IST_STACK_SIZE
#define HV_HOST_IST_STACK_SIZE 0x4000
#endif

// 空壳虚拟化模式 - Win11 卡死根因排查终极隔离 (2026-05-30)
//
// = 1: 关闭所有可选功能子系统, 只保留:
//        - VMX/SVM 启动 + VMLAUNCH/VMRUN
//        - EPT/NPT 身份映射 (2TB / 512GB)
//        - VM Exit 主分发骨架 (CPUID/MSR/VMCALL 透传)
//        - GuestState 保存恢复 (XMM, GPR)
//      关闭的功能:
//        - 所有 Hook (EPT Hook / NPT Hook / Driver/File/Memory/Registry Hide)
//        - 注入框架 (DLL/Shellcode)
//        - HWBP shadow + Debugger
//        - PS/2 + xHCI 输入注入 + xHCI EPT trap
//        - 网络流量伪造
//        - CR3 snoop
//        - VtRoot V2 gadget + 物理访问
//        - PE 头扰乱
//        - 反虚拟检测 (CPUID 隐藏 + MSR fake-0)
//        - MSR Bitmap 拦截 (Phase 2 新增)
//        - 嵌套虚拟化 (Intel + AMD)
//      不影响: Guest 透明运行, VMX/SVM 完全裸跑.
//      用途: 如果 minimal mode 下 Win11 还卡, 问题在 VMX/EPT 骨架本身 (硬件配置错);
//            如果不卡, 问题在某个功能子系统, 二分逐项打开缩小范围.
// = 0: 完整功能模式 (默认未改时项目原始状态)
#ifndef HV_MINIMAL_MODE
#define HV_MINIMAL_MODE 0
#endif

// ============================================================
// 版本检测
// ============================================================

// 检测是否支持 ExAllocatePool2 (Windows 10 2004+)
// NTDDI_WIN10_VB = 0x0A000008 (Windows 10 版本 2004, Build 19041)
#ifndef NTDDI_WIN10_VB
#define NTDDI_WIN10_VB 0x0A000008
#endif

// ============================================================
// 内存分配兼容性宏
// ============================================================

#if (NTDDI_VERSION >= NTDDI_WIN10_VB)

// Windows 10 2004+ - 使用新的 ExAllocatePool2 API
// 这些 API 更安全，默认初始化内存为零

// 分配非分页内存
#define HvAllocateNonPaged(Size, Tag) \
    ExAllocatePool2(POOL_FLAG_NON_PAGED, (Size), (Tag))

// 分配非分页可执行内存 (用于跳板代码等)
// 注意：POOL_FLAG_NON_PAGED_EXECUTE 需要 Windows 10 2004+
// 重要：POOL_FLAG_NON_PAGED_EXECUTE 已隐含非分页属性，必须单独使用！
#ifndef POOL_FLAG_NON_PAGED_EXECUTE
#define POOL_FLAG_NON_PAGED_EXECUTE 0x0000000000000080UI64
#endif

#define HvAllocateNonPagedExecute(Size, Tag) \
    ExAllocatePool2(POOL_FLAG_NON_PAGED_EXECUTE, (Size), (Tag))

// 分配分页内存
#define HvAllocatePaged(Size, Tag) \
    ExAllocatePool2(POOL_FLAG_PAGED, (Size), (Tag))

// 分配零初始化的非分页内存 (ExAllocatePool2 默认行为)
#define HvAllocateNonPagedZeroed(Size, Tag) \
    ExAllocatePool2(POOL_FLAG_NON_PAGED, (Size), (Tag))

#else

// 较旧的 Windows 版本 - 使用旧的 ExAllocatePoolWithTag API
// 警告：这些 API 已弃用，仅用于兼容性

#pragma warning(push)
#pragma warning(disable: 4996) // 禁用弃用警告

// 分配非分页内存
#define HvAllocateNonPaged(Size, Tag) \
    ExAllocatePoolWithTag(NonPagedPool, (Size), (Tag))

// 分配非分页可执行内存
#define HvAllocateNonPagedExecute(Size, Tag) \
    ExAllocatePoolWithTag(NonPagedPoolExecute, (Size), (Tag))

// 分配分页内存
#define HvAllocatePaged(Size, Tag) \
    ExAllocatePoolWithTag(PagedPool, (Size), (Tag))

// 分配零初始化的非分页内存 (需要手动 RtlZeroMemory)
static __forceinline PVOID HvAllocateNonPagedZeroedInternal(SIZE_T Size, ULONG Tag)
{
    PVOID ptr = ExAllocatePoolWithTag(NonPagedPool, Size, Tag);
    if (ptr != NULL) {
        RtlZeroMemory(ptr, Size);
    }
    return ptr;
}
#define HvAllocateNonPagedZeroed(Size, Tag) \
    HvAllocateNonPagedZeroedInternal((Size), (Tag))

#pragma warning(pop)

#endif // NTDDI_VERSION >= NTDDI_WIN10_VB

// ============================================================
// 内存释放宏 (统一接口)
// ============================================================

#define HvFreePool(Ptr, Tag) \
    do { \
        if ((Ptr) != NULL) { \
            ExFreePoolWithTag((Ptr), (Tag)); \
            (Ptr) = NULL; \
        } \
    } while (0)

#define HvFreePoolNonNull(Ptr, Tag) \
    ExFreePoolWithTag((Ptr), (Tag))

// ============================================================
// 时间查询兼容性
// ============================================================

// KeQueryTickCount 已弃用，使用 KeQueryTickCountEx 或其他方法
// 注意：KeQueryTickCountEx 不存在于旧版本 WDK 中

// 使用 KeQueryPerformanceCounter 作为替代方案
static __forceinline LARGE_INTEGER HvQueryTickCount(VOID)
{
    LARGE_INTEGER counter;
    counter = KeQueryPerformanceCounter(NULL);
    return counter;
}

// 获取系统时间（100纳秒为单位）
static __forceinline LARGE_INTEGER HvQuerySystemTime(VOID)
{
    LARGE_INTEGER systemTime;
    KeQuerySystemTimePrecise(&systemTime);
    return systemTime;
}

// 获取一个简单的伪随机数（基于系统时间）
static __forceinline ULONG HvGetPseudoRandom(VOID)
{
    LARGE_INTEGER tick = HvQueryTickCount();
    return (ULONG)(tick.LowPart ^ tick.HighPart);
}

// ============================================================
// 页对齐内存分配
// ============================================================

// 分配页对齐的非分页内存
static __forceinline PVOID HvAllocateAlignedNonPaged(SIZE_T Size, ULONG Tag)
{
    // 使用 MmAllocateContiguousMemory 或 ExAllocatePool2 with alignment
    // 对于大多数情况，我们使用 ExAllocatePool2 分配足够的空间然后对齐
    
    PVOID ptr;
    SIZE_T alignedSize;
    
    // 计算需要的大小（包括对齐开销）
    alignedSize = ROUND_TO_PAGES(Size);
    
#if (NTDDI_VERSION >= NTDDI_WIN10_VB)
    ptr = ExAllocatePool2(POOL_FLAG_NON_PAGED, alignedSize, Tag);
#else
    #pragma warning(push)
    #pragma warning(disable: 4996)
    ptr = ExAllocatePoolWithTag(NonPagedPool, alignedSize, Tag);
    #pragma warning(pop)
#endif
    
    return ptr;
}

// ============================================================
// 原子操作兼容性
// ============================================================

// InterlockedExchange64 在所有 x64 平台上都可用
// 但添加包装以保持一致性

#define HvInterlockedIncrement64(Target) \
    InterlockedIncrement64((volatile LONG64*)(Target))

#define HvInterlockedDecrement64(Target) \
    InterlockedDecrement64((volatile LONG64*)(Target))

#define HvInterlockedExchange64(Target, Value) \
    InterlockedExchange64((volatile LONG64*)(Target), (LONG64)(Value))

#define HvInterlockedExchangeAdd64(Target, Value) \
    InterlockedExchangeAdd64((volatile LONG64*)(Target), (LONG64)(Value))

#define HvInterlockedCompareExchange64(Target, Exchange, Comparand) \
    InterlockedCompareExchange64((volatile LONG64*)(Target), (LONG64)(Exchange), (LONG64)(Comparand))

// ============================================================
// 断言和验证宏
// ============================================================

// 参数验证宏
#define HV_VERIFY_POINTER(Ptr) \
    do { \
        if ((Ptr) == NULL) { \
            return STATUS_INVALID_PARAMETER; \
        } \
    } while (0)

#define HV_VERIFY_POINTER_VOID(Ptr) \
    do { \
        if ((Ptr) == NULL) { \
            return; \
        } \
    } while (0)

#define HV_VERIFY_INITIALIZED(InitFlag) \
    do { \
        if (!(InitFlag)) { \
            return STATUS_UNSUCCESSFUL; \
        } \
    } while (0)

// ============================================================
// 调试辅助
// ============================================================

// 条件断点（仅在调试版本中生效）
#if DBG
#define HV_DEBUG_BREAK() DbgBreakPoint()
#define HV_DEBUG_BREAK_IF(Condition) \
    do { \
        if (Condition) { \
            DbgBreakPoint(); \
        } \
    } while (0)
#else
#define HV_DEBUG_BREAK() ((void)0)
#define HV_DEBUG_BREAK_IF(Condition) ((void)0)
#endif

// ============================================================
// 常量定义
// ============================================================

// 页大小常量
#ifndef PAGE_SIZE_4KB
#define PAGE_SIZE_4KB 0x1000
#endif

#ifndef PAGE_SIZE_2MB
#define PAGE_SIZE_2MB 0x200000
#endif

#ifndef PAGE_SIZE_1GB
#define PAGE_SIZE_1GB 0x40000000
#endif

// 对齐宏
#ifndef ALIGN_UP
#define ALIGN_UP(Value, Alignment) \
    (((Value) + ((Alignment) - 1)) & ~((Alignment) - 1))
#endif

#ifndef ALIGN_DOWN
#define ALIGN_DOWN(Value, Alignment) \
    ((Value) & ~((Alignment) - 1))
#endif

#ifndef IS_ALIGNED
#define IS_ALIGNED(Value, Alignment) \
    (((Value) & ((Alignment) - 1)) == 0)
#endif

#endif // _HV_COMPAT_H_
