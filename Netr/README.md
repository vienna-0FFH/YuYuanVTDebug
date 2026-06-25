# Netr Hypervisor

> 一个功能完整的 Windows 内核模式 Type-1 Hypervisor 框架，支持 Intel VMX 与 AMD SVM 双平台，覆盖嵌套虚拟化、EPT/NPT 隐身 Hook、透明硬件断点、xHCI USB HID 注入、KVAS 影子映射兼容、无痕物理内存访问等高级能力。本项目当前处于 Phase 8 阶段，目标是在 Win10 1709 → Win11 25H2 全主线上稳定运行。

---

## ⚠️ 安全与法律警告（必读）

1. **本项目仅用于授权环境下的安全研究、CTF、教学和反作弊系统开发**。
2. **不得用于未授权访问、规避反作弊、伤害他人系统等违法用途**。所有 rootkit-向 capability（进程隐藏、DLL 注入、内存读写、HWBP 等）使用者需要承担合规责任。
3. 代码会修改 CR0/CR3/CR4、EPT/NPT、SSDT 等关键内核结构，**实现错误可直接导致 BSOD**。强烈建议先在虚拟机或测试机上验证，正式机器使用前完整阅读 [Win11 兼容性专章](#10-win11-兼容性专章) 和 [故障排查](#11-故障排查)。
4. 项目依赖测试签名（`bcdedit /set testsigning on`）和禁用 Hyper-V（`bcdedit /set hypervisorlaunchtype off`），开启后会显著降低系统隔离强度。

---

## 1. 项目概览

- **类型**：Type-1 Windows 内核模式 Hypervisor（`Netr.sys`）
- **平台**：Intel VMX + AMD SVM 双路径，全部 VM Exit 用统一 dispatcher 处理
- **代码规模**：~48,000 行 C + ~1,200 行 ASM，30+ 源文件
- **WDK**：`WindowsKernelModeDriver10.0` (KMDF 1.15)
- **目标**：Win10 22H2 / Win11 21H2 / 22H2 / 23H2 / 24H2 / 25H2 / Canary
- **测试签名**：默认产物 `x64\Release\Netr.sys` 用 `WDKTestCert` 测试签名
- **GUI**：`tools/netr-gui/dist/Netr-GUI.exe`（PySide6 桌面程序，45MB 单文件）

### 主要功能列表

| 类别 | 子系统 | 实现位置 |
|---|---|---|
| **核心** | VMX/SVM 启动、VM Exit 主分发、Guest 状态保存恢复 | `HvCore`, `HvVmExit`, `AsmVmx`, `AsmSvm` |
| **页表** | EPT (2TB, 2MB+1GB 大页) / NPT (默认 512GB, hardening 后 2TB) | `HvEpt`, `HvNpt` |
| **Hook** | EPT/NPT 隐身 Hook 框架（含完整 LDE、原子 PTE 写、跳板池） | `EptHook` (6446 行), `NptHook` (4116 行) |
| **嵌套** | L0-L1-L2 完整 Intel VMX (11 条指令) / AMD SVM (5 条指令) | `HvNested`, `HvNestedEpt`, `HvNestedSvm`, `HvNestedNpt` |
| **反检测** | CPUID 伪装、MSR 拦截、RDTSC 补偿、CR4.VMXE 隐藏 | `HvVmcs`, `HvVmcb`, `HvHook` |
| **隐藏** | 进程/驱动/文件/内存/注册表 | `HvHook`, `HvRegistryHook` |
| **注入** | DLL 手动映射 + Shellcode + PEB 脱链 + VAD 欺骗 + PE 头擦除 | `HvInjection` |
| **HWBP** | 透明硬件断点（DR0-DR3 shadow + event ring） | `HvDebugger` |
| **输入注入** | PS/2 端口 0x60/0x64 拦截 + xHCI USB HID 注入（Layer 4） | `HvInput`, `HvUsbXhci`, `HvXhciEptTrap` |
| **网络伪造** | netio.sys!NsiGetParameter Hook，按规则改写返回的流量统计 | `HvNetworkHook` |
| **物理访问** | VtRoot 无痕物理 R/W（独立 PT 岛），KVAS asymmetric subset 兼容 | `HvVtRoot`, `HvPhysAccess`, `HvCr3Snoop` |

---

## 2. 系统要求

### 2.1 硬件

| 项 | 最低要求 | 推荐 |
|---|---|---|
| CPU 厂商 | Intel 或 AMD | Intel 6 代+ / AMD Zen+ |
| 虚拟化扩展 | VT-x + EPT 或 SVM + NPT | VT-x + EPT + VPID + MTF（启用 xHCI EPT trap 必需） |
| 内存 | 4 GB | 8 GB+ |
| CPU 核数 | 单核可启动，多核充分测试 | 4+ |
| Windows | Win10 1709 (Build 16299) | Win11 24H2 (Build 26100) |

### 2.2 软件

- **Windows Driver Kit (WDK)**：Windows 11 Driver Kit 10.0.26100 或更高
- **Visual Studio**：2019 或 2022，附带 C++ 桌面工作负载 + Spectre Mitigation 库
- **测试签名**：`bcdedit /set testsigning on`
- **关闭 Hyper-V**：`bcdedit /set hypervisorlaunchtype off`（重启生效）
- **Python**（GUI 工具开发用）：3.10+ + PySide6 6.6+；运行 EXE 不需要 Python

### 2.3 Windows 版本支持矩阵

| 版本 | Build | 支持状态 | 备注 |
|---|---|---|---|
| Win10 1709 | 16299 | ✅ 支持 | byte-identical KVAS shadow |
| Win10 22H2 | 19045 | ✅ 支持 | asymmetric subset shadow（Phase 8 修复后兼容） |
| Win11 21H2 | 22000 | ✅ 支持 | 引入 CR4.CET 修补 |
| Win11 23H2 | 22631 | ✅ 支持 | KVAS shadow 行为开始漂移 |
| **Win11 24H2** | **26100** | **✅ 主要测试目标** | NQSI EPT hook 用 atomic PTE 写消除 race |
| Win11 25H2 / Canary | 27xxx+ | ⚠️ Best-effort | 偏移可能漂移，需要 BISECT 验证 |

---

## 3. 快速开始

### 3.1 编译

```cmd
:: 方式 A: 使用项目内 build_test.bat（路径需根据实际 VS 安装调整）
build_test.bat

:: 方式 B: 直接调用 MSBuild
msbuild Netr.vcxproj /p:Configuration=Release /p:Platform=x64
```

产物：`x64\Release\Netr.sys`（约 240 KB，已用 `WDKTestCert` 测试签名）。

预期输出：`0 个错误 0 个警告`（已清理 9 类历史警告）。

### 3.2 BIOS / 系统准备

```cmd
:: 1. 启用测试签名
bcdedit /set testsigning on

:: 2. 关闭 Hyper-V（与本项目互斥）
bcdedit /set hypervisorlaunchtype off

:: 3. 重启
shutdown /r /t 0
```

BIOS 中确认：Intel VT-x / VT-d 启用，或 AMD SVM Mode 启用。

### 3.3 加载驱动

```cmd
sc create Netr type= kernel binPath= "C:\path\to\Netr.sys"
sc start Netr
```

加载成功后，驱动会做以下事情：
1. 在每个逻辑 CPU 上启动 VMX 或 SVM
2. 创建 EPT/NPT 身份映射页表
3. 在 `\Device\<16 字符随机名>` 创建用户态通信设备
4. 把设备名写入 `HKLM\Software\NetrSvc\DeviceName`
5. 把 `NetrSvc` 注册表项加入 `NtEnumerateKey` 隐藏列表（但保留直接 path 访问）
6. 派生系统线程，10 秒后抹零驱动 PE 头

通过 DebugView 观察 `[HV]` 前缀的日志确认加载状态。

### 3.4 启动 GUI

```cmd
:: 双击或命令行启动
tools\netr-gui\dist\Netr-GUI.exe
```

GUI 会：
- 检查管理员权限（必需）
- 尝试启用 `SeLoadDriverPrivilege`
- 从 `HKLM\Software\NetrSvc\DeviceName` 读取设备名
- 打开 `\\.\<leaf>` 设备，激活所有功能页

详细 GUI 使用说明见 [`tools/netr-gui/README.md`](tools/netr-gui/README.md)。

### 3.5 卸载

```cmd
sc stop Netr
sc delete Netr
```

`DriverUnload` 会按以下逆序清理：先卸 Hook（防止 PG 误判已修改代码）、再 VMXOFF/STGI、释放 EPT/NPT、删除设备和符号链接、清除注册表 `DeviceName` 值（保留 `NetrSvc` key 以维持 RegistryHook 状态）。

---

## 4. 架构总览

### 4.1 模块拓扑（30+ 文件）

```
驱动入口
├── Driver.c (2643 行)                    DriverEntry / 46 个 IOCTL 派发器 / 随机设备名
├── HvCore.c / HvCore.h                   统一启动入口；CPU 厂商分叉

平台抽象
├── HvCpu.c / HvCpu.h                     厂商检测、虚拟化能力探测、CPUID 助手
├── HvCompat.h                            API 兼容包装 (HvAllocateNonPaged 等) + 编译宏
├── HvTypes.h (1700+ 行)                  公共结构 / VMCS 字段 / EPT/NPT PTE / MSR 定义
└── HvUtils.c / HvUtils.h                 通用助手、全局 OS 版本探测

Intel VMX 层
├── HvVmcs.c / HvVmcs.h                   VMCS 配置 + MSR Bitmap 拦截 + VPID 启用
├── HvEpt.c / HvEpt.h                     EPT 4 级页表，2MB+1GB 大页，2TB 身份映射
├── EptHook.c / EptHook.h (6446 行)       EPT Hook + 完整 LDE + 原子 PTE 写 + 跳板池
└── AsmVmx.asm (655 行)                   VMX 汇编入口（含 XMM0-15 保存、严格栈对齐）

AMD SVM 层
├── HvVmcb.c / HvVmcb.h                   VMCB 配置 + ASID 池 (HV_ENABLE_SVM_HARDENING)
├── HvNpt.c / HvNpt.h                     NPT 2MB 大页 + 可选 1GB 扩展到 2TB
├── NptHook.c / NptHook.h (4116 行)       NPT FakePage/OriginalPage + RFLAGS.TF + #DB
└── AsmSvm.asm (493 行)                   SVM 汇编入口（XMM 保存 + 栈对齐对称 Intel）

VM Exit 统一分发
└── HvVmExit.c (2775 行)                  Intel 与 AMD 两个独立 dispatcher 共存

嵌套虚拟化
├── HvNested.c (1986 行)                  Intel VMX 嵌套（11 条指令完整实现）
├── HvNestedEpt.c (1109 行)               EPT02 翻译链（L2 GPA → L1 GPA → HPA）
├── HvNestedSvm.c (1345 行)               AMD SVM 嵌套（5 条指令 + vGIF 门控）
└── HvNestedNpt.c (1019 行)               NPT02 翻译链

Hook 与隐藏
├── HvHook.c / HvHook.h (2361 行)         统一 Hook 抽象 + AAD 配置
├── HvNetworkHook.c (1489 行)             netio.sys!NsiGetParameter Hook
├── HvRegistryHook.c                      NtEnumerateKey 跳过隐藏键
└── HvInjection.c (2434 行)               手动映射 PE + PEB 脱链 + VAD 欺骗

xHCI USB HID 注入（特色功能）
├── HvUsbXhci.c (1878 行)                 xHCI 控制器扫描 + TR/Event Ring 操作
├── HvUsbHid.c (181 行)                   HID descriptor 模板
└── HvXhciEptTrap.c (662 行)              USBSTS/IMAN EPT 读 trap（默认 OFF）

输入与调试
├── HvInput.c (1738 行)                   PS/2 端口 0x60/0x64 拦截 + I/O Bitmap
└── HvDebugger.c (768 行)                 HWBP shadow + DR0-DR3 透明硬件断点 + event ring

KVAS 与物理访问
├── HvCr3Snoop.c                          被动 CR3 嗅探，过滤 kernel-mode RIP
└── HvPhysAccess.c (2111 行)              物理页直通 + KVAS asymmetric subset match
```

### 4.2 命名规范

| 前缀 | 含义 |
|---|---|
| `Hv*` | 通用 hypervisor 接口（跨平台） |
| `Ept*` | Intel EPT 专用 |
| `Npt*` | AMD NPT 专用 |
| `Svm*` | AMD SVM 专用 |
| `HvNested*` | 嵌套虚拟化 |
| `Asm*` | 汇编入口 |
| `g_*` | 全局变量 |
| `s_*` | 函数内 / 文件内 static 变量 |

### 4.3 锁层级（IRQL 约束）

| 锁类型 | IRQL | 用途 |
|---|---|---|
| `KSPIN_LOCK` | DISPATCH_LEVEL | 跨 CPU 同步，**绝对不能在锁内调 `MmMapIoSpace` / `Mm*` / DbgPrint** |
| `FAST_MUTEX` | APC_LEVEL | per-device 同步，允许在锁内调 `MmMapIoSpace` |
| `VMX root mode` | 未定义 | 必须先于 IRQL 判定（见 `EptHook.c:170` 注释） |
| `IPI` | IPI_LEVEL | 仅可调 VMCALL/INVEPT/INVVPID 等纯汇编指令 |

典型经验：xHCI HID 注入的三段式锁分离设计（FAST_MUTEX 包 TR 写、KSPIN_LOCK 仅包 Event Ring 写、IPI 在锁外）就是上面规则的具体应用，详见 `HvUsbXhci.c:1715`。

---

## 5. 平台特性

### 5.1 Intel VMX

| 字段 | 配置 | 说明 |
|---|---|---|
| EPT | ✅ 启用 | 2MB + 1GB 大页，2TB 身份映射 |
| **VPID** | ✅ 启用（本次新增） | per-CPU VPID = ProcessorNumber + 1，消除每次 VM-Entry 全 TLB flush |
| **MSR Bitmap** | ✅ 拦截关键 MSR（本次新增） | IA32_FEATURE_CONTROL + IA32_VMX_BASIC..VMX_VMFUNC |
| Secondary controls | EPT / RDTSCP / INVPCID / XSAVES_XRSTORS / VPID | |
| VM Exit controls | HOST_ADDR_SPACE_SIZE / SAVE+LOAD PAT / SAVE+LOAD EFER / ACK_INTR_ON_EXIT | |
| Exception bitmap | 全 0（不拦截） | EPT Hook 走 EPT Violation/MTF，不依赖异常 |
| CR0/CR4 mask | CR4.VMXE 隐藏 | Guest 读 CR4 看不见 VMXE=1（反检测） |
| Host CR4.CET | 强制 0 | Win11 默认开 CET，host 必须关掉避免 #CP 三重故障 |

### 5.2 AMD SVM

| 字段 | 默认 (HARDENING=0) | HARDENING=1 |
|---|---|---|
| **ASID** | 硬编码 1（所有 vCPU 共享） | per-vCPU 从 CPUID 80000008H 探测的池分配 |
| **NPT 范围** | 512 GB（PML4[0] 用 2MB 大页） | 2 TB（PML4[1..3] 用 1GB 大页，若 CPU 支持） |
| **vGIF 中断门控** | 记录但不门控 | 拦截 SvmInjectEvent；GIF=0 时入队，STGI 时 flush |
| **嵌套 IOPM/MSRPM 合并** | "谁配置用谁的" | byte-by-byte OR 合并 L0+L1 |
| MSR Permission Map | 拦截 EFER / VM_CR / HSAVE_PA / FEATURE_CONTROL | |
| Intercepts | CPUID / MSR / VMRUN / VMMCALL / VMLOAD / VMSAVE / STGI / CLGI / XSETBV / SHUTDOWN | |
| TLB control | FLUSH_ALL（启动期）+ FLUSH_GUEST（按需） | |
| V_INTR_MASKING | 启用（bit 24） | |

启用 hardening：在 `HvCompat.h` 把 `HV_ENABLE_SVM_HARDENING` 改为 1，或在项目属性页 PreprocessorDefinitions 加 `HV_ENABLE_SVM_HARDENING=1`。

### 5.3 嵌套虚拟化（L0-L1-L2）

| 指令 | Intel | AMD | 说明 |
|---|---|---|---|
| VMXON/VMXOFF | ✅ | — | 包含 revision-ID 验证、CR0/CR4/CPL 检查 |
| VMCLEAR/VMPTRLD | ✅ | — | VMPTRLD 拒绝 shadow VMCS bit31 |
| VMREAD/VMWRITE | ✅ | — | 86+ 字段索引；VMWRITE 检查只读字段 |
| VMLAUNCH/VMRESUME | ✅ | — | 完整状态机校验 |
| INVEPT/INVVPID | ✅ | — | 全 context 失效（细粒度可后续优化） |
| VMRUN | — | ✅ | |
| VMLOAD/VMSAVE | — | ✅ | |
| STGI/CLGI | — | ✅ | 控制 vGIF |

**VMCS02 合并**（`HvNested.c:1033`）：L0+L1 控制位 OR 合并；EPT bit/VPID bit 强制保留 L0；VM-Exit Host bit 强制 L0；NestedEptGetOrCreateContext 构建 EPT02 PML4。

**VMCB02 合并**（`HvNestedSvm.c:329`）：CR/DR/异常 OR 合并；InterceptMisc2 强制 OR-in VMRUN/VMMCALL/VMLOAD/VMSAVE/STGI/CLGI；ASID 走池；HARDENING=1 时 IOPM/MSRPM 真正按位 OR。

**三层嵌套（L3）**：不支持，注入 #UD。

### 5.4 EPT/NPT Hook 框架

Intel EPT Hook（`EptHook.c`，6446 行）：
- **Execute-Only 隐身**：稳态 FakePage R=0/W=0/X=1，Guest 执行无 VM Exit
- **MTF 单步**：读/写触发 violation → 切到 OriginalPage RWX + MTF → 恢复
- **完整 LDE**：覆盖 Legacy / REX / VEX 2-byte / VEX 3-byte / EVEX 4-byte 前缀
- **跳板池 INT3 填充**：4 页可执行非分页内存，16-byte 对齐 slot，gap 填 `0xCC`
- **原子 PTE 写**：`InterlockedExchange64` 一次写完 64-bit PTE，消除多核 R/W/X/PFN 4 字段 RMW race（2026-05-21 Round 7 修复）
- **跨模式 INVEPT**：`EptInveptAllContexts` 自动派发（root 直调 / PASSIVE IPI / 高 IRQL VMCALL）；root 模式判定**必须先于 IRQL 检查**（避免全核死锁）
- **本次新增**：`EptInvvpidAllContexts` 跨模式 INVVPID 同形派发

AMD NPT Hook（`NptHook.c`，4116 行）：
- **双页面策略**：AMD 不支持 Execute-Only，FakePage = P/W/!NX（允许执行），OriginalPage = P/W/NX（禁执行）
- **#DB 单步**：读取触发 NPF → 切到 OriginalPage + RFLAGS.TF=1 + 拦截 #DB
- **VMCB.TlbControl=FLUSH_GUEST** 替代 INVEPT

---

## 6. 功能子系统

### 6.1 进程隐藏

| API | IOCTL | 实现 |
|---|---|---|
| `HvHookHideProcess(PID)` | `IOCTL_HV_HIDE_PROCESS` (0x20) | Hook `NtQuerySystemInformation` 过滤 SystemProcessInformation 链表 |
| `HvHookHideProcessByName(Name)` | 同上，Mode=1 | |
| `HvHookUnhideProcess(PID)` | `IOCTL_HV_UNHIDE_PROCESS` (0x21) | |

**注意**：进程隐藏默认 OFF（需 IOCTL 显式启用）。`Driver.c:2449` 安装 `HvHookInstallDriverHideHook()` 但不主动隐藏任何具体进程。

### 6.2 驱动隐藏

| API | IOCTL | 实现 |
|---|---|---|
| `HvHookHideDriverByNameSafe(Name)` | `IOCTL_HV_HIDE_DRIVER` (0x30) | EPT/NPT inline hook（**不修改 PsLoadedModuleList，规避 PG**） |

**驱动自隐藏**：`ENABLE_DRIVER_SELF_HIDE=1`（默认开），驱动加载后自动通过 EPT Hook 隐藏自己。

### 6.3 文件隐藏

| API | IOCTL | 状态 |
|---|---|---|
| `HvHookInstallFileHideHook()` | — | **当前禁用** (`ENABLE_FILE_HIDE_HOOK=0`)，2026-05-21 BISECT #80 确认这条 hook 触发 services.exe 0x1E BSOD |

### 6.4 内存隐藏

| API | 说明 |
|---|---|
| `HvHookHideMemoryRegion(PID, Addr, Size)` | Hook `NtQueryVirtualMemory` 过滤 |
| `HvHideInjectedMemory(...)` | 集成路径：Hook + PE 头擦除 + VAD 欺骗 + PEB 脱链 |

### 6.5 注册表枚举隐藏

`HvRegistryHook.c`：仅 Hook `NtEnumerateKey`，直接 path 打开（`NtOpenKey`）不影响。
- `HvRegHookAddHiddenKeyName(KeyName)` 加入隐藏列表
- 当前隐藏 `NetrSvc`（保护 GUI 读取的设备名注册表项）

### 6.6 DLL 注入

| API | IOCTL | 说明 |
|---|---|---|
| `HvInjectDll(...)` | `IOCTL_HV_INJECT_DLL` (0x60) | 完整 PE 手动映射（节映射 + 重定位 + 导入解析 + TLS callback） |

`NETR_INJECT_DLL_REQUEST` 字段：
- `ProcessId` / `DllSize` / `DllBuffer`
- `ErasePeHeader`：擦零 DOS+NT header（默认 0x1000 字节）
- `UnlinkFromPeb`：从 PEB LdrModuleList 三链表脱链
- `UseManualMap` / `StealthLevel` (0-3)

PEB 偏移（`HvInjection.c:2141`）使用 Win7→Win11 x64 用户态稳定偏移（PEB+0x18=Ldr 等），不需要版本分支；若未来支持 32-bit guest 进程需要 WOW64 PEB 分支。

### 6.7 Shellcode 注入

`IOCTL_HV_INJECT_SHELLCODE` (0x70)：写入 + 执行（APC 调度），最大 4KB。

### 6.8 反反调试 (Anti-Anti-Debug)

| Hook 项 | 用途 |
|---|---|
| NtQuerySystemInformation | 隐藏调试器进程 |
| NtQueryInformationProcess | 隐藏 ProcessDebugPort |
| NtSetInformationThread | 拦截 HideFromDebugger |
| ObReferenceObjectByName | 阻止用户反检测拉到我们的驱动对象 |
| ZwQueryInformationProcess | 同 NtQueryInformationProcess |

IOCTL：`IOCTL_HV_ENABLE_ANTIANTIDEBUG` (0x50) / `IOCTL_HV_DISABLE_ANTIANTIDEBUG` (0x51)

### 6.9 透明硬件断点 (HWBP)

`HvDebugger.c` 实现 DR0-DR3 shadow + event ring：
- `IOCTL_HV_DBG_SET_HWBP` (0x100)：设置断点
- `IOCTL_HV_DBG_CLEAR_HWBP` (0x101)：清除
- `IOCTL_HV_DBG_WAIT_EVENT` (0x102)：阻塞等命中事件
- `IOCTL_HV_DBG_CONTINUE` (0x103)：恢复执行

Guest 看到的 DR0-DR3 是 shadow 值，hypervisor 维护真实的 DR0-DR3。命中时拦截 #DB 写入 event ring 通知用户态。

### 6.10 输入注入

**PS/2 路径**：`HvInput.c` 通过 I/O Bitmap 拦截端口 `0x60`/`0x64`，注入 set 1 扫描码或鼠标包。

**xHCI USB HID 路径**（Layer 4，特色功能）：
- `HvUsbXhci.c` 直接扫描 xHCI 控制器
- 找到 HID device 后，按三段式锁分离设计写入 Transfer Ring + Event Ring
- 通过 IPI 强制 VMEXIT 触发 Windows kbdclass/mouclass 处理
- **Item 2**：USBSTS/IMAN EPT 读 trap（拦截 ISR fast-bail）默认 OFF，需 `IOCTL_HV_XHCI_TRAP_ENABLE` (0x55) 显式启用

完整 xHCI 注入流程：
```
[A] APC_LEVEL: FAST_MUTEX(dev->TrMutex)
    └── HvXhciWriteHidReportToTr (512 TRB scan-ahead, IDT TRB ≤8B inline)
[B] DISPATCH_LEVEL: KSPIN_LOCK(g_HvUsbXhci.Lock)
    └── HvXhciWriteTransferEvent (用 EventRingSegMappedVa 预映射)
[C] 锁外: KeIpiGenericCall → 强制 VMEXIT
```

### 6.11 网络流量伪造

`HvNetworkHook.c` Hook `netio.sys!NsiGetParameter`：
- 拦截 GetIfEntry2 / GetIfTable2 用户态调用链
- 改写返回的字节数 / 包数 / 速率
- 支持 4 种模式：固定值 / 缩放百分比 / 减去固定值 / 随机
- `IOCTL_HV_SET_FAKE_TRAFFIC` 配置参数

### 6.12 物理内存直通访问

**VtRoot 无痕 R/W**（`HvVtRoot.c`，Phase 6 V2）：
- 在 kernel CR3 一个未使用的 PML4 槽位插入完全私有的 PDPT/PD/PT 链
- Scratch VA 不在任何 VAD/PFN 反向映射中，MM 子系统看不见
- 每 CPU 私有 PT entry，root 模式只改自己的 → invlpg 自己的 ScratchVa → memcpy
- 零 `Mm*` / `Ke*` / `Ps*` 介入

**KVAS asymmetric subset match**（`HvPhysAccess.c:381`）：
- Win11 23H2/24H2+ 的 KVAS shadow CR3 不再是 user CR3 kernel-half 的 byte-identical 副本，而是 **superset**
- 修正判据：shadow 里 PRESENT 的 entry 必须在 candidate 里也 PRESENT 且 PFN 相同，允许 candidate 有 shadow 没有的额外 entry（5% 噪声容忍）

**CR3 嗅探**（`HvCr3Snoop.c`）：
- 每次 VMEXIT 入口被动记录 GUEST_CR3
- 用 `GuestRip < USER_VA_LIMIT (0x800000000000)` 过滤掉 kernel-mode RIP 看到的 shadow CR3
- 默认禁用，第一次启发式失败自动启用

---

## 7. 用户态接口

### 7.1 设备名随机化与注册表发布机制

为规避反作弊检测固定设备名，本项目使用 **随机 16 字符设备名 + 注册表发布** 机制：

```
启动期 (Driver.c:1761 HvBuildRandomDeviceName):
  ├── 用 KeQuerySystemTime ^ KeQuerySystemTime.HighPart ^ (TID<<8) 作 seed
  ├── 从 [A-Za-z0-9] 随机生成 16 字符 leaf
  ├── 构造 \Device\<leaf> 和 \??\<leaf>
  └── IoCreateDevice + IoCreateSymbolicLink

发布到注册表 (Driver.c:1804 HvPublishDeviceName):
  HKLM\Software\NetrSvc\DeviceName = REG_SZ "<leaf>"

GUI 端解析 (tools/netr-gui/netr/ioctl.py:30 resolve_device_path):
  ├── winreg.OpenKey(HKLM\Software\NetrSvc, KEY_WOW64_64KEY) 读 DeviceName
  ├── 失败则 fallback 到 \\.\HvControl
  └── CreateFile(\\.\<leaf>) 打开设备
```

**关键设计**：`NetrSvc` 注册表项已被 `HvRegistryHook` 加入 `NtEnumerateKey` 隐藏列表。但 `RegOpenKeyEx` 直接 path 访问绕过枚举，所以 GUI 仍能找到设备。第三方枚举注册表的反检测工具看不到 `NetrSvc` 项。

卸载时（`Driver.c:1849 HvUnpublishDeviceName`）只删除 `DeviceName` 值，**保留 `NetrSvc` key**，让 RegistryHook 状态在重新加载时立即可用。

如需固定设备名（开发调试），在 `Driver.c` 顶部把 `HV_USE_FIXED_DEVICE_NAME` 改为 1，则使用 `HvControl` 固定名。

### 7.2 IOCTL 完整表

设备类型 `FILE_DEVICE_UNKNOWN = 0x22`，所有 IOCTL 用 `METHOD_BUFFERED + FILE_ANY_ACCESS`，基址 `HV_IOCTL_BASE = 0x800`。

```c
#define CTL_CODE(t,f,m,a) (((t)<<16) | ((a)<<14) | ((f)<<2) | (m))
#define _hv(off) CTL_CODE(0x22, 0x800+(off), METHOD_BUFFERED, FILE_ANY_ACCESS)
```

| # | IOCTL | offset | 值 | 输入 | 输出 |
|---|---|---|---|---|---|
| 1 | `IOCTL_HV_GET_STATUS` | 0x00 | 0x222000 | — | `HV_STATUS_INFO` |
| 2 | `IOCTL_HV_DISABLE_DSE` | 0x10 | 0x222040 | — | — |
| 3 | `IOCTL_HV_ENABLE_DSE` | 0x11 | 0x222044 | — | — |
| 4 | `IOCTL_HV_GET_DSE_STATUS` | 0x12 | 0x222048 | — | `HV_DSE_STATUS` |
| 5 | `IOCTL_HV_HIDE_PROCESS` | 0x20 | 0x222080 | `HV_PROCESS_REQUEST` | — |
| 6 | `IOCTL_HV_UNHIDE_PROCESS` | 0x21 | 0x222084 | `HV_PROCESS_REQUEST` | — |
| 7 | `IOCTL_HV_HIDE_DRIVER` | 0x30 | 0x2220C0 | `HV_DRIVER_REQUEST` | — |
| 8 | `IOCTL_HV_UNHIDE_DRIVER` | 0x31 | 0x2220C4 | `HV_DRIVER_REQUEST` | — |
| 9 | `IOCTL_HV_ADD_DEBUGGER` | 0x40 | 0x222100 | `HV_DEBUGGER_REQUEST` | — |
| 10 | `IOCTL_HV_REMOVE_DEBUGGER` | 0x41 | 0x222104 | `HV_DEBUGGER_REQUEST` | — |
| 11 | `IOCTL_HV_PROTECT_PROCESS` | 0x43 | 0x22210C | `HV_PROTECT_REQUEST` | — |
| 12 | `IOCTL_HV_UNPROTECT_PROCESS` | 0x44 | 0x222110 | `HV_PROTECT_REQUEST` | — |
| 13 | `IOCTL_HV_ENABLE_ACCESS_BYPASS` | 0x4A | 0x222128 | — | — |
| 14 | `IOCTL_HV_DISABLE_ACCESS_BYPASS` | 0x4B | 0x22212C | — | — |
| 15 | `IOCTL_HV_INPUT_ENABLE` | 0x4C | 0x222130 | — | — |
| 16 | `IOCTL_HV_INPUT_DISABLE` | 0x4D | 0x222134 | — | — |
| 17 | `IOCTL_HV_INPUT_SEND_KEY` | 0x4E | 0x222138 | `HV_INPUT_KEY_REQUEST` | — |
| 18 | `IOCTL_HV_INPUT_SEND_MOUSE` | 0x4F | 0x22213C | `HV_INPUT_MOUSE_REQUEST` | — |
| 19 | `IOCTL_HV_ENABLE_ANTIANTIDEBUG` | 0x50 | 0x222140 | `HV_AAD_REQUEST` | — |
| 20 | `IOCTL_HV_DISABLE_ANTIANTIDEBUG` | 0x51 | 0x222144 | — | — |
| 21 | `IOCTL_HV_INPUT_GET_STATUS` | 0x52 | 0x222148 | — | `HV_INPUT_STATUS` |
| 22 | `IOCTL_HV_INPUT_GET_XHCI_STATUS` | 0x53 | 0x22214C | — | `HV_USB_XHCI_STATUS` |
| 23 | `IOCTL_HV_INPUT_SET_STRICT_MODE` | 0x54 | 0x222150 | BOOLEAN | — |
| 24 | **`IOCTL_HV_XHCI_TRAP_ENABLE`** | **0x55** | **0x222154** | — | — |
| 25 | **`IOCTL_HV_XHCI_TRAP_DISABLE`** | **0x56** | **0x222158** | — | — |
| 26 | **`IOCTL_HV_XHCI_TRAP_GET_STATS`** | **0x57** | **0x22215C** | — | `HV_XHCI_EPT_TRAP_STATE` |
| 27 | `IOCTL_HV_INJECT_DLL` | 0x60 | 0x222180 | `HV_INJECT_DLL_REQUEST` | `HV_INJECT_DLL_RESULT` |
| 28 | `IOCTL_HV_INJECT_SHELLCODE` | 0x70 | 0x2221C0 | `HV_INJECT_SHELLCODE_REQUEST` | `HV_INJECT_SHELLCODE_RESULT` |
| 29 | `IOCTL_HV_MEMORY_READ` | 0x80 | 0x222200 | `HV_MEMORY_REQUEST` (4KB) | `HV_MEMORY_RESULT` |
| 30 | `IOCTL_HV_MEMORY_WRITE` | 0x81 | 0x222204 | `HV_MEMORY_REQUEST` (4KB) | — |
| 31 | `IOCTL_HV_MEMORY_ALLOC` | 0x82 | 0x222208 | `HV_MEMORY_REQUEST` | base address |
| 32 | `IOCTL_HV_MEMORY_FREE` | 0x83 | 0x22220C | `HV_MEMORY_REQUEST` | — |
| 33 | `IOCTL_HV_ENUMERATE_MODULES` | 0x84 | 0x222210 | `HV_MODULE_ENUM_REQUEST` | `HV_MODULE_ENUM_RESULT` |
| 34 | `IOCTL_HV_MEMORY_READ_EX` | 0x85 | 0x222214 | `HV_MEMORY_REQUEST_EX` (64KB) | `HV_MEMORY_RESULT_EX` |
| 35 | `IOCTL_HV_MEMORY_WRITE_EX` | 0x86 | 0x222218 | `HV_MEMORY_REQUEST_EX` (64KB) | — |
| 36 | `IOCTL_HV_MEMORY_BATCH_READ` | 0x87 | 0x22221C | `HV_MEMORY_BATCH_REQUEST` (256 项) | `HV_MEMORY_BATCH_RESULT` |
| 37 | `IOCTL_HV_MEMORY_BATCH_WRITE` | 0x88 | 0x222220 | `HV_MEMORY_BATCH_REQUEST` | `HV_MEMORY_BATCH_RESULT` |
| 38 | `IOCTL_HV_GET_NESTED_STATUS` | 0xA0 | 0x222280 | — | `HV_NESTED_STATUS` |
| 39 | `IOCTL_HV_GET_NESTED_EVENTS` | 0xA1 | 0x222284 | — | event ring |
| 40 | `IOCTL_HV_CLEAR_NESTED_EVENTS` | 0xA2 | 0x222288 | — | — |
| 41 | `IOCTL_HV_DBG_SET_HWBP` | 0x100 | 0x222400 | `HV_HWBP_REQUEST` | `HV_DBG_RESULT` |
| 42 | `IOCTL_HV_DBG_CLEAR_HWBP` | 0x101 | 0x222404 | `HV_HWBP_REQUEST` | — |
| 43 | `IOCTL_HV_DBG_WAIT_EVENT` | 0x102 | 0x222408 | `HV_DBG_WAIT_REQUEST` | `HV_DBG_WAIT_RESULT` |
| 44 | `IOCTL_HV_DBG_CONTINUE` | 0x103 | 0x22240C | `HV_DBG_CONTINUE_REQUEST` | — |
| 45 | `IOCTL_HV_KERNEL_READ` | 0x104 | 0x222410 | `HV_MEMORY_REQUEST` | bytes |
| 46 | `IOCTL_HV_KERNEL_WRITE` | 0x105 | 0x222414 | `HV_MEMORY_REQUEST` | — |

完整结构体定义见 `tools/netr-gui/netr/structs.py`（Python ctypes，`_pack_=1` 与驱动 `#pragma pack(push,1)` 严格对齐）。

### 7.3 GUI 工具速览

`tools/netr-gui/` 是基于 PySide6 (Qt for Python) 的桌面应用，纯 ctypes 通信（不依赖 pywin32）：

- **入口**：`main.py` 检查管理员 + 启用 `SeLoadDriverPrivilege` → `MainWindow`
- **页面**：11 个，覆盖服务管理 / 状态 / DSE / 进程隐藏 / 驱动隐藏 / 调试器 (3 tab) / 进程保护 / 内存读写 / 注入 / HWBP / 输入注入
- **IOCTL 覆盖**：38 / 46（GUI 暴露），4 个 BATCH/KERNEL 仅 client API 暴露
- **打包**：`build.ps1 -OneDir` 或默认 single-file
- **产物**：`tools/netr-gui/dist/Netr-GUI.exe`（PySide6 single-file 45 MB）

详细 GUI 文档见 [`tools/netr-gui/README.md`](tools/netr-gui/README.md)。

---

## 8. 配置开关

### 8.1 编译宏

`Driver.c` 顶部：

| 宏 | 默认 | 说明 |
|---|---|---|
| `ENABLE_DRIVER_SELF_HIDE` | `1` | 启用驱动 EPT Hook 自隐藏 |
| `ENABLE_INJECTION_FRAMEWORK` | `1` | 启用 DLL/Shellcode 注入 |
| `ENABLE_FILE_HIDE_HOOK` | `0` | **禁用**：BISECT #80 确认触发 services.exe 0x1E BSOD |
| `HV_USE_FIXED_DEVICE_NAME` | `0` | 1 = 用 `HvControl` 固定名；0 = 16 字符随机 |

`HvCompat.h` 顶部：

| 宏 | 默认 | 说明 |
|---|---|---|
| **`HV_ENABLE_SVM_HARDENING`** | **`0`** | AMD 加固：ASID 池 / NPT 2TB / vGIF 门控 / IOPM-MSRPM 按位 OR；只有 Intel 真机时建议保持 OFF |

`HvTypes.h` 顶部：

| 宏 | 默认 | 说明 |
|---|---|---|
| `HV_LOG_LEVEL` | `HV_LOG_LEVEL_INFO` | 4 级：ERROR/WARNING/INFO/DEBUG，编译期裁剪 |

### 8.2 默认 OFF 的高危项

| 项 | 风险 | 启用方式 |
|---|---|---|
| `IOCTL_HV_XHCI_TRAP_ENABLE` (0x55) | xHCI USBSTS/IMAN EPT 读 trap，启用前必须 CPU 支持 MTF | IOCTL 显式调用 |
| `IOCTL_HV_ENABLE_ACCESS_BYPASS` (0x4A) | NtOpenProcess 绕过 PPL/System=4 保护 | IOCTL 显式调用 |
| 进程隐藏 | 高频 NQSI hook 可能在 Win11 上 race | IOCTL 显式调用 |
| FileHideHook | services.exe 启动期 0x1E（BISECT #80） | 编译期 `ENABLE_FILE_HIDE_HOOK=1` |
| RegistryHook NtEnumerateKey | NtEnumerateKey trampoline 短跳跨页可能不可靠（BISECT #78） | 取消 `Driver.c:2507` 的 `#if 0` |
| AMD 加固 | 仅 Intel 真机验证过 | 编译期 `HV_ENABLE_SVM_HARDENING=1` |

---

## 9. Win11 兼容性专章

### 9.1 CR4.CET 与 Shadow Stack

Win11 默认开 `CR4.CET=1`（Kernel Shadow Stack + IBT）。如果 host 也保持 CET=1，VMRESUME 时硬件用 host SSP 检查 host RIP 的 shadow stack 一致性，但我们的 VM Exit handler 不在 SSP 维护链上 → 触发 `#CP (Control Protection)` → 三重故障。

**修补**（`HvVmcs.c:541`）：强制 `HOST_CR4.CET=0`。

### 9.2 KVAS asymmetric subset match

Win11 23H2/24H2+ 的 KVAS shadow CR3 与 user CR3 kernel-half 不再是 byte-identical 副本：

| 版本 | KVAS shadow 关系 | 旧 byte-identical 判据 | 新 asymmetric 判据 |
|---|---|---|---|
| Win10 1709 / Win11 21H2-22H2 | full kernel-half copy | ✅ 命中 | ✅ 命中 |
| Win11 23H2/24H2+ servicing updates | SUPERSET（candidate 多出条目） | ❌ 误判为坏候选 | ✅ 命中 |
| Win11 Canary 极端情况 | trampoline 数 = 0 | ❌ | ✅ walk-validation fallback |

判据（`HvPhysAccess.c:381`）：shadow 里 PRESENT 的 entry 必须在 candidate 里也 PRESENT 且 PFN 相同，允许 candidate 有 shadow 没有的额外 entry，5% 噪声容忍。

### 9.3 EPT Hook 原子 PTE 写

`NtQuerySystemInformation` EPT hook 在 Win11 高频 syscall 下多核策略冲突。根因（2026-05-21 BISECT Round 7）：旧代码逐字段写 PTE（`pte->Read=1; pte->Write=1; pte->Execute=1; pte->PA=...`）= 4 次独立 RMW；多核同时写同 PTE 时另一个 CPU 可能看到部分写状态（R=1/W=0/X=0/PA=新值）→ 死循环 EPT Violation → 全核卡死。

修复（`EptHook.c:229 EptSetPteAtomic`）：用 `InterlockedExchange64` 把整个 64-bit PTE 值一次原子写完成，任何 CPU 任何时刻看到的 PTE 都是完整有效状态。

### 9.4 INVEPT/INVVPID 跨模式安全包装

裸 `AsmInveptAllContexts()` 在 guest 模式会 `#UD`。`EptInveptAllContexts` (`EptHook.c:170`) 提供跨模式安全包装：
- VMX root 模式 → 直接 INVEPT
- PASSIVE/APC + HV active → `KeIpiGenericCall` 全核广播
- 高 IRQL 非 root → `AsmVmCall(VMCALL_INVEPT)` 进入 root
- HV 未激活 → no-op

**关键设计**：root 模式判定**必须先于** `KeGetCurrentIrql()` 调用 —— root 模式下 IRQL 行为未定义，可能继承 Guest 的 PASSIVE_LEVEL，错走 IPI 路径 → 其他 CPU 也在 root → 全核死锁（加载 1 秒卡死无 dump）。

`EptInvvpidAllContexts` (Phase 2 新增) 同形派发，用于 VPID 启用后 Guest CR3/页表变化的 TLB 失效。

### 9.5 Win11 已知问题

| 现象 | 状态 | 处理 |
|---|---|---|
| 24H2 加载 0-3s 卡死无 dump | ✅ 已修（CR4.CET 修补） | `HvVmcs.c:541` |
| 加载 1s 卡死无 dump（INVEPT 死锁） | ✅ 已修（root 模式判定先于 IRQL） | `EptHook.c:179` |
| services.exe 0x1E（FileHideHook） | ✅ 默认禁用 | `Driver.c:41` `ENABLE_FILE_HIDE_HOOK=0` |
| NtEnumerateKey trampoline 不可靠 | ⚠️ 怀疑 | `Driver.c:2507` `#if 0`，未确认根因 |
| 25H2 / Canary 偏移漂移 | ⚠️ Best-effort | 待 BISECT |

---

## 10. 故障排查

### 10.1 加载失败

```
[HV] Virtualization not supported!
```
- 检查 BIOS：VT-x / VT-d / SVM Mode 是否启用
- 检查 Hyper-V：`bcdedit /enum` 看 `hypervisorlaunchtype`，必须 `off`
- 检查 VBS：组策略 `计算机配置 → 管理模板 → 系统 → Device Guard → 关闭基于虚拟化的安全性`

```
[HV] Hypervisor ACTIVE: 4/8 CPUs virtualized
```
- 部分 CPU 启动失败：通常是 MSR_IA32_FEATURE_CONTROL.LOCK=1 且 VMX 位未设
- 检查日志找 `[HV] CPU N: VMXON failed` 类消息

### 10.2 BSOD 速查

| Bug Check | 含义 | 常见根因 |
|---|---|---|
| `0x1E` (KMODE_EXCEPTION_NOT_HANDLED) | Hook 跳板跳到 INT3 之外 | LDE 解码失败 / Hook 安装时切到指令中间 |
| `0x1DB` (DPC_WATCHDOG_VIOLATION) | 5 秒内 IPI 看门狗 | EPT violation 死循环未兜底 |
| `0x7E` (SYSTEM_THREAD_EXCEPTION_NOT_HANDLED) | 内核线程异常未处理 | 注入框架越权 / Guest 状态恢复错误 |
| `0x3B` (SYSTEM_SERVICE_EXCEPTION) | SSDT/IAT hook 错误 | Hook 函数签名不匹配 |
| `0x139` (KERNEL_SECURITY_CHECK_FAILURE) | CFG / Shadow Stack 检查失败 | CR4.CET 配置错误（见 9.1） |
| 加载 1-3s 卡死无 dump | 全核死锁 | INVEPT 跨模式路径错（见 9.4）/ NQSI race（见 9.3） |

### 10.3 DebugView 日志前缀

| 前缀 | 模块 |
|---|---|
| `[HV]` | 主驱动 (Driver.c / HvCore.c) |
| `[HV-Util]` | OS 版本探测等通用工具 |
| `[HV-CPU]` | CPU 厂商检测 |
| `[HV-NESTED]` / `[HV-NESTED-SVM]` | 嵌套虚拟化 |
| `[EPT-Hook]` | EPT Hook 框架 |
| `[NPT]` / `[NPT-Hook]` | NPT 路径 |
| `[SVM]` | AMD SVM 控制配置 |
| `[HvHook]` | Hook 抽象层 |
| `[HvNetHook]` | 网络流量伪造 |
| `[HvUsbXhci]` / `[XhciEpt]` | xHCI HID 注入 |
| `[Injection]` / `[Injection-Hide]` | DLL 注入 |
| `[Debugger]` | HWBP 子系统 |

---

## 11. 开发与贡献

### 11.1 命名规范

| 前缀 | 含义 |
|---|---|
| `Hv*` | 通用 hypervisor 接口（跨平台） |
| `Ept*` | Intel EPT 专用 |
| `Npt*` | AMD NPT 专用 |
| `Svm*` | AMD SVM 专用 |
| `HvNested*` | 嵌套虚拟化 |
| `Asm*` | 汇编入口 |
| `g_*` | 全局变量 |
| `s_*` | 函数内 / 文件内 static 变量 |

### 11.2 历史 BSOD 修复注释体例

每个根因修复点用如下格式：

```c
// 2026-05-21 BISECT #N 根因:<现象>
//   <根因 1-3 行>
// 修复方案:
//   <方案 1-3 行>
```

例：`EptHook.c:180-185` 是 INVEPT 全核死锁的范例。

### 11.3 内核 IRQL 约束

- **VMX root mode 内**：禁用 `Mm*` / `Ke*` / `Ps*` API；只能用 VMREAD/VMWRITE/`Interlocked*`/裸内存读写
- **DISPATCH_LEVEL (SpinLock 内)**：禁用 `MmMapIoSpace` / `MmAllocate*` / `DbgPrint`
- **APC_LEVEL (FAST_MUTEX 内)**：允许 `MmMapIoSpace`，但仍禁用阻塞调用
- **DPC routine**：禁用 `KeWaitForSingleObject` 等阻塞调用

### 11.4 测试矩阵

每次大改动后建议跑：
1. Win11 24H2 加载 30 分钟稳定性测试（DebugView 监控）
2. GUI 各页面回归（DSE / 进程隐藏 / 注入 / HWBP / xHCI）
3. RDMSR `0x3A`（FEATURE_CONTROL）从用户态读取，确认 VM Exit 触发（diagnostics 计数器增加）

### 11.5 项目历史快照

项目根有 9 个 zip 快照（Phase 8 之前用 zip 做版本控制）：

| zip | 推测里程碑 |
|---|---|
| `1-3.zip` | 早期初始版本 |
| `4-intel.zip` | Intel VMX 路径完成 |
| `5-intelEPT没问题.zip` | Intel EPT 调通 |
| `6-7.zip` | Hook / HWBP 加入 |
| `8gui.zip` | PySide6 GUI 加入 |
| `0528.zip` | Phase 8 主版本 (2026-05-28) |

---

## 12. 致谢

本项目参考了大量公开的 hypervisor 研究：

- [HyperPlatform](https://github.com/tandasat/HyperPlatform) — VMX 框架范本
- [HyperBone](https://github.com/DarthTon/HyperBone) — EPT Hook 思路
- [Hypervisor From Scratch](https://rayanfam.com/topics/hypervisor-from-scratch-part-1/) — 教学系列
- [Intel SDM Vol 3C](https://www.intel.com/sdm) / [AMD APM Vol 2](https://developer.amd.com/resources/developer-guides-manuals/) — 官方手册

---

## 13. 许可与免责声明

本项目仅供学习、研究、授权安全测试使用。**作者不对任何形式的滥用承担责任**。使用者必须遵守当地法律法规和目标系统的使用条款。

代码遵循 **教育许可**：可自由学习、修改、用于研究和授权环境下的安全工作；不得用于商业产品、未授权访问、规避反作弊等违法用途。

---

> **当前版本状态**：Phase 8（2026 年）；最近构建 0 警告 0 错误；Intel VMX 路径主线验证；AMD SVM 路径代码完整但加固功能（`HV_ENABLE_SVM_HARDENING`）默认 OFF，等 AMD 真机验证后打开。
