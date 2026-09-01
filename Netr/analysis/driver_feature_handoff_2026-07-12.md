# 驱动功能恢复交班（2026-07-12）

## 2026-07-17 第二次快速单步 0x101：修正 MTF 合成 #DB 语义

- 新现场 `C:\Windows\Minidump\071726-14015-01.dmp` 仍为 `CLOCK_WATCHDOG_TIMEOUT (0x101)`，但不是上一份 dump 的 Dbgk hook unwind 重入。挂死 CPU 8 的目标线程在 `nt!KxDebugTrapOrFault` 中对 `gs:[860h]` 访问反复进入 `KiPageFault`；原始用户 RIP 为 `0x7FF650AF12C9`，日志最后一次成功单步停在同线程的 `0x7FF650AF12C3`。
- 最早语义违例是私有 MTF 单步同时写 `GUEST_PENDING_DEBUG_EXCEPTIONS.BS` 和 VM-entry 显式注入 `#DB`。KVM 仅在真实 TF 单步受 `STI/MOV SS` 阻塞时补 pending BS；Unreal 的 MTF 单步只在 CPL3 显式注入一次 `#DB`。当前写法把一个合成单步描述成两个 debug 条件。
- 根因链：潜伏缺陷是双重 debug 状态和缺少注入交付门；第一项回归决策是在私有 MTF 完成路径增加 pending BS；运行触发是用户指令完成后的合成 `#DB`；快速点击只是连续重入放大器；最终 dump 机制是 debug trap 进入时 GS 状态失配，异常入口自身递归页故障，直至 CPU 不再响应时钟中断。pending BS 导致第二次/延迟 `#DB` 是与 Unreal、KVM 语义和现场一致的高置信根因推断。
- `HvVwatch.c` 现改为私有单步专用注入门：不再写 pending BS，只在 CPL3、guest active、无已有 VM-entry 事件且无有效 IDT-vectoring 事件时注入一次 `#DB`。真实 guest 异常重放、外部 debugger vwatch 和原生调试体系未改。
- `Netr\build_test.bat Release DriverOnly` 已完成，驱动 C/ASM 0 warning/0 error；已测试签名并部署到 `Netr\test-package`。source/package SHA-256 均为 `B3F46AE88F83068F01368DAE853D16617E462271C2238FDF8E8ECD24F59A2EB9`，Authenticode=`Valid`，证书 thumbprint=`82FAA0D1CA193262D6EADF824DFE7C6DD2F5ACC4`。
- 本轮未安装或加载驱动，也未进行快速连续单步真机复测；运行验证仍由后续统一测试完成。

## 2026-07-17 自建 DebugObject 快速单步 0x101 修复

- Dump `C:\Windows\Minidump\071726-13750-01.dmp` 为 CPU 8 上的 `CLOCK_WATCHDOG_TIMEOUT (0x101)`；faulting ETHREAD 与 `GuardMeta-PrivateDbgk-entry-p15588-1784249701920.log` 中目标线程 token 一致。
- 根因链：潜伏缺陷是 `HV_PRIVATE_HOOK_BEGIN/END` 用 `__try/__finally` 包住 `HvPrivateHookDbgkForwardException`；第一项回归决策是把通用 hook rundown SEH 套到异常转发 hook；VT 单步 `#DB` 是运行触发，连续点击只是放大器；最终机制是 return 驱动的 `RtlUnwindEx` 经 `_C_specific_handler`/异常分发反复重入 private Dbgk hook，直到 CPU 8 无法响应时钟中断。其他 CPU 的 TLB shootdown 等待是后果，不是根因。
- Unreal Win10/Win11 的 `DbgkForwardException` 使用普通控制流，不存在等价的 return-time SEH unwind 包装。
- 当前 `HvPrivateHookDbgkForwardException` 改为显式 `HvHookCallbackAcquire/Release` 和单一释放出口；未增加异常类型过滤，目标、单步和 `DBG_EXCEPTION_NOT_HANDLED` 的分派语义保持昨晚可用基线不变。其他 hook、原生 DebugObject 模式和原生 VT 路径未因本修复改变。
- `Netr\build_test.bat Release DriverOnly` 与规范完整命令 `Netr\build_test.bat Release` 均完成；驱动 C/ASM 0 error，Full/Open 包刷新 14 个受管产物。
- 包内 `GuardMetaCore.sys` SHA-256 为 `213B8D77E4739BBF9A8CF895D2A044341C947D6055CFF9B5FFC5755BB4CCE189`；SYS/PDB 源与包哈希一致。测试签名有效，thumbprint `AD39C1B28DF46266E5E74CF60A46A8BEA97BB5F0`。
- 仍有既有非阻断 warning：Rust 25 条 unused/dead-code/private-interface，Vite 1 条 mixed static/dynamic import。
- 本轮未安装或加载驱动，也未做快速单步真机复测；运行时验证仍是下一道 gate。

> 后续工作流更新：`build_test.bat Release DriverOnly` 已不再跳过签名；driver-only 与完整构建现在都会自动测试签名并刷新 `Netr\test-package`。长期规则以仓库根 `AGENTS.md` 和 `Netr\README.md` 为准，本报告下文的“未签名 DriverOnly 中间产物”仅记录当时状态。

## 2026-07-13 接续结论（当前权威）

完整功能状态和两份参考差异见 `Netr\analysis\feature_inventory_2026-07-13.md`。本节覆盖并取代下方 2026-07-12 时点的“当前状态/阻断项”。

### 2026-07-13 18:20 Bridge exit20

- 最新日志确认 Driver `REGISTER=STATUS_SUCCESS`；exit20 是 Bridge baseline IAT transaction 设置 Abort 后的 Injector 本地退出码。
- 根因是 `VirtualProtect` 前以 `InterlockedCompareExchangePointer(slot,NULL,NULL)` 读取只读 `.rdata` IAT，LOCK CMPXCHG 触发 `0xC0000005`。现改为普通读取、页面可写后 CAS，并对可回滚的瞬时竞争做 Bridge 内部有限重试。
- x64/x86 Bridge/Injector 已以 `/W4` 重编并刷新 Full 测试包；Bridge64 SHA-256=`F1B9113101A7761CEB02B29973A95C3B9692ACC4DB07CCE1ABC30678D4B48DA7`。未启动调试器做运行测试。

### 2026-07-13 17:23 调试器 487、卸载卡死与最终测试包

- “试图访问无效地址”根因是同一 GPA 页上的 `NtReadVirtualMemory/NtWriteVirtualMemory` 第二个 Hook 被旧后端拒绝；Intel EPT、AMD NPT 现均采用 Unreal 同页多函数思路的唯一 page-owner/composite fake page。
- Bridge 登记改为 identity-only，不再在 transport `REGISTER` 阶段自动发布通用 syscall Hook；手工完整 debugger 登记仍保留 Proxy/AccessBypass 功能。
- 卸载改为先关闭 Injection/Debugger admission 与 process notify，再取消并 drain tracked APC/operation rundown，最后拆 Hook 和释放 backing lists；Ob callback 的 debugger-protect 与 access-bypass 所有权已分离。
- EPT 增加共享 MTF 仲裁、多页 pending 恢复、有限 epoch 退避和 trampoline fail-closed；NPT 按 Unreal 原页 `RW+NX` 稳态实现 fetch 时临时 composite fake 执行，并保留 guest 原 TF/#DB 状态。
- `Netr\build_test.bat Release` 已成功：驱动 C/ASM 0 warning/0 error，Bridge/Injector x64+x86、Rust GUI、签名与 Full profile 14 个受管产物完成；Rust 仍为 27 个既有非阻断 warning。
- 最终 `GuardMetaCore.sys` 为 422176 bytes，source/package SHA-256 均为 `BABD11BCCE7F6E23762DA0CB96CF0B2CC63DA5FD4EF8F42750F85C5389D25AC4`，Authenticode=`Valid`，证书 thumbprint=`82FAA0D1CA193262D6EADF824DFE7C6DD2F5ACC4`，Mode=`Open`。本轮未加载或运行测试；当前仍运行的旧映像已按旧 hash 保存在 `Netr\loaded-image-hold`，测试新包前应重启。

### 2026-07-13 15:22 Unreal 启动链对齐、事务收口与最新测试包

- Unreal 只读基线的实际顺序已按源码确认：`CreateProcess(flags=0)` 正常启动，等待 1000 ms，远程 `LoadLibrary` 并等待注入线程，最后 `SendDebuggerDataToDriver`。`Hook64.dll::SetupHook` 只安装固定调试 API，不启用 `LdrInitializeThunk`，也不替换 `GetProcAddress/LoadLibrary*`。
- 当前启动器保持正常启动并使用 `WaitForInputIdle + 至少 2 秒`；Bridge 已删除 loader/dynamic-import replacement，只允许主 EXE、`x32/x64dbg.dll`、`TitanEngine.dll`，排除 Windows、plugin、CLR/托管模块。
- Bridge 发布改为 `transport-ready -> 显式 debugger_add -> commit -> hooks-committed`。Injector 默认不再自动发布 Hook；30 秒无 commit 会中止。IAT 基线扫描返回结构化结果，并用逐槽 journal 记录原值；应用失败逆序恢复，rollback、PIN、候选数量和扫描完整性任何一项不满足都不发送 `Committed`。x64/x86 `/W4` 均编译通过。
- 内核 `REGISTER` 现在仅做 transport/capability negotiation；所有 BIND 必须已有匹配 `EPROCESS + CreateTime` 的显式 debugger record。generic unprotect 只删除 manual owner，Bridge UNBIND 与进程退出使用独立 owner/身份路径；AccessBypass 的启停统一进入 `g_DebuggerMutationLock`；Bridge anti-debug 查询只作用于 `BridgeOwned` target。
- 注册表枚举修复保留 saved trampoline，彻底移除 helper 对公开 `ZwEnumerateKey` 的同步重入。Hook 发布又拆为 `Prepare -> 发布 handle/trampoline (PreparedBypass) -> Activate -> Active`；卸载先进入 `Quiescing` 并让回调直走 trampoline，Remove 失败保留句柄供重试。`HvRegHookCleanup` 返回真实状态，Driver 只在 cleanup 成功时清除 ownership flags。
- EPT/NPT 后端已编译纳入 `Prepared/Active/Quiescing/Retired` 两阶段实现、每 CPU 原 leaf 精确恢复和失败句柄保留；这些高风险生命周期变化尚未做本轮真机运行验证。
- 最新完整命令 `Netr\build_test.bat Release` 成功：驱动 C/ASM **0 warning / 0 error**，Bridge/Injector x64+x86、Rust Release GUI、测试签名与 Full profile 收集全部成功。Rust 仍有 27 个既有非阻断 warning。
- 当前 `Netr\test-package\GuardMetaCore.sys` 为 415008 bytes，Authenticode=`Valid`，证书 thumbprint=`82FAA0D1CA193262D6EADF824DFE7C6DD2F5ACC4`；source/package SHA-256 均为 `D9E4985723CD6EE0112E427EB88B377E0C6F17B23AE3AD29AFC4E751E9625EE8`。Full profile 刷新 14 个受管产物，`LICENSE_MODE.txt` 为 `Mode=Open`，`SHA256SUMS.txt` 已刷新。
- 本轮没有安装、加载或运行驱动，也没有启动 x64dbg；运行结果必须由后续统一测试确认。`GuardMetaCore1.sys` 与 `GuardMetaCoreLegacy.sys` 仍是 `UNMANAGED_ARTIFACTS.txt` 所列旧产物，不属于本次构建。

### 2026-07-13 11:58 授权默认关闭与故障现场

- `GuardMetaBridge-9820.log` 中的保护启动失败已定位到授权门，而不是保护 hook：设备打开成功后，`IOCTL_HV_BRIDGE_REGISTER` 在进入分发分支前被 `HvLicenseIsValid()` 拒绝，内核 `STATUS_ACCESS_DENIED` 映射为 Win32 5；Bridge 重试只是重复暴露该拒绝，不是根因。
- 当前项目/测试构建默认 `Open`：`HV_LICENSE_ENFORCEMENT=0` 时驱动业务 IOCTL 全部放行，授权提交 IOCTL 也直接成功；只有显式 `build_test.bat Release Full EnforceLicense` 才恢复驱动 enforcement 与 GUI `network-license` feature。正式授权实现没有删除。
- Rust GUI 默认不再要求保存账号或登录：启动自动建立本地 `open` 会话；默认授权提交为纯 no-op，不打开设备、不构造或发送 license IOCTL。显式 `network-license` 和 legacy `dev-license-bypass` 仍是独立可选 feature。
- 新蓝屏现场为 `C:\Windows\Minidump\071326-13312-01.dmp`。该 dump 已完成 WinDbg、故障版本机器码和源代码交叉分析，结论见下方独立根因链；“驱动运行较久”只描述触发时机，不是根因，也与上述授权通信失败无关。
- 2026-07-13 11:58 `Netr\build_test.bat Release` Full 构建成功：驱动 C/ASM 0 warning/0 error，Bridge/Injector x64+x86 与 Rust GUI 均重编并刷新到 `Netr\test-package`。包标识为 `Mode=Open`，14 个受管产物写入 `SHA256SUMS.txt`；未安装、未加载、未运行驱动。
- 当前 `test-package` 内签名驱动仍是本轮故障修复前的 404256-byte 版本，源/包 SHA-256 均为 `C4BEE513162CD7FB0F8FBF57B6CE2C0488B4F028E5083A2E3B710DDA2D8FB561`，Authenticode 状态 `Valid`，证书 thumbprint `82FAA0D1CA193262D6EADF824DFE7C6DD2F5ACC4`。`GuardMetaCore1.sys` 与 `GuardMetaCoreLegacy.sys` 仍仅列在 `UNMANAGED_ARTIFACTS.txt`，不是本次产物。

### 2026-07-13 11:47 蓝屏：注册表枚举 hook 同步自重入

- 现场：`C:\Windows\Minidump\071326-13312-01.dmp`，SHA-256 `53D2D4BD4035DD0625F5251034009C1E59E2B52176BF3E44B51282C23DED09D3`；BugCheck `0x1000007F`、Arg1=`8` (`EXCEPTION_DOUBLE_FAULT`)，当前进程为 `WmiPrvSE.exe`。
- 符号陷阱：故障映像 Timestamp=`0x6A545D18`、Checksum=`0x6B0C3`、ImageSize=`0x34F000`；当前 Release PDB 和 12:35 Enforced 重建 PDB 都不是它的严格身份匹配。强制加载错位 PDB 后显示的 `HvRegHookCleanup` 不可信。Enforced 重建在故障 RVA `+0x355C0..+0x35640` 的机器码与 dump 逐字节一致，结合反汇编可确认真实函数是 `HookedNtEnumerateKey`，而不是依赖错位符号猜测。
- 可信现场为 RIP=`GuardMetaCore+0x35604`、RSP 正好等于当前线程 Stack Limit；故障指令是对 `HvHookCallbackAcquire` 的 `call`。可恢复调用环为 `HookedNtEnumerateKey -> RegFindVisibleRawIndex -> RegQueryRawKeyHidden -> ZwEnumerateKey -> HookedNtEnumerateKey`。现场有 19 条完整同步重入边，即栈上 20 个 `HookedNtEnumerateKey` 帧和 19 个 `RegQueryRawKeyHidden` 帧。

根因按最早不变量破坏排序：

1. **潜伏缺陷**：`NtEnumerateKey` 已被本模块 hook 后，hook helper 仍通过 `ZwEnumerateKey` 回到已替换入口，没有强制使用保存的原始 trampoline。
2. **第一项回归设计决定**：当前“第 N 个可见项”重映射实现把备份中直接调用 `g_OriginalNtEnumerateKey` 的闭环改成了 helper 内调用 `ZwEnumerateKey`，首次引入同步自调用。
3. **运行触发**：`WmiPrvSE.exe` 执行普通注册表枚举，进入已发布的 `HookedNtEnumerateKey`。所谓“运行较久”只是这次 WMI 枚举较晚发生。
4. **重入放大器**：每轮递归严格消耗 `0x520` 字节栈，其中包含 1024-byte `stackBuffer`；最外层到故障层的栈差 `0x6160 = 19 × 0x520`。这里没有 Bridge 重试、异步并发或授权门参与。
5. **最终故障机制**：栈递归推进到 guard page，下一条 `call` 压入返回地址时触发 #PF；内核已无空间建立异常帧，升级为 #DF，最终 `0x7F/8`。

修复以最早破坏点为界：保存的 `PFN_NtEnumerateKey` trampoline 现在显式贯穿 `RegFindVisibleRawIndex` 与 `RegQueryRawKeyHidden`，内部只调用该 `Original`，不再调用 `ZwEnumerateKey`。代码已落入工作树，但截至本段更新尚未编译、签名或运行验证，不能把它写成已测试完成。

### 2026-07-13 12:02 x64dbg 启动异常：CLR 程序集加载失败

- 故障进程为 `D:\tools\snapshot_2025-01-06_23-25\release\x64\x64dbg.exe`。2026-07-13 12:02:05（PID 16272）和 12:02:10（PID 16808）的 .NET Runtime Event 1026、插件日志及两份插件 dump 一致记录：`TargetInvocationException (0x80131604) -> FileLoadException (0x80004005) -> 无法加载 x64DbgMCPServer.Impl, Version=1.0.0.0`。
- 用户看到的 `0xe0434352` 是 CLR 抛出的托管异常代码；dump 中弹窗地址 `0x00007FFF52BB00AC` 对应 `KERNELBASE!RaiseException+0x6c`，不是缺陷函数本身。目标程序集存在、版本/位数匹配且没有 MOTW，同一时间窗也没有 CI、AppLocker 或 Defender 拦截证据，不能简化成“普通缺 DLL”。
- 两份 dump 的托管调用栈同型：`System.AppDomain.CreateInstanceAndUnwrap -> DotNetPlugin.PluginSessionProxy..ctor -> PluginMain.TryLoadPlugin -> PluginMain.pluginit`。`PluginImplDomain` 已加载 stub 与 `RemotingHelper`，但 Impl 没有成功进入域；`FileLoadException._fusionLog` 为空且 minidump 未保存 `_fileName` 字符串页，所以现有证据不能再向下虚构某个缺失依赖。
- `x64DbgMCPServer.log` 两次都记录 `OPEN win32=0`、`REGISTER ok=1 valid=1 status=0` 和 `ready`，且当时没有 target binding。因此这次异常不是 license 拒绝、Bridge 注册失败或 Bridge 自动重试导致的。
- 已验证的最早语义违规是 `HookedNtOpenProcess` 没有兑现“debugger 自身访问不受影响”的约束：日志中连续八次 `caller == target`、`access=0x400` 的 x64dbg self-open 被改写到 `ObOpenObjectByPointer(..., KernelMode, ...)` 路径。现已增加 `caller == targetPidFromCid` 时无条件调用原始 `NtOpenProcess` 的旁路。
- 另一项独立风险是注入时序和 loader IAT 覆盖面：问题版本在 `ResumeThread` 后立即注入，Bridge 随后 patch 全模块、周期重扫，并替换 `GetProcAddress` 与 `LoadLibrary*`。两个只读基线都给宿主/插件初始化至少约 1 秒。当前启动路径已加入 `WaitForInputIdle`、至少 2 秒 grace 以及注入前后存活检查；Bridge 已删除 `GetProcAddress`/`LoadLibrary*` replacement，只允许主 EXE、`x32/x64dbg.dll` 和 `TitanEngine.dll`，并明确排除 Windows、Bridge 自身、plugins、`.dp32/.dp64`、CLR 与托管模块。后加载核心模块另有 1.5 秒稳定窗口，完成项不再重复 patch。
- 现有最终异常 dump 不能做单变量实验，因而**不能证明** self-open 改写或 loader IAT hook 中任一个单独触发 Fusion `E_FAIL`。self-open 修复是纠正已证实的语义错误；收缩 loader hook 是兼容性和架构风险修复，不能冒充唯一根因。

根因按最早设计退化排序：

1. **潜伏缺陷**：debugger 特权 `NtOpenProcess` 分支没有排除 self-open；旧 Bridge 同时允许在宿主 loader 活跃期改写 loader/dynamic-import API。
2. **第一项回归设计决定**：把本应只负责 transport/capability negotiation 的 `REGISTER` 变成 debugger 注册和 syscall-hook 安装点，并在 `ResumeThread` 后立即注入。
3. **运行触发**：MCP 插件创建 `PluginImplDomain` 并加载 `x64DbgMCPServer.Impl`。
4. **放大器**：同一 loader 阶段连续八次 self-open，加上旧 Bridge 的全模块/动态加载干预；这不是 REGISTER 自动重试。
5. **最终故障**：Fusion 返回 `E_FAIL`，插件没有处理最终 `FileLoadException`，CLR 以 `0xe0434352` 终止 x64dbg。

#### Unreal 参考启动/注入约束

- `E:\project_learning\UnrealVTDbgBAK\UnrealDbgDll\StartProcess.cpp` 的稳定顺序是：`CreateProcess(flags=0)` 正常启动调试器，固定等待 1000 ms，调用 `AIHelper!InjectDll` 以 remote `LoadLibrary` 注入并等待远程线程完成，最后才用 `IOCTL_LOAD_DEBUGGER_DATA` 把 debugger PID 交给驱动。它从不在宿主 loader 初始化前发布驱动 debugger hooks。
- `Hook64.dll::SetupHook` 只安装固定调试 API detour；虽然源码保留 `Hook_LdrInitializeThunk`，实际启动集合没有调用它，也没有替换 `GetProcAddress` 或 `LoadLibrary*`。这不是偶然时序，而是明确的 loader 边界。
- 当前实现应保留该架构顺序：正常创建并让宿主/插件先稳定，注入和 Bridge ready 完成后才 AddDebugger/BIND；`WaitForInputIdle + 至少 2 秒`、远端模块校验和 ready event 是在参考顺序上的安全增强，不能反过来让 handshake 提前安装内核 hook。

### 故障修复状态（代码收口中，尚未验证）

- `HvRegistryHook.c` 已把保存的 original trampoline 显式传入两级枚举 helper，关闭同步自重入。
- `HvHook.c` 已增加 `NtOpenProcess` self-open 原始路径，并把重复 PID 注册从永久 `|=` 合并改为最新显式配置覆盖，允许后续配置真正关闭 privilege/protect/hide。
- `Driver.c` 的 Bridge `REGISTER` 不再固定强制 `EnablePrivilege=TRUE` 或 `ProtectFromTerminate=TRUE`；Bridge 专用 anti-debug 策略延迟到成功的首次 `BIND_TARGET`，绑定失败会回滚保护记录。
- Rust 启动器已在 resume 后执行 host initialization grace，并在注入前后确认进程仍存活；Bridge 的 loader IAT/模块重扫收缩仍在并行收口。
- 以上是当前共享工作树状态，不继承 11:58 旧包的构建结论。本轮尚未进行新的编译、签名、`test-package` 刷新或运行测试。

### 2026-07-11 旧 WER 的证据边界

- 7 月 11 日的旧 WER/转储只能证明早期 Bridge 进程曾出现 stack overflow/AV，不能直接解释 7 月 13 日的 CLR `FileLoadException`。
- 对应故障版本的旧 PDB 已丢失；使用当前 PDB 对旧日志地址做 sort/辅助映射只有中等置信度，不能据此证明 loader 递归，更不能覆盖上述 7 月 13 日两份现场的直接证据。

### 071226-14375-01 蓝屏根因链

1. **潜伏缺陷**：问题版本在 Windows 上下文使用 `HvPhysFindUserCr3ForGvaByPid -> HvPhysValidateCr3OwnsProcess -> HvPhysGvaToHpa -> HvPhysMapPage -> MmMapIoSpace`，为每个 CR3 候选反复映射并遍历页表。这个路径没有保持原 `HvVtRootCopyByPid` 的 root 物理窗口、root ownership 验证和隔离属性。
2. **第一项回归设计决定**：把原本由 VMCALL mode 按 PID 在 VMX-root/SVM-host 完成的 CR3 归属验证、页表 walk 和 copy，改成先在 Windows 请求上下文解析“最终 CR3”，再把结果交给 VT。跨越 VT-root/Windows 边界本身就是最早被破坏的不变量；Bridge 重试不是这一层设计变化的理由。
3. **运行触发**：调试器启动后的 Bridge 注册、目标绑定、模块枚举/内存访问进入 PID 数据面；dump 记录的进程为 `msedgewebview2`。
4. **放大器**：Bridge 对失败操作自动重试，使同一个不安全 Windows walker 被更频繁重入，缩短触发时间；停止重试只能降低频率，不能修复缺陷。
5. **最终故障**：dump 已验证 `0x7F`, Arg1=`8` (`EXCEPTION_DOUBLE_FAULT`)，bucket 为 `0x7f_8_STACKPTR_ERROR_GuardMetaCore!HvPhysMapPage`，可恢复栈包含 `MmMapIoSpace -> HvPhysMapPage -> HvPhysReadTableEntry -> HvPhysGvaToHpa`。双重故障 dump 已丢失第一异常的完整现场，因此不把无法证明的某个重试次数或单一调度时刻冒充最终根因。

### 已完成修复

- PID→CR3 候选只在 PASSIVE 侧以 `EPROCESS` 引用、`CreateTime/PEB/ImageBase`、MDL 锁页和 immutable request 收集；所有权判定、GVA walk、4KB/2MB/1GB leaf 处理和最终 copy 回到 root 预映射窗口。`g_VtRootEnabled=FALSE` 时明确失败，没有 Windows `MmMapIoSpace` walker fallback。
- VT-root mode 9 增加 64-byte versioned Leaf-PTE ABI；legacy mutation 对大页 fail-closed。
- Nested VMX/SVM gate 已开启，但只有 VtRoot/per-VCPU 固定池全部就绪后才发布；有 Running/Quiescing、事件、L2 fail-closed 和 unload quiesce。复杂 VMCS12/VMCB12 语义仍属实验性。
- Vwatch、私有 SWBP、VT HWBP 已接入 EPT violation/#BP/#DB/MTF、事件背压、target/debugger 所有权、退出与卸载 rundown；AMD 只如实报告 DR fallback，不虚报 VT HWBP。
- PEB cloak 已启用 Intel overlay：双 patch buffer、global/page root refs、MTF 状态、同 GPA 冲突拒绝、`PEPROCESS + CreateTime` 身份和 PASSIVE stale rebind worker均已接入；remap 先 identity fail-open，再经 VtRoot 重新绑定。
- 通用 EPT/NPT inline hook entry 使用双 epoch root reader；remove 等旧 reader 与 MTF/#DB completion，摘链后二次 epoch drain。普通 `HookFunction` 另有全局 callback rundown，所有活动 handler（含 FileHide/DriverHide/Registry/Network/injected-memory hide）入口 acquire；已移除 entry/fake page 延迟退休，只有关闭全局入口并等待全部在途 callback 后才释放。`RemoveAll` 不再绕过 rundown 批量 free。Intel 活动 root handler 的 CPU identity 改由 `VCPU_DATA.ProcessorNumber` 传入，不再在 violation/MTF 热路径调用 `KeGetCurrentProcessorNumber`。
- Driver/File/Registry/Network 启动链已接成条件发布事务，卸载按 Network→Registry→File→Driver 的真实逆序；真实 syscall 实现和 trampoline 缺失时回滚。Network 主 `NsiGetParameter` 发布不再被可选 enumerate hook 的失败污染状态；hook active 与 traffic rewrite enabled 分开，fake 默认关闭。
- DriverUnload 不再固定重试三次后继续：Nested L2 quiesce、普通 hook callback rundown、Ob callback 注销、注入 process-notify 注销和 nested cleanup 都必须成功 drain，才允许继续撤销 VtRoot/VT。injected-memory 动态列表延后到全局 hook rundown 后释放。
- Injection hidden/module 记录均绑定 `PID + CreateTime`；模块查找不再返回解锁裸指针，卸载使用锁内 claim，进程退出清理 allocation/module/hidden-memory 三类记录，关闭 PID 复用与 cleanup 并发窗口。
- raw-PTE 旧实现已恢复到不参与编译的 `HvPhysRawPteLegacy.c.disabled`；活动 alloc/free API 继续 fail-closed，等待 VAD/PFN/commit/working-set/rollback 设计完成。
- 驱动与 Rust 的正式 network-license 协议/验签/IOCTL 实现完整保留，但当前项目/测试默认是明确的 Open 模式，不再让缺少私有 SDK 阻断驱动、Bridge 或 GUI 通信；未来发布构建必须显式选择 enforcement。Rust GUI 的 memory/injection/input/process-hide/DSE/access-watch/private-SWBP v4 ABI 已按 driver pack/size 对齐并通过离线 `cargo check`。
- Bridge 能力协商不再虚报：VT memory/PEB/VT SWBP/HWBP 只在对应 root manager ready 时授予；Windows protect/COW 使用独立 `OS_*` bits；可选 hook 的实际 published 状态通过高位 state bits 返回。
- `HvHostPt` 的 slot 255/base 硬错误已修为 `0x00007F8000000000` 并加 `C_ASSERT`；因为 0..64GB 统一 WB/大页仍未排除 MMIO、全地址验证未完成，HOST_CR3 继续不发布。

### 仍保留但不虚报的功能

- `ENABLE_PE_IMAGE_OBFUSCATION=0`：旧代码保留，因直接改写 live image 且没有 VT read-shadow/rollback，仍为 unsafe-blocked。
- `HV_ENABLE_SVM_CLOAK=0`：AMD NPT overlay cloak 生命周期尚未实现，不能只翻 gate。
- Network NSI hook 会尝试发布，但流量改写默认关闭，且当前没有完整 versioned 用户态配置/status IOCTL。
- xHCI EPT trap 已补 per-vCPU leaf、原子 PTE 更新和跨 CPU split rollback 的静态实现，但仍未接入 Core 发布；本轮没有真机验证，继续由 `STATUS_DEVICE_NOT_READY` fail-closed。
- Rust GUI 仍没有 private-SWBP 专用 wait/continue event pump；当前 driver/Bridge v4 协议与普通 add/remove/step 路径已对齐，但不能把 GUI 高级命中交互标成完整。DLL 高级 HideFromPeb/Erase/ManualMap/StealthLevel 仍固定为 0，mouse ABI 没有 wheel 字段时非零滚轮请求明确失败。

### 编译、签名与测试

- 2026-07-13 11:58 最新 `Netr\build_test.bat Release`：驱动、DebuggerBridge/Injector x64+x86、Rust GUI、签名和 Full profile 收集全部成功；驱动 C/ASM **0 warning / 0 error**。
- 项目内公共 `.cer` 与实际 Windows 用户证书存储中的私钥匹配。证书 thumbprint `82FAA0D1CA193262D6EADF824DFE7C6DD2F5ACC4`，有效期至 2036-07-11。
- `Netr\x64\Release\GuardMetaCore.sys` 与 `Netr\test-package\GuardMetaCore.sys` 均为 404256 bytes、有效 Authenticode 测试签名，SHA-256 均为 `C4BEE513162CD7FB0F8FBF57B6CE2C0488B4F028E5083A2E3B710DDA2D8FB561`；source/package hash parity 已验证。
- Full profile 刷新 14 个受管产物及 `LICENSE_MODE.txt`、`SHA256SUMS.txt`。`GuardMetaCore1.sys` 与 `GuardMetaCoreLegacy.sys` 准确列入 `UNMANAGED_ARTIFACTS.txt`，不冒充本次构建产物。
- Rust 默认 Open 与显式 `dev-license-bypass` 的 `cargo check --offline` 均通过；Release GUI 构建仍报告 27 个既有/非阻断 unused/dead-code/private-interface warning，未用全局 `allow` 掩盖。
- 11:58 构建没有安装或加载驱动，也没有运行真机测试；`071326-13312-01.dmp` 此后已完成独立根因分析，但对应修复尚未产生新的已签名测试包，也没有运行验证。

### 网络/代理中断恢复审计

- `phys_abi_audit`：mode 9 Leaf-PTE ABI、Intel/AMD 寄存器约定和大页 fail-closed 已在共享树并通过驱动编译。
- `nested_audit`：生命周期、固定池、L2 fail-closed、事件与 quiesce 已在共享树；无“只汇报未落地”的改动。
- `vwatch_audit`：VT HWBP/private SWBP、#DB、MTF、事件背压、L2/PEB 冲突和 Bridge v4 已在共享树；Bridge x64/x86 已编译。
- `optional_hooks_audit`：真实 SSDT resolver、registry rundown、file/driver/network remove 失败保留 handle/original 已在共享树。
- `capability_truth`：能力位和可选 hook 状态已在 `Driver.c`、`NetrBridgeProtocol.h`、`DebuggerBridge/Bridge.cpp` 落地。
- `feature_inventory`：代理最终回报因网络/额度 403 中断，但 `feature_inventory_2026-07-13.md` 已完整写入并由主线程复核、更新 PEB rebind 状态。
- `peb_rebind`：代理中断时留下了编译错误和未接 page-local root gate；主线程补齐 `ZwWaitForSingleObject` 声明、`PEPROCESS/CreateTime` 引用、注册参数、page reader 持有到 MTF、shutdown/unregister drain 和 rollback 引用释放，最终编译通过。
- `hook_callback_rundown`：代理留下多处 callback 宏错位、自持 rundown 和覆盖不完整问题后被主线程停止；主线程逐项修正所有活动 handler、改用独立于 entry 生命周期的全局 rundown、retired-entry 延迟释放，并把 unload 改成确定性 drain，最终编译通过。
- `rust_gui_abi_fix`：memory/injection/input/hide/DSE/access-watch/event/private-SWBP v4 的 pack、长度和失败语义已落地，离线 `cargo check` 通过。
- `license_restore` 后续口径已修正：正式授权链保留供未来发布，但当前项目/测试默认 Open；GUI 不强制登录，驱动与 Bridge 通信不依赖 license。
- `interrupted_work_audit`：发现并推动修复 Injection `__finally` 错位、Nested/hook unload fail-open、Ob callback 残留、Network 发布状态和 module-record 裸指针/PID 复用问题。
- `xhci_trap_lifecycle`：代理留下的 per-vCPU/rollback 中间实现由主线程编译收口，但因为未做 focused runtime validation，Core gate 仍不发布该高风险路径。
- 当前没有仍在运行或等待回报的子代理；所有已知中断项均已由共享树复核，未把代理口头状态当作完成依据。

## 2026-07-12 时点状态（历史）

- 比较范围使用 `YuYuanVTDebug_备份\Netr` 和只读参考 `E:\project_learning\UnrealVTDbgBAK`；没有覆盖式迁移参考文件。
- `071226-14375-01.dmp` 的 `0x7F/8` 已定位为 Windows 上下文 PID→CR3 walker 与大栈 resolver 引发的双重故障；Bridge 重试只扩大触发频率，不是根因。
- PID→CR3 归属验证、页表 walk 和数据复制已经回到 VT-root；Windows 侧只保留进程引用、MDL 锁页和不可变身份快照。
- 最新 `Netr\build_test.bat Release DriverOnly` 已编译并链接成功；唯一代码警告仍是 `HvRegistryHook.c` 的既有 `ExAllocatePoolWithTag` 弃用警告。
- 构建在 `SignDriver.ps1` 停止：沙箱构建账户没有测试证书私钥。未签名、未刷新 `Netr\test-package`、未加载驱动；按本轮要求不做运行测试。

## 本轮蓝屏根因收口

- `HvVtRoot` 的 Intel/AMD process request modes 5–8 在 root 内按 `PID + CreateTime + PEB` 验证 CR3，随后完成 walk/copy；旧 Windows `MmMapIoSpace` CR3 walker 已删除。raw-PTE 旧实现保留在不参与编译的 legacy archive，活动 API 不启用其危险语义。
- nested VMX/SVM 仍含 VM-exit 物理映射旧路径，因此由默认关闭的编译 gate 阻断，setter 不能在 gate 关闭时误启用。
- `EptHookInstall` 在任何分配和链表发布前检查 Execute-Only 能力，消除了“已入链条目失败后直接释放”的悬空链表路径。
- DebuggerProxy、AAD 和 Bridge 的共享 hook 使用显式 owner bits，并统一受 `g_DebuggerMutationLock` 串行化；安装失败不再覆盖已有活 hook 句柄，重复 debugger 注册会检查并修复核心 hook。
- Proxy 只有 `NtSetContextThread + NtReadVirtualMemory + NtWriteVirtualMemory` 三项全部就绪才发布 enabled；回滚只释放 Proxy 自己的 owner，最后一个 debugger 移除时释放 Bridge/Proxy 所有权。
- 目标进程分配/释放继续使用 Windows MM 建立合法 VAD/commit；读写数据面仍走 VT。分配记录绑定 `PID + CreateTime + allocation base + size`，`MEM_RELEASE` 只接受精确记录，进程退出自动清理记录。
- `HvMemoryAllocate/Free/Protect` 均限制在 `PASSIVE_LEVEL`，attach 路径使用 `__try/__finally` 保证分离。

## 备份对比结论

| 功能 | 备份 | 当前原始状态 | 结论 |
| --- | --- | --- | --- |
| AccessBypass 自动生命周期 | 首个调试器启用、最后一个关闭 | 被删，仅保留手动 IOCTL | 当前真实削减，已恢复生命周期接线 |
| Intel #BP VM-exit | exception bitmap 含 bit 3 | 曾清为 0 | 当前已恢复 bit 3，但不能单独依赖旧事件链 |
| 私有 SWBP | 真实写入 `0xCC` 的未完成事件环 | 同样未完成 | 应改为 EPT execute-shadow，当前正在接入但未完成安全收口 |
| PEB EPT cloak | 备份也关闭且 worker 空操作 | 关闭，当前 worker 改为真实 PEB 清理 | 不是回归；需完成后才开启 |
| HOST_CR3 私有页表 | 只建结构、不接管 | 相同 | 不是回归；当前常量有硬错误，必须先修 |
| 驱动/注册表隐藏 | 备份同样 `#if 0` | 同样 `#if 0` | 不是回归；需要修共享 hook 所有权和卸载后才启用 |

## 本轮已落地

### AccessBypass

- `Netr\HvHook.c:2942`：首个调试器注册时启用 `DebuggerProxy` 与 `AccessBypass`，核心 hook 不完整时回滚本次注册。
- `Netr\HvHook.c:3187`：最后一个调试器移除时清理其 HWBP/SWBP/step/vwatch 资源，再关闭上述两组 hook。
- `Netr\HvHook.c:7006`：`NtOpenProcess` 主路径改为 `ObOpenObjectByPointer(..., KernelMode)` 创建当前调试器可用的普通 handle，避免直接改进程 token/protection 字段。
- `Netr\HvHook.c:6933`：原来的硬编码字段策略仍保留为 `HV_ENABLE_LEGACY_EPROCESS_ACCESS_FALLBACK` 兼容回退，默认关闭；在确认特定 Windows build 的偏移后可单独验证。
- `Netr\HvHook.c:7489`：Ob 回调不再给任意调用者扩大权限，只为已注册调试器恢复其原始请求 access。

### Overlay EPT 编译收口

- `Netr\HvPebCloak.h:157`、`Netr\HvPebCloak.c:54`：新增 `HvOverlayEptAcquireMutation/ReleaseMutation`，供 PEB cloak、vwatch 和私有 SWBP 在 PASSIVE_LEVEL 串行修改 `EptPebSpoof`。
- 这仅解决控制面互相踩写和当前编译缺失；它不等于 PEB cloak 已安全开启。

### 注册表枚举模块

- `Netr\HvRegistryHook.c:667`：新增 `HvRegHookInstallAtAddress`，避免直接把 Zw 短入口当成 hook 目标。
- `Netr\HvRegistryHook.c:495`：枚举改为按“第 N 个可见项”映射，修正原先隐藏项导致重复/漏项的问题。
- `Netr\HvRegistryHook.h:26`：`HvRegHookUninstall` 改为返回状态，并新增安装状态查询。
- Driver 端还没有接入正确初始化顺序和真实 NtEnumerateKey 地址，不能现在打开注册表隐藏。

### 私有 SWBP 中间实现

- `Netr\NetrBridgeProtocol.h:140`、`Netr\Driver.c:2127`、`Netr\HvVwatch.c:379`、`Netr\DebuggerBridge\Bridge.cpp:951` 已新增协议、IOCTL、EPT execute-shadow 和 Bridge 的私有事件投递骨架。
- Bridge 写入单字节 `0xCC` 时会改为注册 private SWBP 并抑制物理写入，目标代码页保持原字节。
- 这部分尚未达到可测标准，见下一节的阻断项。

## 下一会话必须先修的阻断项

### 1. 私有 SWBP 的生命周期与 root 安全

涉及：

- `Netr\HvVwatch.c:298`、`:351`、`:1309`、`:1335`、`:1708`
- `Netr\HvDebugger.c` 的 debugger ring 管理
- `Netr\Driver.c:2127`、`:2323`、`:2379`
- `Netr\DebuggerBridge\Bridge.cpp:951`、`:1722`、`:1803`

必须完成：

1. VM-exit 不能读取可能被控制面清零或复用的 SWBP/page 指针。给条目和 page 增加根路径引用计数或不可变快照；remove/target-exit 必须等待完整 grace period 后再复用。
2. MTF 上下文必须先写完整 `Pending*` 再发布 `Active`，销毁时也必须看到该引用。
3. 私有事件 ring 不能丢弃已经把条目置为 `HitPending` 的事件；需要保留槽、背压，或在溢出时安全恢复执行状态。
4. `0xCC`/`CD 03` 原字节必须有明确策略。当前单步重布路径会把真实断点和内部步骤混淆；先拒绝或完整支持后再放行。
5. Bridge 的 DLL detach、目标退出、`SuspendThread` 失败路径必须恢复被暂停线程，并清理 pending map。
6. 私有 SWBP 的 overlay 选择不能只依赖 PEB target；目标绑定或 SWBP 注册后都必须令该 target 使用 overlay EPT。
7. 目标页写入、COW、VA 重新映射和共享镜像页必须重新解析 GPA、同步 shadow 页；不能只按 VA 复用旧页。

完成后再做：普通断点、单步、删除断点、进程退出、调试器退出、并发多线程命中、重复 attach/detach 的软件测试。

### 2. PEB EPT cloak

涉及：

- `Netr\HvPebCloak.c:21`（当前 `HV_ENABLE_PEB_CLOAK=0`）
- `Netr\HvPebCloak.c:483`、`:556`、`:817`、`:876`
- `Netr\HvHook.c` 的 `HvHookpPebCloakRegisterWorker`
- `Netr\HvVmExit.c:848`、`:1615`
- `Netr\Driver.c:2914`

路线：

1. 先拆分 overlay EPT 生命周期，使 vwatch 和 PEB 不再由 PEB 宏互相决定是否分配。
2. PEB 页常驻映射补丁页为只读；只在写/执行访问时临时映射原页并使用 MTF。当前实现忽略 qualification，会把写访问导向只读补丁页，可能重复 EPT violation。
3. PEB 补丁页必须在原页发生写后同步非敏感字段，且敏感字段不能出现短暂真值窗口。第一阶段只处理 `BeingDebugged` 与 `NtGlobalFlag`，不要先启用 heap 页。
4. target slot 要有 `FREE/BUILDING/ACTIVE/RETIRING` 状态与 PASSIVE 控制锁；注册、退出、MTF、卸载之间不得释放仍被 root 路径引用的页。
5. `HvHandleCrAccess` 写入 CR3 后立即重新分类 EPTP；当前入口分类发生在 CR3 handler 之前。
6. `DriverUnload` 需要先 quiesce PEB/vwatch、恢复 PTE、等待 MTF，再 `HvCleanup()` 释放 `VcpuData/EptPebSpoof`。当前顺序在 `Netr\Driver.c:2914` 反了，开启后会使用失效 PTE 指针。
7. PEB worker 必须有 stop/rundown；卸载时先阻止新 worker、等待已有 worker，再拆 hook/释放 cloak 数据。

### 3. 私有 HOST_CR3

涉及：

- `Netr\HvHostPt.h:72`
- `Netr\HvHostPt.c:134`
- `Netr\HvVmcs.c:791`
- `Netr\HvCompat.h:145`

硬错误：`HV_HOST_PT_PML4_SLOT=255`，但 `HV_HOST_PT_PHYS_BASE_VA=0xFFFFFF8000000000` 实际属于 PML4 slot 511；同时代码复制了 system PML4[256..511]。因此现在不能把 `HvHostPtGetCr3()` 直接写入 VMCS。

路线：

1. 先把物理窗口放到正确 canonical 地址，或动态选择一个验证为空的槽；不得覆盖已复制的内核 PML4 项。
2. 用物理内存范围动态建立 RAM 映射，避免对 MMIO 使用统一 WB 映射。
3. 在每个 CPU 上软件 walk 验证 host code、vmexit stack、VCPU、GS/IDT/GDT/TSS 和物理窗口均能由私有 PML4 翻译到正确物理页。
4. 只有所有 CPU 验证成功才设置 `g_HvHostPtReadyForVmcs` 并让 `HvVmcs.c` 使用私有 CR3；否则继续安全的 system CR3 路径。

### 4. 驱动和注册表隐藏

涉及：

- `Netr\Driver.c:3321`、`:3383`
- `Netr\EptHook.c:6230`、`:5883`
- `Netr\HvHook.c:1396`、`:6652`
- `Netr\HvRegistryHook.c:667`

路线：

1. 为共享 `NtQuerySystemInformation` hook 增加 DriverHide 独立 owner/refcount。自隐藏不能依赖第一个 debugger 已注册，也不能在最后一个 debugger 移除时被误卸。
2. 在 `HvHook.c::HookedNtQuerySystemInformation` 正式接入 class 11 的模块列表过滤；当前该分支没有调用 `EptFilterModuleList`。
3. `EptHookInstallDriverHideHook` 必须在模块查询 hook 与对象查询 hook 都成功后才报告成功，并正确回滚。
4. 在发布设备名之前初始化 registry manager；隐藏名应为 `NetrSvc`，不是目前块中的 `Netr`。DriverUnload 要在 hook backend 清理前执行 `HvRegHookUninstall/Cleanup`。
5. 上述完成后再将 `Driver.c` 的 driver hide / registry hide `#if 0` 改为受控开关，先做 unload 循环和高频枚举测试。

## 验证与签名

1. 收口构建命令：`Netr\build_test.bat Release DriverOnly`。该模式是本轮新增，只构建驱动。
2. 当前链接已成功；唯一构建失败来自后置签名：`Netr\SignDriver.ps1` 找不到 `GuardMetaCore` 测试证书。
3. 恢复完整发布前，按既有流程以管理员权限运行 `Netr\SetupTestSigning.ps1` 一次，然后使用 `Netr\build_test.bat Release`；它会构建 bridge、前端、签名并收集到 `Netr\test-package`。
4. 在完成上述阻断项前，不要签发或上机加载本轮的中间驱动。

## 2026-07-14 内置调试器控制补全

- Native 模式已建立完整 Windows DebugObject 控制面：支持附加/启动、持久软件断点、DR0–DR3 硬件断点、Step Into/Over/Out、x64/WOW64 上下文，以及退出时恢复 INT3、DR、TF 和线程暂停计数。
- VT 模式保持用户程序/非系统模块断点走 private EPT，系统模块断点与 TF 单步事件走 Windows DebugObject；没有把相关数据面下沉到 Windows 内存管理器，也没有修改驱动数据路径。
- Native 与 VT 一次性断点均绑定目标 TID。Native 在恢复 INT3 到 TF 重装期间暂停其他线程并处理新线程继承；VT transient 可复用已有持久 private SWBP，错误线程不会消费原线程的 Step Over/Out。
- 前端增加 Step Into/Over/Out、Native/VT 软件与硬件断点操作；寄存器迁入右侧 Dock，显示 RIP，双击 RIP 会切到反汇编并定位。WOW64 使用 EIP/ESP、32 位解码和 4 字节返回地址。
- detach 顺序为清理断点/待处理事件、VT `UNBIND`、DebugObject detach；失败槽与暂停所有权保留供重试，权威 `UNBIND`/`DebugActiveProcessStop` 成功后不会继续保留僵尸会话。
- `cargo check --lib --offline`、`npm exec tsc -- --noEmit`、`git diff --check` 与 `Netr\build_test.bat Release` 均成功。Rust Release 仍有 26 条既有 unused/dead-code/private-interface warning，Vite 仍有一条既有 auth 动静态导入分块 warning。
- Full/Open 测试包于 2026-07-14 02:15:47 +08:00 刷新 14 个管理产物；`GuardMetaCore.sys` 源/包 SHA-256 均为 `17F238E4D8BCADB3C6C20FE91B039BF41F622C7C85AE95855A5AD2179EBDA9B7`，签名证书 thumbprint 为 `82FAA0D1CA193262D6EADF824DFE7C6DD2F5ACC4`，Authenticode 验证有效。
- 本轮没有安装或加载驱动，也没有执行真实调试会话运行测试。`GuardMetaCore1.sys`、`GuardMetaCoreLegacy.sys`、`guardmeta-vsp.running-17064.old` 仍是 `UNMANAGED_ARTIFACTS.txt` 中的历史/不可追溯文件，不属于本轮产物。

## 2026-07-16 自建 VT 单步 timeout 修复

- 根因不是 VT step 驱动 IOCTL 超时，而是自建 DebugObject 会话仍复用了原生 worker 的“空闲时由 `WaitForDebugEventEx(50ms)`返回后轮询 `mpsc`”假设；入口线程保持暂停且没有新 Dbgk 事件时，`StepIntoVt` 命令未被及时消费，调用方固定等待 5 秒后超时。Unreal 的事件循环没有这层跨 worker 同步回执，单步归属通过共享状态随真实调试事件消费。
- 仅对 `VtPrivateDbgk` 增加共享 VT-step intent：恢复线程前登记目标 TID，驱动完成 MTF 单步并注入 `#DB` 后，由该真实事件唤醒 DebugObject worker 并消费 intent。Native 与 Windows DebugObject VT 仍使用原有命令通道，状态机未合并。
- 自建模式的 transient step SWBP 改用目标 TID 作用域注册，使 main/overlay EPT 同步发布；其他模式继续使用原无作用域路径。诊断增加 `vt_step.begin/gate/arm/receiver/resume` 与 `vt_step.receiver.hit`，仍归入已标记的临时 PrivateDbgk 日志设施。
- `cargo check` 成功；Release 仍有 25 条既有 Rust unused/dead-code/private-interface warning，Vite 仍有一条既有 auth 动静态导入分块 warning。`rustfmt` 未安装，因此没有执行格式检查。
- `Netr\build_test.bat Release` 于 2026-07-16 19:36:36 +08:00 成功，驱动 C/ASM 0 warning / 0 error；Full/Open 测试包刷新 14 个受管产物。GUI SHA-256 为 `C35998655EF78196DFFF726F77CFDA2078459EA42F418145565C0E0D9D054880`，驱动 SHA-256 为 `BBCDF119DF72B327F62498F548B3F7C9E56D08A5630CD928B2A02B18D0D4F9BF`，源/包一致，14/14 `SHA256SUMS.txt` 校验通过，测试签名有效（thumbprint `AD39C1B28DF46266E5E74CF60A46A8BEA97BB5F0`）。
- 本轮没有安装或加载驱动，也没有执行真实自建 VT 单步运行测试。测试目录中的两份旧 `GuardMeta-PrivateDbgk-*.log` 仍列于 `UNMANAGED_ARTIFACTS.txt`，不属于本轮构建产物。

## 2026-07-16 自建 `DbgkForwardException` 对齐

- 现场日志与应用错误记录表明 VT MTF 单步已完成并注入 `#DB`，目标随后以 `STATUS_SINGLE_STEP (0x80000004)` 退出；缺口位于自建 Dbgk 异常转发链，不是 VT step IOCTL、入口断点或 worker 命令消费。
- 撤销未发布的 `KiDispatchException` 直拦截及协议 v7 扩展，恢复协议 v6。异常仅由自建 `DbgkForwardException` 处理：只接调试端口分支，按 Unreal 的 DR6 归属规则放过目标自有 DR0–DR3 命中，同步排队并等待 continue；`DBG_EXCEPTION_NOT_HANDLED` 的单步按 Unreal 语义吞掉。原生 DebugObject 路径不变。
- `Netr\build_test.bat Release` 于 2026-07-16 21:03:23 +08:00 成功；驱动 C/ASM 0 warning / 0 error，Rust 保留 25 条既有 warning，Vite 保留 1 条既有分块 warning。Full/Open 测试包已刷新，驱动源/包 SHA-256 均为 `AC4D5F294AA432EA68E5AD6F87EE5E149297995DB01151A452B17D77757A4071`，Authenticode 有效。本轮未安装或加载驱动，未执行运行时单步测试。

## 2026-07-16 main/overlay EPT Hook 一致性修复

- 最新 `p3408` 日志与 WER 再次确认：MTF 已完成并注入 `#DB`，但没有产生单步 `dbgk.event`；目标先以 `0x80000004` 在入口后一条指令退出，随后 Dbgk worker 解附并关闭命令通道，因此“sending half is closed”只是后果。
- 最早缺陷是 EPT Hook 仅发布到 main EPT。CPL3 注入异常后处理器直接进入 guest 内核，不产生可供 EPTP 重分类的新 VM-exit，故异常分发仍运行在 target overlay EPT，绕过 `DbgkForwardException` Hook。Unreal 只有单 EPT，不存在该断层。
- `EPT_HOOK_PAGE` 现同时保存 main/overlay 的逐 CPU leaf 与原始值；激活、同页复合发布、quiesce、remove 和回滚同步两套视图，VM-exit read/write/MTF/防御恢复按当前活动 EPT 选择 leaf。原生模式和 AMD NPT 路径未改。
- `Netr\build_test.bat Release` 于 2026-07-16 21:42:52 +08:00 成功；驱动 C/ASM 0 warning / 0 error，Full/Open 测试包刷新 14 个受管产物。驱动源/包 SHA-256 均为 `00F13F322B553F41D020684E8B7E7D5B46A3230C6E11C1B8EAF0C15DD130AF4E`，Authenticode 有效。本轮未自动加载驱动，运行时结果待现场复测。

## 2026-07-17 VT 单步放行与自建重启修复

- 原生 VT 单步崩溃的残留缺陷位于 `handle_single_step_event`：代码虽已分开 TF 与 VT intent，仍把 VT/MTF 注入的 `#DB` 合并进 `owns_single_step`，并通过 `SetThreadContext` 写回整组 DR 状态。现在只有真实 TF、INT3 rearm 和实际 DR 硬件断点能够清理其拥有的 DR6 位；VT intent 只消费自身状态，不写 TF/DR。
- 自建重启失败的最早缺陷是 loader 尚未完成时异步建立整页 PEB cloak 快照。失败日志中的 loader AV 分别落在 `ntdll+0x2567E` 与 `ntdll+0x7BF0A`，均为读取失效 loader 指针。启动型 Windows/private DebugObject 绑定现携带 `HV_BRIDGE_BIND_DEFER_PEB_CLOAK`，只 scrub 必要字段；入口断点真正挂起后由同一绑定所有者同步激活 cloak。运行中 attach 仍即时注册。
- 私有 `DBG_EXCEPTION_NOT_HANDLED` 现直接返回 `FALSE` 进入目标正常 SEH/second-chance，不再在私有调试器已经处理一次后又调用原始 DebugPort 转发。Windows DebugObject 路径不变。非私有 cloak worker 同时补齐 debugger identity 与模式字段，移除未初始化身份数据造成的随机拒绝。
- `Netr\build_test.bat Release` 于 2026-07-17 12:28:58 +08:00 成功；驱动 C/ASM 0 warning / 0 error，Rust 保留 25 条既有 warning，Vite 保留 1 条既有分块 warning。Full/Open 测试包刷新 14 个受管产物；驱动源/包 SHA-256 均为 `6D3B5F58BEBB368C5B37D93ABC12F6CDD4DAEF04EF47F6D54FA8E5A5FDFFBC28`，测试签名有效（thumbprint `82FAA0D1CA193262D6EADF824DFE7C6DD2F5ACC4`）。本轮未安装或加载驱动，运行时结果待现场复测。

## 2026-07-17 原生 VT 单步放行补全

- 上一轮修复不完整：正常完成分支已停止写回 VT 的 DR 状态，但 `prepare_resume` 的异常恢复分支仍会对未消费的 `vt_steps` 调用 `clear_owned_debug_status`；同时 `handle_single_step_event` 在确认 VT intent 前仍先读取并按 DR6 分类。现在 VT/MTF `#DB` 先按 TID intent 消费，只读取 RIP，不读写 TF/DR；恢复分支也只撤销 intent。
- 步进与放行现会完整释放同一 TID 的 private `SuspendThread` 持有和 Windows DebugObject event；MTF 事务只接受新的 native `#DB` pending 作为完成，旧 private pending 不再提前结束事务。自建 VT 仍使用独立的共享 intent，功能层代码保持共用。
- `cargo check --release` 与 `Netr\build_test.bat Release` 成功。Full/Open 包于 2026-07-17 13:00:25 +08:00 刷新；GUI 源/包 SHA-256 为 `46E1373132C6C78D7484E6B62240B537B0D159D93DC4548CC577D57D1F6A6909`，驱动源/包 SHA-256 为 `DA569B281078D4FD2159418B689BA38894143650004856C9C458A46B97B04EBE`，签名有效。未自动加载驱动，原生 VT 运行时复测仍待现场完成。

## 2026-07-17 卸载收敛与重启身份修复

- `C:\HvUnloadTrace.log` 确认最近一次卸载最终成功，但 32.549 秒全部消耗在 S10 `HvHookCleanup`。20 秒前端等待上限保持不变；修复的是关闭顺序：停止驱动前先权威清理内置调试会话与未发布 DebugObject worker，内核先关闭 hook/PEB cloak 接纳，停止 rebind 并排空 PEB worker，最后才移除 hook 和释放 cloak overlay。用户态原有 `terminate_owned_until_confirmed` 与 `finish_failed_detach` 两个显式无限循环已删除，attach 句柄补齐 `PROCESS_TERMINATE`；优雅清理失败会在约 3.5 秒内升级为终止或 DebugObject kill-on-close，随后幂等 UNBIND 并清理挂起事件。仍在执行的内核回调不会伪造 rundown 或强制 free，以免造成 UAF 蓝屏。
- 原生 VT 的“读取 RIP”不再通过 `SetThreadContext` 无写回目的地提交整份 control context；TF 写入后会读回验证。重启不再只凭 PID 打开终止句柄：要求唯一生命周期和活动 worker，并比较缓存/新开句柄的 PID 与进程创建时间，终止前再次验证身份。
- `cargo check --release`、DriverOnly 和完整 `Netr\build_test.bat Release` 成功；驱动 C/ASM 0 warning / 0 error，Rust 保留 25 条既有 warning，Vite 保留 1 条既有分块 warning。Full/Open 包于 2026-07-17 14:47:38 +08:00 刷新；GUI 源/包 SHA-256 为 `986D558561135B36C138F077C6A77562EC5206C7D2B0906C1886B238720FFEED`，驱动源/包 SHA-256 为 `11D004058495110A1E7DAFB0E196E0DA2E2AA8AD4E6539EC21127DC1F2B18A7C`，测试签名有效（thumbprint `AD39C1B28DF46266E5E74CF60A46A8BEA97BB5F0`）。本轮未安装、加载或卸载驱动，运行时卸载时长待现场复测。

## 2026-07-17 S10 阻塞型 hook 收敛

- 根因链已收敛：潜在缺陷是全局 `NtReadFile` hook 会进入可合法长期阻塞的同步文件读取；首个回归设计决定是加入正确的 driver-wide callback rundown 后，仍把这个第三层兜底与 `Original(...)` 整段纳入 rundown；运行时触发是在卸载时恰有同步读取尚未返回；全局拦截所有进程读取放大了命中概率；最终机制是 `ExWaitForRundownProtectionRelease` 必须等待该原始读取结束，对应现场 S10 的 32.549 秒。备份项目存在该兜底但没有安全 rundown，Unreal 不发布全局 `NtReadFile` hook。
- `NtReadFile` 防护实现完整保留在 `HV_ENABLE_BLOCKING_NTREADFILE_IMAGE_FALLBACK` 独立 gate 后并默认不发布；`NtCreateFile`/`NtOpenFile` 主文件防护保持开启。没有伪造 rundown、强减引用或释放仍在执行的 trampoline；这些做法会把卡顿变成 UAF/蓝屏。审查其余已发布回调后，未发现 `NtWait*` 一类按接口契约可无限等待的全局 hook。
- 完整 `Netr\build_test.bat Release` 成功；驱动 C/ASM 0 warning / 0 error，Rust 保留 25 条既有 warning，Vite 保留 1 条既有分块 warning。Full/Open 测试包于 2026-07-17 15:13:28 +08:00 刷新；GUI 源/包 SHA-256 为 `E6F347CF907BCD1F490A31919FD5A3753CBDA912A39472ED7E4DDD1F165B312B`，驱动源/包 SHA-256 为 `56928FFF39E4F8A8E1C34F908C56A12E4776388C2A41149BA6B56FAA5BEA3F5D`，测试签名有效（thumbprint `AD39C1B28DF46266E5E74CF60A46A8BEA97BB5F0`）。未自动安装、加载或卸载驱动；S10 时长需现场复测。

## 2026-07-17 Windows DebugObject VT 重启入口修复

- 构建后最新五份 VT 日志显示：两份 private Dbgk 均记录 `run_to_entry.success`，首次与再次启动正常；三份 Windows DebugObject VT 均已命中并发布入口 private SWBP，却因 `initial_system_breakpoint=true` 先等待额外的原生初始断点。最后一份日志在入口已挂起后正好等待 30 秒，随后以 `0xE0000001` 回滚终止。最早设计缺陷是同一个 `hold_initial_system_breakpoint` 布尔值同时承担“延迟 PEB cloak”和“等待原生断点”两种独立语义。
- `VtWindowsDebugObject` 现将 `defer_peb_cloak` 独立建模：启动仍携带 `BRIDGE_BIND_DEFER_PEB_CLOAK` 并在 VT 入口命中后激活 cloak，但不再等待第二套原生入口门。`cargo check --release` 与 GUI Release 构建成功；未重编驱动。Full/Open 测试包于 2026-07-17 17:24:10 +08:00 刷新，GUI 源/包 SHA-256 为 `C4063B441D3EB990347B2BA6DE50FD92B86BFD48926AFDDDF76B5839518AB2E1`；驱动仍为 `56928FFF39E4F8A8E1C34F908C56A12E4776388C2A41149BA6B56FAA5BEA3F5D`，签名有效。

## 2026-07-19 外部真实 TF 与内置可切换单步

- 会话历史与现存状态机确认，2026-07-14/16 的内置实现曾由 `native_debug::step_into` 设置并读回校验真实 `RFLAGS.TF`，再由 DebugObject 消费 `EXCEPTION_SINGLE_STEP`；该实现仍完整保留。备份项目直接设置 TF，Unreal 的 `NewSetThreadContext` 同样保留调试器提交的 TF。
- 外部调试器的 `SetThreadContext`/`Wow64SetThreadContext` 钩子现统一映射到独立 `BridgeSetThreadContextRealTf`/`BridgeWow64SetThreadContextRealTf`。两条路径保留现有 DR0–DR3/DR7 虚拟化，但不再调用 `ArmVtStep`，不再清除 TF；原生 VT 与自建 VT 因而都由 Windows 正常接收真实 `#DB`。旧 `BridgeSetThreadContext` 合成实现保留为源码回退点；回退只需恢复 `ReplacementForName` 与 `ReplacementForAddress` 中四个映射。
- 内置调试器新增默认开启的“合成 MTF 单步”会话开关。开启时，VT 用户地址的步入和普通非 call 步过保持现有 MTF/合成 `#DB` 事务不变；关闭时改走独立 `run_real_tf_single_step`。Native 会话固定使用真实 TF；跨 call 步过和步出仍使用原有一次性断点，不属于 TF/MTF 机制切换。
- R0 未修改。Intel VMCS 异常位图仍只拦截 `#BP`，真实 `#DB` 由 guest/Windows 所有；AMD VMCB 常态同样不拦 `#DB`，NPT 内部临时 TF 窗口会保存并恢复 guest 原有 TF 与拦截状态。
- Bridge x64/x86、`npm exec tsc -- --noEmit`、`cargo check --release` 和完整 `Netr\build_test.bat Release` 均成功。Full/Open 包于 2026-07-19 00:32:22 +08:00 刷新，14/14 `SHA256SUMS.txt` 校验通过；GUI SHA-256 为 `48497D4BE32AC8B18F0414DD9348E2BEA555AF842650DE0B4589E287A0ED740F`，驱动 SHA-256 为 `C34BD57DC900237758ADBF909CF2EA6FD4D034AD09AE8C8451FEA95EFE16D774`，Bridge64/32 分别为 `6E93A6D0B3DB52231DA7D5C5FE460E6EDA49D9A13011AD7B605F9AE4B2BA5DA7`/`C8480B46FC7D41D45055B6A248494A901D5AF5BE0206A3849E337CA38931993B`，驱动签名有效（thumbprint `82FAA0D1CA193262D6EADF824DFE7C6DD2F5ACC4`）。
- 本轮没有安装或加载驱动，也没有执行真实外部/内置四组合运行测试；运行时结果仍需现场分别验证。

## 2026-07-19 自建 VT 真实 TF worker 与私有 INT3 上下文修复

- 内置调试器在自建 VT 且关闭“合成 MTF 单步”时，日志 `GuardMeta-VtDebug-p13340-1784442036220.log` 反复只有 `real_tf.begin` 而没有 `real_tf.complete`。潜在缺陷是 `HvPrivateDebugObjectWait` 把 `STATUS_TIMEOUT (0x102)` 交给 `NT_SUCCESS` 判断；由于该状态为正数，有限等待超时被误判为成功并在内核内无限重等。首个回归设计决定是自建 DebugObject wait 循环没有显式把 timeout 当作返回条件；运行触发是当前没有待发布事件；50 ms worker 轮询与上层 5 秒命令等待放大了问题；最终机制是 Native worker 永远无法返回轮询命令队列，真实 TF 根本没有机会写入线程上下文。现已在 timeout 或失败时退出 wait，合成 MTF 路径未改。
- 外部调试器在自建 VT 下的日志 `logs\GuardMetaBridge-18680.log` 显示 private SWBP 命中后，下一事件变成地址 `0` 的 single-step，随后在地址 `0` 执行 AV。潜在缺陷是 `TryDeliverPrivateDbgkSwBpEvent` 发布 `EXCEPTION_BREAKPOINT` 时仅申请暂停/查询权限且不准备线程上下文，造成事件地址为断点地址、线程 RIP 却仍停在断点地址的不一致状态；首个回归设计决定是 private-dbgk 路由没有复用 native-debug-object 路由已有的 `PreparePrivateBreakpointContext`；运行触发是 private EPT 软件断点；标准调试器按真实 INT3 的 `RIP=bp+1` 约定回退 RIP 后放大偏差；最终从错误字节执行并跑入异常。现已让 private-dbgk 路由申请 GET/SET_CONTEXT 权限并复用同一上下文准备与既有 continue 归一化逻辑。
- 本轮没有修改 Intel VMCS 异常位图、STI shadow、pending BS、MTF 注入或 AMD VMCB 拦截语义。真实 TF 的 `#DB` 仍由 guest/Windows 正常处理；修复只恢复 worker timeout 契约与 Windows `INT3` 事件上下文契约。
- Bridge x64/x86、`Netr\build_test.bat Release DriverOnly` 与完整 `Netr\build_test.bat Release` 均成功。驱动 C/ASM 0 warning / 0 error；Rust 保留 25 条既有 unused/dead-code/private-interface warning，Vite 保留 1 条既有 auth 动静态导入分块 warning。Full/Open 测试包于 2026-07-19 15:09:57 +08:00 刷新 14 个受管产物，14/14 `SHA256SUMS.txt` 校验通过；驱动源/包 SHA-256 均为 `D6BF656F6E079C5405D1E47C540371C7BB4632D983837F97ED9F5659F5710D7D`，Authenticode 有效，证书 thumbprint 为 `AD39C1B28DF46266E5E74CF60A46A8BEA97BB5F0`。Bridge64/32 SHA-256 分别为 `F5D5D6CF482E27815F2E2646F42C83F71B27C7311495F55FC0BDED18F52D48C6`/`476E3270EAE3AF4291D3D42AC2C3596BC7098AE8153BFAB4475C3332A9866FBC`。
- 本轮没有安装、加载、启动或卸载驱动，也没有启动调试器。运行时仍需用新测试包分别复测：内置调试器自建 VT + 关闭 MTF 的入口与连续单步，以及外部调试器自建 VT 的 private SWBP continue、连续真实 TF 单步和新断点命中。

## 2026-07-19 自建 VT wait timeout 闭环修正

- 现场复测证明上一条修复不完整：内置自建 VT 在合成 MTF 开启和关闭两种模式都在单步分叉前失败。最新日志 `GuardMeta-VtDebug-p10684-1784447383251.log`、`p10048-1784447411977.log`、`p14564-1784447467853.log` 均先记录 `dbgk.wait.error`，随后 `attach.event_loop` 结束、session 消失；MTF 日志只剩 `vt_step.begin`，真实 TF 日志只剩 `real_tf.begin`。
- 第一处修复正确地让 `HvPrivateDebugObjectWait` 在 `STATUS_TIMEOUT` 返回，但遗漏了第二层消费者 `HvPrivateHookNtWaitForDebugEvent`：它仍用 `NT_SUCCESS(status)` 把正值 `STATUS_TIMEOUT` 当成成功，转换一个全零 wait-state 并返回 `STATUS_SUCCESS`，用户态最终看到 `ERROR_GEN_FAILURE (0x8007001F)`。这就是两种单步模式共同失败的最早违例，而不是 MTF/真实 TF 语义本身。
- 现已将该 hook 改为只有 `STATUS_SUCCESS` 才转换事件；timeout/error 原样向 Windows 返回。直接 `IOCTL_HV_BRIDGE_DBGK_WAIT` 的 timeout 结果和外部 Bridge 路径未改，外部现场已正常的私有断点修复保持不动。该契约与 Unreal `NtWaitForDebugEvent` 对 `STATUS_TIMEOUT` 的处理一致。
- DriverOnly 与完整 `Netr\build_test.bat Release` 均成功；驱动 C/ASM 0 warning / 0 error。Full/Open 包于 2026-07-19 16:21:45 +08:00 刷新，14/14 `SHA256SUMS.txt` 校验通过；驱动源/包 SHA-256 均为 `B0C418A7A7567026D99554525B6E90BADFB0716250FBA9D81210681411C0E5C9`，Authenticode 有效，证书 thumbprint 为 `AD39C1B28DF46266E5E74CF60A46A8BEA97BB5F0`。
- 本轮没有加载或启动驱动。下一次现场验证应先确认自建 DebugObject worker 在 50 ms 空闲轮询后仍存活，再分别验证 MTF 开/关入口单步；若仍有问题，应从新的 `dbgk.wait.*` 首个错误继续追，不再改动已正常的外部路径。
