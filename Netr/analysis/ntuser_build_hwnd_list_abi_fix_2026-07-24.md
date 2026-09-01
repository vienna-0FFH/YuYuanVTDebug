# NtUserBuildHwndList ABI 崩溃根因与修复

## 结论

最新核心转储对应的崩溃不在 AMD SVM 单步、NPT 事务或 Intel VMX/EPT 路径，而在共享的 `NtUserBuildHwndList` 窗口隐藏 Hook。Windows 11 Build 26100 的目标函数有 8 个参数，转储中的驱动仍以 7 参数 ABI 包装并回调原函数，导致第 4 个参数之后全部错位，最终让 `win32kfull` 解引用伪造地址并触发 `PAGE_FAULT_IN_NONPAGED_AREA (0x50)`。

第一次交付错误地把 7/8 参数选择和公共过滤 helper 放进 Intel/AMD 共享路径。随后 Intel 实机日志证明该版本使内置 VT 调试器在 `STEP_ARM` 后重新命中当前 RIP 的临时私有 SWBP，而不是收到 `0x80000004` 单步事件。当前纠正版本恢复 Intel 原有包装器和安装入口；AMD 使用完全独立的过滤 helper、7/8 参数包装器和版本选择。VMX、EPT、VMCS、SVM、NPT、VM-exit、`HvVwatch` 和用户态单步代码均未修改。

## 转储身份

- 文件：`Netr/test-package/MEMORY.DMP`
- 大小：`2,587,142,568` 字节
- SHA-256：`27741C3A641D1E90EE098871D3BB64EC3AB3E20BA80E53AF08A74F5CE983CCE4`
- BugCheck：`PAGE_FAULT_IN_NONPAGED_AREA (0x50)`
- 故障 CPU：12
- 当前进程：`QQEX.exe`
- 运行时长：约 `16:29:40`
- 故障栈：`win32kfull!NtUserBuildHwndList+0x23a -> GuardMetaCore!HookedNtUserBuildHwndList+0xb3`

## 已验证现场

- 故障指令为 `mov eax,dword ptr [r8]`，`r8=00007fffffff0000`，该地址不可读。
- 私有 PDB 局部变量显示旧包装器把 `dwThreadId` 读成 `1`、把 `cHwnd` 读成 `0`、把 `phwndList` 读成 `fffff80200000147`，并把实际 `phwndList` 错认成 `pcHwndNeeded`。
- 目标反汇编读取四个调用方栈参数槽 `[rsp+E0]`、`[rsp+E8]`、`[rsp+F0]`、`[rsp+F8]`；加上 RCX/RDX/R8/R9，目标函数总计 8 个参数。
- 崩溃 CPU 的 `SvmSingleStepBlockInterrupts=0`、`InterceptExceptions=0`，NPT 单步事务已空闲，排除上一轮 AMD TF 事务为本次直接原因。
- 原始 WinDbg 输出保存在 `amd_builtin_MEMORY_2026-07-24_triage.txt`、`amd_builtin_MEMORY_2026-07-24_fault.txt` 和 `amd_builtin_MEMORY_2026-07-24_abi.txt`。

## 根因链

1. **潜伏缺陷**：Hook 的函数类型没有表达随 Windows 版本变化的 7/8 参数 ABI，也没有在安装前做系统版本选择。
2. **首个回归决策**：从备份迁入了全版本统一的 7 参数包装器，并在 Build 26100 上无条件发布；备份本身同样包含这一错误，不能作为 ABI 正确性依据。
3. **运行触发**：`QQEX.exe` 调用 Windows 11 的 8 参数 `NtUserBuildHwndList`，进入驱动的 7 参数包装器后再调用 trampoline。
4. **放大条件**：不需要 VT 单步、并发或重试即可触发；窗口枚举的重复调用只增加命中概率，第一次携带有效输出缓冲区的调用已经足以暴露错位。
5. **最终故障**：缺失的第 4 个 `BOOLEAN` 使所有栈参数后移，目标函数把数量和用户指针解释为错误参数，最终在 `win32kfull` 中解引用 `00007fffffff0000` 并触发 `0x50`。

## 参考对比

- `YuYuanVTDebug_备份/Netr/HvHook.c`：只有 7 参数声明和包装器，错误与转储中的驱动一致。
- `E:/project_learning/UnrealVTDbgBAK`：没有实现这个 Hook，不能提供该 ABI 的参考实现。
- `E:/project_learning/HyperHide-master/HyperHide-master/HyperHideDrv/HookedFunctions.cpp:1664`：同时实现 8 参数与 7 参数包装器，并在 `HookWin32kSyscalls()` 中仅对 Windows 7 SP1 及更早版本选择 7 参数入口。

## 本次修改

- `Netr/HvHook.c`：引入已经由 `DriverEntry` 早期初始化的 `g_HvOsBuildNumber`。
- `Netr/HvHook.c`：Intel 恢复原 `PFN_NtUserBuildHwndList`、`HookedNtUserBuildHwndList` 和原过滤函数体，不调用 AMD helper，也不读取 OS Build 选择 ABI。
- `Netr/HvHook.c`：AMD 新增独立的 `PFN_AmdNtUserBuildHwndListSeven/Eight`、`HookedAmdNtUserBuildHwndListSeven/Eight` 和 `HvHookpFilterAmdNtUserBuildHwndListResult`。
- `Netr/HvHook.c`：只有 `g_HvHookBackend == CPU_VENDOR_AMD` 时才调用 AMD 版本选择；未知 ABI 区间仅在 AMD 上跳过这一 Hook。
- `Netr/HvHook.c`：局部编译门改为 `HV_ENABLE_AMD_NTUSER_BUILD_HWND_LIST_HOOK`，回退只关闭 AMD 新副本。

## Intel 边界

- 正常 Intel 日志 `GuardMeta-VtDebug-p11448-1784864624942.log` 在 `vt_step.arm.result` 后收到 `exception_code=0x80000004`，并连续完成多次单步。
- 错误共享版本日志 `GuardMeta-VtDebug-p16572-1784886603727.log` 在相同用户态流程后产生 `private_swbp.event sequence=2 rip=<原 RIP>`，没有单步异常，线程停在临时 gate。
- 两份日志中的 attach、入口 SWBP、pending continue、gate add、STEP_ARM 和 receiver 注册顺序一致；分叉发生在驱动恢复 guest 执行之后。
- 两次测试之间相关 VT/调试器源文件中只有 `HvHook.c` 被改动。该事实足以确定本次交付的回归边界，但目前没有伪造一个未经转储或硬件 trace 验证的更底层机制解释。
- 当前版本不修改 `AsmVmx.asm`、`EptHook.c/.h`、`HvEpt.c/.h`、`HvVmcs.c`、`HvVwatch.c`、`HvVmExit.c` 或用户态单步代码。
- 按“Intel 保持原行为”的要求，Intel 仍保留旧 7 参数包装器；因此本报告不再声称 Intel 上的 Build 26100 ABI 潜伏风险已被修复。AMD 的转储根因由独立 8 参数入口处理。

## 验证

- `Netr/build_test.bat Release DriverOnly`：成功，驱动编译、测试签名和 4 项 Driver 包刷新均为 0 warning、0 error。
- `Netr/build_test.bat Release`：成功，驱动、DebuggerBridge、32/64 位 injector、Rust/Tauri GUI 和符号全部刷新；GUI 保留 25 个既存 Rust warning。
- `Netr/test-package/GuardMetaCore.sys` 签名状态为 `Valid`，证书 `CN=GuardMetaCore Test Signing`，thumbprint `AD39C1B28DF46266E5E74CF60A46A8BEA97BB5F0`。
- 驱动源/包 SHA-256 一致：`0955CE26C6175DD74733F85335EE7EFC7CDCC159755F7B2B702A69FDB0F0E5AE`。
- PDB 源/包 SHA-256 一致：`6BAD7078982ABFD5CBAE23CFF070DF94EC18F55E30BD007F5F5539D436BB55EC`。
- `SHA256SUMS.txt` 的 14 个受管产物全部存在并逐项复算匹配。
- `MEMORY.DMP` 以原 SHA-256 正确列入 `UNMANAGED_ARTIFACTS.txt`，没有被当作构建产物。
- 安全回退补丁已对最终工作树执行 `git apply --check` 并通过。
- 修改前后 `AsmVmx.asm`、`EptHook.c/.h`、`HvEpt.c/.h`、`HvVmcs.c` 的 SHA-256 逐项一致。
- 没有自动安装、启动或加载驱动。

## 运行验证边界

静态 ABI 证据和构建只能说明 AMD 崩溃路径已隔离，不能替代目标机运行复测。Intel 首轮只验证与旧正常日志相同的入口命中和连续单步；AMD 首轮验证窗口枚举、驱动稳定性和内置调试器启动。两边分开测试，不再把共享改动一次性推给两个厂商。

## 安全回退点

如果 AMD 运行复测发现这个可选 Hook 仍有版本兼容问题，只禁用 AMD 新副本，不改 Intel：

```powershell
git apply --check Netr/analysis/ntuser_build_hwnd_list_disable_rollback_2026-07-24.patch
git apply Netr/analysis/ntuser_build_hwnd_list_disable_rollback_2026-07-24.patch
```

该回退只把 `HV_ENABLE_AMD_NTUSER_BUILD_HWND_LIST_HOOK` 从 `1` 改为 `0`；Intel 原包装器、其他窗口 Hook 和现有调试器代码不变。
