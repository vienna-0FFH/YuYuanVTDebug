# AMD 内置调试器核心转储根因与事务式 TF 修复

## 结论

`MEMORY.DMP` 证明这次 `CLOCK_WATCHDOG_TIMEOUT (0x101)` 不是符号问题、目标程序异常或旧转储重复分析，而是 AMD SVM 内部 TF 单步窗口把 KVM 的 `BLOCKIRQ` 错误映射成了宿主 `IF=0`。CPU6 在 NPT hook owner 活跃时进入 `cli; vmrun`，Windows 无法在该透明 hypervisor 上处理物理时钟/IPI，最终由 CPU7 发起 `0x101`。

本次修复只改 `Netr` 的 AMD SVM/NPT 路径，不改 Intel VMX，不清 guest `RFLAGS.IF`，不在 VM-exit 栈上直接运行 Windows ISR，也未加载驱动。

## 转储身份

- 文件：`Netr/test-package/MEMORY.DMP`
- 大小：`1,818,633,424` 字节
- 时间：`2026-07-23 23:07:40 +08:00`
- SHA-256：`C75B26EB8809DFEB1AF5D79D4EBF264A575C472E83F5D196FF550AA939F03416`
- BugCheck：`CLOCK_WATCHDOG_TIMEOUT (0x101)`
- 挂死 CPU：6
- 发起 BugCheck CPU：7

## 已验证现场

- `g_HypervisorContext.VcpuData = ffffd68721af0000`
- CPU6 VCPU：`ffffd68721af37b0`
- `SvmSingleStepBlockInterrupts = 2`，即 NPT hook owner 活跃
- CPU6 VMCB：`ffff80818591a000`
- NPT step context：`fffff803c1e239b8`
- `StepActive = 1`，`PendingPageCount = 1`
- owner page：`ffffd68721a54a30`
- `InterceptExceptions = 2`，只拦截 `#DB`
- `InterceptMisc1 = 0x90040001`，含 `INTERCEPT_INTR`
- `VIntr = 0x01000000`，含 `V_INTR_MASKING`
- guest `RFLAGS = 0x40386`，含 TF 与 IF
- 最后退出：`SVM_EXIT_NPF (0x400)`
- RIP：`win32kfull!NtUserBuildHwndList+0x23a`
- 指令：`mov eax,dword ptr [r8]`
- NPF GPA：`0x1129b7000`

证据原始输出保存在同目录的 `amd_builtin_MEMORY_2026-07-23_*.txt`。

## 根因链

1. **潜伏缺陷**：AMD NPT 的内部 TF 窗口假定下一次相关退出一定是 `#DB`，没有把 NPT 暴露、TF 所有权、异常位图和异步事件处理组成可回滚事务。
2. **首个回归决策**：把 KVM `KVM_GUESTDBG_BLOCKIRQ` 理解为关闭物理 IRQ，并在 owner 非零时执行 `cli; vmrun`。
3. **运行触发**：CPU6 处理 hook 页 fetch NPF，设置真实 TF、`V_INTR_MASKING` 和 `INTERCEPT_INTR` 后重新进入 guest。
4. **放大条件**：owner 必须等本 CPU 的 `#DB` 才释放；但宿主 IF 被持续清零，物理时钟/IPI 无法进入 Windows。
5. **最终故障**：CPU6 超过 watchdog 时限未响应时钟中断，CPU7 触发 `0x101`。

## 参考语义

- KVM `arch/x86/kvm/svm/vmenter.S:173` 使用 `sti; vmrun; cli`，从不因 guest debug `BLOCKIRQ` 把 Linux host 的物理 IRQ 长期关闭。
- KVM `arch/x86/kvm/x86.c:10415` 的 `KVM_GUESTDBG_BLOCKIRQ` 只阻止向 guest 注入虚拟 IRQ。
- 备份项目只设置 guest TF 与 `#DB` intercept，没有异步事件事务，因此只能证明旧功能意图，不能作为 SMP/中断安全实现。
- Unreal 的 Intel 路径在模拟并跳过指令后补 pending `#DB`；KVM 的 `kvm_skip_emulated_instruction()` 也执行同类语义。该点用于识别剩余严格语义差距，不用于为本次崩溃修复扩大 Intel 改动。

## 本次修改

- `Netr/AsmSvm.asm`：所有实际 AMD guest entry 统一为相邻的 `sti; vmrun; cli`；owner 字段不再控制宿主 IF。
- `Netr/NptHook.c`：TF arm 保存原 TF、完整 exception bitmap、原 `V_INTR_MASKING`/V_TPR、INTR/NMI intercept；窗口内拦截全部 guest exceptions、物理 INTR 与 NMI。
- `Netr/NptHook.c`：新增 owner-aware abort；先原子恢复 debug trap/NPT hook 页，再恢复 VMCB 状态并释放 owner。debug deliver 被中断时从 `COMPLETING` 回到 `ARMED`。
- `Netr/HvVmExit.c`：INTR/NMI/SMI/INIT/VINTR、非 `#DB` guest exception，或即将注入的 `EventInj` 会先中止内部 TF 事务，再沿原有 Windows 事件路径处理。
- `Netr/HvTypes.h`：明确该字段仅是 TF owner，不是宿主 IRQ gate。

## 为什么不再清 guest IF

清 guest `RFLAGS.IF` 会改变被单步指令可见状态，并可能把 IF=0 保存进 Windows 异常/中断帧；旧 `0xA` 已验证该方向不能成立。本修复保持 guest IF 原值，通过 SVM intercept 把异步事件变成可回滚 VM-exit。

## 验证

- `Netr/build_test.bat Release DriverOnly`：成功，驱动编译/签名验证 0 warning、0 error。
- `Netr/build_test.bat Release`：成功，驱动、DebuggerBridge、32/64 位 injector、Rust/Tauri GUI 全部刷新。
- 最终包驱动签名：`Valid`，证书 `CN=GuardMetaCore Test Signing`，thumbprint `AD39C1B28DF46266E5E74CF60A46A8BEA97BB5F0`。
- `Netr/test-package/GuardMetaCore.sys` 与 `Netr/x64/Release/GuardMetaCore.sys` SHA-256 一致：`D1F2FB1ADE6CA8A737C50025EB98D5684E00386247D9A91639E30635A814FEED`。
- PDB SHA-256 一致：`6AA5FB0A79A8A7104C9FD6CD68BBD8BA6545D4DD82CB7CBFE02191B7015A4FBF`。
- `SHA256SUMS.txt` 中 14 个受管产物逐项复算全部通过。
- `MEMORY.DMP` 正确列在 `UNMANAGED_ARTIFACTS.txt`，没有被误当成发布产物。
- 完整 GUI 构建仍有 25 个既存 Rust warning，与本次 AMD 修复无关。

## 运行验证边界

当前只能声明“完整转储对应的宿主 IF 饥饿根因已从代码上修复并通过构建/包校验”，不能在没有 AMD 目标机复测前声明运行问题已经最终关闭。首轮只应验证：加载后稳定、打开内置调试器、命中入口、连续单步、等待定时器/切线程、解附与卸载。

另外，CPUID/MSR/HLT 等由 VMM 模拟并推进 RIP 的指令，在内部 TF owner 活跃时仍需要单独实现“模拟指令退休后立即合成 `#DB`”才能达到 KVM/Unreal 的严格单步语义。本次没有把该语义扩展混入 `0x101` 修复；它不构成本次 watchdog 的原因，但应在后续独立变更中验证。

## 内置调试器与符号

架构上，关闭“VT 自建 DebugObject”后走 Windows 原生 DebugObject，不需要私有内核 Dbgk 符号才能创建进程或断入口；用户态 PDB只影响名称/源码显示。

但当前实现存在额外的启动硬依赖：`bridge_register_builtin()` 无论开关状态都请求 `BRIDGE_CAP_PRIVATE_DEBUG_OBJECT`，且只要驱动返回该 capability 就立即调用 `configure_private_dbgk_symbols()`。因此当前代码的实际行为是：**即使关闭自建模式，首次注册内置调试器仍可能解析/下载 nt 内核符号并因失败而中止**。这是控制面条件错误，不是原生 DebugObject 的技术要求；本次按“不要再动调试器代码”的约束只记录，不修改。

## 回退点

仅回退本次 AMD 事务修复可在仓库根目录执行：

```powershell
git apply --check Netr/analysis/amd_svm_tf_transaction_rollback_2026-07-24.patch
git apply Netr/analysis/amd_svm_tf_transaction_rollback_2026-07-24.patch
```

该补丁已对当前工作树执行 `git apply --check` 并通过；补丁头只包含上述五个 AMD 源码文件。

回退补丁不会还原工作树中更早的调试器、vwatch、GUI 或其他用户改动。
