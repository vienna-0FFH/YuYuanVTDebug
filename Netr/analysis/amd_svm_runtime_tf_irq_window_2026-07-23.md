# AMD SVM 真实 TF 单步 IRQ 窗口蓝屏根因与修复

> **已被后续转储推翻。** 本报告提出的“临时清除 guest `RFLAGS.IF`”会破坏 Windows 的真实执行语义，并已在 `072326-16781-01.dmp` 中直接造成 `IRQL_NOT_LESS_OR_EQUAL (0xA)`。该方案不得恢复或继续测试；现行结论与替代实现见 `amd_svm_tf_blockirq_vintr_2026-07-23.md`。

## 摘要

- 现象：AMD 主机加载驱动后 HV 已显示为 On，但运行很短时间后蓝屏。
- 转储：`Netr/test-package/072326-15781-01.dmp`
- 转储 SHA-256：`7EB0096A7C4CD14B8C83A59B07FB38DD2A5D0ED70BE91F1B80174FFD27D84A6D`
- Bugcheck：`SYSTEM_SERVICE_EXCEPTION (0x3B)`，异常码 `STATUS_SINGLE_STEP (0x80000004)`。
- 修复范围：仅 AMD SVM/NPT 的两类合成真实 TF 单步路径；Intel VMX/EPT、前端和调试器策略未修改。
- 回退补丁只作为故障隔离点保存，未应用到当前源码。

## 已验证事实

| ID | 证据 | 结论 |
|---|---|---|
| F1 | Bugcheck Arg1=`0x80000004`，故障 RIP=`NETIO+0x2ce57` | 最终故障是内核态未处理的单步异常，不是普通访问异常。 |
| F2 | `DR0-DR3=0`、`DR7=0x400`、`DR6=0xFFFF4FF0` | `DR6.BS=1` 且 B0-B3 均为 0，来源是 TF 单步，不是硬件断点槽命中。 |
| F3 | 故障线程位于 `vivoesService_` 的普通 NETIO 路径 | NETIO 是接收遗留 `#DB` 的位置，不是产生 TF 所有权错误的根因。 |
| F4 | AMD NPT 的通用页面恢复和调试器页面恢复均以 per-CPU 状态保存 TF/#DB owner | 设计假设“下一次 `#DB` 仍回到原 CPU”，但旧实现未阻止 guest 中断、调度和线程迁移。 |
| F5 | `YuYuanVTDebug_备份/Netr/NptHook.c` 只设置 `RFLAGS.TF` 和 `#DB` intercept，未保存或屏蔽 IF | 备份实现包含同一潜在缺陷，不能直接作为此问题的正确回退。 |
| F6 | Unreal 参考树没有 AMD SVM/NPT hypervisor 实现 | Unreal 不能为这段 AMD 生命周期提供可照搬语义。 |
| F7 | Linux 6.9.9 `arch/x86/mm/kmmio.c` 保存 `TF|IF`，单步前设置 TF 并清除 IF，完成后恢复；KVM 另有 `KVM_GUESTDBG_BLOCKIRQ` | 成熟实现同样把“真实 TF 窗口内禁止可调度中断”作为单步所有权条件。 |

## 根因链

1. **潜在缺陷**：AMD NPT 用真实 `RFLAGS.TF` 放行一条指令，owner 却只记录在当前 VCPU 的 per-CPU 状态中；旧代码没有封闭该指令窗口内的 guest 本地中断。
2. **首个回归性设计决策**：引入并沿用“设置 TF + 拦截 `#DB` 即足够”的备份语义，遗漏了 IF/IRQ 生命周期。近期真实 TF 路径使这个既有缺口变为常用路径，但缺陷本身来自不完整的单步模型。
3. **运行触发**：某个 NPT fault 在 guest IF=1 时布置 TF；目标指令完成前或其异常交付边界上发生 Windows 可调度中断。
4. **并发放大器**：Windows 可把带 TF 的返回状态保存到中断帧，调度该线程并在另一逻辑处理器恢复；NPT owner 和 `#DB` intercept 仍留在原 VCPU。
5. **最终故障机制**：线程在无 owner 的 VCPU 上执行一条普通内核指令后产生 `#DB(BS)`，该 VCPU 没有对应的内部单步收尾状态，异常泄漏给 Windows，最终形成 `0x3B/0x80000004`。

## 修复

- 新增统一的 `NptHookpArmGuestSingleStepState` / `NptHookpRestoreGuestSingleStepState`，供两类 AMD NPT 单步共同使用，避免两套状态恢复再次分叉。
- Arm 时保存 guest 原始 TF、IF 和原始 `#DB` intercept；设置 TF 的同时临时清除 guest IF，并显式设置 `VmcbCleanBits=0`，保证修改在下一次 VMRUN 生效。
- `#DB` 收尾时恢复原始 IF、TF 和 intercept 所有权；原 guest 已有 TF 或 DR6 存在非合成调试原因时继续向 guest 交付真实 `#DB`。
- 仅消费内部合成单步时清除 `DR6.BS`，避免把本次内部 TF 痕迹泄漏给 Windows，也不吞掉硬件断点、真实 TF 或其他真实调试原因。
- `NPT_DEBUG_STEP_CPU` 和 `NPT_STEP_CONTEXT` 都保存 `GuestIfWasSet`，覆盖调试器 NPT 单步与通用 NPT hook 单步两条路径。

## 参考项目边界

- 备份项目能证明当前 AMD NPT 的原始设计意图是“真实 TF + `#DB` 恢复”，但其实现没有 IRQ 排除条件，因此不是完整正确语义。
- Unreal 的 VT 调试语义可用于 Intel 路径对照，但该树没有 AMD SVM/NPT 实现，不能回答 AMD VMCB 的 IF、exception intercept 和 per-VCPU owner 生命周期。
- 本次没有把 Linux/KVM 代码直接移植进驱动；Linux 参考用于验证不变量，实际实现仍遵循当前项目 VMCB 和 NPT 状态结构。

## 回退点

- 回退文件：`Netr/analysis/amd_svm_runtime_tf_irq_window_rollback_2026-07-23.patch`
- SHA-256：`103663650C86CEB77CC2A0D7E70AE4CCFC0A5D3F3651C0FF9D769ED48B633B05`
- 该补丁方向为“当前修复版 -> 修复前版”，`git apply --check` 已通过。
- 该补丁未被应用；当前 `NptHook.c` / `NptHook.h` 仍保留 IF/TF/#DB 修复。
- 回退会重新暴露本报告描述的无 owner TF 风险，只能用于故障隔离，不应作为正常运行版本。

## 构建与交付

- `Netr/build_test.bat Release DriverOnly`：成功，驱动 0 警告、0 错误，测试签名和包校验通过。
- `Netr/build_test.bat Release`：成功，刷新 `Netr/test-package` 的 14 个受管制品。
- 驱动签名：`Valid`，证书 `CN=GuardMetaCore Test Signing`，指纹 `82FAA0D1CA193262D6EADF824DFE7C6DD2F5ACC4`。
- 14 个受管制品均与 Release/Bridge/GUI 源产物 SHA-256 一致，`SHA256SUMS.txt` 生成时间为 `2026-07-23 21:16:03 +08:00`。
- `GuardMetaCore.sys` SHA-256：`CD027C37187A96B32CDF15A4C8DB4C8E4EB29CF2F692716333EE379B8A943F0D`
- `GuardMetaCore.pdb` SHA-256：`0914982B35DA2D7733CC839638CF6BDEF0848DA39969924E88FB9795F30A4B94`
- `guardmeta-vsp.exe` SHA-256：`FAA13B55A0EE66D1D7B4E777E44AD031864D74DBD5CE12E995093D455989A800`
- 完整构建仍有项目既有的 1 条 Vite 动态导入提示和 25 条 Rust 警告，与本次 AMD 驱动修复无关。
- `072326-15781-01.dmp` 与 `hv-inactive.log` 被 `UNMANAGED_ARTIFACTS.txt` 正确标记为历史诊断输入，不属于本次构建产物。

## 运行验证边界

- 本机未安装、加载或启动驱动。
- 静态证据、局部构建、完整构建、签名、包清单和源包哈希一致性均已验证。
- AMD 真机下一轮应依次验证：首次加载后持续空闲、卸载/第二次加载、内置调试器、外部调试器、真实 TF 单步、硬件断点以及卸载期间仍有 NPT 活动的情况。
