# AMD SVM 加载期 0x133 根因与修复报告

## 摘要

- 转储：`Netr/test-package/072226-14296-01.dmp`
- SHA-256：`667BE3A3E3267C9A3AA2B7A5959405D053D814BA8DCF6EDC590AE3E4BED96DD3`
- 故障：`0x133 DPC_WATCHDOG_VIOLATION`，Arg1=`1`，Arg2=`0x1E00`
- 范围：仅 AMD SVM；未改 Intel VMX、调试器、vwatch 或前端
- 结论：当前 VMCB 在不拦截外部中断的情况下启用了 `V_INTR_MASKING`，破坏了直通中断必须服从 Windows guest `IF/CR8/interrupt shadow` 的语义。
- 状态：静态根因已修复并完成签名构建；未在本机加载驱动，AMD 真机运行验证仍待完成。

## 方法与产物

- 调试器：本机 `cdb.exe 10.0.26100.6901 AMD64`
- 符号：仅使用 `C:\Symbols`、`E:\Symbols` 和 `Netr/test-package/GuardMetaCore.pdb`，未下载符号
- 原始输出：
  - `Netr/analysis/amd_load_072226-14296-01_cdb.txt`
  - `Netr/analysis/amd_load_072226-14296-01_triage.txt`
  - `Netr/analysis/amd_load_072226-14296-01_cpus.txt`
  - `Netr/analysis/amd_load_072226-14296-01_globals.txt`
- 参考：只读备份、Unreal、Bochs SVM 模型和本机 Linux KVM AMD 实现

## 已验证事实

| ID | 证据 | 解释 | 置信度 |
|---|---|---|---|
| F1 | dump 为单处理器 kernel triage dump；`!irql` 为 `0x13` | 只能看到 CPU0，不能从该 dump 直接取得锁持有者 CPU 的栈 | 高 |
| F2 | CPU0 栈为 `nvlddmkm` ISR → `nt!KxWaitForSpinLockAndAcquire`，其上嵌套时钟中断并触发 `nt!KeAccumulateTicks+0x59c` | watchdog 截获时 CPU0 正在高 IRQL 自旋等待 | 高 |
| F3 | 故障参数 Arg1=`1`、Arg2=`0x1E00` | 系统累计长时间处于 `DISPATCH_LEVEL` 或以上，不是上一份 dump 的 `0x50` | 高 |
| F4 | 故障中加载的 `GuardMetaCore.sys` 时间戳为 `2026-07-22 23:29:21` | 新 dump 已运行包含 CET 状态修复的驱动 | 高 |
| F5 | 修复前 `VIntr.bit24=1`，但 `InterceptMisc1` 不含 `SVM_INTERCEPT_INTR` | 开启了 host interrupt masking 语义，却没有外部中断退出/重注入管线 | 高 |
| F6 | 本机 Linux KVM 同时设置 `INTERCEPT_INTR` 和 `V_INTR_MASKING_MASK`；Bochs 模型显示该位使物理中断参考保存的 host IF | 当前项目只复制了该组合的一半 | 高 |
| F7 | 当前 VMCB 断言与 Linux `vmcb_save_area` 对齐：`S_CET=0x1E0`、`SSP=0x1E8`、`ISST_ADDR=0x1F0`、`RAX=0x1F8` | 新故障没有证据指向另一个状态区偏移错误 | 高 |
| F8 | 只读备份也启用该位且不拦截 INTR；Unreal 参考仅实现 Intel VMX | 备份在此处包含同一潜伏缺陷，Unreal 不能作为 AMD 语义依据 | 高 |

## 根因链

1. **潜伏缺陷**：AMD 直通物理中断路径没有外部中断 VMEXIT/重注入实现，却设置了 `V_INTR_MASKING`。
2. **最早的错误设计决策**：把 KVM 风格的 `V_INTR_MASKING` 单独移入 VMCB，遗漏与其配套的 `INTERCEPT_INTR` 和 host IRQ 处理管线；该错误已存在于只读备份，不是本轮 CET 补齐引入。
3. **运行触发**：首次 `VMRUN` 保存启动线程的 host 中断状态，通常为 `IF=1、CR8=0`；之后 Windows guest 即使进入 ISR、清 IF 或提高 CR8，直通物理中断仍可能按保存的 host mask 判定。
4. **放大器**：多核设备中断和高 IRQL 锁竞争可在 guest 认为已屏蔽中断的窗口继续发生，形成重入或跨核优先级反转。
5. **最终故障机制**：CPU0 在 NVIDIA ISR 内长期等待自旋锁，时钟 ISR 累计发现系统高 IRQL 时间超过 `0x1E00` tick，触发 `0x133`。

第 4 步中具体是哪颗 CPU 持锁、是否为同向 ISR 重入，因 dump 仅保留 CPU0 而无法直接证明，置信度为中；前面的 VMCB 语义违规及最终 watchdog 栈均为直接证据。

## 修复

- `Netr/HvVmcb.c` 将 L0 透明直通模式的 `VIntr` 置零，使物理中断重新服从 guest `IF/CR8/interrupt shadow`。
- `Netr/HvVmcb.c` 增加启动期不变量检查，拒绝“启用 `V_INTR_MASKING` 但未拦截 `INTR`”的 VMCB。
- `Netr/README.md` 更新 AMD 中断模型说明。
- 保留 `InterruptShadow` 字段和现有 `CLGI`；没有删除 VMCS STI shadow，也没有改 Intel 路径。

## GIF 处理说明

本次没有在透明 root C 分发器前盲目加入 `STGI`。SVM 硬件在成功 `VMRUN` 时令 guest GIF 可接收中断，在 VMEXIT 时清 GIF；透明 hypervisor 应在短小 root 路径内避免让 Windows ISR/调度器跑在 host 模式和私有 VMEXIT 栈上。当前问题不是缺少 guest GIF，而是 `V_INTR_MASKING` 让直通物理中断绕过了 guest 自己的屏蔽状态。

## 构建与交付

- `Netr/build_test.bat Release DriverOnly`：成功，0 编译错误，驱动完成测试签名并刷新专项包。
- `Netr/build_test.bat Release`：成功，完整测试包刷新为 14 个受管制品。
- `Netr/test-package/GuardMetaCore.sys` SHA-256：`6E6FB1FDBFF56FA6748D00F3457564D1BD088D1F2B0DAF629BFC18566A3842D4`
- `Netr/test-package/GuardMetaCore.pdb` SHA-256：`C7215AECE990D21F93401946D0999D6384BFD40D84BAB5841F652218D5E13070`
- SYS/PDB 与 `Netr/x64/Release` 哈希一致。
- Authenticode 状态：`Valid`；证书指纹 `AD39C1B28DF46266E5E74CF60A46A8BEA97BB5F0`。
- 清单：`Netr/test-package/SHA256SUMS.txt`，生成时间 `2026-07-23 00:05:37 +08:00`。
- 完整构建仍有 1 条既有 Vite 动态导入提示和 25 条既有 Rust 警告；与本次 AMD 驱动修改无关。

## 回退与验证边界

- 仅回退本次中断控制修复：`Netr/analysis/amd_svm_v_intr_masking_rollback_2026-07-23.patch`
- 上一轮 CET 回退点仍独立保留：`Netr/analysis/amd_svm_cet_rollback_2026-07-22.patch`
- 不应把 CET 回退与本次中断修复绑定回退；新 dump 的故障类型变化和高 IRQL ISR 栈支持“状态装载已越过、随后暴露中断语义问题”，但 triage dump 无法读取驱动全局状态，因此该时序判断置信度为中。
- 本机未安装或启动驱动，不能把编译/静态语义验证表述为 AMD 真机已通过。
