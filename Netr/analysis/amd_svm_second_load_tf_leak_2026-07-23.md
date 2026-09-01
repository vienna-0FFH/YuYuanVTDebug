# AMD SVM 第二次加载 #DB 蓝屏根因与修复

## 摘要

- 现象：目标 AMD 主机第一次加载、卸载正常，第二次加载驱动时蓝屏。
- 转储：`Netr/test-package/072326-13312-01.dmp`
- 转储 SHA-256：`C73D89633D1D0364A99734E46B2A9119B0F9EAF28F68C9FB179736782EB54563`
- 辅助日志：`Netr/test-package/hv-inactive.log`
- 日志 SHA-256：`1220E975A7AFBFA24614F5923B08FABDC7625B69D98DDC354F4FB3150EA77299`
- 范围：仅 AMD SVM 的 NPT 合成单步与卸载生命周期；Intel VMX 和正常调试器单步语义未修改。

## 分析环境

- 调试器：本机 Windows Debugger `10.0.26100.6901 AMD64`。
- 符号：仅使用本地 `C:\Symbols`、`E:\Symbols`；未下载符号。
- 转储中的 `GuardMetaCore.sys` 时间戳为 `2026-07-23 14:44:46`，早于当前 PDB。驱动私有符号不用于故障归因；bugcheck、陷阱帧和调试寄存器均来自匹配的本地 Windows 内核符号及转储原始寄存器。

## 已验证事实

| ID | 证据 | 结论 |
|---|---|---|
| F1 | `SYSTEM_SERVICE_EXCEPTION (0x3B)`，Arg1=`0x80000004`，RIP=`nt!BuildQueryDirectoryIrp+0x571` | 最终异常是内核态未处理的 `STATUS_SINGLE_STEP`，不是访问违例 |
| F2 | `DR0-DR3=0`、`DR7=0x400`、`DR6=0xFFFF4FF0` | `DR6.BS=1` 且 B0-B3 全为 0，来源是 Trap Flag 单步，不是硬件断点槽 |
| F3 | 故障线程属于 `WerFault.exe`，命中位置是普通内核目录查询返回序列 | `nt!BuildQueryDirectoryIrp` 只是接收到遗留 `#DB` 的位置，不是根因 |
| F4 | `hv-inactive.log` 记录 `status=0xC0000001`、`virtualized=0/16`、`svm_debug_flag=0xB`、`svm_exit_count=10`、`svm_last_exit=0x81` | 第二次实例至少有一个 CPU 完成 SVM guest 入口，累计发生 10 次 VM-exit，最后一次是 VMMCALL，快照时已全部回滚；日志没有回滚前的 per-CPU 位图，不能把 10 次 VM-exit 严格解释为 10 个成功启动的 CPU |
| F5 | `NptHook.c` 的两类 NPT 单步都会临时设置 `VMCB.RFLAGS.TF` 和 `#DB` intercept，并保存 `GuestTfWasSet` 所有权 | 项目确实存在由 hypervisor 合成、必须在退出 SVM 前完成归还的真实 TF |
| F6 | AMD 卸载由 `KeIpiGenericCall` 在每个 CPU 执行终止 VMMCALL；终止汇编恢复 guest RIP/RSP/RFLAGS/DR 状态 | IPI 可以在“TF 已经布置但对应 #DB 尚未收尾”的单指令窗口内抢占 guest |

## 日志证据边界

- `hv-inactive.log` 能证明 AMD SVM 未被 BIOS 禁用、第二次实例实际到达过 guest、发生过 VM-exit，并最终回滚到 `0/16`；它不能直接记录第一次卸载时的 TF owner。
- `svm_exit_count=10` 是全局 VM-exit 累计值，`svm_last_exit=0x81` 只说明最后一次退出类型为 VMMCALL；二者都不携带 CPU 编号或 VMMCALL 命令号。
- 遗留 TF 的直接证据来自转储的 `DR6.BS=1`、`DR0-DR3=0`、`DR7=0x400`；第一次卸载竞争窗口则由该寄存器状态与 NPT TF owner、IPI 终止代码共同定位。

## 根因链

1. **潜在缺陷**：AMD NPT 使用真实 TF 完成单指令放行，但原生命周期没有“合成单步所有权必须归零后才能退出 SVM”的不变量。
2. **首次回归设计决策**：SVM 终止路径改为精确恢复 guest RFLAGS 后，仍沿用无条件一次性 IPI 终止；旧备份的终止路径没有真实恢复完整 guest 状态，因此只是掩盖了该缺陷。Unreal 参考项目没有 AMD SVM 实现，不能提供这一段语义。
3. **运行触发**：第一次卸载的 IPI 恰好打断一个已布置 NPT TF、尚未处理 `#DB` 的 CPU。
4. **并发放大器**：IPI 入口可把被打断上下文的 TF 保存在 Windows 中断帧中，而 VMMCALL 执行时的 live RFLAGS 已清 TF；因此在终止 handler 里粗暴清 VMCB.TF 既不充分，也会破坏真实调试器 TF。
5. **最终故障机制**：CPU 离开 SVM 后恢复含 TF 的 Windows 上下文，合成单步已失去 NPT owner；第二次加载又通过逐 CPU `pushfq/popfq` 和全有或全无回滚放大该状态，最终在普通内核代码处产生无 owner 的 `#DB(BS)`，触发 `0x3B/0x80000004`。

## 修复

- `NptHookSvmTerminationReady` 只读取当前 AMD VCPU 的两类 NPT 合成单步 owner；任一 owner 在途即禁止终止。
- 终止 VMMCALL 在 owner 未归零时推进 RIP、返回 `STATUS_DEVICE_BUSY` 并继续 guest，不执行 SVM 终止。
- guest 从 IPI 返回后让原有 `#DB` handler 按原逻辑完成 PTE、TF、intercept 和真实异常所有权恢复。
- `HvCleanup` 仅在 AMD 分支重发卸载 IPI，直到所有 VCPU 的汇编终止路径实际把 `IsVirtualized` 清零；Intel 仍保持单次原路径。
- 修复不清除真实 TF，不伪造 `#DB`，也不修改内部/外部调试器和硬件断点正常处理路径。

## 为什么不直接清 TF

直接在终止 VMMCALL 中清 `VMCB.RFLAGS.TF` 不是正确修复：IPI 抢占时 TF 可能已经位于 Windows 保存的中断帧而不在 live VMCB.RFLAGS 中；同时 `GuestTfWasSet=TRUE` 时 TF 属于真实调试器。延迟退出直到 owner 自己收尾，才同时满足完整状态恢复和调试语义。

## 构建与交付

- `Netr/build_test.bat Release DriverOnly`：成功，驱动 0 警告、0 错误，完成测试签名。
- `Netr/build_test.bat Release`：成功，完整测试包刷新为 14 个受管制品。
- `Netr/test-package/GuardMetaCore.sys` SHA-256：`216BB2FC64718FAECB75B901B5134D550EC68A58396FCAE68EAF5B2B3FA1685E`
- `Netr/test-package/GuardMetaCore.pdb` SHA-256：`3224EFE34974185A5EC40B2905464C3456401343EFD246D9ADC8BEEEA0F583EE`
- `Netr/test-package/guardmeta-vsp.exe` SHA-256：`37596FB089E6A0545473B7A52F3C8ED28EE279D1F2D275CE4807A15ED01822F5`
- SYS/PDB/GUI 与对应 Release 输出哈希一致；驱动 Authenticode 状态为 `Valid`。
- `SHA256SUMS.txt` 生成时间：`2026-07-23 15:49:20 +08:00`。
- 完整构建仍有项目既有的 1 条 Vite 动态导入提示和 25 条 Rust 警告，与本次 AMD 驱动修复无关。

## 回退与验证边界

- 仅撤销本修复：`Netr/analysis/amd_svm_second_load_tf_leak_rollback_2026-07-23.patch`。
- 回退会恢复“无条件一次性 AMD IPI 终止”，因此只能用于验证，不应作为安全运行版本。
- 本机未安装、加载或启动驱动。静态证据与构建验证已完成；AMD 真机仍需验证“加载 → 卸载 → 第二次加载”以及带内部/外部调试器真实 TF 的组合。
