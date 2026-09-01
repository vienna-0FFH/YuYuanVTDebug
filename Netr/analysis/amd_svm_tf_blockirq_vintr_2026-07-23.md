# AMD SVM 真实 TF：BLOCKIRQ/V_INTR_MASKING 修复

## 结论

- AMD NPT 的内部真实 TF 单步必须阻止该指令窗口内的可调度外部中断，否则线程可带着 TF 被保存、调度并迁移到没有 owner 的 CPU。
- 阻断不能通过修改 guest `RFLAGS.IF` 完成。guest IF 是 Windows 的架构状态，改成 0 会让普通 DemandZero 缺页进入不可服务上下文并直接蓝屏。
- 正确边界是：guest IF 保持原值；单步窗口临时启用 `V_INTR_MASKING`，用 VMRUN 时捕获的 host IF 控制物理 IRQ，并同步 `CR8 <-> V_TPR`。
- 当前修改仅位于 AMD SVM/NPT 路径。Intel VMX/EPT、前端选项和调试器策略未修改。

## 最新转储证据

- 转储：`Netr/test-package/072326-16781-01.dmp`
- SHA-256：`FB62B90BC4200EFDF38307BAE90C4436D812AD72901762D89FE9CDAA7496C6D5`
- Bugcheck：`IRQL_NOT_LESS_OR_EQUAL (0xA)`，故障点 `nt!BuildQueryDirectoryIrp+0x140`。
- 陷阱帧 `RFLAGS=0x50187`，其中 `IF=0`；`CR8=0`，说明不是 Windows 主动提高 IRQL 后访问分页内存。
- 故障地址 PTE 为合法的 `DemandZero`、`ReadWrite` 用户页。正常上下文应由内存管理器补页，不应成为致命访问错误。
- `DR6=0xFFFF0FF0`，`BS=0`，本次蓝屏不是遗留 TF `#DB`，而是前一版为了封闭 TF 窗口而清除 guest IF 的直接副作用。

## 根因链

1. **潜在缺陷**：AMD NPT 的真实 TF owner 是 per-VCPU 状态；如果单步窗口允许可调度中断，Windows 可把 TF 保存到中断帧并把线程迁移到其他 CPU。
2. **首个回归性设计决策**：把 Linux `kmmio` 在本机内核中短暂关闭 IF 的做法，错误映射成修改虚拟化 guest 的 `RFLAGS.IF`。两者不在同一架构边界。
3. **运行触发**：内置调试器启动后，某次 NPT 单步把 Windows guest IF 改成 0；随后普通目录查询访问一个尚未提交的 DemandZero 页。
4. **放大条件**：该访问本身完全正常，但 Windows 页故障入口把 IF=0 视为不可安全服务的上下文，内存管理器无法按普通路径完成补页。
5. **最终故障机制**：`MmAccessFault` 返回失败，`KiPageFault` 以无效/不可服务 IRQL 路径触发 `0xA`。因此最终故障点位于普通 `nt!BuildQueryDirectoryIrp`，而不在驱动栈上。

## 参考实现对照

### 备份项目

- `YuYuanVTDebug_备份/Netr/NptHook.c:920` 设置真实 `RFLAGS.TF` 并拦截 `#DB`。
- `YuYuanVTDebug_备份/Netr/NptHook.c:935` 在收尾时清 TF 和 `#DB` intercept。
- 备份没有 IRQ 窗口、`V_INTR_MASKING`、`CR8/V_TPR` 同步或跨 owner 排斥，因此只能证明“真实 TF + `#DB` 恢复”的原始意图，不能直接作为完整实现。

### Linux KVM/SVM

- `linux-6.9.9/arch/x86/include/uapi/asm/kvm.h:296` 定义 `KVM_GUESTDBG_BLOCKIRQ`。
- `linux-6.9.9/arch/x86/kvm/x86.c:10415` 在 BLOCKIRQ 生效时停止向 guest 注入普通中断。
- `linux-6.9.9/arch/x86/kvm/svm/svm.c:1265` 拦截 `INTR`，`svm.c:1303` 启用 `V_INTR_MASKING`。
- `linux-6.9.9/arch/x86/kvm/svm/vmenter.S:173` 使用紧邻 VMRUN 的 `sti; vmrun`，让 STI shadow 把 host IF=1 原子带入 VMRUN。
- `linux-6.9.9/arch/x86/kvm/svm/svm.c:3964` 和 `svm.c:3977` 在 VMRUN 前后同步 LAPIC CR8 与 VMCB `V_TPR`。
- KVM 的关键不变量不是“改 guest IF”，而是“guest IRQ 注入受 BLOCKIRQ 控制，SVM 的物理 IRQ 和 CR8 状态按硬件规则虚拟化”。

### QEMU SVM 模型

- `qemu-master/qemu-master/target/i386/tcg/system/svm_helper.c:334` 在加载 guest RFLAGS 前读取 `int_ctl`。
- 同文件 `:337` 在 `V_INTR_MASKING=1` 时保存 VMRUN 入口的 host IF；`target/i386/cpu.c:10458` 用该保存值决定物理硬中断是否可见。
- `target/i386/tcg/system/misc_helper.c:67` 和 `:111` 表明启用 `V_INTR_MASKING` 后，guest CR8 读写转向 `V_TPR`。
- 这验证了当前实现所依赖的硬件语义：`cli; vmrun` 可以阻断单步窗口内的物理 IRQ，同时 guest 仍看到原始 IF。

### Linux kmmio 与本项目的边界

- Linux `arch/x86/mm/kmmio.c` 可以直接清 IF，因为被单步的是 Linux 自己，IRQ 状态与单步 owner 属于同一个内核。
- 本项目是 L0 hypervisor，Windows 是 guest。修改 guest IF 会改变 Windows 可观察的架构状态，并破坏其缺页、异常和调度假设。
- 因此 `kmmio` 只能证明“单步窗口需要排除可调度 IRQ”，不能证明“hypervisor 应修改 guest IF”。对应的 SVM 实现必须采用 KVM/QEMU 展示的 `V_INTR_MASKING + host IF` 边界。

## 当前实现

- `NptHookpArmGuestSingleStepState` 保持 guest IF 不变，只保存原 TF、`#DB` intercept、`V_INTR_MASKING`、`V_TPR` 和 `INTR` intercept 状态。
- 当原先未启用 `V_INTR_MASKING` 时，arm 先把物理 `CR8` 复制到 `V_TPR`，然后临时启用 `V_INTR_MASKING` 和 `SVM_INTERCEPT_INTR`。
- `SvmSingleStepBlockInterrupts` 是 per-VCPU owner：`DEBUG=1`、`HOOK=2`，两类内部 TF 窗口拒绝重叠。
- `AsmSvm.asm` 在 owner 为 0 时执行 `sti; vmrun`，owner 非 0 时执行 `cli; vmrun`；两种情况下 guest RFLAGS 均不被改写。
- `#DB` 收尾时先恢复 TF、intercept 和 `V_INTR_MASKING` 状态；若本窗口临时启用了 V_INTR masking，则把 guest 最新 `V_TPR` 写回物理 CR8，再恢复原先不活跃的 V_TPR 位。
- 原 guest 已有 TF 或 `DR6` 含真实原因时继续重注入 `#DB`；只有纯内部 BS 才被消费。
- SVM 终止条件同时要求 owner、调试单步状态和通用 NPT 单步状态均归零，避免卸载跨过未完成窗口。

## 正确性边界

- 对 guest 可观察语义：IF 不变，目标指令仍以真实 TF 执行，完成后产生真实 `#DB`；这比清 guest IF 更接近裸机语义。
- 对 IRQ：仅在内部 TF owner 存活的 VMRUN 窗口阻断可调度物理 IRQ；窗口结束后恢复原始 SVM interrupt 状态。
- 对 CR8：临时启用 `V_INTR_MASKING` 时，guest 对 CR8 的变化不会丢失。
- 对 NMI/SMI：本修改不伪造 guest IF，也不屏蔽不可屏蔽事件；NMI 不应执行线程调度，因此不构成前述 TF owner 迁移路径。
- 仍需 AMD 真机验证。静态对照和构建不能替代首次加载、空闲、内置调试器、外部调试器、硬件断点、卸载和第二次加载测试。

## 回退点

- 回退补丁：`Netr/analysis/amd_svm_tf_blockirq_vintr_rollback_2026-07-23.patch`
- SHA-256：`0E12A183379A3B32D481CED48E517516D7F0B334F83781DE9C75308B7307273A`
- 补丁方向：当前 `BLOCKIRQ/V_INTR_MASKING` 实现 -> 前一版“清 guest IF”实现，仅用于故障隔离，不应作为正常版本。
- 实际校验命令：`git apply --check -p2 --directory=Netr Netr/analysis/amd_svm_tf_blockirq_vintr_rollback_2026-07-23.patch`
- 校验结果：五个目标文件均显示 `Checking patch ...` 且退出码为 0；补丁未应用。

## 构建状态

- `Netr/build_test.bat Release DriverOnly` 已成功：驱动 0 warning、0 error，测试签名和 DriverOnly 包校验通过。
- 完整 `Netr/build_test.bat Release` 已成功：驱动 C/ASM 0 warning、0 error；Bridge 32/64 位、注入器、Rust/Tauri GUI 和符号均已重新生成。
- 驱动签名状态为 `Valid`，证书 `CN=GuardMetaCore Test Signing`，指纹 `82FAA0D1CA193262D6EADF824DFE7C6DD2F5ACC4`。
- `Netr/test-package/SHA256SUMS.txt` 于 `2026-07-23 22:41:57 +08:00` 以 `Full (Release)` 刷新，共 14 个受管制品。
- 13 个二进制/符号/证书产物均已独立核对源目录与测试包 SHA-256 一致；第 14 项为构建生成的 `LICENSE_MODE.txt`，清单内 14 个哈希全部复算一致。
- `GuardMetaCore.sys` SHA-256：`9D8AD9320A368FD3748357A1C190BEA5700B3ADABBDA4493C96ED7E01600D139`
- `GuardMetaCore.pdb` SHA-256：`F921D75BDA84B1DFD48388849B6CB0D6210E3C527AEBF2CA3381035A0266A423`
- `guardmeta-vsp.exe` SHA-256：`45613D614AEEBF27597FA155AD8E49222F6D339F6EDB4AE1A30FE527DC94DA7C`
- `AsmSvm.obj` 反汇编确认：`cmp dword ptr [rax+940h],0`；普通路径 `sti` 紧邻 `vmrun`，owner 路径 `cli` 紧邻 `vmrun`。
- 本次五个 AMD 目标文件和被替代报告的 scoped `git diff --check` 通过；全工作树检查仍报告未由本次修改触碰的 `Netr/HvHook.c` 五处尾随空白。
- 完整构建保留项目既有的 1 条 Vite 动态导入提示和 25 条 Rust warning；本次驱动修复未新增 C/ASM warning。
- `072326-16781-01.dmp` 与 `hv-inactive.log` 被 `UNMANAGED_ARTIFACTS.txt` 标为历史诊断输入，不属于本次构建产物。
- 本机未安装、启动或加载驱动。
