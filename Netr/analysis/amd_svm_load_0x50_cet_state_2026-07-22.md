# AMD SVM 驱动加载 0x50：CET 状态缺失分析与修复

## 当前阶段 / Current phase

- 故障发生在驱动加载后首次启用 AMD SVM，不涉及内置/外部调试器、硬件断点或目标进程启动。
- 本次只修改 AMD VMCB/SVM 入口；VMX、Intel、调试器、vwatch 和前端策略均未修改。
- 修复已完成 DriverOnly 与规范完整 Release 构建、测试签名、测试包刷新、清单校验和对象级反汇编验证；AMD 真机加载仍待验证。

## 已验证事实 / Verified facts

- Dump：`Netr/test-package/072226-15296-01.dmp`
- Dump SHA-256：`8D37EF166B116CC673E687881CDEE133D39EC032681D06585389C8BC51F91291`
- Bugcheck：`0x50 PAGE_FAULT_IN_NONPAGED_AREA`
- CPU：AMD Ryzen 7 7435HS，family 25 model 68 stepping 1，16 logical processors
- Fault CPU：2；进程：`msedgewebview2`
- Fault：`nt!RtlpWalkFrameChain+0x1B9` 读取 `0x00000001B6A7F7EE`
- 线程 TEB：`0x00000001B6A7E000`；故障地址是该有效用户 TEB 页内的 `TEB+0x17EE`。
- `!pte` 显示四级映射均有效，叶 PTE 为 U/S 用户页；这不是缺页或坏指针。
- Fault CPU `CR4=0x0000000000B50EF8`，同时启用 `SMAP` bit 21 与 `CET` bit 23。
- `RtlpCaptureContext2` 保存的上下文 `EFLAGS=0x00040282`，即 `AC=1`；故障 trap `EFLAGS=0x00010206`，除异常自动加入的 `RF` 外，关键变化是 `AC` 已丢失。
- 当前 VMCB 初始化先清零整个 state-save area；修复前 `VMCB+0x5E0..0x5F7` 被声明为 `Reserved5[0x18]`，因此一直为零。
- Linux 6.9.9 的 AMD `vmcb_save_area` 明确定义该区间为 `s_cet`、`ssp`、`isst_addr`，相对 state-save 偏移分别为 `0x1E0/0x1E8/0x1F0`，完整 VMCB 偏移为 `0x5E0/0x5E8/0x5F0`。
- 两个只读参考工程都不能提供正确实现：备份工程同样把该区间当保留区，Unreal 参考没有 SVM 路径。

## 根因链 / Root-cause chain

1. **潜在缺陷：** AMD VMCB 结构漏掉现代 supervisor CET 的 `S_CET/SSP/ISST_ADDR` 三个状态字段，初始化又把对应 24 字节清零。
2. **首个暴露该缺陷的设计决定：** 上一轮为了修复无效 VMRUN/附加状态不对称，首次引入 `host VMSAVE -> guest VMLOAD -> VMRUN`。状态切换方向是正确的，但 guest VMCB 没有同时补齐 CET 状态契约。
3. **运行时触发：** 驱动加载时 CPU 2 在 `CR4.CET=1` 的 Windows 24H2 内核上首次加载/进入该零 CET VMCB；随后 ETW 栈回溯在一个合法的 SMAP `STAC` 用户页读取窗口内运行。
4. **放大因素：** 本次 dump 没有无效 VMRUN 重试环，也没有证据表明调试器参与。多 CPU 同步启动只提高了在任一 CPU 上撞到敏感窗口的概率，不是根因。
5. **最终故障机制：** 原上下文的 `AC=1` 在虚拟化/异步切换后变为 `AC=0`，SMAP 因而把 ring 0 对有效 U/S 页的读取判为保护违规，最终在 `RtlpWalkFrameChain` 触发 `0x50`。

第 1、2、3、5 项中的结构、指令顺序、CR4、PTE 和两份 RFLAGS 均由源码、对象反汇编或 dump 直接验证。零 CET guest 状态到 AC 丢失之间的精确微架构步骤无法由只有故障 CPU 栈的 mini dump 直接观察，因此该连接属于高置信推断，而不是伪装成已证明事实。

## 修复设计 / Repair design

- `HvTypes.h`：把 `Reserved5[0x18]` 精确替换为 `SCet/Ssp/IsstAddr`，不改变 `Rax` 及所有后续字段偏移或结构总大小。
- `HvVmcb.c`：增加 `0x1E0/0x1E8/0x1F0` 三个编译期偏移断言。
- `AsmSvm.asm`：仅当当前 AMD CPU 的 `CR4.CET=1` 时，在首次 `VMLOAD/VMRUN` 前读取 `MSR 0x6A2`、当前 `SSP` 和 `MSR 0x6A8`，写入 guest VMCB。
- 当前 `SSP` 使用内联 `RDSSPQ`，不能放在 C helper 中：调用 helper 本身会向 supervisor shadow stack 压入返回地址，helper 返回后 SSP 又变化，写入 VMCB 的值会天然错一帧。
- 捕获点位于 `AsmSvmLaunch` 最后一次 `CALL` 之后，且捕获后到 `VMLOAD/VMRUN` 之间没有任何 `CALL/RET`，因此 regular stack 与 shadow stack 的启动帧保持一致。
- `CR4.CET=0` 时三个字段显式清零，旧 AMD 不执行 CET MSR 或 `RDSSPQ`。

本修复没有删除 `VMLOAD`，没有清除 `CR4.CET`，也没有强行设置 `RFLAGS.AC`。这三种症状性方案分别会重新破坏附加状态对称性、改变 Windows CET 语义，或把错误 guest RFLAGS 掩盖为伪正确状态。

## 二进制验证 / Binary verification

- DriverOnly：`Netr/build_test.bat Release DriverOnly`
- 编译：零警告、零错误。
- 签名：成功；证书 SHA-1 `82FAA0D1CA193262D6EADF824DFE7C6DD2F5ACC4`。
- `AsmSvm.obj` 反汇编确认：`bt rax,17h` 门控 CET，`rdmsr 0x6A2` 写 `VMCB+0x5E0`，`rdsspq rax` 写 `+0x5E8`，`rdmsr 0x6A8` 写 `+0x5F0`，随后才执行 `CLGI/VMSAVE/VMLOAD/VMRUN`。
- DriverOnly packaged SYS SHA-256：`174BB2CB3E0450452E82E5B398CD26267BD8F1930C08F89E670A569332479A9C`
- DriverOnly packaged PDB SHA-256：`7C5DB7769558FAD8C63819830F1B16036304A74A9ED42B6C8CF616016CF5129C`
- 对象反汇编记录：`Netr/analysis/amd_svm_cet_asmsvm_obj_disasm.txt`
- 离线控制寄存器记录：`Netr/analysis/amd_load_0x50_offline_control_regs.txt`

规范完整构建：

- 命令：`Netr/build_test.bat Release`
- Driver/MSVC：零警告、零错误；DebuggerBridge 32/64 与 injectors 构建成功。
- Rust/Tauri GUI：构建成功；保留 25 个与本次 AMD 修复无关的既有 Rust 警告。
- 最终测试包：Full profile，14 个 managed artifacts；`SHA256SUMS.txt` 逐项验证 `14/14` 全部匹配。
- 最终 packaged SYS 与 `Netr/x64/Release/GuardMetaCore.sys` SHA-256 相同。
- 最终 packaged PDB 与 `Netr/x64/Release/GuardMetaCore.pdb` SHA-256 相同。
- 最终签名：有效；证书 SHA-1 `AD39C1B28DF46266E5E74CF60A46A8BEA97BB5F0`。
- 最终 packaged SYS SHA-256：`50AB424C3286C18C24B66D66D6F38172144EB4A149E3BBA1AF4749901DF3157B`
- 最终 packaged PDB SHA-256：`BA6C725A2F41B07A08A659432787E24397E830A9ACF72054F59893DD68BA378D`
- 最终 `SHA256SUMS.txt` SHA-256：`7CC285FC1BBCCF4A8B4F1BA4FF808384D6B215E680668128550FB96CEAB059F6`
- `UNMANAGED_ARTIFACTS.txt` 将本次 dump 和既有调试日志明确标为 stale/unmanaged，未把它们伪装为本次构建产物。
- 回退补丁已通过本机 GNU `patch.exe --dry-run --binary -p1`；历史源文件存在混合 CRLF/LF，因此未用 `git apply` 作为验证器。

## 回退点 / Rollback point

修复前、会产生本次 `0x50` 的精确源码和包哈希：

- `AsmSvm.asm`：`D4C5D76B22078DB0C5CFC4B8268A5A1C9066A9F9398C6C549657DB2AE3FC8288`
- `HvTypes.h`：`92F4F3A12B0989409EC2B05DD1E281671776F07CB75260887A4F2D176BD8913F`
- `HvVmcb.c`：`75D4F8A48C0D7FA4FEEBE603EEB9A7C2B1B1649ABB6087A51B2A196367A1C169`
- Packaged SYS：`4C7AAD81003BA0FACF5E0EA36F5BE33AC58E6B0F6429184636DBB9CDF47E5233`
- Packaged PDB：`E281AD95F0CC6DC3DE62EC4327C884467D28F666C1665CC9F2A7A1A72A20AE5C`
- 上一份报告：`Netr/analysis/amd_svm_clock_watchdog_1dmp_2026-07-22.md`
- 精确逆向补丁：`Netr/analysis/amd_svm_cet_rollback_2026-07-22.patch`

修复后源码哈希：

- `AsmSvm.asm`：`B17F7D3BE8AB96BAD2D6B2BAA97D509B73149542F299485E8207907C8A0BFA93`
- `HvTypes.h`：`481437BE7902A21C00AF7F128C2262964004B8EA4692D007368EA9B434998B0C`
- `HvVmcb.c`：`4798DC0E1DD622F4A05854DD89CEA3A642C16114B01E0B49CD9582692BE1E498`

## 运行时缺口 / Runtime gap

- Mini dump 不含其他 CPU 的 SVM live state，无法离线证明首次 VMLOAD 后三字段的实机值。
- 最终结论需要 AMD 主机重新加载本次新包验证；本次会话不会自动安装、启动、停止或卸载驱动。
- 若仍在首次加载蓝屏，必须保留新 dump，并优先比较 bugcheck、fault CPU、`CR4/RFLAGS` 与是否仍为同一 SMAP 保护违规；不能把不同故障机械地归为同一问题。
