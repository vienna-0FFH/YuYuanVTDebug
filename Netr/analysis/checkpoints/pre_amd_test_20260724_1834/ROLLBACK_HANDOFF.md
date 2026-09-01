# 已被新审计取代：AMD 前测试回退检查点

> 本文保留第一次回退过程供审计，其中构建哈希已经过期。
> 当前权威边界、全树校验和交付哈希见 `TRUE_PRE_AMD_ROLLBACK.md`。

## 目的

- 将主线源码临时回退到 AMD 源码修改开始前，用于验证 Intel/内置调试器合成 MTF 的既有行为。
- 不安装、不加载驱动。
- 本次只回退会话中成功落地的源码补丁，不修改只读备份树和 Unreal 参考树。

## 时间边界

- 回退边界：2026-07-22 20:12:26 +08:00。
- 该时刻的第一笔 AMD 补丁尝试失败，第一笔成功 AMD 源码补丁发生于 2026-07-22 20:13:55 +08:00。
- 会话来源：`C:\Users\VIENNA\.codex\sessions\2026\07\18\rollout-2026-07-18T17-31-55-019f7491-6ccf-75e0-90cd-0b8f81c2c231.jsonl`。

## 当前态恢复点

- 精确源码归档：`current_source_before_rollback.zip`
- SHA-256：`B8C5E485B7D9C3E34E30F15CAA0176751BE8CDCF1509A18ECF4392DEA30B2F81`
- 归档大小：137397476 字节，共 6318 项。
- 语义恢复补丁：`restore_current_after_pre_amd_test.patch`
- 补丁 SHA-256：`C3A45AA08F76B63C769F22FE0A5DCE8563893A3EEBE6B26D01DED02FAF18B83F`
- ZIP 是返回当前源码状态的字节级权威；补丁受本机 Git 自动换行转换影响，仅作为便捷语义恢复手段。

## 重建结果

- 临时树：`reconstructed_pre_amd\Netr`
- 18 个文件存在真实内容回退，清单见 `semantic_rollback_files.txt`。
- `poller.rs` 在会话中经历“添加文件日志后又删除”，最终净内容变化为零，不应写回主线；临时树仅有重建脚本造成的换行差异。
- 临时树与当前树的其他源码文件无内容差异；当前树额外存在未纳入源码归档的 `vite-dev.log`。
- 各阶段逆放报告为同目录下的 `*.json` 文件。

## 歧义审计

- 从当前态归档逐文件独立逆放后，只发现 `HvCore.c`、`HvHook.c`、`HvVmExit.c` 三处多重上下文匹配。
- `HvCore.c` 的两行卸载状态清理最初被重建脚本误插到 `HvPrintDebugStats`；现已移回 `HvUnloadIpiCallback`。第一次完整构建准确暴露了该问题。
- `HvHook.c` 的两个候选是 Intel/AMD 分离包装中的相同返回序列，选中的 AMD 包装位置正确。
- `HvVmExit.c` 的多重候选只是无内容变化的 `default:` 定位 hunk，不影响最终源码。
- 独立审计资料位于 `ambiguity_audit`，修正后 18 个主线文件均与目标树内容一致。

## 构建与交付校验

- `build_test.bat Release DriverOnly`：通过，驱动已测试签名并刷新 DriverOnly 包。
- `build_test.bat Release`：通过，驱动、DebuggerBridge、注入器、Rust GUI、符号、证书和清单已刷新。
- 最终测试包：`Netr\test-package`，14 个受管制品。
- `GuardMetaCore.sys` SHA-256：`5540FFCDED95EDD75089EE25D4857FDE2C7E5C6BBF374FF945CE80F4C2A0A701`。
- `GuardMetaCore.pdb` SHA-256：`9865AC3036387D7CD99BF11ADDE0CD92CEB3EB4A82A7CE88D6D2EF779550BDCC`。
- `SHA256SUMS.txt` SHA-256：`CC599B7544E5D509B300C8C9E5ED160483873D537039CF0F34BC5AA9D4D02551`，14 项逐项复算通过。
- 13 个可对应构建产物均通过源产物/测试包 SHA-256 一致性检查。
- 驱动签名有效，证书指纹：`AD39C1B28DF46266E5E74CF60A46A8BEA97BB5F0`。
- 构建保留既有 Rust 未使用项警告和 Vite 动静态导入警告；无 C/C++、链接、签名或打包错误。
- 未安装、未启动、未加载驱动。

## 恢复原则

- 如需结束测试并返回当前版本，优先从 `current_source_before_rollback.zip` 恢复源码，再执行完整构建。
- 不从 `test-package`、`x64` 或 Rust `target` 目录反推源码。
- 回退版本完整构建会刷新 `test-package`；运行日志和转储不是源码恢复点。
- `UNMANAGED_ARTIFACTS.txt` 中的旧日志和转储未被视为本次构建输出。
