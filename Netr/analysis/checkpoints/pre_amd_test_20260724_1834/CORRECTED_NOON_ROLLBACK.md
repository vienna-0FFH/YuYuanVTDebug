# 已作废：2026-07-24 午间状态纠正记录

> 此记录把用户要求误解为“恢复到 7 月 24 日午间状态”，不是最终回退目标。
> 当前权威状态见同目录 `TRUE_PRE_AMD_ROLLBACK.md`；不得再按本文恢复或交付。

## 纠正结论

- 原回退边界 `2026-07-22 20:12:26 +08:00` 选错，不能代表用户已验证正常的 AMD 修改前功能状态。
- 正确锚点是 `test-package/GuardMeta-VtDebug-p11448-1784864624942.log`，其时间为 `2026-07-24 11:43:51 +08:00`。
- “设备未就绪”出现在错误边界构建上，不可作为午间状态的行为结论。

## 当前源码边界

- `rollback_applypatches` 涉及的文件中，除 `HvHook.c` 外的 17 个文件已恢复为 `current_source_before_rollback.zip` 中保存的内容；`poller.rs` 也与该归档一致。
- `HvHook.c` 保持午间实现，并与 `reconstructed_pre_amd/Netr/HvHook.c` 一致，未带回午后的 AMD ABI/分支修改。
- 所有比较均忽略仅由 `apply_patch` 引起的 CRLF/LF 差异；内容校验结果为 `NOON_SOURCE_BOUNDARY_SEMANTIC=PASS`。
- 回退前完整源码归档仍为 `current_source_before_rollback.zip`，SHA-256 为 `B8C5E485B7D9C3E34E30F15CAA0176751BE8CDCF1509A18ECF4392DEA30B2F81`。

## 构建与交付校验

- 已执行 `build_test.bat Release`，驱动、DebuggerBridge、注入器、Rust GUI、符号、证书和清单均已刷新到 `Netr/test-package`。
- `SHA256SUMS.txt` 的 14 个受管产物逐项复算通过。
- `GuardMetaCore.sys` 源/包 SHA-256 均为 `D8354572868D5734FCB060E3FA5C79E2D0DEC69027B26920D80D12386AD2F214`。
- `GuardMetaCore.pdb` 源/包 SHA-256 均为 `4D8AFDC15EDA251E16536FC57EB3353D925E8F5ACB4B44ED71517FDF19DE22DF`。
- 驱动 Authenticode 状态为 `Valid`，证书指纹为 `82FAA0D1CA193262D6EADF824DFE7C6DD2F5ACC4`。
- 构建保留 25 个既有 Rust 未使用/可见性警告和 1 个 Vite 动静态导入警告；无驱动编译、链接、签名或打包错误。
- 未安装、未启动、未加载驱动；当前只完成源码恢复、构建和静态交付校验，运行时仍需在目标机验证。

## 后续约束

- 不得再以 `2026-07-22 20:12:26 +08:00` 作为这次功能测试的恢复点。
- 如需返回午后 AMD 修改状态，使用 `current_source_before_rollback.zip`，不要从构建目录或测试包反推源码。
