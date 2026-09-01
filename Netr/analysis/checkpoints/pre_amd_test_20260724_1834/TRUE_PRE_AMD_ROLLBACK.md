# AMD 修改前完整回退报告

## 结论

- 当前 `Netr` 产品源码已经完整恢复到第一笔成功 AMD 源码修改之前，不是 7 月 24 日午间混合状态。
- AMD 功能询问发生于 `2026-07-22 19:14:33 +08:00`；期间只做审计和构建，第一笔成功源码修改发生于 `2026-07-22 20:13:57 +08:00`。
- 回退边界采用该成功补丁调用前的 `2026-07-22 20:13:55 +08:00` 状态。
- `2026-07-22 20:12:26 +08:00` 的大型补丁验证失败，没有 `patch_apply_end` 成功事件，也没有部分文件落盘。

## 重建依据

- 会话：`C:/Users/VIENNA/.codex/sessions/2026/07/18/rollout-2026-07-18T17-31-55-019f7491-6ccf-75e0-90cd-0b8f81c2c231.jsonl`。
- 基准归档：`current_source_before_rollback.zip`，SHA-256 为 `B8C5E485B7D9C3E34E30F15CAA0176751BE8CDCF1509A18ECF4392DEA30B2F81`。
- 从归档反向重放边界后的全部成功 `patch_apply_end`：58 个补丁事件、89 次产品文件更新、19 个涉及文件。
- 非 `apply_patch` 写入审计未发现通过 `git apply`、复制、重命名或脚本直接修改产品源码的遗漏。
- 精确重放使用补丁事件中的实际 unified diff、实际行号和逐行 CRLF/LF；89 次更新全部按预期位置匹配，0 次搜索迁移、0 次模糊匹配。

## 现场哈希交叉验证

会话在第一笔成功 AMD 补丁前现场记录了三个源文件哈希。字节级重建逐项精确命中：

- `AsmSvm.asm`：`B8177816B46F4134709B1BDA39BAE9914C012B2508672AAA6694A25F3FC0B056`。
- `HvTypes.h`：`6B56738B55788DA23FB75626945FDD594C7002624D910385089C6027D781224F`。
- `HvVmcb.c`：`E5B81C0D429B80F48FA5A1E6B2C59176F1038CB1E819DBC667B0EF72F9E8A557`。

## 主线一致性

- 从错误的午间混合状态向真实前置状态同步了 17 个文件。
- `HvHook.c` 当时已经处于前置状态，无需再次修改。
- `poller.rs` 在 AMD 阶段先增加文件诊断、后删除，最终净内容变化为零。
- 排除构建目录、测试包、分析资料和 `*.tsbuildinfo` 生成物后，当前主线与字节级前置重建树均为 5892 个文件。
- 两棵树无内容差异、无缺失、无额外文件；确定性规范化树 SHA-256 均为 `44DB959049B44CAEF842A0385541411F9337C067D7118E99B5B6191CFA96FAB0`。

## 构建与测试包

- `build_test.bat Release DriverOnly`：通过，驱动 C/ASM、链接、签名均为 0 错误。
- `build_test.bat Release`：通过，驱动、DebuggerBridge、注入器、Rust GUI、符号、证书和清单均已刷新。
- `SHA256SUMS.txt` 的 14 个受管产物全部存在并逐项复算通过。
- `GuardMetaCore.sys` 源/包 SHA-256：`4BF30287041EDBC8D7C605DAF7F34C9110F71827DBC35F2D5DA90CD6AEC9B6F4`。
- `GuardMetaCore.pdb` 源/包 SHA-256：`9521FDB62859CB6D1F7E683E36344DF0A2B07D6EFC161C1D9EAC94A1E80DBDB7`。
- `SHA256SUMS.txt` SHA-256：`FB61D5245DA8DF2D036B6D999744B9D332EE96D8F599A80F9BD12D5FC37332AD`。
- 驱动 Authenticode 状态为 `Valid`，证书指纹为 `82FAA0D1CA193262D6EADF824DFE7C6DD2F5ACC4`。

## 已知边界

- 此回退有意移除边界之后的全部 AMD 修复，包括 VMCB/汇编布局修复、AMD 初始化诊断、SVM TF/中断事务和 AMD 窗口枚举 ABI 分支。
- 构建保留 25 个既有 Rust 未使用/可见性警告和 1 个 Vite 动静态导入警告；无驱动编译、链接、签名或打包错误。
- `UNMANAGED_ARTIFACTS.txt` 中的旧日志和转储不是本次构建产物。
- 本轮未执行任何驱动安装、启动或加载命令；只完成源码恢复、静态审计、构建和交付校验，运行时结果仍需目标机验证。

## 返回 AMD 修改态

- 如需恢复本次回退前的 AMD 修改状态，使用同目录 `current_source_before_rollback.zip`。
- 不得从 `test-package`、`x64`、Rust `target` 或旧构建日志反推源码。
