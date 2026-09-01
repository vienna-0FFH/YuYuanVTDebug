# VT 硬件断点交班报告

> This handoff is superseded by
> `vwatch_hwbp_virtual_dr6_delivery_2026-07-21.md`. The package hash recorded
> below is the failed physical-DR6 build, not the current test package.

## 当前目标

排查并修复 Windows DebugObject/private Dbgk 与内置/外部调试器四种组合下，
VT 硬件断点命中后无法正确交付、单步异常或被判定为未处理的问题。

## 已确认事实

- 四种组合共用 Intel EPT/MTF vwatch 命中与页面重挂路径；日志出现
  `Vwatch True Hits`、`Injected #DB`，说明 EPT 命中和 MTF 完成并非假命中。
- 失败日志同时出现 `hwbp.single_step.classify ... dr6=0x0 configured=0x1`
  以及外部路径的 `DBG_EXCEPTION_NOT_HANDLED`，故故障集中在 #DB 交付、DR6
  原因位和上下文虚拟化，而不是 EPT 命中本身。
- 当前没有复制四套完整 vwatch；EPT 命中、MTF 放行、页面重挂和生命周期仍共用。
  交付策略仍由现有 Windows DebugObject/private Dbgk/兼容环路径决定。

## 当前工作树中的修复

- `Netr/HvVwatch.c`：MTF 硬断命中后记录槽位原因并显式注入一次 vector 1；移除
  合成 HWBP 对 `GUEST_PENDING_DEBUG_EXCEPTIONS` 的重复写入。
- `Netr/HvVmExit.c`：重放真实 vector 1 时从 VM-exit qualification 提取 B/BD/BS，
  写入当前逻辑 CPU 的 DR6 后再注入一次 #DB。
- `Netr/HvHook.c`：调试器调用方继续虚拟化 Dr0..3/Dr7，保留停止线程的 Dr6；
  目标进程自查询的反调试清零行为保持不变。
- `Netr/HvPrivateDebugObject.c`：private Dbgk 按 DR6 B 位和虚拟槽配置判断归属。
- `Netr/AsmVmx.asm`：保留既有 VMX 退出恢复改动；本次交班不再扩大汇编或
  STI/MOV-SS shadow 范围。

## 构建与回退点

- 已知上一隔离包驱动 SHA-256：
  `692866FC4BA72B8521034E60FA98E97C388FAB24334830936DC4020D6178C878`。
- DR6 交付修复后的上一包驱动 SHA-256：
  `09DC782F81ADF74A2C758E071063EFA27B1BC1BA9B05B208E295196F55CABBDD`。
- 相关文件的精确回退哈希记录在
  `Netr/analysis/vwatch_hwbp_dr6_delivery_repair_2026-07-21.md`；不要对整个
  工作树执行 reset 或从参考项目整体覆盖。
- 本次交班后执行 canonical 命令：`Netr\\build_test.bat Release`，输出只刷新
  `Netr\\test-package`，并重新签名、生成 `SHA256SUMS.txt`。

## 本次交付结果

- `Netr\\build_test.bat Release`：成功；驱动、DebuggerBridge/Injector、Rust GUI
  均完成 Release 构建。
- 当前 `Netr\\test-package\\GuardMetaCore.sys` SHA-256：
  `4C9665461C8B3961689448C5B2FE35F744C4F88838F07359F88AAA1B3823BA6A`。
- 中间输出与测试包驱动哈希一致；`SHA256SUMS.txt` 的 14 个托管条目全部匹配。
- Authenticode 状态为 `Valid`，证书指纹为
  `AD39C1B28DF46266E5E74CF60A46A8BEA97BB5F0`。
- 本次仅刷新测试包；没有执行安装、加载、启动或卸载驱动。

## 尚未宣称的事项

- 当前修复尚未在真实四组合运行时验证；不能把“构建通过”当成“硬断已修复”。
- VMX root 中 DR6 的跨 VM-exit/VM-entry 生命周期仍是后续理论核验点；若继续修改，
  应先证明 guest 可见 DR6 的保存/恢复链，再决定是否引入按线程关联的虚拟 pending 状态。
- 本报告不授权安装、加载、启动或卸载驱动。测试包生成后由人工选择运行矩阵。

## 交接动作

1. 完成本报告后执行完整 `Release` 构建和测试包校验。
2. 仅将校验通过的 `Netr\\test-package` 作为测试交付目录。
3. 运行时若出现蓝屏，优先保留新日志和 dump，不先回退；按本报告中的文件级哈希隔离变化。
