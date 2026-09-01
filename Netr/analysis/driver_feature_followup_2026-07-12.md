# 驱动功能恢复跟进交班（2026-07-12）

## 当前阶段 / Current phase

- 本轮以 `driver_feature_handoff_2026-07-12.md` 的第一阻断项“私有 SWBP 生命周期与 root 安全”为主线。
- 对照范围为当前 `Netr`、`YuYuanVTDebug_备份\Netr`，并只读参考 `E:\project_learning\UnrealVTDbgBAK` 的 EPT watch/MTF 与 Dbgk 事件模型。
- private entry/page rundown、MTF 发布顺序、ring 背压和 host-write shadow 刷新已静态收口；终审仍确认 GPA 重映射覆盖与被动 rebind 发布窗口，因此第一阻断项只能标记为“部分完成”。
- 已完成完整 Release 构建、测试签名、Bridge/GUI 构建和严格测试包收集；未加载驱动、未做真机运行测试。
- `GuardMetaCore.sys` 已通过测试签名与包内哈希一致性验证；签名仅表示交付链完成，不代表下述静态阻断已达到上机稳定标准。

## 已验证事实 / Verified facts

### 备份与参考结论

- 备份 SWBP 仍是“R3 写入真实 `0xCC`、driver 登记 owner”的旧事件链；ring 满时丢最老事件，不能作为恢复基线。
- 备份 `HV_ENABLE_PEB_CLOAK=0` 时 `HvPebCloakSetupVcpu` 直接返回，`EptPebSpoof` 不建立，vwatch/private SWBP 实际没有可用 overlay EPT。
- Unreal 参考项目可复用的行为语义是：data/execute 分离、原指令先放行、MTF 后恢复 trap/注异常、写后复制原页并重布同页全部 `0xCC`。
- Unreal 参考项目不能照搬其并发模型：它先 arm MTF 后发布 raw page pointer，deactivate 可立即回收 page，没有 rundown/grace period，也没有 private-event 背压。

### 本轮落地

- `HvPebCloakSetupVcpu` 不再受 PEB 功能开关控制；PEB cloak 仍关闭，但通用 overlay EPT 始终为 vwatch/private SWBP 建立。
- overlay target 使用有界 seqlock 快照和 generation 复核；不稳定分类临时使用主 EPT 且不缓存，避免 root 无限自旋和旧结果覆盖 invalidate。
- `MOV CR3` 写入后立即按规范化新 CR3 重选 EPTP，不再等下一次 VM-exit。
- private SWBP entry/page 增加 root rundown；remove、target/debugger exit 和复用前关闭新引用并等待完整 grace period。
- private MTF 按 `Pending*`/reason 全部写完、barrier、最后发布 `Active=1`；完成时先恢复映射、释放引用，最后清 `Active`。
- private ring 事件不可被普通 overflow 淘汰；入队失败时走原页 MTF step-over 并安全 rearm，不遗留 `HitPending`。
- shadow 使用双缓冲；guest write 后重读原页并重布同页断点。`Driver.c` 的四类 IOCTL 写成功后会调用 `HvVwatchRefreshPrivateSwBpRange`，GPA 改变时恢复旧 slot、等待 root grace、检查冲突并绑定新 GPA；其他 host-write 路径、同 GPA 并发刷新和被动 rebind 发布窗口仍列为阻断项。
- 内核和 Bridge 均拒绝真实 `0xCC` 与 `CD 03` 两字节 INT3 混用。
- Bridge 在暂停线程前预留 pending；失败时撤销并 ack。解绑、退出和 continue 统一使用 `target -> private` 锁序，清理 pending/SWBP/target 状态。
- unload 顺序调整为 `HvHookCleanup -> HvVwatchShutdown -> HvPebCloakShutdown -> HvDbgCleanup -> HvPhysAccessCleanup -> HvVtRootCleanupAll -> HvCleanup`。
- 长期构建流程已固化：完整构建与 `DriverOnly` 都自动测试签名并刷新 `Netr\test-package`；完整构建只在最后执行一次 Full profile 严格收集。

## 关键证据 / Key evidence

| ID | 证据 | 位置 | 结论 | 置信度 |
| --- | --- | --- | --- | --- |
| E1 | private rundown 与 root acquire/revalidate | `Netr\HvVwatch.c:46` | fixed-size entry/page 不再被 root raw pointer 无保护复用 | 高 |
| E2 | PASSIVE GPA 重绑定 | `Netr\HvVwatch.c:724` | driver/Bridge 控制面写入后不直接复用旧 GPA | 高 |
| E3 | Driver IOCTL 写路径刷新 shadow | `Netr\Driver.c:506`、`:1102`、`:1536`、`:1641`、`:1821` | COW、普通、变长、批量四类 IOCTL 已接入 | 高 |
| E4 | private ring preserve/flush | `Netr\HvDebugger.c:678`、`:685` | pending private event 不再被普通 overflow 覆盖，显式 discard 会重置队列 | 高 |
| E5 | overlay 分配与分类 | `Netr\HvPebCloak.c:504`、`:764` | PEB 关闭不再关闭 vwatch overlay | 高 |
| E6 | CR3 写后重分类 | `Netr\HvVmExit.c:914`、`:921` | 避免新地址空间使用旧 EPTP | 高 |
| E7 | Bridge 生命周期 | `Netr\DebuggerBridge\Bridge.cpp:914`、`:996`、`:1850` | pending reservation、解绑和 continue 锁序已收口 | 高 |
| E8 | Unreal 写后重布参考 | `E:\project_learning\UnrealVTDbgBAK\VT_Driver\vmexit_handler.cpp:379` | 仅复用行为语义，不复用 raw-pointer 同步 | 高 |
| E9 | rebind 两态发布窗口 | `Netr\HvVwatch.c:730`、`:833`、`:835`、`:2131` | 新 X-only PTE 激活后才清 `Invalidated`，窗口内 root 查找会跳过该页 | 高 |
| E10 | 同 GPA 刷新未 quiesce root/MTF | `Netr\HvVwatch.c:937`、`:954`、`:965`、`:982` | 持一个 page ref 即直接交换双缓冲并改全核 PTE | 高 |
| E11 | 未接入 refresh 的 host-write | `Netr\HvHook.c:4665`、`Netr\HvDebugger.c:1225`、`Netr\HvInjection.c:457` | hook、PEB scrub、injection 等写入可留下 stale shadow/GPA | 高 |
| E12 | debugger 清理先 flush 后停 producer | `Netr\HvDebugger.c:1337`、`:1363`、`Netr\HvHook.c:3227`、`:3230` | flush 后 root 仍可再次投递 stale private event | 高 |

## 构建验证 / Build verification

- `Netr\build_test.bat Release`：退出码 `0`；driver、Bridge/injector x64+x86、Rust/Tauri GUI、签名和 Full profile 收集全部成功。
- driver 的 `signtool sign` 与 `signtool verify /pa` 均成功；证书 SHA-1 为 `82FAA0D1CA193262D6EADF824DFE7C6DD2F5ACC4`。
- `CollectTestPackage.ps1 -Profile Full -RequireAll -RequireSignedDriver` 收集 13 个受管产物；独立复核确认源路径与包内 SHA-256 全部一致，`SHA256SUMS.txt` 13 项全部通过。
- `git diff --check`：退出码 `0`；只有工作树 LF/CRLF 提示，无 whitespace error。
- 构建仍报告既有告警：driver 的 `HvRegistryHook.c:413` 弃用告警 1 项、Rust 25 项和 Vite 动静态重复导入提示 1 项；本轮未把这些非阻断告警混入交付脚本修改。

| 产物 | 大小 | SHA-256 | 签名 |
| --- | ---: | --- | --- |
| `Netr\test-package\GuardMetaCore.sys` | 346400 | `B3C78731D5E172FBE510436677B329455A9A23AE071D3DC4CEFA91D10C1699DA` | Valid |
| `Netr\test-package\guardmeta-vsp.exe` | 22433792 | `F67DB8D5D1B23113BD5ED415F8C36B02275A2C173844C4B7BEADFEB5B8EB367C` | 非 driver，不要求签名 |
| `Netr\test-package\NetrDebuggerBridge64.dll` | 220672 | `8003C40DF9B0D048F85E277485607704B3773E2262237C8B4E45FE8EC87C4292` | 非 driver，不要求签名 |
| `Netr\test-package\NetrDebuggerBridge32.dll` | 176640 | `A3AC297390AD9E3DB37A1B99A36D5FEB368BC995CFF355D123E594257F8CEF86` | 非 driver，不要求签名 |

- Bridge/Injector 的四份 PDB 已加入测试包；`.obj/.lib/.exp` 明确保留为中间产物。`GuardMetaCore1.sys` 与 `GuardMetaCoreLegacy.sys` 仍是未受当前流程管理的遗留文件，不再写入新 `SHA256SUMS.txt`，并由 `UNMANAGED_ARTIFACTS.txt` 显式列出。

## 推断与置信度 / Inference and confidence

- private entry/page UAF、MTF publish 顺序、ring overflow 丢 private event、overlay 不存在，以及四类 Driver IOCTL 的串行 refresh 等子问题已静态收口并通过编译链接；但 root 并发 refresh、其他 host-write 和 GPA 重映射仍未闭环，第一阻断项尚未整体关闭：高置信度。
- 这些结论尚无真机并发 trace、Driver Verifier 或重复 attach/detach 证据，不能等价为运行稳定：高置信度。
- 当前 `test-package` 的 13 个受管产物已与最新构建源一致并刷新 manifest；其中未受管的两个历史 driver 不作为本轮可追溯产物。

## 风险与剩余阻断 / Remaining blockers

1. 普通（非 private）vwatch 的 `HV_VWATCH_PAGE/ENTRY` 仍由 MTF 持有裸指针，没有与 private 同等级的 rundown/generation；并发 clear/reuse 仍可能逻辑 UAF。
2. target 自身触发的 COW、MapView 或 PTE 重映射可能先落到新 GPA，从而绕过旧 GPA EPT trap；当前 GPA 重绑定覆盖 driver/Bridge host-write 路径，尚未监控任意 guest PTE 变化。
3. `HvVwatchpRebindSwBpPagePassive` 先保持 `Invalidated=1` 激活新 GPA 的 X-only PTE，随后才清失效标志；窗口内 root 查找会跳过该页。data access 可能反复退出并最终注入 `#UD`，取指也可能形成重复 private `#BP`。需要 `ACTIVE/QUIESCING/REBINDING` 或等价的跨核 quiesce，不能把它视为已安全原子切换。
4. 同 GPA 的 PASSIVE refresh 在未等待其他 page/entry root 与 MTF 引用退出时直接交换双缓冲并改全核 EPT PTE，可与 step-over/data MTF 竞态；它必须纳入与 rebind 相同的 page 状态机。
5. refresh 目前只覆盖 `Driver.c` 四类 IOCTL。`HvHook.c` 的 debugger `NtWriteVirtualMemory` 物理直写、`HvDebugger.c` 的 PEB scrub、`HvInjection.c` 等其他 host-write 路径仍可令 shadow/GPA stale；在统一刷新协议完成前不宜简单散落补调用。
6. root 连续 guest write 只允许一次无跨核等待的双缓冲换页；再次写会 fail-closed 禁用该 SWBP page，直到 PASSIVE refresh。该策略保证不执行 stale shadow，但不是完整功能闭环。
7. debugger cleanup 当前先 discard ring，随后才 quiesce vwatch/private producer；窗口内 root 可重新投递 stale event。ring owner 槽本身也只 flush、不回收，第 9 个不同 debugger PID 会耗尽固定 8 槽。安全回收需要 `closing + generation + rundown/ref`，并改为先停 producer、最后 flush/reclaim。
8. Bridge 的 `DLL_PROCESS_DETACH` 仍在 loader-lock 场景执行同步清理，且目标线程依赖 `SuspendThread/ResumeThread`；debugger 被强杀时只能 best-effort 恢复。需要 loader-lock 外显式 shutdown/join，以及能覆盖进程异常退出的 driver/file-session 或 watchdog 恢复路径。
9. PEB cloak 继续保持关闭；启用后其 MTF 仍持有裸 `PendingPage`，register/unregister 未统一进入 overlay mutation 锁，卸载恢复 PTE 后也缺少释放 patch page 前的明确 INVEPT/rundown。worker 与 qualification 同样尚未闭环。
10. 交班中的继承阻断未在本轮处理：`HV_HOST_PT_PML4_SLOT=255` 与 `0xFFFFFF8000000000`（实际 slot 511）不匹配，HOST_CR3 仍未接 VMCS；driver hide/registry hide 仍由 `Driver.c` 的 `#if 0` 关闭，不能启用。
11. 当前已有完整构建、签名和包一致性证据，但仍没有加载、Driver Verifier、真机并发 trace 或重复 attach/detach/unload 循环证据；不能用签名成功替代运行时安全验证。

## 建议下一步 / Suggested next steps

1. 先把 private rebind、同 GPA refresh、guest write 统一到显式 page 状态/跨核 quiesce，再给普通 vwatch page/entry 增加同等级 rundown 与 MTF generation。
2. 建立统一 host-write 通知入口，并为 private SWBP 增加 target PTE/GPA 变化检测；不能只覆盖 `Driver.c` IOCTL，也不能只按 VA 缓存旧 GPA。
3. 为 debugger ring 增加 closing/generation/rundown，调整为先停 private producer、最后 flush/reclaim；随后再处理 Bridge 显式 shutdown、worker join 与异常退出恢复。
4. PEB cloak 单独完成 page/target/worker rundown、overlay mutation 锁序和 restore → INVEPT → free 顺序后，再评估启用；HOST_CR3 与两类 hide 继续独立修复、独立验收。
5. 测试证书、自动签名和一致的 `test-package` 已就绪；完成静态阻断后，再在隔离环境依次测试 add/hit/continue/remove、ring overflow、同页多断点、写/COW/remap、target/debugger exit、重复 attach/detach 和 unload 循环。
6. 在上述运行时证据齐全前，不启用 PEB cloak、HOST_CR3、driver hide 或 registry hide；不要因为 driver 已签名就跳过剩余准入条件。
