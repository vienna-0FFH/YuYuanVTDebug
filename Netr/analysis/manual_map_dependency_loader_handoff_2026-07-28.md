# Manual-map 依赖 loader 生命周期交班（2026-07-28）

## 目标

- 移除“manual-map 依赖必须预先加载”的错误前提。
- 让父映像仍保持手动映射，同时由目标 Windows loader 负责真实依赖解析、API Set/SxS、传递依赖和引用计数。
- 在注入失败、显式卸载、目标退出和不确定 APC 完成状态下闭合依赖引用生命周期。

## 根因链

1. 潜在缺陷：`InjectionResolveImports` 只查询目标 PEB 中已经存在的模块，不会获取 loader 引用。
2. 首个错误设计：把缺失依赖降格为调用方预加载条件；备份实现甚至在缺模块后继续，可能留下无效 IAT。
3. 运行触发：手动映射的 DLL 导入目标尚未加载的模块，例如 `icuio75.dll` 导入 `icuuc75.dll` 和 `icuin75.dll`。
4. 放大因素：重试不会改变目标 loader 状态，因此每次都在同一导入描述符返回 `STATUS_DLL_NOT_FOUND`；这不是根因本身。
5. 最终机制：当前 fail-closed 版本在 IAT 解析前返回 `0xC0000135`；旧备份语义则可能让入口点在坏 IAT 上执行。

`0xC0000604` 是另一条独立路径：目标 ACG/动态代码策略拒绝私有可执行映射或调用桩。该状态不能通过伪造成功或跳过保护来修复。

## 当前实现

- 映射和重定位后先枚举、去重所有直接 import 模块名，最多记录 128 个依赖。
- 对每个直接依赖在目标进程调用真实 `ntdll!LdrLoadDll`：注入 DLL 所在目录优先，未找到时回到目标默认搜索路径。
- 传递依赖、API Set、SxS、依赖 DllMain 和 loader graph 均交给目标 loader；父映像本身仍不加入 PEB loader list。
- 每次成功的 `LdrLoadDll` 都保存返回模块句柄；即使模块原本已加载，也持有本次 manual-map 对应的独立引用。
- 获取全部依赖后重新附加同一进程对象并校验创建时间，随后才解析 IAT、应用最终页权限、注册 unwind、执行 TLS 与父 DllMain。
- 失败回滚和显式卸载顺序为：父 DllMain detach → TLS detach → `RtlDeleteFunctionTable` → 依赖 `LdrUnloadDll` 逆序释放 → 父映像释放。
- 依赖释放按条目推进；部分成功后重试只处理剩余引用，不重复卸载已完成项。
- 若 APC 完成或 loader 返回值无法证明，标记 `UnsafeToUnload` 并保留父映像和记录直到目标退出；不会在依赖状态未知时释放父映像。
- 目标退出回调只释放 driver 记录，不调用已经退出的用户态 loader；进程自身 teardown 负责剩余 loader 引用和地址空间。
- 普通 Windows-loader 模式也把 DLL 所在目录传给 `LdrLoadDll`，修复同目录依赖搜索不一致。

## 保留边界

- manual-map 仍只支持原生 x64。
- delay import、CLR 映像和带静态 TLS 模板的 DLL 仍返回 `STATUS_NOT_SUPPORTED`。
- 父映像不加入 PEB loader list，因此依赖反向按模块名查找父映像、完整 loader 通知和未来线程 TLS attach 不属于当前语义。
- ACG 禁止私有可执行内存时继续返回 `STATUS_DYNAMIC_CODE_BLOCKED`；这不是依赖解析失败。
- 驱动关闭阶段沿用现有策略：不在关闭 admission 后重新进入用户态卸载，只退休记录；显式 `HvUnloadInjectedDll` 才执行完整逆序生命周期。

## 回退原则

- 若真机证明目标 `LdrLoadDll` 依赖阶段不可成立，只回退本报告新增的依赖计划、引用数组和调用接线。
- 不得恢复“缺依赖仍继续写 IAT”或把“依赖必须预加载”重新包装成正确语义。
- 回退后 manual-map 必须明确禁用或对缺依赖 fail-closed，普通 Windows-loader 模式和现有路径修复应保留。

## 验证状态

- 最终 `build_test.bat Release DriverOnly` 通过：driver/MASM 0 warning、0 error，签名验证有效。
- 最终 `build_test.bat Release` 通过：driver、DebuggerBridge、x64/x86 injector、Rust GUI、符号、证书和 Full 清单均刷新到 `test-package`。
- Rust GUI 保留 25 个既有 unused/private-interface/dead-code warning；Vite 保留 1 个既有动态/静态混合导入提示，均与本次注入改动无关且不阻断构建。
- `test-package\SHA256SUMS.txt` 于 `2026-07-28 12:43:46 +08:00` 生成；Full/Release 的 14 个受管产物逐项重算 SHA-256 全部匹配。
- 源输出和测试包 `GuardMetaCore.sys` SHA-256 均为 `B47A75EC06117D3C03E78A82B70E678B299A6906770E42A70412D9436B9C3C60`。
- 测试包驱动 Authenticode 状态为 `Valid`；签名证书指纹为 `AD39C1B28DF46266E5E74CF60A46A8BEA97BB5F0`。
- `UNMANAGED_ARTIFACTS.txt` 仅列出 4 份历史运行日志；这些文件未由构建刷新，也不属于本次受管交付产物。
- 本轮没有安装或加载驱动；尚未执行成功依赖、缺失依赖、失败逆序回滚和显式卸载的真机矩阵。
