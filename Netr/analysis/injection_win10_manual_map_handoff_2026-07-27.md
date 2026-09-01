# Win10 注入兼容与 manual-map 生命周期交班（2026-07-27）

> 依赖加载语义已由 `manual_map_dependency_loader_handoff_2026-07-28.md` 接续；下文关于“依赖必须已加载”的限制不再代表当前实现。

## 目标

1. 移除 `GuardMetaCore.sys` 对 `KeRemoveQueueApc` 的静态导入，使不导出该例程的 Windows 10 19045 内核仍可装载驱动。
2. 修复 GUI 传入 DOS/UNC 路径后 `ZwCreateFile` 返回路径无效的问题。
3. 关闭原 manual-map 在 TLS、DllMain、导入失败、unwind、卸载和并发回滚上的生命周期缺口。

## 参考结论

- 备份 `YuYuanVTDebug_备份\Netr\HvInjection.c` 的 TLS 函数只枚举并打印 callback，实际调用被注释；mapper 忽略 import 失败，也没有调用已声明的 `InjectionCallEntryPoint`，因此不能直接恢复为可用语义。
- Unreal 的 `Common\Ring0\Inject\ApcInject\ApcInject.cpp` 提供了真实用户 APC + 强制 alert 内核 APC、终止线程抑制和 WOW64 包装语义，但它是异步 fire-and-forget，没有 manual-map 初始化完成栅栏、驱动卸载 rundown 或失败回滚。
- 当前实现只复用其可靠的投递意图，并增加可取消 APC 跟踪、rundown、同线程完成栅栏和 fail-closed 回收规则；没有照搬其卸载不闭合部分。

## 当前实现

- 后续运行反馈确认旧 ABI 中 `UseManualMap=false` 一直被驱动忽略，普通 DLL 注入仍被强制送入“依赖必须已加载”的 manual-map；其 `STATUS_DLL_NOT_FOUND` 又被 `DeviceIoControl` 映射成 Win32 错误 126，前端因而只显示“找不到指定的模块”。
- 当前已恢复两条独立语义：`UseManualMap=0` 调用目标 `ntdll!LdrLoadDll`，`UseManualMap=1` 才调用现有 manual-map；Rust 前端默认关闭手动映射并重新提供显式开关。
- `IOCTL_HV_INJECT_DLL` 对格式正确的请求以传输成功返回，并在结果的 `Status` 字段保留原始 NTSTATUS；前端显示十六进制状态和阶段说明，不再丢失根因。
- Windows loader 模式记录 `LdrUnloadDll` 并按 loader 引用计数卸载，不会直接释放 loader 管理的模块地址；进程退出仍清理 driver 侧记录。
- `KeRemoveQueueApc`、`KeTestAlertThread`、`PsWrapApcWow64Thread`、`PsGetThreadProcess` 全部经 `MmGetSystemRoutineAddress` 动态解析。
- 缺少 `KeRemoveQueueApc` 等安全必需能力时不排入新的 driver-owned APC；driver 其余部分可加载，但 Windows loader 注入、manual-map 和 Shellcode 执行均返回 `STATUS_NOT_SUPPORTED`。
- 文件路径支持 DOS、UNC、Win32 extended path 和原生 NT path；固定 ABI 路径和文件完整读取均有有界检查。
- mapper 对 PE、节区、目录、重定位、import、转发导出和 API Set 做边界校验；import 失败不再继续写空 IAT。
- 仅支持原生 x64 和 callback-only TLS；WOW64、delay import、CLR 与静态 TLS 模板明确拒绝。直接/传递依赖现由目标 loader 自动解析并持有。
- 初始化顺序为：映射 → 重定位 → 依赖 `LdrLoadDll` → import → TLS 元数据 → 最终节权限 → 指令缓存刷新 → `RtlAddFunctionTable` → TLS attach → DllMain attach。
- 卸载/失败回滚顺序为：DllMain detach → TLS detach → `RtlDeleteFunctionTable` → 依赖 `LdrUnloadDll` 逆序释放 → 释放映像。每个阶段单独记录，重试不会重复已经完成的阶段。
- 用户调用通过“调用 APC + 同线程 fence APC + force-delivery APC”同步；进程创建时间和线程所属进程对象均校验。
- `KeRemoveQueueApc(FALSE)` 不再被解释为“可以释放”：代码会等待该 APC 自身的完成事件，再根据 user routine 是否已投递决定回收或保留调用桩，关闭 dequeue/kernel-routine 之间的竞态。
- 若 fence 未到达或返回值无法可靠读取，状态标记为 `UnsafeToUnload`，保留目标映像和调用桩直到进程退出，不猜测释放。
- 立即执行的 Shellcode 在写入后降为 RX；APC 排队失败时回收目标分配，不再返回带残留页的失败结果。

## 编译隔离回退点

- `HvInjection.c` 中旧 mapper 和旧直接释放卸载器保留为 `InjectionInjectDllCoreLegacy` / `InjectionUnloadInjectedDllCoreLegacy`，位于 `#if 0` 块内，不参与构建。
- 若新同步执行模型经真机证明不可成立，可在保留动态导入和路径修复的前提下回到“明确禁用 DLL manual-map”状态；不要重新启用旧函数并把映射成功误报为模块初始化成功。

## 已验证

- `build_test.bat Release DriverOnly`：通过，0 warning / 0 error，驱动已测试签名并刷新到 `test-package`。
- 恢复 Windows loader/手动映射双路径后再次执行 `build_test.bat Release DriverOnly`：通过，0 warning / 0 error。
- 恢复 Windows loader/手动映射双路径后的最终 `build_test.bat Release`：通过；驱动、DebuggerBridge、x64/x86 injector、Rust GUI、PDB、测试证书和清单均已刷新到 `test-package`。
- 驱动编译和签名阶段为 0 warning / 0 error；GUI 的 Rust 编译保留 25 个既有 unused/private-interface/dead-code warning，Vite 保留 1 个动态/静态混合导入 warning，均未阻断构建。
- `test-package\SHA256SUMS.txt` 于 `2026-07-27 20:57:18 +08:00` 按 Full/Release profile 生成，14 个受管产物逐项重新计算 SHA-256 均匹配。
- 源输出和交付包中的 `GuardMetaCore.sys` SHA-256 均为 `25B4B863FBDF616ECFBD2C100B74ACD2638362A6E539DE51CA3E16A6BE6405D2`。
- `test-package\GuardMetaCore.sys` Authenticode 状态为 `Valid`，测试证书指纹为 `82FAA0D1CA193262D6EADF824DFE7C6DD2F5ACC4`。
- `dumpbin /imports GuardMetaCore.sys`：存在 `MmGetSystemRoutineAddress`，不存在 `KeRemoveQueueApc`、`KeTestAlertThread`、`PsWrapApcWow64Thread` 或 `PsGetThreadProcess` 静态导入。
- `test-package\UNMANAGED_ARTIFACTS.txt` 仅列出 8 份历史调试日志；这些日志未由本次构建刷新，也不属于本次可追溯交付产物。

## 未验证与测试门槛

- 本轮未加载驱动，也未在 Win10/Win11 目标进程执行 DLL/Shellcode 注入。
- 首轮运行测试应使用无静态 TLS、无 delay import、带同目录未预加载依赖的最小 x64 DLL，并分别验证成功注入、缺失传递依赖、DllMain 返回 FALSE、目标中途退出和卸载重试。
- 在上述矩阵完成前，前端不得把 manual-map 标记为 production-ready。

## 远程 Win10 反馈后的追加修复

- 远程 Win10 日志尚未复制到本机；本机 `C:\HvUnloadTrace.log` 不能作为远程卸载卡死的阶段证据。
- 普通 loader 模式若因内核缺少安全 APC 取消能力返回 `STATUS_NOT_SUPPORTED`，Rust 后端现在按目标位数选择 `NetrBridgeInjector32/64.exe --load`，通过 Windows `LoadLibraryW` 做 R3 回退；manual-map 与 shellcode 不回退。
- helper 通过目标模块枚举确认加载结果，不依赖 x64 远程线程退出码被截断后的低 32 位；超时后不释放仍可能被远程线程读取的路径缓冲区。
- Intel 正常 VMXOFF 路径现在恢复 MXCSR/XMM0-15、当前 RFLAGS、FS/GS base，并按 `(GUEST_CR & ~MASK) | (READ_SHADOW & MASK)` 恢复有效 CR0/CR4，而不是把可能过期的 read-shadow 当成完整寄存器。
- 每 CPU 卸载上下文在 VMCALL 前保存 Windows GDTR/IDTR/TR/LDTR、DS/ES/FS/GS、FS/GS base、DR7、SYSENTER、PAT、EFER 与 DEBUGCTL，VMXOFF 返回后在释放任何 host/VCPU 资源前恢复。
- 这修复了一个确定的 Intel 状态污染：VMCS `HOST_FS_BASE` 指向 `VcpuData`，旧终止路径在 VMXOFF 后从未写回 guest FS base；旧路径也直接跳过终止分支的 XMM/MXCSR 恢复。
- `HvInjectionBeginShutdown` 仍包含安全所需的 rundown 等待，hook/nested 清理也有无界等待；没有远程阶段日志时不能确定卡死是否发生在这些阶段还是 `S15.5` 的 `KeIpiGenericCall`。
- 内置调试器关闭“VT 自建 DebugObject”后不需要内核私有符号：Rust 仅在驱动授予 `BRIDGE_CAP_PRIVATE_DEBUG_OBJECT` 时调用 `configure_private_dbgk_symbols()`，外部 Bridge 也仅在 `g_private_dbgk_mode` 为真时调用 `ConfigurePrivateDbgkSymbols()`。

## 追加验证

- `build_test.bat Release DriverOnly`：通过，驱动/MASM 0 warning、0 error，已测试签名并刷新 Driver profile 测试包。
- `DebuggerBridge\build.bat NoCollect`：x64/x86 Bridge 与 injector 均通过。
- `cargo check --release`：通过；仅保留 25 个既有 warning。
- `NetrBridgeInjector64.exe --load 4294967294 C:\Windows\System32\version.dll`：按设计在无效 PID 的 `OpenProcess` 阶段返回 helper exit 11，确认 `--load` 分支生效且未接触有效目标进程。
- `build_test.bat Release`：通过；驱动、双架构 Bridge/injector、Rust GUI、PDB、证书和 Full profile 清单均刷新到 `test-package`。驱动编译为 0 warning/0 error；GUI 保留 25 个既有 Rust warning 与 1 个既有 Vite 提示。
- Full profile 的 14 个受管产物逐项重算 SHA-256 均匹配；源输出与测试包驱动 SHA-256 均为 `8B80E5503222E7EDAF9A728F84E36591B0C048A98392CF4EC3A32A0A60EDC9C2`，Authenticode 状态为 `Valid`。
- `dumpbin /imports` 确认四个可选 APC 例程没有静态导入，`MmGetSystemRoutineAddress` 存在；测试包内 `--load` helper 的无效 PID 失败路径同样返回 exit 11。
- 本机 stable Rust toolchain 未安装 `rustfmt` 组件，因此 `cargo fmt -- --check` 无法执行；`cargo check --release`、Tauri 的 TypeScript/Vite build 和 Release 编译均已通过。
