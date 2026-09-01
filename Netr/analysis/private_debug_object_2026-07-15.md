# VT 私有 DebugObject 接入记录（2026-07-15）

## 已完成

- 新增驱动内私有 DebugObject 会话，按 debugger PID、target PID、进程对象与创建时间绑定，具备 `DeletePending`、关闭唤醒、解绑、进程退出与卸载清理。
- 内置调试器和外部 Bridge 统一从 `IOCTL_HV_BRIDGE_BIND_TARGET` 建立会话，不再维护两套开关或目标所有权。
- 调试器保护页新增“VT 自建 DebugObject”总开关；运行中切换会同步当前全部 Bridge 目标，新目标自动继承。
- 开启后，VT 硬断事件强制使用私有事件通道；软件断点与 VT 单步继续使用现有私有 ring。关闭后保留原生 DebugObject 兼容回退。
- `ProcessDebugPort`、`ProcessDebugObjectHandle`、`ProcessDebugFlags` 继续按私有目标作用域伪装；PEB `BeingDebugged`/`NtGlobalFlag` 复用现有 VT scrub/cloak；`NtQueryObject(ObjectTypesInformation)` 仅在总开关开启时增加 Bridge 所有权并清理 `DebugObject` 统计。
- Unreal 风格的 Dbgk 生产、等待、继续和 detach 链路已接入私有会话；六个未导出 `Dbgk*` 地址由用户态按当前 `ntoskrnl.exe` 运行时解析后下发驱动。
- 发布包不携带系统 PDB。符号缓存按 `E:\Symbols`、`D:\Symbols`、`C:\Symbols` 顺序选择，目录不存在时创建；首次运行需要网络或已有匹配缓存，后续可离线使用。

## 兼容边界

- 当前私有体系仍不是 Windows Object Manager 原生 `DebugObject` 类型，而是驱动私有会话加用户态令牌句柄；因此不能把它描述为已替换系统对象类型。
- 私有模式下 VT 启动顺序为注册 Bridge、解析并下发符号、建立私有目标绑定，再创建调试控制线程；原生模式不触发该符号路径。
- 本轮仅完成编译级检查，未加载驱动或运行调试器；Rust `cargo check --offline` 与 Bridge x86/x64 编译均通过。
