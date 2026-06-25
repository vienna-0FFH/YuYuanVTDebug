# Netr Hypervisor Control GUI

基于 PySide6 (Qt for Python) 的桌面客户端，覆盖 `Netr.sys` hypervisor 驱动的全部 46 个 IOCTL —— 从服务安装、状态查询、隐藏、注入到透明 HWBP 和 xHCI USB HID 注入。纯 ctypes 通信，不依赖 pywin32。

> 项目根 [`README.md`](../../README.md) 是完整的驱动 + GUI 一体化用户指南；本文档专注于 GUI 工具本身。

---

## 截屏布局

```
┌─────────────────────────────────────────────────────────────────────┐
│ 文件  视图  帮助                                                       │
├──────────────────┬──────────────────────────────────────────────────┤
│ ▾ 驱动管理         │  当前页（QStackedWidget 内容）                     │
│    服务加载/卸载    │                                                  │
│ ▾ 状态查询         │                                                  │
│    总览 / 嵌套      │                                                  │
│ ▾ 安全 / DSE       │                                                  │
│    DSE 开关与查询   │                                                  │
│ ▾ 隐藏             │                                                  │
│    进程隐藏        │                                                  │
│    驱动隐藏        │                                                  │
│ ▾ 保护             │                                                  │
│    调试器管理 (3 tab) │                                                │
│    进程保护         │                                                  │
│ ▾ 进程操作         │                                                  │
│    内存读写/分配    │                                                  │
│    DLL/Shellcode 注入                                                 │
│ ▾ 调试             │                                                  │
│    VT 透明硬件断点  │                                                  │
│ ▾ 输入注入         │                                                  │
│    VT 透明键鼠注入  │                                                  │
├──────────────────┴──────────────────────────────────────────────────┤
│ Log dock — 每次 SCM / IOCTL 调用的成功 / 失败记录                       │
└─────────────────────────────────────────────────────────────────────┘
状态栏:  Admin: YES   Service: RUNNING   Device: open (\\.\<random-leaf>)
```

设备节点不再是固定 `\\.\HvControl` —— Phase 8.4 起驱动启动期生成 16 字符随机 leaf，写入 `HKLM\Software\NetrSvc\DeviceName`，GUI 通过注册表读取后再 `CreateFile`。详见项目根 README 第 7.1 节。

---

## 目录结构

```
netr-gui/
├── main.py                  # QApplication 入口
├── requirements.txt         # PySide6>=6.6
├── README.md                # 本文件
├── Netr-GUI.spec            # PyInstaller 单文件配置
├── build.ps1                # PowerShell 打包脚本
├── build/  dist/            # PyInstaller 中间 / 最终产物
├── netr/                    # 与驱动通信的纯逻辑层（无 Qt 依赖）
│   ├── winapi.py            # ctypes 句柄、Win32 函数原型、Win32Error
│   ├── service.py           # SCM 封装：install / start / stop / uninstall
│   ├── privilege.py         # SeLoadDriverPrivilege 提权 + is_admin()
│   ├── structs.py           # 30+ IOCTL 结构 (pack=1) + NTSTATUS 表
│   ├── ioctl.py             # 44 个 IOCTL 常量 + 注册表动态设备名解析
│   ├── client.py            # NetrClient — 高层方法封装
│   └── processes.py         # Toolhelp32Snapshot 进程枚举
└── ui/                      # Qt 界面层
    ├── main_window.py       # QMainWindow：树 + Stacked + 状态栏 + 日志 dock
    ├── async_worker.py      # QThread + Signal/Slot 异步执行帮助函数
    ├── context.py           # AppContext：状态共享 + service/client 生命周期
    ├── log_panel.py         # 日志面板（带时间戳、monospace、上限 2000 块）
    ├── pages/               # 11 个功能页面
    │   ├── base.py
    │   ├── service_page.py
    │   ├── status_page.py
    │   ├── dse_page.py
    │   ├── process_page.py
    │   ├── driver_page.py
    │   ├── debugger_page.py   # 三 tab：启动+保护 / 反反调试 / 访问绕过
    │   ├── protect_page.py
    │   ├── memory_page.py     # 模块枚举 + READ_EX/WRITE_EX/ALLOC/FREE
    │   ├── inject_page.py     # DLL + Shellcode + StealthLevel 0-3
    │   ├── hwbp_page.py       # DR0-DR3 + 后台 WAIT_EVENT 轮询
    │   └── input_page.py      # 后端自适配 (PS2 / USB-HID / xHCI)
    └── widgets/
        └── process_picker.py  # ProcessPickerDialog + PidPicker
```

注意：早期版本的 `aad_page.py` 已合并到 `debugger_page.py` 的 **反反调试** tab，本目录列表反映当前状态。

---

## 先决条件

1. **Windows 10/11 x64**。驱动是 64 位独占。
2. **测试签名模式**（如驱动未做正式签名）：
   ```powershell
   bcdedit /set testsigning on
   shutdown /r /t 0
   ```
   重启后桌面右下角会出现 "测试模式" 水印。
3. **Python 3.10+**（仅开发态需要）— 推荐 3.11 或 3.12。
4. **管理员账号**。本程序需要 `SeLoadDriverPrivilege` 才能启动驱动。
5. 已编译好的 `Netr.sys`（一般位于 `..\..\x64\Release\Netr.sys`）。

运行打包后的 `Netr-GUI.exe` 不需要 Python 环境。

---

## 安装（开发态）

```powershell
cd C:\Users\Administrator\source\repos\MyDriver1\Netr\tools\netr-gui
python -m pip install -r requirements.txt
```

---

## 启动

**必须以管理员身份运行**。

```powershell
# 在已具备管理员权限的 PowerShell 中：
cd C:\Users\Administrator\source\repos\MyDriver1\Netr\tools\netr-gui
python main.py
```

若以普通用户启动，主窗口会弹出告警提示并继续启动；但任何加载/启动驱动的操作都会在 `SCM` 步骤返回 `ERROR_ACCESS_DENIED`。

---

## 打包成 EXE

仓库附带 `build.ps1`，调用 PyInstaller 把整个项目打成一个独立可执行：

```powershell
# 标准发布版（单文件 + 嵌入 UAC manifest，双击即弹管理员授权）
.\build.ps1

# 调试版（一文件夹形式 + 控制台输出）
.\build.ps1 -OneDir -Console

# 不嵌入 UAC（仅用于测试非管理员路径，正常分发请勿使用）
.\build.ps1 -NoUac

# 增量构建（不清理 build/dist）
.\build.ps1 -NoClean
```

产物路径：
- 默认：`dist\Netr-GUI.exe`（~45 MB，单文件）
- `-OneDir` 模式：`dist\Netr-GUI\Netr-GUI.exe`（启动更快）

脚本会自动 `pip install` PySide6 + PyInstaller，并排除 Qt3D / QtWebEngine / QtCharts / QtMultimedia / QtSql / QtQml / QtPdf 等 25+ 不用的重量级模块以缩小体积（瘦身 100+ MB）。

---

## 推荐操作顺序

| # | 节点 | 动作 |
|---|---|---|
| 1 | 驱动管理 → 服务加载 | 浏览 `Netr.sys` → 安装 → 启动（自动打开设备）|
| 2 | 状态查询 → 总览 | "查询总览" 确认 `HypervisorActive=True`，看 VPID 启用日志 |
| 3 | 安全 / DSE | 查询 → 禁用 → 再查询 → 启用（确认 `CiOptionsValue` 变化）|
| 4 | 隐藏 → 进程隐藏 | 起一个 `notepad.exe`，填 PID → 隐藏；用 `tasklist` 验证 |
| 5 | 隐藏 → 驱动隐藏 | 填 `Netr` → 隐藏；`driverquery` 验证 |
| 6 | 调试器管理 (启动+保护) | 浏览调试器 exe → 加白名单 → Add；目标 PID 自动 attach |
| 7 | 调试器管理 (反反调试) | 选钩子开关 (NQSI/QIP/SetInfoThread/...) → 启用 |
| 8 | 进程保护 | PID + DebuggerPid 白名单 → 启用 |
| 9 | 进程操作 → 内存 | 选 PID + 模块枚举 → "→ 填到读取地址" → READ_EX hex dump |
| 10 | 进程操作 → DLL 注入 | 浏览 .dll → 选 PID → StealthLevel 3 → 注入 |
| 11 | 进程操作 → Shellcode | 粘 hex shellcode → 选 PID → 立即执行 |
| 12 | 调试 → HWBP | 设 DR0 address → 后台监听器自动 wait/continue |
| 13 | 输入注入 → 键盘 tab | 多行打字 + 速度滑块 → 自动选 xHCI/USB-HID/PS2 后端 |
| 14 | 输入注入 → 鼠标 tab | dx/dy + 三按钮 + Smooth |
| 15 | 输入注入 → xHCI 诊断 | 看 7 个计数器 + 健康度判定 |
| 16 | 输入注入 → xHCI EPT trap | **默认 OFF**，显式启用排查 ISR fast-bail |
| 17 | 驱动管理 → 卸载 | 停止 → 卸载（设备被自动关闭）|

---

## IOCTL 全量映射（46 个）

设备类型 `FILE_DEVICE_UNKNOWN=0x22`，`METHOD_BUFFERED+FILE_ANY_ACCESS`，基址 `HV_IOCTL_BASE=0x800`。

| IOCTL | Code | GUI 节点 | 客户端方法 |
|---|---|---|---|
| `HV_GET_STATUS` | `0x00222000` | 状态查询 / 总览 | `get_status()` |
| `HV_DISABLE_DSE` | `0x00222040` | DSE | `disable_dse()` |
| `HV_ENABLE_DSE` | `0x00222044` | DSE | `enable_dse()` |
| `HV_GET_DSE_STATUS` | `0x00222048` | DSE | `get_dse_status()` |
| `HV_HIDE_PROCESS` | `0x00222080` | 隐藏 / 进程 | `hide_process()` |
| `HV_UNHIDE_PROCESS` | `0x00222084` | 隐藏 / 进程 | `unhide_process()` |
| `HV_HIDE_DRIVER` | `0x002220C0` | 隐藏 / 驱动 | `hide_driver()` |
| `HV_UNHIDE_DRIVER` | `0x002220C4` | 隐藏 / 驱动 | `unhide_driver()` |
| `HV_ADD_DEBUGGER` | `0x00222100` | 调试器 / 启动+保护 | `add_debugger()` |
| `HV_REMOVE_DEBUGGER` | `0x00222104` | 调试器 / 启动+保护 | `remove_debugger()` |
| `HV_PROTECT_PROCESS` | `0x0022210C` | 进程保护 | `protect_process()` |
| `HV_UNPROTECT_PROCESS` | `0x00222110` | 进程保护 | `unprotect_process()` |
| `HV_ENABLE_ACCESS_BYPASS` | `0x00222128` | 调试器 / 访问绕过 | `enable_access_bypass()` |
| `HV_DISABLE_ACCESS_BYPASS` | `0x0022212C` | 调试器 / 访问绕过 | `disable_access_bypass()` |
| `HV_INPUT_ENABLE` | `0x00222130` | 输入注入 | `input_enable()` |
| `HV_INPUT_DISABLE` | `0x00222134` | 输入注入 | `input_disable()` |
| `HV_INPUT_SEND_KEY` | `0x00222138` | 输入注入 / 键盘 | `input_send_key()` |
| `HV_INPUT_SEND_MOUSE` | `0x0022213C` | 输入注入 / 鼠标 | `input_send_mouse()` |
| `HV_ENABLE_ANTIANTIDEBUG` | `0x00222140` | 调试器 / 反反调试 | `enable_anti_anti_debug()` |
| `HV_DISABLE_ANTIANTIDEBUG` | `0x00222144` | 调试器 / 反反调试 | `disable_anti_anti_debug()` |
| `HV_INPUT_GET_STATUS` | `0x00222148` | 输入注入 | `input_get_status()` |
| `HV_INPUT_GET_XHCI_STATUS` | `0x0022214C` | 输入注入 / xHCI 诊断 | `input_get_xhci_status()` |
| `HV_INPUT_SET_STRICT_MODE` | `0x00222150` | 输入注入 | `input_set_strict_mode()` |
| **`HV_XHCI_TRAP_ENABLE`** | **`0x00222154`** | 输入注入 / xHCI EPT trap | `xhci_trap_enable()` |
| **`HV_XHCI_TRAP_DISABLE`** | **`0x00222158`** | 输入注入 / xHCI EPT trap | `xhci_trap_disable()` |
| **`HV_XHCI_TRAP_GET_STATS`** | **`0x0022215C`** | 输入注入 / xHCI 诊断 | `xhci_trap_get_stats()` |
| `HV_INJECT_DLL` | `0x00222180` | 进程操作 / 注入 | `inject_dll()` |
| `HV_INJECT_SHELLCODE` | `0x002221C0` | 进程操作 / 注入 | `inject_shellcode()` |
| `HV_MEMORY_READ` | `0x00222200` | — *(已由 READ_EX 取代)* | `memory_read()` |
| `HV_MEMORY_WRITE` | `0x00222204` | — *(已由 WRITE_EX 取代)* | `memory_write()` |
| `HV_MEMORY_ALLOC` | `0x00222208` | 进程操作 / 内存 | `memory_alloc()` |
| `HV_MEMORY_FREE` | `0x0022220C` | 进程操作 / 内存 | `memory_free()` |
| `HV_ENUMERATE_MODULES` | `0x00222210` | 进程操作 / 内存 | `enumerate_modules()` |
| `HV_MEMORY_READ_EX` | `0x00222214` | 进程操作 / 内存 | `memory_read_ex()` |
| `HV_MEMORY_WRITE_EX` | `0x00222218` | 进程操作 / 内存 | `memory_write_ex()` |
| `HV_MEMORY_BATCH_READ` | `0x0022221C` | — *(脚本用)* | `memory_batch_read()` |
| `HV_MEMORY_BATCH_WRITE` | `0x00222220` | — *(脚本用)* | `memory_batch_write()` |
| `HV_GET_NESTED_STATUS` | `0x00222280` | 状态查询 / 嵌套 | `get_nested_status()` |
| `HV_GET_NESTED_EVENTS` | `0x00222284` | — *(暂未启用)* | — |
| `HV_CLEAR_NESTED_EVENTS` | `0x00222288` | — *(暂未启用)* | — |
| `HV_DBG_SET_HWBP` | `0x00222400` | 调试 / HWBP | `dbg_set_hwbp()` |
| `HV_DBG_CLEAR_HWBP` | `0x00222404` | 调试 / HWBP | `dbg_clear_hwbp()` |
| `HV_DBG_WAIT_EVENT` | `0x00222408` | 调试 / HWBP | `dbg_wait_event()` |
| `HV_DBG_CONTINUE` | `0x0022240C` | 调试 / HWBP | `dbg_continue()` |
| `HV_KERNEL_READ` | `0x00222410` | — *(GUI 未暴露)* | — |
| `HV_KERNEL_WRITE` | `0x00222414` | — *(GUI 未暴露)* | — |

GUI 暴露 38 / 46 IOCTL。未暴露的 8 个：
- `MEMORY_READ` / `MEMORY_WRITE`（旧 4KB 接口，GUI 已统一走 `_EX` 64KB 版本）
- `MEMORY_BATCH_READ` / `MEMORY_BATCH_WRITE`（256 项批量，client API 暴露供脚本使用）
- `GET_NESTED_EVENTS` / `CLEAR_NESTED_EVENTS`（驱动定义但 client 未实现）
- `KERNEL_READ` / `KERNEL_WRITE`（高危内核 R/W，故意不暴露给 GUI 减少误操作面）

---

## 设备名动态解析

```python
# tools/netr-gui/netr/ioctl.py:25-55
DEVICE_PATH_FALLBACK = r"\\.\HvControl"

def resolve_device_path() -> str:
    """从 HKLM\\Software\\NetrSvc\\DeviceName 读取驱动随机生成的 leaf。
    驱动启动期把 16 字符随机 leaf 写入这里; NetrSvc 项被 NtEnumerateKey 隐藏,
    但直接 path 打开仍可访问。读不到则 fallback 到 \\\\.\\HvControl。"""
    import winreg
    try:
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"Software\NetrSvc",
            0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
        leaf, _ = winreg.QueryValueEx(key, "DeviceName")
        winreg.CloseKey(key)
        return rf"\\.\{leaf}"
    except OSError:
        return DEVICE_PATH_FALLBACK
```

`NetrDevice.__init__` 每次 open 都重新 resolve，避免 stop/start 周期之间路径 stale。

---

## 常见错误

| 现象 | 原因 / 修复 |
|---|---|
| `OpenSCManagerW failed (5: ERROR_ACCESS_DENIED)` | 没以管理员运行 |
| `StartService failed (577: ERROR_DRIVER_BLOCKED)` | 测试签名未开启或驱动未签名 — 见上方先决条件 |
| `CreateFileW \\.\<leaf> failed (2: not found)` | 驱动未启动 — 先回到 "服务加载/卸载" 启动驱动 |
| `IOCTL ... → HV_STATUS_NOT_FOUND` | 找不到目标进程 / 驱动；检查 PID 或名字 |
| `IOCTL ... → HV_STATUS_INVALID_PARAMETER` | 入参不合法（空 name + 0 pid，长度溢出等） |
| `IOCTL ... → C000000B (PROCESS_IS_TERMINATING)` | 目标进程已退出 |
| `IOCTL ... → C0000207 (ADDRESS_NOT_VALID)` | 目标 GVA 未映射或 paged out |
| `IOCTL ... → C00000BB (NOT_IMPLEMENTED)` | 目标地址撞上 2MB/1GB 大页，需要分割 |
| `IOCTL_HV_INPUT_GET_XHCI_STATUS` 全 0 | 没找到 xHCI HID device；keyboard/mouse 不在 USB 上 |
| xHCI 注入无响应 | 尝试启用 xHCI EPT trap (默认 OFF) 排查 ISR fast-bail |
| 主窗口 `SeLoadDriverPrivilege` 警告 | 当前进程令牌没有此特权 — 用真正的管理员账户重试 |

`structs.py:71-78 NTSTATUS_HINTS` 提供人话错误解释，GUI 会把 NTSTATUS 翻译成可读字符串显示。

---

## 设计要点

- **逻辑 / UI 分离**：`netr/` 不引入 Qt；`ui/` 不直接调 ctypes。两层各自可单测。
- **异步执行**：每个按钮点击通过 `ui/async_worker.run_async` 转入临时 `QThread`，避免 SCM 等慢调用阻塞 UI。`_CallbackBouncer` 用 AutoConnection signal 桥接回 UI 线程。
- **设备状态门控**：未打开设备时，除 "服务加载/卸载" 外的所有节点在树里 disable，杜绝点击未连通的页面。
- **错误友好化**：Win32 错误码通过 `FormatMessageW` 解码；驱动 `HV_STATUS_*` 通过 `hv_status_name()` 映射为可读名；NTSTATUS 加 hint 表注释（"进程不存在" / "目标地址未映射" / "撞上 2MB 大页"）。
- **结构镜像**：`netr/structs.py` 全部 `_pack_ = 1`，因为驱动 typedef 用 `#pragma pack(push, 1)`；`python -m netr.structs` 可打印每个结构的实际尺寸便于跟驱动 `sizeof()` 对账。
- **后端自适配**：`input_page.py` 通过 `INPUT_GET_STATUS`/`INPUT_GET_XHCI_STATUS` 自动判定后端（PS2 / USB-HID / xHCI），动态显示对应控件 + 诊断面板。
- **后台监听器**：`hwbp_page.py` 的 `_EventListener` QThread 用 200ms timeout 轮询 `WAIT_EVENT`，命中后 `continue_event` ack，不阻塞 UI。

---

## 范围 / 非目标

**包含**：
- 46 IOCTL 中 GUI 暴露 38 个，client API 暴露 42 个
- 驱动 SCM 生命周期（install/start/stop/uninstall）
- 提权处理 + 错误信息友好化
- 注册表动态设备名解析
- xHCI / USB-HID / PS/2 输入注入后端自适配

**不包含**：
- 驱动签名/证书安装步骤（见项目根 README 3.2 节）
- 单元测试（工具类应用，依赖手动验证）
- 跨平台（Windows-only）
- 32 位支持（驱动 x64-only）
- 多语言（中文界面写死）
- `KERNEL_READ` / `KERNEL_WRITE` 暴露（高危，故意保留为脚本用）
