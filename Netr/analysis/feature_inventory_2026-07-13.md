# Netr 驱动功能清单与参考差异（2026-07-13）

## 口径与范围

本清单以当前 `Netr` 为唯一实现主线，只读比较：

- `YuYuanVTDebug_备份\Netr`
- `E:\project_learning\UnrealVTDbgBAK\VT_Driver`

状态口径：

- **active**：当前源码已接入初始化、运行时发布与卸载链；仍可能因硬件能力或初始化失败而 fail-closed。
- **implemented-but-gated**：实现和接口保留，但编译门、运行时配置或能力门尚未发布实际行为。
- **unsafe-blocked**：实现保留，但存在明确的生命周期、回滚、体系结构或 PatchGuard 风险，不能把“能编译”当作“可启用”。

本清单任务本身只做静态接线/能力审计，没有加载驱动或运行真机功能测试。同期共享源码的全驱动 C/ASM 编译、链接已成功；能力真实性后续改动的 Driver `ClCompile` 与 Bridge x64/x86 编译也已通过。签名仍因沙箱账户缺少证书私钥失败，`test-package` 未刷新；最终构建/签名状态以同期交班报告为准。

## 总览

| 子系统 | 当前状态 | 当前真实边界 | 备份差异 | Unreal 参考关系 |
| --- | --- | --- | --- | --- |
| VT-root PID 物理读写 | **active** | Windows 侧只获取有引用保护的 `EPROCESS`、锁定目标/锚点页并构造不可变候选快照；CR3 所有权验证、页表 walk 和最终 copy 在 VMX-root/SVM-host 的预映射窗口完成；`g_VtRootEnabled=FALSE` 时直接 `STATUS_DEVICE_NOT_READY`，没有 Windows walker fallback | 备份将 `HV_ENABLE_VT_ROOT` 设为 0；旧 root 路径还会按 PID 在 root 中遍历/解引用 Windows 进程对象，且直接把调用缓冲区送入 root。当前改成生命周期绑定快照 + bounce page | 延续 Unreal `host_physical_memory_base`、root 页表 walk/copy 的 VT-first 意图；当前增加 PID/CreateTime/PEB/ImageBase 归属验证、锁页和 Intel/AMD 对称 ABI |
| VT-root Leaf-PTE 查询 | **active** | mode 9 返回 64-byte versioned ABI，覆盖 4KB/2MB/1GB；legacy mutation API 对大页 `STATUS_NOT_SUPPORTED`，输出保持清零 | 备份没有当前的 versioned leaf metadata 和完整大页语义 | Unreal 有 root GVA→GPA walk 和大页处理，但没有当前可验证的 leaf-table ABI |
| 私有 HOST_CR3/物理 aperture | **implemented-but-gated** | slot 255 的 canonical base 已修为 `0x00007F8000000000` 并有 `C_ASSERT` 防回归，但 VMCS 尚未切换到该 CR3；当前 0..64GB 统一 WB/大页映射也未正确排除 MMIO | 备份的 slot 255 与 `0xFFFFFF8000000000` 实际 slot 511 确定性错配 | 源自 Unreal 私有 host PT/物理窗口范式；当前只能作为后续实现，不能替代已工作的 VtRoot scratch window |
| raw-PTE 进程分配/释放 | **unsafe-blocked** | 活动 API 和 staged bit 保留；`HvPhysAllocateInProcess/HvPhysFreeInProcess` 固定返回 `STATUS_NOT_SUPPORTED`。旧实现已恢复到不参与编译的 `HvPhysRawPteLegacy.c.disabled` 供后续重写审计，不能成为 fallback | 备份的无 VAD raw-PTE 实现此前曾被删除；本轮恢复为 legacy archive，但不恢复其危险行为 | Unreal 不提供可直接迁移的 Windows MM 生命周期实现 |
| Injection manager / shellcode | **active（Windows-assisted，未真机验证）** | allocation/module/hidden-memory 三类记录均绑定 `PID + CreateTime` 并在 process-exit 清理；module unload 使用锁内 claim，不再返回解锁裸指针。process-notify 注销失败会保留 manager 并阻止卸载继续。shellcode APC IOCTL 已接线；它使用 Windows 进程/虚拟内存/APC 机制，不属于 VT-root 数据面。`ENABLE_INJECTION_FRAMEWORK` 同时约束 init/cleanup | 备份保留同类注入框架，生命周期较弱 | Unreal 的 `Hook\Inject` 可作非 VT 行为参考，不能覆盖当前 VT-first 内存读写要求 |
| DLL manual-map | **unsafe-blocked** | PE 映射/重定位/导入骨架存在，但 TLS callback 只枚举未调用，映射后也未执行 DllMain；不得把当前返回成功解释为模块完成初始化 | 备份同样没有完整 target-thread entrypoint/rollback 闭环 | Unreal 有独立注入链参考，但不是可直接迁移的驱动生命周期实现 |
| injected-memory hide | **implemented-but-gated / 高风险** | `NtQueryVirtualMemory` hook 仅在内部 API 请求时惰性发布；本轮补了列表快照、PID+CreateTime、process-exit cleanup、trampoline/handle 失败保留。PE header 擦除/PEB 脱链仍会修改真实目标状态且无完整 rollback，因此不作为默认能力发布 | 备份实现返回解锁裸指针、remove 失败丢 handle，并会在 hook 失败后继续破坏性修改 | Unreal 没有等价的 VT shadow memory-hide 生命周期 |
| Process hide | **active（条件发布）** | IOCTL 显式请求；只有 backend core hook/trampoline 就绪后才加入 hidden list。Intel 依赖共享 NtQSI owner 加 EPT NtGetNextProcess，AMD 使用 NPT NtQSI+NtGetNextProcess；计数是已发布记录，不代表所有可选 ETW/handle 面都成功 | 备份会先记 PID、后安装 hook，并在失败时仍返回成功 | Unreal VT_Driver 无等价 Windows 枚举隐藏 |
| Debugger proxy / process protection | **active（条件发布）** | debugger 注册 0→1 事务会安装 core proxy 与 AccessBypass；Bridge bind 比普通 protect-record IOCTL 更严格。普通 `ProtectedProcessCount` 仍表示策略记录数量，不等于每个 best-effort enforcement hook 都成功 | 备份生命周期接线不完整 | Unreal 无等价 Windows policy/control-plane 子系统 |
| AccessBypass | **active（显式/随 debugger 生命周期）** | `NtOpenProcess` 是发布核心；NtGetNextProcess、文件保护、Ob callback、NtDuplicateObject 为扩展面。本轮 disable 改为逐 handle 检查，remove 失败保留 owner/status 供重试 | 备份曾有自动生命周期，后续版本一度只剩手动 IOCTL | Unreal 无等价实现 |
| Anti-anti-debug | **active（显式、条件发布）** | 只有 configured mask 全部安装才返回 enable 成功；disable 逐 hook 保留失败 owner，不再清 handle 虚报。默认不随 debugger 自动开启 | 备份多个 hook 可部分失败但仍置 Enabled | Unreal `TitanHide_antivmp` 提供反调试 mask 行为参考，当前按 7 组 ABI 发布 |
| Input / xHCI HID | **active（硬件条件）** | PS/2 与 xHCI HID manager 在 core 初始化，严格模式和状态 IOCTL 已接；具体 keyboard/mouse readiness 取决于控制器、端点和 ring discovery | 备份主体实现保留 | Unreal VT_Driver 无等价 xHCI 注入 |
| xHCI EPT read trap | **implemented-but-gated** | staged 实现已改为 per-vCPU leaf、整项原子 Read-bit 更新、全 CPU split 一致性检查和中途失败 rollback；root CPU identity 使用 `VCPU_DATA.ProcessorNumber`。当前 `HvCore` 仍不发布 trap manager，enable 返回 `STATUS_DEVICE_NOT_READY`；未做 focused runtime validation 前不能与基础 xHCI HID readiness 混称 | 备份有较早 trap 实现，只有 CPU0/shared-PT 假设且 rollback 不完整 | Unreal 无等价 manager 生命周期 |
| DSE EPT/NPT bypass | **active（显式高风险）** | IOCTL 显式安装 `CiValidateImageHeader` hook；本轮 re-enable 在 remove 失败时保留 handle/disabled 状态，不再虚报成功。仍需独立真机/卸载矩阵 | 备份同类行为缺少当前失败所有权 | Unreal 无等价实现 |
| Nested VMX/SVM | **active（实验性）** | `HV_ENABLE_NESTED_VIRTUALIZATION=1`；只有 VT-root 与所有 per-VCPU 固定资源就绪后才发布 `Running` gate；有 Ready/Running/Quiescing 状态、事件环和 unload quiesce | 备份虽有 nested 源文件，但 Driver 启动链未发布；当前新增真实初始化/启用/清理接线和固定池 | Unreal 的 VMX 指令路径主要拒绝 guest VMX，没有同等级 L2 生命周期；当前不是简单复制 |
| AMD SVM hardening | **active（未真机验证）** | `HV_ENABLE_SVM_HARDENING=1`，启用 per-vCPU/L2 ASID、2TB NPT 高地址映射、vGIF pending、IOPM/MSRPM 合并路径 | 备份为 0 | Unreal 只有 Intel VMX，无 AMD 对照 |
| VT 虚拟硬断（Vwatch） | **active，Intel-only** | `HV_ENABLE_VWATCH=1`；只有 manager、Intel VMX、全部 `EptPebSpoof` 就绪才报告支持；L2 明确拒绝；读/写/执行 watch 经 EPT violation、MTF 和私有事件环处理 | 备份 Vwatch 为 1，但实现较早，缺少当前 rundown、事务发布、事件背压和 overlay 冲突保护 | 继承 Unreal `EPTW_WRITE/READWRITE/EXECUTE` 与 EPT watch 的行为意图；当前增加 debugger/target 所有权、4 slot ABI 和生命周期收口 |
| 私有/无痕软件断点 | **active，Intel + EPT execute-only** | capability 只有 `HvVwatchIsPrivateSoftwareBreakpointSupported()` 为真才发布；目标代码页保持原字节，通过 execute shadow、#BP、MTF 与 continue 事件实现；L2 fail-closed | 备份只有未完整收口的路径 | 对应 Unreal `VMCALL_HIDE_SOFTWARE_BREAKPOINT` 和 fake page；当前改成有所有权、可继续、可清理的 Bridge/Vwatch 路径 |
| DR 硬断 fallback | **active，但不是 VT 无痕硬断** | AMD 或不支持 Vwatch 时可由 `HvDebugger` 走 DR fallback；Bridge 单独报告 `HV_BRIDGE_CAP_DR_HWBP_FALLBACK`，不能与 VT HWBP 混称 | 备份已有 DR/HWBP 基础 | Unreal 同时记录 DR 状态，但主 watch 是 EPT |
| PEB 字段级 cloak | **active，Intel-only，仍需重点验证** | `HV_ENABLE_PEB_CLOAK=1`；target 持有 `PEPROCESS + CreateTime` 身份；overlay EPT 按 CR3 分类；写/RMW/执行临时回原页；双 patch buffer、global/page root reader、MTF 状态、退出/卸载 rundown 与 PASSIVE stale rebind worker 已接入 | 备份 `HV_ENABLE_PEB_CLOAK=0`，worker 也未形成可靠运行闭环 | Unreal 没有同等级 PEB 字段级 cloak |
| PEB/Vwatch overlay 冲突 | **active（拒绝策略）** | 同 GPA 被另一 owner 占用时返回 `STATUS_CONFLICTING_ADDRESSES`；当前没有 composed multi-owner PTE，因此拒绝比静默互相覆盖真实 | 备份缺少双向 owner 冲突检查 | Unreal 的 watch/fake page 共用结构，但没有当前两个独立管理器的组合问题 |
| Driver hide | **active（条件发布）** | DriverEntry 事务为：安装 shared `NtQuerySystemInformation` owner → backend ready → 把自身加入 hidden set；任一步失败回滚。class 11 模块枚举在 Intel/AMD 都过滤；Intel 另装 `ObReferenceObjectByName`，AMD 尚无等价按对象名阻断 | 备份 Driver.c 为 `#if 0`；当前补了独立 owner、class 11 分发、真 syscall resolver、trampoline fail-closed 和启动/卸载状态 | Unreal VT_Driver 无同等级驱动隐藏子系统 |
| File hide | **active（条件发布）** | `ENABLE_FILE_HIDE_HOOK=1`；解析 `NtQueryDirectoryFile` 的真实内核实现后安装 EPT/NPT hook；只有 hook/trampoline 和当前镜像文件名过滤项都成功才记录 published，否则回滚 | 备份 gate 为 0，卸载也未接线 | Unreal VT_Driver 无同等级文件枚举隐藏 |
| Registry hide | **active（条件发布）** | `ENABLE_REGISTRY_HIDE_HOOK=1`；顺序为 manager init → 添加 `NetrSvc` → 解析真实 `NtEnumerateKey` → install；失败 cleanup；unload 执行 uninstall/cleanup | 备份 Driver.c 为 `#if 0`，并曾在 manager 初始化前添加名字、且名字写成 `Netr` | Unreal VT_Driver 无同等级注册表枚举隐藏 |
| Network hook | **active hook / implemented-but-gated rewrite** | `ENABLE_NETWORK_HOOK=1`；只有至少一个有效 `NsiGetParameter` hook + trampoline 才置 Initialized。`g_FakeEnabled` 默认 FALSE，因此当前启动只发布 hook，不会篡改流量；没有 Driver IOCTL 暴露配置/enable API | 备份初始化/清理整块被注释；当前修复 `BOOLEAN` 被 `InterlockedExchange` 四字节覆盖的内存破坏，并改成 fail-closed 发布 | Unreal VT_Driver 无同等级网络统计 hook |
| PE header obfuscation | **unsafe-blocked** | `ENABLE_PE_IMAGE_OBFUSCATION=0`；旧实现保留，但它会直接写 live driver image，没有 VT read-shadow、可靠 rollback 或 PatchGuard-safe lifetime | 备份同样用 `#if 0` 隔离，曾记录 Win11/PatchGuard/扫描并发风险 | Unreal 没有可证明安全的等价实现，不能据此直接启用 |
| AMD PEB/NPT cloak mirror | **unsafe-blocked** | `HV_ENABLE_SVM_CLOAK=0`；NPT overlay cloak 尚未实现，AMD 不应虚报 PEB/Vwatch VT 能力 | 备份同样为 0 | Unreal 无 AMD 路径 |

## 关键实现与剩余边界

### 1. 物理直通保持 VT-first

当前 by-PID 数据面已经不再调用 `HvPhysFindUserCr3ForGvaByPid` 后把一个 Windows 侧 CR3 当作最终事实。PASSIVE 侧执行的是：

1. `PsLookupProcessByProcessId` 持有进程引用，并记录 `PID + CreateTime + PEB + ImageBase`。
2. 从受控 EPROCESS offsets、CR3 snoop ring 和生命周期缓存收集候选 CR3；这里只收集输入，不做所有权结论。
3. 用 MDL 锁定目标范围与 PEB/ImageBase 锚点，使用 nonpaged request 和单页 bounce buffer。
4. VMX-root/SVM-host 重新验证候选 CR3 能同时解释 PEB/ImageBase，再 walk 目标 GVA 并执行一页 copy。
5. 进程引用、MDL、bounce 和 request 在同步 VMCALL 返回后释放。

这与 Unreal 的 root physical window 思路一致，但没有复制 Unreal 在 root helper 中调用 `IoGetCurrentProcess`、以及部分 hook handler 使用 `MmGetPhysicalAddress` 的做法。参考项目只证明 VT 层行为意图，不是无条件复制权威。

仍需验证：PID 复用、进程退出与复制并发、目标页换出/重映射、跨页 partial copy、候选 CR3 冲突、Intel/AMD ABI 对称、2MB/1GB leaf query、多个 CPU 同时访问各自 scratch window。任何失败都应返回状态，不能恢复 Windows `MmMapIoSpace` walker 或 Bridge 无限重试规避。

`HvHostPt` 是另一条尚未发布的 Unreal-style 私有 HOST_CR3 路线。当前只修正了 PML4 slot/base 的确定性错误，尚未完成 RAM/MMIO memory type 建图、host code/stack/VCPU/GDT/IDT/TSS 全地址验证和 all-CPU 原子发布。因此 VMCS 继续使用安全的 system CR3；`HvHostPt` 不能被用作 VtRoot 物理直通的 fallback，也不能因结构已初始化就报告为 active。

### 2. Nested 已发布，但不能标成“完整兼容”

Nested 的源码和 VM-exit 分发已实际接线，不再因旧 `#if 0` 初始化块存在而误判为整个子系统关闭。旧块是保留的历史实现；真正活动的 vendor-specific 初始化位于其后。

当前能力状态接口 V2 能分别报告 hardware/root window、initialized、enabled、quiescing、lifecycle 和 event loss；这比旧的“文件存在即支持”真实。但实现仍有需要真机关闭的兼容缺口：

- Intel VMCS12 字段覆盖、控制允许位校验、VM-entry/exit MSR list、IO/MSR bitmap 合并和 shadow VMCS 仍非完整硬件语义。
- Nested EPT02 已有固定池、按需翻译和权限合并，但 1GB L0 EPT、复杂 memory type 与 L1 动态更新/invalidations 仍需重点验证。
- AMD VMCB12 保留位/状态校验仍有简化判断，复杂 IOPM/MSRPM、事件注入和 NPT fault 组合尚未真机覆盖。
- 三层 nested（L2 再执行 VMX）明确不支持。

因此状态是“active experimental”，不是“production-ready”。运行失败应撤回 gate 并保持普通 L1，不应删除 nested 代码或虚报 L2 已可运行。

### 3. VT 软硬断已覆盖 Unreal 的核心行为

Unreal 提供了三类重要参考：EPT watch、隐藏软件断点/fake page、VM-exit 中采集寄存器与命中事件。当前项目已经保留这些行为，并增加了：

- debugger/target/slot 所有权与退出清理；
- root reader/rundown，防止控制面复用仍被 VM-exit 引用的 entry/page；
- MTF `PUBLISHING/ARMED/COMPLETING` 发布顺序；
- 私有事件 ring 的 backpressure；
- VA→GPA rebind 与写后 shadow refresh；
- PEB 与 Vwatch 同 GPA 的双向拒绝；
- L2 明确 fail-closed，避免 L1 overlay 错作用于 nested guest。

剩余真机矩阵至少包含：读/写/执行 watch，1/2/4/8-byte 长度，四 slot，同页多个 watch，私有 SWBP add/hit/continue/delete，真实 `0xCC` 指令，目标写代码页/COW/重映射，事件环满，debugger/target 异常退出，attach/detach 重复和 unload 时 pending MTF。

AMD 当前只能如实走 DR fallback；在实现 NPT overlay watch 前，不能把 AMD fallback 标成 VT 无痕硬断。

### 4. PEB cloak 的安全收口与未完成项

当前 PEB cloak 相对备份已从 disabled skeleton 变成有真实生命周期的 Intel overlay 功能：target 状态、root 引用、双 patch buffer、reader 计数、write/execute fail-open、trusted CR3/HPA 复核、进程退出和 worker rundown 都已接线。

PEB/heap VA 的物理页发生 remap 时，VM-exit 会先把旧 overlay PTE 恢复为 identity、标记 `Stale` 并 fail-open。PASSIVE rebind worker 随后在 `OverlayMutation -> ControlLock` 锁序下验证 `PEPROCESS + CreateTime`，通过现有 VtRoot ABI 重新解析可信 CR3/GPA、读取原页并重建双 patch buffer；CR3 ownership、walk 与 copy 仍在 root。worker 有 stop event、失败指数退避、Vwatch/其他 target 同 GPA 冲突拒绝，shutdown 会先停止并等待 worker。page-local root gate 由 violation 持有到 MTF completion，rebind/unregister 关闭 gate 后必须 drain 才能修改或释放页面。

当前剩余的是运行时验证，而不是已知的永久 stale 缺口：需要覆盖 remap/COW 后自动恢复、连续失败退避、进程退出/PID 复用、rebind 与 unregister/shutdown 并发，以及 MTF 长时间 pending 时的 drain 行为。

另外，Bridge 的 `HV_BRIDGE_CAP_PEB_SCRUB` 表示一次性的 VT-root PEB 读写清理操作，不等同于持续的 EPT PEB cloak capability。它现在只在 VT memory ready 且 `HvDebugger` ready 时协商成功；当前协议仍没有单独报告 cloak active/target stale 状态。

### 5. Driver/File/Registry/Network 的启动事务

四类可选 hook 现在都有 Driver 侧状态，只在安装成功后记录 published，并在 SLAT/hook backend 仍存活时清理：

- Driver hide：独立 shared-hook owner，self-hide 失败会回滚 owner。
- File hide：真实 syscall implementation + trampoline + 文件过滤项组成一个事务。
- Registry hide：manager 先初始化，正确隐藏 `NetrSvc`，安装失败 cleanup；卸载先 uninstall 再 cleanup。
- Network：只有真实 NSI hook 成功才报告 initialized；cleanup 失败会保留 manager 状态供 backend safety net 处理。

通用 EPT/NPT inline hook entry 也补了两层 lifetime：VM-exit 无锁遍历持双 epoch root reader；普通 HookFunction 入口持全局 callback rundown。remove 先停止 entry、等待旧 reader 与 MTF/#DB completion，摘链后再次切 epoch；entry/fake page 进入 retired list，不在单项 remove 时释放。DriverUnload 关闭所有新 callback、等待全局 rundown 后，backend 才释放 retired entries/trampoline。`RemoveAll` 不再摘整链直接 free，cleanup 在残留 entry、Nested L2、Ob callback 或注入 process-notify 未 drain 时不会继续撤 VT。Intel root CPU identity 由 `VCPU_DATA.ProcessorNumber`/HOST_FS_BASE 传递，活动 violation/MTF 路径不再调用 `KeGetCurrentProcessorNumber`。

能力并非完全对称：Intel driver hide 同时有模块枚举过滤和 `ObReferenceObjectByName` 阻断；AMD 当前只有模块枚举过滤。文件/注册表/网络又高度依赖目标 Windows build 的 syscall/export、指令 trampoline 和返回结构布局，因此“宏为 1”只表示尝试初始化，不能保证每台机器 published。

Network 还要区分“hook active”和“rewrite active”。当前后者默认关闭且没有用户态控制面；若目标是可用功能，应增加 versioned 配置/状态 IOCTL、参数校验和 disable/rollback，而不是 DriverEntry 硬编码一组假流量。

### 6. PE obfuscation 必须继续阻断

旧 `HvObfuscateImageHeaders` 会在延迟线程中直接清零已加载镜像的 DOS/NT/section headers。这不是 VT cloak：系统组件、调试器、PatchGuard/Defender 和并发扫描看到的是被破坏的真实页；卸载也没有保存/恢复原 header 的可靠事务。

安全发布至少需要：独立 shadow page、按 caller/CR3 或访问类别选择 EPT/NPT 映射、写访问与 MTF 语义、原页永不破坏、所有 CPU invalidate、失败回滚和 unload rundown。在这些条件完成前，`ENABLE_PE_IMAGE_OBFUSCATION=0` 是正确能力状态；实现必须保留供后续重写，但不能直接翻 gate。

## 能力真实性审计

| 能力/状态面 | 当前结论 | 缺口 |
| --- | --- | --- |
| `HV_STATUS_INFO.VtRootEnabled` | **真实** | 直接反映 `g_VtRootEnabled` |
| `HV_STATUS_INFO.HookManagerInitialized`、Proxy、AccessBypass | **基本真实** | 反映 manager/owner 发布状态 |
| `HV_STATUS_INFO.HiddenProcessCount/HiddenDriverCount` | **Intel 为发布记录计数；AMD 均不完整** | Intel process count 现在只在 core hook 就绪后记账，但仍不代表所有可选 ETW/handle 面成功；AMD 尚无 process/driver 精确 count ABI，generic process count 仍为 0，self-hide driver count 只是保守下界 |
| `HV_STATUS_INFO.ProtectedProcessCount` | **策略记录计数** | 表示 policy list 中的记录数，不等于每个 best-effort enforcement hook 都已安装；Bridge target bind 的成功口径更严格 |
| AAD dedicated status | **configured/installed 分离** | enable 现在要求 installed mask 覆盖 configured mask；generic boolean 只在完整发布后置 TRUE |
| Input/xHCI status | **基础 manager 真实；trap 单独阻断** | PS/2/xHCI HID readiness 由 status 返回；xHCI EPT trap 未初始化时 enable 必须 `DEVICE_NOT_READY` |
| Injection/DLL status | **无完整 capability ABI** | manager ready 不代表 DLL TLS/DllMain 已完成；当前 GUI/文档必须把 DLL manual-map 标成 incomplete |
| Nested status V2 | **真实且 fail-closed** | `HardwareSupported` 实际还要求 root window/per-VCPU tables，不是纯 CPUID；命名略宽，但不会把未就绪路径报为可用 |
| Bridge `PRIVATE_SWBP` / `VT_HWBP` | **真实** | 分别检查 Intel overlay/execute-only 条件；AMD 不会误报 VT HWBP |
| Bridge `DR_HWBP_FALLBACK` | **基本真实** | 只代表 `HvDebugger` fallback backend 初始化，不代表某个 target/slot 已成功设置 |
| Bridge `MEMORY_IO` | **真实** | 只有 `g_VtRootEnabled && HvIsHypervisorRunning()` 才协商 `HV_BRIDGE_CAP_MEMORY_IO` |
| Bridge OS memory protect | **真实且与 VT 分离** | 新客户端请求 `HV_BRIDGE_CAP_OS_MEMORY_PROTECT`；实现走 attach + `ZwProtectVirtualMemory`，不再借 legacy generic bit 暗示 VT 属性 |
| Bridge OS COW write | **真实且与 VT 分离** | 只有 `MmCopyVirtualMemory` 可解析才协商 `HV_BRIDGE_CAP_OS_COW_WRITE`；实现不是 VT 数据面，Bridge 可按独立 OS/VT bits 选择路径 |
| Bridge `PEB_SCRUB` | **真实的一次性 VT-root 操作** | 只在 VT memory + debugger ready 时协商；与持续 PEB cloak 仍是两个能力，没有 cloak ready/stale capability |
| Driver/File/Registry/Network hook state | **真实且外部可见** | Bridge `HV_BRIDGE_RESULT.Flags` 追加高位 `HV_BRIDGE_STATE_*`，只反映成功 published 的内部状态；尚未包含 network rewrite enabled |
| Network | **`HvNetHookIsInitialized` 真实** | 没有外部 hook/fake/config 状态；initialized 不代表 traffic rewrite enabled |
| `HvPhysQueryStagedCapabilities` | **仅编译期 staged 信息** | 它返回 raw-PTE alloc staged bit，但 alloc/free 固定 `STATUS_NOT_SUPPORTED`；禁止把它作为 runtime supported mask |

Bridge 注册现已按运行时 readiness 回显 operation bits，并用显式 `OS_*` bits 区分 Windows-assisted fallback。下一步仍建议追加、不打断旧客户端的 status V2：分别报告 `NetworkRewriteEnabled`、`PebCloakReady`、`PebStaleTargets`、AMD hidden-list 精确计数和 optional hook 最近一次失败码。

## 参考项目保留与未迁移结论

### 备份项目

备份不是“功能更多的稳定黄金版”，而是当前主线之前的行为基线：

- VT-root、PEB cloak、SVM hardening 在备份中分别由 0 gate 关闭。
- Driver/file/registry/network/PE obfuscation 的 Driver 接线被 `#if 0` 或整块注释隔离。
- Vwatch/EPT hook/nested 源码存在，但多个生命周期和失败路径没有形成发布事务。
- 旧 root PID resolver 把 Windows 对象布局遍历放在 root 热路径，虽然符合“更多代码在 VT”表象，却违反 root 中不能依赖 Windows object-manager lifetime 的更早不变量。

当前主线应保留备份 API 与功能意图，但不能恢复这些已识别的不安全细节。

### UnrealVTDbgBAK

可确认的 VT 行为参考集中在 `VT_Driver`：

- PML4 slot 物理窗口、root GVA→GPA walk、跨页 read/write；
- EPT shadow/fake page、CC/INT1/VMCALL hook；
- 隐藏软件断点；
- read/write/execute EPT watch、MTF 临时放行、命中事件与 guest 寄存器采集。

当前项目已覆盖上述核心行为，并在生命周期、进程身份、事件所有权、Intel/AMD 分发和卸载上做了扩展。Unreal 中没有可直接对等的 Nested VMX/SVM、PEB 字段 cloak、driver/file/registry/network hide 或安全 PE-image cloak。它也包含在 root helper 中调用 Windows API、部分使用 `MmGetPhysicalAddress` 和全局固定 watch 表等历史做法；这些不能反向覆盖当前 VT-first 不变量。

参考树不只有 `VT_Driver`：`Hook\Inject\ShellCode` / `UnrealDbgDll` 提供用户态/注入行为参考，`TitanHide_antivmp` 提供十类 anti-debug mask。它们可用于核对功能意图和协议覆盖，但属于非 VT 控制面或另一套驱动模型，不能据此把当前 DLL 初始化、Windows hook 生命周期或授权状态标成已完成。

## 运行时验证缺口与建议顺序

本轮未执行下列测试。启用源码不等于完成验证，建议统一真机测试按故障隔离顺序进行：

1. **VT-root 基线**：单线程/并发读写、跨页、无效 VA、进程退出/PID 复用、2MB/1GB leaf query；确认失败不触发 Bridge 重试风暴或 Windows walker。
2. **Vwatch/private SWBP**：普通目标先覆盖所有 hit/continue/remove/exit/unload，再测反作弊目标；监控 event lost、pending MTF 和 overlay owner 冲突。
3. **PEB cloak**：BeingDebugged/NtGlobalFlag/heap 字段的读写/RMW，目标页重映射后的 fail-open→PASSIVE rebind 恢复、失败退避，以及 unregister/shutdown drain。
4. **Nested**：Intel 和 AMD 分开；先无 EPT/NPT 的最小 L2，再测 nested EPT/NPT、IO/MSR bitmap、事件注入、L2 exit 反射和 quiesce/unload。
5. **可选 hide hooks**：逐个高频循环模块枚举、目录枚举、注册表枚举、NSI 查询，再组合测试共享 hook owner 与卸载；AMD driver hide 需单独确认按对象名仍可见的已知差异。
6. **Injection/memory hide**：shellcode APC、目标退出、allocation cleanup 分开测；DLL manual-map 在 TLS/DllMain/rollback 完成前不进入“成功”验收。memory hide 先测 query hook remove/rundown，再隔离验证 PE erase/PEB unlink，禁止和稳定性基线混测。
7. **Input/xHCI**：先 PS/2，再基础 xHCI HID；EPT read trap manager 尚未发布，不进入当前运行矩阵。
8. **GUI ABI/授权**：对每个 IOCTL 做 driver/Rust `sizeof + offset + version` 对照；授权必须验证正式网络路径、license submit、过期/断网 fail-closed 和显式 dev gate，不能以本地非空账号代替。
9. **Network rewrite**：先补配置/状态 ABI，再验证 fixed/scale/subtract/adapter-specific 模式；在此之前只能测试 hook pass-through，不应宣称流量隐藏生效。
10. **PE obfuscation**：不进入当前测试包；完成 VT shadow 设计和 rollback 后另开隔离 gate 测试。

发布判定仍需遵守：未真机验证的高风险功能可以处于源码 active/条件发布状态，但交班报告必须明确实验性和缺口；不得因暂未稳定而删除代码，也不得把 gate、宏或编译成功当作能力已完成。
