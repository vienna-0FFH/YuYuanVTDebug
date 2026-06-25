/*
 * Driver.c - Hypervisor 驱动入口
 *
 * 支持 Intel VMX 和 AMD SVM
 *
 * 功能：
 *   - 全 CPU 虚拟化
 *   - EPT/NPT 隐身 Hook
 *   - 驱动隐藏
 *   - 无痕注入
 *   - 用户态 IOCTL 通信接口
 */

#include "HvCore.h"
#include "HvCpu.h"
#include "HvUtils.h"         // OS 版本全局初始化 (DriverEntry 早期)
#include "HvHook.h"          // 统一的 Hook 抽象层（含 EPT/NPT 驱动隐藏）
// P125 (2026-06-25): HvCloak 整套 dual-EPTP 全 0 cloak 移除 (从未稳定启用,
//   HV_ENABLE_CLOAK=0 长期禁用中). 新的 PEB 字段级 spoof 见 HvPebCloak.h.
#include "HvPebCloak.h"     // PEB 字段级 EPT spoof (target 进程看 BeingDebugged=0)
#include "HvVwatch.h"       // P128: 虚拟硬件断点 (EPT-based HWBP)
#include "EptHook.h"         // EPT Hook（驱动隐藏打印函数）
#include "HvNetworkHook.h"   // 网卡流量伪造模块
#include "HvInjection.h"     // 无痕注入框架
#include "HvPhysAccess.h"    // 物理页直通访问（隐身内存 R/W/Alloc）
#include "HvVtRoot.h"        // 阶段 6: 真·VT 无痕物理 R/W (VMCALL root path)
#include "HvCr3Snoop.h"      // VMEXIT GUEST_CR3 被动嗅探 (反作弊敏感场景兜底)
#include "HvDebugger.h"      // 阶段 7: HWBP shadow + event ring
#include "HvLicense.h"       // Phase 2: 网络验证 license 内核校验
#include "HvInput.h"         // 阶段 7.10: VT 透明键鼠注入
#include "HvUsbXhci.h"       // 阶段 7.10 Layer 4: 真 VT-透明 USB HID (xHCI)
#include "HvXhciEptTrap.h"   // 阶段 7.10 Layer 4 Item 2: USBSTS/IMAN EPT read trap
#include "HvRegistryHook.h"  // 阶段 8.2: 注册表枚举隐藏
#include <ntstrsafe.h>

// P122: 全 driver DbgPrint → GUI ring
#define HV_TRACE_THIS_CAT HV_TRACE_CAT_DRIVER
#include "HvTrace.h"

// RtlRandomEx 在某些 WDK 配置下未被 ntddk.h 暴露 —— 显式声明
NTSYSAPI ULONG NTAPI RtlRandomEx(_Inout_ PULONG Seed);

// 配置选项
#define ENABLE_DRIVER_SELF_HIDE     1   // 是否启用驱动自隐藏（0=禁用，1=启用）
#define ENABLE_INJECTION_FRAMEWORK  1   // 是否启用注入框架
// 2026-05-21 BISECT #80:services.exe 启动期 0x1E (0xC0000096) RIP 在
//   NonPagedPool 跳板池中。Registry Hook 已先一步禁用,本轮再禁掉文件隐藏
//   hook(NtQueryDirectoryFile)单独验证。若仍崩则元凶在 Driver Hide
//   (NtQuerySystemInformation / ObReferenceObjectByName);若不崩则元凶
//   是 NtQueryDirectoryFile 这条 hook 本身。
#define ENABLE_FILE_HIDE_HOOK       0   // BISECT: 暂时禁用以定位跳板崩溃源

// ==================== 用户态通信接口定义 ====================

// 阶段 8.4: 设备名称由 DriverEntry 启动期随机生成 (16 字符) 写入
//   HKLM\Software\NetrSvc\DeviceName (REG_SZ),GUI 直接路径打开读取。
// 旧固定名 "\\Device\\HvControl" 已退役;开发态调试如需固定名,
// 把 HV_USE_FIXED_DEVICE_NAME 改成 1。
#define HV_USE_FIXED_DEVICE_NAME    0
#define HV_DEVICE_FIXED_LEAF        L"HvControl"
#define HV_DEVICE_LEAF_LEN          16
#define HV_DEVICE_REG_SUBKEY        L"NetrSvc"
#define HV_DEVICE_REG_PATH          L"\\Registry\\Machine\\Software\\" HV_DEVICE_REG_SUBKEY
#define HV_DEVICE_REG_VALUE         L"DeviceName"

// IOCTL 基址 (与 VTWindowsProject DriverComm.h 一致)
#define HV_IOCTL_BASE   0x800

// IOCTL 控制码 (与 VTWindowsProject 匹配)
#define IOCTL_HV_GET_STATUS             CTL_CODE(FILE_DEVICE_UNKNOWN, HV_IOCTL_BASE + 0x00, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HV_DISABLE_DSE            CTL_CODE(FILE_DEVICE_UNKNOWN, HV_IOCTL_BASE + 0x10, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HV_ENABLE_DSE             CTL_CODE(FILE_DEVICE_UNKNOWN, HV_IOCTL_BASE + 0x11, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HV_GET_DSE_STATUS         CTL_CODE(FILE_DEVICE_UNKNOWN, HV_IOCTL_BASE + 0x12, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HV_HIDE_PROCESS           CTL_CODE(FILE_DEVICE_UNKNOWN, HV_IOCTL_BASE + 0x20, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HV_UNHIDE_PROCESS         CTL_CODE(FILE_DEVICE_UNKNOWN, HV_IOCTL_BASE + 0x21, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HV_HIDE_DRIVER            CTL_CODE(FILE_DEVICE_UNKNOWN, HV_IOCTL_BASE + 0x30, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HV_UNHIDE_DRIVER          CTL_CODE(FILE_DEVICE_UNKNOWN, HV_IOCTL_BASE + 0x31, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HV_ADD_DEBUGGER           CTL_CODE(FILE_DEVICE_UNKNOWN, HV_IOCTL_BASE + 0x40, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HV_REMOVE_DEBUGGER        CTL_CODE(FILE_DEVICE_UNKNOWN, HV_IOCTL_BASE + 0x41, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HV_PROTECT_PROCESS        CTL_CODE(FILE_DEVICE_UNKNOWN, HV_IOCTL_BASE + 0x43, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HV_UNPROTECT_PROCESS      CTL_CODE(FILE_DEVICE_UNKNOWN, HV_IOCTL_BASE + 0x44, METHOD_BUFFERED, FILE_ANY_ACCESS)
// 阶段 7.9: NtOpenProcess EPT 代理 (PPL/System=4 绕过,默认 OFF,高危)
#define IOCTL_HV_ENABLE_ACCESS_BYPASS   CTL_CODE(FILE_DEVICE_UNKNOWN, HV_IOCTL_BASE + 0x4A, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HV_DISABLE_ACCESS_BYPASS  CTL_CODE(FILE_DEVICE_UNKNOWN, HV_IOCTL_BASE + 0x4B, METHOD_BUFFERED, FILE_ANY_ACCESS)
// 阶段 7.10: VT 透明键鼠注入 (PS/2 I/O bitmap + IRQ injection)
#define IOCTL_HV_INPUT_ENABLE           CTL_CODE(FILE_DEVICE_UNKNOWN, HV_IOCTL_BASE + 0x4C, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HV_INPUT_DISABLE          CTL_CODE(FILE_DEVICE_UNKNOWN, HV_IOCTL_BASE + 0x4D, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HV_INPUT_SEND_KEY         CTL_CODE(FILE_DEVICE_UNKNOWN, HV_IOCTL_BASE + 0x4E, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HV_INPUT_SEND_MOUSE       CTL_CODE(FILE_DEVICE_UNKNOWN, HV_IOCTL_BASE + 0x4F, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HV_ENABLE_ANTIANTIDEBUG   CTL_CODE(FILE_DEVICE_UNKNOWN, HV_IOCTL_BASE + 0x50, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HV_DISABLE_ANTIANTIDEBUG  CTL_CODE(FILE_DEVICE_UNKNOWN, HV_IOCTL_BASE + 0x51, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HV_INPUT_GET_STATUS       CTL_CODE(FILE_DEVICE_UNKNOWN, HV_IOCTL_BASE + 0x52, METHOD_BUFFERED, FILE_ANY_ACCESS)
// Phase 5: Layer 4 xHCI 诊断 — 输出 HV_USB_XHCI_STATUS (HvUsbXhci.h 定义)
#define IOCTL_HV_INPUT_GET_XHCI_STATUS  CTL_CODE(FILE_DEVICE_UNKNOWN, HV_IOCTL_BASE + 0x53, METHOD_BUFFERED, FILE_ANY_ACCESS)
// Phase 6: 严格 xHCI 模式开关 — input 是 1 字节 UCHAR (0 = off, 非 0 = on)
#define IOCTL_HV_INPUT_SET_STRICT_MODE  CTL_CODE(FILE_DEVICE_UNKNOWN, HV_IOCTL_BASE + 0x54, METHOD_BUFFERED, FILE_ANY_ACCESS)
// Item 2: xHCI USBSTS/IMAN EPT 读 trap 的用户层开关 (默认 OFF,显式启用)
#define IOCTL_HV_XHCI_TRAP_ENABLE       CTL_CODE(FILE_DEVICE_UNKNOWN, HV_IOCTL_BASE + 0x55, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HV_XHCI_TRAP_DISABLE      CTL_CODE(FILE_DEVICE_UNKNOWN, HV_IOCTL_BASE + 0x56, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HV_XHCI_TRAP_GET_STATS    CTL_CODE(FILE_DEVICE_UNKNOWN, HV_IOCTL_BASE + 0x57, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HV_INJECT_DLL             CTL_CODE(FILE_DEVICE_UNKNOWN, HV_IOCTL_BASE + 0x60, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HV_INJECT_SHELLCODE       CTL_CODE(FILE_DEVICE_UNKNOWN, HV_IOCTL_BASE + 0x70, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HV_MEMORY_READ            CTL_CODE(FILE_DEVICE_UNKNOWN, HV_IOCTL_BASE + 0x80, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HV_MEMORY_WRITE           CTL_CODE(FILE_DEVICE_UNKNOWN, HV_IOCTL_BASE + 0x81, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HV_MEMORY_ALLOC           CTL_CODE(FILE_DEVICE_UNKNOWN, HV_IOCTL_BASE + 0x82, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HV_MEMORY_FREE            CTL_CODE(FILE_DEVICE_UNKNOWN, HV_IOCTL_BASE + 0x83, METHOD_BUFFERED, FILE_ANY_ACCESS)
// 无痕模块枚举: input=HV_MODULE_ENUM_REQUEST, output=HV_MODULE_ENUM_RESULT (变长尾随 HV_MODULE_INFO 数组)
#define IOCTL_HV_ENUMERATE_MODULES      CTL_CODE(FILE_DEVICE_UNKNOWN, HV_IOCTL_BASE + 0x84, METHOD_BUFFERED, FILE_ANY_ACCESS)
// 变长内存 IOCTL (优化 #3): METHOD_BUFFERED 变长尾, 单次最大 HV_MEMORY_EX_MAX_PAYLOAD (64 KB)
// 比 IOCTL_HV_MEMORY_READ/WRITE 高 16× 上限, 大块读吞吐 ×1024 (摊薄 syscall + vmcall 开销)
//   READ_EX  input  = HV_MEMORY_REQUEST_EX (24B)
//            output = HV_MEMORY_RESULT_EX  (24B) + Size 字节 payload
//   WRITE_EX input  = HV_MEMORY_REQUEST_EX (24B) + Size 字节 payload
//            output = HV_MEMORY_RESULT_EX  (24B)
#define IOCTL_HV_MEMORY_READ_EX         CTL_CODE(FILE_DEVICE_UNKNOWN, HV_IOCTL_BASE + 0x85, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HV_MEMORY_WRITE_EX        CTL_CODE(FILE_DEVICE_UNKNOWN, HV_IOCTL_BASE + 0x86, METHOD_BUFFERED, FILE_ANY_ACCESS)
// 批量内存 IOCTL (优化 #1): 一次系统调用搞 N 个独立地址, 摊薄 DeviceIoControl 与
// METHOD_BUFFERED 拷贝开销。Cheat-Engine 风格多地址轮询场景吞吐 ×6。
//   BATCH_READ  input  = HV_MEMORY_BATCH_REQUEST (8B) + Items[Count] (16B 每条)
//               output = HV_MEMORY_BATCH_RESULT  (8B) + ResItems[Count] (8B 每条)
//                                                    + 紧贴 payload (≤ 64 KB)
//   BATCH_WRITE input  = HV_MEMORY_BATCH_REQUEST + Items[Count] + 紧贴 payload
//               output = HV_MEMORY_BATCH_RESULT  + ResItems[Count]
#define IOCTL_HV_MEMORY_BATCH_READ      CTL_CODE(FILE_DEVICE_UNKNOWN, HV_IOCTL_BASE + 0x87, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HV_MEMORY_BATCH_WRITE     CTL_CODE(FILE_DEVICE_UNKNOWN, HV_IOCTL_BASE + 0x88, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HV_GET_NESTED_STATUS      CTL_CODE(FILE_DEVICE_UNKNOWN, HV_IOCTL_BASE + 0xA0, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HV_GET_NESTED_EVENTS      CTL_CODE(FILE_DEVICE_UNKNOWN, HV_IOCTL_BASE + 0xA1, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HV_CLEAR_NESTED_EVENTS    CTL_CODE(FILE_DEVICE_UNKNOWN, HV_IOCTL_BASE + 0xA2, METHOD_BUFFERED, FILE_ANY_ACCESS)

// ==================== 阶段 7 调试器赋能 IOCTL (0x60-0x65) ====================
// 注:0x60 已被 IOCTL_HV_INJECT_DLL 使用,这里改用 0x100+ 段避开冲突
#define IOCTL_HV_DBG_SET_HWBP           CTL_CODE(FILE_DEVICE_UNKNOWN, HV_IOCTL_BASE + 0x100, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HV_DBG_CLEAR_HWBP         CTL_CODE(FILE_DEVICE_UNKNOWN, HV_IOCTL_BASE + 0x101, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HV_DBG_WAIT_EVENT         CTL_CODE(FILE_DEVICE_UNKNOWN, HV_IOCTL_BASE + 0x102, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HV_DBG_CONTINUE           CTL_CODE(FILE_DEVICE_UNKNOWN, HV_IOCTL_BASE + 0x103, METHOD_BUFFERED, FILE_ANY_ACCESS)
// P50 software breakpoint registry — R3 已写 0xCC,这里只登记 (target,rip)→debugger 用于 #BP vmexit 反查
#define IOCTL_HV_DBG_SW_BP_ADD          CTL_CODE(FILE_DEVICE_UNKNOWN, HV_IOCTL_BASE + 0x108, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HV_DBG_SW_BP_DEL          CTL_CODE(FILE_DEVICE_UNKNOWN, HV_IOCTL_BASE + 0x109, METHOD_BUFFERED, FILE_ANY_ACCESS)
// P51 单步 — R3 用 SetThreadContext 设 EFLAGS.TF=1+resume,这里登记 tid 让 #DB(BS) 命中时能识别为我们的步进
#define IOCTL_HV_DBG_STEP_ARM           CTL_CODE(FILE_DEVICE_UNKNOWN, HV_IOCTL_BASE + 0x10A, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HV_KERNEL_READ            CTL_CODE(FILE_DEVICE_UNKNOWN, HV_IOCTL_BASE + 0x104, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HV_KERNEL_WRITE           CTL_CODE(FILE_DEVICE_UNKNOWN, HV_IOCTL_BASE + 0x105, METHOD_BUFFERED, FILE_ANY_ACCESS)
// Phase G: 根因事件 ring buffer 拉取 —— GUI 1s 轮询,显示到日志面板
#define IOCTL_HV_GET_DBGEVT             CTL_CODE(FILE_DEVICE_UNKNOWN, HV_IOCTL_BASE + 0x106, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Phase 2 (2026-06-20): 网络验证 license 提交 (driver 内核态 ed25519 验签)
// GUI 拿到 yuyuan token + auth_sig 后,通过这个 IOCTL 提交给 driver。
// 验签通过前, 所有业务 IOCTL 直接返 STATUS_ACCESS_DENIED。
#define IOCTL_HV_SUBMIT_LICENSE         CTL_CODE(FILE_DEVICE_UNKNOWN, HV_IOCTL_BASE + 0x107, METHOD_BUFFERED, FILE_ANY_ACCESS)

// 2026-06-16: 0x1AA 诊断快照 (用户态崩前读, 实机无 dmesg/无 dump 兜底)
// 见 HvUtils.h HV_DIAG_SNAPSHOT 结构。
#define IOCTL_HV_GET_DIAG_SNAPSHOT      CTL_CODE(FILE_DEVICE_UNKNOWN, HV_IOCTL_BASE + 0xB0, METHOD_BUFFERED, FILE_ANY_ACCESS)

// ==================== 通信数据结构 (与 VTWindowsProject 匹配) ====================
// 状态码
typedef enum _HV_STATUS_CODE {
    HV_STATUS_SUCCESS = 0,
    HV_STATUS_ERROR = 1,
    HV_STATUS_NOT_INITIALIZED = 2,
    HV_STATUS_INVALID_PARAMETER = 3,
    HV_STATUS_NOT_FOUND = 4,
    HV_STATUS_ALREADY_EXISTS = 5,
    HV_STATUS_ACCESS_DENIED = 6,
    HV_STATUS_INSUFFICIENT_BUFFER = 7,
} HV_STATUS_CODE;

#pragma pack(push, 1)

// 驱动状态
typedef struct _HV_STATUS_INFO {
    ULONG       Version;
    BOOLEAN     HypervisorActive;
    BOOLEAN     HookManagerInitialized;
    BOOLEAN     DseDisabled;
    BOOLEAN     AntiAntiDebugEnabled;
    ULONG       HiddenProcessCount;
    ULONG       HiddenDriverCount;
    ULONG       ProtectedDebuggerCount;
    ULONG       ProtectedProcessCount;
    ULONG       CpuVendor;
    ULONG       ProcessorCount;
    // ---- Phase F (2026-06-03): hook 链路就绪状态,排查"启动并保护没生效"的关键指示 ----
    // 末尾追加,旧 GUI 客户端读到原长度不受影响。Version 不需要 bump,字段不被旧
    // 客户端读取就是 0。GUI 新版按 sizeof(HV_STATUS_INFO) 请求,拿到完整结构。
    BOOLEAN     VtRootEnabled;          // HvPhysReadProcessMemory 等物理直通的前提
    BOOLEAN     DebuggerProxyEnabled;   // NtSetContextThread + Nt[R/W]VirtualMemory hook 装载
    BOOLEAN     AccessBypassEnabled;    // NtOpenProcess hook 装载 (PPL/System 绕过)
} HV_STATUS_INFO, *PHV_STATUS_INFO;

// DSE 状态
typedef struct _HV_DSE_STATUS {
    BOOLEAN     DseEnabled;
    ULONG       CiOptionsValue;
    UINT64      CiOptionsAddress;
} HV_DSE_STATUS, *PHV_DSE_STATUS;

// Phase G: 根因事件拉取请求/响应
#pragma pack(push, 8)
typedef struct _HV_DBGEVT_PULL_REQ {
    UINT64  SinceSequence;   // 0 = 拉取全部存活事件
    ULONG   MaxCount;        // 推荐 64,上限 256
    ULONG   _pad;
} HV_DBGEVT_PULL_REQ, *PHV_DBGEVT_PULL_REQ;

typedef struct _HV_DBGEVT_PULL_RES {
    ULONG   Count;           // 实际写入的事件数
    ULONG   _pad;
    UINT64  NextSequence;    // ring 中最新事件的 Sequence (客户端下次传入)
    // 紧跟 HV_DBGEVT Items[Count]
} HV_DBGEVT_PULL_RES, *PHV_DBGEVT_PULL_RES;
#pragma pack(pop)

// 进程请求
typedef struct _HV_PROCESS_REQUEST {
    ULONG       ProcessId;
    WCHAR       ProcessName[260];
} HV_PROCESS_REQUEST, *PHV_PROCESS_REQUEST;

// 驱动请求
typedef struct _HV_DRIVER_REQUEST {
    WCHAR       DriverName[260];
} HV_DRIVER_REQUEST, *PHV_DRIVER_REQUEST;

// 内存请求
typedef struct _HV_MEMORY_REQUEST {
    ULONG       ProcessId;
    UINT64      Address;
    ULONG       Size;
    ULONG       Protection;
    UCHAR       Buffer[4096];
} HV_MEMORY_REQUEST, *PHV_MEMORY_REQUEST;

// 内存结果
typedef struct _HV_MEMORY_RESULT {
    HV_STATUS_CODE  Status;
    UINT64          Address;
    ULONG           BytesTransferred;
    UCHAR           Buffer[4096];
} HV_MEMORY_RESULT, *PHV_MEMORY_RESULT;

// ---- 变长内存 R/W (优化 #3, METHOD_BUFFERED 变长尾) ----
// payload 紧贴 header, payload 字节数由 inputLength/outputLength - sizeof(header) 决出。
// 单次上限 64 KB, 平衡 SystemBuffer 分配压力与吞吐:
//   - 4KB 时单次 syscall + vmexit 摊给 4KB 数据,bandwidth ~ 100 MB/s
//   - 64KB 时单次 syscall + 16 个 vmcall 摊给 64KB 数据,bandwidth ~ 1.6 GB/s (×16)
#define HV_MEMORY_EX_MAX_PAYLOAD   0x10000  // 64 KB

typedef struct _HV_MEMORY_REQUEST_EX {
    ULONG       ProcessId;
    ULONG       Reserved0;   // 显式 padding 让 Address 8-byte 对齐
    UINT64      Address;
    ULONG       Size;        // 实际 payload 字节数 (≤ HV_MEMORY_EX_MAX_PAYLOAD)
    ULONG       Reserved1;
    // WRITE_EX: 后接 Size 字节 payload
    // READ_EX:  无后续 payload
} HV_MEMORY_REQUEST_EX, *PHV_MEMORY_REQUEST_EX;

typedef struct _HV_MEMORY_RESULT_EX {
    HV_STATUS_CODE  Status;
    ULONG           Reserved0;
    UINT64          Address;
    ULONG           BytesTransferred;
    ULONG           Reserved1;
    // READ_EX:  后接 BytesTransferred 字节 payload
    // WRITE_EX: 无后续 payload
} HV_MEMORY_RESULT_EX, *PHV_MEMORY_RESULT_EX;

// ---- 批量 R/W (优化 #1) ----
//
// 上限设计:
//   HV_BATCH_MAX_ITEMS    = 256    Items[] 数组总大小 = 4KB, 仍可栈拷
//   HV_BATCH_MAX_PAYLOAD  = 64 KB  与 EX 路径一致, METHOD_BUFFERED 总 buffer ≤ ~80 KB
//
// PayloadOffset 由调用方填, 指 payload 段开头(不含 header / items / results)的字节偏移。
// 驱动只做"payloadOffset + Size 是否落在 payload 段内"边界检查, 不做去重 / 排序。
//
// 单项失败不中止 batch:Driver.c 逐项调 HvMemoryRead/Write, 失败把 NTSTATUS 写
// ResItems[i].Status, 继续下一个。TopStatus 只反映 "整批参数是否合法 (Count 越界 /
// payload 总和超限)"; 单项错由 ResItems[i].Status 携带。

#define HV_BATCH_MAX_ITEMS     256
#define HV_BATCH_MAX_PAYLOAD   0x10000   // 64 KB, 与 EX 一致

typedef struct _HV_MEMORY_BATCH_ITEM {
    UINT64 Address;
    ULONG  Size;            // 该项 payload 字节数
    ULONG  PayloadOffset;   // 在 payload 段中的字节偏移 (相对 payload 段开头)
} HV_MEMORY_BATCH_ITEM, *PHV_MEMORY_BATCH_ITEM;

typedef struct _HV_MEMORY_BATCH_RES_ITEM {
    HV_STATUS_CODE Status;
    ULONG          BytesTransferred;
} HV_MEMORY_BATCH_RES_ITEM, *PHV_MEMORY_BATCH_RES_ITEM;

typedef struct _HV_MEMORY_BATCH_REQUEST {
    ULONG ProcessId;
    ULONG Count;
    // 后接: HV_MEMORY_BATCH_ITEM Items[Count]
    // 后接 (仅 WRITE): UCHAR Payload[totalSize]
} HV_MEMORY_BATCH_REQUEST, *PHV_MEMORY_BATCH_REQUEST;

typedef struct _HV_MEMORY_BATCH_RESULT {
    HV_STATUS_CODE TopStatus;   // 0 = 调度成功 (单项错见 ResItems[i].Status)
    ULONG          Count;       // 实际处理项数 (≤ Request.Count)
    // 后接: HV_MEMORY_BATCH_RES_ITEM ResItems[Count]
    // 后接 (仅 READ): UCHAR Payload[totalSize]
} HV_MEMORY_BATCH_RESULT, *PHV_MEMORY_BATCH_RESULT;

// 模块枚举请求 (IOCTL_HV_ENUMERATE_MODULES)
typedef struct _HV_MODULE_ENUM_REQUEST {
    ULONG ProcessId;
    ULONG MaxModules;     // GUI 期望的最大返回条数, 实际由 outputBuffer 大小再限制一次
} HV_MODULE_ENUM_REQUEST, *PHV_MODULE_ENUM_REQUEST;

// 模块枚举结果: 定长头 + 变长 Modules[Count]
// 调用方应分配: sizeof(HV_MODULE_ENUM_RESULT) + MaxModules*sizeof(HV_MODULE_INFO)
typedef struct _HV_MODULE_ENUM_RESULT {
    HV_STATUS_CODE Status;
    ULONG          Count;
    // 后接 HV_MODULE_INFO Modules[Count] (METHOD_BUFFERED, 来自 HvPhysAccess.h)
} HV_MODULE_ENUM_RESULT, *PHV_MODULE_ENUM_RESULT;

// DLL 注入请求
typedef struct _HV_INJECT_DLL_REQUEST {
    ULONG       TargetPid;
    WCHAR       DllPath[520];
    BOOLEAN     HideFromPeb;
    BOOLEAN     ErasePeHeader;
    BOOLEAN     UseManualMap;
    ULONG       StealthLevel;
} HV_INJECT_DLL_REQUEST, *PHV_INJECT_DLL_REQUEST;

// DLL 注入结果
typedef struct _HV_INJECT_DLL_RESULT {
    HV_STATUS_CODE  Status;
    UINT64          ModuleBase;
    ULONG           ModuleSize;
} HV_INJECT_DLL_RESULT, *PHV_INJECT_DLL_RESULT;

// Shellcode 注入请求
typedef struct _HV_INJECT_SHELLCODE_REQUEST {
    ULONG       TargetPid;
    ULONG       ShellcodeSize;
    UINT64      Parameter;
    BOOLEAN     ExecuteImmediately;
    BOOLEAN     HideMemory;
    UCHAR       Shellcode[4096];
} HV_INJECT_SHELLCODE_REQUEST, *PHV_INJECT_SHELLCODE_REQUEST;

// Shellcode 注入结果
typedef struct _HV_INJECT_SHELLCODE_RESULT {
    HV_STATUS_CODE  Status;
    UINT64          ShellcodeAddress;
} HV_INJECT_SHELLCODE_RESULT, *PHV_INJECT_SHELLCODE_RESULT;

// 调试器请求
typedef struct _HV_DEBUGGER_REQUEST {
    ULONG       ProcessId;
    WCHAR       ProcessName[260];
    BOOLEAN     EnablePrivilege;
    BOOLEAN     ProtectFromTerminate;
    BOOLEAN     HideFromList;
} HV_DEBUGGER_REQUEST, *PHV_DEBUGGER_REQUEST;

// 进程保护请求
typedef struct _HV_PROTECT_REQUEST {
    ULONG       ProcessId;
    WCHAR       ProcessName[260];
    ULONG       DebuggerPid;
} HV_PROTECT_REQUEST, *PHV_PROTECT_REQUEST;

// 反反调试请求
typedef struct _HV_ANTIANTIDEBUG_REQUEST {
    ULONG       TargetPid;
    BOOLEAN     Enable;
    BOOLEAN     HookNtQueryInformationProcess;
    BOOLEAN     HookNtQuerySystemInformation;
    BOOLEAN     HookNtSetInformationThread;
    BOOLEAN     HookNtClose;
    BOOLEAN     HookNtQueryObject;
} HV_ANTIANTIDEBUG_REQUEST, *PHV_ANTIANTIDEBUG_REQUEST;

// 嵌套虚拟化状态
typedef struct _HV_NESTED_STATUS {
    BOOLEAN     NestedVmxSupported;     // 是否支持嵌套 VMX
    BOOLEAN     NestedSvmSupported;     // 是否支持嵌套 SVM
    BOOLEAN     L1VmxEnabled;           // L1 是否已启用 VMX
    BOOLEAN     L2Running;              // L2 是否正在运行
    ULONG       ActiveCpuCount;         // 启用嵌套的 CPU 数量
    UINT64      TotalVmxonCount;        // 总 VMXON 次数
    UINT64      TotalVmlaunchCount;     // 总 VMLAUNCH 次数
    UINT64      TotalVmresumeCount;     // 总 VMRESUME 次数
    UINT64      TotalL2ExitCount;       // 总 L2 VM Exit 次数
    UINT64      TotalErrorCount;        // 总错误次数
    UINT64      CurrentVmcsGpa;         // 当前 VMCS GPA
    UINT64      VmxonRegionGpa;         // VMXON Region GPA
    UINT64      LastGvaToGpaError;
    UINT64      LastFailedGva;
    UINT64      LastGuestCr3;
    ULONG       LastIrql;
    UINT64      LastVmcs12ValidationError;
} HV_NESTED_STATUS, *PHV_NESTED_STATUS;

// ==================== 阶段 7 调试器赋能 数据结构 ====================

// 内核任意地址读写请求 (固定 4KB buffer,与现有 MEMORY 风格保持一致)
#define HV_KERNEL_MEM_BUF_SIZE   4096

typedef struct _HV_KERNEL_MEM_REQUEST {
    UINT64      Address;                        // 内核 VA
    ULONG       Size;                           // 实际读写字节数 (<=4096)
    ULONG       Reserved;
    UCHAR       Buffer[HV_KERNEL_MEM_BUF_SIZE]; // 写时:输入;读时:忽略
} HV_KERNEL_MEM_REQUEST, *PHV_KERNEL_MEM_REQUEST;

typedef struct _HV_KERNEL_MEM_RESULT {
    HV_STATUS_CODE  Status;
    UINT64          Address;
    ULONG           BytesTransferred;
    ULONG           Reserved;
    UCHAR           Buffer[HV_KERNEL_MEM_BUF_SIZE];
} HV_KERNEL_MEM_RESULT, *PHV_KERNEL_MEM_RESULT;

// HWBP 请求 (SET_HWBP / CLEAR_HWBP 共用; CLEAR 仅看 TargetPid + SlotIndex)
typedef struct _HV_HWBP_REQUEST {
    ULONG       DebuggerPid;
    ULONG       TargetPid;
    ULONG       SlotIndex;     // 0-3
    ULONG       Reserved0;
    UINT64      Address;
    UCHAR       Length;        // 1/2/4/8
    UCHAR       Type;          // HV_HWBP_TYPE_*
    UCHAR       Reserved1[6];
} HV_HWBP_REQUEST, *PHV_HWBP_REQUEST;

// 调试事件等待请求
typedef struct _HV_DBG_WAIT_REQUEST {
    ULONG       DebuggerPid;
    ULONG       TimeoutMs;     // 0 = 不阻塞, MAXULONG = INFINITE
} HV_DBG_WAIT_REQUEST, *PHV_DBG_WAIT_REQUEST;

// 调试事件等待结果
typedef struct _HV_DBG_WAIT_RESULT {
    HV_STATUS_CODE  Status;
    ULONG           Reserved;
    HV_DEBUG_EVENT  Event;
} HV_DBG_WAIT_RESULT, *PHV_DBG_WAIT_RESULT;

// 调试事件继续请求 (V1 仅做 ack)
typedef struct _HV_DBG_CONTINUE_REQUEST {
    ULONG       DebuggerPid;
    ULONG       Reserved;
    UINT64      Sequence;      // 事件序号
} HV_DBG_CONTINUE_REQUEST, *PHV_DBG_CONTINUE_REQUEST;

// HWBP 通用结果
typedef struct _HV_DBG_RESULT {
    HV_STATUS_CODE  Status;
    ULONG           Reserved;
    UINT64          Info;      // 可选附加信息
} HV_DBG_RESULT, *PHV_DBG_RESULT;

#pragma pack(pop)

// ==================== 全局变量 ====================

static PDEVICE_OBJECT g_DeviceObject = NULL;
static UNICODE_STRING g_DeviceName;
static UNICODE_STRING g_SymbolicLink;
static BOOLEAN g_DeviceCreated = FALSE;

// 阶段 8.4: 启动期随机生成的设备名片段(16 字符 + NUL)
static WCHAR g_DeviceLeafBuf[HV_DEVICE_LEAF_LEN + 1] = { 0 };
static WCHAR g_DeviceFullBuf[64]   = { 0 };  // "\Device\<leaf>"
static WCHAR g_SymlinkFullBuf[64]  = { 0 };  // "\??\<leaf>"

// ==================== IRP 派发函数 ====================

/*
 * IRP 派发函数 - 创建/关闭
 */
static NTSTATUS NetrDispatchCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

/*
 * IRP 派发函数 - DeviceIoControl (与 VTWindowsProject 匹配)
 */
static NTSTATUS NetrDispatchDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    ULONG controlCode = irpSp->Parameters.DeviceIoControl.IoControlCode;
    PVOID inputBuffer = Irp->AssociatedIrp.SystemBuffer;
    PVOID outputBuffer = Irp->AssociatedIrp.SystemBuffer;
    ULONG inputLength = irpSp->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outputLength = irpSp->Parameters.DeviceIoControl.OutputBufferLength;

    NTSTATUS status = STATUS_SUCCESS;
    ULONG bytesReturned = 0;

#if HV_MINIMAL_MODE
    // 空壳模式: 所有功能 IOCTL 直接拒绝, 避免调用未初始化的子系统
    UNREFERENCED_PARAMETER(inputBuffer);
    UNREFERENCED_PARAMETER(outputBuffer);
    UNREFERENCED_PARAMETER(inputLength);
    UNREFERENCED_PARAMETER(outputLength);
    UNREFERENCED_PARAMETER(controlCode);
    Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_NOT_SUPPORTED;
#else

    DbgPrint("[HV] IOCTL received: 0x%X\n", controlCode);

    // Phase 2: license gate
    // 例外白名单:GET_STATUS 与 SUBMIT_LICENSE 必须永远可调
    //   - GET_STATUS 用于 GUI 探测驱动 alive
    //   - SUBMIT_LICENSE 本身就是为了"开锁"
    if (controlCode != IOCTL_HV_GET_STATUS &&
        controlCode != IOCTL_HV_SUBMIT_LICENSE &&
        !HvLicenseIsValid())
    {
        DbgPrint("[HV] IOCTL 0x%X rejected: license not submitted\n", controlCode);
        Irp->IoStatus.Status = STATUS_ACCESS_DENIED;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_ACCESS_DENIED;
    }

    switch (controlCode) {

    // ==================== Phase 2: 网络验证 license 提交 ====================
    case IOCTL_HV_SUBMIT_LICENSE:
        status = HvLicenseSubmit(inputBuffer, inputLength);
        if (NT_SUCCESS(status) && outputLength >= sizeof(NTSTATUS)) {
            *(NTSTATUS*)outputBuffer = STATUS_SUCCESS;
            bytesReturned = sizeof(NTSTATUS);
        }
        break;

    // ==================== 获取状态 ====================
    case IOCTL_HV_GET_STATUS:
        if (outputLength >= sizeof(HV_STATUS_INFO)) {
            PHV_STATUS_INFO pStatus = (PHV_STATUS_INFO)outputBuffer;
            RtlZeroMemory(pStatus, sizeof(HV_STATUS_INFO));
            
            BOOLEAN dseEnabled = TRUE;
            HvDseGetStatus(&dseEnabled, NULL, NULL);
            
            pStatus->Version = 0x00010000;
            pStatus->HypervisorActive = HvIsHypervisorRunning();
            pStatus->HookManagerInitialized = HvHookIsInitialized();
            pStatus->DseDisabled = !dseEnabled;
            pStatus->AntiAntiDebugEnabled = HvHookIsAntiAntiDebugEnabled();
            pStatus->HiddenProcessCount = 0;  // TODO: 实现计数
            pStatus->HiddenDriverCount = 0;   // TODO: 实现计数
            pStatus->ProtectedDebuggerCount = HvHookGetDebuggerCount();
            pStatus->ProtectedProcessCount = HvHookGetProtectedProcessCount();
            pStatus->CpuVendor = (ULONG)HvGetCpuVendor();
            pStatus->ProcessorCount = g_HypervisorContext.ProcessorCount;
            // hook 链路就绪状态 (Phase F)
            pStatus->VtRootEnabled        = g_VtRootEnabled;
            pStatus->DebuggerProxyEnabled = HvHookIsDebuggerProxyEnabled();
            pStatus->AccessBypassEnabled  = HvHookIsAccessBypassEnabled();

            bytesReturned = sizeof(HV_STATUS_INFO);
            DbgPrint("[HV] GET_STATUS: Active=%d, CPUs=%d, AAD=%d, Debuggers=%d, "
                     "VtRoot=%d, Proxy=%d, Bypass=%d\n",
                pStatus->HypervisorActive, pStatus->ProcessorCount,
                pStatus->AntiAntiDebugEnabled, pStatus->ProtectedDebuggerCount,
                pStatus->VtRootEnabled, pStatus->DebuggerProxyEnabled,
                pStatus->AccessBypassEnabled);
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;
    
    // ==================== DSE 控制 (暂不支持) ====================
    case IOCTL_HV_DISABLE_DSE:
        DbgPrint("[HV] DISABLE_DSE\n");
        status = HvDseDisable();
        if (NT_SUCCESS(status)) {
            DbgPrint("[HV] DSE disabled successfully\n");
        } else {
            DbgPrint("[HV] Failed to disable DSE: 0x%X\n", status);
        }
        break;
    
    case IOCTL_HV_ENABLE_DSE:
        DbgPrint("[HV] ENABLE_DSE\n");
        status = HvDseEnable();
        if (NT_SUCCESS(status)) {
            DbgPrint("[HV] DSE enabled successfully\n");
        } else {
            DbgPrint("[HV] Failed to enable DSE: 0x%X\n", status);
        }
        break;
    
    case IOCTL_HV_GET_DSE_STATUS:
        if (outputLength >= sizeof(HV_DSE_STATUS)) {
            PHV_DSE_STATUS pDse = (PHV_DSE_STATUS)outputBuffer;
            RtlZeroMemory(pDse, sizeof(HV_DSE_STATUS));
            
            BOOLEAN dseEnabled;
            ULONG ciOptions = 0;
            UINT64 ciAddress = 0;
            
            status = HvDseGetStatus(&dseEnabled, &ciOptions, &ciAddress);
            if (NT_SUCCESS(status)) {
                pDse->DseEnabled = dseEnabled;
                pDse->CiOptionsValue = ciOptions;
                pDse->CiOptionsAddress = ciAddress;
            } else {
                // 如果获取失败，返回默认值
                pDse->DseEnabled = TRUE;
            }
            
            bytesReturned = sizeof(HV_DSE_STATUS);
            DbgPrint("[HV] GET_DSE_STATUS: Enabled=%d, CiOptions=0x%X\n", 
                pDse->DseEnabled, pDse->CiOptionsValue);
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;
    
    // ==================== 进程隐藏 ====================
    case IOCTL_HV_HIDE_PROCESS:
        if (inputLength >= sizeof(HV_PROCESS_REQUEST)) {
            PHV_PROCESS_REQUEST pReq = (PHV_PROCESS_REQUEST)inputBuffer;
            
            if (pReq->ProcessId != 0) {
                DbgPrint("[HV] HIDE_PROCESS by PID: %d\n", pReq->ProcessId);
                status = HvHookHideProcess(pReq->ProcessId);
            } else if (pReq->ProcessName[0] != L'\0') {
                DbgPrint("[HV] HIDE_PROCESS by Name: %ws\n", pReq->ProcessName);
                status = HvHookHideProcessByName(pReq->ProcessName);
            } else {
                status = STATUS_INVALID_PARAMETER;
            }
        } else {
            status = STATUS_INVALID_PARAMETER;
        }
        break;
    
    case IOCTL_HV_UNHIDE_PROCESS:
        if (inputLength >= sizeof(HV_PROCESS_REQUEST)) {
            PHV_PROCESS_REQUEST pReq = (PHV_PROCESS_REQUEST)inputBuffer;
            
            if (pReq->ProcessId != 0) {
                DbgPrint("[HV] UNHIDE_PROCESS by PID: %d\n", pReq->ProcessId);
                status = HvHookUnhideProcess(pReq->ProcessId);
            } else if (pReq->ProcessName[0] != L'\0') {
                DbgPrint("[HV] UNHIDE_PROCESS by Name: %ws\n", pReq->ProcessName);
                status = HvHookUnhideProcessByName(pReq->ProcessName);
            } else {
                status = STATUS_INVALID_PARAMETER;
            }
        } else {
            status = STATUS_INVALID_PARAMETER;
        }
        break;
    
    // ==================== 驱动隐藏 ====================
    case IOCTL_HV_HIDE_DRIVER:
        if (inputLength >= sizeof(HV_DRIVER_REQUEST)) {
            PHV_DRIVER_REQUEST pReq = (PHV_DRIVER_REQUEST)inputBuffer;
            DbgPrint("[HV] HIDE_DRIVER: %ws\n", pReq->DriverName);
            // 使用安全的驱动隐藏方式（通过 EPT/NPT Hook）
            status = HvHookHideDriverByNameSafe(pReq->DriverName);
            if (NT_SUCCESS(status)) {
                DbgPrint("[HV] Driver hidden successfully: %ws\n", pReq->DriverName);
            } else {
                DbgPrint("[HV] Failed to hide driver: 0x%X\n", status);
            }
        } else {
            status = STATUS_INVALID_PARAMETER;
        }
        break;
    
    case IOCTL_HV_UNHIDE_DRIVER:
        if (inputLength >= sizeof(HV_DRIVER_REQUEST)) {
            PHV_DRIVER_REQUEST pReq = (PHV_DRIVER_REQUEST)inputBuffer;
            DbgPrint("[HV] UNHIDE_DRIVER: %ws\n", pReq->DriverName);
            status = HvHookUnhideDriverFile(pReq->DriverName);
            if (NT_SUCCESS(status)) {
                DbgPrint("[HV] Driver unhidden successfully: %ws\n", pReq->DriverName);
            } else {
                DbgPrint("[HV] Failed to unhide driver: 0x%X\n", status);
            }
        } else {
            status = STATUS_INVALID_PARAMETER;
        }
        break;
    
    // ==================== 调试器保护 ====================
    case IOCTL_HV_ADD_DEBUGGER:
        if (inputLength >= sizeof(HV_DEBUGGER_REQUEST)) {
            PHV_DEBUGGER_REQUEST pReq = (PHV_DEBUGGER_REQUEST)inputBuffer;
            HV_DEBUGGER_CONFIG config = { 0 };
            
            config.ProcessId = pReq->ProcessId;
            if (pReq->ProcessName[0] != L'\0') {
                // RtlStringCbCopyNW：始终 NUL 终止，并以源/目标字节长度截断，
                // 避免用户态发来无 NUL 的 260 字节 ProcessName 撑爆下游字符串处理
                RtlStringCbCopyNW(config.ProcessName,
                                  sizeof(config.ProcessName),
                                  pReq->ProcessName,
                                  sizeof(pReq->ProcessName));
            }
            config.EnablePrivilege = pReq->EnablePrivilege;
            config.ProtectFromTerminate = pReq->ProtectFromTerminate;
            config.HideFromList = pReq->HideFromList;
            
            DbgPrint("[HV] ADD_DEBUGGER: PID=%d, Hide=%d\n", 
                pReq->ProcessId, pReq->HideFromList);
            
            status = HvHookAddDebugger(&config);
            if (NT_SUCCESS(status)) {
                DbgPrint("[HV] Debugger added successfully\n");
            } else {
                DbgPrint("[HV] Failed to add debugger: 0x%X\n", status);
            }
        } else {
            status = STATUS_INVALID_PARAMETER;
        }
        break;
    
    case IOCTL_HV_REMOVE_DEBUGGER:
        if (inputLength >= sizeof(HV_DEBUGGER_REQUEST)) {
            PHV_DEBUGGER_REQUEST pReq = (PHV_DEBUGGER_REQUEST)inputBuffer;
            
            DbgPrint("[HV] REMOVE_DEBUGGER: PID=%d\n", pReq->ProcessId);
            
            status = HvHookRemoveDebugger(pReq->ProcessId);
            if (NT_SUCCESS(status)) {
                DbgPrint("[HV] Debugger removed successfully\n");
            } else {
                DbgPrint("[HV] Failed to remove debugger: 0x%X\n", status);
            }
        } else {
            status = STATUS_INVALID_PARAMETER;
        }
        break;
    
    case IOCTL_HV_PROTECT_PROCESS:
        if (inputLength >= sizeof(HV_PROTECT_REQUEST)) {
            PHV_PROTECT_REQUEST pReq = (PHV_PROTECT_REQUEST)inputBuffer;
            HV_PROTECT_CONFIG config = { 0 };
            
            config.ProcessId = pReq->ProcessId;
            if (pReq->ProcessName[0] != L'\0') {
                RtlStringCbCopyNW(config.ProcessName,
                                  sizeof(config.ProcessName),
                                  pReq->ProcessName,
                                  sizeof(pReq->ProcessName));
            }
            config.DebuggerPid = pReq->DebuggerPid;
            config.PreventTerminate = TRUE;
            config.PreventSuspend = TRUE;
            config.PreventMemoryAccess = TRUE;
            
            DbgPrint("[HV] PROTECT_PROCESS: PID=%d, DebuggerPID=%d\n", 
                pReq->ProcessId, pReq->DebuggerPid);
            
            status = HvHookProtectProcess(&config);
            if (NT_SUCCESS(status)) {
                DbgPrint("[HV] Process protected successfully\n");
            } else {
                DbgPrint("[HV] Failed to protect process: 0x%X\n", status);
            }
        } else {
            status = STATUS_INVALID_PARAMETER;
        }
        break;
    
    case IOCTL_HV_UNPROTECT_PROCESS:
        if (inputLength >= sizeof(HV_PROTECT_REQUEST)) {
            PHV_PROTECT_REQUEST pReq = (PHV_PROTECT_REQUEST)inputBuffer;

            DbgPrint("[HV] UNPROTECT_PROCESS: PID=%d\n", pReq->ProcessId);

            status = HvHookUnprotectProcess(pReq->ProcessId);
            if (NT_SUCCESS(status)) {
                DbgPrint("[HV] Process unprotected successfully\n");
            } else {
                DbgPrint("[HV] Failed to unprotect process: 0x%X\n", status);
            }
        } else {
            status = STATUS_INVALID_PARAMETER;
        }
        break;

    // ==================== 阶段 7.9: NtOpenProcess 访问绕过 ====================
    case IOCTL_HV_ENABLE_ACCESS_BYPASS:
        status = HvHookEnableAccessBypass();
        if (NT_SUCCESS(status)) {
            DbgPrint("[HV] Access bypass enabled\n");
        } else {
            DbgPrint("[HV] Failed to enable access bypass: 0x%X\n", status);
        }
        break;

    case IOCTL_HV_DISABLE_ACCESS_BYPASS:
        HvHookDisableAccessBypass();
        status = STATUS_SUCCESS;
        DbgPrint("[HV] Access bypass disabled\n");
        break;

    // ==================== 阶段 7.10: VT 透明键鼠注入 ====================
    case IOCTL_HV_INPUT_ENABLE:
        status = HvInputEnable();
        if (NT_SUCCESS(status)) {
            DbgPrint("[HV] Input injection enabled\n");
        } else {
            DbgPrint("[HV] HvInputEnable failed 0x%X\n", status);
        }
        break;

    case IOCTL_HV_INPUT_DISABLE:
        HvInputDisable();
        status = STATUS_SUCCESS;
        DbgPrint("[HV] Input injection disabled\n");
        break;

    case IOCTL_HV_INPUT_SEND_KEY:
        if (inputLength < sizeof(HV_INPUT_KEY_REQUEST) || !inputBuffer) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        {
            PHV_INPUT_KEY_REQUEST pReq = (PHV_INPUT_KEY_REQUEST)inputBuffer;
            status = HvInputSendKey(pReq->Scancode,
                                    (BOOLEAN)pReq->IsExtended,
                                    (BOOLEAN)pReq->IsBreak,
                                    (BOOLEAN)pReq->AutoBreak);
        }
        break;

    case IOCTL_HV_INPUT_SEND_MOUSE:
        if (inputLength < sizeof(HV_INPUT_MOUSE_REQUEST) || !inputBuffer) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        {
            PHV_INPUT_MOUSE_REQUEST pReq = (PHV_INPUT_MOUSE_REQUEST)inputBuffer;
            status = HvInputSendMouse(pReq->Dx, pReq->Dy,
                                      pReq->Buttons,
                                      (BOOLEAN)pReq->Smooth);
        }
        break;

    case IOCTL_HV_INPUT_GET_STATUS:
        if (outputLength < sizeof(HV_INPUT_STATUS) || !outputBuffer) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        HvInputQueryStatus((PHV_INPUT_STATUS)outputBuffer);
        bytesReturned = sizeof(HV_INPUT_STATUS);
        status = STATUS_SUCCESS;
        break;

    case IOCTL_HV_INPUT_GET_XHCI_STATUS:
        if (outputLength < sizeof(HV_USB_XHCI_STATUS) || !outputBuffer) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        HvUsbXhciQueryStatus((PHV_USB_XHCI_STATUS)outputBuffer);
        bytesReturned = sizeof(HV_USB_XHCI_STATUS);
        status = STATUS_SUCCESS;
        break;

    case IOCTL_HV_INPUT_SET_STRICT_MODE:
        if (inputLength < sizeof(UCHAR) || !inputBuffer) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        {
            UCHAR strict = *(PUCHAR)inputBuffer;
            HvInputSetStrictMode(strict != 0);
            status = STATUS_SUCCESS;
        }
        break;

    // Item 2: xHCI USBSTS/IMAN EPT 读 trap 控制
    case IOCTL_HV_XHCI_TRAP_ENABLE:
        status = HvXhciEptTrapSetUserEnabled(TRUE);
        DbgPrint("[HV] XHCI_TRAP_ENABLE -> 0x%X\n", status);
        break;

    case IOCTL_HV_XHCI_TRAP_DISABLE:
        status = HvXhciEptTrapSetUserEnabled(FALSE);
        DbgPrint("[HV] XHCI_TRAP_DISABLE -> 0x%X\n", status);
        break;

    case IOCTL_HV_XHCI_TRAP_GET_STATS:
        if (outputLength < sizeof(HV_XHCI_EPT_TRAP_STATE) || !outputBuffer) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        HvXhciEptTrapQueryState((PHV_XHCI_EPT_TRAP_STATE)outputBuffer);
        bytesReturned = sizeof(HV_XHCI_EPT_TRAP_STATE);
        status = STATUS_SUCCESS;
        break;

    // ==================== 反反调试 ====================
    case IOCTL_HV_ENABLE_ANTIANTIDEBUG:
        {
            HV_ANTIANTIDEBUG_CONFIG config = { 0 };
            
            // 如果提供了请求数据，使用它
            if (inputLength >= sizeof(HV_ANTIANTIDEBUG_REQUEST)) {
                PHV_ANTIANTIDEBUG_REQUEST pReq = (PHV_ANTIANTIDEBUG_REQUEST)inputBuffer;
                config.TargetPid = pReq->TargetPid;
                config.HookNtQueryInformationProcess = pReq->HookNtQueryInformationProcess;
                config.HookNtQuerySystemInformation = pReq->HookNtQuerySystemInformation;
                config.HookNtSetInformationThread = pReq->HookNtSetInformationThread;
                config.HookNtClose = pReq->HookNtClose;
                config.HookNtQueryObject = pReq->HookNtQueryObject;
                
                DbgPrint("[HV] ENABLE_ANTIANTIDEBUG: TargetPID=%d\n", pReq->TargetPid);
            } else {
                // 使用默认配置（Hook 所有函数）
                DbgPrint("[HV] ENABLE_ANTIANTIDEBUG: Using default config\n");
            }
            
            status = HvHookEnableAntiAntiDebug(inputLength >= sizeof(HV_ANTIANTIDEBUG_REQUEST) ? &config : NULL);
            if (NT_SUCCESS(status)) {
                DbgPrint("[HV] Anti-anti-debug enabled successfully\n");
            } else {
                DbgPrint("[HV] Failed to enable anti-anti-debug: 0x%X\n", status);
            }
        }
        break;
    
    case IOCTL_HV_DISABLE_ANTIANTIDEBUG:
        DbgPrint("[HV] DISABLE_ANTIANTIDEBUG\n");
        status = HvHookDisableAntiAntiDebug();
        if (NT_SUCCESS(status)) {
            DbgPrint("[HV] Anti-anti-debug disabled successfully\n");
        } else {
            DbgPrint("[HV] Failed to disable anti-anti-debug: 0x%X\n", status);
        }
        break;
    
    // ==================== 注入 ====================
    case IOCTL_HV_INJECT_DLL:
        if (inputLength >= sizeof(HV_INJECT_DLL_REQUEST) && outputLength >= sizeof(HV_INJECT_DLL_RESULT)) {
            PHV_INJECT_DLL_REQUEST pReq = (PHV_INJECT_DLL_REQUEST)inputBuffer;
            PHV_INJECT_DLL_RESULT pResult = (PHV_INJECT_DLL_RESULT)outputBuffer;

            // METHOD_BUFFERED: pReq 和 pResult 共用 SystemBuffer。
            // RtlZeroMemory(pResult, 16) 会抹掉 pReq->TargetPid 和 DllPath 前 6 个 WCHAR。
            // 先 snapshot TargetPid;DllPath 在 offset 4+,pResult 只占 16 bytes,
            // 所以调 HvInjectDllFromFile 时 DllPath 大部分还在 — 但保险起见,
            // 在调注入函数前不写任何 pResult。
            ULONG targetPid = pReq->TargetPid;

            DbgPrint("[HV] INJECT_DLL: PID=%d, Path=%ws\n", targetPid, pReq->DllPath);

            HV_INJECTION_RESULT injResult = { 0 };
            status = HvInjectDllFromFile(targetPid, pReq->DllPath, &injResult);

            pResult->Status = NT_SUCCESS(status) ? HV_STATUS_SUCCESS : HV_STATUS_ERROR;
            pResult->ModuleBase = (UINT64)injResult.ModuleBase;
            pResult->ModuleSize = (ULONG)injResult.ModuleSize;
            bytesReturned = sizeof(HV_INJECT_DLL_RESULT);

            if (NT_SUCCESS(status)) {
                DbgPrint("[HV] DLL injected at 0x%llX, size=%d\n", pResult->ModuleBase, pResult->ModuleSize);
            } else {
                DbgPrint("[HV] DLL injection failed: 0x%X\n", status);
            }
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;
    
    case IOCTL_HV_INJECT_SHELLCODE:
        if (inputLength >= sizeof(HV_INJECT_SHELLCODE_REQUEST) && outputLength >= sizeof(HV_INJECT_SHELLCODE_RESULT)) {
            PHV_INJECT_SHELLCODE_REQUEST pReq = (PHV_INJECT_SHELLCODE_REQUEST)inputBuffer;
            PHV_INJECT_SHELLCODE_RESULT pResult = (PHV_INJECT_SHELLCODE_RESULT)outputBuffer;

            // METHOD_BUFFERED: pReq 和 pResult 共用 SystemBuffer。
            // RtlZeroMemory(pResult, 12) 会抹 TargetPid + ShellcodeSize + Parameter 低 4 字节。
            // 先 snapshot 所有标量字段;Shellcode 在 offset 18,落在 pResult 12 字节之外,安全。
            ULONG  targetPid     = pReq->TargetPid;
            ULONG  shellcodeSize = min(pReq->ShellcodeSize, sizeof(pReq->Shellcode));
            UINT64 parameter     = pReq->Parameter;
            BOOLEAN executeNow   = pReq->ExecuteImmediately;

            DbgPrint("[HV] INJECT_SHELLCODE: PID=%d, Size=%d, Execute=%d\n",
                targetPid, shellcodeSize, executeNow);

            PVOID allocAddr = NULL;
            if (executeNow) {
                status = HvInjectShellcode(
                    targetPid,
                    pReq->Shellcode,
                    shellcodeSize,
                    (PVOID)parameter,
                    &allocAddr
                );
            } else {
                status = HvInjectShellcodeNoExecute(
                    targetPid,
                    pReq->Shellcode,
                    shellcodeSize,
                    &allocAddr
                );
            }

            pResult->Status = NT_SUCCESS(status) ? HV_STATUS_SUCCESS : HV_STATUS_ERROR;
            pResult->ShellcodeAddress = (UINT64)allocAddr;
            bytesReturned = sizeof(HV_INJECT_SHELLCODE_RESULT);

            if (NT_SUCCESS(status)) {
                DbgPrint("[HV] Shellcode injected at 0x%llX\n", pResult->ShellcodeAddress);
            } else {
                DbgPrint("[HV] Shellcode injection failed: 0x%X\n", status);
            }
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;
    
    // ==================== 内存操作 ====================
    case IOCTL_HV_MEMORY_READ:
        if (inputLength >= sizeof(HV_MEMORY_REQUEST) && outputLength >= sizeof(HV_MEMORY_RESULT)) {
            PHV_MEMORY_REQUEST pReq = (PHV_MEMORY_REQUEST)inputBuffer;
            PHV_MEMORY_RESULT pResult = (PHV_MEMORY_RESULT)outputBuffer;

            // METHOD_BUFFERED: pReq 和 pResult 共用同一块 SystemBuffer。
            // 必须先把 input 字段抓到 locals 里, 再写 pResult; 不能反过来,
            // 也不能用 RtlZeroMemory(pResult, ...) 把 input 抹零。
            ULONG  procId  = pReq->ProcessId;
            UINT64 address = pReq->Address;
            ULONG  reqSize = pReq->Size;
            ULONG  readSize = min(reqSize, sizeof(pResult->Buffer));

            DbgPrint("[HV] MEMORY_READ: PID=%d, Addr=0x%llX, Size=%d\n",
                procId, address, readSize);

            SIZE_T bytesRead = 0;
            NTSTATUS opStatus = HvMemoryRead(
                procId,
                (PVOID)address,
                pResult->Buffer,   // 写 pResult->Buffer 之后, pReq->Buffer 等同被覆盖
                readSize,
                &bytesRead
            );

            // 失败 / 部分成功时, 把 pResult->Buffer 中**未写入**的尾部 zero,
            // 不然 METHOD_BUFFERED 下用户会看到 input SystemBuffer 残留数据,
            // 误以为"读到了 0"或者更糟"读到了别的进程的旧数据"。
            // 成功 (bytesRead == readSize) 时这段是 no-op。
            if (bytesRead < readSize) {
                RtlZeroMemory(pResult->Buffer + bytesRead, readSize - bytesRead);
            }

            // NTSTATUS 直接塞进 pResult->Status —— 失败 NTSTATUS 都 ≥ 0x80000000,
            // 与 HV_STATUS_* (0..7) 永不重叠,Python 端能区分。IRP 完成 status 保持
            // SUCCESS,否则 IO Manager 会把 NTSTATUS 映射成 Win32 87 把细节抹掉。
            pResult->Status = (HV_STATUS_CODE)opStatus;
            pResult->Address = address;
            pResult->BytesTransferred = (ULONG)bytesRead;
            bytesReturned = sizeof(HV_MEMORY_RESULT);
            if (!NT_SUCCESS(opStatus)) {
                DbgPrint("[HV] MEMORY_READ failed: 0x%X (bytesRead=%llu/%u, buffer zeroed)\n",
                         opStatus, (UINT64)bytesRead, readSize);
            }
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case IOCTL_HV_MEMORY_WRITE:
        if (inputLength >= sizeof(HV_MEMORY_REQUEST) && outputLength >= sizeof(HV_MEMORY_RESULT)) {
            PHV_MEMORY_REQUEST pReq = (PHV_MEMORY_REQUEST)inputBuffer;
            PHV_MEMORY_RESULT pResult = (PHV_MEMORY_RESULT)outputBuffer;

            // METHOD_BUFFERED 共用 SystemBuffer: 先抓 input locals, 再做写, 最后写 pResult。
            ULONG  procId  = pReq->ProcessId;
            UINT64 address = pReq->Address;
            ULONG  reqSize = pReq->Size;
            ULONG  writeSize = min(reqSize, sizeof(pReq->Buffer));

            DbgPrint("[HV] MEMORY_WRITE: PID=%d, Addr=0x%llX, Size=%d\n",
                procId, address, writeSize);

            SIZE_T bytesWritten = 0;
            NTSTATUS opStatus = HvMemoryWrite(
                procId,
                (PVOID)address,
                pReq->Buffer,    // 写 pResult 字段前读 pReq->Buffer; 之后覆写到 pResult 字段
                writeSize,
                &bytesWritten
            );

            pResult->Status = (HV_STATUS_CODE)opStatus;
            pResult->Address = address;
            pResult->BytesTransferred = (ULONG)bytesWritten;
            bytesReturned = sizeof(HV_MEMORY_RESULT);
            if (!NT_SUCCESS(opStatus)) {
                DbgPrint("[HV] MEMORY_WRITE failed: 0x%X\n", opStatus);
            }
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    // ==================== 变长内存读 (优化 #3) ====================
    case IOCTL_HV_MEMORY_READ_EX:
        if (inputLength >= sizeof(HV_MEMORY_REQUEST_EX) &&
            outputLength >= sizeof(HV_MEMORY_RESULT_EX))
        {
            PHV_MEMORY_REQUEST_EX pReq = (PHV_MEMORY_REQUEST_EX)inputBuffer;

            // METHOD_BUFFERED: pReq 与 pResult 共用 SystemBuffer, 必须先抓 locals。
            ULONG  procId   = pReq->ProcessId;
            UINT64 address  = pReq->Address;
            ULONG  reqSize  = pReq->Size;

            // payload 容量 = output 总长 - header
            ULONG  payloadCap = outputLength - sizeof(HV_MEMORY_RESULT_EX);
            ULONG  readSize   = (reqSize < payloadCap) ? reqSize : payloadCap;
            if (readSize > HV_MEMORY_EX_MAX_PAYLOAD) readSize = HV_MEMORY_EX_MAX_PAYLOAD;

            // payload 写到 (outputBuffer + sizeof(HV_MEMORY_RESULT_EX))
            // (outputBuffer 与 inputBuffer 是同一 SystemBuffer, 但 input 没有 payload,
            //  从 offset 24 开始的字节可以放心覆盖。)
            PUCHAR payload = (PUCHAR)outputBuffer + sizeof(HV_MEMORY_RESULT_EX);

            SIZE_T bytesRead = 0;
            NTSTATUS opStatus = STATUS_INVALID_PARAMETER;
            if (readSize > 0) {
                opStatus = HvMemoryRead(procId, (PVOID)address,
                                        payload, readSize, &bytesRead);
                // 失败 / 部分成功 → 把 payload 尾巴 zero 掉, 避免泄漏 SystemBuffer 残留
                if (bytesRead < readSize) {
                    RtlZeroMemory(payload + bytesRead, readSize - bytesRead);
                }
            }

            // 先写 payload, 再写 header (覆盖前 24 字节)
            PHV_MEMORY_RESULT_EX pResult = (PHV_MEMORY_RESULT_EX)outputBuffer;
            pResult->Status           = (HV_STATUS_CODE)opStatus;
            pResult->Reserved0        = 0;
            pResult->Address          = address;
            pResult->BytesTransferred = (ULONG)bytesRead;
            pResult->Reserved1        = 0;
            bytesReturned = sizeof(HV_MEMORY_RESULT_EX) + readSize;

            if (!NT_SUCCESS(opStatus)) {
                DbgPrint("[HV] MEMORY_READ_EX failed: PID=%d, Size=%u, status=0x%X\n",
                         procId, readSize, opStatus);
            }
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    // ==================== 变长内存写 (优化 #3) ====================
    case IOCTL_HV_MEMORY_WRITE_EX:
        if (inputLength >= sizeof(HV_MEMORY_REQUEST_EX) &&
            outputLength >= sizeof(HV_MEMORY_RESULT_EX))
        {
            PHV_MEMORY_REQUEST_EX pReq = (PHV_MEMORY_REQUEST_EX)inputBuffer;

            ULONG  procId   = pReq->ProcessId;
            UINT64 address  = pReq->Address;
            ULONG  reqSize  = pReq->Size;

            // payload 字节数 = input 总长 - header
            ULONG  payloadAvail = inputLength - sizeof(HV_MEMORY_REQUEST_EX);
            ULONG  writeSize    = (reqSize < payloadAvail) ? reqSize : payloadAvail;
            if (writeSize > HV_MEMORY_EX_MAX_PAYLOAD) writeSize = HV_MEMORY_EX_MAX_PAYLOAD;

            PUCHAR payload = (PUCHAR)inputBuffer + sizeof(HV_MEMORY_REQUEST_EX);

            // HvMemoryWrite 在写完前不会触碰 outputBuffer 头部, 所以可以原地写 payload
            // (offset 24+) 不影响 header(offset 0..23 = pReq, 之后会被 pResult 覆盖)。
            SIZE_T bytesWritten = 0;
            NTSTATUS opStatus = STATUS_INVALID_PARAMETER;
            if (writeSize > 0) {
                opStatus = HvMemoryWrite(procId, (PVOID)address,
                                         payload, writeSize, &bytesWritten);
            }

            PHV_MEMORY_RESULT_EX pResult = (PHV_MEMORY_RESULT_EX)outputBuffer;
            pResult->Status           = (HV_STATUS_CODE)opStatus;
            pResult->Reserved0        = 0;
            pResult->Address          = address;
            pResult->BytesTransferred = (ULONG)bytesWritten;
            pResult->Reserved1        = 0;
            bytesReturned = sizeof(HV_MEMORY_RESULT_EX);

            if (!NT_SUCCESS(opStatus)) {
                DbgPrint("[HV] MEMORY_WRITE_EX failed: PID=%d, Size=%u, status=0x%X\n",
                         procId, writeSize, opStatus);
            }
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    // ==================== 批量读 (优化 #1) ====================
    case IOCTL_HV_MEMORY_BATCH_READ:
        if (inputLength >= sizeof(HV_MEMORY_BATCH_REQUEST) &&
            outputLength >= sizeof(HV_MEMORY_BATCH_RESULT))
        {
            PHV_MEMORY_BATCH_REQUEST pReq = (PHV_MEMORY_BATCH_REQUEST)inputBuffer;
            ULONG procId  = pReq->ProcessId;
            ULONG reqCount = pReq->Count;

            // 上限 + input 长度校验
            if (reqCount == 0 || reqCount > HV_BATCH_MAX_ITEMS) {
                status = STATUS_INVALID_PARAMETER;
                break;
            }
            ULONG itemsBytes = reqCount * sizeof(HV_MEMORY_BATCH_ITEM);
            ULONG inHeaderEnd = sizeof(HV_MEMORY_BATCH_REQUEST) + itemsBytes;
            if (inputLength < inHeaderEnd) {
                status = STATUS_INVALID_PARAMETER;
                break;
            }

            // output 校验: header + ResItems[Count] + 至少 payload 部分占位
            ULONG resItemsBytes = reqCount * sizeof(HV_MEMORY_BATCH_RES_ITEM);
            ULONG outHeaderEnd = sizeof(HV_MEMORY_BATCH_RESULT) + resItemsBytes;
            if (outputLength < outHeaderEnd) {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            ULONG payloadCap = outputLength - outHeaderEnd;
            if (payloadCap > HV_BATCH_MAX_PAYLOAD) payloadCap = HV_BATCH_MAX_PAYLOAD;

            // METHOD_BUFFERED: output 写 Results 时会从 offset 8 开始覆盖,
            // payload 段从 outHeaderEnd 开始覆盖, 都可能覆盖 input 的 Items 数组。
            // 必须先把 Items 拷到本地数组, 再做处理。
            // 256 * 16 = 4KB on stack, x64 默认 12KB 栈, 安全。
            HV_MEMORY_BATCH_ITEM items[HV_BATCH_MAX_ITEMS];
            RtlCopyMemory(items, (PUCHAR)inputBuffer + sizeof(HV_MEMORY_BATCH_REQUEST),
                          itemsBytes);

            // 先写 header (覆盖 input header, 8 字节)
            PHV_MEMORY_BATCH_RESULT pResult = (PHV_MEMORY_BATCH_RESULT)outputBuffer;
            pResult->TopStatus = HV_STATUS_SUCCESS;
            pResult->Count     = reqCount;

            // ResItems 起点
            PHV_MEMORY_BATCH_RES_ITEM resItems =
                (PHV_MEMORY_BATCH_RES_ITEM)((PUCHAR)outputBuffer +
                                            sizeof(HV_MEMORY_BATCH_RESULT));
            // payload 段起点
            PUCHAR payloadBase = (PUCHAR)outputBuffer + outHeaderEnd;

            for (ULONG i = 0; i < reqCount; i++) {
                UINT64 addr        = items[i].Address;
                ULONG  itemSize    = items[i].Size;
                ULONG  itemOffset  = items[i].PayloadOffset;

                // 单项边界: PayloadOffset + Size 落在 payload 段内
                if (itemSize == 0 ||
                    itemSize > HV_BATCH_MAX_PAYLOAD ||
                    itemOffset > payloadCap ||
                    itemSize > payloadCap - itemOffset)
                {
                    resItems[i].Status           = HV_STATUS_INVALID_PARAMETER;
                    resItems[i].BytesTransferred = 0;
                    continue;
                }

                PUCHAR dst = payloadBase + itemOffset;
                SIZE_T thisRead = 0;
                NTSTATUS opStatus = HvMemoryRead(procId, (PVOID)addr,
                                                 dst, itemSize, &thisRead);
                // 部分成功 → zero 尾巴, 不让用户看到 SystemBuffer 残留
                if (thisRead < itemSize) {
                    RtlZeroMemory(dst + thisRead, itemSize - thisRead);
                }
                resItems[i].Status           = (HV_STATUS_CODE)opStatus;
                resItems[i].BytesTransferred = (ULONG)thisRead;
            }

            bytesReturned = outHeaderEnd + payloadCap;
            // 实际 payload 段大部分可能没用到, 但 METHOD_BUFFERED 拷回的字节数由
            // bytesReturned 决出。这里直接报 payloadCap 上限, 等价于把整个 output
            // SystemBuffer 都还给用户。
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    // ==================== 批量写 (优化 #1) ====================
    case IOCTL_HV_MEMORY_BATCH_WRITE:
        if (inputLength >= sizeof(HV_MEMORY_BATCH_REQUEST) &&
            outputLength >= sizeof(HV_MEMORY_BATCH_RESULT))
        {
            PHV_MEMORY_BATCH_REQUEST pReq = (PHV_MEMORY_BATCH_REQUEST)inputBuffer;
            ULONG procId   = pReq->ProcessId;
            ULONG reqCount = pReq->Count;

            if (reqCount == 0 || reqCount > HV_BATCH_MAX_ITEMS) {
                status = STATUS_INVALID_PARAMETER;
                break;
            }
            ULONG itemsBytes = reqCount * sizeof(HV_MEMORY_BATCH_ITEM);
            ULONG inHeaderEnd = sizeof(HV_MEMORY_BATCH_REQUEST) + itemsBytes;
            if (inputLength < inHeaderEnd) {
                status = STATUS_INVALID_PARAMETER;
                break;
            }
            ULONG payloadAvail = inputLength - inHeaderEnd;
            if (payloadAvail > HV_BATCH_MAX_PAYLOAD) payloadAvail = HV_BATCH_MAX_PAYLOAD;

            ULONG resItemsBytes = reqCount * sizeof(HV_MEMORY_BATCH_RES_ITEM);
            ULONG outHeaderEnd = sizeof(HV_MEMORY_BATCH_RESULT) + resItemsBytes;
            if (outputLength < outHeaderEnd) {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }

            // Items 数组与 payload 都在 input 区, 但写 ResItems 会覆盖 Items 的前半。
            // 同样: 先把 Items 拷到本地, payload 段在 inHeaderEnd 之后, 不被 Results
            // 覆盖 (Results 在 sizeof(HEADER)..outHeaderEnd 范围, outHeaderEnd ≤ inHeaderEnd
            // 当 sizeof(RES_ITEM)=8 < sizeof(ITEM)=16, 所以 outHeaderEnd 落在 Items 区内,
            // payload 完全没被触碰)。
            HV_MEMORY_BATCH_ITEM items[HV_BATCH_MAX_ITEMS];
            RtlCopyMemory(items, (PUCHAR)inputBuffer + sizeof(HV_MEMORY_BATCH_REQUEST),
                          itemsBytes);

            PUCHAR payloadBase = (PUCHAR)inputBuffer + inHeaderEnd;

            PHV_MEMORY_BATCH_RESULT pResult = (PHV_MEMORY_BATCH_RESULT)outputBuffer;
            pResult->TopStatus = HV_STATUS_SUCCESS;
            pResult->Count     = reqCount;

            PHV_MEMORY_BATCH_RES_ITEM resItems =
                (PHV_MEMORY_BATCH_RES_ITEM)((PUCHAR)outputBuffer +
                                            sizeof(HV_MEMORY_BATCH_RESULT));

            for (ULONG i = 0; i < reqCount; i++) {
                UINT64 addr        = items[i].Address;
                ULONG  itemSize    = items[i].Size;
                ULONG  itemOffset  = items[i].PayloadOffset;

                if (itemSize == 0 ||
                    itemSize > HV_BATCH_MAX_PAYLOAD ||
                    itemOffset > payloadAvail ||
                    itemSize > payloadAvail - itemOffset)
                {
                    resItems[i].Status           = HV_STATUS_INVALID_PARAMETER;
                    resItems[i].BytesTransferred = 0;
                    continue;
                }

                PUCHAR src = payloadBase + itemOffset;
                SIZE_T thisWritten = 0;
                NTSTATUS opStatus = HvMemoryWrite(procId, (PVOID)addr,
                                                  src, itemSize, &thisWritten);
                resItems[i].Status           = (HV_STATUS_CODE)opStatus;
                resItems[i].BytesTransferred = (ULONG)thisWritten;
            }

            bytesReturned = outHeaderEnd;
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case IOCTL_HV_MEMORY_ALLOC:
        if (inputLength >= sizeof(HV_MEMORY_REQUEST) && outputLength >= sizeof(HV_MEMORY_RESULT)) {
            PHV_MEMORY_REQUEST pReq = (PHV_MEMORY_REQUEST)inputBuffer;
            PHV_MEMORY_RESULT pResult = (PHV_MEMORY_RESULT)outputBuffer;

            // METHOD_BUFFERED: pReq 和 pResult 共用 SystemBuffer。
            // 先把 input 抓 locals,再写 pResult。
            ULONG procId     = pReq->ProcessId;
            ULONG allocSize  = pReq->Size;
            ULONG protection = pReq->Protection;

            DbgPrint("[HV] MEMORY_ALLOC: PID=%d, Size=%d, Protection=0x%X\n",
                procId, allocSize, protection);

            PVOID allocAddr = NULL;
            NTSTATUS opStatus = HvMemoryAllocate(
                procId,
                allocSize,
                protection,
                &allocAddr
            );

            pResult->Status = (HV_STATUS_CODE)opStatus;
            pResult->Address = (UINT64)allocAddr;
            pResult->BytesTransferred = NT_SUCCESS(opStatus) ? allocSize : 0;
            bytesReturned = sizeof(HV_MEMORY_RESULT);

            if (NT_SUCCESS(opStatus)) {
                DbgPrint("[HV] Memory allocated at 0x%llX\n", pResult->Address);
            } else {
                DbgPrint("[HV] Memory allocation failed: 0x%X\n", opStatus);
            }
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;
    
    case IOCTL_HV_MEMORY_FREE:
        if (inputLength >= sizeof(HV_MEMORY_REQUEST)) {
            PHV_MEMORY_REQUEST pReq = (PHV_MEMORY_REQUEST)inputBuffer;
            
            DbgPrint("[HV] MEMORY_FREE: PID=%d, Addr=0x%llX\n",
                pReq->ProcessId, pReq->Address);
            
            status = HvMemoryFree(pReq->ProcessId, (PVOID)pReq->Address);
            
            if (NT_SUCCESS(status)) {
                DbgPrint("[HV] Memory freed successfully\n");
            } else {
                DbgPrint("[HV] Memory free failed: 0x%X\n", status);
            }
        } else {
            status = STATUS_INVALID_PARAMETER;
        }
        break;

    case IOCTL_HV_ENUMERATE_MODULES:
        if (inputLength >= sizeof(HV_MODULE_ENUM_REQUEST) &&
            outputLength >= sizeof(HV_MODULE_ENUM_RESULT) + sizeof(HV_MODULE_INFO))
        {
            PHV_MODULE_ENUM_REQUEST pReq = (PHV_MODULE_ENUM_REQUEST)inputBuffer;
            ULONG procId = pReq->ProcessId;

            // outputBuffer 容纳 result-header + modules[]; 计算实际能装多少条
            ULONG capacityByBuffer = (ULONG)(
                (outputLength - sizeof(HV_MODULE_ENUM_RESULT)) / sizeof(HV_MODULE_INFO));
            ULONG capacityByReq = pReq->MaxModules;
            ULONG capacity = (capacityByReq && capacityByReq < capacityByBuffer)
                                ? capacityByReq
                                : capacityByBuffer;
            if (capacity > HV_MAX_MODULES_PER_PROCESS) capacity = HV_MAX_MODULES_PER_PROCESS;

            PHV_MODULE_ENUM_RESULT pResult = (PHV_MODULE_ENUM_RESULT)outputBuffer;
            PHV_MODULE_INFO modArray = (PHV_MODULE_INFO)(pResult + 1);

            ULONG count = 0;
            NTSTATUS opStatus = HvPhysEnumerateModules(procId, modArray, capacity, &count);

            pResult->Status = (HV_STATUS_CODE)opStatus;
            pResult->Count  = count;
            bytesReturned = sizeof(HV_MODULE_ENUM_RESULT) + count * sizeof(HV_MODULE_INFO);

            DbgPrint("[HV] ENUMERATE_MODULES: PID=%u capacity=%u count=%u status=0x%X\n",
                     procId, capacity, count, opStatus);
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    // ==================== 嵌套虚拟化监控 ====================
    case IOCTL_HV_GET_NESTED_STATUS:
        if (outputLength >= sizeof(HV_NESTED_STATUS)) {
            PHV_NESTED_STATUS pNested = (PHV_NESTED_STATUS)outputBuffer;
            RtlZeroMemory(pNested, sizeof(HV_NESTED_STATUS));
            
            // 检查是否支持嵌套虚拟化
            CPU_VENDOR vendor = HvGetCpuVendor();
            pNested->NestedVmxSupported = (vendor == CPU_VENDOR_INTEL);
            pNested->NestedSvmSupported = (vendor == CPU_VENDOR_AMD);
            
            // 遍历所有 CPU 收集嵌套状态
            ULONG cpuCount = g_HypervisorContext.ProcessorCount;
            ULONG activeCpus = 0;
            UINT64 totalVmxon = 0, totalVmlaunch = 0, totalVmresume = 0;
            UINT64 totalL2Exit = 0, totalErrors = 0;
            BOOLEAN anyL1Enabled = FALSE, anyL2Running = FALSE;
            UINT64 currentVmcsGpa = 0, vmxonRegionGpa = 0;
            
            for (ULONG i = 0; i < cpuCount; i++) {
                PVCPU_DATA vcpu = &g_HypervisorContext.VcpuData[i];
                if (!vcpu->IsVirtualized) continue;
                
                if (vendor == CPU_VENDOR_INTEL) {
                    PNESTED_VMX_STATE nested = &vcpu->NestedVmx;
                    if (nested->VmxEnabled) {
                        anyL1Enabled = TRUE;
                        activeCpus++;
                        totalVmxon++;
                    }
                    if (vcpu->IsInL2) {
                        anyL2Running = TRUE;
                    }
                    totalL2Exit += nested->L2VmExitCount;
                    totalVmlaunch += nested->NestedVmEntryCount;
                    
                    if (nested->CurrentVmcsGpa != 0) {
                        currentVmcsGpa = nested->CurrentVmcsGpa;
                    }
                    if (nested->VmxonRegionGpa != 0) {
                        vmxonRegionGpa = nested->VmxonRegionGpa;
                    }
                } else if (vendor == CPU_VENDOR_AMD) {
                    PNESTED_SVM_STATE nested = &vcpu->NestedSvm;
                    if (nested->SvmEnabled) {
                        anyL1Enabled = TRUE;
                        activeCpus++;
                    }
                    if (nested->InGuestMode) {
                        anyL2Running = TRUE;
                    }
                    totalL2Exit += nested->L2VmExitCount;
                    totalVmlaunch += nested->NestedVmrunCount;
                }
            }
            
            pNested->L1VmxEnabled = anyL1Enabled;
            pNested->L2Running = anyL2Running;
            pNested->ActiveCpuCount = activeCpus;
            pNested->TotalVmxonCount = totalVmxon;
            pNested->TotalVmlaunchCount = totalVmlaunch;
            pNested->TotalVmresumeCount = totalVmresume;
            pNested->TotalL2ExitCount = totalL2Exit;
            pNested->TotalErrorCount = totalErrors;
            pNested->CurrentVmcsGpa = currentVmcsGpa;
            pNested->VmxonRegionGpa = vmxonRegionGpa;
            
            bytesReturned = sizeof(HV_NESTED_STATUS);
            DbgPrint("[HV] GET_NESTED_STATUS: L1=%d, L2=%d, ActiveCPUs=%d\n",
                pNested->L1VmxEnabled, pNested->L2Running, pNested->ActiveCpuCount);
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;
    
    case IOCTL_HV_GET_NESTED_EVENTS:
    case IOCTL_HV_CLEAR_NESTED_EVENTS:
        DbgPrint("[HV] Nested events not implemented\n");
        status = STATUS_NOT_IMPLEMENTED;
        break;

    // ==================== 阶段 7.1: 内核任意地址读写 ====================
    // 仅注册的调试器可调,host CR3 == kernel CR3 → 直接 memcpy 走 SEH
    case IOCTL_HV_KERNEL_READ:
    {
        HANDLE caller = PsGetCurrentProcessId();
        if (!HvHookIsDebuggerPid(caller)) {
            DbgPrint("[HV] KERNEL_READ: access denied (PID=%llu not a registered debugger)\n",
                (ULONG64)(ULONG_PTR)caller);
            status = STATUS_ACCESS_DENIED;
            break;
        }

        if (inputLength < sizeof(HV_KERNEL_MEM_REQUEST) ||
            outputLength < sizeof(HV_KERNEL_MEM_RESULT)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        PHV_KERNEL_MEM_REQUEST pReq = (PHV_KERNEL_MEM_REQUEST)inputBuffer;
        PHV_KERNEL_MEM_RESULT pResult = (PHV_KERNEL_MEM_RESULT)outputBuffer;

        // METHOD_BUFFERED: pReq 和 pResult 共用 SystemBuffer,先 snapshot 再写。
        UINT64 address = pReq->Address;
        ULONG  size    = pReq->Size;

        if (size == 0 || size > HV_KERNEL_MEM_BUF_SIZE) {
            pResult->Status = HV_STATUS_INVALID_PARAMETER;
            pResult->Address = address;
            pResult->BytesTransferred = 0;
            bytesReturned = sizeof(HV_KERNEL_MEM_RESULT);
            break;
        }

        // 地址必须在内核空间且 Address + Size 不溢出
        if (address < 0xFFFF800000000000ULL ||
            (address + size) < address) {
            pResult->Status = HV_STATUS_INVALID_PARAMETER;
            pResult->Address = address;
            pResult->BytesTransferred = 0;
            bytesReturned = sizeof(HV_KERNEL_MEM_RESULT);
            break;
        }

        pResult->Address = address;
        __try {
            RtlCopyMemory(pResult->Buffer, (PVOID)(ULONG_PTR)address, size);
            pResult->BytesTransferred = size;
            pResult->Status = HV_STATUS_SUCCESS;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            pResult->BytesTransferred = 0;
            pResult->Status = HV_STATUS_ACCESS_DENIED;
        }
        bytesReturned = sizeof(HV_KERNEL_MEM_RESULT);

        DbgPrint("[HV] KERNEL_READ: Addr=0x%llX Size=%u Result=%d\n",
            address, size, pResult->Status);
        break;
    }

    case IOCTL_HV_KERNEL_WRITE:
    {
        HANDLE caller = PsGetCurrentProcessId();
        if (!HvHookIsDebuggerPid(caller)) {
            DbgPrint("[HV] KERNEL_WRITE: access denied (PID=%llu not a registered debugger)\n",
                (ULONG64)(ULONG_PTR)caller);
            status = STATUS_ACCESS_DENIED;
            break;
        }

        if (inputLength < sizeof(HV_KERNEL_MEM_REQUEST) ||
            outputLength < sizeof(HV_KERNEL_MEM_RESULT)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        PHV_KERNEL_MEM_REQUEST pReq = (PHV_KERNEL_MEM_REQUEST)inputBuffer;
        PHV_KERNEL_MEM_RESULT pResult = (PHV_KERNEL_MEM_RESULT)outputBuffer;

        // METHOD_BUFFERED: pReq 和 pResult 共用 SystemBuffer。
        // 关键:必须先 snapshot 标量字段,且写 RtlCopyMemory(source=pReq->Buffer)
        // 完成后才能动 pResult,因为 pResult->Reserved 与 pReq->Buffer[0..3] 重叠。
        UINT64 address = pReq->Address;
        ULONG  size    = pReq->Size;

        if (size == 0 || size > HV_KERNEL_MEM_BUF_SIZE) {
            pResult->Status = HV_STATUS_INVALID_PARAMETER;
            pResult->Address = address;
            pResult->BytesTransferred = 0;
            bytesReturned = sizeof(HV_KERNEL_MEM_RESULT);
            break;
        }

        if (address < 0xFFFF800000000000ULL ||
            (address + size) < address) {
            pResult->Status = HV_STATUS_INVALID_PARAMETER;
            pResult->Address = address;
            pResult->BytesTransferred = 0;
            bytesReturned = sizeof(HV_KERNEL_MEM_RESULT);
            break;
        }

        HV_STATUS_CODE resultStatus;
        ULONG resultBytes;
        __try {
            // 先做实际写入(pReq->Buffer 是源数据,绝对不能先动 pResult)。
            RtlCopyMemory((PVOID)(ULONG_PTR)address, pReq->Buffer, size);
            resultStatus = HV_STATUS_SUCCESS;
            resultBytes = size;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            resultStatus = HV_STATUS_ACCESS_DENIED;
            resultBytes = 0;
        }

        // 现在动 pResult,即使它覆盖 pReq 也无所谓 —— 已经用完了。
        pResult->Status = resultStatus;
        pResult->Address = address;
        pResult->BytesTransferred = resultBytes;
        bytesReturned = sizeof(HV_KERNEL_MEM_RESULT);

        DbgPrint("[HV] KERNEL_WRITE: Addr=0x%llX Size=%u Result=%d\n",
            address, size, resultStatus);
        break;
    }

    // ==================== Phase G: 根因事件 ring buffer 拉取 ====================
    case IOCTL_HV_GET_DBGEVT:
    {
        if (inputLength < sizeof(HV_DBGEVT_PULL_REQ) ||
            outputLength < sizeof(HV_DBGEVT_PULL_RES)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        PHV_DBGEVT_PULL_REQ pReq = (PHV_DBGEVT_PULL_REQ)inputBuffer;

        // METHOD_BUFFERED: 输入输出共享 SystemBuffer。先 snapshot 标量字段。
        UINT64 sinceSeq = pReq->SinceSequence;
        ULONG  maxReq   = pReq->MaxCount;
        if (maxReq == 0) maxReq = 64;
        if (maxReq > HV_DBGEVT_RING_SIZE) maxReq = HV_DBGEVT_RING_SIZE;

        // 缓冲区容量上限:res header + maxReq × sizeof(HV_DBGEVT)
        ULONG headerSize = sizeof(HV_DBGEVT_PULL_RES);
        ULONG itemsRoom  = (outputLength > headerSize)
                           ? (outputLength - headerSize) : 0;
        ULONG maxItems   = itemsRoom / sizeof(HV_DBGEVT);
        if (maxItems > maxReq) maxItems = maxReq;
        if (maxItems == 0) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        PHV_DBGEVT_PULL_RES pRes = (PHV_DBGEVT_PULL_RES)outputBuffer;
        PHV_DBGEVT items = (PHV_DBGEVT)((PUCHAR)outputBuffer + headerSize);

        ULONG outCount = 0;
        UINT64 nextSeq = 0;
        status = HvDbgEvtPull(sinceSeq, items, maxItems, &outCount, &nextSeq);
        if (!NT_SUCCESS(status)) {
            break;
        }

        pRes->Count        = outCount;
        pRes->_pad         = 0;
        pRes->NextSequence = nextSeq;

        bytesReturned = headerSize + outCount * sizeof(HV_DBGEVT);
        // 不打 DbgPrint —— 这个 IOCTL 每秒被 GUI 调一次,记录会自己刷屏
        break;
    }

    // ==================== P50 软断点注册 (R3 已写 0xCC,driver 仅登记) ====================
    case IOCTL_HV_DBG_SW_BP_ADD:
    {
        // 输入: ULONG target_pid; UINT64 address
        typedef struct { ULONG TargetPid; ULONG _pad; UINT64 Address; } SW_BP_REQ;
        if (inputLength < sizeof(SW_BP_REQ)) { status = STATUS_BUFFER_TOO_SMALL; break; }
        SW_BP_REQ* r = (SW_BP_REQ*)inputBuffer;
        status = HvDbgRegisterSwBp(
            PsGetCurrentProcessId(),
            (HANDLE)(ULONG_PTR)r->TargetPid,
            r->Address);
        DbgPrint("[HV] SW_BP_ADD: target=%u rip=0x%llX status=0x%X\n",
                 r->TargetPid, r->Address, status);
        break;
    }
    case IOCTL_HV_DBG_SW_BP_DEL:
    {
        typedef struct { ULONG TargetPid; ULONG _pad; UINT64 Address; } SW_BP_REQ;
        if (inputLength < sizeof(SW_BP_REQ)) { status = STATUS_BUFFER_TOO_SMALL; break; }
        SW_BP_REQ* r = (SW_BP_REQ*)inputBuffer;
        status = HvDbgUnregisterSwBp((HANDLE)(ULONG_PTR)r->TargetPid, r->Address);
        DbgPrint("[HV] SW_BP_DEL: target=%u rip=0x%llX status=0x%X\n",
                 r->TargetPid, r->Address, status);
        break;
    }

    case IOCTL_HV_DBG_STEP_ARM:
    {
        // 输入: ULONG target_tid
        if (inputLength < sizeof(ULONG)) { status = STATUS_BUFFER_TOO_SMALL; break; }
        ULONG tid = *(ULONG*)inputBuffer;
        status = HvDbgArmStep(PsGetCurrentProcessId(), (HANDLE)(ULONG_PTR)tid);
        DbgPrint("[HV] STEP_ARM: tid=%u status=0x%X\n", tid, status);
        break;
    }

    // ==================== 2026-06-16: 0x1AA 诊断快照 ====================
    case IOCTL_HV_GET_DIAG_SNAPSHOT:
    {
        if (outputLength < sizeof(HV_DIAG_SNAPSHOT)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        HvUtilsGetDiagSnapshot((PHV_DIAG_SNAPSHOT)outputBuffer);
        bytesReturned = sizeof(HV_DIAG_SNAPSHOT);
        status = STATUS_SUCCESS;
        // 不打 DbgPrint — 这个 IOCTL 可能高频轮询
        break;
    }

    // ==================== 阶段 7.7: HWBP 控制 IOCTL ====================
    case IOCTL_HV_DBG_SET_HWBP:
    {
        HANDLE caller = PsGetCurrentProcessId();
        if (!HvHookIsDebuggerPid(caller)) {
            DbgPrint("[HV] DBG_SET_HWBP: access denied (PID=%llu)\n",
                (ULONG64)(ULONG_PTR)caller);
            status = STATUS_ACCESS_DENIED;
            break;
        }

        if (inputLength < sizeof(HV_HWBP_REQUEST) ||
            outputLength < sizeof(HV_DBG_RESULT)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        PHV_HWBP_REQUEST pReq = (PHV_HWBP_REQUEST)inputBuffer;
        // 先把输入字段全部拷出 (因为 input/output 共享 buffer)
        ULONG  targetPid  = pReq->TargetPid;
        ULONG  slotIndex  = pReq->SlotIndex;
        UINT64 address    = pReq->Address;
        UCHAR  length     = pReq->Length;
        UCHAR  type       = pReq->Type;

        PHV_DBG_RESULT pResult = (PHV_DBG_RESULT)outputBuffer;
        RtlZeroMemory(pResult, sizeof(HV_DBG_RESULT));

        // P128 (2026-06-25): 走虚拟硬断 (EPT-based, 不真写 DR).
        //   HvDbgSetHwBp 旧 DR 路径完全 deprecate, 改成转发 HvVwatchSet.
        NTSTATUS st = HvVwatchSet(
            caller,
            (HANDLE)(ULONG_PTR)targetPid,
            slotIndex,
            address,
            length,
            type);

        pResult->Status = NT_SUCCESS(st) ? HV_STATUS_SUCCESS :
            (st == STATUS_INVALID_PARAMETER) ? HV_STATUS_INVALID_PARAMETER :
            (st == STATUS_INSUFFICIENT_RESOURCES) ? HV_STATUS_INSUFFICIENT_BUFFER :
            HV_STATUS_ERROR;
        bytesReturned = sizeof(HV_DBG_RESULT);

        DbgPrint("[HV] DBG_SET_HWBP -> Vwatch: Dbg=%llu Target=%u Slot=%u Addr=0x%llX Len=%u Type=%u -> NT=0x%X\n",
            (ULONG64)(ULONG_PTR)caller, targetPid, slotIndex, address, length, type, st);
        break;
    }

    case IOCTL_HV_DBG_CLEAR_HWBP:
    {
        HANDLE caller = PsGetCurrentProcessId();
        if (!HvHookIsDebuggerPid(caller)) {
            DbgPrint("[HV] DBG_CLEAR_HWBP: access denied (PID=%llu)\n",
                (ULONG64)(ULONG_PTR)caller);
            status = STATUS_ACCESS_DENIED;
            break;
        }

        if (inputLength < sizeof(HV_HWBP_REQUEST) ||
            outputLength < sizeof(HV_DBG_RESULT)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        PHV_HWBP_REQUEST pReq = (PHV_HWBP_REQUEST)inputBuffer;
        ULONG  targetPid  = pReq->TargetPid;
        ULONG  slotIndex  = pReq->SlotIndex;

        PHV_DBG_RESULT pResult = (PHV_DBG_RESULT)outputBuffer;
        RtlZeroMemory(pResult, sizeof(HV_DBG_RESULT));

        NTSTATUS st = HvVwatchClear(
            (HANDLE)(ULONG_PTR)targetPid,
            slotIndex);

        pResult->Status = NT_SUCCESS(st) ? HV_STATUS_SUCCESS :
            (st == STATUS_INVALID_PARAMETER) ? HV_STATUS_INVALID_PARAMETER :
            (st == STATUS_NOT_FOUND) ? HV_STATUS_NOT_FOUND :
            HV_STATUS_ERROR;
        bytesReturned = sizeof(HV_DBG_RESULT);

        DbgPrint("[HV] DBG_CLEAR_HWBP -> Vwatch: Target=%u Slot=%u -> NT=0x%X\n",
            targetPid, slotIndex, st);
        break;
    }

    case IOCTL_HV_DBG_WAIT_EVENT:
    {
        HANDLE caller = PsGetCurrentProcessId();
        if (!HvHookIsDebuggerPid(caller)) {
            DbgPrint("[HV] DBG_WAIT_EVENT: access denied (PID=%llu)\n",
                (ULONG64)(ULONG_PTR)caller);
            status = STATUS_ACCESS_DENIED;
            break;
        }

        if (inputLength < sizeof(HV_DBG_WAIT_REQUEST) ||
            outputLength < sizeof(HV_DBG_WAIT_RESULT)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        PHV_DBG_WAIT_REQUEST pReq = (PHV_DBG_WAIT_REQUEST)inputBuffer;
        ULONG timeoutMs = pReq->TimeoutMs;
        // DebuggerPid 强制使用 caller

        PHV_DBG_WAIT_RESULT pResult = (PHV_DBG_WAIT_RESULT)outputBuffer;
        RtlZeroMemory(pResult, sizeof(HV_DBG_WAIT_RESULT));

        // METHOD_BUFFERED 阻塞 IOCTL: 在 KernelMode 等待没问题,IRP 待在内核态
        NTSTATUS st = HvDbgWaitDequeueEvent(caller, &pResult->Event, timeoutMs);

        if (NT_SUCCESS(st)) {
            pResult->Status = HV_STATUS_SUCCESS;
        } else if (st == STATUS_TIMEOUT) {
            pResult->Status = HV_STATUS_NOT_FOUND;  // 无事件
        } else {
            pResult->Status = HV_STATUS_ERROR;
        }
        bytesReturned = sizeof(HV_DBG_WAIT_RESULT);

        // 不打印日志 (这个 IOCTL 可能高频)
        break;
    }

    case IOCTL_HV_DBG_CONTINUE:
    {
        HANDLE caller = PsGetCurrentProcessId();
        if (!HvHookIsDebuggerPid(caller)) {
            DbgPrint("[HV] DBG_CONTINUE: access denied (PID=%llu)\n",
                (ULONG64)(ULONG_PTR)caller);
            status = STATUS_ACCESS_DENIED;
            break;
        }

        if (inputLength < sizeof(HV_DBG_CONTINUE_REQUEST) ||
            outputLength < sizeof(HV_DBG_RESULT)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        PHV_DBG_CONTINUE_REQUEST pReq = (PHV_DBG_CONTINUE_REQUEST)inputBuffer;
        UINT64 sequence = pReq->Sequence;

        PHV_DBG_RESULT pResult = (PHV_DBG_RESULT)outputBuffer;
        RtlZeroMemory(pResult, sizeof(HV_DBG_RESULT));

        // V1: 仅 trace ack。命中后调试器用户态自己 NtSuspendThread/Resume,
        //     无需驱动同步状态。后续若加 single-step 才需要真的 continue 副作用。
        pResult->Status = HV_STATUS_SUCCESS;
        pResult->Info   = sequence;
        bytesReturned = sizeof(HV_DBG_RESULT);

        DbgPrint("[HV] DBG_CONTINUE: Dbg=%llu Seq=%llu (ack)\n",
            (ULONG64)(ULONG_PTR)caller, sequence);
        break;
    }

    default:
        DbgPrint("[HV] Unknown IOCTL: 0x%X\n", controlCode);
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }
    
    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = bytesReturned;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
#endif // !HV_MINIMAL_MODE
}

/*
 * 阶段 8.4 — 随机生成设备名片段
 *
 * 16 字符大小写字母+数字。KeQuerySystemTime + 当前线程 ID 做种子,
 * RtlRandomEx 滚动。结果写入 g_DeviceLeafBuf / g_DeviceFullBuf /
 * g_SymlinkFullBuf,并把 UNICODE_STRING 指向 Full buf。
 */
static VOID HvBuildRandomDeviceName(VOID)
{
    static const WCHAR k_Alphabet[] =
        L"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

#if HV_USE_FIXED_DEVICE_NAME
    RtlStringCbCopyW(g_DeviceLeafBuf, sizeof(g_DeviceLeafBuf), HV_DEVICE_FIXED_LEAF);
#else
    {
        const ULONG alphabetLen = (ULONG)(sizeof(k_Alphabet) / sizeof(WCHAR) - 1);
        LARGE_INTEGER now;
        ULONG seed;
        ULONG i;

        KeQuerySystemTime(&now);
        seed = (ULONG)(now.LowPart ^ now.HighPart ^
                       ((ULONG)((ULONG_PTR)PsGetCurrentThreadId()) << 8));

        for (i = 0; i < HV_DEVICE_LEAF_LEN; i++) {
            g_DeviceLeafBuf[i] = k_Alphabet[RtlRandomEx(&seed) % alphabetLen];
        }
        g_DeviceLeafBuf[HV_DEVICE_LEAF_LEN] = L'\0';
    }
#endif

    RtlStringCbPrintfW(g_DeviceFullBuf, sizeof(g_DeviceFullBuf),
                       L"\\Device\\%ls", g_DeviceLeafBuf);
    RtlStringCbPrintfW(g_SymlinkFullBuf, sizeof(g_SymlinkFullBuf),
                       L"\\??\\%ls", g_DeviceLeafBuf);

    RtlInitUnicodeString(&g_DeviceName, g_DeviceFullBuf);
    RtlInitUnicodeString(&g_SymbolicLink, g_SymlinkFullBuf);

    DbgPrint("[HV] Random device leaf: %ls\n", g_DeviceLeafBuf);
}

/*
 * 阶段 8.4 — 把设备名片段写入注册表供 GUI 解析
 *
 * 路径: HKLM\Software\NetrSvc\DeviceName (REG_SZ)
 * GUI 用 RegOpenKey 直接路径打开,不走 NtEnumerateKey,所以即使
 * "NetrSvc" key 名被 reg hook 隐藏,直接路径打开仍工作。
 */
static NTSTATUS HvPublishDeviceName(VOID)
{
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING keyPath;
    UNICODE_STRING valueName;
    HANDLE hKey = NULL;
    NTSTATUS status;
    ULONG disposition = 0;
    SIZE_T leafChars;

    RtlInitUnicodeString(&keyPath, HV_DEVICE_REG_PATH);
    InitializeObjectAttributes(&oa, &keyPath,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL, NULL);

    status = ZwCreateKey(&hKey, KEY_ALL_ACCESS, &oa, 0, NULL,
                         REG_OPTION_NON_VOLATILE, &disposition);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[HV] ZwCreateKey NetrSvc failed: 0x%X\n", status);
        return status;
    }

    RtlInitUnicodeString(&valueName, HV_DEVICE_REG_VALUE);
    leafChars = wcslen(g_DeviceLeafBuf);
    status = ZwSetValueKey(hKey, &valueName, 0, REG_SZ,
                           g_DeviceLeafBuf,
                           (ULONG)((leafChars + 1) * sizeof(WCHAR)));
    ZwClose(hKey);

    if (NT_SUCCESS(status)) {
        DbgPrint("[HV] Published device leaf to HKLM\\Software\\%ls\\%ls\n",
                 HV_DEVICE_REG_SUBKEY, HV_DEVICE_REG_VALUE);
    } else {
        DbgPrint("[HV] ZwSetValueKey DeviceName failed: 0x%X\n", status);
    }
    return status;
}

/*
 * 阶段 8.4 — DriverUnload 时清理注册表中的 DeviceName 值
 *
 * 原因:HvPublishDeviceName 用 REG_OPTION_NON_VOLATILE 写,卸载后会残留;
 * 下次启动 GUI 时若在新驱动加载前导入 ioctl.py,会缓存旧 leaf 导致
 * CreateFileW(\\.\old-leaf) FILE_NOT_FOUND。
 */
static VOID HvUnpublishDeviceName(VOID)
{
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING keyPath;
    UNICODE_STRING valueName;
    HANDLE hKey = NULL;
    NTSTATUS status;

    RtlInitUnicodeString(&keyPath, HV_DEVICE_REG_PATH);
    InitializeObjectAttributes(&oa, &keyPath,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL, NULL);

    status = ZwOpenKey(&hKey, KEY_SET_VALUE, &oa);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[HV] ZwOpenKey for unpublish failed: 0x%X\n", status);
        return;
    }

    RtlInitUnicodeString(&valueName, HV_DEVICE_REG_VALUE);
    status = ZwDeleteValueKey(hKey, &valueName);
    ZwClose(hKey);

    if (NT_SUCCESS(status)) {
        DbgPrint("[HV] Unpublished DeviceName from registry\n");
    } else {
        DbgPrint("[HV] ZwDeleteValueKey DeviceName failed: 0x%X\n", status);
    }
}

/*
 * 创建设备对象和符号链接
 */
static NTSTATUS CreateDeviceAndSymlink(PDRIVER_OBJECT DriverObject)
{
    NTSTATUS status;

    // 阶段 8.4 — 设备名启动期随机生成
    HvBuildRandomDeviceName();
    
    // 创建设备对象
    status = IoCreateDevice(
        DriverObject,
        0,
        &g_DeviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &g_DeviceObject
    );
    
    if (!NT_SUCCESS(status)) {
        DbgPrint("[HV] IoCreateDevice failed: 0x%X\n", status);
        return status;
    }
    
    // 创建符号链接
    status = IoCreateSymbolicLink(&g_SymbolicLink, &g_DeviceName);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[HV] IoCreateSymbolicLink failed: 0x%X\n", status);
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
        return status;
    }
    
    // 设置派发函数
    DriverObject->MajorFunction[IRP_MJ_CREATE] = NetrDispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = NetrDispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = NetrDispatchDeviceControl;
    
    // 设置缓冲 IO 标志
    g_DeviceObject->Flags |= DO_BUFFERED_IO;
    g_DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
    
    g_DeviceCreated = TRUE;
    
    DbgPrint("[HV] Device created: %wZ -> %wZ\n", &g_DeviceName, &g_SymbolicLink);
    return STATUS_SUCCESS;
}

/*
 * 删除设备对象和符号链接
 */
static VOID DeleteDeviceAndSymlink(VOID)
{
    if (g_DeviceCreated) {
        IoDeleteSymbolicLink(&g_SymbolicLink);
        
        if (g_DeviceObject) {
            IoDeleteDevice(g_DeviceObject);
            g_DeviceObject = NULL;
        }
        
        g_DeviceCreated = FALSE;
        DbgPrint("[HV] Device deleted\n");
    }
}

// ==================== 诊断函数 ====================

/*
 * 写入诊断信息到文件 (统一接口)
 */
static VOID HvWriteDiagnosticsToFile(VOID)
{
    HANDLE fileHandle;
    OBJECT_ATTRIBUTES objAttr;
    UNICODE_STRING filePath;
    IO_STATUS_BLOCK ioStatus;
    NTSTATUS status;
    CHAR buffer[2048];
    CPU_VENDOR cpuVendor = HvGetCpuVendor();
    
    RtlInitUnicodeString(&filePath, L"\\??\\C:\\HvDiagnostics.txt");
    InitializeObjectAttributes(&objAttr, &filePath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    
    status = ZwCreateFile(
        &fileHandle,
        FILE_WRITE_DATA | SYNCHRONIZE,
        &objAttr,
        &ioStatus,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ,
        FILE_OVERWRITE_IF,
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL, 0
    );
    
    if (NT_SUCCESS(status)) {
        if (cpuVendor == CPU_VENDOR_INTEL) {
            RtlStringCbPrintfA(buffer, sizeof(buffer),
                "=== Hypervisor Diagnostics (Intel VMX) ===\r\n"
                "VM Exit Counter: %llu\r\n"
                "Debug Flag: 0x%llX\r\n"
                "Last Exit Reason: %llu\r\n"
                "External Interrupts: %llu\r\n"
                "CPUID Exits: %llu\r\n"
                "VMCALL Exits: %llu\r\n"
                "MSR Read: %llu\r\n"
                "MSR Write: %llu\r\n"
                "EPT Violations: %llu\r\n"
                "==========================================\r\n",
                g_VmExitCounter,
                g_AsmDebugFlag,
                g_LastExitReason,
                g_ExternalInterruptCount,
                g_ExitCountCpuid,
                g_ExitCountVmcall,
                g_ExitCountMsrRead,
                g_ExitCountMsrWrite,
                g_ExitCountEptViolation);
        }
        else if (cpuVendor == CPU_VENDOR_AMD) {
            RtlStringCbPrintfA(buffer, sizeof(buffer),
                "=== Hypervisor Diagnostics (AMD SVM) ===\r\n"
                "#VMEXIT Counter: %llu\r\n"
                "Debug Flag: 0x%llX\r\n"
                "Last Exit Code: 0x%llX\r\n"
                "CPUID Exits: %llu\r\n"
                "VMMCALL Exits: %llu\r\n"
                "MSR Exits: %llu\r\n"
                "NPF Exits: %llu\r\n"
                "Other Exits: %llu\r\n"
                "=========================================\r\n",
                g_SvmExitCounter,
                g_SvmDebugFlag,
                g_SvmLastExitCode,
                g_SvmExitCountCpuid,
                g_SvmExitCountVmmcall,
                g_SvmExitCountMsr,
                g_SvmExitCountNpf,
                g_SvmExitCountOther);
        }
        else {
            RtlStringCbPrintfA(buffer, sizeof(buffer),
                "=== Hypervisor Diagnostics ===\r\n"
                "Unknown CPU vendor\r\n"
                "==============================\r\n");
        }
        
        ZwWriteFile(fileHandle, NULL, NULL, NULL, &ioStatus, buffer, (ULONG)strlen(buffer), NULL, NULL);
        ZwClose(fileHandle);
    }
}

/*
 * 驱动卸载函数
 */
static VOID HvWaitImageObfuscation(VOID);  // forward decl, body at end of file

// 2026-06-20: unload 卡死诊断 — 每个 stage 入口写一行到 C:\HvUnloadTrace.log
// 用 FILE_WRITE_THROUGH 同步落盘, 文件 OPEN_IF (existing append 不可靠), 每次重新创建 +
// 追加上一次内容? 太复杂 — 改成 OVERWRITE_IF + 每次写整个轨迹字符串. 内存里维护轨迹缓冲.
static CHAR  g_UnloadTrace[2048];
static ULONG g_UnloadTraceLen = 0;

static VOID HvUnloadStageLog(_In_ PCSTR Tag)
{
    HANDLE fileHandle;
    OBJECT_ATTRIBUTES objAttr;
    UNICODE_STRING filePath;
    IO_STATUS_BLOCK ioStatus;
    NTSTATUS status;

    // append 到内存缓冲
    if (g_UnloadTraceLen < sizeof(g_UnloadTrace) - 64) {
        SIZE_T remain = sizeof(g_UnloadTrace) - g_UnloadTraceLen;
        NTSTATUS rs = RtlStringCbPrintfA(
            g_UnloadTrace + g_UnloadTraceLen, remain,
            "%s\r\n", Tag);
        if (NT_SUCCESS(rs)) {
            for (ULONG i = g_UnloadTraceLen; i < sizeof(g_UnloadTrace); i++) {
                if (g_UnloadTrace[i] == '\0') {
                    g_UnloadTraceLen = i;
                    break;
                }
            }
        }
    }

    RtlInitUnicodeString(&filePath, L"\\??\\C:\\HvUnloadTrace.log");
    InitializeObjectAttributes(&objAttr, &filePath,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL, NULL);
    // FILE_OVERWRITE_IF: 文件存在时 overwrite, 不存在时 create
    // FILE_WRITE_THROUGH: 同步落盘, 不缓存在 cache manager
    status = ZwCreateFile(
        &fileHandle,
        FILE_WRITE_DATA | SYNCHRONIZE,
        &objAttr,
        &ioStatus,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ,
        FILE_OVERWRITE_IF,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_WRITE_THROUGH,
        NULL, 0);
    if (NT_SUCCESS(status)) {
        ZwWriteFile(fileHandle, NULL, NULL, NULL, &ioStatus,
                    g_UnloadTrace, g_UnloadTraceLen, NULL, NULL);
        ZwClose(fileHandle);
    }
}

VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);

    DbgPrint("[HV] DriverUnload called\n");

    // Phase 2: 卸载时清空 license 状态(下次加载需重新提交,避免残留)
    HvLicenseReset();

    // 立刻写第一行: "ENTER" — 如果卡死在 unload 第一句之前, 文件里只有 ENTER
    g_UnloadTraceLen = 0;
    g_UnloadTrace[0] = '\0';
    HvUnloadStageLog("S00 ENTER DriverUnload");

    HvUnloadStageLog("S01 BEFORE HvVmExitCleanup");
    HvVmExitCleanup();
    HvUnloadStageLog("S01 AFTER  HvVmExitCleanup");

#if !HV_MINIMAL_MODE
    HvUnloadStageLog("S02 BEFORE HvWaitImageObfuscation");
    HvWaitImageObfuscation();
    HvUnloadStageLog("S02 AFTER  HvWaitImageObfuscation");

    // 2026-06-20 方案 A: 卸载前 terminate 所有注册的 debugger 进程, 防止它们
    // 在驱动卸载后失去保护时被反作弊 / CE / Spy++ 看穿真名。必须在 HvHookCleanup
    // (卸 ObCallback) 和 DeleteDeviceAndSymlink 之前 — 此时 hypervisor + hook 还在,
    // PsSetCreateProcessNotifyRoutineEx 回调还能跑, HvDbgClearAllForDebugger 会
    // 自动清 HWBP 列表。
    HvUnloadStageLog("S02b BEFORE HvHookTerminateAllDebuggers");
    HvHookTerminateAllDebuggers();
    HvUnloadStageLog("S02b AFTER  HvHookTerminateAllDebuggers");
#endif

    HvUnloadStageLog("S03 BEFORE DeleteDeviceAndSymlink");
    DeleteDeviceAndSymlink();
    HvUnloadStageLog("S03 AFTER  DeleteDeviceAndSymlink");

#if !HV_MINIMAL_MODE
    HvUnloadStageLog("S04 BEFORE HvUnpublishDeviceName");
    HvUnpublishDeviceName();
    HvUnloadStageLog("S04 AFTER  HvUnpublishDeviceName");

    HvUnloadStageLog("S05 BEFORE HvWriteDiagnosticsToFile");
    HvWriteDiagnosticsToFile();
    HvUnloadStageLog("S05 AFTER  HvWriteDiagnosticsToFile");

    HvUnloadStageLog("S06 BEFORE HvPrintDebugStats");
    HvPrintDebugStats();
    HvUnloadStageLog("S06 AFTER  HvPrintDebugStats");
#endif

    // 打印电源管理状态
    //if (HvPowerIsInitialized()) {
    //    DbgPrint("[HV] Power Management Status:\n");
    //    HvPowerPrintStatus();
    //}

#if !HV_MINIMAL_MODE
    // 打印驱动隐藏状态（EPT Hook 方式）
    DbgPrint("[HV] Driver Hide Status (EPT/NPT Hook):\n");
    EptHookPrintHiddenDrivers();

    // 打印注入框架状态
    if (HvInjectionIsInitialized()) {
        DbgPrint("[HV] Injection Framework Status:\n");
        HvInjectionPrintStatus();
    }
#endif

#if !HV_MINIMAL_MODE
    // ========================================
    // 重要：清理顺序必须正确！
    // 0. 先清理电源管理（注销回调）
    // 1. 先清理所有 EPT/NPT Hook（在 Hypervisor 运行时）
    // 2. 然后清理 Hook 管理器
    // 3. 最后清理 Hypervisor
    //
    // 原因：EPT/NPT Hook 依赖于 Hypervisor，如果先关闭 Hypervisor，
    // 被 Hook 的函数会执行无效代码，导致蓝屏！
    // ========================================

    // 清理电源管理模块（先注销回调，防止在卸载过程中触发）
    //DbgPrint("[HV] Cleaning up Power Management...\n");
    //HvPowerCleanup();

    HvUnloadStageLog("S07 BEFORE HvHookRemoveDriverHideHook");
    HvHookRemoveDriverHideHook();
    HvUnloadStageLog("S07 AFTER  HvHookRemoveDriverHideHook");

    // 清理文件隐藏 Hook（必须在 Hypervisor 关闭之前）
#if ENABLE_FILE_HIDE_HOOK
    // DbgPrint("[HV] Cleaning up File Hide Hook...\n");
    // HvHookRemoveFileHideHook();
#endif

    // 清理网卡流量伪造模块
    //DbgPrint("[HV] Cleaning up Network Hook Module...\n");
    //HvNetHookCleanup();

    // 清理注入框架（先移除内存隐藏 Hook）
#if ENABLE_INJECTION_FRAMEWORK
    DbgPrint("[HV] Removing Memory Hide Hook...\n");
    HvRemoveMemoryHideHook();

    DbgPrint("[HV] Cleaning up Injection Framework...\n");
    HvInjectionCleanup();
#endif

    HvUnloadStageLog("S10 BEFORE HvHookCleanup");
    HvHookCleanup();
    HvUnloadStageLog("S10 AFTER  HvHookCleanup");

    HvUnloadStageLog("S11 BEFORE HvDbgCleanup");
    HvDbgCleanup();
    HvUnloadStageLog("S11 AFTER  HvDbgCleanup");

    HvUnloadStageLog("S12 BEFORE HvPhysAccessCleanup");
    HvPhysAccessCleanup();
    HvUnloadStageLog("S12 AFTER  HvPhysAccessCleanup");

    HvUnloadStageLog("S13 BEFORE HvVtRootCleanupAll");
    HvVtRootCleanupAll();
    HvUnloadStageLog("S13 AFTER  HvVtRootCleanupAll");
#else
    DbgPrint("[HV] HV_MINIMAL_MODE: skipping all subsystem cleanups (nothing was initialized)\n");
#endif

    HvUnloadStageLog("S14 BEFORE HvCleanup (VMXOFF all CPUs)");
    HvCleanup();
    HvUnloadStageLog("S14 AFTER  HvCleanup");

    HvUnloadStageLog("S15 BEFORE HvPebCloakShutdown");
    HvPebCloakShutdown();
    HvUnloadStageLog("S15 AFTER  HvPebCloakShutdown");

    HvUnloadStageLog("S15.5 BEFORE HvVwatchShutdown");
    HvVwatchShutdown();
    HvUnloadStageLog("S15.5 AFTER  HvVwatchShutdown");

    HvUnloadStageLog("S16 BEFORE HvUtilsCleanupHostTssAll");
    HvUtilsCleanupHostTssAll();
    HvUnloadStageLog("S16 AFTER  HvUtilsCleanupHostTssAll");

    HvUnloadStageLog("S99 DONE  Driver unloaded - all stages OK");
    DbgPrint("[HV] Driver unloaded\n");
}

/*
 * 阶段 8.3 — PE 头扰乱
 *
 * DriverEntry 末尾抹零 DOS header 的 e_magic/e_lfanew 与 NT headers 的 Signature/
 * FileHeader/SectionHeader[]，让用户态 EnumDeviceDrivers + ReadProcessMemory
 * 扫 4D 5A "MZ" / 50 45 "PE" 失配。代价: WinDbg `lm m Netr` 无法解析符号。
 */
static VOID HvObfuscateImageHeaders(_In_ PDRIVER_OBJECT DriverObject)
{
    PUCHAR  base;
    SIZE_T  size;
    SIZE_T  mapSize;
    PHYSICAL_ADDRESS pa;
    PVOID   rwMap;
    PIMAGE_DOS_HEADER_INJ dosOrig;
    PIMAGE_DOS_HEADER_INJ dosRw;
    ULONG   ntOffset;

    if (!DriverObject || !DriverObject->DriverStart || DriverObject->DriverSize < 0x1000) {
        return;
    }

    base = (PUCHAR)DriverObject->DriverStart;
    size = DriverObject->DriverSize;
    mapSize = PAGE_SIZE;
    if (mapSize > size) mapSize = size;

    // PE header 那一页被加载器映射为 RO。绕路: MmGetPhysicalAddress 拿到 HPA →
    // MmMapIoSpace 拿一份 RW 别名映射 → 通过别名写 → 卸载。原 VA 仍 RO,PG 看不到
    // 我们改过 PTE(没动 PTE,只是用了另一条到同 HPA 的映射)。
    pa = MmGetPhysicalAddress(base);
    if (pa.QuadPart == 0) {
        DbgPrint("[HV] PE header obfuscation: MmGetPhysicalAddress returned 0\n");
        return;
    }

    rwMap = MmMapIoSpace(pa, mapSize, MmCached);
    if (!rwMap) {
        DbgPrint("[HV] PE header obfuscation: MmMapIoSpace failed\n");
        return;
    }

    dosOrig = (PIMAGE_DOS_HEADER_INJ)base;
    ntOffset = (ULONG)dosOrig->e_lfanew;

    dosRw = (PIMAGE_DOS_HEADER_INJ)rwMap;

    if (ntOffset >= sizeof(IMAGE_DOS_HEADER_INJ) &&
        ntOffset + sizeof(IMAGE_NT_HEADERS64_INJ) < mapSize) {
        PIMAGE_NT_HEADERS64_INJ ntRw =
            (PIMAGE_NT_HEADERS64_INJ)((PUCHAR)rwMap + ntOffset);
        ULONG nSec = ntRw->FileHeader.NumberOfSections;
        PIMAGE_SECTION_HEADER_INJ secTable =
            (PIMAGE_SECTION_HEADER_INJ)((PUCHAR)&ntRw->OptionalHeader +
                                        ntRw->FileHeader.SizeOfOptionalHeader);
        if (nSec > 64) nSec = 64;
        if ((PUCHAR)secTable + nSec * sizeof(IMAGE_SECTION_HEADER_INJ) <=
            (PUCHAR)rwMap + mapSize) {
            RtlZeroMemory(secTable, nSec * sizeof(IMAGE_SECTION_HEADER_INJ));
        }
        ntRw->Signature = 0;
        ntRw->FileHeader.Machine = 0;
        ntRw->FileHeader.NumberOfSections = 0;
        ntRw->OptionalHeader.Magic = 0;
        ntRw->OptionalHeader.AddressOfEntryPoint = 0;
    }

    RtlZeroMemory(dosRw, sizeof(IMAGE_DOS_HEADER_INJ));

    MmUnmapIoSpace(rwMap, mapSize);
    DbgPrint("[HV] PE header obfuscation: applied via RW remap (HPA=0x%llX)\n",
             (UINT64)pa.QuadPart);
}

/*
 * 阶段 8.3 — 延迟调度 PE 头扰乱
 *
 * 必须延迟而不能在 DriverEntry 末尾直接抹零:加载器在 DriverEntry 返回后会调
 * IopLoadDriver -> MiFreeDriverInitialization -> MiSnapDriverRange,后者要走
 * 我们的 PE header 找 INIT 段并释放。如果 header 提前抹零, MiSnapDriverRange
 * 会 null-deref (rcx=0x5A4D "MZ" 命中失败 → rax=0 → mov r11d,[rax+0x38] → AV)
 * 触发 0x1000007E SYSTEM_THREAD_EXCEPTION_NOT_HANDLED。
 *
 * 方案:派生系统线程睡眠 10 秒后再抹。DriverUnload 时 KeSetEvent 唤醒线程让它
 * 提前退出(否则 unload 会被阻塞最多 10 秒)。
 */

static KEVENT  g_ObfAbortEvent;
static PETHREAD g_ObfThread = NULL;

static VOID HvObfuscateThreadRoutine(_In_ PVOID Context)
{
    LARGE_INTEGER timeout;
    PDRIVER_OBJECT drv = (PDRIVER_OBJECT)Context;
    NTSTATUS s;

    // 10 秒相对超时(负值,100ns 单位)
    timeout.QuadPart = -100000000LL;
    s = KeWaitForSingleObject(&g_ObfAbortEvent, Executive,
                              KernelMode, FALSE, &timeout);

    if (s == STATUS_TIMEOUT && drv) {
        DbgPrint("[HV] Obfuscation timer fired, applying now\n");
        HvObfuscateImageHeaders(drv);
    } else {
        DbgPrint("[HV] Obfuscation aborted (driver unloading)\n");
    }

    PsTerminateSystemThread(STATUS_SUCCESS);
}

static VOID HvScheduleImageObfuscation(_In_ PDRIVER_OBJECT DriverObject)
{
    HANDLE handle = NULL;
    NTSTATUS s;

    KeInitializeEvent(&g_ObfAbortEvent, NotificationEvent, FALSE);

    s = PsCreateSystemThread(&handle, THREAD_ALL_ACCESS, NULL, NULL, NULL,
                             HvObfuscateThreadRoutine, DriverObject);
    if (!NT_SUCCESS(s)) {
        DbgPrint("[HV] HvScheduleImageObfuscation: PsCreateSystemThread failed 0x%X\n", s);
        return;
    }

    ObReferenceObjectByHandle(handle, THREAD_ALL_ACCESS, NULL,
                              KernelMode, (PVOID*)&g_ObfThread, NULL);
    ZwClose(handle);
    DbgPrint("[HV] PE header obfuscation scheduled for +10s\n");
}

static VOID HvWaitImageObfuscation(VOID)
{
    if (g_ObfThread) {
        KeSetEvent(&g_ObfAbortEvent, IO_NO_INCREMENT, FALSE);
        KeWaitForSingleObject(g_ObfThread, Executive, KernelMode, FALSE, NULL);
        ObDereferenceObject(g_ObfThread);
        g_ObfThread = NULL;
    }
}

/*
 * 驱动入口函数 (支持 Intel VMX 和 AMD SVM)
 */
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    NTSTATUS status = STATUS_SUCCESS;
    CPU_VENDOR cpuVendor;

    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrint("\n\n");
    DbgPrint("[HV] ========================================\n");
    DbgPrint("[HV] SimpleHypervisor DriverEntry\n");
    DbgPrint("[HV] Supports: Intel VMX + AMD SVM\n");
    DbgPrint("[HV] ========================================\n");

    DriverObject->DriverUnload = DriverUnload;

    // 优先初始化全局 OS 版本 (其他模块的 Win11 24H2/KVAS/CR4.CET 兼容判断都依赖此)
    (VOID)HvUtilsInitializeOsVersion();

    // P0-1 (2026-05-31): 解析 PsInitialSystemProcess->DirectoryTableBase 得到 hardware-loaded
    // System CR3, 用于 HOST_CR3。避开 Win11 KVAS 下 __readcr3() 返回 trampoline shadow
    // CR3 导致 vmexit 后 host triple fault 的死亡路径。必须在 HvInitialize 之前。
    (VOID)HvUtilsInitializeSystemCr3();

    // P0-4 (2026-05-31): 初始化独立 host IDT, 替换 vector 2 (NMI) / 18 (#MC) 指向
    // 自定 stub。避开 vmx-root 模式 NMI 进 KiNmiInterrupt 用错位 KPRCB 状态导致
    // Win11 24H2 KCFG 校验 triple fault。必须在 HvInitialize / VMCS setup 之前。
    (VOID)HvUtilsInitializeHostIdt();

    // P0-6 (2026-06-16): 0x1AA 全面修复 — per-CPU 独立 host TSS + IST 栈 + 复制 GDT。
    // 内部按 HV_USE_HOST_TSS_OVERRIDE 守卫, 关闭时是 no-op。必须在 HvInitialize
    // (VMCS setup) 之前 — VMCS 写 HOST_TR_BASE/HOST_GDTR_BASE 时要能从
    // HvUtilsGetHostCpuCtx 拿到已初始化的 per-CPU TSS+GDT。
    (VOID)HvUtilsInitializeHostTssAll();

    // P0-5 (2026-05-31): KeRegisterNmiCallback 诊断 non-root 模式 NMI 频率。
    // DriverUnload 必须 deregister, 否则 BSOD。
    (VOID)HvVmExitInitialize();

    // ========================================
    // 创建用户态通信设备 (必须在虚拟化检查之前,确保设备始终存在)
    // 路径: \\.\<random-16-chars> (阶段 8.4 动态命名)
    // GUI 通过 HKLM\Software\NetrSvc\DeviceName 解析
    // ========================================
    DbgPrint("[HV] Creating communication device...\n");
    status = CreateDeviceAndSymlink(DriverObject);
    if (NT_SUCCESS(status)) {
        DbgPrint("[HV] Communication device created: \\\\.\\%ls\n", g_DeviceLeafBuf);
#if !HV_MINIMAL_MODE
        // 注册表发布与 RegistryHook 隐藏列表 — minimal mode 全部跳过
        if (NT_SUCCESS(HvPublishDeviceName())) {
            HvRegHookAddHiddenKeyName(HV_DEVICE_REG_SUBKEY);
            DbgPrint("[HV] Device name published; '%ls' key hidden from enumeration\n",
                     HV_DEVICE_REG_SUBKEY);
        }
#else
        DbgPrint("[HV] HV_MINIMAL_MODE: registry publish skipped (device only)\n");
#endif
    } else {
        DbgPrint("[HV] Failed to create communication device: 0x%X\n", status);
    }

    // 检测 CPU 厂商和虚拟化支持
    cpuVendor = HvDetectCpuVendor();
    DbgPrint("[HV] Checking virtualization support...\n");

    if (!HvCheckVirtualizationSupport()) {
        DbgPrint("[HV] Virtualization not supported!\n");
        return STATUS_SUCCESS;
    }
    
    if (cpuVendor == CPU_VENDOR_INTEL) {
        DbgPrint("[HV] Intel VMX support: PASSED\n");
    } else if (cpuVendor == CPU_VENDOR_AMD) {
        DbgPrint("[HV] AMD SVM support: PASSED\n");
    }

    // 全CPU虚拟化
    DbgPrint("[HV] Initializing hypervisor on ALL %d CPUs...\n", 
        KeQueryActiveProcessorCount(NULL));
    
    // 重置全局调试变量
    if (cpuVendor == CPU_VENDOR_INTEL) {
        g_AsmDebugFlag = 0;
        g_VmExitCounter = 0;
        g_LastExitReason = 0;
        g_VmInstructionError = 0;
        g_UnknownExitReason = 0;
    }
    // AMD 调试变量在 AsmSvm.asm 中初始化

    // P125 (2026-06-25): PEB cloak manager 初始化 (新 EPT 实例分配在 per-CPU
    // HvSetupEpt 内做, 此处只 init manager 全局结构). 必须在 HvInitialize 之前.
    NTSTATUS pebCloakSt = HvPebCloakInitialize();
    if (!NT_SUCCESS(pebCloakSt)) {
        DbgPrint("[HV] HvPebCloakInitialize failed: 0x%X (PEB spoof 将不可用)\n", pebCloakSt);
    }

    // P128 (2026-06-25): 虚拟硬件断点 manager 初始化 (复用 EptPebSpoof,
    // 实际 EPT 实例由 PebCloak 那一份维护).
    NTSTATUS vwatchSt = HvVwatchInitialize();
    if (!NT_SUCCESS(vwatchSt)) {
        DbgPrint("[HV] HvVwatchInitialize failed: 0x%X (虚拟硬断将不可用)\n", vwatchSt);
    }

    // 调用 HvInitialize() 在所有 CPU 上初始化
    status = HvInitialize();
    
    if (NT_SUCCESS(status)) {
        // P3-15 (2026-05-31): vmlaunch 后 driver 在 guest mode 跑。
        // 实证:同一 __try 块内连续 DbgPrint,第一个成功第二个卡死 →
        // SEH 不可靠 (RtlUnwindEx 也是 indirect call, 在 guest mode 跟着崩 →
        // double fault → triple fault → 整机卡死)。
        // 唯一稳定方案:vmlaunch 后**绝对不调任何 DbgPrint**。
        // 用 g_AsmDebugFlag 数字传递状态,后续 IOCTL 路径读 flag。
        g_AsmDebugFlag = 360;  // marker: NT_SUCCESS path entered (no DbgPrint)
        // P3-15 build verification marker — 如果 dmesg 看到这条,说明 P3-15 build 生效
        DbgPrint("[HV] [P3-15-MARKER] NT_SUCCESS entered, all DbgPrint after this disabled\n");

        // P0-6 (2026-05-31): 推迟后续模块初始化 1 秒, 等所有 12 CPU 经历过若干次
        // vmexit/vmresume 稳态后, 再启动 Hook / VtRoot / Cr3Snoop / Dbg。
        //
        // 原因: P3-14 串行 vmlaunch 后 IsActive=TRUE, 但 CPU 11 刚 launch 0us,
        // 还未 vmexit 过 — vmexit handler 路径完全没冷启 (TLB 未热、per-CPU 数据
        // 未触达 vmread/vmwrite)。此时 HvHookInitialize → KeIpiGenericCall(invept)
        // 在 IPI_LEVEL 等所有 CPU 同步, 若 CPU 11 此刻正撞上首次 vmexit, IPI
        // 等不到 → 死锁 → 整机卡死。
        //
        // 1 秒足够让 Win11 12 CPU 各跑 ~100 个 vmexit (clock tick / syscall storm),
        // 进入稳态。期间 hypervisor 透明运行, 不做任何主动操作。
        {
            LARGE_INTEGER delay;
            delay.QuadPart = -10000000LL;  // 1 second relative
            KeDelayExecutionThread(KernelMode, FALSE, &delay);
            g_AsmDebugFlag = 365;  // marker: 1s delay 完成, 准备 init hook 等
        }

        // ========================================
        // 初始化电源管理模块（必须在 Hypervisor 初始化后立即执行）
        // 
        // 功能：
        //   - 在系统睡眠前自动清理 Hypervisor 和 Hook
        //   - 在系统唤醒后自动恢复 Hypervisor 和 Hook
        //   - 防止睡眠唤醒后 EPT/NPT Hook 导致蓝屏
        // ========================================
        DbgPrint("[HV] Initializing Power Management...\n");
 /*       if (NT_SUCCESS(HvPowerInitialize(DriverObject))) {
            DbgPrint("[HV] Power Management initialized - Sleep/Resume safe!\n");
        } else {
            DbgPrint("[HV] WARNING: Power Management init failed - Sleep may cause BSOD!\n");
        }*/
        
        // 初始化 Hook 管理器（使用统一抽象层，自动检测 CPU 类型）
#if HV_MINIMAL_MODE
        DbgPrint("[HV] HV_MINIMAL_MODE=1 — 跳过 Hook Manager 与所有可选功能子系统\n");
        DbgPrint("[HV]   已禁用: EPT/NPT Hook / 驱动隐藏 / 文件隐藏 / 注入框架 / HWBP /\n");
        DbgPrint("[HV]            PS2+xHCI 输入注入 / xHCI EPT trap / 网络伪造 /\n");
        DbgPrint("[HV]            CR3 snoop / VtRoot V2 / 物理访问 / PE 头扰乱\n");
        DbgPrint("[HV]   仅保留: VMX/SVM 启动 + EPT/NPT 身份映射 + VM Exit 透传骨架\n");
#else
        DbgPrint("[HV] Initializing Hook Manager...\n");
        if (NT_SUCCESS(HvHookInitialize())) {
            DbgPrint("[HV] Hook Manager initialized successfully (Backend: %s)\n",
                HvHookGetBackendType() == CPU_VENDOR_INTEL ? "Intel EPT" : "AMD NPT");

            // 初始化物理页直通模块（必须在任何 IOCTL 内存路径之前）
            // - 走目标 CR3 页表的 R/W/Alloc，完全避开 Ke*/Zw*
            // - 自旋锁/记录链表必须在第一个 IOCTL 到达前就绪
            DbgPrint("[HV] Initializing HvPhysAccess module...\n");
            HvPhysAccessInitialize();
            DbgPrint("[HV] HvPhysAccess initialized\n");

            // 阶段 8.5: 真·VT 无痕 R/W gadget V2 (独立 PT 岛)
            // ---------------------------------------------------------------
            // V1 (PTE 劫持) 已下线 —— 见 HvVtRoot.c 文件头注释。
            //
            // V2 设计:在 kernel CR3 的一个未使用 PML4 槽位安装完全私有的
            //   PDPT → PD → PT 链。PT 内每个 CPU 占一个 entry,空闲态指向
            //   一张静态 backing 页。Scratch VA 不在任何 VAD / 系统 PTE /
            //   PFN 反向映射中,MM zero-page worker 看不见 → 不会再覆写
            //   nt 代码页。
            //
            // 失败不致命:fallback 路径 (HvPhysAccess 的 MmMapIoSpace + 自管
            // 页表 walk) 在 g_VtRootEnabled=FALSE 时自动接管。严禁回落到
            // KeStackAttachProcess / ZwReadVirtualMemory / MmCopyVirtualMemory
            // 任何 Ps*/Ke*Attach* API —— 会被反作弊 hook 检测。
            DbgPrint("[HV] Initializing HvVtRoot V2 (Independent PT Island)...\n");
            {
                NTSTATUS vtStatus = HvVtRootInitializeAll();
                if (NT_SUCCESS(vtStatus)) {
                    DbgPrint("[HV] HvVtRoot V2 enabled\n");
                } else {
                    DbgPrint("[HV] HvVtRoot V2 init failed 0x%X (fallback path active)\n",
                             vtStatus);
                }
            }

            HvCr3SnoopEnable();
            DbgPrint("[HV] CR3 snoop ring enabled\n");

            DbgPrint("[HV] Initializing HvDebugger module...\n");
            HvDbgInitialize();
            
            // 示例：隐藏进程
            // HvHookHideProcessByName(L"explorer.exe");
            
            // ========================================
            // 初始化驱动隐藏模块（基于 EPT/NPT Hook，完美隐身）
            // 
            // 特点：
            //   - 不修改 PsLoadedModuleList（不断链）
            //   - 不触发 PatchGuard
            //   - Hook NtQuerySystemInformation 过滤 SystemModuleInformation
            //   - Hook ObReferenceObjectByName 阻止按名称查找驱动
            // ========================================
            DbgPrint("[HV] Initializing Driver Hide Module (EPT/NPT Hook)...\n");

            // ========================================
            // 2026-05-31 临时禁用 driver hide hook (Win11 真机验证 P1)
            // 见 [[netr_win11_hang_root_cause]] / [[netr_hyperdbg_compare_pt_sharing]]:
            //   Win11 NtQSI ~50-200/s (Defender+DiagTrack+Widgets+Search) +
            //   EPT split PT 跨核策略冲突 → ~10 秒内全核 root mode 死循环 → 卡死。
            //
            // P1-3 per-CPU EPT split PT 已实现但未在此机充分验证, 先关掉这个 hook
            // 让其余 hypervisor 功能跑稳。要重新启用: 把 #if 0 改回 #if 1。
            // ========================================
            // 安装驱动隐藏 Hook
#if 0  // 2026-05-31 临时禁用,Win11 卡死隔离
            if (NT_SUCCESS(HvHookInstallDriverHideHook())) {
                DbgPrint("[HV] Driver Hide Hooks installed (EPT/NPT method)\n");

#if ENABLE_DRIVER_SELF_HIDE
                // 隐藏自身驱动（使用安全的 EPT/NPT Hook 方式）
                DbgPrint("[HV] ========================================\n");
                DbgPrint("[HV] HIDING DRIVER (EPT/NPT Hook Method)\n");
                DbgPrint("[HV] - No PsLoadedModuleList modification\n");
                DbgPrint("[HV] - PatchGuard safe\n");
                DbgPrint("[HV] - Anti-cheat resistant\n");
                DbgPrint("[HV] ========================================\n");

                // 使用 EPT/NPT Hook 方式隐藏驱动
                if (NT_SUCCESS(HvHookHideDriverSafe(DriverObject))) {
                    DbgPrint("[HV] Driver hidden successfully!\n");

                    // 通知电源管理模块：驱动隐藏已启用
                    // 这样在唤醒后会自动重新隐藏驱动

                    // 同时隐藏驱动文件
                    //HvHookHideDriverFile(L"Netr.sys");

                    // 打印隐藏状态
                    EptHookPrintHiddenDrivers();
                } else {
                    DbgPrint("[HV] Driver hiding failed\n");
                }
#endif
            } else {
                DbgPrint("[HV] Driver Hide Hooks installation failed\n");
            }
#else
            DbgPrint("[HV] Driver Hide Hooks DISABLED (Win11 P1 isolation, see netr_win11_hang_root_cause)\n");
#endif

            // ========================================
            // 初始化文件隐藏模块（可选）
            // 
            // 功能：
            //   - Hook NtQueryDirectoryFile 过滤驱动文件
            //   - 在文件浏览器中隐藏 .sys 文件
            // ========================================
#if ENABLE_FILE_HIDE_HOOK
            // 阶段 8.1 重启：cmpxchg64/INVEPT root-mode/MTF active 三处修复已落地，
            // 之前 NtQueryDirectoryFile hook 卡死风险已消除，可重新启用。
            DbgPrint("[HV] Initializing File Hide Hook...\n");
            if (NT_SUCCESS(HvHookInstallFileHideHook())) {
                DbgPrint("[HV] File Hide Hook installed successfully\n");
                HvHookHideDriverFile(L"Netr.sys");
            } else {
                DbgPrint("[HV] File Hide Hook installation failed\n");
            }
#endif

            // ========================================
            // 阶段 8.2 注册表枚举隐藏
            // ========================================
            // BISECT 2026-05-21 #78: services.exe 启动期 BSOD 0x1E
            // (0xC0000096 在 NonPagedPool RIP),栈极浅 KiPageFault → 野指针。
            // 高度怀疑 NtEnumerateKey trampoline 损坏(ZwEnumerateKey 是 SSDT
            // 短 stub,EPT-hook 完整模式可能解码越界)。先禁用本阶段确认。
#if 0
            DbgPrint("[HV] Initializing Registry Hook...\n");
            if (NT_SUCCESS(HvRegHookInitialize())) {
                if (NT_SUCCESS(HvRegHookInstall())) {
                    HvRegHookAddHiddenKeyName(L"Netr");
                    DbgPrint("[HV] Registry hook installed; hiding 'Netr' key\n");
                } else {
                    DbgPrint("[HV] Registry hook install failed\n");
                }
            }
#else
            DbgPrint("[HV] Registry Hook DISABLED (BISECT #78)\n");
#endif
            
            // ========================================
            // 初始化无痕注入框架（内核态无痕）
            // ========================================
// #if ENABLE_INJECTION_FRAMEWORK
//             DbgPrint("[HV] Initializing Injection Framework...\n");
//             if (NT_SUCCESS(HvInjectionInitialize())) {
//                 DbgPrint("[HV] Injection Framework initialized successfully\n");
                
//                 // 安装内存隐藏 Hook（NtQueryVirtualMemory）
//                 DbgPrint("[HV] Installing Memory Hide Hook (NtQueryVirtualMemory)...\n");
//                 if (NT_SUCCESS(HvInstallMemoryHideHook())) {
//                     DbgPrint("[HV] Memory Hide Hook installed - Kernel-level stealth enabled!\n");
//                 } else {
//                     DbgPrint("[HV] Memory Hide Hook installation failed\n");
//                 }
                
//                 // ========================================
//                 // 使用示例（注释掉，仅供参考）
//                 // ========================================
//                 // 
//                 // 示例 1: DLL 注入（内核态无痕）
//                 // PVOID dllBuffer = ...;  // DLL 文件内容
//                 // SIZE_T dllSize = ...;   // DLL 文件大小
//                 // HV_INJECTION_RESULT result;
//                 // HvInjectDll(TargetPid, dllBuffer, dllSize, &result);
//                 // 
//                 // // 启用内核态无痕隐藏（擦除PE头 + 过滤查询 + PEB解链）
//                 // HvHideInjectedMemory(TargetPid, result.ModuleBase, result.ModuleSize);
//                 //
//                 // 示例 2: Shellcode 注入
//                 // UCHAR shellcode[] = { ... };
//                 // PVOID outAddr;
//                 // HvInjectShellcode(TargetPid, shellcode, sizeof(shellcode), NULL, &outAddr);
//                 // 
//                 // // 隐藏 Shellcode 内存
//                 // HvHideInjectedMemory(TargetPid, outAddr, sizeof(shellcode));
//                 //
//                 // 示例 3: 内存读写
//                 // UCHAR buffer[256];
//                 // HvMemoryRead(TargetPid, (PVOID)0x12345678, buffer, sizeof(buffer), NULL);
//                 // HvMemoryWrite(TargetPid, (PVOID)0x12345678, buffer, sizeof(buffer), NULL);
//                 //
//                 // ========================================
                
//             } else {
//                 DbgPrint("[HV] Injection Framework initialization failed\n");
//             }
// #endif
            
            // 初始化网卡流量伪造模块（注释掉）
            //DbgPrint("[HV] Initializing Network Hook Module...\n");
            //if (NT_SUCCESS(HvNetHookInitialize())) {
            //    DbgPrint("[HV] Network Hook Module initialized successfully\n");
            //    
            //    // ========================================
            //    // 使用示例：伪造网卡流量
            //    // 注意：这些函数会互相覆盖，只选择一种模式！
            //    // ========================================
            //    
            //    // 方式1：设置固定的流量值（所有网卡显示相同的值）
            //     HvNetSetFakeTrafficFixed(
            //         1024ULL * 1024 * 100,   // 发送: 100 MB
            //         1024ULL * 1024 * 200    // 接收: 200 MB
            //     );
            //    
            //    // 方式2：按比例缩小显示（显示真实值的 10%）
            //    //HvNetSetFakeTrafficScale(10, 10);
            //    
            //    // 方式3：从真实值中减去指定量
            //    // HvNetSetFakeTrafficSubtract(
            //    //     1024ULL * 1024 * 500,   // 减去发送 500 MB
            //    //     1024ULL * 1024 * 500    // 减去接收 500 MB
            //    // );
            //    
            //    // 方式4：伪造网卡速率（Mbps）
            //    // HvNetSetFakeSpeed(100, 100);  // 显示 100 Mbps
            //    
            //    // 启用伪造（先注释掉测试 Hook 是否正常）
            //    // HvNetEnableFake();
            //    
            //    // 打印当前配置信息
            //    //HvNetPrintInfo();
            //    
            //    DbgPrint("[HV] NOTE: Fake is DISABLED for testing. Uncomment HvNetEnableFake() to enable.\n");
            //    
            //} else {
            //    DbgPrint("[HV] Network Hook Module initialization failed\n");
            //}
        } else {
            DbgPrint("[HV] Hook Manager initialization failed\n");
        }
#endif // !HV_MINIMAL_MODE
    } else {
        DbgPrint("[HV] ========================================\n");
        DbgPrint("[HV] FULL CPU VIRTUALIZATION FAILED: 0x%X\n", status);
        if (cpuVendor == CPU_VENDOR_INTEL) {
            DbgPrint("[HV] AsmDebugFlag: %llu\n", g_AsmDebugFlag);
            DbgPrint("[HV] VM Exit Counter: %llu\n", g_VmExitCounter);
            DbgPrint("[HV] Last Exit Reason: %llu\n", g_LastExitReason);
            DbgPrint("[HV] VM Instruction Error: %llu\n", g_VmInstructionError);
        } else {
            DbgPrint("[HV] SvmDebugFlag: %llu\n", g_SvmDebugFlag);
            DbgPrint("[HV] #VMEXIT Counter: %llu\n", g_SvmExitCounter);
            DbgPrint("[HV] Last Exit Code: 0x%llX\n", g_SvmLastExitCode);
        }
        DbgPrint("[HV] ========================================\n");
    }
    
    DbgPrint("[HV] Supported IOCTLs:\n");
    DbgPrint("[HV]   - IOCTL_HV_GET_STATUS      (0x%X)\n", IOCTL_HV_GET_STATUS);
    DbgPrint("[HV]   - IOCTL_HV_HIDE_PROCESS    (0x%X)\n", IOCTL_HV_HIDE_PROCESS);
    DbgPrint("[HV]   - IOCTL_HV_HIDE_DRIVER     (0x%X)\n", IOCTL_HV_HIDE_DRIVER);
    DbgPrint("[HV]   - IOCTL_HV_MEMORY_READ     (0x%X)\n", IOCTL_HV_MEMORY_READ);
    DbgPrint("[HV]   - IOCTL_HV_MEMORY_WRITE    (0x%X)\n", IOCTL_HV_MEMORY_WRITE);
    DbgPrint("[HV]   - IOCTL_HV_SUBMIT_LICENSE  (0x%X)\n", IOCTL_HV_SUBMIT_LICENSE);

    // P25:ed25519 KAT 自检
    HvLicenseSelfTest();

    DbgPrint("[HV] DriverEntry complete\n");

    // 阶段 8.3 — PE 头扰乱必须延迟到 MiFreeDriverInitialization 之后(它在
    // DriverEntry 返回后走 MiSnapDriverRange 读我们的 PE header 找 INIT 段)。
    // 直接抹零会导致 0x1000007E null-deref AV。派生系统线程睡 10 秒再抹。
    //
    // 仅在虚拟化成功启动时才扰乱 PE 头 — 否则驱动还是普通驱动, 抹头反而暴露
    // (NtQuerySystemInformation 会看见一个无 PE header 的驱动, 比正常更显眼),
    // 而且在虚拟化失败的退化路径上更容易触发 0x7E (访问已被回收的 image region)。
#if !HV_MINIMAL_MODE
    // 2026-05-31 临时禁用 PE header obfuscation (Win11 真机验证 P1)
    // 怀疑此功能 +10s 触发后写 nt 内核镜像区域时与 Win11 PatchGuard / Defender
    // 内存扫描并发触发卡死。隔离 driver hide hook + PE obf 两个模块后,
    // 余下的 hypervisor 骨架应能稳定运行。
#if 0
    if (NT_SUCCESS(status) && HvIsHypervisorRunning()) {
        HvScheduleImageObfuscation(DriverObject);
    } else {
        DbgPrint("[HV] PE obfuscation skipped (virtualization not active)\n");
    }
#else
    DbgPrint("[HV] PE obfuscation DISABLED (Win11 P1 isolation)\n");
#endif
#endif

    return STATUS_SUCCESS;
}
