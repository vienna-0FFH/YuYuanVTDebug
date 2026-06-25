/*
 * HvInput.h
 *
 * 阶段 7.10: VT 透明键鼠注入 — 双后端 (PS/2 + USB HID)
 *
 * 两条相互排他的注入路径,在 Initialize 时按机器实际硬件挑选:
 *
 *  (1) PS/2 后端 (BACKEND_PS2)
 *      通过 VMCS I/O bitmap 拦截 PS/2 端口 0x60/0x64,在 VMEXIT 上吐出
 *      合成扫描码 / 鼠标包,配合 VMCS_CTRL_VMENTRY_INTERRUPTION_INFO
 *      注入 IRQ 1 / IRQ 12,让 i8042prt.sys ISR 自然把数据上行到 KbdClass
 *      / win32k!RIM。
 *      要求: IOAPIC redirection table 在 IRQ 1 / IRQ 12 已写入合法向量,
 *      即机器必须挂着真实 PS/2 设备 (台式机 PS/2 口 + 实物 / VMware/VBox /
 *      Hyper-V Gen1)。USB-only laptop 这条路 IOAPIC 是 0xFFFFFFFF。
 *
 *  (2) USB HID 后端 (BACKEND_USB_HID)
 *      不动 VMCS,改在 ring-0 直接调 \Driver\kbdclass / \Driver\mouclass
 *      的 ClassService callback —— 这是 kbdhid.sys / mouhid.sys 在 USB HID
 *      report 翻译完成后回调 kbdclass 的入口,我们用相同签名 + 自己合成
 *      KEYBOARD_INPUT_DATA / MOUSE_INPUT_DATA 直接调用。
 *      数据从此处沿 kbdclass → win32k → 焦点窗口的真路径上行;
 *      win32k 的 LLKHF_INJECTED 标志位由 SendInput 路径才会置位,
 *      class service callback 路径不会置位,因此反作弊 LLKbdHook /
 *      RawInput 仍把这看作硬件输入。
 *      回调指针发现: 走 ObReferenceObjectByName(\Driver\kbdclass) +
 *      DriverObject->DeviceObject 链 + scan DeviceExtension 内函数指针
 *      落在 kbdclass.sys 模块范围内的第一个 candidate。
 *
 * 选择策略 (HvInputInitialize):
 *    PS/2 IOAPIC 向量发现成功 → BACKEND_PS2
 *    PS/2 失败 → 尝试 USB HID 发现 → 成功则 BACKEND_USB_HID
 *    两者都失败 → BACKEND_NONE,所有 IOCTL 返 STATUS_DEVICE_NOT_READY
 *
 * 安全/PG:
 *  - PS/2 路径: VMCS I/O bitmap + 中断注入,完全在 VT-x root,PG 看不到
 *  - USB HID 路径: 不打 hook、不改任何静态结构,仅在 ring-0 调用别人导出
 *    的函数指针;DeviceObject + ClassService 指针 PG 不验证
 */

#ifndef _HV_INPUT_H_
#define _HV_INPUT_H_

#pragma once

#include <ntddk.h>

// ============================================================
// IOCTL 请求结构
// ============================================================

#pragma pack(push, 1)

typedef struct _HV_INPUT_KEY_REQUEST {
    UCHAR   Scancode;     // PS/2 set 1 scancode (e.g. 'A' = 0x1E)
    UCHAR   IsExtended;   // 1 = 前导 E0 (方向键、Ctrl-R、Alt-R 等)
    UCHAR   IsBreak;      // 0 = 按下, 1 = 释放
    UCHAR   AutoBreak;    // 1 = 按下后自动 30-80ms 内释放 (IsBreak 必须 = 0)
} HV_INPUT_KEY_REQUEST, *PHV_INPUT_KEY_REQUEST;

typedef struct _HV_INPUT_MOUSE_REQUEST {
    SHORT   Dx;
    SHORT   Dy;
    UCHAR   Buttons;      // bit0 = L, bit1 = R, bit2 = M
    UCHAR   Smooth;       // 1 = 拆成多帧插值 (每帧 ≤ 8 像素)
    UCHAR   Reserved[2];
} HV_INPUT_MOUSE_REQUEST, *PHV_INPUT_MOUSE_REQUEST;

// 后端选择 — Initialize 时按硬件实际能力填,IOCTL 可查
typedef enum _HV_INPUT_BACKEND {
    HV_INPUT_BACKEND_NONE    = 0,   // PS/2 + USB HID + xHCI 都发现失败
    HV_INPUT_BACKEND_PS2     = 1,   // IOAPIC IRQ1/12 + I/O bitmap
    HV_INPUT_BACKEND_USB_HID = 2,   // KbdClass/MouClass ClassService 直调 (v3)
    HV_INPUT_BACKEND_XHCI    = 3,   // Layer 4: 真 xHCI Event Ring 注入 + MSI
} HV_INPUT_BACKEND;

// IOCTL_HV_INPUT_GET_STATUS 输出
typedef struct _HV_INPUT_STATUS {
    UCHAR  Backend;          // HV_INPUT_BACKEND
    UCHAR  Initialized;
    UCHAR  Enabled;
    UCHAR  KbdReady;         // PS/2: kbdVec 有效  USB HID: 找到 kbdclass callback
    UCHAR  MouseReady;       // 同上
    UCHAR  StrictXhciMode;   // 1 = 严格 xHCI 模式 (xHCI 失败不回退 v3)
    UCHAR  Reserved[2];
    ULONG  KbdVector;        // PS/2 only — IDT vector (USB HID 时 0)
    ULONG  MouseVector;
    ULONG64 KbdCallback;     // USB HID only — kbdclass ClassService 地址
    ULONG64 MouseCallback;
    ULONG64 KbdDeviceObject; // USB HID only
    ULONG64 MouseDeviceObject;
} HV_INPUT_STATUS, *PHV_INPUT_STATUS;

#pragma pack(pop)

// ============================================================
// 前向声明 GUEST_CONTEXT (避免循环 include HvVmExit 内部结构)
// ============================================================

typedef struct _GUEST_CONTEXT GUEST_CONTEXT, *PGUEST_CONTEXT;

// ============================================================
// 模块生命周期
// ============================================================

// 试 PS/2 IOAPIC,失败回退 USB HID class callback 探测。
// 至少一条成功 = STATUS_SUCCESS,backend 记 g_Backend;两条都失败返
// STATUS_NOT_SUPPORTED,但不阻塞 driver 加载 (调用方应吞掉错误)。
// 必须在第一次 vCPU 启动之前调用 (HvCore.c)。
NTSTATUS HvInputInitialize(VOID);

// 释放 I/O bitmap + 清空 callback,取消所有 AutoBreak timer。
VOID HvInputShutdown(VOID);

// VMCS 配置时查询:返回 TRUE 才在 cpuBasedControls 里 OR 上 USE_IO_BITMAPS。
// 仅 BACKEND_PS2 返 TRUE;USB HID 后端不动 VMCS。
BOOLEAN HvInputNeedsIoBitmap(VOID);

// 兼容别名 (旧 HvVmcs.c 调用点)
#define HvInputIsInitialized HvInputNeedsIoBitmap

HV_INPUT_BACKEND HvInputGetBackend(VOID);

// 填充 HV_INPUT_STATUS 给 IOCTL_HV_INPUT_GET_STATUS
VOID HvInputQueryStatus(_Out_ PHV_INPUT_STATUS status);

// ============================================================
// 启用 / 关闭 (IOCTL 入口)
// ============================================================

// 打开 hooking 开关。VMCS 的 I/O bitmap 一直生效,但 disable 后
// HandleIoExit 走纯 passthrough,等效透明。
NTSTATUS HvInputEnable(VOID);

VOID HvInputDisable(VOID);

// ============================================================
// 提交合成输入 (IOCTL 入口)
// ============================================================

// scancode = PS/2 set 1 make code (低 7 bit)。break 由 hypervisor
// 自己计算: scancode | 0x80。
//
// autoBreak = TRUE 时,30-80ms 后(随机)自动再调一次 IsBreak=TRUE。
// 用 KeSetTimer + DPC 实现。
NTSTATUS HvInputSendKey(UCHAR scancode,
                        BOOLEAN isExtended,
                        BOOLEAN isBreak,
                        BOOLEAN autoBreak);

// dx, dy 可正可负。smooth=TRUE 时大位移拆成 8 像素 / 帧, 16ms 间隔。
// buttons 是状态位掩码,不是边沿;调用方负责按下/抬起两次调用。
NTSTATUS HvInputSendMouse(SHORT dx, SHORT dy, UCHAR buttons, BOOLEAN smooth);

// ============================================================
// 严格 xHCI 模式 (反检测加强)
// ============================================================
//
// 默认行为 (strict=FALSE): SendKey/SendMouse 优先走 xHCI Layer 4 VT-透明路径,
//   失败时回退到 v3 ring-0 ClassService 直调 (kbdclass!ClassServiceCallback)。
//   v3 路径不动 VMCS 也不打 hook,但 ring-0 任何 KbdClass 过滤驱动 / ETWTI
//   都能看见该回调被调用,因此不是真 VT-透明。
//
// 启用后 (strict=TRUE): xHCI 失败时直接返错,不会落到 v3。
//   适合需要保证"反作弊 r0 hook 看不见"的场景,代价是 USB-only 笔记本上
//   xHCI 探测失败时键盘鼠标会完全失效。
//
// 状态保存在 driver,GUI 启动时再 SET 一次即可同步。
VOID    HvInputSetStrictMode(BOOLEAN strict);
BOOLEAN HvInputGetStrictMode(VOID);

// ============================================================
// VMCS 配置访问 (供 HvVmcs.c 写 VMCS_CTRL_IO_BITMAP_A/B)
// ============================================================

PHYSICAL_ADDRESS HvInputGetIoBitmapAPhys(VOID);
PHYSICAL_ADDRESS HvInputGetIoBitmapBPhys(VOID);

// ============================================================
// VMEXIT 回调 (供 HvVmExit.c 调用)
// ============================================================

// 处理 EXIT_REASON_IO_INSTRUCTION (30)。
// qualification = VM_EXIT_QUALIFICATION 字段原值。
// 返回 TRUE 表示已处理(调用方调 HvAdvanceGuestRip 即可)。
BOOLEAN HvInputHandleIoExit(SIZE_T qualification, PGUEST_CONTEXT ctx);

// 从 HvHandleExternalInterrupt 尾部调用 —— 检查 FIFO 有没有 pending
// 合成事件,有的话尝试注入 IRQ 1 / IRQ 12。
// 用 InterlockedExchange 单 CPU 抢锁,防止多核同时各注入一次。
VOID HvInputTryDeliver(VOID);

#endif // _HV_INPUT_H_
