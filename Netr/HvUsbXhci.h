/*
 * HvUsbXhci.h — Layer 4: 真 VT-透明 USB HID 注入
 *
 * 目标:让 ring-3 GUI 发出的"按键"或"鼠标移动"沿真硬件路径上行,
 *       从 ring-0 任何角度看都和物理键鼠按下完全无法区分。
 *
 * 实现策略 (Approach B 精简版,不是全 MMIO 仿真):
 *   1) 启动时扫 PCI 找到真 xHCI 控制器 (Intel/AMD/Via 8086:xxxx Class=0x0C0330)
 *   2) MmMapIoSpace 映射 xHCI BAR0 (Capability+Operational+Runtime+Doorbell)
 *   3) 解析 DCBAA → 走 Device Context → 找 HID Boot interface (kbd subclass=1,
 *      mouse subclass=2) 的 Slot Number
 *   4) 解析该 Slot 的 Endpoint Context (Interrupt-IN 端点),拿到:
 *        - Transfer Ring 物理基址 (TR Dequeue Pointer)
 *        - Max Packet Size
 *        - Endpoint Number
 *   5) 解析 PCI MSI/MSI-X capability 拿 xHCI 的 MSI vector
 *
 * 注入流程 (单次按键):
 *   a) 编 HID Boot Keyboard Report (8 byte: Modifier|Reserved|Key0..Key5)
 *   b) 把 report 写入 xhci.sys 内部 URB 数据缓冲区 (从 Transfer Ring 当前 TRB
 *      的 Data Buffer Pointer 找到)
 *   c) 在 Event Ring 当前 Producer 位置写一条 TRB_TYPE_TRANSFER_EVENT 指回
 *      该 TRB,Slot ID + Endpoint ID 填正确值,Cycle bit 跟随 PCS
 *   d) HvVmExitInjectInterrupt(g_XhciMsiVector, 0)
 *   e) xhci.sys ISR 自然运行 → 处理 EventRing → 完成 URB → kbdhid 收到 report
 *      → kbdclass → win32k → target window
 *
 * PG 安全:
 *   - 不修改任何代码页
 *   - 不动 xHCI MMIO 寄存器 (CRCR/USBSTS/USBCMD 等),只读
 *   - Event Ring/Transfer Ring 是 xHCI 标准里的"共享 RAM",微软驱动写,我们写,
 *     这不是被监视的静态结构
 *   - MSI 注入走标准 VMENTRY_INTERRUPTION_INFO,跟 PS/2 path 同
 *
 * 失败回退:
 *   - 没找到 xHCI / 没找到 HID 设备 → g_UsbXhciState != READY → HvInputSendKey
 *     退回 v4 ring-0 直调 path (g_KbdServiceCallback)
 *
 * 完整 xHCI 规范引用: Intel xHCI Specification rev 1.2 (May 2019)
 *   https://www.intel.com/content/dam/www/public/us/en/documents/technical-specifications/extensible-host-controler-interface-usb-xhci.pdf
 *   章节: 4 (Operational Model), 5 (Register Interface), 6 (Data Structures)
 */

#ifndef _HV_USB_XHCI_H_
#define _HV_USB_XHCI_H_

#pragma once

#include <ntddk.h>

// ============================================================
// xHCI 规范常量 (rev 1.2)
// ============================================================

// ----- PCI Class Code (Class=0x0C SubClass=0x03 ProgIf=0x30)
#define XHCI_PCI_CLASS_CODE         0x0C0330UL
#define XHCI_PCI_CLASS_MASK         0xFFFFFFUL

// PCI 配置空间常量
#define PCI_VENDOR_ID_OFFSET        0x00
#define PCI_DEVICE_ID_OFFSET        0x02
#define PCI_COMMAND_OFFSET          0x04
#define PCI_STATUS_OFFSET           0x06
#define PCI_REVISION_OFFSET         0x08
#define PCI_CLASS_PROG_OFFSET       0x09    // [23:0] = Class|SubClass|ProgIf
#define PCI_HEADER_TYPE_OFFSET      0x0E
#define PCI_BAR0_OFFSET             0x10
#define PCI_CAPABILITY_PTR_OFFSET   0x34
#define PCI_CAP_ID_MSI              0x05
#define PCI_CAP_ID_MSIX             0x11

// PCI BAR 标志位 (BAR & 0xF)
#define PCI_BAR_MMIO_MASK           0x01    // 0 = MMIO, 1 = I/O port
#define PCI_BAR_TYPE_MASK           0x06    // bits 2:1 = type
#define   PCI_BAR_TYPE_32BIT        0x00    // 32-bit MMIO
#define   PCI_BAR_TYPE_64BIT        0x04    // 64-bit MMIO (BAR 跨两个 32-bit slot)
#define PCI_BAR_PREFETCHABLE        0x08

// ----- xHCI Capability Registers (offset 0 from BAR0)
#define XHCI_CAP_CAPLENGTH          0x00    // 8-bit, length of capability regs
#define XHCI_CAP_HCIVERSION         0x02    // 16-bit, interface version
#define XHCI_CAP_HCSPARAMS1         0x04    // [31:24]=MaxPorts [23:8]=MaxIntrs [7:0]=MaxSlots
#define XHCI_CAP_HCSPARAMS2         0x08
#define XHCI_CAP_HCSPARAMS3         0x0C
#define XHCI_CAP_HCCPARAMS1         0x10    // [16]=Context Size (0=32B, 1=64B)
#define XHCI_CAP_DBOFF              0x14    // Doorbell Array offset from BAR0
#define XHCI_CAP_RTSOFF             0x18    // Runtime regs offset from BAR0
#define XHCI_CAP_HCCPARAMS2         0x1C

// HCCPARAMS1 bit fields
#define XHCI_HCC_AC64               (1U << 0)   // 64-bit addressing capable
#define XHCI_HCC_CSZ                (1U << 2)   // Context size: 0=32B, 1=64B
#define XHCI_HCC_XECP_SHIFT         16          // [31:16] xHCI Extended Cap Pointer (DWORD offset)

// ----- xHCI Operational Registers (offset = CAPLENGTH from BAR0)
#define XHCI_OP_USBCMD              0x00
#define XHCI_OP_USBSTS              0x04
#define XHCI_OP_PAGESIZE            0x08
#define XHCI_OP_DNCTRL              0x14
#define XHCI_OP_CRCR_LO             0x18    // Command Ring Control (low 32)
#define XHCI_OP_CRCR_HI             0x1C
#define XHCI_OP_DCBAAP_LO           0x30    // Device Context Base Address Array Pointer
#define XHCI_OP_DCBAAP_HI           0x34
#define XHCI_OP_CONFIG              0x38    // [7:0] = MaxSlotsEn

// USBSTS bits
#define XHCI_STS_HCH                (1U << 0)   // HC Halted
#define XHCI_STS_HSE                (1U << 2)   // Host System Error
#define XHCI_STS_EINT               (1U << 3)   // Event Interrupt
#define XHCI_STS_PCD                (1U << 4)   // Port Change Detect
#define XHCI_STS_CNR                (1U << 11)  // Controller Not Ready

// ----- xHCI Runtime Registers (offset = RTSOFF from BAR0)
#define XHCI_RT_MFINDEX             0x00    // microframe index
#define XHCI_RT_IR0                 0x20    // Interrupter Register Set 0
//   IR[i] is at RTSOFF + 0x20 + i*32
//   Each IR contains:
#define XHCI_IR_IMAN                0x00    // Interrupter Management
#define XHCI_IR_IMOD                0x04    // Interrupter Moderation
#define XHCI_IR_ERSTSZ              0x08    // Event Ring Segment Table Size
#define XHCI_IR_ERSTBA_LO           0x10    // Event Ring Segment Table Base Address
#define XHCI_IR_ERSTBA_HI           0x14
#define XHCI_IR_ERDP_LO             0x18    // Event Ring Dequeue Pointer
#define XHCI_IR_ERDP_HI             0x1C

// IMAN bits
#define XHCI_IMAN_IP                (1U << 0)  // Interrupt Pending (write 1 to clear)
#define XHCI_IMAN_IE                (1U << 1)  // Interrupt Enable

// ERDP bits (low 4 are flags)
#define XHCI_ERDP_DESI_MASK         0x07     // Dequeue ERST Segment Index
#define XHCI_ERDP_EHB               (1U << 3) // Event Handler Busy (W1C)

// ----- xHCI Doorbell Registers (offset = DBOFF from BAR0)
//   DB[0] = Command Ring doorbell
//   DB[1..MaxSlots] = device slot doorbells
//   Each doorbell is 32-bit: [7:0]=DB Target (EP ID) [31:16]=DB Stream ID

// ============================================================
// xHCI Data Structures (xHCI spec ch 6)
// ============================================================

#pragma pack(push, 1)

// TRB — Transfer Request Block (xHCI spec 6.4)
// 16 bytes,所有 ring 的 entry 都是 TRB
typedef struct _XHCI_TRB {
    ULONG64 Parameter;      // varies by TRB type
    ULONG32 Status;         // varies by TRB type
    ULONG32 Control;        // [15:10] = TRB Type, [0] = Cycle bit, [1..9] type-specific
} XHCI_TRB, *PXHCI_TRB;

// TRB Type 字段 (Control 字段 bits 15:10)
#define XHCI_TRB_TYPE_SHIFT             10
#define XHCI_TRB_TYPE_MASK              0x3F
#define   XHCI_TRB_TYPE_NORMAL          1
#define   XHCI_TRB_TYPE_SETUP_STAGE     2
#define   XHCI_TRB_TYPE_DATA_STAGE      3
#define   XHCI_TRB_TYPE_STATUS_STAGE    4
#define   XHCI_TRB_TYPE_ISOCH           5
#define   XHCI_TRB_TYPE_LINK            6
#define   XHCI_TRB_TYPE_EVENT_DATA      7
#define   XHCI_TRB_TYPE_NO_OP_TRANSFER  8
#define   XHCI_TRB_TYPE_ENABLE_SLOT     9
#define   XHCI_TRB_TYPE_DISABLE_SLOT    10
#define   XHCI_TRB_TYPE_ADDRESS_DEVICE  11
#define   XHCI_TRB_TYPE_CONFIGURE_EP    12
#define   XHCI_TRB_TYPE_EVAL_CONTEXT    13
#define   XHCI_TRB_TYPE_RESET_EP        14
#define   XHCI_TRB_TYPE_STOP_EP         15
#define   XHCI_TRB_TYPE_SET_TR_DEQ_PTR  16
#define   XHCI_TRB_TYPE_RESET_DEVICE    17
#define   XHCI_TRB_TYPE_NO_OP_CMD       23
#define   XHCI_TRB_TYPE_TRANSFER_EVENT  32
#define   XHCI_TRB_TYPE_CMD_COMPLETE    33
#define   XHCI_TRB_TYPE_PORT_STATUS     34
#define   XHCI_TRB_TYPE_HOST_CONTROLLER 37
#define   XHCI_TRB_TYPE_DEVICE_NOTIF    38
#define   XHCI_TRB_TYPE_MFINDEX_WRAP    39

// TRB Control 标志位
#define XHCI_TRB_CYCLE                  (1U << 0)
#define XHCI_TRB_ENT                    (1U << 1)   // Evaluate Next TRB
#define XHCI_TRB_ISP                    (1U << 2)   // Interrupt on Short Packet
#define XHCI_TRB_NS                     (1U << 3)   // No Snoop
#define XHCI_TRB_CH                     (1U << 4)   // Chain
#define XHCI_TRB_IOC                    (1U << 5)   // Interrupt on Completion
#define XHCI_TRB_IDT                    (1U << 6)   // Immediate Data
#define XHCI_TRB_BEI                    (1U << 9)   // Block Event Interrupt

// Transfer Event TRB (TRB Type 32) — 我们要写到 Event Ring 的 entry
//   Parameter [63:0]   = TRB Pointer (the Transfer TRB that completed)
//   Status    [23:0]   = TRB Transfer Length (residual)
//             [31:24]  = Completion Code (1 = Success)
//   Control   [0]      = Cycle bit
//             [2]      = Event Data (0 for normal Transfer Event)
//             [15:10]  = TRB Type = 32
//             [20:16]  = Endpoint ID (DCI = 2*ep+1 for IN, 2*ep for OUT)
//             [31:24]  = Slot ID
#define XHCI_CC_SUCCESS                 1
#define XHCI_CC_DATA_BUFFER_ERROR       2
#define XHCI_CC_BABBLE_ERROR            3
#define XHCI_CC_USB_TRANSACTION_ERROR   4
#define XHCI_CC_TRB_ERROR               5
#define XHCI_CC_STALL_ERROR             6
#define XHCI_CC_SHORT_PACKET            13

// Event Ring Segment Table Entry (xHCI spec 6.5)
typedef struct _XHCI_ERST_ENTRY {
    ULONG64 RingSegmentBase;    // physical, 64-byte aligned
    ULONG32 RingSegmentSize;    // [15:0] = number of TRBs (16-4096)
    ULONG32 Reserved;
} XHCI_ERST_ENTRY, *PXHCI_ERST_ENTRY;

// Slot Context (xHCI spec 6.2.2) — 32 bytes (CSZ=0) or 64 bytes (CSZ=1)
typedef struct _XHCI_SLOT_CONTEXT {
    ULONG32 Field1;     // [19:0]=Route, [23:20]=Speed, [25]=MTT, [26]=Hub, [31:27]=Ctx Entries
    ULONG32 Field2;     // [15:0]=MaxLatency, [23:16]=RootHubPort, [31:24]=NumberOfPorts
    ULONG32 Field3;     // [7:0]=ParentHubSlot, [15:8]=ParentPortNum, [25:16]=TTT, [31:22]=IntrTarget
    ULONG32 Field4;     // [7:0]=USB Device Address, [31:27]=Slot State
    ULONG32 Reserved[4];
    // CSZ=1 时再多 32 bytes 厂商保留
} XHCI_SLOT_CONTEXT, *PXHCI_SLOT_CONTEXT;

#define XHCI_SLOT_SPEED_SHIFT       20
#define XHCI_SLOT_SPEED_MASK        0xF
#define   XHCI_SPEED_FULL           1   // 12 Mbps
#define   XHCI_SPEED_LOW            2   // 1.5 Mbps  ← HID Boot 设备常见
#define   XHCI_SPEED_HIGH           3   // 480 Mbps
#define   XHCI_SPEED_SUPER          4   // 5 Gbps
#define XHCI_SLOT_CTX_ENTRIES_SHIFT 27
#define XHCI_SLOT_CTX_ENTRIES_MASK  0x1F

// Endpoint Context (xHCI spec 6.2.3) — 32 bytes (CSZ=0) or 64 bytes (CSZ=1)
typedef struct _XHCI_ENDPOINT_CONTEXT {
    ULONG32 Field1;     // [2:0]=EPState, [9:8]=Mult, [14:10]=MaxPStreams,
                        // [15]=LSA, [23:16]=Interval, [31:24]=MaxESITPayloadHi
    ULONG32 Field2;     // [1]=ErrorCount, [5:3]=EPType, [7]=HID, [15:8]=MaxBurstSize, [31:16]=MaxPacketSize
    ULONG64 TRDequePtr; // [3:0] = Cycle bit (DCS) & flags
                        // [63:4] = Transfer Ring physical address
    ULONG32 Field3;     // [15:0]=AverageTRBLen, [31:16]=MaxESITPayloadLo
    ULONG32 Reserved[3];
    // CSZ=1 时再多 32 bytes 厂商保留
} XHCI_ENDPOINT_CONTEXT, *PXHCI_ENDPOINT_CONTEXT;

#define XHCI_EP_STATE_MASK          0x07
#define   XHCI_EP_STATE_DISABLED    0
#define   XHCI_EP_STATE_RUNNING     1
#define   XHCI_EP_STATE_HALTED      2
#define   XHCI_EP_STATE_STOPPED     3
#define   XHCI_EP_STATE_ERROR       4

#define XHCI_EP_TYPE_SHIFT          3
#define XHCI_EP_TYPE_MASK           0x07
#define   XHCI_EP_TYPE_ISOCH_OUT    1
#define   XHCI_EP_TYPE_BULK_OUT     2
#define   XHCI_EP_TYPE_INTERRUPT_OUT 3
#define   XHCI_EP_TYPE_CONTROL      4   // 双向
#define   XHCI_EP_TYPE_ISOCH_IN     5
#define   XHCI_EP_TYPE_BULK_IN      6
#define   XHCI_EP_TYPE_INTERRUPT_IN 7   // HID 用这个
#define XHCI_EP_MAX_PACKET_SHIFT    16

// Device Context (xHCI spec 6.2.1) — 是 Slot Context + 31 个 Endpoint Context
// CSZ=0: 32B Slot + 31*32B EP = 1024 B
// CSZ=1: 64B Slot + 31*64B EP = 2048 B
// DCI (Device Context Index): 0 = Slot Context, 1 = Default Control EP, 2N = OUT EP N, 2N+1 = IN EP N

#pragma pack(pop)

// ============================================================
// HID Boot Report 协议 (USB HID 1.11, ch 7.2)
// ============================================================

#pragma pack(push, 1)

// Boot Keyboard report — 8 byte (HID 1.11 Appendix B.1)
typedef struct _HID_BOOT_KBD_REPORT {
    UCHAR  Modifiers;       // bit0=LCtrl bit1=LShift bit2=LAlt bit3=LGui
                            // bit4=RCtrl bit5=RShift bit6=RAlt bit7=RGui
    UCHAR  Reserved;
    UCHAR  Keys[6];         // HID usage IDs, 0 = no key
} HID_BOOT_KBD_REPORT, *PHID_BOOT_KBD_REPORT;

// Boot Mouse report — 4 byte (HID 1.11 Appendix B.2 + 现代 wheel 扩展)
typedef struct _HID_BOOT_MOUSE_REPORT {
    UCHAR  Buttons;         // bit0=L bit1=R bit2=M
    CHAR   Dx;              // -127..+127
    CHAR   Dy;
    CHAR   Wheel;
} HID_BOOT_MOUSE_REPORT, *PHID_BOOT_MOUSE_REPORT;

#pragma pack(pop)

// HID Modifier bits
#define HID_MOD_LCTRL       0x01
#define HID_MOD_LSHIFT      0x02
#define HID_MOD_LALT        0x04
#define HID_MOD_LGUI        0x08
#define HID_MOD_RCTRL       0x10
#define HID_MOD_RSHIFT      0x20
#define HID_MOD_RALT        0x40
#define HID_MOD_RGUI        0x80

// ============================================================
// 内部状态
// ============================================================

typedef enum _HV_USB_XHCI_STATE {
    HvUsbXhciState_NotInit       = 0,
    HvUsbXhciState_Discovering   = 1,
    HvUsbXhciState_Ready         = 2,
    HvUsbXhciState_Failed        = 3,
} HV_USB_XHCI_STATE;

typedef struct _HV_USB_HID_DEVICE {
    UCHAR    Valid;                 // 0 = empty slot
    UCHAR    Subclass;              // 1 = boot kbd, 2 = boot mouse
    UCHAR    SlotId;                // xHCI slot 1..MaxSlots
    UCHAR    EndpointId;            // DCI of Interrupt-IN endpoint
    UCHAR    MaxPacketSize;         // 8 (kbd) / 4 (mouse boot) / 8 (mouse with wheel)
    UCHAR    Reserved[3];

    // 从 Endpoint Context 拿到的 Transfer Ring 信息
    ULONG64  TransferRingPhys;      // 当前 dequeue pointer 物理地址 (高 60 bit)
    UCHAR    TransferRingCycle;     // DCS bit (Dequeue Cycle State)

    // Device Context 物理地址 (从 DCBAA 拿到的)
    ULONG64  DeviceContextPhys;

    // --- Phase 7: per-device 锁 + 持久映射 (修 DISPATCH_LEVEL MmMapIoSpace 死锁) ---
    // 旧代码:HvXhciInjectHid 拿 g_HvUsbXhci.Lock (KSPIN_LOCK → DISPATCH_LEVEL),
    // 在锁下做 MmMapIoSpace per-TRB scan (要求 ≤ APC_LEVEL),违规导致 kbd↔mouse
    // 高频争锁直接卡死。修法:
    //   1) TrMutex 是 KFAST_MUTEX (APC_LEVEL) — 让 TR scan/write 可以合法 MmMapIoSpace
    //   2) 启动期把 TR 起始页 pre-map,scan 走指针运算,绝大多数情况下零 MmMapIoSpace
    //   3) DataBufferMappedVa 在首次 inject 看到 buffer phys 后懒映射并缓存,
    //      之后 xhci.sys 复用同一 DMA buffer 也是零额外 map
    //
    // 注:仍旧只支持 TR 段 ≤ 1 page (256 TRBs);跨页 LINK 走 fallback MmMapIoSpace,
    // 但仅在 APC_LEVEL 下做,且不再串到 g_HvUsbXhci.Lock 后面。
    FAST_MUTEX TrMutex;             // 序列化同一 device 上的 TR 写入 (kbd 与 mouse 互不影响)
    PVOID    TransferRingMappedVa;  // 预映射 TR 起始页 (= TransferRingPhys & ~0xFFF 处)
    ULONG64  TransferRingMappedPagePhys; // VA 对应的物理页基址
    PVOID    DataBufferMappedVa;    // 缓存 HID buffer 所在页的映射 (lazy)
    ULONG64  DataBufferMappedPagePhys;   // 缓存 buffer 页的物理基址
} HV_USB_HID_DEVICE, *PHV_USB_HID_DEVICE;

// 最多支持的 HID 设备数 (我们只需要找 1 个 kbd + 1 个 mouse)
#define HV_USB_HID_MAX_DEVICES      4

typedef struct _HV_USB_XHCI_CONTEXT {
    volatile LONG    State;             // HV_USB_XHCI_STATE
    BOOLEAN          ContextSize64;     // CSZ from HCCPARAMS1

    // PCI 定位
    ULONG            PciBus;
    ULONG            PciDevice;
    ULONG            PciFunction;
    USHORT           PciVendorId;
    USHORT           PciDeviceId;

    // BAR0
    ULONG64          BarPhys;
    SIZE_T           BarSize;
    volatile UCHAR*  Bar;               // MmMapIoSpace 后的 kernel VA

    // 关键寄存器块基址 (BAR + 偏移)
    volatile UCHAR*  CapBase;           // = Bar
    volatile UCHAR*  OpBase;            // = Bar + CapLength
    volatile UCHAR*  RtBase;            // = Bar + RtsOff
    volatile UCHAR*  DbBase;            // = Bar + DbOff

    // 解析自 capability
    UCHAR            CapLength;
    USHORT           HciVersion;
    UCHAR            MaxSlots;
    USHORT           MaxIntrs;
    UCHAR            MaxPorts;

    // DCBAA (Device Context Base Address Array)
    ULONG64          DcbaaPhys;
    PULONG64         DcbaaMapped;       // MmMapIoSpace 临时映射 (init 后 unmap)

    // MSI / MSI-X 向量 (interrupter 0)
    UCHAR            MsiVector;         // 0 if not discovered
    BOOLEAN          MsiIsX;            // TRUE = MSI-X, FALSE = legacy MSI

    // Event Ring (interrupter 0)
    ULONG64          ErstPhys;          // ERSTBA
    USHORT           ErstSize;          // entries
    ULONG64          EventRingSegPhys;  // 第一个段的物理基址 (从 ERST[0] 读)
    ULONG            EventRingSegSize;  // entries 数
    ULONG64          ErdpPhys;          // Event Ring Dequeue Pointer (当前)
    UCHAR            EventRingCycle;    // Consumer Cycle State (初始 1)

    // Phase 4: 持久映射整段 Event Ring (init 时 MmMapIoSpace,shutdown 时 Unmap)
    // 这样 scan-ahead 在写入前可以遍历段找真正的 producer 空槽,而不是盲推 ProdIdx
    PVOID            EventRingSegMappedVa;
    SIZE_T           EventRingSegMappedBytes;

    // Producer 状态 (per 我们注入) — Event Ring 的 producer 是真控制器,
    // 这里只记录"我们上次写到了哪",方便下次写时不覆盖未消费的 entry
    ULONG            EventRingProdIdx;  // 0..EventRingSegSize-1

    // 找到的 HID 设备
    HV_USB_HID_DEVICE Devices[HV_USB_HID_MAX_DEVICES];
    UCHAR             DeviceCount;

    // 快捷指针 (找到的第一个 kbd / mouse)
    PHV_USB_HID_DEVICE Keyboard;
    PHV_USB_HID_DEVICE Mouse;

    // 同步
    KSPIN_LOCK        Lock;             // 保护 Event Ring 写入和 ProdIdx

    // MSI 投递:HvXhciInjectHid 在写完 TRB 后置 1,通过 IPI 触发 VMEXIT,
    // HvUsbXhciTryDeliverMsi 在 root 上下文里检查这个 flag → HvVmExitInjectInterrupt
    // 单 CPU 抢占 InterlockedExchange 保证只注入一次,不重复
    volatile LONG     PendingMsi;       // 0 = idle, 1 = 待注入
    volatile LONG     DeliveryLock;     // 0 = unlocked, 1 = locked (root 模式 try-deliver 互斥)

    // --- 诊断计数器 (Phase 6 / Item 1) ---
    // 思路:Inject → 我们写 Event Ring + 注入 MSI;xhci.sys ISR 处理时会:
    //   - 读 IMAN.IP / USBSTS.EINT 确认中断源
    //   - 扫 Event Ring 从 ERDP 起,处理直到 cycle 不匹配
    //   - 把新的 ERDP 写回 IR[0].ERDP_LO/HI
    // 如果我们注入的 MSI 真的被 ISR 处理,**ERDP 会前进**。
    // 在下一次 Inject 时读当前 ERDP 跟 LastInjectedErdp 比较,差值非 0 = 上一帧成功。
    volatile LONG     StatInjectAttempts;       // HvUsbXhciTryDeliverMsi 进入
    volatile LONG     StatInjectDelivered;      // 成功调 HvVmExitInjectInterrupt
    volatile LONG     StatInjectDeferred;       // IF=0, PendingMsi 复原
    volatile LONG     StatErdpAdvanced;         // ERDP 检测到前进 (ISR 真处理了)
    volatile LONG     StatErdpStalled;          // ERDP 没前进 (ISR 没运行 / bail 早)
    volatile LONG     StatTrbWriteOk;           // Transfer Ring 写 NORMAL TRB 成功
    volatile LONG     StatTrbWriteFailed;       // 扫到 512 TRB 都找不到 producer 槽
    ULONG64           LastInjectedErdp;         // 上次 InjectInterrupt 时读到的 ERDP
} HV_USB_XHCI_CONTEXT, *PHV_USB_XHCI_CONTEXT;

extern HV_USB_XHCI_CONTEXT g_HvUsbXhci;

// ============================================================
// 公开 API
// ============================================================

// 启动期发现:扫 PCI 找 xHCI,映 BAR,解析 DCBAA + Endpoint Context,
// 找到 kbd + mouse 的 Interrupt-IN 端点,记下 Event Ring 基址。
// 成功 (READY 状态) → HvInputSendKey 走 xHCI 路径
// 失败 (FAILED 状态) → HvInputSendKey 退回 v4 ring-0 直调 path
// 不阻塞驱动加载,失败非致命。
NTSTATUS HvUsbXhciInitialize(VOID);

// 卸载时 unmap MMIO,清状态。
VOID HvUsbXhciShutdown(VOID);

// 查 ready (HvInput 用于决定走哪条 path)
BOOLEAN HvUsbXhciIsReady(VOID);

// 注入键盘事件 (HID Boot keyboard report)
//   modifiers: HID_MOD_* 位掩码
//   key0..key5: HID usage IDs (USB HID Usage Tables ch 10),0 = no key
// 成功 = STATUS_SUCCESS,xhci.sys 异步处理
NTSTATUS HvUsbXhciSendKeyboard(UCHAR modifiers,
                               UCHAR key0, UCHAR key1, UCHAR key2,
                               UCHAR key3, UCHAR key4, UCHAR key5);

// 注入鼠标事件 (HID Boot mouse report)
NTSTATUS HvUsbXhciSendMouse(UCHAR buttons, CHAR dx, CHAR dy, CHAR wheel);

// 给 IOCTL_HV_INPUT_GET_STATUS 用的诊断查询 (可选)
// 2026-06-01: 加 #pragma pack(push, 1) 配合 GUI 端 _pack_ = 1。
// 没 pack 时内核自然对齐 sizeof=96, GUI 期望 88 → IOCTL 返回
// STATUS_BUFFER_TOO_SMALL (Win32 122 "传递给系统调用的数据区域太小")。
#pragma pack(push, 1)
typedef struct _HV_USB_XHCI_STATUS {
    UCHAR  Ready;
    UCHAR  HasKeyboard;
    UCHAR  HasMouse;
    UCHAR  MsiVector;
    USHORT PciVendorId;
    USHORT PciDeviceId;
    ULONG64 BarPhys;
    ULONG64 EventRingSegPhys;
    ULONG   EventRingSegSize;
    ULONG64 KbdTrPhys;
    ULONG64 MouseTrPhys;
    // 诊断计数器 (Item 1):
    ULONG   StatInjectAttempts;
    ULONG   StatInjectDelivered;
    ULONG   StatInjectDeferred;
    ULONG   StatErdpAdvanced;
    ULONG   StatErdpStalled;
    ULONG   StatTrbWriteOk;
    ULONG   StatTrbWriteFailed;
    ULONG64 CurrentErdp;
    ULONG64 LastInjectedErdp;
} HV_USB_XHCI_STATUS, *PHV_USB_XHCI_STATUS;
#pragma pack(pop)

VOID HvUsbXhciQueryStatus(_Out_ PHV_USB_XHCI_STATUS status);

// ============================================================
// VMEXIT-end hook (root 模式)
//   每次 VMEXIT 末尾调用一次 (HvVmExitDispatch 在 HvInputTryDeliver 旁边),
//   检查 g_HvUsbXhci.PendingMsi —— 有的话 InterlockedExchange 抢锁,
//   调用 HvVmExitInjectInterrupt(MsiVector, 0) 注入。
//   单 CPU 完成,其他 CPU 上的同时调用 no-op。
// ============================================================
VOID HvUsbXhciTryDeliverMsi(VOID);

// ============================================================
// PS/2 → HID Usage ID 翻译表 (USB HID Usage Tables ch 10, Keyboard/Keypad page)
// 在 HvUsbHid.c 里实现 (供 HvInput.c 在 xHCI path 时翻译)
// ============================================================

// scancode = PS/2 set 1 make code (低 7 bit),isExtended = E0 前缀
// 返回 HID usage ID,0 = unmapped (调用方应跳过)
UCHAR HvUsbHidTranslateScancode(UCHAR scancode, BOOLEAN isExtended);

// 判断 HID usage 是不是 modifier (Ctrl/Shift/Alt/GUI)
// 如果是,返回对应 HID_MOD_* bit;否则返回 0
UCHAR HvUsbHidScancodeToModifier(UCHAR scancode, BOOLEAN isExtended);

#endif // _HV_USB_XHCI_H_
