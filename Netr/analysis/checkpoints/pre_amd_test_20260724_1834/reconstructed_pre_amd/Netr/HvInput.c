/*
 * HvInput.c
 *
 * 阶段 7.10: VT 透明键鼠注入 — PS/2 I/O 端口仿真 + IRQ 注入
 *
 * 数据流:
 *   IOCTL → HvInputSendKey → push 字节到 g_KbdFifo →
 *   广播 IPI (callback 在每 CPU 上 VMCALL → 强制 VMEXIT 进 root) →
 *   VMCALL_INPUT_DELIVER → HvInputTryDeliver (单 CPU 抢锁) →
 *   HvVmExitInjectInterrupt(g_KbdVector, 0) →
 *   guest 下次 VMRESUME 后进 IDT[g_KbdVector] = i8042prt!ISR →
 *   ISR 读 0x60 → VMEXIT (case 30) →
 *   HvInputHandleIoExit 从 g_KbdFifo 出队字节,写 ctx->Rax →
 *   ISR 把"扫描码"上行到 KbdClass → win32k → target window
 *
 * 反作弊视角:窗口收到的 KEYDOWN/KEYUP 的 flags 不含 LLKHF_INJECTED,
 * 因为整条上行链路是 Windows 自己的 ISR/dispatcher,我们只在中断和
 * 端口读两个点上注入数据,没有任何 "synthetic input" 标记被设置。
 */

#include <ntddk.h>
#include <ntstrsafe.h>

#include "HvInput.h"
#include "HvTypes.h"
#include "HvUtils.h"
#include "HvVmExit.h"
#include "HvUsbXhci.h"   // Layer 4: 真 VT-透明 USB HID 注入路径

// P122: 全 driver DbgPrint → GUI ring
#define HV_TRACE_THIS_CAT HV_TRACE_CAT_INPUT
#include "HvTrace.h"

// ============================================================
// kbdmou.h 抠出来的最小公共结构 — 避免 #include <kbdmou.h> 依赖
// (那个头里有 PORT_CONFIGURATION_INFORMATION 之类的连环 include)
// ============================================================

#pragma pack(push, 4)

#ifndef KEYBOARD_INPUT_DATA_DEFINED
#define KEYBOARD_INPUT_DATA_DEFINED
typedef struct _KEYBOARD_INPUT_DATA {
    USHORT UnitId;
    USHORT MakeCode;
    USHORT Flags;            // bit0=KEY_BREAK(0=make/1=break) bit1=KEY_E0 bit2=KEY_E1
    USHORT Reserved;
    ULONG  ExtraInformation;
} KEYBOARD_INPUT_DATA, *PKEYBOARD_INPUT_DATA;
#define KEY_MAKE       0x0000
#define KEY_BREAK      0x0001
#define KEY_E0         0x0002
#define KEY_E1         0x0004
#endif

#ifndef MOUSE_INPUT_DATA_DEFINED
#define MOUSE_INPUT_DATA_DEFINED
typedef struct _MOUSE_INPUT_DATA {
    USHORT UnitId;
    USHORT Flags;            // MOUSE_MOVE_RELATIVE / MOUSE_MOVE_ABSOLUTE / ...
    union {
        ULONG  Buttons;
        struct {
            USHORT ButtonFlags;   // RI_MOUSE_LEFT_BUTTON_DOWN / _UP / right / middle / ...
            USHORT ButtonData;    // wheel delta
        };
    };
    ULONG  RawButtons;
    LONG   LastX;
    LONG   LastY;
    ULONG  ExtraInformation;
} MOUSE_INPUT_DATA, *PMOUSE_INPUT_DATA;

#define MOUSE_MOVE_RELATIVE      0x0000
#define MOUSE_MOVE_ABSOLUTE      0x0001
#define MOUSE_LEFT_BUTTON_DOWN   0x0001
#define MOUSE_LEFT_BUTTON_UP     0x0002
#define MOUSE_RIGHT_BUTTON_DOWN  0x0004
#define MOUSE_RIGHT_BUTTON_UP    0x0008
#define MOUSE_MIDDLE_BUTTON_DOWN 0x0010
#define MOUSE_MIDDLE_BUTTON_UP   0x0020
#endif

#pragma pack(pop)

// kbdclass / mouclass 的 ClassService 签名 (ntddkbd.h 内部):
typedef VOID (NTAPI *PHV_KBD_SERVICE_CALLBACK)(
    _In_ PDEVICE_OBJECT NormalDeviceObject,
    _In_ PKEYBOARD_INPUT_DATA InputDataStart,
    _In_ PKEYBOARD_INPUT_DATA InputDataEnd,
    _Inout_ PULONG InputDataConsumed);

typedef VOID (NTAPI *PHV_MOU_SERVICE_CALLBACK)(
    _In_ PDEVICE_OBJECT NormalDeviceObject,
    _In_ PMOUSE_INPUT_DATA InputDataStart,
    _In_ PMOUSE_INPUT_DATA InputDataEnd,
    _Inout_ PULONG InputDataConsumed);

// 模块查表 (SystemModuleInformation = 11)
extern NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(
    _In_ ULONG SystemInformationClass,
    _Inout_opt_ PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength);

extern NTSYSAPI NTSTATUS NTAPI ObReferenceObjectByName(
    _In_ PUNICODE_STRING ObjectName,
    _In_ ULONG Attributes,
    _In_opt_ PACCESS_STATE AccessState,
    _In_opt_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_TYPE ObjectType,
    _In_ KPROCESSOR_MODE AccessMode,
    _Inout_opt_ PVOID ParseContext,
    _Out_ PVOID* Object);

extern POBJECT_TYPE* IoDriverObjectType;

// ============================================================
// 常量
// ============================================================

#define HV_INPUT_TAG                'tpnI'   // 'Inpt'
#define HV_INPUT_FIFO_SIZE          256
#define HV_INPUT_FIFO_MASK          (HV_INPUT_FIFO_SIZE - 1)
#define HV_INPUT_AUTOBREAK_SLOTS    32

// 0x64 status byte bit 编码
#define KBC_STATUS_OBF              0x01    // Output Buffer Full (有数据可读)
#define KBC_STATUS_AUX              0x20    // Auxiliary device (1=mouse, 0=kbd)

// 数据源指示
#define INPUT_SOURCE_KBD            0
#define INPUT_SOURCE_MOUSE          1

// IOAPIC MMIO
#define IOAPIC_PHYS_BASE            0xFEC00000
#define IOAPIC_MMIO_SIZE            0x20

// VMCALL number for IPI-forced delivery (与 HvVmExit.c 的 VMCALL 命名空间一致)
#define VMCALL_INPUT_DELIVER        0x1023DEAD

// ============================================================
// 模块状态
// ============================================================

typedef struct _INPUT_FIFO {
    KSPIN_LOCK Lock;
    UCHAR      Data[HV_INPUT_FIFO_SIZE];
    LONG       Head;          // next read index
    LONG       Tail;          // next write index
    LONG       Count;
} INPUT_FIFO, *PINPUT_FIFO;

typedef struct _AUTOBREAK_SLOT {
    volatile LONG  InUse;     // 0=free, 1=armed
    KTIMER         Timer;
    KDPC           Dpc;
    UCHAR          Scancode;
    UCHAR          IsExtended;
} AUTOBREAK_SLOT, *PAUTOBREAK_SLOT;

static BOOLEAN          g_InputInitialized = FALSE;
static BOOLEAN          g_InputEnabled     = FALSE;
static HV_INPUT_BACKEND g_Backend          = HV_INPUT_BACKEND_NONE;
static EX_RUNDOWN_REF   g_InputDpcRundown;
static volatile LONG    g_InputDpcRundownInitialized = FALSE;
static volatile LONG    g_InputShutdownStarted = FALSE;

// 严格 xHCI 模式 — TRUE 时 SendKey/SendMouse 一旦 xHCI 路径失败就直接返错,
// 不再回退到 v3 ring-0 ClassService 直调(后者被 kbdclass hook 可见,不是真 VT-透明)。
// 默认 FALSE(允许 fallback,优先可用性);GUI 显式打开后才生效。
static BOOLEAN          g_StrictXhciMode   = FALSE;

// PS/2 backend state ----------------------------------------------------------
static PVOID            g_IoBitmapA = NULL;     // ports 0x0000-0x7FFF
static PVOID            g_IoBitmapB = NULL;     // ports 0x8000-0xFFFF
static PHYSICAL_ADDRESS g_IoBitmapAPhys;
static PHYSICAL_ADDRESS g_IoBitmapBPhys;

static ULONG            g_KbdVector   = 0;       // IDT vector for IRQ 1
static ULONG            g_MouseVector = 0;       // IDT vector for IRQ 12

static INPUT_FIFO       g_KbdFifo;
static INPUT_FIFO       g_MouseFifo;

static volatile UCHAR   g_NextByteSource = INPUT_SOURCE_KBD;
static volatile LONG    g_DeliveryLock = 0;      // single-CPU inject lock

// USB HID backend state -------------------------------------------------------
static PHV_KBD_SERVICE_CALLBACK g_KbdServiceCallback   = NULL;
static PDEVICE_OBJECT           g_KbdClassDeviceObject = NULL;
static PDRIVER_OBJECT           g_KbdClassDriverObject = NULL;
static USHORT                   g_KbdUnitId            = 0;

static PHV_MOU_SERVICE_CALLBACK g_MouseServiceCallback = NULL;
static PDEVICE_OBJECT           g_MouseClassDeviceObject = NULL;
static PDRIVER_OBJECT           g_MouseClassDriverObject = NULL;
static USHORT                   g_MouseUnitId            = 0;

// Common --------------------------------------------------------------------
static AUTOBREAK_SLOT   g_AutoBreakSlots[HV_INPUT_AUTOBREAK_SLOTS];

// LCG RNG (seeded from KeQueryPerformanceCounter at init)
static ULONG64          g_RngState = 0x12345678ABCDEF01ULL;

// Layer 4 (xHCI) 路径状态 — HID Boot Keyboard report 是 state-based:
//   每次发送都要包含"当前所有按下的键 + modifier mask"。这里维护当前合成视角下
//   还按着的键 + modifier mask;调用方 send_key(make) 加入,send_key(break) 移除。
// 鼠标的按钮位 g_HidButtonsState 已经存在 (line ~944),复用。
typedef struct _HV_XHCI_KBD_STATE {
    KSPIN_LOCK Lock;
    UCHAR      Modifiers;     // HID_MOD_* 位掩码
    UCHAR      Keys[6];       // 同时按下的非 modifier 键 HID Usage IDs (0 = empty slot)
} HV_XHCI_KBD_STATE;
static HV_XHCI_KBD_STATE g_XhciKbdState;

static VOID HvInputXhciKbdReset(VOID)
{
    KIRQL old;
    KeAcquireSpinLock(&g_XhciKbdState.Lock, &old);
    g_XhciKbdState.Modifiers = 0;
    RtlZeroMemory(g_XhciKbdState.Keys, sizeof(g_XhciKbdState.Keys));
    KeReleaseSpinLock(&g_XhciKbdState.Lock, old);
}

// 在 g_XhciKbdState.Keys 加入 usage (不重) / 移除 usage,返回是否变了
static BOOLEAN HvInputXhciKbdAddKey(UCHAR usage)
{
    ULONG i;
    for (i = 0; i < 6; i++) {
        if (g_XhciKbdState.Keys[i] == usage) return FALSE;  // 已在
    }
    for (i = 0; i < 6; i++) {
        if (g_XhciKbdState.Keys[i] == 0) {
            g_XhciKbdState.Keys[i] = usage;
            return TRUE;
        }
    }
    return FALSE;  // 全满 (USB HID Boot 最多 6 同时键)
}

static BOOLEAN HvInputXhciKbdRemoveKey(UCHAR usage)
{
    ULONG i;
    for (i = 0; i < 6; i++) {
        if (g_XhciKbdState.Keys[i] == usage) {
            g_XhciKbdState.Keys[i] = 0;
            return TRUE;
        }
    }
    return FALSE;
}

// 把 PS/2 scancode 翻译并通过 HvUsbXhciSendKeyboard 注入。
// 返回 STATUS_SUCCESS = 已在 xHCI 路径处理,STATUS_NOT_SUPPORTED = 调用方回退
static NTSTATUS HvInputXhciTrySendKey(UCHAR scancode, BOOLEAN isExtended, BOOLEAN isBreak)
{
    UCHAR modBit;
    UCHAR usage;
    KIRQL old;
    HID_BOOT_KBD_REPORT snapshot;
    NTSTATUS status;

    if (!HvUsbXhciIsReady()) return STATUS_NOT_SUPPORTED;

    modBit = HvUsbHidScancodeToModifier(scancode, isExtended);
    if (modBit == 0) {
        usage = HvUsbHidTranslateScancode(scancode, isExtended);
        if (usage == 0) {
            // 没有对应映射 — 回退给 v3 ring-0 path 仍可能识别
            return STATUS_NOT_SUPPORTED;
        }
    } else {
        usage = 0;
    }

    KeAcquireSpinLock(&g_XhciKbdState.Lock, &old);
    if (modBit != 0) {
        if (isBreak) g_XhciKbdState.Modifiers &= ~modBit;
        else         g_XhciKbdState.Modifiers |=  modBit;
    } else {
        if (isBreak) HvInputXhciKbdRemoveKey(usage);
        else         HvInputXhciKbdAddKey(usage);
    }
    snapshot.Modifiers = g_XhciKbdState.Modifiers;
    snapshot.Reserved  = 0;
    snapshot.Keys[0] = g_XhciKbdState.Keys[0];
    snapshot.Keys[1] = g_XhciKbdState.Keys[1];
    snapshot.Keys[2] = g_XhciKbdState.Keys[2];
    snapshot.Keys[3] = g_XhciKbdState.Keys[3];
    snapshot.Keys[4] = g_XhciKbdState.Keys[4];
    snapshot.Keys[5] = g_XhciKbdState.Keys[5];
    KeReleaseSpinLock(&g_XhciKbdState.Lock, old);

    status = HvUsbXhciSendKeyboard(snapshot.Modifiers,
                                   snapshot.Keys[0], snapshot.Keys[1],
                                   snapshot.Keys[2], snapshot.Keys[3],
                                   snapshot.Keys[4], snapshot.Keys[5]);
    if (!NT_SUCCESS(status)) {
        // xHCI 路径失败,回滚状态以保持一致 (调用方将回退到 v3 path)
        KeAcquireSpinLock(&g_XhciKbdState.Lock, &old);
        if (modBit != 0) {
            if (isBreak) g_XhciKbdState.Modifiers |=  modBit;
            else         g_XhciKbdState.Modifiers &= ~modBit;
        } else {
            if (isBreak) HvInputXhciKbdAddKey(usage);
            else         HvInputXhciKbdRemoveKey(usage);
        }
        KeReleaseSpinLock(&g_XhciKbdState.Lock, old);
        // 2026-06-01: 透传真实状态码 (旧实现强转 NOT_SUPPORTED 把 TR 满/buffer
        // 跨页/IsReady=false 等不同失败模式都遮盖成 50, 严格模式下 GUI 完全看
        // 不到诊断。透传后 IOCTL 返回真实 NTSTATUS, GUI 能区分 21=DEVICE_NOT_READY
        // 还是 122=BUFFER_TOO_SMALL 等。
        DbgPrint("[HV-INPUT] HvInputXhciTrySendKey: SendKeyboard failed 0x%08X (sc=0x%02X)\n",
                 status, scancode);
        return status;
    }
    return STATUS_SUCCESS;
}

// 鼠标 — HID Boot mouse 是 relative + edge buttons,跟 PS/2 视角接近,
// 但 Dx/Dy 是 signed 8-bit (-127..+127)。调用方已经在 PS/2 路径里做了 ±127 clamp,
// 这里只翻译,不再 clamp。Wheel = 0 (Boot mouse 没 wheel,后续可扩展为 4 byte HID)。
static NTSTATUS HvInputXhciTrySendMouse(SHORT dx, SHORT dy, UCHAR buttons)
{
    CHAR cdx, cdy;
    if (!HvUsbXhciIsReady()) return STATUS_NOT_SUPPORTED;
    cdx = (CHAR)((dx > 127) ? 127 : (dx < -127) ? -127 : (CHAR)dx);
    cdy = (CHAR)((dy > 127) ? 127 : (dy < -127) ? -127 : (CHAR)dy);
    return HvUsbXhciSendMouse(buttons & 0x07, cdx, cdy, 0);
}

// ============================================================
// 辅助: LCG + 范围采样
// ============================================================

static ULONG HvInputRandRange(ULONG lo, ULONG hi)
{
    // Numerical Recipes LCG: x = 6364136223846793005 * x + 1442695040888963407
    g_RngState = g_RngState * 6364136223846793005ULL + 1442695040888963407ULL;
    ULONG r = (ULONG)(g_RngState >> 32);
    if (hi <= lo) return lo;
    return lo + (r % (hi - lo + 1));
}

// ============================================================
// 辅助: FIFO 操作 (multi-producer / multi-consumer, spinlock)
// ============================================================

static VOID HvInputFifoInit(PINPUT_FIFO fifo)
{
    KeInitializeSpinLock(&fifo->Lock);
    fifo->Head = 0;
    fifo->Tail = 0;
    fifo->Count = 0;
    RtlZeroMemory(fifo->Data, sizeof(fifo->Data));
}

// PASSIVE_LEVEL 上调用 — IOCTL path
static BOOLEAN HvInputFifoPush_Passive(PINPUT_FIFO fifo, UCHAR byte)
{
    KIRQL oldIrql;
    BOOLEAN ok;
    KeAcquireSpinLock(&fifo->Lock, &oldIrql);
    if (fifo->Count >= HV_INPUT_FIFO_SIZE) {
        ok = FALSE;
    } else {
        fifo->Data[fifo->Tail] = byte;
        fifo->Tail = (fifo->Tail + 1) & HV_INPUT_FIFO_MASK;
        fifo->Count++;
        ok = TRUE;
    }
    KeReleaseSpinLock(&fifo->Lock, oldIrql);
    return ok;
}

// VMX root / DISPATCH 上调用 — VMEXIT path
static BOOLEAN HvInputFifoPop_Dpc(PINPUT_FIFO fifo, PUCHAR outByte)
{
    BOOLEAN ok;
    KeAcquireSpinLockAtDpcLevel(&fifo->Lock);
    if (fifo->Count <= 0) {
        ok = FALSE;
    } else {
        *outByte = fifo->Data[fifo->Head];
        fifo->Head = (fifo->Head + 1) & HV_INPUT_FIFO_MASK;
        fifo->Count--;
        ok = TRUE;
    }
    KeReleaseSpinLockFromDpcLevel(&fifo->Lock);
    return ok;
}

static BOOLEAN HvInputFifoIsEmpty(PINPUT_FIFO fifo)
{
    // 不加锁的快速 peek — 用于状态字节,允许偶尔 stale
    return fifo->Count <= 0;
}

// ============================================================
// 辅助: IOAPIC 向量发现
// ============================================================

static ULONG HvInputReadIoApicRedir(volatile ULONG* mmio, ULONG entryIndex)
{
    // IOREGSEL = offset 0x00, IOWIN = offset 0x10
    // 每个 redirection entry = 2 个 32-bit slot, 从 index 0x10 开始
    mmio[0] = 0x10 + entryIndex * 2;
    return mmio[4];  // low dword: vector + delivery + dest_mode + ...
}

static NTSTATUS HvInputDiscoverVectors(VOID)
{
    PHYSICAL_ADDRESS ioapicPa;
    volatile ULONG* mmio = NULL;
    ULONG kbdRedir, mouseRedir;
    ULONG kbdVec, mouseVec;

    ioapicPa.QuadPart = IOAPIC_PHYS_BASE;
    mmio = (volatile ULONG*)MmMapIoSpace(ioapicPa, IOAPIC_MMIO_SIZE, MmNonCached);
    if (!mmio) {
        DbgPrint("[HV-INPUT] IOAPIC MmMapIoSpace failed\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // IRQ 1 = keyboard, IRQ 12 = mouse
    kbdRedir   = HvInputReadIoApicRedir(mmio, 1);
    mouseRedir = HvInputReadIoApicRedir(mmio, 12);

    MmUnmapIoSpace((PVOID)mmio, IOAPIC_MMIO_SIZE);

    kbdVec   = kbdRedir   & 0xFF;
    mouseVec = mouseRedir & 0xFF;

    // 合理性检查: vector 必须在 0x20-0xFE 范围内 (0x00-0x1F 是 CPU 异常,0xFF 留给伪)
    if (kbdVec < 0x20 || kbdVec >= 0xFF ||
        mouseVec < 0x20 || mouseVec >= 0xFF) {
        DbgPrint("[HV-INPUT] vectors out of range: kbd=0x%X mouse=0x%X "
                 "(本机可能用 USB HID 而不是 PS/2)\n", kbdVec, mouseVec);
        return STATUS_NOT_SUPPORTED;
    }

    // 检查是否被 mask (bit 16 = mask)
    if ((kbdRedir & (1u << 16)) || (mouseRedir & (1u << 16))) {
        DbgPrint("[HV-INPUT] WARNING: IRQ masked in IOAPIC kbdRedir=0x%X mouseRedir=0x%X\n",
                 kbdRedir, mouseRedir);
        // 不当致命错误,有些机器初始 mask,后续 i8042prt 初始化会 unmask
    }

    g_KbdVector   = kbdVec;
    g_MouseVector = mouseVec;
    DbgPrint("[HV-INPUT] discovered IDT vectors: kbd=0x%X mouse=0x%X\n",
             g_KbdVector, g_MouseVector);
    return STATUS_SUCCESS;
}

// ============================================================
// 辅助: I/O bitmap bit 设置
// ============================================================

static VOID HvInputSetBitmapBit(PVOID bitmap, ULONG portOffset)
{
    // bitmap A 覆盖 port 0..0x7FFF
    UCHAR* bytes = (UCHAR*)bitmap;
    bytes[portOffset / 8] |= (UCHAR)(1u << (portOffset & 7));
}

static VOID HvInputClearBitmapBit(PVOID bitmap, ULONG portOffset)
{
    UCHAR* bytes = (UCHAR*)bitmap;
    if (!bytes) {
        return;
    }
    bytes[portOffset / 8] &= (UCHAR)~(1u << (portOffset & 7));
}

// ============================================================
// AutoBreak DPC
// ============================================================

KDEFERRED_ROUTINE HvInputAutoBreakDpc;
VOID HvInputAutoBreakDpc(
    _In_ struct _KDPC* Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArg1,
    _In_opt_ PVOID SystemArg2)
{
    PAUTOBREAK_SLOT slot = (PAUTOBREAK_SLOT)DeferredContext;
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(SystemArg1);
    UNREFERENCED_PARAMETER(SystemArg2);
    if (!slot) return;
    if (!ExAcquireRundownProtection(&g_InputDpcRundown)) {
        InterlockedExchange(&slot->InUse, 0);
        return;
    }
    // 释放 break 扫描码 (no auto-break to avoid infinite loop)
    (VOID)HvInputSendKey(slot->Scancode, (BOOLEAN)slot->IsExtended, TRUE, FALSE);
    InterlockedExchange(&slot->InUse, 0);
    ExReleaseRundownProtection(&g_InputDpcRundown);
}

static BOOLEAN HvInputArmAutoBreak(UCHAR scancode, BOOLEAN isExtended)
{
    ULONG i;
    LARGE_INTEGER due;
    ULONG delayMs;

    for (i = 0; i < HV_INPUT_AUTOBREAK_SLOTS; i++) {
        PAUTOBREAK_SLOT slot = &g_AutoBreakSlots[i];
        if (InterlockedCompareExchange(&slot->InUse, 1, 0) != 0) {
            continue;
        }
        slot->Scancode   = scancode;
        slot->IsExtended = (UCHAR)isExtended;

        delayMs = HvInputRandRange(30, 80);
        due.QuadPart = -((LONGLONG)delayMs * 10000LL);  // 100ns units, negative=relative
        KeSetTimer(&slot->Timer, due, &slot->Dpc);
        return TRUE;
    }
    DbgPrint("[HV-INPUT] no free AutoBreak slot\n");
    return FALSE;
}

// ============================================================
// IPI callback — issue VMCALL to force VMEXIT into root mode
// ============================================================

static ULONG_PTR HvInputDeliverIpiCallback(_In_ ULONG_PTR ctx)
{
    UNREFERENCED_PARAMETER(ctx);
    // 这个 callback 在每 CPU 上,IRQL = IPI_LEVEL
    // VMCALL 触发 VMEXIT → HvHandleVmcall → 由我们扩展的 dispatcher 调 HvInputTryDeliver
    // 注意: vmcall 必须从 non-root 发,这里正是 (我们在 host kernel 里,运行在 guest 上)
    __try {
        // RCX = vmcall number
        ULONG64 leaf = VMCALL_INPUT_DELIVER;
        // 不使用 __vmx_vmcall (那是给 Intel guest 的内联),直接走 ASM 不实际
        // 这里改用一个轻量级 trigger: 强制一次 CPUID,它必然 VMEXIT
        int cpuInfo[4];
        __cpuid(cpuInfo, 0x4853FF01);  // 自定义 leaf,HvHandleCpuid 不会特殊处理,继续走 dispatcher
        (VOID)leaf;
        (VOID)cpuInfo;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        // 安静吞掉 —— 该 CPU 没虚拟化或者其他原因
    }
    return 0;
}

// ============================================================
// USB HID 后端: 模块范围解析 + ClassService callback 发现
// ============================================================

#define HV_INPUT_MODULE_BUF_TAG  'mIvH'
#define HV_INPUT_DEVEXT_SCAN_MAX 0x200    // scan 头 512 bytes

// 在 PsLoadedModuleList (走 SystemModuleInformation = 11) 找 moduleName 的 image 范围。
// 成功返回 STATUS_SUCCESS + outBase/outEnd 填入虚拟地址段。
static NTSTATUS HvInputResolveModuleRange(
    _In_ PCSTR moduleName,
    _Out_ PVOID* outBase,
    _Out_ PVOID* outEnd)
{
    NTSTATUS status;
    ULONG bufSize = 0x20000;     // 128 KB 起步
    PVOID buf = NULL;
    PHV_RTL_PROCESS_MODULES modules;
    ULONG i;
    ULONG retLen = 0;
    BOOLEAN found = FALSE;
    SIZE_T nameLen;

    *outBase = NULL;
    *outEnd  = NULL;

    nameLen = strlen(moduleName);
    if (nameLen == 0 || nameLen > 64) {
        return STATUS_INVALID_PARAMETER;
    }

    for (;;) {
        buf = ExAllocatePool2(POOL_FLAG_NON_PAGED, bufSize, HV_INPUT_MODULE_BUF_TAG);
        if (!buf) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        status = ZwQuerySystemInformation(11, buf, bufSize, &retLen);
        if (status == STATUS_INFO_LENGTH_MISMATCH) {
            ExFreePoolWithTag(buf, HV_INPUT_MODULE_BUF_TAG);
            buf = NULL;
            if (retLen <= bufSize) {
                // safety net
                bufSize *= 2;
            } else {
                bufSize = retLen + 0x4000;
            }
            if (bufSize > 0x400000) {  // 4 MB 兜底
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            continue;
        }
        break;
    }
    if (!NT_SUCCESS(status)) {
        if (buf) ExFreePoolWithTag(buf, HV_INPUT_MODULE_BUF_TAG);
        return status;
    }

    modules = (PHV_RTL_PROCESS_MODULES)buf;
    for (i = 0; i < modules->NumberOfModules; i++) {
        PHV_RTL_PROCESS_MODULE_INFORMATION m = &modules->Modules[i];
        PCSTR leaf = (PCSTR)(m->FullPathName + m->OffsetToFileName);
        if (_stricmp(leaf, moduleName) == 0) {
            *outBase = m->ImageBase;
            *outEnd  = (PUCHAR)m->ImageBase + m->ImageSize;
            found = TRUE;
            break;
        }
    }

    ExFreePoolWithTag(buf, HV_INPUT_MODULE_BUF_TAG);
    return found ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}

// x64 .pdata RUNTIME_FUNCTION — 与 WDK ntimage.h 的 _IMAGE_RUNTIME_FUNCTION_ENTRY 同构
// .pdata 段是 (sorted by BeginAddress) 的 RUNTIME_FUNCTION[] 数组,
// 每个 x64 函数 (除 leaf <= 8 byte 的小函数) 必有一条。
typedef struct _HV_RUNTIME_FUNCTION {
    ULONG BeginAddress;       // RVA, 函数入口
    ULONG EndAddress;         // RVA, 函数末 +1
    ULONG UnwindInfoAddress;  // RVA -> UNWIND_INFO
} HV_RUNTIME_FUNCTION, *PHV_RUNTIME_FUNCTION;

// 解析 PE,定位 addr 是否**正好等于**某个 RUNTIME_FUNCTION 的 BeginAddress —
// 也就是合法函数入口。代替 HvInputIsExecutableAddress —— 后者只判可执行,
// 但 kbdclass 的 .text 里有大量"函数中间标号"指针 (跳板/异常处理回收点等),
// 把它们当成函数入口调用会因为 RAX/RCX 未设而 bugcheck 0xD1 (NULL deref)。
//
// 历史教训:
//   * v1 (无验证):  撞 .rdata 字符串指针 → bugcheck 0xFC (NX)
//   * v2 (仅 MEM_EXECUTE):  撞 .text 中间标号 → bugcheck 0xD1 (mov [rax],rcx with rax=0)
//   * v3 (本版本, .pdata):  只接受 RUNTIME_FUNCTION.BeginAddress 完全匹配
static BOOLEAN HvInputIsFunctionEntry(_In_ PVOID moduleBase, _In_ PVOID addr)
{
    BOOLEAN ok = FALSE;

    __try {
        PHV_IMAGE_DOS_HEADER dos = (PHV_IMAGE_DOS_HEADER)moduleBase;
        if (dos->e_magic != HV_IMAGE_DOS_SIGNATURE) {
            return FALSE;
        }
        PHV_IMAGE_NT_HEADERS64 nt = (PHV_IMAGE_NT_HEADERS64)((PUCHAR)moduleBase + dos->e_lfanew);
        if (nt->Signature != HV_IMAGE_NT_SIGNATURE) {
            return FALSE;
        }

        // DataDirectory[3] = IMAGE_DIRECTORY_ENTRY_EXCEPTION = .pdata
        PHV_IMAGE_DATA_DIRECTORY dd = &nt->OptionalHeader.DataDirectory[HV_IMAGE_DIRECTORY_ENTRY_EXCEPTION];
        if (dd->VirtualAddress == 0 || dd->Size < sizeof(HV_RUNTIME_FUNCTION)) {
            return FALSE;
        }

        ULONG targetRva = (ULONG)((ULONG_PTR)addr - (ULONG_PTR)moduleBase);
        PHV_RUNTIME_FUNCTION rfArr = (PHV_RUNTIME_FUNCTION)((PUCHAR)moduleBase + dd->VirtualAddress);
        ULONG nEntries = dd->Size / sizeof(HV_RUNTIME_FUNCTION);

        // .pdata 按 BeginAddress 严格升序排序 — 二分查找 BeginAddress == targetRva
        ULONG lo = 0, hi = nEntries;
        while (lo < hi) {
            ULONG mid = lo + (hi - lo) / 2;
            ULONG begin = rfArr[mid].BeginAddress;
            if (begin == targetRva) {
                ok = TRUE;
                break;
            }
            if (begin < targetRva) {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
    return ok;
}

// 把指针与 DriverObject 内所有 dispatch / lifecycle 例程比对 —
// MajorFunction[0..IRP_MJ_MAXIMUM_FUNCTION] + DriverInit + DriverUnload + DriverStartIo
// 都是合法函数入口 (.pdata 有它们),但签名跟 ClassServiceCallback 完全不同
// (前者 (DeviceObject, Irp),后者 (DeviceObject, InputDataStart, InputDataEnd, InputDataConsumed))
// 把它们误调用会因为参数错位 bugcheck。
static BOOLEAN HvInputIsDriverDispatchRoutine(_In_opt_ PDRIVER_OBJECT drv, _In_ PVOID addr)
{
    ULONG i;
    if (!drv || !addr) return FALSE;

    for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++) {
        if ((PVOID)drv->MajorFunction[i] == addr) return TRUE;
    }
    if ((PVOID)drv->DriverInit    == addr) return TRUE;
    if ((PVOID)drv->DriverUnload  == addr) return TRUE;
    if ((PVOID)drv->DriverStartIo == addr) return TRUE;
    return FALSE;
}

// 启发式判断指针看起来像不像一个合法的 DEVICE_OBJECT。
// 不做 100% 验证(需要 ObReferenceObjectByPointer + 类型检查,但那需要
// PsProcessType 等导出符号),只做最起码的:kernel 地址 + 16字节对齐 +
// Type 字段 == 3 (IO_TYPE_DEVICE) + Size 合理。误识率极低。
static BOOLEAN HvInputLooksLikeDeviceObject(_In_ PVOID p)
{
    BOOLEAN ok = FALSE;
    __try {
        PDEVICE_OBJECT d = (PDEVICE_OBJECT)p;
        if (!p) return FALSE;
        // kernel space (top half of canonical 48-bit VA)
        if ((ULONG_PTR)p < 0xFFFF800000000000ULL) return FALSE;
        // pool 块对齐 (NPP 块至少 16 字节对齐)
        if ((ULONG_PTR)p & 0xF) return FALSE;
        if (d->Type != 3) return FALSE;  // IO_TYPE_DEVICE
        if (d->Size < sizeof(DEVICE_OBJECT)) return FALSE;
        if (d->Size > 0x1000) return FALSE;  // 防野指针把 USHORT Size 读成天文数字
        ok = TRUE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
    return ok;
}

// 通过 **端口驱动** (kbdhid / mouhid) 找 ClassServiceCallback ——
// 比扫 class driver 自己的 DevExt 可靠得多。
//
// 工作原理:kbdclass 把自己 attach 到 kbdhid 上层时,会向 kbdhid 发
// IOCTL_INTERNAL_KEYBOARD_CONNECT,带一个 CONNECT_DATA 结构:
//     typedef struct _CONNECT_DATA {
//         PDEVICE_OBJECT  ClassDeviceObject;   // 上面 kbdclass 的 device
//         PSERVICE_CALLBACK_ROUTINE ClassService;  // KeyboardClassServiceCallback
//     } CONNECT_DATA;
// kbdhid 把这对值原样存进自己 FDO 的 DeviceExtension(确切 offset 因 Windows
// 版本而异)。我们扫 ext 头部找 **相邻 QWORD 对** (devObj, callback):
//   - 前者必须看起来像 DEVICE_OBJECT (Type=3, kernel 地址)
//   - 后者必须落在 classModule 范围内且是合法 .pdata 函数入口
// 这种"双字段必须同时合法"的匹配几乎不可能误命中,比起单 callback 扫描误识率低几个数量级。
//
// 历史教训:
//   v1-v3: 扫 \Driver\kbdclass 的 DevExt —— 里面有多个内部 callback 指针,
//          首个合法函数入口往往不是 KeyboardClassServiceCallback,call 它会
//          因为期望的状态没初始化而 NULL deref (bugcheck 0xD1 @ kbdclass+0xd5ed)。
//   v4 (本版本): 扫端口驱动 \Driver\kbdhid,找 CONNECT_DATA 对。
static NTSTATUS HvInputFindCallbackViaPortDriver(
    _In_  PCWSTR          portDriverName,    // L"kbdhid" or L"mouhid"
    _In_  PVOID           classModuleBase,
    _In_  PVOID           classModuleEnd,
    _Out_ PDEVICE_OBJECT* outClassDevice,
    _Out_ PVOID*          outCallback)
{
    NTSTATUS status;
    UNICODE_STRING uName;
    WCHAR fullPath[64];
    PDRIVER_OBJECT portDrv = NULL;
    PDEVICE_OBJECT dev;
    ULONG_PTR classBase = (ULONG_PTR)classModuleBase;
    ULONG_PTR classEnd  = (ULONG_PTR)classModuleEnd;

    *outClassDevice = NULL;
    *outCallback    = NULL;

    if (classBase == 0 || classEnd <= classBase) return STATUS_INVALID_PARAMETER;

    RtlStringCchPrintfW(fullPath, RTL_NUMBER_OF(fullPath), L"\\Driver\\%ws", portDriverName);
    RtlInitUnicodeString(&uName, fullPath);

    status = ObReferenceObjectByName(&uName, OBJ_CASE_INSENSITIVE, NULL, 0,
                                     *IoDriverObjectType, KernelMode, NULL,
                                     (PVOID*)&portDrv);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[HV-INPUT] port driver \\Driver\\%ws not found 0x%X\n",
                 portDriverName, status);
        return status;
    }

    for (dev = portDrv->DeviceObject; dev != NULL; dev = dev->NextDevice) {
        PUCHAR ext;
        ULONG offset;

        if (!dev->DeviceExtension) continue;
        ext = (PUCHAR)dev->DeviceExtension;

        // 扫连续 QWORD 对:offset 必须 8-byte 对齐(CONNECT_DATA 的字段都是 PVOID)
        for (offset = 0; offset + 2 * sizeof(PVOID) <= HV_INPUT_DEVEXT_SCAN_MAX;
             offset += sizeof(PVOID)) {
            PVOID candDev, candCb;

            __try {
                candDev = *(PVOID*)(ext + offset);
                candCb  = *(PVOID*)(ext + offset + sizeof(PVOID));
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                break;
            }

            // 前字段必须像 DEVICE_OBJECT
            if (!HvInputLooksLikeDeviceObject(candDev)) continue;

            // 后字段必须在 class 模块范围内
            if ((ULONG_PTR)candCb < classBase || (ULONG_PTR)candCb >= classEnd) continue;

            // 且是 .pdata 注册的函数入口
            if (!HvInputIsFunctionEntry(classModuleBase, candCb)) {
                DbgPrint("[HV-INPUT] %ws ext+0x%X pair (%p, %p): cb not a function entry\n",
                         portDriverName, offset, candDev, candCb);
                continue;
            }

            DbgPrint("[HV-INPUT] %ws ext+0x%X -> CONNECT_DATA{dev=%p, cb=%p} — picked\n",
                     portDriverName, offset, candDev, candCb);

            ObReferenceObject((PDEVICE_OBJECT)candDev);
            *outClassDevice = (PDEVICE_OBJECT)candDev;
            *outCallback    = candCb;
            ObDereferenceObject(portDrv);
            return STATUS_SUCCESS;
        }
    }

    ObDereferenceObject(portDrv);
    return STATUS_NOT_FOUND;
}

// 在 devExt 头部 (前 HV_INPUT_DEVEXT_SCAN_MAX 字节) scan QWORD 对齐的指针,
// 选第一个满足全部条件的指针作为 ClassService 函数指针 candidate:
//   1) 在 moduleBase..moduleEnd 区间内
//   2) **是 .pdata RUNTIME_FUNCTION 的 BeginAddress** (合法函数入口,非数据/非函数中间)
//   3) **不在 drv->MajorFunction[] / DriverInit / DriverUnload / DriverStartIo 集合中**
//      (这些是 dispatch / lifecycle 例程,签名跟 ClassServiceCallback 不兼容)
//
// 历史教训 / 弃用注记:
//   * v1 (无验证):  撞 .rdata 字符串指针 → bugcheck 0xFC (NX, ATTEMPTED_EXECUTE_OF_NOEXECUTE_MEMORY)
//   * v2 (仅 MEM_EXECUTE):  撞 .text 中间标号 → bugcheck 0xD1 (mov [rax],rcx with rax=0)
//   * v3 (.pdata + DriverObject 过滤):  仍撞 kbdclass+0xd5ed 类似的内部 helper —
//     kbdclass 自己的 DevExt 里有多个合法函数入口指针,首个不一定是 ClassServiceCallback
//   * v4: 改走端口驱动 (kbdhid/mouhid) 的 CONNECT_DATA 对(见 HvInputFindCallbackViaPortDriver),
//     本函数仅作为 v4 失败时的回退路径保留
static PVOID HvInputScanDevExtForClassService(
    _In_ PDEVICE_OBJECT devObj,
    _In_opt_ PDRIVER_OBJECT drv,
    _In_ PVOID moduleBase,
    _In_ PVOID moduleEnd)
{
    PUCHAR ext;
    ULONG offset;
    ULONG_PTR base = (ULONG_PTR)moduleBase;
    ULONG_PTR end  = (ULONG_PTR)moduleEnd;

    if (!devObj || !devObj->DeviceExtension) return NULL;
    if (base == 0 || end <= base) return NULL;
    ext = (PUCHAR)devObj->DeviceExtension;

    for (offset = 0; offset + sizeof(PVOID) <= HV_INPUT_DEVEXT_SCAN_MAX; offset += sizeof(PVOID)) {
        PVOID candidate;

        __try {
            candidate = *(PVOID*)(ext + offset);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            break;
        }

        if ((ULONG_PTR)candidate < base || (ULONG_PTR)candidate >= end) {
            continue;
        }
        // 必须是 .pdata 里登记的合法函数入口 —— 排除 .rdata/.pdata/.data
        // 数据指针 (bugcheck 0xFC) 和 .text 函数中间标号 (bugcheck 0xD1)
        if (!HvInputIsFunctionEntry(moduleBase, candidate)) {
            DbgPrint("[HV-INPUT] devExt+0x%X -> %p (in module but not a .pdata entry, skip)\n",
                     offset, candidate);
            continue;
        }
        // 排除 driver 自己的 dispatch / lifecycle 例程 —— 它们是合法函数入口,
        // 但签名是 (DeviceObject, Irp) 而不是 (DeviceObject, InputStart, InputEnd, *Consumed)
        if (HvInputIsDriverDispatchRoutine(drv, candidate)) {
            DbgPrint("[HV-INPUT] devExt+0x%X -> %p (driver dispatch/lifecycle, skip)\n",
                     offset, candidate);
            continue;
        }
        DbgPrint("[HV-INPUT] devExt+0x%X -> %p (function entry, non-dispatch) — picked as ClassService\n",
                 offset, candidate);
        return candidate;
    }
    return NULL;
}

// 发现一组 (class driver, port driver, class module) 的 ServiceCallback。
// 优先走端口驱动 CONNECT_DATA 对(v4 主路径),失败回退到 class driver DevExt 扫描(v3)。
// 成功时 outDriver/outDevice/outCallback 全部就绪,调用方负责 ObDereference。
static NTSTATUS HvInputDiscoverOneClass(
    _In_  PCWSTR classDriverName,       // L"kbdclass" / L"mouclass"
    _In_  PCSTR  classModuleLeaf,       // "kbdclass.sys" / "mouclass.sys"
    _In_  PCWSTR portDriverName,        // L"kbdhid" / L"mouhid"
    _Out_ PDRIVER_OBJECT* outDriver,
    _Out_ PDEVICE_OBJECT* outDevice,
    _Out_ PVOID*          outCallback)
{
    NTSTATUS status;
    PVOID modBase, modEnd;
    UNICODE_STRING uName;
    WCHAR fullPath[64];
    PDRIVER_OBJECT classDrv = NULL;
    PDEVICE_OBJECT classDev = NULL;
    PVOID cb = NULL;

    *outDriver = NULL;
    *outDevice = NULL;
    *outCallback = NULL;

    // 解析 class 模块范围(callback 必须落在这里)
    status = HvInputResolveModuleRange(classModuleLeaf, &modBase, &modEnd);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[HV-INPUT] module range %s not found 0x%X\n", classModuleLeaf, status);
        return status;
    }
    DbgPrint("[HV-INPUT] %s @ %p - %p\n", classModuleLeaf, modBase, modEnd);

    // class driver 的引用(防止 unload,且 HvInputReleaseUsbHid 时要 ObDereference)
    RtlStringCchPrintfW(fullPath, RTL_NUMBER_OF(fullPath), L"\\Driver\\%ws", classDriverName);
    RtlInitUnicodeString(&uName, fullPath);
    status = ObReferenceObjectByName(&uName, OBJ_CASE_INSENSITIVE, NULL, 0,
                                     *IoDriverObjectType, KernelMode, NULL,
                                     (PVOID*)&classDrv);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[HV-INPUT] \\Driver\\%ws not found 0x%X\n", classDriverName, status);
        return status;
    }

    // v4 主路径:扫端口驱动 (kbdhid/mouhid) 的 CONNECT_DATA 对
    status = HvInputFindCallbackViaPortDriver(portDriverName, modBase, modEnd,
                                              &classDev, &cb);
    if (NT_SUCCESS(status) && cb && classDev) {
        DbgPrint("[HV-INPUT] %ws via port driver %ws OK dev=%p cb=%p\n",
                 classDriverName, portDriverName, classDev, cb);
        *outDriver   = classDrv;
        *outDevice   = classDev;
        *outCallback = cb;
        return STATUS_SUCCESS;
    }

    DbgPrint("[HV-INPUT] %ws via port driver %ws failed 0x%X, fallback to class scan\n",
             classDriverName, portDriverName, status);

    // 回退:扫 class driver 自己的 DevExt(v3 风格,.pdata + DriverObject 过滤)
    for (PDEVICE_OBJECT dev = classDrv->DeviceObject; dev != NULL; dev = dev->NextDevice) {
        cb = HvInputScanDevExtForClassService(dev, classDrv, modBase, modEnd);
        if (cb) {
            ObReferenceObject(dev);
            DbgPrint("[HV-INPUT] %ws via class scan OK dev=%p cb=%p\n",
                     classDriverName, dev, cb);
            *outDriver   = classDrv;
            *outDevice   = dev;
            *outCallback = cb;
            return STATUS_SUCCESS;
        }
    }

    DbgPrint("[HV-INPUT] %ws fallback also failed\n", classDriverName);
    ObDereferenceObject(classDrv);
    return STATUS_NOT_FOUND;
}

// 完整 USB HID 后端发现 — 失败时 backend 维持原值,调用方决定是否回退
static NTSTATUS HvInputDiscoverUsbHid(VOID)
{
    NTSTATUS status;
    PDRIVER_OBJECT drv;
    PDEVICE_OBJECT dev;
    PVOID cb;

    // 键盘 — \Driver\kbdclass + kbdclass.sys, 端口 \Driver\kbdhid
    status = HvInputDiscoverOneClass(L"kbdclass", "kbdclass.sys", L"kbdhid",
                                     &drv, &dev, &cb);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[HV-INPUT] USB HID kbd discovery failed 0x%X\n", status);
        return status;
    }
    g_KbdClassDriverObject = drv;
    g_KbdClassDeviceObject = dev;
    g_KbdServiceCallback   = (PHV_KBD_SERVICE_CALLBACK)cb;

    // 鼠标 — \Driver\mouclass + mouclass.sys, 端口 \Driver\mouhid
    status = HvInputDiscoverOneClass(L"mouclass", "mouclass.sys", L"mouhid",
                                     &drv, &dev, &cb);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[HV-INPUT] USB HID mouse discovery failed 0x%X (kbd OK)\n", status);
        // 键盘 OK 即可用,但 mouse 不行 — 接收所有 OK 但记为"半 ready"
        g_MouseClassDriverObject = NULL;
        g_MouseClassDeviceObject = NULL;
        g_MouseServiceCallback   = NULL;
        return STATUS_SUCCESS;  // 部分 OK
    }
    g_MouseClassDriverObject = drv;
    g_MouseClassDeviceObject = dev;
    g_MouseServiceCallback   = (PHV_MOU_SERVICE_CALLBACK)cb;

    DbgPrint("[HV-INPUT] USB HID discovery OK kbd_cb=%p mouse_cb=%p\n",
             g_KbdServiceCallback, g_MouseServiceCallback);
    return STATUS_SUCCESS;
}

static VOID HvInputReleaseUsbHid(VOID)
{
    if (g_KbdClassDeviceObject) {
        ObDereferenceObject(g_KbdClassDeviceObject);
        g_KbdClassDeviceObject = NULL;
    }
    if (g_KbdClassDriverObject) {
        ObDereferenceObject(g_KbdClassDriverObject);
        g_KbdClassDriverObject = NULL;
    }
    g_KbdServiceCallback = NULL;

    if (g_MouseClassDeviceObject) {
        ObDereferenceObject(g_MouseClassDeviceObject);
        g_MouseClassDeviceObject = NULL;
    }
    if (g_MouseClassDriverObject) {
        ObDereferenceObject(g_MouseClassDriverObject);
        g_MouseClassDriverObject = NULL;
    }
    g_MouseServiceCallback = NULL;
}

// ============================================================
// USB HID 后端: 实际 callback 调用 (DISPATCH_LEVEL)
// ============================================================

static NTSTATUS HvInputUsbHidSendKey(UCHAR scancode, BOOLEAN isExtended, BOOLEAN isBreak)
{
    KEYBOARD_INPUT_DATA d;
    ULONG consumed = 0;
    KIRQL oldIrql;

    if (!g_KbdServiceCallback || !g_KbdClassDeviceObject) {
        return STATUS_DEVICE_NOT_CONNECTED;
    }

    RtlZeroMemory(&d, sizeof(d));
    d.UnitId          = g_KbdUnitId;
    d.MakeCode        = (USHORT)scancode;
    d.Flags           = (USHORT)((isBreak ? KEY_BREAK : KEY_MAKE) |
                                 (isExtended ? KEY_E0 : 0));
    d.ExtraInformation = 0;

    KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);
    __try {
        g_KbdServiceCallback(g_KbdClassDeviceObject, &d, (&d) + 1, &consumed);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        KeLowerIrql(oldIrql);
        DbgPrint("[HV-INPUT] USB HID kbd callback raised exception 0x%X\n",
                 GetExceptionCode());
        return STATUS_UNSUCCESSFUL;
    }
    KeLowerIrql(oldIrql);

    return STATUS_SUCCESS;
}

// 按钮 mask (HV_INPUT_MBUTTON_L/R/M) → MOUSE_INPUT_DATA::Flags 的 LEFT/RIGHT/MIDDLE bits
// 注意: MOUSE_INPUT_DATA 的 button bits 是 EDGE (down/up),不是 STATE。
// 我们设计上让 GUI 传 MASK = 当前持有的按钮 mask,这里翻译成所有 mask 内按钮的 down。
// 调用方再发一次 buttons=0 才算抬起 — 跟 GUI 的"original_click 配对"语义一致。
// (mouse_track_state 由 GUI/调用方维护;driver 不持久化 — 跟 PS/2 路径一致)
#define HV_HID_MBUTTON_L  0x01
#define HV_HID_MBUTTON_R  0x02
#define HV_HID_MBUTTON_M  0x04

static USHORT HvInputButtonsToHidFlags(UCHAR buttons, UCHAR prevButtons)
{
    USHORT flags = 0;
    UCHAR down = (UCHAR)(buttons & ~prevButtons);
    UCHAR up   = (UCHAR)(prevButtons & ~buttons);
    if (down & HV_HID_MBUTTON_L) flags |= MOUSE_LEFT_BUTTON_DOWN;
    if (up   & HV_HID_MBUTTON_L) flags |= MOUSE_LEFT_BUTTON_UP;
    if (down & HV_HID_MBUTTON_R) flags |= MOUSE_RIGHT_BUTTON_DOWN;
    if (up   & HV_HID_MBUTTON_R) flags |= MOUSE_RIGHT_BUTTON_UP;
    if (down & HV_HID_MBUTTON_M) flags |= MOUSE_MIDDLE_BUTTON_DOWN;
    if (up   & HV_HID_MBUTTON_M) flags |= MOUSE_MIDDLE_BUTTON_UP;
    return flags;
}

// 按钮状态跟踪 — 在 driver 端维护当前按下的物理按钮(从合成视角),
// 这样 GUI 只用传"当前应处的状态 mask"就行,driver 自动算 down/up edge。
// 也支持调用方传 raw edge (smooth=2),v1 先不暴露。
static volatile UCHAR g_HidButtonsState = 0;

static NTSTATUS HvInputUsbHidSendMouseOnce(SHORT dx, SHORT dy, UCHAR buttons)
{
    MOUSE_INPUT_DATA d;
    ULONG consumed = 0;
    KIRQL oldIrql;
    UCHAR prev;

    if (!g_MouseServiceCallback || !g_MouseClassDeviceObject) {
        return STATUS_DEVICE_NOT_CONNECTED;
    }

    prev = (UCHAR)InterlockedExchange8((volatile CHAR*)&g_HidButtonsState, (CHAR)buttons);

    RtlZeroMemory(&d, sizeof(d));
    d.UnitId      = g_MouseUnitId;
    d.Flags       = MOUSE_MOVE_RELATIVE;
    d.ButtonFlags = HvInputButtonsToHidFlags(buttons, prev);
    d.ButtonData  = 0;
    d.RawButtons  = 0;
    d.LastX       = dx;
    d.LastY       = dy;
    d.ExtraInformation = 0;

    KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);
    __try {
        g_MouseServiceCallback(g_MouseClassDeviceObject, &d, (&d) + 1, &consumed);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        KeLowerIrql(oldIrql);
        DbgPrint("[HV-INPUT] USB HID mouse callback raised exception 0x%X\n",
                 GetExceptionCode());
        return STATUS_UNSUCCESSFUL;
    }
    KeLowerIrql(oldIrql);
    return STATUS_SUCCESS;
}

// ============================================================
// 公共 API: Initialize / Shutdown
// ============================================================

NTSTATUS HvInputInitialize(VOID)
{
    NTSTATUS status;
    NTSTATUS ps2Status;
    NTSTATUS hidStatus;
    ULONG i;
    LARGE_INTEGER perf;
    BOOLEAN ioBitmapAllocated = FALSE;

    if (g_InputInitialized) {
        return STATUS_ALREADY_INITIALIZED;
    }

    ExInitializeRundownProtection(&g_InputDpcRundown);
    InterlockedExchange(&g_InputDpcRundownInitialized, TRUE);
    InterlockedExchange(&g_InputShutdownStarted, FALSE);

    DbgPrint("[HV-INPUT] Initializing — probing backends...\n");
    g_Backend = HV_INPUT_BACKEND_NONE;

    // 公共初始化 (FIFO + AutoBreak + RNG + Layer 4 kbd state) — 即使最后走 USB HID,共享部分也无害
    HvInputFifoInit(&g_KbdFifo);
    HvInputFifoInit(&g_MouseFifo);
    KeInitializeSpinLock(&g_XhciKbdState.Lock);
    HvInputXhciKbdReset();

    RtlZeroMemory(g_AutoBreakSlots, sizeof(g_AutoBreakSlots));
    for (i = 0; i < HV_INPUT_AUTOBREAK_SLOTS; i++) {
        KeInitializeTimer(&g_AutoBreakSlots[i].Timer);
        KeInitializeDpc(&g_AutoBreakSlots[i].Dpc,
                        HvInputAutoBreakDpc,
                        &g_AutoBreakSlots[i]);
    }

    perf = KeQueryPerformanceCounter(NULL);
    g_RngState ^= (ULONG64)perf.QuadPart;
    g_RngState |= 1;

    // ============================================================
    // (A) 先试 PS/2 IOAPIC 向量发现 — 现代台式机有 PS/2 口、虚拟机
    //     默认都会成功;USB-only laptop 会拿到 0xFF 失败。
    // ============================================================

    g_IoBitmapA = HvAllocateAlignedMemory(PAGE_SIZE, &g_IoBitmapAPhys);
    g_IoBitmapB = HvAllocateAlignedMemory(PAGE_SIZE, &g_IoBitmapBPhys);
    if (g_IoBitmapA && g_IoBitmapB) {
        RtlZeroMemory(g_IoBitmapA, PAGE_SIZE);
        RtlZeroMemory(g_IoBitmapB, PAGE_SIZE);
        HvInputSetBitmapBit(g_IoBitmapA, 0x60);
        HvInputSetBitmapBit(g_IoBitmapA, 0x64);
        ioBitmapAllocated = TRUE;

        ps2Status = HvInputDiscoverVectors();
        if (NT_SUCCESS(ps2Status)) {
            g_Backend = HV_INPUT_BACKEND_PS2;
            g_InputInitialized = TRUE;
            g_InputEnabled = FALSE;
            DbgPrint("[HV-INPUT] backend = PS/2 (kbdVec=0x%X mouseVec=0x%X)\n",
                     g_KbdVector, g_MouseVector);
            return STATUS_SUCCESS;
        }
        DbgPrint("[HV-INPUT] PS/2 backend unavailable 0x%X — trying USB HID\n", ps2Status);
    } else {
        DbgPrint("[HV-INPUT] IO bitmap alloc failed — skipping PS/2 backend\n");
        ps2Status = STATUS_INSUFFICIENT_RESOURCES;
    }

    // PS/2 不可用 — IO bitmap 没人用,释放掉
    if (g_IoBitmapA) { MmFreeContiguousMemory(g_IoBitmapA); g_IoBitmapA = NULL; }
    if (g_IoBitmapB) { MmFreeContiguousMemory(g_IoBitmapB); g_IoBitmapB = NULL; }
    ioBitmapAllocated = FALSE;
    g_KbdVector = 0;
    g_MouseVector = 0;

    // ============================================================
    // (B) USB HID v3 — 总是去发现 kbdclass / mouclass 的 ClassService callback,
    //     无论 xHCI 是否 ready。原因:
    //       - xHCI Layer 4 注入复杂,运行时可能因 TR Dequeue 漂移 / TRB 类型
    //         不匹配等而失败;此时 HvInputSendKey/Mouse 需要立即可用的 v3 fallback
    //       - xHCI 即使 ready 也可能只找到 kbd 而没 mouse (本机情况),
    //         鼠标必须走 v3
    //     不影响 xHCI 的优先级:只是 v3 句柄常驻,作为 runtime fallback
    // ============================================================

    hidStatus = HvInputDiscoverUsbHid();
    if (NT_SUCCESS(hidStatus) && g_KbdServiceCallback != NULL) {
        DbgPrint("[HV-INPUT] USB HID v3 discovered (kbd_cb=%p mouse_cb=%p) — runtime fallback ready\n",
                 g_KbdServiceCallback, g_MouseServiceCallback);
    } else {
        DbgPrint("[HV-INPUT] USB HID v3 discover failed 0x%X (no v3 fallback available)\n", hidStatus);
        HvInputReleaseUsbHid();
    }

    // ============================================================
    // (C) Layer 4 — xHCI Event Ring TRB + MSI (VT-透明,最高优先级)
    //     如果 ready 就声明 backend = XHCI;HvInputSendKey/Mouse 优先走 xHCI,
    //     失败再回落 v3。
    // ============================================================

    if (HvUsbXhciIsReady()) {
        g_Backend = HV_INPUT_BACKEND_XHCI;
        g_InputInitialized = TRUE;
        g_InputEnabled = FALSE;
        DbgPrint("[HV-INPUT] backend = xHCI (Layer 4 VT-transparent, v3 fallback %s)\n",
                 g_KbdServiceCallback ? "armed" : "NOT armed");
        return STATUS_SUCCESS;
    }
    DbgPrint("[HV-INPUT] xHCI Layer 4 not ready — using USB HID v3 as primary\n");

    // xHCI 不 ready 时,看 v3 是否 ready
    if (g_KbdServiceCallback != NULL) {
        g_Backend = HV_INPUT_BACKEND_USB_HID;
        g_InputInitialized = TRUE;
        g_InputEnabled = FALSE;
        DbgPrint("[HV-INPUT] backend = USB HID (kbd_cb=%p mouse_cb=%p)\n",
                 g_KbdServiceCallback, g_MouseServiceCallback);
        return STATUS_SUCCESS;
    }

    // 三个后端都不行 — 干净释放 + STATUS_NOT_SUPPORTED
    status = STATUS_NOT_SUPPORTED;
    g_Backend = HV_INPUT_BACKEND_NONE;
    g_InputInitialized = FALSE;
    UNREFERENCED_PARAMETER(ioBitmapAllocated);
    return status;
}

VOID HvInputBeginShutdown(VOID)
{
    ULONG i;

    if (InterlockedExchange(&g_InputShutdownStarted, TRUE) != FALSE) {
        return;
    }

    InterlockedExchange8((volatile CHAR*)&g_InputEnabled, FALSE);
    InterlockedExchange8((volatile CHAR*)&g_InputInitialized, FALSE);

    /* VMCS instances reference the I/O bitmap directly.  Remove the PS/2
     * intercept before publishing shutdown, but keep the pages allocated
     * until HvCleanup has taken every CPU out of VMX. */
    HvInputClearBitmapBit(g_IoBitmapA, 0x60);
    HvInputClearBitmapBit(g_IoBitmapA, 0x64);
    KeMemoryBarrier();

    for (i = 0; i < HV_INPUT_AUTOBREAK_SLOTS; i++) {
        KeCancelTimer(&g_AutoBreakSlots[i].Timer);
        KeRemoveQueueDpc(&g_AutoBreakSlots[i].Dpc);
        InterlockedExchange(&g_AutoBreakSlots[i].InUse, 0);
    }

    if (InterlockedCompareExchange(&g_InputDpcRundownInitialized, 0, 0) != 0) {
        ExWaitForRundownProtectionRelease(&g_InputDpcRundown);
    }
}

VOID HvInputShutdown(VOID)
{
    ULONG i;

    HvInputBeginShutdown();

    if (!g_InputInitialized && g_Backend == HV_INPUT_BACKEND_NONE) {
        // 没初始化成功就直接 return,但 USB HID 也可能引用了对象
        HvInputReleaseUsbHid();
        return;
    }
    DbgPrint("[HV-INPUT] Shutting down (backend=%d)\n", g_Backend);

    g_InputEnabled = FALSE;

    // 取消所有 pending AutoBreak timers (两个 backend 都用)
    for (i = 0; i < HV_INPUT_AUTOBREAK_SLOTS; i++) {
        KeCancelTimer(&g_AutoBreakSlots[i].Timer);
        InterlockedExchange(&g_AutoBreakSlots[i].InUse, 0);
    }

    // PS/2 — 释放 IO bitmap
    if (g_IoBitmapA) { MmFreeContiguousMemory(g_IoBitmapA); g_IoBitmapA = NULL; }
    if (g_IoBitmapB) { MmFreeContiguousMemory(g_IoBitmapB); g_IoBitmapB = NULL; }

    // USB HID — 释放设备/驱动引用
    HvInputReleaseUsbHid();

    g_Backend = HV_INPUT_BACKEND_NONE;
    g_InputInitialized = FALSE;
}

// VMCS 配置时调用 — 只有 PS/2 后端需要在 cpuBasedControls 设 USE_IO_BITMAPS。
// USB HID 后端不动 VMCS,所以这里要返回 FALSE 才能避免不必要的 VMEXIT。
#undef HvInputIsInitialized
BOOLEAN HvInputNeedsIoBitmap(VOID)
{
    return g_InputInitialized && g_Backend == HV_INPUT_BACKEND_PS2;
}

HV_INPUT_BACKEND HvInputGetBackend(VOID)
{
    return g_Backend;
}

VOID HvInputQueryStatus(_Out_ PHV_INPUT_STATUS status)
{
    if (!status) return;
    RtlZeroMemory(status, sizeof(*status));
    status->Backend         = (UCHAR)g_Backend;
    status->Initialized     = (UCHAR)(g_InputInitialized ? 1 : 0);
    status->Enabled         = (UCHAR)(g_InputEnabled ? 1 : 0);
    status->StrictXhciMode  = (UCHAR)(g_StrictXhciMode ? 1 : 0);

    switch (g_Backend) {
    case HV_INPUT_BACKEND_PS2:
        status->KbdReady   = (UCHAR)((g_KbdVector  >= 0x20 && g_KbdVector  < 0xFF) ? 1 : 0);
        status->MouseReady = (UCHAR)((g_MouseVector >= 0x20 && g_MouseVector < 0xFF) ? 1 : 0);
        status->KbdVector  = g_KbdVector;
        status->MouseVector = g_MouseVector;
        break;
    case HV_INPUT_BACKEND_USB_HID:
        status->KbdReady   = (UCHAR)(g_KbdServiceCallback   ? 1 : 0);
        status->MouseReady = (UCHAR)(g_MouseServiceCallback ? 1 : 0);
        status->KbdCallback   = (ULONG64)(ULONG_PTR)g_KbdServiceCallback;
        status->MouseCallback = (ULONG64)(ULONG_PTR)g_MouseServiceCallback;
        status->KbdDeviceObject   = (ULONG64)(ULONG_PTR)g_KbdClassDeviceObject;
        status->MouseDeviceObject = (ULONG64)(ULONG_PTR)g_MouseClassDeviceObject;
        break;
    case HV_INPUT_BACKEND_XHCI:
        // Layer 4: xHCI Event Ring 注入 — 详细字段走 IOCTL_HV_INPUT_GET_XHCI_STATUS
        status->KbdReady   = (UCHAR)(HvUsbXhciIsReady() ? 1 : 0);
        status->MouseReady = status->KbdReady;
        break;
    default:
        break;
    }
}

// ============================================================
// 公共 API: Enable / Disable
// ============================================================

NTSTATUS HvInputEnable(VOID)
{
    if (!g_InputInitialized || g_Backend == HV_INPUT_BACKEND_NONE) {
        return STATUS_DEVICE_NOT_READY;
    }
    g_InputEnabled = TRUE;
    DbgPrint("[HV-INPUT] enabled (backend=%d)\n", g_Backend);
    return STATUS_SUCCESS;
}

VOID HvInputDisable(VOID)
{
    ULONG i;
    KIRQL irql;

    g_InputEnabled = FALSE;
    DbgPrint("[HV-INPUT] disabled\n");

    if (g_InputInitialized) {
        // 清空 PS/2 FIFO
        KeAcquireSpinLock(&g_KbdFifo.Lock, &irql);
        g_KbdFifo.Head = g_KbdFifo.Tail = g_KbdFifo.Count = 0;
        KeReleaseSpinLock(&g_KbdFifo.Lock, irql);

        KeAcquireSpinLock(&g_MouseFifo.Lock, &irql);
        g_MouseFifo.Head = g_MouseFifo.Tail = g_MouseFifo.Count = 0;
        KeReleaseSpinLock(&g_MouseFifo.Lock, irql);

        // 取消未触发的 AutoBreak
        for (i = 0; i < HV_INPUT_AUTOBREAK_SLOTS; i++) {
            KeCancelTimer(&g_AutoBreakSlots[i].Timer);
            InterlockedExchange(&g_AutoBreakSlots[i].InUse, 0);
        }

        // USB HID — 抬起所有当前 down 的按钮,避免 disable 后留下"按住"状态
        if (g_Backend == HV_INPUT_BACKEND_USB_HID && g_MouseServiceCallback) {
            UCHAR prev = (UCHAR)InterlockedExchange8((volatile CHAR*)&g_HidButtonsState, 0);
            if (prev != 0) {
                // 直接调一次 down/up edge transition all-up 的 packet
                MOUSE_INPUT_DATA d;
                ULONG consumed = 0;
                KIRQL oldIrql;
                RtlZeroMemory(&d, sizeof(d));
                d.Flags       = MOUSE_MOVE_RELATIVE;
                d.ButtonFlags = HvInputButtonsToHidFlags(0, prev);
                KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);
                __try {
                    g_MouseServiceCallback(g_MouseClassDeviceObject, &d, (&d)+1, &consumed);
                } __except (EXCEPTION_EXECUTE_HANDLER) {}
                KeLowerIrql(oldIrql);
            }
        }
    }
}

// ============================================================
// 公共 API: 严格 xHCI 模式
// ============================================================

VOID HvInputSetStrictMode(BOOLEAN strict)
{
    g_StrictXhciMode = strict;
    DbgPrint("[HV-INPUT] strict xHCI mode = %s\n", strict ? "ON" : "OFF");
}

BOOLEAN HvInputGetStrictMode(VOID)
{
    return g_StrictXhciMode;
}

// ============================================================
// 公共 API: VMCS 配置访问
// ============================================================

PHYSICAL_ADDRESS HvInputGetIoBitmapAPhys(VOID)
{
    return g_IoBitmapAPhys;
}

PHYSICAL_ADDRESS HvInputGetIoBitmapBPhys(VOID)
{
    return g_IoBitmapBPhys;
}

// ============================================================
// 公共 API: SendKey / SendMouse
// ============================================================

static VOID HvInputKickDelivery(VOID)
{
    // 广播 IPI 强制所有 CPU 短暂离开 guest;某个 CPU 会通过 ExternalInterrupt
    // 或 CPUID VMEXIT 路径走到 HvInputTryDeliver。
    // KeIpiGenericCall 内部就是 RaiseIrql IPI_LEVEL + send IPI vector,
    // 受影响的 CPU 处理 IPI 时若 EXT_INTR_EXITING off 就直接进 guest IDT,
    // 但 IPI callback 里我们调 __cpuid 强制 VMEXIT。
    KeIpiGenericCall(HvInputDeliverIpiCallback, 0);
}

NTSTATUS HvInputSendKey(UCHAR scancode,
                        BOOLEAN isExtended,
                        BOOLEAN isBreak,
                        BOOLEAN autoBreak)
{
    UCHAR byte;

    if (!g_InputInitialized) return STATUS_DEVICE_NOT_READY;
    if (!g_InputEnabled)     return STATUS_DEVICE_POWER_FAILURE;

    // ==================== Layer 4: 真 VT-透明 USB HID 路径 (优先) ====================
    // 不分 g_Backend — 只要 xHCI 控制器探到了并 ready 且找到对应 HID 设备,就尝试。
    // 失败时:严格模式 → 直接返错;非严格 → 回退到下面的 v3 ring-0 直调。
    if (HvUsbXhciIsReady() && g_HvUsbXhci.Keyboard != NULL) {
        NTSTATUS s = HvInputXhciTrySendKey(scancode, isExtended, isBreak);
        DbgPrint("[HV-INPUT] kbd sc=0x%02X ext=%u brk=%u → xHCI status=0x%08X\n",
                 scancode, isExtended, isBreak, s);
        if (NT_SUCCESS(s)) {
            if (autoBreak && !isBreak) {
                HvInputArmAutoBreak(scancode, isExtended);
            }
            return STATUS_SUCCESS;
        }
        if (g_StrictXhciMode) {
            DbgPrint("[HV-INPUT] strict mode: xHCI failed, NOT falling back to v3 (status=0x%08X)\n", s);
            return s;
        }
        // 非严格 — 透传给下面路径 (v3 fallback)
    } else if (g_StrictXhciMode) {
        DbgPrint("[HV-INPUT] strict mode: xHCI not ready or no keyboard, NOT falling back to v3\n");
        return STATUS_DEVICE_NOT_READY;
    }

    // ==================== USB HID v3 fallback (ring-0 直调 kbdclass) ====================
    // 即使 g_Backend == XHCI 也走这里 — 只要 g_KbdServiceCallback 在,init 时常驻
    if (g_KbdServiceCallback != NULL) {
        NTSTATUS s = HvInputUsbHidSendKey(scancode, isExtended, isBreak);
        DbgPrint("[HV-INPUT] kbd sc=0x%02X ext=%u brk=%u → v3 status=0x%08X\n",
                 scancode, isExtended, isBreak, s);
        if (!NT_SUCCESS(s)) return s;
        if (autoBreak && !isBreak) {
            HvInputArmAutoBreak(scancode, isExtended);
        }
        return STATUS_SUCCESS;
    }

    // ==================== PS/2 backend ====================
    // PS/2 set 1: break = make | 0x80
    byte = isBreak ? (UCHAR)(scancode | 0x80) : scancode;

    if (isExtended) {
        if (!HvInputFifoPush_Passive(&g_KbdFifo, 0xE0)) {
            return STATUS_DEVICE_NOT_CONNECTED;
        }
    }
    if (!HvInputFifoPush_Passive(&g_KbdFifo, byte)) {
        return STATUS_DEVICE_NOT_CONNECTED;
    }

    HvInputKickDelivery();

    if (autoBreak && !isBreak) {
        // KeSetTimer 不能在 DISPATCH_LEVEL 设 — caller 是 PASSIVE_LEVEL (IOCTL)
        HvInputArmAutoBreak(scancode, isExtended);
    }
    return STATUS_SUCCESS;
}

NTSTATUS HvInputSendMouse(SHORT dx, SHORT dy, UCHAR buttons, BOOLEAN smooth)
{
    UCHAR pkt0, pkt1, pkt2;
    SHORT remX, remY;
    SHORT stepX, stepY;
    LARGE_INTEGER delay;

    if (!g_InputInitialized) return STATUS_DEVICE_NOT_READY;
    if (!g_InputEnabled)     return STATUS_DEVICE_POWER_FAILURE;

    // ==================== Layer 4: 真 VT-透明 USB HID 路径 (优先) ====================
    // 只有在 xHCI 找到了 mouse 设备时才尝试 (本机情况:kbd=yes mouse=no,直接跳 fallback)
    if (HvUsbXhciIsReady() && g_HvUsbXhci.Mouse != NULL) {
        if (smooth && (dx > 127 || dx < -127 || dy > 127 || dy < -127)) {
            // 拆帧 + 帧间 16ms — HID Boot mouse Dx/Dy 是 ±127 一字节,大位移须分段
            remX = dx; remY = dy;
            while (remX != 0 || remY != 0) {
                stepX = (remX >  127) ?  127 : (remX < -127) ? -127 : remX;
                stepY = (remY >  127) ?  127 : (remY < -127) ? -127 : remY;
                remX -= stepX;
                remY -= stepY;
                NTSTATUS s = HvInputXhciTrySendMouse(stepX, stepY, buttons);
                if (!NT_SUCCESS(s)) {
                    if (g_StrictXhciMode) {
                        DbgPrint("[HV-INPUT] strict mode: xHCI mouse segment failed (status=0x%08X), abort\n", s);
                        return s;
                    }
                    goto xhci_fallback;
                }
                if (remX != 0 || remY != 0) {
                    delay.QuadPart = -160000LL;
                    KeDelayExecutionThread(KernelMode, FALSE, &delay);
                }
            }
            return STATUS_SUCCESS;
        }
        {
            NTSTATUS s = HvInputXhciTrySendMouse(dx, dy, buttons);
            DbgPrint("[HV-INPUT] mouse dx=%d dy=%d btn=0x%02X → xHCI status=0x%08X\n",
                     dx, dy, buttons, s);
            if (NT_SUCCESS(s)) return STATUS_SUCCESS;
            if (g_StrictXhciMode) {
                DbgPrint("[HV-INPUT] strict mode: xHCI mouse failed, NOT falling back to v3 (status=0x%08X)\n", s);
                return s;
            }
        }
    } else if (g_StrictXhciMode) {
        DbgPrint("[HV-INPUT] strict mode: xHCI not ready or no mouse, NOT falling back to v3\n");
        return STATUS_DEVICE_NOT_READY;
    }
xhci_fallback:

    // ==================== USB HID v3 fallback (ring-0 直调 mouclass) ====================
    // 即使 g_Backend == XHCI 也走这里 — 只要 g_MouseServiceCallback 在
    if (g_MouseServiceCallback != NULL) {
        if (smooth && (dx > 8 || dx < -8 || dy > 8 || dy < -8)) {
            // 拆帧 + 帧间 16ms — 跟 PS/2 路径行为对齐
            remX = dx; remY = dy;
            while (remX != 0 || remY != 0) {
                stepX = (remX >  8) ?  8 : (remX < -8) ? -8 : remX;
                stepY = (remY >  8) ?  8 : (remY < -8) ? -8 : remY;
                remX -= stepX;
                remY -= stepY;
                (VOID)HvInputUsbHidSendMouseOnce(stepX, stepY, buttons);
                if (remX != 0 || remY != 0) {
                    delay.QuadPart = -160000LL;
                    KeDelayExecutionThread(KernelMode, FALSE, &delay);
                }
            }
            return STATUS_SUCCESS;
        }
        return HvInputUsbHidSendMouseOnce(dx, dy, buttons);
    }

    // ==================== PS/2 backend ====================
    if (smooth && (dx > 8 || dx < -8 || dy > 8 || dy < -8)) {
        // 拆成多帧,每帧 ≤ 8 像素 / 轴,16ms 间隔
        remX = dx; remY = dy;
        while (remX != 0 || remY != 0) {
            stepX = (remX >  8) ?  8 : (remX < -8) ? -8 : remX;
            stepY = (remY >  8) ?  8 : (remY < -8) ? -8 : remY;
            remX -= stepX;
            remY -= stepY;
            (VOID)HvInputSendMouse(stepX, stepY, buttons, FALSE);
            if (remX != 0 || remY != 0) {
                // 16ms 帧间隔 (约 60 Hz)
                delay.QuadPart = -160000LL;  // 100ns units
                KeDelayExecutionThread(KernelMode, FALSE, &delay);
            }
        }
        return STATUS_SUCCESS;
    }

    // PS/2 mouse 3-byte packet:
    //   byte 0: YOVF XOVF YSGN XSGN  1   MBTN RBTN LBTN
    //   byte 1: X (signed,XSGN 是符号扩展)
    //   byte 2: Y (signed,YSGN 同理 —— 注意 PS/2 Y 是反的,正值朝上)
    pkt0 = 0x08 | (buttons & 0x07);
    if (dx < 0) pkt0 |= 0x10;   // XSGN
    if (dy < 0) pkt0 |= 0x20;   // YSGN
    // overflow bits 在 |dx|/|dy| > 255 时置位,但我们这里只支持 -128..127 单次
    if (dx >  127) { dx =  127; pkt0 |= 0x40; }
    if (dx < -128) { dx = -128; pkt0 |= 0x40; }
    if (dy >  127) { dy =  127; pkt0 |= 0x80; }
    if (dy < -128) { dy = -128; pkt0 |= 0x80; }
    pkt1 = (UCHAR)((SHORT)dx & 0xFF);
    pkt2 = (UCHAR)((SHORT)(-dy) & 0xFF);  // 翻转 Y 方向 — Windows 期望正值=向下,PS/2 是反的

    if (!HvInputFifoPush_Passive(&g_MouseFifo, pkt0) ||
        !HvInputFifoPush_Passive(&g_MouseFifo, pkt1) ||
        !HvInputFifoPush_Passive(&g_MouseFifo, pkt2)) {
        return STATUS_DEVICE_NOT_CONNECTED;
    }

    HvInputKickDelivery();
    return STATUS_SUCCESS;
}

// ============================================================
// VMEXIT 回调: 处理 I/O 端口访问
// ============================================================

BOOLEAN HvInputHandleIoExit(SIZE_T qualification, PGUEST_CONTEXT ctx)
{
    USHORT port;
    BOOLEAN direction;  // 0=OUT, 1=IN
    UCHAR   byte = 0;
    UCHAR   status;

    if (!ctx) return FALSE;
    // USB HID 后端没设 I/O bitmap,理论上不会进这里;但安全起见早返还透传

    // VM_EXIT_QUALIFICATION format (Vol3C 27.2.1):
    //   bits  0-2: size of access (0=byte, 1=word, 3=dword)
    //   bit   3:   direction (0=OUT, 1=IN)
    //   bit   4:   string  (INS/OUTS,我们暂不特殊处理)
    //   bit   5:   REP-prefixed
    //   bit   6:   immediate operand (0=DX, 1=immediate)
    //   bits 16-31: port number
    port      = (USHORT)((qualification >> 16) & 0xFFFF);
    direction = (BOOLEAN)((qualification >> 3) & 1);

    // 只有 0x60 / 0x64 应该在我们的 bitmap 里,但保险起见兜底
    if (direction) {
        // IN
        if (port == 0x60) {
            // 数据端口: 优先吐 mouse,其次 kbd (按 g_NextByteSource hint)
            // 实际上 i8042prt ISR 在读 0x60 前会先读 0x64 status 判断 AUX,
            // 所以这里按 g_NextByteSource 给即可
            if (g_Backend == HV_INPUT_BACKEND_PS2 &&
                g_InputInitialized && g_InputEnabled &&
                g_NextByteSource == INPUT_SOURCE_MOUSE) {
                if (HvInputFifoPop_Dpc(&g_MouseFifo, &byte)) {
                    ctx->Rax = (ctx->Rax & ~(ULONG64)0xFF) | byte;
                    // 出队后,下一字节源 = kbd (除非 mouse fifo 还有数据)
                    if (HvInputFifoIsEmpty(&g_MouseFifo)) {
                        g_NextByteSource = INPUT_SOURCE_KBD;
                    }
                    return TRUE;
                }
                // mouse fifo 空但 hint 是 mouse,fall through 到 passthrough
            }
            if (g_Backend == HV_INPUT_BACKEND_PS2 &&
                g_InputInitialized && g_InputEnabled) {
                if (HvInputFifoPop_Dpc(&g_KbdFifo, &byte)) {
                    ctx->Rax = (ctx->Rax & ~(ULONG64)0xFF) | byte;
                    return TRUE;
                }
            }
            // FIFO 空 — 直通真实硬件端口
            byte = __inbyte(0x60);
            ctx->Rax = (ctx->Rax & ~(ULONG64)0xFF) | byte;
            return TRUE;
        }
        else if (port == 0x64) {
            // 状态端口: 计算合成 status
            BOOLEAN kbdHas = (g_Backend == HV_INPUT_BACKEND_PS2 &&
                              g_InputInitialized && g_InputEnabled)
                                 ? !HvInputFifoIsEmpty(&g_KbdFifo) : FALSE;
            BOOLEAN mouseHas = (g_Backend == HV_INPUT_BACKEND_PS2 &&
                                g_InputInitialized && g_InputEnabled)
                                   ? !HvInputFifoIsEmpty(&g_MouseFifo) : FALSE;

            if (g_Backend == HV_INPUT_BACKEND_PS2 &&
                g_InputInitialized && g_InputEnabled &&
                (kbdHas || mouseHas)) {
                // 优先 mouse (i8042prt 检 AUX bit 决定哪个 ISR 接管)
                if (mouseHas) {
                    g_NextByteSource = INPUT_SOURCE_MOUSE;
                    status = KBC_STATUS_OBF | KBC_STATUS_AUX;
                } else {
                    g_NextByteSource = INPUT_SOURCE_KBD;
                    status = KBC_STATUS_OBF;
                }
                // 还要 OR 上真实硬件 status 的高位 (system flag 等),
                // 否则一些 driver 看不到 KBC ready 会卡。简化: 与真实硬件 OR
                UCHAR realStatus = __inbyte(0x64);
                status |= (realStatus & ~(KBC_STATUS_OBF | KBC_STATUS_AUX));
                ctx->Rax = (ctx->Rax & ~(ULONG64)0xFF) | status;
                return TRUE;
            }
            // 无 pending 数据 — 直通
            byte = __inbyte(0x64);
            ctx->Rax = (ctx->Rax & ~(ULONG64)0xFF) | byte;
            return TRUE;
        }
    } else {
        // OUT — 直通,我们不拦写
        if (port == 0x60) {
            __outbyte(0x60, (UCHAR)(ctx->Rax & 0xFF));
            return TRUE;
        }
        else if (port == 0x64) {
            __outbyte(0x64, (UCHAR)(ctx->Rax & 0xFF));
            return TRUE;
        }
    }

    // 不应到这里(bitmap 没设其他 port),safe fall through
    return FALSE;
}

// ============================================================
// VMEXIT 回调: 尝试投递 IRQ 注入
// ============================================================

VOID HvInputTryDeliver(VOID)
{
    ULONG cpuIndex;
    ULONG vector;
    BOOLEAN hasMouse;
    BOOLEAN hasKbd;

    if (!g_InputInitialized || !g_InputEnabled) return;
    if (g_Backend != HV_INPUT_BACKEND_PS2) return;

    // 单 CPU 抢锁,防止多核同时各注入一次相同 IRQ
    if (InterlockedCompareExchange(&g_DeliveryLock, 1, 0) != 0) {
        return;
    }

    hasMouse = !HvInputFifoIsEmpty(&g_MouseFifo);
    hasKbd   = !HvInputFifoIsEmpty(&g_KbdFifo);

    if (!hasMouse && !hasKbd) {
        goto out;
    }

    // 优先级: mouse 先 (鼠标 3 字节一组,完整性更敏感),然后 kbd
    vector = hasMouse ? g_MouseVector : g_KbdVector;

    if (HvVmExitCanInjectInterrupt()) {
        HvVmExitInjectInterrupt(vector, 0);  // type=0 external interrupt
    } else {
        // 不能注入: 队列起来等中断窗口
        cpuIndex = KeGetCurrentProcessorNumber();
        // intrInfo format 与 HvVmExit.c 一致: vector | (1<<31)
        HvVmExitEnqueuePendingIntr(cpuIndex,
            (ULONG64)vector | (1ULL << 31));
        HvVmExitEnableInterruptWindowExiting();
    }

out:
    InterlockedExchange(&g_DeliveryLock, 0);
}
