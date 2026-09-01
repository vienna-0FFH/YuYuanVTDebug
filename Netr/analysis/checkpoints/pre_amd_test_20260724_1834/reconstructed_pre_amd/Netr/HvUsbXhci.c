/*
 * HvUsbXhci.c — Layer 4: VT-透明 USB HID 注入实现
 *
 * 见 HvUsbXhci.h 顶部的设计注释。本文件实现:
 *   - PCI scan 找 xHCI 控制器
 *   - 映 BAR0、解析 Capability/Operational/Runtime/Doorbell 寄存器
 *   - 解析 DCBAA → 遍历每个 Slot 的 Device Context
 *   - 在 Endpoint Context 里找 Interrupt-IN 端点
 *   - 通过 USB descriptor 缓存(Slot Context.SpeedFlag 加上 Boot interface
 *     约定:HID Boot Keyboard 是 Subclass=1, HID Boot Mouse 是 Subclass=2)
 *     标定哪个 slot 是 kbd / mouse
 *   - 读 PCI MSI/MSI-X cap 拿 xHCI 的 IDT 向量
 *   - 注入:把 HID Boot report 写到 Transfer Ring 当前 TRB 的 Data Buffer,
 *           在 Event Ring 当前位置写 Transfer Event TRB,Inject MSI
 *
 * IRQL: Initialize 必须在 PASSIVE_LEVEL (要用 MmMapIoSpace + HalGetBusData)
 *       SendKeyboard/SendMouse 在 PASSIVE_LEVEL 调用 (从 IOCTL path)
 *
 * PG 安全注解:
 *   - 所有 MMIO 寄存器读都是 volatile read,不修改控制器状态
 *   - 我们不写 CRCR/USBCMD/USBSTS,只读 + 用真硬件留下的数据
 *   - Event Ring/Transfer Ring 是 xHCI 标准里的"共享 RAM",微软驱动随时写,
 *     这块内存不在 PG 监视范围内
 */

#include <ntddk.h>
#include <ntstrsafe.h>

#include "HvUsbXhci.h"
#include "HvVmExit.h"   // HvVmExitInjectInterrupt / HvVmExitCanInjectInterrupt
#include "HvXhciEptTrap.h"  // Item 2: EPT read trap on USBSTS/IMAN

// P122: 全 driver DbgPrint → GUI ring
#define HV_TRACE_THIS_CAT HV_TRACE_CAT_USB
#include "HvTrace.h"

// ============================================================
// HAL APIs we use (PCI 配置空间读取)
// ============================================================

// HalGetBusDataByOffset/HalSetBusDataByOffset are exposed via Hal.h
// 但项目其他文件没 include,我们手工 prototype 避免连环依赖
NTHALAPI ULONG NTAPI HalGetBusDataByOffset(
    _In_ BUS_DATA_TYPE BusDataType,
    _In_ ULONG BusNumber,
    _In_ ULONG SlotNumber,
    _Out_writes_bytes_(Length) PVOID Buffer,
    _In_ ULONG Offset,
    _In_ ULONG Length);

NTHALAPI ULONG NTAPI HalSetBusDataByOffset(
    _In_ BUS_DATA_TYPE BusDataType,
    _In_ ULONG BusNumber,
    _In_ ULONG SlotNumber,
    _In_reads_bytes_(Length) PVOID Buffer,
    _In_ ULONG Offset,
    _In_ ULONG Length);

// ============================================================
// 模块全局
// ============================================================

HV_USB_XHCI_CONTEXT g_HvUsbXhci = { 0 };

#define HV_XHCI_TAG  'cXvH'
#define HV_XHCI_MIN_BAR_MAP_BYTES  ((SIZE_T)PAGE_SIZE)
#define HV_XHCI_MAX_BAR_MAP_BYTES  ((SIZE_T)(2 * 1024 * 1024))

// ============================================================
// 调试日志辅助 (避免重复 [HV-XHCI] 前缀)
// ============================================================

#define XHCI_LOG(fmt, ...) DbgPrint("[HV-XHCI] " fmt "\n", ##__VA_ARGS__)

// ============================================================
// MMIO 安全访问 helper (volatile read/write, 防编译器重排)
// ============================================================

static __forceinline ULONG XhciMmioReadL(_In_ volatile UCHAR* base, _In_ ULONG offset)
{
    return *(volatile ULONG*)(base + offset);
}

static __forceinline ULONG64 XhciMmioReadQ(_In_ volatile UCHAR* base, _In_ ULONG offset)
{
    // 64-bit MMIO read.x86 上多数控制器允许 64-bit 单 transaction,但保险起见拆 2 个 32-bit
    ULONG lo = *(volatile ULONG*)(base + offset);
    ULONG hi = *(volatile ULONG*)(base + offset + 4);
    return ((ULONG64)hi << 32) | lo;
}

static __forceinline UCHAR XhciMmioReadB(_In_ volatile UCHAR* base, _In_ ULONG offset)
{
    return *(volatile UCHAR*)(base + offset);
}

static __forceinline USHORT XhciMmioReadW(_In_ volatile UCHAR* base, _In_ ULONG offset)
{
    return *(volatile USHORT*)(base + offset);
}

// ============================================================
// IPI kick — 强制所有 CPU VMEXIT, 让 HvUsbXhciTryDeliverMsi 在 root 模式下跑
// ============================================================
static ULONG_PTR HvXhciKickIpiCallback(_In_ ULONG_PTR ctx)
{
    UNREFERENCED_PARAMETER(ctx);
    __try {
        // CPUID 必然 VMEXIT (跟 HvInput 的 IPI 同思路)
        int cpuInfo[4];
        __cpuid(cpuInfo, 0x4853FF02);  // 自定义 leaf, dispatcher 不特殊处理
        (VOID)cpuInfo;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        // 安静吞掉 — 该 CPU 没虚拟化
    }
    return 0;
}

// ============================================================
// PCI 配置空间扫描
// ============================================================

//
// 扫所有 PCI device, 找 Class=0x0C SubClass=0x03 ProgIf=0x30 (xHCI)
// 返回第一个找到的; 多控制器机器先取 Bus 最低的
//
//
// Phase 5: 支持从指定 bus:dev.fn 之后继续枚举,允许多 xHCI 控制器系统
//   (现代 Intel 平台 USB 3.x 通常只有一个 xHCI host,但部分服务器板有两个;
//    AMD 平台亦可有 USB3 + USB3.1 分离的两个 host)
//
//   startBus/startDev/startFn = (0,0,0) 即从头扫描
//   传上一次成功返回值的下一项即可继续
//
// CF8/CFC PCI 直读 (Hal API 在某些 Win11 build 上对 DriverEntry 上下文返 0)
// safer than HalGetBusDataByOffset which depends on PCI bus driver being ready
static ULONG HvXhciPciConfigRead32(ULONG bus, ULONG dev, ULONG fn, ULONG offset)
{
    ULONG addr = 0x80000000UL
               | ((bus & 0xFF) << 16)
               | ((dev & 0x1F) << 11)
               | ((fn  & 0x07) << 8)
               | (offset & 0xFC);
    __outdword(0xCF8, addr);
    return __indword(0xCFC);
}

static VOID HvXhciPciConfigWrite32(ULONG bus, ULONG dev, ULONG fn, ULONG offset, ULONG value)
{
    ULONG addr = 0x80000000UL
               | ((bus & 0xFF) << 16)
               | ((dev & 0x1F) << 11)
               | ((fn  & 0x07) << 8)
               | (offset & 0xFC);
    __outdword(0xCF8, addr);
    __outdword(0xCFC, value);
}

// 通用 PCI config 读取:HAL 优先,失败回退到 CF8/CFC 端口 IO。
// Intel ADL/B660 等平台的 PCH 内置设备 (xHCI 在 0:14.0 / 0:20.0 等),
// HalGetBusDataByOffset 在 DriverEntry 早期会返 0 (PCI bus driver 未就绪
// 或被 HVCI/PCI Lockdown 限制)。
static ULONG HvXhciCfgRead(ULONG bus, ULONG dev, ULONG fn,
                           ULONG offset, PVOID buf, ULONG len)
{
    ULONG slot = (dev << 16) | (fn & 0xFFFF);
    ULONG got = HalGetBusDataByOffset(PCIConfiguration, bus, slot, buf, offset, len);
    if (got == len) return got;

    // HAL 失败 — 端口 IO 走 dword-aligned 累积读取
    UCHAR* dst = (UCHAR*)buf;
    ULONG remaining = len;
    ULONG cur = offset & ~3UL;
    ULONG skip = offset & 3;

    while (remaining > 0) {
        ULONG dw = HvXhciPciConfigRead32(bus, dev, fn, cur);
        ULONG avail = 4 - skip;
        ULONG copyN = (remaining < avail) ? remaining : avail;
        RtlCopyMemory(dst, (UCHAR*)&dw + skip, copyN);
        dst       += copyN;
        remaining -= copyN;
        cur       += 4;
        skip = 0;
    }
    return len;
}

// 通用 PCI config 写入。仅支持 dword 对齐 (BAR sizing dance 的写都是 dword)。
static BOOLEAN HvXhciCfgWrite(ULONG bus, ULONG dev, ULONG fn,
                              ULONG offset, PVOID buf, ULONG len)
{
    ULONG slot = (dev << 16) | (fn & 0xFFFF);
    ULONG put = HalSetBusDataByOffset(PCIConfiguration, bus, slot, buf, offset, len);
    if (put == len) return TRUE;

    if ((offset & 3) || (len & 3)) return FALSE;  // 不对齐不走端口 IO

    UCHAR* src = (UCHAR*)buf;
    for (ULONG cur = 0; cur < len; cur += 4) {
        HvXhciPciConfigWrite32(bus, dev, fn, offset + cur, *(ULONG*)(src + cur));
    }
    return TRUE;
}

static NTSTATUS HvXhciFindControllerFrom(
    _In_  ULONG startBus,
    _In_  ULONG startDev,
    _In_  ULONG startFn,
    _Out_ PULONG OutBus,
    _Out_ PULONG OutDevice,
    _Out_ PULONG OutFunction,
    _Out_ PUSHORT OutVendor,
    _Out_ PUSHORT OutDevId)
{
    ULONG bus, dev, fn;
    UCHAR cfg[16];

    // 诊断计数
    ULONG totalProbed   = 0;   // HalGet returning sizeof(cfg)
    ULONG totalValid    = 0;   // vendor != 0xFFFF/0
    ULONG totalUsbClass = 0;   // Class == 0x0C (USB)
    ULONG totalPortIoTried = 0;
    ULONG totalPortIoValid = 0;

    *OutBus = *OutDevice = *OutFunction = 0;
    *OutVendor = *OutDevId = 0;

    for (bus = startBus; bus < 256; bus++) {
        ULONG devStart = (bus == startBus) ? startDev : 0;
        for (dev = devStart; dev < 32; dev++) {
            ULONG fnStart = (bus == startBus && dev == startDev) ? startFn : 0;
            for (fn = fnStart; fn < 8; fn++) {
                ULONG slot = (dev << 16) | (fn & 0xFFFF);
                ULONG got = HalGetBusDataByOffset(PCIConfiguration, bus, slot,
                                                  cfg, 0, sizeof(cfg));
                BOOLEAN cfgValid = (got == sizeof(cfg));

                // 回退:HAL 失败就用 CF8/CFC 端口 IO 直读 (我们这里在 VMX root 之前调用)
                if (!cfgValid && bus < 16) {
                    totalPortIoTried++;
                    ULONG dw0 = HvXhciPciConfigRead32(bus, dev, fn, 0x00);
                    ULONG dw2 = HvXhciPciConfigRead32(bus, dev, fn, 0x08);
                    ULONG dw3 = HvXhciPciConfigRead32(bus, dev, fn, 0x0C);
                    *(ULONG*)&cfg[0]  = dw0;
                    *(ULONG*)&cfg[8]  = dw2;
                    *(ULONG*)&cfg[12] = dw3;
                    cfg[4] = cfg[5] = cfg[6] = cfg[7] = 0;
                    if ((dw0 & 0xFFFF) != 0xFFFF && (dw0 & 0xFFFF) != 0) {
                        cfgValid = TRUE;
                        totalPortIoValid++;
                    }
                }

                if (!cfgValid) {
                    if (fn == 0) goto next_dev;
                    continue;
                }
                totalProbed++;

                USHORT vendor = *(USHORT*)&cfg[0];
                USHORT devid  = *(USHORT*)&cfg[2];
                if (vendor == 0xFFFF || vendor == 0x0000) {
                    if (fn == 0) goto next_dev;
                    continue;
                }
                totalValid++;

                // class 在 offset 0x09..0x0B (LE: ProgIf|SubClass|Class)
                ULONG classCode = ((ULONG)cfg[11] << 16) |
                                  ((ULONG)cfg[10] << 8)  |
                                  (ULONG)cfg[9];

                // 任何 USB 相关 class 都打印,便于发现 ProgIf 不是 0x30 的旧 xHCI
                if ((classCode & 0xFFFF00) == 0x0C0300) {
                    totalUsbClass++;
                    XHCI_LOG("USB class device %u:%u.%u vendor=0x%04X dev=0x%04X class=0x%06X",
                             bus, dev, fn, vendor, devid, classCode);
                }

                if (classCode == XHCI_PCI_CLASS_CODE) {
                    *OutBus      = bus;
                    *OutDevice   = dev;
                    *OutFunction = fn;
                    *OutVendor   = vendor;
                    *OutDevId    = devid;
                    XHCI_LOG("found xHCI at PCI %u:%u.%u vendor=0x%04X dev=0x%04X "
                             "(scan stats: probed=%u valid=%u usb=%u portIO=%u/%u)",
                             bus, dev, fn, vendor, devid,
                             totalProbed, totalValid, totalUsbClass,
                             totalPortIoValid, totalPortIoTried);
                    return STATUS_SUCCESS;
                }

                // Header Type bit 7 = multi-function. 单 function device 跳后续 fn
                if (fn == 0) {
                    UCHAR headerType = cfg[14];
                    if (!(headerType & 0x80)) {
                        goto next_dev;
                    }
                }
            }
        next_dev:;
        }
    }

    XHCI_LOG("no xHCI controller found (start=%u:%u.%u) — scan stats: "
             "HAL probed=%u valid=%u usb=%u; portIO tried=%u valid=%u",
             startBus, startDev, startFn,
             totalProbed, totalValid, totalUsbClass,
             totalPortIoTried, totalPortIoValid);
    return STATUS_NOT_FOUND;
}

// 旧 API:从头开始扫,返回第一个 xHCI
static NTSTATUS HvXhciFindController(
    _Out_ PULONG OutBus,
    _Out_ PULONG OutDevice,
    _Out_ PULONG OutFunction,
    _Out_ PUSHORT OutVendor,
    _Out_ PUSHORT OutDevId)
{
    return HvXhciFindControllerFrom(0, 0, 0,
                                    OutBus, OutDevice, OutFunction,
                                    OutVendor, OutDevId);
}

//
// 读 BAR0 物理基址 + 大小
//   xHCI BAR0 通常是 64-bit MMIO (BAR0 low + BAR1 high), 16 KB 对齐
//   读 size 的标准方法是写全 1 进 BAR,读回看可写位,再写回原值
//
static NTSTATUS HvXhciReadBar0(
    _In_  ULONG bus,
    _In_  ULONG dev,
    _In_  ULONG fn,
    _Out_ PULONG64 OutPhys,
    _Out_ PSIZE_T  OutSize)
{
    ULONG bar0Lo = 0, bar0Hi = 0;
    BOOLEAN bar64;

    *OutPhys = 0;
    *OutSize = HV_XHCI_MIN_BAR_MAP_BYTES;

    if (HvXhciCfgRead(bus, dev, fn, PCI_BAR0_OFFSET, &bar0Lo, 4) != 4)
        return STATUS_DEVICE_NOT_READY;

    if ((bar0Lo & PCI_BAR_MMIO_MASK) != 0) {
        XHCI_LOG("BAR0 is I/O port, not MMIO (BAR0=0x%X)", bar0Lo);
        return STATUS_NOT_SUPPORTED;
    }

    bar64 = ((bar0Lo & PCI_BAR_TYPE_MASK) == PCI_BAR_TYPE_64BIT);

    if (bar64) {
        if (HvXhciCfgRead(bus, dev, fn, PCI_BAR0_OFFSET + 4, &bar0Hi, 4) != 4)
            return STATUS_DEVICE_NOT_READY;
    }

    // 读 BAR size: 写全 1, 读回, 写回原值
    /* BAR sizing writes are intentionally removed: the live xHCI BAR is
       owned by pci.sys/xhci.sys and must never be moved while HID DMA runs. */

    // mask 高位 flag, 取 size
    // 物理基址 = 原 BAR (mask flag)
    ULONG64 phys = ((ULONG64)(bar0Hi) << 32) | (bar0Lo & 0xFFFFFFF0);

    if (phys == 0) {
        return STATUS_DEVICE_NOT_READY;
    }

    *OutPhys = phys;
    XHCI_LOG("BAR0 phys=0x%llX initial-map=0x%llX (%s, non-destructive)",
             phys, (ULONG64)*OutSize, bar64 ? "64-bit" : "32-bit");
    return STATUS_SUCCESS;
}

//
// 在 PCI Capability 链上找 MSI 或 MSI-X, 解码 vector
//
// 读 MSI-X Table entry 0 的 MessageData,提取 IDT vector
// 前提:g_HvUsbXhci.Bar 已经 MmMapIoSpace 完
//      msixCapOff = MSI-X capability 在 PCI 配置空间的偏移
// 返回 vector (0 = 没读到)
// ============================================================
// Intel VT-d Interrupt Remapping (IR) — 在 Windows 11 ADL 上,
// xhci.sys 配置的 MSI 是 "remappable format":
//   addr.bit[3] = 1 (Format = remappable)
//   addr.bits[19:5] = Handle (15-bit IR table base index)
//   addr.bit[4] = SHV (Subhandle Valid)
//   data[15:0] = Subhandle (if SHV=1)
// IR_Index = Handle + Subhandle 时 SHV=1, 否则 = Handle
// 实际 IDT vector 在 VT-d Interrupt Remap Table[IR_Index].V (bits 39:32)
// ============================================================

#define VTD_REG_VER         0x00
#define VTD_REG_CAP         0x08
#define VTD_REG_ECAP        0x10
#define VTD_REG_GSTS        0x1C
#define VTD_REG_IRTA        0xB8

// 桌面 Intel 平台常见的 VT-d Remap Unit MMIO base
//   0xFED90000 = Graphics IOMMU (iGPU/GFX)
//   0xFED91000 = General PCH I/O IOMMU (xHCI 走这个)
//   有些平台也会用 0xFED92000 / 0xFED93000
#define VTD_MMIO_CANDIDATE_0    0xFED91000ULL
#define VTD_MMIO_CANDIDATE_1    0xFED90000ULL
#define VTD_MMIO_CANDIDATE_2    0xFED92000ULL
#define VTD_MMIO_CANDIDATE_3    0xFED93000ULL

//
// 从单个 VT-d unit 读 IRT[index].Vector
// 成功返回 vector (0 = 没读到 / 不 present / unit 不存在)
//
static UCHAR HvXhciReadIrteVector(_In_ ULONG64 vtdMmioPa, _In_ ULONG irIndex)
{
    PHYSICAL_ADDRESS pa;
    volatile UCHAR* mmio;
    ULONG ver;
    ULONG64 cap, ecap, irta;
    ULONG64 irtPa;
    ULONG irtSizeOrder, irtCount;
    SIZE_T irtBytes;
    PVOID irtVa;
    ULONG64 irteQw0, irteQw1;
    UCHAR vector = 0;

    pa.QuadPart = (LONGLONG)vtdMmioPa;
    mmio = (volatile UCHAR*)MmMapIoSpace(pa, 0x1000, MmNonCached);
    if (!mmio) {
        XHCI_LOG("VT-d: map 0x%llX failed", vtdMmioPa);
        return 0;
    }
    ver = *(volatile ULONG*)(mmio + VTD_REG_VER);
    if (ver == 0 || ver == 0xFFFFFFFF) {
        // 这个候选地址不是 VT-d unit
        MmUnmapIoSpace((PVOID)mmio, 0x1000);
        return 0;
    }
    cap  = *(volatile ULONG64*)(mmio + VTD_REG_CAP);
    ecap = *(volatile ULONG64*)(mmio + VTD_REG_ECAP);
    irta = *(volatile ULONG64*)(mmio + VTD_REG_IRTA);
    XHCI_LOG("VT-d @ 0x%llX: VER=0x%X CAP=0x%llX ECAP=0x%llX IRTA=0x%llX",
             vtdMmioPa, ver, cap, ecap, irta);
    (void)cap;

    // ECAP[3] = IR supported
    if (!(ecap & (1ULL << 3))) {
        XHCI_LOG("VT-d @ 0x%llX: IR not supported (ECAP[3]=0)", vtdMmioPa);
        MmUnmapIoSpace((PVOID)mmio, 0x1000);
        return 0;
    }

    irtPa = irta & ~0xFFFULL;
    irtSizeOrder = (ULONG)(irta & 0xF);       // S: #entries = 2^(S+1)
    irtCount = 1U << (irtSizeOrder + 1);
    irtBytes = (SIZE_T)irtCount * 16;
    if (irtPa == 0 || irtBytes == 0) {
        XHCI_LOG("VT-d @ 0x%llX: IRT not configured (irtPa=0x%llX count=%u)",
                 vtdMmioPa, irtPa, irtCount);
        MmUnmapIoSpace((PVOID)mmio, 0x1000);
        return 0;
    }
    if (irIndex >= irtCount) {
        XHCI_LOG("VT-d @ 0x%llX: irIndex %u out of range (count=%u)",
                 vtdMmioPa, irIndex, irtCount);
        MmUnmapIoSpace((PVOID)mmio, 0x1000);
        return 0;
    }

    pa.QuadPart = (LONGLONG)irtPa;
    irtVa = MmMapIoSpace(pa, irtBytes, MmCached);   // IRT 是普通 RAM,可缓存
    if (!irtVa) {
        XHCI_LOG("VT-d @ 0x%llX: IRT map failed pa=0x%llX size=0x%llX",
                 vtdMmioPa, irtPa, (ULONG64)irtBytes);
        MmUnmapIoSpace((PVOID)mmio, 0x1000);
        return 0;
    }

    irteQw0 = *(volatile ULONG64*)((UCHAR*)irtVa + irIndex * 16);
    irteQw1 = *(volatile ULONG64*)((UCHAR*)irtVa + irIndex * 16 + 8);
    // IRTE QWORD0 layout (Intel VT-d spec rev 4.0, Table 9-9):
    //   [0]    Present (P)
    //   [1]    Fault Processing Disable (FPD)
    //   [2]    Destination Mode (DM)  — 1 bit
    //   [3]    Redirection Hint (RH)
    //   [4]    Trigger Mode (TM)
    //   [7:5]  Delivery Mode (DLM)    — 3 bits
    //   [11:8] AVAIL
    //   [14:12] Reserved
    //   [15]   IRTE Mode (IM)         — 0=remapped, 1=posted
    //   [23:16] Vector (V)            ← real IDT vector
    //   [31:24] Reserved
    //   [63:32] Destination ID (DST)  — 32-bit (x2APIC if EIME=1, else low 8 bits)
    XHCI_LOG("VT-d: IRT[%u] qw0=0x%016llX qw1=0x%016llX "
             "(P=%u V=0x%02X DM=%u DLM=%u IM=%u DST=0x%X SID=0x%04X)",
             irIndex, irteQw0, irteQw1,
             (ULONG)(irteQw0 & 1),
             (UCHAR)((irteQw0 >> 16) & 0xFF),
             (ULONG)((irteQw0 >> 2) & 1),
             (ULONG)((irteQw0 >> 5) & 7),
             (ULONG)((irteQw0 >> 15) & 1),
             (ULONG)((irteQw0 >> 32) & 0xFFFFFFFF),
             (USHORT)(irteQw1 & 0xFFFF));

    if (irteQw0 & 1) {
        vector = (UCHAR)((irteQw0 >> 16) & 0xFF);
    }

    MmUnmapIoSpace(irtVa, irtBytes);
    MmUnmapIoSpace((PVOID)mmio, 0x1000);
    return vector;
}

//
// MSI Address 是否为 IR remappable 格式 (bit 3 = 1)
//
static BOOLEAN HvXhciMsiIsRemappable(_In_ ULONG addrLo)
{
    return (addrLo & 0x8) != 0;
}

//
// 解析 remappable MSI → IR_Index
//   addr[19:5] = Handle
//   addr[4]    = SHV
//   data[15:0] = Subhandle (SHV=1 时有效)
//
static ULONG HvXhciMsiToIrIndex(_In_ ULONG addrLo, _In_ USHORT data)
{
    ULONG handle = (addrLo >> 5) & 0x7FFF;
    BOOLEAN shv = (addrLo & 0x10) != 0;
    if (shv) return handle + (ULONG)(data & 0xFFFF);
    return handle;
}

//
// 顶层封装:遍历所有候选 VT-d MMIO base, 在第一个 IRTE.Present 命中的处取 vector
//
static UCHAR HvXhciResolveRemappableMsi(_In_ ULONG addrLo, _In_ USHORT data)
{
    ULONG irIndex = HvXhciMsiToIrIndex(addrLo, data);
    UCHAR vector;
    XHCI_LOG("MSI remappable: addr=0x%08X data=0x%04X -> IR_Index=%u",
             addrLo, data, irIndex);

    vector = HvXhciReadIrteVector(VTD_MMIO_CANDIDATE_0, irIndex);
    if (vector) return vector;
    vector = HvXhciReadIrteVector(VTD_MMIO_CANDIDATE_1, irIndex);
    if (vector) return vector;
    vector = HvXhciReadIrteVector(VTD_MMIO_CANDIDATE_2, irIndex);
    if (vector) return vector;
    vector = HvXhciReadIrteVector(VTD_MMIO_CANDIDATE_3, irIndex);
    return vector;
}

static UCHAR HvXhciReadMsixVector(
    _In_ ULONG bus, _In_ ULONG dev, _In_ ULONG fn,
    _In_ UCHAR msixCapOff)
{
    ULONG tableOffBir = 0;
    USHORT msgCtrl = 0;
    UCHAR  bir;
    ULONG  tableOff;
    ULONG  msgData;
    UCHAR  vector;

    if (HvXhciCfgRead(bus, dev, fn, msixCapOff + 2, &msgCtrl, 2) != 2) {
        XHCI_LOG("MSI-X: read MsgCtrl failed");
        return 0;
    }
    XHCI_LOG("MSI-X: MsgCtrl=0x%04X (enable=%d funcMask=%d size=%u)",
             msgCtrl,
             (msgCtrl & 0x8000) ? 1 : 0,
             (msgCtrl & 0x4000) ? 1 : 0,
             (msgCtrl & 0x7FF) + 1);

    if (HvXhciCfgRead(bus, dev, fn, msixCapOff + 4, &tableOffBir, 4) != 4) {
        XHCI_LOG("MSI-X: read Table Offset/BIR failed");
        return 0;
    }
    bir       = (UCHAR)(tableOffBir & 0x7);
    tableOff  = tableOffBir & ~0x7UL;
    XHCI_LOG("MSI-X: Table BIR=%u Offset=0x%X (raw=0x%08X)", bir, tableOff, tableOffBir);

    if (bir != 0) {
        // MSI-X 表在另一个 BAR — 罕见,xHCI 通常在 BAR0
        XHCI_LOG("MSI-X: Table in BAR%u (not BAR0), unsupported v1", bir);
        return 0;
    }
    if (!g_HvUsbXhci.Bar) {
        XHCI_LOG("MSI-X: BAR not yet mapped");
        return 0;
    }
    if ((SIZE_T)tableOff + 16 > g_HvUsbXhci.BarSize) {
        XHCI_LOG("MSI-X: Table offset 0x%X out of BAR size 0x%llX",
                 tableOff, (ULONG64)g_HvUsbXhci.BarSize);
        return 0;
    }

    // Table entry 0:
    //   +0x00 Address Lo, +0x04 Address Hi, +0x08 MessageData, +0x0C VectorCtrl
    msgData = XhciMmioReadL(g_HvUsbXhci.Bar, tableOff + 0x08);
    vector  = (UCHAR)(msgData & 0xFF);
    XHCI_LOG("MSI-X: Table[0] MsgData=0x%08X vector=0x%02X (VectorCtrl=0x%08X)",
             msgData, vector,
             XhciMmioReadL(g_HvUsbXhci.Bar, tableOff + 0x0C));
    return vector;
}

static NTSTATUS HvXhciFindMsiVector(
    _In_  ULONG bus,
    _In_  ULONG dev,
    _In_  ULONG fn,
    _Out_ PUCHAR OutVector,
    _Out_ PBOOLEAN OutIsX)
{
    UCHAR status, capPtr;
    ULONG iters;
    UCHAR msixCapOff = 0;       // 找到的 MSI-X capability 偏移
    UCHAR intLine = 0, intPin = 0;
    USHORT cmd = 0;
    ULONG bus0Dump[4] = {0};

    *OutVector = 0;
    *OutIsX = FALSE;

    // PCI Command 寄存器 (0x04, 16-bit): bit 10 = Interrupt Disable (INTx mask)
    //   1 → INTx 中断被禁用,设备只能走 MSI/MSI-X
    //   0 → INTx 可能开着,如果 MSI/MSI-X 没编程,这就是当前路径
    HvXhciCfgRead(bus, dev, fn, PCI_COMMAND_OFFSET, &cmd, 2);
    // Interrupt Line (0x3C) = GSI / IDT vector hint (ACPI _PRT 输出)
    // Interrupt Pin (0x3D)  = 0=none, 1=INTA, 2=INTB, 3=INTC, 4=INTD
    HvXhciCfgRead(bus, dev, fn, 0x3C, &intLine, 1);
    HvXhciCfgRead(bus, dev, fn, 0x3D, &intPin,  1);
    XHCI_LOG("MSI: cmd=0x%04X (IntxDis=%s, MEM=%u, BME=%u) intLine=0x%02X intPin=%u",
             cmd, (cmd & (1U<<10)) ? "1" : "0",
             (cmd & 0x02) ? 1 : 0, (cmd & 0x04) ? 1 : 0,
             intLine, intPin);

    // 转储 0x00-0x40 头部 + 0x40-0xFF cap 区域,便于分析整套配置
    {
        ULONG off, dw;
        for (off = 0x00; off < 0x40; off += 0x10) {
            HvXhciCfgRead(bus, dev, fn, off + 0x0, &bus0Dump[0], 4);
            HvXhciCfgRead(bus, dev, fn, off + 0x4, &bus0Dump[1], 4);
            HvXhciCfgRead(bus, dev, fn, off + 0x8, &bus0Dump[2], 4);
            HvXhciCfgRead(bus, dev, fn, off + 0xC, &bus0Dump[3], 4);
            XHCI_LOG("CFG[0x%02X]: %08X %08X %08X %08X",
                     off, bus0Dump[0], bus0Dump[1], bus0Dump[2], bus0Dump[3]);
            (void)dw;
        }
        for (off = 0x40; off < 0x100; off += 0x10) {
            HvXhciCfgRead(bus, dev, fn, off + 0x0, &bus0Dump[0], 4);
            HvXhciCfgRead(bus, dev, fn, off + 0x4, &bus0Dump[1], 4);
            HvXhciCfgRead(bus, dev, fn, off + 0x8, &bus0Dump[2], 4);
            HvXhciCfgRead(bus, dev, fn, off + 0xC, &bus0Dump[3], 4);
            XHCI_LOG("CFG[0x%02X]: %08X %08X %08X %08X",
                     off, bus0Dump[0], bus0Dump[1], bus0Dump[2], bus0Dump[3]);
        }
    }

    if (HvXhciCfgRead(bus, dev, fn, PCI_STATUS_OFFSET, &status, 1) != 1) {
        XHCI_LOG("MSI: PCI Status read failed");
        return STATUS_DEVICE_NOT_READY;
    }
    XHCI_LOG("MSI: PCI Status byte = 0x%02X (cap list bit %s)",
             status, (status & 0x10) ? "set" : "CLEAR");

    if (!(status & 0x10)) {
        return STATUS_NOT_SUPPORTED;
    }

    if (HvXhciCfgRead(bus, dev, fn, PCI_CAPABILITY_PTR_OFFSET, &capPtr, 1) != 1) {
        XHCI_LOG("MSI: cap ptr read failed");
        return STATUS_DEVICE_NOT_READY;
    }
    XHCI_LOG("MSI: cap chain head = 0x%02X (raw)", capPtr);
    capPtr &= 0xFC;

    for (iters = 0; iters < 32 && capPtr != 0; iters++) {
        UCHAR capId = 0, nextPtr = 0;
        if (HvXhciCfgRead(bus, dev, fn, capPtr,     &capId,   1) != 1) {
            XHCI_LOG("MSI: cap[%u] @ 0x%02X capId read failed", iters, capPtr);
            break;
        }
        if (HvXhciCfgRead(bus, dev, fn, capPtr + 1, &nextPtr, 1) != 1) {
            XHCI_LOG("MSI: cap[%u] @ 0x%02X nextPtr read failed", iters, capPtr);
            break;
        }
        XHCI_LOG("MSI: cap[%u] @ 0x%02X id=0x%02X next=0x%02X",
                 iters, capPtr, capId, nextPtr);

        if (capId == PCI_CAP_ID_MSIX) {
            *OutIsX = TRUE;
            msixCapOff = capPtr;
            XHCI_LOG("MSI: -> MSI-X capability found at 0x%02X", capPtr);
            // 继续走链子,但记下偏移,稍后读 MSI-X table
        } else if (capId == PCI_CAP_ID_MSI) {
            USHORT msgCtrl = 0;
            BOOLEAN is64;
            ULONG dataOff;
            USHORT msgData = 0;
            UCHAR vector;
            ULONG addrLo = 0, addrHi = 0;

            if (HvXhciCfgRead(bus, dev, fn, capPtr + 2, &msgCtrl, 2) != 2) {
                XHCI_LOG("MSI: MsgCtrl read failed");
                break;
            }
            is64 = (msgCtrl & 0x80) != 0;
            HvXhciCfgRead(bus, dev, fn, capPtr + 4, &addrLo, 4);
            if (is64) HvXhciCfgRead(bus, dev, fn, capPtr + 8, &addrHi, 4);
            dataOff = is64 ? (capPtr + 0x0C) : (capPtr + 0x08);
            if (HvXhciCfgRead(bus, dev, fn, dataOff, &msgData, 2) != 2) {
                XHCI_LOG("MSI: MsgData read failed");
                break;
            }
            vector = (UCHAR)(msgData & 0xFF);
            // MsgCtrl bits: [0]=Enable [3:1]=MMC [6:4]=MME [7]=64-bit [8]=PVM
            XHCI_LOG("MSI: legacy at 0x%02X ctrl=0x%04X (EN=%u MMC=%u MME=%u 64=%u PVM=%u) "
                     "addr=%08X:%08X data=0x%04X vector=0x%02X",
                     capPtr, msgCtrl,
                     (msgCtrl & 0x01) ? 1 : 0,
                     1U << ((msgCtrl >> 1) & 0x7),
                     1U << ((msgCtrl >> 4) & 0x7),
                     (msgCtrl & 0x80) ? 1 : 0,
                     (msgCtrl & 0x100) ? 1 : 0,
                     addrHi, addrLo, msgData, vector);
            if (vector != 0) {
                *OutVector = vector;
                *OutIsX = FALSE;
                return STATUS_SUCCESS;
            }
            // 标准 MSI 字段没 vector,但 addr 是 IR remappable 格式
            // (Win11 + VT-d 默认走这条路):去查 VT-d IRT
            if ((msgCtrl & 0x01) && HvXhciMsiIsRemappable(addrLo)) {
                UCHAR irV = HvXhciResolveRemappableMsi(addrLo, msgData);
                if (irV != 0) {
                    *OutVector = irV;
                    *OutIsX = FALSE;
                    XHCI_LOG("MSI: -> resolved via VT-d IR vector=0x%02X", irV);
                    return STATUS_SUCCESS;
                }
                XHCI_LOG("MSI: remappable but IR resolve failed");
            }
        }

        capPtr = nextPtr & 0xFC;
    }

    XHCI_LOG("MSI: cap walk ended iters=%u (final capPtr=0x%02X) msixFound=%u",
             iters, capPtr, *OutIsX ? 1 : 0);

    // 走完链子,如果发现 MSI-X,去读 table
    if (*OutIsX && msixCapOff != 0) {
        UCHAR vec = HvXhciReadMsixVector(bus, dev, fn, msixCapOff);
        if (vec != 0) {
            *OutVector = vec;
            return STATUS_SUCCESS;
        }
        // MSI-X 找到了但 table[0] 的 vector 还是 0:可能 xhci.sys
        // 尚未编程 entry 0 (driver 启动顺序),也可能 Mask 中。
        // 返回 SUCCESS + isX=TRUE + vector=0,让上层决定如何处理
        return STATUS_SUCCESS;
    }
    return STATUS_NOT_FOUND;
}

// ============================================================
// MMIO 映射 (4 KB 对齐到 page,长度按真实 BAR size)
// ============================================================

static NTSTATUS HvXhciMapBar(VOID)
{
    PHYSICAL_ADDRESS pa;
    pa.QuadPart = (LONGLONG)g_HvUsbXhci.BarPhys;

    // BAR size 通常 64 KB (Intel) 或更大 (AMD)。要 unCached 映射,
    // MmNonCached 即可 (xHCI BAR 不是 prefetchable)
    g_HvUsbXhci.Bar = (volatile UCHAR*)
        MmMapIoSpace(pa, g_HvUsbXhci.BarSize, MmNonCached);
    if (!g_HvUsbXhci.Bar) {
        XHCI_LOG("MmMapIoSpace failed (phys=0x%llX size=0x%llX)",
                 g_HvUsbXhci.BarPhys, (ULONG64)g_HvUsbXhci.BarSize);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    XHCI_LOG("BAR mapped to %p", g_HvUsbXhci.Bar);
    return STATUS_SUCCESS;
}

static NTSTATUS HvXhciComputeRegisterSpan(
    _In_ ULONG dbOff,
    _In_ ULONG rtsOff,
    _In_ ULONG maxSlots,
    _In_ ULONG maxIntrs,
    _Out_ PSIZE_T outSize)
{
    ULONG64 doorbellEnd;
    ULONG64 runtimeEnd;
    ULONG64 required;

    if (!outSize || maxSlots == 0 || maxSlots > 255 ||
        maxIntrs == 0 || maxIntrs > 2048 ||
        dbOff < 0x20 || rtsOff < 0x20 ||
        (dbOff & 0x3) != 0 || (rtsOff & 0x1F) != 0) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    doorbellEnd = (ULONG64)dbOff + ((ULONG64)maxSlots + 1ULL) * sizeof(ULONG);
    runtimeEnd = (ULONG64)rtsOff + ((ULONG64)maxIntrs * 0x20ULL);
    required = max(0x1000ULL, max(doorbellEnd, runtimeEnd));
    if (required > HV_XHCI_MAX_BAR_MAP_BYTES) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    *outSize = (SIZE_T)((required + PAGE_SIZE - 1ULL) & ~(PAGE_SIZE - 1ULL));
    return STATUS_SUCCESS;
}

// ============================================================
// 解析 Capability 寄存器, 设置子块基址
// ============================================================

static NTSTATUS HvXhciParseCapability(VOID)
{
    UCHAR  capLen;
    USHORT hciVer;
    ULONG  hcsp1, hccp1;
    ULONG  dbOff, rtsOff;
    SIZE_T requiredBarSize;

    if (!g_HvUsbXhci.Bar) return STATUS_INVALID_DEVICE_STATE;

    capLen = XhciMmioReadB(g_HvUsbXhci.Bar, XHCI_CAP_CAPLENGTH);
    hciVer = XhciMmioReadW(g_HvUsbXhci.Bar, XHCI_CAP_HCIVERSION);
    hcsp1  = XhciMmioReadL(g_HvUsbXhci.Bar, XHCI_CAP_HCSPARAMS1);
    hccp1  = XhciMmioReadL(g_HvUsbXhci.Bar, XHCI_CAP_HCCPARAMS1);
    dbOff  = XhciMmioReadL(g_HvUsbXhci.Bar, XHCI_CAP_DBOFF)  & ~0x3UL;
    rtsOff = XhciMmioReadL(g_HvUsbXhci.Bar, XHCI_CAP_RTSOFF) & ~0x1FUL;

    if (capLen < 0x20 || capLen > 0x80 || hciVer == 0 ||
        !NT_SUCCESS(HvXhciComputeRegisterSpan(
            dbOff, rtsOff, hcsp1 & 0xFF, (hcsp1 >> 8) & 0x7FF,
            &requiredBarSize))) {
        XHCI_LOG("invalid capability layout: cap=0x%X ver=0x%X hcsp1=0x%X db=0x%X rts=0x%X",
                 capLen, hciVer, hcsp1, dbOff, rtsOff);
        return STATUS_INVALID_DEVICE_STATE;
    }

    if (requiredBarSize > g_HvUsbXhci.BarSize) {
        SIZE_T oldSize = g_HvUsbXhci.BarSize;
        if (g_HvUsbXhci.Bar) {
            MmUnmapIoSpace((PVOID)g_HvUsbXhci.Bar, oldSize);
            g_HvUsbXhci.Bar = NULL;
        }
        g_HvUsbXhci.BarSize = requiredBarSize;
        if (!NT_SUCCESS(HvXhciMapBar())) {
            g_HvUsbXhci.BarSize = oldSize;
            return STATUS_INSUFFICIENT_RESOURCES;
        }
    }

    g_HvUsbXhci.CapLength = capLen;
    g_HvUsbXhci.HciVersion = hciVer;
    g_HvUsbXhci.MaxSlots   = (UCHAR)(hcsp1 & 0xFF);
    g_HvUsbXhci.MaxIntrs   = (USHORT)((hcsp1 >> 8) & 0x7FF);
    g_HvUsbXhci.MaxPorts   = (UCHAR)((hcsp1 >> 24) & 0xFF);
    g_HvUsbXhci.ContextSize64 = (hccp1 & XHCI_HCC_CSZ) != 0;

    g_HvUsbXhci.CapBase = g_HvUsbXhci.Bar;
    g_HvUsbXhci.OpBase  = g_HvUsbXhci.Bar + capLen;
    g_HvUsbXhci.RtBase  = g_HvUsbXhci.Bar + rtsOff;
    g_HvUsbXhci.DbBase  = g_HvUsbXhci.Bar + dbOff;

    XHCI_LOG("CapLen=%u Ver=0x%04X MaxSlots=%u MaxIntrs=%u MaxPorts=%u CSZ=%u",
             capLen, hciVer, g_HvUsbXhci.MaxSlots, g_HvUsbXhci.MaxIntrs,
             g_HvUsbXhci.MaxPorts, g_HvUsbXhci.ContextSize64);
    XHCI_LOG("OpBase=+0x%X RtsOff=0x%X DbOff=0x%X", capLen, rtsOff, dbOff);

    if (g_HvUsbXhci.MaxSlots == 0 || g_HvUsbXhci.MaxIntrs == 0) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    return STATUS_SUCCESS;
}

// ============================================================
// 解析 Operational 寄存器 (主要是 DCBAA)
// ============================================================

static NTSTATUS HvXhciParseOperational(VOID)
{
    ULONG usbCmd, usbSts;
    ULONG64 dcbaap;

    if (!g_HvUsbXhci.OpBase) return STATUS_INVALID_DEVICE_STATE;

    usbCmd = XhciMmioReadL(g_HvUsbXhci.OpBase, XHCI_OP_USBCMD);
    usbSts = XhciMmioReadL(g_HvUsbXhci.OpBase, XHCI_OP_USBSTS);

    if (usbSts & XHCI_STS_HCH) {
        XHCI_LOG("USBSTS shows Halted (0x%X); xhci.sys not yet started?", usbSts);
        // 不立刻失败:某些时机 USBSTS 暂时 HCH=1
    }
    if (usbSts & XHCI_STS_CNR) {
        XHCI_LOG("USBSTS shows Controller Not Ready (0x%X)", usbSts);
        return STATUS_DEVICE_NOT_READY;
    }

    dcbaap = XhciMmioReadQ(g_HvUsbXhci.OpBase, XHCI_OP_DCBAAP_LO);
    dcbaap &= ~0x3FULL;     // low 6 bits reserved

    if (dcbaap == 0) {
        XHCI_LOG("DCBAAP == 0, controller not configured");
        return STATUS_DEVICE_NOT_READY;
    }

    g_HvUsbXhci.DcbaaPhys = dcbaap;
    XHCI_LOG("USBCMD=0x%X USBSTS=0x%X DCBAAP=0x%llX",
             usbCmd, usbSts, dcbaap);
    return STATUS_SUCCESS;
}

// ============================================================
// DCBAA 映射 + 走每个 Slot 的 Device Context
// ============================================================

//
// 临时映射一段物理内存 (DCBAA / Device Context 都不大,4 KB 内)
// 调用方负责 unmap (HvXhciUnmapPhys)
//
static PVOID HvXhciMapPhys(_In_ ULONG64 phys, _In_ SIZE_T size)
{
    PHYSICAL_ADDRESS pa;
    pa.QuadPart = (LONGLONG)phys;
    return MmMapIoSpace(pa, size, MmCached);
}

static VOID HvXhciUnmapPhys(_In_opt_ PVOID va, _In_ SIZE_T size)
{
    if (va) MmUnmapIoSpace(va, size);
}

//
// 解析 Endpoint Context (DCI = 1..31)
// 返回 TRUE 如果是 Interrupt-IN 端点
//
static BOOLEAN HvXhciParseEpContext(
    _In_  PXHCI_ENDPOINT_CONTEXT epCtx,
    _Out_ PULONG64 OutTrPhys,
    _Out_ PUCHAR   OutTrCycle,
    _Out_ PUCHAR   OutMaxPacket)
{
    ULONG f1 = epCtx->Field1;
    ULONG f2 = epCtx->Field2;
    ULONG64 trd = epCtx->TRDequePtr;

    ULONG epState = f1 & XHCI_EP_STATE_MASK;
    ULONG epType  = (f2 >> XHCI_EP_TYPE_SHIFT) & XHCI_EP_TYPE_MASK;
    ULONG maxPkt  = (f2 >> XHCI_EP_MAX_PACKET_SHIFT) & 0xFFFF;

    *OutTrPhys = trd & ~0xFULL;
    *OutTrCycle = (UCHAR)(trd & 0x1);
    *OutMaxPacket = (UCHAR)(maxPkt > 255 ? 255 : maxPkt);

    if (epState == XHCI_EP_STATE_DISABLED) return FALSE;
    if (epType  != XHCI_EP_TYPE_INTERRUPT_IN) return FALSE;
    return TRUE;
}

//
// 解析 Slot Context, 判断 Speed/State 是否可用
//
static BOOLEAN HvXhciSlotIsActive(_In_ PXHCI_SLOT_CONTEXT slot)
{
    ULONG f4 = slot->Field4;
    ULONG slotState = (f4 >> 27) & 0x1F;
    ULONG addr = f4 & 0xFF;
    // 0=Disabled/Enabled, 1=Default, 2=Addressed, 3=Configured
    // 我们要 Addressed (2) 或 Configured (3),并且 Device Address != 0
    if (slotState < 2) return FALSE;
    if (addr == 0) return FALSE;
    return TRUE;
}

//
// 走 Device Context 的所有 endpoint,记下找到的 Interrupt-IN 端点。
// 注: 我们没法从 Device Context 自身判断 USB Class/Subclass (那是 USB descriptor
//      里的字段,xHCI 不存)。所以我们用启发式:
//         a) 只看 Interval(<= 8ms 优先) 和 MaxPacketSize:
//            keyboard boot report = 8 byte (MaxPacket >= 8)
//            mouse boot report    = 3-4 byte (MaxPacket >= 4)
//         b) 用 MaxPacketSize 区分 kbd (>= 8) vs mouse (4..8)
//         c) 如果 keyboard 和 mouse MaxPacketSize 撞了,按 Slot ID 顺序兜底:
//            第一个找到的 boot 设备视作键盘,第二个视作鼠标
//      这种启发式对 USB HID Boot 协议设备 (>= 95% 笔记本) 准确。
//      Composite USB-C dock / dongle 上挂多个 HID 可能错认,后续 Phase 5 补救。
//
static VOID HvXhciScanSlotForHid(
    _In_ UCHAR slotId,
    _In_ PUCHAR ctxBytes,
    _In_ ULONG  ctxSize)
{
    ULONG slotStride = g_HvUsbXhci.ContextSize64 ? 64 : 32;
    PXHCI_SLOT_CONTEXT slotCtx = (PXHCI_SLOT_CONTEXT)ctxBytes;

    if (!HvXhciSlotIsActive(slotCtx)) return;

    ULONG ctxEntries = (slotCtx->Field1 >> XHCI_SLOT_CTX_ENTRIES_SHIFT)
                       & XHCI_SLOT_CTX_ENTRIES_MASK;
    if (ctxEntries == 0) return;       // 还没 ConfigureEndpoint
    if (ctxEntries > 31) ctxEntries = 31;

    ULONG speed = (slotCtx->Field1 >> XHCI_SLOT_SPEED_SHIFT) & XHCI_SLOT_SPEED_MASK;
    // 注:不再用 speed 做分类硬约束(放宽到任何 USB speed 的 HID Interrupt-IN);
    // speed 仅供日志诊断。

    // 遍历 DCI = 1..ctxEntries (DCI=0 是 Slot Context,DCI=1 是 EP0 Control)
    for (ULONG dci = 1; dci <= ctxEntries; dci++) {
        if (dci * slotStride + slotStride > ctxSize) break;
        PXHCI_ENDPOINT_CONTEXT epCtx =
            (PXHCI_ENDPOINT_CONTEXT)(ctxBytes + dci * slotStride);

        ULONG64 trPhys = 0;
        UCHAR   trCycle = 0;
        UCHAR   maxPkt = 0;
        if (!HvXhciParseEpContext(epCtx, &trPhys, &trCycle, &maxPkt)) continue;
        if (trPhys == 0) continue;

        // DCI 是奇数 = IN (我们已经在 ParseEpContext 里筛过 INTERRUPT_IN)
        // DCI 偶数 = OUT,不可能进这里。但保险起见判断
        if ((dci & 1) == 0) continue;

        // 装入设备表
        if (g_HvUsbXhci.DeviceCount >= HV_USB_HID_MAX_DEVICES) return;
        PHV_USB_HID_DEVICE d = &g_HvUsbXhci.Devices[g_HvUsbXhci.DeviceCount];
        d->Valid             = 1;
        d->SlotId            = slotId;
        d->EndpointId        = (UCHAR)dci;
        d->MaxPacketSize     = maxPkt;
        d->TransferRingPhys  = trPhys;
        d->TransferRingCycle = trCycle;

        // Phase 7: 初始化 per-device 锁 + 预映射 TR 起始页 (PASSIVE_LEVEL,
        // 调用方 HvXhciScanAllSlots 是从 HvUsbXhciInitialize 进来的)。
        // 预映射失败不致命:WriteHidReportToTr 的 scan loop 会回退到 fallback
        // MmMapIoSpace,只是慢一些。但因为现在不再在 spinlock 下做 map,所以
        // 合法 (PASSIVE/APC level via FAST_MUTEX)。
        ExInitializeFastMutex(&d->TrMutex);
        d->TransferRingMappedVa        = NULL;
        d->TransferRingMappedPagePhys  = 0;
        d->DataBufferMappedVa          = NULL;
        d->DataBufferMappedPagePhys    = 0;
        {
            ULONG64 trPagePhys = trPhys & ~(PAGE_SIZE - 1ULL);
            PVOID trPageVa = HvXhciMapPhys(trPagePhys, PAGE_SIZE);
            if (trPageVa) {
                d->TransferRingMappedVa       = trPageVa;
                d->TransferRingMappedPagePhys = trPagePhys;
            } else {
                XHCI_LOG("slot=%u DCI=%u: pre-map TR page 0x%llX failed, will fall back to per-write map",
                         slotId, dci, trPagePhys);
            }
        }

        // 启发式分类 (放宽以匹配 Report-protocol HID 设备):
        //   - 不再要求 bootSpeed:现代 USB 2.0+/USB 3.0 HID 设备常以 HIGH/SUPER 上报
        //   - 不再要求 kbd 先于 mouse:DCI 顺序由 USB 描述符决定,不一定是 kbd 在前
        //   - mouse maxPkt 放宽到 [3, 16]:Report-protocol 鼠标多按键 + wheel 常 5-8 byte,
        //     带 12-bit dx/dy + 多键的现代鼠标可到 16 byte
        //   - kbd maxPkt 保留 >= 8 (Boot kbd 是 8 byte, Report kbd 不会更短)
        if (g_HvUsbXhci.Keyboard == NULL && maxPkt >= 8) {
            d->Subclass = 1;
            g_HvUsbXhci.Keyboard = d;
        } else if (g_HvUsbXhci.Mouse == NULL && maxPkt >= 3 && maxPkt <= 16) {
            d->Subclass = 2;
            g_HvUsbXhci.Mouse = d;
        } else {
            d->Subclass = 0;     // unknown HID
        }
        g_HvUsbXhci.DeviceCount++;

        XHCI_LOG("slot=%u DCI=%u TR=0x%llX cycle=%u MaxPkt=%u speed=%u subclass=%u",
                 slotId, dci, trPhys, trCycle, maxPkt, speed, d->Subclass);
    }
}

static NTSTATUS HvXhciScanAllSlots(VOID)
{
    NTSTATUS status;
    PVOID dcbaaVa;
    ULONG dcbaaBytes;
    PULONG64 dcbaa;
    ULONG ctxBytes;
    PUCHAR ctxBuf = NULL;

    dcbaaBytes = ((ULONG)g_HvUsbXhci.MaxSlots + 1) * 8;     // entry 0 + N slots
    if (dcbaaBytes < PAGE_SIZE) dcbaaBytes = PAGE_SIZE;     // 至少映 1 页

    dcbaaVa = HvXhciMapPhys(g_HvUsbXhci.DcbaaPhys, dcbaaBytes);
    if (!dcbaaVa) {
        XHCI_LOG("MmMapIoSpace(DCBAA) failed");
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    g_HvUsbXhci.DcbaaMapped = (PULONG64)dcbaaVa;
    dcbaa = (PULONG64)dcbaaVa;

    ctxBytes = (g_HvUsbXhci.ContextSize64 ? 64 : 32) * 32;  // Slot+31EP, 2K 或 1K
    ctxBuf = (PUCHAR)ExAllocatePoolUninitialized(NonPagedPool, ctxBytes, HV_XHCI_TAG);
    if (!ctxBuf) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto done;
    }

    for (UCHAR slotId = 1; slotId <= g_HvUsbXhci.MaxSlots; slotId++) {
        ULONG64 devCtxPhys = dcbaa[slotId];
        if (devCtxPhys == 0) continue;
        devCtxPhys &= ~0x3FULL;

        PVOID devCtxVa = HvXhciMapPhys(devCtxPhys, ctxBytes);
        if (!devCtxVa) continue;

        // copy out 一份, 避免在 unmap 后引用
        RtlCopyMemory(ctxBuf, devCtxVa, ctxBytes);
        HvXhciUnmapPhys(devCtxVa, ctxBytes);

        // 记录 Device Context 物理地址 (Phase 2 注入时用)
        ULONG savedCount = g_HvUsbXhci.DeviceCount;
        HvXhciScanSlotForHid(slotId, ctxBuf, ctxBytes);
        for (ULONG i = savedCount; i < g_HvUsbXhci.DeviceCount; i++) {
            g_HvUsbXhci.Devices[i].DeviceContextPhys = devCtxPhys;
        }
    }

    status = STATUS_SUCCESS;

done:
    if (ctxBuf) ExFreePoolWithTag(ctxBuf, HV_XHCI_TAG);
    HvXhciUnmapPhys(dcbaaVa, dcbaaBytes);
    g_HvUsbXhci.DcbaaMapped = NULL;

    if (g_HvUsbXhci.Keyboard == NULL && g_HvUsbXhci.Mouse == NULL) {
        XHCI_LOG("no HID Interrupt-IN endpoint found among %u slots",
                 g_HvUsbXhci.MaxSlots);
        return STATUS_NOT_FOUND;
    }
    XHCI_LOG("HID discovery done: %u devices, kbd=%s mouse=%s",
             g_HvUsbXhci.DeviceCount,
             g_HvUsbXhci.Keyboard ? "yes" : "no",
             g_HvUsbXhci.Mouse    ? "yes" : "no");
    return status;
}

// ============================================================
// Event Ring 发现 (interrupter 0)
// ============================================================

static NTSTATUS HvXhciDiscoverEventRing(VOID)
{
    volatile UCHAR* ir0 = g_HvUsbXhci.RtBase + XHCI_RT_IR0;

    ULONG erstSize = XhciMmioReadL(ir0, XHCI_IR_ERSTSZ) & 0xFFFF;
    ULONG64 erstba = XhciMmioReadQ(ir0, XHCI_IR_ERSTBA_LO) & ~0x3FULL;
    ULONG64 erdp   = XhciMmioReadQ(ir0, XHCI_IR_ERDP_LO);

    if (erstSize == 0 || erstba == 0) {
        XHCI_LOG("Event Ring not configured (ERSTSZ=%u ERSTBA=0x%llX)",
                 erstSize, erstba);
        return STATUS_DEVICE_NOT_READY;
    }

    g_HvUsbXhci.ErstSize = (USHORT)erstSize;
    g_HvUsbXhci.ErstPhys = erstba;
    g_HvUsbXhci.ErdpPhys = erdp & ~0xFULL;

    // 读 ERST[0] 拿到第一个 Event Ring Segment 的物理基址 + size
    PVOID erstVa = HvXhciMapPhys(erstba, sizeof(XHCI_ERST_ENTRY) * erstSize);
    if (!erstVa) {
        XHCI_LOG("MmMapIoSpace(ERST) failed");
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    PXHCI_ERST_ENTRY ent0 = (PXHCI_ERST_ENTRY)erstVa;
    ULONG64 segPhys = ent0->RingSegmentBase & ~0x3FULL;
    ULONG   segSize = ent0->RingSegmentSize & 0xFFFF;
    HvXhciUnmapPhys(erstVa, sizeof(XHCI_ERST_ENTRY) * erstSize);

    if (segPhys == 0 || segSize < 16) {
        XHCI_LOG("ERST[0] invalid (seg=0x%llX size=%u)", segPhys, segSize);
        return STATUS_DEVICE_NOT_READY;
    }

    g_HvUsbXhci.EventRingSegPhys = segPhys;
    g_HvUsbXhci.EventRingSegSize = segSize;
    g_HvUsbXhci.EventRingCycle   = 1;       // 初始 CCS = 1 per spec

    // Phase 4: 持久映射整段 Event Ring,避免每次写都 MmMapIoSpace,
    // 并允许写入前 scan-ahead 找真正的 producer 空槽
    SIZE_T segBytes = (SIZE_T)segSize * sizeof(XHCI_TRB);
    g_HvUsbXhci.EventRingSegMappedVa    = HvXhciMapPhys(segPhys, segBytes);
    g_HvUsbXhci.EventRingSegMappedBytes = g_HvUsbXhci.EventRingSegMappedVa ? segBytes : 0;
    if (!g_HvUsbXhci.EventRingSegMappedVa) {
        XHCI_LOG("MmMapIoSpace(EventRingSeg) failed, bytes=%llu — will use per-write map fallback",
                 (ULONG64)segBytes);
    }

    // 用 ERDP 推算当前 producer index 的近似值。控制器还没产生 event 时,
    // ERDP 指向段基址,Producer == Consumer == 0。我们注入时 Producer 跟着 +1
    if (g_HvUsbXhci.ErdpPhys >= segPhys &&
        g_HvUsbXhci.ErdpPhys < segPhys + segSize * sizeof(XHCI_TRB)) {
        g_HvUsbXhci.EventRingProdIdx =
            (ULONG)((g_HvUsbXhci.ErdpPhys - segPhys) / sizeof(XHCI_TRB));
    } else {
        g_HvUsbXhci.EventRingProdIdx = 0;
    }

    XHCI_LOG("EventRing seg=0x%llX size=%u ERDP=0x%llX prodIdx=%u mappedVa=%p",
             segPhys, segSize, g_HvUsbXhci.ErdpPhys, g_HvUsbXhci.EventRingProdIdx,
             g_HvUsbXhci.EventRingSegMappedVa);
    return STATUS_SUCCESS;
}

// ============================================================
// 初始化主流程
// ============================================================

NTSTATUS HvUsbXhciInitialize(VOID)
{
    NTSTATUS status;
    ULONG nextBus = 0, nextDev = 0, nextFn = 0;
    ULONG controllersTried = 0;
    ULONG controllersWithBar = 0;
    NTSTATUS lastError = STATUS_NOT_FOUND;

    RtlZeroMemory(&g_HvUsbXhci, sizeof(g_HvUsbXhci));
    KeInitializeSpinLock(&g_HvUsbXhci.Lock);
    ExInitializeRundownProtection(&g_HvUsbXhci.OperationRundown);
    InterlockedExchange(&g_HvUsbXhci.OperationRundownInitialized, TRUE);
    InterlockedExchange(&g_HvUsbXhci.ShutdownStarted, FALSE);
    InterlockedExchange(&g_HvUsbXhci.State, HvUsbXhciState_Discovering);

    // Phase 5: 多控制器循环 — 第一个 xHCI 可能没有 HID 设备 (例如只挂 U 盘),
    //          继续找下一个。Intel 平台部分老板有两个 xHCI host (USB3 + USB3.1)。
    for (;;) {
        ULONG curBus, curDev, curFn;
        USHORT curVendor, curDevId;

        status = HvXhciFindControllerFrom(nextBus, nextDev, nextFn,
                                          &curBus, &curDev, &curFn,
                                          &curVendor, &curDevId);
        if (!NT_SUCCESS(status)) {
            // 没有更多 xHCI 了
            status = (controllersTried == 0) ? STATUS_NOT_FOUND : lastError;
            goto failed;
        }

        controllersTried++;
        g_HvUsbXhci.PciBus       = curBus;
        g_HvUsbXhci.PciDevice    = curDev;
        g_HvUsbXhci.PciFunction  = curFn;
        g_HvUsbXhci.PciVendorId  = curVendor;
        g_HvUsbXhci.PciDeviceId  = curDevId;

        // 推进枚举游标到下一个 PCI function 位置 (失败时返回头继续找)
        nextBus = curBus;
        nextDev = curDev;
        nextFn  = curFn + 1;
        if (nextFn >= 8) { nextFn = 0; nextDev++; }
        if (nextDev >= 32) { nextDev = 0; nextBus++; }

        // 尝试用这个控制器完整初始化;失败就 cleanup 并继续下一个
        status = HvXhciReadBar0(curBus, curDev, curFn,
                                &g_HvUsbXhci.BarPhys, &g_HvUsbXhci.BarSize);
        if (!NT_SUCCESS(status)) {
            XHCI_LOG("controller %u:%u.%u BAR0 read failed 0x%X — trying next",
                     curBus, curDev, curFn, status);
            lastError = status;
            continue;
        }

        if (g_HvUsbXhci.BarSize < 0x1000) {
            XHCI_LOG("controller %u:%u.%u BAR too small 0x%llX — trying next",
                     curBus, curDev, curFn, (ULONG64)g_HvUsbXhci.BarSize);
            lastError = STATUS_INVALID_DEVICE_STATE;
            continue;
        }

        status = HvXhciMapBar();
        if (!NT_SUCCESS(status)) {
            lastError = status;
            continue;
        }
        controllersWithBar++;

        status = HvXhciParseCapability();
        if (!NT_SUCCESS(status)) goto controller_unmap;

        status = HvXhciParseOperational();
        if (!NT_SUCCESS(status)) goto controller_unmap;

        // MSI vector — non-fatal here (没 MSI 也能写 Event Ring,只是 ISR 不会跑)
        // 但 Layer 4 没有 MSI 路径就废了,所以 MsiVector==0 时也算"这个控制器不可用"
        HvXhciFindMsiVector(curBus, curDev, curFn,
                            &g_HvUsbXhci.MsiVector, &g_HvUsbXhci.MsiIsX);

        status = HvXhciScanAllSlots();
        if (!NT_SUCCESS(status)) goto controller_unmap;

        // 没有 HID 设备 → 这个控制器对 Layer 4 无用,继续找下一个
        if (g_HvUsbXhci.Keyboard == NULL && g_HvUsbXhci.Mouse == NULL) {
            XHCI_LOG("controller %u:%u.%u has no HID device — trying next",
                     curBus, curDev, curFn);
            lastError = STATUS_NOT_FOUND;
            goto controller_unmap;
        }

        status = HvXhciDiscoverEventRing();
        if (!NT_SUCCESS(status)) goto controller_unmap;

        // 成功!
        InterlockedExchange(&g_HvUsbXhci.State, HvUsbXhciState_Ready);
        XHCI_LOG("READY @ %u:%u.%u vendor=0x%04X dev=0x%04X tried=%u/%u kbd=%s mouse=%s "
                 "msi=0x%02X(%s) eventRing=0x%llX/%u",
                 curBus, curDev, curFn, curVendor, curDevId,
                 controllersTried, controllersWithBar,
                 g_HvUsbXhci.Keyboard ? "yes" : "no",
                 g_HvUsbXhci.Mouse    ? "yes" : "no",
                 g_HvUsbXhci.MsiVector,
                 g_HvUsbXhci.MsiIsX ? "MSI-X" : "MSI",
                 g_HvUsbXhci.EventRingSegPhys,
                 g_HvUsbXhci.EventRingSegSize);

        // Item 2 trap (EPT read trap on USBSTS/IMAN) 的初始化必须延迟到
        // g_HypervisorContext.IsActive = TRUE 之后,在 HvCoreInitialize 末尾
        // 调用 — HvXhciTrapEnsureSplitPt 需要遍历 VCPU 的 EptTables。
        return STATUS_SUCCESS;

controller_unmap:
        // 清掉本控制器留下的 state,继续找下一个
        if (g_HvUsbXhci.Bar) {
            MmUnmapIoSpace((PVOID)g_HvUsbXhci.Bar, g_HvUsbXhci.BarSize);
            g_HvUsbXhci.Bar = NULL;
        }
        // Phase 7: 释放 HvXhciScanSlotForHid 已经预映射的 TR 起始页
        // (本次控制器失败,这些设备表项不会被使用)
        for (ULONG i = 0; i < HV_USB_HID_MAX_DEVICES; i++) {
            PHV_USB_HID_DEVICE d = &g_HvUsbXhci.Devices[i];
            if (d->TransferRingMappedVa) {
                HvXhciUnmapPhys(d->TransferRingMappedVa, PAGE_SIZE);
                d->TransferRingMappedVa       = NULL;
                d->TransferRingMappedPagePhys = 0;
            }
            // 此时 inject 还没跑过,DataBufferMappedVa 一定是 NULL,不用清。
        }
        RtlZeroMemory(g_HvUsbXhci.Devices, sizeof(g_HvUsbXhci.Devices));
        g_HvUsbXhci.DeviceCount = 0;
        g_HvUsbXhci.Keyboard = NULL;
        g_HvUsbXhci.Mouse    = NULL;
        g_HvUsbXhci.MsiVector = 0;
        // 注意:EventRingSegMappedVa 不会在这里被设(只在成功路径里),无须清
        continue;
    }

failed:
    XHCI_LOG("init failed: tried %u controllers (%u with BAR), final status=0x%X",
             controllersTried, controllersWithBar, status);
    InterlockedExchange(&g_HvUsbXhci.State, HvUsbXhciState_Failed);
    return status;
}

VOID HvUsbXhciBeginShutdown(VOID)
{
    InterlockedExchange(&g_HvUsbXhci.State, HvUsbXhciState_NotInit);

    if (InterlockedExchange(&g_HvUsbXhci.ShutdownStarted, TRUE) == FALSE &&
        InterlockedCompareExchange(&g_HvUsbXhci.OperationRundownInitialized, 0, 0) != 0) {
        ExWaitForRundownProtectionRelease(&g_HvUsbXhci.OperationRundown);
    }
}

VOID HvUsbXhciShutdown(VOID)
{
    // 标 NotInit 在前 — Inject/Deliver 路径会查 IsReady 提前 bail
    HvUsbXhciBeginShutdown();

    // Item 2: 关 EPT trap (恢复 R=1,清状态)。注意必须在 IsReady=FALSE 之后,
    // 否则 Arm 还会被 TryDeliverMsi 再触发一次。
    HvXhciEptTrapShutdown();

    // Phase 4: 持久 Event Ring 映射 — 解除前等所有在飞的 deliver 完成
    // (单核进入 Shutdown 时,deliver 已经被 IsReady 拒绝;多核场景下
    //  KeIpiGenericCall 已自然 barrier)
    if (g_HvUsbXhci.EventRingSegMappedVa && g_HvUsbXhci.EventRingSegMappedBytes) {
        HvXhciUnmapPhys(g_HvUsbXhci.EventRingSegMappedVa,
                        g_HvUsbXhci.EventRingSegMappedBytes);
        g_HvUsbXhci.EventRingSegMappedVa    = NULL;
        g_HvUsbXhci.EventRingSegMappedBytes = 0;
    }

    // Phase 7: 每个 HID device 的 TR 起始页 + 缓存 buffer 页
    for (ULONG i = 0; i < HV_USB_HID_MAX_DEVICES; i++) {
        PHV_USB_HID_DEVICE d = &g_HvUsbXhci.Devices[i];
        if (d->TransferRingMappedVa) {
            HvXhciUnmapPhys(d->TransferRingMappedVa, PAGE_SIZE);
            d->TransferRingMappedVa       = NULL;
            d->TransferRingMappedPagePhys = 0;
        }
        if (d->DataBufferMappedVa) {
            HvXhciUnmapPhys(d->DataBufferMappedVa, PAGE_SIZE);
            d->DataBufferMappedVa       = NULL;
            d->DataBufferMappedPagePhys = 0;
        }
    }

    if (g_HvUsbXhci.Bar) {
        MmUnmapIoSpace((PVOID)g_HvUsbXhci.Bar, g_HvUsbXhci.BarSize);
        g_HvUsbXhci.Bar = NULL;
    }
}

BOOLEAN HvUsbXhciIsReady(VOID)
{
    return InterlockedCompareExchange(&g_HvUsbXhci.State,
                                      HvUsbXhciState_Ready,
                                      HvUsbXhciState_Ready)
           == HvUsbXhciState_Ready;
}

// ============================================================
// 注入: 把 HID report 写入 Transfer Ring 的 buffer + Event Ring 写完成事件
// ============================================================

//
// 写 Transfer Event TRB 到 Event Ring 当前 Producer 位置, 推 ProdIdx,
// 更新 Cycle bit (wrap 时翻转)。
// 这是 EventRing 写入的核心。
//
// Transfer Event TRB layout (XHCI spec 6.4.2.1):
//   Parameter [63:0]   = pointer to the Transfer TRB that completed (HPA)
//   Status    [23:0]   = TRB Transfer Length residual
//             [31:24]  = Completion Code
//   Control   [0]      = Cycle (matches PCS at producer)
//             [1]      = 0
//             [2]      = ED (Event Data) = 0
//             [9:3]    = 0
//             [15:10]  = TRB Type = 32 (Transfer Event)
//             [20:16]  = Endpoint ID
//             [23:21]  = 0
//             [31:24]  = Slot ID
//
static NTSTATUS HvXhciWriteTransferEvent(
    _In_ UCHAR slotId,
    _In_ UCHAR endpointId,
    _In_ ULONG64 trbPointerPhys,
    _In_ UCHAR completionCode,
    _In_ ULONG transferResidual)
{
    if (!g_HvUsbXhci.EventRingSegPhys) return STATUS_INVALID_DEVICE_STATE;

    ULONG segSize = g_HvUsbXhci.EventRingSegSize;
    if (segSize == 0) return STATUS_INVALID_DEVICE_STATE;

    PXHCI_TRB ringBase;

    // Phase 7: 调用方 HvXhciInjectHid 在持 g_HvUsbXhci.Lock (KSPIN_LOCK,
    // DISPATCH_LEVEL) 时调本函数。MmMapIoSpace 在 DISPATCH_LEVEL 是违规
    // (要求 PASSIVE_LEVEL),所以我们绝不能走 fallback map 路径。如果 init
    // 时持久映射失败,直接拒绝注入 (init 路径已经记日志了)。
    if (!g_HvUsbXhci.EventRingSegMappedVa) {
        return STATUS_DEVICE_NOT_READY;
    }
    ringBase = (PXHCI_TRB)g_HvUsbXhci.EventRingSegMappedVa;

    // ============================================================
    // Phase 4: scan-ahead 找真正的 producer 空槽
    //
    // xHCI 规范:Event Ring producer (硬件) 把每条 TRB 写完后,Control 字段的
    // Cycle bit 等于当前 PCS。Consumer (xhci.sys ISR) 从 ERDP 起读,
    // 如果 TRB.Cycle == CCS 就消费;否则停。
    //
    // 我们(伪 producer)和真硬件 producer 都向同一个 ring 写,可能竞争同一个
    // 槽位。安全策略:
    //
    //   1) 从 cached ProdIdx 起,向前扫描最多 segSize 槽
    //   2) 找到第一个 "Cycle != cached PCS" 的槽 — 那就是真的 producer 空槽
    //      (这个 PCS 周期里硬件还没写过)
    //   3) 如果一路扫下来全是 "Cycle == cached PCS" — 说明 ring 在这周期里
    //      被填满 (overrun, 硬件会自己置 USBSTS.HSE) — 我们放弃此次注入
    //
    // 这样即便硬件 producer 比我们快,我们也总写到它身后,不会覆盖真实事件。
    // 仍存在一个 ~ns 级窗口 (扫描后到写入前硬件刚好写到同槽),但 HID Boot
    // endpoint 在 8ms USB frame 边界上才产生事件,实际碰撞概率近 0。
    // ============================================================

    UCHAR  pcs = g_HvUsbXhci.EventRingCycle;
    ULONG  idx = g_HvUsbXhci.EventRingProdIdx % segSize;
    ULONG  scans = 0;
    BOOLEAN foundSlot = FALSE;

    while (scans < segSize) {
        PXHCI_TRB candidate = &ringBase[idx];
        ULONG cycleBit = candidate->Control & XHCI_TRB_CYCLE;
        UCHAR candidateCycle = (UCHAR)(cycleBit ? 1 : 0);

        if (candidateCycle != pcs) {
            // 这槽在当前 PCS 周期里没被生产 — 是真的空槽,我们可以写
            foundSlot = TRUE;
            break;
        }

        // 这槽 Cycle == PCS,说明已被硬件 producer 写过(我们跟不上,advance)
        idx = (idx + 1) % segSize;
        if (idx == 0) {
            // 跨边界:PCS 翻转 (但只在本扫描里临时翻;真正写完才更新全局)
            pcs ^= 1;
        }
        scans++;
    }

    if (!foundSlot) {
        XHCI_LOG("EventRing full — abandoning injection (HW producer ahead by %u)", scans);
        return STATUS_DEVICE_BUSY;
    }

    PXHCI_TRB target = &ringBase[idx];

    // 构造 TRB
    XHCI_TRB t;
    t.Parameter = trbPointerPhys;
    t.Status    = (transferResidual & 0xFFFFFF) | ((ULONG)completionCode << 24);
    t.Control   = (XHCI_TRB_TYPE_TRANSFER_EVENT << XHCI_TRB_TYPE_SHIFT)
                | ((ULONG)endpointId << 16)
                | ((ULONG)slotId << 24)
                | (pcs ? XHCI_TRB_CYCLE : 0);

    // 原子写整条 TRB (16 B):
    //   先写 Parameter + Status,最后写 Control (Cycle bit 在 Control 里)
    //   这样若控制器同时读,看到的是"未生产"(Cycle 还是旧值) 而不是部分有效
    target->Parameter = t.Parameter;
    target->Status    = t.Status;
    _ReadWriteBarrier();
    target->Control   = t.Control;
    _mm_sfence();

    // 推 Producer (跟扫描结果一致 — 不再盲推)
    ULONG nextIdx = (idx + 1) % segSize;
    if (nextIdx == 0) {
        pcs ^= 1;       // 真 wrap,翻 PCS
    }
    g_HvUsbXhci.EventRingProdIdx = nextIdx;
    g_HvUsbXhci.EventRingCycle   = pcs;

    return STATUS_SUCCESS;
}

//
// 把 HID report 写到目标设备 Transfer Ring 当前 dequeue 指向的 TRB 的
// Data Buffer Pointer 处。
//
// Transfer Ring 当前 TRB 应当是 Normal TRB (xhci.sys 用它接 IN 数据),
// 其 Parameter = Data Buffer 物理地址,Status[16:0] = TRB Transfer Length。
// 我们读出 buffer 地址,把 report 写进去,再返回该 TRB 的物理地址 (供
// Transfer Event TRB 的 Parameter 字段引用)。
//
static NTSTATUS HvXhciWriteHidReportToTr(
    _In_  PHV_USB_HID_DEVICE dev,
    _In_reads_bytes_(reportLen) PVOID reportData,
    _In_  ULONG reportLen,
    _Out_ PULONG64 OutCompletedTrbPhys,
    _Out_ PULONG   OutResidual)
{
    *OutCompletedTrbPhys = 0;
    *OutResidual = 0;

    if (dev->TransferRingPhys == 0) return STATUS_DEVICE_NOT_READY;

    // ============================================================
    // Phase 5: TR scan-ahead
    //
    // 问题:init 时记的 dev->TransferRingPhys / TransferRingCycle 是 EP
    // Context.TRDequePtr 的快照。xhci.sys 在 init 之后会沿环前进 — 我们的
    // cursor 早过期,看到的 TRB 多半 Cycle 不再匹配 (consumed 状态),
    // 或落在 LINK 上,或在 ring wrap 之后被新 cycle 覆盖。原来的 1-TRB
    // 查找命中率几乎为零 → 每次注入都返 STATUS_DEVICE_NOT_READY。
    //
    // 新策略:从 cursor 起向前扫,最多 MAX_SCAN TRBs(覆盖一整圈+一点冗余):
    //   - LINK TRB:跟随 (按 Toggle Cycle bit=bit1 翻 PCS),不计入 type 检查
    //   - NORMAL && cycle == 当前期望 cycle:命中,写 report,推 cursor 到下一格
    //   - 其他/cycle 不匹配:跳过这一格
    //
    // 命中后推进 cursor (scanPhys + 16),并保留当前扫到的 cycle 状态。下次
    // 注入从新位置接着扫。LINK 跨段时 cycle 已经在扫描里更新,正常推进就行。
    //
    // 选择"任意一条 cycle 匹配的 Normal TRB"而不是"恰好 dequeue 位置那条"
    // 是基于 xHCI spec 4.10.1:Transfer Event 不强制按 TRB 顺序产生,只要
    // 引用的 TRB 在被 xhci.sys 视为 in-flight 的范围内即可。我们扫到的第一
    // 条 cycle 匹配 Normal TRB 一定是 xhci.sys 写入但未消费的 (它写一条就
    // 翻 cycle 一次,被消费的 TRB 周围 cycle 还没翻回来覆盖)。
    // ============================================================

    ULONG64 scanPhys  = dev->TransferRingPhys;
    UCHAR   scanCycle = dev->TransferRingCycle;
    const ULONG MAX_SCAN = 512;        // 256-entry segment × 2 (容 wrap)
    ULONG  scanned = 0;

    // Phase 7: 调用方 (HvXhciInjectHid) 已经在 PASSIVE_LEVEL 持 dev->TrMutex
    // (FAST_MUTEX = APC_LEVEL),不再持 g_HvUsbXhci.Lock 这种 DISPATCH_LEVEL
    // spinlock。因此本函数里所有的 MmMapIoSpace 调用是合法的 (fallback path)。
    // 正常路径直接走 dev->TransferRingMappedVa 指针运算,零额外 map。

    while (scanned < MAX_SCAN) {
        ULONG64 pageBase = scanPhys & ~(PAGE_SIZE - 1ULL);
        ULONG   pageOff  = (ULONG)(scanPhys - pageBase);
        PVOID   pageVa   = NULL;
        BOOLEAN pageOwned = FALSE;   // TRUE 表示这页是本次临时映射,出退出前要 unmap

        // 1) 命中预映射的 TR 起始页 — 走指针运算,零 syscall
        if (dev->TransferRingMappedVa != NULL &&
            dev->TransferRingMappedPagePhys == pageBase) {
            pageVa = dev->TransferRingMappedVa;
        } else {
            // 2) 不在预映射页 (跨段 LINK,或预映射初始化失败的兜底) — 临时映射
            pageVa = HvXhciMapPhys(pageBase, PAGE_SIZE);
            if (!pageVa) return STATUS_INSUFFICIENT_RESOURCES;
            pageOwned = TRUE;
        }

        PXHCI_TRB trb = (PXHCI_TRB)((PUCHAR)pageVa + pageOff);
        UCHAR trbCycle = (UCHAR)(trb->Control & XHCI_TRB_CYCLE);
        ULONG type = (trb->Control >> XHCI_TRB_TYPE_SHIFT) & XHCI_TRB_TYPE_MASK;

        if (type == XHCI_TRB_TYPE_LINK) {
            ULONG64 nextRingPhys = trb->Parameter & ~0xFULL;
            BOOLEAN toggle = (trb->Control & XHCI_TRB_ENT) != 0;
            if (pageOwned) HvXhciUnmapPhys(pageVa, PAGE_SIZE);
            if (nextRingPhys == 0) {
                XHCI_LOG("slot=%u DCI=%u LINK TRB has NULL target at 0x%llX",
                         dev->SlotId, dev->EndpointId, scanPhys);
                return STATUS_INVALID_DEVICE_STATE;
            }
            scanPhys = nextRingPhys;
            if (toggle) scanCycle ^= 1;
            scanned++;
            continue;
        }

        if (type == XHCI_TRB_TYPE_NORMAL && trbCycle == scanCycle) {
            ULONG bufLen = trb->Status & 0x1FFFF;
            if (bufLen < reportLen) {
                if (pageOwned) HvXhciUnmapPhys(pageVa, PAGE_SIZE);
                XHCI_LOG("slot=%u DCI=%u TRB at 0x%llX length %u < report %u",
                         dev->SlotId, dev->EndpointId, scanPhys, bufLen, reportLen);
                return STATUS_BUFFER_TOO_SMALL;
            }

            BOOLEAN useImmediate = (trb->Control & XHCI_TRB_IDT) != 0;
            ULONG64 bufPhys = trb->Parameter;

            *OutCompletedTrbPhys = scanPhys;
            *OutResidual = bufLen - reportLen;

            dev->TransferRingPhys  = scanPhys + sizeof(XHCI_TRB);
            dev->TransferRingCycle = scanCycle;

            if (useImmediate) {
                if (reportLen > 8) {
                    if (pageOwned) HvXhciUnmapPhys(pageVa, PAGE_SIZE);
                    return STATUS_BUFFER_TOO_SMALL;
                }
                ULONG64 imm = 0;
                RtlCopyMemory(&imm, reportData, reportLen);
                trb->Parameter = imm;
                _mm_sfence();
                if (pageOwned) HvXhciUnmapPhys(pageVa, PAGE_SIZE);
                if (scanned > 0) {
                    XHCI_LOG("slot=%u DCI=%u TR scan hit IDT TRB at 0x%llX "
                             "(scanned %u, cycle=%u)",
                             dev->SlotId, dev->EndpointId, scanPhys,
                             scanned, scanCycle);
                }
                InterlockedIncrement(&g_HvUsbXhci.StatTrbWriteOk);
                return STATUS_SUCCESS;
            }

            // 释放 TR 页 (data buffer 在不同页,而且我们要写它)
            if (pageOwned) HvXhciUnmapPhys(pageVa, PAGE_SIZE);

            // ---- 写 data buffer ----
            ULONG64 bufPageBase = bufPhys & ~(PAGE_SIZE - 1ULL);
            ULONG   bufPageOff  = (ULONG)(bufPhys - bufPageBase);
            if (bufPageOff + reportLen > PAGE_SIZE) {
                XHCI_LOG("buffer 0x%llX crosses page boundary, skipping", bufPhys);
                return STATUS_NOT_SUPPORTED;
            }

            // Lazy buffer cache:首次见到 buffer 页就 map 并缓存,xhci.sys 一般
            // 给 HID Interrupt-IN endpoint 长期复用同一个 DMA buffer,缓存后
            // 后续注入零 MmMapIoSpace。
            PVOID bufVa = NULL;
            BOOLEAN bufOwned = FALSE;
            if (dev->DataBufferMappedVa != NULL &&
                dev->DataBufferMappedPagePhys == bufPageBase) {
                bufVa = dev->DataBufferMappedVa;
            } else if (dev->DataBufferMappedVa == NULL) {
                // 首次见到 — 缓存
                bufVa = HvXhciMapPhys(bufPageBase, PAGE_SIZE);
                if (bufVa) {
                    dev->DataBufferMappedVa        = bufVa;
                    dev->DataBufferMappedPagePhys  = bufPageBase;
                }
            } else {
                // 缓存的是旧页 — xhci.sys 极少切换 buffer,但若发生就用临时映射;
                // 这里不替换缓存,等下次 inject 仍试图复用旧的(若旧的不再有效会
                // 在写时拿到 STATUS_INVALID_ADDRESS)。
                bufVa = HvXhciMapPhys(bufPageBase, PAGE_SIZE);
                bufOwned = TRUE;
            }

            if (!bufVa) return STATUS_INSUFFICIENT_RESOURCES;

            RtlCopyMemory((PUCHAR)bufVa + bufPageOff, reportData, reportLen);
            _mm_sfence();

            if (bufOwned) HvXhciUnmapPhys(bufVa, PAGE_SIZE);

            if (scanned > 0) {
                XHCI_LOG("slot=%u DCI=%u TR scan hit Normal TRB at 0x%llX "
                         "(scanned %u, cycle=%u, buf=0x%llX, len=%u)",
                         dev->SlotId, dev->EndpointId, scanPhys,
                         scanned, scanCycle, bufPhys, bufLen);
            }
            InterlockedIncrement(&g_HvUsbXhci.StatTrbWriteOk);
            return STATUS_SUCCESS;
        }

        // 不是 LINK 也不是匹配的 NORMAL — 跳过这格继续扫
        if (pageOwned) HvXhciUnmapPhys(pageVa, PAGE_SIZE);
        scanPhys += sizeof(XHCI_TRB);
        scanned++;
    }

    XHCI_LOG("slot=%u DCI=%u: no pending Normal TRB found after %u TRB scan "
             "(start=0x%llX cycle=%u)",
             dev->SlotId, dev->EndpointId, MAX_SCAN,
             dev->TransferRingPhys, dev->TransferRingCycle);
    InterlockedIncrement(&g_HvUsbXhci.StatTrbWriteFailed);
    return STATUS_DEVICE_NOT_READY;
}

//
// 主注入: 写 HID report → 写 Transfer Event → 触发 MSI
//
// Phase 7 重构 — 分两段锁,根治 kbd↔mouse 高频争锁导致的死锁:
//
//   旧版:KeAcquireSpinLock(&g_HvUsbXhci.Lock) 覆盖 [TR scan + buffer write +
//   Event Ring write + PendingMsi set],TR scan 在 spinlock 下做 MmMapIoSpace
//   per-TRB,违反 ≤APC_LEVEL 约束。鼠标 60Hz 平滑模式时,锁被一次 inject 抓
//   住 5ms+ (512 次 map/unmap),键盘 inject 完全卡死。
//
//   新版:
//     [A] PASSIVE_LEVEL,持 dev->TrMutex (FAST_MUTEX → APC_LEVEL):
//         扫 TR + 写 buffer。MmMapIoSpace fallback 在这里是合法的。
//         不同 device 各自的 TrMutex 独立,kbd 与 mouse 互不阻塞。
//     [B] DISPATCH_LEVEL,持 g_HvUsbXhci.Lock (KSPIN_LOCK):
//         写 Event Ring (持久映射,零 syscall) + 置 PendingMsi。
//         这一段只有几十条指令,kbd 与 mouse 在 Event Ring 上共享 spinlock
//         不会卡死。
//     [C] 锁外 KeIpiGenericCall 触发 VMEXIT,真正注入 MSI 在 root 模式。
//
static NTSTATUS HvXhciInjectHid(
    _In_ PHV_USB_HID_DEVICE dev,
    _In_reads_bytes_(reportLen) PVOID reportData,
    _In_ ULONG reportLen)
{
    NTSTATUS status;
    KIRQL old;
    ULONG64 completedTrb = 0;
    ULONG   residual = 0;

    if (!ExAcquireRundownProtection(&g_HvUsbXhci.OperationRundown)) {
        return STATUS_DEVICE_NOT_READY;
    }

    if (!HvUsbXhciIsReady() || dev == NULL || dev->Valid == 0) {
        ExReleaseRundownProtection(&g_HvUsbXhci.OperationRundown);
        return STATUS_DEVICE_NOT_READY;
    }

    // ===== [A] PASSIVE/APC: 写 TR (per-device, kbd 与 mouse 互不影响) =====
    ExAcquireFastMutex(&dev->TrMutex);
    status = HvXhciWriteHidReportToTr(dev, reportData, reportLen,
                                      &completedTrb, &residual);
    ExReleaseFastMutex(&dev->TrMutex);
    if (!NT_SUCCESS(status)) {
        ExReleaseRundownProtection(&g_HvUsbXhci.OperationRundown);
        return status;
    }

    // ===== [B] DISPATCH: 写 Event Ring + 置 PendingMsi (跨 device 共享) =====
    KeAcquireSpinLock(&g_HvUsbXhci.Lock, &old);
    status = HvXhciWriteTransferEvent(dev->SlotId, dev->EndpointId,
                                      completedTrb, XHCI_CC_SUCCESS, residual);
    if (NT_SUCCESS(status)) {
        InterlockedExchange(&g_HvUsbXhci.PendingMsi, 1);
    }
    KeReleaseSpinLock(&g_HvUsbXhci.Lock, old);
    if (!NT_SUCCESS(status)) {
        ExReleaseRundownProtection(&g_HvUsbXhci.OperationRundown);
        return status;
    }

    // ===== [C] 锁外 IPI kick,任一 CPU 的 dispatcher 末尾会 InjectInterrupt =====
    if (g_HvUsbXhci.MsiVector != 0) {
        KeIpiGenericCall(HvXhciKickIpiCallback, 0);
    }

    ExReleaseRundownProtection(&g_HvUsbXhci.OperationRundown);
    return STATUS_SUCCESS;
}

// VMEXIT 末尾 (root 模式) 调用,InterlockedExchange 单 CPU 抢锁注入 MSI
VOID HvUsbXhciTryDeliverMsi(VOID)
{
    if (!ExAcquireRundownProtection(&g_HvUsbXhci.OperationRundown)) return;
    if (!HvUsbXhciIsReady()) {
        ExReleaseRundownProtection(&g_HvUsbXhci.OperationRundown);
        return;
    }
    if (g_HvUsbXhci.MsiVector == 0) {
        ExReleaseRundownProtection(&g_HvUsbXhci.OperationRundown);
        return;
    }

    // 单 CPU 抢锁,防多核同时注入
    if (InterlockedCompareExchange(&g_HvUsbXhci.DeliveryLock, 1, 0) != 0) {
        ExReleaseRundownProtection(&g_HvUsbXhci.OperationRundown);
        return;
    }

    // 检查并清 pending —— 如果当前 CPU 不能注入,放回去等下次 VMEXIT
    if (InterlockedCompareExchange(&g_HvUsbXhci.PendingMsi, 0, 1) != 1) {
        InterlockedExchange(&g_HvUsbXhci.DeliveryLock, 0);
        ExReleaseRundownProtection(&g_HvUsbXhci.OperationRundown);
        return;
    }

    InterlockedIncrement(&g_HvUsbXhci.StatInjectAttempts);

    if (HvVmExitCanInjectInterrupt()) {
        // 注入前快照 ERDP — 检查上一次注入后 xhci.sys ISR 有没有真的处理我们的
        // Transfer Event TRB (处理 = ERDP 前进)。这是 Item 1 的诊断手段。
        ULONG64 erdpBefore = 0;
        if (g_HvUsbXhci.RtBase != NULL) {
            volatile UCHAR* ir0 = g_HvUsbXhci.RtBase + XHCI_RT_IR0;
            erdpBefore = XhciMmioReadQ(ir0, XHCI_IR_ERDP_LO) & ~0xFULL;

            ULONG64 lastErdp = g_HvUsbXhci.LastInjectedErdp;
            if (lastErdp != 0) {
                if (erdpBefore != lastErdp) {
                    InterlockedIncrement(&g_HvUsbXhci.StatErdpAdvanced);
                } else {
                    InterlockedIncrement(&g_HvUsbXhci.StatErdpStalled);
                    // 这里第一手证据 — xhci.sys ISR 没动 ERDP,说明它要么没运行,
                    // 要么早早 bail (IMAN.IP=0 或 USBSTS.EINT=0 之类 fast-path 检查)
                    DbgPrint("[XHCI-DIAG] ERDP stalled at 0x%llX (no ISR consume since last inject)\n",
                             erdpBefore);
                }
            }
            g_HvUsbXhci.LastInjectedErdp = erdpBefore;
        }

        // type=0 = external interrupt
        HvVmExitInjectInterrupt(g_HvUsbXhci.MsiVector, 0);
        InterlockedIncrement(&g_HvUsbXhci.StatInjectDelivered);

        // Item 2: 激活 USBSTS/IMAN read trap — 这样 xhci.sys ISR 入口读这两个
        // 寄存器时,我们能 OR-in EINT/IP 让它继续处理 Event Ring,而不是 fast-bail。
        // Arm 自身做 INVEPT,VMX root 安全。
        HvXhciEptTrapArm();
    } else {
        // IF=0:复原 pending,下次 VMEXIT 再来
        InterlockedExchange(&g_HvUsbXhci.PendingMsi, 1);
        InterlockedIncrement(&g_HvUsbXhci.StatInjectDeferred);
    }

    InterlockedExchange(&g_HvUsbXhci.DeliveryLock, 0);
    ExReleaseRundownProtection(&g_HvUsbXhci.OperationRundown);
}

NTSTATUS HvUsbXhciSendKeyboard(
    UCHAR modifiers,
    UCHAR key0, UCHAR key1, UCHAR key2,
    UCHAR key3, UCHAR key4, UCHAR key5)
{
    HID_BOOT_KBD_REPORT report;

    if (!HvUsbXhciIsReady()) return STATUS_DEVICE_NOT_READY;
    if (g_HvUsbXhci.Keyboard == NULL) return STATUS_NOT_FOUND;

    report.Modifiers = modifiers;
    report.Reserved  = 0;
    report.Keys[0] = key0; report.Keys[1] = key1; report.Keys[2] = key2;
    report.Keys[3] = key3; report.Keys[4] = key4; report.Keys[5] = key5;

    return HvXhciInjectHid(g_HvUsbXhci.Keyboard, &report, sizeof(report));
}

NTSTATUS HvUsbXhciSendMouse(UCHAR buttons, CHAR dx, CHAR dy, CHAR wheel)
{
    HID_BOOT_MOUSE_REPORT report;

    if (!HvUsbXhciIsReady()) return STATUS_DEVICE_NOT_READY;
    if (g_HvUsbXhci.Mouse == NULL) return STATUS_NOT_FOUND;

    report.Buttons = buttons;
    report.Dx = dx;
    report.Dy = dy;
    report.Wheel = wheel;

    return HvXhciInjectHid(g_HvUsbXhci.Mouse, &report, sizeof(report));
}

VOID HvUsbXhciQueryStatus(_Out_ PHV_USB_XHCI_STATUS s)
{
    if (!s) return;
    RtlZeroMemory(s, sizeof(*s));
    s->Ready         = HvUsbXhciIsReady() ? 1 : 0;
    s->HasKeyboard   = (g_HvUsbXhci.Keyboard != NULL) ? 1 : 0;
    s->HasMouse      = (g_HvUsbXhci.Mouse    != NULL) ? 1 : 0;
    s->MsiVector     = g_HvUsbXhci.MsiVector;
    s->PciVendorId   = g_HvUsbXhci.PciVendorId;
    s->PciDeviceId   = g_HvUsbXhci.PciDeviceId;
    s->BarPhys       = g_HvUsbXhci.BarPhys;
    s->EventRingSegPhys = g_HvUsbXhci.EventRingSegPhys;
    s->EventRingSegSize = g_HvUsbXhci.EventRingSegSize;
    s->KbdTrPhys     = g_HvUsbXhci.Keyboard ? g_HvUsbXhci.Keyboard->TransferRingPhys : 0;
    s->MouseTrPhys   = g_HvUsbXhci.Mouse    ? g_HvUsbXhci.Mouse->TransferRingPhys    : 0;

    // 诊断计数器 (Item 1) — InterlockedRead 在 LONG 上保证 volatile-safe
    s->StatInjectAttempts  = (ULONG)g_HvUsbXhci.StatInjectAttempts;
    s->StatInjectDelivered = (ULONG)g_HvUsbXhci.StatInjectDelivered;
    s->StatInjectDeferred  = (ULONG)g_HvUsbXhci.StatInjectDeferred;
    s->StatErdpAdvanced    = (ULONG)g_HvUsbXhci.StatErdpAdvanced;
    s->StatErdpStalled     = (ULONG)g_HvUsbXhci.StatErdpStalled;
    s->StatTrbWriteOk      = (ULONG)g_HvUsbXhci.StatTrbWriteOk;
    s->StatTrbWriteFailed  = (ULONG)g_HvUsbXhci.StatTrbWriteFailed;
    s->LastInjectedErdp    = g_HvUsbXhci.LastInjectedErdp;

    // 实时读当前 ERDP — 不在 root 模式调用此函数,IRQL 是 PASSIVE,
    // MMIO read 没问题。注意 RtBase 是 MmMapIoSpace 出来的 kernel VA,常驻。
    if (HvUsbXhciIsReady() && g_HvUsbXhci.RtBase != NULL) {
        volatile UCHAR* ir0 = g_HvUsbXhci.RtBase + XHCI_RT_IR0;
        s->CurrentErdp = XhciMmioReadQ(ir0, XHCI_IR_ERDP_LO) & ~0xFULL;
    }
}
