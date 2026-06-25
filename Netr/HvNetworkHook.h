/*
 * HvNetworkHook.h
 * 
 * 网卡流量伪造模块 - 完整版
 * 
 * 功能：
 *   - 伪造网卡发送/接收的总字节数
 *   - 伪造网卡发送/接收速率 (Mbps)
 *   - 伪造网卡发送/接收包数
 *   - 支持指定网卡或全部网卡
 *   - 支持多种 Windows 版本 (Win10/Win11)
 *   - 使用 EPT/NPT Hook 实现内核级隐藏
 */

#ifndef _HV_NETWORK_HOOK_H_
#define _HV_NETWORK_HOOK_H_

#pragma once

#include <ntddk.h>

// ============================================================
// 常量定义
// ============================================================

#define HV_NET_HOOK_TAG         'tNeH'
#define MAX_ADAPTER_NAME        64
#define MAX_HIDDEN_ADAPTERS     16

// ============================================================
// NSI (Network Store Interface) 完整定义
// ============================================================

// NPI Module ID 类型
#define MIT_GUID    1
#define MIT_IF_LUID 2

// NPI Module ID 结构
typedef struct _NPI_MODULEID {
    USHORT Length;
    UCHAR Type;
    UCHAR Reserved;
    union {
        GUID Guid;
        LUID IfLuid;
    };
} NPI_MODULEID, *PNPI_MODULEID;

// NSI 参数类型
typedef enum _NSI_PARAM_TYPE {
    NsiParamTypeRw = 0,             // 可读写参数
    NsiParamTypeRoDynamic = 1,      // 只读动态参数（统计信息）
    NsiParamTypeRoStatic = 2,       // 只读静态参数
    NsiParamTypeMax = 3
} NSI_PARAM_TYPE;

// NSI 结构类型
typedef enum _NSI_STRUCT_TYPE {
    NsiStructTypeNone = 0,
    NsiStructTypeCompartment = 1,
    NsiStructTypeInterface = 2,
    NsiStructTypeUnicastAddress = 3,
    NsiStructTypeAnycastAddress = 4,
    NsiStructTypeMulticastAddress = 5,
    NsiStructTypeBroadcastAddress = 6,
    NsiStructTypeRoute = 7,
    NsiStructTypeNeighbor = 8,
    NsiStructTypePath = 9,
    NsiStructTypeSubInterface = 10,
    NsiStructTypeForward = 11,
    NsiStructTypeMax = 12
} NSI_STRUCT_TYPE;

// NDIS Interface LUID
#ifndef _NET_LUID_LH_DEFINED
#define _NET_LUID_LH_DEFINED
typedef union _HV_NET_LUID {
    ULONG64 Value;
    struct {
        ULONG64 Reserved : 24;
        ULONG64 NetLuidIndex : 24;
        ULONG64 IfType : 16;
    } Info;
} HV_NET_LUID, *PHV_NET_LUID;
#endif

// ============================================================
// MIB_IF_ROW2 完整结构定义 (Windows 10/11)
// ============================================================

// 接口类型
typedef ULONG IF_INDEX;
typedef ULONG NET_IFINDEX;
typedef USHORT NET_IF_TYPE;

// 接口操作状态
typedef enum _IF_OPER_STATUS {
    IfOperStatusUp = 1,
    IfOperStatusDown = 2,
    IfOperStatusTesting = 3,
    IfOperStatusUnknown = 4,
    IfOperStatusDormant = 5,
    IfOperStatusNotPresent = 6,
    IfOperStatusLowerLayerDown = 7
} IF_OPER_STATUS;

// 接口管理状态
typedef enum _NET_IF_ADMIN_STATUS {
    NET_IF_ADMIN_STATUS_UP = 1,
    NET_IF_ADMIN_STATUS_DOWN = 2,
    NET_IF_ADMIN_STATUS_TESTING = 3
} NET_IF_ADMIN_STATUS;

// 接口媒体连接状态
typedef enum _NET_IF_MEDIA_CONNECT_STATE {
    MediaConnectStateUnknown = 0,
    MediaConnectStateConnected = 1,
    MediaConnectStateDisconnected = 2
} NET_IF_MEDIA_CONNECT_STATE;

// 接口连接类型
typedef enum _NET_IF_CONNECTION_TYPE {
    NET_IF_CONNECTION_DEDICATED = 1,
    NET_IF_CONNECTION_PASSIVE = 2,
    NET_IF_CONNECTION_DEMAND = 3,
    NET_IF_CONNECTION_MAXIMUM = 4
} NET_IF_CONNECTION_TYPE;

// 隧道类型
typedef enum _TUNNEL_TYPE {
    TUNNEL_TYPE_NONE = 0,
    TUNNEL_TYPE_OTHER = 1,
    TUNNEL_TYPE_DIRECT = 2,
    TUNNEL_TYPE_6TO4 = 11,
    TUNNEL_TYPE_ISATAP = 13,
    TUNNEL_TYPE_TEREDO = 14,
    TUNNEL_TYPE_IPHTTPS = 15
} TUNNEL_TYPE;

// 接口访问类型
typedef enum _NET_IF_ACCESS_TYPE {
    NET_IF_ACCESS_LOOPBACK = 1,
    NET_IF_ACCESS_BROADCAST = 2,
    NET_IF_ACCESS_POINT_TO_POINT = 3,
    NET_IF_ACCESS_POINT_TO_MULTI_POINT = 4,
    NET_IF_ACCESS_MAXIMUM = 5
} NET_IF_ACCESS_TYPE;

// 接口方向类型
typedef enum _NET_IF_DIRECTION_TYPE {
    NET_IF_DIRECTION_SENDRECEIVE = 0,
    NET_IF_DIRECTION_SENDONLY = 1,
    NET_IF_DIRECTION_RECEIVEONLY = 2,
    NET_IF_DIRECTION_MAXIMUM = 3
} NET_IF_DIRECTION_TYPE;

// 物理地址
#define IF_MAX_PHYS_ADDRESS_LENGTH 32
#define IF_MAX_STRING_SIZE 256

typedef struct _IF_PHYSICAL_ADDRESS_LH {
    USHORT Length;
    UCHAR Address[IF_MAX_PHYS_ADDRESS_LENGTH];
} IF_PHYSICAL_ADDRESS_LH, *PIF_PHYSICAL_ADDRESS_LH;

// MIB_IF_ROW2 完整结构 (大小约 0x1A8 = 424 字节)
typedef struct _MIB_IF_ROW2 {
    // 0x000: 接口 LUID
    HV_NET_LUID InterfaceLuid;
    // 0x008: 接口索引
    NET_IFINDEX InterfaceIndex;
    // 0x00C: 接口 GUID
    GUID InterfaceGuid;
    // 0x01C: 接口别名
    WCHAR Alias[IF_MAX_STRING_SIZE + 1];
    // 0x220: 接口描述
    WCHAR Description[IF_MAX_STRING_SIZE + 1];
    // 0x424: 物理地址长度
    ULONG PhysicalAddressLength;
    // 0x428: 物理地址
    UCHAR PhysicalAddress[IF_MAX_PHYS_ADDRESS_LENGTH];
    // 0x448: 永久物理地址
    UCHAR PermanentPhysicalAddress[IF_MAX_PHYS_ADDRESS_LENGTH];
    // 0x468: MTU
    ULONG Mtu;
    // 0x46C: 接口类型
    ULONG Type;
    // 0x470: 隧道类型
    TUNNEL_TYPE TunnelType;
    // 0x474: 媒体类型
    ULONG MediaType;
    // 0x478: 物理媒体类型
    ULONG PhysicalMediumType;
    // 0x47C: 访问类型
    NET_IF_ACCESS_TYPE AccessType;
    // 0x480: 方向类型
    NET_IF_DIRECTION_TYPE DirectionType;
    // 0x484: 接口和操作标志
    struct {
        BOOLEAN HardwareInterface : 1;
        BOOLEAN FilterInterface : 1;
        BOOLEAN ConnectorPresent : 1;
        BOOLEAN NotAuthenticated : 1;
        BOOLEAN NotMediaConnected : 1;
        BOOLEAN Paused : 1;
        BOOLEAN LowPower : 1;
        BOOLEAN EndPointInterface : 1;
    } InterfaceAndOperStatusFlags;
    // 0x488: 操作状态
    IF_OPER_STATUS OperStatus;
    // 0x48C: 管理状态
    NET_IF_ADMIN_STATUS AdminStatus;
    // 0x490: 媒体连接状态
    NET_IF_MEDIA_CONNECT_STATE MediaConnectState;
    // 0x494: 网络 GUID
    GUID NetworkGuid;
    // 0x4A4: 连接类型
    NET_IF_CONNECTION_TYPE ConnectionType;
    
    // 0x4A8: 发送链路速度 (bps)
    ULONG64 TransmitLinkSpeed;
    // 0x4B0: 接收链路速度 (bps)
    ULONG64 ReceiveLinkSpeed;
    
    // ========== 统计信息部分 (从 0x4B8 开始) ==========
    // 0x4B8: 接收字节数
    ULONG64 InOctets;
    // 0x4C0: 接收单播包数
    ULONG64 InUcastPkts;
    // 0x4C8: 接收非单播包数
    ULONG64 InNUcastPkts;
    // 0x4D0: 接收丢弃包数
    ULONG64 InDiscards;
    // 0x4D8: 接收错误包数
    ULONG64 InErrors;
    // 0x4E0: 接收未知协议包数
    ULONG64 InUnknownProtos;
    // 0x4E8: 接收单播字节数
    ULONG64 InUcastOctets;
    // 0x4F0: 接收多播字节数
    ULONG64 InMulticastOctets;
    // 0x4F8: 接收广播字节数
    ULONG64 InBroadcastOctets;
    // 0x500: 发送字节数
    ULONG64 OutOctets;
    // 0x508: 发送单播包数
    ULONG64 OutUcastPkts;
    // 0x510: 发送非单播包数
    ULONG64 OutNUcastPkts;
    // 0x518: 发送丢弃包数
    ULONG64 OutDiscards;
    // 0x520: 发送错误包数
    ULONG64 OutErrors;
    // 0x528: 发送单播字节数
    ULONG64 OutUcastOctets;
    // 0x530: 发送多播字节数
    ULONG64 OutMulticastOctets;
    // 0x538: 发送广播字节数
    ULONG64 OutBroadcastOctets;
    // 0x540: 发送队列长度
    ULONG64 OutQLen;
    
} MIB_IF_ROW2, *PMIB_IF_ROW2;

// MIB_IF_ROW2 字段偏移（手动定义以确保正确性）
#define OFFSET_MIB_IF_ROW2_InterfaceLuid         0x000
#define OFFSET_MIB_IF_ROW2_InterfaceIndex        0x008
#define OFFSET_MIB_IF_ROW2_TransmitLinkSpeed     0x4A8
#define OFFSET_MIB_IF_ROW2_ReceiveLinkSpeed      0x4B0
#define OFFSET_MIB_IF_ROW2_InOctets              0x4B8
#define OFFSET_MIB_IF_ROW2_InUcastPkts           0x4C0
#define OFFSET_MIB_IF_ROW2_InNUcastPkts          0x4C8
#define OFFSET_MIB_IF_ROW2_InDiscards            0x4D0
#define OFFSET_MIB_IF_ROW2_InErrors              0x4D8
#define OFFSET_MIB_IF_ROW2_OutOctets             0x500
#define OFFSET_MIB_IF_ROW2_OutUcastPkts          0x508
#define OFFSET_MIB_IF_ROW2_OutNUcastPkts         0x510
#define OFFSET_MIB_IF_ROW2_OutDiscards           0x518
#define OFFSET_MIB_IF_ROW2_OutErrors             0x520

// ============================================================
// NDIS 相关结构 (用于 OID_GEN_STATISTICS)
// ============================================================

// NDIS 对象头（简化版）
typedef struct _NDIS_OBJECT_HEADER_EX {
    UCHAR Type;
    UCHAR Revision;
    USHORT Size;
} NDIS_OBJECT_HEADER_EX, *PNDIS_OBJECT_HEADER_EX;

// NDIS 统计信息结构
typedef struct _NDIS_STATISTICS_INFO_EX {
    NDIS_OBJECT_HEADER_EX Header;
    ULONG SupportedStatistics;
    // 接收统计
    ULONG64 ifInDiscards;
    ULONG64 ifInErrors;
    ULONG64 ifHCInOctets;           // 接收字节数
    ULONG64 ifHCInUcastPkts;        // 接收单播包
    ULONG64 ifHCInMulticastPkts;    // 接收多播包
    ULONG64 ifHCInBroadcastPkts;    // 接收广播包
    // 发送统计
    ULONG64 ifHCOutOctets;          // 发送字节数
    ULONG64 ifHCOutUcastPkts;       // 发送单播包
    ULONG64 ifHCOutMulticastPkts;   // 发送多播包
    ULONG64 ifHCOutBroadcastPkts;   // 发送广播包
    ULONG64 ifOutErrors;
    ULONG64 ifOutDiscards;
    // 更多字段...
    ULONG64 ifHCInUcastOctets;
    ULONG64 ifHCInMulticastOctets;
    ULONG64 ifHCInBroadcastOctets;
    ULONG64 ifHCOutUcastOctets;
    ULONG64 ifHCOutMulticastOctets;
    ULONG64 ifHCOutBroadcastOctets;
} NDIS_STATISTICS_INFO_EX, *PNDIS_STATISTICS_INFO_EX;

// ============================================================
// NsiGetParameter 函数原型
// ============================================================

typedef NTSTATUS (NTAPI *PFN_NsiGetParameter)(
    _In_ ULONG Reserved,
    _In_ PNPI_MODULEID ModuleId,
    _In_ ULONG ObjectIndex,
    _In_reads_bytes_(KeyStructLength) PVOID KeyStruct,
    _In_ ULONG KeyStructLength,
    _In_ NSI_PARAM_TYPE ParamType,
    _Out_writes_bytes_(DataLength) PVOID Data,
    _In_ ULONG DataLength,
    _In_ ULONG DataOffset
);

// NsiEnumerateObjectsAllParameters 函数原型
typedef NTSTATUS (NTAPI *PFN_NsiEnumerateObjectsAllParameters)(
    _In_ ULONG Reserved,
    _In_ ULONG Reserved2,
    _In_ PNPI_MODULEID ModuleId,
    _In_ ULONG ObjectIndex,
    _Out_opt_ PVOID KeyStruct,
    _In_ ULONG KeyStructLength,
    _Out_opt_ PVOID RwParamStruct,
    _In_ ULONG RwParamStructLength,
    _Out_opt_ PVOID DynamicParamStruct,
    _In_ ULONG DynamicParamStructLength,
    _Out_opt_ PVOID StaticParamStruct,
    _In_ ULONG StaticParamStructLength,
    _Inout_ PULONG Count
);

// ============================================================
// 伪造模式和配置
// ============================================================

// 伪造模式
typedef enum _HV_NET_FAKE_MODE {
    HvNetFakeModeNone = 0,          // 不伪造（显示真实值）
    HvNetFakeModeFixed,             // 固定值模式
    HvNetFakeModeScale,             // 缩放模式（按比例缩小）
    HvNetFakeModeSubtract,          // 减去指定值
    HvNetFakeModeRandom,            // 随机波动模式
    HvNetFakeModeMax
} HV_NET_FAKE_MODE;

// 单个网卡的伪造配置
typedef struct _HV_NET_ADAPTER_CONFIG {
    BOOLEAN InUse;                  // 是否使用此条目
    BOOLEAN MatchAllAdapters;       // TRUE = 匹配所有网卡
    WCHAR AdapterName[MAX_ADAPTER_NAME]; // 网卡名称（用于匹配）
    ULONG64 InterfaceLuid;          // 网卡 LUID（精确匹配）
    ULONG InterfaceIndex;           // 网卡索引
    
    // 伪造模式
    HV_NET_FAKE_MODE FakeMode;
    
    // 固定值模式参数
    ULONG64 FakeBytesSent;          // 伪造的发送字节数
    ULONG64 FakeBytesReceived;      // 伪造的接收字节数
    ULONG64 FakePacketsSent;        // 伪造的发送包数
    ULONG64 FakePacketsReceived;    // 伪造的接收包数
    
    // 缩放模式参数 (0-100)
    ULONG ScalePercentSent;         // 发送缩放百分比 (0-100)
    ULONG ScalePercentReceived;     // 接收缩放百分比 (0-100)
    
    // 减去模式参数
    ULONG64 SubtractBytesSent;      // 要减去的发送字节数
    ULONG64 SubtractBytesReceived;  // 要减去的接收字节数
    
    // 速率伪造 (bps)
    BOOLEAN FakeSpeed;              // 是否伪造速率
    ULONG64 FakeSendSpeed;          // 伪造的发送速率 (bps)
    ULONG64 FakeReceiveSpeed;       // 伪造的接收速率 (bps)
    
} HV_NET_ADAPTER_CONFIG, *PHV_NET_ADAPTER_CONFIG;

// 网卡 Hook 管理器
typedef struct _HV_NET_HOOK_MANAGER {
    BOOLEAN Initialized;
    BOOLEAN HookInstalled;
    
    // 伪造配置列表
    HV_NET_ADAPTER_CONFIG Configs[MAX_HIDDEN_ADAPTERS];
    ULONG ConfigCount;
    
    // 同步
    KSPIN_LOCK Lock;
    
    // Hook 句柄
    PVOID NsiHookHandle;
    PVOID NsiEnumHookHandle;
    
    // 原始函数指针
    PFN_NsiGetParameter OriginalNsiGetParameter;
    PFN_NsiEnumerateObjectsAllParameters OriginalNsiEnumerate;
    
    // 目标函数地址
    PVOID NsiGetParameterAddress;
    PVOID NsiEnumerateAddress;
    
    // 统计
    volatile LONG64 QueryCount;     // 查询次数
    volatile LONG64 FakeCount;      // 伪造次数
    volatile LONG64 EnumCount;      // 枚举次数
    
    // Windows 版本信息
    RTL_OSVERSIONINFOW OsVersion;
    
    // 动态偏移（根据 Windows 版本调整）
    ULONG OffsetInOctets;
    ULONG OffsetOutOctets;
    ULONG OffsetTransmitSpeed;
    ULONG OffsetReceiveSpeed;
    ULONG OffsetInUcastPkts;
    ULONG OffsetOutUcastPkts;
    
} HV_NET_HOOK_MANAGER, *PHV_NET_HOOK_MANAGER;

// ============================================================
// 函数声明
// ============================================================

//
// 初始化和清理
//

NTSTATUS HvNetHookInitialize(VOID);
VOID HvNetHookCleanup(VOID);
BOOLEAN HvNetHookIsInitialized(VOID);

//
// 伪造配置
//

NTSTATUS HvNetSetFakeTrafficFixed(
    _In_ ULONG64 BytesSent,
    _In_ ULONG64 BytesReceived
);

NTSTATUS HvNetSetFakeTrafficScale(
    _In_ ULONG ScalePercentSent,
    _In_ ULONG ScalePercentReceived
);

NTSTATUS HvNetSetFakeTrafficSubtract(
    _In_ ULONG64 SubtractBytesSent,
    _In_ ULONG64 SubtractBytesReceived
);

NTSTATUS HvNetSetFakeSpeed(
    _In_ ULONG SendSpeedMbps,
    _In_ ULONG ReceiveSpeedMbps
);

NTSTATUS HvNetSetFakePackets(
    _In_ ULONG64 PacketsSent,
    _In_ ULONG64 PacketsReceived
);

VOID HvNetAddHiddenTraffic(
    _In_ ULONG64 BytesSent,
    _In_ ULONG64 BytesReceived
);

VOID HvNetResetHiddenTraffic(VOID);
VOID HvNetDisableFake(VOID);
VOID HvNetEnableFake(VOID);

//
// 高级配置
//

NTSTATUS HvNetSetAdapterConfig(
    _In_ ULONG InterfaceIndex,
    _In_ PHV_NET_ADAPTER_CONFIG Config
);

NTSTATUS HvNetGetAdapterConfig(
    _In_ ULONG InterfaceIndex,
    _Out_ PHV_NET_ADAPTER_CONFIG Config
);

NTSTATUS HvNetRemoveAdapterConfig(
    _In_ ULONG InterfaceIndex
);

//
// 调试和诊断
//

VOID HvNetPrintInfo(VOID);
VOID HvNetGetStats(
    _Out_opt_ PULONG64 QueryCount,
    _Out_opt_ PULONG64 FakeCount
);

// ============================================================
// 全局变量
// ============================================================

extern HV_NET_HOOK_MANAGER g_HvNetHookManager;

#endif // _HV_NETWORK_HOOK_H_
