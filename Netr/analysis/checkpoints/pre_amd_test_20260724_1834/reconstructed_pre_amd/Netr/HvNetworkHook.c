/*
 * HvNetworkHook.c
 * 
 * 网卡流量伪造模块实现 - 完整版
 * 
 * 实现原理：
 *   1. 查找并 Hook netio.sys!NsiGetParameter 函数
 *   2. 拦截网卡统计查询请求 (GetIfEntry2/GetIfTable2)
 *   3. 修改返回的统计数据（字节数、包数、速率）
 * 
 * Windows 获取网卡流量的调用链：
 *   用户态: GetIfEntry2() / GetIfTable2()
 *       -> iphlpapi.dll
 *       -> DeviceIoControl(\Device\Nsi)
 *       -> nsiproxy.sys -> netio.sys!NsiGetParameter
 *       -> NDIS
 */

#include "HvNetworkHook.h"
#include "HvHook.h"
#include "HvCompat.h"
#include "HvUtils.h"
#include <ntstrsafe.h>

// P122: 全 driver DbgPrint → GUI ring
#define HV_TRACE_THIS_CAT HV_TRACE_CAT_NETWORK
#include "HvTrace.h"


// ============================================================
// NDIS 模块 ID (用于识别网络接口查询)
// ============================================================

// NPI_MS_NDIS_MODULEID = {0xEB004A03, 0x9B1A, 0x11D4, {0x91, 0x23, 0x00, 0x50, 0x04, 0x77, 0x59, 0xBC}}
static const NPI_MODULEID NPI_MS_NDIS_MODULEID_VALUE = {
    sizeof(NPI_MODULEID),
    MIT_GUID,
    0,
    {
        .Guid = { 0xEB004A03, 0x9B1A, 0x11D4, {0x91, 0x23, 0x00, 0x50, 0x04, 0x77, 0x59, 0xBC} }
    }
};

// 简化的模块 ID 比较（只比较 GUID 的第一部分）
#define NDIS_MODULE_ID_DATA1    0xEB004A03

// NSI 对象索引
#define NSI_NDIS_IFINFO_OBJECT_INDEX    0x0A  // 网络接口信息对象

// ============================================================
// 全局变量
// ============================================================

HV_NET_HOOK_MANAGER g_HvNetHookManager = { 0 };

// 累计隐藏的流量
static volatile LONG64 g_AccumulatedHiddenBytesSent = 0;
static volatile LONG64 g_AccumulatedHiddenBytesReceived = 0;

#define HV_NET_CALLBACK_BEGIN(_Handle)                                      \
    HV_HOOK_HANDLE hvCallbackHandle = (HV_HOOK_HANDLE)(_Handle);            \
    if (!HvHookCallbackAcquire(hvCallbackHandle)) {                          \
        return STATUS_DELETE_PENDING;                                       \
    }                                                                        \
    __try {

#define HV_NET_CALLBACK_END()                                                \
    } __finally {                                                            \
        HvHookCallbackRelease(hvCallbackHandle);                             \
    }

// 是否启用伪造。必须是 LONG: InterlockedExchange 写 4 字节，旧 BOOLEAN
// 强转 PLONG 会覆盖相邻全局状态，网络子系统一旦启停即可造成内存破坏。
static volatile LONG g_FakeEnabled = FALSE;

// ============================================================
// 系统信息查询相关定义
// ============================================================

typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemModuleInformation = 11,
} SYSTEM_INFORMATION_CLASS;

typedef struct _RTL_PROCESS_MODULE_INFORMATION {
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

// 导入函数
NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(
    _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
    _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength
);

NTSYSAPI NTSTATUS NTAPI RtlGetVersion(
    _Out_ PRTL_OSVERSIONINFOW lpVersionInformation
);

// ============================================================
// PE 导出表解析 (简化的 PE 结构定义)
// ============================================================

#ifndef IMAGE_DOS_SIGNATURE
#define IMAGE_DOS_SIGNATURE 0x5A4D      // MZ
#endif

#ifndef IMAGE_NT_SIGNATURE
#define IMAGE_NT_SIGNATURE  0x00004550  // PE00
#endif

#ifndef IMAGE_DIRECTORY_ENTRY_EXPORT
#define IMAGE_DIRECTORY_ENTRY_EXPORT    0
#endif

// DOS Header (如果未定义)
#ifndef _IMAGE_DOS_HEADER_DEFINED
#define _IMAGE_DOS_HEADER_DEFINED
typedef struct _IMAGE_DOS_HEADER {
    USHORT e_magic;
    USHORT e_cblp;
    USHORT e_cp;
    USHORT e_crlc;
    USHORT e_cparhdr;
    USHORT e_minalloc;
    USHORT e_maxalloc;
    USHORT e_ss;
    USHORT e_sp;
    USHORT e_csum;
    USHORT e_ip;
    USHORT e_cs;
    USHORT e_lfarlc;
    USHORT e_ovno;
    USHORT e_res[4];
    USHORT e_oemid;
    USHORT e_oeminfo;
    USHORT e_res2[10];
    LONG e_lfanew;
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;
#endif

// Data Directory
typedef struct _IMAGE_DATA_DIRECTORY_EX {
    ULONG VirtualAddress;
    ULONG Size;
} IMAGE_DATA_DIRECTORY_EX, *PIMAGE_DATA_DIRECTORY_EX;

// Optional Header (64-bit)
typedef struct _IMAGE_OPTIONAL_HEADER64_EX {
    USHORT Magic;
    UCHAR MajorLinkerVersion;
    UCHAR MinorLinkerVersion;
    ULONG SizeOfCode;
    ULONG SizeOfInitializedData;
    ULONG SizeOfUninitializedData;
    ULONG AddressOfEntryPoint;
    ULONG BaseOfCode;
    ULONGLONG ImageBase;
    ULONG SectionAlignment;
    ULONG FileAlignment;
    USHORT MajorOperatingSystemVersion;
    USHORT MinorOperatingSystemVersion;
    USHORT MajorImageVersion;
    USHORT MinorImageVersion;
    USHORT MajorSubsystemVersion;
    USHORT MinorSubsystemVersion;
    ULONG Win32VersionValue;
    ULONG SizeOfImage;
    ULONG SizeOfHeaders;
    ULONG CheckSum;
    USHORT Subsystem;
    USHORT DllCharacteristics;
    ULONGLONG SizeOfStackReserve;
    ULONGLONG SizeOfStackCommit;
    ULONGLONG SizeOfHeapReserve;
    ULONGLONG SizeOfHeapCommit;
    ULONG LoaderFlags;
    ULONG NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY_EX DataDirectory[16];
} IMAGE_OPTIONAL_HEADER64_EX, *PIMAGE_OPTIONAL_HEADER64_EX;

// File Header
typedef struct _IMAGE_FILE_HEADER_EX {
    USHORT Machine;
    USHORT NumberOfSections;
    ULONG TimeDateStamp;
    ULONG PointerToSymbolTable;
    ULONG NumberOfSymbols;
    USHORT SizeOfOptionalHeader;
    USHORT Characteristics;
} IMAGE_FILE_HEADER_EX, *PIMAGE_FILE_HEADER_EX;

// NT Headers (64-bit)
typedef struct _IMAGE_NT_HEADERS64_EX {
    ULONG Signature;
    IMAGE_FILE_HEADER_EX FileHeader;
    IMAGE_OPTIONAL_HEADER64_EX OptionalHeader;
} IMAGE_NT_HEADERS64_EX, *PIMAGE_NT_HEADERS64_EX;

// Export Directory
typedef struct _IMAGE_EXPORT_DIRECTORY_EX {
    ULONG Characteristics;
    ULONG TimeDateStamp;
    USHORT MajorVersion;
    USHORT MinorVersion;
    ULONG Name;
    ULONG Base;
    ULONG NumberOfFunctions;
    ULONG NumberOfNames;
    ULONG AddressOfFunctions;
    ULONG AddressOfNames;
    ULONG AddressOfNameOrdinals;
} IMAGE_EXPORT_DIRECTORY_EX, *PIMAGE_EXPORT_DIRECTORY_EX;

// ============================================================
// 内部辅助函数
// ============================================================

/*
 * 获取 Windows 版本并设置动态偏移
 * (现在直接读 HvUtils 全局 g_HvOsBuildNumber, 避免重复调 RtlGetVersion)
 */
static VOID
DetectWindowsVersionAndSetOffsets(VOID)
{
    // 与全局 OS 版本同步
    g_HvNetHookManager.OsVersion.dwMajorVersion = g_HvOsMajorVersion;
    g_HvNetHookManager.OsVersion.dwMinorVersion = g_HvOsMinorVersion;
    g_HvNetHookManager.OsVersion.dwBuildNumber  = g_HvOsBuildNumber;
    g_HvNetHookManager.OsVersion.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOW);

    DbgPrint("[HvNetHook] Using global OS version: %lu.%lu Build %lu\n",
             g_HvOsMajorVersion, g_HvOsMinorVersion, g_HvOsBuildNumber);

    // NsiGetParameter 返回的动态数据偏移; Win10/11 通用
    g_HvNetHookManager.OffsetInOctets = 0x00;
    g_HvNetHookManager.OffsetInUcastPkts = 0x08;
    g_HvNetHookManager.OffsetOutOctets = 0x48;
    g_HvNetHookManager.OffsetOutUcastPkts = 0x50;
    g_HvNetHookManager.OffsetTransmitSpeed = 0x00;
    g_HvNetHookManager.OffsetReceiveSpeed = 0x08;
}

/*
 * 通过模块名获取模块基址
 */
static PVOID
GetKernelModuleBase(
    _In_ PCSTR ModuleName
)
{
    NTSTATUS status;
    ULONG bufferSize = 0;
    PRTL_PROCESS_MODULES modules = NULL;
    PVOID moduleBase = NULL;
    
    // 获取所需缓冲区大小
    status = ZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &bufferSize);
    if (status != STATUS_INFO_LENGTH_MISMATCH || bufferSize == 0) {
        return NULL;
    }
    
    // 分配缓冲区
    modules = (PRTL_PROCESS_MODULES)HvAllocateNonPaged(bufferSize, HV_NET_HOOK_TAG);
    if (modules == NULL) {
        return NULL;
    }
    
    // 查询模块信息
    status = ZwQuerySystemInformation(SystemModuleInformation, modules, bufferSize, &bufferSize);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(modules, HV_NET_HOOK_TAG);
        return NULL;
    }
    
    // 查找指定模块
    for (ULONG i = 0; i < modules->NumberOfModules; i++) {
        PRTL_PROCESS_MODULE_INFORMATION module = &modules->Modules[i];
        PCSTR fileName = (PCSTR)(module->FullPathName + module->OffsetToFileName);
        
        if (_stricmp(fileName, ModuleName) == 0) {
            moduleBase = module->ImageBase;
            DbgPrint("[HvNetHook] Found %s at %p (size: 0x%X)\n",
                ModuleName, moduleBase, module->ImageSize);
            break;
        }
    }
    
    ExFreePoolWithTag(modules, HV_NET_HOOK_TAG);
    return moduleBase;
}

/*
 * 在模块导出表中查找函数
 */
static PVOID
GetExportedFunctionAddress(
    _In_ PVOID ModuleBase,
    _In_ PCSTR FunctionName
)
{
    PIMAGE_DOS_HEADER dosHeader;
    PIMAGE_NT_HEADERS64_EX ntHeaders;
    PIMAGE_EXPORT_DIRECTORY_EX exportDir;
    PULONG addressOfFunctions;
    PULONG addressOfNames;
    PUSHORT addressOfOrdinals;
    ULONG exportDirRva;
    ULONG exportDirSize;
    
    if (ModuleBase == NULL || FunctionName == NULL) {
        return NULL;
    }
    
    __try {
        dosHeader = (PIMAGE_DOS_HEADER)ModuleBase;
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            return NULL;
        }
        
        ntHeaders = (PIMAGE_NT_HEADERS64_EX)((PUCHAR)ModuleBase + dosHeader->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
            return NULL;
        }
        
        // 获取导出目录
        exportDirRva = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        exportDirSize = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
        
        if (exportDirRva == 0 || exportDirSize == 0) {
            return NULL;
        }
        
        exportDir = (PIMAGE_EXPORT_DIRECTORY_EX)((PUCHAR)ModuleBase + exportDirRva);
        
        addressOfFunctions = (PULONG)((PUCHAR)ModuleBase + exportDir->AddressOfFunctions);
        addressOfNames = (PULONG)((PUCHAR)ModuleBase + exportDir->AddressOfNames);
        addressOfOrdinals = (PUSHORT)((PUCHAR)ModuleBase + exportDir->AddressOfNameOrdinals);
        
        // 搜索函数名
        for (ULONG i = 0; i < exportDir->NumberOfNames; i++) {
            PCSTR name = (PCSTR)((PUCHAR)ModuleBase + addressOfNames[i]);
            
            if (strcmp(name, FunctionName) == 0) {
                USHORT ordinal = addressOfOrdinals[i];
                ULONG functionRva = addressOfFunctions[ordinal];
                
                // 检查是否是转发
                if (functionRva >= exportDirRva && functionRva < exportDirRva + exportDirSize) {
                    // 这是一个转发的导出，需要解析转发字符串
                    DbgPrint("[HvNetHook] %s is forwarded\n", FunctionName);
                    return NULL;
                }
                
                return (PVOID)((PUCHAR)ModuleBase + functionRva);
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[HvNetHook] Exception while parsing export table\n");
    }
    
    return NULL;
}

/*
 * 通过特征码搜索函数
 */
static PVOID
FindPatternInModule(
    _In_ PVOID ModuleBase,
    _In_ ULONG ModuleSize,
    _In_ PUCHAR Pattern,
    _In_ PCSTR Mask,
    _In_ ULONG PatternLength
)
{
    PUCHAR searchBase = (PUCHAR)ModuleBase;
    
    if (ModuleSize < PatternLength) {
        return NULL;
    }
    
    __try {
        for (ULONG i = 0; i < ModuleSize - PatternLength; i++) {
            BOOLEAN found = TRUE;
            
            for (ULONG j = 0; j < PatternLength; j++) {
                if (Mask[j] == 'x' && searchBase[i + j] != Pattern[j]) {
                    found = FALSE;
                    break;
                }
            }
            
            if (found) {
                return (PVOID)(searchBase + i);
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[HvNetHook] Exception during pattern search\n");
    }
    
    return NULL;
}

/*
 * 检查是否是 NDIS 接口统计查询
 */
static BOOLEAN
IsNdisInterfaceStatsQuery(
    _In_ PNPI_MODULEID ModuleId,
    _In_ ULONG ObjectIndex,
    _In_ NSI_PARAM_TYPE ParamType
)
{
    static LONG64 debugCounter = 0;
    BOOLEAN result = FALSE;
    
    if (ModuleId == NULL) {
        return FALSE;
    }
    
    // 每 100 次打印一次调试信息
    if ((InterlockedIncrement64(&debugCounter) % 100) == 1) {
        DbgPrint("[HvNetHook] Query: Type=%d, ObjIdx=0x%X, ParamType=%d, GUID.Data1=0x%08X\n",
            ModuleId->Type, ObjectIndex, ParamType,
            (ModuleId->Type == MIT_GUID) ? ModuleId->Guid.Data1 : 0);
    }
    
    // 检查是否是 NDIS 模块
    // 方式1：检查 GUID - NDIS 模块 ID
    if (ModuleId->Type == MIT_GUID) {
        if (ModuleId->Guid.Data1 == NDIS_MODULE_ID_DATA1) {
            if (ParamType == NsiParamTypeRoDynamic) {
                result = TRUE;
            }
        }
    }
    
    // 方式2：始终拦截动态参数查询（更宽松的匹配）
    if (!result && ParamType == NsiParamTypeRoDynamic) {
        // 任何动态参数查询都尝试处理
        result = TRUE;
    }
    
    return result;
}

/*
 * 查找匹配的适配器配置
 */
static PHV_NET_ADAPTER_CONFIG
FindMatchingConfig(
    _In_ ULONG64 InterfaceLuid,
    _In_ ULONG InterfaceIndex
)
{
    KIRQL oldIrql;
    PHV_NET_ADAPTER_CONFIG config = NULL;
    
    KeAcquireSpinLock(&g_HvNetHookManager.Lock, &oldIrql);
    
    for (ULONG i = 0; i < MAX_HIDDEN_ADAPTERS; i++) {
        if (g_HvNetHookManager.Configs[i].InUse) {
            // 匹配所有网卡
            if (g_HvNetHookManager.Configs[i].MatchAllAdapters) {
                config = &g_HvNetHookManager.Configs[i];
                break;
            }
            // 按 LUID 匹配
            if (g_HvNetHookManager.Configs[i].InterfaceLuid != 0 &&
                g_HvNetHookManager.Configs[i].InterfaceLuid == InterfaceLuid) {
                config = &g_HvNetHookManager.Configs[i];
                break;
            }
            // 按索引匹配
            if (g_HvNetHookManager.Configs[i].InterfaceIndex == InterfaceIndex) {
                config = &g_HvNetHookManager.Configs[i];
                break;
            }
        }
    }
    
    KeReleaseSpinLock(&g_HvNetHookManager.Lock, oldIrql);
    
    return config;
}

/*
 * 应用伪造配置到统计数据
 */
static VOID
ApplyFakeToStats(
    _In_ PHV_NET_ADAPTER_CONFIG Config,
    _Inout_ PULONG64 InOctets,
    _Inout_ PULONG64 OutOctets,
    _Inout_opt_ PULONG64 InPkts,
    _Inout_opt_ PULONG64 OutPkts
)
{
    if (Config == NULL || !g_FakeEnabled) {
        return;
    }
    
    switch (Config->FakeMode) {
        case HvNetFakeModeFixed:
            if (InOctets) *InOctets = Config->FakeBytesReceived;
            if (OutOctets) *OutOctets = Config->FakeBytesSent;
            if (InPkts) *InPkts = Config->FakePacketsReceived;
            if (OutPkts) *OutPkts = Config->FakePacketsSent;
            break;
            
        case HvNetFakeModeScale:
            if (InOctets) *InOctets = (*InOctets * Config->ScalePercentReceived) / 100;
            if (OutOctets) *OutOctets = (*OutOctets * Config->ScalePercentSent) / 100;
            if (InPkts) *InPkts = (*InPkts * Config->ScalePercentReceived) / 100;
            if (OutPkts) *OutPkts = (*OutPkts * Config->ScalePercentSent) / 100;
            break;
            
        case HvNetFakeModeSubtract:
            if (InOctets) {
                ULONG64 sub = Config->SubtractBytesReceived + (ULONG64)g_AccumulatedHiddenBytesReceived;
                *InOctets = (*InOctets > sub) ? (*InOctets - sub) : 0;
            }
            if (OutOctets) {
                ULONG64 sub = Config->SubtractBytesSent + (ULONG64)g_AccumulatedHiddenBytesSent;
                *OutOctets = (*OutOctets > sub) ? (*OutOctets - sub) : 0;
            }
            break;
            
        case HvNetFakeModeRandom:
            {
                LARGE_INTEGER tick;
                tick = HvQueryTickCount();
                LONG variation = (LONG)((tick.LowPart % 21) - 10);  // -10% to +10%
                
                if (InOctets && *InOctets > 0) {
                    LONG64 delta = (LONG64)(*InOctets) * variation / 100;
                    *InOctets = (ULONG64)((LONG64)*InOctets + delta);
                }
                if (OutOctets && *OutOctets > 0) {
                    LONG64 delta = (LONG64)(*OutOctets) * variation / 100;
                    *OutOctets = (ULONG64)((LONG64)*OutOctets + delta);
                }
            }
            break;
            
        default:
            return;  // HvNetFakeModeNone
    }
    
    InterlockedIncrement64(&g_HvNetHookManager.FakeCount);
}

/*
 * 修改动态参数数据
 * Data 是 NsiGetParameter 返回的动态参数缓冲区
 */
static VOID
ModifyDynamicParamData(
    _Inout_ PVOID Data,
    _In_ ULONG DataLength,
    _In_ PHV_NET_ADAPTER_CONFIG Config
)
{
    PUCHAR pData = (PUCHAR)Data;
    static LONG64 modifyCounter = 0;
    
    // 打印原始数据用于调试
    if ((InterlockedIncrement64(&modifyCounter) % 50) == 1) {
        DbgPrint("[HvNetHook] ModifyData: DataLen=%lu, Mode=%d\n", DataLength, Config->FakeMode);
        if (DataLength >= 0x60) {
            // 打印前几个 ULONG64 值来确定数据布局
            PULONG64 p = (PULONG64)pData;
            DbgPrint("[HvNetHook] Data[0x00]=0x%llX, [0x08]=0x%llX, [0x10]=0x%llX\n", p[0], p[1], p[2]);
            DbgPrint("[HvNetHook] Data[0x18]=0x%llX, [0x20]=0x%llX, [0x28]=0x%llX\n", p[3], p[4], p[5]);
            DbgPrint("[HvNetHook] Data[0x30]=0x%llX, [0x38]=0x%llX, [0x40]=0x%llX\n", p[6], p[7], p[8]);
            DbgPrint("[HvNetHook] Data[0x48]=0x%llX, [0x50]=0x%llX, [0x58]=0x%llX\n", p[9], p[10], p[11]);
        }
    }
    
    // 尝试多个可能的偏移位置
    // 方案1: 标准 NSI 动态参数布局
    // InOctets @ 0x00, OutOctets @ 0x48
    
    if (DataLength >= 0x58) {
        PULONG64 pInOctets = (PULONG64)(pData + 0x00);   // InOctets
        PULONG64 pOutOctets = (PULONG64)(pData + 0x48);  // OutOctets
        PULONG64 pInPkts = (PULONG64)(pData + g_HvNetHookManager.OffsetInUcastPkts);
        PULONG64 pOutPkts = (PULONG64)(pData + g_HvNetHookManager.OffsetOutUcastPkts);
        
        ApplyFakeToStats(Config, pInOctets, pOutOctets, pInPkts, pOutPkts);
    }
}

// ============================================================
// NtDeviceIoControlFile Hook (用于拦截网络状态对话框的 IOCTL 查询)
// ============================================================

// NDIS IOCTL 定义
#define IOCTL_NDIS_QUERY_GLOBAL_STATS    0x00170002

// OID 定义 (在 IOCTL 输入缓冲区中)
#define OID_GEN_STATISTICS          0x00020106
#define OID_GEN_XMIT_OK             0x00020101
#define OID_GEN_RCV_OK              0x00020102
#define OID_GEN_BYTES_XMIT          0x00020201
#define OID_GEN_BYTES_RCV           0x00020202

// NDIS_STATISTICS_INFO 结构中的偏移
#define NDIS_STATS_OFFSET_BYTES_RECV    0x28  // ifHCInOctets
#define NDIS_STATS_OFFSET_BYTES_SENT    0x30  // ifHCOutOctets

// NtDeviceIoControlFile 函数指针类型
typedef NTSTATUS (NTAPI *PFN_NtDeviceIoControlFile)(
    _In_ HANDLE FileHandle,
    _In_opt_ HANDLE Event,
    _In_opt_ PIO_APC_ROUTINE ApcRoutine,
    _In_opt_ PVOID ApcContext,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_ ULONG IoControlCode,
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_opt_(OutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength
);

static PFN_NtDeviceIoControlFile g_OriginalNtDeviceIoControlFile = NULL;
static HV_HOOK_HANDLE g_NtDeviceIoControlFileHookHandle = NULL;
static volatile LONG64 g_IoctlHookCount = 0;
static volatile LONG g_IoctlHookReady = 0;  // 原子标志：1 = 准备好处理

/*
 * 检查设备句柄是否是网络适配器
 * 注意：由于我们已经通过 IOCTL_NDIS_QUERY_GLOBAL_STATS 过滤，
 * 这个 IOCTL 只用于 NDIS 设备，所以可以直接返回 TRUE
 */
static BOOLEAN
IsNetworkAdapterHandle(
    _In_ HANDLE FileHandle
)
{
    UNREFERENCED_PARAMETER(FileHandle);
    // IOCTL_NDIS_QUERY_GLOBAL_STATS 只用于 NDIS 设备
    // 不需要额外检查设备名称
    return TRUE;
}

// 保存原始 NtDeviceIoControlFile 地址（用于备用调用）
static PVOID g_NtDeviceIoControlFileAddress = NULL;

/*
 * NtDeviceIoControlFile Hook
 * 注意：这是一个非常频繁调用的函数，需要极其小心
 * 
 * 关键：g_OriginalNtDeviceIoControlFile 必须在 EPT Hook 激活之前就设置好
 */
static NTSTATUS NTAPI
HookedNtDeviceIoControlFile(
    _In_ HANDLE FileHandle,
    _In_opt_ HANDLE Event,
    _In_opt_ PIO_APC_ROUTINE ApcRoutine,
    _In_opt_ PVOID ApcContext,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_ ULONG IoControlCode,
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_opt_(OutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength
)
{
    HV_NET_CALLBACK_BEGIN(g_NtDeviceIoControlFileHookHandle)
    NTSTATUS status;
    PFN_NtDeviceIoControlFile originalFunc;
    ULONG oid = 0;
    BOOLEAN shouldModify = FALSE;
    
    // 获取原始函数指针（必须在最开始就检查）
    originalFunc = g_OriginalNtDeviceIoControlFile;
    
    // 如果原始函数还没设置好，这是一个严重错误
    // 但我们不能让系统崩溃，所以返回一个温和的错误
    if (originalFunc == NULL) {
        // 极端情况：Hook 已激活但 trampoline 指针还没设置
        // 这不应该发生，但如果发生了，尝试让调用静默失败
        if (IoStatusBlock != NULL) {
            __try {
                IoStatusBlock->Status = STATUS_DEVICE_NOT_READY;
                IoStatusBlock->Information = 0;
            } __except(EXCEPTION_EXECUTE_HANDLER) {
                // 忽略
            }
        }
        return STATUS_DEVICE_NOT_READY;
    }
    
    // 快速路径：只检查 NDIS IOCTL
    if (IoControlCode != IOCTL_NDIS_QUERY_GLOBAL_STATS) {
        // 不是 NDIS 查询，直接调用原始函数
        return originalFunc(
            FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock,
            IoControlCode, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength
        );
    }
    
    // 是 NDIS 查询，检查是否是我们关心的 OID
    __try {
        if (InputBuffer != NULL && InputBufferLength >= sizeof(ULONG)) {
            // 使用 ProbeForRead 风格的检查
            oid = *(volatile PULONG)InputBuffer;
            
            if (oid == OID_GEN_STATISTICS || 
                oid == OID_GEN_BYTES_XMIT || 
                oid == OID_GEN_BYTES_RCV ||
                oid == OID_GEN_XMIT_OK ||
                oid == OID_GEN_RCV_OK) {
                shouldModify = TRUE;
                InterlockedIncrement64(&g_IoctlHookCount);
            }
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        // 读取输入缓冲区失败，继续正常调用
        shouldModify = FALSE;
    }
    
    // 调用原始函数
    status = originalFunc(
        FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock,
        IoControlCode, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength
    );
    
    // 如果成功且需要修改
    if (NT_SUCCESS(status) && shouldModify && g_FakeEnabled && OutputBuffer != NULL) {
        __try {
            PHV_NET_ADAPTER_CONFIG config = FindMatchingConfig(0, 0);
            
            if (config != NULL && config->FakeMode != HvNetFakeModeNone) {
                if (oid == OID_GEN_STATISTICS && OutputBufferLength >= 0x40) {
                    PUCHAR pData = (PUCHAR)OutputBuffer;
                    PULONG64 pBytesRecv = (PULONG64)(pData + NDIS_STATS_OFFSET_BYTES_RECV);
                    PULONG64 pBytesSent = (PULONG64)(pData + NDIS_STATS_OFFSET_BYTES_SENT);
                    
                    ApplyFakeToStats(config, pBytesRecv, pBytesSent, NULL, NULL);
                    InterlockedIncrement64(&g_HvNetHookManager.FakeCount);
                }
                else if ((oid == OID_GEN_BYTES_XMIT || oid == OID_GEN_XMIT_OK) && 
                         OutputBufferLength >= sizeof(ULONG64)) {
                    PULONG64 pBytes = (PULONG64)OutputBuffer;
                    ApplyFakeToStats(config, NULL, pBytes, NULL, NULL);
                    InterlockedIncrement64(&g_HvNetHookManager.FakeCount);
                }
                else if ((oid == OID_GEN_BYTES_RCV || oid == OID_GEN_RCV_OK) && 
                         OutputBufferLength >= sizeof(ULONG64)) {
                    PULONG64 pBytes = (PULONG64)OutputBuffer;
                    ApplyFakeToStats(config, pBytes, NULL, NULL, NULL);
                    InterlockedIncrement64(&g_HvNetHookManager.FakeCount);
                }
            }
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            // 修改失败，忽略
        }
    }
    
    return status;
    HV_NET_CALLBACK_END()
}

// ============================================================
// Hook 函数
// ============================================================

/*
 * NsiGetParameter Hook 函数
 */
static NTSTATUS NTAPI
HookedNsiGetParameter(
    _In_ ULONG Reserved,
    _In_ PNPI_MODULEID ModuleId,
    _In_ ULONG ObjectIndex,
    _In_reads_bytes_(KeyStructLength) PVOID KeyStruct,
    _In_ ULONG KeyStructLength,
    _In_ NSI_PARAM_TYPE ParamType,
    _Out_writes_bytes_(DataLength) PVOID Data,
    _In_ ULONG DataLength,
    _In_ ULONG DataOffset
)
{
    HV_NET_CALLBACK_BEGIN(g_HvNetHookManager.NsiHookHandle)
    NTSTATUS status;
    
    // 增加计数
    InterlockedIncrement64(&g_HvNetHookManager.QueryCount);
    
    // 调用原始函数
    if (g_HvNetHookManager.OriginalNsiGetParameter == NULL) {
        return STATUS_UNSUCCESSFUL;
    }
    
    status = g_HvNetHookManager.OriginalNsiGetParameter(
        Reserved,
        ModuleId,
        ObjectIndex,
        KeyStruct,
        KeyStructLength,
        ParamType,
        Data,
        DataLength,
        DataOffset
    );
    
    // 如果成功且是 NDIS 统计查询，修改数据
    if (NT_SUCCESS(status) && g_FakeEnabled && Data != NULL && DataLength > 0) {
        BOOLEAN isStatsQuery = IsNdisInterfaceStatsQuery(ModuleId, ObjectIndex, ParamType);
        
        // 调试：打印是否识别为统计查询
        static LONG64 hookDebug = 0;
        if ((InterlockedIncrement64(&hookDebug) % 100) == 1) {
            DbgPrint("[HvNetHook] NsiGetParam: isStats=%d, DataLen=%lu, ParamType=%d\n",
                isStatsQuery, DataLength, ParamType);
        }
        
        if (isStatsQuery) {
            // 从 Key 中提取接口信息
            ULONG64 ifLuid = 0;
            ULONG ifIndex = 0;
            
            if (KeyStruct != NULL && KeyStructLength >= sizeof(HV_NET_LUID)) {
                ifLuid = ((PHV_NET_LUID)KeyStruct)->Value;
            }
            
            // 查找配置
            PHV_NET_ADAPTER_CONFIG config = FindMatchingConfig(ifLuid, ifIndex);
            
            if (config != NULL) {
                DbgPrint("[HvNetHook] Found config: Mode=%d, Applying fake data\n", config->FakeMode);
                if (config->FakeMode != HvNetFakeModeNone) {
                    ModifyDynamicParamData(Data, DataLength, config);
                }
            }
        }
    }
    
    return status;
    HV_NET_CALLBACK_END()
}

/*
 * NsiEnumerateObjectsAllParameters Hook 函数
 * 用于 GetIfTable2 等批量查询
 */
static NTSTATUS NTAPI
HookedNsiEnumerateObjectsAllParameters(
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
)
{
    HV_NET_CALLBACK_BEGIN(g_HvNetHookManager.NsiEnumHookHandle)
    NTSTATUS status;
    
    InterlockedIncrement64(&g_HvNetHookManager.EnumCount);
    
    if (g_HvNetHookManager.OriginalNsiEnumerate == NULL) {
        return STATUS_UNSUCCESSFUL;
    }
    
    status = g_HvNetHookManager.OriginalNsiEnumerate(
        Reserved,
        Reserved2,
        ModuleId,
        ObjectIndex,
        KeyStruct,
        KeyStructLength,
        RwParamStruct,
        RwParamStructLength,
        DynamicParamStruct,
        DynamicParamStructLength,
        StaticParamStruct,
        StaticParamStructLength,
        Count
    );
    
    // 如果成功且是 NDIS 查询，修改每个条目的动态数据
    if (NT_SUCCESS(status) && g_FakeEnabled && 
        DynamicParamStruct != NULL && Count != NULL && *Count > 0) {
        
        if (ModuleId != NULL && ModuleId->Type == MIT_GUID &&
            ModuleId->Guid.Data1 == NDIS_MODULE_ID_DATA1) {
            
            PUCHAR pDynamic = (PUCHAR)DynamicParamStruct;
            PUCHAR pKey = (PUCHAR)KeyStruct;
            
            for (ULONG i = 0; i < *Count; i++) {
                ULONG64 ifLuid = 0;
                if (pKey != NULL && KeyStructLength >= sizeof(HV_NET_LUID)) {
                    ifLuid = ((PHV_NET_LUID)(pKey + i * KeyStructLength))->Value;
                }
                
                PHV_NET_ADAPTER_CONFIG config = FindMatchingConfig(ifLuid, 0);
                
                if (config != NULL && config->FakeMode != HvNetFakeModeNone) {
                    ModifyDynamicParamData(
                        pDynamic + i * DynamicParamStructLength,
                        DynamicParamStructLength,
                        config
                    );
                }
            }
        }
    }
    
    return status;
    HV_NET_CALLBACK_END()
}

// ============================================================
// 公共接口实现
// ============================================================

NTSTATUS
HvNetHookInitialize(VOID)
{
    NTSTATUS status = STATUS_SUCCESS;
    PVOID netioBase = NULL;
    PVOID nsiGetParam = NULL;
    PVOID nsiEnum = NULL;
    
    if (g_HvNetHookManager.Initialized) {
        DbgPrint("[HvNetHook] Already initialized\n");
        return STATUS_SUCCESS;
    }
    
    DbgPrint("[HvNetHook] ========================================\n");
    DbgPrint("[HvNetHook] Initializing Network Hook Module v2.0\n");
    DbgPrint("[HvNetHook] ========================================\n");
    
    // 初始化管理器
    RtlZeroMemory(&g_HvNetHookManager, sizeof(g_HvNetHookManager));
    KeInitializeSpinLock(&g_HvNetHookManager.Lock);
    
    // 检测 Windows 版本并设置偏移
    DetectWindowsVersionAndSetOffsets();
    
    // 检查 HvHook 是否可用
    if (!HvHookIsInitialized()) {
        DbgPrint("[HvNetHook] HvHook not available\n");
        return STATUS_NOT_INITIALIZED;
    }
    
    // 方法1：尝试从 netio.sys 获取函数
    netioBase = GetKernelModuleBase("netio.sys");
    if (netioBase != NULL) {
        nsiGetParam = GetExportedFunctionAddress(netioBase, "NsiGetParameter");
        nsiEnum = GetExportedFunctionAddress(netioBase, "NsiEnumerateObjectsAllParameters");
    }
    
    // 方法2：如果 netio.sys 没找到，尝试 nsiproxy.sys
    if (nsiGetParam == NULL) {
        PVOID nsiproxyBase = GetKernelModuleBase("nsiproxy.sys");
        if (nsiproxyBase != NULL) {
            nsiGetParam = GetExportedFunctionAddress(nsiproxyBase, "NsiGetParameter");
        }
    }
    
    // 方法3：使用 MmGetSystemRoutineAddress
    if (nsiGetParam == NULL) {
        UNICODE_STRING funcName;
        RtlInitUnicodeString(&funcName, L"NsiGetParameter");
        nsiGetParam = MmGetSystemRoutineAddress(&funcName);
        if (nsiGetParam != NULL) {
            DbgPrint("[HvNetHook] Found NsiGetParameter via MmGetSystemRoutineAddress: %p\n", nsiGetParam);
        }
    }
    
    if (nsiEnum == NULL) {
        UNICODE_STRING funcName;
        RtlInitUnicodeString(&funcName, L"NsiEnumerateObjectsAllParameters");
        nsiEnum = MmGetSystemRoutineAddress(&funcName);
        if (nsiEnum != NULL) {
            DbgPrint("[HvNetHook] Found NsiEnumerateObjectsAllParameters via MmGetSystemRoutineAddress: %p\n", nsiEnum);
        }
    }
    
    // 安装 Hook
    if (nsiGetParam != NULL) {
        g_HvNetHookManager.NsiGetParameterAddress = nsiGetParam;
        
        status = HvHookInstall(
            nsiGetParam,
            (PVOID)HookedNsiGetParameter,
            &g_HvNetHookManager.NsiHookHandle
        );
        
        if (NT_SUCCESS(status)) {
            g_HvNetHookManager.OriginalNsiGetParameter = 
                (PFN_NsiGetParameter)HvHookGetTrampoline(g_HvNetHookManager.NsiHookHandle);
            if (g_HvNetHookManager.NsiHookHandle &&
                g_HvNetHookManager.OriginalNsiGetParameter) {
                g_HvNetHookManager.HookInstalled = TRUE;
                DbgPrint("[HvNetHook] NsiGetParameter hooked at %p\n", nsiGetParam);
            } else {
                if (g_HvNetHookManager.NsiHookHandle) {
                    NTSTATUS rollbackStatus =
                        HvHookRemove(g_HvNetHookManager.NsiHookHandle);
                    if (NT_SUCCESS(rollbackStatus)) {
                        g_HvNetHookManager.NsiHookHandle = NULL;
                    } else {
                        status = rollbackStatus;
                        DbgPrint("[HvNetHook] NsiGetParameter rollback retained handle: 0x%X\n",
                                 rollbackStatus);
                    }
                }
                if (!g_HvNetHookManager.NsiHookHandle) {
                    g_HvNetHookManager.OriginalNsiGetParameter = NULL;
                    status = STATUS_DEVICE_NOT_READY;
                }
                DbgPrint("[HvNetHook] NsiGetParameter hook has no valid trampoline\n");
            }
        } else {
            DbgPrint("[HvNetHook] Failed to hook NsiGetParameter: 0x%X\n", status);
        }
    } else {
        DbgPrint("[HvNetHook] NsiGetParameter not found\n");
    }
    
    // 安装枚举函数 Hook（可选）
    if (nsiEnum != NULL && g_HvNetHookManager.HookInstalled) {
        g_HvNetHookManager.NsiEnumerateAddress = nsiEnum;
        
        status = HvHookInstall(
            nsiEnum,
            (PVOID)HookedNsiEnumerateObjectsAllParameters,
            &g_HvNetHookManager.NsiEnumHookHandle
        );
        
        if (NT_SUCCESS(status)) {
            g_HvNetHookManager.OriginalNsiEnumerate = 
                (PFN_NsiEnumerateObjectsAllParameters)HvHookGetTrampoline(g_HvNetHookManager.NsiEnumHookHandle);
            if (g_HvNetHookManager.NsiEnumHookHandle &&
                g_HvNetHookManager.OriginalNsiEnumerate) {
                DbgPrint("[HvNetHook] NsiEnumerateObjectsAllParameters hooked at %p\n", nsiEnum);
            } else {
                if (g_HvNetHookManager.NsiEnumHookHandle) {
                    NTSTATUS rollbackStatus =
                        HvHookRemove(g_HvNetHookManager.NsiEnumHookHandle);
                    if (NT_SUCCESS(rollbackStatus)) {
                        g_HvNetHookManager.NsiEnumHookHandle = NULL;
                    } else {
                        status = rollbackStatus;
                        DbgPrint("[HvNetHook] NsiEnumerate rollback retained handle: 0x%X\n",
                                 rollbackStatus);
                    }
                }
                if (!g_HvNetHookManager.NsiEnumHookHandle) {
                    g_HvNetHookManager.OriginalNsiEnumerate = NULL;
                }
                DbgPrint("[HvNetHook] NsiEnumerate hook rejected: missing trampoline\n");
            }
        }
    }
    
    // ========================================
    // 安装 NtDeviceIoControlFile Hook（关键：用于拦截网络状态对话框）
    // 注意：这是一个非常频繁调用的函数，需要特别小心竞态条件
    // ========================================
    {
        UNICODE_STRING funcName;
        PVOID ntDeviceIoControlFile = NULL;
        
        RtlInitUnicodeString(&funcName, L"NtDeviceIoControlFile");
        ntDeviceIoControlFile = MmGetSystemRoutineAddress(&funcName);
        
        if (ntDeviceIoControlFile != NULL) {
            DbgPrint("[HvNetHook] Found NtDeviceIoControlFile at %p\n", ntDeviceIoControlFile);
            
            // NtDeviceIoControlFile Hook 目前禁用
            // Windows 网络状态对话框可能使用 IOCTL_NDIS_QUERY_GLOBAL_STATS
            // 但 Hook 这个函数有竞态条件风险
            DbgPrint("[HvNetHook] NtDeviceIoControlFile hook is DISABLED (race condition risk)\n");
        } else {
            DbgPrint("[HvNetHook] NtDeviceIoControlFile not found\n");
        }
    }
    
    if (!g_HvNetHookManager.HookInstalled) {
        if (g_HvNetHookManager.NsiHookHandle ||
            g_HvNetHookManager.NsiEnumHookHandle ||
            g_NtDeviceIoControlFileHookHandle) {
            g_HvNetHookManager.Initialized = TRUE;
            return NT_SUCCESS(status) ? STATUS_INVALID_DEVICE_STATE : status;
        }
        g_HvNetHookManager.Initialized = FALSE;
        return NT_SUCCESS(status) ? STATUS_PROCEDURE_NOT_FOUND : status;
    }

    g_HvNetHookManager.Initialized = TRUE;
    
    DbgPrint("[HvNetHook] ========================================\n");
    DbgPrint("[HvNetHook] Initialization complete\n");
    DbgPrint("[HvNetHook] Hook installed: %s\n", g_HvNetHookManager.HookInstalled ? "YES" : "NO");
    DbgPrint("[HvNetHook] NtDeviceIoControlFile: %p\n", g_OriginalNtDeviceIoControlFile);
    DbgPrint("[HvNetHook] ========================================\n");
    
    /* NsiEnumerateObjectsAllParameters is an optional extension.  Once the
     * primary NsiGetParameter hook and trampoline are published, an optional
     * install/rollback error must not make DriverEntry believe that no network
     * hook exists.  The manager retains any optional handle for cleanup and
     * reports the primary publication transaction as successful. */
    return STATUS_SUCCESS;
}

VOID
HvNetHookCleanup(VOID)
{
    NTSTATUS status;
    BOOLEAN removeFailed = FALSE;

    if (!g_HvNetHookManager.Initialized) {
        return;
    }
    
    DbgPrint("[HvNetHook] Cleaning up...\n");
    
    // 禁用伪造
    InterlockedExchange(&g_FakeEnabled, FALSE);
    
    // 移除 Hook
    // 首先禁用 IOCTL Hook 处理
    InterlockedExchange(&g_IoctlHookReady, 0);
    MemoryBarrier();
    
    if (g_NtDeviceIoControlFileHookHandle != NULL) {
        status = HvHookRemove(g_NtDeviceIoControlFileHookHandle);
        if (NT_SUCCESS(status)) {
            g_NtDeviceIoControlFileHookHandle = NULL;
            g_OriginalNtDeviceIoControlFile = NULL;
        } else {
            removeFailed = TRUE;
        }
    }
    
    if (g_HvNetHookManager.NsiHookHandle != NULL) {
        status = HvHookRemove(g_HvNetHookManager.NsiHookHandle);
        if (NT_SUCCESS(status)) {
            g_HvNetHookManager.NsiHookHandle = NULL;
            g_HvNetHookManager.OriginalNsiGetParameter = NULL;
        } else {
            removeFailed = TRUE;
        }
    }
    
    if (g_HvNetHookManager.NsiEnumHookHandle != NULL) {
        status = HvHookRemove(g_HvNetHookManager.NsiEnumHookHandle);
        if (NT_SUCCESS(status)) {
            g_HvNetHookManager.NsiEnumHookHandle = NULL;
            g_HvNetHookManager.OriginalNsiEnumerate = NULL;
        } else {
            removeFailed = TRUE;
        }
    }
    
    // 打印统计
    DbgPrint("[HvNetHook] Final Stats:\n");
    DbgPrint("[HvNetHook]   Queries: %lld\n", g_HvNetHookManager.QueryCount);
    DbgPrint("[HvNetHook]   Enumerations: %lld\n", g_HvNetHookManager.EnumCount);
    DbgPrint("[HvNetHook]   IOCTL hooks: %lld\n", g_IoctlHookCount);
    DbgPrint("[HvNetHook]   Fakes: %lld\n", g_HvNetHookManager.FakeCount);
    
    if (removeFailed) {
        DbgPrint("[HvNetHook] Cleanup incomplete: hooks remain installed\n");
        return;
    }

    g_HvNetHookManager.Initialized = FALSE;
    g_HvNetHookManager.HookInstalled = FALSE;
}

BOOLEAN
HvNetHookIsInitialized(VOID)
{
    return g_HvNetHookManager.Initialized;
}

// ============================================================
// 伪造配置接口
// ============================================================

NTSTATUS
HvNetSetFakeTrafficFixed(
    _In_ ULONG64 BytesSent,
    _In_ ULONG64 BytesReceived
)
{
    KIRQL oldIrql;
    
    if (!g_HvNetHookManager.Initialized) {
        return STATUS_UNSUCCESSFUL;
    }
    
    KeAcquireSpinLock(&g_HvNetHookManager.Lock, &oldIrql);
    
    g_HvNetHookManager.Configs[0].InUse = TRUE;
    g_HvNetHookManager.Configs[0].MatchAllAdapters = TRUE;
    g_HvNetHookManager.Configs[0].FakeMode = HvNetFakeModeFixed;
    g_HvNetHookManager.Configs[0].FakeBytesSent = BytesSent;
    g_HvNetHookManager.Configs[0].FakeBytesReceived = BytesReceived;
    g_HvNetHookManager.ConfigCount = 1;
    
    KeReleaseSpinLock(&g_HvNetHookManager.Lock, oldIrql);
    
    DbgPrint("[HvNetHook] Set fixed: Sent=%llu bytes, Received=%llu bytes\n",
        BytesSent, BytesReceived);
    
    return STATUS_SUCCESS;
}

NTSTATUS
HvNetSetFakeTrafficScale(
    _In_ ULONG ScalePercentSent,
    _In_ ULONG ScalePercentReceived
)
{
    KIRQL oldIrql;
    
    if (!g_HvNetHookManager.Initialized) {
        return STATUS_UNSUCCESSFUL;
    }
    
    // 允许超过 100% 以增大显示值
    if (ScalePercentSent > 1000 || ScalePercentReceived > 1000) {
        return STATUS_INVALID_PARAMETER;
    }
    
    KeAcquireSpinLock(&g_HvNetHookManager.Lock, &oldIrql);
    
    g_HvNetHookManager.Configs[0].InUse = TRUE;
    g_HvNetHookManager.Configs[0].MatchAllAdapters = TRUE;
    g_HvNetHookManager.Configs[0].FakeMode = HvNetFakeModeScale;
    g_HvNetHookManager.Configs[0].ScalePercentSent = ScalePercentSent;
    g_HvNetHookManager.Configs[0].ScalePercentReceived = ScalePercentReceived;
    g_HvNetHookManager.ConfigCount = 1;
    
    KeReleaseSpinLock(&g_HvNetHookManager.Lock, oldIrql);
    
    DbgPrint("[HvNetHook] Set scale: Sent=%u%%, Received=%u%%\n",
        ScalePercentSent, ScalePercentReceived);
    
    return STATUS_SUCCESS;
}

NTSTATUS
HvNetSetFakeTrafficSubtract(
    _In_ ULONG64 SubtractBytesSent,
    _In_ ULONG64 SubtractBytesReceived
)
{
    KIRQL oldIrql;
    
    if (!g_HvNetHookManager.Initialized) {
        return STATUS_UNSUCCESSFUL;
    }
    
    KeAcquireSpinLock(&g_HvNetHookManager.Lock, &oldIrql);
    
    g_HvNetHookManager.Configs[0].InUse = TRUE;
    g_HvNetHookManager.Configs[0].MatchAllAdapters = TRUE;
    g_HvNetHookManager.Configs[0].FakeMode = HvNetFakeModeSubtract;
    g_HvNetHookManager.Configs[0].SubtractBytesSent = SubtractBytesSent;
    g_HvNetHookManager.Configs[0].SubtractBytesReceived = SubtractBytesReceived;
    g_HvNetHookManager.ConfigCount = 1;
    
    KeReleaseSpinLock(&g_HvNetHookManager.Lock, oldIrql);
    
    DbgPrint("[HvNetHook] Set subtract: Sent=%llu, Received=%llu\n",
        SubtractBytesSent, SubtractBytesReceived);
    
    return STATUS_SUCCESS;
}

NTSTATUS
HvNetSetFakeSpeed(
    _In_ ULONG SendSpeedMbps,
    _In_ ULONG ReceiveSpeedMbps
)
{
    KIRQL oldIrql;
    
    if (!g_HvNetHookManager.Initialized) {
        return STATUS_UNSUCCESSFUL;
    }
    
    KeAcquireSpinLock(&g_HvNetHookManager.Lock, &oldIrql);
    
    if (!g_HvNetHookManager.Configs[0].InUse) {
        g_HvNetHookManager.Configs[0].InUse = TRUE;
        g_HvNetHookManager.Configs[0].MatchAllAdapters = TRUE;
        g_HvNetHookManager.Configs[0].FakeMode = HvNetFakeModeNone;
        g_HvNetHookManager.ConfigCount = 1;
    }
    
    g_HvNetHookManager.Configs[0].FakeSpeed = TRUE;
    g_HvNetHookManager.Configs[0].FakeSendSpeed = (ULONG64)SendSpeedMbps * 1000000ULL;
    g_HvNetHookManager.Configs[0].FakeReceiveSpeed = (ULONG64)ReceiveSpeedMbps * 1000000ULL;
    
    KeReleaseSpinLock(&g_HvNetHookManager.Lock, oldIrql);
    
    DbgPrint("[HvNetHook] Set speed: Send=%u Mbps, Receive=%u Mbps\n",
        SendSpeedMbps, ReceiveSpeedMbps);
    
    return STATUS_SUCCESS;
}

NTSTATUS
HvNetSetFakePackets(
    _In_ ULONG64 PacketsSent,
    _In_ ULONG64 PacketsReceived
)
{
    KIRQL oldIrql;
    
    if (!g_HvNetHookManager.Initialized) {
        return STATUS_UNSUCCESSFUL;
    }
    
    KeAcquireSpinLock(&g_HvNetHookManager.Lock, &oldIrql);
    
    if (!g_HvNetHookManager.Configs[0].InUse) {
        g_HvNetHookManager.Configs[0].InUse = TRUE;
        g_HvNetHookManager.Configs[0].MatchAllAdapters = TRUE;
        g_HvNetHookManager.ConfigCount = 1;
    }
    
    g_HvNetHookManager.Configs[0].FakePacketsSent = PacketsSent;
    g_HvNetHookManager.Configs[0].FakePacketsReceived = PacketsReceived;
    
    KeReleaseSpinLock(&g_HvNetHookManager.Lock, oldIrql);
    
    DbgPrint("[HvNetHook] Set packets: Sent=%llu, Received=%llu\n",
        PacketsSent, PacketsReceived);
    
    return STATUS_SUCCESS;
}

VOID
HvNetAddHiddenTraffic(
    _In_ ULONG64 BytesSent,
    _In_ ULONG64 BytesReceived
)
{
    InterlockedExchangeAdd64(&g_AccumulatedHiddenBytesSent, (LONG64)BytesSent);
    InterlockedExchangeAdd64(&g_AccumulatedHiddenBytesReceived, (LONG64)BytesReceived);
}

VOID
HvNetResetHiddenTraffic(VOID)
{
    InterlockedExchange64(&g_AccumulatedHiddenBytesSent, 0);
    InterlockedExchange64(&g_AccumulatedHiddenBytesReceived, 0);
    DbgPrint("[HvNetHook] Hidden traffic counters reset\n");
}

VOID
HvNetDisableFake(VOID)
{
    InterlockedExchange(&g_FakeEnabled, FALSE);
    DbgPrint("[HvNetHook] Fake DISABLED\n");
}

VOID
HvNetEnableFake(VOID)
{
    InterlockedExchange(&g_FakeEnabled, TRUE);
    DbgPrint("[HvNetHook] Fake ENABLED\n");
}

// ============================================================
// 高级配置接口
// ============================================================

NTSTATUS
HvNetSetAdapterConfig(
    _In_ ULONG InterfaceIndex,
    _In_ PHV_NET_ADAPTER_CONFIG Config
)
{
    KIRQL oldIrql;
    ULONG freeSlot = (ULONG)-1;
    
    if (!g_HvNetHookManager.Initialized || Config == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    
    KeAcquireSpinLock(&g_HvNetHookManager.Lock, &oldIrql);
    
    for (ULONG i = 0; i < MAX_HIDDEN_ADAPTERS; i++) {
        if (g_HvNetHookManager.Configs[i].InUse) {
            if (g_HvNetHookManager.Configs[i].InterfaceIndex == InterfaceIndex ||
                (InterfaceIndex == 0 && g_HvNetHookManager.Configs[i].MatchAllAdapters)) {
                RtlCopyMemory(&g_HvNetHookManager.Configs[i], Config, sizeof(HV_NET_ADAPTER_CONFIG));
                g_HvNetHookManager.Configs[i].InUse = TRUE;
                g_HvNetHookManager.Configs[i].InterfaceIndex = InterfaceIndex;
                g_HvNetHookManager.Configs[i].MatchAllAdapters = (InterfaceIndex == 0);
                KeReleaseSpinLock(&g_HvNetHookManager.Lock, oldIrql);
                return STATUS_SUCCESS;
            }
        } else if (freeSlot == (ULONG)-1) {
            freeSlot = i;
        }
    }
    
    if (freeSlot != (ULONG)-1) {
        RtlCopyMemory(&g_HvNetHookManager.Configs[freeSlot], Config, sizeof(HV_NET_ADAPTER_CONFIG));
        g_HvNetHookManager.Configs[freeSlot].InUse = TRUE;
        g_HvNetHookManager.Configs[freeSlot].InterfaceIndex = InterfaceIndex;
        g_HvNetHookManager.Configs[freeSlot].MatchAllAdapters = (InterfaceIndex == 0);
        g_HvNetHookManager.ConfigCount++;
        KeReleaseSpinLock(&g_HvNetHookManager.Lock, oldIrql);
        return STATUS_SUCCESS;
    }
    
    KeReleaseSpinLock(&g_HvNetHookManager.Lock, oldIrql);
    return STATUS_INSUFFICIENT_RESOURCES;
}

NTSTATUS
HvNetGetAdapterConfig(
    _In_ ULONG InterfaceIndex,
    _Out_ PHV_NET_ADAPTER_CONFIG Config
)
{
    KIRQL oldIrql;
    NTSTATUS status = STATUS_NOT_FOUND;
    
    if (!g_HvNetHookManager.Initialized || Config == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    
    KeAcquireSpinLock(&g_HvNetHookManager.Lock, &oldIrql);
    
    for (ULONG i = 0; i < MAX_HIDDEN_ADAPTERS; i++) {
        if (g_HvNetHookManager.Configs[i].InUse) {
            if (g_HvNetHookManager.Configs[i].InterfaceIndex == InterfaceIndex ||
                (InterfaceIndex == 0 && g_HvNetHookManager.Configs[i].MatchAllAdapters)) {
                RtlCopyMemory(Config, &g_HvNetHookManager.Configs[i], sizeof(HV_NET_ADAPTER_CONFIG));
                status = STATUS_SUCCESS;
                break;
            }
        }
    }
    
    KeReleaseSpinLock(&g_HvNetHookManager.Lock, oldIrql);
    return status;
}

NTSTATUS
HvNetRemoveAdapterConfig(
    _In_ ULONG InterfaceIndex
)
{
    KIRQL oldIrql;
    NTSTATUS status = STATUS_NOT_FOUND;
    
    if (!g_HvNetHookManager.Initialized) {
        return STATUS_UNSUCCESSFUL;
    }
    
    KeAcquireSpinLock(&g_HvNetHookManager.Lock, &oldIrql);
    
    for (ULONG i = 0; i < MAX_HIDDEN_ADAPTERS; i++) {
        if (g_HvNetHookManager.Configs[i].InUse) {
            if (g_HvNetHookManager.Configs[i].InterfaceIndex == InterfaceIndex ||
                (InterfaceIndex == 0 && g_HvNetHookManager.Configs[i].MatchAllAdapters)) {
                RtlZeroMemory(&g_HvNetHookManager.Configs[i], sizeof(HV_NET_ADAPTER_CONFIG));
                g_HvNetHookManager.ConfigCount--;
                status = STATUS_SUCCESS;
                break;
            }
        }
    }
    
    KeReleaseSpinLock(&g_HvNetHookManager.Lock, oldIrql);
    return status;
}

// ============================================================
// 调试接口
// ============================================================

VOID
HvNetPrintInfo(VOID)
{
    DbgPrint("[HvNetHook] ========== Network Hook Info ==========\n");
    DbgPrint("[HvNetHook] Version: 2.0\n");
    DbgPrint("[HvNetHook] Initialized: %s\n", g_HvNetHookManager.Initialized ? "Yes" : "No");
    DbgPrint("[HvNetHook] Hook Installed: %s\n", g_HvNetHookManager.HookInstalled ? "Yes" : "No");
    DbgPrint("[HvNetHook] Fake Enabled: %s\n", g_FakeEnabled ? "Yes" : "No");
    DbgPrint("[HvNetHook] Windows: %lu.%lu.%lu\n",
        g_HvNetHookManager.OsVersion.dwMajorVersion,
        g_HvNetHookManager.OsVersion.dwMinorVersion,
        g_HvNetHookManager.OsVersion.dwBuildNumber);
    DbgPrint("[HvNetHook] NsiGetParameter: %p\n", g_HvNetHookManager.NsiGetParameterAddress);
    DbgPrint("[HvNetHook] NsiEnumerate: %p\n", g_HvNetHookManager.NsiEnumerateAddress);
    DbgPrint("[HvNetHook] NtDeviceIoControlFile: %p\n", g_OriginalNtDeviceIoControlFile);
    DbgPrint("[HvNetHook] Config Count: %lu\n", g_HvNetHookManager.ConfigCount);
    DbgPrint("[HvNetHook] Statistics:\n");
    DbgPrint("[HvNetHook]   NSI Queries: %lld\n", g_HvNetHookManager.QueryCount);
    DbgPrint("[HvNetHook]   NSI Enumerations: %lld\n", g_HvNetHookManager.EnumCount);
    DbgPrint("[HvNetHook]   IOCTL Hooks: %lld\n", g_IoctlHookCount);
    DbgPrint("[HvNetHook]   Fakes Applied: %lld\n", g_HvNetHookManager.FakeCount);
    DbgPrint("[HvNetHook]   Hidden Sent: %lld bytes\n", g_AccumulatedHiddenBytesSent);
    DbgPrint("[HvNetHook]   Hidden Recv: %lld bytes\n", g_AccumulatedHiddenBytesReceived);
    
    for (ULONG i = 0; i < MAX_HIDDEN_ADAPTERS; i++) {
        if (g_HvNetHookManager.Configs[i].InUse) {
            DbgPrint("[HvNetHook] Config[%lu]:\n", i);
            DbgPrint("[HvNetHook]   IfIndex: %lu, MatchAll: %s\n",
                g_HvNetHookManager.Configs[i].InterfaceIndex,
                g_HvNetHookManager.Configs[i].MatchAllAdapters ? "Yes" : "No");
            DbgPrint("[HvNetHook]   Mode: %d\n", g_HvNetHookManager.Configs[i].FakeMode);
            
            switch (g_HvNetHookManager.Configs[i].FakeMode) {
                case HvNetFakeModeFixed:
                    DbgPrint("[HvNetHook]   Fixed: Sent=%llu, Recv=%llu\n",
                        g_HvNetHookManager.Configs[i].FakeBytesSent,
                        g_HvNetHookManager.Configs[i].FakeBytesReceived);
                    break;
                case HvNetFakeModeScale:
                    DbgPrint("[HvNetHook]   Scale: Sent=%u%%, Recv=%u%%\n",
                        g_HvNetHookManager.Configs[i].ScalePercentSent,
                        g_HvNetHookManager.Configs[i].ScalePercentReceived);
                    break;
                case HvNetFakeModeSubtract:
                    DbgPrint("[HvNetHook]   Subtract: Sent=%llu, Recv=%llu\n",
                        g_HvNetHookManager.Configs[i].SubtractBytesSent,
                        g_HvNetHookManager.Configs[i].SubtractBytesReceived);
                    break;
                default:
                    break;
            }
        }
    }
    
    DbgPrint("[HvNetHook] ===========================================\n");
}

VOID
HvNetGetStats(
    _Out_opt_ PULONG64 QueryCount,
    _Out_opt_ PULONG64 FakeCount
)
{
    if (QueryCount) *QueryCount = g_HvNetHookManager.QueryCount;
    if (FakeCount) *FakeCount = g_HvNetHookManager.FakeCount;
}
