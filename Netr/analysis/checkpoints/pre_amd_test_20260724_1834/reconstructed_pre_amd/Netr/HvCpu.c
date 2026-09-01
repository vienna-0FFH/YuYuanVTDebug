/*
 * HvCpu.c - CPU 检测和厂商识别实现
 */

#include "HvCpu.h"
#include "HvCompat.h"

// ==================== 全局变量 ====================

CPU_VENDOR g_CpuVendor = CPU_VENDOR_UNKNOWN;

// ==================== 内部常量 ====================

// Intel CPU Vendor String: "GenuineIntel"
static const char INTEL_VENDOR_STRING[] = "GenuineIntel";

// AMD CPU Vendor String: "AuthenticAMD"
static const char AMD_VENDOR_STRING[] = "AuthenticAMD";

// ==================== 函数实现 ====================

/*
 * 检测CPU厂商
 */
CPU_VENDOR HvDetectCpuVendor(VOID)
{
    int cpuInfo[4] = { 0 };
    char vendorString[13] = { 0 };

    // CPUID leaf 0: 获取厂商字符串
    __cpuid(cpuInfo, 0);

    // 厂商字符串存储在 EBX, EDX, ECX 中（注意顺序）
    *(int*)&vendorString[0] = cpuInfo[1];  // EBX
    *(int*)&vendorString[4] = cpuInfo[3];  // EDX
    *(int*)&vendorString[8] = cpuInfo[2];  // ECX
    vendorString[12] = '\0';

    // 比较厂商字符串
    if (RtlCompareMemory(vendorString, INTEL_VENDOR_STRING, 12) == 12) {
        g_CpuVendor = CPU_VENDOR_INTEL;
        DbgPrint("[HV-CPU] Detected Intel CPU: %s\n", vendorString);
    }
    else if (RtlCompareMemory(vendorString, AMD_VENDOR_STRING, 12) == 12) {
        g_CpuVendor = CPU_VENDOR_AMD;
        DbgPrint("[HV-CPU] Detected AMD CPU: %s\n", vendorString);
    }
    else {
        g_CpuVendor = CPU_VENDOR_UNKNOWN;
        DbgPrint("[HV-CPU] Unknown CPU vendor: %s\n", vendorString);
    }

    return g_CpuVendor;
}

/*
 * 获取当前CPU厂商
 */
CPU_VENDOR HvGetCpuVendor(VOID)
{
    if (g_CpuVendor == CPU_VENDOR_UNKNOWN) {
        HvDetectCpuVendor();
    }
    return g_CpuVendor;
}

/*
 * 检查是否为Intel CPU
 */
BOOLEAN HvIsIntelCpu(VOID)
{
    return HvGetCpuVendor() == CPU_VENDOR_INTEL;
}

/*
 * 检查是否为AMD CPU
 */
BOOLEAN HvIsAmdCpu(VOID)
{
    return HvGetCpuVendor() == CPU_VENDOR_AMD;
}

/*
 * 检查虚拟化支持（统一接口）
 * 
 * Intel: 检查 CPUID.01H.ECX[5] (VMX)
 * AMD:   检查 CPUID.80000001H.ECX[2] (SVM)
 */
BOOLEAN HvCheckVirtualizationSupport(VOID)
{
    int cpuInfo[4] = { 0 };
    CPU_VENDOR vendor = HvGetCpuVendor();

    // 先检查是否已有 hypervisor 在运行 (CPUID.01H.ECX[31] = hypervisor present)
    // 如果有 (VBS / Hyper-V / 360Hvm 等), VMXON 必定失败或卡死
    // 注意: 用 0x80000000U 而非 (1 << 31) — 后者在 signed int 上是 UB
    __cpuid(cpuInfo, 1);
    DbgPrint("[HV-CPU] CPUID.01H ECX = 0x%08X (bit31=%d, bit5=%d)\n",
             (ULONG)cpuInfo[2],
             (cpuInfo[2] & 0x80000000U) ? 1 : 0,
             (cpuInfo[2] & (1U << 5)) ? 1 : 0);
    if ((ULONG)cpuInfo[2] & 0x80000000U) {
#if HV_FORCE_VMX_REGARDLESS_OF_HVPRESENT
        DbgPrint("[HV-CPU] *** HV_FORCE_VMX=1 *** Hypervisor Present detected,\n");
        DbgPrint("[HV-CPU]     but forcing VMXON anyway. BSOD risk if VBS truly active!\n");
        // 不 return, 继续走 VMXON 验证是固件谎报还是真有 hypervisor
#else
        DbgPrint("[HV-CPU] Another hypervisor is already running. Skipping VMX init.\n");
        return FALSE;
#endif
    }

    if (vendor == CPU_VENDOR_INTEL) {
        // Intel VMX 检查 (ECX[5])
        if (!(cpuInfo[2] & (1U << 5))) {
#if HV_FORCE_VMX_REGARDLESS_OF_HVPRESENT
            DbgPrint("[HV-CPU] *** HV_FORCE_VMX=1 *** VMX bit5 hidden by hypervisor,\n");
            DbgPrint("[HV-CPU]     forcing VMX support assumption. If MSR_IA32_FEATURE_CONTROL\n");
            DbgPrint("[HV-CPU]     is also locked without VMXON_OUTSIDE_SMX, VMXON will fail.\n");
            return TRUE;
#else
            DbgPrint("[HV-CPU] Intel VMX not supported (CPUID.01H.ECX[5] = 0)\n");
            return FALSE;
#endif
        }
        DbgPrint("[HV-CPU] Intel VMX supported\n");
        return TRUE;
    }
    else if (vendor == CPU_VENDOR_AMD) {
        // AMD SVM 检查
        // 首先检查是否支持扩展CPUID
        __cpuid(cpuInfo, 0x80000000);
        if ((ULONG)cpuInfo[0] < 0x80000001) {
            DbgPrint("[HV-CPU] AMD extended CPUID not supported\n");
            return FALSE;
        }

        // 检查 SVM 位
        __cpuid(cpuInfo, 0x80000001);
        if (!(cpuInfo[2] & (1 << 2))) {
#if HV_FORCE_VMX_REGARDLESS_OF_HVPRESENT
            DbgPrint("[HV-CPU] *** HV_FORCE_VMX=1 *** SVM bit hidden by hypervisor,\n");
            DbgPrint("[HV-CPU]     forcing SVM support assumption. VMRUN may fail.\n");
            return TRUE;
#else
            DbgPrint("[HV-CPU] AMD SVM not supported (CPUID.80000001H.ECX[2] = 0)\n");
            return FALSE;
#endif
        }
        DbgPrint("[HV-CPU] AMD SVM supported\n");
        return TRUE;
    }

    DbgPrint("[HV-CPU] Unknown CPU vendor, virtualization not supported\n");
    return FALSE;
}

/*
 * 打印CPU信息
 */
VOID HvPrintCpuInfo(VOID)
{
    int cpuInfo[4] = { 0 };
    char vendorString[13] = { 0 };
    char brandString[49] = { 0 };
    ULONG family, model, stepping;

    // 获取厂商字符串
    __cpuid(cpuInfo, 0);
    *(int*)&vendorString[0] = cpuInfo[1];
    *(int*)&vendorString[4] = cpuInfo[3];
    *(int*)&vendorString[8] = cpuInfo[2];

    // 获取处理器签名
    __cpuid(cpuInfo, 1);
    stepping = cpuInfo[0] & 0xF;
    model = (cpuInfo[0] >> 4) & 0xF;
    family = (cpuInfo[0] >> 8) & 0xF;

    // 扩展模型和家族
    if (family == 0xF) {
        family += (cpuInfo[0] >> 20) & 0xFF;
    }
    if (family == 0x6 || family == 0xF) {
        model += ((cpuInfo[0] >> 16) & 0xF) << 4;
    }

    // 尝试获取品牌字符串
    __cpuid(cpuInfo, 0x80000000);
    if ((ULONG)cpuInfo[0] >= 0x80000004) {
        __cpuid((int*)&brandString[0], 0x80000002);
        __cpuid((int*)&brandString[16], 0x80000003);
        __cpuid((int*)&brandString[32], 0x80000004);
    }

    DbgPrint("[HV-CPU] ========== CPU Information ==========\n");
    DbgPrint("[HV-CPU] Vendor: %s\n", vendorString);
    DbgPrint("[HV-CPU] Brand:  %s\n", brandString[0] ? brandString : "N/A");
    DbgPrint("[HV-CPU] Family: 0x%X, Model: 0x%X, Stepping: 0x%X\n", 
             family, model, stepping);
    DbgPrint("[HV-CPU] Processor Count: %d\n", KeQueryActiveProcessorCount(NULL));

    // 打印虚拟化能力
    __cpuid(cpuInfo, 1);
    DbgPrint("[HV-CPU] Features ECX: 0x%08X\n", cpuInfo[2]);
    
    if (g_CpuVendor == CPU_VENDOR_INTEL) {
        DbgPrint("[HV-CPU] VMX: %s\n", (cpuInfo[2] & (1 << 5)) ? "Yes" : "No");
    }
    else if (g_CpuVendor == CPU_VENDOR_AMD) {
        __cpuid(cpuInfo, 0x80000001);
        DbgPrint("[HV-CPU] SVM: %s\n", (cpuInfo[2] & (1 << 2)) ? "Yes" : "No");
    }

    DbgPrint("[HV-CPU] ==========================================\n");
}

/*
 * AMD SVM: CPUID 80000008H.EBX[31:0] = NumberOfAsids
 * 真实硬件典型值: Zen1/2/3 = 32768, Bulldozer/Piledriver = 64
 */
ULONG HvSvmGetMaxAsid(VOID)
{
    int cpuInfo[4] = { 0 };

    if (g_CpuVendor != CPU_VENDOR_AMD) {
        return 0;
    }

    __cpuid(cpuInfo, 0x80000000);
    if ((ULONG)cpuInfo[0] < 0x80000008) {
        return 0;
    }

    __cpuid(cpuInfo, 0x80000008);
    return (ULONG)cpuInfo[1];  // EBX = NumberOfAsids
}

/*
 * AMD/Intel: CPUID 80000001H.EDX[26] = PdpePages (1GB pages)
 * Intel 同位含义相同; 标志位在 AMD/Intel 上语义一致 (Page1GB)
 */
BOOLEAN HvSvmSupports1GBPages(VOID)
{
    int cpuInfo[4] = { 0 };

    __cpuid(cpuInfo, 0x80000000);
    if ((ULONG)cpuInfo[0] < 0x80000001) {
        return FALSE;
    }

    __cpuid(cpuInfo, 0x80000001);
    return (cpuInfo[3] & (1 << 26)) != 0;
}
