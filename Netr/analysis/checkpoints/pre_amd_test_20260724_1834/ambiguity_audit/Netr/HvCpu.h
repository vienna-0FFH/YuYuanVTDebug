/*
 * HvCpu.h - CPU 检测和厂商识别
 * 
 * 提供统一的CPU厂商检测接口，支持Intel和AMD处理器
 */

#ifndef _HV_CPU_H_
#define _HV_CPU_H_

#include <ntddk.h>
#include <intrin.h>

// ==================== CPU 厂商枚举 ====================

typedef enum _CPU_VENDOR {
    CPU_VENDOR_UNKNOWN = 0,
    CPU_VENDOR_INTEL,      // GenuineIntel
    CPU_VENDOR_AMD         // AuthenticAMD
} CPU_VENDOR;

// ==================== 全局变量声明 ====================

extern CPU_VENDOR g_CpuVendor;

// ==================== 函数声明 ====================

/*
 * 检测CPU厂商
 * 
 * 返回: CPU_VENDOR_INTEL, CPU_VENDOR_AMD, 或 CPU_VENDOR_UNKNOWN
 */
CPU_VENDOR HvDetectCpuVendor(VOID);

/*
 * 获取当前CPU厂商（使用缓存的值）
 */
CPU_VENDOR HvGetCpuVendor(VOID);

/*
 * 检查虚拟化支持（统一接口）
 * 
 * 根据CPU厂商自动检查VMX或SVM支持
 * 
 * 返回: TRUE = 支持虚拟化, FALSE = 不支持
 */
BOOLEAN HvCheckVirtualizationSupport(VOID);

/*
 * 检查是否为Intel CPU
 */
BOOLEAN HvIsIntelCpu(VOID);

/*
 * 检查是否为AMD CPU
 */
BOOLEAN HvIsAmdCpu(VOID);

/*
 * 打印CPU信息（用于调试）
 */
VOID HvPrintCpuInfo(VOID);

/*
 * AMD SVM: 查询 CPUID 80000008H.EBX[7:0] 报告的 NumberOfAsids
 * 返回硬件支持的最大 ASID (典型值 64..32768)；不可用时返回 0
 */
ULONG HvSvmGetMaxAsid(VOID);

/*
 * AMD SVM: 查询 CPUID 80000001H.EDX[26] (1GB Page) 支持
 */
BOOLEAN HvSvmSupports1GBPages(VOID);

#endif // _HV_CPU_H_
