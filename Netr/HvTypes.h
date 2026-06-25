/*
 * HvTypes.h - Hypervisor 公共类型定义和常量
 */

#ifndef _HV_TYPES_H_
#define _HV_TYPES_H_

#include <ntddk.h>
#include <intrin.h>
#include <wdm.h>

#pragma warning(disable:4201) // 无名结构

// ==================== 系统函数声明 ====================

#ifndef STATUS_NOT_INITIALIZED
#define STATUS_NOT_INITIALIZED ((NTSTATUS)0xC000000BL)
#endif

NTKERNELAPI NTSTATUS PsLookupProcessByProcessId(
    _In_ HANDLE ProcessId,
    _Outptr_ PEPROCESS *Process
);

NTKERNELAPI HANDLE PsGetProcessId(
    _In_ PEPROCESS Process
);

NTKERNELAPI PEPROCESS PsInitialSystemProcess;

#ifdef __cplusplus
extern "C" {
#endif

// 段寄存器读取
unsigned short __readcs(void);
unsigned short __readss(void);
unsigned short __readds(void);
unsigned short __reades(void);
unsigned short __readfs(void);
unsigned short __readgs(void);
unsigned short __readldtr(void);
unsigned short __readtr(void);

// 标志寄存器和调试寄存器
unsigned __int64 __readeflags(void);
unsigned __int64 __readdr(unsigned int);
void __writedr(unsigned int, unsigned __int64);

// 返回地址函数
void* _ReturnAddress(void);
void* _AddressOfReturnAddress(void);

// 控制寄存器读写
unsigned __int64 __readcr0(void);
unsigned __int64 __readcr2(void);
unsigned __int64 __readcr3(void);
unsigned __int64 __readcr4(void);
unsigned __int64 __readcr8(void);
void __writecr0(unsigned __int64);
void __writecr3(unsigned __int64);
void __writecr4(unsigned __int64);
void __writecr8(unsigned __int64);

#ifdef __cplusplus
}
#endif

#pragma intrinsic(__readeflags)
#pragma intrinsic(__readdr)
#pragma intrinsic(__writedr)
#pragma intrinsic(_ReturnAddress)
#pragma intrinsic(_AddressOfReturnAddress)
#pragma intrinsic(__readcr0)
#pragma intrinsic(__readcr2)
#pragma intrinsic(__readcr3)
#pragma intrinsic(__readcr4)
#pragma intrinsic(__readcr8)
#pragma intrinsic(__writecr0)
#pragma intrinsic(__writecr3)
#pragma intrinsic(__writecr4)
#pragma intrinsic(__writecr8)

// ==================== 调试宏 ====================

#define HV_LOG_LEVEL_ERROR   0
#define HV_LOG_LEVEL_WARNING 1
#define HV_LOG_LEVEL_INFO    2
#define HV_LOG_LEVEL_DEBUG   3

#ifndef HV_LOG_LEVEL
#define HV_LOG_LEVEL HV_LOG_LEVEL_INFO
#endif

#define HV_LOG_ERROR(fmt, ...)   DbgPrint("[HV-ERROR] " fmt, ##__VA_ARGS__)
#define HV_LOG_WARNING(fmt, ...) do { if (HV_LOG_LEVEL >= HV_LOG_LEVEL_WARNING) DbgPrint("[HV-WARN] " fmt, ##__VA_ARGS__); } while(0)
#define HV_LOG_INFO(fmt, ...)    do { if (HV_LOG_LEVEL >= HV_LOG_LEVEL_INFO) DbgPrint("[HV-INFO] " fmt, ##__VA_ARGS__); } while(0)
#define HV_LOG_DEBUG(fmt, ...)   do { if (HV_LOG_LEVEL >= HV_LOG_LEVEL_DEBUG) DbgPrint("[HV-DEBUG] " fmt, ##__VA_ARGS__); } while(0)

// ==================== VMX 常量 ====================

#define VMX_OK              0
#define VMX_ERROR_WITH_STATUS  1
#define VMX_ERROR_WITHOUT_STATUS 2

// CPUID叶子
#define CPUID_VENDOR_STRING     0x00000000
#define CPUID_FEATURE_INFO      0x00000001
#define CPUID_VMX_FEATURES      0x00000001

// ==================== MSR 定义 ====================

#define MSR_IA32_FEATURE_CONTROL            0x0000003A
#define FEATURE_CONTROL_LOCK                (1U << 0)
#define FEATURE_CONTROL_VMXON_INSIDE_SMX    (1U << 1)
#define FEATURE_CONTROL_VMXON_OUTSIDE_SMX   (1U << 2)
#define MSR_IA32_SYSENTER_CS                0x00000174
#define MSR_IA32_SYSENTER_ESP               0x00000175
#define MSR_IA32_SYSENTER_EIP               0x00000176
#define MSR_IA32_DEBUGCTL                   0x000001D9
#define MSR_IA32_PAT                        0x00000277
#define MSR_IA32_EFER                       0xC0000080
#define MSR_IA32_FS_BASE                    0xC0000100
#define MSR_IA32_GS_BASE                    0xC0000101
#define MSR_IA32_VMX_BASIC                  0x00000480
#define MSR_IA32_VMX_PINBASED_CTLS          0x00000481
#define MSR_IA32_VMX_PROCBASED_CTLS         0x00000482
#define MSR_IA32_VMX_EXIT_CTLS              0x00000483
#define MSR_IA32_VMX_ENTRY_CTLS             0x00000484
#define MSR_IA32_VMX_MISC                   0x00000485
#define MSR_IA32_VMX_CR0_FIXED0             0x00000486
#define MSR_IA32_VMX_CR0_FIXED1             0x00000487
#define MSR_IA32_VMX_CR4_FIXED0             0x00000488
#define MSR_IA32_VMX_CR4_FIXED1             0x00000489
#define MSR_IA32_VMX_VMCS_ENUM              0x0000048A
#define MSR_IA32_VMX_PROCBASED_CTLS2        0x0000048B
#define MSR_IA32_VMX_EPT_VPID_CAP           0x0000048C
#define MSR_IA32_VMX_TRUE_PINBASED_CTLS     0x0000048D
#define MSR_IA32_VMX_TRUE_PROCBASED_CTLS    0x0000048E
#define MSR_IA32_VMX_TRUE_EXIT_CTLS         0x0000048F
#define MSR_IA32_VMX_TRUE_ENTRY_CTLS        0x00000490

// EFER位
#define EFER_SCE    (1 << 0)
#define EFER_LME    (1 << 8)
#define EFER_LMA    (1 << 10)
#define EFER_NXE    (1 << 11)
#define EFER_SVME   (1ULL << 12)  // AMD SVM Enable

// ==================== AMD SVM MSR 定义 ====================

#define MSR_AMD_VM_CR                   0xC0010114
#define MSR_AMD_IGNNE                   0xC0010115
#define MSR_AMD_SMM_CTL                 0xC0010116
#define MSR_AMD_VM_HSAVE_PA             0xC0010117

// VM_CR 位定义
#define VM_CR_DPD                       (1ULL << 0)   // Debug Port Disable
#define VM_CR_R_INIT                    (1ULL << 1)   // Intercept INIT
#define VM_CR_DIS_A20M                  (1ULL << 2)   // Disable A20 Masking
#define VM_CR_LOCK                      (1ULL << 3)   // Lock
#define VM_CR_SVMDIS                    (1ULL << 4)   // SVM Disable

// ==================== AMD SVM #VMEXIT 原因码 ====================

// CR 读取 (0x00 - 0x0F)
#define SVM_EXIT_READ_CR0               0x0000
#define SVM_EXIT_READ_CR2               0x0002
#define SVM_EXIT_READ_CR3               0x0003
#define SVM_EXIT_READ_CR4               0x0004
#define SVM_EXIT_READ_CR8               0x0008

// CR 写入 (0x10 - 0x1F)
#define SVM_EXIT_WRITE_CR0              0x0010
#define SVM_EXIT_WRITE_CR2              0x0012
#define SVM_EXIT_WRITE_CR3              0x0013
#define SVM_EXIT_WRITE_CR4              0x0014
#define SVM_EXIT_WRITE_CR8              0x0018

// DR 读取 (0x20 - 0x2F)
#define SVM_EXIT_READ_DR0               0x0020
#define SVM_EXIT_READ_DR7               0x0027

// DR 写入 (0x30 - 0x3F)
#define SVM_EXIT_WRITE_DR0              0x0030
#define SVM_EXIT_WRITE_DR7              0x0037

// 异常 (0x40 - 0x5F)
#define SVM_EXIT_EXCEPTION_DE           0x0040  // Divide Error
#define SVM_EXIT_EXCEPTION_DB           0x0041  // Debug
#define SVM_EXIT_EXCEPTION_NMI          0x0042  // NMI
#define SVM_EXIT_EXCEPTION_BP           0x0043  // Breakpoint
#define SVM_EXIT_EXCEPTION_OF           0x0044  // Overflow
#define SVM_EXIT_EXCEPTION_BR           0x0045  // Bound Range
#define SVM_EXIT_EXCEPTION_UD           0x0046  // Invalid Opcode
#define SVM_EXIT_EXCEPTION_NM           0x0047  // Device Not Available
#define SVM_EXIT_EXCEPTION_DF           0x0048  // Double Fault
#define SVM_EXIT_EXCEPTION_TS           0x004A  // Invalid TSS
#define SVM_EXIT_EXCEPTION_NP           0x004B  // Segment Not Present
#define SVM_EXIT_EXCEPTION_SS           0x004C  // Stack Fault
#define SVM_EXIT_EXCEPTION_GP           0x004D  // General Protection
#define SVM_EXIT_EXCEPTION_PF           0x004E  // Page Fault
#define SVM_EXIT_EXCEPTION_MF           0x0050  // x87 FP Exception
#define SVM_EXIT_EXCEPTION_AC           0x0051  // Alignment Check
#define SVM_EXIT_EXCEPTION_MC           0x0052  // Machine Check
#define SVM_EXIT_EXCEPTION_XF           0x0053  // SIMD FP Exception

// 杂项退出
#define SVM_EXIT_INTR                   0x0060  // Physical Interrupt
#define SVM_EXIT_NMI                    0x0061  // Physical NMI
#define SVM_EXIT_SMI                    0x0062  // Physical SMI
#define SVM_EXIT_INIT                   0x0063  // Physical INIT
#define SVM_EXIT_VINTR                  0x0064  // Virtual Interrupt
#define SVM_EXIT_CR0_SEL_WRITE          0x0065  // CR0 Selective Write
#define SVM_EXIT_IDTR_READ              0x0066
#define SVM_EXIT_GDTR_READ              0x0067
#define SVM_EXIT_LDTR_READ              0x0068
#define SVM_EXIT_TR_READ                0x0069
#define SVM_EXIT_IDTR_WRITE             0x006A
#define SVM_EXIT_GDTR_WRITE             0x006B
#define SVM_EXIT_LDTR_WRITE             0x006C
#define SVM_EXIT_TR_WRITE               0x006D
#define SVM_EXIT_RDTSC                  0x006E
#define SVM_EXIT_RDPMC                  0x006F
#define SVM_EXIT_PUSHF                  0x0070
#define SVM_EXIT_POPF                   0x0071
#define SVM_EXIT_CPUID                  0x0072
#define SVM_EXIT_RSM                    0x0073
#define SVM_EXIT_IRET                   0x0074
#define SVM_EXIT_SWINT                  0x0075  // Software Interrupt
#define SVM_EXIT_INVD                   0x0076
#define SVM_EXIT_PAUSE                  0x0077
#define SVM_EXIT_HLT                    0x0078
#define SVM_EXIT_INVLPG                 0x0079
#define SVM_EXIT_INVLPGA                0x007A
#define SVM_EXIT_IOIO                   0x007B
#define SVM_EXIT_MSR                    0x007C
#define SVM_EXIT_TASK_SWITCH            0x007D
#define SVM_EXIT_FERR_FREEZE            0x007E
#define SVM_EXIT_SHUTDOWN               0x007F

// SVM 专用指令退出
#define SVM_EXIT_VMRUN                  0x0080
#define SVM_EXIT_VMMCALL                0x0081
#define SVM_EXIT_VMLOAD                 0x0082
#define SVM_EXIT_VMSAVE                 0x0083
#define SVM_EXIT_STGI                   0x0084
#define SVM_EXIT_CLGI                   0x0085
#define SVM_EXIT_SKINIT                 0x0086
#define SVM_EXIT_RDTSCP                 0x0087
#define SVM_EXIT_ICEBP                  0x0088
#define SVM_EXIT_WBINVD                 0x0089
#define SVM_EXIT_MONITOR                0x008A
#define SVM_EXIT_MWAIT                  0x008B
#define SVM_EXIT_MWAIT_COND             0x008C
#define SVM_EXIT_XSETBV                 0x008D

// NPT 相关退出
#define SVM_EXIT_NPF                    0x0400  // Nested Page Fault
#define SVM_EXIT_AVIC_INCOMPLETE_IPI    0x0401
#define SVM_EXIT_AVIC_NOACCEL           0x0402

// 无效状态
#define SVM_EXIT_INVALID                -1

// ==================== VM Exit 原因 ====================

#define EXIT_REASON_EXCEPTION_NMI       0
#define EXIT_REASON_EXTERNAL_INTERRUPT  1
#define EXIT_REASON_TRIPLE_FAULT        2
#define EXIT_REASON_INIT                3
#define EXIT_REASON_SIPI                4
#define EXIT_REASON_CPUID               10
#define EXIT_REASON_HLT                 12
#define EXIT_REASON_INVD                13
#define EXIT_REASON_RDTSC               16
#define EXIT_REASON_VMCALL              18

// VMX 指令 Exit 原因（嵌套虚拟化支持）
#define EXIT_REASON_VMCLEAR             19
#define EXIT_REASON_VMLAUNCH            20
#define EXIT_REASON_VMPTRLD             21
#define EXIT_REASON_VMPTRST             22
#define EXIT_REASON_VMREAD              23
#define EXIT_REASON_VMRESUME            24
#define EXIT_REASON_VMWRITE             25
#define EXIT_REASON_VMXOFF              26
#define EXIT_REASON_VMXON               27

#define EXIT_REASON_CR_ACCESS           28
#define EXIT_REASON_MOV_DR              29
#define EXIT_REASON_IO_INSTRUCTION      30
#define EXIT_REASON_MSR_READ            31
#define EXIT_REASON_MSR_WRITE           32
#define EXIT_REASON_MONITOR_TRAP_FLAG   37
#define EXIT_REASON_EPT_VIOLATION       48
#define EXIT_REASON_EPT_MISCONFIG       49
#define EXIT_REASON_INVEPT              50
#define EXIT_REASON_RDTSCP              51
#define EXIT_REASON_INVVPID             53
#define EXIT_REASON_XSETBV              55

// ==================== VMCS 字段编码 ====================

// 16位控制字段
#define VMCS_CTRL_VIRTUAL_PROCESSOR_IDENTIFIER      0x00000000

// 16位Guest状态字段
#define GUEST_ES_SELECTOR           0x00000800
#define GUEST_CS_SELECTOR           0x00000802
#define GUEST_SS_SELECTOR           0x00000804
#define GUEST_DS_SELECTOR           0x00000806
#define GUEST_FS_SELECTOR           0x00000808
#define GUEST_GS_SELECTOR           0x0000080A
#define GUEST_LDTR_SELECTOR         0x0000080C
#define GUEST_TR_SELECTOR           0x0000080E

// 16位Host状态字段
#define HOST_ES_SELECTOR            0x00000C00
#define HOST_CS_SELECTOR            0x00000C02
#define HOST_SS_SELECTOR            0x00000C04
#define HOST_DS_SELECTOR            0x00000C06
#define HOST_FS_SELECTOR            0x00000C08
#define HOST_GS_SELECTOR            0x00000C0A
#define HOST_TR_SELECTOR            0x00000C0C

// 64位控制字段
#define VMCS_CTRL_IO_BITMAP_A               0x00002000
#define VMCS_CTRL_IO_BITMAP_B               0x00002002
#define VMCS_CTRL_MSR_BITMAP                0x00002004
#define VMCS_CTRL_VMEXIT_MSR_STORE_ADDR     0x00002006
#define VMCS_CTRL_VMEXIT_MSR_LOAD_ADDR      0x00002008
#define VMCS_CTRL_VMENTRY_MSR_LOAD_ADDR     0x0000200A
#define VMCS_CTRL_EXECUTIVE_VMCS_PTR        0x0000200C
#define VMCS_CTRL_TSC_OFFSET                0x00002010
#define VMCS_CTRL_VIRTUAL_APIC_ADDR         0x00002012
#define VMCS_CTRL_APIC_ACCESS_ADDR          0x00002014
#define VMCS_CTRL_EPTP                      0x0000201A

// 64位只读数据字段
#define VMCS_GUEST_PHYSICAL_ADDRESS         0x00002400

// 64位Guest状态字段
#define VMCS_LINK_POINTER               0x00002800
#define GUEST_IA32_DEBUGCTL             0x00002802
#define GUEST_IA32_PAT                  0x00002804
#define GUEST_IA32_EFER                 0x00002806
#define GUEST_PDPTR0                    0x0000280A
#define GUEST_PDPTR1                    0x0000280C
#define GUEST_PDPTR2                    0x0000280E
#define GUEST_PDPTR3                    0x00002810

// 64位Host状态字段
#define HOST_IA32_PAT                   0x00002C00
#define HOST_IA32_EFER                  0x00002C02

// 32位控制字段
#define VMCS_CTRL_PIN_BASED_VM_EXECUTION_CONTROLS       0x00004000
#define VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS 0x00004002
#define VMCS_CTRL_EXCEPTION_BITMAP                      0x00004004
#define VMCS_CTRL_PAGEFAULT_ERROR_CODE_MASK             0x00004006
#define VMCS_CTRL_PAGEFAULT_ERROR_CODE_MATCH            0x00004008
#define VMCS_CTRL_CR3_TARGET_COUNT                      0x0000400A
#define VMCS_CTRL_VMEXIT_CONTROLS                       0x0000400C
#define VMCS_CTRL_VMEXIT_MSR_STORE_COUNT                0x0000400E
#define VMCS_CTRL_VMEXIT_MSR_LOAD_COUNT                 0x00004010
#define VMCS_CTRL_VMENTRY_CONTROLS                      0x00004012
#define VMCS_CTRL_VMENTRY_MSR_LOAD_COUNT                0x00004014
#define VMCS_CTRL_VMENTRY_INTERRUPTION_INFO             0x00004016
#define VMCS_CTRL_VMENTRY_EXCEPTION_ERROR_CODE          0x00004018
#define VMCS_CTRL_VMENTRY_INSTRUCTION_LENGTH            0x0000401A
#define VMCS_CTRL_TPR_THRESHOLD                         0x0000401C
#define VMCS_CTRL_SECONDARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS 0x0000401E
#define VMCS_CTRL_PLE_GAP                               0x00004020
#define VMCS_CTRL_PLE_WINDOW                            0x00004022

// 32位只读数据字段
#define VM_INSTRUCTION_ERROR            0x00004400
#define VM_EXIT_REASON                  0x00004402
#define VM_EXIT_INTERRUPTION_INFO       0x00004404
#define VM_EXIT_INTERRUPTION_ERROR_CODE 0x00004406
#define IDT_VECTORING_INFO              0x00004408
#define IDT_VECTORING_ERROR_CODE        0x0000440A
#define VM_EXIT_INSTRUCTION_LEN         0x0000440C
#define VM_EXIT_INSTRUCTION_INFO        0x0000440E

// 32位Guest状态字段
#define GUEST_ES_LIMIT                  0x00004800
#define GUEST_CS_LIMIT                  0x00004802
#define GUEST_SS_LIMIT                  0x00004804
#define GUEST_DS_LIMIT                  0x00004806
#define GUEST_FS_LIMIT                  0x00004808
#define GUEST_GS_LIMIT                  0x0000480A
#define GUEST_LDTR_LIMIT                0x0000480C
#define GUEST_TR_LIMIT                  0x0000480E
#define GUEST_GDTR_LIMIT                0x00004810
#define GUEST_IDTR_LIMIT                0x00004812
#define GUEST_ES_ACCESS_RIGHTS          0x00004814
#define GUEST_CS_ACCESS_RIGHTS          0x00004816
#define GUEST_SS_ACCESS_RIGHTS          0x00004818
#define GUEST_DS_ACCESS_RIGHTS          0x0000481A
#define GUEST_FS_ACCESS_RIGHTS          0x0000481C
#define GUEST_GS_ACCESS_RIGHTS          0x0000481E
#define GUEST_LDTR_ACCESS_RIGHTS        0x00004820
#define GUEST_TR_ACCESS_RIGHTS          0x00004822
#define GUEST_INTERRUPTIBILITY_STATE    0x00004824
#define GUEST_ACTIVITY_STATE            0x00004826
#define GUEST_SMBASE                    0x00004828
#define GUEST_IA32_SYSENTER_CS          0x0000482A

// 32位Host状态字段
#define HOST_IA32_SYSENTER_CS           0x00004C00

// 自然宽度控制字段
#define VMCS_CTRL_CR0_GUEST_HOST_MASK   0x00006000
#define VMCS_CTRL_CR4_GUEST_HOST_MASK   0x00006002
#define VMCS_CTRL_CR0_READ_SHADOW       0x00006004
#define VMCS_CTRL_CR4_READ_SHADOW       0x00006006
#define VMCS_CTRL_CR3_TARGET_VALUE0     0x00006008
#define VMCS_CTRL_CR3_TARGET_VALUE1     0x0000600A
#define VMCS_CTRL_CR3_TARGET_VALUE2     0x0000600C
#define VMCS_CTRL_CR3_TARGET_VALUE3     0x0000600E

// 自然宽度只读数据字段
#define VM_EXIT_QUALIFICATION           0x00006400
#define IO_RCX                          0x00006402
#define IO_RSI                          0x00006404
#define IO_RDI                          0x00006406
#define IO_RIP                          0x00006408
#define GUEST_LINEAR_ADDRESS            0x0000640A

// 自然宽度Guest状态字段
#define GUEST_CR0                   0x00006800
#define GUEST_CR3                   0x00006802
#define GUEST_CR4                   0x00006804
#define GUEST_ES_BASE               0x00006806
#define GUEST_CS_BASE               0x00006808
#define GUEST_SS_BASE               0x0000680A
#define GUEST_DS_BASE               0x0000680C
#define GUEST_FS_BASE               0x0000680E
#define GUEST_GS_BASE               0x00006810
#define GUEST_LDTR_BASE             0x00006812
#define GUEST_TR_BASE               0x00006814
#define GUEST_GDTR_BASE             0x00006816
#define GUEST_IDTR_BASE             0x00006818
#define GUEST_DR7                   0x0000681A
#define GUEST_RSP                   0x0000681C
#define GUEST_RIP                   0x0000681E
#define GUEST_RFLAGS                0x00006820
#define GUEST_PENDING_DEBUG_EXCEPTIONS 0x00006822
#define GUEST_IA32_SYSENTER_ESP     0x00006824
#define GUEST_IA32_SYSENTER_EIP     0x00006826

// 自然宽度Host状态字段
#define HOST_CR0                    0x00006C00
#define HOST_CR3                    0x00006C02
#define HOST_CR4                    0x00006C04
#define HOST_FS_BASE                0x00006C06
#define HOST_GS_BASE                0x00006C08
#define HOST_TR_BASE                0x00006C0A
#define HOST_GDTR_BASE              0x00006C0C
#define HOST_IDTR_BASE              0x00006C0E
#define HOST_IA32_SYSENTER_ESP      0x00006C10
#define HOST_IA32_SYSENTER_EIP      0x00006C12
#define HOST_RSP                    0x00006C14
#define HOST_RIP                    0x00006C16

// ==================== VM 执行控制位 ====================

// Pin-Based VM-Execution Controls
#define PIN_BASED_EXTERNAL_INTERRUPT_EXITING    (1 << 0)
#define PIN_BASED_NMI_EXITING                   (1 << 3)
#define PIN_BASED_VIRTUAL_NMIS                  (1 << 5)

// Processor-Based VM-Execution Controls
#define CPU_BASED_INTERRUPT_WINDOW_EXITING      (1 << 2)
#define CPU_BASED_USE_TSC_OFFSETING             (1 << 3)
#define CPU_BASED_HLT_EXITING                   (1 << 7)
#define CPU_BASED_INVLPG_EXITING                (1 << 9)
#define CPU_BASED_MWAIT_EXITING                 (1 << 10)
#define CPU_BASED_RDPMC_EXITING                 (1 << 11)
#define CPU_BASED_RDTSC_EXITING                 (1 << 12)
#define CPU_BASED_CR3_LOAD_EXITING              (1 << 15)
#define CPU_BASED_CR3_STORE_EXITING             (1 << 16)
#define CPU_BASED_CR8_LOAD_EXITING              (1 << 19)
#define CPU_BASED_CR8_STORE_EXITING             (1 << 20)
#define CPU_BASED_USE_TPR_SHADOW                (1 << 21)
#define CPU_BASED_NMI_WINDOW_EXITING            (1 << 22)
#define CPU_BASED_MOV_DR_EXITING                (1 << 23)
#define CPU_BASED_UNCONDITIONAL_IO_EXITING      (1 << 24)
#define CPU_BASED_USE_IO_BITMAPS                (1 << 25)
#define CPU_BASED_MONITOR_TRAP_FLAG             (1 << 27)
#define CPU_BASED_ACTIVATE_MSR_BITMAP           (1 << 28)
#define CPU_BASED_MONITOR_EXITING               (1 << 29)
#define CPU_BASED_PAUSE_EXITING                 (1 << 30)
#define CPU_BASED_ACTIVATE_SECONDARY_CONTROLS   (1 << 31)

// Secondary Processor-Based VM-Execution Controls
#define SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES (1 << 0)
#define SECONDARY_EXEC_ENABLE_EPT               (1 << 1)
#define SECONDARY_EXEC_DESCRIPTOR_TABLE_EXITING (1 << 2)
#define SECONDARY_EXEC_ENABLE_RDTSCP            (1 << 3)
#define SECONDARY_EXEC_VIRTUALIZE_X2APIC_MODE   (1 << 4)
#define SECONDARY_EXEC_ENABLE_VPID              (1 << 5)
#define SECONDARY_EXEC_WBINVD_EXITING           (1 << 6)
#define SECONDARY_EXEC_UNRESTRICTED_GUEST       (1 << 7)
#define SECONDARY_EXEC_APIC_REGISTER_VIRT       (1 << 8)
#define SECONDARY_EXEC_VIRTUAL_INTR_DELIVERY    (1 << 9)
#define SECONDARY_EXEC_PAUSE_LOOP_EXITING       (1 << 10)
#define SECONDARY_EXEC_RDRAND_EXITING           (1 << 11)
#define SECONDARY_EXEC_ENABLE_INVPCID           (1 << 12)
#define SECONDARY_EXEC_ENABLE_VMFUNC            (1 << 13)
#define SECONDARY_EXEC_ENABLE_XSAVES_XRSTORS    (1 << 20)
// bit 25 = enable user-level MSR (ENCLV); bit 26 = enable TPAUSE/UMONITOR/UMWAIT (WAITPKG)
// 关键 (Win11 24H2 + Alder Lake 12 代): HalpTimerStallExecutionProcessor 用 TPAUSE 做省电
// 延迟。若此位 = 0, guest 执行 TPAUSE → #UD (0xC000001D) → BSOD/卡死。Win10 用 PAUSE
// 自旋不碰 TPAUSE, 所以 Win10 OK / Win11 卡死。
#define SECONDARY_EXEC_ENABLE_USER_WAIT_PAUSE   (1 << 26)

// VM-Exit Controls
#define VM_EXIT_SAVE_DEBUG_CONTROLS             (1 << 2)
#define VM_EXIT_HOST_ADDR_SPACE_SIZE            (1 << 9)
#define VM_EXIT_LOAD_IA32_PERF_GLOBAL_CTRL      (1 << 12)
#define VM_EXIT_ACK_INTR_ON_EXIT                (1 << 15)
#define VM_EXIT_SAVE_IA32_PAT                   (1 << 18)
#define VM_EXIT_LOAD_IA32_PAT                   (1 << 19)
#define VM_EXIT_SAVE_IA32_EFER                  (1 << 20)
#define VM_EXIT_LOAD_IA32_EFER                  (1 << 21)
#define VM_EXIT_SAVE_VMX_PREEMPTION_TIMER       (1 << 22)
// Win11 24H2 / Alder Lake 12 代关键: 启用让 VM-Exit 时 host CET state load from VMCS
#define VM_EXIT_LOAD_HOST_CET_STATE             (1 << 28)

// VM-Entry Controls
#define VM_ENTRY_LOAD_DEBUG_CONTROLS            (1 << 2)
#define VM_ENTRY_IA32E_MODE                     (1 << 9)
#define VM_ENTRY_SMM                            (1 << 10)
#define VM_ENTRY_DEACT_DUAL_MONITOR             (1 << 11)
#define VM_ENTRY_LOAD_IA32_PERF_GLOBAL_CTRL     (1 << 13)
#define VM_ENTRY_LOAD_IA32_PAT                  (1 << 14)
#define VM_ENTRY_LOAD_IA32_EFER                 (1 << 15)
// Win11 24H2 / Alder Lake 12 代关键: VM-Entry 时 load guest CET state (清 0)
#define VM_ENTRY_LOAD_GUEST_CET_STATE           (1 << 20)

// ==================== EPT 常量 ====================

#define EPT_READ_ACCESS                         0x01
#define EPT_WRITE_ACCESS                        0x02
#define EPT_EXECUTE_ACCESS                      0x04
#define EPT_MEMORY_TYPE_UC                      0x00
#define EPT_MEMORY_TYPE_WB                      0x06

#define EPTP_MEMORY_TYPE_WB                     (6ULL << 0)
#define EPTP_PAGE_WALK_LENGTH_4                 (3ULL << 3)

// ==================== 数据结构 ====================

// 段描述符
typedef struct _SEGMENT_DESCRIPTOR {
    USHORT Limit0;
    USHORT Base0;
    UCHAR Base1;
    UCHAR Attributes1;
    UCHAR Attributes2;
    UCHAR Base2;
} SEGMENT_DESCRIPTOR, * PSEGMENT_DESCRIPTOR;

// 段寄存器
typedef struct _SEGMENT_SELECTOR {
    USHORT Selector;
    ULONG64 Base;
    ULONG Limit;
    ULONG AccessRights;
} SEGMENT_SELECTOR, * PSEGMENT_SELECTOR;

// GDTR/IDTR
typedef struct _DESCRIPTOR_TABLE_REGISTER {
    UCHAR Data[10];
} DESCRIPTOR_TABLE_REGISTER, * PDESCRIPTOR_TABLE_REGISTER;

// AMD64 64-bit TSS (104 bytes, packed). WDK 公开头不暴露 KTSS64,
// host TSS override (0x1AA 修复) 需要自己声明完整布局。
#pragma pack(push, 4)
typedef struct _HV_KTSS64 {
    ULONG  Reserved0;
    ULONG64 Rsp0;
    ULONG64 Rsp1;
    ULONG64 Rsp2;
    ULONG64 Reserved8;
    ULONG64 Ist1;
    ULONG64 Ist2;
    ULONG64 Ist3;
    ULONG64 Ist4;
    ULONG64 Ist5;
    ULONG64 Ist6;
    ULONG64 Ist7;
    ULONG64 Reserved52;
    USHORT Reserved92;
    USHORT IoMapBase;
} HV_KTSS64, *PHV_KTSS64;
#pragma pack(pop)
C_ASSERT(sizeof(HV_KTSS64) == 104);

// Guest寄存器上下文
typedef struct _GUEST_CONTEXT {
    ULONG64 Rax;
    ULONG64 Rbx;
    ULONG64 Rcx;
    ULONG64 Rdx;
    ULONG64 Rsi;
    ULONG64 Rdi;
    ULONG64 Rbp;
    ULONG64 R8;
    ULONG64 R9;
    ULONG64 R10;
    ULONG64 R11;
    ULONG64 R12;
    ULONG64 R13;
    ULONG64 R14;
    ULONG64 R15;
} GUEST_CONTEXT, *PGUEST_CONTEXT;

// 虚拟机CPU状态
typedef struct _VCPU_STATE {
    ULONG64 Rax, Rcx, Rdx, Rbx, Rsp, Rbp, Rsi, Rdi;
    ULONG64 R8, R9, R10, R11, R12, R13, R14, R15;
    ULONG64 Cr0, Cr2, Cr3, Cr4;
    ULONG64 Rflags, Rip;
    BOOLEAN IsVirtualized;
} VCPU_STATE, * PVCPU_STATE;

// EPT页表项
typedef union _EPT_PML4E {
    ULONG64 Value;
    struct {
        ULONG64 Read : 1;
        ULONG64 Write : 1;
        ULONG64 Execute : 1;
        ULONG64 Reserved1 : 5;
        ULONG64 Accessed : 1;
        ULONG64 Reserved2 : 3;
        ULONG64 PageFrameNumber : 40;
        ULONG64 Reserved3 : 12;
    };
} EPT_PML4E, * PEPT_PML4E;

typedef union _EPT_PDPTE {
    ULONG64 Value;
    struct {
        ULONG64 Read : 1;
        ULONG64 Write : 1;
        ULONG64 Execute : 1;
        ULONG64 Reserved1 : 5;
        ULONG64 Accessed : 1;
        ULONG64 Reserved2 : 3;
        ULONG64 PageFrameNumber : 40;
        ULONG64 Reserved3 : 12;
    };
} EPT_PDPTE, * PEPT_PDPTE;

typedef union _EPT_PDE {
    ULONG64 Value;
    struct {
        ULONG64 Read : 1;
        ULONG64 Write : 1;
        ULONG64 Execute : 1;
        ULONG64 Reserved1 : 5;
        ULONG64 Accessed : 1;
        ULONG64 Reserved2 : 3;
        ULONG64 PageFrameNumber : 40;
        ULONG64 Reserved3 : 12;
    };
} EPT_PDE, * PEPT_PDE;

typedef union _EPT_PTE {
    ULONG64 Value;
    struct {
        ULONG64 Read : 1;
        ULONG64 Write : 1;
        ULONG64 Execute : 1;
        ULONG64 MemoryType : 3;
        ULONG64 IgnorePat : 1;
        ULONG64 Reserved1 : 1;
        ULONG64 Accessed : 1;
        ULONG64 Dirty : 1;
        ULONG64 Reserved2 : 2;
        ULONG64 PageFrameNumber : 40;
        ULONG64 Reserved3 : 11;
        ULONG64 SuppressVE : 1;
    };
} EPT_PTE, * PEPT_PTE;

// EPT指针
typedef union _EPTP {
    ULONG64 Value;
    struct {
        ULONG64 MemoryType : 3;
        ULONG64 PageWalkLength : 3;
        ULONG64 EnableAccessAndDirtyFlags : 1;
        ULONG64 Reserved1 : 5;
        ULONG64 PageFrameNumber : 40;
        ULONG64 Reserved2 : 12;
    };
} EPTP, * PEPTP;

// EPT页表
typedef struct _EPT_TABLES {
    DECLSPEC_ALIGN(PAGE_SIZE) EPT_PML4E Pml4[512];
    DECLSPEC_ALIGN(PAGE_SIZE) EPT_PDPTE Pdpt[512];
    DECLSPEC_ALIGN(PAGE_SIZE) EPT_PDE Pd[512][512];
    PHYSICAL_ADDRESS Pml4Physical;
    PHYSICAL_ADDRESS PdptPhysical;
    PEPT_PTE SplitPt[64];
    PHYSICAL_ADDRESS SplitPtPhysical[64];  // 与 SplitPt 同步:每个 PT 的 HPA,供 root 模式无 Mm* 查找
    ULONG SplitPtCount;
    PVOID ExtraPdpt[3];  // PML4[1..3] PDPT pages for >512GB MMIO mapping
} EPT_TABLES, * PEPT_TABLES;

// ==================== 嵌套虚拟化支持 ====================

// 嵌套虚拟化全局开关
extern BOOLEAN g_EnableNestedVirtualization;

// VMX 操作失败类型
#define VMX_FAIL_INVALID                0   // 无效操作（CF=1）
#define VMX_FAIL_VALID                  1   // 有效失败（ZF=1，错误码在VMCS）

// VMX 指令错误码
#define VMXERR_VMCALL_IN_VMX_ROOT       1
#define VMXERR_VMCLEAR_INVALID_ADDRESS  2
#define VMXERR_VMCLEAR_WITH_VMXON       3
#define VMXERR_VMLAUNCH_NONCLEAR_VMCS   4
#define VMXERR_VMRESUME_NONLAUNCHED     5
#define VMXERR_VMRESUME_CORRUPTED_VMCS  6
#define VMXERR_VMENTRY_INVALID_CONTROL  7
#define VMXERR_VMENTRY_INVALID_HOST     8
#define VMXERR_VMPTRLD_INVALID_ADDRESS  9
#define VMXERR_VMPTRLD_WITH_VMXON       10
#define VMXERR_VMPTRLD_INCORRECT_VMCS   11
#define VMXERR_VMREAD_INVALID_COMPONENT 12
#define VMXERR_VMWRITE_INVALID_COMPONENT 12
#define VMXERR_VMWRITE_READONLY         13
#define VMXERR_VMXON_IN_VMX_ROOT        15
#define VMXERR_VMENTRY_INVALID_EXEC_CTRL 16
#define VMXERR_VMENTRY_NONLAUNCHED      19
#define VMXERR_VMENTRY_NOT_VMXON        22
#define VMXERR_VMCALL_NONCLEAR_VMCS     26
#define VMXERR_VMCALL_INVALID_EXIT_CTRL 27
#define VMXERR_VMCALL_INCORRECT_MSEG    28
#define VMXERR_VMXOFF_DUAL_MONITOR      29
#define VMXERR_VMCALL_INVALID_SMM       30
#define VMXERR_VMENTRY_INVALID_EXEC_CTRL_MOV_SS 33
#define VMXERR_INVEPT_INVVPID_INVALID   28

// VMCS 字段数量（用于 VMCS12 缓存）
#define VMCS_FIELD_COUNT                128

// VMCS12 字段索引（用于缓存）
typedef enum _VMCS12_FIELD_INDEX {
    // 控制字段
    VMCS12_PIN_BASED_CONTROLS = 0,
    VMCS12_CPU_BASED_CONTROLS,
    VMCS12_SECONDARY_CONTROLS,
    VMCS12_EXCEPTION_BITMAP,
    VMCS12_EXIT_CONTROLS,
    VMCS12_ENTRY_CONTROLS,
    VMCS12_CR0_GUEST_HOST_MASK,
    VMCS12_CR4_GUEST_HOST_MASK,
    VMCS12_CR0_READ_SHADOW,
    VMCS12_CR4_READ_SHADOW,
    VMCS12_EPTP,
    VMCS12_MSR_BITMAP,
    VMCS12_TSC_OFFSET,
    
    // Guest 状态字段
    VMCS12_GUEST_CR0,
    VMCS12_GUEST_CR3,
    VMCS12_GUEST_CR4,
    VMCS12_GUEST_DR7,
    VMCS12_GUEST_RSP,
    VMCS12_GUEST_RIP,
    VMCS12_GUEST_RFLAGS,
    VMCS12_GUEST_CS_SELECTOR,
    VMCS12_GUEST_CS_BASE,
    VMCS12_GUEST_CS_LIMIT,
    VMCS12_GUEST_CS_ACCESS,
    VMCS12_GUEST_SS_SELECTOR,
    VMCS12_GUEST_SS_BASE,
    VMCS12_GUEST_SS_LIMIT,
    VMCS12_GUEST_SS_ACCESS,
    VMCS12_GUEST_DS_SELECTOR,
    VMCS12_GUEST_DS_BASE,
    VMCS12_GUEST_DS_LIMIT,
    VMCS12_GUEST_DS_ACCESS,
    VMCS12_GUEST_ES_SELECTOR,
    VMCS12_GUEST_ES_BASE,
    VMCS12_GUEST_ES_LIMIT,
    VMCS12_GUEST_ES_ACCESS,
    VMCS12_GUEST_FS_SELECTOR,
    VMCS12_GUEST_FS_BASE,
    VMCS12_GUEST_FS_LIMIT,
    VMCS12_GUEST_FS_ACCESS,
    VMCS12_GUEST_GS_SELECTOR,
    VMCS12_GUEST_GS_BASE,
    VMCS12_GUEST_GS_LIMIT,
    VMCS12_GUEST_GS_ACCESS,
    VMCS12_GUEST_LDTR_SELECTOR,
    VMCS12_GUEST_LDTR_BASE,
    VMCS12_GUEST_LDTR_LIMIT,
    VMCS12_GUEST_LDTR_ACCESS,
    VMCS12_GUEST_TR_SELECTOR,
    VMCS12_GUEST_TR_BASE,
    VMCS12_GUEST_TR_LIMIT,
    VMCS12_GUEST_TR_ACCESS,
    VMCS12_GUEST_GDTR_BASE,
    VMCS12_GUEST_GDTR_LIMIT,
    VMCS12_GUEST_IDTR_BASE,
    VMCS12_GUEST_IDTR_LIMIT,
    VMCS12_GUEST_EFER,
    VMCS12_GUEST_PAT,
    VMCS12_GUEST_DEBUGCTL,
    VMCS12_GUEST_SYSENTER_CS,
    VMCS12_GUEST_SYSENTER_ESP,
    VMCS12_GUEST_SYSENTER_EIP,
    VMCS12_GUEST_ACTIVITY_STATE,
    VMCS12_GUEST_INTERRUPTIBILITY,
    VMCS12_GUEST_PENDING_DBG_EXCEPTIONS,
    VMCS12_VMCS_LINK_POINTER,
    
    // Host 状态字段
    VMCS12_HOST_CR0,
    VMCS12_HOST_CR3,
    VMCS12_HOST_CR4,
    VMCS12_HOST_RSP,
    VMCS12_HOST_RIP,
    VMCS12_HOST_CS_SELECTOR,
    VMCS12_HOST_SS_SELECTOR,
    VMCS12_HOST_DS_SELECTOR,
    VMCS12_HOST_ES_SELECTOR,
    VMCS12_HOST_FS_SELECTOR,
    VMCS12_HOST_FS_BASE,
    VMCS12_HOST_GS_SELECTOR,
    VMCS12_HOST_GS_BASE,
    VMCS12_HOST_TR_SELECTOR,
    VMCS12_HOST_TR_BASE,
    VMCS12_HOST_GDTR_BASE,
    VMCS12_HOST_IDTR_BASE,
    VMCS12_HOST_EFER,
    VMCS12_HOST_PAT,
    VMCS12_HOST_SYSENTER_CS,
    VMCS12_HOST_SYSENTER_ESP,
    VMCS12_HOST_SYSENTER_EIP,
    
    // 退出信息
    VMCS12_EXIT_REASON,
    VMCS12_EXIT_QUALIFICATION,
    VMCS12_EXIT_INTR_INFO,
    VMCS12_EXIT_INTR_ERROR_CODE,
    VMCS12_IDT_VECTORING_INFO,
    VMCS12_IDT_VECTORING_ERROR,
    VMCS12_EXIT_INSTRUCTION_LEN,
    VMCS12_EXIT_INSTRUCTION_INFO,
    VMCS12_GUEST_PHYSICAL_ADDRESS,
    VMCS12_GUEST_LINEAR_ADDRESS,
    
    // 入口字段
    VMCS12_ENTRY_INTR_INFO,
    VMCS12_ENTRY_EXCEPTION_ERROR_CODE,
    VMCS12_ENTRY_INSTRUCTION_LEN,
    
    VMCS12_FIELD_MAX
} VMCS12_FIELD_INDEX;

// 嵌套 VMCS 状态
typedef enum _NESTED_VMCS_STATE {
    VMCS_STATE_CLEAR = 0,       // VMCLEAR 后的状态
    VMCS_STATE_LAUNCHED,        // VMLAUNCH 后的状态
    VMCS_STATE_ACTIVE           // VMPTRLD 后激活
} NESTED_VMCS_STATE;

// 嵌套 VMX 状态结构
typedef struct _NESTED_VMX_STATE {
    // L1 VMX 操作状态
    BOOLEAN VmxEnabled;                     // L1 是否执行了 VMXON
    ULONG64 VmxonRegionGpa;                 // L1 的 VMXON 区域 GPA
    ULONG64 CurrentVmcsGpa;                 // L1 当前 VMCS 的 GPA（VMPTRLD 设置）
    NESTED_VMCS_STATE VmcsState;            // 当前 VMCS 状态
    
    // Shadow VMCS（用于 VMCS Shadowing 如果支持）
    PVOID ShadowVmcs;                       // Shadow VMCS 虚拟地址
    PHYSICAL_ADDRESS ShadowVmcsPhysical;    // Shadow VMCS 物理地址
    
    // L1 Hypervisor 的 VMCS 字段缓存（VMCS12）
    // 这是 L1 为 L2 配置的 VMCS，我们需要缓存它
    ULONG64 Vmcs12[VMCS12_FIELD_MAX];
    BOOLEAN Vmcs12Valid;                    // VMCS12 是否有效
    
    // L1 Guest 状态保存（当进入 L2 时保存 L1 的状态）
    ULONG64 L1GuestRip;                     // L1 的 RIP
    ULONG64 L1GuestRsp;                     // L1 的 RSP
    ULONG64 L1GuestRflags;                  // L1 的 RFLAGS
    ULONG64 L1GuestCr0;
    ULONG64 L1GuestCr3;
    ULONG64 L1GuestCr4;
    ULONG64 L1GuestEfer;
    ULONG64 L1GuestDr7;
    
    // L1 段寄存器保存
    USHORT L1CsSelector;
    USHORT L1SsSelector;
    USHORT L1DsSelector;
    USHORT L1EsSelector;
    USHORT L1FsSelector;
    USHORT L1GsSelector;
    USHORT L1TrSelector;
    USHORT L1LdtrSelector;
    ULONG64 L1CsBase, L1SsBase, L1DsBase, L1EsBase;
    ULONG64 L1FsBase, L1GsBase, L1TrBase, L1LdtrBase;
    ULONG64 L1GdtrBase, L1IdtrBase;
    ULONG L1CsLimit, L1SsLimit, L1DsLimit, L1EsLimit;
    ULONG L1FsLimit, L1GsLimit, L1TrLimit, L1LdtrLimit;
    ULONG L1GdtrLimit, L1IdtrLimit;
    ULONG L1CsAccessRights, L1SsAccessRights, L1DsAccessRights, L1EsAccessRights;
    ULONG L1FsAccessRights, L1GsAccessRights, L1TrAccessRights, L1LdtrAccessRights;
    
    // L1 SYSENTER 保存
    ULONG64 L1SysenterCs;
    ULONG64 L1SysenterEsp;
    ULONG64 L1SysenterEip;
    
    // L0 原始 VMCS 控制字段保存（从 L2 退出时需要恢复）
    ULONG64 SavedPinBasedControls;
    ULONG64 SavedProcBasedControls;
    ULONG64 SavedSecondaryControls;
    ULONG64 SavedExitControls;
    ULONG64 SavedEntryControls;
    ULONG64 SavedExceptionBitmap;
    ULONG64 SavedEptp;
    ULONG64 SavedTscOffset;
    ULONG64 SavedMsrBitmap;
    
    // 嵌套 EPT
    PVOID NestedEptTables;                  // 嵌套 EPT 上下文指针（PNESTED_EPT_CONTEXT）
    ULONG64 L1Eptp;                         // L1 配置的 EPTP
    BOOLEAN L1EptEnabled;                   // L1 是否启用了 EPT
    
    // 缓存的合并控制字段
    ULONG64 MergedPinBasedControls;
    ULONG64 MergedProcBasedControls;
    ULONG64 MergedSecondaryControls;
    ULONG64 MergedExitControls;
    ULONG64 MergedEntryControls;
    ULONG64 MergedExceptionBitmap;
    
    // 统计信息
    ULONG64 L2VmExitCount;                  // L2 VM Exit 计数
    ULONG64 NestedVmEntryCount;             // 嵌套 VM Entry 计数
} NESTED_VMX_STATE, *PNESTED_VMX_STATE;

// Secondary Controls 中的 VMCS Shadowing 位
#define SECONDARY_EXEC_SHADOW_VMCS          (1 << 14)

// ==================== AMD SVM 段寄存器结构（前向声明，用于嵌套 SVM）====================

// VMCB 段寄存器结构 (用于 State Save Area)
// 注意：需要在 NESTED_SVM_STATE 之前定义
typedef struct _SVM_SEGMENT_REGISTER {
    USHORT Selector;
    USHORT Attributes;
    ULONG Limit;
    ULONG64 Base;
} SVM_SEGMENT_REGISTER, *PSVM_SEGMENT_REGISTER;

// ==================== AMD SVM 嵌套虚拟化支持 ====================

// 嵌套 SVM 状态（L1 Hypervisor 在 L0 中运行 SVM）
typedef struct _NESTED_SVM_STATE {
    // L1 SVM 操作状态
    BOOLEAN SvmEnabled;                     // L1 是否启用了 SVM（EFER.SVME）
    ULONG64 VmcbGpa;                        // L1 的 VMCB 地址（VMRUN 参数）
    ULONG64 HostSaveGpa;                    // L1 的 Host Save Area GPA
    BOOLEAN InGuestMode;                    // L1 是否已进入 Guest 模式
    
    // L1 Hypervisor 的 VMCB 缓存（VMCB12）
    // 这是 L1 为 L2 配置的 VMCB
    PVOID Vmcb12;                           // 缓存的 L1 VMCB
    PHYSICAL_ADDRESS Vmcb12Physical;
    BOOLEAN Vmcb12Valid;
    
    // L1 状态保存（当进入 L2 时保存 L1 的状态）
    ULONG64 L1GuestRip;
    ULONG64 L1GuestRsp;
    ULONG64 L1GuestRax;
    ULONG64 L1GuestRflags;
    ULONG64 L1GuestCr0;
    ULONG64 L1GuestCr2;
    ULONG64 L1GuestCr3;
    ULONG64 L1GuestCr4;
    ULONG64 L1GuestEfer;
    ULONG64 L1GuestDr6;
    ULONG64 L1GuestDr7;
    
    // L1 段寄存器保存
    SVM_SEGMENT_REGISTER L1Es;
    SVM_SEGMENT_REGISTER L1Cs;
    SVM_SEGMENT_REGISTER L1Ss;
    SVM_SEGMENT_REGISTER L1Ds;
    SVM_SEGMENT_REGISTER L1Fs;
    SVM_SEGMENT_REGISTER L1Gs;
    SVM_SEGMENT_REGISTER L1Gdtr;
    SVM_SEGMENT_REGISTER L1Ldtr;
    SVM_SEGMENT_REGISTER L1Idtr;
    SVM_SEGMENT_REGISTER L1Tr;
    UCHAR L1Cpl;
    
    // L1 SYSENTER/SYSCALL 保存
    ULONG64 L1Star;
    ULONG64 L1LStar;
    ULONG64 L1CStar;
    ULONG64 L1SfMask;
    ULONG64 L1KernelGsBase;
    ULONG64 L1SysenterCs;
    ULONG64 L1SysenterEsp;
    ULONG64 L1SysenterEip;
    
    // L0 原始 VMCB 控制字段保存（从 L2 退出时需要恢复）
    USHORT SavedInterceptCrRead;
    USHORT SavedInterceptCrWrite;
    USHORT SavedInterceptDrRead;
    USHORT SavedInterceptDrWrite;
    ULONG SavedInterceptExceptions;
    ULONG64 SavedInterceptMisc1;
    ULONG64 SavedInterceptMisc2;
    ULONG64 SavedTscOffset;
    ULONG64 SavedNpEnable;
    ULONG64 SavedNCr3;
    ULONG SavedAsid;
    ULONG64 SavedIopmBasePa;
    ULONG64 SavedMsrpmBasePa;
    
    // ASID 管理
    ULONG L2Asid;                           // 分配给 L2 的 ASID
    ULONG L1Asid;                           // L1 的原始 ASID
    
    // 嵌套 NPT
    PVOID NestedNptTables;                  // 嵌套 NPT 上下文（PNESTED_NPT_CONTEXT）
    ULONG64 L1NCr3;                         // L1 配置的 NPT CR3
    BOOLEAN L1NptEnabled;                   // L1 是否启用了 NPT
    
    // 合并的 IOPM/MSRPM
    PVOID MergedIopm;                       // 合并后的 IOPM
    PVOID MergedMsrpm;                      // 合并后的 MSRPM
    PHYSICAL_ADDRESS MergedIopmPhysical;
    PHYSICAL_ADDRESS MergedMsrpmPhysical;
    
    // 合并的拦截控制
    ULONG64 MergedInterceptMisc1;
    ULONG64 MergedInterceptMisc2;
    ULONG MergedExceptionBitmap;
    
    // 统计信息
    ULONG64 L2VmExitCount;
    ULONG64 NestedVmrunCount;
} NESTED_SVM_STATE, *PNESTED_SVM_STATE;

// ==================== AMD SVM VMCB 结构 ====================

// 注意: SVM_SEGMENT_REGISTER 已在上方定义（用于 NESTED_SVM_STATE）

// VMCB 控制区结构 (偏移 0x000-0x3FF)
// 使用 #pragma pack(1) 确保精确布局
#pragma pack(push, 1)
typedef struct _VMCB_CONTROL_AREA {
    // 拦截控制 (0x000 - 0x01B)
    USHORT InterceptCrRead;             // +0x000: CR0-15 读取拦截
    USHORT InterceptCrWrite;            // +0x002: CR0-15 写入拦截
    USHORT InterceptDrRead;             // +0x004: DR0-15 读取拦截
    USHORT InterceptDrWrite;            // +0x006: DR0-15 写入拦截
    ULONG InterceptExceptions;          // +0x008: 异常拦截位图
    ULONG64 InterceptMisc1;             // +0x00C: 杂项拦截1
    ULONG64 InterceptMisc2;             // +0x014: 杂项拦截2
    UCHAR Reserved1[0x20];              // +0x01C - 0x03B
    
    // Pause 过滤 (0x03C - 0x03F)
    USHORT PauseFilterThreshold;        // +0x03C
    USHORT PauseFilterCount;            // +0x03E
    
    // 物理地址 (0x040 - 0x057)
    ULONG64 IopmBasePa;                 // +0x040: I/O 权限位图物理地址
    ULONG64 MsrpmBasePa;                // +0x048: MSR 权限位图物理地址
    ULONG64 TscOffset;                  // +0x050: TSC 偏移
    
    // Guest ASID 和 TLB 控制 (0x058 - 0x05F)
    ULONG GuestAsid;                    // +0x058: Guest ASID
    ULONG TlbControl;                   // +0x05C: TLB 控制
    
    // 虚拟中断控制 (0x060 - 0x067)
    ULONG64 VIntr;                      // +0x060: 虚拟中断控制
    
    // 中断影映 (0x068 - 0x06F)
    ULONG64 InterruptShadow;            // +0x068
    
    // 退出信息 (0x070 - 0x08F)
    ULONG64 ExitCode;                   // +0x070: Exit Code
    ULONG64 ExitInfo1;                  // +0x078: Exit Info 1
    ULONG64 ExitInfo2;                  // +0x080: Exit Info 2
    ULONG64 ExitIntInfo;                // +0x088: Exit Interrupt Info
    
    // NPT 控制 (0x090 - 0x097)
    ULONG64 NpEnable;                   // +0x090: NPT Enable (bit 0)
    
    // AVIC/APIC (0x098 - 0x0A7)
    ULONG64 AvicApicBar;                // +0x098: AVIC APIC BAR
    ULONG64 GhcbPa;                     // +0x0A0: GHCB 物理地址 (SEV)
    
    // 事件注入 (0x0A8 - 0x0AF)
    ULONG64 EventInj;                   // +0x0A8: Event Injection
    
    // NPT CR3 (0x0B0 - 0x0B7)
    ULONG64 NCr3;                       // +0x0B0: Nested CR3 (NPT)
    
    // LBR 虚拟化 (0x0B8 - 0x0BF)
    ULONG64 LbrVirtualizationEnable;    // +0x0B8
    
    // VMCB 清理位 (0x0C0 - 0x0C7)
    ULONG64 VmcbCleanBits;              // +0x0C0
    
    // 下一条 Guest RIP (0x0C8 - 0x0CF)
    ULONG64 NRip;                       // +0x0C8: Next RIP (用于解码后指令)
    
    // 指令信息 (0x0D0 - 0x0DF)
    UCHAR NumOfBytesFetched;            // +0x0D0
    UCHAR GuestInstructionBytes[15];    // +0x0D1 - 0x0DF
    
    // AVIC (0x0E0 - 0x0FF)
    ULONG64 AvicApicBackingPagePtr;     // +0x0E0
    ULONG64 Reserved3;                  // +0x0E8
    ULONG64 AvicLogicalTablePtr;        // +0x0F0
    ULONG64 AvicPhysicalTablePtr;       // +0x0F8
    
    // 保留到 0x3FF
    UCHAR Reserved4[0x300];             // +0x100 - 0x3FF
} VMCB_CONTROL_AREA, *PVMCB_CONTROL_AREA;

// VMCB 状态保存区结构 (偏移 0x400-0xFFF)
typedef struct _VMCB_STATE_SAVE_AREA {
    // 段寄存器 (0x400 - 0x4A7)
    SVM_SEGMENT_REGISTER Es;            // +0x400
    SVM_SEGMENT_REGISTER Cs;            // +0x410
    SVM_SEGMENT_REGISTER Ss;            // +0x420
    SVM_SEGMENT_REGISTER Ds;            // +0x430
    SVM_SEGMENT_REGISTER Fs;            // +0x440
    SVM_SEGMENT_REGISTER Gs;            // +0x450
    SVM_SEGMENT_REGISTER Gdtr;          // +0x460
    SVM_SEGMENT_REGISTER Ldtr;          // +0x470
    SVM_SEGMENT_REGISTER Idtr;          // +0x480
    SVM_SEGMENT_REGISTER Tr;            // +0x490
    
    // 保留 (0x4A0 - 0x4CA)
    UCHAR Reserved1[0x2B];              // +0x4A0
    
    // CPL (0x4CB)
    UCHAR Cpl;                          // +0x4CB
    
    // 保留 (0x4CC - 0x4CF)
    UCHAR Reserved2[4];                 // +0x4CC
    
    // EFER (0x4D0 - 0x4D7)
    ULONG64 Efer;                       // +0x4D0
    
    // 保留 (0x4D8 - 0x547)
    UCHAR Reserved3[0x70];              // +0x4D8
    
    // 控制寄存器和调试寄存器 (0x548 - 0x56F)
    ULONG64 Cr4;                        // +0x548
    ULONG64 Cr3;                        // +0x550
    ULONG64 Cr0;                        // +0x558
    ULONG64 Dr7;                        // +0x560
    ULONG64 Dr6;                        // +0x568
    
    // RFLAGS 和 RIP (0x570 - 0x57F)
    ULONG64 Rflags;                     // +0x570
    ULONG64 Rip;                        // +0x578
    
    // 保留 (0x580 - 0x5D7)
    UCHAR Reserved4[0x58];              // +0x580
    
    // RSP (0x5D8 - 0x5DF)
    ULONG64 Rsp;                        // +0x5D8
    
    // 保留 (0x5E0 - 0x5F7)
    UCHAR Reserved5[0x18];              // +0x5E0
    
    // RAX (0x5F8 - 0x5FF)
    ULONG64 Rax;                        // +0x5F8
    
    // 系统 MSR (0x600 - 0x64F)
    ULONG64 Star;                       // +0x600
    ULONG64 LStar;                      // +0x608
    ULONG64 CStar;                      // +0x610
    ULONG64 SfMask;                     // +0x618
    ULONG64 KernelGsBase;               // +0x620
    ULONG64 SysenterCs;                 // +0x628
    ULONG64 SysenterEsp;                // +0x630
    ULONG64 SysenterEip;                // +0x638
    ULONG64 Cr2;                        // +0x640
    
    // 保留 (0x648 - 0x667)
    UCHAR Reserved6[0x20];              // +0x648
    
    // Guest PAT (0x668 - 0x66F)
    ULONG64 GPat;                       // +0x668
    
    // DBGCTL (0x670 - 0x677)
    ULONG64 DbgCtl;                     // +0x670
    
    // LBR (0x678 - 0x68F)
    ULONG64 BrFrom;                     // +0x678
    ULONG64 BrTo;                       // +0x680
    ULONG64 LastExcepFrom;              // +0x688
    ULONG64 LastExcepTo;                // +0x690
    
    // 保留到页边界 (填充到 0xFFF)
    UCHAR Reserved7[0x968];             // +0x698 - 0xFFF
} VMCB_STATE_SAVE_AREA, *PVMCB_STATE_SAVE_AREA;
#pragma pack(pop)

// 完整 VMCB 结构 (4KB 对齐)
// 使用联合体确保正确的大小和对齐
typedef struct DECLSPEC_ALIGN(PAGE_SIZE) _VMCB {
    union {
        struct {
            VMCB_CONTROL_AREA ControlArea;      // 0x000 - 0x3FF
            VMCB_STATE_SAVE_AREA StateSaveArea; // 0x400 - 0xFFF
        };
        UCHAR RawData[PAGE_SIZE];               // 确保总大小为 4KB
    };
} VMCB, *PVMCB;

// VMCB 拦截位定义 - InterceptMisc1 (偏移 0x00C)
#define SVM_INTERCEPT_INTR              (1ULL << 0)
#define SVM_INTERCEPT_NMI               (1ULL << 1)
#define SVM_INTERCEPT_SMI               (1ULL << 2)
#define SVM_INTERCEPT_INIT              (1ULL << 3)
#define SVM_INTERCEPT_VINTR             (1ULL << 4)
#define SVM_INTERCEPT_CR0_WRITE_SEL     (1ULL << 5)
#define SVM_INTERCEPT_IDTR_READ         (1ULL << 6)
#define SVM_INTERCEPT_GDTR_READ         (1ULL << 7)
#define SVM_INTERCEPT_LDTR_READ         (1ULL << 8)
#define SVM_INTERCEPT_TR_READ           (1ULL << 9)
#define SVM_INTERCEPT_IDTR_WRITE        (1ULL << 10)
#define SVM_INTERCEPT_GDTR_WRITE        (1ULL << 11)
#define SVM_INTERCEPT_LDTR_WRITE        (1ULL << 12)
#define SVM_INTERCEPT_TR_WRITE          (1ULL << 13)
#define SVM_INTERCEPT_RDTSC             (1ULL << 14)
#define SVM_INTERCEPT_RDPMC             (1ULL << 15)
#define SVM_INTERCEPT_PUSHF             (1ULL << 16)
#define SVM_INTERCEPT_POPF              (1ULL << 17)
#define SVM_INTERCEPT_CPUID             (1ULL << 18)
#define SVM_INTERCEPT_RSM               (1ULL << 19)
#define SVM_INTERCEPT_IRET              (1ULL << 20)
#define SVM_INTERCEPT_INT               (1ULL << 21)
#define SVM_INTERCEPT_INVD              (1ULL << 22)
#define SVM_INTERCEPT_PAUSE             (1ULL << 23)
#define SVM_INTERCEPT_HLT               (1ULL << 24)
#define SVM_INTERCEPT_INVLPG            (1ULL << 25)
#define SVM_INTERCEPT_INVLPGA           (1ULL << 26)
#define SVM_INTERCEPT_IOIO              (1ULL << 27)
#define SVM_INTERCEPT_MSR               (1ULL << 28)
#define SVM_INTERCEPT_TASK_SWITCH       (1ULL << 29)
#define SVM_INTERCEPT_FERR_FREEZE       (1ULL << 30)
#define SVM_INTERCEPT_SHUTDOWN          (1ULL << 31)

// VMCB 拦截位定义 - InterceptMisc2 (偏移 0x014)
#define SVM_INTERCEPT_VMRUN             (1ULL << 0)
#define SVM_INTERCEPT_VMMCALL           (1ULL << 1)
#define SVM_INTERCEPT_VMLOAD            (1ULL << 2)
#define SVM_INTERCEPT_VMSAVE            (1ULL << 3)
#define SVM_INTERCEPT_STGI              (1ULL << 4)
#define SVM_INTERCEPT_CLGI              (1ULL << 5)
#define SVM_INTERCEPT_SKINIT            (1ULL << 6)
#define SVM_INTERCEPT_RDTSCP            (1ULL << 7)
#define SVM_INTERCEPT_ICEBP             (1ULL << 8)
#define SVM_INTERCEPT_WBINVD            (1ULL << 9)
#define SVM_INTERCEPT_MONITOR           (1ULL << 10)
#define SVM_INTERCEPT_MWAIT             (1ULL << 11)
#define SVM_INTERCEPT_MWAIT_COND        (1ULL << 12)
#define SVM_INTERCEPT_XSETBV            (1ULL << 13)

// TLB 控制值
#define SVM_TLB_CONTROL_NOTHING         0
#define SVM_TLB_CONTROL_FLUSH_ALL       1
#define SVM_TLB_CONTROL_FLUSH_GUEST     3
#define SVM_TLB_CONTROL_FLUSH_GUEST_NONGLOBAL 7

// 事件注入格式 (EventInj 字段)
typedef union _SVM_EVENT_INJECTION {
    ULONG64 Value;
    struct {
        ULONG64 Vector : 8;         // 中断/异常向量
        ULONG64 Type : 3;           // 0=INTR, 2=NMI, 3=Exception, 4=SoftINT
        ULONG64 ErrorCodeValid : 1; // 是否有错误码
        ULONG64 Reserved : 19;
        ULONG64 Valid : 1;          // 事件有效
        ULONG64 ErrorCode : 32;     // 错误码
    };
} SVM_EVENT_INJECTION, *PSVM_EVENT_INJECTION;

// 事件注入类型
#define SVM_EVENT_TYPE_INTR             0
#define SVM_EVENT_TYPE_NMI              2
#define SVM_EVENT_TYPE_EXCEPTION        3
#define SVM_EVENT_TYPE_SOFT_INT         4

// 前向声明 NPT 页表结构
struct _NPT_TABLES;
typedef struct _NPT_TABLES NPT_TABLES, *PNPT_TABLES;

// VCPU数据结构
typedef struct _VCPU_DATA {
    // === 公共字段 ===
    ULONG ProcessorNumber;
    BOOLEAN IsVirtualized;
    PVOID VmExitStack;
    ULONG64 VmExitStackPhysical;

    // === Intel VMX 专用字段 ===
    PVOID VmxonRegion;
    PHYSICAL_ADDRESS VmxonRegionPhysical;
    PVOID VmcsRegion;
    PHYSICAL_ADDRESS VmcsRegionPhysical;
    PVOID MsrBitmap;                        // Intel MSR Bitmap (4KB)
    PHYSICAL_ADDRESS MsrBitmapPhysical;
    PEPT_TABLES EptTables;                  // Intel EPT 页表
    USHORT Vpid;                            // Intel VPID (1-based, 0 reserved)；ProcessorNumber+1

    // === P125: PEB 字段级 EPT spoof (HvPebCloak.h) ===
    // 旧 HvCloak (dual-EPTP 全 0 cloak) 整套已删除 (从未启用).
    PEPT_TABLES EptPebSpoof;                // 第二份 EPT 实例: target PEB 页 R=0 强制 violation
    ULONG64     EptpMain;                   // 缓存的 VMCS_CTRL_EPTP 值: EptTables 版本
    ULONG64     EptpPebSpoof;               // 缓存的 VMCS_CTRL_EPTP 值: EptPebSpoof 版本
    volatile LONG ActiveEptpIsPebSpoof;     // 当前 VMCS 实际写入的 EPTP class (0=Main, 1=PebSpoof)
    UINT64      LastSnoopedCr3;             // 上次 vmexit 看到的 GUEST_CR3 (avoid 重复 classify)
    ULONG       LastCallerClass;            // 0=Main, 1=PebSpoof, 0xFF=未分类

    // === AMD SVM 专用字段 ===
    PVMCB Vmcb;                             // VMCB 虚拟地址
    PHYSICAL_ADDRESS VmcbPhysical;          // VMCB 物理地址
    PVOID HostSaveArea;                     // Host 状态保存区
    PHYSICAL_ADDRESS HostSaveAreaPhysical;
    PVOID MsrPermissionMap;                 // MSR 权限位图 (8KB = 2页)
    PHYSICAL_ADDRESS MsrPermissionMapPhysical;
    PNPT_TABLES NptTables;                  // AMD NPT 页表

    // === 嵌套虚拟化支持 ===
    NESTED_VMX_STATE NestedVmx;             // 嵌套 VMX 状态（Intel）
    NESTED_SVM_STATE NestedSvm;             // 嵌套 SVM 状态（AMD）
    BOOLEAN IsInL2;                         // 当前是否在 L2 Guest 中运行

    // === Guest 状态保存 ===
    VCPU_STATE GuestState;
    ULONG64 HostRsp;
    ULONG64 HostRip;
    ULONG64 RestoreRsp;
    ULONG64 RestoreRip;
    ULONG64 RestoreRbx;
    ULONG64 RestoreRbp;
    ULONG64 RestoreRsi;
    ULONG64 RestoreRdi;
    ULONG64 RestoreR12;
    ULONG64 RestoreR13;
    ULONG64 RestoreR14;
    ULONG64 RestoreR15;

    // === 阶段 8.5 真·VT V2: 独立 PT 岛 gadget (per-VCPU slice) ===
    // 见 HvVtRoot.c 注释: 在 kernel CR3 一个未使用 PML4 槽位插入完全私有的
    // PDPT/PD/PT 链。Scratch VA 不在任何 VAD/PFN 反向映射中,MM 子系统看不见。
    // 私有 PT 内每个 CPU 占一个 entry,root 模式只改自己的 entry → invlpg
    // 自己的 ScratchVa → memcpy。零 Mm*/Ke*/Ps* 介入。
    struct {
        PVOID    ScratchVa;         // 该 CPU 私有的 4KB scratch VA
        UINT64*  ScratchPtePtr;     // PT 内对应这个 CPU 的 entry 指针
        UINT64   BackingPagePa;     // 空闲时 PT entry 指向这里
        BOOLEAN  Initialized;
    } VtRootGadget;

    // === 阶段 7.9: 硬件 TSC 偏移补偿 (per-VCPU) ===
    // 记录每次 VM-Exit 入口的 host TSC 快照,VM-Entry 前累积补偿,
    // 然后写入 VMCS_CTRL_TSC_OFFSET / VMCB.TscOffset。
    // 用 INT64:guest 视角 TSC = real_TSC + Compensation,需要负值。
    UINT64 LastVmExitHostTsc;       // VM-Exit 入口 __rdtsc() 快照
    INT64  TscOffsetCompensation;   // 累积 host 处理时间,符号为负

    // (撤回 P134/P135: HostPt 字段已删除)

    // === P117: per-CPU HWBP 快照 (lockless CR3-Load hot path) ===
    // CR3-Load vmexit 路径 100k+/秒, 不能拿 spinlock 不能遍历 list. 这里缓存当前
    // 关心的 target CR3 + 4 个 DR + DR7. Set/Clear API 改完全局 list 后用 IPI 广播
    // 让每个 CPU 拷贝快照到这里. hot path 只比一个 u64.
    struct {
        // bit0=1 表示该 CPU 当前要看 HwbpTargetCr3Base 这个进程; CR3-Load 时只比一下这个字段
        // 用 volatile + InterlockedExchange64 同步, 写时不阻塞读 (写者是 IPI dispatcher, 抢占当前 CPU)
        volatile LONG    HwbpActive;
        UINT64           HwbpTargetCr3Base;  // 已 mask 掉低 12 bit
        UINT64           HwbpDr0;
        UINT64           HwbpDr1;
        UINT64           HwbpDr2;
        UINT64           HwbpDr3;
        UINT64           HwbpDr7;            // 已含 bit10 保留位
    } HwbpShadow;
} VCPU_DATA, * PVCPU_DATA;

// 全局Hypervisor上下文
typedef struct _HYPERVISOR_CONTEXT {
    ULONG ProcessorCount;
    PVCPU_DATA VcpuData;
    BOOLEAN IsActive;
} HYPERVISOR_CONTEXT, * PHYPERVISOR_CONTEXT;

// ==================== 全局变量声明 ====================

extern HYPERVISOR_CONTEXT g_HypervisorContext;
extern volatile BOOLEAN g_VmxTerminated;

// 汇编中定义的变量（AsmVmx.asm）
extern ULONG64 g_AsmRestoreRsp;
extern ULONG64 g_AsmRestoreRip;
extern volatile ULONG64 g_AsmDebugFlag;  // volatile 避免 C 编译器把 flag 赋值重排或合并
extern ULONG64 g_VmExitCounter;
extern ULONG64 g_LastExitReason;
extern ULONG64 g_VmInstructionError;
extern ULONG64 g_UnknownExitReason;
extern ULONG64 g_ExitCountCpuid;
extern ULONG64 g_ExitCountMsrRead;
extern ULONG64 g_ExitCountMsrWrite;
extern ULONG64 g_ExitCountCrAccess;
extern ULONG64 g_ExitCountException;
extern ULONG64 g_ExitCountVmcall;
extern ULONG64 g_ExitCountEptViolation;
extern ULONG64 g_ExitCountOther;
extern ULONG64 g_ExternalInterruptCount;
extern ULONG64 g_InterruptWindowExitCount;

// Intel VMX 汇编函数声明 (AsmVmx.asm)
extern VOID AsmVmExitHandler(VOID);
extern int AsmVmLaunchAndSaveState(PVCPU_DATA VcpuData);
extern VOID AsmVmCall(ULONG64 HypercallNumber);
extern ULONG64 AsmVmCallWithResult(ULONG64 HypercallNumber);
extern UCHAR AsmInveptAllContexts(VOID);
extern UCHAR AsmInveptSingleContext(ULONG64 Eptp);
extern UCHAR AsmInvvpidAllContexts(VOID);

// AMD SVM 汇编函数声明 (AsmSvm.asm)
extern VOID AsmSvmVmExitHandler(VOID);
extern int AsmSvmLaunch(PVCPU_DATA VcpuData);
extern VOID AsmVmmcall(ULONG64 HypercallNumber);
extern ULONG64 AsmVmmcallWithResult(ULONG64 HypercallNumber);
extern VOID AsmStgi(VOID);      // Set Global Interrupt Flag
extern VOID AsmClgi(VOID);      // Clear Global Interrupt Flag
extern VOID AsmSvmVmsave(ULONG64 VmcbPa);
extern VOID AsmSvmVmload(ULONG64 VmcbPa);
extern VOID AsmSvmVmrun(ULONG64 VmcbPa);

// ==================== 内核模块/驱动结构 ====================

// KLDR_DATA_TABLE_ENTRY - 内核加载模块链表条目
typedef struct _KLDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    PVOID ExceptionTable;
    ULONG ExceptionTableSize;
    PVOID GpValue;
    struct _NON_PAGED_DEBUG_INFO* NonPagedDebugInfo;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    USHORT __Unused5;
    PVOID SectionPointer;
    ULONG CheckSum;
    ULONG TimeDateStamp;
    PVOID LoadedImports;
    PVOID EntryPointActivationContext;
    PVOID PatchInformation;
} KLDR_DATA_TABLE_ENTRY, *PKLDR_DATA_TABLE_ENTRY;

// RTL_PROCESS_MODULE_INFORMATION - SystemModuleInformation 返回的模块信息
typedef struct _HV_RTL_PROCESS_MODULE_INFORMATION {
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
} HV_RTL_PROCESS_MODULE_INFORMATION, *PHV_RTL_PROCESS_MODULE_INFORMATION;

typedef struct _HV_RTL_PROCESS_MODULES {
    ULONG NumberOfModules;
    HV_RTL_PROCESS_MODULE_INFORMATION Modules[1];
} HV_RTL_PROCESS_MODULES, *PHV_RTL_PROCESS_MODULES;

// ==================== PE 结构定义 ====================

// PE Magic 常量
#define HV_IMAGE_DOS_SIGNATURE      0x5A4D      // MZ
#define HV_IMAGE_NT_SIGNATURE       0x00004550  // PE\0\0
#define HV_IMAGE_NT_OPTIONAL_HDR64_MAGIC 0x20b

// DOS Header
typedef struct _HV_IMAGE_DOS_HEADER {
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
    LONG   e_lfanew;
} HV_IMAGE_DOS_HEADER, *PHV_IMAGE_DOS_HEADER;

// File Header
typedef struct _HV_IMAGE_FILE_HEADER {
    USHORT Machine;
    USHORT NumberOfSections;
    ULONG  TimeDateStamp;
    ULONG  PointerToSymbolTable;
    ULONG  NumberOfSymbols;
    USHORT SizeOfOptionalHeader;
    USHORT Characteristics;
} HV_IMAGE_FILE_HEADER, *PHV_IMAGE_FILE_HEADER;

// Data Directory
typedef struct _HV_IMAGE_DATA_DIRECTORY {
    ULONG VirtualAddress;
    ULONG Size;
} HV_IMAGE_DATA_DIRECTORY, *PHV_IMAGE_DATA_DIRECTORY;

// Optional Header (64-bit)
typedef struct _HV_IMAGE_OPTIONAL_HEADER64 {
    USHORT Magic;
    UCHAR  MajorLinkerVersion;
    UCHAR  MinorLinkerVersion;
    ULONG  SizeOfCode;
    ULONG  SizeOfInitializedData;
    ULONG  SizeOfUninitializedData;
    ULONG  AddressOfEntryPoint;
    ULONG  BaseOfCode;
    ULONGLONG ImageBase;
    ULONG  SectionAlignment;
    ULONG  FileAlignment;
    USHORT MajorOperatingSystemVersion;
    USHORT MinorOperatingSystemVersion;
    USHORT MajorImageVersion;
    USHORT MinorImageVersion;
    USHORT MajorSubsystemVersion;
    USHORT MinorSubsystemVersion;
    ULONG  Win32VersionValue;
    ULONG  SizeOfImage;
    ULONG  SizeOfHeaders;
    ULONG  CheckSum;
    USHORT Subsystem;
    USHORT DllCharacteristics;
    ULONGLONG SizeOfStackReserve;
    ULONGLONG SizeOfStackCommit;
    ULONGLONG SizeOfHeapReserve;
    ULONGLONG SizeOfHeapCommit;
    ULONG  LoaderFlags;
    ULONG  NumberOfRvaAndSizes;
    HV_IMAGE_DATA_DIRECTORY DataDirectory[16];
} HV_IMAGE_OPTIONAL_HEADER64, *PHV_IMAGE_OPTIONAL_HEADER64;

// NT Headers (64-bit)
typedef struct _HV_IMAGE_NT_HEADERS64 {
    ULONG Signature;
    HV_IMAGE_FILE_HEADER FileHeader;
    HV_IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} HV_IMAGE_NT_HEADERS64, *PHV_IMAGE_NT_HEADERS64;

// Section Header
typedef struct _HV_IMAGE_SECTION_HEADER {
    UCHAR  Name[8];
    union {
        ULONG PhysicalAddress;
        ULONG VirtualSize;
    } Misc;
    ULONG  VirtualAddress;
    ULONG  SizeOfRawData;
    ULONG  PointerToRawData;
    ULONG  PointerToRelocations;
    ULONG  PointerToLinenumbers;
    USHORT NumberOfRelocations;
    USHORT NumberOfLinenumbers;
    ULONG  Characteristics;
} HV_IMAGE_SECTION_HEADER, *PHV_IMAGE_SECTION_HEADER;

// Import Descriptor
typedef struct _HV_IMAGE_IMPORT_DESCRIPTOR {
    union {
        ULONG Characteristics;
        ULONG OriginalFirstThunk;
    };
    ULONG TimeDateStamp;
    ULONG ForwarderChain;
    ULONG Name;
    ULONG FirstThunk;
} HV_IMAGE_IMPORT_DESCRIPTOR, *PHV_IMAGE_IMPORT_DESCRIPTOR;

// Import By Name
typedef struct _HV_IMAGE_IMPORT_BY_NAME {
    USHORT Hint;
    CHAR   Name[1];
} HV_IMAGE_IMPORT_BY_NAME, *PHV_IMAGE_IMPORT_BY_NAME;

// Base Relocation
typedef struct _HV_IMAGE_BASE_RELOCATION {
    ULONG VirtualAddress;
    ULONG SizeOfBlock;
} HV_IMAGE_BASE_RELOCATION, *PHV_IMAGE_BASE_RELOCATION;

// TLS Directory (64-bit)
typedef struct _HV_IMAGE_TLS_DIRECTORY64 {
    ULONGLONG StartAddressOfRawData;
    ULONGLONG EndAddressOfRawData;
    ULONGLONG AddressOfIndex;
    ULONGLONG AddressOfCallBacks;
    ULONG SizeOfZeroFill;
    ULONG Characteristics;
} HV_IMAGE_TLS_DIRECTORY64, *PHV_IMAGE_TLS_DIRECTORY64;

// Export Directory
typedef struct _HV_IMAGE_EXPORT_DIRECTORY {
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
} HV_IMAGE_EXPORT_DIRECTORY, *PHV_IMAGE_EXPORT_DIRECTORY;

// Relocation 类型
#define HV_IMAGE_REL_BASED_ABSOLUTE     0
#define HV_IMAGE_REL_BASED_HIGH         1
#define HV_IMAGE_REL_BASED_LOW          2
#define HV_IMAGE_REL_BASED_HIGHLOW      3
#define HV_IMAGE_REL_BASED_DIR64        10

// 数据目录索引
#define HV_IMAGE_DIRECTORY_ENTRY_EXPORT          0
#define HV_IMAGE_DIRECTORY_ENTRY_IMPORT          1
#define HV_IMAGE_DIRECTORY_ENTRY_RESOURCE        2
#define HV_IMAGE_DIRECTORY_ENTRY_EXCEPTION       3
#define HV_IMAGE_DIRECTORY_ENTRY_SECURITY        4
#define HV_IMAGE_DIRECTORY_ENTRY_BASERELOC       5
#define HV_IMAGE_DIRECTORY_ENTRY_DEBUG           6
#define HV_IMAGE_DIRECTORY_ENTRY_ARCHITECTURE    7
#define HV_IMAGE_DIRECTORY_ENTRY_GLOBALPTR       8
#define HV_IMAGE_DIRECTORY_ENTRY_TLS             9
#define HV_IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    10
#define HV_IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   11
#define HV_IMAGE_DIRECTORY_ENTRY_IAT            12
#define HV_IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   13
#define HV_IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14

#endif // _HV_TYPES_H_
