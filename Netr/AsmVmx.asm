;
; AsmVmx.asm - VMX 汇编核心代码（精简版）
;
; 只包含必须用汇编实现的功能：
; 1. 段寄存器读取（MSVC 没有 intrinsic）
; 2. VM Exit Handler 入口（寄存器保存/恢复）
; 3. VMLAUNCH 入口
; 4. 特权指令包装（VMCALL, INVEPT 等）
;
; 所有 VM Exit 处理逻辑已移至 C 代码（HvVmExit.c）
;

.DATA

; ==================== 全局变量 ====================

; 调试标志
PUBLIC g_AsmDebugFlag
g_AsmDebugFlag DQ 0

; 恢复点（用于 VMXOFF 后返回）
PUBLIC g_AsmRestoreRsp
PUBLIC g_AsmRestoreRip
g_AsmRestoreRsp DQ 0
g_AsmRestoreRip DQ 0

; VM Exit 统计
PUBLIC g_VmExitCounter
PUBLIC g_LastExitReason
PUBLIC g_VmInstructionError
g_VmExitCounter DQ 0
g_LastExitReason DQ 0
g_VmInstructionError DQ 0

; 退出类型计数器
PUBLIC g_ExitCountCpuid
PUBLIC g_ExitCountMsrRead
PUBLIC g_ExitCountMsrWrite
PUBLIC g_ExitCountCrAccess
PUBLIC g_ExitCountException
PUBLIC g_ExitCountVmcall
PUBLIC g_ExitCountEptViolation
PUBLIC g_ExitCountOther
PUBLIC g_ExternalInterruptCount
PUBLIC g_InterruptWindowExitCount
PUBLIC g_UnknownExitReason

g_ExitCountCpuid DQ 0
g_ExitCountMsrRead DQ 0
g_ExitCountMsrWrite DQ 0
g_ExitCountCrAccess DQ 0
g_ExitCountException DQ 0
g_ExitCountVmcall DQ 0
g_ExitCountEptViolation DQ 0
g_ExitCountOther DQ 0
g_ExternalInterruptCount DQ 0
g_InterruptWindowExitCount DQ 0
g_UnknownExitReason DQ 0

; DIAG-3 (2026-05-31): 第一次 vmexit 的诊断快照 (自终止 handler 填)
PUBLIC g_DiagFirstExitReason
PUBLIC g_DiagFirstExitQual
PUBLIC g_DiagFirstGuestRip
PUBLIC g_DiagFirstInstrLen
PUBLIC g_DiagFirstExitIntrInfo
PUBLIC g_DiagVmxInstrError
g_DiagFirstExitReason   DQ 0
g_DiagFirstExitQual     DQ 0
g_DiagFirstGuestRip     DQ 0
g_DiagFirstInstrLen     DQ 0
g_DiagFirstExitIntrInfo DQ 0
g_DiagVmxInstrError     DQ 0

.CODE

; ==================== 外部 C 函数 ====================

EXTERN HvVmExitDispatch:PROC

; ==================== VMCS 字段编码 ====================

GUEST_RSP_ENCODING EQU 0681Ch
GUEST_RIP_ENCODING EQU 0681Eh
GUEST_RFLAGS_ENCODING EQU 06820h
VM_EXIT_INSTRUCTION_LEN_ENCODING EQU 0440Ch

; ==================== 栈偏移常量 ====================
; HOST_RSP 指向 VmExitStack + 0x10000 - 0x80
; 预留区域布局：
VCPU_DATA_OFFSET    EQU 078h    ; VcpuData 指针
RESTORE_RSP_OFFSET  EQU 070h    ; 恢复栈指针
RESTORE_RIP_OFFSET  EQU 068h    ; 恢复返回地址
RESTORE_RFLAGS_OFFSET EQU 060h  ; 恢复 RFLAGS
RESTORE_RBX_OFFSET  EQU 058h
RESTORE_RBP_OFFSET  EQU 050h
RESTORE_RSI_OFFSET  EQU 048h
RESTORE_RDI_OFFSET  EQU 040h
RESTORE_R12_OFFSET  EQU 038h
RESTORE_R13_OFFSET  EQU 030h
RESTORE_R14_OFFSET  EQU 028h
RESTORE_R15_OFFSET  EQU 020h
PENDING_INTR_OFFSET EQU 018h

; ==================== 段寄存器读取函数 ====================
; 这些必须用汇编，因为 MSVC 没有提供 intrinsic

PUBLIC __readcs
__readcs PROC
    mov     ax, cs
    ret
__readcs ENDP

PUBLIC __readss
__readss PROC
    mov     ax, ss
    ret
__readss ENDP

PUBLIC __readds
__readds PROC
    mov     ax, ds
    ret
__readds ENDP

PUBLIC __reades
__reades PROC
    mov     ax, es
    ret
__reades ENDP

PUBLIC __readfs
__readfs PROC
    mov     ax, fs
    ret
__readfs ENDP

PUBLIC __readgs
__readgs PROC
    mov     ax, gs
    ret
__readgs ENDP

PUBLIC __readldtr
__readldtr PROC
    sldt    ax
    ret
__readldtr ENDP

PUBLIC __readtr
__readtr PROC
    str     ax
    ret
__readtr ENDP

; ----------------------------------------------------------------
; P2-4: LAR-based segment access rights (HyperDbg 范式)
;
; ULONG AsmGetAccessRights(USHORT Selector);
;   入参 RCX = selector
;   返回 RAX = LAR 结果 (segment access rights, ZF=1 时合法)
;          0 = selector 不可达 (LAR 失败 ZF=0,或 selector=0)
;
; LAR 指令读取段描述符的 access-rights byte 到 dst 寄存器 bits 8-15
; (Type+S+DPL+P) + bits 20-23 (AVL+L+D+G)。调用方再 >> 8 得到 VMCS
; ACCESS_RIGHTS 字段格式 (bits 0-7 = Type+S+DPL+P, bits 12-15 = AVL+L+D+G)。
;
; LAR 自带 selector 可达性检查 (segment present、不超 GDT 范围、DPL/RPL):
; 失败时 ZF=0,我们直接返回 0,调用方据此设 Unusable=1。
; ----------------------------------------------------------------
PUBLIC AsmGetAccessRights
AsmGetAccessRights PROC
    lar     rax, rcx        ; LAR: ZF=1 成功, ZF=0 不可达
    jz      LarOk
    xor     rax, rax        ; 失败返回 0 (caller 看 0 知道 unusable)
LarOk:
    ret
AsmGetAccessRights ENDP

; ==================== Host IDT NMI / #MC Stub ====================
;
; P0-4 (2026-05-31): 替换 Windows IDT 的 NMI(2) / #MC(18) handler, 避免
; 在 vmx-root 模式 NMI 被分派到 KiNmiInterrupt: 后者用 GS:[KPRCB.IdleThread]
; 等 KPCR 字段, Win11 24H2 KCFG 严苛校验, 在 hypervisor 栈 + 不一致 KPRCB
; 状态下 100% triple fault 静默卡死。
;
; Stub 设计原则: 不调任何 indirect/相对 call, 不修改非 RFLAGS 之外的寄存器
; (RFLAGS 在 IRETQ 自动恢复), 只做计数 + IRETQ。host 在 vmx-root 期间发生的
; NMI 被吞掉是有意的: hypervisor 自己不会触发 NMI, 所以 vmx-root 期间收到的
; NMI 都是 hardware watchdog / SMI inject, 我们丢掉它们让 system 继续运行。
;
; Win10 上 NMI 频率几乎 0, Win11 KeFreezeExecution / KiVerifyScopesExecutionTimeAttribution
; 高频, 这正是 Win10 OK / Win11 卡死的核心差异。

EXTERN g_HvHostNmiCount:QWORD
EXTERN g_HvHostMceCount:QWORD
EXTERN g_HvHostDfCount:QWORD
EXTERN g_HvHostGpCount:QWORD

PUBLIC AsmHostNmiStub
AsmHostNmiStub PROC
    ; NMI 进入: CPU 自动 push ss/rsp/rflags/cs/rip (40 字节, 无 error code).
    ; lock inc 修改 RFLAGS 但 iretq 恢复 host RFLAGS, 无后遗症。
    lock inc QWORD PTR g_HvHostNmiCount
    iretq
AsmHostNmiStub ENDP

PUBLIC AsmHostMceStub
AsmHostMceStub PROC
    ; #MC (Machine Check Abort, vector 18) 也无 error code.
    ; 严格 fault-class abort 不可恢复, 但我们计数后 IRETQ 至少避免 triple,
    ; 让 system 可能继续运行 (实际上 #MC 很罕见, 真触发可能硬件已经死)。
    lock inc QWORD PTR g_HvHostMceCount
    iretq
AsmHostMceStub ENDP

PUBLIC AsmHostDfStub
AsmHostDfStub PROC
    ; #DF (Double Fault, vector 8) 有 error code (固定 0), CPU push 48 字节.
    ; abort-class, 任何 iretq 行为都未定义, 但至少避免 triple → 整机重启。
    ; 用 IST3 → 进入时 RSP 已切到 per-CPU IstDfStack 栈顶, 0x1AA 不会触发。
    lock inc QWORD PTR g_HvHostDfCount
    add     rsp, 8        ; 丢掉 error code
    iretq
AsmHostDfStub ENDP

; ==================== AsmSafeReadMsr / AsmSafeWriteMsr (vmx-root 安全 MSR 读写) ====================
;
; 2026-06-16: 解决真 0x1AA 根因 + 反 VM 检测透明化。
; vmx-root 模式下 __readmsr 透传非法 MSR → #GP, SEH 栈展开因 host RSP 不在 Windows
; 已登记栈区间 → RtlpGetStackLimitsEx → 0x1AA。用裸 stub 配可识别 trap RIP 拦截。
; #GP 时通过 GpRaised 输出告诉调用者, 调用者把 #GP 反射回 guest, 使 guest 行为
; 与 bare metal 完全一致 (避免 ACE 反 VM 检测识破)。
;
; 调用约定 (Windows x64):
;   ULONG64 AsmSafeReadMsr(ULONG32 Msr, OUT BOOLEAN* GpRaised)
;          RCX = Msr,  RDX = GpRaised 指针
;          成功: 返回 RAX = MSR value, *GpRaised = 0
;          #GP:  返回 RAX = 0,        *GpRaised = 1
;
;   BOOLEAN AsmSafeWriteMsr(ULONG32 Msr, ULONG32 Lo, ULONG32 Hi)
;          RCX = Msr, EDX = Lo, R8D = Hi
;          返回 EAX = 1 成功, 0 = #GP

PUBLIC AsmSafeReadMsr
PUBLIC AsmSafeReadMsrRdmsrLabel
PUBLIC AsmSafeReadMsrGpLabel
AsmSafeReadMsr PROC
    ; RCX = Msr (Windows ABI), RDX = GpRaised pointer
    mov     r10, rdx                      ; 保存指针 (rdx 会被 rdmsr 覆盖)
    mov     BYTE PTR [r10], 0             ; 默认 *GpRaised = 0
    mov     ecx, ecx                      ; ECX = msr (形式上确认)
AsmSafeReadMsrRdmsrLabel LABEL NEAR
    rdmsr                                 ; ← 可能 #GP, AsmHostGpStub 看到此 RIP 跳 GpLabel
    shl     rdx, 20h
    or      rax, rdx
    ret
AsmSafeReadMsrGpLabel LABEL NEAR
    mov     BYTE PTR [r10], 1             ; *GpRaised = 1
    xor     eax, eax
    xor     edx, edx
    ret
AsmSafeReadMsr ENDP

PUBLIC AsmSafeWriteMsr
PUBLIC AsmSafeWriteMsrWrmsrLabel
PUBLIC AsmSafeWriteMsrGpLabel
AsmSafeWriteMsr PROC
    ; RCX = Msr (ECX 已就位), EDX = Lo, R8D = Hi
    mov     eax, edx                      ; EAX = Lo (wrmsr 要求 EDX:EAX)
    mov     edx, r8d                      ; EDX = Hi
AsmSafeWriteMsrWrmsrLabel LABEL NEAR
    wrmsr                                 ; ← 可能 #GP
    mov     eax, 1                        ; 成功返回 1
    ret
AsmSafeWriteMsrGpLabel LABEL NEAR
    xor     eax, eax                      ; #GP 返回 0
    ret
AsmSafeWriteMsr ENDP

; ==================== AsmHostGpStub (Host IDT vector 13 #GP handler) ====================
;
; #GP 进入: CPU push error_code (8 字节 padded) + RIP/CS/RFLAGS/RSP/SS (5 qwords).
; 栈布局 (相对 RSP):
;   [rsp+0]   error code
;   [rsp+8]   trap RIP
;   [rsp+16]  trap CS
;   [rsp+24]  trap RFLAGS
;   [rsp+32]  trap RSP
;   [rsp+40]  trap SS
;
; ===== Step 1 (虚幻调试器范式): r10/r11 软异常通用救生圈 =====
;
; 优先级:
;   1) 看 r10 && r11 (虚幻范式 — 通用软异常协议)
;        → 改栈上 RIP=r10, 写 *r11 = {ExceptionOccurred=1, Vector=13, Error=error_code},
;          清零 r10/r11 防止无限异常, 丢 error_code, iretq.
;   2) 比对 trap RIP 是否落在 AsmSafeReadMsrRdmsrLabel / AsmSafeWriteMsrWrmsrLabel
;        (Netr 老路径, 兼容现有 AsmSafeReadMsr/AsmSafeWriteMsr 调用方)
;   3) 都不匹配: 未知 #GP, 计数后 iretq (RIP 不变, 会再次 #GP 但 GpCount 暴涨可定位)
;
; HV_HOST_EXC_INFO 内存布局 (见 HvHostExc.h, 24 字节 pack):
;   +0  UCHAR  ExceptionOccurred
;   +1..7      Pad0[7]
;   +8  UINT64 Vector
;   +16 UINT64 ErrorCode

PUBLIC AsmHostGpStub
AsmHostGpStub PROC
    lock inc QWORD PTR g_HvHostGpCount

    ; ---- (1) r10/r11 通用救生圈 (虚幻范式) ----
    test    r10, r10
    jz      _GpSkipR10R11
    test    r11, r11
    jz      _GpSkipR10R11

    ; r10 = ehandler RIP, r11 = HV_HOST_EXC_INFO*
    mov     rax, QWORD PTR [rsp + 0]       ; rax = error code
    mov     BYTE  PTR [r11 + 0],  1        ; ExceptionOccurred = 1
    mov     QWORD PTR [r11 + 8],  13       ; Vector = 13 (#GP)
    mov     QWORD PTR [r11 + 16], rax      ; ErrorCode

    mov     QWORD PTR [rsp + 8], r10       ; 栈上 RIP ← r10 (跳 stub 内的 ehandler)
    xor     r10, r10                       ; 清 r10/r11 防止无限异常
    xor     r11, r11
    add     rsp, 8                         ; 丢 error code
    iretq

_GpSkipR10R11:
    ; ---- (2) Netr 老 SafeMsr RIP 比对路径 (向后兼容) ----
    mov     rax, QWORD PTR [rsp + 8]
    lea     rcx, AsmSafeReadMsrRdmsrLabel
    cmp     rax, rcx
    jne     _GpTryWrite
    lea     rcx, AsmSafeReadMsrGpLabel
    mov     QWORD PTR [rsp + 8], rcx
    add     rsp, 8                         ; 丢 error code
    iretq

_GpTryWrite:
    lea     rcx, AsmSafeWriteMsrWrmsrLabel
    cmp     rax, rcx
    jne     _GpUnknown
    lea     rcx, AsmSafeWriteMsrGpLabel
    mov     QWORD PTR [rsp + 8], rcx
    add     rsp, 8
    iretq

_GpUnknown:
    ; ---- (3) 未知 #GP — 不是 SafeMsr 路径也没 r10/r11 协议。
    ; 计数后丢 error code + iretq。RIP 不变会再次 #GP 进死循环,
    ; 但 diag.exe 看到 GpCount 暴涨能立刻定位问题点。
    add     rsp, 8
    iretq
AsmHostGpStub ENDP

; ==================== AsmHostPfStub (Host IDT vector 14 #PF handler) ====================
;
; Step 1 新增. 虚幻范式: 任何 vec 都用同一套 r10/r11 协议接住.
; Netr 之前没装 #PF host handler, host 内访问 page-out / 非法 GVA → KiPageFault →
; (HOST_CR3 不一定能映射 KiPageFault 代码) → triple fault. 现在 #PF 也走 r10/r11.
;
; #PF 进入: CPU push error_code + 5 qword machine frame, CR2 由 CPU 自动设置 (我们暂不读 CR2).
;
; 计数器: 借用 g_HvHostGpCount (诊断可看到 host #PF 频次)? 不, 新增 g_HvHostPfCount 更干净.

EXTERN g_HvHostPfCount:QWORD

PUBLIC AsmHostPfStub
AsmHostPfStub PROC
    lock inc QWORD PTR g_HvHostPfCount

    ; ---- r10/r11 通用救生圈 ----
    test    r10, r10
    jz      _PfUnknown
    test    r11, r11
    jz      _PfUnknown

    mov     rax, QWORD PTR [rsp + 0]       ; rax = #PF error code (PFEC)
    mov     BYTE  PTR [r11 + 0],  1
    mov     QWORD PTR [r11 + 8],  14       ; Vector = 14 (#PF)
    mov     QWORD PTR [r11 + 16], rax      ; ErrorCode = PFEC

    mov     QWORD PTR [rsp + 8], r10
    xor     r10, r10
    xor     r11, r11
    add     rsp, 8                         ; 丢 error code
    iretq

_PfUnknown:
    ; 未知 host #PF — 没人在 stub 路径里. 这是真正的"host PT 不完整"问题.
    ; 计数 + iretq, RIP 不变会再次 #PF 死循环, PfCount 暴涨可定位.
    add     rsp, 8
    iretq
AsmHostPfStub ENDP

; ==================== AsmMemcpySafe (虚幻范式 r10/r11 软异常 memcpy) ====================
;
; 入参 (Windows x64 ABI):
;   RCX = HV_HOST_EXC_INFO*   (24 字节, stub 入口写 byte 0 = 0)
;   RDX = dst
;   R8  = src
;   R9  = size
;
; 实现: 走 rep movsb. 任何字节 #PF → AsmHostPfStub 通过 r10/r11 协议
; 把 RIP 跳到 _AsmMemcpySafeEhandler, 同时写 ExceptionOccurred=1.
;
; 返回: ULONG = 0 normal, 1 fault (调用方主要看 Info->ExceptionOccurred,
;       返回值仅做辅助校验, e.g. Info 被 corrupt 时仍可看 EAX).
;
; 保存 RSI/RDI (Windows non-volatile).

PUBLIC AsmMemcpySafe
PUBLIC _AsmMemcpySafeEhandler
AsmMemcpySafe PROC
    ; 设置 r10/r11 软异常路径
    lea     r10, _AsmMemcpySafeEhandler
    mov     r11, rcx                       ; r11 = HV_HOST_EXC_INFO*
    mov     BYTE PTR [rcx + 0], 0          ; Info->ExceptionOccurred = 0

    ; 保存 rsi/rdi
    push    rsi
    push    rdi

    mov     rdi, rdx                       ; rdi = dst
    mov     rsi, r8                        ; rsi = src
    mov     rcx, r9                        ; rcx = count
    cld
    rep movsb
    ; 如果 movsb 内 #PF, AsmHostPfStub 会改 RIP = _AsmMemcpySafeEhandler,
    ; 此时 rsi/rdi/rcx 不可信但栈上已 push 过, ehandler 内 pop 恢复.

_AsmMemcpySafeEhandler LABEL NEAR
    pop     rdi
    pop     rsi

    ; 清 r10/r11 (虚幻范式: stub 出口防止 IDT handler 误判 "仍在 stub 内")
    xor     r10, r10
    xor     r11, r11

    ; 返回值: 读 Info->ExceptionOccurred. 但 r11 已被清, 这里 fast path 直接 xor eax,
    ; ehandler 实际取值通过 Info* 给调用方查 (调用方持有原 Info 指针).
    xor     eax, eax
    ret
AsmMemcpySafe ENDP

; ==================== VM Exit Handler ====================
;
; 入口点：由 HOST_RIP 指向
; 功能：保存 Guest 寄存器 -> 调用 C 函数 -> 恢复寄存器 -> VMRESUME
;
; 栈布局（GUEST_CONTEXT 结构）：
;   [RSP+0]   = RAX    [RSP+56]  = R8     [RSP+112] = R15
;   [RSP+8]   = RBX    [RSP+64]  = R9
;   [RSP+16]  = RCX    [RSP+72]  = R10
;   [RSP+24]  = RDX    [RSP+80]  = R11
;   [RSP+32]  = RSI    [RSP+88]  = R12
;   [RSP+40]  = RDI    [RSP+96]  = R13
;   [RSP+48]  = RBP    [RSP+104] = R14
;

; XMM 保存区大小（16 个 XMM × 16 字节）+ 8 字节对齐 padding
; P1-7 (2026-05-31): MXCSR 复用对齐 padding 前 4 字节 [rsp + 0x100], 总大小不变。
;
; **关键约束**: 15 push 后 RSP mod 16 = 8, 必须 sub mod 16 = 8 才能让 movaps
; 看到 16-byte aligned RSP。0x108 mod 16 = 8 ✓, 0x110 mod 16 = 0 ✗ (导致 #GP)。
; 历史教训: 首版 P1-7 改成 0x110 触发 movaps #GP → bugcheck 0x1E_C000001D
; (RtlpxVirtualUnwind / KiGeneralProtectionFault 雪崩 from AsmVmExitHandler+0x29)。
XMM_SAVE_SIZE       EQU 100h        ; 256 bytes
XMM_SAVE_TOTAL      EQU 108h        ; 256 + 8 padding (保持 mod 16 = 8)
MXCSR_SAVE_OFFSET   EQU 100h        ; MXCSR 槽 [rsp + 0x100], 占 padding 前 4 字节

PUBLIC AsmVmExitHandler
AsmVmExitHandler PROC

    ; 入口标记: vmlaunch 进了 guest, 然后 VM-Exit 回来到 host
    mov     QWORD PTR g_AsmDebugFlag, 20

    ; === 第1步：保存所有 Guest GPR 到栈 ===
    ; 入口 RSP = HOST_RSP，HvSetupVmcsHostState 已确保 16 字节对齐
    push    r15
    push    r14
    push    r13
    push    r12
    push    r11
    push    r10
    push    r9
    push    r8
    push    rbp
    push    rdi
    push    rsi
    push    rdx
    push    rcx
    push    rbx
    push    rax
    ; 15 push × 8 = 120 字节，RSP mod 16 == 8

    ; === 第1.5步：保存 XMM0-XMM15 ===
    ; movaps 需要 16 字节对齐：先 sub 8 字节对齐，再分配 256 字节 XMM 区
    sub     rsp, XMM_SAVE_TOTAL         ; -264：8 字节对齐 + 256 字节 XMM 区
    ; 现在 RSP mod 16 == 0
    movaps  xmmword ptr [rsp + 0],   xmm0
    movaps  xmmword ptr [rsp + 16],  xmm1
    movaps  xmmword ptr [rsp + 32],  xmm2
    movaps  xmmword ptr [rsp + 48],  xmm3
    movaps  xmmword ptr [rsp + 64],  xmm4
    movaps  xmmword ptr [rsp + 80],  xmm5
    movaps  xmmword ptr [rsp + 96],  xmm6
    movaps  xmmword ptr [rsp + 112], xmm7
    movaps  xmmword ptr [rsp + 128], xmm8
    movaps  xmmword ptr [rsp + 144], xmm9
    movaps  xmmword ptr [rsp + 160], xmm10
    movaps  xmmword ptr [rsp + 176], xmm11
    movaps  xmmword ptr [rsp + 192], xmm12
    movaps  xmmword ptr [rsp + 208], xmm13
    movaps  xmmword ptr [rsp + 224], xmm14
    movaps  xmmword ptr [rsp + 240], xmm15

    ; P1-7: 保存 MXCSR (4 字节, 控制 SSE 异常掩码 / 舍入模式)
    ; C 端 dispatch 路径里 KeRaiseIrql / DbgPrint indirect 可能改 MXCSR,
    ; 不保存会污染 guest 的 SSE 状态导致用户进程 FPU 异常行为漂移。
    stmxcsr DWORD PTR [rsp + MXCSR_SAVE_OFFSET]

    ; VM Exit 计数（C 端 InterlockedIncrement 重复，这里保留旧行为）
    lock inc QWORD PTR g_VmExitCounter

    ; === 第2步：调用 C 函数处理 ===
    ; BOOLEAN HvVmExitDispatch(PGUEST_CONTEXT GuestContext)
    ; RCX 指向 GUEST_CONTEXT（GPR 区）：跳过 XMM_SAVE_TOTAL = 264
    lea     rcx, [rsp + XMM_SAVE_TOTAL]

    ; 分配 shadow space。当前 RSP mod 16 == 0，sub 0x20 保持 mod 16 == 0
    ; call 后 callee 入口 RSP mod 16 == 8（符合 x64 ABI）
    sub     rsp, 20h

    call    HvVmExitDispatch

    add     rsp, 20h

    ; === 第3步：检查返回值 ===
    test    al, al
    jz      VmExitTerminate

    ; === 第4步：恢复 XMM ===
    ; P1-7: 先恢复 MXCSR 再恢复 XMM (顺序无关, 但保持对称)
    ldmxcsr DWORD PTR [rsp + MXCSR_SAVE_OFFSET]
    movaps  xmm0,  xmmword ptr [rsp + 0]
    movaps  xmm1,  xmmword ptr [rsp + 16]
    movaps  xmm2,  xmmword ptr [rsp + 32]
    movaps  xmm3,  xmmword ptr [rsp + 48]
    movaps  xmm4,  xmmword ptr [rsp + 64]
    movaps  xmm5,  xmmword ptr [rsp + 80]
    movaps  xmm6,  xmmword ptr [rsp + 96]
    movaps  xmm7,  xmmword ptr [rsp + 112]
    movaps  xmm8,  xmmword ptr [rsp + 128]
    movaps  xmm9,  xmmword ptr [rsp + 144]
    movaps  xmm10, xmmword ptr [rsp + 160]
    movaps  xmm11, xmmword ptr [rsp + 176]
    movaps  xmm12, xmmword ptr [rsp + 192]
    movaps  xmm13, xmmword ptr [rsp + 208]
    movaps  xmm14, xmmword ptr [rsp + 224]
    movaps  xmm15, xmmword ptr [rsp + 240]
    add     rsp, XMM_SAVE_TOTAL

    ; === 第5步：恢复所有 Guest GPR ===
VmExitResume:
    pop     rax
    pop     rbx
    pop     rcx
    pop     rdx
    pop     rsi
    pop     rdi
    pop     rbp
    pop     r8
    pop     r9
    pop     r10
    pop     r11
    pop     r12
    pop     r13
    pop     r14
    pop     r15

    ; === 第6步：VMRESUME ===
    vmresume

    ; VMRESUME 失败（不应该到这里）
    jmp     VmResumeFailed

; === 终止虚拟化 ===
; 重要：此时需要返回到 VMCALL 的调用者，而不是 VMLAUNCH 时的恢复点
; 栈上保存的是 VMCALL 时的 Guest 寄存器状态
; 注意：HvAdvanceGuestRip() 已经在 C 代码中被调用，GUEST_RIP 已是下一条指令
VmExitTerminate:
    ; 此时 RSP 仍指向 XMM 区底部（add rsp,20h 后），先撤销 XMM 区
    add     rsp, XMM_SAVE_TOTAL

    ; 获取 HOST_RSP 以访问预留区域
    ; 此时 RSP = HOST_RSP - 120 (15 个寄存器)
    lea     r8, [rsp + 120]             ; R8 = HOST_RSP (预留区域基址)
    
    ; 从 VMCS 读取 Guest RIP 和 RSP，保存到预留区域
    mov     rcx, GUEST_RIP_ENCODING
    vmread  rax, rcx
    mov     [r8 + RESTORE_RIP_OFFSET], rax    ; 保存 Guest RIP
    
    mov     rcx, GUEST_RSP_ENCODING
    vmread  rax, rcx
    mov     [r8 + RESTORE_RSP_OFFSET], rax    ; 保存 Guest RSP
    
    ; 执行 VMXOFF（退出 VMX 操作模式）
    vmxoff
    
    ; 恢复所有 Guest GPR（从栈上 pop）
    ; 栈布局: [RSP] = RAX, [RSP+8] = RBX, ... [RSP+112] = R15
    pop     rax
    pop     rbx
    pop     rcx
    pop     rdx
    pop     rsi
    pop     rdi
    pop     rbp
    pop     r8
    pop     r9
    pop     r10
    pop     r11
    pop     r12
    pop     r13
    pop     r14
    pop     r15
    
    ; 此时 RSP = HOST_RSP
    ; 从预留区域读取 Guest RIP 和 RSP
    mov     rcx, [rsp + RESTORE_RIP_OFFSET]   ; RCX = Guest RIP (返回地址)
    mov     rax, [rsp + RESTORE_RSP_OFFSET]   ; RAX = Guest RSP
    
    ; 切换到 Guest 栈
    mov     rsp, rax
    
    ; 设置返回值 = 0（表示成功退出虚拟化）
    xor     rax, rax
    
    ; 跳转到 VMCALL 的下一条指令（即 AsmVmCall 的 ret 指令）
    jmp     rcx

; === VMRESUME 失败 ===
VmResumeFailed:
    ; 保存错误码
    mov     rcx, 4400h              ; VM_INSTRUCTION_ERROR
    vmread  rax, rcx
    mov     g_VmInstructionError, rax
    
    ; 尝试终止
    vmxoff
    
    ; 此时 RSP = HOST_RSP（因为已经 pop 完了所有寄存器）
    ; 从预留区域恢复并返回
    mov     rbx, [rsp + RESTORE_RBX_OFFSET]
    mov     rbp, [rsp + RESTORE_RBP_OFFSET]
    mov     rsi, [rsp + RESTORE_RSI_OFFSET]
    mov     rdi, [rsp + RESTORE_RDI_OFFSET]
    mov     r12, [rsp + RESTORE_R12_OFFSET]
    mov     r13, [rsp + RESTORE_R13_OFFSET]
    mov     r14, [rsp + RESTORE_R14_OFFSET]
    mov     r15, [rsp + RESTORE_R15_OFFSET]
    mov     rcx, [rsp + RESTORE_RIP_OFFSET]
    mov     rax, [rsp + RESTORE_RSP_OFFSET]
    
    ; 切换到恢复栈
    mov     rsp, rax
    
    ; 返回错误
    mov     rax, 0C0000001h
    jmp     rcx

AsmVmExitHandler ENDP

; ==================== VMLAUNCH 入口 ====================
;
; int AsmVmLaunchAndSaveState(PVCPU_DATA VcpuData)
; 
; 参数：RCX = VcpuData 指针
; 返回：0 = 成功（在 Guest 模式下返回），非0 = 失败
;

PUBLIC AsmVmLaunchAndSaveState
AsmVmLaunchAndSaveState PROC
    
    mov     QWORD PTR g_AsmDebugFlag, 1
    
    ; 保存 RFLAGS
    pushfq
    
    ; 保存所有通用寄存器
    push    rax
    push    rcx
    push    rdx
    push    rbx
    push    rsp                     ; 占位
    push    rbp
    push    rsi
    push    rdi
    push    r8
    push    r9
    push    r10
    push    r11
    push    r12
    push    r13
    push    r14
    push    r15
    
    mov     QWORD PTR g_AsmDebugFlag, 2
    
    ; R10 = VcpuData 指针
    mov     r10, rcx
    
    ; 读取 HOST_RSP
    mov     rcx, 6C14h
    vmread  r11, rcx
    test    r11, r11
    jz      VmLaunchFailed
    
    ; 保存恢复信息到 HOST_RSP 预留区域
    mov     [r11 + VCPU_DATA_OFFSET], r10
    mov     [r11 + RESTORE_RBX_OFFSET], rbx
    mov     [r11 + RESTORE_RBP_OFFSET], rbp
    mov     [r11 + RESTORE_RSI_OFFSET], rsi
    mov     [r11 + RESTORE_RDI_OFFSET], rdi
    mov     [r11 + RESTORE_R12_OFFSET], r12
    mov     [r11 + RESTORE_R13_OFFSET], r13
    mov     [r11 + RESTORE_R14_OFFSET], r14
    mov     [r11 + RESTORE_R15_OFFSET], r15
    
    ; 保存返回地址和栈指针
    mov     rax, [rsp + 136]        ; 返回地址
    mov     [r11 + RESTORE_RIP_OFFSET], rax
    mov     g_AsmRestoreRip, rax
    
    lea     rdx, [rsp + 144]        ; 调用者栈指针
    mov     [r11 + RESTORE_RSP_OFFSET], rdx
    mov     g_AsmRestoreRsp, rdx
    
    mov     rax, [rsp + 128]        ; RFLAGS
    mov     [r11 + RESTORE_RFLAGS_OFFSET], rax
    
    ; 清除 pending 中断
    xor     rax, rax
    mov     [r11 + PENDING_INTR_OFFSET], rax
    
    mov     QWORD PTR g_AsmDebugFlag, 3
    
    ; 设置 GUEST_RIP = GuestEntry
    lea     rax, GuestEntry
    mov     rcx, GUEST_RIP_ENCODING
    vmwrite rcx, rax
    
    ; GUEST_RSP = 当前 RSP
    mov     rcx, GUEST_RSP_ENCODING
    mov     rdx, rsp
    vmwrite rcx, rdx
    
    ; GUEST_RFLAGS - 确保 IF=1，清除 TF
    mov     rax, [rsp + 128]
    or      rax, 200h               ; IF=1
    and     rax, 0FFFFFFFFFFFFFEFFh ; TF=0
    mov     rcx, GUEST_RFLAGS_ENCODING
    vmwrite rcx, rax
    
    mov     QWORD PTR g_AsmDebugFlag, 4

    ; === VMLAUNCH ===
    vmlaunch

    ; vmlaunch 没进 guest -> fallthrough = VMfail (有 VM-Instruction Error 可读)
    ; 如果 vmlaunch 自己 #UD, 异常发生, 这里不会执行, g_AsmDebugFlag 停在 4
    mov     QWORD PTR g_AsmDebugFlag, 5

    ; VMLAUNCH 失败
    jmp     VmLaunchFailed

; === Guest 入口点（VMLAUNCH 成功后从这里开始） ===
GuestEntry:
    mov     QWORD PTR g_AsmDebugFlag, 10

    ; 恢复所有寄存器
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     r11
    pop     r10
    pop     r9
    pop     r8
    pop     rdi
    pop     rsi
    pop     rbp
    add     rsp, 8                  ; 跳过 RSP 占位
    pop     rbx
    pop     rdx
    pop     rcx
    pop     rax
    popfq

    mov     QWORD PTR g_AsmDebugFlag, 11

    ; 返回 0 = 成功
    xor     rax, rax

    ; 精确定位 #UD 阶段 (2026-05-31):
    ;   stop at 11 → mov 12 或 xor 之前的某指令 #UD
    ;   stop at 12 → ret 之前所有都跑过,ret 跳转后 #UD
    ;   stop at 13 → 不可能(ret 后控制流走了,这条永不执行;用作 placeholder)
    mov     QWORD PTR g_AsmDebugFlag, 12
    ret
    mov     QWORD PTR g_AsmDebugFlag, 13   ; unreachable marker

; === VMLAUNCH 失败 ===
VmLaunchFailed:
    mov     QWORD PTR g_AsmDebugFlag, 99
    
    ; 保存错误码
    push    rcx
    mov     rcx, 4400h
    vmread  rax, rcx
    mov     g_VmInstructionError, rax
    pop     rcx
    
    ; 恢复寄存器
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     r11
    pop     r10
    pop     r9
    pop     r8
    pop     rdi
    pop     rsi
    pop     rbp
    add     rsp, 8
    pop     rbx
    pop     rdx
    pop     rcx
    pop     rax
    popfq
    
    ; 返回错误
    mov     rax, 0C0000001h
    ret

AsmVmLaunchAndSaveState ENDP

; ==================== VMCALL 包装 ====================

PUBLIC AsmVmCall
AsmVmCall PROC
    mov     rax, rcx        ; 命令码
    vmcall
    ret
AsmVmCall ENDP

PUBLIC AsmVmCallWithResult
AsmVmCallWithResult PROC
    mov     rax, rcx        ; 命令码
    vmcall
    ; RAX 已包含结果
    ret
AsmVmCallWithResult ENDP

; ----------------------------------------------------------------
; AsmVmCallPhysCopy
;   阶段 6 真·VT 无痕物理 R/W (Intel VMX) — 走 VMCALL_PHYS_COPY 服务号
;
; C 原型:
;   NTSTATUS AsmVmCallPhysCopy(
;       UINT64 TargetCr3,    // RCX
;       UINT64 TargetGva,    // RDX
;       PVOID  KernelBuf,    // R8
;       SIZE_T Size,         // R9
;       ULONG  Direction,    // [RSP+28h]
;       PSIZE_T OutBytesDone // [RSP+30h]
;   );
;
; VMCALL 服务号约定 (与 HvHandleVmcall 一致):
;   RCX = 0EBF00010h (VMCALL_PHYS_COPY)
;   RDX = target CR3
;   R8  = target GVA
;   R9  = kernel buf
;   R10 = size           →  返回 bytesDone
;   R11 = direction
;   返回 RAX = NTSTATUS
;
; 实现细节: 入口寄存器需要重新洗牌, 因为 Win x64 ABI 让我们拿到的是
; (cr3, gva, buf, size) 在 (RCX,RDX,R8,R9); 而 VMCALL 期望
; (cmd, cr3, gva, buf) 在 (RCX,RDX,R8,R9), size→R10, dir→R11。
;
; 关键: vmcall 本身不 clobber 非约定的寄存器, 但我们的 handler 会写
; ctx->Rax 和 ctx->R10, 通过 GUEST_CONTEXT 回写到 guest GPR。
; ----------------------------------------------------------------
VMCALL_PHYS_COPY_NUM EQU 0EBF00010h

PUBLIC AsmVmCallPhysCopy
AsmVmCallPhysCopy PROC
    ; 保存 nonvolatile (Win x64): 这里没有用到, 直接使用 volatile

    ; 第 5 / 第 6 参数取自栈 (相对于 ret addr 偏移 28h/30h)
    mov     r10, r9                 ; r10 = size (size 是第 4 参数→R9, 转到 R10)
    mov     r9,  r8                 ; r9 = buf
    mov     r8,  rdx                ; r8 = gva
    mov     rdx, rcx                ; rdx = cr3
    mov     rcx, VMCALL_PHYS_COPY_NUM ; rcx = service number
    ; 第 5 参数 Direction 是 C 端的 ULONG (4 字节), MSVC 仅写栈槽低 4 字节,
    ; 上 4 字节是 stack garbage。必须用 r11d 做 4 字节加载,x64 自动零扩展到 r11,
    ; 否则上半的脏数据会让 ctx->R11 != 0,handler 误判为 IsWrite=TRUE,
    ; 写分支用零初始化的 KernelBuf 覆盖目标 → 整个读取范围被清零。
    mov     r11d, [rsp + 28h]       ; r11 = direction (4-byte load, auto zero-extend)

    mov     rax, rcx                ; vmcall 期望 rax=cmd (同 AsmVmCall 约定)
    vmcall
    ; 返回: rax = NTSTATUS, r10 = bytesDone

    ; 写回 *OutBytesDone (如果非 NULL)
    mov     rcx, [rsp + 30h]        ; 第 6 参数: OutBytesDone 指针
    test    rcx, rcx
    jz      @F
    mov     [rcx], r10
@@:
    ret
AsmVmCallPhysCopy ENDP

; ==================== INVEPT/INVVPID 包装 ====================

PUBLIC AsmInveptAllContexts
AsmInveptAllContexts PROC
    ; Type 2 = All contexts
    mov     rax, 2
    
    ; 在栈上构建描述符（16字节）
    sub     rsp, 16
    mov     QWORD PTR [rsp], 0      ; EPTP（all contexts 不需要）
    mov     QWORD PTR [rsp + 8], 0
    
    invept  rax, OWORD PTR [rsp]
    
    add     rsp, 16
    
    ; 返回 CF 标志（0=成功）
    setc    al
    movzx   eax, al
    ret
AsmInveptAllContexts ENDP

PUBLIC AsmInveptSingleContext
AsmInveptSingleContext PROC
    ; RCX = EPTP
    ; Type 1 = Single context
    mov     rax, 1
    
    sub     rsp, 16
    mov     QWORD PTR [rsp], rcx    ; EPTP
    mov     QWORD PTR [rsp + 8], 0
    
    invept  rax, OWORD PTR [rsp]
    
    add     rsp, 16
    
    setc    al
    movzx   eax, al
    ret
AsmInveptSingleContext ENDP

PUBLIC AsmInvvpidAllContexts
AsmInvvpidAllContexts PROC
    ; Type 2 = All contexts
    mov     rax, 2

    sub     rsp, 16
    mov     QWORD PTR [rsp], 0
    mov     QWORD PTR [rsp + 8], 0

    invvpid rax, OWORD PTR [rsp]

    add     rsp, 16

    setc    al
    movzx   eax, al
    ret
AsmInvvpidAllContexts ENDP

; ============================================================
; 2026-06-20: VMXOFF 后描述符表恢复 helper
; ============================================================
; MSVC x64 不支持 inline asm, 且无 __lidt/__lgdt/__ltr intrinsic。
; 提供裸 asm 包装供 C 调用。
;
; 参数: RCX = 指向 10 字节 IDTR/GDTR 结构 (limit:2 + base:8)
;       或对于 LTR/LLDT, RCX = USHORT selector
; ============================================================

; VOID AsmLoadIdtr(_In_ PVOID IdtrBuffer);
PUBLIC AsmLoadIdtr
AsmLoadIdtr PROC
    lidt    FWORD PTR [rcx]
    ret
AsmLoadIdtr ENDP

; VOID AsmLoadGdtr(_In_ PVOID GdtrBuffer);
PUBLIC AsmLoadGdtr
AsmLoadGdtr PROC
    lgdt    FWORD PTR [rcx]
    ret
AsmLoadGdtr ENDP

; VOID AsmLoadTr(_In_ USHORT Selector);
PUBLIC AsmLoadTr
AsmLoadTr PROC
    ; LTR 要求 selector 在 16 位寄存器, ECX 低 16 位
    ; 但要先清掉 GDT 中 TR descriptor 的 busy bit (位 9), 否则 LTR #GP
    ; 这一步在 C 端做 (sgdt + patch)
    ltr     cx
    ret
AsmLoadTr ENDP

; VOID AsmLoadLdtr(_In_ USHORT Selector);
PUBLIC AsmLoadLdtr
AsmLoadLdtr PROC
    lldt    cx
    ret
AsmLoadLdtr ENDP

END
