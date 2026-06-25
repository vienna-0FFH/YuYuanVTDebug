;
; AsmSvm.asm - AMD SVM 汇编核心代码
;
; 包含 SVM 专用的汇编实现：
; 1. VMRUN 启动和 #VMEXIT 处理
; 2. VMMCALL 包装
; 3. STGI/CLGI 中断控制
; 4. VMSAVE/VMLOAD 状态保存
;

.DATA

; ==================== 全局变量 ====================

; SVM 调试标志
PUBLIC g_SvmDebugFlag
g_SvmDebugFlag DQ 0

; SVM 退出计数器
PUBLIC g_SvmExitCounter
PUBLIC g_SvmLastExitCode
g_SvmExitCounter DQ 0
g_SvmLastExitCode DQ 0

; 恢复点
PUBLIC g_SvmRestoreRsp
PUBLIC g_SvmRestoreRip
g_SvmRestoreRsp DQ 0
g_SvmRestoreRip DQ 0

.CODE

; ==================== 外部 C 函数 ====================

EXTERN SvmVmExitDispatch:PROC

; ==================== VCPU_DATA 结构偏移 ====================
; 这些偏移需要与 HvTypes.h 中的 VCPU_DATA 结构保持一致
;
; VCPU_DATA 结构布局（64位系统）:
;   偏移 0x00: ULONG ProcessorNumber (4字节)
;   偏移 0x04: BOOLEAN IsVirtualized (1字节 + 3字节填充)
;   偏移 0x08: PVOID VmExitStack (8字节)
;   偏移 0x10: ULONG64 VmExitStackPhysical (8字节)
;   偏移 0x18: PVOID VmxonRegion (8字节)
;   偏移 0x20: PHYSICAL_ADDRESS VmxonRegionPhysical (8字节)
;   偏移 0x28: PVOID VmcsRegion (8字节)
;   偏移 0x30: PHYSICAL_ADDRESS VmcsRegionPhysical (8字节)
;   偏移 0x38: PVOID MsrBitmap (8字节)
;   偏移 0x40: PHYSICAL_ADDRESS MsrBitmapPhysical (8字节)
;   偏移 0x48: PEPT_TABLES EptTables (8字节)
;   偏移 0x50: PVMCB Vmcb (8字节)
;   偏移 0x58: PHYSICAL_ADDRESS VmcbPhysical (8字节)
;   ...

VCPU_PROCESSOR_NUMBER   EQU 00h     ; ULONG ProcessorNumber
VCPU_IS_VIRTUALIZED     EQU 04h     ; BOOLEAN IsVirtualized
VCPU_VMEXIT_STACK       EQU 08h     ; PVOID VmExitStack
VCPU_VMEXIT_STACK_PA    EQU 10h     ; ULONG64 VmExitStackPhysical
VCPU_VMCB               EQU 50h     ; PVMCB Vmcb
VCPU_VMCB_PHYSICAL      EQU 58h     ; PHYSICAL_ADDRESS VmcbPhysical

; 栈预留区偏移
RESTORE_RSP_OFFSET      EQU 070h
RESTORE_RIP_OFFSET      EQU 068h
RESTORE_RFLAGS_OFFSET   EQU 060h
RESTORE_RBX_OFFSET      EQU 058h
RESTORE_RBP_OFFSET      EQU 050h
RESTORE_RSI_OFFSET      EQU 048h
RESTORE_RDI_OFFSET      EQU 040h
RESTORE_R12_OFFSET      EQU 038h
RESTORE_R13_OFFSET      EQU 030h
RESTORE_R14_OFFSET      EQU 028h
RESTORE_R15_OFFSET      EQU 020h
VCPU_DATA_OFFSET        EQU 078h

; XMM 保存区大小（16 × 16 + 8 align）
XMM_SAVE_SIZE           EQU 100h        ; 256 bytes
XMM_SAVE_TOTAL          EQU 108h        ; 256 + 8 align

; ==================== SVM #VMEXIT Handler ====================
;
; AMD SVM #VMEXIT 处理入口
;
; VMRUN 执行后，如果发生 #VMEXIT：
; - 硬件自动保存 Guest 状态到 VMCB State Save Area
; - 硬件自动从 Host Save Area 恢复 Host 状态
; - 执行继续到 VMRUN 后的下一条指令
;
; 注意：与 Intel VMX 不同，AMD SVM 的 VMRUN 指令执行后会线性返回
; Guest 的 RAX 需要手动保存（其他寄存器在 VMCB 中）

PUBLIC AsmSvmVmExitHandler
AsmSvmVmExitHandler PROC

    ; === 保存所有 Guest GPR 到栈 ===
    ; 注意：RAX 包含 VMCB 物理地址，需要单独处理
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
    push    rax             ; Guest RAX
    ; 15 push × 8 = 120 字节；入口 RSP mod 16 == 0 → 现 RSP mod 16 == 8

    ; === 保存 XMM0-XMM15 ===
    ; movaps 需要 16 字节对齐：sub XMM_SAVE_TOTAL（108h，mod 16 == 8）→ RSP mod 16 == 0
    sub     rsp, XMM_SAVE_TOTAL
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

    ; 增加退出计数
    lock inc QWORD PTR g_SvmExitCounter

    ; === 调用 C 函数处理 ===
    ; BOOLEAN SvmVmExitDispatch(PVCPU_DATA VcpuData, PGUEST_CONTEXT GuestContext)
    ; GUEST_CONTEXT 在 XMM 区之上 (+XMM_SAVE_TOTAL)，预留区再之上 (+120)
    lea     r8, [rsp + XMM_SAVE_TOTAL + 120]    ; R8 = 预留区基址 (HOST_RSP)
    mov     rcx, [r8 + VCPU_DATA_OFFSET]        ; RCX = VcpuData
    lea     rdx, [rsp + XMM_SAVE_TOTAL]         ; RDX = GuestContext

    ; shadow space。当前 RSP mod 16 == 0，sub 20h 保持 mod 16 == 0
    sub     rsp, 20h

    call    SvmVmExitDispatch

    add     rsp, 20h

    ; === 检查返回值 ===
    test    al, al
    jz      SvmExitTerminate

    ; === 恢复 XMM ===
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

    ; === 恢复 Guest GPR 并继续 ===
SvmExitResume:
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

    ; RAX 需要重新加载 VMCB 物理地址用于 VMRUN
    ; 从预留区获取
    mov     rax, [rsp + VCPU_DATA_OFFSET]  ; RAX = VcpuData
    mov     rax, [rax + VCPU_VMCB_PHYSICAL] ; RAX = VmcbPhysical

    ; 执行 VMRUN 继续 Guest
    vmrun   rax

    ; VMRUN 返回意味着又发生了 #VMEXIT
    jmp     AsmSvmVmExitHandler

; === 终止虚拟化 ===
SvmExitTerminate:
    ; 此时 RSP 在 XMM 区基址（add rsp,20h 已撤销 shadow space），先撤销 XMM 区
    add     rsp, XMM_SAVE_TOTAL

    ; 恢复所有寄存器
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

    ; 从预留区恢复返回信息
    mov     rcx, [rsp + RESTORE_RIP_OFFSET]
    mov     rax, [rsp + RESTORE_RSP_OFFSET]

    ; 切换到 Guest 栈
    mov     rsp, rax

    ; 返回值 = 0 (成功退出)
    xor     rax, rax

    ; 跳转回调用者
    jmp     rcx

AsmSvmVmExitHandler ENDP

; ==================== VMRUN 启动 ====================
;
; int AsmSvmLaunch(PVCPU_DATA VcpuData)
;
; 参数：RCX = VcpuData 指针
; 返回：0 = 成功（在 Guest 模式下返回），非0 = 失败
;

PUBLIC AsmSvmLaunch
AsmSvmLaunch PROC
    
    mov     QWORD PTR g_SvmDebugFlag, 1
    
    ; 保存 RFLAGS
    pushfq
    
    ; 保存所有非易失性寄存器
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
    
    mov     QWORD PTR g_SvmDebugFlag, 2
    
    ; R10 = VcpuData
    mov     r10, rcx
    
    ; 获取 VmExit 栈顶
    mov     r11, [r10 + VCPU_VMEXIT_STACK]
    add     r11, 6000h              ; 栈顶
    sub     r11, 80h                ; 预留区
    
    ; 保存恢复信息到预留区
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
    mov     g_SvmRestoreRip, rax
    
    lea     rdx, [rsp + 144]        ; 调用者栈指针
    mov     [r11 + RESTORE_RSP_OFFSET], rdx
    mov     g_SvmRestoreRsp, rdx
    
    mov     rax, [rsp + 128]        ; RFLAGS
    mov     [r11 + RESTORE_RFLAGS_OFFSET], rax
    
    mov     QWORD PTR g_SvmDebugFlag, 3
    
    ; 获取 VMCB 物理地址
    mov     rax, [r10 + VCPU_VMCB_PHYSICAL]
    
    ; 获取 VMCB 虚拟地址用于设置 RIP/RSP
    mov     r8, [r10 + VCPU_VMCB]
    
    ; 设置 Guest RIP = GuestEntry
    lea     rcx, SvmGuestEntry
    mov     [r8 + 578h], rcx        ; VMCB.StateSave.Rip (偏移 0x578)
    
    ; 设置 Guest RSP = 当前 RSP
    mov     [r8 + 5D8h], rsp        ; VMCB.StateSave.Rsp (偏移 0x5D8)
    
    ; 设置 Guest RAX = 0
    mov     QWORD PTR [r8 + 5F8h], 0  ; VMCB.StateSave.Rax (偏移 0x5F8)
    
    ; 设置 Guest RFLAGS - 确保 IF=1
    mov     rcx, [rsp + 128]
    or      rcx, 200h               ; IF=1
    and     rcx, 0FFFFFFFFFFFFFEFFh ; TF=0
    mov     [r8 + 570h], rcx        ; VMCB.StateSave.Rflags (偏移 0x570)
    
    mov     QWORD PTR g_SvmDebugFlag, 4
    
    ; 切换到 VmExit 栈
    mov     rsp, r11
    
    ; === 执行 VMRUN ===
    ; RAX = VMCB 物理地址
    vmrun   rax
    
    ; VMRUN 返回意味着发生了 #VMEXIT
    ; 跳转到 #VMEXIT 处理
    jmp     AsmSvmVmExitHandler

; === Guest 入口点 ===
SvmGuestEntry:
    mov     QWORD PTR g_SvmDebugFlag, 10
    
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
    
    mov     QWORD PTR g_SvmDebugFlag, 11
    
    ; 返回 0 = 成功
    xor     rax, rax
    ret

AsmSvmLaunch ENDP

; ==================== VMMCALL 包装 ====================

PUBLIC AsmVmmcall
AsmVmmcall PROC
    mov     rax, rcx        ; 命令码放入 RAX
    vmmcall
    ret
AsmVmmcall ENDP

PUBLIC AsmVmmcallWithResult
AsmVmmcallWithResult PROC
    mov     rax, rcx        ; 命令码放入 RAX
    vmmcall
    ; 结果在 RAX 中返回
    ret
AsmVmmcallWithResult ENDP

; ----------------------------------------------------------------
; AsmVmmCallPhysCopy
;   阶段 6 真·VT 无痕物理 R/W (AMD SVM) — 走 VMCALL_PHYS_COPY 服务号
;
; 与 Intel 版本 AsmVmCallPhysCopy 行为完全相同, 唯一差别: vmmcall。
; 入口参数: (cr3, gva, buf, size) in (RCX,RDX,R8,R9);
;           dir at [rsp+28h], OutBytesDone at [rsp+30h]
; ----------------------------------------------------------------
VMMCALL_PHYS_COPY_NUM EQU 0EBF00010h

PUBLIC AsmVmmCallPhysCopy
AsmVmmCallPhysCopy PROC
    mov     r10, r9                 ; r10 = size
    mov     r9,  r8                 ; r9 = buf
    mov     r8,  rdx                ; r8 = gva
    mov     rdx, rcx                ; rdx = cr3
    mov     rcx, VMMCALL_PHYS_COPY_NUM
    ; 第 5 参数 Direction 是 C 端的 ULONG (4 字节), 上 4 字节是 stack garbage,
    ; 必须用 r11d 做 4 字节加载, x64 自动零扩展。否则上半脏数据会让 ctx->R11 != 0,
    ; handler 误判 IsWrite=TRUE, 用零初始化 KernelBuf 写穿目标 → 读后整段被清零。
    mov     r11d, [rsp + 28h]       ; r11 = direction (4-byte load, auto zero-extend)

    mov     rax, rcx
    vmmcall
    ; rax = NTSTATUS, r10 = bytesDone

    mov     rcx, [rsp + 30h]
    test    rcx, rcx
    jz      @F
    mov     [rcx], r10
@@:
    ret
AsmVmmCallPhysCopy ENDP

; ==================== STGI/CLGI 中断控制 ====================

; STGI - Set Global Interrupt Flag
; 允许接收中断
PUBLIC AsmStgi
AsmStgi PROC
    stgi
    ret
AsmStgi ENDP

; CLGI - Clear Global Interrupt Flag
; 禁止接收中断（创建原子操作区域）
PUBLIC AsmClgi
AsmClgi PROC
    clgi
    ret
AsmClgi ENDP

; ==================== VMSAVE/VMLOAD ====================

; VMSAVE - 保存额外的 Host 状态到指定地址
PUBLIC AsmSvmVmsave
AsmSvmVmsave PROC
    mov     rax, rcx        ; VMCB 物理地址
    vmsave  rax
    ret
AsmSvmVmsave ENDP

; VMLOAD - 从指定地址加载 Guest 状态
PUBLIC AsmSvmVmload
AsmSvmVmload PROC
    mov     rax, rcx        ; VMCB 物理地址
    vmload  rax
    ret
AsmSvmVmload ENDP

; VMRUN - 启动 Guest（用于外部调用）
PUBLIC AsmSvmVmrun
AsmSvmVmrun PROC
    mov     rax, rcx        ; VMCB 物理地址
    vmrun   rax
    ret
AsmSvmVmrun ENDP

; ==================== SKINIT 包装 ====================

PUBLIC AsmSkinit
AsmSkinit PROC
    mov     eax, ecx        ; SLB 物理地址（32位）
    skinit  eax
    ret
AsmSkinit ENDP

; ==================== INVLPGA 包装 ====================
; 使指定虚拟地址和 ASID 的 TLB 条目失效

PUBLIC AsmInvlpga
AsmInvlpga PROC
    ; RCX = 虚拟地址
    ; RDX = ASID
    mov     rax, rcx
    mov     ecx, edx
    invlpga rax, ecx
    ret
AsmInvlpga ENDP

END
