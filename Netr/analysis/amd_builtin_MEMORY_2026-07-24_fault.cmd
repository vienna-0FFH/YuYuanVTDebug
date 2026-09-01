.lines -e
.reload /f nt
.reload /f GuardMetaCore.sys
.echo === CPU12_TRAP ===
~12s
.trap ffffa80a887ff700
r
r cr2
kv 100
.echo === FAULT_DISASM ===
ub @rip L30
u @rip L30
.echo === FAULT_PTES ===
!pte 00007fffffff0000
!pte ffff80c060203618
.echo === FAULT_ADDRESS ===
!address 00007fffffff0000
!address ffff80c060203618
.echo === TRAP_STACK ===
dq @rsp-80 L60
.trap
.echo === WRAPPER ===
uf GuardMetaCore!HookedNtUserBuildHwndList
x GuardMetaCore!g_HookNtUserBuildHwndList
dq GuardMetaCore!g_HookNtUserBuildHwndList L1
dt -r2 GuardMetaCore!_NPT_HOOK_ENTRY poi(GuardMetaCore!g_HookNtUserBuildHwndList)
.echo === HYPERVISOR ===
dq GuardMetaCore!g_HypervisorContext L3
r @$t0=poi(GuardMetaCore!g_HypervisorContext+8)
r @$t1=@$t0+(0xc*0x948)
dt GuardMetaCore!_VCPU_DATA @$t1
r @$t2=poi(@$t1+88)
.echo === VMCB12_CONTROL ===
dt GuardMetaCore!_VMCB_CONTROL_AREA @$t2
.echo === VMCB12_STATE ===
dt GuardMetaCore!_VMCB_STATE_SAVE_AREA @$t2+400
.echo === STEP12 ===
dt GuardMetaCore!_NPT_STEP_CONTEXT GuardMetaCore!g_NptHookManager+0xc8+(0xc*0x210)
.echo === MANAGER ===
dt GuardMetaCore!_NPT_HOOK_MANAGER GuardMetaCore!g_NptHookManager
q
