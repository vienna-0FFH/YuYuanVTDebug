.reload /f GuardMetaCore.sys
.echo === HYPERVISOR ===
dt -r2 GuardMetaCore!_HYPERVISOR_CONTEXT GuardMetaCore!g_HypervisorContext
dq GuardMetaCore!g_HypervisorContext L3
.echo === TYPES ===
?? sizeof(GuardMetaCore!_VCPU_DATA)
dt GuardMetaCore!_VCPU_DATA
dt GuardMetaCore!_VMCB_CONTROL_AREA
dt GuardMetaCore!_VMCB_STATE_SAVE_AREA
.echo === DEBUG_STEP_GLOBALS ===
x GuardMetaCore!g_NptDebugStepCpu
x GuardMetaCore!g_NptHookManager
dt GuardMetaCore!_NPT_DEBUG_STEP_CPU GuardMetaCore!g_NptDebugStepCpu
q
