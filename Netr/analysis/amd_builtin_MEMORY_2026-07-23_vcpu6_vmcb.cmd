.reload /f GuardMetaCore.sys
.echo === VMCB6_CONTROL ===
dt GuardMetaCore!_VMCB_CONTROL_AREA ffff80818591a000
.echo === VMCB6_STATE ===
dt GuardMetaCore!_VMCB_STATE_SAVE_AREA ffff80818591a400
.echo === VMCB6_RAW_CONTROL ===
dd ffff80818591a000 L8
dq ffff80818591a050 L20
.echo === VMCB6_RAW_STATE ===
dq ffff80818591a548 L28
.echo === STEP_TYPES ===
?? sizeof(GuardMetaCore!_NPT_STEP_CONTEXT)
dt GuardMetaCore!_NPT_STEP_CONTEXT
?? sizeof(GuardMetaCore!_NPT_HOOK_MANAGER)
dt GuardMetaCore!_NPT_HOOK_MANAGER
.echo === MANAGER ===
dt GuardMetaCore!_NPT_HOOK_MANAGER fffff803c1e22c90
q
