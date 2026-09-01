.reload /f GuardMetaCore.sys
.echo === STEP6 ===
dt GuardMetaCore!_NPT_STEP_CONTEXT fffff803c1e239b8
dq fffff803c1e239b8 L70
.echo === GUEST_RIP ===
ln fffff803c0d768aa
u fffff803c0d76870 L30
!address fffff803c0d768aa
lm a fffff803c0d768aa
.echo === GPA ===
!pte fffff803c0d768aa
q
