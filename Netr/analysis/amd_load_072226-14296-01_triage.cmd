.lines
.reload /f nt
.reload /f GuardMetaCore.sys
.bugcheck
dt nt!_DPC_WATCHDOG_GLOBAL_TRIAGE_BLOCK fffff807ef9c53c8
dq fffff807ef9c53c8 L20
!dpcs
!irql
!timer
q
