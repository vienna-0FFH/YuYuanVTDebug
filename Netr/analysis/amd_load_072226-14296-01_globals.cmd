.lines
.reload /f nt
.reload /f GuardMetaCore.sys
x GuardMetaCore!g_Svm*
x GuardMetaCore!g_HypervisorContext
dq GuardMetaCore!g_SvmDebugFlag L1
dq GuardMetaCore!g_SvmExitCounter L1
dt GuardMetaCore!_HYPERVISOR_CONTEXT GuardMetaCore!g_HypervisorContext
q
