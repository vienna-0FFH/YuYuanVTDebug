.reload /f GuardMetaCore.sys
.echo === VCPU6 ===
dt GuardMetaCore!_VCPU_DATA ffffd68721af37b0
.echo === VCPU6_RAW ===
dd ffffd68721af37b0 L4
dq ffffd68721af3838 L6
dd ffffd68721af40f0 L2
.echo === VMCB_POINTER ===
dq ffffd68721af3838 L1
q
