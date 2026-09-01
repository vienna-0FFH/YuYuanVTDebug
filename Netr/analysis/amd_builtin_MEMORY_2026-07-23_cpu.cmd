.lines -e
.reload /f nt
.reload /f GuardMetaCore.sys
.echo === BUGCHECK ===
.bugcheck
.echo === ANALYZE ===
!analyze -v
.echo === MODULE ===
lmvm GuardMetaCore
.echo === CPUINFO ===
!cpuinfo
.echo === RUNNING ===
!running -it
.echo === ALL_CPUS ===
~*
~*kP 80
.echo === CPU14 ===
~14s
r
kv 100
!irql
!prcb 14
!thread
q
