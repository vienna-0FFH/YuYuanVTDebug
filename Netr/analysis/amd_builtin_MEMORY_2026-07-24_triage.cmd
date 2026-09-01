.lines -e
.reload /f nt
.reload /f GuardMetaCore.sys
.echo === DUMP_DEBUG ===
.dumpdebug
.echo === TARGET ===
vertarget
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
.echo === DPCS ===
!dpcs
q
