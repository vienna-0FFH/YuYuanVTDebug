.lines -e
.reload /f nt
.reload /f GuardMetaCore.sys
.echo === CPU6 ===
~6s
r
kv 100
!irql
!prcb 6
!thread
.echo === PRCB_RAW ===
dt nt!_KPRCB ffff8080b46b2180
.echo === CPU6_CONTEXT ===
!thread ffffd68700832280 1f
.echo === DISPATCHER ===
!running -ti
q
