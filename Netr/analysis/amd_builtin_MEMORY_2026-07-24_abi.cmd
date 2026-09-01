.lines -e
.reload /f nt
.reload /f GuardMetaCore.sys
~12s
.trap ffffa80a887ff700
.echo === WRAPPER_FRAME ===
.frame /r 1
dv /t /v
.echo === CALLER_FRAME ===
.frame /r 2
dv /t /v
.echo === TARGET_FULL ===
uf fffff80265116670
.echo === TARGET_BYTES ===
db fffff80265116670 L40
.echo === TRAMPOLINE ===
u ffff9807f62132b0 L30
db ffff9807f62132b0 L40
.echo === WRAPPER_CALL_STACK_WINDOW ===
dq ffffa80a887ff930 L30
.echo === TARGET_UNWIND ===
!unwind fffff802651168aa
q
