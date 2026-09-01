# VT HWBP DR6 delivery repair

> Superseded by `vwatch_hwbp_virtual_dr6_delivery_2026-07-21.md`.
> Runtime logs from the packaged driver
> `4C9665461C8B3961689448C5B2FE35F744C4F88838F07359F88AAA1B3823BA6A`
> disproved this report's host-DR6 publication assumption: the explicit
> VM-entry `#DB` reached Windows, but Windows still captured B0..B3 as zero.

## Scope

The current runtime evidence covers all four combinations: built-in or
external debugger, with Windows DebugObject or private Dbgk control. They all
share the Intel EPT/MTF vwatch path and the debugger-context virtualization
hook, so the failure is not limited to the self-built control plane.

## Root-cause chain

1. The vwatch EPT violation and MTF completion were real: diagnostics counted
   `TrueHits` and injected `#DB` events.
2. The completion injected an explicit vector-1 exception without publishing
   the corresponding guest DR6 B0..B3 cause. The VMCS pending-debug field was
   then used as a substitute, which describes a pending debug condition rather
   than the cause of that explicit injection and can create duplicate events.
3. `HookedNtGetContextThread` subsequently overwrote `CONTEXT.Dr6` with zero
   whenever virtual watches existed. Bridge only virtualized Dr0..Dr3/Dr7, so
   every debugger observed `dr6=0` and classified the event as unowned
   single-step (`configured=0x1`, `hit=0`).
4. The external path then returned `DBG_EXCEPTION_NOT_HANDLED`; the private
   path could also reject a B-bit event as belonging to a native breakpoint.

## Repair

- `HvVwatchpInjectHardwareDb` writes the selected B0..B3 bit to the logical
  CPU's DR6 immediately before the one explicit VM-entry `#DB`; it no longer
  writes `GUEST_PENDING_DEBUG_EXCEPTIONS`.
- Intercepted real vector-1 exceptions replay their qualification cause in
  DR6 with only the architectural B/BD/BS bits, without creating a second
  pending-debug condition.
- The debugger caller branch of `HookedNtGetContextThread` continues to
  virtualize breakpoint addresses and DR7, but preserves the stopped thread's
  native trap-frame Dr6. The target self-query anti-debug branch remains
  unchanged and still hides all debug registers.
- Private Dbgk ownership recognizes B bits whose virtual slots are configured
  for the current target, while preserving the existing pass-through for
  unrelated native slots.

This keeps TF, MTF, STI/MOV-SS shadow handling, page rearm order, native DR
fallback, and software-breakpoint delivery unchanged. No new persistent queue
or allocation was introduced; Dr6 lifetime is the Windows thread exception
context and is cleared by the existing context/continue path.

## Precise rollback point

The pre-repair working-tree hashes were recorded before these edits:

| File | SHA-256 |
| --- | --- |
| `Netr/HvVwatch.c` | `3DBC8C3DA05E5D4F329D75E3A6209A984392EBA1D46B4094BCF8716995E9E159` |
| `Netr/HvVmExit.c` | `E3C7E2B192A797BFCA9B5F58C996E2C3F91E7FCF86834C264C2D92611E207E67` |
| `Netr/HvHook.c` | `3B18021EEADC26293FAD897658B2CA1406E85B21BF9623ADA0C8CF4579361108` |
| `Netr/HvPrivateDebugObject.c` | `23E989CD8B07BB11607CCE56836C947204BB2D31C028CB8745407F0352823831` |

The previous packaged driver was
`692866FC4BA72B8521034E60FA98E97C388FAB24334830936DC4020D6178C878`.
Do not reset the whole worktree; these hashes isolate only the DR6 delivery
change on top of the existing uncommitted project state.

## Build validation

- `build_test.bat Release DriverOnly`: passed, driver C/ASM 0 warnings and 0
  errors.
- `build_test.bat Release`: passed, including Bridge/Injector, Rust GUI and
  package refresh.
- New packaged driver SHA-256:
  `09DC782F81ADF74A2C758E071063EFA27B1BC1BA9B05B208E295196F55CABBDD`.
- Source and `Netr/test-package/GuardMetaCore.sys` hashes are identical.
- `SHA256SUMS.txt`: all 14 managed entries match; Authenticode status is
  `Valid` (thumbprint `AD39C1B28DF46266E5E74CF60A46A8BEA97BB5F0`).
- Runtime validation is still pending. The driver was not installed, loaded,
  unloaded, or started automatically.
