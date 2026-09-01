# Windows DebugObject external VT-HWBP DR6 latch

> Superseded for implementation purposes by
> `external_vt_pending_hwbp_and_private_exit_repair_2026-07-22.md`.
> Runtime log `GuardMetaBridge-13196.log` disproved the live-context-only
> latch described below: the stopped event still reached the Bridge with
> `raw_dr6=0` after earlier debugger context traffic had consumed the R0 hit.
> This file remains as the historical rollback record for that R3-only stage.

## Scope

- This repair covers an external debugger using the standard Windows
  DebugObject control plane with VT-backed hardware breakpoints.
- It does not change the private Dbgk transport, EPT/NPT matching, MTF,
  real TF, synthetic VT stepping, VMCS interrupt shadow, or R0 exception
  dispatch.
- The implementation is confined to `DebuggerBridge/Bridge.cpp` and reuses
  the existing R0 pending-hit/context-hook contract.

## Runtime evidence

- `logs/GuardMetaBridge-16428.log` registered with
  `private_debug_object=0` and bound target 3860 in Windows DebugObject mode.
- The target received first-chance `EXCEPTION_SINGLE_STEP` at
  `0x7FF6009116A4`, but the debugger continued it as
  `DBG_EXCEPTION_NOT_HANDLED (0x80010001)`.
- Windows then entered the target exception path, stopped at a temporary
  system breakpoint, and later returned the same single-step as a
  second-chance exception before execution continued.
- The vwatch diagnostics still closed all producer-side hit, injection,
  publish, and clear counts. The failure was therefore at the standard
  debugger-visible event/context boundary.

## Why ignoring the exception is not a repair

`DBG_EXCEPTION_NOT_HANDLED` is the instruction to pass the exception into the
debuggee. It is the cause of the observed SEH/second-chance detour, not a way to
skip it. Globally forcing `DBG_CONTINUE` would also be incorrect because it
would swallow real target exceptions and unrelated TF single-step events.

## Root-cause chain

1. The latent architectural fact is that injected vector 1 has no VM-entry
   field that can manufacture `DR6.B0..B3`.
2. The first incomplete design decision was to let the Windows DebugObject
   path depend only on repeated live `NtGetContextThread` queries of the R0
   pending-hit record.
3. The runtime trigger was a VT hardware hit delivered as a standard
   first-chance single-step event.
4. Debugger-internal context traffic could acknowledge or outlive the R0
   record before every consumer had classified the event.
5. A later context read then observed `DR6.B0..B3 == 0`; the debugger treated
   the event as unowned and returned `DBG_EXCEPTION_NOT_HANDLED`, causing the
   target exception detour and second-chance stop.

## Reference semantics

- The backup vwatch path injects an ordinary vector-1 exception after MTF and
  does not write physical guest DR6.
- Unreal's external hook reads the stopped thread context inside
  `NewWaitForDebugEvent`, before returning the event to the debugger.
- The private Dbgk repair already uses the stronger form of this rule: latch
  exact VT ownership metadata for the stopped event and retire it on continue.
- The standard Windows path should use the same event lifetime without
  changing the native DebugObject or R0 delivery mechanism.

## Repair

- On a successful native `WaitForDebugEvent` or `WaitForDebugEventEx`, the
  Bridge inspects only bound `EXCEPTION_SINGLE_STEP` events while VT HWBP is
  available and at least one virtual DR slot is configured.
- Before returning the event, it opens the exact stopped TID and calls the
  original `GetThreadContext`. The existing R0 hook supplies a pending B bit.
- The low-four-bit result is intersected with the currently configured slot
  mask and stored in a separate Windows-event map keyed by exact `(PID,TID)`.
- Bridge `GetThreadContext` and WOW64 context reads merge private-Dbgk and
  Windows-event masks. TF-only events latch zero and cannot become HWBP hits.
- The Windows-event entry is removed only after matching native
  `ContinueDebugEvent` succeeds. Failed continues retain the entry, and target
  unbind or Bridge cleanup removes all remaining entries.
- The standard map is separate from private Dbgk state, so its continue path
  can never call a private Dbgk IOCTL or close private event handles.

## Concurrency and failure behavior

- The map uses the existing SRW event lock and the established lock order used
  by target teardown and context setters.
- A context-open/read failure records a zero mask and preserves the native
  event; it never forces a B bit or changes continue status.
- Repeated reads are idempotent. A successful continue is the sole normal
  retirement point, preventing a B bit from leaking to a later event on the
  same thread.
- Unbind and DLL cleanup erase entries even when the debugger or target exits
  without a final continue.

## Precise rollback point

Withdraw only this standard DebugObject extension:

1. Remove `PendingWindowsDebugEvent` and
   `g_pending_windows_debug_events` from `DebuggerBridge/Bridge.cpp`.
2. Restore the DR6 lookup/update helpers to private-Dbgk-only behavior.
3. Remove `LatchWindowsDebugEventDr6` from the two successful native wait
   branches.
4. Remove Windows-event retirement from the native continue path and removal
   from unbind/cleanup.
5. Remove the corresponding paragraph from `DebuggerBridge/README.md`.

Do not remove the R0 pending-hit table, the private Dbgk event metadata repair,
or any MTF/TF/EPT implementation when applying this rollback.

## Validation state

- The focused x64 and x86 DebuggerBridge build passed with `/W4` on
  2026-07-22.
- The canonical `build_test.bat Release` build passed. The driver built with
  zero warnings and zero errors; both Bridge architectures, both injectors,
  the Rust GUI, symbols, certificate, license marker, and package manifest
  were refreshed. The GUI retained 25 pre-existing Rust warnings.
- `SHA256SUMS.txt` contains 14 managed artifacts with zero missing or
  mismatched entries. Source/package parity passed for the SYS, PDB, and both
  Bridge DLLs.
- The packaged driver's SHA-256 is
  `280F09AE1024BBC711E4D231CA881CB062D0130079A7CABBC34AEAC5D86004A3`.
  Authenticode status is valid with signer thumbprint
  `82FAA0D1CA193262D6EADF824DFE7C6DD2F5ACC4`.
- The packaged x64 Bridge SHA-256 is
  `33EE597FDDC1A974DF5F37924AA32C06E69DA2E10EBADD8FEDB1DA23A2B7B209`;
  the x86 Bridge SHA-256 is
  `CF46F76035261930681AC1B96BF866E77F70F2B406A1D5AC122F21A7A027E1B5`.
- Runtime confirmation still requires one standard Windows DebugObject
  external-debugger hit showing `[NATIVE-WAIT] ... virtual_dr6=0x1`, followed
  by `DBG_CONTINUE` rather than `DBG_EXCEPTION_NOT_HANDLED`. Build and static
  lifetime validation do not substitute for that test.
- No driver was installed, loaded, started, stopped, or unloaded.
