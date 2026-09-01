# External VT pending-HWBP and private-exit repair

## Scope

This repair closes two independent external-debugger failures without changing
EPT/NPT byte matching, MTF execution, real-TF policy, VMCS interrupt shadow, or
the built-in debugger event path:

1. Windows DebugObject mode could lose VT DR6 ownership before the Bridge
   classified the stopped event.
2. Private Dbgk mode could delete its session on target exit without delivering
   `EXIT_PROCESS_DEBUG_EVENT`.

## Verified runtime evidence

### Windows DebugObject path

- `test-package/logs/GuardMetaBridge-13196.log:844` records a single-step at
  target address `0x7FF6009116A4` with `raw_dr6=0`, configured slot mask `1`,
  and `virtual_dr6=0`.
- The event is continued as `DBG_EXCEPTION_NOT_HANDLED` at line 853.
- Windows then reports a system breakpoint and returns the same address as a
  second-chance single-step at line 891.
- The producer injected vector 1, but the event boundary no longer carried a
  B0-B3 owner. Passing the exception to the debuggee is therefore the observed
  failure mechanism, not a valid way to ignore it.

### Private Dbgk path

- `test-package/logs/GuardMetaBridge-15968.log:2175` proves that the private
  transport can deliver the same VT hardware hit with `virtual_dr6=0x1`.
- Across the three recorded target sessions, no event code 5 is delivered.
- Each session instead ends with `STATUS_DEBUGGER_INACTIVE (0xC0000354)` at
  lines 1001, 1579, and 2224; the following native continue attempt fails with
  Win32 error 642.
- This isolates the window-stall symptom to missing process-exit delivery and
  premature private-session teardown, not to vwatch hit production.

## Root-cause chain

### Native event ownership

1. **Latent defect:** an injected `#DB` has no VM-entry field that manufactures
   guest `DR6.B0..B3`; ownership must remain in the R0 pending-hit record until
   the debugger event is durably classified.
2. **First regressing decision:** the standard path treated any live context
   query as sufficient observation and allowed a later
   `SetThreadContext(DR6=0)` to clear the record before the Bridge owned the
   corresponding `WaitForDebugEvent` result.
3. **Runtime trigger:** vwatch completed the watched instruction under MTF and
   injected a first-chance vector-1 event.
4. **Amplifier:** debugger-internal Get/SetContext traffic repeatedly entered
   the live R0 context proxy before event classification.
5. **Final fault:** the Bridge saw B0-B3 equal to zero, the debugger classified
   the event as unowned, and `DBG_EXCEPTION_NOT_HANDLED` sent it through target
   SEH and second-chance delivery.

### Private process exit

1. **Latent defect:** the private session lifetime assumed that the hooked
   `DbgkExitProcess` producer would always enqueue the terminal event.
2. **First regressing decision:** process-exit cleanup removed a target session
   immediately, with no fallback terminal event and no delivered-event hold.
3. **Runtime trigger:** a private-debugged target terminated through a path
   that did not reach the producer hook.
4. **Amplifier:** the Bridge wait loop retried after the target had already
   disappeared from the private session list.
5. **Final fault:** wait returned `STATUS_DEBUGGER_INACTIVE`, Bridge fail-closed
   cleanup ran, and the external debugger never received code 5 to close its
   normal debug loop.

## Repair

### Event-owned R0 HWBP latch

- `IOCTL_HV_BRIDGE_PENDING_HWBP` provides owned query and retire operations.
- Driver validation requires a registered debugger, its exact target binding,
  a TID that belongs to that PID, and matching pending-record ownership.
- The owned query returns the low-four-bit DR6 mask plus its generation and is
  the only query that marks the record as event-latched.
- Ordinary `NtGetContextThread` reads can expose DR6 to existing consumers but
  do not authorize a subsequent context write to delete it.
- Native Wait stores DR6 and generation by exact `(PID,TID)`. Native Continue
  retires that exact generation only after Windows accepts the continue.
- Pending entries are atomically claimed before query, acknowledgment, owner
  validation, or clearing. A producer that publishes the next hit between
  Continue and retire can no longer have that newer generation cleared by the
  older event.

### Private terminal-event lifetime

- The process notify callback queues one nonblocking private exit event as a
  fallback; an atomic per-session gate deduplicates it against the normal hook.
- Target-exit cleanup retains a session while its exit event is queued.
- Bridge delivery no longer unbinds a private target before the debugger sees
  the exit event. Successful private Continue removes the event first, then
  performs authoritative target/session unbind.
- Driver unbind explicitly tears down the private session even if process-exit
  cleanup already removed the ordinary protected-target binding.

## Concurrency and failure boundaries

- R0 pending records use an atomic FREE/PUBLISHING/VALID claim state. All owner,
  generation, latch, and DR6 checks occur while the entry is exclusively
  claimed.
- Failed native Continue keeps the R3 event entry and R0 generation intact.
- A stale Continue generation cannot clear a newer hit for the same thread.
- Private exit events retain referenced process/thread objects until Continue
  or explicit detach cleanup frees the event.
- No driver service stop, unload, load, or runtime test is part of this change.

## Rollback points

The two repairs are independent:

1. Native-HWBP rollback removes the `PENDING_HWBP` protocol/IOCTL, the owned
   query/retire APIs, and the generation field in the native Bridge event map.
   Restore the prior live-context-only latch only as a diagnostic rollback; the
   cited runtime log already proves that stage insufficient.
2. Private-exit rollback removes `HvPrivateDebugObjectNotifyProcessExit`,
   `ExitEventQueued`, target-session retention in
   `HvPrivateDebugObjectUnbindOnProcessExit`, and post-Continue unbind in the
   Bridge. This restores the known `STATUS_DEBUGGER_INACTIVE` failure.

Do not roll back MTF, real TF, VMCS STI shadow, EPT/NPT watch matching, or the
built-in debugger synthetic-event path with either isolated rollback.

## Validation state

- `DebuggerBridge\build.bat NoCollect` passed for the x64/x86 Bridge DLLs and
  both injectors after the final latch/claim revision.
- `build_test.bat Release DriverOnly` compiled and linked the driver with zero
  warnings and zero errors, then successfully test-signed and verified it.
- The canonical `build_test.bat Release` compiled the driver, both Bridge
  architectures, both injectors, the TypeScript/Vite frontend, and the Rust GUI.
  Rust retained 25 pre-existing warnings.
- The current signed intermediate driver is
  `x64/Release/GuardMetaCore.sys`, SHA-256
  `67BA7B4555A719181E867F67F737726B03214A07283526DA667B3D6C10858BE2`.
  Authenticode is valid with signer thumbprint
  `82FAA0D1CA193262D6EADF824DFE7C6DD2F5ACC4`.
- Both canonical builds initially failed only at final package collection while
  the old `test-package/GuardMetaCore.sys` was mapped. At deployment time the
  `Netr` service no longer existed, so the full collector completed without
  creating or starting a service.
- `test-package` now contains the current signed driver, both Bridge builds,
  both injectors, GUI, symbols, certificate, license marker, and refreshed
  manifest. Its 14-entry `SHA256SUMS.txt` verifies with zero missing or
  mismatched entries, and source/package SHA-256 parity passes for the driver,
  driver PDB, both Bridge DLLs, and GUI executable.
- The packaged driver SHA-256 is
  `67BA7B4555A719181E867F67F737726B03214A07283526DA667B3D6C10858BE2`.
  No driver service was created, installed, or started during deployment.
- Runtime acceptance still requires both of these traces:
  - native mode: `[NATIVE-WAIT] ... pending_dr6=0x1 generation=<nonzero>` and a
    matching `[NATIVE-CONTINUE] ... retire_ok=1`;
  - private mode: event code 5, successful `[DBGK-CONTINUE]`, followed by
    `[DBGK-EXIT] ... unbound=1` without `0xC0000354` or Win32 642.
- Build success does not substitute for those two runtime checks.
