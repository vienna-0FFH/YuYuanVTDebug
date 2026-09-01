# VT HWBP debugger-context DR6 delivery

## Authority and disproved package

- This document is the current rollback and handoff authority for VT hardware-breakpoint delivery.
- The packaged driver with SHA-256
  `AFD94D37D58ABD6BD7B197919B7B5900010F1705A07280F7282D8A519BF52BF2`
  was disproved by runtime testing. It attempted to expose a pending vwatch
  B0-B3 bit through temporary MOV-DR interception.
- The failed package must not be restored as a known-good implementation.
  Its temporary MOV-DR design produced no guest DR6 reads and therefore did
  not cross the Windows exception/context boundary.

## Runtime evidence

- `GuardMeta-VtDebug-p4612-1784599241724.log` and
  `GuardMeta-VtDebug-p11552-1784599294822.log` both received
  `EXCEPTION_SINGLE_STEP`, then classified the event as
  `dr6=0x0 configured=0x1 vt=0x1 hit=0x0`.
- The same events were returned as `DBG_EXCEPTION_NOT_HANDLED`; both targets
  exited with `0x80000004`.
- `C:\HvDiagnostics.txt` recorded `Vwatch True Hits: 2` and
  `Vwatch Injected #DB: 2`, while the temporary MOV-DR read counter remained
  zero. EPT matching, MTF completion, page rearm, and vector-1 injection all
  completed; the first failed boundary was debugger-visible DR6 delivery.

## Reference semantics

- The backup `HvVwatch.c` injects one ordinary vector-1 exception after MTF
  and does not manufacture a hardware DR6 B bit.
- Unreal's Dbgk path explicitly recognizes an injected single-step event with
  `DR6.BS == 0` and no `B0..B3` bit as the self-built VT event case.
- Therefore an injected `#DB` with physical guest DR6 equal to zero is the
  reference VT semantic. A B0-B3 bit is debugger metadata, not a VM-entry
  payload and not a reason to alter VMCS interrupt shadow or MOV-DR controls.

## Root-cause chain

1. Vwatch correctly traps the watched access, temporarily permits the page,
   executes one instruction with MTF, rearms the page, and injects one `#DB`.
2. VM-entry interruption information carries the vector and exception type,
   but has no field for DR6 B0-B3.
3. The disproved design assumed a later guest MOV-DR read would retrieve a
   pending B bit. Windows delivered the debug event without executing that
   read path, so the pending metadata was never consumed.
4. `NtGetContextThread` returned the stopped thread's native zero DR6.
5. The built-in classifier treated the event as unowned, and external
   consumers could return it unhandled.

## Current repair

- `HvVwatch.c` records the exact `(thread token, debugger PID, target PID,
  slot)` before injecting the ordinary reference-style `#DB`.
- The record lives in a fixed, nonpaged, allocation-free 128-entry table. It
  is published from VMX-root, observed from the context hook, acknowledged
  when the debugger clears the corresponding DR6 bit, and cleared on debugger
  or target teardown.
- `HookedNtGetContextThread` preserves the native context and ORs only the
  pending `DR6.Bx` bit into a debugger-requested debug-register context.
- `HookedNtSetContextThread` captures the debugger's incoming DR6 before the
  existing virtual-DR interception removes the debug-register flag. After the
  original syscall succeeds, a cleared B bit acknowledges and retires the
  pending record.
- Debugger-proxy activation now treats both `NtGetContextThread` and
  `NtSetContextThread` as required core hooks. A missing context hook rolls
  the transaction back instead of publishing a false enabled state.
- The built-in R3 event loop retains the backup/Unreal zero-DR6 semantic as a
  fallback. It applies only when a VT hardware breakpoint exists and the event
  is not an MTF step, TF step, or breakpoint-rearm step. One configured VT
  slot reports that slot; multiple slots stop as `Hardware { slot: None }`
  instead of terminating the target as `unowned-single-step`.
- The external-debugger private-Dbgk extension is documented separately in
  `private_dbgk_external_vt_hwbp_dr6_delivery_2026-07-22.md`. That path carries
  the exact B bit in private event metadata because it does not reliably cross
  the Windows DebugObject context-hook boundary.

## Semantic boundary

- This repair does not claim to create a physical hardware DR6 condition in
  the guest. It preserves the reference project's injected-`#DB` behavior.
- It makes the debugger-visible `GetThreadContext`/`SetThreadContext` lifetime
  equivalent to a hardware breakpoint for B0-B3 observation and clearing.
- Code inside the debuggee that directly reads DR6 before debugger context
  collection still sees the native architectural value. That distinction is
  deliberate and avoids reintroducing global MOV-DR or VMCS state changes.

## Four combinations

| Debugger | VT control plane | Delivery |
| --- | --- | --- |
| Built-in | Windows DebugObject | Context hook supplies Bx; zero-DR6 reference fallback remains available |
| Built-in | Private Dbgk | Same context hook and fallback after the private event is queued |
| External | Windows DebugObject/proxy | Context hook supplies and later acknowledges Bx |
| External | Private Dbgk bridge | Private event metadata supplies Bx only for the stopped event lifetime |

The legacy `HV_BRIDGE_HWBP_PRIVATE_EVENT` direct-ring path is unchanged; its
event already carries `Dr6 = 1 << slot` explicitly.

## Deliberately unchanged

- EPT violation matching, MTF execution, INVEPT, and page-rearm order.
- VMCS STI/MOV-SS interrupt shadow and event-injection gating.
- Built-in synthetic MTF single-step and its frontend option.
- Real TF single-step, software-breakpoint step-over, and native DR fallback.
- The previously repaired real-DR/MOV-DR ownership and CR3-only isolation.

## Precise rollback point

Do not reset the worktree and do not copy either reference project over the
mainline. To withdraw only this repair while preserving earlier ownership and
single-step fixes:

1. Remove `HV_VWATCH_PENDING_HIT`, its fixed table, counters, query API, and
   acknowledge API from `HvVwatch.h` and `HvVwatch.c`.
2. Remove the pending-hit publish call immediately before `HvVwatchpInjectDb`;
   retain the ordinary one-shot `#DB` injection itself.
3. Remove the `NtGetContextThread` B-bit merge and `NtSetContextThread`
   acknowledgement from `HvHook.c`; retain virtual DR0-DR3/DR7 behavior.
4. Remove `reference_vt_hardware_hit` from `native_debug.rs` to restore the
   prior `unowned-single-step` behavior.
5. Remove the five pending-hit diagnostics fields and output values.

The later private-Dbgk extension has its own narrower rollback steps in
`private_dbgk_external_vt_hwbp_dr6_delivery_2026-07-22.md`; do not remove the
shared pending-hit producer when withdrawing only that extension.

The runtime state immediately before this repair is identified by the failed
`AFD94D...BF52BF2` package hash above. It is a rollback locator, not a stable
release.

## Validation state

- Active source contains no `VwatchPendingDr6`,
  `VwatchTransientMovDrExit`, or `HvVwatchpInjectHardwareDb` implementation
  symbol. `VirtualDr6` now exists only as stopped private-event R3 metadata for
  the documented 2026-07-22 external private-Dbgk extension.
- `cargo fmt --check` could not run because this host's Rust toolchain does not
  have the `rustfmt` component installed; no component was installed as part
  of this repair.
- `build_test.bat Release DriverOnly` passed with zero driver warnings and
  zero errors. Signing, verification, the 4-artifact Driver profile, and
  package refresh completed.
- `build_test.bat Release` passed again on 2026-07-22 after the private-Dbgk
  extension. The driver built with zero warnings and zero errors;
  DebuggerBridge, both injectors, the Rust GUI, symbols, certificate, license
  marker, and manifest were refreshed. The Rust crate retained 25
  pre-existing warnings.
- Final source/package `GuardMetaCore.sys` SHA-256 parity is
  `C057387E0D2B94DC5B127DFA310DB85E73869077FD2495FC147AC81BB296D04F`.
- Packaged Authenticode status is `Valid`; signer thumbprint is
  `AD39C1B28DF46266E5E74CF60A46A8BEA97BB5F0`.
- `SHA256SUMS.txt` contains 14 managed entries with zero missing and zero
  mismatched files. The two prior runtime logs are correctly listed in
  `UNMANAGED_ARTIFACTS.txt` and are not current build outputs.
- No driver was installed, loaded, started, stopped, or unloaded.
