# Private Dbgk external VT-HWBP DR6 delivery

## Scope

- This report covers the external-debugger plus self-built VT/private-DebugObject
  failure observed on 2026-07-22.
- It extends the shared vwatch pending-hit design documented in
  `vwatch_hwbp_virtual_dr6_delivery_2026-07-21.md`.
- It does not change EPT matching, MTF completion, page rearm, real TF,
  synthetic MTF stepping, VMCS STI/MOV-SS shadow, or event-injection gating.

## Runtime evidence

- `logs/GuardMetaBridge-5236.log` registered with
  `private_debug_object=1` and bound targets 16068 and 15276 in private-Dbgk
  mode (`flags=0x00060007`).
- Both targets installed slot 0 through the VT path (`mode=1`), then received
  `EXCEPTION_SINGLE_STEP (0x80000004)` as private Dbgk events.
- The Bridge returned native contexts with `dr6=0x0`; the external debugger
  continued both events as `DBG_EXCEPTION_NOT_HANDLED (0x80010001)`.
- Both private transports subsequently terminated with
  `STATUS_DEBUGGER_INACTIVE (0xC0000354)`, matching the reported debugger or
  target disappearance.
- `C:\HvDiagnostics.txt` recorded seven true vwatch hits, seven pending-hit
  publishes, seven injected `#DB` events, zero publish failures, and zero
  overwrites. Only four pending-hit reads reached the pre-existing context-hook
  consumer. The producer, MTF completion, and injection path were therefore
  operating; delivery to every debugger-visible context path was incomplete.
- `logs/GuardMetaBridge-16404.log` used the Windows DebugObject control plane
  (`private_debug_object=0`, `flags=0x00050007`) and progressed beyond startup.
  This isolates the newly reported regression to the private Dbgk boundary,
  not to global VT hardware-breakpoint installation.

## Root-cause chain

1. The latent architectural fact is that VM-entry exception injection carries
   vector 1 but has no field that can manufacture `DR6.B0..B3`.
2. The first regressing design decision was to expose a private Dbgk event to
   an unmodified external debugger without carrying the vwatch hit ownership
   metadata across the private wire protocol. The implementation implicitly
   assumed the Windows DebugObject/context-hook path would always supply it.
3. The runtime trigger was a VT-backed hardware-breakpoint hit while the
   external debugger was using the self-built private Dbgk control plane.
4. Repeated `GetThreadContext` calls amplified the missing metadata: every
   read still showed `DR6=0`, so the debugger classified the event as an
   unrelated single-step and eventually returned it unhandled.
5. The final fault mechanism was loss of debugger ownership for that `#DB`,
   followed by private-session/target termination. EPT matching and MTF page
   rearm had already completed before this boundary failed.

## Reference semantics

- The backup vwatch implementation injects one ordinary vector-1 exception
  after MTF and leaves physical guest DR6 unchanged.
- Unreal's self-built Dbgk path explicitly recognizes the zero-DR6 injected
  single-step case and treats an unhandled single-step as consumed.
- An external debugger cannot use Unreal's internal classifier. It requires
  the corresponding B bit in the context it reads while the event is stopped.
- Therefore the correct compatibility boundary is debugger-visible event
  metadata. Writing physical DR6, enabling global MOV-DR interception, or
  altering VMCS interrupt shadow would change unrelated architectural state
  and is not part of this repair.

## Repair

- `NetrBridgeProtocol.h` reserves one private-event flag and the otherwise
  unused exception-information slots 13 and 14 for the pending-hit generation
  and exact `DR6.B0..B3` mask. The protocol remains version 6 and no structure
  size changes.
- `HvPrivateDebugObject.c` queries the pending-hit table with the exact current
  thread object, debugger owner, and target PID before queueing a single-step.
  Only a matching pending vwatch hit marks the event as VT-HWBP. The event is
  queued to that same debugger owner, and Continue retires only the matching
  generation. A queue failure performs the same exact-generation retirement.
- `DebuggerBridge/Bridge.cpp` stores the mask under the stopped `(PID,TID)`
  event key. `GetThreadContext` and `Wow64GetThreadContext` OR that B mask only
  while the matching private event is pending. The real-TF context setters
  retain or clear the local mask according to the debugger's incoming DR6.
- `ContinueDebugEvent` erases the R3 pending event after the kernel continue
  succeeds, so the B bit cannot leak into a later exception on the same thread.
- Unrelated TF, MTF-step, software-breakpoint rearm, and native exceptions do
  not carry the new event flag and therefore receive no manufactured B bit.

## Follow-up: sticky private hit retirement

- `logs/GuardMetaBridge-15032.log` shows the Windows DebugObject path querying
  `pending_dr6=0x1 generation=24`, then reporting `retire_ok=1`; every later
  ordinary single-step in that run returned to `virtual_dr6=0x0`.
- `logs/GuardMetaBridge-13608.log` shows the private Dbgk path delivering the
  first true hit with `virtual_dr6=0x1`, then repeatedly delivering the same B0
  bit on real-TF steps (including sequences 17 through 32). The pattern repeats
  for later target PIDs and explains both the false HWBP on every step and the
  debugger event storm that makes the target window appear hung.
- The latent defect was the pending-hit record's explicit `EventLatched`
  retirement precondition. The first regressing decision was using the
  ownerless query in private Dbgk; that query deliberately does not latch an
  event or return its generation. The private Continue then called the legacy
  acknowledge helper, which cannot clear an unlatched record.
- The runtime trigger was the first true VT hardware-breakpoint hit. Real-TF
  single-step exceptions amplified the defect by repeatedly querying the same
  stale pending record. The final mechanism was stale `DR6.B0..B3` projection
  into every later step, not a repeated EPT hit and not an MTF/TF dispatcher
  failure.
- The follow-up repair uses the already-proven native owner-plus-generation
  lifecycle at the private Dbgk boundary. It does not alter EPT matching, MTF
  completion, real TF, VMCS STI/MOV-SS shadow, native DebugObject delivery, or
  the built-in debugger path.

## Precise rollback point

Withdraw only this private-Dbgk extension as follows. Do not reset the
worktree and do not remove the shared pending-hit table or context hooks from
the 2026-07-21 repair.

1. Remove `HV_BRIDGE_DBGK_EVENT_VT_HWBP` and
   `HV_BRIDGE_DBGK_VT_DR6_INDEX` from `NetrBridgeProtocol.h`.
2. Remove the exact-thread pending-hit query from
   `HvPrivateDebugObjectDispatchException` and the matching acknowledge call
   from `HvPrivateDebugObjectContinue`.
3. Remove `VirtualDr6`, `LookupPendingPrivateDbgkDr6`, and
   `UpdatePendingPrivateDbgkDr6` from `DebuggerBridge/Bridge.cpp`.
4. Remove private-event DR6 capture in `DeliverPrivateDbgkEvent` and the x64
   and WOW64 context merge/update calls. Restore the prior delivered-event
   trace format.

This rollback leaves the Windows DebugObject path, built-in debugger fallback,
vwatch pending-hit producer, real TF, MTF, STI/MOV-SS shadow, and all EPT
ownership logic unchanged.

For the follow-up retirement repair specifically, the precise rollback point is
the owner-plus-generation extension only: remove
`HV_BRIDGE_DBGK_VT_GENERATION_INDEX`, restore the ownerless pending-hit query
and target-only queue call in `HvPrivateDebugObjectDispatchException`, remove
its exact-generation failure cleanup, and restore the legacy acknowledge call
in `HvPrivateDebugObjectContinue`. Do not roll back the slot-14 DR6 delivery,
context projection, shared pending-hit producer, or any MTF/TF code. This
rollback is retained only for bisectability; it deliberately restores the
confirmed sticky-hit defect.

## Validation state

- `build_test.bat Release` passed on 2026-07-22. The driver built with zero
  warnings and zero errors; Bridge x64/x86, both injectors, the Rust GUI,
  symbols, certificate, license marker, and package manifest were refreshed.
- The Rust crate retained 25 pre-existing warnings.
- `SHA256SUMS.txt` contains 14 managed artifacts with zero missing or
  mismatched entries after the owner-plus-generation follow-up build.
- No feature gate was enabled or disabled by this repair.
- `UNMANAGED_ARTIFACTS.txt` lists 13 pre-existing
  `GuardMeta-VtDebug-*.log` files. They are retained runtime evidence, not
  refreshed or traceable outputs of this build.
- Source/package SYS and PDB hashes match. Final packaged
  `GuardMetaCore.sys` SHA-256 is
  `4C71A1007A9AE5A7C2AE1C95C4292C4EE70B0AFA26A3B028352A1AC3E031A09F`.
- Packaged Authenticode status is `Valid`; signer thumbprint is
  `82FAA0D1CA193262D6EADF824DFE7C6DD2F5ACC4`.
- Runtime confirmation is still required: after the first private-Dbgk event
  with `virtual_dr6=0x1`, its successful Continue must be followed by ordinary
  real-TF events with `virtual_dr6=0x0`. Build and static lifetime validation do
  not substitute for that external-debugger test.
- No driver was installed, loaded, started, stopped, or unloaded.

## Follow-up: thread-scoped HWBP and local EPT invalidation

### Root-cause chain

1. The latent defect was storing external-debugger DR0-DR3/DR7 state by PID,
   although Windows debug registers are thread state.
2. The first regressing decision was replaying all four process-wide vwatch
   slots on every intercepted `SetThreadContext`, even when the state had not
   changed.
3. The runtime trigger was the debugger updating two target threads with
   different DR state. `GuardMetaBridge-3144.log` shows TID 10444 clearing slot
   0 while TID 10436 repeatedly sets it.
4. Every vwatch EPT violation then called `EptInveptAllContexts`. In root mode
   that instruction was local, but the wrapper also incremented the global EPT
   generation, so unrelated processors invalidated their EPT context on later
   VM exits. A hot watched page amplified one target access into cross-CPU
   invalidation churn.
5. The final failure was debugger-window starvation or a machine-wide hard
   lock without a dump. The 8-byte length was not a special vwatch algorithm;
   it only made a frequently accessed data range more likely to trigger the
   page-level EPT path.

### Repair

- The 32-byte HWBP request ABI now uses its final four formerly reserved bytes
  as `TargetTid`. Zero remains the legacy process-wide scope used by the
  built-in debugger and old clients.
- The external Bridge stores state by `(PID,TID)`, serializes commits, skips
  unchanged slots, applies only changed slots, and rolls back only operations
  completed by the failed delta. Thread exit clears the matching four scoped
  slots.
- Vwatch entries are keyed by debugger, PID, TID, and slot. A referenced target
  thread object supplies an opaque token for VM-exit matching. Entry rundown
  prevents that reference from being released while a root reader is using it.
- The vwatch EPT/MTF hot path now invalidates only the actual current EPTP with
  single-context INVEPT. It does not increment the global EPT generation for a
  temporary per-CPU leaf change. Control-plane changes that publish or retire
  entries across processors retain `EptInveptAllContexts`.
- Thread-scoped Bridge requests require VT HWBP and no longer silently fall
  back to the process-wide DR backend. Built-in requests keep `TargetTid=0`
  and retain the existing VT/DR policy.

### Combination boundary

- Built-in plus either DebugObject mode remains process-wide (`TargetTid=0`).
- External plus Windows DebugObject and external plus private Dbgk both use the
  same thread-scoped vwatch installation. Their event transports remain
  separate; pending-hit DR6 ownership and generation retirement are unchanged.
- Real TF, synthetic MTF stepping, private software breakpoints, VMCS
  STI/MOV-SS shadow, and exception disposition were not changed.

### Precise rollback point

If new runtime evidence disproves this repair, revert only this follow-up:

1. Restore the last six HWBP request bytes to `Reserved1[6]` and remove the
   `TargetTid` plumbing from Bridge and Driver.
2. Restore the PID-keyed Bridge DR map and full-state submit functions; remove
   thread-exit HWBP cleanup.
3. Remove vwatch entry `TargetTid`, thread token, and entry rundown, then route
   Driver SET/CLEAR through the process-wide wrappers again.
4. Replace only `HvVwatchpInvalidateCurrentEpt` calls in vwatch EPT/MTF hot
   paths with the previous invalidation call.

Do not roll back the owner-plus-generation DR6 retirement, private Dbgk event
delivery, real-TF implementation, VMCS interrupt shadow, or software-breakpoint
state machine when bisecting this follow-up.

### Current validation

- `build_test.bat Release DriverOnly` and canonical `build_test.bat Release`
  both passed on 2026-07-22. Driver compilation reported zero warnings and zero
  errors; Bridge x64/x86 and both injectors compiled successfully.
- The package step reported 14 managed artifacts. The Rust crate retained 25
  pre-existing warnings unrelated to this change.
- Source and packaged driver SHA-256 both equal
  `AA9EF3690EFA4737CCBE6BE75B4E1A1A7EBD60A9267FBD5556E301BB97228404`.
- Packaged Authenticode status is `Valid` with subject
  `CN=GuardMetaCore Test Signing`.
- Runtime validation is intentionally outstanding. Required evidence is one
  fresh run for each of the four debugger/DebugObject combinations, including
  an 8-byte data watch on the previous workload. No driver was loaded by the
  agent.

## Follow-up: preserve transient thread DR state

### New runtime evidence

- `logs/GuardMetaBridge-3328.log` is the first run after the thread-scoping
  change. At lines 79, 128, 222, and 261, the external debugger submits an
  enabled slot with `address=0`, after which the Bridge records
  `committed=0`. No nonzero HWBP request reaches the driver in that run.
- This is an external-debugger initialization state, not a vwatch hit or an
  EPT/MTF failure. Windows accepts the thread context and permits a later
  context update to supply the final DR address. The Bridge instead exposed
  vwatch's stricter address validation as a `SetThreadContext` failure, so the
  debugger abandoned the later materialization update.

### Repair and invariant

- The `(PID,TID)` virtual DR state remains authoritative and unchanged. A new
  `HardwareSlotMaterializable` predicate separately decides whether an enabled
  slot can currently be represented by vwatch.
- Disabled, null, non-user, unsupported-type, or misaligned intermediate slots
  remain valid virtual thread state but map to no installed vwatch. Transition
  from an unmaterializable state to a valid state installs the scoped watch;
  transition in the other direction clears only that scoped watch.
- `SetThreadContext` therefore retains Windows-compatible transaction
  semantics without restoring the old per-PID collapse. Vwatch matching,
  pending-hit DR6 ownership, private Dbgk delivery, MTF completion, real TF,
  and VMCS interrupt shadow are untouched.
- The x64 and WOW64 context traces now include DR0-DR3 and DR7 so a future run
  proves whether the debugger supplied a final materializable address.

### Precise rollback point

- Revert only `HardwareSlotMaterializable`, restore enabled-state comparison in
  `HardwareSlotsEquivalent`, and restore the enabled check in
  `ApplyHardwareSlot`. The expanded context trace may be retained.
- Do not remove `TargetTid`, the `(PID,TID)` state map, target-thread lifetime,
  entry rundown, local EPTP invalidation, or the DR6 owner/generation repair.

### Validation

- Canonical `build_test.bat Release` passed. Driver compilation and signing
  reported zero warnings and zero errors; both Bridge architectures, both
  injectors, and the GUI were rebuilt and copied to `test-package`.
- `SHA256SUMS.txt` verifies all 14 managed artifacts. Source/package driver
  SHA-256 is
  `B27C7C31EBE942605CC2B83D56AFDBE98582AF11D26F8827555EFDF1ABCA11C3`.
- Packaged Bridge SHA-256 is
  `BBA9AC39F8F4506F7CED1B7A3B78ACEA6BFA25FFD627DC81E7548BCDBEA1D34C`
  for x64 and
  `6172D66CAB97AD984C93E0A84E981E8F236E099A8865C3F7A1EA30695CEED18E`
  for x86. Package hashes match the corresponding build outputs.
- Packaged driver Authenticode status is `Valid`, signed by
  `CN=GuardMetaCore Test Signing`. No driver service operation was performed.
- Runtime confirmation remains required; compilation cannot prove that the
  external debugger sends and hits the later nonzero state.
