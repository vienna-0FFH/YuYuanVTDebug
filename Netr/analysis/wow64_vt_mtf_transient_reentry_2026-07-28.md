# WoW64 VT synthetic-step transient re-entry repair (2026-07-28)

## Status

- The first reproduction is `test-package/GuardMeta-VtDebug-p15128-1785227561418.log` from the 16:25 package.
- The follow-up reproduction is `test-package/GuardMeta-VtDebug-p13892-1785230269198.log` from the 17:04 package. It corrected the initial attribution: continuous step-over invokes the internal active-run cancellation path at `debugger_ui.rs:6104`; the public legacy cleanup guard alone was insufficient.
- The pending-aware active-run cancellation repair below was built into the refreshed 17:26 full Release package.
- The local 2026-07-29 reproductions are `test-package/GuardMeta-VtDebug-p17592-1785304955621.log` and `test-package/GuardMeta-VtDebug-p17944-1785304931489.log`. They exposed a second R3 state mismatch after the cancellation repair: a hit transient was preserved correctly, but `ensure_no_private_run_target` still classified it as an unhit running target and rejected the next step before `vt_step.begin`.
- A non-semantic R0 diagnostic remains included so any failure after atomic pending reuse reports its exact stage instead of inviting another speculative MTF change.
- No driver was installed, loaded, started, stopped, or unloaded during this work.

## Evidence

- The target is a WoW64 process and enters at `0x401310` (`log` lines 25 and 96).
- A run-over transient private SWBP hits `0x40131A`; the private poller suspends TID 6884, records sequence 2, and deliberately defers cleanup (`log` lines 141-146).
- A separate R3 call removes that same breakpoint 399 ms later while sequence 2 is still pending (`log` lines 147-148).
- The next single-step successfully continues sequence 2, creates another breakpoint at `0x40131A`, and successfully arms VT step (`log` lines 149-158), but no native step event is consumed and the private breakpoint immediately re-enters at the unchanged RIP as sequence 3 (`log` lines 160-166).
- The same pattern repeats once at `0x40131F` (`log` lines 194-214). Later sequential steps complete normally through `0x401338` (`log` lines 217-300).
- In the follow-up log, sequence 2 is correctly published as `transient=true` and deferred at `0x40131A`, but `dbg_cancel_active_run` still consumes it through caller line 6104 before the next step begins (`follow-up log` lines 145-154).
- The next command therefore reports `source=new-transient`, not `source=pending-transient`, and again re-enters `0x40131A` (`follow-up log` lines 155-172). No `private_swbp.step_root_failure` is present because the original pending entry was detached before the atomic root conversion could be attempted.
- In the 2026-07-29 local logs, the call fallthrough is preserved as a pending transient (`p17592` sequence 4 at `0x7FF63E5713E1`; `p17944` sequence 2 at `0x7FF63E571275`). Every later command records `private_swbp.transient_cancel.deferred`, but no new `vt_step.begin` follows. This excludes an R0/MTF failure and pins the rejection to the R3 pre-step target check.

## Why the debugger reports an error and then continues

`wait_for_builtin_thread_pause` requires a native synthetic-step event after an MTF step. Re-entering the private gate at the unchanged RIP violates that completion condition, so the current command correctly reports an error instead of pretending that one instruction executed. The private poller has already suspended the real thread and retained the new event sequence, however, so the session and target remain recoverable. A later step consumes that retained event and can succeed when the conversion wins. This is recovery from an incomplete transaction, not proof that the failed step was semantically correct.

## Root-cause chain

1. Latent defect: a transient private SWBP has two owners, the R3 one-shot registry and the pending private-event transaction, but cancellation and cleanup paths checked only the registry owner.
2. First regressing design decision: the private poller was changed to preserve a hit transient for immediate step reuse, while `dbg_cancel_active_run` continued to enumerate and unregister every transient owned by the thread without excluding the matching pending hit.
3. Runtime trigger: the user continuously invokes step-over; a call step-over hits its one-shot breakpoint, and the frontend active-run lifecycle invokes cancellation while that hit is still the pending private event.
4. Retry/concurrency amplifier: removing a driver entry in `HvPrivateSwBpHitPending` intentionally converts it to `HvPrivateSwBpDisarmedPending`; continuing that sequence succeeds by finalizing the disarmed entry, after which R3 adds and arms a replacement at the same RIP. The successful control-plane statuses conceal that the original atomic reuse transaction was already split.
5. Final fault mechanism: the first root attempt does not complete the private-SWBP-to-MTF transition, the unchanged instruction re-enters the private gate, and R3 rejects the step as incomplete. The old package did not expose whether the final root rejection was active-PTE lookup, MTF reservation, entry-state CAS, or another guarded stage, so that sub-stage is not asserted without evidence.
6. Follow-up R3 defect: once pending-aware cancellation preserves the hit correctly, the pre-step `ensure_no_private_run_target` check still treats every transient registry entry as an executing run target. A pending hit is suspended and is no longer executing toward that target, so this stale classification rejects all subsequent step-over commands at a call fallthrough.

## Repair

- `dbg_consume_transient_bp` now refuses legacy removal only when the address is still owned by that TID's transient registry entry and the matching private event remains pending.
- `dbg_cancel_active_run` now applies the same pending-owner rule: it records `private_swbp.transient_cancel.deferred` and leaves the hit entry intact for the next step to reuse atomically. Unhit cancellation targets are still removed normally.
- `ensure_no_private_run_target` now excludes only the transient whose PID, owner TID, and address match the suspended pending private hit. Any other unhit transient for the thread remains a hard rejection, so concurrent run-target protection is unchanged.
- `dbg_suspend_thread` treats a matching pending private event as already suspended, preventing stale or duplicate UI paths from incrementing the suspend count again.
- Transient cleanup records its Rust caller location in the existing per-session file log.
- `HV_PRIVATE_SWBP_ENTRY.StepDiagnostic` records the first guarded root conversion failure. A repeated SWBP event carries the diagnostic in the otherwise unused SWBP `Dr6` field, and R3 emits `private_swbp.step_root_failure stage=...` to the same session log.
- MTF ownership, MTF completion, VMCS STI/MOV-SS shadow, real TF, exception injection, AMD behavior, external-debugger behavior, and hardware-breakpoint delivery are unchanged.

## Reference comparison

- `YuYuanVTDebug_备份/Netr` has the older memory/software-breakpoint cleanup API and no equivalent pending private-EPT-SWBP ownership transaction.
- `E:/project_learning/UnrealVTDbgBAK` does not combine this project's private EPT SWBP overlay, Rust pending-event poller, and synthetic-MTF receiver.
- The repair is therefore current-project integration work; copying either legacy cleanup path would restore the premature deletion.

## Validation

- `cargo check --manifest-path tools/netr-gui-rs/src-tauri/Cargo.toml`: passed with 25 pre-existing warnings.
- `cargo fmt --check`: not run because `cargo-fmt.exe` is not installed in the local stable toolchain; no formatter component was downloaded.
- `build_test.bat Release DriverOnly`: passed and test-signed the focused driver package.
- `build_test.bat Release`: passed; driver, bridge, injectors, GUI, symbols, certificate, license marker, and manifest were refreshed as 14 managed artifacts.
- Packaged driver signature is valid and matches certificate thumbprint `AD39C1B28DF46266E5E74CF60A46A8BEA97BB5F0`.
- Release/package SHA-256 parity passed for the driver, driver PDB, GUI, and GUI PDB.
- Final 17:26 package hashes: driver `A9C5AEE8DE71F6636197F3DD940F19B2527DCE61163E0A79004BBF55E10C260B`; GUI `27A0A41557198B914EB7A20572EF954EB7CF7896BF1ED50C527F6E6C695C8C9C`.
- The 2026-07-29 follow-up passed `cargo check` with the same 25 pre-existing warnings and the canonical `build_test.bat Release` full build. The refreshed 14-artifact package was generated at 14:09:15; every manifest hash and the driver/driver-PDB/GUI/GUI-PDB source parity check passed.
- The packaged driver signature is `Valid` with thumbprint `AD39C1B28DF46266E5E74CF60A46A8BEA97BB5F0`. Current hashes: driver `A125AEB1CDE048231C18B9376F7D41DEFD6F8507340ABACD085C88483780DB6B`; GUI `C858CC141E8DD48D04DDA41BFF68290037DFFFB4CC7D3EB2EDC6EE550B86FFDE`.
- Runtime validation of the repaired call-step-over sequence remains pending; no driver was installed or loaded as part of the build.

## Runtime acceptance

- On a call step-over transient hit, the new log should contain `private_swbp.transient_deferred`, then `private_swbp.transient_cancel.deferred`, then `vt_step.pending_reuse`; it must not contain caller line 6104 removing that address before reuse.
- The command immediately after `private_swbp.transient_cancel.deferred` must reach a new `vt_step.begin`; absence of that line indicates the R3 pre-step gate still rejected the suspended pending hit.
- A successful reuse should advance RIP on the first step attempt without another private event at the same address.
- If same-RIP re-entry remains, the log must contain `private_swbp.step_root_failure stage=...`; fix only the reported invariant and do not change MTF/STI/TF semantics speculatively.
- Recheck native/self-hosted VT and internal/external combinations after the focused WoW64 case passes.

## Rollback boundary

Rollback is limited to the pending-aware legacy/active-run cleanup guards, the pending-hit exclusion in `ensure_no_private_run_target`, the already-suspended guard, transient cleanup caller diagnostics, and `StepDiagnostic` transport/decoding in:

- `tools/netr-gui-rs/src-tauri/src/commands/debugger_ui.rs`
- `HvVwatch.c`
- `HvVwatch.h`

Do not roll back private-SWBP MTF ownership, STI shadow, real-TF selection, hardware-breakpoint delivery, AMD support, or external-debugger paths when isolating this change.
