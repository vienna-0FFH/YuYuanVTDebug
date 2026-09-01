# Built-in debugger run-over transaction fix (2026-07-24)

## Scope

- This change is R3-only. It does not change VMX, SVM, Intel, AMD, TF, MTF, VM-exit, or driver breakpoint semantics.
- A call step-over and step-out now arm their one-shot breakpoint, resume the target, and return from the Tauri command immediately.
- Single-instruction TF/MTF steps remain serialized and still wait for their completion event.

## Evidence

- `GuardMeta-VtDebug-p10656-1784900406657.log` arms the fall-through breakpoint at `0x7FF62E9713C3` at `1784900419274`. The target is terminated at `1784900423600`, but the old synchronous transaction does not attempt its cleanup until `1784900449278`, almost exactly 30 seconds after arming.
- `GuardMeta-VtDebug-p11504-1784900449389.log` reaches the call at `0x7FF62E9713BE` and arms `0x7FF62E9713C3`. The callee enters the program's console-input path. Waiting there is correct step-over behavior, not a debugger hang.
- The inspected logs contain expected `0x80000004` single-step and `0x80000003` breakpoint events. They do not contain an access violation or illegal-instruction crash. `0xC000013A` records user termination.

## Root cause chain

1. Latent defect: a potentially unbounded run-to-return operation was modeled as a bounded single-instruction transaction.
2. First regressing design decision: the R3 step serialization added on 2026-07-16 kept `step_mutation` held while `finish_step_transaction` waited up to 30 seconds for a call to return.
3. Runtime trigger: step-over or step-out enters a long-running callee, including a blocking console input call.
4. Amplifier: additional step commands wait behind the same mutex instead of being rejected as invalid while the target is running.
5. Final fault mechanism: the 30-second timeout force-suspends the thread and removes the one-shot breakpoint; a queued step can then start against partially recovered state, producing the observed UI stall and a possible run-away sequence.

## Repair

- Native and private-VT transports reject a new step intent while the same TID owns an active one-shot run target.
- Interactive step commands use non-queuing mutex acquisition, so rapid repeated clicks fail immediately instead of accumulating.
- Call step-over and step-out no longer call the 30-second completion/cleanup path.
- The frontend records an active step before invoking Tauri, disables all step entry points, and clears the state only on the matching one-shot hit or command failure.
- N-step execution waits for a call to return without holding `step_mutation`; detach or thread exit terminates that wait. A target blocked on input remains a valid running target.

## Validation

- `cargo check --manifest-path Netr/tools/netr-gui-rs/src-tauri/Cargo.toml`: passed with 25 pre-existing warnings.
- `npm run build`: passed; only the existing Vite mixed static/dynamic import warning was emitted.
- `Netr/build_test.bat Release`: passed; full package refreshed with 14 managed artifacts.
- `GuardMetaCore.sys`: test signature valid, thumbprint `AD39C1B28DF46266E5E74CF60A46A8BEA97BB5F0`.
- Packaged driver, driver PDB, and GUI executable SHA-256 values match their Release outputs.
- Runtime driver loading was intentionally not performed.

## Rollback boundary

Revert only the active-run/async-run-over changes in these files; no R0 rollback is involved:

- `tools/netr-gui-rs/src-tauri/src/commands/debugger_ui.rs`
- `tools/netr-gui-rs/src-tauri/src/commands/native_debug.rs`
- `tools/netr-gui-rs/src/debugger/sessionStore.ts`
- `tools/netr-gui-rs/src/debugger/BreakHitToast.tsx`
- `tools/netr-gui-rs/src/debugger/ToolBar.tsx`
- `tools/netr-gui-rs/src/debugger/hotkeys.ts`

The pre-fix behavior to restore is synchronous `finish_step_transaction` for call step-over/step-out, queued `step_mutation.lock().await`, and no frontend `activeStep` state. Restoring it also restores the documented 30-second timeout hazard.
