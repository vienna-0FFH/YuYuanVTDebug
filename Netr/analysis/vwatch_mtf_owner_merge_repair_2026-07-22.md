# Vwatch / VT-step MTF owner merge repair (2026-07-22)

## Status

- Implemented in `Netr/HvVwatch.c` and `Netr/HvVwatch.h` only.
- `Release DriverOnly` and canonical full `Release` both completed successfully.
- The packaged driver is test-signed and source/package hashes match.
- No driver service was installed, started, stopped, or unloaded during this repair.
- Runtime validation of the exact reproduction remains pending on the test machine.

## Verified reproduction

- Target image base: `0x7FF624260000`.
- One-byte write watch: `0x7FF624263000`.
- The original watched write completes and stops at RVA `0x16A4` with virtual DR6 `B0` set.
- VT-step reaches RVA `0x172F`, instruction bytes `48 89 05 D2 18 00 00`.
- That instruction writes `0x7FF624263008`, which is on the same EPT page but outside the watched one-byte range.
- Both Windows DebugObject and private Dbgk logs then report `0xC000001D` at `0x7FF62426172F`:
  - `test-package/GuardMeta-VtDebug-p39976-1784648551010.log`
  - `test-package/GuardMeta-VtDebug-p19940-1784648479557.log`

## Root-cause chain

1. Latent defect: Vwatch and private-SWBP stepping share the single per-vCPU VMCS MTF bit, but Vwatch had no way to attach its page restoration to an already armed owner.
2. First regressing design decision: `HV_VWATCH_MTF_SWBP_REARM` was added as a Vwatch MTF owner while the later Vwatch EPT path still treated any enabled MTF as an unrecoverable reservation failure.
3. Runtime trigger: the instruction being executed under SWBP rearm accesses a separately trapped Vwatch page before that instruction completes.
4. Retry amplifier: `HvVwatchHandleEptViolation` returned `FALSE`; the generic EPT fallback changed the ordinary EPT leaf, not `page->CloakedPte[cpu]`, so the Vwatch restriction remained and the same instruction violated repeatedly.
5. Final fault mechanism: the EPT repeat guard injected `#UD`; user mode observed `STATUS_ILLEGAL_INSTRUCTION (0xC000001D)` at the unchanged RIP.

## Reference comparison

- `YuYuanVTDebug_备份/Netr/HvVwatch.c` implements the expected allow-one-instruction, MTF-complete, restore-trap sequence, but it has no private-SWBP MTF owner and therefore cannot demonstrate owner collision handling.
- `E:/project_learning/UnrealVTDbgBAK` provides the original debugger behavior reference but does not combine this project's private-SWBP overlay and Vwatch restoration in one per-vCPU VMCS MTF context.
- The missing behavior is therefore composition introduced by the current project, not a reason to remove the reference semantics.

## Repair semantics

- `HvVwatchpCanMergeWatchIntoSwBpMtf` accepts only an armed, hardware-enabled `HV_VWATCH_MTF_SWBP_REARM` owned by the same per-vCPU Vwatch context.
- The Vwatch page rundown remains held, `PendingPage` is attached without replacing the SWBP owner fields, and the Vwatch leaf is temporarily made RWX for the current instruction.
- The existing MTF completion restores both the private-SWBP shadow leaf and the Vwatch trap leaf before disabling MTF and releasing both rundowns.
- A same-page non-hit such as `+0x8` produces no additional `#DB`.
- If the stepped instruction itself truly hits the watched bytes, the merged completion publishes virtual DR6 metadata and produces one debugger stop, rather than a step stop plus a second hardware-breakpoint stop.
- STI/MOV-SS interrupt shadow handling, real-TF paths, DebugObject routing, and frontend behavior are unchanged.

## Diagnostics

- `g_VwatchManager.MtfMergedCollisions`: accepted SWBP-rearm/Vwatch collisions.
- `g_VwatchManager.MtfMergedTrueHits`: accepted collisions that truly hit the configured byte range.
- `g_VwatchManager.MtfMergeFailures`: MTF reservation failures that could not be safely merged.
- These counters are symbol-visible for a dump/kernel-debugger inspection and do not add root-mode logging.

## Build and package

- Driver build: zero warnings, zero errors.
- Full build: driver, 32/64-bit bridge and injectors, Rust GUI, PDBs, certificate, and manifest refreshed.
- Existing unrelated Rust/Vite warnings remain; no new warning is attributable to this repair.
- Packaged driver SHA-256: `54C9D7371A468A54CA79CF827AB98634EA3AF1E183EB56A6CB332F1BD5399EF7`.
- `Netr/x64/Release/GuardMetaCore.sys` and `Netr/test-package/GuardMetaCore.sys` hashes are equal.
- Authenticode status: valid; certificate thumbprint `AD39C1B28DF46266E5E74CF60A46A8BEA97BB5F0`.
- `SHA256SUMS.txt` contains the packaged driver hash.
- Existing `.log` files are listed by `UNMANAGED_ARTIFACTS.txt` and are not current build outputs.

## Rollback point

- Reported immediately pre-repair running-package SHA-256: `8FAD981D43F00DBA0C78722B95E117F3207251754F4415EBA25FD1C249D2748E`.
- The exact repair rollback is stored in `Netr/analysis/vwatch_mtf_owner_merge_rollback_2026-07-22.patch`.
- Rollback scope is limited to the three MTF counters, the merge predicate/path, dual-page completion, and the extracted completed-hit helper; it does not revert the earlier virtual-DR6 delivery work.

## Required runtime check

1. Reproduce the one-byte watch at `0x7FF624263000` and VT-step through the write to `0x7FF624263008`.
2. Confirm the next stop advances beyond `0x7FF62426172F` and no `0xC000001D` is delivered.
3. Confirm the original watched write still reports DR6 `B0` and stops after the writing instruction.
4. Repeat for Windows DebugObject and private Dbgk; then smoke-test external debugger and non-VT fallback combinations for regression.
