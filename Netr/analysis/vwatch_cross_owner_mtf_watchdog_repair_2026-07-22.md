# Cross-owner MTF watchdog repair (2026-07-22)

## Status

- The latest crash dump was analyzed and correlated with the debugger runtime logs.
- The VMX-root repair is implemented in `Netr/HvVwatch.c`, `Netr/HvVwatch.h`, and `Netr/HvVmExit.c`.
- `Release DriverOnly` and the canonical full `Release` build both completed successfully.
- `Netr/test-package` contains the refreshed, test-signed full package.
- No driver service was installed, started, stopped, unloaded, or otherwise changed during this repair.
- Exact runtime acceptance remains pending; build success is not treated as proof of kernel-runtime correctness.

## Crash evidence

- Dump: `C:/Windows/Minidump/072226-14000-01.dmp`.
- Dump SHA-256: `1B403D42DD42019B03428FCA8A65859E98AE173D7A823BC9E938B3CA7C1E1779`.
- Dump size: 6,843,675 bytes; last-write time: `2026-07-22 14:32:57 +08:00`.
- Bugcheck: `CLOCK_WATCHDOG_TIMEOUT (0x101)`.
- Arg1 is `0xA`; processor 7 failed to receive the expected clock interrupt for the watchdog interval.
- Failure bucket: `CLOCK_WATCHDOG_TIMEOUT_INTERRUPTS_DISABLED_nt!KeAccumulateTicks`.
- The hung processor's running thread is CID `0df8.2d44`, decimal PID 3576 / TID 11588.
- `Netr/test-package/logs/GuardMetaBridge-17964.log` binds target PID 3576 and records target thread TID 11588 immediately before the machine stops making progress.
- `!analyze -v` reports `x64dbg.exe` as the active crash workload.
- Driver symbols match the loaded `GuardMetaCore.sys` image in the dump.
- The running package associated with this reproduction had SHA-256 `67BA7B4555A719181E867F67F737726B03214A07283526DA667B3D6C10858BE2`.
- `GuardMetaBridge-17052.log` used that same driver generation and completed a nearby two-HWBP scenario, so the failure is timing/state dependent rather than a deterministic bad target address.

## Evidence limit

This is a mini kernel dump. It contains registers and selected stacks but not the driver data pages required to read `g_VwatchManager` or all per-vCPU MTF contexts. It also does not preserve a reliable VMX-root RIP for processor 7. The bugcheck class, hung CPU/thread identity, runtime-log correlation, owner state machines, and the only reachable repeated-violation path support the root cause below with high confidence, but the precise final VM-exit instruction is inferred rather than directly captured.

## Root-cause chain

1. Latent defect: xHCI, Vwatch/private SWBP, PEB cloak, and EptHook independently owned one VMCS-wide `CPU_BASED_MONITOR_TRAP_FLAG` bit. Their per-vCPU restoration contexts had no common completion arbiter.
2. First regressing design decision: the code allowed an earlier owner to arm MTF, while Vwatch treated an already-set VMCS MTF bit as an unconditional reservation failure. MTF completion dispatch could also stop after an earlier owner instead of completing every armed owner for the same guest instruction.
3. Runtime trigger: before an already-armed MTF instruction could complete, that same instruction touched a Vwatch/private-SWBP overlay leaf and generated another EPT violation on processor 7.
4. Retry/concurrency amplifier: Vwatch returned unhandled while its actual restriction remained in `page->CloakedPte[cpu]`. The generic fallback only opened the ordinary EPT leaf, so it did not change the active target overlay. Guest entry retried the unchanged instruction and immediately violated again.
5. Final fault mechanism: processor 7 stayed in the repeated EPT/MTF VM-exit path with interrupts disabled long enough to miss clock/IPI servicing. Another processor then raised bugcheck `0x101`.

## Repair semantics

- `HvVwatchpTryReserveMtf` may reserve an idle Vwatch context even when another known owner already set the VMCS MTF bit. Both contexts then complete after the same guest instruction.
- The MTF dispatcher calls all four known owners on every MTF exit: xHCI, Vwatch, PEB cloak, and EptHook. It no longer short-circuits after the first successful completion.
- If no owner claims an MTF exit, the dispatcher clears the orphan VMCS MTF bit so an unexplained stale bit cannot cause one exit per guest instruction forever.
- If Vwatch cannot merge or reserve its own context, it opens the actual active Vwatch or private-SWBP overlay leaf and returns handled. The generic ordinary-EPT fallback is not entered.
- Conflict fail-open favors machine liveness over perfect breakpoint coverage. The affected leaf can remain open until its next control-plane republish; this is an explicit degraded state, not a claim that exactly one hit is lost.
- PEB cloak and EptHook already fail open their own active leaves on cross-owner reservation failure. xHCI already opens its own PTE on an outstanding same-owner conflict. Those paths were reviewed and left unchanged.
- Real TF, synthetic debugger MTF policy, VMCS STI/MOV-SS interrupt shadow, DR6 delivery, exception routing, nested-VT policy, and frontend behavior are unchanged.

## Owner audit

A source-wide search found exactly four writers of the VMCS MTF control in the current driver: `HvXhciEptTrap.c`, `HvVwatch.c`, `HvPebCloak.c`, and `EptHook.c`. No fifth current owner is bypassed by the dispatcher. The backup and Unreal reference projects demonstrate the normal single-owner allow-one-instruction/restore-on-MTF sequence, but neither composes this project's four independent overlay owners; the cross-owner arbitration is therefore current-project integration work rather than a reference behavior that can be copied verbatim.

## Diagnostics

- `g_VwatchManager.MtfSharedReservations` counts Vwatch reservations that joined an already-enabled VMCS MTF completion.
- `g_VwatchManager.MtfConflictFailOpens` counts conflicts resolved by opening the active overlay leaf.
- Existing `MtfMergedCollisions`, `MtfMergedTrueHits`, and `MtfMergeFailures` continue to describe same-Vwatch private-SWBP/watch merging.
- These are symbol-visible counters only; no VMX-root logging was added.

## Build and package validation

- `Netr/build_test.bat Release DriverOnly`: passed; driver C/ASM had zero warnings and zero errors; signing and package collection passed.
- `Netr/build_test.bat Release`: passed; driver, x64/x86 Bridge DLLs, x64/x86 injectors, Rust GUI, symbols, certificate, license marker, and manifest were refreshed.
- The full build retained 25 unrelated Rust unused/dead-code/private-interface warnings and one existing Vite dynamic/static import warning.
- Final source/package driver SHA-256: `3D5A49A7F355300D4297D7DD6E41E16F624AE020B6A4EB49A12FDB4CDB754420`.
- Packaged driver Authenticode status: `Valid`; signer `CN=GuardMetaCore Test Signing`; thumbprint `82FAA0D1CA193262D6EADF824DFE7C6DD2F5ACC4`.
- `SHA256SUMS.txt`: 14 managed artifacts, 14 verified, zero missing, zero mismatched.
- Source/package parity was independently verified for the driver and ten Bridge/Injector/GUI artifacts.
- Existing runtime `.log` files remain explicitly listed in `UNMANAGED_ARTIFACTS.txt`; they are evidence, not current build outputs.

## Source hashes

- `Netr/HvVmExit.c`: `6F81320F8B35821CB851B2738677DEF5922323F3D217AA2340A74831EDD3C413`.
- `Netr/HvVwatch.c`: `8C34C62FC536C366B005D14A717948002F5447CAF91CADE7ECAAB7369F8DED93`.
- `Netr/HvVwatch.h`: `E646C5FD4E51F039DDBAADECD17E4C8DDC2AF806DA44962EEB1A0B1704F098F5`.

## Rollback point

- The exact pre-repair package locator is driver SHA-256 `67BA7B4555A719181E867F67F737726B03214A07283526DA667B3D6C10858BE2`.
- That package is known to reproduce this watchdog and is retained as an isolation point, not a recommended runtime package.
- A surgical source rollback consists only of: restoring Vwatch's rejection of an already-set VMCS MTF bit, removing the two active-overlay fail-open branches and their counters, and restoring the prior MTF dispatcher order/short-circuit behavior.
- Do not reset or replace the working tree, and do not roll back the earlier virtual-DR6, private DebugObject, real-TF, or STI-shadow work when isolating this repair.
- If runtime validation finds a new regression, first compare the two new counters and the four owner contexts. Revert these isolated hunks only after preserving the failing package and logs.

## Required runtime acceptance

1. Reproduce the exact internal/private VT scenario that created PID 3576 / TID 11588 and confirm the target runs beyond the former hang point without `0x101`.
2. Repeat the two-HWBP run that previously succeeded to verify no deterministic breakpoint regression.
3. Exercise internal and external debuggers in native VT and self-hosted VT, with and without synthetic MTF where that option applies.
4. Confirm hardware watch hits still report the expected virtual DR6 slot and stop after the writing instruction.
5. After the run, inspect the newest Bridge logs and both MTF diagnostic counters before accepting the package.
