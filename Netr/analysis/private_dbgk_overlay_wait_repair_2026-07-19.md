# Private Dbgk Overlay Wait Repair

## Evidence

- Real-TF log: `test-package/GuardMeta-VtDebug-p6612-1784450253614.log`.
- MTF log: `test-package/GuardMeta-VtDebug-p8556-1784450218937.log`.
- Both runs successfully add and hit a persistent private user SWBP, resolve the target TID, suspend the target thread, insert `pending_private`, and publish the hit.
- The next `WaitForDebugEventEx` fails with `0x80070006`; the worker then unbinds. Later breakpoint removal status `1` and the MTF detach `ResumeThread` failure occur after that loss of ownership.
- Before deferred PEB cloak activation, the same private Dbgk worker continuously waits and continues events normally.

## Root Cause

1. Latent defect: the private Dbgk syscall hook page was installed only in the main EPT.
2. First regressing design decision: `HvPrivateDebugObjectInstallNtHook` passed `OverlayVisible=FALSE` even though the private control plane must remain callable while a target overlay EPT is active.
3. Runtime trigger: after a private SWBP hit, execution can reach `NtWaitForDebugEvent` while the active EPTP still selects the target overlay.
4. Amplifier: the worker polls `WaitForDebugEventEx`, so the first bypass immediately repeats the invalid native operation on the synthetic Event handle.
5. Final fault: the unhooked native `NtWaitForDebugEvent` receives the synthetic Event handle and returns `STATUS_INVALID_HANDLE`, surfaced as `ERROR_INVALID_HANDLE`.

The five private syscall entries are on the same kernel 4 KB page on the tested build. Making the private Nt-hook page overlay-visible preserves `NtCreateDebugObject`, `NtSetInformationDebugObject`, `NtWaitForDebugEvent`, `NtDebugContinue`, and `NtRemoveProcessDebug` as one coherent control plane. No MTF, TF, #DB injection, STI shadow, private SWBP state, or user-mode detach policy is changed.

## Change And Rollback

- Change: `HvPrivateDebugObjectInstallNtHook` now passes `OverlayVisible=TRUE`.
- Pre-change `HvPrivateDebugObject.c` SHA-256: `B9651BEBFC6E24F38E2D73A541E69C78FBEA0BA01DC4DF5204386AA4FF9A8DA2`.
- Post-change `HvPrivateDebugObject.c` SHA-256: `23E989CD8B07BB11607CCE56836C947204BB2D31C028CB8745407F0352823831`.
- Roll back only this boolean if hook activation fails, overlay PTE preparation fails, unrelated debugger modes regress, or runtime testing still produces `0x80070006`.

No driver is installed, loaded, unloaded, or started by this repair.

## Validation

- `build_test.bat Release DriverOnly`: succeeded; driver build, signing, and verification reported zero warnings and zero errors.
- `build_test.bat Release`: succeeded; driver, Bridge/injectors, Rust GUI, symbols, certificate, and package manifest were refreshed.
- Rust GUI: 25 pre-existing unused/dead-code warnings; no build failure.
- `SHA256SUMS.txt`: 14 managed entries, 14 matched, 0 missing or mismatched.
- Release/package driver SHA-256: `2D7467BF38A6C6FAA1A35F1F9B6E6E919543ADAE91C26B15407865EFA213E380`.
- Packaged driver signature: `Valid`, subject `CN=GuardMetaCore Test Signing`.
- Release/package `GuardMetaCore.pdb` and `guardmeta-vsp.exe` hashes match.
- The eight supplied debugger logs remain in `test-package` as explicitly unmanaged evidence and are not covered by the refreshed manifest.
- No matching GuardMeta/Netr service, process, or loaded system driver was found after the builds.

Runtime validation still requires the two focused cases: private Dbgk with real TF and private Dbgk with MTF. The expected result is that a persistent user private SWBP can be removed and the worker remains attached; MTF detach must then resume and close the pending thread handle normally.
