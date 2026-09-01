# Vwatch HWBP DebugObject Delivery Repair

## Root-cause chain

1. Latent defect: the `HV_BRIDGE_HWBP_PRIVATE_EVENT` ring is observational; it records a completed MTF hit but does not make Windows hold the faulting thread on a DebugObject event.
2. First regressing decision: VT HWBP setup selected that ring for built-in sessions, and the packaged driver also selected it whenever a private DebugObject binding existed, even when the caller policy was only `ALLOW_VT | ALLOW_DR`.
3. Runtime trigger: vwatch restores the trapped page after MTF and reaches a true HWBP hit.
4. Amplifier: the built-in poller sees the ring only after the target has resumed, while the external bridge explicitly discards `kind=0` HWBP ring records because it expects a real `EXCEPTION_SINGLE_STEP`.
5. Final mechanism: no precise DebugObject event owns the target thread, so three control-plane combinations appear to miss the breakpoint even though diagnostics and ring logs prove the vwatch hit occurred.

## Evidence

- `C:\HvDiagnostics.txt` recorded `Vwatch Violation Hits: 1098`, `Vwatch True Hits: 10`, and zero debugger-intercept publication failures.
- Built-in VT logs recorded `kind=0`, `dr6=1` HWBP ring events after the target had already continued.
- External private-DebugObject logs recorded policy `0x3`, mode `1`, followed by `[PRIVATE] discarded kind=0`; policy `0x3` does not contain the private-event bit `0x4`.
- The Windows-DebugObject external combination worked because it already received the real injected `#DB` path.

## Repair boundary

- Precise VT HWBP delivery now leaves `HV_BRIDGE_HWBP_PRIVATE_EVENT` clear for the built-in debugger and routes the post-MTF `#DB` through whichever real DebugObject owns the target: Windows or private Dbgk.
- The driver no longer changes delivery semantics merely because the target has a private DebugObject binding.
- The built-in event loop merges its VT slot mask with native DR slots when classifying `EXCEPTION_SINGLE_STEP`, then uses DR6 B0..B3 to report `PendingKind::Hardware`.
- Debug-status cleanup also includes VT-owned slot bits.
- The old HWBP ring remains available only as an explicit legacy observational compatibility path.
- This repair does not change TF ownership, MTF execution, the one-instruction pass window, VMCS STI/MOV-SS shadow, page rearm ordering, or software-breakpoint delivery.

## Rollback point

The immediately preceding full test package used driver SHA-256
`C8725FEA33363F91575A141D600EE57F9985B412A216B84E83FAB58A68C23418`.
It contains the corrected CR3-intercept ownership but the broken observational
HWBP delivery described above. Use that hash only as the isolation point if the
new DebugObject route exposes an unrelated regression; do not revert the CR3
ownership repair or alter MTF/STI-shadow semantics.

The new full test package uses driver SHA-256
`692866FC4BA72B8521034E60FA98E97C388FAB24334830936DC4020D6178C878`.

No driver was installed, loaded, unloaded, or started by this repair.

## Build validation

- `build_test.bat Release DriverOnly`: succeeded with zero driver warnings and zero errors; signing and verification succeeded.
- `cargo check --release`: succeeded with 25 pre-existing warnings.
- `build_test.bat Release`: succeeded and refreshed the complete 14-artifact Full package.
- Release/package driver SHA-256 parity: `692866FC4BA72B8521034E60FA98E97C388FAB24334830936DC4020D6178C878`.
- Packaged signature: `Valid`, signer thumbprint `AD39C1B28DF46266E5E74CF60A46A8BEA97BB5F0`.
- `SHA256SUMS.txt`: 14 managed entries checked, zero missing or mismatched.
- `cargo fmt --check` could not run because the installed Rust toolchain lacks the `rustfmt` component; `git diff --check` passed.
- Runtime validation of all four DebugObject/debugger combinations remains pending; the driver was not loaded automatically.
