# AMD SVM long-mode SS launch validation fix

## Evidence

- Input log: `Netr/test-package/hv-inactive.log`, SHA-256
  `98DF7DC8DF25EAA4DE0C4EDC4B170095D6512C2982E48021ED55CE4447C5C58A`.
- AMD SVM was available: all CPUs reported `EFER.SVME=1`, `VM_CR.SVMDIS=0`,
  and non-zero aligned VMCB, HSAVE, MSRPM, and NCr3 addresses.
- Startup attempted all 16 CPUs. CPUs 0-3 and 5-15 entered the guest; CPU 4
  stopped before VMRUN with `validation=0x00001000(ss)`.
- Cleanup then terminated the 15 successful guests through VMMCALL, so the
  final `virtualized=0/16` value is the all-or-nothing rollback result.

## Root-cause chain

1. Latent defect: AMD64 long mode permits an unusable/null SS, represented in
   a VMCB by a clear SS present bit. AMD VMCB has no VMX-style explicit
   unusable bit.
2. First regressing decision: the new pre-VMRUN validation required
   `VMCB.SS.Attributes.P=1` unconditionally, applying a VMX-style invariant to
   AMD SVM.
3. Runtime trigger: one processor exposed an SS state that the shared segment
   reader represented as unusable, producing VMCB SS attributes with P=0.
4. Amplifier: startup is intentionally all-or-nothing, so one rejected CPU
   caused cleanup of the other 15 successful CPUs.
5. Final mechanism: the driver returned `STATUS_INVALID_PARAMETER` before
   VMRUN on CPU 4; hardware never rejected the VMCB.

## Fix

- Keep the real VMCB SS state unchanged. In particular, do not replace a null
  long-mode SS with the backup project's synthetic `0x0093` attributes.
- Accept SS.P=0 only when `EFER.LMA=1`; retain the present-bit validation for
  non-long-mode guests.
- The change is confined to the AMD SVM launch path. Intel VMX setup and
  validation are unchanged.
- Inactive diagnostics version 3 appends per-CPU SS selector, source access
  rights, final VMCB attributes, and interpretation flags. Structure sizes are
  120 bytes per CPU and 7840 bytes total; the Rust parser remains compatible
  with the previous 104-byte/version-2 records.

## Validation

- `Netr/build_test.bat Release DriverOnly`: passed, 0 driver warnings/errors,
  signature verified.
- `cargo check --manifest-path Netr/tools/netr-gui-rs/src-tauri/Cargo.toml
  --locked`: passed; 25 pre-existing Rust warnings.
- `Netr/build_test.bat Release`: passed; driver, bridge, injectors, GUI, PDBs,
  certificate, and final manifest refreshed.
- Packaged driver signature: valid.
- Source/package driver SHA-256 parity: both
  `EA74B83B74CB59641876EF74E67998EFA3731C91026BF2D35451C5FDF84AEDCB`.
- Runtime validation is still required on the AMD host. No driver was loaded
  or started on the build host.

## Rollback point

If AMD runtime testing disproves the fix, restore the old launch guard by
removing the `EFER.LMA == 0` condition from the SS validation in
`Netr/HvVmcb.c`. Keep diagnostics version 3 so the failed state remains
observable; no Intel code needs to be reverted.
