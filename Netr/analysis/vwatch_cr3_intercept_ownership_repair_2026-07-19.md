# Vwatch CR3 Intercept Ownership Repair

## Root-cause chain

1. Latent defect: vwatch pages exist only in `EptPebSpoof`, so a target must be classified on CR3-load before that overlay can produce an EPT violation.
2. First regressing decision: the lazy-intercept repair made `g_GlobalHwbpRefCount` the sole owner of both CR3-load and MOV-DR exits, although that counter represents real DR slots only.
3. Runtime trigger: after a VT hardware breakpoint is accepted, the DR fallback is removed and the real-DR reference count returns to zero.
4. Amplifier: target scheduling and KPTI CR3 transitions continue while CR3-load exiting is disabled, so the active EPTP can remain the main EPT indefinitely.
5. Final mechanism: the watched page is never selected from the overlay EPT, therefore no vwatch EPT violation and no debugger event can occur.

## Repair boundary

- A shared two-bit mode publishes `CR3` and `MOV_DR` independently.
- Real DR slots own `CR3 | MOV_DR`; vwatch entries own `CR3` only.
- Mode changes are serialized and broadcast to every virtualized CPU.
- A first vwatch entry acquires CR3 ownership before publication; failure aborts the set operation.
- Single clear, bulk clear, process cleanup, and shutdown release exactly the number of removed vwatch entries.
- Removing real DR state cannot withdraw CR3 while vwatch still owns it, and removing vwatch state cannot withdraw real-DR exits.
- VMX and SVM handlers replace only the managed bits and clear stale DR7 whenever MOV-DR ownership is withdrawn.

## Rollback point

The pre-change lazy-intercept implementation is the post-repair state recorded in
`analysis/r0_cr3_lazy_intercept_repair_2026-07-19.md`. Reverting this follow-up
means removing vwatch CR3 references and restoring the prior boolean
`VMCALL_TOGGLE_HWBP_INTERCEPTS` publication; do not restore globally pre-armed
CR3/MOV-DR controls.

No driver is installed, loaded, unloaded, or started by this repair.

## Build validation

- `build_test.bat Release DriverOnly`: succeeded with zero driver warnings and zero errors; signing and verification succeeded.
- `build_test.bat Release`: succeeded and refreshed the full test package; the GUI retained 25 pre-existing Rust warnings.
- Release/package driver SHA-256 parity: `C8725FEA33363F91575A141D600EE57F9985B412A216B84E83FAB58A68C23418`.
- Packaged signature: `Valid`, signer thumbprint `AD39C1B28DF46266E5E74CF60A46A8BEA97BB5F0`.
- `SHA256SUMS.txt`: 19 entries checked, zero missing or mismatched.
- Runtime hardware-breakpoint validation remains pending; the driver was not loaded automatically.
