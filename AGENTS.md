# YuYuanVTDebug Project Workflow

## Scope and source authority

- This host is Windows. Use Windows paths and the existing PowerShell, batch, MSBuild, WDK, and MSVC tooling.
- `Netr` is the only writable implementation mainline.
- `YuYuanVTDebug_备份\Netr` and `E:\project_learning\UnrealVTDbgBAK` are read-only reference baselines. Do not build, format, overwrite, or generate files inside either reference tree.
- Integrate reference behavior selectively. Never replace current files or directories wholesale from a reference project.

## Engineering objective

- Preserve as much useful functionality from the backup and Unreal reference as practical, while prioritizing current-project stability, completeness, and maintainability over feature count.
- Before enabling a migrated feature, close its root/VM-exit lifetime, concurrency, rollback, unload, and failure-path requirements.
- Keep incomplete high-risk features behind existing gates. Document remaining blockers instead of treating compilation as runtime readiness.
- Do not sign or load a driver from an intermediate output directory as a handoff artifact.

## VT-first architecture invariants

- Implement memory introspection, address translation, breakpoint virtualization, and related debugger data paths in the VT layer whenever the hardware architecture permits it.
- For PID-based physical access, PASSIVE-level code may acquire lifetime-protected process identity metadata and immutable candidate inputs only. CR3 ownership validation, page-table walking, and the final physical copy must remain in VMX-root/SVM-host mode through the pre-mapped physical window.
- Do not replace a VT-root path with Windows memory-manager, object-manager, attach-process, or `MmMapIoSpace` walking from the request hot path without the user's explicit architectural approval.
- Treat moving work across the VT-root/Windows boundary as an architecture change, not a local refactor. Review stealth properties, lifetime, IRQL, reentrancy, VM-exit duration, concurrency, failure isolation, and rollback before implementation.
- Keep high-risk gates disabled until the gated path has focused validation. Never enable a dormant VT/root feature in the same change set that substantially rewrites its control or data path.
- Reference projects establish behavioral and architectural intent, not copy authority. Preserve their VT-level properties unless a documented, explicitly approved design supersedes them.

## Root-cause discipline

- Root-cause analysis must identify, in order: the latent defect, the first regressing design decision, the runtime trigger, any retry or concurrency amplifier, and the final fault mechanism.
- Do not label a retry loop, caller, workload, or timing condition as the root cause when it only re-enters or exposes an unsafe kernel path.
- Separate verified facts from inferred intent. Code comments can explain the apparent motivation for a change, but they do not prove correctness or excuse an architecture regression.
- For kernel-crash fixes, compare current code with both read-only baselines, correlate the dump and runtime logs, and repair the earliest violated invariant before applying symptom-level mitigations.

## Build, signing, and test delivery

- The canonical full build is `Netr\build_test.bat Release`.
- A full build is complete only after the driver, DebuggerBridge/injectors, Rust GUI, symbols, certificate, and `SHA256SUMS.txt` have been refreshed in `Netr\test-package`.
- `Netr\build_test.bat Release DriverOnly` is allowed for focused driver iteration, but it must still test-sign the driver, copy the driver/PDB/certificate to `Netr\test-package`, refresh the manifest, and verify package/source hash parity. It is not a complete product build.
- Driver test signing uses `Netr\SignDriver.ps1`. Run `Netr\SetupTestSigning.ps1` once from an elevated PowerShell under the same Windows account that performs builds when the private-key certificate is missing.
- Never place an unsigned current driver in `Netr\test-package`. Signing and package verification must fail closed.
- Treat `Netr\test-package` as the only test handoff directory. Files under `x64`, `DebuggerBridge\bin`, or Rust `target` are intermediate outputs.
- Package runtime binaries and their debugging symbols. Compiler/linker intermediates such as `.obj`, `.lib`, and `.exp` do not belong in the test package.
- Do not automatically install or load the packaged driver unless the user explicitly requests it.

## Validation expectations

- Start with the narrowest relevant build/test, then run the canonical full build before declaring an integrated feature ready for testing.
- Verify the packaged driver signature, source-to-package SHA-256 equality, required artifact presence, and a freshly generated `SHA256SUMS.txt`.
- Treat files listed by `Netr\test-package\UNMANAGED_ARTIFACTS.txt` as legacy/untraceable inputs, not current build outputs.
- Record compile warnings, disabled feature gates, runtime-test gaps, and any stale or untraceable legacy artifacts in the active handoff report.
