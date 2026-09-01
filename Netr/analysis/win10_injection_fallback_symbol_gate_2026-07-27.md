# Win10 loader fallback and built-in symbol gate handoff (2026-07-27)

## Scope

- Fix ordinary DLL injection when the kernel APC implementation returns `STATUS_NOT_SUPPORTED` on Windows 10.
- Persist every injection stage to a file that can be copied back from a remote machine.
- Stop the built-in VT debugger from resolving private kernel symbols while `VT self-built DebugObject` is disabled.

## Verified root causes

### Loader fallback

1. Latent defect: the R3 helper discarded a nonzero `LoadLibraryW` thread result unless a second Toolhelp module enumeration found the exact normalized path.
2. First regressing decision: full-path module enumeration was made the sole success authority to avoid x64 `HMODULE` truncation, although a nonzero low 32-bit result already proves that the full pointer was non-null.
3. Runtime trigger: Toolhelp enumeration can fail or report a path through a different alias even after `LoadLibraryW` succeeds.
4. Amplifier: none is required; a single successful load can be reported as a failed fallback.
5. Final mechanism: the GUI receives a helper failure and reports that both the kernel path and Windows loader fallback failed.

The exact remote Windows 10 failure from the previous package cannot be proven without its helper output. The corrected package therefore also records architecture selection, helper path, DLL path, exit code, stdout, and stderr.

### Built-in kernel symbols

1. Latent defect: `bridge_register_builtin` always requested `BRIDGE_CAP_PRIVATE_DEBUG_OBJECT`.
2. First regressing decision: capability negotiation was tied to opening the built-in VT debugger rather than to the current private-DebugObject setting.
3. Runtime trigger: attach or launch in built-in VT mode with the self-built option disabled.
4. Amplifier: the registration path can be entered more than once during a launch or attach.
5. Final mechanism: the granted private capability caused `configure_private_dbgk_symbols` to run and fail on a missing private kernel symbol.

## Changes

- `Netr/DebuggerBridge/Injector.cpp`
  - Treat a nonzero remote `LoadLibraryW` result as authoritative success.
  - Retain exact-path enumeration only to disambiguate the rare x64 case where a valid module base has zero low 32 bits.
  - Emit a success record for both already-loaded and newly-loaded modules.
- `Netr/tools/netr-gui-rs/src-tauri/src/commands/debugger_bridge.rs`
  - Append injection diagnostics to `GuardMeta-injection.log` beside the GUI executable.
  - Fall back to `%ProgramData%\GuardMeta\Logs\GuardMeta-injection.log`, then `%TEMP%\GuardMeta-injection.log` if the executable directory is not writable.
  - Include the actual diagnostic path in fallback errors.
- `Netr/tools/netr-gui-rs/src-tauri/src/commands/inject.rs`
  - Record request parameters, IOCTL transport errors, returned NTSTATUS, module metadata, and final transport selection.
- `Netr/tools/netr-gui-rs/src-tauri/src/commands/antivmp.rs`
  - Expose the driver-reported private-DebugObject state to the built-in debugger backend.
- `Netr/tools/netr-gui-rs/src-tauri/src/commands/debugger_ui.rs`
  - Request and configure private-DebugObject capability only when the driver setting is enabled.
  - Reject a setting change that races registration instead of choosing the wrong control plane.

## Validation

- `Netr\DebuggerBridge\build.bat NoCollect`: x64 and x86 bridge/helper builds passed.
- `cargo check --release`: passed with 25 pre-existing warnings.
- `Netr\build_test.bat Release`: passed; driver build and signing reported 0 warnings and 0 errors.
- `Netr\test-package\SHA256SUMS.txt`: all 14 managed artifacts matched.
- Packaged driver signature: `Valid`, signer thumbprint `82FAA0D1CA193262D6EADF824DFE7C6DD2F5ACC4`.
- Source and packaged driver SHA-256: `A353ED98622E22AC776DF4531C3325D6FCBEB51CAFFF5F8A78165235FA1A82A9`.
- No driver was installed or loaded during this work.

## Remote test evidence needed

- Retry ordinary loader injection from the refreshed `Netr\test-package`.
- If it still fails, copy `GuardMeta-injection.log` from the same directory as `guardmeta-vsp.exe`; the UI error also names the fallback path if that directory was not writable.
- With `VT self-built DebugObject` disabled, built-in VT attach/launch must not enter `configure_private_dbgk_symbols` and must not report `missing kernel symbol`.
