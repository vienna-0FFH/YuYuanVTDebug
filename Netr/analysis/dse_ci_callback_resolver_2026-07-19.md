# DSE `0x222040` / `STATUS_NOT_FOUND` repair

## Scope

- Only the DSE resolver path in `Netr/HvHook.c` changed.
- No debugger, private DebugObject, Vwatch, VM-exit single-step, TF/MTF, VMCS, or NPT/VMX debugger state-machine code changed.
- The existing `CiValidateImageHeader` hook callback and enable/remove ownership semantics remain unchanged.
- No driver was installed, loaded, stopped, or unloaded during this work.

## Root cause

1. The GUI sends `IOCTL_HV_DISABLE_DSE` with the correct value `0x222040`.
2. The driver reaches `HvDseDisable()` and first asks the generic EAT resolver for `ci.dll!CiValidateImageHeader`.
3. The installed `C:\Windows\System32\ci.dll` does not export `CiValidateImageHeader`; its named exports include `CiInitialize`, `CiValidateFileObject`, and other public entry points only.
4. `MmGetSystemRoutineAddress(L"CiValidateImageHeader")` cannot resolve this private `ci.dll` symbol either.
5. The driver therefore returned `STATUS_NOT_FOUND`; `DeviceIoControl` surfaced the localized Win32 `ERROR_NOT_FOUND` text.

The IOCTL number, Tauri command registration, frontend button, and driver dispatch were not the failing components.

## Binary evidence

- Image: `C:\Windows\System32\ci.dll`
- Image timestamp: `0xBE1011E5`
- Image size: `0xFA000`
- Matching public PDB identity: `9D153DEA-53E8-E79F-8F34-0C1C89026BEC`, age `1`
- Public-symbol RVA: `CiValidateImageHeader = 0x541D0`
- `CipInitialize` publishes the callback table with a unique instruction anchor at RVA `0x45264`:
  - callback `+0x20` = `CiValidateImageHeader`
  - callback `+0x28` = `CiValidateImageData`
  - callback `+0x18` = `CiQueryInformation`
- An offline scan of the installed image produced exactly one match and resolved target RVA `0x541D0`.

## Repair

The DSE path now has a private-symbol resolver that:

1. Locates loaded `ci.dll` through `SystemModuleInformation`.
2. Validates the in-memory PE64 headers and section table.
3. Scans only executable, non-discardable sections.
4. Requires the three adjacent callback-publication stores described above.
5. Resolves all three RIP-relative targets and validates that each lies in executable `ci.dll` memory.
6. Accepts exactly one match; ambiguous or unknown builds fail closed.
7. Falls back to the prior `MmGetSystemRoutineAddress` path only if the private resolver does not produce a target.

The generic kernel-export resolver used by other features was not modified.

## Rollback boundary

To return to the pre-repair DSE resolver, remove the `HvDsep*` helper block and the `HvDsepResolveCiValidateImageHeader()` fallback inside `HvDseDisable()`. The old behavior is then restored: EAT lookup, `MmGetSystemRoutineAddress`, and `STATUS_NOT_FOUND` when both fail.

Do not roll back unrelated debugger or VT files for this change.

## Validation

- Offline current-image resolver check: one anchor, `0x45264 -> 0x541D0`.
- `Netr\build_test.bat Release DriverOnly`: success, driver C/ASM `0 warning / 0 error`, signed Driver profile refreshed.
- `Netr\build_test.bat Release`: success, driver C/ASM `0 warning / 0 error`, Bridge/injectors and Rust/Tauri GUI rebuilt.
- Full package manifest: `14/14` entries verified.
- Source/package driver SHA-256: `E7E7F36A4424A50A77096CDD01192F9FFF275470E69ACB16CFB4EF2567E630CD`.
- Packaged driver Authenticode: `Valid`, signer thumbprint `AD39C1B28DF46266E5E74CF60A46A8BEA97BB5F0`.
- Existing Rust build warnings remain; no new Rust/frontend code was added for this repair.

## Runtime gap

This validates the resolver and delivery chain, not live DSE bypass behavior. The driver was not loaded, so disable, unsigned-driver load, re-enable, repeated toggle, and unload-after-toggle still require an isolated runtime test. The existing high-risk hook behavior was intentionally not broadened in this repair.
