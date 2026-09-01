# AMD support and driver build

## Build model

- `Release|x64` is a unified Intel/AMD driver configuration. It compiles both
  `AsmVmx.asm` and `AsmSvm.asm`, links VMX/EPT and SVM/NPT sources, then selects
  the vendor at runtime in `HvInitialize`.
- There is no AMD-only configuration or CPU-specific x64 code-generation flag.
  Creating a renamed copy would not produce a different AMD implementation.

## Current alignment

- Implemented for AMD: SVM startup/teardown, NPT identity map and split pages,
  VT-root physical memory requests through `VMMCALL`, generic NPT inline hooks,
  real-TF exception handling, NPT-backed debugger stepping, ASID/vGIF hardening,
  and experimental nested SVM/NPT.
- Not aligned with Intel: vwatch VT hardware breakpoints and private software
  breakpoints are explicitly Intel-only; AMD therefore advertises only the DR
  hardware-breakpoint fallback. Continuous PEB overlay cloak is disabled by
  `HV_ENABLE_SVM_CLOAK=0` because its NPT ownership/rollback/unload lifecycle is
  not implemented.
- Nested SVM/NPT and the SVM hardening path have static/build validation but no
  AMD-machine runtime validation in this workspace. AMD hidden-process/driver
  status reporting is also less complete than Intel.

## Build result

- `build_test.bat Release DriverOnly` completed successfully on 2026-07-22.
  Driver C/ASM compilation, linking, signing, and package collection reported
  zero warnings and zero errors.
- Source and packaged driver SHA-256 both equal
  `279E6F558857F8B5AC80658DDD0B97E8937BD07C35720E6EB519C93549ED40D4`.
- Packaged Authenticode status is `Valid`; signer thumbprint is
  `82FAA0D1CA193262D6EADF824DFE7C6DD2F5ACC4`.
- The Driver profile manifest verifies all four managed artifacts. The handoff
  artifact is `test-package/GuardMetaCore.sys`; on AMD it automatically selects
  SVM/NPT.
- No driver was installed, loaded, started, stopped, or unloaded. Runtime AMD
  behavior remains unverified until tested on an AMD host with SVM enabled.
