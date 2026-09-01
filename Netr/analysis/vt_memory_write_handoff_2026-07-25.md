# VT memory-write handoff (2026-07-25)

## 2026-07-26 mutable-MZ anchor correction

- Correction to the earlier incident interpretation: the latest runtime did
  not damage the on-disk PE. The shared image page was materialized as a
  process-private COW page and the file hash remained unchanged.
- `GuardMetaBridge-16360.log` shows the decisive sequence. Write `#3` changed
  one byte at the in-memory `ImageBase` successfully through
  `cow-materialize -> vt-after-cow`; the very next read of that address and all
  later VT reads returned `STATUS_NOT_FOUND` from `stage=6(vt-root-copy)`.
  No crash exception preceded the eventual `EXIT_PROCESS_DEBUG_EVENT`.
- The latent defect was `VrRootValidateCr3Snapshot` treating the mutable DOS
  `MZ` bytes as a permanent process-identity anchor. The first triggering
  design decision was validating every fresh PID request against byte content
  that the debugger is explicitly allowed to edit. Changing either DOS-magic
  byte made every candidate CR3 look foreign, so the debugger lost all VT
  memory access and eventually ended the debuggee.
- Request version 2 now captures the physical page addresses from the
  MDL-locked `PEB+0x10` and image-base pages. Root mode walks each candidate CR3
  and accepts it only when both translations reach those exact locked PFNs.
  The ownership check therefore remains fail-closed against wrong/stale CR3s,
  while PEB or PE-header byte edits no longer invalidate the process identity.
- The shared-image COW policy is retained. It prevents a debugger edit from
  changing a shared mapping, but it is not the cause of the post-write VT loss.

## 2026-07-26 shared-image safety correction

- The 2026-07-25 VT-first external write policy was unsafe for a still-shared
  `MEM_IMAGE` page. Pinning with `IoReadAccess` made the page resident but did
  not give the target process private ownership of its PFN.
- The first regressing decision was changing external bound-target writes from
  COW-first to unconditional VT-first. A raw physical copy bypasses guest PTE
  protection and Windows image COW, so it can alter a PFN shared with other
  mappings. This is a separate safety defect; the later
  `stage=6(vt-root-copy)` failure was caused by the mutable-MZ identity anchor,
  not by disk-file damage or COW itself.
- `DriverWriteMemory` now classifies every page of an ordinary write. Committed
  `MEM_PRIVATE` pages and image pages already proven non-shared stay VT-first.
  Shared `MEM_IMAGE` pages and write-copy `MEM_MAPPED` pages use a three-phase
  path: VT-read the original bytes, submit those same bytes to the OS-COW IOCTL,
  verify the working-set `Shared` bit is clear, then apply the requested bytes
  with the VT writer.
- Materialization or private-ownership verification failure is fail-closed.
  The requested bytes are never sent to the raw physical writer while the page
  is shared. A VT failure after verified materialization may use the OS helper
  because the page is already process-private.
- Ordinary shared writable `MEM_MAPPED` pages and unknown mappings are rejected;
  silently writing either mapping could modify a shared section or its backing
  file. Software-breakpoint overlays and Windows-system-module routing remain
  unchanged.
- Every external bound-target write now logs a write sequence, address, length,
  mapping type/protection, working-set ownership, selected route, IOCTL status,
  copy stage, and byte count in `GuardMetaBridge-<pid>.log`.
- If the driver COW helper cannot materialize an image page, the bridge may use
  its saved original `WriteProcessMemory` pointer with the original bytes. The
  same working-set ownership verification is mandatory before any requested
  byte reaches the VT writer, so this fallback cannot reopen the shared-PFN
  path.
- The tested `vmpre.exe` remained unchanged on disk with SHA-256
  `CFB2EAEDA4D9EC4DB7880A2A4888A59D260D10B9424423CFEE5FEB819E0EAD86`.
  This incident is classified as loss of VT process identity after an
  in-memory PE-header edit, not as on-disk PE corruption.

## 2026-07-26 validation

- `Netr\build_test.bat Release DriverOnly` and
  `Netr\build_test.bat Release`: passed; neither build installed or started the
  driver.
- Driver compilation/signing completed with zero warnings and zero errors.
  Packaged Authenticode status is `Valid`, and source/package SHA-256 parity is
  `2B336472B4ED062DCC286D4EA564F28F45F32D443EECC1FFE5EBA9BB94E591FE`.
- Bridge SHA-256 parity passed across `DebuggerBridge\bin`, the Tauri release
  target, and `test-package`: x64
  `34120ABA1D392BF659F20C400B815B551EFE7198EE7B9C81B4A39BC3287A9CA2`;
  x86 `16F2AB9B7909B0EAF18E0C88B93BDC1137D057D4C93A12F1984C886B5C5F4502`.
- `SHA256SUMS.txt` contains 14 Full-profile artifacts and all 14 verified.
- Existing unrelated build diagnostics remain: one Vite chunking warning and
  25 Rust unused/private-interface/dead-code warnings.
- Final service check returned `1060`; `Netr` is not installed or running.

## Scope

- Fixes VT memory writes to valid user pages whose guest mapping is read-only, including image `.text` pages.
- Keeps address translation and the final copy in VMX-root/SVM-host through the pre-mapped scratch physical window.
- Does not change debugger stepping, breakpoint, exception, attach, or detach state machines.
- Does not install or load the built driver.

## Root cause chain

1. Latent defect: `HvVtRootCopyByPid` used `IoWriteAccess` to pin a write target even though the MDL is only a residency/lifetime guard for the later physical copy.
2. First regressing design decision: target-page residency permission was coupled to copy direction. The same conditional exists in the pre-AMD checkpoint, so this is not an AMD-specific regression.
3. Runtime trigger: the debugger edits a readable but non-writable user mapping such as an executable image page.
4. Amplifier: every retry repeats the same PASSIVE-level probe failure before any VM-exit occurs.
5. Final fault mechanism: `MmProbeAndLockProcessPages(..., IoWriteAccess)` rejects the mapping, so `HvVtRootRootProcessRequest` and the VT-root physical write are never reached.

## Fix

- `Netr/HvVtRoot.c`: the target range is now pinned with `IoReadAccess` for both directions.
- The lock only makes the current PFNs resident and lifetime-stable. Write authorization is not delegated to the guest PTE or Windows copy APIs.
- Intel still enters through `AsmVmCallPhysCopy`; AMD still enters through `AsmVmmCallPhysCopy`. Both dispatch to the same `HvVtRootRootProcessRequest` and `VrRootWalkAndCopyOnePage` implementation.

## Four debugger combinations

- Built-in + native: unchanged; uses `VirtualProtectEx` and `WriteProcessMemory`.
- Built-in + VT: fixed path; uses the shared VT-root physical-copy implementation.
- External + native/unbound: unchanged; uses the debugger's original `WriteProcessMemory`.
- External + VT/bound: reads use VT-root. Ordinary private-page writes use
  VT-root first. Shared image/write-copy pages must complete and verify COW
  materialization before the requested bytes can reach VT-root. Software-
  breakpoint overlays and their Windows-system-module exception remain separate.

## Semantic boundary

- A direct VT physical write intentionally ignores guest `PTE.RW`, matching the
  backup's documented physical-write contract and Unreal's GVA-to-HVA direct-
  copy behavior, but it is now restricted to pages proven process-private.
- Windows-assisted COW is used only to establish process ownership. Address
  translation and the requested final copy remain in VT-root whenever the VT
  path succeeds.
- Fully VT-owned COW would require shadow pages plus page-table, TLB, process-
  exit, rollback, concurrency, and unload lifetimes. That larger architecture
  is not added by this focused safety repair.
- No feature gate was enabled or changed.

## Validation

- `build_test.bat Release DriverOnly`: passed; driver compile/sign/verify completed with 0 warnings and 0 errors.
- `build_test.bat Release`: passed; driver, bridge/injectors, Rust GUI, symbols, certificate, and package manifest refreshed.
- Packaged driver Authenticode status: valid.
- Source/package driver SHA-256: `28C57FCB45973F7EEEFEEE946B64A9C57E39C1BC884CE759558025B756BDB000`.
- Bridge binary SHA-256 parity passed across `DebuggerBridge/bin`, the Tauri release target, and `test-package`: x64 `AB06383D4C965FF7F4198EDAAEA940FEB7A071F4186F4BDE82E204E484F49AEA`; x86 `BE1908CE3355BB1E9E24BBDB669C7FE68A96F97113A9E0FEE9C159D57892C0EF`.
- `SHA256SUMS.txt`: all 14 managed artifacts verified.
- Existing full-build warnings remain: one Vite dynamic/static import warning and 25 Rust unused/private-interface/dead-code warnings; none originate from these memory-route changes.
- `UNMANAGED_ARTIFACTS.txt` lists two pre-existing runtime logs; they remain intentionally outside the managed artifact manifest.

## Runtime test gap

The driver was not loaded automatically. Test each combination with writable
data and read-only image bytes, verify immediate readback, and include a cross-
page write. For external VT, retain a pre-test hash of the target PE, verify the
log contains `cow-materialize` followed by `vt-after-cow`, and confirm the disk
hash and a second process mapping remain unchanged.

## Rollback point

Reverting the target-range lock in `HvVtRootCopyByPid` from unconditional `IoReadAccess` to `IsWrite ? IoWriteAccess : IoReadAccess` restores the previous behavior, including failure on read-only mappings. No other code change is required for that rollback.

If working-set ownership verification proves incompatible on a target host, the
safe rollback is COW-only for image/mapped pages and VT-first only for
`MEM_PRIVATE`; do not restore unconditional VT fallback for a shared page. The
pre-correction bridge hashes recorded in the 2026-07-25 validation section are
an unsafe diagnostic checkpoint, not a deployment rollback target.

## 2026-07-26 built-in detach after target exit

### Evidence and root cause

- `GuardMeta-VtDebug-p16452-1785053635093.log` recorded a successful VT target
  unbind followed by `ResumeThread(17068)` failing with `ERROR_INVALID_HANDLE`.
  Every later detach retry found the DebugObject session absent but retained the
  same impossible suspension-handle ownership.
- The user confirmed the target process may have been closed before detach.
  `GuardMeta-VtDebug-p12520-1785053850970.log` is the control case: the same VT
  Windows DebugObject entry-stop path detached normally while the target lived.
- Latent defect: pending-event cleanup could prove thread exit only through the
  thread handle. Once that handle was invalid, it never consulted the retained
  process-identity handle, so process termination could not retire the local
  suspension record.
- Runtime trigger: the target process exits while a VT private breakpoint event
  owns a user-mode `SuspendThread` record. Repeated UI detach calls amplify the
  stale record but do not cause the original failure.
- Final mechanism: the driver and DebugObject ownership are already gone, but
  `target_refs` remains solely because cleanup treats a naturally vanished
  thread suspension as retryable forever.

### Fix and safety boundary

- `debugger_ui.rs` now queries the cached process handle with
  `GetExitCodeProcess` after a failed thread resume. A non-`STILL_ACTIVE` result
  proves that all thread suspension state for that process has naturally ended.
- A live or unproven process still preserves the previous fail-closed behavior;
  arbitrary `ResumeThread` failures are not swallowed and no TID is reopened,
  avoiding a same-PID TID-reuse race.
- `ERROR_INVALID_HANDLE` marks the raw handle value as already gone. Cleanup
  does not call `CloseHandle` on it again, preventing an ABA race from closing a
  newly reused handle value.
- The VT write, stepping, breakpoint, exception, driver, and external-debugger
  paths are unchanged. No feature gate was enabled or changed.

### Build and deployment validation

- `cargo check`: passed. `build_test.bat Release`: passed; driver, bridge,
  injectors, Rust GUI, symbols, certificate, and `test-package` were refreshed.
- Driver signing and verification completed with zero warnings and zero errors.
  Packaged Authenticode status is `Valid` with signer
  `CN=GuardMetaCore Test Signing`.
- Source/package parity independently passed for all 13 copied binaries and
  symbols. `SHA256SUMS.txt` contains 14 managed artifacts and all 14 hashes
  independently verified.
- Packaged driver SHA-256:
  `2D28CF7B1D41627518EF7404422F357DDD9576CA8BC004C4809F164126418AF2`.
- Existing unrelated diagnostics remain: one Vite chunking warning and 25 Rust
  unused/private-interface/dead-code warnings. Runtime logs remain unmanaged.
- Runtime test remains required: stop at a VT private breakpoint, terminate the
  target externally, then detach. Expected result is success with
  `lifecycle.detach.suspension_retired` in the per-target diagnostic log. The
  build did not install or load the driver.
