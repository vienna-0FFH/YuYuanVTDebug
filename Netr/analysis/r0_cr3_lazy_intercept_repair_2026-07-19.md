# R0 CR3 Lazy-Intercept Repair

## Evidence recorded before the repair

- `C:\Windows\Minidump\071926-13703-01.dmp` is a `0x50` with `Arg4=0xF` (`USER_VA_ACCESS_INCONSISTENT`) while `explorer.exe` executes `NtWaitForWorkViaWorkerFactory`.
- The older `071826-14109-01.dmp` is a `0x133` DPC timeout whose captured path is `KiSwapDirectoryTableBaseTarget`, Windows' CR3 address-space switch path.
- The current uncommitted `HvVmcs.c` pre-arms `CPU_BASED_CR3_LOAD_EXITING` and `CPU_BASED_MOV_DR_EXITING` on every CPU, even when `g_GlobalHwbpRefCount == 0`.
- The stable `HEAD` and the backup do not pre-arm those debugger exits. The current change therefore moves the first unsafe boundary to global CR3 emulation, before any debugger is loaded.

## Pre-repair hashes

- `HvVmcs.c`: `5EDDAFB75F38F00FBDE4BD0591B57BAE6DFE7F34EE4642317DED07239353DB05`
- `HvVmcb.c`: `B98CED3FECDB2DE2218A72FE9B382544484DEC55F1A07A4CEA17EAC823AA6666`
- `HvDebugger.c`: `DA47C3049E4192A5094F9F1B5441D10995EB0EEDB2EB5CE10FEF8EB0E17D552A`
- `HvVmExit.c`: `84A40BBF092A203994A17DBA42D9F05A57B4FC685570E81C733B255A4712A918`

## Repair boundary

- VMX/SVM start with CR3/DR debugger exits disabled.
- The first active HWBP requests a synchronized VMCALL broadcast that enables those exits on every virtualized CPU.
- The last active HWBP disables them with the same mechanism.
- No STI-shadow, MTF, pending-DB, or unrelated hook code is changed by this repair.

No driver is installed, loaded, unloaded, or automatically started by this change.

## Post-repair validation

- `build_test.bat Release DriverOnly`: succeeded; driver compile/sign/verify reported zero warnings and zero errors.
- `build_test.bat Release`: succeeded; all product artifacts were refreshed. The Rust GUI retained 25 pre-existing unused/dead-code warnings.
- `SHA256SUMS.txt`: 14 entries, 14 matched, 0 missing or mismatched.
- Release/package driver parity: `B09839F6BBD586EE97D47BF2C4B61262DCA2BCBB050A080A12C4DDE7182061E9`.
- Packaged driver signature: `Valid`, signer thumbprint `AD39C1B28DF46266E5E74CF60A46A8BEA97BB5F0`.

## Post-repair source hashes

- `HvVmcs.c`: `1EB17AEDC6835DD5BDEFE9332B3CABCA9CDDCDBA35F6BFAE468625440CEBF1AD`
- `HvVmcb.c`: `E5B81C0D429B80F48FA5A1E6B2C59176F1038CB1E819DBC667B0EF72F9E8A557`
- `HvDebugger.c`: `25CE999E4C0FE90BAA3C7847B226FFC6FB669450FF986F68AFE1E9E9D1D78FBD`
- `HvDebugger.h`: `C42D9E1493E812AB6B71ED45009A3191421A4612FFB5AA4AD48C03AE28D76102`
- `HvVmExit.c`: `C8864EB7ADA55D6B1A813402A2ED4C58721BA1E64F68A16E38236245735DB983`
