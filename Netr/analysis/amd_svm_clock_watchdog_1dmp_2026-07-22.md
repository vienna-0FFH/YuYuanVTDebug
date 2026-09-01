# AMD SVM CLOCK_WATCHDOG_TIMEOUT analysis and repair

## Evidence

- Dump: `Netr/test-package/1.dmp`
- Debug time: `2026-07-22 20:21:09 +08:00`
- System: AMD Ryzen 7 7435HS, family 25 model 68 stepping 1, 16 logical processors
- Bugcheck: `0x101 CLOCK_WATCHDOG_TIMEOUT`
- Hung processor: CPU 0
- Timeout: 12 nominal clock ticks
- Loaded driver timestamp: `2026-07-22 20:14:48`
- The dump matches the driver/PDB package built after the first AMD VCPU-offset repair.
- The triage dump does not contain CPU 0's stack or the live SVM globals, so the exact instruction at the watchdog is unavailable.

This is not a recurrence of the prior `AsmSvmLaunch+0xB4` access violation. The corrected assembly offsets `VCPU_DATA.Vmcb=0x88` and `VmcbPhysical=0x90` are present in the crashed binary.

## Root-cause chain

1. **Latent defect:** the original VMCB layout declared both instruction-intercept words as `ULONG64`. Word 3 occupied `0x0C..0x13`, while the field named `InterceptMisc2` was placed at `0x14`. AMD defines word 3 at `0x0C`, word 4 at `0x10`, and word 5 at `0x14`.
2. **First exposing decision:** the first repair corrected the separate `VCPU_DATA` offsets, allowing `VMRUN` to consume the real VMCB for the first time instead of faulting on a null pseudo-VMCB pointer.
3. **Runtime trigger:** `SvmSetupVmcbControlArea` wrote `0x203F` to `VMCB+0x14`. On this processor that writes unsupported/reserved word-5 bits instead of the requested VMRUN/VMMCALL/VMLOAD/VMSAVE/STGI/CLGI/XSETBV word-4 intercepts.
4. **Retry amplifier:** an invalid VMCB entry produces `SVM_EXIT_INVALID (-1)`. The old assembly unconditionally entered `SvmVmExitDispatch`, whose unknown-exit branch returned `TRUE`, and immediately executed the same invalid `VMRUN` again.
5. **Final mechanism:** CPU 0 remained in a GIF-blocked invalid-entry/VMEXIT retry loop and stopped accepting clock interrupts. Another processor eventually issued bugcheck `0x101` for CPU 0.

Steps 1, 2 and 4 are verified directly from source, PDB layout and object disassembly. Steps 3 and 5 are the strongest hardware-consistent inference available from this mini dump; the missing hung-CPU stack prevents direct observation of `ExitCode=-1`.

## Additional AMD defects found

- ASID count used `CPUID 0x80000008.EBX`; AMD specifies `0x8000000A.EBX`.
- `HvNestedSvm.h` retained a duplicate, currently unused `VMCB_INTERCEPT_MISC2=0x014` constant after the live VMCB structure was corrected to `0x010`.
- Guest CS/SS/DS/ES/FS/GS/LDTR/TR attributes were hard-coded instead of derived from the active GDT. Several values omitted descriptor flags or marked a null LDTR present.
- The entry/exit loop did not perform the required additional-state `VMSAVE/VMLOAD` switch and did not bracket first entry/host return with `CLGI/STGI`.
- MXCSR was not preserved across the AMD C exit dispatcher.
- A failed initial `VMRUN` had no non-retrying failure return.
- Normal SVM termination jumped to the RIP/RSP captured during the original launch instead of resuming after the current terminating `VMMCALL`; it also left `EFER.SVME` and `VM_HSAVE_PA` active while the VMCB resources were about to be freed.

The duplicate header constant and termination path were not the trigger for `1.dmp`: the first was dead metadata, and the second is reached during devirtualization rather than initial `VMRUN`. They were removed during the same AMD-only audit so the repaired startup path does not expose a later unload failure.

## Repair

- `HvTypes.h`: models VMCB intercept words 3/4/5 as three 32-bit fields at `0x0C/0x10/0x14`.
- `HvVmcb.c`: adds compile-time contracts for the complete VMCB control/state layout and every assembly-consumed VCPU offset, derives segment state from the live descriptors, validates entry resources/control words, and disables SVM safely on setup failure.
- `HvCpu.c` / `HvCpu.h`: reads ASID capacity from `CPUID 0x8000000A.EBX`.
- `AsmSvm.asm`: uses `CLGI -> host VMSAVE -> guest VMLOAD -> VMRUN`, saves guest additional state and restores host state on VMEXIT, restores guest state before re-entry, preserves MXCSR, and returns a failed first entry instead of retrying it.
- `AsmSvm.asm`: if a later, already-running VCPU ever receives `SVM_EXIT_INVALID`, it restores host state and raises deterministic `HYPERVISOR_ERROR (0x20001)` with the VMCB exit data instead of silently hanging the processor.
- `AsmSvm.asm`: normal termination now accepts only the terminating `VMMCALL`, restores the current VMCB's additional state, CR0/CR2/CR3/CR4, DR6/DR7, RIP/RSP/RFLAGS/RAX, clears `VM_HSAVE_PA` and `EFER.SVME`, and resumes at the instruction after that `VMMCALL`.
- `HvNestedSvm.h` / `HvNestedSvm.c`: correct the duplicate word-4 offset to `0x010` and compile-time-check every duplicated raw VMCB offset against the canonical structures.
- `HvCore.c` and `HvNestedSvm.c`: AMD-only failure cleanup and explicit 32-bit intercept-word assignments.

No VMX, VMCS, EPT, Intel assembly, Intel control policy, debugger policy, or vwatch behavior was changed.

## Binary verification

- Full command: `Netr/build_test.bat Release`
- Driver compilation/signing: zero warnings, zero errors
- Full GUI/bridge package: successful; 25 pre-existing Rust warnings remain
- `AsmSvm.obj` confirms VCPU loads at `+0x88/+0x90/+0xA0`, invalid-exit check at VMCB `+0x70`, and the expected `CLGI/VMSAVE/VMLOAD/VMRUN/STGI` instructions.
- The termination machine code checks exit `0x81`, reads VMCB `+0x548/+0x550/+0x558/+0x560/+0x568/+0x570/+0x578/+0x5D8/+0x5F8/+0x640`, executes guest `VMLOAD`, clears MSRs `0xC0010117/0xC0000080`, then restores CR0/2/3/4 and DR6/7.
- `HvVmcb.obj` confirms `0x90040000` is written at VMCB `+0x0C`, `0x203F` at `+0x10`, and `+0x14` is checked as zero.
- Packaged SYS source parity: `true`
- Packaged PDB source parity: `true`
- All 14 `SHA256SUMS.txt` managed artifacts: match
- Packaged driver signature: valid, thumbprint `AD39C1B28DF46266E5E74CF60A46A8BEA97BB5F0`
- Packaged driver SHA-256: `4C7AAD81003BA0FACF5E0EA36F5BE33AC58E6B0F6429184636DBB9CDF47E5233`
- Packaged PDB SHA-256: `E281AD95F0CC6DC3DE62EC4327C884467D28F666C1665CC9F2A7A1A72A20AE5C`

## Rollback point

The pre-repair handoff is the package produced after only the first VCPU-offset fix:

- Driver SHA-256: `763C448DD404FBC566A06927B5C6B2B228041046DA13A6C0CDED083F89B64D93`
- `AsmSvm.asm`: `B8177816B46F4134709B1BDA39BAE9914C012B2508672AAA6694A25F3FC0B056`
- `HvVmcb.c`: `E5B81C0D429B80F48FA5A1E6B2C59176F1038CB1E819DBC667B0EF72F9E8A557`
- Prior report: `Netr/analysis/amd_svm_bsod_072226-12625-01_2026-07-22.md`

Current repaired source hashes:

- `AsmSvm.asm`: `D4C5D76B22078DB0C5CFC4B8268A5A1C9066A9F9398C6C549657DB2AE3FC8288`
- `HvTypes.h`: `92F4F3A12B0989409EC2B05DD1E281671776F07CB75260887A4F2D176BD8913F`
- `HvVmcb.c`: `75D4F8A48C0D7FA4FEEBE603EEB9A7C2B1B1649ABB6087A51B2A196367A1C169`
- `HvVmcb.h`: `35AA4AE54D039598F9F373CDBD2E12011CF9E622BB3C0D8F7B7F4073EDD0D288`
- `HvCpu.c`: `93F1AC41346615C10639B9A58901EE402BD4DE96A8EFB5B3EB13FBCD172DAB5C`
- `HvCpu.h`: `F6AD39B06FFF640F47CBCEE7831ECB97E62E78388F5FA43AF2DB776112E55E73`
- `HvCore.c`: `2193A597BBB9D51E64A58A22585DB46CFEAE01201B451ECE8F743B3F940281D6`
- `HvNestedSvm.c`: `7A129BBC18CB19F24BE3E97F397C1270DBE474F1A9CEC98AA38BD921D715CD41`
- `HvNestedSvm.h`: `EAF66100CAEE354F5B192F47BCAB314DCE0DCDC0A756E3C68CDF81FB596C2C7D`

The driver was built and packaged only. It was not installed, loaded, started, stopped, or unloaded by this repair session.
