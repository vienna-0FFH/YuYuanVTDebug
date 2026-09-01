# R0 VT Step DB Delivery Rollback Point

Recorded before changing the Intel VT private-step completion path.

## Baseline

- `HvVwatch.c` SHA-256: `9ADD0C51A3704FF55BC472A1D62E6E9844425B63C323AAAA58FA6B57FDDD66F9`
- `HvVwatch.h` SHA-256: `178C2F1DB13CC98019178DA2B0B95907DD4190BFDEFDA798938BB21D22BE1B4C`
- `HvVmExit.c` SHA-256: `84A40BBF092A203994A17DBA42D9F05A57B4FC685570E81C733B255A4712A918`
- `Driver.c` SHA-256: `D3FA1103EF95F18E26FB59B339AF869E1BDB30677C9B43B701C63E203D5D03DE`
- No driver was loaded or unloaded while recording this point.

## Attempted Repair

The observed final lost step was at `vmpre.exe+0x1303`, an ordinary user-mode
`mov dword ptr [rip+0x22e3], 1`, not a syscall, process-exit instruction, or
faulting operation. The repair therefore protects the private debugger's MTF
window from a maskable interrupt arriving before the intended instruction:

- when a VT debugger step changes `STEP_ARMED` to `STEP_COMPLETING`, set a
  synthetic VMCS blocking-by-STI state for exactly the next guest instruction;
- clear only that synthetic bit at MTF completion;
- mark the step `COMPLETED` only after the unique explicit `#DB` was actually
  placed in the VM-entry slot;
- if the completion is still at the wrong CPL/activity or conflicts with an
  existing entry/vectoring event, return the step to `ARMED` instead of
  reporting a completion that no debugger can receive;
- expose counters in the existing diagnostics file for shadow arms/rejects and
  each `#DB` rejection class.

This does not set `GUEST_PENDING_DEBUG_EXCEPTIONS.BS`, does not enqueue a second
step event, and does not single-step through a kernel interrupt handler.

## Semantic Scope

This repair is not a complete emulation of architectural `RFLAGS.TF` semantics.
It deliberately delays a maskable interrupt until after the selected user-mode
instruction and the synthesized `#DB`. Native TF may instead enter an interrupt
handler first, retain TF according to the architectural transition, and resume
the selected instruction later. NMI/SMI, synchronous faults, and instructions
that cross privilege levels remain outside the equivalence claim.

For an ordinary non-faulting CPL3 instruction, the intended observable result is
the same post-instruction RIP/register state and one native DebugObject
`EXCEPTION_SINGLE_STEP` stop. The event ordering around asynchronous interrupts
is intentionally different.

## Unreal Reference Comparison

The Unreal reference uses two different semantics:

- ordinary debugger single-step preserves the debugger-supplied `EFlags` in
  `Hook\DebugBreak\DebugBreak.cpp`, including the real TF bit;
- its VMCS exception bitmap leaves `#DB` unintercepted, so the processor and
  Windows deliver the ordinary TF-generated exception through the native guest
  path;
- MTF in `VT_Driver\vmexit_handler.cpp` is primarily an EPT page-rearm tool, not
  the ordinary debugger's TF replacement;
- its EPT virtual-watchpoint path separately synthesizes vector 1 after MTF.
  `DbgkSysWin11\DbgkApi\DbgkApi.cpp` explicitly notes that this injection does
  not update DR6, so that path is also not fully architectural hardware-`#DB`
  semantics.

Therefore Unreal's ordinary F7/F8-style step is closer to complete real TF
semantics than this Netr VT-hidden step, while Unreal's virtual watchpoint event
is synthetic in the same broad sense as Netr's MTF-completion injection.

## Validation

- `build_test.bat Release DriverOnly`: succeeded; driver build, signing, and
  verification reported zero warnings and zero errors.
- `build_test.bat Release`: succeeded. The driver again reported zero warnings
  and zero errors; the Rust GUI completed with 25 pre-existing unused/dead-code
  warnings.
- Packaged `GuardMetaCore.sys` Authenticode status: `Valid`, signer thumbprint
  `AD39C1B28DF46266E5E74CF60A46A8BEA97BB5F0`.
- Release/package driver SHA-256 both:
  `90D72D97F4D4C0EA7879297394170F42422D35688973EDCFC7CEFEFECFA0A4EE`.
- Release/package PDB SHA-256 both:
  `2E2AA8CFDBFF25C0F2F212CBEA7B6F7D3ABFA538E460EFB97A522083B8000DD1`.
- Every `SHA256SUMS.txt` entry matches and all required runtime binaries,
  symbols, and the test certificate are present in `test-package`.
- Current source hashes:
  - `HvVwatch.c`: `FC0AB112DFCF64610E525A12075E4B1CAA3B09D5FE0A2AFE2B401B8320BE238F`
  - `HvVwatch.h`: `D826D6AC87C76D065A297FA8FAFB3CE0CFC5B911CD92E48891763061C3C4798C`
  - `HvVmExit.c`: `84A40BBF092A203994A17DBA42D9F05A57B4FC685570E81C733B255A4712A918`
  - `Driver.c`: `6C4FB954005959333AD38F59F5CA9FCFF26559773CC4BD2EAEF48E22456266D2`
- No driver was installed, loaded, or unloaded. Runtime delivery and unload
  behavior remain unvalidated.

## Original Completion Helper

```c
static BOOLEAN HvVwatchpTryInjectPrivateStepDb(VOID)
{
    SIZE_T csSelector = 0;
    SIZE_T activityState = 0;
    SIZE_T entryInfo = 0;
    SIZE_T vectoringInfo = 0;

    __vmx_vmread(GUEST_CS_SELECTOR, &csSelector);
    __vmx_vmread(GUEST_ACTIVITY_STATE, &activityState);
    __vmx_vmread(VMCS_CTRL_VMENTRY_INTERRUPTION_INFO, &entryInfo);
    __vmx_vmread(IDT_VECTORING_INFO, &vectoringInfo);

    if ((csSelector & 3ULL) != 3ULL ||
        activityState != 0 ||
        (entryInfo & (1ULL << 31)) != 0 ||
        (vectoringInfo & (1ULL << 31)) != 0) {
        return FALSE;
    }

    HvVwatchpInjectDb();
    return TRUE;
}
```

The MTF completion caller ignored this helper's return value.

## Rollback Rule

If the focused build fails, VM-entry validation cannot be justified, or runtime testing shows duplicate `#DB`, incorrect RIP, kernel-mode delivery, unload failure, or a crash, restore the helper above and restore the caller to:

```c
if (debuggerStepCompleted) {
    (void)HvVwatchpTryInjectPrivateStepDb();
}
```

Then rebuild with `build_test.bat Release DriverOnly` and verify the packaged source/driver hashes again.

For the attempted repair, also remove the private-step STI-shadow field,
diagnostic counters, and the corresponding `Driver.c` diagnostic lines. The
baseline hashes above are authoritative; do not reset unrelated working-tree
changes.
