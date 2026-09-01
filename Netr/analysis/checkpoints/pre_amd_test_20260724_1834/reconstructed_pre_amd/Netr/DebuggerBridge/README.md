# Netr debugger bridge

`NetrDebuggerBridge32/64.dll` runs inside an external debugger. It observes
the Win32 debugging lifecycle and dispatches debugger operations to
`GuardMetaCore.sys` while Windows keeps ownership of the native debug port.

The bridge patches module import tables for:

- `DebugActiveProcess` / `DebugActiveProcessStop`
- `CreateProcessA/W` when a debug creation flag is present
- `WaitForDebugEvent` / `WaitForDebugEventEx`
- `ReadProcessMemory` / `WriteProcessMemory` / `VirtualProtectEx`
- `GetThreadContext` / `SetThreadContext` and the WOW64 variants
- `GetProcAddress` and `LoadLibrary*` so late-loaded debugger engines are covered

The driver-backed paths are:

- reads through the VT physical-copy path;
- writes through the driver COW path first so executable/shared image pages
  become process-private, with VT physical copy retained as a fallback;
- memory protection through the native API first (to preserve Windows' page
  protection semantics), with the driver protection IOCTL retained as a
  fallback for access-restricted targets;
- per-target virtual DR0-DR3/DR7 state backed by EPT/NPT vwatch;
- event-scoped virtual DR6 delivery for VT hardware-breakpoint events;
- private software-breakpoint registration without modifying the target byte;
- TF single-step virtualization for user modules/private executable memory,
  while Windows system modules retain native TF delivery;
- merged native/private debug-event delivery through the standard Win32 loop;
- PEB and WOW64 PEB debug-flag scrubbing after the initial breakpoint event;
- `NtQueryInformationProcess` anti-debug filtering for bound targets.

For a bound target, a one-byte `WriteProcessMemory(..., 0xCC, 1, ...)` reads and
records the original byte, registers the address with the driver, and reports a
successful write without changing target memory. A later one-byte non-`0xCC`
write to that registered address unregisters it and is also suppressed, so the
original target byte is never damaged. Other writes keep using the normal
driver COW/VT path.

`WaitForDebugEvent` and `WaitForDebugEventEx` give native debug-port events
priority, then poll the private event ring in 10 ms slices. A private SWBP hit
is converted to a first-chance `EXCEPTION_BREAKPOINT` and its target thread is
suspended before the event is returned. `ContinueDebugEvent` recognizes that
synthetic `(pid, tid)` pair, sends the private continue request, and resumes the
exact thread handle without calling the native continue API. The protocol uses
fixed-width version-4 records, so the event layout is identical in the x86 and
x64 Bridge builds.

For a standard Windows DebugObject single-step event, the Bridge reads the
R0 pending-hit record directly before returning from `WaitForDebugEvent`.
The owned query latches the exact debugger, target, thread, DR6 B0-B3 mask,
and generation under the `(pid, tid)` event key. Ordinary context reads may
observe the mask but cannot authorize its removal; a context write can clear
R0 state only after the event-owned query succeeds. Later `GetThreadContext`
calls see the latched mask until the matching native `ContinueDebugEvent`
succeeds, after which the Bridge retires only the captured generation. This
prevents debugger-internal context traffic from consuming the next hit or
turning the current VT hardware hit into an unowned first-chance exception,
while keeping TF and unrelated native single-step events unchanged.

Private Dbgk process exit has a process-notify fallback when the private
`DbgkExitProcess` producer is not reached. The fallback queues one nonblocking
`EXIT_PROCESS_DEBUG_EVENT`, retains the private session through delivery and
continue, and unbinds only after that continue succeeds. A target exit can
therefore finish the normal debugger loop instead of converting the next wait
to `STATUS_DEBUGGER_INACTIVE`.

When an external debugger sets TF at a user address, the Bridge arms the VT
step request and clears the real TF bit before forwarding the context. Intel
uses a transient private EPT software-breakpoint gate followed by MTF; AMD uses
an NPT execute gate followed by the intercepted `#DB`. The resulting standard
single-step event still arrives through the debugger's native DebugObject.

The driver also pairs successful native `NtDebugActiveProcess` attaches, so a
debugger that bypasses the Win32 wrapper is covered before the syscall returns.
Repeated injection requests must observe the persistent ready event; a loaded
but failed Bridge is not reported as healthy.

Build both target architectures from a normal shell:

```bat
build.bat
```

The build copies the four runtime files to `Netr\test-package` and, when it
exists, the Tauri release directory. You can also set `NETR_BRIDGE_DIR` to a
directory containing them. The injector must match the debugger bitness. For a
new debugger the GUI validates the artifacts while the process is suspended,
resumes its user-mode loader, injects immediately, and reports success only
after the Bridge-to-driver handshake completes.
