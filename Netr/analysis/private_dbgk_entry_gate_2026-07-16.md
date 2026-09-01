# Private Dbgk VT launch entry gate — 2026-07-16

- Evidence: `GuardMeta-PrivateDbgk-entry-p13492-1784198286580.log` continued the synthetic `CREATE_PROCESS` event before the scoped entry SWBP was installed. Loader-side thread/DLL events then ran first and the target exited with `0xC0000142`; private SWBP hit/data-pass counters remained zero.
- Root cause: `attach_process_for_private_vt_launch` reused ordinary attach activation, so `HvPrivateDebugObjectContinue` released the driver-owned process suspension too early.
- Fix: private VT launch sessions now retain a dedicated `CREATE_PROCESS` gate. The UI installs the scoped VT entry SWBP, explicitly activates that gate, and only then releases the creator-owned primary-thread suspend count.
- Isolation: ordinary private attach, native VT launch/attach, and native debugger state machines retain their existing activation paths.
- Validation: canonical `build_test.bat Release` completed; driver signing verified, source/package hashes match, and the full test package was refreshed. Runtime driver loading was intentionally not performed.
- Existing build output: 25 pre-existing Rust warnings; no compile, link, signing, or packaging errors.

## Private-event VT single-step follow-up

- Evidence: the first successful entry hit removed its one-shot SWBP into the driver's `DisarmedPending` state; repeated same-address transient SWBP adds then returned generic driver status `1` before the pending event was continued.
- Fix: VT stepping now continues a pending private event while the user-mode `SuspendThread` hold remains active, then reuses or recreates the SWBP step gate before resuming the thread. Native and Windows-DebugObject paths are unchanged.
- Validation: the full Release package was refreshed at `2026-07-16 19:05:58 +08:00`; runtime stepping remains for on-host testing.
