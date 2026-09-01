from pathlib import Path

path = Path(r"E:\project_learning\YuYuanVTDebug\Netr\DebuggerBridge\Bridge.cpp")
text = path.read_text(encoding="utf-8", errors="replace")
orig = text
steps = []

def must_replace(old, new, label, count=1):
    global text
    n = text.count(old)
    if n == 0:
        raise SystemExit(f"MISS: {label}")
    if count == 1:
        text = text.replace(old, new, 1)
        steps.append(f"OK {label} (first of {n})")
    elif count == -1:
        text = text.replace(old, new)
        steps.append(f"OK {label} (all {n})")
    else:
        if n != count:
            raise SystemExit(f"COUNT {label}: expected {count}, found {n}")
        text = text.replace(old, new, count)
        steps.append(f"OK {label}")

must_replace(
"""struct PendingPrivateEvent {
    std::uint64_t Sequence{};
    std::uint64_t BreakpointAddress{};
    HANDLE Thread = nullptr;
    ULONG Kind{HV_BRIDGE_PRIVATE_EVENT_SWBP};
    bool DriverContinued{};
    bool ContextRipAdvanced{};
    bool Wow64Context{};
};""",
"""struct PendingPrivateEvent {
    std::uint64_t Sequence{};
    std::uint64_t BreakpointAddress{};
    HANDLE Thread = nullptr;
    bool DriverContinued{};
    bool ContextRipAdvanced{};
    bool Wow64Context{};
};""",
"PendingPrivateEvent.Kind")

must_replace(
"""std::unordered_map<std::uint64_t, PendingVtStep> g_pending_vt_steps;
// One-shot suppress window for native EXCEPTION_SINGLE_STEP after a private
// HV_BRIDGE_PRIVATE_EVENT_STEP stop was already delivered (dual-notify).
std::unordered_map<std::uint64_t, ULONGLONG> g_suppress_native_single_step;
SRWLOCK g_suppress_ss_lock = SRWLOCK_INIT;
std::unordered_map<HMODULE, ModulePatchState> g_module_patch_states;""",
"""std::unordered_map<std::uint64_t, PendingVtStep> g_pending_vt_steps;
std::unordered_map<HMODULE, ModulePatchState> g_module_patch_states;""",
"suppress map")

must_replace(
"""void ArmNativeSingleStepSuppress(DWORD pid, DWORD tid)
{
    const std::uint64_t key = PrivateEventKey(pid, tid);
    AcquireSRWLockExclusive(&g_suppress_ss_lock);
    g_suppress_native_single_step[key] = GetTickCount64() + 2000ULL;
    ReleaseSRWLockExclusive(&g_suppress_ss_lock);
}

bool ShouldSuppressNativeSingleStep(const DEBUG_EVENT* event)
{
    if (!event || event->dwDebugEventCode != EXCEPTION_DEBUG_EVENT) {
        return false;
    }
    if (event->u.Exception.ExceptionRecord.ExceptionCode !=
        EXCEPTION_SINGLE_STEP) {
        return false;
    }

    const std::uint64_t key =
        PrivateEventKey(event->dwProcessId, event->dwThreadId);
    AcquireSRWLockExclusive(&g_suppress_ss_lock);
    const auto found = g_suppress_native_single_step.find(key);
    if (found == g_suppress_native_single_step.end()) {
        ReleaseSRWLockExclusive(&g_suppress_ss_lock);
        return false;
    }
    const ULONGLONG expire = found->second;
    const ULONGLONG now = GetTickCount64();
    g_suppress_native_single_step.erase(found);
    ReleaseSRWLockExclusive(&g_suppress_ss_lock);
    if (now > expire) {
        return false;
    }
    Trace(L"[VT-STEP] suppressed duplicate native SS pid=%lu tid=%lu\\n",
          event->dwProcessId, event->dwThreadId);
    return true;
}

bool ConsumeNativeDebugEvent(LPDEBUG_EVENT event)
{
    if (ShouldSuppressNativeSingleStep(event)) {
        if (g_continue_debug_event) {
            (void)g_continue_debug_event(
                event->dwProcessId, event->dwThreadId, DBG_CONTINUE);
        }
        return false;
    }
    ObserveDebugEvent(event);
    return true;
}

bool InstallVtStepGate(""",
"""bool InstallVtStepGate(""",
"Arm/Should/Consume helpers")

must_replace(
"""    ReleaseSRWLockExclusive(&g_vt_step_lock);
    AcquireSRWLockExclusive(&g_suppress_ss_lock);
    for (auto it = g_suppress_native_single_step.begin();
         it != g_suppress_native_single_step.end();) {
        const DWORD step_pid = static_cast<DWORD>(it->first >> 32);
        if (pid == 0 || step_pid == pid) {
            it = g_suppress_native_single_step.erase(it);
        } else {
            ++it;
        }
    }
    ReleaseSRWLockExclusive(&g_suppress_ss_lock);
}""",
"""    ReleaseSRWLockExclusive(&g_vt_step_lock);
}""",
"ForgetTargetVtSteps suppress purge")

must_replace(
"""    if (result.Status != HV_BRIDGE_STATUS_SUCCESS) {
        // VT STEP completion is ring-only; there is no HitPending SWBP entry
        // for Continue to consume. Treat NOT_FOUND as soft success for STEP.
        if (event.Kind == HV_BRIDGE_PRIVATE_EVENT_STEP &&
            result.Status == HV_BRIDGE_STATUS_NOT_FOUND) {
            return true;
        }
        SetLastError(result.Status == HV_BRIDGE_STATUS_NOT_FOUND
            ? ERROR_NOT_FOUND : ERROR_INVALID_PARAMETER);
        return false;
    }
    return true;
}

enum class PrivateDbgkPollResult {""",
"""    if (result.Status != HV_BRIDGE_STATUS_SUCCESS) {
        SetLastError(result.Status == HV_BRIDGE_STATUS_NOT_FOUND
            ? ERROR_NOT_FOUND : ERROR_INVALID_PARAMETER);
        return false;
    }
    return true;
}

enum class PrivateDbgkPollResult {""",
"ContinuePrivateEvent soft STEP")

must_replace(
"""    const auto acknowledge_discarded = [&]() {
        if (!ContinuePrivateEvent(private_event, DBG_CONTINUE)) {
            Trace(L"[PRIVATE] discard ack failed pid=%lu tid=%lu seq=%llu win32=%lu\\n",
                  private_event.ProcessId, private_event.ThreadId,
                  static_cast<unsigned long long>(private_event.Sequence),
                  GetLastError());
        }
    };

    const bool is_swbp =
        private_event.Kind == HV_BRIDGE_PRIVATE_EVENT_SWBP;
    const bool is_step =
        private_event.Kind == HV_BRIDGE_PRIVATE_EVENT_STEP;
    if (!debug_event || g_stop.load() ||
        (!is_swbp && !is_step) ||
        private_event.ThreadId == 0 ||
        private_event.Rip > static_cast<std::uint64_t>(UINTPTR_MAX)) {
        Trace(L"[PRIVATE] discarded kind=%lu pid=%lu tid=%lu rip=0x%llX seq=%llu\\n",
              private_event.Kind, private_event.ProcessId,
              private_event.ThreadId,
              static_cast<unsigned long long>(private_event.Rip),
              static_cast<unsigned long long>(private_event.Sequence));
        acknowledge_discarded();
        return PrivateDeliveryResult::Skipped;
    }

    // Late STEP after inject #DB already completed the stop and cleared the
    // pending VT step receiver. Soft-continue and discard the duplicate so
    // external debuggers do not see a second free-run stop.
    if (is_step &&
        !LookupPendingVtStep(
            private_event.ProcessId, private_event.ThreadId, nullptr)) {
        Trace(L"[VT-STEP] discarded late STEP route=%s pid=%lu tid=%lu "
              L"rip=0x%llX seq=%llu\\n",
              route ? route : L"unknown",
              private_event.ProcessId,
              private_event.ThreadId,
              static_cast<unsigned long long>(private_event.Rip),
              static_cast<unsigned long long>(private_event.Sequence));
        acknowledge_discarded();
        return PrivateDeliveryResult::Skipped;
    }

    // Secondary safety only: if a gate SWBP still arrives while a VT step is
    // armed at the same RIP, continue it without delivering a user BP.  The
    // real stop must come from HV_BRIDGE_PRIVATE_EVENT_STEP.
    if (is_swbp) {
        PendingVtStep pending_step = {};
        if (LookupPendingVtStep(
                private_event.ProcessId,
                private_event.ThreadId,
                &pending_step) &&
            pending_step.Address == private_event.Rip) {
            Trace(L"[VT-STEP] suppressed gate SWBP route=%s pid=%lu tid=%lu "
                  L"rip=0x%llX seq=%llu owns_gate=%d\\n",
                  route ? route : L"unknown",
                  private_event.ProcessId,
                  private_event.ThreadId,
                  static_cast<unsigned long long>(private_event.Rip),
                  static_cast<unsigned long long>(private_event.Sequence),
                  pending_step.OwnsSwBpGate ? 1 : 0);
            if (!ContinuePrivateEvent(private_event, DBG_CONTINUE)) {
                const DWORD cont_error = GetLastError();
                Trace(L"[VT-STEP] gate SWBP continue failed route=%s "
                      L"pid=%lu tid=%lu seq=%llu win32=%lu\\n",
                      route ? route : L"unknown",
                      private_event.ProcessId,
                      private_event.ThreadId,
                      static_cast<unsigned long long>(private_event.Sequence),
                      cont_error);
                SetLastError(cont_error);
                return PrivateDeliveryResult::Error;
            }
            return PrivateDeliveryResult::Skipped;
        }
    }

    const std::uint64_t key = PrivateEventKey(""",
"""    const auto acknowledge_discarded = [&]() {
        if (!ContinuePrivateEvent(private_event, DBG_CONTINUE)) {
            Trace(L"[PRIVATE] discard ack failed pid=%lu tid=%lu seq=%llu win32=%lu\\n",
                  private_event.ProcessId, private_event.ThreadId,
                  static_cast<unsigned long long>(private_event.Sequence),
                  GetLastError());
        }
    };

    if (!debug_event || g_stop.load() ||
        private_event.Kind != HV_BRIDGE_PRIVATE_EVENT_SWBP ||
        private_event.ThreadId == 0 ||
        private_event.Rip > static_cast<std::uint64_t>(UINTPTR_MAX)) {
        Trace(L"[PRIVATE] discarded kind=%lu pid=%lu tid=%lu rip=0x%llX seq=%llu\\n",
              private_event.Kind, private_event.ProcessId,
              private_event.ThreadId,
              static_cast<unsigned long long>(private_event.Rip),
              static_cast<unsigned long long>(private_event.Sequence));
        acknowledge_discarded();
        return PrivateDeliveryResult::Skipped;
    }

    const std::uint64_t key = PrivateEventKey(""",
"private delivery SWBP-only")

must_replace(
"""        PendingPrivateEvent pending = {};
        pending.Sequence = private_event.Sequence;
        pending.BreakpointAddress = private_event.Rip;
        pending.Thread = thread;
        pending.Kind = private_event.Kind;
        if (!g_pending_private_events.emplace(key, pending).second) {""",
"""        PendingPrivateEvent pending = {};
        pending.Sequence = private_event.Sequence;
        pending.BreakpointAddress = private_event.Rip;
        pending.Thread = thread;
        if (!g_pending_private_events.emplace(key, pending).second) {""",
"pending.Kind assign")

must_replace(
"""    auto pending_context = g_pending_private_events.find(key);
    // STEP is reported after the instruction already executed.  Never apply
    // the INT3 RIP+1 emulator used for private SWBP delivery.
    const PreparePrivateEventContextFn context_fn =
        is_step ? nullptr : prepare_context;
    if (pending_context == g_pending_private_events.end() ||
        (context_fn && !context_fn(
            private_event.ProcessId,
            private_event.ThreadId,
            &pending_context->second))) {""",
"""    auto pending_context = g_pending_private_events.find(key);
    if (pending_context == g_pending_private_events.end() ||
        (prepare_context && !prepare_context(
            private_event.ProcessId,
            private_event.ThreadId,
            &pending_context->second))) {""",
"prepare_context no STEP branch")

must_replace(
"""    ZeroMemory(debug_event, sizeof(*debug_event));
    debug_event->dwDebugEventCode = EXCEPTION_DEBUG_EVENT;
    debug_event->dwProcessId = private_event.ProcessId;
    debug_event->dwThreadId = private_event.ThreadId;
    debug_event->u.Exception.ExceptionRecord.ExceptionCode =
        is_step ? EXCEPTION_SINGLE_STEP : EXCEPTION_BREAKPOINT;
    debug_event->u.Exception.ExceptionRecord.ExceptionAddress =
        reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(private_event.Rip));
    debug_event->u.Exception.ExceptionRecord.NumberParameters =
        is_step ? 0 : 1;
    debug_event->u.Exception.ExceptionRecord.ExceptionInformation[0] = 0;
    debug_event->u.Exception.dwFirstChance = TRUE;

    Trace(L"[PRIVATE] delivered %s route=%s pid=%lu tid=%lu rip=0x%llX seq=%llu previous_suspend=%lu\\n",
          is_step ? L"STEP" : L"SWBP",
          route ? route : L"unknown",
          private_event.ProcessId, private_event.ThreadId,
          static_cast<unsigned long long>(private_event.Rip),
          static_cast<unsigned long long>(private_event.Sequence),
          previous_suspend_count);
    ObserveDebugEvent(debug_event);
    if (is_step) {
        // Dual-notify inject #DB may still surface a native SINGLE_STEP.
        // Suppress that second stop so x64dbg / external waiters do not free-run.
        ArmNativeSingleStepSuppress(
            private_event.ProcessId, private_event.ThreadId);
    }
    return PrivateDeliveryResult::Delivered;
}""",
"""    ZeroMemory(debug_event, sizeof(*debug_event));
    debug_event->dwDebugEventCode = EXCEPTION_DEBUG_EVENT;
    debug_event->dwProcessId = private_event.ProcessId;
    debug_event->dwThreadId = private_event.ThreadId;
    debug_event->u.Exception.ExceptionRecord.ExceptionCode =
        EXCEPTION_BREAKPOINT;
    debug_event->u.Exception.ExceptionRecord.ExceptionAddress =
        reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(private_event.Rip));
    debug_event->u.Exception.ExceptionRecord.NumberParameters = 1;
    debug_event->u.Exception.ExceptionRecord.ExceptionInformation[0] = 0;
    debug_event->u.Exception.dwFirstChance = TRUE;

    Trace(L"[PRIVATE] delivered SWBP route=%s pid=%lu tid=%lu rip=0x%llX seq=%llu previous_suspend=%lu\\n",
          route ? route : L"unknown",
          private_event.ProcessId, private_event.ThreadId,
          static_cast<unsigned long long>(private_event.Rip),
          static_cast<unsigned long long>(private_event.Sequence),
          previous_suspend_count);
    ObserveDebugEvent(debug_event);
    return PrivateDeliveryResult::Delivered;
}""",
"delivered SWBP-only synthesis")

# wait loops
pairs = [
(
"""                    if (ConsumeNativeDebugEvent(event)) {
                        return TRUE;
                    }
                    continue;""",
"""                    ObserveDebugEvent(event);
                    return TRUE;""",
),
(
"""            if (ConsumeNativeDebugEvent(event)) {
                return TRUE;
            }
            continue;""",
"""            ObserveDebugEvent(event);
            return TRUE;""",
),
]
for old, new in pairs:
    n = text.count(old)
    if n == 0:
        raise SystemExit(f"MISS wait block: {old[:60]!r}")
    text = text.replace(old, new)
    steps.append(f"OK wait Consume->Observe x{n}")

must_replace(
"""            private_event.Sequence = pending->second.Sequence;
            private_event.ProcessId = pid;
            private_event.ThreadId = tid;
            private_event.Kind = pending->second.Kind;
            continued = ContinuePrivateEvent(private_event, status);
            error = continued ? ERROR_SUCCESS : GetLastError();
            // STEP completion has no HitPending SWBP entry.  Driver continue
            // returns NOT_FOUND by design; still resume the suspended thread.
            if (!continued &&
                pending->second.Kind == HV_BRIDGE_PRIVATE_EVENT_STEP &&
                error == ERROR_NOT_FOUND) {
                continued = true;
                error = ERROR_SUCCESS;
            }
            if (continued) pending->second.DriverContinued = true;""",
"""            private_event.Sequence = pending->second.Sequence;
            private_event.ProcessId = pid;
            private_event.ThreadId = tid;
            continued = ContinuePrivateEvent(private_event, status);
            error = continued ? ERROR_SUCCESS : GetLastError();
            if (continued) pending->second.DriverContinued = true;""",
"HookedContinue soft STEP")

path.write_text(text, encoding="utf-8")
print("wrote", path)
for s in steps:
    print(s)

bad = [
    "ConsumeNativeDebugEvent",
    "ArmNativeSingleStepSuppress",
    "g_suppress_native_single_step",
    "ShouldSuppressNativeSingleStep",
    "Dual-notify",
    "pending.Kind",
    "is_step",
    "late STEP",
]
left = []
for b in bad:
    c = text.count(b)
    if c:
        left.append(f"{b}:{c}")
if left:
    print("LEFTOVER:", ", ".join(left))
    raise SystemExit(2)
print("CLEAN")
print("delta_bytes", len(text) - len(orig))