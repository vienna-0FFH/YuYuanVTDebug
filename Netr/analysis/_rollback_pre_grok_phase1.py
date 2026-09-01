from pathlib import Path
import re

# ========== 1. HvVwatch.c ==========
p = Path(r"E:\project_learning\YuYuanVTDebug\Netr\HvVwatch.c")
text = p.read_text(encoding="utf-8", errors="replace")

old_armed = """    LONG state = InterlockedCompareExchange(&entry->State, 0, 0);
    if (state == HvPrivateSwBpArmed) {
        /*
         * VT single-step owns this SWBP gate.  If MTF arm fails, keep the
         * ContinueArmed hold and re-exit; never demote the gate into a user
         * SWBP hit.  Delivering a gate SWBP to the debugger free-runs the
         * target after CONTINUE because no EXCEPTION_SINGLE_STEP follows.
         */
        if (entry->StepThreadToken == threadToken &&
            InterlockedCompareExchange(
                &entry->StepState,
                HV_VWATCH_STEP_ARMED,
                HV_VWATCH_STEP_ARMED) == HV_VWATCH_STEP_ARMED &&
            InterlockedCompareExchange(
                &entry->State,
                HvPrivateSwBpContinueArmed,
                HvPrivateSwBpArmed) == HvPrivateSwBpArmed) {
            entry->HitTid = entry->StepTid;
            entry->HitThreadToken = threadToken;
            if (HvVwatchpArmSwBpStepOverRoot(VcpuData, entry)) return TRUE;
            HvVwatchpReleaseRootRundown(&entry->RootRundown);
            return TRUE;
        }
        if (InterlockedCompareExchange(
                &entry->State,
                HvPrivateSwBpHitPending,
                HvPrivateSwBpArmed) == HvPrivateSwBpArmed) {"""

new_armed = """    LONG state = InterlockedCompareExchange(&entry->State, 0, 0);
    if (state == HvPrivateSwBpArmed) {
        if (entry->StepThreadToken == threadToken &&
            InterlockedCompareExchange(
                &entry->StepState,
                HV_VWATCH_STEP_ARMED,
                HV_VWATCH_STEP_ARMED) == HV_VWATCH_STEP_ARMED &&
            InterlockedCompareExchange(
                &entry->State,
                HvPrivateSwBpContinueArmed,
                HvPrivateSwBpArmed) == HvPrivateSwBpArmed) {
            entry->HitTid = entry->StepTid;
            entry->HitThreadToken = threadToken;
            if (HvVwatchpArmSwBpStepOverRoot(VcpuData, entry)) return TRUE;
            entry->HitTid = NULL;
            entry->HitThreadToken = NULL;
            InterlockedCompareExchange(
                &entry->State,
                HvPrivateSwBpArmed,
                HvPrivateSwBpContinueArmed);
        }
        if (InterlockedCompareExchange(
                &entry->State,
                HvPrivateSwBpHitPending,
                HvPrivateSwBpArmed) == HvPrivateSwBpArmed) {"""

if old_armed not in text:
    raise SystemExit("HvVwatch armed block not found")
text = text.replace(old_armed, new_armed, 1)

pat = re.compile(
    r"        if \(debuggerStepCompleted && swBpEntry\) \{\n"
    r"            /\*\n"
    r"             \* Dual-notify VT step completion:.*?"
    r"            swBpEntry->StepThreadToken = NULL;\n"
    r"        \}",
    re.S,
)
m = pat.search(text)
if not m:
    raise SystemExit("HvVwatch dual-notify complete block not found")
replacement = """        if (debuggerStepCompleted) {
            (void)HvVwatchpTryInjectPrivateStepDb();
        }"""
text = text[: m.start()] + replacement + text[m.end() :]
p.write_text(text, encoding="utf-8")
print("HvVwatch.c restored to pre-grok inject-only STEP")

# ========== 2. debugger_ui.rs ==========
p = Path(
    r"E:\project_learning\YuYuanVTDebug\Netr\tools\netr-gui-rs\src-tauri\src\commands\debugger_ui.rs"
)
text = p.read_text(encoding="utf-8", errors="replace")

old_wait = """        let private_kind = state
            .pending_private
            .lock()
            .get(&tid)
            .filter(|event| event.process_id == pid)
            .map(|event| event.kind);
        let private_pending = private_kind.is_some();
        // kind=2 is HV_BRIDGE_PRIVATE_EVENT_STEP. Built-in VT steps still arm a
        // native #DB receiver, but dual-notify may complete via private STEP
        // first; treat STEP as a valid pause when require_native_event is set.
        // Do NOT treat SWBP (kind=1) as VT step completion.
        let private_step_pending = private_kind == Some(2);
        let native_pending = super::native_debug::owns_pending_event(pid, tid);
        if native_pending
            || (!require_native_event && private_pending)
            || (require_native_event && private_step_pending)
        {
            return Ok(());
        }"""
new_wait = """        let private_pending = state
            .pending_private
            .lock()
            .get(&tid)
            .is_some_and(|event| event.process_id == pid);
        let native_pending = super::native_debug::owns_pending_event(pid, tid);
        if native_pending || (!require_native_event && private_pending) {
            return Ok(());
        }"""
if old_wait not in text:
    raise SystemExit("debugger_ui wait block not found")
text = text.replace(old_wait, new_wait, 1)

old_cont = """    if written as usize != std::mem::size_of::<OperationResult>()
        || result.reserved != 0
        || result.status != BRIDGE_STATUS_SUCCESS as u32
    {
        // STEP completion has no HitPending SWBP entry. Driver continue returns
        // NOT_FOUND by design; still treat as soft success so the poller can
        // resume the suspended thread.
        if pending.kind == 2
            && written as usize == std::mem::size_of::<OperationResult>()
            && result.reserved == 0
            && result.status == BRIDGE_STATUS_NOT_FOUND as u32
        {
            super::native_debug::private_dbgk_entry_diag(
                pending.process_id,
                "private_swbp.continue.step_not_found",
                format!(
                    "sequence={} tid={} soft-ok",
                    pending.sequence, pending.thread_id
                ),
            );
            return Ok(());
        }
        return Err(AppError::Internal(format!(
            "private continue failed: bytes={written}, status={}, reserved={}",
            result.status, result.reserved,
        )));
    }
    Ok(())
}

fn drain_pending_private_events_for_pid("""
new_cont = """    if written as usize != std::mem::size_of::<OperationResult>()
        || result.reserved != 0
        || result.status != BRIDGE_STATUS_SUCCESS as u32
    {
        return Err(AppError::Internal(format!(
            "private continue failed: bytes={written}, status={}, reserved={}",
            result.status, result.reserved,
        )));
    }
    Ok(())
}

fn drain_pending_private_events_for_pid("""
if old_cont not in text:
    raise SystemExit("debugger_ui continue soft STEP not found")
text = text.replace(old_cont, new_cont, 1)

old_fin = """        Ok(()) => {
            if owns_vt_gate {
                clear_vt_step_gate(state, device, tid)?;
                // Dual-notify may still deliver a late inject #DB after STEP
                // completed the wait. Clear the native/private receiver so the
                // late SINGLE_STEP is not misclassified as a fresh user step.
                let _ = super::native_debug::cancel_vt_step(pid, tid);
            }
            if let Some(address) = transient_address {
                consume_transient_private_swbp(state, device, pid, address)?;
            }
            Ok(())
        }"""
new_fin = """        Ok(()) => {
            if owns_vt_gate {
                clear_vt_step_gate(state, device, tid)?;
            }
            if let Some(address) = transient_address {
                consume_transient_private_swbp(state, device, pid, address)?;
            }
            Ok(())
        }"""
if old_fin not in text:
    raise SystemExit("debugger_ui finish_step dual-notify not found")
text = text.replace(old_fin, new_fin, 1)

late_pat = re.compile(
    r"        // Late HV_BRIDGE_PRIVATE_EVENT_STEP after inject #DB already completed\n"
    r"        // the step and finish_step_transaction cleared vt_step_gates\. Soft\n"
    r"        // continue \+ discard so the target is not left suspended on a duplicate\n"
    r"        // stop\. Active gates mean this STEP is the real completion path\.\n"
    r"        if result\.event\.kind == 2 \{\n"
    r"            let has_active_gate = handles\.vt_step_gates\.lock\(\)\.contains_key\(&tid\);\n"
    r"            if !has_active_gate \{\n"
    r".*?                continue;\n"
    r"            \}\n"
    r"        \}\n",
    re.S,
)
m = late_pat.search(text)
if not m:
    raise SystemExit("debugger_ui late_step_discard not found")
text = text[: m.start()] + text[m.end() :]
p.write_text(text, encoding="utf-8")
print("debugger_ui.rs dual-path reverted")
print("phase1 OK")
