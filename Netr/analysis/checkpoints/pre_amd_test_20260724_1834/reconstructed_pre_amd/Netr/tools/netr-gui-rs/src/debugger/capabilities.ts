import type { BuiltinDebuggerMode } from "./ipc";
import type { DebuggerCapabilities } from "./sessionStore";

export function swBreakpointUnavailableReason(
  mode: BuiltinDebuggerMode,
  capabilities: DebuggerCapabilities | null,
): string | null {
  if (mode === "native") return null;
  if (!capabilities?.privateSwBp) return "VT 会话未获得 private software-breakpoint capability";
  return null;
}

export function hwBreakpointUnavailableReason(
  mode: BuiltinDebuggerMode,
  capabilities: DebuggerCapabilities | null,
): string | null {
  if (mode === "native") {
    return capabilities?.drFallback ? null : "Native 会话尚未建立调试寄存器事件链";
  }
  if (!capabilities?.vtHwBp) return "VT 会话未获得 VT hardware-breakpoint capability";
  return null;
}

export function stepUnavailableReason(
  operation: "into" | "over" | "out",
  mode: BuiltinDebuggerMode,
  capabilities: DebuggerCapabilities | null,
): string | null {
  if (mode === "native") return null;
  if (operation === "into") return null;
  if (operation === "out" && !capabilities?.privateSwBp) {
    return "步出需要临时 VT 软件断点，当前会话未获得 private software-breakpoint capability";
  }
  if (operation === "over" && !capabilities?.privateSwBp) {
    return "步过需要临时 VT 软件断点，当前会话未获得 private software-breakpoint capability";
  }
  return null;
}
