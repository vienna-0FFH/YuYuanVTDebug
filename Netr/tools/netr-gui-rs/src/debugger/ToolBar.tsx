import { useEffect, useState } from "react";
import { Pause, Play, Cpu, Crosshair, Layers, ChevronsUp,
  StepForward, ArrowDownToLine, ArrowUpFromLine, RefreshCw, ScanLine,
  Bot, Network } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { dbgIpc, errMsg } from "./ipc";
import {
  beginStepExecution,
  cancelActiveRunExecution,
  endStepExecution,
  useSession,
} from "./sessionStore";
import { hwBreakpointUnavailableReason, stepUnavailableReason } from "./capabilities";
import { cn } from "@/lib/utils";

/**
 * 工具栏:线程切换 / 暂停-恢复 / 步过-步入 / 模块跳转 / 右停靠开关 / 底部展开。
 */
export function ToolBar() {
  const session = useSession();
  const { selectedTid, pid, rightTab, setRightTab, bottomCollapsed, setBottomCollapsed, setCtx } = session;
  const activeStepReason = session.activeStep
    ? `线程 ${session.activeStep.tid} 的调试器步进仍在执行`
    : null;
  const stepOverReason = activeStepReason ?? stepUnavailableReason("over", session.debugMode, session.capabilities);
  const stepIntoReason = activeStepReason ?? stepUnavailableReason("into", session.debugMode, session.capabilities);
  const stepOutReason = activeStepReason ?? stepUnavailableReason("out", session.debugMode, session.capabilities);
  const hwbpReason = hwBreakpointUnavailableReason(session.debugMode, session.capabilities);

  async function suspend() {
    if (!selectedTid) return toast.error("先选线程");
    try {
      await dbgIpc.suspendThread(selectedTid);
      if (pid) {
        try {
          await cancelActiveRunExecution(pid, selectedTid);
        } catch (error) {
          toast.error(`步进一次性断点清理失败: ${errMsg(error)}`);
        }
      }
      const c = await dbgIpc.getThreadContext(selectedTid);
      setCtx(c);
      toast.success(`线程 ${selectedTid} 已暂停 + 拉取上下文`);
    } catch (e) {
      toast.error(`暂停失败: ${errMsg(e)}`);
    }
  }
  async function resume() {
    if (!selectedTid) return toast.error("先选线程");
    try {
      await dbgIpc.resumeThread(selectedTid);
      setCtx(null);
      toast.success(`线程 ${selectedTid} 已恢复`);
    } catch (e) {
      toast.error(`恢复失败: ${errMsg(e)}`);
    }
  }

  async function stepOver() {
    if (!pid || !selectedTid) return toast.error("先选线程");
    const conflict = beginStepExecution(selectedTid, "over");
    if (conflict) return toast.error(conflict);
    try {
      const result = await dbgIpc.stepOver(pid, selectedTid, session.syntheticMtfStep);
      if (result.kind !== "run-over") endStepExecution(selectedTid, "over");
    } catch (error) {
      try {
        await cancelActiveRunExecution(pid, selectedTid, "over");
        toast.error(errMsg(error));
      } catch (cleanupError) {
        toast.error(`${errMsg(error)}；步进回滚失败: ${errMsg(cleanupError)}`);
      }
    }
  }

  async function stepInto() {
    if (!selectedTid) return toast.error("先选线程");
    const conflict = beginStepExecution(selectedTid, "into");
    if (conflict) return toast.error(conflict);
    try {
      await dbgIpc.stepInto(selectedTid, session.syntheticMtfStep);
    } catch (error) {
      toast.error(errMsg(error));
    } finally {
      endStepExecution(selectedTid, "into");
    }
  }

  async function stepOut() {
    if (!pid || !selectedTid) return toast.error("先选线程");
    const conflict = beginStepExecution(selectedTid, "out");
    if (conflict) return toast.error(conflict);
    try {
      await dbgIpc.stepOut(pid, selectedTid);
    } catch (error) {
      try {
        await cancelActiveRunExecution(pid, selectedTid, "out");
        toast.error(errMsg(error));
      } catch (cleanupError) {
        toast.error(`${errMsg(error)}；步进回滚失败: ${errMsg(cleanupError)}`);
      }
    }
  }

  return (
    <div className="flex h-10 shrink-0 items-center gap-2 border-b border-border bg-card/40 px-3 backdrop-blur-sm">
      <ThreadPicker />

      <div className="mx-1 h-5 w-px bg-border" />

      <Button variant="ghost" size="sm" onClick={suspend} title="暂停线程 (F6)" className="h-7 px-2">
        <Pause className="h-3.5 w-3.5" /> 暂停
      </Button>
      <Button variant="ghost" size="sm" onClick={resume} title="恢复线程 (F5)" className="h-7 px-2">
        <Play className="h-3.5 w-3.5" /> 恢复
      </Button>
      <Button
        variant="ghost"
        size="sm"
        title={stepOverReason ?? "步过 (F8)"}
        className="h-7 px-2"
        disabled={Boolean(stepOverReason)}
        onClick={() => void stepOver()}
      >
        <StepForward className="h-3.5 w-3.5" /> 步过
      </Button>
      <Button
        variant="ghost"
        size="sm"
        title={stepIntoReason ?? "步入 (F11)"}
        className="h-7 px-2"
        disabled={Boolean(stepIntoReason)}
        onClick={() => void stepInto()}
      >
        <ArrowDownToLine className="h-3.5 w-3.5" /> 步入
      </Button>
      <Button
        variant="ghost"
        size="sm"
        title={stepOutReason ?? "步出 (Shift+F11)"}
        className="h-7 px-2"
        disabled={Boolean(stepOutReason)}
        onClick={() => void stepOut()}
      >
        <ArrowUpFromLine className="h-3.5 w-3.5" /> 步出
      </Button>
      {(stepOverReason || stepIntoReason || stepOutReason) && (
        <span
          className="pill pill-muted max-w-44 truncate"
          title={stepOverReason ?? stepIntoReason ?? stepOutReason ?? undefined}
        >
          {session.activeStep ? "运行至断点中" : "单步事件链不可用"}
        </span>
      )}

      <div className="mx-1 h-5 w-px bg-border" />
      <MultiStepButton overReason={stepOverReason} intoReason={stepIntoReason} />

      <button
        type="button"
        role="switch"
        aria-checked={session.debugMode === "vt" && session.syntheticMtfStep}
        disabled={session.debugMode !== "vt"}
        onClick={() => session.setSyntheticMtfStep(!session.syntheticMtfStep)}
        title={session.debugMode !== "vt"
          ? "Native 会话固定使用真实 RFLAGS.TF"
          : session.syntheticMtfStep
            ? "开启：内置 VT 单步使用当前合成 MTF/#DB 方案"
            : "关闭：内置 VT 单步使用真实 RFLAGS.TF/#DB"}
        className={cn(
          "flex h-7 items-center gap-1.5 rounded-md border border-transparent px-2 text-xs transition-colors",
          session.debugMode !== "vt" && "cursor-not-allowed opacity-45",
          session.debugMode === "vt" && session.syntheticMtfStep
            ? "border-primary/40 bg-primary/15 text-primary"
            : "text-muted-foreground hover:bg-accent hover:text-foreground",
        )}
      >
        <span
          className={cn(
            "relative h-4 w-7 rounded-full bg-muted transition-colors",
            session.debugMode === "vt" && session.syntheticMtfStep && "bg-primary/70",
          )}
        >
          <span
            className={cn(
              "absolute left-0.5 top-0.5 h-3 w-3 rounded-full bg-background shadow transition-transform",
              session.debugMode === "vt" && session.syntheticMtfStep && "translate-x-3",
            )}
          />
        </span>
        合成 MTF 单步
      </button>

      <div className="mx-1 h-5 w-px bg-border" />

      <ToggleBtn
        Icon={Cpu}
        label="寄存器/栈"
        active={rightTab === "regs"}
        onClick={() => setRightTab(rightTab === "regs" ? null : "regs")}
      />
      <ToggleBtn
        Icon={Crosshair}
        label="硬件断点"
        active={rightTab === "hwbp"}
        onClick={() => setRightTab(rightTab === "hwbp" ? null : "hwbp")}
        disabled={Boolean(hwbpReason)}
        reason={hwbpReason}
      />
      <ToggleBtn
        Icon={Layers}
        label="调用栈"
        active={rightTab === "callstack"}
        onClick={() => setRightTab(rightTab === "callstack" ? null : "callstack")}
      />
      <ToggleBtn
        Icon={ScanLine}
        label="结构分析"
        active={rightTab === "dissect"}
        onClick={() => setRightTab(rightTab === "dissect" ? null : "dissect")}
      />
      <ToggleBtn
        Icon={Bot}
        label="AI"
        active={rightTab === "ai"}
        onClick={() => setRightTab(rightTab === "ai" ? null : "ai")}
      />
      <ToggleBtn
        Icon={Network}
        label="MCP (静态分析对接, e.g. IDA)"
        active={rightTab === "mcp"}
        onClick={() => setRightTab(rightTab === "mcp" ? null : "mcp")}
      />

      <div className="ml-auto flex items-center gap-2 text-xs text-muted-foreground">
        <span>PID {pid}</span>
        {selectedTid && <span>· TID {selectedTid}</span>}
        {bottomCollapsed && (
          <Button
            size="sm"
            variant="ghost"
            className="h-7 px-2"
            onClick={() => setBottomCollapsed(false)}
            title="展开"
          >
            <ChevronsUp className="h-3.5 w-3.5" />
          </Button>
        )}
        <Button
          size="sm"
          variant="ghost"
          className="h-7 px-2"
          onClick={() => session.setAddress(session.address)}
          title="刷新"
        >
          <RefreshCw className="h-3.5 w-3.5" />
        </Button>
      </div>
    </div>
  );
}

function ToggleBtn({
  Icon,
  label,
  active,
  onClick,
  disabled,
  reason,
}: {
  Icon: React.ComponentType<{ className?: string }>;
  label: string;
  active: boolean;
  onClick: () => void;
  disabled?: boolean;
  reason?: string | null;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      title={reason ?? undefined}
      className={cn(
        "flex h-7 items-center gap-1.5 rounded-md border border-transparent px-2.5 text-xs transition-colors",
        disabled && "cursor-not-allowed opacity-45",
        active
          ? "border-primary/40 bg-primary/15 text-primary"
          : "text-muted-foreground hover:bg-accent hover:text-foreground"
      )}
    >
      <Icon className="h-3.5 w-3.5" />
      {label}
    </button>
  );
}

function MultiStepButton({
  overReason,
  intoReason,
}: {
  overReason: string | null;
  intoReason: string | null;
}) {
  const { pid, selectedTid, syntheticMtfStep } = useSession();
  const [open, setOpen] = useState(false);
  const [kind, setKind] = useState<"over" | "into">("over");
  const [countText, setCountText] = useState("10");
  const [busy, setBusy] = useState(false);

  if (!pid) return null;
  const unavailable = kind === "over" ? overReason : intoReason;
  const allUnavailable = Boolean(overReason && intoReason);

  function show() {
    setKind(overReason && !intoReason ? "into" : "over");
    setOpen(true);
  }

  async function run() {
    if (!pid || !selectedTid) return toast.error("先选择线程");
    const count = Number(countText);
    if (!Number.isInteger(count) || count < 1 || count > 1000) {
      return toast.error("步数必须是 1 到 1000 的整数");
    }
    if (unavailable) return toast.error(unavailable);
    const conflict = beginStepExecution(selectedTid, "many");
    if (conflict) return toast.error(conflict);

    setBusy(true);
    try {
      const result = await dbgIpc.stepMany(
        pid,
        selectedTid,
        kind,
        count,
        syntheticMtfStep,
      );
      const current = useSession.getState();
      if (current.pid === pid && current.selectedTid === selectedTid) {
        current.setAddress(BigInt(result.rip));
        try {
          current.setCtx(await dbgIpc.getThreadContext(selectedTid));
        } catch {
          // 最终 RIP 已由串行命令返回，单独的上下文刷新失败不影响已完成的步进。
        }
      }
      setOpen(false);
      toast.success(`${kind === "over" ? "步过" : "步入"} ${result.steps} 步完成`);
    } catch (error) {
      toast.error(`N步执行失败: ${errMsg(error)}`);
    } finally {
      endStepExecution(selectedTid, "many");
      setBusy(false);
    }
  }

  return (
    <>
      <Button
        size="sm"
        variant="ghost"
        onClick={show}
        disabled={!selectedTid || allUnavailable}
        title={allUnavailable ? (overReason ?? intoReason ?? undefined) : "连续步入/步过"}
        className="h-7 px-2 text-xs"
      >
        <StepForward className="h-3.5 w-3.5" /> N步
      </Button>
      <Dialog
        open={open}
        onClose={() => { if (!busy) setOpen(false); }}
        closeOnOverlay={!busy}
        title="连续执行 N 步"
        description="每一步都等待目标重新暂停后再继续，最多 1000 步。"
        widthClass="max-w-sm"
      >
        <div className="space-y-4 p-5 text-sm">
          <div className="grid grid-cols-2 gap-2">
            {(["over", "into"] as const).map((value) => {
              const reason = value === "over" ? overReason : intoReason;
              return (
                <button
                  key={value}
                  type="button"
                  disabled={Boolean(reason) || busy}
                  onClick={() => setKind(value)}
                  title={reason ?? undefined}
                  className={cn(
                    "rounded-md border px-3 py-2 text-left transition-colors",
                    kind === value ? "border-primary bg-primary/10 text-primary" : "border-border hover:bg-accent",
                    reason && "cursor-not-allowed opacity-45"
                  )}
                >
                  <div className="font-medium">{value === "over" ? "步过" : "步入"}</div>
                  <div className="mt-0.5 text-[11px] text-muted-foreground">
                    {value === "over" ? "调用作为一步执行" : "进入调用内部"}
                  </div>
                </button>
              );
            })}
          </div>
          <label className="block space-y-1.5">
            <span className="text-xs text-muted-foreground">步数</span>
            <Input
              type="number"
              min={1}
              max={1000}
              step={1}
              value={countText}
              disabled={busy}
              onChange={(event) => setCountText(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === "Enter" && !busy) void run();
              }}
              autoFocus
            />
          </label>
          {unavailable && <div className="text-xs text-destructive">{unavailable}</div>}
          <div className="flex justify-end gap-2">
            <Button variant="ghost" onClick={() => setOpen(false)} disabled={busy}>取消</Button>
            <Button onClick={() => void run()} disabled={busy || Boolean(unavailable)}>
              {busy ? "执行中..." : "开始"}
            </Button>
          </div>
        </div>
      </Dialog>
    </>
  );
}
function ThreadPicker() {
  const { pid, selectedTid, setSelectedTid } = useSession();
  const [threads, setThreads] = useState<{ tid: number }[]>([]);
  const [busy, setBusy] = useState(false);

  async function refresh() {
    if (!pid) return;
    setBusy(true);
    try {
      setThreads(await dbgIpc.listThreads(pid));
    } catch {
      setThreads([]);
    } finally {
      setBusy(false);
    }
  }
  useEffect(() => { void refresh(); /* eslint-disable-next-line react-hooks/exhaustive-deps */ }, [pid]);

  if (!pid) return null;
  return (
    <div className="flex items-center gap-1 text-xs">
      <Cpu className="h-3.5 w-3.5 text-muted-foreground" />
      <select
        value={selectedTid ?? ""}
        onChange={(e) => setSelectedTid(e.target.value ? Number(e.target.value) : null)}
        className="h-7 rounded-md border border-input bg-background px-2 font-mono text-xs"
      >
        <option value="">- 线程 -</option>
        {threads.map((t) => (
          <option key={t.tid} value={t.tid}>TID {t.tid}</option>
        ))}
      </select>
      <Button size="sm" variant="ghost" className="h-7 w-7 p-0" onClick={() => void refresh()} disabled={busy}>
        <RefreshCw className="h-3 w-3" />
      </Button>
    </div>
  );
}
