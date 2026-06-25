import { useEffect, useState } from "react";
import { Pause, Play, Boxes, Cpu, Crosshair, Layers, ChevronsUp,
  StepForward, ArrowDownToLine, ArrowUpFromLine, RefreshCw, ScanLine,
  Bot, Network } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { dbgIpc, errMsg } from "./ipc";
import { useSession } from "./sessionStore";
import { cn } from "@/lib/utils";

/**
 * 工具栏:线程切换 / 暂停-恢复 / 步过-步入 / 模块跳转 / 右停靠开关 / 底部展开。
 */
export function ToolBar() {
  const session = useSession();
  const { selectedTid, pid, rightTab, setRightTab, bottomCollapsed, setBottomCollapsed, setCtx } = session;

  async function suspend() {
    if (!selectedTid) return toast.error("先选线程");
    try {
      await dbgIpc.suspendThread(selectedTid);
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
        title="步过 (F8)"
        className="h-7 px-2"
        onClick={async () => {
          if (!pid || !selectedTid) return toast.error("先选线程");
          try { await dbgIpc.stepOver(pid, selectedTid); } catch (e) { toast.error(errMsg(e)); }
        }}
      >
        <StepForward className="h-3.5 w-3.5" /> 步过
      </Button>
      <Button
        variant="ghost"
        size="sm"
        title="步入 (F11)"
        className="h-7 px-2"
        onClick={async () => {
          if (!selectedTid) return toast.error("先选线程");
          try { await dbgIpc.stepInto(selectedTid); } catch (e) { toast.error(errMsg(e)); }
        }}
      >
        <ArrowDownToLine className="h-3.5 w-3.5" /> 步入
      </Button>
      <Button
        variant="ghost"
        size="sm"
        title="步出 (Shift+F11)"
        className="h-7 px-2"
        onClick={async () => {
          if (!pid || !selectedTid) return toast.error("先选线程");
          try { await dbgIpc.stepOut(pid, selectedTid); } catch (e) { toast.error(errMsg(e)); }
        }}
      >
        <ArrowUpFromLine className="h-3.5 w-3.5" /> 步出
      </Button>

      <div className="mx-1 h-5 w-px bg-border" />
      <ModuleJump />

      <div className="mx-1 h-5 w-px bg-border" />

      <ToggleBtn
        Icon={Crosshair}
        label="硬件断点"
        active={rightTab === "hwbp"}
        onClick={() => setRightTab(rightTab === "hwbp" ? null : "hwbp")}
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
}: {
  Icon: React.ComponentType<{ className?: string }>;
  label: string;
  active: boolean;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={cn(
        "flex h-7 items-center gap-1.5 rounded-md border border-transparent px-2.5 text-xs transition-colors",
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

function ModuleJump() {
  const { pid, setAddress } = useSession();
  const [mods, setMods] = useState<{ name: string; base: number }[]>([]);
  const [open, setOpen] = useState(false);
  const [q, setQ] = useState("");

  useEffect(() => {
    if (!open || !pid) return;
    void (async () => {
      try {
        setMods((await dbgIpc.listModules(pid)).map((m) => ({ name: m.name, base: m.base })));
      } catch {
        setMods([]);
      }
    })();
  }, [open, pid]);

  if (!pid) return null;
  const filtered = q
    ? mods.filter((m) => m.name.toLowerCase().includes(q.toLowerCase()))
    : mods;

  return (
    <div className="relative">
      <Button size="sm" variant="ghost" onClick={() => setOpen((v) => !v)} className="h-7 text-xs">
        <Boxes className="h-3.5 w-3.5" /> 模块 ▾
      </Button>
      {open && (
        <div className="absolute left-0 top-8 z-50 max-h-80 w-72 overflow-hidden rounded-md border bg-popover text-popover-foreground shadow-xl">
          <input
            type="text"
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="搜索模块..."
            className="w-full border-b border-border bg-transparent px-2 py-1.5 text-xs outline-none"
            autoFocus
          />
          <div className="max-h-64 overflow-auto p-1">
            {filtered.length === 0 ? (
              <div className="p-3 text-center text-xs text-muted-foreground">无</div>
            ) : (
              filtered.map((m) => (
                <button
                  key={m.base}
                  type="button"
                  onClick={() => {
                    setAddress(BigInt(m.base));
                    setOpen(false);
                    setQ("");
                  }}
                  className="flex w-full items-center gap-2 rounded px-2 py-1 text-left text-xs hover:bg-accent"
                >
                  <span className="w-40 truncate font-medium">{m.name}</span>
                  <span className="font-mono text-muted-foreground">{m.base.toString(16)}</span>
                </button>
              ))
            )}
          </div>
        </div>
      )}
    </div>
  );
}
