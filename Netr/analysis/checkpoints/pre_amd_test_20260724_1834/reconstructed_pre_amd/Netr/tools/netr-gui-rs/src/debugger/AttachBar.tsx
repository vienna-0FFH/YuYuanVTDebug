import { useEffect, useMemo, useState } from "react";
import { Plug, Unplug, Loader2, ShieldCheck, RefreshCw, Search, Save, RotateCcw } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { systemIpc, type ProcessInfo } from "@/ipc";
import { driverIpc } from "@/ipc/driver";
import { dbgIpc, errMsg, type BuiltinDebuggerMode } from "./ipc";
import { useSession } from "./sessionStore";
import { clearExprModuleCache } from "./expr";
import { ProjectMenu } from "./ProjectMenu";

/**
 * 调试器窗口顶部:
 *   未附加 → 搜索/PID 输入 + 附加按钮
 *   已附加 → 进程信息 + 解附按钮 + 自我保护状态
 *
 * P47: 增加 PID 直接输入、搜索过滤、刷新进程列表
 */
export function AttachBar() {
  const session = useSession();
  const [busy, setBusy] = useState(false);
  const [driverAvailable, setDriverAvailable] = useState<boolean | null>(null);

  // 调试器是独立 webview，不能依赖主窗口的 Zustand driverStore。
  // 直接探测后端 device handle：Native 始终可选，VT 只有 device 已打开才可选。
  useEffect(() => {
    let alive = true;
    const probe = async () => {
      try {
        const open = await driverIpc.deviceOpen();
        if (alive) setDriverAvailable(open);
      } catch {
        if (alive) setDriverAvailable(false);
      }
    };
    void probe();
    const id = setInterval(() => void probe(), 1500);
    return () => { alive = false; clearInterval(id); };
  }, []);

  useEffect(() => {
    if (!session.pid && driverAvailable === false && session.debugMode === "vt") {
      session.setDebugMode("native");
    }
  }, [driverAvailable, session.debugMode, session.pid, session.setDebugMode]);

  async function dumpProcessUI() {
    if (!session.pid) return;
    const includeMapped = confirm("包含 MEM_MAPPED 文件映射? (通常巨大, 默认不要)");
    try {
      toast.info("dump 中, 大型进程可能要几十秒...");
      const r = await dbgIpc.dumpProcess({
        pid: session.pid,
        include_images: true,
        include_private: true,
        include_mapped: includeMapped,
      });
      if (r.regions_dumped === 0) {
        toast.warning(
          `Dump 没保存任何段 (${r.regions_total} 段全失败). ` +
          `进程可能受保护 / 已退出 / 权限不足. → ${r.out_dir}`
        );
      } else {
        toast.success(`已 dump ${r.regions_dumped}/${r.regions_total} 段 (${(r.total_bytes / 1024 / 1024).toFixed(1)}MB) → ${r.out_dir}`);
      }
      void navigator.clipboard.writeText(r.out_dir);
    } catch (e) {
      toast.error(`Dump 失败: ${errMsg(e)}`);
    }
  }

  async function attachByPid(pid: number, name: string) {
    if (pid <= 0) return toast.error("无效 PID");
    setBusy(true);
    session.setAttachingPid(pid);
    try {
      // 后端 attach 是会话建立点：Native 打开 R3 handle；VT 还会登记保护、绑定 target。
      // 必须先成功建立后端会话，再让前端进入“已附加”状态。
      const result = await dbgIpc.attach(pid, session.debugMode);
      session.attach(pid, name, result);
      clearExprModuleCache();
      try {
        const mods = await dbgIpc.listModules(pid);
        if (mods.length > 0) session.setAddress(BigInt(mods[0].base));
      } catch {/* ignore */}
      try {
        const ths = await dbgIpc.listThreads(pid);
        if (ths.length > 0) session.setSelectedTid(ths[0].tid);
      } catch {/* ignore */}
      toast.success(`已附加: ${name} (PID ${pid}) · ${result.mode === "vt" ? "VT" : "Native"}`);
    } catch (e) {
      toast.error(`附加失败: ${errMsg(e)}`);
    } finally {
      useSession.getState().setAttachingPid(null);
      setBusy(false);
    }
  }

  async function detach() {
    if (!session.pid) return;
    const pid = session.pid;
    setBusy(true);
    try {
      for (const w of session.watches) {
        if (w.frozen) {
          try { await dbgIpc.freezeClear(pid, Number(w.address)); } catch {/* ignore */}
        }
      }
      await dbgIpc.detach(pid);
      session.detach();
      clearExprModuleCache();
      toast.success("已解附");
    } catch (e) {
      toast.error(`解附失败: ${errMsg(e)}`);
    } finally {
      setBusy(false);
    }
  }

  async function restart() {
    if (!session.pid) return;
    const pid = session.pid;
    setBusy(true);
    session.setAttachingPid(pid);
    try {
      await dbgIpc.restartProcess(pid);
    } catch (e) {
      toast.error(`重启失败: ${errMsg(e)}`, {
        duration: 10000,
      });
    } finally {
      useSession.getState().setAttachingPid(null);
      setBusy(false);
    }
  }

  if (session.pid) {
    const caps = session.capabilities;
    const capabilitySummary = caps
      ? [
          caps.vtMemory && "VT 内存",
          caps.privateSwBp && "VT 软件断点",
          caps.vtHwBp && "VT 硬件断点",
          caps.drFallback && "DR 回退",
        ].filter(Boolean).join(" · ")
      : "能力未知";
    return (
      <div className="flex h-11 shrink-0 items-center gap-3 border-b border-border bg-card/60 px-3 backdrop-blur-sm">
        <ProjectMenu />
        <div className="h-5 w-px bg-border" />
        <span className="pill pill-success">
          <span className="pill-dot pill-dot-pulse bg-success" />
          已附加
        </span>
        <span className="text-sm font-medium">{session.processName}</span>
        <span className="font-mono text-xs text-muted-foreground">PID {session.pid}</span>
        <span className={session.debugMode === "vt" ? "pill pill-primary" : "pill pill-muted"}>
          {session.debugMode === "vt" ? "VT 会话" : "Native 会话"}
        </span>
        {caps?.debuggerProtected ? (
          <span className="pill pill-primary">
            <ShieldCheck className="h-3 w-3" /> 调试器受保护
          </span>
        ) : (
          <span className="pill pill-muted">Windows 原生链</span>
        )}
        <span className="max-w-[28rem] truncate text-[10px] text-muted-foreground" title={capabilitySummary}>
          {capabilitySummary}
        </span>
        <TfModeToggle />
        <Button
          variant="ghost"
          size="sm"
          onClick={() => void restart()}
          disabled={busy}
          className="ml-auto"
          title="按原路径、参数、工作目录和 Native/VT 模式重启，并停在程序入口"
        >
          {busy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <RotateCcw className="h-3.5 w-3.5" />}
          重启
        </Button>
        <Button
          variant="ghost"
          size="sm"
          onClick={() => void dumpProcessUI()}
          disabled={busy}
          title="把进程所有 commit 区分文件 dump 到 workspace"
        >
          <Save className="h-3.5 w-3.5" /> Dump 进程
        </Button>
        <Button
          variant="ghost"
          size="sm"
          onClick={() => void detach()}
          disabled={busy}
        >
          {busy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Unplug className="h-3.5 w-3.5" />}
          解附
        </Button>
      </div>
    );
  }

  return (
    <AttachForm
      onAttach={attachByPid}
      busy={busy}
      driverAvailable={driverAvailable}
      mode={session.debugMode}
      onModeChange={session.setDebugMode}
    />
  );
}

function AttachForm({
  onAttach,
  busy,
  driverAvailable,
  mode,
  onModeChange,
}: {
  onAttach: (pid: number, name: string) => void;
  busy: boolean;
  driverAvailable: boolean | null;
  mode: BuiltinDebuggerMode;
  onModeChange: (mode: BuiltinDebuggerMode) => void;
}) {
  const [pidInput, setPidInput] = useState("");
  const [q, setQ] = useState("");
  const [procs, setProcs] = useState<ProcessInfo[]>([]);
  const [loading, setLoading] = useState(false);
  const [open, setOpen] = useState(false);

  async function refresh() {
    setLoading(true);
    try {
      const list = await systemIpc.listProcesses();
      setProcs(list.sort((a, b) => a.name.localeCompare(b.name)));
    } catch (e) {
      toast.error(`枚举进程失败: ${errMsg(e)}`);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { void refresh(); }, []);

  const filtered = useMemo(() => {
    const t = q.trim().toLowerCase();
    if (!t) return procs;
    return procs.filter(
      (p) => p.name.toLowerCase().includes(t) || String(p.pid).includes(t)
    );
  }, [q, procs]);

  function attachByInput() {
    const n = Number(pidInput.trim());
    if (Number.isFinite(n) && n > 0) {
      const m = procs.find((p) => p.pid === n);
      onAttach(n, m?.name ?? `PID${n}`);
    } else {
      toast.error("请输入有效 PID(纯数字)");
    }
  }

  return (
    <div className="flex shrink-0 flex-col border-b border-border bg-card/60 backdrop-blur-sm">
      <div className="flex h-11 items-center gap-2 px-3">
        <ProjectMenu showQuickLaunch />
        <div className="h-5 w-px bg-border" />
        <span className="text-xs text-muted-foreground">附加进程</span>

        <TfModeToggle />

        <div className="flex items-center rounded-md border border-border bg-background/40 p-0.5">
          <Button
            type="button"
            size="sm"
            variant={mode === "native" ? "secondary" : "ghost"}
            className="h-6 px-2"
            disabled={busy}
            onClick={() => onModeChange("native")}
            title="Native：使用 Windows 进程/线程 API，可在没有驱动时使用"
          >
            Native
          </Button>
          <Button
            type="button"
            size="sm"
            variant={mode === "vt" ? "secondary" : "ghost"}
            className="h-6 px-2"
            disabled={busy || driverAvailable !== true}
            onClick={() => onModeChange("vt")}
            title={driverAvailable === true
              ? "VT：通过驱动保护、VT 内存与无痕断点能力建立会话"
              : "VT 需要驱动设备已连接；当前仍可使用 Native 模式"}
          >
            VT
          </Button>
        </div>

        <Input
          value={pidInput}
          onChange={(e) => setPidInput(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && attachByInput()}
          placeholder="PID"
          className="h-7 w-20 font-mono text-xs"
        />
        <Button size="sm" onClick={attachByInput} disabled={busy || !pidInput.trim()} className="h-7">
          {busy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Plug className="h-3.5 w-3.5" />}
          附加 PID
        </Button>

        <div className="mx-2 h-5 w-px bg-border" />

        <div className="relative flex-1 max-w-md">
          <Search className="absolute left-2 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
          <Input
            value={q}
            onChange={(e) => { setQ(e.target.value); setOpen(true); }}
            onFocus={() => setOpen(true)}
            placeholder="搜索"
            className="h-7 pl-7 text-xs"
          />
        </div>
        <Button size="sm" variant="ghost" onClick={() => void refresh()} disabled={loading} className="h-7 px-2">
          {loading ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <RefreshCw className="h-3.5 w-3.5" />}
        </Button>

        <div className="ml-auto flex items-center text-[10px] text-muted-foreground">
          {driverAvailable === null ? (
            <span className="pill pill-muted">检测驱动...</span>
          ) : driverAvailable ? (
            <span className="pill pill-primary"><ShieldCheck className="h-3 w-3" /> VT 可用</span>
          ) : (
            <span className="pill pill-muted" title="未连接驱动不会阻止内置调试器；仅 VT 会话不可用">
              无驱动：使用 Native
            </span>
          )}
        </div>
      </div>

      {open && (
        <div className="border-t border-border bg-popover/95 px-3 py-1 max-h-64 overflow-auto">
          {filtered.length === 0 ? (
            <div className="py-3 text-center text-xs text-muted-foreground">无匹配进程</div>
          ) : (
            <div className="grid grid-cols-[60px_180px_60px_1fr_auto] gap-2 text-xs">
              <div className="border-b border-border pb-1 font-medium text-muted-foreground">PID</div>
              <div className="border-b border-border pb-1 font-medium text-muted-foreground">名称</div>
              <div className="border-b border-border pb-1 font-medium text-muted-foreground">父</div>
              <div className="border-b border-border pb-1 font-medium text-muted-foreground">路径</div>
              <div className="border-b border-border pb-1" />
              {filtered.slice(0, 200).map((p) => (
                <Row key={p.pid} p={p} onAttach={() => { onAttach(p.pid, p.name); setOpen(false); }} />
              ))}
              {filtered.length > 200 && (
                <div className="col-span-5 py-2 text-center text-[10px] text-muted-foreground">
                  仅显示前 200 项,请用搜索过滤
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function TfModeToggle() {
  const session = useSession();
  const enabled = session.syntheticMtfStep;
  const disabled = Boolean(session.pid) && session.debugMode !== "vt";
  return (
    <button
      type="button"
      role="switch"
      aria-checked={enabled}
      disabled={disabled}
      onClick={() => session.setSyntheticMtfStep(!enabled)}
      title={disabled
        ? "Native 会话固定使用真实 RFLAGS.TF"
        : enabled
        ? "开启：内置 VT 单步使用合成 MTF/#DB 方案"
        : "关闭：内置 VT 单步使用真实 RFLAGS.TF/#DB"}
      className="flex h-7 items-center gap-1.5 rounded-md border border-border px-2 text-xs text-muted-foreground transition-colors hover:bg-accent hover:text-foreground disabled:cursor-not-allowed disabled:opacity-45"
    >
      <span className={enabled
        ? "relative h-4 w-7 rounded-full bg-primary/70"
        : "relative h-4 w-7 rounded-full bg-muted"}>
        <span className={enabled
          ? "absolute left-0.5 top-0.5 h-3 w-3 translate-x-3 rounded-full bg-background shadow"
          : "absolute left-0.5 top-0.5 h-3 w-3 rounded-full bg-background shadow"} />
      </span>
      合成 MTF 单步
    </button>
  );
}

function Row({ p, onAttach }: { p: ProcessInfo; onAttach: () => void }) {
  return (
    <>
      <div className="font-mono text-muted-foreground/80">{p.pid}</div>
      <div className="truncate font-medium">{p.name}</div>
      <div className="font-mono text-[10px] text-muted-foreground/70">{p.parent_pid}</div>
      <div className="truncate font-mono text-[10px] text-muted-foreground" title={p.path}>{p.path}</div>
      <Button size="sm" variant="ghost" className="h-6 px-2 text-[10px]" onClick={onAttach}>
        附加
      </Button>
    </>
  );
}
