import { useEffect, useMemo, useState } from "react";
import { Plug, Unplug, Loader2, ShieldCheck, RefreshCw, Search, Save } from "lucide-react";
import { toast } from "sonner";
import { invoke } from "@tauri-apps/api/core";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { systemIpc, type ProcessInfo } from "@/ipc";
import { dbgIpc, errMsg } from "./ipc";
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

  // 自我保护(独立 webview, 后端 AtomicBool 轮询)
  const [selfProtected, setSelfProtected] = useState(false);
  useEffect(() => {
    let alive = true;
    const tick = async () => {
      try {
        const v = await invoke<boolean>("dbg_self_protected");
        if (alive) setSelfProtected(v);
      } catch {/* ignore */}
    };
    void tick();
    const id = setInterval(tick, 1500);
    return () => { alive = false; clearInterval(id); };
  }, []);

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
    try {
      // 试读 1 字节确认 OpenProcess 通了
      try {
        await dbgIpc.readMemory(pid, 0, 1);
      } catch {/* 0 地址必失败,但 handle 已缓存 */}

      session.attach(pid, name);
      clearExprModuleCache();
      try {
        const mods = await dbgIpc.listModules(pid);
        if (mods.length > 0) session.setAddress(BigInt(mods[0].base));
      } catch {/* ignore */}
      try {
        const ths = await dbgIpc.listThreads(pid);
        if (ths.length > 0) session.setSelectedTid(ths[0].tid);
      } catch {/* ignore */}
      toast.success(`已附加: ${name} (PID ${pid})`);
    } catch (e) {
      toast.error(`附加失败: ${errMsg(e)}`);
    } finally {
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

  if (session.pid) {
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
        {selfProtected ? (
          <span className="pill pill-primary">
            <ShieldCheck className="h-3 w-3" /> 自我保护
          </span>
        ) : (
          <span className="pill pill-muted">未保护</span>
        )}
        <Button
          variant="ghost"
          size="sm"
          onClick={() => void dumpProcessUI()}
          disabled={busy}
          className="ml-auto"
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

  return <AttachForm onAttach={attachByPid} busy={busy} selfProtected={selfProtected} />;
}

function AttachForm({
  onAttach,
  busy,
  selfProtected,
}: {
  onAttach: (pid: number, name: string) => void;
  busy: boolean;
  selfProtected: boolean;
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
        <ProjectMenu />
        <div className="h-5 w-px bg-border" />
        <span className="text-xs text-muted-foreground">附加进程</span>

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

        <div className="ml-auto flex items-center text-xs text-muted-foreground">
          {selfProtected ? (
            <span className="pill pill-primary"><ShieldCheck className="h-3 w-3" /> 已保护</span>
          ) : (
            <span className="pill pill-muted">未保护</span>
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
