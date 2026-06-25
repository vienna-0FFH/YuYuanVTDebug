import { useCallback, useEffect, useState } from "react";
import {
  Shield,
  ShieldOff,
  FolderOpen,
  Play,
  Loader2,
  Plus,
  Trash2,
  Inbox,
} from "lucide-react";
import { toast } from "sonner";
import { open as openDialog } from "@tauri-apps/plugin-dialog";
import { getCurrentWebview } from "@tauri-apps/api/webview";

import { PageHeader } from "@/components/common/PageHeader";
import { ProcessPicker } from "@/components/common/ProcessPicker";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Checkbox } from "@/components/ui/checkbox";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { debuggerIpc, systemIpc, type ProcessInfo } from "@/ipc";
import { useDriver, selfPidPromise } from "@/store/driverStore";
import { ShieldCheck } from "lucide-react";
import { cn } from "@/lib/utils";

interface ProtectedEntry {
  pid: number;
  processName: string;
  imagePath: string;
  startedByUs: boolean;
  startedAt: number;
}

interface HistoryEntry {
  path: string;
  args: string;
  lastUsed: number;
  /** 累计启动次数 */
  launches: number;
}

const HISTORY_KEY = "netr-debugger-history";

function loadHistory(): HistoryEntry[] {
  try {
    const raw = localStorage.getItem(HISTORY_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed as HistoryEntry[];
  } catch {
    return [];
  }
}

function saveHistory(list: HistoryEntry[]) {
  try {
    localStorage.setItem(HISTORY_KEY, JSON.stringify(list));
  } catch {
    // ignore
  }
}

export default function Debugger() {
  const selfProtected = useDriver((s) => s.selfProtected);
  const [selfPid, setSelfPid] = useState<number | null>(null);
  useEffect(() => {
    void selfPidPromise().then(setSelfPid);
  }, []);

  const [exePath, setExePath] = useState("");
  const [args, setArgs] = useState("");
  const [running, setRunning] = useState<ProcessInfo | null>(null);

  const [privilege, setPrivilege] = useState(true);
  const [protectKill, setProtectKill] = useState(true);
  const [hideList, setHideList] = useState(false);

  const [busy, setBusy] = useState(false);
  const [protectedList, setProtectedList] = useState<ProtectedEntry[]>([]);
  const [history, setHistory] = useState<HistoryEntry[]>(loadHistory);

  const [dragHover, setDragHover] = useState(false);

  // ===== Tauri 拖入 .exe 自动填到启动框 =====
  useEffect(() => {
    const wv = getCurrentWebview();
    let unlisten: (() => void) | undefined;

    wv.onDragDropEvent((e) => {
      if (e.payload.type === "over") {
        setDragHover(true);
      } else if (e.payload.type === "leave") {
        setDragHover(false);
      } else if (e.payload.type === "drop") {
        setDragHover(false);
        const files = e.payload.paths;
        const exe = files.find((p) => p.toLowerCase().endsWith(".exe"));
        if (!exe) {
          toast.error("请拖入 .exe 文件");
          return;
        }
        setExePath(exe);
        toast.success(`已拖入: ${exe.split(/[\\/]/).pop() ?? exe}`);
      }
    }).then((un) => {
      unlisten = un;
    });

    return () => {
      if (unlisten) unlisten();
    };
  }, []);

  async function pickExe() {
    const r = await openDialog({
      multiple: false,
      filters: [{ name: "可执行文件", extensions: ["exe"] }],
    });
    if (typeof r === "string") setExePath(r);
  }

  /** 把一条记录推入历史(去重 + 累计) */
  const upsertHistory = useCallback((path: string, argsStr: string) => {
    setHistory((prev) => {
      const existing = prev.find((h) => h.path === path);
      const updated: HistoryEntry = existing
        ? { ...existing, args: argsStr, lastUsed: Date.now(), launches: existing.launches + 1 }
        : { path, args: argsStr, lastUsed: Date.now(), launches: 1 };
      const next = [updated, ...prev.filter((h) => h.path !== path)].slice(0, 30);
      saveHistory(next);
      return next;
    });
  }, []);

  /** 核心动作:启动 + 保护 */
  const launchAndProtect = useCallback(
    async (path: string, argsStr: string) => {
      const name = path.split(/[\\/]/).pop() ?? path;
      setBusy(true);
      try {
        const pid = await systemIpc.launchProcess(path, argsStr);
        await new Promise((r) => setTimeout(r, 1000));
        const alive = await systemIpc.processAlive(pid);
        if (!alive) {
          toast.error(`PID ${pid} 已退出,可能启动失败或瞬间崩溃`);
          return;
        }
        await debuggerIpc.add(pid, name, privilege, protectKill, hideList);
        setProtectedList((prev) => [
          ...prev,
          { pid, processName: name, imagePath: path, startedByUs: true, startedAt: Date.now() },
        ]);
        upsertHistory(path, argsStr);
        toast.success(`已启动 ${name}(PID ${pid})并纳入保护`);
      } catch (e: unknown) {
        const msg = (e as { message?: string })?.message ?? String(e);
        toast.error(`操作失败: ${msg}`);
      } finally {
        setBusy(false);
      }
    },
    [privilege, protectKill, hideList, upsertHistory]
  );

  async function onLaunchClick() {
    if (!exePath) {
      toast.error("请选择 / 拖入 exe");
      return;
    }
    await launchAndProtect(exePath, args);
  }

  async function protectRunning() {
    if (!running) {
      toast.error("请先在列表中选择进程");
      return;
    }
    if (selfPid !== null && running.pid === selfPid) {
      toast.error("本程序已由安全工具自动保护,无需也不能在此手动注册");
      return;
    }
    setBusy(true);
    try {
      await debuggerIpc.add(running.pid, running.name, privilege, protectKill, hideList);
      setProtectedList((prev) =>
        prev.some((e) => e.pid === running.pid)
          ? prev
          : [
              ...prev,
              {
                pid: running.pid,
                processName: running.name,
                imagePath: running.path,
                startedByUs: false,
                startedAt: Date.now(),
              },
            ]
      );
      toast.success(`PID ${running.pid} 已纳入保护`);
    } catch (e: unknown) {
      const msg = (e as { message?: string })?.message ?? String(e);
      toast.error(`保护失败: ${msg}`);
    } finally {
      setBusy(false);
    }
  }

  async function onRemoveProtected(target: number) {
    if (selfPid !== null && target === selfPid) {
      toast.error("不能移除本程序的自我保护");
      return;
    }
    setBusy(true);
    try {
      await debuggerIpc.remove(target);
      setProtectedList((prev) => prev.filter((e) => e.pid !== target));
      toast.success(`PID ${target} 已移除保护`);
    } catch (e: unknown) {
      const msg = (e as { message?: string })?.message ?? String(e);
      toast.error(`移除失败: ${msg}`);
    } finally {
      setBusy(false);
    }
  }

  function removeHistory(path: string) {
    setHistory((prev) => {
      const next = prev.filter((h) => h.path !== path);
      saveHistory(next);
      return next;
    });
  }

  function clearHistory() {
    setHistory([]);
    saveHistory([]);
    toast.success("历史已清空");
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="调试器保护"
      />

      {/* 自我保护状态 — 不可关闭 */}
      <Card className={cn("border", selfProtected ? "border-success/40 bg-success/5" : "border-warning/40 bg-warning/5")}>
        <CardContent className="flex items-center gap-3 p-3 text-sm">
          <ShieldCheck className={cn("h-4 w-4 shrink-0", selfProtected ? "text-success" : "text-warning")} />
          <div className="flex-1">
            {selfProtected ? (
              <>
                <span className="font-medium">自我保护已激活</span>
                <span className="ml-2 font-mono text-muted-foreground">PID {selfPid ?? "?"}</span>
              </>
            ) : (
              <>
                <span className="font-medium">自我保护未激活</span>
              </>
            )}
          </div>
        </CardContent>
      </Card>

      {/* 保护选项 */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base">保护选项</CardTitle>
        </CardHeader>
        <CardContent className="flex flex-wrap gap-x-6 gap-y-2">
          <CheckboxRow id="opt-priv" checked={privilege} onChange={setPrivilege} label="授予 SeDebugPrivilege" />
          <CheckboxRow id="opt-kill" checked={protectKill} onChange={setProtectKill} label="阻止其他进程终结" />
          <CheckboxRow id="opt-hide" checked={hideList} onChange={setHideList} label="从用户态枚举隐藏" />
        </CardContent>
      </Card>

      <div className="grid gap-6 lg:grid-cols-2">
        {/* 启动并保护 */}
        <Card className="card-hover border-primary/20">
          <CardHeader className="pb-3">
            <CardTitle className="flex items-center gap-2 text-base">
              <Play className="h-4 w-4 text-primary" /> 启动并保护
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {/* 拖拽区 */}
            <div
              className={cn(
                "relative rounded-lg border-2 border-dashed bg-card/40 p-4 transition-all",
                dragHover ? "border-primary bg-primary/10" : "border-border"
              )}
            >
              <div className="flex flex-col items-center gap-2 py-2 text-center">
                <Inbox className={cn("h-7 w-7", dragHover ? "text-primary" : "text-muted-foreground")} />
                <div className="text-sm">
                  {dragHover ? (
                    <span className="font-medium text-primary">释放以拖入 .exe</span>
                  ) : (
                    <span className="text-muted-foreground">将 .exe 拖到这里,或下方手动选择</span>
                  )}
                </div>
              </div>
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="dbg-exe">可执行文件</Label>
              <div className="flex gap-2">
                <Input
                  id="dbg-exe"
                  value={exePath}
                  onChange={(e) => setExePath(e.target.value)}
                  placeholder=".exe 路径"
                />
                <Button variant="outline" onClick={pickExe} disabled={busy}>
                  <FolderOpen className="h-4 w-4" /> 浏览
                </Button>
              </div>
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="dbg-args">启动参数(可选)</Label>
              <Input
                id="dbg-args"
                value={args}
                onChange={(e) => setArgs(e.target.value)}
                placeholder='--debug "C:\game.exe"'
              />
            </div>

            <Button onClick={onLaunchClick} disabled={busy || !exePath} className="w-full">
              {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}
              {busy ? "启动中..." : "启动并保护"}
            </Button>
          </CardContent>
        </Card>

        {/* 保护已运行 */}
        <Card className="card-hover">
          <CardHeader className="pb-3">
            <CardTitle className="flex items-center gap-2 text-base">
              <Plus className="h-4 w-4" /> 保护已运行进程
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="space-y-1.5">
              <Label>选择进程</Label>
              <ProcessPicker value={running} onChange={setRunning} disabled={busy} />
            </div>
            <Button onClick={protectRunning} disabled={busy || !running} variant="outline" className="w-full">
              {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Shield className="h-4 w-4" />}
              纳入保护
            </Button>
          </CardContent>
        </Card>
      </div>

      {/* 历史记录列表 */}
      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-3">
          <div>
            <CardTitle className="text-base">历史记录 · {history.length}</CardTitle>
          </div>
          {history.length > 0 && (
            <Button variant="ghost" size="sm" onClick={clearHistory}>
              <Trash2 className="h-3.5 w-3.5" /> 清空
            </Button>
          )}
        </CardHeader>
        <CardContent>
          {history.length === 0 ? (
            <div className="py-8 text-center text-sm text-muted-foreground">
              暂无历史。首次启动后会自动记录,方便下次一键复用。
            </div>
          ) : (
            <div className="divide-y divide-border/60 overflow-hidden rounded-md border">
              {history.map((h) => {
                const name = h.path.split(/[\\/]/).pop() ?? h.path;
                return (
                  <div
                    key={h.path}
                    className="group flex items-center gap-3 px-3 py-2.5 transition-colors hover:bg-accent/40"
                    onDoubleClick={() => void launchAndProtect(h.path, h.args)}
                  >
                    <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-md bg-primary/10 text-primary">
                      <Play className="h-3.5 w-3.5" />
                    </div>
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2 text-sm font-medium">
                        <span className="truncate">{name}</span>
                        <span className="pill pill-muted">×{h.launches}</span>
                      </div>
                      <div className="truncate text-xs text-muted-foreground" title={h.path}>
                        {h.path}
                        {h.args && <span className="ml-2 text-primary/80">{h.args}</span>}
                      </div>
                    </div>
                    <div className="flex shrink-0 gap-1">
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() => {
                          setExePath(h.path);
                          setArgs(h.args);
                        }}
                        title="填入上方表单"
                      >
                        填入
                      </Button>
                      <Button
                        size="sm"
                        disabled={busy}
                        onClick={() => void launchAndProtect(h.path, h.args)}
                      >
                        <Play className="h-3.5 w-3.5" /> 启动
                      </Button>
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() => removeHistory(h.path)}
                        aria-label="删除"
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                      </Button>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </CardContent>
      </Card>

      {/* 当前已保护列表 */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base">受保护进程 · {protectedList.length}</CardTitle>
        </CardHeader>
        <CardContent>
          {protectedList.length === 0 ? (
            <div className="py-8 text-center text-sm text-muted-foreground">暂无保护中的进程</div>
          ) : (
            <div className="space-y-2">
              {protectedList.map((e) => (
                <div
                  key={e.pid}
                  className="flex items-center justify-between rounded-md border bg-card/40 px-3 py-2"
                >
                  <div className="flex min-w-0 items-center gap-3">
                    <Shield className="h-4 w-4 shrink-0 text-success" />
                    <div className="min-w-0">
                      <div className="flex items-center gap-2 text-sm font-medium">
                        <span className="font-mono">{e.pid}</span>
                        <span>{e.processName}</span>
                        {e.startedByUs && <span className="pill pill-primary">本程序启动</span>}
                      </div>
                      <div className="truncate text-xs text-muted-foreground" title={e.imagePath}>
                        {e.imagePath || "—"}
                      </div>
                    </div>
                  </div>
                  <Button size="sm" variant="ghost" disabled={busy} onClick={() => onRemoveProtected(e.pid)}>
                    <ShieldOff className="h-4 w-4" /> 移除
                  </Button>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function CheckboxRow({
  id,
  checked,
  onChange,
  label,
}: {
  id: string;
  checked: boolean;
  onChange: (v: boolean) => void;
  label: string;
}) {
  return (
    <div className="flex items-center gap-2">
      <Checkbox id={id} checked={checked} onCheckedChange={(v) => onChange(Boolean(v))} />
      <Label htmlFor={id} className="cursor-pointer text-sm font-normal">
        {label}
      </Label>
    </div>
  );
}
