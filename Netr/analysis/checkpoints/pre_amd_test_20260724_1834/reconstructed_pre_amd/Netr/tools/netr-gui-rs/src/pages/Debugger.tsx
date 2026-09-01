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
  ShieldCheck,
  ShieldAlert,
  RefreshCw,
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
import {
  antiVmpIpc,
  debuggerIpc,
  systemIpc,
  type AntiVmpConfig,
  type AntiVmpStatus,
  type ProcessInfo,
} from "@/ipc";
import {
  AUTO_REGISTER_GUI_WITH_DRIVER,
  useDriver,
  selfPidPromise,
} from "@/store/driverStore";
import { cn } from "@/lib/utils";

interface ProtectedEntry {
  pid: number;
  processName: string;
  imagePath: string;
  startedByUs: boolean;
  startedAt: number;
  bridgeInjected: boolean;
  architecture: string;
}

interface HistoryEntry {
  path: string;
  args: string;
  lastUsed: number;
  /** 累计启动次数 */
  launches: number;
}

const HISTORY_KEY = "netr-debugger-history";
const SYMBOL_CACHE_KEY = "netr-debugger-symbol-cache";

const DEFAULT_ANTIVMP_CONFIG: AntiVmpConfig = {
  process_debug_query: true,
  kernel_debug_query: true,
  thread_hide: true,
  invalid_handle: true,
  debug_object: true,
  debug_registers: true,
  system_debug_control: true,
};

const ANTIVMP_FEATURES: Array<{
  key: keyof AntiVmpConfig;
  mask: number;
  label: string;
  description: string;
}> = [
  {
    key: "process_debug_query",
    mask: 1 << 0,
    label: "进程调试状态",
    description: "隐藏 DebugPort / DebugObjectHandle / DebugFlags",
  },
  {
    key: "kernel_debug_query",
    mask: 1 << 1,
    label: "内核调试器状态",
    description: "伪装 SystemKernelDebuggerInformation / Ex",
  },
  {
    key: "thread_hide",
    mask: 1 << 2,
    label: "线程隐藏检测",
    description: "吞掉 HideFromDebugger，并把查询结果伪装为已隐藏",
  },
  {
    key: "invalid_handle",
    mask: 1 << 3,
    label: "无效句柄陷阱",
    description: "短路 NtClose 异常，并过滤 DUPLICATE_CLOSE_SOURCE",
  },
  {
    key: "debug_object",
    mask: 1 << 4,
    label: "DebugObject 枚举",
    description: "清除 ObjectAllTypesInformation 中的调试对象统计",
  },
  {
    key: "debug_registers",
    mask: 1 << 5,
    label: "调试寄存器",
    description: "目标自查 DR0–DR7 时返回虚拟零值",
  },
  {
    key: "system_debug_control",
    mask: 1 << 6,
    label: "系统调试控制",
    description: "对探测命令返回 STATUS_DEBUGGER_INACTIVE",
  },
];

function antiVmpConfigFromMask(mask: number): AntiVmpConfig {
  return {
    process_debug_query: (mask & (1 << 0)) !== 0,
    kernel_debug_query: (mask & (1 << 1)) !== 0,
    thread_hide: (mask & (1 << 2)) !== 0,
    invalid_handle: (mask & (1 << 3)) !== 0,
    debug_object: (mask & (1 << 4)) !== 0,
    debug_registers: (mask & (1 << 5)) !== 0,
    system_debug_control: (mask & (1 << 6)) !== 0,
  };
}

function bitCount(value: number) {
  let count = 0;
  for (let bits = value >>> 0; bits !== 0; bits &= bits - 1) count += 1;
  return count;
}

function isMissingProtectedEntryError(message: string) {
  const normalized = message.toLowerCase();
  return (
    normalized.includes("元素不存在") ||
    normalized.includes("not found") ||
    normalized.includes("0xc0000225") ||
    normalized.includes("error_not_found")
  );
}

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
  const [antiVmpConfig, setAntiVmpConfig] = useState<AntiVmpConfig>(DEFAULT_ANTIVMP_CONFIG);
  const [antiVmpStatus, setAntiVmpStatus] = useState<AntiVmpStatus | null>(null);
  const [antiVmpBusy, setAntiVmpBusy] = useState(false);
  const [privateDebugObjectBusy, setPrivateDebugObjectBusy] = useState(false);
  const [symbolCacheBusy, setSymbolCacheBusy] = useState(false);
  const [symbolCachePath, setSymbolCachePath] = useState("");
  const [antiVmpError, setAntiVmpError] = useState("");

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

  async function pickSymbolCache() {
    const selected = await openDialog({ directory: true, multiple: false });
    if (typeof selected !== "string") return;
    setSymbolCacheBusy(true);
    try {
      const applied = await antiVmpIpc.setSymbolCache(selected);
      const path = applied ?? selected;
      setSymbolCachePath(path);
      window.localStorage.setItem(SYMBOL_CACHE_KEY, path);
      toast.success(`符号下载目录已设置为 ${path}`);
    } catch (error: unknown) {
      const message = (error as { message?: string })?.message ?? String(error);
      toast.error(`符号目录设置失败: ${message}`);
    } finally {
      setSymbolCacheBusy(false);
    }
  }

  async function resetSymbolCache() {
    setSymbolCacheBusy(true);
    try {
      await antiVmpIpc.setSymbolCache(null);
      setSymbolCachePath("");
      window.localStorage.removeItem(SYMBOL_CACHE_KEY);
      toast.success("符号目录已恢复自动选择 E → D → C");
    } finally {
      setSymbolCacheBusy(false);
    }
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

  const acceptAntiVmpStatus = useCallback((status: AntiVmpStatus) => {
    setAntiVmpStatus(status);
    setAntiVmpError("");
    if (status.configured_mask !== 0) {
      setAntiVmpConfig(antiVmpConfigFromMask(status.configured_mask));
    }
  }, []);

  const refreshAntiVmp = useCallback(
    async (notify = false) => {
      try {
        acceptAntiVmpStatus(await antiVmpIpc.status());
      } catch (error: unknown) {
        const message = (error as { message?: string })?.message ?? String(error);
        setAntiVmpError(message);
        if (notify) toast.error(`AntiVMP 状态刷新失败: ${message}`);
      }
    },
    [acceptAntiVmpStatus]
  );

  useEffect(() => {
    void refreshAntiVmp(false);
  }, [refreshAntiVmp]);

  useEffect(() => {
    const saved = window.localStorage.getItem(SYMBOL_CACHE_KEY);
    if (!saved) return;
    setSymbolCachePath(saved);
    void antiVmpIpc.setSymbolCache(saved).catch(() => undefined);
  }, []);

  useEffect(() => {
    if (protectedList.length === 0) return;

    let cancelled = false;
    let checking = false;

    const syncExitedProcesses = async () => {
      if (checking) return;
      checking = true;
      try {
        const states = await Promise.all(
          protectedList.map(async (entry) => {
            try {
              return [entry.pid, await systemIpc.processAlive(entry.pid)] as const;
            } catch {
              return [entry.pid, true] as const;
            }
          })
        );
        if (cancelled) return;

        const exited = new Set(states.filter(([, alive]) => !alive).map(([pid]) => pid));
        if (exited.size === 0) return;

        setProtectedList((current) => current.filter((entry) => !exited.has(entry.pid)));
        void refreshAntiVmp(false);
      } finally {
        checking = false;
      }
    };

    void syncExitedProcesses();
    const timer = window.setInterval(() => void syncExitedProcesses(), 1500);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [protectedList, refreshAntiVmp]);

  const applyAntiVmp = useCallback(
    async (enabled: boolean) => {
      setAntiVmpBusy(true);
      try {
        const status = await antiVmpIpc.apply(enabled, antiVmpConfig);
        acceptAntiVmpStatus(status);
        const installed = bitCount(status.installed_mask & status.configured_mask);
        const configured = bitCount(status.configured_mask);
        toast.success(
          enabled
            ? `AntiVMP 已启用 · ${installed}/${configured} 组过滤已安装`
            : "AntiVMP 扩展过滤已关闭"
        );
      } catch (error: unknown) {
        const message = (error as { message?: string })?.message ?? String(error);
        setAntiVmpError(message);
        toast.error(`AntiVMP 配置失败: ${message}`);
      } finally {
        setAntiVmpBusy(false);
      }
    },
    [acceptAntiVmpStatus, antiVmpConfig]
  );

  const applyPrivateDebugObject = useCallback(
    async (enabled: boolean) => {
      setPrivateDebugObjectBusy(true);
      try {
        const status = await antiVmpIpc.setPrivateDebugObject(enabled);
        acceptAntiVmpStatus(status);
        toast.success(
          enabled
            ? "VT 自建 DebugObject 已启用，内置与外部调试器统一生效"
            : "VT 自建 DebugObject 已关闭，调试会话回退原生通道"
        );
      } catch (error: unknown) {
        const message = (error as { message?: string })?.message ?? String(error);
        setAntiVmpError(message);
        toast.error(`VT 自建 DebugObject 配置失败: ${message}`);
      } finally {
        setPrivateDebugObjectBusy(false);
      }
    },
    [acceptAntiVmpStatus]
  );

  /** 核心动作:启动 + 保护 */
  const launchAndProtect = useCallback(
    async (path: string, argsStr: string) => {
      const name = path.split(/[\\/]/).pop() ?? path;
      setBusy(true);
      try {
        const bridge = await debuggerIpc.launchWithBridge(
          path,
          argsStr,
          privilege,
          protectKill,
          hideList
        );
        const pid = bridge.pid;
        setProtectedList((prev) => [
          ...prev,
          {
            pid,
            processName: name,
            imagePath: path,
            startedByUs: true,
            startedAt: Date.now(),
            bridgeInjected: true,
            architecture: bridge.architecture,
          },
        ]);
        upsertHistory(path, argsStr);
        toast.success(`已启动 ${name}(PID ${pid})并纳入保护`);
        void refreshAntiVmp(false);
      } catch (e: unknown) {
        const msg = (e as { message?: string })?.message ?? String(e);
        toast.error(`操作失败: ${msg}`);
      } finally {
        setBusy(false);
      }
    },
    [privilege, protectKill, hideList, refreshAntiVmp, upsertHistory]
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
      toast.error("当前控制程序不能作为调试器保护目标，请选择实际调试器进程");
      return;
    }
    setBusy(true);
    try {
      const bridge = await debuggerIpc.injectBridge(
        running.pid,
        running.name,
        privilege,
        protectKill,
        hideList
      );
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
                bridgeInjected: true,
                architecture: bridge.architecture,
              },
            ]
      );
      toast.success(`PID ${running.pid} 已纳入保护`);
      void refreshAntiVmp(false);
    } catch (e: unknown) {
      const msg = (e as { message?: string })?.message ?? String(e);
      toast.error(`保护失败: ${msg}`);
    } finally {
      setBusy(false);
    }
  }

  async function onRemoveProtected(target: number) {
    if (selfPid !== null && target === selfPid) {
      toast.error("不能从这里移除当前控制程序");
      return;
    }
    setBusy(true);
    try {
      const alive = await systemIpc.processAlive(target).catch(() => true);
      if (!alive) {
        setProtectedList((prev) => prev.filter((e) => e.pid !== target));
        toast.success(`PID ${target} 已退出，界面记录已清理`);
        void refreshAntiVmp(false);
        return;
      }

      await debuggerIpc.remove(target);
      setProtectedList((prev) => prev.filter((e) => e.pid !== target));
      toast.success(`PID ${target} 已移除保护`);
      void refreshAntiVmp(false);
    } catch (e: unknown) {
      const msg = (e as { message?: string })?.message ?? String(e);
      const alive = await systemIpc.processAlive(target).catch(() => true);
      if (!alive || isMissingProtectedEntryError(msg)) {
        setProtectedList((prev) => prev.filter((entry) => entry.pid !== target));
        toast.success(`PID ${target} 的保护记录已清理`);
        void refreshAntiVmp(false);
      } else {
        toast.error(`移除失败: ${msg}`);
      }
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

  const antiVmpEnabled = antiVmpStatus?.enabled ?? false;
  const antiVmpConfiguredCount = bitCount(antiVmpStatus?.configured_mask ?? 0);
  const antiVmpInstalledCount = bitCount(
    (antiVmpStatus?.installed_mask ?? 0) & (antiVmpStatus?.configured_mask ?? 0)
  );

  return (
    <div className="space-y-6">
      <PageHeader
        title="调试器保护"
      />

      {/* 主界面保持被动；实际调试器由 Bridge 按需注册。 */}
      <Card
        className={cn(
          "border",
          selfProtected ? "border-success/40 bg-success/5" : "border-border bg-card/40"
        )}
      >
        <CardContent className="flex items-center gap-3 p-3 text-sm">
          <ShieldCheck
            className={cn(
              "h-4 w-4 shrink-0",
              selfProtected ? "text-success" : "text-muted-foreground"
            )}
          />
          <div className="flex-1">
            {selfProtected ? (
              <>
                <span className="font-medium">自我保护已激活</span>
                <span className="ml-2 font-mono text-muted-foreground">PID {selfPid ?? "?"}</span>
              </>
            ) : (
              <div>
                <span className="font-medium">
                  {AUTO_REGISTER_GUI_WITH_DRIVER ? "主界面保护等待登记" : "主界面采用被动模式"}
                </span>
                <div className="mt-0.5 text-xs text-muted-foreground">
                  选择下方的实际调试器后，Bridge 注入成功会自动向驱动注册并启用对应保护链路。
                </div>
              </div>
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
          <div className="flex items-center gap-2">
            <Checkbox
              id="opt-private-debug-object"
              checked={antiVmpStatus?.private_debug_object_enabled ?? false}
              disabled={privateDebugObjectBusy}
              onCheckedChange={(value) =>
                void applyPrivateDebugObject(Boolean(value))
              }
            />
            <Label
              htmlFor="opt-private-debug-object"
              className="cursor-pointer text-sm font-normal"
              title="仅在 VT 模式下接管私有事件所有权；内置和外部调试器共用同一设置"
            >
              VT 自建 DebugObject
            </Label>
          </div>
          <div className="flex basis-full items-center gap-2 pt-1">
            <Label className="min-w-16 text-xs text-muted-foreground">符号目录</Label>
            <Input
              value={symbolCachePath}
              readOnly
              placeholder="自动搜索 E:\\Symbols、D:\\Symbols、C:\\Symbols"
              className="h-8 min-w-0 flex-1 text-xs"
            />
            <Button
              type="button"
              size="sm"
              variant="outline"
              disabled={symbolCacheBusy}
              onClick={() => void pickSymbolCache()}
            >
              <FolderOpen className="mr-1 h-3.5 w-3.5" />选择
            </Button>
            <Button
              type="button"
              size="sm"
              variant="ghost"
              disabled={symbolCacheBusy || !symbolCachePath}
              onClick={() => void resetSymbolCache()}
            >
              自动
            </Button>
          </div>
        </CardContent>
      </Card>

      <Card
        className={cn(
          "border",
          antiVmpEnabled ? "border-primary/35 bg-primary/[0.03]" : "border-border"
        )}
      >
        <CardHeader className="flex flex-row items-start justify-between space-y-0 pb-3">
          <div className="space-y-1">
            <CardTitle className="flex items-center gap-2 text-base">
              <ShieldAlert className="h-4 w-4 text-primary" /> AntiVMP 反反调试
            </CardTitle>
            <p className="text-xs text-muted-foreground">
              作用域默认跟随 Bridge 已绑定的被调试进程，不对系统其他进程全局改写。
            </p>
          </div>
          <div className="flex items-center gap-2">
            <div className="flex items-center gap-2 rounded-md border px-2.5 py-1.5">
              <Checkbox
                id="antivmp-master"
                checked={antiVmpEnabled}
                disabled={antiVmpBusy}
                onCheckedChange={(value) => void applyAntiVmp(Boolean(value))}
              />
              <Label htmlFor="antivmp-master" className="cursor-pointer text-xs font-medium">
                扩展过滤
              </Label>
            </div>
            <Button
              size="sm"
              variant="ghost"
              disabled={antiVmpBusy}
              onClick={() => void refreshAntiVmp(true)}
              title="刷新驱动中的实际安装状态"
            >
              <RefreshCw className={cn("h-3.5 w-3.5", antiVmpBusy && "animate-spin")} />
            </Button>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex flex-wrap gap-2 text-xs">
            <span className={cn("pill", antiVmpEnabled ? "pill-success" : "pill-muted")}>
              扩展过滤 {antiVmpEnabled ? "ON" : "OFF"}
            </span>
            <span
              className={cn(
                "pill",
                antiVmpEnabled && antiVmpInstalledCount === antiVmpConfiguredCount
                  ? "pill-success"
                  : "pill-muted"
              )}
            >
              已安装 {antiVmpInstalledCount}/{antiVmpConfiguredCount}
            </span>
            <span className="pill pill-muted">
              Bridge 自动 {antiVmpStatus?.bridge_auto_enabled ? "已就绪" : "待注册"}
            </span>
            <span className="pill pill-muted">
              已绑定目标 {antiVmpStatus?.protected_target_count ?? 0}
            </span>
          </div>

          {antiVmpError && (
            <div className="rounded-md border border-destructive/30 bg-destructive/5 px-3 py-2 text-xs text-destructive">
              {antiVmpError}
            </div>
          )}

          <div className="grid gap-2 md:grid-cols-2 xl:grid-cols-3">
            {ANTIVMP_FEATURES.map((feature) => (
              <AntiVmpFeatureRow
                key={feature.key}
                id={`antivmp-${feature.key}`}
                checked={antiVmpConfig[feature.key]}
                installed={Boolean(
                  antiVmpEnabled &&
                    antiVmpStatus &&
                    (antiVmpStatus.installed_mask & feature.mask) !== 0
                )}
                disabled={antiVmpBusy}
                label={feature.label}
                description={feature.description}
                onChange={(checked) =>
                  setAntiVmpConfig((current) => ({
                    ...current,
                    [feature.key]: checked,
                  }))
                }
              />
            ))}
          </div>

          <div className="flex flex-col gap-3 border-t pt-3 sm:flex-row sm:items-center sm:justify-between">
            <div className="flex flex-wrap gap-2 text-[11px] text-muted-foreground">
              <span className="rounded bg-success/10 px-2 py-1 text-success">PEB / Heap 绑定后自动清理</span>
              <span className="rounded bg-success/10 px-2 py-1 text-success">Bridge 目标自动跟随</span>
              <span className="rounded bg-muted px-2 py-1">NtContinue 高风险钩子保持禁用</span>
            </div>
            <Button
              size="sm"
              variant="outline"
              disabled={antiVmpBusy || !antiVmpEnabled}
              onClick={() => void applyAntiVmp(true)}
            >
              {antiVmpBusy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <ShieldCheck className="h-3.5 w-3.5" />}
              应用过滤组合
            </Button>
          </div>
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
                        {e.bridgeInjected && (
                          <span className="pill pill-success">Bridge {e.architecture}</span>
                        )}
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

function AntiVmpFeatureRow({
  id,
  checked,
  installed,
  disabled,
  label,
  description,
  onChange,
}: {
  id: string;
  checked: boolean;
  installed: boolean;
  disabled: boolean;
  label: string;
  description: string;
  onChange: (value: boolean) => void;
}) {
  return (
    <div
      className={cn(
        "flex items-start gap-2 rounded-md border p-3 transition-colors",
        checked ? "border-primary/25 bg-primary/[0.025]" : "border-border/70 bg-card/30"
      )}
    >
      <Checkbox
        id={id}
        checked={checked}
        disabled={disabled}
        onCheckedChange={(value) => onChange(Boolean(value))}
        className="mt-0.5"
      />
      <Label htmlFor={id} className="min-w-0 flex-1 cursor-pointer font-normal">
        <span className="flex items-center justify-between gap-2 text-sm font-medium">
          {label}
          <span
            className={cn(
              "h-1.5 w-1.5 shrink-0 rounded-full",
              installed ? "bg-success shadow-[0_0_6px_hsl(var(--success))]" : "bg-muted-foreground/35"
            )}
            title={installed ? "驱动钩子已安装" : "尚未安装或开关未启用"}
          />
        </span>
        <span className="mt-1 block text-[11px] leading-4 text-muted-foreground">
          {description}
        </span>
      </Label>
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
