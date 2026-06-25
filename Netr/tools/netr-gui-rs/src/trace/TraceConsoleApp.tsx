import { useEffect, useMemo, useRef, useState } from "react";
import {
  Pause, Play, Trash2, Copy, Download, Search, X, ChevronDown, ChevronRight,
} from "lucide-react";
import { toast } from "sonner";
import { useDbgEvt, type DbgEvtView } from "@/store/dbgevtStore";
import { cn } from "@/lib/utils";

// 业务事件 cat (HV_DBGEVT_CAT_*, 1-9) — driver 早期 hand-coded HvDbgEvtPost
const BIZ_CATS: Record<number, { short: string; label: string }> = {
  1: { short: "ADD_DBG",    label: "添加调试器" },
  2: { short: "RM_DBG",     label: "移除调试器" },
  3: { short: "OPEN_PROC",  label: "OpenProcess" },
  4: { short: "READ",       label: "内存读" },
  5: { short: "WRITE",      label: "内存写" },
  6: { short: "AAD",        label: "反反调试" },
  7: { short: "HWBP_HIT",   label: "硬断命中" },
  8: { short: "BREAK_HIT",  label: "软断/单步" },
  9: { short: "DBG_OP",     label: "调试器操作" },
};
// Trace cat (HV_TRACE_CAT_*, 100-199) — P122 driver-wide DbgPrint
const TRACE_CATS: Record<number, { short: string; label: string }> = {
  100: { short: "VM",       label: "VMX/SVM 生命周期" },
  101: { short: "HOOK",     label: "Syscall Hook" },
  102: { short: "EPT",      label: "EPT" },
  103: { short: "NPT",      label: "NPT (AMD)" },
  104: { short: "PHYS",     label: "物理直通" },
  105: { short: "VMEXIT",   label: "VMExit dispatch" },
  106: { short: "INJECT",   label: "DLL 注入" },
  107: { short: "NETWORK",  label: "网络 hook" },
  108: { short: "NESTED",   label: "嵌套虚拟化" },
  109: { short: "CLOAK",    label: "EPT Cloak" },
  110: { short: "DEBUG",    label: "断点/调试" },
  111: { short: "DRIVER",   label: "Driver/IOCTL" },
  112: { short: "INPUT",    label: "输入注入" },
  113: { short: "REGISTRY", label: "注册表 hook" },
  114: { short: "VTROOT",   label: "VT Root" },
  115: { short: "UTIL",     label: "工具/通用" },
  116: { short: "USB",      label: "USB/xHCI" },
  199: { short: "GENERIC",  label: "未分类" },
};
const ALL_CATS = { ...BIZ_CATS, ...TRACE_CATS };

const SEV: Record<number, { label: string; cls: string }> = {
  0: { label: "INFO",  cls: "text-muted-foreground" },
  1: { label: "WARN",  cls: "text-amber-400" },
  2: { label: "ERROR", cls: "text-red-400" },
  3: { label: "FATAL", cls: "text-red-500 font-semibold" },
};

interface CatGroup { name: string; keys: number[] }
const GROUPS: CatGroup[] = [
  { name: "业务事件",       keys: Object.keys(BIZ_CATS).map(Number) },
  { name: "Trace - 核心",   keys: [100, 101, 105, 110, 111] },
  { name: "Trace - 内存",   keys: [102, 103, 104, 109] },
  { name: "Trace - 调试器", keys: [106, 113, 112, 116] },
  { name: "Trace - 其他",   keys: [107, 108, 114, 115, 199] },
];

function formatEvent(e: DbgEvtView): string {
  const cat = ALL_CATS[e.category] ?? { short: `C${e.category}` };
  const sev = SEV[e.severity] ?? { label: `S${e.severity}` };
  const pids = e.caller_pid || e.target_pid
    ? `${e.caller_pid || "-"}→${e.target_pid || "-"} `
    : "";
  return `#${e.sequence} [${sev.label}] ${cat.short.padEnd(8)} ${pids}${e.detail}`;
}

export function TraceConsoleApp() {
  const events = useDbgEvt((s) => s.events);
  const start = useDbgEvt((s) => s.start);
  const stop = useDbgEvt((s) => s.stop);
  const clear = useDbgEvt((s) => s.clear);

  const [paused, setPaused] = useState(false);
  const [autoScroll, setAutoScroll] = useState(true);
  // P122: 默认隐藏高频业务事件 (OpenProcess/Read/Write/DBG_OP), 保留有信息量的 trace 类
  // 用户想看 R3 调用流水自己勾上.
  const NOISY_DEFAULT_OFF = new Set([3, 4, 5, 9]);  // OPEN_PROC / READ / WRITE / DBG_OP
  const [enabledCats, setEnabledCats] = useState<Set<number>>(
    () => new Set(Object.keys(ALL_CATS).map(Number).filter((k) => !NOISY_DEFAULT_OFF.has(k)))
  );
  // 默认显示 INFO+WARN+ERROR (隐 FATAL=3 极少)
  const [enabledSev, setEnabledSev] = useState<Set<number>>(() => new Set([0, 1, 2, 3]));
  const [search, setSearch] = useState("");
  const [pidFilter, setPidFilter] = useState("");
  const [collapsedGroups, setCollapsedGroups] = useState<Set<string>>(new Set());

  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (paused) {
      stop();
      return;
    }
    void start();
    return () => stop();
  }, [paused, start, stop]);

  const view = useMemo(() => {
    const pidNum = pidFilter ? Number(pidFilter) : 0;
    const q = search.toLowerCase();
    return events.filter((e) => {
      if (!enabledCats.has(e.category)) return false;
      if (!enabledSev.has(e.severity)) return false;
      if (pidNum && e.caller_pid !== pidNum && e.target_pid !== pidNum) return false;
      if (q && !e.detail.toLowerCase().includes(q)) return false;
      return true;
    });
  }, [events, enabledCats, enabledSev, search, pidFilter]);

  useEffect(() => {
    if (!autoScroll) return;
    const el = scrollRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [view, autoScroll]);

  const toggleCat = (cat: number) => {
    setEnabledCats((prev) => {
      const next = new Set(prev);
      if (next.has(cat)) next.delete(cat);
      else next.add(cat);
      return next;
    });
  };
  const toggleSev = (sev: number) => {
    setEnabledSev((prev) => {
      const next = new Set(prev);
      if (next.has(sev)) next.delete(sev);
      else next.add(sev);
      return next;
    });
  };
  const toggleAllInGroup = (g: CatGroup, on: boolean) => {
    setEnabledCats((prev) => {
      const next = new Set(prev);
      g.keys.forEach((k) => (on ? next.add(k) : next.delete(k)));
      return next;
    });
  };
  const toggleGroupCollapse = (name: string) => {
    setCollapsedGroups((prev) => {
      const next = new Set(prev);
      if (next.has(name)) next.delete(name);
      else next.add(name);
      return next;
    });
  };

  const copyAll = async () => {
    const text = view.map(formatEvent).join("\n");
    try {
      await navigator.clipboard.writeText(text);
      toast.success(`已复制 ${view.length} 条到剪贴板`);
    } catch (e) {
      toast.error(`复制失败: ${String(e)}`);
    }
  };
  const copyVisible = copyAll;   // alias

  const exportLog = async () => {
    const text = view.map(formatEvent).join("\n");
    const blob = new Blob([text], { type: "text/plain;charset=utf-8" });
    const ts = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `guardmeta-trace-${ts}.log`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    toast.success(`已导出 ${view.length} 条`);
  };

  return (
    <div className="flex h-screen flex-col bg-background text-foreground">
      {/* 标题栏 */}
      <div className="flex h-9 shrink-0 items-center gap-2 border-b border-border bg-card/60 px-3" data-tauri-drag-region>
        <span className="text-xs font-semibold">驱动 Trace 控制台</span>
        <span className="text-[10px] text-muted-foreground">
          ({view.length} / {events.length}{events.length >= 8000 ? " 上限" : ""})
        </span>
      </div>

      {/* 工具条 */}
      <div className="flex h-9 shrink-0 items-center gap-1 border-b border-border bg-card/40 px-2 text-[11px]">
        <button
          type="button"
          onClick={() => setPaused((v) => !v)}
          className={cn(
            "flex h-7 items-center gap-1 rounded px-2 text-[11px] transition-colors",
            paused ? "bg-amber-500/15 text-amber-300" : "hover:bg-accent"
          )}
        >
          {paused ? <Play className="h-3 w-3" /> : <Pause className="h-3 w-3" />}
          {paused ? "继续" : "暂停"}
        </button>
        <button
          type="button"
          onClick={clear}
          className="flex h-7 items-center gap-1 rounded px-2 hover:bg-accent"
        >
          <Trash2 className="h-3 w-3" /> 清空
        </button>
        <button
          type="button"
          onClick={() => setAutoScroll((v) => !v)}
          className={cn(
            "flex h-7 items-center gap-1 rounded px-2",
            autoScroll ? "bg-primary/15 text-primary" : "text-muted-foreground hover:bg-accent"
          )}
        >
          自动滚动
        </button>

        <div className="mx-1 h-5 w-px bg-border" />

        <button
          type="button"
          onClick={copyVisible}
          className="flex h-7 items-center gap-1 rounded px-2 hover:bg-accent"
          title="复制当前过滤后的全部"
        >
          <Copy className="h-3 w-3" /> 复制
        </button>
        <button
          type="button"
          onClick={exportLog}
          className="flex h-7 items-center gap-1 rounded px-2 hover:bg-accent"
        >
          <Download className="h-3 w-3" /> 导出
        </button>

        <div className="mx-1 h-5 w-px bg-border" />

        <div className="flex items-center gap-1">
          {Object.entries(SEV).map(([k, v]) => {
            const sev = Number(k);
            const on = enabledSev.has(sev);
            return (
              <button
                key={k}
                type="button"
                onClick={() => toggleSev(sev)}
                className={cn(
                  "flex h-6 items-center rounded px-1.5 text-[10px] transition-colors",
                  on ? `${v.cls} bg-accent/30` : "text-muted-foreground/40 line-through"
                )}
              >
                {v.label}
              </button>
            );
          })}
        </div>

        <div className="mx-1 h-5 w-px bg-border" />

        <div className="relative flex items-center">
          <Search className="absolute left-1.5 h-3 w-3 text-muted-foreground" />
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="搜索 detail..."
            className="h-7 w-56 rounded border border-border bg-background pl-6 pr-2 text-[11px] outline-none focus:border-primary"
          />
          {search && (
            <button
              type="button"
              onClick={() => setSearch("")}
              className="absolute right-1 text-muted-foreground hover:text-foreground"
            >
              <X className="h-3 w-3" />
            </button>
          )}
        </div>

        <input
          value={pidFilter}
          onChange={(e) => setPidFilter(e.target.value.replace(/[^0-9]/g, ""))}
          placeholder="PID"
          className="h-7 w-16 rounded border border-border bg-background px-1.5 text-[11px] outline-none focus:border-primary"
        />
      </div>

      {/* 主体 */}
      <div className="flex min-h-0 flex-1">
        {/* 左侧 cat 多选 */}
        <div className="flex w-56 shrink-0 flex-col overflow-y-auto border-r border-border bg-card/20 text-[11px]">
          {GROUPS.map((g) => {
            const collapsed = collapsedGroups.has(g.name);
            const allOn = g.keys.every((k) => enabledCats.has(k));
            const someOn = g.keys.some((k) => enabledCats.has(k));
            return (
              <div key={g.name} className="border-b border-border/50">
                <div className="flex items-center gap-1 px-1.5 py-1 hover:bg-accent/30">
                  <button
                    type="button"
                    onClick={() => toggleGroupCollapse(g.name)}
                    className="flex h-4 w-4 items-center justify-center text-muted-foreground hover:text-foreground"
                  >
                    {collapsed ? <ChevronRight className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />}
                  </button>
                  <span className="flex-1 truncate font-medium text-muted-foreground">{g.name}</span>
                  <button
                    type="button"
                    onClick={() => toggleAllInGroup(g, !allOn)}
                    className={cn(
                      "rounded px-1 text-[9px]",
                      allOn ? "bg-primary/20 text-primary" : someOn ? "text-amber-400" : "text-muted-foreground"
                    )}
                    title={allOn ? "全关" : "全开"}
                  >
                    {allOn ? "全" : someOn ? "半" : "空"}
                  </button>
                </div>
                {!collapsed && (
                  <div className="px-2 pb-1">
                    {g.keys.map((cat) => {
                      const info = ALL_CATS[cat];
                      if (!info) return null;
                      const on = enabledCats.has(cat);
                      const count = events.filter((e) => e.category === cat).length;
                      return (
                        <label
                          key={cat}
                          className={cn(
                            "flex cursor-pointer items-center gap-1.5 rounded px-1 py-0.5 text-[10.5px]",
                            on ? "text-foreground" : "text-muted-foreground/50"
                          )}
                        >
                          <input
                            type="checkbox"
                            checked={on}
                            onChange={() => toggleCat(cat)}
                            className="h-3 w-3"
                          />
                          <span className="font-mono w-14 truncate">{info.short}</span>
                          <span className="flex-1 truncate">{info.label}</span>
                          {count > 0 && (
                            <span className="ml-auto shrink-0 text-[9px] text-muted-foreground/60">
                              {count}
                            </span>
                          )}
                        </label>
                      );
                    })}
                  </div>
                )}
              </div>
            );
          })}
        </div>

        {/* 事件列表 */}
        <div
          ref={scrollRef}
          className="min-w-0 flex-1 overflow-auto font-mono text-[10.5px] leading-tight"
        >
          {view.length === 0 ? (
            <div className="flex h-full items-center justify-center text-muted-foreground">
              {paused ? "已暂停" : "等待 driver 事件..."}
            </div>
          ) : (
            <table className="w-full border-collapse">
              <thead className="sticky top-0 z-10 bg-card/95 backdrop-blur">
                <tr className="border-b border-border text-[10px] text-muted-foreground">
                  <th className="px-2 py-1 text-left font-normal">#</th>
                  <th className="px-2 py-1 text-left font-normal">SEV</th>
                  <th className="px-2 py-1 text-left font-normal">CAT</th>
                  <th className="px-2 py-1 text-left font-normal">PID</th>
                  <th className="px-2 py-1 text-left font-normal">Detail</th>
                </tr>
              </thead>
              <tbody>
                {view.map((e) => {
                  const sev = SEV[e.severity] ?? { label: `S${e.severity}`, cls: "" };
                  const cat = ALL_CATS[e.category] ?? { short: `C${e.category}` };
                  return (
                    <tr
                      key={e.sequence}
                      className="border-b border-border/30 hover:bg-accent/20"
                    >
                      <td className="px-2 py-0.5 text-muted-foreground/60">{e.sequence}</td>
                      <td className={cn("px-2 py-0.5", sev.cls)}>{sev.label}</td>
                      <td className="px-2 py-0.5 text-muted-foreground">{cat.short}</td>
                      <td className="px-2 py-0.5 text-muted-foreground/70">
                        {e.caller_pid || e.target_pid
                          ? `${e.caller_pid || "-"}→${e.target_pid || "-"}`
                          : ""}
                      </td>
                      <td className="px-2 py-0.5 text-foreground/90 break-all">{e.detail}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  );
}
