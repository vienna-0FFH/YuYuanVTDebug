import { useEffect, useState } from "react";
import { Activity, Cpu, MemoryStick } from "lucide-react";
import { useSession } from "./sessionStore";
import { useDbgEvt } from "@/store/dbgevtStore";
import { dbgIpc, type SymbolInfo } from "./ipc";
import { formatAddress } from "./expr";
import { cn } from "@/lib/utils";

/**
 * 调试器底部状态栏 — 取代频繁 toast 的常驻信息位置。
 * 显示: PID/TID / 当前地址符号 / ctx 是否挂起 / 最近事件类型 计数 / 截断警告
 */
export function DebuggerStatusBar() {
  const { pid, processName, selectedTid, address, ctx } = useSession();
  const events = useDbgEvt((s) => s.events);

  const [sym, setSym] = useState<SymbolInfo | null>(null);
  useEffect(() => {
    let cancelled = false;
    if (!pid || address === 0n) { setSym(null); return; }
    (async () => {
      try {
        const s = await dbgIpc.resolveSymbol(pid, Number(address));
        if (!cancelled) setSym(s ?? null);
      } catch { /* ignore */ }
    })();
    return () => { cancelled = true; };
  }, [pid, address]);

  const lastEvt = events.length > 0 ? events[events.length - 1] : null;
  const errCount = events.filter((e) => e.severity >= 2).length;

  if (!pid) {
    return <div className="h-6 shrink-0 border-t border-border bg-card/60" />;
  }

  return (
    <div className="flex h-6 shrink-0 items-center gap-3 border-t border-border bg-card/60 px-3 text-[10px] tabular-nums">
      <span className="flex items-center gap-1 text-muted-foreground">
        <Cpu className="h-2.5 w-2.5" /> {processName} · PID {pid}
      </span>
      {selectedTid !== null && (
        <span className="text-muted-foreground/80">TID {selectedTid}</span>
      )}
      <span className={cn(
        "rounded px-1.5 py-0.5 text-[9px] font-medium",
        ctx ? "bg-warning/15 text-warning" : "bg-success/15 text-success"
      )}>
        {ctx ? "已挂起" : "运行中"}
      </span>
      <span className="flex items-center gap-1 text-muted-foreground/80">
        <MemoryStick className="h-2.5 w-2.5" />
        <span className="font-mono">{formatAddress(address)}</span>
        {sym && (
          <span className="text-emerald-400/90">
            {sym.module}!{sym.name}{sym.offset > 0 ? `+0x${sym.offset.toString(16)}` : ""}
          </span>
        )}
      </span>

      <span className="ml-auto flex items-center gap-2 text-muted-foreground">
        <Activity className="h-2.5 w-2.5" />
        {events.length}{errCount > 0 && <span className="text-destructive">/{errCount}错</span>}
        {lastEvt && (
          <span className="max-w-[40ch] truncate text-muted-foreground/70" title={lastEvt.detail}>
            {lastEvt.detail}
          </span>
        )}
      </span>
    </div>
  );
}
