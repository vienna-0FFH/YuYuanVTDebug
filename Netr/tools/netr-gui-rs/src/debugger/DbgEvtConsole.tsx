import { useEffect, useState } from "react";
import { ScrollText, Trash2, Pause, Play, Filter } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useDbgEvt } from "@/store/dbgevtStore";
import { useSession } from "./sessionStore";
import { cn } from "@/lib/utils";

const SEV: Record<number, { label: string; cls: string }> = {
  0: { label: "INFO", cls: "text-muted-foreground" },
  1: { label: "WARN", cls: "text-warning" },
  2: { label: "ERROR", cls: "text-destructive" },
  3: { label: "FATAL", cls: "text-destructive font-semibold" },
};
const CAT: Record<number, string> = {
  1: "ADD_DBG",
  2: "RM_DBG",
  3: "OPEN_PROC",
  4: "READ",
  5: "WRITE",
  6: "AAD",
  7: "HWBP",
  8: "BREAK_HIT",
};

export function DbgEvtConsole() {
  const events = useDbgEvt((s) => s.events);
  const start = useDbgEvt((s) => s.start);
  const stop = useDbgEvt((s) => s.stop);
  const clear = useDbgEvt((s) => s.clear);
  const pid = useSession((s) => s.pid);

  const [paused, setPaused] = useState(false);
  const [filterSelf, setFilterSelf] = useState(true);
  const [hideRead, setHideRead] = useState(true);

  useEffect(() => {
    if (paused) {
      stop();
      return;
    }
    void start();
    return () => stop();
  }, [paused, start, stop]);

  let view = events;
  if (filterSelf && pid) {
    view = view.filter((e) => e.caller_pid === pid || e.target_pid === pid);
  }
  if (hideRead) {
    view = view.filter((e) => e.category !== 4); // 4 = READ_MEMORY 噪音多
  }

  return (
    <div className="flex h-full flex-col">
      <div className="flex h-8 shrink-0 items-center gap-1 border-b border-border bg-card/40 px-2 text-[11px]">
        <ScrollText className="h-3 w-3 text-muted-foreground" />
        <span className="font-medium text-muted-foreground">驱动事件</span>
        <span className="text-muted-foreground/50">({view.length}/{events.length})</span>

        <button
          type="button"
          onClick={() => setFilterSelf((v) => !v)}
          className={cn(
            "ml-2 flex h-6 items-center gap-1 rounded px-2 text-[10px] transition-colors",
            filterSelf ? "bg-primary/15 text-primary" : "text-muted-foreground hover:bg-accent"
          )}
        >
          <Filter className="h-2.5 w-2.5" /> 仅本进程
        </button>
        <button
          type="button"
          onClick={() => setHideRead((v) => !v)}
          className={cn(
            "flex h-6 items-center rounded px-2 text-[10px] transition-colors",
            hideRead ? "bg-primary/15 text-primary" : "text-muted-foreground hover:bg-accent"
          )}
        >
          隐藏 READ
        </button>

        <div className="ml-auto flex gap-1">
          <Button size="sm" variant="ghost" className="h-6 w-6 p-0" onClick={() => setPaused((v) => !v)}>
            {paused ? <Play className="h-3 w-3" /> : <Pause className="h-3 w-3" />}
          </Button>
          <Button size="sm" variant="ghost" className="h-6 w-6 p-0" onClick={clear}>
            <Trash2 className="h-3 w-3" />
          </Button>
        </div>
      </div>

      <div className="min-h-0 flex-1 overflow-auto p-1 font-mono text-[10.5px] leading-tight">
        {view.length === 0 ? (
          <div className="flex h-full items-center justify-center text-muted-foreground">
            暂无事件
          </div>
        ) : (
          view.map((e) => {
            const sev = SEV[e.severity] ?? { label: `S${e.severity}`, cls: "" };
            const cat = CAT[e.category] ?? `C${e.category}`;
            return (
              <div key={e.sequence} className="flex items-baseline gap-2 px-1">
                <span className="shrink-0 text-muted-foreground/60">#{e.sequence}</span>
                <span className={cn("shrink-0 w-12", sev.cls)}>[{sev.label}]</span>
                <span className="shrink-0 w-16 text-muted-foreground">{cat}</span>
                <span className="shrink-0 w-14 text-muted-foreground/70">{e.caller_pid}→{e.target_pid}</span>
                <span className="text-foreground/90 break-all">{e.detail}</span>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}
