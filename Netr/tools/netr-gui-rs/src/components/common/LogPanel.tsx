import { useEffect, useRef } from "react";
import { useDbgEvt, type DbgEvtView } from "@/store/dbgevtStore";
import { Trash2, Pause, Play } from "lucide-react";
import { useState } from "react";
import { Button } from "@/components/ui/button";

const SEV_LABEL: Record<number, { text: string; color: string }> = {
  0: { text: "INFO", color: "text-muted-foreground" },
  1: { text: "WARN", color: "text-warning" },
  2: { text: "ERROR", color: "text-destructive" },
  3: { text: "FATAL", color: "text-destructive" },
};

export function LogPanel() {
  const events = useDbgEvt((s) => s.events);
  const start = useDbgEvt((s) => s.start);
  const stop = useDbgEvt((s) => s.stop);
  const clear = useDbgEvt((s) => s.clear);
  const [paused, setPaused] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!paused) {
      void start();
      return () => stop();
    }
    stop();
  }, [paused, start, stop]);

  useEffect(() => {
    if (!paused && scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [events, paused]);

  return (
    <div className="flex h-72 flex-col rounded-md border bg-card/40">
      <div className="flex items-center justify-between border-b px-3 py-1.5">
        <span className="text-xs font-medium text-muted-foreground">
          事件日志({events.length})
        </span>
        <div className="flex gap-1">
          <Button
            size="sm"
            variant="ghost"
            onClick={() => setPaused((v) => !v)}
            aria-label={paused ? "继续" : "暂停"}
          >
            {paused ? <Play className="h-3.5 w-3.5" /> : <Pause className="h-3.5 w-3.5" />}
          </Button>
          <Button size="sm" variant="ghost" onClick={clear} aria-label="清空">
            <Trash2 className="h-3.5 w-3.5" />
          </Button>
        </div>
      </div>
      <div ref={scrollRef} className="flex-1 overflow-y-auto p-2 font-mono text-[11px] leading-relaxed selectable">
        {events.length === 0 ? (
          <div className="flex h-full items-center justify-center text-muted-foreground">
            暂无事件
          </div>
        ) : (
          events.map((e) => <EventLine key={e.sequence} ev={e} />)
        )}
      </div>
    </div>
  );
}

function EventLine({ ev }: { ev: DbgEvtView }) {
  const sev = SEV_LABEL[ev.severity] ?? { text: `S${ev.severity}`, color: "" };
  return (
    <div className="flex items-baseline gap-2">
      <span className="shrink-0 text-muted-foreground">#{ev.sequence}</span>
      <span className={`shrink-0 ${sev.color}`}>[{sev.text}]</span>
      <span className="shrink-0 text-muted-foreground">cat={ev.category}</span>
      <span className="shrink-0 text-muted-foreground">caller={ev.caller_pid}</span>
      <span className="shrink-0 text-muted-foreground">target={ev.target_pid}</span>
      <span className="text-foreground/90 break-all">{ev.detail}</span>
    </div>
  );
}
