import { useEffect, useState } from "react";
import { Loader2 } from "lucide-react";

import { dbgIpc } from "./ipc";
import { useSession } from "./sessionStore";

export function StackPanel() {
  const { pid, ctx, setAddress } = useSession();
  const [qwords, setQwords] = useState<{ addr: bigint; value: bigint }[]>([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    let cancelled = false;
    if (!pid || !ctx) {
      setQwords([]);
      return;
    }
    (async () => {
      setLoading(true);
      try {
        const r = await dbgIpc.readMemory(pid, ctx.rsp, 64 * 8);
        if (cancelled) return;
        const out: { addr: bigint; value: bigint }[] = [];
        const buf = r.bytes;
        for (let i = 0; i + 8 <= buf.length; i += 8) {
          let v = 0n;
          for (let j = 7; j >= 0; j--) {
            v = (v << 8n) | BigInt(buf[i + j]);
          }
          out.push({ addr: BigInt(ctx.rsp) + BigInt(i), value: v });
        }
        setQwords(out);
      } catch {
        setQwords([]);
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [pid, ctx?.rsp, ctx?.rip]);

  return (
    <div className="flex h-[260px] shrink-0 flex-col">
      <div className="flex h-9 shrink-0 items-center gap-2 border-b border-border bg-card/60 px-3 text-xs">
        <span className="font-semibold uppercase tracking-wider text-muted-foreground">栈</span>
        {ctx ? (
          <span className="font-mono text-muted-foreground/70">RSP {ctx.rsp.toString(16)}</span>
        ) : (
          <span className="pill pill-muted">无上下文</span>
        )}
        <div className="ml-auto">{loading && <Loader2 className="h-3.5 w-3.5 animate-spin text-muted-foreground" />}</div>
      </div>
      <div className="min-h-0 flex-1 overflow-auto font-mono text-[11px]">
        {qwords.length === 0 ? (
          <div className="flex h-full items-center justify-center text-muted-foreground">无数据</div>
        ) : (
          qwords.map((q, i) => (
            <button
              key={q.addr.toString()}
              type="button"
              onClick={() => setAddress(q.value)}
              title="跳到此地址"
              className="flex w-full gap-2 px-3 py-0.5 text-left hover:bg-accent/40"
            >
              <span className="w-10 text-muted-foreground/60">+{(i * 8).toString(16)}</span>
              <span className="w-40 text-muted-foreground tabular-nums">{q.addr.toString(16).padStart(16, "0")}</span>
              <span className="tabular-nums">{q.value.toString(16).padStart(16, "0")}</span>
            </button>
          ))
        )}
      </div>
    </div>
  );
}
