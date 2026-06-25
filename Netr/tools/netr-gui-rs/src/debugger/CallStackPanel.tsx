import { useEffect, useState } from "react";
import { Layers, RefreshCw, Loader2 } from "lucide-react";

import { Button } from "@/components/ui/button";
import { dbgIpc, errMsg } from "./ipc";
import { useSession } from "./sessionStore";
import { formatAddress } from "./expr";

interface Frame {
  rip: bigint;
  /** "modname+0xRVA" 或 "?" */
  symbol: string;
  /** 这条 frame 对应的 RSP(读到该指针的位置) */
  rsp: bigint;
}

/**
 * 简版 call stack walker —
 *   从 RSP 顺次读 8 字节,看是否落在某个 module .text 范围内,
 *   是即视为 return address,展开 frame。
 *   准确度 ~70%(无 unwind info),CE 也是这种风格。
 *
 * 真符号解析后续 P52 接 dbghelp + symsrv,这里先 modname+RVA。
 */
export function CallStackPanel() {
  const { pid, selectedTid, ctx, setAddress } = useSession();
  const [frames, setFrames] = useState<Frame[]>([]);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  async function walk() {
    if (!pid || !selectedTid) {
      setErr("先选线程并暂停");
      return;
    }
    setBusy(true);
    setErr(null);
    try {
      const r = await dbgIpc.callStack({ pid, tid: selectedTid, max_frames: 64, stack_scan_bytes: 4096 });
      const fs: Frame[] = r.frames.map((f) => ({
        rip: BigInt(f.rip),
        rsp: BigInt(f.rsp),
        symbol: f.symbol ?? (f.module ? `${f.module}+0x${(f.module_offset ?? 0).toString(16)}` : "?"),
      }));
      setFrames(fs);
    } catch (e) {
      setErr(errMsg(e));
    } finally {
      setBusy(false);
    }
  }

  // 选线程/ctx 变化时自动重 walk
  useEffect(() => {
    if (ctx && selectedTid) void walk();
    else setFrames([]);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [ctx, selectedTid]);

  return (
    <div className="flex h-full flex-col">
      <div className="flex h-8 shrink-0 items-center gap-2 border-b border-border bg-card/40 px-2 text-xs">
        <Layers className="h-3 w-3 text-muted-foreground" />
        <span className="font-medium text-muted-foreground">栈帧</span>
        <span className="ml-auto text-[10px] text-muted-foreground/60">
          TID {selectedTid ?? "-"}
        </span>
        <Button size="sm" variant="ghost" onClick={() => void walk()} disabled={busy} className="h-6 w-6 p-0">
          {busy ? <Loader2 className="h-3 w-3 animate-spin" /> : <RefreshCw className="h-3 w-3" />}
        </Button>
      </div>

      {err && (
        <div className="border-b border-warning/40 bg-warning/10 px-2 py-1 text-[10px] text-warning">
          {err}
        </div>
      )}

      <div className="min-h-0 flex-1 overflow-auto font-mono text-[11px]">
        {frames.length === 0 ? (
          <div className="flex h-full items-center justify-center text-muted-foreground">
            —
          </div>
        ) : (
          frames.map((f, i) => (
            <button
              key={`${f.rsp}_${f.rip}`}
              type="button"
              onClick={() => setAddress(f.rip)}
              className="flex w-full items-baseline gap-2 px-2 py-1 text-left hover:bg-accent/50"
            >
              <span className="w-6 shrink-0 text-muted-foreground">#{i}</span>
              <span className="w-32 shrink-0 truncate text-primary/90">{formatAddress(f.rip)}</span>
              <span className="truncate text-muted-foreground">{f.symbol}</span>
            </button>
          ))
        )}
      </div>
    </div>
  );
}
