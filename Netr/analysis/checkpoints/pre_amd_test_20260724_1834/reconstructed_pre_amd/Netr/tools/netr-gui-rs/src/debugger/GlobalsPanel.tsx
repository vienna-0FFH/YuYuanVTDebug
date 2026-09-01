import { useEffect, useState } from "react";
import { Compass, Loader2, Plus } from "lucide-react";
import { toast } from "sonner";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { dbgIpc, type FindGlobalsResult, type GlobalCandidate, errMsg } from "./ipc";
import { useSession } from "./sessionStore";
import { formatAddress } from "./expr";
import {
  ContextMenu,
  ContextMenuContent,
  ContextMenuItem,
  ContextMenuSeparator,
  ContextMenuTrigger,
} from "@/components/ui/context-menu";
import { cn } from "@/lib/utils";

interface Progress { pct: number; off?: number; refs?: number; uniq?: number; done?: boolean }

export function GlobalsPanel() {
  const { pid, setAddress, addWatch, setMainTab } = useSession();
  const [moduleName, setModuleName] = useState("");
  const [topN, setTopN] = useState(50);
  const [minRefs, setMinRefs] = useState(5);
  const [busy, setBusy] = useState(false);
  const [progress, setProgress] = useState<Progress | null>(null);
  const [result, setResult] = useState<FindGlobalsResult | null>(null);

  // moduleName 由用户手动填; 留空 = 后端自动 pick 主 exe

  useEffect(() => {
    let un: UnlistenFn | null = null;
    void listen<Progress>("find_globals_progress", (e) => {
      setProgress(e.payload);
      if (e.payload.done) setTimeout(() => setProgress(null), 1500);
    }).then((u) => (un = u));
    return () => { if (un) un(); };
  }, []);

  async function go() {
    if (!pid) return toast.error("未附加");
    setBusy(true);
    setResult(null);
    try {
      const r = await dbgIpc.findGlobals({
        pid,
        module_name: moduleName || null,
        top_n: topN,
        min_refs: minRefs,
      });
      setResult(r);
    } catch (e) {
      toast.error(errMsg(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex h-full flex-col">
      <div className="flex h-8 shrink-0 flex-wrap items-center gap-2 border-b border-border bg-card/40 px-2 text-xs">
        <Compass className="h-3 w-3 text-muted-foreground" />
        <span className="font-medium text-muted-foreground">候选全局指针</span>
        <Input
          value={moduleName}
          onChange={(e) => setModuleName(e.target.value)}
          placeholder="模块"
          className="h-6 w-40 font-mono text-xs"
        />
        <span className="text-[10px] text-muted-foreground">Top</span>
        <Input
          type="number" min={1} max={500} value={topN}
          onChange={(e) => setTopN(Number(e.target.value) || 50)}
          className="h-6 w-16 text-xs"
        />
        <span className="text-[10px] text-muted-foreground">最小引用</span>
        <Input
          type="number" min={1} max={1000} value={minRefs}
          onChange={(e) => setMinRefs(Number(e.target.value) || 5)}
          className="h-6 w-16 text-xs"
        />
        <Button size="sm" onClick={() => void go()} disabled={busy} className="h-6 px-2">
          {busy ? <Loader2 className="h-3 w-3 animate-spin" /> : "扫描"}
        </Button>
        {result && (
          <span className="ml-2 text-[10px] text-muted-foreground/70">
            .text {formatAddress(BigInt(result.text_base))} + {(result.text_size / 1024 / 1024).toFixed(1)} MB
            · {result.rip_refs_total} 引用
          </span>
        )}
      </div>

      {progress && (
        <div className="flex h-5 shrink-0 items-center gap-2 border-b border-border bg-card/30 px-2 text-[10px] text-muted-foreground">
          <div className="relative h-1 flex-1 overflow-hidden rounded bg-border/50">
            <div
              className={cn("absolute inset-y-0 left-0", progress.done ? "bg-success" : "bg-primary")}
              style={{ width: `${progress.pct.toFixed(1)}%` }}
            />
          </div>
          <span className="tabular-nums">{progress.pct.toFixed(1)}%</span>
          {progress.uniq !== undefined && <span>{progress.uniq} 候选</span>}
        </div>
      )}

      <div className="min-h-0 flex-1 overflow-auto font-mono text-xs">
        {!result ? (
          <div className="flex h-full items-center justify-center text-muted-foreground">—</div>
        ) : result.candidates.length === 0 ? (
          <div className="flex h-full items-center justify-center text-muted-foreground">无候选 (调低最小引用)</div>
        ) : (
          <table className="w-full border-collapse">
            <thead className="sticky top-0 bg-card/95 backdrop-blur text-[10px] uppercase tracking-wider text-muted-foreground">
              <tr>
                <th className="px-2 py-1 text-left">地址</th>
                <th className="px-2 py-1 text-right">引用</th>
                <th className="px-2 py-1 text-right">LEA</th>
                <th className="px-2 py-1 text-right">MOV</th>
                <th className="px-2 py-1 text-left">值 (低 8 字节)</th>
                <th className="w-8"></th>
              </tr>
            </thead>
            <tbody>
              {result.candidates.map((c) => (
                <Row
                  key={c.address}
                  c={c}
                  onJump={(a) => setAddress(BigInt(a))}
                  onAddWatch={(a, label) => {
                    addWatch({ address: BigInt(a), description: label, type: "u64" });
                    toast.success("已加监视");
                  }}
                  onViewInHex={(a) => { setAddress(BigInt(a)); setMainTab("hex"); }}
                />
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

function Row({
  c, onJump, onAddWatch, onViewInHex,
}: {
  c: GlobalCandidate;
  onJump: (a: number) => void;
  onAddWatch: (a: number, label: string) => void;
  onViewInHex: (a: number) => void;
}) {
  const label = `global@${c.address.toString(16)}`;
  return (
    <ContextMenu>
      <ContextMenuTrigger asChild>
        <tr className="border-t border-border/40 hover:bg-accent/40">
          <td
            className="cursor-pointer px-2 py-0.5 tabular-nums text-primary hover:underline"
            onClick={() => onJump(c.address)}
          >
            {formatAddress(BigInt(c.address))}
          </td>
          <td className="px-2 py-0.5 text-right tabular-nums">{c.refs}</td>
          <td className="px-2 py-0.5 text-right tabular-nums text-muted-foreground/70">{c.lea_refs}</td>
          <td className="px-2 py-0.5 text-right tabular-nums text-muted-foreground/70">{c.mov_refs}</td>
          <td className="px-2 py-0.5 text-muted-foreground/80">{c.at_value_hex}</td>
          <td className="px-2 py-0.5 text-right">
            <Button size="sm" variant="ghost" className="h-5 w-5 p-0"
              onClick={() => onAddWatch(c.address, label)}>
              <Plus className="h-3 w-3" />
            </Button>
          </td>
        </tr>
      </ContextMenuTrigger>
      <ContextMenuContent>
        <ContextMenuItem onClick={() => onJump(c.address)}>跳到地址</ContextMenuItem>
        <ContextMenuItem onClick={() => onViewInHex(c.address)}>在 Hex 视图查看</ContextMenuItem>
        <ContextMenuSeparator />
        <ContextMenuItem onClick={() => onAddWatch(c.address, label)}>添加到监视 (u64)</ContextMenuItem>
        {c.sample_callers.length > 0 && (
          <ContextMenuItem onClick={() => onJump(c.sample_callers[0])}>
            跳到引用此值的代码 (#1 = 0x{c.sample_callers[0].toString(16)})
          </ContextMenuItem>
        )}
        <ContextMenuSeparator />
        <ContextMenuItem onClick={() => {
          void navigator.clipboard.writeText(formatAddress(BigInt(c.address)));
          toast.success("已复制");
        }}>复制地址</ContextMenuItem>
      </ContextMenuContent>
    </ContextMenu>
  );
}
