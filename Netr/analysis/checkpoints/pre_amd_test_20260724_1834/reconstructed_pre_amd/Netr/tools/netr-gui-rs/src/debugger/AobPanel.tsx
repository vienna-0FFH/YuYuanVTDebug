import { useEffect, useState } from "react";
import { Crosshair, Loader2, Plus } from "lucide-react";
import { toast } from "sonner";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { dbgIpc, type AobHit, type AobScanResult, errMsg } from "./ipc";
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

interface AobProgress { pct: number; addr: number; hits: number; done?: boolean }

export function AobPanel() {
  const { pid, setAddress, addWatch, setMainTab } = useSession();
  const [pattern, setPattern] = useState("48 8B 05 ?? ?? ?? ?? 48 8B");
  const [scope, setScope] = useState<"all" | "module" | "custom">("module");
  const [moduleName, setModuleName] = useState("");
  const [addrMin, setAddrMin] = useState("0");
  const [addrMax, setAddrMax] = useState("7FFFFFFFFFFF");
  const [busy, setBusy] = useState(false);
  const [progress, setProgress] = useState<AobProgress | null>(null);
  const [result, setResult] = useState<AobScanResult | null>(null);

  // 模块名默认空, 用户手动填或选 scope=all

  useEffect(() => {
    let un: UnlistenFn | null = null;
    void listen<AobProgress>("aob_progress", (e) => {
      setProgress(e.payload);
      if (e.payload.done) setTimeout(() => setProgress(null), 1500);
    }).then((u) => (un = u));
    return () => { if (un) un(); };
  }, []);

  async function go() {
    if (!pid) return toast.error("未附加");
    if (!pattern.trim()) return toast.error("特征为空");
    setBusy(true);
    setResult(null);
    try {
      const r = await dbgIpc.aobScan({
        pid,
        pattern,
        scope: scope === "all" ? 0 : scope === "module" ? 1 : 2,
        module_name: scope === "module" ? moduleName : null,
        addr_min: scope === "custom" ? parseInt(addrMin, 16) : null,
        addr_max: scope === "custom" ? parseInt(addrMax, 16) : null,
        max_hits: 5000,
      });
      setResult(r);
      toast.success(`命中 ${r.hits.length}${r.truncated ? "(已截断)" : ""}`);
    } catch (e) {
      toast.error(errMsg(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex h-full flex-col">
      <div className="flex h-8 shrink-0 flex-wrap items-center gap-2 border-b border-border bg-card/40 px-2 text-xs">
        <Crosshair className="h-3 w-3 text-muted-foreground" />
        <Input
          value={pattern}
          onChange={(e) => setPattern(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && void go()}
          placeholder="AOB 特征"
          className="h-6 flex-1 min-w-[20rem] font-mono text-xs"
        />
        <select
          value={scope}
          onChange={(e) => setScope(e.target.value as typeof scope)}
          className="h-6 rounded border border-input bg-background px-1.5 text-[10px]"
        >
          <option value="module">模块</option>
          <option value="all">全空间</option>
          <option value="custom">自定义</option>
        </select>
        {scope === "module" && (
          <Input
            value={moduleName}
            onChange={(e) => setModuleName(e.target.value)}
            placeholder="模块名"
            className="h-6 w-44 font-mono text-xs"
          />
        )}
        {scope === "custom" && (
          <>
            <Input value={addrMin} onChange={(e) => setAddrMin(e.target.value)} className="h-6 w-28 font-mono text-xs" />
            <span className="text-muted-foreground">→</span>
            <Input value={addrMax} onChange={(e) => setAddrMax(e.target.value)} className="h-6 w-28 font-mono text-xs" />
          </>
        )}
        <Button size="sm" onClick={() => void go()} disabled={busy} className="h-6 px-2">
          {busy ? <Loader2 className="h-3 w-3 animate-spin" /> : "扫描"}
        </Button>
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
          <span>命中 {progress.hits}</span>
        </div>
      )}

      <div className="min-h-0 flex-1 overflow-auto font-mono text-xs">
        {!result ? (
          <div className="flex h-full items-center justify-center text-muted-foreground">—</div>
        ) : result.hits.length === 0 ? (
          <div className="flex h-full items-center justify-center text-muted-foreground">未命中</div>
        ) : (
          <table className="w-full border-collapse">
            <thead className="sticky top-0 bg-card/95 backdrop-blur text-[10px] uppercase tracking-wider text-muted-foreground">
              <tr>
                <th className="px-2 py-1 text-left">命中</th>
                <th className="px-2 py-1 text-left">RIP-rel 目标</th>
                <th className="px-2 py-1 text-left">模块+RVA</th>
                <th className="w-12"></th>
              </tr>
            </thead>
            <tbody>
              {result.hits.slice(0, 1000).map((h) => (
                <Row key={h.address} hit={h} onJump={(a) => setAddress(BigInt(a))}
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
  hit,
  onJump,
  onAddWatch,
  onViewInHex,
}: {
  hit: AobHit;
  onJump: (a: number) => void;
  onAddWatch: (a: number, label: string) => void;
  onViewInHex: (a: number) => void;
}) {
  const label = hit.module ? `${hit.module}+0x${(hit.rva ?? 0).toString(16)}` : "—";
  return (
    <ContextMenu>
      <ContextMenuTrigger asChild>
        <tr className="border-t border-border/40 hover:bg-accent/40">
          <td
            className="cursor-pointer px-2 py-0.5 tabular-nums text-muted-foreground"
            onClick={() => onJump(hit.address)}
          >
            {formatAddress(BigInt(hit.address))}
          </td>
          <td
            className={cn(
              "px-2 py-0.5 tabular-nums",
              hit.rip_target ? "cursor-pointer text-amber-400 hover:underline" : "text-muted-foreground/40"
            )}
            onClick={() => hit.rip_target && onJump(hit.rip_target)}
          >
            {hit.rip_target ? formatAddress(BigInt(hit.rip_target)) : "—"}
          </td>
          <td className="px-2 py-0.5 text-muted-foreground/80 truncate" title={label}>{label}</td>
          <td className="px-2 py-0.5 text-right">
            <Button size="sm" variant="ghost" className="h-5 w-5 p-0"
              onClick={() => onAddWatch(hit.rip_target ?? hit.address, label)}
            >
              <Plus className="h-3 w-3" />
            </Button>
          </td>
        </tr>
      </ContextMenuTrigger>
      <ContextMenuContent>
        <ContextMenuItem onClick={() => onJump(hit.address)}>跳到命中</ContextMenuItem>
        {hit.rip_target !== null && (
          <ContextMenuItem onClick={() => onJump(hit.rip_target!)}>跳到 RIP-rel 目标</ContextMenuItem>
        )}
        <ContextMenuItem onClick={() => onViewInHex(hit.address)}>命中处 Hex 视图</ContextMenuItem>
        <ContextMenuSeparator />
        <ContextMenuItem onClick={() => onAddWatch(hit.address, label)}>添加到监视(命中)</ContextMenuItem>
        {hit.rip_target !== null && (
          <ContextMenuItem onClick={() => onAddWatch(hit.rip_target!, label)}>添加到监视(目标)</ContextMenuItem>
        )}
        <ContextMenuSeparator />
        <ContextMenuItem onClick={() => {
          void navigator.clipboard.writeText(formatAddress(BigInt(hit.address)));
          toast.success("已复制");
        }}>复制命中地址</ContextMenuItem>
        {hit.rip_target !== null && (
          <ContextMenuItem onClick={() => {
            void navigator.clipboard.writeText(formatAddress(BigInt(hit.rip_target!)));
            toast.success("已复制");
          }}>复制目标地址</ContextMenuItem>
        )}
      </ContextMenuContent>
    </ContextMenu>
  );
}
