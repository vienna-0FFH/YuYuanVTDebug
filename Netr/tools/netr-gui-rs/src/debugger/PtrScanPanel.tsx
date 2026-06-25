import { useState } from "react";
import { Crosshair, Loader2, ArrowRight } from "lucide-react";
import { invoke } from "@tauri-apps/api/core";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useSession } from "./sessionStore";
import { evalExpression, formatAddress } from "./expr";
import { errMsg } from "./ipc";

interface PtrHit { container: number; value: number; offset: number; }
interface PtrScanResult { regions_scanned: number; hits: PtrHit[]; truncated: boolean; }

/**
 * 指针扫描 — 1 层
 *   输入: 目标地址(表达式) + 偏移窗口 + 最大命中数
 *   扫描 target 进程全部 commit + 可读 region,找指向 [target-window, target+window] 的 QWORD
 *   命中: container(指针所在地址) value(指针值) offset(value-target)
 *   用户在命中行右键继续递归(后续完善多级)
 */
export function PtrScanPanel() {
  const { pid, ctx, setAddress } = useSession();
  const [targetText, setTargetText] = useState("");
  const [window, setWindow] = useState(0x1000);
  const [maxHits, setMaxHits] = useState(1000);
  const [result, setResult] = useState<PtrScanResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  async function go() {
    if (!pid) return toast.error("未附加");
    const t = targetText.trim();
    if (!t) return toast.error("先填目标地址(支持表达式)");
    setBusy(true);
    setErr(null);
    setResult(null);
    try {
      const tAddr = await evalExpression(t, { pid, ctx });
      const r = await invoke<PtrScanResult>("dbg_ptr_scan", {
        pid,
        target: Number(tAddr),
        window: Number(window),
        maxHits: Number(maxHits),
      });
      setResult(r);
      if (r.hits.length === 0) {
        toast.message("未找到指向该地址的指针");
      } else {
        toast.success(`命中 ${r.hits.length} 个${r.truncated ? "(已截断)" : ""}`);
      }
    } catch (e) {
      setErr(errMsg(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex h-full flex-col">
      <div className="flex h-8 shrink-0 items-center gap-2 border-b border-border bg-card/40 px-2 text-xs">
        <Crosshair className="h-3 w-3 text-muted-foreground" />
        <span className="font-medium text-muted-foreground">指针扫描</span>
        <Input
          value={targetText}
          onChange={(e) => setTargetText(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && void go()}
          placeholder="目标地址"
          className="ml-2 h-6 flex-1 max-w-md font-mono text-xs"
        />
        <span className="text-[10px] text-muted-foreground">±</span>
        <Input
          type="number"
          min={0}
          max={0x10000}
          value={window}
          onChange={(e) => setWindow(Number(e.target.value) || 0)}
          className="h-6 w-20 text-xs"
          title="偏移窗口"
        />
        <span className="text-[10px] text-muted-foreground">最大</span>
        <Input
          type="number"
          min={1}
          max={10000}
          value={maxHits}
          onChange={(e) => setMaxHits(Number(e.target.value) || 1000)}
          className="h-6 w-20 text-xs"
        />
        <Button size="sm" variant="outline" onClick={() => void go()} disabled={busy} className="h-6 px-2">
          {busy ? <Loader2 className="h-3 w-3 animate-spin" /> : "扫描"}
        </Button>
      </div>

      {err && <div className="border-b border-warning/40 bg-warning/10 px-2 py-1 text-[10px] text-warning">{err}</div>}

      <div className="min-h-0 flex-1 overflow-auto font-mono text-xs">
        {!result ? (
          <div className="flex h-full items-center justify-center text-muted-foreground">
            —
          </div>
        ) : result.hits.length === 0 ? (
          <div className="flex h-full items-center justify-center text-muted-foreground">
            未命中
          </div>
        ) : (
          <table className="w-full border-collapse">
            <thead className="sticky top-0 bg-card/95 backdrop-blur text-[10px] uppercase tracking-wider text-muted-foreground">
              <tr>
                <th className="px-2 py-1 text-left">指针所在地址</th>
                <th className="px-2 py-1 text-left">指向</th>
                <th className="w-16 px-2 py-1 text-right">offset</th>
                <th className="w-16"></th>
              </tr>
            </thead>
            <tbody>
              {result.hits.slice(0, 1000).map((h) => (
                <tr key={h.container} className="border-b border-border/40 hover:bg-accent/40">
                  <td
                    className="cursor-pointer px-2 py-0.5 tabular-nums text-muted-foreground"
                    onClick={() => setAddress(BigInt(h.container))}
                  >
                    {formatAddress(BigInt(h.container))}
                  </td>
                  <td className="px-2 py-0.5 tabular-nums text-amber-400">
                    {formatAddress(BigInt(h.value))}
                  </td>
                  <td className="px-2 py-0.5 text-right tabular-nums text-muted-foreground/80">
                    {h.offset >= 0 ? `+${h.offset.toString(16)}` : `-${Math.abs(h.offset).toString(16)}`}
                  </td>
                  <td className="px-2 py-0.5">
                    <Button
                      size="sm"
                      variant="ghost"
                      className="h-5 w-5 p-0"
                      onClick={() => {
                        setTargetText(`0x${h.container.toString(16)}`);
                      }}
                      title="递归"
                    >
                      <ArrowRight className="h-3 w-3" />
                    </Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
