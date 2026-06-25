import { useEffect, useState } from "react";
import { Loader2, Crosshair } from "lucide-react";

import { Dialog } from "@/components/ui/dialog";
import { dbgIpc, type XrefHit, errMsg } from "./ipc";
import { useSession } from "./sessionStore";
import { formatAddress } from "./expr";
import { cn } from "@/lib/utils";

/**
 * Xref 弹窗 — 给定 target 地址, 列出所有引用. 点击跳转 disasm.
 */
export function XrefDialog({
  open, target, onOpenChange,
}: {
  open: boolean;
  target: bigint | null;
  onOpenChange: (v: boolean) => void;
}) {
  const { pid, setAddress, setMainTab } = useSession();
  const [hits, setHits] = useState<XrefHit[]>([]);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [total, setTotal] = useState(0);
  const [module, setModule] = useState("");

  useEffect(() => {
    if (!open || !pid || target === null) return;
    setBusy(true); setErr(null); setHits([]);
    dbgIpc.xrefTo({ pid, target: `0x${target.toString(16)}`, max_hits: 1000 })
      .then((r) => { setHits(r.hits); setTotal(r.total_hits); setModule(r.module); })
      .catch((e) => setErr(errMsg(e)))
      .finally(() => setBusy(false));
  }, [open, pid, target]);

  function jump(addr: number) {
    setAddress(BigInt(addr));
    setMainTab("disasm");
    onOpenChange(false);
  }

  return (
    <Dialog
      open={open}
      onClose={() => onOpenChange(false)}
      title={<span className="flex items-center gap-2"><Crosshair className="h-4 w-4" /> 交叉引用</span>}
      widthClass="max-w-2xl"
    >
      <div className="px-3 py-2 text-[11px]">
        <div className="mb-2 flex items-baseline gap-2 text-muted-foreground">
          {target !== null && (
            <span>目标: <code className="font-mono text-primary">{formatAddress(target)}</code></span>
          )}
          {module && <span>模块: <code className="font-mono">{module}</code></span>}
          {total > 0 && <span>共 {total} 个引用</span>}
        </div>

        {busy && (
          <div className="flex items-center gap-2 py-6 text-muted-foreground">
            <Loader2 className="h-4 w-4 animate-spin" /> 扫描中(全 .text 解码 ~3 秒)...
          </div>
        )}
        {err && <div className="rounded bg-red-500/10 px-2 py-1 text-red-300">{err}</div>}

        {!busy && hits.length === 0 && !err && (
          <div className="py-6 text-center text-muted-foreground">无引用</div>
        )}

        {hits.length > 0 && (
          <div className="max-h-[55vh] overflow-auto rounded border border-border/40">
            <table className="w-full font-mono">
              <thead className="sticky top-0 bg-card/95 text-[10px] uppercase tracking-wider text-muted-foreground">
                <tr>
                  <th className="w-40 px-2 py-1 text-left">引用点</th>
                  <th className="w-12 px-2 py-1 text-left">类型</th>
                  <th className="px-2 py-1 text-left">指令</th>
                </tr>
              </thead>
              <tbody>
                {hits.map((h, i) => (
                  <tr
                    key={i}
                    onClick={() => jump(h.source)}
                    className={cn(
                      "cursor-pointer border-t border-border/30 text-[11px] hover:bg-accent/40",
                    )}
                  >
                    <td className="px-2 py-0.5 text-primary">{formatAddress(BigInt(h.source))}</td>
                    <td className="px-2 py-0.5 text-[10px] text-cyan-400">{h.kind}</td>
                    <td className="px-2 py-0.5 text-muted-foreground">{h.mnemonic}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </Dialog>
  );
}
