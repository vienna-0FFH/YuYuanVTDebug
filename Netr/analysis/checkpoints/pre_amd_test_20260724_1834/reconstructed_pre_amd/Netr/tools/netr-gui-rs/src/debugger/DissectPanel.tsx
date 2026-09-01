import { useEffect, useState } from "react";
import { Boxes, RefreshCw, Loader2, Copy } from "lucide-react";
import { invoke } from "@tauri-apps/api/core";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useSession } from "./sessionStore";
import { formatAddress, evalExpression } from "./expr";
import { cn } from "@/lib/utils";
import { errMsg } from "./ipc";

interface DissectField {
  offset: number;
  kind: string;
  raw_hex: string;
  display: string;
}

const KIND_COLOR: Record<string, string> = {
  padding: "text-muted-foreground/40",
  i32: "text-cyan-400",
  i64: "text-cyan-400",
  f32: "text-blue-400",
  f64: "text-blue-400",
  ptr: "text-amber-400",
  string: "text-emerald-400",
  raw: "text-foreground/70",
};

export function DissectPanel() {
  const { pid, ctx, setAddress } = useSession();
  const [startText, setStartText] = useState("");
  const [size, setSize] = useState(256);
  const [fields, setFields] = useState<DissectField[]>([]);
  const [base, setBase] = useState<bigint>(0n);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  async function run() {
    if (!pid) return toast.error("未附加");
    const t = startText.trim();
    if (!t) return toast.error("请输入起始地址(支持表达式)");
    setBusy(true);
    setErr(null);
    try {
      const baseAddr = await evalExpression(t, { pid, ctx });
      const r = await invoke<DissectField[]>("dbg_dissect", {
        pid,
        address: Number(baseAddr),
        size,
      });
      setFields(r);
      setBase(baseAddr);
    } catch (e) {
      setErr(errMsg(e));
      setFields([]);
    } finally {
      setBusy(false);
    }
  }

  // 选 ptr 字段跳转到那地址
  function jumpToPtr(displayText: string) {
    const m = displayText.match(/0x([0-9a-fA-F]+)/);
    if (!m) return;
    try { setAddress(BigInt("0x" + m[1])); } catch { /* ignore */ }
  }

  useEffect(() => {
    if (pid && !startText) setStartText("rsp");
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [pid]);

  return (
    <div className="flex h-full flex-col bg-background">
      <div className="flex h-9 shrink-0 items-center gap-2 border-b border-border bg-card/60 px-3 text-xs">
        <Boxes className="h-3.5 w-3.5 text-primary" />
        <span className="font-semibold text-muted-foreground">结构 Dissect</span>
        <Input
          value={startText}
          onChange={(e) => setStartText(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && void run()}
          placeholder="起始地址"
          className="ml-2 h-6 flex-1 max-w-sm font-mono text-xs"
        />
        <Input
          type="number"
          min={16}
          max={4096}
          step={64}
          value={size}
          onChange={(e) => setSize(Number(e.target.value) || 256)}
          className="h-6 w-20 font-mono text-xs"
        />
        <Button size="sm" variant="outline" onClick={() => void run()} disabled={busy} className="h-6 px-2">
          {busy ? <Loader2 className="h-3 w-3 animate-spin" /> : <RefreshCw className="h-3 w-3" />}
        </Button>
      </div>

      {err && (
        <div className="border-b border-warning/40 bg-warning/10 px-2 py-1 text-[10px] text-warning">
          {err}
        </div>
      )}

      <div className="min-h-0 flex-1 overflow-auto font-mono text-[11px]">
        {fields.length === 0 ? (
          <div className="flex h-full items-center justify-center text-muted-foreground">
            —
          </div>
        ) : (
          <table className="w-full border-collapse">
            <thead className="sticky top-0 bg-card/95 backdrop-blur text-[10px] uppercase tracking-wider text-muted-foreground">
              <tr>
                <th className="w-24 px-2 py-1 text-left">地址</th>
                <th className="w-16 px-2 py-1 text-left">偏移</th>
                <th className="w-12 px-2 py-1 text-left">类型</th>
                <th className="w-52 px-2 py-1 text-left">字节</th>
                <th className="px-2 py-1 text-left">解释</th>
                <th className="w-6"></th>
              </tr>
            </thead>
            <tbody>
              {fields.map((f) => {
                const addr = base + BigInt(f.offset);
                const isPtr = f.kind === "ptr";
                return (
                  <tr key={f.offset} className="border-b border-border/40 hover:bg-accent/40">
                    <td
                      className="cursor-pointer px-2 py-0.5 tabular-nums text-muted-foreground"
                      onClick={() => setAddress(addr)}
                    >
                      {formatAddress(addr).slice(-12)}
                    </td>
                    <td className="px-2 py-0.5 text-muted-foreground/70">+{f.offset.toString(16)}</td>
                    <td className={cn("px-2 py-0.5 font-medium", KIND_COLOR[f.kind] ?? "")}>{f.kind}</td>
                    <td className="px-2 py-0.5 text-muted-foreground/80">{f.raw_hex}</td>
                    <td
                      className={cn("px-2 py-0.5 break-all", isPtr && "cursor-pointer text-amber-400 hover:underline")}
                      onClick={() => isPtr && jumpToPtr(f.display)}
                    >
                      {f.display}
                    </td>
                    <td className="px-2 py-0.5">
                      <button
                        type="button"
                        className="opacity-50 hover:opacity-100"
                        onClick={() => {
                          void navigator.clipboard.writeText(f.display);
                          toast.success("已复制");
                        }}
                      >
                        <Copy className="h-2.5 w-2.5" />
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
