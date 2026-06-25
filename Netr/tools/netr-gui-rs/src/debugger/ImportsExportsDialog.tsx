import { useEffect, useState } from "react";
import { Loader2, Boxes, Download, Upload } from "lucide-react";
import { toast } from "sonner";

import { Dialog } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { dbgIpc, type ImportEntry, type ExportEntry, errMsg } from "./ipc";
import { useSession } from "./sessionStore";
import { formatAddress } from "./expr";
import { cn } from "@/lib/utils";

/**
 * 一个模块的 Imports + Exports 弹窗. 双击或右键 ModulesPanel 触发.
 */
export function ImportsExportsDialog({
  open, moduleName, onOpenChange,
}: {
  open: boolean;
  moduleName: string | null;
  onOpenChange: (v: boolean) => void;
}) {
  const { pid, setAddress, setMainTab } = useSession();
  const [tab, setTab] = useState<"imports" | "exports">("imports");
  const [imp, setImp] = useState<ImportEntry[]>([]);
  const [exp, setExp] = useState<ExportEntry[]>([]);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [q, setQ] = useState("");

  useEffect(() => {
    if (!open || !pid || !moduleName) return;
    setBusy(true); setErr(null);
    const fn = tab === "imports"
      ? dbgIpc.listImports({ pid, module_name: moduleName }).then((r) => setImp(r.imports))
      : dbgIpc.listExports({ pid, module_name: moduleName }).then((r) => setExp(r.exports));
    fn.catch((e) => setErr(errMsg(e))).finally(() => setBusy(false));
  }, [open, pid, moduleName, tab]);

  const filterFn = <T extends { name: string; dll?: string }>(xs: T[]): T[] => {
    if (!q) return xs;
    const lc = q.toLowerCase();
    return xs.filter((x) => x.name.toLowerCase().includes(lc) ||
      (typeof x.dll === "string" && x.dll.toLowerCase().includes(lc)));
  };

  function jump(addr: number) {
    if (addr === 0) { toast.warning("此符号尚未解析(IAT 未填)"); return; }
    setAddress(BigInt(addr));
    setMainTab("disasm");
    onOpenChange(false);
  }

  const fimp = filterFn(imp);
  const fexp = filterFn(exp);

  return (
    <Dialog
      open={open}
      onClose={() => onOpenChange(false)}
      title={<span className="flex items-center gap-2"><Boxes className="h-4 w-4" /> {moduleName ?? "—"}</span>}
      widthClass="max-w-3xl"
    >
      <div className="px-3 py-2 text-[11px]">
        <div className="mb-2 flex items-center gap-2">
          <div className="flex rounded-md border border-input bg-background p-0.5">
            <button
              type="button"
              onClick={() => setTab("imports")}
              className={cn(
                "flex items-center gap-1 rounded-sm px-2 py-0.5 text-[11px] font-medium",
                tab === "imports" ? "bg-primary text-primary-foreground" : "text-muted-foreground"
              )}
            >
              <Download className="h-3 w-3" /> Imports
            </button>
            <button
              type="button"
              onClick={() => setTab("exports")}
              className={cn(
                "flex items-center gap-1 rounded-sm px-2 py-0.5 text-[11px] font-medium",
                tab === "exports" ? "bg-primary text-primary-foreground" : "text-muted-foreground"
              )}
            >
              <Upload className="h-3 w-3" /> Exports
            </button>
          </div>
          <Input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="过滤..."
            className="h-6 max-w-xs text-xs"
          />
          {busy && <Loader2 className="ml-auto h-4 w-4 animate-spin text-muted-foreground" />}
        </div>

        {err && <div className="mb-2 rounded bg-red-500/10 px-2 py-1 text-red-300">{err}</div>}

        <div className="max-h-[55vh] overflow-auto rounded border border-border/40 font-mono">
          {tab === "imports" ? (
            <table className="w-full">
              <thead className="sticky top-0 bg-card/95 text-[10px] uppercase tracking-wider text-muted-foreground">
                <tr>
                  <th className="w-44 px-2 py-1 text-left">DLL</th>
                  <th className="px-2 py-1 text-left">API</th>
                  <th className="w-36 px-2 py-1 text-left">IAT</th>
                  <th className="w-36 px-2 py-1 text-left">解析后</th>
                </tr>
              </thead>
              <tbody>
                {fimp.slice(0, 3000).map((i, k) => (
                  <tr
                    key={k}
                    onClick={() => jump(i.resolved_address)}
                    className="cursor-pointer border-t border-border/30 text-[11px] hover:bg-accent/40"
                  >
                    <td className="px-2 py-0.5 text-muted-foreground/80">{i.dll}</td>
                    <td className="px-2 py-0.5 text-cyan-400">{i.name}</td>
                    <td className="px-2 py-0.5 text-muted-foreground">{formatAddress(BigInt(i.iat_address))}</td>
                    <td className="px-2 py-0.5 text-primary">
                      {i.resolved_address === 0 ? "—" : formatAddress(BigInt(i.resolved_address))}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <table className="w-full">
              <thead className="sticky top-0 bg-card/95 text-[10px] uppercase tracking-wider text-muted-foreground">
                <tr>
                  <th className="px-2 py-1 text-left">名字</th>
                  <th className="w-16 px-2 py-1 text-right">ord</th>
                  <th className="w-36 px-2 py-1 text-left">RVA</th>
                  <th className="w-44 px-2 py-1 text-left">绝对地址</th>
                </tr>
              </thead>
              <tbody>
                {fexp.slice(0, 3000).map((e, k) => (
                  <tr
                    key={k}
                    onClick={() => jump(e.address)}
                    className="cursor-pointer border-t border-border/30 text-[11px] hover:bg-accent/40"
                  >
                    <td className="px-2 py-0.5 text-cyan-400">{e.name}</td>
                    <td className="px-2 py-0.5 text-right text-muted-foreground/70">{e.ordinal}</td>
                    <td className="px-2 py-0.5 text-muted-foreground">0x{e.rva.toString(16)}</td>
                    <td className="px-2 py-0.5 text-primary">{formatAddress(BigInt(e.address))}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </Dialog>
  );
}
