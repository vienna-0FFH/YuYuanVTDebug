import { useMemo, useState } from "react";
import { Workflow, Search, RefreshCw, Loader2 } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { dbgIpc, type FunctionEntry, errMsg } from "./ipc";
import { useSession } from "./sessionStore";
import { formatAddress } from "./expr";
import {
  ContextMenu, ContextMenuContent, ContextMenuItem, ContextMenuTrigger, ContextMenuSeparator,
} from "@/components/ui/context-menu";

/**
 * 函数列表面板 — 从 .pdata 异常表精确推断 (>99% 覆盖).
 * 双击地址跳 disasm; 右键: 设标签 / 重命名 / 查找引用.
 */
export function FunctionsPanel() {
  const { pid, setAddress, setMainTab, annotations } = useSession();
  const [module, setModule] = useState("");
  const [funcs, setFuncs] = useState<FunctionEntry[]>([]);
  const [busy, setBusy] = useState(false);
  const [q, setQ] = useState("");
  const [total, setTotal] = useState(0);

  async function load() {
    if (!pid) return;
    setBusy(true);
    try {
      const r = await dbgIpc.listFunctions({ pid, module_name: module || null, limit: 5000 });
      setFuncs(r.functions);
      setTotal(r.total);
      if (!module) setModule(r.module);
    } catch (e) {
      toast.error(errMsg(e));
    } finally {
      setBusy(false);
    }
  }

  const filtered = useMemo(() => {
    const lc = q.toLowerCase();
    return funcs.filter((f) => {
      if (!lc) return true;
      const addr = f.start.toString(16);
      const name = annotations?.labels?.[`0x${addr}`] ?? annotations?.functions?.[`0x${addr}`]?.name ?? "";
      return addr.includes(lc) || name.toLowerCase().includes(lc);
    });
  }, [funcs, q, annotations]);

  async function rename(f: FunctionEntry) {
    const addr = `0x${f.start.toString(16)}`;
    const cur = annotations?.labels?.[addr] ?? annotations?.functions?.[addr]?.name ?? "";
    const name = prompt(`函数名 (${addr}):`, cur);
    if (name === null) return;
    try {
      await dbgIpc.annoDefineFunction(addr, name, f.size);
      await dbgIpc.annoSetLabel(addr, name);
      await useSession.getState().refreshAnnotations();
      toast.success("已重命名");
    } catch (e) { toast.error(errMsg(e)); }
  }

  async function findXrefs(f: FunctionEntry) {
    if (!pid) return;
    try {
      const r = await dbgIpc.xrefTo({ pid, target: `0x${f.start.toString(16)}`, max_hits: 256 });
      if (r.total_hits === 0) { toast.info("无引用"); return; }
      // 直接跳第一个引用 + toast 列其余
      setAddress(BigInt(r.hits[0].source));
      setMainTab("disasm");
      toast.success(`${r.total_hits} 个引用; 已跳第一个`);
    } catch (e) { toast.error(errMsg(e)); }
  }

  return (
    <div className="flex h-full flex-col bg-card/20">
      <div className="flex h-8 shrink-0 items-center gap-2 border-b border-border bg-card/40 px-2 text-xs">
        <Workflow className="h-3 w-3 text-muted-foreground" />
        <Input
          value={module}
          onChange={(e) => setModule(e.target.value)}
          placeholder="模块名 (空=主exe)"
          className="h-6 w-44 font-mono text-xs"
        />
        <Button size="sm" variant="ghost" className="h-6 px-2" onClick={() => void load()} disabled={busy || !pid}>
          {busy ? <Loader2 className="h-3 w-3 animate-spin" /> : <RefreshCw className="h-3 w-3" />}
          刷新
        </Button>
        <div className="mx-1 h-4 w-px bg-border" />
        <Search className="h-3 w-3 text-muted-foreground" />
        <Input
          value={q}
          onChange={(e) => setQ(e.target.value)}
          placeholder="搜地址 / 名字"
          className="h-6 flex-1 max-w-xs text-xs"
        />
        <span className="ml-auto text-[10px] text-muted-foreground">
          {filtered.length} / {total}
        </span>
      </div>

      <div className="min-h-0 flex-1 overflow-auto font-mono text-[11px]">
        {funcs.length === 0 ? (
          <div className="flex h-full items-center justify-center text-muted-foreground">
            点刷新加载函数列表 (.pdata)
          </div>
        ) : (
          <table className="w-full border-collapse">
            <thead className="sticky top-0 bg-card/95 backdrop-blur text-[10px] uppercase tracking-wider text-muted-foreground">
              <tr>
                <th className="w-40 px-2 py-1 text-left">地址</th>
                <th className="w-16 px-2 py-1 text-right">大小</th>
                <th className="px-2 py-1 text-left">名字</th>
              </tr>
            </thead>
            <tbody>
              {filtered.slice(0, 2000).map((f) => {
                const addrKey = `0x${f.start.toString(16)}`;
                const name = annotations?.functions?.[addrKey]?.name ?? annotations?.labels?.[addrKey] ?? "";
                return (
                  <ContextMenu key={f.start}>
                    <ContextMenuTrigger asChild>
                      <tr
                        className="border-t border-border/40 hover:bg-accent/30"
                        onDoubleClick={() => { setAddress(BigInt(f.start)); setMainTab("disasm"); }}
                      >
                        <td className="cursor-pointer px-2 py-0.5 tabular-nums text-primary">
                          {formatAddress(BigInt(f.start))}
                        </td>
                        <td className="px-2 py-0.5 text-right text-muted-foreground/70">{f.size}</td>
                        <td className="px-2 py-0.5 text-cyan-400">{name || <span className="text-muted-foreground/40">—</span>}</td>
                      </tr>
                    </ContextMenuTrigger>
                    <ContextMenuContent>
                      <ContextMenuItem onClick={() => { setAddress(BigInt(f.start)); setMainTab("disasm"); }}>
                        跳转反汇编
                      </ContextMenuItem>
                      <ContextMenuItem onClick={() => void rename(f)}>重命名 / 标签</ContextMenuItem>
                      <ContextMenuItem onClick={() => void findXrefs(f)}>查找引用 (xref to)</ContextMenuItem>
                      <ContextMenuSeparator />
                      <ContextMenuItem onClick={() => {
                        void navigator.clipboard.writeText(`0x${f.start.toString(16)}`);
                        toast.success("已复制地址");
                      }}>复制地址</ContextMenuItem>
                    </ContextMenuContent>
                  </ContextMenu>
                );
              })}
              {filtered.length > 2000 && (
                <tr><td colSpan={3} className="py-2 text-center text-[10px] text-muted-foreground">
                  显示前 2000, 继续搜索过滤
                </td></tr>
              )}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
