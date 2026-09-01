import { useMemo, useState } from "react";
import { TextSelect, Search, RefreshCw, Loader2 } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { dbgIpc, type StringEntry, errMsg } from "./ipc";
import { useSession } from "./sessionStore";
import { formatAddress } from "./expr";
import {
  ContextMenu, ContextMenuContent, ContextMenuItem, ContextMenuTrigger, ContextMenuSeparator,
} from "@/components/ui/context-menu";

/**
 * 字符串列表 — 扫模块 .rdata/.data/.text 抽 ASCII/UTF-16LE.
 * 右键: 跳转 hex / 查找引用 (xref_to).
 */
export function StringsPanel() {
  const { pid, setAddress, setMainTab } = useSession();
  const [module, setModule] = useState("");
  const [minLen, setMinLen] = useState(5);
  const [strs, setStrs] = useState<StringEntry[]>([]);
  const [busy, setBusy] = useState(false);
  const [q, setQ] = useState("");

  async function load() {
    if (!pid) return;
    setBusy(true);
    try {
      const r = await dbgIpc.listStrings({
        pid,
        module_name: module || null,
        min_len: minLen,
        limit: 5000,
      });
      setStrs(r.strings);
      if (!module) setModule(r.module);
    } catch (e) {
      toast.error(errMsg(e));
    } finally {
      setBusy(false);
    }
  }

  const filtered = useMemo(() => {
    if (!q) return strs;
    const lc = q.toLowerCase();
    return strs.filter((s) => s.text.toLowerCase().includes(lc));
  }, [strs, q]);

  async function findXrefs(s: StringEntry) {
    if (!pid) return;
    try {
      const r = await dbgIpc.xrefTo({ pid, target: `0x${s.address.toString(16)}`, max_hits: 64 });
      if (r.total_hits === 0) { toast.info("无引用"); return; }
      setAddress(BigInt(r.hits[0].source));
      setMainTab("disasm");
      toast.success(`${r.total_hits} 个引用; 已跳第一个`);
    } catch (e) { toast.error(errMsg(e)); }
  }

  return (
    <div className="flex h-full flex-col bg-card/20">
      <div className="flex h-8 shrink-0 items-center gap-2 border-b border-border bg-card/40 px-2 text-xs">
        <TextSelect className="h-3 w-3 text-muted-foreground" />
        <Input
          value={module}
          onChange={(e) => setModule(e.target.value)}
          placeholder="模块名"
          className="h-6 w-44 font-mono text-xs"
        />
        <span className="text-[10px] text-muted-foreground">最小长度</span>
        <Input
          type="number"
          value={minLen}
          onChange={(e) => setMinLen(Math.max(3, Number(e.target.value) || 5))}
          className="h-6 w-14 text-xs"
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
          placeholder="子串"
          className="h-6 flex-1 max-w-md text-xs"
        />
        <span className="ml-auto text-[10px] text-muted-foreground">{filtered.length}</span>
      </div>

      <div className="min-h-0 flex-1 overflow-auto font-mono text-[11px]">
        {strs.length === 0 ? (
          <div className="flex h-full items-center justify-center text-muted-foreground">
            点刷新加载字符串
          </div>
        ) : (
          <table className="w-full border-collapse">
            <thead className="sticky top-0 bg-card/95 backdrop-blur text-[10px] uppercase tracking-wider text-muted-foreground">
              <tr>
                <th className="w-40 px-2 py-1 text-left">地址</th>
                <th className="w-12 px-2 py-1 text-left">类型</th>
                <th className="px-2 py-1 text-left">内容</th>
              </tr>
            </thead>
            <tbody>
              {filtered.slice(0, 3000).map((s, i) => (
                <ContextMenu key={`${s.address}-${i}`}>
                  <ContextMenuTrigger asChild>
                    <tr
                      className="border-t border-border/40 hover:bg-accent/30"
                      onDoubleClick={() => { setAddress(BigInt(s.address)); setMainTab("hex"); }}
                    >
                      <td className="px-2 py-0.5 tabular-nums text-primary">{formatAddress(BigInt(s.address))}</td>
                      <td className="px-2 py-0.5 text-[10px] text-muted-foreground/70">{s.encoding === "utf16le" ? "W" : "A"}</td>
                      <td className="px-2 py-0.5 text-amber-200/90 truncate max-w-[60ch]" title={s.text}>{s.text}</td>
                    </tr>
                  </ContextMenuTrigger>
                  <ContextMenuContent>
                    <ContextMenuItem onClick={() => { setAddress(BigInt(s.address)); setMainTab("hex"); }}>
                      Hex 查看
                    </ContextMenuItem>
                    <ContextMenuItem onClick={() => void findXrefs(s)}>查找引用 (xref to)</ContextMenuItem>
                    <ContextMenuSeparator />
                    <ContextMenuItem onClick={() => {
                      void navigator.clipboard.writeText(s.text);
                      toast.success("已复制");
                    }}>复制文本</ContextMenuItem>
                    <ContextMenuItem onClick={() => {
                      void navigator.clipboard.writeText(`0x${s.address.toString(16)}`);
                      toast.success("已复制地址");
                    }}>复制地址</ContextMenuItem>
                  </ContextMenuContent>
                </ContextMenu>
              ))}
              {filtered.length > 3000 && (
                <tr><td colSpan={3} className="py-2 text-center text-[10px] text-muted-foreground">
                  显示前 3000, 继续过滤
                </td></tr>
              )}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
