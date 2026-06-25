import { useEffect, useMemo, useState } from "react";
import { Boxes, RefreshCw, Loader2, Search, Copy, Download, Save } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { dbgIpc, type ModuleInfo, errMsg } from "./ipc";
import { useSession } from "./sessionStore";
import { formatAddress } from "./expr";
import { ImportsExportsDialog } from "./ImportsExportsDialog";
import {
  ContextMenu,
  ContextMenuContent,
  ContextMenuItem,
  ContextMenuSeparator,
  ContextMenuTrigger,
} from "@/components/ui/context-menu";

type SortKey = "base" | "name" | "size";

export function ModulesPanel() {
  const { pid, setAddress, setMainTab } = useSession();
  const [mods, setMods] = useState<ModuleInfo[]>([]);
  const [busy, setBusy] = useState(false);
  const [q, setQ] = useState("");
  const [sort, setSort] = useState<SortKey>("base");
  const [impExpModule, setImpExpModule] = useState<string | null>(null);

  async function dumpThis(name: string) {
    if (!pid) return;
    try {
      toast.info(`正在 dump ${name}...`);
      const r = await dbgIpc.dumpModule({ pid, module_name: name, fix_sections: true });
      toast.success(`已 dump ${r.module}: ${(r.size / 1024 / 1024).toFixed(1)}MB → ${r.path}`);
      void navigator.clipboard.writeText(r.path);
    } catch (e) {
      toast.error(`Dump 失败: ${errMsg(e)}`);
    }
  }

  async function refresh() {
    if (!pid) return;
    setBusy(true);
    try {
      setMods(await dbgIpc.listModules(pid));
    } catch (e) {
      toast.error(`枚举失败: ${errMsg(e)}`);
    } finally {
      setBusy(false);
    }
  }

  useEffect(() => { void refresh(); /* eslint-disable-next-line react-hooks/exhaustive-deps */ }, [pid]);

  const filtered = useMemo(() => {
    const t = q.trim().toLowerCase();
    let xs = t ? mods.filter((m) => m.name.toLowerCase().includes(t) || m.path.toLowerCase().includes(t)) : mods.slice();
    xs.sort((a, b) => {
      if (sort === "base") return a.base - b.base;
      if (sort === "size") return b.size - a.size;
      return a.name.localeCompare(b.name);
    });
    return xs;
  }, [mods, q, sort]);

  if (!pid) return null;

  return (
    <div className="flex h-full flex-col">
      <div className="flex h-8 shrink-0 items-center gap-2 border-b border-border bg-card/40 px-2 text-xs">
        <Boxes className="h-3 w-3 text-muted-foreground" />
        <span className="font-medium text-muted-foreground">模块</span>
        <span className="text-muted-foreground/50">({filtered.length}/{mods.length})</span>

        <div className="relative ml-2 max-w-xs flex-1">
          <Search className="absolute left-2 top-1/2 h-3 w-3 -translate-y-1/2 text-muted-foreground" />
          <Input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="搜索"
            className="h-6 pl-6 text-[11px]"
          />
        </div>

        <select
          value={sort}
          onChange={(e) => setSort(e.target.value as SortKey)}
          className="h-6 rounded border border-input bg-background px-1.5 text-[10px]"
        >
          <option value="base">按 base</option>
          <option value="name">按名称</option>
          <option value="size">按大小</option>
        </select>

        <Button size="sm" variant="ghost" className="h-6 w-6 p-0" onClick={() => void refresh()} disabled={busy}>
          {busy ? <Loader2 className="h-3 w-3 animate-spin" /> : <RefreshCw className="h-3 w-3" />}
        </Button>
      </div>

      <div className="min-h-0 flex-1 overflow-auto font-mono text-[11px]">
        {filtered.length === 0 ? (
          <div className="flex h-full items-center justify-center text-muted-foreground">
            无模块
          </div>
        ) : (
          <table className="w-full border-collapse">
            <thead className="sticky top-0 bg-card/95 backdrop-blur text-[10px] uppercase tracking-wider text-muted-foreground">
              <tr>
                <th className="w-44 px-3 py-1 text-left">Base</th>
                <th className="w-20 px-2 py-1 text-right">Size</th>
                <th className="w-48 px-2 py-1 text-left">名称</th>
                <th className="px-2 py-1 text-left">路径</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((m) => (
                <ContextMenu key={m.base}>
                  <ContextMenuTrigger asChild>
                    <tr
                      className="cursor-default border-b border-border/40 hover:bg-accent/40"
                      onDoubleClick={() => {
                        setAddress(BigInt(m.base));
                        setMainTab("disasm");
                      }}
                    >
                      <td className="px-3 py-0.5 tabular-nums text-muted-foreground">
                        {formatAddress(BigInt(m.base))}
                      </td>
                      <td className="px-2 py-0.5 text-right tabular-nums text-muted-foreground/70">
                        {(m.size / 1024).toFixed(0)}K
                      </td>
                      <td className="px-2 py-0.5 font-medium">{m.name}</td>
                      <td className="px-2 py-0.5 truncate text-[10px] text-muted-foreground/70" title={m.path}>
                        {m.path}
                      </td>
                    </tr>
                  </ContextMenuTrigger>
                  <ContextMenuContent>
                    <ContextMenuItem onClick={() => { setAddress(BigInt(m.base)); setMainTab("disasm"); }}>
                      在反汇编打开 base
                    </ContextMenuItem>
                    <ContextMenuItem onClick={() => { setAddress(BigInt(m.base)); setMainTab("hex"); }}>
                      在 Hex 打开 base
                    </ContextMenuItem>
                    <ContextMenuSeparator />
                    <ContextMenuItem onClick={() => setImpExpModule(m.name)}>
                      <Download className="mr-2 h-3 w-3" /> 查看导入 / 导出
                    </ContextMenuItem>
                    <ContextMenuItem onClick={() => void dumpThis(m.name)}>
                      <Save className="mr-2 h-3 w-3" /> Dump 模块到文件
                    </ContextMenuItem>
                    <ContextMenuSeparator />
                    <ContextMenuItem onClick={() => {
                      void navigator.clipboard.writeText(formatAddress(BigInt(m.base)));
                      toast.success("base 已复制");
                    }}>
                      <Copy className="mr-2 h-3 w-3" /> 复制 base
                    </ContextMenuItem>
                    <ContextMenuItem onClick={() => {
                      void navigator.clipboard.writeText(m.path);
                      toast.success("路径已复制");
                    }}>
                      复制路径
                    </ContextMenuItem>
                  </ContextMenuContent>
                </ContextMenu>
              ))}
            </tbody>
          </table>
        )}
      </div>
      <ImportsExportsDialog
        open={impExpModule !== null}
        moduleName={impExpModule}
        onOpenChange={(v) => !v && setImpExpModule(null)}
      />
    </div>
  );
}
