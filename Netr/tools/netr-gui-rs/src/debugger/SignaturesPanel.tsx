import { useEffect, useMemo, useState } from "react";
import { FileSearch, RefreshCw, Loader2, CheckCircle2, AlertCircle, XCircle, ArrowRightLeft, Wand2, Plus } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { dbgIpc, type StoredSig, type SigValidationResult, errMsg } from "./ipc";
import { useSession } from "./sessionStore";
import { formatAddress } from "./expr";
import { cn } from "@/lib/utils";
import {
  ContextMenu, ContextMenuContent, ContextMenuItem, ContextMenuTrigger, ContextMenuSeparator,
} from "@/components/ui/context-menu";

/**
 * 签名管理面板 (P99).
 * 列出项目里所有 signatures (builtin + user + ai), 可单条 / 全部验证, 失效自动提示用 AI.
 */
export function SignaturesPanel() {
  const { pid, setAddress, setMainTab } = useSession();
  const [sigs, setSigs] = useState<StoredSig[]>([]);
  const [busy, setBusy] = useState(false);
  const [validating, setValidating] = useState(false);
  const [q, setQ] = useState("");
  const [last, setLast] = useState<Record<string, SigValidationResult>>({});
  const [addOpen, setAddOpen] = useState(false);

  async function refresh() {
    setBusy(true);
    try { setSigs(await dbgIpc.sigList()); }
    catch (e) { toast.error(errMsg(e)); }
    finally { setBusy(false); }
  }
  useEffect(() => { void refresh(); }, []);

  async function validateAll() {
    if (!pid) return toast.error("先附加进程");
    setValidating(true);
    try {
      const r = await dbgIpc.sigValidate({ pid, sig_id: null });
      const map: Record<string, SigValidationResult> = {};
      for (const x of r.results) map[x.id] = x;
      setLast(map);
      const ok = r.results.filter((x) => x.status === "ok_unique").length;
      const drift = r.results.filter((x) => x.status === "drift").length;
      const miss = r.results.filter((x) => x.status === "miss" || x.status === "multiple_hits").length;
      toast.success(`验证完成: ${ok} OK / ${drift} drift / ${miss} 失效`);
      await refresh();
    } catch (e) { toast.error(errMsg(e)); }
    finally { setValidating(false); }
  }

  async function validateOne(id: string) {
    if (!pid) return toast.error("先附加进程");
    try {
      const r = await dbgIpc.sigValidate({ pid, sig_id: id });
      if (r.results[0]) setLast((m) => ({ ...m, [id]: r.results[0] }));
      await refresh();
    } catch (e) { toast.error(errMsg(e)); }
  }

  async function del(id: string) {
    if (!confirm(`删除签名 ${id}?`)) return;
    try {
      await dbgIpc.sigDelete(id);
      setSigs((s) => s.filter((x) => x.id !== id));
      toast.success("已删除");
    } catch (e) { toast.error(errMsg(e)); }
  }

  async function deriveAtCurrent(sig: StoredSig) {
    if (!pid) return toast.error("先附加");
    const a = sig.last_addr;
    if (!a) return toast.warning("此签名尚未命中过 — 不知该从哪 derive. 先 sig_test 一次拿命中点.");
    try {
      const r = await dbgIpc.sigDerive({ pid, address: `0x${a.toString(16)}`, length: 16 });
      // 直接覆盖 pattern
      await dbgIpc.sigSave({
        ...sig,
        pattern: r.pattern,
        source: "user",
      });
      toast.success(`已重新 derive: ${r.pattern}`);
      await refresh();
    } catch (e) { toast.error(errMsg(e)); }
  }

  const filtered = useMemo(() => {
    const lc = q.trim().toLowerCase();
    if (!lc) return sigs;
    return sigs.filter((s) =>
      s.name.toLowerCase().includes(lc) ||
      s.pattern.toLowerCase().includes(lc) ||
      (s.target_exe?.toLowerCase().includes(lc) ?? false) ||
      s.engine.some((e) => e.toLowerCase().includes(lc))
    );
  }, [sigs, q]);

  return (
    <div className="flex h-full flex-col bg-card/20">
      <div className="flex h-8 shrink-0 items-center gap-2 border-b border-border bg-card/40 px-2 text-xs">
        <FileSearch className="h-3 w-3 text-muted-foreground" />
        <span className="font-medium text-muted-foreground">签名</span>
        <Button size="sm" variant="ghost" className="h-6 px-2" onClick={() => void refresh()} disabled={busy}>
          {busy ? <Loader2 className="h-3 w-3 animate-spin" /> : <RefreshCw className="h-3 w-3" />}
        </Button>
        <Button
          size="sm" variant="outline" className="h-6 px-2"
          onClick={() => void validateAll()}
          disabled={validating || !pid}
          title="对当前进程验证所有签名"
        >
          {validating ? <Loader2 className="h-3 w-3 animate-spin" /> : <CheckCircle2 className="h-3 w-3" />}
          验证全部
        </Button>
        <Button
          size="sm" variant="outline" className="h-6 px-2"
          onClick={() => setAddOpen(true)}
          title="手动新建签名"
        >
          <Plus className="h-3 w-3" /> 新建
        </Button>
        <Input
          value={q}
          onChange={(e) => setQ(e.target.value)}
          placeholder="搜名字 / 引擎 / pattern / exe"
          className="h-6 max-w-xs text-xs"
        />
        <span className="ml-auto text-[10px] text-muted-foreground">{filtered.length} / {sigs.length}</span>
      </div>

      <div className="flex h-6 shrink-0 items-center gap-3 border-b border-border/40 bg-card/10 px-2 text-[10px] text-muted-foreground">
        <span>AI 通过 <code className="text-amber-300">sig_test / sig_derive / sig_validate / sig_save</code> 自动维护签名 — 失效会自动重新发现</span>
      </div>

      <div className="min-h-0 flex-1 overflow-auto font-mono text-[11px]">
        {filtered.length === 0 ? (
          <div className="flex h-full items-center justify-center text-muted-foreground">
            无签名 — 让 AI 帮你发现 (告诉它"扫描这个游戏的 UE 全局" / 或新建一条)
          </div>
        ) : (
          <table className="w-full border-collapse">
            <thead className="sticky top-0 bg-card/95 backdrop-blur text-[10px] uppercase tracking-wider text-muted-foreground">
              <tr>
                <th className="w-6 px-1 py-1"></th>
                <th className="px-2 py-1 text-left">名字 / 来源</th>
                <th className="w-44 px-2 py-1 text-left">引擎</th>
                <th className="w-48 px-2 py-1 text-left">上次命中</th>
                <th className="w-32 px-2 py-1 text-left">目标 exe</th>
                <th className="px-2 py-1 text-left">Pattern</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((s) => {
                const v = last[s.id];
                return (
                  <ContextMenu key={s.id}>
                    <ContextMenuTrigger asChild>
                      <tr className="border-t border-border/40 hover:bg-accent/30">
                        <td className="px-1 py-0.5 text-center align-middle">
                          <StatusIcon status={v?.status ?? (s.confirmed ? "ok_unique" : "")} />
                        </td>
                        <td className="px-2 py-0.5">
                          <div className="flex items-center gap-1">
                            <span className="font-medium text-foreground">{s.name}</span>
                            <SourceBadge source={s.source} />
                          </div>
                          {s.description && (
                            <div className="text-[10px] text-muted-foreground/70 truncate max-w-[40ch]" title={s.description}>
                              {s.description}
                            </div>
                          )}
                        </td>
                        <td className="px-2 py-0.5 text-[10px] text-muted-foreground/80">{s.engine.join(", ") || "—"}</td>
                        <td className="px-2 py-0.5 text-primary tabular-nums">
                          {s.last_addr ? formatAddress(BigInt(s.last_addr)) : <span className="text-muted-foreground/40">—</span>}
                          {v?.note && <div className="text-[10px] text-muted-foreground/60 truncate" title={v.note}>{v.note}</div>}
                        </td>
                        <td className="px-2 py-0.5 text-[10px] text-muted-foreground truncate max-w-[16ch]" title={s.target_exe ?? ""}>
                          {s.target_exe ?? "—"}
                        </td>
                        <td className="px-2 py-0.5 text-[10px] text-amber-200/80 truncate" title={s.pattern}>
                          {s.pattern}
                        </td>
                      </tr>
                    </ContextMenuTrigger>
                    <ContextMenuContent>
                      {s.last_addr && (
                        <ContextMenuItem onClick={() => { setAddress(BigInt(s.last_addr!)); setMainTab("disasm"); }}>
                          跳转上次命中地址
                        </ContextMenuItem>
                      )}
                      <ContextMenuItem onClick={() => void validateOne(s.id)}>
                        <ArrowRightLeft className="mr-2 h-3 w-3" /> 验证此签名
                      </ContextMenuItem>
                      {s.last_addr && (
                        <ContextMenuItem onClick={() => void deriveAtCurrent(s)}>
                          <Wand2 className="mr-2 h-3 w-3" /> 重新 derive (用上次命中地址)
                        </ContextMenuItem>
                      )}
                      <ContextMenuSeparator />
                      <ContextMenuItem onClick={() => {
                        void navigator.clipboard.writeText(s.pattern);
                        toast.success("Pattern 已复制");
                      }}>复制 Pattern</ContextMenuItem>
                      {s.last_addr && (
                        <ContextMenuItem onClick={() => {
                          void navigator.clipboard.writeText(`0x${s.last_addr!.toString(16)}`);
                          toast.success("地址已复制");
                        }}>复制地址</ContextMenuItem>
                      )}
                      <ContextMenuSeparator />
                      <ContextMenuItem onClick={() => void del(s.id)} className="text-red-400">删除</ContextMenuItem>
                    </ContextMenuContent>
                  </ContextMenu>
                );
              })}
            </tbody>
          </table>
        )}
      </div>

      <AddSigDialog open={addOpen} onClose={() => setAddOpen(false)} onSaved={() => { setAddOpen(false); void refresh(); }} />
    </div>
  );
}

function StatusIcon({ status }: { status: string }) {
  switch (status) {
    case "ok_unique":
      return <CheckCircle2 className="h-3 w-3 text-emerald-400" />;
    case "drift":
      return <AlertCircle className="h-3 w-3 text-amber-400" />;
    case "multiple_hits":
      return <AlertCircle className="h-3 w-3 text-amber-400" />;
    case "miss":
    case "error":
      return <XCircle className="h-3 w-3 text-red-400" />;
    default:
      return <span className="inline-block h-2 w-2 rounded-full bg-muted-foreground/40" />;
  }
}

function SourceBadge({ source }: { source: string }) {
  const cls = source === "ai" ? "bg-violet-500/15 text-violet-300"
    : source === "ai" ? "bg-violet-500/15 text-violet-300"
    : source === "user" ? "bg-emerald-500/15 text-emerald-300"
    : "bg-blue-500/15 text-blue-300";
  return <span className={cn("rounded px-1 text-[9px] font-medium uppercase", cls)}>{source}</span>;
}

function AddSigDialog({
  open, onClose, onSaved,
}: { open: boolean; onClose: () => void; onSaved: () => void }) {
  const [name, setName] = useState("");
  const [pattern, setPattern] = useState("");
  const [followRip, setFollowRip] = useState(true);
  const [scope, setScope] = useState("main_module");
  const [engine, setEngine] = useState("UE5");
  const [description, setDescription] = useState("");

  if (!open) return null;

  async function save() {
    if (!name.trim() || !pattern.trim()) return toast.error("name 和 pattern 必填");
    try {
      await dbgIpc.sigSave({
        name: name.trim(),
        pattern: pattern.trim(),
        follow_rip: followRip,
        scope: scope.trim(),
        engine: engine.split(/[,\s]+/).filter(Boolean),
        description: description.trim(),
        source: "user",
      });
      toast.success("已保存");
      onSaved();
    } catch (e) { toast.error(errMsg(e)); }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
      <div className="w-[28rem] rounded border border-border bg-card p-4 text-[11px] shadow-xl">
        <div className="mb-2 font-medium">新建签名</div>
        <div className="space-y-2">
          <Input placeholder="名字 (如 'DeltaForce GNames')" value={name} onChange={(e) => setName(e.target.value)} className="h-7" />
          <Input placeholder="Pattern (如 48 8B 05 ?? ?? ?? ??)" value={pattern} onChange={(e) => setPattern(e.target.value)} className="h-7 font-mono" />
          <div className="flex gap-2">
            <Input placeholder="引擎 (UE4,UE5,Unity-Mono...)" value={engine} onChange={(e) => setEngine(e.target.value)} className="h-7 flex-1" />
            <Input placeholder="Scope (main_module / specific_module:foo.dll / all)" value={scope} onChange={(e) => setScope(e.target.value)} className="h-7 flex-1" />
          </div>
          <label className="flex items-center gap-1 text-[11px]">
            <input type="checkbox" checked={followRip} onChange={(e) => setFollowRip(e.target.checked)} /> follow_rip (命中后解 RIP-rel)
          </label>
          <Input placeholder="说明 (可选)" value={description} onChange={(e) => setDescription(e.target.value)} className="h-7" />
        </div>
        <div className="mt-3 flex justify-end gap-2">
          <Button size="sm" variant="ghost" onClick={onClose}>取消</Button>
          <Button size="sm" onClick={() => void save()}>保存</Button>
        </div>
      </div>
    </div>
  );
}
