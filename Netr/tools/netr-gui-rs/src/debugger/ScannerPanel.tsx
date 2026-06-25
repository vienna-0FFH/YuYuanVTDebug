import { useEffect, useState } from "react";
import { Search, RotateCcw, Loader2, ArrowRight, Ban } from "lucide-react";
import { toast } from "sonner";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { dbgIpc, emptyScanValue, type ScanHit, type ScanOp, type ScanValue, type ValueType, errMsg } from "./ipc";
import { useSession } from "./sessionStore";
import { useScanner } from "./scannerStore";
import { AccessLogDialog } from "./AccessLogDialog";
import {
  ContextMenu,
  ContextMenuContent,
  ContextMenuItem,
  ContextMenuSeparator,
  ContextMenuTrigger,
} from "@/components/ui/context-menu";
import { formatAddress } from "./expr";
import { cn } from "@/lib/utils";

interface ScanProgress {
  pct: number;
  addr: number;
  hits: number;
  cancelled?: boolean;
  done?: boolean;
}

const TYPES: { v: ValueType; label: string }[] = [
  { v: "i8", label: "Int8" },
  { v: "i16", label: "Int16" },
  { v: "i32", label: "Int32 (CE 默认)" },
  { v: "i64", label: "Int64" },
  { v: "u8", label: "UInt8" },
  { v: "u16", label: "UInt16" },
  { v: "u32", label: "UInt32" },
  { v: "u64", label: "UInt64" },
  { v: "f32", label: "Float" },
  { v: "f64", label: "Double" },
  { v: "bytes", label: "字节数组 (hex)" },
  { v: "string", label: "字符串" },
];

const FIRST_OPS: { v: ScanOp; label: string }[] = [
  { v: "exact", label: "精确等于" },
  { v: "gt", label: "大于" },
  { v: "lt", label: "小于" },
  { v: "ge", label: "大于等于" },
  { v: "le", label: "小于等于" },
  { v: "ne", label: "不等于" },
];

const NEXT_OPS: { v: ScanOp; label: string }[] = [
  ...FIRST_OPS,
  { v: "changed", label: "已改变" },
  { v: "unchanged", label: "未改变" },
  { v: "increasedby", label: "增大" },
  { v: "decreasedby", label: "减小" },
];

export function ScannerPanel({ pid }: { pid: number }) {
  const setAddress = useSession((s) => s.setAddress);
  const addWatch = useSession((s) => s.addWatch);

  // 状态外提到 zustand — tab 切换不丢
  const valueType = useScanner((s) => s.valueType);
  const setValueType = useScanner((s) => s.setValueType);
  const op = useScanner((s) => s.op);
  const setOp = useScanner((s) => s.setOp);
  const valStr = useScanner((s) => s.valStr);
  const setValStr = useScanner((s) => s.setValStr);
  const addrMin = useScanner((s) => s.addrMin);
  const setAddrMin = useScanner((s) => s.setAddrMin);
  const addrMax = useScanner((s) => s.addrMax);
  const setAddrMax = useScanner((s) => s.setAddrMax);
  const aligned = useScanner((s) => s.aligned);
  const setAligned = useScanner((s) => s.setAligned);
  const hits = useScanner((s) => s.hits);
  const total = useScanner((s) => s.total);
  const hasFirst = useScanner((s) => s.hasFirst);
  const setResult = useScanner((s) => s.setResult);
  const updateDisplays = useScanner((s) => s.updateDisplays);
  const resetStore = useScanner((s) => s.reset);

  // 切 pid 时清空(新进程的旧地址无效)
  useEffect(() => {
    const cur = useScanner.getState();
    if (cur.pid !== null && cur.pid !== pid) {
      resetStore();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [pid]);

  const [scanning, setScanning] = useState(false);
  const [progress, setProgress] = useState<ScanProgress | null>(null);
  // P111: "谁访问/谁改写" 弹窗
  const [accessDialog, setAccessDialog] = useState<{ addr: bigint; mode: "write" | "rw" } | null>(null);

  useEffect(() => {
    let un: UnlistenFn | null = null;
    void listen<ScanProgress>("scan_progress", (e) => {
      setProgress(e.payload);
      if (e.payload.done || e.payload.cancelled) {
        setTimeout(() => setProgress(null), 1500);
      }
    }).then((u) => (un = u));
    return () => { if (un) un(); };
  }, []);

  // P110: 实时刷新 hits 的 display — 200ms 一次, 只刷可见 (top 200) 防爆带宽
  useEffect(() => {
    if (!hits.length) return;
    let alive = true;
    const tick = async () => {
      const cur = useScanner.getState();
      if (!cur.hits.length) return;
      const visible = cur.hits.slice(0, 200);
      try {
        const r = await dbgIpc.scanRefresh({
          pid,
          value_type: cur.valueType,
          addresses: visible.map((h) => h.address),
        });
        if (alive) updateDisplays(r.values);
      } catch { /* ignore RPM 短暂失败 */ }
    };
    const id = setInterval(tick, 200);
    void tick();
    return () => { alive = false; clearInterval(id); };
    // 只在 hits 长度变化时重建 (避免每次 display 更新都重建 interval)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [pid, hits.length]);

  function buildValue(): ScanValue {
    const v = emptyScanValue();
    const s = valStr.trim();
    switch (valueType) {
      case "i8": case "i16": case "i32": case "i64":
      case "u8": case "u16": case "u32": case "u64":
        v.number = s ? Number(s) : null;
        break;
      case "f32": case "f64":
        v.float = s ? Number(s) : null;
        break;
      case "bytes":
        v.bytes = s
          ? s.split(/[\s,]+/).filter(Boolean).map((t) => parseInt(t, 16))
          : null;
        break;
      case "string":
        v.string = s || null;
        break;
    }
    return v;
  }

  function parseAddr(s: string): number {
    const v = parseInt(s.replace(/^0x/, ""), 16);
    return Number.isFinite(v) ? v : 0;
  }

  async function doFirst() {
    setScanning(true);
    try {
      const r = await dbgIpc.scanFirst({
        pid,
        value_type: valueType,
        op,
        value: buildValue(),
        addr_min: parseAddr(addrMin),
        addr_max: parseAddr(addrMax),
        aligned,
      });
      setResult(pid, r.hits, r.total);
      toast.success(`首次扫描完成,${r.total} 个命中(显示前 ${r.hits.length})`);
    } catch (e: unknown) {
      toast.error(`扫描失败: ${errMsg(e)}`);
    } finally {
      setScanning(false);
    }
  }

  async function doNext() {
    setScanning(true);
    try {
      const r = await dbgIpc.scanNext({ pid, op, value: buildValue() });
      setResult(pid, r.hits, r.total);
      if (r.total === 0 && r.diag && r.diag.prev_count > 0) {
        // 用户最关心的诊断: 候选 N 个, 读失败 X, 实际比对 Y, 命中 0
        const d = r.diag;
        const failPct = d.prev_count ? Math.round(d.read_failed * 100 / d.prev_count) : 0;
        if (d.read_failed > d.prev_count / 2) {
          toast.warning(
            `0 命中 — RPM 失败 ${d.read_failed}/${d.prev_count} (${failPct}%). ` +
            `进程换页/handle 失效, 试解附重新附加`
          );
        } else {
          toast.warning(
            `0 命中 — 比对 ${d.compared} 个, 无一匹配. ` +
            `检查: 值类型对吗 (i32/u32/f32)? 大小端? 值真变了吗?`
          );
        }
      } else {
        toast.success(`再次扫描完成,${r.total} 个命中`);
      }
    } catch (e: unknown) {
      toast.error(`扫描失败: ${errMsg(e)}`);
    } finally {
      setScanning(false);
    }
  }

  async function reset() {
    try { await dbgIpc.scanReset(pid); } catch { /* ignore */ }
    resetStore();
  }

  function addToWatch(h: ScanHit) {
    addWatch({
      address: BigInt(h.address),
      type: valueType,
      description: `Scan: ${h.display}`,
    });
    toast.success("已加入监视表");
  }

  return (
    <div className="grid h-full min-h-0" style={{ gridTemplateRows: "auto 1fr" }}>
      {/* 顶部:类型/对比/值 */}
      <div className="grid shrink-0 gap-3 border-b border-border bg-card/30 p-3 lg:grid-cols-[260px_180px_1fr_auto]">
        <div className="space-y-1">
          <Label className="text-xs">值类型</Label>
          <select
            value={valueType}
            onChange={(e) => setValueType(e.target.value as ValueType)}
            className="h-8 w-full rounded-md border border-input bg-background px-2 text-xs"
          >
            {TYPES.map((t) => (
              <option key={t.v} value={t.v}>{t.label}</option>
            ))}
          </select>
        </div>
        <div className="space-y-1">
          <Label className="text-xs">对比</Label>
          <select
            value={op}
            onChange={(e) => setOp(e.target.value as ScanOp)}
            className="h-8 w-full rounded-md border border-input bg-background px-2 text-xs"
          >
            {(hasFirst ? NEXT_OPS : FIRST_OPS).map((o) => (
              <option key={o.v} value={o.v}>{o.label}</option>
            ))}
          </select>
        </div>
        <div className="space-y-1">
          <Label className="text-xs">值</Label>
          <Input
            value={valStr}
            onChange={(e) => setValStr(e.target.value)}
            placeholder={valueType === "bytes" ? "48 8B 05" : valueType === "string" ? "Hello" : "数字"}
            className="h-8 font-mono text-xs"
          />
        </div>
        <div className="flex items-end gap-2">
          {!hasFirst ? (
            <Button onClick={doFirst} disabled={scanning}>
              {scanning ? <Loader2 className="h-4 w-4 animate-spin" /> : <Search className="h-4 w-4" />}
              首次扫描
            </Button>
          ) : (
            <>
              <Button onClick={doNext} disabled={scanning}>
                {scanning ? <Loader2 className="h-4 w-4 animate-spin" /> : <Search className="h-4 w-4" />}
                再次扫描
              </Button>
              <Button variant="outline" onClick={reset}>
                <RotateCcw className="h-4 w-4" /> 重置
              </Button>
            </>
          )}
          {scanning && (
            <Button variant="destructive" size="sm" onClick={() => void dbgIpc.scanCancel()}>
              <Ban className="h-3.5 w-3.5" /> 取消
            </Button>
          )}
        </div>

        <div className="col-span-full flex flex-wrap items-center gap-2 text-xs">
          <Label className="text-xs">范围</Label>
          <Input value={addrMin} onChange={(e) => setAddrMin(e.target.value)} className="h-7 w-40 font-mono text-xs" />
          <span className="text-muted-foreground">→</span>
          <Input value={addrMax} onChange={(e) => setAddrMax(e.target.value)} className="h-7 w-40 font-mono text-xs" />
          <select
            onChange={(e) => {
              const v = e.target.value;
              if (v === "all") { setAddrMin("0"); setAddrMax("7FFFFFFFFFFF"); }
              else if (v === "lo4g") { setAddrMin("0"); setAddrMax("FFFFFFFF"); }
              else if (v === "lo64k") { setAddrMin("10000"); setAddrMax("7FFFFFFF"); }
              else if (v === "stack") { setAddrMin("0"); setAddrMax("7FF000000000"); }
              e.target.value = "preset";
            }}
            defaultValue="preset"
            className="h-7 rounded-md border border-input bg-background px-1.5 text-[11px]"
          >
            <option value="preset" disabled>预设</option>
            <option value="all">全空间</option>
            <option value="lo4g">低 4GB</option>
            <option value="lo64k">低 2GB</option>
            <option value="stack">用户态</option>
          </select>
          <label
            className="flex cursor-pointer items-center gap-1 select-none text-[11px] text-muted-foreground hover:text-foreground"
            title="对齐扫描: 数值类型按 wsize 步进 (4B i32/u32/f32 只看 4B 对齐位置). 关掉用于打包数据/未对齐结构. 关掉慢 4-8x."
          >
            <input type="checkbox" checked={aligned} onChange={(e) => setAligned(e.target.checked)} className="h-3 w-3" />
            <span>对齐</span>
          </label>
          <span className="ml-auto text-muted-foreground">{total > 0 && `${total} 命中`}</span>
        </div>
      </div>

      {progress && (
        <div className="flex h-6 shrink-0 items-center gap-2 border-b border-border bg-card/40 px-2 text-[10px] text-muted-foreground">
          <div className="relative h-1.5 flex-1 overflow-hidden rounded bg-border/50">
            <div
              className={cn(
                "absolute inset-y-0 left-0 transition-all",
                progress.cancelled ? "bg-destructive" : progress.done ? "bg-success" : "bg-primary"
              )}
              style={{ width: `${progress.pct.toFixed(1)}%` }}
            />
          </div>
          <span className="tabular-nums">{progress.pct.toFixed(1)}%</span>
          <span className="text-muted-foreground/70">@ {progress.addr.toString(16)}</span>
          <span className="text-muted-foreground/70">命中 {progress.hits}</span>
        </div>
      )}

      {/* 结果列表 */}
      <div className="flex min-h-0 flex-col border-b border-border">
        <div className="flex h-8 shrink-0 items-center border-b border-border bg-card/40 px-3 text-xs text-muted-foreground">
          扫描结果 · {hits.length}{total > hits.length ? ` / ${total}` : ""}
        </div>
        <div className="min-h-0 flex-1 overflow-auto font-mono text-xs">
          {hits.length === 0 ? (
            <div className="flex h-full items-center justify-center text-muted-foreground">无</div>
          ) : (
            <table className="w-full border-collapse">
              <thead className="sticky top-0 bg-card/95 backdrop-blur text-[11px] uppercase tracking-wider text-muted-foreground">
                <tr>
                  <th className="px-3 py-1 text-left">地址</th>
                  <th className="px-2 py-1 text-left">值</th>
                  <th className="w-20 px-2 py-1 text-right">操作</th>
                </tr>
              </thead>
              <tbody>
                {hits.map((h) => {
                  const a = BigInt(h.address);
                  return (
                  <ContextMenu key={h.address}>
                    <ContextMenuTrigger asChild>
                  <tr className="border-t border-border/40 hover:bg-accent/40">
                    <td
                      className="cursor-pointer px-3 py-0.5 tabular-nums text-muted-foreground"
                      onClick={() => setAddress(a)}
                    >
                      {h.address.toString(16).padStart(16, "0")}
                    </td>
                    <td className="px-2 py-0.5">{h.display}</td>
                    <td className="px-2 py-0.5 text-right">
                      <Button size="sm" variant="ghost" className="h-5 w-5 p-0" onClick={() => addToWatch(h)}>
                        <ArrowRight className="h-3 w-3" />
                      </Button>
                    </td>
                  </tr>
                    </ContextMenuTrigger>
                    <ContextMenuContent>
                      <ContextMenuItem onClick={() => addToWatch(h)}>添加到监视</ContextMenuItem>
                      <ContextMenuSeparator />
                      <ContextMenuItem onClick={() => setAccessDialog({ addr: BigInt(h.address), mode: "write" })}>
                        🔍 找出谁改写了此地址
                      </ContextMenuItem>
                      <ContextMenuItem onClick={() => setAccessDialog({ addr: BigInt(h.address), mode: "rw" })}>
                        🔍 找出谁访问了此地址
                      </ContextMenuItem>
                      <ContextMenuSeparator />
                      <ContextMenuItem onClick={() => setAddress(a)}>跳到地址</ContextMenuItem>
                      <ContextMenuItem onClick={() => {
                        void navigator.clipboard.writeText(formatAddress(a));
                        toast.success("地址已复制");
                      }}>复制地址</ContextMenuItem>
                      <ContextMenuItem onClick={() => {
                        void navigator.clipboard.writeText(h.display);
                        toast.success("值已复制");
                      }}>复制值</ContextMenuItem>
                    </ContextMenuContent>
                  </ContextMenu>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      </div>
      <AccessLogDialog
        open={accessDialog !== null}
        address={accessDialog?.addr ?? null}
        mode={accessDialog?.mode ?? "write"}
        onOpenChange={(v) => !v && setAccessDialog(null)}
      />
    </div>
  );
}

