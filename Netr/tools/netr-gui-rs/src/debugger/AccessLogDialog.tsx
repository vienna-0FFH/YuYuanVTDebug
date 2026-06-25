import { useEffect, useMemo, useState } from "react";
import { Activity, Crosshair, Trash2, ExternalLink, Pause, Play } from "lucide-react";
import { toast } from "sonner";

import { Dialog } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { dbgIpc, errMsg } from "./ipc";
import { hwbpIpc } from "@/ipc";
import { useSession } from "./sessionStore";
import { useDbgEvt } from "@/store/dbgevtStore";
import { formatAddress } from "./expr";
import { cn } from "@/lib/utils";

/**
 * P111: CE 风格 "Find out what accesses/writes this address" 弹窗.
 *
 * 行为:
 *   - 打开时: 自动占用 HWBP slot 0, 装 WRITE 或 RW 类型
 *   - 监听 dbgevt category=7 (HWBP_HIT) 的事件, 只取 target=当前 pid 的
 *   - 每条 hit 显示: 时间, RIP, module+offset, [resolveSymbol], 命中次数聚合
 *   - 关闭时: 自动 clear HWBP slot 0
 */
export function AccessLogDialog({
  open, address, mode, onOpenChange,
}: {
  open: boolean;
  /** 被监听的地址 */
  address: bigint | null;
  /** "write" = 谁改写了 / "rw" = 谁访问了 */
  mode: "write" | "rw";
  onOpenChange: (v: boolean) => void;
}) {
  const { pid } = useSession();
  const events = useDbgEvt((s) => s.events);
  const startEvt = useDbgEvt((s) => s.start);

  const [paused, setPaused] = useState(false);
  const [installed, setInstalled] = useState(false);
  const [length, setLength] = useState<1 | 2 | 4 | 8>(4);
  /** 已聚合的访问者: key = rip, value = {count, lastTs} */
  const [accesses, setAccesses] = useState<Record<string, AccessEntry>>({});
  /** 符号解析缓存 */
  const [symCache, setSymCache] = useState<Record<string, string>>({});
  /** 从打开时刻起的 seq 阈值 — 只看之后的 hit */
  const [seqStart, setSeqStart] = useState(0);

  // 打开时装 HWBP
  useEffect(() => {
    if (!open || !pid || address === null) return;
    let cancelled = false;
    (async () => {
      try {
        const me = await dbgIpc.selfPid();
        const bpType = mode === "write" ? 1 : 3;
        await hwbpIpc.set(me, pid, 0, address, length, bpType);
        if (cancelled) return;
        setInstalled(true);
        void startEvt();
        // 用当前 events 的最大 seq 当起点, 防止历史 hit 污染
        const cur = useDbgEvt.getState().events;
        const maxSeq = cur.reduce((m, e) => Math.max(m, e.sequence), 0);
        setSeqStart(maxSeq);
        setAccesses({});
        toast.success(`HWBP 已装 (slot 0, ${mode === "write" ? "WRITE" : "RW"}, ${length} 字节)`);
      } catch (e) {
        toast.error(`装 HWBP 失败: ${errMsg(e)}`);
      }
    })();
    return () => {
      cancelled = true;
      // 关闭时自动 clear
      if (pid) {
        void hwbpIpc.clear(pid, 0).catch(() => {});
      }
      setInstalled(false);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, address, mode, length, pid]);

  // 聚合 hit
  useEffect(() => {
    if (!open || paused || !pid) return;
    const targetAddr = address;
    if (targetAddr === null) return;
    const targetAddrLow = Number(BigInt.asUintN(53, targetAddr));
    for (const e of events) {
      if (e.sequence <= seqStart) continue;
      if (e.category !== 7) continue;       // HWBP_HIT
      if (e.target_pid !== pid) continue;
      // 同时只装了一个 slot, 所以这里 hit 必属于我们装的 — 不需要再筛地址.
      // 但 e.addr 是 RIP (命中线程指令地址), 不是被命中的数据地址.
      // 我们要把 RIP 作为 access key.
      const ripHex = `0x${e.addr.toString(16)}`;
      setAccesses((cur) => {
        const next = { ...cur };
        const existing = next[ripHex];
        if (existing) {
          next[ripHex] = {
            ...existing,
            count: existing.count + 1,
            lastTs: Date.now(),
          };
        } else {
          next[ripHex] = {
            rip: e.addr,
            count: 1,
            firstTs: Date.now(),
            lastTs: Date.now(),
          };
          // 触发符号解析
          if (!symCache[ripHex]) {
            void dbgIpc.resolveSymbol(pid, e.addr).then((s) => {
              if (!s) return;
              const display = s.offset === 0 ? `${s.module}!${s.name}` : `${s.module}!${s.name}+0x${s.offset.toString(16)}`;
              setSymCache((c) => ({ ...c, [ripHex]: display }));
            }).catch(() => {});
          }
        }
        return next;
      });
      void targetAddrLow; // suppress lint
    }
  }, [events, open, paused, pid, address, seqStart, symCache]);

  const sorted = useMemo(() => {
    return Object.values(accesses).sort((a, b) => b.count - a.count);
  }, [accesses]);

  function clearList() {
    setAccesses({});
    setSeqStart(useDbgEvt.getState().events.reduce((m, e) => Math.max(m, e.sequence), 0));
  }

  function jumpToRip(rip: number) {
    useSession.getState().setAddress(BigInt(rip));
    useSession.getState().setMainTab("disasm");
    onOpenChange(false);
  }

  return (
    <Dialog
      open={open}
      onClose={() => onOpenChange(false)}
      title={
        <span className="flex items-center gap-2">
          <Activity className="h-4 w-4" />
          {mode === "write" ? "找出谁改写了此地址" : "找出谁访问了此地址"}
          {address !== null && (
            <code className="ml-2 rounded bg-card/60 px-2 py-0.5 font-mono text-xs">
              {formatAddress(address)}
            </code>
          )}
        </span>
      }
      widthClass="max-w-3xl"
    >
      <div className="flex flex-col gap-2 px-3 py-2 text-[11px]">
        <div className="flex items-center gap-2">
          <span className={cn(
            "rounded px-2 py-0.5 text-[10px]",
            installed ? "bg-emerald-500/15 text-emerald-300" : "bg-muted text-muted-foreground"
          )}>
            <Crosshair className="mr-1 inline h-3 w-3" />
            {installed ? "HWBP 监听中" : "未启用"}
          </span>
          <span className="text-muted-foreground">长度</span>
          {[1, 2, 4, 8].map((n) => (
            <button
              key={n}
              type="button"
              onClick={() => setLength(n as 1 | 2 | 4 | 8)}
              className={cn(
                "rounded px-1.5 py-0.5",
                length === n ? "bg-primary text-primary-foreground" : "text-muted-foreground hover:bg-accent"
              )}
            >
              {n}
            </button>
          ))}
          <Button size="sm" variant="ghost" className="ml-auto h-6 px-2" onClick={() => setPaused((p) => !p)}>
            {paused ? <Play className="h-3 w-3" /> : <Pause className="h-3 w-3" />}
            {paused ? "继续" : "暂停"}
          </Button>
          <Button size="sm" variant="ghost" className="h-6 px-2" onClick={clearList}>
            <Trash2 className="h-3 w-3" /> 清空
          </Button>
          <span className="text-muted-foreground">共 {sorted.length} 个访问点</span>
        </div>

        <div className="max-h-[55vh] overflow-auto rounded border border-border/40 font-mono">
          {sorted.length === 0 ? (
            <div className="py-8 text-center text-muted-foreground">
              {installed ? `等待 ${mode === "write" ? "写" : "访问"} 触发...让游戏里那个变量动一下` : "..."}
            </div>
          ) : (
            <table className="w-full">
              <thead className="sticky top-0 bg-card/95 text-[10px] uppercase tracking-wider text-muted-foreground">
                <tr>
                  <th className="w-12 px-2 py-1 text-right">次数</th>
                  <th className="w-44 px-2 py-1 text-left">RIP</th>
                  <th className="px-2 py-1 text-left">符号</th>
                  <th className="w-12 px-2 py-1"></th>
                </tr>
              </thead>
              <tbody>
                {sorted.slice(0, 500).map((a) => {
                  const ripHex = `0x${a.rip.toString(16)}`;
                  const sym = symCache[ripHex];
                  return (
                    <tr
                      key={ripHex}
                      className="cursor-pointer border-t border-border/30 text-[11px] hover:bg-accent/40"
                      onClick={() => jumpToRip(a.rip)}
                    >
                      <td className="px-2 py-0.5 text-right tabular-nums text-amber-300">{a.count}</td>
                      <td className="px-2 py-0.5 text-primary">{formatAddress(BigInt(a.rip))}</td>
                      <td className="px-2 py-0.5 text-cyan-400">{sym ?? "(解析中...)"}</td>
                      <td className="px-2 py-0.5">
                        <ExternalLink className="h-3 w-3 text-muted-foreground" />
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
        <div className="text-[10px] text-muted-foreground">
          点一行 → 跳到反汇编。HWBP 在你关此窗口时自动卸。slot 0 被独占, 其他 hwbp 暂时停用。
        </div>
      </div>
    </Dialog>
  );
}

interface AccessEntry {
  rip: number;
  count: number;
  firstTs: number;
  lastTs: number;
}
