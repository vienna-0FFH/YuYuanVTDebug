import { memo, useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import { Loader2, AlertTriangle, Circle, CircleDot } from "lucide-react";
import { toast } from "sonner";

import { dbgIpc, type DisasmLine, type SymbolInfo, type AnnotationsSnapshot, type RegionInfo, errMsg } from "./ipc";
import { useSession } from "./sessionStore";
import { cn } from "@/lib/utils";
import {
  ContextMenu,
  ContextMenuContent,
  ContextMenuItem,
  ContextMenuSeparator,
  ContextMenuShortcut,
  ContextMenuTrigger,
} from "@/components/ui/context-menu";
import { formatAddress } from "./expr";
import { XrefDialog } from "./XrefDialog";
import { tokenizeAsm, tokenizeMemoryInner, classifyMnemonic, type AsmToken } from "./asmTokenize";
import { swBreakpointUnavailableReason } from "./capabilities";

/** 抽取指令文本里第一个 4+ 位 hex 数(粗暴但实用,CE 也是这种风格) */
function extractOperandHex(text: string): bigint | null {
  const m = text.match(/0x([0-9a-fA-F]{4,})/);
  if (!m) return null;
  try { return BigInt("0x" + m[1]); } catch { return null; }
}

/** 提取指令文本里所有 4+ 位 hex 操作数,去重返回 bigint 列表 */
function extractAllHex(text: string): bigint[] {
  const out: bigint[] = [];
  const seen = new Set<string>();
  for (const m of text.matchAll(/0x[0-9a-fA-F]{4,}/g)) {
    if (seen.has(m[0])) continue;
    seen.add(m[0]);
    try { out.push(BigInt(m[0])); } catch { /* skip */ }
  }
  return out;
}

function symLabel(s: SymbolInfo): string {
  return s.offset === 0 ? `${s.module}!${s.name}` : `${s.module}!${s.name}+0x${s.offset.toString(16)}`;
}

const READ_WINDOW = 32 * 1024;
const BACK_CONTEXT = 12 * 1024;
const PAGE_SHIFT = 16 * 1024;
const WINDOW_TAIL_GUARD = 512;
const ROW_H = 20;
const FOLLOW_TRIGGER_ROW = 20;
const FOLLOW_TARGET_ROW = 6;

interface DisasmWindow {
  pid: number;
  start: bigint;
  lower: bigint;
  upper: bigint;
  anchor: bigint;
}

function chooseWindowStart(target: bigint, lower: bigint, upper: bigint): bigint {
  const windowSize = BigInt(READ_WINDOW);
  const desired = target > lower + BigInt(BACK_CONTEXT)
    ? target - BigInt(BACK_CONTEXT)
    : lower;
  let start = desired & ~0xfffn;
  if (start < lower) start = lower;
  const maxStart = upper - lower > windowSize ? upper - windowSize : lower;
  if (start > maxStart) start = maxStart;
  return start;
}

function measureRowPosition(row: HTMLTableRowElement, scroller: HTMLDivElement) {
  const rowRect = row.getBoundingClientRect();
  const scrollerRect = scroller.getBoundingClientRect();
  return {
    top: rowRect.top - scrollerRect.top,
    height: rowRect.height || ROW_H,
  };
}

function alignRowAtTarget(row: HTMLTableRowElement, scroller: HTMLDivElement) {
  const metrics = measureRowPosition(row, scroller);
  scroller.scrollTop += metrics.top - FOLLOW_TARGET_ROW * metrics.height;
}

export function DisasmPanel() {
  const session = useSession();
  const { pid, address, disasmNavigation, bps, ctx, lastHit, setFollow, setBps, setAddress,
    setMainTab, addWatch, annotations, refreshAnnotations } = session;
  const swBpReason = swBreakpointUnavailableReason(session.debugMode, session.capabilities);

  const [lines, setLines] = useState<DisasmLine[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [truncated, setTruncated] = useState(false);
  const [selectedAddr, setSelectedAddr] = useState<bigint | null>(null);
  const [regionMap, setRegionMap] = useState<{ pid: number; regions: RegionInfo[] } | null>(null);
  const [viewWindow, setViewWindow] = useState<DisasmWindow | null>(null);
  const pagingAnchorRef = useRef<bigint | null>(null);
  const pagingRef = useRef(false);
  const followedWindowStartRef = useRef<bigint | null>(null);
  const pendingPreciseFollowRef = useRef(false);
  const handledNavigationSequenceRef = useRef(0);
  /** hex 字符串 → symLabel 缓存 (例: "0x7ffabc1234" → "kernel32!CreateFileW+0x10") */
  const [hexSyms, setHexSyms] = useState<Map<string, string>>(new Map());
  // P95 xref dialog
  const [xrefTarget, setXrefTarget] = useState<bigint | null>(null);
  const tableRef = useRef<HTMLTableElement>(null);
  const ripRowRef = useRef<HTMLTableRowElement>(null);
  const addressRowRef = useRef<HTMLTableRowElement>(null);
  const selectedRowRef = useRef<HTMLTableRowElement>(null);

  // 首次挂载拉一次注解
  useEffect(() => { void refreshAnnotations(); }, [refreshAnnotations]);

  // 新的停止事件以 RIP 为权威，不能让上一次手工选中的行继续抢占自动跟随。
  useLayoutEffect(() => { setSelectedAddr(null); }, [lastHit, address, disasmNavigation.sequence]);

  useEffect(() => {
    let cancelled = false;
    setRegionMap(null);
    setViewWindow(null);
    followedWindowStartRef.current = null;
    if (!pid) return;
    void dbgIpc.listRegions(pid)
      .then((regions) => {
        if (!cancelled) setRegionMap({ pid, regions });
      })
      .catch(() => {
        if (!cancelled) setRegionMap({ pid, regions: [] });
      });
    return () => { cancelled = true; };
  }, [pid]);

  useEffect(() => {
    if (!pid || address === 0n || regionMap?.pid !== pid) {
      if (!pid || address === 0n) {
        setLines([]);
        setHexSyms(new Map());
      }
      return;
    }
    const region = regionMap.regions.find((item) => {
      const lower = BigInt(item.base);
      return address >= lower && address < lower + BigInt(item.size);
    });
    const fallbackLower = address & ~0xffffn;
    const lower = region ? BigInt(region.base) : fallbackLower;
    const upper = region ? lower + BigInt(region.size) : fallbackLower + 0x10000n;
    setViewWindow((current) => {
      const requestedEnd = current ? current.start + BigInt(READ_WINDOW) : 0n;
      const currentEnd = current && requestedEnd > current.upper ? current.upper : requestedEnd;
      const safeEnd = current && currentEnd < current.upper
        ? currentEnd - BigInt(WINDOW_TAIL_GUARD)
        : currentEnd;
      if (
        current?.pid === pid &&
        current.lower === lower &&
        current.upper === upper &&
        address >= current.start &&
        address < safeEnd &&
        address >= current.anchor
      ) {
        return current;
      }
      pagingAnchorRef.current = null;
      pagingRef.current = false;
      if (
        current?.pid === pid &&
        current.lower === lower &&
        current.upper === upper &&
        address >= current.start &&
        address < currentEnd
      ) {
        return {
          ...current,
          start: address < safeEnd
            ? current.start
            : chooseWindowStart(address, lower, upper),
          anchor: address,
        };
      }
      return { pid, start: chooseWindowStart(address, lower, upper), lower, upper, anchor: address };
    });
  }, [pid, address, regionMap, disasmNavigation.sequence]);

  useEffect(() => {
    let cancelled = false;
    if (!pid || !viewWindow || viewWindow.pid !== pid) return;
    const requestEnd = viewWindow.start + BigInt(READ_WINDOW) < viewWindow.upper
      ? viewWindow.start + BigInt(READ_WINDOW)
      : viewWindow.upper;
    const requestSize = Number(requestEnd - viewWindow.start);
    if (requestSize <= 0) return;

    void (async () => {
      setLoading(true);
      setError(null);
      try {
        const startNumber = Number(viewWindow.start);
        const result = await dbgIpc.readMemory(pid, startNumber, requestSize);
        if (cancelled) return;
        const disassembled = await dbgIpc.disasm(
          startNumber,
          result.bytes,
          Number(viewWindow.anchor)
        );
        if (cancelled) return;
        setLines(disassembled);
        setTruncated(result.truncated);

        const hexSet = new Set<string>();
        const addressSet = new Set<bigint>();
        for (const line of disassembled) {
          for (const value of extractAllHex(line.text)) {
            const key = "0x" + value.toString(16);
            if (!hexSet.has(key)) {
              hexSet.add(key);
              addressSet.add(value);
            }
          }
        }
        const addresses = Array.from(addressSet);
        if (addresses.length > 0) {
          try {
            const symbols = await dbgIpc.resolveSymbols(pid, addresses.map((value) => Number(value)));
            if (cancelled) return;
            const nextSymbols = new Map<string, string>();
            for (let index = 0; index < addresses.length; index++) {
              const symbol = symbols[index];
              if (symbol) nextSymbols.set("0x" + addresses[index].toString(16), symLabel(symbol));
            }
            setHexSyms(nextSymbols);
          } catch { /* ignore */ }
        } else {
          setHexSyms(new Map());
        }
      } catch (caught: unknown) {
        setError((caught as { message?: string })?.message ?? String(caught));
        setLines([]);
      } finally {
        if (!cancelled) {
          setLoading(false);
          pagingRef.current = false;
        }
      }
    })();
    return () => { cancelled = true; };
  }, [pid, viewWindow]);

  async function setLabel(a: bigint) {
    const key = `0x${a.toString(16)}`;
    const cur = annotations?.labels?.[key] ?? "";
    const v = prompt(`标签名 (${key}, 留空删除):`, cur);
    if (v === null) return;
    try {
      await dbgIpc.annoSetLabel(key, v);
      await refreshAnnotations();
      session.setProjectDirty(true);
      if (v) toast.success(`已设标签 ${v}`); else toast.info("已删除标签");
    } catch (e) { toast.error(errMsg(e)); }
  }
  async function setComment(a: bigint) {
    const key = `0x${a.toString(16)}`;
    const cur = annotations?.comments?.[key] ?? "";
    const v = prompt(`注释 (${key}, 留空删除):`, cur);
    if (v === null) return;
    try {
      await dbgIpc.annoSetComment(key, v);
      await refreshAnnotations();
      session.setProjectDirty(true);
      if (v) toast.success("注释已保存"); else toast.info("注释已删除");
    } catch (e) { toast.error(errMsg(e)); }
  }
  async function defineFunction(a: bigint) {
    const key = `0x${a.toString(16)}`;
    // 自动调 get_function 推 size
    let suggestedSize = 0;
    if (pid) {
      try {
        const gf = await dbgIpc.getFunction({ pid, address: Number(a) });
        if (gf.found && gf.function) suggestedSize = gf.function.size;
      } catch { /* ignore */ }
    }
    const name = prompt(`函数名 (${key}):`, annotations?.functions?.[key]?.name ?? "");
    if (name === null || !name.trim()) return;
    const sizeStr = prompt("函数大小(字节):", String(suggestedSize || 64));
    if (sizeStr === null) return;
    const size = Number(sizeStr);
    if (!Number.isFinite(size) || size <= 0) { toast.error("size 必须 > 0"); return; }
    try {
      await dbgIpc.annoDefineFunction(key, name, size);
      await dbgIpc.annoSetLabel(key, name);
      await refreshAnnotations();
      session.setProjectDirty(true);
      toast.success(`函数已定义 ${name} (${size} 字节)`);
    } catch (e) { toast.error(errMsg(e)); }
  }
  function showXrefs(a: bigint) { setXrefTarget(a); }
  async function jumpXrefFrom(a: bigint) {
    if (!pid) return;
    try {
      const r = await dbgIpc.xrefFrom({ pid, source: `0x${a.toString(16)}` });
      if (r.references.length === 0) { toast.info("此指令没有引用别处"); return; }
      // 跳第一个有效目标
      const t = r.references[0].target;
      setAddress(BigInt(t));
      toast.success(`跳到 0x${t.toString(16)} (${r.references[0].kind})`);
    } catch (e) { toast.error(errMsg(e)); }
  }

  async function toggleBp(addr: bigint) {
    if (!pid) return;
    if (swBpReason) return toast.error(swBpReason);
    const isSet = bps.some((b) => BigInt(b.address) === addr);
    try {
      if (isSet) {
        await dbgIpc.swBpClear(pid, Number(addr));
        toast.success(`断点已清除 @ ${addr.toString(16)}`);
      } else {
        await dbgIpc.swBpSet(pid, Number(addr));
        toast.success(`软断点已设 @ ${addr.toString(16)}`);
      }
      const list = await dbgIpc.swBpList(pid);
      setBps(list);
    } catch (e: unknown) {
      toast.error(`操作失败: ${errMsg(e)}`);
    }
  }

  const ripAddr = ctx ? BigInt(ctx.rip) : null;

  // P102: 优化 — 把 bps / annotation lookup 提前到 Map, 行渲染 O(1)
  const bpSet = useMemo(() => new Set(bps.map((b) => b.address)), [bps]);

  const scrollerRef = useRef<HTMLDivElement>(null);
  const [scrollTop, setScrollTop] = useState(0);
  const [viewportH, setViewportH] = useState(600);

  useEffect(() => {
    const el = scrollerRef.current;
    if (!el) return;
    const update = () => { setViewportH(el.clientHeight); setScrollTop(el.scrollTop); };
    update();
    el.addEventListener("scroll", update, { passive: true });
    const ro = new ResizeObserver(update);
    ro.observe(el);
    return () => { el.removeEventListener("scroll", update); ro.disconnect(); };
  }, []);

  // RIP 进入从上往下第 21 行时，放回第 7 行。
  // 窗口分页时优先保持分页前的首行位置，避免人工滚动被 RIP 抢回。
  useLayoutEffect(() => {
    const el = scrollerRef.current;
    if (!el || lines.length === 0) return;
    const navigationPending =
      disasmNavigation.sequence !== handledNavigationSequenceRef.current &&
      disasmNavigation.address === address;
    if (
      disasmNavigation.sequence !== handledNavigationSequenceRef.current &&
      disasmNavigation.address !== address
    ) {
      handledNavigationSequenceRef.current = disasmNavigation.sequence;
    }
    const pagingAnchor = pagingAnchorRef.current;
    if (pagingAnchor !== null && !navigationPending) {
      const anchorIndex = lines.findIndex((line) => BigInt(line.address) >= pagingAnchor);
      if (anchorIndex >= 0) el.scrollTop = anchorIndex * ROW_H;
      pagingAnchorRef.current = null;
      return;
    }
    if (navigationPending) pagingAnchorRef.current = null;
    let targetIdx = -1;
    if (navigationPending) {
      targetIdx = lines.findIndex((line) => BigInt(line.address) >= disasmNavigation.address);
    } else if (selectedAddr !== null) {
      targetIdx = lines.findIndex((line) => BigInt(line.address) >= selectedAddr);
    } else {
      targetIdx = lines.findIndex((line) => BigInt(line.address) >= address);
    }
    if (targetIdx < 0) return;
    const targetY = targetIdx * ROW_H;
    const curTop = el.scrollTop;
    const curBottom = curTop + el.clientHeight;
    const targetRow = navigationPending
      ? addressRowRef.current ?? ripRowRef.current
      : selectedAddr !== null
      ? selectedRowRef.current
      : addressRowRef.current ?? ripRowRef.current;
    const rowMetrics = targetRow ? measureRowPosition(targetRow, el) : null;
    const outsideViewport = rowMetrics
      ? rowMetrics.top < 0 || rowMetrics.top + rowMetrics.height > el.clientHeight
      : targetY < curTop || targetY + ROW_H > curBottom;
    const windowStart = BigInt(lines[0].address);
    if (navigationPending) {
      if (disasmNavigation.mode === "force" || outsideViewport) {
        if (targetRow) {
          alignRowAtTarget(targetRow, el);
        } else {
          pendingPreciseFollowRef.current = true;
          el.scrollTop = Math.max(0, (targetIdx - FOLLOW_TARGET_ROW) * ROW_H);
        }
      }
      handledNavigationSequenceRef.current = disasmNavigation.sequence;
      followedWindowStartRef.current = windowStart;
      return;
    }
    if (selectedAddr !== null) {
      if (outsideViewport) {
        if (targetRow) alignRowAtTarget(targetRow, el);
        else el.scrollTop = Math.max(0, (targetIdx - FOLLOW_TARGET_ROW) * ROW_H);
      }
      return;
    }

    const windowChanged = followedWindowStartRef.current !== windowStart;
    const distanceFromTopRows = rowMetrics
      ? rowMetrics.top / rowMetrics.height
      : (targetY - curTop) / ROW_H;
    if (
      windowChanged ||
      distanceFromTopRows < 0 ||
      distanceFromTopRows >= FOLLOW_TRIGGER_ROW
    ) {
      if (targetRow) {
        alignRowAtTarget(targetRow, el);
      } else {
        pendingPreciseFollowRef.current = true;
        el.scrollTop = Math.max(0, (targetIdx - FOLLOW_TARGET_ROW) * ROW_H);
      }
      followedWindowStartRef.current = windowStart;
    }
  }, [lines, selectedAddr, address, disasmNavigation]);

  const overscan = 8;
  const startIdx = Math.max(0, Math.floor(scrollTop / ROW_H) - overscan);
  const visibleCount = Math.ceil(viewportH / ROW_H) + overscan * 2;
  const endIdx = Math.min(lines.length, startIdx + visibleCount);
  const visible = lines.slice(startIdx, endIdx);
  const padTop = startIdx * ROW_H;
  const padBottom = (lines.length - endIdx) * ROW_H;

  useLayoutEffect(() => {
    if (!pendingPreciseFollowRef.current) return;
    const scroller = scrollerRef.current;
    const targetRow = addressRowRef.current ?? ripRowRef.current;
    if (!scroller || !targetRow) return;
    alignRowAtTarget(targetRow, scroller);
    pendingPreciseFollowRef.current = false;
  }, [startIdx, endIdx, address]);

  function pageWindow(direction: "back" | "forward", scroller: HTMLDivElement) {
    if (!viewWindow || loading || pagingRef.current || lines.length === 0) return;
    const windowSize = BigInt(READ_WINDOW);
    const shift = BigInt(PAGE_SHIFT);
    let nextStart = viewWindow.start;
    if (direction === "back") {
      if (viewWindow.start <= viewWindow.lower) return;
      nextStart = viewWindow.start - shift > viewWindow.lower
        ? viewWindow.start - shift
        : viewWindow.lower;
    } else {
      const maxStart = viewWindow.upper - viewWindow.lower > windowSize
        ? viewWindow.upper - windowSize
        : viewWindow.lower;
      if (viewWindow.start >= maxStart) return;
      nextStart = viewWindow.start + shift < maxStart
        ? viewWindow.start + shift
        : maxStart;
    }
    if (nextStart === viewWindow.start) return;
    const anchorIndex = Math.min(
      lines.length - 1,
      Math.max(0, Math.floor(scroller.scrollTop / ROW_H))
    );
    const pagingAnchor = BigInt(lines[anchorIndex].address);
    pagingAnchorRef.current = pagingAnchor;
    pagingRef.current = true;
    setViewWindow({ ...viewWindow, start: nextStart, anchor: pagingAnchor });
  }

  return (
    <div className="flex h-full flex-col">
      <PanelHeader title="反汇编" hint={`@ ${address.toString(16).toUpperCase().padStart(16, "0")}`}>
        {loading && <Loader2 className="h-3.5 w-3.5 animate-spin text-muted-foreground" />}
        {truncated && (
          <span className="pill pill-warning" title="部分页不可读用零填充">
            <AlertTriangle className="h-3 w-3" />
            部分不可读
          </span>
        )}
      </PanelHeader>

      <div
        ref={scrollerRef}
        className="selectable min-h-0 flex-1 overflow-auto font-mono text-xs"
        onWheel={(event) => {
          const scroller = event.currentTarget;
          if (event.deltaY < 0 && scroller.scrollTop <= ROW_H * 2) {
            pageWindow("back", scroller);
          } else if (
            event.deltaY > 0 &&
            scroller.scrollTop + scroller.clientHeight >= lines.length * ROW_H - ROW_H * 2
          ) {
            pageWindow("forward", scroller);
          }
        }}
      >
        {error ? (
          <div className="p-4 text-destructive">{error}</div>
        ) : lines.length === 0 ? (
          <div className="flex h-full items-center justify-center text-muted-foreground">
            {loading ? "读取中..." : "无数据"}
          </div>
        ) : (
          <>
            <div style={{ height: padTop }} />
            <table ref={tableRef} className="w-full border-collapse" style={{ tableLayout: "fixed" }}>
              <tbody>
                {visible.map((l) => {
                  const isRipR = ripAddr !== null && BigInt(l.address) === ripAddr;
                  const isSel = selectedAddr !== null && BigInt(l.address) === selectedAddr;
                  const isAddress = BigInt(l.address) === address;
                  return (
                    <DisasmRow
                      key={l.address}
                      line={l}
                      hexSyms={hexSyms}
                      annotations={annotations}
                      isBp={bpSet.has(l.address)}
                      isRip={isRipR}
                      isSelected={isSel}
                      swBpDisabledReason={swBpReason}
                      rowRef={isSel ? selectedRowRef : isAddress ? addressRowRef : isRipR ? ripRowRef : null}
                      onSelect={selectRow}
                      onToggleBp={toggleBpRow}
                      onGotoOperand={setAddress}
                      onViewInHex={viewInHex}
                      onCopyAddress={copyAddress}
                      onCopyText={copyText}
                      onAddWatch={addWatchRow}
                      onSetLabel={setLabelRow}
                      onSetComment={setCommentRow}
                      onDefineFunction={defineFunctionRow}
                      onShowXrefs={showXrefs}
                      onJumpXrefFrom={jumpXrefFromRow}
                    />
                  );
                })}
              </tbody>
            </table>
            <div style={{ height: padBottom }} />
          </>
        )}
      </div>
      <XrefDialog open={xrefTarget !== null} target={xrefTarget} onOpenChange={(v) => !v && setXrefTarget(null)} />
    </div>
  );

  // 稳定回调 — 避免每行 props 变 → memo 失效
  function selectRow(a: bigint) { setSelectedAddr(a); setFollow(a); }
  function toggleBpRow(a: bigint) { void toggleBp(a); }
  function viewInHex(a: bigint) { setAddress(a); setMainTab("hex"); }
  function copyAddress(a: bigint) { void navigator.clipboard.writeText(formatAddress(a)); toast.success("地址已复制"); }
  function copyText(t: string) { void navigator.clipboard.writeText(t); toast.success("已复制"); }
  function addWatchRow(a: bigint) {
    addWatch({ address: a, description: `disasm@${a.toString(16)}`, type: "i32" });
    toast.success("已添加到监视");
  }
  function setLabelRow(a: bigint) { void setLabel(a); }
  function setCommentRow(a: bigint) { void setComment(a); }
  function defineFunctionRow(a: bigint) { void defineFunction(a); }
  function jumpXrefFromRow(a: bigint) { void jumpXrefFrom(a); }
}

interface RowProps {
  line: DisasmLine;
  hexSyms: Map<string, string>;
  annotations: AnnotationsSnapshot | null;
  isBp: boolean;
  isRip: boolean;
  isSelected: boolean;
  swBpDisabledReason: string | null;
  rowRef: React.RefObject<HTMLTableRowElement> | null;
  onSelect: (a: bigint) => void;
  onToggleBp: (a: bigint) => void;
  onGotoOperand: (a: bigint) => void;
  onViewInHex: (a: bigint) => void;
  onCopyAddress: (a: bigint) => void;
  onCopyText: (t: string) => void;
  onAddWatch: (a: bigint) => void;
  onSetLabel: (a: bigint) => void;
  onSetComment: (a: bigint) => void;
  onDefineFunction: (a: bigint) => void;
  onShowXrefs: (a: bigint) => void;
  onJumpXrefFrom: (a: bigint) => void;
}

/** 单 token → 上色 span. 内存块二次分词. */
function renderToken(t: AsmToken, key: number, hexSyms: Map<string, string>, mnemKind: ReturnType<typeof classifyMnemonic>): React.ReactNode[] {
  switch (t.kind) {
    case "mnemonic": {
      const cls = mnemKind === "control" ? "text-cyan-400 font-semibold"
        : mnemKind === "data" ? "text-violet-400"
        : mnemKind === "arith" ? "text-orange-400"
        : mnemKind === "float" ? "text-pink-400"
        : "text-foreground/95";
      return [<span key={key} className={cls}>{t.text}</span>];
    }
    case "register":
      return [<span key={key} className="text-amber-400">{t.text}</span>];
    case "address": {
      const sym = hexSyms.get(t.text);
      if (sym) {
        return [
          <span key={key} className="text-emerald-300">{t.text}</span>,
          <span key={`s${key}`} className="ml-1 text-[10px] text-emerald-400/70">[{sym}]</span>,
        ];
      }
      return [<span key={key} className="text-emerald-300">{t.text}</span>];
    }
    case "number":
      return [<span key={key} className="text-emerald-200/90">{t.text}</span>];
    case "memory": {
      // 二次 tokenize 内部
      const inner = tokenizeMemoryInner(t.text);
      return [
        <span key={key} className="text-sky-300">
          {inner.map((ti, i) => renderToken(ti, i, hexSyms, mnemKind))}
        </span>,
      ];
    }
    case "keyword":
      return [<span key={key} className="text-blue-400/70">{t.text}</span>];
    case "punct":
      return [<span key={key} className="text-muted-foreground/70">{t.text}</span>];
    case "comment":
      return [<span key={key} className="text-muted-foreground italic">{t.text}</span>];
    case "ws":
      return [<span key={key}>{t.text}</span>];
    default:
      return [<span key={key}>{t.text}</span>];
  }
}

function DisasmRowImpl({
  line, hexSyms, annotations, isBp, isRip, isSelected, swBpDisabledReason, rowRef,
  onSelect, onToggleBp, onGotoOperand, onViewInHex,
  onCopyAddress, onCopyText, onAddWatch,
  onSetLabel, onSetComment, onDefineFunction, onShowXrefs, onJumpXrefFrom,
}: RowProps) {
  const addr = BigInt(line.address);
  const addrKey = `0x${line.address.toString(16)}`;
  const label = annotations?.labels?.[addrKey];
  const comment = annotations?.comments?.[addrKey];
  const funcDef = annotations?.functions?.[addrKey];
  const showFuncHeader = !!funcDef || !!label;

  // tokenize 这条指令 (memo per row 调用即可, React 19 自动缓存; 18 这里不再 memo, 因为 text 单次解析很快)
  const tokens = useMemo(() => tokenizeAsm(line.text), [line.text]);
  const mnemKind = useMemo(() => {
    const mnem = tokens.find((t) => t.kind === "mnemonic")?.text ?? "";
    return classifyMnemonic(mnem);
  }, [tokens]);
  const operandJump = useMemo(() => extractOperandHex(line.text), [line.text]);

  return (
    <ContextMenu>
      <ContextMenuTrigger asChild>
        <>
          {/* 函数头/标签所在地址 — 额外画一行 IDA 风格 */}
          {showFuncHeader && (
            <tr className="border-t border-emerald-500/30 bg-emerald-500/5">
              <td colSpan={4} className="cursor-text px-2 py-0.5 text-[10px] text-emerald-300">
                {funcDef ? `▸ ${funcDef.name}() — ${funcDef.size} bytes` : `: ${label}`}
              </td>
            </tr>
          )}
          <tr
            ref={rowRef ?? undefined}
            onClick={() => onSelect(addr)}
            className={cn(
              "group cursor-default",
              isSelected ? "bg-primary/20" : "hover:bg-accent/40",
              isRip && !isSelected && "bg-info/15"
            )}
            style={{ height: ROW_H }}
          >
            <td className="w-7 px-2 text-center align-middle">
              <button
                type="button"
                onClick={(e) => { e.stopPropagation(); onToggleBp(addr); }}
                disabled={Boolean(swBpDisabledReason)}
                className="opacity-70 hover:opacity-100 disabled:cursor-not-allowed disabled:opacity-25"
                title={swBpDisabledReason ?? (isBp ? "清除断点" : "设软断点 (int3)")}
              >
                {isBp
                  ? <CircleDot className="h-3 w-3 text-destructive" />
                  : <Circle className="h-3 w-3 text-muted-foreground/40" />}
              </button>
            </td>
            <td className="w-44 cursor-text px-2 py-0.5 text-muted-foreground tabular-nums">
              {line.address.toString(16).padStart(16, "0")}
            </td>
            <td className="w-40 cursor-text px-2 py-0.5 text-muted-foreground/60 truncate">{line.bytes_hex}</td>
            <td className="cursor-text px-2 py-0.5 truncate">
              {tokens.map((t, i) => renderToken(t, i, hexSyms, mnemKind))}
              {comment && (
                <span className="ml-3 text-[10px] text-emerald-400/80" title={comment}>
                  ; {comment.length > 60 ? comment.slice(0, 60) + "…" : comment}
                </span>
              )}
            </td>
          </tr>
        </>
      </ContextMenuTrigger>
      <ContextMenuContent>
        <ContextMenuItem
          onClick={() => onToggleBp(addr)}
          disabled={Boolean(swBpDisabledReason)}
          title={swBpDisabledReason ?? undefined}
        >
          {isBp ? "清除断点" : "设软断点"}
          <ContextMenuShortcut>F9</ContextMenuShortcut>
        </ContextMenuItem>
        <ContextMenuItem onClick={() => onAddWatch(addr)}>添加到监视</ContextMenuItem>
        <ContextMenuSeparator />
        <ContextMenuItem onClick={() => onShowXrefs(addr)}>查找引用 (Xrefs to)</ContextMenuItem>
        <ContextMenuItem onClick={() => onJumpXrefFrom(addr)}>跳转引用目标 (Xrefs from)</ContextMenuItem>
        <ContextMenuSeparator />
        <ContextMenuItem onClick={() => onSetLabel(addr)}>
          设标签 / 重命名
          <ContextMenuShortcut>L</ContextMenuShortcut>
        </ContextMenuItem>
        <ContextMenuItem onClick={() => onSetComment(addr)}>
          设注释
          <ContextMenuShortcut>;</ContextMenuShortcut>
        </ContextMenuItem>
        <ContextMenuItem onClick={() => onDefineFunction(addr)}>定义函数</ContextMenuItem>
        <ContextMenuSeparator />
        <ContextMenuItem onClick={() => onViewInHex(addr)}>在 Hex 视图查看</ContextMenuItem>
        {operandJump !== null && (
          <ContextMenuItem onClick={() => onGotoOperand(operandJump)}>
            跳转到操作数 0x{operandJump.toString(16)}
          </ContextMenuItem>
        )}
        <ContextMenuSeparator />
        <ContextMenuItem onClick={() => onCopyAddress(addr)}>复制地址</ContextMenuItem>
        <ContextMenuItem onClick={() => onCopyText(line.text)}>复制指令</ContextMenuItem>
        <ContextMenuItem onClick={() => onCopyText(line.bytes_hex)}>复制字节</ContextMenuItem>
      </ContextMenuContent>
    </ContextMenu>
  );
}

/** memo: 只在影响渲染的字段变时重渲染 (避免 280 行 reconciliation) */
const DisasmRow = memo(DisasmRowImpl, (a, b) => {
  if (a.line !== b.line) return false;
  if (a.isBp !== b.isBp) return false;
  if (a.isRip !== b.isRip) return false;
  if (a.isSelected !== b.isSelected) return false;
  if (a.swBpDisabledReason !== b.swBpDisabledReason) return false;
  if (a.hexSyms !== b.hexSyms) return false;
  if (a.annotations !== b.annotations) return false;
  // callbacks 由父稳定提供, 不比对
  return true;
});

function PanelHeader({
  title,
  hint,
  children,
}: {
  title: string;
  hint?: string;
  children?: React.ReactNode;
}) {
  return (
    <div className="flex h-9 shrink-0 items-center gap-2 border-b border-border bg-card/60 px-3 text-xs">
      <span className="font-semibold uppercase tracking-wider text-muted-foreground">{title}</span>
      {hint && <span className="font-mono text-muted-foreground/70">{hint}</span>}
      <div className="ml-auto flex items-center gap-1.5">{children}</div>
    </div>
  );
}

