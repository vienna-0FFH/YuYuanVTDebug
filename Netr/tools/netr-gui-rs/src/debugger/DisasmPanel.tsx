import { memo, useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import { Loader2, AlertTriangle, Circle, CircleDot } from "lucide-react";
import { toast } from "sonner";

import { dbgIpc, type DisasmLine, type SymbolInfo, type AnnotationsSnapshot, errMsg } from "./ipc";
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

const READ_WINDOW = 4096;

export function DisasmPanel() {
  const session = useSession();
  const { pid, address, bps, ctx, setFollow, setBps, setAddress, setMainTab, addWatch,
    annotations, refreshAnnotations } = session;

  const [lines, setLines] = useState<DisasmLine[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [truncated, setTruncated] = useState(false);
  const [selectedAddr, setSelectedAddr] = useState<bigint | null>(null);
  /** hex 字符串 → symLabel 缓存 (例: "0x7ffabc1234" → "kernel32!CreateFileW+0x10") */
  const [hexSyms, setHexSyms] = useState<Map<string, string>>(new Map());
  // P95 xref dialog
  const [xrefTarget, setXrefTarget] = useState<bigint | null>(null);
  const tableRef = useRef<HTMLTableElement>(null);
  const ripRowRef = useRef<HTMLTableRowElement>(null);
  const selectedRowRef = useRef<HTMLTableRowElement>(null);

  // 首次挂载拉一次注解
  useEffect(() => { void refreshAnnotations(); }, [refreshAnnotations]);

  useEffect(() => {
    let cancelled = false;
    if (!pid || address === 0n) {
      setLines([]);
      setHexSyms(new Map());
      return;
    }
    (async () => {
      setLoading(true);
      setError(null);
      try {
        const addrNum = Number(address);
        const r = await dbgIpc.readMemory(pid, addrNum, READ_WINDOW);
        if (cancelled) return;
        const ds = await dbgIpc.disasm(addrNum, r.bytes);
        if (cancelled) return;
        setLines(ds);
        setTruncated(r.truncated);
        // 收集所有 hex 操作数,批量解析符号
        const hexSet = new Set<string>();
        const addrSet = new Set<bigint>();
        for (const l of ds) {
          for (const v of extractAllHex(l.text)) {
            const key = "0x" + v.toString(16);
            if (!hexSet.has(key)) { hexSet.add(key); addrSet.add(v); }
          }
        }
        const addrs = Array.from(addrSet);
        if (addrs.length > 0) {
          try {
            const syms = await dbgIpc.resolveSymbols(pid, addrs.map((x) => Number(x)));
            if (cancelled) return;
            const m = new Map<string, string>();
            for (let i = 0; i < addrs.length; i++) {
              const s = syms[i];
              if (s) m.set("0x" + addrs[i].toString(16), symLabel(s));
            }
            setHexSyms(m);
          } catch { /* ignore */ }
        } else {
          setHexSyms(new Map());
        }
      } catch (e: unknown) {
        setError((e as { message?: string })?.message ?? String(e));
        setLines([]);
      } finally {
        setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [pid, address]);

  // RIP / 选中行 自动滚动到视口中央
  useEffect(() => {
    const target = selectedRowRef.current ?? ripRowRef.current;
    target?.scrollIntoView({ block: "nearest", behavior: "smooth" });
  }, [lines, selectedAddr, ctx?.rip]);

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

  // 行高 18px (text-xs leading 紧凑). 虚拟滚动用.
  const ROW_H = 18;
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

  // 当 address 变(跳转), 滚到顶
  useLayoutEffect(() => {
    const el = scrollerRef.current;
    if (el) el.scrollTop = 0;
  }, [pid, address]);

  // RIP / 选中行变化 → 居中. lines 加载完毕后跑一次, 把目标 index 转 scrollTop.
  useEffect(() => {
    const el = scrollerRef.current;
    if (!el || lines.length === 0) return;
    let targetIdx = -1;
    if (selectedAddr !== null) {
      targetIdx = lines.findIndex((l) => BigInt(l.address) === selectedAddr);
    } else if (ripAddr !== null) {
      targetIdx = lines.findIndex((l) => BigInt(l.address) === ripAddr);
    }
    if (targetIdx < 0) return;
    const targetY = targetIdx * ROW_H;
    const curTop = el.scrollTop;
    const curBottom = curTop + el.clientHeight;
    if (targetY < curTop || targetY > curBottom - ROW_H) {
      el.scrollTop = Math.max(0, targetY - el.clientHeight / 2);
    }
  }, [lines, selectedAddr, ripAddr]);

  const overscan = 8;
  const startIdx = Math.max(0, Math.floor(scrollTop / ROW_H) - overscan);
  const visibleCount = Math.ceil(viewportH / ROW_H) + overscan * 2;
  const endIdx = Math.min(lines.length, startIdx + visibleCount);
  const visible = lines.slice(startIdx, endIdx);
  const padTop = startIdx * ROW_H;
  const padBottom = (lines.length - endIdx) * ROW_H;

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

      <div ref={scrollerRef} className="min-h-0 flex-1 overflow-auto font-mono text-xs">
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
                  return (
                    <DisasmRow
                      key={l.address}
                      line={l}
                      hexSyms={hexSyms}
                      annotations={annotations}
                      isBp={bpSet.has(l.address)}
                      isRip={isRipR}
                      isSelected={isSel}
                      rowRef={isSel ? selectedRowRef : isRipR ? ripRowRef : null}
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
  line, hexSyms, annotations, isBp, isRip, isSelected, rowRef,
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
              <td colSpan={4} className="px-2 py-0.5 text-[10px] text-emerald-300">
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
            style={{ height: 18 }}
          >
            <td className="w-7 px-2 text-center align-middle">
              <button
                type="button"
                onClick={(e) => { e.stopPropagation(); onToggleBp(addr); }}
                className="opacity-70 hover:opacity-100"
                title={isBp ? "清除断点" : "设软断点 (int3)"}
              >
                {isBp
                  ? <CircleDot className="h-3 w-3 text-destructive" />
                  : <Circle className="h-3 w-3 text-muted-foreground/40" />}
              </button>
            </td>
            <td className="w-44 px-2 py-0.5 text-muted-foreground tabular-nums">
              {line.address.toString(16).padStart(16, "0")}
            </td>
            <td className="w-40 px-2 py-0.5 text-muted-foreground/60 truncate">{line.bytes_hex}</td>
            <td className="px-2 py-0.5 truncate">
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
        <ContextMenuItem onClick={() => onToggleBp(addr)}>
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

