import { useEffect, useRef, useState } from "react";
import { Lock, LockOpen, Pencil, Trash2, Plus, ArrowRight } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { dbgIpc, type ValueType, errMsg } from "./ipc";
import { useSession, type WatchItem } from "./sessionStore";
import { cn } from "@/lib/utils";
import {
  ContextMenu,
  ContextMenuContent,
  ContextMenuItem,
  ContextMenuSeparator,
  ContextMenuSub,
  ContextMenuSubContent,
  ContextMenuSubTrigger,
  ContextMenuTrigger,
} from "@/components/ui/context-menu";
import { formatAddress } from "./expr";
import { AccessLogDialog } from "./AccessLogDialog";

const TYPES: ValueType[] = [
  "i8", "u8", "i16", "u16", "i32", "u32", "i64", "u64", "f32", "f64", "bytes", "string",
];

export function WatchTable() {
  const { pid, watches, addWatch, removeWatch, updateWatch, clearWatches, setAddress, setMainTab } = useSession();
  const [editing, setEditing] = useState<{ id: string; field: "value" | "desc"; text: string } | null>(null);
  const [adding, setAdding] = useState(false);
  const [newAddr, setNewAddr] = useState("");
  const [accessDialog, setAccessDialog] = useState<{ addr: bigint; mode: "write" | "rw" } | null>(null);
  const [newType, setNewType] = useState<ValueType>("i32");
  const [newDesc, setNewDesc] = useState("");

  const pollRef = useRef<number | null>(null);

  // 1Hz 后台轮询读各 watch 的当前值
  useEffect(() => {
    if (!pid || watches.length === 0) {
      if (pollRef.current) {
        clearInterval(pollRef.current);
        pollRef.current = null;
      }
      return;
    }
    const tick = async () => {
      for (const w of watches) {
        const wsize = sizeOf(w.type);
        try {
          const r = await dbgIpc.readMemory(pid, Number(w.address), wsize);
          const cur = formatBytes(w.type, r.bytes.slice(0, wsize));
          updateWatch(w.id, { display: cur });
        } catch {
          updateWatch(w.id, { display: "??" });
        }
      }
    };
    void tick();
    const id = window.setInterval(tick, 1000);
    pollRef.current = id as unknown as number;
    return () => clearInterval(id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [pid, watches.length]);

  function addManual() {
    const addr = parseHex(newAddr);
    if (addr === null) return toast.error("地址必须是 16 进制");
    addWatch({
      address: addr,
      type: newType,
      description: newDesc || "(无标签)",
    });
    setNewAddr("");
    setNewDesc("");
    setAdding(false);
  }

  async function commitValueEdit(w: WatchItem) {
    if (!pid || !editing) return;
    const bytes = parseValueText(w.type, editing.text);
    if (!bytes) return toast.error("值格式错误");
    try {
      await dbgIpc.writeMemory(pid, Number(w.address), bytes);
      // 如果在 frozen 状态,同步更新 frozen bytes
      if (w.frozen) {
        await dbgIpc.freezeSet(pid, Number(w.address), bytes);
        updateWatch(w.id, { frozenBytes: bytes });
      }
      setEditing(null);
      toast.success("已写入");
    } catch (e: unknown) {
      toast.error(`写入失败: ${errMsg(e)}`);
    }
  }

  async function toggleFreeze(w: WatchItem) {
    if (!pid) return;
    if (w.frozen) {
      try {
        await dbgIpc.freezeClear(pid, Number(w.address));
        updateWatch(w.id, { frozen: false, frozenBytes: undefined });
        toast.success("解冻");
      } catch (e: unknown) {
        toast.error(`解冻失败: ${errMsg(e)}`);
      }
    } else {
      // 用当前值锁定
      const bytes = parseValueText(w.type, w.display);
      if (!bytes) return toast.error("当前值无法解析,无法锁定");
      try {
        await dbgIpc.freezeSet(pid, Number(w.address), bytes);
        updateWatch(w.id, { frozen: true, frozenBytes: bytes });
        toast.success("已锁定(10Hz 写回)");
      } catch (e: unknown) {
        toast.error(`锁定失败: ${errMsg(e)}`);
      }
    }
  }

  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="flex h-9 shrink-0 items-center gap-2 border-b border-border bg-card/40 px-3 text-xs">
        <span className="font-semibold uppercase tracking-wider text-muted-foreground">监视表 · {watches.length}</span>
        {watches.some((w) => w.frozen) && (
          <span className="pill pill-warning">
            <Lock className="h-3 w-3" /> {watches.filter((w) => w.frozen).length} 锁定
          </span>
        )}
        <Button size="sm" variant="ghost" className="ml-auto h-6 px-2 text-xs" onClick={() => setAdding((v) => !v)}>
          <Plus className="h-3 w-3" /> 添加
        </Button>
        {watches.length > 0 && (
          <Button size="sm" variant="ghost" className="h-6 px-2 text-xs" onClick={clearWatches}>清空</Button>
        )}
      </div>

      {adding && (
        <div className="flex shrink-0 items-end gap-2 border-b border-border bg-card/20 p-2">
          <div className="flex-1 space-y-0.5">
            <label className="text-[10px] uppercase tracking-wider text-muted-foreground">地址 (hex)</label>
            <Input
              autoFocus
              value={newAddr}
              onChange={(e) => setNewAddr(e.target.value)}
              placeholder="7FF6A0001234"
              className="h-7 font-mono text-xs"
              onKeyDown={(e) => e.key === "Enter" && addManual()}
            />
          </div>
          <div className="w-24 space-y-0.5">
            <label className="text-[10px] uppercase tracking-wider text-muted-foreground">类型</label>
            <select
              value={newType}
              onChange={(e) => setNewType(e.target.value as ValueType)}
              className="h-7 w-full rounded-md border border-input bg-background px-2 text-xs"
            >
              {TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
            </select>
          </div>
          <div className="flex-1 space-y-0.5">
            <label className="text-[10px] uppercase tracking-wider text-muted-foreground">标签</label>
            <Input
              value={newDesc}
              onChange={(e) => setNewDesc(e.target.value)}
              placeholder="标签"
              className="h-7 text-xs"
              onKeyDown={(e) => e.key === "Enter" && addManual()}
            />
          </div>
          <Button size="sm" className="h-7" onClick={addManual}>添加</Button>
          <Button size="sm" variant="ghost" className="h-7" onClick={() => setAdding(false)}>取消</Button>
        </div>
      )}

      <div className="min-h-0 flex-1 overflow-auto font-mono text-xs">
        {watches.length === 0 ? (
          <div className="flex h-full items-center justify-center text-muted-foreground">
            —
          </div>
        ) : (
          <table className="w-full border-collapse">
            <thead className="sticky top-0 bg-card/95 text-[11px] uppercase tracking-wider text-muted-foreground backdrop-blur">
              <tr className="border-b border-border">
                <th className="w-8 px-2 py-1"></th>
                <th className="px-2 py-1 text-left">标签</th>
                <th className="w-40 px-2 py-1 text-left">地址</th>
                <th className="w-14 px-2 py-1 text-left">类型</th>
                <th className="px-2 py-1 text-left">当前值</th>
                <th className="w-28 px-2 py-1 text-right">操作</th>
              </tr>
            </thead>
            <tbody>
              {watches.map((w) => (
                <ContextMenu key={w.id}>
                  <ContextMenuTrigger asChild>
                <tr className={cn("border-b border-border/40 hover:bg-accent/40", w.frozen && "bg-warning/5")}>
                  <td className="px-2 py-0.5">
                    <button
                      type="button"
                      onClick={() => toggleFreeze(w)}
                      className={cn("opacity-80 hover:opacity-100", w.frozen && "text-warning")}
                      title={w.frozen ? "解锁" : "锁定值"}
                    >
                      {w.frozen ? <Lock className="h-3.5 w-3.5" /> : <LockOpen className="h-3.5 w-3.5" />}
                    </button>
                  </td>
                  <td className="px-2 py-0.5">
                    {editing?.id === w.id && editing.field === "desc" ? (
                      <Input
                        autoFocus
                        value={editing.text}
                        onChange={(e) => setEditing({ ...editing, text: e.target.value })}
                        onKeyDown={(e) => {
                          if (e.key === "Enter") {
                            updateWatch(w.id, { description: editing.text });
                            setEditing(null);
                          }
                          if (e.key === "Escape") setEditing(null);
                        }}
                        className="h-5 text-xs"
                      />
                    ) : (
                      <span
                        onDoubleClick={() => setEditing({ id: w.id, field: "desc", text: w.description })}
                        className="cursor-text"
                      >
                        {w.description}
                      </span>
                    )}
                  </td>
                  <td
                    className="cursor-pointer px-2 py-0.5 tabular-nums text-muted-foreground"
                    onClick={() => setAddress(w.address)}
                  >
                    {w.address.toString(16).padStart(16, "0")}
                  </td>
                  <td className="px-2 py-0.5">
                    <select
                      value={w.type}
                      onChange={(e) => updateWatch(w.id, { type: e.target.value as ValueType })}
                      className="h-5 w-full rounded border border-input bg-background px-1 text-[11px]"
                    >
                      {TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
                    </select>
                  </td>
                  <td className="px-2 py-0.5">
                    {editing?.id === w.id && editing.field === "value" ? (
                      <Input
                        autoFocus
                        value={editing.text}
                        onChange={(e) => setEditing({ ...editing, text: e.target.value })}
                        onKeyDown={(e) => {
                          if (e.key === "Enter") commitValueEdit(w);
                          if (e.key === "Escape") setEditing(null);
                        }}
                        className="h-5 text-xs"
                      />
                    ) : (
                      <span
                        onDoubleClick={() => setEditing({ id: w.id, field: "value", text: w.display })}
                        className={cn("cursor-text", w.frozen && "font-semibold text-warning")}
                      >
                        {w.display}
                      </span>
                    )}
                  </td>
                  <td className="px-2 py-0.5 text-right">
                    <Button size="sm" variant="ghost" className="h-5 w-5 p-0"
                      onClick={() => setEditing({ id: w.id, field: "value", text: w.display })}
                      title="编辑值"
                    >
                      <Pencil className="h-3 w-3" />
                    </Button>
                    <Button size="sm" variant="ghost" className="h-5 w-5 p-0"
                      onClick={() => setAddress(w.address)}
                      title="跳到地址"
                    >
                      <ArrowRight className="h-3 w-3" />
                    </Button>
                    <Button size="sm" variant="ghost" className="h-5 w-5 p-0"
                      onClick={() => removeWatch(w.id)}
                      title="删除"
                    >
                      <Trash2 className="h-3 w-3" />
                    </Button>
                  </td>
                </tr>
                  </ContextMenuTrigger>
                  <ContextMenuContent>
                    <ContextMenuItem onClick={() => setEditing({ id: w.id, field: "value", text: w.display })}>
                      修改值
                    </ContextMenuItem>
                    <ContextMenuItem onClick={() => setEditing({ id: w.id, field: "desc", text: w.description })}>
                      重命名标签
                    </ContextMenuItem>
                    <ContextMenuItem onClick={() => void toggleFreeze(w)}>
                      {w.frozen ? "解锁" : "锁定值"}
                    </ContextMenuItem>
                    <ContextMenuSeparator />
                    <ContextMenuSub>
                      <ContextMenuSubTrigger>改类型</ContextMenuSubTrigger>
                      <ContextMenuSubContent>
                        {TYPES.map((t) => (
                          <ContextMenuItem key={t} onClick={() => updateWatch(w.id, { type: t })}>
                            {t}
                          </ContextMenuItem>
                        ))}
                      </ContextMenuSubContent>
                    </ContextMenuSub>
                    <ContextMenuItem onClick={() => { setAddress(w.address); setMainTab("hex"); }}>
                      在 Hex 视图查看
                    </ContextMenuItem>
                    <ContextMenuItem onClick={() => { setAddress(w.address); setMainTab("disasm"); }}>
                      在反汇编查看
                    </ContextMenuItem>
                    <ContextMenuSeparator />
                    <ContextMenuItem onClick={() => setAccessDialog({ addr: w.address, mode: "write" })}>
                      🔍 找出谁改写了此地址
                    </ContextMenuItem>
                    <ContextMenuItem onClick={() => setAccessDialog({ addr: w.address, mode: "rw" })}>
                      🔍 找出谁访问了此地址
                    </ContextMenuItem>
                    <ContextMenuSeparator />
                    <ContextMenuItem onClick={() => {
                      void navigator.clipboard.writeText(formatAddress(w.address));
                      toast.success("地址已复制");
                    }}>
                      复制地址
                    </ContextMenuItem>
                    <ContextMenuItem onClick={() => removeWatch(w.id)} className="text-destructive">
                      删除
                    </ContextMenuItem>
                  </ContextMenuContent>
                </ContextMenu>
              ))}
            </tbody>
          </table>
        )}
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

// ===== utils =====
function parseHex(s: string): bigint | null {
  const v = s.trim().toLowerCase().replace(/^0x/, "");
  if (!/^[0-9a-f]+$/.test(v)) return null;
  return BigInt("0x" + v);
}

function sizeOf(t: ValueType): number {
  switch (t) {
    case "i8": case "u8": return 1;
    case "i16": case "u16": return 2;
    case "i32": case "u32": case "f32": return 4;
    case "i64": case "u64": case "f64": return 8;
    case "bytes": case "string": return 16;
  }
}

function formatBytes(t: ValueType, b: number[]): string {
  if (b.length === 0) return "??";
  const view = new DataView(new Uint8Array(b).buffer);
  switch (t) {
    case "i8": return String(view.getInt8(0));
    case "u8": return String(view.getUint8(0));
    case "i16": return String(view.getInt16(0, true));
    case "u16": return String(view.getUint16(0, true));
    case "i32": return String(view.getInt32(0, true));
    case "u32": return String(view.getUint32(0, true));
    case "i64": return String(view.getBigInt64(0, true));
    case "u64": return String(view.getBigUint64(0, true));
    case "f32": return String(view.getFloat32(0, true));
    case "f64": return String(view.getFloat64(0, true));
    default: return b.map((x) => x.toString(16).padStart(2, "0")).join(" ");
  }
}

function parseValueText(t: ValueType, s: string): number[] | null {
  const trim = s.trim();
  if (!trim) return null;
  try {
    if (t === "bytes") return trim.split(/[\s,]+/).filter(Boolean).map((x) => parseInt(x, 16));
    if (t === "string") return Array.from(new TextEncoder().encode(trim));
    const buf = new ArrayBuffer(sizeOf(t));
    const view = new DataView(buf);
    switch (t) {
      case "i8": view.setInt8(0, Number(trim)); break;
      case "u8": view.setUint8(0, Number(trim)); break;
      case "i16": view.setInt16(0, Number(trim), true); break;
      case "u16": view.setUint16(0, Number(trim), true); break;
      case "i32": view.setInt32(0, Number(trim), true); break;
      case "u32": view.setUint32(0, Number(trim), true); break;
      case "i64": view.setBigInt64(0, BigInt(trim), true); break;
      case "u64": view.setBigUint64(0, BigInt(trim), true); break;
      case "f32": view.setFloat32(0, Number(trim), true); break;
      case "f64": view.setFloat64(0, Number(trim), true); break;
    }
    return Array.from(new Uint8Array(buf));
  } catch {
    return null;
  }
}
