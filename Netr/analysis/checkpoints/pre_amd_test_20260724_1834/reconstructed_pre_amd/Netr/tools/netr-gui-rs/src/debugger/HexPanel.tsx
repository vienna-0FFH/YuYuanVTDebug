import { useEffect, useState } from "react";
import { ArrowRight, Loader2, Save, X, RefreshCw } from "lucide-react";
import { toast } from "sonner";

import { dbgIpc, errMsg } from "./ipc";
import { useSession } from "./sessionStore";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
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
import { evalExpression, formatAddress } from "./expr";
import { cn } from "@/lib/utils";

const READ_BYTES = 1024;
type Width = 8 | 16 | 32;

interface HexPanelProps {
  address?: bigint;
  onAddressChange?: (address: bigint) => void;
  showGoto?: boolean;
  title?: string;
}

export function HexPanel({
  address: controlledAddress,
  onAddressChange,
  showGoto = false,
  title = "Hex 内存",
}: HexPanelProps = {}) {
  const session = useSession();
  const pid = session.pid;
  const address = controlledAddress ?? session.followAddress ?? session.address;
  const setAddress = onAddressChange ?? session.setAddress;
  const addWatch = session.addWatch;

  const [width, setWidth] = useState<Width>(16);
  const [bytes, setBytes] = useState<number[]>([]);
  const [loading, setLoading] = useState(false);
  const [editing, setEditing] = useState<{ offset: number; text: string } | null>(null);
  const [refreshKey, setRefreshKey] = useState(0);
  const [gotoText, setGotoText] = useState("");

  async function gotoAddress() {
    const expression = gotoText.trim();
    if (!expression) return;
    try {
      const next = await evalExpression(expression, { pid: pid ?? 0, ctx: session.ctx });
      setAddress(next);
      setGotoText("");
    } catch (error) {
      toast.error(`跳转失败: ${errMsg(error)}`);
    }
  }

  async function dumpHere() {
    if (!pid || address === 0n) return;
    const sizeStr = prompt(`Dump 多少字节? (从 ${formatAddress(address)}, 上限 256MB)`, "4096");
    if (sizeStr === null) return;
    const size = Number(sizeStr);
    if (!Number.isFinite(size) || size <= 0) { toast.error("size 必须 > 0"); return; }
    try {
      toast.info("dump 中...");
      const r = await dbgIpc.dumpRegion({
        pid,
        address: `0x${address.toString(16)}`,
        size,
      });
      toast.success(`已 dump ${r.bytes_read}/${size} 字节 → ${r.path}`);
      void navigator.clipboard.writeText(r.path);
    } catch (e) { toast.error(errMsg(e)); }
  }

  useEffect(() => {
    let cancelled = false;
    if (!pid || address === 0n) { setBytes([]); return; }
    (async () => {
      setLoading(true);
      try {
        const r = await dbgIpc.readMemory(pid, Number(address), READ_BYTES);
        if (!cancelled) setBytes(r.bytes);
      } catch {
        if (!cancelled) setBytes([]);
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => { cancelled = true; };
  }, [pid, address, refreshKey]);

  async function commitEdit() {
    if (!pid || !editing) return;
    const v = parseInt(editing.text, 16);
    if (Number.isNaN(v) || v < 0 || v > 255) return toast.error("字节必须 00~FF");
    try {
      await dbgIpc.writeMemory(pid, Number(address) + editing.offset, [v]);
      toast.success("已写入");
      setEditing(null);
      setRefreshKey((k) => k + 1);
    } catch (e: unknown) {
      toast.error(`写入失败: ${errMsg(e)}`);
    }
  }

  function getU64LE(off: number): bigint | null {
    if (off + 8 > bytes.length) return null;
    let v = 0n;
    for (let i = 7; i >= 0; i--) v = (v << 8n) | BigInt(bytes[off + i]);
    return v;
  }
  function getI32LE(off: number): number | null {
    if (off + 4 > bytes.length) return null;
    const view = new DataView(new Uint8Array(bytes.slice(off, off + 4)).buffer);
    return view.getInt32(0, true);
  }
  function getF32LE(off: number): number | null {
    if (off + 4 > bytes.length) return null;
    const view = new DataView(new Uint8Array(bytes.slice(off, off + 4)).buffer);
    return view.getFloat32(0, true);
  }
  function getF64LE(off: number): number | null {
    if (off + 8 > bytes.length) return null;
    const view = new DataView(new Uint8Array(bytes.slice(off, off + 8)).buffer);
    return view.getFloat64(0, true);
  }
  function getAsciiStr(off: number, max = 128): string {
    let s = "";
    for (let i = 0; i < max && off + i < bytes.length; i++) {
      const b = bytes[off + i];
      if (b === 0) break;
      if (b < 0x20 || b >= 0x7f) return "";
      s += String.fromCharCode(b);
    }
    return s;
  }
  function getUtf16Str(off: number, max = 128): string {
    let s = "";
    for (let i = 0; i < max && off + i * 2 + 1 < bytes.length; i++) {
      const c = bytes[off + i * 2] | (bytes[off + i * 2 + 1] << 8);
      if (c === 0) break;
      if (c < 0x20 || c > 0xFFFD) return "";
      s += String.fromCharCode(c);
    }
    return s;
  }

  // 行级右键
  function RowContext({ off, children }: { off: number; children: React.ReactNode }) {
    const fieldAddr = address + BigInt(off);
    const ptrVal = getU64LE(off);
    const ascii = getAsciiStr(off);
    const utf16 = getUtf16Str(off);
    const i32 = getI32LE(off);
    const f32 = getF32LE(off);
    const f64 = getF64LE(off);
    function jumpToAddress() {
      if (onAddressChange) onAddressChange(fieldAddr);
      session.requestDisasmNavigation(fieldAddr, "force");
    }
    return (
      <ContextMenu>
        <ContextMenuTrigger asChild>{children}</ContextMenuTrigger>
        <ContextMenuContent>
          <ContextMenuItem onClick={() => {
            void navigator.clipboard.writeText(formatAddress(fieldAddr));
            toast.success("已复制");
          }}>
            复制地址
          </ContextMenuItem>
          <ContextMenuItem onClick={jumpToAddress}>跳到该地址</ContextMenuItem>
          {ptrVal !== null && (
            <ContextMenuItem onClick={() => setAddress(ptrVal)}>
              跟随指针 → 0x{ptrVal.toString(16)}
            </ContextMenuItem>
          )}
          <ContextMenuSeparator />
          <ContextMenuSub>
            <ContextMenuSubTrigger>添加到监视</ContextMenuSubTrigger>
            <ContextMenuSubContent>
              {(["i8","u8","i16","u16","i32","u32","i64","u64","f32","f64"] as const).map((t) => (
                <ContextMenuItem key={t} onClick={() => {
                  addWatch({ address: fieldAddr, description: `hex@${off.toString(16)}`, type: t });
                  toast.success(`已加监视 (${t})`);
                }}>{t}</ContextMenuItem>
              ))}
            </ContextMenuSubContent>
          </ContextMenuSub>
          <ContextMenuSeparator />
          {i32 !== null && (
            <ContextMenuItem onClick={() => {
              void navigator.clipboard.writeText(String(i32));
              toast.success("已复制 i32");
            }}>复制为 i32 = {i32}</ContextMenuItem>
          )}
          {ptrVal !== null && (
            <ContextMenuItem onClick={() => {
              void navigator.clipboard.writeText("0x" + ptrVal.toString(16));
              toast.success("已复制 i64/ptr");
            }}>复制为 i64/ptr = 0x{ptrVal.toString(16)}</ContextMenuItem>
          )}
          {f32 !== null && Number.isFinite(f32) && (
            <ContextMenuItem onClick={() => {
              void navigator.clipboard.writeText(String(f32));
              toast.success("已复制 f32");
            }}>复制为 f32 = {f32.toFixed(4)}</ContextMenuItem>
          )}
          {f64 !== null && Number.isFinite(f64) && (
            <ContextMenuItem onClick={() => {
              void navigator.clipboard.writeText(String(f64));
              toast.success("已复制 f64");
            }}>复制为 f64 = {f64.toFixed(4)}</ContextMenuItem>
          )}
          {ascii.length >= 4 && (
            <ContextMenuItem onClick={() => {
              void navigator.clipboard.writeText(ascii);
              toast.success("已复制 ASCII");
            }}>复制 ASCII = "{ascii.slice(0, 40)}{ascii.length > 40 ? "…" : ""}"</ContextMenuItem>
          )}
          {utf16.length >= 4 && (
            <ContextMenuItem onClick={() => {
              void navigator.clipboard.writeText(utf16);
              toast.success("已复制 UTF-16");
            }}>复制 UTF-16 = "{utf16.slice(0, 40)}{utf16.length > 40 ? "…" : ""}"</ContextMenuItem>
          )}
        </ContextMenuContent>
      </ContextMenu>
    );
  }

  const rows: { addr: bigint; chunk: number[]; chunkStart: number }[] = [];
  for (let i = 0; i < bytes.length; i += width) {
    rows.push({ addr: address + BigInt(i), chunk: bytes.slice(i, i + width), chunkStart: i });
  }

  return (
    <div className="flex h-full flex-col">
      <div className="flex h-9 shrink-0 items-center gap-2 border-b border-border bg-card/60 px-3 text-xs">
        <span className="font-semibold uppercase tracking-wider text-muted-foreground">{title}</span>
        <span className="font-mono text-muted-foreground/70">@ {formatAddress(address)}</span>

        {showGoto && (
          <>
            <Input
              value={gotoText}
              onChange={(event) => setGotoText(event.target.value)}
              onKeyDown={(event) => event.key === "Enter" && void gotoAddress()}
              placeholder="跳转地址"
              className="ml-2 h-6 min-w-32 max-w-64 flex-1 font-mono text-xs"
            />
            <Button size="sm" variant="outline" onClick={() => void gotoAddress()} className="h-6 px-2">
              <ArrowRight className="h-3 w-3" />
            </Button>
          </>
        )}

        <div className="ml-2 flex h-6 rounded-md border border-border bg-background p-0.5">
          {([8, 16, 32] as Width[]).map((w) => (
            <button
              key={w}
              type="button"
              onClick={() => setWidth(w)}
              className={cn(
                "rounded-sm px-2 text-[10px] font-medium transition-colors",
                width === w ? "bg-primary text-primary-foreground" : "text-muted-foreground hover:bg-accent"
              )}
            >
              {w}/行
            </button>
          ))}
        </div>

        <Button
          size="sm" variant="ghost" className="ml-auto h-6 px-2 text-[11px]"
          onClick={() => void dumpHere()}
          title="Dump 此地址到文件"
          disabled={!pid || address === 0n}
        >
          <Save className="mr-1 h-3 w-3" /> Dump
        </Button>
        <Button
          size="sm" variant="ghost" className="h-6 w-6 p-0"
          onClick={() => setRefreshKey((k) => k + 1)}
          title="刷新"
        >
          {loading ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <RefreshCw className="h-3 w-3" />}
        </Button>
      </div>

      <div className="min-h-0 flex-1 overflow-auto font-mono text-xs">
        {rows.length === 0 ? (
          <div className="flex h-full items-center justify-center text-muted-foreground">
            {loading ? "读取中..." : "无数据"}
          </div>
        ) : (
          <table className="w-full border-collapse">
            <tbody>
              {rows.map((r) => (
                <RowContext key={r.addr.toString()} off={r.chunkStart}>
                  <tr className="hover:bg-accent/40">
                    <td className="w-44 px-3 py-0.5 text-muted-foreground tabular-nums">
                      {r.addr.toString(16).padStart(16, "0")}
                    </td>
                    <td className="px-2 py-0.5 tabular-nums">
                      {r.chunk.map((b, i) => {
                        const off = r.chunkStart + i;
                        const isEdit = editing && editing.offset === off;
                        if (isEdit) {
                          return (
                            <span key={i} className="inline-flex items-center gap-1">
                              <Input
                                value={editing!.text}
                                onChange={(e) => setEditing({ offset: off, text: e.target.value })}
                                onKeyDown={(e) => {
                                  if (e.key === "Enter") commitEdit();
                                  if (e.key === "Escape") setEditing(null);
                                }}
                                autoFocus
                                maxLength={2}
                                className="inline-block h-5 w-9 px-1 font-mono text-xs"
                              />
                              <Button size="sm" variant="ghost" className="h-5 w-5 p-0" onClick={commitEdit}>
                                <Save className="h-3 w-3" />
                              </Button>
                              <Button size="sm" variant="ghost" className="h-5 w-5 p-0" onClick={() => setEditing(null)}>
                                <X className="h-3 w-3" />
                              </Button>
                            </span>
                          );
                        }
                        return (
                          <span
                            key={i}
                            onDoubleClick={() => setEditing({ offset: off, text: b.toString(16).padStart(2, "0") })}
                            className="cursor-text hover:bg-primary/20"
                            title={`+${off.toString(16)}`}
                          >
                            {b.toString(16).padStart(2, "0")}{" "}
                          </span>
                        );
                      })}
                    </td>
                    <td className="w-[16rem] px-2 py-0.5 text-muted-foreground/80 break-all">
                      {r.chunk.map((b) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : ".")).join("")}
                    </td>
                  </tr>
                </RowContext>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
