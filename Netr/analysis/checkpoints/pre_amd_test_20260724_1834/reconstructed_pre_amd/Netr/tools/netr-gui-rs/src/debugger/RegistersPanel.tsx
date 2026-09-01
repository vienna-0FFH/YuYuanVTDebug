import { useEffect, useState } from "react";
import { Loader2, RefreshCw, Save } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  ContextMenu,
  ContextMenuContent,
  ContextMenuItem,
  ContextMenuTrigger,
} from "@/components/ui/context-menu";
import { dbgIpc, type ThreadContextView, errMsg } from "./ipc";
import { useSession } from "./sessionStore";
import { cn } from "@/lib/utils";

const REG_KEYS: (keyof ThreadContextView)[] = [
  "rax", "rbx", "rcx", "rdx",
  "rsi", "rdi", "rbp", "rsp",
  "r8", "r9", "r10", "r11",
  "r12", "r13", "r14", "r15",
  "rip", "rflags",
];

export function RegistersPanel() {
  const session = useSession();
  const { selectedTid, ctx, setCtx, setAddress, requestDisasmNavigation, setMainTab, openBottomHexAt } = session;
  const [loading, setLoading] = useState(false);
  const [editing, setEditing] = useState<{ key: string; text: string } | null>(null);

  async function refresh() {
    if (!selectedTid) return;
    setLoading(true);
    try {
      const c = await dbgIpc.getThreadContext(selectedTid);
      setCtx(c);
    } catch (e: unknown) {
      toast.error(`读上下文失败: ${errMsg(e)}`);
      setCtx(null);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    if (selectedTid) void refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedTid]);

  async function commit() {
    if (!ctx || !editing) return;
    const k = editing.key as keyof ThreadContextView;
    const v = parseInt(editing.text.replace(/^0x/, ""), 16);
    if (Number.isNaN(v)) return toast.error("16 进制无效");
    const next: ThreadContextView = { ...ctx, [k]: v };
    try {
      await dbgIpc.setThreadContext(next);
      setCtx(next);
      setEditing(null);
      toast.success(`${editing.key.toUpperCase()} 已写入`);
    } catch (e: unknown) {
      toast.error(`写入失败: ${errMsg(e)}`);
    }
  }

  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="flex h-9 shrink-0 items-center gap-2 border-b border-border bg-card/60 px-3 text-xs">
        <span className="font-semibold uppercase tracking-wider text-muted-foreground">寄存器</span>
        {selectedTid ? (
          <span className="text-muted-foreground/70">TID {selectedTid}</span>
        ) : (
          <span className="pill pill-muted">未选线程</span>
        )}
        <Button size="sm" variant="ghost" onClick={refresh} className="ml-auto h-6 w-6 p-0" disabled={!selectedTid}>
          {loading ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <RefreshCw className="h-3.5 w-3.5" />}
        </Button>
      </div>
      <div className="min-h-0 flex-1 overflow-auto p-1 font-mono text-xs">
        {!ctx ? (
          <div className="flex h-full items-center justify-center text-muted-foreground">
            {loading ? "读取中..." : "选中线程后点 ⟳ 刷新"}
          </div>
        ) : (
          REG_KEYS.map((k) => {
            const v = ctx[k] as number;
            const text = v.toString(16).padStart(k === "rflags" ? 8 : 16, "0");
            const isEdit = editing?.key === k;
            return (
              <ContextMenu key={k}>
                <ContextMenuTrigger asChild>
                  <div className={cn("flex items-center gap-1 px-1 py-0.5 hover:bg-accent/40", k === "rip" && "text-info")}>
                <span className="w-12 text-muted-foreground uppercase">{k}</span>
                {isEdit ? (
                  <>
                    <Input
                      value={editing!.text}
                      onChange={(e) => setEditing({ key: k, text: e.target.value })}
                      onKeyDown={(e) => {
                        if (e.key === "Enter") commit();
                        if (e.key === "Escape") setEditing(null);
                      }}
                      autoFocus
                      className="h-5 w-44 font-mono text-xs"
                    />
                    <Button size="sm" variant="ghost" className="h-5 w-5 p-0" onClick={commit}>
                      <Save className="h-3 w-3" />
                    </Button>
                  </>
                ) : (
                  <span
                    onDoubleClick={() => {
                      if (k === "rip") {
                        requestDisasmNavigation(BigInt(v), "reveal");
                        setMainTab("disasm");
                        return;
                      }
                      setEditing({ key: k, text });
                    }}
                    onClick={() => {
                      if (k === "rip" || k === "rsp") setAddress(BigInt(v));
                    }}
                    className="cursor-pointer tabular-nums hover:bg-primary/10"
                    title={k === "rip"
                      ? "双击在反汇编中定位 RIP"
                      : k === "rsp"
                        ? "单击跳转 / 双击编辑"
                        : "双击编辑"}
                  >
                    {text}
                  </span>
                )}
                  </div>
                </ContextMenuTrigger>
                <ContextMenuContent>
                  <ContextMenuItem onClick={() => {
                    requestDisasmNavigation(BigInt(v), "force");
                    setMainTab("disasm");
                  }}>
                    反汇编窗口跳转
                  </ContextMenuItem>
                  <ContextMenuItem onClick={() => openBottomHexAt(BigInt(v))}>
                    Hex窗口跳转
                  </ContextMenuItem>
                </ContextMenuContent>
              </ContextMenu>
            );
          })
        )}
      </div>
    </div>
  );
}
