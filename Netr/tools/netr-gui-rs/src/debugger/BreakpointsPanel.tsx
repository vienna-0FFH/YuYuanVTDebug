import { useEffect } from "react";
import { CircleDot, Trash2, ArrowRight } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { dbgIpc, errMsg } from "./ipc";
import { useSession } from "./sessionStore";

export function BreakpointsPanel() {
  const { pid, bps, setBps, setAddress } = useSession();

  async function refresh() {
    if (!pid) return;
    try {
      setBps(await dbgIpc.swBpList(pid));
    } catch {
      // ignore
    }
  }

  useEffect(() => {
    if (pid) void refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [pid]);

  async function remove(addr: number) {
    if (!pid) return;
    try {
      await dbgIpc.swBpClear(pid, addr);
      await refresh();
      toast.success("断点已清除");
    } catch (e: unknown) {
      toast.error(`清除失败: ${errMsg(e)}`);
    }
  }

  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="flex h-9 shrink-0 items-center gap-2 border-b border-border bg-card/60 px-3 text-xs">
        <span className="font-semibold uppercase tracking-wider text-muted-foreground">软断点 · {bps.length}</span>
      </div>
      <div className="min-h-0 flex-1 overflow-auto font-mono text-[11px]">
        {bps.length === 0 ? (
          <div className="flex h-full items-center justify-center text-center text-muted-foreground">
            反汇编行左侧○图标设/清断点
          </div>
        ) : (
          bps.map((b) => (
            <div key={b.address} className="flex items-center gap-1 px-2 py-1 hover:bg-accent/40">
              <CircleDot className="h-3 w-3 shrink-0 text-destructive" />
              <span className="flex-1 tabular-nums">{b.address.toString(16).padStart(16, "0")}</span>
              <span className="text-muted-foreground/60">orig {b.original_byte.toString(16).padStart(2, "0")}</span>
              <Button
                size="sm"
                variant="ghost"
                className="h-5 w-5 p-0"
                onClick={() => setAddress(BigInt(b.address))}
                title="跳到此地址"
              >
                <ArrowRight className="h-3 w-3" />
              </Button>
              <Button
                size="sm"
                variant="ghost"
                className="h-5 w-5 p-0"
                onClick={() => remove(b.address)}
                title="清除"
              >
                <Trash2 className="h-3 w-3" />
              </Button>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
