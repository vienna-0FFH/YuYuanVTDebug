import { useEffect, useState } from "react";
import { CircleDot, Trash2, ArrowRight, Plus } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { dbgIpc, errMsg } from "./ipc";
import { useSession } from "./sessionStore";
import { swBreakpointUnavailableReason } from "./capabilities";

export function BreakpointsPanel() {
  const { pid, bps, setBps, setAddress, debugMode, capabilities } = useSession();
  const unavailableReason = swBreakpointUnavailableReason(debugMode, capabilities);
  const [addressText, setAddressText] = useState("");
  const [adding, setAdding] = useState(false);

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
    if (unavailableReason) return toast.error(unavailableReason);
    try {
      await dbgIpc.swBpClear(pid, addr);
      await refresh();
      toast.success("断点已清除");
    } catch (e: unknown) {
      toast.error(`清除失败: ${errMsg(e)}`);
    }
  }

  async function add() {
    if (!pid) return;
    if (unavailableReason) return toast.error(unavailableReason);
    const normalized = addressText.trim().replace(/^0x/i, "");
    if (!/^[0-9a-f]+$/i.test(normalized)) {
      return toast.error("请输入有效的十六进制断点地址");
    }
    const address = Number(BigInt(`0x${normalized}`));
    if (!Number.isSafeInteger(address)) {
      return toast.error("断点地址超出安全整数范围");
    }
    setAdding(true);
    try {
      await dbgIpc.swBpSet(pid, address);
      await refresh();
      setAddressText("");
      toast.success(`软断点已设置 @ 0x${normalized.toUpperCase()}`);
    } catch (error) {
      toast.error(`设置失败: ${errMsg(error)}`);
    } finally {
      setAdding(false);
    }
  }

  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="flex min-h-9 shrink-0 items-center gap-2 border-b border-border bg-card/60 px-3 py-1 text-xs">
        <span className="font-semibold uppercase tracking-wider text-muted-foreground">软断点 · {bps.length}</span>
        <Input
          value={addressText}
          onChange={(event) => setAddressText(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === "Enter") void add();
          }}
          disabled={Boolean(unavailableReason) || adding}
          placeholder="地址，例如 7FF612341000"
          className="ml-auto h-7 w-52 font-mono text-xs"
        />
        <Button
          size="sm"
          variant="outline"
          className="h-7 px-2"
          onClick={() => void add()}
          disabled={Boolean(unavailableReason) || adding || !addressText.trim()}
          title={unavailableReason ?? "按地址新增软断点"}
        >
          <Plus className="h-3.5 w-3.5" /> 新增
        </Button>
        {unavailableReason && (
          <span className="pill pill-muted max-w-72 truncate" title={unavailableReason}>
            当前会话不可用
          </span>
        )}
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
                disabled={Boolean(unavailableReason)}
                title={unavailableReason ?? "清除"}
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
