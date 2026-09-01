import { useEffect, useState } from "react";
import { Crosshair, Eraser, Plus, X } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { hwbpIpc } from "@/ipc";
import { useSession } from "./sessionStore";
import { cn } from "@/lib/utils";
import { errMsg } from "./ipc";
import { hwBreakpointUnavailableReason } from "./capabilities";

const BP_TYPES = [
  { value: 0, label: "执行 (X)" },
  { value: 1, label: "写入 (W)" },
  { value: 3, label: "读写 (RW)" },
];
const BP_LENGTHS = [
  { value: 1, label: "1 字节" },
  { value: 2, label: "2 字节" },
  { value: 4, label: "4 字节" },
  { value: 8, label: "8 字节" },
];

interface HwbpRow {
  slot: number;
  address: bigint;
  type: number;
  length: number;
}

export function HwbpTool({ onClose }: { onClose: () => void }) {
  const { pid, debugMode, capabilities } = useSession();
  const unavailableReason = hwBreakpointUnavailableReason(debugMode, capabilities);
  const [list, setList] = useState<HwbpRow[]>([]);
  const [addrHex, setAddrHex] = useState("");
  const [slot, setSlot] = useState(0);
  const [bpType, setBpType] = useState(0);
  const [length, setLength] = useState(1);

  async function refresh() {
    if (!pid) {
      setList([]);
      return;
    }
    try {
      const rows = await hwbpIpc.list(pid);
      setList(rows.map((row) => ({
        slot: row.slot,
        address: BigInt(row.address),
        type: row.bp_type,
        length: row.length,
      })).sort((left, right) => left.slot - right.slot));
    } catch {
      setList([]);
    }
  }

  useEffect(() => {
    void refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [pid, debugMode]);

  async function selfPid(): Promise<number | null> {
    try {
      const { dbgIpc } = await import("./ipc");
      return await dbgIpc.selfPid();
    } catch {
      return null;
    }
  }

  async function setBp() {
    if (!pid) return toast.error("先附加进程");
    if (unavailableReason) return toast.error(unavailableReason);
    const v = addrHex.trim().toLowerCase().replace(/^0x/, "");
    if (!/^[0-9a-f]+$/.test(v)) return toast.error("地址必须是 16 进制");
    const addr = BigInt("0x" + v);
    const me = await selfPid();
    if (me === null) return toast.error("拿不到本程序 PID");

    try {
      await hwbpIpc.set(me, pid, slot, addr, length, bpType);
      await refresh();
      toast.success(`DR${slot} 已设置 @ ${addr.toString(16)}`);
    } catch (e: unknown) {
      toast.error(`失败: ${errMsg(e)}(安全工具未加载?)`);
    }
  }

  async function clearBp(s: number) {
    if (!pid) return;
    if (unavailableReason) return toast.error(unavailableReason);
    try {
      await hwbpIpc.clear(pid, s);
      await refresh();
      toast.success(`DR${s} 已清除`);
    } catch (e: unknown) {
      toast.error(`清除失败: ${errMsg(e)}`);
    }
  }

  return (
    <ToolWrap title="硬件断点" onClose={onClose}>
      <div className="space-y-3 p-3">
        <div className={cn(
          "rounded border p-2 text-[11px]",
          unavailableReason
            ? "border-muted bg-muted/30 text-muted-foreground"
            : "border-warning/40 bg-warning/10 text-warning"
        )}>
          {unavailableReason
            ? `不可用：${unavailableReason}`
            : debugMode === "vt"
              ? "VT 模式使用 EPT/VT 硬件断点，不向目标线程暴露真实 DR。"
              : "Native 模式使用 Windows 调试事件与 DR0–DR3，新线程会自动继承。"}
        </div>

        <div className="grid grid-cols-2 gap-2">
          <div className="space-y-1">
            <Label className="text-xs">地址 (hex)</Label>
            <Input
              value={addrHex}
              onChange={(e) => setAddrHex(e.target.value)}
              disabled={Boolean(unavailableReason)}
              className="h-7 font-mono text-xs"
              placeholder="7FF6A0001234"
            />
          </div>
          <div className="space-y-1">
            <Label className="text-xs">Slot (DR0~DR3)</Label>
            <select
              value={slot}
              onChange={(e) => setSlot(Number(e.target.value))}
              disabled={Boolean(unavailableReason)}
              className="h-7 w-full rounded border border-input bg-background px-2 text-xs"
            >
              {[0, 1, 2, 3].map((s) => (
                <option key={s} value={s} disabled={list.some((r) => r.slot === s)}>
                  DR{s} {list.some((r) => r.slot === s) ? "(占用)" : ""}
                </option>
              ))}
            </select>
          </div>
          <div className="space-y-1">
            <Label className="text-xs">类型</Label>
            <select
              value={bpType}
              onChange={(e) => setBpType(Number(e.target.value))}
              disabled={Boolean(unavailableReason)}
              className="h-7 w-full rounded border border-input bg-background px-2 text-xs"
            >
              {BP_TYPES.map((t) => <option key={t.value} value={t.value}>{t.label}</option>)}
            </select>
          </div>
          <div className="space-y-1">
            <Label className="text-xs">长度</Label>
            <select
              value={length}
              onChange={(e) => setLength(Number(e.target.value))}
              disabled={Boolean(unavailableReason)}
              className="h-7 w-full rounded border border-input bg-background px-2 text-xs"
            >
              {BP_LENGTHS.map((l) => <option key={l.value} value={l.value}>{l.label}</option>)}
            </select>
          </div>
        </div>

        <Button onClick={setBp} className="w-full" size="sm" disabled={Boolean(unavailableReason)}>
          <Plus className="h-3.5 w-3.5" /> 设置硬断
        </Button>

        <div className="rounded-md border">
          <div className="border-b bg-card/40 px-3 py-1.5 text-[11px] uppercase tracking-wider text-muted-foreground">
            已设置 · {list.length} / 4
          </div>
          {list.length === 0 ? (
            <div className="p-4 text-center text-xs text-muted-foreground">暂无</div>
          ) : (
            <div>
              {list.map((r) => (
                <div key={r.slot} className={cn("flex items-center gap-2 border-t border-border/40 px-3 py-1.5 text-xs first:border-t-0")}>
                  <span className="pill pill-primary">DR{r.slot}</span>
                  <span className="font-mono tabular-nums">{r.address.toString(16).padStart(16, "0")}</span>
                  <span className="text-muted-foreground">
                    {BP_TYPES.find((t) => t.value === r.type)?.label} · {r.length}B
                  </span>
                  <Button
                    size="sm"
                    variant="ghost"
                    className="ml-auto h-6 w-6 p-0"
                    onClick={() => clearBp(r.slot)}
                    disabled={Boolean(unavailableReason)}
                    title={unavailableReason ?? "清除硬件断点"}
                  >
                    <Eraser className="h-3 w-3" />
                  </Button>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </ToolWrap>
  );
}

function ToolWrap({ title, onClose, children }: { title: string; onClose: () => void; children: React.ReactNode }) {
  return (
    <div className="flex h-full flex-col">
      <div className="flex h-9 shrink-0 items-center gap-2 border-b border-border bg-card/60 px-3 text-xs">
        <Crosshair className="h-3.5 w-3.5 text-primary" />
        <span className="font-semibold uppercase tracking-wider text-muted-foreground">{title}</span>
        <Button size="sm" variant="ghost" className="ml-auto h-6 w-6 p-0" onClick={onClose}>
          <X className="h-3.5 w-3.5" />
        </Button>
      </div>
      <div className="min-h-0 flex-1 overflow-auto">{children}</div>
    </div>
  );
}
