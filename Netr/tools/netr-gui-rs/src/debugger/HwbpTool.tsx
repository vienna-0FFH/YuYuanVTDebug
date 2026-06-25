import { useState } from "react";
import { Crosshair, Eraser, Plus, X } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { hwbpIpc } from "@/ipc";
import { useSession } from "./sessionStore";
import { cn } from "@/lib/utils";
import { errMsg } from "./ipc";

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
  const { pid } = useSession();
  const [list, setList] = useState<HwbpRow[]>([]);
  const [addrHex, setAddrHex] = useState("");
  const [slot, setSlot] = useState(0);
  const [bpType, setBpType] = useState(0);
  const [length, setLength] = useState(1);

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
    const v = addrHex.trim().toLowerCase().replace(/^0x/, "");
    if (!/^[0-9a-f]+$/.test(v)) return toast.error("地址必须是 16 进制");
    const addr = BigInt("0x" + v);
    const me = await selfPid();
    if (me === null) return toast.error("拿不到本程序 PID");

    try {
      await hwbpIpc.set(me, pid, slot, addr, length, bpType);
      setList((prev) =>
        [...prev.filter((r) => r.slot !== slot), { slot, address: addr, type: bpType, length }]
          .sort((a, b) => a.slot - b.slot)
      );
      toast.success(`DR${slot} 已设置 @ ${addr.toString(16)}`);
    } catch (e: unknown) {
      toast.error(`失败: ${errMsg(e)}(安全工具未加载?)`);
    }
  }

  async function clearBp(s: number) {
    if (!pid) return;
    try {
      await hwbpIpc.clear(pid, s);
      setList((prev) => prev.filter((r) => r.slot !== s));
      toast.success(`DR${s} 已清除`);
    } catch (e: unknown) {
      toast.error(`清除失败: ${errMsg(e)}`);
    }
  }

  return (
    <ToolWrap title="硬件断点" onClose={onClose}>
      <div className="space-y-3 p-3">
        <div className="rounded border border-warning/40 bg-warning/10 p-2 text-[11px] text-warning">
          ⚠ 走安全工具 hwbp IOCTL,需要安全工具已加载。
          DR 走 VMCS shadow,target 看不到 DR 修改,#DB 由 hypervisor 接管,目标侧无痕。
        </div>

        <div className="grid grid-cols-2 gap-2">
          <div className="space-y-1">
            <Label className="text-xs">地址 (hex)</Label>
            <Input
              value={addrHex}
              onChange={(e) => setAddrHex(e.target.value)}
              className="h-7 font-mono text-xs"
              placeholder="7FF6A0001234"
            />
          </div>
          <div className="space-y-1">
            <Label className="text-xs">Slot (DR0~DR3)</Label>
            <select
              value={slot}
              onChange={(e) => setSlot(Number(e.target.value))}
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
              className="h-7 w-full rounded border border-input bg-background px-2 text-xs"
            >
              {BP_LENGTHS.map((l) => <option key={l.value} value={l.value}>{l.label}</option>)}
            </select>
          </div>
        </div>

        <Button onClick={setBp} className="w-full" size="sm">
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
                  <Button size="sm" variant="ghost" className="ml-auto h-6 w-6 p-0" onClick={() => clearBp(r.slot)}>
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
