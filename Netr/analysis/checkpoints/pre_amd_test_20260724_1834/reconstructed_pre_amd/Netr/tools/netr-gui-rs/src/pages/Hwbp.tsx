import { useState } from "react";
import { Crosshair, Eraser } from "lucide-react";
import { toast } from "sonner";

import { PageHeader } from "@/components/common/PageHeader";
import { ProcessPicker } from "@/components/common/ProcessPicker";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { hwbpIpc, type ProcessInfo } from "@/ipc";

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

interface HwbpEntry {
  targetPid: number;
  slot: number;
  address: string;
  type: number;
  length: number;
}

export default function Hwbp() {
  const [debuggerProc, setDebuggerProc] = useState<ProcessInfo | null>(null);
  const [targetProc, setTargetProc] = useState<ProcessInfo | null>(null);
  const [slot, setSlot] = useState("0");
  const [addrHex, setAddrHex] = useState("");
  const [length, setLength] = useState(1);
  const [bpType, setBpType] = useState(0);
  const [busy, setBusy] = useState(false);
  const [list, setList] = useState<HwbpEntry[]>([]);

  function parseAddr(s: string): bigint | null {
    const v = s.trim().toLowerCase().replace(/^0x/, "");
    if (!/^[0-9a-f]+$/.test(v)) {
      toast.error("地址必须是 16 进制");
      return null;
    }
    return BigInt("0x" + v);
  }

  async function onSet() {
    if (!debuggerProc) return toast.error("请选择调试器进程");
    if (!targetProc) return toast.error("请选择被调试进程");
    const s = Number(slot);
    if (s < 0 || s > 3) return toast.error("Slot 必须 0~3");
    const a = parseAddr(addrHex);
    if (a === null) return;

    setBusy(true);
    try {
      await hwbpIpc.set(debuggerProc.pid, targetProc.pid, s, a, length, bpType);
      const entry: HwbpEntry = {
        targetPid: targetProc.pid,
        slot: s,
        address: "0x" + a.toString(16),
        type: bpType,
        length,
      };
      setList((prev) => [...prev.filter((e) => !(e.targetPid === targetProc.pid && e.slot === s)), entry]);
      toast.success(`DR${s} 已设置 @ ${entry.address}`);
    } catch (e: unknown) {
      const msg = (e as { message?: string })?.message ?? String(e);
      toast.error(`设置失败: ${msg}`);
    } finally {
      setBusy(false);
    }
  }

  async function onClear(entry: HwbpEntry) {
    setBusy(true);
    try {
      await hwbpIpc.clear(entry.targetPid, entry.slot);
      setList((prev) => prev.filter((e) => !(e.targetPid === entry.targetPid && e.slot === entry.slot)));
      toast.success(`DR${entry.slot} 已清除`);
    } catch (e: unknown) {
      const msg = (e as { message?: string })?.message ?? String(e);
      toast.error(`清除失败: ${msg}`);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="硬件断点"
      />

      <Card>
        <CardHeader>
          <CardTitle>设置断点</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="grid gap-3 lg:grid-cols-2">
            <div className="space-y-1.5">
              <Label>调试器进程</Label>
              <ProcessPicker value={debuggerProc} onChange={setDebuggerProc} disabled={busy} placeholder="如 ce.exe" />
            </div>
            <div className="space-y-1.5">
              <Label>被调试进程</Label>
              <ProcessPicker value={targetProc} onChange={setTargetProc} disabled={busy} placeholder="目标游戏 / 程序" />
            </div>
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="hw-slot">Slot (DR0~DR3)</Label>
            <Input id="hw-slot" type="number" min={0} max={3} value={slot} onChange={(e) => setSlot(e.target.value)} className="w-32" />
          </div>

          <div className="space-y-2">
            <Label htmlFor="hw-addr">地址 (hex)</Label>
            <Input id="hw-addr" value={addrHex} onChange={(e) => setAddrHex(e.target.value)} placeholder="7FF6A0001234" />
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-2">
              <Label>类型</Label>
              <select
                className="h-9 w-full rounded-md border border-input bg-background px-3 text-sm"
                value={bpType}
                onChange={(e) => setBpType(Number(e.target.value))}
              >
                {BP_TYPES.map((t) => (
                  <option key={t.value} value={t.value}>
                    {t.label}
                  </option>
                ))}
              </select>
            </div>
            <div className="space-y-2">
              <Label>长度</Label>
              <select
                className="h-9 w-full rounded-md border border-input bg-background px-3 text-sm"
                value={length}
                onChange={(e) => setLength(Number(e.target.value))}
              >
                {BP_LENGTHS.map((l) => (
                  <option key={l.value} value={l.value}>
                    {l.label}
                  </option>
                ))}
              </select>
            </div>
          </div>

          <Button onClick={onSet} disabled={busy}>
            <Crosshair className="h-4 w-4" /> 设置断点
          </Button>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>已设置</CardTitle>
        </CardHeader>
        <CardContent>
          {list.length === 0 ? (
            <div className="text-sm text-muted-foreground">暂无</div>
          ) : (
            <div className="space-y-2">
              {list.map((e, i) => (
                <div key={`${e.targetPid}-${e.slot}-${i}`} className="flex items-center justify-between rounded-md border bg-card/40 px-3 py-2">
                  <div className="flex items-center gap-3 text-sm">
                    <span className="font-mono">PID {e.targetPid}</span>
                    <span className="rounded bg-muted px-2 py-0.5 text-xs">DR{e.slot}</span>
                    <span className="font-mono">{e.address}</span>
                    <span className="text-muted-foreground">{BP_TYPES.find((t) => t.value === e.type)?.label}</span>
                    <span className="text-muted-foreground">{e.length}B</span>
                  </div>
                  <Button size="sm" variant="ghost" disabled={busy} onClick={() => onClear(e)}>
                    <Eraser className="h-4 w-4" /> 清除
                  </Button>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
