import { useState } from "react";
import { Keyboard, Mouse, Power } from "lucide-react";
import { toast } from "sonner";

import { PageHeader } from "@/components/common/PageHeader";
import { Button } from "@/components/ui/button";
import { Input as TextInput } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Checkbox } from "@/components/ui/checkbox";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { inputIpc } from "@/ipc";

export default function InputPage() {
  const [enabled, setEnabled] = useState(false);
  const [busy, setBusy] = useState(false);

  // 键盘
  const [scancode, setScancode] = useState("1E"); // A
  const [extended, setExtended] = useState(false);
  const [isBreak, setIsBreak] = useState(false);

  // 鼠标
  const [dx, setDx] = useState("0");
  const [dy, setDy] = useState("0");
  const [wheel, setWheel] = useState("0");
  const [btnL, setBtnL] = useState(false);
  const [btnR, setBtnR] = useState(false);
  const [btnM, setBtnM] = useState(false);

  async function toggle() {
    setBusy(true);
    try {
      if (enabled) {
        await inputIpc.disable();
        toast.success("已停用底层输入");
        setEnabled(false);
      } else {
        await inputIpc.enable();
        toast.success("已启用底层输入");
        setEnabled(true);
      }
    } catch (e: unknown) {
      const msg = (e as { message?: string })?.message ?? String(e);
      toast.error(`切换失败: ${msg}`);
    } finally {
      setBusy(false);
    }
  }

  async function onSendKey() {
    const sc = parseInt(scancode, 16);
    if (Number.isNaN(sc) || sc < 0 || sc > 0xff) return toast.error("Scancode 必须 16 进制 (0~FF)");
    setBusy(true);
    try {
      await inputIpc.sendKey(sc, extended, isBreak);
      toast.success(`KB scancode=0x${sc.toString(16).toUpperCase()} ${isBreak ? "UP" : "DOWN"}`);
    } catch (e: unknown) {
      const msg = (e as { message?: string })?.message ?? String(e);
      toast.error(`发送失败: ${msg}`);
    } finally {
      setBusy(false);
    }
  }

  async function onSendMouse() {
    let buttons = 0;
    if (btnL) buttons |= 1;
    if (btnR) buttons |= 2;
    if (btnM) buttons |= 4;
    const dxN = Number(dx);
    const dyN = Number(dy);
    const wN = Number(wheel);
    if (![dxN, dyN, wN].every(Number.isFinite)) return toast.error("dx / dy / wheel 必须是数字");
    setBusy(true);
    try {
      await inputIpc.sendMouse(dxN, dyN, buttons, wN);
      toast.success(`MS dx=${dxN} dy=${dyN} btn=0x${buttons.toString(16)} wheel=${wN}`);
    } catch (e: unknown) {
      const msg = (e as { message?: string })?.message ?? String(e);
      toast.error(`发送失败: ${msg}`);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="底层输入"
        actions={
          <Button variant={enabled ? "destructive" : "default"} onClick={toggle} disabled={busy}>
            <Power className="h-4 w-4" /> {enabled ? "停用" : "启用"}
          </Button>
        }
      />

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Keyboard className="h-4 w-4" /> 键盘
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="grid grid-cols-3 gap-3">
            <div className="space-y-2">
              <Label htmlFor="kb-sc">Scancode (hex)</Label>
              <TextInput id="kb-sc" value={scancode} onChange={(e) => setScancode(e.target.value)} />
            </div>
            <div className="space-y-2 pt-6">
              <div className="flex items-center gap-2">
                <Checkbox id="kb-ext" checked={extended} onCheckedChange={(v) => setExtended(Boolean(v))} />
                <Label htmlFor="kb-ext" className="cursor-pointer font-normal">扩展 (E0)</Label>
              </div>
            </div>
            <div className="space-y-2 pt-6">
              <div className="flex items-center gap-2">
                <Checkbox id="kb-brk" checked={isBreak} onCheckedChange={(v) => setIsBreak(Boolean(v))} />
                <Label htmlFor="kb-brk" className="cursor-pointer font-normal">Break (UP)</Label>
              </div>
            </div>
          </div>
          <Button onClick={onSendKey} disabled={busy || !enabled}>发送按键</Button>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Mouse className="h-4 w-4" /> 鼠标
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="grid grid-cols-3 gap-3">
            <div className="space-y-2">
              <Label htmlFor="ms-dx">dx</Label>
              <TextInput id="ms-dx" type="number" value={dx} onChange={(e) => setDx(e.target.value)} />
            </div>
            <div className="space-y-2">
              <Label htmlFor="ms-dy">dy</Label>
              <TextInput id="ms-dy" type="number" value={dy} onChange={(e) => setDy(e.target.value)} />
            </div>
            <div className="space-y-2">
              <Label htmlFor="ms-w">wheel</Label>
              <TextInput id="ms-w" type="number" value={wheel} onChange={(e) => setWheel(e.target.value)} />
            </div>
          </div>
          <div className="flex gap-4">
            <div className="flex items-center gap-2">
              <Checkbox id="ms-l" checked={btnL} onCheckedChange={(v) => setBtnL(Boolean(v))} />
              <Label htmlFor="ms-l" className="cursor-pointer font-normal">L</Label>
            </div>
            <div className="flex items-center gap-2">
              <Checkbox id="ms-r" checked={btnR} onCheckedChange={(v) => setBtnR(Boolean(v))} />
              <Label htmlFor="ms-r" className="cursor-pointer font-normal">R</Label>
            </div>
            <div className="flex items-center gap-2">
              <Checkbox id="ms-m" checked={btnM} onCheckedChange={(v) => setBtnM(Boolean(v))} />
              <Label htmlFor="ms-m" className="cursor-pointer font-normal">M</Label>
            </div>
          </div>
          <Button onClick={onSendMouse} disabled={busy || !enabled}>发送鼠标包</Button>
        </CardContent>
      </Card>
    </div>
  );
}
