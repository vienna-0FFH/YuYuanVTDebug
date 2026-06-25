import { useState } from "react";
import { Syringe, FolderOpen, Code } from "lucide-react";
import { toast } from "sonner";
import { open as openDialog } from "@tauri-apps/plugin-dialog";

import { PageHeader } from "@/components/common/PageHeader";
import { ProcessPicker } from "@/components/common/ProcessPicker";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { injectIpc, type ProcessInfo } from "@/ipc";

export default function Inject() {
  const [target, setTarget] = useState<ProcessInfo | null>(null);
  const [dllPath, setDllPath] = useState("");
  const [shellcodeHex, setShellcodeHex] = useState("");
  const [busy, setBusy] = useState(false);

  function parsePid(): number | null {
    if (!target) {
      toast.error("请先选择目标进程");
      return null;
    }
    return target.pid;
  }

  async function pickDll() {
    const r = await openDialog({
      multiple: false,
      filters: [{ name: "DLL", extensions: ["dll"] }],
    });
    if (typeof r === "string") setDllPath(r);
  }

  async function readDllBytes(path: string): Promise<number[]> {
    void path;
    throw new Error("DLL 注入暂未启用前端文件直读;请改用 shellcode 模式,或后续版本接入 fs:read。");
  }

  async function onInjectDll() {
    const p = parsePid();
    if (p === null) return;
    if (!dllPath) return toast.error("请选择 DLL");
    setBusy(true);
    try {
      const bytes = await readDllBytes(dllPath);
      await injectIpc.dll(p, bytes);
      toast.success(`DLL 已注入 PID ${p}`);
    } catch (e: unknown) {
      const msg = (e as { message?: string })?.message ?? String(e);
      toast.error(`注入失败: ${msg}`);
    } finally {
      setBusy(false);
    }
  }

  async function onInjectShellcode() {
    const p = parsePid();
    if (p === null) return;
    const tokens = shellcodeHex.trim().split(/[\s,]+/).filter(Boolean);
    if (tokens.length === 0) return toast.error("Shellcode 不能为空");
    const bytes: number[] = [];
    for (const t of tokens) {
      const v = parseInt(t, 16);
      if (Number.isNaN(v) || v < 0 || v > 255) return toast.error(`无效字节: ${t}`);
      bytes.push(v);
    }
    setBusy(true);
    try {
      await injectIpc.shellcode(p, bytes);
      toast.success(`Shellcode 已注入 (${bytes.length} 字节)`);
    } catch (e: unknown) {
      const msg = (e as { message?: string })?.message ?? String(e);
      toast.error(`注入失败: ${msg}`);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="DLL / Shellcode 注入"
      />

      <Card>
        <CardHeader>
          <CardTitle>目标进程</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-1.5">
            <Label>进程</Label>
            <ProcessPicker value={target} onChange={setTarget} disabled={busy} />
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>DLL 注入</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="space-y-2">
            <Label htmlFor="inj-dll">DLL 路径</Label>
            <div className="flex gap-2">
              <Input id="inj-dll" value={dllPath} onChange={(e) => setDllPath(e.target.value)} placeholder=".dll 路径" />
              <Button variant="outline" onClick={pickDll}>
                <FolderOpen className="h-4 w-4" /> 浏览
              </Button>
            </div>
          </div>
          <Button onClick={onInjectDll} disabled={busy}>
            <Syringe className="h-4 w-4" /> 注入 DLL
          </Button>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Shellcode 注入</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="space-y-2">
            <Label htmlFor="inj-sc">Shellcode (hex)</Label>
            <textarea
              id="inj-sc"
              className="min-h-32 w-full rounded-md border border-input bg-background p-2 font-mono text-xs"
              value={shellcodeHex}
              onChange={(e) => setShellcodeHex(e.target.value)}
              placeholder="48 31 C0 ..."
            />
          </div>
          <Button onClick={onInjectShellcode} disabled={busy}>
            <Code className="h-4 w-4" /> 注入 Shellcode
          </Button>
        </CardContent>
      </Card>
    </div>
  );
}
