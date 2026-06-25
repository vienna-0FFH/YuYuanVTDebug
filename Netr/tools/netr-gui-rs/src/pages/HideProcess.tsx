import { useState } from "react";
import { EyeOff, Eye } from "lucide-react";
import { toast } from "sonner";

import { PageHeader } from "@/components/common/PageHeader";
import { ProcessPicker } from "@/components/common/ProcessPicker";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { hideIpc, type ProcessInfo } from "@/ipc";

interface HiddenEntry {
  pid: number;
  name: string;
}

export default function HideProcess() {
  const [target, setTarget] = useState<ProcessInfo | null>(null);
  const [busy, setBusy] = useState(false);
  const [hidden, setHidden] = useState<HiddenEntry[]>([]);

  async function action(unhide: boolean) {
    if (!target) {
      toast.error("请先选择目标进程");
      return;
    }
    setBusy(true);
    try {
      if (unhide) {
        await hideIpc.unhideProcess(target.pid);
        setHidden((prev) => prev.filter((p) => p.pid !== target.pid));
        toast.success(`PID ${target.pid} 已取消隐藏`);
      } else {
        await hideIpc.hideProcess(target.pid);
        setHidden((prev) =>
          prev.some((p) => p.pid === target.pid)
            ? prev
            : [...prev, { pid: target.pid, name: target.name }]
        );
        toast.success(`PID ${target.pid} 已隐藏`);
      }
    } catch (e: unknown) {
      const msg = (e as { message?: string })?.message ?? String(e);
      toast.error(`操作失败: ${msg}`);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="进程隐藏"
      />

      <Card>
        <CardHeader>
          <CardTitle>选择目标</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="space-y-1.5">
            <Label>进程</Label>
            <ProcessPicker value={target} onChange={setTarget} disabled={busy} />
          </div>
          <div className="flex gap-2">
            <Button onClick={() => action(false)} disabled={busy || !target}>
              <EyeOff className="h-4 w-4" /> 隐藏
            </Button>
            <Button onClick={() => action(true)} disabled={busy || !target} variant="outline">
              <Eye className="h-4 w-4" /> 取消隐藏
            </Button>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>本次会话已隐藏 · {hidden.length}</CardTitle>
        </CardHeader>
        <CardContent>
          {hidden.length === 0 ? (
            <div className="text-sm text-muted-foreground">暂无</div>
          ) : (
            <div className="flex flex-wrap gap-2">
              {hidden.map((p) => (
                <span key={p.pid} className="rounded bg-muted px-2 py-1 text-xs">
                  <span className="font-mono text-muted-foreground">{p.pid}</span>{" "}
                  <span>{p.name}</span>
                </span>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
