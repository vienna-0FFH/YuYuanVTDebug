import { useState } from "react";
import { EyeOff, Eye, AlertTriangle } from "lucide-react";
import { toast } from "sonner";

import { PageHeader } from "@/components/common/PageHeader";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { hideIpc } from "@/ipc";

export default function HideDriver() {
  const [name, setName] = useState("Netr");
  const [busy, setBusy] = useState(false);

  async function action(unhide: boolean) {
    if (!name.trim()) {
      toast.error("请输入驱动名");
      return;
    }
    setBusy(true);
    try {
      if (unhide) {
        await hideIpc.unhideDriver(name);
        toast.success(`驱动 ${name} 已取消隐藏`);
      } else {
        await hideIpc.hideDriver(name);
        toast.success(`驱动 ${name} 已从 PsLoadedModuleList 摘除`);
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
        title="驱动隐藏"
      />

      <Card className="border-warning/40 bg-warning/5">
        <CardHeader className="flex flex-row items-center gap-3">
          <AlertTriangle className="h-5 w-5 text-warning" />
          <div>
            <CardTitle className="text-base">注意</CardTitle>
          </div>
        </CardHeader>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>目标驱动</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="space-y-2">
            <Label htmlFor="drv-name">驱动名</Label>
            <Input
              id="drv-name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Netr"
            />
          </div>
          <div className="flex gap-2">
            <Button onClick={() => action(false)} disabled={busy} variant="default">
              <EyeOff className="h-4 w-4" /> 隐藏
            </Button>
            <Button onClick={() => action(true)} disabled={busy} variant="outline">
              <Eye className="h-4 w-4" /> 取消隐藏
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
