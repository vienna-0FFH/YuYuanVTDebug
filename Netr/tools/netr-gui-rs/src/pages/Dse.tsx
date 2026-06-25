import { useEffect, useState } from "react";
import { Lock, Unlock, RefreshCw } from "lucide-react";
import { toast } from "sonner";

import { PageHeader } from "@/components/common/PageHeader";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { dseIpc } from "@/ipc";

export default function Dse() {
  const [disabled, setDisabled] = useState<boolean | null>(null);
  const [busy, setBusy] = useState(false);

  async function refresh() {
    try {
      const s = await dseIpc.status();
      setDisabled(s.disabled);
    } catch (e: unknown) {
      const msg = (e as { message?: string })?.message ?? String(e);
      toast.error(`查询失败: ${msg}`);
    }
  }

  useEffect(() => {
    void refresh();
  }, []);

  async function safe(fn: () => Promise<void>, label: string) {
    setBusy(true);
    try {
      await fn();
      toast.success(`${label}成功`);
      await refresh();
    } catch (e: unknown) {
      const msg = (e as { message?: string })?.message ?? String(e);
      toast.error(`${label}失败: ${msg}`);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="DSE 控制"
        actions={
          <Button variant="ghost" size="sm" onClick={refresh}>
            <RefreshCw className="h-4 w-4" /> 刷新
          </Button>
        }
      />

      <Card>
        <CardHeader>
          <CardTitle>当前状态</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex items-center gap-4">
            <StatusPill disabled={disabled} />
            <div className="flex gap-2 ml-auto">
              <Button
                variant="destructive"
                disabled={busy || disabled === true}
                onClick={() => safe(() => dseIpc.disable(), "禁用 DSE")}
              >
                <Unlock className="h-4 w-4" /> 禁用 DSE
              </Button>
              <Button
                variant="default"
                disabled={busy || disabled === false}
                onClick={() => safe(() => dseIpc.enable(), "恢复 DSE")}
              >
                <Lock className="h-4 w-4" /> 恢复 DSE
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

function StatusPill({ disabled }: { disabled: boolean | null }) {
  if (disabled === null) {
    return (
      <span className="rounded-full bg-muted px-3 py-1 text-sm text-muted-foreground">
        未查询
      </span>
    );
  }
  return disabled ? (
    <span className="rounded-full bg-destructive/15 px-3 py-1 text-sm text-destructive">
      已禁用
    </span>
  ) : (
    <span className="rounded-full bg-success/15 px-3 py-1 text-sm text-success">
      正常 (启用中)
    </span>
  );
}
