import { useNavigate } from "react-router-dom";
import { Lock, HardDrive, ShieldPlus, ChevronRight, Loader2 } from "lucide-react";
import { toast } from "sonner";
import { useEffect, useState } from "react";

import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { useDriver, serviceStateLabel } from "@/store/driverStore";
import { useAuth } from "@/store/authStore";
import { driverIpc, systemIpc, type DriverFile } from "@/ipc";

/**
 * 路由守卫:安全工具未加载 → 显示提示;加载了才渲染子内容。
 * 同时提供「加载安全工具」一键动作。
 */
export function RequireDriver({ children }: { children: React.ReactNode }) {
  const deviceOpen = useDriver((s) => s.deviceOpen);
  const service = useDriver((s) => s.service);
  const refresh = useDriver((s) => s.refreshService);
  const trySubmit = useAuth((s) => s.trySubmitToDriver);
  const navigate = useNavigate();
  const [busy, setBusy] = useState(false);
  const [driverFile, setDriverFile] = useState<DriverFile | null>(null);

  useEffect(() => {
    void systemIpc.resolveDriverPath().then(setDriverFile).catch(() => null);
  }, []);

  if (deviceOpen) return <>{children}</>;

  async function loadNow() {
    if (!driverFile?.exists) {
      toast.error("未找到 GuardMetaCore.sys,请放到本程序所在目录");
      return;
    }
    setBusy(true);
    try {
      if (service?.state === "not_installed") {
        await driverIpc.install(driverFile.path);
      }
      if (service?.state !== "running") {
        await driverIpc.start();
        await new Promise((r) => setTimeout(r, 500));
      }
      await driverIpc.openDevice();
      await trySubmit();
      await refresh();
      toast.success("安全工具已加载");
    } catch (e: unknown) {
      const msg = (e as { message?: string })?.message ?? String(e);
      toast.error(`加载失败: ${msg};请去服务页排查`);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex min-h-[60vh] items-center justify-center">
      <Card className="card-steel relative w-full max-w-xl overflow-hidden">
        <div className="bg-steel-soft pointer-events-none absolute inset-0" />
        <CardContent className="relative space-y-5 p-8 text-center">
          <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-full border bg-card shadow-sm">
            <Lock className="h-6 w-6 text-muted-foreground" />
          </div>

          <div className="space-y-1.5">
            <h2 className="text-lg font-semibold">安全工具未加载</h2>
            <p className="text-sm text-muted-foreground">
              当前功能依赖内核安全工具,加载后即可使用。
            </p>
          </div>

          <div className="mx-auto inline-flex items-center gap-2 rounded-md border bg-background/70 px-3 py-1.5 text-xs">
            <span className="text-muted-foreground">服务</span>
            <span className="font-medium text-warning">{serviceStateLabel(service?.state)}</span>
            <span className="text-muted-foreground/60">·</span>
            <span className="text-muted-foreground">设备</span>
            <span className="font-medium text-warning">未打开</span>
          </div>

          <div className="flex flex-col gap-2">
            <Button onClick={loadNow} disabled={busy || !driverFile?.exists} className="w-full">
              {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <ShieldPlus className="h-4 w-4" />}
              {busy ? "加载中..." : "加载安全工具"}
            </Button>
            <Button variant="ghost" size="sm" onClick={() => navigate("/service")} className="w-full">
              <HardDrive className="h-3.5 w-3.5" /> 打开安全服务页 <ChevronRight className="ml-auto h-3.5 w-3.5" />
            </Button>
            {!driverFile?.exists && (
              <p className="text-xs text-warning">未找到 GuardMetaCore.sys,请放到本程序所在目录</p>
            )}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
