import { useEffect, useState } from "react";
import { ShieldAlert, Loader2 } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { systemIpc } from "@/ipc";

/**
 * 启动后检测 elevation。manifest 会强制 UAC,所以正常路径下永不显示。
 * 万一用户从命令行 / 调试器以非 admin 起的进程,显示红条引导。
 */
export function ElevationBanner() {
  const [checked, setChecked] = useState(false);
  const [elevated, setElevated] = useState(true);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    void systemIpc
      .isElevated()
      .then((e) => {
        setElevated(e);
        setChecked(true);
      })
      .catch(() => setChecked(true));
  }, []);

  if (!checked || elevated) return null;

  async function relaunch() {
    setBusy(true);
    try {
      await systemIpc.restartAsAdmin();
    } catch (e: unknown) {
      const msg = (e as { message?: string })?.message ?? String(e);
      toast.error(`提升失败(可能被 UAC 取消):${msg}`);
      setBusy(false);
    }
  }

  return (
    <div className="flex shrink-0 items-center gap-3 border-b border-warning/40 bg-warning/10 px-4 py-2 text-sm">
      <ShieldAlert className="h-4 w-4 shrink-0 text-warning" />
      <div className="flex-1">
        <span className="font-medium">未以管理员运行</span>
      </div>
      <Button size="sm" variant="default" onClick={relaunch} disabled={busy}>
        {busy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <ShieldAlert className="h-3.5 w-3.5" />}
        以管理员重启
      </Button>
    </div>
  );
}
