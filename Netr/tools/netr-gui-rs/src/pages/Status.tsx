import { useEffect, useState } from "react";
import { Activity, CheckCircle2, XCircle, RefreshCw, Loader2, AlertTriangle } from "lucide-react";
import { toast } from "sonner";

import { PageHeader } from "@/components/common/PageHeader";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { useAuth } from "@/store/authStore";
import { useDriver, serviceStateLabel, serviceStateTone } from "@/store/driverStore";

const CPU_VENDOR: Record<number, string> = {
  0: "未知",
  1: "Intel (VMX)",
  2: "AMD (SVM)",
};

export default function Status() {
  const service = useDriver((s) => s.service);
  const deviceOpen = useDriver((s) => s.deviceOpen);
  const hv = useDriver((s) => s.status);
  const statusError = useDriver((s) => s.statusError);
  const selfProtected = useDriver((s) => s.selfProtected);
  const refreshService = useDriver((s) => s.refreshService);
  const refreshStatus = useDriver((s) => s.refreshStatus);
  const startPoll = useDriver((s) => s.startPolling);
  const stopPoll = useDriver((s) => s.stopPolling);
  const auth = useAuth();

  const [busy, setBusy] = useState(false);

  async function refreshAll() {
    setBusy(true);
    try {
      await refreshService();
      await refreshStatus();
    } catch (e: unknown) {
      const msg = (e as { message?: string })?.message ?? String(e);
      toast.error(`刷新失败: ${msg}`);
    } finally {
      setBusy(false);
    }
  }

  useEffect(() => {
    startPoll();
    return () => stopPoll();
  }, [startPoll, stopPoll]);

  const hvLoaded = !!hv;
  const hvWaiting = deviceOpen && !hvLoaded;

  return (
    <div className="space-y-6">
      <PageHeader
        title="系统状态"
        actions={
          <Button variant="ghost" size="sm" onClick={refreshAll} disabled={busy}>
            <RefreshCw className="h-4 w-4" /> 刷新
          </Button>
        }
      />

      {/* 顶部诊断条:hv 拿不到时显示具体原因 */}
      {deviceOpen && !hvLoaded && (
        <Card className="border-warning/40 bg-warning/5">
          <CardContent className="flex items-start gap-3 p-4 text-sm">
            <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-warning" />
            <div className="flex-1">
              <div className="font-medium">
                {auth.driverLicensed ? "正在加载运行时状态" : "授权未下发"}
              </div>
              {statusError && (
                <div className="mt-1 text-xs text-warning font-mono">{statusError}</div>
              )}
            </div>
          </CardContent>
        </Card>
      )}

      <div className="grid gap-4 lg:grid-cols-3">
        {/* 授权 */}
        <Card className="card-hover">
          <CardHeader>
            <CardTitle className="text-base">授权</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            <Row label="登录状态" value={auth.user ? "已登录" : "未登录"} ok={!!auth.user} />
            <Row label="Subject" value={auth.user ? `${auth.user.subject_type} #${auth.user.subject_id}` : "—"} />
            <Row
              label="到期"
              value={
                auth.user && auth.user.expires_at > 0
                  ? new Date(auth.user.expires_at * 1000).toLocaleString()
                  : auth.user && auth.user.remaining_count >= 0
                  ? `剩 ${auth.user.remaining_count} 次`
                  : "—"
              }
            />
            <Row label="授权下发" value={auth.driverLicensed ? "已下发" : "未下发"} ok={auth.driverLicensed} />
            <Row label="自我保护" value={selfProtected ? "已激活" : "未激活"} ok={selfProtected} />
          </CardContent>
        </Card>

        {/* 服务 & 设备 */}
        <Card className="card-hover">
          <CardHeader>
            <CardTitle className="text-base">服务</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            <Row
              label="服务"
              value={serviceStateLabel(service?.state)}
              tone={serviceStateTone(service?.state)}
            />
            <Row label="PID" value={service?.process_id ? String(service.process_id) : "—"} />
            <Row label="设备" value={deviceOpen ? "已打开" : "已关闭"} ok={deviceOpen} />
          </CardContent>
        </Card>

        {/* Hypervisor 运行时 */}
        <Card className="card-hover">
          <CardHeader>
            <CardTitle className="text-base">Hypervisor</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            <HvRow label="HV 激活" hv={hv} waiting={hvWaiting} k="hypervisor_active" />
            <HvRow label="Hook 已装" hv={hv} waiting={hvWaiting} k="hook_initialized" />
            <Row
              label="DSE"
              value={hvLoaded ? (hv!.dse_disabled ? "已禁用" : "正常") : waitingText(hvWaiting)}
              tone={!hvLoaded ? "muted" : hv!.dse_disabled ? "warning" : "success"}
            />
            <HvRow label="反反调试" hv={hv} waiting={hvWaiting} k="anti_anti_debug" />
            <Row
              label="CPU 厂商"
              value={hvLoaded ? (CPU_VENDOR[hv!.cpu_vendor] ?? `${hv!.cpu_vendor}`) : waitingText(hvWaiting)}
            />
            <Row label="CPU 数" value={hvLoaded ? String(hv!.cpu_count) : waitingText(hvWaiting)} />
            <HvRow label="VT-root" hv={hv} waiting={hvWaiting} k="vt_root_enabled" />
            <HvRow label="Debugger Proxy" hv={hv} waiting={hvWaiting} k="debugger_proxy_enabled" />
            <HvRow label="访问绕过" hv={hv} waiting={hvWaiting} k="access_bypass_enabled" />
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <Activity className="h-4 w-4" /> 实时事件
          </CardTitle>
        </CardHeader>
        <CardContent>
        </CardContent>
      </Card>
    </div>
  );
}

function waitingText(waiting: boolean): string {
  return waiting ? "等待中..." : "—";
}

/** Hypervisor bool 字段统一渲染 */
function HvRow({
  label,
  hv,
  waiting,
  k,
}: {
  label: string;
  hv: import("@/ipc/driver").DriverStatusView | null;
  waiting: boolean;
  k: keyof Pick<
    import("@/ipc/driver").DriverStatusView,
    | "hypervisor_active"
    | "hook_initialized"
    | "anti_anti_debug"
    | "vt_root_enabled"
    | "debugger_proxy_enabled"
    | "access_bypass_enabled"
  >;
}) {
  if (!hv) {
    return (
      <div className="flex items-center justify-between text-sm">
        <span className="text-muted-foreground">{label}</span>
        <span className="flex items-center gap-1 text-muted-foreground">
          {waiting && <Loader2 className="h-3.5 w-3.5 animate-spin" />}
          {waitingText(waiting)}
        </span>
      </div>
    );
  }
  const v = hv[k] as boolean;
  return <Row label={label} value={v ? "ON" : "OFF"} ok={v} />;
}

function Row({
  label,
  value,
  ok,
  tone,
}: {
  label: string;
  value: string;
  ok?: boolean;
  tone?: "success" | "warning" | "destructive" | "muted";
}) {
  const valueColor =
    tone === "success"
      ? "text-success"
      : tone === "warning"
      ? "text-warning"
      : tone === "destructive"
      ? "text-destructive"
      : ok === true
      ? "text-success"
      : ok === false
      ? "text-muted-foreground"
      : "text-foreground";

  const Icon = ok === true ? CheckCircle2 : ok === false ? XCircle : null;
  return (
    <div className="flex items-center justify-between text-sm">
      <span className="text-muted-foreground">{label}</span>
      <span className={`flex items-center gap-1 font-medium ${valueColor}`}>
        {Icon ? <Icon className="h-3.5 w-3.5" /> : null}
        {value}
      </span>
    </div>
  );
}
