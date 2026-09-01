import { useEffect, useState } from "react";
import { CheckCircle2, XCircle, RefreshCw, Loader2, AlertTriangle, Info } from "lucide-react";
import { toast } from "sonner";

import { PageHeader } from "@/components/common/PageHeader";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { useAuth } from "@/store/authStore";
import {
  AUTO_REGISTER_GUI_WITH_DRIVER,
  useDriver,
  serviceStateLabel,
  serviceStateTone,
} from "@/store/driverStore";

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
  const selfProtectError = useDriver((s) => s.selfProtectError);
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
  const selfProtectionValue = selfProtected
    ? "已激活"
    : AUTO_REGISTER_GUI_WITH_DRIVER
    ? selfProtectError
      ? "登记失败"
      : "等待登记"
    : "被动模式";

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

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
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
            <Row
              label="主界面自我保护"
              value={selfProtectionValue}
              ok={selfProtected ? true : undefined}
              tone={selfProtectError ? "warning" : "muted"}
            />
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
            <Row
              label="CPU 厂商"
              value={hvLoaded ? (CPU_VENDOR[hv!.cpu_vendor] ?? `${hv!.cpu_vendor}`) : waitingText(hvWaiting)}
            />
            <Row label="CPU 数" value={hvLoaded ? formatCpuCount(hv!.cpu_count) : waitingText(hvWaiting)} />
            <Row
              label="VT-root"
              value={
                hvLoaded
                  ? hv!.vt_root_enabled
                    ? "ON"
                    : "编译关闭 · fallback"
                  : waitingText(hvWaiting)
              }
              ok={hvLoaded && hv!.vt_root_enabled ? true : undefined}
              tone="muted"
            />
          </CardContent>
        </Card>

        {/* 调试器与按需功能 */}
        <Card className="card-hover">
          <CardHeader>
            <CardTitle className="text-base">调试器链路</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            <Row label="受保护调试器" value={hvLoaded ? String(hv!.debuggers) : waitingText(hvWaiting)} />
            <Row label="Bridge 绑定目标" value={hvLoaded ? String(hv!.protected_processes) : waitingText(hvWaiting)} />
            <Row
              label="Debugger Proxy"
              value={
                hvLoaded
                  ? hv!.debugger_proxy_enabled
                    ? "ON"
                    : hv!.debuggers > 0
                    ? "核心 Hook 未就绪"
                    : "待注册调试器"
                  : waitingText(hvWaiting)
              }
              ok={hvLoaded && hv!.debugger_proxy_enabled ? true : undefined}
              tone={hvLoaded && hv!.debuggers > 0 && !hv!.debugger_proxy_enabled ? "warning" : "muted"}
            />
            <Row
              label="AntiVMP 扩展过滤"
              value={hvLoaded ? (hv!.anti_anti_debug ? "ON" : "按需关闭") : waitingText(hvWaiting)}
              ok={hvLoaded && hv!.anti_anti_debug ? true : undefined}
              tone="muted"
            />
            <Row
              label="访问绕过"
              value={hvLoaded ? (hv!.access_bypass_enabled ? "ON" : "高风险 · 未启用") : waitingText(hvWaiting)}
              ok={hvLoaded && hv!.access_bypass_enabled ? true : undefined}
              tone="muted"
            />
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <Info className="h-4 w-4" /> 状态启用条件
          </CardTitle>
        </CardHeader>
        <CardContent className="grid gap-3 md:grid-cols-2">
          <Condition
            title="主界面自我保护"
            description="当前采用被动策略，状态轮询不会注册主界面，也不会顺带安装 EPT Hook。使用“调试器保护”后，Bridge 会注册实际调试器进程。"
          />
          <Condition
            title="Debugger Proxy"
            description="至少一个调试器完成 Bridge 注入和驱动注册，并且 NtReadVirtualMemory、NtWriteVirtualMemory 两个核心 Hook 都安装成功后才显示 ON。"
          />
          <Condition
            title="AntiVMP 扩展过滤"
            description="只反映“调试器保护”页中的手动扩展开关。Bridge 绑定目标后自动生效的 PEB/Heap 清理等基线能力不由此状态表示。"
          />
          <Condition
            title="访问绕过"
            description="这是独立的高风险 NtOpenProcess/句柄访问绕过，默认不随驱动加载启用；只有显式请求且核心 Hook 安装成功才显示 ON。"
          />
          <Condition
            title="VT-root"
            description="当前驱动已编译启用 VT 物理读写；只有 RAM 范围快照、私有 PT 岛和全部 VCPU 分片均初始化成功时显示 ON，任一步失败都会保持 OFF 并拒绝进入直通路径。"
          />
          <Condition
            title="HV 激活与 Hook 已装"
            description="驱动启动、CPU 虚拟化可用且 VMX/SVM 初始化成功后 HV 激活；EPT Hook 管理器完成初始化后 Hook 已装才显示 ON。"
          />
        </CardContent>
      </Card>
    </div>
  );
}

function waitingText(waiting: boolean): string {
  return waiting ? "等待中..." : "—";
}

function Condition({ title, description }: { title: string; description: string }) {
  return (
    <div className="rounded-md border border-border/70 bg-card/40 p-3">
      <div className="text-sm font-medium">{title}</div>
      <div className="mt-1 text-xs leading-5 text-muted-foreground">{description}</div>
    </div>
  );
}

function formatCpuCount(value: number): string {
  if (value > 0) {
    return String(value);
  }

  const browserValue = navigator.hardwareConcurrency;
  return browserValue > 0 ? String(browserValue) : "—";
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
      : tone === "muted"
      ? "text-muted-foreground"
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
