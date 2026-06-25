import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  Activity,
  Bug,
  ShieldCheck,
  Cpu,
  Play,
  Square,
  Power,
  Plug,
  Unlock,
  Lock,
  Eye,
  EyeOff,
  Settings,
  CreditCard,
  ChevronRight,
  Sparkles,
  ScrollText,
} from "lucide-react";
import { invoke } from "@tauri-apps/api/core";
import { toast } from "sonner";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { driverIpc } from "@/ipc/driver";
import { dseIpc, systemIpc } from "@/ipc";
import { useDriver, serviceStateLabel, serviceStateTone } from "@/store/driverStore";
import { useAuth } from "@/store/authStore";
import { cn } from "@/lib/utils";

const CPU_VENDOR: Record<number, string> = {
  0: "未知",
  1: "Intel VMX",
  2: "AMD SVM",
};

export default function Dashboard() {
  const service = useDriver((s) => s.service);
  const status = useDriver((s) => s.status);
  const deviceOpen = useDriver((s) => s.deviceOpen);
  const startPoll = useDriver((s) => s.startPolling);
  const stopPoll = useDriver((s) => s.stopPolling);
  const refreshService = useDriver((s) => s.refreshService);
  const user = useAuth((s) => s.user);
  const driverLicensed = useAuth((s) => s.driverLicensed);
  const trySubmit = useAuth((s) => s.trySubmitToDriver);

  useEffect(() => {
    startPoll();
    return () => stopPoll();
  }, [startPoll, stopPoll]);

  const isRunning = service?.state === "running";
  const isOnline = Boolean(user);

  return (
    <div className="space-y-6">
      <HeroSection user={user} licensed={driverLicensed} />

      {/* KPI 卡片 */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <KpiCard
          icon={Cpu}
          label="安全服务"
          value={serviceStateLabel(service?.state)}
          tone={serviceStateTone(service?.state)}
          hint={status?.hypervisor_active ? "保护已激活" : "未激活"}
          accent={isRunning}
        />
        <KpiCard
          icon={Activity}
          label="CPU"
          value={status ? `${status.cpu_count} 核` : "—"}
          tone="info"
          hint={status ? CPU_VENDOR[status.cpu_vendor] ?? "—" : "—"}
        />
        <KpiCard
          icon={Bug}
          label="活跃调试器"
          value={status ? String(status.debuggers) : "0"}
          tone="info"
          hint={status?.debugger_proxy_enabled ? "Proxy 已开" : "Proxy 关"}
        />
        <KpiCard
          icon={ShieldCheck}
          label="授权"
          value={user ? (driverLicensed ? "已激活" : "待下发") : "未登录"}
          tone={driverLicensed ? "success" : user ? "warning" : "warning"}
          hint={user ? `账号 #${user.subject_id}` : "请先登录"}
          accent={isOnline}
        />
      </div>

      {/* 主面板:快捷操作 + 实时事件已迁移到独立 Trace 控制台 */}
      <QuickActions
        serviceState={service?.state}
        deviceOpen={deviceOpen}
        dseDisabled={status?.dse_disabled ?? false}
        onAfterAction={refreshService}
        trySubmitLicense={trySubmit}
      />

      {/* 系统详情 - 三列 */}
      {status && (
        <div className="grid gap-4 lg:grid-cols-3">
          <DetailCard
            icon={Cpu}
            title="Hypervisor"
            items={[
              ["激活", boolPill(status.hypervisor_active, "ON", "OFF")],
              ["VT-root", boolPill(status.vt_root_enabled, "ON", "OFF")],
              ["Hook 已装", boolPill(status.hook_initialized, "ON", "OFF")],
              ["反反调试", boolPill(status.anti_anti_debug, "ON", "OFF")],
            ]}
          />
          <DetailCard
            icon={ShieldCheck}
            title="安全"
            items={[
              ["DSE", status.dse_disabled ? pill("已禁用", "warning") : pill("正常", "success")],
              ["访问绕过", boolPill(status.access_bypass_enabled, "ON", "OFF")],
              ["调试器代理", boolPill(status.debugger_proxy_enabled, "ON", "OFF")],
            ]}
          />
          <DetailCard
            icon={Sparkles}
            title="平台"
            items={[
              ["CPU 厂商", pill(CPU_VENDOR[status.cpu_vendor] ?? "Unknown", "info")],
              ["逻辑核", pill(String(status.cpu_count), "info")],
              ["服务", pill(serviceStateLabel(service?.state), serviceStateTone(service?.state))],
              ["设备", deviceOpen ? pill("打开", "success") : pill("关闭", "muted")],
            ]}
          />
        </div>
      )}
    </div>
  );
}

function HeroSection({
  user,
  licensed,
}: {
  user: { subject_type: string; subject_id: number; expires_at: number; remaining_count: number } | null;
  licensed: boolean;
}) {
  const navigate = useNavigate();
  const hello = user ? `账号 #${user.subject_id}` : "御元虚拟化安全工具";
  const sub = user
    ? licensed ? "授权已下发" : "授权未下发"
    : "未登录";

  return (
    <div className="bg-steel relative overflow-hidden rounded-xl border border-white/10 p-6 shadow-xl shadow-primary/20">
      {/* 光晕装饰 */}
      <div className="absolute -right-12 -top-12 h-48 w-48 rounded-full bg-white/10 blur-3xl" />
      <div className="absolute -bottom-16 -left-16 h-56 w-56 rounded-full bg-white/5 blur-3xl" />
      {/* 钢面反光纹路 */}
      <div className="pointer-events-none absolute inset-0 opacity-30 mix-blend-overlay"
        style={{
          backgroundImage:
            "linear-gradient(105deg, transparent 30%, rgba(255,255,255,0.18) 50%, transparent 70%)",
        }}
      />

      <div className="relative flex items-start justify-between gap-4">
        <div>
          <h1 className="text-silver text-2xl font-semibold tracking-tight">{hello}</h1>
          <p className="mt-1 text-sm text-white/75">{sub}</p>
        </div>
        <div className="flex gap-2">
          {user ? (
            <>
              <Button
                variant="outline"
                size="sm"
                className="border-white/30 bg-white/10 text-white backdrop-blur hover:bg-white/20"
                onClick={() => navigate("/account")}
              >
                <Settings className="h-4 w-4" /> 账号
              </Button>
              <Button
                variant="outline"
                size="sm"
                className="border-white/30 bg-white/10 text-white backdrop-blur hover:bg-white/20"
                onClick={() => navigate("/account")}
              >
                <CreditCard className="h-4 w-4" /> 续费
              </Button>
            </>
          ) : (
            <Button
              size="sm"
              className="bg-white text-primary hover:bg-white/90"
              onClick={() => navigate("/login")}
            >
              立即登录
            </Button>
          )}
        </div>
      </div>
    </div>
  );
}

function KpiCard({
  icon: Icon,
  label,
  value,
  hint,
  tone,
  accent,
}: {
  icon: React.ComponentType<{ className?: string }>;
  label: string;
  value: string;
  hint: string;
  tone: "success" | "warning" | "destructive" | "muted" | "info";
  accent?: boolean;
}) {
  const toneColor =
    {
      success: "text-success",
      warning: "text-warning",
      destructive: "text-destructive",
      muted: "text-muted-foreground",
      info: "text-info",
    }[tone] ?? "text-muted-foreground";

  return (
    <Card
      className={cn(
        "card-hover relative overflow-hidden",
        accent && "card-steel"
      )}
    >
      {accent && (
        <div className="bg-steel-soft pointer-events-none absolute inset-0" />
      )}
      <CardContent className="relative p-5">
        <div className="flex items-center justify-between">
          <span className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
            {label}
          </span>
          <Icon className={cn("h-4 w-4", toneColor)} />
        </div>
        <div className="mt-2 text-2xl font-semibold tabular-nums">{value}</div>
        <div className="mt-1 text-xs text-muted-foreground">{hint}</div>
      </CardContent>
    </Card>
  );
}

function QuickActions({
  serviceState,
  deviceOpen,
  dseDisabled,
  onAfterAction,
  trySubmitLicense,
}: {
  serviceState: string | undefined;
  deviceOpen: boolean;
  dseDisabled: boolean;
  onAfterAction: () => Promise<void>;
  trySubmitLicense: () => Promise<boolean>;
}) {
  const [busy, setBusy] = useState(false);
  const isRunning = serviceState === "running";

  async function safe(fn: () => Promise<void>, label: string) {
    setBusy(true);
    try {
      await fn();
      toast.success(`${label}成功`);
      await onAfterAction();
    } catch (e: unknown) {
      const msg = (e as { message?: string })?.message ?? String(e);
      toast.error(`${label}失败: ${msg}`);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card className="card-hover">
      <CardHeader className="pb-3">
        <CardTitle className="text-base">快捷操作</CardTitle>
      </CardHeader>
      <CardContent className="space-y-2">
        {!isRunning ? (
          <ActionButton
            icon={Play}
            label="加载安全工具"
            sub="注册 → 启动 → 打开通道 → 下发授权"
            busy={busy}
            tone="primary"
            onClick={() =>
              safe(async () => {
                const f = await systemIpc.resolveDriverPath();
                if (!f.exists) throw new Error(`未找到 ${f.path}`);
                await driverIpc.install(f.path);
                await driverIpc.start();
                await new Promise((r) => setTimeout(r, 400));
                await driverIpc.openDevice();
                await trySubmitLicense();
              }, "加载")
            }
          />
        ) : (
          <ActionButton
            icon={Square}
            label="卸载安全工具"
            sub="关闭通道 → 停止 → 注销"
            busy={busy}
            tone="warning"
            onClick={() =>
              safe(async () => {
                try { await driverIpc.closeDevice(); } catch { /* ignore */ }
                try { await driverIpc.stop(); } catch { /* ignore */ }
                await new Promise((r) => setTimeout(r, 200));
                try { await driverIpc.uninstall(); } catch { /* ignore */ }
              }, "卸载")
            }
          />
        )}

        {!deviceOpen ? (
          <ActionButton
            icon={Plug}
            label="打开通道"
            sub="单独打开 \\.\\Netr handle"
            busy={busy || !isRunning}
            onClick={() =>
              safe(async () => {
                await driverIpc.openDevice();
                await trySubmitLicense();
              }, "打开设备")
            }
          />
        ) : (
          <ActionButton
            icon={Power}
            label="关闭设备"
            sub="只关 handle 不停服务"
            busy={busy}
            onClick={() => safe(() => driverIpc.closeDevice(), "关闭设备")}
          />
        )}

        <Divider />

        {!dseDisabled ? (
          <ActionButton
            icon={Unlock}
            label="禁用 DSE"
            sub="允许加载未签名驱动"
            busy={busy || !deviceOpen}
            tone="warning"
            onClick={() => safe(() => dseIpc.disable(), "禁用 DSE")}
          />
        ) : (
          <ActionButton
            icon={Lock}
            label="恢复 DSE"
            sub="恢复驱动签名强制"
            busy={busy || !deviceOpen}
            onClick={() => safe(() => dseIpc.enable(), "恢复 DSE")}
          />
        )}

        <Divider />

        <NavButton icon={Bug} label="调试器保护" to="/debugger" />
        <NavButton icon={EyeOff} label="进程隐藏" to="/process-hide" />
        <NavButton icon={Eye} label="状态详情" to="/status" />
        <NavButton
          icon={ScrollText}
          label="驱动 Trace 控制台"
          onClick={async () => {
            try {
              await invoke("trace_open_window");
            } catch (e) {
              toast.error(`打开 trace 失败: ${String(e)}`);
            }
          }}
        />
      </CardContent>
    </Card>
  );
}

function ActionButton({
  icon: Icon,
  label,
  sub,
  busy,
  onClick,
  tone,
}: {
  icon: React.ComponentType<{ className?: string }>;
  label: string;
  sub: string;
  busy: boolean;
  onClick: () => void;
  tone?: "primary" | "warning";
}) {
  return (
    <button
      type="button"
      disabled={busy}
      onClick={onClick}
      className={cn(
        "group flex w-full items-center gap-3 rounded-md border border-transparent bg-secondary/40 px-3 py-2.5 text-left transition-all",
        "hover:border-primary/30 hover:bg-secondary disabled:cursor-not-allowed disabled:opacity-50",
        tone === "primary" && "bg-primary/10 hover:bg-primary/20",
        tone === "warning" && "bg-warning/10 hover:bg-warning/20"
      )}
    >
      <Icon
        className={cn(
          "h-4 w-4 shrink-0",
          tone === "primary" && "text-primary",
          tone === "warning" && "text-warning",
          !tone && "text-muted-foreground group-hover:text-foreground"
        )}
      />
      <div className="min-w-0 flex-1">
        <div className="truncate text-sm font-medium">{label}</div>
        <div className="truncate text-[11px] text-muted-foreground">{sub}</div>
      </div>
      <ChevronRight className="h-4 w-4 shrink-0 text-muted-foreground opacity-0 transition-opacity group-hover:opacity-100" />
    </button>
  );
}

function NavButton({
  icon: Icon,
  label,
  to,
  onClick,
}: {
  icon: React.ComponentType<{ className?: string }>;
  label: string;
  to?: string;
  onClick?: () => void;
}) {
  const navigate = useNavigate();
  return (
    <button
      type="button"
      onClick={() => (onClick ? onClick() : to ? navigate(to) : undefined)}
      className="group flex w-full items-center gap-3 rounded-md px-3 py-2 text-left text-sm text-muted-foreground transition-colors hover:bg-accent hover:text-foreground"
    >
      <Icon className="h-4 w-4 shrink-0" />
      <span className="flex-1">{label}</span>
      <ChevronRight className="h-4 w-4 opacity-0 transition-opacity group-hover:opacity-100" />
    </button>
  );
}

function Divider() {
  return <div className="my-1.5 h-px bg-border/60" />;
}

function DetailCard({
  icon: Icon,
  title,
  items,
}: {
  icon: React.ComponentType<{ className?: string }>;
  title: string;
  items: Array<[string, React.ReactNode]>;
}) {
  return (
    <Card className="card-hover">
      <CardHeader className="pb-2">
        <CardTitle className="flex items-center gap-2 text-sm">
          <Icon className="h-4 w-4 text-primary" />
          {title}
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-2">
        {items.map(([k, v]) => (
          <div key={k} className="flex items-center justify-between text-sm">
            <span className="text-muted-foreground">{k}</span>
            {v}
          </div>
        ))}
      </CardContent>
    </Card>
  );
}

function pill(text: string, tone: "success" | "warning" | "destructive" | "muted" | "info" | "primary") {
  const cls = {
    success: "pill-success",
    warning: "pill-warning",
    destructive: "pill-danger",
    muted: "pill-muted",
    info: "pill-info",
    primary: "pill-primary",
  }[tone];
  return <span className={cn("pill", cls)}>{text}</span>;
}

function boolPill(b: boolean, on: string, off: string) {
  return b ? pill(on, "success") : pill(off, "muted");
}
