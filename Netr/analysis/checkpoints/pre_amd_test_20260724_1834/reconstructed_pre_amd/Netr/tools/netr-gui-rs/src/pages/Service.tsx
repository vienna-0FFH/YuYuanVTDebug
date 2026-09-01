import { useEffect, useState } from "react";
import { ShieldPlus, ShieldOff, ShieldCheck, AlertTriangle, Loader2, FileCheck, FileWarning } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { driverIpc } from "@/ipc/driver";
import { systemIpc, type DriverFile } from "@/ipc";
import { useAuth } from "@/store/authStore";
import {
  AUTO_REGISTER_GUI_WITH_DRIVER,
  useDriver,
  serviceStateLabel,
  serviceStateTone,
} from "@/store/driverStore";
import { cn } from "@/lib/utils";
import { errMsg } from "@/debugger/ipc";

/**
 * 安全服务页(原:驱动服务)
 *
 * 用户视角:只有两个动作 ——「加载安全工具」/「卸载安全工具」
 * 内部:
 *   加载 = install + start + openDevice + 自动 license
 *   调试器保护 = 在 Bridge 注入实际调试器时按需注册，不由状态轮询触发
 *   卸载 = closeDevice + stop + uninstall
 *
 * 驱动路径固定为 GUI exe 同目录的 GuardMetaCore.sys,不允许用户修改。
 */
export default function Service() {
  const service = useDriver((s) => s.service);
  const deviceOpen = useDriver((s) => s.deviceOpen);
  const selfProtected = useDriver((s) => s.selfProtected);
  const selfProtectError = useDriver((s) => s.selfProtectError);
  const refresh = useDriver((s) => s.refreshService);
  const startPoll = useDriver((s) => s.startPolling);
  const stopPoll = useDriver((s) => s.stopPolling);

  const trySubmit = useAuth((s) => s.trySubmitToDriver);
  const driverLicensed = useAuth((s) => s.driverLicensed);
  const lastAuthError = useAuth((s) => s.lastError);

  const [driverFile, setDriverFile] = useState<DriverFile | null>(null);
  const [busy, setBusy] = useState(false);
  const [phase, setPhase] = useState<string>("");

  useEffect(() => {
    startPoll();
    return () => stopPoll();
  }, [startPoll, stopPoll]);

  // 1 秒轮一次驱动文件存在性(用户可能把 GuardMetaCore.sys 放进来)
  useEffect(() => {
    let cancelled = false;
    const tick = async () => {
      try {
        const f = await systemIpc.resolveDriverPath();
        if (!cancelled) setDriverFile(f);
      } catch {
        // ignore
      }
    };
    void tick();
    const id = setInterval(tick, 1500);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, []);

  async function load() {
    if (!driverFile?.exists) {
      toast.error(`找不到安全工具:${driverFile?.path ?? "GuardMetaCore.sys"}`);
      return;
    }
    setBusy(true);
    try {
      // 1) install(已装会失败但 SCM 会返"已存在",忽略)
      if (service?.state === "not_installed") {
        setPhase("注册安全工具…");
        await driverIpc.install(driverFile.path);
      }
      // 2) start
      if (service?.state !== "running") {
        setPhase("启动安全工具…");
        await driverIpc.start();
        await new Promise((r) => setTimeout(r, 400));
      }
      // 3) openDevice
      if (!deviceOpen) {
        setPhase("打开设备通道…");
        await driverIpc.openDevice();
      }
      // 4) license + self-protect 由 driverStore 自动接通
      setPhase("下发授权…");
      await trySubmit();
      await refresh();
      toast.success("安全工具已加载");
    } catch (e: unknown) {
      const msg = (e as { message?: string })?.message ?? String(e);
      toast.error(`加载失败: ${msg}`);
    } finally {
      setBusy(false);
      setPhase("");
    }
  }

  async function unload() {
    setBusy(true);
    try {
      if (deviceOpen) {
        setPhase("关闭设备通道…");
        try {
          await driverIpc.closeDevice();
        } catch {
          // ignore
        }
      }
      if (service?.state === "running") {
        setPhase("停止安全工具…");
        await driverIpc.stop();
        await new Promise((r) => setTimeout(r, 400));
      }
      if (service?.state !== "not_installed") {
        setPhase("注销安全工具…");
        await driverIpc.uninstall();
      }
      await refresh();
      toast.success("安全工具已卸载");
    } catch (e: unknown) {
      const msg = (e as { message?: string })?.message ?? String(e);
      toast.error(`卸载失败: ${msg}`);
    } finally {
      setBusy(false);
      setPhase("");
    }
  }

  // 综合判定:加载完成的标志 = device 已开
  const fullyLoaded = deviceOpen && service?.state === "running";
  const stateLabel = serviceStateLabel(service?.state);
  const stateTone = serviceStateTone(service?.state);
  const selfProtectionLabel = selfProtected
    ? "已激活"
    : AUTO_REGISTER_GUI_WITH_DRIVER
    ? selfProtectError
      ? "登记失败"
      : "等待登记"
    : "被动模式";

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold tracking-tight">安全服务</h1>

      {/* 文件状态 */}
      <Card className={cn("border", driverFile?.exists ? "border-success/30" : "border-warning/40 bg-warning/5")}>
        <CardContent className="flex items-start gap-3 p-4 text-sm">
          {driverFile?.exists ? (
            <FileCheck className="mt-0.5 h-4 w-4 shrink-0 text-success" />
          ) : (
            <FileWarning className="mt-0.5 h-4 w-4 shrink-0 text-warning" />
          )}
          <div className="min-w-0 flex-1">
            <div className="font-medium">
              {driverFile?.exists ? "安全工具文件就绪" : "未找到安全工具文件"}
            </div>
            <div className="mt-0.5 truncate text-xs text-muted-foreground" title={driverFile?.path}>
              {driverFile?.path ?? "正在查询…"}
            </div>
            {!driverFile?.exists && (
              <div className="mt-1 text-xs text-warning">
                请把 <code className="rounded bg-warning/15 px-1.5 py-0.5">GuardMetaCore.sys</code> 放到本程序所在目录后再加载
              </div>
            )}
          </div>
        </CardContent>
      </Card>

      {/* 状态总览 */}
      <Card className="card-hover">
        <CardHeader>
          <CardTitle>当前状态</CardTitle>
        </CardHeader>
        <CardContent className="grid gap-4 sm:grid-cols-3">
          <StatBlock label="服务" value={stateLabel} tone={stateTone} />
          <StatBlock
            label="设备通道"
            value={deviceOpen ? "已打开" : "已关闭"}
            tone={deviceOpen ? "success" : "muted"}
          />
          <StatBlock
            label="主界面保护"
            value={selfProtectionLabel}
            tone={selfProtected ? "success" : selfProtectError ? "warning" : "muted"}
          />
        </CardContent>
      </Card>

      {/* 操作 */}
      <Card>
        <CardHeader>
          <CardTitle>操作</CardTitle>
        </CardHeader>
        <CardContent className="grid gap-3 sm:grid-cols-2">
          <Button
            size="lg"
            disabled={busy || fullyLoaded || !driverFile?.exists}
            onClick={load}
            className="h-12"
          >
            {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <ShieldPlus className="h-4 w-4" />}
            {busy ? phase || "加载中..." : fullyLoaded ? "已加载" : "加载安全工具"}
          </Button>
          <Button
            size="lg"
            variant="destructive"
            disabled={busy || service?.state === "not_installed"}
            onClick={unload}
            className="h-12"
          >
            {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <ShieldOff className="h-4 w-4" />}
            {busy ? phase || "卸载中..." : "卸载安全工具"}
          </Button>
        </CardContent>
      </Card>

      {/* 加载成功后的状态 */}
      {fullyLoaded && (
        <Card className="border-success/30 bg-success/5">
          <CardContent className="flex items-center gap-3 p-4 text-sm">
            <ShieldCheck className="h-5 w-5 text-success" />
            <div className="flex-1">
              <div className="font-medium text-success">安全工具运行中</div>
              <div className="text-xs text-muted-foreground">
                授权: <span className={driverLicensed ? "text-success" : "text-warning"}>{driverLicensed ? "已下发" : "等待中…"}</span>
                {" · "}
                主界面保护: <span className={selfProtected ? "text-success" : "text-muted-foreground"}>{selfProtectionLabel}</span>
              </div>
              {!AUTO_REGISTER_GUI_WITH_DRIVER && (
                <div className="mt-1 text-xs text-muted-foreground">
                  被动模式不会因轮询安装 Hook；请在“调试器保护”页启动或注入实际调试器。
                </div>
              )}
              {!driverLicensed && lastAuthError && (
                <div className="mt-1 text-xs text-warning">授权下发失败: {lastAuthError}</div>
              )}
              {AUTO_REGISTER_GUI_WITH_DRIVER && driverLicensed && !selfProtected && selfProtectError && (
                <div className="mt-1 text-xs text-warning">自我保护登记失败: {selfProtectError}</div>
              )}
            </div>
          </CardContent>
        </Card>
      )}

      {/* P21:授权失败时显示诊断面板 */}
      {fullyLoaded && !driverLicensed && (
        <LicenseDumpCard />
      )}

      {/* 加载失败/缺文件的备用说明 */}
      {!driverFile?.exists && (
        <Card className="border-border/60">
          <CardContent className="flex items-start gap-3 p-4 text-sm">
            <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-muted-foreground" />
            <div className="text-xs text-muted-foreground">
              安全工具不会与本程序一起发布。请向运营获取 <code>GuardMetaCore.sys</code> 文件,
              放到本程序所在目录(即上方显示路径所在目录),刷新页面后再加载。
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

function LicenseDumpCard() {
  const [dump, setDump] = useState<Awaited<ReturnType<typeof authIpcLazy>> | null>(null);
  const [busy, setBusy] = useState(false);

  async function load() {
    setBusy(true);
    try {
      const d = await authIpcLazy();
      setDump(d);
    } catch (e: unknown) {
      toast.error(`拉取诊断失败: ${errMsg(e)}`);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card className="border-warning/30">
      <CardHeader className="pb-3">
        <CardTitle className="text-base">授权下发诊断</CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        <Button size="sm" onClick={load} disabled={busy}>
          {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : null}
          拉取当前 license 诊断信息
        </Button>
        {dump && (
          <pre className="max-h-96 overflow-auto rounded-md border bg-muted/40 p-3 font-mono text-[11px]">
{`*** 本地验证 (用同一栈 ed25519-dalek) : ${dump.local_verify_ok ? "✓ PASS — 数据正确,driver bug" : "❌ FAIL — 数据本身就是错的,SDK 给我们的字段跟服务端签名时不一致"} ***
*** GUI 端 SHA-512(R||A||M)[0..16] = ${dump.sha512_ram_first16_hex} ***
    驱动日志 [Ed25519] sha512(R||A||M)[0..16]=... 跟这个比对,不一致 = driver SHA-512 bug


subject_type   : ${dump.subject_type}
subject_id     : ${dump.subject_id}
machine_code   : ${dump.machine_code}
expires_at     : ${dump.expires_at}${dump.expires_at > 0 ? `  (${new Date(dump.expires_at * 1000).toLocaleString()})` : "  (次数卡)"}
now_unix       : ${dump.now_unix}  (${new Date(dump.now_unix * 1000).toLocaleString()})
expired?       : ${dump.expires_at > 0 && dump.now_unix > dump.expires_at ? "❌ 是,已过期" : "✓ 否"}
token          : ${dump.token}
auth_sig_len   : ${dump.auth_sig_len}${dump.auth_sig_len === 64 ? "  ✓" : "  ❌ 必须 64"}
auth_sig_hex   : ${dump.auth_sig_hex.slice(0, 64)}
                 ${dump.auth_sig_hex.slice(64)}
deploy_pub_hex : ${dump.deploy_pub_hex}
app_key        : ${dump.app_key}
canonical      :
${dump.canonical}`}
          </pre>
        )}
        <div className="text-xs text-muted-foreground">
          下载 DebugView 后管理员运行,勾选「Capture Kernel」,在驱动失败时会输出 <code>[HvLic]</code> 开头的诊断,
          可直接告诉我那行错误。
        </div>
      </CardContent>
    </Card>
  );
}

async function authIpcLazy() {
  const { authIpc } = await import("@/ipc/auth");
  return authIpc.licenseDump();
}

function StatBlock({
  label,
  value,
  tone,
}: {
  label: string;
  value: string;
  tone: "success" | "warning" | "destructive" | "muted";
}) {
  const valueColor = {
    success: "text-success",
    warning: "text-warning",
    destructive: "text-destructive",
    muted: "text-foreground",
  }[tone];
  return (
    <div className="rounded-md border border-border bg-card/40 p-3">
      <div className="text-xs text-muted-foreground">{label}</div>
      <div className={`mt-1 text-lg font-semibold ${valueColor}`}>{value}</div>
    </div>
  );
}
