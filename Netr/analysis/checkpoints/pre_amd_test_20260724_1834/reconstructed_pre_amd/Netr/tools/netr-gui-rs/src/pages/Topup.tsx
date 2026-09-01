import { useState } from "react";
import { useNavigate, Link, useSearchParams } from "react-router-dom";
import { Lock, User as UserIcon, KeyRound, Loader2, CreditCard } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardHeader, CardTitle } from "@/components/ui/card";
import { authIpc } from "@/ipc/auth";
import { TitleBar } from "@/components/layout/TitleBar";

/**
 * 免登录卡密充值页。
 * 与 /login、/register 同级路由,不受 AuthGuard 保护。
 * 用于「注册时没填卡密 → 无法登录」的死锁场景。
 */
export default function Topup() {
  const navigate = useNavigate();
  const [params] = useSearchParams();

  const [username, setUsername] = useState(params.get("u") ?? "");
  const [password, setPassword] = useState("");
  const [cardKey, setCardKey] = useState("");
  const [busy, setBusy] = useState(false);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!username || !password || !cardKey) return toast.error("请填写完整");

    setBusy(true);
    try {
      const r = await authIpc.topup(username, password, cardKey);
      const detail =
        r.expires_at > 0
          ? `到期 ${new Date(r.expires_at * 1000).toLocaleString()}`
          : r.remaining_count > 0
          ? `剩 ${r.remaining_count} 次`
          : "";
      toast.success(detail ? `${r.message} · ${detail}` : r.message);
      setTimeout(() => navigate("/login", { replace: true }), 800);
    } catch (e: unknown) {
      const msg = (e as { message?: string })?.message ?? String(e);
      toast.error(`充值失败: ${msg}`);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex h-screen flex-col bg-background text-foreground">
      <TitleBar />

      <div className="flex flex-1 items-center justify-center p-6">
        <Card className="grid w-full max-w-3xl overflow-hidden md:grid-cols-2">
          <div className="bg-steel relative hidden overflow-hidden p-8 text-white md:flex md:flex-col md:justify-between">
            <div className="absolute -right-12 -top-12 h-48 w-48 rounded-full bg-white/15 blur-3xl" />
            <div className="absolute -bottom-16 -left-12 h-56 w-56 rounded-full bg-white/8 blur-3xl" />
            <div className="pointer-events-none absolute inset-0 opacity-30 mix-blend-overlay"
              style={{
                backgroundImage:
                  "linear-gradient(105deg, transparent 30%, rgba(255,255,255,0.20) 50%, transparent 70%)",
              }}
            />

            <div className="relative flex items-center gap-2">
              <div className="h-7 w-7 rounded-md bg-white/20 backdrop-blur-sm ring-1 ring-white/30" />
              <div className="flex flex-col leading-tight">
                <span className="text-silver text-base font-semibold tracking-wide">御元虚拟化安全工具</span>
                <span className="text-[10px] uppercase tracking-[0.15em] text-white/60">GuardMeta · Virtual Security Platform</span>
              </div>
            </div>

            <div className="relative space-y-3">
              <h2 className="text-silver text-2xl font-semibold leading-tight">
                卡密充值
                <br />
                无需登录
              </h2>
              <p className="text-sm text-white/75">
                适用于:已注册但未激活,或老用户续费。
              </p>
            </div>

            <div className="relative flex items-center gap-2 text-xs text-white/75">
              <CreditCard className="h-3.5 w-3.5" />
              输入账密 + 卡密 · 部署端校验所有权
            </div>
          </div>

          <div className="p-8">
            <CardHeader className="p-0">
              <CardTitle>卡密充值</CardTitle>
            </CardHeader>

            <form className="mt-6 space-y-4" onSubmit={onSubmit} autoComplete="off">
              <Field id="tp-user" label="账号" icon={UserIcon} value={username} onChange={setUsername} disabled={busy} autoFocus />
              <Field id="tp-pwd" label="密码" icon={Lock} type="password" value={password} onChange={setPassword} disabled={busy} />
              <Field
                id="tp-card"
                label="卡密"
                icon={KeyRound}
                value={cardKey}
                onChange={setCardKey}
                disabled={busy}
                mono
                placeholder="XXXX-XXXX-XXXX-XXXX"
              />

              <Button type="submit" className="w-full" disabled={busy}>
                {busy && <Loader2 className="h-4 w-4 animate-spin" />}
                {busy ? "提交中..." : "立即充值"}
              </Button>

              <div className="flex justify-between text-xs text-muted-foreground">
                <Link to="/register" className="hover:text-primary hover:underline">
                  没有账号 → 注册
                </Link>
                <Link to="/login" className="hover:text-primary hover:underline">
                  返回登录
                </Link>
              </div>
            </form>
          </div>
        </Card>
      </div>
    </div>
  );
}

function Field({
  id,
  label,
  icon: Icon,
  value,
  onChange,
  disabled,
  autoFocus,
  type = "text",
  placeholder,
  mono,
}: {
  id: string;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  value: string;
  onChange: (v: string) => void;
  disabled?: boolean;
  autoFocus?: boolean;
  type?: string;
  placeholder?: string;
  mono?: boolean;
}) {
  return (
    <div className="space-y-1.5">
      <Label htmlFor={id}>{label}</Label>
      <div className="relative">
        <Icon className="pointer-events-none absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
        <Input
          id={id}
          type={type}
          className={`pl-8 ${mono ? "font-mono" : ""}`}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          disabled={disabled}
          autoFocus={autoFocus}
          placeholder={placeholder}
          autoComplete="off"
        />
      </div>
    </div>
  );
}
