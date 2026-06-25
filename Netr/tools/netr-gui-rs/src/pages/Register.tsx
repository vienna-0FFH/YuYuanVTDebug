import { useState } from "react";
import { useNavigate, Link } from "react-router-dom";
import { Lock, User as UserIcon, KeyRound, Loader2, ShieldCheck } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardHeader, CardTitle } from "@/components/ui/card";
import { authIpc } from "@/ipc/auth";
import { useAuth } from "@/store/authStore";
import { TitleBar } from "@/components/layout/TitleBar";

export default function Register() {
  const navigate = useNavigate();
  const login = useAuth((s) => s.login);

  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [cardKey, setCardKey] = useState("");
  const [busy, setBusy] = useState(false);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!username || !password) return toast.error("请输入账号与密码");
    if (password.length < 6) return toast.error("密码至少 6 位");
    if (password !== confirm) return toast.error("两次密码不一致");

    const ck = cardKey.trim();
    setBusy(true);
    try {
      // Step 1: 注册 — 单独 RPC
      await authIpc.register(username, password, ck || null);
    } catch (e: unknown) {
      const msg = (e as { message?: string })?.message ?? String(e);
      toast.error(`注册失败: ${msg}`);
      setBusy(false);
      return;
    }

    // 没填卡密 → 账号已建,但无授权登不上,直接导去 /topup,把账号预填
    if (!ck) {
      toast.success("注册成功 · 请充值卡密后登录");
      setBusy(false);
      navigate(`/topup?u=${encodeURIComponent(username)}`, { replace: true });
      return;
    }

    // Step 2: 带卡密注册 → 自动登录
    try {
      await login(username, password, true);
      toast.success("注册并登录成功");
      navigate("/", { replace: true });
    } catch (e: unknown) {
      const msg = (e as { message?: string })?.message ?? String(e);
      // 注册已成功,登录失败常因服务端卡密绑定异步还没就位 — 给出明确指引
      toast.error(`注册成功但登录失败: ${msg};请前往登录页重试`);
      navigate("/login", { replace: true });
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
                创建账号
                <br />
                开始使用
              </h2>
              <p className="text-sm text-white/75">
                可选附带卡密直接激活时长 / 次数。
              </p>
            </div>

            <div className="relative flex items-center gap-2 text-xs text-white/75">
              <ShieldCheck className="h-3.5 w-3.5" />
              密码不会以明文形式发送 · 机器码本地生成
            </div>
          </div>

          <div className="p-8">
            <CardHeader className="p-0">
              <CardTitle>账号注册</CardTitle>
            </CardHeader>

            <form className="mt-6 space-y-4" onSubmit={onSubmit}>
              <Field
                id="reg-username"
                label="账号"
                icon={UserIcon}
                value={username}
                onChange={setUsername}
                disabled={busy}
                autoFocus
              />
              <Field
                id="reg-password"
                label="密码 (≥6 位)"
                icon={Lock}
                type="password"
                value={password}
                onChange={setPassword}
                disabled={busy}
              />
              <Field
                id="reg-confirm"
                label="确认密码"
                icon={Lock}
                type="password"
                value={confirm}
                onChange={setConfirm}
                disabled={busy}
              />
              <Field
                id="reg-card"
                label="卡密 (可选)"
                icon={KeyRound}
                value={cardKey}
                onChange={setCardKey}
                disabled={busy}
                placeholder="留空则仅注册"
              />

              <Button type="submit" className="w-full" disabled={busy}>
                {busy && <Loader2 className="h-4 w-4 animate-spin" />}
                {busy ? "提交中..." : "注册并登录"}
              </Button>

              <p className="text-[11px] leading-relaxed text-muted-foreground">
                <KeyRound className="mr-1 inline h-3 w-3" />
                未填卡密的账号无法登录,可注册后单独前往
                <Link to="/topup" className="ml-1 text-primary hover:underline">
                  卡密充值
                </Link>
                。
              </p>

              <div className="flex items-center justify-between text-xs text-muted-foreground">
                <Link to="/topup" className="hover:text-primary hover:underline">
                  仅充值
                </Link>
                <Link to="/login" className="text-primary hover:underline">
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
}) {
  return (
    <div className="space-y-1.5">
      <Label htmlFor={id}>{label}</Label>
      <div className="relative">
        <Icon className="pointer-events-none absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
        <Input
          id={id}
          type={type}
          className="pl-8"
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
