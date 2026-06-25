import { useEffect, useState } from "react";
import { useNavigate, Link } from "react-router-dom";
import { Lock, User as UserIcon, ShieldCheck, Loader2 } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Checkbox } from "@/components/ui/checkbox";
import { Card, CardHeader, CardTitle } from "@/components/ui/card";
import { authIpc } from "@/ipc/auth";
import { useAuth } from "@/store/authStore";
import { TitleBar } from "@/components/layout/TitleBar";

/**
 * 登录页 — 账号密码模式。
 * 设计:
 *   - 顶部留 TitleBar(无边框窗口,登录态也要能拖动 / 关闭)
 *   - 中间内容卡片,左侧品牌 + 标语,右侧表单
 *   - 启动时 bootstrap 一次:如果本地有保存账号且 auto-login 成功,直接跳走;
 *     否则保留 username 预填
 */
export default function Login() {
  const navigate = useNavigate();
  const login = useAuth((s) => s.login);

  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [remember, setRemember] = useState(true);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    let cancel = false;
    authIpc.bootstrap().then((b) => {
      if (cancel) return;
      if (b.saved_username) setUsername(b.saved_username);
    });
    return () => {
      cancel = true;
    };
  }, []);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!username || !password) {
      toast.error("请输入账号与密码");
      return;
    }
    setBusy(true);
    try {
      await login(username, password, remember);
      toast.success("登录成功");
      navigate("/", { replace: true });
    } catch (e: unknown) {
      const msg =
        (e as { message?: string })?.message ?? String(e);
      toast.error(`登录失败: ${msg}`);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex h-screen flex-col bg-background text-foreground">
      <TitleBar />

      <div className="flex flex-1 items-center justify-center p-6">
        <Card className="grid w-full max-w-3xl overflow-hidden md:grid-cols-2">
          {/* 品牌区 */}
          <div className="bg-steel relative hidden overflow-hidden p-8 text-white md:flex md:flex-col md:justify-between">
            {/* 光晕 + 钢面反光 */}
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
                Type-1 Hypervisor
                <br />
                控制台
              </h2>
              <p className="text-sm text-white/75">
                VMX / SVM 双平台,反作弊定向,内核态注入,EPT 隐身。
              </p>
            </div>

            <div className="relative flex items-center gap-2 text-xs text-white/75">
              <ShieldCheck className="h-3.5 w-3.5" />
              端到端加密 · Ed25519 验签 · 心跳保护
            </div>
          </div>

          {/* 表单区 */}
          <div className="p-8">
            <CardHeader className="p-0">
              <CardTitle>账号登录</CardTitle>
            </CardHeader>

            <form className="mt-6 space-y-4" onSubmit={onSubmit}>
              <div className="space-y-1.5">
                <Label htmlFor="username">账号</Label>
                <div className="relative">
                  <UserIcon className="pointer-events-none absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
                  <Input
                    id="username"
                    autoComplete="username"
                    className="pl-8"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    disabled={busy}
                    autoFocus
                  />
                </div>
              </div>

              <div className="space-y-1.5">
                <Label htmlFor="password">密码</Label>
                <div className="relative">
                  <Lock className="pointer-events-none absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
                  <Input
                    id="password"
                    type="password"
                    autoComplete="current-password"
                    className="pl-8"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    disabled={busy}
                  />
                </div>
              </div>

              <div className="flex items-center gap-2">
                <Checkbox
                  id="remember"
                  checked={remember}
                  onCheckedChange={setRemember}
                  disabled={busy}
                />
                <Label htmlFor="remember" className="cursor-pointer">
                  记住账号(凭据加密存放于 Windows 凭据管理器)
                </Label>
              </div>

              <Button type="submit" className="w-full" disabled={busy}>
                {busy && <Loader2 className="h-4 w-4 animate-spin" />}
                {busy ? "登录中..." : "登录"}
              </Button>

              <div className="flex items-center justify-between text-xs text-muted-foreground">
                <Link to="/register" className="text-primary hover:underline">
                  立即注册
                </Link>
                <Link to="/topup" className="text-primary hover:underline">
                  卡密充值
                </Link>
              </div>
            </form>
          </div>
        </Card>
      </div>
    </div>
  );
}
