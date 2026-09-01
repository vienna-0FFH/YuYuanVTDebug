import { useState } from "react";
import { KeyRound, Lock, Loader2, CreditCard } from "lucide-react";
import { toast } from "sonner";

import { PageHeader } from "@/components/common/PageHeader";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { useAuth } from "@/store/authStore";

export default function Account() {
  const user = useAuth((s) => s.user);
  const changePassword = useAuth((s) => s.changePassword);
  const topup = useAuth((s) => s.topup);

  return (
    <div className="space-y-6">
      <PageHeader
        title="账号管理"
        description={user ? `已登录:${user.subject_type} #${user.subject_id}` : "未登录"}
      />

      <div className="grid gap-6 lg:grid-cols-2">
        <ChangePasswordCard onSubmit={changePassword} />
        <TopupCard onSubmit={topup} />
      </div>
    </div>
  );
}

function ChangePasswordCard({
  onSubmit,
}: {
  onSubmit: (oldPwd: string, newPwd: string) => Promise<string>;
}) {
  const [oldPwd, setOldPwd] = useState("");
  const [newPwd, setNewPwd] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!oldPwd || !newPwd) return toast.error("请填写完整");
    if (newPwd.length < 6) return toast.error("新密码至少 6 位");
    if (newPwd !== confirm) return toast.error("两次新密码不一致");
    if (newPwd === oldPwd) return toast.error("新密码不能与旧密码相同");

    setBusy(true);
    try {
      const msg = await onSubmit(oldPwd, newPwd);
      toast.success(msg || "修改成功");
      setOldPwd("");
      setNewPwd("");
      setConfirm("");
    } catch (e: unknown) {
      const m = (e as { message?: string })?.message ?? String(e);
      toast.error(`修改失败: ${m}`);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Lock className="h-4 w-4" /> 修改密码
        </CardTitle>
      </CardHeader>
      <CardContent>
        <form className="space-y-3" onSubmit={submit} autoComplete="off">
          <div className="space-y-1.5">
            <Label htmlFor="old-pwd">当前密码</Label>
            <Input
              id="old-pwd"
              type="password"
              value={oldPwd}
              onChange={(e) => setOldPwd(e.target.value)}
              disabled={busy}
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="new-pwd">新密码 (≥6 位)</Label>
            <Input
              id="new-pwd"
              type="password"
              value={newPwd}
              onChange={(e) => setNewPwd(e.target.value)}
              disabled={busy}
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="confirm-pwd">确认新密码</Label>
            <Input
              id="confirm-pwd"
              type="password"
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
              disabled={busy}
            />
          </div>
          <Button type="submit" disabled={busy}>
            {busy && <Loader2 className="h-4 w-4 animate-spin" />}
            {busy ? "提交中..." : "修改密码"}
          </Button>
        </form>
      </CardContent>
    </Card>
  );
}

function TopupCard({
  onSubmit,
}: {
  onSubmit: (u: string, p: string, k: string) => Promise<{ message: string; expires_at: number; remaining_count: number }>;
}) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [cardKey, setCardKey] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!username || !password || !cardKey) return toast.error("请填写完整");

    setBusy(true);
    try {
      const r = await onSubmit(username, password, cardKey);
      const detail = formatBalance(r);
      toast.success(detail ? `${r.message} · ${detail}` : r.message);
      setCardKey("");
    } catch (e: unknown) {
      const m = (e as { message?: string })?.message ?? String(e);
      toast.error(`充值失败: ${m}`);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <CreditCard className="h-4 w-4" /> 卡密充值
        </CardTitle>
      </CardHeader>
      <CardContent>
        <form className="space-y-3" onSubmit={submit} autoComplete="off">
          <div className="space-y-1.5">
            <Label htmlFor="tp-user">账号</Label>
            <Input
              id="tp-user"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              disabled={busy}
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="tp-pwd">密码</Label>
            <Input
              id="tp-pwd"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              disabled={busy}
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="tp-card">卡密</Label>
            <div className="relative">
              <KeyRound className="pointer-events-none absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
              <Input
                id="tp-card"
                className="pl-8 font-mono"
                value={cardKey}
                onChange={(e) => setCardKey(e.target.value)}
                disabled={busy}
                placeholder="XXXX-XXXX-XXXX-XXXX"
              />
            </div>
          </div>
          <Button type="submit" disabled={busy}>
            {busy && <Loader2 className="h-4 w-4 animate-spin" />}
            {busy ? "提交中..." : "立即充值"}
          </Button>
        </form>
      </CardContent>
    </Card>
  );
}

function formatBalance(r: { expires_at: number; remaining_count: number }): string {
  if (r.expires_at > 0) {
    return `到期 ${new Date(r.expires_at * 1000).toLocaleString()}`;
  }
  if (r.remaining_count > 0) {
    return `剩 ${r.remaining_count} 次`;
  }
  return "";
}
