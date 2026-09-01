import { useEffect, useLayoutEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { useNavigate } from "react-router-dom";
import { User as UserIcon, LogOut, ShieldCheck, Settings } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { useAuth } from "@/store/authStore";
import { cn } from "@/lib/utils";

/**
 * 顶部头像/账号下拉。
 * - 显示当前账号、subject 信息、到期时间
 * - 提供"立即心跳"+"登出"
 */
export function UserMenu() {
  const user = useAuth((s) => s.user);
  const logout = useAuth((s) => s.logout);
  const checkOnline = useAuth((s) => s.checkOnline);
  const navigate = useNavigate();
  const [open, setOpen] = useState(false);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const panelRef = useRef<HTMLDivElement>(null);
  const [pos, setPos] = useState<{ top: number; right: number } | null>(null);

  // 计算 popover 在 viewport 中的固定位置(锚到触发器右下方)
  useLayoutEffect(() => {
    if (!open || !triggerRef.current) return;
    const update = () => {
      const r = triggerRef.current!.getBoundingClientRect();
      setPos({
        top: r.bottom + 8,
        right: window.innerWidth - r.right,
      });
    };
    update();
    window.addEventListener("resize", update);
    window.addEventListener("scroll", update, true);
    return () => {
      window.removeEventListener("resize", update);
      window.removeEventListener("scroll", update, true);
    };
  }, [open]);

  // 外部点击关闭(触发器和面板内都不算外部)
  useEffect(() => {
    if (!open) return;
    const onClick = (e: MouseEvent) => {
      const t = e.target as Node;
      if (
        !triggerRef.current?.contains(t) &&
        !panelRef.current?.contains(t)
      ) {
        setOpen(false);
      }
    };
    document.addEventListener("mousedown", onClick);
    return () => document.removeEventListener("mousedown", onClick);
  }, [open]);

  if (!user) return null;

  async function onLogout() {
    setOpen(false);
    try {
      await logout();
      toast.success("已注销");
      navigate("/login", { replace: true });
    } catch (e: unknown) {
      const msg = (e as { message?: string })?.message ?? String(e);
      toast.error(`注销失败: ${msg}`);
    }
  }

  async function onHeartbeat() {
    setOpen(false);
    const online = await checkOnline();
    if (online) {
      toast.success("会话在线");
    } else {
      toast.error("会话已下线");
      navigate("/login", { replace: true });
    }
  }

  const panel =
    open && pos ? (
      <div
        ref={panelRef}
        className={cn(
          "fixed z-[200] w-72 overflow-hidden rounded-md border border-border text-popover-foreground shadow-2xl shadow-black/50",
          "animate-in fade-in-0 zoom-in-95"
        )}
        style={{
          top: pos.top,
          right: pos.right,
          backgroundColor: "hsl(var(--popover))",
        }}
      >
        <div className="px-3 py-3">
          <div className="text-sm font-medium truncate">
            {user.subject_type === "account" ? "账号" : "卡密"} #{user.subject_id}
          </div>
          <div className="mt-0.5 text-xs text-muted-foreground">
            {user.notice || formatExpiry(user.expires_at, user.remaining_count)}
          </div>
          {user.machine_code && (
            <div className="mt-2 flex items-center gap-1 rounded bg-muted px-2 py-1 text-[10px] text-muted-foreground font-mono truncate">
              <ShieldCheck className="h-3 w-3 shrink-0" />
              {user.machine_code.slice(0, 16)}...
            </div>
          )}
        </div>

        <div className="h-px bg-border" />

        <div className="p-1">
          <button
            type="button"
            onClick={onHeartbeat}
            className="flex w-full items-center gap-2 rounded-sm px-3 py-2 text-sm hover:bg-accent"
          >
            <ShieldCheck className="h-4 w-4" />
            检查会话状态
          </button>
          <button
            type="button"
            onClick={() => {
              setOpen(false);
              navigate("/account");
            }}
            className="flex w-full items-center gap-2 rounded-sm px-3 py-2 text-sm hover:bg-accent"
          >
            <Settings className="h-4 w-4" />
            账号管理 (改密 / 充值)
          </button>
          <button
            type="button"
            onClick={onLogout}
            className="flex w-full items-center gap-2 rounded-sm px-3 py-2 text-sm text-destructive hover:bg-destructive/10"
          >
            <LogOut className="h-4 w-4" />
            注销
          </button>
        </div>
      </div>
    ) : null;

  return (
    <>
      <Button
        ref={triggerRef}
        variant="ghost"
        size="icon"
        onClick={() => setOpen((v) => !v)}
        aria-label="账号菜单"
      >
        <UserIcon className="h-4 w-4" />
      </Button>
      {panel && createPortal(panel, document.body)}
    </>
  );
}

function formatExpiry(expiresAt: number, remainingCount: number): string {
  if (remainingCount >= 0) {
    return `剩余次数 ${remainingCount}`;
  }
  if (expiresAt <= 0) {
    return "永久";
  }
  const d = new Date(expiresAt * 1000);
  return `到期 ${d.toLocaleString("zh-CN", { hour12: false })}`;
}
