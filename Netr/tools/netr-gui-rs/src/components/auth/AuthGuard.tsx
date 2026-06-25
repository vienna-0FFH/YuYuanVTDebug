import { useEffect } from "react";
import { Navigate, Outlet, useLocation } from "react-router-dom";
import { Loader2 } from "lucide-react";

import { useAuth } from "@/store/authStore";

/**
 * 路由级守卫:
 *   - 首次渲染调 bootstrap()(尝试用 keyring 凭证自动登录)
 *   - bootstrapDone 之前显示加载态
 *   - 未登录 → 重定向到 /login
 *   - 已登录 → 渲染子路由
 */
export function AuthGuard() {
  const bootstrapDone = useAuth((s) => s.bootstrapDone);
  const user = useAuth((s) => s.user);
  const bootstrap = useAuth((s) => s.bootstrap);
  const location = useLocation();

  useEffect(() => {
    if (!bootstrapDone) {
      void bootstrap();
    }
  }, [bootstrapDone, bootstrap]);

  if (!bootstrapDone) {
    return (
      <div className="flex h-screen items-center justify-center bg-background text-foreground">
        <div className="flex flex-col items-center gap-3">
          <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
          <span className="text-sm text-muted-foreground">正在恢复会话…</span>
        </div>
      </div>
    );
  }

  if (!user) {
    return <Navigate to="/login" replace state={{ from: location }} />;
  }

  return <Outlet />;
}
