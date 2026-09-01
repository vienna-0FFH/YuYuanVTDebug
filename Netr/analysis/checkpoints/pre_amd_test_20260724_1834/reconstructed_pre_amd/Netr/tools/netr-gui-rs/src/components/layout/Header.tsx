import { useEffect } from "react";
import { Sun, Moon, PanelLeftClose, PanelLeftOpen } from "lucide-react";
import { useLocation, useNavigate } from "react-router-dom";

import { Button } from "@/components/ui/button";
import { useTheme } from "@/store/themeStore";
import { useUi } from "@/store/uiStore";
import { UserMenu } from "@/components/auth/UserMenu";

const ROUTE_LABELS: Record<string, string> = {
  "/": "仪表板",
  "/account": "账号管理",
  "/service": "安全服务",
  "/status": "系统状态",
  "/dse": "DSE 开关",
  "/process-hide": "进程隐藏",
  "/driver-hide": "驱动隐藏",
  "/debugger": "调试器保护",
  "/launch-debugger": "内置调试器",
  "/memory": "内存读写",
  "/inject": "DLL / Shellcode 注入",
  "/hwbp": "硬件断点",
  "/input": "底层输入",
};

export function Header() {
  const theme = useTheme((s) => s.theme);
  const toggleTheme = useTheme((s) => s.toggle);
  const sidebarCollapsed = useUi((s) => s.sidebarCollapsed);
  const toggleSidebar = useUi((s) => s.toggleSidebar);
  const navigate = useNavigate();
  const { pathname } = useLocation();
  const crumb = ROUTE_LABELS[pathname] ?? "御元虚拟化安全工具";

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (!e.ctrlKey || e.shiftKey || e.altKey) return;
      const key = e.key.toLowerCase();
      const map: Record<string, string> = {
        "1": "/",
        "2": "/service",
        "3": "/status",
        "4": "/launch-debugger",
        "5": "/memory",
        "6": "/hwbp",
      };
      if (map[key]) {
        e.preventDefault();
        navigate(map[key]);
      } else if (key === "d") {
        e.preventDefault();
        toggleTheme();
      } else if (key === "b") {
        e.preventDefault();
        toggleSidebar();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [navigate, toggleTheme, toggleSidebar]);

  return (
    <header className="flex h-12 shrink-0 items-center justify-between border-b border-border bg-card/30 px-3 backdrop-blur-sm">
      <div className="flex items-center gap-2">
        <Button
          variant="ghost"
          size="icon"
          onClick={toggleSidebar}
          aria-label={sidebarCollapsed ? "展开侧栏" : "折叠侧栏"}
          title="Ctrl+B"
        >
          {sidebarCollapsed ? (
            <PanelLeftOpen className="h-4 w-4" />
          ) : (
            <PanelLeftClose className="h-4 w-4" />
          )}
        </Button>
        <div className="ml-1 flex items-center gap-2 text-sm">
          <span className="text-muted-foreground">御元虚拟化安全工具</span>
          <span className="text-muted-foreground/40">/</span>
          <span className="font-medium">{crumb}</span>
        </div>
      </div>

      <div className="flex items-center gap-1">
        <Button
          variant="ghost"
          size="icon"
          onClick={toggleTheme}
          aria-label={theme === "dark" ? "切换浅色" : "切换深色"}
          title="Ctrl+D 切换主题"
        >
          {theme === "dark" ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
        </Button>
        <UserMenu />
      </div>
    </header>
  );
}
