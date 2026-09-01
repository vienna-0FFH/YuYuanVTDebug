import { NavLink } from "react-router-dom";
import {
  LayoutDashboard,
  HardDrive,
  Activity,
  ShieldCheck,
  EyeOff,
  Bug,
  MemoryStick,
  Syringe,
  Crosshair,
  Keyboard,
  PanelLeftClose,
  PanelLeftOpen,
  Lock,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { useUi } from "@/store/uiStore";
import { useDriver } from "@/store/driverStore";

interface NavItem {
  to: string;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  shortcut?: string;
  /** 是否需要驱动 device 打开才有效 */
  needsDriver?: boolean;
}

interface NavGroup {
  title: string;
  items: NavItem[];
}

const groups: NavGroup[] = [
  {
    title: "概览",
    items: [
      { to: "/", label: "仪表板", icon: LayoutDashboard, shortcut: "Ctrl+1" },
    ],
  },
  {
    title: "安全",
    items: [
      { to: "/service", label: "安全服务", icon: HardDrive, shortcut: "Ctrl+2", needsDriver: true },
      { to: "/status", label: "运行状态", icon: Activity, shortcut: "Ctrl+3" },
    ],
  },
  {
    title: "安全 / 隐藏",
    items: [
      { to: "/dse", label: "DSE 开关", icon: ShieldCheck, needsDriver: true },
      { to: "/process-hide", label: "进程隐藏", icon: EyeOff, needsDriver: true },
      { to: "/driver-hide", label: "驱动隐藏", icon: EyeOff, needsDriver: true },
    ],
  },
  {
    title: "调试",
    items: [
      { to: "/launch-debugger", label: "内置调试器", icon: Bug, shortcut: "Ctrl+4" },
      { to: "/debugger", label: "调试器保护", icon: ShieldCheck, needsDriver: true },
      { to: "/hwbp", label: "硬件断点", icon: Crosshair, shortcut: "Ctrl+6", needsDriver: true },
    ],
  },
  {
    title: "进程",
    items: [
      { to: "/memory", label: "内存读写", icon: MemoryStick, shortcut: "Ctrl+5", needsDriver: true },
      { to: "/inject", label: "DLL / Shellcode", icon: Syringe, needsDriver: true },
    ],
  },
  {
    title: "输入",
    items: [{ to: "/input", label: "键鼠注入", icon: Keyboard, needsDriver: true }],
  },
];

export function Sidebar() {
  const collapsed = useUi((s) => s.sidebarCollapsed);
  const toggle = useUi((s) => s.toggleSidebar);
  const deviceOpen = useDriver((s) => s.deviceOpen);

  return (
    <aside
      className={cn(
        "flex shrink-0 flex-col border-r border-border bg-card/40 backdrop-blur-sm transition-[width] duration-200",
        collapsed ? "w-[60px]" : "w-60"
      )}
    >
      <nav className="flex-1 overflow-y-auto overflow-x-hidden py-3">
        {groups.map((group) => (
          <div key={group.title} className="mb-4 last:mb-0">
            {!collapsed && (
              <div className="px-4 pb-1.5 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground/60">
                {group.title}
              </div>
            )}
            {collapsed && <div className="mx-3 my-2 h-px bg-border" />}
            <div className="space-y-0.5 px-2">
              {group.items.map((item) => (
                <SidebarLink
                  key={item.to}
                  item={item}
                  collapsed={collapsed}
                  locked={Boolean(item.needsDriver) && !deviceOpen}
                />
              ))}
            </div>
          </div>
        ))}
      </nav>

      <button
        type="button"
        onClick={toggle}
        title={collapsed ? "展开侧栏 (Ctrl+B)" : "折叠侧栏 (Ctrl+B)"}
        className={cn(
          "flex h-10 items-center gap-2 border-t border-border px-4 text-xs text-muted-foreground transition-colors hover:bg-accent hover:text-foreground",
          collapsed && "justify-center px-0"
        )}
      >
        {collapsed ? (
          <PanelLeftOpen className="h-4 w-4" />
        ) : (
          <>
            <PanelLeftClose className="h-4 w-4" />
            <span>折叠侧栏</span>
            <span className="ml-auto rounded bg-muted px-1.5 py-0.5 text-[10px]">Ctrl+B</span>
          </>
        )}
      </button>
    </aside>
  );
}

function SidebarLink({
  item,
  collapsed,
  locked,
}: {
  item: NavItem;
  collapsed: boolean;
  locked: boolean;
}) {
  const Icon = item.icon;
  const title = collapsed
    ? `${item.label}${locked ? " (需先启动驱动)" : ""}${item.shortcut ? ` (${item.shortcut})` : ""}`
    : locked
    ? "需先启动驱动"
    : undefined;
  return (
    <NavLink
      to={item.to}
      end={item.to === "/"}
      title={title}
      className={({ isActive }) =>
        cn(
          "group relative flex items-center gap-2.5 rounded-md text-sm transition-colors",
          collapsed ? "h-9 justify-center" : "h-9 px-2.5",
          isActive
            ? "bg-primary/15 text-primary"
            : locked
            ? "text-muted-foreground/50 hover:bg-accent/40 hover:text-muted-foreground"
            : "text-muted-foreground hover:bg-accent hover:text-foreground"
        )
      }
    >
      {({ isActive }) => (
        <>
          {isActive && (
            <span className="absolute left-0 top-1.5 h-6 w-0.5 rounded-r-full bg-primary" />
          )}
          <Icon className={cn("h-4 w-4 shrink-0", isActive && "text-primary")} />
          {!collapsed && (
            <>
              <span className="truncate">{item.label}</span>
              {locked ? (
                <Lock className="ml-auto h-3 w-3 shrink-0 text-muted-foreground/70" />
              ) : item.shortcut ? (
                <span className="ml-auto rounded bg-muted/60 px-1.5 py-0.5 text-[10px] text-muted-foreground opacity-0 group-hover:opacity-100">
                  {item.shortcut}
                </span>
              ) : null}
            </>
          )}
        </>
      )}
    </NavLink>
  );
}
