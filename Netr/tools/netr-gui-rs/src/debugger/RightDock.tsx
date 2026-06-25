import { X, Crosshair, Layers, Boxes, Bot, Network } from "lucide-react";

import { HwbpTool } from "./HwbpTool";
import { CallStackPanel } from "./CallStackPanel";
import { DissectPanel } from "./DissectPanel";
import { AiAssistantPanel } from "./AiAssistantPanel";
import { McpPanel } from "./McpPanel";
import { useSession, type RightTab } from "./sessionStore";
import { cn } from "@/lib/utils";

/**
 * 右侧停靠区 — HwBp / CallStack 等。打开时显示,可关。
 */
export function RightDock() {
  const { rightTab, setRightTab } = useSession();
  if (!rightTab) return null;

  const TABS: { v: NonNullable<RightTab>; label: string; Icon: typeof X }[] = [
    { v: "ai", label: "AI", Icon: Bot },
    { v: "mcp", label: "MCP", Icon: Network },
    { v: "hwbp", label: "硬件断点", Icon: Crosshair },
    { v: "callstack", label: "调用栈", Icon: Layers },
    { v: "dissect", label: "结构分析", Icon: Boxes },
  ];

  return (
    <div className="flex h-full flex-col border-l border-border bg-card/30">
      <div className="flex h-8 shrink-0 items-center border-b border-border bg-card/60 text-xs">
        <div className="flex min-w-0 flex-1 items-center gap-px overflow-x-auto pl-1">
          {TABS.map(({ v, label, Icon }) => (
            <button
              key={v}
              type="button"
              onClick={() => setRightTab(v)}
              title={label}
              className={cn(
                "flex h-7 shrink-0 items-center gap-1 whitespace-nowrap rounded-md px-2 text-[11px] font-medium transition-colors",
                rightTab === v
                  ? "bg-primary/15 text-primary"
                  : "text-muted-foreground hover:bg-accent hover:text-foreground"
              )}
            >
              <Icon className="h-3 w-3" />
              <span>{label}</span>
            </button>
          ))}
        </div>
        <button
          type="button"
          onClick={() => setRightTab(null)}
          title="关闭"
          className="mr-1 flex h-6 w-6 shrink-0 items-center justify-center rounded text-muted-foreground hover:bg-accent hover:text-foreground"
        >
          <X className="h-3.5 w-3.5" />
        </button>
      </div>
      <div className="min-h-0 flex-1 overflow-hidden">
        {rightTab === "hwbp" && <HwbpTool onClose={() => setRightTab(null)} />}
        {rightTab === "callstack" && <CallStackPanel />}
        {rightTab === "dissect" && <DissectPanel />}
        {rightTab === "ai" && <AiAssistantPanel />}
        {rightTab === "mcp" && <McpPanel />}
      </div>
    </div>
  );
}
