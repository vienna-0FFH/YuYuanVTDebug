import { useState } from "react";
import { Code, ArrowRight, Copy, MapPin } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { DisasmPanel } from "./DisasmPanel";
import { HexPanel } from "./HexPanel";
import { RegistersPanel } from "./RegistersPanel";
import { StackPanel } from "./StackPanel";
import { BreakpointsPanel } from "./BreakpointsPanel";
import { useSession, type MainTab } from "./sessionStore";
import { evalExpression, formatAddress } from "./expr";
import { cn } from "@/lib/utils";
import { errMsg } from "./ipc";

/**
 * 主区永久面板 — 反汇编/Hex/寄存器/栈/软断点 子 tab。
 * 跳转支持表达式: hex、modname+offset、寄存器、[rax+8] 间接。
 */
export function MainViewPanel() {
  const { address, mainTab, setMainTab, pid, ctx, setAddress } = useSession();
  const [gotoText, setGotoText] = useState("");

  async function go() {
    const s = gotoText.trim();
    if (!s) return;
    try {
      const v = await evalExpression(s, { pid: pid ?? 0, ctx });
      setAddress(v);
      setGotoText("");
    } catch (e) {
      toast.error(`跳转失败: ${errMsg(e)}`);
    }
  }

  return (
    <div className="flex h-full flex-col bg-background">
      <div className="flex h-9 shrink-0 items-center gap-2 border-b border-border bg-card/60 px-3 text-xs">
        <Code className="h-3.5 w-3.5 text-primary" />
        <div className="flex h-6 rounded-md border border-border bg-background p-0.5">
          {(["disasm", "hex", "regs", "stack", "bps"] as MainTab[]).map((t) => (
            <button
              key={t}
              type="button"
              onClick={() => setMainTab(t)}
              className={cn(
                "rounded-sm px-2.5 text-[11px] font-medium transition-colors",
                mainTab === t
                  ? "bg-primary text-primary-foreground"
                  : "text-muted-foreground hover:bg-accent hover:text-foreground"
              )}
            >
              {labelOf(t)}
            </button>
          ))}
        </div>

        <div className="mx-2 h-4 w-px bg-border" />

        <button
          type="button"
          onClick={() => {
            void navigator.clipboard.writeText(formatAddress(address));
            toast.success("已复制");
          }}
          className="flex items-center gap-1 font-mono text-muted-foreground/80 hover:text-foreground"
          title="复制"
        >
          <MapPin className="h-3 w-3" />
          {formatAddress(address)}
          <Copy className="h-2.5 w-2.5 opacity-50" />
        </button>

        <Input
          value={gotoText}
          onChange={(e) => setGotoText(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && void go()}
          placeholder="跳转"
          className="ml-2 h-6 flex-1 max-w-md font-mono text-xs"
        />
        <Button size="sm" variant="outline" onClick={() => void go()} className="h-6 px-2">
          <ArrowRight className="h-3 w-3" />
        </Button>
      </div>

      <div className="min-h-0 flex-1 overflow-hidden">
        {mainTab === "disasm" && <DisasmPanel />}
        {mainTab === "hex" && <HexPanel />}
        {mainTab === "regs" && <RegistersPanel />}
        {mainTab === "stack" && <StackPanel />}
        {mainTab === "bps" && <BreakpointsPanel />}
      </div>
    </div>
  );
}

function labelOf(t: MainTab): string {
  return ({ disasm: "反汇编", hex: "Hex", regs: "寄存器", stack: "栈", bps: "软断点" } as const)[t];
}
