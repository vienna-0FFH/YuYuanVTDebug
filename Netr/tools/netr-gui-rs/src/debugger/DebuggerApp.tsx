import { TitleBar } from "@/components/layout/TitleBar";
import { AttachBar } from "./AttachBar";
import { ToolBar } from "./ToolBar";
import { MainViewPanel } from "./MainViewPanel";
import { BottomDock } from "./BottomDock";
import { RightDock } from "./RightDock";
import { DebuggerStatusBar } from "./DebuggerStatusBar";
import { useSession } from "./sessionStore";
import { ResizableHandle, ResizablePanel, ResizablePanelGroup } from "@/components/ui/resizable";
import { useGlobalDebuggerHotkeys } from "./hotkeys";
import { useAiStreamListener } from "./useAiStreamListener";
import { BreakHitToast } from "./BreakHitToast";

/**
 * 调试器主壳 — CE 风格三区:
 *   ┌─ TitleBar
 *   ├─ AttachBar (附加进程 / 状态)
 *   ├─ ToolBar   (线程 / 暂停-恢复 / 步过-步入 / 模块跳转)
 *   ├──────────────────────────────────────────┐
 *   │  主区 (反汇编/Hex/Regs/Stack/Bps)        │ 右停靠
 *   │  (永久挂载, 不能关)                       │ (HwBp /
 *   │                                          │  Callstack)
 *   ├──────────────────────────────────────────┤
 *   │  底部停靠 (Scanner / Watches / Log)      │
 *   │  (可折叠, 可拖)                           │
 *   └──────────────────────────────────────────┘
 *
 * 全部分隔条可拖。
 */
export function DebuggerApp() {
  const session = useSession();
  useGlobalDebuggerHotkeys();
  useAiStreamListener();
  const showBottom = !!session.pid && !session.bottomCollapsed;
  const showRight = !!session.pid && session.rightTab !== null;

  return (
    <div className="flex h-full min-h-0 flex-col bg-background text-foreground">
      <TitleBar />
      <AttachBar />

      {!session.pid ? (
        <div className="flex flex-1 items-center justify-center text-sm text-muted-foreground">
          请先附加进程
        </div>
      ) : (
        <>
          <ToolBar />
          {/* 水平 split: 主+底 vs 右.
              key 只在 showRight 切换时变 — RightDock 内部 tab 切换不再 remount 主区,
              否则 DisasmPanel 会重新 read_memory 刷新, 失去滚动位置. */}
          <ResizablePanelGroup
            key={`hg-${showRight ? "on" : "off"}`}
            direction="horizontal"
            className="min-h-0 flex-1"
          >
            <ResizablePanel defaultSize={showRight ? 62 : 100} minSize={35}>
              {/* 垂直 split: 主 vs 底 */}
              <ResizablePanelGroup direction="vertical">
                <ResizablePanel defaultSize={showBottom ? 65 : 100} minSize={25}>
                  <MainViewPanel />
                </ResizablePanel>
                {showBottom && (
                  <>
                    <ResizableHandle withHandle />
                    <ResizablePanel defaultSize={35} minSize={15}>
                      <BottomDock />
                    </ResizablePanel>
                  </>
                )}
              </ResizablePanelGroup>
            </ResizablePanel>
            {showRight && (
              <>
                <ResizableHandle withHandle />
                <ResizablePanel
                  defaultSize={session.rightTab === "ai" ? 38 : 28}
                  minSize={20}
                  maxSize={65}
                >
                  <RightDock />
                </ResizablePanel>
              </>
            )}
          </ResizablePanelGroup>
        </>
      )}

      <DebuggerStatusBar />
      <BreakHitToast />
    </div>
  );
}
