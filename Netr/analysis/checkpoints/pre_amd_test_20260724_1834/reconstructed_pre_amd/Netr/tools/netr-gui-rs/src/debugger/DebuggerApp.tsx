import { useCallback, useEffect, useRef } from "react";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { toast } from "sonner";

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
import { dbgIpc, errMsg, type BuiltinRestartResult } from "./ipc";
import { clearExprModuleCache } from "./expr";

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
  const closingRef = useRef(false);
  useGlobalDebuggerHotkeys();
  useAiStreamListener();
  const showBottom = !!session.pid && !session.bottomCollapsed;
  const showRight = !!session.pid && session.rightTab !== null;

  const closeDebuggerWindow = useCallback(async () => {
    if (closingRef.current) return;
    closingRef.current = true;

    const current = useSession.getState();
    if (current.attachingPid) {
      closingRef.current = false;
      toast.warning(`正在附加 PID ${current.attachingPid}，完成后再关闭窗口`);
      return;
    }
    if (current.pid) {
      try {
        await dbgIpc.detach(current.pid);
        useSession.getState().detach();
      } catch (error) {
        closingRef.current = false;
        toast.error(`关闭前解附失败，窗口已保留: ${errMsg(error)}`);
        return;
      }
    }

    try {
      await getCurrentWindow().destroy();
    } catch (error) {
      closingRef.current = false;
      toast.error(`关闭调试器失败: ${errMsg(error)}`);
    }
  }, []);

  useEffect(() => {
    const win = getCurrentWindow();
    let disposed = false;
    let unlisten: (() => void) | null = null;
    void win.onCloseRequested((event) => {
      event.preventDefault();
      void closeDebuggerWindow();
    }).then((fn) => {
      if (disposed) fn();
      else unlisten = fn;
    });
    return () => {
      disposed = true;
      unlisten?.();
    };
  }, [closeDebuggerWindow]);

  useEffect(() => {
    let unlisten: UnlistenFn | null = null;
    let disposed = false;
    void listen<BuiltinRestartResult>("dbg-debuggee-restarted", (event) => {
      const restarted = event.payload;
      const current = useSession.getState();
      if (current.pid !== restarted.old_pid && current.pid !== restarted.new_pid) return;

      clearExprModuleCache();
      current.attach(restarted.new_pid, restarted.process_name, restarted.attach);
      const next = useSession.getState();
      next.setSelectedTid(restarted.primary_tid);
      next.setAddress(BigInt(restarted.entry_address));
      next.setMainTab("disasm");
      next.setLastHit({
        ts: Date.now(),
        tid: restarted.primary_tid,
        rip: BigInt(restarted.entry_address),
        reason: "restart_entry",
      });
      toast.success(
        `已重启 ${restarted.process_name}：PID ${restarted.old_pid} → ${restarted.new_pid}`,
        {
          description: restarted.stopped_at_entry
            ? `已停在程序入口 0x${restarted.entry_address.toString(16).toUpperCase()}`
            : "新进程已启动",
        },
      );
    }).then((fn) => {
      if (disposed) fn();
      else unlisten = fn;
    }).catch((error) => {
      toast.error(`重启事件监听失败: ${errMsg(error)}`);
    });
    return () => {
      disposed = true;
      unlisten?.();
    };
  }, []);

  return (
    <div className="flex h-full min-h-0 flex-col bg-background text-foreground">
      <TitleBar onClose={closeDebuggerWindow} />
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
