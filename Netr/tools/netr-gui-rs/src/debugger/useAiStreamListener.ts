import { useEffect } from "react";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { toast } from "sonner";

import { useAi, type ChatMsg } from "./aiStore";

/**
 * 全局 AI 流式事件监听 — 挂在 DebuggerApp 顶层. 不依赖 AiAssistantPanel 是否挂载,
 * 切右停靠 tab 时 AI 仍在跑, 状态走 zustand, 切回来一切如常.
 *
 * 跟随 sessionId 重订阅. sessionId 变化(开新会话 / 加载历史) → 取消旧 listen, 装新的.
 */
export function useAiStreamListener() {
  const sessionId = useAi((s) => s.sessionId);
  const setBusy = useAi((s) => s.setBusy);
  const setCurrentRound = useAi((s) => s.setCurrentRound);
  const setActiveTool = useAi((s) => s.setActiveTool);
  const setRetryInfo = useAi((s) => s.setRetryInfo);
  const appendMessage = useAi((s) => s.appendMessage);

  useEffect(() => {
    let unlisten: UnlistenFn | undefined;
    let cancelled = false;
    const channel = `ai-run::${sessionId}`;
    void listen<{ kind: string; data: Record<string, unknown> }>(channel, (ev) => {
      const { kind, data } = ev.payload;
      switch (kind) {
        case "round_start":
          setCurrentRound((data.round as number) ?? 0);
          setActiveTool(null);
          setRetryInfo(null);
          break;
        case "assistant":
          setRetryInfo(null);
          appendMessage(data.message as ChatMsg);
          break;
        case "tool_start":
          setActiveTool(
            ((data.name as string) ?? "") +
              (data.args ? ` ${JSON.stringify(data.args).slice(0, 40)}` : "")
          );
          break;
        case "tool_done":
          setActiveTool(null);
          break;
        case "tool_message":
          appendMessage(data.message as ChatMsg);
          break;
        case "llm_retry": {
          const attempt = data.attempt as number;
          const max = data.max as number;
          const delayMs = data.delay_ms as number;
          const status = data.status as number | null;
          const reason = (data.reason as string) ?? "";
          const statusTxt = status ? ` [HTTP ${status}]` : "";
          setRetryInfo(`重试 ${attempt}/${max}${statusTxt} · ${Math.round(delayMs / 1000)}s 后 · ${reason}`);
          break;
        }
        case "llm_retry_giveup":
          setRetryInfo(null);
          toast.error(`LLM 调用 ${data.attempts} 次重试后仍失败: ${data.reason}`);
          break;
        case "error":
          setRetryInfo(null);
          appendMessage({
            role: "assistant",
            content: `[阶段 ${data.stage}: ${data.error}]`,
          });
          break;
        case "complete":
          setRetryInfo(null);
          setBusy(false);
          setActiveTool(null);
          if (data.summary) toast.success(`AI 完成: ${data.summary}`);
          else if (data.cancelled) toast.info("已取消");
          else if (data.truncated) toast.warning("达到最大轮数, 可继续追问");
          break;
      }
    }).then((u) => {
      if (cancelled) { u(); return; }
      unlisten = u;
    });
    return () => {
      cancelled = true;
      if (unlisten) unlisten();
    };
  }, [sessionId, setBusy, setCurrentRound, setActiveTool, setRetryInfo, appendMessage]);
}
