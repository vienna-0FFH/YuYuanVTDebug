import { create } from "zustand";

/**
 * AI 助手运行时状态 — 提到 zustand, 避免面板 unmount 时丢.
 *
 * 切右停靠 tab(ai ↔ engine 等)时 RightDock 用 && 条件渲染会 unmount AI 面板.
 * 把所有跟"AI 正在跑"相关的状态外提到这里, 面板只读不持有.
 *
 * 监听器(listen("ai-run::*"))也外移, 在 DebuggerApp 顶层挂一次, 不依赖面板挂载.
 */

export interface ChatMsg {
  role: "user" | "assistant" | "tool" | "system";
  content: unknown;
  tool_calls?: Array<{ id: string; type: "function"; function: { name: string; arguments: string } }>;
  tool_call_id?: string;
  _guardmeta?: { kind: string; [key: string]: unknown };
}

const STORAGE_HISTORY = "netr-ai-history";
const STORAGE_CONTEXT = "netr-ai-context";

function loadHistory(): ChatMsg[] {
  try {
    const raw = localStorage.getItem(STORAGE_HISTORY);
    if (!raw) return [];
    return JSON.parse(raw) as ChatMsg[];
  } catch { return []; }
}
function saveHistory(h: ChatMsg[]) {
  try { localStorage.setItem(STORAGE_HISTORY, JSON.stringify(h)); } catch {}
}
function loadContext(): ChatMsg[] | null {
  try {
    const raw = localStorage.getItem(STORAGE_CONTEXT);
    if (!raw) return null;
    return JSON.parse(raw) as ChatMsg[];
  } catch { return null; }
}
function saveContext(h: ChatMsg[]) {
  try { localStorage.setItem(STORAGE_CONTEXT, JSON.stringify(h)); } catch {}
}

let sidSeq = 0;
export function newAiSessionId(): string {
  sidSeq += 1;
  return `sess-${Date.now().toString(36)}-${sidSeq}`;
}

interface AiState {
  history: ChatMsg[];
  setHistory: (h: ChatMsg[]) => void;
  appendMessage: (m: ChatMsg) => void;
  clearHistory: () => void;
  contextHistory: ChatMsg[] | null;
  setContextHistory: (h: ChatMsg[]) => void;
  appendContextMessage: (m: ChatMsg) => void;
  clearContextHistory: () => void;

  /** 当前 session id, send 时分配 cancel 用 */
  sessionId: string;
  resetSessionId: () => void;
  setSessionId: (id: string) => void;

  busy: boolean;
  setBusy: (v: boolean) => void;

  currentRound: number;
  setCurrentRound: (n: number) => void;

  activeTool: string | null;
  setActiveTool: (s: string | null) => void;

  /** 重试状态文本 "重试 2/5 (...)" */
  retryInfo: string | null;
  setRetryInfo: (s: string | null) => void;
}

export const useAi = create<AiState>((set) => ({
  history: loadHistory(),
  setHistory: (h) => { saveHistory(h); set({ history: h }); },
  appendMessage: (m) => set((s) => {
    const next = [...s.history, m];
    saveHistory(next);
    return { history: next };
  }),
  clearHistory: () => { saveHistory([]); saveContext([]); set({ history: [], contextHistory: [] }); },
  contextHistory: loadContext(),
  setContextHistory: (h) => { saveContext(h); set({ contextHistory: h }); },
  appendContextMessage: (m) => set((s) => {
    const next = [...(s.contextHistory ?? s.history), m];
    saveContext(next);
    return { contextHistory: next };
  }),
  clearContextHistory: () => { saveContext([]); set({ contextHistory: [] }); },

  sessionId: newAiSessionId(),
  resetSessionId: () => set({ sessionId: newAiSessionId() }),
  setSessionId: (id) => set({ sessionId: id }),

  busy: false,
  setBusy: (v) => set({ busy: v }),

  currentRound: 0,
  setCurrentRound: (n) => set({ currentRound: n }),

  activeTool: null,
  setActiveTool: (s) => set({ activeTool: s }),

  retryInfo: null,
  setRetryInfo: (s) => set({ retryInfo: s }),
}));
