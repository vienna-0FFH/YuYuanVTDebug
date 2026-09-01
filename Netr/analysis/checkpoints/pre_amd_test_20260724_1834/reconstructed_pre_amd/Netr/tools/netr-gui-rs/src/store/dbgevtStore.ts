import { create } from "zustand";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";

export interface DbgEvtView {
  sequence: number;
  severity: number;
  category: number;
  status: number;
  caller_pid: number;
  target_pid: number;
  addr: number;
  size: number;
  detail: string;
}

interface DbgEvtState {
  events: DbgEvtView[];
  unlisten: UnlistenFn | null;
  start: () => Promise<void>;
  stop: () => void;
  clear: () => void;
}

// P122: trace 总线模式 ring 4096, 前端保留 8000 (滚动窗口可看历史)
const MAX_EVENTS = 8000;

export const useDbgEvt = create<DbgEvtState>((set, get) => ({
  events: [],
  unlisten: null,

  start: async () => {
    if (get().unlisten) return;
    const un = await listen<DbgEvtView[]>("dbgevt", (e) => {
      const incoming = e.payload;
      const cur = get().events;
      const next = [...cur, ...incoming];
      // 留最近 MAX_EVENTS
      if (next.length > MAX_EVENTS) next.splice(0, next.length - MAX_EVENTS);
      set({ events: next });
    });
    set({ unlisten: un });
  },

  stop: () => {
    const u = get().unlisten;
    if (u) u();
    set({ unlisten: null });
  },

  clear: () => set({ events: [] }),
}));
