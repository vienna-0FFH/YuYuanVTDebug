import { create } from "zustand";

interface UiState {
  sidebarCollapsed: boolean;
  toggleSidebar: () => void;
  setSidebarCollapsed: (v: boolean) => void;
}

const STORAGE_KEY = "netr-ui";

function loadInitial(): { sidebarCollapsed: boolean } {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return { sidebarCollapsed: false };
    const parsed = JSON.parse(raw) as { sidebarCollapsed?: boolean };
    return { sidebarCollapsed: !!parsed.sidebarCollapsed };
  } catch {
    return { sidebarCollapsed: false };
  }
}

export const useUi = create<UiState>((set, get) => ({
  sidebarCollapsed: loadInitial().sidebarCollapsed,
  toggleSidebar: () => {
    const next = !get().sidebarCollapsed;
    set({ sidebarCollapsed: next });
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify({ sidebarCollapsed: next }));
    } catch {
      // ignore
    }
  },
  setSidebarCollapsed: (v) => {
    set({ sidebarCollapsed: v });
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify({ sidebarCollapsed: v }));
    } catch {
      // ignore
    }
  },
}));
