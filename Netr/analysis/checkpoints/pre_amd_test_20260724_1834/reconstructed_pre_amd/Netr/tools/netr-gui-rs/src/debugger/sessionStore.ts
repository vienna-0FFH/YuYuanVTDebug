import { create } from "zustand";
import type {
  AnnotationsSnapshot,
  BuiltinAttachResult,
  BuiltinDebuggerMode,
  SwBreakpoint,
  ThreadContextView,
  ValueType,
} from "./ipc";
import { dbgIpc } from "./ipc";

export interface WatchItem {
  id: string;
  address: bigint;
  /** 用户起的标签 */
  description: string;
  type: ValueType;
  /** 当前值的可读形式,后台轮询填进来 */
  display: string;
  /** 是否锁定(freeze 后台 10Hz 写回)*/
  frozen: boolean;
  /** 锁定值(字节) */
  frozenBytes?: number[];
}

/** 主区子 tab — memview 永久挂载,这是其中显示的视图 */
export type MainTab = "disasm" | "hex" | "bps";

/** 底部停靠 tab — 不固定显示某一个,默认显示扫描器,可切到监视表 */
export type BottomTab = "scanner" | "watches" | "hex" | "log" | "ptrscan" | "script" | "modules" | "aob" | "globals" | "functions" | "strings" | "signatures";

/** 右侧停靠 tab — 默认隐藏,打开后显示对应工具 */
export type RightTab = "regs" | "hwbp" | "callstack" | "dissect" | "ai" | "mcp" | null;

/** 断点命中事件 — VT 命中由后端挂起真实线程；legacy 事件由前端挂起后跳转 RIP。 */
export interface BreakHit {
  ts: number;
  tid: number;
  rip: bigint;
  /** "int3" | "hwbp_exec" | "hwbp_rw" | "step" */
  reason: string;
  /** 命中具体哪个断点(可选,driver 给到就有) */
  bpIndex?: number;
}

/** P88: 项目书签 — 一个标了地址 + 标签 + 备注的位置 */
export interface Bookmark {
  id: string;
  address: bigint;
  label: string;
  note: string;
}

export interface DebuggerCapabilities {
  debuggerProtected: boolean;
  vtMemory: boolean;
  privateSwBp: boolean;
  vtHwBp: boolean;
  vtStep: boolean;
  drFallback: boolean;
}

export type DisasmNavigationMode = "force" | "reveal";

export interface DisasmNavigationRequest {
  address: bigint;
  mode: DisasmNavigationMode;
  sequence: number;
}

interface SessionState {
  pid: number | null;
  processName: string;
  attachingPid: number | null;
  debugMode: BuiltinDebuggerMode;
  syntheticMtfStep: boolean;
  capabilities: DebuggerCapabilities | null;
  selectedTid: number | null;
  ctx: ThreadContextView | null;
  bps: SwBreakpoint[];
  address: bigint;
  followAddress: bigint | null;
  disasmNavigation: DisasmNavigationRequest;

  /** 用户监视表(CE 下方 Active Address List) */
  watches: WatchItem[];

  /** 当前主区子 tab */
  mainTab: MainTab;
  /** 当前底部停靠 tab */
  bottomTab: BottomTab;
  bottomHexAddress: bigint;
  /** 底部是否折叠 */
  bottomCollapsed: boolean;
  /** 当前右侧停靠 tab(null = 不显示) */
  rightTab: RightTab;

  /** 最近一次断点命中,弹窗用 */
  lastHit: BreakHit | null;

  /** P88: 当前项目 */
  projectPath: string | null;
  projectDirty: boolean;
  bookmarks: Bookmark[];
  notes: string;
  targetExeName: string | null;       // 项目保存的目标 exe (恢复时按名找进程)

  /** P93: 注解 (labels / comments / functions) — 从后端同步, 反汇编渲染时读 */
  annotations: AnnotationsSnapshot | null;

  setDebugMode: (mode: BuiltinDebuggerMode) => void;
  setSyntheticMtfStep: (enabled: boolean) => void;
  setAttachingPid: (pid: number | null) => void;
  attach: (pid: number, name: string, result: BuiltinAttachResult) => void;
  detach: () => void;
  setSelectedTid: (tid: number | null) => void;
  setCtx: (ctx: ThreadContextView | null) => void;
  setBps: (bps: SwBreakpoint[]) => void;
  setAddress: (a: bigint) => void;
  requestDisasmNavigation: (a: bigint, mode?: DisasmNavigationMode) => void;
  setFollow: (a: bigint | null) => void;

  setMainTab: (t: MainTab) => void;
  setBottomTab: (t: BottomTab) => void;
  setBottomHexAddress: (a: bigint) => void;
  openBottomHexAt: (a: bigint) => void;
  setBottomCollapsed: (v: boolean) => void;
  setRightTab: (t: RightTab) => void;

  setLastHit: (h: BreakHit | null) => void;

  addWatch: (w: Omit<WatchItem, "id" | "display" | "frozen">) => void;
  removeWatch: (id: string) => void;
  updateWatch: (id: string, patch: Partial<WatchItem>) => void;
  clearWatches: () => void;

  // P88 项目
  setProjectPath: (p: string | null) => void;
  setProjectDirty: (v: boolean) => void;
  setBookmarks: (b: Bookmark[]) => void;
  addBookmark: (b: Omit<Bookmark, "id">) => void;
  removeBookmark: (id: string) => void;
  setNotes: (s: string) => void;
  setTargetExeName: (s: string | null) => void;
  loadProject: (input: {
    watches: WatchItem[];
    bookmarks: Bookmark[];
    notes: string;
    targetExeName: string | null;
    address: bigint;
    path: string;
  }) => void;

  // P93 annotations
  setAnnotations: (a: AnnotationsSnapshot | null) => void;
  refreshAnnotations: () => Promise<void>;
}

let watchSeq = 0;
function nextId() {
  watchSeq += 1;
  return `w${watchSeq}`;
}

const FRESH: Pick<
  SessionState,
  | "pid"
  | "processName"
  | "attachingPid"
  | "debugMode"
  | "syntheticMtfStep"
  | "capabilities"
  | "selectedTid"
  | "ctx"
  | "bps"
  | "address"
  | "followAddress"
  | "disasmNavigation"
  | "watches"
  | "mainTab"
  | "bottomTab"
  | "bottomHexAddress"
  | "bottomCollapsed"
  | "rightTab"
  | "lastHit"
  | "projectPath"
  | "projectDirty"
  | "bookmarks"
  | "notes"
  | "targetExeName"
  | "annotations"
> = {
  pid: null,
  processName: "",
  attachingPid: null,
  debugMode: "native",
  syntheticMtfStep: true,
  capabilities: null,
  selectedTid: null,
  ctx: null,
  bps: [],
  address: 0n,
  followAddress: null,
  disasmNavigation: { address: 0n, mode: "reveal", sequence: 0 },
  watches: [],
  mainTab: "disasm",
  bottomTab: "scanner",
  bottomHexAddress: 0n,
  bottomCollapsed: false,
  rightTab: null,
  lastHit: null,
  projectPath: null,
  projectDirty: false,
  bookmarks: [],
  notes: "",
  targetExeName: null,
  annotations: null,
};

export const useSession = create<SessionState>((set) => ({
  ...FRESH,

  setDebugMode: (mode) => set((s) => (s.pid ? s : { debugMode: mode })),
  setSyntheticMtfStep: (enabled) => set({ syntheticMtfStep: enabled }),
  setAttachingPid: (pid) => set({ attachingPid: pid }),
  attach: (pid, name, result) =>
    set({
      pid,
      processName: name,
      attachingPid: null,
      debugMode: result.mode,
      capabilities: {
        debuggerProtected: result.debugger_protected,
        vtMemory: result.vt_memory,
        privateSwBp: result.private_swbp,
        vtHwBp: result.vt_hwbp,
        vtStep: result.vt_step,
        drFallback: result.dr_fallback,
      },
      selectedTid: null,
      ctx: null,
      bps: [],
      followAddress: null,
      lastHit: null,
    }),
  detach: () => set((state) => ({
    ...FRESH,
    debugMode: state.debugMode,
    syntheticMtfStep: state.syntheticMtfStep,
  })),
  setSelectedTid: (tid) => set({ selectedTid: tid }),
  setCtx: (ctx) => set({ ctx }),
  setBps: (bps) => set({ bps }),
  setAddress: (a) => set({ address: a, followAddress: null }),
  requestDisasmNavigation: (a, mode = "force") => set((state) => ({
    address: a,
    followAddress: null,
    disasmNavigation: {
      address: a,
      mode,
      sequence: state.disasmNavigation.sequence + 1,
    },
  })),
  setFollow: (a) => set({ followAddress: a }),

  setMainTab: (t) => set({ mainTab: t }),
  setBottomTab: (t) => set((s) => ({
    bottomTab: t,
    bottomCollapsed: false,
    bottomHexAddress: t === "hex" && s.bottomHexAddress === 0n ? s.address : s.bottomHexAddress,
  })),
  setBottomHexAddress: (a) => set({ bottomHexAddress: a }),
  openBottomHexAt: (a) => set({ bottomHexAddress: a, bottomTab: "hex", bottomCollapsed: false }),
  setBottomCollapsed: (v) => set({ bottomCollapsed: v }),
  setRightTab: (t) => set({ rightTab: t }),

  setLastHit: (h) => set({ lastHit: h }),

  addWatch: (w) =>
    set((s) => {
      // 同地址同类型去重
      if (s.watches.some((x) => x.address === w.address && x.type === w.type)) return s;
      return {
        watches: [
          ...s.watches,
          { ...w, id: nextId(), display: "?", frozen: false },
        ],
        projectDirty: true,
      };
    }),
  removeWatch: (id) => set((s) => ({ watches: s.watches.filter((w) => w.id !== id), projectDirty: true })),
  updateWatch: (id, patch) =>
    set((s) => ({ watches: s.watches.map((w) => (w.id === id ? { ...w, ...patch } : w)), projectDirty: true })),
  clearWatches: () => set({ watches: [], projectDirty: true }),

  // P88 项目
  setProjectPath: (p) => set({ projectPath: p, projectDirty: false }),
  setProjectDirty: (v) => set({ projectDirty: v }),
  setBookmarks: (b) => set({ bookmarks: b, projectDirty: true }),
  addBookmark: (b) => set((s) => ({
    bookmarks: [...s.bookmarks, { ...b, id: `bm${Date.now().toString(36)}${Math.floor(Math.random()*1000)}` }],
    projectDirty: true,
  })),
  removeBookmark: (id) => set((s) => ({ bookmarks: s.bookmarks.filter((b) => b.id !== id), projectDirty: true })),
  setNotes: (s) => set({ notes: s, projectDirty: true }),
  setTargetExeName: (s) => set({ targetExeName: s, projectDirty: true }),
  loadProject: ({ watches, bookmarks, notes, targetExeName, address, path }) =>
    set({
      watches, bookmarks, notes, targetExeName, address,
      projectPath: path, projectDirty: false,
    }),

  setAnnotations: (a) => set({ annotations: a }),
  refreshAnnotations: async () => {
    try {
      const s = await dbgIpc.annoSnapshot();
      set({ annotations: s });
    } catch { /* 忽略 */ }
  },
}));
