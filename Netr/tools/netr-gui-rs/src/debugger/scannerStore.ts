import { create } from "zustand";
import type { ScanHit, ScanOp, ValueType } from "./ipc";

/**
 * P110: 扫描器状态外提到 zustand. ScannerPanel mount/unmount 不丢, BottomDock tab 切换继续保留.
 * hits / valueType / valStr 都在这里, 面板只读+写.
 */
interface ScannerState {
  valueType: ValueType;
  setValueType: (v: ValueType) => void;
  op: ScanOp;
  setOp: (v: ScanOp) => void;
  valStr: string;
  setValStr: (v: string) => void;
  addrMin: string;
  setAddrMin: (v: string) => void;
  addrMax: string;
  setAddrMax: (v: string) => void;
  /** P116: 对齐扫描. 默认 true (CE 行为). 关掉用于打包/未对齐结构. */
  aligned: boolean;
  setAligned: (v: boolean) => void;

  hits: ScanHit[];
  total: number;
  hasFirst: boolean;
  /** 拿到 first scan 结果后的 pid (切进程要 reset) */
  pid: number | null;

  setResult: (pid: number, hits: ScanHit[], total: number) => void;
  /** 替换 hits 中每条的 display (实时刷新用, 不动 address) */
  updateDisplays: (values: string[]) => void;
  reset: () => void;
}

export const useScanner = create<ScannerState>((set) => ({
  valueType: "i32",
  setValueType: (v) => set({ valueType: v }),
  op: "exact",
  setOp: (v) => set({ op: v }),
  valStr: "",
  setValStr: (v) => set({ valStr: v }),
  addrMin: "0",
  setAddrMin: (v) => set({ addrMin: v }),
  addrMax: "7FFFFFFFFFFF",
  setAddrMax: (v) => set({ addrMax: v }),
  aligned: true,
  setAligned: (v) => set({ aligned: v }),

  hits: [],
  total: 0,
  hasFirst: false,
  pid: null,

  setResult: (pid, hits, total) => set({ pid, hits, total, hasFirst: true }),
  updateDisplays: (values) => set((s) => ({
    hits: s.hits.map((h, i) =>
      i < values.length ? { ...h, display: values[i] } : h
    ),
  })),
  reset: () => set({ hits: [], total: 0, hasFirst: false, pid: null }),
}));
