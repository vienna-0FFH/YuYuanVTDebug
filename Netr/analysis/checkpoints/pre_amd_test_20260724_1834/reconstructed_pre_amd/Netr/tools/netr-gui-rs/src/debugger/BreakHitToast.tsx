import { useCallback, useEffect, useRef } from "react";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { toast } from "sonner";

import { useDbgEvt } from "@/store/dbgevtStore";
import { dbgIpc, errMsg, type BuiltinPrivateHit } from "./ipc";
import { formatAddress } from "./expr";
import { useSession } from "./sessionStore";

interface HitInput {
  pid: number;
  tid: number | null;
  rip: bigint;
  reason: string;
  /** VT private poller 已经挂起真实命中线程，前端不能再次 SuspendThread。 */
  alreadySuspended: boolean;
  entry?: boolean;
  transient?: boolean;
  cleanupError?: string | null;
}

interface NativeControlError {
  pid: number;
  tid: number;
  operation: string;
  error: string;
}

/**
 * 两条命中链：
 * - VT private hit：Rust 后端已解析真实 TID 并挂起该线程，直接拉上下文。
 * - legacy dbgevt：没有真实 TID，只能用当前选中线程并由前端挂起。
 *
 * VT 会话获得 private SWBP/HWBP 能力后，以 dbg-private-hit 为权威，忽略同一
 * driver 命中在旧 dbgevt ring 中的镜像，避免重复 toast 和二次 suspend。
 */
export function BreakHitToast() {
  const start = useDbgEvt((s) => s.start);
  const stop = useDbgEvt((s) => s.stop);
  const events = useDbgEvt((s) => s.events);
  const pid = useSession((s) => s.pid);
  const debugMode = useSession((s) => s.debugMode);
  const capabilities = useSession((s) => s.capabilities);
  const hitGenerationRef = useRef(0);

  useEffect(() => {
    void start();
    return () => stop();
  }, [start, stop]);

  const handleHit = useCallback(async (hit: HitInput) => {
    const generation = ++hitGenerationRef.current;
    const initial = useSession.getState();
    if (initial.pid !== hit.pid) return;

    let wasTransient = hit.transient === true;
    const needsLegacyLookup = hit.transient === undefined;
    if (!hit.entry && (needsLegacyLookup || (wasTransient && Boolean(hit.cleanupError)))) {
      try {
        wasTransient = await dbgIpc.consumeTransientBp(hit.pid, Number(hit.rip));
      } catch { /* 非临时断点或已被后端清理 */ }
      if (generation !== hitGenerationRef.current) return;
    }

    let stoppedRip = hit.rip;
    if (hit.tid) {
      try {
        if (!hit.alreadySuspended) {
          await dbgIpc.suspendThread(hit.tid);
        }
        const ctx = await dbgIpc.getThreadContext(hit.tid);
        if (generation !== hitGenerationRef.current) return;
        const current = useSession.getState();
        if (current.pid !== hit.pid) return;
        stoppedRip = BigInt(ctx.rip);
        current.setSelectedTid(hit.tid);
        current.setCtx(ctx);
      } catch (error) {
        if (generation !== hitGenerationRef.current) return;
        toast.message(`命中但拉取线程 ${hit.tid} 上下文失败: ${errMsg(error)}`);
      }
    }

    if (generation !== hitGenerationRef.current) return;
    const current = useSession.getState();
    if (current.pid !== hit.pid) return;
    current.setAddress(stoppedRip);
    current.setMainTab("disasm");
    current.setLastHit({
      ts: Date.now(),
      tid: hit.tid ?? 0,
      rip: stoppedRip,
      reason: hit.reason,
    });
    if (hit.cleanupError) {
      toast.error(`程序入口已命中，但一次性断点清理失败: ${hit.cleanupError}`, { duration: 10000 });
    } else {
      toast.success(
        hit.entry
          ? `已停在程序入口 @ ${formatAddress(stoppedRip)}`
          : wasTransient
            ? `步过/步出 @ ${formatAddress(stoppedRip)}`
            : `命中 TID ${hit.tid ?? "?"} @ ${formatAddress(stoppedRip)}`,
        { duration: 3000 }
      );
    }
  }, []);

  const lastPrivateSeqRef = useRef(0);
  useEffect(() => {
    let unlisten: UnlistenFn | null = null;
    let disposed = false;
    void listen<BuiltinPrivateHit>("dbg-private-hit", (event) => {
      const hit = event.payload;
      if (hit.sequence <= lastPrivateSeqRef.current) return;
      lastPrivateSeqRef.current = hit.sequence;
      const current = useSession.getState();
      if (current.pid !== hit.pid || current.debugMode !== "vt") return;
      void handleHit({
        pid: hit.pid,
        tid: hit.tid || null,
        rip: BigInt(hit.rip),
        reason: `vt_private_${hit.kind}`,
        alreadySuspended: true,
        entry: hit.entry === true,
        transient: hit.transient === true,
        cleanupError: hit.cleanup_error,
      });
    }).then((fn) => {
      if (disposed) fn();
      else unlisten = fn;
    }).catch((error) => {
      toast.error(`VT 命中监听失败: ${errMsg(error)}`);
    });
    return () => {
      disposed = true;
      unlisten?.();
    };
  }, [handleHit]);

  const lastNativeSeqRef = useRef(0);
  useEffect(() => {
    let unlisten: UnlistenFn | null = null;
    let disposed = false;
    void listen<BuiltinPrivateHit>("dbg-native-hit", (event) => {
      const hit = event.payload;
      if (hit.sequence <= lastNativeSeqRef.current) return;
      lastNativeSeqRef.current = hit.sequence;
      const current = useSession.getState();
      if (current.pid !== hit.pid) return;
      void handleHit({
        pid: hit.pid,
        tid: hit.tid || null,
        rip: BigInt(hit.rip),
        reason: hit.entry
          ? "native_entry"
          : hit.kind === 3
            ? "native_hwbp"
            : hit.kind === 4
              ? "native_step"
              : hit.kind === 5
                ? "native_step_over"
                : "native_swbp",
        alreadySuspended: true,
        entry: hit.entry === true,
        transient: hit.transient === true,
        cleanupError: hit.cleanup_error,
      });
    }).then((fn) => {
      if (disposed) fn();
      else unlisten = fn;
    }).catch((error) => {
      toast.error(`Native 命中监听失败: ${errMsg(error)}`);
    });
    return () => {
      disposed = true;
      unlisten?.();
    };
  }, [handleHit]);

  useEffect(() => {
    let unlisten: UnlistenFn | null = null;
    let disposed = false;
    void listen<NativeControlError>("dbg-native-error", (event) => {
      const error = event.payload;
      if (useSession.getState().pid !== error.pid) return;
      toast.error(
        `Native 调试控制失败（TID ${error.tid} / ${error.operation}）：${error.error}`,
        { duration: 10000 },
      );
    }).then((fn) => {
      if (disposed) fn();
      else unlisten = fn;
    }).catch((error) => {
      toast.error(`Native 错误事件监听失败: ${errMsg(error)}`);
    });
    return () => {
      disposed = true;
      unlisten?.();
    };
  }, []);

  const lastDbgevtSeqRef = useRef(0);
  useEffect(() => {
    if (!pid) return;
    for (const event of events) {
      if (event.sequence <= lastDbgevtSeqRef.current) continue;
      lastDbgevtSeqRef.current = event.sequence;
      if (event.category !== 7 && event.category !== 8) continue;
      if (event.target_pid !== pid && event.caller_pid !== pid) continue;
      const mirroredByPrivateChannel = debugMode === "vt" && (
        (event.category === 8 && capabilities?.privateSwBp)
        || (event.category === 7 && capabilities?.vtHwBp)
      );
      if (mirroredByPrivateChannel) continue;

      const selectedTid = useSession.getState().selectedTid;
      void handleHit({
        pid,
        tid: selectedTid,
        rip: BigInt(event.addr),
        reason: event.category === 7 ? "hwbp" : "break",
        alreadySuspended: false,
      });
    }
  }, [capabilities, debugMode, events, handleHit, pid]);

  return null;
}
