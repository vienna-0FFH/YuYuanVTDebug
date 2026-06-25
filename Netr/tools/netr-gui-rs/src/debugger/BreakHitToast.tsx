import { useEffect, useRef } from "react";
import { toast } from "sonner";
import { useSession } from "./sessionStore";
import { useDbgEvt } from "@/store/dbgevtStore";
import { dbgIpc, errMsg } from "./ipc";
import { formatAddress } from "./expr";

/**
 * driver 断点命中事件回传链路:
 *   driver #BP/#DB vmexit → HvDbgEvtPost(cat=HWBP_HIT/BREAK_HIT) → dbgevt ring
 *   → GUI dbgevt poller(后端 1Hz IOCTL_HV_GET_DBGEVT)→ dbgevtStore.events
 *   → 这里监听 cat=7/8 + target_pid==self.pid
 *
 * P58 行为:
 *   - 自动 SuspendThread(命中线程, driver 上 RIP 并未前进所以这是必要的)
 *   - 拉 ctx 填到 store
 *   - 切到反汇编 + 跳 RIP
 *   - 临时 bp(步过/步出 装的) → 自动 clear,不污染 sw_bps 列表
 *   - 弹 toast
 *
 * 选线程: 我们当前从 ToolBar 直接选 TID, 命中时 dbgevt 里没带 tid (cat=7/8 只有 addr=RIP),
 * 所以"自动 suspend"先用 selectedTid。命中 TID 跟 selectedTid 多数情况一致(我们 set hwbp 时
 * 也是给 selectedTid 用的)。后续可在 driver 把 tid 编进 HV_DBGEVT 解决。
 */
export function BreakHitToast() {
  const start = useDbgEvt((s) => s.start);
  const stop = useDbgEvt((s) => s.stop);
  const events = useDbgEvt((s) => s.events);
  const pid = useSession((s) => s.pid);
  const selectedTid = useSession((s) => s.selectedTid);
  const setAddress = useSession((s) => s.setAddress);
  const setMainTab = useSession((s) => s.setMainTab);
  const setCtx = useSession((s) => s.setCtx);

  // 独立 webview 也启动 dbgevt 订阅
  useEffect(() => {
    void start();
    return () => stop();
  }, [start, stop]);

  const lastSeqRef = useRef(0);
  useEffect(() => {
    if (!pid) return;
    for (const e of events) {
      if (e.sequence <= lastSeqRef.current) continue;
      lastSeqRef.current = e.sequence;
      if (e.category !== 7 && e.category !== 8) continue;
      if (e.target_pid !== pid && e.caller_pid !== pid) continue;
      const ripAddr = BigInt(e.addr);
      void handleHit(ripAddr);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [events, pid, selectedTid]);

  async function handleHit(ripAddr: bigint) {
    if (!pid) return;
    // 1. 优先尝试清"临时 sw bp"(步过/步出 装的)
    let wasTransient = false;
    try {
      wasTransient = await dbgIpc.consumeTransientBp(pid, Number(ripAddr));
    } catch { /* ignore */ }

    // 2. 自动 suspend 选中线程 + 拉 ctx
    if (selectedTid) {
      try {
        await dbgIpc.suspendThread(selectedTid);
        const c = await dbgIpc.getThreadContext(selectedTid);
        setCtx(c);
      } catch (err) {
        toast.message(`命中但拉 ctx 失败: ${errMsg(err)}`);
      }
    }
    // 3. 跳转 RIP
    setAddress(ripAddr);
    setMainTab("disasm");
    toast.success(
      wasTransient ? `步过/步出 @ ${formatAddress(ripAddr)}` : `命中 @ ${formatAddress(ripAddr)}`,
      { duration: 3000 }
    );
  }

  return null;
}
