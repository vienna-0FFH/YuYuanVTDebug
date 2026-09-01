import { useHotkeys } from "react-hotkeys-hook";
import { toast } from "sonner";
import { useSession } from "./sessionStore";
import { dbgIpc, errMsg } from "./ipc";
import { stepUnavailableReason, swBreakpointUnavailableReason } from "./capabilities";

/**
 * 全局调试器快捷键(在 DebuggerApp 顶层挂一次)。
 * 按键风格沿用 Visual Studio / WinDbg / x64dbg 习惯。
 */
export function useGlobalDebuggerHotkeys() {
  const session = useSession();
  const swBpReason = swBreakpointUnavailableReason(session.debugMode, session.capabilities);
  const stepIntoReason = stepUnavailableReason("into", session.debugMode, session.capabilities);
  const stepOverReason = stepUnavailableReason("over", session.debugMode, session.capabilities);
  const stepOutReason = stepUnavailableReason("out", session.debugMode, session.capabilities);

  // Ctrl+G — 聚焦跳转输入框(由 MainViewPanel 自己监听 focus 失败时这里至少切到 disasm)
  useHotkeys(
    "ctrl+g",
    (e) => {
      e.preventDefault();
      session.setMainTab("disasm");
      const inp = document.querySelector<HTMLInputElement>(
        'input[placeholder^="跳转"]'
      );
      inp?.focus();
      inp?.select();
    },
    { enableOnFormTags: false },
    [session]
  );

  // Ctrl+S — 保存项目
  useHotkeys(
    "ctrl+s",
    async (e) => {
      e.preventDefault();
      // 派事件给 ProjectMenu 抓 (避免循环依赖)
      window.dispatchEvent(new CustomEvent("gm:project-save"));
    },
    { enableOnFormTags: false }
  );

  // F5 — 恢复当前选中线程(类似 VS Run)
  useHotkeys(
    "f5",
    async (e) => {
      e.preventDefault();
      if (!session.selectedTid) return toast.error("先选线程");
      try {
        await dbgIpc.resumeThread(session.selectedTid);
        toast.success(`线程 ${session.selectedTid} 已恢复`);
      } catch (err) {
        toast.error(`F5 失败: ${errMsg(err)}`);
      }
    },
    [session.selectedTid]
  );

  // F6 — 暂停当前选中线程
  useHotkeys(
    "f6",
    async (e) => {
      e.preventDefault();
      if (!session.selectedTid) return toast.error("先选线程");
      try {
        await dbgIpc.suspendThread(session.selectedTid);
        toast.success(`线程 ${session.selectedTid} 已暂停`);
      } catch (err) {
        toast.error(`F6 失败: ${errMsg(err)}`);
      }
    },
    [session.selectedTid]
  );

  // F9 — 在当前地址切软断点
  useHotkeys(
    "f9",
    async (e) => {
      e.preventDefault();
      if (!session.pid) return;
      if (swBpReason) return toast.error(swBpReason);
      const addr = Number(session.address);
      try {
        const exist = session.bps.find((b) => b.address === addr);
        if (exist) {
          await dbgIpc.swBpClear(session.pid, addr);
          session.setBps(session.bps.filter((b) => b.address !== addr));
          toast.success(`断点已清除 @ ${session.address.toString(16)}`);
        } else {
          const bp = await dbgIpc.swBpSet(session.pid, addr);
          session.setBps([...session.bps, bp]);
          toast.success(`断点已设置 @ ${session.address.toString(16)}`);
        }
      } catch (err) {
        toast.error(`F9 失败: ${errMsg(err)}`);
      }
    },
    [session.pid, session.address, session.bps, swBpReason]
  );

  // F11 — 步入(TF + #DB)
  useHotkeys(
    "f11",
    async (e) => {
      e.preventDefault();
      if (!session.selectedTid) return toast.error("先选线程");
      if (stepIntoReason) return toast.error(stepIntoReason);
      try {
        await dbgIpc.stepInto(session.selectedTid, session.syntheticMtfStep);
        // 命中事件由 driver dbgevt 回传, BreakHitToast 自动跳转 RIP
      } catch (err) {
        toast.error(`F11 失败: ${errMsg(err)}`);
      }
    },
    [session.selectedTid, session.syntheticMtfStep, stepIntoReason]
  );

  // F8 — 步过: 看是 call/int 就在 RIP+len 装临时 sw bp + resume;否则等价 step-into
  useHotkeys(
    "f8",
    async (e) => {
      e.preventDefault();
      if (!session.pid || !session.selectedTid) return toast.error("先选线程");
      if (stepOverReason) return toast.error(stepOverReason);
      try {
        await dbgIpc.stepOver(
          session.pid,
          session.selectedTid,
          session.syntheticMtfStep,
        );
      } catch (err) {
        toast.error(`F8 失败: ${errMsg(err)}`);
      }
    },
    [session.pid, session.selectedTid, session.syntheticMtfStep, stepOverReason]
  );

  // Shift+F11 — 步出: 拿 [RSP] 当 ret addr,装临时 sw bp + resume
  useHotkeys(
    "shift+f11",
    async (e) => {
      e.preventDefault();
      if (!session.pid || !session.selectedTid) return toast.error("先选线程");
      if (stepOutReason) return toast.error(stepOutReason);
      try {
        await dbgIpc.stepOut(session.pid, session.selectedTid);
      } catch (err) {
        toast.error(`Shift+F11 失败: ${errMsg(err)}`);
      }
    },
    [session.pid, session.selectedTid, stepOutReason]
  );

  // Esc — 解附 / 关右停靠
  useHotkeys(
    "escape",
    () => {
      if (session.rightTab) {
        session.setRightTab(null);
      }
    },
    [session]
  );

  // Ctrl+1/2/3 — 切主区子 tab
  useHotkeys("ctrl+1", (e) => { e.preventDefault(); session.setMainTab("disasm"); }, [session]);
  useHotkeys("ctrl+2", (e) => { e.preventDefault(); session.setMainTab("hex"); }, [session]);
  useHotkeys("ctrl+3", (e) => { e.preventDefault(); session.setRightTab("regs"); }, [session]);
  useHotkeys("ctrl+4", (e) => { e.preventDefault(); session.setRightTab("regs"); }, [session]);
  useHotkeys("ctrl+5", (e) => { e.preventDefault(); session.setMainTab("bps"); }, [session]);
}
