import { create } from "zustand";
import { invoke } from "@tauri-apps/api/core";
import { driverIpc, type DriverStatusView, type ServiceInfo, type ServiceState } from "@/ipc/driver";
import { useAuth } from "@/store/authStore";

interface DriverStore {
  service: ServiceInfo | null;
  deviceOpen: boolean;
  status: DriverStatusView | null;
  poll: { interval: ReturnType<typeof setInterval> | null };

  /** GUI 自身已自动注册到驱动保护(每轮重试直到成功) */
  selfProtected: boolean;
  /** 最近一次自我保护登记失败的原因 */
  selfProtectError: string | null;
  /** 最近一次 GET_STATUS 失败的原因(license 未通过/驱动未响应) */
  statusError: string | null;

  refreshService: () => Promise<void>;
  refreshStatus: () => Promise<void>;
  startPolling: (ms?: number) => void;
  stopPolling: () => void;
}

let cachedSelfPid: number | null = null;
async function getSelfPid(): Promise<number | null> {
  if (cachedSelfPid !== null) return cachedSelfPid;
  try {
    cachedSelfPid = await invoke<number>("dbg_self_pid");
    return cachedSelfPid;
  } catch {
    return null;
  }
}

async function tryRegisterSelf(): Promise<{ ok: boolean; error: string | null }> {
  const pid = await getSelfPid();
  if (pid === null) return { ok: false, error: "self_pid 不可用" };
  try {
    await invoke<void>("debugger_add", {
      pid,
      processName: "GuardMetaVirtualSecurityPlatform",
      enablePrivilege: true,
      protectFromTerminate: true,
      hideFromList: false,
    });
    return { ok: true, error: null };
  } catch (e: unknown) {
    const msg = (e as { message?: string })?.message ?? String(e);
    return { ok: false, error: msg };
  }
}

export const useDriver = create<DriverStore>((set, get) => ({
  service: null,
  deviceOpen: false,
  status: null,
  poll: { interval: null },
  selfProtected: false,
  selfProtectError: null,
  statusError: null,

  refreshService: async () => {
    try {
      const svc = await driverIpc.query();
      const deviceOpen = await driverIpc.deviceOpen();
      const wasOpen = get().deviceOpen;
      set({ service: svc, deviceOpen });

      // === 关键修复:device 打开时,持续重试 license + selfProtect 直到都成功 ===
      if (deviceOpen) {
        const auth = useAuth.getState();

        // Step 1: license 未下发 → 重试一次
        if (!auth.driverLicensed && auth.user) {
          await auth.trySubmitToDriver();
        }

        // Step 2: license 下发后,再尝试 selfProtect(否则 IOCTL_HV_ADD_DEBUGGER 必失败)
        const licensed = useAuth.getState().driverLicensed;
        if (licensed && !get().selfProtected) {
          const r = await tryRegisterSelf();
          if (r.ok) {
            set({ selfProtected: true, selfProtectError: null });
            // 同步到后端全局 flag,供调试器等独立窗口查询
            void invoke("dbg_set_self_protected", { value: true }).catch(() => undefined);
          } else {
            set({ selfProtectError: r.error });
          }
        }
      } else if (wasOpen) {
        // 边沿 true→false:复位
        set({ selfProtected: false, selfProtectError: null });
        void invoke("dbg_set_self_protected", { value: false }).catch(() => undefined);
      }
    } catch {
      set({ service: null });
    }
  },

  refreshStatus: async () => {
    if (!get().deviceOpen) return;
    try {
      const st = await driverIpc.getStatus();
      set({ status: st, statusError: null });
    } catch (e: unknown) {
      // 保留上一次拿到的 status,只更新 statusError
      const msg = (e as { message?: string })?.message ?? String(e);
      set({ statusError: msg });
    }
  },

  startPolling: (ms = 1500) => {
    if (get().poll.interval) return;
    const id = setInterval(() => {
      void get().refreshService();
      void get().refreshStatus();
    }, ms);
    set({ poll: { interval: id } });
    void get().refreshService();
    void get().refreshStatus();
  },

  stopPolling: () => {
    const id = get().poll.interval;
    if (id) clearInterval(id);
    set({ poll: { interval: null } });
  },
}));

export function serviceStateLabel(state: ServiceState | undefined): string {
  switch (state) {
    case "running": return "运行中";
    case "stopped": return "已停止";
    case "start_pending": return "启动中…";
    case "stop_pending": return "停止中…";
    case "paused": return "已暂停";
    case "not_installed": return "未安装";
    case undefined: return "未知";
    default: return state;
  }
}

export function serviceStateTone(state: ServiceState | undefined): "success" | "warning" | "destructive" | "muted" {
  if (state === "running") return "success";
  if (state === "start_pending" || state === "stop_pending") return "warning";
  if (state === "not_installed") return "muted";
  return "muted";
}

export async function selfPidPromise(): Promise<number | null> {
  return getSelfPid();
}
