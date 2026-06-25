import { create } from "zustand";
import { authIpc, type LoginView, type TopupSummary } from "@/ipc/auth";

interface AuthState {
  /** 是否已尝试过自动登录(用于决定渲染骨架屏 vs 登录页) */
  bootstrapDone: boolean;
  /** 已登录用户信息(null = 未登录) */
  user: LoginView | null;
  /** 心跳判定下线之类的最近错误,显示给用户 */
  lastError: string | null;
  /** driver 是否已接受 license(=> 业务 IOCTL 解锁) */
  driverLicensed: boolean;

  bootstrap: () => Promise<void>;
  login: (username: string, password: string, remember: boolean) => Promise<void>;
  logout: () => Promise<void>;
  /** 用户主动触发心跳检查(SDK 后台已 60s 自动跑) */
  checkOnline: () => Promise<boolean>;
  /** 尝试把当前 license 提交给 driver(driver 未启动时静默失败) */
  trySubmitToDriver: () => Promise<boolean>;
  /** 自助注册 → 注册成功自动登录(remember=true) */
  register: (username: string, password: string, cardKey: string | null) => Promise<void>;
  /** 改密 */
  changePassword: (oldPassword: string, newPassword: string) => Promise<string>;
  /** 卡密充值(需重输账号密码) */
  topup: (username: string, password: string, cardKey: string) => Promise<TopupSummary>;
}

export const useAuth = create<AuthState>((set, get) => ({
  bootstrapDone: false,
  user: null,
  lastError: null,
  driverLicensed: false,

  bootstrap: async () => {
    try {
      const view = await authIpc.autoLogin();
      if (view) {
        set({ user: view, bootstrapDone: true, lastError: null });
        // 异步尝试提交 driver,不阻塞 bootstrap
        void get().trySubmitToDriver();
        return;
      }
    } catch {
      // 自动登录失败不要打扰用户,默默继续到登录页
    }
    set({ bootstrapDone: true });
  },

  login: async (username, password, remember) => {
    const view = await authIpc.login(username, password, remember);
    set({ user: view, lastError: null });
    void get().trySubmitToDriver();
  },

  logout: async () => {
    await authIpc.logout();
    set({ user: null, driverLicensed: false });
  },

  checkOnline: async () => {
    try {
      const hb = await authIpc.heartbeat();
      if (!hb.online) {
        set({ user: null, driverLicensed: false, lastError: hb.message || "授权已失效" });
      }
      return hb.online;
    } catch (e) {
      set({ lastError: String(e) });
      return false;
    }
  },

  trySubmitToDriver: async () => {
    try {
      await authIpc.submitToDriver();
      set({ driverLicensed: true, lastError: null });
      return true;
    } catch (e: unknown) {
      // 失败原因记到 lastError,方便排查(driver 未启 / 设备未开 / license 拒绝 等)
      const msg = (e as { message?: string })?.message ?? String(e);
      set({ driverLicensed: false, lastError: `license submit: ${msg}` });
      return false;
    }
  },

  register: async (username, password, cardKey) => {
    await authIpc.register(username, password, cardKey);
    // 注册成功后:用同样账密 verify_account,默认记住凭据
    const view = await authIpc.login(username, password, true);
    set({ user: view, lastError: null });
    void get().trySubmitToDriver();
  },

  changePassword: async (oldPassword, newPassword) => {
    return authIpc.changePassword(oldPassword, newPassword);
  },

  topup: async (username, password, cardKey) => {
    return authIpc.topup(username, password, cardKey);
  },
}));
