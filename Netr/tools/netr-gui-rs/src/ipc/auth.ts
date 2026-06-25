import { invoke } from "@tauri-apps/api/core";

/**
 * 后端 AppError 序列化为 { kind, message }(util/error.rs)
 */
export interface AppError {
  kind: string;
  message: string;
}

export interface BootstrapView {
  has_saved: boolean;
  saved_username: string | null;
}

export interface LoginView {
  token: string;
  subject_type: string;
  subject_id: number;
  /** 时长卡的 Unix 秒到期时间,次数卡为 0 */
  expires_at: number;
  /** 次数卡剩余次数,时长卡为 -1 */
  remaining_count: number;
  notice: string;
  machine_code: string;
}

export interface HeartbeatSummary {
  online: boolean;
  expires_at: number;
  remaining_count: number;
  server_time: number;
  message: string;
}

export interface TopupSummary {
  message: string;
  expires_at: number;
  remaining_count: number;
}

export const authIpc = {
  bootstrap: () => invoke<BootstrapView>("auth_bootstrap"),

  login: (username: string, password: string, remember: boolean) =>
    invoke<LoginView>("auth_login", { username, password, remember }),

  autoLogin: () => invoke<LoginView | null>("auth_auto_login"),

  logout: () => invoke<void>("auth_logout"),

  heartbeat: () => invoke<HeartbeatSummary>("auth_heartbeat"),

  isAuthorized: () => invoke<boolean>("auth_is_authorized"),

  /** Phase 2:把当前 license 提交给 driver(IOCTL_HV_SUBMIT_LICENSE) */
  submitToDriver: () => invoke<number>("license_submit_to_driver"),

  /** P21 诊断:dump 当前 license payload(canonical / 签名 / 时间) */
  licenseDump: () => invoke<{
    app_key: string;
    subject_type: string;
    subject_id: number;
    machine_code: string;
    expires_at: number;
    token: string;
    auth_sig_b64: string;
    auth_sig_hex: string;
    auth_sig_len: number;
    canonical: string;
    now_unix: number;
    deploy_pub_hex: string;
    local_verify_ok: boolean;
    sha512_ram_first16_hex: string;
  }>("license_dump"),

  /** Phase 9:自助注册。card_key 可选,传 null 仅注册不充值 */
  register: (username: string, password: string, cardKey: string | null) =>
    invoke<string>("auth_register", { username, password, cardKey }),

  /** Phase 9:改密。需要旧密码 */
  changePassword: (oldPassword: string, newPassword: string) =>
    invoke<string>("auth_change_password", { oldPassword, newPassword }),

  /** Phase 9:卡密充值。部署端要求重输账号密码 */
  topup: (username: string, password: string, cardKey: string) =>
    invoke<TopupSummary>("auth_topup", { username, password, cardKey }),
};

/** Tauri invoke 抛出来的 error 都是 AppError 形态(json) */
export function isAppError(e: unknown): e is AppError {
  return (
    typeof e === "object" &&
    e !== null &&
    "kind" in e &&
    "message" in e
  );
}

export function errorMessage(e: unknown): string {
  if (isAppError(e)) return e.message;
  if (e instanceof Error) return e.message;
  return String(e);
}
