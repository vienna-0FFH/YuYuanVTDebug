import { invoke } from "@tauri-apps/api/core";

export type ServiceState =
  | "not_installed"
  | "stopped"
  | "start_pending"
  | "stop_pending"
  | "running"
  | "continue_pending"
  | "pause_pending"
  | "paused"
  | "unknown";

export interface ServiceInfo {
  state: ServiceState;
  process_id: number;
  image_path: string | null;
}

export interface DriverStatusView {
  hypervisor_active: boolean;
  hook_initialized: boolean;
  dse_disabled: boolean;
  anti_anti_debug: boolean;
  debuggers: number;
  protected_processes: number;
  cpu_vendor: number;
  cpu_count: number;
  vt_root_enabled: boolean;
  debugger_proxy_enabled: boolean;
  access_bypass_enabled: boolean;
}

export const driverIpc = {
  install: (driver_path: string) => invoke<void>("driver_install", { driverPath: driver_path }),
  start: () => invoke<void>("driver_start"),
  stop: () => invoke<void>("driver_stop"),
  uninstall: () => invoke<void>("driver_uninstall"),
  query: () => invoke<ServiceInfo>("driver_query"),
  openDevice: () => invoke<void>("driver_open_device"),
  closeDevice: () => invoke<void>("driver_close_device"),
  deviceOpen: () => invoke<boolean>("driver_device_open"),
  getStatus: () => invoke<DriverStatusView>("driver_get_status"),
};
