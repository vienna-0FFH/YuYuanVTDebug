// 集中导出所有 IPC 包装
export * from "./auth";
export * from "./driver";

import { invoke } from "@tauri-apps/api/core";

export interface ProcessInfo {
  pid: number;
  name: string;
  path: string;
  parent_pid: number;
}

export interface DriverFile {
  path: string;
  exists: boolean;
}

export interface DebuggerBridgeResult {
  pid: number;
  architecture: string;
  bridge_path: string;
  injector_path: string;
}

export interface AntiVmpConfig {
  process_debug_query: boolean;
  kernel_debug_query: boolean;
  thread_hide: boolean;
  invalid_handle: boolean;
  debug_object: boolean;
  debug_registers: boolean;
  system_debug_control: boolean;
}

export interface AntiVmpStatus {
  version: number;
  enabled: boolean;
  target_pid: number;
  configured_mask: number;
  installed_mask: number;
  bridge_auto_enabled: boolean;
  protected_target_count: number;
  private_debug_object_enabled: boolean;
}

export const systemIpc = {
  listProcesses: () => invoke<ProcessInfo[]>("system_list_processes"),
  launchProcess: (exePath: string, args = "", workingDir: string | null = null) =>
    invoke<number>("system_launch_process", {
      req: { exe_path: exePath, args, working_dir: workingDir },
    }),
  processAlive: (pid: number) => invoke<boolean>("system_process_alive", { pid }),
  resolveDriverPath: () => invoke<DriverFile>("system_resolve_driver_path"),
  isElevated: () => invoke<boolean>("system_is_elevated"),
  restartAsAdmin: () => invoke<void>("system_restart_as_admin"),
};

export interface DseStatusView {
  disabled: boolean;
}

export const dseIpc = {
  status: () => invoke<DseStatusView>("dse_status"),
  enable: () => invoke<void>("dse_enable"),
  disable: () => invoke<void>("dse_disable"),
};

export const hideIpc = {
  hideProcess: (pid: number) => invoke<void>("hide_process", { pid }),
  unhideProcess: (pid: number) => invoke<void>("unhide_process", { pid }),
  hideDriver: (name: string) => invoke<void>("hide_driver", { name }),
  unhideDriver: (name: string) => invoke<void>("unhide_driver", { name }),
};

export const debuggerIpc = {
  add: (
    pid: number,
    processName: string,
    enablePrivilege: boolean,
    protectFromTerminate: boolean,
    hideFromList: boolean
  ) =>
    invoke<void>("debugger_add", {
      pid,
      processName,
      enablePrivilege,
      protectFromTerminate,
      hideFromList,
    }),
  remove: (pid: number) => invoke<void>("debugger_remove", { pid }),
  launchWithBridge: (
    exePath: string,
    args: string,
    enablePrivilege: boolean,
    protectFromTerminate: boolean,
    hideFromList: boolean,
    workingDir: string | null = null
  ) =>
    invoke<DebuggerBridgeResult>("debugger_bridge_launch", {
      req: {
        exe_path: exePath,
        args,
        working_dir: workingDir,
        enable_privilege: enablePrivilege,
        protect_from_terminate: protectFromTerminate,
        hide_from_list: hideFromList,
      },
    }),
  injectBridge: (
    pid: number,
    processName: string,
    enablePrivilege: boolean,
    protectFromTerminate: boolean,
    hideFromList: boolean
  ) =>
    invoke<DebuggerBridgeResult>("debugger_bridge_inject", {
      req: {
        pid,
        process_name: processName,
        enable_privilege: enablePrivilege,
        protect_from_terminate: protectFromTerminate,
        hide_from_list: hideFromList,
      },
    }),
};

export const antiVmpIpc = {
  status: () => invoke<AntiVmpStatus>("antivmp_get_status"),
  apply: (enabled: boolean, config: AntiVmpConfig) =>
    invoke<AntiVmpStatus>("antivmp_apply", { enabled, config }),
  setPrivateDebugObject: (enabled: boolean) =>
    invoke<AntiVmpStatus>("antivmp_set_private_debug_object", { enabled }),
  getSymbolCache: () => invoke<string | null>("dbg_symbol_cache_get"),
  setSymbolCache: (path: string | null) =>
    invoke<string | null>("dbg_symbol_cache_set", { path }),
};

export interface HwbpInfo {
  slot: number;
  address: number;
  length: number;
  bp_type: number;
}

export const hwbpIpc = {
  set: (debuggerPid: number, targetPid: number, slot: number, address: bigint, length: number, bpType: number) =>
    invoke<void>("hwbp_set", {
      debuggerPid,
      targetPid,
      slot,
      address: Number(address),
      length,
      bpType,
    }),
  clear: (targetPid: number, slot: number) =>
    invoke<void>("hwbp_clear", { targetPid, slot }),
  list: (targetPid: number) =>
    invoke<HwbpInfo[]>("hwbp_list", { targetPid }),
};

export const memoryIpc = {
  read: (pid: number, address: bigint, size: number) =>
    invoke<number[]>("memory_read", { pid, address: Number(address), size }),
  write: (pid: number, address: bigint, data: number[]) =>
    invoke<void>("memory_write", { pid, address: Number(address), data }),
  alloc: (pid: number, size: number, protect: number) =>
    invoke<number>("memory_alloc", { pid, size, protect }),
  free: (pid: number, address: bigint) =>
    invoke<void>("memory_free", { pid, address: Number(address) }),
};

export const injectIpc = {
  dll: (pid: number, dllPathOrBytes: string | number[]) =>
    invoke<void>("inject_dll", {
      pid,
      dllPath: typeof dllPathOrBytes === "string" ? dllPathOrBytes : null,
      dllBytes: Array.isArray(dllPathOrBytes) ? dllPathOrBytes : null,
    }),
  shellcode: (pid: number, shellcode: number[]) =>
    invoke<void>("inject_shellcode", { pid, shellcode }),
};

export const inputIpc = {
  enable: () => invoke<void>("input_enable"),
  disable: () => invoke<void>("input_disable"),
  sendKey: (scancode: number, isExtended: boolean, isBreak: boolean) =>
    invoke<void>("input_send_key", { scancode, isExtended, isBreak }),
  sendMouse: (dx: number, dy: number, buttons: number, wheel: number) =>
    invoke<void>("input_send_mouse", { dx, dy, buttons, wheel }),
};
