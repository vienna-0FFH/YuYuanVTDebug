import { invoke } from "@tauri-apps/api/core";

// ===== 基础类型 =====
export interface ReadResult {
  address: number;
  bytes: number[];
  truncated: boolean;
}

export interface DisasmLine {
  address: number;
  bytes_hex: string;
  text: string;
  len: number;
}

export interface ModuleInfo {
  base: number;
  size: number;
  name: string;
  path: string;
}

export interface ThreadBrief {
  tid: number;
  owner_pid: number;
}

export interface RegionInfo {
  base: number;
  size: number;
  protect: number;
  state: number;
  type_: number;
}

export interface ThreadContextView {
  tid: number;
  rax: number; rbx: number; rcx: number; rdx: number;
  rsi: number; rdi: number; rbp: number; rsp: number;
  r8: number; r9: number; r10: number; r11: number;
  r12: number; r13: number; r14: number; r15: number;
  rip: number;
  rflags: number;
  cs: number;
  ss: number;
}

export interface StepManyResult {
  kind: "into" | "over";
  steps: number;
  tid: number;
  rip: number;
}

export interface SwBreakpoint {
  address: number;
  original_byte: number;
}

export type BuiltinDebuggerMode = "native" | "vt";

export interface BuiltinAttachResult {
  pid: number;
  mode: BuiltinDebuggerMode;
  debugger_protected: boolean;
  vt_memory: boolean;
  private_swbp: boolean;
  vt_hwbp: boolean;
  vt_step: boolean;
  dr_fallback: boolean;
}

export interface BuiltinPrivateHit {
  sequence: number;
  pid: number;
  tid: number;
  rip: number;
  kind: number;
  entry?: boolean;
  slot?: number | null;
  transient?: boolean;
  cleanup_error?: string | null;
}

export interface BuiltinLaunchResult {
  attach: BuiltinAttachResult;
  primary_tid: number;
  entry_address: number;
  stopped_at_entry: boolean;
}

export interface BuiltinRunToEntryResult {
  pid: number;
  primary_tid: number;
  entry_address: number;
  stopped_at_entry: boolean;
}

export interface BuiltinRestartResult {
  old_pid: number;
  new_pid: number;
  process_name: string;
  attach: BuiltinAttachResult;
  primary_tid: number;
  entry_address: number;
  stopped_at_entry: boolean;
}

// ===== 内存扫描 =====
export type ValueType =
  | "i8" | "i16" | "i32" | "i64"
  | "u8" | "u16" | "u32" | "u64"
  | "f32" | "f64"
  | "bytes" | "string";

export type ScanOp =
  | "exact" | "gt" | "lt" | "ge" | "le" | "ne"
  | "changed" | "unchanged" | "increasedby" | "decreasedby";

export interface ScanValue {
  number: number | null;
  float: number | null;
  bytes: number[] | null;
  string: string | null;
}

export interface ScanHit {
  address: number;
  display: string;
}

export interface ScanResult {
  total: number;
  hits: ScanHit[];
  diag?: { prev_count: number; read_failed: number; compared: number; matched: number };
}

// ===== IPC 包装 =====
export const dbgIpc = {
  // window
  openWindow: () => invoke<string>("dbg_open_window"),
  closeWindow: (label: string) => invoke<void>("dbg_close_window", { label }),
  attach: (pid: number, mode: BuiltinDebuggerMode) =>
    invoke<BuiltinAttachResult>("dbg_attach", { pid, mode }),
  detach: (pid: number) => invoke<void>("dbg_detach", { pid }),
  launchExecutable: (
    exePath: string,
    mode: BuiltinDebuggerMode,
    args: string | null = null,
    workingDir: string | null = null,
  ) => invoke<BuiltinLaunchResult>("dbg_launch_executable", {
    exePath,
    args,
    workingDir,
    mode,
  }),
  runToEntry: (pid: number) =>
    invoke<BuiltinRunToEntryResult>("dbg_run_to_entry", { pid }),
  restartProcess: (pid: number) =>
    invoke<BuiltinRestartResult>("dbg_restart_process", { pid }),

  // memory
  readMemory: (pid: number, address: number, size: number) =>
    invoke<ReadResult>("dbg_read_memory", { pid, address, size }),
  writeMemory: (pid: number, address: number, bytes: number[]) =>
    invoke<void>("dbg_write_memory", { pid, address, bytes }),

  // disasm
  disasm: (address: number, bytes: number[], anchor?: number) =>
    invoke<DisasmLine[]>("dbg_disasm", { address, bytes, anchor: anchor ?? null }),

  // 枚举
  listModules: (pid: number) => invoke<ModuleInfo[]>("dbg_list_modules", { pid }),
  listThreads: (pid: number) => invoke<ThreadBrief[]>("dbg_list_threads", { pid }),
  listRegions: (pid: number) => invoke<RegionInfo[]>("dbg_list_regions", { pid }),

  // thread context
  getThreadContext: (tid: number) =>
    invoke<ThreadContextView>("dbg_get_thread_context", { tid }),
  setThreadContext: (ctx: ThreadContextView) =>
    invoke<void>("dbg_set_thread_context", { ctx }),
  suspendThread: (tid: number) => invoke<number>("dbg_suspend_thread", { tid }),
  resumeThread: (tid: number) => invoke<number>("dbg_resume_thread", { tid }),
  stepInto: (tid: number, syntheticMtf = true) =>
    invoke<void>("dbg_step_into", { tid, syntheticMtf }),
  stepOver: (pid: number, tid: number, syntheticMtf = true) =>
    invoke<{
      kind: "step" | "run-over" | "vt-single-step" | "real-tf-single-step";
      next_rip: number;
    }>("dbg_step_over", { pid, tid, syntheticMtf }),
  stepMany: (
    pid: number,
    tid: number,
    kind: "into" | "over",
    count: number,
    syntheticMtf = true,
  ) => invoke<StepManyResult>("dbg_step_many", { pid, tid, kind, count, syntheticMtf }),
  stepOut: (pid: number, tid: number) =>
    invoke<number>("dbg_step_out", { pid, tid }),
  cancelActiveRun: (pid: number, tid: number) =>
    invoke<boolean>("dbg_cancel_active_run", { pid, tid }),
  consumeTransientBp: (pid: number, address: number) =>
    invoke<boolean>("dbg_consume_transient_bp", { pid, address }),

  // sw breakpoint
  swBpSet: (pid: number, address: number) =>
    invoke<SwBreakpoint>("dbg_sw_bp_set", { pid, address }),
  swBpClear: (pid: number, address: number) =>
    invoke<void>("dbg_sw_bp_clear", { pid, address }),
  swBpList: (pid: number) => invoke<SwBreakpoint[]>("dbg_sw_bp_list", { pid }),

  // scan
  scanFirst: (req: {
    pid: number;
    value_type: ValueType;
    op: ScanOp;
    value: ScanValue;
    addr_min: number;
    addr_max: number;
    /** P116: 对齐扫描. 默认 true. 不填后端默认 true. */
    aligned?: boolean;
  }) => invoke<ScanResult>("dbg_scan_first", { req }),
  scanNext: (req: { pid: number; op: ScanOp; value: ScanValue }) =>
    invoke<ScanResult>("dbg_scan_next", { req }),
  scanReset: (pid: number) => invoke<void>("dbg_scan_reset", { pid }),
  scanCancel: () => invoke<void>("dbg_scan_cancel"),
  scanRefresh: (req: { pid: number; value_type: ValueType; addresses: number[] }) =>
    invoke<{ values: string[] }>("dbg_scan_refresh", { req }),

  // self pid + freeze + driver protect 接入
  selfPid: () => invoke<number>("dbg_self_pid"),
  freezeSet: (pid: number, address: number, bytes: number[]) =>
    invoke<void>("dbg_freeze_set", { pid, address, bytes }),
  freezeClear: (pid: number, address: number) =>
    invoke<void>("dbg_freeze_clear", { pid, address }),

  // 符号解析 (P52)
  resolveSymbol: (pid: number, address: number, refresh: boolean = false) =>
    invoke<SymbolInfo | null>("dbg_resolve_symbol", { pid, address, refresh }),
  resolveSymbols: (pid: number, addresses: number[]) =>
    invoke<(SymbolInfo | null)[]>("dbg_resolve_symbols", { pid, addresses }),

  // P66 AOB
  aobScan: (req: AobScanReq) => invoke<AobScanResult>("dbg_aob_scan", { req }),
  // P75 全局指针候选发现
  findGlobals: (req: FindGlobalsReq) =>
    invoke<FindGlobalsResult>("dbg_find_globals", { req }),

  // P105 dump 提取
  dumpRegion: (req: { pid: number; address: string; size: number; out_path?: string | null }) =>
    invoke<DumpResult>("dbg_dump_region", { req }),
  dumpModule: (req: { pid: number; module_name?: string | null; fix_sections?: boolean; out_path?: string | null }) =>
    invoke<DumpModuleResult>("dbg_dump_module", { req }),
  dumpProcess: (req: { pid: number; out_dir?: string | null; include_images?: boolean; include_private?: boolean; include_mapped?: boolean }) =>
    invoke<DumpProcessResult>("dbg_dump_process", { req }),

  // P99 签名管理
  sigList: () => invoke<StoredSig[]>("sig_list"),
  sigSave: (req: SigSaveReq) => invoke<StoredSig>("sig_save", { req }),
  sigDelete: (id: string) => invoke<boolean>("sig_delete", { id }),
  sigTest: (req: SigTestReq) => invoke<SigTestResp>("sig_test", { req }),
  sigDerive: (req: { pid: number; address: string; length?: number }) =>
    invoke<SigDeriveResp>("sig_derive", { req }),
  sigValidate: (req: { pid: number; sig_id?: string | null }) =>
    invoke<SigValidateResp>("sig_validate", { req }),

  // P84 AI 助手 (tool-calling, 旧接口已废弃, 用 aiRun)
  aiChat: (req: AiChatReq) => invoke<AiChatResp>("dbg_ai_chat", { req }),

  // P87 流式 agent
  aiRun: (req: AiRunReq) => invoke<AiRunResp>("dbg_ai_run", { req }),
  aiCancel: (sessionId: string) => invoke<void>("dbg_ai_cancel", { sessionId }),
  aiSessionList: () => invoke<AiSessionFileInfo[]>("dbg_ai_session_list"),
  aiSessionLoad: (sessionId: string) => invoke<AiSessionLoad>("dbg_ai_session_load", { sessionId }),
  aiSessionDelete: (sessionId: string) => invoke<void>("dbg_ai_session_delete", { sessionId }),
  aiToolsDescribe: () => invoke<AiToolInfo[]>("dbg_ai_tools_describe"),

  // P101 AI 拖放文件读取 (任意路径)
  aiReadDroppedFile: (path: string, max_kb?: number) =>
    invoke<DroppedFileResult>("ai_read_dropped_file", { req: { path, max_kb: max_kb ?? null } }),

  // P88 项目
  projectNew: () => invoke<void>("project_new"),
  projectSave: (path: string, doc: ProjectDoc) => invoke<void>("project_save", { path, doc }),
  projectLoad: (path: string) => invoke<ProjectDoc>("project_load", { path }),
  projectListRecent: () => invoke<RecentProject[]>("project_list_recent"),
  projectPickSave: (defaultName?: string | null) =>
    invoke<string | null>("project_pick_save", { defaultName: defaultName ?? null }),
  projectPickOpen: () => invoke<string | null>("project_pick_open"),

  // P91 Xref
  xrefTo: (req: { pid: number; target: string; module_name?: string | null; max_hits?: number }) =>
    invoke<XrefToResult>("dbg_xref_to", { req }),
  xrefFrom: (req: { pid: number; source: string }) =>
    invoke<XrefFromResult>("dbg_xref_from", { req }),

  // P91 函数
  listFunctions: (req: { pid: number; module_name?: string | null; limit?: number; offset?: number }) =>
    invoke<ListFunctionsResult>("dbg_list_functions", { req }),
  getFunction: (req: { pid: number; address: number }) =>
    invoke<GetFunctionResult>("dbg_get_function", { req }),

  // P92 字符串 + 导入导出
  listStrings: (req: { pid: number; module_name?: string | null; min_len?: number; limit?: number; filter?: string | null }) =>
    invoke<ListStringsResult>("dbg_list_strings", { req }),
  listImports: (req: { pid: number; module_name?: string | null }) =>
    invoke<ListImportsResult>("dbg_list_imports", { req }),
  listExports: (req: { pid: number; module_name?: string | null }) =>
    invoke<ListExportsResult>("dbg_list_exports", { req }),

  // P94 调用栈 (后端)
  callStack: (req: { pid: number; tid: number; max_frames?: number; stack_scan_bytes?: number }) =>
    invoke<CallStackResp>("dbg_call_stack", { req }),

  // P93 注解
  annoSetLabel: (address: string, name: string) =>
    invoke<void>("anno_set_label", { req: { address, name } }),
  annoGetLabel: (address: string) =>
    invoke<string | null>("anno_get_label", { address }),
  annoSetComment: (address: string, text: string) =>
    invoke<void>("anno_set_comment", { req: { address, name: text } }),
  annoGetComment: (address: string) =>
    invoke<string | null>("anno_get_comment", { address }),
  annoDefineFunction: (address: string, name: string, size: number) =>
    invoke<void>("anno_define_function", { req: { address, name, size } }),
  annoGetFunction: (address: string) =>
    invoke<{ name: string; size: number } | null>("anno_get_function", { address }),
  annoSnapshot: () => invoke<AnnotationsSnapshot>("anno_snapshot"),
  annoReplace: (data: AnnotationsSnapshot) => invoke<void>("anno_replace", { data }),
  annoListLabels: () => invoke<[string, string][]>("anno_list_labels"),
};

// === P91-P94 types ===
export interface XrefHit {
  source: number;
  kind: "call" | "jmp" | "lea" | "mov" | "other";
  mnemonic: string;
  target: number;
  source_module_offset: number;
}
export interface XrefToResult {
  module: string;
  module_base: number;
  text_base: number;
  text_size: number;
  hits: XrefHit[];
  total_hits: number;
  bytes_decoded: number;
}
export interface XrefRef { kind: string; target: number }
export interface XrefFromResult {
  source: number;
  instruction: string;
  bytes_hex: string;
  length: number;
  references: XrefRef[];
}

export interface FunctionEntry {
  start: number;
  end: number;
  size: number;
  rva: number;
}
export interface ListFunctionsResult {
  module: string;
  module_base: number;
  total: number;
  offset: number;
  count: number;
  functions: FunctionEntry[];
}
export interface GetFunctionResult {
  found: boolean;
  module: string | null;
  function: FunctionEntry | null;
  offset_in_function: number | null;
}

export interface StringEntry {
  address: number;
  encoding: "ascii" | "utf16le";
  text: string;
}
export interface ListStringsResult {
  module: string;
  module_base: number;
  total: number;
  returned: number;
  strings: StringEntry[];
}

export interface ImportEntry {
  dll: string;
  name: string;
  ordinal: number | null;
  iat_address: number;
  resolved_address: number;
}
export interface ListImportsResult {
  module: string;
  module_base: number;
  count: number;
  imports: ImportEntry[];
}

export interface ExportEntry {
  name: string;
  rva: number;
  ordinal: number;
  address: number;
}
export interface ListExportsResult {
  module: string;
  module_base: number;
  count: number;
  exports: ExportEntry[];
}

export interface CallFrame {
  rip: number;
  rsp: number;
  module: string | null;
  module_offset: number | null;
  symbol: string | null;
}
export interface CallStackResp {
  tid: number;
  frames: CallFrame[];
  stack_bytes_scanned: number;
  note: string;
}

export interface AnnotationsSnapshot {
  labels: Record<string, string>;
  comments: Record<string, string>;
  functions: Record<string, { name: string; size: number }>;
}

export interface StoredSig {
  id: string;
  name: string;
  engine: string[];
  pattern: string;
  follow_rip: boolean;
  scope: string;
  description: string;
  source: "builtin" | "user" | "ai" | string;
  confirmed: boolean;
  last_addr: number | null;
  last_tested_at: number | null;
  target_exe: string | null;
}
export interface SigSaveReq {
  id?: string | null;
  name: string;
  engine: string[];
  pattern: string;
  follow_rip: boolean;
  scope: string;
  description: string;
  source?: string | null;
  target_exe?: string | null;
}
export interface SigTestReq {
  pid: number;
  pattern: string;
  follow_rip: boolean;
  scope: number;
  module_name?: string | null;
  addr_min?: number | null;
  addr_max?: number | null;
}
export interface SigHit { at: number; target: number | null }
export interface SigTestResp {
  hits: SigHit[];
  total_hits: number;
  unique_target: number | null;
  bytes_scanned: number;
}
export interface SigDeriveResp {
  address: number;
  pattern: string;
  bytes_hex: string;
  mask_explanation: string;
  follow_rip_target: number | null;
}
export interface SigValidationResult {
  id: string;
  name: string;
  status: "ok_unique" | "multiple_hits" | "miss" | "drift" | "error" | string;
  hits: number;
  target: number | null;
  previous_target: number | null;
  note: string;
}
export interface SigValidateResp {
  tested: number;
  results: SigValidationResult[];
}

export interface DumpResult {
  path: string;
  bytes_requested: number;
  bytes_read: number;
  bytes_zero_filled: number;
  chunks_failed: number;
}
export interface DumpModuleResult {
  path: string;
  module: string;
  base: number;
  size: number;
  fixed: boolean;
  sections_fixed: number;
  bytes_read: number;
  bytes_zero_filled: number;
  chunks_failed: number;
}
export interface DumpProcessResult {
  out_dir: string;
  regions_total: number;
  regions_dumped: number;
  total_bytes: number;
  regions: { file: string; base: number; size: number; protect: number; mem_type: number; bytes_read: number; bytes_zero_filled: number }[];
  manifest_path: string;
  aborted_reason: string | null;
}

export interface DroppedFileResult {
  path: string;
  name: string;
  size: number;
  truncated: boolean;
  is_binary: boolean;
  content: string | null;
  hex: string | null;
}

export interface AiToolInfo {
  name: string;
  description: string;
  input_schema: unknown;
  requires_confirm: boolean;
  serial?: boolean;
}

export interface AiRunReq {
  session_id: string;
  config: {
    provider: "openai" | "anthropic";
    base_url: string;
    api_key: string;
    model: string;
    temperature?: number;
    reasoning_effort?: "none" | "minimal" | "low" | "medium" | "high" | "xhigh" | "max";
    context_tokens?: number;
    input_tokens?: number;
    output_tokens?: number;
    output_token_max?: number;
    compaction_reserved_tokens?: number;
  };
  messages: unknown[];
  display_messages?: unknown[];
  enabled_tools?: string[] | null;
  max_rounds?: number;
}
export interface AiRunResp {
  rounds: number;
  input_tokens: number;
  output_tokens: number;
  cache_read_tokens: number;
  cache_write_tokens: number;
  total_tokens: number;
  truncated: boolean;
  cancelled: boolean;
  completed: boolean;
  final_summary: string | null;
}
export interface AiSessionFileInfo {
  id: string;
  size_bytes: number;
  modified: number;
  first_user: string | null;
}
export interface AiSessionLoad {
  history: unknown[];
  context: unknown[];
}

export interface ProjectTarget {
  exe_name: string;
  module_name: string | null;
  last_pid: number | null;
}
export interface ProjectWatch {
  address: string;
  type_: string;
  description: string;
  frozen: boolean;
  frozen_bytes: number[] | null;
}
export interface ProjectBookmark {
  address: string;
  label: string;
  note: string;
}
export interface ProjectDoc {
  version: number;
  target: ProjectTarget | null;
  watches: ProjectWatch[];
  bookmarks: ProjectBookmark[];
  notes: string;
  main_address: string | null;
  created_at: number | null;
  modified_at: number | null;
}
export interface RecentProject {
  path: string;
  name: string;
  modified: number;
}

export interface AiChatReq {
  config: {
    provider: "openai" | "anthropic";
    base_url: string;
    api_key: string;
    model: string;
    temperature?: number;
    reasoning_effort?: "none" | "minimal" | "low" | "medium" | "high" | "xhigh" | "max";
    context_tokens?: number;
    input_tokens?: number;
    output_tokens?: number;
    output_token_max?: number;
    compaction_reserved_tokens?: number;
  };
  /** 完整对话历史 — 由前端维护,后端追加 */
  messages: unknown[];
  enabled_tools?: string[] | null;
  max_rounds?: number;
}
export interface AiChatResp {
  new_messages: unknown[];
  rounds: number;
  input_tokens: number;
  output_tokens: number;
  truncated: boolean;
}

export interface FindGlobalsReq {
  pid: number;
  module_name?: string | null;
  top_n?: number | null;
  min_refs?: number | null;
}
export interface GlobalCandidate {
  address: number;
  refs: number;
  lea_refs: number;
  mov_refs: number;
  at_value_hex: string;
  sample_callers: number[];
  in_module: boolean;
}
export interface FindGlobalsResult {
  candidates: GlobalCandidate[];
  text_base: number;
  text_size: number;
  bytes_decoded: number;
  rip_refs_total: number;
}

export interface AobScanReq {
  pid: number;
  pattern: string;
  /** 0=全空间 1=单模块 2=自定义 */
  scope: number;
  module_name?: string | null;
  addr_min?: number | null;
  addr_max?: number | null;
  max_hits?: number | null;
}
export interface AobHit {
  address: number;
  rip_target: number | null;
  module: string | null;
  rva: number | null;
}
export interface AobScanResult {
  hits: AobHit[];
  regions_scanned: number;
  bytes_scanned: number;
  truncated: boolean;
}
export interface SymbolInfo {
  address: number;
  name: string;
  module: string;
  offset: number;
}

export function emptyScanValue(): ScanValue {
  return { number: null, float: null, bytes: null, string: null };
}

/**
 * 把 invoke catch 出来的对象规范化成可读字符串.
 *
 * Tauri 把 Rust 的 `AppError` 序列化成 `{ kind, message }` 普通对象 (见 util/error.rs),
 * 所以 catch (e) 里 e 不是 JS Error, `errMsg(e)` 永远 undefined.
 * 用 errMsg(e) 包一下, 兼容字符串 / Error / { message } / 其它任意值.
 */
export function errMsg(e: unknown): string {
  if (e == null) return "未知错误";
  if (typeof e === "string") return e;
  if (typeof e === "object") {
    const o = e as { kind?: unknown; message?: unknown };
    if (typeof o.message === "string" && o.message) {
      // 带 kind 前缀显得是后端结构化错误, 不带就当普通错误
      const kind = typeof o.kind === "string" ? o.kind : "";
      return kind ? `[${kind}] ${o.message}` : o.message;
    }
  }
  try { return JSON.stringify(e); } catch { return String(e); }
}
