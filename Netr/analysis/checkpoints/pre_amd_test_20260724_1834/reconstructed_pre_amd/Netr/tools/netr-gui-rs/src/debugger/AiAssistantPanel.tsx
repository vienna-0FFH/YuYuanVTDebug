import { useEffect, useRef, useState } from "react";
import { Bot, Send, Settings, Trash2, Loader2, Wrench, ChevronRight, ChevronDown, AlertCircle, Square, History, CheckCircle2, Paperclip, FileText, X } from "lucide-react";
import { toast } from "sonner";
import { getCurrentWebview } from "@tauri-apps/api/webview";
import { open as openDialog } from "@tauri-apps/plugin-dialog";

import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { dbgIpc, type DroppedFileResult, errMsg } from "./ipc";
import { useSession } from "./sessionStore";
import { LlmConfigDialog } from "./LlmConfigDialog";
import { loadLlmConfig, hydrateLlmConfigFromDisk, type LlmConfig } from "@/lib/llm";
import { cn } from "@/lib/utils";
import { useAi, type ChatMsg } from "./aiStore";

/**
 * AI 助手 — 用对话指挥调试器跑工具.
 *
 * P100: history / busy / currentRound / activeTool / retryInfo / sessionId 全部外提到 useAi 全局 store.
 * 监听器在 DebuggerApp 顶层 useAiStreamListener() 装一次, 切右停靠 tab 不影响.
 */

function extOf(name: string): string {
  const i = name.lastIndexOf(".");
  return i >= 0 ? name.slice(i + 1).toLowerCase() : "";
}
function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(2)} MB`;
}
function formatAttachment(f: DroppedFileResult): string {
  const head = `[文件: ${f.name} (${formatBytes(f.size)}${f.truncated ? ", 已截断" : ""})]`;
  if (f.is_binary) {
    return `${head}\n二进制 (前 4KB hex):\n\`\`\`\n${f.hex ?? ""}\n\`\`\``;
  }
  const ext = extOf(f.name);
  return `${head}\n\`\`\`${ext}\n${f.content ?? ""}\n\`\`\``;
}

export function AiAssistantPanel() {
  const { pid, processName, selectedTid } = useSession();
  // 持久化状态从全局 store 拿 — 切 tab 不会丢
  const history = useAi((s) => s.history);
  const setHistory = useAi((s) => s.setHistory);
  const contextHistory = useAi((s) => s.contextHistory);
  const setContextHistory = useAi((s) => s.setContextHistory);
  const sessionId = useAi((s) => s.sessionId);
  const resetSessionId = useAi((s) => s.resetSessionId);
  const setSessionId = useAi((s) => s.setSessionId);
  const busy = useAi((s) => s.busy);
  const setBusy = useAi((s) => s.setBusy);
  const currentRound = useAi((s) => s.currentRound);
  const setCurrentRound = useAi((s) => s.setCurrentRound);
  const activeTool = useAi((s) => s.activeTool);
  const setActiveTool = useAi((s) => s.setActiveTool);
  const retryInfo = useAi((s) => s.retryInfo);

  // panel-only UI 状态
  const [input, setInput] = useState("");
  const [cfgOpen, setCfgOpen] = useState(false);
  const [cfg, setCfg] = useState<LlmConfig | null>(() => loadLlmConfig());
  const [historyOpen, setHistoryOpen] = useState(false);
  // P101 拖放文件
  const [attached, setAttached] = useState<DroppedFileResult[]>([]);
  const [dragOver, setDragOver] = useState(false);
  const scroller = useRef<HTMLDivElement>(null);

  // 自动滚到底, 切回来重 mount 也会滚一次
  useEffect(() => {
    const el = scroller.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [history, busy]);

  function refreshCfg() { setCfg(loadLlmConfig()); }
  useEffect(() => { if (!cfgOpen) refreshCfg(); }, [cfgOpen]);
  useEffect(() => {
    void hydrateLlmConfigFromDisk().then((c) => { if (c) setCfg(c); });
  }, []);
  useEffect(() => {
    const handler = (e: StorageEvent) => { if (e.key === "netr-llm") refreshCfg(); };
    window.addEventListener("storage", handler);
    return () => window.removeEventListener("storage", handler);
  }, []);

  // P101: Tauri webview 拖放. 只在 panel 挂载时监听.
  useEffect(() => {
    let unlisten: (() => void) | undefined;
    const webview = getCurrentWebview();
    void webview.onDragDropEvent((event) => {
      const t = event.payload.type;
      if (t === "enter" || t === "over") {
        setDragOver(true);
      } else if (t === "leave") {
        setDragOver(false);
      } else if (t === "drop") {
        setDragOver(false);
        const paths = event.payload.paths;
        void processDroppedPaths(paths);
      }
    }).then((u) => { unlisten = u; });
    return () => { if (unlisten) unlisten(); };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function processDroppedPaths(paths: string[]) {
    let okCount = 0;
    for (const p of paths) {
      try {
        const r = await dbgIpc.aiReadDroppedFile(p);
        setAttached((cur) => [...cur, r]);
        okCount += 1;
      } catch (e) {
        toast.error(`读 ${p}: ${errMsg(e)}`);
      }
    }
    if (okCount > 0) toast.success(`已附加 ${okCount} 个文件`);
  }

  function removeAttached(idx: number) {
    setAttached((cur) => cur.filter((_, i) => i !== idx));
  }

  async function pickFilesViaDialog() {
    try {
      const selected = await openDialog({
        title: "选择要发送给 AI 的文件",
        multiple: true,
        directory: false,
      });
      if (!selected) return;
      await processDroppedPaths(Array.isArray(selected) ? selected : [selected]);
    } catch (error) {
      toast.error(`选择文件失败: ${errMsg(error)}`);
    }
  }

  const hasCfg = Boolean(cfg?.api_key);

  async function send() {
    const text = input.trim();
    if (!text && attached.length === 0) return;
    const c = loadLlmConfig();
    if (!c || !c.api_key) {
      setCfgOpen(true);
      return;
    }
    if (!cfg) setCfg(c);
    // 拼附件为代码块
    const attachmentsText = attached.length === 0 ? "" : attached.map(formatAttachment).join("\n\n");
    const pidPrefix = pid
      ? `(当前内置调试会话: PID ${pid}${processName ? ` ${processName}` : ""}, `
        + `TID ${selectedTid ?? "未选择"}) `
      : "";
    const fullText = [
      pidPrefix + (text || "(请分析附件)"),
      attachmentsText,
    ].filter(Boolean).join("\n\n");
    const userMsg: ChatMsg = {
      role: "user",
      content: fullText,
    };
    const next: ChatMsg[] = [...history, userMsg];
    const nextContext: ChatMsg[] = [...(contextHistory ?? history), userMsg];
    setHistory(next);
    setContextHistory(nextContext);
    setInput("");
    setAttached([]);
    setBusy(true);
    setCurrentRound(0);
    setActiveTool(null);

    // listen 已在 DebuggerApp::useAiStreamListener 装好(跟随 sessionId)— 这里只发请求
    try {
      const resp = await dbgIpc.aiRun({
        session_id: sessionId,
        config: {
          provider: c.provider,
          base_url: c.base_url,
          api_key: c.api_key,
          model: c.model,
          temperature: c.temperature,
          reasoning_effort: c.reasoning_effort,
          context_tokens: c.context_tokens,
          input_tokens: c.input_tokens,
          output_tokens: c.output_tokens,
          output_token_max: c.output_token_max,
          compaction_reserved_tokens: c.compaction_reserved_tokens,
        },
        messages: nextContext as unknown[],
        display_messages: next as unknown[],
        max_rounds: 200,
      });
      if (resp.cancelled) toast.info("AI 已取消");
      else if (resp.truncated) toast.warning(`已达最大 ${resp.rounds} 轮`);
    } catch (e) {
      setHistory([
        ...useAi.getState().history,
        { role: "assistant", content: `[失败] ${errMsg(e)}` },
      ]);
    } finally {
      // complete 事件已经会 setBusy(false), 这里兜底
      setBusy(false);
      setActiveTool(null);
    }
  }

  async function cancel() {
    if (!busy) return;
    try { await dbgIpc.aiCancel(sessionId); } catch {}
  }

  function onKey(e: React.KeyboardEvent<HTMLTextAreaElement>) {
    if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) {
      e.preventDefault();
      void send();
    }
  }

  function clearAll() {
    if (!confirm("清空对话(开启新会话)?")) return;
    setHistory([]);
    setContextHistory([]);
    resetSessionId();
  }

  async function loadOldSession(id: string) {
    try {
      const loaded = await dbgIpc.aiSessionLoad(id);
      setHistory(loaded.history as ChatMsg[]);
      setContextHistory(loaded.context as ChatMsg[]);
      setSessionId(id);
      setHistoryOpen(false);
      toast.success(`已加载会话 ${id}`);
    } catch (e) {
      toast.error(`加载失败: ${errMsg(e)}`);
    }
  }

  return (
    <div className="flex h-full flex-col bg-card/30">
      <div className="flex h-8 shrink-0 items-center gap-2 border-b border-border bg-card/40 px-2 text-xs">
        <Bot className="h-3 w-3 text-primary" />
        <span className="font-medium text-muted-foreground">AI 助手</span>
        {hasCfg ? (
          <button
            type="button"
            onClick={() => setCfgOpen(true)}
            title="点击修改"
            className="rounded bg-emerald-500/10 px-1.5 py-px font-mono text-[10px] text-emerald-400 hover:bg-emerald-500/20"
          >
            {cfg!.provider}·{cfg!.model}
          </button>
        ) : (
          <button
            type="button"
            onClick={() => setCfgOpen(true)}
            className="flex items-center gap-1 rounded bg-warning/15 px-1.5 py-px text-[10px] text-warning hover:bg-warning/25"
          >
            <AlertCircle className="h-3 w-3" /> 未配置 (点这里配置)
          </button>
        )}
        <span className="ml-auto text-[10px] text-muted-foreground">
          {pid ? `PID ${pid}` : "未附加"}
        </span>
        <Button
          size="sm" variant="ghost" className="h-6 w-6 p-0"
          onClick={() => setHistoryOpen(true)}
          title="历史会话"
        >
          <History className="h-3 w-3" />
        </Button>
        <Button
          size="sm" variant="ghost" className="h-6 w-6 p-0"
          onClick={clearAll}
          title="清空对话 (开启新会话)"
        >
          <Trash2 className="h-3 w-3" />
        </Button>
        <Button
          size="sm" variant="ghost" className="h-6 w-6 p-0"
          onClick={() => setCfgOpen(true)}
          title="AI 配置"
        >
          <Settings className="h-3 w-3" />
        </Button>
      </div>

      <SessionHistoryDialog open={historyOpen} onOpenChange={setHistoryOpen} onLoad={loadOldSession} />

      <LlmConfigDialog open={cfgOpen} onOpenChange={setCfgOpen} />

      <div ref={scroller} className="min-h-0 flex-1 overflow-y-auto px-2 py-2 text-[11px]">
        {history.length === 0 && (
          <div className="mx-auto mt-8 max-w-[28rem] space-y-2 text-center text-[11px] text-muted-foreground">
            <Bot className="mx-auto h-8 w-8 text-primary/50" />
            <div className="text-sm font-medium text-foreground">让 AI 驾驶调试器</div>
            <div>
              直接说目标,例如"找到 Notepad 进程并 dump 它的模块表"、
              "在 GameXX.exe 里定位 UE GNames"、"找血量内存地址"。
            </div>
            <div className="text-[10px]">AI 会自动调 list_processes / find_globals / ue_auto / read_memory 等工具。</div>
            <div className="text-[10px]">Ctrl+Enter 发送</div>
          </div>
        )}
        {history.map((m, i) => (
          <MessageView key={i} msg={m} />
        ))}
      </div>

      {busy && (
        <div
          className={cn(
            "flex h-6 shrink-0 items-center gap-2 border-t px-2 text-[10px]",
            retryInfo
              ? "border-amber-500/40 bg-amber-500/10 text-amber-300"
              : "border-primary/30 bg-primary/5 text-primary"
          )}
        >
          <Loader2 className="h-3 w-3 animate-spin shrink-0" />
          {retryInfo ? (
            <span className="truncate">{retryInfo}</span>
          ) : (
            <>
              <span className="shrink-0">轮次 {currentRound}</span>
              {activeTool && (
                <span className="truncate text-[10px] text-foreground/80">
                  <Wrench className="mr-1 inline h-3 w-3" />
                  {activeTool}
                </span>
              )}
            </>
          )}
          <button
            type="button"
            onClick={() => void cancel()}
            className="ml-auto flex items-center gap-1 rounded bg-red-500/20 px-2 py-0.5 text-[10px] text-red-300 hover:bg-red-500/30 shrink-0"
          >
            <Square className="h-3 w-3" /> 取消
          </button>
        </div>
      )}

      <div
        className={cn(
          "shrink-0 border-t border-border bg-card/40 p-1.5 transition-colors",
          dragOver && "border-primary ring-2 ring-primary/40 bg-primary/5"
        )}
      >
        {dragOver && (
          <div className="mb-1 flex items-center justify-center gap-1 rounded border border-dashed border-primary/40 bg-primary/10 px-2 py-3 text-[11px] text-primary">
            <Paperclip className="h-3 w-3" /> 释放以附加文件
          </div>
        )}
        {attached.length > 0 && (
          <div className="mb-1 flex flex-wrap gap-1">
            {attached.map((f, i) => (
              <div
                key={i}
                className={cn(
                  "flex items-center gap-1 rounded border px-1.5 py-0.5 text-[10px]",
                  f.is_binary
                    ? "border-amber-500/40 bg-amber-500/10 text-amber-300"
                    : "border-emerald-500/40 bg-emerald-500/10 text-emerald-300"
                )}
                title={`${f.path}\n${formatBytes(f.size)}${f.truncated ? " · 已截断" : ""}`}
              >
                <FileText className="h-2.5 w-2.5" />
                <span className="max-w-[16ch] truncate font-mono">{f.name}</span>
                <span className="text-muted-foreground">{formatBytes(f.size)}</span>
                {f.truncated && <span className="text-amber-300">…</span>}
                <button
                  type="button"
                  onClick={() => removeAttached(i)}
                  className="ml-0.5 rounded hover:bg-background/40"
                  title="移除"
                >
                  <X className="h-2.5 w-2.5" />
                </button>
              </div>
            ))}
          </div>
        )}
        <div className="flex gap-1.5">
          <textarea
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={onKey}
            placeholder={hasCfg
              ? attached.length > 0
                ? `${attached.length} 个附件 · 写说明或直接发送  (Ctrl+Enter)`
                : "问 AI 或把文件拖进来...  (Ctrl+Enter 发送)"
              : "先点右上⚙ 配置 AI"
            }
            disabled={busy}
            rows={3}
            className="min-h-[3rem] flex-1 resize-none rounded border border-input bg-background p-1.5 font-mono text-[11px] outline-none placeholder:text-muted-foreground focus:border-primary"
          />
          <div className="flex flex-col gap-1">
            <Button
              size="sm" variant="ghost" className="h-6 w-7 p-0"
              onClick={() => void pickFilesViaDialog()}
              title="附加文件"
              disabled={busy}
            >
              <Paperclip className="h-3 w-3" />
            </Button>
            <Button
              size="sm" className="h-auto flex-1"
              onClick={() => void send()}
              disabled={busy || (!input.trim() && attached.length === 0)}
            >
              <Send className="h-3 w-3" />
            </Button>
          </div>
        </div>
      </div>
    </div>
  );
}

function MessageView({ msg }: { msg: ChatMsg }) {
  if (msg.role === "user") {
    // Anthropic: user 消息携带 tool_result blocks(回灌)— 不显示气泡, 改显示为工具结果
    if (Array.isArray(msg.content)) {
      const trs = (msg.content as Array<{ type?: string; content?: string }>)
        .filter((b) => b.type === "tool_result");
      if (trs.length > 0) {
        return (
          <>{trs.map((b, i) => (
            <ToolResultView key={i} raw={typeof b.content === "string" ? b.content : JSON.stringify(b)} />
          ))}</>
        );
      }
    }
    return (
      <div className="mb-2 ml-8 rounded-md bg-primary/15 px-2 py-1.5 text-[11px] text-foreground">
        <div className="mb-0.5 text-[9px] uppercase tracking-wider text-primary/70">你</div>
        <div className="whitespace-pre-wrap font-sans">{textOf(msg.content)}</div>
      </div>
    );
  }
  if (msg.role === "assistant") {
    const text = textOf(msg.content);
    const tcs = extractToolCalls(msg);
    return (
      <div className="mb-2 mr-8 rounded-md bg-card/60 px-2 py-1.5 text-[11px] text-foreground">
        <div className="mb-0.5 flex items-center gap-1 text-[9px] uppercase tracking-wider text-muted-foreground">
          <Bot className="h-3 w-3" /> AI
        </div>
        {text && <div className="whitespace-pre-wrap font-sans">{text}</div>}
        {tcs.length > 0 && (
          <div className="mt-1 space-y-0.5">
            {tcs.map((tc, i) => (
              <ToolCallView key={i} name={tc.name} args={tc.args} />
            ))}
          </div>
        )}
      </div>
    );
  }
  if (msg.role === "tool") {
    // OpenAI 协议: content = stringified JSON
    const raw = typeof msg.content === "string" ? msg.content : JSON.stringify(msg.content);
    return <ToolResultView raw={raw} />;
  }
  return null;
}

function textOf(content: unknown): string {
  if (typeof content === "string") return content;
  if (Array.isArray(content)) {
    return content
      .map((blk: unknown) => {
        if (typeof blk === "string") return blk;
        if (blk && typeof blk === "object") {
          const b = blk as { type?: string; text?: string; content?: string };
          if (b.type === "text" && typeof b.text === "string") return b.text;
          if (b.type === "tool_result" && typeof b.content === "string") return "";
          return "";
        }
        return "";
      })
      .join("");
  }
  return "";
}

interface ToolCallSummary { name: string; args: string }
function extractToolCalls(msg: ChatMsg): ToolCallSummary[] {
  const out: ToolCallSummary[] = [];
  // OpenAI: msg.tool_calls
  if (Array.isArray(msg.tool_calls)) {
    for (const tc of msg.tool_calls) {
      out.push({ name: tc.function.name, args: tc.function.arguments });
    }
  }
  // Anthropic: content blocks tool_use
  if (Array.isArray(msg.content)) {
    for (const blk of msg.content as Array<{ type?: string; name?: string; input?: unknown }>) {
      if (blk.type === "tool_use" && blk.name) {
        out.push({ name: blk.name, args: JSON.stringify(blk.input ?? {}) });
      }
    }
  }
  return out;
}

function ToolCallView({ name, args }: { name: string; args: string }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="rounded border border-amber-500/30 bg-amber-500/5 text-[10px]">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="flex w-full items-center gap-1 px-2 py-0.5 text-left text-amber-400 hover:bg-amber-500/10"
      >
        {open ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />}
        <Wrench className="h-3 w-3" /> <span className="font-mono">{name}</span>
        <span className="ml-auto truncate text-[9px] text-muted-foreground">
          {summarizeArgs(args)}
        </span>
      </button>
      {open && (
        <pre className="border-t border-amber-500/20 bg-background/40 px-2 py-1 font-mono text-[10px]">
          {prettyJson(args)}
        </pre>
      )}
    </div>
  );
}

function ToolResultView({ raw }: { raw: string }) {
  const [open, setOpen] = useState(false);
  let snippet = raw;
  let ok = true;
  let completed = false;
  let completeSummary = "";
  try {
    const j = JSON.parse(raw);
    ok = j?.ok !== false;
    if (j?.error) snippet = `× ${j.error}`;
    else snippet = `✓ ${summarizeJson(j)}`;
    if (j?.completed && j?.summary) {
      completed = true;
      completeSummary = String(j.summary);
    }
  } catch {}
  if (completed) {
    return (
      <div className="my-2 rounded-md border border-emerald-500/40 bg-emerald-500/10 px-2 py-1.5 text-[11px] text-emerald-200">
        <div className="mb-0.5 flex items-center gap-1 text-[10px] uppercase tracking-wider text-emerald-400">
          <CheckCircle2 className="h-3 w-3" /> 任务完成
        </div>
        <div className="whitespace-pre-wrap font-sans">{completeSummary}</div>
      </div>
    );
  }
  return (
    <div className={cn(
      "ml-4 mb-1 rounded border bg-card/40 text-[10px]",
      ok ? "border-emerald-500/30" : "border-red-500/40"
    )}>
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className={cn(
          "flex w-full items-center gap-1 px-2 py-0.5 text-left hover:bg-accent/30",
          ok ? "text-emerald-400" : "text-red-400"
        )}
      >
        {open ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />}
        工具结果
        <span className="ml-2 truncate text-[9px] text-muted-foreground">{snippet}</span>
      </button>
      {open && (
        <pre className="max-h-64 overflow-auto border-t border-border/40 bg-background/60 px-2 py-1 font-mono text-[10px]">
          {prettyJson(raw)}
        </pre>
      )}
    </div>
  );
}

function summarizeArgs(s: string): string {
  if (!s) return "";
  if (s.length < 80) return s;
  return s.slice(0, 76) + "…";
}
function summarizeJson(j: unknown): string {
  if (j && typeof j === "object") {
    const o = j as Record<string, unknown>;
    const keys = Object.keys(o).filter((k) => k !== "ok").slice(0, 4);
    return keys.map((k) => {
      const v = o[k];
      let preview: string;
      if (Array.isArray(v)) preview = `[${v.length}]`;
      else if (typeof v === "object" && v) preview = "{…}";
      else preview = String(v).slice(0, 40);
      return `${k}=${preview}`;
    }).join(" ");
  }
  return String(j).slice(0, 60);
}
function prettyJson(s: string): string {
  try { return JSON.stringify(JSON.parse(s), null, 2); }
  catch { return s; }
}

function SessionHistoryDialog({
  open, onOpenChange, onLoad,
}: {
  open: boolean;
  onOpenChange: (v: boolean) => void;
  onLoad: (id: string) => void;
}) {
  const [list, setList] = useState<Array<{ id: string; size_bytes: number; modified: number; first_user: string | null }>>([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!open) return;
    setLoading(true);
    dbgIpc.aiSessionList()
      .then((l) => setList(l))
      .catch(() => setList([]))
      .finally(() => setLoading(false));
  }, [open]);

  async function del(id: string) {
    try {
      await dbgIpc.aiSessionDelete(id);
      setList((l) => l.filter((s) => s.id !== id));
    } catch (e) { toast.error(errMsg(e)); }
  }

  return (
    <Dialog
      open={open}
      onClose={() => onOpenChange(false)}
      title={<span className="flex items-center gap-2"><History className="h-4 w-4" /> AI 历史会话</span>}
      widthClass="max-w-xl"
    >
      <div className="max-h-[60vh] overflow-y-auto px-2 py-2 text-[11px]">
        {loading ? (
          <div className="flex items-center justify-center py-8 text-muted-foreground">
            <Loader2 className="mr-2 h-4 w-4 animate-spin" /> 加载中
          </div>
        ) : list.length === 0 ? (
          <div className="py-8 text-center text-muted-foreground">无会话</div>
        ) : list.map((s) => (
          <div key={s.id} className="mb-1 flex items-start gap-2 rounded border border-border/50 bg-card/30 p-2">
            <div className="min-w-0 flex-1">
              <div className="truncate font-medium text-foreground">
                {s.first_user || s.id}
              </div>
              <div className="mt-0.5 text-[10px] text-muted-foreground">
                {new Date(s.modified * 1000).toLocaleString()} · {s.size_bytes} B · <code className="font-mono">{s.id}</code>
              </div>
            </div>
            <Button size="sm" variant="outline" className="h-6 px-2" onClick={() => onLoad(s.id)}>
              加载
            </Button>
            <Button size="sm" variant="ghost" className="h-6 w-6 p-0" onClick={() => void del(s.id)} title="删除">
              <Trash2 className="h-3 w-3 text-red-400" />
            </Button>
          </div>
        ))}
      </div>
    </Dialog>
  );
}
