import { useCallback, useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Plug, PlugZap, Trash2, RefreshCw, Plus, X, Settings, ChevronDown, ChevronRight } from "lucide-react";

import { cn } from "@/lib/utils";

/**
 * P115: MCP (Model Context Protocol) 管理面板.
 *
 * 用户能:
 *  - 添加 stdio / http MCP server (IDA Pro / Ghidra / Filesystem / GitHub ...)
 *  - 连接 / 断开, 看 server 提供的工具列表
 *  - 选择是否暴露给 AI agent (默认是)
 *
 * 连接后 server 的工具自动加进 AI 工具池, 命名 mcp__<server>__<tool>.
 */

type McpTransport =
  | {
      kind: "stdio";
      command: string;
      args: string[];
      env: [string, string][];
      cwd: string | null;
    }
  | {
      kind: "http";
      url: string;
      headers: [string, string][];
    };

interface McpServerConfig {
  name: string;
  transport: McpTransport;
  enabled: boolean;
  description: string | null;
  expose_to_ai: boolean;
}

interface McpToolInfo {
  name: string;
  description: string | null;
  input_schema: unknown;
}

type McpStatus = "disconnected" | "connecting" | "connected" | "error";

interface McpServerStatus {
  name: string;
  status: McpStatus;
  tools: McpToolInfo[];
  error: string | null;
  server_info: unknown | null;
}

const STATUS_COLOR: Record<McpStatus, string> = {
  disconnected: "bg-muted-foreground/40",
  connecting: "bg-amber-500 animate-pulse",
  connected: "bg-emerald-500",
  error: "bg-rose-500",
};

const STATUS_LABEL: Record<McpStatus, string> = {
  disconnected: "未连接",
  connecting: "连接中",
  connected: "已连接",
  error: "错误",
};

export function McpPanel() {
  const [statuses, setStatuses] = useState<McpServerStatus[]>([]);
  const [configs, setConfigs] = useState<McpServerConfig[]>([]);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [showAdd, setShowAdd] = useState(false);
  const [editing, setEditing] = useState<McpServerConfig | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [globalError, setGlobalError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      const [s, c] = await Promise.all([
        invoke<McpServerStatus[]>("mcp_list_servers"),
        invoke<McpServerConfig[]>("mcp_get_configs"),
      ]);
      setStatuses(s);
      setConfigs(c);
      setGlobalError(null);
    } catch (e) {
      setGlobalError(String(e));
    }
  }, []);

  useEffect(() => {
    refresh();
    const t = setInterval(refresh, 4000);
    return () => clearInterval(t);
  }, [refresh]);

  const merged = useMemo(() => {
    // 按 config 顺序展示, 状态从 statuses 找
    return configs.map((c) => ({
      cfg: c,
      st: statuses.find((s) => s.name === c.name) ?? {
        name: c.name,
        status: "disconnected" as McpStatus,
        tools: [],
        error: null,
        server_info: null,
      },
    }));
  }, [configs, statuses]);

  const onConnect = async (name: string) => {
    setBusy(name);
    try {
      await invoke("mcp_connect", { name });
      await refresh();
    } catch (e) {
      setGlobalError(`connect ${name}: ${String(e)}`);
    } finally {
      setBusy(null);
    }
  };
  const onDisconnect = async (name: string) => {
    setBusy(name);
    try {
      await invoke("mcp_disconnect", { name });
      await refresh();
    } finally {
      setBusy(null);
    }
  };
  const onRemove = async (name: string) => {
    if (!confirm(`删除 MCP server "${name}"?`)) return;
    try {
      await invoke("mcp_remove_server", { name });
      await refresh();
    } catch (e) {
      setGlobalError(`remove ${name}: ${String(e)}`);
    }
  };

  const toggleExpand = (name: string) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(name)) next.delete(name);
      else next.add(name);
      return next;
    });
  };

  return (
    <div className="flex h-full min-h-0 flex-col bg-card/30 text-xs">
      <div className="flex h-8 shrink-0 items-center gap-2 border-b border-border px-2">
        <span className="font-medium">MCP Servers</span>
        <span className="text-muted-foreground">({configs.length})</span>
        <div className="ml-auto flex items-center gap-1">
          <button
            type="button"
            onClick={refresh}
            title="刷新"
            className="flex h-6 w-6 items-center justify-center rounded text-muted-foreground hover:bg-accent hover:text-foreground"
          >
            <RefreshCw className="h-3.5 w-3.5" />
          </button>
          <button
            type="button"
            onClick={() => {
              setEditing(null);
              setShowAdd(true);
            }}
            title="添加 server"
            className="flex h-6 w-6 items-center justify-center rounded text-muted-foreground hover:bg-accent hover:text-foreground"
          >
            <Plus className="h-3.5 w-3.5" />
          </button>
        </div>
      </div>

      {globalError && (
        <div className="border-b border-rose-500/30 bg-rose-500/10 px-2 py-1 text-[10px] text-rose-400">
          {globalError}
        </div>
      )}

      <div className="min-h-0 flex-1 overflow-y-auto">
        {merged.length === 0 ? (
          <EmptyState onAdd={() => { setEditing(null); setShowAdd(true); }} />
        ) : (
          merged.map(({ cfg, st }) => {
            const isExpanded = expanded.has(cfg.name);
            const isBusy = busy === cfg.name;
            const transportLabel =
              cfg.transport.kind === "stdio"
                ? `stdio: ${cfg.transport.command}`
                : `http: ${cfg.transport.url}`;
            return (
              <div key={cfg.name} className="border-b border-border/60">
                <div className="flex items-center gap-1 px-2 py-1.5 hover:bg-accent/30">
                  <button
                    type="button"
                    onClick={() => toggleExpand(cfg.name)}
                    className="flex h-5 w-5 items-center justify-center text-muted-foreground hover:text-foreground"
                  >
                    {isExpanded ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />}
                  </button>
                  <span className={cn("h-2 w-2 shrink-0 rounded-full", STATUS_COLOR[st.status])} title={STATUS_LABEL[st.status]} />
                  <div className="min-w-0 flex-1">
                    <div className="truncate font-medium">{cfg.name}</div>
                    <div className="truncate text-[10px] text-muted-foreground">{transportLabel}</div>
                  </div>
                  <span className="shrink-0 text-[10px] text-muted-foreground">{st.tools.length} 工具</span>
                  <button
                    type="button"
                    disabled={isBusy}
                    onClick={() => (st.status === "connected" ? onDisconnect(cfg.name) : onConnect(cfg.name))}
                    title={st.status === "connected" ? "断开" : "连接"}
                    className={cn(
                      "flex h-6 w-6 shrink-0 items-center justify-center rounded transition-colors",
                      st.status === "connected"
                        ? "text-emerald-400 hover:bg-emerald-500/10"
                        : "text-muted-foreground hover:bg-accent hover:text-foreground",
                      isBusy && "opacity-50",
                    )}
                  >
                    {st.status === "connected" ? <PlugZap className="h-3.5 w-3.5" /> : <Plug className="h-3.5 w-3.5" />}
                  </button>
                  <button
                    type="button"
                    onClick={() => { setEditing(cfg); setShowAdd(true); }}
                    title="编辑"
                    className="flex h-6 w-6 shrink-0 items-center justify-center rounded text-muted-foreground hover:bg-accent hover:text-foreground"
                  >
                    <Settings className="h-3.5 w-3.5" />
                  </button>
                  <button
                    type="button"
                    onClick={() => onRemove(cfg.name)}
                    title="删除"
                    className="flex h-6 w-6 shrink-0 items-center justify-center rounded text-rose-400 hover:bg-rose-500/10"
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                  </button>
                </div>
                {isExpanded && (
                  <div className="bg-card/40 px-3 pb-2 pt-1 text-[10px] leading-relaxed">
                    {st.error && (
                      <div className="mb-1 rounded border border-rose-500/40 bg-rose-500/10 p-1 text-rose-400">
                        {st.error}
                      </div>
                    )}
                    <div className="mb-1 text-muted-foreground">
                      暴露给 AI: <span className="text-foreground">{cfg.expose_to_ai ? "是" : "否"}</span>
                      {cfg.description && <span> · {cfg.description}</span>}
                    </div>
                    {st.tools.length === 0 ? (
                      <div className="text-muted-foreground">
                        {st.status === "connected" ? "(此 server 未声明工具)" : "(未连接)"}
                      </div>
                    ) : (
                      <ul className="space-y-0.5">
                        {st.tools.map((t) => (
                          <li key={t.name} className="rounded px-1 py-0.5 hover:bg-accent/40">
                            <span className="font-mono text-primary">{t.name}</span>
                            {t.description && <span className="ml-2 text-muted-foreground">{t.description}</span>}
                          </li>
                        ))}
                      </ul>
                    )}
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>

      {showAdd && (
        <McpServerDialog
          initial={editing}
          onClose={() => { setShowAdd(false); setEditing(null); }}
          onSaved={async () => { setShowAdd(false); setEditing(null); await refresh(); }}
        />
      )}
    </div>
  );
}

function EmptyState({ onAdd }: { onAdd: () => void }) {
  return (
    <div className="flex h-full flex-col items-center justify-center gap-3 p-4 text-center text-[11px] text-muted-foreground">
      <div>还没有 MCP server.</div>
      <div className="max-w-xs leading-relaxed">
        添加一个外部 MCP server (IDA Pro / Ghidra / Filesystem ...) 后, 它的工具会自动出现在 AI 工具池里, 命名 <span className="font-mono">mcp__server__tool</span>.
      </div>
      <button
        type="button"
        onClick={onAdd}
        className="flex items-center gap-1 rounded bg-primary px-2.5 py-1 text-[11px] font-medium text-primary-foreground hover:bg-primary/90"
      >
        <Plus className="h-3 w-3" />
        添加 server
      </button>
    </div>
  );
}

interface DialogProps {
  initial: McpServerConfig | null;
  onClose: () => void;
  onSaved: () => Promise<void>;
}

function McpServerDialog({ initial, onClose, onSaved }: DialogProps) {
  const [name, setName] = useState(initial?.name ?? "");
  const [kind, setKind] = useState<"stdio" | "http">(initial?.transport.kind ?? "http");
  const [command, setCommand] = useState(initial?.transport.kind === "stdio" ? initial.transport.command : "");
  const [argsText, setArgsText] = useState(
    initial?.transport.kind === "stdio" ? initial.transport.args.join("\n") : "",
  );
  const [cwd, setCwd] = useState(initial?.transport.kind === "stdio" ? initial.transport.cwd ?? "" : "");
  const [envText, setEnvText] = useState(
    initial?.transport.kind === "stdio"
      ? initial.transport.env.map(([k, v]) => `${k}=${v}`).join("\n")
      : "",
  );
  const [url, setUrl] = useState(initial?.transport.kind === "http" ? initial.transport.url : "http://localhost:13337/mcp");
  const [headersText, setHeadersText] = useState(
    initial?.transport.kind === "http"
      ? initial.transport.headers.map(([k, v]) => `${k}: ${v}`).join("\n")
      : "",
  );
  const [description, setDescription] = useState(initial?.description ?? "");
  const [exposeAi, setExposeAi] = useState(initial?.expose_to_ai ?? true);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const isEdit = initial != null;

  const onSubmit = async () => {
    setErr(null);
    if (!name.trim()) { setErr("name 不能为空"); return; }
    if (name.includes("__")) { setErr("name 不能含 '__' (MCP 工具名前缀冲突)"); return; }

    let transport: McpTransport;
    if (kind === "stdio") {
      if (!command.trim()) { setErr("stdio: command 不能为空"); return; }
      const args = argsText.split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
      const env: [string, string][] = envText
        .split(/\r?\n/)
        .map((s) => s.trim())
        .filter(Boolean)
        .map((line) => {
          const i = line.indexOf("=");
          return i < 0 ? [line, ""] : [line.slice(0, i), line.slice(i + 1)];
        });
      transport = { kind: "stdio", command: command.trim(), args, env, cwd: cwd.trim() || null };
    } else {
      if (!url.trim()) { setErr("http: url 不能为空"); return; }
      const headers: [string, string][] = headersText
        .split(/\r?\n/)
        .map((s) => s.trim())
        .filter(Boolean)
        .map((line) => {
          const i = line.indexOf(":");
          return i < 0 ? [line, ""] : [line.slice(0, i).trim(), line.slice(i + 1).trim()];
        });
      transport = { kind: "http", url: url.trim(), headers };
    }

    const config: McpServerConfig = {
      name: name.trim(),
      transport,
      enabled: true,
      description: description.trim() || null,
      expose_to_ai: exposeAi,
    };

    setBusy(true);
    try {
      await invoke("mcp_upsert_server", { config });
      await onSaved();
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="absolute inset-0 z-50 flex items-center justify-center bg-background/80 p-4">
      <div className="w-full max-w-md rounded-lg border border-border bg-card p-4 shadow-2xl">
        <div className="mb-3 flex items-center justify-between">
          <div className="text-sm font-medium">{isEdit ? "编辑 MCP server" : "添加 MCP server"}</div>
          <button type="button" onClick={onClose} className="text-muted-foreground hover:text-foreground">
            <X className="h-4 w-4" />
          </button>
        </div>
        <div className="space-y-2 text-xs">
          <Field label="名称 (任意, 仅允许字母/数字/-)">
            <input
              value={name}
              onChange={(e) => setName(e.target.value)}
              disabled={isEdit}
              placeholder="ida"
              className="w-full rounded border border-border bg-background px-2 py-1 outline-none focus:border-primary"
            />
          </Field>
          <Field label="Transport">
            <div className="flex gap-2">
              {(["http", "stdio"] as const).map((k) => (
                <label key={k} className="flex items-center gap-1 cursor-pointer">
                  <input type="radio" checked={kind === k} onChange={() => setKind(k)} />
                  <span>{k}</span>
                </label>
              ))}
            </div>
          </Field>
          {kind === "http" ? (
            <>
              <Field label="URL">
                <input
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  placeholder="http://localhost:13337/mcp"
                  className="w-full rounded border border-border bg-background px-2 py-1 font-mono outline-none focus:border-primary"
                />
              </Field>
              <Field label="HTTP Headers (每行 Key: Value, 可选)">
                <textarea
                  value={headersText}
                  onChange={(e) => setHeadersText(e.target.value)}
                  rows={2}
                  placeholder="Authorization: Bearer xxx"
                  className="w-full rounded border border-border bg-background px-2 py-1 font-mono outline-none focus:border-primary"
                />
              </Field>
            </>
          ) : (
            <>
              <Field label="可执行命令">
                <input
                  value={command}
                  onChange={(e) => setCommand(e.target.value)}
                  placeholder="npx 或 python 或 C:\\path\\to\\server.exe"
                  className="w-full rounded border border-border bg-background px-2 py-1 font-mono outline-none focus:border-primary"
                />
              </Field>
              <Field label="参数 (每行一个)">
                <textarea
                  value={argsText}
                  onChange={(e) => setArgsText(e.target.value)}
                  rows={3}
                  placeholder={"-y\n@modelcontextprotocol/server-filesystem\nC:\\Users"}
                  className="w-full rounded border border-border bg-background px-2 py-1 font-mono outline-none focus:border-primary"
                />
              </Field>
              <Field label="环境变量 (每行 KEY=VALUE, 可选)">
                <textarea
                  value={envText}
                  onChange={(e) => setEnvText(e.target.value)}
                  rows={2}
                  className="w-full rounded border border-border bg-background px-2 py-1 font-mono outline-none focus:border-primary"
                />
              </Field>
              <Field label="工作目录 (可选)">
                <input
                  value={cwd}
                  onChange={(e) => setCwd(e.target.value)}
                  className="w-full rounded border border-border bg-background px-2 py-1 font-mono outline-none focus:border-primary"
                />
              </Field>
            </>
          )}
          <Field label="描述 (可选)">
            <input
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="IDA Pro MCP - 静态分析对接"
              className="w-full rounded border border-border bg-background px-2 py-1 outline-none focus:border-primary"
            />
          </Field>
          <label className="flex items-center gap-2 pt-1 cursor-pointer">
            <input type="checkbox" checked={exposeAi} onChange={(e) => setExposeAi(e.target.checked)} />
            <span>暴露给 AI agent</span>
          </label>
        </div>
        {err && (
          <div className="mt-2 rounded border border-rose-500/40 bg-rose-500/10 p-2 text-[11px] text-rose-400">
            {err}
          </div>
        )}
        <div className="mt-3 flex justify-end gap-2">
          <button
            type="button"
            onClick={onClose}
            disabled={busy}
            className="rounded px-3 py-1 text-xs text-muted-foreground hover:bg-accent hover:text-foreground"
          >
            取消
          </button>
          <button
            type="button"
            onClick={onSubmit}
            disabled={busy}
            className="rounded bg-primary px-3 py-1 text-xs font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
          >
            {busy ? "保存中..." : "保存"}
          </button>
        </div>
      </div>
    </div>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <label className="block">
      <div className="mb-0.5 text-muted-foreground">{label}</div>
      {children}
    </label>
  );
}
