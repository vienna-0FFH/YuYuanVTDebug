//! P115: 通用 MCP (Model Context Protocol) client.
//!
//! 用户在 GUI 里添加任意 MCP server (IDA Pro / Ghidra / Filesystem / GitHub 等),
//! 我们做 stdio + HTTP 两种 transport,跑标准 MCP 握手 (initialize → tools/list),
//! 把 server 提供的工具暴露给 GUI 和 AI agent。
//!
//! 协议要点 (MCP 2024-11-05 / 2025-06-18):
//!   - JSON-RPC 2.0 over stdio (NDJSON, 每行一条 message) 或 HTTP POST
//!   - 启动后必须先发 `initialize` 取得 server capabilities
//!   - 拿到 capabilities 后发 `notifications/initialized` (stdio only)
//!   - 然后才能 `tools/list` / `tools/call` / `resources/list` 等
//!
//! 设计:
//!   - 全局 McpRegistry 在 Tauri State 注册,管 server 列表
//!   - 每个 server 一个 McpServer 状态 (config + transport + tools cache)
//!   - stdio: tokio::process 启子进程,line-delimited JSON
//!   - http: reqwest POST JSON-RPC 到指定 URL
//!   - 配置持久化到 %LOCALAPPDATA%\GuardMetaVSP\mcp_servers.json

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex as PlMutex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::sync::{oneshot, Mutex as AsyncMutex};

use crate::util::error::{AppError, AppResult};

// ============================================================
// 公开类型
// ============================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum McpTransport {
    /// 子进程, stdin/stdout 交互。command + args + 可选 cwd / env
    Stdio {
        command: String,
        #[serde(default)]
        args: Vec<String>,
        #[serde(default)]
        env: Vec<(String, String)>,
        #[serde(default)]
        cwd: Option<String>,
    },
    /// HTTP JSON-RPC 端点。一般是 http://localhost:PORT/mcp
    Http {
        url: String,
        #[serde(default)]
        headers: Vec<(String, String)>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpServerConfig {
    pub name: String,
    pub transport: McpTransport,
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// 可选的备注 / 描述,GUI 展示用
    #[serde(default)]
    pub description: Option<String>,
    /// AI agent 是否能调这个 server 的工具
    #[serde(default = "default_true")]
    pub expose_to_ai: bool,
}

fn default_true() -> bool { true }

#[derive(Debug, Clone, Serialize)]
pub struct McpToolInfo {
    pub name: String,
    pub description: Option<String>,
    /// JSON schema (object) 描述参数
    pub input_schema: Value,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum McpStatus {
    Disconnected,
    Connecting,
    Connected,
    Error,
}

#[derive(Debug, Clone, Serialize)]
pub struct McpServerStatus {
    pub name: String,
    pub status: McpStatus,
    pub tools: Vec<McpToolInfo>,
    pub error: Option<String>,
    pub server_info: Option<Value>,   // initialize 返回的 server info
}

// ============================================================
// 持久化
// ============================================================

fn store_path() -> AppResult<PathBuf> {
    let base = std::env::var_os("LOCALAPPDATA")
        .or_else(|| std::env::var_os("APPDATA"))
        .map(PathBuf::from)
        .ok_or_else(|| AppError::Internal("无法解析 LOCALAPPDATA".into()))?;
    let dir = base.join("GuardMetaVSP");
    std::fs::create_dir_all(&dir).map_err(|e| AppError::Internal(format!("mkdir: {e}")))?;
    Ok(dir.join("mcp_servers.json"))
}

fn load_configs() -> Vec<McpServerConfig> {
    let p = match store_path() {
        Ok(p) => p,
        Err(_) => return vec![],
    };
    if !p.exists() { return vec![]; }
    let raw = match std::fs::read_to_string(&p) {
        Ok(s) => s,
        Err(_) => return vec![],
    };
    serde_json::from_str(&raw).unwrap_or_default()
}

fn save_configs(list: &[McpServerConfig]) -> AppResult<()> {
    let p = store_path()?;
    let s = serde_json::to_string_pretty(list)
        .map_err(|e| AppError::Internal(format!("encode: {e}")))?;
    std::fs::write(&p, s).map_err(|e| AppError::Internal(format!("写 {p:?}: {e}")))?;
    Ok(())
}

// ============================================================
// 内部: 单 server 状态
// ============================================================

/// stdio transport 的活动状态。child 持有子进程 handle, stdin 写请求,
/// reader_task 在后台读 stdout 把响应分发回 pending map。
struct StdioState {
    _child: Child,
    stdin: ChildStdin,
    /// id -> oneshot::Sender, reader_task 收到 response 时唤醒等待者
    pending: Arc<PlMutex<HashMap<u64, oneshot::Sender<Value>>>>,
}

/// HTTP transport 状态 (无连接概念, 每次请求建新的 reqwest call)
struct HttpState {
    url: String,
    headers: Vec<(String, String)>,
    client: reqwest::Client,
    /// HTTP 也支持 session id (`Mcp-Session-Id` header), initialize 后存
    session_id: Arc<PlMutex<Option<String>>>,
}

enum TransportState {
    Stdio(StdioState),
    Http(HttpState),
}

struct McpServer {
    config: McpServerConfig,
    /// 已连接时持有的 transport,断开就置 None
    transport: Option<TransportState>,
    /// initialize 返回的 server info (name + version + capabilities)
    server_info: Option<Value>,
    /// tools/list 缓存
    tools: Vec<McpToolInfo>,
    status: McpStatus,
    last_error: Option<String>,
    /// 单调递增 request id
    next_id: u64,
}

impl McpServer {
    fn new(config: McpServerConfig) -> Self {
        Self {
            config,
            transport: None,
            server_info: None,
            tools: vec![],
            status: McpStatus::Disconnected,
            last_error: None,
            next_id: 1,
        }
    }

    fn alloc_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id = self.next_id.saturating_add(1).max(1);
        id
    }
}

// ============================================================
// Registry (全局 state)
// ============================================================

pub struct McpRegistry {
    /// name -> server。AsyncMutex 因为 connect/call 涉及 .await
    servers: AsyncMutex<HashMap<String, McpServer>>,
}

impl McpRegistry {
    pub fn new() -> Self {
        let mut map = HashMap::new();
        for c in load_configs() {
            map.insert(c.name.clone(), McpServer::new(c));
        }
        Self { servers: AsyncMutex::new(map) }
    }
}

impl Default for McpRegistry {
    fn default() -> Self { Self::new() }
}

// ============================================================
// 协议 helpers
// ============================================================

const PROTOCOL_VERSION: &str = "2025-06-18";
const CLIENT_NAME: &str = "GuardMetaVSP";
const CLIENT_VERSION: &str = env!("CARGO_PKG_VERSION");

fn make_request(id: u64, method: &str, params: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": method,
        "params": params,
    })
}

fn make_notification(method: &str, params: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
    })
}

/// 解析 JSON-RPC response, 提取 result 或翻成 AppError
fn unwrap_response(resp: Value) -> AppResult<Value> {
    if let Some(err) = resp.get("error") {
        let code = err.get("code").and_then(|v| v.as_i64()).unwrap_or(0);
        let msg = err.get("message").and_then(|v| v.as_str()).unwrap_or("(no message)");
        return Err(AppError::Internal(format!("MCP error {code}: {msg}")));
    }
    resp.get("result")
        .cloned()
        .ok_or_else(|| AppError::Internal("MCP response 无 result".into()))
}

fn initialize_params() -> Value {
    json!({
        "protocolVersion": PROTOCOL_VERSION,
        "capabilities": {
            // 我们是 client, 不实现 sampling 等高级能力, 但声明 tools 让 server 知道我们要工具
            "tools": {},
            "resources": {},
        },
        "clientInfo": {
            "name": CLIENT_NAME,
            "version": CLIENT_VERSION,
        }
    })
}

fn parse_tools_list(result: Value) -> Vec<McpToolInfo> {
    let arr = result.get("tools").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    arr.into_iter().filter_map(|t| {
        let name = t.get("name").and_then(|v| v.as_str())?.to_string();
        let description = t.get("description").and_then(|v| v.as_str()).map(String::from);
        let input_schema = t.get("inputSchema").cloned().unwrap_or_else(|| json!({"type":"object"}));
        Some(McpToolInfo { name, description, input_schema })
    }).collect()
}

// ============================================================
// Stdio transport: 启动 + 后台 reader + 请求/响应
// ============================================================

fn spawn_stdio(
    command: &str,
    args: &[String],
    env: &[(String, String)],
    cwd: Option<&str>,
) -> AppResult<StdioState> {
    let mut cmd = Command::new(command);
    cmd.args(args);
    cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    for (k, v) in env {
        cmd.env(k, v);
    }
    if let Some(d) = cwd { cmd.current_dir(d); }

    // 防 Windows 弹黑窗口 — tokio::process::Command 自己暴露 creation_flags (windows)
    #[cfg(windows)]
    {
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }

    let mut child = cmd.spawn().map_err(|e| AppError::Io(format!("spawn {command}: {e}")))?;
    let stdin = child.stdin.take().ok_or_else(|| AppError::Internal("子进程无 stdin".into()))?;
    let stdout = child.stdout.take().ok_or_else(|| AppError::Internal("子进程无 stdout".into()))?;
    let stderr = child.stderr.take();

    let pending: Arc<PlMutex<HashMap<u64, oneshot::Sender<Value>>>> =
        Arc::new(PlMutex::new(HashMap::new()));

    // reader task
    let pending_cl = pending.clone();
    tokio::spawn(async move {
        let reader = BufReader::new(stdout as ChildStdout);
        let mut lines = reader.lines();
        loop {
            match lines.next_line().await {
                Ok(Some(line)) => {
                    let line = line.trim();
                    if line.is_empty() { continue; }
                    let v: Value = match serde_json::from_str(line) {
                        Ok(v) => v,
                        Err(_) => continue,    // 非 JSON 行 (server 偶尔有日志) 忽略
                    };
                    // notifications 没有 id, 我们当前不订阅 server 主动通知, 跳过
                    let id = match v.get("id").and_then(|x| x.as_u64()) {
                        Some(i) => i,
                        None => continue,
                    };
                    if let Some(tx) = pending_cl.lock().remove(&id) {
                        let _ = tx.send(v);
                    }
                }
                Ok(None) => break,    // EOF, 子进程退出
                Err(_) => break,
            }
        }
    });

    // stderr drain (避免管道堵塞)。只收集前 8KB 避免无限增长。
    if let Some(stderr) = stderr {
        tokio::spawn(async move {
            let reader = BufReader::new(stderr);
            let mut lines = reader.lines();
            let mut total = 0usize;
            while let Ok(Some(line)) = lines.next_line().await {
                total += line.len() + 1;
                if total > 8192 { break; }
            }
        });
    }

    Ok(StdioState { _child: child, stdin, pending })
}

async fn stdio_request(state: &mut StdioState, id: u64, payload: Value) -> AppResult<Value> {
    let (tx, rx) = oneshot::channel();
    state.pending.lock().insert(id, tx);

    let mut line = serde_json::to_vec(&payload)
        .map_err(|e| AppError::Internal(format!("encode: {e}")))?;
    line.push(b'\n');
    state.stdin.write_all(&line).await
        .map_err(|e| AppError::Io(format!("stdin write: {e}")))?;
    state.stdin.flush().await
        .map_err(|e| AppError::Io(format!("stdin flush: {e}")))?;

    let timeout = Duration::from_secs(60);
    match tokio::time::timeout(timeout, rx).await {
        Ok(Ok(v)) => unwrap_response(v),
        Ok(Err(_)) => {
            state.pending.lock().remove(&id);
            Err(AppError::Internal("reader 通道关闭 (子进程退出?)".into()))
        }
        Err(_) => {
            state.pending.lock().remove(&id);
            Err(AppError::Network(format!("MCP 请求超时 (>{:?})", timeout)))
        }
    }
}

async fn stdio_notify(state: &mut StdioState, payload: Value) -> AppResult<()> {
    let mut line = serde_json::to_vec(&payload)
        .map_err(|e| AppError::Internal(format!("encode: {e}")))?;
    line.push(b'\n');
    state.stdin.write_all(&line).await
        .map_err(|e| AppError::Io(format!("stdin write: {e}")))?;
    state.stdin.flush().await
        .map_err(|e| AppError::Io(format!("stdin flush: {e}")))?;
    Ok(())
}

// ============================================================
// HTTP transport
// ============================================================

fn make_http(url: &str, headers: &[(String, String)]) -> AppResult<HttpState> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(60))
        .build()
        .map_err(|e| AppError::Network(format!("reqwest: {e}")))?;
    Ok(HttpState {
        url: url.to_string(),
        headers: headers.to_vec(),
        client,
        session_id: Arc::new(PlMutex::new(None)),
    })
}

async fn http_request(state: &HttpState, payload: Value) -> AppResult<Value> {
    let mut req = state.client.post(&state.url)
        .header("Content-Type", "application/json")
        // MCP HTTP transport 要求接受 SSE 也接受 JSON, 我们直接收 JSON
        .header("Accept", "application/json, text/event-stream");
    for (k, v) in &state.headers {
        req = req.header(k, v);
    }
    if let Some(sid) = state.session_id.lock().clone() {
        req = req.header("Mcp-Session-Id", sid);
    }
    let resp = req.json(&payload).send().await
        .map_err(|e| AppError::Network(format!("MCP HTTP send: {e}")))?;

    // server 可能在 initialize response 里下发 Mcp-Session-Id
    if let Some(sid) = resp.headers().get("Mcp-Session-Id").and_then(|h| h.to_str().ok()) {
        *state.session_id.lock() = Some(sid.to_string());
    }

    let status = resp.status();
    let ctype = resp.headers().get("Content-Type")
        .and_then(|h| h.to_str().ok()).unwrap_or("").to_string();
    let body = resp.text().await
        .map_err(|e| AppError::Network(format!("MCP HTTP read: {e}")))?;
    if !status.is_success() {
        return Err(AppError::Network(format!("MCP HTTP {status}: {body}")));
    }

    // server 可能返回 SSE 流, 第一条 data: {...} 就是我们要的 response
    if ctype.contains("text/event-stream") {
        for line in body.lines() {
            if let Some(rest) = line.strip_prefix("data:") {
                let v: Value = serde_json::from_str(rest.trim())
                    .map_err(|e| AppError::Network(format!("SSE parse: {e}")))?;
                return unwrap_response(v);
            }
        }
        return Err(AppError::Network("SSE 响应无 data 行".into()));
    }

    let v: Value = serde_json::from_str(&body)
        .map_err(|e| AppError::Network(format!("MCP HTTP parse: {e}")))?;
    unwrap_response(v)
}

// ============================================================
// 连接 / 断开 / 调用
// ============================================================

async fn do_connect(server: &mut McpServer) -> AppResult<()> {
    server.status = McpStatus::Connecting;
    server.last_error = None;

    let transport = match &server.config.transport {
        McpTransport::Stdio { command, args, env, cwd } => {
            let st = spawn_stdio(command, args, env, cwd.as_deref())?;
            TransportState::Stdio(st)
        }
        McpTransport::Http { url, headers } => {
            TransportState::Http(make_http(url, headers)?)
        }
    };
    server.transport = Some(transport);

    // initialize
    let init_id = server.alloc_id();
    let init_req = make_request(init_id, "initialize", initialize_params());
    let init_result = call_raw(server, init_id, init_req).await?;
    server.server_info = init_result.get("serverInfo").cloned();

    // stdio 必须发 initialized notification
    if let Some(TransportState::Stdio(st)) = &mut server.transport {
        let n = make_notification("notifications/initialized", json!({}));
        stdio_notify(st, n).await?;
    }

    // tools/list
    let list_id = server.alloc_id();
    let list_req = make_request(list_id, "tools/list", json!({}));
    let list_result = call_raw(server, list_id, list_req).await?;
    server.tools = parse_tools_list(list_result);

    server.status = McpStatus::Connected;
    Ok(())
}

/// 发已构造好的 JSON-RPC payload (要求 server.transport 已就绪)。
/// id 必须与 payload 内 id 一致(用于 stdio pending map)。
async fn call_raw(server: &mut McpServer, id: u64, payload: Value) -> AppResult<Value> {
    let res = match server.transport.as_mut() {
        Some(TransportState::Stdio(st)) => stdio_request(st, id, payload).await,
        Some(TransportState::Http(st)) => http_request(st, payload).await,
        None => Err(AppError::Internal("未连接".into())),
    };
    if let Err(e) = &res {
        server.last_error = Some(e.to_string());
        server.status = McpStatus::Error;
    }
    res
}

fn server_status(s: &McpServer) -> McpServerStatus {
    McpServerStatus {
        name: s.config.name.clone(),
        status: s.status.clone(),
        tools: s.tools.clone(),
        error: s.last_error.clone(),
        server_info: s.server_info.clone(),
    }
}

// ============================================================
// 内部 API (供 ai_chat 路由用, 不经 Tauri command)
// ============================================================

/// 给 ai_chat::build_tool_registry 用: 取所有 connected 且 expose_to_ai 的 server
/// 的工具列表, 返回 (server_name, tool_name, description, input_schema)。
pub async fn list_ai_visible_tools(registry: &McpRegistry) -> Vec<(String, String, Option<String>, Value)> {
    let map = registry.servers.lock().await;
    let mut out = Vec::new();
    for (name, s) in map.iter() {
        if !s.config.expose_to_ai { continue; }
        if !matches!(s.status, McpStatus::Connected) { continue; }
        for t in &s.tools {
            out.push((name.clone(), t.name.clone(), t.description.clone(), t.input_schema.clone()));
        }
    }
    out
}

/// 直接调一个 MCP 工具,返回 server 的 result (`{content: [...], isError: bool}` 形态)。
pub async fn call_tool_internal(
    registry: &McpRegistry,
    server_name: &str,
    tool_name: &str,
    arguments: Value,
) -> AppResult<Value> {
    let mut map = registry.servers.lock().await;
    let s = map.get_mut(server_name)
        .ok_or_else(|| AppError::Internal(format!("MCP server `{server_name}` 不存在")))?;
    if !matches!(s.status, McpStatus::Connected) {
        return Err(AppError::Internal(format!("MCP server `{server_name}` 未连接")));
    }
    let id = s.alloc_id();
    let req = make_request(id, "tools/call", json!({
        "name": tool_name,
        "arguments": arguments,
    }));
    call_raw(s, id, req).await
}

// ============================================================
// Tauri commands
// ============================================================

#[tauri::command]
pub async fn mcp_list_servers(
    registry: tauri::State<'_, Arc<McpRegistry>>,
) -> AppResult<Vec<McpServerStatus>> {
    let map = registry.servers.lock().await;
    Ok(map.values().map(server_status).collect())
}

#[tauri::command]
pub async fn mcp_get_configs(
    registry: tauri::State<'_, Arc<McpRegistry>>,
) -> AppResult<Vec<McpServerConfig>> {
    let map = registry.servers.lock().await;
    Ok(map.values().map(|s| s.config.clone()).collect())
}

#[tauri::command]
pub async fn mcp_upsert_server(
    registry: tauri::State<'_, Arc<McpRegistry>>,
    config: McpServerConfig,
) -> AppResult<()> {
    if config.name.trim().is_empty() {
        return Err(AppError::Internal("name 不能为空".into()));
    }
    let mut map = registry.servers.lock().await;
    let key = config.name.clone();
    // 如果替换的是已连接 server, 先断开再换 config
    if let Some(old) = map.get_mut(&key) {
        if old.transport.is_some() {
            old.transport = None;
            old.status = McpStatus::Disconnected;
            old.tools.clear();
        }
        old.config = config;
    } else {
        map.insert(key, McpServer::new(config));
    }
    let all: Vec<_> = map.values().map(|s| s.config.clone()).collect();
    drop(map);
    save_configs(&all)?;
    Ok(())
}

#[tauri::command]
pub async fn mcp_remove_server(
    registry: tauri::State<'_, Arc<McpRegistry>>,
    name: String,
) -> AppResult<()> {
    let mut map = registry.servers.lock().await;
    map.remove(&name);
    let all: Vec<_> = map.values().map(|s| s.config.clone()).collect();
    drop(map);
    save_configs(&all)?;
    Ok(())
}

#[tauri::command]
pub async fn mcp_connect(
    registry: tauri::State<'_, Arc<McpRegistry>>,
    name: String,
) -> AppResult<McpServerStatus> {
    let mut map = registry.servers.lock().await;
    let s = map.get_mut(&name)
        .ok_or_else(|| AppError::Internal(format!("server `{name}` 不存在")))?;
    if matches!(s.status, McpStatus::Connected | McpStatus::Connecting) {
        return Ok(server_status(s));
    }
    do_connect(s).await?;
    Ok(server_status(s))
}

#[tauri::command]
pub async fn mcp_disconnect(
    registry: tauri::State<'_, Arc<McpRegistry>>,
    name: String,
) -> AppResult<()> {
    let mut map = registry.servers.lock().await;
    let s = map.get_mut(&name)
        .ok_or_else(|| AppError::Internal(format!("server `{name}` 不存在")))?;
    s.transport = None;
    s.tools.clear();
    s.server_info = None;
    s.status = McpStatus::Disconnected;
    s.last_error = None;
    Ok(())
}

#[tauri::command]
pub async fn mcp_list_tools(
    registry: tauri::State<'_, Arc<McpRegistry>>,
    name: String,
) -> AppResult<Vec<McpToolInfo>> {
    let map = registry.servers.lock().await;
    let s = map.get(&name)
        .ok_or_else(|| AppError::Internal(format!("server `{name}` 不存在")))?;
    Ok(s.tools.clone())
}

#[tauri::command]
pub async fn mcp_call_tool(
    registry: tauri::State<'_, Arc<McpRegistry>>,
    server_name: String,
    tool_name: String,
    arguments: Value,
) -> AppResult<Value> {
    call_tool_internal(&registry, &server_name, &tool_name, arguments).await
}
